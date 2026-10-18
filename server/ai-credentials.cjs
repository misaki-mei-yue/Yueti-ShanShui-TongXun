'use strict';

// Only provider key-management metadata crosses the chat server. Prompt and
// completion requests are intentionally absent from this module.
const crypto = require('node:crypto');
const MANAGEMENT_URL = 'https://openrouter.ai/api/v1/keys';
const BASE_URL = 'https://openrouter.ai/api/v1';
const TTL_MS = 5 * 60 * 1000;
const COOLDOWN_MS = 10 * 1000;
const MAX_OUTBOUND = 4;
const MAX_OUTSTANDING = 64;
const MICROS = 1000000;
const DEFAULTS = Object.freeze({ credentialLimitUsd: 0.05, dailyUserLimitUsd: 1, dailyTotalLimitUsd: 10 });
const BOUNDS = Object.freeze({ credentialLimitUsd: [0.01, 0.25], dailyUserLimitUsd: [0.01, 5], dailyTotalLimitUsd: [0.01, 50] });

function createCredentialBroker({ db, getConfig, fail, fetchImpl = fetch, clock = Date.now }) {
  db.exec(`CREATE TABLE IF NOT EXISTS ai_credential_leases(
    id TEXT PRIMARY KEY,user_id TEXT NOT NULL,chat_id TEXT NOT NULL,session_hash TEXT NOT NULL,
    provider_hash TEXT,expires_at INTEGER NOT NULL,limit_micros INTEGER NOT NULL,
    budget_day TEXT NOT NULL,created_at INTEGER NOT NULL,state TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ai_credentials_user ON ai_credential_leases(user_id,created_at);
    CREATE INDEX IF NOT EXISTS ai_credentials_expiry ON ai_credential_leases(expires_at);
    CREATE INDEX IF NOT EXISTS ai_credentials_budget ON ai_credential_leases(budget_day);`);
  const q = (sql, ...params) => db.prepare(sql).get(...params);
  const all = (sql, ...params) => db.prepare(sql).all(...params);
  const run = (sql, ...params) => db.prepare(sql).run(...params);
  const tasks = new Set(), controllers = new Set(), deletions = new Map();
  let outbound = 0, blocked = false, stopped = false, cleaning = null;
  const digest = key => crypto.createHash('sha256').update(key).digest('hex');
  const stamp = config => digest(JSON.stringify([config.managementKey,config.model,config.credentialLimitUsd,config.dailyUserLimitUsd,config.dailyTotalLimitUsd,config.enabled]));
  const error = (status, message, code) => fail(status,message,{code});
  function track(promise) { tasks.add(promise); promise.finally(() => tasks.delete(promise)).catch(() => {}); return promise; }
  function statusError(status) {
    if ([401,403].includes(status)) error(503,'OpenRouter 管理密钥无效或没有管理权限，请管理员重新配置 Management API Key','AI_MANAGEMENT_AUTH');
    if (status === 429) error(429,'OpenRouter 暂时无法发放凭证，请稍后重试','AI_MANAGEMENT_RATE_LIMIT');
    error(503,'OpenRouter 凭证服务暂时不可用，请稍后重试','AI_MANAGEMENT_UNAVAILABLE');
  }
  async function provider(method, suffix, key, value) {
    if (outbound >= MAX_OUTBOUND) error(429,'AI 凭证请求较多，请稍后重试','AI_CREDENTIAL_BUSY');
    const abort = new AbortController(); controllers.add(abort); outbound++;
    const timer = setTimeout(() => abort.abort(),8000); timer.unref();
    try {
      const response = await fetchImpl(MANAGEMENT_URL + suffix,{method,redirect:'error',credentials:'omit',cache:'no-store',signal:abort.signal,
        headers:{Authorization:'Bearer ' + key,'Content-Type':'application/json'},...(value === undefined ? {} : {body:JSON.stringify(value)})});
      // Never echo a provider error body: it may include keys or request data.
      if (!response.ok) { await response.body?.cancel(); if (method === 'DELETE' && response.status === 404) return null; statusError(response.status); }
      if (method === 'DELETE') { await response.body?.cancel(); return null; }
      if (!response.body) error(502,'OpenRouter 没有返回有效的短期凭证','AI_CREDENTIAL_INVALID');
      const reader = response.body.getReader(), chunks = []; let size = 0;
      for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > 32768) { await reader.cancel(); error(502,'OpenRouter 凭证回复超过限制','AI_CREDENTIAL_INVALID'); } chunks.push(Buffer.from(part.value)); }
      try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { error(502,'OpenRouter 凭证回复格式不正确','AI_CREDENTIAL_INVALID'); }
    } catch (cause) {
      if (cause?.diagnostics) throw cause;
      error(503,'无法连接 OpenRouter 凭证服务，请稍后重试','AI_MANAGEMENT_UNAVAILABLE');
    } finally { clearTimeout(timer); controllers.delete(abort); outbound--; }
  }
  async function revokeRow(row, config = getConfig()) {
    if (deletions.has(row.id)) return deletions.get(row.id);
    const work = (async () => {
      run("UPDATE ai_credential_leases SET state='revoking' WHERE id=? AND state<>'revoked'",row.id);
      if (!row.provider_hash) return false; // Unknown create outcome is bounded by its requested expiry.
      if (!config.managementKey) return false;
      try {
        await provider('DELETE','/' + row.provider_hash,config.managementKey);
        run("UPDATE ai_credential_leases SET state='revoked' WHERE id=?",row.id); return true;
      } catch { return false; }
    })();
    deletions.set(row.id,work);
    try { return await track(work); } finally { deletions.delete(row.id); }
  }
  async function revokeWhere(where, values = [], config = getConfig()) {
    const rows = all("SELECT * FROM ai_credential_leases WHERE state NOT IN ('revoked','expired') AND " + where,...values);
    let ok = true;
    // Bounded groups avoid flooding the management API on logout/config change.
    for (let i = 0; i < rows.length; i += MAX_OUTBOUND) {
      const outcomes = await Promise.all(rows.slice(i,i + MAX_OUTBOUND).map(row => revokeRow(row,config)));
      if (outcomes.some(result => !result)) ok = false;
    }
    return ok;
  }
  async function issue(user, chat, auth, authorized) {
    if (stopped || blocked) error(503,'AI 配置正在更新，请稍后重试','AI_CREDENTIAL_BUSY');
    const config = getConfig();
    if (!config.enabled || config.mode !== 'openrouter_direct' || !config.managementKey || !config.model) error(503,config.needsMigration ? 'AI 已改为客户端直连，请管理员重新配置 OpenRouter Management API Key' : 'AI 尚未配置，请联系管理员','AI_DIRECT_NOT_CONFIGURED');
    if (!authorized()) error(403,'此账户或会话当前不能使用 AI','AI_CREDENTIAL_FORBIDDEN');
    const at = clock(), day = new Date(at).toISOString().slice(0,10), micros = Math.round(config.credentialLimitUsd * MICROS);
    const active = q("SELECT 1 FROM ai_credential_leases WHERE user_id=? AND state NOT IN ('revoked','expired') AND expires_at>?",user.id,at);
    if (active) error(409,'你已有一个 AI 请求正在进行，请先停止或等待短期凭证失效','AI_CREDENTIAL_ACTIVE');
    const latest = q('SELECT max(created_at) AS at FROM ai_credential_leases WHERE user_id=?',user.id);
    if (latest.at !== null && at - latest.at < COOLDOWN_MS) error(429,'请稍等几秒再请求 AI','AI_CREDENTIAL_COOLDOWN');
    const used = q('SELECT coalesce(sum(limit_micros),0) AS amount FROM ai_credential_leases WHERE budget_day=? AND user_id=?',day,user.id).amount;
    const total = q('SELECT coalesce(sum(limit_micros),0) AS amount FROM ai_credential_leases WHERE budget_day=?',day).amount;
    if (used + micros > Math.round(config.dailyUserLimitUsd * MICROS)) error(429,'你今日可领取的 AI 额度已用完，明日 UTC 零点恢复','AI_DAILY_USER_LIMIT');
    if (total + micros > Math.round(config.dailyTotalLimitUsd * MICROS)) error(429,'今日全站可领取的 AI 额度已用完，请明日再试','AI_DAILY_TOTAL_LIMIT');
    if (q("SELECT count(*) AS n FROM ai_credential_leases WHERE state NOT IN ('revoked','expired') AND expires_at>?",at).n >= MAX_OUTSTANDING || outbound >= MAX_OUTBOUND) error(429,'当前 AI 请求较多，请稍后重试','AI_CREDENTIAL_BUSY');
    const row = {id:crypto.randomUUID(),user_id:user.id,chat_id:chat.id,session_hash:auth.tokenHash,provider_hash:null,expires_at:at + TTL_MS,limit_micros:micros,budget_day:day,created_at:at,state:'pending'};
    // Reservations survive restarts. Even uncertain/failed creation outcomes
    // consume their granted cap, so retries cannot bypass the daily ceiling.
    run('INSERT INTO ai_credential_leases(id,user_id,chat_id,session_hash,provider_hash,expires_at,limit_micros,budget_day,created_at,state) VALUES(?,?,?,?,?,?,?,?,?,?)',...Object.values(row));
    const configStamp = stamp(config);
    return track((async () => {
      try {
        const result = await provider('POST','',config.managementKey,{name:'shanshui-' + row.id,expires_at:new Date(row.expires_at).toISOString(),limit:config.credentialLimitUsd,limit_reset:null,include_byok_in_limit:true});
        const hash = result?.data?.hash;
        if (typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash)) { row.provider_hash = hash; run('UPDATE ai_credential_leases SET provider_hash=? WHERE id=?',hash,row.id); }
        const expiry = Date.parse(result?.data?.expires_at), returnedLimit = result?.data?.limit;
        if (!row.provider_hash || typeof result?.key !== 'string' || !/^sk-or-v1-[A-Za-z0-9_-]{20,200}$/.test(result.key) || !Number.isFinite(expiry) || expiry <= clock() || expiry > row.expires_at || !Number.isFinite(returnedLimit) || returnedLimit < 0 || returnedLimit > config.credentialLimitUsd + 0.00000001 || result?.data?.disabled === true || result?.data?.limit_reset != null || result?.data?.include_byok_in_limit !== true) {
          await revokeRow(row,config); error(502,'OpenRouter 没有确认短期凭证的到期时间或消费限额，已拒绝发放','AI_CREDENTIAL_UNSAFE');
        }
        if (stopped || blocked || configStamp !== stamp(getConfig()) || !authorized()) { await revokeRow(row,config); error(409,'账户、会话或 AI 配置已经变化，凭证已取消','AI_CREDENTIAL_CANCELLED'); }
        run("UPDATE ai_credential_leases SET state='active',expires_at=? WHERE id=?",expiry,row.id);
        return {credential:{id:row.id,key:result.key,expiresAt:new Date(expiry).toISOString(),limitUsd:returnedLimit,baseUrl:BASE_URL,model:config.model,apiFormat:'chat_completions'},directOnly:true};
      } catch (cause) {
        run("UPDATE ai_credential_leases SET state='revoking' WHERE id=? AND state='pending'",row.id);
        throw cause;
      }
    })());
  }
  async function release(userId,chatId,leaseId) {
    const row = q('SELECT * FROM ai_credential_leases WHERE id=? AND user_id=? AND chat_id=?',leaseId,userId,chatId);
    if (!row) error(404,'短期凭证不存在或不属于当前账户','AI_CREDENTIAL_NOT_FOUND');
    if (['revoked','expired'].includes(row.state) || row.expires_at <= clock()) return {ok:true};
    const revoked = await revokeRow(row);
    // A failed deletion stays in the bounded revocation queue until provider expiry.
    return {ok:true,revoked,expiresAt:new Date(row.expires_at).toISOString()};
  }
  async function configure(save) {
    if (blocked) error(409,'AI 配置正在更新，请稍后重试','AI_CREDENTIAL_BUSY');
    blocked = true;
    try {
      await Promise.allSettled([...tasks]);
      const config = getConfig();
      await revokeWhere('1=1',[],config);
      if (q("SELECT 1 FROM ai_credential_leases WHERE provider_hash IS NOT NULL AND state='revoking' AND expires_at>?",clock())) error(503,'现有短期凭证暂时无法撤销，请稍后再保存 AI 设置','AI_CREDENTIAL_REVOKE_FAILED');
      save();
    } finally { blocked = false; }
  }
  async function cleanup(authorized) {
    if (cleaning || stopped) return cleaning;
    cleaning = (async () => {
      const at = clock(), config = getConfig();
      const rows = all("SELECT * FROM ai_credential_leases WHERE state NOT IN ('revoked','expired')");
      for (let i = 0; i < rows.length; i += MAX_OUTBOUND) await Promise.all(rows.slice(i,i + MAX_OUTBOUND).map(async row => {
        if (row.expires_at <= at || row.state === 'revoking' || !authorized(row)) await revokeRow(row,config);
        if (row.expires_at <= at) run("UPDATE ai_credential_leases SET state='expired' WHERE id=?",row.id);
      }));
      // Metadata is kept for today's budget and a short audit/restart window.
      // There is no prompt, generated answer, or plaintext inference key here.
      run('DELETE FROM ai_credential_leases WHERE expires_at<? AND budget_day<?',at - 48 * 3600 * 1000,new Date(at).toISOString().slice(0,10));
    })();
    try { await track(cleaning); } finally { cleaning = null; }
  }
  async function stop() { stopped = true; for (const abort of controllers) abort.abort(); await Promise.allSettled([...tasks]); }
  // On restart no inference-key plaintext is available to return to a client.
  // Revoke old leases rather than issuing a second simultaneous capability.
  run("UPDATE ai_credential_leases SET state='revoking' WHERE state IN ('pending','active')");
  return {issue,release,configure,cleanup,stop,revokeSession:hash => revokeWhere('session_hash=?',[hash]),revokeUserExcept:(userId,hash) => revokeWhere('user_id=? AND session_hash<>?',[userId,hash]),revokeChat:chatId => revokeWhere('chat_id=?',[chatId]),revokeRemoved:(chatId,members) => revokeWhere('chat_id=? AND user_id NOT IN (' + members.map(() => '?').join(',') + ')',[chatId,...members])};
}

module.exports = {createCredentialBroker,MANAGEMENT_URL,BASE_URL,TTL_MS,COOLDOWN_MS,DEFAULTS,BOUNDS};
