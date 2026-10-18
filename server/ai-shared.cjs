'use strict';
// Only signed metadata and OpenPGP ciphertext belong on the chat server.
// Provider secrets are decrypted exclusively by authorized devices.
const crypto = require('node:crypto');
const net = require('node:net');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HEX = /^[a-f0-9]{64}$/;
const MAX_RECIPIENTS = 200;
const PAYLOAD_KEYS = ['v', 'purpose', 'serverId', 'configId', 'revision', 'previousHash', 'ownerId', 'ownerFingerprint', 'baseUrl', 'model', 'enabled', 'recipients', 'ciphertextHash'];

function createSharedConfigurationStore({ db, serverId, canonical, fail, verifyDetached, validateCiphertext }) {
  db.exec(`CREATE TABLE IF NOT EXISTS ai_shared_configurations(revision INTEGER PRIMARY KEY,config_id TEXT NOT NULL UNIQUE,payload TEXT NOT NULL,signature TEXT NOT NULL,ciphertext TEXT,config_hash TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL);`);
  const sha = value => crypto.createHash('sha256').update(value).digest('hex');
  const q = (sql, ...params) => db.prepare(sql).get(...params);
  const all = (sql, ...params) => db.prepare(sql).all(...params);
  const exact = (value, keys, label) => {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(400, `${label}格式不正确`);
  };
  function currentRow() { return q('SELECT * FROM ai_shared_configurations ORDER BY revision DESC LIMIT 1'); }
  function configuration(row = currentRow()) { return row ? { payload: JSON.parse(row.payload), signature: row.signature, ciphertext: row.ciphertext } : null; }
  function history() { return all('SELECT payload,signature,config_hash FROM ai_shared_configurations ORDER BY revision').map(row => ({ payload: JSON.parse(row.payload), signature: row.signature, hash: row.config_hash })); }
  function currentMetadata() { const row = currentRow(); return row ? JSON.parse(row.payload) : null; }
  function validateBaseUrl(value, serverOrigin) {
    if (typeof value !== 'string' || value.length > 500) fail(400, 'AI 接口地址格式不正确');
    let url; try { url = new URL(value); } catch { fail(400, 'AI 接口地址格式不正确'); }
    const host = url.hostname;
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.port === '0' || net.isIP(host.replace(/^\[|\]$/g, '')) || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host) || /(?:^|\.)(?:localhost|local|internal|lan)$/.test(host) || !/^\/[A-Za-z0-9/_~.-]*$/.test(url.pathname) || value !== (url.origin + url.pathname).replace(/\/+$/, '') || url.origin === serverOrigin) fail(400, 'AI 接口需填写规范的 HTTPS 公网基础地址，例如 https://ai.isok.dev/v1');
  }
  function validateMetadata(payload, adminId) {
    exact(payload, payload?.v === 3 ? [...PAYLOAD_KEYS, 'searchEnabled', 'vision', 'image'] : payload?.v === 2 ? [...PAYLOAD_KEYS, 'searchEnabled'] : PAYLOAD_KEYS, 'AI 签名配置');
    if (![1, 2, 3].includes(payload.v) || payload.v >= 2 && typeof payload.searchEnabled !== 'boolean' || payload.purpose !== 'shanshui-ai-shared' || payload.serverId !== serverId || !UUID.test(payload.configId) || payload.ownerId !== adminId || !Number.isSafeInteger(payload.revision) || payload.revision < 1 || !(payload.previousHash === null || typeof payload.previousHash === 'string' && HEX.test(payload.previousHash)) || typeof payload.enabled !== 'boolean' || typeof payload.ciphertextHash !== 'string' || !HEX.test(payload.ciphertextHash)) fail(400, 'AI 签名配置身份或版本不正确');
    if(payload.v===3) for(const name of ['vision','image']) {
      const profile=payload[name]; exact(profile,['enabled','baseUrl','model'],'多模态模型');
      if(typeof profile.enabled!=='boolean'||typeof profile.baseUrl!=='string'||typeof profile.model!=='string'||profile.enabled&&(!profile.baseUrl||!profile.model)||profile.model&&(!/^[A-Za-z0-9_.:/-]{1,200}$/.test(profile.model)||/:online(?:$|:)/i.test(profile.model))) fail(400,'多模态模型配置不正确');
      if(profile.baseUrl) validateBaseUrl(profile.baseUrl);
    }
    validateBaseUrl(payload.baseUrl);
    if (typeof payload.model !== 'string' || !/^[A-Za-z0-9_.:/-]{1,200}$/.test(payload.model) || /:online(?:$|:)/i.test(payload.model)) fail(400, '模型名称格式不正确，当前直连版本不允许 :online 联网后缀');
    if (!Array.isArray(payload.recipients) || !payload.recipients.length || payload.recipients.length > MAX_RECIPIENTS) fail(400, 'AI 授权配置需包含 1 至 200 位账户');
    let previousId = '';
    for (const recipient of payload.recipients) {
      exact(recipient, ['userId', 'fingerprint'], 'AI 授权账户');
      if (typeof recipient.userId !== 'string' || !UUID.test(recipient.userId) || recipient.userId <= previousId || typeof recipient.fingerprint !== 'string') fail(400, 'AI 授权账户需去重排序');
      const identity = q('SELECT fingerprint FROM identities WHERE user_id=?', recipient.userId);
      if (!identity || identity.fingerprint !== recipient.fingerprint) fail(409, '有账户尚未建立加密身份，或公钥指纹已变化');
      previousId = recipient.userId;
    }
    const owner = q('SELECT i.public_key,i.fingerprint,u.role FROM identities i JOIN users u ON u.id=i.user_id WHERE i.user_id=?', adminId);
    if (!owner || owner.role !== 'admin' || owner.fingerprint !== payload.ownerFingerprint || !payload.recipients.some(recipient => recipient.userId === adminId && recipient.fingerprint === owner.fingerprint)) fail(403, '管理员加密身份不匹配，或未保留自身授权');
    return owner;
  }
  async function validate(signed, adminId, serverOrigin) {
    exact(signed, ['payload', 'signature', 'ciphertext'], 'AI 加密配置包');
    const owner = validateMetadata(signed.payload, adminId);
    validateBaseUrl(signed.payload.baseUrl, serverOrigin);
    if(signed.payload.v===3) for(const name of ['vision','image']) if(signed.payload[name].baseUrl) validateBaseUrl(signed.payload[name].baseUrl,serverOrigin);
    if (typeof signed.ciphertext !== 'string' || sha(signed.ciphertext) !== signed.payload.ciphertextHash) fail(400, 'AI 加密配置校验不一致');
    await validateCiphertext(signed.ciphertext);
    await verifyDetached(signed.payload, signed.signature, owner.public_key);
    return { signed, hash: sha(canonical({ payload: signed.payload, signature: signed.signature })) };
  }
  function commit(validated, adminId) {
    const { signed, hash } = validated;
    validateMetadata(signed.payload, adminId);
    const previous = currentRow();
    if (previous && previous.config_id === signed.payload.configId && previous.config_hash === hash && previous.ciphertext === signed.ciphertext) return;
    if (previous && (JSON.parse(previous.payload).ownerId !== signed.payload.ownerId || JSON.parse(previous.payload).ownerFingerprint !== signed.payload.ownerFingerprint)) fail(409, '共享 AI 配置的签署管理员不能更换', { code: 'AI_SHARED_OWNER_CHANGED' });
    if (previous?.revision >= 4096) fail(409, '共享 AI 配置历史已达到 4096 次上限，请联系开发者处理；当前配置继续有效', { code: 'AI_SHARED_HISTORY_FULL' });
    if (signed.payload.revision !== (previous?.revision || 0) + 1 || signed.payload.previousHash !== (previous?.config_hash || null)) fail(409, 'AI 配置已经更新，请刷新后重新签署', { code: 'AI_SHARED_CONFIGURATION_CHANGED' });
    if (q('SELECT 1 FROM ai_shared_configurations WHERE config_id=?', signed.payload.configId)) fail(409, 'AI 配置标识已经使用，不能重新发布');
    db.prepare('INSERT INTO ai_shared_configurations(revision,config_id,payload,signature,ciphertext,config_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(signed.payload.revision, signed.payload.configId, canonical(signed.payload), signed.signature, signed.ciphertext, hash, new Date().toISOString());
    // Old signed metadata retains the verifiable chain. The previous encrypted
    // key package is no longer needed by any response, so avoid storing copies.
    db.prepare('UPDATE ai_shared_configurations SET ciphertext=NULL WHERE revision<?').run(signed.payload.revision);
  }
  function authorized(userId) { const payload = currentMetadata(); return !!payload?.recipients.some(recipient => recipient.userId === userId && q('SELECT fingerprint FROM identities WHERE user_id=?', userId)?.fingerprint === recipient.fingerprint); }
  function view(userId, active) {
    const payload = currentMetadata(), granted = !!payload && authorized(userId);
    return { mode: active ? 'shared_direct' : null, enabled: !!(active && granted && payload.enabled), authorized: !!(active && granted), pending: !!(active && !granted), configuration: active && granted ? configuration() : null, history: active && granted ? history() : [] };
  }
  return { validate, commit, configuration, history, currentMetadata, authorized, view };
}
module.exports = { createSharedConfigurationStore, MAX_RECIPIENTS };
