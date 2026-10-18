'use strict';

// 山水通讯 1.3.2: ciphertext storage and prompt-free AI authorization.
const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const { pathToFileURL } = require('node:url');
const { createCredentialBroker, BASE_URL: AI_BASE_URL, DEFAULTS: AI_DEFAULTS, BOUNDS: AI_BOUNDS } = require('./ai-credentials.cjs');
const { createSharedConfigurationStore } = require('./ai-shared.cjs');
const { createAIMemoryStore } = require('./ai-memory.cjs');
const { createAttachmentStore } = require('./attachments.cjs');
const scrypt = promisify(crypto.scrypt);
const VERSION = '1.4.1';
const openpgpReady = import(pathToFileURL(path.join(__dirname, '..', 'public', 'vendor', 'openpgp.min.mjs')).href);
const AI_USER = Object.freeze({ id: 'ai', username: 'ai', displayName: '山岚', avatarUrl: '', role: 'user' });
const MB = 1024 * 1024;
const now = () => new Date().toISOString();
// A freshly signed browser request can arrive before a slightly slower server
// clock reaches its timestamp. Keep OpenPGP checks enabled, with a bounded
// two-minute allowance; larger future timestamps remain invalid.
const verificationDate = () => new Date(Date.now() + 2 * 60 * 1000);
const id = () => crypto.randomUUID();
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}
class ApiError extends Error { constructor(status, message, diagnostics) { super(message); this.status = status; if (diagnostics) this.diagnostics = diagnostics; } }
function fail(status, message, diagnostics) { throw new ApiError(status, message, diagnostics); }
function exactKeys(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key) => !fields.includes(key)) || fields.some((key) => !Object.hasOwn(value, key))) fail(400, `${label}格式不正确`);
}
function string(value, max, label, empty = false) {
  if (typeof value !== 'string' || value.length > max || (!empty && !value.trim())) fail(400, `${label}不正确`);
  return value.trim();
}
function password(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 256) fail(400, '密码需要 8 至 256 个字符');
  return value;
}
async function hashPassword(value) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await scrypt(value, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * MB });
  return `scrypt$${salt}$${hash.toString('hex')}`;
}
async function verifyPassword(value, stored) {
  const [, salt, expected] = String(stored || '').split('$');
  if (!salt || !expected || typeof value !== 'string' || value.length > 256) return false;
  const actual = await scrypt(value, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * MB });
  const other = Buffer.from(expected, 'hex');
  return actual.length === other.length && crypto.timingSafeEqual(actual, other);
}
function verifiedImage(data) {
  // Only inert raster formats with a valid envelope and bounded dimensions.
  // Browsers perform final decoding; user-supplied MIME types are never trusted.
  let mime, width = 0, height = 0;
  if (data.length >= 45 && data.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) {
    if (data.readUInt32BE(8) !== 13 || data.toString('ascii', 12, 16) !== 'IHDR') return null;
    width = data.readUInt32BE(16); height = data.readUInt32BE(20);
    let pos = 8, ended = false, imageData = false;
    while (pos + 12 <= data.length) {
      const length = data.readUInt32BE(pos), type = data.toString('ascii', pos + 4, pos + 8);
      if (length > data.length - pos - 12) return null;
      if (type === 'IDAT') imageData = true;
      pos += length + 12;
      if (type === 'IEND') { ended = length === 0 && pos === data.length; break; }
    }
    if (!ended || !imageData) return null;
    mime = 'image/png';
  } else if (data.length >= 20 && data[0] === 0xff && data[1] === 0xd8 && data.at(-2) === 0xff && data.at(-1) === 0xd9) {
    let pos = 2;
    while (pos + 4 < data.length) {
      if (data[pos++] !== 0xff) return null;
      while (data[pos] === 0xff) pos++;
      const marker = data[pos++];
      if (marker === 0xda) break;
      if (marker === 0xd9 || marker === 0x00) return null;
      if (marker >= 0xd0 && marker <= 0xd7) continue;
      const length = data.readUInt16BE(pos);
      if (length < 2 || pos + length > data.length) return null;
      if ([0xc0, 0xc1, 0xc2].includes(marker) && length >= 8) { height = data.readUInt16BE(pos + 3); width = data.readUInt16BE(pos + 5); }
      pos += length;
    }
    mime = 'image/jpeg';
  } else if (data.length >= 30 && data.toString('ascii', 0, 4) === 'RIFF' && data.toString('ascii', 8, 12) === 'WEBP' && data.readUInt32LE(4) + 8 === data.length) {
    const type = data.toString('ascii', 12, 16);
    if (type === 'VP8X') { width = data.readUIntLE(24, 3) + 1; height = data.readUIntLE(27, 3) + 1; }
    else if (type === 'VP8L' && data[20] === 0x2f) { const bits = data.readUInt32LE(21); width = (bits & 0x3fff) + 1; height = ((bits >> 14) & 0x3fff) + 1; }
    else if (type === 'VP8 ' && data[23] === 0x9d && data[24] === 0x01 && data[25] === 0x2a) { width = data.readUInt16LE(26) & 0x3fff; height = data.readUInt16LE(28) & 0x3fff; }
    mime = 'image/webp';
  }
  return mime && width > 0 && height > 0 && width <= 4096 && height <= 4096 ? mime : null;
}

function createApplication(options = {}) {
  const dataDir = path.resolve(options.dataDir || process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
  const publicDir = path.resolve(options.publicDir || path.join(__dirname, '..', 'public'));
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const filesDir = path.join(dataDir, 'files');
  fs.mkdirSync(filesDir, { recursive: true, mode: 0o700 });
  const dbFile = path.join(dataDir, 'shanshui.sqlite');
  const db = new DatabaseSync(dbFile);
  const schemaVersion = db.prepare('PRAGMA user_version').get().user_version;
  if (schemaVersion > 3) { db.close(); throw new Error('数据版本比服务器更新，禁止降级启动。'); }
  try { fs.chmodSync(dbFile, 0o600); } catch { /* ACLs govern Windows. */ }
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,display_name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',avatar_path TEXT,avatar_mime TEXT,avatar_version TEXT,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL,created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY,creator_id TEXT NOT NULL REFERENCES users(id),max_uses INTEGER NOT NULL,uses INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS chats(id TEXT PRIMARY KEY,kind TEXT NOT NULL,name TEXT NOT NULL,owner_id TEXT NOT NULL REFERENCES users(id),context TEXT NOT NULL DEFAULT 'recent',direct_key TEXT UNIQUE,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS members(chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,user_id TEXT NOT NULL,last_seq INTEGER NOT NULL DEFAULT 0,pinned INTEGER NOT NULL DEFAULT 0,muted INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(chat_id,user_id));
    CREATE INDEX IF NOT EXISTS members_user ON members(user_id,chat_id);
    CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,chat_id TEXT NOT NULL REFERENCES chats(id),owner_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL,size INTEGER NOT NULL,mime TEXT NOT NULL,path TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,client_id TEXT NOT NULL,chat_id TEXT NOT NULL REFERENCES chats(id),sender_id TEXT NOT NULL,text TEXT NOT NULL,file_id TEXT REFERENCES files(id),reply_to TEXT REFERENCES messages(id),created_at TEXT NOT NULL,ai_status TEXT,UNIQUE(sender_id,chat_id,client_id));
    CREATE INDEX IF NOT EXISTS messages_chat ON messages(chat_id,seq);
    CREATE TABLE IF NOT EXISTS saved(user_id TEXT NOT NULL REFERENCES users(id),message_id TEXT NOT NULL REFERENCES messages(id),created_at TEXT NOT NULL,PRIMARY KEY(user_id,message_id));
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);`);
  db.exec('BEGIN IMMEDIATE');
  try {
    const additions = { chats: [['e2ee_revision', 'INTEGER NOT NULL DEFAULT 0']], messages: [['content_version', 'INTEGER NOT NULL DEFAULT 0'], ['envelope', 'TEXT'], ['request_digest', 'TEXT']], files: [['encrypted', 'INTEGER NOT NULL DEFAULT 0'], ['cipher_sha256', 'TEXT']] };
    for (const [table, columns] of Object.entries(additions)) {
      const existing = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((x) => x.name));
      for (const [column, type] of columns) if (!existing.has(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
    db.exec(`CREATE TABLE IF NOT EXISTS identities(user_id TEXT PRIMARY KEY REFERENCES users(id),fingerprint TEXT NOT NULL,public_key TEXT NOT NULL,encrypted_private_key TEXT NOT NULL,proof TEXT NOT NULL,created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS friendships(user_a TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,user_b TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,accepted_at TEXT NOT NULL,PRIMARY KEY(user_a,user_b),CHECK(user_a<user_b));
      CREATE INDEX IF NOT EXISTS friendships_user_b ON friendships(user_b,user_a);
      CREATE TABLE IF NOT EXISTS friend_requests(id TEXT PRIMARY KEY,user_a TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,user_b TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,sender_id TEXT NOT NULL REFERENCES users(id),recipient_id TEXT NOT NULL REFERENCES users(id),status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected','cancelled')),created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(user_a,user_b),CHECK(user_a<user_b),CHECK(sender_id<>recipient_id),CHECK((sender_id=user_a AND recipient_id=user_b) OR (sender_id=user_b AND recipient_id=user_a)));
      CREATE INDEX IF NOT EXISTS friend_requests_recipient ON friend_requests(recipient_id,status);
      CREATE INDEX IF NOT EXISTS friend_requests_sender ON friend_requests(sender_id,status);
      CREATE TABLE IF NOT EXISTS manifests(chat_id TEXT NOT NULL REFERENCES chats(id),revision INTEGER NOT NULL,payload TEXT NOT NULL,signature TEXT NOT NULL,manifest_hash TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(chat_id,revision));
      CREATE TRIGGER IF NOT EXISTS messages_require_ciphertext_insert BEFORE INSERT ON messages
        WHEN NEW.content_version<>1 OR NEW.envelope IS NULL OR NEW.envelope='' OR NEW.text<>'' OR NEW.reply_to IS NOT NULL
        BEGIN SELECT RAISE(ABORT,'E2EE client required'); END;
      CREATE TRIGGER IF NOT EXISTS messages_protect_ciphertext_update BEFORE UPDATE ON messages
        WHEN OLD.content_version=1 AND (NEW.content_version<>1 OR NEW.envelope IS NULL OR NEW.envelope='' OR NEW.text<>'' OR NEW.reply_to IS NOT NULL)
        BEGIN SELECT RAISE(ABORT,'E2EE content cannot be downgraded'); END;
      PRAGMA user_version=3;`);
    db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES('serverInstanceId',?)").run(id());
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); db.close(); throw error; }
  fs.writeFileSync(path.join(dataDir, 'minimum-compatible-schema'), '3\n', { mode: 0o600 });
  db.prepare("UPDATE messages SET ai_status='failed',text=CASE WHEN text='' THEN '升级前的模型生成已中断。' ELSE text || char(10) || '（升级前的模型生成已中断）' END WHERE content_version=0 AND ai_status='generating'").run();
  const serverId = db.prepare("SELECT value FROM settings WHERE key='serverInstanceId'").get().value;
  const sharedAi = createSharedConfigurationStore({ db, serverId, canonical, fail, verifyDetached, validateCiphertext });
  const privateAiMemory = createAIMemoryStore({ db, fail, validateCiphertext });
  const attachments = createAttachmentStore({ db, filesDir, fail, body, json, requireChat, requireChatWrite, validateCiphertext, transaction, ...(options.attachmentReserveBytes===undefined?{}:{reserveBytes:options.attachmentReserveBytes}) });
  const setupFile = path.join(dataDir, 'setup-token');
  let setupToken = options.setupToken || process.env.SETUP_TOKEN || '';
  if (!setupToken && !db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
    try { setupToken = fs.readFileSync(setupFile, 'utf8').trim(); } catch { /* First start. */ }
    if (!setupToken) { setupToken = crypto.randomBytes(24).toString('base64url'); fs.writeFileSync(setupFile, setupToken + '\n', { mode: 0o600 }); }
  }
  const trustProxy = options.trustProxy ?? process.env.TRUST_PROXY === '1';
  const sessionTtl = options.sessionTtlMs || 30 * 24 * 3600 * 1000;
  const events = new Map(), rate = new Map();
  let closing = false;
  const q = (sql, ...params) => db.prepare(sql).get(...params);
  const all = (sql, ...params) => db.prepare(sql).all(...params);
  const run = (sql, ...params) => db.prepare(sql).run(...params);
  function transaction(fn) {
    db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); db.exec('COMMIT'); return value; } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  function userJson(row) {
    if (row?.id === 'ai') return AI_USER;
    return row ? { id: row.id, username: row.username, displayName: row.display_name, role: row.role, avatarUrl: row.avatar_path ? `/api/avatars/${row.id}?v=${row.avatar_version}` : '' } : null;
  }
  function getUser(userId) { return userId === 'ai' ? AI_USER : userJson(q('SELECT * FROM users WHERE id=?', userId)); }
  function friendPair(one, other) { return one < other ? [one, other] : [other, one]; }
  function friendship(userId, otherId) {
    if (userId === otherId) return { friendshipStatus: 'self', friendRequestId: null };
    const pair = friendPair(userId, otherId);
    if (q('SELECT 1 FROM friendships WHERE user_a=? AND user_b=?', ...pair)) return { friendshipStatus: 'accepted', friendRequestId: null };
    const request = q("SELECT id,sender_id FROM friend_requests WHERE user_a=? AND user_b=? AND status='pending'", ...pair);
    return { friendshipStatus: request ? request.sender_id === userId ? 'outgoing' : 'incoming' : 'none', friendRequestId: request?.id || null };
  }
  function friendUserJson(row, userId) { return { ...userJson(row), ...friendship(userId, row.id) }; }
  function friendRequestJson(row, userId) {
    if (!row) return null;
    return { id: row.id, senderId: row.sender_id, recipientId: row.recipient_id, status: row.status, direction: row.sender_id === userId ? 'outgoing' : 'incoming', user: getUser(row.sender_id === userId ? row.recipient_id : row.sender_id), createdAt: row.created_at };
  }
  function requireFriend(userId, otherId) {
    if (friendship(userId, otherId).friendshipStatus !== 'accepted') fail(403, '请先添加好友，待对方通过后再开始聊天', { code: 'FRIENDSHIP_REQUIRED' });
  }
  function directCanMessage(chat, userId) {
    if (chat.kind !== 'direct') return true;
    const humans = all("SELECT user_id FROM members WHERE chat_id=? AND user_id<>'ai'", chat.id).map(row => row.user_id);
    return humans.length === 2 && humans.includes(userId) && friendship(userId, humans.find(other => other !== userId)).friendshipStatus === 'accepted';
  }
  function requireChatWrite(chat, user) { if (!directCanMessage(chat, user.id)) fail(403, '请先添加好友，待对方通过后再开始聊天', { code: 'FRIENDSHIP_REQUIRED' }); }
  function fileJson(row) { return row ? { id: row.id, name: row.encrypted ? '加密附件.pgp' : row.name, size: row.size, mime: row.encrypted ? 'application/octet-stream' : row.mime, encrypted: !!row.encrypted, legacy: !row.encrypted, url: `/api/files/${row.id}`,...attachments.metadata(db.prepare('SELECT * FROM chunked_files WHERE file_id=?').get(row.id)) } : null; }
  function messageJson(row) {
    if (!row) return null;
    const reply = row.reply_to ? q('SELECT id,sender_id,text FROM messages WHERE id=? AND chat_id=?', row.reply_to, row.chat_id) : null;
    return { id: row.id, seq: row.seq, clientId: row.client_id, chatId: row.chat_id, senderId: row.sender_id, contentVersion: row.content_version, envelope: row.content_version === 1 ? JSON.parse(row.envelope) : null, legacy: row.content_version === 0, text: row.content_version === 1 ? '' : row.text, file: row.file_id ? fileJson(q('SELECT * FROM files WHERE id=?', row.file_id)) : null, quote: row.content_version === 0 && reply ? { id: reply.id, senderName: getUser(reply.sender_id)?.displayName || '成员', text: reply.text.slice(0, 500) } : null, createdAt: row.created_at, ...(row.ai_status ? { aiStatus: row.ai_status } : {}) };
  }
  function chatJson(row, userId) {
    const membership = q('SELECT * FROM members WHERE chat_id=? AND user_id=?', row.id, userId);
    const members = all('SELECT user_id FROM members WHERE chat_id=? ORDER BY rowid', row.id).map((x) => getUser(x.user_id)).filter(Boolean);
    let name = row.name;
    if (row.kind === 'direct') name = members.find((x) => x.id !== userId)?.displayName || '私聊';
    const relation = row.kind === 'direct' ? friendship(userId, members.find(member => member.id !== userId && member.id !== 'ai')?.id || '') : { friendshipStatus: null, friendRequestId: null };
    return { id: row.id, name, kind: row.kind, members, canMessage: directCanMessage(row, userId), ...relation, unread: q('SELECT count(*) AS n FROM messages WHERE chat_id=? AND seq>? AND sender_id<>?', row.id, membership.last_seq, userId).n, pinned: !!membership.pinned, muted: !!membership.muted, context: row.context, lastMessage: messageJson(q('SELECT * FROM messages WHERE chat_id=? ORDER BY seq DESC LIMIT 1', row.id)), updatedAt: row.updated_at, ownerId: row.owner_id, e2eeRevision: row.e2ee_revision };
  }
  function requireChat(chatId, user) {
    const chat = q('SELECT c.* FROM chats c JOIN members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?', chatId, user.id);
    if (!chat) fail(404, '会话不存在或无权访问');
    return chat;
  }
  function requireOwner(chat, user) { if (chat.owner_id !== user.id && user.role !== 'admin') fail(403, '只有群主或管理员可以更改此设置'); }
  function requireAdmin(user) { if (user.role !== 'admin') fail(403, '此操作需要管理员权限'); }
  function sendEvent(userIds) {
    const allowed = userIds ? new Set(userIds) : null;
    for (const [res, entry] of events) if (!allowed || allowed.has(entry.userId)) { if (!res.destroyed) res.write('data: {"type":"refresh"}\n\n'); }
  }
  function refreshChat(chatId) { sendEvent(all('SELECT user_id FROM members WHERE chat_id=?', chatId).map((x) => x.user_id)); }
  function closeSessionEvents(tokenHash) {
    for (const [res, entry] of events) if (entry.tokenHash === tokenHash) { res.write('event: auth\ndata: {"type":"expired"}\n\n'); res.end(); events.delete(res); }
  }
  function aiConfig() {
    const row = q("SELECT value FROM settings WHERE key='ai'");
    const config = row ? JSON.parse(row.value) : {};
    if (config.mode === 'shared_direct') {
      const payload = sharedAi.currentMetadata();
      return { ...AI_DEFAULTS, mode: 'shared_direct', baseUrl: payload?.baseUrl || '', model: payload?.model || '', apiFormat: 'chat_completions', enabled: !!payload?.enabled, managementKey: '', needsMigration: false, searchEnabled: payload?.v === 2 && payload.searchEnabled === true, hasTavilyKey: false };
    }
    const compatible = config.mode === 'openrouter_direct';
    return { ...AI_DEFAULTS, ...config, mode: 'openrouter_direct', baseUrl: AI_BASE_URL, apiFormat: 'chat_completions',
      managementKey: compatible ? config.managementKey || '' : '', needsMigration: !!row && !compatible,
      enabled: !!(compatible && config.enabled && config.managementKey && config.model), searchEnabled: false, hasTavilyKey: false };
  }
  function publicAiConfig(config = aiConfig()) {
    if (config.mode === 'shared_direct') return { enabled: !!config.enabled, mode: 'shared_direct', directOnly: true, baseUrl: config.baseUrl, model: config.model, apiFormat: 'chat_completions', hasKey: !!sharedAi.currentMetadata(), hasManagementKey: false, needsMigration: false, credentialLimitUsd: null, dailyUserLimitUsd: null, dailyTotalLimitUsd: null, credentialTtlSeconds: null, credentialCooldownSeconds: null, searchEnabled: !!config.searchEnabled, searchConfigured: !!config.searchEnabled, hasTavilyKey: !!config.searchEnabled };
    return { enabled: !!config.enabled, mode: 'openrouter_direct', directOnly: true, baseUrl: AI_BASE_URL, model: config.model || '', apiFormat: 'chat_completions',
      hasKey: !!config.managementKey, hasManagementKey: !!config.managementKey, needsMigration: !!config.needsMigration,
      credentialLimitUsd: config.credentialLimitUsd, dailyUserLimitUsd: config.dailyUserLimitUsd, dailyTotalLimitUsd: config.dailyTotalLimitUsd,
      credentialTtlSeconds: 300, credentialCooldownSeconds: 10, searchEnabled: false, hasTavilyKey: false };
  }
  function adminAiConfig() {
    return { ...publicAiConfig(), configuration: sharedAi.configuration(), history: sharedAi.history(), candidateUsers: all('SELECT * FROM users ORDER BY display_name').map(row => {
      const identity = q('SELECT fingerprint,public_key FROM identities WHERE user_id=?', row.id);
      return { ...userJson(row), identity: identity ? { fingerprint: identity.fingerprint, publicKey: identity.public_key } : null };
    }) };
  }
  function currentAdmin(userId, tokenHash) {
    const row = q('SELECT u.role FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND s.token_hash=? AND s.expires_at>?', userId, tokenHash, Date.now());
    if (closing || !row || row.role !== 'admin') fail(403, '管理员登录状态已经变化，请重新登录后配置 AI');
  }
  function requestOrigin(req) {
    const host = trustProxy ? String(req.headers['x-forwarded-host'] || req.headers.host).split(',')[0].trim() : req.headers.host;
    const protocol = req.socket.encrypted || trustProxy && req.headers['x-forwarded-proto'] === 'https' ? 'https:' : 'http:';
    try { return new URL(`${protocol}//${host}`).origin; } catch { fail(400, '服务器公开地址格式不正确'); }
  }
  const aiBroker = createCredentialBroker({ db, getConfig: aiConfig, fail,
    ...(options.aiManagementFetch ? {fetchImpl:options.aiManagementFetch} : {}), ...(options.aiCredentialNow ? {clock:options.aiCredentialNow} : {}) });
  function aiAuthorization(userId, chatId, tokenHash) {
    const active = q('SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND expires_at>?', tokenHash,userId,Date.now());
    const allowed = q("SELECT 1 FROM chats c JOIN members me ON me.chat_id=c.id AND me.user_id=? JOIN identities i ON i.user_id=me.user_id WHERE c.id=? AND c.context<>'none' AND (c.kind='direct' OR EXISTS(SELECT 1 FROM members ai WHERE ai.chat_id=c.id AND ai.user_id='ai'))",userId,chatId);
    const chat = allowed && q('SELECT * FROM chats WHERE id=?', chatId);
    const config = aiConfig();
    return !closing && !!active && !!allowed && directCanMessage(chat, userId) && config.enabled && (config.mode !== 'shared_direct' || sharedAi.authorized(userId));
  }
  function canReadIdentity(user, otherId) {
    if (otherId === user.id || user.role === 'admin' || friendship(user.id, otherId).friendshipStatus === 'accepted') return true;
    // A member must still verify old encrypted history after un-friending or a
    // group membership change. Signed historical members are limited to chats
    // the caller is currently permitted to read; they do not form a directory.
    if (q(`SELECT 1 FROM members me WHERE me.user_id=? AND (
      EXISTS(SELECT 1 FROM members peer WHERE peer.chat_id=me.chat_id AND peer.user_id=?) OR
      EXISTS(SELECT 1 FROM manifests mf,json_each(mf.payload,'$.members') entry WHERE mf.chat_id=me.chat_id AND json_extract(entry.value,'$.userId')=?)
      ) LIMIT 1`, user.id, otherId, otherId)) return true;
    const shared = sharedAi.currentMetadata();
    return aiConfig().mode === 'shared_direct' && shared?.ownerId === otherId && sharedAi.authorized(user.id);
  }
  function noAiPayload(req, url) {
    // A credential request is metadata-only and has no request body/query.
    // Reject before buffering or JSON parsing anything supplied by an old client.
    if (url.search || req.headers['transfer-encoding'] !== undefined || req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0') fail(400,'AI 授权接口不接收正文或查询参数，请升级客户端',{code:'AI_CREDENTIAL_NO_CONTENT'});
  }
  function identityJson(row, includeBackup = false) {
    return row ? { userId: row.user_id, fingerprint: row.fingerprint, publicKey: row.public_key, ...(includeBackup ? { encryptedPrivateKey: row.encrypted_private_key } : {}) } : null;
  }
  function manifestJson(row) { return { payload: JSON.parse(row.payload), signature: row.signature }; }
  async function verifyDetached(payload, signature, publicKey) {
    if (typeof signature !== 'string' || signature.length > 16000 || !signature.startsWith('-----BEGIN PGP SIGNATURE-----')) fail(400, '数字签名格式不正确');
    try {
      const pgp = await openpgpReady;
      const key = typeof publicKey === 'string' ? await pgp.readKey({ armoredKey: publicKey }) : publicKey;
      const result = await pgp.verify({ message: await pgp.createMessage({ text: canonical(payload) }), signature: await pgp.readSignature({ armoredSignature: signature }), verificationKeys: key, date: verificationDate() });
      if (result.signatures.length !== 1) fail(400, '数字签名无效');
      await result.signatures[0].verified;
    } catch (error) {
      if (String(error?.message).includes('Signature creation time is in the future')) fail(400, '设备时间与服务器相差过大，请同步系统时间后重新验证。');
      fail(400, '数字签名无效，内容可能被修改');
    }
  }
  async function validateCiphertext(ciphertext, binary = false) {
    if (!binary && (typeof ciphertext !== 'string' || Buffer.byteLength(ciphertext) > 256 * 1024 || !ciphertext.startsWith('-----BEGIN PGP MESSAGE-----') || !ciphertext.trimEnd().endsWith('-----END PGP MESSAGE-----'))) fail(400, '加密消息格式不正确或过大');
    try {
      const pgp = await openpgpReady;
      const message = await pgp.readMessage(binary ? { binaryMessage: new Uint8Array(ciphertext) } : { armoredMessage: ciphertext });
      const tags = [...message.packets].map((packet) => packet.constructor.tag);
      const types = pgp.enums.packet;
      const allowed = [types.publicKeyEncryptedSessionKey, types.symEncryptedIntegrityProtectedData, types.aeadEncryptedData];
      if (!message.getEncryptionKeyIDs().length || tags.some((tag) => !allowed.includes(tag)) || !tags.some((tag) => [types.symEncryptedIntegrityProtectedData, types.aeadEncryptedData].includes(tag))) fail(400, '只接受带完整性保护的公钥加密内容');
    } catch { fail(400, '只接受有效的公钥加密内容，不接受明文或伪装文件'); }
  }
  function validateEnvelope(envelope, chat, user, clientId) {
    exactKeys(envelope, ['v', 'serverId', 'chatId', 'clientId', 'senderId', 'senderFingerprint', 'revision', 'manifestHash', 'recipients', 'ciphertext'], '加密信封');
    const identity = q('SELECT * FROM identities WHERE user_id=?', user.id);
    if (!identity) fail(409, '请先创建或解锁你的加密身份');
    if (envelope.v !== 1 || envelope.serverId !== serverId || envelope.chatId !== chat.id || envelope.clientId !== clientId || envelope.senderId !== user.id || envelope.senderFingerprint !== identity.fingerprint) fail(400, '加密消息身份或会话绑定不正确');
    const current = q('SELECT * FROM manifests WHERE chat_id=? ORDER BY revision DESC LIMIT 1', chat.id);
    if (!current) fail(409, '会话尚未建立加密成员清单');
    if (envelope.revision !== current.revision || envelope.manifestHash !== current.manifest_hash || canonical(envelope.recipients) !== canonical(JSON.parse(current.payload).members)) fail(409, '会话成员或密钥已经变化，请重新核对后发送');
  }
  function securityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data: blob:; connect-src 'self' https:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  }
  function json(res, status, value) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); }
  function ip(req) { return trustProxy ? String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim() : req.socket.remoteAddress; }
  function limited(req, bucket, limit = 20, duration = 15 * 60 * 1000) {
    limitKey(`${bucket}:${ip(req)}`, limit, duration);
  }
  function limitKey(key, limit, duration) {
    let entry = rate.get(key); if (!entry || entry.until < Date.now()) { entry = { count: 0, until: Date.now() + duration }; rate.set(key, entry); }
    if (++entry.count > limit) fail(429, '尝试过于频繁，请稍后再试');
  }
  async function body(req, limit = 256 * 1024, raw = false) {
    if (Number(req.headers['content-length'] || 0) > limit) fail(413, '文件或请求内容过大');
    let total = 0; const chunks = [];
    for await (const chunk of req) { total += chunk.length; if (total > limit) fail(413, '文件或请求内容过大'); chunks.push(chunk); }
    const data = Buffer.concat(chunks);
    if (raw) return data;
    if (req.headers['content-type']?.split(';')[0] !== 'application/json') fail(415, '请使用 JSON 格式');
    try { const value = JSON.parse(data.toString('utf8')); if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, '请求格式不正确'); return value; } catch (e) { if (e instanceof ApiError) throw e; fail(400, 'JSON 格式不正确'); }
  }
  function checkMutation(req) {
    if (req.headers['x-yueti-request'] !== '1') fail(403, '请求校验失败，请刷新后重试');
    const origin = req.headers.origin;
    if (origin) {
      let parsed; try { parsed = new URL(origin); } catch { fail(403, '请求来源无效'); }
      const host = trustProxy ? String(req.headers['x-forwarded-host'] || req.headers.host).split(',')[0].trim() : req.headers.host;
      const protocol = req.socket.encrypted || (trustProxy && req.headers['x-forwarded-proto'] === 'https') ? 'https:' : 'http:';
      if (parsed.host !== host || parsed.protocol !== protocol) fail(403, '不允许跨站请求');
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') fail(403, '不允许跨站请求');
  }
  function cookieToken(req) { return String(req.headers.cookie || '').split(';').map((x) => x.trim()).find((x) => x.startsWith('yueti_session='))?.slice(14) || ''; }
  function session(req) {
    const token = cookieToken(req); if (!token || token.length > 200) fail(401, '请先登录');
    const tokenHash = sha(token);
    const row = q('SELECT s.token_hash,s.expires_at,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?', tokenHash);
    if (!row || row.expires_at <= Date.now()) { if (row) { run('DELETE FROM sessions WHERE token_hash=?', tokenHash); closeSessionEvents(tokenHash); } fail(401, '登录已过期，请重新登录'); }
    return { user: userJson(row), tokenHash, expiresAt: row.expires_at };
  }
  function setCookie(req, res, token, maxAge) {
    const secure = req.socket.encrypted || (trustProxy && req.headers['x-forwarded-proto'] === 'https');
    res.setHeader('Set-Cookie', `yueti_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`);
  }
  function issueSession(req, res, userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    run('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)', sha(token), userId, Date.now() + sessionTtl, now());
    setCookie(req, res, token, Math.floor(sessionTtl / 1000));
  }
  function makeChat(kind, name, userId, memberIds, directKey = null, includeAI = false) {
    const chatId = id(), stamp = now();
    run('INSERT INTO chats(id,kind,name,owner_id,direct_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?)', chatId, kind, name, userId, directKey, stamp, stamp);
    for (const user of new Set([userId, ...memberIds, ...(includeAI ? ['ai'] : [])])) run('INSERT INTO members(chat_id,user_id) VALUES(?,?)', chatId, user);
    return q('SELECT * FROM chats WHERE id=?', chatId);
  }
  function accountValues(data) {
    const username = string(data.username, 32, '用户名').toLowerCase();
    if (!/^[a-z0-9_\-\u4e00-\u9fff]{3,32}$/u.test(username) || username === 'ai') fail(400, '用户名需为 3 至 32 位汉字、字母、数字或下划线');
    return { username, displayName: string(data.displayName || username, 40, '昵称'), password: password(data.password) };
  }
  function createAccount(values, hash, role) {
    if (q('SELECT id FROM users WHERE username=?', values.username)) fail(409, '用户名已被使用');
    const userId = id();
    run('INSERT INTO users(id,username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?,?)', userId, values.username, values.displayName, hash, role, now());
    makeChat('notes', '我的笔记', userId, []);
    return getUser(userId);
  }
  function insertMessage(chatId, senderId, clientId, envelope, requestDigest, fileId = null) {
    const messageId = id(), stamp = now();
    run('INSERT INTO messages(id,client_id,chat_id,sender_id,text,file_id,created_at,content_version,envelope,request_digest) VALUES(?,?,?,?,?,?,?,?,?,?)', messageId, clientId, chatId, senderId, '', fileId, stamp, 1, canonical(envelope), requestDigest);
    run('UPDATE chats SET updated_at=? WHERE id=?', stamp, chatId);
    return q('SELECT * FROM messages WHERE id=?', messageId);
  }

  async function api(req, res, url) {
    const pathname = url.pathname, method = req.method;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) checkMutation(req);
    if (method === 'GET' && pathname === '/api/health') return json(res, 200, { ok: true, version: VERSION });
    if (method === 'GET' && pathname === '/api/bootstrap') return json(res, 200, { needsSetup: !q('SELECT 1 FROM users LIMIT 1'), registrationOpen: false, aiEnabled: aiConfig().enabled, serverInstanceId: serverId, e2eeRequired: true, friendshipRequired: true, sharedAIDirect: true, sharedSearchDirect: true, chunkedAttachments:true, version: VERSION });
    if (method === 'POST' && pathname === '/api/setup') {
      limited(req, 'setup', 10);
      const data = await body(req), values = accountValues(data);
      if (q('SELECT 1 FROM users LIMIT 1')) fail(409, '管理员已经设置，请登录');
      const actual = sha(String(data.setupToken || '')), expected = sha(setupToken);
      if (!setupToken || !crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) fail(403, '初始化口令不正确，请查看服务器部署结果');
      const hash = await hashPassword(values.password);
      const user = transaction(() => { if (q('SELECT 1 FROM users LIMIT 1')) fail(409, '管理员已经设置，请登录'); return createAccount(values, hash, 'admin'); });
      setupToken = ''; try { fs.unlinkSync(setupFile); } catch { /* Environment-only token. */ }
      issueSession(req, res, user.id); return json(res, 201, { user });
    }
    if (method === 'POST' && pathname === '/api/auth/register') {
      limited(req, 'register', 15);
      const data = await body(req), values = accountValues(data), code = string(data.inviteCode, 120, '邀请码');
      const invite = q('SELECT * FROM invites WHERE code=?', code);
      if (!invite || invite.uses >= invite.max_uses || invite.expires_at <= Date.now()) fail(403, '邀请码无效、已用完或已过期');
      const hash = await hashPassword(values.password);
      const user = transaction(() => {
        const changed = run('UPDATE invites SET uses=uses+1 WHERE code=? AND uses<max_uses AND expires_at>?', code, Date.now());
        if (!changed.changes) fail(403, '邀请码无效、已用完或已过期');
        return createAccount(values, hash, 'user');
      });
      issueSession(req, res, user.id); sendEvent(); return json(res, 201, { user });
    }
    if (method === 'POST' && pathname === '/api/auth/login') {
      limited(req, 'login', 30);
      const data = await body(req), username = string(data.username, 32, '用户名').toLowerCase();
      const row = q('SELECT * FROM users WHERE username=?', username);
      const valid = await verifyPassword(data.password, row?.password_hash || 'scrypt$deadbeefdeadbeefdeadbeefdeadbeef$' + '00'.repeat(64));
      if (!valid || !row || q('SELECT password_hash FROM users WHERE id=?', row.id)?.password_hash !== row.password_hash) fail(401, '用户名或密码不正确');
      issueSession(req, res, row.id); return json(res, 200, { user: userJson(row) });
    }
    const auth = session(req), user = auth.user;
    if (req.headers['x-yueti-user'] !== undefined && req.headers['x-yueti-user'] !== user.id) fail(409, '账户已在其他窗口切换，请刷新后重试');
    if (method === 'GET' && pathname === '/api/ai/shared') {
      if (url.search) fail(400, 'AI 配置接口不接收正文或查询参数');
      return json(res, 200, sharedAi.view(user.id, aiConfig().mode === 'shared_direct'));
    }
    if (pathname === '/api/ai/memory') {
      if (url.search) fail(400, '长期记忆接口不接受账户或查询参数');
      if (method === 'GET') return json(res, 200, privateAiMemory.view(user.id));
      if (method === 'PUT') {
        limitKey(`ai-memory:${user.id}`, 120, 60000);
        const data = await privateAiMemory.validate(await body(req, 280 * 1024));
        if (res.destroyed || !q('SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND expires_at>?', auth.tokenHash, user.id, Date.now())) fail(409, '长期记忆修改已取消');
        return json(res, 200, transaction(() => privateAiMemory.commit(user.id, data)));
      }
      fail(405, '长期记忆仅支持读取或保存加密版本');
    }
    if (pathname === '/api/e2ee/identity') {
      if (method === 'GET') return json(res, 200, { identity: identityJson(q('SELECT * FROM identities WHERE user_id=?', user.id), true) });
      if (method === 'POST') {
        limited(req, 'identity', 20);
        const data = await body(req, 160 * 1024);
        exactKeys(data, ['userId', 'fingerprint', 'publicKey', 'encryptedPrivateKey', 'proof'], '加密身份');
        if (data.userId !== user.id || typeof data.fingerprint !== 'string' || !/^[a-f0-9]{40,64}$/.test(data.fingerprint)) fail(400, '加密身份不属于当前用户');
        if (typeof data.publicKey !== 'string' || data.publicKey.length > 64000 || !data.publicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') || typeof data.encryptedPrivateKey !== 'string' || data.encryptedPrivateKey.length > 80000 || !data.encryptedPrivateKey.startsWith('-----BEGIN PGP PRIVATE KEY BLOCK-----')) fail(400, '公钥或加密备份格式不正确');
        let publicKey;
        try {
          const pgp = await openpgpReady;
          publicKey = await pgp.readKey({ armoredKey: data.publicKey });
          const backup = await pgp.readPrivateKey({ armoredKey: data.encryptedPrivateKey });
          if (publicKey.isPrivate() || publicKey.getFingerprint() !== data.fingerprint || backup.getFingerprint() !== data.fingerprint || backup.isDecrypted()) fail(400, '密钥指纹不匹配或私钥备份未加密');
          const date = verificationDate();
          await publicKey.getEncryptionKey(undefined, date); await publicKey.getSigningKey(undefined, date);
        } catch { fail(400, '密钥无效，或私钥备份未加密'); }
        await verifyDetached({ v: 1, serverId, userId: user.id, fingerprint: data.fingerprint }, data.proof, publicKey);
        const existing = q('SELECT * FROM identities WHERE user_id=?', user.id);
        if (existing) {
          if (canonical(identityJson(existing, true)) !== canonical({ userId: data.userId, fingerprint: data.fingerprint, publicKey: data.publicKey, encryptedPrivateKey: data.encryptedPrivateKey })) fail(409, '此账户已绑定加密身份，禁止覆盖或静默换钥');
          return json(res, 200, { identity: identityJson(existing, true) });
        }
        run('INSERT INTO identities(user_id,fingerprint,public_key,encrypted_private_key,proof,created_at) VALUES(?,?,?,?,?,?)', user.id, data.fingerprint, data.publicKey, data.encryptedPrivateKey, data.proof, now());
        sendEvent(); return json(res, 201, { identity: identityJson(q('SELECT * FROM identities WHERE user_id=?', user.id), true) });
      }
    }
    if (method === 'GET' && pathname === '/api/e2ee/keys') {
      const ids = (url.searchParams.get('ids') || '').split(',').filter(Boolean);
      if (ids.length > 100 || ids.some((value) => !/^[a-f0-9-]{36}$/.test(value))) fail(400, '公钥查询列表不正确');
      return json(res, 200, { keys: [...new Set(ids)].filter(otherId => canReadIdentity(user, otherId)).map(otherId => identityJson(q('SELECT * FROM identities WHERE user_id=?', otherId))).filter(Boolean) });
    }
    if (method === 'POST' && pathname === '/api/auth/logout') {
      run('DELETE FROM sessions WHERE token_hash=?', auth.tokenHash); closeSessionEvents(auth.tokenHash);
      await aiBroker.revokeSession(auth.tokenHash); setCookie(req, res, '', 0); return json(res, 200, { ok: true });
    }
    if (method === 'GET' && pathname === '/api/me') return json(res, 200, { user });
    if (method === 'PATCH' && pathname === '/api/me') {
      const data = await body(req), displayName = string(data.displayName, 40, '昵称');
      run('UPDATE users SET display_name=? WHERE id=?', displayName, user.id); sendEvent(); return json(res, 200, { user: getUser(user.id) });
    }
    if (method === 'POST' && pathname === '/api/auth/password') {
      limited(req, 'password', 10); const data = await body(req); password(data.newPassword);
      const row = q('SELECT password_hash FROM users WHERE id=?', user.id);
      if (!(await verifyPassword(data.currentPassword, row.password_hash))) fail(403, '原密码不正确');
      const hashed = await hashPassword(data.newPassword), revoked = all('SELECT token_hash FROM sessions WHERE user_id=? AND token_hash<>?', user.id, auth.tokenHash);
      transaction(() => { run('UPDATE users SET password_hash=? WHERE id=?', hashed, user.id); run('DELETE FROM sessions WHERE user_id=? AND token_hash<>?', user.id, auth.tokenHash); });
      for (const row of revoked) closeSessionEvents(row.token_hash);
      await aiBroker.revokeUserExcept(user.id,auth.tokenHash);
      return json(res, 200, { ok: true });
    }
    if (method === 'PUT' && pathname === '/api/me/avatar') {
      limited(req, 'avatar', 30); const data = await body(req, 3 * MB);
      const previous = q('SELECT avatar_path FROM users WHERE id=?', user.id).avatar_path;
      let filename = null, mime = null;
      if (data.dataUrl !== '') {
        if (typeof data.dataUrl !== 'string') fail(400, '请选择 PNG、JPEG 或 WebP 图片');
        const match = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]*={0,2})$/.exec(data.dataUrl);
        if (!match) fail(400, '请选择 PNG、JPEG 或 WebP 图片');
        const bytes = Buffer.from(match[2], 'base64');
        if (bytes.length > 2 * MB) fail(413, '头像不能超过 2 MB');
        mime = verifiedImage(bytes);
        if (!mime || mime !== `image/${match[1]}`) fail(400, '图片内容无效或尺寸超过 4096 像素');
        filename = `avatar-${id()}`; await fsp.writeFile(path.join(filesDir, filename), bytes, { mode: 0o600 });
      }
      run('UPDATE users SET avatar_path=?,avatar_mime=?,avatar_version=? WHERE id=?', filename, mime, id(), user.id);
      if (previous) await fsp.unlink(path.join(filesDir, previous)).catch(() => {});
      sendEvent(); return json(res, 200, { user: getUser(user.id) });
    }
    let match;
    if (method === 'GET' && (match = /^\/api\/avatars\/([^/]+)$/.exec(pathname))) {
      const row = q('SELECT avatar_path,avatar_mime FROM users WHERE id=?', match[1]);
      if (!row?.avatar_path) fail(404, '用户没有设置头像');
      const bytes = await fsp.readFile(path.join(filesDir, row.avatar_path));
      res.writeHead(200, { 'Content-Type': row.avatar_mime, 'Content-Length': bytes.length, 'Cache-Control': 'private, max-age=300' }); return res.end(bytes);
    }
    if (method === 'GET' && pathname === '/api/users') {
      if ([...url.searchParams.keys()].some(key => key !== 'q') || url.searchParams.getAll('q').length > 1) fail(400, '请只输入一个完整用户名或账户编号');
      const term = (url.searchParams.get('q') || '').trim();
      if (!term) return json(res, 200, { users: [] });
      limitKey(`user-lookup-minute-user:${user.id}`, 10, 60000); limitKey(`user-lookup-hour-user:${user.id}`, 30, 3600000);
      limited(req, 'user-lookup-minute', 10, 60000); limited(req, 'user-lookup-hour', 30, 3600000);
      if (term.length < 3 || term.length > 64) return json(res, 200, { users: [] });
      const normalized = term.toLowerCase(), uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
      const row = uuid.test(normalized) ? q('SELECT * FROM users WHERE id=? AND id<>?', normalized, user.id) : /^[a-z0-9_\-\u4e00-\u9fff]{3,32}$/u.test(normalized) ? q('SELECT * FROM users WHERE username=? AND id<>?', normalized, user.id) : null;
      return json(res, 200, { users: row ? [friendUserJson(row, user.id)] : [] });
    }
    if (method === 'GET' && ['/api/friends', '/api/friend-requests'].includes(pathname)) {
      const requests = all("SELECT * FROM friend_requests WHERE status='pending' AND (sender_id=? OR recipient_id=?) ORDER BY created_at DESC", user.id, user.id).map(row => friendRequestJson(row, user.id));
      if (pathname === '/api/friend-requests') return json(res, 200, { requests });
      const friends = all('SELECT u.* FROM users u JOIN friendships f ON (f.user_a=? AND f.user_b=u.id) OR (f.user_b=? AND f.user_a=u.id) ORDER BY u.display_name', user.id, user.id).map(row => friendUserJson(row, user.id));
      return json(res, 200, { friends, requests });
    }
    if (method === 'POST' && pathname === '/api/friend-requests') {
      limited(req, 'friend-request', 80); limitKey(`friend-request-user:${user.id}`, 20, 15 * 60 * 1000);
      const data = await body(req, 4096); exactKeys(data, ['userId'], '好友申请');
      const otherId = string(data.userId, 100, '用户标识');
      if (otherId === user.id || otherId === 'ai' || !q('SELECT 1 FROM users WHERE id=?', otherId)) fail(400, '请选择其他用户添加好友');
      let created = false;
      const result = transaction(() => {
        const pair = friendPair(user.id, otherId), relation = friendship(user.id, otherId);
        if (relation.friendshipStatus === 'accepted') return { request: null, ...relation };
        const pending = q("SELECT * FROM friend_requests WHERE user_a=? AND user_b=? AND status='pending'", ...pair);
        if (pending) return { request: friendRequestJson(pending, user.id), ...relation };
        const requestId = id(), stamp = now();
        // Reusing the pair replaces the old request ID: an old accept action
        // cannot approve a newly created request or restore a removed friend.
        run("INSERT INTO friend_requests(id,user_a,user_b,sender_id,recipient_id,status,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?) ON CONFLICT(user_a,user_b) DO UPDATE SET id=excluded.id,sender_id=excluded.sender_id,recipient_id=excluded.recipient_id,status='pending',created_at=excluded.created_at,updated_at=excluded.updated_at", requestId, ...pair, user.id, otherId, stamp, stamp);
        created = true;
        return { request: friendRequestJson(q('SELECT * FROM friend_requests WHERE id=?', requestId), user.id), ...friendship(user.id, otherId) };
      });
      sendEvent([user.id, otherId]); return json(res, created ? 201 : 200, result);
    }
    if (method === 'POST' && (match = /^\/api\/friend-requests\/([^/]+)\/(accept|reject|cancel)$/.exec(pathname))) {
      limited(req, 'friend-action', 180); limitKey(`friend-action-user:${user.id}`, 60, 15 * 60 * 1000);
      const requestId = match[1], action = match[2];
      const result = transaction(() => {
        const request = q('SELECT * FROM friend_requests WHERE id=?', requestId);
        if (!request || ![request.sender_id, request.recipient_id].includes(user.id)) fail(404, '好友申请不存在');
        if ((action === 'cancel' ? request.sender_id : request.recipient_id) !== user.id) fail(403, action === 'cancel' ? '只有申请人可以取消申请' : '只有收到申请的用户可以处理申请');
        const next = { accept: 'accepted', reject: 'rejected', cancel: 'cancelled' }[action];
        if (request.status !== 'pending' && request.status !== next) fail(409, '该好友申请已经处理，请刷新后重试');
        if (request.status === 'pending') {
          if (action === 'accept') run('INSERT OR IGNORE INTO friendships(user_a,user_b,accepted_at) VALUES(?,?,?)', request.user_a, request.user_b, now());
          run('UPDATE friend_requests SET status=?,updated_at=? WHERE id=?', next, now(), request.id);
        }
        const otherId = request.sender_id === user.id ? request.recipient_id : request.sender_id;
        return { request: friendRequestJson(q('SELECT * FROM friend_requests WHERE id=?', requestId), user.id), ...friendship(user.id, otherId) };
      });
      sendEvent([result.request.senderId, result.request.recipientId]); return json(res, 200, result);
    }
    if (method === 'DELETE' && (match = /^\/api\/friends\/([^/]+)$/.exec(pathname))) {
      limited(req, 'friend-action', 180); limitKey(`friend-action-user:${user.id}`, 60, 15 * 60 * 1000);
      const otherId = string(match[1], 100, '用户标识');
      if (otherId === user.id || otherId === 'ai' || !q('SELECT 1 FROM users WHERE id=?', otherId)) fail(400, '用户不存在');
      transaction(() => {
        const pair = friendPair(user.id, otherId);
        run('DELETE FROM friendships WHERE user_a=? AND user_b=?', ...pair);
        run("UPDATE friend_requests SET status='cancelled',updated_at=? WHERE user_a=? AND user_b=? AND status='accepted'", now(), ...pair);
      });
      sendEvent([user.id, otherId]); return json(res, 200, { ok: true });
    }
    if (method === 'GET' && pathname === '/api/chats') return json(res, 200, { chats: all('SELECT c.* FROM chats c JOIN members m ON m.chat_id=c.id WHERE m.user_id=? ORDER BY m.pinned DESC,c.updated_at DESC', user.id).map((chat) => chatJson(chat, user.id)) });
    if (method === 'POST' && pathname === '/api/chats') {
      limited(req, 'newchat', 80); const data = await body(req);
      if (!['direct', 'group', 'ai', 'notes'].includes(data.kind)) fail(400, '会话类型不正确');
      if (data.includeAI !== undefined && typeof data.includeAI !== 'boolean') fail(400, 'AI 成员设置不正确');
      if (data.memberIds !== undefined && (!Array.isArray(data.memberIds) || data.memberIds.some((x) => typeof x !== 'string'))) fail(400, '成员列表不正确');
      const memberIds = [...new Set(data.memberIds || [])].filter((x) => x !== user.id);
      if (memberIds.length > 99) fail(400, '一个群聊最多包含 100 位成员');
      if (memberIds.some((member) => member === 'ai' || !q('SELECT id FROM users WHERE id=?', member))) fail(400, '成员不存在');
      if (data.kind === 'direct' && (memberIds.length !== 1 || data.includeAI)) fail(400, '私聊需要选择一位联系人');
      if (['ai', 'notes'].includes(data.kind) && memberIds.length) fail(400, '此会话不能添加其他用户');
      if (['direct', 'group'].includes(data.kind)) for (const memberId of memberIds) requireFriend(user.id, memberId);
      const key = data.kind === 'direct' ? [user.id, ...memberIds].sort().join(':') : ['notes', 'ai'].includes(data.kind) ? `${data.kind}:${user.id}` : null;
      const existing = key ? q('SELECT * FROM chats WHERE direct_key=? OR (kind=? AND owner_id=? AND kind=\'notes\')', key, data.kind, user.id) : null;
      if (existing) return json(res, 200, { chat: chatJson(existing, user.id) });
      const name = data.kind === 'notes' ? '我的笔记' : data.kind === 'ai' ? '山岚' : data.kind === 'group' ? string(data.name || '新群聊', 80, '群聊名称') : '私聊';
      const chat = transaction(() => {
        if (['direct', 'group'].includes(data.kind)) for (const memberId of memberIds) requireFriend(user.id, memberId);
        return makeChat(data.kind, name, user.id, memberIds, key, data.kind === 'ai' || (data.kind === 'group' && data.includeAI));
      });
      refreshChat(chat.id); return json(res, 201, { chat: chatJson(chat, user.id) });
    }
    if ((match = /^\/api\/chats\/([^/]+)(?:\/(messages|members|manifests|read|ai\/stop|ai\/relay|ai\/credential(?:\/[a-f0-9-]{36})?))?$/.exec(pathname))) {
      const chat = requireChat(match[1], user), action = match[2];
      if (method === 'GET' && action === 'manifests') return json(res, 200, { manifests: all('SELECT * FROM manifests WHERE chat_id=? ORDER BY revision', chat.id).map(manifestJson) });
      if (method === 'PUT' && action === 'manifests') {
        if (chat.owner_id !== user.id) fail(403, '只有会话创建者可以签署成员变更');
        requireChatWrite(chat, user);
        const data = await body(req, 64 * 1024); exactKeys(data, ['manifest'], '成员变更');
        const signed = data.manifest; exactKeys(signed, ['payload', 'signature'], '成员清单');
        const payload = signed.payload; exactKeys(payload, ['v', 'serverId', 'chatId', 'kind', 'ownerId', 'revision', 'previousHash', 'members'], '成员清单');
        if (payload.v !== 1 || payload.serverId !== serverId || payload.chatId !== chat.id || payload.kind !== chat.kind || payload.ownerId !== user.id || !Number.isInteger(payload.revision) || payload.revision < 1 || (payload.previousHash !== null && (typeof payload.previousHash !== 'string' || !/^[a-f0-9]{64}$/.test(payload.previousHash)))) fail(400, '成员清单的身份或版本不正确');
        if (!Array.isArray(payload.members) || !payload.members.length || payload.members.length > 100) fail(400, '成员清单需包含 1 至 100 位用户');
        const memberIds = [];
        for (const member of payload.members) {
          exactKeys(member, ['userId', 'fingerprint'], '成员身份');
          if (typeof member.userId !== 'string' || member.userId === 'ai') fail(400, 'AI 不能成为加密收件人');
          const registered = q('SELECT fingerprint FROM identities WHERE user_id=?', member.userId);
          if (!registered || member.fingerprint !== registered.fingerprint) fail(409, '有成员尚未建立加密身份，或公钥指纹不匹配');
          memberIds.push(member.userId);
        }
        if (new Set(memberIds).size !== memberIds.length || !memberIds.includes(user.id) || canonical(memberIds) !== canonical([...memberIds].sort())) fail(400, '成员需要去重排序，并保留会话创建者');
        if ((['notes', 'ai'].includes(chat.kind) && (memberIds.length !== 1 || memberIds[0] !== chat.owner_id)) || (chat.kind === 'direct' && memberIds.length !== 2)) fail(400, '私聊、笔记和 AI 会话的人数不正确');
        const ownerIdentity = q('SELECT * FROM identities WHERE user_id=?', user.id);
        await verifyDetached(payload, signed.signature, ownerIdentity.public_key);
        const hash = sha(canonical(signed));
        const formerMembers = all('SELECT user_id FROM members WHERE chat_id=?', chat.id).map((x) => x.user_id);
        transaction(() => {
          requireChatWrite(requireChat(chat.id, user), user);
          const current = q('SELECT * FROM manifests WHERE chat_id=? ORDER BY revision DESC LIMIT 1', chat.id);
          if (payload.revision !== (current?.revision || 0) + 1 || payload.previousHash !== (current?.manifest_hash || null)) fail(409, '成员清单版本过期，请刷新后重新签署');
          const currentHumans = all("SELECT user_id FROM members WHERE chat_id=? AND user_id<>'ai' ORDER BY user_id", chat.id).map((x) => x.user_id);
          if ((!current || chat.kind !== 'group') && canonical(memberIds) !== canonical(currentHumans)) fail(400, '初始成员须与会话一致，私聊和笔记不能更换成员');
          if (chat.kind === 'group') for (const memberId of memberIds) if (!currentHumans.includes(memberId)) requireFriend(user.id, memberId);
          run('INSERT INTO manifests(chat_id,revision,payload,signature,manifest_hash,created_at) VALUES(?,?,?,?,?,?)', chat.id, payload.revision, canonical(payload), signed.signature, hash, now());
          for (const oldId of currentHumans) if (!memberIds.includes(oldId)) run('DELETE FROM members WHERE chat_id=? AND user_id=?', chat.id, oldId);
          for (const memberId of memberIds) run('INSERT OR IGNORE INTO members(chat_id,user_id) VALUES(?,?)', chat.id, memberId);
          run('UPDATE chats SET e2ee_revision=?,updated_at=? WHERE id=?', payload.revision, now(), chat.id);
        });
        await aiBroker.revokeRemoved(chat.id,memberIds);
        sendEvent([...formerMembers, ...memberIds]); return json(res, 200, { chat: chatJson(q('SELECT * FROM chats WHERE id=?', chat.id), user.id), manifest: signed });
      }
      if (method === 'PATCH' && !action) {
        const data = await body(req);
        if (data.name !== undefined || data.context !== undefined) requireOwner(chat, user);
        let name;
        if (data.name !== undefined) { if (chat.kind !== 'group') fail(400, '只有群聊可以更名'); name = string(data.name, 80, '群聊名称'); }
        if (data.context !== undefined && !['recent', 'mention', 'none'].includes(data.context)) fail(400, 'AI 上下文范围不正确');
        for (const flag of ['pinned', 'muted']) if (data[flag] !== undefined && typeof data[flag] !== 'boolean') fail(400, '会话设置不正确');
        transaction(() => {
          if (name !== undefined) run('UPDATE chats SET name=? WHERE id=?', name, chat.id);
          if (data.context !== undefined) run('UPDATE chats SET context=? WHERE id=?', data.context, chat.id);
          for (const flag of ['pinned', 'muted']) if (data[flag] !== undefined) run(`UPDATE members SET ${flag}=? WHERE chat_id=? AND user_id=?`, +data[flag], chat.id, user.id);
        });
        if (data.context === 'none') await aiBroker.revokeChat(chat.id);
        refreshChat(chat.id); return json(res, 200, { chat: chatJson(q('SELECT * FROM chats WHERE id=?', chat.id), user.id) });
      }
      if (method === 'POST' && action === 'members') fail(426, '请升级客户端并使用签名成员清单更改成员');
      if (method === 'GET' && action === 'messages') {
        const rawBefore = url.searchParams.get('before'), before = rawBefore ? Number(rawBefore) : Number.MAX_SAFE_INTEGER;
        const limit = Number(url.searchParams.get('limit') || 50);
        if (!Number.isSafeInteger(before) || before < 1 || !Number.isInteger(limit) || limit < 1 || limit > 100) fail(400, '分页参数不正确');
        const rows = all('SELECT * FROM messages WHERE chat_id=? AND seq<? ORDER BY seq DESC LIMIT ?', chat.id, before, limit + 1);
        return json(res, 200, { messages: rows.slice(0, limit).reverse().map(messageJson), hasMore: rows.length > limit });
      }
      if (method === 'POST' && action === 'messages') {
        requireChatWrite(chat, user);
        limited(req, 'message', 300, 60000); const data = await body(req, 320 * 1024);
        requireChatWrite(requireChat(chat.id, user), user);
        if (Object.keys(data).some((key) => !['clientId', 'envelope', 'fileId'].includes(key))) fail(426, '新消息必须端到端加密，请升级客户端后重试');
        const clientId = string(data.clientId, 100, '消息标识');
        if (!data.envelope) fail(426, '新消息必须端到端加密，请升级客户端后重试');
        if (data.fileId !== undefined && (typeof data.fileId !== 'string' || !data.fileId || data.fileId.length > 100)) fail(400, '附件标识不正确');
        const requestDigest = sha(canonical(data));
        const existing = q('SELECT * FROM messages WHERE chat_id=? AND sender_id=? AND client_id=?', chat.id, user.id, clientId);
        if (existing) {
          if (existing.content_version !== 1 || existing.request_digest !== requestDigest) fail(409, '消息标识已被其他内容使用，不能覆盖');
          return json(res, 200, { message: messageJson(existing) });
        }
        validateEnvelope(data.envelope, chat, user, clientId);
        await validateCiphertext(data.envelope.ciphertext);
        if (data.fileId && !q('SELECT id FROM files WHERE id=? AND chat_id=? AND owner_id=? AND encrypted=1', data.fileId, chat.id, user.id)) fail(403, '只能发送属于当前用户和会话的加密附件');
        if (data.fileId) attachments.assertSend(data.fileId,chat,user,data.envelope);
        const row = transaction(() => {
          requireChatWrite(requireChat(chat.id, user), user);
          const concurrent = q('SELECT * FROM messages WHERE chat_id=? AND sender_id=? AND client_id=?', chat.id, user.id, clientId);
          if (concurrent) { if (concurrent.content_version !== 1 || concurrent.request_digest !== requestDigest) fail(409, '消息标识已被其他内容使用，不能覆盖'); return concurrent; }
          validateEnvelope(data.envelope, chat, user, clientId);
          if (data.fileId) attachments.assertSend(data.fileId,chat,user,data.envelope);
          const item = insertMessage(chat.id, user.id, clientId, data.envelope, requestDigest, data.fileId || null);
          run('UPDATE members SET last_seq=max(last_seq,?) WHERE chat_id=? AND user_id=?', item.seq, chat.id, user.id);
          return q('SELECT * FROM messages WHERE id=?', item.id);
        });
        refreshChat(chat.id); return json(res, 201, { message: messageJson(row) });
      }
      if (method === 'POST' && action === 'read') {
        const data = await body(req), seq = Number(data.lastSeq);
        if (!Number.isSafeInteger(seq) || seq < 0) fail(400, '已读位置不正确');
        const max = q('SELECT coalesce(max(seq),0) AS seq FROM messages WHERE chat_id=?', chat.id).seq;
        const cursor = Math.min(seq, max);
        const changed = run('UPDATE members SET last_seq=? WHERE chat_id=? AND user_id=? AND last_seq<?', cursor, chat.id, user.id, cursor);
        // A sent message already advances its sender's cursor. Acknowledging it
        // again must not trigger another full encrypted-message refresh.
        if (changed.changes) sendEvent([user.id]);
        return json(res, 200, { ok: true });
      }
      if (method === 'POST' && action === 'ai/stop') fail(426, 'AI 已改为客户端直连，请升级客户端后在本机停止请求');
      if (method === 'POST' && action === 'ai/relay') {
        // No body() call: plaintext is never parsed, persisted, or sent upstream.
        fail(410, 'AI 正文中转已关闭，请升级客户端使用直连；聊天服务器不再接收 AI 正文', {code:'AI_RELAY_DISABLED'});
      }
      if (method === 'POST' && action === 'ai/credential') {
        requireChatWrite(chat, user);
        noAiPayload(req,url); limited(req,'ai-credential',120,60000);
        const authorized = () => !res.destroyed && aiAuthorization(user.id,chat.id,auth.tokenHash);
        if (aiConfig().mode === 'shared_direct') {
          if (!aiConfig().enabled) fail(503, 'AI 尚未启用，请联系管理员', { code: 'AI_DIRECT_NOT_CONFIGURED' });
          if (!sharedAi.authorized(user.id)) fail(403, '管理员尚未向你的加密身份授权 AI，请等待管理员确认', { code: 'AI_SHARED_NOT_AUTHORIZED' });
          if (!authorized()) fail(403, '此账户或会话当前不能使用 AI', { code: 'AI_CREDENTIAL_FORBIDDEN' });
          const view = sharedAi.view(user.id, true);
          return json(res, 201, { credential: { mode: 'shared_direct', configuration: view.configuration, history: view.history }, directOnly: true });
        }
        const result = await aiBroker.issue(user,chat,auth,authorized);
        if (!authorized()) { await aiBroker.release(user.id,chat.id,result.credential.id); fail(409,'本次 AI 授权已取消',{code:'AI_CREDENTIAL_CANCELLED'}); }
        return json(res,201,result);
      }
      if (method === 'DELETE' && action?.startsWith('ai/credential/')) {
        noAiPayload(req,url);
        if (aiConfig().mode === 'shared_direct') return json(res, 200, { ok: true, mode: 'shared_direct' });
        return json(res,200,await aiBroker.release(user.id,chat.id,action.slice('ai/credential/'.length)));
      }
    }
    if (pathname.startsWith('/api/files/') && await attachments.handle(req,res,url,user)) return;
    if (method === 'GET' && pathname === '/api/notifications') {
      const chats=all(`SELECT me.chat_id AS id,me.muted,
        (SELECT count(*) FROM messages msg WHERE msg.chat_id=me.chat_id AND msg.seq>me.last_seq AND msg.sender_id<>me.user_id) AS unread,
        (SELECT coalesce(max(msg.seq),0) FROM messages msg WHERE msg.chat_id=me.chat_id AND msg.sender_id<>me.user_id) AS latestIncomingSeq
        FROM members me WHERE me.user_id=? ORDER BY me.chat_id`,user.id).map(r=>({...r,muted:!!r.muted}));
      return json(res,200,{userId:user.id,chats});
    }
    if (method === 'POST' && pathname === '/api/files') {
      limited(req, 'upload', 40); const chatId = url.searchParams.get('chatId'); requireChatWrite(requireChat(chatId, user), user);
      if (url.searchParams.get('encrypted') !== '1' || url.searchParams.has('name')) fail(426, '附件必须先在客户端加密，不能上传明文或原始文件名');
      if (!q('SELECT 1 FROM identities WHERE user_id=?', user.id)) fail(409, '请先建立加密身份');
      const bytes = await body(req, 24 * MB, true); if (!bytes.length) fail(400, '不能上传空文件');
      await validateCiphertext(bytes, true);
      requireChatWrite(requireChat(chatId, user), user);
      const fileId = id(), diskName = `file-${fileId}`;
      await fsp.writeFile(path.join(filesDir, diskName), bytes, { mode: 0o600 });
      try {
        transaction(() => {
          requireChatWrite(requireChat(chatId, user), user);
          run('INSERT INTO files(id,chat_id,owner_id,name,size,mime,path,created_at,encrypted,cipher_sha256) VALUES(?,?,?,?,?,?,?,?,1,?)', fileId, chatId, user.id, '加密附件.pgp', bytes.length, 'application/octet-stream', diskName, now(), sha(bytes));
        });
      } catch (error) { await fsp.unlink(path.join(filesDir, diskName)).catch(() => {}); throw error; }
      return json(res, 201, { file: fileJson(q('SELECT * FROM files WHERE id=?', fileId)) });
    }
    if (method === 'GET' && (match = /^\/api\/files\/([^/]+)$/.exec(pathname))) {
      const row = q('SELECT * FROM files WHERE id=?', match[1]); if (!row) fail(404, '附件不存在'); requireChat(row.chat_id, user);
      if (row.owner_id !== user.id && !q('SELECT 1 FROM messages WHERE file_id=? AND chat_id=?', row.id, row.chat_id)) fail(404, '附件尚未发送');
      const inline = !row.encrypted && url.searchParams.get('inline') === '1' && ['image/png', 'image/jpeg', 'image/webp'].includes(row.mime);
      const stat = await fsp.stat(path.join(filesDir, row.path));
      res.writeHead(200, { 'Content-Type': inline ? row.mime : 'application/octet-stream', 'Content-Length': stat.size, 'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="download"; filename*=UTF-8''${encodeURIComponent(row.name).replace(/['()]/g, (c) => '%' + c.charCodeAt(0).toString(16))}`, 'Cache-Control': 'private, no-store', 'Content-Security-Policy': "default-src 'none'; sandbox" });
      const stream = fs.createReadStream(path.join(filesDir, row.path)); stream.on('error', () => res.destroy()); res.on('close', () => stream.destroy()); stream.pipe(res); return;
    }
    if (method === 'GET' && pathname === '/api/search') return json(res, 410, { error: '端到端加密消息请在本机搜索', clientSearchRequired: true });
    if (method === 'GET' && pathname === '/api/saved') {
      const rows = all('SELECT msg.* FROM saved s JOIN messages msg ON msg.id=s.message_id JOIN members m ON m.chat_id=msg.chat_id AND m.user_id=s.user_id WHERE s.user_id=? ORDER BY s.created_at DESC LIMIT 500', user.id);
      return json(res, 200, { items: rows.map((row) => ({ message: messageJson(row), chatName: chatJson(q('SELECT * FROM chats WHERE id=?', row.chat_id), user.id).name, senderName: getUser(row.sender_id)?.displayName || '成员' })) });
    }
    if (['PUT', 'DELETE'].includes(method) && (match = /^\/api\/messages\/([^/]+)\/saved$/.exec(pathname))) {
      const row = q('SELECT * FROM messages WHERE id=?', match[1]); if (!row) fail(404, '消息不存在'); requireChat(row.chat_id, user);
      if (method === 'PUT') run('INSERT OR IGNORE INTO saved(user_id,message_id,created_at) VALUES(?,?,?)', user.id, row.id, now()); else run('DELETE FROM saved WHERE user_id=? AND message_id=?', user.id, row.id);
      sendEvent([user.id]); return json(res, 200, { ok: true });
    }
    if (method === 'GET' && pathname === '/api/events') {
      if ([...events.values()].filter((entry) => entry.userId === user.id).length >= 12) fail(429, '打开的页面过多，请关闭部分窗口');
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
      res.write('retry: 3000\ndata: {"type":"refresh"}\n\n');
      events.set(res, { userId: user.id, tokenHash: auth.tokenHash, expiresAt: auth.expiresAt });
      const timer = setInterval(() => {
        const valid = q('SELECT expires_at FROM sessions WHERE token_hash=?', auth.tokenHash);
        if (!valid || valid.expires_at <= Date.now()) { closeSessionEvents(auth.tokenHash); return; }
        if (!res.destroyed) res.write(': heartbeat\n\n');
      }, options.heartbeatMs || 15000); timer.unref();
      res.on('close', () => { clearInterval(timer); events.delete(res); }); return;
    }
    if (pathname.startsWith('/api/admin/')) {
      requireAdmin(user);
      if (pathname === '/api/admin/invites') {
        if (method === 'GET') return json(res, 200, { invites: all('SELECT code,max_uses AS maxUses,uses,created_at AS createdAt,expires_at AS expiresAt FROM invites ORDER BY created_at DESC LIMIT 100') });
        if (method === 'POST') {
          const data = await body(req), maxUses = data.maxUses ?? 1;
          if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 100) fail(400, '邀请码次数需为 1 至 100 次');
          const code = crypto.randomBytes(12).toString('base64url'), createdAt = now(), expiresAt = Date.now() + 14 * 24 * 3600 * 1000;
          run('INSERT INTO invites(code,creator_id,max_uses,created_at,expires_at) VALUES(?,?,?,?,?)', code, user.id, maxUses, createdAt, expiresAt);
          return json(res, 201, { invite: { code, maxUses, uses: 0, createdAt, expiresAt } });
        }
      }
      if (pathname === '/api/admin/ai') {
        if (method === 'GET') return json(res, 200, adminAiConfig());
        if (method === 'PUT') {
          const data = await body(req, 512 * 1024);
          if (data.mode === 'shared_direct') {
            exactKeys(data, ['mode', 'configuration'], 'AI 共享配置');
            const validated = await sharedAi.validate(data.configuration, user.id, requestOrigin(req));
            await aiBroker.configure(() => transaction(() => {
              currentAdmin(user.id, auth.tokenHash);
              sharedAi.commit(validated, user.id);
              run("INSERT INTO settings(key,value) VALUES('ai',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", JSON.stringify({ mode: 'shared_direct' }));
            }));
            sendEvent(); return json(res, 200, adminAiConfig());
          }
          if (sharedAi.currentMetadata()) fail(409, '共享 AI 配置必须由管理员在本机签署，不能使用未签名设置覆盖', { code: 'AI_SHARED_SIGNED_CONFIGURATION_REQUIRED' });
          if (typeof data.enabled !== 'boolean') fail(400, 'AI 开关不正确');
          const fields = ['enabled','mode','model','managementKey',...Object.keys(AI_BOUNDS)];
          if (Object.keys(data).some(key => !fields.includes(key)) || data.mode !== 'openrouter_direct') fail(400,'AI 已改为 OpenRouter 客户端直连，请升级设置界面并配置 Management API Key',{code:'AI_DIRECT_CONFIG_REQUIRED'});
          const model = string(data.model ?? '', 200, '模型名称', !data.enabled);
          if (model && (!/^[a-z0-9][a-z0-9._:/-]{0,199}$/i.test(model) || /:online\b/i.test(model))) fail(400,'模型名称需为 OpenRouter 模型标识；当前直连版本不允许 :online 联网后缀');
          const previous = aiConfig(), managementKey = data.managementKey === undefined ? previous.managementKey : string(data.managementKey,1000,'OpenRouter 管理密钥',true);
          if (managementKey && !/^sk-or-v1-[A-Za-z0-9_-]{20,200}$/.test(managementKey)) fail(400,'请填写 OpenRouter Management API Key，普通模型密钥不能替代管理密钥');
          if (data.enabled && !managementKey) fail(400,'启用 AI 需要重新配置 OpenRouter Management API Key');
          const config = {enabled:data.enabled,mode:'openrouter_direct',model,managementKey};
          for (const [field,[min,max]] of Object.entries(AI_BOUNDS)) {
            const value = Object.hasOwn(data,field) ? data[field] : previous[field];
            if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max || Math.abs(value * 100 - Math.round(value * 100)) > 0.000001) fail(400,`${field} 需要 ${min} 至 ${max} 美元，最多两位小数`);
            config[field] = value;
          }
          if (config.credentialLimitUsd > config.dailyUserLimitUsd || config.dailyUserLimitUsd > config.dailyTotalLimitUsd) fail(400,'单次额度不能超过每用户日额度，每用户日额度不能超过全站日额度');
          await aiBroker.configure(() => run("INSERT INTO settings(key,value) VALUES('ai',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",JSON.stringify(config)));
          sendEvent(); return json(res,200,publicAiConfig(config));
        }
      }
    }
    fail(404, '接口不存在');
  }

  const staticTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.otf': 'font/otf', '.ico': 'image/x-icon' };
  const server = http.createServer(async (req, res) => {
    securityHeaders(res);
    try {
      if (closing) fail(503, '服务正在重新启动，请稍后重试');
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) return await api(req, res, url);
      if (!['GET', 'HEAD'].includes(req.method)) fail(405, '请求方式不支持');
      let pathname; try { pathname = decodeURIComponent(url.pathname); } catch { fail(400, '地址无效'); }
      if (pathname.includes('\0') || pathname.includes('\\') || pathname.split('/').some((part) => part.startsWith('.'))) fail(404, '页面不存在');
      const filename = path.resolve(publicDir, `.${pathname === '/' ? '/index.html' : pathname}`);
      if (!filename.startsWith(publicDir + path.sep)) fail(404, '页面不存在');
      let actual; try { actual = await fsp.realpath(filename); } catch { fail(404, '页面不存在'); }
      const publicReal = await fsp.realpath(publicDir);
      if (!actual.startsWith(publicReal + path.sep)) fail(404, '页面不存在');
      const stat = await fsp.stat(actual); if (!stat.isFile()) fail(404, '页面不存在');
      res.writeHead(200, { 'Content-Type': staticTypes[path.extname(actual).toLowerCase()] || 'application/octet-stream', 'Content-Length': stat.size, 'Cache-Control': /\.(html|mjs|js|css)$/.test(actual) ? 'no-cache' : 'public, max-age=86400' });
      if (req.method === 'HEAD') return res.end();
      const stream = fs.createReadStream(actual); stream.on('error', () => res.destroy()); res.on('close', () => stream.destroy()); stream.pipe(res);
    } catch (error) {
      if (res.headersSent) { res.end(); return; }
      const status = error instanceof ApiError ? error.status : error.code === 'ENOENT' ? 404 : 500;
      if (status === 500) console.error(`[${now()}] request failed: ${error.code || error.name || 'Error'}`);
      json(res, status, { error: error instanceof ApiError ? error.message : status === 404 ? '文件不存在' : '服务器暂时无法完成请求，请稍后重试', ...(error instanceof ApiError && error.diagnostics ? { diagnostics: error.diagnostics } : {}) });
      if (!req.complete) req.resume();
    }
  });
  server.requestTimeout = 120000; server.headersTimeout = 15000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 60;
  const cleanup = setInterval(() => {
    const expired = all('SELECT token_hash FROM sessions WHERE expires_at<=?', Date.now());
    run('DELETE FROM sessions WHERE expires_at<=?', Date.now());
    for (const row of expired) closeSessionEvents(row.token_hash);
    for (const [key, entry] of rate) if (entry.until < Date.now()) rate.delete(key);
    aiBroker.cleanup(row => aiAuthorization(row.user_id,row.chat_id,row.session_hash)).catch(() => {});
    attachments.cleanup().catch(() => {});
  }, 60000); cleanup.unref();
  aiBroker.cleanup(row => aiAuthorization(row.user_id,row.chat_id,row.session_hash)).catch(() => {});
  async function close() {
    if (closing) return; closing = true; clearInterval(cleanup);
    for (const res of events.keys()) res.end(); events.clear();
    await aiBroker.stop();
    await new Promise((resolve) => { server.close(resolve); server.closeIdleConnections(); });
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close();
  }
  return { server, close, dataDir, db, setupFile, serverId, version: VERSION, aiCredentials: aiBroker };
}

if (require.main === module) {
  const application = createApplication();
  const port = Number(process.env.PORT || 18088), host = process.env.HOST || '127.0.0.1';
  if (!Number.isInteger(port) || port < 1 || port > 65535) { console.error('PORT must be 1-65535'); process.exit(1); }
  application.server.listen(port, host, () => {
    console.log(`山水通讯 ${VERSION} listening on ${host}:${port}`);
    console.log(`Persistent data: ${application.dataDir}`);
    if (fs.existsSync(application.setupFile)) console.log(`首次设置口令请查看 ${application.setupFile}`);
  });
  application.server.on('error', (error) => { console.error(`Server failed: ${error.code || error.message}`); process.exit(1); });
  const shutdown = () => { const timer = setTimeout(() => process.exit(1), 10000); timer.unref(); application.close().then(() => process.exit(0)).catch(() => process.exit(1)); };
  process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);
}
module.exports = { createApplication, verifiedImage, canonical };
