'use strict';
// User-scoped opaque storage. Only the account's devices can decrypt memory.
const crypto = require('node:crypto');
const MAX_MEMORY_CIPHERTEXT = 256 * 1024;

function createAIMemoryStore({ db, fail, validateCiphertext }) {
  db.exec(`CREATE TABLE IF NOT EXISTS ai_private_memories(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,revision INTEGER NOT NULL,ciphertext TEXT NOT NULL,ciphertext_hash TEXT NOT NULL,updated_at TEXT NOT NULL)`);
  const row = userId => db.prepare('SELECT * FROM ai_private_memories WHERE user_id=?').get(userId);
  function view(userId) {
    const record = row(userId);
    return { memory: record ? { revision: record.revision, ciphertext: record.ciphertext, hash: record.ciphertext_hash } : null };
  }
  async function validate(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 2 || !Object.hasOwn(input, 'baseRevision') || !Object.hasOwn(input, 'ciphertext') || !Number.isSafeInteger(input.baseRevision) || input.baseRevision < 0 || input.baseRevision >= Number.MAX_SAFE_INTEGER || typeof input.ciphertext !== 'string' || Buffer.byteLength(input.ciphertext) > MAX_MEMORY_CIPHERTEXT) fail(400, '长期记忆仅接受加密内容与版本号');
    await validateCiphertext(input.ciphertext);
    return { ...input, hash: crypto.createHash('sha256').update(input.ciphertext).digest('hex') };
  }
  function commit(userId, input) {
    if (!db.prepare('SELECT 1 FROM identities WHERE user_id=?').get(userId)) fail(409, '请先建立加密身份');
    const current = row(userId), revision = current?.revision || 0;
    // A network retry may repeat the exact same already committed operation.
    if (revision === input.baseRevision + 1 && current.ciphertext === input.ciphertext && current.ciphertext_hash === input.hash) return view(userId);
    if (revision !== input.baseRevision) fail(409, '长期记忆已在其他设备更新，请重新载入后再修改', { code: 'AI_MEMORY_CONFLICT' });
    db.prepare('INSERT INTO ai_private_memories(user_id,revision,ciphertext,ciphertext_hash,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision,ciphertext=excluded.ciphertext,ciphertext_hash=excluded.ciphertext_hash,updated_at=excluded.updated_at').run(userId, revision + 1, input.ciphertext, input.hash, new Date().toISOString());
    return view(userId);
  }
  return { view, validate, commit };
}
module.exports = { createAIMemoryStore, MAX_MEMORY_CIPHERTEXT };
