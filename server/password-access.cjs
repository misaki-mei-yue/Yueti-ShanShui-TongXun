'use strict';

// The random OpenPGP unlocking secret is still generated on the device. Only
// its password-encrypted, identity-signed envelope is persisted here.
function createPasswordAccessStore({db,serverId,canonical,fail,verifyDetached}) {
  db.exec(`CREATE TABLE IF NOT EXISTS password_access(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,fingerprint TEXT NOT NULL,access TEXT NOT NULL,proof TEXT NOT NULL,revision INTEGER NOT NULL,updated_at TEXT NOT NULL);`);
  const row = userId => db.prepare('SELECT * FROM password_access WHERE user_id=?').get(userId);
  function view(userId) {
    const stored=row(userId);
    return {access:stored?JSON.parse(stored.access):null,proof:stored?stored.proof:null};
  }
  function validBytes(value,length) {
    if(typeof value!=='string'||! /^[A-Za-z0-9_-]+$/.test(value)||value.length!==Math.ceil(length*4/3))return false;
    const bytes=Buffer.from(value,'base64url');
    return bytes.length===length&&bytes.toString('base64url')===value;
  }
  function validateFormat(access,proof) {
    const fields=['v','salt','iv','ciphertext','revision'];
    if(!access||typeof access!=='object'||Array.isArray(access)||Object.keys(access).length!==fields.length||fields.some(field=>!Object.hasOwn(access,field))||access.v!==1||!Number.isSafeInteger(access.revision)||access.revision<1||!validBytes(access.salt,16)||!validBytes(access.iv,12)||!validBytes(access.ciphertext,80))fail(400,'密码保护的加密密钥格式不正确');
    if(typeof proof!=='string'||proof.length>16000||!proof.startsWith('-----BEGIN PGP SIGNATURE-----'))fail(400,'密码保护密钥的签名格式不正确');
  }
  async function validate(userId,identity,access,proof) {
    validateFormat(access,proof);
    if(!identity||identity.userId!==userId)fail(409,'请先建立当前账户的加密身份');
    await verifyDetached({v:1,purpose:'password-access',serverId,userId,fingerprint:identity.fingerprint,access},proof,identity.publicKey);
    return {userId,fingerprint:identity.fingerprint,access,proof};
  }
  // The caller checks authenticated password and session freshness, and invokes
  // this function in the same DB transaction as identity/password updates.
  function commit(value,expectedRevision) {
    const {userId,fingerprint,access,proof}=value,current=row(userId),identity=db.prepare('SELECT fingerprint FROM identities WHERE user_id=?').get(userId);
    if(identity?.fingerprint!==fingerprint||current&&current.fingerprint!==fingerprint)fail(409,'账户加密身份已变化，请重新登录');
    if((current?.revision||0)!==expectedRevision||access.revision!==expectedRevision+1)fail(409,'密码保护的加密密钥已更新，请重新登录后再操作');
    db.prepare('INSERT INTO password_access(user_id,fingerprint,access,proof,revision,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET fingerprint=excluded.fingerprint,access=excluded.access,proof=excluded.proof,revision=excluded.revision,updated_at=excluded.updated_at').run(userId,fingerprint,canonical(access),proof,access.revision,new Date().toISOString());
    return view(userId);
  }
  function provision(value) {
    const current=row(value.userId);
    if(current&&current.fingerprint===value.fingerprint&&current.access===canonical(value.access)&&current.proof===value.proof)return view(value.userId);
    if(current)fail(409,'此账户已启用密码保护，修改密码时才能重新加密密钥');
    return commit(value,0);
  }
  return {row,view,validate,commit,provision};
}
module.exports={createPasswordAccessStore};
