import * as pgp from './vendor/openpgp.min.mjs';
import {ArchiveAssist} from './archive-assist.mjs';
pgp.config.maxDecompressedMessageSize = 24 * 1024 * 1024;

// The cryptographic operations are OpenPGP.js primitives. This module binds them
// to immutable account identities, signed membership and application messages.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}
const utf8 = new TextEncoder();
export async function digest(value) {
  const bytes = typeof value === 'string' ? utf8.encode(value) : value instanceof Uint8Array ? value : utf8.encode(canonical(value));
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), x => x.toString(16).padStart(2, '0')).join('');
}
// Assistance returns an operation-local copy, never a private or long-term key.
// Best effort: release its mutable bytes immediately after consuming them.
export function wipeSessionKeys(options) {
  const keys=options?.sessionKeys;
  for(const key of Array.isArray(keys)?keys:keys?[keys]:[]) if(key?.data instanceof Uint8Array) key.data.fill(0);
}
const same = (a, b) => canonical(a) === canonical(b);
const fail = message => { throw new Error(message); };
const MAX_FILE = 20 * 1024 * 1024;
const bindings = e => ({ v:e.v, serverId:e.serverId, chatId:e.chatId, clientId:e.clientId, senderId:e.senderId, senderFingerprint:e.senderFingerprint, revision:e.revision, manifestHash:e.manifestHash, recipients:e.recipients });
const isArmor = (s, kind) => typeof s === 'string' && s.startsWith(`-----BEGIN PGP ${kind}-----`);
const cleanCode = code => String(code || '').replace(/[\s-]/g, '').toUpperCase();
// A password unlocks a randomly generated private-key passphrase. The account
// password itself is not saved in the device vault. Legacy codes remain usable
// only as a one-time migration path for old identities.
const passwordIterations=600000;
const passwordBytes=password=>{
  if(typeof password!=='string'||password.length<1||password.length>128) fail('请输入账户密码。');
  return utf8.encode(password);
};
const b64url=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function unbase64(value,length) {
  if(typeof value!=='string'||!(/^[A-Za-z0-9_-]+$/).test(value)||value.length!==Math.ceil(length*8/6)) fail('密码保护记录格式无效。');
  const bytes=Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
  if(bytes.length!==length||b64url(bytes)!==value) fail('密码保护记录格式无效。');
  return bytes;
}
function accessAad(box,fingerprint,revision) { return {v:1,purpose:'password-access',serverId:box.serverId,userId:box.user.id,fingerprint,revision}; }
function accessBinding(box,fingerprint,access) { return {v:1,purpose:'password-access',serverId:box.serverId,userId:box.user.id,fingerprint,access}; }
function validatePasswordAccess(access) {
  if(!access||typeof access!=='object'||Array.isArray(access)||Object.keys(access).sort().join(',')!=='ciphertext,iv,revision,salt,v'||access.v!==1||!Number.isSafeInteger(access.revision)||access.revision<1) fail('密码保护记录格式无效。');
  return {salt:unbase64(access.salt,16),iv:unbase64(access.iv,12),ciphertext:unbase64(access.ciphertext,80)};
}
async function passwordKey(password,salt) {
  const bytes=passwordBytes(password);
  try {
    const input=await crypto.subtle.importKey('raw',bytes,'PBKDF2',false,['deriveKey']);
    return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:passwordIterations},input,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  } finally {bytes.fill(0);}
}
async function sealPasswordAccess(box,password,identity,privateKey,code,revision) {
  if(!/^[0-9A-F]{64}$/.test(code||'')) fail('本机加密密钥尚未解锁。');
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),bytes=utf8.encode(code);
  let ciphertext;
  try { ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(canonical(accessAad(box,identity.fingerprint,revision)))},await passwordKey(password,salt),bytes); }
  finally {bytes.fill(0);}
  const access={v:1,salt:b64url(salt),iv:b64url(iv),ciphertext:b64url(ciphertext),revision};
  const proof=await pgp.sign({message:await pgp.createMessage({text:canonical(accessBinding(box,identity.fingerprint,access))}),signingKeys:privateKey,detached:true,format:'armored'});
  return {access,proof};
}
async function openPasswordAccess(box,password,access,fingerprint) {
  const {salt,iv,ciphertext}=validatePasswordAccess(access); let bytes;
  try { bytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:utf8.encode(canonical(accessAad(box,fingerprint,access.revision)))},await passwordKey(password,salt),ciphertext)); }
  catch {fail('账户密码无法解锁聊天，请确认密码或重新登录。');}
  try { const code=new TextDecoder().decode(bytes); if(!/^[0-9A-F]{64}$/.test(code)) fail('密码保护记录不正确。');return code; }
  finally {bytes.fill(0);}
}
async function generateIdentity(box) {
  const seed=crypto.getRandomValues(new Uint8Array(32));
  const code=Array.from(seed,x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();seed.fill(0);
  const generated=await pgp.generateKey({type:'ecc',curve:'curve25519',userIDs:[{name:`yueti:${box.serverId}:${box.user.id}`}],passphrase:code,format:'armored'});
  const publicKey=await pgp.readKey({armoredKey:generated.publicKey});
  const privateKey=await pgp.decryptKey({privateKey:await pgp.readPrivateKey({armoredKey:generated.privateKey}),passphrase:code});
  const identity={userId:box.user.id,fingerprint:publicKey.getFingerprint(),publicKey:generated.publicKey,encryptedPrivateKey:generated.privateKey};
  const proof=await pgp.sign({message:await pgp.createMessage({text:canonical({v:1,serverId:box.serverId,userId:box.user.id,fingerprint:identity.fingerprint})}),signingKeys:privateKey,detached:true,format:'armored'});
  return {identity,privateKey,code,proof};
}
// This is the sending device's signed timestamp, not a claim about either
// device's current clock. Historical messages must remain readable after years.
const validSentAt = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number(value.slice(0,4)) >= 1970 && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

class Vault {
  async db() {
    if (!this.promise) this.promise = new Promise((resolve,reject) => {
      const r = indexedDB.open('yueti-shanshui-e2ee-v1', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('vault');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(new Error('无法打开本机加密存储，请检查浏览器的存储权限。'));
    });
    return this.promise;
  }
  async operation(mode, action) {
    const db = await this.db();
    return new Promise((resolve,reject) => {
      const tx = db.transaction('vault',mode), request = action(tx.objectStore('vault'));
      let value;
      request.onsuccess = () => { value = request.result; };
      tx.oncomplete = () => resolve(value);
      tx.onerror = tx.onabort = () => reject(new Error('本机加密存储失败。'));
    });
  }
  get(k) { return this.operation('readonly',s=>s.get(k)); }
  set(k,v) { return this.operation('readwrite',s=>s.put(v,k)); }
  delete(k) { return this.operation('readwrite',s=>s.delete(k)); }
  async checkedWrite(k,check) {
    const db=await this.db();
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('vault','readwrite'),store=tx.objectStore('vault'),r=store.get(k);
      let value,error;
      r.onsuccess=()=>{
        try { const result=check(r.result); value=result.value; if(result.write) store.put(result.write,k); }
        catch(e) { error=e; tx.abort(); }
      };
      tx.oncomplete=()=>resolve(value);
      tx.onerror=tx.onabort=()=>reject(error||new Error('本机安全记录写入失败。'));
    });
  }
  pinIdentity(k,fingerprint,permit) {
    return this.checkedWrite(k,prior=>{
      if(prior&&prior!==fingerprint) fail('安全验证失败：联系人密钥发生变化，已阻止收发。');
      return {value:Boolean(prior||permit),write:!prior&&permit?fingerprint:null};
    });
  }
  pinChat(k,pin,knownHashes) {
    return this.checkedWrite(k,prior=>{
      if(prior&&(prior.revision>pin.revision || prior.ownerId!==pin.ownerId || knownHashes[prior.revision-1]!==prior.hash)) fail('检测到聊天成员记录回退或分叉，已阻止收发。');
      return {value:true,write:pin};
    });
  }
}

export class CryptoBox {
  constructor({ api, user, serverId, storage }) {
    if (!api || !user?.id || !serverId) fail('加密账户信息不完整。');
    this.api=api; this.user=user; this.serverId=serverId; this.storage=storage||new Vault();
    this.peerRecovery=new ArchiveAssist(this);
    this.messageManifestLoads=new WeakMap();
    this.scope=`${serverId}:${user.id}:`; this.identity=null; this.privateKey=null; this.code=null;
    this.archiveSyncAvailable=false;this.pendingArchiveAccess=new Map();this.verifiedArchiveAccess=new Map();
    this.archiveSyncStamp=null;this.archiveRetryAt=0;this.archiveTrustAttempts=new Map();
    this.records=new Map();this.historicalRecords=new Map();this.archivedPrivateKeys=new Map();this.archivedFingerprints=new Set();this.archiveRestoreError=null; this.chains=new Map(); this.epoch=0; this.passwordAccess=null;this.passwordAccessProof=null;this.rememberError=null;this.passwordMode=false;this.pendingReset=null;
  }
  get fingerprint() { return this.identity?.fingerprint || ''; }
  get ready() { return Boolean(this.privateKey); }
  requireReady() { if (!this.ready) fail('请先解锁加密消息。'); }
  guard(epoch) { if (epoch !== this.epoch || !this.ready) fail('加密会话已锁定，请重新解锁。'); }
  async pin(record, permit=false) {
    const k=this.scope+`pin:${record.userId}`, prior=await this.storage.get(k);
    if(this.storage.pinIdentity) return this.storage.pinIdentity(k,record.fingerprint,permit);
    if (prior && prior !== record.fingerprint) fail('安全验证失败：联系人密钥发生变化，已阻止收发。请通过其他渠道核对指纹。');
    if (!prior && !permit) return false;
    if (!prior) await this.storage.set(k,record.fingerprint);
    return true;
  }
  historyPin(userId,fingerprint) {return this.scope+`pin-history:${userId}:${fingerprint}`;}
  async repin(record,previous) {
    const key=this.scope+`pin:${record.userId}`;
    if(previous&&previous!==record.fingerprint)await this.storage.set(this.historyPin(record.userId,previous),true);
    const check=prior=>{if(prior!==previous&&prior!==record.fingerprint)fail('安全码在核验期间发生变化，请重新确认。');return {value:true,write:record.fingerprint};};
    if(this.storage.checkedWrite)await this.storage.checkedWrite(key,check);else {check(await this.storage.get(key));await this.storage.set(key,record.fingerprint);}
  }
  recordFor(userId,fingerprint) {
    const current=this.records.get(userId);
    return current?.fingerprint===fingerprint?current:this.historicalRecords.get(`${userId}:${fingerprint}`);
  }
  async parseRecord(record) {
    if (!record || !/^[a-f0-9]{40,64}$/.test(record.fingerprint) || typeof record.userId!=='string' || !isArmor(record.publicKey,'PUBLIC KEY BLOCK') || record.publicKey.length>65536) fail('服务器返回了无效的加密身份。');
    const key=await pgp.readKey({armoredKey:record.publicKey});
    if (key.isPrivate() || key.getFingerprint()!==record.fingerprint) fail('公钥指纹不匹配，已阻止收发。');
    await key.verifyPrimaryKey();
    await key.getEncryptionKey();
    return {...record,key};
  }
  async devicePassphrase(wrapped) {
    const bytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:wrapped.iv,additionalData:utf8.encode(this.scope)},wrapped.key,wrapped.bytes));
    try{return new TextDecoder().decode(bytes);}finally{bytes.fill(0);}
  }
  async initialize(options={}) {
    const usePassword=options.passwordAccess===true||typeof options.password==='string',password=options.password,remember=options.remember!==false;
    this.passwordMode=usePassword;
    const epoch=this.epoch;
    if (globalThis.isSecureContext === false) fail('端到端加密需要 HTTPS。请使用安全域名或安装版客户端。');
    const {identity,previousFingerprints}=await this.api('/api/e2ee/identity');
    if(epoch!==this.epoch) fail('加密会话已关闭。');
    this.archivedFingerprints=new Set((Array.isArray(previousFingerprints)?previousFingerprints:[]).filter(value=>typeof value==='string'&&/^[a-f0-9]{40,64}$/.test(value)));
    this.identity=identity;
    if (!identity) {
      if (await this.storage.get(this.scope+'own-identity')) fail('服务器的加密身份记录缺失。为避免丢失历史，请恢复原服务器数据，不要创建新密钥。');
      return {status:'new',identity:null};
    }
    if (identity.userId!==this.user.id) fail('加密身份不属于当前账户。');
    const record=await this.parseRecord(identity);
    const prior=await this.storage.get(this.scope+`pin:${identity.userId}`);
    if(usePassword&&prior&&prior!==record.fingerprint&&Array.isArray(previousFingerprints)&&previousFingerprints.includes(prior)){
      this.pendingReset={record,previous:prior};await this.loadPasswordAccess();
      if(!this.passwordAccess)fail('新加密身份缺少密码保护记录。');
      return {status:'identity_changed',identity};
    }
    await this.pin(record,true);
    await this.storage.set(this.scope+'own-identity',identity.fingerprint);
    this.records.set(record.userId,record);
    const wrapped=await this.storage.get(this.scope+'remembered');
    if(epoch!==this.epoch) fail('加密会话已关闭。');
    if (wrapped) {
      try {
        const passphrase=await this.devicePassphrase(wrapped);
        if(epoch!==this.epoch) fail('加密会话已关闭。');
        await this.unlock(passphrase);
      } catch { if(epoch===this.epoch)await this.storage.delete(this.scope+'remembered'); }
    }
    if(epoch!==this.epoch) { await this.lock(); fail('加密会话已关闭。'); }
    if(usePassword){
      await this.loadPasswordAccess();
      if(typeof password==='string'&&(this.passwordAccess||this.ready))await this.unlockPassword(password,{remember});
      if(epoch!==this.epoch) fail('加密会话已关闭。');
      if(!this.passwordAccess)return {status:this.ready?'ready':'legacy_locked',identity};
    }
    if(usePassword&&this.ready&&typeof password!=='string')await this.loadRememberedArchivedIdentities();
    return {status:this.ready?'ready':'locked',identity};
  }
  async createIdentity({deferRegistration=false}={}) {
    const epoch=this.epoch;
    if (this.identity) fail('账户已有加密身份，请输入原恢复码。');
    if(this.pendingIdentity) {
      const pending=this.pendingIdentity;
      if(!deferRegistration) await this.registerIdentity();
      return {recoveryCode:pending.code.match(/.{1,8}/g).join('-'),identity:pending.identity};
    }
    const {identity,privateKey,code,proof}=await generateIdentity(this);
    if(epoch!==this.epoch) fail('加密初始化已取消。请使用保存的恢复码重新登录。');
    this.pendingIdentity={identity,privateKey,code,proof};
    if(!deferRegistration) await this.registerIdentity();
    return {recoveryCode:code.match(/.{1,8}/g).join('-'),identity};
  }
  async registerIdentity(passwordFields=null) {
    const epoch=this.epoch;
    if(this.ready) return this.identity;
    if(!this.pendingIdentity) fail('请先生成并保存恢复码。');
    const {identity,privateKey,code,proof}=this.pendingIdentity;
    let result;
    try { result=await this.api('/api/e2ee/identity',{method:'POST',body:{...identity,proof,...(passwordFields||{})}}); }
    catch(error) {
      // A response can be lost after the immutable identity was committed.
      // Retrying the same generated key is essential; never generate another one.
      const current=await this.api('/api/e2ee/identity').catch(()=>null);
      if(!current||!same(current.identity,identity)) throw error;
      result=current;
      if(passwordFields) {
        const saved=await this.api('/api/e2ee/password-access').catch(()=>null);
        if(!saved||!same(saved.access,passwordFields.access)||saved.proof!==passwordFields.accessProof) throw error;
        result={...result,...saved};
      }
    }
    if (!same(result.identity,identity)) fail('服务器未正确保存加密身份，请勿继续。');
    if(epoch!==this.epoch) fail('加密初始化已取消。请使用保存的恢复码重新登录。');
    this.identity=identity; this.privateKey=privateKey; this.code=code;
    const record=await this.parseRecord(identity); await this.pin(record,true); this.records.set(record.userId,record);
    await this.storage.set(this.scope+'own-identity',identity.fingerprint);
    this.pendingIdentity=null;
    if(passwordFields){
      if(!same(result.access,passwordFields.access)||result.proof!==passwordFields.accessProof)fail('服务器未正确保存密码保护记录。');
      await this.verifyPasswordAccess(result.access,result.proof);
    }
    return identity;
  }
  async verifyPasswordAccess(access,proof) {
    const epoch=this.epoch,identity=this.identity;
    if(!identity)fail('请先建立加密身份。');
    if(access===null){
      const prior=await this.storage.get(this.scope+'password-access-pin');
      if(prior?.fingerprint===identity.fingerprint) fail('服务器缺少已保存的密码保护记录，请联系管理员恢复数据。');
      if(epoch!==this.epoch)fail('加密会话已关闭。');
      this.passwordAccess=null;this.passwordAccessProof=null;return null;
    }
    validatePasswordAccess(access);
    if(!isArmor(proof,'SIGNATURE')||proof.length>16000)fail('密码保护记录签名无效。');
    const record=await this.parseRecord(identity);
    const result=await pgp.verify({message:await pgp.createMessage({text:canonical(accessBinding(this,identity.fingerprint,access))}),signature:await pgp.readSignature({armoredSignature:proof}),verificationKeys:record.key,expectSigned:true});
    if(result.signatures.length!==1)fail('密码保护记录签名无效。');
    await result.signatures[0].verified;
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    const pin={fingerprint:identity.fingerprint,revision:access.revision,hash:await digest({access,proof})},k=this.scope+'password-access-pin';
    const check=prior=>{
      if(prior?.fingerprint===pin.fingerprint&&(prior.revision>pin.revision||prior.revision===pin.revision&&prior.hash!==pin.hash))fail('密码保护记录发生回退或冲突，请重新登录。');
      return {value:true,write:pin};
    };
    if(this.storage.checkedWrite)await this.storage.checkedWrite(k,check);else {check(await this.storage.get(k));await this.storage.set(k,pin);}
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    this.passwordAccess=structuredClone(access);this.passwordAccessProof=proof;
    return this.passwordAccess;
  }
  async loadPasswordAccess() {
    const epoch=this.epoch;
    const {access,proof}=await this.api('/api/e2ee/password-access');
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    return this.verifyPasswordAccess(access,proof);
  }
  async tryRemember(remember) {
    this.rememberError=null;
    try {if(remember)await this.rememberDevice();else await this.storage.delete(this.scope+'remembered');}
    catch(error){this.rememberError=error.message||'此设备不能保存自动登录凭据。';}
  }
  async createPasswordIdentity(password,{remember=true}={}) {
    this.passwordMode=true;
    if(this.identity)fail('加密身份已存在，请使用账户密码解锁。');
    const epoch=this.epoch,pending=this.pendingIdentity||await generateIdentity(this);
    if(epoch!==this.epoch)fail('加密初始化已取消。');
    this.pendingIdentity=pending;
    const {identity,privateKey,code}=pending;
    const {access,proof}=await sealPasswordAccess(this,password,identity,privateKey,code,1);
    if(epoch!==this.epoch||this.pendingIdentity?.identity!==identity)fail('加密初始化已取消。');
    await this.registerIdentity({password,access,accessProof:proof});
    await this.tryRemember(remember);
    this.guard(epoch);return this.identity;
  }
  async unlockPassword(password,{remember=true}={}) {
    const epoch=this.epoch;
    this.passwordMode=true;
    if(this.pendingReset)fail('账户密钥已经重建，请先确认新身份。');
    if(!this.identity) fail('请先建立加密身份。');
    const ownPin=await this.storage.get(this.scope+`pin:${this.user.id}`);
    if(ownPin&&ownPin!==this.fingerprint)fail('自己的加密身份发生变化，尚不能解锁。');
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    await this.loadPasswordAccess();
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    if(this.passwordAccess){
      let code;
      try{code=await openPasswordAccess(this,password,this.passwordAccess,this.fingerprint);}
      catch(error){if(epoch===this.epoch){this.privateKey=null;this.code=null;this.archivedPrivateKeys.clear();}throw error;}
      if(epoch!==this.epoch)fail('加密会话已关闭。');
      await this.unlock(code);
    }else{
      if(!this.ready)fail('旧版加密身份尚未解锁，需要一次迁移。');
      const {access,proof}=await sealPasswordAccess(this,password,this.identity,this.privateKey,this.code,1);
      this.guard(epoch);
      const result=await this.api('/api/e2ee/password-access',{method:'PUT',body:{password,access,proof}});
      this.guard(epoch);
      if(!same(result.access,access)||result.proof!==proof)fail('服务器未正确保存密码保护记录。');
      await this.verifyPasswordAccess(access,proof);
    }
    await this.tryRemember(remember);
    this.guard(epoch);await this.loadRememberedArchivedIdentities();this.guard(epoch);
    return this.identity;
  }
  async passwordChangeFields(newPassword) {
    this.requireReady();const epoch=this.epoch;
    await this.loadPasswordAccess();this.guard(epoch);
    if(!this.passwordAccess)fail('请先完成账户密码保护迁移。');
    const result=await sealPasswordAccess(this,newPassword,this.identity,this.privateKey,this.code,this.passwordAccess.revision+1);
    this.guard(epoch);return result;
  }
  async acceptPasswordChange(access,proof) {
    if(!proof){const result=await this.api('/api/e2ee/password-access');if(!same(access,result.access))fail('密码保护记录更新冲突。');proof=result.proof;}
    return this.verifyPasswordAccess(access,proof);
  }
  async acceptIdentityReset(password,{remember=true}={}) {
    this.passwordMode=true;const epoch=this.epoch,pending=this.pendingReset;
    if(!pending||pending.record.fingerprint!==this.fingerprint)fail('没有需要确认的新加密身份。');
    await this.loadPasswordAccess();if(!this.passwordAccess)fail('新加密身份缺少密码保护记录。');
    const code=await openPasswordAccess(this,password,this.passwordAccess,this.fingerprint);
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    await this.unlock(code,{acceptReset:true});try{
      // An older trusted installation may still hold the previous identity's
      // only usable passphrase. Preserve it before replacing the device vault.
      this.records.set(this.user.id,pending.record);
      const wrapped=await this.storage.get(this.scope+'remembered');
      if(wrapped){
        const previousCode=await this.devicePassphrase(wrapped).catch(()=>null);
        const localKey=this.archivedCodeKey(pending.previous);
        if(previousCode!==code&&/^[0-9A-F]{64}$/.test(previousCode||'')&&!await this.storage.get(localKey)){
          const ciphertext=await this.encryptLocal({v:1,purpose:'historical-key-code',fingerprint:pending.previous,code:previousCode});
          this.guard(epoch);await this.storage.set(localKey,ciphertext);
        }
      }
      this.guard(epoch);await this.repin(pending.record,pending.previous);this.guard(epoch);
      await this.storage.set(this.scope+'own-identity',this.fingerprint);
      await this.storage.delete(this.scope+'ai-private-memory-pin');this.archivedFingerprints.add(pending.previous);this.pendingReset=null;
      await this.tryRemember(remember);this.guard(epoch);
      await this.loadRememberedArchivedIdentities();this.guard(epoch);return this.identity;
    }catch(e){await this.lock();throw e;}
  }
  async resetPasswordIdentity(password,{remember=true}={}) {
    this.passwordMode=true;const epoch=this.epoch,previous=this.identity;
    if(!previous||this.ready||this.pendingReset)fail('这台设备仍可访问原身份，不能重新建立密钥。');
    const ownPin=await this.storage.get(this.scope+`pin:${this.user.id}`);
    if(ownPin&&ownPin!==previous.fingerprint)fail('此账户安全码与本机记录不一致，不能重设。');
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    await this.loadPasswordAccess();if(this.passwordAccess)fail('账户已支持密码解锁，不能重建密钥。');
    const replacement=await generateIdentity(this),{identity,privateKey,code}=replacement;
    const {access,proof}=await sealPasswordAccess(this,password,identity,privateKey,code,1);
    if(epoch!==this.epoch||this.identity!==previous||this.ready)fail('加密会话已关闭。');
    let result;
    try{result=await this.api('/api/e2ee/identity/reset',{method:'POST',body:{password,previousFingerprint:previous.fingerprint,identity:{...identity,proof:replacement.proof},access,proof}});}
    catch(error){
      const current=await this.api('/api/e2ee/identity').catch(()=>null),saved=await this.api('/api/e2ee/password-access').catch(()=>null);
      if(!current||!same(current.identity,identity)||!saved||!same(saved.access,access)||saved.proof!==proof)throw error;
      result={identity,...saved};
    }
    if(epoch!==this.epoch)fail('加密会话已关闭。');
    if(!same(result.identity,identity)||!same(result.access,access)||result.proof!==proof)fail('服务器未正确保存新加密身份。');
    this.identity=identity;this.pendingReset={record:await this.parseRecord(identity),previous:previous.fingerprint};this.chains.clear();this.historicalRecords.clear();this.records.clear();
    await this.acceptIdentityReset(password,{remember});
    return result;
  }
  async unlock(recoveryCode,{remember=false,acceptReset=false}={}) {
    const epoch=this.epoch;
    if (!this.identity) fail('请先建立加密身份。');
    const prior=await this.storage.get(this.scope+`pin:${this.user.id}`);
    if(prior&&prior!==this.fingerprint&&!(acceptReset&&this.pendingReset?.previous===prior&&this.pendingReset.record.fingerprint===this.fingerprint))fail('自己的加密身份发生变化，尚不能解锁。');
    if(epoch!==this.epoch)fail('加密解锁已取消。');
    const code=cleanCode(recoveryCode);
    if (!/^[0-9A-F]{64}$/.test(code)) fail('恢复码应包含 64 位字母和数字，请完整复制。');
    let key;
    try { key=await pgp.decryptKey({privateKey:await pgp.readPrivateKey({armoredKey:this.identity.encryptedPrivateKey}),passphrase:code}); }
    catch { fail('恢复码不正确，未能解锁私钥。'); }
    if (key.getFingerprint()!==this.fingerprint) fail('恢复的私钥与账户身份不一致。');
    if(epoch!==this.epoch) fail('加密解锁已取消。');
    this.privateKey=key; this.code=code;
    if (remember) await this.rememberDevice();
  }
  async rememberDevice() {
    this.requireReady(); const epoch=this.epoch;
    const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const bytes=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(this.scope)},key,utf8.encode(this.code));
    this.guard(epoch);
    await this.storage.set(this.scope+'remembered',{key,iv,bytes});
    if(epoch!==this.epoch) await this.storage.delete(this.scope+'remembered');
  }
  async lock({forget=false}={}) {
    this.epoch++; this.privateKey=null; this.code=null; this.pendingIdentity=null; this.archivedPrivateKeys.clear();this.chains.clear();this.peerRecovery?.lock?.();
    this.pendingArchiveAccess.clear();this.verifiedArchiveAccess.clear();this.archiveSyncStamp=null;this.archiveTrustAttempts.clear();
    if (forget) {await this.storage.delete(this.scope+'remembered');await this.forgetArchivedIdentities();}
  }
  get restoredArchivedIdentities() { return [...this.archivedPrivateKeys.keys()]; }
  hasArchivedIdentity(fingerprint) { return this.archivedPrivateKeys.has(fingerprint); }
  archivedCodeKey(fingerprint) { return `${this.scope}archived-code:${this.fingerprint}:${fingerprint}`; }
  async archivedIdentities() {
    this.requireReady();const epoch=this.epoch;
    const {identities,accountSync}=await this.api('/api/e2ee/archived-identities');this.guard(epoch);
    if(!Array.isArray(identities)||identities.length>64||new Set(identities.map(record=>record?.fingerprint)).size!==identities.length)fail('历史加密身份资料无效。');
    for(const identity of identities) {
      if(identity?.userId!==this.user.id||identity.fingerprint===this.fingerprint||!this.archivedFingerprints.has(identity.fingerprint)||typeof identity.archivedAt!=='string'||!isArmor(identity.encryptedPrivateKey,'PRIVATE KEY BLOCK')||identity.encryptedPrivateKey.length>80000||!isArmor(identity.proof,'SIGNATURE')||identity.proof.length>16000)fail('历史加密身份不属于当前账户，或数据已修改。');
      const record=await this.parseRecord(identity),key=await pgp.readPrivateKey({armoredKey:identity.encryptedPrivateKey});
      if(key.getFingerprint()!==identity.fingerprint||key.isDecrypted())fail('历史密钥备份不正确。');
      const binding={v:1,serverId:this.serverId,userId:this.user.id,fingerprint:identity.fingerprint};
      const result=await pgp.verify({message:await pgp.createMessage({text:canonical(binding)}),signature:await pgp.readSignature({armoredSignature:identity.proof}),verificationKeys:record.key,expectSigned:true});
      if(result.signatures.length!==1)fail('历史身份签名无效。');await result.signatures[0].verified;this.guard(epoch);
    }
    this.archiveSyncAvailable=accountSync===true;
    return identities;
  }
  async listArchivedIdentities() {
    const records=await this.archivedIdentities();
    await this.loadRememberedArchivedIdentities(records);
    return records.map(({fingerprint,archivedAt})=>({fingerprint,archivedAt,restored:this.hasArchivedIdentity(fingerprint),synced:this.verifiedArchiveAccess.has(fingerprint)}));
  }
  async unlockArchivedRecord(identity,code,epoch) {
    this.guard(epoch);
    if(!this.archivedFingerprints.has(identity?.fingerprint)||identity.userId!==this.user.id||identity.fingerprint===this.fingerprint)fail('历史加密身份不属于当前账户。');
    if(!/^[0-9A-F]{64}$/.test(code))fail('旧版恢复码应包含完整 64 位字母和数字。');
    let key;
    try {key=await pgp.decryptKey({privateKey:await pgp.readPrivateKey({armoredKey:identity.encryptedPrivateKey}),passphrase:code});}
    catch{fail('此恢复码与所选历史身份不匹配。');}
    if(key.getFingerprint()!==identity.fingerprint)fail('恢复的历史私钥与原身份不一致。');
    this.guard(epoch);return key;
  }
  async archiveAccessBinding(archivedFingerprint,ciphertext) {
    return {v:1,purpose:'archived-identity-access',serverId:this.serverId,userId:this.user.id,
      activeFingerprint:this.fingerprint,archivedFingerprint,ciphertextHash:await digest(ciphertext)};
  }
  async applyArchivedKey(fingerprint,key,epoch) {
    this.guard(epoch);
    // Trust this key for historical signatures, never for new messages.
    await this.storage.set(this.historyPin(this.user.id,fingerprint),true);this.guard(epoch);
    this.archivedPrivateKeys.set(fingerprint,key);
  }
  async publishArchivedAccess(fingerprint,ciphertext,epoch) {
    const binding=await this.archiveAccessBinding(fingerprint,ciphertext);
    this.guard(epoch);
    const {signature:proof}=await this.signManifest(binding);
    const result=await this.api('/api/e2ee/archived-access',{method:'PUT',body:{
      activeFingerprint:binding.activeFingerprint,archivedFingerprint:fingerprint,ciphertext,proof}});
    this.guard(epoch);
    if(result.ciphertextHash!==binding.ciphertextHash)fail('服务器未确认保存历史聊天解锁资料。');
    this.verifiedArchiveAccess.set(fingerprint,{ciphertext,proof});
    this.pendingArchiveAccess.delete(fingerprint);
  }
  async recoverArchivedAccess(identity,ciphertext,proof,epoch) {
    if(typeof ciphertext!=='string'||ciphertext.length>12000||!isArmor(ciphertext,'MESSAGE'))fail('历史聊天同步资料格式不正确。');
    if(proof!==undefined){
      if(!isArmor(proof,'SIGNATURE')||proof.length>16000)fail('历史聊天同步签名无效。');
      const binding=await this.archiveAccessBinding(identity.fingerprint,ciphertext);
      const signed=await pgp.verify({message:await pgp.createMessage({text:canonical(binding)}),
        signature:await pgp.readSignature({armoredSignature:proof}),verificationKeys:this.records.get(this.user.id).key,expectSigned:true});
      if(signed.signatures.length!==1)fail('历史聊天同步签名无效。');
      await signed.signatures[0].verified;
    }
    const value=await this.decryptLocal(ciphertext);
    if(value?.v!==1||value.purpose!=='historical-key-code'||value.fingerprint!==identity.fingerprint||Object.keys(value).length!==4)fail('历史聊天解锁资料与旧身份不符。');
    const key=await this.unlockArchivedRecord(identity,value.code,epoch);
    await this.applyArchivedKey(identity.fingerprint,key,epoch);
  }
  async restoreArchivedIdentity(fingerprint,oldCode,{remember=true}={}) {
    this.requireReady();const epoch=this.epoch,code=cleanCode(oldCode);
    const identity=(await this.archivedIdentities()).find(record=>record.fingerprint===fingerprint);
    if(!identity)fail('所选历史加密身份不存在。');
    const key=await this.unlockArchivedRecord(identity,code,epoch);
    const ciphertext=await this.encryptLocal({v:1,purpose:'historical-key-code',fingerprint,code});
    this.guard(epoch);
    if(remember)await this.storage.set(this.archivedCodeKey(fingerprint),ciphertext);
    else await this.storage.delete(this.archivedCodeKey(fingerprint));
    await this.applyArchivedKey(fingerprint,key,epoch);
    this.archiveRestoreError=null;
    let synced=false;
    if(this.archiveSyncAvailable){
      this.pendingArchiveAccess.set(fingerprint,ciphertext);
      try {await this.publishArchivedAccess(fingerprint,ciphertext,epoch);synced=true;}
      catch(error){this.guard(epoch);this.archiveRestoreError='本机已恢复，账号同步待重试。'+error.message;}
    }
    return {fingerprint,archivedAt:identity.archivedAt,restored:true,synced};
  }
  async loadRememberedArchivedIdentities(records) {
    this.requireReady();const epoch=this.epoch,previous=this.archivedPrivateKeys.size;
    this.archiveRestoreError=null;
    if(!this.archivedFingerprints.size)return 0;
    try {
      const identities=records||await this.archivedIdentities();
      for(const identity of identities){
        this.guard(epoch);
        try {
          const fingerprint=identity.fingerprint,remote=identity.accountAccess;
          if(remote){
            if(!isArmor(remote.proof,'SIGNATURE'))fail('历史聊天同步签名缺失。');
            const verified=this.verifiedArchiveAccess.get(fingerprint);
            if(!this.hasArchivedIdentity(fingerprint)||verified?.ciphertext!==remote.ciphertext||verified?.proof!==remote.proof){
              await this.recoverArchivedAccess(identity,remote.ciphertext,remote.proof,epoch);
              this.verifiedArchiveAccess.set(fingerprint,{ciphertext:remote.ciphertext,proof:remote.proof});
            }
            this.pendingArchiveAccess.delete(fingerprint);
            continue;
          }
          this.verifiedArchiveAccess.delete(fingerprint);
          const local=this.pendingArchiveAccess.get(fingerprint)||await this.storage.get(this.archivedCodeKey(fingerprint));
          this.guard(epoch);if(!local)continue;
          if(!this.hasArchivedIdentity(fingerprint))await this.recoverArchivedAccess(identity,local,undefined,epoch);
          if(this.archiveSyncAvailable)await this.publishArchivedAccess(fingerprint,local,epoch);
        } catch(error){this.guard(epoch);this.archiveRestoreError=error.message||'历史聊天同步失败，请重试。';}
      }
    }catch(error){this.guard(epoch);this.archiveRestoreError=error.message||'历史聊天同步失败，请重试。';}
    return this.archivedPrivateKeys.size-previous;
  }
  async refreshArchivedAccess(stamp,chats=[]) {
    const generation=this.epoch;
    if(this.ready)for(const chat of chats){
      if(!chat.archived||chat.archiveTrustSynced!==false||!chat.e2eeRevision||this.archiveTrustAttempts.get(chat.id)>Date.now())continue;
      this.archiveTrustAttempts.set(chat.id,Date.now()+60000);
      const pin=await this.storage.get(this.scope+'chat:'+chat.id);this.guard(generation);
      if(pin?.revision===chat.e2eeRevision&&pin.ownerId===chat.ownerId){
        // Includes a 1.5.1 installation which previously read this archive.
        // This value was pinned only after the entire signed chain passed.
        await this.publishArchiveTrust(chat,pin,generation);
      }
    }
    if(typeof stamp!=='string'||!this.ready||!this.archivedFingerprints.size)return 0;
    const retry=this.archiveRestoreError||this.pendingArchiveAccess.size;
    if(this.archiveSyncStamp===stamp&&(!retry||Date.now()<this.archiveRetryAt))return 0;
    const epoch=this.epoch,count=await this.loadRememberedArchivedIdentities();
    this.guard(epoch);this.archiveSyncStamp=stamp;this.archiveRetryAt=Date.now()+30000;
    return count;
  }
  async forgetArchivedIdentities() {
    this.epoch++;this.archivedPrivateKeys.clear();this.pendingArchiveAccess.clear();this.verifiedArchiveAccess.clear();this.archiveRestoreError=null;this.archiveSyncStamp=null;
    for(const fingerprint of this.archivedFingerprints) await this.storage.delete(this.archivedCodeKey(fingerprint));
  }
  decryptionKeyFor(message) {
    this.requireReady();const envelope=message?.envelope;
    const recipient=Array.isArray(envelope?.recipients)?envelope.recipients.find(r=>r.userId===this.user.id):null;
    if(!recipient)return null;
    return recipient.fingerprint===this.fingerprint?this.privateKey:(this.archivedPrivateKeys.get(recipient.fingerprint)||null);
  }
  async decryptionOptionsFor(chat,message,ciphertext,{part='message',index=null}={}) {
    const epoch=this.epoch,key=this.decryptionKeyFor(message);
    if(key)return {decryptionKeys:key};
    const recipient=message?.envelope?.recipients?.find?.(r=>r.userId===this.user.id);
    if(chat?.archived&&recipient&&this.archivedFingerprints.has(recipient.fingerprint)&&this.peerRecovery?.decryptionOptionsFor) {
      const options=await this.peerRecovery.decryptionOptionsFor(chat,message,ciphertext,{part,index});
      try {this.guard(epoch);if(options?.sessionKeys)return {sessionKeys:options.sessionKeys};}
      catch(error){wipeSessionKeys(options);throw error;}
    }
    fail('这条消息发送时使用的是其他加密身份，当前没有解密权限。');
  }
  exportBackup() {
    const identity=this.identity||this.pendingIdentity?.identity;
    if (!identity) fail('尚未建立加密身份。');
    return {v:1,serverId:this.serverId,userId:this.user.id,identity};
  }
  async importBackup(backup,recoveryCode,options={}) {
    if (backup?.v!==1 || backup.serverId!==this.serverId || backup.userId!==this.user.id || backup.identity?.userId!==this.user.id || (this.identity&&!same(backup.identity,this.identity))) fail('恢复包不属于当前服务器和账户，或密钥已发生变化。');
    if(!this.identity) {
      const epoch=this.epoch,code=cleanCode(recoveryCode),identity=backup.identity;
      if(!/^[0-9A-F]{64}$/.test(code)) fail('恢复码应包含 64 位字母和数字，请完整复制。');
      const record=await this.parseRecord(identity);
      let privateKey;
      try { privateKey=await pgp.decryptKey({privateKey:await pgp.readPrivateKey({armoredKey:identity.encryptedPrivateKey}),passphrase:code}); }
      catch { fail('恢复码不正确，未能解锁私钥。'); }
      if(privateKey.getFingerprint()!==record.fingerprint) fail('恢复的私钥与账户身份不一致。');
      const proof=await pgp.sign({message:await pgp.createMessage({text:canonical({v:1,serverId:this.serverId,userId:this.user.id,fingerprint:identity.fingerprint})}),signingKeys:privateKey,detached:true,format:'armored'});
      if(epoch!==this.epoch) fail('加密恢复已取消。');
      this.pendingIdentity={identity,privateKey,code,proof};
      await this.registerIdentity();
      if(options.remember) await this.rememberDevice();
      return;
    }
    await this.unlock(recoveryCode,options);
  }
  async getRecords(ids,approveTrust) {
    this.requireReady(); const epoch=this.epoch;
    const unique=[...new Set(ids)].filter(id=>id!=='ai').sort();
    // Always re-read the directory: a changed public identity must never be ignored.
    if(unique.length>10000) fail('历史成员过多，无法安全加载此会话。');
    const keys=[];
    for(let start=0;start<unique.length;start+=100) {
      const page=await this.api('/api/e2ee/keys?ids='+encodeURIComponent(unique.slice(start,start+100).join(',')));
      if(!Array.isArray(page.keys)) fail('服务器返回了无效的成员公钥。');
      keys.push(...page.keys);
    }
    if (!Array.isArray(keys) || keys.length!==unique.length || new Set(keys.map(k=>k.userId)).size!==unique.length) fail('有成员尚未启用加密，请先让对方登录并建立加密身份。');
    const records=[],changed=new Map(),unknown=[];
    for (const id of unique) {
      const raw=keys.find(k=>k.userId===id); if(!raw) fail('成员的加密身份缺失。');
      const record=await this.parseRecord(raw),prior=await this.storage.get(this.scope+`pin:${id}`);
      if (id===this.user.id && record.fingerprint!==this.fingerprint) fail('自己的加密身份发生变化。');
      if(prior&&prior!==record.fingerprint){
        if(!this.passwordMode||id===this.user.id||!Array.isArray(raw.previousFingerprints)||!raw.previousFingerprints.includes(prior))fail('安全验证失败：联系人密钥发生变化，已阻止收发。请通过其他渠道核对指纹。');
        // A server statement alone must never change a contact's trusted key.
        // The current user explicitly approves the new out-of-band safety code.
        changed.set(id,prior);unknown.push({userId:id,fingerprint:record.fingerprint,changed:true,previousFingerprint:prior});
      }else if(!await this.pin(record,id===this.user.id))unknown.push({userId:id,fingerprint:record.fingerprint});
      records.push(record);
    }
    if (unknown.length) {
      if (!approveTrust || !await approveTrust(unknown)) fail('尚未确认联系人的安全指纹。请打开聊天并核对身份。');
      this.guard(epoch);
      for(const record of records) {if(changed.has(record.userId))await this.repin(record,changed.get(record.userId));else await this.pin(record,true);}
    }
    this.guard(epoch); records.forEach(r=>this.records.set(r.userId,r));
    return records;
  }
  archiveTrustBinding(chat,pin) {
    return {v:1,purpose:'archived-chat-trust',serverId:this.serverId,userId:this.user.id,
      activeFingerprint:this.fingerprint,chatId:chat.id,ownerId:pin.ownerId,revision:pin.revision,manifestHash:pin.hash};
  }
  async publishArchiveTrust(chat,pin,epoch) {
    this.archiveTrustAttempts.set(chat.id,Date.now()+60000);
    try{
      const {signature:proof}=await this.signManifest(this.archiveTrustBinding(chat,pin));this.guard(epoch);
      const result=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/archive-trust`,{method:'PUT',body:{revision:pin.revision,manifestHash:pin.hash,proof}});
      this.guard(epoch);if(result.manifestHash!==pin.hash)fail('归档成员核验记录未正确保存。');
    }catch(error){
      // Reading locally verified history remains available while offline.
      this.guard(epoch);
    }
  }
  async verifyArchiveTrust(chat,manifests,proof) {
    if(!isArmor(proof,'SIGNATURE')||proof.length>16000)fail('已同步的归档成员签名无效。');
    const pin={ownerId:chat.ownerId,revision:manifests.length,hash:await digest(manifests.at(-1))};
    const verified=await pgp.verify({message:await pgp.createMessage({text:canonical(this.archiveTrustBinding(chat,pin))}),
      signature:await pgp.readSignature({armoredSignature:proof}),verificationKeys:this.records.get(this.user.id).key,expectSigned:true});
    if(verified.signatures.length!==1)fail('已同步的归档成员签名无效。');
    await verified.signatures[0].verified;
    // Before using any of the signed historical identities, check that every
    // revision belongs to the exact chain previously verified by this account.
    for(let i=1;i<manifests.length;i++)if(manifests[i].payload.previousHash!==await digest(manifests[i-1]))fail('归档成员链已更改。');
  }
  async getHistoricalRecords(chat,manifests,approveTrust,archiveTrustProof) {
    this.requireReady();const epoch=this.epoch,expected=new Map();
    for(const signed of manifests) {
      const members=signed?.payload?.members;
      if(!Array.isArray(members)||members.length<1||members.length>100)fail('聊天成员记录无效。');
      for(const member of members) {
        if(typeof member?.userId!=='string'||typeof member.fingerprint!=='string'||!/^[a-f0-9]{40,64}$/.test(member.fingerprint))fail('聊天成员记录无效。');
        expected.set(`${member.userId}:${member.fingerprint}`,member);
      }
    }
    if(expected.size>10000)fail('历史成员过多，无法安全加载此会话。');
    const {keys}=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/keys`);
    if(!Array.isArray(keys)||keys.length!==expected.size||new Set(keys.map(k=>`${k.userId}:${k.fingerprint}`)).size!==expected.size)fail('历史加密身份记录缺失。');
    const records=[],unknown=[];
    for(const raw of keys) {
      const pair=`${raw.userId}:${raw.fingerprint}`;if(!expected.has(pair))fail('历史加密身份记录无效。');
      const record=await this.parseRecord(raw),prior=await this.storage.get(this.scope+`pin:${raw.userId}`),trusted=await this.storage.get(this.historyPin(raw.userId,raw.fingerprint));
      if(prior!==raw.fingerprint&&!trusted&&!(raw.userId===this.user.id&&raw.fingerprint===this.fingerprint))unknown.push({userId:raw.userId,fingerprint:raw.fingerprint,historical:true,...(prior?{previousFingerprint:prior}:{})});
      records.push(record);
    }
    if(unknown.length&&chat.archived&&archiveTrustProof){
      await this.verifyArchiveTrust(chat,manifests,archiveTrustProof);
      this.guard(epoch);
    }else if(unknown.length) {
      if(!approveTrust||!await approveTrust(unknown))fail('尚未确认历史联系人的安全指纹。');
      this.guard(epoch);
      for(const raw of unknown)await this.storage.set(this.historyPin(raw.userId,raw.fingerprint),true);
    }
    this.guard(epoch);for(const record of records)this.historicalRecords.set(`${record.userId}:${record.fingerprint}`,record);
  }
  async signManifest(payload) {
    this.requireReady();const epoch=this.epoch;
    const result={payload,signature:await pgp.sign({message:await pgp.createMessage({text:canonical(payload)}),signingKeys:this.privateKey,detached:true,format:'armored'})};
    this.guard(epoch); return result;
  }
  async verifyManifest(signed,previous,chat) {
    const p=signed?.payload;
    if (!p || p.v!==1 || p.serverId!==this.serverId || p.chatId!==chat.id || p.kind!==chat.kind || p.ownerId!==chat.ownerId || p.revision!==(previous?.payload.revision||0)+1 || p.previousHash!==(previous?await digest(previous):null) || !Array.isArray(p.members) || p.members.length<1 || p.members.length>100 || !p.members.some(m=>m.userId===p.ownerId)) fail('聊天成员记录不完整或已被修改，已阻止收发。');
    if((['notes','ai'].includes(p.kind)&& (p.members.length!==1||p.members[0].userId!==p.ownerId)) || (p.kind==='direct'&&p.members.length!==2) || (p.kind!=='group'&&previous&&!same(previous.payload.members,p.members))) fail('此类聊天不允许变更加密成员。');
    const members=[...p.members].sort((a,b)=>a.userId.localeCompare(b.userId,'en'));
    // Stable UUID ordering is ASCII; locale ordering agrees for UUID strings.
    if (!same(members,p.members) || new Set(members.map(m=>m.userId)).size!==members.length) fail('加密成员清单无效。');
    for(const member of members) if(!this.recordFor(member.userId,member.fingerprint)) fail('聊天成员指纹与已确认的身份不一致。');
    const ownerMember=p.members.find(m=>m.userId===p.ownerId),owner=this.recordFor(ownerMember.userId,ownerMember.fingerprint);
    const result=await pgp.verify({message:await pgp.createMessage({text:canonical(p)}),signature:await pgp.readSignature({armoredSignature:signed.signature}),verificationKeys:owner.key,expectSigned:true});
    if(result.signatures.length!==1) fail('聊天成员签名无效。');
    await result.signatures[0].verified;
  }
  async prepareChat(chat,approveTrust) {
    this.requireReady(); const epoch=this.epoch;
    if(!chat?.id || !chat.ownerId) fail('会话尚未支持加密，请升级服务器。');
    let {manifests,archiveTrustProof}=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/manifests`);
    if(!Array.isArray(manifests) || manifests.length>10000) fail('聊天成员记录无效。');
    const humanIds=(chat.members||[]).map(m=>m.id).filter(id=>id!=='ai');
    if((['notes','ai'].includes(chat.kind)&&(humanIds.length!==1||humanIds[0]!==this.user.id))||(chat.kind==='direct'&&humanIds.length!==2)) fail('会话的加密成员数量不正确。');
    if(!manifests.length) {
      if(chat.archived)fail('旧会话已经归档，不能发送新消息。');
      if(chat.ownerId!==this.user.id) fail('请让聊天创建者先打开此会话，完成加密初始化。');
      const records=await this.getRecords(humanIds,approveTrust);
      if(['direct','group'].includes(chat.kind) && (!approveTrust||!await approveTrust(records.map(r=>({userId:r.userId,fingerprint:r.fingerprint,membership:true}))))) fail('尚未确认此会话的加密成员。');
      this.guard(epoch);
      const payload={v:1,serverId:this.serverId,chatId:chat.id,kind:chat.kind,ownerId:this.user.id,revision:1,previousHash:null,members:records.map(r=>({userId:r.userId,fingerprint:r.fingerprint}))};
      const manifest=await this.signManifest(payload);
      this.guard(epoch);
      try { await this.api(`/api/chats/${encodeURIComponent(chat.id)}/manifests`,{method:'PUT',body:{manifest}}); }
      catch(error) {
        const fresh=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/manifests`);
        if(!fresh.manifests?.length) throw error;
      }
      ({manifests}=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/manifests`));
    }
    if(this.passwordMode) {
      // Each historical signature is verified with that revision's exact key;
      // sending to a new active chat still requires the current trusted keys.
      if(!chat.archived)await this.getRecords(humanIds,approveTrust);
      await this.getHistoricalRecords(chat,manifests,approveTrust,archiveTrustProof);
    }else{
      const ids=manifests.flatMap(m=>m.payload?.members?.map(r=>r.userId)||[]);
      await this.getRecords(ids,approveTrust);
    }
    let previous=null;
    for(const signed of manifests) { await this.verifyManifest(signed,previous,chat); previous=signed; }
    if(!previous) fail('加密成员记录缺失。');
    const latest=previous,hash=await digest(latest),pinKey=this.scope+`chat:${chat.id}`,pin=await this.storage.get(pinKey);
    if(pin) {
      if(latest.payload.revision<pin.revision || !manifests[pin.revision-1] || await digest(manifests[pin.revision-1])!==pin.hash || pin.ownerId!==chat.ownerId) fail('检测到聊天成员记录回退或分叉，已阻止收发。');
    }
    if(!latest.payload.members.some(m=>m.userId===this.user.id)) fail('你已不在此聊天的加密成员中。');
    // Raw metadata cannot add recipients. Any discrepancy is surfaced, not adopted.
    if(!same([...humanIds].sort(),latest.payload.members.map(m=>m.userId).sort())) fail('服务器成员列表与签名记录不一致，已阻止收发。');
    if(!chat.archived&&latest.payload.members.some(m=>this.records.get(m.userId)?.fingerprint!==m.fingerprint))fail('会话的加密身份已经变化，请从新版会话继续发送。');
    this.guard(epoch);
    const newPin={revision:latest.payload.revision,hash,ownerId:chat.ownerId};
    if(this.storage.pinChat) await this.storage.pinChat(pinKey,newPin,await Promise.all(manifests.map(m=>digest(m))));
    else await this.storage.set(pinKey,newPin);
    this.guard(epoch);
    this.chains.set(chat.id,manifests);
    if(chat.archived&&archiveTrustProof===null)await this.publishArchiveTrust(chat,newPin,epoch);
    return latest;
  }
  async updateMembers(chat,userIds,approveTrust) {
    this.requireReady(); const epoch=this.epoch;
    if(chat.archived)fail('旧会话已经归档，不能修改成员。');
    if(chat.kind!=='group' || chat.ownerId!==this.user.id) fail('仅群主可以调整加密群成员。');
    const latest=await this.prepareChat(chat,approveTrust);
    const ids=[...new Set([...userIds,this.user.id])].sort();
    if(ids.includes('ai') || ids.length>100) fail('加密群成员无效。');
    const records=await this.getRecords(ids,approveTrust);
    this.guard(epoch);
    const manifest=await this.signManifest({v:1,serverId:this.serverId,chatId:chat.id,kind:chat.kind,ownerId:this.user.id,revision:latest.payload.revision+1,previousHash:await digest(latest),members:records.map(r=>({userId:r.userId,fingerprint:r.fingerprint}))});
    this.guard(epoch);
    const result=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/manifests`,{method:'PUT',body:{manifest}});
    this.guard(epoch);
    this.chains.delete(chat.id);
    if(result.chat) await this.prepareChat(result.chat,approveTrust);
    return result;
  }
  async encrypt(chat,content,clientId,approveTrust) {
    this.requireReady(); const epoch=this.epoch;
    if(chat.archived)fail('旧会话已经归档，请从新会话继续聊天。');
    const sentAt=content.sentAt===undefined ? new Date().toISOString() : content.sentAt;
    if(!validSentAt(sentAt)) fail('消息发送时间无效，请检查设备日期和时间。');
    const manifest=await this.prepareChat(chat,approveTrust);
    if(typeof clientId!=='string' || !clientId || typeof content.text!=='string' || content.text.length>12000) fail('消息内容或长度无效。');
    const envelope={v:1,serverId:this.serverId,chatId:chat.id,clientId,senderId:this.user.id,senderFingerprint:this.fingerprint,revision:manifest.payload.revision,manifestHash:await digest(manifest),recipients:manifest.payload.members};
    if(content.file&&content.file.manifestHash!==envelope.manifestHash) fail('附件加密后群成员已变化，请移除附件并重新选择后发送。');
    const payload={...envelope,kind:content.kind||'text',text:content.text,quote:content.quote||null,file:content.file||null,ai:content.ai||null,sentAt};
    const ciphertext=await pgp.encrypt({message:await pgp.createMessage({text:canonical(payload)}),encryptionKeys:envelope.recipients.map(m=>this.records.get(m.userId).key),signingKeys:this.privateKey,format:'armored'});
    this.guard(epoch); return {...envelope,ciphertext};
  }
  async verifiedPayload(chat,message) {
    this.requireReady(); const epoch=this.epoch;
    if(message.contentVersion!==1 || !message.envelope) fail('此消息不是端到端加密消息。');
    const e=message.envelope;
    if(e.v!==1 || e.serverId!==this.serverId || e.chatId!==chat.id || message.chatId!==chat.id || e.senderId!==message.senderId || e.clientId!==message.clientId || !isArmor(e.ciphertext,'MESSAGE')) fail('消息路由或发送者校验失败。');
    let chain=this.chains.get(chat.id);
    if(!chain?.[e.revision-1]) {
      // A page of history uses the same physical room snapshot. Only share a
      // read within this unlocked identity. Each envelope is still verified.
      let load=this.messageManifestLoads.get(chat);
      if(!load || load.epoch!==epoch) {
        load={epoch,promise:this.prepareChat(chat)};
        this.messageManifestLoads.set(chat,load);
      }
      try { await load.promise; }
      finally { if(this.messageManifestLoads.get(chat)===load)this.messageManifestLoads.delete(chat); }
      this.guard(epoch);
      chain=this.chains.get(chat.id);
    }
    const manifest=chain?.[e.revision-1];
    if(!manifest || await digest(manifest)!==e.manifestHash || !same(manifest.payload.members,e.recipients)) fail('消息收件人与签名成员记录不一致。');
    const sender=this.recordFor(e.senderId,e.senderFingerprint);
    if(!sender || sender.fingerprint!==e.senderFingerprint || !e.recipients.some(r=>r.userId===e.senderId&&r.fingerprint===e.senderFingerprint)) fail('消息发送者不属于已验证的成员。');
    if(!e.recipients.some(r=>r.userId===this.user.id)) fail('这条消息发送于你加入之前，未向你提供解密权限。');
    const options=await this.decryptionOptionsFor(chat,message,e.ciphertext,{part:'message'});let result;
    try {
      this.guard(epoch);result=await pgp.decrypt({message:await pgp.readMessage({armoredMessage:e.ciphertext}),...options,verificationKeys:sender.key,expectSigned:true,format:'utf8'});
      if(result.signatures.length!==1) fail('消息缺少有效的发送者签名。');await result.signatures[0].verified;
    } finally {wipeSessionKeys(options);}
    let payload; try { payload=JSON.parse(result.data); } catch { fail('加密消息格式无效。'); }
    if(!same(bindings(payload),bindings(e)) || !['text','ai-result'].includes(payload.kind) || typeof payload.text!=='string' || payload.text.length>12000 || (payload.kind==='ai-result' && payload.ai?.requestedBy!==e.senderId)) fail('消息签名内容与外层信息不一致。');
    if(payload.sentAt!==undefined && !validSentAt(payload.sentAt)) fail('消息签名中的发送时间无效。');
    if(payload.file) {
      const f=payload.file,chunked=f.format==='pgp-chunks-v1';
      if(typeof f.name!=='string'||f.name.length>255||typeof f.mime!=='string'||f.mime.length>128||!Number.isSafeInteger(f.size)||f.size<0||(!chunked&&f.size>MAX_FILE)||!/^[a-f0-9]{64}$/.test(f.sha256)||f.id!==message.file?.id||f.manifestHash!==e.manifestHash) fail('加密附件信息无效。');
      if(chunked && (Object.keys(f).some(k=>!['id','format','name','mime','size','chunkSize','chunkCount','manifestHash','sha256'].includes(k))||f.chunkSize!==4*1024*1024||!Number.isSafeInteger(f.chunkCount)||f.chunkCount!==Math.max(1,Math.ceil(f.size/f.chunkSize))||!/^[a-f0-9-]{36}$/i.test(f.id)||message.file?.format!=='pgp-chunks-v1'||message.file?.chunkCount!==f.chunkCount||message.file?.chunkSize!==f.chunkSize)) fail('分块附件签名信息无效。');
      if(f.format!==undefined&&!chunked) fail('不支持此附件加密格式，请更新客户端。');
    }
    this.guard(epoch); return payload;
  }
  async decrypt(chat,message) {
    this.requireReady();
    if(message.contentVersion===0 || (!message.envelope && !message.contentVersion)) return {kind:'text',text:message.text||'',quote:message.quote||null,file:message.file||null,ai:null,legacy:true};
    return this.verifiedPayload(chat,message);
  }
  async encryptAttachment(chat,file,approveTrust) {
    this.requireReady();const epoch=this.epoch;
    if(chat.archived)fail('旧会话已经归档，不能发送新附件。');
    if(file.size>MAX_FILE) fail('文件不能超过 20 MB。');
    const manifest=await this.prepareChat(chat,approveTrust);
    const bytes=await pgp.encrypt({message:await pgp.createMessage({binary:new Uint8Array(await file.arrayBuffer())}),encryptionKeys:manifest.payload.members.map(m=>this.records.get(m.userId).key),signingKeys:this.privateKey,format:'binary'});
    this.guard(epoch);
    return {bytes,meta:{name:String(file.name).slice(0,255),mime:String(file.type||'application/octet-stream').slice(0,128),size:file.size,sha256:await digest(bytes),manifestHash:await digest(manifest)}};
  }
  async decryptAttachment(chat,message,encryptedBytes) {
    const payload=await this.verifiedPayload(chat,message), epoch=this.epoch;
    if(!payload.file || await digest(encryptedBytes)!==payload.file.sha256) fail('附件完整性校验失败，已停止下载。');
    const sender=this.recordFor(message.senderId,message.envelope.senderFingerprint);
    const options=await this.decryptionOptionsFor(chat,message,encryptedBytes,{part:'attachment'});let result;
    try {
      this.guard(epoch);result=await pgp.decrypt({message:await pgp.readMessage({binaryMessage:encryptedBytes}),...options,verificationKeys:sender.key,expectSigned:true,format:'binary'});
      if(result.signatures.length!==1) fail('附件发送者签名无效。');await result.signatures[0].verified;
    } finally {wipeSessionKeys(options);}
    if(result.data.byteLength!==payload.file.size) fail('附件大小校验失败。');
    this.guard(epoch); return {bytes:result.data,name:payload.file.name,mime:payload.file.mime};
  }
  async encryptLocal(value) {
    this.requireReady();const epoch=this.epoch;
    const ciphertext=await pgp.encrypt({message:await pgp.createMessage({text:canonical({v:1,serverId:this.serverId,userId:this.user.id,purpose:'local-cache',value})}),encryptionKeys:this.records.get(this.user.id).key,signingKeys:this.privateKey,format:'armored'});
    this.guard(epoch);return ciphertext;
  }
  async decryptLocal(ciphertext) {
    this.requireReady();const epoch=this.epoch;
    const result=await pgp.decrypt({message:await pgp.readMessage({armoredMessage:ciphertext}),decryptionKeys:this.privateKey,verificationKeys:this.records.get(this.user.id).key,expectSigned:true,format:'utf8'});
    if(result.signatures.length!==1) fail('本地加密缓存签名无效。');
    await result.signatures[0].verified;
    const payload=JSON.parse(result.data);
    if(payload.v!==1 || payload.serverId!==this.serverId || payload.userId!==this.user.id || payload.purpose!=='local-cache') fail('本地缓存不属于当前加密账户。');
    this.guard(epoch); return payload.value;
  }
}
