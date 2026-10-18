import * as pgp from './vendor/openpgp.min.mjs';
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
const same = (a, b) => canonical(a) === canonical(b);
const fail = message => { throw new Error(message); };
const MAX_FILE = 20 * 1024 * 1024;
const bindings = e => ({ v:e.v, serverId:e.serverId, chatId:e.chatId, clientId:e.clientId, senderId:e.senderId, senderFingerprint:e.senderFingerprint, revision:e.revision, manifestHash:e.manifestHash, recipients:e.recipients });
const isArmor = (s, kind) => typeof s === 'string' && s.startsWith(`-----BEGIN PGP ${kind}-----`);
const cleanCode = code => String(code || '').replace(/[\s-]/g, '').toUpperCase();
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
    this.scope=`${serverId}:${user.id}:`; this.identity=null; this.privateKey=null; this.code=null;
    this.records=new Map(); this.chains=new Map(); this.epoch=0;
  }
  get fingerprint() { return this.identity?.fingerprint || ''; }
  get ready() { return Boolean(this.privateKey); }
  requireReady() { if (!this.ready) fail('请先用恢复码解锁加密消息。'); }
  guard(epoch) { if (epoch !== this.epoch || !this.ready) fail('加密会话已锁定，请重新解锁。'); }
  async pin(record, permit=false) {
    const k=this.scope+`pin:${record.userId}`, prior=await this.storage.get(k);
    if(this.storage.pinIdentity) return this.storage.pinIdentity(k,record.fingerprint,permit);
    if (prior && prior !== record.fingerprint) fail('安全验证失败：联系人密钥发生变化，已阻止收发。请通过其他渠道核对指纹。');
    if (!prior && !permit) return false;
    if (!prior) await this.storage.set(k,record.fingerprint);
    return true;
  }
  async parseRecord(record) {
    if (!record || !/^[a-f0-9]{40,64}$/.test(record.fingerprint) || typeof record.userId!=='string' || !isArmor(record.publicKey,'PUBLIC KEY BLOCK') || record.publicKey.length>65536) fail('服务器返回了无效的加密身份。');
    const key=await pgp.readKey({armoredKey:record.publicKey});
    if (key.isPrivate() || key.getFingerprint()!==record.fingerprint) fail('公钥指纹不匹配，已阻止收发。');
    await key.verifyPrimaryKey();
    await key.getEncryptionKey();
    return {...record,key};
  }
  async initialize() {
    const epoch=this.epoch;
    if (globalThis.isSecureContext === false) fail('端到端加密需要 HTTPS。请使用安全域名或安装版客户端。');
    const {identity}=await this.api('/api/e2ee/identity');
    if(epoch!==this.epoch) fail('加密会话已关闭。');
    this.identity=identity;
    if (!identity) {
      if (await this.storage.get(this.scope+'own-identity')) fail('服务器的加密身份记录缺失。为避免丢失历史，请恢复原服务器数据，不要创建新密钥。');
      return {status:'new',identity:null};
    }
    if (identity.userId!==this.user.id) fail('加密身份不属于当前账户。');
    const record=await this.parseRecord(identity);
    await this.pin(record,true);
    await this.storage.set(this.scope+'own-identity',identity.fingerprint);
    this.records.set(record.userId,record);
    const wrapped=await this.storage.get(this.scope+'remembered');
    if(epoch!==this.epoch) fail('加密会话已关闭。');
    if (wrapped) {
      try {
        const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:wrapped.iv,additionalData:utf8.encode(this.scope)},wrapped.key,wrapped.bytes);
        if(epoch!==this.epoch) fail('加密会话已关闭。');
        await this.unlock(new TextDecoder().decode(bytes));
      } catch { await this.storage.delete(this.scope+'remembered'); }
    }
    if(epoch!==this.epoch) { await this.lock(); fail('加密会话已关闭。'); }
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
    const seed=crypto.getRandomValues(new Uint8Array(32));
    const code=Array.from(seed,x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();
    seed.fill(0);
    const generated=await pgp.generateKey({type:'ecc',curve:'curve25519',userIDs:[{name:`yueti:${this.serverId}:${this.user.id}`}],passphrase:code,format:'armored'});
    const publicKey=await pgp.readKey({armoredKey:generated.publicKey});
    const privateKey=await pgp.decryptKey({privateKey:await pgp.readPrivateKey({armoredKey:generated.privateKey}),passphrase:code});
    const identity={userId:this.user.id,fingerprint:publicKey.getFingerprint(),publicKey:generated.publicKey,encryptedPrivateKey:generated.privateKey};
    const proof=await pgp.sign({message:await pgp.createMessage({text:canonical({v:1,serverId:this.serverId,userId:this.user.id,fingerprint:identity.fingerprint})}),signingKeys:privateKey,detached:true,format:'armored'});
    if(epoch!==this.epoch) fail('加密初始化已取消。请使用保存的恢复码重新登录。');
    this.pendingIdentity={identity,privateKey,code,proof};
    if(!deferRegistration) await this.registerIdentity();
    return {recoveryCode:code.match(/.{1,8}/g).join('-'),identity};
  }
  async registerIdentity() {
    const epoch=this.epoch;
    if(this.ready) return this.identity;
    if(!this.pendingIdentity) fail('请先生成并保存恢复码。');
    const {identity,privateKey,code,proof}=this.pendingIdentity;
    let result;
    try { result=await this.api('/api/e2ee/identity',{method:'POST',body:{...identity,proof}}); }
    catch(error) {
      // A response can be lost after the immutable identity was committed.
      // Retrying the same generated key is essential; never generate another one.
      const current=await this.api('/api/e2ee/identity').catch(()=>null);
      if(!current||!same(current.identity,identity)) throw error;
      result=current;
    }
    if (!same(result.identity,identity)) fail('服务器未正确保存加密身份，请勿继续。');
    if(epoch!==this.epoch) fail('加密初始化已取消。请使用保存的恢复码重新登录。');
    this.identity=identity; this.privateKey=privateKey; this.code=code;
    const record=await this.parseRecord(identity); await this.pin(record,true); this.records.set(record.userId,record);
    await this.storage.set(this.scope+'own-identity',identity.fingerprint);
    this.pendingIdentity=null;
    return identity;
  }
  async unlock(recoveryCode,{remember=false}={}) {
    const epoch=this.epoch;
    if (!this.identity) fail('请先建立加密身份。');
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
    this.epoch++; this.privateKey=null; this.code=null; this.pendingIdentity=null; this.chains.clear();
    if (forget) await this.storage.delete(this.scope+'remembered');
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
    const records=[];
    for (const id of unique) {
      const raw=keys.find(k=>k.userId===id); if(!raw) fail('成员的加密身份缺失。');
      const record=await this.parseRecord(raw); await this.pin(record,id===this.user.id);
      if (id===this.user.id && record.fingerprint!==this.fingerprint) fail('自己的加密身份发生变化。');
      records.push(record);
    }
    const unknown=[];
    for(const record of records) if (!await this.pin(record)) unknown.push({userId:record.userId,fingerprint:record.fingerprint});
    if (unknown.length) {
      if (!approveTrust || !await approveTrust(unknown)) fail('尚未确认联系人的安全指纹。请打开聊天并核对身份。');
      this.guard(epoch);
      for(const record of records) await this.pin(record,true);
    }
    this.guard(epoch); records.forEach(r=>this.records.set(r.userId,r));
    return records;
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
    for(const member of members) if(this.records.get(member.userId)?.fingerprint!==member.fingerprint) fail('聊天成员指纹与已确认的身份不一致。');
    const owner=this.records.get(p.ownerId);
    const result=await pgp.verify({message:await pgp.createMessage({text:canonical(p)}),signature:await pgp.readSignature({armoredSignature:signed.signature}),verificationKeys:owner.key,expectSigned:true});
    if(result.signatures.length!==1) fail('聊天成员签名无效。');
    await result.signatures[0].verified;
  }
  async prepareChat(chat,approveTrust) {
    this.requireReady(); const epoch=this.epoch;
    if(!chat?.id || !chat.ownerId) fail('会话尚未支持加密，请升级服务器。');
    let {manifests}=await this.api(`/api/chats/${encodeURIComponent(chat.id)}/manifests`);
    if(!Array.isArray(manifests) || manifests.length>10000) fail('聊天成员记录无效。');
    const humanIds=(chat.members||[]).map(m=>m.id).filter(id=>id!=='ai');
    if((['notes','ai'].includes(chat.kind)&&(humanIds.length!==1||humanIds[0]!==this.user.id))||(chat.kind==='direct'&&humanIds.length!==2)) fail('会话的加密成员数量不正确。');
    if(!manifests.length) {
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
    const ids=manifests.flatMap(m=>m.payload?.members?.map(r=>r.userId)||[]);
    await this.getRecords(ids,approveTrust);
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
    this.guard(epoch);
    const newPin={revision:latest.payload.revision,hash,ownerId:chat.ownerId};
    if(this.storage.pinChat) await this.storage.pinChat(pinKey,newPin,await Promise.all(manifests.map(m=>digest(m))));
    else await this.storage.set(pinKey,newPin);
    this.guard(epoch);
    this.chains.set(chat.id,manifests);
    return latest;
  }
  async updateMembers(chat,userIds,approveTrust) {
    this.requireReady(); const epoch=this.epoch;
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
    if(!chain || !chain[e.revision-1]) { await this.prepareChat(chat); chain=this.chains.get(chat.id); }
    const manifest=chain[e.revision-1];
    if(!manifest || await digest(manifest)!==e.manifestHash || !same(manifest.payload.members,e.recipients)) fail('消息收件人与签名成员记录不一致。');
    const sender=this.records.get(e.senderId);
    if(!sender || sender.fingerprint!==e.senderFingerprint || !e.recipients.some(r=>r.userId===e.senderId&&r.fingerprint===e.senderFingerprint)) fail('消息发送者不属于已验证的成员。');
    if(!e.recipients.some(r=>r.userId===this.user.id&&r.fingerprint===this.fingerprint)) fail('这条消息发送于你加入之前，未向你提供解密权限。');
    const result=await pgp.decrypt({message:await pgp.readMessage({armoredMessage:e.ciphertext}),decryptionKeys:this.privateKey,verificationKeys:sender.key,expectSigned:true,format:'utf8'});
    if(result.signatures.length!==1) fail('消息缺少有效的发送者签名。');
    await result.signatures[0].verified;
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
    if(file.size>MAX_FILE) fail('文件不能超过 20 MB。');
    const manifest=await this.prepareChat(chat,approveTrust);
    const bytes=await pgp.encrypt({message:await pgp.createMessage({binary:new Uint8Array(await file.arrayBuffer())}),encryptionKeys:manifest.payload.members.map(m=>this.records.get(m.userId).key),signingKeys:this.privateKey,format:'binary'});
    this.guard(epoch);
    return {bytes,meta:{name:String(file.name).slice(0,255),mime:String(file.type||'application/octet-stream').slice(0,128),size:file.size,sha256:await digest(bytes),manifestHash:await digest(manifest)}};
  }
  async decryptAttachment(chat,message,encryptedBytes) {
    const payload=await this.verifiedPayload(chat,message), epoch=this.epoch;
    if(!payload.file || await digest(encryptedBytes)!==payload.file.sha256) fail('附件完整性校验失败，已停止下载。');
    const sender=this.records.get(message.senderId);
    const result=await pgp.decrypt({message:await pgp.readMessage({binaryMessage:encryptedBytes}),decryptionKeys:this.privateKey,verificationKeys:sender.key,expectSigned:true,format:'binary'});
    if(result.signatures.length!==1) fail('附件发送者签名无效。');
    await result.signatures[0].verified;
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
