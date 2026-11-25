import * as pgp from './vendor/openpgp.min.mjs';
import {canonical,digest} from './e2ee.mjs';
import {iterateAttachment} from './attachments.mjs';

const fail=message=>{throw new Error(message);};
const same=(a,b)=>canonical(a)===canonical(b);
const abort=signal=>{if(signal?.aborted)throw signal.reason||new DOMException('已取消','AbortError');};
const algorithms={aes128:16,aes192:24,aes256:32};
function armor(ciphertext){return typeof ciphertext==='string'?{armoredMessage:ciphertext}:{binaryMessage:ciphertext};}
function requestPayload(value){return {v:value.v,purpose:value.purpose,serverId:value.serverId,chatId:value.chatId,requestId:value.requestId,requesterId:value.requesterId,targetFingerprint:value.targetFingerprint,helperId:value.helperId};}
async function sign(payload,key){return pgp.sign({message:await pgp.createMessage({text:canonical(payload)}),signingKeys:key,detached:true,format:'armored'});}
async function verify(payload,signature,key){
  const result=await pgp.verify({message:await pgp.createMessage({text:canonical(payload)}),signature:await pgp.readSignature({armoredSignature:signature}),verificationKeys:key});
  if(result.signatures.length!==1)fail('协助恢复数字签名无效。');await result.signatures[0].verified;
}

export class ArchiveAssist {
  constructor(box){this.box=box;}
  lock(){/* No session keys or plaintext are cached across decryptions. */}
  peer(chat,{allowFormer=false}={}){
    this.box.requireReady();
    const members=chat?.members?.map(member=>member.id);
    if(!chat?.archived||chat.kind!=='direct'||(!allowFormer&&chat.friendshipStatus!=='accepted')||members?.length!==2||members.includes('ai')||new Set(members).size!==2||!members.includes(this.box.user.id))fail('仅原有两人好友的旧加密私聊支持协助恢复。');
    return members.find(id=>id!==this.box.user.id);
  }
  path(chat,suffix=''){return `/api/chats/${encodeURIComponent(chat.id)}/archive-assist${suffix}`;}
  async status(chat){this.peer(chat);const epoch=this.box.epoch;const value=await this.box.api(this.path(chat));this.box.guard(epoch);return value;}
  expectedRequest(chat,request,requesterId,targetFingerprint,helperId){
    const expected={v:1,purpose:'archive-assist-request',serverId:this.box.serverId,chatId:chat.id,requestId:request?.requestId,requesterId,targetFingerprint,helperId};
    if(typeof request?.requestId!=='string'||!same(requestPayload(request),expected))fail('协助请求和当前会话或加密身份不一致。');return expected;
  }
  async request(chat){
    const helperId=this.peer(chat),box=this.box,epoch=box.epoch;
    const payload={v:1,purpose:'archive-assist-request',serverId:box.serverId,chatId:chat.id,requestId:crypto.randomUUID(),requesterId:box.user.id,targetFingerprint:box.fingerprint,helperId};
    const signature=await sign(payload,box.privateKey);box.guard(epoch);
    const result=await box.api(this.path(chat),{method:'POST',body:{payload,signature}});box.guard(epoch);
    const saved=this.expectedRequest(chat,result.outgoing,box.user.id,box.fingerprint,helperId);
    await verify(saved,result.outgoing.signature,box.records.get(box.user.id).key);box.guard(epoch);return result;
  }
  async binding(chat,message,ciphertext,part,request,index=null){
    const box=this.box,e=message.envelope,peer=this.peer(chat,{allowFormer:request.requesterId===box.user.id}),original=box.chains.get(chat.id)?.[e?.revision-1];
    if(message.contentVersion!==1||!message.id||message.chatId!==chat.id||e?.chatId!==chat.id||e.serverId!==box.serverId||e.senderId!==message.senderId||e.clientId!==message.clientId||!original||await digest(original)!==e.manifestHash||!same(original.payload.members,e.recipients)||e.recipients.length!==2||!e.recipients.some(r=>r.userId===box.user.id)||!e.recipients.some(r=>r.userId===peer))fail('原消息未得到完整的原始签名成员验证。');
    const target=e.recipients.find(r=>r.userId===request.requesterId),helper=e.recipients.find(r=>r.userId===request.helperId);
    if(!target||!helper||target.userId===helper.userId||target.fingerprint===request.targetFingerprint||!box.recordFor(helper.userId,helper.fingerprint)||!box.recordFor(target.userId,target.fingerprint))fail('协助恢复的原始身份不一致。');
    return {v:1,purpose:'archive-assist-grant',serverId:box.serverId,chatId:chat.id,requestId:request.requestId,messageId:message.id,clientId:message.clientId,manifestHash:e.manifestHash,cipherHash:await digest(ciphertext),part,index,fileId:part==='message'?null:message.file?.id,helperId:helper.userId,helperFingerprint:helper.fingerprint,requesterId:target.userId,targetFingerprint:request.targetFingerprint};
  }
  async makeGrant(chat,message,ciphertext,part,request,targetKey,helperKey,index=null){
    const box=this.box,epoch=box.epoch,binding=await this.binding(chat,message,ciphertext,part,request,index);
    if(helperKey.getFingerprint()!==binding.helperFingerprint||targetKey.getFingerprint()!==binding.targetFingerprint)fail('协助密钥的指纹不一致。');
    const sessions=await pgp.decryptSessionKeys({message:await pgp.readMessage(armor(ciphertext)),decryptionKeys:helperKey});
    try {
      if(sessions.length!==1||!algorithms[sessions[0].algorithm]||sessions[0].data.length!==algorithms[sessions[0].algorithm])fail('此消息无法安全提取独立的会话密钥。');
      const session={algorithm:sessions[0].algorithm,data:btoa(String.fromCharCode(...sessions[0].data))};
      const encryptedSessionKey=await pgp.encrypt({message:await pgp.createMessage({text:canonical({v:1,purpose:'archive-session-key',binding,session})}),encryptionKeys:targetKey,signingKeys:helperKey,format:'armored'});
      const payload={...binding,encryptedSessionKey};const signature=await sign(payload,helperKey);box.guard(epoch);return {payload,signature};
    } finally {for(const session of sessions)session.data?.fill(0);}
  }
  async chunkGrants(chat,message,request,target,local,{signal,onProgress}){
    const box=this.box,epoch=box.epoch;let currentCipher=null,index=0;const grants=[];
    // Capture only the encrypted bytes already fetched by iterateAttachment.
    // Its generator verifies each original sender signature, exact index,
    // file binding, chain link and final signed aggregate before we transmit
    // any chunk authorization. Plain chunks are never copied by this path.
    const api=async(path,opts)=>{const response=await box.api(path,opts);if(opts?.response==='bytes')currentCipher=response;return response;};
    try {
      for await(const plain of iterateAttachment({box,api,chat,message,signal})){
        try {abort(signal);box.guard(epoch);if(!currentCipher)fail('附件分块密文缺失。');grants.push(await this.makeGrant(chat,message,currentCipher,'chunk',request,target.key,local,index++));onProgress?.({chunkIndex:index,chunkCount:message.file.chunkCount});}
        finally {plain.fill(0);currentCipher=null;}
      }
      if(index!==message.file.chunkCount)fail('附件分块数量不一致。');
      return grants;
    } finally {currentCipher?.fill(0);}
  }
  async grant(chat,messages,{signal,onProgress,approveTrust}={}){
    const requesterId=this.peer(chat),box=this.box,epoch=box.epoch;abort(signal);
    const status=await this.status(chat);if(!status.incoming)fail('对方尚未请求协助恢复。');
    const [target]=await box.getRecords([requesterId],approveTrust);abort(signal);box.guard(epoch);
    const request=this.expectedRequest(chat,status.incoming,requesterId,target.fingerprint,box.user.id);
    await verify(request,status.incoming.signature,target.key);await box.prepareChat(chat,approveTrust);abort(signal);box.guard(epoch);
    let granted=0,skipped=0,attachmentSkipped=0,processed=0;
    for(const message of messages) {
      abort(signal);box.guard(epoch);
      let grants=null,chunks=[];
      try {
        const local=box.decryptionKeyFor?.(message);
        // An old key restored on this helper device is accepted, but a grant
        // received from someone else cannot be forwarded by this feature.
        if(!local)fail('本设备没有用于解锁原消息的私钥。');
        const payload=await box.verifiedPayload(chat,message);abort(signal);box.guard(epoch);
        grants=[await this.makeGrant(chat,message,message.envelope.ciphertext,'message',request,target.key,local)];
        if(payload.file&&message.file){
          if(payload.file.format==='pgp-chunks-v1'){
            try {chunks=await this.chunkGrants(chat,message,request,target,local,{signal,onProgress:progress=>onProgress?.({granted,skipped,attachmentSkipped,processed,total:messages.length,...progress})});}
            catch(error){abort(signal);box.guard(epoch);attachmentSkipped++;}
          }
          else {
            let cipher,plain;
            try {
              cipher=await box.api(`/api/files/${encodeURIComponent(message.file.id)}`,{response:'bytes',maxBytes:25*1024*1024,signal});abort(signal);
              plain=await box.decryptAttachment(chat,message,cipher);abort(signal);box.guard(epoch);
              grants.push(await this.makeGrant(chat,message,cipher,'attachment',request,target.key,local));
            } catch(error) {abort(signal);box.guard(epoch);attachmentSkipped++;}
            finally{cipher?.fill(0);plain?.bytes?.fill(0);}
          }
        }
      } catch(error){abort(signal);box.guard(epoch);if(message.file)attachmentSkipped++;grants=null;}
      if(grants){abort(signal);box.guard(epoch);await box.api(this.path(chat,'/grants'),{method:'POST',body:{grants},signal});box.guard(epoch);granted++;
        for(let start=0;start<chunks.length;start+=12){abort(signal);box.guard(epoch);await box.api(this.path(chat,'/grants'),{method:'POST',body:{grants:chunks.slice(start,start+12)},signal});box.guard(epoch);}
      }else skipped++;
      processed++;onProgress?.({granted,skipped,attachmentSkipped,processed,total:messages.length});
    }
    return {granted,skipped,attachmentSkipped,processed};
  }
  async decryptionOptionsFor(chat,message,ciphertext,{part='message',index=null}={}){
    const box=this.box,epoch=box.epoch;
    if(!['message','attachment','chunk'].includes(part)||(part==='chunk'?(!Number.isSafeInteger(index)||index<0):index!==null)||!chat?.archived||chat.kind!=='direct')return null;
    const helperId=this.peer(chat,{allowFormer:true}),path=this.path(chat,`/grants/${encodeURIComponent(message.id)}/${part}${part==='chunk'?`/${index}`:''}`);
    let result;try{result=await box.api(path);}catch(error){if(error.status===403||error.status===404)return null;throw error;}
    box.guard(epoch);if(!result.grant)return null;
    const request=this.expectedRequest(chat,result.request?.payload,box.user.id,box.fingerprint,helperId);
    await verify(request,result.request.signature,box.records.get(box.user.id).key);
    const expected=await this.binding(chat,message,ciphertext,part,request,index),{encryptedSessionKey,...actual}=result.grant.payload||{};
    if(!same(actual,expected)||typeof encryptedSessionKey!=='string')fail('恢复授权与原始加密消息不一致。');
    const helper=box.recordFor(expected.helperId,expected.helperFingerprint);
    await verify(result.grant.payload,result.grant.signature,helper.key);
    const opened=await pgp.decrypt({message:await pgp.readMessage({armoredMessage:encryptedSessionKey}),decryptionKeys:box.privateKey,verificationKeys:helper.key,expectSigned:true,format:'utf8'});
    if(opened.signatures.length!==1)fail('恢复授权签名无效。');await opened.signatures[0].verified;
    let recovered;try{recovered=JSON.parse(opened.data);}catch{fail('恢复授权格式无效。');}
    if(recovered.v!==1||recovered.purpose!=='archive-session-key'||!same(recovered.binding,expected)||!algorithms[recovered.session?.algorithm]||typeof recovered.session?.data!=='string'||recovered.session.data.length>48)fail('会话密钥的原始消息身份不一致。');
    const data=Uint8Array.from(atob(recovered.session.data),c=>c.charCodeAt(0));
    if(data.length!==algorithms[recovered.session.algorithm]){data.fill(0);fail('恢复会话密钥长度不正确。');}
    try{box.guard(epoch);return {sessionKeys:[{algorithm:recovered.session.algorithm,data}]};}catch(error){data.fill(0);throw error;}
  }
}
