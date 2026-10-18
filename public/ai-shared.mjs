import * as pgp from './vendor/openpgp.min.mjs';
import {canonical,digest} from './e2ee.mjs';
import {normalizeAIBaseUrl,validateAIKey} from './ai-direct.mjs';

const fail=message=>{throw new Error(message);};
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const fingerprint=/^[a-f0-9]{40,64}$/, hex=/^[a-f0-9]{64}$/;
const payloadFields=['v','purpose','serverId','configId','revision','previousHash','ownerId','ownerFingerprint','baseUrl','model','enabled','recipients','ciphertextHash'].sort();
const same=(a,b)=>canonical(a)===canonical(b);
function profile(value) {
  const p=value || {enabled:false,baseUrl:'',model:''};
  if(typeof p.enabled!=='boolean'||typeof p.baseUrl!=='string'||typeof p.model!=='string') fail('看图或生图模型设置不完整。');
  const baseUrl=p.baseUrl?normalizeAIBaseUrl(p.baseUrl):'';
  if(p.enabled&&(!baseUrl||!p.model)||p.model&&!/^[A-Za-z0-9_.:/-]{1,200}$/.test(p.model)||/:online(?:$|:)/i.test(p.model)) fail('请填写看图或生图的接口与模型。');
  return {enabled:p.enabled,baseUrl,model:p.model};
}
export async function sharedAIHistoryEntry(configuration) {
  return {payload:configuration.payload,signature:configuration.signature,hash:await digest({payload:configuration.payload,signature:configuration.signature})};
}
function check(box,epoch,signal) {
  box.guard(epoch);
  if(signal?.aborted) throw new DOMException('请求已取消','AbortError');
}
async function cancellable(promise,signal) {
  if(!signal) return promise;
  if(signal.aborted) throw new DOMException('请求已取消','AbortError');
  let cancel;
  try {return await Promise.race([promise,new Promise((resolve,reject)=>{cancel=()=>reject(new DOMException('请求已取消','AbortError'));signal.addEventListener('abort',cancel,{once:true});})]);}
  finally {if(cancel)signal.removeEventListener('abort',cancel);}
}
function trustCallback(box,epoch,signal,approveTrust) {
  return async unknown=>{check(box,epoch,signal);const ok=await cancellable(Promise.resolve(approveTrust?.(unknown)||false),signal);check(box,epoch,signal);return ok;};
}
function metadata(payload) {
  const {ciphertextHash,...rest}=payload; return rest;
}
function validatePayload(box,p) {
  const fields=p?.v===3?[...payloadFields,'searchEnabled','vision','image'].sort():p?.v===2?[...payloadFields,'searchEnabled'].sort():payloadFields;
  if(!p || !same(Object.keys(p).sort(),fields) || ![1,2,3].includes(p.v) || p.v>=2&&typeof p.searchEnabled!=='boolean' || p.purpose!=='shanshui-ai-shared' || p.serverId!==box.serverId || !uuid.test(p.configId) || !uuid.test(p.ownerId) || !fingerprint.test(p.ownerFingerprint) || !Number.isSafeInteger(p.revision) || p.revision<1 || p.revision>4096 || !(p.previousHash===null||hex.test(p.previousHash)) || !hex.test(p.ciphertextHash) || typeof p.enabled!=='boolean') fail('AI 配置签名资料不完整。');
  if(p.v===3) for(const name of ['vision','image']) if(!p[name]||!same(p[name],profile(p[name]))) fail('多模态模型签名资料无效。');
  if(normalizeAIBaseUrl(p.baseUrl)!==p.baseUrl || typeof p.model!=='string' || !/^[A-Za-z0-9_.:/-]{1,200}$/.test(p.model) || /:online(?:$|:)/i.test(p.model)) fail('AI 接口或模型配置无效。');
  if(!Array.isArray(p.recipients)||p.recipients.length<1||p.recipients.length>200) fail('AI 授权用户清单无效。');
  let prior='';
  for(const r of p.recipients) {
    if(!r || !same(Object.keys(r).sort(),['fingerprint','userId']) || !uuid.test(r.userId) || !fingerprint.test(r.fingerprint) || r.userId<=prior) fail('AI 授权用户清单无效。');
    prior=r.userId;
  }
  if(!p.recipients.some(r=>r.userId===p.ownerId&&r.fingerprint===p.ownerFingerprint)) fail('AI 管理员身份不在授权清单中。');
}
async function verifiedHistory(box,configuration,history,approveTrust,epoch,signal) {
  check(box,epoch,signal);
  validatePayload(box,configuration?.payload);
  if(typeof configuration.signature!=='string'||configuration.signature.length>65536 || typeof configuration.ciphertext!=='string'||configuration.ciphertext.length>262144||!configuration.ciphertext.startsWith('-----BEGIN PGP MESSAGE-----')) fail('AI 加密配置格式无效。');
  const p=configuration.payload;
  if(!Array.isArray(history)||history.length!==p.revision||history.length>4096) fail('AI 配置历史不完整，已停止连接。');
  const storageKey=box.scope+'ai-config-pin',pin=await box.storage.get(storageKey);
  check(box,epoch,signal);
  if(pin&&(pin.ownerId!==p.ownerId||pin.ownerFingerprint!==p.ownerFingerprint||pin.revision>p.revision)) fail('AI 管理员身份被替换或配置发生回退，已停止连接。');
  const [owner]=await cancellable(box.getRecords([p.ownerId],trustCallback(box,epoch,signal,approveTrust)),signal);
  check(box,epoch,signal);
  if(owner.fingerprint!==p.ownerFingerprint) fail('AI 管理员签名身份不匹配。');
  const hashes=[],ids=new Set(); let previousHash=null;
  for(let i=0;i<history.length;i++) {
    const item=history[i],entry=item?.payload; validatePayload(box,entry);
    if(entry.revision!==i+1||entry.previousHash!==previousHash||entry.ownerId!==p.ownerId||entry.ownerFingerprint!==p.ownerFingerprint||ids.has(entry.configId)||typeof item.signature!=='string'||item.signature.length>65536) fail('AI 配置签名链被修改，已停止连接。');
    ids.add(entry.configId);
    const result=await pgp.verify({message:await pgp.createMessage({text:canonical(entry)}),signature:await pgp.readSignature({armoredSignature:item.signature}),verificationKeys:owner.key});
    if(result.signatures.length!==1) fail('AI 配置数字签名无效。');
    await result.signatures[0].verified;
    previousHash=await digest({payload:entry,signature:item.signature});
    if(item.hash!==previousHash) fail('AI 配置历史校验失败。');
    hashes.push(previousHash); check(box,epoch,signal);
  }
  const last=history.at(-1);
  if(!same(last.payload,p)||last.signature!==configuration.signature||await digest(configuration.ciphertext)!==p.ciphertextHash) fail('AI 加密配置被修改，已停止连接。');
  if(pin&&hashes[pin.revision-1]!==pin.hash) fail('AI 配置发生分叉，已停止连接。');
  const self=p.recipients.find(r=>r.userId===box.user.id);
  if(!self||self.fingerprint!==box.fingerprint) fail('此账户尚未获准使用 AI，请联系管理员授权。');
  check(box,epoch,signal);
  return {owner,hashes,pin,storageKey};
}

export async function unlockSharedAIConfiguration(box,{configuration,history,approveTrust,approveEndpoint,signal}={}) {
  box.requireReady(); const epoch=box.epoch;
  const verified=await verifiedHistory(box,configuration,history,approveTrust,epoch,signal);
  const p=configuration.payload;
  const result=await pgp.decrypt({message:await pgp.readMessage({armoredMessage:configuration.ciphertext}),decryptionKeys:box.privateKey,verificationKeys:verified.owner.key,expectSigned:true,format:'utf8'});
  if(result.signatures.length!==1) fail('AI 密钥密文签名无效。');
  await result.signatures[0].verified;
  if(typeof result.data!=='string'||result.data.length>65536) fail('AI 密钥配置大小无效。');
  let secret; try {secret=JSON.parse(result.data);} catch {fail('AI 密钥密文内容无效。');}
  const secretFields=p.v===3?['configuration','imageKey','key','purpose','tavilyKey','v','visionKey']:p.v===2?['configuration','key','purpose','tavilyKey','v']:['configuration','key','purpose','v'];
  if(secret?.v!==p.v||!same(Object.keys(secret||{}).sort(),secretFields)||secret.purpose!=='shanshui-ai-shared-secret'||!same(secret.configuration,metadata(p))) fail('AI 密钥与签名配置不匹配。');
  if(p.enabled||secret.key) validateAIKey(secret.key); else if(secret.key!=='') fail('AI 密钥格式无效。');
  const searchEnabled=p.v>=2&&p.searchEnabled;
  if(p.v>=2) { if(searchEnabled||secret.tavilyKey) validateAIKey(secret.tavilyKey); else if(secret.tavilyKey!=='') fail('Tavily Key 格式无效。'); }
  if(p.v===3) for(const name of ['vision','image']) { if(p[name].enabled||secret[name+'Key']) validateAIKey(secret[name+'Key']); else if(secret[name+'Key']!=='') fail('多模态模型 Key 无效。'); }
  check(box,epoch,signal);
  if(!verified.pin||verified.pin.baseUrl!==p.baseUrl) {
    if(!approveEndpoint||!await cancellable(Promise.resolve(approveEndpoint({baseUrl:p.baseUrl,model:p.model,revision:p.revision,previousBaseUrl:verified.pin?.baseUrl||null})),signal)) fail('尚未确认 AI 接口，已停止连接。');
    check(box,epoch,signal);
  }
  const profileEndpoints={};
  if(p.v===3) for(const name of ['vision','image']) if(p[name].enabled) {
    const endpoint=p[name].baseUrl, prior=verified.pin?.profileEndpoints?.[name];
    if(endpoint!==p.baseUrl&&endpoint!==prior) {
      if(!approveEndpoint||!await cancellable(Promise.resolve(approveEndpoint({baseUrl:endpoint,model:p[name].model,capability:name,revision:p.revision,previousBaseUrl:prior||null})),signal)) fail('尚未确认多模态模型接口，已停止连接。');
      check(box,epoch,signal);
    }
    profileEndpoints[name]=endpoint;
  }
  const newPin={revision:p.revision,hash:verified.hashes.at(-1),ownerId:p.ownerId,ownerFingerprint:p.ownerFingerprint,baseUrl:p.baseUrl,profileEndpoints};
  const pinCheck=prior=>{
    check(box,epoch,signal);
    if(prior&&(prior.revision>p.revision||prior.ownerId!==p.ownerId||prior.ownerFingerprint!==p.ownerFingerprint||verified.hashes[prior.revision-1]!==prior.hash)) fail('AI 配置回退或分叉，已停止连接。');
    return {value:true,write:newPin};
  };
  if(box.storage.checkedWrite) await box.storage.checkedWrite(verified.storageKey,pinCheck);
  else {pinCheck(await box.storage.get(verified.storageKey));check(box,epoch,signal);await box.storage.set(verified.storageKey,newPin);}
  check(box,epoch,signal);
  const profiles=Object.fromEntries(['vision','image'].map(name=>[name,p.v===3?{...p[name],enabled:p.enabled&&p[name].enabled,key:secret[name+'Key'],mode:'shared_direct',apiFormat:name==='image'?'images_generations':'chat_completions'}:{enabled:false}]));
  return {mode:'shared_direct',apiFormat:'chat_completions',baseUrl:p.baseUrl,key:secret.key,model:p.model,enabled:p.enabled,searchEnabled,tavilyKey:p.v>=2?secret.tavilyKey:'',configId:p.configId,revision:p.revision,...profiles};
}

export async function createSharedAIConfiguration(box,{baseUrl,model,key,enabled=true,searchEnabled=false,tavilyKey='',vision,image,recipientIds,previousConfiguration=null,history=[],approveTrust,signal}={}) {
  box.requireReady();const epoch=box.epoch;
  if(box.user.role!=='admin') fail('只有管理员可以设置统一 AI。');
  baseUrl=normalizeAIBaseUrl(baseUrl);
  if(typeof model!=='string'||!/^[A-Za-z0-9_.:/-]{1,200}$/.test(model)||/:online(?:$|:)/i.test(model)||typeof enabled!=='boolean') fail('请填写正确的模型名称。');
  if(enabled||key) validateAIKey(key);else if(key!=='') fail('API Key 无效。');
  if(typeof searchEnabled!=='boolean') fail('Tavily 设置无效。');
  if(searchEnabled||tavilyKey) validateAIKey(tavilyKey);else if(tavilyKey!=='') fail('Tavily Key 无效。');
  const multimodal=vision!==undefined||image!==undefined, profiles={}, profileKeys={};
  if(multimodal) for(const [name,value] of Object.entries({vision,image})) {
    profiles[name]=profile(value); const valueKey=value?.key || '';
    if(profiles[name].enabled||valueKey) validateAIKey(valueKey);
    profileKeys[name+'Key']=valueKey;
  }
  let revision=1,previousHash=null;
  if(previousConfiguration) {
    await verifiedHistory(box,previousConfiguration,history,approveTrust,epoch,signal);
    if(previousConfiguration.payload.ownerId!==box.user.id||previousConfiguration.payload.ownerFingerprint!==box.fingerprint) fail('AI 原管理员身份不匹配。');
    revision=previousConfiguration.payload.revision+1;
    previousHash=await digest({payload:previousConfiguration.payload,signature:previousConfiguration.signature});
  } else if(history.length || await box.storage.get(box.scope+'ai-config-pin')) fail('原有 AI 配置记录缺失，请恢复服务器数据后再设置。');
  if(revision>4096) fail('AI 配置修订数量已达安全上限，请联系维护者。');
  if(!Array.isArray(recipientIds)||recipientIds.length>200) fail('AI 授权用户清单无效。');
  const ids=[...new Set([...recipientIds,box.user.id])].sort();
  if(ids.length>200||ids.some(id=>!uuid.test(id))) fail('AI 授权用户清单无效。');
  const records=await cancellable(box.getRecords(ids,trustCallback(box,epoch,signal,approveTrust)),signal);check(box,epoch,signal);
  const meta={v:multimodal?3:2,purpose:'shanshui-ai-shared',serverId:box.serverId,configId:crypto.randomUUID(),revision,previousHash,ownerId:box.user.id,ownerFingerprint:box.fingerprint,baseUrl,model,enabled,searchEnabled,...profiles,recipients:records.map(r=>({userId:r.userId,fingerprint:r.fingerprint}))};
  const ciphertext=await pgp.encrypt({message:await pgp.createMessage({text:canonical({v:meta.v,purpose:'shanshui-ai-shared-secret',configuration:meta,key,tavilyKey,...profileKeys})}),encryptionKeys:records.map(r=>r.key),signingKeys:box.privateKey,format:'armored'});
  check(box,epoch,signal);
  if(ciphertext.length>262144) fail('AI 授权配置过大，请减少用户数量。');
  const payload={...meta,ciphertextHash:await digest(ciphertext)};validatePayload(box,payload);
  const signed=await box.signManifest(payload);check(box,epoch,signal);
  return {...signed,ciphertext};
}
