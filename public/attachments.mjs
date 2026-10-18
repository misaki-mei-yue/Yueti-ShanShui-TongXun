import * as pgp from './vendor/openpgp.min.mjs';
import { canonical, digest } from './e2ee.mjs';

export const ATTACHMENT_FORMAT='pgp-chunks-v1';
export const ATTACHMENT_CHUNK_SIZE=4*1024*1024;
const MAX_CIPHER_CHUNK=ATTACHMENT_CHUNK_SIZE+256*1024;
const EMPTY_HASH='0'.repeat(64), encoder=new TextEncoder(), decoder=new TextDecoder('utf-8',{fatal:true});
const fail=message=>{throw new Error(message);};
const abort=signal=>{if(signal?.aborted) throw signal.reason||new DOMException('已取消','AbortError');};
const chainHash=(previous,index,hash)=>digest(`${previous}:${index}:${hash}`);
const validDescriptor=f=>f?.format===ATTACHMENT_FORMAT&&Number.isSafeInteger(f.size)&&f.size>=0&&f.chunkSize===ATTACHMENT_CHUNK_SIZE&&Number.isSafeInteger(f.chunkCount)&&f.chunkCount===Math.max(1,Math.ceil(f.size/f.chunkSize))&&/^[a-f0-9-]{36}$/i.test(f.id)&&/^[a-f0-9]{64}$/.test(f.sha256)&&/^[a-f0-9]{64}$/.test(f.manifestHash);
function guard(box,epoch,signal) {abort(signal);box.guard(epoch);}
function chunkHeader(box,chat,meta,index,previousHash) {
  return {v:1,purpose:'shanshui-file-chunk',format:ATTACHMENT_FORMAT,serverId:box.serverId,chatId:chat.id,fileId:meta.id,senderId:box.user.id,senderFingerprint:box.fingerprint,manifestHash:meta.manifestHash,index,count:meta.chunkCount,totalSize:meta.size,chunkSize:meta.chunkSize,previousHash};
}

// Only file.slice(...) is read. Even a multi-gigabyte file never becomes one
// arrayBuffer on the sending device or one HTTP request on the server.
export async function uploadAttachment({box,api=box.api,chat,file,approveTrust,signal,onProgress}) {
  box.requireReady(); const epoch=box.epoch;
  if(!file||!Number.isSafeInteger(file.size)||file.size<0||typeof file.slice!=='function') fail('附件信息无效。');
  const manifest=await box.prepareChat(chat,approveTrust);guard(box,epoch,signal);
  const meta={id:crypto.randomUUID(),format:ATTACHMENT_FORMAT,name:String(file.name||'附件').slice(0,255),mime:String(file.type||'application/octet-stream').slice(0,128),size:file.size,chunkSize:ATTACHMENT_CHUNK_SIZE,chunkCount:Math.max(1,Math.ceil(file.size/ATTACHMENT_CHUNK_SIZE)),manifestHash:await digest(manifest),sha256:EMPTY_HASH};
  let started=false;
  try {
    started=true;
    await api('/api/files/chunked',{method:'POST',body:{fileId:meta.id,chatId:chat.id,format:meta.format,size:meta.size,chunkSize:meta.chunkSize,chunkCount:meta.chunkCount,manifestHash:meta.manifestHash},signal});
    for(let index=0;index<meta.chunkCount;index++) {
      guard(box,epoch,signal);
      let plain=new Uint8Array(await file.slice(index*meta.chunkSize,Math.min(meta.size,(index+1)*meta.chunkSize)).arrayBuffer());
      let packed,cipher;
      try {
        guard(box,epoch,signal);
        const header=encoder.encode(canonical(chunkHeader(box,chat,meta,index,meta.sha256)));
        packed=new Uint8Array(4+header.length+plain.length);new DataView(packed.buffer).setUint32(0,header.length);packed.set(header,4);packed.set(plain,4+header.length);plain.fill(0);plain=null;
        cipher=await pgp.encrypt({message:await pgp.createMessage({binary:packed}),encryptionKeys:manifest.payload.members.map(m=>box.records.get(m.userId).key),signingKeys:box.privateKey,format:'binary'});
        guard(box,epoch,signal);
        if(cipher.length>MAX_CIPHER_CHUNK) fail('附件分块加密后过大，请减少群成员后重试。');
        const hash=await digest(cipher);
        const result=await api(`/api/files/${meta.id}/chunks/${index}`,{method:'PUT',raw:true,body:cipher,headers:{'Content-Type':'application/octet-stream'},signal});
        guard(box,epoch,signal);
        if(result.index!==index||result.sha256!==hash) fail('服务器未正确保存附件分块。');
        meta.sha256=await chainHash(meta.sha256,index,hash);
        const loaded=Math.min(meta.size,(index+1)*meta.chunkSize);
        onProgress?.({loaded,done:loaded,total:meta.size,phase:'upload',index,chunkCount:meta.chunkCount});
      } finally {plain?.fill(0);packed?.fill(0);cipher?.fill(0);}
    }
    const uploaded=await api(`/api/files/${meta.id}/complete`,{method:'POST',body:{sha256:meta.sha256},signal});guard(box,epoch,signal);
    if(uploaded.file?.id!==meta.id||uploaded.file?.sha256!==meta.sha256||uploaded.file?.chunkCount!==meta.chunkCount) fail('服务器返回的附件校验信息不一致。');
    return {file:uploaded.file,meta};
  } catch(error) {
    // A separate signal allows cancel/lock to clean unpublished ciphertext too.
    if(started) for(let attempt=0;attempt<8;attempt++) {
      try {await api(`/api/files/${meta.id}`,{method:'DELETE',timeout:10000});break;}
      catch(cleanupError) {if(cleanupError?.status!==429) break;await new Promise(resolve=>setTimeout(resolve,150));}
    }
    throw error;
  }
}

export async function* iterateAttachment({box,api=box.api,chat,message,signal,onProgress}) {
  const payload=await box.verifiedPayload(chat,message), meta=payload.file,epoch=box.epoch;
  if(!validDescriptor(meta)) fail('分块附件信息无效。');
  const sender=box.records.get(message.senderId);let previous=EMPTY_HASH,loaded=0;
  for(let index=0;index<meta.chunkCount;index++) {
    guard(box,epoch,signal);
    const cipher=await api(`/api/files/${encodeURIComponent(meta.id)}/chunks/${index}`,{response:'bytes',signal});
    if(!(cipher instanceof Uint8Array)||!cipher.length||cipher.length>MAX_CIPHER_CHUNK) fail('附件分块大小无效。');
    const hash=await digest(cipher);let result,plain;
    try {
      result=await pgp.decrypt({message:await pgp.readMessage({binaryMessage:cipher}),decryptionKeys:box.privateKey,verificationKeys:sender.key,expectSigned:true,format:'binary',config:{maxDecompressedMessageSize:ATTACHMENT_CHUNK_SIZE+65536}});
      if(result.signatures.length!==1) fail('附件发送者签名无效。');await result.signatures[0].verified;
      const packed=result.data;if(!(packed instanceof Uint8Array)||packed.length<4) fail('附件分块格式无效。');
      const length=new DataView(packed.buffer,packed.byteOffset,packed.byteLength).getUint32(0);if(length>16384||4+length>packed.length) fail('附件分块头无效。');
      let header;try {header=JSON.parse(decoder.decode(packed.subarray(4,4+length)));} catch {fail('附件分块头无效。');}
      const expected={v:1,purpose:'shanshui-file-chunk',format:ATTACHMENT_FORMAT,serverId:box.serverId,chatId:chat.id,fileId:meta.id,senderId:message.senderId,senderFingerprint:message.envelope.senderFingerprint,manifestHash:meta.manifestHash,index,count:meta.chunkCount,totalSize:meta.size,chunkSize:meta.chunkSize,previousHash:previous};
      if(canonical(header)!==canonical(expected)) fail('附件分块顺序、会话或发送者校验失败。');
      const size=Math.min(meta.chunkSize,meta.size-index*meta.chunkSize);if(packed.length-4-length!==size) fail('附件大小校验失败。');
      previous=await chainHash(previous,index,hash);guard(box,epoch,signal);
      if(index===meta.chunkCount-1&&previous!==meta.sha256) fail('附件完整性校验失败，已停止下载。');
      loaded+=size;plain=packed.slice(4+length);packed.fill(0);result=null;
      onProgress?.({loaded,done:loaded,total:meta.size,phase:'download',index,chunkCount:meta.chunkCount});
      yield plain;
    } finally {cipher.fill(0);result?.data?.fill(0);plain?.fill(0);}
  }
  if(loaded!==meta.size||previous!==meta.sha256) fail('附件完整性校验失败。');
}

export async function downloadAttachment(options) {
  const {box,chat,message,sink,signal}=options;
  const payload=await box.verifiedPayload(chat,message),meta=payload.file;
  if(!validDescriptor(meta)) fail('分块附件信息无效。');
  // Large output needs a disk-backed destination; never accidentally buffer it.
  if(!sink&&meta.size>20*1024*1024) fail('大附件请使用保存到文件功能下载。');
  const chunks=[];let done=false;
  try {
    for await(const chunk of iterateAttachment(options)) {abort(signal);if(sink) await sink.write(chunk);else chunks.push(chunk.slice());}
    if(sink) {abort(signal);await sink.close?.();done=true;return {name:meta.name,mime:meta.mime,size:meta.size};}
    const bytes=new Uint8Array(meta.size);let offset=0;for(const part of chunks) {bytes.set(part,offset);offset+=part.length;part.fill(0);}done=true;
    return {bytes,name:meta.name,mime:meta.mime};
  } finally {for(const part of chunks) part.fill(0);if(!done) try {await sink?.abort?.();} catch { /* Preserve the original verification/cancellation error. */ }}
}
