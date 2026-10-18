'use strict';

// Files are independently signed/encrypted on the device. The server handles one
// bounded ciphertext chunk at a time and never receives names or plaintext.
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_CIPHER_CHUNK = CHUNK_SIZE + 256 * 1024;
const FORMAT = 'pgp-chunks-v1';
const EMPTY_HASH = '0'.repeat(64);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const chainHash = (previous, index, hash) => sha(`${previous}:${index}:${hash}`);

function createAttachmentStore({db, filesDir, fail, body, json, requireChat, requireChatWrite, validateCiphertext, transaction, reserveBytes = 64 * 1024 * 1024}) {
  db.exec(`CREATE TABLE IF NOT EXISTS chunked_files(file_id TEXT PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,format TEXT NOT NULL,manifest_hash TEXT NOT NULL,plain_size INTEGER NOT NULL,chunk_size INTEGER NOT NULL,chunk_count INTEGER NOT NULL,received INTEGER NOT NULL DEFAULT 0,cipher_size INTEGER NOT NULL DEFAULT 0,chain_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'uploading',updated_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS file_chunks(file_id TEXT NOT NULL REFERENCES chunked_files(file_id) ON DELETE CASCADE,chunk_index INTEGER NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,PRIMARY KEY(file_id,chunk_index));
    CREATE INDEX IF NOT EXISTS messages_file ON messages(file_id) WHERE file_id IS NOT NULL;`);
  const q = (sql,...p) => db.prepare(sql).get(...p), run=(sql,...p)=>db.prepare(sql).run(...p);
  const busy = new Set(); let active = 0, sweeping = false;
  const row = fileId => q('SELECT f.*,c.format,c.manifest_hash,c.plain_size,c.chunk_size,c.chunk_count,c.received,c.chain_hash,c.status,c.updated_at FROM files f JOIN chunked_files c ON c.file_id=f.id WHERE f.id=?',fileId);
  function current(r,user,write=false) {
    const chat = requireChat(r.chat_id,user);
    if(write) {
      requireChatWrite(chat,user);
      if(r.owner_id!==user.id) fail(404,'附件不存在或无权访问');
      const manifest=q('SELECT manifest_hash FROM manifests WHERE chat_id=? ORDER BY revision DESC LIMIT 1',r.chat_id);
      if(!manifest || manifest.manifest_hash!==r.manifest_hash) fail(409,'会话成员或密钥已经变化，请重新选择附件后发送');
    }
    return chat;
  }
  function published(fileId) { return !!q('SELECT 1 FROM messages WHERE file_id=? LIMIT 1',fileId); }
  function readable(r,user) { current(r,user); if(r.status!=='complete'||(r.owner_id!==user.id&&!published(r.id))) fail(404,'附件尚未发送'); }
  function metadata(r) { return r ? {format:r.format,chunkCount:r.chunk_count,chunkSize:r.chunk_size} : {}; }
  function assertSend(fileId,chat,user,envelope) {
    const r=row(fileId); if(!r) return;
    current(r,user,true);
    if(r.chat_id!==chat.id||r.status!=='complete'||r.manifest_hash!==envelope.manifestHash) fail(409,'附件尚未上传完整或加密成员已经变化');
    if(published(fileId)) fail(409,'附件已用于另一条消息，请重新选择文件发送');
  }
  async function room(bytes) {
    const stats=await fsp.statfs(filesDir,{bigint:true});
    if(stats.bavail*stats.bsize < BigInt(bytes)+BigInt(reserveBytes)) fail(507,'服务器磁盘空间不足，已停止附件上传；请清理空间后重试');
  }
  const disk = r => path.join(filesDir,r.path);
  async function remove(r) {
    if(!r||published(r.id)) return false;
    transaction(()=>{ if(published(r.id)) fail(409,'附件已经发送，不能取消'); run('DELETE FROM file_chunks WHERE file_id=?',r.id); run('DELETE FROM chunked_files WHERE file_id=?',r.id); run('DELETE FROM files WHERE id=?',r.id); });
    await fsp.rm(disk(r),{recursive:true,force:true}); return true;
  }
  async function cleanup() {
    if(sweeping) return; sweeping=true;
    try {
      const old=db.prepare('SELECT f.*,c.updated_at FROM files f JOIN chunked_files c ON c.file_id=f.id WHERE c.updated_at<? AND NOT EXISTS(SELECT 1 FROM messages WHERE file_id=f.id) LIMIT 20').all(Date.now()-24*3600*1000);
      for(const r of old) if(!busy.has(r.id)) { busy.add(r.id); try { await remove(r); } finally { busy.delete(r.id); } }
    } finally { sweeping=false; }
  }
  async function handle(req,res,url,user) {
    const pathname=url.pathname, method=req.method;
    if(method==='POST'&&pathname==='/api/files/chunked') {
      const d=await body(req,4096);
      const fields=['fileId','chatId','format','size','chunkSize','chunkCount','manifestHash'];
      if(Object.keys(d).some(k=>!fields.includes(k))||fields.some(k=>!Object.hasOwn(d,k))||d.format!==FORMAT||typeof d.chatId!=='string'||!d.chatId||d.chatId.length>100||typeof d.fileId!=='string'||!/^[a-f0-9-]{36}$/i.test(d.fileId)||!Number.isSafeInteger(d.size)||d.size<0||d.chunkSize!==CHUNK_SIZE||!Number.isSafeInteger(d.chunkCount)||d.chunkCount!==Math.max(1,Math.ceil(d.size/CHUNK_SIZE))||!/^[a-f0-9]{64}$/.test(d.manifestHash)) fail(400,'分块附件信息无效');
      const chat=requireChat(d.chatId,user); requireChatWrite(chat,user);
      if(!q('SELECT 1 FROM identities WHERE user_id=?',user.id)) fail(409,'请先建立加密身份');
      const manifest=q('SELECT manifest_hash FROM manifests WHERE chat_id=? ORDER BY revision DESC LIMIT 1',chat.id);
      if(!manifest||manifest.manifest_hash!==d.manifestHash) fail(409,'会话成员或密钥已经变化，请重新选择附件');
      const previous=row(d.fileId);
      if(previous) {
        current(previous,user,true);
        if(previous.chat_id!==chat.id||previous.plain_size!==d.size||previous.chunk_count!==d.chunkCount) fail(409,'附件标识已用于其他内容');
        return json(res,200,{file:{id:previous.id,...metadata(previous)}}),true;
      }
      if(q('SELECT 1 FROM files WHERE id=?',d.fileId)) fail(409,'附件标识已被使用');
      if(q("SELECT count(*) n FROM chunked_files c JOIN files f ON f.id=c.file_id WHERE f.owner_id=? AND c.status='uploading'",user.id).n>=8) fail(429,'同时上传的附件过多，请先完成或取消其他上传');
      await room(Math.min(d.size,CHUNK_SIZE)+MAX_CIPHER_CHUNK);
      const diskName='chunks-'+d.fileId;
      await fsp.mkdir(path.join(filesDir,diskName),{mode:0o700});
      try {
        transaction(()=>{
          requireChatWrite(requireChat(chat.id,user),user);
          run('INSERT INTO files(id,chat_id,owner_id,name,size,mime,path,created_at,encrypted,cipher_sha256) VALUES(?,?,?,?,?,?,?,?,1,?)',d.fileId,chat.id,user.id,'加密附件.pgp',0,'application/octet-stream',diskName,new Date().toISOString(),EMPTY_HASH);
          run('INSERT INTO chunked_files(file_id,format,manifest_hash,plain_size,chunk_size,chunk_count,chain_hash,updated_at) VALUES(?,?,?,?,?,?,?,?)',d.fileId,FORMAT,d.manifestHash,d.size,CHUNK_SIZE,d.chunkCount,EMPTY_HASH,Date.now());
        });
      } catch(e) { await fsp.rm(path.join(filesDir,diskName),{recursive:true,force:true}); throw e; }
      return json(res,201,{file:{id:d.fileId,format:FORMAT,chunkSize:CHUNK_SIZE,chunkCount:d.chunkCount}}),true;
    }
    const match=/^\/api\/files\/([^/]+)(?:\/(complete|chunks)(?:\/(\d+))?)?$/.exec(pathname);
    if(!match) return false;
    const r=row(match[1]); if(!r) return false;
    if(method==='GET'&&match[2]==='chunks'&&match[3]!==undefined) {
      readable(r,user); const index=Number(match[3]);
      if(!Number.isSafeInteger(index)||index<0||index>=r.chunk_count) fail(404,'附件分块不存在');
      const item=q('SELECT * FROM file_chunks WHERE file_id=? AND chunk_index=?',r.id,index); if(!item) fail(409,'附件不完整，缺少分块');
      const filename=path.join(disk(r),String(index)), stat=await fsp.stat(filename);
      if(stat.size!==item.size||stat.size>MAX_CIPHER_CHUNK) fail(409,'附件分块损坏');
      current(row(r.id),user);
      res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':stat.size,'Cache-Control':'private, no-store','Content-Security-Policy':"default-src 'none'; sandbox"});
      const stream=fs.createReadStream(filename); stream.on('error',()=>res.destroy()); res.on('close',()=>stream.destroy()); stream.pipe(res); return true;
    }
    if(method==='GET'&&!match[2]) { readable(r,user); fail(409,'此附件需要支持分块下载的新版客户端'); }
    if(!['PUT','POST','DELETE'].includes(method)) return false;
    if(method==='DELETE'&&!match[2]) { if(r.owner_id!==user.id) fail(404,'附件不存在或无权访问'); }
    else current(r,user,true);
    if(busy.has(r.id)||active>=4) fail(429,'附件正在传输，请稍后重试');
    busy.add(r.id); active++;
    try {
      if(method==='DELETE'&&!match[2]) { if(published(r.id)) fail(409,'附件已经发送，不能取消'); await remove(r); json(res,200,{ok:true}); return true; }
      if(method==='PUT'&&match[2]==='chunks'&&match[3]!==undefined) {
        const index=Number(match[3]);
        if(!Number.isSafeInteger(index)||index<0||index>=r.chunk_count) fail(400,'附件分块序号无效');
        await room(MAX_CIPHER_CHUNK);
        const bytes=await body(req,MAX_CIPHER_CHUNK,true); if(!bytes.length) fail(400,'加密附件分块不能为空');
        await validateCiphertext(bytes,true); const hash=sha(bytes);
        const latest=row(r.id); current(latest,user,true);
        const previous=q('SELECT sha256 FROM file_chunks WHERE file_id=? AND chunk_index=?',r.id,index);
        if(previous) { if(previous.sha256!==hash) fail(409,'附件分块已存在且内容不同'); json(res,200,{ok:true,index,sha256:hash}); return true; }
        if(latest.status!=='uploading'||index!==latest.received) fail(409,'请按顺序上传附件分块');
        const filename=path.join(disk(r),String(index)), temp=filename+'.partial';
        await fsp.writeFile(temp,bytes,{mode:0o600});
        try {
          await fsp.rename(temp,filename);
          transaction(()=>{
            current(row(r.id),user,true);
            const size=latest.size+bytes.length; if(!Number.isSafeInteger(size)) fail(413,'附件大小超出系统可表示范围');
            run('INSERT INTO file_chunks(file_id,chunk_index,size,sha256) VALUES(?,?,?,?)',r.id,index,bytes.length,hash);
            run('UPDATE chunked_files SET received=received+1,cipher_size=?,chain_hash=?,updated_at=? WHERE file_id=?',size,chainHash(latest.chain_hash,index,hash),Date.now(),r.id);
            run('UPDATE files SET size=? WHERE id=?',size,r.id);
          });
        } catch(e) { await fsp.unlink(temp).catch(()=>{}); await fsp.unlink(filename).catch(()=>{}); throw e; }
        json(res,201,{ok:true,index,sha256:hash}); return true;
      }
      if(method==='POST'&&match[2]==='complete'&&match[3]===undefined) {
        const d=await body(req,512), latest=row(r.id); current(latest,user,true);
        if(Object.keys(d).length!==1||!/^[a-f0-9]{64}$/.test(d.sha256)) fail(400,'附件摘要格式无效');
        if(latest.received!==latest.chunk_count||latest.chain_hash!==d.sha256) fail(409,'附件未完整上传或顺序校验失败');
        // Check disk metadata as well as the transactional ledger before publish.
        for(let index=0;index<latest.chunk_count;index++) { const expected=q('SELECT size FROM file_chunks WHERE file_id=? AND chunk_index=?',r.id,index); const stat=await fsp.stat(path.join(disk(r),String(index))).catch(()=>null); if(!expected||!stat||stat.size!==expected.size) fail(409,'附件分块缺失或损坏，请重新上传'); }
        transaction(()=>{current(row(r.id),user,true); run("UPDATE chunked_files SET status='complete',updated_at=? WHERE file_id=?",Date.now(),r.id); run('UPDATE files SET cipher_sha256=? WHERE id=?',d.sha256,r.id);});
        json(res,200,{file:{id:r.id,encrypted:true,size:latest.size,sha256:d.sha256,...metadata(latest)}}); return true;
      }
      return false;
    } catch(e) {
      if(e.code==='ENOSPC'||e.code==='EDQUOT') fail(507,'服务器磁盘空间不足，已停止附件上传；请清理空间后重试');
      throw e;
    } finally { busy.delete(r.id); active--; }
  }
  return {handle,metadata,assertSend,cleanup};
}
module.exports={createAttachmentStore,CHUNK_SIZE,MAX_CIPHER_CHUNK,FORMAT,chainHash};
