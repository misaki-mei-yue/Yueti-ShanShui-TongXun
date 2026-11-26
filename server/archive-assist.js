'use strict';

// Recovery is a new, explicit exchange of one original message/attachment's
// encrypted session key. Never store a recovery code, private key or plaintext.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS archive_assist_requests(
    id TEXT PRIMARY KEY, chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    requester_id TEXT NOT NULL REFERENCES users(id), target_fingerprint TEXT NOT NULL,
    helper_id TEXT NOT NULL REFERENCES users(id), payload TEXT NOT NULL, signature TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(chat_id,requester_id,target_fingerprint,helper_id));
  CREATE TABLE IF NOT EXISTS archive_assist_grants(
    request_id TEXT NOT NULL REFERENCES archive_assist_requests(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part TEXT NOT NULL CHECK(part IN ('message','attachment','chunk')), chunk_index INTEGER NOT NULL,
    payload TEXT NOT NULL, signature TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY(request_id,message_id,part,chunk_index),CHECK((part='chunk' AND chunk_index>=0) OR (part!='chunk' AND chunk_index=-1)));
  CREATE TABLE IF NOT EXISTS archive_assist_revisions(
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,requester_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_fingerprint TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(chat_id,requester_id,target_fingerprint));`;

const REQUEST_FIELDS=['v','purpose','serverId','chatId','requestId','requesterId','targetFingerprint','helperId'];
const GRANT_FIELDS=['v','purpose','serverId','chatId','requestId','messageId','clientId','manifestHash','cipherHash','part','index','fileId','helperId','helperFingerprint','requesterId','targetFingerprint','encryptedSessionKey'];
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);

// Run inside the application's schema transaction. Keep the original request
// IDs and signed payloads so every previously granted key remains readable.
function ensureSchema(db) {
  const oldConstraint=db.prepare(`SELECT 1 FROM pragma_index_list('archive_assist_requests') i
    WHERE i.origin='u' AND (SELECT count(*) FROM pragma_index_info(i.name))=3`).get();
  if(!oldConstraint){db.exec(SCHEMA);return;}
  db.exec(`ALTER TABLE archive_assist_grants RENAME TO archive_assist_grants_v5;
    ALTER TABLE archive_assist_requests RENAME TO archive_assist_requests_v5;`);
  db.exec(SCHEMA);
  db.exec(`INSERT INTO archive_assist_requests SELECT * FROM archive_assist_requests_v5;
    INSERT INTO archive_assist_grants SELECT * FROM archive_assist_grants_v5;
    DROP TABLE archive_assist_grants_v5;
    DROP TABLE archive_assist_requests_v5;`);
}

function createArchiveAssist({db,serverId,canonical,sha,fail,exactKeys,verifyDetached,validateCiphertext,requireChat,requireFriend,body,json,transaction,authorize,onChanged}) {
  const q=(sql,...params)=>db.prepare(sql).get(...params), all=(sql,...params)=>db.prepare(sql).all(...params), run=(sql,...params)=>db.prepare(sql).run(...params);
  function scope(chatId,user) {
    if(!uuid(chatId))fail(404,'归档会话不存在');
    const chat=requireChat(chatId,user);
    const members=all("SELECT user_id FROM members WHERE chat_id=? AND user_id<>'ai' ORDER BY user_id",chatId).map(r=>r.user_id);
    if(!['direct','group'].includes(chat.kind)||!q('SELECT 1 FROM chat_archives WHERE chat_id=?',chatId)||members.length<2||!members.includes(user.id))fail(403,'请选择有其他成员的归档加密会话');
    return {chat,members};
  }
  function requirePeer(s,userId,peerId) {
    if(!peerId||peerId===userId||!s.members.includes(peerId))fail(403,'协助双方必须是此归档会话的成员');
    requireFriend(userId,peerId);
  }
  function friendsInChat(chatId,userId) {
    return all(`SELECT m.user_id FROM members m JOIN friendships f ON
      f.user_a=min(m.user_id,?) AND f.user_b=max(m.user_id,?) WHERE m.chat_id=? AND m.user_id<>? ORDER BY m.user_id`,
      userId,userId,chatId,userId).map(r=>r.user_id);
  }
  function active(userId) {return q('SELECT fingerprint,public_key FROM identities WHERE user_id=?',userId);}
  function requestFor(chatId,requesterId,helperId) {
    return q(`SELECT r.* FROM archive_assist_requests r JOIN identities i ON i.user_id=r.requester_id AND i.fingerprint=r.target_fingerprint
      WHERE r.chat_id=? AND r.requester_id=? AND r.helper_id=?`,chatId,requesterId,helperId)||null;
  }
  function viewRequest(row) {
    if(!row)return null;
    const grantedMessages=q("SELECT count(*) n FROM archive_assist_grants WHERE request_id=? AND part='message'",row.id).n;
    return {...JSON.parse(row.payload),createdAt:row.created_at,signature:row.signature,grantedMessages,state:grantedMessages?'granted':'requested'};
  }
  function original(scope,request,messageId,part,index=null) {
    if(!uuid(messageId)||!['message','attachment','chunk'].includes(part)||(part==='chunk'?(!Number.isSafeInteger(index)||index<0):index!==null))fail(400,'协助恢复消息格式不正确');
    const row=q('SELECT * FROM messages WHERE id=? AND chat_id=? AND content_version=1',messageId,scope.chat.id);
    if(!row)fail(404,'归档会话中没有这条加密消息');
    const e=JSON.parse(row.envelope), mf=q('SELECT * FROM manifests WHERE chat_id=? AND revision=?',scope.chat.id,e.revision);
    const signed=mf&&JSON.parse(mf.payload),members=signed?.members;
    if(e.v!==1||e.serverId!==serverId||e.chatId!==scope.chat.id||e.clientId!==row.client_id||e.senderId!==row.sender_id||!mf||signed?.serverId!==serverId||signed?.chatId!==scope.chat.id||signed?.kind!==scope.chat.kind||signed?.revision!==e.revision||e.manifestHash!==mf.manifest_hash||!Array.isArray(members)||members.length<2||members.some(m=>m.userId==='ai')||canonical(e.recipients)!==canonical(members)||!members.some(m=>m.userId===e.senderId&&m.fingerprint===e.senderFingerprint))fail(400,'旧消息与原始签名收件人记录不一致');
    const target=members.find(m=>m.userId===request.requester_id),helper=members.find(m=>m.userId===request.helper_id);
    if(!target||!helper||target.fingerprint===request.target_fingerprint||!q('SELECT 1 FROM historical_identities WHERE user_id=? AND fingerprint=?',target.userId,target.fingerprint))fail(403,'请求人不属于这条旧消息的原始加密身份');
    const helperKey=q('SELECT public_key FROM identities WHERE user_id=? AND fingerprint=?',helper.userId,helper.fingerprint)||q('SELECT public_key FROM historical_identities WHERE user_id=? AND fingerprint=?',helper.userId,helper.fingerprint);
    if(!helperKey)fail(409,'原始协助人的签名公钥缺失');
    let fileId=null,cipherHash=sha(e.ciphertext);
    if(part!=='message') {
      const f=q('SELECT * FROM files WHERE id=? AND chat_id=? AND encrypted=1',row.file_id,scope.chat.id);
      if(!f||f.owner_id!==row.sender_id||!/^[a-f0-9]{64}$/.test(f.cipher_sha256))fail(400,'旧附件记录与原始消息不一致');
      const chunks=q('SELECT * FROM chunked_files WHERE file_id=?',f.id);
      if(part==='chunk'){
        const chunk=chunks&&q('SELECT sha256 FROM file_chunks WHERE file_id=? AND chunk_index=?',f.id,index);
        if(!chunks||chunks.status!=='complete'||chunks.manifest_hash!==e.manifestHash||index>=chunks.chunk_count||!chunk||!/^[a-f0-9]{64}$/.test(chunk.sha256))fail(400,'旧附件分块与原始加密记录不一致');
        cipherHash=chunk.sha256;
      }else {if(chunks)fail(400,'旧附件是分块格式');cipherHash=f.cipher_sha256;}
      fileId=f.id;
    }
    return {helperKey,binding:{v:1,purpose:'archive-assist-grant',serverId,chatId:scope.chat.id,requestId:request.id,messageId:row.id,clientId:row.client_id,manifestHash:e.manifestHash,cipherHash,part,index,fileId,helperId:helper.userId,helperFingerprint:helper.fingerprint,requesterId:target.userId,targetFingerprint:request.target_fingerprint}};
  }
  function signedRequest(row){return {payload:JSON.parse(row.payload),signature:row.signature};}
  async function handle(req,res,url,user,auth) {
    const match=/^\/api\/chats\/([^/]+)\/archive-assist(?:\/(grants)(?:\/([^/]+)\/([^/]+)(?:\/([0-9]+))?)?)?$/.exec(url.pathname);
    if(!match)return false;
    if(url.search)fail(400,'协助恢复不接受查询参数');
    const [,chatId,action,messageId,part,indexText]=match,s=scope(chatId,user),index=indexText===undefined?null:Number(indexText);
    const readDelivered=req.method==='GET'&&action==='grants'&&messageId&&part;
    if(!readDelivered && s.members.length===2)requirePeer(s,user.id,s.members.find(member=>member!==user.id));
    if(req.method==='GET'&&!action){
      const helperIds=friendsInChat(chatId,user.id),accepted=new Set(helperIds);
      const pending=all(`SELECT r.* FROM archive_assist_requests r JOIN identities i ON i.user_id=r.requester_id AND i.fingerprint=r.target_fingerprint
        WHERE r.chat_id=? AND (r.requester_id=? OR r.helper_id=?) ORDER BY r.created_at,r.id`,chatId,user.id,user.id);
      const incomingRequests=pending.filter(r=>r.helper_id===user.id&&accepted.has(r.requester_id)).map(viewRequest);
      const outgoingRequests=pending.filter(r=>r.requester_id===user.id).map(viewRequest);
      json(res,200,{outgoing:outgoingRequests[0]||null,incoming:incomingRequests[0]||null,helperIds,outgoingRequests,incomingRequests});return true;
    }
    if(req.method==='POST'&&!action){
      const data=await body(req,24*1024);exactKeys(data,['payload','signature'],'恢复请求');
      const p=data.payload;exactKeys(p,REQUEST_FIELDS,'恢复请求');const current=active(user.id);
      requirePeer(s,user.id,p.helperId);
      if(!current||!uuid(p.requestId)||p.v!==1||p.purpose!=='archive-assist-request'||p.serverId!==serverId||p.chatId!==chatId||p.requesterId!==user.id||p.targetFingerprint!==current.fingerprint||!q('SELECT 1 FROM historical_identities WHERE user_id=? AND fingerprint<>?',user.id,current.fingerprint))fail(403,'恢复请求只能由已更新加密身份的原联系人本人提出');
      if(!q(`SELECT 1 FROM manifests m,json_each(m.payload,'$.members') r JOIN historical_identities h ON h.user_id=json_extract(r.value,'$.userId') AND h.fingerprint=json_extract(r.value,'$.fingerprint')
        WHERE m.chat_id=? AND h.user_id=? AND EXISTS(SELECT 1 FROM json_each(m.payload,'$.members') peer WHERE json_extract(peer.value,'$.userId')=?) LIMIT 1`,chatId,user.id,p.helperId))fail(403,'你们没有共同的历史加密身份记录');
      await verifyDetached(p,data.signature,current.public_key);
      const result=transaction(()=>{authorize(auth,res);requirePeer(scope(chatId,user),user.id,p.helperId);if(active(user.id)?.fingerprint!==p.targetFingerprint)fail(409,'恢复请求的当前加密身份已变化');const existing=requestFor(chatId,user.id,p.helperId);if(existing)return existing;
        run('INSERT INTO archive_assist_requests(id,chat_id,requester_id,target_fingerprint,helper_id,payload,signature,created_at) VALUES(?,?,?,?,?,?,?,?)',p.requestId,chatId,user.id,p.targetFingerprint,p.helperId,canonical(p),data.signature,new Date().toISOString());return requestFor(chatId,user.id,p.helperId);});
      onChanged?.([user.id,p.helperId]);json(res,200,{outgoing:viewRequest(result)});return true;
    }
    if(req.method==='GET'&&action==='grants'&&messageId&&part){
      const grant=q(`SELECT g.payload,g.signature,r.helper_id FROM archive_assist_grants g JOIN archive_assist_requests r ON r.id=g.request_id
        JOIN identities i ON i.user_id=r.requester_id AND i.fingerprint=r.target_fingerprint
        WHERE r.chat_id=? AND r.requester_id=? AND g.message_id=? AND g.part=? AND g.chunk_index=? ORDER BY g.created_at,r.id LIMIT 1`,
        chatId,user.id,messageId,part,index??-1);
      if(!grant){json(res,200,{grant:null});return true;}
      const request=requestFor(chatId,user.id,grant.helper_id);original(s,request,messageId,part,index);
      json(res,200,{request:signedRequest(request),grant:{payload:JSON.parse(grant.payload),signature:grant.signature}});return true;
    }
    if(req.method==='POST'&&action==='grants'&&!messageId){
      const data=await body(req,240*1024);exactKeys(data,['grants'],'恢复授权');
      if(!Array.isArray(data.grants)||!data.grants.length||data.grants.length>12)fail(400,'每次只能提交同一条消息及至多 12 个附件授权');
      const requesterId=data.grants[0]?.payload?.requesterId;requirePeer(s,user.id,requesterId);
      const request=requestFor(chatId,requesterId,user.id);if(!request)fail(403,'原联系人尚未请求协助恢复');
      const seen=new Set();let originalMessageId=null;
      for(const grant of data.grants){exactKeys(grant,['payload','signature'],'恢复授权');const p=grant.payload;exactKeys(p,GRANT_FIELDS,'恢复授权');const o=original(s,request,p.messageId,p.part,p.index),{encryptedSessionKey,...binding}=p,partKey=`${p.part}:${p.index??-1}`;
        if(canonical(binding)!==canonical(o.binding)||typeof encryptedSessionKey!=='string'||encryptedSessionKey.length>12000||seen.has(partKey)||(originalMessageId&&originalMessageId!==p.messageId))fail(400,'恢复授权与原消息或收件人绑定不一致');
        seen.add(partKey);originalMessageId=p.messageId;
        await validateCiphertext(encryptedSessionKey);await verifyDetached(p,grant.signature,o.helperKey.public_key);
      }
      const result=transaction(()=>{authorize(auth,res);const freshScope=scope(chatId,user);requirePeer(freshScope,user.id,requesterId);const fresh=requestFor(chatId,requesterId,user.id);if(fresh?.id!==request.id)fail(409,'恢复请求或目标加密身份已经变化');let granted=0;
        if(!seen.has('message:-1')&&!q("SELECT 1 FROM archive_assist_grants WHERE request_id=? AND message_id=? AND part='message'",fresh.id,originalMessageId))fail(409,'请先授予对应的原消息恢复权限');
        for(const grant of data.grants){const p=grant.payload,{encryptedSessionKey,...binding}=p;if(canonical(original(freshScope,fresh,p.messageId,p.part,p.index).binding)!==canonical(binding))fail(409,'原始消息记录已经变化');
          granted+=Number(run('INSERT OR IGNORE INTO archive_assist_grants(request_id,message_id,part,chunk_index,payload,signature,created_at) VALUES(?,?,?,?,?,?,?)',fresh.id,p.messageId,p.part,p.index??-1,canonical(p),grant.signature,new Date().toISOString()).changes);}
        if(granted)run(`INSERT INTO archive_assist_revisions(chat_id,requester_id,target_fingerprint,revision) VALUES(?,?,?,1)
          ON CONFLICT(chat_id,requester_id,target_fingerprint) DO UPDATE SET revision=revision+1`,chatId,requesterId,fresh.target_fingerprint);
        return {granted,grantedMessages:viewRequest(fresh).grantedMessages};});
      // Updating the recipient's chat/UI is an optimization; decryption remains
      // message-scoped and does not rely on this notification.
      if(result.granted)onChanged?.([requesterId]);json(res,200,result);return true;
    }
    fail(405,'不支持的协助恢复操作');
  }
  function incoming(chatId,helperId){
    // A first-grant acknowledgement clears the inbox badge; further batches
    // can still be explicitly authorized from the request details.
    return Boolean(q(`SELECT 1 FROM archive_assist_requests r JOIN identities i ON i.user_id=r.requester_id AND i.fingerprint=r.target_fingerprint
      JOIN friendships f ON f.user_a=min(r.requester_id,r.helper_id) AND f.user_b=max(r.requester_id,r.helper_id)
      WHERE r.chat_id=? AND r.helper_id=? AND NOT EXISTS(SELECT 1 FROM archive_assist_grants g WHERE g.request_id=r.id)`,chatId,helperId));
  }
  function grantStamp(chatId,userId){
    return q(`SELECT r.revision FROM archive_assist_revisions r JOIN identities i ON r.requester_id=i.user_id AND r.target_fingerprint=i.fingerprint
      WHERE r.chat_id=? AND r.requester_id=?`,chatId,userId)?.revision||0;
  }
  return {handle,incoming,grantStamp};
}
module.exports={SCHEMA,ensureSchema,createArchiveAssist};
