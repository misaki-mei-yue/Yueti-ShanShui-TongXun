import { CryptoBox } from './e2ee.mjs';
import { connectAI, getModels } from './ai-direct.mjs';
import { prepareVisionMessage, generateImages } from './ai-multimodal.mjs';
import { parseAIInvocation, drawingDraft, STICKER_INSTRUCTION, splitAISticker, withPrivateMemory } from './ai-actions.mjs';
import { EncryptedAIMemory, relevantMemory, memoryExtractionMessages, parseExtractedFacts, MEMORY_EXTRACTION_INSTRUCTION } from './ai-memory.mjs';
import { searchWeb, withSearchResults } from './ai-search.mjs';
import { createSharedAIConfiguration, unlockSharedAIConfiguration, sharedAIHistoryEntry } from './ai-shared.mjs';
import { normalizeAIPreferences, buildAIContext, isShareableAIMessage } from './ai-context.mjs';
import { EMOJI_CHOICES, EncryptedEmoticonStore, validateRasterImage } from './emoticons.mjs';
import { DEFAULT_STICKERS, loadDefaultSticker } from './default-stickers.mjs';
import { uploadAttachment, downloadAttachment as downloadChunkedAttachment } from './attachments.mjs';
import { createFileSink as openFileSink } from './file-save.mjs';
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const paths = {
    chat:'<path d="M21 11.5a8.5 8.5 0 0 1-8.5 8.5H4l-1 1v-9.5A8.5 8.5 0 0 1 11.5 3H13a8 8 0 0 1 8 8.5Z"/><path d="M7 9h10M7 13h7"/>',
    people:'<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3M16 5a3 3 0 0 1 0 6M17 14a5 5 0 0 1 4 5v2"/>',
    bookmark:'<path d="M6 3h12v18l-6-4-6 4Z"/>', settings:'<path d="m9 3-1 3-3 1 1 3-2 2 2 2-1 3 3 1 1 3h6l1-3 3-1-1-3 2-2-2-2 1-3-3-1-1-3Z"/><circle cx="12" cy="12" r="3"/>',
    plus:'<path d="M12 5v14M5 12h14"/>',search:'<circle cx="10" cy="10" r="7"/><path d="m15 15 6 6"/>',back:'<path d="m14 5-7 7 7 7"/>',panel:'<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M15 4v16"/>',
    smile:'<circle cx="12" cy="12" r="9"/><path d="M8 15c2 3 6 3 8 0M8 8v1M16 8v1"/>',attach:'<path d="m8 14 7-7a3 3 0 0 1 4 4L9 21a5 5 0 0 1-7-7L14 2"/>',
    send:'<path d="m22 2-7 20-4-9L2 9Zm0 0L11 13"/>',file:'<path d="M14 2H5v20h14V7ZM14 2v5h5M8 12h8M8 16h6"/>',mountain:'<path d="m2 19 8-13 6 9 3-5 5 9ZM8 9l2 3 2-3M2 22h20"/>',
    ai:'<path d="m12 2 3 7 7 3-7 3-3 7-3-7-7-3 7-3ZM20 2v4M18 4h4"/>',pin:'<path d="m8 3 8 0-1 6 4 4H5l4-4ZM12 13v9"/>',bell:'<path d="M5 17h14l-2-4V8a5 5 0 0 0-10 0v5ZM10 21h4"/>'
  };
  const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.chat}</svg>`;
  const paintIcons = (root = document) => root.querySelectorAll('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); });
  let stableHTML = new WeakMap();
  function setStableHTML(node,html) {
    const previous = stableHTML.get(node);
    if (previous?.html === html && previous.first === node.firstChild && previous.last === node.lastChild) return;
    node.innerHTML = html; stableHTML.set(node,{html,first:node.firstChild,last:node.lastChild});
  }
  function stableChildren(node,html,attribute) {
    const template = document.createElement('template'); template.innerHTML = html;
    const previous = new Map([...node.children].filter(child => child.hasAttribute(attribute)).map(child => [child.getAttribute(attribute),child]));
    let cursor = node.firstChild;
    for (const next of [...template.content.childNodes]) {
      const key = next.nodeType === 1 ? next.getAttribute(attribute) : null, old = key === null ? null : previous.get(key);
      const item = old && stableHTML.get(old)?.html === next.outerHTML ? old : next;
      if (item === next && item.nodeType === 1) stableHTML.set(item,{html:item.outerHTML});
      if (item !== cursor) node.insertBefore(item,cursor); else cursor = cursor.nextSibling;
    }
    while (cursor) { const next = cursor.nextSibling; cursor.remove(); cursor = next; }
  }
  const uid = () => crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(24)), x => x.toString(16).padStart(2,'0')).join('');
  const bytes = n => n < 1024 * 1024 ? `${Math.max(1,Math.round(n / 1024))} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`;
  const time = value => { const d = new Date(value); return Number.isNaN(d.getTime()) ? '' : d.toLocaleString('zh-CN',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}); };
  function safeURL(value, prefix) { try { const url = new URL(value,location.origin); return url.origin === location.origin && url.pathname.startsWith(prefix) ? url.href : ''; } catch { return ''; } }
  function safeAIDiagnostics(value) {
    if (!value || typeof value !== 'object' || !/^AI_[A-Z0-9_]{1,64}$/.test(value.code || '')) return null;
    return {code:value.code,...(Number.isInteger(value.upstreamStatus) && value.upstreamStatus >= 100 && value.upstreamStatus <= 599 ? {upstreamStatus:value.upstreamStatus} : {}),...(typeof value.requestId === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value.requestId) ? {requestId:value.requestId} : {})};
  }
  let user = null, chats = [], current = null, filter = 'all', epoch = 0, selection = 0, dialogVersion = 0, chatRevision = 0;
  let cryptoBox = null, serverId = '', persistTimer, persistVersion = 0, persistCommitted = 0, restoreVersion = 0, vaultVersion = 0, securityResolve = null, trustResolve = null, restoring = false, securityTransition = false;
  const objectURLs = new Set(), aiJobs = new Map(), transfers = new Set();
  const outgoingJobs = new Map();
  const aiPreparing = new Set(), aiStates = new Map();
  let aiPreferences = {};
  let aiMemoryStore = null, aiMemoryBox = null;
  const memoryUpdates = new Set();
  let messages = new Map(), hasMore = new Map(), requests = new Map(), drafts = {}, pending = [], quotes = {}, attachments = new Map(), rawPending = new Map(), saved = new Set();
  const chatSecurityErrors = new Map();
  let source = null, refreshTimer = null, pollTimer = null, refreshing = false, refreshAgain = false, toastTimer, authMode = 'login', needsSetup = false;
  let storedKey = '', connected = false, retryAttachmentId = null;
  let nativeNotificationState=null,pendingNotificationChat=null;
  let sensitiveDialogCleanup = null;
  let activeView = 'chat', contactRevision = 0, contactController = null, contactBusy = false, contactError = '', contactUsers = [], contactRequests = [], directoryUsers = [], contactFilter = '', contactMode = 'friends', contactSubmittedQuery = '', contactSearchComplete = false;
  const sessionChannel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('shanshui:session:v1') : null;
  const chat = (id = current) => chats.find(c => String(c.id) === String(id));
  const normalizeChat = c => ({...c,id:String(c.id),members:(c.members || []).map(u => ({...u,id:String(u.id)}))});
  const normalizeMessage = m => ({...m,id:String(m.id),chatId:String(m.chatId),senderId:String(m.senderId)});
  function upsertChat(value) { const c = normalizeChat(value); chatRevision++; chats = [...chats.filter(old => old.id !== c.id),c]; renderList(); return c; }
  const isAI = c => c && (c.kind === 'ai' || c.kind === 'direct' || c.members.some(m => m.id === 'ai'));
  const canEdit = c => c && String(c.ownerId) === user?.id;
  const friendshipBlocked = c => c?.kind === 'direct' && c.canMessage !== true;
  const directPeer = c => c?.members.find(member => member.id !== user?.id && member.id !== 'ai');
  function toast(value) { $('toast').textContent = value; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; },4500); }
  function activeNotificationChat() {return cryptoBox?.ready&&document.visibilityState==='visible'&&activeView==='chat'&&(innerWidth>720||$('app').classList.contains('mobile-chat'))?current:null;}
  async function syncNativeNotifications(extra={}) {
    if(!window.YuetiNative?.notifications||!user)return null;
    const account=user.id,generation=epoch;
    const result=await window.YuetiNative.notifications({userId:account,activeChatId:activeNotificationChat(),...extra});
    if(user?.id===account&&generation===epoch)nativeNotificationState=result;
    return result;
  }
  function refreshNativeNotificationView(){syncNativeNotifications().catch(()=>{});}
  async function openNotificationChat() {
    const id=pendingNotificationChat;if(!id||!user)return;
    const account=user.id;await refreshAll();if(user?.id!==account||!chat(id))return;
    pendingNotificationChat=null;
    if(!cryptoBox?.ready)await unlockAndRefresh();
    if(user?.id===account&&cryptoBox?.ready&&chat(id)){setNavigation('chat');await switchChat(id);}
  }
  window.addEventListener('yueti-notification-open',event=>{const id=event.detail?.chatId;if(typeof id!=='string'||!/^[a-f0-9-]{36}$/i.test(id))return;pendingNotificationChat=id;if(user)run(openNotificationChat);});
  function storeState() {
    if (!cryptoBox?.ready || !user || !storedKey || restoring) return;
    clearTimeout(persistTimer); persistTimer = setTimeout(() => run(persistEncrypted),160);
  }
  async function persistEncrypted() {
    clearTimeout(persistTimer);
    if (!cryptoBox?.ready || !storedKey || restoring) return;
    const version = ++persistVersion, box = cryptoBox, generation = epoch, vault = vaultVersion, key = storedKey;
    const snapshot = JSON.parse(JSON.stringify({drafts,pending,aiPreferences}));
    const ciphertext = await box.encryptLocal(snapshot);
    if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box.ready) return;
    if (version < persistCommitted) return;
    try { localStorage.setItem(key,JSON.stringify({v:1,ciphertext})); persistCommitted = version; } catch { throw new Error('本机存储空间不足，草稿与待发送消息尚未保存。请释放空间后重试。'); }
  }
  async function loadState() {
    if (!user || !cryptoBox?.ready) return;
    const box = cryptoBox, generation = epoch, version = ++restoreVersion;
    const valid = () => box === cryptoBox && box.ready && generation === epoch && version === restoreVersion;
    storedKey = `shanshui:1.3:${serverId}:${user.id}`; restoring = true;
    try {
      for (const key of Object.keys(localStorage)) if (key.startsWith('shanshui:1.2:') && key.endsWith(`:${user.id}`)) localStorage.removeItem(key);
      const stored = JSON.parse(localStorage.getItem(storedKey) || '{}');
      const value = stored.ciphertext ? await box.decryptLocal(stored.ciphertext) : {};
      if (!valid()) return;
      drafts = value.drafts && typeof value.drafts === 'object' && !Array.isArray(value.drafts) ? value.drafts : {};
      aiPreferences = Object.fromEntries(Object.entries(value.aiPreferences && typeof value.aiPreferences === 'object' && !Array.isArray(value.aiPreferences) ? value.aiPreferences : {}).map(([id,pref]) => [id,normalizeAIPreferences(pref)]));
      pending = Array.isArray(value.pending) ? value.pending.filter(p => typeof p.clientId === 'string' && typeof p.chatId === 'string' && typeof p.text === 'string').map(p => ({...p,status:'failed',error:'上次发送未确认，请重试。'})) : [];
    } catch { if (valid()) { drafts = {}; pending = []; aiPreferences = {}; toast('本机加密草稿无法解锁，已跳过恢复。'); } }
    finally { if (version === restoreVersion) restoring = false; }
  }
  function clearPlaintext() {
    sensitiveDialogCleanup?.(); sensitiveDialogCleanup = null;
    stableHTML = new WeakMap();
    resetMediaTools();
    resetContacts();
    selection++; dialogVersion++; persistVersion++; restoreVersion++; vaultVersion++; restoring = false; clearTimeout(persistTimer);
    for (const controller of aiJobs.values()) controller.abort(); aiJobs.clear();
    aiPreparing.clear(); aiStates.clear(); aiPreferences = {};
    aiMemoryStore?.dispose(); aiMemoryStore = null; aiMemoryBox = null;
    for(const controller of memoryUpdates)controller.abort(); memoryUpdates.clear();
    for (const controller of transfers) controller.abort(); transfers.clear();outgoingJobs.clear();
    for (const url of objectURLs) URL.revokeObjectURL(url); objectURLs.clear();
    messages = new Map(); hasMore = new Map(); requests = new Map(); drafts = {}; pending = []; quotes = {}; attachments = new Map(); rawPending = new Map(); saved = new Set();
    chatSecurityErrors.clear();
    $('input').value = ''; $('messages').replaceChildren(); if ($('new-messages')) $('new-messages').hidden = true; $('details').replaceChildren(); $('fileinput').value = ''; $('photoinput').value = ''; $('search').value = '';
    $('quotetext').textContent = ''; $('attachmentname').textContent = ''; $('quote').hidden = true; $('attachment').hidden = true;
    $('dialog').close(); $('dialogcontent').replaceChildren(); $('trust-dialog').close(); $('trust-content').replaceChildren();
    if (trustResolve) { trustResolve(false); trustResolve = null; }
    chats = chats.map(c => ({...c,lastMessage:c.lastMessage ? {id:c.lastMessage.id,createdAt:c.lastMessage.createdAt,text:'',locked:true} : null}));
  }
  function clearSession() {
    if(user&&window.YuetiNative?.notifications)Promise.resolve(window.YuetiNative.notifications({enabled:false,userId:user.id,activeChatId:null})).catch(()=>{});
    nativeNotificationState=null;pendingNotificationChat=null;
    securityTransition = false;
    cryptoBox?.lock().catch(() => {}); cryptoBox = null; clearPlaintext();
    $('security-dialog').close(); $('security-content').replaceChildren(); if (securityResolve) { securityResolve(false); securityResolve = null; }
    epoch++; selection++; dialogVersion++;
    source?.close(); source = null; clearInterval(pollTimer); clearTimeout(refreshTimer); pollTimer = null;
    user = null; chats = []; current = null; messages = new Map(); hasMore = new Map(); requests = new Map();
    drafts = {}; pending = []; quotes = {}; attachments = new Map(); rawPending = new Map(); saved = new Set(); storedKey = ''; refreshing = false; refreshAgain = false;
    $('input').value = ''; $('messages').replaceChildren(); $('chatlist').replaceChildren(); $('details').replaceChildren(); $('self-avatar').textContent = '我';
    $('search').value = ''; $('fileinput').value = ''; retryAttachmentId = null;
    $('dialog').close(); $('dialogcontent').replaceChildren(); $('app').hidden = true; $('auth').hidden = false;
    $('app').classList.remove('mobile-chat'); hideDetails(); document.body.classList.remove('art-focus');
  }
  async function api(path, options = {}) {
    const startEpoch = epoch, controller = new AbortController(), timeout = setTimeout(() => controller.abort(),options.timeout || (options.raw ? 120000 : 30000));
    const cancel = () => controller.abort(); options.signal?.addEventListener('abort',cancel,{once:true});
    if (options.signal?.aborted) controller.abort();
    const method = options.method || 'GET';
    const headers = {'Accept':'application/json',...(user ? {'X-Yueti-User':user.id} : {}),...(method !== 'GET' ? {'X-Yueti-Request':'1'} : {}),...options.headers};
    let body;
    if (options.raw) body = options.body;
    else if (options.body !== undefined) { body = JSON.stringify(options.body); headers['Content-Type'] = 'application/json'; }
    try {
      const response = await fetch(path,{method,headers,body,credentials:'same-origin',cache:'no-store',signal:controller.signal});
      let result;
      if(response.ok&&options.response==='bytes') {
        const reader=response.body?.getReader();if(!reader)throw new Error('附件没有返回内容。');
        const parts=[];let length=0;
        try { for(;;){const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>8*1024*1024){await reader.cancel();throw new Error('附件分块格式无效。');}parts.push(value);}result=new Uint8Array(length);let offset=0;for(const part of parts){result.set(part,offset);offset+=part.byteLength;} }
        finally{for(const part of parts)part.fill(0);reader.releaseLock();}
      } else result = await response.json().catch(() => ({}));
      if (startEpoch !== epoch) throw Object.assign(new Error('账户已切换。'),{stale:true});
      if (!response.ok) {
        if (response.status === 409 && result.error === '账户已在其他窗口切换，请刷新后重试') {
          if (current) drafts[current] = $('input').value;
          storeState(); clearSession(); run(bootstrap);
          throw Object.assign(new Error(result.error),{stale:true});
        }
        if (response.status === 401 && user) { clearSession(); showAuth('login','登录已过期，请重新登录。'); }
        throw Object.assign(new Error(result.error || `请求失败（${response.status}）`),{status:response.status,diagnostics:safeAIDiagnostics(result.diagnostics)});
      }
      return result;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('请求超时。消息可安全重试，不会重复发送。');
      if (error instanceof TypeError) throw new Error('无法连接服务器，请检查网络后重试。');
      throw error;
    } finally { clearTimeout(timeout); options.signal?.removeEventListener('abort',cancel); }
  }
  const run = task => Promise.resolve().then(task).catch(e => { if (!e.stale) toast(e.message || '操作未完成，请重试。'); });
  async function saveBytes(value,name,mime = 'application/octet-stream') {
    const bytesValue = typeof value === 'string' ? new TextEncoder().encode(value) : value;
    if (window.YuetiNative?.saveFile) return window.YuetiNative.saveFile({name,mime,bytes:bytesValue});
    const url = URL.createObjectURL(new Blob([bytesValue],{type:mime})); objectURLs.add(url);
    const link = document.createElement('a'); link.href = url; link.download = String(name).replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').slice(0,160) || '山水文件'; link.click();
    setTimeout(() => { URL.revokeObjectURL(url); objectURLs.delete(url); },60000);
  }
  async function exportRecovery() {
    if (!cryptoBox) throw new Error('请先登录并建立加密身份。');
    const backup = await cryptoBox.exportBackup();
    await saveBytes(JSON.stringify(backup,null,2),`山水通讯-加密恢复文件-${user.username}.json`,'application/json');
  }
  const formatFingerprint = value => String(value || '').replace(/(.{4})/g,'$1 ').trim();
  function approveTrust(peers) {
    if (!cryptoBox?.ready) return Promise.resolve(false);
    return new Promise(resolve => {
      if (trustResolve) trustResolve(false); trustResolve = resolve;
      const membership = peers.some(p => p.membership);
      $('trust-content').innerHTML = `<h2 id="trust-title">${membership ? '确认加密成员' : '确认联系人的安全码'}</h2><p class="dialogcopy">${membership ? '你将作为群主签名确认以下实际收件人。请检查成员名单与完整安全码，之后发出的消息将只加密给这些成员。' : '请通过见面、电话或另一条可信渠道，与这些联系人核对完整安全码。服务器提供的公钥不能代替核对。'}</p>${peers.map(p => `<div class="security-code"><strong>${esc(p.displayName || person(p.userId)?.displayName || p.userId)}</strong><code>${esc(formatFingerprint(p.fingerprint))}</code><small>${esc(p.userId)}</small></div>`).join('')}<label class="inline-check"><input id="trust-checked" type="checkbox">${membership ? '我确认以上成员与安全码' : '我已核对这些安全码'}</label><div class="dialogactions"><button class="secondarybtn" id="trust-cancel">暂不发送</button><button class="sendbtn" id="trust-confirm" disabled>确认并继续</button></div>`;
      $('trust-checked').onchange = event => { $('trust-confirm').disabled = !event.target.checked; };
      const finish = accepted => { const done = trustResolve; trustResolve = null; $('trust-dialog').close(); $('trust-content').replaceChildren(); done?.(accepted); };
      $('trust-confirm').onclick = () => finish(true); $('trust-cancel').onclick = () => finish(false);
      if (!$('trust-dialog').open) $('trust-dialog').showModal();
    });
  }
  function approveAIEndpoint(details,{signal} = {}) {
    if (!cryptoBox?.ready || securityTransition || signal?.aborted) return Promise.resolve(false);
    const generation = epoch, vault = vaultVersion, box = cryptoBox;
    return new Promise(resolve => {
      if (trustResolve) trustResolve(false);
      const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && !securityTransition && !signal?.aborted;
      const finish = accepted => { signal?.removeEventListener('abort',cancel); if (trustResolve !== done) return; trustResolve = null; $('trust-dialog').close(); $('trust-content').replaceChildren(); resolve(accepted && valid()); };
      const cancel = () => finish(false), done = accepted => { signal?.removeEventListener('abort',cancel); resolve(accepted && valid()); };
      trustResolve = done;
      $('trust-content').innerHTML = `<h2 id="trust-title">确认设备直连的 AI 服务</h2><p class="dialogcopy">${details.previousBaseUrl ? '管理员更换了模型 API 地址。' : '这台设备第一次使用此模型 API。'}你的问题、选定前文及主动附带的图片会直接交给下面的服务商；AI 私聊还会参考已开启的长期记忆。回复在本机加密后存入聊天。</p><div class="security-code"><strong>API 地址</strong><code id="ai-endpoint-review">${esc(details.baseUrl)}</code><strong>模型</strong><code>${esc(details.model || '读取可用模型')}</code></div>${details.previousBaseUrl ? `<p class="dialogcopy">原地址：${esc(details.previousBaseUrl)}</p>` : ''}<p class="dialogcopy">聊天服务器不接收 AI 原文，模型服务商会处理原文。请确认以上地址可信。</p><label class="inline-check"><input id="trust-checked" type="checkbox">我确认将 AI 提问交给以上服务</label><div class="dialogactions"><button id="trust-cancel" class="secondarybtn">取消</button><button id="trust-confirm" class="sendbtn" disabled>确认并继续</button></div>`;
      $('trust-checked').onchange = event => { $('trust-confirm').disabled = !event.target.checked; };
      $('trust-cancel').onclick = () => finish(false); $('trust-confirm').onclick = () => finish(true);
      signal?.addEventListener('abort',cancel,{once:true}); if (!$('trust-dialog').open) $('trust-dialog').showModal();
    });
  }
  $('trust-dialog').addEventListener('cancel',event => { event.preventDefault(); const done = trustResolve; trustResolve = null; $('trust-dialog').close(); $('trust-content').replaceChildren(); done?.(false); });
  function showLocked() {
    $('input').disabled = true; $('send').disabled = true; $('attach').disabled = true; $('stop').hidden = true; $('quickactions').hidden = true; $('mention').hidden = true;
    $('chatpolicy').hidden = false; $('chatpolicy').innerHTML = '<span>聊天已锁定 · 正文与附件在此设备解锁</span><button id="unlock-shortcut">解锁</button>';
    $('unlock-shortcut').onclick = () => run(unlockAndRefresh);
    $('messages').innerHTML = '<div class="live-empty"><strong>山水依旧，书信已锁</strong><span>使用恢复码解锁此设备，继续阅读与发送。</span><button class="secondarybtn" id="unlock-messages">解锁聊天</button></div>';
    $('unlock-messages').onclick = () => run(unlockAndRefresh); renderList();
  }
  async function requestSecurity(status = 'locked') {
    if (securityResolve) return false;
    const box = cryptoBox, generation = epoch, vault = vaultVersion;
    const result = new Promise(resolve => { securityResolve = resolve; });
    const finish = success => { const done = securityResolve; securityResolve = null; if (!success && box === cryptoBox) box.lock().catch(() => {}); $('security-dialog').close(); $('security-content').replaceChildren(); done?.(success); };
    const valid = () => box === cryptoBox && generation === epoch && vault === vaultVersion && $('security-dialog').open;
    if (status === 'new') {
      $('security-content').innerHTML = '<h2 id="security-title">给你的书信一把私钥</h2><p class="dialogcopy">加密身份会在此设备生成。服务器只保存公钥、密文及加密私钥备份，恢复码不会发送给服务器。</p><p class="dialogcopy">恢复码与登录密码不同。请将恢复码和加密恢复文件分开妥善保存；丢失恢复码后，管理员也无法解锁历史。</p><p id="security-error" class="form-error" role="alert"></p><div class="dialogactions"><button class="secondarybtn" id="security-later">稍后</button><button class="sendbtn" id="security-create">创建加密身份</button></div>';
      $('security-later').onclick = () => finish(false);
      $('security-create').onclick = async () => {
        const button = $('security-create'); button.disabled = true;
        try {
          const created = await box.createIdentity({deferRegistration:true}); if (!valid()) return;
          $('security-content').innerHTML = `<h2 id="security-title">请保存你的恢复码</h2><p class="dialogcopy">这串恢复码可以解锁你的全部加密聊天，请勿发到聊天里或分享给任何人。</p><label class="dialogfield">恢复码<textarea class="recovery-code" id="recovery-code" readonly spellcheck="false">${esc(created.recoveryCode)}</textarea></label><div class="profile-avatar-tools"><button class="secondarybtn" id="recovery-copy">复制恢复码</button><button class="secondarybtn" id="recovery-export">下载加密恢复文件</button></div><label class="inline-check"><input id="recovery-ack" type="checkbox">我已单独保存恢复码，知道恢复文件仍需要此码解锁</label><label class="inline-check"><input id="recovery-remember" type="checkbox">记住这台私人设备</label><p class="dialogcopy">共用或不可信的设备请勿勾选。恢复码仅以本机密钥包裹后保存。</p><p id="security-error" class="form-error" role="alert"></p><div class="dialogactions"><button class="sendbtn" id="recovery-done" disabled>进入聊天</button></div>`;
          $('recovery-copy').onclick = () => run(async () => { if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText($('recovery-code').value); toast('恢复码已复制，请保存到安全的地方。'); } else { $('recovery-code').focus(); $('recovery-code').select(); toast('请复制已选中的恢复码。'); } });
          $('recovery-export').onclick = () => run(exportRecovery);
          $('recovery-ack').onchange = event => { $('recovery-done').disabled = !event.target.checked; };
          $('recovery-done').onclick = async () => { const doneButton = $('recovery-done'); doneButton.disabled = true; try { await box.registerIdentity(); if ($('recovery-remember').checked) await box.rememberDevice(); if (valid()) finish(true); } catch (e) { if (valid()) $('security-error').textContent = e.message; doneButton.disabled = false; } };
        } catch (e) { if (valid()) $('security-error').textContent = e.message; if (button.isConnected) button.disabled = false; }
      };
    } else {
      $('security-content').innerHTML = `<h2 id="security-title">解锁你的聊天</h2><p class="dialogcopy">恢复码只在此设备使用，不会传给服务器。登录密码不能替代恢复码。</p><form id="unlock-form" class="account-form"><label>恢复码<input id="unlock-code" type="password" autocomplete="off" spellcheck="false" required></label><label>加密恢复文件（可选）<input id="unlock-backup" type="file" accept=".json,application/json"></label><label class="inline-check"><input id="unlock-remember" type="checkbox">记住这台私人设备</label><p id="security-error" class="form-error" role="alert"></p><div class="dialogactions"><button class="secondarybtn" id="unlock-later" type="button">稍后</button><button class="sendbtn" id="unlock-confirm">解锁</button></div></form>`;
      $('unlock-later').onclick = () => finish(false);
      $('unlock-form').onsubmit = async event => {
        event.preventDefault(); const button = $('unlock-confirm'), code = $('unlock-code').value.trim(); button.disabled = true;
        try { const file = $('unlock-backup').files?.[0], opts = {remember:$('unlock-remember').checked}; if (file) { if (file.size > 2 * 1024 * 1024) throw new Error('恢复文件过大，请选择正确的 JSON 备份。'); await box.importBackup(JSON.parse(await file.text()),code,opts); } else await box.unlock(code,opts); if (valid()) { $('unlock-code').value = ''; finish(true); } }
        catch (e) { if (valid()) $('security-error').textContent = e.message; }
        finally { if (button.isConnected) button.disabled = false; }
      };
    }
    $('security-dialog').showModal(); return result;
  }
  $('security-dialog').addEventListener('cancel',event => { event.preventDefault(); if ($('recovery-code')) return; const done = securityResolve; securityResolve = null; cryptoBox?.lock().catch(() => {}); $('security-dialog').close(); $('security-content').replaceChildren(); done?.(false); });
  async function unlockAndRefresh() {
    if (!cryptoBox || !user) return; const box = cryptoBox, generation = epoch;
    if (!box.ready && !await requestSecurity(box.identity ? 'locked' : 'new')) { showLocked(); return; }
    if (box !== cryptoBox || generation !== epoch) return;
    await loadState(); await refreshAll(); if (current) await switchChat(current,false,false);
  }
  async function lockChat(forget = false) {
    if (!cryptoBox || !beginSecurityTransition()) return;
    const box = cryptoBox, generation = epoch;
    try { if (current) drafts[current] = $('input').value; await persistEncrypted(); } catch { toast('最新草稿未能加密保存，锁定后将清除它。'); }
    if (box !== cryptoBox || generation !== epoch) return;
    try { await box.lock({forget}); }
    finally { if (box === cryptoBox && generation === epoch) { clearPlaintext(); securityTransition = false; showLocked(); } }
  }
  function beginSecurityTransition() {
    if (securityTransition) return false;
    securityTransition = true; vaultVersion++; clearTimeout(persistTimer);
    sensitiveDialogCleanup?.(); sensitiveDialogCleanup = null;
    contactRevision++; contactController?.abort(); contactController = null; contactBusy = false;
    for (const controller of aiJobs.values()) controller.abort();
    for (const controller of transfers) controller.abort();
    aiPreparing.clear();
    for (const id of ['input','send','mention','attach','ai-search']) if ($(id)) $(id).disabled = true;
    return true;
  }
  async function logoutAccount() {
    if (!beginSecurityTransition()) return;
    if (current) drafts[current] = $('input').value;
    try { await persistEncrypted(); } catch { toast('最新草稿未保存，退出后将清除它。'); }
    let warning = '';
    try { await api('/api/auth/logout',{method:'POST',timeout:10000}); }
    catch { warning = '本机已退出；服务器连接失败，会话撤销尚未确认。'; }
    finally { sessionChannel?.postMessage({type:'signed-out'}); clearSession(); showAuth('login',warning); }
  }
  async function decodedMessage(c,m) {
    const sourceMessage = normalizeMessage(m);
    if (!cryptoBox?.ready) return {...sourceMessage,text:'',quote:null,file:null,locked:true};
    const box = cryptoBox, generation = epoch, vault = vaultVersion;
    try {
      const prior = (messages.get(c.id) || []).find(item => item.id === sourceMessage.id), envelope = sourceMessage.envelope;
      const senderKey = box.records.get(sourceMessage.senderId)?.key, manifest = envelope && box.chains.get(c.id)?.[envelope.revision - 1];
      if (prior?._decrypted && !prior.decryptError && prior._verifiedEpoch === box.epoch && senderKey && prior._verifiedSenderKey === senderKey && manifest && prior._verifiedManifest === manifest && envelope?.senderFingerprint === box.records.get(sourceMessage.senderId)?.fingerprint && sourceMessage.chatId === c.id && sourceMessage.chatId === prior.chatId && sourceMessage.senderId === prior.senderId && sourceMessage.clientId === prior.clientId && sourceMessage.contentVersion === 1 && sourceMessage.file?.id === prior._wire?.file?.id && JSON.stringify(envelope) === JSON.stringify(prior._wire?.envelope)) {
        return {...prior,...sourceMessage,kind:prior.kind,text:prior.text,quote:prior.quote,file:prior.file,ai:prior.ai,createdAt:prior.sentAt || sourceMessage.createdAt,_wire:sourceMessage};
      }
      const payload = await box.decrypt(c,sourceMessage);
      if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box.ready) return {...sourceMessage,text:'',quote:null,file:null,locked:true};
      const quote = payload.quote && typeof payload.quote === 'object' ? {id:String(payload.quote.id || ''),senderName:String(payload.quote.senderName || '').slice(0,100),text:String(payload.quote.text || '').slice(0,12000)} : null;
      return {...sourceMessage,createdAt:payload.sentAt || sourceMessage.createdAt,sentAt:payload.sentAt || null,kind:payload.kind,text:payload.text,quote,file:payload.file || null,ai:payload.ai || null,legacy:sourceMessage.contentVersion === 0 || !sourceMessage.envelope && !sourceMessage.contentVersion,_wire:sourceMessage,_decrypted:true,_verifiedEpoch:box.epoch,_verifiedSenderKey:box.records.get(sourceMessage.senderId)?.key,_verifiedManifest:envelope && box.chains.get(c.id)?.[envelope.revision - 1]};
    }
    catch (error) {
      if (c?.kind === 'group' && /尚未确认联系人的安全指纹/.test(error.message) && generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready) {
        chatSecurityErrors.set(c.id,'群成员有变化，请核对新成员的安全码后继续收发。');
        if (current === c.id) renderHeader();
      }
      return {...sourceMessage,text:'',quote:null,file:null,decryptError:error.message,_wire:sourceMessage};
    }
  }
  function showAuth(mode = 'login', error = '') {
    authMode = mode; const setup = mode === 'setup', register = mode === 'register';
    $('auth').hidden = false; $('app').hidden = true;
    $('auth').innerHTML = `<div class="auth-card"><h2>${setup ? '开启你的山水空间' : register ? '相聚山水之间' : '欢迎回到山水之间'}</h2><p class="dialogcopy">${setup ? '使用部署时生成的初始化口令，创建管理员账户。' : register ? '使用朋友分享的邀请码，创建你的账户。' : '登录，与朋友和 AI 继续聊聊。'}</p><form id="auth-form">${setup ? '<label>初始化口令<input name="setupToken" id="setup-token" autocomplete="off" type="password" required></label>' : ''}<label>账户名<input name="username" id="auth-username" autocomplete="username" minlength="3" maxlength="32" required placeholder="英文字母、数字或下划线"></label>${setup || register ? '<label>昵称<input name="displayName" id="auth-name" autocomplete="nickname" maxlength="40" required></label>' : ''}<label>密码<input name="password" id="auth-password" type="password" autocomplete="${setup || register ? 'new-password' : 'current-password'}" minlength="8" maxlength="128" required></label>${register ? '<label>邀请码<input name="inviteCode" id="auth-invite" autocomplete="off" required></label>' : ''}<p class="form-error" id="auth-error" role="alert">${esc(error)}</p><button class="sendbtn" type="submit" id="auth-submit">${setup ? '创建管理员' : register ? '注册并进入' : '登录'}</button></form>${!setup ? `<div class="auth-links"><button id="auth-switch">${register ? '已有账户，去登录' : '使用邀请码注册'}</button><button id="auth-refresh">重新连接</button></div>` : ''}<p class="auth-server">${esc(location.host)} · 山水通讯</p></div>`;
    if ($('auth-switch')) $('auth-switch').onclick = () => showAuth(register ? 'login' : 'register');
    if ($('auth-refresh')) $('auth-refresh').onclick = () => run(bootstrap);
    $('auth-form').onsubmit = async event => {
      event.preventDefault(); const button = $('auth-submit'), errorBox = $('auth-error'), startEpoch = epoch;
      button.disabled = true; errorBox.textContent = '';
      const values = Object.fromEntries(new FormData(event.currentTarget));
      try {
        const result = await api(setup ? '/api/setup' : register ? '/api/auth/register' : '/api/auth/login',{method:'POST',body:values});
        if (startEpoch !== epoch) return;
        sessionChannel?.postMessage({type:'changed'});
        $('auth-password').value = ''; if ($('setup-token')) $('setup-token').value = '';
        await enter(result.user);
      } catch (e) { if (!e.stale && errorBox.isConnected) errorBox.textContent = e.message; }
      finally { if (button.isConnected) button.disabled = false; }
    };
  }
  async function bootstrap() {
    try {
      const info = await api('/api/bootstrap'); needsSetup = info.needsSetup;
      if (!info.e2eeRequired || typeof info.serverInstanceId !== 'string') throw new Error('此客户端需要山水通讯 1.3 加密服务器，请升级服务端后重试。');
      if (info.friendshipRequired !== true) throw new Error('此客户端需要支持好友申请的山水通讯服务器，请升级服务端后重试。');
      serverId = info.serverInstanceId;
      if (needsSetup) { showAuth('setup'); return; }
      try { const me = await api('/api/me'); await enter(me.user); }
      catch (e) { if (e.status === 401) showAuth('login'); else throw e; }
    } catch (e) { showAuth(needsSetup ? 'setup' : 'login',e.message); }
  }
  async function enter(value) {
    epoch++; user = {...value,id:String(value.id)}; $('auth').hidden = true; $('app').hidden = false; $('auth').replaceChildren();
    setNavigation('chat');
    cryptoBox = new CryptoBox({api,user,serverId}); const box = cryptoBox, generation = epoch;
    paintSelf(); renderEmpty();
    const state = await box.initialize(); if (generation !== epoch || box !== cryptoBox) return;
    if (state.status !== 'ready') await requestSecurity(state.status);
    if (generation !== epoch || box !== cryptoBox) return;
    if (box.ready) await loadState();
    await refreshAll();
    if (user && !current && chats.length) await switchChat(chats[0].id,false);
    if (!user) return;
    if (box.ready) run(async () => { const result = await api('/api/saved'); saved = new Set(result.items.map(i => String(i.message.id))); renderMessages(); });
    connectEvents();
    refreshNativeNotificationView();if(pendingNotificationChat)run(openNotificationChat);
    clearInterval(pollTimer); pollTimer = setInterval(() => { if (user && document.visibilityState === 'visible') queueRefresh(); },20000);
  }
  function setConnection(ok) { connected = ok; $('connection').textContent = ok ? '已连接' : '正在重连'; $('networknotice').hidden = ok; document.querySelector('.statusdot').style.background = ok ? 'var(--accent)' : 'var(--error)'; }
  function connectEvents() {
    source?.close(); if (!user) return;
    const generation = epoch; source = new EventSource('/api/events',{withCredentials:true});
    source.onopen = () => { if (epoch === generation) { setConnection(true); queueRefresh(); } };
    source.onmessage = event => { if (generation !== epoch) return; try { if (JSON.parse(event.data).type === 'refresh') queueRefresh(); } catch {} };
    source.addEventListener('auth',() => { if (generation !== epoch) return; if (current) drafts[current] = $('input').value; storeState(); clearSession(); showAuth('login','登录已结束，请重新登录。'); });
    source.onerror = () => { if (generation === epoch) setConnection(false); };
  }
  function queueRefresh() { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => run(refreshAll),150); }
  async function refreshAll() {
    if (!user) return;
    if (refreshing) { refreshAgain = true; return; }
    refreshing = true; const generation = epoch, revision = chatRevision; let refreshedChat = null;
    try {
      const result = await api('/api/chats'); if (generation !== epoch || !user) return;
      if (revision !== chatRevision) { refreshAgain = true; return; }
      chats = result.chats.map(normalizeChat);
      if (cryptoBox?.ready && current && chat()) { const visible = current; renderHeader(); await fetchMessages(visible,false); refreshedChat = visible; if (generation !== epoch || !user) return; }
      if (cryptoBox?.ready) {
        const box = cryptoBox;
        const previews = await Promise.all(chats.map(async c => [c.id,c.lastMessage ? await decodedMessage(c,c.lastMessage) : null]));
        if (generation !== epoch || box !== cryptoBox || !box.ready) return;
        if (revision !== chatRevision) { refreshAgain = true; return; }
        const byId = new Map(previews); chats = chats.map(c => ({...c,lastMessage:byId.get(c.id)}));
      }
      const refreshedSelf = chats.flatMap(c => c.members).find(member => member.id === user.id);
      if (refreshedSelf) { user = {...refreshedSelf}; paintSelf(); }
      renderList();
      if (current && !chat()) { current = null; selection++; renderEmpty(); }
      if (!cryptoBox?.ready) showLocked();
      else if (current) { renderHeader(); if (current !== refreshedChat) await fetchMessages(current,false); }
      else if (chats.length && activeView !== 'people') await switchChat(chats[0].id,false);
      if (activeView === 'people' && !contactBusy && cryptoBox?.ready && !securityTransition) run(() => loadContacts({silent:true}));
      if (source?.readyState === EventSource.OPEN) setConnection(true);
    } catch (e) { if (generation === epoch) setConnection(false); throw e; }
    finally { if (generation === epoch) { refreshing = false; if (refreshAgain) { refreshAgain = false; queueRefresh(); } } }
  }
  function person(id,c = chat()) { return String(id) === user?.id ? user : c?.members.find(p => p.id === String(id)) || {id:String(id),displayName:String(id) === 'ai' ? '山岚' : '成员'}; }
  function avatar(p) { const url = safeURL(p?.avatarUrl,'/api/avatars/'); return url ? `<img class="avatar-image" src="${esc(url)}" alt="">` : p?.id === 'ai' ? icon('ai') : esc((p?.displayName || p?.username || '我').slice(0,1)); }
  function chatAvatar(c) { if (c.kind === 'ai') return icon('ai'); if (c.kind === 'group') return icon('mountain'); if (c.kind === 'notes') return '记'; return avatar(c.members.find(p => p.id !== user?.id) || user); }
  const chatStyle = c => c.kind === 'ai' ? 'ai' : c.kind === 'group' ? 'group' : '';
  function paintSelf() { if (!user) return; setStableHTML($('self-avatar'),avatar(user)); $('self-avatar').title = `${user.displayName} · 更换头像`; }
  function renderList() {
    const q = $('search').value.trim().toLocaleLowerCase();
    const list = chats.filter(c => (filter === 'all' || filter === 'person' && ['direct','group'].includes(c.kind) || filter === 'ai' && (c.kind === 'ai'||c.members.some(m=>m.id==='ai')) || filter === 'unread' && c.unread > 0) && (!q || c.name.toLocaleLowerCase().includes(q) || cryptoBox?.ready && c.lastMessage?.text?.toLocaleLowerCase().includes(q)));
    list.sort((a,b) => Number(b.pinned) - Number(a.pinned) || String(b.updatedAt).localeCompare(String(a.updatedAt)));
    stableChildren($('chatlist'),list.length ? list.map(c => `<button class="chatitem ${c.id === current ? 'current' : ''}" data-chat="${esc(c.id)}" ${c.id === current ? 'aria-current="true"' : ''}><div class="avatar ${chatStyle(c)}">${chatAvatar(c)}</div><div class="itemtext"><div class="itemtop"><strong>${esc(c.name)}${c.pinned ? '<span class="smalltag">置顶</span>' : ''}</strong><time>${esc(time(c.updatedAt))}</time></div><div class="preview"><span>${esc(c.lastMessage ? !cryptoBox?.ready || c.lastMessage.locked ? '加密消息 · 解锁后查看' : c.lastMessage.decryptError ? '加密消息 · 需核验安全码' : c.lastMessage.file ? `[文件] ${c.lastMessage.file.name}` : c.lastMessage.text || '加密消息' : '开始一段新的对话')}</span>${c.unread ? `<span class="unread">${c.unread > 99 ? '99+' : c.unread}</span>` : ''}</div></div></button>`).join('') : '<p class="empty">还没有符合条件的会话。<br>点击右上角 +，开始聊天。</p>','data-chat');
    $('chatlist').querySelectorAll('[data-chat]').forEach(b => { b.onclick = () => run(() => switchChat(b.dataset.chat)); });
  }
  async function switchChat(id,mobile = true,saveDraft = true) {
    id = String(id); if (!chat(id)) return;
    setNavigation('chat');
    if (current && saveDraft) drafts[current] = $('input').value;
    current = id; selection++; $('input').value = typeof drafts[id] === 'string' ? drafts[id] : ''; hideDetails();
    if (mobile) $('app').classList.add('mobile-chat');
    if (!cryptoBox?.ready) { showLocked(); return; }
    chatSecurityErrors.set(id,'正在核验加密成员…');
    renderHeader(); renderList(); renderMessages('open'); renderCompose(); storeState();
    const version = selection, box = cryptoBox, generation = epoch; let preparationError = '';
    try { await box.prepareChat(chat(id),approveTrust); } catch (e) { preparationError = e.message || '加密成员尚未完成验证。'; }
    if (current !== id || selection !== version || generation !== epoch || box !== cryptoBox || !box.ready) return;
    if (preparationError) chatSecurityErrors.set(id,preparationError); else chatSecurityErrors.delete(id);
    renderHeader(); renderCompose();
    // Legacy history remains readable without a manifest. Encrypted records still
    // go through CryptoBox signature/audience verification, with no plaintext fallback.
    try { await fetchMessages(id,true); if (current === id && selection === version) markRead(); }
    catch (e) { if (current === id && selection === version && !messages.has(id)) $('messages').innerHTML = `<div class="errorblock">${esc(e.message)}<br><button id="reload-messages" class="secondarybtn">重新加载</button></div>`; if ($('reload-messages')) $('reload-messages').onclick = () => run(() => switchChat(id)); throw e; }
  }
  async function fetchMessages(id,scroll = false,before = null) {
    if (!cryptoBox?.ready) return;
    const box = cryptoBox;
    const generation = epoch, vault = vaultVersion, key = `${id}:${before || 'latest'}`, request = (requests.get(key) || 0) + 1; requests.set(key,request);
    const result = await api(`/api/chats/${encodeURIComponent(id)}/messages?limit=50${before ? `&before=${encodeURIComponent(before)}` : ''}`);
    if (generation !== epoch || vault !== vaultVersion || requests.get(key) !== request) return;
    const incoming = result.messages.map(normalizeMessage), prior = messages.get(id) || [];
    // A long disconnection can add more than one page. Fill the interval before
    // merging the latest page so messages cannot silently disappear in a gap.
    if (!before && prior.length && incoming.length && incoming[0].seq > prior.at(-1).seq) {
      let boundary = incoming[0].seq, more = result.hasMore;
      while (more && boundary > prior.at(-1).seq) {
        const bridge = await api(`/api/chats/${encodeURIComponent(id)}/messages?limit=50&before=${encodeURIComponent(boundary)}`);
        if (generation !== epoch || vault !== vaultVersion || requests.get(key) !== request) return;
        const rows = bridge.messages.map(normalizeMessage); if (!rows.length || rows[0].seq >= boundary) break;
        incoming.unshift(...rows); boundary = rows[0].seq; more = bridge.hasMore;
      }
    }
    const decrypted = await Promise.all(incoming.map(m => decodedMessage(chat(id),m)));
    if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box.ready || requests.get(key) !== request) return;
    const merged = new Map((messages.get(id) || []).map(m => [m.id,m]));
    decrypted.forEach(m => merged.set(m.id,m)); messages.set(id,[...merged.values()].sort((a,b) => a.seq - b.seq));
    if (before || !prior.length) hasMore.set(id,Boolean(result.hasMore));
    const confirmed = new Set(decrypted.filter(m => m.senderId === user?.id && m._decrypted && pending.some(p => p.clientId === m.clientId && p.envelope?.ciphertext === m._wire?.envelope?.ciphertext)).map(m => m.clientId));
    if (pending.some(p => p.chatId === id && confirmed.has(p.clientId))) { pending = pending.filter(p => !(p.chatId === id && confirmed.has(p.clientId))); storeState(); }
    if (current === id) { renderMessages(scroll,Boolean(before)); renderCompose(); if ($('app').classList.contains('show-details')) renderDetails(); markRead(); }
  }
  function renderMention() {
    const c = chat(), button = $('mention');
    button.hidden = !['group','direct'].includes(c?.kind) || !isAI(c);
    button.disabled = !cryptoBox?.ready || chatSecurityErrors.has(current) || $('input').disabled || c?.context === 'none' || aiJobs.has(current) || aiPreparing.has(current);
    button.title = !cryptoBox?.ready || chatSecurityErrors.has(current) || $('input').disabled ? '完成聊天加密验证后可使用' : c?.context === 'none' ? '山岚已暂停，可在会话详情启用' : aiJobs.has(current) || aiPreparing.has(current) ? '山岚正在处理，请等待或停止' : '在光标处插入 @山岚，不会立即发送';
  }
  function renderEmpty() {
    $('chatname').textContent = '山水之间'; $('chatsub').textContent = '朋友与 AI，都在这里'; $('headavatar').textContent = '山';
    $('chatpolicy').hidden = true; $('quickactions').hidden = true; $('messages').innerHTML = '<div class="live-empty"><strong>从一句话，开始相聚</strong><span>点击 +，联系朋友、创建小群，或与山岚聊聊。</span></div>';
    $('input').disabled = true; $('send').disabled = true; $('attach').disabled = true; $('mention').hidden = true;
  }
  function renderHeader() {
    if (securityTransition) return;
    const c = chat(); if (!c) { renderEmpty(); return; }
    refreshNativeNotificationView();
    if (!cryptoBox?.ready) { showLocked(); return; }
    $('input').disabled = false; $('attach').disabled = false; $('emoji').disabled = false;
    $('chatname').textContent = c.name; $('headavatar').className = `avatar ${chatStyle(c)}`; setStableHTML($('headavatar'),chatAvatar(c));
    $('chatsub').textContent = c.kind === 'group' ? `${c.members.filter(p => p.id !== 'ai').length} 位成员${isAI(c) ? ' · 山岚直连 AI' : ''}` : c.kind === 'ai' ? 'AI 助手 · 此设备直连模型' : c.kind === 'notes' ? '仅自己可见' : '私聊';
    if (friendshipBlocked(c)) {
      $('input').disabled = true; $('attach').disabled = true; $('send').disabled = true; $('emoji').disabled = true; $('quickactions').hidden = true; renderMention();
      $('input').placeholder = '成为好友后才能发送消息';
      $('chatpolicy').hidden = false;
      setStableHTML($('chatpolicy'),`<span>${c.friendshipStatus === 'outgoing' ? '好友申请等待通过' : c.friendshipStatus === 'incoming' ? '对方向你发送了好友申请' : '尚未成为好友'} · 历史可读，对方同意后才能发送消息</span><button id="friendship-shortcut">${c.friendshipStatus === 'incoming' || c.friendshipStatus === 'outgoing' ? '查看申请' : '添加好友'}</button>`);
      $('friendship-shortcut').onclick = () => run(() => openContacts(c.friendshipStatus === 'incoming' || c.friendshipStatus === 'outgoing' ? 'requests' : 'add',directPeer(c)?.username || ''));
      return;
    }
    const securityError = chatSecurityErrors.get(c.id);
    if (securityError) {
      $('input').disabled = true; $('attach').disabled = true; $('send').disabled = true; $('quickactions').hidden = true; renderMention();
      $('chatpolicy').hidden = false; $('chatpolicy').innerHTML = `<span>需要核验加密成员 · ${esc(securityError)}</span><button id="retry-encryption">${c.kind === 'group' ? '核验群成员' : '重新验证'}</button>`;
      $('retry-encryption').onclick = () => run(() => switchChat(c.id,false)); return;
    }
    $('chatpolicy').hidden = false; $('chatpolicy').innerHTML = `<span>${isAI(c) ? c.context === 'none' ? '聊天端到端加密 · AI 已暂停' : '聊天端到端加密 · AI 输入由此设备直达模型' : '端到端加密 · 在你的设备解密'}</span>${isAI(c) ? '<button id="ai-context-shortcut">AI 前文与隐私</button>' : ''}${c.kind==='ai'?'<button id="ai-memory-shortcut">长期记忆</button>':''}<button id="viewpolicy">安全详情</button>`;
    if ($('ai-context-shortcut')) $('ai-context-shortcut').onclick = () => run(() => showAIContext(c.id));
    if($('ai-memory-shortcut'))$('ai-memory-shortcut').onclick=()=>run(memorySettings);
    $('viewpolicy').onclick = showDetails; $('quickactions').hidden = !isAI(c) || c.context === 'none'; renderMention();
    $('input').placeholder = c.context === 'none' && isAI(c) ? 'AI 已暂停…' : isAI(c) && ['group','direct'].includes(c.kind) ? '输入消息，@山岚 提问，/生图 画图' : c.kind === 'ai' ? '和山岚聊聊…' : '输入消息…';
  }
  let emoticonStore = null, emoticonScope = '', imageLoadCount = 0;
  const imagePreviewCache = new Map(), imagePreviewJobs = new Map(), imageLoadQueue = [], stickerPreviewURLs = new Map(), mediaURLs = new Set();
  function resetMediaTools() {
    emoticonStore?.lock(); emoticonStore = null; emoticonScope = '';
    for (const item of imagePreviewCache.values()) item.bytes.fill(0); imagePreviewCache.clear(); imagePreviewJobs.clear(); stickerPreviewURLs.clear();
    for (const url of mediaURLs) { URL.revokeObjectURL(url); objectURLs.delete(url); } mediaURLs.clear();
    $('emoticon-file-input')?.remove();
  }
  function rasterCandidate(file) { return /^(?:image\/(?:png|jpe?g|gif|webp))$/i.test(file?.mime || '') || (!file?.mime || file.mime === 'application/octet-stream') && /\.(?:png|jpe?g|gif|webp)$/i.test(file?.name || ''); }
  function mediaURL(bytes,mime) { const url = URL.createObjectURL(new Blob([bytes],{type:mime})); objectURLs.add(url); mediaURLs.add(url); return url; }
  function revokeMediaURL(url) { URL.revokeObjectURL(url); objectURLs.delete(url); mediaURLs.delete(url); }
  async function imageLoadSlot() { if (imageLoadCount >= 3) await new Promise(resolve => imageLoadQueue.push(resolve)); else imageLoadCount++; }
  function releaseImageSlot() { const next = imageLoadQueue.shift(); if (next) next(); else imageLoadCount--; }
  function emoticonLibrary() {
    if (!cryptoBox?.ready || !user) throw new Error('请先解锁聊天。');
    const scope = `${serverId}:${user.id}`;
    if (!emoticonStore || emoticonScope !== scope) {
      emoticonStore?.lock(); const box = cryptoBox, generation = epoch, vault = vaultVersion;
      emoticonStore = new EncryptedEmoticonStore({box,serverId,userId:user.id,isCurrent:() => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready}); emoticonScope = scope;
    }
    return emoticonStore;
  }
  async function imageAttachment(id) {
    const message = [...messages.values()].flat().find(value => value.id === id);
    if (!message?._decrypted || message.decryptError || message.legacy || !message.file || !rasterCandidate(message.file) || !cryptoBox?.ready) throw new Error('请先解锁并验证这条图片消息。');
    const box = cryptoBox, generation = epoch, vault = vaultVersion, key = `${serverId}:${user.id}:${id}:${message.file.sha256}`;
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready;
    if (imagePreviewCache.has(key)) return imagePreviewCache.get(key);
    if (imagePreviewJobs.has(key)) return imagePreviewJobs.get(key);
    const task = (async () => {
      await imageLoadSlot(); const controller = new AbortController(); transfers.add(controller);
      try {
        if (!valid()) throw new Error('聊天已锁定，图片预览已取消。');
        const response = await fetch(`/api/files/${encodeURIComponent(message.file.id)}`,{credentials:'same-origin',headers:{'X-Yueti-User':user.id},cache:'no-store',signal:controller.signal});
        if (!response.ok || !response.body) throw new Error('图片下载失败，请检查网络或重新核验成员。');
        const chunks = [], reader = response.body.getReader(); let length = 0;
        while (true) { const {value,done} = await reader.read(); if (done) break; length += value.length; if (length > 25 * 1024 * 1024) { await reader.cancel(); throw new Error('加密图片超过大小限制。'); } chunks.push(value); }
        if (!valid()) throw new Error('聊天已锁定，图片预览已取消。');
        const encrypted = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { encrypted.set(chunk,offset); offset += chunk.length; }
        const result = await box.decryptAttachment(chat(message.chatId),message._wire || message,encrypted);
        if (!valid()) throw new Error('聊天已锁定，图片预览已取消。');
        const mime = validateRasterImage(result.bytes,result.mime), item = {bytes:result.bytes,name:result.name,mime,url:mediaURL(result.bytes,mime)};
        imagePreviewCache.set(key,item);
        let total = [...imagePreviewCache.values()].reduce((sum,image) => sum + image.bytes.length,0);
        while (imagePreviewCache.size > 64 || total > 48 * 1024 * 1024) { const oldest = imagePreviewCache.keys().next().value, old = imagePreviewCache.get(oldest); total -= old.bytes.length; old.bytes.fill(0); revokeMediaURL(old.url); imagePreviewCache.delete(oldest); }
        return item;
      } finally { transfers.delete(controller); releaseImageSlot(); }
    })();
    imagePreviewJobs.set(key,task);
    try { return await task; } finally { if (imagePreviewJobs.get(key) === task) imagePreviewJobs.delete(key); }
  }
  async function prepareStickerBytes(value,mime = '') {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value), type = validateRasterImage(bytes,mime);
    if (bytes.length <= 3 * 1024 * 1024) return {bytes,mime:type};
    if (type === 'image/gif') throw new Error('动态表情最大 3 MB，请选择更小的 GIF。');
    const bitmap = await createImageBitmap(new Blob([bytes],{type}));
    try {
      const scale = Math.min(1,768 / Math.max(bitmap.width,bitmap.height)), canvas = document.createElement('canvas');
      canvas.width = Math.max(1,Math.round(bitmap.width * scale)); canvas.height = Math.max(1,Math.round(bitmap.height * scale)); canvas.getContext('2d').drawImage(bitmap,0,0,canvas.width,canvas.height);
      const blob = await new Promise(resolve => canvas.toBlob(resolve,'image/webp',0.88)); if (!blob) throw new Error('无法缩小这张图片，请换一张图片。');
      return {bytes:new Uint8Array(await blob.arrayBuffer()),mime:blob.type};
    } finally { bitmap.close(); }
  }
  function stickerURL(item) { if (!stickerPreviewURLs.has(item.id)) stickerPreviewURLs.set(item.id,mediaURL(item.bytes,item.mime)); return stickerPreviewURLs.get(item.id); }
  async function sendEmoticon(item,id) {
    if (!cryptoBox?.ready || !chat(id) || current !== id || securityTransition || friendshipBlocked(chat(id))) return;
    const box = cryptoBox, generation = epoch, vault = vaultVersion, extension = { 'image/png':'png','image/jpeg':'jpg','image/webp':'webp','image/gif':'gif' }[item.mime];
    const file = new File([item.bytes],`${item.name.replace(/\.(?:png|jpe?g|gif|webp)$/i,'')}.${extension}`,{type:item.mime});
    const outgoing = makeOutgoing(id,'',file,null); $('dialog').close(); renderMessages('send'); await persistEncrypted();
    if (generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready) await deliver(outgoing);
  }
  async function openEmoticons(tab = 'emoji') {
    if (!current || !cryptoBox?.ready || securityTransition || friendshipBlocked(chat())) return;
    const id = current, box = cryptoBox, generation = epoch, vault = vaultVersion, selected = selection, account = user.id, library = emoticonLibrary();
    const version = openDialog('表情',`<div class="emoticon-tabs"><button id="emoticon-emoji-tab" aria-pressed="${tab === 'emoji'}">常用表情</button><button id="emoticon-saved-tab" aria-pressed="${tab === 'saved'}">我的表情</button><button id="emoticon-default-tab" aria-pressed="${tab === 'default'}">初始表情</button><button id="emoticon-upload" class="secondarybtn">＋ 从相册添加</button></div><div id="emoticon-emoji-grid" class="emoticon-emoji-grid" ${tab !== 'emoji' ? 'hidden' : ''}>${EMOJI_CHOICES.map((choice,index) => `<button type="button" data-emoji-choice="${index}" title="${esc(choice.label)}" aria-label="${esc(choice.label)}">${choice.text}</button>`).join('')}</div><div id="emoticon-saved-grid" class="emoticon-saved-grid" ${tab !== 'saved' ? 'hidden' : ''}><p class="dialogcopy">正在解锁本机表情…</p></div><div id="emoticon-default-grid" class="emoticon-saved-grid" ${tab !== 'default' ? 'hidden' : ''}>${DEFAULT_STICKERS.map(item => `<div class="emoticon-card"><button type="button" class="emoticon-send" data-default-emoticon="${item.id}" title="${esc(item.label)}" aria-label="发送初始表情 ${esc(item.label)}"><img src="${item.path}" alt="${esc(item.label)}" loading="lazy"></button><small class="emoticon-remove">${esc(item.label)}</small></div>`).join('')}</div><p id="emoticon-error" class="form-error" role="status"></p><p class="emoticon-note">初始表情所有账户都可使用，点击图片直接加密发送。我的表情仅保存在此账户的本设备，按聊天密钥加密；较大的静态图片会缩小，GIF 保留动画。</p>`);
    const valid = () => dialogCurrent(version) && generation === epoch && vault === vaultVersion && selected === selection && box === cryptoBox && box.ready && current === id && user?.id === account && !securityTransition && !friendshipBlocked(chat(id));
    let activeTab = tab, defaultController = null;
    const cancelDefaultLoad = () => defaultController?.abort();
    $('dialog').addEventListener('close',cancelDefaultLoad,{once:true});
    const selectTab = next => { if (!valid()) return; if (next !== activeTab) cancelDefaultLoad(); activeTab = next; for (const name of ['emoji','saved','default']) { $(`emoticon-${name}-grid`).hidden = name !== next; $(`emoticon-${name}-tab`).setAttribute('aria-pressed',String(name === next)); } };
    $('emoticon-emoji-tab').onclick = () => selectTab('emoji'); $('emoticon-saved-tab').onclick = () => selectTab('saved'); $('emoticon-default-tab').onclick = () => selectTab('default');
    $('dialogcontent').querySelectorAll('[data-default-emoticon]').forEach(button => { button.onclick = () => run(async () => {
      if (!valid() || activeTab !== 'default') return; cancelDefaultLoad(); const controller = new AbortController(); defaultController = controller; transfers.add(controller); button.disabled = true; $('emoticon-error').textContent = '正在准备表情…'; let item;
      try { item = await loadDefaultSticker(button.dataset.defaultEmoticon,{signal:controller.signal,isCurrent:() => valid() && activeTab === 'default' && defaultController === controller}); if (!valid() || controller.signal.aborted || activeTab !== 'default' || defaultController !== controller) return; await sendEmoticon(item,id); }
      catch (error) { if (valid() && !controller.signal.aborted) $('emoticon-error').textContent = error.message; }
      finally { item?.bytes.fill(0); transfers.delete(controller); if (defaultController === controller) defaultController = null; if (button.isConnected) button.disabled = false; }
    }); });
    $('dialogcontent').querySelectorAll('[data-emoji-choice]').forEach(button => { button.onclick = () => { if (!valid()) return; const choice = EMOJI_CHOICES[Number(button.dataset.emojiChoice)]; $('dialog').close(); insertText(choice.text); }; });
    let input = $('emoticon-file-input'); if (!input) { input = document.createElement('input'); input.id = 'emoticon-file-input'; input.type = 'file'; input.accept = 'image/png,image/jpeg,image/webp,image/gif'; input.hidden = true; document.body.append(input); }
    $('emoticon-upload').onclick = () => { if (valid()) { input.value = ''; input.click(); } };
    input.onchange = () => run(async () => {
      const file = input.files?.[0]; input.value = ''; if (!file || !valid()) return;
      const button = $('emoticon-upload'); button.disabled = true; $('emoticon-error').textContent = '正在加密保存表情…';
      try { const prepared = await prepareStickerBytes(new Uint8Array(await file.arrayBuffer()),file.type); if (!valid()) return; await library.add(prepared.bytes,file.name); if (!valid()) return; await openEmoticons('saved'); toast('已添加到我的表情，点击图片即可发送。'); }
      catch (error) { if (valid()) $('emoticon-error').textContent = error.message; }
      finally { if (button.isConnected) button.disabled = false; }
    });
    try {
      const items = await library.list(); if (!valid()) return;
      $('emoticon-saved-grid').innerHTML = items.map(item => `<div class="emoticon-card"><button class="emoticon-send" data-send-emoticon="${esc(item.id)}" aria-label="发送表情 ${esc(item.name)}"><img src="${esc(stickerURL(item))}" alt="${esc(item.name)}"></button><button class="emoticon-remove" data-remove-emoticon="${esc(item.id)}" aria-label="删除表情 ${esc(item.name)}">移除</button></div>`).join('') || '<p class="dialogcopy">还没有收藏的表情。可从相册添加，也可把聊天图片添加到表情。</p>';
      $('dialogcontent').querySelectorAll('[data-send-emoticon]').forEach(button => { button.onclick = () => run(async () => { if (!valid()) return; const item = items.find(value => value.id === button.dataset.sendEmoticon); if (item) { button.disabled = true; await sendEmoticon(item,id); } }); });
      $('dialogcontent').querySelectorAll('[data-remove-emoticon]').forEach(button => { button.onclick = () => run(async () => { if (!valid()) return; button.disabled = true; const itemId = button.dataset.removeEmoticon; await library.remove(itemId); if (!valid()) return; const url = stickerPreviewURLs.get(itemId); if (url) revokeMediaURL(url); stickerPreviewURLs.delete(itemId); await openEmoticons('saved'); }); });
      if (library.skipped) $('emoticon-error').textContent = '有表情无法解锁，已跳过显示，原加密记录仍保留。';
    } catch (error) { if (valid()) $('emoticon-error').textContent = error.message; }
  }
  function fileMarkup(file,message) {
    if (message?.legacy) {
      const url = safeURL(file?.url,'/api/files/'); if (!url) return `<span>[旧版附件不可用] ${esc(file?.name)}</span>`;
      return `<button class="file-download" type="button" data-file-message="${esc(message.id)}"><div class="filebubble">${icon('file')}<div><strong>${esc(file.name)}</strong><small>${esc(bytes(file.size))} · 下载旧版未加密附件</small></div></div></button>`;
    }
    if (message?._decrypted && !message.pending && file.format!=='pgp-chunks-v1' && rasterCandidate(file)) return `<div class="message-photo" data-inline-image="${esc(message.id)}"><button type="button" class="message-photo-open" data-show-image="${esc(message.id)}" aria-label="查看图片 ${esc(file.name)}"><span class="message-photo-loading">正在解密图片…</span><img class="message-inline-image" alt="${esc(file.name)}" hidden></button><div class="message-photo-tools"><button type="button" data-add-sticker="${esc(message.id)}">添加到表情</button><button type="button" data-file-message="${esc(message.id)}">保存图片</button></div></div>`;
    return `<button class="file-download" type="button" data-file-message="${esc(message?.id || '')}" ${!message || message.pending ? 'disabled' : ''}><div class="filebubble">${icon('file')}<div><strong>${esc(file.name)}</strong><small>${esc(bytes(file.size))} · 解密并下载</small></div></div></button>`;
  }
  async function downloadAttachment(id,onProgress) {
    const message = [...messages.values()].flat().find(m => m.id === id); if (!message?.file || !cryptoBox?.ready) throw new Error('请先解锁并加载这条消息。');
    const box = cryptoBox, generation = epoch, vault = vaultVersion, controller = new AbortController(); transfers.add(controller);
    try {
      if(message.file.format==='pgp-chunks-v1') {
        if(!message._decrypted||message.decryptError)throw new Error('请先验证这条附件消息。');
        const sink=await openFileSink({name:message.file.name,mime:message.file.mime,size:message.file.size,signal:controller.signal});
        if(!sink)return;
        try {await downloadChunkedAttachment({box,api,chat:chat(message.chatId),message:message._wire||message,signal:controller.signal,sink,onProgress});}
        catch(error){await sink.abort().catch(()=>{});throw error;}
        if(generation===epoch&&vault===vaultVersion&&box===cryptoBox&&box.ready)toast('附件已验证并保存。');
        return;
      }
      const response = await fetch(`/api/files/${encodeURIComponent(message.file.id)}`,{credentials:'same-origin',headers:{'X-Yueti-User':user.id},cache:'no-store',signal:controller.signal});
      if (!response.ok) throw new Error('附件下载失败或已无权访问。');
      const reader = response.body.getReader(), chunks = []; let length = 0;
      while (true) { const {value,done} = await reader.read(); if (done) break; length += value.byteLength; if (length > 25 * 1024 * 1024) { await reader.cancel(); throw new Error('附件超过允许的加密大小。'); } chunks.push(value); }
      const ciphertext = new Uint8Array(length); let position = 0; for (const chunk of chunks) { ciphertext.set(chunk,position); position += chunk.length; }
      if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box.ready) return;
      const result = message.legacy ? {bytes:ciphertext,name:message.file.name} : await box.decryptAttachment(chat(message.chatId),message._wire || message,ciphertext);
      if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box.ready) return;
      await saveBytes(result.bytes,result.name,'application/octet-stream');
    } finally { transfers.delete(controller); }
  }
  function bindDownloads(root) {
    root.querySelectorAll('[data-file-message]').forEach(button => { button.onclick = () => run(async () => { button.disabled = true;const label=button.querySelector('small'),text=label?.textContent;try { await downloadAttachment(button.dataset.fileMessage,progress=>{if(label?.isConnected)label.textContent=`正在解密保存 ${bytes(progress.loaded)} / ${bytes(progress.total)}`;}); } finally { if (button.isConnected) button.disabled = false;if(label?.isConnected)label.textContent=text; } }); });
    root.querySelectorAll('[data-inline-image]').forEach(element => {
      if (element.dataset.previewStarted) return; element.dataset.previewStarted = 'true';
      run(async () => { try { const image = await imageAttachment(element.dataset.inlineImage); if (!element.isConnected || !cryptoBox?.ready) return; const img = element.querySelector('img'), loading = element.querySelector('.message-photo-loading'), log = $('messages');
        const ready = () => { if (!element.isConnected || !cryptoBox?.ready) return; const viewport = captureMessageViewport(log); img.hidden = false; loading.hidden = true; if (log.contains(element)) restoreMessageViewport(log,viewport); };
        img.onload = ready; img.onerror = () => { const viewport = captureMessageViewport(log); img.hidden = true; loading.hidden = false; loading.textContent = '图片无法显示，可保存原文件。'; if (log.contains(element)) restoreMessageViewport(log,viewport); }; if (img.getAttribute('src') !== image.url) img.src = image.url; if (img.complete && img.naturalWidth) ready();
      } catch (error) { if (element.isConnected && cryptoBox?.ready) element.querySelector('.message-photo-loading').textContent = `图片暂未显示：${error.message}`; } });
    });
    root.querySelectorAll('[data-show-image]').forEach(button => { button.onclick = () => run(async () => { const box = cryptoBox, generation = epoch, vault = vaultVersion, image = await imageAttachment(button.dataset.showImage); if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box?.ready) return; openDialog('查看图片',`<img class="message-image-full" src="${esc(image.url)}" alt="${esc(image.name)}">`); }); });
    root.querySelectorAll('[data-add-sticker]').forEach(button => { button.onclick = () => run(async () => { button.disabled = true; const box = cryptoBox, generation = epoch, vault = vaultVersion; try { const image = await imageAttachment(button.dataset.addSticker), prepared = await prepareStickerBytes(image.bytes,image.mime); if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box?.ready) return; const result = await emoticonLibrary().add(prepared.bytes,image.name); if (generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready) toast(result.alreadySaved ? '这张图片已经在我的表情里。' : '已添加到我的表情，点击笑脸即可找到。'); } finally { if (button.isConnected) button.disabled = false; } }); });
  }
  function captureMessageViewport(box) {
    const top = box.getBoundingClientRect().top, node = [...box.querySelectorAll('.msg')].find(item => item.getBoundingClientRect().bottom > top + 1);
    return {node,offset:node ? node.getBoundingClientRect().top - top : 0,top:box.scrollTop,height:box.scrollHeight,clientHeight:box.clientHeight,nearBottom:box.scrollHeight - box.scrollTop - box.clientHeight < 72};
  }
  function restoreMessageViewport(box,view,{follow = false,prepend = false} = {}) {
    if (follow || view.nearBottom && (box.scrollHeight !== view.height || box.clientHeight !== view.clientHeight) && !prepend) { if (box.scrollHeight - box.clientHeight - box.scrollTop > 1) box.scrollTop = box.scrollHeight; }
    else if (view.node?.isConnected && box.contains(view.node)) { const delta = view.node.getBoundingClientRect().top - box.getBoundingClientRect().top - view.offset; if (Math.abs(delta) > .5) box.scrollTop += delta; }
    else if (prepend) box.scrollTop = view.top + box.scrollHeight - view.height;
    else if (Math.abs(box.scrollTop - view.top) > .5) box.scrollTop = view.top;
  }
  function reconcileMessageRows(box,markup) {
    const template = document.createElement('template'); template.innerHTML = markup;
    const previous = new Map([...box.children].filter(node => node.hasAttribute('data-message-key')).map(node => [node.dataset.messageKey,node])); let cursor = box.firstChild;
    for (const next of [...template.content.childNodes]) {
      const key = next.nodeType === 1 ? next.dataset.messageKey : null, old = key ? previous.get(key) : null;
      let item = old || next;
      if (old?.classList.contains('msg') && next.classList.contains('msg')) {
        old.className = next.className; old.dataset.message = next.dataset.message; old.dataset.clientId = next.dataset.clientId;
        for (const selector of ['.avatar','.msgmeta','.bubble','.msgactions']) { const target = old.querySelector(selector), source = next.querySelector(selector); if (target && source && (selector !== '.msgactions' || stableHTML.get(target)?.html !== source.innerHTML)) setStableHTML(target,source.innerHTML); }
      } else if (old && old.outerHTML !== next.outerHTML) item = next;
      if (item === next && item.nodeType === 1 && item.classList.contains('msg')) for (const node of item.querySelectorAll('.avatar,.msgmeta,.bubble,.msgactions')) stableHTML.set(node,{html:node.innerHTML,first:node.firstChild,last:node.lastChild});
      if (item !== cursor) box.insertBefore(item,cursor); else cursor = cursor.nextSibling;
    }
    while (cursor) { const next = cursor.nextSibling; cursor.remove(); cursor = next; }
  }
  function updateNewMessagesButton() {
    const button = $('new-messages'); if (!button) return;
    if (!user || !cryptoBox?.ready || !$('messages').querySelector('.msg') || $('messages').scrollHeight - $('messages').scrollTop - $('messages').clientHeight < 72) button.hidden = true;
  }
  function renderMessages(scroll = false,prepend = false) {
    if (!current || !user) return;
    if (!cryptoBox?.ready) { showLocked(); return; }
    const id = current, c = chat(id), box = $('messages'), view = captureMessageViewport(box), changedChat = box.dataset.renderedChat !== id;
    const priorKeys = new Set([...box.querySelectorAll('.msg')].map(node => node.dataset.messageKey)); box.dataset.renderedChat = id;
    const list = messages.get(id) || [], queued = pending.filter(p => p.chatId === id);
    const all = [...list,...queued.map(p => ({id:`pending:${p.clientId}`,clientId:p.clientId,chatId:id,senderId:user.id,text:p.text,createdAt:p.createdAt,quote:p.quote,file:p.file,kind:p.kind,ai:p.ai,pending:p}))];
    const messageKey = m => m.clientId ? `client:${m.senderId}:${m.clientId}` : `message:${m.id}`, newRows = all.some(m => !priorKeys.has(messageKey(m)));
    reconcileMessageRows(box,(hasMore.get(id) ? '<button class="load-earlier" id="load-earlier" data-message-key="earlier">查看更早的消息</button>' : '') + (all.length ? all.map(m => {
      const p = person(m.senderId,c), mine = m.senderId === user.id && m.kind !== 'ai-result', ai = m.senderId === 'ai' || m.kind === 'ai-result';
      const status = m.pending ? m.pending.status !== 'failed' ? m.pending.progress ? `上传 ${bytes(m.pending.progress.loaded)} / ${bytes(m.pending.progress.total)}` : '正在发送…' : m.pending.error || '发送失败' : m.aiStatus === 'generating' ? '山岚正在思考…' : m.aiStatus === 'failed' ? 'AI 回复失败' : m.aiStatus === 'stopped' ? '已停止生成' : mine ? '已发送' : '';
      const content = m.decryptError ? `<div class="decrypt-error">无法验证或解密这条消息：${esc(m.decryptError)}</div>` : `${m.quote ? `<div class="inlinequote">${esc(m.quote.senderName)}：${esc(m.quote.text?.slice(0,160))}</div>` : ''}${m.text ? `<div>${esc(m.text)}</div>` : ''}${m.file ? fileMarkup(m.file,m) : ''}${m.pending?.fileName && !m.file ? `<div class="filecaption">${icon('file')}${esc(m.pending.fileName)}</div>` : ''}${!m.text && !m.file && ai ? '<span>…</span>' : ''}`;
      return `<article class="msg ${mine ? 'mine' : ''} ${ai ? 'ai' : ''}" data-message="${esc(m.id)}" data-client-id="${esc(m.clientId || '')}" data-message-key="${esc(messageKey(m))}"><div class="avatar ${ai ? 'ai' : ''}">${ai ? icon('ai') : avatar(p)}</div><div class="msgbody"><div class="msgmeta"><strong>${m.kind === 'ai-result' ? `山岚 · ${esc(p.displayName)} 分享` : esc(p.displayName)}</strong>${ai ? '<span class="smalltag">AI</span>' : ''}${m.legacy ? '<span class="smalltag legacy-tag">旧版未加密</span>' : ''}<time datetime="${esc(m.createdAt)}" title="${esc(new Date(m.createdAt).toLocaleString('zh-CN'))}">${esc(time(m.createdAt))}</time></div><div class="bubble">${content}</div><div class="msgactions">${status ? `<span class="msgstate ${m.pending?.status === 'failed' || m.aiStatus === 'failed' ? 'failed' : ''}">${esc(status)}</span>` : ''}${m.pending ? m.pending.status === 'failed' ? `<button data-retry="${esc(m.clientId)}" class="failed">重试</button><button data-discard="${esc(m.clientId)}">取消</button>` : `<button disabled>回复</button><button disabled>收藏</button>${isAI(c) && m.text ? '<button disabled>不让 AI 参考</button>' : ''}` : !m.decryptError ? `<button data-reply="${esc(m.id)}">回复</button><button data-save="${esc(m.id)}">${saved.has(m.id) ? '已收藏' : '收藏'}</button>` : ''}</div></div></article>`;
    }).join('') : `<div class="live-empty" data-message-key="empty"><strong>${c?.kind === 'notes' ? '留下一点想法' : '开始聊聊吧'}</strong><span>${c?.kind === 'ai' ? '此设备直接连接管理员配置的模型。' : '文字、图片和文件，都可以从这里发送。'}</span></div>`));
    if (isAI(c)) {
      const pref = aiPreference(id);
      box.querySelectorAll('.msg[data-message]').forEach(article => {
        const m = list.find(row => row.id === article.dataset.message);
        if (!m?._decrypted || m.decryptError || !m.text || m.seq <= pref.cutoffSeq) return;
        const excluded = pref.excludedIds.includes(m.id), button = article.querySelector('[data-ai-exclude]') || document.createElement('button');
        button.dataset.aiExclude = m.id; button.textContent = excluded ? '已排除 · 恢复 AI 参考' : '不让 AI 参考'; button.setAttribute('aria-pressed',String(excluded));
        button.onclick = () => { const updated = aiPreference(id), ids = new Set(updated.excludedIds); ids.has(m.id) ? ids.delete(m.id) : ids.add(m.id); saveAIPreference(id,{...updated,excludedIds:[...ids]}); renderMessages(); };
        if (!button.parentNode) article.querySelector('.msgactions').append(button);
      });
    }
    const aiState = aiStates.get(id);
    if (aiState) {
      const panel = document.createElement('div'); panel.className = `ai-request-state ${aiState.state === 'error' ? 'failed' : ''}`; panel.setAttribute('role',aiState.state === 'error' ? 'alert' : 'status');
      panel.innerHTML = `<span>${esc(aiState.state === 'error' ? 'AI 回复未完成：' : '')}${esc(aiState.message)}</span>${aiState.state === 'error' && aiState.retry ? '<button id="ai-retry-request" class="secondarybtn">重试 AI 回复</button>' : ''}`;
      const diagnostics = safeAIDiagnostics(aiState.diagnostics);
      if (aiState.state === 'error' && diagnostics) {
        const text = `${diagnostics.code}${diagnostics.upstreamStatus ? ` · 模型接口 HTTP ${diagnostics.upstreamStatus}` : ''}${diagnostics.requestId ? `\n请求编号：${diagnostics.requestId}` : ''}`;
        panel.insertAdjacentHTML('beforeend',`<details class="ai-diagnostics"><summary>诊断信息</summary><code>${esc(text)}</code></details>`);
      }
      box.append(panel);
      if ($('ai-retry-request')) $('ai-retry-request').onclick = () => run(async () => {
        if (aiJobs.has(id) || aiPreparing.has(id) || !isAI(chat(id)) || chat(id).context === 'none') return;
        const oldTrigger = (messages.get(id) || []).find(m => m.clientId === aiState.retry.clientId), generation = epoch;
        if (!oldTrigger) { toast('原提问暂未加载，请重新打开会话后发送新问题。'); return; }
        const parsed = parseAIInvocation(aiState.retry.text,{direct:chat(id).kind === 'ai'});
        const historyCount = chat(id).context === 'mention' ? 0 : aiState.retry.historyCount ?? parsed.historyCount;
        aiPreparing.add(id); renderCompose();
        try {
          if (historyCount && !await prepareAIHistory(id,historyCount,oldTrigger.seq)) return;
          if (generation !== epoch || !cryptoBox?.ready || chat(id)?.context === 'none') return;
          const context = aiContext(id,aiState.retry.prompt || parsed.prompt,aiPreference(id),{historyCount,beforeSeq:oldTrigger.seq,currentClientId:aiState.retry.clientId});
          await relayAI(id,context.messages,null,{...aiState.retry,historyCount});
        } finally { aiPreparing.delete(id); if (current === id) renderCompose(); }
      });
    }
    if ($('load-earlier')) $('load-earlier').onclick = () => run(async () => { $('load-earlier').disabled = true; await fetchMessages(id,false,list[0]?.seq); });
    bindDownloads(box);
    for(const item of queued.filter(item=>item.fileName&&item.status==='sending'&&outgoingJobs.has(item.clientId))) {
      const row=[...box.querySelectorAll('[data-client-id]')].find(row=>row.dataset.clientId===item.clientId),actions=row?.querySelector('.msgactions');
      if(actions&&!actions.querySelector('[data-stop-upload]')) {const button=document.createElement('button');button.type='button';button.dataset.stopUpload=item.clientId;button.textContent='停止上传';button.onclick=()=>{outgoingJobs.get(item.clientId)?.abort();item.status='failed';item.error='上传已停止，可重试发送。';delete item.progress;storeState();renderMessages();};actions.append(button);}
    }
    box.querySelectorAll('[data-reply]').forEach(b => { b.onclick = () => { const m = list.find(m => m.id === b.dataset.reply); if (!m) return; quotes[id] = {id:m.id,senderName:person(m.senderId,c).displayName,text:m.text || m.file?.name || ''}; renderCompose(); $('input').focus(); }; });
    box.querySelectorAll('[data-save]').forEach(b => { b.onclick = () => run(async () => { b.disabled = true; const mid = b.dataset.save, remove = saved.has(mid); await api(`/api/messages/${encodeURIComponent(mid)}/saved`,{method:remove ? 'DELETE' : 'PUT'}); remove ? saved.delete(mid) : saved.add(mid); if (current === id) renderMessages(); }); });
    box.querySelectorAll('[data-retry]').forEach(b => { b.onclick = () => { const p = pending.find(p => p.clientId === b.dataset.retry); if (p?.fileName && !p.fileId && !rawPending.has(p.clientId)) { retryAttachmentId = p.clientId; $('fileinput').value = ''; $('fileinput').click(); toast('请重新选择未上传成功的原附件。'); } else if (p) run(() => deliver(p)); }; });
    box.querySelectorAll('[data-discard]').forEach(b => { b.onclick = () => { rawPending.delete(b.dataset.discard); pending = pending.filter(p => p.clientId !== b.dataset.discard); storeState(); renderMessages(); }; });
    const follow = changedChat || scroll === 'open' || scroll === 'send' || view.nearBottom && newRows && !prepend;
    restoreMessageViewport(box,view,{follow,prepend});
    let indicator = $('new-messages'); if (!indicator) { indicator = document.createElement('button'); indicator.id = 'new-messages'; indicator.type = 'button'; indicator.className = 'new-messages secondarybtn'; indicator.textContent = '新消息 ↓'; indicator.hidden = true; $('conversation').insertBefore(indicator,$('messages')); indicator.onclick = () => { box.scrollTop = box.scrollHeight; indicator.hidden = true; markRead(); }; box.addEventListener('scroll',updateNewMessagesButton,{passive:true}); }
    if (changedChat || follow || prepend) indicator.hidden = true; else if (newRows) indicator.hidden = false;
    updateNewMessagesButton();
  }
  const readCursors = new Map();
  function markRead() {
    const id = current, list = messages.get(id), last = list?.at(-1); if (!user || !last || document.visibilityState !== 'visible') return;
    if (window.innerWidth <= 720 && !$('app').classList.contains('mobile-chat')) return;
    if ($('messages').scrollHeight - $('messages').clientHeight - $('messages').scrollTop > 100) return;
    const key = `${user.id}:${id}`; if ((readCursors.get(key) || 0) >= last.seq) return;
    readCursors.set(key,last.seq);
    api(`/api/chats/${encodeURIComponent(id)}/read`,{method:'POST',body:{lastSeq:last.seq}}).then(() => { const c = chat(id); if (c) { c.unread = 0; renderList(); } }).catch(() => { readCursors.delete(key); });
  }
  function resizeComposer() {
    const input = $('input'), mobile = window.innerWidth <= 720, attach = $('attach');
    attach.setAttribute('aria-label',mobile ? '更多聊天功能' : '选择附件'); attach.title = mobile ? '更多聊天功能' : '选择附件'; attach.innerHTML = icon(mobile ? 'plus' : 'attach');
    if (!input.getClientRects().length) return;
    const log = $('messages'), view = captureMessageViewport(log), priorHeight = input.style.height;
    input.style.height = '0px'; const style = getComputedStyle(input), extra = parseFloat(style.borderTopWidth) + parseFloat(style.borderBottomWidth), height = Math.max(parseFloat(style.minHeight) || 0,Math.min(input.scrollHeight + extra,parseFloat(style.maxHeight) || (mobile ? 108 : 120)));
    input.style.height = height + 'px'; if (input.style.height !== priorHeight) restoreMessageViewport(log,view);
  }
  function renderCompose() {
    if (securityTransition) { for (const id of ['input','send','mention','attach','ai-search','ai-draw']) if ($(id)) $(id).disabled = true; return; }
    renderMention();
    let searchButton = $('ai-search'); if (!searchButton) { searchButton = document.createElement('button'); searchButton.id = 'ai-search'; searchButton.type = 'button'; searchButton.className = 'mention ai-search'; searchButton.innerHTML = `${icon('search')}联网搜索`; $('mention').parentNode.append(searchButton); searchButton.onpointerdown = event => { if (event.isPrimary && event.button === 0 && document.activeElement === $('input')) event.preventDefault(); }; searchButton.onclick = () => { const id = current; if (searchButton.disabled || securityTransition || !id || !cryptoBox?.ready) return; const pref = aiPreference(id); saveAIPreference(id,{...pref,search:!pref.search}); renderCompose(); run(persistEncrypted); $('input').focus({preventScroll:true}); }; }
    searchButton.hidden = !isAI(chat()) || chat().context === 'none'; searchButton.disabled = !cryptoBox?.ready || chatSecurityErrors.has(current) || friendshipBlocked(chat()) || aiJobs.has(current) || aiPreparing.has(current); searchButton.setAttribute('aria-pressed',String(aiPreference(current).search)); searchButton.title = '仅将本次问题交给搜索服务，不搜索聊天前文';
    let drawButton=$('ai-draw');if(!drawButton){drawButton=document.createElement('button');drawButton.id='ai-draw';drawButton.type='button';drawButton.className='mention ai-draw';drawButton.innerHTML=`${icon('mountain')}画一张`;searchButton.after(drawButton);drawButton.onpointerdown=event=>{if(event.isPrimary&&event.button===0&&document.activeElement===$('input'))event.preventDefault();};drawButton.onclick=insertDrawingCommand;}
    drawButton.hidden=searchButton.hidden;drawButton.disabled=searchButton.disabled;drawButton.title='描述想画的内容，发送后由生图模型绘制';
    if (!cryptoBox?.ready) { $('send').disabled = true; return; }
    if (chatSecurityErrors.has(current) || friendshipBlocked(chat())) { $('send').disabled = true; return; }
    if (!current) return; const quote = quotes[current], file = attachments.get(current), generating = aiJobs.has(current), preparing = aiPreparing.has(current);
    $('quote').hidden = !quote; $('quotetext').textContent = quote ? `回复 ${quote.senderName}：${quote.text}` : '';
    $('attachment').hidden = !file; $('attachmentname').textContent = file ? `${file.name} · ${bytes(file.size)}` : '';
    $('stop').hidden = !generating; $('send').hidden = false; $('send').disabled = preparing || generating || (!$('input').value.trim() && !file); resizeComposer();
  }
  async function deliver(item,{signal} = {}) {
    if (!user || !cryptoBox?.ready || securityTransition || signal?.aborted || item.status === 'sending') return false; const generation = epoch, vault = vaultVersion, box = cryptoBox;
    if (chatSecurityErrors.has(item.chatId)) { item.status = 'failed'; item.error = '加密成员尚未完成验证，请先重新验证此会话。'; storeState(); if (current === item.chatId) renderMessages(); return; }
    if (friendshipBlocked(chat(item.chatId))) { item.status = 'failed'; item.error = '请先添加好友，申请通过后再发送。'; storeState(); if (current === item.chatId) renderMessages(); return; }
    const controller = new AbortController(), cancel = () => controller.abort(); signal?.addEventListener('abort',cancel,{once:true}); if (signal?.aborted) controller.abort(); transfers.add(controller);outgoingJobs.set(item.clientId,controller);
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && !securityTransition && !controller.signal.aborted;
    item.status = 'sending'; item.error = ''; storeState(); if (current === item.chatId) renderMessages();
    try {
      if (item.fileName && !item.fileId) {
        const file = rawPending.get(item.clientId); if (!file) throw new Error('请选择原附件后重试。');
        if(file.size>20*1024*1024) {
          const uploaded=await uploadAttachment({box,api,chat:chat(item.chatId),file,approveTrust,signal:controller.signal,onProgress:progress=>{if(valid()){item.progress={loaded:progress.loaded,total:progress.total};if(current===item.chatId)renderMessages();}}});
          if(!valid())return;item.fileId=uploaded.file.id;item.file=uploaded.meta;
        } else {
          const encrypted = await box.encryptAttachment(chat(item.chatId),file,approveTrust);
          try {
            if (!valid()) return;
            const uploaded = await api(`/api/files?chatId=${encodeURIComponent(item.chatId)}&encrypted=1`,{method:'POST',raw:true,body:encrypted.bytes,headers:{'Content-Type':'application/octet-stream'},signal:controller.signal});
            if (!valid()) return;
            item.fileId = uploaded.file.id; item.file = {...encrypted.meta,id:uploaded.file.id};
          } finally {encrypted.bytes.fill(0);}
        }
        delete item.progress;rawPending.delete(item.clientId);await persistEncrypted();
      }
      if (!item.envelope) item.envelope = await box.encrypt(chat(item.chatId),{text:item.text,sentAt:item.createdAt,quote:item.quote || null,file:item.file || null,kind:item.kind || 'text',ai:item.ai || null},item.clientId,approveTrust);
      if (!valid()) return;
      await persistEncrypted();
      if (!valid()) return;
      const result = await api(`/api/chats/${encodeURIComponent(item.chatId)}/messages`,{method:'POST',body:{clientId:item.clientId,envelope:item.envelope,...(item.fileId ? {fileId:item.fileId} : {})},signal:controller.signal});
      if (!valid()) return;
      const message = await decodedMessage(chat(item.chatId),result.message);
      if (!valid()) return;
      if (!message._decrypted || message._wire?.envelope?.ciphertext !== item.envelope.ciphertext) throw new Error('服务器返回的消息未通过验证，保留原密文供安全重试。');
      const list = messages.get(item.chatId) || []; if (!list.some(m => m.id === message.id)) list.push(message); list.sort((a,b) => a.seq - b.seq); messages.set(item.chatId,list);
      pending = pending.filter(p => p.clientId !== item.clientId); rawPending.delete(item.clientId); storeState();
      if (current === item.chatId) { renderMessages(); renderCompose(); markRead(); }
      queueRefresh();
      return true;
    } catch (e) { if (!valid() || e.stale) return false; item.status = 'failed'; item.error = e.message; storeState(); if (current === item.chatId) renderMessages(); if (!e.status) setConnection(false); }
    finally { signal?.removeEventListener('abort',cancel); transfers.delete(controller);if(outgoingJobs.get(item.clientId)===controller)outgoingJobs.delete(item.clientId); }
  }
  function makeOutgoing(id,text,file,quote,extra = {}) {
    const item = {clientId:uid(),chatId:id,text,createdAt:new Date().toISOString(),status:'queued',...(quote ? {quote} : {}),...(file ? {fileName:file.name,fileSize:file.size} : {}),...extra};
    if (file) rawPending.set(item.clientId,file); pending.push(item); storeState(); return item;
  }
  function consumeComposer(id) { drafts[id] = ''; delete quotes[id]; attachments.delete(id); if (current === id) { $('input').value = ''; renderCompose(); } storeState(); }
  function aiPreference(id) { return normalizeAIPreferences(aiPreferences[id]); }
  function saveAIPreference(id,value) { aiPreferences[id] = normalizeAIPreferences(value); storeState(); }
  function memoryLibrary() {
    if(!cryptoBox?.ready)throw new Error('请先解锁聊天。');
    if(aiMemoryBox!==cryptoBox) {aiMemoryStore?.dispose();aiMemoryBox=cryptoBox;aiMemoryStore=new EncryptedAIMemory({box:cryptoBox,api});}
    return aiMemoryStore;
  }
  function updatePrivateMemory(id,credential,prompt,answer,exchangeId,snapshot) {
    if(chat(id)?.kind!=='ai'||!snapshot?.enabled||!prompt?.trim())return;
    const store=memoryLibrary(),box=cryptoBox,generation=epoch,vault=vaultVersion,controller=new AbortController();
    memoryUpdates.add(controller);transfers.add(controller);
    const valid=()=>box===cryptoBox&&box.ready&&generation===epoch&&vault===vaultVersion&&!controller.signal.aborted;
    (async()=>{
      const result=await connectAI(credential,memoryExtractionMessages({userText:prompt,assistantText:answer,chatKind:'ai'}),{signal:controller.signal,systemExtra:MEMORY_EXTRACTION_INSTRUCTION});
      if(!valid())return;
      const facts=parseExtractedFacts(result.text,{userText:prompt,chatKind:'ai'});
      if(facts.length)await store.remember(facts,{chatKind:'ai',exchangeId,expectedRevision:snapshot.revision,signal:controller.signal});
    })().catch(error=>{if(valid()&&!/冲突|更新|过期|取消|变化/.test(error.message))toast('本次长期记忆未能更新，聊天回复已保留。');}).finally(()=>{memoryUpdates.delete(controller);transfers.delete(controller);});
  }
  async function memorySettings() {
    if(!cryptoBox?.ready) {await unlockAndRefresh();if(!cryptoBox?.ready)return;}
    const store=memoryLibrary(),box=cryptoBox,generation=epoch,controller=new AbortController();transfers.add(controller);
    const version=openDialog('山岚 · 关于你的记忆','<p class="dialogbusy">正在解锁你的记忆…</p>');
    const valid=()=>dialogCurrent(version)&&box===cryptoBox&&box.ready&&generation===epoch&&!controller.signal.aborted;
    sensitiveDialogCleanup=()=>{controller.abort();transfers.delete(controller);};
    async function paint() {
      const memory=await store.load({signal:controller.signal});if(!valid())return;
      $('dialogcontent').innerHTML=`<p class="dialogcopy">山岚会从你和它的单独私聊中记住稳定的偏好与个人信息，帮助以后继续聊。记忆只用于你的 AI 私聊，不带入好友或群聊；在本机解密，参与回答时交给模型服务商。</p><label class="toggleline">长期记忆<input id="memory-enabled" type="checkbox" ${memory.enabled?'checked':''}></label><p class="dialogcopy">${memory.enabled?'已开启 · 新的私聊回复后会整理记忆':'已暂停 · 不读取或新增记忆，已有条目保留'}。记忆会加密同步到登录同一账户的设备。</p><form id="memory-add-form" class="account-form"><label>希望山岚记住的事<textarea id="memory-new" maxlength="360" rows="2" placeholder="例如：我喜欢简短直接的回答" required></textarea></label><button class="secondarybtn">记住这件事</button></form><div class="memory-list">${memory.entries.map(entry=>`<form class="memory-item account-form" data-memory-id="${esc(entry.id)}"><label>${entry.source==='manual'?'你写下的记忆':'私聊中记住的事'}<textarea maxlength="360" rows="2" required>${esc(entry.text)}</textarea></label><div class="profile-avatar-tools"><button class="secondarybtn">保存修改</button><button type="button" class="secondarybtn" data-memory-remove="${esc(entry.id)}">忘记</button></div></form>`).join('')||'<p class="dialogcopy">还没有记住的事。你可以在私聊中介绍自己，也可以在这里直接添加。</p>'}</div><p id="memory-error" class="form-error" role="alert"></p><details class="memory-clear"><summary>清空所有记忆</summary><p class="dialogcopy">清空后山岚将不再参考这些记忆，聊天记录保留。</p><button id="memory-clear" class="secondarybtn">确认清空记忆</button></details>`;
      $('memory-error').insertAdjacentHTML('afterend','<button id="memory-reload" type="button" class="secondarybtn" hidden>重新载入记忆</button>');
      $('memory-reload').onclick=async()=>{if(!valid())return;const button=$('memory-reload');button.disabled=true;try{await paint();}catch(error){if(valid()){$('memory-error').textContent=error.message;button.disabled=false;}}};
      const change=async fn=>{
        if(!valid())return;
        for(const task of memoryUpdates)task.abort();memoryUpdates.clear();
        $('dialogcontent').querySelectorAll('button,input,textarea').forEach(el=>el.disabled=true);
        try{await fn();if(valid())await paint();}
        catch(error){if(valid()){$('memory-error').textContent=error.message;$('memory-reload').hidden=false;$('dialogcontent').querySelectorAll('button,input,textarea').forEach(el=>el.disabled=false);}}
      };
      $('memory-enabled').onchange=event=>change(()=>store.setEnabled(event.target.checked,{signal:controller.signal}));
      $('memory-add-form').onsubmit=event=>{event.preventDefault();const value=$('memory-new').value;return change(()=>store.add(value,{signal:controller.signal}));};
      $('dialogcontent').querySelectorAll('[data-memory-id]').forEach(form=>form.onsubmit=event=>{event.preventDefault();const text=form.querySelector('textarea').value;return change(()=>store.edit(form.dataset.memoryId,text,{signal:controller.signal}));});
      $('dialogcontent').querySelectorAll('[data-memory-remove]').forEach(button=>button.onclick=()=>change(()=>store.remove(button.dataset.memoryRemove,{signal:controller.signal})));
      $('memory-clear').onclick=()=>change(()=>store.clear({signal:controller.signal}));
    }
    try{await paint();}catch(error){if(valid())$('dialogcontent').innerHTML=`<p class="form-error">${esc(error.message)}</p>`;}
  }
  function aiHistory(id) { return (messages.get(id) || []).filter(isShareableAIMessage).slice(-200); }
  async function prepareAIHistory(id,count = 199,beforeSeq = null) {
    const generation = epoch, vault = vaultVersion, box = cryptoBox;
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box?.ready;
    // A retry fetches directly before its original trigger, never around new messages.
    await fetchMessages(id,false,beforeSeq);
    for (let page = 0; page < 4 && valid() && hasMore.get(id); page++) {
      const rows = (messages.get(id) || []).filter(m => !beforeSeq || m.seq < beforeSeq);
      if (rows.length >= count) break;
      const first = rows[0]?.seq; if (!first || first <= aiPreference(id).cutoffSeq) break;
      await fetchMessages(id,false,first);
      if ((messages.get(id) || [])[0]?.seq >= first) break;
    }
    return valid();
  }
  function aiContext(id,text,pref = aiPreference(id),extra = {}) {
    const c = chat(id), rows = c?.context === 'mention' ? [] : (messages.get(id) || []);
    return buildAIContext(rows,text,pref,{chatId:id,...(['group','direct'].includes(c?.kind) ? {speakerName:m => person(m.senderId,c).displayName,currentSpeakerName:user.displayName} : {}),...extra});
  }
  async function showAIContext(id) {
    if (!cryptoBox?.ready || !isAI(chat(id))) return;
    const generation = epoch, vault = vaultVersion, box = cryptoBox;
    if (!await prepareAIHistory(id)) return;
    const pref = aiPreference(id), rows = aiHistory(id);
    openDialog('山岚 · 前文与隐私',`<p class="dialogcopy">@山岚 默认只读取当前问题；@山岚 /10 或 /10 会读取前 10 条加当前问题，条数可选 1 至 199，不再弹分享确认。AI 私聊中不加命令时继续参考可用前文。先确定最近 N 条范围，再排除你取消勾选的消息、错误和不可解密记录，不会补入更早的聊天。最多 48,000 字符。前文选择在此账户的本机加密保存。你与山岚单独私聊的长期记忆可在“设置 → 山岚的长期记忆”查看、修改和删除；好友和群聊不带入私人记忆。</p><p class="dialogcopy">你选定的问题与前文会从此设备直接发送给配置的模型服务商，聊天服务器只保存加密配置，不接收 AI 原文。回复在本机加密后才存入聊天。附件不交给模型。联网搜索尚未启用；仅你指定的内容会交给模型服务商。</p><div class="ai-context-tools"><button id="ai-start-new" class="secondarybtn">从下一条开始，不参考之前的聊天</button><button id="ai-restore-history" class="secondarybtn">恢复参考前文</button></div><div class="ai-history-list">${rows.map(m => `<label class="ai-context-choice"><input type="checkbox" data-context-id="${esc(m.id)}" ${!pref.excludedIds.includes(m.id) && m.seq > pref.cutoffSeq ? 'checked' : ''} ${m.seq <= pref.cutoffSeq ? 'disabled' : ''}><span><strong>${esc(m.kind === 'ai-result' ? '山岚' : person(m.senderId,chat(id)).displayName)}</strong>${esc(m.text.slice(0,600))}</span></label>`).join('') || '<p class="dialogcopy">还没有可用前文。</p>'}</div><div class="dialogactions"><button id="ai-context-save" class="sendbtn">保存设置</button></div>`);
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready;
    const save = async value => { if (!valid()) return; saveAIPreference(id,value); await persistEncrypted(); if (!valid()) return; $('dialog').close(); if (current === id) { renderHeader(); renderCompose(); renderMessages(); if ($('app').classList.contains('show-details')) renderDetails(); } };
    $('dialogcontent').querySelectorAll('.dialogcopy')[1].textContent='你选定的问题与前文直接交给模型服务商；这次提问附带的图片交给看图模型，不会自动读取其他图片。私聊会使用已开启的长期记忆，好友和群聊不会。/生图 只交付本次描述，返回图片加密后发送。联网搜索只将当前问题交给 Tavily，附件与前文不交给搜索服务。';
    $('dialogcontent').querySelector('.ai-context-tools').insertAdjacentHTML('beforebegin',`<label class="toggleline"><span>联网搜索<small class="dialogcopy">只搜索当前问题（最多 1,000 字），由设备直达 Tavily；前文与附件不交给搜索服务。</small></span><input id="ai-search-toggle" type="checkbox" ${pref.search ? 'checked' : ''}></label>`);
    const choices = () => ({...pref,search:$('ai-search-toggle').checked});
    $('ai-context-save').onclick = () => run(async () => {
      const excluded = new Set(pref.excludedIds);
      $('dialogcontent').querySelectorAll('[data-context-id]:not(:disabled)').forEach(input => input.checked ? excluded.delete(input.dataset.contextId) : excluded.add(input.dataset.contextId));
      await save({...choices(),excludedIds:[...excluded]});
    });
    $('ai-start-new').onclick = () => run(() => save({...choices(),cutoffSeq:Math.max(0,...(messages.get(id) || []).map(m => m.seq || 0))}));
    $('ai-restore-history').onclick = () => run(() => save({...choices(),cutoffSeq:0,excludedIds:[]}));
  }
  async function relayAI(id,shared,triggerItem,selection = null,mediaFile = null) {
    if (!cryptoBox?.ready || securityTransition || aiJobs.has(id)) { toast('请等待本次 AI 请求结束后再分享。'); return; }
    const generation = epoch, vault = vaultVersion, box = cryptoBox, controller = new AbortController(), pref = aiPreference(id);
    const retry = triggerItem ? {text:triggerItem.text,clientId:triggerItem.clientId,...selection} : aiStates.get(id)?.retry;
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && !controller.signal.aborted;
    let answerItems = [], credential = null, memorySnapshot = null;
    aiJobs.set(id,controller); aiStates.set(id,{state:'loading',message:'山岚正在通过此设备直连模型…',retry}); renderCompose(); if (current === id) renderMessages(true);
    try {
      if (triggerItem && !await deliver(triggerItem)) throw new Error('消息尚未发送成功，未请求 AI。请先重试发送这条消息。');
      if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box.ready || controller.signal.aborted) return;
      const authorization = await api(`/api/chats/${encodeURIComponent(id)}/ai/credential`,{method:'POST',signal:controller.signal});
      if (authorization.directOnly !== true || authorization.credential?.mode !== 'shared_direct') throw new Error('AI 配置需要更新，请联系管理员保存共享直连设置。');
      credential = await unlockSharedAIConfiguration(box,{...authorization.credential,approveTrust,approveEndpoint:details => approveAIEndpoint(details,{signal:controller.signal}),signal:controller.signal});
      if (!valid()) return;
      if (credential?.enabled !== true) throw new Error('山岚已停用，请联系管理员。');
      const operation=selection?.operation||retry?.operation||'chat',prompt=selection?.prompt||retry?.prompt||'';
      const useSearch=operation==='chat'&&(selection?.search ?? retry?.search ?? pref.search) === true;
      let memory=null;
      if(operation==='chat'&&chat(id)?.kind==='ai') {
        memorySnapshot=await memoryLibrary().load({signal:controller.signal});if(!valid())return;
        memory=relevantMemory(memorySnapshot,prompt,{chatKind:'ai'});
      }
      let modelMessages=withPrivateMemory(shared,memory,{reserve:useSearch?12400:0});
      if(useSearch) {
        const query=selection?.prompt || retry?.prompt || parseAIInvocation(triggerItem?.text || retry?.text || '',{direct:true}).prompt;
        aiStates.set(id,{state:'loading',message:'山岚正在从此设备联网搜索…',retry}); if(current===id)renderMessages();
        const result=await searchWeb(credential,query,{signal:controller.signal}); if(!valid())return;
        modelMessages=withSearchResults(modelMessages,result);
        aiStates.set(id,{state:'loading',message:'已完成搜索，山岚正在回答…',retry}); if(current===id)renderMessages();
      }
      let result,answer='',files=[];
      if(operation==='images') {
        if(!credential.image?.enabled)throw new Error('尚未配置生图模型，请管理员在山岚的模型设置中启用生图。');
        aiStates.set(id,{state:'loading',message:'山岚正在画图，完成后会加密发送…',retry});if(current===id)renderMessages();
        result=await generateImages(credential.image,prompt,{signal:controller.signal});
        if(!valid()){for(const image of result.images||[])image.bytes.fill(0);return;}
        for(const image of result.images){try{files.push(new File([image.bytes],image.name,{type:image.mime}));}finally{image.bytes.fill(0);}}
      } else {
        const imageAttached=selection?.imageAttached??retry?.imageAttached;
        let modelCredential=credential;
        if(imageAttached) {
          if(!credential.vision?.enabled)throw new Error('尚未配置看图模型，请管理员在山岚的模型设置中启用看图。');
          if(!mediaFile) {
            const original=(messages.get(id)||[]).find(m=>m.clientId===retry?.clientId);
            if(!original)throw new Error('原图片尚未加载，请打开原消息后重试。');
            const image=await imageAttachment(original.id);if(!valid())return;
            mediaFile=new File([image.bytes],image.name,{type:image.mime});
          }
          modelMessages=await prepareVisionMessage(modelMessages,mediaFile,{signal:controller.signal});if(!valid())return;
          modelCredential=credential.vision;
        }
        result=await connectAI(modelCredential,modelMessages,{signal:controller.signal,systemExtra:STICKER_INSTRUCTION});
        if(!valid())return;
        const split=splitAISticker(result.text);answer=split.text;
        if(split.stickerId) {
          const sticker=await loadDefaultSticker(split.stickerId,{signal:controller.signal,isCurrent:valid});
          try{if(!valid())return;files.push(new File([sticker.bytes],sticker.name,{type:sticker.mime}));}finally{sticker.bytes.fill(0);}
        }
      }
      if(!valid())return;
      if(!answer&&!files.length)throw new Error('AI 没有返回可用内容。');
      const extra={kind:'ai-result',ai:{requestedBy:user.id,model:String(result.model||'配置的模型')}};
      const items=answerItems=[...(answer.match(/[\s\S]{1,12000}/g)||[]).map(text=>makeOutgoing(id,text,null,null,extra)),...files.map(file=>makeOutgoing(id,'',file,null,extra))];
      await persistEncrypted();
      for (const item of items) { if (!valid()) return; if (!await deliver(item,{signal:controller.signal})) throw new Error('山岚回复已生成，但发送未完成。请在回复旁点击重试。'); }
      aiStates.delete(id);
      if(operation==='chat'&&answer&&memorySnapshot?.enabled&&valid())updatePrivateMemory(id,{...credential},prompt,answer,retry?.clientId,memorySnapshot);
    } catch (e) { if (generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready) { aiStates.set(id,{state:'error',message:controller.signal.aborted ? '本次 AI 请求已停止。' : e.message,diagnostics:safeAIDiagnostics(e.diagnostics),retry:answerItems.length||triggerItem && pending.some(p => p.clientId === triggerItem.clientId) ? null : retry}); } }
    finally {
      credential = null;
      if (controller.signal.aborted && generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready) aiStates.set(id,{state:'error',message:'本次 AI 请求已停止。',retry:answerItems.length?null:retry});
      if (controller.signal.aborted && generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && answerItems.length) {
        const ids = new Set(answerItems.map(item => item.clientId)); pending = pending.filter(item => !ids.has(item.clientId)); storeState();
      }
      if (aiJobs.get(id) === controller) aiJobs.delete(id); if (generation === epoch && current === id) { renderCompose(); renderMessages(true); }
    }
  }
  async function requestAI(id,text,file,quote,invocation) {
    if (securityTransition) return;
    if (aiJobs.has(id) || aiPreparing.has(id)) { toast('山岚正在处理，请先等待或停止。'); return; }
    if (invocation.error) { toast(invocation.error); return; }
    const generation = epoch, vault = vaultVersion, box = cryptoBox;
    const historyCount = chat(id)?.context === 'mention' ? 0 : invocation.historyCount, pref=aiPreference(id);
    if (chat(id)?.context === 'mention' && invocation.explicit && invocation.historyCount > 0) {
      toast('此会话设置为只读当前消息，请先在会话详情中允许指定前文。'); return;
    }
    // Show the outgoing message immediately, while verified history is loading.
    // Keep this exact item for retries; the context builder excludes its clientId.
    const item = makeOutgoing(id,text,file,quote); item.status='queued'; consumeComposer(id); renderMessages('send');
    const preparingState = {state:'loading',message:historyCount ? '正在读取指定前文…' : '正在准备本次提问…'};
    aiPreparing.add(id); aiStates.set(id,preparingState); renderCompose(); if (current === id) renderMessages(true);
    try { if (historyCount && !await prepareAIHistory(id,historyCount)) return; }
    catch (e) { if (generation === epoch && vault === vaultVersion && box === cryptoBox && box?.ready) { item.status='failed'; item.error='读取前文失败，请重试发送。'; storeState(); aiStates.set(id,{state:'error',message:`读取前文失败：${e.message}。消息已保留在待发送队列。`}); } return; }
    finally { aiPreparing.delete(id); if (aiStates.get(id) === preparingState) aiStates.delete(id); if (current === id) { renderCompose(); renderMessages(); } }
    if (generation !== epoch || vault !== vaultVersion || box !== cryptoBox || !box?.ready || current !== id || chat(id)?.context === 'none') return;
    const context = aiContext(id,invocation.prompt,pref,{historyCount,currentClientId:item.clientId});
    if (context.truncated) toast('前文较长，本次只保留指定范围内最近的可用内容。');
    await relayAI(id,context.messages,item,{prompt:invocation.prompt,historyCount,search:pref.search,operation:invocation.operation,imageAttached:!!file&&rasterCandidate({name:file.name,mime:file.type})},file);
  }
  $('sendform').onsubmit = event => {
    event.preventDefault(); if (!user || !chat() || !cryptoBox?.ready || securityTransition || $('input').disabled || chatSecurityErrors.has(current) || friendshipBlocked(chat())) return;
    const text = $('input').value.trim(), file = attachments.get(current); if (!text && !file) return;
    if (text.length > 12000) { toast('单条消息最多 12,000 字，请分成几条发送。'); return; }
    // Keep the IME attached to the textarea across a send. A button otherwise
    // takes focus and, once disabled by the empty composer, drops focus to body.
    $('input').focus({preventScroll:true});
    const invocation = parseAIInvocation(text || (file&&chat().kind==='ai'&&rasterCandidate({name:file.name,mime:file.type})?'请描述这张图片。':''),{direct:chat().kind === 'ai'});
    if (isAI(chat()) && chat().context !== 'none' && invocation.requested) { run(() => requestAI(current,text,file,quotes[current],invocation)); return; }
    const item = makeOutgoing(current,text,file,quotes[current]); consumeComposer(current); renderMessages('send'); run(() => deliver(item));
  };
  $('input').oninput = () => { if (current) { drafts[current] = $('input').value; storeState(); } renderCompose(); };
  for (const id of ['send','mention']) $(id).onpointerdown = event => {
    if (event.isPrimary && event.button === 0 && document.activeElement === $('input')) event.preventDefault();
  };
  $('input').onkeydown = event => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && event.keyCode !== 229) { event.preventDefault(); $('sendform').requestSubmit(); } };
  function chooseAttachment(photo=false) { retryAttachmentId = null; const input=$(photo?'photoinput':'fileinput');input.value = '';input.click(); }
  $('attach').onclick = () => {
    if (!current || !cryptoBox?.ready || securityTransition || friendshipBlocked(chat())) return;
    if (window.innerWidth > 720) {
      const id=current;openDialog('发送附件',`<div class="compose-menu"><button class="secondarybtn" id="compose-photo">${icon('mountain')}照片</button><button class="secondarybtn" id="compose-file">${icon('file')}文件</button></div>`);
      $('compose-photo').onclick=()=>{$('dialog').close();if(current===id&&cryptoBox?.ready)chooseAttachment(true);};
      $('compose-file').onclick=()=>{$('dialog').close();if(current===id&&cryptoBox?.ready)chooseAttachment();};return;
    }
    if (!current || !cryptoBox?.ready || friendshipBlocked(chat())) return;
    const id = current, c = chat(id), canAsk = isAI(c) && c.context !== 'none';
    openDialog('聊天工具',`<div class="compose-menu"><button class="secondarybtn" id="compose-photo">${icon('mountain')}照片</button><button class="secondarybtn" id="compose-file">${icon('file')}文件</button>${canAsk ? `<button class="secondarybtn" id="compose-mention">${icon('ai')}请山岚帮忙</button><button class="secondarybtn" id="compose-draw">${icon('mountain')}请山岚画图</button><button class="secondarybtn" id="compose-search" aria-pressed="${aiPreference(id).search}">${icon('search')}联网搜索 · ${aiPreference(id).search ? '已开启' : '已关闭'}</button><button class="secondarybtn" data-compose-prompt="总结一下刚才的讨论">总结讨论</button><button class="secondarybtn" data-compose-prompt="把讨论整理成待办">整理待办</button>` : ''}</div>`);
    $('compose-photo').onclick = () => { $('dialog').close(); if (current === id && cryptoBox?.ready) chooseAttachment(true); };
    $('compose-file').onclick = () => { $('dialog').close(); if (current === id && cryptoBox?.ready) chooseAttachment(); };
    if($('compose-draw'))$('compose-draw').onclick=()=>{$('dialog').close();if(current===id)insertDrawingCommand();};
    if ($('compose-mention')) $('compose-mention').onclick = () => { $('dialog').close(); if (current === id) insertText(c.kind !== 'ai' ? '@山岚 ' : ''); };
    if ($('compose-search')) $('compose-search').onclick = () => { if (current !== id || !cryptoBox?.ready || aiJobs.has(id) || aiPreparing.has(id)) return; saveAIPreference(id,{...aiPreference(id),search:!aiPreference(id).search}); $('dialog').close(); renderCompose(); run(persistEncrypted); $('input').focus({preventScroll:true}); };
    $('dialogcontent').querySelectorAll('[data-compose-prompt]').forEach(button => { button.onclick = () => { const text = `${c.kind !== 'ai' ? '@山岚 ' : ''}/10 ${button.dataset.composePrompt}`; $('dialog').close(); if (current === id && cryptoBox?.ready) { $('input').value = text; $('input').dispatchEvent(new Event('input')); $('input').focus(); } }; });
  };
  $('photoinput').onchange = $('fileinput').onchange = event => {
    const file = event.target.files[0]; if (!file || !user || !current || !cryptoBox?.ready || friendshipBlocked(chat())) return;
    if (!Number.isSafeInteger(file.size)||file.size<0) { toast('无法读取这个文件的大小，请重新选择。'); return; }
    if (retryAttachmentId) {
      const p = pending.find(p => p.clientId === retryAttachmentId); retryAttachmentId = null; if (!p) return;
      if (p.fileName !== file.name || p.fileSize !== file.size) { toast('文件名称或大小不同，请选择原附件；也可以取消该消息后重新发送。'); return; }
      rawPending.set(p.clientId,file); run(() => deliver(p));
    } else { attachments.set(current,file); renderCompose(); }
    event.target.value = '';
  };
  $('removefile').onclick = () => { attachments.delete(current); renderCompose(); };
  $('cancelquote').onclick = () => { delete quotes[current]; renderCompose(); };
  function insertText(text) { if (!current || !cryptoBox?.ready || $('input').disabled || chatSecurityErrors.has(current)) return; $('input').setRangeText(text,$('input').selectionStart,$('input').selectionEnd,'end'); $('input').dispatchEvent(new Event('input')); $('input').focus({preventScroll:true}); }
  function insertDrawingCommand() { if (!current || !cryptoBox?.ready || $('input').disabled || chatSecurityErrors.has(current)) return; $('input').value=drawingDraft($('input').value,{direct:chat()?.kind==='ai'});$('input').dispatchEvent(new Event('input'));$('input').focus({preventScroll:true}); }
  function insertAIMention() {
    const c = chat(), input = $('input');
    if (!['group','direct'].includes(c?.kind) || !isAI(c) || c.context === 'none' || $('mention').disabled) return;
    const prefix = input.value.slice(0,input.selectionStart), separator = prefix && !/\s$/.test(prefix) ? ' ' : '';
    insertText(`${separator}@山岚 `);
  }
  $('emoji').onclick = () => run(() => openEmoticons()); $('mention').onclick = insertAIMention;
  document.querySelectorAll('[data-prompt]').forEach(b => { b.onclick = () => insertText(`${$('input').value ? '\n' : ''}${chat()?.kind !== 'ai' ? '@山岚 ' : ''}/10 ${b.dataset.prompt}`); });
  $('stop').onclick = () => { aiJobs.get(current)?.abort(); };
  function hideDetails() { $('app').classList.add('no-details'); $('app').classList.remove('show-details'); $('info').setAttribute('aria-expanded','false'); }
  function showDetails() { if (!chat()) return; renderDetails(); $('app').classList.remove('no-details'); $('app').classList.add('show-details'); $('info').setAttribute('aria-expanded','true'); }
  function renderDetails() {
    const c = chat(); if (!c) return; const editable = canEdit(c);
    $('details').innerHTML = `<div class="detailshead"><h3>会话详情</h3><button class="iconbtn" id="closedetails" aria-label="关闭详情">×</button></div><div class="detailsprofile"><div class="avatar ${chatStyle(c)}">${chatAvatar(c)}</div><h3>${esc(c.name)}</h3>${editable && c.kind === 'group' ? '<button id="rename-chat" class="secondarybtn">修改名称</button>' : ''}</div><section class="detailsection"><button class="detailaction" id="security-details">查看安全码与加密成员</button><h4>参与者${editable && c.kind === 'group' ? '<button id="add-members">添加成员</button>' : ''}</h4>${c.members.map(p => `<div class="memberrow"><div class="avatar ${p.id === 'ai' ? 'ai' : ''}">${avatar(p)}</div><span>${esc(p.displayName)}</span><small>${p.id === 'ai' ? 'AI' : p.id === user.id ? '我' : ''}</small></div>`).join('')}</section>${isAI(c) ? `<section class="detailsection"><div class="policybox"><strong>${icon('ai')}山岚的参与方式</strong><p>${c.kind !== 'ai' ? '被 @山岚 时直接请求 AI，默认只读取当前问题。' : '普通消息连续回复；@山岚 只读取当前问题。'}本次提问附带的图片会交给看图模型；其他附件和历史图片不会自动分享。双人和群聊不使用私人长期记忆。</p><label>AI 分享<select id="context" ${editable ? '' : 'disabled'}><option value="recent" ${c.context === 'recent' ? 'selected' : ''}>允许指定前文</option><option value="mention" ${c.context === 'mention' ? 'selected' : ''}>只分享当前输入</option><option value="none" ${c.context === 'none' ? 'selected' : ''}>暂停 AI</option></select></label>${user.role === 'admin' ? '<button id="aiconfig">模型设置</button>' : ''}</div></section>` : ''}<section class="detailsection"><label class="toggleline">置顶会话<input type="checkbox" id="pin" ${c.pinned ? 'checked' : ''}></label><button class="detailaction" id="mutebtn">${icon('bell')}${c.muted ? '关闭免打扰' : '开启免打扰'}</button><button class="detailaction" id="searchdetail">${icon('search')}搜索这段对话</button></section><section class="detailsection"><h4>已加载的附件</h4>${(messages.get(c.id) || []).filter(m => m.file).map(m => `<div class="detailfile">${fileMarkup(m.file,m)}</div>`).join('') || '<p class="dialogcopy">附件会出现在这里。</p>'}</section>`;
    $('closedetails').onclick = hideDetails; $('searchdetail').onclick = () => openSearch(true);
    if (c.kind === 'group') {
      const section = $('security-details').closest('.detailsection');
      const heading = section.querySelector('h4');
      heading.textContent = `群成员（${c.members.filter(p => p.id !== 'ai').length}）`;
      const action = document.createElement('button'); action.id = 'group-members-action'; action.className = 'detailaction';
      action.innerHTML = editable ? `${icon('plus')}添加群成员` : `${icon('people')}添加成员由群主操作`;
      action.onclick = () => editable ? run(() => choosePeople('add',c)) : toast(`请让群主${person(c.ownerId,c).displayName}打开会话详情，选择“添加群成员”。`);
      heading.before(action);
      const note = document.createElement('p'); note.className = 'dialogcopy'; note.id = 'group-members-note';
      note.textContent = editable ? '可添加已通过申请的好友。新成员只能解密加入之后的消息。' : `群主：${person(c.ownerId,c).displayName}。新成员加入需由群主确认加密身份。`;
      action.after(note);
      section.querySelectorAll('.memberrow').forEach((row,index) => {
        const member = c.members[index];
        row.querySelector('small').textContent = member.id === 'ai' ? 'AI' : member.id === String(c.ownerId) ? (member.id === user.id ? '群主 · 我' : '群主') : member.id === user.id ? '我' : '';
      });
    }
    if (isAI(c)) {
      const policy = $('details').querySelector('.policybox');
      policy.querySelector('p').textContent = `${c.kind === 'group' ? '普通消息不会召唤 AI；@山岚 只读当前问题，/10 带前十条。' : '普通消息连续回复；@山岚 只读当前问题，/10 带前十条。'}选定文字从此设备直达配置的模型服务；聊天服务器只保存加密配置。回复在本机加密后存入聊天，附件不提供给模型。`;
      $('context').querySelector('[value="recent"]').textContent = '允许指定前文';
      const button = document.createElement('button'); button.id = 'ai-context-settings'; button.textContent = '管理前文与隐私'; button.onclick = () => run(() => showAIContext(c.id)); policy.append(button);
    }
    if (c.kind === 'direct' && directPeer(c)) {
      const peer = directPeer(c), section = document.createElement('section'); section.className = 'detailsection';
      section.innerHTML = c.canMessage === true ? '<button class="detailaction friend-remove" id="remove-chat-friend">解除好友</button>' : '<p class="dialogcopy">这段历史仍可阅读。成为好友后才能继续聊天。</p><button class="secondarybtn" id="add-chat-friend">查看好友申请</button>';
      $('details').append(section);
      if ($('remove-chat-friend')) $('remove-chat-friend').onclick = () => confirmRemoveFriend(peer);
      if ($('add-chat-friend')) $('add-chat-friend').onclick = () => run(() => openContacts(c.friendshipStatus === 'incoming' || c.friendshipStatus === 'outgoing' ? 'requests' : 'add',peer.username || ''));
    }
    $('pin').onchange = event => run(() => patchChat(c.id,{pinned:event.target.checked}));
    $('mutebtn').onclick = () => run(() => patchChat(c.id,{muted:!c.muted}));
    if ($('context')) $('context').onchange = event => run(() => patchChat(c.id,{context:event.target.value}));
    if ($('aiconfig')) $('aiconfig').onclick = () => run(aiSettings);
    if ($('add-members')) $('add-members').onclick = () => run(() => choosePeople('add',c));
    if ($('security-details')) $('security-details').onclick = () => run(() => encryptionDetails(c));
    bindDownloads($('details'));
    if ($('rename-chat')) $('rename-chat').onclick = () => {
      openDialog('修改群名称',`<form id="rename-form" class="account-form"><label>名称<input id="rename-value" value="${esc(c.name)}" maxlength="80" required></label><button class="sendbtn">保存</button></form>`);
      $('rename-form').onsubmit = event => { event.preventDefault(); run(async () => { await patchChat(c.id,{name:$('rename-value').value.trim()}); $('dialog').close(); }); };
    };
  }
  async function patchChat(id,body) { const result = await api(`/api/chats/${encodeURIComponent(id)}`,{method:'PATCH',body}); upsertChat(result.chat); if (id === current) { renderHeader(); renderDetails(); } }
  function openDialog(title,html) { sensitiveDialogCleanup?.(); sensitiveDialogCleanup = null; dialogVersion++; $('dialog').classList.remove('scene-dialog','typography-dialog'); $('dialogtitle').textContent = title; $('dialogcontent').innerHTML = html; paintIcons($('dialogcontent')); if (!$('dialog').open) $('dialog').showModal(); return dialogVersion; }
  function dialogCurrent(version) { return dialogVersion === version && $('dialog').open; }
  $('closedialog').onclick = () => { sensitiveDialogCleanup?.(); sensitiveDialogCleanup = null; $('dialog').close(); };
  $('dialog').addEventListener('cancel',() => { sensitiveDialogCleanup?.(); sensitiveDialogCleanup = null; });
  $('dialog').addEventListener('close',() => { sensitiveDialogCleanup?.(); sensitiveDialogCleanup = null; dialogVersion++; $('dialog').classList.remove('scene-dialog'); });
  $('info').onclick = () => $('app').classList.contains('show-details') ? hideDetails() : showDetails();
  $('back').onclick = () => { $('app').classList.remove('mobile-chat'); hideDetails();refreshNativeNotificationView(); };
  $('search').oninput = renderList;
  $('messages').addEventListener('scroll',markRead,{passive:true});
  document.querySelectorAll('[data-filter]').forEach(b => { b.onclick = () => { filter = b.dataset.filter; document.querySelectorAll('[data-filter]').forEach(p => { p.classList.toggle('selected',p === b); p.setAttribute('aria-pressed',String(p === b)); }); renderList(); }; });
  async function choosePeople(kind,c = null) {
    if (!cryptoBox?.ready) { await unlockAndRefresh(); if (!cryptoBox?.ready) return; }
    if (kind === 'add' && (c?.kind !== 'group' || !canEdit(c))) { toast('请让群主打开会话详情，选择“添加群成员”。'); return; }
    const box = cryptoBox, generation = epoch, vault = vaultVersion;
    const version = openDialog(kind === 'group' ? '创建小群' : kind === 'add' ? '添加群成员' : '和朋友聊天','<p class="dialogbusy">正在加载联系人…</p>');
    const valid = () => dialogCurrent(version) && box === cryptoBox && box.ready && generation === epoch && vault === vaultVersion;
    const [result,latest] = await Promise.all([api('/api/friends'),kind === 'add' ? api('/api/chats') : null]); if (!valid()) return;
    if (kind === 'add') {
      c = latest.chats.map(normalizeChat).find(value => value.id === c.id);
      if (!c || c.kind !== 'group' || !canEdit(c)) { $('dialogcontent').innerHTML = '<p class="form-error" role="alert">你已无法管理此群。请刷新会话列表，或联系群主。</p>'; return; }
      upsertChat(c); $('dialogtitle').textContent = `给“${c.name}”添加成员`;
    }
    const users = result.friends.filter(p => String(p.id) !== user.id && String(p.id) !== 'ai' && (!c || !c.members.some(m => m.id === String(p.id))));
    $('dialogcontent').innerHTML = `${kind === 'group' ? '<label class="dialogfield">群名称<input id="new-name" class="dialoginput" maxlength="80" placeholder="给这次相聚起个名字"></label>' : ''}<label class="dialogfield">查找好友<input id="people-filter" class="dialoginput" placeholder="昵称或账户名"></label><div id="people-list" class="choice-users">${users.map(p => `<label class="choice-user" data-person-name="${esc(`${p.displayName} ${p.username}`.toLocaleLowerCase())}"><input type="${kind === 'direct' ? 'radio' : 'checkbox'}" name="member" value="${esc(p.id)}"><div class="avatar">${avatar(p)}</div><span>${esc(p.displayName)}<small>@${esc(p.username)}</small></span></label>`).join('') || '<p class="dialogcopy">暂无可选择的好友。请先添加朋友，等待申请通过。</p>'}</div><button class="secondarybtn" id="people-add-friend">添加朋友</button>${kind === 'group' ? '<label class="inline-check"><input id="include-ai" type="checkbox">邀请山岚 AI 加入</label>' : ''}<p id="people-error" class="form-error" role="alert"></p><div class="dialogactions"><button id="create-confirm" class="sendbtn" ${!users.length ? 'disabled' : ''}>${kind === 'add' ? '添加' : '开始聊天'}</button></div>`;
    $('people-add-friend').onclick = () => { $('dialog').close(); run(() => openContacts('add')); };
    $('people-filter').oninput = event => { const q = event.target.value.trim().toLocaleLowerCase(); $('people-list').querySelectorAll('[data-person-name]').forEach(el => { el.hidden = !el.dataset.personName.includes(q); }); };
    if (kind === 'add') {
      const note = document.createElement('p'); note.className = 'dialogcopy'; note.textContent = '选择已通过申请的好友，再核对新成员的安全码。对方须先登录并设置加密身份；加入前的聊天不会分享给新成员。'; $('dialogcontent').prepend(note);
      $('create-confirm').textContent = '确认添加成员'; $('create-confirm').disabled = !users.length;
      if (!users.length) $('people-list').innerHTML = '<p class="dialogcopy">没有可添加的好友。请先通过好友申请，并让对方设置加密身份，再回来添加。</p>';
    }
    $('create-confirm').onclick = async () => {
      if (!valid()) return;
      const memberIds = [...$('people-list').querySelectorAll('input:checked')].map(i => i.value), button = $('create-confirm'), errorBox = $('people-error');
      if (!memberIds.length) { errorBox.textContent = '请选择至少一位朋友。'; return; }
      const name = kind === 'group' ? $('new-name').value.trim() : undefined;
      if (kind === 'group' && !name) { errorBox.textContent = '请填写群名称。'; return; }
      button.disabled = true;
      try {
        let result;
        if (kind === 'add') {
          const manifest = await box.prepareChat(c,approveTrust); if (!valid()) return;
          const ids = [...new Set([...manifest.payload.members.map(m => m.userId),...memberIds])];
          if (ids.length > 100) throw new Error('一个群聊最多包含 100 位成员，请减少选择。');
          result = await box.updateMembers(c,ids,approveTrust);
          if (!valid()) return; assertAudience(result.chat,ids);
        }
        else { result = await api('/api/chats',{method:'POST',body:{kind,name,memberIds,includeAI:kind === 'group' && $('include-ai').checked}}); assertAudience(result.chat,[user.id,...memberIds]); }
        if (!valid()) return; upsertChat(result.chat); $('dialog').close(); await switchChat(String(result.chat.id)); queueRefresh();
        if (kind === 'add') { showDetails(); toast(`已添加 ${memberIds.length} 位群成员，新成员只能解密加入后的消息。`); }
      }
      catch (e) { if (dialogCurrent(version)) errorBox.textContent = e.message; }
      finally { if (button.isConnected) button.disabled = false; }
    };
  }
  function newChat() {
    if (!cryptoBox?.ready) { run(unlockAndRefresh); return; }
    openDialog('开始一段会话',`<button class="dialogchoice" data-create="direct"><div class="avatar">${icon('people')}</div><span><strong>和朋友聊天</strong><small>选择已通过好友申请的朋友</small></span></button><button class="dialogchoice" data-create="group"><div class="avatar group">${icon('mountain')}</div><span><strong>创建小群</strong><small>邀请朋友，也可以让 AI 参与</small></span></button><button class="dialogchoice" data-create="ai"><div class="avatar ai">${icon('ai')}</div><span><strong>和山岚聊聊</strong><small>开启一段独立的 AI 会话</small></span></button><button class="dialogchoice" data-create="notes"><div class="avatar">记</div><span><strong>我的随手记</strong><small>只属于自己的文字和文件</small></span></button>`);
    $('dialogcontent').querySelectorAll('[data-create]').forEach(b => { b.onclick = () => run(async () => { const kind = b.dataset.create; if (kind === 'direct' || kind === 'group') return choosePeople(kind); b.disabled = true; try { const result = await api('/api/chats',{method:'POST',body:{kind,name:kind === 'ai' ? '和山岚聊聊' : '随手记',memberIds:[]}}); assertAudience(result.chat,[user.id]); upsertChat(result.chat); $('dialog').close(); await switchChat(String(result.chat.id)); queueRefresh(); } finally { if (b.isConnected) b.disabled = false; } }); });
  }
  function assertAudience(c,expected) { const actual = (c.members || []).filter(m => m.id !== 'ai').map(m => m.id).sort(); if (JSON.stringify(actual) !== JSON.stringify([...new Set(expected)].sort())) throw new Error('服务器返回的参与者与你选择的不一致，已停止建立加密会话。'); }
  $('newchat').onclick = newChat;
  function resultsMarkup(items) { return items.map(({message:m,chatName,senderName}) => `<button class="searchresult" data-locate="${esc(m.id)}" data-chat="${esc(m.chatId)}" data-seq="${esc(m.seq)}"><strong>${esc(chatName)} · ${esc(senderName)} · ${esc(time(m.createdAt))}${m.legacy ? ' · 旧版未加密' : ''}</strong><p>${esc(m.text || m.file?.name || '')}</p></button>`).join(''); }
  function bindResults() { $('dialogcontent').querySelectorAll('[data-locate]').forEach(b => { b.onclick = () => run(() => locateMessage(b.dataset.chat,b.dataset.locate,Number(b.dataset.seq))); }); }
  async function locateMessage(id,mid,seq) {
    id = String(id); $('dialog').close(); await switchChat(id); const generation = selection;
    while (!(messages.get(id) || []).some(m => m.id === mid) && hasMore.get(id) && current === id && selection === generation) {
      const first = messages.get(id)?.[0]; if (!first || first.seq <= seq) break;
      await fetchMessages(id,false,first.seq);
    }
    if (current !== id || selection !== generation) return;
    const element = [...$('messages').querySelectorAll('[data-message]')].find(el => el.dataset.message === mid);
    if (element) { element.scrollIntoView({block:'center'}); element.classList.add('highlight'); setTimeout(() => element.classList.remove('highlight'),2200); }
  }
  function openSearch(inChat = false) {
    if (!cryptoBox?.ready) { run(unlockAndRefresh); return; }
    const scope = inChat ? current : null, version = openDialog(inChat ? '在此设备搜索这段对话' : '在此设备搜索消息','<label class="dialogfield">关键词<input id="messagesearch" class="dialoginput" maxlength="200" placeholder="关键词只在此设备处理"></label><p class="dialogcopy">搜索已加载并成功解密的消息。可逐批加载更早消息，关键词不会发给服务器。</p><button id="search-older" class="secondarybtn">加载更多历史</button><p id="search-progress" class="dialogcopy"></p><div id="searchresults" class="searchresults"><p class="dialogcopy">输入关键词开始搜索。</p></div>');
    const searchLocal = () => {
      if (!dialogCurrent(version) || !cryptoBox?.ready) return;
      const q = $('messagesearch').value.trim().toLocaleLowerCase(), candidates = [...messages.entries()].filter(([id]) => !scope || id === scope).flatMap(([id,list]) => list.filter(m => m._decrypted && !m.decryptError).map(message => ({message,chatName:chat(id)?.name || '会话',senderName:person(message.senderId,chat(id)).displayName})));
      const found = q ? candidates.filter(item => `${item.message.text}\n${item.message.file?.name || ''}`.toLocaleLowerCase().includes(q)).slice(0,100) : [];
      $('search-progress').textContent = `已在此设备解密 ${candidates.length} 条消息${q ? `，显示 ${found.length} 条匹配` : ''}`;
      $('searchresults').innerHTML = !q ? '<p class="dialogcopy">输入关键词开始搜索。</p>' : found.length ? resultsMarkup(found) : '<p class="dialogcopy">已加载的内容中没有找到，可继续加载历史。</p>'; bindResults();
    };
    $('messagesearch').oninput = searchLocal;
    $('search-older').onclick = () => run(async () => {
      const button = $('search-older'); button.disabled = true; let count = 0;
      try {
        const targets = chats.filter(c => !scope || c.id === scope);
        for (const c of targets) {
          if (!dialogCurrent(version) || !cryptoBox?.ready) break;
          if (messages.has(c.id) && !hasMore.get(c.id)) continue;
          try { try { await cryptoBox.prepareChat(c,approveTrust); } catch (e) { chatSecurityErrors.set(c.id,e.message); } await fetchMessages(c.id,false,messages.get(c.id)?.[0]?.seq || null); count++; }
          catch (e) { if (dialogCurrent(version)) $('search-progress').textContent = `${c.name}：${e.message}`; }
          if (count >= 5) break;
        }
        searchLocal(); if (!count && dialogCurrent(version)) $('search-progress').textContent += ' · 没有可加载的历史，或需要先核验联系人。';
      } finally { if (button.isConnected) button.disabled = false; }
    });
    $('messagesearch').focus(); searchLocal();
  }
  async function openSaved() {
    if (!cryptoBox?.ready) { await unlockAndRefresh(); if (!cryptoBox?.ready) return; }
    const version = openDialog('我的收藏','<p class="dialogbusy">正在此设备解密收藏…</p>'), box = cryptoBox;
    const result = await api('/api/saved'); if (!dialogCurrent(version)) return;
    const items = [];
    for (const item of result.items) {
      if (!dialogCurrent(version) || box !== cryptoBox || !box.ready) return;
      const c = chat(String(item.message.chatId)); if (!c) continue;
      try { await box.prepareChat(c,approveTrust); } catch {}
      const message = await decodedMessage(c,item.message); items.push({...item,message:message.decryptError ? {...message,text:`无法解密：${message.decryptError}`} : message});
    }
    if (!dialogCurrent(version) || box !== cryptoBox || !box.ready) return;
    saved = new Set(result.items.map(i => String(i.message.id))); $('dialogcontent').innerHTML = items.length ? resultsMarkup(items) : '<p class="dialogcopy">点消息下方的“收藏”，把值得再看的内容留下来。</p>'; bindResults(); renderMessages();
  }
  $('chatsearch').onclick = () => { if (current) openSearch(true); };
  function setNavigation(view) {
    if (view !== 'people' && activeView === 'people') { contactRevision++; contactController?.abort(); contactController = null; contactBusy = false; }
    activeView = view;
    $('app').classList.toggle('contacts-open',view === 'people');
    if ($('contacts-view')) $('contacts-view').hidden = view !== 'people';
    document.querySelectorAll('[data-nav]').forEach(button => { const selected = button.dataset.nav === view; button.classList.toggle('active',selected); if (selected) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current'); });
    queueMicrotask(refreshNativeNotificationView);
  }
  function resetContacts() {
    contactRevision++; contactController?.abort(); contactController = null; contactBusy = false; contactError = ''; contactUsers = []; contactRequests = []; directoryUsers = []; contactFilter = ''; contactMode = 'friends'; contactSubmittedQuery = ''; contactSearchComplete = false;
    if ($('contacts-view')) { $('contacts-view').replaceChildren(); $('contacts-view').hidden = true; }
    setNavigation('chat');
  }
  function ensureContactsView() {
    if (!$('contacts-view')) { const panel = document.createElement('section'); panel.id = 'contacts-view'; panel.className = 'contacts-view'; panel.setAttribute('aria-label','联系人'); panel.hidden = activeView !== 'people'; $('app').append(panel); }
    if ($('contacts-filter')) return;
    $('contacts-view').innerHTML = `<header class="contacts-head"><div><h1>联系人</h1><p>好友申请通过后，才能开始聊天</p></div><button id="contacts-reload" class="iconbtn" aria-label="刷新联系人" title="刷新联系人"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 7v5h-5M4 17v-5h5M20 12a8 8 0 0 0-14-5M4 12a8 8 0 0 0 14 5"/></svg></button></header><div class="contacts-tabs" role="group" aria-label="联系人页面"><button data-contact-mode="friends">朋友</button><button data-contact-mode="requests">新的朋友<span id="friend-request-count"></span></button><button data-contact-mode="add">添加朋友</button></div><form id="contacts-search-form" class="contacts-query"><label class="contacts-search">${icon('search')}<input id="contacts-filter" type="search" autocomplete="off" aria-label="筛选联系人" placeholder="搜索昵称或账户名"></label><button id="contacts-search" type="submit" class="sendbtn" hidden>搜索</button></form><div id="contacts-status" class="contacts-status" role="status"></div><div id="contacts-list" class="contacts-list" aria-label="联系人列表"></div>`;
    $('contacts-filter').value = contactFilter;
    $('contacts-filter').oninput = event => {
      contactFilter = event.target.value;
      if (contactMode === 'add') { contactRevision++; contactController?.abort(); contactController = null; contactBusy = false; contactError = ''; contactSubmittedQuery = ''; contactSearchComplete = false; directoryUsers = []; }
      renderContacts();
    };
    $('contacts-search-form').onsubmit = event => { event.preventDefault(); if (contactMode === 'add') run(searchFriend); };
    $('contacts-reload').onclick = () => run(loadContacts);
    $('contacts-view').querySelectorAll('[data-contact-mode]').forEach(button => { button.onclick = () => run(async () => {
      if (contactBusy || securityTransition) return;
      contactMode = button.dataset.contactMode; contactFilter = ''; contactSubmittedQuery = ''; contactSearchComplete = false; directoryUsers = []; $('contacts-filter').value = ''; renderContacts(); await loadContacts();
    }); });
  }
  async function searchFriend() {
    if (contactBusy || securityTransition || activeView !== 'people' || contactMode !== 'add' || !cryptoBox?.ready) return;
    const query = contactFilter.trim(); contactError = ''; directoryUsers = []; contactSearchComplete = false; contactSubmittedQuery = '';
    if (query.length < 3) { contactError = '请输入至少 3 个字符的完整用户名或账号。'; renderContacts(); return; }
    contactSubmittedQuery = query; await loadContacts();
  }
  const contactMatches = (person,query) => `${person.displayName || ''} ${person.username || ''}`.toLocaleLowerCase().includes(query);
  function contactPersonMarkup(person) { return `<div class="avatar">${avatar(person)}</div><span class="friend-person"><strong>${esc(person.displayName || person.username)}</strong><small>@${esc(person.username)}</small></span>`; }
  function friendRequestActions(status,requestId,personId) {
    const busy = contactBusy ? 'disabled' : '';
    if (status === 'accepted') return `<button class="secondarybtn" data-directory-chat="${esc(personId)}" ${busy}>发消息</button>`;
    if (status === 'incoming' && requestId) return `<button class="sendbtn" data-friend-action="accept" data-request-id="${esc(requestId)}" ${busy}>同意</button><button class="secondarybtn" data-friend-action="reject" data-request-id="${esc(requestId)}" ${busy}>拒绝</button>`;
    if (status === 'outgoing' && requestId) return `<span class="friend-waiting">等待通过</span><button class="secondarybtn" data-friend-action="cancel" data-request-id="${esc(requestId)}" ${busy}>撤回</button>`;
    return `<button class="sendbtn" data-friend-action="request" data-person-id="${esc(personId)}" ${busy}>添加好友</button>`;
  }
  function renderContacts() {
    if (activeView !== 'people' || !user || !cryptoBox?.ready || !$('contacts-list')) return;
    const query = contactFilter.trim().toLocaleLowerCase(), friends = contactUsers.filter(person => contactMatches(person,query)), requests = contactRequests.filter(request => contactMatches(request.user,query)), directory = contactSubmittedQuery ? directoryUsers : [];
    $('contacts-reload').disabled = contactBusy;
    $('contacts-view').querySelectorAll('[data-contact-mode]').forEach(button => { button.classList.toggle('selected',button.dataset.contactMode === contactMode); button.setAttribute('aria-pressed',String(button.dataset.contactMode === contactMode)); button.disabled = contactBusy; });
    const incoming = contactRequests.filter(request => request.direction === 'incoming').length; $('friend-request-count').textContent = incoming ? ` ${incoming}` : '';
    $('contacts-filter').placeholder = contactMode === 'add' ? '输入对方完整用户名或账号' : contactMode === 'requests' ? '查找好友申请' : '搜索好友昵称或账户名';
    $('contacts-filter').setAttribute('aria-label',contactMode === 'add' ? '对方完整用户名或账号' : '筛选联系人'); $('contacts-filter').setAttribute('enterkeyhint',contactMode === 'add' ? 'search' : 'done'); $('contacts-filter').maxLength = contactMode === 'add' ? 64 : 100;
    $('contacts-search').hidden = contactMode !== 'add'; $('contacts-search').disabled = contactBusy;
    $('contacts-list').setAttribute('aria-busy',String(contactBusy));
    const count = contactMode === 'friends' ? friends.length : contactMode === 'requests' ? requests.length : directory.length;
    setStableHTML($('contacts-status'),contactError ? `<span class="failed">${esc(contactError)}</span>${contactMode !== 'add' || contactSubmittedQuery ? '<button id="contacts-retry" class="secondarybtn">重试</button>' : ''}` : contactBusy ? contactMode === 'add' && contactSubmittedQuery ? '正在查找账号…' : '正在更新联系人…' : contactMode === 'friends' ? `${contactUsers.length} 位好友${query ? ` · 找到 ${count} 位` : ''}` : contactMode === 'requests' ? `${incoming} 条待处理申请 · ${contactRequests.filter(request => request.direction === 'outgoing').length} 条等待通过` : contactSearchComplete ? count ? '找到这个账号，对方同意申请后才能聊天' : '没有找到这个账号，请核对完整用户名或账号' : '按完整用户名或账号查找，不公开空间中的用户名单');
    if ($('contacts-retry')) $('contacts-retry').onclick = () => run(contactMode === 'add' ? searchFriend : loadContacts);
    let markup;
    if (contactMode === 'friends') markup = friends.map(person => `<div class="friend-row" data-friend-row="${esc(person.id)}"><button class="contact-row" data-contact-id="${esc(person.id)}" ${contactBusy ? 'disabled' : ''}>${contactPersonMarkup(person)}<span class="contact-open" aria-hidden="true">›</span></button><button class="friend-remove" data-remove-friend="${esc(person.id)}" aria-label="解除与${esc(person.displayName || person.username)}的好友关系" ${contactBusy ? 'disabled' : ''}>解除好友</button></div>`).join('');
    else if (contactMode === 'requests') markup = requests.map(request => `<div class="friend-request-row" data-friend-row="request:${esc(request.id)}">${contactPersonMarkup(request.user)}<div class="friend-actions">${friendRequestActions(request.direction,request.id,request.user.id)}</div><small class="friend-request-time">${request.direction === 'incoming' ? '收到的申请' : '已发送的申请'} · ${esc(time(request.createdAt))}</small></div>`).join('');
    else markup = directory.map(person => `<div class="friend-request-row" data-friend-row="directory:${esc(person.id)}">${contactPersonMarkup(person)}<div class="friend-actions">${friendRequestActions(person.friendshipStatus,person.friendRequestId,person.id)}</div></div>`).join('');
    if (!markup) markup = `<p class="contacts-empty">${contactMode === 'add' ? contactBusy && contactSubmittedQuery ? '正在查找，请稍候。' : contactError ? '请稍后再试，或核对输入的账号。' : contactSearchComplete ? '没有找到这个账号。' : '输入朋友的完整用户名或账号，再点击“搜索”。' : contactBusy ? '联系人即将显示在这里。' : query ? '没有找到匹配的朋友。' : contactError ? '重新加载后再试一次。' : contactMode === 'friends' ? '还没有好友。点击“添加朋友”，发送你的第一份好友申请。' : '暂无好友申请。收到的新申请会出现在这里。'}</p>`;
    stableChildren($('contacts-list'),markup,'data-friend-row');
    $('contacts-list').querySelectorAll('[data-contact-id]').forEach(button => { button.onclick = () => run(() => openContact(button.dataset.contactId)); });
    $('contacts-list').querySelectorAll('[data-directory-chat]').forEach(button => { button.onclick = () => run(() => openContact(button.dataset.directoryChat)); });
    $('contacts-list').querySelectorAll('[data-friend-action]').forEach(button => { button.onclick = () => run(() => changeFriendship(button.dataset.friendAction,button.dataset.requestId || button.dataset.personId)); });
    $('contacts-list').querySelectorAll('[data-remove-friend]').forEach(button => { button.onclick = () => confirmRemoveFriend(contactUsers.find(person => person.id === button.dataset.removeFriend)); });
  }
  function readFriends(result) {
    contactUsers = (result.friends || []).filter(person => String(person.id) !== user.id && String(person.id) !== 'ai').map(person => ({...person,id:String(person.id)})).sort((left,right) => String(left.displayName || left.username).localeCompare(String(right.displayName || right.username),'zh-CN'));
    contactRequests = (result.requests || []).filter(request => request.status === 'pending' && ['incoming','outgoing'].includes(request.direction)).map(request => ({...request,id:String(request.id),user:{...request.user,id:String(request.user.id)}}));
    directoryUsers = directoryUsers.map(person => { const friend = contactUsers.find(item => item.id === person.id), request = contactRequests.find(item => item.user.id === person.id); return {...person,friendshipStatus:friend ? 'accepted' : request?.direction || 'none',friendRequestId:request?.id || null}; });
  }
  async function loadContacts({silent = false} = {}) {
    if (activeView !== 'people' || !user || !cryptoBox?.ready || securityTransition) return;
    contactController?.abort(); const controller = new AbortController(), generation = epoch, vault = vaultVersion, box = cryptoBox, revision = ++contactRevision;
    contactController = controller; contactBusy = !silent; if (!silent) contactError = ''; renderContacts();
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && !securityTransition && revision === contactRevision && activeView === 'people';
    try {
      const lookup = !silent && contactMode === 'add' && contactSubmittedQuery.length >= 3 ? contactSubmittedQuery : '';
      const [result,directory] = await Promise.all([api('/api/friends',{signal:controller.signal}),lookup ? api(`/api/users?q=${encodeURIComponent(lookup)}`,{signal:controller.signal}) : null]); if (!valid()) return;
      readFriends(result); contactError = '';
      if (directory) { directoryUsers = (directory.users || []).filter(person => String(person.id) !== user.id && String(person.id) !== 'ai').map(person => ({...person,id:String(person.id)})); contactSearchComplete = true; }
    } catch (error) { if (valid() && !error.stale) contactError = error.message || '联系人加载失败，请重试。'; }
    finally { if (valid()) { contactBusy = false; contactController = null; renderContacts(); } }
  }
  async function openContacts(mode = 'friends',query = '') {
    if (!user) return;
    const generation = epoch;
    if (!cryptoBox?.ready) { await unlockAndRefresh(); if (generation !== epoch || !cryptoBox?.ready) return; }
    if (current) { drafts[current] = $('input').value; storeState(); }
    if ($('dialog').open) $('dialog').close();
    contactMode = ['friends','requests','add'].includes(mode) ? mode : 'friends'; contactFilter = query; contactSubmittedQuery = ''; contactSearchComplete = false; directoryUsers = [];
    hideDetails(); $('app').classList.remove('mobile-chat'); setNavigation('people'); ensureContactsView(); renderContacts();
    $('contacts-filter').value = contactFilter;
    $('contacts-filter').focus(); await loadContacts();
  }
  async function openContact(id) {
    if (contactBusy || securityTransition || activeView !== 'people' || !cryptoBox?.ready || !contactUsers.some(person => person.id === id)) return;
    const generation = epoch, vault = vaultVersion, box = cryptoBox, revision = ++contactRevision, controller = new AbortController();
    contactController?.abort(); contactController = controller; contactBusy = true; contactError = ''; renderContacts();
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && revision === contactRevision && activeView === 'people';
    try {
      const result = await api('/api/chats',{method:'POST',body:{kind:'direct',memberIds:[id]},signal:controller.signal}); if (!valid()) return;
      assertAudience(result.chat,[user.id,id]); upsertChat(result.chat); await switchChat(String(result.chat.id)); queueRefresh();
    } catch (error) { if (valid() && !error.stale) contactError = error.message || '暂时无法打开聊天，请重试。'; }
    finally { if (valid()) { contactBusy = false; contactController = null; renderContacts(); } }
  }
  async function changeFriendship(action,id) {
    if (contactBusy || securityTransition || activeView !== 'people' || !user || !cryptoBox?.ready) return;
    if (!['request','accept','reject','cancel'].includes(action)) return;
    const generation = epoch, vault = vaultVersion, box = cryptoBox, revision = ++contactRevision, controller = new AbortController();
    contactController?.abort(); contactController = controller; contactBusy = true; contactError = ''; renderContacts();
    const valid = () => generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && !securityTransition && revision === contactRevision && activeView === 'people';
    try {
      await api(action === 'request' ? '/api/friend-requests' : `/api/friend-requests/${encodeURIComponent(id)}/${action}`,{method:'POST',...(action === 'request' ? {body:{userId:id}} : {}),signal:controller.signal});
      if (!valid()) return;
      const friends = await api('/api/friends',{signal:controller.signal});
      if (!valid()) return; readFriends(friends);
      toast(action === 'request' ? '好友申请已更新，可在“新的朋友”查看。' : action === 'accept' ? '已成为好友，现在可以聊天了。' : action === 'reject' ? '已拒绝这份好友申请。' : '已撤回好友申请。'); queueRefresh();
    } catch (error) { if (valid() && !error.stale) contactError = error.message || '好友申请操作失败，请重试。'; }
    finally { if (valid()) { contactBusy = false; contactController = null; renderContacts(); } }
  }
  function confirmRemoveFriend(peer) {
    if (!peer || !user || !cryptoBox?.ready || securityTransition) return;
    const generation = epoch, vault = vaultVersion, box = cryptoBox;
    const version = openDialog('解除好友',`<p class="dialogcopy">确认解除与 ${esc(peer.displayName || peer.username)} 的好友关系？已有私聊记录保留，双方需要重新申请并通过才能发送新消息。共同群聊不受影响。</p><p id="remove-friend-error" class="form-error" role="alert"></p><div class="dialogactions"><button id="remove-friend-cancel" class="secondarybtn">取消</button><button id="remove-friend-confirm" class="sendbtn">确认解除</button></div>`);
    $('remove-friend-cancel').onclick = () => $('dialog').close();
    $('remove-friend-confirm').onclick = async () => {
      const valid = () => dialogCurrent(version) && generation === epoch && vault === vaultVersion && box === cryptoBox && box.ready && !securityTransition;
      if (!valid()) return; const button = $('remove-friend-confirm'), controller = new AbortController(); button.disabled = true; transfers.add(controller);
      try {
        await api(`/api/friends/${encodeURIComponent(peer.id)}`,{method:'DELETE',signal:controller.signal}); if (!valid()) return;
        chats = chats.map(c => c.kind === 'direct' && directPeer(c)?.id === peer.id ? {...c,canMessage:false,friendshipStatus:'none',friendRequestId:null} : c);
        chatRevision++; contactUsers = contactUsers.filter(person => person.id !== peer.id);
        directoryUsers = directoryUsers.map(person => person.id === peer.id ? {...person,friendshipStatus:'none',friendRequestId:null} : person);
        $('dialog').close(); if (current) { renderHeader(); renderCompose(); if ($('app').classList.contains('show-details')) renderDetails(); }
        renderContacts(); queueRefresh(); toast('已解除好友，历史记录仍可阅读。');
      } catch (error) { if (valid() && !error.stale) $('remove-friend-error').textContent = error.message || '暂时无法解除好友，请重试。'; }
      finally { transfers.delete(controller); if (button.isConnected) button.disabled = false; }
    };
  }
  document.querySelectorAll('[data-nav]').forEach(button => { button.onclick = () => { if (button.dataset.nav === 'chat') { setNavigation('chat'); $('app').classList.remove('mobile-chat'); } else if (button.dataset.nav === 'people') run(openContacts); else { setNavigation('saved'); run(openSaved); } }; });
  $('dialog').addEventListener('close',() => { if (activeView === 'saved') setNavigation('chat'); });
  async function aiSettings() {
    if (user?.role !== 'admin') { toast('请联系管理员配置 AI 模型。'); return; }
    if (!cryptoBox?.ready || securityTransition) { await unlockAndRefresh(); if (!cryptoBox?.ready || securityTransition) return; }
    const box = cryptoBox, generation = epoch, vault = vaultVersion, controller = new AbortController(); transfers.add(controller);
    const version = openDialog('山岚 · 模型设置','<p class="dialogbusy">正在读取加密配置…</p>');
    let currentCredential = null, busy = false, keyField = null, searchKeyField = null;
    const profileKeyFields=[];
    const valid = () => dialogCurrent(version) && box === cryptoBox && box.ready && generation === epoch && vault === vaultVersion && !securityTransition && !controller.signal.aborted;
    const cleanup = () => { controller.abort(); transfers.delete(controller); currentCredential = null; if (keyField) keyField.value = ''; if(searchKeyField)searchKeyField.value=''; for(const field of profileKeyFields)field.value=''; };
    sensitiveDialogCleanup = cleanup;
    let config;
    try { config = await api('/api/admin/ai',{signal:controller.signal}); }
    catch (error) { if (valid()) { $('dialogcontent').innerHTML = `<p class="form-error" role="alert">${esc(error.message)}</p><button id="ai-retry-settings" class="secondarybtn">重新读取</button>`; $('ai-retry-settings').onclick = () => run(aiSettings); } return; }
    if (!valid()) return;
    const candidates = (config.candidateUsers || []).map(person => ({...person,id:String(person.id)})), existingRecipients = new Set((config.configuration?.payload?.recipients || []).map(person => String(person.userId)));
    $('dialogcontent').innerHTML = `<form id="ai-form" class="account-form"><p class="dialogcopy">填写服务商的普通 API Key。获准用户的设备直接连接模型，聊天服务器只保存加密配置。</p><label class="inline-check"><input type="checkbox" id="ai-enabled" ${config.configuration ? config.enabled ? 'checked' : '' : 'checked'}>启用山岚</label><label>API 地址<input id="ai-base-url" type="url" required maxlength="2048" value="${esc(config.configuration?.payload?.baseUrl || (config.mode === 'shared_direct' ? config.baseUrl : '') || 'https://ai.isok.dev/v1')}" placeholder="https://ai.isok.dev/v1" autocomplete="off"></label><label>API Key<input id="ai-key" type="password" maxlength="4096" autocomplete="new-password" placeholder="${config.configuration ? '已加密保存，留空保留原 Key' : '粘贴服务商提供的普通 API Key'}"></label><label>模型<input id="ai-model" list="ai-model-options" maxlength="200" required value="${esc(config.configuration?.payload?.model || (config.mode === 'shared_direct' ? config.model : '') || '')}" placeholder="读取模型列表，或手动填写模型名称" autocomplete="off"><datalist id="ai-model-options"></datalist></label><div class="ai-model-tools"><button type="button" class="secondarybtn" id="ai-load-models">读取模型</button><span id="ai-model-status" class="dialogcopy" role="status">模型列表由此设备直接读取；也可手动填写。</span></div><h3 class="ai-authorize-title">允许使用山岚的账户</h3><p class="dialogcopy">Key 不在普通用户界面显示，获准设备仍有能力提取。请只授权你信任的账户；费用与限额由服务商管理。</p><button type="button" id="ai-authorize-new" class="secondarybtn">勾选所有已准备好的账户</button><div class="choice-users ai-authorized-users">${candidates.map(person => `<label class="choice-user"><input type="checkbox" name="ai-recipient" value="${esc(person.id)}" ${person.identity && (!config.configuration || existingRecipients.has(person.id)) ? 'checked' : ''} ${!person.identity || person.id === user.id ? 'disabled' : ''}><div class="avatar">${avatar(person)}</div><span>${esc(person.displayName || person.username)}<small>@${esc(person.username)} · ${person.identity ? existingRecipients.has(person.id) ? '已授权' : '待授权' : '尚未建立加密身份，需先登录并解锁聊天'}</small></span></label>`).join('')}</div><p class="dialogcopy">新用户加入后，回来勾选并保存即可，不用重新输入 Key。取消授权不能收回已取得的 Key；彻底撤销时，请在服务商处更换 Key 后重新保存。服务商会处理你主动交给 AI 的原文。</p><p class="form-error" id="ai-error" role="alert"></p><button class="sendbtn" id="ai-save">加密并保存设置</button></form>`;
    keyField = $('ai-key');
    $('ai-form').querySelector('.ai-authorize-title').insertAdjacentHTML('beforebegin',`<div class="ai-capability-settings">${[['vision','看图','给山岚发送图片时使用，模型需要支持图片理解。'],['image','生图','使用 /生图 加描述，或对山岚说“帮我画一张…”。支持兼容接口的 images/generations。']].map(([name,label,copy])=>{const item=config.configuration?.payload?.[name];return `<details class="ai-model-section" ${item?.enabled?'open':''}><summary>${label}模型${item?.enabled?' · 已启用':' · 可选'}</summary><p class="dialogcopy">${copy}</p><label class="inline-check"><input id="ai-${name}-enabled" type="checkbox" ${item?.enabled?'checked':''}>启用${label}</label><label>API 地址<input id="ai-${name}-base-url" type="url" maxlength="512" value="${esc(item?.baseUrl||'')}" placeholder="留空使用文字模型的 API 地址" autocomplete="off"></label><label>API Key<input id="ai-${name}-key" type="password" maxlength="4096" autocomplete="new-password" placeholder="留空保留；首次留空使用文字模型的 Key"></label><label>模型名称<input id="ai-${name}-model" list="ai-${name}-model-options" maxlength="200" value="${esc(item?.model||'')}" placeholder="填写支持${label}的模型名称" autocomplete="off"><datalist id="ai-${name}-model-options"></datalist></label><button type="button" class="secondarybtn" id="ai-${name}-load-models">读取可用模型</button><p class="dialogcopy" id="ai-${name}-status" role="status"></p></details>`;}).join('')}</div>`);
    for(const name of ['vision','image'])profileKeyFields.push($('ai-'+name+'-key'));
    $('ai-form').querySelector('.ai-authorize-title').insertAdjacentHTML('beforebegin',`<h3 class="ai-authorize-title">Tavily 联网搜索</h3><label class="inline-check"><input id="ai-search-enabled" type="checkbox" ${config.configuration?.payload?.searchEnabled ? 'checked' : ''}>允许用户开启联网搜索</label><label>Tavily API Key<input id="ai-tavily-key" type="password" maxlength="4096" autocomplete="new-password" placeholder="${config.configuration?.payload?.searchEnabled ? '已加密保存，留空保留原 Tavily Key' : '粘贴 Tavily Key，搜索为可选功能'}"></label><p class="dialogcopy">Key 与模型 Key 一起加密授权。搜索由用户设备直接连接 Tavily，仅查询当前问题；管理员开启后，用户仍需在会话中打开“联网”。</p>`);
    searchKeyField=$('ai-tavily-key');
    const initialDisabled = new Map([...$('ai-form').querySelectorAll('input,button')].map(input => [input,input.disabled]));
    const setBusy = value => { busy = value; if (!valid()) return; for (const [input,disabled] of initialDisabled) input.disabled = value || disabled; $('ai-form').setAttribute('aria-busy',String(value)); };
    const savedCredential = async () => {
      if (currentCredential) return currentCredential;
      if (!config.configuration) return null;
      const credential = await unlockSharedAIConfiguration(box,{configuration:config.configuration,history:config.history,approveTrust,approveEndpoint:details => approveAIEndpoint(details,{signal:controller.signal}),signal:controller.signal});
      if (!valid()) return null; currentCredential = credential; return credential;
    };
    for(const name of ['vision','image'])$('ai-'+name+'-load-models').onclick=async()=>{
      if(!valid()||busy)return;setBusy(true);$('ai-error').textContent='';$('ai-'+name+'-status').textContent='正在读取…';
      try {
        const saved=await savedCredential();if(!valid())return;
        const key=$('ai-'+name+'-key').value.trim()||saved?.[name]?.key||$('ai-key').value.trim()||saved?.key;
        if(!key)throw new Error('请先填写 API Key。');
        const baseUrl=$('ai-'+name+'-base-url').value.trim()||$('ai-base-url').value.trim(),model=$('ai-'+name+'-model').value.trim();
        if(!await approveAIEndpoint({baseUrl,model,capability:name},{signal:controller.signal})||!valid())return;
        const result=await getModels({baseUrl,key,model,mode:'shared_direct',apiFormat:'chat_completions'},{signal:controller.signal});if(!valid())return;
        $('ai-'+name+'-model-options').innerHTML=result.models.map(item=>`<option value="${esc(item.id)}">${esc(item.name||item.id)}</option>`).join('');
        $('ai-'+name+'-status').textContent=`已读取 ${result.models.length} 个模型，请选择支持${name==='vision'?'看图':'生图'}的模型。`;
      } catch(error){if(valid()){$('ai-error').textContent=error.message;$('ai-'+name+'-status').textContent='也可直接填写模型名称。';}}
      finally{if(valid())setBusy(false);}
    };
    $('ai-authorize-new').onclick = () => { if (!valid() || busy) return; $('ai-form').querySelectorAll('[name="ai-recipient"]:not(:disabled)').forEach(input => { input.checked = true; }); $('ai-error').textContent = ''; };
    $('ai-load-models').onclick = async () => {
      if (!valid() || busy) return; setBusy(true); $('ai-error').textContent = ''; $('ai-model-status').textContent = '正在从此设备读取模型…';
      try {
        const saved = $('ai-key').value.trim() ? null : await savedCredential(); if (!valid()) return;
        const key = $('ai-key').value.trim() || saved?.key; if (!key) throw new Error('请先输入服务商的 API Key。');
        const baseUrl = $('ai-base-url').value.trim(), model = $('ai-model').value.trim();
        if (!await approveAIEndpoint({baseUrl,model,previousBaseUrl:saved?.baseUrl && saved.baseUrl !== baseUrl ? saved.baseUrl : null},{signal:controller.signal})) { if (valid()) $('ai-model-status').textContent = '已取消读取，可手动填写模型。'; return; }
        if (!valid()) return;
        const result = await getModels({mode:'shared_direct',baseUrl,key,model,apiFormat:'chat_completions'},{signal:controller.signal}); if (!valid()) return;
        $('ai-model-options').innerHTML = result.models.map(model => `<option value="${esc(model.id)}">${esc(model.name || model.id)}</option>`).join('');
        if (!$('ai-model').value.trim() && result.models.length) $('ai-model').value = result.models[0].id;
        $('ai-model-status').textContent = result.models.length ? `已读取 ${result.models.length} 个模型，可选择或手动填写。` : '服务商未列出模型，请手动填写。';
      } catch (error) { if (valid()) { $('ai-error').textContent = error.message; $('ai-model-status').textContent = '读取失败；仍可手动填写模型名称。'; } }
      finally { if (valid()) setBusy(false); }
    };
    $('ai-form').onsubmit = async event => {
      event.preventDefault(); if (!valid() || busy) return; setBusy(true); $('ai-error').textContent = '';
      try {
        const inputKey = $('ai-key').value.trim(), inputTavilyKey=$('ai-tavily-key').value.trim();
        const saved = config.configuration ? await savedCredential() : null; if (!valid()) return;
        const key = inputKey || saved?.key; if (!key) throw new Error('请先输入服务商的 API Key。');
        const tavilyKey=inputTavilyKey || saved?.tavilyKey || '', searchEnabled=$('ai-search-enabled').checked;
        if(searchEnabled&&!tavilyKey)throw new Error('启用联网搜索前，请填写 Tavily API Key。');
        const recipientIds = [...$('ai-form').querySelectorAll('[name="ai-recipient"]:checked')].map(input => input.value);
        if (!recipientIds.includes(user.id)) throw new Error('请保留当前管理员的授权，以便以后在本机调整配置。');
        const profiles={};for(const name of ['vision','image'])profiles[name]={enabled:$('ai-'+name+'-enabled').checked,baseUrl:$('ai-'+name+'-base-url').value.trim()||$('ai-base-url').value.trim(),model:$('ai-'+name+'-model').value.trim(),key:$('ai-'+name+'-key').value.trim()||saved?.[name]?.key||key};
        const configuration = await createSharedAIConfiguration(box,{baseUrl:$('ai-base-url').value.trim(),model:$('ai-model').value.trim(),key,enabled:$('ai-enabled').checked,searchEnabled,tavilyKey,...profiles,recipientIds,previousConfiguration:config.configuration,history:config.history,approveTrust,signal:controller.signal});
        if (!valid()) return; $('ai-key').value = ''; $('ai-tavily-key').value='';
        for(const field of profileKeyFields)field.value='';
        await api('/api/admin/ai',{method:'PUT',body:{mode:'shared_direct',configuration},signal:controller.signal}); if (!valid()) return;
        const historyEntry = await sharedAIHistoryEntry(configuration); if (!valid()) return;
        await unlockSharedAIConfiguration(box,{configuration,history:[...(config.history || []),historyEntry],approveTrust,approveEndpoint:async () => true,signal:controller.signal}); if (!valid()) return;
        currentCredential = null; $('dialog').close(); toast('共享 Key 已加密保存，获准设备可直接使用模型与已启用的搜索。'); queueRefresh();
      } catch (error) { if (valid()) $('ai-error').textContent = error.message; }
      finally { if (valid()) setBusy(false); }
    };
  }

  async function invites() {
    const version = openDialog('邀请朋友','<p class="dialogbusy">正在读取邀请码…</p>'); const result = await api('/api/admin/invites'); if (!dialogCurrent(version)) return;
    const paint = list => { $('dialogcontent').innerHTML = `<p class="dialogcopy">把邀请码分享给朋友，他们就能在登录页注册。</p><form id="invite-form" class="account-form"><label>本次允许注册的人数<input id="invite-uses" type="number" min="1" max="100" value="1" required></label><button class="sendbtn" id="invite-create">生成邀请码</button></form><div id="invite-list">${list.map(i => `<div class="admin-code"><code>${esc(i.code)}</code><small>已使用 ${Number(i.uses || i.usedCount || 0)} / ${Number(i.maxUses || 1)} 次</small></div>`).join('')}</div>`; $('invite-form').onsubmit = async event => { event.preventDefault(); const button = $('invite-create'); button.disabled = true; try { await api('/api/admin/invites',{method:'POST',body:{maxUses:Number($('invite-uses').value)}}); const all = await api('/api/admin/invites'); if (dialogCurrent(version)) paint(all.invites); } catch (e) { toast(e.message); } finally { if (button.isConnected) button.disabled = false; } }; }; paint(result.invites);
  }
  function passwordSettings() {
    const version = openDialog('修改密码','<form id="password-form" class="account-form"><label>当前密码<input id="old-password" type="password" autocomplete="current-password" required></label><label>新密码<input id="new-password" type="password" autocomplete="new-password" minlength="8" maxlength="128" required></label><p class="dialogcopy">修改后，其他设备需要重新登录。</p><p class="form-error" id="password-error"></p><button class="sendbtn" id="password-save">修改密码</button></form>');
    $('password-form').onsubmit = async event => { event.preventDefault(); const button = $('password-save'); button.disabled = true; try { await api('/api/auth/password',{method:'POST',body:{currentPassword:$('old-password').value,newPassword:$('new-password').value}}); if (dialogCurrent(version)) { $('old-password').value = ''; $('new-password').value = ''; $('dialog').close(); toast('密码已修改。'); } } catch (e) { if (dialogCurrent(version)) $('password-error').textContent = e.message; } finally { if (button.isConnected) button.disabled = false; } };
  }
  async function encryptionDetails(c = chat()) {
    if (!cryptoBox?.ready) { await unlockAndRefresh(); if (!cryptoBox?.ready) return; }
    if (!c) return securitySettings();
    const manifest = await cryptoBox.prepareChat(c,approveTrust);
    openDialog('这段对话的加密成员',`<p class="dialogcopy">以下收件人来自群主签名的成员记录，版本 ${manifest.payload.revision}。安全码发生变化时会停止发送，不会自动信任新密钥。</p>${manifest.payload.members.map(member => `<div class="security-code"><strong>${esc(person(member.userId,c).displayName)}${member.userId === user.id ? ' · 我' : ''}</strong><code>${esc(formatFingerprint(member.fingerprint))}</code></div>`).join('')}<p class="dialogcopy">第一次联系时，请通过另一条可信渠道核对安全码。新成员不能解密加入前的消息；服务器仍能看到成员、时间、大小与公开资料。</p>${canEdit(c) && c.kind === 'group' ? '<div class="dialogactions"><button class="secondarybtn" id="edit-encrypted-members">管理群成员</button></div>' : ''}`);
    if (canEdit(c) && c.kind === 'group') {
      const add = document.createElement('button'); add.className = 'sendbtn'; add.id = 'add-encrypted-members'; add.textContent = '添加群成员'; add.onclick = () => run(() => choosePeople('add',c)); $('dialogcontent').querySelector('.dialogactions').prepend(add);
    }
    if ($('edit-encrypted-members')) $('edit-encrypted-members').onclick = () => {
      const version = openDialog('管理加密群成员',`<p class="dialogcopy">取消勾选的成员将不再收到新消息的解密副本。已经收到的消息无法收回。新增成员请使用会话详情中的“添加成员”。</p><div class="choice-users">${manifest.payload.members.map(member => `<label class="choice-user"><input type="checkbox" data-keep-member="${esc(member.userId)}" checked ${member.userId === user.id ? 'disabled' : ''}><span>${esc(person(member.userId,c).displayName)}${member.userId === user.id ? ' · 群主' : ''}</span></label>`).join('')}</div><p class="form-error" id="members-error"></p><div class="dialogactions"><button class="sendbtn" id="save-encrypted-members">签名并保存成员</button></div>`);
      $('save-encrypted-members').onclick = async () => { const button = $('save-encrypted-members'); button.disabled = true; try { const ids = [...$('dialogcontent').querySelectorAll('[data-keep-member]:checked')].map(input => input.dataset.keepMember); const result = await cryptoBox.updateMembers(c,ids,approveTrust); if (!dialogCurrent(version)) return; upsertChat(result.chat); $('dialog').close(); if (current === c.id) showDetails(); queueRefresh(); } catch (e) { if (dialogCurrent(version)) $('members-error').textContent = e.message; } finally { if (button.isConnected) button.disabled = false; } };
    };
  }
  function securitySettings() {
    if (!cryptoBox) return;
    const box = cryptoBox, generation = epoch, vault = vaultVersion, selectedChat = chat();
    const version = openDialog('聊天加密与恢复',`<div class="settingsrow"><span>此设备</span><strong>${box.ready ? '已解锁' : '已锁定'}</strong></div><div class="security-code"><strong>我的安全码</strong><code id="own-fingerprint">${esc(formatFingerprint(box.fingerprint)) || '尚未建立加密身份'}</code><small>这是本账户完整的公钥指纹，可以与朋友核对；它不能解锁聊天。</small></div><div class="profile-avatar-tools"><button class="secondarybtn" id="fingerprint-copy" ${box.fingerprint ? '' : 'disabled'}>复制安全码</button>${selectedChat ? '<button class="secondarybtn" id="view-chat-security">核对当前会话安全码</button>' : ''}</div><div class="security-code"><strong>我的恢复码</strong><p id="local-recovery-mask" class="dialogcopy">${box.ready ? '恢复码已遮盖，点击下方按钮在本机查看。' : '先用原恢复码解锁此设备，再查看和复制。服务器和管理员无法找回恢复码。'}</p><textarea class="recovery-code" id="local-recovery-code" aria-label="我的恢复码" readonly spellcheck="false" autocomplete="off" hidden></textarea><small>恢复码不是登录密码。持有码的人可以解锁你的加密聊天，请勿分享。</small></div><div class="profile-avatar-tools"><button class="secondarybtn" id="local-recovery-reveal" aria-controls="local-recovery-code" aria-expanded="false">${box.ready ? '查看恢复码' : '解锁后查看恢复码'}</button><button class="secondarybtn" id="local-recovery-copy" disabled>复制恢复码</button></div><p class="dialogcopy">恢复码只在本机查看与复制，不会上传。加密恢复文件仍需要此码解锁；重置登录密码不能解锁聊天。</p><div class="settingsrow"><span>加密恢复文件</span><button id="backup-export" ${box.identity ? '' : 'disabled'}>下载备份</button></div><div class="settingsrow"><span>当前设备</span><button id="security-lock-toggle">${box.ready ? '立即锁定' : '解锁聊天'}</button></div><div class="settingsrow"><span>可信设备</span><button id="remember-device" ${box.ready ? '' : 'disabled'}>记住此设备</button></div><div class="settingsrow"><span>共用设备</span><button id="forget-device">忘记此设备并锁定</button></div><p class="dialogcopy">正文、引用和附件在客户端加密。账户资料、头像、会话名称、成员关系与时间大小属于服务器可见元数据。旧版历史会标记为未加密；AI 提问与指定前文直接交给配置的模型服务商，不能视为仅聊天双方可见。</p>`);
    const valid = () => dialogCurrent(version) && box === cryptoBox && generation === epoch && vault === vaultVersion;
    const codeField = $('local-recovery-code'), mask = $('local-recovery-mask'), reveal = $('local-recovery-reveal'), copy = $('local-recovery-copy');
    const hideCode = () => { codeField.value = ''; codeField.hidden = true; mask.hidden = false; copy.disabled = true; reveal.setAttribute('aria-expanded','false'); reveal.textContent = box.ready ? '查看恢复码' : '解锁后查看恢复码'; };
    // The recovery code stays in the unlocked CryptoBox until the user asks to
    // see it. Never put it in HTML, storage, logs, or a network request here.
    const onVisibility = () => { if (document.visibilityState === 'hidden') hideCode(); };
    document.addEventListener('visibilitychange',onVisibility);
    $('dialog').addEventListener('close',() => { hideCode(); document.removeEventListener('visibilitychange',onVisibility); },{once:true});
    reveal.onclick = () => run(async () => {
      if (!valid()) return;
      if (!box.ready) { $('dialog').close(); await unlockAndRefresh(); if (box === cryptoBox && generation === epoch && box.ready) securitySettings(); return; }
      if (!codeField.hidden) { hideCode(); return; }
      if (typeof box.code !== 'string' || !/^[0-9A-F]{64}$/.test(box.code)) throw new Error('本机未持有恢复码，请先锁定，再用原恢复码解锁。');
      codeField.value = box.code.match(/.{1,8}/g).join('-'); codeField.hidden = false; mask.hidden = true; copy.disabled = false; reveal.textContent = '隐藏恢复码'; reveal.setAttribute('aria-expanded','true');
    });
    copy.onclick = () => run(async () => {
      if (!valid() || !box.ready || codeField.hidden || !codeField.value) { hideCode(); return; }
      if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(codeField.value); if (valid() && box.ready) toast('恢复码已复制，请妥善保存，勿分享。'); }
      else { codeField.focus(); codeField.select(); toast('请复制已选中的恢复码，勿分享。'); }
    });
    $('fingerprint-copy').onclick = () => run(async () => {
      if (!valid() || !box.fingerprint) return;
      if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(formatFingerprint(box.fingerprint)); if (valid()) toast('安全码已复制，可通过可信渠道与朋友核对。'); }
      else { const range = document.createRange(); range.selectNodeContents($('own-fingerprint')); const selection = window.getSelection(); selection?.removeAllRanges(); selection?.addRange(range); toast('请复制已选中的完整安全码。'); }
    });
    if ($('view-chat-security')) $('view-chat-security').onclick = () => { hideCode(); run(() => encryptionDetails(selectedChat)); };
    $('backup-export').onclick = () => run(exportRecovery);
    $('security-lock-toggle').onclick = () => run(async () => { if (!valid()) return; hideCode(); if (box.ready) await lockChat(); else { await unlockAndRefresh(); if (box === cryptoBox && generation === epoch && box.ready) securitySettings(); } });
    $('remember-device').onclick = () => run(async () => { if (!valid() || !box.ready) return; await box.rememberDevice(); if (valid()) toast('已用本机密钥保护恢复码，此设备可自动解锁。'); });
    $('forget-device').onclick = () => run(async () => { await lockChat(true); toast('此设备已锁定，自动解锁信息已移除。'); });
  }
  function accountSettings() {
    if (!user) return;
    openDialog('账户与设置',`<div class="settingsrow"><span>账户</span><strong>@${esc(user.username)}${user.role === 'admin' ? ' · 管理员' : ''}</strong></div><form id="name-form" class="account-form"><label>昵称<input id="display-name" value="${esc(user.displayName)}" maxlength="40" required></label><button class="secondarybtn">保存昵称</button></form><div class="settingsrow"><span>我的头像</span><button id="avatarsettings">更换头像</button></div><div class="settingsrow"><span>字体与书法</span><button id="fontsettings">预览与选择</button></div><div class="settingsrow"><span>账户安全</span><button id="passwordsettings">修改密码</button></div><div class="settingsrow"><span>聊天加密与恢复</span><button id="encryption-settings">安全设置</button></div><div class="settingsrow"><span>山岚的长期记忆</span><button id="memory-settings">查看与管理</button></div>${user.role === 'admin' ? '<div class="settingsrow"><span>邀请朋友加入</span><button id="invite-settings">管理邀请码</button></div><div class="settingsrow"><span>山岚 AI</span><button id="ai-settings">模型设置</button></div>' : ''}<p class="dialogcopy">新消息以密文保存在服务器；本机草稿和待发送内容也按账户加密保存。</p><div class="dialogactions"><button class="secondarybtn" id="logout">退出登录</button></div>`);
    $('name-form').onsubmit = event => { event.preventDefault(); run(async () => { const result = await api('/api/me',{method:'PATCH',body:{displayName:$('display-name').value.trim()}}); updateUser(result.user); toast('昵称已保存。'); }); };
    $('avatarsettings').onclick = () => window.YuetiAvatar.open(); $('fontsettings').onclick = () => window.YuetiFonts.openPicker(); $('passwordsettings').onclick = passwordSettings;
    $('encryption-settings').onclick = securitySettings;
    $('memory-settings').onclick=()=>run(memorySettings);
    if(window.YuetiNative?.notifications) {
      $('memory-settings').closest('.settingsrow').insertAdjacentHTML('afterend','<div class="settingsrow"><span>消息提醒</span><button id="notification-settings">声音与后台通知</button></div>');
      $('notification-settings').onclick=()=>run(notificationSettings);
    }
    if ($('invite-settings')) $('invite-settings').onclick = () => run(invites); if ($('ai-settings')) $('ai-settings').onclick = () => run(aiSettings);
    $('logout').onclick = () => run(logoutAccount);
  }
  async function notificationSettings() {
    if(!user||!window.YuetiNative?.notifications)return;
    const account=user.id,generation=epoch,version=openDialog('消息提醒','<p class="dialogbusy">正在读取通知设置…</p>');
    const valid=()=>dialogCurrent(version)&&user?.id===account&&generation===epoch;
    const paint=state=>{
      if(!valid())return;
      const enabled=state?.enabled===true&&state?.permission==='granted';
      $('dialogcontent').innerHTML=`<p class="dialogcopy">收到新消息时显示系统通知，并按安卓的通知设置播放声音或震动。通知只显示“有新消息”，不展示聊天原文。</p><div class="settingsrow"><span>消息通知</span><strong>${enabled?'已开启':'未开启'}</strong></div><p class="dialogcopy">${state?.permission==='denied'?'安卓尚未允许通知，请在系统“应用 → 山水通讯 → 通知”中开启。':enabled?'后台消息提醒已运行，通知栏会保留连接提示。':'开启后，安卓会询问是否允许消息通知。'}</p><button id="notification-toggle" class="${enabled?'secondarybtn':'sendbtn'}">${enabled?'关闭消息提醒':'开启消息提醒'}</button><p id="notification-error" class="form-error" role="alert"></p><p class="dialogcopy">你正在阅读的会话和免打扰会话不重复提醒。请允许山水通讯后台运行；系统强行停止应用、省电限制或网络中断时，提醒可能延迟。</p>`;
      $('notification-toggle').onclick=async()=>{
        if(!valid())return;const button=$('notification-toggle');button.disabled=true;
        try{const next=await syncNativeNotifications({enabled:!enabled});if(valid())paint(next);}
        catch(error){if(valid()){$('notification-error').textContent=error.message||'未能更新消息提醒，请检查系统通知权限。';button.disabled=false;}}
      };
    };
    try{paint(await syncNativeNotifications());}catch(error){if(valid())$('dialogcontent').innerHTML=`<p class="form-error">${esc(error.message||'无法读取系统通知设置。')}</p>`;}
  }
  function updateUser(value) { user = {...value,id:String(value.id)}; chats = chats.map(c => ({...c,members:c.members.map(p => p.id === user.id ? user : p)})); paintSelf(); renderList(); renderMessages(); if ($('app').classList.contains('show-details')) renderDetails(); }
  $('settings').onclick = accountSettings; $('self-avatar').onclick = () => { if (user) window.YuetiAvatar.open(); };
  $('reconnect').onclick = () => { connectEvents(); run(refreshAll); };
  document.addEventListener('keydown',event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && user) { event.preventDefault(); openSearch(); } if (event.key === 'Escape') { hideDetails(); $('appearance-menu').open = false; if (document.body.classList.contains('art-focus')) $('focus-scene').click(); } });
  document.addEventListener('visibilitychange',() => { refreshNativeNotificationView();if (document.visibilityState === 'visible' && user) { queueRefresh(); markRead(); } });
  window.addEventListener('online',() => { if (user) { connectEvents(); queueRefresh(); } }); window.addEventListener('offline',() => setConnection(false)); window.addEventListener('resize',resizeComposer);
  window.addEventListener('pagehide',storeState); window.addEventListener('beforeunload',storeState);
  if (sessionChannel) sessionChannel.onmessage = event => { if (!['changed','signed-out'].includes(event.data?.type)) return; if (current) drafts[current] = $('input').value; storeState(); clearSession(); if (event.data.type === 'signed-out') showAuth('login'); else run(bootstrap); };
  document.fonts.ready.then(resizeComposer); document.fonts.addEventListener('loadingdone',resizeComposer);
  // Appearance belongs to this device; accounts, drafts and pending messages never share storage keys.
  let appearance = {}; try { appearance = JSON.parse(localStorage.getItem('shanshui:appearance:v1') || '{}'); } catch {}
  function saveAppearance() { try { localStorage.setItem('shanshui:appearance:v1',JSON.stringify(appearance)); } catch {} }
  const scenes = [
    {id:'ink',name:'烟雨山水',detail:'墨山与一抹朱红',src:'assets/reference-mountains.png'}, {id:'traveler',name:'江湖行旅',detail:'旅人、马与飞鸟',src:'assets/reference-traveler.png'},
    {id:'meeting',name:'水边相逢',detail:'相逢与倒影',src:'assets/reference-meeting.png'}, {id:'walking',name:'江岸同行',detail:'牵马与水中倒影',src:'assets/reference-walking.png'}, {id:'rider',name:'远山归途',detail:'江岸与远行',src:'assets/reference-rider.png'},
    {id:'zha',name:'疏林远水',detail:'查士标 · 四季山水图册，1684',src:'assets/zha-ni-zan.jpg'}, {id:'chen',name:'竹石清溪',detail:'陈洪绶 · 仿古山水册',src:'assets/chen-ni-zan.jpg'}, {id:'zhai',name:'春溪放舟',detail:'翟大坤 · 山水，1775',src:'assets/zhai-landscape.jpg'},
    {id:'monet',name:'睡莲水光',detail:'克劳德·莫奈 · 睡莲，1906',src:'assets/monet-water-lilies.jpg'}, {id:'starry',name:'罗讷河星夜',detail:'文森特·梵高，1888',src:'assets/van-gogh-rhone.jpg'}
  ];
  function applyTheme() { document.body.classList.toggle('dark',appearance.theme === 'dark'); $('theme').textContent = appearance.theme === 'dark' ? '日景' : '夜景'; }
  let weatherMode = ['snow','petals','none'].includes(appearance.weather) ? appearance.weather : 'snow', moving = typeof appearance.moving === 'boolean' ? appearance.moving : !matchMedia('(prefers-reduced-motion: reduce)').matches;
  function updateSceneControls() { const label = weatherMode === 'snow' ? '飘雪' : weatherMode === 'petals' ? '落樱' : '无落花'; $('weather').innerHTML = `<span aria-hidden="true">${weatherMode === 'snow' ? '❄' : weatherMode === 'petals' ? '✿' : '·'}</span>${label}`; $('weather').setAttribute('aria-label',`当前${label}，点击切换`); $('motion').textContent = moving ? '静止' : '流动'; $('motion').setAttribute('aria-pressed',String(moving)); window.YuetiScene?.setWeather(weatherMode); window.YuetiScene?.setMotion(moving); }
  $('scene-picker').onclick = () => { openDialog('选一幅画，住进山水里',`<div class="scene-grid">${scenes.map(s => `<button class="scene-card" data-scene-choice="${s.id}" aria-pressed="${document.body.dataset.scene === s.id}"><img src="${s.src}" alt="${s.name}" loading="lazy"><span>${s.name}</span><small>${s.detail}</small></button>`).join('')}</div><p class="dialogcopy"><a href="artwork-sources.html" target="_blank" rel="noopener">查看画作与字库来源</a></p>`); $('dialog').classList.add('scene-dialog'); $('dialogcontent').querySelectorAll('[data-scene-choice]').forEach(b => { b.onclick = () => { appearance.scene = b.dataset.sceneChoice; document.body.dataset.scene = appearance.scene; appearance.theme = appearance.scene === 'starry' ? 'dark' : 'light'; applyTheme(); saveAppearance(); $('dialog').close(); }; }); };
  $('weather').onclick = () => { weatherMode = weatherMode === 'snow' ? 'petals' : weatherMode === 'petals' ? 'none' : 'snow'; appearance.weather = weatherMode; saveAppearance(); updateSceneControls(); };
  $('motion').onclick = () => { moving = !moving; appearance.moving = moving; saveAppearance(); updateSceneControls(); };
  $('focus-scene').onclick = () => { $('appearance-menu').open = false; const focused = document.body.classList.toggle('art-focus'); $('focus-scene').textContent = focused ? '聊天' : '看画'; $('focus-scene').setAttribute('aria-pressed',String(focused)); };
  $('theme').onclick = () => { appearance.theme = appearance.theme === 'dark' ? 'light' : 'dark'; applyTheme(); saveAppearance(); };
  $('font-shortcut').onclick = () => { $('appearance-menu').open = false; window.YuetiFonts.openPicker(); };
  document.addEventListener('click',event => { if (!$('appearance-menu').contains(event.target)) $('appearance-menu').open = false; });
  document.body.dataset.scene = scenes.some(s => s.id === appearance.scene) ? appearance.scene : 'ink'; applyTheme(); updateSceneControls(); window.addEventListener('yueti-scene-ready',updateSceneControls);
  window.YuetiFonts?.init({preferences:appearance.typography,onChange(preferences) { appearance.typography = preferences; saveAppearance(); }});
  window.YuetiAvatar?.init({api,getUser:() => user,onChange:updateUser,openDialog,toast,escape:esc,safeURL});
  paintIcons(); run(bootstrap);
})();
