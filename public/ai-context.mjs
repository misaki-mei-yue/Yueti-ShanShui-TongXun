// These preferences contain only local sharing choices, never message contents.
const MAX_CHARACTERS = 48000;
const MAX_MESSAGES = 200;
const MAX_EXCLUSIONS = 5000;

function sequence(value) {
  if (typeof value !== 'number' && !(typeof value === 'string' && /^\d+$/.test(value))) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function messageId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  return typeof value === 'string' && value.length > 0 && value.length <= 256 ? value : null;
}

export function normalizeAIPreferences(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const excludedIds = [];
  const seen = new Set();
  if (Array.isArray(source.excludedIds)) {
    for (const value of source.excludedIds) {
      const id = messageId(value);
      if (id === null || seen.has(id)) continue;
      seen.add(id); excludedIds.push(id);
      if (excludedIds.length === MAX_EXCLUSIONS) break;
    }
  }
  return {mode:source.mode === 'auto' ? 'auto' : 'ask',excludedIds,cutoffSeq:sequence(source.cutoffSeq) ?? 0,search:source.search === true};
}

function budget(value,maximum) {
  return Number.isSafeInteger(value) && value > 0 ? Math.min(value,maximum) : maximum;
}

function label(value) {
  return typeof value === 'string' ? value.replace(/[\r\n]+/g,' ').trim().slice(0,120) : '';
}

// A mention or a leading /N is the user's explicit request to call the AI.
// Keep the original message in encrypted chat; only this parsed prompt is relayed.
export function parseAIInvocation(value,options = {}) {
  const text = typeof value === 'string' ? value.trim() : '';
  const mention = /(^|[^A-Za-z0-9_])(@(?:山岚|ai))(?=$|\s|[，。！？,.!?：:/])/iu.exec(text);
  const mentionIndex = mention ? mention.index + mention[1].length : -1;
  let prompt = mention ? `${text.slice(0,mentionIndex)} ${text.slice(mentionIndex + mention[2].length)}`.trim() : text;
  if (mentionIndex === 0) prompt = prompt.replace(/^[，,：:\s]+/u,'');
  const command = /^\/(\d+)(?=$|\s|[，。！？,.!?：:])/u.exec(prompt);
  const explicit = !!mention || !!command;
  const requested = !!text && (explicit || options.direct === true);
  let historyCount = explicit ? 0 : MAX_MESSAGES - 1;
  if (command) {
    historyCount = Number(command[1]);
    if (!Number.isSafeInteger(historyCount) || historyCount < 1 || historyCount >= MAX_MESSAGES) {
      return {requested,explicit,historyCount:0,prompt:'',error:'前文条数需为 1 至 199，例如 @山岚 /10 你的问题。'};
    }
    prompt = prompt.slice(command[0].length).replace(/^[，,：:\s]+/u,'');
  }
  return {requested,explicit,historyCount,prompt:prompt || (historyCount > 0 ? '请根据这段聊天继续回复。' : '你好。'),error:''};
}

export function isShareableAIMessage(message) {
  if (!message || typeof message !== 'object' || message._decrypted !== true ||
      message.decryptError || message.pending || typeof message.text !== 'string' || !message.text.trim()) return false;
  // Older server releases stored AI errors/partial output as message rows.
  // Keep the record visible in chat, but never treat it as an assistant answer.
  return !['failed','error','stopped','cancelled','canceled','generating','pending','running'].includes(message.aiStatus);
}

/**
 * Build a bounded, temporary model context from this device's verified plaintext.
 * This does not decrypt messages, fetch older history, or create learned memory.
 * Build before sending the current message, or supply currentMessageId/currentClientId
 * when that message already exists in history. Content-based deduplication would lose
 * an intentional repeat (for example, a second "hello"), so only IDs are deduplicated.
 */
export function buildAIContext(messages,currentText,preference,options = {}) {
  const settings = normalizeAIPreferences(preference);
  const excluded = new Set(settings.excludedIds);
  const safeOptions = options && typeof options === 'object' && !Array.isArray(options) ? options : {};
  const maxChars = budget(safeOptions.maxChars,MAX_CHARACTERS);
  const maxMessages = budget(safeOptions.maxMessages,MAX_MESSAGES);
  const chatId = safeOptions.chatId === undefined ? null : String(safeOptions.chatId);
  const currentId = messageId(safeOptions.currentMessageId);
  const currentClientId = messageId(safeOptions.currentClientId);
  const available = [];
  const seen = new Set();
  let excludedCount = 0;

  const sorted = (Array.isArray(messages) ? messages : [])
    .map((message,index) => ({message,index,seq:sequence(message?.seq)}))
    .filter(({message}) => message && typeof message === 'object')
    .sort((a,b) => (a.seq ?? -1) - (b.seq ?? -1) || a.index - b.index);
  const raw = [];
  const rawIds = new Set();
  const beforeSeq = sequence(safeOptions.beforeSeq);
  for (let index = sorted.length - 1; index >= 0; index--) {
    const item = sorted[index], {message,seq} = item;
    if (message.pending || (chatId !== null && String(message.chatId) !== chatId) ||
        (beforeSeq !== null && (seq === null || seq >= beforeSeq))) continue;
    const id = messageId(message.id);
    if ((currentId !== null && id === currentId) ||
        (currentClientId !== null && messageId(message.clientId) === currentClientId)) continue;
    if (id !== null && rawIds.has(id)) continue;
    if (id !== null) rawIds.add(id);
    raw.push(item);
  }
  raw.reverse();
  // Cut the requested chronological window BEFORE exclusions. A hidden, failed,
  // locked or attachment-only row must not cause older messages to be shared.
  const historyCount = Number.isSafeInteger(safeOptions.historyCount) && safeOptions.historyCount >= 0
    ? Math.min(safeOptions.historyCount,MAX_MESSAGES - 1) : null;
  const window = historyCount === null ? raw : historyCount === 0 ? [] : raw.slice(-historyCount);
  // Prefer the latest copy if a refreshed message appears more than once.
  for (let index = window.length - 1; index >= 0; index--) {
    const {message,seq} = window[index];
    if (!isShareableAIMessage(message) ||
        (chatId !== null && String(message.chatId) !== chatId)) continue;
    const id = messageId(message.id);
    if ((currentId !== null && id === currentId) ||
        (currentClientId !== null && messageId(message.clientId) === currentClientId)) continue;
    if (id !== null && seen.has(id)) continue;
    if (id !== null) seen.add(id);
    if ((id !== null && excluded.has(id)) || (settings.cutoffSeq > 0 && seq !== null && seq <= settings.cutoffSeq)) {
      excludedCount++; continue;
    }
    const role = message.kind === 'ai-result' || message.senderId === 'ai' ? 'assistant' : 'user';
    const name = role === 'user' && typeof safeOptions.speakerName === 'function' ? label(safeOptions.speakerName(message)) : '';
    available.push({id,role,content:name ? `${name}：${message.text}` : message.text});
  }
  available.reverse();

  const current = typeof currentText === 'string' && currentText.trim() ? currentText : '';
  const currentName = label(safeOptions.currentSpeakerName);
  const currentContent = current ? currentName ? `${currentName}：${current}` : current : '';
  const prompt = currentContent ? {role:'user',content:currentContent.slice(0,maxChars)} : null;
  let truncated = currentContent.length > maxChars;
  let chars = prompt?.content.length ?? 0;
  let remaining = maxMessages - (prompt ? 1 : 0);
  const selected = [];
  // Keep a contiguous recent window. Skipping a large recent message would make
  // older context look current, so stop at the first message that cannot fit.
  for (let index = available.length - 1; index >= 0; index--) {
    const item = available[index];
    if (remaining <= 0 || chars + item.content.length > maxChars) break;
    selected.push(item); chars += item.content.length; remaining--;
  }
  selected.reverse();
  const omittedCount = available.length - selected.length;
  truncated ||= omittedCount > 0;
  return {
    messages:[...selected.map(({role,content}) => ({role,content})),...(prompt ? [prompt] : [])],
    includedIds:selected.map(item => item.id).filter(id => id !== null),
    omittedCount,excludedCount,truncated,
  };
}
