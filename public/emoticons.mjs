export const EMOJI_CHOICES = Object.freeze([
  ['😀','开心'],['😄','大笑'],['😁','露齿笑'],['😊','微笑'],['🥰','喜欢'],['😍','心动'],['😘','亲亲'],['😎','酷'],
  ['🤔','思考'],['🧐','仔细看看'],['😅','不好意思'],['😂','笑哭'],['🤣','笑得打滚'],['🥹','感动'],['🥲','苦笑'],['😭','大哭'],
  ['😤','气鼓鼓'],['😡','生气'],['😱','惊讶'],['😴','困了'],['🤤','馋了'],['🤗','抱抱'],['🫡','收到'],['🤝','握手'],
  ['👍','赞'],['👎','不赞同'],['👏','鼓掌'],['🙏','谢谢'],['💪','加油'],['✌️','胜利'],['👋','挥手'],['👌','好的'],
  ['❤️','爱心'],['💕','两颗心'],['💔','心碎'],['✨','闪亮'],['🎉','庆祝'],['🌹','玫瑰'],['🌸','花朵'],['🌄','日出'],
  ['🐱','猫咪'],['🐶','小狗'],['🐼','熊猫'],['🐧','企鹅'],['🍵','喝茶'],['☕','咖啡'],['🍰','蛋糕'],['🍜','吃面']
].map(([text,label]) => Object.freeze({text,label})));
const MAX_STICKERS = 80, MAX_STICKER_BYTES = 3 * 1024 * 1024, MAX_TOTAL_BYTES = 40 * 1024 * 1024;

export function validateRasterImage(value,declaredMime = '',maxBytes = 20 * 1024 * 1024) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  if (!bytes.length || bytes.length > maxBytes) throw Error('图片为空或超过大小限制。');
  let mime = '';
  if (bytes.length >= 24 && [137,80,78,71,13,10,26,10].every((byte,index) => bytes[index] === byte)) mime = 'image/png';
  else if (bytes.length >= 4 && bytes[0] === 255 && bytes[1] === 216 && bytes.at(-2) === 255 && bytes.at(-1) === 217) mime = 'image/jpeg';
  else if (bytes.length >= 13 && ['GIF87a','GIF89a'].includes(String.fromCharCode(...bytes.slice(0,6)))) mime = 'image/gif';
  else if (bytes.length >= 20 && String.fromCharCode(...bytes.slice(0,4)) === 'RIFF' && String.fromCharCode(...bytes.slice(8,12)) === 'WEBP') mime = 'image/webp';
  if (!mime) throw Error('请选择 PNG、JPEG、WebP 或 GIF 图片，不支持 SVG 或伪装的图片文件。');
  const declared = String(declaredMime || '').toLowerCase().split(';')[0];
  if (declared && declared !== 'application/octet-stream' && declared !== mime && !(mime === 'image/jpeg' && declared === 'image/jpg')) throw Error('图片格式与加密记录不一致，已停止预览。');
  return mime;
}
function encode(bytes) { let binary = ''; for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset,offset + 8192)); return btoa(binary); }
function decode(value) {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_STICKER_BYTES / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw Error('表情文件格式无效。');
  const binary = atob(value), bytes = new Uint8Array(binary.length); for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index); return bytes;
}
async function digest(bytes) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(byte => byte.toString(16).padStart(2,'0')).join(''); }
function databaseStorage() {
  let opening;
  const database = () => opening ||= new Promise((resolve,reject) => {
    const request = indexedDB.open('shanshui-emoticons-v1',1);
    request.onupgradeneeded = () => { const store = request.result.createObjectStore('encrypted',{keyPath:'key'}); store.createIndex('scope','scope'); };
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(Error('无法打开本机表情存储。'));
  });
  async function operation(mode,action) {
    const db = await database();
    return new Promise((resolve,reject) => {
      const transaction = db.transaction('encrypted',mode), store = transaction.objectStore('encrypted'); let result;
      const request = action(store); request.onsuccess = () => { result = request.result; };
      transaction.oncomplete = () => resolve(result); transaction.onerror = transaction.onabort = () => reject(Error('表情尚未保存，本机存储空间可能不足。'));
    });
  }
  return {read:scope => operation('readonly',store => store.index('scope').getAll(scope,MAX_STICKERS + 1)),put:record => operation('readwrite',store => store.put(record)),remove:key => operation('readwrite',store => store.delete(key))};
}

// Only ciphertext and public account/server scope are durable. Neither image
// bytes, names nor preview URLs are written to localStorage or IndexedDB.
export class EncryptedEmoticonStore {
  constructor({box,serverId,userId,isCurrent = () => true,storage}) {
    this.box = box; this.scope = `server:${serverId}:account:${userId}`; this.storage = storage || databaseStorage(); this.isCurrent = isCurrent;
    this.items = null; this.loading = null; this.alive = true; this.skipped = 0; this.operation = Promise.resolve();
  }
  guard() { if (!this.alive || !this.box?.ready || !this.isCurrent()) throw Error('聊天已锁定或账户已切换，请重新打开表情。'); }
  lock() { this.alive = false; if (this.items) this.items.forEach(item => item.bytes.fill(0)); this.items = null; }
  async list() {
    this.guard(); if (this.items) return this.items;
    if (this.loading) return this.loading;
    this.loading = (async () => {
      const records = await this.storage.read(this.scope); this.guard(); const items = []; let total = 0;
      for (const record of records) {
        this.guard();
        try {
          const item = await this.box.decryptLocal(record.ciphertext); this.guard();
          if (item?.purpose !== 'emoticon' || item.id !== record.id || typeof item.name !== 'string' || item.name.length > 255) throw Error('Invalid encrypted sticker.');
          const bytes = decode(item.data), mime = validateRasterImage(bytes,item.mime,MAX_STICKER_BYTES); total += bytes.length;
          if (items.length >= MAX_STICKERS || total > MAX_TOTAL_BYTES) throw Error('Sticker limit.');
          items.push({id:item.id,name:item.name,mime,bytes,hash:await digest(bytes)}); this.guard();
        } catch (error) { this.guard(); this.skipped++; }
      }
      this.guard(); this.items = items; return items;
    })();
    try { return await this.loading; } finally { this.loading = null; }
  }
  async add(value,name = '收藏的表情') {
    const operation = async () => {
      this.guard(); const bytes = new Uint8Array(value), mime = validateRasterImage(bytes,'',MAX_STICKER_BYTES), hash = await digest(bytes); this.guard();
      const items = await this.list(); this.guard(); const existing = items.find(item => item.hash === hash); if (existing) return {item:existing,alreadySaved:true};
      if (items.length >= MAX_STICKERS || items.reduce((total,item) => total + item.bytes.length,0) + bytes.length > MAX_TOTAL_BYTES) throw Error('表情收藏已满，请先删除不再使用的表情。最多 80 张、合计 40 MB。');
      const id = crypto.randomUUID(), cleanName = String(name).slice(0,255) || '收藏的表情';
      const ciphertext = await this.box.encryptLocal({purpose:'emoticon',id,name:cleanName,mime,data:encode(bytes)}); this.guard();
      await this.storage.put({key:`${this.scope}:${id}`,scope:this.scope,id,ciphertext}); this.guard();
      const item = {id,name:cleanName,mime,bytes,hash}; items.push(item); return {item,alreadySaved:false};
    };
    const result = this.operation.then(operation,operation); this.operation = result.catch(()=>{}); return result;
  }
  async remove(id) {
    const operation = async () => { this.guard(); const items = await this.list(); this.guard(); await this.storage.remove(`${this.scope}:${id}`); this.guard(); const index = items.findIndex(item => item.id === id); if (index >= 0) { items[index].bytes.fill(0); items.splice(index,1); } };
    const result = this.operation.then(operation,operation); this.operation = result.catch(()=>{}); return result;
  }
}
