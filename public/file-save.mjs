const MAX_WRITE = 4 * 1024 * 1024;
const aborted = () => new DOMException('文件保存已取消。','AbortError');
function filename(value) { return String(value || '聊天文件').replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').slice(0,160) || '聊天文件'; }
function checkSignal(signal) { if(signal?.aborted)throw aborted(); }
function guarded(sink,{size,signal}) {
  let ended=false,busy=false,written=0,aborting;
  const cancel=()=>{if(!ended){ended=true;signal?.removeEventListener('abort',cancel);aborting=Promise.resolve().then(()=>sink.abort()).catch(()=>{});}};
  signal?.addEventListener('abort',cancel,{once:true});
  if(signal?.aborted)cancel();
  return Object.freeze({
    async write(bytes) {
      if(ended)throw aborted(); checkSignal(signal);
      if(busy)throw new Error('请等待上一块文件写入完成。');
      if(!(bytes instanceof Uint8Array)||bytes.byteLength>MAX_WRITE||!Number.isSafeInteger(written+bytes.byteLength)||size!==undefined&&written+bytes.byteLength>size)throw new Error('保存数据大小无效。');
      busy=true;
      try{await sink.write(bytes);if(ended)throw aborted();checkSignal(signal);written+=bytes.byteLength;return {written};}
      catch(error){cancel();throw error;}
      finally{busy=false;}
    },
    async close() {
      if(ended)throw aborted();checkSignal(signal);
      if(busy)throw new Error('文件仍在写入。');
      try{
        if(size!==undefined&&written!==size)throw new Error('文件未完整接收，已取消保存。');
        const result=await sink.close();ended=true;signal?.removeEventListener('abort',cancel);return result||{saved:true};
      }catch(error){cancel();throw error;}
    },
    async abort(){cancel();await aborting;}
  });
}
/** A bounded, sequential sink for decrypted attachment chunks. A cancelled
 * chooser returns null; callers must not begin downloading until it resolves. */
export async function createFileSink({name,mime='application/octet-stream',size,signal}={}) {
  if(size!==undefined&&(!Number.isSafeInteger(size)||size<0))throw new Error('文件大小无效。');
  checkSignal(signal);name=filename(name);
  const environment=globalThis.window||globalThis;
  let sink;
  if(environment.YuetiNative?.openFileSink) sink=await environment.YuetiNative.openFileSink({name,mime,size,signal});
  else if(typeof environment.showSaveFilePicker==='function') {
    let handle;
    try{handle=await environment.showSaveFilePicker({suggestedName:name});}
    catch(error){if(error.name==='AbortError')return null;throw error;}
    checkSignal(signal);
    const writer=await handle.createWritable();
    sink={write:bytes=>writer.write(bytes),close:async()=>{await writer.close();return {saved:true};},abort:()=>writer.abort()};
  } else throw new Error('此浏览器不支持大文件分块保存，请使用山水通讯 PC / 安卓客户端，或新版 Chrome / Edge 浏览器。');
  if(!sink)return null;
  if(signal?.aborted){await sink.abort().catch(()=>{});throw aborted();}
  return guarded(sink,{size,signal});
}
