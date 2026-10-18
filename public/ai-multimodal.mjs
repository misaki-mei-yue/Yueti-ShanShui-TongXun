import {normalizeAIBaseUrl,validateAIKey,rasterMime,validateVisionDataURL} from './ai-direct.mjs';

const MAX_IMAGE=20*1024*1024,MAX_JSON=28*1024*1024;
const fail=(message,code='AI_IMAGE_INVALID',status)=>Object.assign(new Error(message),{diagnostics:{code,...(status?{upstreamStatus:status}:{})}});
const cancelled=signal=>{if(signal?.aborted)throw new DOMException('请求已取消','AbortError');};
function base64(bytes){let text='';for(let offset=0;offset<bytes.length;offset+=32768)text+=String.fromCharCode(...bytes.subarray(offset,offset+32768));return btoa(text);}
export function imageResultURL(value,{chatOrigin=globalThis.location?.origin}={}) {
  if(typeof value!=='string'||value.length>4096||/[\x00-\x20\x7f\\]/.test(value))throw fail('生图服务返回的图片地址无效。');
  let url;try{url=new URL(value);}catch{throw fail('生图服务返回的图片地址无效。');}
  if(url.protocol!=='https:'||url.username||url.password||url.hash||url.port==='0'||url.origin===chatOrigin||url.hostname.length>253||!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(url.hostname)||/(?:^|\.)(?:localhost|local|internal|lan)$/.test(url.hostname))throw fail('图片必须来自独立的 HTTPS 服务域名。');
  return url.href;
}
async function bounded(response,limit,signal){
  cancelled(signal);const reader=response.body?.getReader();if(!reader)throw fail('生图服务没有返回图片。');
  const parts=[];let length=0;
  try{for(;;){cancelled(signal);const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>limit){await reader.cancel();throw fail('图片超过大小限制。','AI_IMAGE_TOO_LARGE');}parts.push(value);}const bytes=new Uint8Array(length);let at=0;for(const part of parts){bytes.set(part,at);at+=part.length;}return bytes;}
  catch(error){await reader.cancel().catch(()=>{});throw error;}
  finally{for(const part of parts)part.fill(0);reader.releaseLock();}
}
function verifyImage(bytes){const mime=rasterMime(bytes);if(!mime||bytes.length>MAX_IMAGE){bytes.fill(0);throw fail('生图服务没有返回有效的 PNG、JPEG 或 WebP 图片。');}return {bytes,mime,name:'山岚创作.'+({'image/png':'png','image/jpeg':'jpg','image/webp':'webp'}[mime])};}
export function imageGenerationRequest(credential,prompt){
  normalizeAIBaseUrl(credential?.baseUrl);validateAIKey(credential?.key);
  if(credential?.enabled!==true||credential.mode!=='shared_direct'||credential.apiFormat!=='images_generations')throw fail('管理员尚未启用生图模型。','AI_IMAGE_DISABLED');
  if(typeof credential.model!=='string'||!/^[A-Za-z0-9_.:/-]{1,200}$/.test(credential.model)||typeof prompt!=='string'||!prompt.trim()||prompt.length>8000)throw fail('请使用不超过 8000 字的生图描述。');
  return {model:credential.model,prompt:prompt.trim(),n:1,size:'1024x1024',response_format:'b64_json'};
}
export async function generateImages(credential,prompt,{signal,fetcher=globalThis.fetch,native=globalThis.YuetiNative}={}){
  const body=imageGenerationRequest(credential,prompt),baseUrl=normalizeAIBaseUrl(credential.baseUrl);
  cancelled(signal);const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),120000),stop=()=>controller.abort();signal?.addEventListener('abort',stop,{once:true});
  let imageBytes;
  try{
    const local=globalThis.location?.protocol==='shanshui:';
    const response=native?.requestAI?await native.requestAI({operation:'images',body,key:credential.key,baseUrl,signal:controller.signal}):await fetcher(local?'/_native/ai':baseUrl+'/images/generations',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+credential.key,...(local?{'X-Shanshui-AI-BaseUrl':baseUrl,'X-Shanshui-AI-Operation':'images'}:{})},body:JSON.stringify(body),credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal:controller.signal});
    if(response.redirected||!response.ok){await response.body?.cancel();throw fail(response.status===401||response.status===403?'生图 Key 无效或模型未授权，请联系管理员。':response.status===402?'生图服务余额不足。':response.status===429?'生图请求过于频繁，请稍后再试。':'生图请求未完成，请检查模型配置。','AI_IMAGE_UPSTREAM',response.status);}
    if(!(response.headers.get('content-type')||'').toLowerCase().startsWith('application/json')){await response.body?.cancel();throw fail('生图服务返回格式无效。');}
    const bytes=await bounded(response,MAX_JSON,controller.signal);let result;try{result=JSON.parse(new TextDecoder().decode(bytes));}finally{bytes.fill(0);}
    const item=result?.data?.[0];if(!item)throw fail('生图服务没有返回图片。');
    if(typeof item.b64_json==='string'){
      const encoded=item.b64_json;if(!encoded.length||encoded.length>Math.ceil(MAX_IMAGE/3)*4||encoded.length%4||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))throw fail('生图服务的图片编码无效。');
      const raw=atob(encoded);imageBytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
    }else{
      const url=imageResultURL(item.url);cancelled(controller.signal);
      const download=native?.requestAI?await native.requestAI({operation:'image-download',url,signal:controller.signal}):await fetcher(local?'/_native/ai':url,{method:local?'POST':'GET',headers:local?{'X-Shanshui-AI-Operation':'image-download','X-Shanshui-AI-ImageUrl':url}:{},credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal:controller.signal});
      if(download.redirected||!download.ok){await download.body?.cancel();throw fail('生成图片下载失败，请重试。','AI_IMAGE_DOWNLOAD');}
      if(!['image/png','image/jpeg','image/webp','application/octet-stream'].includes((download.headers.get('content-type')||'').split(';')[0].trim().toLowerCase())){await download.body?.cancel();throw fail('生成图片下载格式无效。');}
      imageBytes=await bounded(download,MAX_IMAGE,controller.signal);
    }
    cancelled(controller.signal);const image=verifyImage(imageBytes);imageBytes=null;return {model:credential.model,images:[image]};
  }catch(error){if(imageBytes)imageBytes.fill(0);if(signal?.aborted)throw new DOMException('请求已取消','AbortError');if(controller.signal.aborted)throw fail('生图连接超时，请稍后再试。','AI_IMAGE_TIMEOUT');if(error.diagnostics)throw error;throw fail('此设备无法直连生图服务，请检查网络和模型接口；网页版还需要服务商允许跨域访问。','AI_IMAGE_NETWORK');}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',stop);}
}

export async function prepareVisionMessage(messages,file,{signal}={}){
  if(!Array.isArray(messages)||!messages.length||messages.at(-1)?.role!=='user'||typeof messages.at(-1).content!=='string')throw fail('请先填写要问山岚的问题。');
  if(!file||typeof file.arrayBuffer!=='function'||!file.size||file.size>MAX_IMAGE)throw fail('识图文件需小于 20 MiB。');
  cancelled(signal);const input=new Uint8Array(await file.arrayBuffer());let bitmap,canvas;
  try{
    const mime=rasterMime(input);if(!mime)throw fail('识图支持 PNG、JPEG 和 WebP。');
    cancelled(signal);bitmap=await createImageBitmap(new Blob([input],{type:mime}));cancelled(signal);
    if(!bitmap.width||!bitmap.height||bitmap.width*bitmap.height>32000000)throw fail('图片尺寸过大，请先缩小图片。');
    const scale=Math.min(1,1600/Math.max(bitmap.width,bitmap.height));canvas=document.createElement('canvas');canvas.width=Math.max(1,Math.round(bitmap.width*scale));canvas.height=Math.max(1,Math.round(bitmap.height*scale));
    const context=canvas.getContext('2d');context.fillStyle='#fff';context.fillRect(0,0,canvas.width,canvas.height);context.drawImage(bitmap,0,0,canvas.width,canvas.height);
    const blob=await new Promise((resolve,reject)=>canvas.toBlob(value=>value?resolve(value):reject(fail('无法读取图片。')),'image/jpeg',.86));cancelled(signal);
    if(blob.size>4*1024*1024)throw fail('图片处理后仍过大，请选择较小图片。');
    const bytes=new Uint8Array(await blob.arrayBuffer());let data;try{data='data:image/jpeg;base64,'+base64(bytes);validateVisionDataURL(data);}finally{bytes.fill(0);}cancelled(signal);
    return [...messages.slice(0,-1).map(m=>({role:m.role,content:m.content})),{role:'user',content:[{type:'text',text:messages.at(-1).content},{type:'image_url',image_url:{url:data}}]}];
  }finally{input.fill(0);bitmap?.close();if(canvas){canvas.width=1;canvas.height=1;}}
}
