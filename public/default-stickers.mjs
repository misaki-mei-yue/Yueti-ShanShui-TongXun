import { validateRasterImage } from './emoticons.mjs';

// Original raster assets are shared by every account. Names and hashes contain
// only packaged asset metadata; no source download URL or credential is stored.
export const DEFAULT_STICKERS = Object.freeze([
  ['01','开心',72221,'62578ae9de57629f5b7795b7cd9f357e80d8a0c3a9cc810cc6b10a5a13d95fc6'],
  ['02','哭哭',77373,'b301a61c267b24363aed70696e76f0fc507915e80196c4819379b1f1fa7cad55'],
  ['03','点赞',69137,'0ec33a78df7ab628bbaa69cbaee6f241dde2a74d101f1a75ba432353afb87416'],
  ['04','惊讶',67795,'6b9f8870fefcec90d3d09c8c892ee0a1b42d8d517513657a9906fa6d0367f726'],
  ['05','大哭',93466,'e0c02754e2d1afbf1b857954c45935bcced2aa38dd55645da086ceae3ca9bfd5'],
  ['06','拜托',71819,'d00a51ca208f8d4705bf61455bc3ca39ac91467cedb4391fc4bd1d01da8c043a'],
  ['07','困了',68143,'a71c2eca4d40b9f5eda242db5c55a1c41ee6cf9d21d22de41357c7a220f734b8'],
  ['08','疑惑',80542,'0ae4958dcad887eb26bd3756e3d4d336a2f48d005ba88ede5fd2e3abc78d7f78'],
  ['09','你好',60643,'64d5a9ae8e1261f067b849155c91d041a37711be65f7deb26ec2ae5989f0d0b2'],
  ['10','比心',77291,'13f938ca0fd245785864cbb9e5c6806e97c716ece4679ac3c740a9ac4546730a'],
  ['11','无语',72312,'8b959ff28b54fed049c4ea855ac11267f487584300c649b9c776a9fb88e62f62']
].map(([id,label,size,sha256]) => Object.freeze({id,label,size,sha256,mime:'image/png',path:`/stickers/yueti/${id}.png`})));

export async function loadDefaultSticker(id,{signal,isCurrent=()=>true,fetchImpl=fetch,cryptoImpl=crypto}={}) {
  const item=DEFAULT_STICKERS.find(value=>value.id===id);
  if(!item)throw Error('这张初始表情不存在。');
  const guard=()=>{if(signal?.aborted || !isCurrent())throw new DOMException('表情准备已取消。','AbortError');};
  guard();
  let bytes;const chunks=[];
  try {
    const response=await fetchImpl(item.path,{credentials:'omit',redirect:'error',cache:'force-cache',signal});guard();
    if(!response.ok || response.redirected || !response.body || (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase()!==item.mime)throw Error('初始表情加载失败，请重新打开表情。');
    const reader=response.body.getReader();let length=0;
    try {
      for(;;){guard();const {value,done}=await reader.read();guard();if(done)break;length+=value.length;if(length>item.size)throw Error('初始表情文件不完整，请重新安装或刷新。');chunks.push(value);}
    } catch(error) {await reader.cancel().catch(()=>{});throw error;}
    if(length!==item.size)throw Error('初始表情文件不完整，请重新安装或刷新。');
    bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    const hash=[...new Uint8Array(await cryptoImpl.subtle.digest('SHA-256',bytes))].map(value=>value.toString(16).padStart(2,'0')).join('');guard();
    if(hash!==item.sha256 || validateRasterImage(bytes,item.mime)!==item.mime)throw Error('初始表情校验失败，请重新安装或刷新。');
    return {id:item.id,name:`${item.label}.png`,mime:item.mime,bytes};
  } catch(error) {bytes?.fill(0);throw error;}
  finally {for(const chunk of chunks)chunk.fill(0);}
}
