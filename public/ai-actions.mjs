import {parseAIInvocation as parseTextInvocation} from './ai-context.mjs';
import {DEFAULT_STICKERS} from './default-stickers.mjs';

export function parseAIInvocation(text,options={}) {
  const request=parseTextInvocation(text,options);
  const command=/^\/(?:draw|image|生图|画图)(?=\s|[：:]|$)[\s：:]*(.*)$/isu.exec(request.prompt);
  const natural=/^(?:(?:请|麻烦)(?:你)?\s*)?(?:(?:帮我|给我|为我)\s*)?(?:画(?:一(?:张|幅|个|只)|个|只|张|幅)|(?:生成|绘制|创作)(?:一)?(?:张|幅)(?:图片|图像|插画|画)?)[\s：:]*(.+)$/su.exec(request.prompt);
  if(command||request.requested&&natural) {
    const prompt=(command?.[1]||natural?.[1]||'').trim();
    return {...request,requested:true,explicit:true,historyCount:0,prompt,operation:'images',error:prompt?'':'请在生图命令后描述想画的内容，例如 /生图 雨中的江南小巷。'};
  }
  return {...request,operation:'chat'};
}

export const STICKER_INSTRUCTION=`你可以在轻松的对话中发送一张内置表情。不是每次都要发送；严肃的问题以回答问题为主。只有确实合适时，才在回答最后独立一行写 [山岚表情:编号]，正文不解释此标记。可用编号：${DEFAULT_STICKERS.map(s=>`${s.id}=${s.label}`).join('、')}。最多一张，不创造编号，不提供表情下载链接。`;

export function splitAISticker(answer) {
  const text=typeof answer==='string'?answer.trim():'';
  const match=/(?:^|\n)\[山岚表情:(\d{2})\]\s*$/.exec(text);
  if(!match||!DEFAULT_STICKERS.some(s=>s.id===match[1]))return {text,stickerId:null};
  return {text:text.slice(0,match.index).trim(),stickerId:match[1]};
}

export function drawingDraft(value,{direct=false}={}) {
  const text=typeof value==='string'?value.trim():'';
  const request=text?parseAIInvocation(text,{direct:true}):null;
  return `${direct?'':'@山岚 '}/生图 ${request?.prompt||''}`;
}

export function withPrivateMemory(messages,memory,{reserve=0}={}) {
  const selected=messages.map(m=>({...m}));
  const size=m=>typeof m.content==='string'?m.content.length:m.content.filter(p=>p.type==='text').reduce((n,p)=>n+p.text.length,0);
  const limit=48000-Math.max(0,Math.min(24000,Number.isFinite(reserve)?reserve:0)),memorySize=memory?size(memory):0;
  while(selected.length>1&&(selected.length+(memory?1:0)>200||selected.reduce((n,m)=>n+size(m),0)+memorySize>limit))selected.shift();
  // Never shorten the user's current question. Skip optional memory if it won't fit.
  return memory&&selected.reduce((n,m)=>n+size(m),0)+memorySize<=limit?[memory,...selected]:selected;
}
