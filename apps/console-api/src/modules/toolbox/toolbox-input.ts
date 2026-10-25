import { BadRequestException } from '@nestjs/common';
import { isIP } from 'node:net';
import { configurationId, configurationObject } from '../configuration/configuration-input';

export const toolboxId = configurationId;
export const toolboxObject = configurationObject;
export const TOOLBOX_ENTITIES = ['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'] as const;
const secretName = /(?:password|passphrase|secret|private.?key|api.?key|token|authorization|cookie|credential|^key$|^cert$)/i;
const scriptName = /^(?:functions?|scripts?|lua|lua_code|source_code|pre_function|post_function)$/i;
const secretMaterial = /-----BEGIN|(?:[a-z][a-z\d+.-]*:\/\/)[^\s/]*@|(?:[?&])(?:token|key|password|secret|access_token)=|\b(?:authorization|proxy-authorization|cookie|set-cookie|(?:x[-_])?api[-_]key|access[-_]token|password|passphrase|secret)\b["']?\s*[:=,]|\b(?:Bearer|Basic)\s+\S+/i;
/** Drafts contain editing material, never plaintext credentials or control fields. */
export function assertPublicDraft(value: unknown, depth = 0): asserts value is Record<string, unknown> {
  if (depth === 0 && (!value || typeof value !== 'object' || Array.isArray(value))) throw new BadRequestException({code:'INVALID_DRAFT_PAYLOAD'});
  if (depth > 12) throw new BadRequestException({code:'DRAFT_DEPTH_LIMIT'});
  if (depth === 0 && Buffer.byteLength(JSON.stringify(value)) > 65536) throw new BadRequestException({code:'DRAFT_SIZE_LIMIT'});
  if (typeof value === 'string') {
    if (secretMaterial.test(value)) throw new BadRequestException({code:'DRAFT_SECRET_FORBIDDEN',message:'草稿不保存私钥、密码、认证请求头、Cookie、令牌或含凭证的地址；请移除相关材料后保存'});
    return;
  }
  if (Array.isArray(value)) { if(value.length>500)throw new BadRequestException({code:'DRAFT_ARRAY_LIMIT'});for(const item of value)assertPublicDraft(item,depth+1);return; }
  if (value && typeof value === 'object') for (const [key,item] of Object.entries(value)) {
    if (scriptName.test(key)) throw new BadRequestException({code:'DRAFT_SCRIPT_FORBIDDEN',message:'草稿不保存 Serverless 函数或脚本；请通过配置变更流程管理脚本'});
    if (['__proto__','prototype','constructor','owner_user_id','ownerId','clusterId','workspaceId','approved','superAdmin'].includes(key) || secretName.test(key)) throw new BadRequestException({code:'DRAFT_SECRET_FORBIDDEN',message:'草稿包含秘密字段或禁止的控制字段'});
    assertPublicDraft(item,depth+1);
  }
}
export function cacheKey(value: unknown): string {
  if(typeof value!=='string'||value.length<1||value.length>256||!/^[A-Za-z0-9_.:-]+$/.test(value)||value==='.'||value==='..'||/password|secret|token|authorization|cookie|credential|keyauth|basicauth|hmacauth/i.test(value))throw new BadRequestException({code:'INVALID_CACHE_KEY',message:'缓存键仅允许字母、数字、点、冒号、下划线和短横线，不能包含路径或凭证缓存键'});
  return value;
}
export function boundedName(value:unknown):string {
  if(typeof value!=='string'||!value.trim()||value.length>128||/[\u0000-\u001f]/.test(value))throw new BadRequestException({code:'INVALID_TOOLBOX_NAME'});return value.trim();
}
export interface RouteDebugInput { method:string; url:string; headers:Record<string,string>; sourceIp?:string; sourcePort?:number; destinationIp?:string; destinationPort?:number; sni?:string; consumerId?:string; }
export function routeDebugInput(value:unknown):RouteDebugInput {
  const input=toolboxObject(value,['method','url','headers','sourceIp','sourcePort','destinationIp','destinationPort','sni','consumerId']);
  if(typeof input.method!=='string'||!/^[A-Z]{1,16}$/.test(input.method)||typeof input.url!=='string'||input.url.length>4096)throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_INPUT'});
  let url:URL;try{url=new URL(input.url);}catch{throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_URL'});}
  if(!['http:','https:','tcp:','tls:'].includes(url.protocol)||url.username||url.password||url.hash)throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_URL'});
  if(url.search)throw new BadRequestException({code:'ROUTE_DEBUG_QUERY_UNSUPPORTED',message:'路由模拟无需查询参数，请仅填写匹配地址路径'});
  const headers=toolboxObject(input.headers??{},Object.keys(input.headers??{}));if(Object.keys(headers).length>32)throw new BadRequestException({code:'ROUTE_DEBUG_HEADER_LIMIT'});
  const normalized:Record<string,string>={};for(const [name,content]of Object.entries(headers)) {
    if(!/^[a-zA-Z0-9-]{1,64}$/.test(name)||typeof content!=='string'||content.length>1024||/[^\t\x20-\x7e\x80-\xff]/.test(content))throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_HEADER'});normalized[name.toLowerCase()]=content;
  }
  for(const key of ['sourceIp','destinationIp'])if(input[key]!==undefined&&(typeof input[key]!=='string'||input[key].includes('%')||!isIP(input[key])))throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_IP'});
  for(const key of ['sourcePort','destinationPort'])if(input[key]!==undefined&&(!Number.isInteger(input[key])||input[key]<1||input[key]>65535))throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_PORT'});
  if(input.sni!==undefined&&(typeof input.sni!=='string'||input.sni.length>253||!/^[a-zA-Z0-9.-]+$/.test(input.sni)))throw new BadRequestException({code:'INVALID_ROUTE_DEBUG_SNI'});
  return {...input,headers:normalized,...(input.consumerId?{consumerId:toolboxId(input.consumerId)}:{})} as RouteDebugInput;
}
