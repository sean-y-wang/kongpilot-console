import { lookup } from 'node:dns/promises';
import { BlockList,isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { BadRequestException, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';

export function providerUrl(value:unknown,protocol='https:'):URL {
 if(typeof value!=='string'||value.length>2048)throw new BadRequestException({code:'AUTH_PROVIDER_CONFIG_INVALID',message:'认证提供方地址配置无效'});
 let url:URL;try{url=new URL(value);}catch{throw new BadRequestException('认证提供方地址配置无效');}
 if(url.protocol!==protocol||url.username||url.password||url.hash||url.search||url.hostname.endsWith('.')||/%2f|%5c|%00/i.test(url.pathname))throw new BadRequestException('认证提供方必须使用固定 TLS 地址');
 const host=url.hostname.replace(/^\[|\]$/g,'').toLowerCase(),port=url.port||(protocol==='ldaps:'?'636':'443');
 const allowed=(process.env.AUTH_PROVIDER_ALLOWED_HOSTS??'').split(',').map(v=>v.trim().toLowerCase()).filter(Boolean);
 if(!allowed.includes(host)&&!allowed.includes(`${host}:${port}`))throw new ForbiddenException({code:'AUTH_PROVIDER_HOST_FORBIDDEN',message:'认证提供方主机不在允许列表中'});
 return url;
}
const prohibitedIPv4=new BlockList(),prohibitedIPv6=new BlockList();
prohibitedIPv4.addAddress('0.0.0.0','ipv4');
for(const [address,prefix]of [['127.0.0.0',8],['169.254.0.0',16],['224.0.0.0',4]] as const)prohibitedIPv4.addSubnet(address,prefix,'ipv4');
// Numeric subnet checks include compressed and expanded IPv6 spellings.
for(const [address,prefix]of [['::',96],['::ffff:0:0',96],['fe80::',10],['ff00::',8]] as const)prohibitedIPv6.addSubnet(address,prefix,'ipv6');
function prohibited(address:string):boolean {
 const family=isIP(address);return !family||(family===4?prohibitedIPv4.check(address,'ipv4'):prohibitedIPv6.check(address,'ipv6'));
}
export async function providerAddress(url:URL):Promise<{address:string;family:number}> {
 const host=url.hostname.replace(/^\[|\]$/g,'');let timer:NodeJS.Timeout|undefined;
 const entries=isIP(host)?[{address:host,family:isIP(host)}]:await Promise.race([
  lookup(host,{all:true}),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new ServiceUnavailableException({code:'AUTH_PROVIDER_TIMEOUT',message:'认证提供方连接超时'})),3000);}),
 ]).finally(()=>{if(timer)clearTimeout(timer);});
 if(!entries.length||entries.some(entry=>prohibited(entry.address)))throw new ForbiddenException({code:'AUTH_PROVIDER_ADDRESS_FORBIDDEN',message:'认证提供方地址不允许访问'});
 return entries[0];
}
/** No redirects, bounded JSON, TLS verification and one pinned DNS address. */
export async function providerJson(urlValue:string,method:'GET'|'POST'='GET',form?:URLSearchParams,authorization?:string):Promise<any> {
 const started=Date.now(),url=providerUrl(urlValue),address=await providerAddress(url),serialized=form?.toString();
 if(serialized&&Buffer.byteLength(serialized)>65536)throw new BadRequestException('认证请求过大');
 return new Promise((resolve,reject)=>{
  const request=httpsRequest(url,{method,lookup:((_host:any,options:any,callback:any)=>options?.all?callback(null,[address]):callback(null,address.address,address.family)) as any,
   headers:{Accept:'application/json',...(serialized?{'Content-Type':'application/x-www-form-urlencoded','Content-Length':String(Buffer.byteLength(serialized))}:{}),...(authorization?{Authorization:authorization}:{})}},response=>{
   const chunks:Buffer[]=[];let size=0;
   response.on('data',chunk=>{size+=chunk.length;if(size>1024*1024){request.destroy(new Error('AUTH_PROVIDER_RESPONSE_LIMIT'));return;}chunks.push(Buffer.from(chunk));});
   response.on('error',()=>reject(new ServiceUnavailableException({code:'AUTH_PROVIDER_FAILED',message:'认证提供方响应失败'})));
   response.on('end',()=>{if(response.statusCode!==200){reject(new ServiceUnavailableException({code:'AUTH_PROVIDER_FAILED',message:'认证提供方返回失败'}));return;}
    try{const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!value||typeof value!=='object'||Array.isArray(value))throw new Error();resolve(value);}catch{reject(new ServiceUnavailableException({code:'AUTH_PROVIDER_INVALID_RESPONSE',message:'认证提供方响应格式无效'}));}
   });
  });
  const timer=setTimeout(()=>request.destroy(new Error('AUTH_PROVIDER_TIMEOUT')),Math.max(1,5000-(Date.now()-started)));
  request.on('close',()=>clearTimeout(timer));request.on('error',()=>reject(new ServiceUnavailableException({code:'AUTH_PROVIDER_FAILED',message:'认证提供方连接失败'})));
  if(serialized)request.write(serialized);request.end();
 });
}
