import { BadGatewayException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { request as httpRequest, type ClientRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { performance } from 'node:perf_hooks';
import { validateOutboundUrl } from '../../infrastructure/kong/outbound';
import type { RouteDebugInput } from './toolbox-input';
import type { DbService } from '../../infrastructure/db.service';

type Endpoint={host:string;port:string};
export type ProxyDestinationProof=Readonly<{host:string;port:string;addresses:readonly string[];dnsDeadline:number}>;
const destinationProofs=new WeakSet<object>();
function endpoint(url:URL):Endpoint{
  const port=url.port||({'http:':'80','https:':'443','postgres:':'5432','postgresql:':'5432','redis:':'6379','rediss:':'6379'} as Record<string,string>)[url.protocol];
  const host=url.hostname.replace(/^\[|\]$/g,'').toLowerCase();
  if(!host||!port)throw new ForbiddenException({code:'PROXY_PROTECTED_REGISTRY_INVALID'});
  return{host,port};
}
function canonicalAddress(value:string):string{
  if(isIP(value)===4)return value;
  if(isIP(value)!==6||value.includes('%'))throw new ForbiddenException({code:'PROXY_PROTECTED_DNS_INVALID'});
  const text=new URL(`http://[${value}]/`).hostname.slice(1,-1).toLowerCase();
  if(text.startsWith('::ffff:')){const words=text.slice(7).split(':');if(words.length===2){const number=(Number.parseInt(words[0],16)*65536)+Number.parseInt(words[1],16);return[24,16,8,0].map(shift=>(number>>>shift)&255).join('.');}}
  return text;
}
export function validateProxyOrigin(value:unknown,adminOrigin?:string):string{
  if(typeof value!=='string')throw new BadRequestException({code:'INVALID_PROXY_ORIGIN'});
  const url=validateOutboundUrl(value);
  if(!['http:','https:'].includes(url.protocol)||!['','/'].includes(url.pathname)||url.search||url.hash||url.username||url.password)throw new BadRequestException({code:'INVALID_PROXY_ORIGIN'});
  const target=endpoint(url),admin=adminOrigin?endpoint(new URL(adminOrigin)):undefined;
  if(admin&&target.host===admin.host&&target.port===admin.port||['3000','8001','8444','5432','6379','9090','3100'].includes(url.port))throw new ForbiddenException({code:'PROTECTED_PROXY_DESTINATION'});
  return url.origin;
}
export async function assertRegisteredProxyOrigin(db:DbService,value:string,destination?:ProxyDestinationProof):Promise<void>{
  const origin=validateProxyOrigin(value),rows=await db.query<{url:string}>(`SELECT admin_url AS url FROM clusters WHERE deleted_at IS NULL UNION ALL SELECT base_url AS url FROM data_sources WHERE deleted_at IS NULL LIMIT 2001`);
  if(rows.length>2000)throw new ForbiddenException({code:'PROXY_REGISTRY_BUDGET'});
  const target=endpoint(new URL(origin)),samePort=new Map<string,Endpoint>();
  const protectedUrls=[...rows.map(row=>row.url),...(process.env.PUBLIC_ORIGINS??'').split(','),...(process.env.PORTAL_PUBLIC_ORIGINS??'').split(','),process.env.DATABASE_URL,process.env.REDIS_URL].filter((url):url is string=>!!url?.trim());
  for(const url of protectedUrls){let candidate:URL;try{candidate=new URL(url);}catch{throw new ForbiddenException({code:'PROXY_PROTECTED_REGISTRY_INVALID'});}
    const protectedEndpoint=endpoint(candidate);
    if(protectedEndpoint.host===target.host&&protectedEndpoint.port===target.port)throw new ForbiddenException({code:'PROTECTED_PROXY_DESTINATION'});
    if(protectedEndpoint.port===target.port)samePort.set(protectedEndpoint.host,protectedEndpoint);
  }
  if(!destination)return;
  if(!destinationProofs.has(destination)||destination.host!==target.host||destination.port!==target.port)throw new ForbiddenException({code:'PROXY_DESTINATION_PROOF_REQUIRED'});
  if(samePort.size>32)throw new ForbiddenException({code:'PROXY_PROTECTED_DNS_BUDGET'});
  if(!samePort.size)return;
  const remaining=destination.dnsDeadline-Date.now();if(remaining<=0)throw new ForbiddenException({code:'PROXY_PROTECTED_DNS_TIMEOUT'});
  let timer:NodeJS.Timeout|undefined;
  try{
    const targetAddresses=new Set(destination.addresses.map(canonicalAddress));
    await Promise.race([Promise.all([...samePort.values()].map(async candidate=>{
      const addresses=isIP(candidate.host)?[{address:candidate.host,family:isIP(candidate.host)}]:await lookup(candidate.host,{all:true});
      if(!addresses.length)throw new ForbiddenException({code:'PROXY_PROTECTED_DNS_INVALID'});
      if(addresses.some(address=>targetAddresses.has(canonicalAddress(address.address))))throw new ForbiddenException({code:'PROTECTED_PROXY_DESTINATION'});
    })),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new ForbiddenException({code:'PROXY_PROTECTED_DNS_TIMEOUT'})),remaining);})]);
  }catch(error){if(error instanceof ForbiddenException)throw error;throw new ForbiddenException({code:'PROXY_PROTECTED_DNS_FAILED'});}finally{clearTimeout(timer);}
}
function forbiddenAddress(value:string){
  let address=value.toLowerCase();const family=isIP(address);
  if(!family||address.includes('%'))return true;
  if(family===6){try{address=new URL(`http://[${address}]/`).hostname.slice(1,-1).toLowerCase();}catch{return true;}}
  return address==='0.0.0.0'||address==='::'||address.startsWith('127.')||address==='::1'||address.startsWith('::ffff:')||address.startsWith('169.254.')||/^fe[89ab][0-9a-f]:/.test(address)||address.startsWith('ff')||/^22[4-9]\.|^23\d\./.test(address);
}
/** A registered origin is the sole connection destination. The debug URL only
 * supplies Host/path and transient headers; stored connection credentials are
 * never loaded. No redirects, retries or response bodies are returned. */
export async function proxyProbe(origin:string,input:RouteDebugInput,beforeSend:(destination:ProxyDestinationProof)=>Promise<void>){
  if(!['GET','HEAD'].includes(input.method))throw new BadRequestException({code:'PROBE_METHOD_NOT_ALLOWED',message:'真实探测仅支持 GET/HEAD'});
  const start=performance.now(),dnsDeadline=Date.now()+1500,target=new URL(validateProxyOrigin(origin)),routing=new URL(input.url),host=target.hostname.replace(/^\[|\]$/g,'');
  if(!['http:','https:'].includes(routing.protocol))throw new BadRequestException({code:'PROBE_PROTOCOL_NOT_ALLOWED'});
  target.pathname=routing.pathname;
  let dnsTimer:NodeJS.Timeout|undefined;
  const addresses=isIP(host)?[{address:host,family:isIP(host)}]:await Promise.race([lookup(host,{all:true}),new Promise<never>((_,reject)=>{dnsTimer=setTimeout(()=>reject(new BadGatewayException({code:'PROBE_DNS_TIMEOUT'})),1500);})]).finally(()=>clearTimeout(dnsTimer));
  if(!addresses.length||addresses.some(entry=>forbiddenAddress(entry.address)))throw new ForbiddenException({code:'PROBE_ADDRESS_FORBIDDEN'});
  const dnsMs=performance.now()-start,destination=Object.freeze({host,port:endpoint(target).port,addresses:Object.freeze(addresses.map(entry=>canonicalAddress(entry.address))),dnsDeadline});destinationProofs.add(destination);
  try{await beforeSend(destination);}finally{destinationProofs.delete(destination);}
  const preflightMs=performance.now()-start-dnsMs;
  return new Promise<Record<string,unknown>>((resolve,reject)=>{
    let connectMs:number|null=null,tlsMs:number|null=null,ttfbMs:number|null=null,bytes=0,done=false;
    let req:ClientRequest|undefined;
    const timer=setTimeout(()=>req?.destroy(Object.assign(new Error('Probe timeout'),{code:'PROBE_TIMEOUT'})),5000);
    const finish=(error?:unknown,result?:Record<string,unknown>)=>{if(done)return;done=true;clearTimeout(timer);if(error)reject(error);else resolve(result!);};
    const headers:Record<string,string>={};for(const [name,value]of Object.entries(input.headers))if(!/^(host|connection|content-length|transfer-encoding|upgrade|proxy-|te$|trailer)/i.test(name))headers[name]=value;
    try{req=(target.protocol==='https:'?httpsRequest:httpRequest)(target,{method:input.method,headers:{...headers,host:routing.host,connection:'close'},maxHeaderSize:16384,...(target.protocol==='https:'?{servername:input.sni??routing.hostname}:{}),
      lookup:(_hostname,options,callback)=>{const entry=addresses[0];if((options as any).all)(callback as any)(null,[entry]);else callback(null,entry.address,entry.family);},
    },response=>{
      ttfbMs=performance.now()-start;
      const safeHeaders:Record<string,string>={};for(const name of ['content-type','content-length','x-kong-proxy-latency','x-kong-upstream-latency']){const value=response.headers[name];if(typeof value==='string'&&value.length<=256)safeHeaders[name]=value;}
      const result=()=>({status:response.statusCode??null,headers:safeHeaders,bodyReturned:false,truncated:bytes>65536,observedBytes:Math.min(bytes,65536),timings:{dns:dnsMs,preflight:preflightMs,connect:connectMs,tls:tlsMs,ttfb:ttfbMs,total:performance.now()-start},timingSource:'bff_observed_milliseconds',observedAt:new Date().toISOString()});
      response.on('data',chunk=>{bytes+=chunk.length;if(bytes>65536){finish(undefined,result());response.destroy();req?.destroy();}});
      response.on('end',()=>finish(undefined,result()));response.on('error',()=>finish(new BadGatewayException({code:'PROBE_RESPONSE_FAILED'})));
    });}catch{finish(new BadRequestException({code:'INVALID_PROXY_REQUEST'}));return;}
    req.on('socket',socket=>{socket.once('connect',()=>{connectMs=performance.now()-start;});socket.once('secureConnect',()=>{tlsMs=performance.now()-start;});});
    req.on('error',error=>finish(new BadGatewayException({code:(error as any).code==='PROBE_TIMEOUT'?'PROBE_TIMEOUT':'PROBE_CONNECTION_FAILED',message:'代理探测失败，请检查已登记的代理地址与连通性'})));
    req.end();
  });
}
