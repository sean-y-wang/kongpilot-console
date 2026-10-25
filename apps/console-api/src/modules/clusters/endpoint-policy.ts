import { ConflictException } from '@nestjs/common';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import type { DbService } from '../../infrastructure/db.service';
export interface EndpointInspection {url:string;scope:string;registry:Map<string,string>}
async function addresses(host:string):Promise<string[]>{
 const normalized=host.replace(/^\[|\]$/g,'');if(isIP(normalized))return [normalized];let timer:NodeJS.Timeout|undefined;
 try{return (await Promise.race([lookup(normalized,{all:true}),new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>reject(new Error('DNS budget')),1000);})])).map(row=>row.address.toLowerCase());}
 catch{return [];}finally{clearTimeout(timer);}
}
/** Existing aliases stay readable. New endpoints are checked before the SQL write transaction. */
export async function inspectRegistryEndpoint(db:Pick<DbService,'query'>,url:string,ignoreId?:string):Promise<EndpointInspection>{
 const rows=await db.query<any>('SELECT id,admin_url FROM clusters WHERE deleted_at IS NULL ORDER BY id LIMIT 1001');
 if(rows.length>1000)throw new ConflictException({code:'CLUSTER_REGISTRY_BUDGET',message:'集群登记数量超过地址核验预算'});
 const scope=transportScopeFor(url),candidate=new URL(url),resolved=await addresses(candidate.hostname),registry=new Map<string,string>();
 const candidates=rows.filter(row=>{registry.set(row.id,row.admin_url);const existing=new URL(row.admin_url);return row.id!==ignoreId&&existing.protocol===candidate.protocol&&(existing.port||(existing.protocol==='https:'?'443':'80'))===(candidate.port||(candidate.protocol==='https:'?'443':'80'))&&existing.pathname.replace(/\/+$/,'')===candidate.pathname.replace(/\/+$/,'');});
 for(let i=0;i<candidates.length;i+=20)await Promise.all(candidates.slice(i,i+20).map(async row=>{
  if(transportScopeFor(row.admin_url)===scope||resolved.length&&(await addresses(new URL(row.admin_url).hostname)).some(ip=>resolved.includes(ip)))throw new ConflictException({code:'CLUSTER_ENDPOINT_EXISTS',message:'Admin API 地址或其 DNS 别名已登记，请使用已有集群'});
 }));return {url,scope,registry};
}
export async function assertRegistryEndpoint(tx:Pick<DbService,'query'>,inspection:EndpointInspection,ignoreId?:string):Promise<void>{
 const rows=await tx.query<any>('SELECT id,admin_url FROM clusters WHERE deleted_at IS NULL ORDER BY id LIMIT 1001');if(rows.length>1000)throw new ConflictException('集群登记数量超过地址核验预算');
 for(const row of rows){if(row.id===ignoreId)continue;
  if(transportScopeFor(row.admin_url)===inspection.scope)throw new ConflictException({code:'CLUSTER_ENDPOINT_EXISTS',message:'Admin API 地址已登记'});
  if(inspection.registry.get(row.id)!==row.admin_url)throw new ConflictException({code:'CLUSTER_REGISTRY_CHANGED',message:'集群连接登记已变更，请刷新后重新核验地址'});
 }
}
