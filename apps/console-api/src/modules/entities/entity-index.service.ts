import { BadRequestException, ForbiddenException, Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { createHash, createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { AuthorizationService } from '../authorization/authorization.service';
import type { AuthUser } from '../../common/auth';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { workspaceIndexWhere } from '../workspaces/workspace-index-scope';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { entityMatchesSearch, entitySearchSql } from './entity-search';

const kinds=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'];
type SearchOptions={search?:string;sort?:string;size?:number;cursor?:string;tags?:string;workspaceId?:string};
@Injectable()
export class EntityIndexService implements OnModuleInit,OnModuleDestroy {
 private timer?:NodeJS.Timeout;
 private running=false;
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,private readonly kong:KongService,private readonly authz:AuthorizationService,private readonly workspaces:WorkspaceResolverService,private readonly execution:KongExecutionContextService){}
 onModuleInit(){this.timer=setInterval(()=>void this.tick().catch(()=>undefined),Number(process.env.INDEX_SYNC_INTERVAL_MS??20000));this.timer.unref();void this.tick().catch(()=>undefined);}
 onModuleDestroy(){if(this.timer)clearInterval(this.timer);}
 async upsert(clusterId:string,entityType:string,entity:any,syncCycle?:string){
  if(!kinds.includes(entityType)||typeof entity?.id!=='string')return;
  const safe=this.secrets.redact(entity),name=entity.name??entity.username??entity.custom_id??entity.id;
  await this.db.exec(`INSERT INTO entity_index(cluster_id,entity_type,kong_id,name,tags,document,content_hash,kong_created_at,observed_at,sync_cycle)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),coalesce($9::uuid,(SELECT cycle_id FROM index_sync_state WHERE cluster_id=$1 AND entity_type=$2))) ON CONFLICT(cluster_id,entity_type,kong_id) DO UPDATE SET
   name=excluded.name,tags=excluded.tags,document=excluded.document,content_hash=excluded.content_hash,kong_created_at=excluded.kong_created_at,observed_at=now(),sync_cycle=excluded.sync_cycle`,
   [clusterId,entityType,entity.id,String(name),Array.isArray(entity.tags)?entity.tags:[],safe,createHash('sha256').update(JSON.stringify(safe)).digest('hex'),Number.isFinite(entity.created_at)?Math.floor(entity.created_at):0,syncCycle??null]);
 }
 async remove(clusterId:string,entityType:string,id:string){await this.db.exec('DELETE FROM entity_index WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=$3',[clusterId,entityType,id]);}
 private sign(payload:any){const raw=Buffer.from(JSON.stringify(payload)).toString('base64url');return `${raw}.${createHmac('sha256',process.env.APP_SECRET!).update(raw).digest('base64url')}`;}
 private read(cursor:string,binding:string){
  if(cursor.length>4096)throw new BadRequestException('游标无效');
  const [raw,sig,...extra]=cursor.split('.');if(!raw||!sig||extra.length)throw new BadRequestException('游标无效');
  const want=createHmac('sha256',process.env.APP_SECRET!).update(raw).digest('base64url');
  if(sig.length!==want.length||!timingSafeEqual(Buffer.from(sig),Buffer.from(want)))throw new BadRequestException('游标无效');
  try{const data=JSON.parse(Buffer.from(raw,'base64url').toString());if(data.binding!==binding||data.exp<Date.now()||typeof data.id!=='string'||!['string','number'].includes(typeof data.value))throw new Error();return data;}catch{throw new BadRequestException('游标已失效或查询条件已改变');}
 }
 async search(clusterId:string,entityType:string,options:SearchOptions,actor:AuthUser){
  await this.authz.assertCluster(actor,clusterId,entityType,'read');
  if(!kinds.includes(entityType))throw new BadRequestException('不支持的实体');
  const size=Number(options.size??20),search=String(options.search??'').slice(0,128).trim(),sort=options.sort??'name:asc';
  if(!Number.isInteger(size)||size<1||size>100||!['name:asc','name:desc','created_at:asc','created_at:desc'].includes(sort))throw new BadRequestException('无效排序或分页参数');
  const workspace=await this.workspaces.resolve(clusterId,options.workspaceId);
  await this.authz.assertCluster(actor,clusterId,entityType,'read',workspace.id);
  const tags=await this.authz.scopeTags(actor,clusterId,workspace.id,options.tags,entityType);
  const scope=await this.workspaces.listScope(clusterId,workspace.id,tags);
  const binding=createHash('sha256').update(JSON.stringify({clusterId,entityType,search,sort,size,scope:scope.binding,actor:actor.id,permissions:await this.authz.permissionVersion(actor)})).digest('hex');
  const previous=options.cursor?this.read(options.cursor,binding):null;
  const column=sort.startsWith('name:')?'name':'kong_created_at',direction=sort.endsWith(':asc')?'ASC':'DESC',comparison=direction==='ASC'?'>':'<';
  const params:unknown[]=[clusterId,entityType,search],where=['cluster_id=$1','entity_type=$2',entitySearchSql(entityType,'$3')];
  where.push(...workspaceIndexWhere(scope,params));
  if(previous){params.push(previous.value,previous.id);where.push(`(${column},kong_id) ${comparison} ($${params.length-1},$${params.length})`);}
  params.push(Math.min(500,size*5+1));
  const rows=await this.db.query<any>(`SELECT * FROM entity_index WHERE ${where.join(' AND ')} ORDER BY ${column} ${direction},kong_id ${direction} LIMIT $${params.length}`,params);
  const items:any[]=[];let last:any=null,consumed=0;
  for(const row of rows){
   if(items.length>=size)break;consumed++;last=row;
   try{
    const entity=await this.kong.request(clusterId,'GET',`/${entityType}/${encodeURIComponent(row.kong_id)}`);
    if(search&&!entityMatchesSearch(entityType,entity,search)){await this.upsert(clusterId,entityType,entity);continue;}
    if(!this.workspaces.matches(scope,entity))continue;
    const allowed=await this.authz.filterEntities(actor,clusterId,entityType,[entity],scope.workspaceId);if(!allowed.length)continue;
    await this.upsert(clusterId,entityType,entity);items.push(this.secrets.redact(entity));
   }catch(error:any){if(error?.getStatus?.()===404){await this.remove(clusterId,entityType,row.kong_id);continue;}if(error instanceof ForbiddenException)continue;throw error;}
  }
  const hasMore=consumed<rows.length||rows.length===params[params.length-1];
  const nextCursor=last&&hasMore?this.sign({binding,id:last.kong_id,value:last[column],exp:Date.now()+900000}):null;
  const state=await this.db.one<any>('SELECT completed_at,last_run_at,last_error FROM index_sync_state WHERE cluster_id=$1 AND entity_type=$2',[clusterId,entityType]);
  return {items,nextCursor,size,total:null,indexed:true,workspace_id:scope.workspaceId,observed_at:state?.completed_at??state?.last_run_at??null,sync_error:state?.last_error??null};
 }
 async summary(clusterId:string,actor:AuthUser,workspaceId?:string){
  await this.authz.assertCluster(actor,clusterId,'overview','read');
  const workspace=await this.workspaces.resolve(clusterId,workspaceId);
  await this.authz.assertCluster(actor,clusterId,'overview','read',workspace.id);
  if(!await this.authz.isPlatformAdmin(actor))return {counts:null,observed_at:null,workspace_id:workspace.id,source:'index'};
  const permissions=await this.authz.permissionVersion(actor);
  const tags=await this.authz.scopeTags(actor,clusterId,workspace.id,undefined);
  const scope=await this.workspaces.listScope(clusterId,workspace.id,tags),params:unknown[]=[clusterId];
  const predicates=workspaceIndexWhere(scope,params);
  const counts=await this.db.query<any>(`SELECT entity_type,count(*)::int AS count,max(observed_at) AS observed_at FROM entity_index WHERE cluster_id=$1 AND ${predicates.join(' AND ')} GROUP BY entity_type`,params);
  const quarantine=await this.db.one<any>(`SELECT count(*)::int AS count FROM entity_index i WHERE cluster_id=$1 AND
    ((SELECT count(*) FROM unnest(i.tags) AS t WHERE t LIKE 'kos-ws-%')>1 OR
     EXISTS (SELECT 1 FROM unnest(i.tags) AS t WHERE t LIKE 'kos-ws-%' AND NOT EXISTS
      (SELECT 1 FROM workspaces w WHERE w.cluster_id=i.cluster_id AND w.deleted_at IS NULL AND t='kos-ws-'||w.code)))`,[clusterId]);
  if(permissions!==await this.authz.permissionVersion(actor))throw new ForbiddenException({code:'PERMISSIONS_CHANGED',message:'权限已变化，请刷新总览'});
  return {counts:Object.fromEntries(kinds.map(kind=>[kind,counts.find(row=>row.entity_type===kind)?.count??0])),observed_at:counts.reduce((latest:any,row:any)=>!latest||row.observed_at>latest?row.observed_at:latest,null),source:'index',workspace_id:workspace.id,workspace_revision:workspace.revision,quarantined_count:quarantine?.count??0,traffic:{available:false,reason:'监控数据通道尚未启用'}};
 }
 async refreshForActor(clusterId:string,actor:AuthUser,workspaceId?:string){
  await this.authz.assertCluster(actor,clusterId,'overview','write',workspaceId);
  const workspace=await this.workspaces.resolve(clusterId,workspaceId);
  await this.authz.assertCluster(actor,clusterId,'overview','write',workspace.id);
  const result=await this.execution.runActor({actor,clusterId,workspaceId:workspace.id,module:'overview',action:'write'},()=>this.execution.runInternalRead(clusterId,'inventory',()=>this.refreshCluster(clusterId),{paths:kinds.map(kind=>`/${kind}`),maxCalls:8,maxPages:8,maxRecords:800,maxBytes:32*1024*1024,timeoutMs:15000}));
  return {workspace_id:workspace.id,...result};
 }
 async refreshCluster(clusterId:string){return this.redis.withLock(`index:${clusterId}`,()=>this.sync(clusterId));}
 private async tick(){
  if(this.running)return;this.running=true;
  try{const clusters=await this.db.query<any>("SELECT id FROM clusters WHERE deleted_at IS NULL AND status='healthy' AND version ~ '^1\\.[345]\\.[0-9]+$'");for(const c of clusters)try{await this.execution.runSystemRead(c.id,'indexer',()=>this.refreshCluster(c.id));}catch{/* A failed provider never produces synthetic inventory. */}}
  finally{this.running=false;}
 }
 private async sync(clusterId:string){
  const results:any[]=[];const deadline=Date.now()+10000;
  for(const entityType of kinds){
   if(Date.now()>deadline)break;
   let state=await this.db.one<any>('SELECT * FROM index_sync_state WHERE cluster_id=$1 AND entity_type=$2',[clusterId,entityType]);
   if(!state){await this.db.exec('INSERT INTO index_sync_state(cluster_id,entity_type,started_at) VALUES($1,$2,now()) ON CONFLICT DO NOTHING',[clusterId,entityType]);state={cursor:null};}
   if(!state.cursor){state.cycle_id=randomUUID();await this.db.exec('UPDATE index_sync_state SET cycle_id=$3,started_at=now() WHERE cluster_id=$1 AND entity_type=$2',[clusterId,entityType,state.cycle_id]);}
   try{
    const page=await this.kong.list(clusterId,`/${entityType}`,{size:100},state.cursor??undefined,'indexer');
    for(const entity of page.items)await this.upsert(clusterId,entityType,entity,state.cycle_id);
    // Sweep only after a complete successful cursor traversal. Keep objects created
    // or read by the console during the traversal, even if Kong's page order changed.
    if(!page.nextCursor)await this.db.exec(`DELETE FROM entity_index WHERE cluster_id=$1 AND entity_type=$2 AND sync_cycle IS DISTINCT FROM $3::uuid
      AND observed_at < (SELECT started_at FROM index_sync_state WHERE cluster_id=$1 AND entity_type=$2)`,[clusterId,entityType,state.cycle_id]);
    await this.db.exec('UPDATE index_sync_state SET cursor=$3,last_run_at=now(),last_error=NULL,completed_at=CASE WHEN $3::text IS NULL THEN now() ELSE completed_at END WHERE cluster_id=$1 AND entity_type=$2',[clusterId,entityType,page.nextCursor]);
    results.push({entityType,indexed:page.items.length,complete:!page.nextCursor});
   }catch(error:any){await this.db.exec('UPDATE index_sync_state SET last_run_at=now(),last_error=$3,cursor=CASE WHEN $4 THEN NULL ELSE cursor END WHERE cluster_id=$1 AND entity_type=$2',[clusterId,entityType,String(error?.getResponse?.()?.code??'INDEX_SYNC_FAILED').slice(0,80),error?.getStatus?.()===400]);results.push({entityType,complete:false});}
  }
  return {results};
 }
}
