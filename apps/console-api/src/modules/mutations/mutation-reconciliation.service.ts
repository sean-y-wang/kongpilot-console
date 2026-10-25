import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, NotFoundException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { AuditService } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import type { EntityActor } from '../entities/entities.types';
import { RecycleService, graphOrder } from '../recycle-bin/recycle.service';
import type { GraphNode, RecycleGraph } from '../recycle-bin/graph-capturer.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';

const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const conflict=()=>new ConflictException({code:'RECONCILIATION_PROOF_INCOMPLETE',message:'当前对象图不能完整证明变更结果，保留未知状态'});
function comparable(value:any,type:string):any {
 const copy={...value};for(const key of ['created_at','updated_at','ttl'])delete copy[key];
 if(type==='certificates')delete copy.snis;
 if(type==='targets')delete copy.id;
 return copy;
}

/** Explicit recovery of an archived graph, using GET only. It does not retry
 * an unknown native write or accept an operator-provided outcome. The result
 * describes the verified current graph, not the causal history of outsiders. */
@Injectable()
export class MutationReconciliationService {
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly kong:KongService,private readonly execution:KongExecutionContextService,private readonly authz:AuthorizationService,
  private readonly recycle:RecycleService,private readonly workspaces:WorkspaceResolverService,private readonly audit:AuditService){}

 @KongActorScope({module:'mutations',action:'write',queryArg:2})
 async reconcile(cid:string,id:string,query:{workspaceId?:string},body:unknown,actor:EntityActor):Promise<any>{
  if(!uuid.test(cid)||!uuid.test(id)||query.workspaceId!==undefined&&!uuid.test(query.workspaceId)
   ||Object.keys(query).some(key=>key!=='workspaceId')||!body||typeof body!=='object'||Array.isArray(body)
   ||Object.keys(body).some(key=>!['confirmed','confirm_name'].includes(key)))throw new BadRequestException({code:'INVALID_RECONCILIATION'});
  if(!await this.authz.isPlatformAdmin(actor.user))throw new ForbiddenException({code:'RECONCILIATION_PLATFORM_ADMIN_REQUIRED',message:'完整对象图核验需当前平台管理员'});
  await this.authz.assertCluster(actor.user,cid,'mutations','write',query.workspaceId);
  const cluster=await this.db.one<any>('SELECT id,admin_url,transport_scope,execution_mode,revision FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
  if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND'});
  if(cluster.execution_mode!=='direct')throw new ConflictException({code:'APPROVAL_REQUIRED',message:'审批集群的核验状态变更须通过工作流'});
  const scope=transportScopeFor(cluster.admin_url,cluster.transport_scope);
  return this.redis.withLock(`mutation:${scope}`,async()=>{
   const version=await this.authz.permissionVersion(actor.user);
   const operation=await this.db.one<any>('SELECT *,updated_at::text AS recovery_revision FROM mutation_operations WHERE cluster_id=$1 AND id=$2',[cid,id]);
   if(!operation)throw new NotFoundException({code:'MUTATION_NOT_FOUND'});
   if(!['delete','restore'].includes(operation.action))throw new ConflictException({code:'RECONCILIATION_GRAPH_REQUIRED',message:'此核验只支持已完整归档的删除或恢复操作'});
   const payload=operation.payload_secret?this.secrets.decrypt<any>(operation.payload_secret,`mutation:${id}:payload`):null;
   let entry=operation.action==='restore'&&uuid.test(payload?.entryId??'')
    ?await this.db.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[cid,payload.entryId])
    :await this.db.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND mutation_id=$2',[cid,id]);
   if(!entry&&operation.action==='delete'){
    // Early M1 archives predate the mutation link. Never pick the newest of
    // several archives or accept an entry ID supplied by the caller.
    const candidates=await this.db.query<any>(`SELECT * FROM recycle_entries WHERE cluster_id=$1 AND root_type=$2
     AND original_id=$3 AND mutation_id IS NULL ORDER BY created_at,id LIMIT 2`,[cid,operation.entity_type,operation.entity_id]);
    if(candidates.length===1)entry=candidates[0];
   }
   if(!entry?.payload_secret||entry.state==='purged')throw conflict();
   const graph=this.secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${entry.id}`);
   if(graph.complete!==true||graph.purpose==='migration'||!Array.isArray(graph.nodes)||!graph.nodes.length||graph.nodes.length>200
    ||new Set(graph.nodes.map(node=>node.key)).size!==graph.nodes.length)throw conflict();
   const root=graph.nodes.find(node=>node.key===graph.rootKey);
   if(!root||root.type!==entry.root_type||root.id!==entry.original_id||entry.root_type!==operation.entity_type||entry.original_id!==operation.entity_id)throw conflict();
   if((body as any).confirmed!==true||(body as any).confirm_name!==entry.root_name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'请输入归档对象名称并确认核验'});
   const wid=query.workspaceId??operation.workspace_id??entry.workspace_id;
   if(operation.workspace_id&&wid!==operation.workspace_id||entry.workspace_id&&wid!==entry.workspace_id)throw new ForbiddenException({code:'WORKSPACE_MISMATCH'});
   // This existing domain entry checks complete archive membership and native
   // read rights, including historical NULL-workspace binding with an audit.
   const preview=await this.recycle.preview(cid,entry.id,actor.user,wid);
   const verifiedWid=preview.entry.workspace_id;
   if(!uuid.test(verifiedWid??''))throw conflict();
   if(['succeeded','failed'].includes(operation.state)&&operation.remote_completed===true)
    return {operationId:id,entryId:entry.id,state:operation.state,alreadyReconciled:operation.error_code?.startsWith('RECONCILED_')===true};
   if(operation.state!=='uncertain'||Date.now()-Date.parse(operation.updated_at)<15000)throw new ConflictException({code:'RECONCILIATION_OPERATION_NOT_QUIESCENT',message:'仅核验已停止发送至少 15 秒的未知操作'});
   const ordered=graphOrder(graph),affected=ordered.filter(node=>node.affected===true);
   if(!affected.length)throw conflict();
   const steps=new Map<string,any>((preview.nodes??[]).map((row:any)=>[row.node_key,row]));
   const states=affected.map(node=>steps.get(node.key)?.[operation.action==='delete'?'delete_state':'restore_state']);
   // An elapsed client timeout does not cancel Kong's database operation.
   // Close only parent-receipt uncertainty with durable child acknowledgements:
   // an unknown last packet still requires separate operational investigation.
   const acknowledged=operation.action==='delete'?'deleted':'restored';
   if(states.some(state=>!['pending','failed',acknowledged].includes(state))
    ||states.includes('pending')&&!states.includes('failed'))throw conflict();
   const archivedScope=await this.workspaces.listScope(cid,verifiedWid);
   const observed: Array<{node:GraphNode;present:boolean;restoredId?:string}> = [];
   for(const node of affected){
    // Authorize original objects even when their real parent was deleted.
    await this.authz.assertEntity(actor.user,cid,node.type,operation.action==='delete'?'delete':'write',node.data,verifiedWid);
    let actual:any=null;
    try{
     if(node.type==='targets'){
      const match=/^\/upstreams\/([^/]+)\/targets\/[^/]+$/.exec(node.path);if(!match)throw conflict();
      const parent=decodeURIComponent(match[1]),path=`/upstreams/${encodeURIComponent(parent)}/targets`;
      actual=await this.execution.runInternalRead(cid,'operation-check',async()=>
       (await currentEffectiveTarget(this.kong,cid,parent,node.data.target)).target,{paths:[path],maxCalls:100,maxPages:100,maxRecords:10000});
     }else actual=await this.execution.runInternalRead(cid,'operation-check',()=>this.kong.request(cid,'GET',node.path),{paths:[node.path],maxCalls:3,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000});
    }catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
    if(actual){
     const parentType=node.type==='targets'?'upstreams':['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(node.type)?'consumers':null;
     const parent=parentType?graph.nodes.find(candidate=>node.dependencies.includes(candidate.key)&&candidate.type===parentType):null;
     const owner=parent?await this.execution.runInternalRead(cid,'operation-check',()=>this.kong.request(cid,'GET',parent.path),{paths:[parent.path],maxCalls:3,maxRecords:1,maxPages:1,maxBytes:2*1024*1024,timeoutMs:5000}):actual;
     if(!owner)throw conflict();this.workspaces.assertMembership(archivedScope,owner);
     if(this.secrets.fingerprint(comparable(actual,node.type))!==this.secrets.fingerprint(comparable(node.data,node.type)))throw conflict();
    }
    observed.push({node,present:!!actual,...(actual?{restoredId:actual.id}: {})});
   }
   // Every node is now either the exact archived configuration or absent.
   // This proves a known partial result too; changed/unreadable nodes never
   // reach here, and the complete encrypted archive remains recoverable.
   const applied=observed.filter(row=>operation.action==='delete'?!row.present:row.present);
   const succeeded=applied.length===affected.length,state=succeeded?'succeeded':'failed';
   if(operation.action==='restore'&&applied.length){
    for(const reference of ordered.filter(node=>!node.affected)){
     const actual=await this.execution.runInternalRead(cid,'operation-check',()=>this.kong.request(cid,'GET',reference.path),{paths:[reference.path],maxCalls:3,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000});
     this.workspaces.assertMembership(archivedScope,actual);
     if(this.secrets.fingerprint(comparable(actual,reference.type))!==this.secrets.fingerprint(comparable(reference.data,reference.type)))throw conflict();
    }
   }
   await this.redis.assertLeaseOwnership();
   if(await this.authz.permissionVersion(actor.user)!==version||!await this.authz.isPlatformAdmin(actor.user))throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
   const result={operationId:id,entryId:entry.id,state,observedOutcome:succeeded?'completely_applied':applied.length?'partially_applied':'not_applied',verifiedObjects:affected.length,appliedObjects:applied.length,
    ...(succeeded?{[operation.action==='delete'?'deleted':'restored']:applied.map(row=>({type:row.node.type,id:row.node.id,...(operation.action==='restore'?{originalId:row.node.id,restoredId:row.restoredId}: {})}))}: {})};
   return this.db.transaction(async tx=>{
    const currentCluster=await tx.one<any>('SELECT revision,execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[cid]);
    await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR SHARE');
    const currentEntry=await tx.one<any>('SELECT state,payload_secret,workspace_id FROM recycle_entries WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,entry.id]);
    if(currentCluster?.revision!==cluster.revision||currentCluster.execution_mode!=='direct'||!currentEntry
     ||currentEntry.payload_secret!==entry.payload_secret||currentEntry.workspace_id!==verifiedWid||currentEntry.state!==preview.entry.state)throw conflict();
    await this.redis.assertLeaseOwnership();
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    const count=await tx.exec(`UPDATE mutation_operations SET state=$3,remote_completed=true,error_code=$4,workspace_id=$5,
     result_secret=$6,safe_result=$7::jsonb,updated_at=now() WHERE cluster_id=$1 AND id=$2 AND state='uncertain' AND updated_at=$8::timestamptz`,
     [cid,id,state,succeeded?'RECONCILED_APPLIED':applied.length?'RECONCILED_PARTIAL':'RECONCILED_NOT_APPLIED',verifiedWid,this.secrets.encrypt(result,`mutation:${id}:result`),JSON.stringify(result),operation.recovery_revision]);
    if(count!==1)throw conflict();
    for(const row of observed)await tx.exec(operation.action==='delete'
     ?"UPDATE recycle_nodes SET delete_state=$3,safe_error=NULL,updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND affected=true"
     :"UPDATE recycle_nodes SET restore_state=$3,restored_id=$4,safe_error=NULL,updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND affected=true",
     [entry.id,row.node.key,operation.action==='delete'?row.present?'failed':'deleted':row.present?'restored':'failed',...(operation.action==='restore'?[row.restoredId??null]:[])]);
    const entryState=operation.action==='delete'?succeeded?'deleted':applied.length?'partially_deleted':'archived':succeeded?'restored':'partially_restored';
    await tx.exec("UPDATE recycle_entries SET state=$2,restored_at=CASE WHEN $2='restored' THEN now() ELSE restored_at END,updated_at=now() WHERE id=$1",[entry.id,entryState]);
    await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:verifiedWid,entityType:'mutation_operations',entityId:id,action:'mutation.reconciled',
     before:{state:'uncertain',remote_completed:operation.remote_completed},after:result,result:'success',requestId:actor.requestId,ip:actor.ip},tx);
    return result;
   });
  });
 }
}
