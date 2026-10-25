import { BadGatewayException, BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { decodeTag, workspaceTag } from '../../infrastructure/kong/tags';
import { AuditService } from '../audit/audit.service';
import { nativeAuditScope } from '../event-producers/native-audit-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { EntityIndexService } from '../entities/entity-index.service';
import { CREDENTIAL_KINDS, EntityActor, identifier, objectBody } from '../entities/entities.types';
import { MutationService } from '../mutations/mutation.service';
import { GraphCapturerService, GraphNode } from '../recycle-bin/graph-capturer.service';
import { WorkspaceResolverService, WorkspaceRow } from './workspace-resolver.service';
import { assertMigrationConsumerCredentialClosure } from './workspace-credential-closure';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';

const nativeKinds=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'];
const credentials=new Set<string>(CREDENTIAL_KINDS);
const MAX={pages:100,records:10000,nodes:10000,bytes:32*1024*1024};
type Budget={pages:number;records:number;nodes:number;bytes?:number};
type StepState='pending'|'succeeded'|'failed'|'uncertain';
type PlanState='planned'|'running'|'partial'|'succeeded'|'failed'|'expired';
type Conflict={code:string;message:string;objects:string[]};
type PlanNode=GraphNode&{sourceWorkspaceId:string;beforeFingerprint:string;configFingerprint:string;afterTags:string[];inheritedOnly:boolean};
export type WorkspaceMigrationMaterial={source:WorkspaceRow;target:WorkspaceRow;nodes:PlanNode[];referenceNodes:Array<GraphNode&{workspaceId?:string}>;edges:Array<[string,string]>;conflicts:Conflict[];budget:Budget;permissions:string};
type PlanPayload=WorkspaceMigrationMaterial;
type Step={key:string;type:string;id:string;status:StepState;after_fingerprint?:string;error_code?:string};
type PlanRow={id:string;cluster_id:string;actor_id:string;source_workspace_id:string;target_workspace_id:string;state:PlanState;plan_hash:string;payload_secret:string;steps:Step[];operation_id:string|null;expires_at:string|Date;created_at:string|Date;updated_at:string|Date;workflow_id?:string};

function foreign(value:any):string|undefined{return typeof value==='string'?value:typeof value?.id==='string'?value.id:undefined;}
function displayName(node:GraphNode):string{return String(node.data?.name??node.data?.username??node.data?.target??node.id);}
function sameTags(a:unknown,b:unknown):boolean{return JSON.stringify(Array.isArray(a)?[...a].sort():[])===JSON.stringify(Array.isArray(b)?[...b].sort():[]);}
function stableConfig(data:any):any{const {tags:_tags,updated_at:_updated,...rest}=structuredClone(data);return rest;}
function parentKey(node:GraphNode):string|undefined{
 if(node.type==='targets'){const id=foreign(node.data.upstream);return id?`upstreams:${id}`:undefined;}
 if(credentials.has(node.type)){const id=foreign(node.data.consumer);return id?`consumers:${id}`:undefined;}
 return undefined;
}
function objectKey(type:string,id:string):string{return `${type}:${id}`;}

/** Plans retain encrypted native state. Apply changes tags only and never rotates credentials. */
@Injectable()
export class WorkspaceMigrationService {
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly kong:KongService,private readonly authz:AuthorizationService,private readonly audit:AuditService,
  private readonly captures:GraphCapturerService,private readonly mutations:MutationService,
  private readonly workspaces:WorkspaceResolverService,private readonly index:EntityIndexService,private readonly execution:KongExecutionContextService){}
 private async read(cid:string,path:string):Promise<any>{return this.execution.runInternalRead(cid,'migration',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:4*1024*1024,timeoutMs:5000});}
 private graph(payload:PlanPayload,target=false):Array<{type:string;id:string;data:any}>{return [...payload.nodes.map(node=>({type:node.type,id:node.id,data:target&&!node.inheritedOnly?{...node.data,tags:node.afterTags}:node.data})),...payload.referenceNodes];}

 private body(value:unknown,allowed:string[]):any{
  const body=objectBody(value);if(Object.keys(body).some(key=>!allowed.includes(key)))throw new BadRequestException({code:'INVALID_MIGRATION_FIELD',message:'迁移请求包含不支持的字段'});return body;
 }
 private budget(value:Budget):void{if(value.pages>MAX.pages||value.records>MAX.records||value.nodes>MAX.nodes||(value.bytes??0)>MAX.bytes)throw new ConflictException({code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT',message:'迁移检查超过 100 页 / 10000 记录或对象 / 32 MiB，请缩小选择范围，尚未修改配置'});}
 private active(workspace:WorkspaceRow):void{if(workspace.status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED',message:'迁移的源与目标工作区都必须启用'});}
 private async membership(cid:string,node:GraphNode,all:Map<string,GraphNode>):Promise<WorkspaceRow>{
  const owner=parentKey(node),subject=owner?all.get(owner)?.data:node.data;
  if(!subject)throw new BadGatewayException({code:'MIGRATION_PARENT_MISSING',message:'迁移图缺少真实父对象'});
  const resolved=await this.workspaces.classify(cid,subject.tags);
  if(resolved.state!=='resolved'||!resolved.workspace)throw new ForbiddenException({code:'WORKSPACE_ENTITY_MISMATCH',message:'迁移对象包含无效工作区归属'});
  return resolved.workspace;
 }
 private edgeKeys(type:string,data:any,upstreams:Map<string,string>):string[]{
  const refs:Record<string,string>=type==='routes'?{service:'services'}:type==='plugins'?{service:'services',route:'routes',consumer:'consumers'}:type==='snis'?{certificate:'certificates'}:type==='services'?{client_certificate:'certificates'}:{};
  const result:string[]=[];for(const [field,kind] of Object.entries(refs)){const id=foreign(data[field]);if(id)result.push(objectKey(kind,id));}
  if(type==='services'){
   if(typeof data.host==='string'&&upstreams.has(data.host))result.push(objectKey('upstreams',upstreams.get(data.host)!));
   if(Array.isArray(data.ca_certificates))for(const value of data.ca_certificates){const id=foreign(value);if(id)result.push(objectKey('ca_certificates',id));}
  }
  return [...new Set(result)];
 }
 private async inventory(cid:string,budget:Budget):Promise<Map<string,GraphNode>>{
  const nodes=new Map<string,GraphNode>();
  for(const type of nativeKinds){let cursor:string|undefined;const seen=new Set<string>();
   do{
    if(budget.pages>=MAX.pages)throw new ConflictException({code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT',message:'迁移引用检查的分页预算已耗尽，尚未修改配置'});
    const path=`/${type}`,page=await this.execution.runInternalRead(cid,'migration',()=>this.kong.list(cid,path,{size:100},cursor,'workspace-migration-reference-check'),{paths:[path],maxCalls:1,maxPages:1,maxRecords:100,maxBytes:32*1024*1024,timeoutMs:10000});budget.pages++;budget.records+=page.items.length;budget.bytes=(budget.bytes??0)+Buffer.byteLength(JSON.stringify(page.items));this.budget(budget);
    if(page.items.length>100)throw new BadGatewayException({code:'KONG_INVALID_LIST',message:'引用检查收到无效分页'});
    for(const data of page.items){if(typeof data?.id!=='string')throw new BadGatewayException({code:'KONG_INVALID_ENTITY',message:'引用检查收到无效实体'});const key=objectKey(type,data.id);nodes.set(key,{key,type,id:data.id,path:`/${type}/${identifier(data.id)}`,data,affected:false,dependencies:[],restorable:true});}
    if(page.nextCursor&&seen.has(page.nextCursor))throw new ConflictException({code:'WORKSPACE_MIGRATION_PAGINATION_LOOP',message:'引用检查收到重复游标，尚未修改配置'});
    if(page.nextCursor)seen.add(page.nextCursor);cursor=page.nextCursor??undefined;
   }while(cursor);
  }
  budget.nodes+=nodes.size;this.budget(budget);return nodes;
 }
 private async referenceGraph(cid:string,affected:Map<string,GraphNode>,budget:Budget):Promise<{references:GraphNode[];edges:Array<[string,string]>}>{
  const inventory=await this.inventory(cid,budget),upstreams=new Map<string,string>();
  for(const node of inventory.values())if(node.type==='upstreams')upstreams.set(node.data.name,node.id);
  const edges:Array<[string,string]>=[],references=new Map<string,GraphNode>();
  for(const node of inventory.values()){
   for(const parent of this.edgeKeys(node.type,node.data,upstreams)){
    if(!affected.has(node.key)&&!affected.has(parent))continue;
    edges.push([node.key,parent]);
    for(const key of [node.key,parent])if(!affected.has(key)){
     const reference=inventory.get(key);if(!reference)throw new ConflictException({code:'MIGRATION_REFERENCE_MISSING',message:'相关对象存在无效引用，尚未修改配置'});references.set(key,reference);
    }
   }
  }
  // Nested Target/credential edges are captured with their real parents.
  for(const node of affected.values())for(const parent of node.dependencies){edges.push([node.key,parent]);if(!affected.has(parent)&&!references.has(parent)){
   const reference=inventory.get(parent);if(!reference)throw new ConflictException({code:'MIGRATION_REFERENCE_MISSING',message:'迁移依赖已不存在，尚未修改配置'});references.set(parent,reference);
  }}
  return {references:[...references.values()],edges:[...new Map(edges.map(edge=>[JSON.stringify(edge),edge])).values()]};
 }
 @KongActorScope({module:'workspaces',action:'write'})
 async plan(cid:string,input:unknown,actor:EntityActor):Promise<any>{
  await this.authz.assertCluster(actor.user,cid,'workspaces','read',actor.workspaceId);
  const body=this.body(input,['source_workspace_id','target_workspace_id','roots']);
  const source=await this.workspaces.resolve(cid,actor.workspaceId??body.source_workspace_id);this.active(source);
  if(body.source_workspace_id!==undefined&&body.source_workspace_id!==source.id)throw new BadRequestException({code:'MIGRATION_SOURCE_MISMATCH',message:'迁移源与当前工作区不一致'});
  const target=await this.workspaces.get(cid,body.target_workspace_id);this.active(target);
  if(source.id===target.id)throw new BadRequestException({code:'MIGRATION_SAME_WORKSPACE',message:'请选择不同的目标工作区'});
  await this.authz.assertCluster(actor.user,cid,'workspaces','write',source.id);await this.authz.assertCluster(actor.user,cid,'workspaces','write',target.id);
  if(!Array.isArray(body.roots)||body.roots.length<1||body.roots.length>50)throw new BadRequestException({code:'INVALID_MIGRATION_ROOTS',message:'每次迁移须选择 1–50 个根对象'});
  const all=new Map<string,GraphNode>(),budget:Budget={pages:0,records:0,nodes:0,bytes:0};
  for(const inputRoot of body.roots){
   const root=this.body(inputRoot,['type','id','parent_id','credential_kind']);
   if(![...nativeKinds,'targets','credentials'].includes(root.type))throw new BadRequestException({code:'INVALID_MIGRATION_TYPE',message:'迁移对象类型无效'});
   identifier(root.id);if(root.parent_id!==undefined)identifier(root.parent_id);
   if(root.type==='credentials'&&!credentials.has(root.credential_kind))throw new BadRequestException({code:'INVALID_MIGRATION_CREDENTIAL_KIND',message:'迁移凭证类型无效'});
   const graph=await this.captures.capture(cid,root.type,root.id,{purpose:'migration',parentId:root.parent_id,credentialKind:root.credential_kind,budget:{maxPages:MAX.pages-budget.pages,maxRecords:MAX.records-budget.records,maxNodes:MAX.nodes-budget.nodes,maxBytes:MAX.bytes-(budget.bytes??0)}});
   if(!graph.budget||graph.purpose!=='migration')throw new BadGatewayException({code:'MIGRATION_CAPTURE_INCOMPLETE',message:'迁移捕获缺少完整预算或用途记录'});
   budget.pages+=graph.budget.pages;budget.records+=graph.budget.records;budget.nodes+=graph.budget.nodes;budget.bytes=(budget.bytes??0)+(graph.budget.bytes??Buffer.byteLength(JSON.stringify(graph)));this.budget(budget);
   for(const node of graph.nodes){const previous=all.get(node.key);if(previous&&this.secrets.fingerprint(previous.data)!==this.secrets.fingerprint(node.data))throw new ConflictException({code:'MIGRATION_CAPTURE_CHANGED',message:'对象在引用检查期间发生变化，请重新生成计划'});all.set(node.key,previous?{...previous,affected:previous.affected||node.affected,dependencies:[...new Set([...previous.dependencies,...node.dependencies])]}:node);}
  }
  const affected=new Map([...all].filter(([,node])=>node.affected)),related=await this.referenceGraph(cid,affected,budget);
  for(const node of related.references)all.set(node.key,node);
  const targetGraph=[...all.values()].map(node=>({...node,data:affected.has(node.key)&&node.type!=='targets'?{...node.data,tags:[...new Set([...(node.data.tags??[]).filter((tag:string)=>!tag.startsWith('kos-ws-')),workspaceTag(target.code)])]}:node.data}));
  const nodes:PlanNode[]=[];
  for(const node of affected.values()){
   const workspace=await this.membership(cid,node,all);if(workspace.id!==source.id)throw new ForbiddenException({code:'WORKSPACE_ENTITY_MISMATCH',message:'选择对象及其级联子对象必须属于源工作区'});
   await this.authz.assertEntity(actor.user,cid,node.type,'write',node.data,source.id);await this.authz.assertCluster(actor.user,cid,node.type,'write',target.id);
   if(node.type==='plugins'&&!foreign(node.data.service)&&!foreign(node.data.route)&&!foreign(node.data.consumer)&&!await this.authz.isPlatformAdmin(actor.user))throw new ForbiddenException({code:'GLOBAL_PLUGIN_PERMISSION_REQUIRED',message:'全局插件迁移需要平台管理权限'});
   const afterTags=[...new Set([...(Array.isArray(node.data.tags)?node.data.tags:[]).filter((tag:string)=>!tag.startsWith('kos-ws-')),workspaceTag(target.code)])];
   await this.authz.assertMigrationEntity(actor.user,cid,node.type,'write',{...node.data,tags:node.type==='targets'?node.data.tags:afterTags},target.id,targetGraph);
   nodes.push({...node,sourceWorkspaceId:source.id,beforeFingerprint:this.secrets.fingerprint(node.data),configFingerprint:this.secrets.fingerprint(stableConfig(node.data)),afterTags:node.type==='targets'?node.data.tags??[]:afterTags,inheritedOnly:node.type==='targets'});
  }
  const conflicts:Conflict[]=[];
  for(const reference of related.references){const workspace=await this.membership(cid,reference,all);(reference as GraphNode&{workspaceId?:string}).workspaceId=workspace.id;await this.authz.assertEntity(actor.user,cid,reference.type,'read',reference.data,workspace.id);}
  for(const [child,parent] of related.edges){
   const childNode=all.get(child),parentNode=all.get(parent);if(!childNode||!parentNode)throw new BadGatewayException({code:'MIGRATION_REFERENCE_MISSING',message:'迁移检查缺少完整引用对象'});
   const childWorkspace=affected.has(child)?target.id:(await this.membership(cid,childNode,all)).id;
   const parentWorkspace=affected.has(parent)?target.id:(await this.membership(cid,parentNode,all)).id;
   if(childWorkspace!==parentWorkspace)conflicts.push({code:'CROSS_WORKSPACE_REFERENCE',message:'迁移后会产生跨工作区引用；请把相关对象一同选择，或先解除关联',objects:[child,parent]});
  }
  const payload:PlanPayload={source,target,nodes:this.order(nodes),referenceNodes:related.references,edges:related.edges,conflicts,budget,permissions:await this.authz.permissionVersion(actor.user)};
  if(Buffer.byteLength(JSON.stringify(payload))>MAX.bytes)throw new ConflictException({code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT',message:'加密迁移计划超过 32 MiB，请缩小范围'});
  const id=randomUUID(),hash=this.secrets.fingerprint({cid,actor:actor.user.id,payload}),expires=new Date(Date.now()+1800000);
  const steps:Step[]=payload.nodes.map(node=>({key:node.key,type:node.type,id:node.id,status:'pending'}));
  await this.db.transaction(async tx=>{
   await tx.exec(`INSERT INTO workspace_migration_plans(id,cluster_id,actor_id,source_workspace_id,target_workspace_id,plan_hash,payload_secret,steps,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'[]',$8)`,[id,cid,actor.user.id,source.id,target.id,hash,this.secrets.encrypt(payload,`workspace-migration:${id}`),expires]);
   await tx.exec(`INSERT INTO workspace_migration_steps(cluster_id,plan_id,object_key,type,kong_id,status)
    SELECT $1,$2,entry.key,entry.type,entry.id::uuid,entry.status FROM jsonb_to_recordset($3::jsonb) AS entry(key text,type text,id text,status text)`,[cid,id,JSON.stringify(steps)]);
   await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:source.id,entityType:'workspace_migration',entityId:id,action:'plan',after:{target_workspace_id:target.id,affected:nodes.map(node=>({type:node.type,id:node.id})),conflicts,budget},requestId:actor.requestId,ip:actor.ip},tx);
  });
  return this.get(cid,id,{...actor,workspaceId:source.id});
 }
 private order(nodes:PlanNode[]):PlanNode[]{
  const remaining=new Map(nodes.map(node=>[node.key,node])),ordered:PlanNode[]=[];
  while(remaining.size){const ready=[...remaining.values()].filter(node=>node.dependencies.every(key=>!remaining.has(key))).sort((a,b)=>a.key.localeCompare(b.key));if(!ready.length)throw new ConflictException({code:'MIGRATION_DEPENDENCY_CYCLE',message:'迁移对象依赖存在循环'});for(const node of ready){ordered.push(node);remaining.delete(node.key);}}
  return ordered;
 }
 private async load(cid:string,id:string,actor:EntityActor):Promise<{row:PlanRow;payload:PlanPayload}>{
  await this.authz.assertCluster(actor.user,cid,'workspaces','read',actor.workspaceId);
  const source=await this.workspaces.resolve(cid,actor.workspaceId),row=await this.db.one<PlanRow>('SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2',[cid,id]);
  if(!row)throw new NotFoundException({code:'MIGRATION_PLAN_NOT_FOUND',message:'迁移计划不存在'});
  if(row.source_workspace_id!==source.id)throw new ForbiddenException({code:'MIGRATION_WORKSPACE_MISMATCH',message:'迁移计划不属于所选源工作区'});
  if(row.actor_id!==actor.user.id&&!await this.authz.isPlatformAdmin(actor.user))throw new NotFoundException({code:'MIGRATION_PLAN_NOT_FOUND',message:'迁移计划不存在'});
  const payload=this.secrets.decrypt<PlanPayload>(row.payload_secret,`workspace-migration:${row.id}`);
  const normalized=await this.db.query<Step>('SELECT object_key AS key,type,kong_id::text AS id,status,after_fingerprint,error_code FROM workspace_migration_steps WHERE cluster_id=$1 AND plan_id=$2',[cid,id]);
  row.steps=normalized;
  row.workflow_id=(await this.db.one<{workflow_id:string}>('SELECT workflow_id FROM workspace_migration_workflow_bindings WHERE cluster_id=$1 AND migration_plan_id=$2',[cid,id]))?.workflow_id;
  const nodes=new Map(payload.nodes.map(node=>[node.key,node]));
  if(payload.source.id!==row.source_workspace_id||payload.target.id!==row.target_workspace_id||payload.source.cluster_id!==cid||payload.target.cluster_id!==cid||nodes.size!==payload.nodes.length||normalized.length!==nodes.size||new Set(normalized.map(step=>step.key)).size!==nodes.size||normalized.some(step=>{const node=nodes.get(step.key);return !node||node.type!==step.type||node.id!==step.id||!['pending','succeeded','failed','uncertain'].includes(step.status)||step.status==='succeeded'&&!step.after_fingerprint;}))throw new BadGatewayException({code:'MIGRATION_PLAN_INVALID',message:'迁移计划的范围或步骤记录不一致'});
  await this.authz.assertCluster(actor.user,cid,'workspaces','read',payload.source.id);await this.authz.assertCluster(actor.user,cid,'workspaces','read',payload.target.id);
  // Re-authorize encrypted history rather than treating its submitting actor as a capability.
  for(const node of payload.nodes)await this.authz.assertMigrationEntity(actor.user,cid,node.type,'read',node.data,payload.source.id,this.graph(payload));
  for(const reference of payload.referenceNodes){const workspaceId=reference.workspaceId??(await this.workspaces.classify(cid,reference.data.tags)).workspace?.id;if(!workspaceId)throw new ForbiddenException({code:'WORKSPACE_ENTITY_MISMATCH',message:'迁移引用的历史范围无效'});await this.authz.assertEntity(actor.user,cid,reference.type,'read',reference.data,workspaceId);}
  return {row,payload};
 }
 private view(row:PlanRow,payload:PlanPayload):any{
  const statuses=new Map(row.steps.map(step=>[step.key,step]));
  return {id:row.id,cluster_id:row.cluster_id,source_workspace_id:row.source_workspace_id,target_workspace_id:row.target_workspace_id,target_workspace_name:payload.target.name,
   state:row.state==='planned'&&Date.parse(String(row.expires_at))<=Date.now()?'expired':row.state,plan_hash:row.plan_hash,expires_at:row.expires_at,operation_id:row.operation_id,...(row.workflow_id?{workflow_id:row.workflow_id}:{}),
   affected:payload.nodes.map(node=>({key:node.key,type:node.type,id:node.id,name:displayName(node),before_tags:(node.data.tags??[]).map(decodeTag),after_tags:node.afterTags.map(decodeTag),status:statuses.get(node.key)?.status??'pending',inherited_only:node.inheritedOnly,source_workspace_id:node.sourceWorkspaceId,target_workspace_id:payload.target.id})),
   references:payload.referenceNodes.map(node=>({type:node.type,id:node.id,name:displayName(node),workspace_id:node.workspaceId??null,affected:false})),conflicts:payload.conflicts,budget:payload.budget,
   steps:row.steps.map(step=>({key:step.key,type:step.type,id:step.id,status:step.status,...(step.error_code?{error_code:step.error_code}:{})})),warnings:['工作区仅限制控制台管理范围；直连 Admin API 可以绕过，Kong 名称与 Consumer 仍属于同一运行空间。','全局插件的运行效果不受工作区标签限制。','Target 继承 Upstream 工作区；迁移不追加 Target 历史。','Kong 不提供多对象事务；部分失败后须先核验，再明确确认继续。','回收站历史归属保持不变，恢复时会重新校验共享依赖。']};
 }
 @KongActorScope({module:'workspaces',action:'read'})
 async get(cid:string,id:string,actor:EntityActor):Promise<any>{const {row,payload}=await this.load(cid,id,actor);return this.view(row,payload);}

 /** Server compiler input, never an HTTP response. Complete encrypted M3
  * evidence must be current before it is bound to an immutable approval. */
 @KongActorScope({module:'workspaces',action:'write'})
 async workflowMaterial(cid:string,id:string,input:unknown,actor:EntityActor):Promise<{row:PlanRow;material:WorkspaceMigrationMaterial}>{
  const body=this.body(input,['confirmed','confirm_name','plan_hash']),{row,payload}=await this.load(cid,id,actor);this.validateHash(row,body);
  if(row.actor_id!==actor.user.id)throw new ForbiddenException({code:'MIGRATION_PLAN_OWNER_REQUIRED'});
  if(body.confirmed!==true||body.confirm_name!==payload.target.name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED'});
  if(row.state!=='planned'||row.operation_id||row.steps.some(step=>step.status!=='pending')||payload.conflicts.length)throw new ConflictException({code:'MIGRATION_NOT_SUBMITTABLE',message:'仅未执行且无冲突的完整迁移计划可提交审批'});
  if(Date.parse(String(row.expires_at))<=Date.now())throw new ConflictException({code:'MIGRATION_PLAN_EXPIRED'});
  if(this.secrets.fingerprint({cid,actor:row.actor_id,payload})!==row.plan_hash)throw new ConflictException({code:'MIGRATION_PLAN_INVALID'});
  await this.revisions(cid,payload,actor);
  if(payload.permissions!==await this.authz.permissionVersion(actor.user))throw new ConflictException({code:'MIGRATION_PERMISSIONS_CHANGED'});
  await this.referencesUnchanged(cid,payload);this.validateCurrent(row,payload,await this.currentNodes(cid,payload,actor));
  return {row,material:structuredClone(payload)};
 }

 private validateHash(row:PlanRow,body:any):void{
  if(typeof body.plan_hash!=='string'||body.plan_hash!==row.plan_hash)throw new ConflictException({code:'MIGRATION_PLAN_HASH_MISMATCH',message:'迁移计划已变化，请重新预览'});
 }
 private async revisions(cid:string,payload:PlanPayload,actor:EntityActor,rebase=false):Promise<void>{
  const source=await this.workspaces.get(cid,payload.source.id),target=await this.workspaces.get(cid,payload.target.id);this.active(source);this.active(target);
  if(source.code!==payload.source.code||target.code!==payload.target.code)throw new ConflictException({code:'MIGRATION_WORKSPACE_CHANGED',message:'工作区编码已变化，核验已停止'});
  if(!rebase&&(source.revision!==payload.source.revision||target.revision!==payload.target.revision))throw new ConflictException({code:'MIGRATION_WORKSPACE_CHANGED',message:'工作区元数据已变化，请重新预览或核验迁移计划'});
  await this.authz.assertCluster(actor.user,cid,'workspaces','write',source.id);await this.authz.assertCluster(actor.user,cid,'workspaces','write',target.id);
  if(rebase){payload.source=source;payload.target=target;payload.permissions=await this.authz.permissionVersion(actor.user);}
 }
 private async currentNodes(cid:string,payload:PlanPayload,actor:EntityActor):Promise<Map<string,GraphNode>>{
  const current=new Map<string,GraphNode>();
  for(const node of [...payload.nodes,...payload.referenceNodes]){
   const data=await this.read(cid,node.path);if(data?.id!==node.id)throw new ConflictException({code:'MIGRATION_OBJECT_ID_CHANGED',message:'迁移对象标识已变化，执行已停止'});current.set(node.key,{...node,data});
  }
  for(const node of current.values()){
   const workspace=await this.membership(cid,node,current);
   const original=payload.nodes.find(item=>item.key===node.key);
   if(original){if(![payload.source.id,payload.target.id].includes(workspace.id))throw new ForbiddenException({code:'WORKSPACE_ENTITY_MISMATCH',message:'迁移对象已被移入其他工作区'});await this.authz.assertMigrationEntity(actor.user,cid,node.type,'write',original.data,payload.source.id,this.graph(payload));}
   else await this.authz.assertEntity(actor.user,cid,node.type,'read',node.data,workspace.id);
   if(payload.nodes.some(item=>item.key===node.key)){
    await this.authz.assertCluster(actor.user,cid,node.type,'write',payload.source.id);await this.authz.assertCluster(actor.user,cid,node.type,'write',payload.target.id);
    const planned=payload.nodes.find(item=>item.key===node.key)!;
    await this.authz.assertMigrationEntity(actor.user,cid,node.type,'write',{...node.data,tags:planned.afterTags},payload.target.id,this.graph(payload,true));
    if(node.type==='plugins'&&!foreign(node.data.service)&&!foreign(node.data.route)&&!foreign(node.data.consumer)&&!await this.authz.isPlatformAdmin(actor.user))throw new ForbiddenException({code:'GLOBAL_PLUGIN_PERMISSION_REQUIRED',message:'全局插件迁移需要平台管理权限'});
   }
  }
  return current;
 }
 private async referencesUnchanged(cid:string,payload:PlanPayload):Promise<void>{
  const affected=new Map(payload.nodes.map(node=>[node.key,node])),budget:Budget={pages:0,records:0,nodes:0,bytes:0};
  const related=await this.referenceGraph(cid,affected,budget);
  const paths=payload.nodes.filter(node=>node.type==='consumers').flatMap(node=>[...credentials].map(kind=>`/consumers/${identifier(node.id)}/${kind}`));
  if(paths.length)await this.execution.runInternalRead(cid,'migration',()=>assertMigrationConsumerCredentialClosure(this.kong,cid,payload.nodes,budget,{maxPages:MAX.pages,maxRecords:MAX.records}),{paths,maxCalls:MAX.pages,maxPages:MAX.pages,maxRecords:MAX.records,maxBytes:MAX.bytes,timeoutMs:120000});
  const normalize=(edges:Array<[string,string]>)=>JSON.stringify(edges.map(edge=>JSON.stringify(edge)).sort());
  if(normalize(related.edges)!==normalize(payload.edges))throw new ConflictException({code:'MIGRATION_REFERENCES_CHANGED',message:'相关引用已变化，迁移已停止，请重新检查配置'});
  const originals=new Map(payload.referenceNodes.map(node=>[node.key,node]));
  for(const reference of related.references){const original=originals.get(reference.key);if(!original||this.secrets.fingerprint(reference.data)!==this.secrets.fingerprint(original.data))throw new ConflictException({code:'MIGRATION_REFERENCE_CHANGED',message:'共享引用已变化，迁移已停止'});}
 }
 private validateCurrent(row:PlanRow,payload:PlanPayload,current:Map<string,GraphNode>):void{
  const steps=new Map(row.steps.map(step=>[step.key,step]));
  for(const node of payload.nodes){const step=steps.get(node.key),data=current.get(node.key)?.data;
   if(!step||!data)throw new BadGatewayException({code:'MIGRATION_PLAN_INVALID',message:'迁移步骤记录不完整'});
   if(step.status==='uncertain')throw new ConflictException({code:'MIGRATION_RECONCILIATION_REQUIRED',message:'存在结果不确定的步骤，请先核验迁移状态'});
   const fingerprint=this.secrets.fingerprint(data),expected=step.status==='succeeded'?(step.after_fingerprint??node.beforeFingerprint):node.beforeFingerprint;
   if(fingerprint!==expected)throw new ConflictException({code:'MIGRATION_OBJECT_CHANGED',message:'对象在计划生成后发生变化，请先核验迁移状态'});
  }
 }
 private async recordStep(row:PlanRow,node:PlanNode,status:StepState,actor:EntityActor,data?:any,code?:string):Promise<void>{
  const next:Step={key:node.key,type:node.type,id:node.id,status,...(data?{after_fingerprint:this.secrets.fingerprint(data)}:{}),...(code?{error_code:code}:{})};
  row.steps=row.steps.map(step=>step.key===node.key?next:step);
  await this.db.transaction(async tx=>{
   const changed=await tx.exec(`INSERT INTO workspace_migration_steps(cluster_id,plan_id,object_key,type,kong_id,status,after_fingerprint,error_code)
    SELECT $1,$2,$3,$4,$5::uuid,$6,$7,$8 FROM workspace_migration_plans p WHERE p.cluster_id=$1 AND p.id=$2 AND p.operation_id=$9
    ON CONFLICT(cluster_id,plan_id,object_key) DO UPDATE SET status=excluded.status,after_fingerprint=excluded.after_fingerprint,error_code=excluded.error_code,updated_at=now()`,[row.cluster_id,row.id,node.key,node.type,node.id,status,next.after_fingerprint??null,code??null,row.operation_id]);
   if(!changed)throw new ConflictException({code:'MIGRATION_OPERATION_CHANGED',message:'迁移执行记录已变化，结果需要核验'});
   await this.audit.append({actorId:actor.user.id,clusterId:row.cluster_id,workspaceId:row.source_workspace_id,entityType:node.type,entityId:node.id,
    workflowId:row.workflow_id,action:node.inheritedOnly?'workspace.inherit':'workspace.migrate',before:node.inheritedOnly?{workspace_id:node.sourceWorkspaceId,target:node.data.target}:node.data,
    after:data?node.inheritedOnly?{workspace_id:row.target_workspace_id,target:data.target}:data:{error_code:code??null},result:status,requestId:actor.requestId,ip:actor.ip,...(status==='succeeded'&&data?{scopeHints:nativeAuditScope({type:node.type,id:node.id,before:node.data,after:data,beforeWorkspaceId:node.sourceWorkspaceId,afterWorkspaceId:row.target_workspace_id,parentId:node.data.consumer?.id??node.data.upstream?.id,credentialKind:credentials.has(node.type)?node.type:undefined})}:{})},tx);
  });
 }
 private code(error:any):string{const detail=error instanceof HttpException?error.getResponse():null;return String((typeof detail==='object'&&detail!==null&&(detail as any).code)||error?.code||'MIGRATION_STEP_FAILED').toUpperCase().replace(/[^A-Z0-9_]/g,'_').slice(0,80)||'MIGRATION_STEP_FAILED';}
 private uncertain(error:any):boolean{return !(error instanceof HttpException)||error.getStatus()>=500||['KONG_WRITE_RESULT_UNKNOWN','LOCK_LOST','ETIMEDOUT','ECONNRESET'].includes(this.code(error));}
 private async state(row:PlanRow,state:PlanState):Promise<void>{
  const changed=await this.db.exec('UPDATE workspace_migration_plans SET state=$3,updated_at=now() WHERE cluster_id=$1 AND id=$2 AND operation_id IS NOT DISTINCT FROM $4::uuid',[row.cluster_id,row.id,state,row.operation_id]);
  if(!changed)throw new ConflictException({code:'MIGRATION_OPERATION_CHANGED',message:'迁移执行记录已变化，结果需要核验'});row.state=state;
 }

 @KongActorScope({module:'workspaces',action:'write'})
 async apply(cid:string,id:string,input:unknown,actor:EntityActor):Promise<any>{
  const body=this.body(input,['confirmed','confirm_name','plan_hash']),initial=await this.load(cid,id,actor);
  this.validateHash(initial.row,body);
  if(initial.row.actor_id!==actor.user.id)throw new ForbiddenException({code:'MIGRATION_PLAN_OWNER_REQUIRED',message:'请由提交此迁移计划的账号执行'});
  if(body.confirmed!==true||body.confirm_name!==initial.payload.target.name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'请二次确认并输入目标工作区名称'});
  if(initial.payload.conflicts.length)throw new ConflictException({code:'MIGRATION_REFERENCE_CONFLICT',message:'迁移计划存在跨工作区引用冲突，尚未修改配置'});
  if(Date.parse(String(initial.row.expires_at))<=Date.now())throw new ConflictException({code:'MIGRATION_PLAN_EXPIRED',message:'迁移计划已过期，请重新生成'});
  if(initial.row.workflow_id){
   // A later cluster mode change cannot turn an already frozen approval into
   // a direct mutation. Only the private running native step can enter here.
   if(this.execution.currentApprovedStep().kind!=='native'||(await this.db.one<{execution_mode:string}>('SELECT execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]))?.execution_mode!=='approval')throw new ForbiddenException({code:'MIGRATION_APPROVED_EXECUTION_REQUIRED'});
  }
  const context={clusterId:cid,workspaceId:initial.row.source_workspace_id,actor:actor.user,entityType:'workspace_migration',entityId:id,action:'migrate',
   before:{id,workspace_id:initial.row.source_workspace_id},payload:{plan_id:id,plan_hash:body.plan_hash,confirmed:true,confirm_name:body.confirm_name},
   idempotencyKey:actor.idempotencyKey,requestId:actor.requestId,ip:actor.ip,impactNodes:[...initial.payload.nodes,...initial.payload.referenceNodes],operationId:undefined as string|undefined};
  return this.mutations.execute(context,async()=>{
   const {row,payload}=await this.load(cid,id,actor);
   this.validateHash(row,body);
   if(body.confirmed!==true||body.confirm_name!==payload.target.name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'目标工作区名称已变化，请重新预览并二次确认'});
   if(payload.conflicts.length)throw new ConflictException({code:'MIGRATION_REFERENCE_CONFLICT',message:'迁移计划存在跨工作区引用冲突，尚未修改配置'});
   if(Date.parse(String(row.expires_at))<=Date.now())throw new ConflictException({code:'MIGRATION_PLAN_EXPIRED',message:'迁移计划已过期，请重新生成'});
   if(row.state==='succeeded')return this.view(row,payload);
   if(!['planned','partial'].includes(row.state))throw new ConflictException({code:'MIGRATION_STATE_CONFLICT',message:'迁移正在执行或需要核验，请检查原操作'});
   if(row.operation_id){const prior=await this.db.one<any>('SELECT state FROM mutation_operations WHERE cluster_id=$1 AND id=$2',[cid,row.operation_id]);if(!prior||['running','uncertain'].includes(prior.state))throw new ConflictException({code:'MIGRATION_RECONCILIATION_REQUIRED',message:'上一轮操作尚未核验为确定结果'});}
   await this.revisions(cid,payload,actor);
   if(payload.permissions!==await this.authz.permissionVersion(actor.user))throw new ConflictException({code:'MIGRATION_PERMISSIONS_CHANGED',message:'执行权限已变化，请重新生成计划'});
   await this.referencesUnchanged(cid,payload);
   const current=await this.currentNodes(cid,payload,actor);this.validateCurrent(row,payload,current);
   await this.redis.assertLeaseOwnership();
   const operationId=context.operationId??null;
   const started=await this.db.exec("UPDATE workspace_migration_plans SET state='running',operation_id=$3,updated_at=now() WHERE cluster_id=$1 AND id=$2 AND plan_hash=$4 AND state=$5 AND operation_id IS NOT DISTINCT FROM $6::uuid",[cid,id,operationId,row.plan_hash,row.state,row.operation_id]);
   if(!started)throw new ConflictException({code:'MIGRATION_OPERATION_CHANGED',message:'迁移执行记录已变化，请核验原操作'});
   row.operation_id=operationId;row.state='running';
   for(const node of payload.nodes){
    if(row.steps.find(step=>step.key===node.key)?.status==='succeeded')continue;
    let remoteReturned=false;
    try{
     // Existing references are reread before each write. The cluster lock protects other BFF writers.
     const fresh=await this.refreshStep(cid,row,payload,node,current,actor);
     const before=fresh.get(node.key)!.data,actualWorkspace=await this.membership(cid,{...node,data:before},fresh);
     await this.authz.assertMigrationEntity(actor.user,cid,node.type,'write',node.data,payload.source.id,this.graph(payload));
     await this.authz.assertMigrationEntity(actor.user,cid,node.type,'write',{...before,tags:node.afterTags},payload.target.id,this.graph(payload,true));
     let after=before;
     if(!node.inheritedOnly){await this.kong.request(cid,'PATCH',node.path,{tags:node.afterTags});remoteReturned=true;after=await this.read(cid,node.path);}
     if(after?.id!==node.id||!sameTags(after.tags,node.afterTags)||this.secrets.fingerprint(stableConfig(after))!==node.configFingerprint)throw new BadGatewayException({code:'MIGRATION_WRITE_VERIFICATION_FAILED',message:'标签写入后配置校验不一致，请核验迁移状态'});
     await this.recordStep(row,node,'succeeded',actor,after);
     current.set(node.key,{...node,data:after});
     if(nativeKinds.includes(node.type))await this.index.upsert(cid,node.type,after).catch(()=>undefined);
    }catch(error:any){
     const unknown=remoteReturned||this.uncertain(error),status=unknown?'uncertain':'failed';
     await this.recordStep(row,node,status,actor,undefined,this.code(error)).catch(()=>undefined);
     await this.state(row,'partial').catch(()=>undefined);
     if(unknown)throw new HttpException({code:'MIGRATION_RESULT_UNCERTAIN',message:'迁移步骤结果需要核验；不会自动重试',operationId:context.operationId,state:'uncertain'},503);
     return this.view(row,payload);
    }
   }
   await this.state(row,'succeeded');return this.view(row,payload);
  });
 }

 private async refreshStep(cid:string,row:PlanRow,payload:PlanPayload,node:PlanNode,current:Map<string,GraphNode>,actor:EntityActor):Promise<Map<string,GraphNode>>{
  const planned=new Map(payload.nodes.map(item=>[item.key,item])),references=new Map(payload.referenceNodes.map(item=>[item.key,item]));
  const keys=new Set([node.key,...node.dependencies]);
  for(const [child,parent] of payload.edges)if((child===node.key&&references.has(parent))||(parent===node.key&&references.has(child)))keys.add(child===node.key?parent:child);
  for(const key of keys){const known=current.get(key);if(!known)throw new BadGatewayException({code:'MIGRATION_PARENT_MISSING',message:'执行图缺少引用对象'});const data=await this.read(cid,known.path);if(data?.id!==known.id)throw new ConflictException({code:'MIGRATION_OBJECT_ID_CHANGED',message:'对象标识在执行期间变化'});current.set(key,{...known,data});}
  for(const key of keys){
   const actual=current.get(key)!,original=references.get(key),candidate=planned.get(key),step=row.steps.find(item=>item.key===key);
   const expected=original?this.secrets.fingerprint(original.data):step?.status==='succeeded'?(step.after_fingerprint??candidate?.beforeFingerprint):candidate?.beforeFingerprint;
   if(!expected||this.secrets.fingerprint(actual.data)!==expected)throw new ConflictException({code:'MIGRATION_OBJECT_CHANGED',message:'对象或共享引用在执行期间变化，请核验迁移状态'});
   const workspace=await this.membership(cid,actual,current);
   if(candidate){if(![payload.source.id,payload.target.id].includes(workspace.id))throw new ForbiddenException({code:'WORKSPACE_ENTITY_MISMATCH',message:'迁移对象已被移入其他工作区'});await this.authz.assertMigrationEntity(actor.user,cid,actual.type,'write',candidate.data,payload.source.id,this.graph(payload));}
   else await this.authz.assertEntity(actor.user,cid,actual.type,'read',actual.data,workspace.id);
  }
  return current;
 }

 /** No native writes. A durable receipt is resolved only from every object's fresh state. */
 @KongActorScope({module:'workspaces',action:'write'})
 async reconcile(cid:string,id:string,input:unknown,actor:EntityActor):Promise<any>{
  const body=this.body(input,['plan_hash']),initial=await this.load(cid,id,actor);this.validateHash(initial.row,body);
  if(initial.row.actor_id!==actor.user.id)throw new ForbiddenException({code:'MIGRATION_PLAN_OWNER_REQUIRED',message:'请由提交此迁移计划的账号核验'});
  return this.redis.withLock(`mutation:${await this.kong.transportScope(cid)}`,async()=>{
   const {row,payload}=await this.load(cid,id,actor),oldHash=row.plan_hash,bound=!!row.workflow_id;this.validateHash(row,body);await this.revisions(cid,payload,actor,!bound);
   await this.referencesUnchanged(cid,payload);const current=await this.currentNodes(cid,payload,actor);
   const next:Step[]=[],proof:Array<{key:string;state:string;fingerprint:string}>=[];
   for(const node of payload.nodes){
    const data=current.get(node.key)!.data;
    if(this.secrets.fingerprint(stableConfig(data))!==node.configFingerprint)throw new ConflictException({code:'MIGRATION_OBJECT_CHANGED',message:'对象的非标签配置已变化，核验已停止，未执行网关写入'});
    const applied=node.inheritedOnly?(await this.membership(cid,{...node,data},current)).id===payload.target.id:sameTags(data.tags,node.afterTags);
    const original=node.inheritedOnly?(await this.membership(cid,{...node,data},current)).id===payload.source.id:sameTags(data.tags,node.data.tags);
    if(!applied&&!original)throw new ConflictException({code:'MIGRATION_TAGS_CHANGED',message:'对象标签与计划前后状态均不一致，核验已停止'});
    const fingerprint=this.secrets.fingerprint(data);
    next.push({key:node.key,type:node.type,id:node.id,status:applied?'succeeded':'pending',...(applied?{after_fingerprint:fingerprint}:{})});
    if(!applied&&!bound){node.beforeFingerprint=fingerprint;node.data=data;}
    proof.push({key:node.key,state:applied?'applied':'unchanged',fingerprint});
   }
   row.steps=next;row.state=next.every(step=>step.status==='succeeded')?'succeeded':row.operation_id?'partial':'planned';
   if(row.state!=='succeeded'&&!bound)row.expires_at=new Date(Date.now()+1800000);
   if(!bound)row.plan_hash=this.secrets.fingerprint({cid,actor:row.actor_id,payload});
   const result=this.view(row,payload);
   await this.redis.assertLeaseOwnership();
   await this.db.transaction(async tx=>{
    const locked=await tx.one<any>('SELECT plan_hash,operation_id FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,id]);
    if(!locked||locked.plan_hash!==oldHash||locked.operation_id!==row.operation_id)throw new ConflictException({code:'MIGRATION_OPERATION_CHANGED',message:'迁移计划在核验期间变化，请重新获取状态'});
    await tx.exec(`INSERT INTO workspace_migration_steps(cluster_id,plan_id,object_key,type,kong_id,status,after_fingerprint)
     SELECT $1,$2,entry.key,entry.type,entry.id::uuid,entry.status,entry.after_fingerprint FROM jsonb_to_recordset($3::jsonb) AS entry(key text,type text,id text,status text,after_fingerprint text)
     ON CONFLICT(cluster_id,plan_id,object_key) DO UPDATE SET status=excluded.status,after_fingerprint=excluded.after_fingerprint,error_code=NULL,updated_at=now()`,[cid,id,JSON.stringify(next)]);
    if(bound)await tx.exec("UPDATE workspace_migration_plans SET state=$3,updated_at=now() WHERE cluster_id=$1 AND id=$2",[cid,id,row.state]);
    else await tx.exec("UPDATE workspace_migration_plans SET state=$3,steps='[]',payload_secret=$4,plan_hash=$5,expires_at=$6,updated_at=now() WHERE cluster_id=$1 AND id=$2",[cid,id,row.state,this.secrets.encrypt(payload,`workspace-migration:${id}`),row.plan_hash,row.expires_at]);
    if(row.operation_id){
     const operation=await tx.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,row.operation_id]);
     if(!operation||operation.actor_id!==row.actor_id||operation.entity_type!=='workspace_migration'||operation.entity_id!==id||operation.workspace_id!==row.source_workspace_id)throw new ConflictException({code:'MIGRATION_RECEIPT_MISMATCH',message:'迁移回执与计划不一致，核验结果未提交'});
     await tx.exec("UPDATE mutation_operations SET state='succeeded',remote_completed=true,error_code=NULL,result_secret=$3,safe_result=$4::jsonb,updated_at=now() WHERE cluster_id=$1 AND id=$2",[cid,row.operation_id,this.secrets.encrypt(result,`mutation:${row.operation_id}:result`),JSON.stringify(this.secrets.redact(result))]);
    }
    await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:row.source_workspace_id,entityType:'workspace_migration',entityId:id,workflowId:row.workflow_id,action:'reconcile',before:{plan_hash:oldHash},after:{plan_hash:row.plan_hash,state:row.state,proof,native_writes:0},requestId:actor.requestId,ip:actor.ip},tx);
   });
   for(const node of payload.nodes)if(nativeKinds.includes(node.type))await this.index.upsert(cid,node.type,current.get(node.key)!.data).catch(()=>undefined);
   return result;
  });
 }
}
