import { BadRequestException, ForbiddenException, HttpException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import { DbService } from '../../infrastructure/db.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import type { AuthUser } from '../../common/auth';
import { ConsoleCapabilities, EffectiveGrant, PERMISSION_ACTIONS, PERMISSION_MODULES, PermissionAction, permissionAction, permissionModule } from '../../common/authorization.types';
import { coarseGrantMatches, grantContains, grantMatchesEntity, inheritedTagMatches, validGrant } from './grant-policy';
import { canonicalJson } from '../../infrastructure/secret.service';
import { pluginMetadata } from '../plugin-center/plugin-metadata';
import type { GraphNode } from '../recycle-bin/graph-capturer.service';
import type { WorkspaceMigrationMaterial } from '../workspaces/workspace-migration.service';
import { normalizeEntityAuthorizationView } from '../entities/entity-reference';
import type { WorkflowScheduledNamespaceProof } from '../workflows/workflow-scheduled-authority.types';

const native = new Set(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis']);
// Operational grants permit only the minimal cluster/workspace registry
// discovery needed to select their tenant. They never imply native read.
const discoverableModules = [...native,'workspaces','overview','monitoring','portal','developers','applications','workflows','audit','events','notifications','snapshots','gitops','toolbox','batches','drafts'];
const credentials = new Set(['credentials','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const denied=()=>new ForbiddenException({code:'PERMISSION_DENIED',message:'当前账号无此操作权限'});
export interface AuthorizationSnapshot {user:AuthUser;grants:EffectiveGrant[];version:string}
type ArchivedParents=ReadonlyMap<string,GraphNode>;

/** Root installs one SQL-only bridge. The original Context namespace handle
 * and proof reference are its input, never caller-provided authority. The
 * bridge independently checks the live claim, window, lease, delegation and
 * principal's current eligibility without re-entering the full business
 * verifier or AuthorizationService.snapshot(). Its result grants no packet. */
export interface WorkflowScheduledCurrentIdentityBridge {
 currentPrincipal(originalNamespaceHandle:object,originalNamespaceProof:Readonly<WorkflowScheduledNamespaceProof>,
  actualActorId:string,transaction:DbService):Promise<Readonly<{
   actorId:string;credentialEpoch:string;permissionVersion:string;role:'executor'|'reviewer';readOnly:boolean;
  }>>;
}

/** Each native request uses current database grants; no JWT or caller projection grants authority. */
@Injectable()
export class AuthorizationService {
 private workflowScheduledIdentityBridge?:Readonly<WorkflowScheduledCurrentIdentityBridge>;
 private readonly workflowScheduledIdentityBridgeActive=new AsyncLocalStorage<true>();
 constructor(private readonly db:DbService,private readonly workspaces:WorkspaceResolverService,
  private readonly kong:KongService,private readonly execution:KongExecutionContextService){}

 installWorkflowScheduledCurrentIdentityBridge(bridge:WorkflowScheduledCurrentIdentityBridge):void{
  if(this.workflowScheduledIdentityBridge||!bridge||typeof bridge.currentPrincipal!=='function')
   throw new Error('A single complete business scheduled current identity bridge must be installed');
  this.workflowScheduledIdentityBridge=Object.freeze({currentPrincipal:bridge.currentPrincipal.bind(bridge)});
 }

 /** Epoch-only fences still re-read the active user and live session. They
  * do not need to materialize all grants; actual permission checks below do. */
 private async currentIdentity(user:AuthUser,transaction?:DbService):Promise<{row:any;version:string}>{
  const db=transaction??this.db;
  if(!user?.id||!uuid.test(user.id))throw denied();
  const frame=this.execution.peek();if(frame?.actor&&frame.actor.id!==user.id)throw denied();
  const businessNamespace=frame&&!frame.sessionId&&this.execution.hasWorkflowScheduledNamespace()
   ?this.execution.requireWorkflowScheduledNamespaceHandle():null;
  let business:Readonly<{actorId:string;credentialEpoch:string;permissionVersion:string;role:'executor'|'reviewer';readOnly:boolean}>|null=null;
  let businessProof:Readonly<WorkflowScheduledNamespaceProof>|null=null;
  let businessPrincipal:ReturnType<KongExecutionContextService['requireWorkflowScheduledCurrentPrincipal']>|null=null;
  const originalBusinessPrincipal=()=>{
   if(!businessNamespace||!businessPrincipal)return false;
   const current=this.execution.requireWorkflowScheduledCurrentPrincipal(businessNamespace);
   return this.execution.peek()===frame&&this.execution.requireWorkflowScheduledNamespaceHandle()===businessNamespace
    &&current.namespace===businessPrincipal.namespace&&current.actor===businessPrincipal.actor
    &&current.role===businessPrincipal.role&&current.readOnly===businessPrincipal.readOnly
    &&current.validationReadHandle===businessPrincipal.validationReadHandle;
  };
  if(businessNamespace){
   if(this.workflowScheduledIdentityBridgeActive.getStore())throw new ForbiddenException({code:'WORKFLOW_SCHEDULE_CURRENT_IDENTITY_REENTRANT'});
   if(!this.workflowScheduledIdentityBridge)throw new ForbiddenException({code:'WORKFLOW_SCHEDULE_CURRENT_IDENTITY_UNAVAILABLE'});
   businessPrincipal=this.execution.requireWorkflowScheduledCurrentPrincipal(businessNamespace);
   businessProof=businessPrincipal.namespace;
   business=await this.workflowScheduledIdentityBridgeActive.run(true,()=>this.workflowScheduledIdentityBridge!.currentPrincipal(businessNamespace,businessProof!,user.id,db));
   // The awaited SQL bridge can outlive its callback or lease. Retain the
   // exact private Context association and recheck the synchronous chain.
   if(!originalBusinessPrincipal())throw denied();
   if(!business||business.actorId!==user.id||typeof business.credentialEpoch!=='string'||!business.credentialEpoch
    ||typeof business.permissionVersion!=='string'||!business.permissionVersion
    ||!['executor','reviewer'].includes(business.role)||typeof business.readOnly!=='boolean'
    ||businessPrincipal.actor.id!==user.id||business.role!==businessPrincipal.role||business.readOnly!==businessPrincipal.readOnly
    ||businessProof.version!==1||businessProof.origin!=='scheduled-workflow'||businessProof.sessionId!==null
    ||!['configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(businessProof.kind)
    ||!Number.isFinite(Date.parse(businessProof.expiresAt))||Date.parse(businessProof.expiresAt)<=Date.now()
    ||business.role==='executor'&&(businessProof.actor.id!==user.id||business.credentialEpoch!==businessProof.credentialEpoch
     ||business.permissionVersion!==businessProof.permissionVersion)
    ||business.role==='reviewer'&&(!business.readOnly||businessProof.actor.id===user.id
     ||!businessProof.approvalSet.reviewers.some(reviewer=>reviewer.userId===user.id)))throw denied();
  }
  const scheduled=!business&&frame&&!frame.sessionId&&(this.execution.hasEntityScheduledNamespace()||!!frame.operation)
   ?await this.execution.verifyEntityScheduledNamespace('packet'):null;
  if(frame?.operation&&!frame.sessionId&&!scheduled&&!business)throw denied();
  const row=await db.one<any>("SELECT id,username,super_admin,status,deleted_at,permissions_epoch,credential_epoch,force_password_change,revision,display_name,locale,timezone FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL",[user.id]);
  if(!row)throw new UnauthorizedException({code:'SESSION_EXPIRED',message:'账号或授权已失效'});
  if(frame?.sessionId&&!await db.one("SELECT id FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() AND credential_epoch=$3",[frame.sessionId,user.id,row.credential_epoch]))throw new UnauthorizedException({code:'SESSION_EXPIRED',message:'会话已失效'});
  const epoch=await db.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!epoch)throw new ForbiddenException({code:'AUTHORIZATION_UNAVAILABLE',message:'权限模型尚未初始化'});
  if(scheduled&&(scheduled.actor.id!==row.id||scheduled.credentialEpoch!==String(row.credential_epoch)
   ||scheduled.permissionVersion!==`${row.id}:${row.permissions_epoch}:${epoch.version}`))throw denied();
  if(business&&(row.force_password_change===true||business.actorId!==row.id||business.credentialEpoch!==String(row.credential_epoch)
   ||business.permissionVersion!==`${row.id}:${row.permissions_epoch}:${epoch.version}`))throw denied();
  if(businessNamespace&&!originalBusinessPrincipal())throw denied();
  return{row,version:`${row.id}:${row.permissions_epoch}:${epoch.version}`};
 }
 async snapshot(user:AuthUser,transaction?:DbService):Promise<AuthorizationSnapshot>{
  const {row,version}=await this.currentIdentity(user,transaction);
  const grants=(await (transaction??this.db).query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[user.id])).filter(validGrant);
  return {user:{id:row.id,username:row.username,superAdmin:row.super_admin===true,displayName:row.display_name,locale:row.locale,
   timezone:row.timezone,revision:row.revision,forcePasswordChange:row.force_password_change===true},grants,version};
 }
 async isPlatformAdmin(user:AuthUser):Promise<boolean>{return (await this.snapshot(user)).user.superAdmin;}
 async permissionVersion(user:AuthUser,transaction?:DbService):Promise<string>{return (await this.currentIdentity(user,transaction)).version;}
 private modules(module:string,action:PermissionAction):string[]{
  module=permissionModule(module);
  if(module==='entities')return [...native];
  if(module==='overview'||module==='workspaces'&&action==='read'||module==='annotations'||module==='mutations'&&action==='read')return [module,...native];
  if(module==='routes'&&(action==='write'||action==='delete'))return [module,'services'];
  if(module==='plugins')return [module,'services','routes','consumers'];
  if(module==='services'&&action==='read')return [module,'routes'];
  if(module==='clusters'&&action==='read')return [module,...discoverableModules];
  return [module];
 }
 private coarse(snapshot:AuthorizationSnapshot,cid:string,module:string,action:PermissionAction,wid?:string):boolean {
  if(snapshot.user.superAdmin)return true;
  if(action==='read'&&module==='services'&&snapshot.grants.some(grant=>permissionModule(grant.module)==='routes'&&coarseGrantMatches(grant,'routes',grant.action,{clusterId:cid,workspaceId:wid})))return true;
  if(action==='read'&&['clusters','workspaces'].includes(module)&&snapshot.grants.some(grant=>discoverableModules.includes(permissionModule(grant.module))&&coarseGrantMatches(grant,grant.module,grant.action,{clusterId:cid,workspaceId:wid})))return true;
  return this.modules(module,action).some(candidate=>snapshot.grants.some(grant=>coarseGrantMatches(grant,candidate,action,{clusterId:cid,workspaceId:wid})));
 }
 async assertCluster(user:AuthUser,cid:string,module:string,action:string,wid?:string,transaction?:DbService):Promise<void>{
  if(!uuid.test(cid??'')||wid!==undefined&&!uuid.test(wid))throw new BadRequestException({code:'INVALID_SCOPE_ID',message:'集群或工作区 ID 无效'});
  if(!this.coarse(await this.snapshot(user,transaction),cid,module,permissionAction(action),wid))throw denied();
  if(!await (transaction??this.db).one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]))throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
  if(wid!==undefined)await this.workspaces.get(cid,wid,true,transaction);
 }
 async assertConsole(user:AuthUser,module:string,action:string,_targetId?:string):Promise<void>{
  const snapshot=await this.snapshot(user);
  if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>grant.module===permissionModule(module)&&grant.action===permissionAction(action)
   &&grant.scope_type==='global'&&grant.cluster_id===null&&grant.workspace_id===null))throw denied();
 }
 /** Operational data has its own module grants. Knowing a monitored identity
  * never grants the native configuration or a parent's inherited permissions. */
 private async scopedResourceMatches(snapshot:AuthorizationSnapshot,cid:string,module:string,action:PermissionAction,
  nativeType:string,entity:any,wid?:string):Promise<boolean>{
  if(!native.has(nativeType)||!entity||typeof entity!=='object'||Array.isArray(entity)||!uuid.test(entity.id??''))return false;
  const membership=await this.workspaces.classify(cid,entity.tags);
  if(membership.state!=='resolved'||!membership.workspace||membership.workspace.status==='deleted'
   ||wid!==undefined&&membership.workspace.id!==wid)return false;
  // Disabled workspaces retain their read history; provisioning is checked by
  // the workspace writer separately. Deleted/ambiguous scopes never match.
  return snapshot.user.superAdmin||snapshot.grants.some(grant=>grantMatchesEntity(grant,module,action,
   {clusterId:cid,workspaceId:membership.workspace!.id,entityType:nativeType,entity}));
 }
 async assertScopedResource(user:AuthUser,cid:string,module:string,action:string,nativeType:string,entity:any,wid?:string):Promise<void>{
  await this.assertCluster(user,cid,module,action,wid);
  const snapshot=await this.snapshot(user);
  if(!await this.scopedResourceMatches(snapshot,cid,permissionModule(module),permissionAction(action),nativeType,entity,wid))throw denied();
  if(await this.permissionVersion(user)!==snapshot.version)throw denied();
 }
 async filterScopedResources(user:AuthUser,cid:string,module:string,action:string,nativeType:string,items:any[],wid?:string):Promise<any[]>{
  if(!Array.isArray(items)||items.length>10_000)throw new BadRequestException({code:'SCOPED_RESOURCE_BUDGET',message:'范围核验对象数量超出预算'});
  await this.assertCluster(user,cid,module,action,wid);
  const snapshot=await this.snapshot(user),allowed:any[]=[];
  for(const item of items)if(await this.scopedResourceMatches(snapshot,cid,permissionModule(module),permissionAction(action),nativeType,item,wid))allowed.push(item);
  if(await this.permissionVersion(user)!==snapshot.version)throw denied();
  return allowed;
 }
 async hasWholeCluster(user:AuthUser,cid:string,module:string,action:string,transaction?:DbService):Promise<boolean>{
  if(!uuid.test(cid??''))throw new BadRequestException({code:'INVALID_SCOPE_ID',message:'集群 ID 无效'});
  const snapshot=await this.snapshot(user,transaction),normalizedModule=permissionModule(module),normalizedAction=permissionAction(action);
  if(!await (transaction??this.db).one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]))throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
  const allowed=snapshot.user.superAdmin||snapshot.grants.some(grant=>grant.module===normalizedModule&&grant.action===normalizedAction
   &&grant.scope_type==='global'&&grant.workspace_id===null&&(grant.cluster_id===null||grant.cluster_id===cid));
  if(await this.permissionVersion(user,transaction)!==snapshot.version)throw denied();
  return allowed;
 }
 async assertWholeCluster(user:AuthUser,cid:string,module:string,action:string,transaction?:DbService):Promise<void>{
  if(!await this.hasWholeCluster(user,cid,module,action,transaction))throw denied();
 }
 /** Metadata without native tags or a service identity requires one complete
  * global/workspace grant. Separate restricted rows cannot be combined. */
 async hasWholeWorkspace(user:AuthUser,cid:string,wid:string,module:string,action:string,transaction?:DbService):Promise<boolean>{
  if(!uuid.test(cid??'')||!uuid.test(wid??''))throw new BadRequestException({code:'INVALID_SCOPE_ID',message:'集群或工作区 ID 无效'});
  const normalizedModule=permissionModule(module),normalizedAction=permissionAction(action);
  const snapshot=await this.snapshot(user,transaction);
  if(!await (transaction??this.db).one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]))throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
  const workspace=await this.workspaces.get(cid,wid,false,transaction);
  const allowed=(normalizedAction==='read'||workspace.status==='active')&&(snapshot.user.superAdmin||snapshot.grants.some(grant=>
   grant.module===normalizedModule&&grant.action===normalizedAction
   &&(grant.cluster_id===null||grant.cluster_id===cid)
   &&(grant.workspace_id===null||grant.workspace_id===wid)
   &&(grant.scope_type==='global'||grant.scope_type==='workspace'
    &&grant.cluster_id===cid&&grant.workspace_id===wid
    &&grant.scope_values.length===1&&grant.scope_values[0]===wid)));
  if(await this.permissionVersion(user,transaction)!==snapshot.version)throw denied();
  return allowed;
 }
 async assertWholeWorkspace(user:AuthUser,cid:string,wid:string,module:string,action:string,transaction?:DbService):Promise<void>{
  if(!await this.hasWholeWorkspace(user,cid,wid,module,action,transaction))throw denied();
 }
 /** Revalidate an existing approval under the executor's real session. This
  * verifies the other principal's current SQL eligibility only; it never
  * replaces the HTTP actor, grants a session, or mints native authority. The
  * approved verifier supplies its authenticated/decrypted fixed M3 material. */
 async assertMigrationWorkflowReviewerEligibility(reviewerId:string,cid:string,material:WorkspaceMigrationMaterial):Promise<void>{
  const frame=this.execution.current();
  if(!frame.actor||!frame.sessionId||frame.clusterId!==cid||frame.workspaceId!==material?.source?.id||!['workflows','workspaces','workspace_migration'].includes(frame.module??'')||!['write','migrate'].includes(frame.action??'')||!uuid.test(reviewerId??'')||reviewerId===frame.actor.id||!Array.isArray(material?.nodes)||!material.nodes.length||material.nodes.length+material.referenceNodes.length>96)throw denied();
  const executor=await this.currentIdentity(frame.actor);
  const load=()=>this.db.one<any>("SELECT id,username,super_admin,permissions_epoch,credential_epoch,force_password_change,status,deleted_at FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false",[reviewerId]);
  const row=await load(),epoch=await this.db.one<{version:string}>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!row||!epoch)throw denied();
  const snapshot:AuthorizationSnapshot={user:{id:row.id,username:row.username,superAdmin:row.super_admin===true},grants:(await this.db.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[reviewerId])).filter(validGrant),version:`${row.id}:${row.permissions_epoch}:${epoch.version}`};
  const sourceGraph=[...material.nodes,...material.referenceNodes],targetGraph=[...material.nodes.map(node=>({...node,data:node.inheritedOnly?node.data:{...node.data,tags:node.afterTags}})),...material.referenceNodes];
  const planned=(graph:typeof sourceGraph)=>new Map(graph.filter(node=>native.has(node.type)&&node.data?.id===node.id).map(node=>[`${node.type}:${node.id}`,node.data]));
  const sourcePlanned=planned(sourceGraph),targetPlanned=planned(targetGraph);
  for(const original of [material.source,material.target]){
   const current=await this.workspaces.get(cid,original.id);
   if(current.status!=='active'||current.revision!==original.revision||current.code!==original.code)throw denied();
   const completeApproval=snapshot.user.superAdmin||snapshot.grants.some(grant=>grant.module==='workflows'&&grant.action==='approve'&&(grant.cluster_id===null||grant.cluster_id===cid)&&(grant.workspace_id===null||grant.workspace_id===original.id)
    &&(grant.scope_type==='global'||grant.scope_type==='workspace'&&grant.cluster_id===cid&&grant.workspace_id===original.id&&grant.scope_values.length===1&&grant.scope_values[0]===original.id));
   if(!completeApproval||!this.coarse(snapshot,cid,'workspaces','read',original.id))throw denied();
  }
  for(const node of material.nodes){
   if(!this.coarse(snapshot,cid,node.type,'read',material.source.id)||!await this.permits(snapshot,cid,node.type,'read',node.data,material.source.id,sourcePlanned)
    ||!this.coarse(snapshot,cid,node.type,'read',material.target.id)||!await this.permits(snapshot,cid,node.type,'read',node.inheritedOnly?node.data:{...node.data,tags:node.afterTags},material.target.id,targetPlanned))throw denied();
  }
  for(const node of material.referenceNodes)if(!node.workspaceId||!this.coarse(snapshot,cid,node.type,'read',node.workspaceId)||!await this.permits(snapshot,cid,node.type,'read',node.data,node.workspaceId))throw denied();
  const finalRow=await load(),finalEpoch=await this.db.one<{version:string}>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!finalRow||canonicalJson(finalRow)!==canonicalJson(row)||String(finalEpoch?.version)!==String(epoch.version)||(await this.currentIdentity(frame.actor)).version!==executor.version)throw denied();
 }
 async assertDelegatable(user:AuthUser,proposed:EffectiveGrant[]):Promise<void>{
  const snapshot=await this.snapshot(user);
  if(!Array.isArray(proposed)||proposed.some(grant=>!validGrant(grant)||!(PERMISSION_MODULES as readonly string[]).includes(permissionModule(grant.module))))throw new BadRequestException({code:'INVALID_GRANT',message:'授权必须包含完整且有效的模块、操作及范围'});
  if(snapshot.user.superAdmin)return;
  for(const grant of proposed){
   const pieces=grant.scope_type==='tag_group'||grant.scope_type==='entity'?grant.scope_values.map(value=>({...grant,scope_values:[value]})): [grant];
   if(pieces.some(piece=>!snapshot.grants.some(existing=>grantContains(existing,piece))))throw new ForbiddenException({code:'GRANT_EXCEEDS_AUTHORITY',message:'不能授予超出自身权限范围的角色或权限'});
  }
 }
 async capabilities(user:AuthUser):Promise<ConsoleCapabilities>{
  const snapshot=await this.snapshot(user),rows=await this.db.query<any>('SELECT id FROM clusters WHERE deleted_at IS NULL ORDER BY created_at');
  const modules:ConsoleCapabilities['modules']={};
  for(const module of PERMISSION_MODULES)modules[module]=Object.fromEntries(PERMISSION_ACTIONS.map(action=>[action,snapshot.user.superAdmin||snapshot.grants.some(grant=>this.modules(module,action).includes(permissionModule(grant.module))&&grant.action===action)])) as Record<PermissionAction,boolean>;
  if(snapshot.grants.some(grant=>permissionModule(grant.module)==='routes'))modules.services.read=true;
  if(snapshot.grants.some(grant=>discoverableModules.includes(permissionModule(grant.module))))modules.clusters.read=modules.workspaces.read=true;
  return {modules,grants:snapshot.grants,clusters:rows.filter(row=>this.coarse(snapshot,row.id,'clusters','read')).map(row=>row.id),platformAdmin:snapshot.user.superAdmin};
 }

 /** Delegate to KongExecutionContextService so Authz.fresh and
  * runPortalNativeParentRead share one scheduled-aware point budget. */
 private authorizationPointTimeoutMs():number{return this.execution.authorizationPointTimeoutMs();}
 private async fresh(cid:string,type:string,id:string):Promise<any>{
  if(typeof id!=='string'||!id.length||id.length>256||/[\/\\\u0000-\u001f]/.test(id))throw denied();
  const path=`/${type}/${encodeURIComponent(id)}`;
  return this.execution.runInternalRead(cid,'authorization',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:this.authorizationPointTimeoutMs()});
 }
 private async parent(cid:string,type:string,id:string,planned?:Map<string,any>,archived?:ArchivedParents):Promise<any>{
  const archivedNode=archived?.get(`${type}:${id}`);
  let actual:any;
  try{actual=await this.fresh(cid,type,id);}catch(error){
   // Only a server-decrypted affected node may provide an absent parent's
   // identity. A denied read, timeout or transport failure is never absence.
   if(!(error instanceof HttpException&&error.getStatus()===404)||!archivedNode?.affected)throw error;
   return archivedNode.data;
  }
  if(archivedNode?.affected){
   const comparable=(value:any)=>Object.fromEntries(Object.entries(value).filter(([key])=>!['created_at','updated_at','ttl'].includes(key)&&!(type==='certificates'&&key==='snis')));
   if(actual.id!==id||canonicalJson(comparable(actual))!==canonicalJson(comparable(archivedNode.data)))throw new ForbiddenException({code:'ARCHIVED_PARENT_CHANGED',message:'恢复父对象的配置与归档不一致'});
  }
  // Shared parents retain their current tags and configuration; the archive
  // cannot project them back into a workspace or an obsolete tag grant.
  const candidate=planned?.get(`${type}:${id}`);if(!candidate)return actual;
  const comparable=(value:any)=>{const {tags:_tags,updated_at:_updated,...rest}=value;return rest;};
  if(candidate.id!==id||canonicalJson(comparable(actual))!==canonicalJson(comparable(candidate)))throw new ForbiddenException({code:'MIGRATION_PARENT_CHANGED',message:'迁移父对象的非标签配置已变化'});
  return candidate;
 }
 private async workspaceFor(cid:string,type:string,entity:any,wid?:string,planned?:Map<string,any>,archived?:ArchivedParents):Promise<string>{
  entity=normalizeEntityAuthorizationView(type,entity);
  if(type==='workspaces'){
   if(entity.cluster_id!==cid||!uuid.test(entity.id??'')||wid&&wid!==entity.id)throw denied();return entity.id;
  }
  if(!native.has(type)&&type!=='targets'&&!credentials.has(type))return (await this.workspaces.resolve(cid,wid)).id;
  let owner=entity;
  if(type==='targets'||credentials.has(type)){
   const parent=type==='targets'?entity.upstream?.id:entity.consumer?.id;
   if(!parent)throw denied();owner=await this.parent(cid,type==='targets'?'upstreams':'consumers',parent,planned,archived);
  }
  const scope=await this.workspaces.classify(cid,owner.tags);
  if(scope.state!=='resolved'||!scope.workspace||wid&&scope.workspace.id!==wid)throw denied();return scope.workspace.id;
 }
 private direct(snapshot:AuthorizationSnapshot,cid:string,wid:string,type:string,action:PermissionAction,entity:any):EffectiveGrant[]{
  return snapshot.grants.filter(grant=>grantMatchesEntity(grant,permissionModule(type),action,{clusterId:cid,workspaceId:wid,entityType:type,entity}));
 }
 private async parentGrants(snapshot:AuthorizationSnapshot,cid:string,wid:string,parentType:string,parentId:string,action:PermissionAction,child:any,planned?:Map<string,any>,archived?:ArchivedParents):Promise<EffectiveGrant[]>{
  const parent=await this.parent(cid,parentType,parentId,planned,archived);
  if(await this.workspaceFor(cid,parentType,parent,wid,planned,archived)!==wid)return [];
  const direct=this.direct(snapshot,cid,wid,parentType,action,parent).filter(grant=>inheritedTagMatches(grant,child));
  if(direct.length)return direct;
  if(parentType==='routes'&&(action==='write'||action==='delete')&&parent.service?.id)return this.parentGrants(snapshot,cid,wid,'services',parent.service.id,action,child,planned,archived).then(grants=>grants.filter(grant=>inheritedTagMatches(grant,parent)));
  return [];
 }
 private async serviceFromRoute(snapshot:AuthorizationSnapshot,cid:string,wid:string,service:any,planned?:Map<string,any>):Promise<boolean>{
  const grants=snapshot.grants.filter(grant=>coarseGrantMatches(grant,'routes',grant.action,{clusterId:cid,workspaceId:wid}));if(!grants.length)return false;
  const visible=(route:any)=>grants.some(grant=>grantMatchesEntity(grant,'routes',grant.action,{clusterId:cid,workspaceId:wid,entityType:'routes',entity:route}));
  if(planned){
   // Only server-authenticated migration graphs supply planned state. Before
   // accepting future tags, parent() rereads the actual Route and compares
   // every non-tag field, including its real Service reference and UUID.
   const candidates=[...planned.entries()].filter(([key,route])=>key===`routes:${route?.id}`&&route?.service?.id===service.id&&visible(route)).map(([,route])=>route);
   if(candidates.length>100)throw new ForbiddenException({code:'AUTHORIZATION_SCAN_LIMIT',message:'迁移关系权限核验超出预算'});
   for(const candidate of candidates){
    const route=await this.parent(cid,'routes',candidate.id,planned);
    if(route?.id!==candidate.id||route?.service?.id!==service.id)throw denied();
    if(await this.workspaceFor(cid,'routes',route,wid,planned)===wid&&visible(route))return true;
   }
  }
  const ids=[...new Set(grants.filter(grant=>grant.scope_type==='entity').flatMap(grant=>grant.scope_values.filter(value=>typeof value==='object'&&value.entity_type==='routes').map(value=>(value as any).entity_id)))];
  if(ids.length>100)throw new ForbiddenException({code:'AUTHORIZATION_SCAN_LIMIT',message:'关系权限核验超出预算'});
  for(const id of ids){
   let route:any;try{route=await this.fresh(cid,'routes',id as string);}catch(error){if(error instanceof HttpException&&error.getStatus()===404)continue;throw error;}
   if(route.service?.id===service.id&&await this.workspaceFor(cid,'routes',route,wid)===wid&&visible(route))return true;
  }
  if(grants.every(grant=>grant.scope_type==='entity'))return false;
  const path=`/services/${encodeURIComponent(service.id)}/routes`;
  return this.execution.runInternalRead(cid,'authorization',async()=>{
   let offset:string|undefined;
   for(let page=0;page<8;page++){
    const result=await this.kong.request<any>(cid,'GET',path,undefined,{size:100,...(offset?{offset}:{})});if(!Array.isArray(result?.data))throw denied();
    for(const route of result.data)if(route.service?.id===service.id&&(await this.workspaces.classify(cid,route.tags)).workspace?.id===wid&&visible(route))return true;
    if(!result.next)return false;
    const next=new URL(result.next,'http://kong.local');if(next.pathname!==path||!next.searchParams.has('offset'))throw denied();offset=next.searchParams.get('offset')!;
   }
   throw new ForbiddenException({code:'AUTHORIZATION_SCAN_LIMIT',message:'关系权限核验超出预算'});
  },{paths:[path],maxCalls:8,maxPages:8,maxRecords:800,maxBytes:4*1024*1024,timeoutMs:10000});
 }
 private async serviceFromArchivedRoutes(snapshot:AuthorizationSnapshot,cid:string,wid:string,service:any,archived:ArchivedParents):Promise<boolean>{
  const candidates=[...archived.values()].filter(node=>node.type==='routes'&&node.data.service?.id===service.id);
  if(candidates.length>100)throw new ForbiddenException({code:'AUTHORIZATION_SCAN_LIMIT',message:'归档关系权限核验超出预算'});
  for(const node of candidates){
   const route=await this.parent(cid,'routes',node.id,undefined,archived);
   if(route.service?.id!==service.id||await this.workspaceFor(cid,'routes',route,wid,undefined,archived)!==wid)continue;
   if(snapshot.grants.some(grant=>permissionModule(grant.module)==='routes'&&grantMatchesEntity(grant,'routes',grant.action,{clusterId:cid,workspaceId:wid,entityType:'routes',entity:route})))return true;
  }
  return false;
 }
 private async permits(snapshot:AuthorizationSnapshot,cid:string,type:string,action:PermissionAction,entity:any,wid?:string,planned?:Map<string,any>,archived?:ArchivedParents):Promise<boolean>{
  if(!entity||typeof entity!=='object'||Array.isArray(entity))return false;if(snapshot.user.superAdmin)return true;
  entity=normalizeEntityAuthorizationView(type,entity);
  const workspace=await this.workspaceFor(cid,type,entity,wid,planned,archived),grants=this.direct(snapshot,cid,workspace,type,action,entity);
  if(type==='workspaces'&&action==='read')return grants.length>0||snapshot.grants.some(grant=>discoverableModules.includes(permissionModule(grant.module))&&coarseGrantMatches(grant,grant.module,grant.action,{clusterId:cid,workspaceId:workspace}));
  if(type==='plugins'){
   const parents:[string,string][]=[];for(const [field,parentType] of [['service','services'],['route','routes'],['consumer','consumers']])if(entity[field]?.id)parents.push([parentType,entity[field].id]);
   if(!parents.length)return action==='read'&&grants.length>0;
   for(const [parentType,id] of parents)if(!(await this.parentGrants(snapshot,cid,workspace,parentType,id,action,entity,planned,archived)).length)return false;
   return true;
  }
  if(grants.length)return true;
  if(type==='routes'&&(action==='write'||action==='delete')&&entity.service?.id)return (await this.parentGrants(snapshot,cid,workspace,'services',entity.service.id,action,entity,planned,archived)).length>0;
  if(type==='services'&&action==='read'){
   if(archived&&await this.serviceFromArchivedRoutes(snapshot,cid,workspace,entity,archived))return true;
   return this.serviceFromRoute(snapshot,cid,workspace,entity,planned);
  }
  if(type==='targets'&&entity.upstream?.id)return (await this.parentGrants(snapshot,cid,workspace,'upstreams',entity.upstream.id,action,entity,planned,archived)).length>0;
  if(credentials.has(type)&&entity.consumer?.id)return (await this.parentGrants(snapshot,cid,workspace,'consumers',entity.consumer.id,action,entity,planned,archived)).length>0;
  return false;
 }
 async assertEntity(user:AuthUser,cid:string,type:string,action:string,entity:any,wid?:string):Promise<void>{
  await this.assertCluster(user,cid,type,action,wid);if(!await this.permits(await this.snapshot(user),cid,type,permissionAction(action),entity,wid))throw denied();
 }
 /** Internal recycle boundary only: the caller supplies nodes already
  * authenticated by SecretService, never an HTTP parent projection. Grants,
  * session and workspace membership remain current, including missing parents. */
 async assertArchivedEntity(user:AuthUser,cid:string,type:string,action:string,entity:any,wid:string,graph:ReadonlyArray<GraphNode>):Promise<void>{
  await this.assertCluster(user,cid,type,action,wid);
  if(!Array.isArray(graph)||!graph.length||graph.length>10000)throw denied();
  const archived=new Map<string,GraphNode>(),keys=new Set<string>();
  for(const node of graph){
   if(!node||!native.has(node.type)&&node.type!=='targets'&&!credentials.has(node.type)||!uuid.test(node.id??'')
    ||node.data?.id!==node.id||typeof node.affected!=='boolean'||typeof node.key!=='string'||!node.key||!Array.isArray(node.dependencies)
    ||archived.has(`${node.type}:${node.id}`)||keys.has(node.key))throw denied();
   archived.set(`${node.type}:${node.id}`,node);keys.add(node.key);
  }
  const node=archived.get(`${type}:${entity?.id}`);
  if(!node||canonicalJson(node.data)!==canonicalJson(entity))throw denied();
  for(const item of graph){
   if(item.dependencies.some((key:unknown)=>typeof key!=='string'||!keys.has(key)))throw denied();
   const references:[string,any][]=[];
   if(item.type==='targets')references.push(['upstreams',item.data.upstream]);
   if(credentials.has(item.type))references.push(['consumers',item.data.consumer]);
   if(item.type==='routes'&&item.data.service)references.push(['services',item.data.service]);
   if(item.type==='plugins')for(const [field,parentType] of [['service','services'],['route','routes'],['consumer','consumers']])if(item.data[field])references.push([parentType,item.data[field]]);
   for(const [parentType,value] of references){
    const parent=archived.get(`${parentType}:${value?.id}`);
    if(!parent||!item.dependencies.includes(parent.key))throw denied();
   }
  }
  const snapshot=await this.snapshot(user),operation=permissionAction(action);
  let current=entity;
  if(!node.affected){
   if(native.has(type))current=await this.fresh(cid,type,node.id);
   else{
    const parentType=type==='targets'?'upstreams':'consumers',parentId=type==='targets'?node.data.upstream?.id:node.data.consumer?.id;
    const path=`/${parentType}/${encodeURIComponent(parentId)}/${type}/${encodeURIComponent(node.id)}`;
    if(path!==node.path)throw denied();
    current=await this.execution.runInternalRead(cid,'authorization',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:this.authorizationPointTimeoutMs()});
   }
   if(current?.id!==node.id)throw denied();
  }
  await this.workspaceFor(cid,type,current,wid,undefined,archived);
  if(!await this.permits(snapshot,cid,type,operation,current,wid,undefined,archived)||await this.permissionVersion(user)!==snapshot.version)throw denied();
 }
 /** Only server-captured/encrypted migration graphs call this method. Future
  * parent tags are accepted after rereading and comparing every used parent's
  * non-tag configuration; HTTP callers cannot supply a parent override. */
 async assertMigrationEntity(user:AuthUser,cid:string,type:string,action:string,entity:any,wid:string,graph:ReadonlyArray<{type:string;id:string;data:any}>):Promise<void>{
  await this.assertCluster(user,cid,type,action,wid);const planned=new Map<string,any>();
  for(const node of graph)if(native.has(node.type)&&node.data?.id===node.id)planned.set(`${node.type}:${node.id}`,node.data);
  if(!await this.permits(await this.snapshot(user),cid,type,permissionAction(action),entity,wid,planned))throw denied();
 }
 /** A child grant may inspect its parent's identity internally without disclosing
  * the parent's configuration. It does not become a public parent read grant. */
 async assertNestedParentScope(user:AuthUser,cid:string,parentType:string,parent:any,childType:string,action:string,wid?:string,child?:any):Promise<void>{
  if(!['consumers','upstreams'].includes(parentType)||parentType==='consumers'&&!credentials.has(childType)||parentType==='upstreams'&&childType!=='targets')throw denied();
  const snapshot=await this.snapshot(user),operation=permissionAction(action),workspace=await this.workspaceFor(cid,parentType,parent,wid);
  if(await this.permits(snapshot,cid,parentType,operation,parent,workspace))return;
  await this.assertCluster(user,cid,childType,operation,workspace);
  const field=parentType==='consumers'?'consumer':'upstream';
  if(child){
   if(child[field]?.id!==parent.id||!await this.permits(snapshot,cid,childType,operation,child,workspace))throw denied();return;
  }
  const grants=snapshot.grants.filter(grant=>coarseGrantMatches(grant,permissionModule(childType),operation,{clusterId:cid,workspaceId:workspace}));
  // Non-entity scopes can authorize children by their own tags. The parent is
  // still private, and every returned child is filtered independently.
  if(grants.some(grant=>grant.scope_type!=='entity'))return;
  const ids=[...new Set(grants.flatMap(grant=>grant.scope_values.filter(value=>typeof value==='object'&&value.entity_type===childType).map(value=>(value as any).entity_id)))];
  if(ids.length>100)throw new ForbiddenException({code:'AUTHORIZATION_SCAN_LIMIT',message:'子对象归属核验超出预算'});
  for(const id of ids){
   const path=`/${parentType}/${encodeURIComponent(parent.id)}/${childType}/${encodeURIComponent(id as string)}`;
   let actual:any;try{actual=await this.execution.runInternalRead(cid,'authorization',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:this.authorizationPointTimeoutMs()});}
   catch(error){if(error instanceof HttpException&&error.getStatus()===404)continue;throw error;}
   if(actual[field]?.id===parent.id&&await this.permits(snapshot,cid,childType,operation,actual,workspace))return;
  }
  throw denied();
 }
 async filterEntities(user:AuthUser,cid:string,type:string,items:any[],wid?:string):Promise<any[]>{
  await this.assertCluster(user,cid,type,'read',wid);const snapshot=await this.snapshot(user),allowed:any[]=[];
  for(const item of items){try{if(await this.permits(snapshot,cid,type,'read',item,wid))allowed.push(item);}catch(error){if(!(error instanceof ForbiddenException)&&!(error instanceof HttpException&&error.getStatus()===404))throw error;}}return allowed;
 }
 async assertSecretRead(user:AuthUser,cid:string,type:string,entity:any,wid?:string):Promise<void>{
  await this.assertEntity(user,cid,type,'read',entity,wid);const snapshot=await this.snapshot(user);if(snapshot.user.superAdmin)return;
  const workspace=await this.workspaceFor(cid,type,entity,wid);
  if(!snapshot.grants.some(grant=>grantMatchesEntity(grant,'secrets','read',{clusterId:cid,workspaceId:workspace,entityType:type,entity})))throw denied();
 }
 async scopeTags(user:AuthUser,cid:string,wid:string|undefined,requestedTags:string|undefined,module='entities'):Promise<string|undefined>{
  await this.assertCluster(user,cid,module,'read',wid);const snapshot=await this.snapshot(user);if(snapshot.user.superAdmin||requestedTags)return requestedTags;
  const grants=snapshot.grants.filter(grant=>this.modules(module,'read').some(candidate=>coarseGrantMatches(grant,candidate,'read',{clusterId:cid,workspaceId:wid})));
  // Push down only an all-tag grant set. Mixed boolean conditions require the
  // bounded BFF filter, which independently rechecks every actual object.
  if(grants.length&&grants.every(grant=>grant.scope_type==='tag_group'))return [...new Set(grants.flatMap(grant=>grant.scope_values as string[]))].sort().join('/');return requestedTags;
 }
 async entityCapabilities(user:AuthUser,cid:string,type:string,entity:any,wid?:string):Promise<Record<string,boolean>>{
  const snapshot=await this.snapshot(user),result:Record<string,boolean>={};
  for(const action of PERMISSION_ACTIONS){try{result[action]=this.coarse(snapshot,cid,type,action,wid)&&await this.permits(snapshot,cid,type,action,entity,wid);}catch(error){if(!(error instanceof ForbiddenException)&&!(error instanceof HttpException&&error.getStatus()===404))throw error;result[action]=false;}}
  if(type==='plugins'&&!snapshot.user.superAdmin&&(['pre-function','post-function','file-log'].includes(entity.name)||!pluginMetadata(entity.name).known||!entity.service?.id&&!entity.route?.id&&!entity.consumer?.id))result.write=result.delete=result.approve=false;
  try{await this.assertSecretRead(user,cid,type,entity,wid);result.reveal=true;}catch(error){if(!(error instanceof ForbiddenException))throw error;result.reveal=false;}return result;
 }
}
