import {ForbiddenException,ConflictException,Injectable,OnModuleInit} from '@nestjs/common';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService,type KongExecutionFrame} from '../../infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {encodeTag} from '../../infrastructure/kong/tags';
import {validGrant,grantMatchesEntity} from '../authorization/grant-policy';
import {ConfigurationService} from '../configuration/configuration.service';
import type {EntityActor} from '../entities/entities.types';
import {GovernanceRepositoryService} from './governance-repository.service';
import {GovernanceAuthorityService} from './governance-authority.service';
import {GovernanceInventoryService} from './governance-inventory.service';
import type {GovernanceReadHandle,GovernanceInventory} from './governance-inventory.types';
import type {PromoteOptions,ComparisonInventory} from './comparison-types';
import {governanceId} from './governance-input';

const deny=(code:string)=>new ForbiddenException({code,message:'环境发布所需来源或目标权限已失效'});
const changed=(code:string)=>new ConflictException({code,message:'环境发布冻结来源、选择或物理连接已变化'});
/** The sole fixed source delegate. Server data and a private handle never become a client-supplied proof. */
@Injectable()
export class GovernancePromotionSourceService implements OnModuleInit {
 private readonly handles=new WeakMap<object,{promotionId:string;actorId:string;sessionId:string;frame:KongExecutionFrame;handle:GovernanceReadHandle;requiredPluginSchemas:readonly string[]}>();
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly context:KongExecutionContextService,
  private readonly repo:GovernanceRepositoryService,private readonly authority:GovernanceAuthorityService,private readonly inventory:GovernanceInventoryService,
  private readonly configuration:ConfigurationService){}
 onModuleInit():void{this.configuration.installGovernancePromotionSourcePolicy(Object.freeze({
  acquire:(id:string,actor:EntityActor)=>this.acquire(id,actor),refresh:(id:string,handle:object,actor:EntityActor)=>this.refresh(id,handle,actor),
  fingerprints:(id:string,handle:object,inventory:ComparisonInventory)=>this.fingerprints(id,handle,inventory),
  ...(typeof (this.inventory as any).selectedFingerprints==='function'?{selectedFingerprints:(id:string,handle:object,actor:EntityActor,selected:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[])=>this.selectedFingerprints(id,handle,actor,selected)}:{}),
  assertCurrent:(id:string,handle:object)=>this.assertCurrent(id,handle),assertGrants:(id:string,actorId:string,action:'read'|'write'|'approve',tx?:DbService)=>this.assertGrants(id,actorId,action,tx),
  assertVerifierCurrent:(id:string,handle:object,origin:{actorId:string;sessionId:string;frame:KongExecutionFrame},tx?:DbService)=>this.assertVerifierCurrent(id,handle,origin,tx),
 }));}
 private async material(id:string,tx=this.db,grantCheck=false):Promise<{row:any;source:GovernanceInventory;target:GovernanceInventory;options:PromoteOptions}>{
  const row=await tx.one<any>('SELECT * FROM governance_promotions WHERE id=$1',[governanceId(id)]);if(!row||!(grantCheck?['planning','ready','blocked']:['planning','ready']).includes(row.state))throw changed('GOVERNANCE_PROMOTION_SOURCE_UNAVAILABLE');
  const c=await this.repo.comparison(row.comparison_id,row.cluster_id,row.workspace_id,tx),{source,target}=this.repo.comparisonInventories(c),options=this.secrets.decrypt<PromoteOptions>(row.selection_secret,this.repo.aad('promotion-selection',id));
  if(row.source_inventory_hmac!==c.source_inventory_hmac||row.target_inventory_hmac!==c.target_inventory_hmac||row.cluster_id!==source.scope.clusterId||row.workspace_id!==source.scope.workspaceId||row.target_cluster_id!==target.scope.clusterId||row.target_workspace_id!==target.scope.workspaceId||this.secrets.fingerprint(options)!==row.selection_hmac||source.completeness!=='complete'||target.completeness!=='complete'||source.projection||target.projection||source.scope.transportScope===target.scope.transportScope)throw changed('GOVERNANCE_PROMOTION_MATERIAL_CHANGED');
  return{row,source,target,options};
 }
 async assertGrants(id:string,actorId:string,action:'read'|'write'|'approve',tx=this.db):Promise<void>{
  const m=await this.material(id,tx,true),u=await tx.one<any>("SELECT id,super_admin,force_password_change,credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL",[governanceId(actorId)]);
  if(!u||u.force_password_change)throw deny('GOVERNANCE_PROMOTE_ACTOR_INACTIVE');const grants=(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[actorId])).filter(validGrant);
  const whole=(inv:GovernanceInventory,module:string,op:string)=>u.super_admin===true||grants.some(g=>g.module===module&&g.action===op&&(g.cluster_id===null||g.cluster_id===inv.scope.clusterId)&&(g.workspace_id===null||g.workspace_id===inv.scope.workspaceId)&&(g.scope_type==='global'||g.scope_type==='workspace'&&g.cluster_id===inv.scope.clusterId&&g.workspace_id===inv.scope.workspaceId&&g.scope_values.length===1&&g.scope_values[0]===inv.scope.workspaceId));
  for(const inv of [m.source,m.target]){
   const c=await tx.one<any>('SELECT admin_url,transport_scope,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL',[inv.scope.clusterId]),w=await tx.one<any>('SELECT code,status FROM workspaces WHERE cluster_id=$1 AND id=$2',[inv.scope.clusterId,inv.scope.workspaceId]);
   if(!c||!w||c.status==='disabled'||w.status!=='active'||!/^1\.5\.\d+$/.test(c.version??'')||transportScopeFor(c.admin_url,c.transport_scope)!==inv.scope.transportScope)throw changed('GOVERNANCE_PROMOTE_SCOPE_CHANGED');
   if(inv===m.target&&w.code!==m.options.targetWorkspaceCode)throw changed('GOVERNANCE_PROMOTE_WORKSPACE_CHANGED');
   if(!whole(inv,'promote',action==='write'?'write':'read'))throw deny('GOVERNANCE_PROMOTE_SCOPE_DENIED');
   for(const object of inv.objects){if(!object.objectWorkspaceId)throw changed('GOVERNANCE_PROMOTE_OBJECT_SCOPE_INVALID');const entity={...object.payload,id:object.nativeId,tags:Array.isArray(object.payload.tags)?object.payload.tags.map(t=>encodeTag(String(t))):[]},nativeModule=object.entityType==='targets'?'upstreams':object.entityType;
    if(!u.super_admin&&!grants.some(g=>grantMatchesEntity(g,nativeModule,'read',{clusterId:inv.scope.clusterId,workspaceId:object.objectWorkspaceId,entityType:object.entityType,entity})))throw deny('GOVERNANCE_PROMOTE_OBJECT_READ_DENIED');
   }
  }
  if(action==='write'&&m.row.actor_id!==actorId)throw deny('GOVERNANCE_PROMOTE_REQUESTER_REQUIRED');
  if((m.options.includeSecrets||m.options.includeCredentials)&&![m.source,m.target].every(inv=>whole(inv,'secrets','read')))throw deny('GOVERNANCE_PROMOTE_SECRETS_DENIED');
 }
 private actualActor(actor:EntityActor):{actorId:string;sessionId:string;frame:KongExecutionFrame}{const f=this.context.current();if(!f.actor||!f.sessionId||f.actor.id!==actor.user.id)throw deny('GOVERNANCE_PROMOTE_ACTOR_CONTEXT_REQUIRED');return{actorId:f.actor.id,sessionId:f.sessionId,frame:f};}
 async acquire(id:string,actor:EntityActor):Promise<{source:ComparisonInventory;target:ComparisonInventory;sourceNativeFingerprints:Readonly<Record<string,string>>;targetNativeFingerprints:Readonly<Record<string,string>>;options:PromoteOptions;handle:object}>{
  const claim=this.actualActor(actor);await this.assertGrants(id,claim.actorId,'read');const m=await this.material(id),handle=await this.authority.acquireActor(m.source.scope.clusterId,{scope:m.source.scope.kind,serviceIds:m.source.scope.rootIds,workspaceId:m.source.scope.workspaceId,module:'promote'},{...actor,workspaceId:m.source.scope.workspaceId});
  const targetHandle=await this.authority.acquireActor(m.target.scope.clusterId,{scope:m.target.scope.kind,serviceIds:m.target.scope.rootIds,workspaceId:m.target.scope.workspaceId,module:'promote'},{...actor,workspaceId:m.target.scope.workspaceId});
  // Preserve the sealed comparison's exact schema set across initial and
  // every-packet checks. Fresh captures still include their own configured
  // plugins, so newly introduced objects/schemas remain detectable changes.
  const requiredPluginSchemas=Object.freeze([...new Set([...Object.keys(m.source.pluginSchemas),...Object.keys(m.target.pluginSchemas),...[...m.source.objects,...m.target.objects].filter(object=>object.entityType==='plugins').map(object=>object.payload.name as string)])].sort());
  const source=await this.inventory.capture(handle,{requiredPluginSchemas}),target=await this.inventory.capture(targetHandle,{requiredPluginSchemas});
  const sourceNativeFingerprints=await this.inventory.privateFingerprints(handle,source),targetNativeFingerprints=await this.inventory.privateFingerprints(targetHandle,target);
  await this.authority.assertCurrent(handle);await this.authority.assertCurrent(targetHandle);this.handles.set(handle,{promotionId:id,...claim,handle,requiredPluginSchemas});return{source,target,sourceNativeFingerprints,targetNativeFingerprints,options:m.options,handle};
 }
 private handle(id:string,handle:object):{promotionId:string;actorId:string;sessionId:string;frame:KongExecutionFrame;handle:GovernanceReadHandle;requiredPluginSchemas:readonly string[]}{const s=this.handles.get(handle),f=this.context.current();if(!s||s.promotionId!==id||f.actor?.id!==s.actorId||f.sessionId!==s.sessionId)throw deny('GOVERNANCE_PROMOTE_SOURCE_HANDLE_REQUIRED');return s;}
 async refresh(id:string,handle:object,actor:EntityActor):Promise<ComparisonInventory>{const s=this.handle(id,handle);if(actor.user.id!==s.actorId)throw deny('GOVERNANCE_PROMOTE_SOURCE_ACTOR_CHANGED');await this.material(id);await this.assertGrants(id,s.actorId,'write');return this.inventory.capture(s.handle,{requiredPluginSchemas:s.requiredPluginSchemas});}
 async selectedFingerprints(id:string,handle:object,actor:EntityActor,selected:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]):Promise<Readonly<Record<string,string>>>{const s=this.handle(id,handle);if(actor.user.id!==s.actorId)throw deny('GOVERNANCE_PROMOTE_SOURCE_ACTOR_CHANGED');await this.material(id);await this.assertGrants(id,s.actorId,'write');if(typeof (this.inventory as any).selectedFingerprints!=='function')throw deny('GOVERNANCE_PROMOTE_SOURCE_HANDLE_REQUIRED');return this.inventory.selectedFingerprints(s.handle,selected);}
 async fingerprints(id:string,handle:object,inventory:ComparisonInventory):Promise<Readonly<Record<string,string>>>{const s=this.handle(id,handle);return this.inventory.privateFingerprints(s.handle,inventory as GovernanceInventory);}
 async assertCurrent(id:string,handle:object):Promise<void>{const s=this.handle(id,handle);await this.authority.assertCurrent(s.handle);await this.assertGrants(id,s.actorId,'read');}
 async assertVerifierCurrent(id:string,handle:object,origin:{actorId:string;sessionId:string;frame:KongExecutionFrame},tx=this.db):Promise<void>{
  const s=this.handles.get(handle);
  if(!s||s.promotionId!==id||s.actorId!==origin.actorId||s.sessionId!==origin.sessionId||s.frame!==origin.frame)throw deny('GOVERNANCE_PROMOTE_VERIFIER_SOURCE_REQUIRED');
  this.context.assertGovernanceOrigin(s.frame,s.actorId,s.sessionId);
  await this.authority.assertCurrent(s.handle);await this.assertGrants(id,s.actorId,'read',tx);
 }
}
