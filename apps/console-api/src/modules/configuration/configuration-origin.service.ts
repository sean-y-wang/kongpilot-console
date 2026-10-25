import {ConflictException,ForbiddenException,Injectable} from '@nestjs/common';
import {AsyncLocalStorage} from 'node:async_hooks';
import {DbService} from '../../infrastructure/db.service';
import {SecretService,canonicalJson} from '../../infrastructure/secret.service';
import {KongExecutionContextService,type KongExecutionFrame,type PromotionRecoveryReadProof,type PromotionPlanningProof} from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {decodeTag} from '../../infrastructure/kong/tags';
import type {EntityActor} from '../entities/entities.types';
import type {ComparisonInventory,PromoteOptions} from '../governance/comparison-types';
import {compilePromoteDocument,promotionConsumerClosure} from '../governance/promote-compiler';
import {objectIdentity} from '../governance/logical-graph';
import {GOVERNANCE_ENTITY_TYPES} from '../governance/governance-inventory.types';
import {decryptComparisonMaterial,governanceComparisonEnvelope} from '../governance/governance-comparison-material';
import type {ConfigurationOriginStoragePolicy} from '../config-storage/configuration-repository.service';
import type {CaptureGraph,ConfigPlan,ConfigurationAccessHandle,ConfigurationOriginRef,ConfigurationPromotionSourcePolicy,ConfigurationPromotionRecoveryDelegate} from './configuration.types';
import {configurationId} from './configuration-input';
import type {WorkflowScheduledConfigurationCheckpoint,WorkflowScheduledConfigurationJobHandle,WorkflowScheduledConfigurationJobProof} from '../workflows/workflow-scheduled-configuration-origin.types';

const denied=(code='CONFIGURATION_ORIGIN_REQUIRED')=>new ForbiddenException({code,message:'环境发布的源材料或当前权限无效'});
const changed=(code='CONFIGURATION_ORIGIN_SOURCE_CHANGED')=>new ConflictException({code,message:'源环境配置或发布来源已变化，请核验原回执并重新生成计划'});
const hex=/^[a-f\d]{64}$/;
interface Loaded {parent:any;source:ComparisonInventory;target:ComparisonInventory;sourceNativeFingerprints:Readonly<Record<string,string>>|null;targetNativeFingerprints:Readonly<Record<string,string>>|null;selection:Record<string,any>;ref:ConfigurationOriginRef;recovery?:any;}
interface Prepared extends Loaded {selectedSourceObjects?:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]|null;handle:object;frame:KongExecutionFrame;actor:EntityActor;sourceHash:string;checkedAt:number;compilationInputs:{source:ComparisonInventory;target:ComparisonInventory;sourceNativeFingerprints:Readonly<Record<string,string>>;targetNativeFingerprints:Readonly<Record<string,string>>;options:PromoteOptions};}
interface RecoveryClaim {loaded:Loaded;actor:EntityActor;frame:KongExecutionFrame;proof:PromotionRecoveryReadProof;graph?:CaptureGraph;handle?:ConfigurationAccessHandle;points:Map<string,string>;collections:Map<string,Set<string>>;}
interface PlanningClaim {loaded:Loaded;frame:KongExecutionFrame;proof:PromotionPlanningProof;active:boolean;}
/** Fixed server bootstrap bridge. It authenticates the original private job
 * without recursively calling this service. Current source/target permissions,
 * raw secret-bearing observations and EOF membership remain mandatory at each
 * call; neither the persisted author SID nor an HTTP source handle is adopted. */
export interface ConfigurationWorkflowScheduledOriginMaterial {
 readonly job:Readonly<Record<string,any>>;readonly ref:Readonly<ConfigurationOriginRef>;readonly parent:Readonly<Record<string,any>>;
  source:ComparisonInventory;target:ComparisonInventory;sourceNativeFingerprints:Readonly<Record<string,string>>;targetNativeFingerprints:Readonly<Record<string,string>>;
  selection:Readonly<Record<string,any>>;recovery:Readonly<Record<string,any>>|null;proof:Readonly<WorkflowScheduledConfigurationJobProof>;
  originalJobHandle:WorkflowScheduledConfigurationJobHandle;phase:string;actorId:string;action:'read'|'write'|'approve';
}
export interface ConfigurationWorkflowScheduledBudgetInput extends ConfigurationWorkflowScheduledOriginMaterial {
 readonly plan:Readonly<ConfigPlan>;readonly limits:Readonly<{calls:500;pages:100;records:10000;bytes:33554432}>;
 readonly readRetriesReserved:3;readonly sourceFenceRounds:number;
}
export interface ConfigurationWorkflowScheduledOriginBridge {
 currentOriginalJobHandle():WorkflowScheduledConfigurationJobHandle;
 verifyOriginalJobHandle(handle:WorkflowScheduledConfigurationJobHandle,checkpoint:WorkflowScheduledConfigurationCheckpoint,tx:DbService):Promise<Readonly<WorkflowScheduledConfigurationJobProof>>;
 assertCurrentSourceMaterial(input:Readonly<ConfigurationWorkflowScheduledOriginMaterial>,tx:DbService):Promise<void>;
 /** Mandatory preflight, based on the current actual bounded raw read usage.
  * It must reserve both source fences and all three GET retries per packet,
  * including private credential collections. It cannot enlarge the limits. */
 assertExecutionBudget(input:Readonly<ConfigurationWorkflowScheduledBudgetInput>,tx:DbService):Promise<void>;
}

/** A fixed, once-installed source provider. JSON IDs and ConfigPlan TS casts
 * never mint its runtime proof. All SQL callbacks remain network-free. */
@Injectable()
export class ConfigurationOriginService {
  private policy?:ConfigurationPromotionSourcePolicy;
  private readonly runs=new AsyncLocalStorage<Map<string,Prepared>>();
  private readonly permittedJobs=new WeakMap<object,ConfigurationOriginRef>();
  private readonly recoveryClaims=new WeakMap<object,RecoveryClaim>();
  private readonly planningClaims=new WeakMap<object,PlanningClaim>();
  private readonly recoveryByRun=new AsyncLocalStorage<Map<string,object>>();
  private recoveryDelegate?:ConfigurationPromotionRecoveryDelegate;
  private scheduledOrigin?:ConfigurationWorkflowScheduledOriginBridge;
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly context:KongExecutionContextService,private readonly kong?:KongService){}
  install(policy:ConfigurationPromotionSourcePolicy):void{
    if(this.policy||!policy||['acquire','refresh','fingerprints','assertCurrent','assertVerifierCurrent','assertGrants'].some(name=>typeof (policy as any)[name]!=='function'))throw denied();
    this.policy=Object.freeze({...policy});
  }
  installRecovery(delegate:ConfigurationPromotionRecoveryDelegate):void{if(this.recoveryDelegate)throw denied();this.recoveryDelegate=Object.freeze(delegate);}
  installWorkflowScheduledOrigin(bridge:ConfigurationWorkflowScheduledOriginBridge):void{
    if(this.scheduledOrigin||!bridge||['currentOriginalJobHandle','verifyOriginalJobHandle','assertCurrentSourceMaterial','assertExecutionBudget'].some(k=>typeof(bridge as any)[k]!=='function'))throw denied('CONFIGURATION_SCHEDULE_ORIGIN_BRIDGE_INVALID');
    this.scheduledOrigin=Object.freeze({...bridge});
  }
  recoveryPolicy(){return{verifyHandle:(handle:object)=>this.verifyRecovery(handle),assertResponse:(handle:object,path:string,result:unknown)=>this.assertRecoveryResponse(handle,path,result)};}
  planningPolicy(){return{verifyHandle:(handle:object)=>this.verifyPlanning(handle)};}
  /** The original source HTTP actor can enter only this server-owned target
   * planning namespace. This opaque claim grants reads and metadata planning,
   * never a native write or a reusable cross-cluster actor transition. */
  async runTargetPlanning<T>(id:string,actor:EntityActor,fn:()=>Promise<T>):Promise<T>{
    const loaded=await this.load(configurationId(id)),frame=this.context.current();
    if(loaded.parent.state!=='planning'||loaded.parent.actor_id!==actor.user.id||frame.actor?.id!==actor.user.id||!frame.sessionId
      ||frame.clusterId!==loaded.source.scope.clusterId||frame.workspaceId!==loaded.source.scope.workspaceId)throw denied('CONFIGURATION_ORIGIN_PLANNING_SOURCE_REQUIRED');
    this.context.assertGovernanceOrigin(frame,actor.user.id,frame.sessionId);
    await this.sourcePolicy().assertGrants(id,actor.user.id,'write');
    const user=await this.db.one<any>("SELECT id,username,super_admin,credential_epoch,permissions_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false",[actor.user.id]),
      session=await this.db.one<any>('SELECT expires_at,credential_epoch FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()',[frame.sessionId,actor.user.id]),
      epoch=await this.db.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if(!user||!session||!epoch||String(user.credential_epoch)!==String(session.credential_epoch))throw denied('CONFIGURATION_ORIGIN_PLANNING_IDENTITY');
    const proof:PromotionPlanningProof={promotionId:id,actor:{id:user.id,username:user.username,superAdmin:user.super_admin===true},sessionId:frame.sessionId,
      sourceClusterId:loaded.source.scope.clusterId,sourceWorkspaceId:loaded.source.scope.workspaceId,clusterId:loaded.target.scope.clusterId,workspaceId:loaded.target.scope.workspaceId,
      transportScope:loaded.target.scope.transportScope,permissionVersion:`${user.id}:${user.permissions_epoch}:${epoch.version}`,credentialEpoch:Number(user.credential_epoch),
      expiresAt:Math.min(Date.now()+120000,new Date(session.expires_at).getTime()),originFrame:frame};
    const handle=Object.freeze({}),claim:PlanningClaim={loaded,frame,proof,active:true};this.planningClaims.set(handle,claim);
    try{return await this.context.runPromotionPlanning(handle,fn);}finally{claim.active=false;this.planningClaims.delete(handle);}
  }
  private async verifyPlanning(handle:object):Promise<PromotionPlanningProof>{
    const claim=this.planningClaims.get(handle);if(!claim?.active||claim.proof.expiresAt<=Date.now())throw denied('CONFIGURATION_ORIGIN_PLANNING_HANDLE_REQUIRED');
    const {proof}=claim;this.context.assertGovernanceOrigin(claim.frame,proof.actor.id,proof.sessionId);
    const loaded=await this.load(proof.promotionId);
    if(!['planning','ready','blocked'].includes(loaded.parent.state)||loaded.parent.actor_id!==proof.actor.id||loaded.ref.materialHmac!==claim.loaded.ref.materialHmac
      ||loaded.source.scope.clusterId!==proof.sourceClusterId||loaded.source.scope.workspaceId!==proof.sourceWorkspaceId
      ||loaded.target.scope.clusterId!==proof.clusterId||loaded.target.scope.workspaceId!==proof.workspaceId||loaded.target.scope.transportScope!==proof.transportScope)throw denied('CONFIGURATION_ORIGIN_PLANNING_MATERIAL_CHANGED');
    await this.sourcePolicy().assertGrants(proof.promotionId,proof.actor.id,'write');
    const user=await this.db.one<any>("SELECT id,credential_epoch,permissions_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false",[proof.actor.id]),
      session=await this.db.one<any>('SELECT credential_epoch,expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()',[proof.sessionId,proof.actor.id]),
      epoch=await this.db.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if(!user||!session||!epoch||Number(user.credential_epoch)!==proof.credentialEpoch||String(user.credential_epoch)!==String(session.credential_epoch)
      ||`${proof.actor.id}:${user.permissions_epoch}:${epoch.version}`!==proof.permissionVersion||new Date(session.expires_at).getTime()<proof.expiresAt)throw denied('CONFIGURATION_ORIGIN_PLANNING_IDENTITY');
    return proof;
  }
  run<T>(fn:()=>Promise<T>):Promise<T>{return this.runs.getStore()?fn():this.runs.run(new Map(),()=>this.recoveryByRun.run(new Map(),fn));}
  private sourcePolicy():ConfigurationPromotionSourcePolicy{if(!this.policy)throw denied('CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE');return this.policy;}
  private assertRef(ref:ConfigurationOriginRef):void{if(!ref||ref.version!==1||ref.kind!=='governance-promote'||!hex.test(ref.materialHmac)||configurationId(ref.originId)!==ref.originId)throw denied();}
  private manifest(inv:ComparisonInventory,nativeFingerprints?:Readonly<Record<string,string>>|null):unknown{
    return{scope:inv.scope,version:inv.version,adapterVersion:inv.adapterVersion??'kong-1.5',schemas:inv.schemas,pluginSchemas:inv.pluginSchemas,enabledPlugins:[...inv.enabledPlugins].sort(),
      ...(nativeFingerprints?{nativeFingerprints:governanceComparisonEnvelope(inv,nativeFingerprints).nativeFingerprints}:{}),
      completeness:inv.completeness,projection:inv.projection,consistency:inv.consistency??'console_fenced_best_effort',
      objects:inv.objects.map(o=>({entityType:o.entityType,nativeId:o.nativeId,parentId:o.parentId??null,credentialKind:o.credentialKind??null,objectWorkspaceId:o.objectWorkspaceId??null,
        payload:o.payload,sensitiveFields:[...(o.sensitiveFields??[])].sort(),referenceOnly:o.referenceOnly===true,managedBoundary:o.managedBoundary??'none',certificate:o.certificate??null}))
        .sort((a,b)=>`${a.entityType}:${a.nativeId}`.localeCompare(`${b.entityType}:${b.nativeId}`))};
  }
  private async load(id:string,db=this.db):Promise<Loaded>{
    const parent=await db.one<any>('SELECT * FROM governance_promotions WHERE id=$1',[configurationId(id)]);
    if(!parent||!['planning','ready','blocked','uncertain'].includes(parent.state))throw denied('CONFIGURATION_ORIGIN_PARENT_UNAVAILABLE');
    const row=await db.one<any>('SELECT * FROM governance_comparisons WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[parent.comparison_id,parent.cluster_id,parent.workspace_id]);
    if(!row||row.target_cluster_id!==parent.target_cluster_id||row.target_workspace_id!==parent.target_workspace_id||row.quality!=='complete')throw denied('CONFIGURATION_ORIGIN_COMPARISON_INVALID');
    const decoded=decryptComparisonMaterial<ComparisonInventory>(row,this.secrets),source=decoded.source.inventory,target=decoded.target.inventory;
    const sourceNativeFingerprints=decoded.source.nativeFingerprints,targetNativeFingerprints=decoded.target.nativeFingerprints;
    const selection=this.secrets.decrypt<Record<string,any>>(parent.selection_secret,`governance:promotion-selection:${id}`);
    if(this.secrets.fingerprint(row.policy)!==row.policy_hmac
      ||row.source_inventory_hmac!==parent.source_inventory_hmac||row.target_inventory_hmac!==parent.target_inventory_hmac||this.secrets.fingerprint(selection)!==parent.selection_hmac
      ||source.scope.clusterId!==parent.cluster_id||source.scope.workspaceId!==parent.workspace_id||target.scope.clusterId!==parent.target_cluster_id||target.scope.workspaceId!==parent.target_workspace_id
      ||source.scope.transportScope===target.scope.transportScope||source.completeness!=='complete'||target.completeness!=='complete'||source.projection||target.projection)throw denied('CONFIGURATION_ORIGIN_MATERIAL_INVALID');
    const recovery=await db.one<any>('SELECT * FROM promotion_recovery_bindings WHERE promotion_id=$1',[id]);
    if((selection.includeSecrets||selection.includeCredentials)&&!recovery)throw denied('CONFIGURATION_ORIGIN_RECOVERY_REQUIRED');
    if(recovery&&(recovery.source_cluster_id!==source.scope.clusterId||recovery.source_workspace_id!==source.scope.workspaceId))throw denied('CONFIGURATION_ORIGIN_RECOVERY_INVALID');
    const material={version:1,kind:'governance-promote',originId:id,comparisonId:row.id,actorId:parent.actor_id,sourceScope:source.scope,targetScope:target.scope,
      requestHmac:parent.request_hmac,selectionHmac:parent.selection_hmac,sourceInventoryHmac:parent.source_inventory_hmac,targetInventoryHmac:parent.target_inventory_hmac,
      sourceManifest:this.manifest(source,sourceNativeFingerprints),policyHmac:row.policy_hmac,recovery:recovery?{sourceJobId:recovery.source_job_id,snapshotId:recovery.snapshot_id,version:recovery.snapshot_version,manifestHmac:recovery.manifest_hmac,recoveryHmac:recovery.recovery_hmac}:null};
    return{parent,source,target,sourceNativeFingerprints,targetNativeFingerprints,selection,...(recovery?{recovery}:{}),ref:{version:1,kind:'governance-promote',originId:id,materialHmac:this.secrets.fingerprint(material)}};
  }
  private current(ref:ConfigurationOriginRef):Prepared{
    this.assertRef(ref);const prepared=this.runs.getStore()?.get(ref.originId),frame=this.context.current();
    if(!prepared||prepared.ref.materialHmac!==ref.materialHmac||frame.actor?.id!==prepared.actor.user.id||frame.sessionId!==prepared.frame.sessionId)throw denied('CONFIGURATION_ORIGIN_READ_PROOF_REQUIRED');
    this.context.assertGovernanceOrigin(prepared.frame,prepared.actor.user.id,prepared.frame.sessionId!);return prepared;
  }
  async prepare(ref:ConfigurationOriginRef,actor:EntityActor):Promise<void>{
    this.assertRef(ref);const store=this.runs.getStore();if(!store)throw denied('CONFIGURATION_ORIGIN_CONTEXT_REQUIRED');
    if(store.has(ref.originId)){const p=this.current(ref);await this.sourcePolicy().assertCurrent(ref.originId,p.handle);return;}
    const loaded=await this.load(ref.originId);if(loaded.ref.materialHmac!==ref.materialHmac)throw denied('CONFIGURATION_ORIGIN_MATERIAL_INVALID');
    if(!loaded.sourceNativeFingerprints||!loaded.targetNativeFingerprints)throw denied('CONFIGURATION_ORIGIN_PRIVATE_MANIFEST_REQUIRED');
    const frame=this.context.current();if(frame.actor?.id!==actor.user.id||!frame.sessionId)throw denied('CONFIGURATION_ORIGIN_IDENTITY_INVALID');
    await this.sourcePolicy().assertGrants(ref.originId,actor.user.id,'read');
    const material=await this.sourcePolicy().acquire(ref.originId,actor),actual=this.secrets.fingerprint(this.manifest(material.source,material.sourceNativeFingerprints)),expected=this.secrets.fingerprint(this.manifest(loaded.source,loaded.sourceNativeFingerprints));
    if(!material.sourceNativeFingerprints||!material.targetNativeFingerprints||actual!==expected||this.secrets.fingerprint(this.manifest(material.target,material.targetNativeFingerprints))!==this.secrets.fingerprint(this.manifest(loaded.target,loaded.targetNativeFingerprints))||canonicalJson(material.source.scope)!==canonicalJson(loaded.source.scope)||canonicalJson(material.target.scope)!==canonicalJson(loaded.target.scope))throw changed();
    const prepared:Prepared={...loaded,handle:material.handle,frame,actor:{...actor},sourceHash:actual,checkedAt:Date.now(),compilationInputs:material};store.set(ref.originId,prepared);
    await this.sourcePolicy().assertCurrent(ref.originId,material.handle);
    if(loaded.recovery)await this.prepareRecovery(loaded,actor);
  }
  async preparePromotion(id:string,actor:EntityActor):Promise<void>{const loaded=await this.load(id);await this.prepare(loaded.ref,actor);}
  async compile(id:string,actor:EntityActor,targetGraph?:CaptureGraph):Promise<{ref:ConfigurationOriginRef;compiled:ReturnType<typeof compilePromoteDocument>;source:ComparisonInventory;target:ComparisonInventory}>{
    const loaded=await this.load(id);if(loaded.parent.actor_id!==actor.user.id||loaded.parent.state!=='planning')throw denied('CONFIGURATION_ORIGIN_PARENT_OWNER_REQUIRED');
    await this.sourcePolicy().assertGrants(id,actor.user.id,'write');
    await this.prepare(loaded.ref,actor);const material=this.current(loaded.ref).compilationInputs;
    if(this.secrets.fingerprint(this.manifest(material.source,material.sourceNativeFingerprints))!==this.current(loaded.ref).sourceHash)throw changed();
    const compiled=loaded.recovery&&targetGraph?await this.compileWithTargetRecovery(id,targetGraph):compilePromoteDocument(material.source,material.target,{...material.options,...loaded.selection,targetWorkspaceCode:loaded.selection.targetWorkspaceCode});
    return{ref:loaded.ref,compiled,source:material.source,target:material.target};
  }
  async preparePlan(planId:string,actor:EntityActor):Promise<ConfigurationOriginRef|undefined>{
    const row=await this.db.one<any>('SELECT j.required_origin_kind,j.required_origin_id,j.required_origin_hmac FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id WHERE p.id=$1',[configurationId(planId)]);
    if(!row?.required_origin_kind){if(row&&(row.required_origin_id||row.required_origin_hmac))throw denied();return undefined;}
    const ref:ConfigurationOriginRef={version:1,kind:row.required_origin_kind,originId:row.required_origin_id,materialHmac:row.required_origin_hmac};await this.prepare(ref,actor);return ref;
  }
  async prepareJob(jobId:string,actor:EntityActor):Promise<void>{const row=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[configurationId(jobId)]);if(row?.required_origin_kind)await this.prepare({version:1,kind:row.required_origin_kind,originId:row.required_origin_id,materialHmac:row.required_origin_hmac},actor);}
  permitJob(handle:ConfigurationAccessHandle,ref:ConfigurationOriginRef):void{this.current(ref);this.permittedJobs.set(handle,ref);}
  recoveryHash(graph:CaptureGraph):string{return this.secrets.fingerprint({scope:graph.scope,schemas:graph.schemas,objects:graph.objects,collections:graph.collections});}
  private assertRecoveryRootObservation(loaded:Loaded,graph:CaptureGraph,side:'source'|'target'='source'):void{
    const inventory=side==='source'?loaded.source:loaded.target,nativeFingerprints=side==='source'?loaded.sourceNativeFingerprints:loaded.targetNativeFingerprints;
    if(!nativeFingerprints)throw denied('CONFIGURATION_ORIGIN_PRIVATE_MANIFEST_REQUIRED');
    // Governance's legacy comparison label and M8's fixed capture label name
    // the same supported 1.5 adapter. Do not alter either sealed material or
    // its raw fingerprints; only these two known component labels align.
    const supportedAdapters=new Set(['kong-1.5','kong-oss-1.5-v1']),comparisonAdapter=inventory.adapterVersion??'kong-1.5';
    if(canonicalJson(graph.scope)!==canonicalJson(inventory.scope)||graph.completeness!=='complete'||graph.consistency!=='console_fenced_best_effort'
      ||graph.kongVersion!==inventory.version||!/^1\.5\.\d+$/.test(graph.kongVersion)||!supportedAdapters.has(graph.adapterVersion)||!supportedAdapters.has(comparisonAdapter))throw changed(side==='source'?'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED':'CONFIGURATION_ORIGIN_TARGET_CHANGED');
    const roots=new Map(graph.objects.filter(object=>object.entityType!=='credentials').map(object=>[`${object.entityType}:${object.nativeId}`,object]));
    // M8 can capture additional read-only dependencies. Only objects present
    // in the original comparison may supply noncredential Promote material.
    // Every such raw payload must be the exact original native observation.
    for(const object of inventory.objects){
      const key=`${object.entityType}:${object.nativeId}`,raw=roots.get(key),expected=nativeFingerprints[key];
      if(!raw||!hex.test(expected??'')||raw.beforeHmac!==expected||this.secrets.fingerprint(raw.payload)!==expected)throw changed(side==='source'?'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED':'CONFIGURATION_ORIGIN_TARGET_CHANGED');
    }
  }
  private async prepareRecovery(loaded:Loaded,actor:EntityActor):Promise<void>{
    const runs=this.recoveryByRun.getStore();if(!runs||!loaded.recovery||!this.recoveryDelegate)throw denied('CONFIGURATION_ORIGIN_RECOVERY_REQUIRED');if(runs.has(loaded.ref.originId))return;
    const frame=this.context.current(),u=await this.db.one<any>("SELECT id,username,super_admin,credential_epoch,permissions_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false",[actor.user.id]);
    const session=frame.sessionId?await this.db.one<any>('SELECT expires_at,credential_epoch FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()',[frame.sessionId,actor.user.id]):null,epoch=await this.db.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if(!u||!session||String(session.credential_epoch)!==String(u.credential_epoch)||!epoch)throw denied('CONFIGURATION_ORIGIN_RECOVERY_IDENTITY');
    const claim:RecoveryClaim={loaded,actor,frame,points:new Map(),collections:new Map(),proof:{mode:'bootstrap',actor:{id:u.id,username:u.username,superAdmin:u.super_admin===true},sessionId:frame.sessionId!,
      clusterId:loaded.source.scope.clusterId,workspaceId:loaded.source.scope.workspaceId,transportScope:loaded.source.scope.transportScope,permissionVersion:`${u.id}:${u.permissions_epoch}:${epoch.version}`,
      credentialEpoch:Number(u.credential_epoch),expiresAt:Math.min(Date.now()+14*60_000,new Date(session.expires_at).getTime()),originFrame:frame,pointPaths:[],credentialCollections:[],schemaPaths:[]}};
    const handle=Object.freeze({});this.recoveryClaims.set(handle,claim);
    const material=await this.context.runPromotionRecoveryRead(handle,()=>this.recoveryDelegate!.read(loaded.recovery!,loaded.source,actor));
    if(this.secrets.fingerprint(material.graph)!==loaded.recovery.manifest_hmac||this.recoveryHash(material.graph)!==loaded.recovery.recovery_hmac
      ||canonicalJson(material.graph.scope)!==canonicalJson(loaded.source.scope)||material.graph.completeness!=='complete'||material.graph.consistency!=='console_fenced_best_effort')throw denied('CONFIGURATION_ORIGIN_RECOVERY_INVALID');
    this.assertRecoveryRootObservation(loaded,material.graph);
    const consumers=promotionConsumerClosure(loaded.source,{...this.current(loaded.ref).compilationInputs.options,...loaded.selection,targetWorkspaceCode:loaded.selection.targetWorkspaceCode});
    const path=(o:CaptureGraph['objects'][number]):string=>o.entityType==='credentials'?`/consumers/${o.parentId}/${o.credentialKind}/${o.nativeId}`:o.entityType==='targets'?`/upstreams/${o.parentId}/targets/${o.nativeId}`:`/${o.entityType}/${o.nativeId}`;
    claim.graph=material.graph;claim.handle=material.handle;
    // Noncredential raw fields, including omitted secrets, are fenced by the
    // whole current v2 Governance native map before every packet. Credentials
    // require the selected Consumers' complete six-kind private child graph.
    for(const object of material.graph.objects)if(object.entityType==='credentials'&&object.parentId&&consumers.has(object.parentId))claim.points.set(path(object),object.beforeHmac);
    const credentialMembers=(parentId:string,kind:string)=>new Set(material.graph.objects.filter(o=>o.entityType==='credentials'&&o.parentId===parentId&&o.credentialKind===kind).map(o=>o.nativeId));
    for(const collection of material.graph.collections)if(collection.entityType==='credentials'&&collection.parentId&&collection.credentialKind&&consumers.has(collection.parentId)){
      claim.collections.set(`/consumers/${collection.parentId}/${collection.credentialKind}`,credentialMembers(collection.parentId,collection.credentialKind));
    }
    // A capture that used Kong's global credential collection proved the complete
    // membership of every captured Consumer for that kind. Re-verify the selected
    // Consumers with the same exact per-Consumer membership fence as before.
    for(const collection of material.graph.collections)if(collection.entityType==='credentials'&&!collection.parentId&&collection.credentialKind)
      for(const consumer of material.graph.objects)if(consumer.entityType==='consumers'&&!consumer.referenceOnly&&consumers.has(consumer.nativeId))
        claim.collections.set(`/consumers/${consumer.nativeId}/${collection.credentialKind}`,credentialMembers(consumer.nativeId,collection.credentialKind));
    claim.proof={...claim.proof,mode:'read',pointPaths:[...claim.points.keys()].sort(),credentialCollections:[...claim.collections.keys()].sort()};
    await this.recoveryDelegate.verify(claim.handle,claim.graph);runs.set(loaded.ref.originId,handle);
    await this.checkPrivateSource(loaded.ref.originId);
  }
  private async verifyRecovery(handle:object):Promise<PromotionRecoveryReadProof>{
    const claim=this.recoveryClaims.get(handle);if(!claim)throw denied('CONFIGURATION_ORIGIN_RECOVERY_HANDLE_REQUIRED');
    this.context.assertGovernanceOrigin(claim.frame,claim.actor.user.id,claim.proof.sessionId);
    const loaded=await this.load(claim.loaded.ref.originId);if(loaded.ref.materialHmac!==claim.loaded.ref.materialHmac)throw denied('CONFIGURATION_ORIGIN_RECOVERY_INVALID');
    await this.sourcePolicy().assertGrants(loaded.ref.originId,claim.actor.user.id,'read');
    const u=await this.db.one<any>("SELECT credential_epoch,permissions_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false",[claim.actor.user.id]),epoch=await this.db.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const session=await this.db.one<any>('SELECT credential_epoch,expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()',[claim.proof.sessionId,claim.actor.user.id]);
    if(!u||!epoch||!session||String(u.credential_epoch)!==String(session.credential_epoch)||Number(u.credential_epoch)!==claim.proof.credentialEpoch||`${claim.actor.user.id}:${u.permissions_epoch}:${epoch.version}`!==claim.proof.permissionVersion)throw denied('CONFIGURATION_ORIGIN_RECOVERY_IDENTITY');
    if(claim.proof.mode==='read'){if(!claim.handle||!claim.graph||!this.recoveryDelegate)throw denied();await this.recoveryDelegate.verify(claim.handle,claim.graph);}
    return claim.proof;
  }
  private async assertRecoveryResponse(handle:object,path:string,result:unknown):Promise<void>{
    await this.verifyRecovery(handle);const claim=this.recoveryClaims.get(handle)!;
    if(claim.points.has(path)){if(this.secrets.fingerprint(result)!==claim.points.get(path))throw changed('CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED');return;}
    const expected=claim.collections.get(path),data=(result as any)?.data;
    if(!expected||!Array.isArray(data))throw denied('CONFIGURATION_ORIGIN_RECOVERY_RESPONSE_INVALID');
    for(const item of data){if(!expected.has(item?.id))throw changed('CONFIGURATION_ORIGIN_CREDENTIAL_MEMBERSHIP_CHANGED');const point=`${path}/${item.id}`;if(this.secrets.fingerprint(item)!==claim.points.get(point))throw changed('CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED');}
  }
  private privateObjects(graph:CaptureGraph):import('../governance/comparison-types').ComparisonObject[]{
    const display=(payload:Record<string,unknown>)=>({...structuredClone(payload),...(Array.isArray(payload.tags)?{tags:payload.tags.map(tag=>decodeTag(String(tag)))}:{})});
    return graph.objects.map(object=>({...object,payload:display(object.payload),...(object.recovery.restorePayload?{recovery:{...object.recovery,restorePayload:display(object.recovery.restorePayload)}}:{})}));
  }
  private credentialAliases(source:ComparisonInventory,target:ComparisonInventory):Record<string,string>{
    const aliases:Record<string,string>={};
    for(const inv of [source,target])for(const object of inv.objects)if(object.entityType==='credentials'&&['key-auth','jwt'].includes(object.credentialKind??'')){
      const consumer=inv.objects.find(candidate=>candidate.entityType==='consumers'&&candidate.nativeId===object.parentId),username=consumer?.payload.username,customId=consumer?.payload.custom_id,
        name=typeof username==='string'&&username.length?`username:${username}`:typeof customId==='string'&&customId.length?`custom_id:${customId}`:undefined,key=object.payload.key;
      if(typeof name!=='string'||typeof key!=='string')continue;
      aliases[`credentials:${object.credentialKind}:${object.parentId}:${object.nativeId}`]=`credential-${this.secrets.fingerprint({kind:object.credentialKind,consumer:name,key})}`;
    }
    return aliases;
  }
  async compileWithTargetRecovery(id:string,targetGraph:CaptureGraph):Promise<ReturnType<typeof compilePromoteDocument>>{
    const prepared=this.runs.getStore()?.get(id),opaque=this.recoveryByRun.getStore()?.get(id),claim=opaque?this.recoveryClaims.get(opaque):undefined;
    if(!prepared||!claim?.graph)throw denied('CONFIGURATION_ORIGIN_RECOVERY_REQUIRED');
    this.assertRecoveryRootObservation(prepared,targetGraph,'target');
    const privateSourceObjects=this.privateObjects(claim.graph),source={...prepared.compilationInputs.source,schemas:{...prepared.compilationInputs.source.schemas,...claim.graph.schemas.entities}},
      target={...prepared.compilationInputs.target,schemas:{...prepared.compilationInputs.target.schemas,...targetGraph.schemas.entities},objects:this.privateObjects(targetGraph).map(object=>({...object,certificate:prepared.compilationInputs.target.objects.find(publicObject=>publicObject.entityType===object.entityType&&publicObject.nativeId===object.nativeId)?.certificate}))};
    const aliasSource={...source,objects:[...source.objects.filter(o=>o.entityType!=='credentials'),...privateSourceObjects.filter(o=>o.entityType==='credentials')]};
    const identityAliases={...(prepared.compilationInputs.options.identityAliases??{}),...(prepared.selection.identityAliases??{}),...this.credentialAliases(aliasSource,target)};
    return compilePromoteDocument(source,target,{...prepared.compilationInputs.options,...prepared.selection,targetWorkspaceCode:prepared.selection.targetWorkspaceCode,identityAliases,privateSourceObjects});
  }
  private async checkPrivateSource(id:string):Promise<void>{
    const opaque=this.recoveryByRun.getStore()?.get(id),claim=opaque?this.recoveryClaims.get(opaque):undefined;if(!claim)return;if(!this.kong)throw denied();
    await this.context.runPromotionRecoveryRead(opaque!,async()=>{
      for(const path of claim.points.keys())await this.kong!.request(claim.proof.clusterId,'GET',path);
      for(const[path,expected]of claim.collections){let cursor:string|undefined;const found=new Set<string>();
        do{const page=await this.kong!.list(claim.proof.clusterId,path,{size:100},cursor);for(const item of page.items){if(found.has(item.id))throw changed('CONFIGURATION_ORIGIN_CREDENTIAL_MEMBERSHIP_CHANGED');found.add(item.id);}cursor=page.nextCursor??undefined;}while(cursor);
        if(found.size!==expected.size||[...expected].some(id=>!found.has(id)))throw changed('CONFIGURATION_ORIGIN_CREDENTIAL_MEMBERSHIP_CHANGED');
      }
    });
  }
  /** Selected source objects for the per-packet fence (approved 2026-10-25),
   * or undefined when the full source refresh must apply instead (recovery
   * material, projection, credentials, or missing plan-time fingerprints). */
  private selectedSourceObjects(prepared:Prepared):readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]|undefined{
    if(typeof this.policy?.selectedFingerprints!=='function'||!prepared.sourceNativeFingerprints||prepared.recovery)return undefined;
    if(prepared.selectedSourceObjects!==undefined)return prepared.selectedSourceObjects||undefined;
    const material=prepared.compilationInputs,source=material.source,planTime=prepared.sourceNativeFingerprints;
    let result:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]|undefined;
    if(!source.projection){
      const compiled=compilePromoteDocument(material.source,material.target,{...material.options,...prepared.selection,targetWorkspaceCode:prepared.selection.targetWorkspaceCode});
      const byKey=new Map(source.objects.map(object=>[objectIdentity(object),object])),types=new Set<string>(GOVERNANCE_ENTITY_TYPES),picked:Array<Readonly<{entityType:string;nativeId:string;parentId?:string}>>=[];
      let complete=compiled.selectedObjectKeys.length>0;
      for(const key of compiled.selectedObjectKeys){const object=byKey.get(key);
        if(!object||!(types.has(object.entityType)||object.entityType==='targets'&&object.parentId)||!/^[a-f\d]{64}$/.test(planTime[`${object.entityType}:${object.nativeId}`]??'')){complete=false;break;}
        picked.push(Object.freeze({entityType:object.entityType,nativeId:object.nativeId,...(object.entityType==='targets'?{parentId:object.parentId!}:{})}));}
      if(complete)result=Object.freeze(picked);
    }
    prepared.selectedSourceObjects=result??null;return result;
  }
  private selectedFenceCost(prepared:Prepared,selected:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]):{calls:number;pages:number;records:number;bytes:number}{
    const source=prepared.compilationInputs.source,cost={calls:0,pages:0,records:0,bytes:0};
    for(const path of new Set(selected.map(o=>o.entityType==='targets'?`targets:${o.parentId}`:o.entityType))){
      const members=source.objects.filter(object=>path.startsWith('targets:')?object.entityType==='targets'&&`targets:${object.parentId}`===path:object.entityType===path);
      const pages=Math.floor(members.length/100)+1;cost.calls+=pages;cost.pages+=pages;cost.records+=members.length;
      cost.bytes+=members.reduce((sum,object)=>sum+Buffer.byteLength(canonicalJson(object.payload))*2,0)+pages*1024;
    }
    return cost;
  }
  async assertExecutionBudget(ref:ConfigurationOriginRef,plan:ConfigPlan):Promise<void>{
    if(this.context.peek()&&this.context.hasWorkflowScheduledNamespace()){
      if(!this.scheduledOrigin)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_BRIDGE_UNAVAILABLE');
      const original=this.scheduledOrigin.currentOriginalJobHandle(),proof=await this.scheduledOrigin.verifyOriginalJobHandle(original,'ledger',this.db);
      const job=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[proof.jobId]);
      if(!job||this.secrets.fingerprint(plan)!==job.plan_hash||plan.scope.clusterId!==job.cluster_id||plan.scope.workspaceId!==job.workspace_id
        ||plan.scope.transportScope!==job.transport_scope||plan.scope.kind!==job.scope_kind||canonicalJson(plan.scope.rootIds)!==canonicalJson(job.root_ids))throw denied('CONFIGURATION_SCHEDULE_ORIGIN_BUDGET_PLAN_INVALID');
      const bound=await this.boundJob(job,this.db);if(!bound||canonicalJson(bound)!==canonicalJson(ref))throw denied('CONFIGURATION_ORIGIN_BINDING_INVALID');
      const material=await this.assertScheduledJob(job,ref,'preflight',proof.actor.id,this.db,'write');
      const packets=plan.steps.reduce((n,step)=>n+step.nativeRequests.length,0);
      if(!Number.isSafeInteger(packets)||packets<0||packets>500)throw changed('CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED');
      const input=Object.freeze({...material,plan:Object.freeze(structuredClone(plan)),limits:Object.freeze({calls:500 as const,pages:100 as const,records:10000 as const,bytes:33554432 as const}),
        readRetriesReserved:3 as const,sourceFenceRounds:packets*2}),hmac=this.secrets.fingerprint(input);
      await this.scheduledOrigin.assertExecutionBudget(input,this.db);
      if(this.secrets.fingerprint(input)!==hmac||proof.expiresAt<=Date.now()||this.scheduledOrigin.currentOriginalJobHandle()!==original
        ||this.context.requireWorkflowScheduledNamespaceHandle()!==proof.namespaceHandle)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_SOURCE_CHANGED');
      return;
    }
    const prepared=this.current(ref),nativePackets=plan.steps.reduce((total,step)=>total+step.nativeRequests.length,0),usage=(prepared.compilationInputs.source as any).usage??{calls:500,pages:100,records:10000,bytes:33554432};
    // A write is sent once. Its two source fences each use GETs, whose fixed
    // transport may attempt three reads. Reserve those future calls upfront.
    const futureRounds=nativePackets*2,rounds=futureRounds+1,selected=this.selectedSourceObjects(prepared);
    // Selected-object fence: each future round lists only the collections that
    // hold the selected objects (three transport attempts reserved per call).
    const fence=selected?this.selectedFenceCost(prepared,selected):undefined;
    const publicEstimate=fence?{calls:usage.calls+fence.calls*futureRounds*3,pages:usage.pages+fence.pages*futureRounds,records:usage.records+fence.records*futureRounds,bytes:usage.bytes+fence.bytes*futureRounds}
      :{calls:usage.calls*(futureRounds*3+1),pages:usage.pages*rounds,records:usage.records*rounds,bytes:usage.bytes*rounds};
    const limits={calls:500,pages:100,records:10000,bytes:33554432};
    const reject=(estimated:typeof publicEstimate,privateUsage?:unknown):never=>{throw new ConflictException({code:'CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED',
      message:'发布批次超过源环境核验预算，请减少对象或凭证类型并重新生成计划',budget:{nativePackets,readRetriesReserved:3,limits,estimated,publicUsage:usage,...(privateUsage?{privateUsage}:{})}});};
    const opaque=this.recoveryByRun.getStore()?.get(ref.originId),claim=opaque?this.recoveryClaims.get(opaque):undefined;
    if(publicEstimate.calls>limits.calls||publicEstimate.pages>limits.pages||publicEstimate.records>limits.records||publicEstimate.bytes>limits.bytes)reject(publicEstimate);
    if(claim?.graph){
      const current=await this.context.promotionRecoveryUsage(opaque!);
      const pages=[...claim.collections.values()].reduce((sum,members)=>sum+Math.floor(members.size/100)+1,0),records=claim.points.size*2,
        bytes=claim.graph.objects.filter(object=>object.entityType==='credentials'&&claim.points.has(`/consumers/${object.parentId}/${object.credentialKind}/${object.nativeId}`)).reduce((sum,object)=>sum+Buffer.byteLength(canonicalJson(object.payload)),0)*2;
      const estimated={calls:publicEstimate.calls+current.calls+(claim.points.size+pages)*futureRounds*3,pages:publicEstimate.pages+current.pages+pages*futureRounds,
        records:publicEstimate.records+current.records+records*futureRounds,bytes:publicEstimate.bytes+current.bytes+bytes*futureRounds};
      if(current.deadline<=Date.now()||estimated.calls>limits.calls||estimated.pages>limits.pages||estimated.records>limits.records||estimated.bytes>limits.bytes)reject(estimated,current);
    }
  }
  private async boundJob(row:any,db:DbService):Promise<ConfigurationOriginRef|undefined>{
    if(!row.required_origin_kind){if(row.required_origin_id||row.required_origin_hmac)throw denied();return undefined;}
    const ref:ConfigurationOriginRef={version:1,kind:row.required_origin_kind,originId:row.required_origin_id,materialHmac:row.required_origin_hmac};this.assertRef(ref);
    const binding=await db.one<any>('SELECT * FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3',[row.cluster_id,row.workspace_id,row.id]);
    const loaded=await this.load(ref.originId,db);
    if(!binding||binding.origin_kind!==ref.kind||binding.origin_id!==ref.originId||binding.material_hmac!==ref.materialHmac||loaded.ref.materialHmac!==ref.materialHmac
      ||binding.source_cluster_id!==loaded.parent.cluster_id||binding.source_workspace_id!==loaded.parent.workspace_id||binding.comparison_id!==loaded.parent.comparison_id
      ||row.cluster_id!==loaded.parent.target_cluster_id||row.workspace_id!==loaded.parent.target_workspace_id||row.actor_id!==loaded.parent.actor_id||row.transport_scope!==loaded.target.scope.transportScope)throw denied('CONFIGURATION_ORIGIN_BINDING_INVALID');
    return ref;
  }
  /** Only ConfigurationAccess's genuine private job verifier invokes this
   * SQL-only boundary. Native packet dispatch still uses current(ref). */
  async assertJobVerifier(row:any,phase:string,actorId:string,sessionId:string|null,db=this.db):Promise<void>{
    const ref=await this.boundJob(row,db);if(!ref)return;
    if(!['read','step'].includes(phase))throw denied('CONFIGURATION_ORIGIN_VERIFIER_PHASE_INVALID');
    if(this.context.peek()&&this.context.hasWorkflowScheduledNamespace()){
      if(sessionId!==null)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_NULL_SID_REQUIRED');
      await this.assertScheduledJob(row,ref,phase,actorId,db);return;
    }
    const proof=this.runs.getStore()?.get(ref.originId);
    if(!proof||proof.ref.materialHmac!==ref.materialHmac||proof.actor.user.id!==actorId||row.actor_id!==actorId||phase==='step'&&row.origin_session_id!==sessionId
      ||proof.frame.actor?.id!==actorId||proof.frame.sessionId!==sessionId||proof.frame.clusterId!==row.cluster_id
      ||proof.target.scope.workspaceId!==row.workspace_id||proof.frame.workspaceId!==undefined&&proof.frame.workspaceId!==row.workspace_id)throw denied('CONFIGURATION_ORIGIN_VERIFIER_PROOF_REQUIRED');
    this.context.assertGovernanceOrigin(proof.frame,actorId,sessionId);
    await this.sourcePolicy().assertGrants(ref.originId,actorId,phase==='step'?'write':'read',db);
    await this.sourcePolicy().assertVerifierCurrent(ref.originId,proof.handle,{actorId,sessionId,frame:proof.frame},db);
  }
  async assertJob(row:any,phase:string,actorId:string,db=this.db,receiptOnly=false):Promise<void>{
    const ref=await this.boundJob(row,db);if(!ref)return;
    if(receiptOnly)return;
    if(this.context.peek()&&this.context.hasWorkflowScheduledNamespace()){await this.assertScheduledJob(row,ref,phase,actorId,db);return;}
    // Known outcome bookkeeping must remain possible after source access is
    // withdrawn. It cannot mint a native request or disclose source materials.
    if(phase==='ledger')return;
    await this.sourcePolicy().assertGrants(ref.originId,actorId,phase==='step'?'write':'read',db);
    if(['step','plan'].includes(phase)){const proof=this.current(ref);await this.sourcePolicy().assertCurrent(ref.originId,proof.handle);}
  }
  async beforeNativeSend(jobId:string,actorId:string):Promise<void>{
    const row=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[jobId]);if(!row?.required_origin_kind)return;
    if(this.context.peek()&&this.context.hasWorkflowScheduledNamespace()){
      const ref=await this.boundJob(row,this.db);if(!ref)throw denied();
      await this.assertScheduledJob(row,ref,'before-send',actorId,this.db,'write');return;
    }
    await this.assertJob(row,'step',actorId);
    const ref:ConfigurationOriginRef={version:1,kind:row.required_origin_kind,originId:row.required_origin_id,materialHmac:row.required_origin_hmac},prepared=this.current(ref);
    const selected=this.selectedSourceObjects(prepared),policy=this.sourcePolicy();
    if(selected){
      // Approved 2026-10-25: each packet re-checks only the selected source
      // objects against their plan-time private fingerprints.
      const current=await policy.selectedFingerprints!(ref.originId,prepared.handle,prepared.actor,selected),planTime=prepared.sourceNativeFingerprints!;
      if(selected.some(o=>{const key=`${o.entityType}:${o.nativeId}`;return!/^[a-f\d]{64}$/.test(planTime[key]??'')||current[key]!==planTime[key];}))throw changed();
    }else{
      const fresh=await policy.refresh(ref.originId,prepared.handle,prepared.actor);
      const fingerprints=await policy.fingerprints(ref.originId,prepared.handle,fresh);
      if(fresh.completeness!=='complete'||fresh.projection||this.secrets.fingerprint(this.manifest(fresh,fingerprints))!==prepared.sourceHash)throw changed();
    }
    await this.checkPrivateSource(ref.originId);await this.sourcePolicy().assertCurrent(ref.originId,prepared.handle);await this.assertJob(row,'step',actorId);prepared.checkedAt=Date.now();
  }
  private async assertScheduledJob(row:any,ref:ConfigurationOriginRef,phase:string,actorId:string,db:DbService,action?:'read'|'write'|'approve'):Promise<Readonly<ConfigurationWorkflowScheduledOriginMaterial>>{
    if(!this.scheduledOrigin)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_BRIDGE_UNAVAILABLE');
    if(!['read','step','ledger','stored','plan','workflow','capture-page','seal','metadata-write','preflight','before-send'].includes(phase))throw denied('CONFIGURATION_SCHEDULE_ORIGIN_PHASE_INVALID');
    const frame=this.context.current(),namespaceHandle=this.context.requireWorkflowScheduledNamespaceHandle();
    if(frame.sessionId!=null||frame.actor?.id!==row.actor_id||frame.clusterId!==row.cluster_id||frame.workspaceId!==row.workspace_id
      ||row.origin_type!=='http'||!row.origin_session_id||!['apply','rollback'].includes(row.kind)||row.execution_mode!=='approval'||row.approval_required!==true)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_JOB_INVALID');
    // Core checks step authority while initializing the genuine nested E.
    // This source read itself grants no Native permit. Only before-send needs
    // the already executing original nested ledger and its reciprocal links.
    const originalJobHandle=this.scheduledOrigin.currentOriginalJobHandle(),checkpoint:WorkflowScheduledConfigurationCheckpoint=phase==='before-send'?'before-send':['capture-page','seal'].includes(phase)?'capture':'ledger';
    const proof=await this.scheduledOrigin.verifyOriginalJobHandle(originalJobHandle,checkpoint,db);
    const deadline=Math.min(Date.parse(row.authority_expires_at),Date.parse(row.expires_at));
    if(proof.origin!=='workflow-scheduled-configuration'||proof.sessionId!==null||proof.readOnly||proof.namespaceHandle!==namespaceHandle
      ||proof.actor.id!==row.actor_id||proof.jobId!==row.id||proof.clusterId!==row.cluster_id||proof.workspaceId!==row.workspace_id
      ||proof.planId!==row.plan_id||proof.planRevision!==row.plan_revision||proof.planHash!==row.plan_hash||proof.permissionVersion!==row.permission_version
      ||proof.credentialEpoch!==Number(row.credential_epoch)||proof.leaseGeneration!==row.lease_generation||proof.purpose!==row.kind
      ||!Number.isFinite(deadline)||!Number.isFinite(proof.expiresAt)||proof.expiresAt<=Date.now()||proof.expiresAt>deadline)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_PROOF_INVALID');
    const loaded=await this.load(ref.originId,db);
    if(loaded.ref.materialHmac!==ref.materialHmac||!loaded.sourceNativeFingerprints||!loaded.targetNativeFingerprints)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_PRIVATE_MATERIAL_REQUIRED');
    const planBinding=await db.one<any>('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',[row.cluster_id,row.workspace_id,row.plan_id,row.plan_revision,row.plan_hash]);
    if(!planBinding||planBinding.job_id!==row.id||planBinding.origin_kind!==ref.kind||planBinding.origin_id!==ref.originId||planBinding.material_hmac!==ref.materialHmac)throw denied('CONFIGURATION_ORIGIN_BINDING_INVALID');
    const input=Object.freeze({job:Object.freeze(structuredClone(row)),ref:Object.freeze({...ref}),parent:Object.freeze(structuredClone(loaded.parent)),
      source:structuredClone(loaded.source),target:structuredClone(loaded.target),sourceNativeFingerprints:Object.freeze({...loaded.sourceNativeFingerprints}),
      targetNativeFingerprints:Object.freeze({...loaded.targetNativeFingerprints}),selection:Object.freeze(structuredClone(loaded.selection)),
      recovery:loaded.recovery?Object.freeze(structuredClone(loaded.recovery)):null,proof:Object.freeze({...proof}),originalJobHandle,phase,actorId:configurationId(actorId),
      action:action??(['step','metadata-write','before-send'].includes(phase)?'write':'read')as'read'|'write'|'approve'});
    const materialHmac=this.secrets.fingerprint(input);
    await this.scheduledOrigin.assertCurrentSourceMaterial(input,db);
    if(this.secrets.fingerprint(input)!==materialHmac||proof.expiresAt<=Date.now()||this.context.requireWorkflowScheduledNamespaceHandle()!==namespaceHandle
      ||this.scheduledOrigin.currentOriginalJobHandle()!==originalJobHandle||this.context.current().sessionId!=null)throw denied('CONFIGURATION_SCHEDULE_ORIGIN_SOURCE_CHANGED');
    return input;
  }
  async assertWorkflow(plan:import('../workflows/workflow.types').WorkflowPlanV1,actorId:string,action:'read'|'write'|'approve',tx=this.db):Promise<void>{
    await this.assertStoredWorkflow(plan,tx);
    const payload=plan.steps[0]?.metadata as any;if(!payload?.jobId)return;
    const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[payload.jobId,plan.clusterId,plan.workspaceId]);
    if(!job?.required_origin_kind)return;
    const ref:ConfigurationOriginRef={version:1,kind:job.required_origin_kind,originId:job.required_origin_id,materialHmac:job.required_origin_hmac};
    if(this.context.peek()&&this.context.hasWorkflowScheduledNamespace()){await this.assertScheduledJob(job,ref,'workflow',actorId,tx,action);return;}
    await this.assertJob(job,'workflow',actorId,tx);
    await this.sourcePolicy().assertGrants(ref.originId,job.actor_id,'write',tx);await this.sourcePolicy().assertGrants(ref.originId,actorId,action,tx);
  }
  async assertStoredWorkflow(plan:import('../workflows/workflow.types').WorkflowPlanV1,tx=this.db):Promise<void>{
    const p=plan.steps[0]?.metadata as any;if(!p?.jobId)return;
    const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[p.jobId,plan.clusterId,plan.workspaceId]);
    if(!job?.required_origin_kind)return;
    if(job.plan_id!==p.planId||job.plan_revision!==p.planRevision||job.plan_hash!==p.planHash)throw denied('CONFIGURATION_ORIGIN_WORKFLOW_PLAN_MISMATCH');
    await this.assertJob(job,'stored',job.actor_id,tx);
    const b=await tx.one<any>('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',[job.cluster_id,job.workspace_id,p.planId,p.planRevision,p.planHash]);
    if(!b||b.job_id!==job.id||b.origin_kind!==job.required_origin_kind||b.origin_id!==job.required_origin_id||b.material_hmac!==job.required_origin_hmac)throw denied('CONFIGURATION_ORIGIN_BINDING_INVALID');
  }
  storagePolicy():ConfigurationOriginStoragePolicy{return{
    bindJob:async(handle,job,ref,tx)=>{
      const permit=this.permittedJobs.get(handle);if(!permit||canonicalJson(permit)!==canonicalJson(ref))throw denied('CONFIGURATION_ORIGIN_JOB_PERMIT_REQUIRED');
      const loaded=await this.load(ref.originId,tx);if(loaded.ref.materialHmac!==ref.materialHmac||job.cluster_id!==loaded.parent.target_cluster_id||job.workspace_id!==loaded.parent.target_workspace_id||job.actor_id!==loaded.parent.actor_id)throw denied();
      await tx.exec(`INSERT INTO configuration_job_origin_bindings(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac,source_cluster_id,source_workspace_id,comparison_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[job.cluster_id,job.workspace_id,job.id,ref.kind,ref.originId,ref.materialHmac,loaded.parent.cluster_id,loaded.parent.workspace_id,loaded.parent.comparison_id]);
    },
    beforeFreeze:async(_handle,job,plan,tx)=>{
      const marker=job.required_origin_kind?{version:1,kind:job.required_origin_kind,originId:job.required_origin_id,materialHmac:job.required_origin_hmac}:undefined;
      if(canonicalJson(marker??null)!==canonicalJson(plan.originRef??null))throw denied('CONFIGURATION_ORIGIN_PLAN_MARKER_REQUIRED');
      await this.assertJob(job,'plan',job.actor_id,tx);
    },
    bindPlan:async(_handle,job,plan,identity,tx)=>{
      if(!plan.originRef)return;await this.assertJob(job,'plan',job.actor_id,tx);const ref=plan.originRef;
      await tx.exec(`INSERT INTO configuration_plan_origin_bindings(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,job_id,origin_kind,origin_id,material_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[job.cluster_id,job.workspace_id,identity.planId,identity.planRevision,identity.planHash,job.id,ref.kind,ref.originId,ref.materialHmac]);
      if(job.kind==='import'){
        const n=await tx.exec(`UPDATE governance_promotions SET state='ready',configuration_job_id=$2,plan_id=$3,plan_revision=$4,plan_hash=$5,updated_at=now() WHERE id=$1 AND state='planning' AND configuration_job_id IS NULL`,[ref.originId,job.id,identity.planId,identity.planRevision,identity.planHash]);
        if(n!==1)throw changed('CONFIGURATION_ORIGIN_PARENT_ALREADY_BOUND');
      }
    },
    verifyPlan:async(_handle,row,plan,tx)=>{
      const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[row.source_job_id]);
      if(!job)throw denied();await this.assertJob(job,'plan',job.actor_id,tx);
      if(!job.required_origin_kind){if(plan.originRef)throw denied();return;}
      if(!plan.originRef||plan.originRef.kind!==job.required_origin_kind||plan.originRef.originId!==job.required_origin_id||plan.originRef.materialHmac!==job.required_origin_hmac)throw denied('CONFIGURATION_ORIGIN_PLAN_MARKER_REQUIRED');
      const binding=await tx.one<any>('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',[row.cluster_id,row.workspace_id,row.plan_id,row.plan_revision,row.plan_hash]);
      if(!binding||binding.job_id!==job.id||binding.origin_id!==plan.originRef.originId||binding.origin_kind!==plan.originRef.kind||binding.material_hmac!==plan.originRef.materialHmac)throw denied('CONFIGURATION_ORIGIN_BINDING_INVALID');
    },
  };}
}
