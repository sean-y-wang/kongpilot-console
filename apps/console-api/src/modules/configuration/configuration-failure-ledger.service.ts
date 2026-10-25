import{ConflictException,ForbiddenException,Injectable}from'@nestjs/common';
import{DbService}from'../../infrastructure/db.service';
import{SecretService}from'../../infrastructure/secret.service';
import{KongExecutionContextService}from'../../infrastructure/kong/execution-context.service';
import{AuditService}from'../audit/audit.service';
import{metadataAuditScope}from'../event-producers/native-audit-scope';
import{AuthorizationService}from'../authorization/authorization.service';
import{ConfigurationAccessService}from'./configuration-access.service';
import type{ConfigurationAccessHandle}from'./configuration.types';
import type{EntityActor}from'../entities/entities.types';
import type{WorkflowScheduledConfigurationExecutionProof}from'../workflows/workflow-scheduled-configuration-origin.types';
import{immutableJson}from'../../infrastructure/kong/immutable-json';
import{CONFIGURATION_INITIALIZATION_ANCHOR_QUERY as INIT_ANCHOR,CONFIGURATION_INITIALIZATION_FOOTPRINT_QUERY as INIT_FOOTPRINT,
 CONFIGURATION_INITIALIZATION_PLAN_OBJECTS_QUERY as INIT_OBJECTS,CONFIGURATION_INITIALIZATION_CHILD_QUERY as INIT_CHILD,
 CONFIGURATION_INITIALIZATION_STEPS_QUERY as INIT_STEPS,CONFIGURATION_INITIALIZATION_JOB_CAS as INIT_JOB,
 CONFIGURATION_INITIALIZATION_EXECUTION_CAS as INIT_EXECUTION}from'./configuration-initialization-failure';
import{configurationId,configurationKey,configurationObject,configurationConfirm,CONFIGURATION_HEX,safeConfigurationError}from'./configuration-input';
import{CONFIGURATION_FAILURE_ANCHOR_QUERY,CONFIGURATION_FAILURE_STEPS_QUERY,CONFIGURATION_FAILURE_JOB_CAS,
 CONFIGURATION_FAILURE_EXECUTION_CAS,CONFIGURATION_FAILURE_STEP_CAS,CONFIGURATION_ABANDON_CURRENT_IDENTITY_QUERY,
 CONFIGURATION_ABANDON_EXECUTION_REFERENCE_QUERY}from'./configuration-failure-queries';

declare const brand:unique symbol;
export type ConfigurationFailureHandle=Readonly<{[brand]:true}>;
declare const initializationBrand:unique symbol;
export type ConfigurationInitializationFailureHandle=Readonly<{[initializationBrand]:true}>;
type Identity={clusterId:string;workspaceId:string;jobId:string;executionId:string;planId:string;planRevision:number;planHash:string;
 actorId:string;sessionId:string;leaseGeneration:number;leaseOwnerHash:string;claimHash:string;workflowId:string|null;workflowExecutionId:string|null;
 jobRevision:number;executionRevision:number;requestId?:string;ip?:string;permissionVersion:string;transportScope:string;
 scheduledOrigin?:Readonly<{claimId:string;wrapperOriginId:string;configurationOriginId:string;factsHmac:string}>};
type InitializationIdentity=Readonly<{anchor:any;anchorHmac:string;objectsHmac:string;claimHash:string}>;
/** Both rows are append-only SQL 026 facts. This read grants no execution or
 * current principal and is deliberately usable after the original run closes. */
export const CONFIGURATION_FAILURE_SCHEDULED_ORIGINS_QUERY=`SELECT row_to_json(o) AS wrapper_origin,row_to_json(c) AS configuration_origin
 FROM workflow_configuration_execution_origins c JOIN workflow_execution_origins o ON o.id=c.wrapper_origin_id
 AND o.cluster_id=c.cluster_id AND o.workspace_id=c.workspace_id AND o.claim_id=c.claim_id
 AND o.execution_id=c.workflow_execution_id AND o.workflow_id=c.workflow_id
 AND o.workflow_plan_revision=c.workflow_plan_revision AND o.workflow_plan_hash=c.workflow_plan_hash
 WHERE c.cluster_id=$1 AND c.workspace_id=$2 AND c.configuration_job_id=$3 AND c.configuration_execution_id=$4
 AND c.workflow_execution_id=$5`;
const refused=(code='CONFIGURATION_FAILURE_CAPABILITY_INVALID')=>new ForbiddenException({code,message:'原配置执行的失败记账引用无效'});
const conflict=()=>new ConflictException({code:'CONFIGURATION_FAILURE_LEDGER_CHANGED',message:'原执行状态已变化，请读取原回执'});
const integer=(v:unknown)=>Number.isSafeInteger(v)&&Number(v)>0;
/** A failure handle authorizes only recording facts of one already initialized
 * run. It has no Native, Mutation, workflow execution, frame or recovery API.
 * Handles never leave ConfigurationService's same-run stack. */
@Injectable()
export class ConfigurationFailureLedgerService{
 private readonly handles=new WeakMap<object,Identity>();
 private readonly scheduledArmedRuns=new WeakMap<object,Set<string>>();
 private readonly initializationHandles=new WeakMap<object,InitializationIdentity>();
 private readonly initializationArmedJobs=new WeakSet<object>();
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly audit:AuditService,
  private readonly access:ConfigurationAccessService,private readonly context:KongExecutionContextService,private readonly authz:AuthorizationService){}
 private args(i:Identity):unknown[]{return[i.clusterId,i.workspaceId,i.jobId,i.executionId,i.planId,i.planRevision,i.planHash,i.leaseGeneration,i.actorId,i.sessionId];}
 private scope(a:any):void{
  if(!a||!['apply','rollback'].includes(a.kind)||a.job_state!=='running'||a.execution_state!=='executing'
   ||a.execution_actor_id!==a.actor_id||a.execution_mode_actual!==a.execution_mode
   ||a.execution_permission_version!==a.permission_version||a.execution_lease_generation!==a.lease_generation
   ||a.execution_plan_id!==a.plan_id||a.execution_plan_revision!==a.plan_revision||a.execution_plan_hash!==a.plan_hash
   ||a.version_plan_hash!==a.plan_hash||a.current_revision!==a.plan_revision||!CONFIGURATION_HEX.test(a.plan_hash??'')
   ||!CONFIGURATION_HEX.test(a.claim_hash??'')||!CONFIGURATION_HEX.test(a.lease_owner_hash??'')
   ||!integer(a.lease_generation)||!integer(a.job_revision)||!integer(a.execution_revision)||!integer(a.step_count)||a.step_count>10000
   ||!a.origin_session_id)throw refused();
  if(a.execution_mode==='approval'){
   if(a.execution_workflow_id!==a.workflow_id||a.workflow_kind!=='configuration_v2'||a.subject_type!=='configuration_jobs'
    ||a.subject_id!==a.job_id||a.requester_user_id!==a.actor_id||a.workflow_execution_actor_id!==a.actor_id
    ||!a.workflow_execution_id||a.snapshot_state!=='ready'||a.approved_version!==a.workflow_plan_revision
    ||a.workflow_execution_plan_revision!==a.workflow_plan_revision||a.workflow_plan_hash!==a.current_workflow_plan_hash
    ||a.workflow_execution_plan_hash!==a.current_workflow_plan_hash)throw refused();
  }else if(a.execution_mode!=='direct'||a.workflow_id!==null||a.execution_workflow_id!==null||a.workflow_execution_id!==null
   ||a.approved_version!==null||a.workflow_plan_hash!==null)throw refused();
 }
 private identity(a:any,requestId:string|undefined,ip?:string):Identity{return Object.freeze({clusterId:a.cluster_id,workspaceId:a.workspace_id,jobId:a.job_id,
  executionId:a.execution_id,planId:a.plan_id,planRevision:a.plan_revision,planHash:a.plan_hash,actorId:a.actor_id,sessionId:a.origin_session_id,
  leaseGeneration:a.lease_generation,leaseOwnerHash:a.lease_owner_hash,claimHash:a.claim_hash,workflowId:a.workflow_id,workflowExecutionId:a.workflow_execution_id,
  jobRevision:a.job_revision,executionRevision:a.execution_revision,requestId,ip,permissionVersion:a.permission_version,transportScope:a.transport_scope});}
 /** A genuine AccessService handle is required; client-shaped objects and
  * copied handles fail its existing private WeakMap/current authority checks. */
 async arm(handle:ConfigurationAccessHandle,executionId:string,claimHash:string,workflowExecutionId:string|null):Promise<ConfigurationFailureHandle>{
  const frame=this.context.current(),state=await this.access.description(handle),scheduled=this.context.hasWorkflowScheduledNamespace();
  if(!frame.actor||frame.actor.id!==state.actor.id||!state.jobId
   ||frame.clusterId!==state.scope.clusterId||frame.workspaceId!==state.scope.workspaceId
   ||!CONFIGURATION_HEX.test(claimHash)||(!scheduled&&(!frame.sessionId||frame.sessionId!==state.sessionId||typeof frame.requestId!=='string'||!frame.requestId)))throw refused();
  if(scheduled){const proof=await this.access.verifyHandle(handle);
   if(frame.sessionId!=null||state.sessionId!==null||proof.origin!=='workflow-scheduled-configuration'||proof.sessionId!==null
    ||proof.readOnly||!proof.originalScheduledJobHandle||proof.originalScheduledJobHandle!==this.access.originalWorkflowScheduledConfigurationJobHandle(handle)
    ||proof.namespaceHandle!==this.context.requireWorkflowScheduledNamespaceHandle()||proof.jobId!==state.jobId)throw refused();
   const id=configurationId(executionId),used=this.scheduledArmedRuns.get(proof.originalScheduledJobHandle)??new Set<string>();
   if(used.has(id))throw refused('CONFIGURATION_FAILURE_SCHEDULED_ARM_REPLAY');
   // Consume this genuine original run before another await. A failed arm
   // cannot be retried with substituted provenance or a replacement token.
   used.add(id);this.scheduledArmedRuns.set(proof.originalScheduledJobHandle,used);
  }
  const originalRequestId=frame.requestId,originalIp=frame.ip,originalSid=frame.sessionId;
  await this.access.assertCurrent(handle,{phase:'step',jobId:state.jobId});
  return this.db.transaction(async tx=>{
   const a=await tx.one<any>(CONFIGURATION_FAILURE_ANCHOR_QUERY,[state.scope.clusterId,state.scope.workspaceId,state.jobId,configurationId(executionId),workflowExecutionId]);
   this.scope(a);
   if(a.claim_hash!==claimHash||a.actor_id!==state.actor.id||!scheduled&&a.origin_session_id!==originalSid||a.permission_version!==state.permissionVersion
    ||a.transport_scope!==state.scope.transportScope||a.lease_generation!==state.leaseGeneration||!a.lease_until
    ||!Number.isFinite(Date.parse(a.lease_until))||Date.parse(a.lease_until)<=Date.now()
    ||a.execution_mode==='approval'&&(!['executing'].includes(a.workflow_state)||a.workflow_execution_state!=='executing'
      ||!scheduled&&a.workflow_request_id!==originalRequestId)||a.execution_mode==='direct'&&a.job_request_id!==originalRequestId)throw refused();
   let identity:Identity;
   if(scheduled){
    const original=await this.access.workflowScheduledConfigurationExecutionProof(handle,a.execution_id,tx,'ledger');
    if(a.execution_mode!=='approval'||a.workflow_request_id!==null
     ||original.origin!=='workflow-scheduled-configuration'||original.sessionId!==null
     ||original.jobHandle!==this.access.originalWorkflowScheduledConfigurationJobHandle(handle)
     ||original.namespaceHandle!==this.context.requireWorkflowScheduledNamespaceHandle()||original.expiresAt<=Date.now())throw refused();
    this.scheduledTuple(original,a);
    const facts=await this.scheduledFacts(tx,a);this.scheduledRows(facts,a,original);
    identity={...this.identity(a,undefined),scheduledOrigin:Object.freeze({claimId:original.claimId,
     wrapperOriginId:original.wrapperOriginId,configurationOriginId:original.configurationOriginId,factsHmac:this.secrets.fingerprint(facts)})};
   }else identity=this.identity(a,originalRequestId!,originalIp);
   const token=Object.freeze({})as ConfigurationFailureHandle;this.handles.set(token,Object.freeze(identity));return token;
  });
 }
 private scheduledTuple(p:Readonly<WorkflowScheduledConfigurationExecutionProof>,a:any):void{
  if(p.clusterId!==a.cluster_id||p.workspaceId!==a.workspace_id||p.actorId!==a.actor_id||p.configurationJobId!==a.job_id
   ||p.configurationExecutionId!==a.execution_id||p.configurationPlanId!==a.plan_id||p.configurationPlanRevision!==a.plan_revision
   ||p.configurationPlanHash!==a.plan_hash||p.configurationClaimHash!==a.claim_hash||p.workflowId!==a.workflow_id
   ||p.wrapperExecutionId!==a.workflow_execution_id||p.workflowPlanRevision!==a.workflow_plan_revision||p.workflowPlanHash!==a.current_workflow_plan_hash
   ||p.permissionVersion!==a.permission_version||p.credentialEpoch!==Number(a.credential_epoch)||p.leaseGeneration!==a.lease_generation)throw refused();
 }
 private async scheduledFacts(tx:DbService,a:any):Promise<any>{const facts=await tx.one<any>(CONFIGURATION_FAILURE_SCHEDULED_ORIGINS_QUERY,
  [a.cluster_id,a.workspace_id,a.job_id,a.execution_id,a.workflow_execution_id]);if(!facts?.wrapper_origin||!facts.configuration_origin)throw refused();return facts;}
 private scheduledRows(facts:any,a:any,p:Readonly<WorkflowScheduledConfigurationExecutionProof>):void{
  const o=facts.wrapper_origin,c=facts.configuration_origin;
  if(o.id!==p.wrapperOriginId||c.id!==p.configurationOriginId||o.claim_id!==p.claimId||c.claim_id!==p.claimId
   ||c.wrapper_origin_id!==o.id||o.executor_id!==a.actor_id||o.execution_id!==a.workflow_execution_id||c.workflow_execution_id!==a.workflow_execution_id
   ||o.cluster_id!==a.cluster_id||c.cluster_id!==a.cluster_id||o.workspace_id!==a.workspace_id||c.workspace_id!==a.workspace_id
   ||o.workflow_id!==a.workflow_id||c.workflow_id!==a.workflow_id||o.workflow_plan_revision!==a.workflow_plan_revision
   ||c.workflow_plan_revision!==a.workflow_plan_revision||o.workflow_plan_hash!==a.current_workflow_plan_hash||c.workflow_plan_hash!==a.current_workflow_plan_hash
   ||c.configuration_job_id!==a.job_id||c.configuration_execution_id!==a.execution_id||c.configuration_plan_id!==a.plan_id
   ||c.configuration_plan_revision!==a.plan_revision||c.configuration_plan_hash!==a.plan_hash)throw refused();
 }
 release(handle:ConfigurationFailureHandle):void{if(!this.handles.delete(handle))throw refused();}
 /** Reserve only a future initialization failure under the original live job.
  * No execution exists at this point. A copied token, a restarted process or
  * an old claimed child can never establish this separate capability. */
 async armInitialization(handle:ConfigurationAccessHandle,claimHash:string,workflowExecutionId:string):Promise<ConfigurationInitializationFailureHandle>{
  const frame=this.context.current(),state=await this.access.description(handle),step=this.context.currentApprovedStep();
  if(!this.context.hasWorkflowScheduledNamespace()||frame.sessionId!=null||state.sessionId!==null||step.kind!=='metadata'
   ||step.execution.origin!=='scheduled-workflow'||step.execution.sessionId!==null||step.execution.executionId!==workflowExecutionId
   ||!frame.actor||frame.actor.id!==state.actor.id||frame.clusterId!==state.scope.clusterId||frame.workspaceId!==state.scope.workspaceId
   ||!state.jobId||!CONFIGURATION_HEX.test(claimHash))throw refused('CONFIGURATION_INITIALIZATION_CAPABILITY_INVALID');
  // This capability precedes createExecution. Generic verifyHandle deliberately
  // requires a nested packet execution and cannot authorize this job-only SQL
  // boundary. The private Access job association and the transaction's genuine
  // Origin ledger proof retain the original Root/current-principal checks.
  const original=this.access.originalWorkflowScheduledConfigurationJobHandle(handle),namespace=this.context.requireWorkflowScheduledNamespaceHandle();
  if(this.context.current()!==frame||this.initializationArmedJobs.has(original))throw refused('CONFIGURATION_INITIALIZATION_CAPABILITY_INVALID');
  this.initializationArmedJobs.add(original);
  return this.db.transaction(async tx=>{
   const proof=await this.access.workflowScheduledConfigurationJobProof(handle,tx),keys=[state.scope.clusterId,state.scope.workspaceId,state.jobId,configurationId(workflowExecutionId)];
   const anchor=await tx.one<any>(INIT_ANCHOR,keys);this.initializationAnchor(anchor);
   const {job:j,wrapper:e,wrapper_origin:o}=anchor;
   if(proof.origin!=='workflow-scheduled-configuration'||proof.sessionId!==null||proof.readOnly||proof.namespaceHandle!==namespace
    ||proof.expiresAt<=Date.now()||proof.jobId!==j.id||proof.actor.id!==j.actor_id||proof.clusterId!==j.cluster_id||proof.workspaceId!==j.workspace_id
    ||proof.planId!==j.plan_id||proof.planRevision!==j.plan_revision||proof.planHash!==j.plan_hash||proof.permissionVersion!==j.permission_version
    ||proof.leaseGeneration!==j.lease_generation||Number(j.credential_epoch)!==proof.credentialEpoch||proof.claimId!==o.claim_id
    ||proof.wrapperOriginId!==o.id||proof.wrapperExecutionId!==e.id||step.stepId!==anchor.workflow_step.id||step.execution.workflowId!==j.workflow_id
    ||step.execution.actorId!==j.actor_id||step.execution.clusterId!==j.cluster_id||step.execution.workspaceId!==j.workspace_id
    ||step.execution.scheduleClaimId!==o.claim_id||step.execution.workflowOriginId!==o.id||step.execution.permissionVersion!==j.permission_version
    ||j.actor_id!==state.actor.id||j.permission_version!==state.permissionVersion
    ||j.lease_generation!==state.leaseGeneration||!Number.isFinite(Date.parse(j.lease_until))||Date.parse(j.lease_until)<=Date.now())throw refused('CONFIGURATION_INITIALIZATION_CAPABILITY_INVALID');
   const footprint=await tx.one<any>(INIT_FOOTPRINT,[j.cluster_id,j.workspace_id,j.id,j.workflow_id,e.id]);
   if(!footprint||footprint.execution_count!==0||footprint.operation_count!==0||footprint.fence_count!==0||footprint.step_count!==0)throw refused('CONFIGURATION_INITIALIZATION_NOT_FRESH');
   const objects=await tx.query<any>(INIT_OBJECTS,[j.cluster_id,j.workspace_id,j.plan_id,j.plan_revision,j.plan_hash]);
   this.initializationObjects(objects,anchor);
   await this.access.assertCurrent(handle,{phase:'step',jobId:j.id},tx);
   if(this.context.current()!==frame||this.context.requireWorkflowScheduledNamespaceHandle()!==namespace
    ||this.access.originalWorkflowScheduledConfigurationJobHandle(handle)!==original||proof.expiresAt<=Date.now())throw refused('CONFIGURATION_INITIALIZATION_CAPABILITY_INVALID');
   const token=Object.freeze({})as ConfigurationInitializationFailureHandle;
   this.initializationHandles.set(token,Object.freeze({anchor:immutableJson(anchor),anchorHmac:this.secrets.fingerprint(anchor),objectsHmac:this.secrets.fingerprint(objects),claimHash}));return token;
  });
 }
 private initializationAnchor(a:any):void{
  const j=a?.job,v=a?.version,p=a?.plan,w=a?.workflow,e=a?.wrapper,o=a?.wrapper_origin,s=a?.workflow_step;
  if(!j||!v||!p||!w||!e||!o||!s||!['apply','rollback'].includes(j.kind)||j.origin_type!=='http'||!j.origin_session_id
   ||j.state!=='running'||j.execution_mode!=='approval'||j.approval_required!==true||j.remote_started!==false||j.remote_completed!==false
   ||!integer(j.revision)||!integer(j.lease_generation)||!CONFIGURATION_HEX.test(j.lease_owner_hash??'')||!CONFIGURATION_HEX.test(j.plan_hash??'')
   ||!Number.isSafeInteger(v.step_count)||v.step_count<0||v.step_count>10000||v.plan_hash!==j.plan_hash||v.plan_id!==j.plan_id||v.plan_revision!==j.plan_revision||p.current_revision!==j.plan_revision
   ||w.id!==j.workflow_id||w.kind!=='configuration_v2'||w.subject_type!=='configuration_jobs'||w.subject_id!==j.id||w.requester_type!=='console'
   ||w.requester_user_id!==j.actor_id||w.state!=='executing'||w.execution_mode!=='approval'||w.approval_required!==true
   ||e.workflow_id!==w.id||e.state!=='executing'||e.snapshot_state!=='ready'||e.request_id!==null||e.execution_actor_id!==j.actor_id
   ||e.plan_revision!==w.plan_revision||e.plan_hash!==w.plan_hash||e.permission_version!==j.permission_version
   ||o.execution_id!==e.id||o.workflow_id!==w.id||o.executor_id!==j.actor_id||o.workflow_plan_revision!==w.plan_revision||o.workflow_plan_hash!==w.plan_hash
   ||s.workflow_id!==w.id||s.plan_revision!==w.plan_revision||s.plan_hash!==w.plan_hash||s.kind!=='metadata'||s.handler!=='configuration_v2'
   ||s.entity_type!=='configuration_jobs'||s.entity_id!==j.id||s.state!=='running'||!Array.isArray(s.native_requests)||s.native_requests.length
   ||[v,p,w,e,o,s].some(row=>row.cluster_id!==j.cluster_id||row.workspace_id!==j.workspace_id))throw refused('CONFIGURATION_INITIALIZATION_GRAPH_INVALID');
 }
 private initializationObjects(objects:any[],a:any):void{
  const j=a.job;if(objects.length!==a.version.step_count||objects.some((p,n)=>p.cluster_id!==j.cluster_id||p.workspace_id!==j.workspace_id
   ||p.plan_id!==j.plan_id||p.plan_revision!==j.plan_revision||p.plan_hash!==j.plan_hash||p.step_order!==n+1||!p.step_id||!p.object_workspace_id))throw refused('CONFIGURATION_INITIALIZATION_DAG_INVALID');
 }
 releaseInitialization(handle:ConfigurationInitializationFailureHandle):void{if(!this.initializationHandles.delete(handle))throw refused('CONFIGURATION_INITIALIZATION_CAPABILITY_INVALID');}
 /** Metadata only: consume before await, then prove zero actual Native effects
  * from locked SQL. Expiry cannot grant execution and cannot erase this fact. */
 async recordInitializationFailure(handle:ConfigurationInitializationFailureHandle,error:unknown):Promise<Readonly<Record<string,unknown>>>{
  const identity=this.initializationHandles.get(handle);if(!identity)throw refused('CONFIGURATION_INITIALIZATION_CAPABILITY_INVALID');this.initializationHandles.delete(handle);
  return this.db.transaction(async tx=>{
   const old=identity.anchor,j=old.job,keys=[j.cluster_id,j.workspace_id,j.id,old.wrapper.id],a=await tx.one<any>(INIT_ANCHOR,keys);
   this.initializationAnchor(a);if(this.secrets.fingerprint(a)!==identity.anchorHmac)throw conflict();
   const objects=await tx.query<any>(INIT_OBJECTS,[j.cluster_id,j.workspace_id,j.plan_id,j.plan_revision,j.plan_hash]);this.initializationObjects(objects,a);
   if(this.secrets.fingerprint(objects)!==identity.objectsHmac)throw conflict();
   const footprint=await tx.one<any>(INIT_FOOTPRINT,[j.cluster_id,j.workspace_id,j.id,j.workflow_id,old.wrapper.id]);
   if(!footprint||footprint.execution_count!==1||footprint.operation_count!==0||footprint.fence_count!==0)throw refused('CONFIGURATION_INITIALIZATION_NOT_KNOWN_ZERO');
   const child=await tx.one<any>(INIT_CHILD,[j.cluster_id,j.workspace_id,j.id]),e=child?.execution,c=child?.origin,o=a.wrapper_origin,w=a.workflow;
   if(!e||!c||!['claimed','executing'].includes(e.state)||e.revision!==(e.state==='claimed'?1:2)||e.completed_at!==null
    ||e.cluster_id!==j.cluster_id||e.workspace_id!==j.workspace_id||e.job_id!==j.id||e.actor_id!==j.actor_id||e.execution_mode!=='approval'
    ||e.plan_id!==j.plan_id||e.plan_revision!==j.plan_revision||e.plan_hash!==j.plan_hash||e.permission_version!==j.permission_version
    ||e.workflow_id!==w.id||e.approved_version!==w.plan_revision||e.workflow_plan_hash!==w.plan_hash||e.claim_hash!==identity.claimHash
    ||e.lease_generation!==j.lease_generation||e.expires_at!==j.expires_at||e.before_snapshot_id!==j.safe_progress?.baselineSnapshotId||e.before_snapshot_version!==j.safe_progress?.baselineVersion
    ||c.cluster_id!==j.cluster_id||c.workspace_id!==j.workspace_id||c.wrapper_origin_id!==o.id||c.claim_id!==o.claim_id
    ||c.workflow_execution_id!==a.wrapper.id||c.workflow_id!==w.id||c.workflow_plan_revision!==w.plan_revision||c.workflow_plan_hash!==w.plan_hash
    ||c.configuration_execution_id!==e.id||c.configuration_job_id!==j.id||c.configuration_plan_id!==j.plan_id
    ||c.configuration_plan_revision!==j.plan_revision||c.configuration_plan_hash!==j.plan_hash||c.workflow_step_id!==a.workflow_step.id)throw refused('CONFIGURATION_INITIALIZATION_CHILD_INVALID');
   const steps=await tx.query<any>(INIT_STEPS,[j.cluster_id,j.workspace_id,j.id]);
   if(footprint.step_count!==steps.length||steps.length!==0&&steps.length!==objects.length||steps.some((s,n)=>{
    const p=objects[n];return !p||s.cluster_id!==j.cluster_id||s.workspace_id!==j.workspace_id||s.job_id!==j.id||s.execution_id!==e.id
     ||s.plan_id!==j.plan_id||s.plan_revision!==j.plan_revision||s.plan_hash!==j.plan_hash||s.plan_step_id!==p.step_id||s.step_order!==n+1
     ||s.object_workspace_id!==p.object_workspace_id||s.approval_required!==true||s.before_hmac!==p.before_hmac||s.original_native_id!==(p.native_id??p.allocated_native_id)
     ||s.state!=='pending'||s.revision!==1||s.started_at!==null||s.completed_at!==null||s.operation_id!==null||s.receipt_operation_id!==null
     ||s.receipt_ciphertext!==null||s.after_hmac!==null||s.recycle_entry_id!==null||s.effective_native_id!==null||s.error_code!==null
     ||!s.safe_result||Object.keys(s.safe_result).length!==0;
   }))throw refused('CONFIGURATION_INITIALIZATION_NOT_KNOWN_ZERO');
   const code=safeConfigurationError(error),progress={...j.safe_progress,executionId:e.id,executionRevision:e.revision+1,planRevision:j.plan_revision,planHash:j.plan_hash,
    leaseGeneration:j.lease_generation,workflowExecutionId:a.wrapper.id,completedSteps:0,unresolvedSteps:0,terminalFailureRecorded:true,initializationFailed:true};
   for(const s of steps)if(await tx.exec(CONFIGURATION_FAILURE_STEP_CAS,[j.cluster_id,j.workspace_id,j.id,e.id,j.plan_id,j.plan_revision,j.plan_hash,s.id,s.revision,'failed','CONFIGURATION_NOT_STARTED'])!==1)throw conflict();
   const args=[j.cluster_id,j.workspace_id,j.id,e.id,j.plan_id,j.plan_revision,j.plan_hash,j.lease_generation,j.actor_id,j.origin_session_id,j.revision,e.revision,identity.claimHash,j.lease_owner_hash,code,JSON.stringify(this.secrets.redact(progress))];
   if(await tx.exec(INIT_JOB,args)!==1||await tx.exec(INIT_EXECUTION,args.slice(0,14))!==1)throw conflict();
   await this.audit.append({actorId:j.actor_id,clusterId:j.cluster_id,workspaceId:j.workspace_id,workflowId:j.workflow_id,entityType:'configuration_jobs',entityId:j.id,
    action:'configuration.execution.failure',result:'failed',before:{state:'running',revision:j.revision,executionId:e.id,executionState:e.state,executionRevision:e.revision},
    after:{state:'failed',revision:j.revision+1,executionId:e.id,executionRevision:e.revision+1,completedSteps:0,unresolvedSteps:0,initializationFailed:true,errorCode:code,
     claimId:o.claim_id,wrapperOriginId:o.id,configurationOriginId:c.id},scopeHints:metadataAuditScope('snapshots','configuration_jobs',j.id,j.workspace_id)},tx);
   return Object.freeze({jobId:j.id,executionId:e.id,state:'failed',terminalFailureRecorded:true,initializationFailed:true,completedSteps:0,unresolvedSteps:0,nativeRequestsSent:0});
  });
 }
 /** Consume before the first await. SQL/COMMIT uncertainty cannot re-arm or
  * replay this run's failure transaction with a replacement identity. */
 async recordFailure(handle:ConfigurationFailureHandle,error:unknown):Promise<Readonly<Record<string,unknown>>>{
  const identity=this.handles.get(handle);if(!identity)throw refused();this.handles.delete(handle);
  return this.db.transaction(tx=>this.record(tx,identity,safeConfigurationError(error),false));
 }
 private exact(a:any,i:Identity):void{
  this.scope(a);
  const actual=this.identity(a,i.requestId,i.ip);
  for(const k of['clusterId','workspaceId','jobId','executionId','planId','planRevision','planHash','actorId','sessionId','leaseGeneration','leaseOwnerHash','claimHash',
   'workflowId','workflowExecutionId','jobRevision','executionRevision','permissionVersion','transportScope']as const)if(actual[k]!==i[k])throw conflict();
 }
 private validateOperation(s:any,i:Identity,approval:boolean):void{
  if(s.state==='succeeded'&&(!s.receipt_present||!CONFIGURATION_HEX.test(s.after_hmac??'')||!s.receipt_operation_id))throw refused('CONFIGURATION_FAILURE_RECEIPT_INVALID');
  if(!s.native_operation_id){if(s.operation_id||s.receipt_operation_id)throw refused('CONFIGURATION_FAILURE_RECEIPT_INVALID');return;}
  const append=s.entity_type==='targets'&&s.mutation_action==='update'&&s.remote_completed===true;
  const entityId=s.mutation_action==='create'||append?s.allocated_native_id:s.native_id;
  if(s.native_entity_id!==entityId||s.native_cluster_id!==i.clusterId||s.native_workspace_id!==s.object_workspace_id||s.native_actor_id!==i.actorId||s.native_transport_scope!==i.transportScope
   ||s.native_entity_type!==s.entity_type||s.native_action!==s.mutation_action||(s.native_parent_id??null)!==(s.parent_id??null)
   ||(s.native_credential_kind??null)!==(s.credential_kind??null)||s.native_key!==`configuration-${i.jobId}-${s.id}`
   ||s.receipt_operation_id&&s.receipt_operation_id!==s.native_operation_id)throw refused('CONFIGURATION_FAILURE_RECEIPT_INVALID');
  const v1=['workflow_execution_id','workflow_step_id','workflow_plan_revision','workflow_plan_hash'];
  if(approval){if(s.native_workflow_id!==i.workflowId||s.operation_id!==s.native_operation_id||s.configuration_job_id!==i.jobId||s.configuration_execution_id!==i.executionId
   ||s.configuration_step_id!==s.id||s.configuration_plan_revision!==i.planRevision||s.configuration_plan_hash!==i.planHash||v1.some(k=>s[k]!=null))throw refused('CONFIGURATION_FAILURE_RECEIPT_INVALID');}
  else if(s.native_workflow_id!==null||s.operation_id!==null||[...v1,'configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(k=>s[k]!=null))throw refused('CONFIGURATION_FAILURE_RECEIPT_INVALID');
  if(s.state==='succeeded'&&(s.native_state!=='succeeded'||s.remote_started!==true||s.remote_completed!==true||s.native_result_present!==true))throw refused('CONFIGURATION_FAILURE_RECEIPT_INVALID');
 }
 private async record(tx:DbService,i:Identity,errorCode:string,abandon:boolean):Promise<Readonly<Record<string,unknown>>>{
  const a=await tx.one<any>(CONFIGURATION_FAILURE_ANCHOR_QUERY,[i.clusterId,i.workspaceId,i.jobId,i.executionId,i.workflowExecutionId]);this.exact(a,i);
  if(i.scheduledOrigin){const facts=await this.scheduledFacts(tx,a);
   if(abandon||a.execution_mode!=='approval'||a.workflow_request_id!==null||i.requestId!==undefined||facts.wrapper_origin.id!==i.scheduledOrigin.wrapperOriginId
    ||facts.configuration_origin.id!==i.scheduledOrigin.configurationOriginId||facts.wrapper_origin.claim_id!==i.scheduledOrigin.claimId
    ||facts.configuration_origin.claim_id!==i.scheduledOrigin.claimId||this.secrets.fingerprint(facts)!==i.scheduledOrigin.factsHmac)throw conflict();}
  const steps=await tx.query<any>(CONFIGURATION_FAILURE_STEPS_QUERY,[i.clusterId,i.workspaceId,i.jobId,i.executionId,i.planId,i.planRevision,i.planHash,i.actorId]);
  if(steps.length!==a.step_count||steps.some((s,n)=>s.step_order!==n+1))throw refused('CONFIGURATION_FAILURE_DAG_INVALID');
  for(const s of steps)this.validateOperation(s,i,a.execution_mode==='approval');
  let unresolved=0,completed=0;
  for(const s of steps){if(s.state==='succeeded'){completed++;continue;}if(!['pending','running'].includes(s.state)){if(s.state==='uncertain')unresolved++;continue;}
   const next=abandon||s.state==='running'&&(s.remote_started!==false||s.remote_completed!==false||s.fence_count>0)?'uncertain':'failed';
   if(next==='uncertain')unresolved++;
   if(await tx.exec(CONFIGURATION_FAILURE_STEP_CAS,[i.clusterId,i.workspaceId,i.jobId,i.executionId,i.planId,i.planRevision,i.planHash,s.id,s.revision,next,
    s.state==='pending'&&!abandon?'CONFIGURATION_NOT_STARTED':errorCode])!==1)throw conflict();
  }
  const state=abandon||unresolved?'uncertain':completed?'partial':'failed';
  const progress={...a.safe_progress,executionId:i.executionId,executionRevision:i.executionRevision+1,planRevision:i.planRevision,planHash:i.planHash,
   leaseGeneration:i.leaseGeneration,workflowExecutionId:i.workflowExecutionId,completedSteps:completed,unresolvedSteps:unresolved,terminalFailureRecorded:true,
   ...(abandon?{abandoned:true,abandonRequestId:i.requestId}:{})};
  if(await tx.exec(CONFIGURATION_FAILURE_JOB_CAS,[...this.args(i),i.jobRevision,state,JSON.stringify(this.secrets.redact(progress)),errorCode,i.leaseOwnerHash,i.claimHash])!==1)throw conflict();
  if(await tx.exec(CONFIGURATION_FAILURE_EXECUTION_CAS,[...this.args(i),i.executionRevision,state,i.leaseOwnerHash,i.claimHash])!==1)throw conflict();
  const before={jobId:i.jobId,executionId:i.executionId,state:a.job_state,revision:i.jobRevision,executionRevision:i.executionRevision};
  const after={...before,state,revision:i.jobRevision+1,executionRevision:i.executionRevision+1,completedSteps:completed,unresolvedSteps:unresolved,
   planRevision:i.planRevision,planHash:i.planHash,leaseGeneration:i.leaseGeneration,errorCode,abandoned:abandon};
  await this.audit.append({actorId:i.actorId,clusterId:i.clusterId,workspaceId:i.workspaceId,workflowId:i.workflowId,
   entityType:'configuration_jobs',entityId:i.jobId,action:abandon?'configuration.execution.abandon':'configuration.execution.failure',before,after,
   ...(i.requestId!==undefined?{requestId:i.requestId}:{}),ip:i.ip,result:state==='uncertain'?'uncertain':'failed',scopeHints:metadataAuditScope('snapshots','configuration_jobs',i.jobId,i.workspaceId)},tx);
  return Object.freeze({jobId:i.jobId,executionId:i.executionId,clusterId:i.clusterId,workspaceId:i.workspaceId,state,completedSteps:completed,unresolvedSteps:unresolved,
   terminalFailureRecorded:true,abandoned:abandon,originalWorkflowUnchanged:true,originalNativeReceiptsUnchanged:true});
 }
 async abandon(cid:string,jobId:string,value:Record<string,unknown>,actor:EntityActor):Promise<Readonly<Record<string,unknown>>>{
  const v=configurationObject(value,['revision','executionId','executionRevision','planRevision','planHash','leaseGeneration','workflowExecutionId','confirmed','confirm_name']);
  cid=configurationId(cid);jobId=configurationId(jobId);const executionId=configurationId(v.executionId),wid=configurationId(actor.workspaceId);
  configurationConfirm(v,`abandon:${jobId}`);configurationKey(actor.idempotencyKey);
  if(![v.revision,v.executionRevision,v.planRevision,v.leaseGeneration].every(integer)||!CONFIGURATION_HEX.test(v.planHash??''))throw refused();
  const workflowExecutionId=v.workflowExecutionId===null?null:configurationId(v.workflowExecutionId),frame=this.context.current();
  if(frame.actor?.id!==actor.user.id||!frame.sessionId||frame.clusterId!==cid||frame.workspaceId!==wid||!frame.requestId)throw refused();
  const originalRequestId=frame.requestId,originalIp=frame.ip,originalSid=frame.sessionId;
  const version=await this.authz.permissionVersion(actor.user);await this.authz.assertWholeWorkspace(actor.user,cid,wid,'snapshots','write');
  return this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
   const a=await tx.one<any>(CONFIGURATION_FAILURE_ANCHOR_QUERY,[cid,wid,jobId,executionId,workflowExecutionId]);this.scope(a);
   const current=await tx.one(CONFIGURATION_ABANDON_CURRENT_IDENTITY_QUERY,[actor.user.id,originalSid,cid,wid,a.credential_epoch]);if(!current)throw refused();
   if(a.actor_id!==actor.user.id||a.origin_session_id!==originalSid||a.job_revision!==v.revision||a.execution_revision!==v.executionRevision
    ||a.plan_revision!==v.planRevision||a.plan_hash!==v.planHash||a.lease_generation!==v.leaseGeneration||!a.lease_until
    ||!Number.isFinite(Date.parse(a.lease_until))||Date.parse(a.lease_until)+6000>Date.now()
    ||a.execution_mode==='approval'&&(!['failed','uncertain'].includes(a.workflow_state)||!['failed','uncertain'].includes(a.workflow_execution_state)))throw refused('CONFIGURATION_ABANDON_NOT_AVAILABLE');
   if(a.execution_mode==='approval')await this.authz.assertWholeWorkspace(actor.user,cid,wid,'workflows','write');
   if(await this.authz.permissionVersion(actor.user)!==version)throw refused('CONFIGURATION_ABANDON_AUTHORITY_CHANGED');
   return this.record(tx,this.identity(a,originalRequestId,originalIp),'CONFIGURATION_ABANDONED_UNRESOLVED',true);
  });
 }
 /** Current read-only discovery for UI confirmation. This is deliberately not
  * a capability: abandon re-reads all facts, locks epoch, and applies strict CAS. */
 async abandonmentIntent(handle:ConfigurationAccessHandle,jobId:string):Promise<Readonly<Record<string,unknown>>|null>{
  const current=await this.access.description(handle),frame=this.context.current();jobId=configurationId(jobId);
  if(!frame.actor||!frame.sessionId||frame.actor.id!==current.actor.id||frame.sessionId!==current.sessionId
   ||frame.clusterId!==current.scope.clusterId||frame.workspaceId!==current.scope.workspaceId)return null;
  if(!await this.authz.hasWholeWorkspace(frame.actor,current.scope.clusterId,current.scope.workspaceId,'snapshots','write'))return null;
  const refs=await this.db.query<any>(CONFIGURATION_ABANDON_EXECUTION_REFERENCE_QUERY,[current.scope.clusterId,current.scope.workspaceId,jobId,frame.actor.id]);
  if(refs.length!==1)return null;
  const a=await this.db.one<any>(CONFIGURATION_FAILURE_ANCHOR_QUERY.replace('FOR UPDATE OF j,e',''),[current.scope.clusterId,current.scope.workspaceId,jobId,refs[0].execution_id,refs[0].workflow_execution_id]);
  try{this.scope(a);}catch{return null;}
  if(a.origin_session_id!==frame.sessionId||a.actor_id!==frame.actor.id||!a.lease_until||!Number.isFinite(Date.parse(a.lease_until))
   ||Date.parse(a.lease_until)+6000>Date.now()||a.execution_mode==='approval'&&(!['failed','uncertain'].includes(a.workflow_state)
    ||!['failed','uncertain'].includes(a.workflow_execution_state)||!await this.authz.hasWholeWorkspace(frame.actor,a.cluster_id,a.workspace_id,'workflows','write')))return null;
  if(!await this.db.one(CONFIGURATION_ABANDON_CURRENT_IDENTITY_QUERY.replace('FOR SHARE OF u,s,c,w',''),[frame.actor.id,frame.sessionId,a.cluster_id,a.workspace_id,a.credential_epoch]))return null;
  return Object.freeze({jobId,revision:a.job_revision,executionId:a.execution_id,executionRevision:a.execution_revision,
   planRevision:a.plan_revision,planHash:a.plan_hash,leaseGeneration:a.lease_generation,workflowExecutionId:a.workflow_execution_id,confirmationName:`abandon:${jobId}`});
 }
}
