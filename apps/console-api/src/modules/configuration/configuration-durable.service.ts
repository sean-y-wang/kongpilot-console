import { ConflictException, ForbiddenException, Injectable, OnModuleInit } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { normalizeWorkflowApprovalPolicy } from '../workflows/workflow-approval-policy';
import type { WorkflowPlanV1 } from '../workflows/workflow.types';
import type { EntityActor } from '../entities/entities.types';
import { ConfigurationAccessService } from './configuration-access.service';
import { ConfigurationDurableRepository, configurationDurableMarker } from './configuration-durable.repository';
import { CONFIGURATION_DURABLE_DOMAIN, type DurableConfigurationEnvelope } from './configuration-durable.types';
import {assertDurableConfigurationEquivalent} from './configuration-durable-equivalence';
import {ConfigurationDurableRejectionRepository,DURABLE_REJECTION_KIND,DURABLE_REJECTION_CODE,DURABLE_REJECTION_CONFLICT_QUERY,durableRejectionProjection,type DurableConfigurationRejectionFact} from './configuration-durable-rejection';
import type { CaptureGraph, ConfigPlan, ConfigurationAccessHandle, ConfigurationPlanIdentity } from './configuration.types';
import { configurationTargetAppendPacketIncomplete } from './configuration-target-append-packet';

const denied=(code='CONFIGURATION_DURABLE_ADMISSION_INVALID')=>new ForbiddenException({code});
const conflict=(code:string)=>new ConflictException({code});
const iso=(v:any)=>new Date(v).toISOString();
interface Admission {active:boolean;used:boolean;handle:ConfigurationAccessHandle;frame:object;actor:EntityActor;scope:any;
 issueId:string;jobId:string;key:string;source:any;sourcePlan:ConfigPlan;sourceKind:'import'|'rollback';proof:any;
 definition:{id:string;version:number;policyHash:string};ttl:number;issuedAt:string;expiresAt:string;admissionExpiresAt:number;requestHmac:string;}
export type DurableAdmissionHandle=Readonly<object>;
export interface ConfigurationDurablePublicationWriter {
 persist(tx:DbService,input:Readonly<{handle:ConfigurationAccessHandle;jobId:string;issueId:string;sourcePlanId:string;expiresAt:string;plan:ConfigPlan;baseline:CaptureGraph;actor:EntityActor}>):
  Promise<{identity:ConfigurationPlanIdentity;workflow:WorkflowPlanV1}>;
 recordRejection?(tx:DbService,fact:DurableConfigurationRejectionFact):Promise<void>;
}
/** Independent durable issuance. The short current HTTP proof is never made
 * longer, and no old job/plan/claim/deadline is changed or adopted. */
@Injectable()
export class ConfigurationDurableService implements OnModuleInit {
 private readonly handles=new WeakMap<object,Admission>();
 private readonly rejections:ConfigurationDurableRejectionRepository;
 private writer?:Readonly<ConfigurationDurablePublicationWriter>;
 installPublicationWriter(writer:ConfigurationDurablePublicationWriter):void{
   if(this.writer||!writer||typeof writer.persist!=='function'||writer.recordRejection!==undefined&&typeof writer.recordRejection!=='function')throw denied('CONFIGURATION_DURABLE_WRITER_ALREADY_INSTALLED');
   this.writer=Object.freeze({persist:writer.persist.bind(writer),...(writer.recordRejection?{recordRejection:writer.recordRejection.bind(writer)}:{})});
 }
 private readonly publishing=new AsyncLocalStorage<{a:Admission;tx:DbService;handle:ConfigurationAccessHandle}>();
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly context:KongExecutionContextService,
  private readonly access:ConfigurationAccessService,private readonly repository:ConfigurationDurableRepository,private readonly redis:RedisService){this.rejections=new ConfigurationDurableRejectionRepository(secrets);}
 onModuleInit():void{this.access.installDurableConfigurationPolicy({verifyJob:async(handle,row,phase,tx)=>{
  const issueId=configurationDurableMarker(row);if(!issueId)return;
  const active=this.publishing.getStore();
  if(active?.handle===handle&&active.tx===tx&&active.a.jobId===row.id&&active.a.issueId===issueId){
   this.live(active.a);if(!['read','plan','step','ledger'].includes(phase)||this.context.current().operation)throw denied();
   await this.repository.issue(row,tx);return;
  }
  await this.repository.verify(row,tx,!['read','receipt'].includes(phase));
 },verifyPlan:async(handle,row,plan,tx)=>{
   const active=this.publishing.getStore();
   if(active?.handle===handle&&active.tx===tx&&active.a.jobId===row.source_job_id){
    this.live(active.a);if(plan.originRef!==undefined||plan.durableRef?.issueId!==active.a.issueId||plan.durableRef.domain!==CONFIGURATION_DURABLE_DOMAIN
     ||plan.expiresAt!==active.a.expiresAt)throw denied();return;
   }
   const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[row.source_job_id,row.cluster_id,row.workspace_id]);
   if(!job)throw denied();await this.repository.verify(job,tx,false,plan);
  }});}
 private live(a:Admission):void{
  if(!a.active||a.admissionExpiresAt<=Date.now()||this.context.current()!==a.frame||this.context.current().sessionId!==a.proof.sessionId
   ||this.context.current().actor?.id!==a.actor.user.id)throw denied();
 }
 private state(handle:DurableAdmissionHandle):Admission{const a=this.handles.get(handle);if(!a)throw denied();this.live(a);return a;}
 /** Target weight updates append a new Kong 1.5 physical row (POST + fresh
  * allocatedNativeId). Transfer DAG, approved configuration verifier,
  * mutation entity_id rebinding and scheduled-configuration before-read already
  * support that shape. Admission and business-schedule gates share the same
  * fail-closed packet check; incomplete seals stay closed before publication. */
 unsupportedReason(plan:ConfigPlan):Readonly<{code:string;message:string}>|null{
  for(const step of plan.steps){
   if(configurationTargetAppendPacketIncomplete(step)){
    return Object.freeze({code:'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED',message:'当前配置的 Target 权重变更封存包不完整，暂不能创建配置工单'});
   }
  }
  return null;
 }
 async assertUnconsumedSource(sourcePlanId:string,cid:string,wid:string,tx:DbService=this.db):Promise<void>{
   const rows=await tx.query<any>(`SELECT id,input_secret FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2
     AND kind IN('apply','rollback') ORDER BY created_at,id LIMIT 5001`,[cid,wid]);
   if(rows.length>5000)throw conflict('CONFIGURATION_DURABLE_SOURCE_HISTORY_BUDGET');
   for(const row of rows){
    if(!row.input_secret)throw denied('CONFIGURATION_DURABLE_SOURCE_HISTORY_INVALID');
    let value:any;try{value=this.secrets.decrypt(row.input_secret,`configuration-job:${row.id}`);}catch{throw denied('CONFIGURATION_DURABLE_SOURCE_HISTORY_INVALID');}
    if(value?.planId===sourcePlanId||value?.sourcePlanId===sourcePlanId)throw conflict('CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED');
   }
 }
 private async assertNotRejected(sourcePlanId:string,cid:string,wid:string,ownerId:string,key:string,tx:DbService=this.db):Promise<void>{
  if(await tx.one(DURABLE_REJECTION_CONFLICT_QUERY,[sourcePlanId,cid,wid,ownerId,key]))throw conflict('CONFIGURATION_DURABLE_SOURCE_REJECTED');
 }
 async begin(handle:ConfigurationAccessHandle,source:any,sourcePlan:ConfigPlan,actor:EntityActor,key:string):Promise<DurableAdmissionHandle>{
  const unsupported=this.unsupportedReason(sourcePlan);if(unsupported)throw new ConflictException(unsupported);
  const proof=await this.access.assertCurrent(handle,{phase:'read'}),frame=this.context.current();
  await this.assertUnconsumedSource(source.plan_id,source.cluster_id,source.workspace_id);
  if(!frame.sessionId||frame.actor?.id!==actor.user.id||frame.clusterId!==source.cluster_id||frame.workspaceId!=null&&frame.workspaceId!==source.workspace_id
   ||source.actor_id!==actor.user.id||source.origin_session_id!==frame.sessionId||source.origin_type!=='http'||source.state!=='succeeded'
   ||source.authority_domain!=null||source.durable_issue_id!=null||source.required_origin_kind!=null||source.required_origin_id!=null||source.required_origin_hmac!=null
   ||sourcePlan.originRef!==undefined||sourcePlan.durableRef!==undefined||sourcePlan.expiresAt<=new Date().toISOString()
   ||this.secrets.fingerprint(sourcePlan)!==source.plan_hash||new Date(source.authority_expires_at).getTime()<=Date.now()
   ||new Date(source.expires_at).getTime()<=Date.now()||!['import','compare'].includes(source.kind))throw denied('CONFIGURATION_DURABLE_SOURCE_UNAVAILABLE');
  const input=source.input_secret?this.secrets.decrypt<any>(source.input_secret,`configuration-job:${source.id}`):null;
  const sourceKind=source.kind==='import'&&input?.documentHmac?'import':source.kind==='compare'&&input?.action==='rollback-preview'?'rollback':null;
  if(!sourceKind)throw denied('CONFIGURATION_DURABLE_RECIPE_UNSUPPORTED');
  await this.assertNotRejected(source.plan_id,source.cluster_id,source.workspace_id,actor.user.id,key);
  const definition=await this.db.one<any>(`SELECT v.*,d.kind FROM workflow_definition_versions v JOIN workflow_definitions d
   ON d.id=v.definition_id AND d.cluster_id=v.cluster_id AND d.workspace_id=v.workspace_id AND d.current_version=v.version
   JOIN clusters c ON c.id=d.cluster_id AND c.deleted_at IS NULL AND c.execution_mode='approval' AND c.revision=$3
   WHERE d.cluster_id=$1 AND d.workspace_id=$2 AND d.kind='configuration_v2' AND d.status='active'`,[source.cluster_id,source.workspace_id,proof.clusterRevision]);
  if(!definition||definition.approval_format!==2||this.secrets.fingerprint(definition.policy)!==definition.policy_hash)throw denied('CONFIGURATION_DURABLE_V2_POLICY_REQUIRED');
  const policy=normalizeWorkflowApprovalPolicy(definition.policy,'configuration_v2'),clock=await this.db.one<any>('SELECT clock_timestamp() AS observed_at');
  if(!clock)throw denied();const issuedAt=iso(clock.observed_at),expiresAt=new Date(Date.parse(issuedAt)+policy.intentTtlHours*3600000).toISOString();
  const a:Admission={active:true,used:false,handle,frame,actor:Object.freeze({...actor,user:Object.freeze({...actor.user})}),scope:proof.scope,issueId:randomUUID(),jobId:randomUUID(),key,source:structuredClone(source),
   sourcePlan:structuredClone(sourcePlan),sourceKind,proof,definition:{id:definition.definition_id,version:definition.version,policyHash:definition.policy_hash},
   ttl:policy.intentTtlHours,issuedAt,expiresAt,admissionExpiresAt:Math.min(proof.expiresAt,Date.parse(issuedAt)+300000),
   requestHmac:this.secrets.fingerprint({domain:CONFIGURATION_DURABLE_DOMAIN,sourceJobId:source.id,sourcePlanId:source.plan_id,sourcePlanRevision:source.plan_revision,sourcePlanHash:source.plan_hash})};
  const original=Object.freeze({});this.handles.set(original,a);return original;
 }
 async canSubmit(handle:ConfigurationAccessHandle,source:any,plan:ConfigPlan,actor:EntityActor):Promise<boolean>{
   try{const admission=await this.begin(handle,source,plan,actor,'durable-capability-read');const a=this.handles.get(admission)!;a.active=false;return true;}
   catch(error){if(error instanceof ForbiddenException||error instanceof ConflictException)return false;throw error;}
 }
 describe(handle:DurableAdmissionHandle):Readonly<{issueId:string;jobId:string;issuedAt:string;expiresAt:string;sourceKind:'import'|'rollback'}>{
  const a=this.state(handle);return Object.freeze({issueId:a.issueId,jobId:a.jobId,issuedAt:a.issuedAt,expiresAt:a.expiresAt,sourceKind:a.sourceKind});
 }
 async receipt(sourcePlanId:string,key:string,actor:EntityActor,cid:string,wid:string,revision?:number,hash?:string):Promise<string|null>{
  const row=await this.db.one<any>('SELECT job_id,prepare_key,source_plan_id,source_plan_revision,source_plan_hash FROM configuration_durable_issues WHERE cluster_id=$1 AND workspace_id=$2 AND owner_id=$3 AND(source_plan_id=$4 OR prepare_key=$5)',
   [cid,wid,actor.user.id,sourcePlanId,key]);
  if(!row)return null;if(row.source_plan_id!==sourcePlanId||revision!==undefined&&row.source_plan_revision!==revision||hash!==undefined&&row.source_plan_hash!==hash)throw conflict('IDEMPOTENCY_CONFLICT');if(row.prepare_key!==key)throw conflict('CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED');return row.job_id;
 }
 async publish(original:DurableAdmissionHandle,plan:ConfigPlan,baseline:CaptureGraph,recipeHmac:string):Promise<{jobId:string;workflowId:string}>{
  if(!this.writer)throw denied('CONFIGURATION_DURABLE_WRITER_UNAVAILABLE');
  const unsupported=this.unsupportedReason(plan);if(unsupported)throw new ConflictException(unsupported);
  const a=this.state(original);if(a.used)throw denied('CONFIGURATION_DURABLE_ADMISSION_SPENT');a.used=true;
  if(!plan.recoveryComplete||!plan.steps.length||plan.originRef!==undefined||plan.durableRef?.issueId!==a.issueId
   ||plan.durableRef.domain!==CONFIGURATION_DURABLE_DOMAIN||plan.expiresAt!==a.expiresAt||this.secrets.fingerprint(plan.scope)!==this.secrets.fingerprint(a.scope)
   ||plan.baselineManifestHmac!==this.secrets.fingerprint(baseline)||baseline.completeness!=='complete'||baseline.consistency!=='console_fenced_best_effort'
   ||plan.permissionVersion!==a.proof.permissionVersion||plan.schemaHmac!==baseline.schemaHmac||baseline.jobId===a.source.id
   ||plan.sourceManifestHmac!==recipeHmac||this.secrets.fingerprint(baseline.scope)!==this.secrets.fingerprint(a.scope)
   ||baseline.permissionVersion!==a.proof.permissionVersion||baseline.credentialEpoch!==a.proof.credentialEpoch
   ||baseline.clusterRevision!==plan.clusterRevision||baseline.workspaceRevision!==plan.workspaceRevision
   ||Date.parse(baseline.observedFrom)<Date.parse(a.issuedAt)||Date.parse(baseline.observedUntil)>Date.now())throw denied();
  try{const result=await this.db.transaction(async tx=>this.publishing.run({a,tx,handle:a.handle},async()=>{
   this.live(a);await this.redis.assertLeaseOwnership();this.live(a);
   await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-source-plan:${a.source.plan_id.toLowerCase()}`]);this.live(a);
   await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-durable-command:${a.actor.user.id}:${a.key}`]);this.live(a);
   await this.assertNotRejected(a.source.plan_id,a.scope.clusterId,a.scope.workspaceId,a.actor.user.id,a.key,tx);
   if(await tx.one('SELECT id FROM configuration_jobs WHERE actor_id=$1 AND idempotency_key=$2 LIMIT 1',[a.actor.user.id,a.key]))throw conflict('CONFIGURATION_DURABLE_COMMAND_KEY_IN_USE');
   await this.assertUnconsumedSource(a.source.plan_id,a.scope.clusterId,a.scope.workspaceId,tx);this.live(a);
   const proof=await this.access.assertCurrent(a.handle,{phase:'read'},tx);
   if(proof.permissionVersion!==a.proof.permissionVersion||proof.credentialEpoch!==a.proof.credentialEpoch
    ||proof.clusterRevision!==plan.clusterRevision||proof.workspaceRevision!==plan.workspaceRevision)throw denied();
   const source=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR SHARE',[a.source.id,a.scope.clusterId,a.scope.workspaceId]);
   if(!source||source.state!=='succeeded'||source.plan_id!==a.source.plan_id||source.plan_hash!==a.source.plan_hash
    ||iso(source.authority_expires_at)!==iso(a.source.authority_expires_at)||new Date(source.authority_expires_at).getTime()<=Date.now())throw denied();
   await tx.exec(`INSERT INTO configuration_durable_issues(id,cluster_id,workspace_id,job_id,owner_id,authoring_session_id,credential_epoch,permission_version,
    source_job_id,source_plan_id,source_plan_revision,source_plan_hash,source_kind,prepare_key,request_hmac,issued_at,expires_at,definition_id,definition_version,policy_hash,intent_ttl_hours,admission_expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,[a.issueId,a.scope.clusterId,a.scope.workspaceId,a.jobId,a.actor.user.id,a.proof.sessionId,
    proof.credentialEpoch,proof.permissionVersion,a.source.id,a.source.plan_id,a.source.plan_revision,a.source.plan_hash,a.sourceKind,a.key,a.requestHmac,a.issuedAt,a.expiresAt,
    a.definition.id,a.definition.version,a.definition.policyHash,a.ttl,new Date(a.admissionExpiresAt).toISOString()]);
   const input={durableIssueId:a.issueId,sourcePlanId:a.source.plan_id,sourcePlanRevision:a.source.plan_revision,sourcePlanHash:a.source.plan_hash,confirmed:true,driver:'bff'};
   await tx.exec(`INSERT INTO configuration_jobs(id,cluster_id,workspace_id,transport_scope,actor_id,origin_session_id,authority_expires_at,kind,idempotency_key,
    request_hmac,request_id,scope_kind,root_ids,input_secret,permission_version,credential_epoch,cluster_revision,workspace_revision,capture_epoch,execution_mode,approval_required,
    expires_at,origin_type,authority_domain,durable_issue_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'approval',true,$7,'http',$20,$21)`,
    [a.jobId,a.scope.clusterId,a.scope.workspaceId,a.scope.transportScope,a.actor.user.id,a.proof.sessionId,a.expiresAt,a.sourceKind==='rollback'?'rollback':'apply',a.key,
    a.requestHmac,a.actor.requestId??null,a.scope.kind,a.scope.rootIds,
    this.secrets.encrypt(input,`configuration-job:${a.jobId}`),proof.permissionVersion,proof.credentialEpoch,proof.clusterRevision,proof.workspaceRevision,proof.captureEpoch,
    CONFIGURATION_DURABLE_DOMAIN,a.issueId]);
   const stored=await this.writer!.persist(tx,{handle:a.handle,jobId:a.jobId,issueId:a.issueId,sourcePlanId:a.source.plan_id,expiresAt:a.expiresAt,plan,baseline,actor:a.actor});this.live(a);
   const e:DurableConfigurationEnvelope={domain:CONFIGURATION_DURABLE_DOMAIN,envelopeVersion:1,issueId:a.issueId,clusterId:a.scope.clusterId,workspaceId:a.scope.workspaceId,
    jobId:a.jobId,ownerId:a.actor.user.id,authoringSessionId:a.proof.sessionId,credentialEpoch:proof.credentialEpoch,permissionVersion:proof.permissionVersion,
    issuedAt:a.issuedAt,expiresAt:a.expiresAt,admissionExpiresAt:new Date(a.admissionExpiresAt).toISOString(),policy:{definitionId:a.definition.id,version:a.definition.version,hash:a.definition.policyHash,intentTtlHours:a.ttl},
    provenance:{jobId:a.source.id,planId:a.source.plan_id,planRevision:a.source.plan_revision,planHash:a.source.plan_hash,kind:a.sourceKind},
    baseline:{snapshotId:baseline.snapshotId,version:1,manifestHmac:plan.baselineManifestHmac},recipeHmac,schemaHmac:plan.schemaHmac,scopeHmac:this.secrets.fingerprint(plan.scope),
    plan:{planId:stored.identity.planId,planRevision:stored.identity.planRevision,planHash:stored.identity.planHash,stepsHmac:this.secrets.fingerprint(plan.steps),
     sourceManifestHmac:plan.sourceManifestHmac,baselineManifestHmac:plan.baselineManifestHmac}};
   if(stored.workflow.definition.id!==a.definition.id||stored.workflow.definition.version!==a.definition.version||stored.workflow.definition.policyHash!==a.definition.policyHash
    ||stored.workflow.expiresAt!==a.expiresAt)throw denied();
   await this.repository.bind(tx,e,stored.workflow);this.live(a);
   const row=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[a.jobId]);if(!row)throw denied();
   await this.repository.verify(row,tx,true,plan);this.live(a);
   const closing=await this.access.assertCurrent(a.handle,{phase:'read'},tx);this.live(a);
   if(closing.permissionVersion!==proof.permissionVersion||closing.credentialEpoch!==proof.credentialEpoch||closing.clusterRevision!==proof.clusterRevision||closing.workspaceRevision!==proof.workspaceRevision)throw denied();
   await this.redis.assertLeaseOwnership();this.live(a);
   return{jobId:a.jobId,workflowId:stored.workflow.workflowId};
  }));this.live(a);await this.redis.assertLeaseOwnership();this.live(a);return result;}finally{a.active=false;}
 }
 async rejectionReceipt(key:string,actor:EntityActor,cid:string,wid:string):Promise<Readonly<{receipt:Readonly<Record<string,unknown>>;fact:DurableConfigurationRejectionFact;scopeKind:string;rootIds:string[];transportScope:string}>|null>{
  const frame=this.context.current();if(frame.actor?.id!==actor.user.id||frame.clusterId!==cid||frame.workspaceId!=null&&frame.workspaceId!==wid)throw denied();
  const stored=await this.rejections.read(this.db,cid,wid,actor.user.id,key);if(!stored)return null;
  return Object.freeze({...stored,receipt:durableRejectionProjection(stored.fact)});
 }
 /** Only the actual fresh compiler's typed semantic mismatch reaches this
  * method with a genuine original admission. Generic HTTP errors never do. */
 async rejectFreshDiff(original:DurableAdmissionHandle,plan:ConfigPlan,baseline:CaptureGraph,recipeHmac:string):Promise<Readonly<Record<string,unknown>>>{
  if(!this.writer?.recordRejection)throw denied('CONFIGURATION_DURABLE_REJECTION_AUDIT_UNAVAILABLE');
  const a=this.state(original);if(a.used)throw denied('CONFIGURATION_DURABLE_ADMISSION_SPENT');
  if(!plan.recoveryComplete||!plan.steps.length||plan.originRef!==undefined||plan.durableRef?.issueId!==a.issueId||plan.durableRef.domain!==CONFIGURATION_DURABLE_DOMAIN
   ||plan.expiresAt!==a.expiresAt||plan.sourceManifestHmac!==recipeHmac||plan.baselineManifestHmac!==this.secrets.fingerprint(baseline)||plan.schemaHmac!==baseline.schemaHmac
   ||this.secrets.fingerprint(plan.scope)!==this.secrets.fingerprint(a.scope)||this.secrets.fingerprint(baseline.scope)!==this.secrets.fingerprint(a.scope)
   ||baseline.jobId===a.source.id||baseline.completeness!=='complete'||baseline.consistency!=='console_fenced_best_effort'||baseline.permissionVersion!==a.proof.permissionVersion
   ||baseline.credentialEpoch!==a.proof.credentialEpoch||baseline.clusterRevision!==plan.clusterRevision||baseline.workspaceRevision!==plan.workspaceRevision
   ||Date.parse(baseline.observedFrom)<Date.parse(a.issuedAt)||Date.parse(baseline.observedUntil)>Date.now())throw denied();
  let changed=false;try{assertDurableConfigurationEquivalent(a.sourcePlan,plan,this.secrets);}catch(error){
   if(error instanceof ConflictException&&(error.getResponse()as any)?.code===DURABLE_REJECTION_CODE)changed=true;else throw error;
  }
  if(!changed)throw denied('CONFIGURATION_DURABLE_REJECTION_NOT_PROVEN');a.used=true;
  try{const fact=await this.db.transaction(async tx=>{
   this.live(a);await this.redis.assertLeaseOwnership();this.live(a);
   await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-source-plan:${a.source.plan_id.toLowerCase()}`]);this.live(a);
   await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-durable-command:${a.actor.user.id}:${a.key}`]);this.live(a);
   await this.assertNotRejected(a.source.plan_id,a.scope.clusterId,a.scope.workspaceId,a.actor.user.id,a.key,tx);
   if(await tx.one('SELECT id FROM configuration_jobs WHERE actor_id=$1 AND idempotency_key=$2 LIMIT 1',[a.actor.user.id,a.key]))throw conflict('CONFIGURATION_DURABLE_COMMAND_KEY_IN_USE');
   if(await tx.one('SELECT id FROM configuration_durable_issues WHERE(source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3) OR(owner_id=$4 AND prepare_key=$5)',[a.source.plan_id,a.scope.clusterId,a.scope.workspaceId,a.actor.user.id,a.key]))throw conflict('CONFIGURATION_DURABLE_REGISTRATION_EXISTS');
   await this.assertUnconsumedSource(a.source.plan_id,a.scope.clusterId,a.scope.workspaceId,tx);this.live(a);
   const proof=await this.access.assertCurrent(a.handle,{phase:'read'},tx);this.live(a);
   if(proof.permissionVersion!==a.proof.permissionVersion||proof.credentialEpoch!==a.proof.credentialEpoch||proof.clusterRevision!==plan.clusterRevision||proof.workspaceRevision!==plan.workspaceRevision)throw denied();
   const clock=await tx.one<any>('SELECT clock_timestamp() AS observed_at');this.live(a);if(!clock)throw denied();
   const value:DurableConfigurationRejectionFact={domain:DURABLE_REJECTION_KIND,effectScope:'durable-registration',code:DURABLE_REJECTION_CODE,
    id:randomUUID(),clusterId:a.scope.clusterId,workspaceId:a.scope.workspaceId,ownerId:a.actor.user.id,authoringSessionId:a.proof.sessionId,
    credentialEpoch:proof.credentialEpoch,permissionVersion:proof.permissionVersion,sourceJobId:a.source.id,sourcePlanId:a.source.plan_id,
    sourcePlanRevision:a.source.plan_revision,sourcePlanHash:a.source.plan_hash,sourceKind:a.sourceKind,idempotencyKey:a.key,requestHmac:a.requestHmac,
    admissionIssuedAt:a.issuedAt,admissionExpiresAt:new Date(a.admissionExpiresAt).toISOString(),rejectedAt:iso(clock.observed_at),freshPlanHmac:this.secrets.fingerprint(plan),
    baselineSnapshotId:baseline.snapshotId,baselineVersion:1,baselineManifestHmac:plan.baselineManifestHmac};
   await this.rejections.insert(tx,value);this.live(a);
   const stored=await this.rejections.read(tx,a.scope.clusterId,a.scope.workspaceId,a.actor.user.id,a.key);this.live(a);
   if(!stored||this.secrets.fingerprint(stored.fact)!==this.secrets.fingerprint(value))throw denied();
   await this.writer!.recordRejection!(tx,stored.fact);this.live(a);
   const close=await this.access.assertCurrent(a.handle,{phase:'read'},tx);this.live(a);
   if(close.permissionVersion!==proof.permissionVersion||close.credentialEpoch!==proof.credentialEpoch||close.clusterRevision!==proof.clusterRevision||close.workspaceRevision!==proof.workspaceRevision)throw denied();
   await this.redis.assertLeaseOwnership();this.live(a);return stored.fact;
  });this.live(a);await this.redis.assertLeaseOwnership();this.live(a);return durableRejectionProjection(fact);}finally{a.active=false;}
 }
 async scheduledProposal(plan:WorkflowPlanV1,base:WorkflowPlanV1,tx:DbService):Promise<void>{await this.repository.verifyScheduledProposal(plan,base,tx);}
 async workflow(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
   const active=this.publishing.getStore();
   if(active?.tx===tx&&plan.subject.id===active.a.jobId){
    this.live(active.a);const m=plan.steps[0]?.metadata as any;
    if(plan.kind!=='configuration_v2'||plan.requester.type!=='console'||plan.requester.id!==active.a.actor.user.id
     ||plan.expiresAt!==active.a.expiresAt||plan.definition.id!==active.a.definition.id||plan.definition.version!==active.a.definition.version
     ||plan.definition.policyHash!==active.a.definition.policyHash||m?.jobId!==active.a.jobId)throw denied();
    const row=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[active.a.jobId]);
    if(!row||row.plan_id!==m.planId||row.plan_revision!==m.planRevision||row.plan_hash!==m.planHash)throw denied();return;
   }
   return this.repository.verifyWorkflow(plan,tx);
 }
}
