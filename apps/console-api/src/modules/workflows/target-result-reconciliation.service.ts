import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import {ConflictException,ForbiddenException,Injectable,ServiceUnavailableException} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService,type KongExecutionFrame} from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {disabledTargetReadback} from '../../infrastructure/kong/disabled-target-readback';
import {AuthorizationService} from '../authorization/authorization.service';
import {AuditService} from '../audit/audit.service';
import {EntityChangeBoundaryService} from '../entities/entity-change-boundary.service';
import type {EntityActor} from '../entities/entities.types';
import {portalConfirm,portalObject,portalRevision,requirePortalCas} from '../portal/portal-input';
import {WorkflowPlansService} from './workflow-plans.service';
import {EntityChangeIntentsService} from './entity-change-intents.service';
import {decodeEntityExecutionSource} from './entity-change-source-codec';
import {assertEntityChangeWorkflowPlan,entityChangeIntentAad} from './entity-change-workflow';
import {workflowId,workflowKey} from './workflow-validation';
import type {WorkflowPlanV1} from './workflow.types';
import type {EntityChangeIntentEnvelopeV1,EntityChangeExecutionSource} from './entity-change-intent.types';
import {certifyTargetReconciliationHistory,authenticateTargetResultObservation,targetResultObservationBinding,targetResultObservationAad,type TargetReconciliationHistoryCertificate} from './entity-change-target-reconciliation-proof';
import {TARGET_APPEND_RESPONSE_CONTRACT,type TargetOriginalProducerAttestation} from './entity-change-target-producer-contract';

export interface TargetResultReconciliationBridge{
 assertNoActiveSource(sourceId:string):Promise<void>;
 attestProducer(certificate:Readonly<TargetReconciliationHistoryCertificate>):Promise<Readonly<TargetOriginalProducerAttestation>>;
}
export interface TargetResultHistoricalObservation{
 readonly id:string;readonly auditId:string;readonly eventHash:string;readonly observedAt:string;
 readonly kind:'target-weight-zero-original-response-v1';readonly nativeRequestsSent:0;readonly originalNativeStatus:null;
 readonly workflowStepId:string;readonly operationId:string;readonly operationState:'succeeded';
}
const hex=/^[a-f\d]{64}$/,deny=(code='ENTITY_CHANGE_TARGET_RECONCILIATION_ACTOR_REQUIRED')=>new ForbiddenException({code}),changed=(code='ENTITY_CHANGE_TARGET_RECONCILIATION_CHANGED')=>new ConflictException({code});
/** Metadata-only closure of the original, already observed Target response.
 * Root must explicitly install the bridge and exact applied SQL027 checksum.
 * This provider creates no native Source/claim/packet/lease/retry. Its only Kong
 * requests are genuine scoped GETs of parent/history/effective collections. */
@Injectable()
export class TargetResultReconciliationService{
 private bridge?:Readonly<TargetResultReconciliationBridge>;private checksum?:string;
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly context:KongExecutionContextService,private readonly kong:KongService,private readonly authz:AuthorizationService,
  private readonly audit:AuditService,private readonly plans:WorkflowPlansService,private readonly intents:EntityChangeIntentsService,private readonly boundary:EntityChangeBoundaryService){}
 installFixedBridge(bridge:TargetResultReconciliationBridge,storageChecksum:string):void{
  if(this.bridge||!bridge||typeof bridge.assertNoActiveSource!=='function'||typeof bridge.attestProducer!=='function'||!hex.test(storageChecksum))throw changed('ENTITY_CHANGE_TARGET_RECONCILIATION_BRIDGE_INVALID');
  this.bridge=Object.freeze({assertNoActiveSource:bridge.assertNoActiveSource.bind(bridge),attestProducer:bridge.attestProducer.bind(bridge)});this.checksum=storageChecksum;
 }
 private policy(){if(!this.bridge)throw new ServiceUnavailableException({code:'ENTITY_CHANGE_TARGET_RECONCILIATION_UNAVAILABLE'});return this.bridge;}
 private same(a:unknown,b:unknown){if(this.secrets.fingerprint(a)!==this.secrets.fingerprint(b))throw changed();}
 private actor(plan:WorkflowPlanV1,actor:EntityActor,key:string,frame=this.context.current()):KongExecutionFrame{
  if(frame.kind!=='actor'||frame.module!=='workflows'||frame.action!=='write'||frame.operation||frame.archive||frame.purpose||!frame.sessionId
   ||frame.actor?.id!==actor.user.id||this.secrets.fingerprint(frame.actor)!==this.secrets.fingerprint(actor.user)||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId
   ||actor.workspaceId!==plan.workspaceId||frame.idempotencyKey!==key)throw deny();return frame;
 }
 private scopeHints(plan:WorkflowPlanV1){return{quality:'verified' as const,module:'workflows',subject:{type:'workflows',id:plan.workflowId},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:plan.workspaceId,afterWorkspaceId:plan.workspaceId};}
 private async currentAuthority(plan:WorkflowPlanV1,envelope:EntityChangeIntentEnvelopeV1,source:EntityChangeExecutionSource,actor:EntityActor,frame:KongExecutionFrame,actorHmac:string,tx:DbService,capabilityOnly=false):Promise<string>{
  if(this.context.current()!==frame||this.secrets.fingerprint(actor)!==actorHmac)throw deny();if(!capabilityOnly)this.actor(plan,actor,workflowKey(actor.idempotencyKey),frame);
  const session=await tx.one<any>(`SELECT s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
   WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
   AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u`,[frame.sessionId,actor.user.id]);
  if(!session||String(session.credential_epoch)!==source.credentialEpoch||String(session.user_epoch)!==source.credentialEpoch)throw deny('ENTITY_CHANGE_SESSION_REVOKED');
  const permissionVersion=await this.authz.permissionVersion(actor.user,tx);if(this.secrets.fingerprint(permissionVersion)!==source.permissionVersionHmac)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
  const cluster=await tx.one<any>('SELECT revision,execution_mode,admin_url,transport_scope,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[plan.clusterId]),workspace=await tx.one<any>("SELECT revision,status FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL FOR SHARE",[plan.workspaceId,plan.clusterId]);
  if(!cluster||cluster.revision!==plan.scope.clusterRevision||cluster.execution_mode!==plan.executionMode||!isSupportedKong(cluster.version??'')||['disabled','incompatible'].includes(cluster.status)
   ||!workspace||workspace.revision!==plan.scope.workspaceRevision||workspace.status!=='active'||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==plan.scope.transportScope)throw changed('ENTITY_CHANGE_EXECUTION_SCOPE_CHANGED');
  await this.intents.assertSubject(plan,actor.user.id,'write',tx);await this.boundary.assertStoredSubject({material:envelope.prepared,actor,action:'write',mode:'historical'},tx);
  if(await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');await this.policy().assertNoActiveSource(source.id);if(!capabilityOnly)await this.redis.assertLeaseOwnership();return permissionVersion;
 }
 private async producer(certificate:Readonly<TargetReconciliationHistoryCertificate>):Promise<Readonly<TargetOriginalProducerAttestation>>{
  const value=immutableJson(await this.policy().attestProducer(certificate)),{evidenceHmac,...body}=value;
  if(value.version!==1||value.contract!==TARGET_APPEND_RESPONSE_CONTRACT||value.producerProtocol!=='http-source-v1/entity-mutation-v3/packet-fact-v1'||value.nativeStatusInferred!==201
   ||value.sourceId!==certificate.sourceId||value.sourceHmac!==certificate.sourceHmac||value.outcomeFactHmac!==certificate.outcomeFactHmac||value.resultHmac!==certificate.resultHmac||this.secrets.fingerprint(body)!==evidenceHmac)throw changed('ENTITY_CHANGE_TARGET_PRODUCER_CONTRACT_INVALID');
  return value;
 }
 /** Detail-page capability only. It creates no observations, execution key,
  * locks, native handle or permission; the confirmed POST repeats all checks. */
 async canReconcile(plan:WorkflowPlanV1,actor:EntityActor):Promise<boolean>{
  if(!this.bridge)return false;
  try{const frame=this.context.current(),actorHmac=this.secrets.fingerprint(actor),hash=this.secrets.fingerprint(plan);assertEntityChangeWorkflowPlan(plan);
   if(frame.kind!=='actor'||frame.module!=='workflows'||!['read','write'].includes(frame.action??'')||frame.operation||frame.archive||frame.purpose||!frame.sessionId||frame.actor?.id!==actor.user.id
    ||this.secrets.fingerprint(frame.actor)!==this.secrets.fingerprint(actor.user)||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId||actor.workspaceId!==plan.workspaceId)return false;
   return await this.db.transaction(async tx=>{const ledger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='027_m11_target_result_observations.sql'");if(!ledger||ledger.checksum!==this.checksum)return false;
    const row=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE workflow_id=$1 AND workflow_plan_revision=$2 AND workflow_plan_hash=$3 AND cluster_id=$4 AND workspace_id=$5',[plan.workflowId,plan.planRevision,hash,plan.clusterId,plan.workspaceId]),source=decodeEntityExecutionSource(row);
    if('origin'in source||source.executionActorId!==actor.user.id||Date.parse(source.expiresAt)>Date.now())return false;
    const envelope=await this.intents.executionMaterial(plan,actor,tx);if(envelope.version!==1||envelope.prepared.metadataObligations.length)return false;
    const e=await tx.one<any>('SELECT state FROM workflow_executions WHERE id=$1',[source.workflowExecutionId]);if(e?.state!=='uncertain')return false;
    await this.currentAuthority(plan,envelope,source,actor,frame,actorHmac,tx,true);const certificate=await certifyTargetReconciliationHistory({tx,secrets:this.secrets,plan,envelope,source});await this.producer(certificate);
    return this.context.current()===frame&&this.secrets.fingerprint(actor)===actorHmac;});
  }catch{return false;}
 }
 /** Read permission, not the original execution key or expired owner session,
  * controls visibility. The separate authenticated observation never replaces
  * the original packet's unknown outcome or absent native status. */
 async authenticatedHistoricalProjection(plan:WorkflowPlanV1,actor:EntityActor,sourceId:string):Promise<Readonly<TargetResultHistoricalObservation>|null>{
  const id=workflowId(sourceId),frame=this.context.current(),actorHmac=this.secrets.fingerprint(actor),planHash=this.secrets.fingerprint(plan);assertEntityChangeWorkflowPlan(plan);
  const assertFrame=()=>{if(this.context.current()!==frame||this.secrets.fingerprint(actor)!==actorHmac||frame.kind!=='actor'||frame.module!=='workflows'||!['read','write'].includes(frame.action??'')
   ||frame.operation||frame.archive||frame.purpose||!frame.sessionId||frame.actor?.id!==actor.user.id||this.secrets.fingerprint(frame.actor)!==this.secrets.fingerprint(actor.user)
   ||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId||actor.workspaceId!==plan.workspaceId)throw deny();};
  assertFrame();return this.db.transaction(async tx=>{
   const currentRead=async()=>{assertFrame();const session=await tx.one<any>(`SELECT s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
    WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
    AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[frame.sessionId,actor.user.id]);
    if(!session||String(session.credential_epoch)!==String(session.user_epoch))throw deny('ENTITY_CHANGE_SESSION_REVOKED');
    await this.intents.assertSubject(plan,actor.user.id,'read',tx);return this.authz.permissionVersion(actor.user,tx);};
   const permission=await currentRead();if(!this.bridge||!this.checksum)return null;
   const ledger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='027_m11_target_result_observations.sql'");if(!ledger||ledger.checksum!==this.checksum)return null;
   const selected=await tx.one<any>('SELECT id FROM entity_change_target_result_observations WHERE source_id=$1 AND cluster_id=$2 AND workspace_id=$3',[id,plan.clusterId,plan.workspaceId]);if(!selected)return null;
   const{row}=await authenticateTargetResultObservation(tx,this.secrets,selected.id);
   if(row.source_id!==id||row.cluster_id!==plan.clusterId||row.workspace_id!==plan.workspaceId||row.workflow_id!==plan.workflowId||row.workflow_plan_revision!==plan.planRevision||row.workflow_plan_hash!==planHash
    ||row.workflow_step_id!==assertEntityChangeWorkflowPlan(plan).id||row.transport_scope!==plan.scope.transportScope||row.cluster_revision!==plan.scope.clusterRevision||row.workspace_revision!==plan.scope.workspaceRevision)throw changed();
   const source=decodeEntityExecutionSource(await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1',[id]));
   if('origin'in source||source.id!==id||source.clusterId!==plan.clusterId||source.workspaceId!==plan.workspaceId||source.workflowId!==plan.workflowId||source.workflowPlanRevision!==plan.planRevision
    ||source.workflowPlanHash!==planHash||source.workflowExecutionId!==row.workflow_execution_id||this.secrets.fingerprint(source)!==row.source_hmac)throw changed();
   // Read authorization already authenticated the plan/intent binding. Load
   // original bytes directly; executionMaterial requires current write-owner
   // authority and would incorrectly hide history from authorized readers.
   const version=await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4',[plan.clusterId,plan.workspaceId,source.intentId,source.intentRevision]);
   if(!version)throw changed();const envelope=this.secrets.decrypt<EntityChangeIntentEnvelopeV1>(version.envelope_ciphertext,entityChangeIntentAad(plan.clusterId,plan.workspaceId,source.intentId,source.intentRevision));
   const certificate=await certifyTargetReconciliationHistory({tx,secrets:this.secrets,plan,envelope,source,priorObservationId:row.id});
   if(certificate.attemptId!==row.attempt_id||certificate.packetKey!==row.packet_key||certificate.operationId!==row.operation_id||certificate.nativeId!==row.native_id)throw changed();
   if(await currentRead()!==permission)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');assertFrame();
   return immutableJson({id:row.id,auditId:row.audit_id,eventHash:row.audit_event_hash,observedAt:new Date(row.observed_at).toISOString(),kind:'target-weight-zero-original-response-v1',nativeRequestsSent:0,originalNativeStatus:null,workflowStepId:row.workflow_step_id,operationId:certificate.operationId,operationState:'succeeded'});
  });
 }
 async reconcile(plan:WorkflowPlanV1,body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
  this.policy();const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']);portalConfirm(value,'native-change');portalRevision(value.revision);workflowId(value.executionId);
  const step=assertEntityChangeWorkflowPlan(plan),key=workflowKey(actor.idempotencyKey),frame=this.actor(plan,actor,key),actorHmac=this.secrets.fingerprint(actor),planHash=this.secrets.fingerprint(plan);
  if(value.planHash!==planHash)throw changed('WORKFLOW_PLAN_CHANGED');const requestHmac=this.secrets.fingerprint({workflowId:plan.workflowId,actorId:actor.user.id,key,...value});
  return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${plan.scope.transportScope}`,()=>this.db.transaction(async tx=>{
   const ledger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='027_m11_target_result_observations.sql'");if(!ledger||ledger.checksum!==this.checksum)throw new ServiceUnavailableException({code:'ENTITY_CHANGE_TARGET_RECONCILIATION_STORAGE_UNAVAILABLE'});
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
   const current=await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId,tx);this.same(current.plan,plan);
   const e=await tx.one<any>(`SELECT e.*,w.state AS workflow_state,w.revision AS workflow_revision FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id
    WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND e.plan_revision=$5 AND e.plan_hash=$6 FOR UPDATE OF e,w`,[value.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,plan.planRevision,planHash]);
   if(!e||e.execution_actor_id!==actor.user.id||e.idempotency_key!==key||e.snapshot_state!=='ready'||!e.completed_at)throw changed();
   const source=decodeEntityExecutionSource(await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE workflow_execution_id=$1 AND cluster_id=$2 AND workspace_id=$3',[value.executionId,plan.clusterId,plan.workspaceId]));
   if('origin'in source||source.executionActorId!==actor.user.id||source.workflowId!==plan.workflowId||source.workflowPlanHash!==planHash||source.workflowPlanRevision!==plan.planRevision||Date.parse(source.expiresAt)>Date.now())throw changed();
   await this.policy().assertNoActiveSource(source.id);
   const envelope=await this.intents.executionMaterial(plan,actor,tx);if(envelope.version!==1||envelope.prepared.packets.length!==1||envelope.prepared.metadataObligations.length)throw changed();
   const material=envelope as EntityChangeIntentEnvelopeV1,permissionVersion=await this.currentAuthority(plan,material,source,actor,frame,actorHmac,tx);
   const attempts=await tx.query<any>('SELECT id FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order,id',[source.id]);if(attempts.length!==1)throw changed();
   await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))",[plan.scope.transportScope]);
   await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-attempt:'||$1,0))",[workflowId(attempts[0].id)]);
   const storedStep=await tx.one<any>('SELECT * FROM workflow_steps WHERE id=$1 AND workflow_id=$2 FOR UPDATE',[step.id,plan.workflowId]),mutations=await tx.query<any>('SELECT * FROM mutation_operations WHERE entity_change_source_id=$1 ORDER BY id FOR UPDATE',[source.id]);
   if(!storedStep||mutations.length!==1)throw changed();const m=mutations[0],prior=await tx.one<any>('SELECT id FROM entity_change_target_result_observations WHERE source_id=$1',[source.id]);
   if(!prior&&(e.state!=='uncertain'||e.workflow_state!=='uncertain'||storedStep.state!=='uncertain'||m.state!=='uncertain'||e.workflow_revision!==value.revision||current.row.revision!==value.revision))throw changed();
   const certificate=await certifyTargetReconciliationHistory({tx,secrets:this.secrets,plan,envelope:material,source,...(prior?{priorObservationId:prior.id}:{})}),producer=await this.producer(certificate),packet=material.prepared.packets[0];
   if(prior){const authenticated=await authenticateTargetResultObservation(tx,this.secrets,prior.id);if(authenticated.row.request_hmac!==requestHmac||authenticated.row.original_execution_key!==key||authenticated.row.workflow_revision_before!==value.revision)throw changed('IDEMPOTENCY_CONFLICT');this.same(authenticated.material.producer,producer);}
   const parentPath=`/upstreams/${certificate.upstreamId}`,parentReference=material.prepared.prerequisites.find(p=>p.type==='upstreams'&&p.nativeId===certificate.upstreamId&&!p.absent);
   if(!parentReference)throw changed();const raw=this.secrets.decrypt(m.result_secret,`mutation:${m.id}:result`);if(this.secrets.fingerprint(raw)!==certificate.resultHmac)throw changed();
   // Parent GET and collection EOF are genuine reads in the original current
   // HTTP actor frame. No retired /targets/{UUID} GET is issued.
   const observation=await this.context.runInternalRead(plan.clusterId,'operation-check',async()=>{
    const parent=await this.kong.request(plan.clusterId,'GET',parentPath);this.same(parent,parentReference.before);
    const readback=await disabledTargetReadback(this.kong,this.secrets,{clusterId:plan.clusterId,upstreamId:certificate.upstreamId,approvedBody:packet.body,nativeResult:raw},{maxPages:80,maxRecords:9000,maxBytes:24*1024*1024});
    return immutableJson({version:2,contract:'kong-1.5-disabled-target-two-eof-readback-v2',sourceId:source.id,operationId:m.id,parentHmac:this.secrets.fingerprint(parent),originalResultHmac:readback.originalResultHmac,
     historyRetention:readback.historyRetention,observedHistoryHmac:readback.observedHistoryHmac,historyAddressAbsent:readback.historyAddressAbsent,currentEffectiveAbsent:readback.currentEffectiveAbsent,
     historySnapshotHmac:readback.historySnapshotHmac,effectiveSnapshotHmac:readback.effectiveSnapshotHmac,budget:readback.budget,observedAt:new Date().toISOString()});
   },{paths:[parentPath,`${parentPath}/targets/all`,`${parentPath}/targets`],workspaceId:plan.workspaceId,maxCalls:200,maxPages:80,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
   if(observation.originalResultHmac!==certificate.resultHmac||await this.currentAuthority(plan,material,source,actor,frame,actorHmac,tx)!==permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
   if(prior){const known=await authenticateTargetResultObservation(tx,this.secrets,prior.id);return{workflowId:plan.workflowId,executionId:e.id,operationId:m.id,state:'succeeded',metadataReconciled:true,alreadyReconciled:true,nativeRequestsSent:0,observationId:prior.id,auditId:known.row.audit_id,eventHash:known.row.audit_event_hash,originalNativeStatus:null,statusInferredViaContract:201};}
   const observationId=randomUUID(),observedAt=new Date().toISOString(),binding:any={id:observationId,version:1,proof_kind:'target-weight-zero-original-response-v1',cluster_id:plan.clusterId,workspace_id:plan.workspaceId,transport_scope:plan.scope.transportScope,
    cluster_revision:plan.scope.clusterRevision,workspace_revision:plan.scope.workspaceRevision,source_id:source.id,source_hmac:certificate.sourceHmac,intent_id:source.intentId,intent_revision:source.intentRevision,material_hmac:source.materialHmac,change_digest:source.changeDigest,packet_manifest_hmac:source.packetManifestHmac,
    workflow_id:plan.workflowId,workflow_plan_revision:plan.planRevision,workflow_plan_hash:planHash,workflow_execution_id:e.id,workflow_step_id:step.id,execution_actor_id:actor.user.id,credential_epoch:source.credentialEpoch,metadata_session_id:frame.sessionId,permission_version_hmac:source.permissionVersionHmac,
    original_execution_key:key,operation_key:m.idempotency_key,request_hmac:requestHmac,workflow_revision_before:e.workflow_revision,execution_revision_before:e.revision,step_revision_before:storedStep.revision,
    baseline_id:certificate.baselineId,baseline_hmac:certificate.baselineHmac,object_manifest_hmac:certificate.objectManifestHmac,pin_id:certificate.pinId,attempt_id:certificate.attemptId,packet_key:certificate.packetKey,packet_order:1,operation_id:m.id,method:'POST',native_type:'targets',permission_action:'write',mutation_action:'update',
    parent_id:certificate.upstreamId,original_native_id:certificate.originalNativeId,native_id:certificate.nativeId,weight:0,path_hmac:this.secrets.fingerprint(packet.canonicalPath),body_hmac:certificate.bodyHmac,before_hmac:certificate.beforeHmac,target_address_hmac:certificate.targetAddressHmac,result_hmac:certificate.resultHmac,
    send_event_id:certificate.sendEventId,send_fact_hmac:certificate.sendFactHmac,outcome_event_id:certificate.outcomeEventId,outcome_fact_hmac:certificate.outcomeFactHmac,approval_set_id:certificate.approvalSetId,approval_set_hmac:certificate.approvalSetHmac,
    history_proof_hmac:certificate.proofHmac,producer_attestation_hmac:producer.evidenceHmac,current_observation_hmac:this.secrets.fingerprint(observation),certified_native_status:201,current_observed_at:observation.observedAt,observed_at:observedAt};
   const sealed=immutableJson({version:1,binding:targetResultObservationBinding(binding),historyCertificate:certificate,producer,currentObservation:observation}),observationHmac=this.secrets.fingerprint(sealed);
   const after={observationId,observationHmac,requestHmac,executionId:e.id,sourceId:source.id,attemptId:certificate.attemptId,operationId:m.id,proofHmac:certificate.proofHmac,producerAttestationHmac:producer.evidenceHmac,currentObservationHmac:binding.current_observation_hmac,resultHmac:certificate.resultHmac,
    originalOutcome:'sent-unknown',nativeStatusRecorded:null,certifiedNativeStatus:201,nativeRequestsSent:0,metadataReconciled:true,workflowState:'succeeded',executionState:'succeeded',operationState:'succeeded',stepState:'succeeded'};
   const audit=await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,action:'workflow.execute.target-result-reconciled',result:'success',requestId:actor.requestId,ip:actor.ip,
    before:{workflowState:'uncertain',executionState:'uncertain',operationState:'uncertain',stepState:'uncertain'},after,scopeHints:this.scopeHints(plan)},tx);
   const row={...binding,observation_hmac:observationHmac,observation_ciphertext:this.secrets.encrypt(sealed,targetResultObservationAad(plan.clusterId,plan.workspaceId,observationId)),audit_id:audit.id,audit_event_hash:audit.eventHash},columns=Object.keys(row);
   await tx.exec(`INSERT INTO entity_change_target_result_observations(${columns.join(',')}) VALUES(${columns.map((_c,i)=>`$${i+1}`).join(',')})`,columns.map(c=>(row as any)[c]));
   // All CAS updates preserve original result/before/payload ciphertext,
   // transport flags, completed timestamps, failures and old packet outcomes.
   requirePortalCas(await tx.exec("UPDATE mutation_operations SET state='succeeded',safe_result=$2::jsonb,updated_at=now() WHERE id=$1 AND state='uncertain' AND remote_started AND remote_completed AND entity_id=$3 AND result_secret=$4 AND error_code='KONG_VALIDATION_ERROR'",[m.id,JSON.stringify({metadataReconciled:true,observationId,nativeRequestsSent:0}),certificate.nativeId,m.result_secret]));
   requirePortalCas(await tx.exec("UPDATE workflow_steps SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain' AND revision=$2",[step.id,storedStep.revision]));
   requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain' AND revision=$2",[e.id,e.revision]));
   requirePortalCas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain' AND revision=$2",[plan.workflowId,e.workflow_revision]));
   if(await this.currentAuthority(plan,material,source,actor,frame,actorHmac,tx)!==permissionVersion)throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');await this.redis.assertLeaseOwnership();
   return{workflowId:plan.workflowId,executionId:e.id,operationId:m.id,state:'succeeded',metadataReconciled:true,alreadyReconciled:false,nativeRequestsSent:0,observationId,auditId:audit.id,eventHash:audit.eventHash,originalNativeStatus:null,statusInferredViaContract:201};
  })));
 }
}
