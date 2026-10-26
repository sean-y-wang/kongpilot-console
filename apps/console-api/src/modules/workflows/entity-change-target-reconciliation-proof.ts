import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import {ConflictException} from '@nestjs/common';
import {createHash} from 'node:crypto';
import type {DbService} from '../../infrastructure/db.service';
import {canonicalJson,type SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {entityReferenceId} from '../entities/entity-reference';
import {derivePreparedEntityWrite} from '../entities/entity-prepared-writer.service';
import type {EntityChangeIntentEnvelopeV1,EntityChangeExecutionSource} from './entity-change-intent.types';
import type {EntityChangeBaselineEnvelope} from './entity-change-execution-facts.types';
import {entityBaselineAad,entityPacketFactAad} from './entity-change-execution-facts.service';
import {decodeEntityExecutionSource} from './entity-change-source-codec';
import {assertEntityChangeWorkflowPlan,entityChangeIntentAad,normalizedEntityChangePackets} from './entity-change-workflow';
import {assertWorkflowCandidateFeasibility,normalizeWorkflowApprovalPolicy} from './workflow-approval-policy';
import {planAad,type WorkflowPlanV1} from './workflow.types';
import {eventAuditScopeDigest} from '../event-core/event-utils';

export interface TargetReconciliationHistoryInput{
 readonly tx:Pick<DbService,'one'|'query'>;readonly secrets:SecretService;
 readonly plan:WorkflowPlanV1;readonly envelope:EntityChangeIntentEnvelopeV1;readonly source:EntityChangeExecutionSource;
 /** Optional selector only. The helper authenticates the actual append-only
  * SQL027 observation, audit and exact post-CAS states before accepting it. */
 readonly priorObservationId?:string;
}
export interface TargetReconciliationHistoryCertificate{
 readonly version:1;readonly kind:'target-weight-zero-original-response';readonly nativeAuthority:false;readonly nativeWrites:0;
 readonly clusterId:string;readonly workspaceId:string;readonly transportScope:string;readonly sourceId:string;readonly sourceHmac:string;
 readonly intentId:string;readonly intentRevision:number;readonly materialHmac:string;readonly workflowId:string;readonly workflowPlanRevision:number;readonly workflowPlanHash:string;readonly workflowExecutionId:string;
 readonly baselineId:string;readonly baselineHmac:string;readonly objectManifestHmac:string;readonly pinId:string;
 readonly packetKey:string;readonly attemptId:string;readonly operationId:string;readonly operationKey:string;
 readonly upstreamId:string;readonly originalNativeId:string;readonly nativeId:string;readonly targetAddressHmac:string;readonly bodyHmac:string;readonly beforeHmac:string;readonly resultHmac:string;
 readonly sendEventId:string;readonly sendFactHmac:string;readonly outcomeEventId:string;readonly outcomeFactHmac:string;readonly approvalSetId:string;readonly approvalSetHmac:string;
 /** The old unknown fact contains no HTTP status. Matching authenticated
  * responseHMAC is not a manufactured replacement native201 receipt. */
 readonly originalOutcome:'sent-unknown';readonly nativeStatusRecorded:null;readonly originalResponseAuthenticated:true;
 readonly requiresFrozenOriginalProducerAttestation:true;readonly requiresFreshCurrentStateObservation:true;
 readonly metadataEligibility:'requires-frozen-producer-and-current-observation';readonly proofHmac:string;
}
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i,hex=/^[a-f\d]{64}$/;
const invalid=()=>new ConflictException({code:'ENTITY_CHANGE_TARGET_RECONCILIATION_PROOF_INVALID'});
const record=(v:any):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const iso=(v:any)=>{const d=new Date(v);if(!Number.isFinite(d.getTime()))throw invalid();return d.toISOString();};
const packetTuple=(r:any)=>({key:r.packet_key,order:r.packet_order,dependencies:r.dependencies,method:r.method,pathHmac:r.path_hmac,nativeType:r.native_type,nativeId:r.native_id,
 parentId:r.parent_id,credentialKind:r.credential_kind,originalNativeId:r.original_native_id,mutationAction:r.mutation_action,permissionAction:r.permission_action,bodyHmac:r.body_hmac,beforeHmac:r.before_hmac});
export const targetResultObservationAad=(cid:string,wid:string,id:string)=>`entity-change-target-result-observation:${cid}:${wid}:${id}:material`;
/** Columns authenticated inside the AEAD material. Audit is appended afterward
 * with this material's HMA; audit identity/hash are deliberately outside it. */
export const TARGET_RESULT_OBSERVATION_BINDING_COLUMNS=Object.freeze(['id','version','proof_kind','cluster_id','workspace_id','transport_scope','cluster_revision','workspace_revision',
 'source_id','source_hmac','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','workflow_id','workflow_plan_revision','workflow_plan_hash','workflow_execution_id','workflow_step_id',
 'execution_actor_id','credential_epoch','metadata_session_id','permission_version_hmac','original_execution_key','operation_key','request_hmac','workflow_revision_before','execution_revision_before','step_revision_before',
 'baseline_id','baseline_hmac','object_manifest_hmac','pin_id','attempt_id','packet_key','packet_order','operation_id','method','native_type','permission_action','mutation_action','parent_id','original_native_id','native_id','weight',
 'path_hmac','body_hmac','before_hmac','target_address_hmac','result_hmac','send_event_id','send_fact_hmac','outcome_event_id','outcome_fact_hmac','approval_set_id','approval_set_hmac','history_proof_hmac','producer_attestation_hmac','current_observation_hmac','certified_native_status','current_observed_at','observed_at'] as const);
export function targetResultObservationBinding(row:any):Record<string,unknown>{return Object.fromEntries(TARGET_RESULT_OBSERVATION_BINDING_COLUMNS.map(k=>{
 if(row[k]===undefined||row[k]===null)throw invalid();return[k,k==='credential_epoch'?String(row[k]):k==='observed_at'||k==='current_observed_at'?iso(row[k]):row[k]];}));}
export async function authenticateTargetResultObservation(tx:Pick<DbService,'one'|'query'>,secrets:SecretService,id:string):Promise<Readonly<{row:any;material:any}>>{
 try{return await authenticateObservation(tx,secrets,id);}catch{throw invalid();}
}
async function authenticateObservation(tx:Pick<DbService,'one'|'query'>,secrets:SecretService,id:string):Promise<Readonly<{row:any;material:any}>>{
 if(!uuid.test(id))throw invalid();const row=await tx.one<any>('SELECT * FROM entity_change_target_result_observations WHERE id=$1',[id]);
 if(!row||row.id!==id||row.version!==1||row.proof_kind!=='target-weight-zero-original-response-v1'||row.certified_native_status!==201)throw invalid();
 const material=secrets.decrypt<any>(row.observation_ciphertext,targetResultObservationAad(row.cluster_id,row.workspace_id,id));
 if(material.version!==1||secrets.fingerprint(material)!==row.observation_hmac||secrets.fingerprint(material.binding)!==secrets.fingerprint(targetResultObservationBinding(row))
  ||material.historyCertificate?.proofHmac!==row.history_proof_hmac||material.producer?.evidenceHmac!==row.producer_attestation_hmac||secrets.fingerprint(material.currentObservation)!==row.current_observation_hmac)throw invalid();
 const{proofHmac,...history}=material.historyCertificate,{evidenceHmac,...producer}=material.producer;
 if(secrets.fingerprint(history)!==proofHmac||secrets.fingerprint(producer)!==evidenceHmac||producer.version!==1||producer.contract!=='root-entity-v3-target-append-201-before-response-hmac-v1'
  ||producer.producerProtocol!=='http-source-v1/entity-mutation-v3/packet-fact-v1'||producer.nativeStatusInferred!==201||producer.sourceId!==row.source_id||producer.sourceHmac!==row.source_hmac||producer.outcomeFactHmac!==row.outcome_fact_hmac||producer.resultHmac!==row.result_hmac
  ||material.currentObservation?.observedAt!==iso(row.current_observed_at))throw invalid();
 const current=material.currentObservation;
 if(current?.version===1){if(current.contract!=='kong-1.5-disabled-target-two-eof-readback-v1'||current.resultHmac!==row.result_hmac)throw invalid();}
 else if(current?.version===2){
  const keys=['version','contract','sourceId','operationId','parentHmac','originalResultHmac','historyRetention','observedHistoryHmac','historyAddressAbsent','currentEffectiveAbsent','historySnapshotHmac','effectiveSnapshotHmac','budget','observedAt'],budget=current.budget;
  if(current.contract!=='kong-1.5-disabled-target-two-eof-readback-v2'||current.originalResultHmac!==row.result_hmac||current.sourceId!==row.source_id||current.operationId!==row.operation_id
   ||!hex.test(current.parentHmac)||!hex.test(current.historySnapshotHmac)||!hex.test(current.effectiveSnapshotHmac)||current.currentEffectiveAbsent!==true
   ||Object.keys(current).length!==keys.length||Object.keys(current).some(k=>!keys.includes(k))||!record(budget)||Object.keys(budget).length!==3||Object.keys(budget).some(k=>!['pages','records','bytes'].includes(k))
   ||!Number.isInteger(budget.pages)||budget.pages<4||budget.pages>80||!Number.isInteger(budget.records)||budget.records<0||budget.records>9000||!Number.isInteger(budget.bytes)||budget.bytes<0||budget.bytes>24*1024*1024
   ||!(current.historyRetention==='retained'&&current.observedHistoryHmac===row.result_hmac&&current.historyAddressAbsent===false
     ||current.historyRetention==='native-pruned'&&current.observedHistoryHmac===null&&current.historyAddressAbsent===true)
   )throw invalid();
 }else throw invalid();
 const audit=await tx.one<any>('SELECT * FROM audit_events WHERE id=$1',[row.audit_id]),scope=await tx.one<any>('SELECT * FROM audit_event_scopes WHERE audit_event_id=$1',[row.audit_id]);
 if(!audit||!scope||audit.event_hash!==row.audit_event_hash||audit.cluster_id!==row.cluster_id||audit.workspace_id!==row.workspace_id||audit.workflow_id!==row.workflow_id||audit.actor_id!==row.execution_actor_id
  ||audit.entity_type!=='workflows'||audit.entity_id!==row.workflow_id||audit.action!=='workflow.execute.target-result-reconciled'||audit.result!=='success'
  ||scope.audit_event_hash!==audit.event_hash||scope.cluster_id!==row.cluster_id||scope.workspace_id!==row.workspace_id||scope.scope?.quality!=='verified'||scope.scope?.module!=='workflows'||scope.scope?.subject?.type!=='workflows'||scope.scope?.subject?.id!==row.workflow_id
  ||scope.scope_hmac!==eventAuditScopeDigest(secrets,{auditEventId:audit.id,auditEventHash:audit.event_hash,clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:scope.scope}))throw invalid();
 const auditRecord=Object.fromEntries(['id','chain_scope','sequence','actor_id','actor_type','source_ip','cluster_id','workspace_id','entity_type','entity_id','action','before','after','json_patch','workflow_id','result','request_id','prev_hash','occurred_at'].map(k=>[k,k==='sequence'?String(audit[k]):k==='occurred_at'?iso(audit[k]):audit[k]]));
 if(createHash('sha256').update(canonicalJson(auditRecord)).digest('hex')!==audit.event_hash)throw invalid();
 const expected={observationId:id,observationHmac:row.observation_hmac,requestHmac:row.request_hmac,executionId:row.workflow_execution_id,sourceId:row.source_id,attemptId:row.attempt_id,operationId:row.operation_id,
  proofHmac:row.history_proof_hmac,producerAttestationHmac:row.producer_attestation_hmac,currentObservationHmac:row.current_observation_hmac,resultHmac:row.result_hmac,originalOutcome:'sent-unknown',nativeStatusRecorded:null,
  certifiedNativeStatus:201,nativeRequestsSent:0,metadataReconciled:true,workflowState:'succeeded',executionState:'succeeded',operationState:'succeeded',stepState:'succeeded'};
 for(const[k,v]of Object.entries(expected))if(secrets.fingerprint(audit.after?.[k])!==secrets.fingerprint(v))throw invalid();
 return immutableJson({row,material});
}

/** Pure SELECT/AEAD/HMA certification of one original HTTP V1 Target append
 * whose later metadata/readback failed. No current identity, lease, actor,
 * source, UUID, native permit, HTTP status or outcome is reconstructed here.
 * Root must separately certify the original frozen producer's 201-before-HMA
 * branch, perform genuine bounded current parent/history/effective reads, and
 * own current authorization, original key, locks, observation/audit transaction.
 * The original sent-unknown event remains immutable, even if reconciliation
 * subsequently proves the gateway state. The returned summary alone cannot
 * authorize that metadata transition or suppress foreign/unknown footprints. */
export async function certifyTargetReconciliationHistory(input:TargetReconciliationHistoryInput):Promise<Readonly<TargetReconciliationHistoryCertificate>>{
 try{return await certify(input);}catch{throw invalid();}
}
async function certify(input:TargetReconciliationHistoryInput):Promise<Readonly<TargetReconciliationHistoryCertificate>>{
 const{tx,secrets}=input,seed=secrets.fingerprint({plan:input.plan,envelope:input.envelope,source:input.source});
 const{plan,envelope,source}=immutableJson({plan:input.plan,envelope:input.envelope,source:input.source}),same=(a:unknown,b:unknown)=>{if(secrets.fingerprint(a)!==secrets.fingerprint(b))throw invalid();};
 const scope=(r:any)=>{if(!r||r.cluster_id!==source.clusterId||r.workspace_id!==source.workspaceId)throw invalid();};
 const intent=(r:any)=>{scope(r);if(r.intent_id!==source.intentId||r.intent_revision!==source.intentRevision||r.material_hmac!==source.materialHmac||r.change_digest!==source.changeDigest||r.packet_manifest_hmac!==source.packetManifestHmac)throw invalid();};
 const execution=(r:any,baselineId?:string,pinId?:string)=>{scope(r);if(r.source_id!==source.id||r.workflow_execution_id!==source.workflowExecutionId||baselineId&&r.baseline_id!==baselineId||pinId&&r.pin_id!==pinId)throw invalid();};
 const prior=input.priorObservationId?await authenticateTargetResultObservation(tx,secrets,input.priorObservationId):null,expectedState=prior?'succeeded':'uncertain';
 if(!source||'origin' in source||!uuid.test(source.sessionId)||envelope.version!==1||plan.version!==1||!plan.approvalRequired||plan.requester.type!=='console'
  ||plan.requester.id!==source.executionActorId||plan.workflowId!==source.workflowId||plan.planRevision!==source.workflowPlanRevision||plan.clusterId!==source.clusterId||plan.workspaceId!==source.workspaceId
  ||secrets.fingerprint(plan)!==source.workflowPlanHash||envelope.requesterId!==source.executionActorId||envelope.credentialEpoch!==source.credentialEpoch
  ||envelope.intentId!==source.intentId||envelope.revision!==source.intentRevision||envelope.clusterId!==source.clusterId||envelope.workspaceId!==source.workspaceId
  ||secrets.fingerprint(envelope)!==source.materialHmac||envelope.packetManifestHmac!==source.packetManifestHmac||!hex.test(plan.scope.transportScope))throw invalid();
 const step=assertEntityChangeWorkflowPlan(plan),material=envelope.prepared,{changeDigest,...base}=material;
 same(step.metadata,{intentId:source.intentId,intentRevision:source.intentRevision,materialHmac:source.materialHmac,changeDigest:source.changeDigest,packetManifestHmac:source.packetManifestHmac});
 if(material.version!==1||material.clusterId!==source.clusterId||material.workspaceId!==source.workspaceId||material.requesterId!==source.executionActorId||material.scope.transportScope!==plan.scope.transportScope
  ||changeDigest!==source.changeDigest||secrets.fingerprint(base)!==changeDigest||material.request.kind!=='target'||material.request.action!=='weight'||material.packets.length!==1
  ||material.metadataObligations.length||!isSupportedKongBuild(material.scope.kongVersion))throw invalid();
 const packet=material.packets[0],operation=derivePreparedEntityWrite(packet),parentId=packet.parentId!,oldId=packet.originalNativeId!;
 if(operation.kind!=='target-weight'||packet.order!==1||packet.method!=='POST'||packet.credentialKind!==undefined||packet.dependencies.length||packet.body?.weight!==0
  ||packet.canonicalPath!==`/upstreams/${parentId}/targets`||packet.body?.id!==packet.nativeId||packet.body?.target!==(packet.before as any)?.target
  ||!record(packet.before)||!Number.isFinite(packet.before.weight)||packet.before.weight<=0||!record(packet.body)||!Array.isArray(packet.body.tags)
  ||packet.bodyHmac!==secrets.fingerprint(packet.body)||packet.beforeHmac!==secrets.fingerprint(packet.before)||material.request.upstreamId!==parentId||material.request.targetId!==oldId||material.request.body.weight!==0
  ||secrets.fingerprint(material.scope)!==secrets.fingerprint({...plan.scope,kongVersion:material.scope.kongVersion,adapter:material.scope.adapter}))throw invalid();
 const manifest=normalizedEntityChangePackets(material,secrets);if(secrets.fingerprint(manifest)!==source.packetManifestHmac)throw invalid();
 const sourceRow=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1',[source.id]);same(decodeEntityExecutionSource(sourceRow),source);
 const version=await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4',[source.clusterId,source.workspaceId,source.intentId,source.intentRevision]);intent(version);
 if(version.packet_count!==1)throw invalid();same(version.packet_manifest,manifest);same(secrets.decrypt(version.envelope_ciphertext,entityChangeIntentAad(source.clusterId,source.workspaceId,source.intentId,source.intentRevision)),envelope);
 const storedPackets=await tx.query<any>('SELECT * FROM entity_change_intent_packets WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4 ORDER BY packet_order',[source.clusterId,source.workspaceId,source.intentId,source.intentRevision]);
 if(storedPackets.length!==1)throw invalid();storedPackets.forEach(intent);same(storedPackets.map(packetTuple),manifest);
 const submission=await tx.one<any>('SELECT * FROM entity_change_submissions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4',[source.clusterId,source.workspaceId,source.intentId,source.intentRevision]);intent(submission);
 if(submission.actor_id!==source.executionActorId||submission.workflow_id!==source.workflowId||submission.workflow_plan_revision!==source.workflowPlanRevision||submission.workflow_plan_hash!==source.workflowPlanHash)throw invalid();
 const w=await tx.one<any>('SELECT * FROM workflows WHERE id=$1',[source.workflowId]),e=await tx.one<any>('SELECT * FROM workflow_executions WHERE id=$1',[source.workflowExecutionId]);scope(w);scope(e);
 if(w.id!==source.workflowId||w.kind!=='native-change'||w.subject_type!=='entity_change_intents'||w.subject_id!==source.intentId||w.requester_type!=='console'||w.requester_user_id!==source.executionActorId
  ||w.state!==expectedState||w.plan_revision!==source.workflowPlanRevision||w.plan_hash!==source.workflowPlanHash||w.definition_id!==plan.definition.id||w.definition_version!==plan.definition.version
  ||e.id!==source.workflowExecutionId||e.workflow_id!==source.workflowId||e.plan_revision!==source.workflowPlanRevision||e.plan_hash!==source.workflowPlanHash||e.state!==expectedState
  ||e.execution_actor_id!==source.executionActorId||e.snapshot_state!=='ready'||!e.completed_at||e.approval_format!==2||w.approval_format!==2||!e.approval_required||!w.approval_required
  ||e.approval_set_id!==w.approval_set_id||e.approval_set_hmac!==w.approval_set_hmac||e.approved_by!==w.approved_by)throw invalid();
 const wfVersion=await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND plan_revision=$2',[source.workflowId,source.workflowPlanRevision]);scope(wfVersion);
 if(wfVersion.plan_hash!==source.workflowPlanHash||wfVersion.approval_format!==2||!wfVersion.approval_required)throw invalid();same(secrets.decrypt(wfVersion.payload_secret,planAad(source.clusterId,source.workspaceId,source.workflowId,source.workflowPlanRevision)),plan);
 const steps=await tx.query<any>('SELECT * FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY step_order',[source.workflowId,source.workflowPlanRevision]);
 if(steps.length!==1)throw invalid();const storedStep=steps[0];scope(storedStep);
 if(storedStep.id!==step.id||storedStep.plan_hash!==source.workflowPlanHash||storedStep.kind!=='metadata'||storedStep.handler!=='entity.change'||storedStep.state!==expectedState||storedStep.entity_id!==source.intentId
  ||storedStep.operation_id!==null||storedStep.receipt_secret!==null||!storedStep.completed_at)throw invalid();
 const approvals=await historicalApprovalProof(tx,secrets,plan,w,e);
 const baselines=await tx.query<any>('SELECT * FROM entity_change_baselines WHERE source_id=$1',[source.id]);if(baselines.length!==1)throw invalid();const b=baselines[0];intent(b);
 if(!uuid.test(b.id)||b.source_id!==source.id||b.workflow_id!==source.workflowId||b.workflow_execution_id!==source.workflowExecutionId||b.workflow_plan_revision!==source.workflowPlanRevision||b.workflow_plan_hash!==source.workflowPlanHash
  ||b.execution_actor_id!==source.executionActorId||String(b.credential_epoch)!==source.credentialEpoch||b.readiness!=='ready'||b.object_count!==3||b.graph_count!==1)throw invalid();
 const baseline=secrets.decrypt<EntityChangeBaselineEnvelope>(b.material_ciphertext,entityBaselineAad(source.clusterId,source.workspaceId,b.id)),capture=baseline.capture;
 same(baseline.source,source);if(baseline.version!==1||baseline.baselineId!==b.id||secrets.fingerprint(baseline)!==b.baseline_hmac||secrets.fingerprint(capture)!==b.capture_hmac
  ||capture.version!==1||capture.objects.length!==3||capture.graphs.length!==1||capture.blockerCodes.length||capture.nonreversiblePacketKeys.length||capture.observedFrom!==iso(b.observed_from)||capture.observedUntil!==iso(b.observed_until)
  ||Date.parse(capture.observedFrom)<Date.parse(source.issuedAt)||Date.parse(capture.observedUntil)>Date.parse(source.expiresAt)||Date.parse(capture.observedUntil)<Date.parse(capture.observedFrom))throw invalid();
 const parentKey=`upstreams:${parentId}`,oldKey=`targets:${parentId}:${oldId}`,newKey=`targets:${parentId}:${packet.nativeId}`,parent=capture.objects.find(o=>o.key===parentKey),old=capture.objects.find(o=>o.key===oldKey),absent=capture.objects.find(o=>o.key===newKey);
 if(!parent||!old||!absent||parent.nativeType!=='upstreams'||parent.nativeId!==parentId||parent.parentId!==undefined||parent.affected||!parent.present||parent.recovery!=='reference'||parent.restorePayload!==undefined||parent.dependencies.length
  ||old.nativeType!=='targets'||old.nativeId!==oldId||old.parentId!==parentId||!old.affected||!old.present||old.recovery!=='complete'||!record(old.restorePayload)||old.restorePayload.id!==oldId
  ||absent.nativeType!=='targets'||absent.nativeId!==packet.nativeId||absent.parentId!==parentId||!absent.affected||absent.present||absent.before!==null||absent.restorePayload!==undefined||absent.recovery!=='absent')throw invalid();
 same(old.before,packet.before);same(old.dependencies,[parentKey]);same(absent.dependencies,[parentKey]);
 const{created_at:_created,updated_at:_updated,ttl:_ttl,...restore}=packet.before;same(old.restorePayload,restore);
 if(!record(parent.before)||parent.before.id!==parentId||entityReferenceId((old.before as any).upstream)!==parentId)throw invalid();
 for(const object of capture.objects){if(object.credentialKind!==undefined||object.schemaMaterial===undefined||object.trustedProvenance===undefined)throw invalid();
  if(object.present)same(object.trustedProvenance,{kind:'native-observed',beforeHmac:secrets.fingerprint(object.before)});
  else same(object.trustedProvenance,{kind:'native-get-404',pathHmac:secrets.fingerprint(`${packet.canonicalPath}/${packet.nativeId}`)});}
 const graph=capture.graphs[0];
 if(graph.complete!==true||graph.purpose!=='baseline'||graph.rootKey!==oldKey||graph.nodes.length!==2||graph.targetHistory!==undefined)throw invalid();
 for(const node of graph.nodes){const object=capture.objects.find(o=>o.key===node.key);if(!object||!object.present||node.type!==object.nativeType||node.id!==object.nativeId||node.affected!==object.affected||!node.restorable
   ||node.path!==(node.type==='targets'?`${packet.canonicalPath}/${oldId}`:`/upstreams/${parentId}`))throw invalid();same(node.data,object.before);same(node.dependencies,object.dependencies);
  if(node.affected)same(node.restoreData,object.restorePayload);}
 const normalized=capture.objects.map(o=>({key:o.key,nativeType:o.nativeType,nativeId:o.nativeId,parentId:o.parentId??null,credentialKind:o.credentialKind??null,affected:o.affected,present:o.present,
  dependencies:o.dependencies,beforeHmac:secrets.fingerprint(o.before),restoreHmac:o.restorePayload===undefined?null:secrets.fingerprint(o.restorePayload),schemaHmac:secrets.fingerprint(o.schemaMaterial),provenanceHmac:secrets.fingerprint(o.trustedProvenance),recovery:o.recovery}));
 if(secrets.fingerprint(normalized)!==b.object_manifest_hmac)throw invalid();same(b.object_manifest,normalized);
 const objects=await tx.query<any>('SELECT * FROM entity_change_baseline_objects WHERE baseline_id=$1 ORDER BY object_order',[b.id]);if(objects.length!==3)throw invalid();
 objects.forEach((o,i)=>{scope(o);if(o.baseline_id!==b.id||o.object_manifest_hmac!==b.object_manifest_hmac||o.object_order!==i+1)throw invalid();});
 same(objects.map(o=>({key:o.object_key,nativeType:o.native_type,nativeId:o.native_id,parentId:o.parent_id,credentialKind:o.credential_kind,affected:o.affected,present:o.present,dependencies:o.dependencies,beforeHmac:o.before_hmac,restoreHmac:o.restore_hmac,schemaHmac:o.schema_hmac,provenanceHmac:o.provenance_hmac,recovery:o.recovery})),normalized);
 const attempts=await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order',[source.id]);if(attempts.length!==1)throw invalid();const attempt=attempts[0];intent(attempt);execution(attempt,b.id);
 const{dependencies:_deps,...expectedAttempt}=manifest[0];const{dependencies:_absent,...actualAttempt}=packetTuple(attempt);same(actualAttempt,expectedAttempt);if(!uuid.test(attempt.id)||!uuid.test(attempt.pin_id))throw invalid();
 const pin=await tx.one<any>('SELECT * FROM entity_change_baseline_pins WHERE id=$1',[attempt.pin_id]);execution(pin,b.id);
 if(pin.id!==attempt.pin_id||pin.baseline_hmac!==b.baseline_hmac||pin.object_manifest_hmac!==b.object_manifest_hmac||pin.pin_version!==1||pin.previous_pin_id!==null
  ||Date.parse(iso(pin.protected_until))<Date.parse(iso(b.created_at))+30*86400000||Date.parse(iso(pin.created_at))>Date.parse(iso(attempt.created_at)))throw invalid();
 if(e.snapshot_id!==b.id)throw invalid();const snapshot=secrets.decrypt(e.snapshot_secret,`workflow:${source.clusterId}:${source.workspaceId}:${source.workflowId}:${e.id}:snapshot`);
 same(snapshot,{version:1,baselineId:b.id,sourceId:source.id,captureHmac:b.capture_hmac,objectManifestHmac:b.object_manifest_hmac});if(secrets.fingerprint(snapshot)!==e.snapshot_hash)throw invalid();
 const mutations=await tx.query<any>('SELECT * FROM mutation_operations WHERE entity_change_source_id=$1 ORDER BY id',[source.id]);if(mutations.length!==1)throw invalid();const m=mutations[0];scope(m);
 if(!uuid.test(m.id)||m.entity_change_source_id!==source.id||m.entity_change_baseline_id!==b.id||m.entity_change_attempt_id!==attempt.id||m.entity_change_packet_key!==packet.key||m.workflow_id!==source.workflowId||m.actor_id!==source.executionActorId
  ||m.entity_type!=='targets'||m.action!=='update'||m.entity_id!==packet.nativeId||m.parent_id!==parentId||m.credential_kind!==null||m.state!==expectedState||m.remote_started!==true||m.remote_completed!==true||m.error_code!=='KONG_VALIDATION_ERROR'
  ||m.transport_scope!==plan.scope.transportScope||m.idempotency_key!==`entity-${source.workflowExecutionId}-1`||!record(packet.body)||typeof m.result_secret!=='string'
  ||['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(key=>m[key]!=null))throw invalid();
 same(secrets.decrypt(m.before_secret,`mutation:${m.id}:before`),packet.before);same(secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`),packet.body);
 const binding={version:3,workflowId:source.workflowId,executionId:source.workflowExecutionId,planRevision:source.workflowPlanRevision,planHash:source.workflowPlanHash,stepId:step.id,
  sourceId:source.id,baselineId:b.id,attemptId:attempt.id,packetKey:packet.key,nativeId:packet.nativeId,beforeHmac:packet.beforeHmac};
 if(m.request_hash!==secrets.fingerprint({actor:source.executionActorId,clusterId:source.clusterId,workspaceId:source.workspaceId,entityType:'targets',entityId:oldId,action:'update',payload:packet.body,parentId,credentialKind:null,approvedWorkflow:binding}))throw invalid();
 const raw=secrets.decrypt<any>(m.result_secret,`mutation:${m.id}:result`);
 if(!record(raw)||raw.id!==packet.nativeId||raw.weight!==0||raw.target!==packet.body.target||entityReferenceId(raw.upstream)!==parentId||!Number.isFinite(raw.created_at)||raw.created_at<=0)throw invalid();
 for(const[field,value]of Object.entries(packet.body))same(raw[field],value);const resultHmac=secrets.fingerprint(raw);
 const events=await tx.query<any>('SELECT * FROM entity_change_packet_events WHERE source_id=$1 ORDER BY event_kind',[source.id]);if(events.length!==2||new Set(events.map(r=>r.event_kind)).size!==2||new Set(events.map(r=>r.id)).size!==2)throw invalid();
 let send:any,outcome:any,sendRow:any,outcomeRow:any;
 for(const row of events){execution(row,b.id,pin.id);if(!uuid.test(row.id)||row.attempt_id!==attempt.id||!['send-intent','outcome'].includes(row.event_kind))throw invalid();
  const fact=secrets.decrypt<any>(row.fact_ciphertext,entityPacketFactAad(source.clusterId,source.workspaceId,attempt.id,row.event_kind));
  if(fact.version!==1||fact.kind!==row.event_kind||secrets.fingerprint(fact)!==row.fact_hmac||fact.observedAt!==iso(row.observed_at)||Date.parse(fact.observedAt)<Date.parse(iso(attempt.created_at))||Date.parse(fact.observedAt)>Date.parse(iso(row.created_at)))throw invalid();
  same(fact.binding,{sourceId:source.id,baselineId:b.id,pinId:pin.id,packetKey:packet.key,attemptId:attempt.id});
  if(row.event_kind==='send-intent'){if(row.outcome!==null||row.native_status!==null||row.error_code!==null||Date.parse(fact.observedAt)>Date.parse(source.expiresAt))throw invalid();same(fact.evidence,{operationId:m.id,method:'POST',pathHmac:manifest[0].pathHmac,bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac});send=fact;sendRow=row;}
  else{if(row.outcome!=='sent-unknown'||row.native_status!==null||fact.outcome!==row.outcome||fact.nativeStatus!==undefined||fact.errorCode!=='MUTATION_RESULT_UNCERTAIN'||row.error_code!=='MUTATION_RESULT_UNCERTAIN')throw invalid();
   same(fact.evidence,{operationId:m.id,mutationState:'uncertain',remoteCompleted:true,responseHmac:resultHmac,metadataComplete:false});outcome=fact;outcomeRow=row;}
 }
 if(!send||!outcome||Date.parse(outcome.observedAt)<Date.parse(send.observedAt)||Date.parse(iso(e.completed_at))<Date.parse(outcome.observedAt))throw invalid();
 if(seed!==secrets.fingerprint({plan:input.plan,envelope:input.envelope,source:input.source}))throw invalid();
 const proof={version:1,kind:'target-weight-zero-original-response',nativeAuthority:false,nativeWrites:0,clusterId:source.clusterId,workspaceId:source.workspaceId,transportScope:plan.scope.transportScope,
  sourceId:source.id,sourceHmac:secrets.fingerprint(source),intentId:source.intentId,intentRevision:source.intentRevision,materialHmac:source.materialHmac,workflowId:source.workflowId,workflowPlanRevision:source.workflowPlanRevision,workflowPlanHash:source.workflowPlanHash,workflowExecutionId:source.workflowExecutionId,
  baselineId:b.id,baselineHmac:b.baseline_hmac,objectManifestHmac:b.object_manifest_hmac,pinId:pin.id,packetKey:packet.key,attemptId:attempt.id,operationId:m.id,operationKey:m.idempotency_key,
  upstreamId:parentId,originalNativeId:oldId,nativeId:packet.nativeId,targetAddressHmac:secrets.fingerprint(packet.body.target),bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac,resultHmac,
  sendEventId:sendRow.id,sendFactHmac:sendRow.fact_hmac,outcomeEventId:outcomeRow.id,outcomeFactHmac:outcomeRow.fact_hmac,approvalSetId:approvals.id,approvalSetHmac:approvals.hmac,
  originalOutcome:'sent-unknown',nativeStatusRecorded:null,originalResponseAuthenticated:true,requiresFrozenOriginalProducerAttestation:true,requiresFreshCurrentStateObservation:true,
  metadataEligibility:'requires-frozen-producer-and-current-observation'} as const;
 const certificate=immutableJson({...proof,proofHmac:secrets.fingerprint(proof)});
 if(prior){same(prior.material.historyCertificate,certificate);const r=prior.row;
  if(r.source_id!==source.id||r.source_hmac!==secrets.fingerprint(source)||r.workflow_step_id!==step.id||r.execution_actor_id!==source.executionActorId||String(r.credential_epoch)!==source.credentialEpoch
   ||r.permission_version_hmac!==source.permissionVersionHmac||r.change_digest!==source.changeDigest||r.packet_manifest_hmac!==source.packetManifestHmac||r.original_execution_key!==e.idempotency_key
   ||w.revision!==r.workflow_revision_before+1||e.revision!==r.execution_revision_before+1||storedStep.revision!==r.step_revision_before+1)throw invalid();}
 return certificate;
}

async function historicalApprovalProof(tx:Pick<DbService,'one'|'query'>,secrets:SecretService,plan:WorkflowPlanV1,w:any,e:any):Promise<{id:string;hmac:string}>{
 const same=(a:unknown,b:unknown)=>{if(secrets.fingerprint(a)!==secrets.fingerprint(b))throw invalid();};
 const bound=(r:any)=>{if(!r||r.cluster_id!==plan.clusterId||r.workspace_id!==plan.workspaceId||r.workflow_id!==plan.workflowId||r.plan_revision!==plan.planRevision||r.plan_hash!==secrets.fingerprint(plan))throw invalid();};
 const dv=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[plan.clusterId,plan.workspaceId,plan.definition.id,plan.definition.version]);
 if(!dv||dv.approval_format!==2||dv.allow_self_approval!==false||dv.policy_hash!==plan.definition.policyHash||secrets.fingerprint(dv.policy)!==dv.policy_hash)throw invalid();
 const policy=normalizeWorkflowApprovalPolicy(dv.policy,plan.kind);same(policy,dv.policy);
 const candidate=await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE workflow_id=$1 AND plan_revision=$2 AND candidate_version=$3',[plan.workflowId,plan.planRevision,w.candidate_version]);bound(candidate);
 const manifest=candidate.manifest;if(!manifest||secrets.fingerprint(manifest)!==candidate.manifest_hmac||candidate.manifest_hmac!==w.candidate_manifest_hmac
  ||manifest.version!==1||manifest.clusterId!==plan.clusterId||manifest.workspaceId!==plan.workspaceId||manifest.workflowId!==plan.workflowId||manifest.planRevision!==plan.planRevision||manifest.planHash!==secrets.fingerprint(plan)
  ||manifest.definitionId!==plan.definition.id||manifest.definitionVersion!==plan.definition.version||manifest.policyHash!==plan.definition.policyHash||manifest.candidateVersion!==w.candidate_version||manifest.stages.length!==policy.stages.length)throw invalid();
 const stages=await tx.query<any>('SELECT * FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY level',[plan.workflowId,plan.planRevision]),votes=await tx.query<any>('SELECT * FROM workflow_approvals WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY level,approver_id,id',[plan.workflowId,plan.planRevision]);
 if(stages.length!==policy.stages.length||!votes.length||new Set(votes.map(v=>v.id)).size!==votes.length
  ||new Set(votes.map(v=>`${v.level}:${v.approver_id}`)).size!==votes.length
  ||policy.distinctAcrossStages&&new Set(votes.map(v=>v.approver_id)).size!==votes.length)throw invalid();
 const reviewers=votes.map(v=>{bound(v);const stage=manifest.stages.find((s:any)=>s.level===v.level),c=stage?.candidates.find((c:any)=>c.userId===v.approver_id);
  if(!uuid.test(v.id)||!uuid.test(v.approver_id)||(v.is_self_approval===true?v.approver_id!==plan.requester.id||w.self_approved!==true:v.approver_id===plan.requester.id||!c)||v.decision!=='approve'||v.candidate_version!==w.candidate_version||v.candidate_manifest_hmac!==w.candidate_manifest_hmac)throw invalid();
  return{approvalId:v.id,userId:v.approver_id,level:v.level,candidateVersion:v.candidate_version,...(v.is_self_approval===true?{selfApproval:true}:{})};});
 for(const[i,s]of stages.entries()){bound(s);const frozen=manifest.stages[i],p=policy.stages[i];
  if(s.level!==i+1||s.state!=='approved'||s.approval_format!==2||s.candidate_version!==w.candidate_version||s.candidate_manifest_hmac!==w.candidate_manifest_hmac
   ||s.stage_mode!==p.mode||frozen.level!==s.level||frozen.mode!==p.mode||!Array.isArray(frozen.candidates)||frozen.candidates.length>100||frozen.threshold!==(p.mode==='all'?frozen.candidates.length:p.threshold)
   ||s.required_approvals!==frozen.threshold||votes.filter(v=>v.level===s.level).length!==frozen.threshold
   ||new Set(frozen.candidates.map((c:any)=>c.userId)).size!==frozen.candidates.length)throw invalid();}
 // Historical certification uses the original sealed policy and candidates,
 // never today's roles or sessions. Feasibility still forbids empty all-stages
 // and impossible distinct-reviewer policies; every actual vote remains bound.
 if(!reviewers.some((r:any)=>r.selfApproval===true))assertWorkflowCandidateFeasibility(manifest.stages,policy.distinctAcrossStages);
 if(!reviewers.some(r=>r.userId===w.approved_by&&r.level===policy.stages.length))throw invalid();
 const candidates=await tx.query<any>('SELECT * FROM workflow_candidates WHERE workflow_id=$1 AND plan_revision=$2 AND candidate_version=$3 ORDER BY level,user_id',[plan.workflowId,plan.planRevision,w.candidate_version]);
 const expected=manifest.stages.flatMap((s:any)=>s.candidates.map((c:any)=>({level:s.level,...c})));if(candidates.length!==expected.length
  ||new Set(candidates.map(c=>`${c.level}:${c.user_id}`)).size!==candidates.length)throw invalid();
 for(const c of candidates){bound(c);const original=expected.find((o:any)=>o.level===c.level&&o.userId===c.user_id);if(!original||c.manifest_hmac!==w.candidate_manifest_hmac||String(c.credential_epoch)!==original.credentialEpoch)throw invalid();same(c.provenance,original.provenance);}
 const set=await tx.one<any>('SELECT * FROM workflow_approval_sets WHERE id=$1',[w.approval_set_id]);bound(set);
 const material={version:1,clusterId:plan.clusterId,workspaceId:plan.workspaceId,workflowId:plan.workflowId,planRevision:plan.planRevision,planHash:secrets.fingerprint(plan),policyHash:plan.definition.policyHash,
  candidateVersion:w.candidate_version,candidateManifestHmac:w.candidate_manifest_hmac,reviewers};
 if(set.set_hmac!==w.approval_set_hmac||e.approval_set_id!==set.id||e.approval_set_hmac!==set.set_hmac||secrets.fingerprint(material)!==set.set_hmac)throw invalid();same(set.manifest,material);
 const members=await tx.query<any>('SELECT * FROM workflow_approval_set_members WHERE set_id=$1 ORDER BY level,user_id,approval_id',[set.id]);if(members.length!==reviewers.length
  ||new Set(members.map(member=>member.approval_id)).size!==members.length)throw invalid();
 for(const member of members){bound(member);const r=reviewers.find(r=>r.approvalId===member.approval_id);if(!r||member.set_hmac!==set.set_hmac||member.user_id!==r.userId||member.level!==r.level||member.candidate_version!==w.candidate_version||member.candidate_manifest_hmac!==w.candidate_manifest_hmac)throw invalid();}
 return{id:set.id,hmac:set.set_hmac};
}

function isSupportedKongBuild(v: unknown): boolean { return typeof v === 'string' && isSupportedKong(v.replace(/[-+].*$/, '')); }
