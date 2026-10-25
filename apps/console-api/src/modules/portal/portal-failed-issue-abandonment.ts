import { BadRequestException, ConflictException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import type { DbService } from '../../infrastructure/db.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import type { AuditOutboxReceipt } from '../audit/audit.service';
import { deriveImpact, mergeImpact } from '../mutations/mutation-impact';
import { portalId } from './portal-input';

export interface RejectedIssueScope { clusterId:string; workspaceId:string; grantId:string; workflowId:string; executionId:string; }
/** Server-only current proof. Booleans/IDs from HTTP never authorize a native read or abandonment. */
export interface RejectedIssueProofV1 extends RejectedIssueScope {
  version:1;planRevision:number;planHash:string;actorId:string;sessionId:string;transportScope:string;observedAt:string;
  consumerId:string;consumerAbsent:true;aclId:string;aclAbsent:true;keyId:string;keyAbsent:true;
  clusterRevision:number;workspaceRevision:number;serviceId:string;serviceFingerprint:string;
  publicationId:string;publicationRevision:number;publicationProofHmac:string;factsHash:string;
}
export interface RejectedIssueAbandonmentInput extends RejectedIssueScope {
  planRevision:number;planHash:string;failedStepId:string;failedOperationId:string;actorId:string;sessionId:string;
  originalExecutionKey:string;requestHash:string;expectedGrantRevision:number;factsHash:string;
  proof:RejectedIssueProofV1;auditReceipt:AuditOutboxReceipt;
}
export interface PortalRejectedIssueCertificate {
  id:string;clusterId:string;workspaceId:string;grantId:string;workflowId:string;executionId:string;actorId:string;
  requestHash:string;reservationReleased:true;createdAt:string;
}
export interface RejectedIssueFacts {
  grant:any;workflow:any;execution:any;version:any;steps:any[];operation:any;credential:any;factsHash:string;
}
export const rejectedIssueProofAad=(cid:string,wid:string,grant:string,execution:string)=>`portal:failed-issue:${cid}:${wid}:${grant}:${execution}:proof`;
const invalid=()=>new ConflictException({code:'PORTAL_FAILED_ISSUE_PROOF_INVALID',message:'失败申请证明已变化，请核验原执行回执'});
const sha=(value:unknown)=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
function scope(input:RejectedIssueScope):void { for(const id of [input.clusterId,input.workspaceId,input.grantId,input.workflowId,input.executionId])portalId(id); }
function view(row:any):PortalRejectedIssueCertificate { return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,grantId:row.grant_id,workflowId:row.workflow_id,executionId:row.execution_id,actorId:row.actor_id,requestHash:row.request_hash,reservationReleased:true,createdAt:new Date(row.created_at).toISOString()}; }

/** Caller must pass its real SQL transaction. This repository is not an authorization capability. */
export async function loadRejectedIssueAbandonmentFacts(tx:DbService,input:RejectedIssueScope):Promise<RejectedIssueFacts> {
  scope(input);
  const grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE',[input.grantId,input.clusterId,input.workspaceId]);
  if(!grant||grant.workflow_id!==input.workflowId)throw invalid();
  try { await tx.query('SELECT m6_assert_rejected_issue_candidate($1)',[grant.id]); }
  catch(error:any) { if(error?.code==='23514')throw invalid();throw error; }
  const workflow=await tx.one<any>('SELECT * FROM workflows WHERE id=$1',[input.workflowId]),execution=await tx.one<any>('SELECT * FROM workflow_executions WHERE id=$1 AND workflow_id=$2',[input.executionId,input.workflowId]);
  if(!workflow||!execution||execution.cluster_id!==input.clusterId||execution.workspace_id!==input.workspaceId)throw invalid();
  const version=await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND plan_revision=$2',[workflow.id,workflow.plan_revision]);
  const steps=await tx.query<any>('SELECT * FROM workflow_steps WHERE workflow_id=$1 ORDER BY step_order',[workflow.id]);
  const operation=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[steps[0]?.operation_id]),credential=await tx.one<any>('SELECT * FROM portal_credentials WHERE grant_id=$1',[grant.id]);
  const factsHash=(await tx.one<any>('SELECT m6_rejected_issue_facts_hash($1) AS hash',[grant.id]))?.hash;
  if(!sha(factsHash))throw invalid();return{grant,workflow,execution,version,steps,operation,credential,factsHash};
}

/** Only the original execution actor and unchanged original client key can replay this receipt.
 * The endpoint still rechecks current session and source authority before this lookup. */
export async function getRejectedIssueAbandonment(tx:DbService,secrets:SecretService,input:{clusterId:string;workspaceId:string;workflowId:string;executionId:string;actorId:string;originalExecutionKey:string;requestHash?:string}):Promise<PortalRejectedIssueCertificate|null> {
  for(const id of [input.clusterId,input.workspaceId,input.workflowId,input.executionId,input.actorId])portalId(id);
  const row=await tx.one<any>('SELECT * FROM portal_failed_issue_abandonments WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND execution_id=$4 AND actor_id=$5 AND original_execution_key=$6',[input.clusterId,input.workspaceId,input.workflowId,input.executionId,input.actorId,input.originalExecutionKey]);
  if(!row)return null;if(input.requestHash!==undefined&&row.request_hash!==input.requestHash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
  let proof:RejectedIssueProofV1;
  try { proof=secrets.decrypt<RejectedIssueProofV1>(row.proof_secret,rejectedIssueProofAad(row.cluster_id,row.workspace_id,row.grant_id,row.execution_id)); }
  catch { throw invalid(); }
  const grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1',[row.grant_id]);
  const credential=await tx.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[row.credential_id]);
  const audit=await tx.one<any>('SELECT * FROM audit_events WHERE id=$1',[row.audit_event_id]);
  if(!grant||!credential||!audit||secrets.fingerprint(proof)!==row.proof_hmac||secrets.fingerprint(credential.key_secret)!==row.key_cipher_hmac
    ||proof.version!==1||proof.consumerAbsent!==true||proof.aclAbsent!==true||proof.keyAbsent!==true||proof.planRevision!==row.plan_revision
    ||Object.entries({clusterId:row.cluster_id,workspaceId:row.workspace_id,grantId:row.grant_id,workflowId:row.workflow_id,executionId:row.execution_id,
      actorId:row.actor_id,sessionId:row.session_id,planHash:row.plan_hash,factsHash:row.facts_hash,transportScope:row.transport_scope,
      consumerId:grant.consumer_id,aclId:grant.acl_id,keyId:credential.kong_id,publicationId:grant.publication_id}).some(([key,value])=>(proof as any)[key]!==value))throw invalid();
  // Exact immutable audit content is rehashed using the unchanged AuditService
  // record format. A future key rotation never permits a verification fallback.
  const auditRecord={id:audit.id,chain_scope:audit.chain_scope,sequence:String(audit.sequence),actor_id:audit.actor_id,actor_type:audit.actor_type,
    source_ip:audit.source_ip,cluster_id:audit.cluster_id,workspace_id:audit.workspace_id,entity_type:audit.entity_type,entity_id:audit.entity_id,
    action:audit.action,before:audit.before,after:audit.after,json_patch:audit.json_patch,workflow_id:audit.workflow_id,result:audit.result,
    request_id:audit.request_id,prev_hash:audit.prev_hash,occurred_at:new Date(audit.occurred_at).toISOString()};
  if(createHash('sha256').update(canonicalJson(auditRecord)).digest('hex')!==row.audit_event_hash)throw invalid();
  try { await tx.query('SELECT m6_assert_certified_failed_issue($1)',[row.grant_id]); }
  catch(error:any) { if(error?.code==='23514')throw invalid();throw error; }
  return view(row);
}

/** The caller has already locked/verified the sealed plan and performed exact
 * fresh native absence reads under the physical lock. Atomic order is grant CAS,
 * actual success audit, then this append-only certificate, then final fences and
 * COMMIT. Deferred SQL proves the released row against all retained native facts. */
export async function persistRejectedIssueAbandonment(tx:DbService,secrets:SecretService,input:RejectedIssueAbandonmentInput):Promise<PortalRejectedIssueCertificate> {
  scope(input);for(const id of [input.failedStepId,input.failedOperationId,input.actorId,input.sessionId,input.auditReceipt.id])portalId(id);
  if(!Number.isInteger(input.planRevision)||input.planRevision<1||!Number.isInteger(input.expectedGrantRevision)||input.expectedGrantRevision<1
    ||![input.planHash,input.requestHash,input.factsHash,input.auditReceipt.eventHash].every(sha)
    ||!/^[A-Za-z\d_.:-]{8,128}$/.test(input.originalExecutionKey))throw new BadRequestException({code:'PORTAL_FAILED_ISSUE_CERTIFICATE_INVALID'});
  const facts=await loadRejectedIssueAbandonmentFacts(tx,input),g=facts.grant,e=facts.execution,p=input.proof;
  const observed=Date.parse(p.observedAt);
  if(g.state!=='disabled'||!g.reservation_released_at||g.revision!==input.expectedGrantRevision+1||facts.factsHash!==input.factsHash
    ||facts.workflow.plan_revision!==input.planRevision||facts.workflow.plan_hash!==input.planHash||facts.steps[0].id!==input.failedStepId||facts.operation.id!==input.failedOperationId
    ||e.execution_actor_id!==input.actorId||e.idempotency_key!==input.originalExecutionKey||input.auditReceipt.chainScope!==`cluster:${input.clusterId}`
    ||p.version!==1||Object.entries({clusterId:input.clusterId,workspaceId:input.workspaceId,grantId:input.grantId,workflowId:input.workflowId,executionId:input.executionId,
      actorId:input.actorId,sessionId:input.sessionId,planHash:input.planHash,factsHash:input.factsHash,transportScope:g.transport_scope,
      consumerId:g.consumer_id,aclId:g.acl_id,keyId:facts.credential.kong_id,publicationId:g.publication_id}).some(([key,value])=>(p as any)[key]!==value)
    ||p.planRevision!==input.planRevision||p.consumerAbsent!==true||p.aclAbsent!==true||p.keyAbsent!==true
    ||!Number.isFinite(observed)||observed>Date.now()+1000||observed<Date.now()-15000
    ||![p.serviceFingerprint,p.publicationProofHmac].every(sha))throw invalid();
  portalId(p.serviceId);
  const cluster=await tx.one<any>('SELECT admin_url,transport_scope,revision,status,version FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[input.clusterId]);
  const workspace=await tx.one<any>('SELECT revision,status FROM workspaces WHERE cluster_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE',[input.clusterId,input.workspaceId]);
  // Lock the mutable publication's version pointer; proof history is append-only.
  // Locking the proof would require UPDATE privilege that the runtime must lack.
  const publication=await tx.one<any>(`SELECT p.service_id,p.published_revision,p.transport_scope,p.state,proof.publication_proof_hmac FROM portal_publications p JOIN portal_publication_proofs proof ON proof.cluster_id=p.cluster_id AND proof.workspace_id=p.workspace_id AND proof.publication_id=p.id AND proof.publication_revision=p.published_revision WHERE p.id=$1 AND p.cluster_id=$2 AND p.workspace_id=$3 FOR SHARE OF p`,[g.publication_id,input.clusterId,input.workspaceId]);
  if(!cluster||cluster.status==='disabled'||!/^1\.5\.\d+$/.test(cluster.version??'')||cluster.revision!==p.clusterRevision||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==p.transportScope
    ||!workspace||workspace.status!=='active'||workspace.revision!==p.workspaceRevision||!publication||publication.state!=='published'
    ||publication.service_id!==p.serviceId||publication.published_revision!==p.publicationRevision||publication.transport_scope!==p.transportScope||publication.publication_proof_hmac!==p.publicationProofHmac)throw invalid();
  const reservedImpact=mergeImpact(deriveImpact({entityType:'consumers',entityId:g.consumer_id,action:'create'}),deriveImpact({entityType:'credentials',entityId:g.acl_id,parentId:g.consumer_id,credentialKind:'acls',action:'create'}),deriveImpact({entityType:'credentials',entityId:facts.credential.kong_id,parentId:g.consumer_id,credentialKind:'key-auth',action:'create'}));
  await tx.query('SELECT m6_assert_rejected_issue_candidate($1,$2::jsonb)',[g.id,JSON.stringify(reservedImpact)]);
  const id=randomUUID();
  const row=await tx.one<any>(`INSERT INTO portal_failed_issue_abandonments(id,cluster_id,workspace_id,grant_id,workflow_id,execution_id,plan_revision,plan_hash,failed_step_id,failed_operation_id,credential_id,actor_id,session_id,original_execution_key,request_hash,transport_scope,original_grant_revision,facts_hash,reserved_impact,key_cipher_hmac,proof_secret,proof_hmac,absence_observed_at,audit_event_id,audit_event_hash)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20,$21,$22,$23,$24,$25) RETURNING *`,
    [id,input.clusterId,input.workspaceId,input.grantId,input.workflowId,input.executionId,input.planRevision,input.planHash,input.failedStepId,input.failedOperationId,facts.credential.id,input.actorId,input.sessionId,input.originalExecutionKey,input.requestHash,g.transport_scope,input.expectedGrantRevision,input.factsHash,JSON.stringify(reservedImpact),secrets.fingerprint(facts.credential.key_secret),secrets.encrypt(p,rejectedIssueProofAad(input.clusterId,input.workspaceId,g.id,e.id)),secrets.fingerprint(p),p.observedAt,input.auditReceipt.id,input.auditReceipt.eventHash]);
  if(!row)throw invalid();return view(row);
}
