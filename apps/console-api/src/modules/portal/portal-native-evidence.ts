import { ConflictException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import type { SecretService } from '../../infrastructure/secret.service';
import { normalizedNativeRequests } from '../workflows/approved-execution.types';
import { planAad, type WorkflowPlanV1 } from '../workflows/workflow.types';
import { validateWorkflowPlan } from '../workflows/workflow-validation';
import { portalKeyAad } from './portal-proof';

export interface PortalIssueNativeEvidence {
  readonly grant: any; readonly credential: any; readonly workflow: any;
  readonly execution: any; readonly plan: WorkflowPlanV1; readonly rows: any[];
  readonly consumer: any; readonly acl: any; readonly keyCredential: any;
  readonly operationIds: readonly string[];
}
const invalid = () => new ConflictException({ code: 'PORTAL_CREDENTIAL_PROOF_INVALID', message: '门户凭证的原始成功账本证明不完整' });
const digest = /^[a-f\d]{64}$/;

/** Private, DB-only reconstruction. It never creates an actor, reads Kong or
 * turns a historical receipt into native execution authority. */
export async function loadPortalIssueNativeEvidence(tx: DbService, secrets: SecretService, input: {
  clusterId: string; workspaceId: string; grantId: string;
  parentState: 'executing' | 'uncertain' | 'succeeded'; executionId?: string; lock?: boolean;
}): Promise<PortalIssueNativeEvidence> {
  const { clusterId: cid, workspaceId: wid } = input, suffix = input.lock ? ' FOR UPDATE' : '';
  const grant = await tx.one<any>(`SELECT * FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3${suffix}`, [input.grantId, cid, wid]);
  const credential = await tx.one<any>(`SELECT * FROM portal_credentials WHERE grant_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND generation=1${suffix}`, [input.grantId, cid, wid]);
  if (!grant || !credential || grant.reservation_released_at || credential.consumer_id !== grant.consumer_id || credential.developer_id !== grant.developer_id) throw invalid();
  const workflow = await tx.one<any>(`SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3${suffix}`, [credential.workflow_id, cid, wid]);
  if (!workflow || workflow.state !== input.parentState || workflow.kind !== 'portal-credential-issue' || workflow.subject_type !== 'portal_application_grants'
    || workflow.subject_id !== grant.id || workflow.approval_required !== true || workflow.requester_type !== 'developer' || workflow.requester_developer_id !== grant.developer_id) throw invalid();
  const version = await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4', [workflow.id, cid, wid, workflow.plan_revision]);
  const execution = await tx.one<any>(`SELECT * FROM workflow_executions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4${suffix}`, [workflow.id, cid, wid, workflow.plan_revision]);
  if (!version || !execution || execution.state !== input.parentState || input.executionId && execution.id !== input.executionId
    || execution.approval_required !== true || execution.plan_hash !== workflow.plan_hash || version.plan_hash !== workflow.plan_hash
    || execution.approved_by !== workflow.approved_by || !execution.approved_by || execution.execution_mode !== workflow.execution_mode
    || version.execution_mode !== workflow.execution_mode || version.approval_required !== true) throw invalid();
  let plan: WorkflowPlanV1;
  try { plan = secrets.decrypt(version.payload_secret, planAad(cid, wid, workflow.id, workflow.plan_revision)); validateWorkflowPlan(plan); } catch { throw invalid(); }
  if (plan.clusterId !== cid || plan.workspaceId !== wid || plan.workflowId !== workflow.id || plan.planRevision !== workflow.plan_revision
    || plan.kind !== 'portal-credential-issue' || plan.subject.type !== 'portal_application_grants' || plan.subject.id !== grant.id
    || plan.requester.type !== 'developer' || plan.requester.id !== grant.developer_id || plan.approvalRequired !== true
    || plan.executionMode !== workflow.execution_mode || plan.scope.transportScope !== grant.transport_scope
    || secrets.fingerprint(plan) !== workflow.plan_hash || secrets.fingerprint(plan.steps) !== version.steps_hash
    || plan.steps.length !== 4 || version.step_count !== 4 || version.native_request_count !== 3) throw invalid();
  const metadata = plan.steps[3], payload: any = metadata.metadata;
  if (metadata.kind !== 'metadata' || metadata.handler !== 'portal.credential.activate' || metadata.entityType !== 'portal_application_grants'
    || metadata.entityId !== grant.id || metadata.nativeRequests.length || payload?.action !== 'issue' || payload.generation !== 1
    || metadata.permissionAction !== 'write' || secrets.fingerprint(metadata.dependencies) !== secrets.fingerprint([plan.steps[2].id])
    || payload.credentialId !== credential.id || payload.consumerId !== grant.consumer_id || payload.aclId !== grant.acl_id
    || payload.kongId !== credential.kong_id || payload.keyFingerprint !== credential.key_fingerprint
    || metadata.metadataPayloadHmac !== secrets.fingerprint(payload) || metadata.metadataBeforeHmac !== secrets.fingerprint(metadata.before)) throw invalid();
  let sealedKey: any;
  try { sealedKey = secrets.decrypt(credential.key_secret, portalKeyAad(cid, wid, credential.id, 1)); } catch { throw invalid(); }
  if (typeof sealedKey?.key !== 'string' || secrets.fingerprint(sealedKey.key) !== credential.key_fingerprint || !plan.generated
    || plan.generated.key !== sealedKey.key || plan.generated.consumerId !== grant.consumer_id || plan.generated.aclId !== grant.acl_id
    || plan.generated.credentialId !== credential.kong_id) throw invalid();
  const rows = await tx.query<any>(`SELECT * FROM workflow_steps WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY step_order${suffix}`, [workflow.id, cid, wid, workflow.plan_revision]);
  if (rows.length !== 4) throw invalid();
  const results: any[] = [], operationIds: string[] = [];
  for (const [index, step] of plan.steps.entries()) {
    const row = rows[index];
    if (row.id !== step.id || row.workflow_id !== workflow.id || row.cluster_id !== cid || row.workspace_id !== wid
      || row.plan_revision !== workflow.plan_revision || row.plan_hash !== workflow.plan_hash || row.kind !== step.kind || row.step_order !== step.order
      || row.step_key !== step.key || row.entity_type !== step.entityType || (row.entity_id ?? null) !== (step.entityId ?? null)
      || (row.parent_id ?? null) !== (step.parentId ?? null) || (row.credential_kind ?? null) !== (step.credentialKind ?? null)
      || row.permission_action !== step.permissionAction || (row.mutation_action ?? null) !== (step.mutationAction ?? null)
      || (row.handler ?? null) !== (step.handler ?? null) || (row.mutation_payload_hmac ?? null) !== (step.mutationPayloadHmac ?? null)
      || (row.before_fingerprint ?? null) !== (step.beforeFingerprint ?? null) || (row.mutation_idempotency_key ?? null) !== (step.mutationIdempotencyKey ?? null)
      || (row.metadata_before_hmac ?? null) !== (step.metadataBeforeHmac ?? null) || (row.metadata_payload_hmac ?? null) !== (step.metadataPayloadHmac ?? null)
      || (row.metadata_revision ?? null) !== (step.metadataRevision ?? null) || row.execution_mode !== plan.executionMode || row.approval_required !== true
      || secrets.fingerprint(row.dependencies) !== secrets.fingerprint(step.dependencies)
      || secrets.fingerprint(row.native_requests) !== secrets.fingerprint(normalizedNativeRequests(step.nativeRequests, secrets))) throw invalid();
    if (index === 3) {
      if (row.operation_id || row.state !== (input.parentState === 'succeeded' ? 'succeeded' : input.parentState === 'uncertain' ? 'uncertain' : 'running')) throw invalid();
      continue;
    }
    const request = step.nativeRequests[0], kind = index === 0 ? undefined : index === 1 ? 'acls' : 'key-auth';
    const nativeId = index === 0 ? grant.consumer_id : index === 1 ? grant.acl_id : credential.kong_id;
    if (step.kind !== 'native' || step.mutationAction !== 'create' || step.entityId != null || step.nativeRequests.length !== 1
      || step.permissionAction !== 'write' || secrets.fingerprint(step.dependencies) !== secrets.fingerprint(index ? [plan.steps[index - 1].id] : [])
      || step.entityType !== (index === 0 ? 'consumers' : 'credentials') || step.credentialKind !== kind
      || step.parentId !== (index === 0 ? undefined : grant.consumer_id) || request?.method !== 'POST' || request.nativeId !== nativeId
      || request.nativeType !== (kind ?? 'consumers') || request.parentId !== step.parentId || request.credentialKind !== kind
      || request.canonicalPath !== (index === 0 ? '/consumers' : `/consumers/${grant.consumer_id}/${kind}`)
      || (request.body as any)?.id !== nativeId || step.mutationPayloadHmac !== secrets.fingerprint(step.mutationPayload)
      || request.bodyHmac !== secrets.fingerprint(request.body) || request.bodyHmac !== step.mutationPayloadHmac || step.beforeFingerprint !== secrets.fingerprint(null)
      || step.before != null || row.state !== 'succeeded' || !row.operation_id || !digest.test(row.after_fingerprint ?? '')) throw invalid();
    const op = await tx.one<any>(`SELECT * FROM mutation_operations WHERE id=$1${suffix}`, [row.operation_id]);
    if (!op || op.cluster_id !== cid || op.workspace_id !== wid || op.transport_scope !== plan.scope.transportScope
      || op.actor_id !== execution.execution_actor_id || op.action !== 'create' || op.entity_type !== step.entityType || op.entity_id !== nativeId
      || (op.parent_id ?? null) !== (step.parentId ?? null) || (op.credential_kind ?? null) !== (kind ?? null)
      || op.workflow_id !== workflow.id || op.workflow_execution_id !== execution.id || op.workflow_plan_revision !== workflow.plan_revision
      || op.workflow_plan_hash !== workflow.plan_hash || op.workflow_step_id !== step.id || op.idempotency_key !== step.mutationIdempotencyKey
      || op.state !== 'succeeded' || op.remote_started !== true || op.remote_completed !== true || !op.result_secret) throw invalid();
    let original: any, rawPayload: any, raw: any;
    try {
      original = secrets.decrypt(op.before_secret, `mutation:${op.id}:before`);
      rawPayload = secrets.decrypt(op.payload_secret, `mutation:${op.id}:payload`);
      const result: any = secrets.decrypt(op.result_secret, `mutation:${op.id}:result`); raw = result?.entity ?? result;
    } catch { throw invalid(); }
    const binding = { workflowId: workflow.id, executionId: execution.id, planRevision: workflow.plan_revision, planHash: workflow.plan_hash, stepId: step.id, beforeHmac: step.beforeFingerprint };
    const requestHash = secrets.fingerprint({ actor: execution.execution_actor_id, clusterId: cid, workspaceId: wid, entityType: step.entityType,
      entityId: null, action: 'create', payload: step.mutationPayload ?? null, parentId: step.parentId ?? null, credentialKind: kind ?? null, approvedWorkflow: binding });
    if (original !== null || secrets.fingerprint(rawPayload) !== step.mutationPayloadHmac || op.request_hash !== requestHash
      || !raw || raw.id !== nativeId || secrets.fingerprint(raw) !== row.after_fingerprint
      || index > 0 && raw.consumer?.id !== grant.consumer_id || index === 1 && raw.group !== grant.acl_group
      || index === 2 && (typeof raw.key !== 'string' || secrets.fingerprint(raw.key) !== credential.key_fingerprint)) throw invalid();
    if (Buffer.byteLength(JSON.stringify(raw)) > 2 * 1024 * 1024) throw invalid();
    results.push(raw); operationIds.push(op.id);
  }
  return { grant, credential, workflow, execution, plan, rows, consumer: results[0], acl: results[1], keyCredential: results[2], operationIds };
}

/** Every generation uses the same first issuance proof, never an unbounded
 * previous-key chain or mutable information placed in the immutable key box. */
export function loadPortalGrantNativeEvidence(tx: DbService, secrets: SecretService, input: {
  clusterId: string; workspaceId: string; grantId: string;
}): Promise<PortalIssueNativeEvidence> {
  return loadPortalIssueNativeEvidence(tx, secrets, { ...input, parentState: 'succeeded' });
}
