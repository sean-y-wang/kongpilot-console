import type { ApiError } from './client';
import { canonicalId, scopeQuery } from './workspace-scope';
import type { ConsolePortalReceipt, Workflow, WorkflowMetadataRecoveryKind, WorkflowReceipt } from '../features/portal.types';
import type { WorkflowTargetResultRecoveryReference } from '../features/workflow-target-result-recovery.model';
type Recovery = NonNullable<ApiError['recovery']>;
export function portalWorkflowReceiptPath(reference: Recovery) { const cid = canonicalId(reference.clusterId), wid = canonicalId(reference.workspaceId), key = canonicalId(reference.idempotencyKey); if (!cid || !wid || !key || reference.domain || !['portal', 'workflow'].includes(reference.kind ?? '')) throw new Error('原门户 / 审批操作范围缺失，请保留原幂等键。'); return scopeQuery(`/clusters/${cid}/${reference.kind === 'portal' ? 'portal/operations' : 'workflows/receipts'}/by-key/${key}`, cid, wid); }
export function workflowReceiptMatches(receipt: unknown, reference: Recovery): receipt is WorkflowReceipt { const row = receipt as WorkflowReceipt; return !!row && !!canonicalId(row.id) && row.clusterId === reference.clusterId && row.workspaceId === reference.workspaceId && row.idempotencyKey === reference.idempotencyKey && Array.isArray(row.steps) && row.steps.length <= 512 && new Set(row.steps.map(step => step?.id)).size === row.steps.length && row.steps.every(step => !!step && !!canonicalId(step.id) && typeof step.state === 'string' && typeof step.remoteStarted === 'boolean' && typeof step.remoteCompleted === 'boolean'); }
export function workflowReceiptProvesCompletion(receipt: unknown, reference: Recovery) { if (!workflowReceiptMatches(receipt, reference)) return false; if (receipt.action === 'submit' && receipt.approvalRequired === true && receipt.submissionCompleted === true && ['pending', 'approved', 'rejected', 'cancelled', 'expired'].includes(receipt.state)) return true; if (receipt.decisionCompleted === true && (receipt.action === 'approve' && (receipt.state === 'approved' || receipt.executionRequested === false && ['pending', 'rejected', 'cancelled', 'expired'].includes(receipt.state)) || receipt.action === 'reject' && receipt.state === 'rejected' || receipt.action === 'cancel' && receipt.state === 'cancelled')) return true; if (workflowIssueAbandonmentCertificateComplete(receipt, reference)) return true; return receipt.state === 'succeeded' && receipt.steps.length > 0 && receipt.steps.every(step => step.state === 'succeeded' && step.remoteCompleted === true); }
export function consolePortalReceiptProvesCompletion(receipt: unknown, reference: Recovery) { const row = receipt as ConsolePortalReceipt; if (!row || reference.kind !== 'portal' || row.kind === 'not_sent') return false; if (row.kind === 'workflow') return workflowReceiptProvesCompletion(row.receipt, reference); const sql = row.receipt as any; return row.kind === 'iam' && !!canonicalId(sql?.id) && sql.cluster_id === reference.clusterId && sql.workspace_id === reference.workspaceId && ['succeeded', 'failed'].includes(sql.state) && sql.remote_completed === true; }
export function workflowRecoveryProvesCompletion(receipt: unknown, reference: Recovery) { return reference.kind === 'portal' ? consolePortalReceiptProvesCompletion(receipt, reference) : reference.kind === 'workflow' ? workflowReceiptProvesCompletion(receipt, reference) : false; }

/** A new authenticated observation closes the operation metadata while the
 * append-only native packet keeps its original unknown state and NULL status.
 * Only the actor-bound original-key receipt plus the current detail can close
 * this tab's original execute fence. */
export function workflowTargetResultProvesCompletion(receipt: unknown, workflow: Workflow,
  reference: WorkflowTargetResultRecoveryReference): receipt is WorkflowReceipt {
  if (![reference.actorId, reference.clusterId, reference.workspaceId, reference.workflowId, reference.executionId,
    reference.originalExecutionKey].every(value => typeof value === 'string' && canonicalId(value) === value)
    || !reference.permissionsVersion || !Number.isSafeInteger(reference.workflowRevision) || reference.workflowRevision < 1
    || !Number.isSafeInteger(reference.planRevision) || reference.planRevision < 1 || !/^[a-f\d]{64}$/.test(reference.planHash)
    || workflow.kind !== 'native-change' || workflow.name !== 'native-change' || workflow.state !== 'succeeded'
    || workflow.id !== reference.workflowId || workflow.clusterId !== reference.clusterId || workflow.workspaceId !== reference.workspaceId
    || workflow.planHash !== reference.planHash || workflow.planRevision !== reference.planRevision
    || !Number.isSafeInteger(workflow.revision) || ![reference.workflowRevision, reference.workflowRevision + 1].includes(workflow.revision)
    || workflow.nativeChange?.executionId !== reference.executionId || workflow.nativeChange.packets.length !== 1) return false;
  const packet = workflow.nativeChange.packets[0], proof = packet.targetResultObservation;
  if (!proof || proof.kind !== 'target-weight-zero-original-response-v1' || proof.operationState !== 'succeeded'
    || ![proof.id, proof.auditId, proof.operationId, proof.workflowStepId].every(value => typeof value === 'string' && canonicalId(value) === value)
    || !/^[a-f\d]{64}$/.test(proof.eventHash) || typeof proof.observedAt !== 'string' || !Number.isFinite(Date.parse(proof.observedAt))
    || proof.nativeRequestsSent !== 0 || proof.originalNativeStatus !== null || proof.operationId !== packet.operationId
    || packet.entityType !== 'targets' || packet.nativeStatus !== null || !['sent-unknown', 'uncertain'].includes(packet.state)) return false;
  if (!workflowReceiptMatches(receipt, { clusterId: reference.clusterId, workspaceId: reference.workspaceId,
    idempotencyKey: reference.originalExecutionKey, kind: 'workflow' }) || receipt.action !== 'execute' || receipt.state !== 'succeeded'
    || receipt.workflowId !== workflow.id || receipt.id !== reference.executionId || receipt.executionId !== reference.executionId
    || receipt.revision !== workflow.revision || receipt.planHash !== workflow.planHash || receipt.steps.length !== 1) return false;
  const step = receipt.steps[0];
  return step.id === proof.workflowStepId && step.name === 'entity.change' && step.state === 'succeeded'
    && step.operationId === null && step.remoteStarted === true && step.remoteCompleted === true;
}

export interface WorkflowMetadataRecoveryReference {
  actorId: string; clusterId: string; workspaceId: string; workflowId: string; idempotencyKey: string; permissionsVersion: string;
}

/** The original actor-bound by-key read supplies proof; a key input alone supplies no authority. */
export function workflowMetadataRecoveryEligible(receipt: unknown, workflow: Workflow, reference: WorkflowMetadataRecoveryReference): receipt is WorkflowReceipt {
  if (!canonicalId(reference.actorId) || !reference.permissionsVersion || !canonicalId(reference.workflowId)
    || !canonicalId(reference.clusterId) || !canonicalId(reference.workspaceId) || !canonicalId(reference.idempotencyKey)
    || reference.workflowId !== workflow.id || workflow.clusterId !== reference.clusterId || workflow.workspaceId !== reference.workspaceId
    || !['portal-credential-issue', 'workspace-migration'].includes(workflow.kind) || workflow.name !== workflow.kind
    || (workflow.kind === 'portal-credential-issue' ? workflow.state !== 'uncertain' : !['uncertain', 'partial'].includes(workflow.state))
    || workflow.capabilities?.reconcileMetadata !== true || !Number.isSafeInteger(workflow.revision) || workflow.revision < 1
    || !workflow.planHash || !workflowReceiptMatches(receipt, { ...reference, kind: 'workflow' })) return false;
  const row = receipt as WorkflowReceipt;
  if (row.workflowId !== workflow.id || !canonicalId(row.executionId) || row.id !== row.executionId
    || row.action !== 'execute' || row.state !== workflow.state || row.revision !== workflow.revision || row.planHash !== workflow.planHash
    || row.metadataRecovery?.eligible !== true || row.metadataRecovery.kind !== workflow.kind
    || row.metadataRecovery.executionId !== row.executionId || row.metadataRecovery.originalExecutionKeyRequired !== true
  ) return false;
  if (workflow.kind === 'workspace-migration') return row.metadataRecovery.kind === 'workspace-migration'
    && row.metadataRecovery.knownNativeComplete === true && row.metadataRecovery.completed === undefined && migrationNativeStepComplete(row);
  if (row.steps.length !== 4) return false;
  const names = ['consumers.create.1', 'credentials.create.2', 'credentials.create.3'];
  if (!row.steps.slice(0, 3).every((step, index) => step.name === names[index] && step.state === 'succeeded'
    && !!canonicalId(step.operationId) && step.remoteStarted === true && step.remoteCompleted === true)) return false;
  const final = row.steps[3];
  return final.name === 'portal.credential.activate' && final.state === 'uncertain' && final.operationId === null && final.remoteCompleted === false;
}

export function workflowMetadataRecoveryContextMatches(reference: WorkflowMetadataRecoveryReference, current: Omit<WorkflowMetadataRecoveryReference, 'idempotencyKey'>): boolean {
  return reference.actorId === current.actorId && reference.clusterId === current.clusterId && reference.workspaceId === current.workspaceId
    && reference.workflowId === current.workflowId && reference.permissionsVersion === current.permissionsVersion;
}

export function workflowMetadataReceiptPath(reference: WorkflowMetadataRecoveryReference): string {
  if (!canonicalId(reference.idempotencyKey)) throw new Error('请提供原执行幂等键，不会创建新的执行键。');
  return scopeQuery(`/clusters/${reference.clusterId}/workflows/receipts/by-key/${reference.idempotencyKey}`, reference.clusterId, reference.workspaceId);
}

function migrationNativeStepComplete(row: WorkflowReceipt): boolean {
  const step = row.steps[0];
  return row.steps.length === 1 && step.name === 'workspace-migration' && step.state === 'succeeded'
    && !!canonicalId(step.operationId) && step.remoteStarted === true && step.remoteCompleted === true;
}

function portalIssueStepsComplete(row: WorkflowReceipt): boolean {
  const names = ['consumers.create.1', 'credentials.create.2', 'credentials.create.3'];
  return row.steps.length === 4 && row.steps.slice(0, 3).every((step, index) => step.name === names[index]
    && step.state === 'succeeded' && !!canonicalId(step.operationId) && step.remoteStarted === true && step.remoteCompleted === true)
    && row.steps[3].name === 'portal.credential.activate' && row.steps[3].state === 'succeeded'
    && row.steps[3].operationId === null && row.steps[3].remoteCompleted === true;
}

/** Completion is tied to a fixed workflow kind; a different kind's native shape is never interchangeable. */
export function workflowMetadataRecoveryProvesCompletion(receipt: unknown, reference: WorkflowMetadataRecoveryReference, executionId: string, kind: WorkflowMetadataRecoveryKind = 'portal-credential-issue', originalPlanHash?: string): receipt is WorkflowReceipt {
  const row = receipt as WorkflowReceipt;
  if (!(!!canonicalId(reference.actorId) && !!reference.permissionsVersion && !!canonicalId(reference.workflowId)
    && !!canonicalId(reference.clusterId) && !!canonicalId(reference.workspaceId) && !!canonicalId(reference.idempotencyKey)
    && !!canonicalId(executionId) && workflowReceiptMatches(row, { ...reference, kind: 'workflow' })
    && row.workflowId === reference.workflowId && row.executionId === executionId && row.id === executionId && row.action === 'execute' && row.state === 'succeeded'
    && (originalPlanHash === undefined || row.planHash === originalPlanHash)
    && workflowReceiptProvesCompletion(row, { ...reference, kind: 'workflow' }))) return false;
  if (kind === 'portal-credential-issue') return (!row.metadataRecovery || row.metadataRecovery.kind === kind) && portalIssueStepsComplete(row);
  const proof = row.metadataRecovery;
  return kind === 'workspace-migration' && typeof originalPlanHash === 'string' && /^[a-f0-9]{64}$/.test(originalPlanHash)
    && proof?.kind === kind && proof.executionId === executionId
    && proof.originalExecutionKeyRequired === true && proof.eligible === false && proof.knownNativeComplete === true
    && proof.completed === true && migrationNativeStepComplete(row);
}

/** This is a metadata-only write. The request must never manufacture or replace the execution key. */
export function workflowMetadataRecoveryRequest(receipt: unknown, workflow: Workflow, reference: WorkflowMetadataRecoveryReference): { path: string; options: RequestInit } {
  if (!workflowMetadataRecoveryEligible(receipt, workflow, reference)) throw new Error('原执行回执尚未证明符合此工单的元数据恢复条件，请重新核验。');
  return {
    path: scopeQuery(`/clusters/${reference.clusterId}/workflows/${workflow.id}/reconcile-metadata`, reference.clusterId, reference.workspaceId),
    options: { method: 'POST', headers: { 'X-Idempotency-Key': reference.idempotencyKey }, body: JSON.stringify({ revision: workflow.revision, planHash: workflow.planHash, executionId: receipt.executionId, confirmed: true, confirm_name: workflow.name }) },
  };
}

function rejectedIssueStepsMatch(row: WorkflowReceipt): boolean {
  if (row.steps.length !== 4) return false;
  const first = row.steps[0], laterNames = ['credentials.create.2', 'credentials.create.3', 'portal.credential.activate'];
  return first.name === 'consumers.create.1' && first.state === 'failed' && !!canonicalId(first.operationId)
    && first.errorCode === 'KONG_VALIDATION_ERROR' && first.remoteStarted === true && first.remoteCompleted === false
    && row.steps.slice(1).every((step, index) => step.name === laterNames[index] && step.state === 'pending'
      && step.operationId === null && step.remoteStarted === false && step.remoteCompleted === false);
}

export function workflowIssueAbandonmentEligible(receipt: unknown, workflow: Workflow, reference: WorkflowMetadataRecoveryReference): receipt is WorkflowReceipt {
  if (!canonicalId(reference.actorId) || !reference.permissionsVersion || !canonicalId(reference.idempotencyKey)
    || !canonicalId(reference.clusterId) || !canonicalId(reference.workspaceId) || !canonicalId(reference.workflowId)
    || workflow.id !== reference.workflowId || workflow.clusterId !== reference.clusterId || workflow.workspaceId !== reference.workspaceId
    || workflow.kind !== 'portal-credential-issue' || workflow.name !== 'portal-credential-issue' || workflow.state !== 'failed'
    || workflow.capabilities?.abandonRejectedIssue !== true || !Number.isSafeInteger(workflow.revision) || workflow.revision < 1 || !workflow.planHash
    || !workflowReceiptMatches(receipt, { ...reference, kind: 'workflow' })) return false;
  const row = receipt as WorkflowReceipt, proof = row.issueAbandonment;
  return row.workflowId === workflow.id && row.action === 'execute' && row.state === 'failed'
    && !!canonicalId(row.executionId) && row.id === row.executionId && row.revision === workflow.revision && row.planHash === workflow.planHash
    && proof?.eligible === true && proof.completed === false && proof.kind === 'portal-credential-issue'
    && proof.executionId === row.executionId && !!canonicalId(proof.grantId) && proof.originalExecutionKeyRequired === true
    && proof.reservationReleased === false && proof.certificateId === undefined && rejectedIssueStepsMatch(row);
}

/** A failed workflow is terminal for closure only with the explicit durable certificate; it never becomes a successful issue. */
function workflowIssueAbandonmentCertificateComplete(receipt: unknown, reference: Recovery): boolean {
  if (!workflowReceiptMatches(receipt, reference)) return false;
  const row = receipt as WorkflowReceipt, proof = row.issueAbandonment;
  return !!canonicalId(row.workflowId) && !!canonicalId(row.executionId) && row.id === row.executionId
    && row.action === 'execute' && row.state === 'failed' && proof?.completed === true && typeof proof.eligible === 'boolean' && proof.reservationReleased === true
    && proof.kind === 'portal-credential-issue' && proof.executionId === row.executionId && !!canonicalId(proof.grantId)
    && !!canonicalId(proof.certificateId) && proof.originalExecutionKeyRequired === true && rejectedIssueStepsMatch(row);
}

export function workflowIssueAbandonmentProvesCompletion(receipt: unknown, reference: WorkflowMetadataRecoveryReference, executionId: string, grantId?: string): receipt is WorkflowReceipt {
  return !!canonicalId(executionId) && workflowReceiptMatches(receipt, { ...reference, kind: 'workflow' }) && workflowIssueAbandonmentCertificateComplete(receipt, { ...reference, kind: 'workflow' })
    && receipt.workflowId === reference.workflowId && receipt.executionId === executionId
    && (grantId === undefined || !!canonicalId(grantId) && receipt.issueAbandonment?.grantId === grantId);
}

export function workflowIssueAbandonmentRequest(receipt: unknown, workflow: Workflow, reference: WorkflowMetadataRecoveryReference): { path: string; options: RequestInit } {
  if (!workflowIssueAbandonmentEligible(receipt, workflow, reference)) throw new Error('原执行尚未证明符合明确失败申请关闭条件，请重新核验。');
  return {
    path: scopeQuery(`/clusters/${reference.clusterId}/workflows/${workflow.id}/abandon-rejected-issue`, reference.clusterId, reference.workspaceId),
    options: { method: 'POST', headers: { 'X-Idempotency-Key': reference.idempotencyKey }, body: JSON.stringify({ revision: workflow.revision, planHash: workflow.planHash, executionId: receipt.executionId, confirmed: true, confirm_name: workflow.name }) },
  };
}
