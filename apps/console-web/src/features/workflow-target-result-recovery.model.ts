import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { workflowReceiptMatches } from '../api/workflow-recovery';
import type { Workflow, WorkflowReceipt } from './portal.types';
import type { NativeChangeHistory, WorkflowIdentity, WorkflowWriteAttempt } from './workflow-entity-change.model';

type Packet = NativeChangeHistory['packets'][number];
export type WorkflowTargetResultWorkflow = Workflow;
export interface WorkflowTargetResultContext {
  /** Supply useAuth/getApiActorId from the currently authenticated session. */
  authenticatedActorId?: string;
  identity: WorkflowIdentity;
  readonlyWorkspace?: boolean;
  /** An existing unknown-request fence must remain in place. This operation
   * closes its original metadata and never opens another execute request. */
  writeBlocked?: boolean;
}
export interface WorkflowTargetResultRecoveryReference {
  readonly actorId: string;
  readonly permissionsVersion: string;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly workflowId: string;
  readonly executionId: string;
  readonly workflowRevision: number;
  readonly planRevision: number;
  readonly planHash: string;
  readonly originalExecutionKey: string;
}
const record = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && canonicalId(value) === value;
const positiveInteger = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0;
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const unavailable = () => new Error('请在当前账号和范围下核验原执行回执，不能创建新的执行键。');

function originalWorkflow(value: unknown, context: WorkflowTargetResultContext): value is WorkflowTargetResultWorkflow {
  const identity = context?.identity;
  if (!identity || !id(context.authenticatedActorId) || identity.actor !== context.authenticatedActorId
    || !id(identity.cid) || !id(identity.wid) || typeof identity.version !== 'string' || !identity.version.trim()
    || !record(value) || value.id === undefined
    || !id(value.id) || value.clusterId !== identity.cid || value.workspaceId !== identity.wid
    || value.kind !== 'native-change' || value.name !== 'native-change' || !['uncertain', 'succeeded'].includes(value.state)
    || !positiveInteger(value.revision) || !positiveInteger(value.planRevision) || !hash(value.planHash)
    || identity.mode !== undefined && identity.mode !== value.executionMode
    || !record(value.nativeChange)
    || !id(value.nativeChange.executionId) || !Array.isArray(value.nativeChange.packets) || value.nativeChange.packets.length !== 1) return false;
  const packet = value.nativeChange.packets[0];
  return record(packet) && packet.entityType === 'targets' && id(packet.entityId) && id(packet.operationId)
    && typeof packet.key === 'string' && packet.key.length > 0 && packet.key.length <= 160 && packet.order === 1
    && ['uncertain', 'sent-unknown'].includes(packet.state) && packet.nativeStatus === null;
}
function currentWorkflow(value: unknown, context: WorkflowTargetResultContext): value is WorkflowTargetResultWorkflow {
  return originalWorkflow(value, context) && value.state === 'uncertain' && context.readonlyWorkspace !== true
    && value.nativeChange?.targetResultReconciliationAvailable === true;
}

function currentReceipt(value: unknown, workflow: WorkflowTargetResultWorkflow, key: string): value is WorkflowReceipt {
  const ref = { clusterId: workflow.clusterId, workspaceId: workflow.workspaceId, idempotencyKey: key, kind: 'workflow' as const };
  return workflowReceiptMatches(value, ref) && value.action === 'execute' && value.workflowId === workflow.id
    && value.id === workflow.nativeChange!.executionId && value.executionId === value.id && value.state === 'uncertain'
    && value.revision === workflow.revision && value.planHash === workflow.planHash
    && value.steps.length === 1 && value.steps[0].name === 'entity.change' && value.steps[0].state === 'uncertain'
    && value.steps[0].operationId === null && value.steps[0].remoteStarted === true && value.steps[0].remoteCompleted === false;
}

/** The original-key journal is only a locator. Root must fetch the by-key
 * receipt through the current authenticated BFF, which checks the execution
 * actor and scope. No local journal/DTO supplies backend authorization. */
export function workflowTargetResultRecoveryReference(workflow: unknown, context: WorkflowTargetResultContext,
  originalExecuteAttempt: unknown, authenticatedOriginalReceipt: unknown): Readonly<WorkflowTargetResultRecoveryReference> | undefined {
  const locator = workflowTargetResultOriginalReference(workflow, context, originalExecuteAttempt);
  if (!locator || !currentWorkflow(workflow, context)
    || !currentReceipt(authenticatedOriginalReceipt, workflow, locator.originalExecutionKey)) return undefined;
  return locator;
}

/** Locate a receipt using this tab's existing execute journal. This does not
 * grant metadata-write authority; the current actor-bound receipt is required
 * separately before confirmation can become available. */
export function workflowTargetResultOriginalReference(workflow: unknown, context: WorkflowTargetResultContext,
  originalExecuteAttempt: unknown): Readonly<WorkflowTargetResultRecoveryReference> | undefined {
  if (!originalWorkflow(workflow, context) || !record(originalExecuteAttempt)) return undefined;
  const attempt = originalExecuteAttempt as WorkflowWriteAttempt, identity = context.identity;
  if (attempt.actor !== identity.actor || attempt.cid !== identity.cid || attempt.wid !== identity.wid
    || attempt.subject !== workflow.id || attempt.action !== 'execute' || !id(attempt.key)
    || !['pending', 'unknown', 'failed'].includes(attempt.state) || attempt.planHash !== workflow.planHash
    || !positiveInteger(attempt.revision) || attempt.revision > workflow.revision) return undefined;
  // Permission-version changes do not erase an original unknown journal.
  // This reference captures the current authenticated version for the modal.
  return Object.freeze({ actorId: identity.actor!, permissionsVersion: identity.version!, clusterId: workflow.clusterId,
    workspaceId: workflow.workspaceId, workflowId: workflow.id, executionId: workflow.nativeChange!.executionId!,
    workflowRevision: workflow.revision, planRevision: workflow.planRevision, planHash: workflow.planHash,
    originalExecutionKey: attempt.key });
}

function validReference(value: unknown): value is WorkflowTargetResultRecoveryReference {
  return record(value) && [value.actorId, value.clusterId, value.workspaceId, value.workflowId, value.executionId, value.originalExecutionKey].every(id)
    && typeof value.permissionsVersion === 'string' && !!value.permissionsVersion.trim() && hash(value.planHash)
    && positiveInteger(value.workflowRevision) && positiveInteger(value.planRevision);
}

export function workflowTargetResultReceiptPath(reference: WorkflowTargetResultRecoveryReference): string {
  if (!validReference(reference)) throw unavailable();
  return scopeQuery(`/clusters/${reference.clusterId}/workflows/receipts/by-key/${reference.originalExecutionKey}`,
    reference.clusterId, reference.workspaceId);
}

/** Call only from the confirmed modal callback, after refetching the detail
 * and actor-bound original receipt. A scope/revision change closes the modal.
 * It sends metadata only with the original execute key, never a native retry. */
export function workflowTargetResultRecoveryRequest(reference: WorkflowTargetResultRecoveryReference,
  currentDetail: unknown, current: WorkflowTargetResultContext, authenticatedOriginalReceipt: unknown,
  confirmation: { confirmed: boolean; confirmName: string }): { path: string; options: RequestInit } {
  if (!validReference(reference) || confirmation?.confirmed !== true || confirmation.confirmName !== 'native-change'
    || !currentWorkflow(currentDetail, current) || current.identity.actor !== reference.actorId
    || current.identity.version !== reference.permissionsVersion || currentDetail.clusterId !== reference.clusterId
    || currentDetail.workspaceId !== reference.workspaceId || currentDetail.id !== reference.workflowId
    || currentDetail.nativeChange!.executionId !== reference.executionId || currentDetail.revision !== reference.workflowRevision
    || currentDetail.planRevision !== reference.planRevision || currentDetail.planHash !== reference.planHash
    || !currentReceipt(authenticatedOriginalReceipt, currentDetail, reference.originalExecutionKey)) throw unavailable();
  return { path: scopeQuery(`/clusters/${reference.clusterId}/workflows/${reference.workflowId}/reconcile-target-result`,
    reference.clusterId, reference.workspaceId), options: { method: 'POST', headers: { 'X-Idempotency-Key': reference.originalExecutionKey },
    body: JSON.stringify({ revision: reference.workflowRevision, planHash: reference.planHash, executionId: reference.executionId,
      confirmed: true, confirm_name: 'native-change' }) } };
}

/** Separate observation badge; retain the original packet state and NULL
 * native status. A badge alone never releases the local unknown-request fence. */
export function workflowTargetResultPacketObservation(packet: Packet): {
  state: string; nativeStatus: number | null; observationKnown: boolean; observationLabel?: string;
} {
  if (!record(packet) || typeof packet.state !== 'string' || packet.nativeStatus !== null
    && (!Number.isSafeInteger(packet.nativeStatus) || packet.nativeStatus < 100 || packet.nativeStatus > 599)) throw new Error('原逐步回执格式无效。');
  const proof = packet.targetResultObservation;
  const observationKnown = !!proof && id(proof.id) && id(proof.auditId) && hash(proof.eventHash)
    && typeof proof.observedAt === 'string' && Number.isFinite(Date.parse(proof.observedAt))
    && proof.kind === 'target-weight-zero-original-response-v1' && proof.operationId === packet.operationId
    && id(proof.operationId) && id(proof.workflowStepId) && proof.operationState === 'succeeded' && proof.nativeRequestsSent === 0
    && proof.originalNativeStatus === null && packet.nativeStatus === null && packet.entityType === 'targets'
    && ['sent-unknown', 'uncertain'].includes(packet.state);
  return { state: packet.state, nativeStatus: packet.nativeStatus, observationKnown,
    ...(observationKnown ? { observationLabel: '原结果已核验' } : {}) };
}
