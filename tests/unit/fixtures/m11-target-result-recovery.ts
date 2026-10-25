import type { Workflow, WorkflowReceipt } from '../../../apps/console-web/src/features/portal.types';
import type { WorkflowWriteAttempt } from '../../../apps/console-web/src/features/workflow-entity-change.model';
export const targetRecoveryIds = {
  cid: '5b316db5-b0b7-4b91-8197-f893ecb76540', wid: 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor: 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40',
  key: 'fc843d08-7627-46f5-8cd0-93fc49f1af22', workflow: 'bc7bd065-9372-405d-9782-015d31a30aa1', execution: '631dde84-fd98-47a0-aa35-45f458595231',
  target: '9303db34-99cb-4ce3-b6f2-67b74370e01e', operation: 'fc5d7a72-dbec-43af-abcd-c65b0497641c',
  step: 'b4eaee06-9e7f-44fa-bfd4-cddc703c43dd', observation: '27a847b3-e2e1-4e6b-8245-4e2f6cc99b08', audit: '46863a31-e5bd-4c8e-9c76-741643c3a834',
  other: '9a72f30c-414d-4d10-9599-6b35b6297ff0',
};
export function targetRecoveryIdentity() { const ids = targetRecoveryIds; return { actor: ids.actor, cid: ids.cid, wid: ids.wid, version: 'actor:9' }; }
export function targetRecoveryAttempt(): WorkflowWriteAttempt {
  return { ...targetRecoveryIdentity(), subject: targetRecoveryIds.workflow, key: targetRecoveryIds.key, action: 'execute', revision: 4, planHash: 'a'.repeat(64), state: 'unknown' };
}
export function targetRecoveryWorkflow(completed = false): Workflow {
  const ids = targetRecoveryIds;
  return { id: ids.workflow, kind: 'native-change', name: 'native-change', clusterId: ids.cid, workspaceId: ids.wid, revision: completed ? 6 : 5,
    planRevision: 1, planHash: 'a'.repeat(64), state: completed ? 'succeeded' : 'uncertain', executionMode: 'approval', approvalRequired: true,
    createdAt: '2026-10-13T00:00:00.000Z', expiresAt: '2026-10-14T00:00:00.000Z', capabilities: { approve: false, reject: false, cancel: false, execute: false },
    nativeChange: { executionId: ids.execution, targetResultReconciliationAvailable: !completed, baseline: null,
      packets: [{ key: 'target-weight-zero', order: 1, entityType: 'targets', entityId: ids.target, operationId: ids.operation, state: 'sent-unknown', nativeStatus: null,
        errorCode: 'MUTATION_RESULT_UNCERTAIN', ...(completed ? { targetResultObservation: { id: ids.observation, auditId: ids.audit, eventHash: 'b'.repeat(64),
          observedAt: '2026-10-13T00:01:00.000Z', kind: 'target-weight-zero-original-response-v1' as const, nativeRequestsSent: 0 as const,
          originalNativeStatus: null, operationId: ids.operation, workflowStepId: ids.step, operationState: 'succeeded' as const } } : {}) }] } };
}
export function targetRecoveryReceipt(completed = false): WorkflowReceipt {
  const ids = targetRecoveryIds;
  return { id: ids.execution, executionId: ids.execution, workflowId: ids.workflow, clusterId: ids.cid, workspaceId: ids.wid, idempotencyKey: ids.key,
    action: 'execute', state: completed ? 'succeeded' : 'uncertain', revision: completed ? 6 : 5, planHash: 'a'.repeat(64),
    steps: [{ id: ids.step, name: 'entity.change', state: completed ? 'succeeded' : 'uncertain', operationId: null,
      remoteStarted: true, remoteCompleted: completed }], propagation: completed ? 'acknowledged' : 'pending' };
}
