import type { ConfigurationWorkflowPlan } from '../../../apps/console-web/src/features/configuration-workflow.model';
export const id = (n: number) => `7f000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const identity = { actor: id(1), cid: id(2), wid: id(3), version: 'workflow-web-PV' };
export const requestKey = id(10), expiry = '2099-01-01T00:00:00.000Z';
export function sourcePlan(): ConfigurationWorkflowPlan {
  return { id: id(4), jobId: id(5), name: `配置计划 ${id(4)}`, clusterId: identity.cid, workspaceId: identity.wid, scope: 'workspace',
    revision: 2, planRevision: 1, planHash: 'a'.repeat(64), mode: 'merge', state: 'ready', expiresAt: expiry,
    executionMode: 'approval', approvalRequired: true, authorityDomain: 'legacy-http-v1', durableIssueId: null, workflowId: null,
    capabilities: { apply: true, durableSubmit: true }, recoveryComplete: true, blockers: [], stepCount: 1, nativePacketCount: 1, deleteCount: 0, deleteConfirmName: null };
}
export function publishedPlan(): ConfigurationWorkflowPlan {
  return { ...sourcePlan(), id: id(7), jobId: id(6), name: `配置计划 ${id(7)}`, state: 'pending_approval', planHash: 'b'.repeat(64),
    authorityDomain: 'durable-configuration-v1', durableIssueId: id(9), workflowId: id(8), capabilities: { apply: false, durableSubmit: false } };
}
/** Public jobProjection/plan DTO fixtures only; no fake backend authority or execution. */
export function receipt(state = 'waiting_approval'): any {
  const progress = { authorityDomain: 'durable-configuration-v1', durableIssueId: id(9), sourcePlanId: id(4), expiresAt: expiry };
  const job = { id: id(6), jobId: id(6), actorId: identity.actor, clusterId: identity.cid, workspaceId: identity.wid, kind: 'apply', state,
    planId: id(7), workflowId: id(8), executionMode: 'approval', approvalRequired: true, safeProgress: { ...progress }, ...progress };
  return { ...job, domain: 'configuration', durable: true, registrationCompleted: true, submissionCompleted: true,
    executionCompleted: ['succeeded', 'failed', 'partial', 'uncertain', 'cancelled'].includes(state), idempotencyKey: requestKey, job,
    originalScope: { clusterId: identity.cid, workspaceId: identity.wid } };
}
export function rejectedReceipt(): any {
  return { domain: 'configuration', authorityDomain: 'durable-configuration-v1', receiptKind: 'durable-submission-rejected-v1', result: 'rejected',
    commandCompleted: true, registrationCompleted: false, registrationRejected: true, submissionCompleted: false, knownNoEffect: true,
    effectScope: 'durable-registration', nativeWrites: 'none', newPreviewRequired: true, idempotencyKey: requestKey, actorId: identity.actor,
    clusterId: identity.cid, workspaceId: identity.wid, sourceJobId: id(5), sourcePlanId: id(4), sourcePlanRevision: 1, sourcePlanHash: 'a'.repeat(64),
    rejectionId: id(90), rejectedAt: '2026-10-15T12:00:00.000Z', code: 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED' };
}
