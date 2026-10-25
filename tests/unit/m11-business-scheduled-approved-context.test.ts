import { describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

function fixture() {
  const context = new KongExecutionContextService(), namespaceHandle = Object.freeze({}), executionHandle = Object.freeze({});
  const namespace: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', sessionId: null,
    actor: Object.freeze({ id: 'executor' }), clusterId: 'cluster', workspaceId: 'workspace', kind: 'configuration_v2',
    permissionVersion: 'current-version', workflow: { id: 'workflow' }, claim: { id: 'claim' },
    expiresAt: new Date(Date.now() + 60000).toISOString() });
  let proof: any = Object.freeze({ executionId: 'execution', workflowId: 'workflow', actorId: 'executor', clusterId: 'cluster',
    workspaceId: 'workspace', sessionId: null, origin: 'scheduled-workflow', scheduleClaimId: 'claim',
    permissionVersion: 'current-version', expiresAt: Date.now() + 30000 });
  let originalProof = proof;
  context.installWorkflowScheduledNamespacePolicy({ assertLive(handle) { if (handle !== namespaceHandle) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); },
    async verifyHandle(handle) { if (handle !== namespaceHandle) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); return namespace; } });
  const verify = vi.fn(async (execution: any, handle: object) => {
    if (execution !== originalProof || handle !== namespaceHandle) throw Error('ORIGINAL_EXECUTION_REQUIRED');
  });
  const policy: any = { async verifyExecution(handle: object) { if (handle !== executionHandle) throw Error('ORIGINAL_HANDLE_REQUIRED'); return proof; },
    verifyWorkflowScheduledExecution: verify, async verifyStep() {}, async mutationBinding() {}, async bindOperation() {}, async assertNative() {}, async assertMetadata() {} };
  return { context, namespaceHandle, executionHandle, namespace, policy, verify,
    alter(change: Record<string, unknown>, authentic = false) { proof = Object.freeze({ ...proof, ...change }); if (authentic) originalProof = proof; } };
}

describe('approved business execution requires both original namespace and proof', () => {
  it('accepts a NULL SID only behind the original scheduled-workflow verification', async () => {
    const f = fixture(); f.context.installApprovedPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await f.context.runApprovedWorkflow(f.executionHandle as any, async () => {
        expect(f.context.current()).toMatchObject({ kind: 'actor', actor: { id: 'executor' }, clusterId: 'cluster', workspaceId: 'workspace' });
        expect(f.context.current().sessionId).toBeUndefined();
        expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.namespaceHandle);
      });
    });
    expect(f.verify).toHaveBeenCalledTimes(1);
  });
  it('missing explicit scheduled approved verifier keeps the NULL-SID branch closed', async () => {
    const f = fixture(); delete f.policy.verifyWorkflowScheduledExecution; f.context.installApprovedPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runApprovedWorkflow(f.executionHandle as any, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_APPROVED_POLICY_UNAVAILABLE' } });
    });
  });
  it('rejects a copied execution proof even when all visible fields match', async () => {
    const f = fixture(); f.context.installApprovedPolicy(f.policy); f.alter({});
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runApprovedWorkflow(f.executionHandle as any, async () => {})).rejects.toThrow('ORIGINAL_EXECUTION_REQUIRED');
    });
  });
  it.each([{ sessionId: 'old-browser-session' }, { origin: undefined }, { scheduleClaimId: 'foreign-claim' },
    { clusterId: 'foreign-cluster' }, { actorId: 'reviewer' }, { permissionVersion: 'old-grants' }])('rejects a mismatched scheduled binding %j', async change => {
    const f = fixture(); f.context.installApprovedPolicy(f.policy); f.alter(change, true);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runApprovedWorkflow(f.executionHandle as any, async () => {})).rejects.toMatchObject({ response: { code: 'APPROVED_EXECUTION_SCOPE_MISMATCH' } });
    });
    expect(f.verify).not.toHaveBeenCalled();
  });
  it('preserves genuine HTTP string SID execution and rejects background origin in HTTP', async () => {
    const f = fixture(); f.context.installApprovedPolicy(f.policy); f.alter({ origin: undefined, sessionId: 'real-session' }, true);
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor({ id: 'executor' } as any, 'real-session');
      await f.context.runActor({ actor: { id: 'executor' } as any, clusterId: 'cluster', workspaceId: 'workspace' }, async () => {
        await f.context.runApprovedWorkflow(f.executionHandle as any, async () => { expect(f.context.current().sessionId).toBe('real-session'); });
        f.alter({ origin: 'scheduled-workflow' }, true);
        await expect(f.context.runApprovedWorkflow(f.executionHandle as any, async () => {})).rejects.toMatchObject({ response: { code: 'APPROVED_EXECUTION_SCOPE_MISMATCH' } });
      });
    });
    expect(f.verify).not.toHaveBeenCalled();
  });
});
