import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { configurationApprovedFixture } from '../security/m8-configuration-approved-fixture';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ba'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

/** Actual Approved/ConfigurationVerifier, encrypted plans and Context-issued
 * capabilities. SQL, authz and Kong transport are explicit Source adapters.
 * No private registry seeding, real SQL/HTTP, timer or Native result is claimed. */
async function fixture() {
  const f = await configurationApprovedFixture();
  const run = (fn: (proof: any, input: any) => Promise<void>) => f.run(() =>
    f.verifier.runConfigurationExecution(f.executionId, () => f.context.runApprovedStep(f.jobStepId, async () => {
      const proof = f.context.currentApprovedStep(), binding = await f.verifier.mutationBinding(proof, f.mutation);
      const operation = f.op(binding); f.operations.set(operation.id, operation);
      await f.verifier.bindOperation(proof, f.mutation, binding, operation.id, f.db);
      operation.remote_started = true;
      const input: any = { frame: f.context.current(), cluster: f.cluster, clusterId: f.cid, workspaceId: f.wid,
        transportScope: f.job.transport_scope, operationId: operation.id, method: 'POST', canonicalPath: '/services',
        body: f.step.body, before: null, mutationAction: 'create', query: {}, result: { id: f.nativeId } };
      f.delegate.verifyExecution.mockClear(); f.kong.request.mockClear();
      await fn(proof, input);
    })));
  return { ...f, run };
}

describe('configuration Native retains its fresh complete load and post-currentBefore closing', () => {
  it.each(['authorize', 'prepare', 'before-send', 'response'] as const)('validates a real minted %s packet with only Native-owned complete loads', async stage => {
    const f = await fixture(); await f.run(async (proof, input) => {
      await f.verifier.assertNative(proof, input, stage);
      expect(f.delegate.verifyExecution).toHaveBeenCalledTimes(stage === 'before-send' ? 2 : 1);
      expect(f.kong.request).toHaveBeenCalledTimes(stage === 'before-send' ? 1 : 0);
      if (stage === 'before-send') expect(f.kong.request).toHaveBeenCalledExactlyOnceWith(f.cid, 'GET', `/services/${f.nativeId}`);
    });
  });
  it.each(['job', 'workspace', 'execution', 'permission', 'reviewer'] as const)('fresh Native load rejects current %s invalidation before currentBefore GET', async change => {
    const f = await fixture(); await f.run(async (proof, input) => {
      if (change === 'job') f.job.state = 'cancelled';
      if (change === 'workspace') f.ws.status = 'disabled';
      if (change === 'execution') f.execution.state = 'uncertain';
      if (change === 'permission') f.authz.permissionVersion.mockResolvedValue('changed-permissions');
      if (change === 'reviewer') f.approvalGrants.length = 0;
      await expect(f.verifier.assertNative(proof, input, 'before-send')).rejects.toThrow();
      expect(f.kong.request).not.toHaveBeenCalled();
    });
  });
  it.each(['job', 'permission', 'reviewer', 'deadline'] as const)('post-currentBefore complete load still rejects %s changes during its GET', async change => {
    const f = await fixture(); await f.run(async (proof, input) => {
      f.kong.request.mockImplementationOnce(async () => {
        if (change === 'job') f.job.state = 'cancelled';
        if (change === 'permission') f.authz.permissionVersion.mockResolvedValue('changed-permissions');
        if (change === 'reviewer') f.approvalGrants.length = 0;
        if (change === 'deadline') f.job.authority_expires_at = new Date(Date.now() - 1).toISOString();
        const error: any = Error('controlled-current-absence'); error.status = 404; throw error;
      });
      await expect(f.verifier.assertNative(proof, input, 'before-send')).rejects.toThrow();
      expect(f.kong.request).toHaveBeenCalledTimes(1); expect(f.delegate.verifyExecution).toHaveBeenCalledTimes(2);
    });
  });
  it('still rejects a changed currentBefore, without skipping the real point read', async () => {
    const f = await fixture(); await f.run(async (proof, input) => {
      f.kong.request.mockResolvedValueOnce({ id: f.nativeId, name: 'already-created' });
      await expect(f.verifier.assertNative(proof, input, 'before-send')).rejects.toMatchObject({ response: { code: 'CONFIGURATION_CURRENT_BEFORE_CHANGED' } });
      expect(f.kong.request).toHaveBeenCalledTimes(1);
    });
  });
  it.each(['body', 'query', 'operation', 'created-id'] as const)('keeps the actual Native %s packet rejection', async change => {
    const f = await fixture(); await f.run(async (proof, input) => {
      if (change === 'body') input.body = { ...input.body, host: 'foreign.invalid' };
      if (change === 'query') input.query = { unexpected: '1' };
      if (change === 'operation') input.operationId = f.nativeId;
      if (change === 'created-id') input.result = { id: f.jobId };
      await expect(f.verifier.assertNative(proof, input, change === 'created-id' ? 'response' : 'prepare')).rejects.toThrow();
      expect(f.kong.request).not.toHaveBeenCalled();
    });
  });
});
