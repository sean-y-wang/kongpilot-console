import 'reflect-metadata';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { WorkflowScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';
import type { WorkflowScheduledContextRunner } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.types';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';

function fixture(kind: 'configuration_v2' | 'portal-credential-issue' | 'portal-credential-rotate' | 'portal-credential-revoke' = 'configuration_v2') {
  const f = workflowScheduledFixture(kind), service = new WorkflowScheduledNamespaceService(f.service, f.secrets, f.redis);
  let last: object | null = null;
  const runner: WorkflowScheduledContextRunner = { assertNoFrame: vi.fn(() => { if (f.state.frame !== null) throw new ForbiddenException({ code: 'ORIGINAL_EMPTY_ALS_REQUIRED' }); }),
    run: vi.fn(async <T>(handle: object, fn: () => Promise<T>): Promise<T> => {
      runner.assertNoFrame(); last = handle; f.state.frame = { originalNamespaceHandle: handle };
      try { await service.verifyHandle(handle, 'claim'); return await fn(); } finally { f.state.frame = null; }
    }) };
  const run = async (callback: () => Promise<any>) => {
    f.executor.executeClaim.mockImplementation(async (authority: object,begin) => { await service.runOriginalClaim(authority,async()=>{f.beginCallback(begin,last!);return callback();}); return f.complete(); });
    const authority = await f.service.acquireDueClaim(f.scheduleId); await f.service.executeClaim(authority!); return authority!;
  };
  return { ...f, namespace: service, runner, last: () => last!, run, install: () => { f.install(); service.installContextRunner(runner); } };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T20:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M11 business original NULL-SID namespace (actual Authority, controlled SQL/Root runner)', () => {
  it('requires a once-installed complete Root runner and refuses an arbitrary or Entity-scheduled handle', async () => {
    const f = fixture();
    await expect(f.namespace.runOriginalClaim({}, async () => true)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_NAMESPACE_UNAVAILABLE' } });
    expect(() => f.namespace.installContextRunner({ run: f.runner.run } as any)).toThrow(); f.install();
    expect(() => f.namespace.installContextRunner(f.runner)).toThrow();
    for (const copied of [{}, { ...f.draft }, { approved: true, sessionId: null }, { origin: 'scheduled-entity' }])
      await expect(f.namespace.runOriginalClaim(copied, async () => true)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
  });
  it.each(['configuration_v2', 'portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke'] as const)('keeps %s genuine console principal separate from requester with no SID or copied authority', async kind => {
    const f = fixture(kind); f.install();
    await f.run(async () => { const handle = f.last(), proof = await f.namespace.verifyHandle(handle, 'capture');
      expect(proof.origin).toBe('scheduled-workflow'); expect(proof.sessionId).toBeNull(); expect(proof.actor.id).toBe(f.owner);
      expect(proof.requester.id).toBe(kind === 'configuration_v2' ? f.owner : f.developer); expect(proof.kind).toBe(kind); expect(proof.claim.executorId).toBe(f.owner);
      expect(proof.claim.delegationHmac).toBe(f.draft.delegationHmac); expect(proof.subjectSealHmac).toBe(f.secrets.fingerprint(f.draft.binding.subjectSeal));
      expect(proof).not.toHaveProperty('authorityHandle'); expect(proof).not.toHaveProperty('plan'); expect(Object.isFrozen(proof.actor)).toBe(true);
      for (const copy of [{ ...handle }, { ...proof }, { ...proof.actor }]) {
        await expect(f.namespace.verifyHandle(copy, 'before-send')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED' } });
        expect(() => f.namespace.assertLive(copy)).toThrow();
      }
    });
    await expect(f.namespace.verifyHandle(f.last(), 'step')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED' } });
  });
  it('cannot issue outside the actual original executor callback, even while the original SQL claim exists', async () => {
    const f = fixture(); f.install(); const handle = await f.service.acquireDueClaim(f.scheduleId), callback = vi.fn(async () => true);
    await expect(f.namespace.runOriginalClaim(handle!, callback)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXECUTOR_CALLBACK_REQUIRED' } });
    expect(callback).not.toHaveBeenCalled(); expect(f.runner.run).not.toHaveBeenCalled();
  });
  it('rejects inherited HTTP/read/capture ALS and never clears or adopts it', async () => {
    const f = fixture(); f.install(); const callback = vi.fn(async () => true);
    f.executor.executeClaim.mockImplementation(async (authority: object) => { const frame = { sessionId: 'ordinary-source-sid', purpose: 'system-read' }; f.state.frame = frame;
      await expect(f.namespace.runOriginalClaim(authority, callback)).rejects.toMatchObject({ response: { code: 'ORIGINAL_EMPTY_ALS_REQUIRED' } });
      expect(f.state.frame).toBe(frame); f.state.frame = null; return f.complete(); });
    const handle = await f.service.acquireDueClaim(f.scheduleId); await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED'}}); expect(callback).not.toHaveBeenCalled(); expect(f.runner.run).not.toHaveBeenCalled();
    expect(f.repository.finishClaim).not.toHaveBeenCalled();expect(f.state.stored.progress.state).toBe('claimed');
  });
  it.each(['epoch', 'reviewer', 'subject', 'requester', 'lease', 'deadline'])('rejects current %s revocation at the original final-wire checkpoint', async reason => {
    const f = fixture('portal-credential-issue'); f.install();
    await expect(f.run(async () => { await f.namespace.verifyHandle(f.last(), 'step');
      if (reason === 'epoch') f.state.epoch = '2'; else if (reason === 'reviewer') f.state.reviewerActive = false;
      else if (reason === 'subject') f.state.scopeAllowed = false; else if (reason === 'requester') f.state.requesterActive = false;
      else if (reason === 'lease') f.state.lease = false; else vi.setSystemTime(new Date(f.draft.spec.windowEnd));
      await f.namespace.verifyHandle(f.last(), 'before-send');
    })).rejects.toBeDefined(); expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('claimed');
  });
  it('binds current permission epoch and immutable full plan/draft/approval set rather than timestamp alone', async () => {
    const f = fixture(); f.install();
    await expect(f.run(async () => { await f.namespace.verifyHandle(f.last(), 'packet'); f.state.principalVersion = '2';
      await f.namespace.verifyHandle(f.last(), 'before-send'); })).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_NAMESPACE_FACTS_CHANGED' } });
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
  });
  it('issues one original namespace and retains truthful original completion after the window closes', async () => {
    const f = fixture(); f.install(); let seen = 0;
    f.executor.executeClaim.mockImplementation(async (authority: object,begin) => {
      await f.namespace.runOriginalClaim(authority, async () => { f.beginCallback(begin,f.last());seen++; await f.namespace.verifyHandle(f.last(), 'before-send'); });
      await expect(f.namespace.runOriginalClaim(authority, async () => true)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_NAMESPACE_ALREADY_ISSUED' } });
      vi.setSystemTime(new Date(f.draft.spec.windowEnd)); return f.complete();
    });
    const handle = await f.service.acquireDueClaim(f.scheduleId); await f.service.executeClaim(handle!);
    expect(seen).toBe(1); expect(f.state.stored.progress.state).toBe('succeeded'); expect(f.executor.verifyCompletion).toHaveBeenCalledTimes(3);
    expect(() => f.namespace.assertLive(f.last())).toThrow();
  });
});
