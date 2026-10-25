import 'reflect-metadata';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ServiceUnavailableException } from '@nestjs/common';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';
import { workflowSchedulePlanSeal } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T20:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M11 business schedule current authority (controlled SQL and fixed Root adapters)', () => {
  it('defaults closed and only installs each complete fixed policy/repository/executor once', async () => {
    const f = workflowScheduledFixture(); await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXECUTOR_UNAVAILABLE' } });
    expect(() => f.service.installBusinessPolicy('native-change' as any, f.policy)).toThrow();
    expect(() => f.service.installBusinessPolicy('configuration_v2', {} as any)).toThrow();
    f.install(); expect(() => f.service.installBusinessPolicy('configuration_v2', f.policy)).toThrow();
    expect(() => f.service.installRepositoryPolicies('a'.repeat(64))).toThrow(); expect(() => f.service.installExecutor(f.executor)).toThrow();
  });
  it('requires exact applied storage and a separately installed business kind policy', async () => {
    const f = workflowScheduledFixture(); f.install(); f.state.migration = false;
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_STORAGE_UNAVAILABLE' } }); expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
    const g = workflowScheduledFixture(); g.service.installRepositoryPolicies('a'.repeat(64)); g.service.installExecutor(g.executor);
    await expect(g.service.acquireDueClaim(g.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_BUSINESS_POLICY_UNAVAILABLE' } }); expect(g.repository.appendDueClaim).not.toHaveBeenCalled();
  });
  it('persists explicit real console acceptance in the same transaction while copied metadata proof is refused', async () => {
    const f = workflowScheduledFixture('portal-credential-issue'); f.install(); f.enterHttp();
    await f.service.persistPreparedDraft(f.draft, f.actor, f.db); expect(f.policy.assertDraft).toHaveBeenCalledTimes(2);
    expect(f.policy.assertRequester).toHaveBeenCalled(); expect(f.repository.persistDraft.mock.calls[0][3]).toBe(f.db);
    const original = f.repository.persistDraft.mock.calls[0][2];
    for (const copy of [{}, { ...original }, { accepted: true, executorId: f.owner }])
      await expect(f.delegate().verifyDraft(f.draft, f.actor, copy, f.db)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
    f.state.frame = null; await expect(f.service.persistPreparedDraft(f.draft, f.actor)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ACTUAL_ACTOR_REQUIRED' } });
  });
  it.each([{}, { actor: { id: randomUUID() }, sessionId: randomUUID() }, { purpose: 'system-read' }, { purpose: 'configuration', sessionId: null }])('refuses inherited frame %j without adopting or clearing it', async frame => {
    const f = workflowScheduledFixture(); f.install(); f.state.frame = frame;
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_BACKGROUND_CONTEXT_REQUIRED' } });
    expect(f.state.frame).toBe(frame); expect(f.repository.inspectStored).not.toHaveBeenCalled();
  });
  it.each(['owner', 'epoch', 'forcePasswordChange', 'reviewer', 'subject', 'physical', 'policy'])('records actual %s blocking without creating an occurrence claim', async reason => {
    const f = workflowScheduledFixture(); f.install();
    if (reason === 'owner') f.state.ownerActive = false;
    else if (reason === 'epoch') f.state.epoch = '2';
    else if (reason === 'forcePasswordChange') f.state.forceChange = true;
    else if (reason === 'reviewer') f.state.reviewerActive = false;
    else if (reason === 'subject') f.state.scopeAllowed = false;
    else if (reason === 'physical') f.state.conflict = true;
    else f.state.policyChanged = true;
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull(); expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
    expect(f.state.stored.progress.state).toBe('blocked'); expect(f.repository.appendBlocked).toHaveBeenCalledTimes(1);
    expect(f.executor.executeClaim).not.toHaveBeenCalled();
  });
  it('checks the actual Portal developer independently of the accepted console owner', async () => {
    const f = workflowScheduledFixture('portal-credential-issue'); f.install(); f.state.requesterActive = false;
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull(); expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
    expect(f.state.stored.progress.reasonCode).toBe('WORKFLOW_SCHEDULE_REQUESTER_REVOKED'); expect(f.owner).not.toBe(f.developer);
  });
  it('uses the genuine claim only once and checks all reviewers/current executor at each step and final wire checkpoint', async () => {
    const f = workflowScheduledFixture(); f.install(); const handle = await f.service.acquireDueClaim(f.scheduleId); expect(handle).not.toBeNull();
    for (const copied of [{}, { ...handle }, { claim: f.state.stored.claim, approved: true }]) await expect(f.service.verifyClaim(copied, 'inspect')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
    await expect(f.service.verifyClaim(handle!, 'packet')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXECUTOR_CALLBACK_REQUIRED' } });
    f.state.beforeExecute = async (original: object) => { for (const checkpoint of ['claim', 'capture', 'step', 'packet', 'before-send'] as const) {
      const inspected = await f.service.verifyClaim(original, checkpoint); expect(inspected.principal.id).toBe(f.owner); expect(inspected.approvalSet.reviewers).toHaveLength(3); } };
    await f.service.executeClaim(handle!); expect(f.state.stored.progress.state).toBe('succeeded'); expect(f.executor.verifyCompletion).toHaveBeenCalledTimes(3);
    expect(f.policy.assertReviewer.mock.calls.length).toBeGreaterThan(3 * 5); await expect(f.service.executeClaim(handle!)).rejects.toBeDefined();
    expect(f.executor.executeClaim).toHaveBeenCalledTimes(1); await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
  });
  it('allows mandatory-approved Portal issue on a direct cluster without synthesizing direct configuration consent', async () => {
    const f = workflowScheduledFixture('portal-credential-issue'); f.install();
    const reseal = () => { const { scheduling, ...base } = f.plan; f.draft.binding.basePlanHash = f.secrets.fingerprint(base); f.draft.delegation.basePlanHash = f.draft.binding.basePlanHash;
      f.draft.delegationHmac = f.secrets.fingerprint(f.draft.delegation); f.plan.scheduling = workflowSchedulePlanSeal(f.draft);
      f.draft.binding.workflowPlanHash = f.secrets.fingerprint(f.plan); f.state.stored.activation.workflowPlanHash = f.draft.binding.workflowPlanHash; };
    f.plan.executionMode = 'direct'; f.state.directMode = true; reseal(); const handle = await f.service.acquireDueClaim(f.scheduleId);
    expect(handle).not.toBeNull(); await f.service.executeClaim(handle!); expect(f.state.stored.progress.state).toBe('succeeded'); expect(f.plan.requester.id).toBe(f.developer);
    const g = workflowScheduledFixture(); g.install(); g.plan.approvalRequired = false;
    await expect(g.service.acquireDueClaim(g.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_DIRECT_CONSENT_UNAVAILABLE' } }); expect(g.repository.appendDueClaim).not.toHaveBeenCalled();
  });
  it('rejects the half-open end window and a current credential revocation before entering Root execution', async () => {
    const f = workflowScheduledFixture(); f.install(); const handle = await f.service.acquireDueClaim(f.scheduleId);
    vi.setSystemTime(new Date(f.draft.spec.windowEnd)); await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_WINDOW_EXPIRED' } });
    expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('failed'); expect(f.state.stored.progress.claimId).toBe(f.state.stored.claim.id);
    expect(f.state.outcomeEvidence.provenance).toBe('callback-not-entered');
  });
  it('attributes activation to the real HTTP accepting actor and rejects copied activation receipts after original proof consumption', async () => {
    const f = workflowScheduledFixture(); f.install(); f.enterHttp(); f.state.stored.progress.state = 'pending-approval';
    f.actor.requestId = randomUUID(); f.actor.ip = '127.0.0.1';
    await f.service.activateApproved(f.scheduleId, f.actor, f.db); expect(f.repository.activate.mock.calls[0][4]).toBe(f.actor);
    const call = f.repository.activate.mock.calls[0];
    await expect(f.delegate().verifyApproved(f.scheduleId, call[1], call[2], f.db, f.actor)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
  });
  it.each(['execution', 'origin', 'configuration_origin', 'mutation', 'configuration_execution', 'missing'])('never infers no-callback absence when actual %s facts are present or missing', async key => {
    const f = workflowScheduledFixture(); f.install(); const handle = await f.service.acquireDueClaim(f.scheduleId); f.state.ownerActive = false;
    if (key === 'missing') f.state.lifecycleFacts.execution = null; else f.state.lifecycleFacts[key] = true;
    await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXECUTOR_REVOKED' } });
    expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('claimed');
  });
  it('closes only genuine pre-callback known0 failure, retains claim and original workflow, and uses physical before progress lock order', async () => {
    const f = workflowScheduledFixture(); f.install(); const handle = await f.service.acquireDueClaim(f.scheduleId); f.state.ownerActive = false;
    await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXECUTOR_REVOKED' } });
    expect(f.state.stored.progress.state).toBe('failed'); expect(f.state.workflowState).toBe('approved'); expect(f.state.stored.progress.claimId).toBe(f.state.stored.claim.id);
    expect(f.state.outcomeEvidence).toMatchObject({ version: 1, provenance: 'callback-not-entered', evidenceHmac: expect.stringMatching(/^[a-f\d]{64}$/) });
    const calls = [...f.db.exec.mock.calls.map((c: any[], i: number) => ({ sql: c[0], order: f.db.exec.mock.invocationCallOrder[i] })),
      ...f.db.one.mock.calls.map((c: any[], i: number) => ({ sql: c[0], order: f.db.one.mock.invocationCallOrder[i] }))].sort((a, b) => a.order - b.order);
    const progress = calls.findIndex(c => c.sql.includes('FROM workflow_schedule_progress'));
    expect(progress).toBeGreaterThan(0); expect(calls.slice(0, progress).some(c => c.sql.includes('entity-schedule-impact:'))).toBe(true);
    expect(f.executor.executeClaim).not.toHaveBeenCalled(); await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
  });
  it('records conservative partial for an authentic completed config with failed wrapper metadata without inventing a no-callback source', async () => {
    const f = workflowScheduledFixture(); f.install(); f.executor.executeClaim.mockImplementation(async (_handle,begin) => { f.beginCallback(begin);f.state.outcome = 'partial'; return f.complete('partial', 'failed'); });
    const handle = await f.service.acquireDueClaim(f.scheduleId); await f.service.executeClaim(handle!);
    expect(f.state.workflowState).toBe('failed'); expect(f.state.nestedState).toBe('succeeded'); expect(f.state.stored.progress.state).toBe('partial');
    expect(f.state.outcomeEvidence.provenance).toBe('original-execution'); expect(f.executor.verifyCompletion).toHaveBeenCalledTimes(3);
  });
  it('will not relabel actual unknown native facts as failed/partial/succeeded from any genuine-looking callback result', async () => {
    const f = workflowScheduledFixture(); f.install(); f.executor.executeClaim.mockImplementation(async (_handle,begin) => { f.beginCallback(begin);f.state.nativeUnknown = true; f.state.outcome = 'partial'; return f.complete('partial', 'failed'); });
    const handle = await f.service.acquireDueClaim(f.scheduleId); await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID' } });
    expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('claimed'); expect(f.state.outcomeEvidence).toBeUndefined();
  });
  it('rejects mandatory Portal password change even with unchanged requester credential epoch at a later checkpoint', async () => {
    const f = workflowScheduledFixture('portal-credential-issue'); f.install(); f.state.beforeExecute = async (handle: object) => {
      await f.service.verifyClaim(handle, 'step'); f.state.forceRequesterChange = true; await f.service.verifyClaim(handle, 'before-send'); };
    const handle = await f.service.acquireDueClaim(f.scheduleId); await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_REQUESTER_REVOKED' } });
    expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('claimed');
  });
  it('does not turn infrastructure failure, copied completion or an unresolved occurrence into success/retry', async () => {
    const f = workflowScheduledFixture(); f.install(); f.policy.assertSubject.mockRejectedValueOnce(new ServiceUnavailableException({ code: 'READ_ADAPTER_UNAVAILABLE' }));
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toBeDefined(); expect(f.repository.appendBlocked).not.toHaveBeenCalled();
    const g = workflowScheduledFixture(); g.install(); g.executor.executeClaim.mockImplementation(async (_handle,begin) => {g.beginCallback(begin);return { outcome: 'succeeded', approved: true } as any;});
    const handle = await g.service.acquireDueClaim(g.scheduleId); await expect(g.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code: 'ORIGINAL_ROOT_COMPLETION_REQUIRED' } });
    expect(g.state.stored.progress.state).toBe('claimed'); expect(g.repository.finishClaim).not.toHaveBeenCalled();
    await expect(g.service.acquireDueClaim(g.scheduleId)).resolves.toBeNull(); expect(g.repository.appendDueClaim).toHaveBeenCalledTimes(1);
  });
});
