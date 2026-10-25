import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import {
  KP007_ACCESS_DIMENSIONS,
  KP007_FAULT_FORBIDDEN_WITHOUT_COMPLETION,
  KP007_FAULT_HELD_STATES,
  KP007_SCHEDULE_KINDS,
  assertKp007AccessIdentity,
  assertKp007FaultFailClosed,
  assertKp007SingleWorkerClaim,
  assertKp007WorkerTickBounds,
  isKp007ScheduleKind,
} from '../../apps/console-api/src/modules/workflows/kp007-access-fault-contract';
import { WorkflowScheduledAuthorityService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import { WorkflowBusinessSchedulesWorker } from '../../apps/console-api/src/modules/workflows/workflow-business-schedules.worker';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';

beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'e7'.repeat(32));
  vi.stubEnv('APP_SECRET', 'kp007-access-fault-contract-'.repeat(2));
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-24T05:00:00.000Z'));
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

const uuid = () => randomUUID();
const hmac = (n = 1) => n.toString(16).repeat(64).slice(0, 64);

describe('KP-007 access/fault contract (pure fail-closed)', () => {
  it('enumerates the five matrix dimensions and four schedule kinds', () => {
    expect([...KP007_ACCESS_DIMENSIONS]).toEqual([
      'actor', 'cluster', 'workspace', 'entity', 'originalExecutor',
    ]);
    expect([...KP007_SCHEDULE_KINDS]).toEqual([
      'configuration_v2',
      'portal-credential-issue',
      'portal-credential-rotate',
      'portal-credential-revoke',
    ]);
    for (const kind of KP007_SCHEDULE_KINDS) expect(isKp007ScheduleKind(kind)).toBe(true);
    expect(isKp007ScheduleKind('entity-annotation')).toBe(false);
    expect([...KP007_FAULT_HELD_STATES]).toEqual(['failed', 'uncertain', 'claimed']);
    expect([...KP007_FAULT_FORBIDDEN_WITHOUT_COMPLETION]).toEqual(['succeeded', 'partial']);
  });

  it.each(KP007_ACCESS_DIMENSIONS)('rejects a mismatched %s dimension', (dim) => {
    const sealed = {
      actorId: uuid(), clusterId: uuid(), workspaceId: uuid(), entityId: uuid(), originalExecutorId: '',
    };
    sealed.originalExecutorId = sealed.actorId;
    const observed = { ...sealed };
    if (dim === 'actor') {
      observed.actorId = uuid();
      observed.originalExecutorId = observed.actorId;
    } else if (dim === 'cluster') observed.clusterId = uuid();
    else if (dim === 'workspace') observed.workspaceId = uuid();
    else if (dim === 'entity') observed.entityId = uuid();
    else {
      observed.originalExecutorId = uuid();
      // keep actorId so EXECUTOR_MISMATCH fires before EXECUTOR_NOT_ACTOR
    }
    expect(() => assertKp007AccessIdentity(sealed, observed)).toThrow(ForbiddenException);
  });

  it('accepts an exact five-dimension match and rejects executor≠actor', () => {
    const actorId = uuid();
    const tuple = {
      actorId, clusterId: uuid(), workspaceId: uuid(), entityId: uuid(), originalExecutorId: actorId,
    };
    expect(() => assertKp007AccessIdentity(tuple, { ...tuple })).not.toThrow();
    expect(() => assertKp007AccessIdentity(tuple, { ...tuple, originalExecutorId: uuid() }))
      .toThrow(/KP007_ACCESS_EXECUTOR/);
  });

  it('enforces single worker claim per schedule', () => {
    const scheduleId = uuid(), a = hmac(1), b = hmac(2);
    expect(() => assertKp007SingleWorkerClaim([
      { scheduleId, workerOwnerHmac: a, generation: 1 },
      { scheduleId: uuid(), workerOwnerHmac: b, generation: 1 },
    ])).not.toThrow();
    expect(() => assertKp007SingleWorkerClaim([
      { scheduleId, workerOwnerHmac: a },
      { scheduleId, workerOwnerHmac: a },
    ])).not.toThrow();
    expect(() => assertKp007SingleWorkerClaim([
      { scheduleId, workerOwnerHmac: a },
      { scheduleId, workerOwnerHmac: b },
    ])).toThrow(/KP007_SINGLE_CLAIM_MULTI_WORKER/);
    expect(() => assertKp007SingleWorkerClaim([
      { scheduleId, workerOwnerHmac: a, generation: 2 },
    ])).toThrow(/KP007_SINGLE_CLAIM_GENERATION/);
  });

  it.each([
    { progressState: 'failed', executorEntered: false, completionVerified: false, reacquired: false, finishedAsSuccess: false },
    { progressState: 'claimed', executorEntered: true, completionVerified: false, reacquired: false, finishedAsSuccess: false },
    { progressState: 'uncertain', executorEntered: true, completionVerified: false, reacquired: false, finishedAsSuccess: false },
    { progressState: 'succeeded', executorEntered: true, completionVerified: true, reacquired: false, finishedAsSuccess: true },
  ] as const)('accepts fail-closed fault observation %j', (obs) => {
    expect(() => assertKp007FaultFailClosed(obs)).not.toThrow();
  });

  it.each([
    { progressState: 'succeeded', executorEntered: true, completionVerified: false, reacquired: false, finishedAsSuccess: false },
    { progressState: 'partial', executorEntered: false, completionVerified: false, reacquired: false, finishedAsSuccess: false },
    { progressState: 'failed', executorEntered: false, completionVerified: false, reacquired: true, finishedAsSuccess: false },
    { progressState: 'active', executorEntered: true, completionVerified: false, reacquired: false, finishedAsSuccess: false },
    { progressState: 'failed', executorEntered: false, completionVerified: false, reacquired: false, finishedAsSuccess: true },
  ] as const)('rejects unsafe fault observation %j', (obs) => {
    expect(() => assertKp007FaultFailClosed(obs)).toThrow(ForbiddenException);
  });

  it('bounds worker tick counters', () => {
    expect(() => assertKp007WorkerTickBounds({ checked: 3, claimed: 1, completed: 1, blocked: 2, busy: false })).not.toThrow();
    expect(() => assertKp007WorkerTickBounds({ checked: 0, claimed: 0, completed: 0, blocked: 0, busy: true })).not.toThrow();
    expect(() => assertKp007WorkerTickBounds({ checked: 1, claimed: 2, completed: 0, blocked: 0, busy: false }))
      .toThrow(/KP007_TICK_CLAIMED_OVERFLOW/);
    expect(() => assertKp007WorkerTickBounds({ checked: 2, claimed: 1, completed: 0, blocked: 0, busy: false }))
      .toThrow(/KP007_TICK_UNACCOUNTED/);
    expect(() => assertKp007WorkerTickBounds({ checked: 1, claimed: 0, completed: 0, blocked: 0, busy: true }))
      .toThrow(/KP007_TICK_BUSY_NONZERO/);
  });
});

describe('KP-007 multi-worker single claim (business authority, no Kong)', () => {
  function installMutex(f: ReturnType<typeof workflowScheduledFixture>) {
    let chain: Promise<unknown> = Promise.resolve();
    f.redis.withLock.mockImplementation(async (_key: string, fn: () => Promise<unknown>) => {
      const run = chain.then(async () => {
        if (f.state.lease) throw new Error('Recursive lock acquisition');
        f.state.lease = true;
        try { return await fn(); } finally { f.state.lease = false; }
      });
      chain = run.then(() => undefined, () => undefined);
      return run;
    });
  }

  it.each([...KP007_SCHEDULE_KINDS] as const)('admits one claim for %s under concurrent dual acquire', async (kind) => {
    const f = workflowScheduledFixture(kind);
    f.install();
    installMutex(f);
    const [a, b] = await Promise.all([
      f.service.acquireDueClaim(f.scheduleId),
      f.service.acquireDueClaim(f.scheduleId),
    ]);
    const handles = [a, b].filter(Boolean);
    expect(handles).toHaveLength(1);
    expect(f.repository.appendDueClaim).toHaveBeenCalledTimes(1);
    const claim = f.state.stored.claim;
    expect(claim.generation).toBe(1);
    assertKp007SingleWorkerClaim([{ scheduleId: f.scheduleId, workerOwnerHmac: claim.workerOwnerHmac, generation: 1 }]);
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
  });

  it('second Authority instance cannot steal opaque handle or re-claim', async () => {
    const f = workflowScheduledFixture('portal-credential-rotate');
    f.install();
    const handle = await f.service.acquireDueClaim(f.scheduleId);
    expect(handle).not.toBeNull();
    const other = new WorkflowScheduledAuthorityService(
      f.db, f.secrets, f.redis, f.context, f.plans, f.approvals, f.repository,
    );
    // Restarted worker: own policy/executor/storage contract, distinct workerOwnerHmac.
    other.installBusinessPolicy('portal-credential-rotate', f.policy);
    other.installRepositoryPolicies('a'.repeat(64));
    other.installExecutor(f.executor);
    // Shared durable progress already claimed: second worker sees null (no second claim).
    await expect(other.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    expect(f.repository.appendDueClaim).toHaveBeenCalledTimes(1);
    // Opaque handle is private to the issuing Authority instance.
    await expect(other.executeClaim(handle!)).rejects.toBeDefined();
    expect(f.executor.executeClaim).not.toHaveBeenCalled();
    expect(f.state.stored.progress.state).toBe('claimed');
    assertKp007FaultFailClosed({
      progressState: 'claimed',
      executorEntered: false,
      completionVerified: false,
      reacquired: false,
      finishedAsSuccess: false,
    });
  });

  it('two workers racing tick yield a single execute for one due schedule', async () => {
    const handle = Object.freeze({});
    let acquired = 0;
    const acquire = vi.fn(async () => {
      if (acquired++) return null;
      return handle;
    });
    const execute = vi.fn(async () => undefined);
    const repo: any = { listDue: vi.fn(async () => [uuid()]) };
    const w1 = new WorkflowBusinessSchedulesWorker(repo);
    const w2 = new WorkflowBusinessSchedulesWorker(repo);
    w1.installFixedDelegate({ acquireDueClaim: acquire, executeClaim: execute });
    w2.installFixedDelegate({ acquireDueClaim: acquire, executeClaim: execute });
    const [t1, t2] = await Promise.all([w1.tick(), w2.tick()]);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledExactlyOnceWith(handle);
    const claimed = t1.claimed + t2.claimed;
    const completed = t1.completed + t2.completed;
    expect(claimed).toBe(1);
    expect(completed).toBe(1);
    assertKp007WorkerTickBounds(t1);
    assertKp007WorkerTickBounds(t2);
  });
});

describe('KP-007 IDOR matrix against sealed schedule identity', () => {
  it.each([...KP007_SCHEDULE_KINDS] as const)('blocks %s claim when a sealed dimension drifts', async (kind) => {
    const cases: Array<{ mutate: (f: ReturnType<typeof workflowScheduledFixture>) => void; code: RegExp }> = [
      { mutate: (f) => { f.draft.binding.clusterId = uuid(); }, code: /WORKFLOW_SCHEDULE_|KP007_ACCESS_/ },
      { mutate: (f) => { f.draft.binding.workspaceId = uuid(); }, code: /WORKFLOW_SCHEDULE_|KP007_ACCESS_/ },
      { mutate: (f) => { f.draft.binding.subjectId = uuid(); }, code: /WORKFLOW_SCHEDULE_|KP007_ACCESS_/ },
      { mutate: (f) => { f.draft.spec.executorId = uuid(); }, code: /WORKFLOW_SCHEDULE_|KP007_ACCESS_/ },
    ];
    for (const { mutate, code } of cases) {
      const f = workflowScheduledFixture(kind);
      f.install();
      mutate(f);
      f.state.stored = {
        draft: f.draft, plan: f.plan,
        progress: { state: 'active', revision: 1, claimId: null, reasonCode: null },
        activation: f.state.stored.activation, claim: null, latestLease: null,
      };
      // scope()/KP-007 both fail-closed: no claim append, no native. Drift may
      // surface as Conflict PLAN_CHANGED (scope) or Forbidden KP007_* (matrix).
      await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({
        response: expect.objectContaining({ code: expect.stringMatching(code) }),
      });
      expect(f.state.stored.progress.state).toBe('active');
      expect(f.state.stored.progress.claimId).toBeNull();
      expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
      expect(f.executor.executeClaim).not.toHaveBeenCalled();
    }
  });

  it('keeps foreign actor subject denial free of native side effects for rotate/revoke', async () => {
    for (const kind of ['portal-credential-rotate', 'portal-credential-revoke'] as const) {
      const f = workflowScheduledFixture(kind);
      f.install();
      f.state.scopeAllowed = false;
      await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
      expect(f.state.stored.progress.state).toBe('blocked');
      expect(f.state.stored.progress.reasonCode).toMatch(/SUBJECT_SCOPE|SCOPE/);
      expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
      expect(f.executor.executeClaim).not.toHaveBeenCalled();
    }
  });
});

describe('KP-007 fault-injection fail-closed (lease loss / mid-execute)', () => {
  it('pre-callback Redis lease loss fails closed without native send or reacquire', async () => {
    const f = workflowScheduledFixture('configuration_v2');
    f.install();
    const handle = await f.service.acquireDueClaim(f.scheduleId);
    expect(handle).not.toBeNull();
    f.redis.assertLeaseOwnership.mockRejectedValueOnce(
      new ForbiddenException({ code: 'LIVE_LEASE_REQUIRED' }),
    );
    await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({
      response: { code: 'LIVE_LEASE_REQUIRED' },
    });
    expect(f.executor.executeClaim).not.toHaveBeenCalled();
    expect(f.state.stored.progress.state).toBe('failed');
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    assertKp007FaultFailClosed({
      progressState: f.state.stored.progress.state,
      executorEntered: false,
      completionVerified: false,
      reacquired: false,
      finishedAsSuccess: f.state.stored.progress.state === 'succeeded',
    });
  });

  it('mid-callback authority denial holds the original claim without replay', async () => {
    const f = workflowScheduledFixture('portal-credential-issue');
    f.install();
    const handle = await f.service.acquireDueClaim(f.scheduleId);
    const claim = structuredClone(f.state.stored.claim);
    f.state.beforeExecute = async (original: object) => {
      f.state.scopeAllowed = false;
      await f.service.verifyClaim(original, 'before-send');
    };
    await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({
      response: { code: 'WORKFLOW_SCHEDULE_SUBJECT_SCOPE_DENIED' },
    });
    expect(f.state.stored.progress.state).toBe('claimed');
    expect(f.state.stored.claim).toEqual(claim);
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    assertKp007FaultFailClosed({
      progressState: 'claimed',
      executorEntered: true,
      completionVerified: false,
      reacquired: false,
      finishedAsSuccess: false,
    });
  });

  it('worker restart model: new Authority cannot finish a foreign worker claim as success', async () => {
    const f = workflowScheduledFixture('portal-credential-revoke');
    f.install();
    const handle = await f.service.acquireDueClaim(f.scheduleId);
    const foreignOwner = hmac(9);
    // Model a restarted worker observing the durable claim with a different owner hmac.
    f.state.stored.claim = { ...f.state.stored.claim, workerOwnerHmac: foreignOwner };
    f.state.stored.latestLease = { ...f.state.stored.latestLease, workerOwnerHmac: foreignOwner };
    await expect(f.service.executeClaim(handle!)).rejects.toBeDefined();
    expect(f.state.stored.progress.state).toBe('claimed');
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    assertKp007SingleWorkerClaim([
      { scheduleId: f.scheduleId, workerOwnerHmac: foreignOwner, generation: 1 },
    ]);
    assertKp007FaultFailClosed({
      progressState: 'claimed',
      executorEntered: false,
      completionVerified: false,
      reacquired: false,
      finishedAsSuccess: false,
    });
  });
});
