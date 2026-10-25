import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { EntityScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.service';
import type { EntityScheduledContextRunner } from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.types';

/** Original-handle/lease/Root-context domain adapters only. Real SQL owner,
 * approver, source and native namespace acceptance remains Root's separate
 * integration gate; a valid-looking inspection is deliberately insufficient. */
function fixture() {
  const secrets = new SecretService(), owner = randomUUID(), cid = randomUUID(), wid = randomUUID(), now = Date.now();
  const expiresAt = new Date(now + 240000).toISOString(), authorityHandle = Object.freeze({}), known = new WeakSet<object>([authorityHandle]);
  const plan: any = { workflowId: randomUUID(), planRevision: 1, clusterId: cid, workspaceId: wid, kind: 'native-change',
    requester: { type: 'console', id: owner }, executionMode: 'approval', approvalRequired: true, expiresAt, steps: [{ metadata: 'fixed material' }] };
  const e: any = { version: 2, clusterId: cid, workspaceId: wid, requesterId: owner, credentialEpoch: '1', intentId: randomUUID(), revision: 1,
    expiresAt, executionMode: 'approval', prepared: { scope: { transportScope: 'a'.repeat(64), clusterRevision: 1, workspaceRevision: 1 }, privateFixture: 'immutable envelope' },
    scheduling: { specHmac: 'b'.repeat(64), delegationHmac: 'c'.repeat(64), delegation: { id: randomUUID(), ownerId: owner, executorId: owner, ownerCredentialEpoch: '1', executorCredentialEpoch: '1' } } };
  const inspection: any = { version: 1, envelope: e, plan, principal: { id: owner, username: 'current-sql-owner', superAdmin: false },
    permissionVersion: `${owner}:1:1`, authorityExpiresAt: expiresAt, leaseUntil: expiresAt,
    draft: { scheduleId: randomUUID(), binding: { clusterId: cid, workspaceId: wid, materialHmac: 'd'.repeat(64), changeDigest: 'e'.repeat(64), packetManifestHmac: 'f'.repeat(64) },
      spec: { windowStart: new Date(now - 1000).toISOString(), windowEnd: expiresAt } },
    approvalSet: { format: 2, policyHash: '1'.repeat(64), setId: randomUUID(), setHmac: '2'.repeat(64), reviewers: [{ approvalId: randomUUID(), userId: randomUUID(), level: 1, candidateVersion: 1 }] } };
  inspection.claim = { id: randomUUID(), scheduleId: inspection.draft.scheduleId, scheduleVersion: 1, occurrenceId: randomUUID(), generation: 1,
    workerOwnerHmac: '3'.repeat(64), issuedAt: new Date(now).toISOString(), authorityExpiresAt: expiresAt, initialLeaseUntil: expiresAt,
    workflowId: plan.workflowId, workflowPlanRevision: 1, workflowPlanHash: secrets.fingerprint(plan) };
  const state: any = { executing: false, leaseActive: false, ownerActive: true, reviewersActive: true, inheritedFrame: null, lastNamespace: null, pauseNext: false, resume: null };
  const current = () => immutableJson(inspection);
  const authority: any = { verifyClaim: vi.fn(async (handle: object) => {
    if (!known.has(handle) || !state.executing || !state.leaseActive) throw new ForbiddenException({ code: 'AUTHORITY_ORIGINAL_EXECUTION_REQUIRED' });
    if (!state.ownerActive || !state.reviewersActive) throw new ForbiddenException({ code: 'CURRENT_AUTHORIZATION_REVOKED' });
    if (Date.parse(expiresAt) <= Date.now()) throw new ForbiddenException({ code: 'AUTHORITY_WINDOW_EXPIRED' });
    if (state.pauseNext) { state.pauseNext = false; await new Promise<void>(resolve => { state.resume = resolve; }); }
    return current();
  }), inspect: vi.fn(async (handle: object) => { if (!known.has(handle)) throw new ForbiddenException(); return current(); }) };
  const redis: any = { assertLeaseActive: vi.fn(() => { if (!state.leaseActive) throw new ForbiddenException({ code: 'LIVE_REDIS_LEASE_REQUIRED' }); }),
    assertLeaseOwnership: vi.fn(async () => { if (!state.leaseActive) throw new ForbiddenException({ code: 'LIVE_REDIS_LEASE_REQUIRED' }); }) };
  const service = new EntityScheduledNamespaceService(authority, secrets, redis);
  const runner: EntityScheduledContextRunner = { assertNoFrame: vi.fn(() => { if (state.inheritedFrame !== null) throw new ForbiddenException({ code: 'NO_INHERITED_CONTEXT_REQUIRED' }); }),
    run: vi.fn(async <T>(handle: object, fn: () => Promise<T>): Promise<T> => {
      runner.assertNoFrame(); state.lastNamespace = handle; state.inheritedFrame = { originalNamespace: handle };
      try { await service.verifyHandle(handle, 'claim'); return await fn(); } finally { state.inheritedFrame = null; }
    }) };
  const install = () => service.installContextRunner(runner), execute = async <T>(fn: () => Promise<T>): Promise<T> => {
    state.executing = true; state.leaseActive = true;
    try { return await fn(); } finally { state.executing = false; state.leaseActive = false; }
  };
  return { service, authority, authorityHandle, runner, redis, state, inspection, secrets, install, execute };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T16:45:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M11 original scheduled namespace (source-only domain adapters)', () => {
  it('defaults closed and installs one complete fixed Root runner', async () => {
    const f = fixture(); await expect(f.service.runOriginalClaim(f.authorityHandle, async () => true)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_NOT_ENABLED' } });
    expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(() => f.service.installContextRunner({ run: f.runner.run } as any)).toThrow();
    f.install(); expect(() => f.install()).toThrow();
  });
  it('cannot issue outside the original live Authority callback or from an inspection/handle copy', async () => {
    const f = fixture(); f.install(); const callback = vi.fn(async () => true);
    await expect(f.service.runOriginalClaim(f.authorityHandle, callback)).rejects.toMatchObject({ response: { code: 'AUTHORITY_ORIGINAL_EXECUTION_REQUIRED' } });
    await f.execute(async () => {
      for (const copied of [{ ...f.authorityHandle }, { ...f.inspection }, { ...f.inspection.principal }])
        await expect(f.service.runOriginalClaim(copied, callback)).rejects.toMatchObject({ response: { code: 'AUTHORITY_ORIGINAL_EXECUTION_REQUIRED' } });
    }); expect(callback).not.toHaveBeenCalled(); expect(f.runner.run).not.toHaveBeenCalled();
  });
  it.each([{ sessionId: randomUUID() }, { actor: { id: randomUUID() }, module: 'system-read' }, {}])('refuses every inherited frame without clearing/adopting it', async frame => {
    const f = fixture(); f.install(); f.state.inheritedFrame = frame;
    await f.execute(() => expect(f.service.runOriginalClaim(f.authorityHandle, async () => true)).rejects.toMatchObject({ response: { code: 'NO_INHERITED_CONTEXT_REQUIRED' } }));
    expect(f.state.inheritedFrame).toBe(frame); expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(f.runner.run).not.toHaveBeenCalled();
  });
  it('projects genuine current SQL facts with no SID and full claim binding while copies remain unauthoritative', async () => {
    const f = fixture(); f.install(); await f.execute(() => f.service.runOriginalClaim(f.authorityHandle, async () => {
      const handle = f.state.lastNamespace, proof = await f.service.verifyHandle(handle, 'capture');
      expect(proof.origin).toBe('scheduled-entity'); expect(proof.sessionId).toBeNull(); expect(proof.actor.id).toBe(f.inspection.envelope.requesterId);
      expect(proof.claim).toMatchObject({ ...f.inspection.claim, clusterId: f.inspection.envelope.clusterId, workspaceId: f.inspection.envelope.workspaceId,
        ownerId: proof.actor.id, ownerCredentialEpoch: '1', delegationId: f.inspection.envelope.scheduling.delegation.id,
        delegationVersion: 1, delegationHmac: f.inspection.envelope.scheduling.delegationHmac, specHmac: f.inspection.envelope.scheduling.specHmac });
      expect(proof).not.toHaveProperty('authorityHandle'); expect(proof).not.toHaveProperty('originalAuthorityHandle'); expect(Object.isFrozen(proof.actor)).toBe(true);
      for (const copied of [{ ...handle }, { ...proof }, { ...proof.actor }]) {
        await expect(f.service.verifyHandle(copied, 'before-send')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED' } });
        expect(() => f.service.assertLive(copied)).toThrow();
      }
    }));
    await expect(f.service.verifyHandle(f.state.lastNamespace, 'packet')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED' } });
  });
  it.each(['ownerActive', 'reviewersActive'])('rechecks real current %s at every original checkpoint', async field => {
    const f = fixture(); f.install(); await f.execute(() => f.service.runOriginalClaim(f.authorityHandle, async () => {
      await f.service.verifyHandle(f.state.lastNamespace, 'packet'); f.state[field] = false;
      await expect(f.service.verifyHandle(f.state.lastNamespace, 'before-send')).rejects.toMatchObject({ response: { code: 'CURRENT_AUTHORIZATION_REVOKED' } });
    }));
  });
  it('fences exact sealed principal/permission/material tuples and does not accept a mutable inspection identity', async () => {
    const f = fixture(); f.install(); await f.execute(() => f.service.runOriginalClaim(f.authorityHandle, async () => {
      f.inspection.permissionVersion += ':changed'; await expect(f.service.verifyHandle(f.state.lastNamespace, 'packet')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_FACTS_CHANGED' } });
    }));
    const g = fixture(); g.install(); g.inspection.principal.id = randomUUID();
    await g.execute(() => expect(g.service.runOriginalClaim(g.authorityHandle, async () => true)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_FACTS_INVALID' } })); expect(g.runner.run).not.toHaveBeenCalled();
  });
  it('checks synchronous live Redis/expiry fences and dynamically rejects the half-open deadline', async () => {
    const f = fixture(); f.install(); await f.execute(() => f.service.runOriginalClaim(f.authorityHandle, async () => {
      const handle = f.state.lastNamespace; f.state.leaseActive = false;
      expect(() => f.service.assertLive(handle)).toThrow(); await expect(f.service.verifyHandle(handle, 'packet')).rejects.toMatchObject({ response: { code: 'LIVE_REDIS_LEASE_REQUIRED' } });
      f.state.leaseActive = true; vi.setSystemTime(new Date(f.inspection.authorityExpiresAt));
      expect(() => f.service.assertLive(handle)).toThrow(); await expect(f.service.verifyHandle(handle, 'before-send')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_EXPIRED' } });
    }));
  });
  it('issues one namespace for simultaneous calls and permanently invalidates it after either return or exception', async () => {
    const f = fixture(); f.install(); const callback = vi.fn(async () => 'done');
    const results = await f.execute(() => Promise.allSettled([f.service.runOriginalClaim(f.authorityHandle, callback), f.service.runOriginalClaim(f.authorityHandle, callback)]));
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1); expect(callback).toHaveBeenCalledTimes(1); expect(f.runner.run).toHaveBeenCalledTimes(1);
    expect(() => f.service.assertLive(f.state.lastNamespace)).toThrow();
    const g = fixture(); g.install(); await expect(g.execute(() => g.service.runOriginalClaim(g.authorityHandle, async () => { throw new Error('Root callback failed'); }))).rejects.toThrow('Root callback failed');
    expect(() => g.service.assertLive(g.state.lastNamespace)).toThrow();
  });
  it('refuses a verification completing after finally invalidated the original namespace', async () => {
    const f = fixture(); f.install(); let late: Promise<any>;
    await f.execute(() => f.service.runOriginalClaim(f.authorityHandle, async () => {
      f.state.pauseNext = true; late = f.service.verifyHandle(f.state.lastNamespace, 'before-send');
      // Let verification reach its actual dynamic Authority await, then return
      // without awaiting it, as an orphaned async task would.
      for (let step = 0; step < 4 && !f.state.resume; step++) await Promise.resolve();
      expect(f.state.resume).toBeTypeOf('function');
    }));
    const assertion = expect(late!).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED' } });
    f.state.resume(); await assertion;
  });
});
