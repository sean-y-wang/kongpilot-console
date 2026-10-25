import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { fixedValidationFixture, fixedParentChild, fixedSourceWorkspaces } from './helpers/m11-fixed-validation-reader-fixture';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z')); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });
type Fixture = ReturnType<typeof fixedValidationFixture>;
function present(f: Fixture, count = 2) {
  f.outbound.mockClear();
  f.values.resources = Array.from({ length: count }, () => { const id = randomUUID(); return { clusterId: f.cid, workspaceId: f.wid,
    path: `/services/${id}`, kind: 'point', entityType: 'services', entityId: id, secrets: false, required: true }; });
  f.values.present = new Set(f.values.resources.map((r: any) => r.path));
}

describe('private fixed validation GET groups retain full admission and closing', () => {
  it.each(['executor', 'reviewer'] as const)('uses two complete currents for the fixed %s group while preserving every response policy', async role => {
    const f = fixedValidationFixture(); present(f); const current = vi.spyOn(f.service as any, 'current');
    const userId = role === 'reviewer' ? f.approvalSet.reviewers[0].userId : f.owner; let entered = false;
    await f.liveRead(async (_input: any, observations: any, usage: any) => {
      entered = true; expect(current).toHaveBeenCalledTimes(2); expect(observations.size).toBe(2); expect(usage.calls).toBe(2);
      expect(f.context.current().actor?.id).toBe(f.owner);
    }, userId, role);
    expect(entered).toBe(true); expect(current).toHaveBeenCalledTimes(2); expect(f.business.authorizeResponse).toHaveBeenCalledTimes(2);
    expect(f.business.authorizeResponse.mock.calls.every((c: any) => c[0].principal.user.id === userId)).toBe(true);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound.mock.calls.every(c => c[2] === 'GET')).toBe(true);
  });

  it('keeps the original generic group full current protocol after fixed-reader installation', async () => {
    const f = fixedValidationFixture(); present(f); const current = vi.spyOn(f.service as any, 'current');
    await f.run(async (handle: object) => { await f.rootRead(handle); });
    expect(current).toHaveBeenCalledTimes(17); expect(f.business.authorizeResponse).toHaveBeenCalledTimes(2);
  });

  it('retains original full fallback for a Root that has not installed a private fixed reader', async () => {
    const f = fixedValidationFixture(false); present(f); const current = vi.spyOn(f.service as any, 'current');
    await f.liveRead(async () => {}); expect(current).toHaveBeenCalledTimes(17);
  });

  it('installs only one fixed callback and never accepts a caller callback or light option', async () => {
    const f = fixedValidationFixture(); present(f);
    expect(() => f.runtime.installFixedValidationReader()).toThrow();
    expect(() => f.service.installFixedReader({ frame: () => ({}), read: async () => ({}) } as any)).toThrow();
    await expect(f.liveRead(async () => {}, f.owner, 'unknown' as any)).rejects.toBeDefined();
  });

  it.each(['approval', 'candidate', 'progress', 'claim', 'material', 'scope'] as const)('withholds all group results when %s changes before the complete closing', async reason => {
    const f = fixedValidationFixture(); present(f); let published = false;
    const original = f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (...args: any[]) => {
      const result = await original(...args);
      if (reason === 'approval') f.values.invalidated = true;
      if (reason === 'candidate') f.values.reviewerEpoch = '2';
      if (reason === 'progress') f.state.stored.progress.state = 'uncertain';
      if (reason === 'claim') f.state.stored.claim.workerOwnerHmac = '0'.repeat(64);
      if (reason === 'material') f.values.read = false;
      if (reason === 'scope') f.values.resources = f.values.resources.slice(1);
      return result;
    });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined();
    expect(published).toBe(false); expect(f.material.assertCurrentReadGrants).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['lease', 'owner-epoch', 'iam', 'registry', 'endpoint', 'workspace', 'grant', 'password', 'read'] as const)('rejects current %s changes at inner response fences before outer publication', async reason => {
    const f = fixedValidationFixture(); present(f); let published = false; const original = f.outbound.getMockImplementation()!;
    f.outbound.mockImplementation(async (...args: any[]) => {
      const result = await original(...args);
      if (reason === 'lease') f.state.lease = false;
      if (reason === 'owner-epoch') f.state.epoch = '2';
      if (reason === 'iam') f.state.principalVersion = '2';
      if (reason === 'registry') f.values.registryRevision = 2;
      if (reason === 'endpoint') { const one = f.db.one.getMockImplementation()!; f.db.one.mockImplementation(async (sql: string, args: any[]) => {
        const row = await one(sql, args); return row && sql.includes('FROM clusters') ? { ...row, admin_url: 'http://changed:8001' } : row;
      }); }
      if (reason === 'workspace') { const one = f.db.one.getMockImplementation()!; f.db.one.mockImplementation(async (sql: string, args: any[]) => {
        const row = await one(sql, args); return row && sql.includes('FROM workspaces') ? { ...row, status: 'disabled' } : row;
      }); }
      if (reason === 'grant') f.values.secretGrant = false;
      if (reason === 'password') f.state.forceChange = true;
      if (reason === 'read') f.values.read = false;
      return result;
    });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined(); expect(published).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('keeps the original complete 404/FK witness gates inside the fixed group', async () => {
    const f = fixedValidationFixture(); f.outbound.mockClear(); fixedParentChild(f); const current = vi.spyOn(f.service as any, 'current'); let values: any;
    await f.liveRead(async (_: any, observations: any, usage: any) => { values = [...observations.values()]; expect(usage.calls).toBe(1); expect(usage.records).toBe(1); });
    expect(current).toHaveBeenCalledTimes(6); expect(values.map((o: any) => o.absence)).toEqual(['sdk404', 'parent-FK-absence']);
    expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1); expect(f.outbound).toHaveBeenCalledTimes(1); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('closes each exact workspace group independently before merging results', async () => {
    const f = fixedValidationFixture(); present(f); f.values.resources[1].workspaceId = randomUUID(); fixedSourceWorkspaces(f);
    const current = vi.spyOn(f.service as any, 'current'); let observed: any;
    await f.liveRead(async (_: any, values: any) => { observed = values; }); expect(current).toHaveBeenCalledTimes(4); expect(observed.size).toBe(2);
  });

  it('rejects a same-actor descendant frame and poisons a caught inner failure', async () => {
    const f = fixedValidationFixture(); present(f); let published = false;
    const original = f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (resources: any, observations: any, capsule: any) => {
      await expect(f.context.runInternalRead(f.cid, 'authorization', () => f.service.verifyHandle(capsule.handle, f.nsHandle, f.ns),
        { paths: [resources[0].path], maxCalls: 1 })).rejects.toBeDefined();
      return original(resources, observations, capsule);
    });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined(); expect(published).toBe(false); expect(f.outbound).not.toHaveBeenCalled();
  });

  it.each(['lease', 'iam', 'database'] as const)('fails closed when %s changes while a fresh inner principal SQL awaits', async reason => {
    const f = fixedValidationFixture(); present(f); let reading = false, changed = false, published = false;
    const originalReader = f.runtime.readResources.bind(f.runtime), one = f.db.one.getMockImplementation()!;
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (...args: any[]) => { reading = true; return originalReader(...args); });
    f.db.one.mockImplementation(async (sql: string, args: any[]) => {
      const value = await one(sql, args);
      if (reading && !changed && sql.includes('jsonb_agg')) {
        changed = true;
        if (reason === 'lease') f.state.lease = false;
        if (reason === 'iam') f.state.principalVersion = '2';
        if (reason === 'database') throw Error('SOURCE_INNER_SQL_FAILURE');
      }
      return value;
    });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined();
    expect(changed).toBe(true); expect(published).toBe(false); expect(f.outbound).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('does not extend the original short group budget or publish an expired result', async () => {
    const f = fixedValidationFixture(); present(f); let published = false; const original = f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (...args: any[]) => { const value = await original(...args); vi.advanceTimersByTime(120001); return value; });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined(); expect(published).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('never reuses the original group handle or request after its closing', async () => {
    const f = fixedValidationFixture(); present(f); let handle: object; let token: object;
    const reader = f.runtime.readResources.bind(f.runtime), authorize = f.service.authorizeRequest.bind(f.service);
    vi.spyOn(f.runtime, 'readResources').mockImplementation((resources: any, observations: any, capsule: any) => { handle = capsule.handle; return reader(resources, observations, capsule); });
    vi.spyOn(f.service, 'authorizeRequest').mockImplementation(async (h: object, request: any) => { token = await authorize(h, request); return token; });
    await f.liveRead(async () => {});
    await expect(f.service.verifyHandle(handle!, f.nsHandle, f.ns)).rejects.toBeDefined();
    await expect(f.service.verifyHandle({ ...handle! }, f.nsHandle, f.ns)).rejects.toBeDefined();
    await expect(f.service.verifyRequest(token!)).rejects.toBeDefined(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects unconsumed requests and withholds results even when the fixed reader returns', async () => {
    const f = fixedValidationFixture(); present(f, 1); let published = false;
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (resources: any, _: any, capsule: any) => {
      const r = resources[0]; await f.service.authorizeRequest(capsule.handle, { clusterId: r.clusterId, workspaceId: r.workspaceId, path: r.path, method: 'GET', query: {} }); return 0;
    });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined(); expect(published).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'] as const)('keeps %s forbidden inside the genuine fixed group', async method => {
    const f = fixedValidationFixture(); present(f, 1); let published = false;
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (resources: any) => { await f.kong.request(f.cid, method, resources[0].path, { id: resources[0].entityId }); return 0; });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined(); expect(published).toBe(false); expect(f.outbound).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('keeps later groups independently fresh when an earlier group completed', async () => {
    const f = fixedValidationFixture(); present(f); f.values.resources[1].workspaceId = randomUUID(); fixedSourceWorkspaces(f); let published = false, reads = 0;
    const original = f.runtime.readResources.bind(f.runtime);
    vi.spyOn(f.runtime, 'readResources').mockImplementation(async (...args: any[]) => {
      const result = await original(...args); if (++reads === 2) f.values.invalidated = true; return result;
    });
    await expect(f.liveRead(async () => { published = true; })).rejects.toBeDefined(); expect(reads).toBe(2); expect(published).toBe(false);
    expect(f.material.assertCurrentReadGrants).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('accepts the genuine Context scheduled-job actor clone while pinning its original parent frame', async () => {
    const f = fixedValidationFixture(); present(f); const wrapperHandle = Object.freeze({}), jobHandle = Object.freeze({}), originalJob = Object.freeze({});
    const wrapper: any = Object.freeze({ executionId: randomUUID(), workflowId: f.plan.workflowId, clusterId: f.cid, workspaceId: f.wid, actorId: f.owner,
      sessionId: null, permissionVersion: f.ns.permissionVersion, expiresAt: Date.parse(f.ns.expiresAt), origin: 'scheduled-workflow', scheduleClaimId: f.ns.claim.id,
      workflowOriginId: randomUUID(), approvalFormat: 2, approvalSetId: f.approvalSet.setId, approvalSetHmac: f.approvalSet.setHmac });
    const job: any = Object.freeze({ origin: 'workflow-scheduled-configuration', sessionId: null, actor: f.ns.actor, clusterId: f.cid, workspaceId: f.wid,
      module: 'snapshots', purpose: 'apply', jobId: randomUUID(), permissionVersion: f.ns.permissionVersion, credentialEpoch: 1, leaseGeneration: 1,
      expiresAt: Date.parse(f.ns.expiresAt), readOnly: false, namespaceHandle: f.nsHandle, claimId: f.ns.claim.id, wrapperOriginId: wrapper.workflowOriginId,
      wrapperExecutionId: wrapper.executionId, planId: randomUUID(), planRevision: 1, planHash: 'd'.repeat(64), subjectSealHmac: f.ns.subjectSealHmac,
      originalScheduledJobHandle: originalJob });
    const forbidden = async () => { throw Error('NO_NATIVE_WRITE_IN_FIXED_READER_SOURCE_TEST'); };
    f.context.installApprovedPolicy({ verifyExecution: async (h: object) => { if (h !== wrapperHandle) throw Error('ORIGINAL_WRAPPER_REQUIRED'); return wrapper; },
      verifyWorkflowScheduledExecution: async (proof: object, namespace: object) => { if (proof !== wrapper || namespace !== f.nsHandle) throw Error('ORIGINAL_NS_REQUIRED'); },
      verifyStep: forbidden, mutationBinding: forbidden, bindOperation: forbidden, assertNative: forbidden, assertMetadata: forbidden } as any);
    f.context.installConfigurationJobPolicy({ verifyHandle: async (h: object) => { if (h !== jobHandle) throw Error('ORIGINAL_JOB_REQUIRED'); return job; } });
    const current = vi.spyOn(f.service as any, 'current'); let published = false;
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, () => f.context.runApprovedWorkflow(wrapperHandle as any,
      () => f.context.runConfigurationJob(jobHandle, async () => {
        const parent = f.context.current(); expect(parent.actor).not.toBe(f.ns.actor); expect(parent.actor?.id).toBe(f.owner);
        expect(f.context.requireWorkflowScheduledCurrentPrincipal(f.nsHandle).actor).toBe(f.ns.actor);
        await f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db, async (_: any, observations: any) => {
          expect(f.context.current()).toBe(parent); expect(observations.size).toBe(2); published = true;
        });
      })));
    expect(published).toBe(true); expect(current).toHaveBeenCalledTimes(2); expect(f.db.exec).not.toHaveBeenCalled();
  });
});
