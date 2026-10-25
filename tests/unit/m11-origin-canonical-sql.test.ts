import 'reflect-metadata';
import { trackEnteredAsyncLocalStorage } from './helpers/release-async-local-storage';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { WorkflowApprovalAuthorityService } from '../../apps/console-api/src/modules/workflows/workflow-approval-authority.service';
import { WorkflowCandidatesService } from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import { originCanonicalSqlFixture, installOriginSqlOutbound } from './helpers/m11-origin-canonical-sql-fixture';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const outbound = vi.mocked(outboundJson), denied = (code: string) => ({ response: { code } });
let monotonic: number;
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'd2'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T19:00:00Z'));
  monotonic = 10_000; vi.spyOn(performance, 'now').mockImplementation(() => monotonic); });
const releaseStorages = trackEnteredAsyncLocalStorage();
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); releaseStorages(); });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
async function fixture(count = 3, selector: 'user' | 'role' | 'team' = 'user') {
  const f = await originCanonicalSqlFixture(count, selector), sdk = installOriginSqlOutbound(f, outbound); return { ...f, sdk };
}

/** Execute the real fixed Runtime callbacks, complete canonical SQL and actual
 * Context maps. Controlled SQL rows model a held view-now and independently
 * advancing DB wall clock; these are not PostgreSQL or Native-write receipts. */
describe('closed Origin canonical SQL comparison, actual providers', () => {
  it.each(['step', 'packet', 'before-send'] as const)('integrates actual Origin, Root, canonical authority and guarded Native GETs at %s', async phase => {
    const f = await fixture();
    await f.withOrigin(async (job, execution) => {
      const frame = f.context.current(), before = f.sdk.calls;
      for (const method of ['assertLiveMaterial', 'openClosedCheckpoint', 'assertClosedCheckpoint', 'assertClosedCheckpointLive', 'releaseClosedCheckpoint']) f.observedRoot[method].mockClear();
      for (const method of ['openClosedCheckpoint', 'assertClosedCheckpoint']) f.observedRoot[method].mockImplementation(async (...args: any[]) => {
        const native = f.sdk.calls, result = await f.root[method](...args); expect(f.sdk.calls).toBe(native); return result;
      });
      const pair = await f.origin.verifyOriginalExecutionAndJob(job, execution, phase, f.db);
      expect(Object.isFrozen(pair)).toBe(true);
      expect(pair.job.jobId).toBe(f.job.id);
      expect(pair.execution.jobHandle).toBe(job);
      expect(pair.execution.configurationExecutionId).toBe(f.control.nested.id);
      expect(pair.job.namespaceHandle).toBe(f.current().handle);
      expect(pair.job.expiresAt).toBe(pair.execution.expiresAt);
      expect(f.sdk.calls).toBeGreaterThan(before);
      expect(f.sdk.prepared).toBe(f.sdk.calls); expect(f.sdk.before).toBe(f.sdk.calls);
      expect(f.context.current()).toBe(frame);
      expect(f.observedRoot.openClosedCheckpoint).toHaveBeenCalledOnce(); expect(f.observedRoot.assertClosedCheckpoint).toHaveBeenCalledOnce();
      expect(f.observedRoot.assertLiveMaterial).toHaveBeenCalledOnce(); expect(f.observedRoot.assertClosedCheckpointLive).toHaveBeenCalledTimes(3);
      const token = await f.observedRoot.openClosedCheckpoint.mock.results[0].value;
      expect(f.observedRoot.releaseClosedCheckpoint).toHaveBeenCalledExactlyOnceWith(token);
    });
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'] as const)('actual combined Origin rejects %s natural binding expiry after guarded Native reads with held view-now', async party => {
    const f = await fixture(); await f.withOrigin(async (job, execution) => {
      const actor = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))];
      f.bindingFor(actor).expires_at = new Date(f.control.dbNow + 1000).toISOString();
      f.observedRoot.openClosedCheckpoint.mockClear(); f.observedRoot.assertClosedCheckpoint.mockClear(); f.observedRoot.releaseClosedCheckpoint.mockClear();
      f.observedRoot.assertLiveMaterial.mockImplementation(async (...args: any[]) => {
        await f.root.assertLiveMaterial(...args); f.control.dbNow += 1001;
        expect(f.rawView(actor).length).toBeGreaterThan(0); expect(f.tables.iam_epoch[0].version).toBe('1');
      });
      const before = f.sdk.calls;
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db))
        .rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_GRANT_CHANGED'));
      expect(f.sdk.calls).toBeGreaterThan(before); expect(f.observedRoot.assertClosedCheckpoint).toHaveBeenCalledOnce();
      const token = await f.observedRoot.openClosedCheckpoint.mock.results[0].value;
      expect(f.observedRoot.releaseClosedCheckpoint).toHaveBeenCalledExactlyOnceWith(token);
      expect(() => f.root.assertClosedCheckpointLive(token, f.current().handle, f.current().proof, 'packet', f.observedRoot.openClosedCheckpoint.mock.calls[0][3])).toThrow();
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['grant', 'candidate', 'terminal-job'] as const)('actual combined Origin withholds publication for %s drift after its final Native gate', async cause => {
    const f = await fixture(); await f.withOrigin(async (job, execution) => {
      f.observedRoot.openClosedCheckpoint.mockClear(); f.observedRoot.releaseClosedCheckpoint.mockClear();
      f.observedRoot.assertLiveMaterial.mockImplementation(async (...args: any[]) => {
        await f.root.assertLiveMaterial(...args);
        if (cause === 'grant') f.tables.iam_effective_grants.find((g: any) => g.user_id === f.reviewers[2] && g.module === 'secrets')!.scope_values = ['unexpected'];
        if (cause === 'candidate') f.candidateRows[2].credential_epoch = '2';
        if (cause === 'terminal-job') f.job.state = 'failed';
      });
      let published = false;
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'before-send', f.db).then(value => { published = true; return value; })).rejects.toBeDefined();
      expect(published).toBe(false); expect(f.observedRoot.releaseClosedCheckpoint).toHaveBeenCalledOnce();
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('actual combined Origin refuses copied or mixed handles and releases a minted opener when its real frame closes', async () => {
    const f = await fixture(1), entered = deferred(), release = deferred(); let pending!: Promise<unknown>, minted!: object;
    await f.withOrigin(async (job, execution) => {
      await expect(f.origin.verifyOriginalExecutionAndJob({ ...job }, execution, 'packet', f.db)).rejects.toBeDefined();
      await expect(f.origin.verifyOriginalExecutionAndJob(job, { ...execution }, 'packet', f.db)).rejects.toBeDefined();
      f.observedRoot.openClosedCheckpoint.mockClear(); f.observedRoot.releaseClosedCheckpoint.mockClear();
      f.observedRoot.openClosedCheckpoint.mockImplementation(async (...args: any[]) => {
        minted = await f.root.openClosedCheckpoint(...args); entered.resolve(); await release.promise; return minted;
      });
      pending = f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db); void pending.catch(() => undefined); await entered.promise;
    });
    release.resolve(); await expect(pending).rejects.toBeDefined();
    expect(f.observedRoot.releaseClosedCheckpoint).toHaveBeenCalledExactlyOnceWith(minted);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it('opens before Native, repeats complete canonical/party SQL on close, returns no data or capability', async () => {
    const f = await fixture(), fullReviewer = vi.spyOn(f.approved as any, 'configurationCanonicalReviewerSql');
    await f.withNamespace(async () => {
      f.state.native.length = 0; fullReviewer.mockClear(); const before = f.sdk.calls;
      const token = await f.open(); expect(Object.isFrozen(token)).toBe(true); expect(Object.keys(token)).toEqual([]);
      expect(f.sdk.calls).toBe(before); expect(fullReviewer).toHaveBeenCalledTimes(f.reviewers.length * 2);
      const firstSql = f.seenSql.length; await expect(f.close(token)).resolves.toBeUndefined();
      expect(f.seenSql.length).toBeGreaterThan(firstSql); expect(fullReviewer).toHaveBeenCalledTimes(f.reviewers.length * 4);
      f.assertLive(token); f.assertLive(token); expect(f.sdk.calls).toBe(before); f.release(token);
      expect(() => f.assertLive(token)).toThrow(); await expect(f.close(token)).rejects.toBeDefined();
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'] as const)('detects complete %s entity/secret grant drift with unchanged epoch/PV', async party => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(), actor = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))];
      const grant = f.tables.iam_effective_grants.find((g: any) => g.user_id === actor && g.module === 'secrets' && g.action === 'read')!;
      grant.scope_type = 'entity'; grant.scope_values = [{ entity_type: 'services', entity_id: f.service.id }];
      expect(f.tables.iam_epoch[0].version).toBe('1'); await expect(f.close(token)).rejects.toBeDefined();
      expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  });

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'] as const)('rejects %s binding expiry while held view-now stays valid and IAM epoch does not change', async party => {
    const f = await fixture(); await f.withNamespace(async () => {
      const actor = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))], binding = f.bindingFor(actor);
      binding.expires_at = new Date(f.control.dbNow + 1000).toISOString(); const token = await f.open();
      f.control.dbNow += 1001; // DB wall moves; transaction now() and Node/perf clocks stay held.
      expect(f.rawView(actor).length).toBeGreaterThan(0); expect(f.tables.iam_epoch[0].version).toBe('1');
      await expect(f.close(token)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_GRANT_CHANGED')); f.release(token);
    });
  });

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'] as const)('freshly rejects %s credential change and principal revocation', async party => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(), id = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))];
      f.tables.users.find((user: any) => user.id === id)!.credential_epoch = '2';
      await expect(f.close(token)).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow(); f.release(token);
      f.tables.users.find((user: any) => user.id === id)!.credential_epoch = '1';
      const next = await f.open(); f.tables.users.find((user: any) => user.id === id)!.status = 'disabled';
      await expect(f.close(next)).rejects.toBeDefined(); expect(() => f.assertLive(next)).toThrow(); f.release(next);
    });
  });

  it('preserves complete grant provenance and accepts a reordered equivalent SQL result', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(); f.tables.iam_effective_grants.reverse();
      await f.close(token); f.assertLive(token); f.release(token);
      const changed = await f.open(); f.bindingFor(f.reviewers[2]).revision++;
      await expect(f.close(changed)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_OBSERVATION_CHANGED'));
      f.release(changed);
    });
  });

  it('uses a conservative DB-relative monotonic bound when Node and DB wall clocks differ', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      f.control.dbNow += 3_600_000; f.control.viewNow = f.control.dbNow;
      for (const binding of f.bindings.values()) binding.expires_at = new Date(f.control.dbNow + 1000).toISOString();
      // Job wall deadlines must also be real database deadlines in this clock model.
      // Only the grants clock is offset here, so restore DB for job observations.
      const before = f.control.beforeRead;
      f.control.beforeRead = async (sql: string) => { await before?.(sql); f.control.dbNow = sql.includes('to_jsonb(g)') ? Date.now() + 3_600_000 : Date.now(); };
      const token = await f.open(); await f.close(token); monotonic += 1001;
      expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  });

  it.each(['manifest', 'candidate-row', 'vote', 'stage', 'set', 'member', 'invalidation', 'malformed-policy', 'format-1', 'job-state'] as const)
  ('keeps canonical %s rejection with no witness publication or extra Native scan', async cause => {
    const f = await fixture(); await f.withNamespace(async () => {
      const before = f.sdk.calls;
      if (cause === 'manifest') f.manifest.stages[0].candidates[0].credentialEpoch = '2';
      if (cause === 'candidate-row') f.candidateRows[0].credential_epoch = '2';
      if (cause === 'vote') f.votes[0].decision = 'reject';
      if (cause === 'stage') f.stages[0].required_approvals++;
      if (cause === 'set') f.set.set_hmac = '0'.repeat(64);
      if (cause === 'member') f.setMembers[0].user_id = f.actor;
      if (cause === 'invalidation') f.state.invalidated = true;
      if (cause === 'malformed-policy') f.definition.policy = { ...f.policy, allowSelfApproval: true };
      if (cause === 'format-1') f.tables.workflows[0].approval_format = 1;
      if (cause === 'job-state') f.job.state = 'uncertain';
      await expect(f.open()).rejects.toBeDefined(); expect(f.sdk.calls).toBe(before);
    });
  });

  it('rejects coherently re-HMACed infeasible frozen candidates through the real feasibility algorithm', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      const reused = structuredClone(f.manifest.stages[0].candidates[0]);
      for (const stage of f.manifest.stages) stage.candidates = [structuredClone(reused)];
      const hmac = f.secrets.fingerprint(f.manifest); f.tables.workflows[0].candidate_manifest_hmac = hmac;
      for (const stage of f.stages) stage.candidate_manifest_hmac = hmac;
      f.candidateRows.splice(0, f.candidateRows.length, ...f.manifest.stages.map((stage: any) => ({ level: stage.level, user_id: reused.userId,
        credential_epoch: reused.credentialEpoch, provenance: reused.provenance, plan_hash: f.draft.binding.workflowPlanHash, manifest_hmac: hmac })));
      const old = f.db.one.getMockImplementation()!;
      f.db.one.mockImplementation(async function (this: unknown, sql: string, args: any[]) {
        if (sql.includes('FROM workflow_candidate_versions')) return { manifest: structuredClone(f.manifest), manifest_hmac: hmac };
        return old.call(this, sql, args);
      });
      await expect(f.open()).rejects.toMatchObject(denied('WORKFLOW_APPROVAL_CANDIDATES_UNSATISFIABLE'));
    });
  });

  it('new fixed reader rejects SQL format1 before any full reviewer fallback', async () => {
    const f = await fixture(), fallback = vi.fn(async () => { throw Error('MUST_NOT_REENTER_NATIVE_REVIEWER'); });
    const approval = new WorkflowApprovalAuthorityService(f.db, f.secrets, new WorkflowCandidatesService(f.db));
    approval.installReviewerPolicy('configuration_v2', { verifyCurrent: fallback });
    const token = Object.freeze({}), verifier = { enter: vi.fn(async (actual: object) => { if (actual !== token) throw Error('ORIGINAL_TOKEN'); }), leave: vi.fn(async () => undefined) };
    const reader = approval.installScheduledConfigurationOriginSqlReader(verifier);
    Object.assign(f.definition, { approval_format: 1, mode: 'single' }); f.tables.workflows[0].approval_format = 1; f.tables.workflow_versions[0].approval_format = 1;
    await expect(reader(token, f.plan, { checkpoint: 'packet' }, f.db)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_FORMAT_INVALID'));
    expect(fallback).not.toHaveBeenCalled(); expect(verifier.enter).toHaveBeenCalledOnce(); expect(verifier.leave).toHaveBeenCalledOnce();
  });

  it('new fixed reader rejects a raw authenticated policy whose normalized HMAC differs', async () => {
    const f = await fixture(1), fallback = vi.fn(async () => { throw Error('MUST_NOT_REENTER_NATIVE_REVIEWER'); });
    const approval = new WorkflowApprovalAuthorityService(f.db, f.secrets, new WorkflowCandidatesService(f.db));
    approval.installReviewerPolicy('configuration_v2', { verifyCurrent: fallback });
    const token = Object.freeze({}), gate = { enter: vi.fn(async () => undefined), leave: vi.fn(async () => undefined) };
    const reader = approval.installScheduledConfigurationOriginSqlReader(gate), policy = structuredClone(f.policy);
    policy.stages[0].name = `  ${policy.stages[0].name}  `;
    f.definition.policy = policy; f.definition.policy_hash = f.secrets.fingerprint(policy);
    const plan = { ...f.plan, definition: { ...f.plan.definition, policyHash: f.definition.policy_hash } };
    expect(f.secrets.fingerprint(f.definition.policy)).toBe(plan.definition.policyHash);
    await expect(reader(token, plan, { checkpoint: 'packet' }, f.db)).rejects.toMatchObject(denied('WORKFLOW_APPROVAL_POLICY_INVALID'));
    expect(fallback).not.toHaveBeenCalled(); expect(gate.leave).toHaveBeenCalledOnce(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['early-live', 'double-close', 'copied', 'wrong-tx', 'wrong-phase', 'wrong-proof'] as const)('poisons or refuses %s and never permits replay', async reason => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(), { handle, proof } = f.current();
      if (reason === 'early-live') expect(() => f.assertLive(token)).toThrow();
      else if (reason === 'double-close') { await f.close(token); await expect(f.close(token)).rejects.toBeDefined(); }
      else if (reason === 'copied') { await expect(f.close({ ...token })).rejects.toBeDefined(); await f.close(token); f.assertLive(token); }
      else await expect(f.root.assertClosedCheckpoint(token, handle, reason === 'wrong-proof' ? { ...proof } : proof,
        reason === 'wrong-phase' ? 'step' : 'packet', reason === 'wrong-tx' ? { ...f.db } : f.db)).rejects.toBeDefined();
      if (reason !== 'copied') { await expect(f.close(token)).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow(); }
      f.release(token); f.release(token); await expect(f.close(token)).rejects.toBeDefined();
    });
  });

  it.each(['open-during-open', 'close-during-close', 'release-during-close'] as const)('refuses %s at actual suspended SQL boundaries', async reason => {
    const f = await fixture(); await f.withNamespace(async () => {
      if (reason === 'open-during-open') {
        let entered = false;
        f.control.beforeRead = async () => { f.control.beforeRead = undefined; entered = true;
          await expect(f.open()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED')); };
        const token = await f.open(); expect(entered).toBe(true); await f.close(token); f.assertLive(token); f.release(token);
      } else {
        const token = await f.open();
        f.control.beforeRead = async () => { f.control.beforeRead = undefined;
          if (reason === 'close-during-close') await expect(f.close(token)).rejects.toBeDefined(); else f.release(token); };
        await expect(f.close(token)).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow(); f.release(token);
      }
    });
  });

  it('rejects a matching principal in a different real Context frame', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(), { proof } = f.current();
      await f.context.runActor({ actor: proof.actor, clusterId: f.cid, workspaceId: f.wid, module: 'snapshots', action: 'write' }, async () => {
        await expect(f.close(token)).rejects.toBeDefined();
      });
      expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  });

  it('rejects a pending opener after frame closure', async () => {
    // Split from the matching-principal case: one heavy fixture per it keeps each
    // under vitest's 10s budget when CI runs --maxWorkers=2 (dual-fixture its flaked).
    const f = await fixture(), entered = deferred(), release = deferred(); let pending!: Promise<unknown>;
    await f.withNamespace(async () => {
      f.control.beforeRead = async () => { f.control.beforeRead = undefined; entered.resolve(); await release.promise; };
      pending = f.open(); void pending.catch(() => undefined); await entered.promise;
    });
    release.resolve(); await expect(pending).rejects.toBeDefined();
  });

  it.each(['create', 'update', 'delete', 'archive-delete', 'internal-read', 'actor-clone', 'cross-workspace'] as const)
  ('accepts the real Context %s chain without changing its Native authorization', async kind => {
    const f = await fixture(); await f.withNamespace(async () => {
      const { proof } = f.current(), other = randomUUID();
      const check = async () => { const frame = f.context.current(), before = f.sdk.calls; const token = await f.open(); await f.close(token); f.assertLive(token);
        expect(f.context.current()).toBe(frame); expect(f.sdk.calls).toBe(before); f.release(token); };
      const operation: any = { operationId: randomUUID(), actor: proof.actor, clusterId: f.cid, workspaceId: kind === 'cross-workspace' ? other : f.wid,
        entityType: 'services', entityId: f.service.id, action: ['create', 'update', 'delete'].includes(kind) ? kind : 'delete' };
      if (kind === 'actor-clone') {
        const make = (f.context as any).make.bind(f.context);
        const spy = vi.spyOn(f.context as any, 'make').mockImplementation((input: any, limits: any, parent: any) => make({ ...input, actor: Object.freeze({ ...input.actor }) }, limits, parent));
        await f.context.runActor({ actor: proof.actor, clusterId: f.cid, workspaceId: f.wid, module: 'snapshots', action: 'write' }, async () => {
          expect(f.context.current().actor).not.toBe(proof.actor); await check(); }); spy.mockRestore();
      } else if (kind === 'internal-read') await f.context.runInternalRead(f.cid, 'entity-preflight', check, { workspaceId: f.wid, paths: [`/services/${f.service.id}`] });
      else await f.context.runOperation(operation, async () => {
        if (kind === 'archive-delete') await f.context.runArchiveDelete({ entryId: randomUUID(), operationId: operation.operationId, clusterId: f.cid,
          workspaceId: f.wid, nodes: [{ path: `/services/${f.service.id}`, type: 'services', id: f.service.id }] }, check);
        else await check();
      });
    });
  });

  it.each(['endpoint', 'connection-secret', 'generation', 'owner', 'credential', 'iam', 'role'] as const)('freshly rejects %s changes on close', async cause => {
    const f = await fixture(3, cause === 'role' ? 'role' : 'user'); await f.withNamespace(async () => {
      const token = await f.open();
      if (cause === 'endpoint') f.cluster.admin_url = 'http://changed:8001';
      if (cause === 'connection-secret') f.cluster.connection_secret = 'source-changed-ciphertext';
      if (cause === 'generation') f.job.lease_generation++;
      if (cause === 'owner') f.job.lease_owner_hash = '9'.repeat(64);
      if (cause === 'credential') f.tables.users[1].credential_epoch = '2';
      if (cause === 'iam') f.tables.iam_epoch[0].version = '2';
      if (cause === 'role') f.state.roleLive = false;
      await expect(f.close(token)).rejects.toBeDefined(); f.release(token);
    });
  });

  it('allows eligible probe/heartbeat/counter metadata while preserving original witness bounds', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open();
      Object.assign(f.cluster, { last_probed_at: new Date().toISOString(), updated_at: new Date().toISOString(), status: 'unhealthy' });
      Object.assign(f.job, { lease_until: new Date(Date.parse(f.job.lease_until) + 5_000).toISOString(), updated_at: new Date().toISOString(), safe_progress: { count: 7 }, revision: 11 });
      await f.close(token); f.assertLive(token); f.release(token);
    });
  });

  it('cannot finish after deferred final Redis crosses a participant deadline', async () => {
    const f = await fixture(), entered = deferred(), release = deferred(); let pending!: Promise<unknown>;
    await f.withNamespace(async () => {
      for (const binding of f.bindings.values()) binding.expires_at = new Date(f.control.dbNow + 1000).toISOString();
      const token = await f.open(), ownership = f.redis.assertLeaseOwnership.getMockImplementation()!; let held = false;
      f.control.afterRead = async (sql: string) => { if (sql.includes('SELECT version FROM iam_epoch')) held = true; };
      f.redis.assertLeaseOwnership.mockImplementation(async () => { await ownership(); if (held) { held = false; entered.resolve(); await release.promise; } });
      pending = f.close(token); void pending.catch(() => undefined); await entered.promise; monotonic += 1001; release.resolve();
      await expect(pending).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  });

  it('checks a sealed witness again after the async close-return microtask', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      for (const binding of f.bindings.values()) binding.expires_at = new Date(f.control.dbNow + 1000).toISOString();
      const token = await f.open(); await f.close(token).then(() => { monotonic += 1001; });
      expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  });

  it('rejects a real Context that closes while SQL is suspended', async () => {
    // Split from sealed-token assert: one fixture per it — dual fixture() in one it
    // was ~4.4s locally and timed out at 10s under CI --maxWorkers=2 (not a hang).
    const f = await fixture(), entered = deferred(), release = deferred(); let pending!: Promise<unknown>, token!: object;
    await f.withNamespace(async () => {
      token = await f.open(); f.control.beforeRead = async () => { f.control.beforeRead = undefined; entered.resolve(); await release.promise; };
      pending = f.close(token); void pending.catch(() => undefined); await entered.promise;
    });
    release.resolve(); await expect(pending).rejects.toBeDefined(); f.release(token);
  });

  it('rejects a sealed token after its frame closes', async () => {
    const f = await fixture(); let token!: object;
    await f.withNamespace(async () => { token = await f.open(); await f.close(token); });
    expect(() => f.assertLive(token)).toThrow(); f.release(token);
  });
});
