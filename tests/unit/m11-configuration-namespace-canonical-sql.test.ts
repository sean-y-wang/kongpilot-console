import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { preNamespaceApprovalFixture } from './helpers/workflow-pre-namespace-approval-fixture';
import { originalNamespaceEligibility } from './helpers/m11-original-namespace-eligibility-source';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const outbound = vi.mocked(outboundJson), denied = (code: string) => ({ response: { code } });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ce'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** Actual Approval/Candidates/Approved/Authority eligibility, Namespace and
 * Context private handles, Material SQL/AEAD/grants and SDK GET responses.
 * SQL rows, Namespace's initial issuer and outbound transport are controlled
 * Source adapters. This does not create a runtime claim or Native mutation. */
async function fixture(reviewers = 1) {
  const f = await preNamespaceApprovalFixture('configuration_v2', reviewers, 'user', true);
  outbound.mockImplementation(async (_base, path, method, _body, _query, _auth, _timeout, beforeSend, prepareSend) => {
    if (method !== 'GET') throw Error('SOURCE_NO_NATIVE_MUTATION');
    await prepareSend?.(); beforeSend?.();
    const read: any = { path, actorId: f.context.current().actor!.id,
      response: path.startsWith('/schemas/') ? { fields: [] } : path.split('/').length === 3 ? { message: 'Not found' } : { data: [], next: null } };
    f.state.native.push({ path, actorId: read.actorId }); await f.state.callback?.(read);
    return { status: path.startsWith('/schemas/') || path.split('/').length === 2 ? 200 : 404, body: read.response, bytes: 32, jsonParsed: true };
  });
  const broad = (userId: string, scope = 'global') => ({ user_id: userId, cluster_id: scope === 'global' ? null : f.cid,
    workspace_id: scope === 'global' ? null : f.wid, module: 'workflows', action: 'approve', scope_type: scope, scope_values: scope === 'global' ? [] : [f.wid] });
  const grantReviewer = (index = 0) => { const userId = f.reviewers[index]; f.tables.users[index + 1].super_admin = false;
    f.tables.iam_effective_grants.push(...['workflows', 'snapshots', 'services', 'secrets'].flatMap(module => ['read', 'write', 'approve'].map(action =>
      ({ user_id: userId, module, action, cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] }))));
    return userId;
  };
  return { ...f, broad, grantReviewer };
}

describe('genuine configuration fmt2 Namespace canonical SQL split, Source only', () => {
  it('keeps one complete final real reviewer scan and a fresh canonical SQL tail', async () => {
    const f = await fixture(2), full = vi.spyOn(f.approvals, 'verifyApprovalSet'), sql = vi.spyOn(f.approved as any, 'configurationCanonicalReviewerSql');
    const result = await f.runInNamespace();
    expect(result.approvalSet.reviewers.map((r: any) => r.userId)).toEqual(f.reviewers);
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual(f.reviewers.map(userId => ({ userId, action: 'approve', checkpoint: 'before-send' })));
    expect(new Set(f.state.native.map((r: any) => r.actorId))).toEqual(new Set([f.actor, ...f.reviewers]));
    // The initial controlled issuer performs ordinary full approval before
    // entering the Namespace. Eligibility then uses two private SQL reads.
    expect(full).toHaveBeenCalledTimes(1); expect(sql).toHaveBeenCalledTimes(4);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it.each(['global', 'workspace'] as const)('preserves valid exact %s canonical approval for a non-super-admin', async scope => {
    const f = await fixture(), reviewer = f.grantReviewer();
    f.tables.iam_effective_grants = f.tables.iam_effective_grants.filter(row => !(row.user_id === reviewer && row.module === 'workflows' && row.action === 'approve'));
    f.tables.iam_effective_grants.push(f.broad(reviewer, scope));
    await f.runInNamespace(); expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
    expect(f.state.native.some((r: any) => r.actorId === reviewer)).toBe(true);
  });

  it.each(['entity-only', 'duplicate-workspace', 'missing', 'wrong-module', 'wrong-action', 'foreign-cluster', 'foreign-workspace'] as const)
  ('keeps the original canonical %s broad grant rejection even when scoped checks are otherwise available', async reason => {
    const f = await fixture(), reviewer = f.grantReviewer();
    await expect(f.runInNamespace(async () => {
      f.tables.iam_effective_grants = f.tables.iam_effective_grants.filter(row => !(row.user_id === reviewer && row.module === 'workflows' && row.action === 'approve'));
      const grant: any = f.broad(reviewer, reason === 'duplicate-workspace' ? 'workspace' : 'global');
      if (reason === 'entity-only') Object.assign(grant, { cluster_id: f.cid, workspace_id: f.wid, scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: f.service.id }] });
      if (reason === 'duplicate-workspace') grant.scope_values = [f.wid, f.wid];
      if (reason === 'wrong-module') grant.module = 'snapshots';
      if (reason === 'wrong-action') grant.action = 'read';
      if (reason === 'foreign-cluster') grant.cluster_id = '9b000000-0000-4000-8000-000000000099';
      if (reason === 'foreign-workspace') Object.assign(grant, { cluster_id: f.cid, workspace_id: '9b000000-0000-4000-8000-000000000099' });
      if (reason !== 'missing') f.tables.iam_effective_grants.push(grant);
      if (['entity-only', 'duplicate-workspace'].includes(reason)) {
        // Real final Root material/scoped authorization alone is insufficient
        // to prove the additional canonical exact broad approval predicate.
        await (f.runtime as any).subject(f.plan, reviewer, 'approve', 'before-send', f.db);
        expect(f.state.native.some((r: any) => r.actorId === reviewer)).toBe(true); f.state.rootReads.length = 0;
      }
      return f.run('before-send');
    })).rejects.toMatchObject(denied('APPROVED_APPROVER_REVOKED'));
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(0); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['cancelled', 'expired', 'failed', 'uncertain'] as const)('keeps non-super-admin canonical job state %s rejection', async state => {
    const f = await fixture(); f.grantReviewer();
    await expect(f.runInNamespace(async () => { f.job.state = state; return f.run('before-send'); }))
      .rejects.toMatchObject(denied('CONFIGURATION_APPROVED_WRAPPER_INVALID'));
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(0);
  });

  it('preserves the original super-admin skip of non-super-admin wrapper state and broad grants', async () => {
    const f = await fixture();
    await f.runInNamespace(async () => { f.job.state = 'failed'; return f.run('before-send'); });
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
  });

  it.each(['actor', 'plan-id', 'plan-revision', 'plan-hash', 'transport', 'mode', 'approval-required', 'workflow', 'missing-row'] as const)
  ('shares the complete original canonical configuration job %s binding predicate', async field => {
    const f = await fixture(), reviewer = f.grantReviewer();
    const foreign = '9b000000-0000-4000-8000-000000000099';
    if (field === 'actor') f.job.actor_id = foreign;
    if (field === 'plan-id') f.job.plan_id = foreign;
    if (field === 'plan-revision') f.job.plan_revision++;
    if (field === 'plan-hash') f.job.plan_hash = 'a'.repeat(64);
    if (field === 'transport') f.job.transport_scope = 'b'.repeat(64);
    if (field === 'mode') f.job.execution_mode = 'direct';
    if (field === 'approval-required') f.job.approval_required = false;
    if (field === 'workflow') f.job.workflow_id = foreign;
    if (field === 'missing-row') f.tables.configuration_jobs.length = 0;
    await expect((f.approved as any).configurationCanonicalReviewerSql({ id: reviewer, super_admin: false }, f.plan, f.db))
      .rejects.toMatchObject(denied('CONFIGURATION_APPROVED_WRAPPER_INVALID'));
    expect(f.state.native).toEqual([]); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['grant', 'job-state', 'reviewer-status', 'reviewer-epoch', 'invalidation', 'iam', 'lease', 'deadline'] as const)
  ('rejects fresh %s change after the final full Native reviewer, before any inspection is published', async reason => {
    const f = await fixture(), reviewer = f.grantReviewer(); let published = false;
    await expect(f.runInNamespace(async () => {
      f.state.afterReviewer = async () => {
        if (reason === 'grant') f.tables.iam_effective_grants = f.tables.iam_effective_grants.filter(row => !(row.user_id === reviewer && row.module === 'workflows' && row.action === 'approve'));
        if (reason === 'job-state') f.job.state = 'uncertain';
        if (reason === 'reviewer-status') f.tables.users[1].status = 'disabled';
        if (reason === 'reviewer-epoch') f.tables.users[1].credential_epoch = '2';
        if (reason === 'invalidation') f.state.invalidated = true;
        if (reason === 'iam') f.tables.iam_epoch[0].version = '2';
        if (reason === 'lease') f.state.lease = false;
        if (reason === 'deadline') vi.spyOn(Date, 'now').mockReturnValue(Date.parse(f.plan.expiresAt));
      };
      const result = await f.run('before-send'); published = true; return result;
    })).rejects.toBeDefined();
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1); expect(published).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('awaits the last actual reviewer and checks exact original frame restoration before publishing', async () => {
    const f = await fixture(), entered = deferred(), release = deferred(); let published = false;
    const pending = f.runInNamespace(async () => {
      const original = f.context.current();
      f.state.afterReviewer = async () => { expect(f.context.current()).toBe(original); entered.resolve(); await release.promise; };
      const result = await f.run('before-send'); expect(f.context.current()).toBe(original); published = true; return result;
    });
    await entered.promise; expect(published).toBe(false); release.resolve(); await pending; expect(published).toBe(true); expect(f.context.peek()).toBeNull();
  });

  it('propagates an unknown real reviewer error with no inspection or Native retry', async () => {
    const f = await fixture(), unknown = new Error('SOURCE_UNKNOWN_FINAL_REVIEWER');
    await expect(f.runInNamespace(async () => { f.state.afterReviewer = async () => { throw unknown; }; return f.run('before-send'); })).rejects.toBe(unknown);
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('refuses reentrant eligibility while the original Namespace invocation is still active', async () => {
    const f = await fixture();
    await f.runInNamespace(async () => {
      f.state.afterReviewer = async () => { const calls = f.state.native.length;
        await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_REENTRANT')); expect(f.state.native).toHaveLength(calls); };
      return f.run('before-send');
    });
  });

  it('never accepts a copied/replayed token, altered plan/transaction/checkpoint or readonly descendant frame', async () => {
    const f = await fixture(), authority: any = f.authority, gate = authority.configurationNamespaceFactsGate.bind(authority);
    let originalToken: object | undefined, exercised = false;
    vi.spyOn(authority, 'configurationNamespaceFactsGate').mockImplementation(async (token: object, plan: any, checkpoint: any, tx: any, phase: any) => {
      if (phase === 'enter' && !exercised) {
        exercised = true; originalToken = token;
        for (const args of [[{ ...token }, plan, checkpoint, tx, phase], [token, structuredClone(plan), checkpoint, tx, phase],
          [token, plan, 'snapshot', tx, phase], [token, plan, checkpoint, { ...tx }, phase], [token, plan, checkpoint, tx, 'leave']])
          await expect(gate(...args)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED'));
        const frame = f.context.current();
        await f.context.runActor({ actor: frame.actor!, clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'read' }, async () => {
          await expect(gate(token, plan, checkpoint, tx, phase)).rejects.toBeDefined();
        });
        expect(f.context.current()).toBe(frame);
      }
      return gate(token, plan, checkpoint, tx, phase);
    });
    await f.runInNamespace(); expect(exercised).toBe(true);
    await expect(authority.configurationNamespaceFacts(originalToken, f.plan, { checkpoint: 'before-send' }, f.db)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED'));
  });

  it('refuses missing or replaced fixed SQL policy and reader registration', async () => {
    const f = await fixture();
    expect(() => f.approvals.installScheduledConfigurationCanonicalSqlPolicy({ verifyCurrent: async () => undefined })).toThrow();
    expect(() => f.approvals.installScheduledConfigurationEligibilityFactsReader({ enter: async () => undefined, leave: async () => undefined })).toThrow();
    await expect(f.runInNamespace(async () => { (f.approvals as any).scheduledConfigurationSql = undefined; return f.run('before-send'); }))
      .rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_SQL_POLICY_UNAVAILABLE'));
  });

  it('executes the original in-memory Source body and observes its extra real Native reviewer group', async () => {
    const f = await fixture();
    await f.runInNamespace(async () => {
      const actual = await f.run('before-send'), current = f.state.native.filter((r: any) => r.actorId === f.reviewers[0]).map((r: any) => r.path);
      expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
      f.state.native.length = 0; f.state.rootReads.length = 0;
      const previous = await originalNamespaceEligibility.call(f.authority, f.stored, f.db, 'before-send');
      expect(previous).toEqual(actual);
      expect(f.state.native.filter((r: any) => r.actorId === f.reviewers[0]).map((r: any) => r.path)).toEqual([...current, ...current]);
      expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual([
        { userId: f.reviewers[0], action: 'approve', checkpoint: 'packet' }, { userId: f.reviewers[0], action: 'approve', checkpoint: 'before-send' },
      ]);
    });
  });

  it('rejects a late canonical-only job-state change which the original body would publish', async () => {
    const f = await fixture(); f.grantReviewer();
    await f.runInNamespace(async () => {
      let scans = 0; f.state.afterReviewer = async () => { if (++scans === 2) f.job.state = 'uncertain'; };
      const previous = await originalNamespaceEligibility.call(f.authority, f.stored, f.db, 'before-send');
      expect(previous.approvalSet.reviewers[0].userId).toBe(f.reviewers[0]);
      f.job.state = 'running'; f.state.rootReads.length = 0; f.state.afterReviewer = async () => { f.job.state = 'uncertain'; };
      await expect(f.run('before-send')).rejects.toMatchObject(denied('CONFIGURATION_APPROVED_WRAPPER_INVALID'));
      expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
    });
  });

  it('accepts a genuine configuration-job actor clone while retaining the Namespace principal reference', async () => {
    const f = await fixture();
    // The real Context scheduled job creates the actor clone only after an
    // approved wrapper; those capabilities are outside this eligibility test.
    // Here a genuine Context child is used and only its immutable make input
    // is instrumented to reproduce that clone without inventing a Namespace.
    await f.runInNamespace(async () => {
      const parent = f.context.current(), make = (f.context as any).make.bind(f.context), namespace = f.context.requireWorkflowScheduledCurrentPrincipal(f.context.requireWorkflowScheduledNamespaceHandle()).namespace;
      const spy = vi.spyOn(f.context as any, 'make').mockImplementation((input: any, limits: any, ancestor: any) => make(
        input.kind === 'actor' && input.module === 'snapshots' ? { ...input, actor: Object.freeze({ ...input.actor }) } : input, limits, ancestor));
      await f.context.runActor({ actor: parent.actor!, clusterId: f.cid, workspaceId: f.wid, module: 'snapshots', action: 'write', purpose: 'configuration' }, async () => {
        expect(f.context.current().actor).not.toBe(namespace.actor); expect(f.context.current().actor?.id).toBe(namespace.actor.id);
        const principal = f.context.requireWorkflowScheduledCurrentPrincipal(f.context.requireWorkflowScheduledNamespaceHandle()); expect(principal.actor).toBe(namespace.actor);
        await f.run('before-send');
      });
      spy.mockRestore(); expect(f.context.current()).toBe(parent);
    });
  });

  it('keeps read-only actor descendants on the original complete canonical and Root path', async () => {
    const f = await fixture(), full = vi.spyOn(f.approvals, 'verifyApprovalSet'), reader = vi.spyOn(f.authority as any, 'readConfigurationNamespaceFacts');
    await f.runInNamespace(async () => {
      const frame = f.context.current();
      await f.context.runActor({ actor: frame.actor!, clusterId: f.cid, workspaceId: f.wid, module: 'snapshots', action: 'read' }, () => f.run('before-send'));
      expect(f.context.current()).toBe(frame);
    });
    expect(full).toHaveBeenCalledTimes(2); expect(reader).not.toHaveBeenCalled();
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(2);
  });

  it('does not convert a public full verification into the Namespace private reader', async () => {
    const f = await fixture(), reader = vi.spyOn(f.authority as any, 'readConfigurationNamespaceFacts');
    await f.runInNamespace(async () => { const result = await f.publicFull(); expect(result.reviewers[0].userId).toBe(f.reviewers[0]); });
    expect(reader).not.toHaveBeenCalled(); expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
  });

  it('keeps simultaneous Namespace invocation tokens isolated when the second invocation finishes first', async () => {
    const f = await fixture(), authority: any = f.authority, gate = authority.configurationNamespaceFactsGate.bind(authority);
    const held = deferred(), release = deferred(); let firstToken: object | undefined, tested = false;
    vi.spyOn(authority, 'configurationNamespaceFactsGate').mockImplementation(async (token: object, plan: any, checkpoint: any, tx: any, phase: any) => {
      if (phase === 'enter' && !firstToken) { firstToken = token; held.resolve(); await release.promise; }
      else if (phase === 'enter' && !tested) {
        tested = true; await expect(gate(firstToken, plan, checkpoint, tx, phase)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED'));
      }
      return gate(token, plan, checkpoint, tx, phase);
    });
    await f.runInNamespace(async () => {
      const first = f.run('before-send'); await held.promise;
      const second = await f.run('before-send'); expect(second.plan.workflowId).toBe(f.plan.workflowId);
      release.resolve(); expect((await first).plan.workflowId).toBe(f.plan.workflowId);
    });
    expect(tested).toBe(true); expect(f.db.exec).not.toHaveBeenCalled();
  });
});
