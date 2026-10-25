import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkflowScheduleCandidateReadService } from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import { WorkflowCandidatesService } from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import { WorkflowApprovalAuthorityService } from '../../apps/console-api/src/modules/workflows/workflow-approval-authority.service';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { coarseGrantMatches } from '../../apps/console-api/src/modules/authorization/grant-policy';
import { validationAbsenceFixture } from './helpers/workflow-scheduled-read-absence-fixture';

/** Real Approved/ApprovalAuthority/Candidate/Context and HMACs, controlled
 * current SQL results and GET responses only. No PostgreSQL/network/native
 * permit, actual scheduler outcome or production acceptance is claimed. */
function fixture(kind: 'configuration_v2' | 'portal-credential-issue' = 'configuration_v2', install = true) {
  const f = validationAbsenceFixture(false, kind), context = new KongExecutionContextService();
  const state: any = { iamEpoch: '1', blockedRead: false, skipRead: false, failAfterRead: false, lastHandle: null,
    immutable: false, callbackKinds: [], inputKinds: [], presentAtReturn: false };
  const users = new Map<string, any>(), grants = new Map<string, any[]>();
  const reviewers = f.approvalSet.reviewers.map((r: any) => r.userId);
  const grant = (id: string, module: string, action: string) => ({ user_id: id, cluster_id: f.cid, workspace_id: f.wid,
    module, action, scope_type: 'global', scope_values: [] });
  for (const id of [f.owner, ...reviewers]) {
    users.set(id, { id, username: `current-${id}`, super_admin: false, status: 'active', deleted_at: null,
      force_password_change: false, credential_epoch: '1', permissions_epoch: '1' });
    grants.set(id, [grant(id, 'services', 'read'), grant(id, 'secrets', 'read'), grant(id, 'workflows', id === f.owner ? 'write' : 'approve')]);
  }
  const baseOne = f.db.one.getMockImplementation()!, baseQuery = f.db.query.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM iam_epoch')) return { version: state.iamEpoch };
    if (sql.includes('FROM users')) {
      const row = users.get(args[0]);
      return row && row.status === 'active' && row.deleted_at === null && !row.force_password_change ? { ...row } : null;
    }
    return baseOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('iam_effective_grants')) return (grants.get(args[0]) ?? []).map((g: any) => ({ ...g, scope_values: [...g.scope_values] }));
    return baseQuery(sql, args);
  });
  f.plans.load.mockImplementation(async () => ({ plan: f.plan, row: { ...f.values.row } }));
  const candidates = new WorkflowCandidatesService(f.db);
  const reader = new WorkflowScheduleCandidateReadService(f.db, f.secrets, context, f.plans, f.repository, candidates);
  const ordinary = vi.fn(async () => { throw new Error('ORDINARY_HTTP_POLICY_MUST_NOT_RUN'); });
  context.installPolicy({ authorizeRequest: ordinary, authorizeResponse: ordinary });
  context.installWorkflowScheduleCandidateReadPolicy({ verifyHandle: reader.verifyHandle.bind(reader), assertLive: reader.assertLive.bind(reader),
    authorizeRequest: reader.authorizeRequest.bind(reader), verifyRequest: reader.verifyRequest.bind(reader), authorizeResponse: reader.authorizeResponse.bind(reader) });
  const current = vi.fn(async (input: any) => {
    state.inputKinds.push({ role: input.role, actorId: input.principal.user.id });
    if (state.blockedRead || !input.principal.grants.some((g: any) => coarseGrantMatches(g, 'workflows', 'approve', { clusterId: f.cid, workspaceId: f.wid })))
      throw new ForbiddenException({ code: 'ACTUAL_CURRENT_REVIEWER_SCOPE_DENIED' });
    if (!input.principal.grants.some((g: any) => g.module === 'services' && g.action === 'read')) throw new ForbiddenException({ code: 'ACTUAL_CURRENT_READ_DENIED' });
  });
  reader.installStorageContract('a'.repeat(64));
  reader.installBusinessPolicy(kind, { ...f.business, assertCurrent: current });
  reader.installContextRunner({ assertNoFrame() { if (context.peek() !== null) throw new ForbiddenException({ code: 'ACTUAL_EMPTY_CONTEXT_REQUIRED' }); },
    run(handle, fn) { state.lastHandle = handle; return context.runWorkflowScheduleCandidateRead(handle, fn); } });
  const approvals = new WorkflowApprovalAuthorityService(f.db, f.secrets, candidates);
  const installReviewer = vi.spyOn(approvals, 'installReviewerPolicy');
  const approved = new ApprovedWorkflowExecutionService(f.db, f.secrets, {} as any, {} as any, {} as any, f.redis, context, approvals);
  approved.onModuleInit();
  const reviewerPolicy = installReviewer.mock.calls.find(call => call[0] === kind)![1];
  const cluster: any = { id: f.cid, admin_url: 'http://kong:8001', version: '1.5.1', revision: 1, execution_mode: 'approval' };
  const response = () => ({ id: f.nativeId, host: 'controlled-current-service' });
  const read = async () => {
    const ticket = await context.authorizeRequest(cluster, 'GET', f.values.resources[0].path, undefined, {});
    await context.refreshAuthorization(ticket); await context.beforeNativeSend(ticket);
    return context.authorizeResponse(ticket, response());
  };
  const callback = vi.fn(async (id: string, plan: any, tx: any) => {
    expect(context.peek()).toBeNull(); expect(tx).toBe(f.db);
    state.immutable = Object.isFrozen(plan) && Object.isFrozen(plan.scheduling) && Object.isFrozen(plan.steps);
    await reader.runOriginalPlan(plan, id, 'reviewer', async handle => {
      const proof = await reader.verifyHandle(handle), frame = context.current();
      state.callbackKinds.push({ kind: frame.kind, actorId: frame.actor?.id, sid: frame.sessionId, proofSid: proof.sessionId, role: proof.role });
      if (!state.skipRead) await read();
      if (state.failAfterRead) throw new ForbiddenException({ code: 'ACTUAL_CURRENT_GRANTS_CHANGED' });
    }, tx);
  });
  if (install) approved.installWorkflowScheduledReviewerReadPolicy({ verifyCurrent: callback });
  const review = (id = reviewers[0], plan: any = f.plan) => reviewerPolicy.verifyCurrent(id, plan, f.db, 'claim');
  const verifySet = () => approvals.verifyApprovalSet(f.plan, { checkpoint: 'claim' }, f.db);
  return { ...f, context, approved, approvals, reader, callback, review, verifySet, current, state, users, grants, reviewers, read, cluster, ordinary, grant };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T12:00:00Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('scheduled business empty-context current reviewer (Source-only)', () => {
  it.each(['configuration_v2', 'portal-credential-issue'] as const)('checks the complete %s vote set without borrowing a SID', async kind => {
    const f = fixture(kind), set = await f.verifySet();
    expect(set.reviewers.map(r => r.userId)).toEqual(f.reviewers);
    expect(f.callback.mock.calls.map(call => call[0])).toEqual(f.reviewers);
    expect(f.state.callbackKinds).toEqual(f.reviewers.map(actorId => ({ kind: 'workflow-candidate-read', actorId, sid: undefined, proofSid: null, role: 'reviewer' })));
    expect(f.state.immutable).toBe(true); expect(f.context.peek()).toBeNull(); expect(f.ordinary).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('requires the fixed bootstrap delegate and never enters generic authorization when missing', async () => {
    const f = fixture('configuration_v2', false);
    await expect(f.verifySet()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_REVIEWER_READ_POLICY_UNAVAILABLE' } });
    expect(f.ordinary).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('permits one complete delegate only and binds the installed method', async () => {
    const f = fixture('configuration_v2', false), policy = { marker: 1, verifyCurrent: f.callback };
    expect(() => f.approved.installWorkflowScheduledReviewerReadPolicy(policy)).toThrow();
    const original: any = { verifyCurrent: f.callback }; f.approved.installWorkflowScheduledReviewerReadPolicy(original);
    original.verifyCurrent = async () => { throw Error('REPLACEMENT_MUST_NOT_RUN'); };
    await expect(f.review()).resolves.toBeUndefined();
    expect(() => f.approved.installWorkflowScheduledReviewerReadPolicy({ verifyCurrent: f.callback })).toThrow();
  });
  it.each(['cluster', 'workspace', 'workflow', 'revision', 'schedule', 'step-payload', 'definition', 'expired'] as const)('rejects a substituted %s plan selector', async field => {
    const f = fixture(), plan = structuredClone(f.plan);
    if (field === 'cluster') plan.clusterId = randomUUID();
    if (field === 'workspace') plan.workspaceId = randomUUID();
    if (field === 'workflow') plan.workflowId = randomUUID();
    if (field === 'revision') plan.planRevision++;
    if (field === 'schedule') plan.scheduling.scheduleId = randomUUID();
    if (field === 'step-payload') plan.steps[0].metadata.jobId = randomUUID();
    if (field === 'definition') plan.definition.policyHash = '1'.repeat(64);
    if (field === 'expired') plan.expiresAt = new Date(Date.now() - 1).toISOString();
    await expect(f.review(f.reviewers[0], plan)).rejects.toThrow();
    expect(f.state.callbackKinds).toEqual([]); expect(f.context.peek()).toBeNull();
  });
  it('treats byte-equivalent JSON only as a selector and still performs original SQL verification', async () => {
    const f = fixture(); await f.review(f.reviewers[0], structuredClone(f.plan));
    expect(f.repository.inspectStored).toHaveBeenCalled(); expect(f.plans.load).toHaveBeenCalled();
    expect(f.state.callbackKinds).toHaveLength(1);
  });
  it.each(['disabled', 'deleted', 'password', 'credential', 'approve-grant', 'read-grant', 'foreign-grant', 'noncandidate'] as const)('rejects an actual current %s reviewer', async cause => {
    const f = fixture(), id = f.reviewers[0], user = f.users.get(id)!;
    if (cause === 'disabled') user.status = 'disabled';
    if (cause === 'deleted') user.deleted_at = new Date().toISOString();
    if (cause === 'password') user.force_password_change = true;
    if (cause === 'credential') user.credential_epoch = '2';
    if (cause === 'approve-grant') f.grants.set(id, f.grants.get(id)!.filter((g: any) => g.module !== 'workflows'));
    if (cause === 'read-grant') f.grants.set(id, f.grants.get(id)!.filter((g: any) => g.module !== 'services'));
    if (cause === 'foreign-grant') for (const g of f.grants.get(id)!) g.cluster_id = randomUUID();
    await expect(f.review(cause === 'noncandidate' ? randomUUID() : id)).rejects.toThrow();
    expect(f.context.peek()).toBeNull(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('checks the earlier reviewer even when the final approved_by remains authorized', async () => {
    const f = fixture(); f.grants.set(f.reviewers[0], []);
    await expect(f.verifySet()).rejects.toThrow();
    expect(f.callback.mock.calls.map(call => call[0])).toEqual([f.reviewers[0]]);
  });
  it.each(['permissions', 'iam', 'read-grant', 'approve-grant', 'owner-epoch'] as const)('poisons a capsule when %s changes after the first GET', async cause => {
    const f = fixture(); f.callback.mockImplementation(async (id: string, plan: any, tx: any) => {
      await f.reader.runOriginalPlan(plan, id, 'reviewer', async () => {
        await f.read();
        if (cause === 'permissions') f.users.get(id)!.permissions_epoch = '2';
        if (cause === 'iam') f.state.iamEpoch = '2';
        if (cause === 'read-grant') f.grants.set(id, f.grants.get(id)!.filter((g: any) => g.module !== 'services'));
        if (cause === 'approve-grant') f.grants.set(id, f.grants.get(id)!.filter((g: any) => g.module !== 'workflows'));
        if (cause === 'owner-epoch') f.users.get(f.owner)!.credential_epoch = '2';
        try { await f.read(); } catch { /* A denial cannot make the original capsule complete. */ }
      }, tx);
    });
    await expect(f.review()).rejects.toThrow(); expect(f.context.peek()).toBeNull();
  });
  it('rejects required unread resources and closed original handles', async () => {
    const f = fixture(); f.state.skipRead = true;
    await expect(f.review()).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_INCOMPLETE' } });
    await expect(f.reader.verifyHandle(f.state.lastHandle)).rejects.toThrow(); expect(f.context.peek()).toBeNull();
  });
  it('cannot create native authority or a fake HTTP session from the reviewer capsule', async () => {
    const f = fixture(); f.callback.mockImplementation(async (id: string, plan: any, tx: any) => {
      await f.reader.runOriginalPlan(plan, id, 'reviewer', async () => {
        await expect(f.context.authorizeRequest(f.cluster, 'POST', '/services', { host: 'forbidden' }, {})).rejects.toThrow();
        await expect(f.context.runHttp({ requestId: 'borrowed-sid' }, async () => { f.context.bindHttpActor({ id: f.owner, username: 'fake-owner', superAdmin: false }, randomUUID()); })).rejects.toThrow();
      }, tx);
    });
    await expect(f.review()).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it('preserves genuine HTTP behavior and does not call the empty-context delegate', async () => {
    const f = fixture(); f.approved.installWorkflowScheduledDelegate({ runValidationRead: vi.fn(), assertConfigurationOrigin: vi.fn() } as any);
    const original = vi.spyOn(f.approved, 'assertConfigurationOrigin').mockRejectedValue(new Error('ORIGINAL_HTTP_CONFIGURATION_CHECK'));
    await expect(f.context.runHttp({ requestId: 'actual-source-http' }, async () => {
      const actor: any = { id: f.reviewers[0], username: 'current-reviewer', superAdmin: false };
      f.context.bindHttpActor(actor, randomUUID());
      return f.context.runActor({ actor, clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'approve' }, () => f.review());
    })).rejects.toThrow('ORIGINAL_HTTP_CONFIGURATION_CHECK');
    expect(original).toHaveBeenCalled(); expect(f.callback).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it('does not enable the empty bridge for unscheduled plans', async () => {
    const f = fixture(), { scheduling: _, ...plan } = f.plan;
    await expect(f.review(f.reviewers[0], plan)).rejects.toThrow(); expect(f.callback).not.toHaveBeenCalled();
  });
  it('rejects recursive fixed callback invocation and restores the guard after failure', async () => {
    const f = fixture(); f.callback.mockImplementationOnce(async () => f.review());
    await expect(f.review()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_REVIEWER_READ_INVALID' } });
    await expect(f.review()).resolves.toBeUndefined();
  });
  it('freezes the plan before an awaited delegate can see caller mutation', async () => {
    const f = fixture(), original = structuredClone(f.plan); let release!: () => void;
    f.callback.mockImplementationOnce(async (id: string, plan: any, tx: any) => {
      await new Promise<void>(resolve => { release = resolve; });
      expect(plan.clusterId).toBe(f.cid); expect(Object.isFrozen(plan.steps[0])).toBe(true);
      await f.reader.runOriginalPlan(plan, id, 'reviewer', async () => { await f.read(); }, tx);
    });
    const pending = f.review(f.reviewers[0], original); original.clusterId = randomUUID(); release(); await pending;
  });
  it('closes if a faulty delegate changes the outer context', async () => {
    const f = fixture(), peek = vi.spyOn(f.context, 'peek');
    f.callback.mockImplementationOnce(async () => { peek.mockReturnValue({ kind: 'http', sessionId: 'forbidden' } as any); });
    await expect(f.review()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_REVIEWER_READ_CONTEXT_CHANGED' } });
  });
});
