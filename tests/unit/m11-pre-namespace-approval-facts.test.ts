import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { preNamespaceApprovalFixture } from './helpers/workflow-pre-namespace-approval-fixture';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cb'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };

describe('pre-Namespace scheduled canonical facts with one mandatory full Root reviewer, Source only', () => {
  it.each(['configuration_v2', 'portal-credential-issue'] as const)('keeps the actual %s SQL/AEAD/GET chain and every final reviewer', async kind => {
    const f = await preNamespaceApprovalFixture(kind, 2), original = vi.spyOn(f.approvals, 'verifyApprovalSet');
    const result = await f.run('before-send');
    expect(result.approvalSet.reviewers.map((r: any) => r.userId)).toEqual(f.reviewers);
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual(f.reviewers.map(userId => ({ userId, action: 'approve', checkpoint: 'before-send' })));
    expect(new Set(f.state.native.map((r: any) => r.actorId))).toEqual(new Set([f.actor, ...f.reviewers]));
    expect(f.state.native.length).toBeGreaterThan(0); expect(original).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it.each(['configuration_v2', 'portal-credential-issue'] as const)('retains the exact canonical %s pre-Namespace Root reviewer and GET scope', async kind => {
    const f = await preNamespaceApprovalFixture(kind);
    await f.publicFull(); const canonical = f.state.native.filter((r: any) => r.actorId === f.reviewers[0]).map((r: any) => r.path);
    expect(f.state.rootReads).toEqual([{ userId: f.reviewers[0], action: 'approve', checkpoint: 'claim' }]);
    f.state.native.length = 0; f.state.rootReads.length = 0;
    await f.run('before-send');
    expect(f.state.native.filter((r: any) => r.actorId === f.reviewers[0]).map((r: any) => r.path)).toEqual(canonical);
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual([{ userId: f.reviewers[0], action: 'approve', checkpoint: 'before-send' }]);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['status', 'credential', 'manifest', 'candidate-row', 'vote', 'stage', 'member', 'set', 'invalidation'] as const)('retains canonical rejection for current %s', async reason => {
    const f = await preNamespaceApprovalFixture('configuration_v2');
    if (reason === 'status') f.tables.users[1].status = 'disabled';
    if (reason === 'credential') f.tables.users[1].credential_epoch = '2';
    if (reason === 'manifest') f.manifest.stages[0].candidates[0].credentialEpoch = '2';
    if (reason === 'candidate-row') f.candidateRows[0].credential_epoch = '2';
    if (reason === 'vote') f.votes[0].decision = 'reject';
    if (reason === 'stage') f.stages[0].required_approvals = 2;
    if (reason === 'member') f.setMembers[0].user_id = f.actor;
    if (reason === 'set') f.set.set_hmac = '0'.repeat(64);
    if (reason === 'invalidation') f.state.invalidated = true;
    await expect(f.run()).rejects.toBeDefined(); expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual([]);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['role', 'team'] as const)('keeps actual current %s selector checks before and after the final reviewer', async selector => {
    const f = await preNamespaceApprovalFixture('configuration_v2', 1, selector);
    f.state.afterReviewer = async () => { f.state[selector === 'role' ? 'roleLive' : 'teamLive'] = false; };
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_APPROVER_SELECTOR_REVOKED'));
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['invalidation', 'iam', 'reviewer-status', 'reviewer-credential', 'cluster', 'policy', 'lease', 'deadline'] as const)('rejects %s changed after the last full reviewer and before publication', async reason => {
    const f = await preNamespaceApprovalFixture('configuration_v2');
    f.state.afterReviewer = async () => {
      if (reason === 'invalidation') f.state.invalidated = true;
      if (reason === 'iam') f.tables.iam_epoch[0].version = '2';
      if (reason === 'reviewer-status') f.tables.users[1].status = 'disabled';
      if (reason === 'reviewer-credential') f.tables.users[1].credential_epoch = '2';
      if (reason === 'cluster') f.cluster.revision++;
      if (reason === 'policy') f.plans.definition.mockImplementation(async () => ({ ...f.plan.definition, version: 2 }));
      if (reason === 'lease') f.state.lease = false;
      if (reason === 'deadline') vi.spyOn(Date, 'now').mockReturnValue(Date.parse(f.plan.expiresAt));
    };
    await expect(f.run()).rejects.toBeDefined(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects an IAM change during the final canonical facts observation', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'); let observations = 0;
    f.state.afterSql = async (sql: string) => { if (sql.includes('FROM workflow_approval_invalidations') && ++observations === 2) f.tables.iam_epoch[0].version = '2'; };
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_APPROVAL_PERMISSIONS_CHANGED'));
  });

  it('does not publish before its last reviewer has actually completed', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), entered = deferred(), release = deferred();
    f.state.afterReviewer = async () => { entered.resolve(); await release.promise; };
    let published = false; const pending = f.run().then(() => { published = true; });
    await entered.promise; expect(published).toBe(false); release.resolve(); await pending; expect(published).toBe(true);
  });

  it('propagates an unknown full-reviewer error without publishing authority', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), unknown = new Error('SOURCE_UNKNOWN_REVIEWER_ERROR');
    f.state.afterReviewer = async () => { throw unknown; };
    await expect(f.run()).rejects.toBe(unknown); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects a nested eligibility invocation before issuing another GET', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2');
    f.state.afterReviewer = async () => { const before = f.state.native.length;
      await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_REENTRANT')); expect(f.state.native).toHaveLength(before); };
    await f.run();
  });

  it.each(['forged', 'copied-plan', 'foreign-tx', 'foreign-checkpoint', 'outside-scope', 'consumed'] as const)('rejects a %s facts token independently of a valid full reviewer', async reason => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), authority: any = f.authority;
    const gate = authority.approvalFactsGate.bind(authority); let exercised = false;
    vi.spyOn(authority, 'approvalFactsGate').mockImplementation(async (token: object, plan: any, checkpoint: any, tx: any, phase: any) => {
      if (!exercised && phase === (reason === 'consumed' ? 'leave' : 'enter')) {
        exercised = true;
        if (reason === 'consumed') { await gate(token, plan, checkpoint, tx, phase);
          await expect(gate(token, plan, checkpoint, tx, 'enter')).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED')); return; }
        const invoke = () => gate(reason === 'forged' ? Object.freeze({}) : token, reason === 'copied-plan' ? structuredClone(plan) : plan,
          reason === 'foreign-checkpoint' ? 'packet' : checkpoint, reason === 'foreign-tx' ? { ...tx } : tx, phase);
        if (reason === 'outside-scope') await authority.eligibilityScope.exit(() => expect(invoke()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED')));
        else await expect(invoke()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED'));
      }
      return gate(token, plan, checkpoint, tx, phase);
    });
    await f.run(); expect(exercised).toBe(true); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('retains the public full reviewer policy after installing the internal reader', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'); await f.publicFull();
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
    f.tables.users[1].status = 'disabled'; await expect(f.publicFull()).rejects.toBeDefined();
    expect(f.db.exec).not.toHaveBeenCalled();
  });
});
