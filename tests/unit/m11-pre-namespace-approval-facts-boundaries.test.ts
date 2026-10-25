import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { preNamespaceApprovalFixture } from './helpers/workflow-pre-namespace-approval-fixture';
import { workflowSchedulePlanSeal } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

const denied = (code: string) => ({ response: { code } });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cc'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('pre-Namespace facts private reader boundaries, Source only', () => {
  it('retains both original full reviewer checks for format 1 without a third tail scan', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), h = (x: unknown) => f.secrets.fingerprint(x);
    const policy = { version: 1, mode: 'single', allowSelfApproval: false, kind: f.plan.kind };
    f.plan.definition.policyHash = h(policy); f.draft.binding.policyHash = h(policy); f.draft.delegation.policyHash = h(policy);
    const { scheduling: _old, ...base } = f.plan;
    f.draft.binding.basePlanHash = h(base); f.draft.delegation.basePlanHash = h(base); f.draft.delegationHmac = h(f.draft.delegation);
    f.plan.scheduling = workflowSchedulePlanSeal(f.draft); f.draft.binding.workflowPlanHash = h(f.plan); f.persist();
    Object.assign(f.tables.workflows[0], { state: 'approved', approval_format: 1, approved_by: f.reviewers[0], candidate_version: null,
      candidate_manifest_hmac: null, approval_set_id: null, approval_set_hmac: null });
    f.tables.workflow_versions[0].approval_format = 1;
    f.stages[0].plan_hash = h(f.plan); f.votes[0].plan_hash = h(f.plan);
    const one = f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async (sql: string, args: any[]) => sql.includes('FROM workflow_definition_versions')
      ? { approval_format: 1, mode: 'single', allow_self_approval: false, policy_hash: h(policy), policy } : one(sql, args));
    const result = await f.run('before-send'); expect(result.approvalSet.format).toBe(1);
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual([
      { userId: f.reviewers[0], action: 'approve', checkpoint: 'claim' }, { userId: f.reviewers[0], action: 'approve', checkpoint: 'before-send' },
    ]); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['namespace-shaped', 'http-shaped', 'readonly-shaped'] as const)('rejects %s callers through the unchanged public full verifier', async kind => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), full = vi.spyOn(f.approvals, 'verifyApprovalSet');
    const reader = vi.spyOn(f.authority as any, 'readApprovalFacts');
    // Admission branch isolation only: a Source frame stand-in and no-op
    // subject adapter cannot constitute a real Namespace or Native authority.
    // The separate real Namespace suite checks its genuine private handles.
    vi.spyOn(f.context, 'peek').mockReturnValue(Object.freeze({ kind: 'actor', sessionId: kind === 'http-shaped' ? 'source-only-sid' : null }) as any);
    // Only the first private-selector probe sees this stand-in's absent
    // Namespace. The public verifier still executes its original Context
    // liveness check and rejects the copied frame, rather than borrowing it.
    if (kind !== 'http-shaped') vi.spyOn(f.context, 'hasWorkflowScheduledNamespace').mockReturnValueOnce(false);
    vi.mocked((f.runtime as any).subject).mockImplementation(async () => undefined);
    await expect(f.run()).rejects.toBeDefined(); expect(full).toHaveBeenCalledExactlyOnceWith(f.plan, { checkpoint: 'claim' }, f.db);
    expect(reader).not.toHaveBeenCalled(); expect(f.state.native).toEqual([]); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects a Context introduced during canonical facts rather than switching admission modes', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2');
    f.state.afterSql = async (sql: string) => { if (sql.includes('FROM workflow_approval_invalidations')) {
      f.state.afterSql = undefined; vi.spyOn(f.context, 'peek').mockReturnValue(Object.freeze({ kind: 'actor' }) as any);
    } };
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED'));
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toEqual([]);
  });

  it('keeps a missing fixed canonical reviewer policy closed', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'); (f.approvals as any).policies.delete(f.plan.kind);
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_REVIEWER_POLICY_UNAVAILABLE'));
  });

  it('rejects another invocation token even when concurrent invocations finish in reverse order', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), authority: any = f.authority, gate = authority.approvalFactsGate.bind(authority);
    const held = deferred(), release = deferred(); let first: object | undefined, checked = false;
    vi.spyOn(authority, 'approvalFactsGate').mockImplementation(async (token: object, plan: any, checkpoint: any, tx: any, phase: any) => {
      if (phase === 'enter' && !first) { first = token; held.resolve(); await release.promise; }
      else if (phase === 'enter' && !checked) { checked = true;
        await expect(gate(first, plan, checkpoint, tx, phase)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED'));
      }
      return gate(token, plan, checkpoint, tx, phase);
    });
    const before = f.run(); await held.promise; const after = await f.run(); expect(after.plan.workflowId).toBe(f.plan.workflowId);
    release.resolve(); expect((await before).plan.workflowId).toBe(f.plan.workflowId); expect(checked).toBe(true);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('does not reuse a consumed facts token after its originating invocation returns', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2'), authority: any = f.authority, gate = authority.approvalFactsGate.bind(authority);
    let original: object | undefined;
    vi.spyOn(authority, 'approvalFactsGate').mockImplementation(async (...args: any[]) => { original ??= args[0]; return gate(...args); });
    await f.run(); await expect(authority.approvalFacts(original, f.plan, { checkpoint: 'claim' }, f.db)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED'));
  });

  it('does not reinstall or replace the fixed internal reader', async () => {
    const f = await preNamespaceApprovalFixture('configuration_v2');
    expect(() => f.approvals.installScheduledEligibilityFactsReader({ enter: async () => undefined, leave: async () => undefined }))
      .toThrow(); await f.run();
  });

  it.each(['workflows-approve', 'portal-read', 'services-read'] as const)('retains actual final Root %s authorization after canonical facts', async missing => {
    const f = await preNamespaceApprovalFixture('portal-credential-issue'), reviewer = f.reviewers[0];
    f.tables.users[1].super_admin = false;
    const grants = [ ['workflows', 'approve'], ['portal', 'read'], ['services', 'read'], ['plugins', 'read'], ['consumers', 'read'], ['secrets', 'read'] ];
    for (const [module, action] of grants) if (`${module}-${action}` !== missing) f.tables.iam_effective_grants.push({ user_id: reviewer,
      module, action, cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] });
    await expect(f.run()).rejects.toBeDefined();
    expect(f.state.rootReads.filter((r: any) => r.action === 'approve')).toHaveLength(1);
    if (missing === 'services-read') expect(f.state.native.some((r: any) => r.actorId === reviewer)).toBe(true);
    else expect(f.state.native.some((r: any) => r.actorId === reviewer)).toBe(false);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('retains the actual fresh Native publication fingerprint during the final Root reviewer', async () => {
    const f = await preNamespaceApprovalFixture('portal-credential-issue');
    f.state.callback = async (read: any) => { if (read.actorId === f.reviewers[0] && read.path === `/services/${f.service.id}`) read.response.host = 'source-unapproved-change.invalid'; };
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_BUSINESS_PORTAL_NATIVE_PUBLICATION_CHANGED'));
    expect(f.db.exec).not.toHaveBeenCalled();
  });
});
