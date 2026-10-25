import 'reflect-metadata';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';
import { WorkflowCandidatesService } from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import { workflowSchedulePlanSeal } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { WorkflowScheduleCandidateReadService } from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import { grantMatchesEntity } from '../../apps/console-api/src/modules/authorization/grant-policy';

/** Actual reader and crypto/grant predicates; SQL, Root runner and business
 * compiler are controlled fixtures, never production subject authorization,
 * an actual Admin API response, live SQL026 or native execution evidence. */
function fixture(collection = false, kind: 'configuration_v2' | 'portal-credential-issue' = 'configuration_v2') {
  const f = workflowScheduledFixture(kind), nativeId = randomUUID(), reviewer = f.approvalSet.reviewers[0].userId;
  const policyBody: any = { version: 1, mode: 'single', allowSelfApproval: false, kind };
  f.plan.definition.policyHash = f.secrets.fingerprint(policyBody); f.draft.binding.policyHash = f.plan.definition.policyHash;
  f.draft.delegation.policyHash = f.plan.definition.policyHash;
  const reseal = () => { const { scheduling, ...base } = f.plan;
    f.draft.binding.basePlanHash = f.secrets.fingerprint(base); f.draft.delegation.basePlanHash = f.draft.binding.basePlanHash;
    f.draft.delegationHmac = f.secrets.fingerprint(f.draft.delegation); f.plan.scheduling = workflowSchedulePlanSeal(f.draft);
    f.draft.binding.workflowPlanHash = f.secrets.fingerprint(f.plan); };
  reseal(); f.state.workflowState = 'pending';
  const values: any = { read: true, secrets: true, secretResource: false, definition: policyBody, selectorVersion: 1, frozen: null, scopeChanged: false,
    badScope: false, last: null, counter: 0, resources: [{ clusterId: f.cid, workspaceId: f.wid, path: collection ? '/services' : `/services/${nativeId}`,
      kind: collection ? 'collection' : 'point', entityType: 'services', ...(collection ? { query: { size: 2 } } : { entityId: nativeId }), secrets: false }] };
  const baseOne = f.db.one.getMockImplementation()!, baseQuery = f.db.query.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, args: any[]) => {
    if (sql.includes('FROM workflow_definition_versions')) return { approval_format: values.selectorVersion, policy: values.definition, policy_hash: f.plan.definition.policyHash, mode: 'single', allow_self_approval: false };
    if (sql.includes('FROM workflow_candidate_versions')) return values.frozen;
    if (sql.includes('SELECT status,deleted_at,force_password_change,credential_epoch FROM users')) return f.state.ownerActive && !f.state.forceChange
      ? { status: 'active', deleted_at: null, force_password_change: false, credential_epoch: f.state.epoch } : null;
    return baseOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[]) => {
    if (sql.includes('iam_effective_grants')) return [{ user_id: args[0], cluster_id: f.cid, workspace_id: f.wid, module: 'services', action: 'read', scope_type: 'global', scope_values: [] },
      ...(values.secrets ? [{ user_id: args[0], cluster_id: f.cid, workspace_id: f.wid, module: 'secrets', action: 'read', scope_type: 'global', scope_values: [] }] : [])];
    return baseQuery(sql, args);
  });
  const policies: any = { resolveReadScope: vi.fn(async () => ({ version: 1, resources: values.resources,
    limits: { maxCalls: 10, maxPages: 5, maxRecords: 10, maxBytes: 8192 } })),
    assertCurrent: vi.fn(async () => { if (!values.read) throw new ForbiddenException({ code: 'ACTUAL_BUSINESS_READ_DENIED' }); }),
    authorizeResponse: vi.fn(async (input: any) => {
      if (values.scopeChanged) throw new ForbiddenException({ code: 'ACTUAL_OBJECT_SCOPE_CHANGED' });
      const items = input.resource.kind === 'collection' ? input.response.data : input.resource.kind === 'schema' || input.status === 404 ? [] : [input.response];
      for (const item of items) {
        const target = { clusterId: input.resource.clusterId, workspaceId: input.resource.workspaceId, entityType: 'services', entity: item };
        if (!input.principal.grants.some((g: any) => grantMatchesEntity(g, 'services', 'read', target))) throw new ForbiddenException({ code: 'ACTUAL_ENTITY_READ_DENIED' });
        if (input.resource.secrets && !input.principal.grants.some((g: any) => grantMatchesEntity(g, 'secrets', 'read', target))) throw new ForbiddenException({ code: 'ACTUAL_SECRET_READ_DENIED' });
      }
    }) };
  const service = new WorkflowScheduleCandidateReadService(f.db, f.secrets, f.context, f.plans, f.repository, new WorkflowCandidatesService(f.db));
  const runner: any = { assertNoFrame: vi.fn(() => { if (f.state.frame !== null) throw new ForbiddenException({ code: 'ACTUAL_EMPTY_CONTEXT_REQUIRED' }); }),
    run: vi.fn(async (handle: object, fn: any) => { runner.assertNoFrame(); values.last = handle; f.state.frame = { originalCandidateRead: handle };
      try { return await fn(); } finally { f.state.frame = null; } }) };
  const install = () => { service.installStorageContract('a'.repeat(64)); service.installBusinessPolicy(kind, policies); service.installContextRunner(runner); };
  const packet = (query: any = collection ? { size: 2 } : {}, overrides: any = {}) => ({ clusterId: f.cid, workspaceId: f.wid, method: 'GET', path: values.resources[0].path, query, ...overrides });
  const read = async (handle: object, raw: any = { id: nativeId, host: 'actual-controlled-read' }, query: any = collection ? { size: 2 } : {}, status = 200) => {
    const token = await service.authorizeRequest(handle, packet(query)); await service.verifyRequest(token); return service.authorizeResponse(token, raw, status);
  };
  return { ...f, service, values, policies, runner, install, nativeId, reviewer, reseal, packet, read };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T22:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M11 original scheduled candidate READ (controlled business/SQL/Root context)', () => {
  it('defaults closed and installs every fixed adapter once', async () => {
    const f = fixture(); await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async () => true)).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_CONTEXT_UNAVAILABLE' } });
    expect(() => f.service.installBusinessPolicy('native-change' as any, f.policies)).toThrow(); expect(() => f.service.installContextRunner({ run: f.runner.run } as any)).toThrow();
    f.install(); expect(() => f.install()).toThrow();
  });
  it.each([{}, { sessionId: randomUUID() }, { origin: 'scheduled-entity' }, { origin: 'capture', sessionId: null }])('never borrows or clears inherited frame %j', async frame => {
    const f = fixture(); f.install(); f.state.frame = frame;
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async () => true)).rejects.toMatchObject({ response: { code: 'ACTUAL_EMPTY_CONTEXT_REQUIRED' } });
    expect(f.state.frame).toBe(frame); expect(f.plans.load).not.toHaveBeenCalled();
  });
  it('returns real SQL principal with NULL SID and private request proof, never a writable namespace or copied identity', async () => {
    const f = fixture(); f.install(); await f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      const proof = await f.service.verifyHandle(handle); expect(proof.origin).toBe('workflow-schedule-candidate-read'); expect(proof.readOnly).toBe(true);
      expect(proof.actor.id).toBe(f.owner); expect(proof.sessionId).toBeNull(); expect(proof).not.toHaveProperty('claim'); expect(Object.isFrozen(proof.actor)).toBe(true);
      for (const copy of [{ ...handle }, { ...proof }, { ...proof.actor }]) await expect(f.service.verifyHandle(copy)).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED' } });
      await f.read(handle);
    }); await expect(f.service.verifyHandle(f.values.last)).rejects.toBeDefined();
  });
  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('rejects %s before a native packet/namespace can be created', async method => {
    const f = fixture(); f.install(); await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      await expect(f.service.authorizeRequest(handle, f.packet({}, { method, body: { approved: true } }))).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_GET_ONLY' } });
      return { approved: true };
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
  });
  it('rejects foreign path, wrong CID/WID, body and copied request tokens', async () => {
    const f = fixture(); f.install();
    for (const wrong of [{ path: `/services/${randomUUID()}` }, { clusterId: randomUUID() }, { workspaceId: randomUUID() }])
      await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
        await expect(f.service.authorizeRequest(handle, f.packet({}, wrong))).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_PATH_FORBIDDEN' } });
      })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      await expect(f.service.authorizeRequest(handle, f.packet({}, { body: { fake: true } }))).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_GET_ONLY' } });
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    await f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      const token = await f.service.authorizeRequest(handle, f.packet());
      await expect(f.service.authorizeResponse({ ...token }, { id: f.nativeId })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_ORIGINAL_REQUEST_REQUIRED' } });
      await f.service.verifyRequest(token); await f.service.verifyRequest(token); await f.service.authorizeResponse(token, { id: f.nativeId });
      await expect(f.service.verifyRequest(token)).rejects.toBeDefined();
    });
  });
  it.each(['epoch', 'password', 'read', 'registry', 'plan', 'deadline'])('revalidates %s before DNS/response and never returns stale private data', async reason => {
    const f = fixture(); f.install(); await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      const token = await f.service.authorizeRequest(handle, f.packet());
      if (reason === 'epoch') f.state.epoch = '2'; else if (reason === 'password') f.state.forceChange = true;
      else if (reason === 'read') f.values.read = false; else if (reason === 'registry') f.state.directMode = true;
      else if (reason === 'plan') f.plan.steps[0].metadata.planHash = '0'.repeat(64); else vi.advanceTimersByTime(30000);
      await f.service.verifyRequest(token); await f.service.authorizeResponse(token, { id: f.nativeId, private: 'not-delivered' });
    })).rejects.toBeDefined(); expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('checks actual current object scope and secret grants before returning raw material', async () => {
    const f = fixture(); f.values.resources[0].secrets = true; f.install();
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => { const token = await f.service.authorizeRequest(handle, f.packet());
      f.values.scopeChanged = true; return f.service.authorizeResponse(token, { id: f.nativeId, key: 'controlled-source-only-key' }); })).rejects.toMatchObject({ response: { code: 'ACTUAL_OBJECT_SCOPE_CHANGED' } });
    const g = fixture(); g.values.resources[0].secrets = true; g.values.secrets = false; g.install();
    await expect(g.service.runOriginalPlan(g.plan, g.owner, 'executor', handle => g.read(handle))).rejects.toMatchObject({ response: { code: 'ACTUAL_SECRET_READ_DENIED' } });
  });
  it('refuses actual private fields mislabeled as a non-secret resource even if the fixed callback would accept them', async () => {
    const f = fixture(); f.install();
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      await expect(f.read(handle, { id: f.nativeId, config: { password: 'controlled-test-only' } }))
        .rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_SECRET_SCOPE_REQUIRED' } });
      return { accepted: true };
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('requires every declared read to finish rather than accepting an authentic-looking no-read result', async () => {
    const f = fixture(); f.install(); await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async () => ({ approved: true }))).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_INCOMPLETE' } });
  });
  it('observes continuous exact cursor EOF, rejects arbitrary offset and revalidates DNS without reallocating a pending cursor', async () => {
    const f = fixture(true); f.install(); await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      await expect(f.service.authorizeRequest(handle, f.packet({ size: 2, offset: 'body-chosen' }))).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_CURSOR_INVALID' } });
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    await f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      const token = await f.service.authorizeRequest(handle, f.packet({ size: 2 })); await f.service.verifyRequest(token); await f.service.verifyRequest(token);
      await f.service.authorizeResponse(token, { data: [{ id: f.nativeId }], next: '/services?size=2&offset=opaque-next' });
      await f.read(handle, { data: [{ id: randomUUID() }], next: null }, { size: 2, offset: 'opaque-next' });
    });
  });
  it('never accepts EOF from a rejected final page even when the caller catches the response failure', async () => {
    const f = fixture(true); f.install(); const first = { data: [{ id: f.nativeId }], next: '/services?offset=last' };
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      const accepted = await f.read(handle, first);
      f.values.scopeChanged = true;
      await expect(f.read(handle, { data: [{ id: randomUUID() }], next: null }, { size: 2, offset: 'last' }))
        .rejects.toMatchObject({ response: { code: 'ACTUAL_OBJECT_SCOPE_CHANGED' } });
      f.values.scopeChanged = false;
      await expect(f.service.verifyHandle(handle)).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
      return accepted;
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(2);
  });
  it('poisons optional point reads and dynamic verification failures rather than letting callers shrink the scope', async () => {
    const f = fixture(); f.values.resources[0].required = false; f.install();
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      const token = await f.service.authorizeRequest(handle, f.packet()); f.state.forceChange = true;
      await expect(f.service.verifyRequest(token)).rejects.toBeDefined(); f.state.forceChange = false;
      return { callerSelectedSubset: [] };
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
  });
  it.each(['truncated', 'duplicate', 'foreign-next', 'ambiguous-next', 'cycle', 'budget'])('rejects %s collections rather than shrinking current observed configuration', async reason => {
    const f = fixture(true); f.install(); await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      if (reason === 'truncated') return f.read(handle, { data: [] });
      if (reason === 'foreign-next') return f.read(handle, { data: [], next: 'http://foreign:8001/services?offset=foreign' });
      if (reason === 'ambiguous-next') return f.read(handle, { data: [], next: '/services?offset=first&offset=second' });
      if (reason === 'budget') { f.policies.resolveReadScope.mockImplementation(async () => ({ version: 1, resources: f.values.resources, limits: { maxCalls: 10, maxPages: 5, maxRecords: 10, maxBytes: 8192 } }));
        return f.read(handle, { data: [{ id: f.nativeId, enormous: 'x'.repeat(9000) }], next: null }); }
      await f.read(handle, { data: [{ id: f.nativeId }], next: '/services?offset=next' });
      return f.read(handle, { data: reason === 'duplicate' ? [{ id: f.nativeId }] : [], next: reason === 'cycle' ? '/services?offset=next' : null }, { size: 2, offset: 'next' });
    })).rejects.toBeDefined();
  });
  it('supports actual pending-policy selection before approvals without resolving itself recursively', async () => {
    const f = fixture(); f.values.selectorVersion = 2; f.values.definition = { version: 2, kind: 'configuration_v2', allowSelfApproval: false,
      distinctAcrossStages: true, intentTtlHours: 24, stages: [{ level: 1, name: 'Selected reviewers', mode: 'any', threshold: 1, selector: { users: [f.reviewer] } }] };
    f.plan.definition.policyHash = f.secrets.fingerprint(f.values.definition); f.draft.binding.policyHash = f.plan.definition.policyHash; f.draft.delegation.policyHash = f.plan.definition.policyHash; f.reseal(); f.install();
    await f.service.runOriginalPlan(f.plan, f.reviewer, 'reviewer', async handle => { const proof = await f.service.verifyHandle(handle); expect(proof.actor.id).toBe(f.reviewer); await f.read(handle); });
    expect(f.state.workflowState).toBe('pending'); expect(f.approvals.verifyApprovalSet).not.toHaveBeenCalled();
    await expect(f.service.runOriginalPlan(f.plan, randomUUID(), 'reviewer', async () => true)).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_REVIEWER_REQUIRED' } });
  });
  it('preserves real developer/executor identity and refuses mandatory developer password change', async () => {
    const f = fixture(false, 'portal-credential-issue'); f.install(); await f.service.runOriginalPlan(f.plan, f.owner, 'executor', handle => f.read(handle));
    expect(f.plan.requester.id).toBe(f.developer); expect(f.owner).not.toBe(f.developer); f.state.forceRequesterChange = true;
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', handle => f.read(handle))).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_REQUESTER_REVOKED' } });
  });
});
