import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkflowScheduleCandidateReadService } from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import { WorkflowCandidatesService } from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import { candidateAbsenceFixture } from './helpers/workflow-scheduled-read-absence-fixture';

/** SOURCE ONLY: real Context/private Candidate state and real HMACs, with
 * controlled SQL result adapters. No network, PostgreSQL, Docker, ledger,
 * approval, mutation, permit or production acceptance is asserted here. */
function fixture(options: { admission?: boolean; maxCalls?: number } = {}) {
  const f = candidateAbsenceFixture(), context = new KongExecutionContextService();
  const sessions = new Map<string, any>(), users = new Map<string, any>();
  const h = (value: unknown) => f.secrets.fingerprint(value), ownerSid = randomUUID(), reviewerSid = randomUUID();
  const reviewers = f.approvalSet.reviewers.map(member => member.userId);
  const grant = (id: string, module: string, action: string) => ({ user_id: id, cluster_id: f.cid, workspace_id: f.wid,
    module, action, scope_type: 'global', scope_values: [] });
  const state: any = { iamEpoch: '1', originalParent: null, lastHandle: null, candidateValid: true, voteValid: true,
    row: null, manifest: null, parentReads: 0, iamGrants: new Map<string, any[]>() };
  for (const id of [f.owner, ...reviewers]) {
    users.set(id, { id, username: id === f.owner ? 'current-owner' : 'actual-reviewer', super_admin: false,
      status: 'active', deleted_at: null, force_password_change: false, credential_epoch: '1', permissions_epoch: '1' });
    state.iamGrants.set(id, [grant(id, 'services', 'read'), grant(id, 'secrets', 'read'), grant(id, 'workflows', id === f.owner ? 'write' : 'approve')]);
  }
  sessions.set(ownerSid, { id: ownerSid, user_id: f.owner, credential_epoch: '1', revoked_at: null,
    expires_at: new Date(Date.now() + 600000).toISOString(), refresh_expires_at: new Date(Date.now() + 600000).toISOString() });
  sessions.set(reviewerSid, { ...sessions.get(ownerSid), id: reviewerSid, user_id: reviewers[0] });
  const policy: any = { version: 2, kind: f.plan.kind, allowSelfApproval: false, distinctAcrossStages: true, intentTtlHours: 1,
    stages: reviewers.map((id, index) => ({ level: index + 1, name: `stage-${index + 1}`, mode: 'any', threshold: 1, selector: { users: [id] } })) };
  f.values.definition = policy; f.values.selectorVersion = 2;
  f.plan.definition.policyHash = h(policy); f.draft.binding.policyHash = h(policy); f.draft.delegation.policyHash = h(policy); f.reseal();
  const stages = reviewers.map((id, index) => ({ level: index + 1, mode: 'any', threshold: 1,
    candidates: [{ userId: id, credentialEpoch: '1', provenance: [{ kind: 'user', selectorId: id }] }] }));
  const manifest: any = { version: 1, clusterId: f.cid, workspaceId: f.wid, workflowId: f.plan.workflowId, planRevision: f.plan.planRevision,
    planHash: h(f.plan), definitionId: f.plan.definition.id, definitionVersion: f.plan.definition.version,
    policyHash: f.plan.definition.policyHash, candidateVersion: 1, stages };
  const manifestHmac = h(manifest);
  state.manifest = manifest; f.values.frozen = { manifest, manifest_hmac: manifestHmac };
  state.row = { id: f.plan.workflowId, cluster_id: f.cid, workspace_id: f.wid, requester_id: f.owner,
    state: 'pending', plan_revision: f.plan.planRevision, plan_hash: h(f.plan), approval_format: 2,
    candidate_version: 1, candidate_manifest_hmac: manifestHmac };
  state.votes = reviewers.map((id, index) => ({ id: f.approvalSet.reviewers[index].approvalId, cluster_id: f.cid, workspace_id: f.wid,
    workflow_id: f.plan.workflowId, plan_revision: f.plan.planRevision, plan_hash: h(f.plan), level: index + 1,
    approver_id: id, decision: 'approve', candidate_version: 1, candidate_manifest_hmac: manifestHmac }));
  const baseOne = f.db.one.getMockImplementation()!, baseQuery = f.db.query.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM iam_epoch')) return { version: state.iamEpoch };
    if (sql.includes('FROM users')) {
      const value = users.get(args[0]);
      if (!value || value.status !== 'active' || value.deleted_at !== null || value.force_password_change) return null;
      return { ...value };
    }
    if (sql.includes('FROM auth_sessions')) {
      const value = sessions.get(args[0]);
      if (!value || value.revoked_at !== null || Date.parse(value.expires_at) <= Date.now()) return null;
      if (args.length > 1 && typeof args[1] === 'string' && users.has(args[1]) && value.user_id !== args[1]) return null;
      const user = users.get(value.user_id);
      if (!user || user.status !== 'active' || user.deleted_at !== null || user.force_password_change) return null;
      return { session_id: value.id, user_id: value.user_id, session_credential_epoch: value.credential_epoch,
        user_credential_epoch: user.credential_epoch, permissions_epoch: user.permissions_epoch, iam_version: state.iamEpoch };
    }
    if (sql.includes('FROM workflow_candidate_versions')) return state.candidateValid ? f.values.frozen : null;
    if (sql.includes('FROM workflows')) return { ...state.row };
    if (sql.includes('FROM workflow_approvals')) return state.voteValid ? state.votes.find((vote: any) => args.includes(vote.approver_id)) ?? state.votes[0] : null;
    return baseOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('iam_effective_grants')) return (state.iamGrants.get(args[0]) ?? []).map((row: any) => ({ ...row, scope_values: [...row.scope_values] }));
    if (sql.includes('FROM workflow_approvals')) return state.voteValid ? state.votes.filter((vote: any) => args.length < 5 || args[4] === vote.approver_id).map((vote: any) => ({ ...vote })) : [];
    return baseQuery(sql, args);
  });
  f.plans.load.mockImplementation(async () => ({ plan: f.plan, row: { ...state.row } }));
  f.policies.resolveReadScope.mockImplementation(async () => ({ version: 1, resources: f.values.resources,
    limits: { maxCalls: options.maxCalls ?? 10, maxPages: 5, maxRecords: 10, maxBytes: 8192 } }));
  const service = new WorkflowScheduleCandidateReadService(f.db, f.secrets, context, f.plans, f.repository, new WorkflowCandidatesService(f.db));
  const provider = { verifyHandle: service.verifyHandle.bind(service), assertLive: service.assertLive.bind(service),
    authorizeRequest: service.authorizeRequest.bind(service), verifyRequest: service.verifyRequest.bind(service), authorizeResponse: service.authorizeResponse.bind(service) };
  const generic = vi.fn(async () => { throw new Error('ORDINARY_HTTP_POLICY_MUST_NOT_RUN'); });
  context.installPolicy({ authorizeRequest: generic, authorizeResponse: generic }); context.installWorkflowScheduleCandidateReadPolicy(provider);
  const verifyParent = vi.fn(async (handle: object, frame: any) => {
    state.parentReads++; return (service as any).assertOriginalHttpAcceptance(handle, frame);
  });
  if (options.admission !== false) (context as any).installWorkflowCandidateHttpAdmissionPolicy({ verifyParent });
  service.installStorageContract('a'.repeat(64)); service.installBusinessPolicy(f.plan.kind, f.policies);
  service.installContextRunner({ assertNoFrame() { (context as any).assertWorkflowScheduleCandidateReadAdmission(); },
    run(handle, fn) { state.lastHandle = handle; return context.runWorkflowScheduleCandidateRead(handle, fn); } });
  const actor = (id: string) => ({ id, username: users.get(id)?.username ?? 'unknown', superAdmin: false, forcePasswordChange: false,
    permissionsVersion: `${id}:1:1` });
  const http = <T>(fn: () => Promise<T>, config: any = {}) => context.runHttp({ requestId: 'source-admission' }, async () => {
    const actual = config.actor ?? actor(config.userId ?? f.owner);
    if (config.bind !== false) context.bindHttpActor(actual, config.noSid ? undefined : config.sid ?? (actual.id === f.owner ? ownerSid : reviewerSid));
    if (config.actorFrame === false) return fn();
    return context.runActor({ actor: actual, clusterId: config.clusterId ?? f.cid, workspaceId: config.workspaceId ?? f.wid,
      module: config.module ?? 'workflows', action: config.action ?? (actual.id === f.owner ? 'write' : 'approve') }, async () => {
      state.originalParent = context.current(); return fn();
    });
  });
  const run = <T>(fn: (handle: object) => Promise<T>, readActor = reviewers[1], role: 'executor' | 'reviewer' = 'reviewer') =>
    service.runOriginalPlan(f.plan, readActor, role, fn);
  const cluster: any = { id: f.cid, admin_url: 'http://kong:8001', version: '1.5.1', revision: 1, execution_mode: 'approval' };
  const packet = () => context.authorizeRequest(cluster, 'GET', f.values.resources[0].path, undefined, {});
  const response = () => ({ id: f.nativeId, host: 'controlled-source-response' });
  const read = async () => {
    const ticket = await packet(); await context.refreshAuthorization(ticket); await context.beforeNativeSend(ticket);
    return context.authorizeResponse(ticket, response());
  };
  return { ...f, context, service, state, sessions, users, ownerSid, reviewerSid, reviewers, actor, http, run, packet, response, read,
    cluster, provider, generic, verifyParent, grant };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T12:00:00Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('Candidate original HTTP-parent admission (Source-only)', () => {
  it('links owner HTTP ancestry while keeping the actual reviewer identity and no browser SID', async () => {
    const f = fixture(); await f.http(() => f.run(async handle => {
      const frame = f.context.current(), proof = await f.service.verifyHandle(handle);
      expect(frame.kind).toBe('workflow-candidate-read'); expect(frame.actor?.id).toBe(f.reviewers[1]);
      expect(frame.sessionId).toBeUndefined(); expect(proof.sessionId).toBeNull(); expect(proof.role).toBe('reviewer');
      await expect(f.read()).resolves.toEqual(f.response());
      expect(f.context.currentUsage().calls).toBe(1);
      expect(f.state.originalParent.actor.id).toBe(f.owner);
    }));
    expect(f.verifyParent).toHaveBeenCalled(); expect(f.generic).not.toHaveBeenCalled();
    expect(f.policies.authorizeResponse.mock.calls[0][0].principal.user.id).toBe(f.reviewers[1]);
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('allows actual voted reviewer approve ancestry and independently reads as the delegated owner', async () => {
    const f = fixture(); await f.http(() => f.run(async handle => {
      const proof = await f.service.verifyHandle(handle); expect(proof.actor.id).toBe(f.owner); expect(proof.role).toBe('executor');
      await f.read();
    }, f.owner, 'executor'), { userId: f.reviewers[0], action: 'approve' });
    expect(f.policies.authorizeResponse.mock.calls[0][0].principal.user.id).toBe(f.owner);
    expect(f.state.originalParent.actor.id).toBe(f.reviewers[0]); expect(f.generic).not.toHaveBeenCalled();
  });
  it('preserves old empty-context reads without any HTTP parent callback', async () => {
    const f = fixture(); await f.run(async () => { await f.read(); });
    expect(f.verifyParent).not.toHaveBeenCalled(); expect(f.generic).not.toHaveBeenCalled();
  });
  it('keeps HTTP ancestry default-closed when the fixed admission policy is not installed', async () => {
    const f = fixture({ admission: false }); await expect(f.http(() => f.run(async () => { await f.read(); }))).rejects.toThrow();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it.each(['missing-actor', 'missing-sid', 'http-only', 'wrong-module', 'read-action', 'delete-action', 'foreign-cluster', 'foreign-workspace', 'owner-approve', 'reviewer-write'])
  ('rejects %s ancestry before any Candidate read response', async reason => {
    const f = fixture(), config: any = {};
    if (reason === 'missing-actor') { config.bind = false; config.actorFrame = false; }
    if (reason === 'missing-sid') config.noSid = true;
    if (reason === 'http-only') config.actorFrame = false;
    if (reason === 'wrong-module') config.module = 'services';
    if (reason === 'read-action') config.action = 'read';
    if (reason === 'delete-action') config.action = 'delete';
    if (reason === 'foreign-cluster') config.clusterId = randomUUID();
    if (reason === 'foreign-workspace') config.workspaceId = randomUUID();
    if (reason === 'owner-approve') config.action = 'approve';
    if (reason === 'reviewer-write') { config.userId = f.reviewers[0]; config.action = 'write'; }
    await expect(f.http(() => f.run(async () => { await f.read(); }), config)).rejects.toThrow();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled(); expect(f.generic).not.toHaveBeenCalled();
  });
  it.each(['revoked-session', 'expired-session', 'session-user', 'session-epoch', 'parent-epoch', 'parent-pv', 'parent-iam', 'parent-disabled', 'parent-password', 'parent-grant'])
  ('rejects a current %s change before the next packet', async reason => {
    const f = fixture(); await expect(f.http(() => f.run(async () => {
      await f.read(); const session = f.sessions.get(f.ownerSid), owner = f.users.get(f.owner)!;
      if (reason === 'revoked-session') session.revoked_at = new Date().toISOString();
      if (reason === 'expired-session') session.expires_at = new Date(Date.now() - 1).toISOString();
      if (reason === 'session-user') session.user_id = f.reviewers[0];
      if (reason === 'session-epoch') session.credential_epoch = '2';
      if (reason === 'parent-epoch') owner.credential_epoch = '2';
      if (reason === 'parent-pv') owner.permissions_epoch = '2';
      if (reason === 'parent-iam') f.state.iamEpoch = '2';
      if (reason === 'parent-disabled') owner.status = 'disabled';
      if (reason === 'parent-password') owner.force_password_change = true;
      if (reason === 'parent-grant') f.state.iamGrants.set(f.owner, f.state.iamGrants.get(f.owner).filter((g: any) => g.module !== 'workflows'));
      try { await f.packet(); } catch { /* A caught denial cannot complete the capsule. */ }
    }))).rejects.toThrow();
    expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1); expect(f.generic).not.toHaveBeenCalled();
  });
  it.each(['permissionsVersion', 'username', 'superAdmin', 'forcePasswordChange'])('does not trust a caller-shaped actor %s value', async field => {
    const f = fixture(), actor: any = { ...f.actor(f.owner) };
    actor[field] = field === 'superAdmin' || field === 'forcePasswordChange' ? true : 'caller-shaped-value';
    await expect(f.http(() => f.run(async () => { await f.read(); }), { actor })).rejects.toThrow();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled(); expect(f.generic).not.toHaveBeenCalled();
  });
  it.each(['missing-vote', 'reject-vote', 'wrong-vote-plan', 'wrong-vote-candidate', 'wrong-vote-hmac', 'missing-manifest', 'changed-manifest', 'voter-epoch', 'voter-grant'])
  ('rejects %s on actual reviewer approve ancestry', async reason => {
    const f = fixture();
    if (reason === 'missing-vote') f.state.voteValid = false;
    if (reason === 'reject-vote') f.state.votes[0].decision = 'reject';
    if (reason === 'wrong-vote-plan') f.state.votes[0].plan_hash = 'f'.repeat(64);
    if (reason === 'wrong-vote-candidate') f.state.votes[0].candidate_version = 2;
    if (reason === 'wrong-vote-hmac') f.state.votes[0].candidate_manifest_hmac = 'e'.repeat(64);
    if (reason === 'missing-manifest') f.state.candidateValid = false;
    if (reason === 'changed-manifest') f.state.manifest.stages[0].candidates[0].credentialEpoch = '2';
    if (reason === 'voter-epoch') f.users.get(f.reviewers[0])!.credential_epoch = '2';
    if (reason === 'voter-grant') f.state.iamGrants.set(f.reviewers[0], f.state.iamGrants.get(f.reviewers[0]).filter((g: any) => g.module !== 'workflows'));
    await expect(f.http(() => f.run(async () => { await f.read(); }), { userId: f.reviewers[0], action: 'approve' })).rejects.toThrow();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('uses the actual reviewer entity grants rather than borrowing the HTTP owner grants', async () => {
    const f = fixture(); f.state.iamGrants.set(f.reviewers[1], [f.grant(f.reviewers[1], 'workflows', 'approve')]);
    await expect(f.http(() => f.run(async () => { await f.read(); }))).rejects.toMatchObject({ response: { code: 'ACTUAL_ENTITY_READ_DENIED' } });
    expect(f.policies.authorizeResponse.mock.calls[0][0].principal.user.id).toBe(f.reviewers[1]);
    expect(f.generic).not.toHaveBeenCalled();
  });
  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('never admits Native %s from a linked readonly capsule', async method => {
    const f = fixture(); await f.http(() => f.run(async () => {
      await expect(f.context.authorizeRequest(f.cluster, method, '/services', undefined, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_ONLY' } });
      await f.read();
    })); expect(f.generic).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rejects GET body null in Context and retains the valid GET-only read path', async () => {
    const f = fixture(); await f.http(() => f.run(async () => {
      await expect(f.context.authorizeRequest(f.cluster, 'GET', f.values.resources[0].path, null, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_ONLY' } });
      await f.read();
    }));
  });
  it('retains HTTP ancestor budget accounting across independent linked capsules', async () => {
    const f = fixture(); await f.http(async () => {
      await f.run(async () => { await f.read(); }); await f.run(async () => { await f.read(); });
      expect(f.context.currentUsage().calls).toBe(2);
    });
  });
  it('retains the current Candidate call budget before allocating another provider request', async () => {
    const f = fixture({ maxCalls: 1 }); await f.http(() => f.run(async () => {
      await f.read(); await expect(f.packet()).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CALL_LIMIT' } });
    }));
    expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('never accepts a copied handle', async () => {
    const f = fixture(); await f.http(() => f.run(async handle => {
      await expect((f.service as any).assertOriginalHttpAcceptance({}, f.state.originalParent)).rejects.toThrow();
      await f.read();
    }));
  });
  it('poisons a caught copied-parent attempt on the original Candidate handle', async () => {
    const f = fixture(); await expect(f.http(() => f.run(async handle => {
      try { await (f.service as any).assertOriginalHttpAcceptance(handle, { ...f.state.originalParent }); } catch { /* Exact pointer required. */ }
    }))).rejects.toThrow();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it.each(['operation', 'archive', 'internal-read', 'configuration-purpose'])('rejects %s already active under the HTTP ancestor', async kind => {
    const f = fixture(); await f.http(async () => {
      const invoke = () => f.run(async () => { await f.read(); });
      const operation = { actor: f.context.current().actor!, clusterId: f.cid, workspaceId: f.wid,
        operationId: randomUUID(), module: 'workflows', action: 'write', entityType: 'services', entityId: f.nativeId };
      if (kind === 'operation') await expect(f.context.runOperation(operation, invoke)).rejects.toThrow();
      if (kind === 'archive') await expect(f.context.runOperation(operation, () => f.context.runArchiveDelete({ clusterId: f.cid,
        workspaceId: f.wid, operationId: operation.operationId, entryId: randomUUID(), nodes: [{ path: f.values.resources[0].path,
          type: 'services', id: f.nativeId }] }, invoke))).rejects.toThrow();
      if (kind === 'internal-read') await expect(f.context.runInternalRead(f.cid, 'capture', invoke)).rejects.toThrow();
      if (kind === 'configuration-purpose') await expect(f.context.runActor({ actor: f.context.current().actor!, clusterId: f.cid,
        workspaceId: f.wid, module: 'workflows', action: 'write', purpose: 'configuration' }, invoke)).rejects.toThrow();
    }); expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('retains the genuine HTTP closer fence while a linked capsule is running', async () => {
    const f = fixture(); await expect(f.http(async () => {
      const close = f.context.captureHttpCloser(); return f.run(async () => {
        await f.read(); close(); await expect(f.packet()).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
      });
    })).rejects.toThrow();
    expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('cannot reuse a completed original read handle from the HTTP parent', async () => {
    const f = fixture(); let original: object | undefined;
    await f.http(async () => {
      await f.run(async handle => { original = handle; await f.read(); });
      await expect(f.context.runWorkflowScheduleCandidateRead(original!, async () => {})).rejects.toThrow();
      await expect((f.service as any).assertOriginalHttpAcceptance(original!, f.context.current())).rejects.toThrow();
    }); expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('rechecks reviewer votes before send when approval ancestry was accepted earlier', async () => {
    const f = fixture(); await expect(f.http(() => f.run(async () => {
      const ticket = await f.packet(); f.state.voteValid = false;
      try { await f.context.beforeNativeSend(ticket); } catch { /* End of capsule also remains denied. */ }
    }), { userId: f.reviewers[0], action: 'approve' })).rejects.toThrow();
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });
  it('does not detach linked reads into an independent worker Namespace or a nested Candidate', async () => {
    const f = fixture(); await f.http(() => f.run(async () => {
      await expect(f.context.runWorkflowScheduledNamespace({}, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN' } });
      await expect(f.run(async () => { await f.read(); })).rejects.toThrow();
      await f.read();
    })); expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('cannot detach a linked Candidate into a fresh HTTP context to rebind an actor and SID', async () => {
    const f = fixture(), rebind = vi.fn(() => f.context.bindHttpActor(f.actor(f.owner), f.ownerSid));
    await f.http(() => f.run(async () => {
      expect(() => f.context.runHttp({}, rebind)).toThrowError(expect.objectContaining({ response: { code: 'WORKFLOW_CANDIDATE_READ_ONLY', message: expect.any(String) } }));
      expect(rebind).not.toHaveBeenCalled();
      expect(f.context.current().actor?.id).toBe(f.reviewers[1]); expect(f.context.current().sessionId).toBeUndefined();
      await f.read();
    })); expect(f.generic).not.toHaveBeenCalled(); expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('blocks an async escaped read after its real Candidate and actor parents have closed', async () => {
    const f = fixture(); let release!: () => void, escaped!: Promise<unknown>;
    const gate = new Promise<void>(resolve => { release = resolve; });
    await f.http(() => f.run(async () => {
      await f.read(); escaped = gate.then(() => f.packet());
    }));
    const check = expect(escaped).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    release(); await check; expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
  it('rejects installing an extra callback or registering the fixed policy twice', () => {
    const context = new KongExecutionContextService();
    expect(() => (context as any).installWorkflowCandidateHttpAdmissionPolicy({ verifyParent: async () => undefined, grants: () => true })).toThrow();
    (context as any).installWorkflowCandidateHttpAdmissionPolicy({ verifyParent: async () => undefined });
    expect(() => (context as any).installWorkflowCandidateHttpAdmissionPolicy({ verifyParent: async () => undefined })).toThrow();
  });
});
