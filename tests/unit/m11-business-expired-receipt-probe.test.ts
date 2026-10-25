import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { WorkflowBusinessExecutionService } from '../../apps/console-api/src/modules/workflows/workflow-business-execution.service';

/** Real BusinessExecution/Context/Mutation receipt inspector and AES/HMA.
 * SQL, original fixed Root policies, approved prefix and native dispatch are
 * controlled adapters. Original private completion is minted only by execute;
 * no runtime, PostgreSQL trigger, actual Native send or historical fixup. */
function fixture() {
  const secrets = new SecretService(), context = new KongExecutionContextService(), now = Date.now();
  const cid = randomUUID(), wid = randomUUID(), wf = randomUUID(), subject = randomUUID(), developer = randomUUID();
  const actor: any = Object.freeze({ id: randomUUID(), username: 'source-original-executor', superAdmin: false });
  const authorityHandle = Object.freeze({}), namespaceHandle = Object.freeze({}), expiry = new Date(now + 60000).toISOString();
  const ids = [randomUUID(), randomUUID(), randomUUID()], transportScope = transportScopeFor('http://kong:8001');
  const bodies = [{ id: ids[0], username: `app-${wf}` }, { id: ids[1], group: 'source-portal' },
    { id: ids[2], key: 'source-synthetic-key-never-log' }];
  const paths = ['/consumers', `/consumers/${ids[0]}/acls`, `/consumers/${ids[0]}/key-auth`];
  const native = ids.map((id, index): any => ({ id: randomUUID(), key: `native-${index + 1}`, order: index + 1, kind: 'native',
    entityType: index ? 'credentials' : 'consumers', entityId: id, parentId: index ? ids[0] : undefined,
    credentialKind: index ? index === 1 ? 'acls' : 'key-auth' : undefined, permissionAction: 'write', dependencies: [],
    mutationAction: 'create', mutationPayload: bodies[index], mutationPayloadHmac: secrets.fingerprint(bodies[index]),
    mutationIdempotencyKey: `source-${wf}-${index + 1}`, before: null, beforeFingerprint: secrets.fingerprint(null),
    nativeRequests: [{ method: 'POST', canonicalPath: paths[index], nativeType: index ? index === 1 ? 'acls' : 'key-auth' : 'consumers',
      nativeId: id, body: bodies[index], bodyHmac: secrets.fingerprint(bodies[index]) }] }));
  native[1].dependencies = [native[0].id]; native[2].dependencies = [native[1].id];
  const metadata: any = { id: randomUUID(), key: 'activate', order: 4, kind: 'metadata', handler: 'portal.credential.activate',
    entityType: 'portal_application_grants', entityId: subject, permissionAction: 'write', dependencies: [native[2].id], nativeRequests: [],
    metadata: { consumerId: ids[0], aclId: ids[1], kongId: ids[2], credentialId: randomUUID(), action: 'issue' }, metadataRevision: 1,
    before: { id: subject, state: 'pending' }, metadataBeforeHmac: secrets.fingerprint({ id: subject, state: 'pending' }) };
  metadata.metadataPayloadHmac = secrets.fingerprint(metadata.metadata);
  const claim: any = { id: randomUUID(), scheduleId: randomUUID(), occurrenceId: randomUUID(), generation: 1, workflowId: wf,
    workflowPlanRevision: 1, issuedAt: new Date(now - 1000).toISOString(), authorityExpiresAt: expiry };
  const set = { format: 2, setId: randomUUID(), setHmac: 'c'.repeat(64), reviewers: [{ userId: randomUUID() }] };
  const plan: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId: wf, planRevision: 1, kind: 'portal-credential-issue',
    executionMode: 'approval', approvalRequired: true, subject: { type: 'portal_application_grants', id: subject },
    requester: { type: 'developer', id: developer }, definition: { id: randomUUID(), version: 1, policyHash: 'b'.repeat(64) },
    issuedAt: new Date(now - 2000).toISOString(), expiresAt: expiry, scope: { transportScope, clusterRevision: 1, workspaceRevision: 1 },
    prerequisites: [], steps: [...native, metadata], scheduling: { version: 1, scheduleId: claim.scheduleId,
      occurrenceId: claim.occurrenceId, executorId: actor.id } };
  claim.workflowPlanHash = secrets.fingerprint(plan);
  const ns: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', sessionId: null, actor, clusterId: cid, workspaceId: wid,
    kind: plan.kind, permissionVersion: 'source-original-pv', credentialEpoch: '1', transportScope, clusterRevision: 1, workspaceRevision: 1,
    expiresAt: expiry, workflow: { id: wf, planRevision: 1, planHash: claim.workflowPlanHash }, claim, requester: plan.requester, approvalSet: set });
  const inspection: any = { version: 1, claim, draft: { scheduleId: claim.scheduleId, binding: { workflowId: wf, workflowPlanRevision: 1,
    workflowPlanHash: claim.workflowPlanHash, clusterId: cid, workspaceId: wid } }, plan, approvalSet: set, principal: actor,
    permissionVersion: ns.permissionVersion, leaseUntil: expiry, authorityExpiresAt: expiry };
  const stored: any = { w: { id: wf, state: 'approved', revision: 2, plan_revision: 1, plan_hash: claim.workflowPlanHash,
    approval_format: 2, approved_by: set.reviewers[0].userId }, e: null, origin: null,
    steps: plan.steps.map((s: any) => ({ id: s.id, kind: s.kind, step_order: s.order, state: 'pending', operation_id: null })),
    operations: [], audits: [] };
  const state: any = { failAt: 1, expire: false, queryFailure: null, mutationQueryFailure: null, auditFailure: null,
    terminalCasFailure: null, deriveFailure: null, revokeInspector: false, primary: new ForbiddenException({ code: 'SOURCE_PRIMARY_AUTHORITY_FAILURE' }) };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('iam_epoch')) return { version: 1 };
    if (sql.includes('SELECT id FROM workflow_executions')) return stored.e ? { id: stored.e.id } : null;
    if (sql.includes("state='running' ORDER BY step_order")) {
      if (state.queryFailure) throw state.queryFailure;
      return stored.steps.find((s: any) => s.state === 'running') ?? null;
    }
    if (sql.includes('w.state AS workflow_state')) return stored.e && stored.origin ? { ...stored.e, workflow_state: stored.w.state,
      origin_id: stored.origin.id, claim_id: stored.origin.claim_id, schedule_id: stored.origin.schedule_id, executor_id: stored.origin.executor_id } : null;
    if (sql.includes('FROM mutation_operations')) { if (state.mutationQueryFailure) throw state.mutationQueryFailure; return null; }
    throw new Error('UNEXPECTED_CONTROLLED_READ');
  }), exec: vi.fn(async (sql: string, p: any[]) => {
    if (sql.startsWith("UPDATE workflows SET state='executing'")) { stored.w.state = 'executing'; stored.w.revision++; return 1; }
    if (sql.startsWith('INSERT INTO workflow_executions')) {
      stored.e = { id: p[0], cluster_id: p[1], workspace_id: p[2], workflow_id: p[3], plan_revision: p[4], plan_hash: p[5],
        execution_actor_id: p[7], expires_at: p[10], permission_version: p[13], state: 'executing', snapshot_state: 'pending' }; return 1;
    }
    if (sql.startsWith('INSERT INTO workflow_execution_origins')) {
      stored.origin = { id: p[0], schedule_id: p[3], claim_id: p[4], execution_id: p[8], executor_id: p[9] }; return 1;
    }
    if (sql.startsWith("UPDATE workflow_executions SET snapshot_state='ready'")) {
      Object.assign(stored.e, { snapshot_state: 'ready', snapshot_secret: p[1], snapshot_hash: p[2], snapshot_id: p[3] }); return 1;
    }
    if (sql.startsWith("UPDATE workflow_steps SET state='running'")) { stored.steps.find((s: any) => s.id === p[0]).state = 'running'; return 1; }
    if (sql.startsWith("UPDATE workflow_steps SET state='succeeded'")) {
      Object.assign(stored.steps.find((s: any) => s.id === p[0]), { state: 'succeeded', safe_result: JSON.parse(p[1]), receipt_secret: p[2], after_fingerprint: p[3] }); return 1;
    }
    if (sql.startsWith('UPDATE workflow_steps SET state=$2')) {
      if (state.terminalCasFailure === 'step') return 0;
      Object.assign(stored.steps.find((s: any) => s.id === p[0]), { state: p[1], error_code: p[2], safe_result: JSON.parse(p[3]), completed_at: new Date().toISOString() }); return 1;
    }
    if (sql.startsWith('UPDATE workflow_executions SET state=$2')) {
      if (state.terminalCasFailure === 'execution') return 0;
      Object.assign(stored.e, { state: p[1], completed_at: new Date().toISOString() }); return 1;
    }
    if (sql.startsWith('UPDATE workflows SET state=$2')) {
      if (state.terminalCasFailure === 'workflow') return 0;
      stored.w.state = p[1]; return 1;
    }
    throw new Error('UNEXPECTED_CONTROLLED_WRITE');
  }), transaction: vi.fn(async (fn: any) => {
    const snapshot = structuredClone(stored);
    try { return await fn(db); } catch (error) { Object.assign(stored, snapshot); throw error; }
  }) };
  const namespaceRegistry = new WeakMap<object, any>([[namespaceHandle, ns]]), authorityRegistry = new WeakMap<object, any>([[authorityHandle, inspection]]);
  const executions = new WeakMap<object, any>(), approvedSteps = new WeakMap<object, any>();
  context.installWorkflowScheduledNamespacePolicy({ assertLive: h => {
    if (!namespaceRegistry.has(h)) throw new ForbiddenException({ code: 'SOURCE_ORIGINAL_NAMESPACE_REQUIRED' });
  }, verifyHandle: async h => {
    const value = namespaceRegistry.get(h); if (!value) throw new ForbiddenException(); return value;
  } });
  context.installApprovedPolicy({ verifyExecution: async h => { const p = executions.get(h); if (!p) throw new ForbiddenException(); return p; },
    verifyWorkflowScheduledExecution: async (p, h) => { if (h !== namespaceHandle || p.executionId !== stored.e.id) throw new ForbiddenException(); },
    verifyStep: async (p, id) => { const s = plan.steps.find((x: any) => x.id === id), row = stored.steps.find((x: any) => x.id === id);
      if (!s || row.state !== 'running') throw new ForbiddenException(); const proof: any = Object.freeze({ execution: p, stepId: id, kind: s.kind }); approvedSteps.set(proof, s); return proof; },
    assertNative: async () => { throw new Error('NO_NATIVE_AUTHORITY_IN_THIS_FIXTURE'); }, assertMetadata: async () => { throw new Error('NO_METADATA_WRITE_IN_THIS_FIXTURE'); },
    mutationBinding: async () => { throw new Error('NO_MUTATION_BINDING_IN_THIS_FIXTURE'); }, bindOperation: async () => { throw new Error('NO_OPERATION_IN_THIS_FIXTURE'); } });
  const kong: any = { request: vi.fn(async () => { throw new Error('NO_KONG_IO'); }) };
  const authz: any = { permissionVersion: vi.fn(async () => ns.permissionVersion), assertCluster: vi.fn(async () => {
    if (state.revokeInspector) throw new ForbiddenException({ code: 'SOURCE_INSPECTOR_AUTHORITY_REVOKED' });
  }) };
  const workspaces: any = { resolve: vi.fn(async () => ({ id: wid, status: 'active' })) };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn(async () => undefined) };
  const audit: any = { append: vi.fn(async (event: any, tx: any) => {
    if (tx !== db) throw new Error('ORIGINAL_TRANSACTION_REQUIRED');
    if (event.action === 'workflow.execute' && state.auditFailure) throw state.auditFailure;
    stored.audits.push(secrets.redact(event));
  }) };
  const mutations = new MutationService(db, redis, secrets, audit, kong, authz, workspaces, context);
  const receiptProbe = vi.spyOn(mutations, 'inspectStepReceipt'), receipts = new Map<string, any>();
  const approved: any = { runApprovedBusinessExecution: vi.fn(async (h: object, id: string, fn: any) => {
    if (h !== namespaceHandle || id !== stored.e.id) throw new ForbiddenException();
    const proof = Object.freeze({ executionId: id, workflowId: wf, actorId: actor.id, clusterId: cid, workspaceId: wid, sessionId: null,
      permissionVersion: ns.permissionVersion, expiresAt: Date.parse(expiry), origin: 'scheduled-workflow', scheduleClaimId: claim.id, workflowOriginId: stored.origin.id });
    const handle = Object.freeze({}); executions.set(handle, proof);
    try { return await context.runApprovedWorkflow(handle as any, fn); } finally { executions.delete(handle); }
  }) };
  const dispatch = vi.fn(async (_p: any, step: any) => {
    if (step.order === state.failAt) {
      if (state.expire) { vi.advanceTimersByTime(60001); context.current(); }
      throw state.primary;
    }
    // Prior known completions are controlled dispatch facts, not Native sends.
    const receipt = { operationId: randomUUID(), state: 'succeeded', remoteStarted: true, remoteCompleted: true, entityId: step.entityId, safeResult: {} };
    receipts.set(step.mutationIdempotencyKey, receipt); stored.operations.push(receipt);
    stored.steps.find((s: any) => s.id === step.id).operation_id = receipt.operationId;
    return structuredClone(step.mutationPayload);
  });
  const mutationContext = (p: any, s: any, a: any): any => ({ clusterId: p.clusterId, workspaceId: p.workspaceId, actor: a.user,
    entityType: s.entityType, entityId: s.mutationAction === 'create' ? undefined : s.entityId, action: s.mutationAction,
    idempotencyKey: s.mutationIdempotencyKey, payload: s.mutationPayload, before: s.before, parentId: s.parentId, credentialKind: s.credentialKind });
  const plans: any = { load: vi.fn(async () => ({ row: structuredClone(stored.w), plan: structuredClone(plan) })) };
  const registry: any = { get: vi.fn(() => { throw new Error('PORTAL_ACTIVATION_MUST_NOT_RUN'); }) };
  const service = new WorkflowBusinessExecutionService({ db, redis, secrets, context, authz, audit, mutations, plans, registry, approved, dispatch, mutationContext });
  const delegate = { verifyOriginalClaim: vi.fn(async (h: object, n: object) => {
    if (!authorityRegistry.has(h) || n !== namespaceHandle || context.requireWorkflowScheduledNamespaceHandle() !== n) throw new ForbiddenException();
    return authorityRegistry.get(h);
  }), captureSnapshot: vi.fn(async (_h: object, _n: object, p: any, eid: string) => ({ version: 1, workflowId: wf, executionId: eid,
    clusterId: cid, workspaceId: wid, planRevision: 1, planHash: claim.workflowPlanHash, capturedAt: new Date().toISOString(),
    objects: p.steps.flatMap((s: any) => s.nativeRequests.map((r: any) => ({ type: r.nativeType, id: r.nativeId,
      path: `${r.canonicalPath}/${r.nativeId}`, before: null, absent: true, fingerprint: secrets.fingerprint(null) }))) })),
    readNativeAfter: vi.fn(async (_h: object, _n: object, _p: any, s: any) => structuredClone(s.mutationPayload)),
    deriveCompletion: vi.fn(async (h: object, eid: string) => {
      if (state.deriveFailure) throw state.deriveFailure;
      if (!authorityRegistry.has(h) || eid !== stored.e?.id || !stored.origin || !stored.e.completed_at) throw new ForbiddenException();
      return stored.e.state;
    }) };
  service.install(delegate as any);
  const run = () => context.runWorkflowScheduledNamespace(namespaceHandle, () => service.execute(authorityHandle, namespaceHandle));
  return { service, context, mutations, receiptProbe, authz, db, audit, kong, dispatch, registry, delegate, stored, state, claim,
    plan, expiry, authorityHandle, namespaceHandle, run, receipts, mutationContext, actor };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'e7'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T14:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('M11 original business catch cannot be aborted by an expired receipt probe (Source-only)', () => {
  it('uses the real Context ancestor expiry and real Mutation inspector, then records uncertain without any Native/operation', async () => {
    const f = fixture(); f.state.expire = true;
    let completion: any;
    // The business catch commits the terminal fact before the original outer
    // Namespace fence rejects its now-expired continuation. That rejection
    // never erases the opaque completion or permits another Native attempt.
    await expect(f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      completion = await f.service.execute(f.authorityHandle, f.namespaceHandle);
    })).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(completion).toBeDefined();
    expect(f.receiptProbe).toHaveBeenCalledOnce();
    await expect(f.receiptProbe.mock.results[0].value).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(f.stored.w.state).toBe('uncertain'); expect(f.stored.e.state).toBe('uncertain');
    expect(f.stored.steps[0]).toMatchObject({ state: 'uncertain', error_code: 'KONG_EXECUTION_CONTEXT_EXPIRED', safe_result: {} });
    expect(f.stored.steps.slice(1).every((s: any) => s.state === 'pending')).toBe(true);
    expect(f.stored.operations).toEqual([]); expect(f.kong.request).not.toHaveBeenCalled(); expect(f.dispatch).toHaveBeenCalledOnce();
    expect(f.registry.get).not.toHaveBeenCalled(); expect(f.db.one.mock.calls.some(([sql]: any[]) => sql.includes('FROM mutation_operations'))).toBe(false);
    const terminal = f.stored.audits.filter((a: any) => a.action === 'workflow.execute');
    expect(terminal).toHaveLength(1); expect(terminal[0]).toMatchObject({ result: 'uncertain', after: { state: 'uncertain', code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(f.stored.e.expires_at).toBe(f.expiry); expect(f.stored.origin.claim_id).toBe(f.claim.id);
    expect(f.context.peek()).toBeNull();
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
    for (const copy of [{ ...completion }, { state: 'uncertain' }, 'uncertain']) await expect(f.service.verifyCompletion(f.authorityHandle, copy as any, f.db))
      .rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED' } });
    await expect(f.service.verifyCompletion({ ...f.authorityHandle }, completion, f.db)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED' } });
    await expect(f.service.execute(f.authorityHandle, f.namespaceHandle)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_BUSINESS_EXECUTION_REPLAY_FORBIDDEN' } });
    expect(f.dispatch).toHaveBeenCalledOnce();
    expect(JSON.stringify(f.stored.audits)).not.toContain('source-synthetic-key-never-log');
  });

  it('keeps the original business error when the real historical inspector loses current authorization', async () => {
    const f = fixture(); f.state.revokeInspector = true;
    const completion = await f.run();
    expect(f.authz.assertCluster).toHaveBeenCalledOnce();
    await expect(f.receiptProbe.mock.results[0].value).rejects.toMatchObject({ response: { code: 'SOURCE_INSPECTOR_AUTHORITY_REVOKED' } });
    expect(f.stored.steps[0]).toMatchObject({ state: 'uncertain', error_code: 'SOURCE_PRIMARY_AUTHORITY_FAILURE', safe_result: {} });
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain'); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('treats a real inspector SQL failure as unavailable evidence, keeping the original error and an uncertain terminal', async () => {
    const f = fixture(); f.state.mutationQueryFailure = new Error('controlled inspector SQL failure');
    const completion = await f.run();
    expect(f.db.one.mock.calls.some(([sql]: any[]) => sql.includes('FROM mutation_operations'))).toBe(true);
    expect(f.stored.steps[0]).toMatchObject({ state: 'uncertain', error_code: 'SOURCE_PRIMARY_AUTHORITY_FAILURE', safe_result: {} });
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
  });
  it.each([new Error('controlled callback probe failure'), new ForbiddenException({ code: 'SOURCE_PROBE_FORBIDDEN' }),
    new ConflictException({ code: 'SOURCE_PROBE_CONFLICT' }), new ServiceUnavailableException({ code: 'SOURCE_PROBE_UNAVAILABLE' })])
  ('does not let an independent receipt adapter failure replace the original business code', async probeError => {
    const f = fixture(); f.receiptProbe.mockRejectedValueOnce(probeError);
    const completion = await f.run();
    expect(f.stored.w.state).toBe('uncertain'); expect(f.stored.steps[0].error_code).toBe('SOURCE_PRIMARY_AUTHORITY_FAILURE');
    expect(f.stored.steps[0].safe_result).toEqual({}); expect(f.kong.request).not.toHaveBeenCalled();
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
  });
  it('keeps an earlier controlled completion from masking a later unreadable outcome as partial', async () => {
    const f = fixture(); f.state.failAt = 2;
    f.receiptProbe.mockImplementation(async input => {
      if (input.idempotencyKey === f.plan.steps[0].mutationIdempotencyKey) return f.receipts.get(input.idempotencyKey)!;
      throw new ForbiddenException({ code: 'SOURCE_SECOND_PROBE_EXPIRED' });
    });
    const completion = await f.run();
    expect(f.stored.steps[0].state).toBe('succeeded'); expect(f.stored.steps[1].state).toBe('uncertain');
    expect(f.stored.e.state).toBe('uncertain'); expect(f.dispatch).toHaveBeenCalledTimes(2); expect(f.kong.request).not.toHaveBeenCalled();
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
  });

  it('preserves the prior readable-null/original-403 failed branch instead of broadening every failure', async () => {
    const f = fixture(), completion = await f.run();
    expect(f.receiptProbe).toHaveBeenCalledOnce(); await expect(f.receiptProbe.mock.results[0].value).resolves.toBeNull();
    expect(f.stored.e.state).toBe('failed'); expect(f.stored.steps[0]).toMatchObject({ state: 'failed', error_code: 'SOURCE_PRIMARY_AUTHORITY_FAILURE' });
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('failed');
  });
  it.each(['pending', 'running', 'uncertain'])('preserves a readable %s operation as unresolved', async state => {
    const f = fixture(); f.receiptProbe.mockResolvedValueOnce({ operationId: randomUUID(), state, remoteStarted: true,
      remoteCompleted: true, entityId: f.plan.steps[0].entityId, safeResult: {} });
    const completion = await f.run();
    expect(f.stored.e.state).toBe('uncertain'); await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
  });
  it('preserves the original partial branch for a readable completed, non-unresolved operation', async () => {
    const f = fixture(), operationId = randomUUID();
    f.receiptProbe.mockResolvedValueOnce({ operationId, state: 'succeeded', remoteStarted: true,
      remoteCompleted: true, entityId: f.plan.steps[0].entityId, safeResult: {} });
    const completion = await f.run();
    expect(f.stored.e.state).toBe('partial'); expect(f.stored.steps[0].safe_result).toEqual({ nativeOperationId: operationId, remoteStarted: true, remoteCompleted: true });
    await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('partial');
  });
  it.each([new ServiceUnavailableException({ code: 'SOURCE_PRIMARY_SERVER_FAILURE' }),
    new ConflictException({ code: 'SOURCE_PRIMARY_UNKNOWN', state: 'uncertain' }), new Error('controlled original failure')])
  ('does not downgrade an original unknown/server failure when a readable receipt is absent', async primary => {
    const f = fixture(); f.state.primary = primary; const completion = await f.run();
    expect(f.stored.e.state).toBe('uncertain'); await expect(f.service.verifyCompletion(f.authorityHandle, completion, f.db)).resolves.toBe('uncertain');
  });

  it.each(['step', 'execution', 'workflow'])('does not swallow a downstream %s CAS failure or manufacture completion', async where => {
    const f = fixture(); f.state.expire = true; f.state.terminalCasFailure = where;
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_BUSINESS_CAS_CONFLICT' } });
    expect(f.stored.e.state).toBe('executing'); expect(f.stored.w.state).toBe('executing'); expect(f.stored.steps[0].state).toBe('running');
    expect(f.stored.audits.filter((a: any) => a.action === 'workflow.execute')).toEqual([]);
    expect(f.delegate.deriveCompletion).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('does not swallow an active-step lookup failure', async () => {
    const f = fixture(), error = new Error('controlled active-step SQL failure'); f.state.expire = true; f.state.queryFailure = error;
    await expect(f.run()).rejects.toBe(error); expect(f.receiptProbe).not.toHaveBeenCalled();
    expect(f.stored.e.state).toBe('executing'); expect(f.delegate.deriveCompletion).not.toHaveBeenCalled();
  });
  it('does not swallow the original terminal audit transaction failure', async () => {
    const f = fixture(), error = new Error('controlled audit write failure'); f.state.expire = true; f.state.auditFailure = error;
    await expect(f.run()).rejects.toBe(error); expect(f.stored.e.state).toBe('executing'); expect(f.stored.w.state).toBe('executing');
    expect(f.stored.steps[0].state).toBe('running'); expect(f.delegate.deriveCompletion).not.toHaveBeenCalled();
  });
  it('does not turn a rejected original Root completion verifier into a returned closure', async () => {
    const f = fixture(), error = new Error('controlled original Root completion failure'); f.state.expire = true; f.state.deriveFailure = error;
    await expect(f.run()).rejects.toBe(error); expect(f.stored.e.state).toBe('uncertain');
    expect(f.delegate.deriveCompletion).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
  });
});
