import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { MutationService, type MutationContext } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { assertMetricsSetupPlan, metricsSetupSteps } from '../../apps/console-api/src/modules/vitals/vitals-setup-plan';
import type { MetricsSetupIntent } from '../../apps/console-api/src/modules/vitals/vitals-setup.types';
import { approvedFixture, actor, approverId, cid, eid, nativeId, sid, subjectId, wid, wf } from '../security/m6-approved-fixture';

beforeEach(() => { vi.stubEnv('APP_SECRET', 'metrics-create-approved-source-test-hmac-minimum-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); });
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

/** Controlled SQL, domain-current facts, approval-set reader and transport.
 * Context/Approved private registries, original AEAD/HMAC, Metrics plan compiler
 * and MutationService are real. No private map insertion or patched logical,
 * trusted, step or mutation-binding method mints a proof. This is not actual
 * SQL, authentication, HTTP, Kong, timer or production acceptance. */
function fixture(mode: 'native_prometheus' | 'collector' = 'native_prometheus', operation: 'create' | 'update' = 'create') {
  const f = approvedFixture(), context = new KongExecutionContextService(), executor = { ...actor, superAdmin: true };
  const state = { grantsCurrent: true, sourceCurrent: true, reviewersCurrent: true, sid: 'metrics-original-http-session' };
  Object.assign(f.workspace, { is_default: true, code: 'default' });
  const plugins = (mode === 'collector' ? ['prometheus', 'http-log'] : ['prometheus']).map((name, index) => {
    const id = index ? randomUUID() : nativeId;
    const before = operation === 'create' ? null : { id, name, enabled: false, config: {}, tags: ['kos-ws-default'] };
    const payload = operation === 'create' ? { id, name, enabled: true, config: {}, tags: ['kos-ws-default'] } : { enabled: true, config: {} };
    return { name, workspaceId: wid, workspaceRevision: 1, nativeId: id, action: operation, before, payload, schemaHmac: 'd'.repeat(64) };
  });
  const intent = { id: subjectId, mode, plugins, settings: { revision: 3 }, source: { id: randomUUID() } } as unknown as MetricsSetupIntent;
  let allocated = 0;
  Object.assign(f.plan, { kind: 'metrics-setup', subject: { type: 'metrics_setup_requests', id: subjectId }, requester: { type: 'console', id: executor.id },
    prerequisites: [], steps: metricsSetupSteps(intent, value => f.secrets.fingerprint(value), () => allocated++ === 0 ? sid : randomUUID()) });
  Object.assign(f.workflow, { requester_type: 'console', requester_user_id: executor.id, requester_developer_id: null });
  const set = { format: 2, policyHash: f.plan.definition.policyHash, setId: randomUUID(), setHmac: 'c'.repeat(64),
    reviewers: [{ approvalId: randomUUID(), userId: approverId, level: 1, candidateVersion: 1 }] };
  for (const row of [f.execution, f.workflow, f.version]) Object.assign(row, { approval_format: 2, approval_set_id: set.setId, approval_set_hmac: set.setHmac });
  let sealedHash: string;
  const seal = () => { f.seal(); sealedHash = f.secrets.fingerprint(f.plan); };
  seal();
  const assertOriginal = (plan: any) => { assertMetricsSetupPlan(plan); if (!state.sourceCurrent || f.secrets.fingerprint(plan) !== sealedHash) throw new ForbiddenException({ code: 'METRICS_SETUP_CURRENT_SOURCE_REQUIRED' }); };
  const delegate: any = {
    verifyIntent: vi.fn(async (plan: any) => assertOriginal(plan)),
    assertSubject: vi.fn(async (plan: any, userId: string, action: string) => {
      assertOriginal(plan); const frame = context.current();
      if (!state.grantsCurrent || userId !== executor.id || action !== 'write' || frame.actor?.id !== executor.id || frame.sessionId !== state.sid) throw new ForbiddenException({ code: 'METRICS_SETUP_CURRENT_AUTHOR_REQUIRED' });
    }),
    verifyReviewer: vi.fn(async (reviewer: string, plan: any) => { assertOriginal(plan); if (!state.reviewersCurrent || reviewer !== approverId || reviewer === executor.id) throw new ForbiddenException({ code: 'METRICS_SETUP_CURRENT_REVIEWER_REQUIRED' }); }),
    nativeWorkspace: vi.fn(async (plan: any, step: any) => { assertOriginal(plan); if (!plan.steps.some((s: any) => s.id === step.id && s.kind === 'native' && s.entityId === step.entityId)) throw Error('ORIGINAL_METRICS_STEP_REQUIRED'); return wid; }),
  };
  const approvals: any = { installScheduledConfigurationCanonicalSqlPolicy: vi.fn(), installReviewerPolicy: vi.fn(), verifyApprovalSet: vi.fn(async (plan: any) => { await delegate.verifyReviewer(approverId, plan); return structuredClone(set); }) };
  const workspaces: any = { resolve: vi.fn(async () => f.workspace), listScope: vi.fn(async () => ({ workspaceId: wid, mode: 'default', workspaceTag: 'kos-ws-default' })),
    matches: () => true, assertMembership: vi.fn() };
  const verifier = new ApprovedWorkflowExecutionService(f.db, f.secrets, f.authz, workspaces, f.kong, f.redis, context, approvals);
  verifier.onModuleInit(); verifier.installMetricsSetupDelegate(delegate);
  context.installPolicy({ authorizeRequest: vi.fn(async () => {
    const proof = context.currentApprovedStep(), step = f.plan.steps.find(step => step.id === proof.stepId)!;
    return { before: step.before ?? null };
  }), authorizeResponse: vi.fn(async (_ticket: unknown, result: unknown) => result) });
  const audit: any = { append: vi.fn(async () => undefined) }, mutations = new MutationService(f.db, f.redis, f.secrets, audit, f.kong, f.authz, workspaces, context);
  const http = <T>(fn: () => Promise<T>) => context.runHttp({}, async () => { context.bindHttpActor(executor, state.sid); const close = context.captureHttpCloser();
    try { return await context.runActor({ actor: executor, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write' }, fn); } finally { close(); } });
  const run = <T>(fn: () => Promise<T>, index = 0) => http(() => verifier.runApprovedExecution(eid, () => context.runApprovedStep(f.plan.steps[index].id, fn)));
  const mutation = (index = 0): MutationContext => { const step = f.plan.steps[index]; return { actor: executor, clusterId: cid, workspaceId: wid,
    entityType: step.entityType, entityId: step.mutationAction === 'create' ? undefined : step.entityId, action: step.mutationAction!,
    payload: structuredClone(step.mutationPayload), before: step.mutationAction === 'create' ? undefined : structuredClone(step.before),
    idempotencyKey: step.mutationIdempotencyKey, parentId: step.parentId, credentialKind: step.credentialKind }; };
  const sends = vi.fn(async () => undefined);
  const callback = (index = 0, resultId?: string) => vi.fn(async () => {
    const step = f.plan.steps[index], request = step.nativeRequests[0], body = request.body as any;
    const ticket = await context.authorizeRequest(f.cluster, request.method, request.canonicalPath, body, {});
    await context.beforeNativeSend(ticket); await sends();
    const result = { ...(step.before as any ?? {}), ...body, id: resultId ?? request.nativeId };
    f.nativeObjects.set(`/plugins/${request.nativeId}`, structuredClone(result));
    return context.authorizeResponse(ticket, result);
  });
  return { ...f, context, verifier, executor, state, workspaces, delegate, approvalsReader: approvals, audit, mutations, seal, run, http, mutation, callback, sends };
}

describe('Metrics native plugin CREATE original empty logical identity contract', () => {
  it('reproduces the original null logical/allocated sealed ID difference and binds through real Approved and Mutation services', async () => {
    const f = fixture(), ctx = f.mutation(), dispatch = f.callback();
    // This is EntityService.create's existing context. The pre-fix exact-ID
    // comparator rejected this real compiler-produced step before any callback.
    expect(ctx.entityId).toBeUndefined(); expect(f.plan.steps[0].entityId).toBe(nativeId); expect(ctx.entityId ?? null).not.toBe(f.plan.steps[0].entityId ?? null);
    await f.run(async () => {
      const frame = f.context.current(), step = f.context.currentApprovedStep();
      expect(frame.sessionId).toBe(f.state.sid); expect(step.kind).toBe('native');
      await f.mutations.execute(ctx, dispatch);
    });
    expect(dispatch).toHaveBeenCalledOnce(); expect(f.sends).toHaveBeenCalledOnce(); expect(ctx.entityId).toBeUndefined(); expect(f.plan.steps[0].entityId).toBe(nativeId);
    const op = [...f.operations.values()][0]; expect(op).toMatchObject({ workflow_id: wf, workflow_execution_id: eid, workflow_step_id: sid, state: 'succeeded', entity_id: nativeId, remote_started: true, remote_completed: true });
    expect(f.rows[0].operation_id).toBe(op.id); expect(f.delegate.verifyIntent).toHaveBeenCalled(); expect(f.delegate.assertSubject).toHaveBeenCalled(); expect(f.delegate.verifyReviewer).toHaveBeenCalled();
    await f.http(async () => { expect(await f.mutations.inspectStepReceipt(f.mutation())).toMatchObject({ entityId: nativeId, state: 'succeeded', remoteCompleted: true }); });
  });
  it('links the real initially NULL mutation identity before the original native callback', async () => {
    const f = fixture(), original = f.callback();
    await f.run(() => f.mutations.execute(f.mutation(), async () => { const op = [...f.operations.values()][0];
      expect(op.entity_id).toBeNull(); expect(op.workflow_step_id).toBe(sid); expect(f.rows[0].operation_id).toBe(op.id); return original(); }));
    expect([...f.operations.values()][0].entity_id).toBe(nativeId);
  });
  it('verifies the original Metrics native execution bridge before the MutationService entry', async () => {
    const f = fixture(), dispatch = f.callback();
    await f.run(async () => {
      await f.verifier.verifyMetricsSetupExecution(f.plan, eid, 'native');
      await f.mutations.execute(f.mutation(), dispatch);
    });
    expect(f.delegate.nativeWorkspace).toHaveBeenCalledOnce(); expect(dispatch).toHaveBeenCalledOnce();
    expect([...f.operations.values()][0]).toMatchObject({ entity_id: nativeId, state: 'succeeded' });
  });
  it('rejects a foreign original Metrics plugin workspace at the fixed execution bridge before allocation', async () => {
    const f = fixture(), dispatch = f.callback(); f.delegate.nativeWorkspace.mockResolvedValue(randomUUID());
    await expect(f.run(async () => {
      await f.verifier.verifyMetricsSetupExecution(f.plan, eid, 'native');
      return f.mutations.execute(f.mutation(), dispatch);
    })).rejects.toMatchObject({ response: { code: 'METRICS_SETUP_PLUGIN_WORKSPACE_REQUIRED' } });
    expect(dispatch).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0); expect(f.sends).not.toHaveBeenCalled();
  });
  it('also permits an explicit null create identity and before value without mutating either slot', async () => {
    const f = fixture(), ctx = { ...f.mutation(), entityId: null, before: null } as unknown as MutationContext;
    await f.run(() => f.mutations.execute(ctx, f.callback()));
    expect(ctx.entityId).toBeNull(); expect(ctx.before).toBeNull(); expect([...f.operations.values()][0]).toMatchObject({ entity_id: nativeId, state: 'succeeded' });
  });
  it.each([nativeId, 'explicit-foreign-id'])('does not accept a nonempty create context identity %s even if it resembles the sealed ID', async value => {
    const f = fixture(), dispatch = f.callback(); await expect(f.run(() => f.mutations.execute({ ...f.mutation(), entityId: value }, dispatch))).rejects.toMatchObject({ response: { code: 'APPROVED_MUTATION_MISMATCH' } });
    expect(dispatch).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0); expect(f.sends).not.toHaveBeenCalled();
  });
  it.each(['actor', 'cluster', 'workspace', 'entity-type', 'action', 'key', 'payload', 'before', 'parent', 'credential'])('retains the original %s logical guard before allocation', async field => {
    const f = fixture(), ctx: any = f.mutation(), dispatch = f.callback();
    if (field === 'actor') ctx.actor = { ...f.executor, id: randomUUID() };
    if (field === 'cluster') ctx.clusterId = randomUUID(); if (field === 'workspace') ctx.workspaceId = randomUUID();
    if (field === 'entity-type') ctx.entityType = 'consumers'; if (field === 'action') ctx.action = 'update'; if (field === 'key') ctx.idempotencyKey = randomUUID();
    if (field === 'payload') ctx.payload.config = { unexpected: true }; if (field === 'before') ctx.before = { unexpected: true };
    if (field === 'parent') ctx.parentId = randomUUID(); if (field === 'credential') ctx.credentialKind = 'key-auth';
    await expect(f.run(() => f.mutations.execute(ctx, dispatch))).rejects.toThrow(); expect(dispatch).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0); expect(f.sends).not.toHaveBeenCalled();
  });
  it.each(['missing-native', 'extra-native', 'native-id', 'payload-id', 'step-id', 'non-uuid', 'patch', 'path', 'request-type', 'parent', 'credential', 'before', 'before-hmac', 'body-hmac', 'native-body', 'bound-route', 'missing-settings', 'scheduled', 'other-name'])('rejects a sealed but invalid %s Metrics plan without a native callback', async field => {
    const f = fixture(), step = f.plan.steps[0], request = step.nativeRequests[0], dispatch = f.callback();
    if (field === 'missing-native') step.nativeRequests = []; if (field === 'extra-native') step.nativeRequests.push(structuredClone(request));
    if (field === 'native-id') request.nativeId = randomUUID(); if (field === 'payload-id') (step.mutationPayload as any).id = randomUUID();
    if (field === 'step-id') step.entityId = randomUUID(); if (field === 'non-uuid') step.entityId = 'invalid-id';
    if (field === 'patch') request.method = 'PATCH'; if (field === 'path') request.canonicalPath = '/consumers'; if (field === 'request-type') request.nativeType = 'consumers';
    if (field === 'parent') { step.parentId = randomUUID(); request.parentId = step.parentId; }
    if (field === 'credential') { step.credentialKind = 'key-auth'; request.credentialKind = 'key-auth'; }
    if (field === 'before') { step.before = { id: nativeId }; step.beforeFingerprint = f.secrets.fingerprint(step.before); request.beforeHmac = step.beforeFingerprint; }
    if (field === 'before-hmac') { step.beforeFingerprint = 'f'.repeat(64); request.beforeHmac = step.beforeFingerprint; }
    if (field === 'body-hmac') request.bodyHmac = 'f'.repeat(64);
    if (field === 'native-body') { request.body = { ...(request.body as any), config: { different: true } }; request.bodyHmac = f.secrets.fingerprint(request.body); }
    if (field === 'bound-route') (step.mutationPayload as any).route = { id: randomUUID() };
    if (field === 'missing-settings') f.plan.steps.pop(); if (field === 'scheduled') (f.plan as any).scheduling = {};
    if (field === 'other-name') (step.mutationPayload as any).name = 'arbitrary-plugin';
    f.seal(); await expect(f.run(() => f.mutations.execute(f.mutation(), dispatch))).rejects.toThrow();
    expect(dispatch).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0); expect(f.sends).not.toHaveBeenCalled();
  });
  it('retains current source, original SID, reviewer, permission-version and lease checks', async () => {
    for (const boundary of ['source', 'reviewer', 'grant', 'epoch', 'lease', 'session']) {
      const f = fixture(), dispatch = f.callback();
      await expect(f.run(async () => {
        if (boundary === 'source') f.state.sourceCurrent = false; if (boundary === 'reviewer') f.state.reviewersCurrent = false;
        if (boundary === 'grant') f.state.grantsCurrent = false; if (boundary === 'epoch') f.setVersion('new-permission-version');
        if (boundary === 'lease') f.redis.assertLeaseOwnership.mockRejectedValue(new Error('ORIGINAL_LEASE_LOST'));
        if (boundary === 'session') f.state.sid = 'different-authenticated-session';
        return f.mutations.execute(f.mutation(), dispatch);
      })).rejects.toThrow(); expect(dispatch).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0); expect(f.sends).not.toHaveBeenCalled();
    }
  });
  it('cannot substitute a copied binding or fabricate a private step from matching public IDs', async () => {
    const f = fixture(); let original: any;
    await f.run(async () => {
      original = f.context.currentApprovedStep(); const ctx = f.mutation(), binding = (await f.context.approvedMutationBinding(ctx))!;
      await expect(f.verifier.mutationBinding({ ...original }, ctx)).rejects.toMatchObject({ response: { code: 'APPROVED_STEP_REQUIRED' } });
      await expect(f.context.bindApprovedOperation(ctx, { ...binding }, randomUUID(), f.db)).rejects.toMatchObject({ response: { code: 'APPROVED_BINDING_INVALID' } });
    });
    await expect(f.verifier.mutationBinding(original, f.mutation())).rejects.toThrow(); expect(f.operations.size).toBe(0); expect(f.sends).not.toHaveBeenCalled();
  });
  it('preserves ordinary Portal creation and still rejects another kind with an explicitly populated sealed identity', async () => {
    const p = approvedFixture(); await p.run(async () => { expect(p.plan.steps[0].entityId).toBeUndefined(); expect(await p.context.approvedMutationBinding(p.mutationContext())).toMatchObject({ workflowId: wf }); });
    p.plan.steps[0].entityId = nativeId; p.seal(); await expect(p.run(() => p.context.approvedMutationBinding({ ...p.mutationContext(), entityId: undefined }))).rejects.toMatchObject({ response: { code: 'APPROVED_MUTATION_MISMATCH' } });
  });
  it('preserves the existing Metrics UPDATE identity and rejects an empty update slot', async () => {
    const f = fixture('native_prometheus', 'update'), before = f.plan.steps[0].before as any;
    f.nativeObjects.set(`/plugins/${nativeId}`, structuredClone(before)); const dispatch = f.callback();
    await expect(f.run(() => f.mutations.execute({ ...f.mutation(), entityId: undefined }, dispatch))).rejects.toMatchObject({ response: { code: 'APPROVED_MUTATION_MISMATCH' } });
    expect(dispatch).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0);
    await f.run(() => f.mutations.execute(f.mutation(), dispatch)); expect(dispatch).toHaveBeenCalledOnce(); expect([...f.operations.values()][0]).toMatchObject({ entity_id: nativeId, state: 'succeeded' });
  });
  it('never turns an acknowledgement for a different native UUID into successful creation', async () => {
    const f = fixture(), dispatch = f.callback(0, randomUUID()); await expect(f.run(() => f.mutations.execute(f.mutation(), dispatch))).rejects.toThrow();
    expect(dispatch).toHaveBeenCalledOnce(); expect(f.sends).toHaveBeenCalledOnce(); expect([...f.operations.values()][0].state).not.toBe('succeeded');
  });
  it('handles both fixed collector plugin creates through their genuine ordered steps', async () => {
    const f = fixture('collector');
    await f.http(() => f.verifier.runApprovedExecution(eid, async () => {
      for (let index = 0; index < 2; index++) {
        await f.context.runApprovedStep(f.plan.steps[index].id, () => f.mutations.execute(f.mutation(index), f.callback(index)));
        // Model the parent workflow acknowledgement only after its real
        // MutationService contract produced a known-success original receipt.
        const op = [...f.operations.values()].find(op => op.workflow_step_id === f.plan.steps[index].id);
        expect(op.state).toBe('succeeded'); expect(op.entity_id).toBe(f.plan.steps[index].entityId); f.rows[index].state = 'succeeded';
      }
    }));
    expect(f.sends).toHaveBeenCalledTimes(2); expect([...f.operations.values()].every(op => op.state === 'succeeded')).toBe(true);
  });
});
