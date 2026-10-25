import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException } from '@nestjs/common';
import { fixedValidationFixture, fixedSourceWorkspaces } from './helpers/m11-fixed-validation-reader-fixture';
import { WorkflowBusinessRuntimeService } from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import { WorkflowBusinessScopedReadService } from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });

/** Component boundary: actual Root onModuleInit registration, full
 * withLiveReads/readResources, real validation provider private capabilities,
 * Context ALS and Kong SDK 404 observation. Controlled SQL, original Namespace
 * issuer, configuration material and fixed Approved/closed-SQL providers do not
 * prove real Root claim/Approved read-handle minting, database SQL, HTTP, timer
 * or Native sends. No product private Map or provider field is seeded. The
 * independent capability suite exercises actual Approved issuance/cleanup.
 * Target reader cases below exercise the defensive read component. Incomplete
 * V2 Target-append seals stay fail-closed at schedule gates; well-formed seals
 * are admitted past author/revision/activate/preclaim (natural execute is separate). */
function fixture(kind: 'update' | 'create' | 'target' = 'update') {
  const f: any = fixedValidationFixture(false), nativeId = randomUUID(), allocatedId = randomUUID(), upstreamId = randomUUID();
  const jobId = randomUUID(), executionId = randomUUID(), jobStepId = randomUUID(), planStepId = randomUUID(), planId = randomUUID();
  const unrelatedId = randomUUID(), point = (type: string, id: string, extra: any = {}) => ({ clusterId: f.cid, workspaceId: f.wid,
    path: `/${type}/${id}`, kind: 'point', entityType: type, entityId: id, required: true, secrets: false, ...extra });
  // Generic currentBefore observations use a Consumer. A Service PATCH also
  // requires its real scheduled Approved/job/operation observer boundary,
  // which this direct-delegate fixture deliberately does not manufacture.
  const schemaType = kind === 'update' ? 'consumers' : 'services';
  const unrelated = point('services', unrelatedId), schema = { clusterId: f.cid, workspaceId: f.wid, path: `/schemas/${schemaType}`, kind: 'schema', entityType: schemaType, secrets: false, required: true };
  const targetPath = `/upstreams/${upstreamId}/targets`, path = kind === 'target' ? targetPath : kind === 'create' ? '/services' : `/consumers/${nativeId}`;
  const method = kind === 'update' ? 'PATCH' : 'POST', body = kind === 'target' ? { id: allocatedId, target: '127.0.0.1:8080', weight: 70 } : kind === 'create' ? { id: allocatedId, host: '127.0.0.1' } : { username: 'fixture-consumer' };
  const before = kind === 'create' ? null : { id: nativeId }, step: any = { stepId: planStepId, entityType: kind === 'target' ? 'targets' : kind === 'update' ? 'consumers' : 'services',
    mutationAction: kind === 'create' ? 'create' : 'update', objectWorkspaceId: f.wid, body, before,
    ...(kind !== 'create' ? { nativeId } : {}), ...(kind !== 'update' ? { allocatedNativeId: allocatedId } : {}),
    ...(kind === 'target' ? { parentId: upstreamId } : {}), nativeRequests: [{ method, canonicalPath: path, bodyHmac: f.secrets.fingerprint(body), beforeHmac: f.secrets.fingerprint(before) }] };
  const job: any = { id: jobId, cluster_id: f.cid, plan_id: planId, plan_revision: 1, plan_hash: 'a'.repeat(64) }, material: any = { kind: 'configuration_v2', job, plan: { steps: [step] }, subjectSeal: { kind: 'configuration_v2', planId } };
  const selected = kind === 'target' ? point('targets', nativeId, { path: `${targetPath}/${nativeId}`, parentId: upstreamId }) : point(kind === 'update' ? 'consumers' : 'services', nativeId);
  const parent = point('upstreams', upstreamId), allocated = point('targets', allocatedId, { path: `${targetPath}/${allocatedId}`, parentId: upstreamId, required: false, allowAbsent: true });
  f.values.resources = kind === 'create' ? [{ clusterId: f.cid, workspaceId: f.wid, path: '/services', kind: 'collection', entityType: 'services', secrets: false, required: true, query: { size: 100 } }, unrelated, schema]
    : kind === 'target' ? [parent, selected, allocated, unrelated, schema] : [selected, unrelated, schema];
  f.values.present = new Set(f.values.resources.filter((r: any) => r.kind === 'point' && r.required !== false).map((r: any) => r.path));
  const intent: any = { namespaceHandle: f.nsHandle, namespace: f.ns, clusterId: f.cid, workspaceId: f.wid, actorId: f.owner,
    workflowId: f.plan.workflowId, jobId, executionId, jobStepId, planStepId, planId, planRevision: 1, planHash: job.plan_hash,
    operationId: randomUUID(), method, canonicalPath: path, beforePath: kind === 'target' ? `${targetPath}/${nativeId}` : kind === 'create' ? `/services/${allocatedId}` : path,
    ...(kind === 'target' ? { allocatedPath: `${targetPath}/${allocatedId}`, parentId: upstreamId } : {}), entityType: step.entityType,
    ...(step.nativeId ? { nativeId: step.nativeId } : {}), ...(step.allocatedNativeId ? { allocatedNativeId: step.allocatedNativeId } : {}),
    bodyHmac: step.nativeRequests[0].bodyHmac, beforeHmac: step.nativeRequests[0].beforeHmac,
    mutationAction: step.mutationAction, expiresAt: Date.parse(f.ns.expiresAt) };
  const state: any = { live: true, sqlLive: true, phase: undefined, handle: undefined, frame: undefined, entered: false, deadline: Infinity, calls: [], afterBegin: undefined };
  const handles = new WeakMap<object, any>(), closed = new WeakMap<object, any>();
  const current = (handle: object, tx: any) => { const read = handles.get(handle); if (!read || !state.live || tx !== f.db
    || read.frame !== f.context.current() || !read.active) throw Error('SOURCE_ORIGINAL_APPROVED_READ_REQUIRED'); return read; };
  const approved: any = { installWorkflowScheduledReviewerReadPolicy: vi.fn(), installWorkflowScheduledDelegate: vi.fn((delegate: any) => { state.delegate = delegate; }),
    installWorkflowScheduledCurrentIdentityBridge: vi.fn(), assertSubject: vi.fn(),
    beginConfigurationNativeBeforeRead: vi.fn(async (handle: object, tx: any) => {
      const read = current(handle, tx); if (read.entered) throw Error('SOURCE_APPROVED_READ_ALREADY_ENTERED'); read.entered = true;
      state.calls.push('approved:begin'); await state.afterBegin?.(); return intent;
    }),
    limitConfigurationNativeBeforeRead: vi.fn((handle: object, tx: any, deadline: number) => { const read = current(handle, tx); read.deadline = Math.min(read.deadline, deadline); }),
    assertConfigurationNativeBeforeRead: vi.fn(async (handle: object, tx: any) => { current(handle, tx); state.calls.push('approved:close'); }),
    assertConfigurationNativeBeforeReadLive: vi.fn((handle: object, tx: any) => { current(handle, tx); }),
  };
  const sql: any = { openClosedCheckpoint: vi.fn(async (handle: object, namespace: object, phase: string, tx: any) => {
    if (handle !== f.nsHandle || namespace !== f.ns || phase !== 'before-send' || tx !== f.db || !state.sqlLive) throw Error('SOURCE_CURRENT_SQL_REQUIRED');
    const token = Object.freeze({}); closed.set(token, { active: true, frame: f.context.current() }); state.calls.push('sql:open'); return token;
  }), assertClosedCheckpoint: vi.fn(async (token: object, handle: object, namespace: object, phase: string, tx: any) => {
    if (!closed.get(token)?.active || closed.get(token).frame !== f.context.current() || handle !== f.nsHandle || namespace !== f.ns || phase !== 'before-send' || tx !== f.db || !state.sqlLive) throw Error('SOURCE_CURRENT_SQL_REQUIRED');
    state.calls.push('sql:close');
  }), assertClosedCheckpointLive: vi.fn((token: object) => { if (!closed.get(token)?.active || !state.sqlLive) throw Error('SOURCE_CURRENT_SQL_REQUIRED'); }),
    releaseClosedCheckpoint: vi.fn((token: object) => { const row = closed.get(token); if (row) row.active = false; closed.delete(token); state.calls.push('sql:release'); }) };
  Object.assign(f.material, { installScopedReadBridge: vi.fn(), businessReadPolicy: vi.fn(() => f.business),
    configurationMaterial: vi.fn(async () => material), materialForPlan: vi.fn(async () => material), promoteClosedSqlMaterial: vi.fn(), authorizeScopedParentAbsence: vi.fn() });
  // The fixture already installs actual Namespace/validation/SDK bridges. Root
  // receives a bootstrap adapter that keeps those original registrations; its
  // new fixed reader and all Runtime orchestration below are installed once.
  const contextInstallers = new Set(['installWorkflowScheduledNamespacePolicy', 'installWorkflowScheduleCandidateReadPolicy',
    'installWorkflowCandidateHttpAdmissionPolicy', 'installWorkflowScheduledValidationReadPolicy', 'installScheduledReadAbsentTransportObserver']);
  const context = new Proxy(f.context, { get(target, key) { if (contextInstallers.has(String(key))) return () => undefined;
    const value = Reflect.get(target, key); return typeof value === 'function' ? value.bind(target) : value; } });
  const validationInstallers = new Set(['installStorageContract', 'installContextRunner', 'installAbsentResponseVerifier', 'installParentAbsencePolicy', 'installBusinessPolicy']);
  const validation = new Proxy(f.service, { get(target, key) { if (validationInstallers.has(String(key))) return () => undefined;
    const value = Reflect.get(target, key); return typeof value === 'function' ? value.bind(target) : value; } });
  const noop = vi.fn(), candidates: any = { installStorageContract: noop, installContextRunner: noop, installAbsentResponseVerifier: noop,
    installParentAbsencePolicy: noop, installBusinessPolicy: noop, installFixedReader: vi.fn(() => undefined) };
  const authority: any = { installRepositoryPolicies: noop, installBusinessPolicy: vi.fn((kind: string, policy: any) => { (state.authorityPolicies ??= {})[kind] = policy; }), installExecutor: noop,
    installScheduledConfigurationOriginSqlVerifier: vi.fn(() => sql) };
  const namespaces: any = { installContextRunner: noop, assertLive: noop }, core: any = { installWorkflowScheduledConfigurationOrigin: noop }, origins: any = { installWorkflowScheduledOrigin: noop };
  const workflows: any = { installBusinessScheduledDelegate: noop }, schedules: any = { installProposalPolicy: vi.fn((policy: any) => { state.proposalPolicy = policy; }), installWorkflowOperationPolicy: vi.fn((policy: any) => { state.operationPolicy = policy; }), receiptReadActive: () => false };
  const runtime = new WorkflowBusinessRuntimeService(f.db, f.redis, f.secrets, context, f.kong, { installWorkflowScheduledCurrentIdentityBridge: noop } as any,
    f.plans, workflows, approved, f.repository, authority, namespaces, candidates, validation, { installRootVerifier: noop } as any,
    f.material, {} as any, schedules, { installFixedDelegate: noop } as any, { get: (type: any) => type.name === 'ConfigurationService' ? core : origins } as any,
    new WorkflowBusinessScopedReadService());
  runtime.onModuleInit(); f.outbound.mockClear();
  const read = async () => { const handle = Object.freeze({}); const row = { active: true, entered: false, deadline: Infinity, frame: f.context.current() };
    handles.set(handle, row); state.handle = handle;
    try { return await state.delegate.readConfigurationNativeBefore(handle); } finally { row.active = false; handles.delete(handle); } };
  const run = (fn: () => Promise<any> = read) => f.context.runWorkflowScheduledNamespace(f.nsHandle, fn).catch((error: any) => {
    if (error?.response?.code) error.message += ` (${error.response.code})`; throw error; });
  return { ...f, runtime, kind, nativeId, allocatedId, upstreamId, unrelatedId, selected, unrelated, schema, parent, allocated, job, step, configMaterial: material, intent, approved, sql, state, read, run };
}

describe('fixed currentBefore Root consumes only this new complete read round', () => {
  it('reads the complete scope once and returns its exact current point without repeating a selected GET', async () => {
    const f = fixture(); await expect(f.run()).resolves.toEqual({ before: { id: f.nativeId } });
    expect(f.outbound.mock.calls.map((c: any) => c[1])).toEqual(f.values.resources.map((r: any) => r.path));
    expect(f.business.authorizeResponse).toHaveBeenCalledTimes(3);
    expect(f.approved.beginConfigurationNativeBeforeRead).toHaveBeenCalledOnce();
    expect(f.approved.assertConfigurationNativeBeforeRead).toHaveBeenCalledOnce();
    expect(f.sql.openClosedCheckpoint).toHaveBeenCalledOnce(); expect(f.sql.assertClosedCheckpoint).toHaveBeenCalledOnce();
    expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce(); expect(f.state.calls).toEqual(['approved:begin', 'sql:open', 'approved:close', 'sql:close', 'sql:release']);
    expect(f.outbound.mock.calls.every((c: any) => c[2] === 'GET')).toBe(true); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('starts its fixed 30-second round before begin SQL and refuses to renew it after that await', async () => {
    const f = fixture(); let mono = 1000; vi.spyOn(performance, 'now').mockImplementation(() => mono);
    f.state.afterBegin = async () => { mono += 30001; };
    await expect(f.run()).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_ORIGINAL_READ_EXPIRED'));
    expect(f.approved.limitConfigurationNativeBeforeRead.mock.calls[0][2]).toBe(31000);
    expect(f.sql.openClosedCheckpoint).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });

  it('performs a new complete read for each invocation and never borrows an earlier observation', async () => {
    const f = fixture(); await f.run(async () => {
      await expect(f.read()).resolves.toEqual({ before: { id: f.nativeId } });
      f.values.present.delete(f.selected.path);
      await expect(f.read()).rejects.toBeDefined();
    });
    expect(f.outbound.mock.calls.filter((c: any) => c[1] === f.selected.path)).toHaveLength(2);
    expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledTimes(2);
  });

  it('requires full actual collection EOF to prove a newly allocated create ID absent', async () => {
    const f = fixture('create'); await expect(f.run()).resolves.toEqual({ before: null });
    expect(f.outbound.mock.calls.map((c: any) => c[1])).toEqual(['/services', f.unrelated.path, '/schemas/services']);
    expect(f.outbound.mock.calls.some((c: any) => c[1] === f.intent.beforePath)).toBe(false);
    expect(f.sql.assertClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('does not fabricate absence from an omitted EOF marker', async () => {
    const f = fixture('create'), outbound = f.outbound.getMockImplementation()!;
    f.outbound.mockImplementation(async (...args: any[]) => { const result = await outbound(...args); return args[1] === '/services' ? { ...result, body: { data: [] } } : result; });
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID'));
    expect(f.sql.assertClosedCheckpoint).not.toHaveBeenCalled(); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('rejects a point from a different object workspace instead of falling back to an ordinary GET', async () => {
    const f = fixture(); f.intent.workspaceId = randomUUID(); f.step.objectWorkspaceId = f.intent.workspaceId;
    await expect(f.run()).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_POINT_NOT_OBSERVED'));
    expect(f.outbound.mock.calls).toHaveLength(3); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('retains all unrelated full-scope Native READ failures before returning the selected point', async () => {
    const f = fixture(); f.values.present.delete(f.unrelated.path);
    await expect(f.run()).rejects.toBeDefined();
    expect(f.outbound.mock.calls.map((c: any) => c[1])).toEqual([f.selected.path, f.unrelated.path]);
    expect(f.sql.assertClosedCheckpoint).not.toHaveBeenCalled(); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('keeps selected and unrelated resource/workspace groups when an object belongs to another workspace', async () => {
    const f = fixture(), objectWorkspace = randomUUID(); f.intent.workspaceId = objectWorkspace; f.step.objectWorkspaceId = objectWorkspace;
    f.selected.workspaceId = objectWorkspace; fixedSourceWorkspaces(f);
    await expect(f.run()).resolves.toEqual({ before: { id: f.nativeId } });
    expect(f.acceptedRequests.map((r: any) => r.workspaceId)).toEqual([objectWorkspace, f.wid, f.wid]);
    expect(f.outbound.mock.calls).toHaveLength(3);
  });

  it.each(['prepareRevision', 'assertProposal'] as const)('fixed proposal delegate %s rejects incomplete V2 Target-append seals before persistence', async method => {
    const f = fixture('target');
    // Authentication is an explicit upstream component adapter here. The
    // actual registered proposal callback and support guard remain real.
    vi.spyOn(f.runtime as any, 'proposalPrincipal').mockResolvedValue(undefined);
    const input: any = { old: { plan: f.plan }, basePlan: f.plan, plan: f.plan, transaction: f.db, checkpoint: 'before-version' };
    await expect(f.state.proposalPolicy[method](input)).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED'));
    expect(f.material.materialForPlan).toHaveBeenCalledOnce(); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });

  it('fixed activation operation policy rejects an incomplete V2 Target-append plan before execution', async () => {
    const f = fixture('target'), sid = randomUUID(), actor = f.ns.actor;
    const input: any = { action: 'write', command: 'activate', plan: f.plan, actor: { user: actor, workspaceId: f.wid },
      acceptance: { sessionId: sid }, transaction: f.db };
    await expect(f.context.runHttp({}, () => {
      f.context.bindHttpActor(actor, sid); const close = f.context.captureHttpCloser();
      return f.context.runActor({ actor, clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'write' },
        () => f.state.operationPolicy.assertOperation(input)).finally(close);
    })).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED'));
    expect(f.material.materialForPlan).toHaveBeenCalledOnce(); expect(f.approved.assertSubject).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });

  it.each(['assertDraft', 'assertRequester'] as const)('fixed authority %s blocks an incomplete V2 Target-append subject before new claim work', async method => {
    const f = fixture('target'), policy = f.state.authorityPolicies.configuration_v2;
    const call = method === 'assertDraft' ? policy.assertDraft(f.plan, {}, { user: f.ns.actor }, f.db) : policy.assertRequester(f.plan, {}, f.db);
    await expect(call).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED'));
    expect(f.material.materialForPlan).toHaveBeenCalledOnce(); expect(f.material.currentReadInput).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });


  it.each(['prepareRevision', 'assertProposal'] as const)('fixed proposal delegate %s admits a well-formed V2 Target-append seal past the schedule fence', async method => {
    const f = fixture('target');
    f.step.bodyHmac = f.step.nativeRequests[0].bodyHmac; f.step.beforeHmac = f.step.nativeRequests[0].beforeHmac;
    vi.spyOn(f.runtime as any, 'proposalPrincipal').mockResolvedValue(undefined);
    const plan = { ...f.plan, planRevision: (f.plan.planRevision ?? 1) + 1, approvalRequired: true,
      scheduling: { ownerId: f.ns.actor.id, executorId: f.ns.actor.id, ownerCredentialEpoch: '1' } };
    const input: any = { old: { plan: { ...f.plan, expiresAt: f.plan.expiresAt } }, basePlan: plan, plan, transaction: f.db, checkpoint: 'before-version',
      draft: { binding: { subjectSeal: f.configMaterial.subjectSeal }, impact: { version: 0 } }, actor: { user: f.ns.actor },
      acceptance: { credentialEpoch: '1' }, spec: { windowEnd: f.plan.expiresAt } };
    const outcome = await f.state.proposalPolicy[method](input).then((value: unknown) => ({ ok: true as const, value }), (error: any) => ({ ok: false as const, error }));
    // Fence must not close a complete append seal; later proposal invariants may still fail closed.
    if (!outcome.ok) expect(outcome.error?.response?.code).not.toBe('WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED');
    else if (method === 'prepareRevision') expect(outcome.value).toMatchObject({ subjectSeal: f.configMaterial.subjectSeal });
    else expect(outcome.ok).toBe(true);
    expect(f.material.materialForPlan).toHaveBeenCalledOnce(); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });

  it('fixed activation admits a well-formed V2 Target-append plan past the schedule fence', async () => {
    const f = fixture('target'), sid = randomUUID(), actor = f.ns.actor;
    f.step.bodyHmac = f.step.nativeRequests[0].bodyHmac; f.step.beforeHmac = f.step.nativeRequests[0].beforeHmac;
    const input: any = { action: 'write', command: 'activate', plan: f.plan, actor: { user: actor, workspaceId: f.wid },
      acceptance: { sessionId: sid }, transaction: f.db };
    await expect(f.context.runHttp({}, () => {
      f.context.bindHttpActor(actor, sid); const close = f.context.captureHttpCloser();
      return f.context.runActor({ actor, clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'write' },
        () => f.state.operationPolicy.assertOperation(input)).finally(close);
    })).resolves.toBeUndefined();
    expect(f.material.materialForPlan).toHaveBeenCalledOnce(); expect(f.approved.assertSubject).toHaveBeenCalledOnce();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });

  it('fixed authority assertRequester admits a well-formed V2 Target-append subject past the schedule fence', async () => {
    const f = fixture('target');
    f.step.bodyHmac = f.step.nativeRequests[0].bodyHmac; f.step.beforeHmac = f.step.nativeRequests[0].beforeHmac;
    const policy = f.state.authorityPolicies.configuration_v2;
    await expect(policy.assertRequester(f.plan, { binding: { subjectSeal: f.configMaterial.subjectSeal } }, f.db)).resolves.toBeUndefined();
    expect(f.material.materialForPlan).toHaveBeenCalledOnce(); expect(f.material.currentReadInput).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.outbound).not.toHaveBeenCalled();
  });

  it('rejects the legacy optional Target absence after its genuine point 404 instead of minting a strict scoped witness', async () => {
    const f = fixture('target');
    await expect(f.run()).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_ORIGINAL_SCOPED_ABSENCE_REQUIRED'));
    const paths = f.outbound.mock.calls.map((c: any) => c[1]);
    expect(paths.filter((p: string) => p === f.parent.path)).toHaveLength(2);
    expect(paths.filter((p: string) => p === f.allocated.path)).toHaveLength(1);
    expect(paths).not.toContain(`/upstreams/${f.upstreamId}/targets`);
    expect(f.sql.assertClosedCheckpoint).not.toHaveBeenCalled(); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('consumes the genuine SDK404 from a required scoped Target point in the complete round without another capsule', async () => {
    const f = fixture('target'); f.allocated.required = true;
    await expect(f.run()).resolves.toEqual({ before: { id: f.nativeId }, allocatedAbsent: true });
    const paths = f.outbound.mock.calls.map((c: any) => c[1]);
    expect(paths.filter((p: string) => p === f.parent.path)).toHaveLength(1);
    expect(paths.filter((p: string) => p === f.allocated.path)).toHaveLength(1);
    expect(paths).toEqual(f.values.resources.map((r: any) => r.path));
    expect(f.acceptedRequests.filter((r: any) => r.path === f.allocated.path)).toHaveLength(1);
    expect(f.sql.assertClosedCheckpoint).toHaveBeenCalledOnce(); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('reports a present historical allocated Target as occupied even if an active list would be empty', async () => {
    const f = fixture('target'); f.values.present.add(f.allocated.path);
    await expect(f.run()).resolves.toEqual({ before: { id: f.nativeId }, allocatedAbsent: false });
    expect(f.outbound.mock.calls.filter((c: any) => c[1] === f.allocated.path)).toHaveLength(1);
    expect(f.outbound.mock.calls.every((c: any) => c[2] === 'GET')).toBe(true);
  });

  it('never accepts a fabricated thrown Target 404 without the SDK original absent-response observer', async () => {
    const f = fixture('target'), request = f.kong.request.bind(f.kong);
    vi.spyOn(f.kong, 'request').mockImplementation(async (...args: any[]) => {
      if (args[2] === f.allocated.path) throw new HttpException({ message: 'synthetic-not-found' }, 404); return request(...args);
    });
    await expect(f.run()).rejects.toBeDefined();
    expect(f.outbound.mock.calls.some((c: any) => c[1] === f.allocated.path)).toBe(false);
    expect(f.sql.assertClosedCheckpoint).not.toHaveBeenCalled(); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it('rejects an allocated Target without its exact parent-scoped absence descriptor', async () => {
    const f = fixture('target'); f.values.resources = f.values.resources.filter((r: any) => r !== f.allocated);
    await expect(f.run()).rejects.toMatchObject(denied('WORKFLOW_BUSINESS_READBACK_SCOPE_REQUIRED'));
    expect(f.outbound.mock.calls.some((c: any) => c[1] === f.allocated.path)).toBe(false);
    expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it.each(['step', 'packet', 'plan', 'parent', 'workspace'] as const)('revalidates sealed %s material after the complete round and before publishing', async reason => {
    const f = fixture('target');
    if (reason === 'step') f.step.stepId = randomUUID();
    if (reason === 'packet') f.step.nativeRequests[0].bodyHmac = 'f'.repeat(64);
    if (reason === 'plan') f.job.plan_hash = 'f'.repeat(64);
    if (reason === 'parent') f.step.parentId = randomUUID();
    if (reason === 'workspace') f.step.objectWorkspaceId = randomUUID();
    await expect(f.run()).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_SEALED_STEP_CHANGED'));
    expect(f.outbound.mock.calls.length).toBeGreaterThan(0); expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce();
  });

  it.each(['approved', 'sql', 'grants'] as const)('withholds the selected object when final %s closing fails', async reason => {
    const f = fixture(), configure = f.material.configurationMaterial.getMockImplementation()!;
    f.material.configurationMaterial.mockImplementation(async (...args: any[]) => {
      const result = await configure(...args);
      if (reason === 'approved') f.state.live = false;
      if (reason === 'sql') f.state.sqlLive = false;
      if (reason === 'grants') f.material.assertCurrentReadGrants.mockRejectedValueOnce(Error('SOURCE_CURRENT_READ_GRANTS_REVOKED'));
      return result;
    });
    await expect(f.run()).rejects.toBeDefined();
    expect(f.sql.releaseClosedCheckpoint).toHaveBeenCalledOnce(); expect(f.outbound.mock.calls).toHaveLength(3);
  });
});
