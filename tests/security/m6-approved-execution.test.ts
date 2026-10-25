import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { approvedFixture, actor, approverId, cid, eid, id, nativeId, sid, wid, wf } from './m6-approved-fixture';

beforeEach(() => { vi.stubEnv('APP_SECRET', 'm6-approved-test-hmac-secret-minimum-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); });
afterEach(() => { vi.unstubAllEnvs(); vi.useRealTimers(); });
const denies = (promise: Promise<unknown>, code: string) => expect(promise).rejects.toMatchObject({ response: { code } });

describe('M6 actual immutable approved execution verifier', () => {
  it('binds logical CREATE null ID to its sealed native ID and atomically links the ledger before callback', async () => {
    const f = approvedFixture(), audit: any = { append: vi.fn(async () => undefined) };
    const mutations = new MutationService(f.db, f.redis, f.secrets, audit, f.kong, f.authz, {
      resolve: async () => f.workspace, listScope: async () => ({ workspaceId: wid }), assertMembership: () => undefined,
      matches: () => true,
    } as any, f.context);
    const callback = vi.fn(async () => {
      const op = [...f.operations.values()][0];
      expect(op.entity_id).toBeNull(); expect(op.workflow_execution_id).toBe(eid); expect(op.workflow_step_id).toBe(sid);
      expect(f.rows[0].operation_id).toBe(op.id);
      const ticket = await f.context.authorizeRequest(f.cluster, 'POST', '/consumers', f.plan.steps[0].mutationPayload, {});
      await f.context.beforeNativeSend(ticket);
      f.nativeObjects.set(`/consumers/${nativeId}`, f.plan.steps[0].mutationPayload);
      return f.context.authorizeResponse(ticket, f.plan.steps[0].mutationPayload);
    });
    await f.run(() => mutations.execute(f.mutationContext(), callback));
    expect(callback).toHaveBeenCalledTimes(1);
    expect([...f.operations.values()][0]).toMatchObject({ state: 'succeeded', entity_id: nativeId, remote_completed: true });
    expect(f.db.transaction).toHaveBeenCalled(); expect(audit.append.mock.calls[0][1]).toBe(f.db);
    await f.http(async () => {
      const replay = await mutations.inspectStepReceipt(f.mutationContext());
      expect(replay).toMatchObject({ entityId: nativeId, state: 'succeeded', remoteCompleted: true });
      expect(await f.context.approvedMutationBinding(f.mutationContext())).toBeNull();
      await denies(mutations.inspectStepReceipt({ ...f.mutationContext(), entityId: nativeId }), 'IDEMPOTENCY_CONFLICT');
      await denies(mutations.inspectStepReceipt({ ...f.mutationContext(), payload: { ...f.mutationContext().payload as any, username: 'changed' } }), 'IDEMPOTENCY_CONFLICT');
    });
  });

  it('rolls back approved allocation if step CAS fails, leaving zero native callbacks and ledger rows', async () => {
    const f = approvedFixture(), original = f.db.exec.getMockImplementation()!;
    f.db.exec.mockImplementation(async (sql: string, params: any[]) => sql.startsWith('UPDATE workflow_steps SET operation_id') ? 0 : original(sql, params));
    const mutations = new MutationService(f.db, f.redis, f.secrets, { append: vi.fn() } as any, f.kong, f.authz, {
      resolve: async () => f.workspace, listScope: async () => ({ workspaceId: wid }), assertMembership: () => undefined,
    } as any, f.context);
    const callback = vi.fn();
    await denies(f.run(() => mutations.execute(f.mutationContext(), callback)), 'APPROVED_OPERATION_LINK_CONFLICT');
    expect(callback).not.toHaveBeenCalled(); expect(f.operations.size).toBe(0); expect(f.rows[0].operation_id).toBeNull();
  });

  it('permits genuinely approved issuance on a direct cluster while direct no-approval plans cannot mint capabilities', async () => {
    const f = approvedFixture(); f.plan.executionMode = 'direct'; f.cluster.execution_mode = 'direct'; f.seal();
    await f.run(async () => { expect((await f.context.approvedMutationBinding(f.mutationContext()))?.workflowId).toBe(wf); });
    f.plan.approvalRequired = false; f.seal(); f.execution.approved_by = null; f.workflow.approved_by = null;
    await denies(f.http(() => f.verifier.runApprovedExecution(eid, async () => undefined)), 'APPROVED_VERSION_MISMATCH');
  });

  it('rejects forged workflow handles, copied private bindings and ordinary HTTP workflow IDs', async () => {
    const f = approvedFixture();
    await denies(f.http(() => f.context.runApprovedWorkflow({ executionId: eid } as any, async () => undefined)), 'APPROVED_EXECUTION_INVALID');
    await f.run(async () => {
      const binding = (await f.context.approvedMutationBinding(f.mutationContext()))!;
      await denies(f.context.bindApprovedOperation(f.mutationContext(), { ...binding }, id(99), f.db), 'APPROVED_BINDING_INVALID');
    });
    await f.http(async () => { expect(await f.context.approvedMutationBinding({ ...f.mutationContext(), workflowId: wf })).toBeNull(); });
  });

  it.each([
    ['unready snapshot', (f: ReturnType<typeof approvedFixture>) => { f.execution.snapshot_state = 'pending'; }, 'APPROVED_EXECUTION_NOT_READY'],
    ['cancelled workflow', (f: ReturnType<typeof approvedFixture>) => { f.workflow.state = 'cancelled'; }, 'APPROVED_VERSION_MISMATCH'],
    ['normalized row substitution', (f: ReturnType<typeof approvedFixture>) => { f.rows[0].native_requests[0].native_id = id(999); }, 'APPROVED_NORMALIZED_STEP_MISMATCH'],
    ['missing steps', (f: ReturnType<typeof approvedFixture>) => { f.rows.length = 0; }, 'APPROVED_STEPS_INCOMPLETE'],
    ['rejected approval', (f: ReturnType<typeof approvedFixture>) => { f.approvals[0].decision = 'reject'; }, 'APPROVED_DECISION_INVALID'],
    ['foreign snapshot anchor', (f: ReturnType<typeof approvedFixture>) => { f.snapshot().workspaceId = id(999); f.sealSnapshot(); }, 'APPROVED_SNAPSHOT_INVALID'],
    ['incomplete absent-object snapshot', (f: ReturnType<typeof approvedFixture>) => { f.snapshot().objects.pop(); f.sealSnapshot(); }, 'APPROVED_SNAPSHOT_INCOMPLETE'],
    ['expired version', (f: ReturnType<typeof approvedFixture>) => { f.version.expires_at = new Date(Date.now() - 1).toISOString(); }, 'APPROVED_EXECUTION_EXPIRED'],
    ['changed physical registry mapping', (f: ReturnType<typeof approvedFixture>) => { f.cluster.transport_scope = 'b'.repeat(64); }, 'APPROVED_PLAN_STALE'],
    ['changed workspace revision', (f: ReturnType<typeof approvedFixture>) => { f.workspace.revision++; }, 'APPROVED_PLAN_STALE'],
    ['substituted requester', (f: ReturnType<typeof approvedFixture>) => { f.workflow.requester_developer_id = id(999); }, 'APPROVED_SUBJECT_MISMATCH'],
    ['substituted definition version', (f: ReturnType<typeof approvedFixture>) => { f.workflow.definition_version = 2; }, 'APPROVED_SUBJECT_MISMATCH'],
  ])('sends no packet for %s', async (_name, change, code) => {
    const f = approvedFixture(), dispatch = vi.fn(async () => undefined); change(f);
    await denies(f.http(() => f.verifier.runApprovedExecution(eid, dispatch)), code); expect(dispatch).not.toHaveBeenCalled();
  });

  it('requires exact logical payload/key/before, including no substituted preallocated body ID', async () => {
    const f = approvedFixture();
    await f.run(async () => {
      for (const patch of [{ entityId: nativeId }, { idempotencyKey: 'unapproved-new-key' }, { payload: { ...f.mutationContext().payload as any, id: id(888) } }, { before: { id: nativeId } }]) {
        await denies(f.context.approvedMutationBinding({ ...f.mutationContext(), ...patch }), 'APPROVED_MUTATION_MISMATCH');
      }
    });
  });

  it('rejects native packet body substitution and acknowledges only the sealed created UUID', async () => {
    const f = approvedFixture();
    await f.run(() => f.withPacket(async ticket => {
      await f.context.beforeNativeSend(ticket);
      await denies(f.context.authorizeResponse(ticket, { id: id(555) }), 'APPROVED_CREATED_ID_MISMATCH');
    }));
    f.rows[0].operation_id = null;
    await f.run(async () => {
      const { ctx, opId } = await f.allocate();
      await f.context.runOperation({ ...ctx, operationId: opId, workspaceId: wid }, async () => {
        const ticket = await f.context.authorizeRequest(f.cluster, 'POST', '/consumers', { ...ctx.payload as any, username: 'substituted' }, {});
        await denies(f.context.beforeNativeSend(ticket), 'APPROVED_NATIVE_REQUEST_MISMATCH');
      });
    });
  });

  it('rechecks revoked executor and approver grants after the execution capability was minted', async () => {
    const f = approvedFixture();
    await f.run(() => f.withPacket(async ticket => {
      f.grants.length = 0;
      await denies(f.context.beforeNativeSend(ticket), 'APPROVED_APPROVER_REVOKED');
    }));
    f.rows[0].operation_id = null; f.grants.push({ module: 'workflows', action: 'approve', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    await f.run(() => f.withPacket(async ticket => {
      f.setVersion('epoch-2'); await denies(f.context.beforeNativeSend(ticket), 'APPROVED_EXECUTOR_CHANGED');
    }));
  });

  it('fresh dependency change and cancellation during a dependency await stop the packet', async () => {
    const f = approvedFixture();
    await f.run(() => f.withPacket(async ticket => {
      f.serviceObject.host = 'changed-business.test'; await denies(f.context.beforeNativeSend(ticket), 'APPROVED_PLAN_STALE');
    }));
    f.serviceObject.host = 'business.test'; f.rows[0].operation_id = null;
    await f.run(() => f.withPacket(async ticket => {
      const original = f.kong.request.getMockImplementation()!; let reads = 0;
      f.kong.request.mockImplementation(async (...args: any[]) => {
        const result = await original(...args); if (++reads === 3) f.workflow.state = 'cancelled'; return result;
      });
      await denies(f.context.beforeNativeSend(ticket), 'APPROVED_VERSION_MISMATCH');
    }));
  });

  it('checks current approver grant against the actual Service scope instead of a fabricated session', async () => {
    const f = approvedFixture(); f.grants[0].scope_values[0].entity_id = id(777);
    await denies(f.http(() => f.verifier.runApprovedExecution(eid, async () => undefined)), 'APPROVED_APPROVER_REVOKED');
    expect(f.authz.snapshot.mock.calls.every(call => call[0].id === actor.id)).toBe(true);
    f.grants[0].scope_values[0].entity_id = f.serviceObject.id; f.approvedBy.status = 'disabled';
    await denies(f.http(() => f.verifier.runApprovedExecution(eid, async () => undefined)), 'APPROVED_APPROVER_REVOKED');
  });

  it('refuses unacknowledged native dependencies and does not infer success from a partial receipt', async () => {
    const f = approvedFixture(), oldBody = { ...f.plan.steps[0].mutationPayload as any, id: id(124), username: 'first-consumer' };
    const previous = { ...f.plan.steps[0], id: id(123), key: 'previous', order: 1, mutationPayload: oldBody, mutationPayloadHmac: f.secrets.fingerprint(oldBody),
      nativeRequests: [{ ...f.plan.steps[0].nativeRequests[0], nativeId: id(124), body: oldBody, bodyHmac: f.secrets.fingerprint(oldBody) }] };
    f.plan.steps = [previous, { ...f.plan.steps[0], order: 2, dependencies: [previous.id] }]; f.seal();
    f.rows[0].state = 'succeeded'; f.rows[0].operation_id = id(98);
    f.operations.set(id(98), { state: 'uncertain', remote_completed: false, workflow_execution_id: eid, workflow_step_id: previous.id, workflow_plan_hash: f.execution.plan_hash });
    await denies(f.http(() => f.verifier.runApprovedExecution(eid, () => f.context.runApprovedStep(sid, async () => undefined))), 'APPROVED_DEPENDENCY_UNACKNOWLEDGED');
  });

  it('honors an intentionally changed prerequisite only with a succeeded prior step and exact raw readback fingerprint', async () => {
    const f = approvedFixture(), before = structuredClone(f.serviceObject), patch = { name: 'renamed-api' };
    const previous: any = { id: id(123), key: 'rename', order: 1, kind: 'native', entityType: 'services', entityId: before.id, permissionAction: 'write', dependencies: [], mutationAction: 'update',
      mutationPayload: patch, mutationPayloadHmac: f.secrets.fingerprint(patch), mutationIdempotencyKey: 'sealed-rename', before, beforeFingerprint: f.secrets.fingerprint(before),
      nativeRequests: [{ method: 'PATCH', canonicalPath: `/services/${before.id}`, nativeType: 'services', nativeId: before.id, body: patch, bodyHmac: f.secrets.fingerprint(patch), beforeHmac: f.secrets.fingerprint(before) }] };
    f.plan.steps = [previous, { ...f.plan.steps[0], order: 2, dependencies: [previous.id] }]; f.seal();
    f.snapshot().objects = f.snapshot().objects.filter((obj: any, index: number, all: any[]) => all.findIndex((x: any) => x.path === obj.path) === index); f.sealSnapshot();
    f.serviceObject.name = 'renamed-api'; Object.assign(f.rows[0], { state: 'succeeded', operation_id: id(98), after_fingerprint: f.secrets.fingerprint(f.serviceObject) });
    f.operations.set(id(98), { state: 'succeeded', remote_completed: true, workflow_execution_id: eid, workflow_step_id: previous.id, workflow_plan_hash: f.execution.plan_hash });
    await f.http(() => f.verifier.runApprovedExecution(eid, () => f.context.runApprovedStep(sid, async () => {
      const step = f.plan.steps[1], ctx = { ...f.mutationContext(), entityType: step.entityType, entityId: step.entityId, action: step.mutationAction!, payload: step.mutationPayload, before: step.before, idempotencyKey: step.mutationIdempotencyKey };
      const binding = (await f.context.approvedMutationBinding(ctx))!, opId = id(99);
      f.operations.set(opId, { id: opId, state: 'running', actor_id: actor.id, cluster_id: cid, workspace_id: wid, workflow_id: wf, workflow_execution_id: eid, workflow_plan_revision: 1, workflow_plan_hash: f.execution.plan_hash, workflow_step_id: sid,
        remote_started: true, before_secret: f.secrets.encrypt(null, `mutation:${opId}:before`), payload_secret: f.secrets.encrypt(step.mutationPayload, `mutation:${opId}:payload`) });
      await f.context.bindApprovedOperation(ctx, binding, opId, f.db);
      await f.context.runOperation({ ...ctx, workspaceId: wid, operationId: opId }, async () => {
        const ticket = await f.context.authorizeRequest(f.cluster, 'POST', '/consumers', ctx.payload, {});
        await f.context.beforeNativeSend(ticket);
        f.rows[0].after_fingerprint = f.secrets.fingerprint({ redacted: 'display-only' });
        await denies(f.context.beforeNativeSend(ticket), 'APPROVED_PLAN_STALE');
      });
    })));
  });

  it('revokes the ancestor capability when callback ends and rejects a later asynchronous continuation', async () => {
    const f = approvedFixture(); let resume!: () => void, late!: Promise<unknown>;
    const gate = new Promise<void>(done => { resume = done; });
    await f.run(async () => { late = gate.then(() => f.context.approvedMutationBinding(f.mutationContext())).catch(error => error); });
    resume(); expect(await late).toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
  });

  it('loss of the trusted physical lease blocks the approved send without reclassifying approval', async () => {
    const f = approvedFixture();
    await f.run(() => f.withPacket(async ticket => {
      f.redis.assertLeaseOwnership.mockRejectedValue(new ServiceUnavailableException({ code: 'LOCK_LOST' }));
      await denies(f.context.beforeNativeSend(ticket), 'LOCK_LOST');
    }));
  });

  it('allows pure-metadata approve-only and disabled-target review without granting subject writes', async () => {
    const f = approvedFixture(); f.plan.subject = { type: 'portal_developers', id: f.developer.id }; f.developer.status = 'disabled';
    await f.http(() => f.verifier.assertSubject(f.plan, actor, 'approve'));
    expect(f.authz.assertWholeWorkspace.mock.calls.map(call => [call[3], call[4]])).toEqual([['workflows', 'approve']]);
    f.authz.assertWholeWorkspace.mockClear();
    await f.http(() => f.verifier.assertSubject(f.plan, actor, 'write'));
    expect(f.authz.assertWholeWorkspace.mock.calls.map(call => [call[3], call[4]])).toEqual([['workflows', 'write'], ['developers', 'write']]);
  });

  it('metadata approval cannot become a managed-Consumer exception or native mutation capability', async () => {
    const f = approvedFixture(); f.plan.kind = 'portal-developer-review'; f.plan.subject = { type: 'portal_developers', id: f.developer.id };
    const before = { id: f.developer.id, status: 'pending' }, payload = { status: 'active' };
    f.plan.steps = [{ id: sid, order: 1, key: 'review', kind: 'metadata', entityType: 'portal_developers', entityId: f.developer.id, handler: 'portal.developer.review', permissionAction: 'write', dependencies: [], nativeRequests: [],
      metadata: payload, metadataRevision: 1, metadataBeforeHmac: f.secrets.fingerprint(before), metadataPayloadHmac: f.secrets.fingerprint(payload) }];
    f.grants[0] = { module: 'workflows', action: 'approve', scope_type: 'workspace', scope_values: [wid], cluster_id: cid, workspace_id: wid }; f.seal();
    await f.run(async () => {
      const input = { handler: 'portal.developer.review', actor, clusterId: cid, workspaceId: wid, entityType: 'portal_developers', entityId: f.developer.id, before, revision: 1, payload };
      await f.verifier.assertStep(input, f.db);
      await denies(f.verifier.assertStep({ ...input, payload: { status: 'active', super_admin: true } }, f.db), 'APPROVED_METADATA_REQUEST_MISMATCH');
      await denies(f.context.approvedMutationBinding(f.mutationContext()), 'APPROVED_NATIVE_STEP_REQUIRED');
      await denies(f.verifier.assertNativeWrite({ clusterId: cid, workspaceId: wid, transportScope: 'a'.repeat(64), operationId: id(99), method: 'POST', canonicalPath: '/consumers', body: {}, before: null, mutationAction: 'create' }), 'PORTAL_MANAGED_OBJECT');
    });
  });
});
