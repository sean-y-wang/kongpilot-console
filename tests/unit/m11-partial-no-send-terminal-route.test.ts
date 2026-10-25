import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException, RequestMethod } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkflowController } from '../../apps/console-api/src/modules/workflows/workflow.controller';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';

/** Source-only BFF boundary tests. SQL, subject policy and the fixed terminal
 * verifier are explicit adapters; the real HTTP/actor execution frames are
 * retained. These tests do not prove PostgreSQL facts, a terminal proof or a
 * native grant, and never construct an executable Root handle. */
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), id = randomUUID(), sessionId = randomUUID();
  const actor = { user: { id: randomUUID(), username: 'authenticated-owner', superAdmin: false },
    workspaceId: wid, requestId: randomUUID(), ip: '192.0.2.75', idempotencyKey: 'terminal-original-key' };
  const plan: any = { kind: 'native-change', clusterId: cid, workspaceId: wid, workflowId: id,
    planRevision: 1, executionMode: 'direct', approvalRequired: false,
    requester: { type: 'console', id: actor.user.id } };
  const state = { canWrite: true };
  const authorize = vi.fn(async (_plan: any, _userId: string, action: string) => {
    if (action === 'write' && !state.canWrite) throw new ForbiddenException({ code: 'OFFLINE_SUBJECT_WRITE_DENIED' });
  });
  const handlerAuthorize = vi.fn(async () => undefined);
  const plans: any = { load: vi.fn(async () => ({ plan })), assertEntityChangeSubject: authorize };
  const registry: any = { get: vi.fn(() => ({ authorize: handlerAuthorize })) };
  const db: any = { one: vi.fn(), query: vi.fn(), exec: vi.fn(), transaction: vi.fn() };
  const kong: any = { request: vi.fn() };
  const context = new KongExecutionContextService();
  const service = new WorkflowService(db, {} as any, {} as any, kong, context, {} as any,
    {} as any, {} as any, {} as any, {} as any, {} as any, plans, registry, {} as any, {} as any);
  const delegate: any = { canExecute: vi.fn(), canPreflight: vi.fn(), canRollback: vi.fn(),
    execute: vi.fn(), historical: vi.fn(), rollbackPrepare: vi.fn(), preflight: vi.fn(),
    closeUnsent: vi.fn(), reconcileNoSend: vi.fn(),
    reconcilePartialRestoreNoSend: vi.fn(async () => ({ state: 'failed', terminal: 'failed', metadataReconciled: true })) };
  const controller = new WorkflowController(service);
  const body = { executionId: randomUUID(), revision: 2, planHash: 'a'.repeat(64), confirmed: true, confirm_name: 'native-change' };
  const http = <T>(fn: () => T, boundUser = actor.user) => context.runHttp({ requestId: actor.requestId,
    ip: actor.ip, idempotencyKey: actor.idempotencyKey }, () => {
    context.bindHttpActor(boundUser, sessionId);
    return fn();
  });
  const call = (value: unknown = body, caller: any = actor, clusterId = cid, workflowId = id) =>
    http(() => service.reconcilePartialRestoreNoSend(clusterId, workflowId, value, caller));
  const route = (query: Record<string, unknown> = { workspaceId: wid }, value: unknown = body,
    key = actor.idempotencyKey, req: any = actor) =>
    http(() => controller.reconcilePartialRestoreNoSend(cid, id, query, value, key, req));
  const noEffects = () => {
    for (const method of ['execute', 'historical', 'rollbackPrepare', 'preflight', 'closeUnsent', 'reconcileNoSend']) {
      expect(delegate[method]).not.toHaveBeenCalled();
    }
    expect(kong.request).not.toHaveBeenCalled();
    expect(db.one).not.toHaveBeenCalled(); expect(db.query).not.toHaveBeenCalled();
    expect(db.exec).not.toHaveBeenCalled(); expect(db.transaction).not.toHaveBeenCalled();
  };
  return { cid, wid, id, sessionId, actor, plan, state, authorize, handlerAuthorize, plans, registry,
    db, kong, context, service, delegate, controller, body, http, call, route, noEffects };
}

afterEach(() => { vi.restoreAllMocks(); });

describe('M11 partial no-send terminal metadata route and current write scope', () => {
  it('registers the dedicated POST endpoint with HTTP 200', () => {
    const method = WorkflowController.prototype.reconcilePartialRestoreNoSend;
    // Nest PATH_METADATA, METHOD_METADATA and HTTP_CODE_METADATA keys.
    expect(Reflect.getMetadata('path', WorkflowController)).toBe('clusters/:clusterId/workflows');
    expect(Reflect.getMetadata('path', method)).toBe(':id/reconcile-partial-restore-no-send');
    expect(Reflect.getMetadata('method', method)).toBe(RequestMethod.POST);
    expect(Reflect.getMetadata('__httpCode__', method)).toBe(200);
  });

  it('preserves the authenticated current write frame and delegates the original body and actor', async () => {
    const f = fixture();
    f.delegate.reconcilePartialRestoreNoSend.mockImplementation(async (plan: any, body: unknown, actor: any) => {
      await Promise.resolve();
      expect(plan).toBe(f.plan); expect(body).toBe(f.body); expect(actor).toBe(f.actor);
      expect(f.context.current()).toMatchObject({ kind: 'actor', actor: f.actor.user, sessionId: f.sessionId,
        clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'write', requestId: f.actor.requestId,
        ip: f.actor.ip, idempotencyKey: f.actor.idempotencyKey });
      return { state: 'failed', terminal: 'failed', metadataReconciled: true };
    });
    f.service.installEntityChangeExecutor(f.delegate);
    expect(await f.call()).toEqual({ state: 'failed', terminal: 'failed', metadataReconciled: true });
    expect(f.plans.load).toHaveBeenCalledExactlyOnceWith(f.cid, f.wid, f.id);
    expect(f.authorize).toHaveBeenCalledExactlyOnceWith(f.plan, f.actor.user.id, 'write');
    expect(f.delegate.reconcilePartialRestoreNoSend).toHaveBeenCalledExactlyOnceWith(f.plan, f.body, f.actor);
    f.noEffects();
  });

  it('takes user identity from the request and forwards only the scoped workspace and original key', async () => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    const req = { ...f.actor, workspaceId: randomUUID(), idempotencyKey: 'untrusted-request-key',
      approved: true, executionId: randomUUID() };
    const result = await f.route({ workspaceId: f.wid.toUpperCase() }, f.body, 'route-original-key', req);
    expect(result).toEqual({ state: 'failed', terminal: 'failed', metadataReconciled: true });
    const [plan, body, actor] = f.delegate.reconcilePartialRestoreNoSend.mock.calls[0];
    expect(plan).toBe(f.plan); expect(body).toBe(f.body); expect(actor.user).toBe(req.user);
    expect(actor).toEqual({ user: req.user, requestId: req.requestId, ip: req.ip,
      workspaceId: f.wid, idempotencyKey: 'route-original-key' });
    expect(f.plans.load).toHaveBeenCalledExactlyOnceWith(f.cid, f.wid, f.id);
    f.noEffects();
  });

  it.each(['actor', 'clusterId', 'executionId', 'approved', 'nativeAuthority', 'idempotencyKey'])
  ('rejects caller query field %s before loading or delegating', async field => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    await expect(Promise.resolve().then(() => f.route({ workspaceId: f.wid, [field]: 'caller-controlled' })))
      .rejects.toMatchObject({ status: 400, response: { code: 'UNKNOWN_PORTAL_FIELD' } });
    expect(f.plans.load).not.toHaveBeenCalled(); expect(f.authorize).not.toHaveBeenCalled();
    expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled(); f.noEffects();
  });

  it('requires current subject write permission even when historical read would succeed', async () => {
    const f = fixture(); f.state.canWrite = false; f.service.installEntityChangeExecutor(f.delegate);
    await expect(f.call()).rejects.toMatchObject({ status: 403, response: { code: 'OFFLINE_SUBJECT_WRITE_DENIED' } });
    expect(f.authorize).toHaveBeenCalledExactlyOnceWith(f.plan, f.actor.user.id, 'write');
    expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled(); f.noEffects();
  });

  it('rejects a copied actor from a different bound HTTP identity before loading the plan', async () => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    const copiedActor = { ...f.actor, user: { ...f.actor.user, id: randomUUID() } };
    await expect(Promise.resolve().then(() => f.call(f.body, copiedActor)))
      .rejects.toMatchObject({ status: 403, response: { code: 'KONG_ACTOR_SCOPE_MISMATCH' } });
    expect(f.plans.load).not.toHaveBeenCalled(); expect(f.authorize).not.toHaveBeenCalled();
    expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled(); f.noEffects();
  });

  it.each(['cluster', 'workspace', 'workflow'])('rejects a malformed %s UUID before the scoped load', async field => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    const caller = field === 'workspace' ? { ...f.actor, workspaceId: 'not-a-uuid' } : f.actor;
    await expect(Promise.resolve().then(() => f.call(f.body, caller,
      field === 'cluster' ? 'not-a-uuid' : f.cid, field === 'workflow' ? 'not-a-uuid' : f.id)))
      .rejects.toMatchObject({ status: 400, response: { code: 'INVALID_WORKFLOW_ID' } });
    expect(f.plans.load).not.toHaveBeenCalled(); expect(f.authorize).not.toHaveBeenCalled();
    expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled(); f.noEffects();
  });

  it.each([undefined, 'not-a-uuid', ['invalid']])('rejects missing or malformed route workspace %j', async workspaceId => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    await expect(Promise.resolve().then(() => f.route(workspaceId === undefined ? {} : { workspaceId })))
      .rejects.toMatchObject({ status: 400, response: { code: 'INVALID_WORKFLOW_ID' } });
    expect(f.plans.load).not.toHaveBeenCalled(); expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled();
    f.noEffects();
  });

  it('does not fall through a failed scoped plan load into the fixed delegate', async () => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    f.plans.load.mockRejectedValue(new NotFoundException({ code: 'WORKFLOW_NOT_FOUND' }));
    await expect(f.call()).rejects.toMatchObject({ status: 404, response: { code: 'WORKFLOW_NOT_FOUND' } });
    expect(f.plans.load).toHaveBeenCalledExactlyOnceWith(f.cid, f.wid, f.id);
    expect(f.authorize).not.toHaveBeenCalled(); expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled();
    f.noEffects();
  });

  it.each(['absent', 'legacy'])('fails closed when the terminal metadata adapter is %s', async condition => {
    const f = fixture();
    if (condition === 'legacy') {
      const legacy = { ...f.delegate }; delete legacy.reconcilePartialRestoreNoSend;
      f.service.installEntityChangeExecutor(legacy);
    }
    await expect(f.call()).rejects.toMatchObject({ status: 409,
      response: { code: 'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED' } });
    expect(f.authorize).toHaveBeenCalledExactlyOnceWith(f.plan, f.actor.user.id, 'write');
    expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled(); f.noEffects();
  });

  it('authorizes but rejects a different workflow kind without calling the native-change adapter', async () => {
    const f = fixture(); f.plan.kind = 'event-metadata';
    f.plan.steps = [{ kind: 'metadata', handler: 'event.test' }];
    f.service.installEntityChangeExecutor(f.delegate);
    await expect(f.call()).rejects.toMatchObject({ status: 409,
      response: { code: 'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED' } });
    expect(f.handlerAuthorize).toHaveBeenCalledExactlyOnceWith(f.plan, f.actor, 'write');
    expect(f.delegate.reconcilePartialRestoreNoSend).not.toHaveBeenCalled(); f.noEffects();
  });

  it.each([null, true, 1, 'function', {}])('rejects a supplied nonfunction terminal delegate %j', async value => {
    const f = fixture();
    expect(() => f.service.installEntityChangeExecutor({ ...f.delegate, reconcilePartialRestoreNoSend: value }))
      .toThrow('fixed execution delegate');
    f.service.installEntityChangeExecutor(f.delegate);
    await f.call(); expect(f.delegate.reconcilePartialRestoreNoSend).toHaveBeenCalledTimes(1);
    f.noEffects();
  });

  it('propagates fixed verifier failure without retrying, executing or reconciling a different operation', async () => {
    const f = fixture(); f.service.installEntityChangeExecutor(f.delegate);
    const failure = new ForbiddenException({ code: 'TERMINAL_PROOF_INVALID' });
    f.delegate.reconcilePartialRestoreNoSend.mockRejectedValue(failure);
    await expect(f.call()).rejects.toBe(failure);
    expect(f.delegate.reconcilePartialRestoreNoSend).toHaveBeenCalledTimes(1); f.noEffects();
  });
});
