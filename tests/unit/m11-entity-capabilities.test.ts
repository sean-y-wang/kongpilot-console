import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { EntityChangeIntentsService } from '../../apps/console-api/src/modules/workflows/entity-change-intents.service';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

/** Real capability projection code with explicit SQL/authorization adapters.
 * No fixture here proves a live source, approval, baseline or native grant. */
function intentFixture() {
  const secrets = new SecretService(), cid = randomUUID(), wid = randomUUID(), uid = randomUUID();
  const definition = { id: randomUUID(), version: 1, policyHash: 'a'.repeat(64) };
  const envelope: any = { intentId: randomUUID(), revision: 1, clusterId: cid, workspaceId: wid,
    requesterId: uid, credentialEpoch: '1', issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400000).toISOString(), executionMode: 'approval', definition,
    prepared: { request: { kind: 'entity', entityType: 'services', action: 'create' } }, review: { changes: [{ config: { api_key: 'offline-private-review-key' } }] } };
  const actor = { user: { id: uid, username: 'owner', superAdmin: false }, workspaceId: wid };
  const state: any = { epoch: '1', active: true, submission: null, permissionVersion: 'current-v1', definition, canWrite: true };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM users')) return state.active ? { credential_epoch: state.epoch } : null;
    if (sql.includes('FROM entity_change_submissions')) return state.submission;
    throw new Error('Unexpected projection query');
  }), exec: vi.fn(), transaction: vi.fn() };
  const compiler: any = { prepare: vi.fn(), projectStored: vi.fn(async () => secrets.redact(envelope.review)), revalidateStored: vi.fn() };
  const plans: any = { definition: vi.fn(async () => state.definition), persist: vi.fn() };
  const authz: any = { permissionVersion: vi.fn(async () => state.permissionVersion) };
  const subject = vi.fn(async (_envelope: any, _userId: string, action: string) => {
    if (action === 'write' && !state.canWrite) throw new ForbiddenException({ code: 'OFFLINE_WRITE_DENIED' });
  });
  const service = new EntityChangeIntentsService(db, secrets, {} as any, compiler, plans, {} as any, {} as any, {} as any, authz);
  service.installSubjectPolicy({ assertSubject: subject, verifyReviewer: vi.fn() });
  vi.spyOn(service as any, 'load').mockResolvedValue({ envelope, version: { material_hmac: 'b'.repeat(64) } });
  const get = (caller = actor) => service.get(cid, envelope.intentId, caller);
  return { service, actor, state, envelope, db, compiler, plans, authz, subject, get };
}

function workflowFixture() {
  const cid = randomUUID(), wid = randomUUID(), uid = randomUUID(), id = randomUUID();
  const actor = { user: { id: uid, username: 'owner', superAdmin: false }, workspaceId: wid };
  const plan: any = { kind: 'native-change', clusterId: cid, workspaceId: wid, workflowId: id, planRevision: 1,
    approvalRequired: false, executionMode: 'direct', requester: { type: 'console', id: uid } };
  const row: any = { id, kind: plan.kind, cluster_id: cid, workspace_id: wid, requester_user_id: uid,
    approval_format: 1, approval_required: false, revision: 1, plan_revision: 1, plan_hash: 'c'.repeat(64),
    state: 'pending', execution_mode: 'direct', created_at: new Date(), expires_at: new Date(Date.now() + 86400000) };
  const state = { canWrite: true };
  const db: any = { one: vi.fn(), exec: vi.fn(), query: vi.fn() };
  const authorize = vi.fn(async (_plan: any, _uid: string, action: string) => {
    if (action === 'write' && !state.canWrite) throw new ForbiddenException({ code: 'OFFLINE_WRITE_DENIED' });
  });
  const plans: any = { assertEntityChangeSubject: authorize, load: vi.fn(async () => ({ row, plan })) };
  const registry: any = { get: vi.fn(() => ({ authorize: vi.fn() })) };
  const context = new KongExecutionContextService();
  const service = new WorkflowService(db, {} as any, {} as any, {} as any, context, {} as any,
    {} as any, {} as any, {} as any, {} as any, {} as any, plans, registry, {} as any, {} as any);
  const delegate: any = { canExecute: vi.fn(async () => true), canPreflight: vi.fn(async () => true),
    canRollback: vi.fn(async () => false), execute: vi.fn(), historical: vi.fn(),
    rollbackPrepare: vi.fn(), preflight: vi.fn(), closeUnsent: vi.fn(), reconcileNoSend: vi.fn() };
  const summary = (caller: any = actor) => (service as any).summary(row, plan, caller);
  return { service, plan, row, actor, state, db, authorize, delegate, summary, context, plans, cid };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T14:00:00Z')); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('M11 intent submit capability reflects current owner and SQL facts', () => {
  it('reports submit for the current writable owner without invoking a compiler, write or execution', async () => {
    const f = intentFixture(), result = await f.get();
    expect(result.capabilities).toEqual({ submit: true });
    expect(Object.isFrozen(result.capabilities)).toBe(true);
    expect(result.nativeExecutionAvailable).toBe(false);
    expect(JSON.stringify(result)).not.toContain('offline-private-review-key');
    expect(f.subject).toHaveBeenCalledWith(f.envelope, f.actor.user.id, 'write', f.db);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
    expect(f.compiler.prepare).not.toHaveBeenCalled(); expect(f.compiler.revalidateStored).not.toHaveBeenCalled();
    expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it.each(['submitted', 'expired', 'nonowner', 'epoch', 'inactive', 'policy', 'readonly'])('reports false for %s under the isolated historical-read adapter', async condition => {
    const f = intentFixture(); let caller: any = f.actor;
    if (condition === 'submitted') f.state.submission = { workflow_id: randomUUID() };
    if (condition === 'expired') f.envelope.expiresAt = new Date(Date.now() - 1).toISOString();
    if (condition === 'nonowner') caller = { ...f.actor, user: { ...f.actor.user, id: randomUUID() } };
    if (condition === 'epoch') f.state.epoch = '2';
    if (condition === 'inactive') f.state.active = false;
    if (condition === 'policy') f.state.definition = { ...f.state.definition, version: 2 };
    if (condition === 'readonly') f.state.canWrite = false;
    const result = await f.get(caller);
    expect(result.capabilities.submit).toBe(false); expect(result.nativeExecutionAvailable).toBe(false);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.compiler.revalidateStored).not.toHaveBeenCalled();
  });

  it('rejects a mismatched workspace in the capability projection before checking SQL or grants', async () => {
    const f = intentFixture();
    expect(await (f.service as any).canSubmit(f.envelope, { ...f.actor, workspaceId: randomUUID() })).toBe(false);
    expect(f.db.one).not.toHaveBeenCalled(); expect(f.subject).not.toHaveBeenCalled();
    // The real get() loader separately rejects a foreign workspace. This
    // direct projection check does not replace that IDOR boundary.
  });

  it('returns false for permission drift and known policy denial, and propagates infrastructure failure', async () => {
    const f = intentFixture(); f.authz.permissionVersion.mockResolvedValueOnce('v1').mockResolvedValueOnce('v1').mockResolvedValueOnce('v2');
    expect((await f.get()).capabilities.submit).toBe(false);
    const g = intentFixture(); g.plans.definition.mockRejectedValue(new ConflictException({ code: 'POLICY_DISABLED' }));
    expect((await g.get()).capabilities.submit).toBe(false);
    const h = intentFixture(); h.plans.definition.mockRejectedValue(new ServiceUnavailableException({ code: 'DB_UNAVAILABLE' }));
    await expect(h.get()).rejects.toMatchObject({ status: 503 });
  });
});

describe('M11 workflow capabilities use fixed read-only Root projections', () => {
  it('defaults both capabilities to false when no delegate is installed', async () => {
    const f = workflowFixture(), result = await f.summary();
    expect(result.capabilities).toMatchObject({ execute: false, entityPreflight: false, rollbackPrepare: false });
    expect(Object.isFrozen(result.capabilities)).toBe(true);
  });

  it.each([undefined, null, 1, 'true', { ready: true }])('requires literal true, rejecting a missing or truthy projection %j', async value => {
    const f = workflowFixture();
    for (const method of ['canExecute', 'canPreflight', 'canRollback']) f.delegate[method].mockResolvedValue(value);
    f.service.installEntityChangeExecutor(f.delegate);
    expect((await f.summary()).capabilities).toMatchObject({ execute: false, entityPreflight: false, rollbackPrepare: false });
  });

  it('does not infer rollback from a terminal workflow state; only the actual Root verifier enables it', async () => {
    const f = workflowFixture(); f.row.state = 'succeeded'; f.service.installEntityChangeExecutor(f.delegate);
    expect((await f.summary()).capabilities.rollbackPrepare).toBe(false);
    f.delegate.canRollback.mockResolvedValue(true);
    expect((await f.summary()).capabilities.rollbackPrepare).toBe(true);
    expect(f.delegate.canRollback).toHaveBeenCalledWith(f.plan, f.actor);
    for (const method of ['execute', 'rollbackPrepare', 'preflight', 'closeUnsent', 'reconcileNoSend']) expect(f.delegate[method]).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects capabilities without current write permission or an actor, even when the delegate would say true', async () => {
    const f = workflowFixture(); f.state.canWrite = false; f.service.installEntityChangeExecutor(f.delegate);
    expect((await f.summary()).capabilities).toMatchObject({ execute: false, entityPreflight: false, rollbackPrepare: false });
    expect((await f.summary(null)).capabilities).toMatchObject({ execute: false, entityPreflight: false, rollbackPrepare: false });
    for (const method of ['canExecute', 'canPreflight', 'canRollback']) expect(f.delegate[method]).not.toHaveBeenCalled();
  });

  it('never asks the entity delegate about a different workflow kind', async () => {
    const f = workflowFixture(); f.plan.kind = f.row.kind = 'event-metadata'; f.plan.steps = [{ kind: 'metadata', handler: 'event.test' }];
    f.service.installEntityChangeExecutor(f.delegate);
    expect((await f.summary()).capabilities).toMatchObject({ entityPreflight: false, rollbackPrepare: false });
    expect(f.delegate.canPreflight).not.toHaveBeenCalled(); expect(f.delegate.canRollback).not.toHaveBeenCalled();
  });

  it('requires both fixed projection methods and refuses provider replacement', () => {
    const f = workflowFixture(); const incomplete = { ...f.delegate }; delete incomplete.canRollback;
    expect(() => f.service.installEntityChangeExecutor(incomplete)).toThrow('fixed execution delegate');
    f.service.installEntityChangeExecutor(f.delegate);
    expect(() => f.service.installEntityChangeExecutor(f.delegate)).toThrow('fixed execution delegate');
  });

  it('delegates metadata-only no-send reconciliation only inside the authenticated current write scope', async () => {
    const f = workflowFixture(), sessionId = randomUUID(), body = { executionId: randomUUID(), confirmed: true };
    f.delegate.reconcileNoSend.mockImplementation(async (plan: any, value: any, actor: any) => {
      expect(plan).toBe(f.plan); expect(value).toBe(body); expect(actor).toBe(f.actor);
      expect(f.context.current()).toMatchObject({ kind: 'actor', sessionId, actor: f.actor.user,
        clusterId: f.cid, workspaceId: f.actor.workspaceId, module: 'workflows', action: 'write' });
      return { state: 'failed', knownNoNativeSend: true };
    });
    f.service.installEntityChangeExecutor(f.delegate);
    const result = await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor.user, sessionId);
      return f.service.reconcileEntityNoSend(f.cid, f.row.id, body, f.actor);
    });
    expect(result).toEqual({ state: 'failed', knownNoNativeSend: true });
    expect(f.authorize).toHaveBeenCalledWith(f.plan, f.actor.user.id, 'write');
    expect(f.delegate.execute).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('does not enter reconciliation without current subject write permission or a fixed adapter', async () => {
    const f = workflowFixture(); f.state.canWrite = false; f.service.installEntityChangeExecutor(f.delegate);
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor.user, randomUUID());
      await expect(f.service.reconcileEntityNoSend(f.cid, f.row.id, {}, f.actor)).rejects.toMatchObject({ status: 403 });
    });
    expect(f.delegate.reconcileNoSend).not.toHaveBeenCalled();
    const g = workflowFixture();
    await g.context.runHttp({}, async () => {
      g.context.bindHttpActor(g.actor.user, randomUUID());
      await expect(g.service.reconcileEntityNoSend(g.cid, g.row.id, {}, g.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED' } });
    });
    expect(g.db.exec).not.toHaveBeenCalled();
  });
});
