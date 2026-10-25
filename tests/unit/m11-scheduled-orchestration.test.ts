import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException, Logger, NotFoundException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityChangeSchedulesController } from '../../apps/console-api/src/modules/workflows/entity-change-schedules.controller';
import { EntityChangeScheduleBootstrapService } from '../../apps/console-api/src/modules/workflows/entity-change-schedule-bootstrap.service';

/** BFF SQL/HTTP-scope and timer domain adapters. Real global AuthGuard,
 * PostgreSQL, scheduling context and native transport have separate Root gates.
 * No current-source/approval facts or executable fake actors are constructed. */
function controllerFixture() {
  const cid = randomUUID(), wid = randomUUID(), uid = randomUUID(), id = randomUUID(), secrets = new SecretService();
  const actor: any = { user: { id: uid, username: 'authenticated-owner', superAdmin: false }, workspaceId: wid, requestId: randomUUID(), ip: '192.0.2.51' };
  const query = { workspaceId: wid }, rows = [{ id }, { id: randomUUID() }, { id: randomUUID() }];
  const state: any = { revision: 1, progress: 'active', claimed: false, journal: [], readable: new Set(rows.map(row => row.id)), permissionVersion: 'current-1', readOnly: false, foreign: false, failAudit: false, transactionActive: false };
  const scope = () => state.foreign ? null : { id, owner_id: uid, intent_id: randomUUID(), intent_revision: 1, revision: state.revision, state: state.progress, claim_id: state.claimed ? randomUUID() : null, workflow_id: null };
  const receipt = (schedule: string) => ({ id: schedule, revision: state.revision, state: state.progress, intentId: randomUUID(), notBefore: '2026-10-13T17:00:00.000Z', windowStart: '2026-10-13T17:00:00.000Z', windowEnd: '2026-10-13T17:05:00.000Z', workflowId: null, claimId: null, reasonCode: null, nativeAuthority: false });
  const db: any = { one: vi.fn(async (sql: string, values: any[] = []) => {
    if (sql.includes('FROM schema_migrations')) return { checksum: '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f' };
    if (sql.includes('FROM iam_epoch')) return { version: 1 };
    if (sql.includes('FROM audit_events')) return state.journal.find((event: any) => event.after.keyHmac === values[3]) ?? null;
    if (sql.includes('SELECT transport_scope')) return state.foreign ? null : { transport_scope: 'a'.repeat(64) };
    if (sql.includes('FROM entity_change_schedule_progress')) return { schedule_id: id };
    if (sql.includes('FROM entity_change_schedules')) return values[0] === cid && values[1] === wid && values[2] === id ? scope() : null;
    throw new Error('Unexpected schedule BFF domain read');
  }), query: vi.fn(async (sql: string, values: any[]) => { expect(sql).toContain('LIMIT $3 OFFSET $4'); expect(values.slice(0, 2)).toEqual([cid, wid]); return rows.slice(values[3], values[3] + values[2]); }),
    exec: vi.fn(async (sql: string) => { if (!sql.includes('pg_advisory_xact_lock')) throw new Error('Unexpected BFF direct write'); return 1; }),
    transaction: vi.fn(async (fn: any) => { const saved = { revision: state.revision, progress: state.progress, journal: [...state.journal] }; state.transactionActive = true;
      try { return await fn(db); } catch (error) { Object.assign(state, saved); throw error; } finally { state.transactionActive = false; } }) };
  const context: any = { runActor: vi.fn(async (scope: any, fn: any) => { expect(scope.actor).toBe(actor.user); expect(scope.clusterId).toBe(cid); expect(scope.workspaceId).toBe(wid); return fn(); }) };
  const authz: any = { assertCluster: vi.fn(async (_user: any, _cid: any, _module: any, action: string) => { if (state.readOnly && action !== 'read') throw new ForbiddenException({ code: 'READ_ONLY' }); }), permissionVersion: vi.fn(async () => state.permissionVersion) };
  const repo: any = { get: vi.fn(async (schedule: string, actualActor: any) => {
    expect(actualActor.user).toBe(actor.user); if (!state.readable.has(schedule)) throw new ForbiddenException({ code: 'ENTITY_SCOPE_DENIED' }); return receipt(schedule);
  }), cancel: vi.fn(async (schedule: string, actualActor: any, tx: any) => {
    expect(schedule).toBe(id); expect(tx).toBe(db); expect(state.transactionActive).toBe(true); expect(actualActor.user).toBe(actor.user);
    if (state.claimed) throw new ForbiddenException({ code: 'ALREADY_CLAIMED' }); state.progress = 'cancelled'; state.revision++; return receipt(id);
  }) };
  const authority: any = { projection: vi.fn(async () => ({ activate: state.progress === 'pending-approval' && !state.readOnly, cancel: ['active', 'pending-approval'].includes(state.progress) && !state.readOnly })), activateApproved: vi.fn(async (schedule: string, actualActor: any, tx: any) => {
    expect(schedule).toBe(id); expect(tx).toBe(db); expect(state.transactionActive).toBe(true); expect(actualActor.user).toBe(actor.user);
    state.progress = 'active'; state.revision++; return receipt(id);
  }) }, redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn(async () => undefined) }, audit: any = { append: vi.fn(async (event: any, tx: any) => {
    expect(tx).toBe(db); expect(state.transactionActive).toBe(true); if (state.failAudit) throw new Error('Audit commit refused'); state.journal.push(structuredClone(event));
  }) };
  const controller = new EntityChangeSchedulesController(db, secrets, redis, audit, authz, context, repo, authority);
  const cancel = (body: any = { revision: 1, confirmed: true, confirm_name: 'cancel-schedule' }, key = 'original-cancel-key') => controller.cancel(cid, id, query, body, key, actor);
  const activate = (body: any = { revision: 1, confirmed: true, confirm_name: 'activate-schedule' }, key = 'original-activate-key') => controller.activate(cid, id, query, body, key, actor);
  return { controller, state, db, repo, authority, authz, context, audit, actor, cid, wid, id, query, rows, cancel, activate };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ba'.repeat(32)); vi.stubEnv('CURSOR_SIGNING_KEY', 'public-unit-cursor-key'); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });
describe('M11 schedule product BFF orchestration (source-only adapters)', () => {
  it('bounds candidates and filters hidden schedules with a cursor advancing only the actual scanned offset', async () => {
    const f = controllerFixture(); f.state.readable.delete(f.rows[0].id);
    const first: any = await f.controller.list(f.cid, { ...f.query, size: 1 }, f.actor); expect(first.items).toEqual([]); expect(first.nextCursor).toBeTypeOf('string'); expect(f.repo.get).toHaveBeenCalledTimes(1);
    const second: any = await f.controller.list(f.cid, { ...f.query, size: 1, cursor: first.nextCursor }, f.actor); expect(second.items[0].id).toBe(f.rows[1].id);
    expect(f.db.query.mock.calls[1][1]).toEqual([f.cid, f.wid, 2, 1]);
    expect(Buffer.from(first.nextCursor.split('.')[0], 'base64url').toString()).not.toContain(f.rows[0].id);
    f.state.permissionVersion = 'changed-version'; await expect(f.controller.list(f.cid, { ...f.query, size: 1, cursor: first.nextCursor }, f.actor)).rejects.toMatchObject({ response: { code: 'INVALID_CURSOR' } });
    await expect(f.controller.list(f.cid, { ...f.query, size: 101 }, f.actor)).rejects.toMatchObject({ response: { code: 'INVALID_PAGE_SIZE' } });
  });
  it('checks CID/WID before a scoped detail lookup and rejects all caller Actor/claim fields', async () => {
    const f = controllerFixture(); f.state.foreign = true; await expect(f.controller.get(f.cid, f.id, f.query, f.actor)).rejects.toBeInstanceOf(NotFoundException); expect(f.repo.get).not.toHaveBeenCalled();
    f.state.foreign = false; await expect(f.controller.get(f.cid, f.id, { ...f.query, actor: f.actor.user }, f.actor)).rejects.toMatchObject({ response: { code: 'UNKNOWN_PORTAL_FIELD' } });
    await expect(f.cancel({ revision: 1, confirmed: true, confirm_name: 'cancel-schedule', claim: { approved: true } })).rejects.toMatchObject({ response: { code: 'UNKNOWN_PORTAL_FIELD' } }); expect(f.repo.cancel).not.toHaveBeenCalled();
  });
  it('requires typed confirmation, original key and real CAS before metadata cancellation', async () => {
    const f = controllerFixture(); await expect(f.cancel({ revision: 1, confirmed: false, confirm_name: 'cancel-schedule' })).rejects.toMatchObject({ response: { code: 'CONFIRMATION_REQUIRED' } });
    await expect(f.cancel(undefined, 'bad')).rejects.toMatchObject({ response: { code: 'INVALID_IDEMPOTENCY_KEY' } });
    await expect(f.cancel({ revision: 2, confirmed: true, confirm_name: 'cancel-schedule' })).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } }); expect(f.repo.cancel).not.toHaveBeenCalled();
    const result: any = await f.cancel(); expect(result.entity.state).toBe('cancelled'); expect(result.commandCompleted).toBe(true); expect(f.audit.append).toHaveBeenCalledTimes(1);
    expect(result.entity.capabilities).toEqual({ activate: false, cancel: false });
    expect(f.db.exec.mock.calls.every(([sql]: any[]) => sql.includes('pg_advisory_xact_lock'))).toBe(true);
  });
  it('recovers the exact same committed DTO on original-key replay without a second cancel/claim and detects changed bodies', async () => {
    const f = controllerFixture(), first = await f.cancel(); f.state.progress = 'later-historical-view';
    const second = await f.cancel(); expect(second).toEqual(first); expect(f.repo.cancel).toHaveBeenCalledTimes(1); expect(f.audit.append).toHaveBeenCalledTimes(1);
    await expect(f.cancel({ revision: 2, confirmed: true, confirm_name: 'cancel-schedule' })).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    f.state.readable.delete(f.id); await expect(f.cancel()).rejects.toMatchObject({ response: { code: 'ENTITY_SCOPE_DENIED' } }); expect(f.repo.cancel).toHaveBeenCalledTimes(1);
  });
  it('activates with the same real transaction and rejects cross-action key reuse', async () => {
    const f = controllerFixture(); f.state.progress = 'pending-approval'; const first = await f.activate(); expect(f.authority.activateApproved).toHaveBeenCalledTimes(1);
    expect(await f.activate()).toEqual(first); expect(f.authority.activateApproved).toHaveBeenCalledTimes(1);
    await expect(f.cancel(undefined, 'original-activate-key')).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } }); expect(f.repo.cancel).not.toHaveBeenCalled();
  });
  it('denies read-only writes and rolls back state and original-key command when audit commit fails', async () => {
    const f = controllerFixture(); f.state.readOnly = true; await expect(f.cancel()).rejects.toMatchObject({ response: { code: 'READ_ONLY' } }); expect(f.repo.cancel).not.toHaveBeenCalled();
    f.state.readOnly = false; f.state.failAudit = true; await expect(f.cancel()).rejects.toThrow('Audit commit refused'); expect(f.state.progress).toBe('active'); expect(f.state.revision).toBe(1); expect(f.state.journal).toEqual([]);
    f.state.failAudit = false; expect((await f.cancel() as any).entity.state).toBe('cancelled'); expect(f.state.journal).toHaveLength(1);
  });
});
function bootstrapFixture() {
  const repository: any = {}, scheduling = Object.freeze({ assertAvailable: vi.fn(), persistDraft: vi.fn() }), handle = Object.freeze({}), authority: any = {
    installRepositoryPolicies: vi.fn(), intentSchedulingDelegate: vi.fn(() => scheduling), acquireDueClaim: vi.fn(async () => handle), executeClaim: vi.fn(async () => undefined) };
  const intents: any = { installSchedulingDelegate: vi.fn() }; let delegate: any;
  const worker: any = { installFixedDelegate: vi.fn((value: any) => { delegate = value; }), tick: vi.fn(async () => ({ completed: 0 })) }, bootstrap = new EntityChangeScheduleBootstrapService(repository, authority, intents, worker);
  return { bootstrap, authority, intents, worker, scheduling, handle, delegate: () => delegate };
}
describe('M11 explicit scheduler bootstrap (no fake context or executor)', () => {
  it('installs once and hands original handles through the fixed worker without installing a Root executor', async () => {
    const f = bootstrapFixture(); f.bootstrap.onModuleInit(); f.bootstrap.onModuleInit();
    expect(f.authority.installRepositoryPolicies).toHaveBeenCalledTimes(1); expect(f.intents.installSchedulingDelegate).toHaveBeenCalledWith(f.scheduling); expect(f.worker.installFixedDelegate).toHaveBeenCalledTimes(1);
    const original = await f.delegate().acquireDueClaim('schedule'); expect(original).toBe(f.handle); await f.delegate().executeClaim(original); expect(f.authority.executeClaim).toHaveBeenCalledWith(f.handle);
  });
  it.each([undefined, 'false', 'TRUE', '1'])('starts no timer unless the exact explicit flag is true (%s)', async flag => {
    vi.useFakeTimers(); if (flag === undefined) vi.stubEnv('ENTITY_SCHEDULES_ENABLED', undefined); else vi.stubEnv('ENTITY_SCHEDULES_ENABLED', flag);
    const f = bootstrapFixture(); f.bootstrap.onModuleInit(); f.bootstrap.onApplicationBootstrap(); await vi.advanceTimersByTimeAsync(15000); expect(f.worker.tick).not.toHaveBeenCalled(); f.bootstrap.onModuleDestroy();
  });
  it('starts only after bootstrap, excludes overlapping ticks, logs only a safe code and continues after failure', async () => {
    vi.useFakeTimers(); vi.stubEnv('ENTITY_SCHEDULES_ENABLED', 'true'); const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined), f = bootstrapFixture();
    f.bootstrap.onModuleInit(); await vi.advanceTimersByTimeAsync(5000); expect(f.worker.tick).not.toHaveBeenCalled();
    let finish: (() => void) | undefined; f.worker.tick.mockImplementationOnce(() => new Promise<void>(resolve => { finish = resolve; })).mockRejectedValueOnce(new Error('private credential must never reach logs'));
    f.bootstrap.onApplicationBootstrap(); f.bootstrap.onApplicationBootstrap(); await vi.advanceTimersByTimeAsync(15000); expect(f.worker.tick).toHaveBeenCalledTimes(1);
    finish!(); await Promise.resolve(); await vi.advanceTimersByTimeAsync(5000); expect(warn).toHaveBeenCalledWith({ code: 'ENTITY_SCHEDULE_WORKER_TICK_FAILED' });
    expect(JSON.stringify(warn.mock.calls)).not.toContain('credential'); await vi.advanceTimersByTimeAsync(5000); expect(f.worker.tick).toHaveBeenCalledTimes(3);
    f.bootstrap.onModuleDestroy(); await vi.advanceTimersByTimeAsync(10000); expect(f.worker.tick).toHaveBeenCalledTimes(3);
  });
});
