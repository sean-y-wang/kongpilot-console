import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { AuthorizationService, type WorkflowScheduledCurrentIdentityBridge } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import type { WorkflowScheduledNamespaceProof } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.types';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Real Context private frames and original-handle associations. SQL and the
 * fixed Root bridge are controlled Source adapters, not live claims, sessions,
 * workflow approvals, native permissions or commercial acceptance evidence. */
function fixture(kind: WorkflowScheduledNamespaceProof['kind'] = 'configuration_v2') {
  const context = new KongExecutionContextService(), handle = Object.freeze({}), cid = randomUUID(), wid = randomUUID(), operationId = randomUUID();
  const executor = Object.freeze({ id: randomUUID(), username: 'source-executor', superAdmin: false });
  const reviewer = Object.freeze({ id: randomUUID(), username: 'source-reviewer', superAdmin: false });
  const state = { lease: true, claim: true, window: true, iam: '7', current: true,
    bridgeOverride: {} as Record<string, unknown>, afterBridge: undefined as undefined | (() => void) };
  const rows = new Map([executor, reviewer].map((actor, index) => [actor.id, {
    id: actor.id, username: actor.username, super_admin: false, status: 'active', deleted_at: null,
    permissions_epoch: String(4 + index), credential_epoch: String(3 + index), force_password_change: false, revision: 1,
  }]));
  const grant = (module: string, action = 'read') => ({ module, action, scope_type: 'workspace', cluster_id: cid, workspace_id: wid, scope_values: [wid] });
  const grants = new Map([[executor.id, [grant('services'), grant('secrets')]], [reviewer.id, [grant('services')]]]);
  const db: any = { one: vi.fn(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM users')) { const row = rows.get(args[0]); return row?.status === 'active' && !row.deleted_at ? { ...row } : null; }
    if (sql.includes('FROM iam_epoch')) return { version: state.iam };
    if (sql.includes('FROM auth_sessions')) return { id: args[0] };
    if (sql.includes('FROM clusters')) return args[0] === cid ? { id: cid } : null;
    throw Error('UNEXPECTED_SOURCE_SQL');
  }), query: vi.fn(async (sql: string, args: any[]) => {
    if (!sql.includes('iam_effective_grants')) throw Error('UNEXPECTED_SOURCE_GRANT_SQL');
    return structuredClone(grants.get(args[0]) ?? []);
  }) };
  const workspaces: any = { get: vi.fn(async () => ({ id: wid, status: 'active' })),
    classify: vi.fn(async () => ({ state: 'resolved', workspace: { id: wid, status: 'active' } })) };
  const kong: any = { request: vi.fn(async () => { throw Error('UNEXPECTED_NATIVE_REQUEST'); }) };
  const authorization = new AuthorizationService(db, workspaces, kong, context);
  const namespace: Readonly<WorkflowScheduledNamespaceProof> = Object.freeze({ version: 1, origin: 'scheduled-workflow', actor: executor, sessionId: null,
    kind, clusterId: cid, workspaceId: wid, transportScope: transportScopeFor('http://source:8001'), clusterRevision: 1, workspaceRevision: 1,
    credentialEpoch: '3', permissionVersion: `${executor.id}:4:7`, expiresAt: new Date(Date.now() + 60000).toISOString(),
    claim: { id: randomUUID(), scheduleId: randomUUID() } as any, workflow: { id: randomUUID(), planRevision: 1, planHash: 'a'.repeat(64) },
    requester: { type: kind === 'configuration_v2' ? 'console' : 'developer', id: kind === 'configuration_v2' ? executor.id : randomUUID(), credentialEpoch: '3' },
    subjectSealHmac: 'b'.repeat(64), approvalSet: { format: 2, policyHash: 'c'.repeat(64), setId: randomUUID(), setHmac: 'd'.repeat(64),
      reviewers: [{ userId: reviewer.id, approvalId: randomUUID(), level: 1, candidateVersion: 1 }] } });
  const fullVerify = vi.fn(async (original: object) => { if (original !== handle) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); return namespace; });
  context.installWorkflowScheduledNamespacePolicy({ verifyHandle: fullVerify,
    assertLive(original) { if (original !== handle || !state.lease) throw new ForbiddenException({ code: 'SOURCE_LEASE_CLOSED' }); } });
  const ordinaryPolicy = vi.fn(async () => { throw Error('ORDINARY_HTTP_NATIVE_POLICY_NOT_AVAILABLE'); });
  context.installPolicy({ authorizeRequest: ordinaryPolicy, authorizeResponse: ordinaryPolicy });
  const reads = new WeakMap<object, any>();
  context.installWorkflowScheduledValidationReadPolicy({
    async verifyHandle(read, original, proof) {
      const value = reads.get(read);
      if (!value || original !== handle || proof !== namespace || !state.current) throw Error('CURRENT_PRIVATE_READ_REQUIRED'); return value;
    },
    assertLive(read) { if (!reads.has(read) || !state.lease) throw Error('SOURCE_READ_CLOSED'); },
    async authorizeRequest() { throw Error('NO_SOURCE_TEST_GET_NEEDED'); },
    async verifyRequest() { throw Error('NO_SOURCE_TEST_GET_NEEDED'); },
    async authorizeResponse() { throw Error('NO_SOURCE_TEST_GET_NEEDED'); },
  });
  const bridge = { currentPrincipal: vi.fn(async (original: object, proof: Readonly<WorkflowScheduledNamespaceProof>, actorId: string, transaction: any) => {
    if (original !== handle || proof !== namespace || !state.current || !state.lease || !state.claim || !state.window) throw Error('CURRENT_SQL_CLAIM_WINDOW_LEASE_DENIED');
    const principal = context.requireWorkflowScheduledCurrentPrincipal(original);
    if (principal.namespace !== proof || principal.actor.id !== actorId) throw Error('CURRENT_PRIVATE_PRINCIPAL_REQUIRED');
    const row = await transaction.one('SELECT * FROM users WHERE id=$1', [actorId]), epoch = await transaction.one('SELECT version FROM iam_epoch WHERE singleton=true');
    const result = { actorId, credentialEpoch: String(row?.credential_epoch), permissionVersion: `${row?.id}:${row?.permissions_epoch}:${epoch?.version}`,
      role: principal.role, readOnly: principal.readOnly, ...state.bridgeOverride };
    state.afterBridge?.(); return Object.freeze(result);
  }) } satisfies WorkflowScheduledCurrentIdentityBridge;
  const install = () => authorization.installWorkflowScheduledCurrentIdentityBridge(bridge);
  const run = <T>(fn: () => Promise<T>) => context.runWorkflowScheduledNamespace(handle, fn);
  const operation = <T>(fn: () => Promise<T>) => context.runOperation({ actor: executor, clusterId: cid, workspaceId: wid, operationId, entityType: 'services', action: 'write' }, fn);
  const validation = async <T>(role: 'executor' | 'reviewer', fn: () => Promise<T>) => {
    const read = Object.freeze({}), actor = role === 'executor' ? executor : reviewer;
    const proof = Object.freeze({ version: 1, origin: 'workflow-scheduled-validation-read', readOnly: true, sessionId: null, role, actor, namespace,
      expiresAt: new Date(Date.now() + 20000).toISOString(), scope: { version: 1, limits: { maxCalls: 2, maxPages: 2, maxRecords: 10, maxBytes: 1048576 },
        resources: [{ clusterId: cid, workspaceId: wid, path: '/services', kind: 'collection' }] },
      registries: [{ clusterId: cid, workspaceId: wid, transportScope: namespace.transportScope, clusterRevision: 1, workspaceRevision: 1, endpointHmac: 'e'.repeat(64) }] });
    reads.set(read, proof);
    try { return await context.runWorkflowScheduledValidationRead(read, handle, fn); } finally { reads.delete(read); }
  };
  return { context, handle, cid, wid, executor, reviewer, namespace, state, rows, grants, db, kong, authorization, bridge, install, run, operation, validation, fullVerify, ordinaryPolicy };
}

describe('business scheduled current authorization uses original private provenance and fresh SQL', () => {
  it('requires one fixed complete bridge and stays closed when it is absent', async () => {
    const f = fixture();
    await f.run(() => expect(f.authorization.snapshot(f.executor)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CURRENT_IDENTITY_UNAVAILABLE' } }));
    expect(f.db.one).not.toHaveBeenCalled();
    expect(() => f.authorization.installWorkflowScheduledCurrentIdentityBridge({} as any)).toThrow();
    f.install(); expect(() => f.install()).toThrow();
  });
  it.each(['configuration_v2', 'portal-credential-issue'] as const)('uses current %s executor SQL grants without a SID, full-verifier recursion or Native call', async kind => {
    const f = fixture(kind); f.install();
    await f.run(() => f.operation(async () => {
      const value = await f.authorization.snapshot({ ...f.executor, superAdmin: true });
      expect(value.user.superAdmin).toBe(false); expect(value.version).toBe(f.namespace.permissionVersion);
      expect(value.grants.map(grant => grant.module)).toEqual(['services', 'secrets']);
      expect(f.context.current().sessionId).toBeUndefined();
      expect(f.bridge.currentPrincipal).toHaveBeenCalledWith(f.handle, f.namespace, f.executor.id, f.db);
    }));
    expect(f.fullVerify).toHaveBeenCalledTimes(1);
    expect(f.db.one.mock.calls.some(([sql]: any[]) => sql.includes('auth_sessions'))).toBe(false); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('reads actual reviewer grants in a genuine validation capsule instead of lending executor secrets or identity', async () => {
    const f = fixture(); f.install();
    await f.run(() => f.validation('reviewer', async () => {
      const value = await f.authorization.snapshot(f.reviewer);
      expect(value.version).toBe(`${f.reviewer.id}:5:7`); expect(value.grants.map(grant => grant.module)).toEqual(['services']);
      await f.authorization.assertWholeWorkspace(f.reviewer, f.cid, f.wid, 'services', 'read');
      await expect(f.authorization.assertWholeWorkspace(f.reviewer, f.cid, f.wid, 'secrets', 'read')).rejects.toMatchObject({ status: 403 });
      await expect(f.authorization.snapshot(f.executor)).rejects.toMatchObject({ status: 403 });
      expect(f.context.requireWorkflowScheduledCurrentPrincipal(f.handle)).toMatchObject({ role: 'reviewer', readOnly: true });
    }));
    expect(f.fullVerify).toHaveBeenCalledTimes(1); expect(f.kong.request).not.toHaveBeenCalled();
    expect(f.db.query.mock.calls.every(([, args]: any[]) => args[0] === f.reviewer.id)).toBe(true);
  });
  it('can inspect the executor in a readonly validation capsule without converting that capsule to write authority', async () => {
    const f = fixture(); f.install();
    await f.run(() => f.validation('executor', async () => {
      expect((await f.authorization.snapshot(f.executor)).version).toBe(f.namespace.permissionVersion);
      await expect(f.context.authorizeRequest({ id: f.cid, admin_url: 'http://source:8001', revision: 1, version: '1.5.1', execution_mode: 'approval' },
        'POST', '/services', { host: 'source-only' }, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY' } });
    })); expect(f.ordinaryPolicy).not.toHaveBeenCalled();
  });
  it.each(['claim', 'window', 'current'])('requires independent fresh SQL %s even when the cached namespace and its lease stay live', async field => {
    const f = fixture(); f.install();
    await f.run(async () => {
      await f.authorization.permissionVersion(f.executor); f.state[field as 'claim' | 'window' | 'current'] = false;
      await expect(f.operation(() => f.authorization.snapshot(f.executor))).rejects.toThrow('CURRENT_SQL_CLAIM_WINDOW_LEASE_DENIED');
    }); expect(f.fullVerify).toHaveBeenCalledTimes(1);
  });
  it.each(['credential', 'permission', 'iam', 'force-password', 'disabled', 'deleted'])('denies current executor %s changes without trusting the old namespace projection', async field => {
    const f = fixture(); f.install();
    await f.run(async () => {
      const row = f.rows.get(f.executor.id)!;
      if (field === 'credential') row.credential_epoch = '99'; if (field === 'permission') row.permissions_epoch = '99'; if (field === 'iam') f.state.iam = '99';
      if (field === 'force-password') row.force_password_change = true; if (field === 'disabled') row.status = 'disabled'; if (field === 'deleted') row.deleted_at = '2026-10-14' as any;
      await expect(f.authorization.snapshot(f.executor)).rejects.toThrow();
    }); expect(f.db.query).not.toHaveBeenCalled();
  });
  it.each(['actorId', 'credentialEpoch', 'permissionVersion', 'role', 'readOnly'])('rejects a fixed bridge with a mismatched %s observation', async field => {
    const f = fixture(); f.install(); f.state.bridgeOverride[field] = field === 'readOnly' ? true : 'invalid';
    await f.run(() => expect(f.authorization.snapshot(f.executor)).rejects.toMatchObject({ status: 403 }));
    expect(f.db.query).not.toHaveBeenCalled();
  });
  it('checks current reviewer epochs instead of accepting an executor epoch or stale reviewer projection', async () => {
    const f = fixture(); f.install();
    await f.run(() => f.validation('reviewer', async () => {
      f.state.bridgeOverride.credentialEpoch = f.namespace.credentialEpoch;
      await expect(f.authorization.snapshot(f.reviewer)).rejects.toMatchObject({ status: 403 });
      f.state.bridgeOverride = {}; f.state.afterBridge = () => { f.rows.get(f.reviewer.id)!.permissions_epoch = '99'; };
      await expect(f.authorization.snapshot(f.reviewer)).rejects.toMatchObject({ status: 403 });
    })); expect(f.db.query).not.toHaveBeenCalled();
  });
  it('does not cache grants between authorization reads within the same original namespace', async () => {
    const f = fixture(); f.install();
    await f.run(async () => {
      await f.authorization.assertWholeWorkspace(f.executor, f.cid, f.wid, 'services', 'read'); f.grants.set(f.executor.id, []);
      await expect(f.authorization.assertWholeWorkspace(f.executor, f.cid, f.wid, 'services', 'read')).rejects.toMatchObject({ status: 403 });
    }); expect(f.bridge.currentPrincipal.mock.calls.length).toBeGreaterThanOrEqual(3);
  });
  it('keeps every bridge and local identity/grant query on the caller transaction', async () => {
    const f = fixture(); f.install(); const tx: any = { one: f.db.one.getMockImplementation(), query: f.db.query.getMockImplementation() };
    await f.run(async () => {
      expect((await f.authorization.snapshot(f.executor, tx)).version).toBe(f.namespace.permissionVersion);
      expect(f.bridge.currentPrincipal).toHaveBeenCalledWith(f.handle, f.namespace, f.executor.id, tx);
    }); expect(f.db.one).not.toHaveBeenCalled(); expect(f.db.query).not.toHaveBeenCalled();
  });
  it('closes a wrongly recursive Root bridge instead of re-entering the full business authorization chain', async () => {
    const f = fixture(); f.install(); f.bridge.currentPrincipal.mockImplementation(async () => {
      await f.authorization.snapshot(f.executor); throw Error('RECURSIVE_BRIDGE_MUST_NOT_RETURN');
    });
    await f.run(() => expect(f.authorization.permissionVersion(f.executor)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CURRENT_IDENTITY_REENTRANT' } }));
    expect(f.bridge.currentPrincipal).toHaveBeenCalledTimes(1); expect(f.db.query).not.toHaveBeenCalled(); expect(f.fullVerify).toHaveBeenCalledTimes(1);
  });
  it('still permits independent concurrent current authorization reads in the same genuine namespace', async () => {
    const f = fixture(); f.install();
    await f.run(async () => {
      const values = await Promise.all([f.authorization.snapshot(f.executor), f.authorization.snapshot(f.executor)]);
      expect(values.map(value => value.version)).toEqual([f.namespace.permissionVersion, f.namespace.permissionVersion]);
    }); expect(f.bridge.currentPrincipal).toHaveBeenCalledTimes(2);
  });
  it('rechecks the genuine chain after the awaited SQL bridge and does not revive a lost lease', async () => {
    const f = fixture(); f.install(); f.state.afterBridge = () => { f.state.lease = false; };
    await f.run(() => expect(f.authorization.snapshot(f.executor)).rejects.toMatchObject({ response: { code: 'SOURCE_LEASE_CLOSED' } }));
    expect(f.db.query).not.toHaveBeenCalled();
  });
  it('preserves ordinary HTTP SID validation and does not apply a business bridge to a no-SID ordinary operation', async () => {
    const f = fixture(); f.install(); const sid = randomUUID();
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.executor, sid); const close = f.context.captureHttpCloser();
      try { await f.operation(async () => { expect((await f.authorization.snapshot(f.executor)).user.id).toBe(f.executor.id); }); } finally { close(); }
    }); expect(f.db.one.mock.calls.some(([sql]: any[]) => sql.includes('FROM auth_sessions'))).toBe(true);
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.executor); const close = f.context.captureHttpCloser();
      try { await expect(f.operation(() => f.authorization.snapshot(f.executor))).rejects.toMatchObject({ status: 403 }); } finally { close(); }
    }); expect(f.bridge.currentPrincipal).not.toHaveBeenCalled();
  });
  it('cannot turn a copied namespace DTO or detached continuation into a business principal', async () => {
    const f = fixture(); f.install();
    await expect(f.context.runWorkflowScheduledNamespace({ ...f.namespace }, () => f.authorization.snapshot(f.executor))).rejects.toThrow('ORIGINAL_NAMESPACE_REQUIRED');
    let release!: () => void, pending!: Promise<unknown>; const gate = new Promise<void>(resolve => { release = resolve; });
    await f.run(async () => { pending = (async () => { await gate; return f.authorization.snapshot(f.executor); })(); });
    release(); await expect(pending).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(f.bridge.currentPrincipal).not.toHaveBeenCalled();
  });
});
