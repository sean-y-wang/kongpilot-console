import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ControlMetadataBusinessService } from '../../apps/console-api/src/modules/control-plane/control-metadata-business.service';
import { ClustersService } from '../../apps/console-api/src/modules/clusters/clusters.service';
import { DataSourcesService } from '../../apps/console-api/src/modules/data-sources/data-sources.service';
import { WorkspaceService } from '../../apps/console-api/src/modules/workspaces/workspace.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import type { ControlBusinessBridge, ControlCapturedChange } from '../../apps/console-api/src/modules/control-plane/control-metadata.types';
import { executionFixture } from './execution-test-fixture';

/** Real business service, real ALS and real original services/once bridges.
 * SQL, IAM/Mutation ledgers, authorization, Kong reads and the Root-owned
 * private authority policy are explicit fixtures; these are Source tests. */
const cid = '62000000-0000-4000-8000-000000000001';
const wid = '62000000-0000-4000-8000-000000000002';
const defaultId = '62000000-0000-4000-8000-000000000003';
const sourceId = '62000000-0000-4000-8000-000000000004';
const otherCid = '62000000-0000-4000-8000-000000000005';
const actor = { user: { id: '62000000-0000-4000-8000-000000000006', username: 'owner', superAdmin: true }, idempotencyKey: 'original-control-key' };
type SqlCall = { owner: 'outer' | 'tx'; sql: string; params: any[] };
const clone = <T>(value: T): T => structuredClone(value);
const projected = (sql: string, row: any): any => {
  if (!row) return null;
  const columns = sql.match(/^SELECT\s+(.+?)\s+FROM\s/s)?.[1];
  if (!columns || columns === '*') return clone(row);
  return Object.fromEntries(columns.split(',').map(column => {
    const name = column.trim();
    if (name.includes(' AS connection_configured')) return ['connection_configured', !!row.connection_secret];
    if (name.includes(' AS auth_configured')) return ['auth_configured', !!row.auth_secret];
    return [name, clone(row[name] ?? null)];
  }));
};
function fixture(installPolicy = true) {
  const secrets = new SecretService();
  let state: any = {
    cluster: { id: cid, name: 'Production', environment: 'prod', admin_url: 'http://192.0.2.31:8001', proxy_origin: null, labels: ['prod'], execution_mode: 'approval', transport_scope: 'a'.repeat(64), connection_secret: secrets.encrypt({ type: 'basic', username: 'operator', password: 'Synthetic-admin-password' }, `cluster:${cid}`), revision: 1, deleted_at: null, status: 'healthy', version: '1.5.1', capabilities: { status: true }, enabled_plugins: ['key-auth'], last_probed_at: '2026-10-14T00:00:00Z', created_at: '2026-10-14T00:00:00Z', updated_at: '2026-10-14T00:00:00Z' },
    sources: new Map([[sourceId, { id: sourceId, cluster_id: cid, name: 'Metrics', type: 'prometheus', base_url: 'http://192.0.2.32:9090', auth_secret: secrets.encrypt({ type: 'bearer', token: 'Synthetic-metrics-token' }, `data-source:${cid}:${sourceId}`), enabled: true, revision: 1, deleted_at: null, last_status: 'healthy', last_probed_at: '2026-10-14T00:00:00Z', created_at: '2026-10-14T00:00:00Z', updated_at: '2026-10-14T00:00:00Z' }]]),
    workspaces: new Map([
      [defaultId, { id: defaultId, cluster_id: cid, code: 'default', name: '默认工作区', owner_user_id: null, description: '', is_default: true, status: 'active', revision: 1, deleted_at: null, retention_until: null }],
      [wid, { id: wid, cluster_id: cid, code: 'payments', name: 'Payments', owner_user_id: actor.user.id, description: 'Original description', is_default: false, status: 'active', revision: 1, deleted_at: null, retention_until: null }],
    ]),
  };
  const calls: SqlCall[] = [], writes: SqlCall[] = [];
  const assign = (row: any, sql: string, params: any[]) => {
    for (const match of sql.matchAll(/(?:SET\s+|,)\s*([a-z_]+)\s*=\s*\$(\d+)/gi)) row[match[1]] = clone(params[Number(match[2]) - 1]);
    if (sql.includes('revision=revision+1')) row.revision++;
    if (sql.includes('deleted_at=now()')) row.deleted_at = '2026-10-14T00:01:00Z';
  };
  const sql = (owner: 'outer' | 'tx') => ({
    one: vi.fn(async (statement: string, params: any[] = []) => {
      const call = { owner, sql: statement, params: clone(params) }; calls.push(call);
      if (statement.includes('FROM iam_epoch')) return { version: 1 };
      if (statement.includes('FROM users')) return params[0] === actor.user.id ? { id: actor.user.id } : null;
      if (statement.includes('FROM clusters')) {
        if (statement.includes('lower(name)')) return null;
        const row = params[0] === cid ? state.cluster : null;
        return !row || statement.includes('deleted_at IS NULL') && row.deleted_at ? null : projected(statement, row);
      }
      if (statement.includes('FROM data_sources')) {
        if (statement.includes('lower(name)')) return null;
        const row = state.sources.get(params[1]);
        return params[0] !== cid || !row || statement.includes('deleted_at IS NULL') && row.deleted_at ? null : projected(statement, row);
      }
      if (statement.startsWith('SELECT') && statement.includes('FROM workspaces')) {
        const row = statement.includes("code='default'") ? state.workspaces.get(defaultId) : state.workspaces.get(params[1]);
        return row?.cluster_id === params[0] ? projected(statement, row) : null;
      }
      if (statement.startsWith('INSERT INTO workspaces')) {
        writes.push(call); const row = { id: params[5], cluster_id: params[0], code: params[1], name: params[2], owner_user_id: params[3], description: params[4], is_default: false, status: 'active', revision: 1, deleted_at: null, retention_until: null };
        state.workspaces.set(row.id, row); return clone(row);
      }
      if (statement.startsWith('UPDATE workspaces')) {
        const row = state.workspaces.get(params[1]), revision = statement.includes('SET name=') ? params[6] : params[2];
        if (!row || row.cluster_id !== params[0] || row.revision !== revision) return null;
        writes.push(call);
        if (statement.includes("SET status='deleted'")) Object.assign(row, { status: 'deleted', deleted_at: '2026-10-14T00:01:00Z', retention_until: '2026-11-13T00:01:00Z', revision: row.revision + 1 });
        else if (statement.includes("SET status='active'")) Object.assign(row, { status: 'active', deleted_at: null, retention_until: null, revision: row.revision + 1 });
        else assign(row, statement, params);
        return clone(row);
      }
      throw new Error(`Unexpected fixture SQL: ${statement}`);
    }),
    query: vi.fn(async (statement: string, params: any[] = []) => { calls.push({ owner, sql: statement, params: clone(params) }); return statement.includes('FROM clusters') ? [projected(statement, state.cluster)] : []; }),
    exec: vi.fn(async (statement: string, params: any[] = []) => {
      const call = { owner, sql: statement, params: clone(params) }; calls.push(call);
      if (statement.startsWith('INSERT INTO workspaces') && statement.includes('SELECT id')) throw new Error('Unexpected lazy default write during capture/apply');
      writes.push(call);
      if (statement.startsWith('INSERT INTO data_sources')) {
        const row = { id: params[0], cluster_id: params[1], name: params[2], type: params[3], base_url: params[4], auth_secret: params[5], enabled: params[6], revision: 1, deleted_at: null, last_status: 'unknown', last_probed_at: null };
        state.sources.set(row.id, row); return 1;
      }
      if (statement.startsWith('UPDATE clusters')) {
        if (state.cluster.revision !== params[1]) return 0; assign(state.cluster, statement, params); return 1;
      }
      if (statement.startsWith('UPDATE data_sources')) {
        const row = state.sources.get(params[1]); if (!row || row.revision !== params[2]) return 0;
        assign(row, statement, params); return 1;
      }
      throw new Error(`Unexpected fixture write: ${statement}`);
    }),
    transaction: vi.fn(async () => { throw new Error('Unexpected nested transaction'); }),
  });
  const tx: any = sql('tx'), db: any = sql('outer');
  const transact = async (fn: (transaction: any) => Promise<any>) => { const before = clone(state); try { return await fn(tx); } catch (error) { state = before; throw error; } };
  db.transaction = vi.fn(transact);
  const audit = { append: vi.fn().mockResolvedValue(undefined) };
  const authz: any = { assertConsole: vi.fn().mockResolvedValue(undefined), assertCluster: vi.fn().mockResolvedValue(undefined), assertEntity: vi.fn().mockResolvedValue(undefined), isPlatformAdmin: vi.fn().mockResolvedValue(true), snapshot: vi.fn().mockResolvedValue({ user: { superAdmin: true }, grants: [] }), permissionVersion: vi.fn().mockResolvedValue('permission-1') };
  const kong: any = { invalidate: vi.fn(), list: vi.fn().mockResolvedValue({ items: [], nextCursor: null, size: 1 }) };
  const operations: any = { completed: vi.fn().mockResolvedValue(null), execute: vi.fn(async (_context: any, fn: any) => transact(fn)) };
  const mutations: any = { execute: vi.fn(async (_context: any, fn: any) => fn()) };
  const execution = executionFixture();
  const clusters = new ClustersService(db, secrets, kong, audit as any, authz, operations, execution);
  const sources = new DataSourcesService(db, secrets, clusters, audit as any, authz, operations);
  const resolver = new WorkspaceResolverService(db);
  const workspaces = new WorkspaceService(db, resolver, authz, mutations, audit as any, kong, execution);
  const service = new ControlMetadataBusinessService(db, secrets, clusters, sources, workspaces, operations);
  const bridges: ControlBusinessBridge[] = [];
  for (const original of [clusters, sources, workspaces]) {
    const install = original.installControlMetadataBridge.bind(original);
    vi.spyOn(original, 'installControlMetadataBridge').mockImplementation(bridge => { bridges.push(bridge); install(bridge); });
  }
  service.onModuleInit();
  const handles = new WeakMap<object, { capture: Readonly<ControlCapturedChange>; live: boolean; claimed: boolean; phase: 'before' | 'after' | 'done' }>();
  const reject = () => new ForbiddenException({ code: 'FIXTURE_ORIGINAL_CONTROL_HANDLE_REQUIRED' });
  const policy: any = {
    verifyCapture: vi.fn(async (handle: object, capture: Readonly<ControlCapturedChange>, actualActor: any, actualTx: any) => {
      const original = handles.get(handle);
      if (!original?.live || original.claimed || actualTx !== tx || actualActor.user.id !== actor.user.id || secrets.fingerprint(capture) !== secrets.fingerprint(original.capture)) throw reject();
      original.claimed = true;
    }),
    verifyMutation: vi.fn(async (handle: object, mutation: any, phase: 'before' | 'after', actualTx: any) => {
      const original = handles.get(handle), { actor: actualActor, ...pure } = mutation;
      if (!original?.live || !original.claimed || original.phase !== phase || actualTx !== tx || actualActor.user.id !== actor.user.id || secrets.fingerprint(pure) !== secrets.fingerprint(original.capture.mutation)) throw reject();
      original.phase = phase === 'before' ? 'after' : 'done';
    }),
  };
  if (installPolicy) service.installApprovedPolicy(policy);
  const mint = (capture: Readonly<ControlCapturedChange>) => { const handle = Object.freeze({}); handles.set(handle, { capture, live: true, claimed: false, phase: 'before' }); return { handle, revoke: () => { handles.get(handle)!.live = false; } }; };
  return { service, secrets, state: () => state, calls, writes, tx, db, audit, authz, kong, operations, mutations, clusters, sources, workspaces, bridges, policy, mint, transact };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '2c'.repeat(32)); vi.stubEnv('APP_SECRET', 'control-business-source-key-over-32-bytes'); vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', '192.0.2.31,192.0.2.32,192.0.2.33'); });
afterEach(() => vi.unstubAllEnvs());
const cases = [
  { resource: 'clusters', operation: 'update', resourceId: cid, input: { revision: 1, name: 'New production' } },
  { resource: 'clusters', operation: 'deactivate', resourceId: cid, input: { revision: 1, confirm: true, confirm_name: 'Production' } },
  { resource: 'data-sources', operation: 'create', input: { name: 'New logs', type: 'loki', base_url: 'http://192.0.2.33:3100', auth: { type: 'bearer', token: 'Synthetic-new-token' } } },
  { resource: 'data-sources', operation: 'update', resourceId: sourceId, input: { revision: 1, name: 'New metrics' } },
  { resource: 'data-sources', operation: 'deactivate', resourceId: sourceId, input: { revision: 1, confirm: true, confirm_name: 'Metrics' } },
  { resource: 'workspaces', operation: 'create', input: { code: 'ops', name: 'Operations', owner_user_id: actor.user.id } },
  { resource: 'workspaces', operation: 'update', resourceId: wid, input: { revision: 1, description: 'New description' } },
  { resource: 'workspaces', operation: 'archive', resourceId: wid, input: { revision: 1, confirmed: true, confirm_name: 'Payments' } },
] as const;

describe('M11 control metadata real original business ALS boundary', () => {
  it.each(cases)('captures $resource/$operation without SQL mutation, original ledger, audit or native emptiness execution', async request => {
    const f = fixture(), initial = clone(f.state()), capture = await f.service.capture(request, cid, actor, f.tx);
    expect(capture.request).toEqual(request);
    expect(capture.mutation).toMatchObject({ resource: request.resource, operation: request.operation, clusterId: cid, module: request.resource, action: ['deactivate', 'archive'].includes(request.operation) ? 'delete' : 'write' });
    expect(capture.mutation).not.toHaveProperty('actor');
    expect(capture.allocatedIds).toHaveLength(request.operation === 'create' ? 1 : 0);
    if (request.operation === 'create') { expect(capture.before).toBeNull(); expect(capture.mutation.resourceId).toBe(capture.allocatedIds[0]); }
    else expect(capture.before).toHaveProperty('id', request.resourceId);
    expect(f.calls.every(call => call.owner === 'tx')).toBe(true);
    expect(f.writes).toEqual([]); expect(f.state()).toEqual(initial);
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.operations.completed).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
    expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.tx.transaction).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
    expect(f.policy.verifyCapture).not.toHaveBeenCalled(); expect(f.bridges[0].currentTransaction()).toBeUndefined();
  });

  it.each(cases)('applies $resource/$operation through original business SQL on the supplied transaction only', async request => {
    const f = fixture(), capture = await f.service.capture(request, cid, actor, f.tx), original = f.mint(capture);
    f.calls.length = 0;
    const result = await f.transact(tx => f.service.apply(original.handle, capture, actor, tx));
    expect(result).toBeTruthy(); expect(f.writes).toHaveLength(1); expect(f.calls.every(call => call.owner === 'tx')).toBe(true);
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.tx.transaction).not.toHaveBeenCalled();
    expect(f.audit.append).toHaveBeenCalledWith(expect.any(Object), f.tx);
    expect(f.policy.verifyCapture).toHaveBeenCalledWith(original.handle, capture, actor, f.tx);
    expect(f.policy.verifyMutation.mock.calls.map(call => call[2])).toEqual(['before', 'after']);
    expect(f.policy.verifyMutation.mock.calls.every(call => call[0] === original.handle && call[3] === f.tx)).toBe(true);
    const afterCall = f.policy.verifyMutation.mock.calls[1]; expect(afterCall[4]).toEqual(result); expect(afterCall[5]).toHaveProperty('id', capture.mutation.resourceId);
    if (request.operation === 'create') expect(result.id).toBe(capture.allocatedIds[0]);
    if (request.operation === 'archive') expect(f.kong.list).toHaveBeenCalledTimes(8);
  });

  it('captures and restores the exact soft-deleted workspace while requiring real original confirmation', async () => {
    const f = fixture(); Object.assign(f.state().workspaces.get(wid), { status: 'deleted', deleted_at: '2026-10-14T00:00:00Z', retention_until: '2026-11-13T00:00:00Z' });
    const request = { resource: 'workspaces', operation: 'restore', resourceId: wid, input: { revision: 1, confirmed: true, confirm_name: 'Payments' } };
    const capture = await f.service.capture(request, cid, actor, f.tx), original = f.mint(capture);
    expect(capture.before).toMatchObject({ status: 'deleted', id: wid });
    expect(await f.transact(tx => f.service.apply(original.handle, capture, actor, tx))).toMatchObject({ id: wid, status: 'active', revision: 2, deleted_at: null, description: 'Original description' });
  });

  it('freezes the entire captured request, nested payload, allocated IDs and encrypted before configuration', async () => {
    const f = fixture(), raw = { resource: 'clusters', operation: 'update', resourceId: cid, input: { revision: 1, labels: ['prod'], connection_auth: { type: 'basic', username: 'operator', password: 'Synthetic-new-password' } } };
    const capture = await f.service.capture(raw, cid, actor, f.tx); raw.input.labels.push('late-label'); raw.input.connection_auth.password = 'Late-mutation';
    expect(Object.isFrozen(capture)).toBe(true); expect(Object.isFrozen(capture.request.input)).toBe(true); expect(Object.isFrozen(capture.mutation.payload)).toBe(true); expect(Object.isFrozen(capture.before)).toBe(true); expect(Object.isFrozen(capture.allocatedIds)).toBe(true);
    expect((capture.mutation.payload as any).labels).toEqual(['prod']);
    expect(capture.before!.connection_secret).toBe(f.state().cluster.connection_secret);
    expect(JSON.stringify(capture.before)).not.toContain('Synthetic-admin-password');
    expect(() => ((capture.request.input as any).connection_auth.password = 'tampered')).toThrow();
  });

  for (const resource of ['clusters', 'data-sources'] as const) {
    it(`excludes ${resource} probe projections/timestamps from the private configuration fingerprint`, async () => {
      const f = fixture(), request = resource === 'clusters' ? cases[0] : cases[3], id = request.resourceId;
      const before = await f.service.readConfig(request, cid, id, f.tx);
      const row = resource === 'clusters' ? f.state().cluster : f.state().sources.get(sourceId);
      Object.assign(row, { last_status: 'unhealthy', last_probed_at: '2026-10-14T23:59:59Z', updated_at: '2026-10-14T23:59:59Z', status: 'unhealthy', version: '1.5.2', enabled_plugins: ['key-auth', 'cors'], capabilities: { status: false } });
      const after = await f.service.readConfig(request, cid, id, f.tx);
      expect(f.secrets.fingerprint(after)).toBe(f.secrets.fingerprint(before));
      for (const name of ['last_status', 'last_probed_at', 'updated_at', 'version', 'capabilities', 'enabled_plugins']) expect(after).not.toHaveProperty(name);
    });
  }

  it('allows fresh probe observations between capture and apply without silently accepting a changed configuration', async () => {
    const f = fixture(), capture = await f.service.capture(cases[3], cid, actor, f.tx), original = f.mint(capture);
    Object.assign(f.state().sources.get(sourceId), { last_status: 'unhealthy', last_probed_at: '2026-10-14T20:00:00Z', updated_at: '2026-10-14T20:00:00Z' });
    expect(await f.transact(tx => f.service.apply(original.handle, capture, actor, tx))).toMatchObject({ name: 'New metrics', revision: 2 });
  });

  for (const field of ['name', 'auth_secret', 'enabled', 'revision'] as const) {
    it(`rejects actual data-source ${field} drift before invoking the original SQL callback`, async () => {
      const f = fixture(), capture = await f.service.capture(cases[3], cid, actor, f.tx), original = f.mint(capture);
      f.state().sources.get(sourceId)[field] = field === 'enabled' ? false : field === 'revision' ? 2 : `Synthetic-new-${field}`;
      await expect(f.transact(tx => f.service.apply(original.handle, capture, actor, tx))).rejects.toMatchObject({ response: { code: 'CONTROL_METADATA_CHANGED' } });
      expect(f.writes).toEqual([]); expect(f.policy.verifyMutation).not.toHaveBeenCalled();
    });
  }

  for (const change of ['copy-handle', 'revoked-handle', 'wrong-actor', 'wrong-transaction', 'before-password-cipher', 'mutation-payload', 'allocated-id'] as const) {
    it(`rejects ${change} using the fixture private original-handle provider before all business writes`, async () => {
      const f = fixture(), capture = await f.service.capture(change === 'allocated-id' ? cases[2] : cases[0], cid, actor, f.tx), original = f.mint(capture);
      let handle: object = original.handle, supplied: any = capture, actualActor: any = actor, actualTx = f.tx;
      if (change === 'copy-handle') handle = { ...original.handle };
      if (change === 'revoked-handle') original.revoke();
      if (change === 'wrong-actor') actualActor = { user: { ...actor.user, id: otherCid } };
      if (change === 'wrong-transaction') actualTx = { ...f.tx };
      if (['before-password-cipher', 'mutation-payload', 'allocated-id'].includes(change)) {
        supplied = clone(capture);
        if (change === 'before-password-cipher') supplied.before.connection_secret = 'Synthetic-altered-cipher';
        if (change === 'mutation-payload') supplied.mutation.payload.name = 'Late mutation';
        if (change === 'allocated-id') supplied.allocatedIds[0] = otherCid;
      }
      await expect(f.service.apply(handle, supplied, actualActor, actualTx)).rejects.toMatchObject({ response: { code: 'FIXTURE_ORIGINAL_CONTROL_HANDLE_REQUIRED' } });
      expect(f.writes).toEqual([]); expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.policy.verifyMutation).not.toHaveBeenCalled();
    });
  }

  it('takes an immutable apply snapshot before awaiting private verification', async () => {
    const f = fixture(), capture = await f.service.capture(cases[0], cid, actor, f.tx), original = f.mint(capture), supplied: any = clone(capture);
    const verify = f.policy.verifyCapture.getMockImplementation()!, gate = deferred<void>();
    f.policy.verifyCapture.mockImplementation(async (...args: any[]) => { await verify(...args); await gate.promise; });
    const applying = f.transact(tx => f.service.apply(original.handle, supplied, actor, tx));
    await Promise.resolve(); supplied.request.input.name = 'External after-await mutation'; supplied.mutation.payload.name = 'External after-await mutation';
    gate.resolve(); expect(await applying).toMatchObject({ name: 'New production' });
  });

  it('does not authorize from a successful-looking policy before callback and rolls back a failing after verification', async () => {
    const f = fixture(), capture = await f.service.capture(cases[0], cid, actor, f.tx), original = f.mint(capture), initial = clone(f.state());
    const verify = f.policy.verifyMutation.getMockImplementation()!;
    f.policy.verifyMutation.mockImplementation(async (...args: any[]) => { await verify(...args); if (args[2] === 'after') throw new ForbiddenException({ code: 'FIXTURE_CONTROL_READBACK_MISMATCH' }); });
    await expect(f.transact(tx => f.service.apply(original.handle, capture, actor, tx))).rejects.toMatchObject({ response: { code: 'FIXTURE_CONTROL_READBACK_MISMATCH' } });
    expect(f.writes).toHaveLength(1); expect(f.state()).toEqual(initial); expect(f.bridges[0].currentTransaction()).toBeUndefined();
  });

  it('requires an installed private policy and rejects reuse of the already claimed original handle', async () => {
    const noPolicy = fixture(false), capture = await noPolicy.service.capture(cases[0], cid, actor, noPolicy.tx);
    await expect(noPolicy.service.apply({}, capture, actor, noPolicy.tx)).rejects.toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    const f = fixture(), prepared = await f.service.capture(cases[0], cid, actor, f.tx), original = f.mint(prepared);
    await f.transact(tx => f.service.apply(original.handle, prepared, actor, tx));
    await expect(f.service.apply(original.handle, prepared, actor, f.tx)).rejects.toMatchObject({ response: { code: 'FIXTURE_ORIGINAL_CONTROL_HANDLE_REQUIRED' } });
    expect(f.writes).toHaveLength(1);
  });

  it('installs the genuine bridge and private policy exactly once', () => {
    const f = fixture(); expect(f.clusters.installControlMetadataBridge).toHaveBeenCalledTimes(1); expect(f.sources.installControlMetadataBridge).toHaveBeenCalledTimes(1); expect(f.workspaces.installControlMetadataBridge).toHaveBeenCalledTimes(1);
    expect(() => f.service.onModuleInit()).toThrow(); expect(() => f.service.installApprovedPolicy(f.policy)).toThrow();
  });

  it('keeps ordinary Direct execution on the original kernel callback without invoking approved policy', async () => {
    const f = fixture(); f.state().cluster.execution_mode = 'direct';
    expect(await f.sources.update(cid, sourceId, { revision: 1, name: 'Direct metrics' }, actor)).toMatchObject({ name: 'Direct metrics', revision: 2 });
    expect(f.operations.execute).toHaveBeenCalledWith(expect.objectContaining({ module: 'data-sources', cluster_id: cid, targetId: sourceId, payload: { revision: 1, name: 'Direct metrics' } }), expect.any(Function));
    expect(f.policy.verifyCapture).not.toHaveBeenCalled(); expect(f.policy.verifyMutation).not.toHaveBeenCalled(); expect(f.bridges[0].currentTransaction()).toBeUndefined();
  });

  it('keeps a Direct workspace write on its original MutationService and one ordinary transaction', async () => {
    const f = fixture(); f.state().cluster.execution_mode = 'direct';
    expect(await f.workspaces.update(cid, wid, { revision: 1, description: 'Direct description' }, actor)).toMatchObject({ id: wid, description: 'Direct description', revision: 2 });
    expect(f.mutations.execute).toHaveBeenCalledWith(expect.objectContaining({ entityType: 'workspaces', workspaceId: wid, action: 'update', payload: { revision: 1, description: 'Direct description' } }), expect.any(Function));
    expect(f.db.transaction).toHaveBeenCalledTimes(1); expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.policy.verifyCapture).not.toHaveBeenCalled(); expect(f.policy.verifyMutation).not.toHaveBeenCalled();
  });

  it('preserves the original Direct completed receipt provider outside a frame', async () => {
    const f = fixture(); f.operations.completed.mockResolvedValue({ result: { id: cid, completedOriginal: true } });
    expect(await f.clusters.update(cid, { revision: 1, name: 'Already complete' }, actor)).toEqual({ id: cid, completedOriginal: true });
    expect(f.operations.completed).toHaveBeenCalledWith(expect.objectContaining({ actor, module: 'clusters', targetId: cid })); expect(f.writes).toEqual([]);
  });

  it('rejects an unrelated cluster request before entering the original service', async () => {
    const f = fixture();
    await expect(f.service.capture(cases[0], otherCid, actor, f.tx)).rejects.toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    expect(f.calls).toEqual([]); expect(f.writes).toEqual([]);
  });

  it('rejects reentrant capture before selecting another original business operation', async () => {
    const f = fixture(), original = f.clusters.update.bind(f.clusters);
    vi.spyOn(f.clusters, 'update').mockImplementation(async (...args) => { await f.service.capture(cases[3], cid, actor, f.tx); return original(...args); });
    await expect(f.service.capture(cases[0], cid, actor, f.tx)).rejects.toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    expect(f.writes).toEqual([]); expect(f.calls).toEqual([]);
  });

  it('rejects a second sequential callback in capture without creating a second prepared fact', async () => {
    const f = fixture(), original = f.clusters.update.bind(f.clusters);
    vi.spyOn(f.clusters, 'update').mockImplementation(async (...args) => { await original(...args); return original(...args); });
    await expect(f.service.capture(cases[0], cid, actor, f.tx)).rejects.toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    expect(f.writes).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.operations.execute).not.toHaveBeenCalled();
  });

  it('rejects a second sequential approved callback and propagates failure for transaction rollback', async () => {
    const f = fixture(), capture = await f.service.capture(cases[0], cid, actor, f.tx), original = f.mint(capture), initial = clone(f.state()), update = f.clusters.update.bind(f.clusters);
    vi.spyOn(f.clusters, 'update').mockImplementation(async (...args) => { await update(...args); return update(...args); });
    await expect(f.transact(tx => f.service.apply(original.handle, capture, actor, tx))).rejects.toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    expect(f.writes).toHaveLength(1); expect(f.state()).toEqual(initial); expect(f.policy.verifyMutation).toHaveBeenCalledTimes(2);
  });

  it('reserves one callback before an awaited configuration read so parallel capture cannot overwrite it', async () => {
    const f = fixture(), original = f.clusters.update.bind(f.clusters), read = f.service.readConfig.bind(f.service), entered = deferred<void>(), release = deferred<void>();
    let first = true, rejected: any;
    vi.spyOn(f.service, 'readConfig').mockImplementation(async (...args) => { if (first) { first = false; entered.resolve(); await release.promise; } return read(...args); });
    const fn = vi.fn(), direct = vi.fn();
    vi.spyOn(f.clusters, 'update').mockImplementation(async (...args) => {
      const primary = original(...args); await entered.promise;
      const secondary = f.bridges[0].execute({ resource: 'clusters', operation: 'update', clusterId: cid, resourceId: cid, module: 'clusters', action: 'write', workspaceId: null, actor, payload: args[1] }, fn, direct).catch(error => { rejected = error; });
      release.resolve(); await secondary; return primary;
    });
    const capture = await f.service.capture(cases[0], cid, actor, f.tx);
    expect(rejected).toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    expect(capture.mutation.payload).toEqual(cases[0].input); expect(fn).not.toHaveBeenCalled(); expect(direct).not.toHaveBeenCalled(); expect(f.writes).toEqual([]);
    expect(f.service.readConfig).toHaveBeenCalledTimes(1);
  });

  it('prevents an extra creation ID from entering the fixed allocation sequence', async () => {
    const f = fixture(), original = f.sources.create.bind(f.sources);
    vi.spyOn(f.sources, 'create').mockImplementation(async (...args) => { f.bridges[1].allocateId(); return original(...args); });
    await expect(f.service.capture(cases[2], cid, actor, f.tx)).rejects.toMatchObject({ response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } });
    expect(f.writes).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('closes an escaped approved SQL bridge after its one verified callback has completed', async () => {
    const f = fixture(), capture = await f.service.capture(cases[0], cid, actor, f.tx), origin = f.mint(capture), original = f.clusters.update.bind(f.clusters), release = deferred<void>();
    let escaped!: Promise<any>;
    const fn = vi.fn(), direct = vi.fn();
    vi.spyOn(f.clusters, 'update').mockImplementation(async (...args) => {
      escaped = (async () => {
        await release.promise;
        return f.bridges[0].execute({ resource: 'clusters', operation: 'update', clusterId: cid, resourceId: cid, module: 'clusters', action: 'write', workspaceId: null, actor, payload: args[1] }, fn, direct);
      })().then(result => ({ result }), error => ({ error }));
      return original(...args);
    });
    await f.transact(tx => f.service.apply(origin.handle, capture, actor, tx)); release.resolve();
    expect(await escaped).toMatchObject({ error: { response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } } });
    expect(f.writes).toHaveLength(1); expect(fn).not.toHaveBeenCalled(); expect(direct).not.toHaveBeenCalled(); expect(f.policy.verifyMutation).toHaveBeenCalledTimes(2);
  });

  for (const operation of ['transaction', 'allocate', 'completed', 'execute'] as const) {
    it(`closes an escaped original ALS ${operation} closure after capture completes`, async () => {
      const f = fixture(), original = f.clusters.update.bind(f.clusters), release = deferred<void>();
      let escaped!: Promise<any>;
      const fn = vi.fn(), direct = vi.fn();
      vi.spyOn(f.clusters, 'update').mockImplementation(async (...args) => {
        escaped = (async () => {
          await release.promise;
          if (operation === 'transaction') return f.bridges[0].currentTransaction();
          if (operation === 'allocate') return f.bridges[0].allocateId();
          if (operation === 'completed') return f.bridges[0].completed({ actor, module: 'clusters', action: 'write', cluster_id: null, workspace_id: null, payload: args[1] });
          return f.bridges[0].execute({ resource: 'clusters', operation: 'update', clusterId: cid, resourceId: cid, module: 'clusters', action: 'write', workspaceId: null, actor, payload: args[1] }, fn, direct);
        })().then(result => ({ result }), error => ({ error }));
        return original(...args);
      });
      await f.service.capture(cases[0], cid, actor, f.tx); release.resolve();
      expect(await escaped).toMatchObject({ error: { response: { code: 'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED' } } });
      expect(f.writes).toEqual([]); expect(fn).not.toHaveBeenCalled(); expect(direct).not.toHaveBeenCalled(); expect(f.operations.completed).not.toHaveBeenCalled();
    });
  }
});

function deferred<T>() {
  let resolve!: (value?: T) => void;
  const promise = new Promise<T>(accept => { resolve = value => accept(value as T); });
  return { promise, resolve };
}
