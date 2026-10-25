import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ClustersService } from '../../apps/console-api/src/modules/clusters/clusters.service';
import { DataSourcesService } from '../../apps/console-api/src/modules/data-sources/data-sources.service';
import { WorkspaceService } from '../../apps/console-api/src/modules/workspaces/workspace.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { executionFixture } from './execution-test-fixture';

// Domain/source tests only. SQL, IAM/Mutation ledgers, network transport and the
// private approval provider are fixture transports, never runtime evidence.
const outbound = vi.hoisted(() => ({ json: vi.fn() }));
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', async importOriginal => ({
  ...await importOriginal<typeof import('../../apps/console-api/src/infrastructure/kong/outbound')>(),
  outboundJson: outbound.json,
}));

const cid = '61000000-0000-4000-8000-000000000001';
const wid = '61000000-0000-4000-8000-000000000002';
const defaultId = '61000000-0000-4000-8000-000000000003';
const sourceId = '61000000-0000-4000-8000-000000000004';
const allocatedId = '61000000-0000-4000-8000-000000000005';
const userId = '61000000-0000-4000-8000-000000000006';
const actor = { user: { id: userId, username: 'operator', superAdmin: true }, idempotencyKey: 'control-source-key', requestId: 'control-source-request', ip: '192.0.2.6' };
type Call = { owner: 'outer' | 'tx'; method: 'one' | 'query' | 'exec'; sql: string; params: any[] };
type BridgeMode = 'capture' | 'approved' | 'direct';

function harness() {
  const initialWorkspace = { id: wid, cluster_id: cid, code: 'pay', name: 'Payments', owner_user_id: userId, description: 'preserved-description', status: 'active', is_default: false, revision: 1, deleted_at: null, retention_until: null, created_at: '2026-10-14T00:00:00Z', updated_at: '2026-10-14T00:00:00Z' };
  const state = {
    cluster: { id: cid, name: 'Production', environment: 'prod', admin_url: 'http://192.0.2.11:8001', proxy_origin: null, labels: ['prod'], execution_mode: 'direct', status: 'healthy', version: '1.5.1', capabilities: {}, enabled_plugins: ['key-auth'], revision: 1, deleted_at: null, connection_secret: null, connection_configured: false },
    source: { id: sourceId, cluster_id: cid, name: 'Metrics', type: 'prometheus', base_url: 'http://192.0.2.12:9090', enabled: true, last_status: 'unknown', last_probed_at: null, revision: 1, deleted_at: null, auth_secret: null, auth_configured: false },
    workspaces: [initialWorkspace, { ...initialWorkspace, id: defaultId, code: 'default', name: '默认工作区', owner_user_id: null, description: '', is_default: true }],
    duplicateCluster: false, duplicateSource: false, ownerAvailable: true,
  };
  const calls: Call[] = [];
  const copy = <T>(value: T): T => structuredClone(value);
  const assignment = (row: Record<string, any>, sql: string, params: any[]) => {
    for (const match of sql.matchAll(/(?:SET\s+|,)\s*([a-z_]+)\s*=\s*\$(\d+)/gi)) row[match[1]] = copy(params[Number(match[2]) - 1]);
    if (sql.includes('revision=revision+1')) row.revision++;
  };
  let tx: any;
  const transport = (owner: 'outer' | 'tx'): any => ({
    one: vi.fn(async (sql: string, params: any[] = []) => {
      calls.push({ owner, method: 'one', sql, params: copy(params) });
      if (sql.includes('FROM iam_epoch')) return { version: 1 };
      if (sql.includes('FROM users')) return state.ownerAvailable && params[0] === userId ? { id: userId } : null;
      if (sql.includes('FROM clusters')) {
        if (sql.includes('environment=$1')) return state.duplicateCluster ? { id: cid } : null;
        if (sql.startsWith('SELECT connection_secret')) return { connection_secret: state.cluster.connection_secret };
        return params[0] === state.cluster.id && !state.cluster.deleted_at ? copy(state.cluster) : null;
      }
      if (sql.includes('FROM data_sources')) {
        if (sql.includes('lower(name)')) return state.duplicateSource ? { id: sourceId } : null;
        if (params[0] !== cid || params[1] !== state.source.id || state.source.deleted_at) return null;
        return sql.includes('SELECT auth_secret') ? { auth_secret: state.source.auth_secret } : copy(state.source);
      }
      if (sql.startsWith('SELECT') && sql.includes('FROM workspaces')) {
        const row = state.workspaces.find(row => row.cluster_id === params[0] && (sql.includes("code='default'") ? row.is_default : row.id === params[1]));
        return row ? copy(row) : null;
      }
      if (sql.startsWith('INSERT INTO workspaces') && !sql.includes('SELECT id')) {
        const columns = sql.match(/workspaces\(([^)]+)\)/)?.[1].split(',').map(x => x.trim()) ?? [];
        const row: any = { ...copy(initialWorkspace), id: allocatedId, owner_user_id: null, description: '' };
        columns.forEach((name, index) => { row[name] = copy(params[index]); });
        if (state.workspaces.some(existing => existing.code === row.code)) return null;
        state.workspaces.push(row); return copy(row);
      }
      if (sql.startsWith('UPDATE workspaces')) {
        const row = state.workspaces.find(row => row.cluster_id === params[0] && row.id === params[1]);
        if (!row) return null;
        const revision = sql.includes('SET name=') ? params[6] : params[2];
        if (row.revision !== revision) return null;
        if (sql.includes("SET status='deleted'")) Object.assign(row, { status: 'deleted', deleted_at: '2026-10-14T00:01:00Z', retention_until: '2026-11-13T00:01:00Z' });
        else if (sql.includes("SET status='active'")) Object.assign(row, { status: 'active', deleted_at: null, retention_until: null });
        else assignment(row, sql, params);
        if (!sql.includes('SET name=')) row.revision++;
        return copy(row);
      }
      throw new Error(`Unexpected fixture one: ${sql}`);
    }),
    query: vi.fn(async (sql: string, params: any[] = []) => {
      calls.push({ owner, method: 'query', sql, params: copy(params) });
      if (sql.includes('FROM clusters')) return [];
      if (sql.includes('FROM workspaces')) return copy(state.workspaces);
      return [];
    }),
    exec: vi.fn(async (sql: string, params: any[] = []) => {
      calls.push({ owner, method: 'exec', sql, params: copy(params) });
      if (sql.startsWith('INSERT INTO clusters')) {
        const columns = sql.match(/clusters\(([^)]+)\)/)?.[1].split(',').map(x => x.trim()) ?? [];
        columns.forEach((name, index) => { (state.cluster as any)[name] = copy(params[index]); }); return 1;
      }
      if (sql.startsWith('INSERT INTO data_sources')) {
        const columns = sql.match(/data_sources\(([^)]+)\)/)?.[1].split(',').map(x => x.trim()) ?? [];
        columns.forEach((name, index) => { (state.source as any)[name] = copy(params[index]); }); return 1;
      }
      if (sql.startsWith('UPDATE data_sources')) {
        if (params[0] !== cid || params[1] !== state.source.id || state.source.deleted_at) return 0;
        if (sql.includes('enabled=true') && !state.source.enabled) return 0;
        const isConfig = sql.includes('revision=revision+1');
        if (isConfig && state.source.revision !== params[2]) return 0;
        assignment(state.source, sql, params);
        if (sql.includes('deleted_at=now()')) Object.assign(state.source, { deleted_at: '2026-10-14T00:01:00Z', enabled: false, last_status: 'disabled' });
        if (sql.includes('last_probed_at=now()')) state.source.last_probed_at = '2026-10-14T00:01:00Z' as any;
        return 1;
      }
      if (sql.startsWith('UPDATE clusters')) {
        if (state.cluster.revision !== params[1]) return 0;
        assignment(state.cluster, sql, params);
        if (sql.includes('deleted_at=now()')) Object.assign(state.cluster, { deleted_at: '2026-10-14T00:01:00Z', status: 'disabled' });
      }
      return 1;
    }),
    transaction: vi.fn(async () => { throw new Error('Unexpected nested transaction'); }),
  });
  tx = transport('tx'); const db = transport('outer');
  db.transaction.mockImplementation(async (fn: any) => {
    const before = copy(state);
    try { return await fn(tx); } catch (error) { Object.assign(state, before); throw error; }
  });
  const authz = {
    assertConsole: vi.fn().mockResolvedValue(undefined), assertCluster: vi.fn().mockResolvedValue(undefined), assertEntity: vi.fn().mockResolvedValue(undefined),
    snapshot: vi.fn().mockResolvedValue({ user: { superAdmin: true }, grants: [] }),
    isPlatformAdmin: vi.fn().mockResolvedValue(true), permissionVersion: vi.fn().mockResolvedValue('epoch-1'),
    filterEntities: vi.fn(async (_actor: any, _cid: any, _module: any, rows: any[]) => rows),
  };
  const audit = { append: vi.fn().mockResolvedValue(undefined) };
  const operations = { execute: vi.fn(async (_mutation: any, fn: any) => db.transaction(fn)), completed: vi.fn().mockResolvedValue(null) };
  const mutations = { execute: vi.fn(async (_mutation: any, fn: any) => fn()) };
  const execution = executionFixture(); execution.runActor = vi.fn(execution.runActor); execution.runInternalRead = vi.fn(execution.runInternalRead);
  const inspection = Object.freeze({ sourceInspection: true });
  const kong = { invalidate: vi.fn(), list: vi.fn().mockResolvedValue({ items: [], nextCursor: null, size: 1 }), inspectProbe: vi.fn().mockResolvedValue(inspection), persistProbe: vi.fn(async (_cid: any, value: any, _actor: any, transaction: any) => { expect(value).toBe(inspection); await audit.append({ action: 'cluster.probe' }, transaction); return { clusterId: cid, version: '1.5.1' }; }) };
  const secrets = new SecretService();
  const clusters = new ClustersService(db, secrets, kong as any, audit as any, authz as any, operations as any, execution);
  const sources = new DataSourcesService(db, secrets, clusters, audit as any, authz as any, operations as any);
  const resolver = new WorkspaceResolverService(db);
  const workspaces = new WorkspaceService(db, resolver, authz as any, mutations as any, audit as any, kong as any, execution);
  const businessWrites = () => calls.filter(call => /^\s*(?:INSERT|UPDATE|DELETE)\s+(?:INTO\s+)?(?:clusters|data_sources|data_source_probes|workspaces)\b/i.test(call.sql));
  return { state, calls, tx, db, authz, audit, operations, mutations, kong, execution, inspection, secrets, clusters, sources, resolver, workspaces, businessWrites };
}

function bridge(f: ReturnType<typeof harness>, mode: BridgeMode) {
  const mutations: any[] = [];
  const fixed = {
    currentTransaction: vi.fn(() => mode === 'direct' ? undefined : f.tx),
    allocateId: vi.fn(() => allocatedId),
    completed: vi.fn().mockResolvedValue(null),
    execute: vi.fn(async (mutation: any, fn: any, direct: any) => {
      mutations.push(structuredClone(mutation));
      return mode === 'capture' ? { prepared: true } : mode === 'approved' ? fn(f.tx) : direct();
    }),
  };
  return { fixed, mutations };
}

describe('M11 control metadata: original business services under fixed capture and execution', () => {
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '63'.repeat(32));
    vi.stubEnv('APP_SECRET', 'control-metadata-source-signing-key-more-than-32-bytes');
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', '192.0.2.11,192.0.2.12,192.0.2.13');
    outbound.json.mockResolvedValue({ status: 200, body: { status: 'success', data: { resultType: 'vector', result: [] } } });
  });
  afterEach(() => vi.unstubAllEnvs());

  for (const resource of ['clusters', 'sources', 'workspaces'] as const) {
    it(`${resource} installs one fixed complete bridge and rejects replacing it`, () => {
      const f = harness(), b = bridge(f, 'capture'), service = f[resource];
      expect(() => service.installControlMetadataBridge({ ...b.fixed, allocateId: undefined } as any)).toThrow('fixed business bridge');
      service.installControlMetadataBridge(b.fixed);
      expect(() => service.installControlMetadataBridge(b.fixed)).toThrow('fixed business bridge');
    });
  }

  it('captures an existing approval cluster update using its exact old row transaction and normalized typed mutation without SQL writes', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.state.cluster.execution_mode = 'approval';
    f.clusters.installControlMetadataBridge(b.fixed);
    expect(await f.clusters.update(cid, { revision: 1, name: '  New production  ', execution_mode: 'direct' }, actor)).toEqual({ prepared: true });
    expect(b.mutations).toEqual([{ resource: 'clusters', operation: 'update', clusterId: cid, resourceId: cid, module: 'clusters', action: 'write', workspaceId: null, actor, payload: { revision: 1, name: 'New production', execution_mode: 'direct' } }]);
    expect(f.calls.length).toBeGreaterThan(0); expect(f.calls.every(call => call.owner === 'tx')).toBe(true);
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
    expect(f.state.cluster).toMatchObject({ name: 'Production', execution_mode: 'approval', revision: 1 });
  });

  it('captures exact cluster deactivation confirmation and routes completed receipt checks through the fixed provider', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.clusters.installControlMetadataBridge(b.fixed);
    const input = { revision: 1, confirm: true, confirm_name: 'Production' };
    await f.clusters.deactivate(cid, input, actor);
    expect(b.mutations[0]).toMatchObject({ resource: 'clusters', operation: 'deactivate', action: 'delete', clusterId: cid, resourceId: cid, payload: input });
    expect(b.fixed.completed).toHaveBeenCalledWith(expect.objectContaining({ module: 'clusters', targetId: cid, payload: input }));
    expect(f.operations.completed).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]); expect(f.state.cluster.deleted_at).toBeNull();
  });

  it('approved cluster mode transition invokes only the original business SQL on the exact transaction and audits it there', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.state.cluster.execution_mode = 'approval'; f.clusters.installControlMetadataBridge(b.fixed);
    expect(await f.clusters.update(cid, { revision: 1, execution_mode: 'direct' }, actor)).toMatchObject({ id: cid, execution_mode: 'direct', revision: 2 });
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.tx.transaction).not.toHaveBeenCalled();
    expect(f.calls.every(call => call.owner === 'tx')).toBe(true);
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'update', clusterId: cid, before: expect.objectContaining({ execution_mode: 'approval' }), after: expect.objectContaining({ execution_mode: 'direct' }) }), f.tx);
    expect(f.kong.invalidate).toHaveBeenCalledWith(cid);
  });

  it('approved connection replacement preserves secret encryption and resets only original capability observations', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.clusters.installControlMetadataBridge(b.fixed);
    const input = { revision: 1, admin_url: 'http://192.0.2.13:8001/', connection_auth: { type: 'bearer', token: 'Synthetic-control-token' } };
    const result = await f.clusters.update(cid, input, actor);
    expect(result).toMatchObject({ admin_url: 'http://192.0.2.13:8001', status: 'unknown', version: null, enabled_plugins: [], revision: 2 });
    expect(f.secrets.decrypt(f.state.cluster.connection_secret!, `cluster:${cid}`)).toEqual(input.connection_auth);
    expect(f.state.cluster.connection_secret).not.toContain(input.connection_auth.token);
    expect(f.calls.filter(call => call.method === 'query').every(call => call.owner === 'tx')).toBe(true);
  });

  for (const input of [
    { revision: 1, execution_mode: 'direct' },
    { revision: 1, name: 'renamed' },
    { revision: 1, admin_url: 'http://192.0.2.13:8001' },
    { revision: 1, connection_auth: { type: 'bearer', token: 'Synthetic-new-token' } },
  ]) {
    it(`without a bridge rejects approval-cluster ${Object.keys(input)[1]} update before the original null-scope ledger`, async () => {
      const f = harness(); f.state.cluster.execution_mode = 'approval';
      await expect(f.clusters.update(cid, input, actor)).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
      expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
    });
  }

  it('without a bridge rejects approval-cluster deactivation before ledger and soft deletion', async () => {
    const f = harness(); f.state.cluster.execution_mode = 'approval';
    await expect(f.clusters.deactivate(cid, { revision: 1, confirm: true, confirm_name: 'Production' }, actor)).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]); expect(f.state.cluster.deleted_at).toBeNull();
  });

  it('without a bridge rechecks the actual old mode with a same-transaction row lock before updating', async () => {
    const f = harness(); f.operations.execute.mockImplementation(async (_context: any, fn: any) => { f.state.cluster.execution_mode = 'approval'; return f.db.transaction(fn); });
    await expect(f.clusters.update(cid, { revision: 1, name: 'stale-mode' }, actor)).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.calls).toContainEqual(expect.objectContaining({ owner: 'tx', sql: expect.stringMatching(/SELECT execution_mode,status FROM clusters.*FOR SHARE/), params: [cid] }));
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('without a bridge permits direct-to-approval transition using the old direct mode and original request tuple', async () => {
    const f = harness();
    expect(await f.clusters.update(cid, { revision: 1, execution_mode: 'approval' }, actor)).toMatchObject({ execution_mode: 'approval', revision: 2 });
    expect(f.operations.execute).toHaveBeenCalledWith(expect.objectContaining({ module: 'clusters', action: 'write', targetId: cid, cluster_id: null, workspace_id: null, payload: { revision: 1, execution_mode: 'approval' } }), expect.any(Function));
    expect(f.calls).toContainEqual(expect.objectContaining({ owner: 'tx', sql: expect.stringContaining('FOR SHARE'), params: [cid] }));
  });

  it('a completed direct-to-approval change remains readable under its original key without executing a second business callback', async () => {
    const f = harness(), input = { revision: 1, execution_mode: 'approval' };
    const result = await f.clusters.update(cid, input, actor);
    f.operations.completed.mockResolvedValueOnce({ result });
    const writes = f.businessWrites().length;
    expect(await f.clusters.update(cid, input, actor)).toEqual(result);
    expect(f.operations.execute).toHaveBeenCalledTimes(1); expect(f.businessWrites()).toHaveLength(writes);
    expect(f.operations.completed.mock.calls.at(-1)?.[0]).toEqual({ actor, module: 'clusters', action: 'write', targetId: cid, cluster_id: null, workspace_id: null, payload: input });
    expect(f.state.cluster).toMatchObject({ revision: 2, execution_mode: 'approval' });
  });

  it('new registration stays original authorized console-direct and is not turned into a fake existing-cluster approval', async () => {
    const f = harness(), b = bridge(f, 'direct'); f.clusters.installControlMetadataBridge(b.fixed);
    const result = await f.clusters.create({ name: 'New cluster', admin_url: 'http://192.0.2.13:8001', execution_mode: 'approval' }, actor);
    expect(result).toMatchObject({ name: 'New cluster', execution_mode: 'approval' });
    expect(b.fixed.execute).not.toHaveBeenCalled(); expect(f.operations.execute).toHaveBeenCalledWith(expect.objectContaining({ cluster_id: null, workspace_id: null, payload: expect.objectContaining({ environment: 'default', labels: [] }) }), expect.any(Function));
    expect(f.authz.assertConsole).toHaveBeenCalledWith(actor.user, 'clusters', 'write');
  });

  it('captures new data source defaults with a fixed ID on the original transaction without invoking the SQL callback', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.sources.installControlMetadataBridge(b.fixed);
    expect(await f.sources.create(cid, { name: '  New metrics  ', type: 'prometheus', base_url: 'http://192.0.2.12:9090' }, actor)).toEqual({ prepared: true });
    expect(b.mutations[0]).toMatchObject({ resource: 'data-sources', operation: 'create', clusterId: cid, resourceId: allocatedId, workspaceId: null, module: 'data-sources', action: 'write', payload: { name: 'New metrics', type: 'prometheus', base_url: 'http://192.0.2.12:9090', enabled: true } });
    expect(b.fixed.allocateId).toHaveBeenCalledTimes(1); expect(f.calls.every(call => call.owner === 'tx')).toBe(true);
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.operations.execute).not.toHaveBeenCalled();
  });

  it('approved data source creation uses its fixed ID for SQL and encrypted authentication context', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.sources.installControlMetadataBridge(b.fixed);
    const auth = { type: 'basic', username: 'metrics-user', password: 'Synthetic-metrics-password' };
    const result = await f.sources.create(cid, { name: 'New metrics', type: 'prometheus', base_url: 'http://192.0.2.12:9090/', auth }, actor);
    expect(result).toMatchObject({ id: allocatedId, cluster_id: cid, name: 'New metrics', base_url: 'http://192.0.2.12:9090' });
    expect(f.secrets.decrypt(f.state.source.auth_secret!, `data-source:${cid}:${allocatedId}`)).toEqual(auth);
    expect(f.state.source.auth_secret).not.toContain(auth.password); expect(f.businessWrites()[0]).toMatchObject({ owner: 'tx', params: expect.arrayContaining([allocatedId]) });
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'create', entityId: allocatedId }), f.tx);
  });

  it('approved data source updates and deactivation retain original revision, audit and soft-delete semantics', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.sources.installControlMetadataBridge(b.fixed);
    expect(await f.sources.update(cid, sourceId, { revision: 1, name: 'Updated metrics' }, actor)).toMatchObject({ name: 'Updated metrics', revision: 2 });
    expect(await f.sources.deactivate(cid, sourceId, { revision: 2, confirm: true, confirm_name: 'Updated metrics' }, actor)).toEqual({ id: sourceId, deactivated: true });
    expect(f.state.source).toMatchObject({ deleted_at: expect.any(String), enabled: false, last_status: 'disabled', revision: 3 });
    expect(f.calls.every(call => call.owner === 'tx')).toBe(true); expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.operations.completed).not.toHaveBeenCalled();
    expect(f.businessWrites().every(call => !call.sql.startsWith('DELETE'))).toBe(true); expect(f.audit.append.mock.calls.every(([, transaction]) => transaction === f.tx)).toBe(true);
  });

  it('captures both data source update and deactivation without writing or using the direct ledger', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.sources.installControlMetadataBridge(b.fixed);
    await f.sources.update(cid, sourceId, { revision: 1, enabled: false }, actor);
    await f.sources.deactivate(cid, sourceId, { revision: 1, confirm: true, confirm_name: 'Metrics' }, actor);
    expect(b.mutations.map(mutation => mutation.operation)).toEqual(['update', 'deactivate']); expect(b.mutations.map(mutation => mutation.action)).toEqual(['write', 'delete']);
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.calls.every(call => call.owner === 'tx')).toBe(true);
  });

  it('captures workspace creation without ensureDefault INSERT and seals the fixed new workspace ID', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.workspaces.installControlMetadataBridge(b.fixed);
    const input = { code: 'ops', name: 'Operations', owner_user_id: userId };
    expect(await f.workspaces.create(cid, input, actor)).toEqual({ prepared: true });
    expect(b.mutations[0]).toMatchObject({ resource: 'workspaces', operation: 'create', clusterId: cid, resourceId: allocatedId, workspaceId: defaultId, module: 'workspaces', action: 'write', payload: input });
    expect(b.fixed.allocateId).toHaveBeenCalledTimes(1); expect(f.businessWrites()).toEqual([]); expect(f.calls.every(call => call.owner === 'tx')).toBe(true); expect(f.mutations.execute).not.toHaveBeenCalled();
  });

  it('approved workspace creation writes the exact allocated ID and preserves original owner validation and audit transaction', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.workspaces.installControlMetadataBridge(b.fixed);
    const result = await f.workspaces.create(cid, { code: 'ops', name: ' Operations ', owner_user_id: userId }, actor);
    expect(result).toMatchObject({ id: allocatedId, code: 'ops', name: 'Operations', owner_user_id: userId });
    expect(f.businessWrites()).toHaveLength(1); expect(f.businessWrites()[0]).toMatchObject({ owner: 'tx', params: [cid, 'ops', 'Operations', userId, '', allocatedId] });
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'workspace.metadata.created', workspaceId: allocatedId }), f.tx);
    expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.tx.transaction).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
  });

  it('fixed workspace preflight uses real resolver.get on the original transaction and captures update without writes', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.workspaces.installControlMetadataBridge(b.fixed);
    const get = vi.spyOn(f.resolver, 'get');
    expect(await f.workspaces.update(cid, wid, { revision: 1, description: 'proposed' }, actor)).toEqual({ prepared: true });
    expect(get).toHaveBeenCalledWith(cid, wid, false, f.tx);
    expect(b.mutations[0]).toMatchObject({ resource: 'workspaces', operation: 'update', clusterId: cid, resourceId: wid, workspaceId: wid, payload: { revision: 1, description: 'proposed' } });
    expect(f.calls.every(call => call.owner === 'tx')).toBe(true); expect(f.businessWrites()).toEqual([]); expect(f.state.workspaces[0].description).toBe('preserved-description');
  });

  it('approved workspace update retains same-transaction CAS and owner metadata without a nested original mutation', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.workspaces.installControlMetadataBridge(b.fixed);
    expect(await f.workspaces.update(cid, wid, { revision: 1, name: 'New payments', description: 'new description' }, actor)).toMatchObject({ id: wid, name: 'New payments', revision: 2 });
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'workspace.metadata.updated', before: expect.objectContaining({ revision: 1, description: 'preserved-description' }) }), f.tx);
    expect(f.calls.every(call => call.owner === 'tx')).toBe(true); expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
  });

  it('approved workspace soft-deletion keeps the private bounded native emptiness check, then restores original ID and description', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.workspaces.installControlMetadataBridge(b.fixed);
    expect(await f.workspaces.remove(cid, wid, { revision: 1, confirmed: true, confirm_name: 'Payments' }, actor)).toMatchObject({ state: 'deleted', workspace: { id: wid, status: 'deleted', revision: 2, description: 'preserved-description' } });
    expect(f.kong.list).toHaveBeenCalledTimes(8); expect(f.kong.list.mock.calls.every((args: any[]) => args[2].size === 1 && args[2].tags === 'kos-ws-pay')).toBe(true);
    expect(f.execution.runInternalRead).toHaveBeenCalledWith(cid, 'workspace-empty', expect.any(Function), expect.objectContaining({ workspaceId: wid, maxCalls: 8, maxPages: 8, maxRecords: 8 }));
    expect(await f.workspaces.restore(cid, wid, { revision: 2, confirmed: true, confirm_name: 'Payments' }, actor)).toMatchObject({ id: wid, status: 'active', revision: 3, description: 'preserved-description', deleted_at: null });
    expect(f.businessWrites().every(call => call.owner === 'tx' && !call.sql.startsWith('DELETE'))).toBe(true); expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
    expect(f.audit.append.mock.calls.every(([, transaction]) => transaction === f.tx)).toBe(true);
  });

  it('capture workspace deletion never calls native emptiness traversal or SQL mutations', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.workspaces.installControlMetadataBridge(b.fixed);
    await f.workspaces.remove(cid, wid, { revision: 1, confirmed: true, confirm_name: 'Payments' }, actor);
    expect(b.mutations[0]).toMatchObject({ resource: 'workspaces', operation: 'archive', action: 'delete' });
    expect(f.kong.list).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('capture workspace recovery uses includeDeleted on the exact transaction and never writes', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.state.workspaces[0].status = 'deleted'; f.workspaces.installControlMetadataBridge(b.fixed);
    const get = vi.spyOn(f.resolver, 'get');
    await f.workspaces.restore(cid, wid, { revision: 1, confirmed: true, confirm_name: 'Payments' }, actor);
    expect(get).toHaveBeenCalledWith(cid, wid, true, f.tx); expect(b.mutations[0]).toMatchObject({ operation: 'restore', action: 'write' }); expect(f.businessWrites()).toEqual([]);
  });

  it('diagnostic cluster probe remains an authorized observation in approval mode and passes its exact inspection into original same-transaction persistence', async () => {
    const f = harness(); f.state.cluster.execution_mode = 'approval';
    expect(await f.clusters.probe(cid, actor)).toEqual({ clusterId: cid, version: '1.5.1' });
    expect(f.kong.inspectProbe).toHaveBeenCalledOnce(); expect(f.kong.persistProbe).toHaveBeenCalledWith(cid, f.inspection, { id: userId, requestId: actor.requestId, ip: actor.ip }, f.tx);
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.operations.completed).not.toHaveBeenCalled(); expect(f.audit.append).toHaveBeenCalledWith({ action: 'cluster.probe' }, f.tx);
    expect(f.authz.assertConsole).toHaveBeenCalledTimes(2); expect(f.execution.runActor).toHaveBeenCalledWith(expect.objectContaining({ clusterId: cid, module: 'clusters', action: 'write', actor: actor.user }), expect.any(Function));
  });

  it('cluster probe never persists an observation if current permissions are revoked after inspection', async () => {
    const f = harness(); f.authz.assertConsole.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new ForbiddenException({ code: 'IAM_SCOPE_DENIED' }));
    await expect(f.clusters.probe(cid, actor)).rejects.toMatchObject({ response: { code: 'IAM_SCOPE_DENIED' } });
    expect(f.kong.inspectProbe).toHaveBeenCalledOnce(); expect(f.kong.persistProbe).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('cluster probe refuses permission-version drift before original private persistence', async () => {
    const f = harness(); f.authz.permissionVersion.mockResolvedValueOnce('epoch-1').mockResolvedValueOnce('epoch-2');
    await expect(f.clusters.probe(cid, actor)).rejects.toMatchObject({ response: { code: 'PERMISSIONS_CHANGED' } });
    expect(f.kong.persistProbe).not.toHaveBeenCalled(); expect(f.operations.execute).not.toHaveBeenCalled();
  });

  it('Prometheus diagnostic probe uses only a fixture GET and atomically records status, history and audit without the original mutation kernel', async () => {
    const f = harness(); f.state.cluster.execution_mode = 'approval';
    const result = await f.sources.probe(cid, sourceId, actor);
    expect(result).toMatchObject({ id: sourceId, cluster_id: cid, status: 'healthy' });
    expect(outbound.json).toHaveBeenCalledWith('http://192.0.2.12:9090', '/api/v1/query', 'GET', undefined, { query: 'vector(1)' }, null);
    expect(f.operations.execute).not.toHaveBeenCalled(); expect(f.operations.completed).not.toHaveBeenCalled();
    expect(f.businessWrites()).toHaveLength(2); expect(f.businessWrites().every(call => call.owner === 'tx')).toBe(true);
    expect(f.businessWrites()[0]).toMatchObject({ sql: expect.stringContaining('revision=$4'), params: [cid, sourceId, 'healthy', 1] });
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'probe', result: 'success', after: { status: 'healthy' } }), f.tx);
  });

  it('Loki diagnostic probe calls readiness and label GETs and stores sanitized failure only when a provider response is invalid', async () => {
    const f = harness(); f.state.source.type = 'loki';
    outbound.json.mockResolvedValueOnce({ status: 200, body: null }).mockResolvedValueOnce({ status: 200, body: { status: 'success', data: ['app'] } });
    expect(await f.sources.probe(cid, sourceId, actor)).toMatchObject({ status: 'healthy' });
    expect(outbound.json.mock.calls.map(args => args.slice(1, 3))).toEqual([['/ready', 'GET'], ['/loki/api/v1/labels', 'GET']]);
    outbound.json.mockRejectedValueOnce(new Error('Synthetic-password-leak-risk'));
    const failed = await f.sources.probe(cid, sourceId, actor);
    expect(failed).toMatchObject({ status: 'unhealthy' }); expect(JSON.stringify(failed)).not.toContain('Synthetic-password-leak-risk');
    expect(f.audit.append.mock.calls.at(-1)?.[0]).toMatchObject({ result: 'failure' });
  });

  it('disabled data source probe refuses before outbound observation and has no durable side effects', async () => {
    const f = harness(); f.state.source.enabled = false;
    await expect(f.sources.probe(cid, sourceId, actor)).rejects.toMatchObject({ response: { code: 'DATA_SOURCE_DISABLED' } });
    expect(outbound.json).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('probe revision drift after its GET rolls back status/history and never records a successful observation', async () => {
    const f = harness(); outbound.json.mockImplementationOnce(async () => { f.state.source.revision = 2; return { status: 200, body: { status: 'success', data: { resultType: 'vector', result: [] } } }; });
    await expect(f.sources.probe(cid, sourceId, actor)).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.state.source.last_status).toBe('unknown');
  });

  for (const changed of [0, 2]) {
    it(`probe rejects an inexact ${changed}-row observation CAS and rolls back fixture status without history or audit`, async () => {
      const f = harness(), original = f.tx.exec.getMockImplementation();
      f.tx.exec.mockImplementation(async (sql: string, params: any[]) => {
        const result = await original(sql, params);
        return sql.startsWith('UPDATE data_sources') ? changed : result;
      });
      await expect(f.sources.probe(cid, sourceId, actor)).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
      expect(f.state.source.last_status).toBe('unknown'); expect(f.state.source.last_probed_at).toBeNull(); expect(f.audit.append).not.toHaveBeenCalled();
      expect(f.businessWrites().filter(call => call.sql.startsWith('INSERT INTO data_source_probes'))).toEqual([]);
    });
  }

  it('a source disabled during its GET cannot persist a stale healthy observation even if its revision is unchanged', async () => {
    const f = harness(); outbound.json.mockImplementationOnce(async () => { f.state.source.enabled = false; return { status: 200, body: { status: 'success', data: { resultType: 'vector', result: [] } } }; });
    await expect(f.sources.probe(cid, sourceId, actor)).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    expect(f.state.source.last_status).toBe('unknown'); expect(f.audit.append).not.toHaveBeenCalled();
    expect(f.businessWrites().filter(call => call.sql.startsWith('INSERT INTO data_source_probes'))).toEqual([]);
  });

  it('probe permission revocation after GET prevents any observation persistence', async () => {
    const f = harness(); f.authz.assertCluster.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new ForbiddenException({ code: 'IAM_SCOPE_DENIED' }));
    await expect(f.sources.probe(cid, sourceId, actor)).rejects.toMatchObject({ response: { code: 'IAM_SCOPE_DENIED' } });
    expect(outbound.json).toHaveBeenCalledOnce(); expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('data source probe rejects changed permission version after GET before writing observation metadata', async () => {
    const f = harness(); f.authz.permissionVersion.mockResolvedValueOnce('epoch-1').mockResolvedValueOnce('epoch-2');
    await expect(f.sources.probe(cid, sourceId, actor)).rejects.toMatchObject({ response: { code: 'PERMISSIONS_CHANGED' } });
    expect(outbound.json).toHaveBeenCalledOnce(); expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('original preflight rejects malformed/unknown cluster fields before entering capture', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.clusters.installControlMetadataBridge(b.fixed);
    await expect(f.clusters.update(cid, { revision: 1, expression: 'unsupported' }, actor)).rejects.toMatchObject({ response: { code: 'VALIDATION_ERROR' } });
    await expect(f.clusters.deactivate(cid, { revision: 1, confirm: true, confirm_name: 'wrong' }, actor)).rejects.toMatchObject({ response: { code: 'CONFIRMATION_MISMATCH' } });
    expect(b.fixed.execute).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]);
  });

  it('original approved cluster duplicate-name and stale revision rules still fail before SQL update', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.clusters.installControlMetadataBridge(b.fixed); f.state.duplicateCluster = true;
    await expect(f.clusters.update(cid, { revision: 1, name: 'duplicate' }, actor)).rejects.toMatchObject({ response: { code: 'CLUSTER_NAME_EXISTS' } });
    f.state.duplicateCluster = false;
    await expect(f.clusters.update(cid, { revision: 2, name: 'stale' }, actor)).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('original approved cluster callback rechecks the exact confirmation against concurrent rename', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.clusters.installControlMetadataBridge(b.fixed);
    b.fixed.execute.mockImplementationOnce(async (_mutation, fn) => { f.state.cluster.name = 'Renamed'; return fn(f.tx); });
    await expect(f.clusters.deactivate(cid, { revision: 1, confirm: true, confirm_name: 'Production' }, actor)).rejects.toMatchObject({ response: { code: 'CONFIRMATION_MISMATCH' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('original data source authorization, IDOR and malformed fields refuse before capture or any business write', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.sources.installControlMetadataBridge(b.fixed);
    await expect(f.sources.update(cid, allocatedId, { revision: 1, name: 'foreign' }, actor)).rejects.toMatchObject({ response: { code: 'DATA_SOURCE_NOT_FOUND' } });
    await expect(f.sources.create(cid, { name: 'x', type: 'vault', base_url: 'http://192.0.2.12:9090' }, actor)).rejects.toMatchObject({ response: { code: 'VALIDATION_ERROR' } });
    f.authz.assertCluster.mockRejectedValueOnce(new ForbiddenException({ code: 'IAM_SCOPE_DENIED' }));
    await expect(f.sources.update(cid, sourceId, { revision: 1, name: 'denied' }, actor)).rejects.toMatchObject({ response: { code: 'IAM_SCOPE_DENIED' } });
    expect(b.fixed.execute).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]);
  });

  it('original approved data source uniqueness, revision and confirmation rules still fail without SQL business writes', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.sources.installControlMetadataBridge(b.fixed); f.state.duplicateSource = true;
    await expect(f.sources.create(cid, { name: 'duplicate', type: 'prometheus', base_url: 'http://192.0.2.12:9090' }, actor)).rejects.toMatchObject({ response: { code: 'DATA_SOURCE_NAME_EXISTS' } });
    f.state.duplicateSource = false;
    await expect(f.sources.update(cid, sourceId, { revision: 2, name: 'stale' }, actor)).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    await expect(f.sources.deactivate(cid, sourceId, { revision: 1, confirm: true, confirm_name: 'wrong' }, actor)).rejects.toMatchObject({ response: { code: 'CONFIRMATION_MISMATCH' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('workspace default protection and malformed fields refuse before capture', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.workspaces.installControlMetadataBridge(b.fixed);
    await expect(f.workspaces.update(cid, defaultId, { revision: 1, status: 'disabled' }, actor)).rejects.toMatchObject({ response: { code: 'DEFAULT_WORKSPACE_PROTECTED' } });
    await expect(f.workspaces.remove(cid, defaultId, { revision: 1, confirmed: true, confirm_name: '默认工作区' }, actor)).rejects.toMatchObject({ response: { code: 'DEFAULT_WORKSPACE_PROTECTED' } });
    await expect(f.workspaces.create(cid, { code: 'default', name: 'reserved' }, actor)).rejects.toMatchObject({ response: { code: 'INVALID_WORKSPACE_CODE' } });
    await expect(f.workspaces.update(cid, wid, { revision: 1, unsupported: true } as any, actor)).rejects.toMatchObject({ response: { code: 'INVALID_WORKSPACE_FIELD' } });
    expect(b.fixed.execute).not.toHaveBeenCalled(); expect(f.businessWrites()).toEqual([]);
  });

  it('fixed workspace creation refuses a missing real default without attempting to manufacture a default during capture', async () => {
    const f = harness(), b = bridge(f, 'capture'); f.workspaces.installControlMetadataBridge(b.fixed); f.state.workspaces.splice(1, 1);
    await expect(f.workspaces.create(cid, { code: 'ops', name: 'Operations' }, actor)).rejects.toMatchObject({ response: { code: 'CONTROL_DEFAULT_WORKSPACE_REQUIRED' } });
    expect(f.businessWrites()).toEqual([]); expect(b.fixed.execute).not.toHaveBeenCalled();
  });

  it('approved workspace stale revision and unavailable owner refuse before SQL update or insert', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.workspaces.installControlMetadataBridge(b.fixed);
    await expect(f.workspaces.update(cid, wid, { revision: 2, description: 'stale' }, actor)).rejects.toMatchObject({ response: { code: 'WORKSPACE_REVISION_CONFLICT' } });
    f.state.ownerAvailable = false;
    await expect(f.workspaces.create(cid, { code: 'ops', name: 'Operations', owner_user_id: userId }, actor)).rejects.toMatchObject({ response: { code: 'WORKSPACE_OWNER_UNAVAILABLE' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('approved workspace deletion refuses a hidden native object without trusting a filtered caller page', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.workspaces.installControlMetadataBridge(b.fixed);
    f.kong.list.mockResolvedValueOnce({ items: [{ id: 'hidden', tags: ['kos-ws-pay', 'team:foreign'] }], nextCursor: null, size: 1 } as any);
    await expect(f.workspaces.remove(cid, wid, { revision: 1, confirmed: true, confirm_name: 'Payments' }, actor)).rejects.toMatchObject({ response: { code: 'WORKSPACE_NOT_EMPTY' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.kong.list).toHaveBeenCalledOnce();
  });

  it('approved workspace deletion and recovery callback still recheck exact confirmation', async () => {
    const f = harness(), b = bridge(f, 'approved'); f.workspaces.installControlMetadataBridge(b.fixed);
    b.fixed.execute.mockImplementationOnce(async (_mutation, fn) => { f.state.workspaces[0].name = 'Renamed'; return fn(f.tx); });
    await expect(f.workspaces.remove(cid, wid, { revision: 1, confirmed: true, confirm_name: 'Payments' }, actor)).rejects.toMatchObject({ response: { code: 'CONFIRMATION_REQUIRED' } });
    f.state.workspaces[0].status = 'deleted';
    b.fixed.execute.mockImplementationOnce(async (_mutation, fn) => { f.state.workspaces[0].name = 'Renamed again'; return fn(f.tx); });
    await expect(f.workspaces.restore(cid, wid, { revision: 1, confirmed: true, confirm_name: 'Renamed' }, actor)).rejects.toMatchObject({ response: { code: 'CONFIRMATION_REQUIRED' } });
    expect(f.businessWrites()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
  });
});
