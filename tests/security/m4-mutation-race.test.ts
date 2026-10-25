import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ServiceUnavailableException } from '@nestjs/common';
import { MutationService, type MutationContext } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { executionFixture } from '../unit/execution-test-fixture';
import { workspaceFixture, payWorkspaceId } from '../unit/workspace-test-fixture';

// Explicit integration mocks: real MutationService/impact/encryption code,
// in-memory durable rows and a queued physical-endpoint lock, no network faults.
const cid = 'd533edb4-8b45-421f-9bfc-3f095381e762';
const alias = 'ae9a1c70-b960-491c-875a-6a9d8dce0621';
const secondary = 'c089d140-2a31-422c-8337-e5e27607b718';
const alice = { id: '35a0f472-ef45-4af5-9bf6-a93d2a0fe5e3', username: 'alice', superAdmin: false };
const bob = { ...alice, id: 'b806bdf9-d24c-4568-8239-9b3bda1289ad', username: 'bob' };
const physical = 'a'.repeat(64), differentPhysical = 'b'.repeat(64);
function gate() { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { resolve, promise }; }
function fixture() {
  const operations = new Map<string, any>(), rowsByCluster = new Map<string, any>();
  const secrets = new SecretService();
  const workspaces = new Map([cid, alias, secondary].map(id => [id, workspaceFixture(id).resolver]));
  const resolver: any = Object.create(workspaces.get(cid)!);
  for (const name of ['resolve', 'get', 'listScope', 'classify']) resolver[name] = (...args: any[]) => (workspaces.get(args[0]) as any)[name](...args);
  const db: any = {
    query: vi.fn(async (_: string, p: any[]) => [...operations.values()].filter(row => ['running', 'uncertain'].includes(row.state) && row.id !== p[1] && (row.transport_scope === p[0] || row.transport_scope == null))),
    one: vi.fn(async (sql: string, p: any[]) => {
      if (sql.includes('FROM clusters')) return { id: p[0], version: '1.5.1', execution_mode: 'direct' };
      if (sql.includes('FROM recycle_entries')) return null;
      if (sql.includes('FROM mutation_operations')) return [...operations.values()].find(row => row.cluster_id === p[0] && (row.idempotency_key === p[1] || row.id === p[1])) ?? operations.get(p[0]) ?? null;
      return null;
    }),
    exec: vi.fn(async (sql: string, p: any[]) => {
      if (sql.startsWith('INSERT INTO mutation_operations')) {
        const [id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret, workspace_id, transport_scope, impact, parent_id, credential_kind] = p;
        operations.set(id, { id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret, workspace_id, transport_scope, impact: JSON.parse(impact), parent_id, credential_kind, state: 'running' }); return 1;
      }
      const row = operations.get(p[0]); if (!row) return 0;
      if (sql.includes('remote_started=true')) row.remote_started = true;
      else if (sql.includes('remote_completed=true')) Object.assign(row, { remote_completed: true, entity_id: p[1], result_secret: p[2] });
      else if (sql.includes("state='succeeded'")) Object.assign(row, { state: 'succeeded', safe_result: JSON.parse(p[1]) });
      else if (sql.includes('SET state=$2')) Object.assign(row, { state: p[1], error_code: p[2] });
      return 1;
    }),
    transaction: vi.fn(),
  };
  db.transaction.mockImplementation(async (fn: any) => fn(db));
  const tails = new Map<string, Promise<void>>();
  const redis: any = { assertLeaseOwnership: vi.fn(async () => undefined), withLock: vi.fn(async (key: string, fn: () => Promise<unknown>) => {
    const previous = tails.get(key) ?? Promise.resolve(), release = gate();
    tails.set(key, previous.then(() => release.promise));
    await previous;
    try { return await fn(); } finally { release.resolve(); }
  }) };
  const authz: any = { assertCluster: vi.fn(async () => undefined), assertEntity: vi.fn(async () => undefined), isPlatformAdmin: vi.fn(async () => false) };
  const kong: any = { transportScope: vi.fn(async (id: string) => id === secondary ? differentPhysical : physical), request: vi.fn(async (id: string, _method: string, path: string) => rowsByCluster.get(`${id}:${path}`) ?? { id: path.split('/').pop(), name: 'shared-name', host: 'example.test', tags: ['kos-ws-pay'] }) };
  const audit: any = { append: vi.fn(async () => undefined) };
  const createService = () => new MutationService(db, redis, secrets, audit, kong, authz, resolver, executionFixture());
  const context: MutationContext = { clusterId: cid, workspaceId: payWorkspaceId, actor: alice, entityType: 'services', action: 'create', idempotencyKey: 'original-key', payload: { name: 'shared-name', host: 'example.test', tags: ['kos-ws-pay'] } };
  return { operations, createService, context, redis, rowsByCluster, secrets };
}
beforeEach(() => { vi.stubEnv('APP_SECRET', 'm4-independent-impact-key-private-minimum-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cd'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());
const responseLost = () => new ServiceUnavailableException({ code: 'KONG_WRITE_RESULT_UNKNOWN', message: 'simulated applied write with lost response' });

describe('M4 independent durable unknown-write race protection', () => {
  it('serializes a second actor/alias before checking an applied-but-unknown first write', async () => {
    const f = fixture(), service = f.createService(), entered = gate(), release = gate();
    const nativeWrites: string[] = [];
    const first = service.execute({ ...f.context }, async () => {
      nativeWrites.push('first-actor-native-create'); entered.resolve(); await release.promise; throw responseLost();
    });
    const firstRejected = expect(first).rejects.toMatchObject({ response: { code: 'KONG_WRITE_RESULT_UNKNOWN' } });
    await entered.promise;
    const secondWrite = vi.fn(async () => ({ id: 'duplicate-create' }));
    const second = service.execute({ ...f.context, actor: bob, clusterId: alias, idempotencyKey: 'new-key-after-response-loss' }, secondWrite);
    const secondRejected = expect(second).rejects.toMatchObject({ response: { code: 'MUTATION_RECONCILIATION_REQUIRED' } });
    await Promise.resolve();
    expect(secondWrite).not.toHaveBeenCalled(); release.resolve();
    await Promise.all([firstRejected, secondRejected]);
    expect(nativeWrites).toEqual(['first-actor-native-create']);
    expect(secondWrite).not.toHaveBeenCalled();
    expect([...f.operations.values()]).toHaveLength(1);
    expect([...f.operations.values()][0].state).toBe('uncertain');
    expect(f.redis.withLock.mock.calls.map(call => call[0])).toEqual([`mutation:${physical}`, `mutation:${physical}`]);
    try { await service.execute({ ...f.context, actor: bob, clusterId: alias, idempotencyKey: 'third-key' }, secondWrite); }
    catch (error: any) { expect(error.getResponse()).not.toHaveProperty('operationId'); }
  });

  it('survives a fresh BFF service instance and a new key without browser recovery state', async () => {
    const f = fixture();
    await expect(f.createService().execute({ ...f.context }, async () => { throw responseLost(); })).rejects.toMatchObject({ status: 503 });
    const restarted = f.createService(), nativeWrite = vi.fn();
    await expect(restarted.execute({ ...f.context, idempotencyKey: 'fresh-process-and-empty-local-storage' }, nativeWrite)).rejects.toMatchObject({ response: { code: 'MUTATION_RECONCILIATION_REQUIRED' } });
    expect(nativeWrite).not.toHaveBeenCalled(); expect(f.operations.size).toBe(1);
  });

  it('does not confuse genuine different gateways with an alias even when UUID and name match', async () => {
    const f = fixture();
    await expect(f.createService().execute({ ...f.context }, async () => { throw responseLost(); })).rejects.toMatchObject({ status: 503 });
    const nativeWrite = vi.fn(async () => ({ id: 'same-uuid', name: 'shared-name', tags: ['kos-ws-pay'] }));
    await expect(f.createService().execute({ ...f.context, clusterId: secondary, actor: bob, idempotencyKey: 'genuine-c2' }, nativeWrite)).resolves.toMatchObject({ id: 'same-uuid' });
    expect(nativeWrite).toHaveBeenCalledTimes(1);
    expect([...f.operations.values()].map(row => row.state).sort()).toEqual(['succeeded', 'uncertain']);
    expect(f.redis.withLock.mock.calls.at(-1)?.[0]).toBe(`mutation:${differentPhysical}`);
  });

  it('blocks Target address reuse across immutable history IDs and blocks its owning Upstream', async () => {
    const f = fixture(), service = f.createService();
    const context = { ...f.context, entityType: 'targets', parentId: 'upstream-id', entityId: 'old-history-id', action: 'update', payload: { target: 'echo.test:8081', weight: 80 } };
    await expect(service.execute(context, async () => { throw responseLost(); })).rejects.toMatchObject({ status: 503 });
    const nativeWrite = vi.fn();
    await expect(service.execute({ ...context, actor: bob, entityId: 'new-history-id', idempotencyKey: 'new-target-key' }, nativeWrite)).rejects.toMatchObject({ response: { code: 'MUTATION_RECONCILIATION_REQUIRED' } });
    await expect(service.execute({ ...f.context, entityType: 'upstreams', entityId: 'upstream-id', action: 'update', payload: { name: 'renamed' }, idempotencyKey: 'upstream-key' }, nativeWrite)).rejects.toMatchObject({ response: { code: 'MUTATION_RECONCILIATION_REQUIRED' } });
    expect(nativeWrite).not.toHaveBeenCalled(); expect(f.operations.size).toBe(1);
  });
});
