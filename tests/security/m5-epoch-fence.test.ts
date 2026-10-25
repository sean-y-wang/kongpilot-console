import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { MetricsRepositoryService } from '../../apps/console-api/src/modules/metrics/metrics-repository.service';
import { MetricsCredentialsService, metricsTokenDigest } from '../../apps/console-api/src/modules/metrics/metrics-credentials.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { payWorkspaceId, workspaceFixture } from '../unit/workspace-test-fixture';

const cid = '7530297b-364c-41d9-aeb5-9e2d119843b4', actorId = '75ea1b46-eb04-4b56-8d1d-87b020bdb68a';
const entityId = '9d0043e1-576e-4ad2-a397-2b9da0e6ce11', opId = 'a4c2a47b-16c7-4b80-b945-5c008d431892';
const actor = { id: actorId, username: 'fence-user', superAdmin: false };
const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
const deferred = () => { let resolve!: (value?: any) => void; const promise = new Promise<any>(done => { resolve = done; }); return { promise, resolve }; };
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ae'.repeat(32)); vi.stubEnv('APP_SECRET', 'metrics-fence-independent-fixture-private-key-32'); vi.stubEnv('METRICS_BRIDGE_ENABLED', 'true'); });
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

function nativeFixture(fenceFn: () => Promise<any>) {
  const execution = new KongExecutionContextService(), secrets = new SecretService(), ws = workspaceFixture(cid);
  const state = { epoch: 1, enabled: true, session: true };
  const before = { id: entityId, name: 'original', host: 'private.example', tags: ['kos-ws-pay'] }, patch = { name: 'updated' };
  const operation: any = { id: opId, actor_id: actorId, cluster_id: cid, workspace_id: payWorkspaceId, entity_type: 'services', entity_id: entityId,
    action: 'update', state: 'running', remote_started: true, payload_secret: secrets.encrypt(patch, `mutation:${opId}:payload`), before_secret: secrets.encrypt(before, `mutation:${opId}:before`) };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM mutation_operations')) return operation;
    if (sql.includes('FROM users')) return state.enabled ? { id: actorId, username: actor.username, super_admin: false, status: 'active', permissions_epoch: state.epoch, credential_epoch: 1 } : null;
    if (sql.includes('FROM auth_sessions')) return state.session ? { id: 'session-valid' } : null;
    if (sql.includes('FROM iam_epoch')) return { version: state.epoch };
    if (sql.includes('FROM clusters')) return cluster; return null;
  }), query: vi.fn(async () => [{ module: 'services', action: 'write', scope_type: 'workspace', cluster_id: cid, workspace_id: payWorkspaceId, scope_values: [payWorkspaceId] }]) };
  const kong: any = { request: vi.fn(async (_cid: string, _method: string, path: string) => { if (path === `/services/${entityId}`) return structuredClone(before); throw new NotFoundException(); }) };
  const authz = new AuthorizationService(db, ws.resolver, kong, execution), fence = { beforeNativeWrite: vi.fn(fenceFn) };
  const policy = new NativeKongPolicyService(db, secrets, kong, execution, authz, ws.resolver, fence); policy.install();
  const run = <T>(fn: () => Promise<T>) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor, 'session-valid'); const close = execution.captureHttpCloser();
    try { return await execution.runActor({ actor, clusterId: cid, workspaceId: payWorkspaceId, module: 'services', action: 'write' }, () => execution.runOperation({ actor, clusterId: cid, workspaceId: payWorkspaceId, operationId: opId, entityType: 'services', entityId, action: 'update' }, fn)); }
    finally { close(); }
  });
  return { execution, state, operation, fence, run, patch };
}

describe('M5 independent real native-policy fence before-packet authorization', () => {
  it('awaits durable fence before transport preparation can finish and passes only trusted operation dimensions', async () => {
    const gate = deferred(), entered = deferred(), f = nativeFixture(async () => { entered.resolve(); return gate.promise; }), send = vi.fn();
    const pending = f.run(async () => { const ticket = await f.execution.authorizeRequest(cluster, 'PATCH', `/services/${entityId}`, f.patch, {}); await f.execution.beforeNativeSend(ticket); send(); });
    await entered.promise; expect(send).not.toHaveBeenCalled(); gate.resolve(); await pending; expect(send).toHaveBeenCalledOnce();
    expect(f.fence.beforeNativeWrite.mock.calls[0][0]).toMatchObject({ cid, transportScope: transportScopeFor(cluster.admin_url), operationId: opId, entityType: 'services', entityId, method: 'PATCH', path: `/services/${entityId}` });
    expect(f.fence.beforeNativeWrite.mock.calls[0][0].requestFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });
  it('prevents any next transport callback if the durable fence cannot be persisted', async () => {
    const f = nativeFixture(async () => { throw new Error('controlled persistence failure'); }), send = vi.fn();
    await expect(f.run(async () => { const ticket = await f.execution.authorizeRequest(cluster, 'PATCH', `/services/${entityId}`, f.patch, {}); await f.execution.beforeNativeSend(ticket); send(); })).rejects.toThrow('controlled persistence failure');
    expect(send).not.toHaveBeenCalled();
  });
  it.each(['account', 'session', 'permissions', 'operation'])('rechecks fresh %s after the fence await before transport', async changed => {
    const gate = deferred(), entered = deferred(), f = nativeFixture(async () => { entered.resolve(); return gate.promise; }), send = vi.fn();
    const pending = f.run(async () => { const ticket = await f.execution.authorizeRequest(cluster, 'PATCH', `/services/${entityId}`, f.patch, {}); await f.execution.beforeNativeSend(ticket); send(); });
    await entered.promise;
    if (changed === 'account') f.state.enabled = false; else if (changed === 'session') f.state.session = false; else if (changed === 'permissions') f.state.epoch++; else f.operation.state = 'uncertain';
    gate.resolve(); await expect(pending).rejects.toBeDefined(); expect(send).not.toHaveBeenCalled();
  });
  it('rejects a closed HTTP execution even if delayed persistence acknowledges successfully', async () => {
    const gate = deferred(), entered = deferred(), f = nativeFixture(async () => { entered.resolve(); return gate.promise; }), send = vi.fn();
    let continuation!: Promise<void>;
    await f.run(async () => { const ticket = await f.execution.authorizeRequest(cluster, 'PATCH', `/services/${entityId}`, f.patch, {}); continuation = f.execution.beforeNativeSend(ticket).then(() => { send(); }); await entered.promise; });
    const denied = expect(continuation).rejects.toBeDefined(); gate.resolve(); await denied; expect(send).not.toHaveBeenCalled();
  });
});

function repositoryFixture() {
  const state = { revision: 1, generation: 1, blocked: false, rows: [] as any[], afterRows: undefined as (() => void) | undefined };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM clusters')) return cluster;
    if (sql.includes('FROM metrics_settings')) return { catalog_revision: state.revision, credential_generation: state.generation, max_age_ms: 15000, last_verified_at: new Date().toISOString(), catalog_status: 'ready' };
    if (sql.includes('FROM mutation_operations') || sql.includes('FROM metrics_write_fences')) return state.blocked ? { blocked: 1 } : null; throw new Error('Unexpected repository fixture SQL');
  }), query: vi.fn(async (sql: string) => {
    if (sql.includes('FROM clusters')) return [cluster];
    if (sql.includes('FROM metrics_assignment_epochs')) { const rows = structuredClone(state.rows); state.afterRows?.(); return rows; } throw new Error('Unexpected repository query');
  }) };
  const repository = new MetricsRepositoryService(db, new SecretService(), workspaceFixture(cid).resolver);
  return { state, db, repository };
}
describe('M5 independent repository and token response races', () => {
  it.each(['fence', 'catalog', 'generation'])('discards a verified catalog read if %s changes before response', async changed => {
    const f = repositoryFixture(); f.state.afterRows = () => { if (changed === 'fence') f.state.blocked = true; else if (changed === 'catalog') f.state.revision++; else f.state.generation++; };
    await expect(f.repository.catalog(cid)).rejects.toMatchObject({ status: 409, response: { code: 'METRICS_CATALOG_CHANGED' } });
  });
  it('does not emit epoch bindings when the durable parent is uncertain even though the old catalog is ready', async () => {
    const f = repositoryFixture(); f.state.blocked = true;
    const result = await f.repository.validateEventBindings(cid, { credentialGeneration: 1, items: [{ index: 0, serviceId: entityId, startedAt: Date.now()-1000, endedAt: Date.now()-900 }] });
    expect(result.items).toEqual([{ index: 0, quality: 'blocked', reasonCode: 'METRICS_WRITE_UNRESOLVED' }]);
    expect(f.db.query.mock.calls.some(([sql]) => sql.includes('metrics_assignment_epochs'))).toBe(false);
  });
  it('rechecks the token family at the final managed-endpoint response, preventing validate-then-rotate races', async () => {
    const token = 'A'.repeat(43); let calls = 0;
    const credentials = new MetricsCredentialsService({ one: vi.fn(async () => ++calls === 1 ? { id: opId, cluster_id: cid, purpose: 'collector_ingest', audience: 'collector', generation: 1, token_fingerprint: metricsTokenDigest(token) } : null) } as any, new SecretService(), {} as any);
    expect(await credentials.verifyManagedIngestUrl(cid, `http://kongos:${token}@telemetry-collector:9093/ingest/${cid}`)).toEqual({ valid: false });
    expect(calls).toBe(2);
  });
  it('rejects copied or cross-instance issued token identities despite identical public dimensions', async () => {
    const token = 'A'.repeat(43), db: any = { one: vi.fn(async () => ({ id: opId, cluster_id: cid, purpose: 'native_scrape', audience: 'bff', generation: 1, token_fingerprint: metricsTokenDigest(token) })) };
    const one = new MetricsCredentialsService(db, new SecretService(), {} as any), two = new MetricsCredentialsService(db, new SecretService(), {} as any), identity = await one.validate(token, cid, 'native_scrape', 'bff');
    expect(Object.isFrozen(identity)).toBe(true); await expect(two.assertCurrent(identity)).rejects.toMatchObject({ status: 401 }); await expect(one.assertCurrent(JSON.parse(JSON.stringify(identity)))).rejects.toMatchObject({ status: 401 });
    expect(db.one).toHaveBeenCalledTimes(1);
  });
});
