import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { payWorkspaceId, workspaceFixture } from '../unit/workspace-test-fixture';

const cid = 'c161a6b0-dacd-4c28-a95d-acf3ef0e205b';
const id = 'a5c84a6c-5836-41f0-b4d6-fdc865ed9f53';
const actor = { id: '56275c42-ed7e-466b-ae01-90c3d3a0edaf', username: 'metrics-reader', superAdmin: false };
const cluster = { id: cid, admin_url: 'http://kong:8001', execution_mode: 'direct', status: 'connected', version: '1.5.1', enabled_plugins: ['prometheus'] };
function fixture() {
  const execution = new KongExecutionContextService(), secret = new SecretService(), workspace = workspaceFixture(cid);
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM users')) return { id: actor.id, username: actor.username, super_admin: false, status: 'active', permissions_epoch: 1, credential_epoch: 1 };
    if (sql.includes('FROM iam_epoch')) return { version: 1 };
    if (sql.includes('FROM clusters')) return cluster;
    throw new Error('unexpected context policy fixture SQL');
  }), query: vi.fn(async () => [{ module: 'monitoring', action: 'read', scope_type: 'workspace', scope_values: [payWorkspaceId], cluster_id: cid, workspace_id: payWorkspaceId }]) };
  const kong: any = { request: vi.fn() }, authz = new AuthorizationService(db, workspace.resolver, kong, execution);
  const policy = new NativeKongPolicyService(db, secret, kong, execution, authz, workspace.resolver, { beforeNativeWrite: vi.fn() }); policy.install();
  const user = <T>(fn: () => Promise<T>) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor); const close = execution.captureHttpCloser();
    try { return await execution.runActor({ actor, clusterId: cid, workspaceId: payWorkspaceId, module: 'monitoring', action: 'read' }, fn); }
    finally { close(); }
  });
  return { execution, db, kong, user };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '72'.repeat(32)); });
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

describe('M5 independent actual metrics system capabilities and native policy', () => {
  it('admits only an actor-free standalone scrape and bounded text response', async () => {
    const f = fixture();
    await f.execution.runSystemRead(cid, 'metrics-scrape', async () => {
      expect(f.execution.current().actor).toBeUndefined();
      const ticket = await f.execution.authorizeRequest(cluster, 'GET', '/metrics', undefined, {});
      expect(f.execution.verifiedPlatformAdmin(ticket)).toBe(false);
      expect(await f.execution.authorizeResponse(ticket, 'kong_datastore_reachable 1\n')).toBe('kong_datastore_reachable 1\n');
    });
    expect(f.db.one).not.toHaveBeenCalled();
  });
  it.each(['/status', '/services', '/metrics/other', '/plugins/enabled'])('prevents scrape from reading %s', async path => {
    const f = fixture();
    await expect(f.execution.runSystemRead(cid, 'metrics-scrape', () => f.execution.authorizeRequest(cluster, 'GET', path, undefined, {}))).rejects.toMatchObject({ status: 403 });
  });
  it('rejects scrape query expansion and all write methods before policy execution', async () => {
    const f = fixture();
    for (const [method, query] of [['GET', { url: 'http://untrusted' }], ['POST', {}], ['DELETE', {}]] as const) {
      await expect(f.execution.runSystemRead(cid, 'metrics-scrape', () => f.execution.authorizeRequest(cluster, method, '/metrics', undefined, query))).rejects.toMatchObject({ status: 403 });
    }
    expect(f.db.one).not.toHaveBeenCalled();
  });
  it('allows only native Service/Route/Consumer catalog collections and UUID identities', async () => {
    const f = fixture();
    await f.execution.runSystemRead(cid, 'metrics-catalog', async () => {
      for (const type of ['services', 'routes', 'consumers']) {
        const list = await f.execution.authorizeRequest(cluster, 'GET', `/${type}`, undefined, { size: 100, offset: 'native-cursor' });
        expect(await f.execution.authorizeResponse(list, { data: [], next: null })).toEqual({ data: [], next: null });
        const single = await f.execution.authorizeRequest(cluster, 'GET', `/${type}/${id}`, undefined, {});
        expect(await f.execution.authorizeResponse(single, { id })).toEqual({ id });
      }
    });
  });
  it.each(['/plugins', '/certificates', '/services/by-name', `/consumers/${id}/key-auth`, '/metrics', '/cache'])
    ('rejects catalog expansion to %s', async path => {
      const f = fixture();
      await expect(f.execution.runSystemRead(cid, 'metrics-catalog', () => f.execution.authorizeRequest(cluster, 'GET', path, undefined, {}))).rejects.toMatchObject({ status: 403 });
    });
  it('refuses catalog filter overrides, overlarge pages and identity queries', async () => {
    const f = fixture();
    for (const [path, query] of [['/services', { size: 101 }], ['/services', { tags: 'untrusted' }], [`/services/${id}`, { offset: 'untrusted' }]] as const) {
      await expect(f.execution.runSystemRead(cid, 'metrics-catalog', () => f.execution.authorizeRequest(cluster, 'GET', path, undefined, query))).rejects.toMatchObject({ status: 403 });
    }
  });
  it('cannot lift an HTTP actor or an internal user read into either metrics system purpose', async () => {
    const f = fixture();
    for (const purpose of ['metrics-scrape', 'metrics-catalog'] as const) {
      await expect(f.user(() => f.execution.runSystemRead(cid, purpose, async () => undefined))).rejects.toMatchObject({ status: 403 });
      await expect(f.user(() => f.execution.runInternalRead(cid, purpose, () => f.execution.authorizeRequest(cluster, 'GET', purpose === 'metrics-scrape' ? '/metrics' : '/services', undefined, {}))))
        .rejects.toMatchObject({ status: 403 });
    }
    await expect(f.user(() => f.execution.authorizeRequest(cluster, 'GET', '/metrics', undefined, {}))).rejects.toMatchObject({ status: 403 });
  });
  it('requires Kong 1.5, active native capability and the matching system cluster', async () => {
    const f = fixture();
    for (const changed of [{ version: '2.8.0' }, { status: 'disabled' }, { enabled_plugins: [] }, { id: 'a893078d-af0e-4e85-9d48-31f45dc47338' }]) {
      await expect(f.execution.runSystemRead(cid, 'metrics-scrape', () => f.execution.authorizeRequest({ ...cluster, ...changed }, 'GET', '/metrics', undefined, {}))).rejects.toMatchObject({ status: 403 });
    }
  });
  it('enforces the scrape retry/call cap and UTF-8 byte ceiling across the actual context', async () => {
    const f = fixture();
    await f.execution.runSystemRead(cid, 'metrics-scrape', async () => {
      const ticket = await f.execution.authorizeRequest(cluster, 'GET', '/metrics', undefined, {});
      f.execution.chargeRetry(ticket); f.execution.chargeRetry(ticket);
      expect(() => f.execution.chargeRetry(ticket)).toThrow();
    });
    await expect(f.execution.runSystemRead(cid, 'metrics-scrape', async () => {
      const ticket = await f.execution.authorizeRequest(cluster, 'GET', '/metrics', undefined, {});
      return f.execution.authorizeResponse(ticket, '汉'.repeat(700_000));
    })).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_RESPONSE_LIMIT' } });
    expect(() => f.execution.runSystemRead(cid, 'metrics-scrape', async () => undefined, { maxCalls: 4 })).toThrow();
    expect(() => f.execution.runSystemRead(cid, 'metrics-scrape', async () => undefined, { maxBytes: 2 * 1024 * 1024 + 1 })).toThrow();
  });
  it('rejects a scrape ticket after the fixed five-second scope expires', async () => {
    let now = 1_000; vi.spyOn(Date, 'now').mockImplementation(() => now); const f = fixture();
    await f.execution.runSystemRead(cid, 'metrics-scrape', async () => {
      const ticket = await f.execution.authorizeRequest(cluster, 'GET', '/metrics', undefined, {}); now += 5001;
      await expect(f.execution.authorizeResponse(ticket, 'metric 1\n')).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    });
  });
});
