import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { outboundJson, outboundText } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { lookup } from 'node:dns/promises';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn(), outboundText: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: vi.fn(async () => []) }));
const cid = '0acf928b-adbc-484d-82fa-a0c72d038139', wid = '9f79a9f4-fd54-42cc-8f66-3d80b7e6c632', pid = 'ba9d5146-02d6-4c28-b34d-3af7d9c75a5a';
const url = `http://kongos:${'x'.repeat(43)}@telemetry-collector:9093/ingest/${cid}`;
afterEach(() => { vi.unstubAllEnvs(); vi.clearAllMocks(); });
function fixture() {
  vi.stubEnv('KONG_RATE_WAIT_MS', '0');
  vi.stubEnv('COLLECTOR_TELEMETRY_IP', '172.28.31.30');
  vi.stubEnv('COLLECTOR_SELF_IPS', '172.28.31.30');
  vi.stubEnv('PROTECTED_DESTINATION_HOSTS', '172.28.21.20,172.28.22.20,172.28.31.20,172.28.31.30,telemetry-collector');
  vi.mocked(lookup).mockImplementation(async (host: string) => ['telemetry-collector', 'metrics-collector'].includes(host) ? [{ address: '172.28.31.30', family: 4 }] : host === 'kong' ? [{ address: '172.28.11.20', family: 4 }] : [] as any);
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', enabled_plugins: ['prometheus'], execution_mode: 'direct', status: 'healthy', revision: 1 };
  const state = { platform: true, valid: true, before: { id: pid, name: 'http-log', config: { http_endpoint: url } } as any };
  const execution = new KongExecutionContextService();
  // Real ALS and opaque-ticket pipeline; DB authorization and token proof are
  // explicit fixtures. Production NativePolicy/credential tests run separately.
  execution.installPolicy({ authorizeRequest: async () => ({ platformAdmin: state.platform, before: state.before }), authorizeResponse: async (_ticket, value) => value });
  const db: any = { one: vi.fn(async () => ({ ...cluster })), query: vi.fn(async (sql: string) => sql.includes('FROM clusters') ? [{ admin_url: cluster.admin_url }] : []) }, verifier = { verifyManagedIngestUrl: vi.fn(async (_cid, value) => ({ valid: state.valid && _cid === cid && value === url })) };
  const redis: any = { assertLeaseOwnership: vi.fn(async () => undefined), assertLeaseActive: vi.fn(), rateLimit: vi.fn(async () => ({ allowed: true })), withLock: vi.fn(async (_key, fn) => fn()) };
  const kong = new KongService(db, redis, { redactError: (value: unknown) => value } as any, {} as any, execution, verifier as any);
  const actor = { id: 'synthetic-user', username: 'unit', superAdmin: true };
  const run = (fn: () => Promise<any>, managed = false) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor);
    return execution.runActor({ actor, clusterId: cid, workspaceId: wid, module: 'plugins', action: 'write' }, () => {
      const operation = () => execution.runOperation({ actor, clusterId: cid, workspaceId: wid, entityType: 'plugins', action: 'update', operationId: 'synthetic-durable-id' }, fn);
      return managed ? execution.runManagedMetricsProvision(cid, operation) : operation();
    });
  });
  vi.mocked(outboundJson).mockImplementation(async (_base, path, method, body) => ({ status: 200, body: method !== 'GET' ? { id: pid, ...body as any } : path === '/schemas/plugins' ? { fields: [{ name: { type: 'string' } }, { enabled: { type: 'boolean' } }, { config: { type: 'record' } }] } : path === '/plugins/schema/http-log' ? { fields: [{ http_endpoint: { type: 'string' } }] } : state.before || { id: pid, name: 'http-log', config: { http_endpoint: url } }, bytes: 100 }));
  vi.mocked(outboundText).mockResolvedValue({ status: 200, body: 'kong_datastore_reachable 1\n', bytes: 28 });
  return { kong, execution, state, cluster, run, verifier };
}
describe('M5 strict native metrics text transport', () => {
  it('uses exact actor-free metrics capability and text transport only', async () => {
    const f = fixture();
    const text = await f.execution.runSystemRead(cid, 'metrics-scrape', () => f.kong.requestMetricsText(cid));
    expect(text).toContain('kong_datastore_reachable'); expect(outboundJson).not.toHaveBeenCalled();
    expect(outboundText).toHaveBeenCalledWith('http://kong:8001', '/metrics', null, 5000, expect.any(Function), 2 * 1024 * 1024);
  });
  it.each(['probe', 'metrics-catalog'])('does not grant metrics text to %s context', async purpose => {
    const f = fixture(); await expect(f.execution.runSystemRead(cid, purpose as any, () => f.kong.requestMetricsText(cid))).rejects.toMatchObject({ status: 403 }); expect(outboundText).not.toHaveBeenCalled();
  });
  it('does not add metrics to generic public request or allow HTTP actor escalation', async () => {
    const f = fixture(); await expect(f.run(() => f.kong.request(cid, 'GET', '/metrics'))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.execution.runSystemRead(cid, 'metrics-scrape', () => f.kong.requestMetricsText(cid)))).rejects.toMatchObject({ status: 403 }); expect(outboundText).not.toHaveBeenCalled();
  });
  it.each(['version', 'plugin', 'disabled'])('requires current %s capability before metrics packets', async cause => {
    const f = fixture(); if (cause === 'version') f.cluster.version = '2.0.0'; else if (cause === 'plugin') f.cluster.enabled_plugins = []; else f.cluster.status = 'disabled';
    await expect(f.execution.runSystemRead(cid, 'metrics-scrape', () => f.kong.requestMetricsText(cid))).rejects.toMatchObject({ status: 409 }); expect(outboundText).not.toHaveBeenCalled();
  });
  it('rejects a metrics result after registered connection changes', async () => {
    const f = fixture(); vi.mocked(outboundText).mockImplementation(async () => { f.cluster.revision++; return { status: 200, body: 'kong_datastore_reachable 1\n', bytes: 28 }; });
    await expect(f.execution.runSystemRead(cid, 'metrics-scrape', () => f.kong.requestMetricsText(cid))).rejects.toMatchObject({ response: { code: 'KONG_METRICS_CONNECTION_CHANGED' } });
  });
});
describe('M5 retained managed collector endpoint maintenance', () => {
  it('allows private provision of the exact protected collector channel after DNS and current token proof', async () => {
    const f = fixture(); f.state.before = null;
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).resolves.toMatchObject({ id: pid, name: 'http-log' });
    expect(lookup).toHaveBeenCalledWith('telemetry-collector', { all: true });
    expect(vi.mocked(outboundJson).mock.calls.filter(call => call[2] !== 'GET')).toHaveLength(1);
    expect(f.verifier.verifyManagedIngestUrl.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
  it('allows current platform to toggle its existing active managed endpoint', async () => {
    const f = fixture(); await expect(f.run(() => f.kong.request(cid, 'PATCH', `/plugins/${pid}`, { enabled: false }))).resolves.toMatchObject({ enabled: false }); expect(f.verifier.verifyManagedIngestUrl).toHaveBeenCalledWith(cid, url);
  });
  it.each(['nonplatform', 'rotated', 'beforeabsent', 'foreignCID', 'arbitraryUserinfo', 'changedEndpoint'])('rejects %s before native mutation', async cause => {
    const f = fixture(); let body: any = { enabled: true };
    if (cause === 'nonplatform') f.state.platform = false;
    else if (cause === 'rotated') f.state.valid = false;
    else if (cause === 'beforeabsent') f.state.before = null;
    else { const changed = cause === 'foreignCID' ? url.replace(cid, wid) : cause === 'arbitraryUserinfo' ? 'http://u:p@business.example/log' : url.replace('/ingest/', '/other/'); f.state.before = { id: pid, name: 'http-log', config: { http_endpoint: changed } }; body = { enabled: true, ...(cause === 'changedEndpoint' ? { config: { http_endpoint: url } } : {}) }; }
    await expect(f.run(() => f.kong.request(cid, 'PATCH', `/plugins/${pid}`, body))).rejects.toMatchObject({ status: 403 }); expect(vi.mocked(outboundJson).mock.calls.some(call => call[2] !== 'GET')).toBe(false);
  });
  it.each(['admin', 'storage', 'linklocal', 'unknown'])('does not let a managed ancestor bypass %s DNS destinations', async cause => {
    const f = fixture(); f.state.before = null;
    const address = cause === 'admin' ? '172.28.11.20' : cause === 'storage' ? '172.28.21.20' : cause === 'linklocal' ? '169.254.169.254' : null;
    vi.mocked(lookup).mockImplementation(async (host: string) => host === 'metrics-collector' ? [{ address: '172.28.31.30', family: 4 }] : host === 'telemetry-collector' ? address ? [{ address, family: 4 }] : [] : host === 'kong' ? [{ address: '172.28.11.20', family: 4 }] : [] as any);
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).rejects.toMatchObject({ status: cause === 'unknown' ? 502 : 403 });
    expect(vi.mocked(outboundJson).mock.calls.some(call => call[2] !== 'GET')).toBe(false);
  });
  it.each(['platform', 'generation'])('rechecks %s changes during collector DNS validation before any mutation packet', async cause => {
    const f = fixture(); f.state.before = null;
    vi.mocked(lookup).mockImplementation(async (host: string) => {
      if (host === 'telemetry-collector') { if (cause === 'platform') f.state.platform = false; else f.state.valid = false; return [{ address: '172.28.31.30', family: 4 }]; }
      if (host === 'metrics-collector') return [{ address: '172.28.31.30', family: 4 }];
      return host === 'kong' ? [{ address: '172.28.11.20', family: 4 }] : [] as any;
    });
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).rejects.toMatchObject({ status: 403 });
    expect(vi.mocked(outboundJson).mock.calls.some(call => call[2] !== 'GET')).toBe(false);
  });
  it.each(['wrong', 'mixed', 'missing'])('requires exact enrolled telemetry identity, rejecting %s alias proof', async cause => {
    const f = fixture(); f.state.before = null;
    vi.mocked(lookup).mockImplementation(async (host: string) => {
      if (host === 'metrics-collector') return cause === 'missing' ? [] : cause === 'mixed' ? [{ address: '172.28.31.30', family: 4 }, { address: '10.80.1.30', family: 4 }] : [{ address: '10.80.1.30', family: 4 }];
      return host === 'telemetry-collector' ? [{ address: '172.28.31.30', family: 4 }] : [] as any;
    });
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).rejects.toMatchObject({ status: 502, response: { code: 'DESTINATION_POLICY_UNAVAILABLE' } });
    expect(vi.mocked(outboundJson).mock.calls.some(call => call[2] !== 'GET')).toBe(false);
  });
  it.each(['wrong', 'mixed'])('rejects %s native hostname DNS even when the telemetry alias is verified', async cause => {
    const f = fixture(); f.state.before = null;
    vi.mocked(lookup).mockImplementation(async (host: string) => {
      if (host === 'metrics-collector') return [{ address: '172.28.31.30', family: 4 }];
      return host === 'telemetry-collector' ? cause === 'mixed' ? [{ address: '172.28.31.30', family: 4 }, { address: '10.80.1.30', family: 4 }] : [{ address: '10.80.1.30', family: 4 }] : [] as any;
    });
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).rejects.toMatchObject({ status: 403 });
    expect(vi.mocked(outboundJson).mock.calls.some(call => call[2] !== 'GET')).toBe(false);
  });
  it('accepts only other explicitly registered collector interfaces when the native hostname selects another network', async () => {
    const f = fixture(); f.state.before = null;
    vi.stubEnv('COLLECTOR_SELF_IPS', '172.28.31.30,172.22.0.30');
    vi.mocked(lookup).mockImplementation(async (host: string) => host === 'metrics-collector' ? [{ address: '172.28.31.30', family: 4 }] : host === 'telemetry-collector' ? [{ address: '172.22.0.30', family: 4 }] : [] as any);
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).resolves.toMatchObject({ name: 'http-log' });
    expect(vi.mocked(outboundJson).mock.calls.filter(call => call[2] !== 'GET')).toHaveLength(1);
  });
  it.each(['', '10.80.1.30', '172.28.31.30,127.0.0.1', '172.28.31.30,business.example'])('rejects missing or invalid configured collector identities', async selfIps => {
    const f = fixture(); f.state.before = null; vi.stubEnv('COLLECTOR_SELF_IPS', selfIps);
    await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } }), true)).rejects.toMatchObject({ status: 502 });
    expect(vi.mocked(outboundJson).mock.calls.some(call => call[2] !== 'GET')).toBe(false);
  });
});
