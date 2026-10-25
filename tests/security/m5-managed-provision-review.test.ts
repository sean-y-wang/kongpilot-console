import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { MetricsCredentialsService, metricsTokenDigest } from '../../apps/console-api/src/modules/metrics/metrics-credentials.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { lookup } from 'node:dns/promises';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn(), outboundText: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: vi.fn(async () => []) }));
const cid = '3315a638-6bcb-49b6-971b-c3592afcccef', foreignCid = 'f54e9160-24e1-4f7b-9283-f956c3891e49';
const wid = 'e5f39d06-b46e-4d5d-8321-a448572f4d06', pid = '2b11a9a3-a76e-4dc1-88b3-4fb6ba5b5533';
const token = 'v'.repeat(43), url = `http://kongos:${token}@telemetry-collector:9093/ingest/${cid}`;
const actor = { id: 'a3069a87-a69f-4d02-b452-6c6ed4eb334f', username: 'managed-review', superAdmin: true };
beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'f1'.repeat(32));
  vi.stubEnv('PROTECTED_DESTINATION_HOSTS', 'telemetry-collector,metrics-bff,prometheus,172.28.31.30,172.28.32.30,172.28.33.30');
  vi.stubEnv('COLLECTOR_TELEMETRY_IP', '172.28.31.30');
  vi.stubEnv('COLLECTOR_SELF_IPS', '172.28.31.30,172.28.32.30,172.28.33.30');
  vi.stubEnv('KONG_RATE_WAIT_MS', '0');
  vi.mocked(lookup).mockImplementation(async (host: any) => {
    const addresses: Record<string, string> = { 'metrics-collector': '172.28.31.30', 'telemetry-collector': '172.28.31.30', kong: '172.28.11.20', 'metrics-bff': '172.28.31.10', prometheus: '172.28.31.20' };
    return addresses[host] ? [{ address: addresses[host], family: 4 }] : [] as any;
  });
});
afterEach(() => { vi.unstubAllEnvs(); vi.clearAllMocks(); });

/** Actual Kong destination policy, opaque execution ancestors and credential
 * verifier. The current-platform policy decision, SQL rows and transport are
 * explicit fixtures; packet recording follows both actual transport fences. */
function fixture() {
  const execution = new KongExecutionContextService(), secrets = new SecretService();
  const state = { platform: true, generation: 1, currentToken: token, before: null as any, closeHttp: () => {},
    beforePacket: undefined as (() => void) | undefined, duringFence: undefined as (() => void) | undefined };
  const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', enabled_plugins: ['http-log'], execution_mode: 'direct', status: 'healthy', revision: 1 };
  const packets: Array<{ method: string; path: string; body: any }> = [];
  const db: any = {
    one: vi.fn(async (sql: string, p: any[]) => {
      if (sql.includes('FROM metrics_credentials')) {
        if (sql.includes('WHERE k.id=$1')) return p[1] === cid && p[2] === 'collector_ingest' && p[3] === 'collector' && p[4] === state.generation ? { id: pid } : null;
        return p[0] === cid && p[1] === 'collector_ingest' && p[2] === 'collector' ? { id: pid, cluster_id: cid, purpose: 'collector_ingest', audience: 'collector', generation: state.generation, token_fingerprint: metricsTokenDigest(state.currentToken) } : null;
      }
      if (sql.includes('FROM clusters')) return p[0] === cid ? { ...cluster } : null;
      throw new Error('unexpected managed-provision SQL fixture');
    }),
    query: vi.fn(async (sql: string) => sql.includes('FROM clusters') ? [{ admin_url: cluster.admin_url }] : [{ base_url: 'http://prometheus:9090' }]),
  };
  const credentials = new MetricsCredentialsService(db, secrets, {} as any);
  execution.installPolicy({ authorizeRequest: async () => ({ platformAdmin: state.platform, before: state.before }), authorizeResponse: async (_ticket, value) => value,
    beforeNativeSend: async () => { state.duringFence?.(); } });
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), rateLimit: vi.fn(async () => ({ allowed: true })), assertLeaseOwnership: vi.fn(async () => undefined), assertLeaseActive: vi.fn() };
  const kong = new KongService(db, redis, secrets, {} as any, execution, credentials);
  vi.mocked(outboundJson).mockImplementation(async (_base, path, method, body, _query, _auth, _timeout, syncFence, asyncFence) => {
    if (method !== 'GET') {
      state.beforePacket?.();
      await asyncFence?.(); syncFence?.();
      packets.push({ method, path, body });
      return { status: 200, body: { id: pid, ...body as any }, bytes: 100 };
    }
    if (path.startsWith('/upstreams/')) return { status: 404, body: { message: 'Not found' }, bytes: 100 };
    return { status: 200, body: path === '/schemas/plugins' ? { fields: [{ name: { type: 'string' } }, { enabled: { type: 'boolean' } }, { config: { type: 'record' } }] }
      : path.startsWith('/plugins/schema/') ? { fields: [{ http_endpoint: { type: 'string' } }] }
      : path === '/schemas/services' ? { fields: [{ host: { type: 'string' } }, { port: { type: 'integer' } }] }
      : path === '/schemas/targets' ? { fields: [{ target: { type: 'string' } }] } : state.before, bytes: 100 };
  });
  const run = (fn: () => Promise<any>, managed = false) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor, 'current-console-session');
    state.closeHttp = execution.captureHttpCloser();
    return execution.runActor({ actor, clusterId: cid, workspaceId: wid, module: 'plugins', action: 'write' }, () => {
      const operation = () => execution.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId: pid, entityType: 'plugins', action: state.before ? 'update' : 'create' }, fn);
      return managed ? execution.runManagedMetricsProvision(cid, operation) : operation();
    });
  });
  const create = (endpoint = url, managed = false) => run(() => kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: endpoint } }), managed);
  return { execution, state, packets, kong, run, create, db };
}

describe('M5 independent fixed collector provisioning destination exception', () => {
  it('allows only the private platform provisioner with the exact active CID/purpose token, despite the protected collector host', async () => {
    const f = fixture(); await expect(f.create(url, true)).resolves.toMatchObject({ name: 'http-log' });
    expect(f.packets).toHaveLength(1); expect(f.packets[0]).toMatchObject({ method: 'POST', path: '/plugins', body: { config: { http_endpoint: url } } });
    expect(f.db.one.mock.calls.filter(([sql]) => sql.includes('FROM metrics_credentials')).length).toBeGreaterThanOrEqual(4);
  });
  it('keeps a retained exact active managed endpoint maintainable by current platform without minting a new provisioner', async () => {
    const f = fixture(); f.state.before = { id: pid, name: 'http-log', config: { http_endpoint: url } };
    await expect(f.run(() => f.kong.request(cid, 'PATCH', `/plugins/${pid}`, { enabled: false }))).resolves.toMatchObject({ enabled: false });
    expect(f.packets).toHaveLength(1);
  });
  it('accepts actual multi-network DNS only when every address is a registered Collector interface', async () => {
    const f = fixture(), ordinaryLookup = vi.mocked(lookup).getMockImplementation()!;
    vi.mocked(lookup).mockImplementation(async (host: any, options: any) => host === 'telemetry-collector'
      ? [{ address: '172.28.32.30', family: 4 }, { address: '172.28.33.30', family: 4 }] : ordinaryLookup(host, options));
    await expect(f.create(url, true)).resolves.toMatchObject({ name: 'http-log' }); expect(f.packets).toHaveLength(1);
  });
  it.each([
    ['ordinary exact managed URL', url, false],
    ['protected no-userinfo collector', `http://telemetry-collector:9093/ingest/${cid}`, false],
    ['protected no-userinfo collector inside provisioner', `http://telemetry-collector:9093/ingest/${cid}`, true],
    ['ordinary private URL with userinfo', 'http://user:password@business.example/log', false],
    ['protected admin userinfo', 'http://kongos:password@kong:8001/services', true],
    ['protected BFF', 'http://metrics-bff:9092/catalog', true],
    ['foreign CID', url.replace(cid, foreignCid), true],
    ['wrong token purpose', url.replace(token, 'c'.repeat(43)), true],
    ['wrong port', url.replace(':9093/', ':9094/'), true],
    ['query', `${url}?sink=other`, true],
    ['fragment', `${url}#other`, true],
    ['userinfo username', url.replace('kongos:', 'other:'), true],
  ])('rejects %s with zero simulated native packets', async (_name, endpoint, managed) => {
    const f = fixture(); await expect(f.create(endpoint as string, managed as boolean)).rejects.toMatchObject({ status: 403 }); expect(f.packets).toEqual([]);
  });
  it('denies forged public frame properties without a privately registered ancestor', async () => {
    const f = fixture(); await expect(f.run(async () => {
      const copy = { ...f.execution.current(), managedMetricsProvision: { clusterId: cid } };
      expect(copy.managedMetricsProvision.clusterId).toBe(cid);
      return f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } });
    })).rejects.toMatchObject({ status: 403 }); expect(f.packets).toEqual([]);
  });
  it('denies a current non-platform decision even inside a private provisioning ancestor', async () => {
    const f = fixture(); f.state.platform = false;
    await expect(f.create(url, true)).rejects.toMatchObject({ status: 403 }); expect(f.packets).toEqual([]);
  });
  it('does not extend the collector exception to Service proxy destinations inside the same private ancestor', async () => {
    const f = fixture(); await expect(f.run(() => f.kong.request(cid, 'POST', '/services', { host: 'telemetry-collector', port: 9093 }), true)).rejects.toMatchObject({ status: 403, response: { code: 'PROTECTED_PROXY_DESTINATION' } });
    expect(f.packets).toEqual([]);
  });
  it('does not extend the credential-bearing exception to another log plugin', async () => {
    const f = fixture(); await expect(f.run(() => f.kong.request(cid, 'POST', '/plugins', { name: 'zipkin', config: { http_endpoint: url } }), true)).rejects.toMatchObject({ status: 403, response: { code: 'PROTECTED_PROXY_DESTINATION' } });
    expect(f.packets).toEqual([]);
  });
  it.each(['172.28.31.30', '172.28.32.30', '172.28.33.30'].flatMap(address => ['Service', 'Target', 'ordinary http-log'].map(kind => [kind, address])))('keeps generic %s requests to Collector interface %s blocked before any packet', async (kind, address) => {
    const f = fixture();
    const request = kind === 'Service' ? () => f.kong.request(cid, 'POST', '/services', { host: address, port: 9093 })
      : kind === 'Target' ? () => f.kong.request(cid, 'POST', `/upstreams/${wid}/targets`, { target: `${address}:9093` })
      : () => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: `http://${address}:9093/ingest/${cid}` } });
    await expect(f.run(request)).rejects.toMatchObject({ status: 403, response: { code: 'PROTECTED_PROXY_DESTINATION' } }); expect(f.packets).toEqual([]);
  });
  it.each([
    ['wrong business IP', ['10.84.12.20']],
    ['mixed self and unregistered IP', ['172.28.31.30', '10.84.12.20']],
    ['Admin IP', ['172.28.11.20']],
    ['metrics BFF IP', ['172.28.31.10']],
    ['empty DNS proof', []],
  ])('rejects %s DNS proof rather than treating any non-protected address as the Collector', async (_name, addresses) => {
    const f = fixture(), ordinaryLookup = vi.mocked(lookup).getMockImplementation()!;
    vi.mocked(lookup).mockImplementation(async (host: any, options: any) => host === 'telemetry-collector'
      ? (addresses as string[]).map(address => ({ address, family: 4 })) : ordinaryLookup(host, options));
    await expect(f.create(url, true)).rejects.toMatchObject({ status: addresses.length ? 403 : 502 }); expect(f.packets).toEqual([]);
  });
  it.each([
    ['wrong identity address', ['10.84.12.20']],
    ['mixed identity and unregistered address', ['172.28.31.30', '10.84.12.20']],
    ['empty identity proof', []],
  ])('rejects a dedicated telemetry alias with %s', async (_name, addresses) => {
    const f = fixture(), ordinaryLookup = vi.mocked(lookup).getMockImplementation()!;
    vi.mocked(lookup).mockImplementation(async (host: any, options: any) => host === 'metrics-collector'
      ? (addresses as string[]).map(address => ({ address, family: 4 })) : ordinaryLookup(host, options));
    await expect(f.create(url, true)).rejects.toMatchObject({ status: 502, response: { code: 'DESTINATION_POLICY_UNAVAILABLE' } }); expect(f.packets).toEqual([]);
  });
  it('rejects a private provision ancestor for a foreign CID', async () => {
    const f = fixture(); await expect(f.run(() => f.execution.runManagedMetricsProvision(foreignCid, () => f.kong.request(cid, 'POST', '/plugins', { name: 'http-log', config: { http_endpoint: url } })))).rejects.toMatchObject({ status: 403 });
    expect(f.packets).toEqual([]);
  });
  it('rechecks token generation after an awaited write fence and emits no packet', async () => {
    const f = fixture(); f.state.duringFence = () => { f.state.generation++; f.state.currentToken = 'n'.repeat(43); };
    await expect(f.create(url, true)).rejects.toMatchObject({ status: 403 }); expect(f.packets).toEqual([]);
  });
  it.each(['platform', 'generation'])('rechecks %s at the DNS/packet boundary instead of relying on the first URL verification', async changed => {
    const f = fixture(); f.state.beforePacket = () => { if (changed === 'platform') f.state.platform = false; else { f.state.generation++; f.state.currentToken = 'n'.repeat(43); } };
    await expect(f.create(url, true)).rejects.toMatchObject({ status: 403 }); expect(f.packets).toEqual([]);
  });
  it('does not resurrect a closed HTTP/managed ancestor at the delayed packet boundary', async () => {
    const f = fixture(); f.state.beforePacket = () => f.state.closeHttp();
    await expect(f.create(url, true)).rejects.toMatchObject({ status: 403 }); expect(f.packets).toEqual([]);
  });
});
