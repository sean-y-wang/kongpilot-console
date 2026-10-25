import 'reflect-metadata';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MetricsBridgeService } from '../../apps/console-api/src/modules/vitals/bridges/metrics-bridge.service';
import { MetricsCredentialsService, metricsTokenDigest } from '../../apps/console-api/src/modules/metrics/metrics-credentials.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';

const cid = '721bfeda-dc12-4d7a-b33e-06b2879a7ead', otherCid = 'de3aa362-52b1-4b94-b2f1-1715d6203853';
const serviceId = '14368d69-dd76-46f6-b490-583893b13cba', routeId = 'cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e';
const wid = 'a109e333-40a0-4965-966b-6b810f54e9b6', epochId = '40246f11-52ee-43c2-8ca9-71976d078848';
const nodeId = 'a'.repeat(64), observedNodeId = 'febd8e86-b117-45c2-831a-123e44d36e59', nativeToken = 'N'.repeat(43), catalogToken = 'C'.repeat(43);
const deferred = () => { let resolve!: (value?: any) => void; const promise = new Promise<any>(done => { resolve = done; }); return { promise, resolve }; };
const servers: Server[] = [];
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'bd'.repeat(32)));
afterEach(async () => { vi.unstubAllEnvs(); for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } });
async function fixture() {
  const state = { active: true, generation: 1, revision: 1, blocked: false, observedNode: observedNodeId, nativeText: 'kong_http_status{code="200",service="private-label.example",route="route-name"} 10\n', afterText: undefined as (() => void) | undefined, beforeText: undefined as (() => Promise<void>) | undefined, assigned: true };
  const execution = new KongExecutionContextService();
  const nativeCredentialId = serviceId, catalogCredentialId = routeId;
  const db: any = { one: vi.fn(async (sql: string, p: any[]) => {
    if (sql.includes('FROM metrics_nodes')) return { observed_kong_node_id: observedNodeId };
    if (sql.includes('FROM metrics_credentials')) {
      if (!state.active) return null;
      if (sql.includes('WHERE k.id=$1')) return p[4] === state.generation ? { id: p[0] } : null;
      if (p[0] !== cid || p[2] !== 'bff' || !['native_scrape', 'collector_catalog'].includes(p[1])) return null;
      const native = p[1] === 'native_scrape'; return { id: native ? nativeCredentialId : catalogCredentialId, cluster_id: cid, purpose: p[1], audience: 'bff', generation: state.generation, token_fingerprint: metricsTokenDigest(native ? nativeToken : catalogToken) };
    } throw new Error('Unexpected private bridge fixture SQL');
  }) };
  const credentials = new MetricsCredentialsService(db, new SecretService(), {} as any);
  const assignment = () => ({ epoch_id: epochId, cluster_id: cid, node_id: nodeId, entity_type: 'routes', entity_id: routeId, workspace_id: wid, service_id: serviceId, route_id: routeId, consumer_id: null, tags: [], service_label: 'private-label.example', route_label: 'route-name', valid_from: new Date(Date.now()-60_000).toISOString(), verified_until: new Date(Date.now()+15000).toISOString(), closed_at: null, quality: 'verified' });
  const repository: any = { currentAllowedEpochs: vi.fn(async () => ({ items: [], blocked: state.blocked, catalogRevision: state.revision, warnings: [] })), resolvePair: vi.fn(async () => ({ catalogRevision: state.revision, assignment: state.assigned ? assignment() : null })), catalog: vi.fn(async () => ({ items: [], catalogRevision: state.revision, credentialGeneration: state.generation })), validateEventBindings: vi.fn(async (_cid, input) => ({ catalogRevision: state.revision, credentialGeneration: state.generation, items: input.items.map(item => ({ index: item.index, quality: 'verified', routeEpoch: assignment() })) })) };
  const settings: any = { get: vi.fn(async () => ({ state: 'ready', catalogRevision: state.revision, credentialGeneration: state.generation, lastVerifiedAt: new Date().toISOString(), maxAgeMs: 15000 })) };
  const catalog: any = { ensureFresh: vi.fn(async () => undefined), nodeIdentity: vi.fn(async () => state.observedNode), scan: vi.fn(async () => undefined) };
  const kong: any = { transportScope: vi.fn(async () => nodeId), requestMetricsText: vi.fn(async () => { expect(execution.current().kind).toBe('system-read'); expect(execution.current().purpose).toBe('metrics-scrape'); expect(execution.current().actor).toBeUndefined(); await state.beforeText?.(); state.afterText?.(); return state.nativeText; }) };
  const service = new MetricsBridgeService(credentials, repository, settings, catalog, kong, execution, { rateLimit: vi.fn(async () => ({ allowed: true })) } as any, db);
  const server = createServer((req, res) => { void service.handle(req, res); }); servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as any).port;
  const send = async (path: string, options: any = {}) => { const response = await fetch(`http://127.0.0.1:${port}${path}`, { ...options, headers: { connection: 'close', ...options.headers } }); return { status: response.status, text: await response.text() }; };
  return { state, execution, credentials, repository, catalog, kong, service, port, send };
}
describe('M5 independent real isolated BFF listener and final identity checks', () => {
  it('scrapes under an actor-free system capability and exposes only immutable scope labels', async () => {
    const f = await fixture(), result = await f.send(`/scrape/${cid}`, { headers: { authorization: `Bearer ${nativeToken}` } });
    expect(result.status).toBe(200); expect(result.text).toContain(`service_id="${serviceId}"`); expect(result.text).toContain(`membership_epoch="${epochId}"`); expect(result.text).not.toContain('private-label.example'); expect(result.text).not.toContain('route-name');
  });
  it('denies public session cookies, cross-purpose/cross-cluster tokens and generic proxy parameters before native reads', async () => {
    const f = await fixture();
    for (const [path, headers] of [[`/scrape/${cid}`, { cookie: 'access=fake', authorization: `Bearer ${nativeToken}` }], [`/scrape/${cid}`, { authorization: 'Bearer eyJ.jwt.fake' }], [`/scrape/${cid}`, { authorization: `Bearer ${catalogToken}` }], [`/catalog/${cid}`, { authorization: `Bearer ${nativeToken}` }], [`/scrape/${otherCid}`, { authorization: `Bearer ${nativeToken}` }], [`/scrape/${cid}?path=/cache`, { authorization: `Bearer ${nativeToken}` }]] as const) expect((await f.send(path, { headers })).status).not.toBe(200);
    expect(f.kong.requestMetricsText).not.toHaveBeenCalled(); expect(f.repository.catalog).not.toHaveBeenCalled();
  });
  it('rejects duplicate Authorization raw headers rather than relying on Node first-header projection', async () => {
    const f = await fixture();
    const result = await new Promise<number>((resolve, reject) => { const req = httpRequest({ host: '127.0.0.1', port: f.port, path: `/scrape/${cid}`, headers: ['Host', `127.0.0.1:${f.port}`, 'Authorization', `Bearer ${nativeToken}`, 'Authorization', `Bearer ${catalogToken}`, 'Connection', 'close'] }, res => { res.resume(); res.on('end', () => resolve(res.statusCode!)); }); req.on('error', reject); req.end(); });
    expect(result).toBe(401); expect(f.kong.requestMetricsText).not.toHaveBeenCalled();
  });
  it('rejects final scrape output after token rotation, catalog revision changes or observed node rollover', async () => {
    for (const cause of ['token', 'catalog', 'node']) {
      const f = await fixture(); f.state.afterText = () => { if (cause === 'token') f.state.generation++; else if (cause === 'catalog') f.state.revision++; else f.state.observedNode = routeId; };
      const result = await f.send(`/scrape/${cid}`, { headers: { authorization: `Bearer ${nativeToken}` } }); expect(result.status).not.toBe(200); expect(result.text).not.toContain('kong_http_status');
    }
  });
  it('keeps ambiguous native labels unassigned without labeling them as a workspace', async () => {
    const f = await fixture(); f.state.assigned = false;
    const result = await f.send(`/scrape/${cid}`, { headers: { authorization: `Bearer ${nativeToken}` } }); expect(result.status).toBe(200); expect(result.text).toContain('attribution="unassigned"'); expect(result.text).not.toContain(wid); expect(result.text).not.toContain('private-label.example');
  });
  it('rejects native text if a durable pending write appeared at unchanged catalog revision and uses no candidate enumeration', async () => {
    const f = await fixture(); f.state.afterText = () => { f.state.blocked = true; };
    const result = await f.send(`/scrape/${cid}`, { headers: { authorization: `Bearer ${nativeToken}` } });
    expect(result.status).not.toBe(200); expect(result.text).not.toContain('kong_http_status');
    expect(f.repository.currentAllowedEpochs.mock.calls.at(-1)?.[1]).toEqual({ expectedCatalogRevision: 1, authorizedServiceIds: [], authorizedRouteIds: [], authorizedConsumerIds: [] });
  });
  it('does not accept collector tokens as ordinary HTTP identity or lift an existing HTTP actor into scrape system context', async () => {
    const f = await fixture(), identity = await f.credentials.validate(nativeToken, cid, 'native_scrape', 'bff');
    await expect(f.execution.runHttp({}, () => { f.execution.bindHttpActor({ id: serviceId, username: 'user', superAdmin: true }); return f.service.scrape(cid, identity); })).rejects.toMatchObject({ status: 403 }); expect(f.kong.requestMetricsText).not.toHaveBeenCalled();
  });
  it('projects collector validation to bounded interval IDs without disclosing labels or raw epoch tags', async () => {
    const f = await fixture(), result = await f.send(`/catalog/${cid}/validate`, { method: 'POST', headers: { authorization: `Bearer ${catalogToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ refs: [{ serviceId, routeId, startedAt: Date.now()-1000, endedAt: Date.now()-900 }] }) });
    expect(result.status).toBe(200); expect(JSON.parse(result.text).items[0]).toMatchObject({ serviceId, routeId, nodeId, workspaceId: wid, epochId }); expect(result.text).not.toContain('private-label'); expect(result.text).not.toContain('business_tags');
  });
});
