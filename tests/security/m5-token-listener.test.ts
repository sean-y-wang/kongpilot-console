import { request as httpRequest, type Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCollector } from '../../deploy/metrics-collector/collector.mjs';
import { fingerprint } from '../../deploy/metrics-collector/config.mjs';

const cid = '721bfeda-dc12-4d7a-b33e-06b2879a7ead', otherCid = 'de3aa362-52b1-4b94-b2f1-1715d6203853';
const serviceId = '14368d69-dd76-46f6-b490-583893b13cba', routeId = 'cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e';
const workspaceId = 'a109e333-40a0-4965-966b-6b810f54e9b6', epochId = '40246f11-52ee-43c2-8ca9-71976d078848';
const catalog = 'C'.repeat(43), ingest = 'I'.repeat(43), scrape = 'S'.repeat(43), now = 1_700_000_000_000;
const canary = 'SYNTHETIC-SECRET-ERROR-CANARY';
const raw = () => ({ service: { id: serviceId }, route: { id: routeId }, response: { status: 200 }, started_at: now - 1000, latencies: { request: 20 }, request: { headers: { authorization: canary }, body: canary } });
const row = (id = cid) => ({ clusterId: id, generation: 1, catalogToken: catalog, ingestFingerprint: fingerprint(ingest), scrapeFingerprint: fingerprint(scrape) });
const basic = (token = ingest) => `Basic ${Buffer.from(`kongos:${token}`).toString('base64')}`;
const servers: Server[] = [];
afterEach(async () => { for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } });
async function fixture(fetchOverride?: any) {
  let config = [row()];
  const fetchImpl = vi.fn(fetchOverride ?? (async (_url, init) => {
    const refs = JSON.parse(init.body).refs;
    return new Response(JSON.stringify({ catalogRevision: 1, credentialGeneration: config[0].generation, items: refs.map((ref, index) => ({ ...ref, index, clusterId: cid, quality: 'verified', nodeId: 'a'.repeat(64), workspaceId, epochId, validFrom: now - 10_000, validUntil: null })) }));
  }));
  const server = createCollector({ readConfig: () => config, fetchImpl, now: () => now }); servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as any).port;
  const send = async (path: string, options: any = {}) => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { ...options, headers: { connection: 'close', ...options.headers } });
    return { status: response.status, headers: response.headers, text: await response.text() };
  };
  const post = (body: any = raw(), auth = basic()) => send(`/ingest/${cid}`, { method: 'POST', headers: { authorization: auth, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { server, port, send, post, fetchImpl, rotate: () => { config = [{ ...row(), generation: 2, catalogToken: 'D'.repeat(43), ingestFingerprint: fingerprint('J'.repeat(43)), scrapeFingerprint: fingerprint('T'.repeat(43)) }]; } };
}
const deferred = () => { let resolve!: (value: any) => void; const promise = new Promise<any>(done => { resolve = done; }); return { promise, resolve }; };

describe('M5 independent actual Collector HTTP listener and purpose isolation', () => {
  it('authenticates valid ingest, independently authenticates every scrape, and reports approximation semantics', async () => {
    const f = await fixture();
    const accepted = await f.post([raw(), raw()]); expect(accepted.status).toBe(202); expect(JSON.parse(accepted.text)).toEqual({ accepted: 2, rejected: 0, semantics: 'at_least_once_approximate' });
    const metrics = await f.send(`/metrics/${cid}`, { headers: { authorization: `Bearer ${scrape}` } });
    expect(metrics.status).toBe(200); expect(metrics.text).toMatch(/kongos_collector_requests_total\{[^\n]*\} 2/); expect(metrics.text).not.toContain(canary);
    expect(f.fetchImpl).toHaveBeenCalledTimes(2); expect(JSON.parse(f.fetchImpl.mock.calls[1][1].body)).toEqual({ refs: [] });
  });
  it('rejects cookies, JWTs, catalog tokens, cross-purpose credentials and cluster substitution before calling BFF', async () => {
    const f = await fixture();
    for (const headers of [{ cookie: `access=${scrape}` }, { authorization: 'Bearer eyJ.fake.jwt' }, { authorization: `Bearer ${catalog}` }, { authorization: `Bearer ${ingest}` }, { authorization: basic(scrape) }]) {
      expect((await f.send(`/metrics/${cid}`, { headers })).status).toBe(401);
    }
    expect((await f.post(raw(), basic(catalog))).status).toBe(401);
    expect((await f.send(`/metrics/${otherCid}`, { headers: { authorization: `Bearer ${scrape}` } })).status).toBe(401);
    expect(f.fetchImpl).not.toHaveBeenCalled();
  });
  it('rejects duplicate Authorization fields using actual HTTP raw headers', async () => {
    const f = await fixture();
    const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const request = httpRequest({ host: '127.0.0.1', port: f.port, path: `/metrics/${cid}`, headers: ['Host', `127.0.0.1:${f.port}`, 'Authorization', `Bearer ${scrape}`, 'Authorization', `Bearer ${scrape}`, 'Connection', 'close'] }, response => { let body = ''; response.on('data', part => { body += part; }); response.on('end', () => resolve({ status: response.statusCode!, body })); }); request.on('error', reject); request.end();
    });
    expect(result.status).toBe(401); expect(f.fetchImpl).not.toHaveBeenCalled();
  });
  it('has exact listener routes and never accepts URL/query/path proxy parameters', async () => {
    const f = await fixture();
    for (const path of [`/metrics/${cid}?url=http://untrusted`, `/api/v1/metrics/${cid}`, `/ingest/${cid}/extra`, '/catalog/'+cid]) expect((await f.send(path)).status).toBe(404);
    expect((await f.send(`/ingest/${cid}`)).status).toBe(405); expect((await f.send('/healthz')).status).toBe(200);
    expect(f.fetchImpl).not.toHaveBeenCalled();
  });
  it('bounds input bytes and returns only a safe code on malformed secret-bearing payloads', async () => {
    const f = await fixture();
    const invalid = await f.send(`/ingest/${cid}`, { method: 'POST', headers: { authorization: basic(), 'content-type': 'application/json' }, body: '{'+canary });
    expect(invalid.status).toBe(400); expect(JSON.parse(invalid.text)).toEqual({ error: { code: 'COLLECTOR_JSON_INVALID' } }); expect(invalid.text).not.toContain(canary);
    const large = await f.post({ padding: 'x'.repeat(2 * 1024 * 1024), password: canary }); expect(large.status).toBe(413); expect(large.text).not.toContain(canary); expect(f.fetchImpl).not.toHaveBeenCalled();
    expect((await f.send(`/ingest/${cid}`, { method: 'POST', headers: { authorization: basic(), 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: '{}' })).status).toBe(415);
  });
  it('does not count an event if credentials rotate while its fresh catalog verification is in flight', async () => {
    const gate = deferred(), entered = deferred();
    const f = await fixture(async () => { entered.resolve(null); return gate.promise; });
    const request = f.post(); await entered.promise; f.rotate();
    gate.resolve(new Response(JSON.stringify({ catalogRevision: 1, credentialGeneration: 1, items: [{ index: 0, serviceId, routeId, clusterId: cid, quality: 'verified', nodeId: 'a'.repeat(64), workspaceId, epochId, validFrom: now - 10_000, validUntil: null }] })));
    const result = await request; expect(result.status).toBe(401); expect(JSON.parse(result.text)).toEqual({ error: { code: 'METRICS_TOKEN_INVALID' } });
    expect((await f.send(`/metrics/${cid}`, { headers: { authorization: `Bearer ${scrape}` } })).status).toBe(401);
  });
  it('refuses a scrape after database generation validation fails and does not serve cached counters', async () => {
    const f = await fixture(async () => new Response(JSON.stringify({ error: { message: canary } }), { status: 401 }));
    const result = await f.send(`/metrics/${cid}`, { headers: { authorization: `Bearer ${scrape}` } });
    expect(result.status).toBe(503); expect(JSON.parse(result.text)).toEqual({ error: { code: 'COLLECTOR_CATALOG_UNAVAILABLE' } }); expect(result.text).not.toContain(canary);
  });
});
