import { describe, expect, it, vi } from 'vitest';
import { sanitizeBatch, sanitizeEvent } from '../../deploy/metrics-collector/sanitize.mjs';
import { validateAssignments } from '../../deploy/metrics-collector/catalog.mjs';
import { CollectorCounters } from '../../deploy/metrics-collector/counters.mjs';
import { pushSanitizedLoki } from '../../deploy/metrics-collector/loki.mjs';

const cid = '721bfeda-dc12-4d7a-b33e-06b2879a7ead', serviceId = '14368d69-dd76-46f6-b490-583893b13cba';
const routeId = 'cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e', consumerId = 'f4095396-0771-4b02-9f09-2739a1809c0d';
const workspaceId = 'a109e333-40a0-4965-966b-6b810f54e9b6', epochId = '40246f11-52ee-43c2-8ca9-71976d078848';
const nodeId = 'a'.repeat(64), now = 1_700_000_000_000, canary = 'SYNTHETIC-SECRET-DO-NOT-EXPORT';
const config = { clusterId: cid, generation: 1, catalogToken: 'C'.repeat(43) };
function raw(extra: any = {}) { return { service: { id: serviceId, url: canary }, route: { id: routeId }, response: { status: 200, size: 0, headers: { authorization: canary } }, request: { size: 10, url: canary, querystring: { api_key: canary }, body: canary }, started_at: now - 1000, latencies: { request: 20, kong: 0, proxy: 10, token: canary }, ...extra }; }
const event = () => sanitizeEvent(raw(), now)!;
function reply(refs: any[], extra: any = {}) { return { catalogRevision: 1, credentialGeneration: 1, items: refs.map((ref, index) => ({ ...ref, index, clusterId: cid, quality: 'verified', nodeId, workspaceId, epochId, validFrom: now - 10_000, validUntil: null, ...(ref.consumerId ? { consumerEpochId: epochId } : {}) })), ...extra }; }
const response = (value: any) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });

describe('M5 independent actual collector event projection', () => {
  it('constructs a minimal whitelist and preserves genuine zero without retaining request secrets', () => {
    const projected = event();
    expect(projected).toEqual({ serviceId, routeId, status: 200, startedAt: now - 1000, endedAt: now - 980, latencies: { request: 20, kong: 0, proxy: 10 }, requestBytes: 10, responseBytes: 0 });
    expect(JSON.stringify(projected)).not.toContain(canary);
    expect(JSON.stringify(projected)).not.toMatch(/headers|querystring|url|body|token/);
  });
  it.each([0, 42, 1_073_741_824, '0', '123', '1073741824'])('normalizes genuine Kong 1.5 serializer size %s into finite numeric bytes', size => {
    const projected = sanitizeEvent(raw({ request: { size, url: canary }, response: { status: 200, size, headers: { cookie: canary } } }), now)!;
    expect(projected.requestBytes).toBe(Number(size)); expect(projected.responseBytes).toBe(Number(size));
    expect(Number.isFinite(projected.requestBytes)).toBe(true); expect(Number.isSafeInteger(projected.responseBytes)).toBe(true);
    expect(JSON.stringify(projected)).not.toContain(canary);
  });
  it('omits malformed optional byte fields without coercing them to zero or rejecting the otherwise valid request', () => {
    const invalid = [undefined, null, false, true, -1, 1.5, NaN, Infinity, -Infinity, 1_073_741_825,
      '', ' ', ' 1', '1 ', '-1', '+1', '1.0', '1.5', '1e3', '0x10', '00', '01', 'NaN', 'Infinity', '1073741825', '12345678901', {}, [], { value: '12' }, canary];
    for (const size of invalid) {
      const projected = sanitizeEvent(raw({ request: { size, body: canary }, response: { status: 200, size } }), now)!;
      expect(projected).not.toBeNull(); expect(projected).not.toHaveProperty('requestBytes'); expect(projected).not.toHaveProperty('responseBytes');
      expect(projected.status).toBe(200); expect(JSON.stringify(projected)).not.toContain(canary);
    }
  });
  it('requires own byte-size properties and never treats a prototype or numeric wrapper as native serializer data', () => {
    const request = Object.create({ size: '123' }), response = Object.create({ size: '456' }); response.status = 200;
    const projected = sanitizeEvent(raw({ request, response }), now)!;
    expect(projected).not.toHaveProperty('requestBytes'); expect(projected).not.toHaveProperty('responseBytes');
    const boxed = sanitizeEvent(raw({ request: { size: new Number(123) }, response: { status: 200, size: new String('456') } }), now)!;
    expect(boxed).not.toHaveProperty('requestBytes'); expect(boxed).not.toHaveProperty('responseBytes');
  });
  it('limits decimal-string conversion to byte fields and preserves numeric-only duration/time/status checks', () => {
    expect(sanitizeEvent(raw({ request: { size: '123' }, response: { status: 200, size: '456' }, latencies: { request: '20' } }), now)).toBeNull();
    expect(sanitizeEvent(raw({ started_at: String(now - 1000) }), now)).toBeNull();
    expect(sanitizeEvent(raw({ response: { status: '200', size: '456' } }), now)).toBeNull();
    const projected = sanitizeEvent(raw({ request: { size: '123' }, latencies: { request: 20, kong: '5', proxy: '10' } }), now)!;
    expect(projected.requestBytes).toBe(123); expect(projected.latencies).toEqual({ request: 20 });
  });
  it('counts actual serializer decimal strings as numeric bytes and sends only the numeric flat Loki schema', async () => {
    const projected = sanitizeEvent(raw({ request: { size: '123', url: canary, body: canary }, response: { status: 200, size: '456', headers: { authorization: canary } } }), now)!;
    const assignment = { quality: 'verified', nodeId, workspaceId, epochId }, counters = new CollectorCounters();
    counters.add(cid, [projected, projected], [assignment, assignment]);
    const rendered = counters.render(cid);
    expect(rendered).toMatch(/kongos_collector_requests_total\{[^\n]*\} 2/);
    expect(rendered).toMatch(/kongos_collector_request_bytes_total\{[^\n]*\} 246/);
    expect(rendered).toMatch(/kongos_collector_response_bytes_total\{[^\n]*\} 912/); expect(rendered).not.toContain(canary);
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    await pushSanitizedLoki(cid, [projected, projected], [assignment, assignment], { fetchImpl });
    const payload = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(payload.streams).toHaveLength(2);
    for (const stream of payload.streams) expect(JSON.parse(stream.values[0][1])).toEqual({ code: '200', latency_request_ms: 20, latency_upstream_ms: 10, latency_kong_ms: 0, bytes_ingress: 123, bytes_egress: 456 });
    expect(fetchImpl.mock.calls[0][1].body).not.toContain(canary); expect(fetchImpl.mock.calls[0][1].body).not.toMatch(/headers|querystring|url|body|authorization/);
  });
  it('keeps absent or invalid Loki byte observations null while preserving a real zero', async () => {
    const invalid = sanitizeEvent(raw({ request: { size: '1e3' }, response: { status: 200, size: undefined } }), now)!;
    const zero = sanitizeEvent(raw({ request: { size: '0' }, response: { status: 200, size: '0' } }), now)!;
    const assignment = { quality: 'verified', nodeId, workspaceId, epochId }, fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    await pushSanitizedLoki(cid, [invalid, zero], [assignment, assignment], { fetchImpl });
    const lines = JSON.parse(fetchImpl.mock.calls[0][1].body).streams.map((stream: any) => JSON.parse(stream.values[0][1]));
    expect(lines[0]).toMatchObject({ bytes_ingress: null, bytes_egress: null }); expect(lines[1]).toMatchObject({ bytes_ingress: 0, bytes_egress: 0 });
  });
  it('rejects inherited identities and missing request duration rather than fabricating attribution or zero', () => {
    expect(sanitizeEvent(raw({ service: Object.create({ id: serviceId }) }), now)).toBeNull();
    expect(sanitizeEvent(Object.create(raw()), now)).toBeNull();
    for (const request of [undefined, null, -1, NaN, Infinity, '20']) expect(sanitizeEvent(raw({ latencies: { request } }), now)).toBeNull();
  });
  it('keeps an authenticated 401 event with unknown upstream latency and omits that latency', () => {
    expect(sanitizeEvent(raw({ consumer: { id: consumerId }, response: { status: 401 }, latencies: { request: 5, kong: 5, proxy: -1 } }), now)).toMatchObject({ consumerId, status: 401, latencies: { request: 5, kong: 5 } });
    expect(sanitizeEvent(raw({ response: { status: 401 }, latencies: { request: 5, proxy: -1 } }), now)!.latencies).not.toHaveProperty('proxy');
  });
  it('enforces the five-minute lateness and whole-request end interval boundaries', () => {
    expect(sanitizeEvent(raw({ started_at: now - 300_000 }), now)).not.toBeNull();
    expect(sanitizeEvent(raw({ started_at: now - 300_001 }), now)).toBeNull();
    expect(sanitizeEvent(raw({ started_at: now + 990, latencies: { request: 10 } }), now)).not.toBeNull();
    expect(sanitizeEvent(raw({ started_at: now + 990, latencies: { request: 11 } }), now)).toBeNull();
    expect(sanitizeEvent(raw({ response: { status: 600 } }), now)).toBeNull();
    expect(sanitizeEvent(raw({ consumer: { id: 'username' } }), now)).toBeNull();
  });
  it('rounds fractional serializer timestamps outwards so an event cannot be moved inside an epoch boundary', () => {
    const projected = sanitizeEvent(raw({ started_at: now - 1000.4, latencies: { request: 0.2 } }), now)!;
    expect(projected.startedAt).toBe(now - 1001); expect(projected.endedAt).toBe(now - 1000);
    expect(projected.startedAt).toBeLessThanOrEqual(now - 1000.4); expect(projected.endedAt).toBeGreaterThanOrEqual(now - 1000.2);
    expect(sanitizeEvent(raw({ started_at: now - 299999.4, latencies: { request: 300000 } }), now)).toBeNull();
  });
  it('bounds a batch without serializing rejected inputs or collapsing legitimate duplicates', () => {
    expect(sanitizeBatch([raw(), raw(), { secret: canary }], now)).toMatchObject({ events: [event(), event()], safeRejectedCount: 1 });
    expect(() => sanitizeBatch([], now)).toThrow(); expect(() => sanitizeBatch(Array(1001).fill(raw()), now)).toThrow();
    const counters = new CollectorCounters(); counters.add(cid, [event(), event()], [{ quality: 'verified', nodeId, workspaceId, epochId }, { quality: 'verified', nodeId, workspaceId, epochId }]);
    expect(counters.render(cid)).toMatch(/kongos_collector_requests_total\{[^\n]*\} 2/);
    expect(counters.render(cid)).not.toContain(canary);
  });
  it('reserves all new series before counting any part of an overflowing batch', () => {
    const counters = new CollectorCounters({ maxSeries: 1 }), assignment = { quality: 'verified', nodeId, workspaceId, epochId };
    counters.add(cid, [event()], [assignment]);
    expect(() => counters.add(cid, [event(), { ...event(), status: 201 }], [assignment, assignment])).toThrow();
    expect(counters.render(cid)).toMatch(/kongos_collector_requests_total\{[^\n]*\} 1/);
  });
  it('ships only projected fields to the fixed Loki endpoint and never follows redirects', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    await pushSanitizedLoki(cid, [event()], [{ quality: 'verified', nodeId, workspaceId, epochId }], { fetchImpl });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('http://loki:3100/loki/api/v1/push'); expect(init.redirect).toBe('error');
    expect(init.body).not.toContain(canary); expect(init.body).not.toMatch(/headers|querystring|api_key/);
  });
});

describe('M5 independent fresh bounded collector catalog authority', () => {
  it('splits by native reference count and preserves every duplicate event and index', async () => {
    const events = Array.from({ length: 171 }, () => ({ ...event(), consumerId }));
    const fetchImpl = vi.fn(async (_url, init) => response(reply(JSON.parse(init.body).refs)));
    const assignments = await validateAssignments(config, events, { fetchImpl, now: () => now, deadline: now + 10_000 });
    expect(assignments).toHaveLength(171); expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(fetchImpl.mock.calls.map(([, init]) => JSON.parse(init.body).refs.length)).toEqual([85, 85, 1]);
    for (const [url, init] of fetchImpl.mock.calls) { expect(url).toBe(`http://metrics-bff:9092/catalog/${cid}/validate`); expect(init.redirect).toBe('error'); expect(init.body).not.toContain(canary); }
  });
  it('performs a fresh empty probe on scrape and refuses a rotated family generation', async () => {
    const fetchImpl = vi.fn(async (_url, init) => response(reply(JSON.parse(init.body).refs)));
    await validateAssignments(config, [], { fetchImpl, now: () => now, deadline: now + 5000 });
    expect(JSON.parse(fetchImpl.mock.calls[0][1].body)).toEqual({ refs: [] });
    await expect(validateAssignments(config, [event()], { fetchImpl: async () => response(reply([event()], { credentialGeneration: 2 })), now: () => now, deadline: now + 5000 })).rejects.toMatchObject({ code: 'COLLECTOR_CATALOG_INVALID' });
  });
  it('requires the entire event interval inside one matching workspace epoch', async () => {
    for (const mutation of [{ validFrom: now - 999 }, { validUntil: now - 981 }, { workspaceId: 'invalid' }, { serviceId: consumerId }, { clusterId: consumerId }, { nodeId: epochId }]) {
      const data = reply([event()]); Object.assign(data.items[0], mutation);
      await expect(validateAssignments(config, [event()], { fetchImpl: async () => response(data), now: () => now, deadline: now + 5000 })).rejects.toMatchObject({ code: 'COLLECTOR_CATALOG_INVALID' });
    }
    const unknown = reply([event()]); unknown.items[0].quality = 'blocked';
    expect(await validateAssignments(config, [event()], { fetchImpl: async () => response(unknown), now: () => now, deadline: now + 5000 })).toEqual([null]);
  });
  it('rejects duplicate response indices, compressed/oversized authority replies and arbitrary bridge URLs', async () => {
    const data = reply([event(), event()]); data.items[1].index = 0;
    await expect(validateAssignments(config, [event(), event()], { fetchImpl: async () => response(data), now: () => now, deadline: now + 5000 })).rejects.toMatchObject({ code: 'COLLECTOR_CATALOG_INVALID' });
    for (const bad of [new Response('{}', { headers: { 'content-encoding': 'gzip' } }), new Response(' '.repeat(2 * 1024 * 1024 + 1))]) {
      await expect(validateAssignments(config, [], { fetchImpl: async () => bad, now: () => now, deadline: now + 5000 })).rejects.toMatchObject({ code: 'COLLECTOR_CATALOG_UNAVAILABLE' });
    }
    const fetchImpl = vi.fn(); await expect(validateAssignments(config, [], { bridge: 'http://untrusted', fetchImpl })).rejects.toMatchObject({ code: 'COLLECTOR_CATALOG_CONFIGURATION_INVALID' }); expect(fetchImpl).not.toHaveBeenCalled();
  });
});
