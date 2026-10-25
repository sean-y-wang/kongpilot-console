import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VitalsService } from '../../apps/console-api/src/modules/vitals/vitals.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { LokiProvider } from '../../apps/console-api/src/modules/vitals/providers/loki.provider';
import { PrometheusProvider } from '../../apps/console-api/src/modules/vitals/providers/prometheus.provider';
import { MetricsQueryBudget } from '../../apps/console-api/src/modules/vitals/providers/query-budget';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const transport = vi.mocked(outboundJson);
const cid = '7ec38626-fb8a-4f8b-a2e9-0f9390b11c9c', wid = '5700ad8a-acba-4b7e-8bd8-ecc6d515febb';
const sid = '9080c396-c30f-466d-8fb5-a3a37f9cd6b6', rid = '46d4d6bb-ab43-45aa-953a-f657d44c20c6';
const epochId = '4c4b8c83-e48a-44b2-b5a8-613a5d96ac07', uid = '5c544f66-49da-42a1-a066-c8f7d8ed55d1';
const now = Date.parse('2026-10-10T20:18:00.000Z'), firstLogSample = Date.parse('2026-10-10T20:15:45.000Z');
const actor = { user: { id: uid, username: 'grid-monitor', superAdmin: false } };
const original = { workspaceId: wid, start: '2026-10-10T20:12:01.000Z', end: '2026-10-10T20:17:01.000Z', step: 15 };
const matrix = (rows: any[], type = 'matrix') => ({ status: 200, body: { status: 'success', data: { resultType: type, result: rows } }, bytes: 200 });
beforeEach(() => { transport.mockReset(); vi.spyOn(Date, 'now').mockReturnValue(now); });
afterEach(() => vi.restoreAllMocks());

/** Actual public service, request ancestors, Loki/Prom provider, strict parsers
 * and budgets. Authorized scope/current metadata are explicit fixtures. The
 * Loki fixture reproduces the actual global grid and end overhang diagnosed at
 * artifacts/M5/loki-fixed-window-diagnosis.json, without querying live data. */
function fixture(type: 'loki' | 'prometheus' = 'loki') {
  const execution = new KongExecutionContextService();
  const epoch: any = { epoch_id: epochId, cluster_id: cid, node_id: 'a'.repeat(64), entity_type: 'routes', entity_id: rid,
    workspace_id: wid, service_id: sid, route_id: rid, consumer_id: null, tags: [], quality: 'verified', closed_at: null,
    valid_from: '2026-10-10T20:15:31.254Z', verified_until: new Date(now + 15000).toISOString() };
  const resolved: any = { workspaceId: wid, mode: 'workspace', version: 'current', wholeCluster: false,
    epochs: [epoch], consumerPairEpochs: [], serviceNames: new Map([[sid, 'display-only']]), consumerNames: new Map() };
  const scope: any = { resolve: vi.fn(async () => resolved), stable: vi.fn(async () => undefined) };
  const source: any = { id: sid, name: 'authorized-source', type, baseUrl: 'http://authorized-private-provider', auth: null, revision: 1 };
  const sources: any = { read: vi.fn(async () => source), public: vi.fn(() => ({ id: sid, name: source.name, type, status: 'healthy', availability: 'available' })), assertCurrent: vi.fn(async () => undefined) };
  const settings: any = { get: vi.fn(async () => ({ revision: 1, catalogRevision: 1, credentialGeneration: 1, state: 'ready',
    enabled: true, collectorEnabled: true, activeSourceId: sid, lastVerifiedAt: new Date(now).toISOString(), maxAgeMs: 15000 })) };
  const repository: any = { currentAllowedEpochs: vi.fn(async () => ({ items: [epoch], blocked: false, warnings: [], catalogRevision: 1 })) };
  const db: any = { one: vi.fn(async () => ({ id: cid, name: 'fixture', revision: 1, version: '1.5.1', execution_mode: 'direct' })) };
  const service = new VitalsService(scope, sources, settings, {} as any, db, repository, {} as any, execution, {} as any, {} as any, {} as any, {} as any);
  transport.mockImplementation(async (_base, path, _method, _body, params) => {
    const expression = String(params?.query);
    if (path.endsWith('/query')) return matrix(expression.includes('sum by(service_id)') ? [{ metric: { service_id: sid }, value: [type === 'loki' ? Date.parse(String(params!.time)) / 1000 : Number(params!.time), '0.3'] }] : [], 'vector');
    if (!expression.includes('sum by(code)')) return matrix([]);
    const start = type === 'loki' ? Date.parse(String(params!.start)) : Number(params!.start) * 1000;
    const end = type === 'loki' ? Date.parse(String(params!.end)) : Number(params!.end) * 1000, step = Number(params!.step) * 1000;
    const begin = type === 'loki' ? Math.ceil(Math.max(firstLogSample, start) / step) * step : start;
    const last = type === 'loki' ? Math.ceil(end / step) * step : end;
    const values: Array<[number, string]> = [];
    for (let ts = begin; ts <= last; ts += step) values.push([ts / 1000, '0.3']);
    return matrix(values.length ? [{ metric: { code: '200' }, values }] : []);
  });
  const overview = (query: any = original) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor.user, 'real-context-fixture');
    return service.overview(cid, query, actor);
  });
  return { service, overview, epoch, source };
}

describe('M5 independent source-specific Loki evaluation grid', () => {
  it.each([
    ['unaligned seconds', original],
    ['subsecond bounds', { ...original, start: '2026-10-10T20:12:01.123Z', end: '2026-10-10T20:17:01.987Z' }],
    ['high sampling interval', { ...original, step: 60 }],
  ])('uses a real inward grid for %s and echoes requested/effective windows separately', async (_label, query) => {
    const f = fixture(); f.epoch.valid_from = '2026-10-10T20:00:00.000Z';
    const result: any = await f.overview(query), step = Number(query.step) * 1000;
    const start = Math.ceil(Date.parse(query.start) / step) * step, end = Math.floor(Date.parse(query.end) / step) * step;
    expect(result.requestedWindow).toMatchObject({ start: query.start, end: query.end, step: query.step });
    expect(result.timeWindow).toMatchObject({ start: new Date(start).toISOString(), end: new Date(end).toISOString(), step: query.step });
    expect(result.evaluationAt).toBe(new Date(end).toISOString());
    expect(result.quality.reasonCodes).toContain('LOKI_EVALUATION_GRID_ALIGNED');
    expect(result.quality.reasonCodes).not.toContain('METRICS_SOURCE_QUERY_FAILED');
    expect(result.cards.qps.value).toBe(0.3); expect(result.topN.services).toEqual([{ id: sid, name: 'display-only', value: 0.3 }]);
    for (const points of Object.values(result.series) as any[]) for (const point of points) {
      expect(point.ts).toBeGreaterThanOrEqual(Date.parse(query.start)); expect(point.ts).toBeLessThanOrEqual(Date.parse(query.end));
      expect(point.ts % step).toBe(0);
    }
    expect(result.series.qps.at(-1)).toEqual({ ts: end, value: 0.3 });
    for (const call of transport.mock.calls) if (call[1].endsWith('query_range')) expect(call[4]).toMatchObject({ start: new Date(start).toISOString(), end: new Date(end).toISOString(), step: query.step });
  });
  it('retains the exact current-epoch rate mask despite inward grid alignment', async () => {
    const f = fixture(), result = await f.overview();
    expect(result.series.qps.find(point => point.ts === Date.parse('2026-10-10T20:16:30.000Z'))?.value).toBeNull();
    expect(result.series.qps.find(point => point.ts === Date.parse('2026-10-10T20:16:45.000Z'))?.value).toBe(0.3);
    expect(result.cards.qps.value).toBe(0.3); expect(result.quality.reasonCodes).toContain('LOKI_CURRENT_EPOCH_WINDOW_INCOMPLETE');
  });
  it('does not announce alignment or add a second window when the requested Loki bounds are already aligned', async () => {
    const f = fixture(), result: any = await f.overview({ ...original, start: '2026-10-10T20:12:00.000Z', end: '2026-10-10T20:17:00.000Z' });
    expect(result.requestedWindow).toBeUndefined(); expect(result.quality.reasonCodes).not.toContain('LOKI_EVALUATION_GRID_ALIGNED'); expect(result.cards.qps.value).toBe(0.3);
  });
  it.each([3600, 86400])('rejects a valid five-minute request with no effective point at step %s before any provider call', async step => {
    const f = fixture(); await expect(f.overview({ ...original, step })).rejects.toMatchObject({ status: 400, response: { code: 'LOKI_EVALUATION_WINDOW_EMPTY' } });
    expect(transport).not.toHaveBeenCalled();
  });
  it('preserves Prometheus start-relative points and metadata instead of imposing Loki alignment globally', async () => {
    const f = fixture('prometheus'), result: any = await f.overview();
    expect(result.requestedWindow).toBeUndefined(); expect(result.timeWindow).toMatchObject({ start: original.start, end: original.end });
    expect(result.evaluationAt).toBe(original.end); expect(result.cards.qps.value).toBe(0.3);
    expect(result.series.qps[0].ts).toBe(Date.parse(original.start)); expect(result.series.qps.at(-1).ts).toBe(Date.parse(original.end));
    expect(result.quality.reasonCodes).not.toContain('LOKI_EVALUATION_GRID_ALIGNED');
  });
  it.each(['loki', 'prometheus'])('continues to reject %s off-grid and out-of-bounds samples rather than clamping or relabelling them', async type => {
    const f = fixture(type as 'loki' | 'prometheus'), window = { start: '2026-10-10T20:12:15.000Z', end: '2026-10-10T20:17:00.000Z', step: 15, rateWindowSeconds: 60 };
    for (const ts of [Date.parse(window.start) - 15000, Date.parse(window.start) + 1000, Date.parse(window.end) + 15000]) {
      transport.mockResolvedValue(matrix([{ metric: { code: '200' }, values: [[ts / 1000, '0.3']] }]));
      const provider = type === 'loki' ? new LokiProvider() : new PrometheusProvider();
      await expect(provider.range(f.source, 'server-owned-template', window, new MetricsQueryBudget())).rejects.toMatchObject({ response: { code: 'INVALID_METRICS_RESPONSE' } });
    }
  });
});
