import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LokiProvider } from '../../apps/console-api/src/modules/vitals/providers/loki.provider';
import { fixedLogql, currentLokiAssignments } from '../../apps/console-api/src/modules/vitals/providers/logql';
import { MetricsQueryBudget } from '../../apps/console-api/src/modules/vitals/providers/query-budget';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import type { MetricsScope } from '../../apps/console-api/src/modules/vitals/metrics-scope.service';
import type { MetricsAssignment } from '../../apps/console-api/src/modules/metrics/metrics.types';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const transport = vi.mocked(outboundJson);
const cid = '721bfeda-dc12-4d7a-b33e-06b2879a7ead', wid = 'a109e333-40a0-4965-966b-6b810f54e9b6';
const serviceId = '14368d69-dd76-46f6-b490-583893b13cba', routeId = 'cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e';
const consumerId = 'f4095396-0771-4b02-9f09-2739a1809c0d', epochId = '40246f11-52ee-43c2-8ca9-71976d078848', consumerEpochId = '9b9c7ab2-6c18-4b15-ac98-7f68a6b94d57';
const first = Date.parse('2026-10-10T11:55:00Z'), now = Date.parse('2026-10-10T12:00:00Z');
const window = { start: new Date(first).toISOString(), end: new Date(now).toISOString(), step: 15, rateWindowSeconds: 60 };
const pair: MetricsAssignment = { epoch_id: epochId, cluster_id: cid, node_id: 'a'.repeat(64), entity_type: 'routes', entity_id: routeId, workspace_id: wid, service_id: serviceId, route_id: routeId, consumer_id: null, tags: [], service_label: 'service', route_label: 'route', valid_from: new Date(first - 120000).toISOString(), verified_until: new Date(now + 15000).toISOString(), closed_at: null, quality: 'verified' };
const consumer: MetricsAssignment = { ...pair, epoch_id: consumerEpochId, entity_type: 'consumers', entity_id: consumerId, consumer_id: consumerId, service_id: null, route_id: null };
const scope = (): MetricsScope => ({ workspaceId: wid, mode: 'workspace', version: 'permission-1', wholeCluster: false, epochs: [pair, consumer], consumerPairEpochs: [pair], serviceNames: new Map([[serviceId, 'authorized-service']]), consumerNames: new Map([[consumerId, 'authorized-consumer']]) });
const source: any = { id: serviceId, name: 'registered-loki', type: 'loki', baseUrl: 'http://approved-loki:3100', auth: { type: 'bearer', token: 'test-only-loki-fixture-credential' }, revision: 1 };
const response = (result: any[], instant = false) => ({ status: 200, body: { status: 'success', data: { resultType: instant ? 'vector' : 'matrix', result } } });
const ranged = (value: string, metric = {}) => ({ metric, values: [[first / 1000, value], [(first + 60000) / 1000, value]] });
const instantaneous = (value: string, metric = {}) => ({ metric, value: [now / 1000, value] });
beforeEach(() => { transport.mockReset(); });
function actualResponses() {
  transport.mockImplementation(async (_base, path, _method, _body, query) => {
    const logql = String(query?.query);
    if (logql.includes('sum by(code)')) return response([ranged('2', { code: '200' }), ranged('0', { code: '404' })]);
    if (logql.includes('quantile_over_time')) return response([ranged('1500')]);
    if (logql.includes('bytes_ingress')) return response([ranged('1024', { type: 'ingress' }), ranged('NaN', { type: 'egress' })]);
    if (logql.includes('sum by(service_id)')) return response([instantaneous('2', { service_id: serviceId }), instantaneous('999', { service_id: consumerId })], true);
    if (logql.includes('sum by(consumer_id)')) return response([instantaneous('0', { consumer_id: consumerId }), instantaneous('999', { consumer_id: serviceId })], true);
    throw new Error('Unexpected fixed Loki query');
  });
}
describe('M5 actual Loki provider', () => {
  it('computes all actual units and TopN through exactly13 bounded calls, never node requests', async () => {
    actualResponses(); const budget = new MetricsQueryBudget(), result = await new LokiProvider().evaluate(source, cid, scope(), window, budget, true);
    expect(result.series.qps[0].value).toBe(2); expect(result.series.status4xx[0].value).toBe(0); expect(result.series.status5xx[0].value).toBeNull();
    for (const name of ['latencyRequestP50', 'latencyUpstreamP95', 'latencyKongP99'] as const) expect(result.series[name][0].value).toBe(1500);
    expect(result.series.bandwidthIngress[0].value).toBe(1024); expect(result.series.bandwidthEgress[0].value).toBeNull();
    expect(result.topN.services).toEqual([{ id: serviceId, name: 'authorized-service', value: 2 }]); expect(result.topN.consumers).toEqual([{ id: consumerId, name: 'authorized-consumer', value: 0 }]);
    expect(result.nodes).toEqual([]); expect(result.reasonCodes).toContain('LOKI_NODE_METRICS_UNSUPPORTED'); expect(result.reasonCodes).toContain('LOKI_LOG_DELIVERY_AT_LEAST_ONCE');
    expect(budget.snapshot().calls).toBe(13); expect(transport.mock.calls.every(call => call[0] === source.baseUrl && call[1].startsWith('/loki/api/v1/') && call[2] === 'GET' && call[5] === source.auth)).toBe(true);
    expect(transport.mock.calls[0][4]).toMatchObject({ start: window.start, end: window.end, step: 15 });
  });
  it('keeps newly opened log windows null rather than extrapolating incomplete attribution', async () => {
    actualResponses(); const selected = scope(); selected.epochs = [{ ...pair, valid_from: window.start }, consumer];
    const result = await new LokiProvider().evaluate(source, cid, selected, window, new MetricsQueryBudget(), true);
    expect(result.series.qps[0].value).toBeNull(); expect(result.series.qps[4].value).toBe(2); expect(result.reasonCodes).toContain('LOKI_CURRENT_EPOCH_WINDOW_INCOMPLETE');
  });
  it('supports Consumer-only scope without exposing unrelated traffic or Service TopN', async () => {
    actualResponses(); const selected = scope(); selected.epochs = [consumer]; selected.serviceNames.clear();
    const result = await new LokiProvider().evaluate(source, cid, selected, window, new MetricsQueryBudget(), true);
    expect(result.series.qps.every(point => point.value === null)).toBe(true); expect(result.topN.services).toEqual([]); expect(result.topN.consumers[0].id).toBe(consumerId); expect(transport).toHaveBeenCalledTimes(1);
  });
  it('returns explicit missing-channel quality with no upstream calls when collector is disabled', async () => {
    const result = await new LokiProvider().evaluate(source, cid, scope(), window, new MetricsQueryBudget(), false);
    expect(result.series.qps.every(point => point.value === null)).toBe(true); expect(result.reasonCodes).toContain('LOKI_COLLECTOR_NOT_ENABLED'); expect(transport).not.toHaveBeenCalled();
  });
  it('does not swallow cumulative budget exhaustion or an actual provider HTTP failure', async () => {
    actualResponses(); await expect(new LokiProvider().evaluate(source, cid, scope(), window, new MetricsQueryBudget({ calls: 1, bytes: 8388608, series: 64, points: 51200 }), true)).rejects.toMatchObject({ status: 409 });
    transport.mockResolvedValue({ status: 503, body: {} }); await expect(new LokiProvider().evaluate(source, cid, scope(), window, new MetricsQueryBudget(), true)).rejects.toMatchObject({ status: 502 });
  });
  it('rejects duplicate aggregate rows and malformed matrix/sample bodies', async () => {
    for (const rows of [[ranged('1', { code: '200' }), ranged('2', { code: '200' })], [ranged('1', { code: 'fake' })], [{ metric: { code: '200' }, values: [[first / 1000, '0x10']] }]]) {
      transport.mockResolvedValue(response(rows)); await expect(new LokiProvider().evaluate(source, cid, scope(), window, new MetricsQueryBudget(), true)).rejects.toMatchObject({ status: 502 });
    }
  });
  it('validates exact current identities before queries and forbids configurable expressions', () => {
    const queries = fixedLogql(cid, scope(), window);
    for (const selector of [`cluster_id="${cid}"`, `epoch_id="${epochId}"`, `workspace_id="${wid}"`, `service_id="${serviceId}"`, `route_id="${routeId}"`, `node_id="${pair.node_id}"`]) expect(queries.status).toContain(selector);
    expect(queries.consumers).toContain(`consumer_epoch_id="${consumerEpochId}"`); expect(queries.consumers).toContain(`consumer_id="${consumerId}"`);
    expect(queries.bandwidth).toContain('bytes_ingress'); expect(queries.bandwidth).toContain('/ 60'); expect(() => queries.latency('request" | drop', 0.5)).toThrow();
    expect(() => fixedLogql(cid, { ...scope(), epochs: [{ ...pair, route_id: 'invalid" | json' }] }, window)).toThrow();
    expect(() => currentLokiAssignments(cid, { ...scope(), epochs: [{ ...pair, closed_at: window.end }] })).toThrow();
  });
});
