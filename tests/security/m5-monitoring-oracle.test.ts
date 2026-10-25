import { describe, expect, it } from 'vitest';
import { classicHistogramQuantile, compareMonitoringPoints, finitePrometheusValue, oracleMatrixPoints } from './lib/m5-oracle.mjs';
import { collectorCounterTotal } from './lib/m5-consumer-oracle.mjs';
import { compareRealLokiEvents } from './lib/m5-loki-oracle.mjs';
import { compareRealNativePrometheus } from './lib/m5-native-oracle.mjs';

describe('M5 independent real-Prometheus oracle safeguards', () => {
  it('preserves NaN, missing and infinite observations as null while preserving a real zero', () => {
    for (const value of [null, undefined, '', 'NaN', '+Inf', '-Inf']) expect(finitePrometheusValue(value)).toBeNull();
    expect(finitePrometheusValue('0')).toBe(0);
  });
  it('aggregates only real samples at exact millisecond timestamps and applies the explicit unit', () => {
    expect(oracleMatrixPoints([{ values: [[100.125, '12'], [115.125, 'NaN']] }, { values: [[100.125, '8']] }], 0.001)).toEqual([[100125, 0.02], [115125, null]]);
  });
  it('fails rather than accepting invented zero or silently omitted real data', () => {
    expect(() => compareMonitoringPoints([[1000, 0]], [])).toThrow('missing oracle sample');
    expect(() => compareMonitoringPoints([], [[1000, 2]])).toThrow('omitted');
    expect(() => compareMonitoringPoints([[1000, 2], [1000, 2]], [[1000, 2]])).toThrow('duplicate');
  });
  it('compares the identical evaluation grid with bounded numeric tolerance', () => {
    expect(compareMonitoringPoints([[1000, 2.0000001], [2000, null]], [[1000, 2], [2000, null]])).toEqual({ compared: 1, nullCompared: 1, points: 2 });
    expect(() => compareMonitoringPoints([[1000, 2.01]], [[1000, 2]])).toThrow('differs');
  });
  it('independently computes millisecond histogram quantiles with the actual bucket boundaries', () => {
    const buckets = [[1, 5], [2, 10], [5, 20], [10, 40], ['+Inf', 40]];
    expect(classicHistogramQuantile(0.5, buckets)).toBe(5);
    expect(classicHistogramQuantile(0.95, buckets)).toBe(9.5);
    expect(classicHistogramQuantile(0.99, buckets)).toBe(9.9);
  });
  it('does not manufacture latency when counters have no usable observations', () => {
    expect(classicHistogramQuantile(0.95, [[1, 0], ['+Inf', 0]])).toBeNull();
    expect(classicHistogramQuantile(0.95, [[1, 3], [2, 2], ['+Inf', 3]])).toBeNull();
    expect(classicHistogramQuantile(0.99, [[1, 1], [2, 2], ['+Inf', 10]])).toBe(2);
  });
  it('counts only the exact owned collector identity and preserves duplicate legitimate events', () => {
    const text = [
      'kongos_collector_requests_total{route_id="owned",consumer_id="one",code="201"} 2',
      'kongos_collector_requests_total{route_id="foreign",consumer_id="one",code="201"} 7',
      'kongos_collector_requests_total{route_id="owned",consumer_id="other",code="201"} 11',
    ].join('\n');
    expect(collectorCounterTotal(text, { route_id: 'owned', consumer_id: 'one' })).toBe(2);
    expect(collectorCounterTotal(text, { route_id: 'missing' })).toBe(0);
  });
  it('computes all Loki series from current-epoch events with empirical quantiles and exact window boundaries', () => {
    const values: Record<string, number> = { qps: 3 / 60, status2xx: 1 / 60, status4xx: 1 / 60, status5xx: 1 / 60, bandwidthIngress: 1, bandwidthEgress: 2 };
    for (const [prefix, multiplier] of [['latencyRequest', 1], ['latencyUpstream', 3], ['latencyKong', 2]] as const) {
      for (const [suffix, quantile] of [['P50', 2], ['P95', 2.9], ['P99', 2.98]] as const) values[prefix + suffix] = quantile * multiplier;
    }
    const line = (code: number, index: number) => JSON.stringify({ code: String(code), latency_request_ms: index, latency_upstream_ms: index * 3, latency_kong_ms: index * 2, bytes_ingress: index * 10, bytes_egress: index * 20 });
    const actual: any = { timeWindow: { end: new Date(100000).toISOString(), rateWindowSeconds: 60 }, series: Object.fromEntries(Object.entries(values).map(([name, value]) => [name, [{ ts: 50000, value: null }, { ts: 100000, value }]])) };
    const current = [{ epoch_id: 'current', valid_from: new Date(0).toISOString() }];
    const streams = [
      { stream: { epoch_id: 'current' }, values: [['40000000000', line(200, 999)], ['90000000000', line(200, 1)], ['95000000000', line(404, 2)], ['100000000000', line(500, 3)]] },
      { stream: { epoch_id: 'closed' }, values: [['98000000000', line(200, 999)]] },
    ];
    const fake = { check: (condition: boolean) => { if (!condition) throw new Error('oracle guard'); } };
    const result = compareRealLokiEvents(fake, actual, streams, current);
    expect(Object.keys(result.comparisons)).toHaveLength(15);
    expect(result.comparisons.latencyRequestP95).toMatchObject({ compared: 1, nullCompared: 1 });
    actual.series.qps[0].value = 0;
    expect(() => compareRealLokiEvents(fake, actual, streams, current)).toThrow('missing oracle');
  });
  it('native oracle selectors independently exclude closed epochs instead of relabeling old samples', () => {
    const queries: string[] = [];
    const fake = {
      check: () => {},
      prometheus: (query: string) => { queries.push(query); return { result: [] }; },
    };
    const names = ['qps', 'status2xx', 'status4xx', 'status5xx', 'bandwidthIngress', 'bandwidthEgress', ...['latencyRequest', 'latencyUpstream', 'latencyKong'].flatMap(prefix => ['P50', 'P95', 'P99'].map(suffix => prefix + suffix))];
    const end = new Date(100000).toISOString();
    compareRealNativePrometheus(fake, { timeWindow: { start: new Date(0).toISOString(), end, step: 15, rateWindowSeconds: 60 }, evaluationAt: end, units: { latency: 'milliseconds', bandwidth: 'bytes/second', throughput: 'requests/second' }, series: Object.fromEntries(names.map(name => [name, []])) }, {
      clusterId: 'cid', workspaceId: 'wid', serviceId: 'svc', epochs: [
        { epoch_id: 'current', entity_type: 'routes', service_id: 'svc', workspace_id: 'wid', closed_at: null },
        { epoch_id: 'closed', entity_type: 'routes', service_id: 'svc', workspace_id: 'wid', closed_at: 'closed' },
      ],
    });
    expect(queries.length).toBeGreaterThan(3);
    expect(queries.every(query => query.includes('membership_epoch=~"current"') && !query.includes('closed'))).toBe(true);
  });
});
