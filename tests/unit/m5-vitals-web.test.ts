import { beforeEach, describe, expect, it, vi } from 'vitest';
import { chartPoints, createVitalsWindow, finiteMetric, formatMetric, hasMetricSamples, metricChartOption, sameVitalsScope, vitalsPath, vitalsQueryKey, VITALS_RANGES } from '../../apps/console-web/src/features/vitals-model';
import { requestVitals, validateVitalsCapabilities, validateVitalsOverview } from '../../apps/console-web/src/features/vitals-response';
import { VITALS_SERIES } from '../../apps/console-web/src/features/vitals.types';
import { permissionEntityTypes } from '../../apps/console-web/src/api/permissions';

const mock = vi.hoisted(() => ({ actor: 'actor-A', api: vi.fn() }));
vi.mock('../../apps/console-web/src/api/client', async importOriginal => ({ ...await importOriginal<any>(), api: mock.api, getApiActorId: () => mock.actor }));
const cid = '721bfeda-dc12-4d7a-b33e-06b2879a7ead', wid = 'a109e333-40a0-4965-966b-6b810f54e9b6', source = '14368d69-dd76-46f6-b490-583893b13cba';
const scope = () => ({ actorId: 'actor-A', clusterId: cid, workspaceId: wid, permissionVersion: 'iam-1', sourceId: source });
const deferred = () => { let resolve!: (value: any) => void; const promise = new Promise<any>(done => { resolve = done; }); return { promise, resolve }; };
function overview() { return { clusterId: cid, workspaceId: wid, scope: 'workspace', source: { id: source }, units: { throughput: 'requests/second', latency: 'milliseconds', bandwidth: 'bytes/second' }, series: Object.fromEntries(VITALS_SERIES.map(name => [name, [{ ts: 1000, value: null }, { ts: 2000, value: 0 }]])), cards: {}, quality: {}, topN: { services: [], consumers: [] }, nodes: [] } as any; }
beforeEach(() => { mock.actor = 'actor-A'; mock.api.mockReset(); });

describe('M5 independent Vitals UI units, budgets and scope-aware cache identity', () => {
  it.each(VITALS_RANGES)('builds canonical UTC $label windows within 800 inclusive timestamps', ({ value }) => {
    const window = createVitalsWindow(value, Date.parse('2026-10-10T12:00:00.999Z'));
    expect(window.end).toBe('2026-10-10T12:00:00.000Z'); expect(Date.parse(window.end) - Date.parse(window.start)).toBe(value * 1000);
    expect(Math.floor(value / window.step) + 1).toBeLessThanOrEqual(800); expect(window.step % 15).toBe(0);
  });
  it('distinguishes unavailable gaps from measured zero and retains real millisecond units', () => {
    for (const value of [undefined, null, NaN, Infinity, '0']) expect(finiteMetric(value)).toBeNull();
    expect(finiteMetric(0)).toBe(0); expect(formatMetric(null, 'ms')).toBe('—'); expect(formatMetric(0, 'ms')).toBe('0'); expect(formatMetric(1500, 'ms')).toBe('1,500');
    expect(formatMetric(1024, 'bytes/s')).toBe('1 KiB/s'); expect(hasMetricSamples([{ ts: 1, value: null }])).toBe(false); expect(hasMetricSamples([{ ts: 1, value: 0 }])).toBe(true);
    expect(chartPoints([{ ts: 1000, value: null }, { ts: 2000, value: 0 }])).toEqual([[1000, null], [2000, 0]]);
    const chart: any = metricChartOption([{ name: '<img src=x onerror=1>', points: [{ ts: 1000, value: null }, { ts: 2000, value: 0 }] }], 'ms');
    expect(chart.series[0].connectNulls).toBe(false); expect(chart.tooltip.renderMode).toBe('richText'); expect(chart.yAxis.name).toBe('ms');
  });
  it('rejects excessive public chart samples and invalid UTC time ranges without clipping', () => {
    expect(() => chartPoints(Array(801).fill({ ts: 1, value: 0 }))).toThrow(); expect(() => createVitalsWindow(1)).toThrow();
    expect(() => vitalsPath('overview', scope(), { window: { start: '2026-02-30T12:00:00.000Z', end: '2026-03-02T12:05:00.000Z', step: 15 } })).toThrow();
    expect(() => vitalsPath('overview', scope(), { window: { start: '2026-10-10T12:00:00.000Z', end: '2026-10-10T15:20:00.000Z', step: 15 } })).toThrow();
  });
  it('isolates every account, permission, cluster, workspace, source, metric scope and entity dimension', () => {
    const original = scope(), key = vitalsQueryKey('overview', original);
    for (const patch of [{ actorId: 'actor-B' }, { permissionVersion: 'iam-2' }, { clusterId: source }, { workspaceId: source }, { sourceId: wid }, { metricsScope: 'cluster' as const }, { serviceId: source }, { routeId: source }]) {
      const changed = { ...original, ...patch }; expect(sameVitalsScope(original, changed)).toBe(false); expect(vitalsQueryKey('overview', changed)).not.toEqual(key);
    }
    expect(sameVitalsScope(original, { ...original, metricsScope: 'workspace' })).toBe(true);
  });
  it('constructs exact BFF-only paths and does not send source IDs or scope to unrelated interfaces', () => {
    const caps = new URL(vitalsPath('capabilities', scope()), 'http://console.test'); expect(caps.pathname).toBe(`/clusters/${cid}/vitals/capabilities`); expect(caps.searchParams.get('workspaceId')).toBe(wid); expect(caps.searchParams.get('sourceId')).toBe(source);
    const entities = new URL(vitalsPath('entities', { ...scope(), metricsScope: 'cluster' }, { type: 'routes', search: 'a&url=http://secret', size: 20 }), 'http://console.test'); expect(entities.searchParams.get('sourceId')).toBeNull(); expect(entities.searchParams.get('scope')).toBe('cluster'); expect(entities.searchParams.get('url')).toBeNull();
    const setup = new URL(vitalsPath('setup', { ...scope(), metricsScope: 'cluster' }), 'http://console.test'); expect(setup.searchParams.get('scope')).toBeNull(); expect(setup.searchParams.get('sourceId')).toBeNull();
    expect(() => vitalsPath('overview', { ...scope(), clusterId: 'http://kong:8001' }, { window: createVitalsWindow(300) })).toThrow();
  });
  it('offers monitoring typed IDs only for actual traffic identities', () => {
    expect(permissionEntityTypes('monitoring')).toEqual(['services', 'routes', 'consumers']); expect(permissionEntityTypes('annotations')).toHaveLength(8);
  });
  it('validates actual overview scope, units and all fifteen series without converting null to zero', () => {
    const value = overview(); expect(validateVitalsOverview(value, scope())).toBe(value);
    for (const changed of [{ ...value, clusterId: source }, { ...value, workspaceId: source }, { ...value, scope: 'cluster' }, { ...value, units: { ...value.units, latency: 'seconds' } }, { ...value, series: { ...value.series, qps: [{ ts: 1, value: Infinity }] } }, { ...value, series: { ...value.series, latencyKongP99: undefined } }]) expect(() => validateVitalsOverview(changed, scope())).toThrow();
  });
  it('rejects capabilities from another aggregate scope even with the same source, and fails closed on incomplete caps', () => {
    const value: any = { clusterId: cid, workspaceId: wid, scope: 'workspace', source: { id: source }, sources: [], permissions: { clusterMetrics: false }, capabilities: {}, limitations: [] };
    expect(validateVitalsCapabilities(value, scope())).toBe(value);
    expect(() => validateVitalsCapabilities({ ...value, scope: 'cluster' }, scope())).toThrow();
    expect(() => validateVitalsCapabilities({ ...value, source: { id: wid } }, scope())).toThrow();
    expect(() => validateVitalsCapabilities({ ...value, permissions: undefined }, scope())).toThrow();
  });
});

describe('M5 independent actual delayed Vitals response admission', () => {
  it.each(['actor', 'workspace', 'source', 'permission', 'metricsScope'])('discards a successful response after %s changes', async field => {
    const gate = deferred(), captured = scope(); let current: any = captured;
    mock.api.mockReturnValue(gate.promise); const validate = vi.fn(value => value);
    const pending = requestVitals('/clusters/'+cid+'/vitals/overview', captured, () => current, undefined, validate);
    if (field === 'actor') mock.actor = 'actor-B';
    else current = { ...captured, ...({ workspace: { workspaceId: source }, source: { sourceId: wid }, permission: { permissionVersion: 'iam-2' }, metricsScope: { metricsScope: 'cluster' } } as any)[field] };
    gate.resolve(overview()); await expect(pending).rejects.toMatchObject({ code: 'METRICS_SCOPE_CHANGED' }); expect(validate).not.toHaveBeenCalled();
  });
  it('cancels a completed transport before cache admission and permits a fresh current-scope response', async () => {
    const gate = deferred(), captured = scope(), abort = new AbortController(); mock.api.mockReturnValue(gate.promise);
    const pending = requestVitals('vitals', captured, () => captured, abort.signal, validateVitalsOverview); abort.abort(); gate.resolve(overview());
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    mock.api.mockResolvedValue(overview()); expect(await requestVitals('vitals', captured, () => captured, undefined, validateVitalsOverview)).toMatchObject({ series: { qps: [{ ts: 1000, value: null }, { ts: 2000, value: 0 }] } });
  });
  it('does not issue a query already known to belong to a stale account or scope', async () => {
    mock.actor = 'actor-B'; await expect(requestVitals('vitals', scope(), scope)).rejects.toMatchObject({ code: 'METRICS_SCOPE_CHANGED' }); expect(mock.api).not.toHaveBeenCalled();
  });
});
