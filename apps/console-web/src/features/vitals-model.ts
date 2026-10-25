import type { EChartsOption } from 'echarts';
import { canonicalId, scopeQuery } from '../api/workspace-scope';

export const VITALS_RANGES = [
  { value: 300, label: '最近 5 分钟' },
  { value: 900, label: '最近 15 分钟' },
  { value: 3600, label: '最近 1 小时' },
  { value: 21600, label: '最近 6 小时' },
  { value: 86400, label: '最近 24 小时' },
  { value: 604800, label: '最近 7 天' },
] as const;
export const MAX_VITALS_POINTS = 800;
export type VitalsDuration = typeof VITALS_RANGES[number]['value'];
export type MetricUnit = 'requests/s' | 'ms' | 'bytes/s' | 'count';
export interface MetricPoint { ts: number; value: number | null; }
export interface VitalsWindow { start: string; end: string; step: number; }
export interface VitalsScope {
  actorId: string; clusterId: string; workspaceId: string; permissionVersion: string;
  metricsScope?: 'workspace' | 'cluster';
  sourceId?: string; serviceId?: string; routeId?: string;
}

export function createVitalsWindow(duration: number, now = Date.now()): VitalsWindow {
  if (!VITALS_RANGES.some(range => range.value === duration) || !Number.isFinite(now)) throw new Error('请选择有效的监控时间范围。');
  const end = Math.floor(now / 1000) * 1000;
  const step = Math.max(15, Math.ceil(duration / (MAX_VITALS_POINTS - 1) / 15) * 15);
  return { start: new Date(end - duration * 1000).toISOString(), end: new Date(end).toISOString(), step };
}

export function vitalsQueryKey(resource: string, scope: VitalsScope, detail: unknown = null): readonly unknown[] {
  return ['vitals', resource, scope.actorId, scope.permissionVersion, scope.clusterId, scope.workspaceId, scope.metricsScope ?? 'workspace', scope.sourceId ?? null, scope.serviceId ?? null, scope.routeId ?? null, detail];
}

export function sameVitalsScope(a: VitalsScope, b: VitalsScope): boolean {
  return a.actorId === b.actorId && a.permissionVersion === b.permissionVersion && a.clusterId === b.clusterId && a.workspaceId === b.workspaceId && (a.metricsScope ?? 'workspace') === (b.metricsScope ?? 'workspace') && a.sourceId === b.sourceId && a.serviceId === b.serviceId && a.routeId === b.routeId;
}

export function vitalsPath(resource: 'capabilities' | 'overview' | 'entities' | 'setup', scope: VitalsScope, options: { window?: VitalsWindow; type?: 'services' | 'routes' | 'consumers'; search?: string; cursor?: string; size?: number } = {}): string {
  if (!['capabilities', 'overview', 'entities', 'setup'].includes(resource)) throw new Error('无效的监控接口。');
  const cid = canonicalId(scope.clusterId), wid = canonicalId(scope.workspaceId);
  if (!cid || !wid) throw new Error('请先选择集群与工作区。');
  const params = new URLSearchParams();
  if (scope.metricsScope && !['workspace', 'cluster'].includes(scope.metricsScope)) throw new Error('监控聚合范围无效。');
  if (resource !== 'setup') params.set('scope', scope.metricsScope ?? 'workspace');
  if (scope.sourceId && ['capabilities', 'overview'].includes(resource)) { const id = canonicalId(scope.sourceId); if (!id) throw new Error('监控数据源标识无效。'); params.set('sourceId', id); }
  if (resource === 'overview') {
    for (const [key, value] of [['serviceId', scope.serviceId], ['routeId', scope.routeId]] as const) {
      if (value) { const id = canonicalId(value); if (!id) throw new Error('监控实体标识无效。'); params.set(key, id); }
    }
    if (!options.window) throw new Error('监控查询缺少时间范围。');
    const { start, end, step } = options.window;
    const validUtc = (value: string) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
    const seconds = (Date.parse(end) - Date.parse(start)) / 1000;
    if (!validUtc(start) || !validUtc(end) || seconds < 300 || seconds > 604800 || !Number.isInteger(step) || step < 15 || step > 86400 || Math.floor(seconds / step) + 1 > MAX_VITALS_POINTS) throw new Error('监控时间范围或采样点预算无效。');
    params.set('start', options.window.start); params.set('end', options.window.end); params.set('step', String(options.window.step));
  }
  if (resource === 'entities') {
    if (!options.type || !['services', 'routes', 'consumers'].includes(options.type)) throw new Error('请选择受支持的监控实体类型。');
    const size = options.size ?? 20;
    if (!Number.isInteger(size) || size < 1 || size > 100) throw new Error('监控实体每页条数无效。');
    params.set('type', options.type); params.set('size', String(size));
    if (options.search) params.set('search', options.search);
    if (options.cursor) params.set('cursor', options.cursor);
  }
  return scopeQuery(`/clusters/${cid}/vitals/${resource}${params.size ? `?${params}` : ''}`, cid, wid);
}

export function finiteMetric(value: unknown): number | null { return typeof value === 'number' && Number.isFinite(value) ? value : null; }
export function formatMetric(value: unknown, unit: MetricUnit = 'count'): string {
  const number = finiteMetric(value);
  if (number === null) return '—';
  if (unit === 'bytes/s') {
    const abs = Math.abs(number), divisor = abs >= 1024 ** 3 ? 1024 ** 3 : abs >= 1024 ** 2 ? 1024 ** 2 : abs >= 1024 ? 1024 : 1;
    const suffix = divisor === 1024 ** 3 ? 'GiB/s' : divisor === 1024 ** 2 ? 'MiB/s' : divisor === 1024 ? 'KiB/s' : 'B/s';
    return `${new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 }).format(number / divisor)} ${suffix}`;
  }
  return new Intl.NumberFormat('zh-CN', { maximumFractionDigits: unit === 'count' ? 0 : 2 }).format(number);
}
export function hasMetricSamples(points: MetricPoint[] | undefined): boolean { return !!points?.some(point => finiteMetric(point.value) !== null); }
export function chartPoints(points: MetricPoint[] = []): Array<[number, number | null]> {
  if (points.length > MAX_VITALS_POINTS) throw new Error('指标时间点超出展示预算，请缩短时间范围。');
  return points.filter(point => Number.isFinite(point.ts)).map(point => [point.ts, finiteMetric(point.value)]);
}

export function metricChartOption(series: Array<{ name: string; points: MetricPoint[]; color?: string }>, unit: MetricUnit, stacked = false): EChartsOption {
  const axisUnit = unit === 'ms' ? 'ms' : unit === 'requests/s' ? '请求/秒' : unit === 'bytes/s' ? 'B/s' : '次数';
  return {
    animation: false,
    color: series.map(row => row.color ?? '#3b6c99'),
    textStyle: { fontFamily: 'Inter, PingFang SC, Microsoft YaHei, sans-serif' },
    legend: { bottom: 0, type: 'scroll', textStyle: { color: '#758295', fontSize: 11 } },
    grid: { left: 18, right: 20, top: 36, bottom: 48, containLabel: true },
    tooltip: { trigger: 'axis', renderMode: 'richText', confine: true, valueFormatter: value => `${formatMetric(value, unit)}${unit === 'ms' ? ' ms' : unit === 'requests/s' ? ' 请求/秒' : ''}` },
    xAxis: { type: 'time', axisLine: { lineStyle: { color: '#dce3eb' } }, axisLabel: { color: '#758295', hideOverlap: true }, axisTick: { show: false }, splitLine: { show: false } },
    yAxis: { type: 'value', name: axisUnit, nameTextStyle: { color: '#758295' }, min: 0, axisLabel: { color: '#758295', formatter: value => unit === 'bytes/s' ? formatMetric(value, unit) : formatMetric(value, unit) }, splitLine: { lineStyle: { color: '#edf1f6' } } },
    series: series.map(row => ({ name: row.name, type: 'line', data: chartPoints(row.points), showSymbol: false, connectNulls: false, lineStyle: { width: 2 }, ...(stacked ? { stack: 'status', areaStyle: { opacity: 0.12 } } : {}) })),
  };
}
