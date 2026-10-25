import { BadGatewayException } from '@nestjs/common';
import { outboundJson } from '../../../infrastructure/kong/outbound';
import type { MetricsScope } from '../metrics-scope.service';
import type { VitalsOverview, VitalsPoint, VitalsSeriesKey, VitalsTimeWindow } from '../vitals.types';
import { VITALS_SERIES } from '../vitals.types';
import type { MetricsSourceConnection } from './metrics-source.service';
import { MetricsQueryBudget } from './query-budget';
import { fixedPromql } from './promql';
export interface ProviderResult { series: Record<VitalsSeriesKey, VitalsPoint[]>; topN: VitalsOverview['topN']; nodes: VitalsOverview['nodes']; reasonCodes: string[]; }
const invalid = () => new BadGatewayException({ code: 'INVALID_METRICS_RESPONSE', message: '监控数据源响应无效，未返回未经验证的样本' });
const numeric = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;
function sampleNumber(value: string): number | null { if (['NaN', '+Inf', '-Inf', 'Inf'].includes(value)) return null; if (!numeric.test(value)) throw invalid(); const result = Number(value); if (!Number.isFinite(result) || result < 0) throw invalid(); return result; }
export function nullSeries(window: VitalsTimeWindow): Record<VitalsSeriesKey, VitalsPoint[]> {
  const points: VitalsPoint[] = []; for (let ts = Date.parse(window.start); ts <= Date.parse(window.end); ts += window.step * 1000) points.push({ ts, value: null });
  return Object.fromEntries(VITALS_SERIES.map(key => [key, points.map(point => ({ ...point }))])) as Record<VitalsSeriesKey, VitalsPoint[]>;
}
export class PrometheusProvider {
  protected templates(cid: string, scope: MetricsScope, window: VitalsTimeWindow) { return fixedPromql(cid, scope, window); }
  async evaluate(source: MetricsSourceConnection, cid: string, scope: MetricsScope, window: VitalsTimeWindow, budget: MetricsQueryBudget, collectorEnabled: boolean): Promise<ProviderResult> {
    const series = nullSeries(window), templates = this.templates(cid, scope, window), result: ProviderResult = { series, topN: { services: [], consumers: [] }, nodes: [], reasonCodes: [] };
    if (!scope.epochs.some(epoch => epoch.entity_type !== 'consumers')) result.reasonCodes.push('NO_VERIFIED_TRAFFIC_ASSIGNMENT');
    else {
      const statuses = await this.range(source, templates.status, window, budget);
      for (const row of statuses) {
        if (!/^[1-5]\d\d$/.test(row.metric.code || '')) throw invalid();
        this.add(series.qps, row.values);
        const family = row.metric.code[0]; if (family === '2' || family === '4' || family === '5') this.add(series[`status${family}xx` as VitalsSeriesKey], row.values);
      }
      for (const [type, prefix] of [['request', 'latencyRequest'], ['upstream', 'latencyUpstream'], ['kong', 'latencyKong']] as const) for (const [quantile, suffix] of [[0.5, 'P50'], [0.95, 'P95'], [0.99, 'P99']] as const) {
        const rows = await this.range(source, templates.latency(type, quantile), window, budget);
        if (rows.length > 1) throw invalid(); if (rows[0]) this.add(series[`${prefix}${suffix}` as VitalsSeriesKey], rows[0].values);
      }
      for (const row of await this.range(source, templates.bandwidth, window, budget)) {
        if (!['ingress', 'egress'].includes(row.metric.type || '')) throw invalid();
        this.add(series[row.metric.type === 'ingress' ? 'bandwidthIngress' : 'bandwidthEgress'], row.values);
      }
      result.topN.services = (await this.instant(source, templates.services, window, budget)).filter(row => scope.serviceNames.has(row.metric.service_id)).map(row => ({ id: row.metric.service_id, name: scope.serviceNames.get(row.metric.service_id)!, value: row.value }));
    }
    if (collectorEnabled && scope.consumerPairEpochs.length && scope.epochs.some(epoch => epoch.entity_type === 'consumers')) result.topN.consumers = (await this.instant(source, templates.consumers, window, budget)).filter(row => scope.consumerNames.has(row.metric.consumer_id) && scope.epochs.some(epoch => epoch.consumer_id === row.metric.consumer_id && Date.parse(epoch.valid_from) <= Date.parse(window.end) - window.rateWindowSeconds * 1000)).map(row => ({ id: row.metric.consumer_id, name: scope.consumerNames.get(row.metric.consumer_id)!, value: row.value }));
    else result.reasonCodes.push('CONSUMER_COLLECTOR_UNAVAILABLE');
    if (scope.wholeCluster) {
      const online = await this.instant(source, templates.nodes, window, budget), datastore = await this.instant(source, templates.datastore, window, budget), nodes = new Set([...online, ...datastore].map(row => row.metric.node_id).filter(Boolean));
      result.nodes = [...nodes].map(id => ({ id, online: online.find(row => row.metric.node_id === id)?.value ?? null, datastoreReachable: datastore.find(row => row.metric.node_id === id)?.value ?? null }));
      if (result.nodes.some(row => row.online !== null && ![0, 1].includes(row.online) || row.datastoreReachable !== null && ![0, 1].includes(row.datastoreReachable))) throw invalid();
    } else result.reasonCodes.push('NODE_METRICS_CLUSTER_PERMISSION_REQUIRED');
    return result;
  }
  private async response(source: MetricsSourceConnection, path: string, query: Record<string, string | number>, budget: MetricsQueryBudget): Promise<any> {
    if (source.type === 'loki') { path = path.replace('/api/v1/', '/loki/api/v1/'); for (const key of ['start', 'end', 'time']) if (query[key] !== undefined) query[key] = new Date(Number(query[key]) * 1000).toISOString(); }
    const remaining = budget.beginCall(), result = await outboundJson(source.baseUrl, path, 'GET', undefined, query, source.auth, 5000, undefined, undefined, remaining);
    budget.chargeResponse(result.bytes ?? Buffer.byteLength(JSON.stringify(result.body)));
    if (result.status !== 200 || result.body?.status !== 'success' || !Array.isArray(result.body?.data?.result)) throw invalid(); return result.body.data;
  }
  async range(source: MetricsSourceConnection, query: string, window: VitalsTimeWindow, budget: MetricsQueryBudget): Promise<Array<{ metric: Record<string, string>; values: Array<[number, number | null]> }>> {
    const data = await this.response(source, '/api/v1/query_range', { query, start: Date.parse(window.start) / 1000, end: Date.parse(window.end) / 1000, step: window.step, timeout: '5s' }, budget);
    if (data.resultType !== 'matrix') throw invalid();
    return data.result.map((row: any) => {
      if (!row.metric || typeof row.metric !== 'object' || Array.isArray(row.metric) || !Array.isArray(row.values)) throw invalid();
      budget.chargeSeries(row.values.length); const seen = new Set<number>();
      const values = row.values.map((value: any) => {
        if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'number' || typeof value[1] !== 'string') throw invalid();
        const ts = Math.round(value[0] * 1000), start = Date.parse(window.start);
        if (!Number.isFinite(value[0]) || ts < start || ts > Date.parse(window.end) || (ts - start) % (window.step * 1000) !== 0 || seen.has(ts)) throw invalid(); seen.add(ts);
        return [ts, sampleNumber(value[1])] as [number, number | null];
      }); return { metric: row.metric, values };
    });
  }
  async instant(source: MetricsSourceConnection, query: string, window: VitalsTimeWindow, budget: MetricsQueryBudget): Promise<Array<{ metric: Record<string, string>; value: number }>> {
    const data = await this.response(source, '/api/v1/query', { query, time: Date.parse(window.end) / 1000, timeout: '5s' }, budget);
    if (data.resultType !== 'vector') throw invalid(); const result: Array<{ metric: Record<string, string>; value: number }> = [];
    for (const row of data.result) {
      budget.chargeSeries(1);
      if (!row.metric || typeof row.metric !== 'object' || Array.isArray(row.metric) || !Array.isArray(row.value) || row.value.length !== 2 || typeof row.value[0] !== 'number' || Math.abs(row.value[0] * 1000 - Date.parse(window.end)) > 1 || typeof row.value[1] !== 'string') throw invalid();
      const value = sampleNumber(row.value[1]); if (value === null) continue; result.push({ metric: row.metric, value });
    } return result;
  }
  private add(target: VitalsPoint[], values: Array<[number, number | null]>) {
    const byTime = new Map(target.map(point => [point.ts, point])); for (const [ts, value] of values) { const point = byTime.get(ts); if (point && value !== null) point.value = (point.value ?? 0) + value; }
  }
}
