import { BadGatewayException, BadRequestException } from '@nestjs/common';
import type { MetricsScope } from '../metrics-scope.service';
import type { VitalsPoint, VitalsSeriesKey, VitalsTimeWindow } from '../vitals.types';
import { currentLokiAssignments, fixedLogql, lokiCompleteAfter } from './logql';
import type { MetricsSourceConnection } from './metrics-source.service';
import { PrometheusProvider, nullSeries, type ProviderResult } from './prometheus.provider';
import type { MetricsQueryBudget } from './query-budget';

const invalid = () => new BadGatewayException({ code: 'INVALID_METRICS_RESPONSE', message: '日志指标响应无效，未返回未经验证的样本' });
/** Uses the shared bounded transport/parser, with fixed LogQL and no node inference. */
export class LokiProvider extends PrometheusProvider {
  protected templates(cid: string, scope: MetricsScope, window: VitalsTimeWindow) { return fixedLogql(cid, scope, window); }
  async evaluate(source: MetricsSourceConnection, cid: string, scope: MetricsScope, window: VitalsTimeWindow, budget: MetricsQueryBudget, collectorEnabled: boolean): Promise<ProviderResult> {
    if (source.type !== 'loki') throw new BadRequestException({ code: 'INVALID_LOKI_METRICS_SOURCE', message: '日志指标需要已登记的 Loki 数据源' });
    const { pairs, consumerPairs, consumers } = currentLokiAssignments(cid, scope), templates = this.templates(cid, scope, window);
    const result: ProviderResult = { series: nullSeries(window), topN: { services: [], consumers: [] }, nodes: [], reasonCodes: ['LOKI_NODE_METRICS_UNSUPPORTED', 'LOKI_LOG_DELIVERY_AT_LEAST_ONCE'] };
    const append = (target: VitalsPoint[], values: Array<[number, number | null]>) => {
      const positions = new Map(target.map(point => [point.ts, point]));
      for (const [ts, value] of values) if (value !== null) { const point = positions.get(ts); if (point) point.value = (point.value ?? 0) + value; }
    };
    if (!collectorEnabled) { result.reasonCodes.push('CONSUMER_COLLECTOR_UNAVAILABLE', 'LOKI_COLLECTOR_NOT_ENABLED'); return result; }
    if (!pairs.length) result.reasonCodes.push('NO_VERIFIED_TRAFFIC_ASSIGNMENT');
    else {
      const statuses = await this.range(source, templates.status, window, budget), seenCodes = new Set<string>();
      for (const row of statuses) {
        const code = row.metric.code;
        if (!/^[1-5]\d\d$/.test(code || '') || seenCodes.has(code)) throw invalid(); seenCodes.add(code);
        append(result.series.qps, row.values);
        if (['2', '4', '5'].includes(code[0])) append(result.series[`status${code[0]}xx` as VitalsSeriesKey], row.values);
      }
      for (const [type, prefix] of [['request', 'latencyRequest'], ['upstream', 'latencyUpstream'], ['kong', 'latencyKong']] as const) for (const [quantile, suffix] of [[0.5, 'P50'], [0.95, 'P95'], [0.99, 'P99']] as const) {
        const rows = await this.range(source, templates.latency(type, quantile), window, budget);
        if (rows.length > 1) throw invalid(); if (rows[0]) append(result.series[`${prefix}${suffix}`], rows[0].values);
      }
      const directions = new Set<string>();
      for (const row of await this.range(source, templates.bandwidth, window, budget)) {
        const direction = row.metric.type;
        if (!['ingress', 'egress'].includes(direction) || directions.has(direction)) throw invalid(); directions.add(direction);
        append(result.series[direction === 'ingress' ? 'bandwidthIngress' : 'bandwidthEgress'], row.values);
      }
      const completeAfter = lokiCompleteAfter(pairs, window);
      for (const points of Object.values(result.series)) for (const point of points) if (point.ts < completeAfter) point.value = null;
      if (Date.parse(window.start) < completeAfter) result.reasonCodes.push('LOKI_CURRENT_EPOCH_WINDOW_INCOMPLETE');
      const seenServices = new Set<string>();
      for (const row of await this.instant(source, templates.services, window, budget)) {
        const id = row.metric.service_id;
        if (!scope.serviceNames.has(id)) continue;
        if (seenServices.has(id)) throw invalid(); seenServices.add(id);
        const servicePairs = pairs.filter(pair => pair.service_id === id);
        if (!servicePairs.length || Date.parse(window.end) < lokiCompleteAfter(servicePairs, window)) continue;
        result.topN.services.push({ id, name: scope.serviceNames.get(id)!, value: row.value });
      }
    }
    if (!consumers.length || !consumerPairs.length) result.reasonCodes.push('CONSUMER_COLLECTOR_UNAVAILABLE');
    else {
      const seenConsumers = new Set<string>();
      for (const row of await this.instant(source, templates.consumers, window, budget)) {
        const id = row.metric.consumer_id;
        if (!scope.consumerNames.has(id)) continue;
        if (seenConsumers.has(id)) throw invalid(); seenConsumers.add(id);
        const matches = consumers.filter(consumer => consumer.consumer_id === id);
        const requiredPairs = consumerPairs.filter(pair => matches.some(consumer => consumer.workspace_id === pair.workspace_id && consumer.node_id === pair.node_id));
        if (!requiredPairs.length || Date.parse(window.end) < lokiCompleteAfter([...matches, ...requiredPairs], window)) continue;
        result.topN.consumers.push({ id, name: scope.consumerNames.get(id)!, value: row.value });
      }
    }
    return result;
  }
}
