import { BadRequestException, ConflictException } from '@nestjs/common';
import type { MetricsAssignment } from '../../metrics/metrics.types';
import type { MetricsScope } from '../metrics-scope.service';
import type { VitalsTimeWindow } from '../vitals.types';
import { metricsId } from '../vitals-query';

const quote = (value: string) => JSON.stringify(value);
const invalid = (): never => { throw new BadRequestException({ code: 'INVALID_LOKI_METRICS_SCOPE', message: '日志指标归属标识无效，未生成查询' }); };
const unique = (rows: MetricsAssignment[]) => [...new Map(rows.map(row => [row.epoch_id, row])).values()].sort((a, b) => a.epoch_id.localeCompare(b.epoch_id));
function assertAssignment(cid: string, scope: MetricsScope, row: MetricsAssignment, consumer: boolean): void {
  if (!row || row.cluster_id !== cid || row.quality !== 'verified' || row.closed_at !== null || !/^[a-f0-9]{64}$/.test(row.node_id) || !Number.isFinite(Date.parse(row.valid_from))) invalid();
  for (const id of [row.epoch_id, row.workspace_id, row.entity_id]) metricsId(id);
  if (scope.mode === 'workspace' && row.workspace_id !== scope.workspaceId) invalid();
  if (consumer) { if (row.entity_type !== 'consumers' || row.consumer_id !== row.entity_id) invalid(); metricsId(row.consumer_id); }
  else { if (row.entity_type !== 'routes' || row.route_id !== row.entity_id) invalid(); metricsId(row.service_id); metricsId(row.route_id); }
}

/** Only identities already proven by MetricsScopeService are accepted. */
export function currentLokiAssignments(cid: string, scope: MetricsScope) {
  metricsId(cid); metricsId(scope.workspaceId);
  if (!['workspace', 'cluster'].includes(scope.mode)) invalid();
  const pairs = unique(scope.epochs.filter(row => row.entity_type === 'routes'));
  const consumerPairs = unique(scope.consumerPairEpochs);
  const consumers = unique(scope.epochs.filter(row => row.entity_type === 'consumers'));
  for (const row of [...pairs, ...consumerPairs]) assertAssignment(cid, scope, row, false);
  for (const row of consumers) assertAssignment(cid, scope, row, true);
  if (new Set([...pairs, ...consumerPairs, ...consumers].map(row => row.epoch_id)).size > 256) throw new ConflictException({ code: 'METRICS_SELECTOR_BUDGET_EXHAUSTED', message: '日志指标身份超过 256 项，请缩小范围' });
  return { pairs, consumerPairs, consumers };
}
function pairPredicate(row: MetricsAssignment): string {
  return `(epoch_id=${quote(row.epoch_id)} and workspace_id=${quote(row.workspace_id)} and node_id=${quote(row.node_id)} and service_id=${quote(row.service_id!)} and route_id=${quote(row.route_id!)})`;
}
function stream(cid: string, rows: MetricsAssignment[], predicate = rows.map(pairPredicate).join(' or ')): string {
  // UUID validation precedes this regex; no user expression or template enters LogQL.
  const ids = rows.map(row => row.epoch_id).join('|') || 'a^';
  return `{job="kongos-collector",cluster_id=${quote(cid)},epoch_id=~${quote(ids)}}${predicate ? ` | ${predicate}` : ''}`;
}
export interface LokiTemplates {
  status: string; latency: (type: string, quantile: number) => string; bandwidth: string; services: string; consumers: string;
  nodes: string; datastore: string;
}
/** Fixed server-owned LogQL over the collector's explicit sanitized JSON schema. */
export function fixedLogql(cid: string, scope: MetricsScope, window: VitalsTimeWindow): LokiTemplates {
  if (!Number.isInteger(window.rateWindowSeconds) || window.rateWindowSeconds < 60 || window.rateWindowSeconds > 172800) invalid();
  const { pairs, consumerPairs, consumers } = currentLokiAssignments(cid, scope), base = stream(cid, pairs), interval = `${window.rateWindowSeconds}s`;
  const rates = (logs: string) => `rate(${logs} | json code="code" | code=~"[1-5][0-9][0-9]" | __error__="" [${interval}])`;
  const consumerGroups = new Map<string, { pairs: MetricsAssignment[]; consumers: MetricsAssignment[] }>();
  for (const pair of consumerPairs) {
    const matches = consumers.filter(consumer => consumer.workspace_id === pair.workspace_id && consumer.node_id === pair.node_id);
    if (!matches.length) continue;
    const key = `${pair.workspace_id}:${pair.node_id}`, group = consumerGroups.get(key) ?? { pairs: [], consumers: matches };
    group.pairs.push(pair); consumerGroups.set(key, group);
  }
  const consumerPredicate = [...consumerGroups.values()].map(group => `((${group.pairs.map(pairPredicate).join(' or ')}) and (${group.consumers.map(row => `(consumer_id=${quote(row.consumer_id!)} and consumer_epoch_id=${quote(row.epoch_id)})`).join(' or ')}))`).join(' or ');
  const consumerStream = stream(cid, consumerPredicate ? consumerPairs : [], consumerPredicate);
  const bytes = (name: 'ingress' | 'egress') => `label_replace(sum(sum_over_time(${base} | json bytes="bytes_${name}" | unwrap bytes | __error__="" [${interval}])) / ${window.rateWindowSeconds},"type","${name}","","")`;
  const result: LokiTemplates = {
    status: `sum by(code) (${rates(base)})`,
    latency: (type, quantile) => {
      if (!['request', 'upstream', 'kong'].includes(type) || ![0.5, 0.95, 0.99].includes(quantile)) invalid();
      return `quantile_over_time(${quantile},${base} | json latency="latency_${type}_ms" | unwrap latency | __error__="" [${interval}]) by ()`;
    },
    bandwidth: `${bytes('ingress')} or ${bytes('egress')}`,
    services: `topk(10,sum by(service_id) (${rates(base)}))`,
    consumers: `topk(10,sum by(consumer_id) (${rates(consumerStream)}))`,
    nodes: '', datastore: '',
  };
  for (const query of [result.status, result.bandwidth, result.services, result.consumers, result.latency('request', 0.5)]) if (query.length > 128 * 1024) throw new ConflictException({ code: 'METRICS_SELECTOR_BUDGET_EXHAUSTED', message: '日志查询表达式超过身份预算，请缩小范围' });
  return result;
}
export function lokiCompleteAfter(rows: MetricsAssignment[], window: VitalsTimeWindow): number {
  return Math.max(0, ...rows.map(row => Date.parse(row.valid_from))) + window.rateWindowSeconds * 1000;
}
