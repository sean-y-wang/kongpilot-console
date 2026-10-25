import { escapePrometheusLabel } from '../bridges/prometheus-text';
import type { MetricsScope } from '../metrics-scope.service';
import type { VitalsTimeWindow } from '../vitals.types';
const re = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const quoted = (value: string) => `"${escapePrometheusLabel(value)}"`;
export function epochSelector(cid: string, scope: MetricsScope, consumer = false): string {
  const ids = [...new Set(scope.epochs.filter(epoch => consumer ? epoch.entity_type === 'consumers' : epoch.entity_type !== 'consumers').map(epoch => epoch.epoch_id))];
  return `cluster_id=${quoted(cid)},${scope.mode === 'workspace' ? `workspace_id=${quoted(scope.workspaceId)},` : ''}${consumer ? 'consumer_epoch_id' : 'membership_epoch'}=~${quoted(ids.length ? ids.map(re).join('|') : 'a^')}`;
}
export function nativeRate(metric: string, cid: string, scope: MetricsScope, window: VitalsTimeWindow, extra = ''): string {
  const selectors = epochSelector(cid, scope), match = `${selectors}${extra ? `,${extra}` : ''}`;
  // Each new epoch establishes a counter baseline. Do not extrapolate a short
  // epoch over a range that crosses its verified creation boundary.
  return `(rate(${metric}{${match}}[${window.rateWindowSeconds}s]) and on(cluster_id,node_id,membership_epoch) (time() - kongos_metrics_epoch_started_timestamp_seconds{${selectors}} >= ${window.rateWindowSeconds}))`;
}
export function fixedPromql(cid: string, scope: MetricsScope, window: VitalsTimeWindow) {
  const status = `sum by(code) (${nativeRate('kong_http_status', cid, scope, window)})`;
  const latency = (type: string, quantile: number) => `histogram_quantile(${quantile}, sum by(le) (${nativeRate('kong_latency_bucket', cid, scope, window, `type="${type}"`)}))`;
  const bandwidth = `sum by(type) (${nativeRate('kong_bandwidth', cid, scope, window)})`;
  const services = `topk(10, sum by(service_id) (${nativeRate('kong_http_status', cid, scope, window)}))`;
  const consumerGroups = new Map<string, string[]>();
  for (const epoch of scope.epochs) if (epoch.entity_type === 'consumers' && Date.parse(epoch.valid_from) <= Date.parse(window.end) - window.rateWindowSeconds * 1000) {
    const values = consumerGroups.get(epoch.workspace_id) || []; values.push(epoch.epoch_id); consumerGroups.set(epoch.workspace_id, values);
  }
  const consumerTerms = [...consumerGroups].map(([workspaceId, consumerEpochs]) => {
    const pairIds = scope.consumerPairEpochs.filter(epoch => epoch.workspace_id === workspaceId).map(epoch => re(epoch.epoch_id)).join('|') || 'a^';
    const selectors = `cluster_id=${quoted(cid)},workspace_id=${quoted(workspaceId)},consumer_epoch_id=~${quoted(consumerEpochs.map(re).join('|'))},epoch_id=~${quoted(pairIds)}`;
    const guard = `label_replace((time() - kongos_metrics_epoch_started_timestamp_seconds{cluster_id=${quoted(cid)},workspace_id=${quoted(workspaceId)},membership_epoch=~${quoted(pairIds)}} >= ${window.rateWindowSeconds}),"epoch_id","$1","membership_epoch","(.*)")`;
    return `(rate(kongos_collector_requests_total{${selectors}}[${window.rateWindowSeconds}s]) and on(cluster_id,node_id,epoch_id) ${guard})`;
  });
  const consumers = `topk(10, sum by(consumer_id) (${consumerTerms.length ? consumerTerms.join(' or ') : `rate(kongos_collector_requests_total{cluster_id=${quoted(cid)},consumer_epoch_id=~"a^"}[${window.rateWindowSeconds}s])`}))`;
  const nodes = `up{job_kind="kongos-native",cluster_id=${quoted(cid)}}`;
  const datastore = `kong_datastore_reachable{cluster_id=${quoted(cid)}}`;
  return { status, latency, bandwidth, services, consumers, nodes, datastore };
}
