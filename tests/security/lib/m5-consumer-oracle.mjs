import { finitePrometheusValue } from './m5-oracle.mjs';

/** Independently sum real collector counter rates over current two-epoch pairs. */
export function compareRealConsumerPrometheus(h, overview, { clusterId, workspaceId, consumerId, epochs }) {
  const consumer = epochs.filter(epoch => epoch.closed_at === null && epoch.entity_type === 'consumers' && epoch.consumer_id === consumerId && epoch.workspace_id === workspaceId);
  const pairs = epochs.filter(epoch => epoch.closed_at === null && epoch.entity_type === 'routes' && epoch.workspace_id === workspaceId);
  h.check(consumer.length === 1 && pairs.length > 0, 'Consumer/Oracle', 'own Consumer and same-workspace Route pairs are independently verified');
  const window = overview.timeWindow, seconds = Date.parse(window.end) / 1000;
  const quote = value => JSON.stringify(value);
  const selector = `cluster_id=${quote(clusterId)},workspace_id=${quote(workspaceId)},consumer_id=${quote(consumerId)},consumer_epoch_id=${quote(consumer[0].epoch_id)},epoch_id=~${quote(pairs.map(pair => pair.epoch_id).join('|'))}`;
  const starts = h.prometheus(`kongos_metrics_epoch_started_timestamp_seconds{cluster_id=${quote(clusterId)},workspace_id=${quote(workspaceId)}}`, { time: seconds }).result;
  const startByEpoch = new Map(starts.map(row => [row.metric.membership_epoch, finitePrometheusValue(row.value[1])]));
  const actual = h.prometheus(`rate(kongos_collector_requests_total{${selector}}[${window.rateWindowSeconds}s])`, { time: seconds }).result;
  let total = null, matchedSeries = 0;
  for (const row of actual) {
    const start = startByEpoch.get(row.metric.epoch_id), value = finitePrometheusValue(row.value[1]);
    if (value === null || start == null || seconds - start < window.rateWindowSeconds || seconds - Date.parse(consumer[0].valid_from) / 1000 < window.rateWindowSeconds) continue;
    total = (total ?? 0) + value; matchedSeries++;
  }
  const exposed = overview.topN.consumers.find(row => row.id === consumerId)?.value ?? null;
  h.check(total !== null && total > 0 && exposed !== null && Math.abs(total - exposed) <= 1e-8 + Math.abs(total) * 1e-6, 'Consumer/Oracle', 'own Consumer TopN equals actual same-evaluation collector rates with both current epoch filters');
  return { evaluationAt: window.end, rateWindowSeconds: window.rateWindowSeconds, matchedSeries, sameWorkspacePairs: pairs.length, actualValue: total, exposedValue: exposed, semantics: 'at_least_once_approximate' };
}

/** A narrow counter parser; labels/values stay private, only safe totals escape. */
export function collectorCounterTotal(text, labels) {
  let result = 0;
  for (const line of text.split('\n')) {
    const match = /^kongos_collector_requests_total\{(.+)\}\s+(\S+)$/.exec(line);
    if (!match) continue;
    if (Object.entries(labels).every(([key, value]) => match[1].includes(`${key}=${JSON.stringify(value)}`))) {
      const value = finitePrometheusValue(match[2]);
      if (value === null || value < 0) throw new Error('collector counter is invalid');
      result += value;
    }
  }
  return result;
}
