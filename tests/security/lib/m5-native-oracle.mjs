import { classicHistogramQuantile, compareMonitoringPoints, finitePrometheusValue, oracleMatrixPoints } from './m5-oracle.mjs';

/** Hand-written source-backed oracle. It does not import the BFF query builder. */
export function compareRealNativePrometheus(h, overview, { clusterId, workspaceId, serviceId, routeId, epochs }) {
  const quote = value => JSON.stringify(value);
  const current = epochs.filter(epoch => epoch.closed_at === null && epoch.entity_type !== 'consumers' && epoch.workspace_id === workspaceId && epoch.service_id === serviceId && (!routeId || epoch.route_id === routeId));
  h.check(current.length > 0, 'Oracle/Epoch', 'native oracle uses independently authenticated current verified identities');
  const selector = `cluster_id=${quote(clusterId)},workspace_id=${quote(workspaceId)},service_id=${quote(serviceId)},membership_epoch=~${quote(current.map(epoch => epoch.epoch_id).join('|'))}${routeId ? `,route_id=${quote(routeId)}` : ''}`;
  const window = overview.timeWindow;
  const evaluation = Date.parse(window.end) / 1000;
  const range = { start: Date.parse(window.start) / 1000, end: evaluation, step: window.step };
  const starts = h.prometheus(`kongos_metrics_epoch_started_timestamp_seconds{${selector}}`, { time: evaluation }).result;
  const epochStarted = new Map(starts.map(row => [row.metric.membership_epoch, finitePrometheusValue(row.value[1])]));
  h.check(epochStarted.size > 0, 'Oracle/Epoch', 'real bridge exports a baseline timestamp for the measured stable identity');
  const rawRate = (metric, extra = '') => h.prometheus(`rate(${metric}{${selector}${extra ? ',' + extra : ''}}[${window.rateWindowSeconds}s])`, range).result.map(row => ({ ...row, values: row.values.map(([seconds, value]) => {
    const started = epochStarted.get(row.metric.membership_epoch);
    return [seconds, started !== null && started !== undefined && seconds - started >= window.rateWindowSeconds ? value : 'NaN'];
  }) }));
  const status = rawRate('kong_http_status');
  const expected = {
    qps: oracleMatrixPoints(status),
    status2xx: oracleMatrixPoints(status.filter(row => /^2\d\d$/.test(row.metric.code))),
    status4xx: oracleMatrixPoints(status.filter(row => /^4\d\d$/.test(row.metric.code))),
    status5xx: oracleMatrixPoints(status.filter(row => /^5\d\d$/.test(row.metric.code))),
  };
  const bandwidth = rawRate('kong_bandwidth');
  expected.bandwidthIngress = oracleMatrixPoints(bandwidth.filter(row => row.metric.type === 'ingress'));
  expected.bandwidthEgress = oracleMatrixPoints(bandwidth.filter(row => row.metric.type === 'egress'));
  for (const [type, prefix] of [['request', 'latencyRequest'], ['upstream', 'latencyUpstream'], ['kong', 'latencyKong']]) {
    const buckets = rawRate('kong_latency_bucket', `type=${quote(type)}`);
    const byTimestamp = new Map();
    for (const row of buckets) for (const [seconds, raw] of row.values) {
      const value = finitePrometheusValue(raw);
      if (value === null) continue;
      const timestamp = Math.round(seconds * 1000);
      const byBound = byTimestamp.get(timestamp) ?? new Map();
      byBound.set(row.metric.le, (byBound.get(row.metric.le) ?? 0) + value);
      byTimestamp.set(timestamp, byBound);
    }
    for (const [quantile, suffix] of [[0.5, 'P50'], [0.95, 'P95'], [0.99, 'P99']]) expected[prefix + suffix] = [...byTimestamp].sort(([a], [b]) => a - b).map(([timestamp, bounds]) => [timestamp, classicHistogramQuantile(quantile, [...bounds])]);
  }
  const comparisons = {};
  for (const [name, oracle] of Object.entries(expected)) {
    try { comparisons[name] = compareMonitoringPoints(overview.series[name].map(point => [point.ts, point.value]), oracle); }
    catch (error) { error.message = `Native oracle ${name}: ${error.message}`; error.safeEvidenceMessage = true; throw error; }
    h.check(comparisons[name].compared > 0, 'Oracle/Series', `${name} has actual same-window numeric samples`);
  }
  h.check(overview.evaluationAt === window.end, 'Oracle/Time', 'BFF and oracle use the exact same evaluation timestamp');
  h.check(overview.units?.latency === 'milliseconds' && overview.units?.bandwidth === 'bytes/second' && overview.units?.throughput === 'requests/second', 'Oracle/Units', 'units match Kong1.5 actual millisecond buckets and byte counters');
  return { sameEvaluationAt: window.end, start: window.start, step: window.step, rateWindowSeconds: window.rateWindowSeconds, templateSource: 'independent raw rates plus explicit epoch-age masking and hand-computed classic histogram quantiles', comparisons };
}
