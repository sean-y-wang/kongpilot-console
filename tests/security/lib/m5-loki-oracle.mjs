import { compareMonitoringPoints } from './m5-oracle.mjs';

/** Compute an independent Loki window oracle from actual sanitized log entries. */
export function compareRealLokiEvents(h, overview, streamResult, currentRouteEpochs) {
  h.check(Array.isArray(streamResult) && currentRouteEpochs.length > 0, 'Loki/Oracle', 'actual streams and current verified Route epochs are present');
  const ids = new Set(currentRouteEpochs.map(epoch => epoch.epoch_id));
  const events = [];
  for (const stream of streamResult) {
    if (!ids.has(stream.stream.epoch_id)) continue;
    for (const [nanoseconds, serialized] of stream.values) {
      const value = JSON.parse(serialized);
      events.push({ ts: Number(BigInt(nanoseconds) / 1_000_000n), value });
    }
  }
  h.check(events.length > 0, 'Loki/Oracle', 'real sanitized events exist under the selected current epochs');
  const window = overview.timeWindow, duration = window.rateWindowSeconds * 1000;
  const earliestComplete = Math.max(...currentRouteEpochs.map(epoch => Date.parse(epoch.valid_from))) + duration;
  const percentile = (numbers, q) => {
    const sorted = numbers.filter(value => typeof value === 'number' && Number.isFinite(value)).sort((a, b) => a - b);
    if (!sorted.length) return null;
    const rank = q * (sorted.length - 1), lower = Math.floor(rank), upper = Math.ceil(rank);
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (rank - lower);
  };
  const comparisons = {};
  for (const [name, points] of Object.entries(overview.series)) {
    const oracle = points.map(point => {
      if (point.ts < earliestComplete) return [point.ts, null];
      const samples = events.filter(event => event.ts > point.ts - duration && event.ts <= point.ts);
      if (name === 'qps') return [point.ts, samples.length ? samples.length / window.rateWindowSeconds : null];
      if (/^status[245]xx$/.test(name)) {
        const family = name[6], matching = samples.filter(event => String(event.value.code).startsWith(family));
        return [point.ts, matching.length ? matching.length / window.rateWindowSeconds : null];
      }
      if (/^bandwidth/.test(name)) {
        const key = name === 'bandwidthIngress' ? 'bytes_ingress' : 'bytes_egress';
        const bytes = samples.map(event => event.value[key]).filter(value => typeof value === 'number' && Number.isFinite(value));
        return [point.ts, bytes.length ? bytes.reduce((sum, value) => sum + value, 0) / window.rateWindowSeconds : null];
      }
      const match = /^latency(Request|Upstream|Kong)P(50|95|99)$/.exec(name);
      if (!match) throw new Error('unexpected public Loki series');
      return [point.ts, percentile(samples.map(event => event.value[`latency_${match[1].toLowerCase()}_ms`]), Number(match[2]) / 100)];
    });
    try { comparisons[name] = compareMonitoringPoints(points.map(point => [point.ts, point.value]), oracle, { absolute: 1e-6, relative: 1e-6 }); }
    catch (error) { error.message = `Loki oracle ${name}: ${error.message}`; error.safeEvidenceMessage = true; throw error; }
    h.check(comparisons[name].compared > 0, 'Loki/Oracle', `${name} matches the actual same-window sanitized-event calculation`);
  }
  return { sameEvaluationAt: window.end, realSanitizedEvents: events.length, currentRouteEpochs: currentRouteEpochs.length, semantics: 'at_least_once_approximate', unit: 'milliseconds', comparisons };
}
