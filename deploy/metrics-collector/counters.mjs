import { CollectorError, isUuid } from './sanitize.mjs';

const escape = value => String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('\n', '\\n');
export class CollectorCounters {
  constructor({ maxSeries = 2048 } = {}) { this.maxSeries = maxSeries; this.rows = new Map(); this.diagnostics = new Map(); }
  diagnostic(clusterId, reason, count = 1) {
    const allowed = ['invalid_event', 'unassigned', 'capacity', 'loki_delivery_failed'];
    const safe = allowed.includes(reason) ? reason : 'unassigned';
    const key = JSON.stringify([clusterId, safe]);
    this.diagnostics.set(key, (this.diagnostics.get(key) || 0) + count);
  }
  add(clusterId, events, assignments) {
    const pending = [];
    const newKeys = new Set();
    events.forEach((event, index) => {
      const assignment = assignments[index];
      if (!assignment || assignment.quality !== 'verified') return;
      if (!isUuid(clusterId) || !/^[a-f0-9]{64}$/.test(assignment.nodeId || '') || ![event.serviceId, event.routeId, assignment.workspaceId, assignment.epochId].every(isUuid) || (event.consumerId && (!isUuid(event.consumerId) || !isUuid(assignment.consumerEpochId))) || !Number.isInteger(event.status) || event.status < 100 || event.status > 599 || [event.requestBytes, event.responseBytes].some(value => value !== undefined && (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1_073_741_824))) throw new CollectorError('COLLECTOR_EVENT_INVALID', 503);
      const labels = { cluster_id: clusterId, node_id: assignment.nodeId, service_id: event.serviceId, route_id: event.routeId, consumer_id: event.consumerId || '', workspace_id: assignment.workspaceId, epoch_id: assignment.epochId, consumer_epoch_id: assignment.consumerEpochId || '', code: String(event.status) };
      const key = JSON.stringify(labels);
      if (!this.rows.has(key)) newKeys.add(key);
      pending.push({ key, labels, event });
    });
    if (this.rows.size + newKeys.size > this.maxSeries) throw new CollectorError('COLLECTOR_SERIES_BUDGET_EXCEEDED', 503);
    for (const item of pending) {
      const row = this.rows.get(item.key) || { labels: item.labels, requests: 0, requestBytes: 0, responseBytes: 0 };
      // Deliberately preserve two identical legitimate events; no hash dedup.
      row.requests++;
      row.requestBytes += item.event.requestBytes || 0;
      row.responseBytes += item.event.responseBytes || 0;
      this.rows.set(item.key, row);
    }
    return pending.length;
  }
  render(clusterId) {
    if (!isUuid(clusterId)) throw new CollectorError('COLLECTOR_CLUSTER_INVALID');
    const lines = [
      '# HELP kongos_collector_requests_total Accepted verified http-log events; at-least-once approximate counts.',
      '# TYPE kongos_collector_requests_total counter',
      '# HELP kongos_collector_request_bytes_total Verified event request bytes.',
      '# TYPE kongos_collector_request_bytes_total counter',
      '# HELP kongos_collector_response_bytes_total Verified event response bytes.',
      '# TYPE kongos_collector_response_bytes_total counter',
      '# HELP kongos_collector_rejected_events_total Rejected or unassigned events without any object labels.',
      '# TYPE kongos_collector_rejected_events_total counter',
    ];
    for (const row of this.rows.values()) {
      if (row.labels.cluster_id !== clusterId) continue;
      const labels = Object.entries(row.labels).map(([key, value]) => `${key}="${escape(value)}"`).join(',');
      for (const [name, value] of [['requests', row.requests], ['request_bytes', row.requestBytes], ['response_bytes', row.responseBytes]]) lines.push(`kongos_collector_${name}_total{${labels}} ${value}`);
    }
    for (const [key, count] of this.diagnostics) {
      const [cluster, reason] = JSON.parse(key);
      if (cluster === clusterId) lines.push(`kongos_collector_rejected_events_total{cluster_id="${cluster}",reason="${reason}"} ${count}`);
    }
    const result = `${lines.join('\n')}\n`;
    if (Buffer.byteLength(result) > 2 * 1024 * 1024) throw new CollectorError('COLLECTOR_METRICS_BUDGET_EXCEEDED', 503);
    return result;
  }
}
