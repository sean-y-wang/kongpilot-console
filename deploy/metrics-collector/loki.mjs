import { readFileSync, statSync } from 'node:fs';
import { CollectorError, isUuid } from './sanitize.mjs';

function readAuth(path) {
  if (!path) return {};
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o077)) throw new Error('invalid');
    const token = readFileSync(path, 'utf8').trim();
    if (!/^[A-Za-z0-9._~-]{16,2048}$/.test(token)) throw new Error('invalid');
    return { authorization: `Bearer ${token}` };
  } catch { throw new CollectorError('COLLECTOR_LOKI_CONFIGURATION_INVALID', 503); }
}
export async function pushSanitizedLoki(clusterId, events, assignments, { fetchImpl = fetch, url = 'http://loki:3100', authFile } = {}) {
  if (url !== 'http://loki:3100') throw new CollectorError('COLLECTOR_LOKI_CONFIGURATION_INVALID', 503);
  const streams = [];
  events.forEach((event, index) => {
    const assignment = assignments[index];
    if (!assignment) return;
    if (assignment.quality !== 'verified' || !isUuid(clusterId) || !/^[a-f0-9]{64}$/.test(assignment.nodeId || '') || ![event.serviceId, event.routeId, assignment.workspaceId, assignment.epochId].every(isUuid) || (event.consumerId && (!isUuid(event.consumerId) || !isUuid(assignment.consumerEpochId))) || !Number.isInteger(event.status) || event.status < 100 || event.status > 599 || !Number.isFinite(event.startedAt) || event.startedAt < 0 || !Number.isFinite(event.endedAt) || event.endedAt < event.startedAt) throw new CollectorError('COLLECTOR_LOKI_EVENT_INVALID', 503);
    const stream = { job: 'kongos-collector', cluster_id: clusterId, node_id: assignment.nodeId, workspace_id: assignment.workspaceId, service_id: event.serviceId, route_id: event.routeId, epoch_id: assignment.epochId };
    if (event.consumerId) { stream.consumer_id = event.consumerId; stream.consumer_epoch_id = assignment.consumerEpochId; }
    // Exact explicit DTO, never raw JSON or event-dependent string fields.
    const latencies = {};
    for (const key of ['request', 'kong', 'proxy']) {
      const value = event.latencies?.[key];
      if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 300_000) latencies[key] = value;
    }
    const bytes = {};
    for (const [key, value] of [['request_bytes', event.requestBytes], ['response_bytes', event.responseBytes]]) if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1_073_741_824) bytes[key] = value;
    const line = JSON.stringify({ code: String(event.status), latency_request_ms: latencies.request ?? null, latency_upstream_ms: latencies.proxy ?? null, latency_kong_ms: latencies.kong ?? null, bytes_ingress: bytes.request_bytes ?? null, bytes_egress: bytes.response_bytes ?? null });
    streams.push({ stream, values: [[(BigInt(Math.trunc(event.startedAt)) * 1_000_000n).toString(), line]] });
  });
  if (!streams.length) return true;
  const body = JSON.stringify({ streams });
  if (Buffer.byteLength(body) > 2 * 1024 * 1024) throw new CollectorError('COLLECTOR_LOKI_BUDGET_EXCEEDED', 503);
  try {
    const response = await fetchImpl(`${url}/loki/api/v1/push`, { method: 'POST', body, headers: { 'content-type': 'application/json', ...readAuth(authFile) }, redirect: 'error', signal: AbortSignal.timeout(2000) });
    // Loki errors sometimes echo submitted content: never consume/log the body.
    await response.body?.cancel();
    return response.ok;
  } catch { return false; }
}
