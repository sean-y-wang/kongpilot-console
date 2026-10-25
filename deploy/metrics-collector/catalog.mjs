import { CollectorError, isUuid } from './sanitize.mjs';

async function boundedJson(response, maximum = 2 * 1024 * 1024) {
  if (response.headers.get('content-encoding') && response.headers.get('content-encoding') !== 'identity') throw new CollectorError('COLLECTOR_CATALOG_UNAVAILABLE', 503);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body || []) {
    size += chunk.byteLength;
    if (size > maximum) throw new CollectorError('COLLECTOR_CATALOG_UNAVAILABLE', 503);
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new CollectorError('COLLECTOR_CATALOG_UNAVAILABLE', 503); }
}
export async function validateAssignments(config, events, { fetchImpl = fetch, bridge = 'http://metrics-bff:9092', deadline = Date.now() + 10_000, now = Date.now } = {}) {
  // Fixed private authority. Neither event JSON nor HTTP parameters select URLs.
  if (bridge !== 'http://metrics-bff:9092') throw new CollectorError('COLLECTOR_CATALOG_CONFIGURATION_INVALID', 503);
  const output = [];
  let offset = 0;
  let probe = events.length === 0;
  while (offset < events.length || probe) {
    probe = false;
    const batch = [];
    let referenceCount = 0;
    while (offset < events.length) {
      const event = events[offset];
      const count = event.consumerId ? 3 : 2;
      if (referenceCount + count > 256) break;
      referenceCount += count;
      batch.push(event);
      offset++;
    }
    const body = JSON.stringify({ refs: batch.map(event => ({ serviceId: event.serviceId, routeId: event.routeId, ...(event.consumerId ? { consumerId: event.consumerId } : {}), startedAt: event.startedAt, endedAt: event.endedAt })) });
    if (Buffer.byteLength(body) > 128 * 1024 || now() >= deadline) throw new CollectorError('COLLECTOR_CATALOG_BUDGET_EXCEEDED', 503);
    let result;
    try {
      const response = await fetchImpl(`${bridge}/catalog/${config.clusterId}/validate`, { method: 'POST', headers: { 'content-type': 'application/json', 'accept-encoding': 'identity', authorization: `Bearer ${config.catalogToken}` }, body, redirect: 'error', signal: AbortSignal.timeout(Math.max(1, Math.min(5000, deadline - now()))) });
      if (!response.ok) throw new Error('status');
      result = await boundedJson(response);
    } catch { throw new CollectorError('COLLECTOR_CATALOG_UNAVAILABLE', 503); }
    if (!result || !['string', 'number'].includes(typeof result.catalogRevision) || result.credentialGeneration !== config.generation || !Array.isArray(result.items) || result.items.length !== batch.length) throw new CollectorError('COLLECTOR_CATALOG_INVALID', 503);
    const seen = new Set();
    const assignments = Array(batch.length).fill(null);
    for (const item of result.items) {
      if (!item || !Number.isInteger(item.index) || item.index < 0 || item.index >= batch.length || seen.has(item.index)) throw new CollectorError('COLLECTOR_CATALOG_INVALID', 503);
      seen.add(item.index);
      if (item.quality !== 'verified') continue;
      const event = batch[item.index];
      if (item.clusterId !== config.clusterId || item.serviceId !== event.serviceId || item.routeId !== event.routeId || (item.consumerId || undefined) !== event.consumerId || !/^[a-f0-9]{64}$/.test(item.nodeId || '') || !isUuid(item.workspaceId) || !isUuid(item.epochId) || (event.consumerId && !isUuid(item.consumerEpochId)) || !Number.isFinite(item.validFrom) || item.validFrom < 0 || item.validFrom > event.startedAt || (item.validUntil !== null && (!Number.isFinite(item.validUntil) || item.validUntil < event.endedAt))) throw new CollectorError('COLLECTOR_CATALOG_INVALID', 503);
      assignments[item.index] = { quality: 'verified', nodeId: item.nodeId, workspaceId: item.workspaceId, epochId: item.epochId, ...(event.consumerId ? { consumerEpochId: item.consumerEpochId } : {}) };
    }
    output.push(...assignments);
  }
  return output;
}
