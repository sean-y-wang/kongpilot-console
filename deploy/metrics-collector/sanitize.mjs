const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const isUuid = value => typeof value === 'string' && UUID.test(value);
export class CollectorError extends Error {
  constructor(code, status = 400) { super(code); this.code = code; this.status = status; }
}
const own = (object, key) => object && typeof object === 'object' && Object.hasOwn(object, key) ? object[key] : undefined;
const number = (value, maximum) => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= maximum ? value : undefined;
// Kong1.5 basic-log-serializer preserves ngx.var request_length/bytes_sent as
// decimal strings. Parse only these byte fields, never arbitrary event values.
const bytes = value => {
  const parsed = typeof value === 'string' && /^(?:0|[1-9][0-9]{0,9})$/.test(value) ? Number(value) : value;
  return typeof parsed === 'number' && Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 1_073_741_824 ? parsed : undefined;
};
const id = object => { const value = own(object, 'id'); return isUuid(value) ? value.toLowerCase() : undefined; };

// Do not copy/serialize the original event. Lua's serializer includes credentials
// in headers and URL fields, which must never leave this function.
export function sanitizeEvent(value, now = Date.now()) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const serviceId = id(own(value, 'service'));
  const routeId = id(own(value, 'route'));
  const consumer = own(value, 'consumer');
  const consumerId = consumer == null ? undefined : id(consumer);
  const response = own(value, 'response');
  const status = own(response, 'status');
  const rawStartedAt = number(own(value, 'started_at'), now + 1000);
  const latencySource = own(value, 'latencies');
  const request = number(own(latencySource, 'request'), 300_000);
  if (!serviceId || !routeId || (consumer != null && !consumerId) || !Number.isInteger(status) || status < 100 || status > 599 || rawStartedAt === undefined || rawStartedAt < now - 300_000 || request === undefined) return null;
  // Serializer ngx timestamps can contain fractions. Outward rounding preserves
  // the complete request interval; rounding inward could cross an epoch fence.
  const startedAt = Math.floor(rawStartedAt);
  const endedAt = Math.ceil(rawStartedAt + request);
  if (endedAt > now + 1000 || endedAt - startedAt > 300_000) return null;
  const latencies = { request };
  for (const name of ['kong', 'proxy']) {
    const duration = number(own(latencySource, name), 300_000);
    if (duration !== undefined) latencies[name] = duration;
  }
  const result = { serviceId, routeId, ...(consumerId ? { consumerId } : {}), status, startedAt, endedAt, latencies };
  const requestBytes = bytes(own(own(value, 'request'), 'size'));
  const responseBytes = bytes(own(response, 'size'));
  if (requestBytes !== undefined) result.requestBytes = requestBytes;
  if (responseBytes !== undefined) result.responseBytes = responseBytes;
  return result;
}

export function sanitizeBatch(payload, now = Date.now()) {
  const input = Array.isArray(payload) ? payload : [payload];
  if (!input.length || input.length > 1000) throw new CollectorError('COLLECTOR_BATCH_SIZE_INVALID');
  const events = [];
  let safeRejectedCount = 0;
  for (const raw of input) {
    const event = sanitizeEvent(raw, now);
    if (event) events.push(event); else safeRejectedCount++;
  }
  return { events, safeRejectedCount };
}
