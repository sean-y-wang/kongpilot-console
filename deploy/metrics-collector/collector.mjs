import { createServer } from 'node:http';
import { authorization, matchesToken, readConfiguration, validateConfig } from './config.mjs';
import { sanitizeBatch, CollectorError, isUuid } from './sanitize.mjs';
import { validateAssignments } from './catalog.mjs';
import { CollectorCounters } from './counters.mjs';
import { pushSanitizedLoki } from './loki.mjs';

async function body(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw new CollectorError('COLLECTOR_BODY_TOO_LARGE', 413);
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new CollectorError('COLLECTOR_JSON_INVALID'); }
}
const json = (response, status, value) => { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); response.end(JSON.stringify(value)); };

export function createCollector({ readConfig = readConfiguration, fetchImpl = fetch, now = Date.now, counters = new CollectorCounters(), lokiEnabled = false, lokiAuthFile, lokiUrl = 'http://loki:3100' } = {}) {
  const active = new Map();
  const rate = new Map();
  function current(clusterId) { return validateConfig(readConfig()).find(row => row.clusterId === clusterId); }
  function unchanged(config) {
    const fresh = current(config.clusterId);
    if (!fresh || fresh.generation !== config.generation || fresh.catalogToken !== config.catalogToken || fresh.ingestFingerprint !== config.ingestFingerprint || fresh.scrapeFingerprint !== config.scrapeFingerprint) throw new CollectorError('METRICS_TOKEN_INVALID', 401);
  }
  const server = createServer(async (request, response) => {
    let clusterId;
    let held = false;
    try {
      if (request.url === '/healthz' && request.method === 'GET') { validateConfig(readConfig()); return json(response, 200, { status: 'ready' }); }
      const match = /^\/(ingest|metrics)\/([0-9a-f-]{36})$/.exec(request.url || '');
      if (!match || !isUuid(match[2])) throw new CollectorError('COLLECTOR_NOT_FOUND', 404);
      clusterId = match[2];
      const ingest = match[1] === 'ingest';
      if (request.method !== (ingest ? 'POST' : 'GET')) throw new CollectorError('COLLECTOR_METHOD_NOT_ALLOWED', 405);
      const config = current(clusterId);
      const token = authorization(request, ingest ? 'basic' : 'bearer');
      if (!config || !matchesToken(token, ingest ? config.ingestFingerprint : config.scrapeFingerprint)) throw new CollectorError('METRICS_TOKEN_INVALID', 401);
      const window = Math.floor(now() / 1000);
      const budget = rate.get(clusterId);
      const count = budget?.window === window ? budget.count + 1 : 1;
      rate.set(clusterId, { window, count });
      if (count > 20) throw new CollectorError('COLLECTOR_RATE_LIMITED', 429);
      if ((active.get(clusterId) || 0) >= 2) throw new CollectorError('COLLECTOR_BUSY', 429);
      active.set(clusterId, (active.get(clusterId) || 0) + 1); held = true;
      if (!ingest) {
        // Empty validation still authenticates the current DB generation/fence.
        await validateAssignments(config, [], { fetchImpl, now, deadline: now() + 5000 });
        unchanged(config);
        response.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store' });
        return response.end(counters.render(clusterId));
      }
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] || '') || request.headers['content-encoding']) throw new CollectorError('COLLECTOR_CONTENT_TYPE_INVALID', 415);
      const { events, safeRejectedCount } = sanitizeBatch(await body(request), now());
      const assignments = await validateAssignments(config, events, { fetchImpl, now, deadline: now() + 10_000 });
      unchanged(config);
      const accepted = counters.add(clusterId, events, assignments);
      const rejected = safeRejectedCount + events.length - accepted;
      if (safeRejectedCount) counters.diagnostic(clusterId, 'invalid_event', safeRejectedCount);
      if (events.length > accepted) counters.diagnostic(clusterId, 'unassigned', events.length - accepted);
      if (lokiEnabled) {
        let delivered = false;
        try { delivered = await pushSanitizedLoki(clusterId, events, assignments, { fetchImpl, authFile: lokiAuthFile, url: lokiUrl }); } catch { /* preserve accepted counters; do not echo Loki errors */ }
        if (!delivered) counters.diagnostic(clusterId, 'loki_delivery_failed');
      }
      return json(response, 202, { accepted, rejected, semantics: 'at_least_once_approximate' });
    } catch (error) {
      if (!response.headersSent) json(response, error instanceof CollectorError ? error.status : 503, { error: { code: error instanceof CollectorError ? error.code : 'COLLECTOR_UNAVAILABLE' } });
      else response.end();
    } finally { if (held) active.set(clusterId, Math.max(0, (active.get(clusterId) || 1) - 1)); }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 32;
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); });
  return server;
}
