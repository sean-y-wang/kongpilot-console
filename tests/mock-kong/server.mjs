import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureDir = process.env.KONG_FIXTURES || resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/kong-1.5.1');
const port = Number(process.env.MOCK_KONG_PORT || 18001);
const host = process.env.MOCK_KONG_HOST || '127.0.0.1';
let scenario = { mode: 'normal', delayMs: 0, version: '1.5.1' };
const requests = [];
const fixture = name => JSON.parse(readFileSync(resolve(fixtureDir, name), 'utf8'));
const entities = new Set(['services','routes','consumers','plugins','certificates','ca_certificates','snis','upstreams']);
function respond(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', 'x-kong-mock': 'true' });
  res.end(JSON.stringify(body));
}
async function readBody(req) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 64 * 1024) throw new Error('Body too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}
createServer(async (req, res) => {
  const url = new URL(req.url, 'http://mock-kong');
  try {
    if (url.pathname === '/__control' && req.method === 'POST') {
      const body = await readBody(req);
      const allowed = ['normal','unavailable','validation','timeout','pagination','unsafe-next'];
      if (!allowed.includes(body.mode || 'normal')) return respond(res, 400, { message: 'Unknown mock mode' });
      scenario = { mode: body.mode || 'normal', delayMs: Math.min(Math.max(Number(body.delayMs || 0), 0), 30000), version: String(body.version || '1.5.1') };
      requests.length = 0;
      return respond(res, 200, { ...scenario, mock: true });
    }
    if (url.pathname === '/__requests' && req.method === 'GET') return respond(res, 200, requests);
    if (url.pathname === '/__health') return respond(res, 200, { mock: true });
    const safeQuery = Object.fromEntries([...url.searchParams].map(([key,value]) => [key, ['size','offset','tags'].includes(key) ? value : '[REDACTED]']));
    requests.push({ method: req.method, path: url.pathname, query: safeQuery, at: new Date().toISOString() });
    if (requests.length > 500) requests.shift();
    if (scenario.mode === 'timeout' || scenario.delayMs) await new Promise(r => setTimeout(r, scenario.delayMs || 10000));
    if (res.destroyed) return;
    if (scenario.mode === 'unavailable') return respond(res, 503, { message: 'Mock upstream unavailable' });
    if (scenario.mode === 'validation') return respond(res, 400, { message: 'schema violation (host: required field missing)', fields: { host: 'required field missing', config: { limit: 'expected a number' } } });
    if (req.method !== 'GET') return respond(res, 405, { message: 'M0 mock is read-only' });
    if (url.pathname === '/') return respond(res, 200, { ...fixture('root.json'), version: scenario.version });
    if (url.pathname === '/status') return respond(res, 200, fixture('status.json'));
    if (url.pathname === '/endpoints') return respond(res, 200, fixture('endpoints.json'));
    if (url.pathname === '/plugins/enabled') return respond(res, 200, fixture('plugins-enabled.json'));
    const schema = url.pathname.match(/^\/schemas\/([a-z_]+)$/);
    if (schema && entities.has(schema[1])) return respond(res, 200, fixture(`schema-${schema[1]}.json`));
    const plugin = url.pathname.match(/^\/plugins\/schema\/([a-z0-9-]+)$/);
    if (plugin) {
      try { return respond(res, 200, fixture(`plugin-schema-${plugin[1]}.json`)); }
      catch { return respond(res, 404, { message: 'No plugin named ' + plugin[1] }); }
    }
    const entity = url.pathname.slice(1);
    if (entities.has(entity)) {
      if (scenario.mode === 'pagination' || scenario.mode === 'unsafe-next') {
        const offset = url.searchParams.get('offset');
        const size = Math.min(Math.max(Number(url.searchParams.get('size') || 2), 1), 100);
        // Clearly synthetic records are used solely for cursor tests.
        const items = [1,2,3].map(n => ({ id: `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`, name: `synthetic-pagination-${n}`, tags: ['mock-fixture'] }));
        const start = offset === 'synthetic-page-2' ? 2 : Number(offset?.match(/^synthetic-offset-(\d+)$/)?.[1] || 0);
        const data = items.slice(start, start + size);
        const nextOffset = `synthetic-offset-${start + size}`;
        const next = start + size < items.length ?
          (scenario.mode === 'unsafe-next' ? `http://unregistered.example/services?offset=${nextOffset}` : `/${entity}?offset=${nextOffset}&size=${size}`) : null;
        return respond(res, 200, { data, next, offset: next ? nextOffset : null });
      }
      return respond(res, 200, fixture(`list-${entity}-empty.json`));
    }
    return respond(res, 404, { message: 'Not found' });
  } catch (error) {
    if (!res.headersSent) respond(res, 400, { message: 'Invalid mock request' });
  }
}).listen(port, host, () => console.log(`Read-only Kong 1.5.1 fixture mock listening on ${host}:${port}; synthetic scenarios are explicitly marked.`));
