import { createServer } from 'node:http';

const port = Number(process.env.PORT || 8081);
const server = createServer((request, response) => {
  response.setHeader('Content-Type', 'application/json');
  response.setHeader('Cache-Control', 'no-store');
  const url = new URL(request.url || '/', 'http://test-upstream.invalid');
  if (url.pathname === '/health') {
    response.end('{"status":"ok"}');
    return;
  }
  // Kong's consumer UUID is useful for credential tests. Never echo credentials.
  const consumer = request.headers['x-consumer-id'];
  const consumerId = typeof consumer === 'string' && /^[0-9a-f-]{36}$/i.test(consumer) ? consumer : null;
  response.end(JSON.stringify({ upstream: 'kongos-test', method: request.method, path: url.pathname, consumerId }));
  request.resume();
});
server.requestTimeout = 10_000;
server.headersTimeout = 10_000;
server.listen(port, '0.0.0.0', () => console.log(JSON.stringify({ event: 'test_upstream_ready', port })));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
