import { createCollector } from './collector.mjs';

const server = createCollector({ lokiEnabled: process.env.COLLECTOR_LOKI_ENABLED === 'true', lokiAuthFile: process.env.COLLECTOR_LOKI_AUTH_FILE || undefined, lokiUrl: process.env.COLLECTOR_LOKI_URL || 'http://loki:3100' });
server.listen(9093, '0.0.0.0', () => process.stdout.write(JSON.stringify({ event: 'collector_started', port: 9093 }) + '\n'));
server.on('error', () => { process.stderr.write(JSON.stringify({ event: 'collector_start_failed' }) + '\n'); process.exitCode = 1; });
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => server.close(() => process.exit(0)));
