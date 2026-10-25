import { accessSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const proxyCa = process.env.CODEX_PROXY_CERT;
if (!proxyCa) throw new Error('CODEX_PROXY_CERT is not configured; ordinary docker compose build needs no override.');
accessSync(proxyCa);
const destination = resolve(process.argv[2] || '/tmp/kongos-compose-managed-build.yml');
const services = ['console-api', 'console-migrations', 'console-web'];
const content = 'services:\n' + services.map(service =>
  `  ${service}:\n    build:\n      secrets:\n        - proxy_ca\n`).join('') +
  `secrets:\n  proxy_ca:\n    file: ${JSON.stringify(proxyCa)}\n`;
writeFileSync(destination, content, { mode: 0o600 });
console.log(`Generated local build override ${destination}; TLS verification remains enabled.`);
