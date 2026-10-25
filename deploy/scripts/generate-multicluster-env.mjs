import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const target = resolve(process.argv[2] || '.env.multicluster');
const content = `KONG_SECONDARY_DATABASE_PASSWORD=${randomBytes(24).toString('hex')}\nKONG_SECONDARY_PROXY_PORT=9000\n`;
writeFileSync(target, content, { mode: 0o600, flag: 'wx' });
console.log(`Generated ${target} (mode 0600); credential values were not printed.`);
