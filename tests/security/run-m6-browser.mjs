import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { privateReference, M6_REFERENCE } from './lib/m6-harness.mjs';

if (process.env.M6_DEPLOYMENT_READY !== 'true') throw new Error('explicit M6 browser write-window handoff required');
const before = privateReference(M6_REFERENCE, true);
const result = spawnSync('npx', ['playwright', 'test', 'tests/e2e/m6.spec.ts', ...process.argv.slice(2)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 });
const after = existsSync(M6_REFERENCE) ? privateReference(M6_REFERENCE, true) : {};
const secrets = [...new Set([...(before.secrets ?? []), ...(after.secrets ?? []), ...(after.tokens ?? []).map(row => row.token)].filter(value => typeof value === 'string' && value.length >= 8))];
let output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
for (const value of secrets.sort((a, b) => b.length - a.length)) for (const spelling of [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString('base64')]) output = output.split(spelling).join('[REDACTED]');
if (result.status !== 0) process.stderr.write(output);
console.log(JSON.stringify({ browserExitCode: result.status, passed: result.status === 0, rawDiagnosticsPublished: false }));
process.exitCode = result.status ?? 1;
