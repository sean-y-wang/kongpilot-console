import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

// Playwright diagnostics can contain failed request headers. Keep the raw
// diagnostic buffer private and scrub known credentials before displaying it.
const result = spawnSync('npx', ['playwright', 'test', 'tests/e2e/m4.spec.ts', ...process.argv.slice(2)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 });
const reference = '/tmp/kongos-m4-runtime-secrets.json';
const secrets = existsSync(reference) ? JSON.parse(readFileSync(reference, 'utf8')).secrets ?? [] : [];
let output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
for (const secret of secrets.filter(value => typeof value === 'string' && value.length >= 8).sort((a, b) => b.length - a.length)) {
  for (const spelling of [secret, JSON.stringify(secret).slice(1, -1), encodeURIComponent(secret)]) output = output.split(spelling).join('[REDACTED]');
}
if (result.status !== 0) process.stderr.write(output);
process.stdout.write(JSON.stringify({ browserExitCode: result.status, passed: result.status === 0, rawDiagnosticOutputPublished: false }) + '\n');
process.exitCode = result.status ?? 1;
