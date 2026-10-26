import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { portalAcceptanceChecks } from './portal-acceptance-policy.mjs';
const args = ['compose', '--env-file', '.env', '--env-file', '.env.multicluster', '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml', '-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test', '-f', 'deploy/compose/compose.metrics.yml', '--profile', 'observability'];
let checks = [];
try {
  const env = { ...process.env, KONG_PORTAL_DATABASE_PASSWORD: randomBytes(32).toString('hex') };
  const config = extra => JSON.parse(execFileSync('docker', [...args, ...extra, 'config', '--format', 'json'], { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000 }));
  checks = portalAcceptanceChecks(config([]), config(['-f', 'deploy/compose/compose.portal-acceptance.yml', '--profile', 'portal-acceptance']));
} catch { checks.push({ name: 'offline Compose validation completed', passed: false }); }
const result = { stage: 'M6', scope: 'offline optional C3 Compose facts only; no environment generated or runtime changed', observedAt: new Date().toISOString(), allPassed: checks.length > 0 && checks.every(row => row.passed), checks };
mkdirSync('artifacts/M6', { recursive: true });
writeFileSync('artifacts/M6/portal-acceptance-compose-verification.json', JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(row => row.passed).length}/${checks.length} isolated C3 offline Compose checks passed; no secret values recorded.`);
if (!result.allPassed) process.exitCode = 1;
