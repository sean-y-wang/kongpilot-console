import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

// A narrow continuation after the preserved M5 daemon tmpfs failure. The API,
// compiled sources, schema007 and enrolled families already passed their steps.
const evidence = JSON.parse(readFileSync('artifacts/M5/startup-before-collector-tmpfs-fix.json', 'utf8'));
if (evidence.failedStep !== 'apply-metrics-services') { console.error('M5_CONTINUATION_PRECONDITION_FAILED'); process.exit(2); }
const compose = ['compose', '--env-file', '.env', '--env-file', '.env.multicluster', '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml', '-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test', '-f', 'deploy/compose/compose.metrics.yml', '--profile', 'observability'];
const generations = () => JSON.parse(readFileSync('deploy/private/metrics/manifest.json', 'utf8')).clusters.map(row => ({ clusterId: row.clusterId, generation: row.generation }));
const before = generations();
const commands = [];
let step = 'metrics-services';
let allPassed = false;
function run(name, command, args) { step = name; execFileSync(command, args, { stdio: 'inherit' }); commands.push({ name, completed: true }); }
try {
  run('metrics-services', 'docker', [...compose, 'up', '-d', '--no-deps', '--no-build', '--wait', '--wait-timeout', '45', 'telemetry-collector', 'prometheus', 'loki']);
  run('prometheus-reload', 'docker', [...compose, 'exec', '-T', 'prometheus', 'wget', '-Y', 'off', '-q', '-O', '/dev/null', '--post-data=', 'http://127.0.0.1:9090/-/reload']);
  run('apply-web-config', 'docker', [...compose, 'up', '-d', '--no-deps', '--no-build', 'console-web']);
  run('nginx-config', 'docker', [...compose, 'exec', '-T', 'console-web', 'nginx', '-t']);
  run('restart-web', 'docker', [...compose, 'restart', 'console-web']);
  run('complete-runtime-verification', 'node', ['deploy/scripts/stage-deploy.mjs', 'M5', '--multicluster', '--observability', '--verify-only']);
  if (JSON.stringify(before) !== JSON.stringify(generations())) throw new Error('generation changed');
  allPassed = true;
} catch { process.exitCode = 1; console.error(`M5_CONTINUATION_FAILED at ${step}; no secrets or response bodies recorded.`); }
writeFileSync('artifacts/M5/deployment-continuation.json', JSON.stringify({ stage: 'M5', observedAt: new Date().toISOString(), allPassed, failedStep: allPassed ? null : step, priorEvidence: 'startup-before-collector-tmpfs-fix.json', compilationRepeated: false, migrationRepeated: false, enrollmentRepeated: false, credentialGenerations: before, commands }, null, 2) + '\n');
