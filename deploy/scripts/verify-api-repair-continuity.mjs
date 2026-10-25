import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function repairContainerProjection(name, container, includeProcess = true) {
  return { name, id: container.Id, image: container.Image,
    ...(includeProcess ? { startedAt: container.State.StartedAt } : {}),
    envSHA256: createHash('sha256').update(JSON.stringify([...(container.Config.Env || [])].sort())).digest('hex'),
    volumes: container.Mounts.filter(row => row.Type === 'volume').map(row => ({ name: row.Name, target: row.Destination })).sort((a, b) => a.target.localeCompare(b.target)),
    networks: Object.entries(container.NetworkSettings.Networks).map(([name, row]) => ({ name, id: row.NetworkID, ip: row.IPAddress })).sort((a, b) => a.name.localeCompare(b.name)) };
}

export function apiRepairContinuityChecks(before, after) {
  const checks = before.services.map(old => ({ name: `${old.name} process/container/image/env/volumes/networks unchanged`,
    passed: JSON.stringify(old) === JSON.stringify(after.services.find(row => row.name === old.name)) }));
  checks.push({ name: 'API container/image/env/volumes/networks unchanged; process restart only', passed: JSON.stringify(before.api) === JSON.stringify(after.api) });
  checks.push({ name: 'no extra preserved service appeared or disappeared', passed: before.services.length === after.services.length });
  checks.push({ name: 'all private environment and metrics material bytes unchanged', passed: before.materialSHA256 === after.materialSHA256 });
  checks.push({ name: 'monitoring generations/catalog revisions and immutable epochs unchanged', passed: JSON.stringify(before.database) === JSON.stringify(after.database) });
  return checks;
}

export function captureApiRepairSnapshot() {
  const project = process.env.COMPOSE_PROJECT_NAME || 'kongos-console';
  function container(service) {
    const ids = execFileSync('docker', ['ps', '-q', '--filter', `label=com.docker.compose.project=${project}`, '--filter', `label=com.docker.compose.service=${service}`], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 }).trim().split(/\s+/).filter(Boolean);
    if (ids.length !== 1) throw new Error('API_REPAIR_CONTAINER_INVALID');
    return JSON.parse(execFileSync('docker', ['inspect', ids[0]], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 }))[0];
  }
  const names = ['kong', 'kong-secondary', 'kong-db', 'kong-secondary-db', 'console-db', 'redis', 'telemetry-collector', 'prometheus', 'loki', 'echo-upstream', 'console-web', 'portal-web'];
  const api = container('console-api');
  const manifest = JSON.parse(readFileSync('deploy/private/metrics/manifest.json', 'utf8'));
  const paths = ['.env', '.env.multicluster', 'deploy/private/metrics/manifest.json', 'deploy/private/metrics/collector/credentials.json', 'deploy/private/metrics/prometheus/prometheus.yml'];
  for (const row of manifest.clusters) for (const purpose of ['native_scrape', 'collector_scrape']) paths.push(`deploy/private/metrics/prometheus/${row.clusterId}-${purpose}.token`);
  const hash = createHash('sha256');
  for (const path of paths.sort()) { hash.update(path); hash.update(readFileSync(path)); }
  const program = String.raw`const{Pool}=require('pg'),{createHash}=require('node:crypto');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});try{const settings=(await p.query('SELECT cluster_id,credential_generation,catalog_revision FROM metrics_settings ORDER BY cluster_id')).rows;const epochs=(await p.query('SELECT id,cluster_id,node_id,entity_type,entity_id,workspace_id,config_fingerprint,tags_fingerprint,source_pair_hash,valid_from,closed_at FROM metrics_assignment_epochs ORDER BY id')).rows;console.log(JSON.stringify({settings,epochCount:epochs.length,epochIdentitySHA256:createHash('sha256').update(JSON.stringify(epochs)).digest('hex')}));}finally{await p.end();}})().catch(()=>process.exit(1));`;
  const database = JSON.parse(execFileSync('docker', ['exec', '-i', api.Id, 'node', '-e', program], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000 }));
  return { observedAt: new Date().toISOString(), services: names.map(name => repairContainerProjection(name, container(name))), api: repairContainerProjection('console-api', api, false), materialSHA256: hash.digest('hex'), database };
}

export function apiRepairContinuityMain(args = process.argv.slice(2)) {
  const mode = args[0], label = args[1];
  if (args.length !== 2 || !['--before', '--after'].includes(mode) || !/^[a-z][a-z0-9-]{0,63}$/.test(label || '')) throw new Error('API_REPAIR_ARGUMENTS_INVALID');
  const directory = resolve('artifacts/M6');
  const output = resolve(directory, `api-repair-${label}-continuity.json`);
  if (mode === '--before' && existsSync(output)) throw new Error('API_REPAIR_BASELINE_EXISTS');
  const current = captureApiRepairSnapshot();
  mkdirSync(directory, { recursive: true });
  if (mode === '--before') {
    writeFileSync(output, JSON.stringify({ stage: 'M6', scope: 'API process-only repair; preserves all other processes and private material', label, allPassed: null, before: current }, null, 2) + '\n', { flag: 'wx' });
    console.log('API repair read-only continuity baseline captured; no private values recorded.');
  } else {
    const saved = JSON.parse(readFileSync(output, 'utf8'));
    if (saved.label !== label || saved.stage !== 'M6' || !saved.before) throw new Error('API_REPAIR_BASELINE_INVALID');
    const checks = apiRepairContinuityChecks(saved.before, current), allPassed = checks.every(row => row.passed);
    writeFileSync(output, JSON.stringify({ ...saved, after: current, checks, allPassed }, null, 2) + '\n');
    console.log(`${checks.filter(row => row.passed).length}/${checks.length} API-only repair continuity checks passed; no private values recorded.`);
    if (!allPassed) process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { apiRepairContinuityMain(); }
  catch { console.error('API_REPAIR_CONTINUITY_FAILED; no private values or raw tool errors printed.'); process.exitCode = 1; }
}
