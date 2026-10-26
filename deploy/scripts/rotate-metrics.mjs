import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, renameSync, chownSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { materialFromEnrollment, prometheusConfiguration } from './metrics-material.mjs';

if (!process.argv.includes('--confirmed')) { console.error('Rotation requires --confirmed and bounded JSON stdin; tokens are never accepted as command arguments.'); process.exit(2); }
const multicluster = process.argv.includes('--multicluster');
const compose = ['compose', '--env-file', '.env', ...(multicluster ? ['--env-file', '.env.multicluster'] : []), '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml', ...(multicluster ? ['-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test'] : []), '-f', 'deploy/compose/compose.metrics.yml', '--profile', 'observability'];
const directory = resolve('deploy/private/metrics');
function atomic(path, text, uid) {
  const temporary = `${path}.pending`;
  writeFileSync(temporary, text, { flag: 'wx', mode: 0o400 });
  if (process.getuid?.() === 0) chownSync(temporary, uid, uid);
  renameSync(temporary, path);
  chmodSync(path, 0o400);
}
try {
  if (![0, 1000].includes(process.getuid?.())) throw new Error('METRICS_DEPLOYMENT_UID_UNSUPPORTED');
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 8192) throw new Error('budget'); chunks.push(chunk); }
  const material = materialFromEnrollment(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  chunks.length = 0;
  const manifest = JSON.parse(readFileSync(resolve(directory, 'manifest.json'), 'utf8'));
  const config = JSON.parse(readFileSync(resolve(directory, 'collector/credentials.json'), 'utf8'));
  if (!manifest.clusters.some(row => row.clusterId === material.enrollment.clusterId) || !config.clusters.some(row => row.clusterId === material.enrollment.clusterId)) throw new Error('unknown');
  const output = execFileSync('docker', [...compose, 'exec', '-T', 'console-api', 'node', 'dist/infrastructure/metrics-enroll.js'], { input: JSON.stringify(material.enrollment), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 20_000 });
  const result = JSON.parse(output);
  if (!result.enrolled || result.clusterId !== material.enrollment.clusterId || result.generation !== material.enrollment.generation) throw new Error('enrollment');
  const previous = manifest.clusters.find(row => row.clusterId === result.clusterId);
  const record = { clusterId: result.clusterId, nodeId: previous.nodeId, generation: result.generation, fingerprints: material.fingerprints, state: 'pending' };
  manifest.clusters = manifest.clusters.map(row => row.clusterId === record.clusterId ? record : row);
  atomic(resolve(directory, 'manifest.json'), JSON.stringify(manifest) + '\n', 0);
  atomic(resolve(directory, `prometheus/${record.clusterId}-native_scrape.token`), material.prometheus.native + '\n', 1000);
  atomic(resolve(directory, `prometheus/${record.clusterId}-collector_scrape.token`), material.prometheus.collector + '\n', 1000);
  config.clusters = config.clusters.map(row => row.clusterId === record.clusterId ? material.collector : row);
  atomic(resolve(directory, 'collector/credentials.json'), JSON.stringify(config) + '\n', 1000);
  record.state = 'ready';
  atomic(resolve(directory, 'prometheus/prometheus.yml'), prometheusConfiguration(manifest.clusters), 1000);
  atomic(resolve(directory, 'manifest.json'), JSON.stringify(manifest) + '\n', 0);
  // No secrets in process arguments; mounted directories see the new inodes.
  execFileSync('docker', [...compose, 'exec', '-T', 'prometheus', '/bin/promtool', 'check', 'config', '/etc/prometheus/prometheus.yml'], { stdio: ['pipe', 'pipe', 'pipe'], timeout: 15_000 });
  execFileSync('docker', [...compose, 'exec', '-T', 'prometheus', 'wget', '-Y', 'off', '-q', '-O', '/dev/null', '--post-data=', 'http://127.0.0.1:9090/-/reload'], { stdio: ['pipe', 'pipe', 'pipe'], timeout: 15_000 });
  console.log(JSON.stringify({ rotated: true, clusterId: record.clusterId, generation: record.generation, rawIngestPersisted: false, nativePluginRequiresAuthorizedReprovision: true }));
} catch {
  console.error('METRICS_ROTATION_FAILED: no token or error response was printed; review protected state and repeat only with the confirmed original bundle or a newer generation.');
  process.exitCode = 1;
}
