import { execFileSync } from 'node:child_process';
import { readFileSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
const evidenceStage=process.env.METRICS_EVIDENCE_STAGE||'M5';
const evidenceDirectory=resolve(process.env.METRICS_EVIDENCE_DIRECTORY||`artifacts/${evidenceStage}`);
const multicluster = process.argv.includes('--multicluster');
const compose = ['compose', '--env-file', '.env', ...(multicluster ? ['--env-file', '.env.multicluster'] : []), '-f', 'docker-compose.yml', '-f', 'deploy/compose.development.yml', ...(multicluster ? ['-f', 'deploy/compose.multicluster-test.yml', '--profile', 'multicluster-test'] : []), '-f', 'deploy/compose.metrics.yml', '--profile', 'observability'];
const checks = [];
const collectorSources = [];
let collectorIdentity;
const check = (name, passed) => checks.push({ name, passed: Boolean(passed) });
function inspect(service) {
  const id = execFileSync('docker', [...compose, 'ps', '-q', service], { encoding: 'utf8' }).trim();
  if (!id) throw new Error('missing');
  return JSON.parse(execFileSync('docker', ['inspect', id], { encoding: 'utf8' }))[0];
}
try {
  const api = inspect('console-api');
  check('API telemetry listener enabled', api.Config.Env.includes('METRICS_BRIDGE_ENABLED=true'));
  const telemetry = Object.entries(api.NetworkSettings.Networks).find(([name]) => name.endsWith('_telemetry'))?.[1];
  check('API listener binds telemetry IPv4', Boolean(telemetry?.IPAddress) && api.Config.Env.includes(`METRICS_BRIDGE_HOST=${telemetry.IPAddress}`));
  for (const service of ['prometheus', 'telemetry-collector']) {
    const value = inspect(service);
    check(`${service} healthy`, value.State.Health?.Status === 'healthy');
    check(`${service} Admin/storage isolated`, Object.keys(value.NetworkSettings.Networks).every(network => !/admin|storage/.test(network)));
    check(`${service} no host publication`, !Object.keys(value.HostConfig.PortBindings || {}).length);
    check(`${service} cap_drop ALL`, value.HostConfig.CapDrop?.includes('ALL'));
    check(`${service} rootfs read-only`, value.HostConfig.ReadonlyRootfs);
    check(`${service} actual configureduid1000`, value.Config.User === '1000:1000');
    check(`${service} secret directory read-only`, value.Mounts.some(mount => /deploy\/private\/metrics\//.test(mount.Source) && !mount.RW));
  }
  const sourceNames = ['sanitize.mjs', 'config.mjs', 'catalog.mjs', 'counters.mjs', 'loki.mjs', 'collector.mjs', 'server.mjs'];
  const sourceCode = "const fs=require('fs'),crypto=require('crypto');const names=JSON.parse(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(names.map(name=>({name,sha256:crypto.createHash('sha256').update(fs.readFileSync('/opt/kongos-collector/'+name)).digest('hex')}))));";
  const actualSources = JSON.parse(execFileSync('docker', [...compose, 'exec', '-T', 'telemetry-collector', 'node', '-e', sourceCode], { input: JSON.stringify(sourceNames), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  for (const name of sourceNames) {
    const hostSHA256 = createHash('sha256').update(readFileSync(resolve('deploy/metrics-collector', name))).digest('hex');
    const actualSHA256 = actualSources.find(row => row.name === name)?.sha256;
    check(`collector actual source ${name} matches final owned source`, actualSHA256 === hostSHA256);
    collectorSources.push({ name, hostSHA256, actualSHA256 });
  }
  const collector = inspect('telemetry-collector');
  check('collector final source tree bound read-only', collector.Mounts.some(mount => mount.Type === 'bind' && mount.Destination === '/opt/kongos-collector' && !mount.RW));
  const collectorTelemetry = Object.entries(collector.NetworkSettings.Networks).find(([name]) => name.endsWith('_telemetry'))?.[1];
  check('collector positive identity alias is confined to telemetry', collectorTelemetry?.Aliases?.includes('metrics-collector') && Object.entries(collector.NetworkSettings.Networks).filter(([name]) => !name.endsWith('_telemetry')).every(([, network]) => !network.Aliases?.includes('metrics-collector')));
  const identityCode = "require('node:dns').promises.lookup('metrics-collector',{all:true}).then(rows=>console.log(JSON.stringify(rows))).catch(()=>process.exit(1));";
  const identityAddresses = JSON.parse(execFileSync('docker', [...compose, 'exec', '-T', 'console-api', 'node', '-e', identityCode], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  check('API positively resolves dedicated collector alias to exact configured IPv4', identityAddresses.length === 1 && identityAddresses[0].family === 4 && identityAddresses[0].address === collectorTelemetry?.IPAddress && api.Config.Env.includes(`COLLECTOR_TELEMETRY_IP=${collectorTelemetry?.IPAddress}`));
  const selfIPs = api.Config.Env.find(value => value.startsWith('COLLECTOR_SELF_IPS='))?.slice('COLLECTOR_SELF_IPS='.length).split(',') || [];
  const protectedHosts = api.Config.Env.find(value => value.startsWith('PROTECTED_DESTINATION_HOSTS='))?.slice('PROTECTED_DESTINATION_HOSTS='.length).split(',') || [];
  const collectorInterfaces = Object.entries(collector.NetworkSettings.Networks).map(([name, network]) => ({network: name, address: network.IPAddress}));
  check('actual three collector interface IPv4s equal complete managed self set', collectorInterfaces.length === 3 && selfIPs.length === 3 && new Set(selfIPs).size === 3 && collectorInterfaces.every(row => selfIPs.includes(row.address)));
  check('ordinary destination policy protects every actual collector interface', collectorInterfaces.every(row => protectedHosts.includes(row.address)));
  const nativeDNSCode = "require('node:dns').promises.lookup('telemetry-collector',{all:true}).then(rows=>console.log(JSON.stringify(rows))).catch(()=>process.exit(1));";
  const nativeAddresses = JSON.parse(execFileSync('docker', [...compose, 'exec', '-T', 'console-api', 'node', '-e', nativeDNSCode], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  check('every native collector DNS response belongs to exact managed interface set', nativeAddresses.length > 0 && nativeAddresses.every(row => row.family === 4 && selfIPs.includes(row.address)));
  const configured = JSON.parse(execFileSync('docker', [...compose, 'config', '--format', 'json'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  for (const row of collectorInterfaces) {
    const logicalName = row.network.replace(/^kongos-console_/, '');
    check(`actual collector ${logicalName} equals declared static IP`, configured.services['telemetry-collector'].networks[logicalName]?.ipv4_address === row.address);
    const actualNetwork = JSON.parse(execFileSync('docker', ['network', 'inspect', row.network], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }))[0];
    check(`actual ${logicalName} subnet equals declared source IPAM`, actualNetwork.IPAM.Config[0].Subnet === configured.networks[logicalName].ipam.config[0].subnet);
  }
  collectorIdentity = {interfaces: collectorInterfaces, nativeHostnameAnswers: nativeAddresses, telemetryAliasAnswers: identityAddresses};
  check('host private root0700', (statSync('deploy/private/metrics').mode & 0o777) === 0o700);
  const manifest = JSON.parse(readFileSync('deploy/private/metrics/manifest.json', 'utf8'));
  const rows = JSON.parse(readFileSync('deploy/private/metrics/collector/credentials.json', 'utf8')).clusters;
  check('every local enrollment ready', manifest.clusters.length > 0 && manifest.clusters.every(row => row.state === 'ready'));
  check('collector contains no raw ingest', rows.every(row => typeof row.ingestFingerprint === 'string' && !Object.hasOwn(row, 'ingestToken')));
  for (const cluster of manifest.clusters) {
    const status=JSON.parse(execFileSync('docker',[...compose,'exec','-T','console-api','node','dist/infrastructure/metrics-enroll.js'],{input:JSON.stringify({action:'status',clusterId:cluster.clusterId}),encoding:'utf8',stdio:['pipe','pipe','pipe']}));
    check(`${cluster.clusterId} preserved local generation matches fresh active DB family`,status.enrolled===true&&status.generation===cluster.generation);
    check(`${cluster.clusterId} Prom native token0400`, (statSync(resolve(`deploy/private/metrics/prometheus/${cluster.clusterId}-native_scrape.token`)).mode & 0o777) === 0o400);
    check(`${cluster.clusterId} Prom collector token0400`, (statSync(resolve(`deploy/private/metrics/prometheus/${cluster.clusterId}-collector_scrape.token`)).mode & 0o777) === 0o400);
    for (const purpose of ['native_scrape', 'collector_scrape']) {
      execFileSync('docker', [...compose, 'exec', '-T', 'prometheus', '/bin/sh', '-ec', 'test -r "$1"', 'prom-readable', `/etc/prometheus/${cluster.clusterId}-${purpose}.token`], { stdio: ['pipe', 'pipe', 'pipe'] });
      check(`${cluster.clusterId} ${purpose} readable by actual Prom UID`, true);
    }
  }
  const collectorCode = "const fs=require('fs');const x=JSON.parse(fs.readFileSync('/run/kongos-metrics/credentials.json','utf8'));console.log(JSON.stringify({readable:Array.isArray(x.clusters)&&x.clusters.length>0,uid:process.getuid()}));";
  const access = JSON.parse(execFileSync('docker', [...compose, 'exec', '-T', 'telemetry-collector', 'node', '-e', collectorCode], { encoding: 'utf8' }));
  check('collector actualuid1000 can read credential file', access.readable && access.uid === 1000);
  const promReadable = execFileSync('docker', [...compose, 'exec', '-T', 'prometheus', '/bin/promtool', 'check', 'config', '/etc/prometheus/prometheus.yml'], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' });
  check('Prometheus actual UID parses configuration and token paths', promReadable.includes('SUCCESS'));
  const publicPaths = ['/scrape', '/catalog', '/ingest', '/metrics'];
  for (const prefix of publicPaths) {
    const response = await fetch(`http://127.0.0.1:8080${prefix}/${manifest.clusters[0].clusterId}`, { method: prefix === '/ingest' ? 'POST' : 'GET', signal: AbortSignal.timeout(3000) });
    // SPA shells must never expose internal telemetry bodies or permissions.
    check(`public ${prefix} has no telemetry endpoint`, response.status === 404 || response.status === 401 || (response.headers.get('content-type') || '').includes('text/html'));
    await response.body?.cancel();
  }
} catch { check('metrics deployment verification completed', false); }
const result = { stage: evidenceStage, observedAt: new Date().toISOString(), scope: 'startup/network/UID and actual collector source SHA; does not assert traffic or metric math', allPassed: checks.length > 0 && checks.every(row => row.passed), checks, collectorSources, collectorIdentity };
mkdirSync(evidenceDirectory, { recursive: true });
writeFileSync(resolve(evidenceDirectory,'metrics-deployment-verification.json'), JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(row => row.passed).length}/${checks.length} actual metrics deployment checks passed; no secret values recorded.`);
if (!result.allPassed) process.exitCode = 1;
