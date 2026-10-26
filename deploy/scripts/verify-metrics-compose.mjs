import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
const multicluster = process.argv.includes('--multicluster');
const args = ['compose', '--env-file', '.env', ...(multicluster ? ['--env-file', '.env.multicluster'] : []), '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml', ...(multicluster ? ['-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test'] : []), '-f', 'deploy/compose/compose.metrics.yml', '--profile', 'observability'];
const checks = [];
const check = (name, passed) => checks.push({ name, passed: Boolean(passed) });
function subnetRange(value) {
  const [address, bitsText] = value.split('/');
  const bytes = address.split('.').map(Number);
  const bits = Number(bitsText);
  if (bytes.length !== 4 || bytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255) || !Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error('subnet');
  const size = 1n << BigInt(32 - bits);
  const ip = bytes.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
  const low = (ip / size) * size;
  return { low, high: low + size - 1n };
}
function ipv4Value(value) {
  const bytes = value.split('.').map(Number);
  if (bytes.length !== 4 || bytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error('address');
  return bytes.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
}
try {
  // Resolved environment includes secrets. Keep it in memory, emit booleans only.
  const config = JSON.parse(execFileSync('docker', [...args, 'config', '--format', 'json'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  const api = config.services['console-api'];
  const collector = config.services['telemetry-collector'];
  const prometheus = config.services.prometheus;
  check('telemetry network internal', config.networks.telemetry.internal);
  check('bridge binds telemetry interface only', api.environment.METRICS_BRIDGE_HOST === api.networks.telemetry.ipv4_address && api.environment.METRICS_BRIDGE_HOST !== '0.0.0.0');
  check('managed collector IP equals configured telemetry destination', api.environment.COLLECTOR_TELEMETRY_IP === collector.networks.telemetry.ipv4_address);
  const collectorNetworks = ['telemetry', 'proxy-edge', 'observability'];
  const selfIPs = api.environment.COLLECTOR_SELF_IPS?.split(',') || [];
  const protectedHosts = api.environment.PROTECTED_DESTINATION_HOSTS?.split(',') || [];
  check('managed collector self set contains exact three declared interfaces', selfIPs.length === 3 && new Set(selfIPs).size === 3 && collectorNetworks.every(name => selfIPs.includes(collector.networks[name].ipv4_address)));
  check('ordinary proxy policy protects every collector interface', selfIPs.length === 3 && selfIPs.every(ip => protectedHosts.includes(ip)));
  for (const name of collectorNetworks) {
    const subnet = config.networks[name].ipam.config[0].subnet;
    const range = subnetRange(subnet);
    const address = ipv4Value(collector.networks[name].ipv4_address);
    check(`collector ${name} interface statically within declared subnet`, address > range.low && address < range.high);
  }
  const declaredRanges = Object.entries(config.networks).flatMap(([name, network]) => (network.ipam?.config || []).filter(row => row.subnet).map(row => ({name, ...subnetRange(row.subnet)})));
  check('explicit collector subnets do not overlap other declared networks', collectorNetworks.every(name => {
    const value = declaredRanges.find(row => row.name === name);
    return value && declaredRanges.filter(row => row.name !== name).every(row => !(value.low <= row.high && row.low <= value.high));
  }));
  check('metrics-collector identity alias exists only on telemetry', collector.networks.telemetry.aliases?.includes('metrics-collector') && Object.entries(collector.networks).filter(([name]) => name !== 'telemetry').every(([, network]) => !network.aliases?.includes('metrics-collector')));
  check('metrics-bff DNS alias exists only on telemetry network', api.networks.telemetry.aliases?.includes('metrics-bff') && Object.entries(api.networks).filter(([name]) => name !== 'telemetry').every(([, network]) => !network.aliases?.includes('metrics-bff')));
  check('bridge port9092 not published', !api.ports?.length);
  for (const [name, service] of [['prometheus', prometheus], ['collector', collector]]) {
    const networks = Object.keys(service.networks);
    check(`${name} has no Admin or storage network`, networks.every(network => !/admin|storage/.test(network)));
    check(`${name} has telemetry network`, networks.includes('telemetry'));
    check(`${name} has no published port`, !service.ports?.length);
    check(`${name} drops all capabilities`, service.cap_drop?.includes('ALL'));
    check(`${name} disallows privilege gain`, service.security_opt?.includes('no-new-privileges:true'));
    check(`${name} filesystem read-only`, service.read_only);
    check(`${name} secret directory read-only`, service.volumes.some(volume => volume.type === 'bind' && /deploy\/private\/metrics\//.test(volume.source) && volume.read_only));
  }
  check('collector runs uid1000', collector.user === '1000:1000');
  check('collector tmpfs option strings retain absolute mount paths', collector.tmpfs?.length > 0 && collector.tmpfs.every(value => value.split(':')[0].startsWith('/')));
  check('prometheus runs uid1000', prometheus.user === '1000:1000');
  check('collector retains proxy-edge for native ingestion', collector.networks['proxy-edge']);
  check('Prom config directory replaces individual file mount', !prometheus.volumes.some(volume => volume.target === '/etc/prometheus/prometheus.yml'));
  check('collector has no administration/session/database credentials', Object.keys(collector.environment).every(key => !/APP_SECRET|DATABASE|JWT|ADMIN_PASSWORD|ENCRYPTION|REDIS/.test(key)));
  const subnet = config.networks.telemetry.ipam.config[0].subnet;
  const target = subnetRange(subnet);
  check('telemetry subnet does not overlap Admin or storage networks', Object.entries(config.networks).filter(([name]) => /admin|storage/.test(name)).every(([, network]) => !network.ipam?.config?.some(row => { const range = subnetRange(row.subnet); return target.low <= range.high && range.low <= target.high; })));
  check('Kong Admin remains unpublished', !config.services.kong.ports?.some(port => port.target === 8001));
} catch { check('Compose metrics configuration parses', false); }
const result = { stage: 'M5', scope: 'configuration only; no services started or credentials generated', observedAt: new Date().toISOString(), allPassed: checks.length > 0 && checks.every(row => row.passed), checks };
mkdirSync('artifacts/M5', { recursive: true });
writeFileSync('artifacts/M5/metrics-compose-verification.json', JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(row => row.passed).length}/${checks.length} metrics Compose checks passed; configuration only.`);
if (!result.allPassed) process.exitCode = 1;
