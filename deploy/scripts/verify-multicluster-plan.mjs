import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const stage = process.argv[2] || 'planning';
if (!/^(?:planning|M(?:[0-9]|1[01]))$/.test(stage)) throw new Error('Invalid evidence stage');

function ipv4CidrRange(cidr) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr || '');
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const bits = Number(match[5]);
  if (octets.some(octet => octet > 255) || bits > 32) return null;
  const address = octets.reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
  const size = 1n << BigInt(32 - bits);
  const start = (address / size) * size;
  return { start, end: start + size - 1n };
}

function disjointIpv4Cidrs(cidrs) {
  const ranges = cidrs.map(ipv4CidrRange);
  if (ranges.some(range => range === null)) return false;
  return ranges.every((range, index) => ranges.slice(index + 1).every(other => range.end < other.start || other.end < range.start));
}

// Read-only Compose resolution. Does not start a service or print resolved secrets.
const temporary = mkdtempSync(join(tmpdir(), 'kongos-multicluster-plan-'));
const credentialFile = join(temporary, 'secondary.env');
writeFileSync(credentialFile, `KONG_SECONDARY_DATABASE_PASSWORD=${randomBytes(24).toString('hex')}\n`, { mode: 0o600 });
try {
  const args = ['compose', '--env-file', '.env', '--env-file', credentialFile, '-f', 'docker-compose.yml', '-f', 'deploy/compose.multicluster-test.yml', '--profile', 'multicluster-test', 'config', '--format', 'json'];
  const compose = JSON.parse(execFileSync('docker', args, { encoding: 'utf8', maxBuffer: 5e6 }));
  const s = compose.services;
  const hasNetwork = (service, network) => Object.hasOwn(service.networks || {}, network);
  const checks = [
    ['second gateway pinned to 1.5.1', s['kong-secondary'].image === 'kong:1.5.1'],
    ['second dedicated PostgreSQL11 container', s['kong-secondary-db'].image === 'postgres:11-alpine'],
    ['independent database and user', s['kong-secondary'].environment.KONG_PG_DATABASE === 'kong_secondary' && s['kong-secondary'].environment.KONG_PG_USER === 'kong_secondary'],
    ['independent database host', s['kong-secondary'].environment.KONG_PG_HOST === 'kong-secondary-db'],
    ['independent secret', s['kong-secondary-db'].environment.POSTGRES_PASSWORD !== s['kong-db'].environment.POSTGRES_PASSWORD],
    ['independent persistent volume', s['kong-secondary-db'].volumes[0].source === 'kong_secondary_db_data' && s['kong-db'].volumes[0].source === 'kong_db_data'],
    ['secondary Admin port not host published', !s['kong-secondary'].ports.some(p => Number(p.target) === 8001)],
    ['only loopback proxy publication', s['kong-secondary'].ports.every(p => p.host_ip === '127.0.0.1' && Number(p.target) === 8000)],
    ['secondary database network isolated', Object.keys(s['kong-secondary-db'].networks).join(',') === 'kong-secondary-storage' && compose.networks['kong-secondary-storage'].internal],
    ['secondary Admin network isolated', compose.networks['kong-secondary-admin'].internal && Object.entries(s).filter(([, v]) => hasNetwork(v, 'kong-secondary-admin')).map(([k]) => k).sort().join(',') === 'console-api,kong-secondary'],
    ['frontend no secondary Admin or DB network', !hasNetwork(s['console-web'], 'kong-secondary-admin') && !hasNetwork(s['console-web'], 'kong-secondary-storage')],
    ['API has no secondary DB network', !hasNetwork(s['console-api'], 'kong-secondary-storage')],
    ['API retains existing four networks', ['frontend', 'kong-admin', 'console-storage', 'observability'].every(n => hasNetwork(s['console-api'], n))],
    ['API exact secondary host allowlist', s['console-api'].environment.OUTBOUND_ALLOWED_HOSTS.split(',').includes('kong-secondary')],
    ['all secondary services explicitly profile gated', ['kong-secondary', 'kong-secondary-db', 'kong-secondary-migrations'].every(n => s[n].profiles.includes('multicluster-test'))],
    ['primary configuration/database unchanged', s.kong.environment.KONG_PG_HOST === 'kong-db' && s.kong.environment.KONG_PG_DATABASE === 'kong' && s.kong.image === 'kong:1.5.1'],
    ['primary Admin IP is fixed in its network', s.kong.networks['kong-admin'].ipv4_address === s.kong.environment.KONGOS_ADMIN_BIND_IP],
    ['primary BFF exact source matches fixed network IP', s['console-api'].networks['kong-admin'].ipv4_address === s.kong.environment.KONGOS_BFF_ADMIN_IP],
    ['secondary Admin IP is fixed in its network', s['kong-secondary'].networks['kong-secondary-admin'].ipv4_address === s['kong-secondary'].environment.KONGOS_ADMIN_BIND_IP],
    ['secondary BFF exact source matches fixed network IP', s['console-api'].networks['kong-secondary-admin'].ipv4_address === s['kong-secondary'].environment.KONGOS_BFF_ADMIN_IP],
    ['both gateways have distinct BFF/Admin addresses', ['kong','kong-secondary'].every(name=>s[name].environment.KONGOS_ADMIN_BIND_IP!==s[name].environment.KONGOS_BFF_ADMIN_IP)],
    ['neither BFF source permits loopback or wildcard', ['kong','kong-secondary'].every(name=>!/^127\.|^0\.0\.0\.0$/.test(s[name].environment.KONGOS_BFF_ADMIN_IP))],
    ['both gateways use shared read-only secure startup', ['kong','kong-secondary'].every(name=>s[name].volumes.some(v=>v.target==='/opt/kongos/kong-secure-start.sh'&&v.read_only))],
    ['both gateway workers have no Linux capabilities', ['kong','kong-secondary'].every(name=>s[name].cap_drop?.includes('ALL'))],
    ['gateway privilege escalation is disabled', ['kong','kong-secondary'].every(name=>s[name].security_opt?.includes('no-new-privileges:true'))],
    ['BFF Linux capabilities are dropped', s['console-api'].cap_drop?.includes('ALL')],
    ['primary DB fixed IP is protected without joining its storage network', s['console-api'].environment.PROTECTED_DESTINATION_HOSTS.split(',').includes(s['kong-db'].networks['kong-storage'].ipv4_address) && !hasNetwork(s['console-api'],'kong-storage')],
    ['secondary DB fixed IP is protected without joining its storage network', s['console-api'].environment.PROTECTED_DESTINATION_HOSTS.split(',').includes(s['kong-secondary-db'].networks['kong-secondary-storage'].ipv4_address) && !hasNetwork(s['console-api'],'kong-secondary-storage')],
    ['Admin and storage IPv4 subnets have no overlapping address ranges', disjointIpv4Cidrs(['kong-admin','kong-secondary-admin','kong-storage','kong-secondary-storage'].map(n=>compose.networks[n].ipam.config[0].subnet))],
    ['destination protection uses exact hosts rather than private subnet wildcard', !s['console-api'].environment.PROTECTED_DESTINATION_HOSTS.split(',').some(host=>host.includes('/'))],
    ['provider secrets configure only server runtime, never Web or migration job', Object.hasOwn(s['console-api'].environment,'AUTH_PROVIDERS_JSON') && !Object.hasOwn(s['console-web'].environment??{},'AUTH_PROVIDERS_JSON') && !Object.hasOwn(s['console-migrations'].environment??{},'AUTH_PROVIDERS_JSON')],
  ].map(([name, passed]) => ({ name, passed: Boolean(passed) }));
  mkdirSync(`artifacts/${stage}`, { recursive: true });
  writeFileSync(`artifacts/${stage}/multicluster-compose.json`, JSON.stringify({ checkedAt: new Date().toISOString(), validation: 'compose-config-only', servicesStartedByThisCheck: false, allPassed:checks.every(c=>c.passed), checks }, null, 2) + '\n');
  const count = checks.filter(c => c.passed).length;
  console.log(`Secondary Compose plan: ${count}/${checks.length} passed. No services started.`);
  if (count !== checks.length) process.exitCode = 1;
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
