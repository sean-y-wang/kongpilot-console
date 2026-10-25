import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

// Read-only network proof. All native responses/configuration stay in memory;
// evidence contains only public identifiers, statuses, and boolean assertions.
const compose = ['compose', '--env-file', '.env', '--env-file', '.env.multicluster',
  '-f', 'docker-compose.yml', '-f', 'deploy/compose.development.yml',
  '-f', 'deploy/compose.multicluster-test.yml', '--profile', 'multicluster-test', '--profile', 'test'];
const checks = [];
const services = [];
const observations = [];
const iamActive = process.argv.includes('--iam-active');
function check(name, condition, detail) {
  checks.push({ name, passed: Boolean(condition), ...(detail === undefined ? {} : { detail }) });
}
function docker(args, input) {
  return execFileSync('docker', args, { encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 20_000, maxBuffer: 2e6 });
}
function inspect(service) {
  const id = docker([...compose, 'ps', '-q', service]).trim();
  if (!id) throw new Error('REQUIRED_SERVICE_MISSING');
  return JSON.parse(docker(['inspect', id]))[0];
}
function serverBlock(configuration, name) {
  const marker = configuration.indexOf(`server_name ${name};`);
  if (marker < 0) throw new Error('NGINX_SERVER_NOT_FOUND');
  const start = configuration.lastIndexOf('\nserver {', marker);
  const end = configuration.indexOf('\nserver {', marker);
  return configuration.slice(start, end === -1 ? undefined : end);
}
function workerStatus(service, address, headers = {}) {
  const args = ['exec', service, 'wget', '-Y', 'off', '-T', '3', '-q', '-O', '/dev/null'];
  for (const [name, value] of Object.entries(headers)) args.push('--header', `${name}: ${value}`);
  args.push(`http://${address}:8001/status`);
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 6000 });
  if (result.status === 0) return 200;
  // The fixed path has no credentials; still never copy the raw error body.
  return Number((result.stderr || '').match(/server returned error:\s*(?:HTTP\/[\d.]+\s+)?(\d{3})/)?.[1] || 0);
}
let failure;
try {
  const config = JSON.parse(docker([...compose, 'config', '--format', 'json']));
  const api = inspect('console-api');
  const web = inspect('console-web');
  check('API health after network-only activation', api.State.Health?.Status === 'healthy');
  check('Web health after upstream DNS restart', web.State.Health?.Status === 'healthy');
  check('API has no primary or secondary Kong database network', !Object.keys(api.NetworkSettings.Networks).some(n => /_kong(?:-secondary)?-storage(?:-secure)?$/.test(n)));
  check('Web is isolated on frontend network', Object.keys(web.NetworkSettings.Networks).length === 1 && Object.keys(web.NetworkSettings.Networks)[0].endsWith('_frontend'));
  check('API drops all Linux capabilities and disallows privilege elevation', api.HostConfig.CapDrop?.includes('ALL') && api.HostConfig.SecurityOpt?.includes('no-new-privileges:true'));
  const nativeCode = String.raw`let input='';for await(const chunk of process.stdin)input+=chunk;const urls=JSON.parse(input);const out=[];for(const url of urls){const root=await fetch(url+'/',{redirect:'manual',signal:AbortSignal.timeout(5000)});const info=await root.json();const status=await fetch(url+'/status',{redirect:'manual',signal:AbortSignal.timeout(5000)});await status.arrayBuffer();const plugins=await fetch(url+'/plugins/enabled',{redirect:'manual',signal:AbortSignal.timeout(5000)});const enabled=await plugins.json();out.push({url,rootStatus:root.status,statusStatus:status.status,pluginsStatus:plugins.status,version:info.version,nodeId:info.node_id,enabledPluginCount:enabled.enabled_plugins?.length});}console.log(JSON.stringify(out));`;
  const native = JSON.parse(docker([...compose, 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', nativeCode], JSON.stringify(['http://kong:8001', 'http://kong-secondary:8001'])));
  check('Both native versions are Kong 1.5.1', native.every(n => n.version === '1.5.1'));
  check('Genuine clusters have distinct node IDs', native.length === 2 && native[0].nodeId && native[1].nodeId && native[0].nodeId !== native[1].nodeId);
  check('BFF source can read root/status/enabled plugins on both nodes', native.every(n => n.rootStatus === 200 && n.statusStatus === 200 && n.pluginsStatus === 200));
  observations.push(...native);
  for (const name of ['kong', 'kong-secondary']) {
    const value = inspect(name), container = value.Id;
    const env = config.services[name].environment;
    const admin = env.KONGOS_ADMIN_BIND_IP, bff = env.KONGOS_BFF_ADMIN_IP;
    const adminNetwork = name === 'kong' ? config.networks['kong-admin'].name : config.networks['kong-secondary-admin'].name;
    const main = docker(['exec', container, 'cat', '/usr/local/kong/nginx.conf']);
    const generated = docker(['exec', container, 'cat', '/usr/local/kong/nginx-kong.conf']);
    const adminBlock = serverBlock(generated, 'kong_admin');
    const proxyBlock = serverBlock(generated, 'kong');
    const global = generated.slice(0, generated.indexOf('\nserver {'));
    const acl = docker(['exec', container, 'cat', '/usr/local/kong/kongos-admin-access.conf']);
    const format = docker(['exec', container, 'cat', '/usr/local/kong/kongos-http.conf']);
    const listen = [...adminBlock.matchAll(/\blisten\s+([^;]+);/g)].map(m => m[1].trim()).sort();
    const logDestinations = [...(main + generated).matchAll(/\berror_log\s+([^;]+);/g)].map(m => m[1].trim());
    const source = api.NetworkSettings.Networks[adminNetwork]?.IPAddress;
    const spoofHeaders = { 'X-Forwarded-For': bff, 'X-Real-IP': bff, Forwarded: `for=${bff}` };
    const loopbackStatus = workerStatus(container, '127.0.0.1');
    const managementStatus = workerStatus(container, admin);
    const spoofStatus = workerStatus(container, admin, spoofHeaders);
    check(`${name}: native PID health works with loopback Admin denied`, value.State.Health?.Status === 'healthy' && loopbackStatus === 403);
    check(`${name}: Admin has only fixed IPv4 and denied loopback listeners`, JSON.stringify(listen) === JSON.stringify([`${admin}:8001`, '127.0.0.1:8001'].sort()), listen);
    check(`${name}: ordered ACL allows exactly the deployed BFF source`, acl === `allow ${bff};\ndeny all;\n` && source === bff);
    check(`${name}: Admin/global configuration does not trust forwarded source headers`, !/\b(?:real_ip_header|set_real_ip_from|real_ip_recursive)\b/.test(adminBlock + global + main));
    check(`${name}: worker source cannot access own Admin`, managementStatus === 403, managementStatus);
    check(`${name}: spoofed forwarding headers do not bypass Admin ACL`, spoofStatus === 403, spoofStatus);
    check(`${name}: native Admin port is unpublished`, !value.NetworkSettings.Ports['8001/tcp']?.length);
    check(`${name}: Kong process has no Linux capabilities or privilege elevation`, value.Config.User === 'kong' && value.HostConfig.CapDrop?.includes('ALL') && value.HostConfig.SecurityOpt?.includes('no-new-privileges:true'));
    check(`${name}: request-context error logs have no persistent or external sink`, logDestinations.length > 0 && logDestinations.every(line => /^\/dev\/null(?:\s+\w+)?$/.test(line)), [...new Set(logDestinations)]);
    check(`${name}: Admin/proxy access logs use request-free format`, /access_log\s+\/dev\/stdout kongos_safe;/.test(adminBlock) && /access_log\s+\/dev\/stdout kongos_safe;/.test(proxyBlock) && !/\$(?:request_uri|uri|args|query_string|http_|request_body|request\b)/.test(format));
    services.push({ name, state: value.State.Status, health: value.State.Health?.Status, user: value.Config.User,
      managementAddress: admin, allowedBffAddress: bff, actualBffAddress: source, adminListeners: listen,
      loopbackStatus, managementStatus, spoofStatus, nativeRequestErrorLogsDiscarded: true,
      networks: Object.keys(value.NetworkSettings.Networks), proxyPort: value.NetworkSettings.Ports['8000/tcp']?.map(p => ({ host: p.HostIp, port: p.HostPort })) });
  }
  const primaryDatabase = inspect('kong-db');
  const secondaryDatabase = inspect('kong-secondary-db');
  const volumes = [primaryDatabase, secondaryDatabase].map(db => db.Mounts.find(m => m.Destination === '/var/lib/postgresql/data')?.Name);
  check('Kong databases use independent durable volumes', volumes.every(Boolean) && volumes[0] !== volumes[1], volumes);
  check('Kong databases use separate isolated storage networks', !Object.keys(primaryDatabase.NetworkSettings.Networks).some(n => Object.keys(secondaryDatabase.NetworkSettings.Networks).includes(n)));
  if(iamActive){
    const protectedHosts=config.services['console-api'].environment.PROTECTED_DESTINATION_HOSTS.split(',');
    for(const [name,value,network] of [['kong-db',primaryDatabase,'kong-storage'],['kong-secondary-db',secondaryDatabase,'kong-secondary-storage']]){
      const actual=value.NetworkSettings.Networks[config.networks[network].name]?.IPAddress;
      const expected=config.services[name].networks[network].ipv4_address;
      check(`${name}: actual isolated DB IP is fixed and explicitly protected`, actual===expected&&protectedHosts.includes(actual),{actual,expected});
    }
    const runtimeProtection=docker([...compose,'exec','-T','console-api','node','-e',"console.log(JSON.stringify({protectedHosts:(process.env.PROTECTED_DESTINATION_HOSTS||'').split(',')}))"]);
    check('runtime BFF loaded protected storage IPs from current deployment', protectedHosts.filter(Boolean).every(host=>JSON.parse(runtimeProtection).protectedHosts.includes(host)));
  }
  const migrationStatus = JSON.parse(docker([...compose, 'exec', '-T', 'console-api', 'node', '-e', "const{Pool}=require('pg');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});try{console.log(JSON.stringify({applied:(await p.query(\"SELECT count(*)::int AS n FROM schema_migrations WHERE name='005_m4_iam.sql'\")).rows[0].n}));}finally{await p.end();}})().catch(()=>process.exit(1));"]));
  check(iamActive ? 'Approved IAM migration005 is present' : 'Network activation did not apply unfinished IAM migration005', migrationStatus.applied === (iamActive ? 1 : 0));
  for (const path of ['/healthz', '/api/v1/health/live', '/api/v1/health/ready']) {
    const response = await fetch(`http://127.0.0.1:8080${path}`, { signal: AbortSignal.timeout(5000) });
    check(`Same-origin ${path} remains available`, response.status === 200, response.status);
  }
} catch {
  failure = 'NETWORK_VERIFICATION_EXCEPTION';
  check('Read-only network verification completed', false, failure);
}
const validationProfile = iamActive ? 'M4-approved-IAM-runtime' : 'M4-network-only-before-IAM';
const result = { observedAt: new Date().toISOString(), stage: process.env.ADMIN_NETWORK_EVIDENCE_STAGE || validationProfile, validationProfile,
  productionImageBuildPerformed: false, consoleMigrationAppliedByThisScript: false,
  nativeWritesPerformedByThisScript: false, databaseVolumesPreserved: true,
  nativeProxyErrorLogTradeoff: 'Native request-context errors are discarded; use redacted BFF errors and safe status/timing access logs. Anonymous report syslog is disabled.',
  services, observations, checks, allPassed: checks.every(c => c.passed), ...(failure ? { failure } : {}) };
const evidenceDirectory = process.env.ADMIN_NETWORK_EVIDENCE_DIRECTORY || 'artifacts/M4';
mkdirSync(evidenceDirectory, { recursive: true });
writeFileSync(`${evidenceDirectory}/admin-network-${iamActive ? 'final-' : ''}verification.json`, JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(c => c.passed).length}/${checks.length} actual Admin-network checks passed; no native response bodies or credentials recorded.`);
if (!result.allPassed) process.exitCode = 1;
