import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const output = resolve(process.env.DEPLOYMENT_EVIDENCE_OUTPUT || 'artifacts/M0/deployment-verification.json');
mkdirSync(resolve(output, '..'), { recursive: true });
const checks = [];
function check(name, predicate, detail) {
  checks.push({ name, passed: Boolean(predicate), detail });
  if (!predicate) process.exitCode = 1;
}
function inspect(service) {
  const id = execFileSync('docker', ['compose', 'ps', '-q', service], { encoding: 'utf8' }).trim();
  if (!id) throw new Error(`Service ${service} is missing`);
  const value = JSON.parse(execFileSync('docker', ['inspect', id], { encoding: 'utf8' }))[0];
  // Do not include Config.Env: it contains required private credentials.
  return {
    service,
    state: value.State.Status,
    health: value.State.Health?.Status,
    networks: Object.keys(value.NetworkSettings.Networks),
    ports: value.NetworkSettings.Ports || {},
    imageId: value.Image,
    codeBindMounts: value.Mounts.filter(mount => mount.Type === 'bind' && ['/app/apps/console-api/dist','/app/apps/console-api/dist/infrastructure/migrations','/usr/share/nginx/html'].includes(mount.Destination)).map(mount => ({ destination: mount.Destination, readOnly: !mount.RW })),
  };
}
function cannotReachFromWeb(address) {
  try {
    execFileSync('docker', ['compose', 'exec', '-T', 'console-web', 'wget', '-Y', 'off', '-T', '3', '-q', '--spider', address], { stdio: 'pipe', timeout: 6000 });
    return false;
  } catch { return true; }
}
const services = ['kong-db', 'kong', 'console-db', 'redis', 'console-api', 'console-web'].map(inspect);
for (const item of services) check(`${item.service} healthy`, item.health === 'healthy', item.health);
const kong = services.find(item => item.service === 'kong');
const web = services.find(item => item.service === 'console-web');
const api = services.find(item => item.service === 'console-api');
check('Kong Admin API is not published', !kong.ports['8001/tcp']?.length, kong.ports);
check('Web has only frontend network', web.networks.length === 1 && web.networks[0].endsWith('_frontend'), web.networks);
check('API does not join Kong storage', !api.networks.some(n => /_kong(?:-secondary)?-storage(?:-secure)?$/.test(n)), api.networks);
check('Web cannot resolve/reach Kong Admin', cannotReachFromWeb('http://kong:8001/'));
check('Web cannot resolve/reach Kong database', cannotReachFromWeb('http://kong-db:5432/'));
const upstreamId = execFileSync('docker', ['compose', 'ps', '-q', 'echo-upstream'], { encoding: 'utf8' }).trim();
if (upstreamId) {
  const upstream = inspect('echo-upstream');
  check('Test upstream joins only proxy network', upstream.networks.length === 1 && upstream.networks[0].endsWith('_proxy-edge'), upstream.networks);
  const upstreamReachability = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'echo-upstream', 'node', '-e', `
  (async()=>{
    const result={adminReachable:false,proxyReachable:false};
    try{await fetch('http://kong:8001/status',{signal:AbortSignal.timeout(2000)});result.adminReachable=true;}catch{}
    try{await fetch('http://kong:8000/',{signal:AbortSignal.timeout(2000)});result.proxyReachable=true;}catch{}
    console.log(JSON.stringify(result));
  })().catch(()=>process.exit(1));
  `], { encoding: 'utf8' }));
  check('Upstream cannot reach Kong Admin listener', !upstreamReachability.adminReachable, upstreamReachability);
  check('Upstream can reach Kong proxy listener', upstreamReachability.proxyReachable);
}
const baseUrl = process.env.CONSOLE_BASE_URL || 'http://127.0.0.1:8080';
for (const path of ['/healthz', '/api/v1/health/live', '/api/v1/health/ready']) {
  const response = await fetch(`${baseUrl}${path}`, { signal: AbortSignal.timeout(5000) });
  check(`${path} responds`, response.ok, response.status);
}
const headers = await fetch(baseUrl);
for (const header of ['content-security-policy', 'x-frame-options', 'x-content-type-options']) check(`Web sends ${header}`, Boolean(headers.headers.get(header)));
const databaseEvidence = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '-e', `
const {Pool}=require('pg');
(async()=>{
  const pool=new Pool({connectionString:process.env.DATABASE_URL});
  try{
    const role=(await pool.query("SELECT current_user AS username, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname=current_user")).rows[0];
    const permissions=(await pool.query("SELECT has_table_privilege(current_user,'audit_events','SELECT') AS audit_select,has_table_privilege(current_user,'audit_events','INSERT') AS audit_insert,has_table_privilege(current_user,'audit_events','UPDATE') AS audit_update,has_table_privilege(current_user,'audit_events','DELETE') AS audit_delete,has_table_privilege(current_user,'audit_events','TRUNCATE') AS audit_truncate,has_schema_privilege(current_user,'public','CREATE') AS schema_create")).rows[0];
    let deleteDenied=false;
    try{await pool.query('DELETE FROM audit_events WHERE false');}catch(error){deleteDenied=error.code==='42501';}
    // Swagger's production peer graph includes TypeScript; frontend/test tools should be absent.
    const unexpectedPackages=['vitest','vite','@playwright/test','react'].filter(name=>{try{require.resolve(name);return true;}catch{return false;}});
    console.log(JSON.stringify({role,permissions,deleteDenied,unexpectedPackages,bootstrapPasswordPresent:Boolean(process.env.BOOTSTRAP_ADMIN_PASSWORD),ownerPasswordPresent:Boolean(process.env.CONSOLE_DATABASE_PASSWORD),skipMigrations:process.env.SKIP_MIGRATIONS==='true'}));
  }finally{await pool.end();}
})().catch(()=>process.exit(1));
`], { encoding: 'utf8' }));
check('API database role is not a superuser', !databaseEvidence.role.rolsuper && !databaseEvidence.role.rolcreatedb && !databaseEvidence.role.rolcreaterole && !databaseEvidence.role.rolbypassrls, databaseEvidence.role);
const permissions = databaseEvidence.permissions;
check('Runtime audit grants are append/read only', permissions.audit_select && permissions.audit_insert && !permissions.audit_update && !permissions.audit_delete && !permissions.audit_truncate, permissions);
check('Runtime audit deletion is denied by PostgreSQL', databaseEvidence.deleteDenied);
check('Runtime cannot create schema objects', !permissions.schema_create);
check('Runtime has no bootstrap/owner credentials', !databaseEvidence.bootstrapPasswordPresent && !databaseEvidence.ownerPasswordPresent);
check('Runtime does not execute migrations', databaseEvidence.skipMigrations);
check('Runtime has only API production packages', databaseEvidence.unexpectedPackages.length === 0, databaseEvidence.unexpectedPackages);
const verificationMode = services.some(service => service.codeBindMounts.length) ? 'development override' : 'production images';
const result = { observedAt: new Date().toISOString(), verificationMode, services, checks, allPassed: checks.every(c => c.passed) };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(c => c.passed).length}/${checks.length} deployment checks passed; evidence ${output}`);
