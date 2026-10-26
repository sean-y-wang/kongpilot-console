import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { stagePlan } from './stage-plan.mjs';

const stage = process.argv[2];
const dryRun = process.argv.includes('--dry-run');
const verifyOnly = process.argv.includes('--verify-only');
const multicluster = process.argv.includes('--multicluster');
const observability = process.argv.includes('--observability');
const captureMetricsTokens = process.argv.includes('--capture-metrics-test-tokens');
const portal = process.argv.includes('--portal');
const portalAcceptance = process.argv.includes('--portal-acceptance');
const notificationsTest = process.argv.includes('--notifications-test');
const gitopsRunner = process.argv.includes('--gitops-runner');
const captureExistingMetrics = process.argv.includes('--capture-existing-metrics-test-reference');
const transitionStorage = process.argv.includes('--transition-kong-storage');
if (!/^M(?:[0-9]|1[01])$/.test(stage || '')) {
  console.error('Usage: node deploy/scripts/stage-deploy.mjs M0..M11 [--dry-run|--verify-only] [--multicluster] [--observability] [--portal] [--transition-kong-storage]');
  process.exit(2);
}
if (dryRun && verifyOnly) {
  console.error('Choose either --dry-run or --verify-only.');
  process.exit(2);
}
if (transitionStorage && (!multicluster || verifyOnly)) {
  console.error('Storage transition requires a full --multicluster deployment.');
  process.exit(2);
}
if (captureMetricsTokens && (!observability || stage !== 'M5' || verifyOnly)) {
  console.error('Private metric-token capture is test-only and requires a full M5 --observability deployment.');
  process.exit(2);
}
if (portal && Number(stage.slice(1)) < 6) { console.error('Portal deployment starts at M6.'); process.exit(2); }
if (portalAcceptance && (!portal || !multicluster)) {console.error('Portal acceptance preservation requires --portal --multicluster.');process.exit(2);}
if(gitopsRunner && Number(stage.slice(1))<8){console.error('Fixed GitOps runner deployment starts at M8.');process.exit(2);}
if (notificationsTest && Number(stage.slice(1)) < 7) {console.error('Delivery receiver deployment starts at M7.');process.exit(2);}
if (captureExistingMetrics && (stage !== 'M6' || !portal || !observability || verifyOnly)) { console.error('Existing key capture requires a full M6 --portal --observability test deployment.'); process.exit(2); }
const compose = ['compose', ...(multicluster ? ['--env-file', '.env', '--env-file', '.env.multicluster'] : []),...(portalAcceptance?['--env-file','.env.portal-acceptance']:[]),
  '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml',
  ...(multicluster ? ['-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test'] : []),
  ...(observability ? ['-f', 'deploy/compose/compose.metrics.yml', '--profile', 'observability'] : []),
  ...(portalAcceptance?['-f','deploy/compose/compose.portal-acceptance.yml','--profile','portal-acceptance']:[]),
  ...(notificationsTest?['-f','deploy/compose/compose.notifications-test.yml','--profile','notifications-test']:[]),
  ...(gitopsRunner?['-f','deploy/compose/compose.gitops.yml','--profile','gitops-runner']:[])];
const steps = stagePlan({stage,compose,multicluster,observability,portal,notificationsTest,gitopsRunner,captureMetricsTokens,captureExistingMetrics,transitionStorage});
if (dryRun) {
  console.log(JSON.stringify({ stage, mode: 'development-bindmounts', deploymentPerformed: false, commands: steps.map(([name, command, args]) => ({ name, command, args })), finalSteps: ['wait readiness', 'verify runtime reload', 'verify deployment boundary', 'record startup evidence'], productionImagesRebuilt: false }, null, 2));
  process.exit(0);
}

const directory = resolve('artifacts', stage);
mkdirSync(directory, { recursive: true });
const output = resolve(directory, verifyOnly ? 'startup-final-verification.json' : 'startup-verification.json');
const startedAt = new Date().toISOString();
const commands = [];
const checks = [];
const traces = [];
let currentStep = 'preflight';
function check(name, condition, detail) {
  checks.push({ name, passed: Boolean(condition), ...(detail === undefined ? {} : { detail }) });
  if (!condition) throw new Error('Stage check failed');
}
function run(name, command, args, env = process.env) {
  currentStep = name;
  const began = Date.now();
  execFileSync(command, args, { stdio: 'inherit', env });
  commands.push({ name, completed: true, durationMs: Date.now() - began });
}
function inspect(service) {
  const id = execFileSync('docker', [...compose, 'ps', '-q', service], { encoding: 'utf8' }).trim();
  if (!id) throw new Error('Required service is missing');
  const container = JSON.parse(execFileSync('docker', ['inspect', id], { encoding: 'utf8' }))[0];
  // Never include Docker Config.Env: it contains database/session credentials.
  return { service, state: container.State.Status, health: container.State.Health?.Status, startedAt: container.State.StartedAt, imageId: container.Image, codeBindings: container.Mounts.filter(m => m.Type === 'bind' && ['/app/apps/console-api/dist', '/app/apps/console-api/dist/infrastructure/migrations', '/usr/share/nginx/html'].includes(m.Destination)).map(m => ({ destination: m.Destination, readOnly: !m.RW })) };
}
function latestCompiledTime(directory) {
  let result = 0;
  for (const item of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, item.name);
    if (item.isDirectory()) result = Math.max(result, latestCompiledTime(path));
    else if (item.isFile() && /\.(?:js|json|map)$/.test(item.name)) result = Math.max(result, statSync(path).mtimeMs);
  }
  return result;
}
let result;
try {
  check('environment file exists', existsSync('.env'));
  check('development override exists', existsSync('deploy/compose/compose.development.yml'));
  if (multicluster) check('private secondary environment exists with mode0600', existsSync('.env.multicluster') && (statSync('.env.multicluster').mode & 0o777) === 0o600);
  if (!verifyOnly) for (const [name, command, args] of steps) run(name, command, args);
  currentStep = 'readiness';
  const base = (process.env.CONSOLE_BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
  const paths = ['/', '/healthz', '/api/v1/health/live', '/api/v1/health/ready'];
  const portalBase = (process.env.PORTAL_BASE_URL || 'http://127.0.0.1:8082').replace(/\/$/, '');
  const deadline = Date.now() + 55_000;
  let ready = false;
  while (Date.now() < deadline) {
    const responses = [];
    for (const path of paths) {
      try {
        const response = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(3000) });
        responses.push({ method: 'GET', path, status: response.status, requestId: response.headers.get('x-request-id') });
        await response.arrayBuffer();
      } catch { responses.push({ method: 'GET', path, status: null }); }
    }
    const runtime = ['kong', 'console-db', 'redis', 'console-api', 'console-web', ...(observability ? ['prometheus', 'telemetry-collector', 'loki'] : []), ...(portal ? ['portal-web'] : [])].map(inspect);
    if (portal) { try { const response=await fetch(`${portalBase}/healthz`,{signal:AbortSignal.timeout(3000)}); responses.push({method:'GET',origin:'portal',path:'/healthz',status:response.status});await response.body?.cancel(); } catch {responses.push({method:'GET',origin:'portal',path:'/healthz',status:null});} }
    if (responses.every(r => r.status === 200) && runtime.every(s => s.health === 'healthy')) {
      traces.push(...responses);
      ready = true;
      break;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  check('web/API/core services ready before deadline', ready);
  currentStep = 'runtime-reload';
  const runtime = ['kong', 'console-db', 'redis', 'console-api', 'console-web', ...(observability ? ['prometheus', 'telemetry-collector', 'loki'] : []), ...(portal ? ['portal-web'] : [])].map(inspect);
  const api = runtime.find(s => s.service === 'console-api');
  const web = runtime.find(s => s.service === 'console-web');
  check('runtime API process restarted after compilation', Date.parse(api.startedAt) >= latestCompiledTime(resolve('apps/console-api/dist')));
  check('development API code bound read-only', api.codeBindings.some(m => m.destination === '/app/apps/console-api/dist' && m.readOnly));
  const webId = execFileSync('docker', [...compose, 'ps', '-q', 'console-web'], { encoding: 'utf8' }).trim();
  const webMounts = JSON.parse(execFileSync('docker', ['inspect', '--format', '{{json .Mounts}}', webId], { encoding: 'utf8' }));
  check('development nginx configuration bound read-only', webMounts.some(m => m.Type === 'bind' && m.Destination === '/etc/nginx/conf.d/default.conf' && !m.RW));
  check('development frontend assets bound read-only', web.codeBindings.some(m => m.destination === '/usr/share/nginx/html' && m.readOnly));
  currentStep = 'frontend-assets';
  const indexResponse = await fetch(`${base}/`, { signal: AbortSignal.timeout(5000) });
  const indexBytes = Buffer.from(await indexResponse.arrayBuffer());
  const indexSha = createHash('sha256').update(indexBytes).digest('hex');
  check('served frontend index matches current compiled file', indexResponse.status === 200 && indexSha === createHash('sha256').update(readFileSync(resolve('apps/console-web/dist/index.html'))).digest('hex'));
  const assetPaths = [...new Set([...indexBytes.toString('utf8').matchAll(/(?:src|href)="(\/assets\/[A-Za-z0-9_-]+\.(?:js|css))"/g)].map(match => match[1]))];
  check('frontend index declares compiled assets', assetPaths.length > 0);
  const frontend = { indexSHA256: indexSha, assets: [] };
  for (const path of assetPaths) {
    const response = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(5000) });
    const bytes = Buffer.from(await response.arrayBuffer());
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    check(`served frontend asset matches current file ${path}`, response.status === 200 && sha256 === createHash('sha256').update(readFileSync(resolve('apps/console-web/dist', path.slice(1)))).digest('hex'));
    frontend.assets.push({ path, sha256, bytes: bytes.length });
  }
  currentStep = 'swagger';
  const documentResponse = await fetch(`${base}/api/docs-json`, { signal: AbortSignal.timeout(5000) });
  check('Swagger document responds', documentResponse.status === 200);
  const document = await documentResponse.json();
  const swagger = { pathCount: Object.keys(document.paths || {}).length, schemas: Object.keys(document.components?.schemas || {}) };
  check('Swagger contains runtime paths', swagger.pathCount > 0, swagger.pathCount);
  currentStep = 'migration-verification';
  const migrations = execFileSync('docker', [...compose, 'exec', '-T', 'console-api', 'node', '-e', "const {Pool}=require('pg');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});try{console.log(JSON.stringify((await p.query('SELECT name FROM schema_migrations ORDER BY name')).rows.map(r=>r.name)));}finally{await p.end();}})().catch(()=>process.exit(1));"], { encoding: 'utf8' });
  const applied = JSON.parse(migrations.trim());
  const expected = readdirSync(resolve('apps/console-api/src/infrastructure/migrations')).filter(name => name.endsWith('.sql')).sort();
  check('all repository console migrations applied', expected.every(name => applied.includes(name)), applied);
  run('deployment-boundary', 'node', ['deploy/scripts/verify-deployment.mjs'], { ...process.env, DEPLOYMENT_EVIDENCE_OUTPUT: resolve(directory, verifyOnly ? 'deployment-boundary-final.json' : 'deployment-boundary.json') });
  if (multicluster) run('dual-cluster-admin-boundary', 'node', ['deploy/scripts/verify-admin-network.mjs', '--iam-active'], { ...process.env, ADMIN_NETWORK_EVIDENCE_DIRECTORY: directory, ADMIN_NETWORK_EVIDENCE_STAGE: stage });
  if (observability) run('metrics-network-boundary', 'node', ['deploy/scripts/verify-metrics-deployment.mjs', ...(multicluster ? ['--multicluster'] : [])], {...process.env,METRICS_EVIDENCE_STAGE:stage,METRICS_EVIDENCE_DIRECTORY:directory});
  if (portal) run('portal-network-boundary','node',['deploy/scripts/verify-portal-deployment.mjs',...(multicluster?['--multicluster']:[]),...(observability?['--observability']:[])], {...process.env,PORTAL_EVIDENCE_STAGE:stage,PORTAL_EVIDENCE_DIRECTORY:directory});
  if (notificationsTest) run('delivery-network-boundary','node',['deploy/scripts/verify-event-delivery-deployment.mjs',...(portalAcceptance?['--portal-acceptance']:[])], {...process.env,DELIVERY_EVIDENCE_STAGE:stage,DELIVERY_EVIDENCE_DIRECTORY:directory});
  result = { stage, mode: 'development-bindmounts', deploymentPerformed: !verifyOnly, productionImagesRebuilt: false, startedAt, completedAt: new Date().toISOString(), allPassed: true, commands, traces, checks, runtime, frontend, swagger, compiledApiMainSHA256: createHash('sha256').update(readFileSync(resolve('apps/console-api/dist/main.js'))).digest('hex') };
} catch {
  result = { stage, mode: 'development-bindmounts', deploymentPerformed: !verifyOnly, productionImagesRebuilt: false, startedAt, completedAt: new Date().toISOString(), allPassed: false, failedStep: currentStep, commands, traces, checks };
  process.exitCode = 1;
  console.error(`Stage deployment failed during ${currentStep}; no response bodies or credentials were recorded.`);
} finally {
  writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
}
if (result.allPassed) console.log(`${stage} startup verification passed (${verifyOnly ? 'verification only' : 'compiled, migrated and restarted'}); evidence ${output}`);
