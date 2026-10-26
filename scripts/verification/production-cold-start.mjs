#!/usr/bin/env node
/**
 * M11: host-network production-shaped cold start (compose.production.yml spirit).
 * Box reality: Docker bridge DNS → 198.18.0.0/15 + inter-container TCP blackhole →
 * full bridge compose.production.yml is not viable; this evidence uses host networking
 * + non-hijacked loopback service endpoints. commercialClosed stays false.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync, spawnSync } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { parseDocument } from 'yaml';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ts = process.env.PCE_TS || new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
const outDir = resolve(process.env.PCE_OUT || join(repo, `artifacts/M11/runs/${ts}-production-compose`));
const project = process.env.PCE_PROJECT || 'kongos-pce';
const apiImage = process.env.KONGOS_API_IMAGE || 'kongpilot/console-api:m11-prod-compose';
const composeFile = join(repo, 'deploy/compose/compose.production-hostnetwork-evidence.yml');
const envFile = join(outDir, 'production-compose.env');
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });

function sh(cmd, opts = {}) {
  return execSync(cmd, { encoding: 'utf8', cwd: repo, ...opts });
}
function shOk(cmd, opts = {}) {
  try { return { ok: true, out: sh(cmd, opts) }; }
  catch (e) { return { ok: false, out: String(e.stdout || '') + String(e.stderr || e.message) }; }
}

mkdirSync(outDir, { recursive: true });

// --- DNS / bridge honesty ---
let dnsHijack = false;
let dnsAddrs = [];
try {
  dnsAddrs = await lookup('example.com', { all: true });
  dnsHijack = dnsAddrs.some((a) => /^198\.18\./.test(String(a.address)));
} catch (e) {
  record('dns_lookup_example_com', false, { error: e.message });
}
record('runner_dns_hijack_19818', dnsHijack, {
  addrs: dnsAddrs.map((a) => a.address),
  note: dnsHijack
    ? 'host/example.com resolves into 198.18.0.0/15 — bridge compose.production.yml not claimed; host-network evidence'
    : 'dns looks normal',
});

// Bridge TCP probe (optional existing network)
const bridgeProbe = shOk(`docker network ls --format '{{.Name}}' | head -5`);
record('docker_networks_listed', bridgeProbe.ok, { sample: bridgeProbe.out.trim().split('\n').slice(0, 5) });

// --- Static overlay contract ---
const base = parseDocument(readFileSync(join(repo, 'docker-compose.yml'), 'utf8'), {
  customTags: [{ tag: '!override', collection: 'seq', resolve: (v) => v }],
}).toJS();
const production = parseDocument(readFileSync(join(repo, 'deploy/compose/compose.production.yml'), 'utf8'), {
  customTags: [{ tag: '!override', collection: 'seq', resolve: (v) => v }],
}).toJS();
record('compose_production_overlay_present', !!production.services?.['console-api']?.read_only, {
  overlayServices: Object.keys(production.services || {}),
  baseApiSchedulesDefault: base.services?.['console-api']?.environment?.BUSINESS_SCHEDULES_ENABLED,
});
const prodEnvExample = readFileSync(join(repo, 'deploy/production.env.example'), 'utf8');
record('production_env_example_schedules_default_false',
  /ENTITY_SCHEDULES_ENABLED=false/.test(prodEnvExample) && /BUSINESS_SCHEDULES_ENABLED=false/.test(prodEnvExample));

// --- Bake / image identity ---
let imageId = null;
try {
  const insp = JSON.parse(sh(`docker image inspect ${apiImage}`));
  imageId = insp[0]?.Id;
  record('api_image_present', !!imageId, {
    image: apiImage,
    imageId,
    created: insp[0]?.Created,
    user: insp[0]?.Config?.User,
    bakeNote: 'local commit of built dist (schedule ready probe) onto prior evidence base; not GitHub immutable-images SBOM',
  });
} catch (e) {
  record('api_image_present', false, { image: apiImage, error: e.message });
}

// --- Generate env (never print secrets) ---
const hex = (n) => randomBytes(n).toString('hex');
const lines = {
  KONG_DATABASE_PASSWORD: hex(24),
  CONSOLE_DATABASE_PASSWORD: hex(24),
  CONSOLE_APP_PASSWORD: hex(24),
  REDIS_PASSWORD: hex(24),
  BOOTSTRAP_ADMIN_USERNAME: 'admin',
  BOOTSTRAP_ADMIN_PASSWORD: `KongPilot!9${randomBytes(24).toString('base64url')}`,
  CONSOLE_ENCRYPTION_KEY: hex(32),
  APP_SECRET: hex(32),
  PORTAL_SECRET: hex(32),
  PUBLIC_ORIGINS: 'https://127.0.0.1:48443',
  PORTAL_PUBLIC_ORIGINS: 'https://127.0.0.1:49443',
  ENTITY_SCHEDULES_ENABLED: 'false',
  BUSINESS_SCHEDULES_ENABLED: 'false',
  KONGOS_API_IMAGE: apiImage,
  COMPOSE_PROFILES: 'production-compose-evidence',
};
writeFileSync(envFile, Object.entries(lines).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
chmodSync(envFile, 0o600);
// Redacted copy for evidence
writeFileSync(join(outDir, 'production-compose.env.redacted'), Object.keys(lines).map((k) =>
  /PASSWORD|SECRET|KEY|IMAGE/.test(k) && k !== 'KONGOS_API_IMAGE' ? `${k}=<redacted>` : `${k}=${lines[k]}`
).join('\n') + '\n');
record('env_generated', true, { envFile: 'production-compose.env', schedulesDefault: false });

const compose = `docker --host=unix:///var/run/docker.sock compose --project-name ${project} --env-file ${envFile} -f ${composeFile}`;

// Tear any prior project remnants
shOk(`${compose} --profile production-compose-evidence down -v --remove-orphans`, { stdio: 'pipe' });

// Cold start
const up = shOk(`${compose} --profile production-compose-evidence up -d --pull missing pce-console-db pce-redis pce-kong-db pce-upstream`, { timeout: 120000 });
record('infra_up', up.ok, { snippet: up.out.slice(-500) });
if (!up.ok) {
  finish(false);
  process.exit(1);
}

// Wait for DBs
function sleep(ms) { spawnSync('sleep', [String(Math.max(1, Math.ceil(ms / 1000)))], { stdio: 'ignore' }); }
let dbReady = false, redisReady = false, kongDbReady = false;
for (let i = 0; i < 60; i++) {
  const ps = shOk(`${compose} ps --format json`, { timeout: 15000 });
  writeFileSync(join(outDir, 'compose-ps-infra.json'), ps.out || '[]');
  dbReady = shOk(`${compose} exec -T pce-console-db pg_isready -h 127.0.0.1 -p 45433 -U kongos -d kongos`, { timeout: 10000 }).ok;
  redisReady = shOk(`${compose} exec -T pce-redis sh -ec 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli -h 127.0.0.1 -p 46379 ping | grep -q PONG'`, { timeout: 10000 }).ok;
  kongDbReady = shOk(`${compose} exec -T pce-kong-db pg_isready -h 127.0.0.1 -p 45432 -U kong -d kong`, { timeout: 10000 }).ok;
  if (dbReady && redisReady && kongDbReady) break;
  sleep(2000);
}
record('console_db_ready', dbReady, { port: 45433 });
record('redis_ready', redisReady, { port: 46379 });
record('kong_db_ready', kongDbReady, { port: 45432 });

const migKong = shOk(`${compose} --profile production-compose-evidence up --no-deps pce-kong-migrations`, { timeout: 180000 });
record('kong_migrations', migKong.ok || /Database is already bootstrapped|already/i.test(migKong.out), { snippet: migKong.out.slice(-400) });

const kongUp = shOk(`${compose} --profile production-compose-evidence up -d --no-deps pce-kong`, { timeout: 120000 });
record('kong_up', kongUp.ok, { snippet: kongUp.out.slice(-300) });

let kongHealthy = false;
for (let i = 0; i < 40; i++) {
  const h = shOk(`curl -sf http://127.0.0.1:48001/status`, { timeout: 5000 });
  if (h.ok) { kongHealthy = true; break; }
  sleep(2000);
}
record('kong_admin_status', kongHealthy, { url: 'http://127.0.0.1:48001/status' });

const migApi = shOk(`${compose} --profile production-compose-evidence up --no-deps pce-console-migrations`, { timeout: 300000 });
record('console_migrations', migApi.ok, { snippet: migApi.out.slice(-600) });

const apiUp = shOk(`${compose} --profile production-compose-evidence up -d --no-deps pce-console-api`, { timeout: 120000 });
record('console_api_up', apiUp.ok, { snippet: apiUp.out.slice(-300) });

let readyBody = null, readyStatus = 0;
for (let i = 0; i < 50; i++) {
  try {
    const r = await fetch('http://127.0.0.1:43001/api/v1/health/ready', { signal: AbortSignal.timeout(5000) });
    readyStatus = r.status;
    readyBody = await r.text();
    if (r.status === 200) break;
  } catch { /* */ }
  sleep(2000);
}
let readyJson = null;
try { readyJson = JSON.parse(readyBody || ''); } catch { /* */ }
writeFileSync(join(outDir, 'health-ready.json'), JSON.stringify({ status: readyStatus, body: readyJson || readyBody }, null, 2) + '\n');
record('api_health_ready', readyStatus === 200 && readyJson?.status === 'ready', {
  status: readyStatus,
  schedules: readyJson?.schedules,
});
record('schedules_default_off_in_ready',
  readyJson?.schedules?.business?.enabled === false
  && readyJson?.schedules?.business?.timerRunning === false
  && readyJson?.schedules?.entity?.enabled === false, {
  schedules: readyJson?.schedules,
});

const live = await fetch('http://127.0.0.1:43001/api/v1/health/live', { signal: AbortSignal.timeout(5000) })
  .then(async (r) => ({ status: r.status, text: await r.text() }))
  .catch((e) => ({ status: 0, error: e.message }));
record('api_health_live', live.status === 200, live);

// Inspect hardening on API container
const apiName = `${project}-pce-console-api-1`;
try {
  const insp = JSON.parse(sh(`docker inspect ${apiName}`))[0];
  const hc = insp.HostConfig || {};
  record('api_host_network', insp.HostConfig?.NetworkMode === 'host');
  record('api_read_only_rootfs', hc.ReadonlyRootfs === true);
  record('api_cap_drop_all', Array.isArray(hc.CapDrop) && hc.CapDrop.map(String).includes('ALL'));
  record('api_no_new_privileges', (hc.SecurityOpt || []).some((x) => String(x).includes('no-new-privileges')));
  record('api_nonroot_user', insp.Config?.User === '1000:1000' || insp.Config?.User === '1000', { user: insp.Config?.User });
} catch (e) {
  record('api_inspect', false, { error: e.message, apiName });
}

const psFinal = shOk(`${compose} ps -a`, { timeout: 30000 });
writeFileSync(join(outDir, 'compose-ps-final.txt'), psFinal.out || '');
record('compose_ps_captured', psFinal.ok);

const healthy = checks.filter((c) => [
  'infra_up', 'console_db_ready', 'redis_ready', 'kong_admin_status',
  'console_migrations', 'console_api_up', 'api_health_ready', 'schedules_default_off_in_ready',
].includes(c.id)).every((c) => c.passed);

finish(healthy);
process.exit(healthy ? 0 : 1);

function finish(healthy) {
  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.filter((c) => !c.passed && !c.skipped).length;
  const skipped = checks.filter((c) => c.skipped).length;
  const evidence = {
    schemaVersion: 1,
    kind: 'm11-production-compose-hostnetwork-cold-start-evidence',
    commercialClosed: false,
    claimsClosed: false,
    fullBridgeComposeProductionVerified: false,
    hostNetworkProductionShapedVerified: !!healthy,
    networkMode: 'host',
    dnsHijack19818: dnsHijack,
    apiImage,
    apiImageId: imageId,
    project,
    ports: {
      consoleApi: 43001,
      consoleDb: 45433,
      redis: 46379,
      kongDb: 45432,
      kongProxy: 48000,
      kongAdmin: 48001,
      upstream: 45678,
    },
    schedulesDefault: { ENTITY_SCHEDULES_ENABLED: false, BUSINESS_SCHEDULES_ENABLED: false },
    workerReadinessProbe: 'health/ready.includes.schedules + fail-closed when business enabled without timer',
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'timestamps UTC; report Asia/Shanghai',
    headSha: shOk('git rev-parse HEAD').out.trim(),
    totals: { total: checks.length, passed, failed, skipped },
    remainingForClosure: [
      'Full compose.production.yml on non-hijacked Docker DNS/bridge with inter-container TCP',
      'GitHub-hosted immutable-images SBOM bake for this revision',
      'Public CA TLS + browser UI matrix (left to operator)',
      'Portal independent TLS edge under host-network evidence',
    ],
    secretsPrinted: false,
    checks,
  };
  writeFileSync(join(outDir, 'production-compose-cold-start-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
  // Persist admin password path note only in private env file (mode 0600); summary omits it
  writeFileSync(join(outDir, 'SUMMARY.json'), JSON.stringify({
    written: join(outDir, 'production-compose-cold-start-evidence.json'),
    commercialClosed: false,
    hostNetworkProductionShapedVerified: !!healthy,
    readyStatus,
    schedules: readyJson?.schedules ?? null,
    passed, failed, skipped, total: checks.length,
    envFilePrivate: 'production-compose.env',
    baseUrl: 'http://127.0.0.1:43001',
  }, null, 2) + '\n');
  console.log(JSON.stringify({
    outDir, healthy, commercialClosed: false, passed, failed, skipped,
    readyStatus, schedules: readyJson?.schedules ?? null,
  }, null, 2));
}
