#!/usr/bin/env node
/**
 * Bounded write-load + Kong/Redis failure-injection against a production-shaped stack (host-network evidence compose by default, or the bridge production compose via COMPOSE_FILES).
 * Expect fail-closed on Kong admin / Redis loss. Never sets commercialClosed.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync, spawnSync } from 'node:child_process';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const outDir = resolve(process.env.PCE_OUT || process.argv[2] || '');
const envFile = process.env.FAULT_ENV_FILE || join(outDir, 'production-compose.env');
if (!outDir || !existsSync(envFile)) {
  console.error('PCE_OUT must point at production-compose evidence dir with production-compose.env');
  process.exit(2);
}
const envMap = Object.fromEntries(readFileSync(envFile, 'utf8').split('\n').filter(Boolean).map((l) => {
  const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)];
}));
const base = process.env.BFF_BASE || 'http://127.0.0.1:43001';
const project = process.env.PCE_PROJECT || 'kongos-pce';
// Default: host-network evidence compose. Bridge production compose: COMPOSE_FILES=docker-compose.yml,deploy/compose/compose.production.yml
const composeFiles = (process.env.COMPOSE_FILES || 'deploy/compose/compose.production-hostnetwork-evidence.yml').split(',').map((f) => join(repo, f.trim()));
const compose = `docker --host=unix:///var/run/docker.sock compose --project-name ${project} --env-file ${envFile} ${composeFiles.map((f) => `-f ${f}`).join(' ')}`;
const redisService = process.env.REDIS_SERVICE || 'pce-redis', kongService = process.env.KONG_SERVICE || 'pce-kong';
const outName = process.env.FAULT_OUT_NAME || 'write-fault-smoke-evidence.json';
const adminUser = envMap.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = envMap.BOOTSTRAP_ADMIN_PASSWORD;
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
const sleep = (ms) => spawnSync('sleep', [String(Math.max(1, Math.ceil(ms / 1000)))], { stdio: 'ignore' });
const shOk = (cmd, opts = {}) => {
  try { return { ok: true, out: execSync(cmd, { encoding: 'utf8', cwd: repo, ...opts }) }; }
  catch (e) { return { ok: false, out: String(e.stdout || '') + String(e.stderr || e.message) }; }
};

let writeResults = [];
let writeOk = 0, writeRejected = 0, writeUnexpected = 0;
let clusterId = null;

function mergeCookie(prev, set) {
  const jar = new Map();
  for (const p of (prev || '').split(';').map((s) => s.trim()).filter(Boolean)) {
    const i = p.indexOf('='); if (i > 0) jar.set(p.slice(0, i), p.slice(i + 1));
  }
  for (const c of set || []) {
    const p = c.split(';')[0]; const i = p.indexOf('='); if (i > 0) jar.set(p.slice(0, i), p.slice(i + 1));
  }
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function login() {
  const res = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: base, Accept: 'application/json' },
    body: JSON.stringify({ username: adminUser, password: adminPass }),
    redirect: 'manual',
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let payload = null; try { payload = JSON.parse(text); } catch { /* */ }
  const cookie = mergeCookie('', res.headers.getSetCookie?.() || []);
  const csrf = payload?.data?.csrfToken || payload?.csrfToken || '';
  return { ok: res.status === 200 || res.status === 201, status: res.status, cookie, csrf, bodySha16: createHash('sha256').update(text).digest('hex').slice(0, 16) };
}

async function api(session, method, path, body, { idempotency } = {}) {
  const start = Date.now();
  try {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: {
        Accept: 'application/json',
        Cookie: session.cookie,
        Origin: base,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(session.csrf ? { 'X-CSRF-Token': session.csrf } : {}),
        ...(idempotency ? { 'X-Idempotency-Key': idempotency } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(30000),
    });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch { /* */ }
    const set = res.headers.getSetCookie?.() || [];
    if (set.length) session.cookie = mergeCookie(session.cookie, set);
    if (json?.data?.csrfToken) session.csrf = json.data.csrfToken;
    return { status: res.status, elapsedMs: Date.now() - start, json, text: text.slice(0, 400), code: json?.error?.code || json?.code };
  } catch (e) {
    return { status: 0, elapsedMs: Date.now() - start, error: e.message };
  }
}

mkdirSync(outDir, { recursive: true });

const live = await fetch(`${base}/api/v1/health/live`, { signal: AbortSignal.timeout(10000) })
  .then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, error: e.message }));
record('precondition_live', live.status === 200, live);

const loginRes = await login();
record('login', loginRes.ok, { status: loginRes.status, bodySha16: loginRes.bodySha16 });
if (!loginRes.ok) { finish(); process.exit(1); }
const session = { cookie: loginRes.cookie, csrf: loginRes.csrf };

const listed = await api(session, 'GET', '/api/v1/clusters');
const clusters = Array.isArray(listed.json?.data) ? listed.json.data : listed.json?.data?.items || [];
clusterId = clusters[0]?.id || null;
record('bootstrap_cluster_present', !!clusterId, { clusterId, count: clusters.length, name: clusters[0]?.name });
if (!clusterId) { finish(); process.exit(1); }

const suffix = randomBytes(4).toString('hex');
for (let i = 0; i < 20; i++) {
  const username = `pce-c-${suffix}-${i}`;
  const r = await api(session, 'POST', `/api/v1/clusters/${clusterId}/entities/consumers`, {
    username,
    custom_id: `pce-${suffix}-${i}`,
  }, { idempotency: `pce-consumer-${suffix}-${i}` });
  writeResults.push({ i, op: 'POST consumers', status: r.status, code: r.code, elapsedMs: r.elapsedMs });
}
writeOk = writeResults.filter((r) => [200, 201].includes(r.status)).length;
writeRejected = writeResults.filter((r) => r.status >= 400 && r.status < 500).length;
writeUnexpected = writeResults.filter((r) => r.status === 0 || r.status >= 500).length;
record('bounded_write_load', writeOk >= 15 && writeUnexpected === 0, {
  total: writeResults.length, writeOk, writeRejected, writeUnexpected,
  sample: writeResults.slice(0, 5),
  note: '20 POST consumers on bootstrap cluster; expect mostly 201',
});

// Concurrent writes on one cluster: a 409 RESOURCE_LOCKED must say it is a cluster-level lock.
const lockProbe = await Promise.all(Array.from({ length: 6 }, (_, i) => api(session, 'POST', `/api/v1/clusters/${clusterId}/entities/consumers`, {
  username: `pce-lock-${suffix}-${i}`, custom_id: `pce-lock-${suffix}-${i}`,
}, { idempotency: `pce-lock-${suffix}-${i}` })));
const locked = lockProbe.filter((r) => r.status === 409 && r.code === 'RESOURCE_LOCKED');
const lockBody = locked[0]?.json?.error || locked[0]?.json || null;
record('resource_locked_message_cluster_scope', locked.length === 0 || locked.every((r) => /集群级写锁/.test(r.text) && !/同一对象/.test(r.text)), {
  statuses: lockProbe.map((r) => r.status), lockedCount: locked.length, lockScope: lockBody?.lockScope, message: lockBody?.message,
  note: locked.length ? undefined : 'no contention observed in this probe (vacuous)',
});

const readyBefore = await api(session, 'GET', '/api/v1/health/ready');
record('ready_before_fault', readyBefore.status === 200, { status: readyBefore.status, schedules: readyBefore.json?.data?.schedules || readyBefore.json?.schedules });

// Redis stop (harder than pause — freeze can leave idle clients ambiguous)
const redisStop = shOk(`${compose} stop ${redisService}`, { timeout: 60000 });
record('redis_stop', redisStop.ok, { snippet: redisStop.out.slice(-200) });
sleep(3000);
const readyRedisDown = await fetch(`${base}/api/v1/health/ready`, { signal: AbortSignal.timeout(10000) })
  .then(async (r) => ({ status: r.status, text: (await r.text()).slice(0, 300) }))
  .catch((e) => ({ status: 0, error: e.message }));
record('ready_fail_closed_on_redis_stop', readyRedisDown.status === 503 || readyRedisDown.status === 0, {
  status: readyRedisDown.status, body: readyRedisDown.text || readyRedisDown.error, expected: '503 NOT_READY',
});
const writeWhileRedisDown = await api(session, 'POST', `/api/v1/clusters/${clusterId}/entities/consumers`, {
  username: `pce-redis-down-${suffix}`, custom_id: `pce-redis-down-${suffix}`,
}, { idempotency: `pce-redis-down-${suffix}` });
record('write_fail_closed_on_redis_stop', writeWhileRedisDown.status === 0 || writeWhileRedisDown.status >= 500 || [401, 403, 503].includes(writeWhileRedisDown.status), {
  status: writeWhileRedisDown.status, code: writeWhileRedisDown.code, body: writeWhileRedisDown.text,
});
const redisStart = shOk(`${compose} start ${redisService}`, { timeout: 60000 });
record('redis_start', redisStart.ok);
let redisRecovered = false;
for (let i = 0; i < 40; i++) {
  const r = await fetch(`${base}/api/v1/health/ready`, { signal: AbortSignal.timeout(5000) })
    .then(async (x) => ({ status: x.status })).catch(() => ({ status: 0 }));
  if (r.status === 200) { redisRecovered = true; break; }
  sleep(2000);
}
record('ready_recovered_after_redis_start', redisRecovered);

const login2 = await login();
record('relogin_after_redis', login2.ok, { status: login2.status });
Object.assign(session, { cookie: login2.cookie, csrf: login2.csrf });

// Kong pause — admin path must fail-closed on writes that need Kong
const kongPause = shOk(`${compose} pause ${kongService}`, { timeout: 30000 });
record('kong_pause', kongPause.ok);
sleep(2000);
const readyKongDown = await fetch(`${base}/api/v1/health/ready`, { signal: AbortSignal.timeout(10000) })
  .then(async (r) => ({ status: r.status, text: (await r.text()).slice(0, 300) }))
  .catch((e) => ({ status: 0, error: e.message }));
record('ready_independent_of_kong_pause', readyKongDown.status === 200, {
  status: readyKongDown.status, note: 'storage ready does not require Kong; write path must fail-closed',
});
const writeWhileKongDown = await api(session, 'POST', `/api/v1/clusters/${clusterId}/entities/consumers`, {
  username: `pce-kong-down-${suffix}`, custom_id: `pce-kong-down-${suffix}`,
}, { idempotency: `pce-kong-down-${suffix}` });
record('write_fail_closed_on_kong_pause', writeWhileKongDown.status === 0 || writeWhileKongDown.status >= 500 || [502, 503, 504].includes(writeWhileKongDown.status), {
  status: writeWhileKongDown.status, code: writeWhileKongDown.code, body: writeWhileKongDown.text,
  expected: 'fail-closed (5xx/timeout) — no silent success',
});
const kongUnpause = shOk(`${compose} unpause ${kongService}`, { timeout: 30000 });
record('kong_unpause', kongUnpause.ok);
sleep(3000);
const writeAfterKong = await api(session, 'POST', `/api/v1/clusters/${clusterId}/entities/consumers`, {
  username: `pce-kong-up-${suffix}`, custom_id: `pce-kong-up-${suffix}`,
}, { idempotency: `pce-kong-up-${suffix}` });
record('write_after_kong_unpause', [200, 201].includes(writeAfterKong.status), {
  status: writeAfterKong.status, code: writeAfterKong.code,
});

finish();
const critical = ['bounded_write_load', 'ready_fail_closed_on_redis_stop', 'write_fail_closed_on_kong_pause', 'ready_recovered_after_redis_start'];
const ok = critical.every((id) => checks.some((c) => c.id === id && c.passed));
process.exitCode = ok ? 0 : 1;

function finish() {
  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.filter((c) => !c.passed && !c.skipped).length;
  const evidence = {
    schemaVersion: 1,
    kind: 'm11-production-compose-write-fault-smoke-evidence',
    commercialClosed: false,
    claimsClosed: false,
    failClosedExpected: true,
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'timestamps UTC; report Asia/Shanghai',
    baseUrl: base,
    composeFiles: composeFiles.map((f) => f.slice(repo.length + 1)),
    clusterId,
    writeLoad: { total: writeResults.length, writeOk, writeRejected, writeUnexpected, sample: writeResults.slice(0, 8) },
    totals: { total: checks.length, passed, failed },
    secretsPrinted: false,
    checks,
  };
  writeFileSync(join(outDir, outName), JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({
    written: join(outDir, outName),
    commercialClosed: false, passed, failed, total: checks.length,
    writeOk, writeRejected, writeUnexpected, ok: failed === 0,
  }, null, 2));
}
