#!/usr/bin/env node
/**
 * Smoke + light concurrency sanity against the real production compose
 * (docker-compose.yml + deploy/compose/compose.production.yml) on bridge networking.
 * Env: BRIDGE_ENV (private env file, never copied), BFF_BASE, PUBLIC_ORIGIN, PORTAL_BASE,
 *      KONG_PROXY_BASE, PCE_PROJECT, PCE_OUT, CONCURRENCY (default 20), ITERATIONS (default 10).
 * Self-signed lab TLS: run with NODE_TLS_REJECT_UNAUTHORIZED=0 (recorded in evidence).
 * Never sets commercialClosed. Prints no secrets.
 */
import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
async function walkIntegrity(fetchPage){const pages=[];let cursor;for(let i=0;i<50;i++){const r=await fetchPage('/api/v1/audit/global/integrity'+(cursor?'?cursor='+encodeURIComponent(cursor):''));const v=r.json?.data??r.json??{};pages.push({status:v.status,checkedRows:v.checkedRows,complete:v.complete,verifiedInterval:v.verifiedInterval,reasonCodes:v.reasonCodes});if(r.status!==200)return{ok:false,httpStatus:r.status,pages};if(v.status==='verified'&&v.complete===true)return{ok:true,httpStatus:200,pages,checkedRows:pages.reduce((n,p)=>n+(p.checkedRows||0),0)};if(v.status!=='partial'||!(v.reasonCodes||[]).includes('AUDIT_BUDGET_REACHED')||typeof v.nextCursor!=='string'||v.nextCursor===cursor)return{ok:false,httpStatus:200,pages};cursor=v.nextCursor;}return{ok:false,pageBudget:true,pages};}

const envMap = Object.fromEntries(readFileSync(process.env.BRIDGE_ENV, 'utf8').split('\n').filter((l) => l && !l.startsWith('#') && l.includes('=')).map((l) => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; }));
const base = process.env.BFF_BASE || 'https://127.0.0.1:48443';
const origin = process.env.PUBLIC_ORIGIN || base;
const portal = process.env.PORTAL_BASE || 'https://127.0.0.1:49443';
const proxy = process.env.KONG_PROXY_BASE || 'http://127.0.0.1:47800';
const project = process.env.PCE_PROJECT || 'kp-bridge';
const outDir = resolve(process.env.PCE_OUT);
const N = Number(process.env.CONCURRENCY || 20), ITER = Number(process.env.ITERATIONS || 10), THINK = Number(process.env.THINK_MS || 1200);
const user = envMap.BOOTSTRAP_ADMIN_USERNAME, pass = envMap.BOOTSTRAP_ADMIN_PASSWORD;
const checks = []; const record = (id, passed, detail = {}) => { checks.push({ id, passed: !!passed, ...detail }); console.log(passed ? 'PASS' : 'FAIL', id); };
const startedAt = new Date().toISOString();
const docker = (...a) => execFileSync('docker', a, { encoding: 'utf8' });
const merge = (prev, set) => { const j = new Map(); for (const p of (prev || '').split(';').map((s) => s.trim()).filter(Boolean)) { const i = p.indexOf('='); j.set(p.slice(0, i), p.slice(i + 1)); } for (const c of set || []) { const p = c.split(';')[0]; const i = p.indexOf('='); if (i > 0) j.set(p.slice(0, i), p.slice(i + 1)); } return [...j].map(([k, v]) => `${k}=${v}`).join('; '); };
async function req(s, method, path, body, extra = {}) {
  const t = performance.now();
  try {
    const r = await fetch(`${base}${path}`, { method, redirect: 'manual', signal: AbortSignal.timeout(30000), body: body ? JSON.stringify(body) : undefined,
      headers: { Accept: 'application/json', Origin: origin, ...(s?.cookie ? { Cookie: s.cookie } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}), ...(s?.csrf ? { 'X-CSRF-Token': s.csrf } : {}), ...extra } });
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {}
    if (s) { const set = r.headers.getSetCookie?.() || []; if (set.length) s.cookie = merge(s.cookie, set); if (json?.data?.csrfToken) s.csrf = json.data.csrfToken; }
    return { status: r.status, ms: performance.now() - t, json, headers: r.headers, code: json?.error?.code };
  } catch (e) { return { status: 0, ms: performance.now() - t, error: e.cause?.code || e.message }; }
}
async function login() { const s = {}; const r = await req(s, 'POST', '/api/v1/auth/login', { username: user, password: pass }); return { s, r }; }
const pct = (a, p) => { if (!a.length) return null; const b = [...a].sort((x, y) => x - y); return Math.round(b[Math.min(b.length - 1, Math.ceil(p / 100 * b.length) - 1)]); };
mkdirSync(outDir, { recursive: true });

// 1. topology: real bridge networks, nothing on host network, only loopback published ports
const ids = docker('compose', '-p', project, 'ps', '-q').trim().split('\n').filter(Boolean);
const topo = ids.map((id) => JSON.parse(docker('inspect', id))[0]).map((c) => ({
  service: c.Config.Labels['com.docker.compose.service'], networkMode: c.HostConfig.NetworkMode, health: c.State.Health?.Status || c.State.Status,
  networks: Object.keys(c.NetworkSettings.Networks).map((n) => n.replace(`${project}_`, '')),
  published: Object.entries(c.NetworkSettings.Ports || {}).flatMap(([p, b]) => (b || []).map((x) => `${x.HostIp}:${x.HostPort}->${p}`)),
}));
record('topology_no_host_network', topo.every((t) => t.networkMode !== 'host'), { topology: topo });
record('topology_all_running_healthy', topo.every((t) => ['healthy', 'running'].includes(t.health)));
const pubs = topo.flatMap((t) => t.published.map((p) => ({ service: t.service, p })));
record('published_ports_loopback_only_and_minimal', pubs.every((x) => x.p.startsWith('127.0.0.1:')) && new Set(pubs.map((x) => x.service)).size <= 3 && !pubs.some((x) => /^(console-db|kong-db|redis|console-api)$/.test(x.service)), { published: pubs });
const nets = {}; for (const t of topo) for (const n of t.networks) (nets[n] ||= []).push(t.service);
for (const n of Object.keys(nets)) { const i = JSON.parse(docker('network', 'inspect', `${project}_${n}`))[0]; nets[n] = { members: nets[n].sort(), internal: i.Internal, driver: i.Driver }; }
record('networks_bridge_driver', Object.values(nets).every((n) => n.driver === 'bridge'), { networks: nets });

// 2. edge TLS + headers
const ready = await req(null, 'GET', '/api/v1/health/ready');
record('console_https_ready', ready.status === 200, { status: ready.status, hsts: ready.headers?.get('strict-transport-security') || null });
const web = await fetch(`${base}/`, { signal: AbortSignal.timeout(10000) }).then((r) => ({ status: r.status, csp: !!r.headers.get('content-security-policy') })).catch((e) => ({ status: 0, error: e.message }));
record('console_web_served', web.status === 200, web);
const pr = await fetch(`${portal}/`, { signal: AbortSignal.timeout(10000) }).then((r) => ({ status: r.status })).catch((e) => ({ status: 0, error: e.message }));
record('portal_https_served', pr.status === 200, pr);
const anon = await req(null, 'GET', '/api/v1/clusters');
record('anonymous_api_rejected', anon.status === 401, { status: anon.status });
const bad = await req({}, 'POST', '/api/v1/auth/login', { username: user, password: 'wrong-' + randomBytes(4).toString('hex') });
record('bad_password_rejected', bad.status === 401, { status: bad.status });

// 3. admin login, Kong via internal DNS
const { s: admin, r: lr } = await login();
record('admin_login', [200, 201].includes(lr.status), { status: lr.status });
const cl = await req(admin, 'GET', '/api/v1/clusters');
const cluster = cl.json?.data?.[0]; const cid = cluster?.id;
const probe = await req(admin, 'POST', `/api/v1/clusters/${cid}/probe`, {});
const cl2 = await req(admin, 'GET', `/api/v1/clusters/${cid}`);
record('bootstrap_cluster_probe_healthy_via_internal_dns', cl2.json?.data?.status === 'healthy', { adminUrl: cluster?.admin_url, probeStatus: probe.status, clusterStatus: cl2.json?.data?.status, version: cl2.json?.data?.version, executionMode: cluster?.execution_mode });

// 4. write path end-to-end: service + route + consumer, verified through Kong proxy
const sfx = randomBytes(3).toString('hex');
const svc = await req(admin, 'POST', `/api/v1/clusters/${cid}/entities/services`, { name: `bridge-svc-${sfx}`, host: '203.0.113.10', port: 80, connect_timeout: 2000, retries: 0 }, { 'X-Idempotency-Key': `bridge-svc-${sfx}` });
record('write_service', [200, 201].includes(svc.status), { status: svc.status, code: svc.code });
const svcId = svc.json?.data?.id || svc.json?.data?.entity?.id;
const route = await req(admin, 'POST', `/api/v1/clusters/${cid}/entities/routes`, { name: `bridge-rt-${sfx}`, paths: [`/bridge-${sfx}`], service: { id: svcId } }, { 'X-Idempotency-Key': `bridge-rt-${sfx}` });
record('write_route', [200, 201].includes(route.status), { status: route.status, code: route.code });
let proxied = { status: 0 };
for (let i = 0; i < 10; i++) { proxied = await fetch(`${proxy}/bridge-${sfx}`, { signal: AbortSignal.timeout(20000) }).then((r) => ({ status: r.status })).catch((e) => ({ status: 0, error: e.message })); if (proxied.status !== 404) break; await new Promise((r) => setTimeout(r, 1000)); }
record('route_live_on_kong_proxy', proxied.status !== 404 && proxied.status !== 0, { status: proxied.status, note: 'upstream is TEST-NET-3 IP literal (no DNS; box containers have no external resolver); any non-404 (502/504) proves Kong applied the route' });
const list = await req(admin, 'GET', `/api/v1/clusters/${cid}/entities/services?size=100`);
record('read_back_service', JSON.stringify(list.json || {}).includes(`bridge-svc-${sfx}`), { status: list.status });
const cdb = (sql) => execFileSync('docker', ['compose', '-p', project, 'exec', '-T', 'console-db', 'sh', '-c', `psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "${sql}"`], { encoding: 'utf8' }).trim();
const routeId = route.json?.data?.id || route.json?.data?.entity?.id;
const auditRows = cdb(`select entity_type||':'||action||':'||result from audit_events where entity_id in ('${svcId}','${routeId}') order by sequence`).split('\n').filter(Boolean);
const auditApi = await req(admin, 'GET', `/api/v1/clusters/${cid}/audit?size=100&scope=cluster`);
record('audit_records_write', auditRows.includes('services:create:success') && auditRows.includes('routes:create:success') && auditApi.status === 200, { auditRows, apiStatus: auditApi.status, apiItems: auditApi.json?.data?.items?.length });
// 5. concurrency sanity: N distinct admin users (built-in admin role, default workspace).
// Login limits are 10/min/account and 30/min/IP, so fixture logins are paced (not part of the timed window).
const roles = await req(admin, 'GET', '/api/v1/iam/roles?size=50');
const adminRole = (roles.json?.data?.items || roles.json?.data || []).find((r) => r.code === 'admin');
const wsl = await req(admin, 'GET', `/api/v1/clusters/${cid}/workspaces`);
const wsId = (wsl.json?.data?.items || []).find((w) => w.is_default)?.id;
const pace = () => new Promise((r) => setTimeout(r, 2200));
const sessions = []; const fixture = [];
for (let i = 0; i < N; i++) {
  const username = `bridge-adm-${sfx}-${i}`, p1 = randomBytes(18).toString('base64url') + 'Aa1!', p2 = randomBytes(18).toString('base64url') + 'Bb2!';
  const u = await req(admin, 'POST', '/api/v1/iam/users', { username, display_name: `Bridge admin ${i}`, password: p1 }, { 'X-Idempotency-Key': `bu-${sfx}-${i}` });
  const uid = u.json?.data?.id;
  const b = await req(admin, 'POST', `/api/v1/iam/users/${uid}/role-bindings`, { role_id: adminRole?.id, cluster_id: cid, workspace_id: wsId }, { 'X-Idempotency-Key': `bb-${sfx}-${i}` });
  await pace(); const s0 = {}; const l0 = await req(s0, 'POST', '/api/v1/auth/login', { username, password: p1 });
  const ch = await req(s0, 'POST', '/api/v1/auth/me/password', { revision: l0.json?.data?.user?.revision, current_password: p1, new_password: p2, confirmed: true });
  await pace(); const s = {}; const l1 = await req(s, 'POST', '/api/v1/auth/login', { username, password: p2 });
  fixture.push({ i, create: u.status, bind: b.status, login0: l0.status, change: ch.status, login: l1.status, superAdmin: l1.json?.data?.user?.superAdmin ?? null });
  sessions.push({ s, status: l1.status });
}
record('concurrent_admin_fixture', fixture.every((f) => [200, 201].includes(f.create) && [200, 201].includes(f.bind) && [200, 201].includes(f.login) && f.superAdmin === false), { users: N, role: 'built-in admin (non-super)', sample: fixture.slice(0, 3), statuses: [...new Set(fixture.map((f) => `${f.create}/${f.bind}/${f.login0}/${f.change}/${f.login}`))] });
const RATE = Number(process.env.CLIENT_RPS || 16); let nextSlot = 0;
const takeToken = async () => { const now = performance.now(); const at = Math.max(now, nextSlot); nextSlot = at + 1000 / RATE; const w = at - now; if (w > 0) await new Promise((x) => setTimeout(x, w)); return w; };
const results = []; const t0 = performance.now();
await Promise.all(sessions.map(async ({ s }, u) => {
  for (let k = 0; k < ITER; k++) {
    const ops = [
      ['read', 'GET', '/api/v1/clusters'],
      ['read', 'GET', `/api/v1/clusters/${cid}/entities/services?size=20`],
      ['read', 'GET', `/api/v1/clusters/${cid}/entities/consumers?size=20`],
      ['write', 'POST', `/api/v1/clusters/${cid}/entities/consumers`, { username: `bridge-cc-${sfx}-${u}-${k}`, custom_id: `bridge-cc-${sfx}-${u}-${k}` }],
    ];
    for (const [kind, m, p, b] of ops) {
      let r, tries = 0; const ts = performance.now();
      // 409 RESOURCE_LOCKED = per-Kong-cluster mutation lock (fail-fast by design); client retries like the UI would.
      // Shared client-side limiter (<=16 r/s) emulates distinct-IP admins under the edge per-IP 20 r/s gate; limiter wait is recorded and excluded from latency. Gate unchanged; a 429 still counts as an error.
      // 409 RESOURCE_LOCKED = per-Kong-cluster mutation lock (fail-fast by design); client retries like the UI would.
      let limiterWaitMs = 0;
      do { if (tries) await new Promise((x) => setTimeout(x, 50 + Math.random() * 150 * tries)); limiterWaitMs += await takeToken(); r = await req(s, m, p, b, b ? { 'X-Idempotency-Key': `bridge-cc-${sfx}-${u}-${k}` } : {}); tries++; } while (r.status === 409 && r.code === 'RESOURCE_LOCKED' && tries < 40);
      results.push({ kind, status: r.status, ms: performance.now() - ts - limiterWaitMs, limiterWaitMs, firstTryMs: r.ms, lockRetries: tries - 1, code: r.code, error: r.error });
      if (THINK) await new Promise((x) => setTimeout(x, THINK * (0.5 + Math.random())));
    }
  }
}));
const wall = performance.now() - t0;
const sum = (kind) => { const a = results.filter((r) => !kind || r.kind === kind); const ok = a.filter((r) => r.status >= 200 && r.status < 300); return { total: a.length, ok: ok.length, errors: a.length - ok.length, p50: pct(a.map((r) => r.ms), 50), p95: pct(a.map((r) => r.ms), 95), max: Math.round(Math.max(...a.map((r) => r.ms))), lockRetriesTotal: a.reduce((x, r) => x + (r.lockRetries || 0), 0), requestsNeedingRetry: a.filter((r) => r.lockRetries > 0).length, errorStatuses: [...new Set(a.filter((r) => !(r.status >= 200 && r.status < 300)).map((r) => `${r.status}:${r.code || r.error || ''}`))] }; };
const conc = { sessions: N, iterationsPerSession: ITER, thinkTimeMs: THINK, sourceIpNote: 'all simulated admins share one source IP (127.0.0.1); edge nginx limit_req is 20 r/s burst 40 per IP, so think time keeps aggregate below the per-IP gate (gate not relaxed)', wallMs: Math.round(wall), throughputRps: Math.round(results.length / (wall / 1000) * 10) / 10, all: sum(), reads: sum('read'), writes: sum('write'), bar: 'sanity only (not an SLA): 0 final errors, read p95 < 1000ms, write p95 (incl. lock retries) < 3000ms', latencyNote: 'write ms includes RESOURCE_LOCKED client retries' };
record('concurrency_sanity_zero_errors', conc.all.errors === 0, conc);
record('concurrency_sanity_latency_reasonable', conc.reads.p95 < 1000 && conc.writes.p95 < 3000, { readP95: conc.reads.p95, writeP95: conc.writes.p95 });
// 5b. unpaced burst from the same IP: expect the edge per-IP limit to engage (gate check, informative)
const burst = await Promise.all(Array.from({ length: 120 }, (_, i) => req(sessions[i % N].s, 'GET', '/api/v1/clusters')));
const b429 = burst.filter((r) => r.status === 429).length, b200 = burst.filter((r) => r.status === 200).length;
record('edge_per_ip_rate_limit_engages_on_burst', b429 > 0 && b200 >= 40 && b200 + b429 === burst.length, { requests: burst.length, ok200: b200, limited429: b429, other: burst.length - b200 - b429 });
await new Promise((x) => setTimeout(x, 3000));
const kdb = (sql) => execFileSync('docker', ['compose', '-p', project, 'exec', '-T', 'kong-db', 'sh', '-c', `psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "${sql}"`], { encoding: 'utf8' }).trim();
const created = Number(kdb(`select count(*) from consumers where username like 'bridge-cc-${sfx}-%'`));
record('concurrent_writes_all_landed_in_kong', created === N * ITER, { expected: N * ITER, inKongStorage: created, source: 'kong-db consumers table' });
const integ = await walkIntegrity((p) => req(admin, 'GET', p));
record('audit_integrity_after_load', integ.ok, integ);

const passed = checks.filter((c) => c.passed).length;
const ev = { schemaVersion: 1, kind: 'm11-production-compose-bridge-evidence', commercialClosed: false, startedAt, completedAt: new Date().toISOString(), timezoneNote: 'UTC; report Asia/Shanghai',
  composeFiles: ['docker-compose.yml', 'deploy/compose/compose.production.yml'], project, base, tlsNote: 'self-signed lab certs; client ran with NODE_TLS_REJECT_UNAUTHORIZED=0', secretsPrinted: false,
  marker: sfx, clusterId: cid, concurrency: conc, totals: { total: checks.length, passed, failed: checks.length - passed }, checks };
writeFileSync(join(outDir, 'bridge-smoke-concurrency-evidence.json'), JSON.stringify(ev, null, 2) + '\n');
console.log(JSON.stringify({ passed, total: checks.length, conc: { all: conc.all, reads: conc.reads.p95, writes: conc.writes.p95 } }));
process.exitCode = passed === checks.length ? 0 : 1;
