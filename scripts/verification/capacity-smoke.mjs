#!/usr/bin/env node
/**
 * KP-009 / W14: bounded capacity/load smoke at realistic sizes against a live BFF.
 * Read-only authenticated list traffic (services/routes/consumers). No writes.
 * Never sets commercialClosed / commercialSlaCertified.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const outDir = resolve(process.env.KP_CAPACITY_OUT || join(repo, 'artifacts/M11/runs/20261025-capacity-smoke'));
const base = process.env.BFF_BASE || 'http://127.0.0.1:13000';
const adminUser = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const clusterId = process.env.KP_CAPACITY_CLUSTER_ID || process.env.KP005_APPEND_CLUSTER_ID || '3b148022-2251-47f5-b79d-faa7e1202e6d';
if (!adminPass) { console.error('BOOTSTRAP_ADMIN_PASSWORD required'); process.exit(2); }

const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
};

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
  const session = { cookie: '', csrf: '' };
  const res = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: base, Accept: 'application/json' },
    body: JSON.stringify({ username: adminUser, password: adminPass }),
    redirect: 'manual',
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let payload = null; try { payload = JSON.parse(text); } catch { /* */ }
  session.cookie = mergeCookie('', res.headers.getSetCookie?.() || []);
  session.csrf = payload?.data?.csrfToken || payload?.csrfToken || '';
  return { ok: res.status === 200 || res.status === 201, status: res.status, session };
}

async function get(session, path) {
  const start = Date.now();
  try {
    const res = await fetch(path.startsWith('http') ? path : `${base}${path}`, {
      headers: { Accept: 'application/json', Cookie: session.cookie },
      redirect: 'manual',
      signal: AbortSignal.timeout(30000),
    });
    await res.arrayBuffer();
    return { status: res.status, elapsedMs: Date.now() - start };
  } catch (e) {
    return { status: 0, elapsedMs: Date.now() - start, error: e.message };
  }
}

async function burst(session, url, { concurrency, perWorker, label }) {
  const results = [];
  const began = Date.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    for (let i = 0; i < perWorker; i++) results.push(await get(session, url));
  }));
  const elapsedMs = Date.now() - began;
  const sorted = results.map((r) => r.elapsedMs).sort((a, b) => a - b);
  const pct = (p) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
  const successful = results.filter((r) => r.status === 200).length;
  const limited429 = results.filter((r) => r.status === 429).length;
  const unexpected = results.filter((r) => ![200, 429].includes(r.status)).length;
  return {
    label,
    concurrency,
    perWorker,
    totalRequests: results.length,
    elapsedMs,
    successful,
    limited429,
    unexpected,
    p50Ms: pct(0.5),
    p95Ms: pct(0.95),
    p99Ms: pct(0.99),
    requestsPerSecond: results.length * 1000 / Math.max(1, elapsedMs),
    sampleStatuses: [...new Set(results.map((r) => r.status))].sort((a, b) => a - b),
  };
}

mkdirSync(outDir, { recursive: true });
const live = await get({ cookie: '' }, '/api/v1/health/live');
const ready = await get({ cookie: '' }, '/api/v1/health/ready');
record('health_live', live.status === 200, live);
record('health_ready', ready.status === 200, ready);

const { ok, status, session } = await login();
record('login', ok && !!session.csrf, { status });
if (!ok) {
  writeFileSync(join(outDir, 'kp009-capacity-load-smoke-evidence.json'), JSON.stringify({
    commercialClosed: false, commercialSlaCertified: false, writeLoadTested: false,
    allPassed: false, checks, startedAt, completedAt: new Date().toISOString(),
  }, null, 2) + '\n');
  process.exit(1);
}

const ws = await fetch(`${base}/api/v1/clusters/${clusterId}/workspaces`, {
  headers: { Cookie: session.cookie, Accept: 'application/json' },
});
const wsBody = await ws.json();
const wid = (wsBody.data?.items || wsBody.data || [])[0]?.id;
record('workspace', !!wid, { status: ws.status, wid });

const q = (entity, size) =>
  `/api/v1/clusters/${clusterId}/entities/${entity}?workspaceId=${wid}&size=${size}`;

const inventory = {};
for (const entity of ['services', 'routes', 'consumers']) {
  const r = await fetch(`${base}${q(entity, 100)}`, { headers: { Cookie: session.cookie, Accept: 'application/json' } });
  const j = await r.json();
  const items = j.data?.items || [];
  inventory[entity] = { status: r.status, count: Array.isArray(items) ? items.length : null, total: j.data?.total ?? null };
}
record('inventory_services', inventory.services?.status === 200 && (inventory.services.count ?? 0) >= 1, inventory.services);
record('inventory_routes', inventory.routes?.status === 200, inventory.routes);
record('inventory_consumers', inventory.consumers?.status === 200, inventory.consumers);

const tiers = [
  { label: 'S-services-size20', concurrency: 5, perWorker: 10, url: q('services', 20) },
  { label: 'M-services-size50', concurrency: 10, perWorker: 20, url: q('services', 50) },
  { label: 'L-services-size100', concurrency: 20, perWorker: 25, url: q('services', 100) },
  { label: 'M-routes-size50', concurrency: 10, perWorker: 15, url: q('routes', 50) },
  { label: 'M-consumers-size50', concurrency: 10, perWorker: 15, url: q('consumers', 50) },
];

const bursts = [];
for (const tier of tiers) {
  const b = await burst(session, tier.url, tier);
  bursts.push(b);
  record(`burst_${tier.label}`, b.unexpected === 0 && b.successful > 0, {
    successful: b.successful, unexpected: b.unexpected, limited429: b.limited429,
    p95Ms: b.p95Ms, rps: Number(b.requestsPerSecond.toFixed(2)),
  });
}

const allPassed = checks.every((c) => c.passed);
const report = {
  schemaVersion: 1,
  kind: 'kp009-capacity-load-smoke',
  commercialClosed: false,
  commercialSlaCertified: false,
  writeLoadTested: false,
  claimsClosed: false,
  allPassed,
  startedAt,
  completedAt: new Date().toISOString(),
  timezoneNote: 'Asia/Shanghai (UTC+8)',
  stack: { bffBase: base, clusterId, workspaceId: wid },
  inventory,
  historicalProductionBounded: existsSync(join(repo, 'artifacts/Production/root-production-bounded-capacity-fault-actual.json'))
    ? { path: 'artifacts/Production/root-production-bounded-capacity-fault-actual.json', note: 'prior exclusive production harness; not overwritten' }
    : null,
  bursts,
  totals: {
    requests: bursts.reduce((n, b) => n + b.totalRequests, 0),
    unexpected: bursts.reduce((n, b) => n + b.unexpected, 0),
    maxP95Ms: Math.max(...bursts.map((b) => b.p95Ms)),
  },
  remainingForClosure: [
    'Write-load / mutation throughput SLA under production overlay',
    'Fault injection (Kong/Redis stop) under exclusive production harness',
    'Persist restart + capacity under full compose.production.yml',
  ],
  checks,
  sourceRevisionHint: process.env.GITHUB_SHA || null,
};
const out = join(outDir, 'kp009-capacity-load-smoke-evidence.json');
writeFileSync(out, JSON.stringify(report, null, 2) + '\n', { flag: 'w', mode: 0o644 });
console.log(JSON.stringify({
  allPassed, out, requests: report.totals.requests, unexpected: report.totals.unexpected,
  maxP95Ms: report.totals.maxP95Ms, commercialClosed: false,
}));
process.exit(allPassed ? 0 : 1);
