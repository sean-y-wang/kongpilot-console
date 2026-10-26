#!/usr/bin/env node
/**
 * Ephemeral Kong OSS 1.5.1 live evidence for KP-004/006/007 highest-value proxy slices.
 * Does NOT claim commercial closure. Redacts credentials from the published artifact.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const project = process.env.LIVE_KONG_EVIDENCE_PROJECT || 'kp-live-evidence';
const adminPort = process.env.LIVE_KONG_EVIDENCE_ADMIN_PORT || '18001';
const proxyPort = process.env.LIVE_KONG_EVIDENCE_PROXY_PORT || '18000';
const password = process.env.LIVE_KONG_EVIDENCE_DB_PASSWORD || 'kong';
const outDir = resolve(process.env.LIVE_KONG_EVIDENCE_OUT || 'artifacts/M11/runs/20261024-live-kp');
const composeFile = 'deploy/compose/compose.live-kong-evidence.yml';
const admin = `http://127.0.0.1:${adminPort}`;
const proxy = `http://127.0.0.1:${proxyPort}`;
const startedAt = new Date().toISOString();

const redact = (value) => {
  if (value == null) return value;
  const s = String(value);
  if (s.length <= 8) return '[redacted]';
  return `${s.slice(0, 2)}…${s.slice(-2)}(len=${s.length})`;
};

function run(argv, opts = {}) {
  const result = spawnSync(argv[0], argv.slice(1), {
    encoding: 'utf8',
    env: { ...process.env, LIVE_KONG_EVIDENCE_ADMIN_PORT: adminPort, LIVE_KONG_EVIDENCE_PROXY_PORT: proxyPort },
    timeout: opts.timeout ?? 120_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0 && !opts.allowFail) {
    const err = new Error(`command_failed:${argv.join(' ')}`);
    err.stderr = `${result.stderr || ''}\n---stdout---\n${result.stdout || ''}`.slice(0, 4000);
    err.stdout = (result.stdout || '').slice(0, 1000);
    err.status = result.status;
    throw err;
  }
  return result;
}

async function waitHealthy(ms = 90_000) {
  const deadline = Date.now() + ms;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${admin}/`);
      last = `status=${res.status}`;
      if (res.ok) {
        const body = await res.json();
        if (body?.version || body?.tagline || body?.configuration) return body;
        // Kong 1.5 root may return differently
        return body ?? { ok: true };
      }
    } catch (e) {
      last = e.message;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`kong_admin_not_ready:${last}`);
}

async function adminJson(method, path, body) {
  const res = await fetch(`${admin}${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { rawType: typeof text, rawLen: text.length }; }
  return { status: res.status, ok: res.ok, json };
}

async function proxyProbe(headers = {}) {
  const res = await fetch(`${proxy}/live-evidence`, { headers });
  const text = await res.text();
  return { status: res.status, bodyPreview: text.slice(0, 80), hasUpstreamMarker: text.includes('kongpilot-live-upstream-ok') };
}

const steps = [];
const record = (id, passed, detail = {}) => {
  steps.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
};

let teardown = async () => {};
let exitCode = 1;

try {
  mkdirSync(outDir, { recursive: true });
  run(['docker', 'compose', '--project-name', project, '-f', composeFile, '--profile', 'live-kong-evidence', 'down', '-v', '--remove-orphans'], { allowFail: true, timeout: 60_000 });
  const up = run(['docker', 'compose', '--project-name', project, '-f', composeFile, '--profile', 'live-kong-evidence', 'up', '-d', '--pull', 'missing', '--wait'], { timeout: 180_000 });
  record('compose_up', up.status === 0, { project, composeFile });
  teardown = async () => {
    run(['docker', 'compose', '--project-name', project, '-f', composeFile, '--profile', 'live-kong-evidence', 'down', '-v', '--remove-orphans'], { allowFail: true, timeout: 90_000 });
  };

  const root = await waitHealthy();
  record('kong_admin_ready', true, { version: root?.version || root?.tagline || 'present' });

  const service = await adminJson('POST', '/services', { name: 'live-evidence-svc', url: 'http://127.0.0.1:25678' });
  record('create_service', service.ok, { status: service.status, idPresent: !!service.json?.id });
  const route = await adminJson('POST', `/services/${service.json.id}/routes`, { name: 'live-evidence-route', paths: ['/live-evidence'] });
  record('create_route', route.ok, { status: route.status });

  const consumerA = await adminJson('POST', '/consumers', { username: `kp-a-${randomBytes(4).toString('hex')}` });
  const consumerB = await adminJson('POST', '/consumers', { username: `kp-b-${randomBytes(4).toString('hex')}` });
  record('create_consumers', consumerA.ok && consumerB.ok, { statusA: consumerA.status, statusB: consumerB.status });

  const keyIssue = await adminJson('POST', `/consumers/${consumerA.json.id}/key-auth`, {});
  const apiKey = keyIssue.json?.key;
  record('issue_key_auth', keyIssue.ok && typeof apiKey === 'string' && apiKey.length > 8, {
    status: keyIssue.status,
    keyFingerprint: createHash('sha256').update(String(apiKey || '')).digest('hex').slice(0, 16),
    keyRedacted: redact(apiKey),
  });

  const plugin = await adminJson('POST', '/plugins', { name: 'key-auth', config: { key_names: ['apikey'], hide_credentials: true } });
  record('enable_key_auth_plugin', plugin.ok, { status: plugin.status });

  const withKey = await proxyProbe({ apikey: apiKey });
  record('kp006_proxy_with_issued_key', withKey.status === 200 && withKey.hasUpstreamMarker, withKey);

  const withoutKey = await proxyProbe();
  record('kp006_proxy_without_key_denied', withoutKey.status === 401, withoutKey);

  const wrongKey = await proxyProbe({ apikey: `wrong-${randomBytes(8).toString('hex')}` });
  record('kp006_proxy_wrong_key_denied', wrongKey.status === 401, wrongKey);

  const del = await adminJson('DELETE', `/consumers/${consumerA.json.id}/key-auth/${keyIssue.json.id}`);
  record('kp006_revoke_delete_key', del.status === 204 || del.status === 200, { status: del.status });
  const afterRevoke = await proxyProbe({ apikey: apiKey });
  record('kp006_proxy_after_revoke_denied', afterRevoke.status === 401, afterRevoke);

  const reissue = await adminJson('POST', `/consumers/${consumerA.json.id}/key-auth`, {});
  const newKey = reissue.json?.key;
  record('kp004_reissue_key_same_consumer', reissue.ok && newKey && newKey !== apiKey, {
    status: reissue.status,
    newKeyFingerprint: createHash('sha256').update(String(newKey || '')).digest('hex').slice(0, 16),
  });
  const afterRestore = await proxyProbe({ apikey: newKey });
  record('kp004_proxy_after_reissue_ok', afterRestore.status === 200 && afterRestore.hasUpstreamMarker, afterRestore);
  const oldKeyStillDead = await proxyProbe({ apikey: apiKey });
  record('kp004_old_key_remains_denied', oldKeyStillDead.status === 401, oldKeyStillDead);

  // KP-007-style Admin IDOR: consumer B must not read consumer A's credential by id.
  const idor = await adminJson('GET', `/consumers/${consumerB.json.id}/key-auth/${reissue.json.id}`);
  record('kp007_admin_cross_consumer_key_denied', idor.status === 404 || idor.status === 403, { status: idor.status });
  const ownList = await adminJson('GET', `/consumers/${consumerA.json.id}/key-auth`);
  record('kp007_admin_own_consumer_key_list_ok', ownList.ok && Array.isArray(ownList.json?.data), {
    status: ownList.status,
    count: ownList.json?.data?.length ?? null,
  });

  const image = run(['docker', 'image', 'inspect', 'kong:1.5.1', '--format', '{{.Id}} {{.RepoDigests}}'], { allowFail: true });
  record('kong_image_pin', image.status === 0, { inspectPreview: (image.stdout || '').trim().slice(0, 200) });

  exitCode = steps.every((s) => s.passed) ? 0 : 1;
} catch (error) {
  record('fatal', false, { message: error.message, stderr: error.stderr?.slice?.(0, 500) });
  exitCode = 1;
} finally {
  try { await teardown(); record('compose_down', true); } catch (e) { record('compose_down', false, { message: e.message }); }
}

const completedAt = new Date().toISOString();
const evidence = {
  schemaVersion: 1,
  kind: 'kp004-006-007-live-kong-oss-1.5.1-proxy-evidence',
  commercialClosed: false,
  claimsClosed: false,
  scope: {
    kongOss: '1.5.1',
    layer: 'kong-admin-and-proxy-only',
    productBffHttp: false,
    portalBrowser: false,
    fiveRootRecycle: false,
    multiWorkerRedis: false,
    note: 'Highest-value Kong-native issue/revoke/reissue proxy + Admin cross-consumer denial. Not product IDOR/HTTP matrix or full KP-004 five-root restore.',
  },
  project,
  startedAt,
  completedAt,
  timezoneNote: 'timestamps are UTC; report to owner in Asia/Shanghai',
  steps,
  totals: {
    total: steps.length,
    passed: steps.filter((s) => s.passed).length,
    failed: steps.filter((s) => !s.passed).length,
  },
  allPassed: steps.every((s) => s.passed),
  secretsPrinted: false,
  composeSourceSha256: createHash('sha256').update(readFileSync(composeFile)).digest('hex'),
  scriptSourceSha256: createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex'),
};

mkdirSync(outDir, { recursive: true });
const outPath = resolve(outDir, 'live-kong-proxy-evidence.json');
writeFileSync(outPath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o644 });
console.log(JSON.stringify({ written: outPath, allPassed: evidence.allPassed, passed: evidence.totals.passed, failed: evidence.totals.failed, commercialClosed: false }, null, 2));
process.exit(exitCode);
