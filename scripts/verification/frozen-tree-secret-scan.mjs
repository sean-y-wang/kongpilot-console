#!/usr/bin/env node
/**
 * KP-013: full secret scan of frozen publishable tree + three builds + owned
 * evidence logs/audit, fail-closed on findings. Uses m11-current-secret-scan.mjs.
 * commercialClosed stays false (scan alone ≠ commercial acceptance).
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  chmodSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync,
  rmSync, writeFileSync, lstatSync, openSync, closeSync, fsyncSync,
} from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runCurrentSecretScan, currentScanGitPaths } from '../../tests/security/m11-current-secret-scan.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const outDir = resolve(process.env.KP013_OUT || join(repo, 'artifacts/M11/runs/20261024-kp013-secret-scan'));
const privateParent = resolve(process.env.KP013_PRIVATE_PARENT || '/opt/kp-private-parent');
const apiContainer = process.env.KP013_API || 'kp-bff-api-evidence';
const evidenceDb = process.env.KP013_DB || 'kp-bff-evidence-bff-evidence-db-1';
const bffBase = process.env.KP013_BFF || 'http://127.0.0.1:13000';
const kongAdmin = process.env.KP013_KONG_ADMIN || 'http://127.0.0.1:18001';
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed) console.error(JSON.stringify({ checkFailed: id, ...detail }));
};

function digest(v) {
  return createHash('sha256').update(String(v)).digest('hex');
}
function shortDigest(v) { return digest(v).slice(0, 16); }

function docker(args, opts = {}) {
  const r = spawnSync('docker', ['--host=unix:///var/run/docker.sock', ...args], {
    encoding: opts.encoding ?? 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: opts.timeout ?? 120000, ...opts,
  });
  if (r.error || r.status !== 0) throw new Error(`DOCKER_FAILED:${(r.stderr || r.stdout || r.error?.message || '').toString().slice(0, 300)}`);
  return r.stdout;
}

function writePrivate(path, bytes) {
  const fd = openSync(path, 'wx', 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(path, 0o600);
}

function extractEnv(container) {
  const rows = JSON.parse(docker(['inspect', container]))[0].Config.Env;
  return Object.fromEntries(rows.map((l) => {
    const i = l.indexOf('=');
    return [l.slice(0, i), l.slice(i + 1)];
  }));
}

async function httpJson(url, { method = 'GET', headers = {}, body } = {}) {
  const res = await fetch(url, {
    method, headers: { Accept: 'application/json', ...headers },
    body: body != null ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* */ }
  const setCookie = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  return { status: res.status, data, text, setCookie };
}

mkdirSync(outDir, { recursive: true });
mkdirSync(privateParent, { recursive: true });
chmodSync(privateParent, 0o755);

const workRoot = join(privateParent, `kp013-${randomUUID()}`);
mkdirSync(workRoot, { mode: 0o700 });
chmodSync(workRoot, 0o700);
const privateRoot = join(workRoot, 'private');
const inputRoot = join(privateRoot, 'capture');
const buildRoot = join(workRoot, 'builds');
const materialDir = join(privateRoot, 'material');
mkdirSync(privateRoot, { mode: 0o700 });
mkdirSync(inputRoot, { mode: 0o700 });
mkdirSync(materialDir, { mode: 0o700 });
mkdirSync(buildRoot, { mode: 0o755 });
chmodSync(privateRoot, 0o700);
chmodSync(inputRoot, 0o700);
chmodSync(materialDir, 0o700);

let scanReport = null;
let failure = null;
let profile = 'credential-complete';
const materialMeta = { password: false, cookie: false, csrf: false, apiKey: false, environmentSecret: false };

try {
  const env = extractEnv(apiContainer);
  const adminUser = env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
  const adminPass = env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!adminPass || adminPass.length < 8) throw new Error('KP013_ADMIN_PASSWORD_MISSING');

  // Environment file (0600) — actual secret values stay private
  const envLines = [
    `CONSOLE_ENCRYPTION_KEY=${env.CONSOLE_ENCRYPTION_KEY}`,
    `APP_SECRET=${env.APP_SECRET}`,
    `PORTAL_SECRET=${env.PORTAL_SECRET}`,
    `BOOTSTRAP_ADMIN_PASSWORD=${adminPass}`,
    `DATABASE_URL=${env.DATABASE_URL || ''}`,
    `REDIS_URL=${env.REDIS_URL || ''}`,
  ].filter((l) => !l.endsWith('='));
  const envPath = join(materialDir, 'evidence.env');
  writePrivate(envPath, envLines.join('\n') + '\n');
  materialMeta.environmentSecret = true;
  materialMeta.password = true;

  // Live login → cookie + csrf
  const login = await httpJson(`${bffBase}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: { username: adminUser, password: adminPass },
  });
  if (login.status !== 200 && login.status !== 201) throw new Error('KP013_LOGIN_FAILED:' + login.status);
  const csrf = login.data?.data?.csrfToken || login.data?.csrfToken || login.data?.csrf || '';
  const cookieParts = [];
  for (const c of login.setCookie) {
    const m = /^(kongos_[^=]+|kongpilot_[^=]+)=([^;]+)/i.exec(c) || /^([^=]+)=([^;]+)/.exec(c);
    if (m) cookieParts.push(`${m[1]}=${m[2]}`);
  }
  const cookieHeader = cookieParts.join('; ');
  if (!csrf || csrf.length < 8) throw new Error('KP013_CSRF_MISSING');
  if (!cookieHeader || cookieHeader.length < 8) throw new Error('KP013_COOKIE_MISSING');
  materialMeta.cookie = true;
  materialMeta.csrf = true;
  record('live_admin_login_for_material', true, { csrfLen: csrf.length, cookieParts: cookieParts.length });

  // Temporary Kong key-auth credential for api-key material (cleaned after)
  const tag = `kp013-${randomBytes(4).toString('hex')}`;
  const apiKeyValue = `kp013-key-${randomBytes(16).toString('hex')}`;
  let consumerId = null;
  let keyCredId = null;
  try {
    const cons = await httpJson(`${kongAdmin}/consumers`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: { username: `scan-${tag}` },
    });
    consumerId = cons.data?.id;
    if (!consumerId) throw new Error('KP013_CONSUMER_CREATE_FAILED');
    const key = await httpJson(`${kongAdmin}/consumers/${consumerId}/key-auth`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: { key: apiKeyValue },
    });
    keyCredId = key.data?.id;
    if (!keyCredId) throw new Error('KP013_KEY_CREATE_FAILED');
    materialMeta.apiKey = true;
    record('temporary_api_key_material_issued', true, { consumerIdDigest: shortDigest(consumerId) });
  } catch (e) {
    record('temporary_api_key_material_issued', false, { error: String(e.message).slice(0, 200) });
    profile = 'checkpoint-api-key-not-issued';
  }

  // Ledger with required material kinds (no secrets in public report)
  const ledger = {
    version: 1,
    milestone: 'M11-KP013',
    requests: [{
      method: 'POST',
      path: '/api/v1/auth/login',
      status: login.status,
      body: { username: adminUser, password: adminPass },
      responseData: { data: { csrfToken: csrf } },
      headers: { cookie: cookieHeader, 'x-csrf-token': csrf },
    },
    ...(materialMeta.apiKey ? [{
      method: 'POST',
      path: `/consumers/${consumerId}/key-auth`,
      status: 201,
      body: {},
      responseData: { id: keyCredId, key: apiKeyValue, issuedKey: apiKeyValue },
      headers: {},
    }] : [])],
  };
  const ledgerPath = join(materialDir, 'ledger.json');
  writePrivate(ledgerPath, JSON.stringify(ledger) + '\n');

  // Capture owned container logs (evidence DB/redis + BFF API)
  const owned = [
    { name: evidenceDb, file: 'logs/evidence-db.log' },
    { name: 'kp-bff-evidence-bff-evidence-redis-1', file: 'logs/evidence-redis.log' },
    { name: apiContainer, file: 'logs/bff-api.log' },
  ];
  mkdirSync(join(inputRoot, 'logs'), { mode: 0o700 });
  chmodSync(join(inputRoot, 'logs'), 0o700);
  const captureFiles = [];
  for (const row of owned) {
    const logs = spawnSync('docker', ['--host=unix:///var/run/docker.sock', 'logs', '--timestamps', row.name], {
      encoding: null, maxBuffer: 64 * 1024 * 1024, timeout: 60000,
    });
    // docker logs writes container stdout to stdout and stderr to stderr even on success
    const bytes = Buffer.concat([logs.stdout || Buffer.alloc(0), Buffer.from('\n'), logs.stderr || Buffer.alloc(0)]);
    if (logs.error || (logs.status !== 0 && logs.status != null)) {
      throw new Error('KP013_LOG_CAPTURE_FAILED:' + row.name);
    }
    const abs = join(inputRoot, row.file);
    writePrivate(abs, bytes);
    captureFiles.push({
      kind: 'owned-container-log',
      file: row.file,
      complete: true,
      ownContainer: true,
      stdout: true,
      stderr: true,
      clipped: false,
      byteCount: bytes.length,
      sha256: digest(bytes),
    });
  }
  record('owned_container_logs_captured', captureFiles.length === 3, { count: captureFiles.length });

  // Actual audit JSON from evidence DB
  const auditSql = `SELECT coalesce(json_agg(row_to_json(a) ORDER BY chain_scope, seq), '[]'::json)
FROM (SELECT id, chain_scope, sequence::text AS seq, sequence::text AS sequence, actor_id, actor_type, entity_type, entity_id, action, result, request_id,
  prev_hash, event_hash, to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at
  FROM audit_events ORDER BY chain_scope, sequence::bigint LIMIT 5000) a;`;
  const auditRaw = docker(['exec', '-i', evidenceDb, 'psql', '-h', '127.0.0.1', '-p', '25433',
    '-U', 'kongpilot', '-d', 'kongpilot_bff_evidence', '-At', '--set=ON_ERROR_STOP=1'], { input: auditSql });
  let auditRows;
  try { auditRows = JSON.parse(String(auditRaw).trim()); } catch (e) { throw new Error('KP013_AUDIT_JSON_INVALID'); }
  if (!Array.isArray(auditRows) || auditRows.length < 1) throw new Error('KP013_AUDIT_EMPTY');
  const auditPathRel = 'audit/actual-audit.json';
  mkdirSync(join(inputRoot, 'audit'), { mode: 0o700 });
  chmodSync(join(inputRoot, 'audit'), 0o700);
  const auditBytes = Buffer.from(JSON.stringify(auditRows) + '\n');
  writePrivate(join(inputRoot, auditPathRel), auditBytes);
  captureFiles.push({
    kind: 'actual-audit-json',
    file: auditPathRel,
    complete: true,
    actualAudit: true,
    byteCount: auditBytes.length,
    sha256: digest(auditBytes),
  });
  record('actual_audit_captured', true, { rows: auditRows.length });

  // Capture manifest
  const captureManifest = {
    version: 1,
    complete: true,
    capturedAt: new Date().toISOString(),
    files: captureFiles,
  };
  writePrivate(join(inputRoot, 'manifest.json'), JSON.stringify(captureManifest, null, 2) + '\n');

  // Isolated three-build copy (outside repository)
  for (const name of ['console-api', 'console-web', 'portal-web']) {
    const src = join(repo, 'apps', name, 'dist');
    const dst = join(buildRoot, name);
    if (!existsSync(src) || readdirSync(src).length === 0) throw new Error('KP013_BUILD_MISSING:' + name);
    cpSync(src, dst, { recursive: true });
    // Ensure no symlinks in build tree
    const walk = (d) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, e.name);
        if (e.isSymbolicLink() || lstatSync(p).isSymbolicLink()) throw new Error('KP013_BUILD_SYMLINK:' + p);
        if (e.isDirectory()) walk(p);
      }
    };
    walk(dst);
  }
  record('three_builds_isolated', true, {
    consoleApiFiles: readdirSync(join(buildRoot, 'console-api')).length,
    consoleWebFiles: readdirSync(join(buildRoot, 'console-web')).length,
    portalWebFiles: readdirSync(join(buildRoot, 'portal-web')).length,
  });

  // Freeze handoff + run scanner (fail-closed)
  const config = {
    repository: repo,
    privateRoot,
    inputRoot,
    buildRoot,
    reportDirectory: outDir,
    ledgerPaths: [ledgerPath],
    environmentPaths: [envPath],
    privateMaterialDiagnostic: false,
    profile,
  };
  record('inputs_frozen_handoff', true, { profile, privateRootMode: (lstatSync(privateRoot).mode & 0o777).toString(8) });

  // Enumerate once to pin tree size for evidence
  const names = currentScanGitPaths(repo);
  record('frozen_tree_enumerated', names.length > 0, { publishableFileCount: names.length });

  scanReport = runCurrentSecretScan(config);
  const passed = scanReport?.passed === true && Number(scanReport?.findingCount || 0) === 0;
  record('secret_scan_passed', passed, {
    findingCount: scanReport?.findingCount,
    actualSecretCount: scanReport?.actualSecretCount,
    byteCount: scanReport?.byteCount,
    profile: scanReport?.profile,
    failure: scanReport?.failure || null,
  });
  record('secret_scan_fail_closed', !passed ? scanReport?.passed !== true : true, {
    note: passed ? 'zero findings' : 'scanner refused or findings present — not claimed closed',
  });
  record('final_credential_complete_flag', scanReport?.finalCredentialComplete === (profile === 'credential-complete'), {
    finalCredentialComplete: scanReport?.finalCredentialComplete,
  });

  // Cleanup temporary Kong consumer/key (best effort)
  if (consumerId) {
    try {
      await httpJson(`${kongAdmin}/consumers/${consumerId}`, { method: 'DELETE' });
      record('temporary_api_key_cleaned', true);
    } catch {
      record('temporary_api_key_cleaned', false);
    }
  }

  // Write scanner report into outDir explicitly if not already (runCurrentSecretScan doesn't write — CLI does)
  // We persist a public redacted copy via our evidence wrapper; also dump the scan report (no secret values)
  const scanOut = join(outDir, `m11-current-secret-scan-kp013-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  const publicScan = {
    version: scanReport.version,
    passed: scanReport.passed,
    scanOnly: true,
    findingCount: scanReport.findingCount,
    actualSecretCount: scanReport.actualSecretCount,
    patternCount: scanReport.patternCount,
    byteCount: scanReport.byteCount,
    profile: scanReport.profile,
    scope: scanReport.scope,
    groups: scanReport.groups,
    files: (scanReport.files || []).map((f) => ({
      path: f.path, kinds: f.kinds, sha256: f.sha256, byteCount: f.byteCount, findingCount: f.findingCount,
    })),
    findings: scanReport.findings || [],
    limitations: scanReport.limitations,
    exactAPIKeyMaterials: scanReport.exactAPIKeyMaterials,
    apiKeyIssuanceAcceptance: scanReport.apiKeyIssuanceAcceptance,
    finalCredentialComplete: scanReport.finalCredentialComplete,
    elapsedMs: scanReport.elapsedMs,
    failure: scanReport.failure || null,
    materialFiles: (scanReport.materialFiles || []).map((m) => ({ path: m.path, sha256: m.sha256, byteCount: m.byteCount })),
  };
  writeFileSync(scanOut, JSON.stringify(publicScan, null, 2) + '\n');
  record('scan_report_artifact_written', true, { path: relative(repo, scanOut) });

  if (!passed) throw new Error(scanReport?.failure?.code || 'SCAN_SECRET_FINDINGS_REQUIRE_REVIEW');
} catch (e) {
  failure = { code: /^[A-Z0-9_]+$/.test(e?.message ?? '') ? e.message : 'KP013_EVIDENCE_FAILED', message: String(e?.message || e).slice(0, 400) };
  record('evidence_exception', false, failure);
} finally {
  try { if (existsSync(workRoot)) rmSync(workRoot, { recursive: true, force: true }); } catch { /* */ }
}

const critical = ['live_admin_login_for_material', 'owned_container_logs_captured', 'actual_audit_captured',
  'three_builds_isolated', 'frozen_tree_enumerated', 'secret_scan_passed'];
const allCritical = critical.every((id) => checks.find((c) => c.id === id)?.passed);

const report = {
  version: 1,
  kp: 'KP-013',
  title: 'full secret scan of frozen publishable tree (fail-closed)',
  startedAt,
  completedAt: new Date().toISOString(),
  commercialClosed: false,
  commercialClosedReason: 'Secret scan evidence is one security check and does not establish commercial acceptance; KP-005 durable target append still unsupported; KP-010 restore productionReady=false.',
  scanner: 'tests/security/m11-current-secret-scan.mjs',
  profile,
  materialKindsPrepared: materialMeta,
  allCriticalPassed: allCritical,
  failClosed: true,
  findingCount: scanReport?.findingCount ?? null,
  actualSecretCount: scanReport?.actualSecretCount ?? null,
  byteCount: scanReport?.byteCount ?? null,
  groups: scanReport?.groups ?? null,
  finalCredentialComplete: scanReport?.finalCredentialComplete ?? false,
  apiKeyIssuanceAcceptance: scanReport?.apiKeyIssuanceAcceptance ?? false,
  checks,
  limitations: [
    'Scanner covers publishable git tree (excluding node_modules/dist/.git), isolated three-build copies, owned evidence container logs, and an actual audit snapshot — not historical RAM keys or external credentials outside retained material.',
    'Byte matching does not OCR screenshots.',
    'Temporary Kong api-key was issued only as scan material and cleaned when possible.',
    'wholeM11Accepted / commercialClosed remain false.',
  ],
  ...(failure ? { failure } : {}),
};

writeFileSync(join(outDir, 'kp013-frozen-tree-secret-scan-evidence.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({
  written: join(outDir, 'kp013-frozen-tree-secret-scan-evidence.json'),
  allCriticalPassed: allCritical,
  profile,
  findingCount: report.findingCount,
  passedCount: checks.filter((c) => c.passed).length,
  checkCount: checks.length,
  commercialClosed: false,
  ...(failure ? { failure } : {}),
}));
process.exit(allCritical ? 0 : 1);
