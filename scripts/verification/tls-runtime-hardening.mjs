#!/usr/bin/env node
/**
 * KP-009: production-like hardened API (read_only+cap_drop+nnp) + TLS/CSP nginx edge on host network.
 * DNS/bridge still hijacked — full compose.production.yml not claimed. commercialClosed=false.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';
import { request as httpsRequest } from 'node:https';
import { parseDocument } from 'yaml';
import { assertProductionComposition } from '../../deploy/scripts/production-policy.mjs';

const outDir = resolve(process.env.KP009_HARDENED_OUT || 'artifacts/M11/runs/20261024-kp009-runtime');
const apiContainer = process.env.KP009_HARDENED_API || 'kp009-hardened-api-evidence';
const tlsContainer = process.env.KP009_TLS_EDGE || 'kp009-tls-console-edge';
const apiReady = process.env.KP009_HARDENED_READY || 'http://127.0.0.1:13001/api/v1/health/ready';
const tlsHttps = process.env.KP009_TLS_HTTPS || 'https://127.0.0.1:18444';
const tlsHealthzHttp = process.env.KP009_TLS_HEALTHZ_HTTP || 'http://127.0.0.1:18080/healthz';
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });

function httpsGet(url, { ca, servername } = {}) {
  return new Promise((resolveP) => {
    const u = new URL(url);
    const req = httpsRequest({
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
      method: 'GET', rejectUnauthorized: !!ca, ca, servername: servername || u.hostname, timeout: 10000,
      headers: { Accept: '*/*' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolveP({
        status: res.statusCode,
        headers: res.headers,
        text: Buffer.concat(chunks).toString('utf8').slice(0, 500),
      }));
    });
    req.on('error', (e) => resolveP({ status: 0, error: e.message, headers: {}, text: '' }));
    req.end();
  });
}

try {
  // Static overlay contract still holds
  const base = parseDocument(readFileSync('docker-compose.yml', 'utf8'), {
    customTags: [{ tag: '!override', collection: 'seq', resolve: (v) => v }],
  }).toJS();
  const production = parseDocument(readFileSync('deploy/compose/compose.production.yml', 'utf8'), {
    customTags: [{ tag: '!override', collection: 'seq', resolve: (v) => v }],
  }).toJS();
  // Full assertProductionComposition needs Docker-resolved synthetic merge (see production-overlay.mjs).
  record('overlay_files_present', !!base.services && !!production.services, {
    baseServices: Object.keys(base.services || {}).length,
    overlayServices: Object.keys(production.services || {}).length,
    note: 'synthetic assert covered by kp009-production-overlay-evidence.json in same run dir',
  });
  for (const [name, conf] of [['console', 'deploy/nginx/console-production.conf'], ['portal', 'deploy/nginx/portal-production.conf']]) {
    const text = readFileSync(conf, 'utf8');
    const csp = /Content-Security-Policy/.test(text) && text.includes("frame-ancestors 'none'") && text.includes("object-src 'none'");
    record(`static_csp_${name}`, csp, { conf });
  }
  record('overlay_api_read_only_declared', production.services['console-api']?.read_only === true);
  record('overlay_api_user_declared', production.services['console-api']?.user === '1000:1000');
  record('overlay_web_cap_drop_declared', production.services['console-web']?.cap_drop?.includes?.('ALL') === true);

  // Hardened API runtime
  const inspect = JSON.parse(execSync(`docker inspect ${apiContainer}`, { encoding: 'utf8' }))[0];
  const hc = inspect.HostConfig || {};
  record('hardened_api_running', inspect.State?.Running === true, { image: inspect.Config?.Image, user: inspect.Config?.User });
  record('hardened_api_read_only_rootfs', hc.ReadonlyRootfs === true, { readonlyRootfs: !!hc.ReadonlyRootfs });
  record('hardened_api_cap_drop_all', Array.isArray(hc.CapDrop) && hc.CapDrop.map(String).includes('ALL'), { capDrop: hc.CapDrop });
  record('hardened_api_no_new_privileges', (hc.SecurityOpt || []).some((x) => String(x).includes('no-new-privileges')), { securityOpt: hc.SecurityOpt });
  record('hardened_api_nonroot_user', inspect.Config?.User === '1000:1000' || inspect.Config?.User === '1000', { user: inspect.Config?.User });
  const ready = await fetch(apiReady, { signal: AbortSignal.timeout(10000) }).then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, error: e.message }));
  record('hardened_api_health_ready', ready.status === 200 && String(ready.text).includes('ready'), { status: ready.status, url: apiReady });

  // TLS edge runtime
  const tls = JSON.parse(execSync(`docker inspect ${tlsContainer}`, { encoding: 'utf8' }))[0];
  const thc = tls.HostConfig || {};
  record('tls_edge_running', tls.State?.Running === true, { image: tls.Config?.Image, user: tls.Config?.User });
  record('tls_edge_read_only_rootfs', thc.ReadonlyRootfs === true);
  record('tls_edge_cap_drop_all', Array.isArray(thc.CapDrop) && thc.CapDrop.map(String).includes('ALL'), { capDrop: thc.CapDrop });
  record('tls_edge_no_new_privileges', (thc.SecurityOpt || []).some((x) => String(x).includes('no-new-privileges')));

  const hzHttp = await fetch(tlsHealthzHttp, { signal: AbortSignal.timeout(10000) }).then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, error: e.message }));
  record('tls_edge_local_healthz_http', hzHttp.status === 200 && String(hzHttp.text).includes('ok'), { status: hzHttp.status });

  const hzHttps = await httpsGet(`${tlsHttps}/healthz`);
  const csp = String(hzHttps.headers['content-security-policy'] || '');
  const hsts = String(hzHttps.headers['strict-transport-security'] || '');
  record('tls_edge_https_healthz', hzHttps.status === 200 && String(hzHttps.text).includes('ok'), { status: hzHttps.status });
  record('tls_edge_csp_header', csp.includes("default-src 'self'") && csp.includes("frame-ancestors 'none'") && csp.includes("object-src 'none'"), { csp: csp.slice(0, 200) });
  record('tls_edge_hsts_header', hsts.includes('max-age='), { hsts });

  const apiViaTls = await httpsGet(`${tlsHttps}/api/v1/health/ready`);
  record('tls_edge_proxies_api_ready', apiViaTls.status === 200 && String(apiViaTls.text).includes('ready'), { status: apiViaTls.status, bodySha16: createHash('sha256').update(apiViaTls.text || '').digest('hex').slice(0, 16) });

  // Hostname verification with dedicated CA (self-signed evidence CA)
  const caPath = process.env.KP009_TLS_CA || '/tmp/kp009-tls-console/tls.crt';
  let hostnameVerified = false;
  if (existsSync(caPath)) {
    const ca = readFileSync(caPath);
    const verified = await new Promise((resolveP) => {
      const req = httpsRequest({
        hostname: '127.0.0.1', port: 18444, path: '/healthz', method: 'GET',
        rejectUnauthorized: true, ca, servername: 'oauth.evidence.local', timeout: 10000,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolveP({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', (e) => resolveP({ status: 0, error: e.message }));
      req.end();
    });
    hostnameVerified = verified.status === 200 && String(verified.text).includes('ok');
    record('tls_hostname_verify_with_evidence_ca', hostnameVerified, {
      status: verified.status, error: verified.error, servername: 'oauth.evidence.local', caPath,
      note: 'self-signed evidence CA; not public DNS / public CA',
    });
  } else {
    record('tls_hostname_verify_with_evidence_ca', false, { skipped: true, reason: 'ca_missing' });
  }

  // DNS / full compose honesty
  let dnsHijack = false;
  try {
    const { lookup } = await import('node:dns/promises');
    const addrs = await lookup('example.com', { all: true });
    dnsHijack = addrs.some((a) => String(a.address).startsWith('198.18.'));
  } catch { /* */ }
  record('runner_dns_bridge_hijack_detected', dnsHijack, {
    note: dnsHijack
      ? 'example.com resolves into 198.18.0.0/15 — full compose.production.yml bridge stack not started; host-network evidence only'
      : 'dns looks normal',
  });
  record('full_compose_production_stack', false, {
    skipped: true,
    reason: 'DNS/bridge hijack; host-network hardened API + TLS edge used instead of compose.production.yml',
  });
  record('capacity_rollback_drill', false, {
    skipped: true,
    reason: 'capacity/persist/rollback under full production overlay not in this slice',
  });
} catch (e) {
  record('fatal', false, { message: e.message });
}

const passed = checks.filter((c) => c.passed).length;
const skipped = checks.filter((c) => !c.passed && c.skipped).length;
const failed = checks.filter((c) => !c.passed && !c.skipped).length;
const runtimeHardened = checks.some((c) => c.id === 'hardened_api_read_only_rootfs' && c.passed)
  && checks.some((c) => c.id === 'hardened_api_cap_drop_all' && c.passed)
  && checks.some((c) => c.id === 'hardened_api_health_ready' && c.passed);
const runtimeTls = checks.some((c) => c.id === 'tls_edge_https_healthz' && c.passed)
  && checks.some((c) => c.id === 'tls_edge_csp_header' && c.passed)
  && checks.some((c) => c.id === 'tls_edge_proxies_api_ready' && c.passed);

const evidence = {
  schemaVersion: 1,
  kind: 'kp009-hardened-tls-hostnetwork-runtime-evidence',
  commercialClosed: false,
  claimsClosed: false,
  runtimeHardenedVerified: runtimeHardened,
  runtimeTlsCspVerified: runtimeTls,
  fullProductionComposeVerified: false,
  startedAt,
  completedAt: new Date().toISOString(),
  timezoneNote: 'timestamps UTC; report Asia/Shanghai',
  totals: { total: checks.length, passed, failed, skipped },
  remainingForClosure: [
    'Full compose.production.yml on non-hijacked Docker DNS/bridge',
    'Public/DNS hostname + public CA TLS (evidence used self-signed SAN)',
    'Portal independent TLS edge + browser UI matrix',
    'Capacity / persist restart / rollback under production overlay',
  ],
  secretsPrinted: false,
  checks,
};
mkdirSync(outDir, { recursive: true });
const outPath = resolve(outDir, 'kp009-hardened-tls-runtime-evidence.json');
writeFileSync(outPath, JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify({
  written: outPath, commercialClosed: false, runtimeHardenedVerified: runtimeHardened,
  runtimeTlsCspVerified: runtimeTls, passed, failed, skipped, total: checks.length,
}, null, 2));
