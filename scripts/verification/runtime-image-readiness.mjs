#!/usr/bin/env node
/**
 * KP-009 runtime: immutable API image startup + /api/v1/health/ready.
 * Honest gaps recorded; never sets commercialClosed without full production overlay TLS.
 */
import { createHash as hash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';

const outDir = resolve(process.env.KP009_RUNTIME_OUT || 'artifacts/M11/runs/20261024-bff-portal');
const readyUrl = process.env.KP009_READY_URL || 'http://127.0.0.1:13000/api/v1/health/ready';
const liveUrl = process.env.KP009_LIVE_URL || 'http://127.0.0.1:13000/api/v1/health/live';
const container = process.env.KP009_API_CONTAINER || 'kp-bff-api-evidence';
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });

try {
  const inspect = JSON.parse(execSync(`docker inspect ${container}`, { encoding: 'utf8' }));
  const c = inspect[0];
  const image = c.Config.Image;
  const user = c.Config.User;
  const cmd = c.Config.Cmd;
  const running = c.State.Running === true;
  const imageId = c.Image;
  record('immutable_container_running', running, { container, image, imageId: imageId?.slice(0, 19), user, cmd });
  record('immutable_image_nonroot_user', user === '1000:1000' || user === '1000', { user });
  record('immutable_image_node_entrypoint', Array.isArray(cmd) && cmd.join(' ').includes('dist/main.js'), { cmd });

  const imgInspect = JSON.parse(execSync(`docker image inspect ${imageId}`, { encoding: 'utf8' }));
  const created = imgInspect[0]?.Created;
  const digests = imgInspect[0]?.RepoDigests || [];
  record('immutable_image_inspect', true, { created, repoDigests: digests.slice(0, 3), size: imgInspect[0]?.Size });

  // readiness HTTP
  const ready = await fetch(readyUrl, { signal: AbortSignal.timeout(10000) }).then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, error: e.message }));
  const live = await fetch(liveUrl, { signal: AbortSignal.timeout(10000) }).then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, error: e.message }));
  record('runtime_health_ready_http_200', ready.status === 200 && String(ready.text).includes('ready'), {
    status: ready.status, bodySha16: hash('sha256').update(ready.text || '').digest('hex').slice(0, 16), url: readyUrl,
  });
  record('runtime_health_live_http_200', live.status === 200 && String(live.text).includes('alive'), {
    status: live.status, url: liveUrl,
  });

  // production-like read_only not applied on this evidence container — record honestly
  const hostConfig = c.HostConfig || {};
  record('runtime_read_only_rootfs', hostConfig.ReadonlyRootfs === true, {
    readonlyRootfs: !!hostConfig.ReadonlyRootfs,
    gap: hostConfig.ReadonlyRootfs ? null : 'evidence container started without --read-only; production overlay requires read_only+tmpfs',
  });
  record('runtime_cap_drop_all', Array.isArray(hostConfig.CapDrop) && hostConfig.CapDrop.map(String).includes('ALL'), {
    capDrop: hostConfig.CapDrop || [],
    gap: 'full production overlay CapDrop/security_opt not applied on host-network evidence run',
  });
  record('runtime_tls_edge_hostname', false, {
    skipped: true,
    reason: 'no production nginx TLS edge in this host-network BFF evidence slice; static CSP/TLS contracts remain in kp009-production-overlay-evidence.json',
  });
  record('runtime_full_production_compose', false, {
    skipped: true,
    reason: 'Docker bridge DNS still hijacked to 198.18.0.0/15 on this runner; full compose.production.yml stack not started',
  });

  // persist restart smoke: restart container and re-check ready
  const beforeId = c.Id.slice(0, 12);
  execSync(`docker restart ${container}`, { stdio: 'pipe', timeout: 60000 });
  let restartedReady = false;
  let lastStatus = 0;
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    const r = await fetch(readyUrl, { signal: AbortSignal.timeout(5000) }).then(async (x) => ({ status: x.status, text: await x.text() })).catch(() => ({ status: 0 }));
    lastStatus = r.status;
    if (r.status === 200 && String(r.text).includes('ready')) { restartedReady = true; break; }
  }
  record('immutable_image_restart_health_ready', restartedReady, { beforeId, lastStatus });
} catch (e) {
  record('fatal', false, { message: e.message });
}

const completedAt = new Date().toISOString();
const evidence = {
  schemaVersion: 1,
  kind: 'kp009-runtime-immutable-image-health-ready-evidence',
  commercialClosed: false,
  claimsClosed: false,
  runtimeVerifiedPartial: checks.some((c) => c.id === 'runtime_health_ready_http_200' && c.passed)
    && checks.some((c) => c.id === 'immutable_container_running' && c.passed),
  startedAt,
  completedAt,
  timezoneNote: 'timestamps UTC; report Asia/Shanghai',
  checks,
  totals: {
    total: checks.length,
    passed: checks.filter((c) => c.passed).length,
    failed: checks.filter((c) => !c.passed && !c.skipped).length,
    skipped: checks.filter((c) => c.skipped).length,
  },
  remainingForClosure: [
    'Full compose.production.yml + TLS edge on non-hijacked network',
    'read_only rootfs + cap_drop ALL + no-new-privileges on live API',
    'Real TLS hostname verification with dedicated CA',
    'Persist/capacity/rollback drill under production overlay',
  ],
  secretsPrinted: false,
};
mkdirSync(outDir, { recursive: true });
const outPath = resolve(outDir, 'kp009-runtime-image-ready-evidence.json');
writeFileSync(outPath, JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify({
  written: outPath,
  runtimeVerifiedPartial: evidence.runtimeVerifiedPartial,
  commercialClosed: false,
  passed: evidence.totals.passed,
  failed: evidence.totals.failed,
  skipped: evidence.totals.skipped,
}, null, 2));
process.exit(evidence.runtimeVerifiedPartial && evidence.totals.failed === 0 ? 0 : (evidence.runtimeVerifiedPartial ? 0 : 1));
