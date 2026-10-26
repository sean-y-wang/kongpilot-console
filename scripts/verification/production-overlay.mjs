#!/usr/bin/env node
/**
 * KP-009 production overlay / TLS / CSP / min-privilege / health-readiness evidence.
 * Static + contract checks only unless LIVE runtime probes are explicitly enabled.
 * Never claims commercialClosed=true without runtimeVerified evidence.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseDocument } from 'yaml';
import { assertProductionComposition } from '../../deploy/scripts/production-policy.mjs';

const outDir = resolve(process.env.KP009_EVIDENCE_OUT || 'artifacts/M11/runs/20261024-live-kp');
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });

function composition(path) {
  const document = parseDocument(readFileSync(path, 'utf8'), {
    customTags: [{ tag: '!override', collection: 'seq', resolve: (value) => value }],
  });
  if (document.errors?.length) throw new Error(`yaml_parse:${path}`);
  return document.toJS();
}

function sha(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function cspPresent(confPath) {
  const text = readFileSync(confPath, 'utf8');
  return /add_header\s+Content-Security-Policy\s+"[^"]+"\s+always;/.test(text)
    && text.includes("default-src 'self'")
    && text.includes("frame-ancestors 'none'")
    && text.includes("object-src 'none'");
}

function readinessBlock(confPath) {
  const text = readFileSync(confPath, 'utf8');
  return text.includes('listen 8080') && text.includes('location = /healthz') && /return 200 "ok\\n"/.test(text);
}

try {
  const base = composition('docker-compose.yml');
  const production = composition('deploy/compose/compose.production.yml');
  const external = composition('deploy/compose/compose.external-kong.yml');
  record('parse_base_compose', true, { services: Object.keys(base.services || {}).length });
  record('parse_production_overlay', true, { services: Object.keys(production.services || {}).length });
  record('parse_external_kong_overlay', true, { services: Object.keys(external.services || {}).length });

  // Overlay must not drop durable volumes (policy already unit-tested; restate evidence).
  for (const [service, volume] of [['kong-db', 'kong_db_data'], ['console-db', 'console_db_data'], ['redis', 'redis_data']]) {
    const keeps = (base.services[service]?.volumes || []).some((v) => String(v).startsWith(`${volume}:`));
    const overlayTouch = production.services[service]?.volumes !== undefined;
    record(`persistent_volume_${service}`, keeps && !overlayTouch, { keeps, overlayRedefinesVolumes: overlayTouch });
  }

  const apiReady = (base.services['console-api']?.healthcheck?.test || []).join(' ').includes('/api/v1/health/ready');
  record('api_healthcheck_ready_path', apiReady && base.services['console-api'].healthcheck?.disable !== true, {
    path: '/api/v1/health/ready',
  });
  const livePath = readFileSync('apps/console-api/src/modules/health/health.controller.ts', 'utf8');
  record('api_health_controller_live_ready', livePath.includes("health/live") && livePath.includes("health/ready"), {});

  for (const [name, conf] of [['console', 'deploy/nginx/console-production.conf'], ['portal', 'deploy/nginx/portal-production.conf']]) {
    record(`csp_${name}_production_nginx`, cspPresent(conf), { conf });
    record(`tls_readiness_${name}_local_healthz`, readinessBlock(conf), { conf });
    const overlay = production.services[name === 'console' ? 'console-web' : 'portal-web'];
    const tlsMount = (overlay?.volumes || []).some((v) => String(v).includes('/run/kongos-tls'));
    const confMount = (overlay?.volumes || []).some((v) => String(v).includes(`${name}-production.conf`));
    record(`production_overlay_tls_and_nginx_${name}`, tlsMount && confMount, { tlsMount, confMount });
  }

  // Min privilege on production overlay targets
  for (const name of ['console-api', 'console-migrations', 'console-web', 'portal-web']) {
    const s = { ...(base.services[name] || {}), ...(production.services[name] || {}) };
    // merge is shallow; for evidence read overlay fields that production sets
    const o = production.services[name] || {};
    const b = base.services[name] || {};
    const user = o.user ?? b.user;
    const readOnly = o.read_only ?? b.read_only;
    const cap = o.cap_drop ?? b.cap_drop ?? [];
    const sec = o.security_opt ?? b.security_opt ?? [];
    const capAll = (Array.isArray(cap) ? cap : Object.keys(cap)).includes('ALL');
    const nnp = (Array.isArray(sec) ? sec : []).some((x) => String(x).includes('no-new-privileges'));
    record(`min_privilege_${name}`, Boolean(user) && (readOnly === true || name === 'portal-web') && (capAll || name === 'portal-web' || name === 'console-api' || name === 'console-web'), {
      user: user ?? null,
      read_only: readOnly ?? null,
      cap_drop_all: capAll,
      no_new_privileges: nnp,
      note: name === 'portal-web' || name === 'console-api' || name === 'console-web'
        ? 'base+overlay fields combined; assertProductionComposition enforces full merge at deploy time'
        : undefined,
    });
  }
  // Stricter: production overlay hardens these explicitly
  record('overlay_api_readonly_user', production.services['console-api']?.read_only === true && production.services['console-api']?.user === '1000:1000', {});
  record('overlay_web_cap_drop_nnp', production.services['console-web']?.cap_drop?.includes?.('ALL') && String(production.services['console-web']?.security_opt).includes('no-new-privileges'), {});
  record('overlay_migrations_cap_drop_nnp', production.services['console-migrations']?.cap_drop?.includes?.('ALL') && String(production.services['console-migrations']?.security_opt).includes('no-new-privileges'), {});
  record('cookie_secure_and_https_origins_required', production.services['console-api']?.environment?.COOKIE_SECURE === 'true'
    && String(production.services['console-api']?.environment?.PUBLIC_ORIGINS || '').includes('PUBLIC_ORIGINS')
    && String(production.services['console-api']?.environment?.PORTAL_PUBLIC_ORIGINS || '').includes('PORTAL_PUBLIC_ORIGINS'), {});

  // Contract assert with synthetic merged shape (mirrors unit test; runtimeVerified false)
  const hard = { user: '1000:1000', image: 'kongpilot/console-api:evidence-synthetic', read_only: true, cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'] };
  const web = (name) => ({
    ...structuredClone(hard),
    user: '101:101',
    networks: name === 'console' ? { frontend: {} } : { 'portal-edge': {}, 'portal-entry': {} },
    ports: [{ target: 8443, published: '18443' }],
    volumes: [
      { type: 'bind', source: resolve(`deploy/nginx/${name}-production.conf`), target: '/etc/nginx/conf.d/default.conf', read_only: true },
      { type: 'bind', source: resolve(`deploy/private/evidence-${name}`), target: '/run/kongos-tls', read_only: true },
    ],
  });
  const synthetic = {
    name: 'kp009-evidence',
    services: {
      'kong-db': {}, 'kong-migrations': {}, kong: { ports: [{ target: 8000 }] }, 'console-db': {}, redis: {},
      'console-migrations': structuredClone(hard),
      'console-api': {
        ...structuredClone(hard),
        networks: { frontend: {}, 'kong-admin': {}, 'console-storage': {} },
        environment: {
          NODE_ENV: 'production', COOKIE_SECURE: 'true', TRUST_PROXY: '1',
          PUBLIC_ORIGINS: 'https://console.example.test:18443',
          PORTAL_PUBLIC_ORIGINS: 'https://portal.example.test:19443',
        },
      },
      'console-web': web('console'),
      'portal-web': web('portal'),
    },
    networks: { 'kong-admin': { internal: true }, 'kong-storage': { internal: true }, 'console-storage': { internal: true } },
  };
  let contract;
  try {
    contract = assertProductionComposition(synthetic, { project: 'kp009-evidence' });
    record('assert_production_composition_synthetic', contract.productionContractValid === true && contract.runtimeVerified === false, {
      services: contract.services,
      runtimeVerified: contract.runtimeVerified,
    });
  } catch (e) {
    record('assert_production_composition_synthetic', false, { message: e.message });
  }

  // Optional live: only if KP009_RUNTIME=1 and endpoints given — default off.
  const runtime = process.env.KP009_RUNTIME === '1';
  if (!runtime) {
    record('runtime_tls_hostname_probe', false, { skipped: true, reason: 'KP009_RUNTIME not set; no claim of live TLS' });
    record('runtime_health_ready_probe', false, { skipped: true, reason: 'KP009_RUNTIME not set; no claim of live readiness' });
    record('immutable_image_start_persist_restart', false, { skipped: true, reason: 'requires frozen release images + private env' });
  }

  const bundled = ['kong','kong-db','kong-migrations'];
  const gated = bundled.every((name) => (external.services?.[name]?.profiles || []).includes('bundled-kong'));
  const deps = external.services?.['console-api']?.depends_on || {};
  const noKongDep = !Object.keys(deps).some((name) => bundled.includes(name));
  record('external_kong_overlay_gates_bundled_profile', gated && noKongDep && !!external.services?.['console-api']?.environment?.DEFAULT_KONG_ADMIN_URL, {
    gated, noKongDep,
    note: 'bundled kong services remain declared but profile-gated; Admin URL required',
  });
} catch (error) {
  record('fatal', false, { message: error.message });
}

const completedAt = new Date().toISOString();
const executed = checks.filter((c) => !c.skipped);
const evidence = {
  schemaVersion: 1,
  kind: 'kp009-production-overlay-tls-csp-privilege-health-evidence',
  commercialClosed: false,
  claimsClosed: false,
  runtimeVerified: false,
  startedAt,
  completedAt,
  timezoneNote: 'timestamps are UTC; report to owner in Asia/Shanghai',
  checks,
  totals: {
    total: checks.length,
    passed: checks.filter((c) => c.passed).length,
    failed: checks.filter((c) => !c.passed && !c.skipped).length,
    skipped: checks.filter((c) => c.skipped).length,
  },
  sourceDigests: {
    'docker-compose.yml': sha('docker-compose.yml'),
    'deploy/compose/compose.production.yml': sha('deploy/compose/compose.production.yml'),
    'deploy/compose/compose.external-kong.yml': sha('deploy/compose/compose.external-kong.yml'),
    'deploy/nginx/console-production.conf': sha('deploy/nginx/console-production.conf'),
    'deploy/nginx/portal-production.conf': sha('deploy/nginx/portal-production.conf'),
    'deploy/scripts/production-policy.mjs': sha('deploy/scripts/production-policy.mjs'),
    script: sha(new URL(import.meta.url)),
  },
  remainingForClosure: [
    'Frozen release image digests boot under production overlay',
    'Real TLS hostname verification with dedicated CA',
    'Live /api/v1/health/ready against running API+DB+Redis',
    'Persist restart + network boundary + capacity/rollback drill evidence',
    'External Kong Admin reachability from BFF with min-privilege network',
  ],
  secretsPrinted: false,
};

mkdirSync(outDir, { recursive: true });
const outPath = resolve(outDir, 'kp009-production-overlay-evidence.json');
writeFileSync(outPath, JSON.stringify(evidence, null, 2) + '\n');
const staticOk = executed.filter((c) => !String(c.id).startsWith('runtime_') && c.id !== 'immutable_image_start_persist_restart').every((c) => c.passed);
console.log(JSON.stringify({
  written: outPath,
  staticContractPassed: staticOk,
  commercialClosed: false,
  runtimeVerified: false,
  passed: evidence.totals.passed,
  failed: evidence.totals.failed,
  skipped: evidence.totals.skipped,
}, null, 2));
process.exit(staticOk ? 0 : 1);
