#!/usr/bin/env node
/**
 * KP-004 live evidence: portal published DELETE fail-fast + ordinary five-root
 * archive→delete→original-ID restore against Kong OSS 1.5.1 + BFF.
 * commercialClosed stays false unless every close condition is met.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const base = (process.env.BFF_BASE_URL || 'http://127.0.0.1:13000').replace(/\/$/, '');
const adminUser = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const kongAdmin = process.env.LIVE_KONG_ADMIN_URL || 'http://127.0.0.1:18001';
const kongProxy = process.env.LIVE_KONG_PROXY_URL || 'http://127.0.0.1:18000';
const upstreamHost = process.env.LIVE_UPSTREAM_HOST || '172.30.0.2';
const upstreamPort = Number(process.env.LIVE_UPSTREAM_PORT || 25678);
const outDir = resolve(process.env.KP004_EVIDENCE_OUT || 'artifacts/M11/runs/20261024-kp004-five-root');
const certPem = process.env.M11_EVIDENCE_CERT_PEM || '';
const keyPem = process.env.M11_EVIDENCE_KEY_PEM || '';
const tag = `m11kp4${Date.now().toString(36)}`;
const startedAt = new Date().toISOString();
const checks = [];
const gaps = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed && !detail.skipped) gaps.push({ id, ...detail });
};
const digest = (v) => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v ?? null)).digest('hex').slice(0, 16);
const entity = (d) => d?.entity ?? d;

if (!adminPass) { console.error('BOOTSTRAP_ADMIN_PASSWORD required'); process.exit(2); }

function mergeCookie(prev, setCookie) {
  const jar = new Map();
  for (const part of String(prev || '').split('; ').filter(Boolean)) {
    const i = part.indexOf('=');
    if (i > 0) jar.set(part.slice(0, i), part.slice(i + 1));
  }
  for (const raw of setCookie || []) {
    const first = String(raw).split(';')[0];
    const i = first.indexOf('=');
    if (i > 0) jar.set(first.slice(0, i), first.slice(i + 1));
  }
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function raw(session, path, method = 'GET', body, { origin, expected } = {}) {
  const write = method !== 'GET' && method !== 'HEAD';
  const headers = {
    Accept: 'application/json',
    ...(session?.cookie ? { Cookie: session.cookie } : {}),
    ...(origin ? { Origin: origin } : {}),
    ...(write ? {
      'Content-Type': 'application/json',
      'X-Idempotency-Key': randomUUID(),
      ...(session?.csrf ? { 'X-CSRF-Token': session.csrf } : {}),
    } : {}),
  };
  const url = path.startsWith('http') ? path : `${base}${path}`;
  let res, text;
  try {
    res = await fetch(url, {
      method, headers, redirect: 'manual', signal: AbortSignal.timeout(120000),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    text = await res.text();
  } catch (e) {
    return { ok: false, status: 0, error: e.message, data: null, text: '', code: undefined };
  }
  if (session) session.cookie = mergeCookie(session.cookie || '', res.headers.getSetCookie?.() || []);
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { /* */ }
  const data = payload?.data ?? payload;
  if (data?.csrfToken && session) session.csrf = data.csrfToken;
  const code = payload?.error?.code || payload?.code || data?.code;
  const ok = expected ? expected.includes(res.status) : res.ok;
  return { ok, status: res.status, data, text: text.slice(0, 1200), code, payload, entryId: data?.entryId || payload?.error?.entryId || payload?.entryId };
}

async function kong(path, method = 'GET', body) {
  const res = await fetch(kongAdmin + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { /* */ }
  return { ok: res.ok, status: res.status, data, text: text.slice(0, 400) };
}

async function cycleRoot(admin, q, rootType, createBody, { nameField = 'name', childFactory } = {}) {
  const create = await raw(admin, q(`entities/${rootType}`), 'POST', createBody, { origin: base, expected: [200, 201] });
  const created = entity(create.data);
  const originalId = created?.id;
  const confirmName = created?.[nameField] || created?.username || created?.name || originalId;
  record(`create_${rootType}`, create.ok && !!originalId, { status: create.status, code: create.code, idDigest: originalId ? digest(originalId) : null });
  if (!originalId) return { ok: false };

  let childMeta = null;
  if (childFactory) {
    childMeta = await childFactory(created);
    record(`create_${rootType}_child`, !!childMeta?.ok, childMeta || {});
  }

  const del = await raw(admin, q(`entities/${rootType}/${originalId}`), 'DELETE', {
    confirmed: true, confirm_name: confirmName, revision: created.revision,
  }, { origin: base, expected: [200, 201, 202] });
  const entryId = del.data?.entryId || del.entryId;
  record(`delete_archive_${rootType}`, del.ok && del.data?.state === 'deleted' && !!entryId, {
    status: del.status, code: del.code, state: del.data?.state, entryIdDigest: entryId ? digest(entryId) : null,
    deletedCount: Array.isArray(del.data?.deleted) ? del.data.deleted.length : null,
  });
  if (!del.ok || !entryId) return { ok: false, originalId, entryId };

  const gone = await kong(`/${rootType}/${originalId}`);
  record(`kong_absent_after_delete_${rootType}`, gone.status === 404, { status: gone.status });

  const restore = await raw(admin, q(`recycle-bin/${entryId}/restore`), 'POST', {
    confirmed: true, confirm_name: confirmName,
  }, { origin: base, expected: [200, 201] });
  record(`restore_${rootType}`, restore.ok && (restore.data?.state === 'restored' || Array.isArray(restore.data?.restored)), {
    status: restore.status, code: restore.code, state: restore.data?.state,
  });

  const back = await kong(`/${rootType}/${originalId}`);
  const sameId = back.ok && back.data?.id === originalId;
  record(`original_id_restored_${rootType}`, sameId, {
    status: back.status, idMatch: sameId, idDigest: digest(originalId),
  });
  return { ok: sameId && del.ok && restore.ok, originalId, entryId, childMeta };
}

async function main() {
  const admin = { cookie: '', csrf: '' };
  const health = await raw(null, '/api/v1/health/ready');
  record('bff_health_ready', health.status === 200, { status: health.status });
  const k = await kong('/');
  record('live_kong_admin_reachable', k.status === 200, { status: k.status });

  const login = await raw(admin, '/api/v1/auth/login', 'POST', { username: adminUser, password: adminPass }, { origin: base, expected: [200, 201] });
  if (login.data?.csrfToken) admin.csrf = login.data.csrfToken;
  record('console_admin_login', login.ok && !!admin.csrf, { status: login.status });
  if (!login.ok) throw new Error('LOGIN_FAILED');

  let clusters = await raw(admin, '/api/v1/clusters');
  let cluster = (clusters.data?.items || clusters.data || []).find?.((c) => String(c.admin_url || '').includes('18001'));
  if (!cluster) {
    const created = await raw(admin, '/api/v1/clusters', 'POST', {
      name: `${tag}-kong15`, environment: 'evidence', admin_url: kongAdmin, proxy_origin: kongProxy,
      execution_mode: 'direct', labels: ['m11-kp004', tag],
    }, { origin: base, expected: [200, 201] });
    cluster = entity(created.data);
    record('cluster_create', created.ok, { status: created.status, code: created.code });
  } else {
    record('cluster_create', true, { reused: true, idDigest: digest(cluster.id) });
  }
  const cid = cluster.id;
  await raw(admin, `/api/v1/clusters/${cid}/probe`, 'POST', {}, { origin: base, expected: [200, 201, 202] });
  const workspaces = await raw(admin, `/api/v1/clusters/${cid}/workspaces`);
  const wid = ((workspaces.data?.items || [])[0] || entity(workspaces.data))?.id;
  record('workspace_resolved', !!wid, { widPresent: !!wid });
  if (!wid) throw new Error('WORKSPACE_REQUIRED');
  const q = (s) => `/api/v1/clusters/${cid}/${s}${s.includes('?') ? '&' : '?'}workspaceId=${wid}`;

  // --- A) Portal published DELETE fail-fast (must NOT 503 RECYCLE_DELETE_INCOMPLETE) ---
  const pubSvcBody = { name: `${tag}-pub-svc`, host: upstreamHost, port: upstreamPort, protocol: 'http', tags: [tag, 'm11-kp004-pub'] };
  const pubSvcRes = await raw(admin, q('entities/services'), 'POST', pubSvcBody, { origin: base, expected: [200, 201] });
  const pubSvc = entity(pubSvcRes.data);
  record('portal_fixture_service', pubSvcRes.ok && !!pubSvc?.id, { status: pubSvcRes.status, code: pubSvcRes.code });
  let publication = null;
  if (pubSvc?.id) {
    const routeRes = await raw(admin, q('entities/routes'), 'POST', {
      name: `${tag}-pub-route`, paths: [`/m11/${tag}/pub`], protocols: ['http'], service: { id: pubSvc.id }, tags: [tag],
    }, { origin: base, expected: [200, 201] });
    record('portal_fixture_route', routeRes.ok, { status: routeRes.status, code: routeRes.code });
    await raw(admin, q('portal/settings'), 'POST', {
      slug: `${tag}-portal`, name: `${tag} KP004 Portal`, published: true, registrationEnabled: false, publicProxyOrigin: kongProxy,
    }, { origin: base, expected: [200, 201, 409] });
    const pubRes = await raw(admin, q('portal/publications'), 'POST', {
      slug: `${tag}-api`, name: `${tag} Pub`, category: '证据', serviceId: pubSvc.id,
      document: { openapi: '3.0.3', info: { title: 't', version: '1.0.0' }, paths: { [`/m11/${tag}/pub`]: { get: { responses: { 200: { description: 'ok' } } } } } },
    }, { origin: base, expected: [200, 201] });
    publication = entity(pubRes.data);
    record('portal_fixture_publication', pubRes.ok && !!publication?.id, { status: pubRes.status, code: pubRes.code });
    if (publication?.id) {
      const got = entity((await raw(admin, q(`portal/publications/${publication.id}`))).data);
      const pub = await raw(admin, q(`portal/publications/${publication.id}/publish`), 'POST', {
        revision: got.revision ?? publication.revision, confirmed: true, confirm_name: got.name || publication.name,
      }, { origin: base, expected: [200, 201] });
      publication = entity((await raw(admin, q(`portal/publications/${publication.id}`))).data) || publication;
      record('portal_fixture_publish', pub.ok && publication?.status === 'published', {
        status: pub.status, code: pub.code, publicationStatus: publication?.status,
      });
    }
  }

  if (pubSvc?.id && publication?.status === 'published') {
    const blocked = await raw(admin, q(`entities/services/${pubSvc.id}`), 'DELETE', {
      confirmed: true, confirm_name: pubSvc.name, revision: pubSvc.revision,
    }, { origin: base, expected: [403, 409, 400] });
    const code = blocked.code;
    const failFast = blocked.status === 403 && code === 'PORTAL_PUBLISHED_OBJECT';
    const notIncomplete = code !== 'RECYCLE_DELETE_INCOMPLETE' && blocked.status !== 503;
    record('kp004_portal_published_delete_failfast', failFast && notIncomplete, {
      status: blocked.status, code, failFast, notIncomplete, textDigest: digest(blocked.text),
    });
    // Confirm Kong objects still present (no partial delete)
    const still = await kong(`/services/${pubSvc.id}`);
    record('kp004_portal_service_intact_after_refuse', still.ok && still.data?.id === pubSvc.id, { status: still.status });
  } else {
    record('kp004_portal_published_delete_failfast', false, { reason: 'publication_not_ready' });
    record('kp004_portal_service_intact_after_refuse', false, { skipped: true, reason: 'publication_not_ready' });
  }

  // --- B) Ordinary five-root cycles (no portal) ---
  const results = {};

  // services (+ optional route child deleted with graph)
  results.services = await cycleRoot(admin, q, 'services', {
    name: `${tag}-svc`, host: upstreamHost, port: upstreamPort, protocol: 'http', tags: [tag, 'm11-kp004'],
  }, {
    childFactory: async (svc) => {
      const r = await raw(admin, q('entities/routes'), 'POST', {
        name: `${tag}-svc-route`, paths: [`/m11/${tag}/svc`], protocols: ['http'], service: { id: svc.id }, tags: [tag],
      }, { origin: base, expected: [200, 201] });
      return { ok: r.ok, status: r.status, code: r.code, routeIdDigest: entity(r.data)?.id ? digest(entity(r.data).id) : null };
    },
  });

  // routes (standalone route needs service — create service as shared parent then recycle route only)
  {
    const parent = await raw(admin, q('entities/services'), 'POST', {
      name: `${tag}-route-parent`, host: upstreamHost, port: upstreamPort, protocol: 'http', tags: [tag],
    }, { origin: base, expected: [200, 201] });
    const parentSvc = entity(parent.data);
    record('create_routes_parent_service', parent.ok && !!parentSvc?.id, { status: parent.status });
    if (parentSvc?.id) {
      results.routes = await cycleRoot(admin, q, 'routes', {
        name: `${tag}-route`, paths: [`/m11/${tag}/route-only`], protocols: ['http'], service: { id: parentSvc.id }, tags: [tag],
      });
    } else {
      results.routes = { ok: false };
      record('create_routes', false, { reason: 'parent_missing' });
    }
  }

  // consumers
  results.consumers = await cycleRoot(admin, q, 'consumers', {
    username: `${tag}-consumer`, tags: [tag, 'm11-kp004'],
  }, { nameField: 'username' });

  // upstreams (+ target child)
  results.upstreams = await cycleRoot(admin, q, 'upstreams', {
    name: `${tag}-up`, tags: [tag, 'm11-kp004'],
  }, {
    childFactory: async (up) => {
      const t = await raw(admin, q(`upstreams/${up.id}/targets`), 'POST', {
        target: `${upstreamHost}:${upstreamPort}`, weight: 100, tags: [tag],
      }, { origin: base, expected: [200, 201] });
      return { ok: t.ok, status: t.status, code: t.code, targetIdDigest: entity(t.data)?.id ? digest(entity(t.data).id) : null };
    },
  });

  // certificates (+ sni)
  if (certPem && keyPem) {
    results.certificates = await cycleRoot(admin, q, 'certificates', {
      cert: certPem.replace(/\\n/g, '\n'),
      key: keyPem.replace(/\\n/g, '\n'),
      snis: [`${tag}.evidence.local`],
      tags: [tag, 'm11-kp004'],
    }, { nameField: 'id' });
  } else {
    results.certificates = { ok: false };
    record('create_certificates', false, { reason: 'cert_pem_missing' });
  }

  const fiveOk = ['services', 'routes', 'consumers', 'upstreams', 'certificates'].every((k) => results[k]?.ok);
  record('kp004_five_root_archive_delete_restore_all', fiveOk, {
    roots: Object.fromEntries(Object.entries(results).map(([k, v]) => [k, !!v?.ok])),
  });

  const portalFix = checks.find((c) => c.id === 'kp004_portal_published_delete_failfast')?.passed;
  const commercialClosed = false; // checkpoint close conditions not fully met (workflow/三票/凭证代理等仍缺)
  const evidence = {
    schemaVersion: 1,
    kind: 'kp004-five-root-recycle-live-kong-evidence',
    commercialClosed,
    claimsClosed: false,
    portalPublishedDeleteFailFast: !!portalFix,
    fiveRootOrdinaryCycleVerified: fiveOk,
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'timestamps UTC; report Asia/Shanghai',
    stack: {
      bffBase: base, kongAdmin, kongProxy, upstream: `${upstreamHost}:${upstreamPort}`,
      clusterIdDigest: digest(cid), workspaceIdDigest: digest(wid), tag,
      bffImage: process.env.BFF_IMAGE_LABEL || 'kpapi-test:m11-portal-recycle-fix',
    },
    checks,
    totals: {
      total: checks.length,
      passed: checks.filter((c) => c.passed).length,
      failed: checks.filter((c) => !c.passed && !c.skipped).length,
      skipped: checks.filter((c) => c.skipped).length,
    },
    remainingGaps: gaps.map((g) => g.id),
    remainingForClosure: [
      '六类凭证恢复后代理正负认证与 OAuth2 HTTPS token 链',
      '真实五类全图经新意图/三票/执行与回读（本证据为 BFF 直接 archiveAndDelete 路径）',
      'HMAC/ACL live partial + fresh witness 最终验收',
      'KP-009 全 overlay+TLS / 浏览器全链 / 容量与回退',
    ],
    secretsPrinted: false,
  };
  mkdirSync(outDir, { recursive: true });
  const out = resolve(outDir, 'kp004-five-root-recycle-evidence.json');
  writeFileSync(out, JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify({ out, totals: evidence.totals, commercialClosed, fiveRootOrdinaryCycleVerified: fiveOk, portalPublishedDeleteFailFast: !!portalFix }, null, 2));
  if (!portalFix || !fiveOk) process.exitCode = 1;
}

main().catch((e) => { console.error(e); process.exit(2); });
