import { mkdirSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

// Explicit M4 integration-cluster registration. Uses the normal authenticated,
// CSRF-protected BFF API; never reads or writes either Kong database.
process.loadEnvFile('.env');
const base = 'http://127.0.0.1:8080/api/v1';
const target = 'http://kong-secondary:8001';
const expectedName = 'M4 真实隔离集群';
const expectedEnvironment = 'm4-secondary';
const traces = [];
let cookie = '', csrf = '', result;
async function request(path, method = 'GET', body) {
  const response = await fetch(base + path, {
    method, redirect: 'manual', signal: AbortSignal.timeout(20_000),
    headers: { ...(cookie ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(['GET', 'HEAD'].includes(method) ? {} : { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const payload = await response.json();
  traces.push({ method, path, status: response.status, requestId: payload?.meta?.requestId });
  if (!response.ok) throw new Error(`BFF_HTTP_${response.status}`);
  return { response, data: payload.data };
}
function publicCluster(row) {
  return { id: row.id, name: row.name, environment: row.environment, admin_url: row.admin_url,
    created_at: row.created_at, revision: row.revision, deleted_at: row.deleted_at ?? null };
}
try {
  const login = await request('/auth/login', 'POST', {
    username: process.env.BOOTSTRAP_ADMIN_USERNAME, password: process.env.BOOTSTRAP_ADMIN_PASSWORD,
  });
  cookie = login.response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  csrf = login.data.csrfToken;
  const listed = (await request('/clusters')).data;
  const before = Array.isArray(listed) ? listed : listed.items;
  if (!Array.isArray(before)) throw new Error('CLUSTER_LIST_SHAPE');
  const same = before.filter(c => c.admin_url.replace(/\/$/, '') === target && !c.deleted_at);
  if (same.length > 1 || (same.length && (same[0].name !== expectedName || same[0].environment !== expectedEnvironment))) {
    throw new Error('SECONDARY_REGISTRY_ALREADY_OWNED');
  }
  const created = same.length === 0;
  const secondary = same[0] || (await request('/clusters', 'POST', {
    name: expectedName, environment: expectedEnvironment, admin_url: target,
    labels: ['console:integration-test', 'stage:m4'], execution_mode: 'direct', connection_auth: { type: 'none' },
  })).data;
  await request(`/clusters/${secondary.id}/probe`, 'POST', {});
  const capabilities = (await request(`/clusters/${secondary.id}/capabilities`)).data;
  const primary = before.filter(c => c.admin_url.replace(/\/$/, '') === 'http://kong:8001' && !c.deleted_at)
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))[0];
  if (!primary || primary.id === secondary.id) throw new Error('CANONICAL_PRIMARY_NOT_FOUND');
  result = { observedAt: new Date().toISOString(), kind: 'M4-genuine-dual-cluster-registration',
    allPassed: true, createdThroughAuditedBff: created, reusedExistingApprovedRegistration: !created,
    primary: publicCluster(primary), secondary: publicCluster(secondary),
    secondaryVersion: capabilities.version ?? capabilities.kong_version,
    registryBefore: before.map(publicCluster), knownTestAliasesDeactivatedByThisScript: false,
    databaseAccess: 'console BFF only; no Kong database connection', traces };
} catch (error) {
  result = { observedAt: new Date().toISOString(), kind: 'M4-genuine-dual-cluster-registration',
    allPassed: false, code: /^BFF_HTTP_\d{3}$|^[A-Z_]+$/.test(error.message) ? error.message : 'REGISTRATION_EXCEPTION', traces };
  process.exitCode = 1;
} finally {
  if (cookie) try { await request('/auth/logout', 'POST', {}); } catch { /* Preserve the primary result. */ }
  mkdirSync('artifacts/M4', { recursive: true });
  writeFileSync('artifacts/M4/dual-cluster-registration.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ allPassed: result.allPassed, primaryId: result.primary?.id, secondaryId: result.secondary?.id, code: result.code }));
}
