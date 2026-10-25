import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

const apiRequire = createRequire(new URL('../../apps/console-api/package.json', import.meta.url));
const jwt = apiRequire('jsonwebtoken');

// Run against a disposable demo environment. Credentials are never printed.
if (existsSync('.env')) process.loadEnvFile('.env');
const base = (process.env.SECURITY_BASE_URL || 'http://127.0.0.1:8080/api/v1').replace(/\/$/, '');
const checks = [];
const ownedClusters = [];
const ownedSources = [];
let cookie = '';
let csrf = '';

function mergeCookies(current, additions) {
  const values = new Map(current.split('; ').filter(Boolean).map(value => { const index = value.indexOf('='); return [value.slice(0, index), value.slice(index + 1)]; }));
  for (const raw of additions) {
    const value = raw.split(';')[0], index = value.indexOf('=');
    values.set(value.slice(0, index), value.slice(index + 1));
  }
  return [...values].map(([key, value]) => `${key}=${value}`).join('; ');
}

function assert(condition, name) {
  if (!condition) throw new Error(name);
  checks.push({ name, passed: true });
}

async function request(path, method = 'GET', body, options = {}) {
  const headers = { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(cookie && !options.anonymous ? { Cookie: cookie } : {}), ...(csrf && !options.noCsrf && method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}), ...options.headers };
  const response = await fetch(`${base}${path}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual' });
  const text = await response.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = null; }
  return { response, payload, text, status: response.status };
}

try {
  assert((await request('/clusters', 'GET', undefined, { anonymous: true })).status === 401, 'anonymous cluster listing is denied');
  const foreignLogin = await request('/auth/login', 'POST', { username: 'invalid', password: 'invalid' }, { anonymous: true, headers: { Origin: 'https://attacker.invalid' } });
  assert(foreignLogin.status === 403, 'cross-origin login is denied');
  const username = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required for live validation');
  const login = await request('/auth/login', 'POST', { username, password }, { anonymous: true });
  assert(login.status === 201 || login.status === 200, 'bootstrap administrator can log in');
  const setCookies = login.response.headers.getSetCookie();
  assert(setCookies.some(value => value.startsWith('kongos_access=') && /httponly/i.test(value) && /samesite=strict/i.test(value)), 'access cookie is HttpOnly and SameSite=Strict');
  assert(setCookies.some(value => value.startsWith('kongos_refresh=') && /httponly/i.test(value) && /samesite=strict/i.test(value)), 'refresh cookie is HttpOnly and SameSite=Strict');
  assert(!login.text.includes(password) && !login.payload?.data?.accessToken && !login.payload?.data?.refreshToken, 'login JSON does not expose password or JWT/refresh material');
  cookie = setCookies.map(value => value.split(';')[0]).join('; ');
  csrf = login.payload.data.csrfToken;
  assert(typeof csrf === 'string' && csrf.length >= 32, 'login returns a strong session CSRF token');

  const oldAccess = setCookies.find(value => value.startsWith('kongos_access=')).split(';')[0].slice('kongos_access='.length);
  const oldClaims = jwt.decode(oldAccess);
  const expired = jwt.sign({ sid: oldClaims.sid, username: oldClaims.username }, process.env.APP_SECRET, { algorithm: 'HS256', issuer: 'kongos-console', audience: 'kongos-api', subject: oldClaims.sub, expiresIn: -1 });
  cookie = mergeCookies(cookie, [`kongos_access=${expired}`]);
  assert((await request('/auth/me')).status === 401, 'expired access JWT cannot read the session');
  const csrfRecovery = await request('/auth/csrf');
  assert(csrfRecovery.status === 200 && csrfRecovery.payload?.data?.csrfToken === csrf, 'CSRF recovery validates the existing refresh and cookie token after access expiry');
  const wrongRefresh = await request('/auth/refresh', 'POST', {}, { headers: { 'X-CSRF-Token': 'invalid-token' } });
  assert(wrongRefresh.status === 403, 'wrong CSRF cannot rotate refresh material');
  const refreshed = await request('/auth/refresh', 'POST', {});
  assert(refreshed.status < 300 && refreshed.payload?.data?.user?.username === username, 'valid refresh restores the same authenticated actor');
  cookie = mergeCookies(cookie, refreshed.response.headers.getSetCookie());
  assert((await request('/clusters')).status === 200, 'refreshed access cookie can read protected API');

  const csrfDenied = await request('/clusters', 'POST', {}, { noCsrf: true });
  assert(csrfDenied.status === 403, 'cookie-authenticated write without CSRF is denied');
  const csrfWrong = await request('/clusters', 'POST', {}, { headers: { 'X-CSRF-Token': 'invalid-token' } });
  assert(csrfWrong.status === 403, 'cookie-authenticated write with wrong CSRF is denied');

  const forbiddenURL = await request('/clusters', 'POST', { name: 'should-not-exist', admin_url: 'http://169.254.169.254/latest/meta-data/' });
  assert(forbiddenURL.status === 403, 'metadata URL registration is rejected by outbound allowlist');
  const extraProperty = await request('/clusters', 'POST', { name: 'should-not-exist', admin_url: 'http://kong:8001', super_admin: true });
  assert(extraProperty.status === 400, 'unknown write fields cannot be mass-assigned');

  const suffix = randomUUID().slice(0, 8);
  for (const label of ['a', 'b']) {
    const created = await request('/clusters', 'POST', { name: `security-${suffix}-${label}`, admin_url: process.env.DEFAULT_KONG_ADMIN_URL || 'http://kong:8001', environment: 'security-test', execution_mode: 'direct' });
    assert(created.status === 201 || created.status === 200, `security cluster ${label} is created`);
    ownedClusters.push(created.payload.data);
  }
  const clusterA = ownedClusters[0], clusterB = ownedClusters[1];
  const probe = await request(`/clusters/${clusterA.id}/probe`, 'POST');
  assert(probe.status < 300, 'registered Kong cluster probe completes through BFF');
  const detail = await request(`/clusters/${clusterA.id}`);
  assert(detail.payload?.data?.version?.startsWith('1.5.'), 'real cluster version is locked to Kong 1.5.x');
  ownedClusters[0] = detail.payload.data;

  const testSecret = `test-only-${randomUUID()}`;
  const source = await request(`/clusters/${clusterA.id}/data-sources`, 'POST', { name: `security-source-${suffix}`, type: 'prometheus', base_url: 'http://prometheus:9090', enabled: true, auth: { type: 'bearer', token: testSecret } });
  assert(source.status === 201 || source.status === 200, 'data source is registered under its cluster');
  assert(!source.text.includes(testSecret) && !source.payload?.data?.auth_secret && !source.payload?.data?.auth?.token, 'data source response hides connection secret');
  ownedSources.push(source.payload.data);
  const sourceId = source.payload.data.id;
  const foreignRead = await request(`/clusters/${clusterB.id}/data-sources/${sourceId}`);
  assert(foreignRead.status === 404, 'cross-cluster data source IDOR read is rejected');
  const foreignWrite = await request(`/clusters/${clusterB.id}/data-sources/${sourceId}`, 'PATCH', { name: 'foreign-edit', revision: source.payload.data.revision });
  assert(foreignWrite.status === 404, 'cross-cluster data source IDOR write is rejected');
  const foreignProbe = await request(`/clusters/${clusterB.id}/data-sources/${sourceId}/probe`, 'POST');
  assert(foreignProbe.status === 404, 'cross-cluster data source IDOR connection test is rejected');
  const unchanged = await request(`/clusters/${clusterA.id}/data-sources/${sourceId}`);
  assert(unchanged.payload?.data?.name === source.payload.data.name, 'rejected IDOR leaves the original object unchanged');

  const secureHeaders = await request('/clusters');
  assert(secureHeaders.response.headers.get('x-frame-options') === 'DENY' || secureHeaders.response.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"), 'API prevents framing');
  assert((secureHeaders.response.headers.get('x-content-type-options') || '').split(',').some(value => value.trim() === 'nosniff'), 'API sends nosniff security header');

  for (const item of ownedSources) {
    const removed = await request(`/clusters/${item.cluster_id}/data-sources/${item.id}/deactivate`, 'POST', { confirm: true, confirm_name: item.name, revision: item.revision });
    assert(removed.status < 300, 'data source soft deactivation succeeds with confirmation');
  }
  ownedSources.length = 0;
  for (const item of ownedClusters) {
    const removed = await request(`/clusters/${item.id}/deactivate`, 'POST', { confirm: true, confirm_name: item.name, revision: item.revision });
    assert(removed.status < 300, 'cluster soft deactivation succeeds with confirmation');
  }
  ownedClusters.length = 0;
  const logout = await request('/auth/logout', 'POST');
  assert(logout.status < 300, 'logout revokes the session');
  assert((await request('/clusters')).status === 401, 'previous access cookie cannot be reused after logout');
} catch (error) {
  checks.push({ name: error.message, passed: false });
  process.exitCode = 1;
} finally {
  await mkdir('artifacts/M0', { recursive: true });
  const evidence = { performedAt: new Date().toISOString(), kind: 'live-http-security', passed: checks.filter(item => item.passed).length, failed: checks.filter(item => !item.passed).length, checks, disposableObjectsRemaining: ownedClusters.length + ownedSources.length };
  await writeFile('artifacts/M0/security-live.json', `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ kind: evidence.kind, passed: evidence.passed, failed: evidence.failed, disposableObjectsRemaining: evidence.disposableObjectsRemaining }));
}
