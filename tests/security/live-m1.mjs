import { existsSync, mkdtempSync, readFileSync, chmodSync, rmSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { findSecretArtifacts } from './check-artifacts.mjs';

if (existsSync('.env')) process.loadEnvFile('.env');
const base = (process.env.SECURITY_BASE_URL || 'http://127.0.0.1:8080/api/v1').replace(/\/$/, '');
const proxy = (process.env.SECURITY_PROXY_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const suffix = randomUUID().slice(0, 8), tag = `m1-security-${suffix}`;
const checks = [], secrets = [];
let cookie = '', csrf = '', clusterId;
let temporaryDirectory;
let lastRequestAt = 0;

function check(condition, name, details = {}) {
  if (!condition) throw new Error(name);
  checks.push({ name, passed: true, ...details });
}

async function request(path, method = 'GET', body, extraHeaders = {}) {
  // This is a functional gate, paced to respect the default per-cluster
  // 120 Admin requests/second even when a single BFF call traverses a graph.
  const pause = 60 - (Date.now() - lastRequestAt);
  if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
  lastRequestAt = Date.now();
  const headers = { ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(['GET', 'HEAD'].includes(method) ? {} : { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }), ...extraHeaders };
  const response = await fetch(`${base}${path}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual' });
  const text = await response.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = null; }
  return { status: response.status, payload, data: payload?.data, text, response };
}

function ok(response, name) {
  const errorCode = response.payload?.error?.code;
  const safeCode = typeof errorCode === 'string' && /^[A-Z_\d]{1,80}$/.test(errorCode) ? errorCode : undefined;
  check(response.status >= 200 && response.status < 300, `${name}: HTTP ${response.status}${safeCode ? ` (${safeCode})` : ''}`, { requestId: response.payload?.meta?.requestId });
  return response.data;
}

function entity(data) {
  if (data?.entity && typeof data.entity === 'object') return data.entity;
  if (data?.result && typeof data.result === 'object') return entity(data.result);
  return data;
}

function resource(type, id) { return `/clusters/${clusterId}/entities/${type}${id ? `/${id}` : ''}`; }
async function create(type, body) {
  const result = await request(resource(type), 'POST', body);
  const value = entity(ok(result, `${type} create`));
  check(typeof value?.id === 'string', `${type} returns a real Kong ID`);
  return value;
}
async function get(type, id) { return entity(ok(await request(resource(type, id)), `${type} read`)); }
async function update(type, id, body) { return entity(ok(await request(resource(type, id), 'PATCH', body), `${type} update`)); }
function confirmation(value) { return String(value.name || value.username || value.target || value.id); }

async function recycle(type, value) {
  await new Promise(resolve => setTimeout(resolve, 300));
  ok(await request(resource(type, value.id), 'DELETE', { confirmed: true, confirm_name: confirmation(value) }), `${type} archive and delete`);
  const listing = ok(await request(`/clusters/${clusterId}/recycle-bin?size=100`), 'recycle bin list');
  const entry = listing.items?.find(item => item.original_id === value.id && !['restored', 'purged'].includes(item.state));
  check(Boolean(entry), `${type} deletion has a recycle entry`);
  const preview = ok(await request(`/clusters/${clusterId}/recycle-bin/${entry.id}`), `${type} recycle graph preview`);
  check(Boolean(preview.graph), `${type} recovery graph is available`);
  check(!secrets.some(secret => JSON.stringify(preview).includes(secret)), `${type} recycle graph preview hides secrets`);
  const missing = await request(resource(type, value.id));
  check(missing.status === 404, `${type} deleted object is absent from Kong`);
  return entry;
}

async function restore(entry, type, originalId) {
  await new Promise(resolve => setTimeout(resolve, 300));
  const result = ok(await request(`/clusters/${clusterId}/recycle-bin/${entry.id}/restore`, 'POST', { confirmed: true, confirm_name: entry.root_name }), `${type} restore`);
  check(result.state === 'restored', `${type} restore reaches restored state`);
  const value = await get(type, originalId);
  check(value.id === originalId, `${type} restores original ID`);
  return { value, result };
}

async function waitProxy(path, expected, headers = {}) {
  const deadline = Date.now() + 18_000;
  let lastStatus = 0;
  while (Date.now() < deadline) {
    const response = await fetch(`${proxy}${path}`, { headers, redirect: 'manual' });
    lastStatus = response.status;
    if (lastStatus === expected) return response;
    await response.arrayBuffer();
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error(`proxy expectation ${expected} not reached (last HTTP ${lastStatus})`);
}

try {
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required');
  secrets.push(password, process.env.APP_SECRET, process.env.CONSOLE_ENCRYPTION_KEY);
  const login = await request('/auth/login', 'POST', { username: process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password });
  ok(login, 'administrator login');
  cookie = login.response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  csrf = login.data.csrfToken;
  const clusters = ok(await request('/clusters'), 'registered cluster listing');
  const cluster = clusters.find(item => item.version?.startsWith('1.5.') && item.execution_mode === 'direct' && item.labels?.includes('bootstrap'));
  check(Boolean(cluster), 'healthy Kong 1.5 direct cluster is available');
  clusterId = cluster.id;
  const liveCapabilities = ok(await request(`/clusters/${clusterId}/probe`, 'POST'), 'fresh real Kong capability probe');
  check(liveCapabilities.version === '1.5.1', 'real gateway reports Kong OSS 1.5.1 for this verification');

  for (const type of ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis']) {
    const schema = ok(await request(`/clusters/${clusterId}/schemas/${type}`), `${type} live schema`);
    check(Array.isArray(schema.fields || schema.schema?.fields), `${type} schema contains live Kong fields`);
  }
  const incompatible = await request(resource('services'), 'POST', { name: `${tag}-invalid`, host: 'echo-upstream', tls_verify: true });
  check(incompatible.status === 400, 'unsupported Service TLS field is rejected on Kong 1.5');
  const vaults = await request(resource('vaults'));
  check(vaults.status === 400 || vaults.status === 404, 'unsupported vault entity is rejected');

  temporaryDirectory = mkdtempSync(join(tmpdir(), 'kongos-m1-'));
  const keyPath = join(temporaryDirectory, 'private.pem'), certPath = join(temporaryDirectory, 'certificate.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '30', '-subj', `/CN=${tag}.invalid`, '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' });
  chmodSync(keyPath, 0o600);
  const privateKey = readFileSync(keyPath, 'utf8'), certificate = readFileSync(certPath, 'utf8');
  secrets.push(privateKey);
  const cert = await create('certificates', { cert: certificate, key: privateKey, tags: [tag] });
  check(!JSON.stringify(cert).includes(privateKey), 'certificate create response hides the private key');
  const ca = await create('ca_certificates', { cert: certificate, tags: [tag] });
  let sni = await create('snis', { name: `${tag}.invalid`, certificate: { id: cert.id }, tags: [tag] });
  sni = await update('snis', sni.id, { name: `${tag}-updated.invalid` });
  check((await get('snis', sni.id)).name === sni.name, 'SNI update matches Kong state');
  await update('certificates', cert.id, { tags: [tag, 'updated'] });
  await update('ca_certificates', ca.id, { tags: [tag, 'updated'] });
  const certificateDetails = ok(await request(resource('certificates', cert.id)), 'certificate expiration inspection');
  check(certificateDetails.certificate?.key_matches === true && certificateDetails.certificate?.days_remaining >= 29 && certificateDetails.certificate?.expired === false, 'certificate PEM expiry and matching private key are validated');

  let upstream = await create('upstreams', { name: `${tag}.upstream`, algorithm: 'round-robin', tags: [tag] });
  upstream = await update('upstreams', upstream.id, { algorithm: 'consistent-hashing', hash_on: 'header', hash_on_header: 'X-Request-Id' });
  const targetPath = `/clusters/${clusterId}/upstreams/${upstream.id}/targets`;
  let target = entity(ok(await request(targetPath, 'POST', { target: 'echo-upstream:8081', weight: 100, tags: [tag] }), 'target create'));
  check(typeof target?.id === 'string', 'target receives Kong history ID');
  // Kong 1.5 prunes all history when its final active target becomes zero. A
  // second active fixture keeps the DAO below its 90% history-pruning threshold.
  ok(await request(targetPath, 'POST', { target: 'echo-upstream:8082', weight: 1, tags: [tag] }), 'second Target keeps history observable');
  const changedTarget = entity(ok(await request(`${targetPath}/${target.id}`, 'PATCH', { weight: 80 }), 'target weight update'));
  if (changedTarget?.id) target = changedTarget;
  const targetList = ok(await request(targetPath), 'target effective list');
  check(targetList.items?.some(item => item.target === 'echo-upstream:8081' && item.weight === 80), 'effective target weight is updated');
  for (const state of ['unhealthy', 'healthy']) {
    ok(await request(`${targetPath}/${target.id}/${state}`, 'POST'), `target manual ${state}`);
  }
  ok(await request(`/clusters/${clusterId}/upstreams/${upstream.id}/health`), 'upstream real health');
  const otherUpstream = await create('upstreams', { name: `${tag}-other-upstream`, tags: [tag] });
  for (const [method, tail, body] of [['PATCH', '', { weight: 1 }], ['POST', '/unhealthy', undefined], ['DELETE', '', { confirmed: true, confirm_name: target.target }]]) {
    const denied = await request(`/clusters/${clusterId}/upstreams/${otherUpstream.id}/targets/${target.id}${tail}`, method, body);
    check(denied.status === 404, `Target ${method}${tail} cannot use another Upstream parent ID`);
  }
  const targetsAfterIdor = ok(await request(targetPath), 'Target owner integrity after IDOR attempts');
  check(targetsAfterIdor.items?.some(item => item.id === target.id && item.weight === 80), 'wrong-parent Target writes leave its original effective state intact');

  let service = await create('services', { name: `${tag}-service`, protocol: 'http', host: 'echo-upstream', port: 8081, connect_timeout: 3000, write_timeout: 3000, read_timeout: 3000, tags: [tag] });
  service = await update('services', service.id, { name: `${tag}-service-updated`, retries: 1 });
  const basePath = `/m1/${suffix}/base`;
  let route = await create('routes', { name: `${tag}-route`, service: { id: service.id }, protocols: ['http'], paths: [basePath], strip_path: true, tags: [tag] });
  route = await update('routes', route.id, { regex_priority: 1 });
  check((await get('routes', route.id)).regex_priority === 1, 'Route update matches real configuration');
  const servicePlugin = await create('plugins', { name: 'correlation-id', service: { id: service.id }, config: { header_name: 'X-M1-Request-Id' }, tags: [tag] });
  await waitProxy(`${basePath}/echo`, 200);
  check(true, 'real Service and Route proxy to the isolated echo upstream');
  // Kong 1.5 permits client_certificate only when the Service protocol is HTTPS.
  await update('services', service.id, { protocol: 'https', client_certificate: { id: cert.id } });
  const inUseCertificate = await request(resource('certificates', cert.id), 'DELETE', { confirmed: true, confirm_name: cert.id });
  check(inUseCertificate.status === 409 && inUseCertificate.payload?.error?.code === 'CERTIFICATE_IN_USE', 'certificate used by a live Service is protected from deletion');
  check((await get('certificates', cert.id)).id === cert.id && (await get('services', service.id)).client_certificate?.id === cert.id, 'rejected certificate deletion preserves both certificate and Service reference');
  await update('services', service.id, { protocol: 'http', client_certificate: null });

  let consumer = await create('consumers', { username: `${tag}-consumer`, custom_id: tag, tags: [tag] });
  consumer = await update('consumers', consumer.id, { custom_id: `${tag}-updated` });
  const key = `m1-key-${randomUUID()}`, basicPassword = `m1-basic-${randomUUID()}`, jwtSecret = `m1-jwt-${randomUUID()}`, oauthSecret = `m1-oauth-${randomUUID()}`, hmacSecret = `m1-hmac-${randomUUID()}`;
  secrets.push(key, basicPassword, jwtSecret, oauthSecret, hmacSecret);
  const inputs = {
    'key-auth': { key },
    'basic-auth': { username: `${tag}-basic`, password: basicPassword },
    jwt: { key: `${tag}-jwt`, secret: jwtSecret, algorithm: 'HS256' },
    oauth2: { name: `${tag}-application`, client_id: `${tag}-client`, client_secret: oauthSecret, redirect_uris: ['https://example.invalid/callback'] },
    'hmac-auth': { username: `${tag}-hmac`, secret: hmacSecret },
    acls: { group: 'm1-test-group' },
  };
  const credentials = {};
  for (const [kind, input] of Object.entries(inputs)) {
    const path = `/clusters/${clusterId}/consumers/${consumer.id}/credentials/${kind}`;
    const response = await request(path, 'POST', { ...input, tags: [tag] });
    credentials[kind] = entity(ok(response, `${kind} credential create`));
    check(Boolean(credentials[kind]?.id), `${kind} credential has real ID`);
    const listed = await request(path);
    ok(listed, `${kind} credential list`);
    check(!secrets.some(secret => listed.text.includes(secret)), `${kind} credential list is masked`);
    ok(await request(`${path}/${credentials[kind].id}`, 'PATCH', { tags: [tag, 'updated'] }), `${kind} credential update`);
  }
  const otherConsumer = await create('consumers', { username: `${tag}-other-consumer`, tags: [tag] });
  const wrongCredentialPath = `/clusters/${clusterId}/consumers/${otherConsumer.id}/credentials/key-auth/${credentials['key-auth'].id}`;
  for (const [method, body] of [['GET', undefined], ['PATCH', { tags: ['unauthorized-change'] }], ['DELETE', { confirmed: true, confirm_name: credentials['key-auth'].id }]]) {
    check((await request(wrongCredentialPath, method, body)).status === 404, `credential ${method} cannot use another Consumer parent ID`);
  }
  const credentialAfterIdor = entity(ok(await request(`/clusters/${clusterId}/consumers/${consumer.id}/credentials/key-auth/${credentials['key-auth'].id}`), 'credential owner integrity after IDOR attempts'));
  check(credentialAfterIdor.id === credentials['key-auth'].id && credentialAfterIdor.tags?.includes('updated') && !credentialAfterIdor.tags?.includes('unauthorized-change'), 'wrong-parent credential writes leave its original state intact');
  const consumerPlugin = await create('plugins', { name: 'rate-limiting', consumer: { id: consumer.id }, config: { minute: 1000, policy: 'local' }, tags: [tag] });
  const keyPathProxy = `/m1/${suffix}/key`, basicPathProxy = `/m1/${suffix}/basic`;
  const keyRoute = await create('routes', { name: `${tag}-key-route`, service: { id: service.id }, protocols: ['http'], paths: [keyPathProxy], strip_path: true, tags: [tag] });
  const basicRoute = await create('routes', { name: `${tag}-basic-route`, service: { id: service.id }, protocols: ['http'], paths: [basicPathProxy], strip_path: true, tags: [tag] });
  await create('plugins', { name: 'key-auth', route: { id: keyRoute.id }, config: { key_names: ['apikey'], hide_credentials: true }, tags: [tag] });
  await create('plugins', { name: 'basic-auth', route: { id: basicRoute.id }, config: { hide_credentials: true }, tags: [tag] });
  const basicHeader = `Basic ${Buffer.from(`${inputs['basic-auth'].username}:${basicPassword}`).toString('base64')}`;
  secrets.push(basicHeader);
  await waitProxy(`${keyPathProxy}/echo`, 401);
  await waitProxy(`${keyPathProxy}/echo`, 200, { apikey: key });
  await waitProxy(`${basicPathProxy}/echo`, 200, { Authorization: basicHeader });
  check(true, 'created key-auth and basic-auth credentials are usable through real proxy');

  const pluginPath = `/m1/${suffix}/plugin`;
  const pluginRoute = await create('routes', { name: `${tag}-plugin-route`, service: { id: service.id }, protocols: ['http'], paths: [pluginPath], strip_path: true, tags: [tag] });
  let plugin = await create('plugins', { name: 'request-termination', route: { id: pluginRoute.id }, config: { status_code: 418, message: 'M1 fixture' }, tags: [tag] });
  plugin = await update('plugins', plugin.id, { config: { status_code: 419, message: 'M1 updated' } });
  await waitProxy(`${pluginPath}/echo`, 419);
  plugin = await update('plugins', plugin.id, { enabled: false });
  await waitProxy(`${pluginPath}/echo`, 200);
  plugin = await update('plugins', plugin.id, { enabled: true });
  await waitProxy(`${pluginPath}/echo`, 419);
  check(true, 'plugin configuration and enable/disable affect real proxy');

  const pageTag = `${tag}-pagination`;
  for (let index = 0; index < 3; index++) await create('services', { name: `${tag}-page-${index}`, host: 'echo-upstream', port: 8081, tags: [pageTag] });
  const first = ok(await request(`${resource('services')}?size=2&tags=${pageTag}`), 'real cursor first page');
  check(first.items?.length === 2 && typeof first.nextCursor === 'string', 'real Kong pagination returns two rows and cursor');
  const second = ok(await request(`${resource('services')}?size=2&tags=${pageTag}&cursor=${encodeURIComponent(first.nextCursor)}`), 'real cursor next page');
  check(second.items?.length === 1 && !first.items.some(left => second.items.some(right => left.id === right.id)), 'next cursor has one new row with preserved filter');
  const badCursor = await request(`${resource('services')}?size=2&tags=${pageTag}&cursor=${encodeURIComponent(`${first.nextCursor}x`)}`);
  check(badCursor.status === 400, 'tampered cursor is rejected');
  const differentFilter = await request(`${resource('services')}?size=2&tags=${tag}&cursor=${encodeURIComponent(first.nextCursor)}`);
  check(differentFilter.status === 400, 'cursor cannot be replayed under another filter');

  const idempotencyKey = randomUUID(), idempotentInput = { name: `${tag}-idempotent`, host: 'echo-upstream', port: 8081, tags: [tag] };
  const firstCreate = entity(ok(await request(resource('services'), 'POST', idempotentInput, { 'X-Idempotency-Key': idempotencyKey }), 'idempotent Service first create'));
  const replayedCreate = entity(ok(await request(resource('services'), 'POST', idempotentInput, { 'X-Idempotency-Key': idempotencyKey }), 'idempotent Service replay'));
  check(replayedCreate.id === firstCreate.id, 'replayed idempotency key returns the same Kong object');
  const alteredReplay = await request(resource('services'), 'POST', { ...idempotentInput, name: `${tag}-different` }, { 'X-Idempotency-Key': idempotencyKey });
  check(alteredReplay.status === 409, 'idempotency key cannot be reused with a different payload');

  const deniedDelete = await request(resource('services', service.id), 'DELETE', { confirmed: false, confirm_name: service.name });
  check(deniedDelete.status === 400, 'delete without explicit confirmation is denied');
  check((await get('services', service.id)).id === service.id, 'denied deletion leaves the Service intact');

  const pluginEntry = await recycle('plugins', plugin);
  await waitProxy(`${pluginPath}/echo`, 200);
  await restore(pluginEntry, 'plugins', plugin.id);
  await waitProxy(`${pluginPath}/echo`, 419);
  check(true, 'Plugin delete and restore preserve its real proxy behavior');

  const consumerEntry = await recycle('consumers', consumer);
  await waitProxy(`${keyPathProxy}/echo`, 401, { apikey: key });
  await waitProxy(`${basicPathProxy}/echo`, 401, { Authorization: basicHeader });
  await restore(consumerEntry, 'consumers', consumer.id);
  for (const [kind, credential] of Object.entries(credentials)) {
    const listed = ok(await request(`/clusters/${clusterId}/consumers/${consumer.id}/credentials/${kind}`), `${kind} restored credential list`);
    check(listed.items?.some(item => item.id === credential.id), `${kind} restores original credential ID`);
  }
  check((await get('plugins', consumerPlugin.id)).consumer?.id === consumer.id, 'consumer-bound Plugin is restored after Consumer');
  await waitProxy(`${keyPathProxy}/echo`, 200, { apikey: key });
  await waitProxy(`${basicPathProxy}/echo`, 200, { Authorization: basicHeader });
  check(true, 'Consumer restore keeps original key-auth and basic-auth credentials usable');

  const serviceEntry = await recycle('services', service);
  await waitProxy(`${basePath}/echo`, 404);
  await restore(serviceEntry, 'services', service.id);
  check((await get('routes', route.id)).service?.id === service.id, 'Service restore restores Route relation');
  check((await get('plugins', servicePlugin.id)).service?.id === service.id, 'Service restore restores bound Plugin');
  await waitProxy(`${basePath}/echo`, 200);
  await waitProxy(`${keyPathProxy}/echo`, 200, { apikey: key });
  check(true, 'Service graph restore makes related proxy routes and credentials usable');

  const upstreamEntry = await recycle('upstreams', upstream);
  const restoredUpstream = await restore(upstreamEntry, 'upstreams', upstream.id);
  const restoredTargets = ok(await request(targetPath), 'restored target effective list');
  check(restoredTargets.items?.some(item => item.target === 'echo-upstream:8081' && item.weight === 80), 'Upstream restore preserves effective Target and weight');
  const targetMapping = restoredUpstream.result.restored?.find(item => item.type === 'targets');
  check(Boolean(targetMapping?.restoredId), 'Target restore reports its effective history ID');

  const effectiveTarget = restoredTargets.items.find(item => item.target === 'echo-upstream:8081' && item.weight === 80);
  ok(await request(`${targetPath}/${effectiveTarget.id}`, 'DELETE', { confirmed: true, confirm_name: effectiveTarget.target }), 'Target archive and zero-weight deletion');
  const removedTargets = ok(await request(targetPath), 'Target list after deletion');
  check(!removedTargets.items?.some(item => item.target === effectiveTarget.target && item.weight > 0), 'Target deletion removes its effective positive-weight entry');
  const probeCode = `const r=await fetch(process.env.DEFAULT_KONG_ADMIN_URL+'/upstreams/'+${JSON.stringify(upstream.id)}+'/targets/all?size=100');const j=await r.json();if(!r.ok)process.exit(1);console.log(JSON.stringify({zeroWeightRecords:j.data.filter(t=>t.target==='echo-upstream:8081'&&t.weight===0).length}));`;
  const historySummary = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', probeCode], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  check(historySummary.zeroWeightRecords >= 1, 'Kong 1.5 Target deletion appends a zero-weight history record', { zeroWeightRecords: historySummary.zeroWeightRecords, evidenceSource: 'backend-network bounded read-only Admin API probe' });
  const targetEntries = ok(await request(`/clusters/${clusterId}/recycle-bin?size=100`), 'Target recycle entry listing');
  const targetEntry = targetEntries.items.find(item => item.original_id === effectiveTarget.id && !['restored', 'purged'].includes(item.state));
  check(Boolean(targetEntry), 'Target zero-weight deletion has an encrypted recovery entry');
  const targetRestoration = ok(await request(`/clusters/${clusterId}/recycle-bin/${targetEntry.id}/restore`, 'POST', { confirmed: true, confirm_name: targetEntry.root_name }), 'individual Target restore');
  check(targetRestoration.state === 'restored', 'individual Target restore completes');
  const targetAfterRestore = ok(await request(targetPath), 'individual Target effective list after restore');
  const restoredEffective = targetAfterRestore.items.find(item => item.target === effectiveTarget.target && item.weight === 80);
  check(Boolean(restoredEffective) && restoredEffective.id !== effectiveTarget.id, 'Target recovery appends a new effective history ID with original weight');

  const certEntry = await recycle('certificates', cert);
  check((await request(resource('snis', sni.id))).status === 404, 'Certificate deletion captures and removes dependent SNI');
  await restore(certEntry, 'certificates', cert.id);
  check((await get('snis', sni.id)).certificate?.id === cert.id, 'Certificate restore rebuilds SNI with original ID and relation');
  check((await get('ca_certificates', ca.id)).cert === certificate, 'CA certificate read matches uploaded public certificate');

  for (const [type, value] of [['routes', route], ['snis', sni], ['ca_certificates', ca]]) {
    const entry = await recycle(type, value);
    await restore(entry, type, value.id);
  }
  check(true, 'all eight core entity types complete explicit CRUD and original-ID recovery');

  for (const [kind, credential] of Object.entries(credentials)) {
    const path = `/clusters/${clusterId}/consumers/${consumer.id}/credentials/${kind}/${credential.id}`;
    const name = confirmation(credential);
    ok(await request(path, 'DELETE', { confirmed: true, confirm_name: name }), `${kind} credential archive and delete`);
    check((await request(path)).status === 404, `${kind} credential deletion removes its nested entity`);
    const listing = ok(await request(`/clusters/${clusterId}/recycle-bin?size=100`), `${kind} credential recycle list`);
    const entry = listing.items?.find(item => item.original_id === credential.id && !['restored', 'purged'].includes(item.state));
    check(Boolean(entry), `${kind} credential has its own recycle entry`);
    const result = ok(await request(`/clusters/${clusterId}/recycle-bin/${entry.id}/restore`, 'POST', { confirmed: true, confirm_name: entry.root_name }), `${kind} credential restore`);
    check(result.state === 'restored', `${kind} credential recovery is complete`);
    const restored = entity(ok(await request(path), `${kind} restored credential detail`));
    check(restored.id === credential.id, `${kind} nested credential keeps its original ID`);
  }
  await waitProxy(`${keyPathProxy}/echo`, 200, { apikey: key });
  await waitProxy(`${basicPathProxy}/echo`, 200, { Authorization: basicHeader });
  check(true, 'individual key-auth and basic-auth credential recovery also preserves proxy access');

  const approvalCluster = ok(await request('/clusters', 'POST', { name: `${tag}-approval`, environment: 'security-test', admin_url: cluster.admin_url, execution_mode: 'approval' }), 'approval cluster registration');
  ok(await request(`/clusters/${approvalCluster.id}/probe`, 'POST'), 'approval cluster real probe');
  const noWorkflow = await request(`/clusters/${approvalCluster.id}/entities/services`, 'POST', { name: `${tag}-approval-blocked`, host: 'echo-upstream', port: 8081 });
  check(noWorkflow.status === 403 || noWorkflow.status === 409, 'approval-mode cluster blocks writes without an approved workflow');
  const blockedLookup = ok(await request(`${resource('services')}?search=${tag}-approval-blocked`), 'blocked write real-object lookup');
  check(blockedLookup.items?.length === 0, 'rejected approval-mode write did not reach Kong');
  const approvalCurrent = ok(await request(`/clusters/${approvalCluster.id}`), 'approval cluster current revision');
  ok(await request(`/clusters/${approvalCluster.id}/deactivate`, 'POST', { confirm: true, confirm_name: approvalCurrent.name, revision: approvalCurrent.revision }), 'approval test cluster soft deactivation');

  const scan = findSecretArtifacts(secrets.filter(Boolean));
  check(scan.leaks.length === 0, 'generated and tracked artifacts contain no test credentials/private key', { scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles });
} catch (error) {
  checks.push({ name: error.message, passed: false });
  process.exitCode = 1;
} finally {
  if (temporaryDirectory) rmSync(temporaryDirectory, { recursive: true, force: true });
  await mkdir('artifacts/M1', { recursive: true });
  const evidence = { performedAt: new Date().toISOString(), kind: 'real-kong-1.5-m1', testTag: tag, clusterId, passed: checks.filter(item => item.passed).length, failed: checks.filter(item => !item.passed).length, checks, configurationRetainedForDemo: true };
  await writeFile('artifacts/M1/security-live.json', `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ kind: evidence.kind, passed: evidence.passed, failed: evidence.failed }));
}
