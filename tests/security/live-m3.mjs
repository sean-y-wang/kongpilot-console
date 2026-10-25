import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { findSecretArtifacts } from './check-artifacts.mjs';

if (existsSync('.env')) process.loadEnvFile('.env');
const base = (process.env.SECURITY_BASE_URL || 'http://127.0.0.1:8080/api/v1').replace(/\/$/, '');
const proxy = (process.env.SECURITY_PROXY_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const suffix = randomUUID().slice(0, 8), tag = `m3-security-${suffix}`;
const checks = [], secrets = [], fixtures = {}, migrations = [];
// Outside the workspace and evidence tree. Keep only until all browser/manual
// artifacts have been scanned, then remove it; never print or commit its data.
const runtimeSecretReference = join(tmpdir(), 'kongos-m3-runtime-secrets.json');
let cookie = '', csrf = '', clusterId, clusterAdminUrl, defaultWorkspace, workspaceA, workspaceB, temporaryDirectory, lastRequestAt = 0;

function check(condition, name, details = {}) {
  if (!condition) throw new Error(name);
  checks.push({ name, passed: true, ...details });
}
function dataEntity(data) {
  if (data?.entity) return data.entity;
  if (data?.result) return dataEntity(data.result);
  return data;
}
function rows(data) { return Array.isArray(data) ? data : data?.items || data?.workspaces || []; }
function confirmation(value) { return String(value.name || value.username || value.target || value.id); }
function scoped(path, workspace = workspaceA, extra = {}) {
  const [pathname, query = ''] = path.split('?');
  const params = new URLSearchParams(query);
  if (workspace) params.set('workspaceId', workspace.id || workspace);
  for (const [key, value] of Object.entries(extra)) if (value !== undefined) params.set(key, String(value));
  return `${pathname}${params.size ? `?${params}` : ''}`;
}
function path(type, id, cid = clusterId) { return `/clusters/${cid}/entities/${type}${id ? `/${id}` : ''}`; }
async function request(pathname, method = 'GET', body, extraHeaders = {}) {
  const pause = 70 - (Date.now() - lastRequestAt);
  if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
  lastRequestAt = Date.now();
  const headers = { ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(['GET', 'HEAD'].includes(method) ? {} : { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }), ...extraHeaders };
  const response = await fetch(`${base}${pathname}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual' });
  const text = await response.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = null; }
  return { status: response.status, payload, data: payload?.data, response, text };
}
function ok(result, name) {
  const code = result.payload?.error?.code;
  const safeCode = typeof code === 'string' && /^[A-Z_\d]{1,80}$/.test(code) ? code : undefined;
  check(result.status >= 200 && result.status < 300, `${name}: HTTP ${result.status}${safeCode ? ` (${safeCode})` : ''}`, { requestId: result.payload?.meta?.requestId });
  return result.data;
}
async function read(type, id, workspace = workspaceA, reveal = false) { return dataEntity(ok(await request(scoped(path(type, id), workspace, reveal ? { reveal: true } : {})), `${type} scoped read`)); }
async function create(type, body, workspace = workspaceA) {
  const item = dataEntity(ok(await request(scoped(path(type), workspace), 'POST', body), `${type} scoped create`));
  check(typeof item?.id === 'string', `${type} has real Kong ID`);
  return item;
}
async function update(type, id, body, workspace = workspaceA) { return dataEntity(ok(await request(scoped(path(type, id), workspace), 'PATCH', body), `${type} scoped update`)); }
async function crossScope(pathname, writes = [], workspace = workspaceB, label = 'resource') {
  const response = await request(scoped(pathname, workspace));
  check(response.status === 403, `${label} cross-workspace GET is denied without a body leak`);
  check(!secrets.filter(Boolean).some(value => response.text.includes(value)), `${label} denial contains no credential`);
  for (const [method, body] of writes) {
    const denied = await request(scoped(pathname, workspace), method, body);
    check(denied.status === 403, `${label} cross-workspace ${method} is denied`);
    check(!secrets.filter(Boolean).some(value => denied.text.includes(value)), `${label} ${method} denial contains no credential`);
  }
}
async function archive(type, value, workspace = workspaceA, resourcePath = path(type, value.id)) {
  await new Promise(resolve => setTimeout(resolve, 300));
  ok(await request(scoped(resourcePath, workspace), 'DELETE', { confirmed: true, confirm_name: confirmation(value) }), `${type} scoped archive`);
  const listing = ok(await request(scoped(`/clusters/${clusterId}/recycle-bin`, workspace, { size: 100 })), `${type} scoped recycle list`);
  const entry = rows(listing).find(item => item.original_id === value.id && !['restored', 'purged'].includes(item.state));
  check(Boolean(entry), `${type} archive belongs to original workspace`);
  const preview = ok(await request(scoped(`/clusters/${clusterId}/recycle-bin/${entry.id}`, workspace)), `${type} scoped recycle preview`);
  check(!secrets.filter(Boolean).some(secret => JSON.stringify(preview).includes(secret)), `${type} archived graph is redacted`);
  await crossScope(`/clusters/${clusterId}/recycle-bin/${entry.id}`, [], workspaceB, `${type} recycle preview`);
  const foreignRestore = await request(scoped(`/clusters/${clusterId}/recycle-bin/${entry.id}/restore`, workspaceB), 'POST', { confirmed: true, confirm_name: entry.root_name });
  check(foreignRestore.status === 403, `${type} cross-workspace restore denied`);
  return entry;
}
async function restore(entry, workspace = workspaceA) {
  await new Promise(resolve => setTimeout(resolve, 300));
  const result = ok(await request(scoped(`/clusters/${clusterId}/recycle-bin/${entry.id}/restore`, workspace), 'POST', { confirmed: true, confirm_name: entry.root_name }), `${entry.root_type} scoped restore`);
  check(result.state === 'restored', `${entry.root_type} restoration completed`);
  return result;
}
async function waitProxy(routePath, status, headers = {}) {
  const deadline = Date.now() + 18_000;
  let actual = 0;
  while (Date.now() < deadline) {
    const response = await fetch(`${proxy}${routePath}`, { headers, redirect: 'manual' });
    actual = response.status;
    await response.arrayBuffer();
    if (actual === status) return;
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error(`isolated proxy expected ${status}, last HTTP ${actual}`);
}

// Native reads are a trusted backend-network test probe, never a product
// passthrough. JSON stays inside this process and is never added to evidence.
// The only writes below create explicit untagged/invalid-tag Service fixtures
// needed to demonstrate that direct Admin access bypasses tag soft isolation.
function native(pathname, method = 'GET', body) {
  if (method !== 'GET' && (method !== 'POST' || pathname !== '/services')) throw new Error('native test write is outside controlled fixture contract');
  const code = `let input='';for await(const chunk of process.stdin)input+=chunk;const q=JSON.parse(input);const u=process.env.DEFAULT_KONG_ADMIN_URL.replace(/\\/$/,'');if(u!==q.adminUrl.replace(/\\/$/,''))process.exit(3);const r=await fetch(u+q.path,{method:q.method,headers:q.body?{'Content-Type':'application/json'}:{},...(q.body?{body:JSON.stringify(q.body)}:{})});if(!r.ok)process.exit(2);console.log(JSON.stringify(await r.json()));`;
  return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify({ path: pathname, method, body, adminUrl: clusterAdminUrl }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
}
function canonical(value, ignoreTags = false) {
  if (Array.isArray(value)) return value.map(item => canonical(item, ignoreTags));
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).filter(key => key !== 'updated_at' && (!ignoreTags || key !== 'tags')).sort().map(key => [key, canonical(value[key], ignoreTags)]));
  return value;
}
function nativeSnapshot(paths) { return new Map(paths.map(pathname => [pathname, native(pathname)])); }
function unchangedProof(before, label, allowTagChanges = false) {
  for (const [pathname, original] of before) check(JSON.stringify(canonical(native(pathname), allowTagChanges)) === JSON.stringify(canonical(original, allowTagChanges)), `${label}: native ${allowTagChanges ? 'non-tag ' : ''}configuration unchanged`, { resourcePath: pathname });
}
function observedIndexCount(ids) {
  const code = `import pg from 'pg';let input='';for await(const chunk of process.stdin)input+=chunk;const q=JSON.parse(input);const pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});try{const r=await pool.query('SELECT count(*)::int AS count FROM entity_index WHERE cluster_id=$1 AND kong_id=ANY($2::text[]) AND entity_type=$3',[q.clusterId,q.ids,'services']);console.log(JSON.stringify(r.rows[0]));}catch{process.exitCode=2;}finally{await pool.end();}`;
  const result = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify({ clusterId, ids }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  return result.count;
}

try {
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required');
  secrets.push(password, process.env.APP_SECRET, process.env.CONSOLE_ENCRYPTION_KEY);
  const login = await request('/auth/login', 'POST', { username: process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password });
  ok(login, 'administrator login');
  cookie = login.response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  csrf = login.data.csrfToken;
  const clusters = rows(ok(await request('/clusters'), 'registered clusters'));
  const cluster = clusters.find(item => item.version?.startsWith('1.5.') && item.execution_mode === 'direct' && item.labels?.includes('bootstrap'));
  check(Boolean(cluster), 'real direct Kong 1.5 bootstrap cluster available');
  clusterId = cluster.id; clusterAdminUrl = cluster.admin_url;
  const capabilities = ok(await request(`/clusters/${clusterId}/probe`, 'POST'), 'fresh real Kong version capability probe');
  check(capabilities.version === '1.5.1', 'M3 verification runs against real Kong OSS 1.5.1');
  const workspaces = rows(ok(await request(`/clusters/${clusterId}/workspaces`), 'canonical workspace listing'));
  defaultWorkspace = workspaces.find(item => item.is_default || item.code === 'default');
  check(Boolean(defaultWorkspace?.id), 'canonical default workspace UUID discovered');
  async function makeWorkspace(letter) {
    const created = ok(await request(`/clusters/${clusterId}/workspaces`, 'POST', { code: `m3_${suffix}_${letter.toLowerCase()}`, name: `${tag}-${letter}`, owner_user_id: login.data.user.id, description: 'isolated real milestone validation fixture' }), `workspace ${letter} create`);
    check(created.owner_user_id === login.data.user.id && typeof created.description === 'string', `workspace ${letter} preserves owner and description metadata`);
    return created;
  }
  workspaceA = await makeWorkspace('A'); workspaceB = await makeWorkspace('B');
  check(workspaceA.id !== workspaceB.id, 'two independent real workspace IDs');
  const workspaceAOldRevision = workspaceA.revision;
  workspaceA = ok(await request(`/clusters/${clusterId}/workspaces/${workspaceA.id}`, 'PATCH', { revision: workspaceA.revision, description: 'verified workspace metadata edit' }), 'workspace metadata update');
  check((await request(`/clusters/${clusterId}/workspaces/${workspaceA.id}`, 'PATCH', { revision: workspaceAOldRevision, description: 'stale update' })).status === 409, 'stale workspace revision denied');
  workspaceA = ok(await request(`/clusters/${clusterId}/workspaces/${workspaceA.id}`, 'PATCH', { revision: workspaceA.revision, status: 'disabled' }), 'workspace temporarily disabled');
  ok(await request(scoped(path('services'), workspaceA)), 'disabled workspace remains readable');
  check((await request(scoped(path('services'), workspaceA), 'POST', { name: `${tag}-disabled-write`, host: 'echo-upstream', port: 8081 })).status === 409, 'disabled workspace native write denied');
  workspaceA = ok(await request(`/clusters/${clusterId}/workspaces/${workspaceA.id}`, 'PATCH', { revision: workspaceA.revision, status: 'active' }), 'workspace reactivated');
  check((await request(`/clusters/${clusterId}/workspaces/${defaultWorkspace.id}`, 'DELETE', { revision: defaultWorkspace.revision, confirmed: true, confirm_name: defaultWorkspace.name })).status === 409, 'default workspace deletion protected');
  check((await request(`/clusters/${clusterId}/workspaces/${defaultWorkspace.id}`, 'PATCH', { revision: defaultWorkspace.revision, status: 'disabled' })).status === 409, 'default workspace cannot be disabled');
  for (const type of ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis']) {
    const schema = ok(await request(scoped(`/clusters/${clusterId}/schemas/${type}`, workspaceA)), `${type} workspace schema`);
    check(Array.isArray(schema.fields || schema.schema?.fields), `${type} authoritative Kong 1.5 schema fields`);
  }
  const defaultService = await create('services', { name: `${tag}-default`, host: 'echo-upstream', port: 8081, tags: [tag] }, defaultWorkspace);
  const legacyUntagged = native('/services', 'POST', { name: `${tag}-legacy-untagged`, host: 'echo-upstream', port: 8081, tags: [tag] });
  check(!legacyUntagged.tags?.some(value => value.startsWith('kos-ws-')), 'controlled historical fixture has no native workspace tag');
  check((await read('services', legacyUntagged.id, defaultWorkspace)).id === legacyUntagged.id, 'default workspace contains historical untagged entities');
  await crossScope(path('services', legacyUntagged.id), [], workspaceA, 'historical untagged Service');
  await crossScope(path('services', defaultService.id), [], workspaceA, 'default Service');
  const unscoped = ok(await request(`${path('services')}?tags=${tag}&size=100`), 'missing workspace resolves default');
  check(rows(unscoped).some(item => item.id === defaultService.id), 'legacy list resolves canonical default rather than all workspaces');
  check(rows(unscoped).some(item => item.id === legacyUntagged.id), 'default listing includes actual untagged historical native fixture');

  temporaryDirectory = mkdtempSync(join(tmpdir(), 'kongos-m3-'));
  const keyPath = join(temporaryDirectory, 'private.pem'), certPath = join(temporaryDirectory, 'certificate.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '30', '-subj', `/CN=${tag}.invalid`, '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' });
  chmodSync(keyPath, 0o600);
  const privateKey = readFileSync(keyPath, 'utf8'), certificate = readFileSync(certPath, 'utf8'); secrets.push(privateKey);
  fixtures.certificates = await create('certificates', { cert: certificate, key: privateKey, tags: [tag] });
  fixtures.ca_certificates = await create('ca_certificates', { cert: certificate, tags: [tag] });
  fixtures.snis = await create('snis', { name: `${tag}.invalid`, certificate: { id: fixtures.certificates.id }, tags: [tag] });
  fixtures.upstreams = await create('upstreams', { name: `${tag}.upstream`, algorithm: 'round-robin', tags: [tag] });
  const targetBase = `/clusters/${clusterId}/upstreams/${fixtures.upstreams.id}/targets`;
  let target = dataEntity(ok(await request(scoped(targetBase), 'POST', { target: 'echo-upstream:8081', weight: 100, tags: [tag] }), 'workspace Target create'));
  ok(await request(scoped(targetBase), 'POST', { target: 'echo-upstream:8082', weight: 1, tags: [tag] }), 'second Target history fixture');
  target = dataEntity(ok(await request(scoped(`${targetBase}/${target.id}`), 'PATCH', { weight: 90 }), 'workspace Target weight update'));
  check(typeof target.id === 'string' && target.target === 'echo-upstream:8081' && target.weight === 90, 'Target weight update returns the actual effective history ID and weight');
  check((await request(scoped(`${targetBase}/${target.id}`), 'PATCH', { upstream: { id: randomUUID() } })).status === 400, 'Target reparenting through PATCH is rejected');
  for (const [method, body] of [['PATCH', { weight: 7 }], ['DELETE', { confirmed: true, confirm_name: target.target }]]) check((await request(scoped(`${targetBase}/${target.id}`, workspaceB), method, body)).status === 403, `Target cross-workspace ${method} denied`);
  await crossScope(targetBase, [['POST', { target: 'echo-upstream:8083', weight: 1 }]], workspaceB, 'Target list');
  await crossScope(`/clusters/${clusterId}/upstreams/${fixtures.upstreams.id}/health`, [], workspaceB, 'Upstream health');
  check((await request(scoped(`${targetBase}/${target.id}/unhealthy`, workspaceB), 'POST')).status === 403, 'cross-workspace Target health write denied');
  const targetAfterForbidden = rows(ok(await request(scoped(targetBase)), 'Target after forbidden cross-scope writes'));
  check(targetAfterForbidden.some(item => item.id === target.id && item.weight === 90), 'cross-workspace Target writes preserve effective ID and weight');
  ok(await request(scoped(`${targetBase}/${target.id}/healthy`), 'POST'), 'workspace Target manual healthy');
  fixtures.services = await create('services', { name: `${tag}-service`, host: fixtures.upstreams.name, port: 8081, tags: [tag] });
  const publicPath = `/m3/${suffix}/public`, keyProxyPath = `/m3/${suffix}/key`, basicProxyPath = `/m3/${suffix}/basic`;
  fixtures.routes = await create('routes', { name: `${tag}-route`, service: { id: fixtures.services.id }, protocols: ['http'], paths: [publicPath], tags: [tag] });
  fixtures.consumers = await create('consumers', { username: `${tag}-consumer`, custom_id: tag, tags: [tag] });
  fixtures.plugins = await create('plugins', { name: 'correlation-id', service: { id: fixtures.services.id }, config: { header_name: 'X-M3-Request-ID' }, tags: [tag] });
  for (const [type, value] of Object.entries(fixtures)) {
    const current = await read(type, value.id);
    check(current.tags?.includes(`workspace:${workspaceA.code}`), `${type} automatically receives logical reserved workspace tag`);
    await update(type, value.id, { tags: [tag, 'm3-updated'] });
    check((await read(type, value.id)).tags?.includes(`workspace:${workspaceA.code}`), `${type} business tag edit preserves workspace`);
    await crossScope(path(type, value.id), [['PATCH', { tags: ['foreign-write'] }], ['DELETE', { confirmed: true, confirm_name: confirmation(value) }]], workspaceB, type);
    const afterForbidden = await read(type, value.id);
    check(afterForbidden.tags?.includes('m3-updated') && !afterForbidden.tags?.includes('foreign-write'), `${type} forbidden writes preserve business tags and live object`);
    const ownList = ok(await request(scoped(path(type), workspaceA, { size: 100, tags: tag })), `${type} A listing`);
    const otherList = ok(await request(scoped(path(type), workspaceB, { size: 100, tags: tag })), `${type} B listing`);
    check(rows(ownList).some(item => item.id === value.id) && !rows(otherList).some(item => item.id === value.id), `${type} server list isolates A from B`);
  }
  const annotationPath = `/clusters/${clusterId}/entity-annotations/services/${fixtures.services.id}`;
  const nativeBeforeAnnotation = nativeSnapshot([`/services/${fixtures.services.id}`]);
  const emptyAnnotation = ok(await request(scoped(annotationPath)), 'Service console annotation initial version');
  let serviceAnnotation = ok(await request(scoped(annotationPath), 'PUT', { revision: emptyAnnotation.revision, description: 'M3 console-only owner and description', owner_user_id: login.data.user.id, metadata: { milestone: 'M3' } }), 'Service console annotation creation');
  check(serviceAnnotation.owner_user_id === login.data.user.id && serviceAnnotation.description === 'M3 console-only owner and description', 'console-only annotations preserve owner and description');
  await crossScope(annotationPath, [['PUT', { revision: serviceAnnotation.revision, description: 'foreign metadata' }], ['DELETE', { revision: serviceAnnotation.revision, confirmed: true, confirm_name: fixtures.services.name }]], workspaceB, 'Service console annotation');
  check((await request(scoped(annotationPath), 'PUT', { revision: emptyAnnotation.revision, description: 'stale annotation' })).status === 409, 'stale console annotation revision rejected');
  serviceAnnotation = ok(await request(scoped(annotationPath), 'DELETE', { revision: serviceAnnotation.revision, confirmed: true, confirm_name: fixtures.services.name }), 'Service console annotation soft deletion');
  check(serviceAnnotation.status === 'deleted', 'console annotation delete retains a restorable deleted row');
  serviceAnnotation = ok(await request(scoped(`${annotationPath}/restore`), 'POST', { revision: serviceAnnotation.revision, confirmed: true, confirm_name: fixtures.services.name }), 'Service console annotation restoration');
  check(serviceAnnotation.status === 'active', 'console annotation restoration returns active metadata');
  unchangedProof(nativeBeforeAnnotation, 'console-only annotation lifecycle');
  await crossScope(`${path('services', fixtures.services.id)}/relations/routes`, [], workspaceB, 'Service routes relationship');
  await crossScope(`${path('routes', fixtures.routes.id)}/relations/service`, [], workspaceB, 'Route Service relationship');
  await crossScope(`${path('plugins', fixtures.plugins.id)}/relations/service`, [], workspaceB, 'Plugin Service relationship');
  await crossScope(`${path('certificates', fixtures.certificates.id)}/relations/snis`, [], workspaceB, 'Certificate SNI relationship');
  check((await request(scoped(`/clusters/${clusterId}/plugin-center/instances/${fixtures.plugins.id}/toggle`, workspaceB), 'POST', { enabled: false })).status === 403, 'plugin-center cross-workspace toggle denied');
  check((await request(scoped(`/clusters/${clusterId}/plugin-center/context?routeId=${fixtures.routes.id}`, workspaceB))).status === 403, 'plugin execution context cannot reveal a foreign route');
  const override = await request(scoped(path('services', fixtures.services.id)), 'PATCH', { tags: [tag, `workspace:${workspaceB.code}`] });
  check(override.status === 400 || override.status === 403, 'reserved workspace tags cannot move entity through ordinary edit');
  const physicalPrefixTag = await create('services', { name: `${tag}-physical-prefix`, host: 'echo-upstream', port: 8081, tags: [tag, `kos-ws-${workspaceB.code}`] });
  check((await read('services', physicalPrefixTag.id)).tags?.includes(`workspace:${workspaceA.code}`), 'user physical-prefix text is encoded as business tag without changing workspace');
  await crossScope(path('services', physicalPrefixTag.id), [], workspaceB, 'physical-prefix business tag Service');

  const key = `m3-key-${randomUUID()}`, basicPassword = `m3-basic-${randomUUID()}`, jwtSecret = `m3-jwt-${randomUUID()}`, oauthSecret = `m3-oauth-${randomUUID()}`, hmacSecret = `m3-hmac-${randomUUID()}`;
  secrets.push(key, basicPassword, jwtSecret, oauthSecret, hmacSecret);
  const credentialInputs = {
    'key-auth': { key }, 'basic-auth': { username: `${tag}-basic`, password: basicPassword },
    jwt: { key: `${tag}-jwt`, secret: jwtSecret, algorithm: 'HS256' },
    oauth2: { name: `${tag}-app`, client_id: `${tag}-client`, client_secret: oauthSecret, redirect_uris: ['https://example.invalid/callback'] },
    'hmac-auth': { username: `${tag}-hmac`, secret: hmacSecret }, acls: { group: 'm3-fixture' },
  };
  const credentials = {};
  for (const [kind, input] of Object.entries(credentialInputs)) {
    const schema = ok(await request(scoped(`/clusters/${clusterId}/schemas/${kind}`)), `${kind} fresh native credential schema`);
    check((schema.fields || schema.schema?.fields)?.some(field => Object.hasOwn(field, 'tags')), `${kind} real Kong 1.5 credential schema supports tags-only migration`);
    const credentialBase = `/clusters/${clusterId}/consumers/${fixtures.consumers.id}/credentials/${kind}`;
    const credential = dataEntity(ok(await request(scoped(credentialBase), 'POST', { ...input, tags: [tag] }), `${kind} workspace credential create`));
    credentials[kind] = credential;
    const forbiddenBaseline = nativeSnapshot([`/consumers/${fixtures.consumers.id}/${kind}/${credential.id}`]);
    if (kind === 'basic-auth') {
      const originalNativePassword = [...forbiddenBaseline.values()][0]?.password;
      if (typeof originalNativePassword === 'string') secrets.push(originalNativePassword);
    }
    await crossScope(credentialBase, [['POST', { ...input, tags: ['foreign-write'] }]], workspaceB, `${kind} list`);
    await crossScope(`${credentialBase}/${credential.id}`, [['PATCH', { tags: ['foreign-write'] }], ['DELETE', { confirmed: true, confirm_name: confirmation(credential) }]], workspaceB, kind);
    check((await request(scoped(`${credentialBase}/${credential.id}`), 'PATCH', { consumer: { id: randomUUID() } })).status === 400, `${kind} Consumer reparenting through PATCH rejected`);
    unchangedProof(forbiddenBaseline, `${kind} rejected cross-scope writes`);
    ok(await request(scoped(`${credentialBase}/${credential.id}`), 'PATCH', { tags: [tag, 'm3-updated'] }), `${kind} workspace credential tags update`);
    const masked = await request(scoped(`${credentialBase}/${credential.id}`)); ok(masked, `${kind} workspace credential detail`);
    check(!secrets.filter(Boolean).some(secret => masked.text.includes(secret)), `${kind} workspace credential response masked`);
    const secretField = { 'key-auth': 'key', 'basic-auth': 'password', jwt: 'secret', oauth2: 'client_secret', 'hmac-auth': 'secret' }[kind];
    if (secretField) check(String(dataEntity(masked.data)[secretField]).startsWith('[REDACTED'), `${kind} credential field is explicitly redacted including native hash`);
    const entry = await archive(kind, credential, workspaceA, `${credentialBase}/${credential.id}`);
    await restore(entry);
    check(dataEntity(ok(await request(scoped(`${credentialBase}/${credential.id}`)), `${kind} credential after restore`)).id === credential.id, `${kind} restored original ID in same workspace`);
  }
  const keyRoute = await create('routes', { name: `${tag}-key-route`, service: { id: fixtures.services.id }, paths: [keyProxyPath], protocols: ['http'], tags: [tag] });
  const basicRoute = await create('routes', { name: `${tag}-basic-route`, service: { id: fixtures.services.id }, paths: [basicProxyPath], protocols: ['http'], tags: [tag] });
  const keyPlugin = await create('plugins', { name: 'key-auth', route: { id: keyRoute.id }, config: { hide_credentials: true }, tags: [tag] });
  const basicPlugin = await create('plugins', { name: 'basic-auth', route: { id: basicRoute.id }, config: { hide_credentials: true }, tags: [tag] });
  const basicHeader = `Basic ${Buffer.from(`${credentialInputs['basic-auth'].username}:${basicPassword}`).toString('base64')}`; secrets.push(basicHeader);
  await waitProxy(`${publicPath}/echo`, 200); await waitProxy(`${keyProxyPath}/echo`, 200, { apikey: key }); await waitProxy(`${basicProxyPath}/echo`, 200, { Authorization: basicHeader });
  check(true, 'workspace-scoped graph serves public/APIKey/raw Basic through real proxy');

  const targetEntry = await archive('targets', target, workspaceA, `${targetBase}/${target.id}`); await restore(targetEntry);
  const restoredTargets = rows(ok(await request(scoped(targetBase)), 'Target effective collection after restore'));
  target = restoredTargets.find(item => item.target === 'echo-upstream:8081' && item.weight === 90);
  check(Boolean(target), 'Target restore retains weight in original workspace');
  // Deleting individual SNI/Route first keeps their separate CRUD graphs small;
  // subsequent parent deletion still verifies complete dependent restoration.
  for (const type of ['plugins', 'routes', 'snis', 'certificates', 'ca_certificates', 'consumers', 'services', 'upstreams']) {
    const entry = await archive(type, fixtures[type]); await restore(entry);
    check((await read(type, fixtures[type].id)).id === fixtures[type].id, `${type} original ID scoped restoration`);
  }
  await waitProxy(`${keyProxyPath}/echo`, 200, { apikey: key }); await waitProxy(`${basicProxyPath}/echo`, 200, { Authorization: basicHeader });
  check(true, 'eight scoped core CRUD graphs and six credentials preserve proxy access after restore');

  const pageTag = `${tag}-page`, redTag = `${tag}-red`, blueTag = `${tag}-blue`;
  const expectedAND = [], expectedOR = [];
  for (const workspace of [workspaceA, workspaceB]) for (let index = 0; index < 5; index++) {
    const item = await create('services', { name: `${tag}-page-${workspace.code}-${index}`, host: 'echo-upstream', port: 8081, tags: [pageTag, index % 2 ? blueTag : redTag, ...(index === 0 ? [blueTag] : [])] }, workspace);
    if (workspace.id === workspaceA.id) { expectedOR.push(item.id); if (index === 0) expectedAND.push(item.id); }
  }
  async function collectFilter(tags) {
    let cursor, firstCursor;
    const found = [];
    for (let index = 0; index < 6; index++) {
      const page = ok(await request(scoped(path('services'), workspaceA, { size: 2, tags, cursor })), 'workspace filtered native cursor page');
      found.push(...rows(page).map(item => item.id));
      if (!firstCursor) firstCursor = page.nextCursor;
      cursor = page.nextCursor;
      if (!cursor) return { found, firstCursor };
    }
    throw new Error('workspace filter paging did not finish within bounded fixture pages');
  }
  const and = await collectFilter(`${redTag},${blueTag}`), or = await collectFilter(`${redTag}/${blueTag}`);
  check(and.found.length === 1 && and.found[0] === expectedAND[0], 'business tag AND within workspace returns exact joint match');
  check(or.found.length === 5 && new Set(or.found).size === 5 && expectedOR.every(id => or.found.includes(id)), 'business tag OR spans three pages without cross-workspace rows or duplicates');
  check((await request(scoped(path('services'), workspaceB, { size: 2, tags: `${redTag}/${blueTag}`, cursor: or.firstCursor }))).status === 400, 'native cursor cannot cross workspace scope');
  workspaceA = ok(await request(`/clusters/${clusterId}/workspaces/${workspaceA.id}`, 'PATCH', { revision: workspaceA.revision, description: 'cursor revision verification' }), 'workspace revision advances after cursor capture');
  check((await request(scoped(path('services'), workspaceA, { size: 2, tags: `${redTag}/${blueTag}`, cursor: or.firstCursor }))).status === 400, 'native cursor captured under an old workspace revision is rejected');
  check((await request(scoped(path('services'), workspaceA, { size: 2, tags: `${redTag},${blueTag}/${pageTag}` }))).status === 400, 'mixed AND/OR tag syntax is rejected');
  const indexed = ok(await request(scoped(path('services'), workspaceA, { tags: pageTag, search: `${tag}-page`, sort: 'name:asc', size: 2 })), 'workspace indexed list');
  check(rows(indexed).length === 2 && rows(indexed).every(item => expectedOR.includes(item.id)), 'search/sort index revalidates workspace rather than leaking B rows');
  const missingWorkspace = await request(scoped(path('services'), randomUUID())); check(missingWorkspace.status === 403, 'unknown workspace ID denied');
  check((await request(`${path('services')}?workspaceId=${workspaceA.id}&workspaceId=${workspaceB.id}`)).status === 400, 'ambiguous repeated workspace query rejected');
  for (const workspace of [workspaceA, workspaceB]) {
    const inventory = ok(await request(scoped(`/clusters/${clusterId}/inventory`, workspace)), 'workspace inventory dashboard');
    check(inventory.workspace_id === workspace.id && inventory.source === 'index' && typeof inventory.workspace_revision === 'number', 'dashboard reports current workspace and observed index source');
    check(inventory.observed_at === null || Number.isFinite(Date.parse(String(inventory.observed_at))), 'dashboard observation time is valid or explicitly unknown');
    check(inventory.traffic?.available === false && typeof inventory.traffic?.reason === 'string', 'M3 dashboard does not invent traffic before metrics provider');
    check(Object.keys(fixtures).every(type => typeof inventory.counts?.[type] === 'number'), 'dashboard counts cover all eight real entity kinds');
  }

  // Controlled direct Admin fixtures show the documented soft-isolation limit.
  const invalidFixtures = [
    native('/services', 'POST', { name: `${tag}-unknown-workspace`, host: 'echo-upstream', port: 8081, tags: [tag, `kos-ws-unknown_${suffix}`] }),
    native('/services', 'POST', { name: `${tag}-multiple-workspaces`, host: 'echo-upstream', port: 8081, tags: [tag, `kos-ws-${workspaceA.code}`, `kos-ws-${workspaceB.code}`] }),
  ];
  const invalidIds = invalidFixtures.map(item => item.id);
  let observedInvalidCount = observedIndexCount(invalidIds);
  for (let attempt = 0; observedInvalidCount < 2 && attempt < 6; attempt++) {
    const refreshed = await request(scoped(`/clusters/${clusterId}/inventory/refresh`, workspaceA), 'POST');
    check(refreshed.status >= 200 && refreshed.status < 300 || refreshed.status === 409, 'bounded quarantine index observation respects background refresh lock');
    await new Promise(resolve => setTimeout(resolve, 400));
    observedInvalidCount = observedIndexCount(invalidIds);
  }
  check(observedInvalidCount === 2, 'both invalid-tag fixtures are present in console index before testing indexed exclusion', { evidenceSource: 'read-only console database row count; no Kong database connection' });
  for (const workspace of [defaultWorkspace, workspaceA, workspaceB]) {
    const listing = ok(await request(scoped(path('services'), workspace, { tags: tag, size: 100 })), 'quarantine native list exclusion');
    const sorted = ok(await request(scoped(path('services'), workspace, { search: tag, sort: 'name:asc', size: 100 })), 'quarantine indexed list exclusion');
    for (const invalid of invalidFixtures) {
      check(!rows(listing).some(item => item.id === invalid.id) && !rows(sorted).some(item => item.id === invalid.id), 'invalid workspace tags excluded from both list providers', { objectId: invalid.id, workspaceId: workspace.id });
      check((await request(scoped(path('services', invalid.id), workspace))).status === 403, 'invalid workspace tags single entity quarantined', { objectId: invalid.id, workspaceId: workspace.id });
    }
  }
  const invalidSummary = ok(await request(scoped(`/clusters/${clusterId}/inventory`, workspaceA)), 'administrator quarantine summary');
  check(typeof invalidSummary.quarantined_count === 'number' && invalidSummary.quarantined_count >= 2, 'administrator receives observed quarantine count without raw objects');
  check((await request(scoped(`/clusters/${clusterId}/inventory/refresh`, randomUUID()), 'POST')).status === 403, 'inventory refresh validates requested workspace before starting cluster read job');
  check(true, 'direct Admin bypass fixtures explicitly quarantined; no product raw passthrough used', { fixtureMechanism: 'backend-network controlled native POST services only' });

  const credentialNativePaths = Object.entries(credentials).map(([kind, value]) => `/consumers/${fixtures.consumers.id}/${kind}/${value.id}`);
  const graphNativePaths = [...Object.entries(fixtures).map(([type, value]) => `/${type}/${value.id}`), `/routes/${keyRoute.id}`, `/routes/${basicRoute.id}`, `/plugins/${keyPlugin.id}`, `/plugins/${basicPlugin.id}`, ...credentialNativePaths];
  const beforeMigration = nativeSnapshot(graphNativePaths);
  const nativeBasic = beforeMigration.get(`/consumers/${fixtures.consumers.id}/basic-auth/${credentials['basic-auth'].id}`);
  if (typeof nativeBasic?.password === 'string') secrets.push(nativeBasic.password);
  const targetHistoryPath = `/upstreams/${fixtures.upstreams.id}/targets/all?size=100`, targetHistoryBefore = native(targetHistoryPath);
  const roots = ['services', 'consumers', 'upstreams', 'certificates', 'ca_certificates'].map(type => ({ type, id: fixtures[type].id }));
  const planPath = `/clusters/${clusterId}/workspace-migrations/plan`;
  check((await request(scoped(planPath), 'POST', { source_workspace_id: workspaceB.id, target_workspace_id: defaultWorkspace.id, roots })).status === 400, 'migration query/body source scope mismatch rejected');
  check((await request(scoped(planPath), 'POST', { source_workspace_id: workspaceA.id, target_workspace_id: workspaceB.id, roots: Array.from({ length: 51 }, () => roots[0]) })).status === 400, 'migration root count bounded at fifty before native writes');
  const plan = ok(await request(scoped(planPath), 'POST', { source_workspace_id: workspaceA.id, target_workspace_id: workspaceB.id, roots }), 'joint migration plan preview');
  check(plan.conflicts?.length === 0 && plan.affected?.length >= 15 && typeof plan.plan_hash === 'string', 'joint migration complete graph has no conflicts and a stable review hash');
  check(plan.affected.some(item => item.type === 'targets' && item.inherited_only === true), 'migration targets inherit parent workspace without native writes');
  check(plan.budget?.pages <= 100 && plan.budget?.records <= 10_000 && plan.budget?.nodes <= 10_000, 'migration capture shared budgets bounded');
  unchangedProof(beforeMigration, 'preview');
  const wrongHash = await request(scoped(`/clusters/${clusterId}/workspace-migrations/${plan.id}/apply`), 'POST', { confirmed: true, confirm_name: workspaceB.name, plan_hash: `${plan.plan_hash}wrong` });
  check(wrongHash.status === 409 || wrongHash.status === 400, 'stale/altered migration plan hash denied');
  const migrationKey = randomUUID();
  const applied = ok(await request(scoped(`/clusters/${clusterId}/workspace-migrations/${plan.id}/apply`), 'POST', { confirmed: true, confirm_name: workspaceB.name, plan_hash: plan.plan_hash }, { 'X-Idempotency-Key': migrationKey }), 'joint migration apply');
  check(applied.state === 'succeeded' || applied.state === 'completed', 'joint migration reaches successful terminal state');
  migrations.push({ id: plan.id, state: applied.state, affectedCount: plan.affected.length });
  unchangedProof(beforeMigration, 'migration', true);
  check(JSON.stringify(native(targetHistoryPath)) === JSON.stringify(targetHistoryBefore), 'workspace migration makes zero Target writes/history/effective-ID changes');
  const receipt = ok(await request(scoped(`/clusters/${clusterId}/mutations/by-key/${migrationKey}`, workspaceA)), 'migration original-source-workspace receipt');
  check(receipt.state === 'succeeded' && !secrets.filter(Boolean).some(secret => JSON.stringify(receipt).includes(secret)), 'migration receipt terminal and fully redacted');
  await crossScope(`/clusters/${clusterId}/mutations/by-key/${migrationKey}`, [], workspaceB, 'source-bound migration receipt');
  for (const [type, value] of Object.entries(fixtures)) {
    const moved = await read(type, value.id, workspaceB);
    check(moved.tags?.includes(`workspace:${workspaceB.code}`) && !moved.tags?.includes(`workspace:${workspaceA.code}`), `${type} moves to B using reserved tags`);
    check((await request(scoped(path(type, value.id), workspaceA))).status === 403, `${type} former workspace access rejected after migration`);
  }
  const movedAnnotation = ok(await request(scoped(annotationPath, workspaceB)), 'migrated Service console annotation visibility');
  check(movedAnnotation.description === serviceAnnotation.description && movedAnnotation.owner_user_id === serviceAnnotation.owner_user_id && movedAnnotation.revision === serviceAnnotation.revision, 'migration preserves console-only annotations without sending unsupported Kong fields');
  check((await request(scoped(annotationPath, workspaceA))).status === 403, 'migrated console annotations follow authoritative new workspace membership');
  for (const [kind, value] of Object.entries(credentials)) {
    const moved = ok(await request(scoped(`/clusters/${clusterId}/consumers/${fixtures.consumers.id}/credentials/${kind}/${value.id}`, workspaceB)), `${kind} target-workspace credential read`);
    check(dataEntity(moved).id === value.id, `${kind} credential original ID survives tags-only migration`);
  }
  const movedTargetListing = ok(await request(scoped(targetBase, workspaceB)), 'target-workspace inherited Target listing');
  const movedTargets = rows(movedTargetListing);
  check(movedTargets.some(item => item.target === 'echo-upstream:8081' && item.weight === 90), 'Target visible in new parent workspace with unchanged effective weight');
  check(movedTargetListing.effective_workspace_id === workspaceB.id && movedTargetListing.workspace_inheritance === 'upstream' && movedTargetListing.historical_tags_may_differ === true, 'Target collection explicitly discloses parent-derived workspace despite historical native tag lag');
  check((await request(scoped(targetBase, workspaceA))).status === 403, 'Target old-parent-workspace listing denied after migration');
  await waitProxy(`${keyProxyPath}/echo`, 200, { apikey: key }); await waitProxy(`${basicProxyPath}/echo`, 200, { Authorization: basicHeader });
  check(true, 'migration retains real APIKey/rawBasic access and native Basic hash/Key/JWT/HMAC/OAuth secrets unchanged');
  const beforeReconcile = nativeSnapshot(graphNativePaths);
  ok(await request(scoped(`/clusters/${clusterId}/workspace-migrations/${plan.id}/reconcile`, workspaceA), 'POST', { plan_hash: plan.plan_hash }), 'completed migration read-only reconciliation');
  unchangedProof(beforeReconcile, 'reconcile');
  check(JSON.stringify(native(targetHistoryPath)) === JSON.stringify(targetHistoryBefore), 'reconcile performs no native Target writes');

  const conflictUpstream = await create('upstreams', { name: `${tag}-shared.upstream`, tags: [tag] });
  const conflictService = await create('services', { name: `${tag}-conflict-service`, host: conflictUpstream.name, port: 8081, tags: [tag] });
  const conflictBefore = nativeSnapshot([`/services/${conflictService.id}`, `/upstreams/${conflictUpstream.id}`]);
  const conflictPlan = ok(await request(scoped(planPath), 'POST', { source_workspace_id: workspaceA.id, target_workspace_id: workspaceB.id, roots: [{ type: 'upstreams', id: conflictUpstream.id }] }), 'shared-reference conflict preview still returns view');
  check(conflictPlan.conflicts?.length > 0, 'moving shared Upstream without its Service surfaces future cross-workspace reference conflict');
  check((await request(scoped(`/clusters/${clusterId}/workspace-migrations/${conflictPlan.id}/apply`), 'POST', { confirmed: true, confirm_name: workspaceB.name, plan_hash: conflictPlan.plan_hash })).status === 409, 'conflicting migration apply denied');
  unchangedProof(conflictBefore, 'conflict apply');

  let workspaceC = await makeWorkspace('C');
  const deletedScopeService = await create('services', { name: `${tag}-deleted-scope`, host: 'echo-upstream', port: 8081, tags: [tag] }, workspaceC);
  check((await request(`/clusters/${clusterId}/workspaces/${workspaceC.id}`, 'DELETE', { revision: workspaceC.revision, confirmed: true, confirm_name: workspaceC.name })).status === 409, 'nonempty workspace deletion denied');
  // C recycle cross-scope denial still uses B, never the original A.
  const deletedScopeEntry = await archive('services', deletedScopeService, workspaceC);
  const deletedWorkspace = ok(await request(`/clusters/${clusterId}/workspaces/${workspaceC.id}`, 'DELETE', { revision: workspaceC.revision, confirmed: true, confirm_name: workspaceC.name }), 'empty workspace soft deletion');
  check(deletedWorkspace.state === 'deleted', 'workspace deletion returns explicit soft-deleted state');
  workspaceC = deletedWorkspace.workspace;
  check((await request(scoped(path('services'), workspaceC))).status === 403, 'deleted workspace cannot query entities');
  ok(await request(scoped(`/clusters/${clusterId}/recycle-bin/${deletedScopeEntry.id}`, workspaceC)), 'platform administrator can preview original deleted-workspace archive');
  const inactiveRestore = await request(scoped(`/clusters/${clusterId}/recycle-bin/${deletedScopeEntry.id}/restore`, workspaceC), 'POST', { confirmed: true, confirm_name: deletedScopeEntry.root_name });
  check(inactiveRestore.status === 403 || inactiveRestore.status === 409, 'archive restoration into deleted workspace is blocked');
  workspaceC = ok(await request(`/clusters/${clusterId}/workspaces/${workspaceC.id}/restore`, 'POST', { revision: workspaceC.revision, confirmed: true, confirm_name: workspaceC.name }), 'workspace metadata restore');
  await restore(deletedScopeEntry, workspaceC);

  const otherCluster = ok(await request('/clusters', 'POST', { name: `${tag}-foreign-cluster`, environment: 'security-fixture', admin_url: cluster.admin_url, execution_mode: 'approval' }), 'foreign registered cluster for scope mismatch probe');
  check((await request(scoped(path('services', fixtures.services.id, otherCluster.id), workspaceB))).status === 403, 'valid foreign cluster with another cluster workspace ID denied');
  const foreignMetadata = await request(`/clusters/${otherCluster.id}/workspaces/${workspaceB.id}`);
  check(foreignMetadata.status === 404 && !foreignMetadata.text.includes(workspaceB.name), 'foreign cluster metadata lookup returns not found without exposing workspace');
  const otherCurrent = ok(await request(`/clusters/${otherCluster.id}`), 'foreign cluster current revision');
  ok(await request(`/clusters/${otherCluster.id}/deactivate`, 'POST', { confirm: true, confirm_name: otherCurrent.name, revision: otherCurrent.revision }), 'foreign fixture cluster soft deactivation');

} catch (error) {
  // Never persist remote response bodies, config, or exception stacks.
  checks.push({ name: error.message, passed: false }); process.exitCode = 1;
} finally {
  if (temporaryDirectory) rmSync(temporaryDirectory, { recursive: true, force: true });
  await mkdir('artifacts/M3', { recursive: true });
  const evidence = { performedAt: new Date().toISOString(), kind: 'real-kong-1.5-m3', testTag: tag, clusterId, defaultWorkspaceId: defaultWorkspace?.id, workspaceA: workspaceA && { id: workspaceA.id, code: workspaceA.code, name: workspaceA.name }, workspaceB: workspaceB && { id: workspaceB.id, code: workspaceB.code, name: workspaceB.name }, fixtureIds: Object.fromEntries(Object.entries(fixtures).map(([type, value]) => [type, value.id])), migrations, passed: checks.filter(item => item.passed).length, failed: checks.filter(item => !item.passed).length, checks, configurationRetainedForDemo: true, faultInjectionNativeTransport: 'not part of this real HTTP gate; separate labelled integration mock evidence required' };
  await writeFile('artifacts/M3/security-live.json', `${JSON.stringify(evidence, null, 2)}\n`);
  const scan = findSecretArtifacts(secrets.filter(Boolean));
  checks.push({ name: 'workspace artifacts including final HTTP report contain no generated credential/private-key/hash plaintext', passed: scan.leaks.length === 0, scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles });
  if (scan.leaks.length) process.exitCode = 1;
  evidence.passed = checks.filter(item => item.passed).length; evidence.failed = checks.filter(item => !item.passed).length;
  await writeFile('artifacts/M3/security-live.json', `${JSON.stringify(evidence, null, 2)}\n`);
  await writeFile('artifacts/M3/http-secret-artifact-scan.json', `${JSON.stringify({ performedAt: new Date().toISOString(), kind: 'M3-HTTP-runtime-secrets', allPassed: scan.leaks.length === 0, scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles, leaks: scan.leaks, coversFutureBrowserArtifacts: false }, null, 2)}\n`);
  if (evidence.failed === 0) {
    await writeFile(runtimeSecretReference, JSON.stringify(secrets.filter(Boolean)), { mode: 0o600 });
    chmodSync(runtimeSecretReference, 0o600);
  }
  console.log(JSON.stringify({ kind: evidence.kind, passed: evidence.passed, failed: evidence.failed }));
}
