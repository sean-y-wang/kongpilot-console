import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { findSecretArtifacts } from './check-artifacts.mjs';

if (existsSync('.env')) process.loadEnvFile('.env');
const base = (process.env.SECURITY_BASE_URL || 'http://127.0.0.1:8080/api/v1').replace(/\/$/, '');
const proxy = (process.env.SECURITY_PROXY_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const suffix = randomUUID().slice(0, 8), tag = `m2-security-${suffix}`;
const checks = [], plugins = [], verifiedPlugins = [], runtimeSecrets = [];
let cookie = '', csrf = '', clusterId, lastRequestAt = 0;

function check(condition, name, detail = {}) {
  if (!condition) throw Object.assign(new Error(name), { safeDetail: detail });
  checks.push({ name, passed: true, ...detail });
}
function secret(prefix) { const value = `${prefix}-${randomUUID()}`; runtimeSecrets.push(value); return value; }
async function request(path, method = 'GET', body, extraHeaders = {}) {
  const pause = 70 - (Date.now() - lastRequestAt);
  if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
  lastRequestAt = Date.now();
  const response = await fetch(`${base}${path}`, { method, redirect: 'manual', headers: { ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(['GET', 'HEAD'].includes(method) ? {} : { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }), ...extraHeaders }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await response.text();
  let payload; try { payload = JSON.parse(text); } catch { payload = null; }
  return { response, status: response.status, payload, data: payload?.data, text };
}
function ok(result, label) {
  const code = result.payload?.error?.code;
  const fieldPaths = Object.keys(result.payload?.error?.fields || {}).filter(value => /^[\w.\[\]-]{1,200}$/.test(value));
  check(result.status >= 200 && result.status < 300, `${label}: HTTP ${result.status}${typeof code === 'string' && /^[A-Z_\d]{1,80}$/.test(code) ? ` (${code})` : ''}`, { requestId: result.payload?.meta?.requestId, ...(fieldPaths.length ? { fieldPaths } : {}) });
  return result.data;
}
function unwrap(data) { return data?.entity ?? data; }
function path(type, id) { return `/clusters/${clusterId}/entities/${type}${id ? `/${id}` : ''}`; }
async function create(type, body) {
  if (type === 'plugins' && !body.service && !body.route && !body.consumer) {
    let cursor, pages = 0;
    do {
      const page = ok(await request(`/clusters/${clusterId}/plugin-center/instances?size=100&name=${body.name}&binding_scope=global${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`), `${body.name} global singleton preflight`);
      for (const previous of page.items || []) {
        check(previous.tags?.some(value => value.startsWith('m2-security-')), `${body.name} existing global configuration belongs to a prior test fixture`);
        // Repeated live gates archive their own prior global fixture, preserving
        // recovery material. An operator's global configuration is never changed.
        ok(await request(path('plugins', previous.id), 'DELETE', { confirmed: true, confirm_name: body.name }), `${body.name} prior global fixture archived`);
      }
      cursor = page.nextCursor;
      if (++pages > 10) throw new Error('global singleton preflight exceeded its bounded page budget');
    } while (cursor);
  }
  const writeKey = randomUUID();
  const value = unwrap(ok(await request(path(type), 'POST', body, { 'X-Idempotency-Key': writeKey }), `${type} create`));
  check(typeof value?.id === 'string', `${type} has real Kong ID`);
  if (type === 'plugins') {
    plugins.push({ id: value.id, name: value.name });
    const receipt = await request(`/clusters/${clusterId}/mutations/by-key/${writeKey}`);
    const operation = ok(receipt, `${body.name} original-key write receipt`);
    check(operation.state === 'succeeded' && !runtimeSecrets.filter(Boolean).some(secret => receipt.text.includes(secret)), `${body.name} successful receipt hides secret config`);
  }
  return value;
}
async function patchPlugin(plugin, body, label) { return unwrap(ok(await request(path('plugins', plugin.id), 'PATCH', body), label)); }
async function togglePlugin(plugin, enabled, label) { return unwrap(ok(await request(`/clusters/${clusterId}/plugin-center/instances/${plugin.id}/toggle`, 'POST', { enabled }), label)); }
async function rawPlugin(plugin) { return unwrap(ok(await request(`${path('plugins', plugin.id)}?reveal=true`), `${plugin.name} authorized config read`)); }
function subset(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((item, index) => subset(actual[index], item));
  if (expected && typeof expected === 'object') return actual && typeof actual === 'object' && Object.entries(expected).every(([key, value]) => subset(actual[key], value));
  return actual === expected;
}
function schemaFieldAt(schema, keys) {
  return keys.reduce((parent, key) => Array.isArray(parent?.fields)
    ? parent.fields.flatMap(entry => Object.entries(entry)).find(([name]) => name === key)?.[1]
    : parent?.fields?.[key], schema);
}
async function waitProxy(url, status, headers) {
  const deadline = Date.now() + 20_000;
  let last;
  while (Date.now() < deadline) {
    const response = await fetch(`${proxy}${url}`, { headers, redirect: 'manual' });
    last = response.status; await response.arrayBuffer();
    if (last === status) return;
    await new Promise(resolve => setTimeout(resolve, 350));
  }
  throw new Error(`isolated proxy expected HTTP ${status}, last HTTP ${last}`);
}

function configurations() {
  return {
    'correlation-id': [{ header_name: 'X-M2-Initial' }, { header_name: 'X-M2-Updated' }],
    'pre-function': [{ functions: ['return'] }, { functions: ['local fixture = 1; return'] }],
    cors: [{ origins: ['https://example.invalid'] }, { origins: ['https://updated.invalid'], max_age: 60, credentials: true }],
    'ldap-auth': [{ ldap_host: '127.0.0.1', ldap_port: 389, base_dn: 'dc=example,dc=invalid', attribute: 'uid' }, { timeout: 1001 }],
    loggly: [{ key: secret('m2-loggly'), host: '127.0.0.1', port: 9 }, { tags: ['m2-fixture'] }],
    'hmac-auth': [{}, { clock_skew: 100 }],
    zipkin: [{ http_endpoint: 'http://127.0.0.1:9/ignored' }, { sample_ratio: 0.01 }],
    'request-size-limiting': [{ allowed_payload_size: 10 }, { allowed_payload_size: 11 }],
    'azure-functions': [{ appname: 'kongos-fixture', functionname: 'disabled', apikey: secret('m2-azure') }, { timeout: 1001 }],
    'request-transformer': [{ remove: {}, rename: {}, replace: {}, add: {}, append: {} }, { add: { headers: ['X-M2-Fixture:updated'] } }],
    oauth2: [{ provision_key: secret('m2-oauth-provision'), enable_client_credentials: true }, { token_expiration: 7201, enable_password_grant: true }],
    'response-transformer': [{ remove: {}, rename: {}, replace: {}, add: {}, append: {} }, { add: { headers: ['X-M2-Fixture:updated'] } }],
    'ip-restriction': [{ whitelist: ['127.0.0.1'] }, { whitelist: ['127.0.0.1', '127.0.0.2'] }],
    statsd: [{ host: '127.0.0.1', port: 9, metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 1 }] }, { prefix: 'm2-updated' }],
    jwt: [{}, { run_on_preflight: false, secret_is_base64: true }],
    'proxy-cache': [{ strategy: 'memory', memory: {} }, { cache_ttl: 301 }],
    'basic-auth': [{}, { hide_credentials: true }],
    'key-auth': [{}, { hide_credentials: true }],
    'http-log': [{ http_endpoint: 'http://127.0.0.1:9/ignored' }, { timeout: 1001 }],
    datadog: [{ host: '127.0.0.1', port: 9 }, { prefix: 'm2-updated' }],
    'tcp-log': [{ host: '127.0.0.1', port: 9 }, { timeout: 1001 }],
    'rate-limiting': [{ minute: 10, policy: 'local' }, { minute: 11 }],
    'post-function': [{ functions: ['return'] }, { functions: ['local fixture = 1; return'] }],
    prometheus: [{}, {}],
    acl: [{ whitelist: ['m2-fixture'] }, { hide_groups_header: true }],
    'kubernetes-sidecar-injector': [{}, { imagePullPolicy: 'Never' }],
    syslog: [{}, { log_level: 'notice' }],
    'file-log': [{ path: '/tmp/kongos-m2-disabled.log' }, { reopen: true }],
    'udp-log': [{ host: '127.0.0.1', port: 9 }, { timeout: 1001 }],
    'response-ratelimiting': [{ limits: { fixture: { minute: 10 } }, policy: 'local' }, { limits: { fixture: { minute: 11 } } }],
    'aws-lambda': [{ aws_key: secret('m2-aws-key'), aws_secret: secret('m2-aws-secret'), aws_region: 'us-east-1', function_name: 'kongos-disabled-fixture' }, { timeout: 1001 }],
    session: [{ secret: secret('m2-session') }, { cookie_name: 'm2_updated' }],
    'bot-detection': [{}, { blacklist: ['m2-fixture-bot'] }],
    'request-termination': [{ status_code: 418, message: 'M2 initial' }, { status_code: 419, message: 'M2 updated' }],
  };
}

try {
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required');
  runtimeSecrets.push(password, process.env.APP_SECRET, process.env.CONSOLE_ENCRYPTION_KEY);
  const login = await request('/auth/login', 'POST', { username: process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password });
  const auth = ok(login, 'administrator login');
  cookie = login.response.headers.getSetCookie().map(value => value.split(';')[0]).join('; '); csrf = auth.csrfToken;
  const clusters = ok(await request('/clusters'), 'cluster listing');
  const cluster = clusters.find(value => value.labels?.includes('bootstrap') && value.execution_mode === 'direct' && value.version?.startsWith('1.5.'));
  check(Boolean(cluster), 'bootstrap direct Kong 1.5 cluster is available'); clusterId = cluster.id;
  const probe = ok(await request(`/clusters/${clusterId}/probe`, 'POST'), 'fresh real gateway probe');
  check(probe.version === '1.5.1', 'real Kong 1.5.1 version is verified');
  const pairs = configurations(), enabled = probe.enabled_plugins;
  check(Array.isArray(enabled) && enabled.length === 34, 'real Kong 1.5.1 reports its actual 34 installed plugins');
  check(enabled.every(name => pairs[name]), 'every installed plugin has a schema-based valid fixture');
  const center = `/clusters/${clusterId}/plugin-center`;
  const catalog = ok(await request(`${center}/catalog`), 'plugin market catalog');
  check(catalog.items?.length === 34 && enabled.every(name => catalog.items.some(item => item.name === name)), 'market lists exactly the installed 34 plugin names');
  check(catalog.items.every(item => item.known && item.source === 'kong-oss-1.5.1-source') && new Set(catalog.items.map(item => item.category)).size === 7, 'market supplies versioned source metadata and seven categories');
  const precedence = ok(await request(`${center}/precedence`), 'plugin precedence metadata');
  const expectedScopes = ['consumer-route-service', 'consumer-route', 'consumer-service', 'route-service', 'consumer', 'route', 'service', 'global'];
  check(JSON.stringify(precedence.levels?.map(item => item.scope)) === JSON.stringify(expectedScopes) && precedence.disabled_fallback === true, 'BFF eight precedence levels and disabled fallback match real 1.5 iterator');
  check(precedence.execution_order?.[0]?.name === 'pre-function' && precedence.execution_order?.[0]?.priority_label === '∞' && precedence.execution_order?.[1]?.name === 'zipkin', 'infinite and numeric handler priorities retain their real execution order');
  const unusedService = await create('services', { name: `${tag}-no-traffic`, host: 'echo-upstream', port: 8081, tags: [tag] });
  const unusedDetails = ok(await request(path('services', unusedService.id)), 'unused Service relations');
  check(unusedDetails.relations?.routes?.items?.length === 0, '33 Service-scoped plugin fixtures have no Routes or proxy traffic');

  for (const name of enabled) {
    const schema = ok(await request(`/clusters/${clusterId}/plugin-schemas/${name}`), `${name} old-style schema`);
    check(Array.isArray(schema.fields), `${name} schema exposes live config fields`);
    const centerSchema = ok(await request(`${center}/schemas/${name}`), `${name} enriched center schema`);
    check(centerSchema.remote_authoritative === true && JSON.stringify(centerSchema.wire_schema) === JSON.stringify(schema) && Array.isArray(centerSchema.form_schema?.fields), `${name} enriched form preserves the old-style authoritative wire schema`);
    const [initial, change] = pairs[name];
    // The real injector schema forbids Service/Route/Consumer bindings. It is
    // pure response transformation and is toggled globally without proxy calls.
    const binding = name === 'kubernetes-sidecar-injector' ? {} : { service: { id: unusedService.id } };
    let plugin = await create('plugins', { name, ...binding, enabled: false, config: initial, tags: [tag] });
    check(plugin.enabled === false, `${name} is initially disabled`);
    check(subset((await rawPlugin(plugin)).config, initial), `${name} config create echoes Kong state`);
    plugin = await patchPlugin(plugin, { config: change }, `${name} config PATCH`);
    check(subset((await rawPlugin(plugin)).config, change), `${name} config update echoes Kong state`, { configurableFields: schema.fields.length });
    if (name === 'ip-restriction') {
      await patchPlugin(plugin, { config: { blacklist: [] } }, 'empty alternate blacklist is permitted beside nonempty whitelist');
      check(subset((await rawPlugin(plugin)).config, { whitelist: change.whitelist, blacklist: [] }), 'Kong nonempty semantics preserve the populated restriction');
    }
    plugin = await togglePlugin(plugin, true, `${name} enable without traffic`);
    check(plugin.enabled === true, `${name} enabled value is true`);
    plugin = await togglePlugin(plugin, false, `${name} disable`);
    check(plugin.enabled === false, `${name} enabled value is false`);
    const masked = await request(path('plugins', plugin.id)); ok(masked, `${name} default read`);
    check(!runtimeSecrets.filter(Boolean).some(value => masked.text.includes(value)), `${name} default response hides secret config`);
    if (name === 'cors') check(unwrap(masked.data).config.credentials === true, 'CORS public credentials boolean remains readable');
    if (name === 'oauth2') check(unwrap(masked.data).config.enable_password_grant === true, 'OAuth2 public enable_password_grant flag remains readable');
    if (name === 'jwt') check(unwrap(masked.data).config.secret_is_base64 === true, 'JWT public secret_is_base64 flag remains readable');
    await new Promise(resolve => setTimeout(resolve, 300));
    const deletion = ok(await request(path('plugins', plugin.id), 'DELETE', { confirmed: true, confirm_name: name }), `${name} recycle deletion`);
    check(typeof deletion.entryId === 'string', `${name} delete returns recovery entry ID`);
    const preview = await request(`/clusters/${clusterId}/recycle-bin/${deletion.entryId}`);
    ok(preview, `${name} recycle preview`);
    check(!runtimeSecrets.filter(Boolean).some(value => preview.text.includes(value)), `${name} recovery preview hides secret config`);
    check((await request(path('plugins', plugin.id))).status === 404, `${name} deleted instance is absent`);
    await new Promise(resolve => setTimeout(resolve, 300));
    const restoration = ok(await request(`/clusters/${clusterId}/recycle-bin/${deletion.entryId}/restore`, 'POST', { confirmed: true, confirm_name: name }), `${name} recycle restoration`);
    check(restoration.state === 'restored', `${name} recovery completes`);
    const restored = await rawPlugin(plugin);
    check(restored.id === plugin.id && restored.enabled === false && subset(restored.config, change), `${name} restores original ID, updated config and disabled state`);
    verifiedPlugins.push(name);
    if (verifiedPlugins.length % 10 === 0) console.log(JSON.stringify({ kind: 'm2-plugin-sweep-progress', verifiedPlugins: verifiedPlugins.length }));
  }

  const condition = await request(path('plugins'), 'POST', { name: 'statsd', enabled: false, service: { id: unusedService.id }, config: { metrics: [{ name: 'unique_users', stat_type: 'counter', sample_rate: 1, consumer_identifier: 'custom_id' }] }, tags: [tag] });
  check(condition.status === 400 && Object.keys(condition.payload?.error?.fields || {}).length > 0, 'invalid nested StatsD condition returns readable Kong fields');
  const unsupported = await request(`/clusters/${clusterId}/plugin-schemas/degraphql`);
  check(unsupported.status === 400 || unsupported.status === 404, 'plugin absent from actual installed list is rejected');

  const upstreamSchema = ok(await request(`/clusters/${clusterId}/schemas/upstreams`), 'live Upstream header capability schema');
  const upstreamHeaderField = schemaFieldAt(upstreamSchema, ['healthchecks', 'active', 'headers']);
  if (upstreamHeaderField) {
    const headerValue = `Bearer ${secret('m2-upstream-header')}`;
    const upstream = await create('upstreams', { name: `${tag}-protected-upstream`, healthchecks: { active: { headers: { Authorization: [headerValue] }, healthy: { interval: 0 }, unhealthy: { interval: 0 } } }, tags: [tag] });
    const masked = await request(path('upstreams', upstream.id)); ok(masked, 'protected Upstream default read');
    check(!masked.text.includes(headerValue) && masked.text.includes('[REDACTED'), 'supported active health headers are masked');
    ok(await request(path('upstreams', upstream.id), 'PATCH', { slots: 10001, healthchecks: { active: { http_path: '/health' } } }), 'unrelated Upstream nested PATCH');
    const revealed = unwrap(ok(await request(`${path('upstreams', upstream.id)}?reveal=true`), 'protected Upstream authorized verification'));
    check(revealed.slots === 10001 && revealed.healthchecks.active.http_path === '/health' && revealed.healthchecks.active.headers.Authorization?.[0] === headerValue, 'supported active health headers survive unrelated PATCH');
  } else check(true, 'live Kong 1.5.1 has no active health headers capability; unsupported write is skipped', { supported: false });

  const service = await create('services', { name: `${tag}-precedence`, host: 'echo-upstream', port: 8081, tags: [tag] });
  const routePath = `/m2/${suffix}/precedence`;
  const route = await create('routes', { name: `${tag}-precedence-route`, service: { id: service.id }, paths: [routePath], protocols: ['http'], strip_path: true, tags: [tag] });
  const consumer = await create('consumers', { username: `${tag}-precedence-consumer`, tags: [tag] });
  const forbiddenConsumer = await request(path('plugins'), 'POST', { name: 'key-auth', consumer: { id: consumer.id }, enabled: false, config: {}, tags: [tag] });
  check(forbiddenConsumer.status === 400 && Object.keys(forbiddenConsumer.payload?.error?.fields || {}).length > 0, 'Kong 1.5 key-auth rejects unsupported Consumer binding');
  const apiKey = secret('m2-precedence-key');
  ok(await request(`/clusters/${clusterId}/consumers/${consumer.id}/credentials/key-auth`, 'POST', { key: apiKey, tags: [tag] }), 'precedence Consumer key credential');
  await create('plugins', { name: 'key-auth', route: { id: route.id }, enabled: true, config: { key_names: ['apikey'], hide_credentials: true }, tags: [tag] });
  const bindings = [
    { scope: 'consumer+route+service', service: { id: service.id }, route: { id: route.id }, consumer: { id: consumer.id } },
    { scope: 'consumer+route', route: { id: route.id }, consumer: { id: consumer.id } },
    { scope: 'consumer+service', service: { id: service.id }, consumer: { id: consumer.id } },
    { scope: 'route+service', service: { id: service.id }, route: { id: route.id } },
    { scope: 'consumer', consumer: { id: consumer.id } },
    { scope: 'route', route: { id: route.id } },
    { scope: 'service', service: { id: service.id } },
    { scope: 'global' },
  ];
  const hierarchy = [];
  for (const [rank, binding] of bindings.entries()) {
    const { scope, ...foreignKeys } = binding;
    hierarchy.push(await create('plugins', { name: 'request-termination', ...foreignKeys, config: { status_code: 480 + rank, message: `M2 precedence ${scope}` }, tags: [tag], enabled: true }));
  }
  for (const [rank, plugin] of hierarchy.entries()) {
    const diagnosis = ok(await request(`${center}/context?routeId=${route.id}&consumerId=${consumer.id}&name=request-termination&protocol=http`), `precedence context ${bindings[rank].scope}`);
    const selected = diagnosis.selected?.find(item => item.name === 'request-termination');
    check(diagnosis.complete === true && selected?.entity?.id === plugin.id && selected?.scope === expectedScopes[rank], `BFF selects the same ${bindings[rank].scope} instance as the gateway`);
    await waitProxy(`${routePath}/echo`, 480 + rank, { apikey: apiKey });
    check(true, `real proxy selects ${bindings[rank].scope} after higher scopes are disabled`, { statusCode: 480 + rank });
    await togglePlugin(plugin, false, `disable precedence ${bindings[rank].scope}`);
  }
  await waitProxy(`${routePath}/echo`, 200, { apikey: apiKey });
  check(true, 'all eight disabled scopes fall back to the upstream');
  const emptyDiagnosis = ok(await request(`${center}/context?routeId=${route.id}&consumerId=${consumer.id}&name=request-termination&protocol=http`), 'all-disabled context diagnosis');
  check(emptyDiagnosis.complete === true && emptyDiagnosis.selected?.length === 0 && emptyDiagnosis.candidates?.length === 8 && emptyDiagnosis.candidates.every(item => item.entity.enabled === false), 'all-disabled BFF diagnosis agrees with gateway fallback');
  const wrongService = await request(`${center}/context?routeId=${route.id}&serviceId=${unusedService.id}`);
  check(wrongService.status === 400 && wrongService.payload?.error?.code === 'ROUTE_SERVICE_MISMATCH', 'context refuses mismatched Route and Service');
  const massAssignment = await request(`${center}/instances/${hierarchy[0].id}/toggle`, 'POST', { enabled: true, config: { status_code: 500 } });
  check(massAssignment.status === 400, 'toggle endpoint rejects additional mutation fields');
  for (const scope of ['consumer', 'route', 'service', 'global']) {
    let cursor, seen = [], pages = 0;
    do {
      const listing = ok(await request(`${center}/instances?size=2&tags=${tag}&name=request-termination&binding_scope=${scope}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`), `${scope} paginated center instances`);
      check(listing.items.every(item => item.name === 'request-termination' && item.binding_scope === scope && item.tags?.includes(tag)), `${scope} instance filters remain server-side`);
      seen.push(...listing.items.map(item => item.id)); cursor = listing.nextCursor; pages++;
      if (pages > 50) throw new Error('bounded instance test exceeded its page budget');
    } while (cursor);
    check(new Set(seen).size === seen.length && seen.length === (scope === 'service' ? 2 : 1), `${scope} instances preserve filters and unique IDs across actual cursors`);
  }
  const scan = findSecretArtifacts(runtimeSecrets.filter(Boolean));
  check(scan.leaks.length === 0, 'tracked and generated evidence contains no credentials', { scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles });
} catch (error) {
  checks.push({ name: error.message, passed: false, ...error.safeDetail }); process.exitCode = 1;
} finally {
  const failedDisables = [];
  for (const plugin of plugins) {
    try {
      const response = await request(path('plugins', plugin.id), 'PATCH', { enabled: false });
      if (response.status !== 404 && !(response.status >= 200 && response.status < 300 && unwrap(response.data)?.enabled === false)) failedDisables.push(plugin.id);
    }
    catch { failedDisables.push(plugin.id); }
  }
  if (failedDisables.length) { checks.push({ name: 'not every fixture plugin could be safely disabled', passed: false, pluginIds: failedDisables }); process.exitCode = 1; }
  else if (plugins.length) checks.push({ name: 'all created fixture plugins are confirmed disabled or absent', passed: true, fixturePluginCount: plugins.length });
  await mkdir('artifacts/M2', { recursive: true });
  const evidence = { performedAt: new Date().toISOString(), kind: 'real-kong-1.5-m2', clusterId, testTag: tag, passed: checks.filter(item => item.passed).length, failed: checks.filter(item => !item.passed).length, verifiedPlugins, fixturePluginCount: plugins.length, allFixturePluginsDisabled: failedDisables.length === 0, checks };
  await writeFile('artifacts/M2/security-live.json', `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ kind: evidence.kind, passed: evidence.passed, failed: evidence.failed, verifiedPlugins: verifiedPlugins.length, allFixturePluginsDisabled: evidence.allFixturePluginsDisabled }));
}
