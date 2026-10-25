import { randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { M5Harness, entity, rows, scope, strongPassword } from './lib/m5-harness.mjs';
import { compareRealNativePrometheus } from './lib/m5-native-oracle.mjs';
import { compareRealLokiEvents } from './lib/m5-loki-oracle.mjs';
import { compareRealConsumerPrometheus, collectorCounterTotal } from './lib/m5-consumer-oracle.mjs';
import { proveRealEpochIsolation, proveRealCollectorSanitization } from './lib/m5-epoch-proof.mjs';
import { recoverKnownLegacyReceipts } from './lib/m5-legacy-recovery.mjs';

// Source preparation only until Root explicitly hands over the unified runtime.
// All remote bodies/tokens stay private. No arbitrary Admin/PromQL proxy exists.
const h = new M5Harness();
let admin, c1, c2, pay, ops;
const accounts = {}, fixtures = {}, sources = {};
const vitals = (cluster, workspace, route, query = {}) => scope(`/clusters/${cluster.id}/vitals/${route}`, workspace, query);
const grant = (scopeType, values, workspace = pay, cluster = c1, action = 'read') => ({ module: 'monitoring', action, scope_type: scopeType, cluster_id: cluster?.id ?? null, workspace_id: workspace?.id ?? null, scope_values: values });
const timeWindow = () => { const end = Math.floor(Date.now() / 1000) * 1000; return { start: new Date(end - 300_000).toISOString(), end: new Date(end).toISOString(), step: 15 }; };
async function makeAccount(label, permissions, binding = {}) {
  const password = h.remember(strongPassword());
  const user = h.ok(await h.request(admin, '/iam/users', 'POST', { username: `${h.tag}-${label}`, password, display_name: `M5 ${label}` }), 'IAM', 'ordinary monitoring fixture account');
  const role = h.ok(await h.request(admin, '/iam/roles', 'POST', { code: `${h.tag}-${label}`, name: `${h.tag}-${label}`, description: 'isolated M5 monitoring permission test' }), 'IAM', 'monitoring fixture role');
  const changed = h.ok(await h.request(admin, `/iam/roles/${role.id}/permissions`, 'PUT', { revision: role.revision, permissions }), 'IAM', 'complete monitoring permission tuples');
  const bound = h.ok(await h.request(admin, `/iam/users/${user.id}/role-bindings`, 'POST', { role_id: role.id, ...binding }), 'IAM', 'monitoring fixture role binding');
  let session = await h.login(user.username, password), currentPassword = password;
  if (user.force_password_change || session.user.forcePasswordChange || session.user.force_password_change) {
    currentPassword = h.remember(strongPassword());
    h.ok(await h.request(session, '/auth/me/password', 'POST', { revision: user.revision, current_password: password, new_password: currentPassword, confirmed: true }), 'IAM', 'mandatory fixture password rotation');
    session = await h.login(user.username, currentPassword);
  }
  h.users.push({ id: user.id, username: user.username, password: currentPassword, label });
  accounts[label] = { user, session, role: { ...role, ...(changed?.role ?? {}) }, binding: bound };
  return accounts[label];
}
async function overview(session, cluster, workspace, query = {}, id = 'Metrics') {
  const response = await h.request(session, vitals(cluster, workspace, 'overview', { ...timeWindow(), ...query }));
  const result = h.ok(response, id, 'scoped real monitoring overview');
  h.check(!h.secrets.filter(Boolean).some(secret => response.text.includes(secret)), id, 'overview exposes no known password, API key, collector token or cookie');
  h.check(result.clusterId === cluster.id && result.workspaceId === workspace.id && result.quality?.historicalScope === 'current_epoch', id, 'response preserves exact context and explicitly current-epoch history');
  h.check(Object.values(result.series).every(points => points.length <= 800 && points.every(point => point.value === null || typeof point.value === 'number' && Number.isFinite(point.value))), id, 'public samples are bounded finite numbers or explicit null');
  return result;
}
async function setup(cluster, workspace, sourceId, mode) {
  const key = randomUUID();
  const attempt = { clusterId: cluster.id, workspaceId: workspace.id, sourceId, mode, idempotencyKey: key, startedAt: new Date().toISOString() };
  h.privateSetupAttempts.push(attempt);
  h.persistReference();
  const response = await h.request(admin, vitals(cluster, workspace, 'setup'), 'POST', { sourceId, mode, confirmed: true, confirm_name: cluster.name }, { key });
  attempt.status = response.status;
  h.persistReference();
  h.public.setupAttempts ??= [];
  h.public.setupAttempts.push({ ...attempt });
  const result = h.ok(response, 'Setup', 'typed platform-authorized audited monitoring setup');
  const receipt = h.ok(await h.request(admin, vitals(cluster, workspace, `setup/receipts/by-key/${key}`)), 'Setup/Receipt', 'original caller key reads the dedicated complete monitoring parent receipt');
  h.check(receipt.parentState === 'succeeded' && receipt.workspaceId === workspace.id && receipt.steps.length >= 2 && receipt.steps.every(step => step.state === 'succeeded' && step.remoteCompleted), 'Setup/Receipt', 'parent receipt proves every native step and settings commit without pretending the marker alone is success');
  h.check(!h.secrets.filter(Boolean).some(secret => JSON.stringify(receipt).includes(secret)), 'Setup/Receipt', 'monitoring parent receipt contains no raw ingest token or private config');
  if (mode === 'collector') {
    const ids = [result.pluginId, result.collectorPluginId];
    h.check(ids.every(value => typeof value === 'string' && /^[\da-f-]{36}$/.test(value)), 'Setup/Replay', 'completed collector receipt identifies both actual native plugin instances');
    const before = ids.map(id => h.native(cluster, `/plugins/${id}`));
    h.check(before.every(value => value.status === 200), 'Setup/Replay', 'native configuration is read privately before same-original-key terminal replay');
    const writeCount = h.successfulWrites.length;
    const replayResponse = await h.request(admin, vitals(cluster, workspace, 'setup'), 'POST', { sourceId, mode, confirmed: true, confirm_name: cluster.name }, { key });
    const replayed = h.ok(replayResponse, 'Setup/Replay', 'terminal complete setup reuses its recorded original key');
    // This cached idempotent readback produces no new configuration write.
    // Keep its HTTP evidence separately from actual write audit coverage.
    const replayRequests = h.successfulWrites.splice(writeCount);
    h.check(replayRequests.length === 1, 'Setup/Replay', 'one explicit completed-result replay has one HTTP receipt and no automatic retry');
    const again = h.ok(await h.request(admin, vitals(cluster, workspace, `setup/receipts/by-key/${key}`)), 'Setup/Replay', 'same-original-key dedicated parent receipt remains complete');
    const after = ids.map(id => h.native(cluster, `/plugins/${id}`));
    h.check(again.parentState === 'succeeded' && JSON.stringify(again.steps) === JSON.stringify(receipt.steps) && replayed.settingsRevision === result.settingsRevision && after.every((value, index) => value.status === 200 && JSON.stringify(value.body) === JSON.stringify(before[index].body)), 'Setup/Replay', 'complete replay retains every native step ID, settings revision and full private native configuration');
    h.public.setupReplayProof ??= [];
    h.public.setupReplayProof.push({ clusterId: cluster.id, workspaceId: workspace.id, idempotencyKey: key, requestId: replayRequests[0].requestId, completedParentReceipt: true, unchangedNativeConfiguration: true, excludedFromNewConfigurationWriteCount: true });
  }
  return result;
}
function currentToken(clusterId, purpose, generation) {
  const value = h.privateTokens.findLast(token => token.clusterId === clusterId && token.purpose === purpose && token.generation === generation);
  h.check(Boolean(value), 'Tokens', `trusted private reference contains current ${purpose} identity`);
  return value.token;
}
function probePrivate(clusterId, purpose, token) {
  if (purpose === 'native_scrape') return h.internal('bridge', `/scrape/${clusterId}`, { token });
  if (purpose === 'collector_catalog') return h.internal('bridge', `/catalog/${clusterId}`, { token });
  if (purpose === 'collector_scrape') return h.internal('collector', `/metrics/${clusterId}`, { token });
  const encoded = h.remember(Buffer.from(`kongos:${token}`).toString('base64'));
  return h.internal('collector', `/ingest/${clusterId}`, { method: 'POST', headers: { Authorization: `Basic ${encoded}` }, body: {} });
}
function tokenMatrix(cluster, foreignCluster, capabilities, foreignCapabilities) {
  const purposes = ['native_scrape', 'collector_scrape', 'collector_catalog', 'collector_ingest'];
  for (const destination of purposes) for (const credential of purposes) {
    const response = probePrivate(cluster.id, destination, currentToken(cluster.id, credential, capabilities.credentialGeneration));
    h.check(destination === credential ? (destination === 'collector_ingest' ? [202, 400].includes(response.status) : response.status === 200) : [401, 403].includes(response.status), 'Tokens/Purpose', `${credential} cannot substitute for ${destination} except its own purpose`, { status: response.status });
  }
  for (const purpose of purposes) {
    h.check([401, 403].includes(probePrivate(cluster.id, purpose, currentToken(foreignCluster.id, purpose, foreignCapabilities.credentialGeneration)).status), 'Tokens/Cluster', `${purpose} from actual C2 cannot access C1`);
    h.check([401, 403].includes(probePrivate(cluster.id, purpose, h.remember(randomBytes(32).toString('base64url'))).status), 'Tokens/Invalid', `${purpose} refuses an unrelated random token`);
  }
}
function currentCatalog(cluster, generation) {
  const token = currentToken(cluster.id, 'collector_catalog', generation);
  const result = []; let cursor;
  for (let page = 0; page < 100; page++) {
    const query = new URLSearchParams({ size: '100', ...(cursor ? { cursor } : {}) });
    const response = h.internal('bridge', `/catalog/${cluster.id}?${query}`, { token });
    h.check(response.status === 200 && response.json?.complete === true && response.json?.blocked === false, 'Catalog', 'private current catalog is authenticated, complete and unblocked');
    result.push(...response.json.items);
    h.check(result.length <= 10_000, 'Catalog', 'trusted catalog read respects its shared record budget');
    cursor = response.json.nextCursor;
    if (!cursor) return result;
  }
  h.check(false, 'Catalog', 'trusted catalog read never exceeds100pages');
}
async function createTrafficGraph(cluster, workspace, label, ids = {}) {
  const service = await h.create(admin, cluster, workspace, 'services', { ...(ids.service ? { id: ids.service } : {}), name: `${h.tag}-${label}`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:pay'] }, 'Fixtures');
  const route = await h.create(admin, cluster, workspace, 'routes', { ...(ids.route ? { id: ids.route } : {}), name: `${h.tag}-${label}-ok`, service: { id: service.id }, paths: [`/m5/${h.tag}/${label}/ok`], protocols: ['http'], tags: [h.tag, 'team:pay'] }, 'Fixtures');
  const consumer = await h.create(admin, cluster, workspace, 'consumers', { username: `${h.tag}-${label}`, tags: [h.tag, 'team:pay'] }, 'Fixtures');
  const apiKey = h.remember(`m5-key-${randomUUID()}`);
  const credential = entity(h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/consumers/${consumer.id}/credentials/key-auth`, workspace), 'POST', { key: apiKey, tags: [h.tag, 'team:pay'] }), 'Fixtures', 'real Consumer API key fixture'));
  await h.create(admin, cluster, workspace, 'plugins', { name: 'key-auth', service: { id: service.id }, config: { hide_credentials: true }, enabled: true, tags: [h.tag, 'team:pay'] }, 'Fixtures');
  const statuses = {};
  for (const code of [404, 500]) {
    const statusRoute = await h.create(admin, cluster, workspace, 'routes', { name: `${h.tag}-${label}-${code}`, service: { id: service.id }, paths: [`/m5/${h.tag}/${label}/${code}`], protocols: ['http'], tags: [h.tag, 'team:pay'] }, 'Fixtures');
    await h.create(admin, cluster, workspace, 'plugins', { name: 'request-termination', route: { id: statusRoute.id }, config: { status_code: code, message: 'M5 controlled status fixture' }, enabled: true, tags: [h.tag, 'team:pay'] }, 'Fixtures');
    statuses[code] = statusRoute;
  }
  return { service, route, consumer, apiKey, credentialId: credential.id, statuses, label };
}

let failure;
try {
  h.check(process.env.M5_DEPLOYMENT_READY === 'true', 'GATE', 'explicit unified M5 deployment and exclusive write handoff is required');
  admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  const clusters = rows(h.ok(await h.request(admin, '/clusters'), 'Fixture', 'current registered cluster discovery'));
  c1 = clusters.find(cluster => cluster.labels?.includes('bootstrap') && cluster.execution_mode === 'direct');
  c2 = clusters.find(cluster => cluster.admin_url?.replace(/\/$/, '') === 'http://kong-secondary:8001' && cluster.execution_mode === 'direct');
  h.check(c1 && c2 && c1.id !== c2.id && c1.admin_url !== c2.admin_url, 'Dual', 'two genuine independent gateways are selected');
  h.public.legacyRecovery = await recoverKnownLegacyReceipts(h, admin, c1);
  const makeWorkspace = async (cluster, name) => h.ok(await h.request(admin, `/clusters/${cluster.id}/workspaces`, 'POST', { code: `${h.tag.replace(/-/g, '_')}_${name}`, name: `${h.tag}-${name}-${cluster.id.slice(0, 6)}` }), 'Fixture', 'isolated monitoring workspace');
  pay = await makeWorkspace(c1, 'pay'); ops = await makeWorkspace(c1, 'ops');
  const pay2 = await makeWorkspace(c2, 'pay');
  h.public = { ...h.public, clusterId: c1.id, secondaryClusterId: c2.id, payWorkspace: pay, opsWorkspace: ops, secondaryPayWorkspace: pay2 };
  for (const cluster of [c1, c2]) {
    const list = rows(h.ok(await h.request(admin, `/clusters/${cluster.id}/data-sources`), 'Sources', 'registered cluster-specific data sources'));
    for (const type of ['prometheus', 'loki']) if (!list.some(value => value.type === type && value.enabled)) {
      const created = h.ok(await h.request(admin, `/clusters/${cluster.id}/data-sources`, 'POST', { name: `${h.tag}-${type}`, type, base_url: type === 'prometheus' ? 'http://prometheus:9090' : 'http://loki:3100', enabled: true }), 'Sources', 'normal audited BFF registers a missing fixed monitoring provider for the actual cluster');
      list.push(created);
      h.public.createdDataSources ??= [];
      h.public.createdDataSources.push({ id: created.id, clusterId: cluster.id, name: created.name, type: created.type });
    }
    sources[cluster.id] = { prometheus: list.find(value => value.type === 'prometheus' && value.enabled), loki: list.find(value => value.type === 'loki' && value.enabled) };
    h.check(sources[cluster.id].prometheus && sources[cluster.id].loki, 'Sources', 'real Prometheus and Loki are both explicitly registered');
    const workspace = cluster.id === c1.id ? pay : pay2;
    await setup(cluster, workspace, sources[cluster.id].prometheus.id, 'native_prometheus');
    await setup(cluster, workspace, sources[cluster.id].prometheus.id, 'collector');
  }
  const shared = { service: randomUUID(), route: randomUUID() };
  fixtures.primary = await createTrafficGraph(c1, pay, 'primary', shared);
  fixtures.secondary = await createTrafficGraph(c2, pay2, 'secondary', shared);
  fixtures.unused = await h.create(admin, c1, pay, 'services', { name: `${h.tag}-no-traffic`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:pay'] }, 'Fixtures');
  fixtures.foreign = await h.create(admin, c1, pay, 'services', { name: `${h.tag}-other-tag`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:other'] }, 'Fixtures');
  fixtures.ops = await h.create(admin, c1, ops, 'services', { name: `${h.tag}-other-workspace`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:pay'] }, 'Fixtures');
  fixtures.opsRoute = await h.create(admin, c1, ops, 'routes', { name: `${h.tag}-cross-workspace`, service: { id: fixtures.ops.id }, paths: [`/m5/${h.tag}/cross-workspace`], protocols: ['http'], tags: [h.tag, 'team:pay'] }, 'Fixtures');
  await h.create(admin, c1, ops, 'plugins', { name: 'key-auth', service: { id: fixtures.ops.id }, config: { hide_credentials: true }, enabled: true, tags: [h.tag, 'team:pay'] }, 'Fixtures');
  fixtures.epoch = await createTrafficGraph(c1, pay, 'epoch');
  h.public.fixtureIds = { service: shared.service, route: shared.route, primaryConsumer: fixtures.primary.consumer.id, secondaryConsumer: fixtures.secondary.consumer.id, unusedService: fixtures.unused.id, foreignService: fixtures.foreign.id, opsService: fixtures.ops.id };
  h.public.sources = Object.fromEntries(Object.entries(sources).map(([cid, values]) => [cid, Object.fromEntries(Object.entries(values).map(([type, value]) => [type, { id: value.id, name: value.name }]))]));
  await makeAccount('monitor-workspace', [grant('workspace', [pay.id])]);
  await makeAccount('monitor-tags', [grant('tag_group', ['team:pay', 'team:ops'])]);
  await makeAccount('monitor-service', [grant('entity', [{ entity_type: 'services', entity_id: shared.service }])]);
  await makeAccount('monitor-route', [grant('entity', [{ entity_type: 'routes', entity_id: shared.route }])]);
  await makeAccount('monitor-consumer', [grant('entity', [{ entity_type: 'consumers', entity_id: fixtures.primary.consumer.id }])]);
  await makeAccount('monitor-tuple-mix', [grant('entity', [{ entity_type: 'services', entity_id: shared.service }]), grant('workspace', [pay.id], pay, c1, 'write')]);
  await makeAccount('monitor-cluster', [grant('global', [], null, null)], { cluster_id: c1.id });
  await makeAccount('config-only', [{ module: 'services', action: 'read', scope_type: 'workspace', cluster_id: c1.id, workspace_id: pay.id, scope_values: [pay.id] }]);
  h.public.accounts = Object.fromEntries(Object.entries(accounts).map(([label, account]) => [label, { id: account.user.id, username: account.user.username, role: { id: account.role.id, name: account.role.name }, binding: { id: account.binding.id, revision: account.binding.revision } }]));
  const caps = h.ok(await h.request(admin, vitals(c1, pay, 'capabilities')), 'Caps', 'actual primary monitoring capability discovery');
  const caps2 = h.ok(await h.request(admin, vitals(c2, pay2, 'capabilities')), 'Caps', 'actual secondary monitoring capability discovery');
  h.check(caps.configured && caps.collectorEnabled && caps2.configured && caps2.collectorEnabled, 'Caps', 'both native and Consumer collection channels are configured');
  tokenMatrix(c1, c2, caps, caps2);
  for (const privatePath of [`/scrape/${c1.id}`, `/catalog/${c1.id}`]) {
    const purpose = privatePath.startsWith('/scrape/') ? 'native_scrape' : 'collector_catalog';
    h.check(h.internal('bridge', privatePath, { token: currentToken(c1.id, purpose, caps.credentialGeneration), headers: { Cookie: admin.cookie } }).status === 401, 'Private/Cookies', 'even correct bridge token never mixes with MainHTTP actor cookies');
    h.check(h.internal('bridge', privatePath, { headers: { Cookie: admin.cookie } }).status === 401, 'Private/Cookies', 'platform actor cookie alone is not a private bridge identity');
  }
  h.check(h.internal('collector', `/metrics/${c1.id}`, { headers: { Cookie: admin.cookie } }).status === 401, 'Private/Cookies', 'collector never accepts the platform actor cookie as a scrape credential');
  for (const source of ['scrape', 'catalog', 'ingest']) for (const session of [null, accounts['monitor-workspace'].session, admin]) await h.reject(session, `/${source}/${c1.id}`, 'GET', undefined, 'Private/Public', 'public/main BFF never upgrades ordinary cookies or admin JWT into a collector identity', [401, 403, 404]);
  const nativeForbidden = await h.request(accounts['monitor-workspace'].session, scope(`/clusters/${c1.id}/entities/services/${shared.service}`, pay));
  h.check(nativeForbidden.status === 403, 'Scope', 'monitoring-only permission never grants native Service configuration read');
  await h.reject(accounts['config-only'].session, vitals(c1, pay, 'capabilities'), 'GET', undefined, 'Scope', 'native configuration read does not grant monitoring read');
  for (const [account, target, query] of [
    [accounts['monitor-workspace'], ops, {}], [accounts['monitor-tags'], pay, { serviceId: fixtures.foreign.id }],
    [accounts['monitor-service'], pay, { routeId: shared.route }], [accounts['monitor-route'], pay, { serviceId: shared.service }],
    [accounts['monitor-tuple-mix'], pay, { serviceId: fixtures.foreign.id }], [accounts['monitor-workspace'], pay, { scope: 'cluster' }],
  ]) await h.reject(account.session, vitals(c1, target, 'overview', { ...timeWindow(), ...query }), 'GET', undefined, 'Scope/FourTuple', 'current monitoring dimensions and explicit hierarchy cannot be unioned or broadened');
  await h.reject(accounts['monitor-cluster'].session, vitals(c2, pay2, 'overview', timeWindow()), 'GET', undefined, 'Scope/Cluster', 'C1 whole-cluster monitoring binding cannot read actual C2');
  await h.reject(accounts['monitor-service'].session, vitals(c2, pay2, 'overview', { ...timeWindow(), serviceId: shared.service }), 'GET', undefined, 'Scope/TypedCluster', 'typed C1 Service permission cannot read the identical actual UUID in C2');
  await h.reject(accounts['monitor-workspace'].session, vitals(c1, pay, 'overview', { ...timeWindow(), sourceId: sources[c2.id].prometheus.id }), 'GET', undefined, 'Scope/Source', 'actual C2 source ID cannot be used in C1', [403, 404]);
  const identities = h.ok(await h.request(accounts['monitor-service'].session, vitals(c1, pay, 'entities', { type: 'services', size: 20 })), 'Scope/Minimal', 'monitoring identity selector works without native configuration read');
  h.check(rows(identities).some(value => value.id === shared.service) && rows(identities).every(value => Object.keys(value).every(key => ['id', 'name', 'parentName'].includes(key))), 'Scope/Minimal', 'selector returns only actual authorized IDs and display names');
  const noTraffic = await overview(accounts['monitor-workspace'].session, c1, pay, { serviceId: fixtures.unused.id }, 'Null');
  h.check(noTraffic.cards.qps.value === null && noTraffic.series.qps.every(point => point.value === null), 'Null', 'new unused counter is unavailable/null and is never invented as zero');
  const beforeInvalid = h.providerQueryCount('prometheus');
  const validWindow = timeWindow();
  const invalidQueries = [
    { query: 'up' }, { promql: 'sum(up)' }, { url: 'http://kong:8001/' }, { path: '/cache' }, { template: 'all' }, { consumerId: fixtures.primary.consumer.id }, { rateWindow: 1 },
    { scope: 'global' }, { serviceId: 'name-not-uuid' }, { routeId: `${shared.route}" or true` }, { start: '2026-02-30T00:00:00Z' }, { end: '2026-02-30T00:00:00Z' },
    { start: validWindow.start.replace('Z', '+00:00') }, { end: new Date(Date.now() + 60_000).toISOString() }, { start: validWindow.end },
    { start: new Date(Date.parse(validWindow.end) - 8 * 86400_000).toISOString() }, { start: new Date(Date.parse(validWindow.end) - 299_000).toISOString() },
    { step: 0 }, { step: 14 }, { step: 15.5 }, { step: 'NaN' }, { step: '1e3' }, { step: 86401 },
    { start: new Date(Date.parse(validWindow.end) - 7 * 86400_000).toISOString(), step: 15 },
  ];
  for (const query of invalidQueries) await h.reject(admin, vitals(c1, pay, 'overview', { ...validWindow, ...query }), 'GET', undefined, 'Input/Budget', 'unknown fields, invalid time/selector and excessive point requests are rejected before querying', [400]);
  await h.reject(admin, `${vitals(c1, pay, 'overview', validWindow)}&workspaceId=${ops.id}`, 'GET', undefined, 'Input/Budget', 'duplicate scope parameters are rejected', [400]);
  const afterInvalid = h.providerQueryCount('prometheus');
  h.check(beforeInvalid.observed && afterInvalid.observed && beforeInvalid.count === afterInvalid.count, 'Input/ActualQueries', 'actual Prometheus query counters do not increase during malformed request suite');
  h.public.invalidQueryProof = { requests: invalidQueries.length + 1, actualPromQueryCountUnchanged: true };
  // Finish every native configuration write before measuring the stable final
  // 80-second window; native-write fencing conservatively closes CID epochs.
  const newFamily = { clusterId: c1.id, generation: caps.credentialGeneration + 1, credentials: ['native_scrape', 'collector_scrape', 'collector_catalog', 'collector_ingest'].map(purpose => ({ purpose, audience: purpose === 'native_scrape' || purpose === 'collector_catalog' ? 'bff' : 'collector', token: randomBytes(32).toString('base64url') })) };
  const previous = new Map(newFamily.credentials.map(value => [value.purpose, currentToken(c1.id, value.purpose, caps.credentialGeneration)]));
  h.rememberTokenSet(newFamily);
  const rotation = JSON.parse(execFileSync('node', ['deploy/scripts/rotate-metrics.mjs', '--confirmed', '--multicluster'], { input: JSON.stringify(newFamily), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  h.check(!h.secrets.filter(Boolean).some(secret => JSON.stringify(rotation).includes(secret)), 'Tokens/Rotation', 'actual trusted rotation helper never emits raw secrets');
  for (const credential of newFamily.credentials) {
    h.check([401, 403].includes(probePrivate(c1.id, credential.purpose, previous.get(credential.purpose)).status), 'Tokens/Rotation', `${credential.purpose} old generation is immediately revoked`);
    const renewed = probePrivate(c1.id, credential.purpose, credential.token);
    h.check(credential.purpose === 'collector_ingest' ? [202, 400].includes(renewed.status) : renewed.status === 200, 'Tokens/Rotation', `${credential.purpose} fresh generation remains purpose-valid`);
  }
  await setup(c1, pay, sources[c1.id].prometheus.id, 'collector');
  caps.credentialGeneration = newFamily.generation;
  h.public.tokenProof = { purposes: 4, samePurposeOnly: true, crossClusterDenied: true, actualRotationOldTokensRevoked: true, runtimeCredentialsNeverPublished: true };
  h.public.epochProof = await proveRealEpochIsolation(h, { admin, cluster: c1, source: pay, target: ops, graph: fixtures.epoch, taggedActor: accounts['monitor-tags'].session, catalog: () => currentCatalog(c1, caps.credentialGeneration), overview });
  const canary = h.remember(`m5-canary-${randomUUID()}`);
  h.public.collectorSanitization = proveRealCollectorSanitization(h, { cluster: c1, graph: fixtures.epoch, token: currentToken(c1.id, 'collector_ingest', caps.credentialGeneration), scrapeToken: currentToken(c1.id, 'collector_scrape', caps.credentialGeneration), foreignConsumerId: fixtures.primary.consumer.id, canary });
  const sanitizedLogQuery = new URLSearchParams({ query: `{job="kongos-collector",cluster_id="${c1.id}",route_id="${fixtures.epoch.route.id}"}`, start: String(BigInt(Date.now() - 60_000) * 1_000_000n), end: String(BigInt(Date.now()) * 1_000_000n), limit: '100' });
  const sanitizedLogs = await h.poll(() => h.internal('loki', `/loki/api/v1/query_range?${sanitizedLogQuery}`), reply => reply.status === 200 && reply.json?.data?.result?.some(stream => stream.values.some(([, line]) => JSON.parse(line).code === '201')), 'bounded read observes actual sanitized Loki delivery', { timeoutMs: 10_000, intervalMs: 500 });
  h.check(sanitizedLogs.status === 200 && sanitizedLogs.json?.data?.result?.some(stream => stream.values.some(([, line]) => JSON.parse(line).code === '201')), 'Collector/Loki', 'explicit canary-bearing raw event produces a real minimal Loki observation');
  h.check(!h.secrets.filter(Boolean).some(secret => sanitizedLogs.text.includes(secret)), 'Collector/Loki', 'actual duplicate-event Loki observation discards raw body, query, URL, Cookie and header secrets');
  const traffic = [];
  for (const [cluster, graph] of [[c1, fixtures.primary], [c2, fixtures.secondary]]) for (const status of [200, 404, 500]) {
    const path = `/m5/${h.tag}/${graph.label}/${status === 200 ? 'ok' : status}`;
    await h.waitProxy(cluster, path, status, { apikey: graph.apiKey });
  }
  const trafficStarted = Date.now();
  while (Date.now() - trafficStarted < 80_000) {
    for (const [cluster, graph] of [[c1, fixtures.primary], [c2, fixtures.secondary]]) for (const status of [200, 404, 500]) {
      const path = `/m5/${h.tag}/${graph.label}/${status === 200 ? 'ok' : status}?canary=${encodeURIComponent(canary)}`;
      const observed = await h.proxy(cluster, path, 'GET', undefined, { apikey: graph.apiKey, 'X-M5-Canary': canary });
      h.check(observed === status, 'Traffic', `actual C${cluster.id === c1.id ? 1 : 2} proxy produces configured HTTP${status}`);
      traffic.push({ clusterId: cluster.id, status });
    }
    h.check(await h.proxy(c1, `/m5/${h.tag}/cross-workspace`, 'GET', undefined, { apikey: fixtures.primary.apiKey }) === 200, 'Consumer/CrossWorkspace', 'actual OSS gateway accepts a same-Consumer request routed through another console workspace');
    await new Promise(resolve => setTimeout(resolve, 750));
  }
  const evaluatedWindow = timeWindow();
  const measured = await overview(admin, c1, pay, { ...evaluatedWindow, serviceId: shared.service }, 'Oracle');
  const measured2 = await overview(admin, c2, pay2, { ...evaluatedWindow, serviceId: shared.service }, 'Oracle/Dual');
  const currentPrimary = currentCatalog(c1, caps.credentialGeneration).filter(epoch => epoch.closed_at === null);
  const currentSecondary = currentCatalog(c2, caps2.credentialGeneration).filter(epoch => epoch.closed_at === null);
  h.public.prometheusOracle = { primary: compareRealNativePrometheus(h, measured, { clusterId: c1.id, workspaceId: pay.id, serviceId: shared.service, epochs: currentPrimary }), secondary: compareRealNativePrometheus(h, measured2, { clusterId: c2.id, workspaceId: pay2.id, serviceId: shared.service, epochs: currentSecondary }) };
  h.public.traffic = { startedAt: new Date(trafficStarted).toISOString(), durationMs: Date.now() - trafficStarted, requests: traffic.length, statuses: [...new Set(traffic.map(item => item.status))], realDualCluster: true, includedAuthenticatedConsumer: true };
  h.privateTraffic = [[c1, fixtures.primary], [c2, fixtures.secondary]].flatMap(([cluster, graph]) => [200, 404, 500].map(status => ({ origin: cluster.id === c1.id ? 'http://127.0.0.1:8000' : 'http://127.0.0.1:9000', path: `/m5/${h.tag}/${graph.label}/${status === 200 ? 'ok' : status}`, apiKey: graph.apiKey, status })));
  const workspaceMetrics = await overview(accounts['monitor-workspace'].session, c1, pay, { ...evaluatedWindow }, 'Scope/Positive');
  const serviceMetrics = await overview(accounts['monitor-service'].session, c1, pay, { ...evaluatedWindow, serviceId: shared.service }, 'Scope/Positive');
  const routeMetrics = await overview(accounts['monitor-route'].session, c1, pay, { ...evaluatedWindow, routeId: shared.route }, 'Scope/Positive');
  const consumerMetrics = await overview(accounts['monitor-consumer'].session, c1, pay, evaluatedWindow, 'Consumer/Positive');
  h.check(workspaceMetrics.cards.qps.value !== null && serviceMetrics.cards.qps.value !== null && routeMetrics.cards.qps.value !== null, 'Scope/Positive', 'workspace, Service-only and Route-only monitoring scopes obtain real samples');
  h.check(consumerMetrics.topN.consumers.some(value => value.id === fixtures.primary.consumer.id && value.value > 0) && consumerMetrics.topN.consumers.every(value => value.id === fixtures.primary.consumer.id), 'Consumer', 'real http-log channel supplies own Consumer TopN without native config permission');
  h.check(consumerMetrics.series.qps.every(point => point.value === null) && consumerMetrics.topN.services.length === 0, 'Consumer', 'Consumer-only native-unavailable series is not replaced with whole-Service traffic');
  h.public.consumerOracle = compareRealConsumerPrometheus(h, consumerMetrics, { clusterId: c1.id, workspaceId: pay.id, consumerId: fixtures.primary.consumer.id, epochs: currentPrimary });
  const collectorProof = h.internal('collector', `/metrics/${c1.id}`, { token: currentToken(c1.id, 'collector_scrape', caps.credentialGeneration) });
  h.check(collectorProof.status === 200 && collectorCounterTotal(collectorProof.text, { route_id: fixtures.opsRoute.id, consumer_id: fixtures.primary.consumer.id }) === 0, 'Consumer/CrossWorkspace', 'actual cross-workspace request never enters the authorized Consumer collector series');
  h.public.consumerCrossWorkspaceProof = { realProxyAccepted: true, consumerCollectorEvents: 0, closedAndForeignEpochsExcluded: true };
  const lokiMetrics = await overview(accounts['monitor-workspace'].session, c1, pay, { ...evaluatedWindow, sourceId: sources[c1.id].loki.id, serviceId: shared.service }, 'Loki/Actual');
  h.check(lokiMetrics.source?.type === 'loki' && lokiMetrics.cards.qps.value !== null, 'Loki/Actual', 'actual Loki channel supplies scoped observations rather than connectivity alone');
  const lokiSearch = new URLSearchParams({ query: `{job="kongos-collector",cluster_id="${c1.id}",workspace_id="${pay.id}",service_id="${shared.service}"}`, start: String(Date.parse(evaluatedWindow.start) * 1e6), end: String(Date.parse(evaluatedWindow.end) * 1e6), limit: '1000' });
  const lokiReply = h.internal('loki', `/loki/api/v1/query_range?${lokiSearch}`);
  h.check(lokiReply.status === 200 && lokiReply.json?.data?.result?.length > 0, 'Loki/Actual', 'real Loki stores collector minimal event observations');
  h.check(!h.secrets.filter(Boolean).some(secret => lokiReply.text.includes(secret)), 'Loki/Secrets', 'actual Loki data contains no known canary, key, token, header or cookie value');
  h.check(lokiReply.json.data.result.reduce((total, stream) => total + stream.values.length, 0) < 1000, 'Loki/Oracle', 'raw event oracle stays below its explicit limit without silently truncated evidence');
  const catalog = currentCatalog(c1, caps.credentialGeneration).filter(epoch => epoch.closed_at === null);
  h.public.lokiOracle = compareRealLokiEvents(h, lokiMetrics, lokiReply.json.data.result, catalog.filter(epoch => epoch.entity_type === 'routes' && epoch.service_id === shared.service && epoch.workspace_id === pay.id));
  const beforeInvalidLoki = h.providerQueryCount('loki');
  for (const query of [{ logql: '{job="any"}' }, { query: '{job="any"}' }, { url: 'http://kong:8001' }, { scope: 'any' }, { step: 1 }]) await h.reject(admin, vitals(c1, pay, 'overview', { ...evaluatedWindow, sourceId: sources[c1.id].loki.id, ...query }), 'GET', undefined, 'Loki/Input', 'malicious Loki query, URL, scope and resolution fail before provider access', [400]);
  const afterInvalidLoki = h.providerQueryCount('loki');
  h.check(beforeInvalidLoki.observed && afterInvalidLoki.observed && beforeInvalidLoki.count === afterInvalidLoki.count, 'Loki/Input', 'actual Loki query instrumentation does not increase during rejected malformed requests');
  for (const service of ['telemetry-collector', 'console-api', 'console-web', 'kong', 'kong-secondary', 'loki']) {
    const logText = h.logs(service);
    h.check(!h.secrets.filter(Boolean).some(secret => logText.includes(secret)), 'Logs/Secrets', `${service} actual logs contain no known runtime secret or raw canary`);
  }
  const clusterMetrics = await overview(accounts['monitor-cluster'].session, c1, pay, { ...evaluatedWindow, scope: 'cluster' }, 'Cluster/Positive');
  h.check(clusterMetrics.scope === 'cluster' && clusterMetrics.nodes.some(node => node.online === 1 && node.datastoreReachable === 1), 'Cluster/Nodes', 'proper whole-cluster monitoring grant obtains actual node gauges');
  const binding = accounts['monitor-service'];
  h.ok(await h.request(admin, `/iam/users/${binding.user.id}/role-bindings/${binding.binding.id}`, 'DELETE', { revision: binding.binding.revision, confirmed: true, confirm_name: binding.role.name }), 'Revocation', 'actual monitoring role binding revocation');
  await h.reject(binding.session, vitals(c1, pay, 'overview', { ...evaluatedWindow, serviceId: shared.service }), 'GET', undefined, 'Revocation', 'existing cookies and old evaluation window cannot bypass immediate permission revocation');
  // Keep a separate live workspace actor for the browser gate.
  await makeAccount('browser-revoke', [grant('workspace', [pay.id])]);
  h.public.accounts = Object.fromEntries(Object.entries(accounts).map(([label, account]) => [label, { id: account.user.id, username: account.user.username, role: { id: account.role.id, name: account.role.name }, binding: { id: account.binding.id, revision: account.binding.revision } }]));
  h.public.savedEvaluationWindow = evaluatedWindow;
  h.verifyAuditCoverage();
} catch (error) { failure = error; }
process.exitCode = await h.finish(failure);
