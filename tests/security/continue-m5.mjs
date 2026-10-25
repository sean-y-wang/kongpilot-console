import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { M5Harness, rows, scope, strongPassword } from './lib/m5-harness.mjs';
import { compareRealNativePrometheus } from './lib/m5-native-oracle.mjs';
import { compareRealConsumerPrometheus } from './lib/m5-consumer-oracle.mjs';
import { compareRealLokiEvents } from './lib/m5-loki-oracle.mjs';

// Explicit checkpoint continuation: never calls setup, enroll, rotation,
// recovery, migration or native configuration creation/update.
const h = new M5Harness();
const checkpointPath = '/tmp/kongos-m5-continuation.json';
let failure;
try {
  h.check(process.env.M5_CONTINUATION_READY === 'true', 'Continuation/Gate', 'explicit patched runtime and exclusive continuation handoff required');
  h.check((statSync(checkpointPath).mode & 0o777) === 0o600, 'Continuation/Gate', 'existing fixture/window checkpoint is private0600');
  const original = JSON.parse(readFileSync(checkpointPath, 'utf8'));
  h.check(original.passed === 1220 && original.failed === 1 && /^m5-security-[\da-f]{8}$/.test(original.testTag), 'Continuation/Gate', 'only the preserved identified second-attempt Loki checkpoint may continue');
  const passedGateChecks = h.checks;
  h.checks = [...original.checks.filter(check => check.passed), ...passedGateChecks];
  h.tag = original.testTag;
  const { checks, fixtures, passed, failed, lastHttpRequest, performedAt, kind, currentEpochs, checkpointWindow, ...safeOriginal } = original;
  h.public = { ...safeOriginal, continuation: { checkpointEvidence: 'security-live-second-attempt.json', preservedPassedChecks: passed, originalFailurePreserved: true, noSetupRecoveryRotationOrNativeConfigurationReplay: true } };
  h.journal = fixtures;
  // Recover the original successful wire-write request IDs from the preserved
  // HTTP assertions. Cached replay201s are separately documented readbacks.
  h.successfulWrites = checks.filter(check => check.requestId && check.passed && check.id !== 'Setup/Replay' && (/HTTP 201$/.test(check.name) || /^(complete monitoring permission tuples|audited Service business tag mutation): HTTP 200$/.test(check.name))).map(check => ({ method: check.name.startsWith('complete monitoring') ? 'PUT' : check.name.startsWith('audited Service') ? 'PATCH' : 'POST', path: `checkpoint assertion: ${check.name.split(': HTTP')[0]}`, requestId: check.requestId }));
  h.public.continuation.originalWriteIdsRecoveredFromRecordedHttpAssertions = h.successfulWrites.length;
  const admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  const clusters = rows(h.ok(await h.request(admin, '/clusters'), 'Continuation/Context', 'fresh registered real cluster discovery'));
  const c1 = clusters.find(value => value.id === original.clusterId), c2 = clusters.find(value => value.id === original.secondaryClusterId);
  h.check(c1 && c2 && c1.admin_url !== c2.admin_url && c2.admin_url === 'http://kong-secondary:8001', 'Continuation/Context', 'same two genuine cluster identities remain active');
  const pay = original.payWorkspace, pay2 = original.secondaryPayWorkspace;
  const serviceId = original.fixtureIds.service, primaryConsumer = original.fixtureIds.primaryConsumer;
  const vitals = (cluster, workspace, endpoint, query = {}) => scope(`/clusters/${cluster.id}/vitals/${endpoint}`, workspace, query);
  const currentCatalog = cluster => {
    const token = h.privateTokens.findLast(value => value.clusterId === cluster.id && value.purpose === 'collector_catalog');
    h.check(Boolean(token), 'Continuation/Catalog', 'retained current catalog purpose credential exists');
    const epochs = []; let cursor;
    for (let page = 0; page < 100; page++) {
      const query = new URLSearchParams({ size: '100', ...(cursor ? { cursor } : {}) });
      const response = h.internal('bridge', `/catalog/${cluster.id}?${query}`, { token: token.token });
      h.check(response.status === 200 && response.json?.complete === true && response.json?.blocked === false, 'Continuation/Catalog', 'current private catalog remains complete and unblocked');
      epochs.push(...response.json.items); h.check(epochs.length <= 10_000, 'Continuation/Catalog', 'shared catalog record budget remains bounded');
      cursor = response.json.nextCursor; if (!cursor) return epochs.filter(epoch => epoch.closed_at === null);
    }
    h.check(false, 'Continuation/Catalog', 'catalog page budget was not exhausted');
  };
  let primaryEpochs = currentCatalog(c1);
  const expectedPairs = original.currentEpochs.filter(epoch => epoch.entity_type === 'routes' && epoch.service_id === serviceId && epoch.workspace_id === pay.id).map(epoch => epoch.epoch_id).sort();
  h.check(JSON.stringify(primaryEpochs.filter(epoch => epoch.entity_type === 'routes' && epoch.service_id === serviceId && epoch.workspace_id === pay.id).map(epoch => epoch.epoch_id).sort()) === JSON.stringify(expectedPairs), 'Continuation/Epoch', 'API/collector-only repairs preserved the exact native fixture membership epochs');
  const loginAccount = async label => {
    const account = original.accounts[label], privateUser = h.users.find(value => value.id === account.id && value.label === label);
    h.check(Boolean(privateUser), 'Continuation/Identity', 'existing account password is retained privately for exact current fixture ID');
    return h.login(privateUser.username, privateUser.password);
  };
  const monitor = await loginAccount('monitor-workspace');
  h.check(h.privateTraffic.length === 6, 'Continuation/Traffic', 'same six owned authenticated proxy routes remain available');
  const started = Date.now(); let requests = 0;
  while (Date.now() - started < 80_000) {
    for (const row of h.privateTraffic) {
      h.check(['http://127.0.0.1:8000', 'http://127.0.0.1:9000'].includes(row.origin) && row.path.startsWith(`/m5/${h.tag}/`) && [200, 404, 500].includes(row.status), 'Continuation/Traffic', 'retained traffic target is an exact owned safe fixture');
      const response = await fetch(row.origin + row.path, { headers: { apikey: row.apiKey }, redirect: 'manual', signal: AbortSignal.timeout(5000) });
      await response.arrayBuffer(); h.check(response.status === row.status, 'Continuation/Traffic', 'actual retained dual-cluster proxy response matches the configured status'); requests++;
    }
    await new Promise(resolve => setTimeout(resolve, 750));
  }
  const trafficFinished = Date.now();
  const end = Math.floor(trafficFinished / 1000) * 1000, requested = { start: new Date(end - 300_000).toISOString(), end: new Date(end).toISOString(), step: 15 };
  // Freeze the end before waiting, so asynchronous delivery and scrape lag do
  // not turn the independent providers into comparisons of moving windows.
  writeFileSync(checkpointPath, JSON.stringify({ ...original, continuationWindow: { requested, trafficStartedAt: new Date(started).toISOString(), trafficFinishedAt: new Date(trafficFinished).toISOString(), requests, deliverySettleMs: 15_000 } }, null, 2) + '\n', { mode: 0o600 });
  h.persistReference();
  await new Promise(resolve => setTimeout(resolve, 15_000));
  const overview = async (actor, cluster, workspace, query, id) => {
    const response = await h.request(actor, vitals(cluster, workspace, 'overview', { ...requested, ...query }));
    const result = h.ok(response, id, 'real current scoped overview over the explicit requested checkpoint continuation window');
    h.check(!h.secrets.filter(Boolean).some(secret => response.text.includes(secret)), id, 'public monitoring response contains no known retained runtime credential');
    h.check(result.clusterId === cluster.id && result.workspaceId === workspace.id && result.quality?.historicalScope === 'current_epoch', id, 'actual scope and current-epoch historical limits are explicit');
    return result;
  };
  const native = await overview(admin, c1, pay, { serviceId }, 'Continuation/Prometheus');
  const native2 = await overview(admin, c2, pay2, { serviceId }, 'Continuation/PrometheusDual');
  primaryEpochs = currentCatalog(c1); const secondaryEpochs = currentCatalog(c2);
  h.public.priorPrometheusOracle = original.prometheusOracle;
  h.public.prometheusOracle = { primary: compareRealNativePrometheus(h, native, { clusterId: c1.id, workspaceId: pay.id, serviceId, epochs: primaryEpochs }), secondary: compareRealNativePrometheus(h, native2, { clusterId: c2.id, workspaceId: pay2.id, serviceId, epochs: secondaryEpochs }) };
  const consumerActor = await loginAccount('monitor-consumer'), consumer = await overview(consumerActor, c1, pay, {}, 'Continuation/Consumer');
  h.public.priorConsumerOracle = original.consumerOracle;
  h.public.consumerOracle = compareRealConsumerPrometheus(h, consumer, { clusterId: c1.id, workspaceId: pay.id, consumerId: primaryConsumer, epochs: primaryEpochs });
  const lokiSource = original.sources[c1.id].loki;
  const loki = await overview(monitor, c1, pay, { serviceId, sourceId: lokiSource.id }, 'Continuation/Loki');
  h.check(loki.source?.type === 'loki' && loki.cards.qps.value !== null && !loki.quality.reasonCodes.includes('METRICS_SOURCE_QUERY_FAILED'), 'Continuation/Loki', 'actual Loki metrics are available after strict effective-grid and serializer fixes');
  const actual = loki.timeWindow;
  h.check(loki.evaluationAt === actual.end && actual.step === requested.step && Date.parse(actual.start) >= Date.parse(requested.start) && Date.parse(actual.end) <= Date.parse(requested.end), 'Continuation/LokiGrid', 'effective Loki query bounds are explicit inward bounds without timestamp rewriting or sample clamping');
  const search = new URLSearchParams({ query: `{job="kongos-collector",cluster_id="${c1.id}",workspace_id="${pay.id}",service_id="${serviceId}"}`, start: String(Date.parse(actual.start) * 1e6), end: String(Date.parse(actual.end) * 1e6), limit: '1000' });
  const raw = h.internal('loki', `/loki/api/v1/query_range?${search}`);
  h.check(raw.status === 200 && raw.json?.data?.result?.length > 0 && raw.json.data.result.reduce((n, stream) => n + stream.values.length, 0) < 1000, 'Continuation/Loki', 'real sanitized event oracle is present and not silently truncated');
  h.check(!h.secrets.filter(Boolean).some(secret => raw.text.includes(secret)), 'Continuation/Loki', 'raw minimal event source has no known password, token, Key, cookie or canary');
  h.public.lokiOracle = compareRealLokiEvents(h, loki, raw.json.data.result, primaryEpochs.filter(epoch => epoch.entity_type === 'routes' && epoch.service_id === serviceId && epoch.workspace_id === pay.id));
  h.public.lokiOracle.requestedWindow = requested;
  h.public.lokiOracle.effectiveWindow = actual;
  const before = h.providerQueryCount('loki');
  for (const query of [{ logql: '{job="any"}' }, { query: '{job="any"}' }, { url: 'http://kong:8001' }, { scope: 'any' }, { step: 1 }]) await h.reject(admin, vitals(c1, pay, 'overview', { ...requested, sourceId: lokiSource.id, ...query }), 'GET', undefined, 'Loki/Input', 'malformed arbitrary Loki query and budget fields are rejected before provider access', [400]);
  const after = h.providerQueryCount('loki');
  h.check(before.observed && after.observed && before.count === after.count, 'Loki/Input', 'real Loki query instrumentation does not increase for malformed requests');
  for (const service of ['telemetry-collector', 'console-api', 'console-web', 'kong', 'kong-secondary', 'loki']) h.check(!h.secrets.filter(Boolean).some(secret => h.logs(service).includes(secret)), 'Logs/Secrets', `${service} actual logs contain no known retained runtime secret`);
  const clusterActor = await loginAccount('monitor-cluster'), cluster = await overview(clusterActor, c1, pay, { scope: 'cluster' }, 'Cluster/Positive');
  h.check(cluster.scope === 'cluster' && cluster.nodes.some(node => node.online === 1 && node.datastoreReachable === 1), 'Cluster/Nodes', 'whole-cluster grant reads actual node availability and datastore gauges');
  const actor = await loginAccount('monitor-service'), binding = original.accounts['monitor-service'];
  h.ok(await h.request(admin, `/iam/users/${binding.id}/role-bindings/${binding.binding.id}`, 'DELETE', { revision: binding.binding.revision, confirmed: true, confirm_name: binding.role.name }), 'Revocation', 'explicit existing monitoring fixture binding revocation');
  await h.reject(actor, vitals(c1, pay, 'overview', { ...requested, serviceId }), 'GET', undefined, 'Revocation', 'existing cookies and saved evaluation window cannot bypass immediate revocation');
  const password = h.remember(strongPassword()); h.persistReference();
  const user = h.ok(await h.request(admin, '/iam/users', 'POST', { username: `${h.tag}-browser-revoke`, password, display_name: 'M5 browser revocation' }), 'IAM', 'ordinary browser monitoring fixture account');
  const role = h.ok(await h.request(admin, '/iam/roles', 'POST', { code: `${h.tag}-browser-revoke`, name: `${h.tag}-browser-revoke` }), 'IAM', 'browser monitoring fixture role');
  h.ok(await h.request(admin, `/iam/roles/${role.id}/permissions`, 'PUT', { revision: role.revision, permissions: [{ module: 'monitoring', action: 'read', scope_type: 'workspace', cluster_id: c1.id, workspace_id: pay.id, scope_values: [pay.id] }] }), 'IAM', 'browser monitoring exact workspace grant');
  const bound = h.ok(await h.request(admin, `/iam/users/${user.id}/role-bindings`, 'POST', { role_id: role.id }), 'IAM', 'browser monitoring fixture binding');
  h.users.push({ id: user.id, username: user.username, password, label: 'browser-revoke' });
  h.public.accounts['browser-revoke'] = { id: user.id, username: user.username, role: { id: role.id, name: role.name }, binding: { id: bound.id, revision: bound.revision } };
  h.public.savedEvaluationWindow = requested;
  h.public.continuation.traffic = { startedAt: new Date(started).toISOString(), finishedAt: new Date(trafficFinished).toISOString(), requests, actualStableTrafficMs: trafficFinished - started, deliverySettleMs: 15_000, fixedEvaluationEndBeforeSettle: requested.end, newNativeFixtures: 0, credentialRotations: 0 };
  h.verifyAuditCoverage();
} catch (error) { failure = error; }
process.exitCode = await h.finish(failure);
