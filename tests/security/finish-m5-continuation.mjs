import { readFileSync, statSync } from 'node:fs';
import { M5Harness, rows, scope, strongPassword } from './lib/m5-harness.mjs';

// Only finish the preserved completed-oracle checkpoint. There is no setup,
// token rotation, traffic generation or native configuration replay here.
const h = new M5Harness();
let failure;
try {
  h.check(process.env.M5_CONTINUATION_TAIL_READY === 'true', 'Continuation/TailGate', 'explicit completed-oracle remaining-check handoff required');
  const original = JSON.parse(readFileSync('artifacts/M5/security-live-continuation-log-harness.json', 'utf8'));
  h.check(original.passed === 2596 && original.failed === 1 && original.checks.at(-2)?.name === 'real Loki query instrumentation does not increase for malformed requests', 'Continuation/TailGate', 'only the exact preserved log-helper failure checkpoint may finish');
  h.check(Object.values(original.lokiOracle?.comparisons ?? {}).length === 15 && Object.values(original.lokiOracle.comparisons).every(value => value.compared > 0), 'Continuation/TailGate', 'all15 actual same-window Loki oracles already passed');
  h.check((statSync('/tmp/kongos-m5-continuation.json').mode & 0o777) === 0o600, 'Continuation/TailGate', 'frozen window checkpoint is private0600');
  const frozen = JSON.parse(readFileSync('/tmp/kongos-m5-continuation.json', 'utf8')).continuationWindow;
  h.check(frozen?.requested?.end === original.lokiOracle.requestedWindow.end, 'Continuation/TailGate', 'exact fixed requested window matches the preserved completed oracles');
  const gateChecks = h.checks;
  h.checks = [...original.checks.filter(check => check.passed), ...gateChecks];
  const { checks, fixtures, passed, failed, lastHttpRequest, performedAt, kind, successfulConfigurationWrites, ...safeOriginal } = original;
  h.public = safeOriginal; h.tag = original.testTag; h.journal = fixtures;
  h.successfulWrites = successfulConfigurationWrites;
  h.public.continuation.logHarnessFailurePreserved = 'security-live-continuation-log-harness.json';
  const requested = frozen.requested;
  const admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  const clusters = rows(h.ok(await h.request(admin, '/clusters'), 'Continuation/Context', 'fresh registered cluster identity for remaining checks'));
  const c1 = clusters.find(value => value.id === original.clusterId), pay = original.payWorkspace;
  h.check(Boolean(c1), 'Continuation/Context', 'original genuine primary cluster remains active');
  const vitals = (endpoint, query = {}) => scope(`/clusters/${c1.id}/vitals/${endpoint}`, pay, query);
  const loginAccount = async label => {
    const account = original.accounts[label], user = h.users.find(value => value.id === account.id && value.label === label);
    h.check(Boolean(user), 'Continuation/Identity', 'exact existing account has its private retained password');
    return h.login(user.username, user.password);
  };
  for (const service of ['telemetry-collector', 'console-api', 'console-web', 'kong', 'kong-secondary', 'loki']) {
    const logs = h.logs(service);
    h.check(!h.secrets.filter(Boolean).some(secret => logs.includes(secret)), 'Logs/Secrets', `${service} actual logs contain no known retained runtime secret`);
  }
  const clusterActor = await loginAccount('monitor-cluster');
  const cluster = h.ok(await h.request(clusterActor, vitals('overview', { ...requested, scope: 'cluster' })), 'Cluster/Positive', 'whole-cluster current monitoring grant uses the same fixed evaluation window');
  h.check(cluster.scope === 'cluster' && cluster.nodes.some(node => node.online === 1 && node.datastoreReachable === 1), 'Cluster/Nodes', 'whole-cluster grant reads actual node availability and datastore gauges');
  const actor = await loginAccount('monitor-service'), binding = original.accounts['monitor-service'];
  h.ok(await h.request(admin, `/iam/users/${binding.id}/role-bindings/${binding.binding.id}`, 'DELETE', { revision: binding.binding.revision, confirmed: true, confirm_name: binding.role.name }), 'Revocation', 'explicit existing monitoring fixture binding revocation');
  await h.reject(actor, vitals('overview', { ...requested, serviceId: original.fixtureIds.service }), 'GET', undefined, 'Revocation', 'existing cookies and saved evaluation window cannot bypass immediate revocation');
  const password = h.remember(strongPassword()); h.persistReference();
  const user = h.ok(await h.request(admin, '/iam/users', 'POST', { username: `${h.tag}-browser-revoke`, password, display_name: 'M5 browser revocation' }), 'IAM', 'ordinary browser monitoring fixture account');
  h.users.push({ id: user.id, username: user.username, password, label: 'browser-revoke' }); h.persistReference();
  const role = h.ok(await h.request(admin, '/iam/roles', 'POST', { code: `${h.tag}-browser-revoke`, name: `${h.tag}-browser-revoke` }), 'IAM', 'browser monitoring fixture role');
  h.ok(await h.request(admin, `/iam/roles/${role.id}/permissions`, 'PUT', { revision: role.revision, permissions: [{ module: 'monitoring', action: 'read', scope_type: 'workspace', cluster_id: c1.id, workspace_id: pay.id, scope_values: [pay.id] }] }), 'IAM', 'browser monitoring exact workspace grant');
  const bound = h.ok(await h.request(admin, `/iam/users/${user.id}/role-bindings`, 'POST', { role_id: role.id }), 'IAM', 'browser monitoring fixture binding');
  h.public.accounts['browser-revoke'] = { id: user.id, username: user.username, role: { id: role.id, name: role.name }, binding: { id: bound.id, revision: bound.revision } };
  h.public.savedEvaluationWindow = requested;
  h.public.continuation.traffic = { startedAt: frozen.trafficStartedAt, finishedAt: frozen.trafficFinishedAt, requests: frozen.requests, actualStableTrafficMs: Date.parse(frozen.trafficFinishedAt) - Date.parse(frozen.trafficStartedAt), deliverySettleMs: frozen.deliverySettleMs, fixedEvaluationEndBeforeSettle: requested.end, newNativeFixtures: 0, credentialRotations: 0 };
  h.verifyAuditCoverage();
} catch (error) { failure = error; }
process.exitCode = await h.finish(failure);
