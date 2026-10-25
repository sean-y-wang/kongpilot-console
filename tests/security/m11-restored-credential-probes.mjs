import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

// Source-only until Root explicitly invokes one original stage. Importing the
// pure signing helper or running node --check never opens the private ledger.
// All configuration writes use new typed BFF intents and three actual votes.
// Neither stage retries an HTTP request, refreshes a session, calls Admin API,
// ticks a worker, changes the existing echo Service/plugin, or creates tokens.
const kinds = ['key-auth', 'basic-auth', 'jwt', 'hmac-auth', 'acls'];
const routeKinds = [...kinds, 'acls-denied'];
const allCredentialKinds = [...kinds, 'oauth2'];
const pluginNames = ['key-auth', 'basic-auth', 'jwt', 'hmac-auth', 'acl'];
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const referenceId = value => typeof value === 'string' ? value : value?.id;
const fieldMap = schema => Array.isArray(schema?.fields) ? Object.assign({}, ...schema.fields) : schema?.fields;

/** Offline-testable request construction; no sessions, files or I/O. The Basic
 * password is the original private input, never Kong's native password hash.
 * ACL positive and negative authenticate the same real restored Consumer Key;
 * the negative uses a separately approved route with a nonmatching ACL group. */
export function restoredAuthProbeHeaders(kind, inputs, requestPath, positive, now = Date.now(), wrongSecret = randomBytes(32).toString('hex')) {
  assert(kinds.includes(kind), 'FIXED_AUTH_PROBE_KIND_REQUIRED');
  assert(typeof positive === 'boolean', 'EXPLICIT_AUTH_PROBE_POLARITY_REQUIRED');
  assert(typeof requestPath === 'string' && /^\/[a-zA-Z0-9/_-]+$/.test(requestPath), 'EXACT_AUTH_PROBE_PATH_REQUIRED');
  assert(Number.isSafeInteger(now) && now > 0, 'AUTH_PROBE_TIME_REQUIRED');
  assert(typeof wrongSecret === 'string' && wrongSecret.length >= 32, 'INDEPENDENT_NEGATIVE_MATERIAL_REQUIRED');
  const raw = inputs[kind];
  assert(raw && typeof raw === 'object', 'ORIGINAL_PRIVATE_AUTH_INPUT_REQUIRED');
  if (kind === 'key-auth') {
    assert(typeof raw.key === 'string' && raw.key.length > 0);
    assert(wrongSecret !== raw.key, 'NEGATIVE_KEY_MUST_DIFFER');
    return { apikey: positive ? raw.key : wrongSecret };
  }
  if (kind === 'acls') {
    assert(typeof inputs['key-auth']?.key === 'string' && inputs['key-auth'].key.length > 0);
    return { apikey: inputs['key-auth'].key };
  }
  if (kind === 'basic-auth') {
    assert(typeof raw.username === 'string' && typeof raw.password === 'string' && raw.password.length > 0);
    assert(wrongSecret !== raw.password, 'NEGATIVE_BASIC_PASSWORD_MUST_DIFFER');
    return { authorization: `Basic ${Buffer.from(`${raw.username}:${positive ? raw.password : wrongSecret}`).toString('base64')}` };
  }
  assert(typeof raw.secret === 'string' && raw.secret.length > 0);
  assert(wrongSecret !== raw.secret, 'NEGATIVE_SIGNING_SECRET_MUST_DIFFER');
  if (kind === 'jwt') {
    assert.equal(raw.algorithm, 'HS256'); assert(typeof raw.key === 'string' && raw.key.length > 0);
    const payload = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: raw.key, exp: Math.floor(now / 1000) + 120 })).toString('base64url')}`;
    return { authorization: `Bearer ${payload}.${createHmac('sha256', positive ? raw.secret : wrongSecret).update(payload).digest('base64url')}` };
  }
  assert(typeof raw.username === 'string' && /^[a-zA-Z0-9_-]+$/.test(raw.username), 'ORIGINAL_HMAC_USERNAME_REQUIRED');
  const date = new Date(now).toUTCString(), digest = `SHA-256=${createHash('sha256').update(Buffer.alloc(0)).digest('base64')}`;
  const signed = `date: ${date}\ndigest: ${digest}\nGET ${requestPath} HTTP/1.1`;
  return { date, digest, authorization: `hmac username="${raw.username}", algorithm="hmac-sha256", headers="date digest request-line", signature="${createHmac('sha256', positive ? raw.secret : wrongSecret).update(signed).digest('base64')}"` };
}

async function main() {
  assert.equal(process.env.RELEASE_LAB_M11_RESTORED_CREDENTIAL_PROBES_READY, 'true', 'ROOT_EXPLICIT_RESTORED_CREDENTIAL_PROBE_GATE_REQUIRED');
  assert([3, 4].includes(process.argv.length), 'EXACT_ORIGINAL_AUTH_PROBE_STAGE_REQUIRED');
  const afterSelectorFix = process.argv[3] === '--after-selector-order-fix';
  assert(process.argv[3] === undefined || afterSelectorFix, 'FIXED_AUTH_PROBE_VARIANT_REQUIRED');
  const stateKey = afterSelectorFix ? 'gate3RestoredCredentialProbesAfterSelectorOrderFix' : 'gate3RestoredCredentialProbes';
  const variant = afterSelectorFix ? '-after-selector-order-fix' : '';
  const stage = process.argv[2];
  assert(['create-probes', 'probe-auth'].includes(stage), 'FIXED_AUTH_PROBE_STAGE_REQUIRED');
  const reportPath = resolve(`artifacts/M11/gate3-restored-credential-probes-${stage}${variant}-http-original.json`);
  assert(!existsSync(reportPath), 'ORIGINAL_AUTH_PROBE_REPORT_EXISTS_NO_REPLAY');
  const h = new ReleaseHarness('M11', { resume: true }), cid = h.state.cid, wid = h.state.wid;
  const seed = h.state.gate3PersistentCredentials;
  assert(uuid(cid) && uuid(wid) && seed?.version === 1 && seed.clusterId === cid && seed.workspaceId === wid, 'ORIGINAL_CONSUMER_B_NAMESPACE_REQUIRED');
  assert(uuid(seed.consumerId) && seed.sourceInputs && seed.credentialIds, 'ORIGINAL_CONSUMER_B_MATERIAL_REQUIRED');
  const actors = ['admin', 'a', 'b', 'c'];
  function session(label) {
    const actual = h.state.sessions[label];
    assert(uuid(actual?.user?.id) && uuid(actual.sid) && typeof actual.cookie === 'string', 'ROOT_ACTUAL_SESSION_REQUIRED');
    const access = actual.cookie.split('; ').find(pair => pair.startsWith('kongos_access='));
    assert(access, 'ROOT_ACTUAL_ACCESS_COOKIE_REQUIRED');
    let claims;
    try { claims = JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1], 'base64url').toString()); }
    catch { throw Error('ROOT_ACTUAL_ACCESS_COOKIE_INVALID'); }
    assert.equal(claims.sub, actual.user.id); assert.equal(claims.sid, actual.sid);
    // ReleaseHarness refreshes within 90 seconds; stop before that branch.
    assert(Number.isFinite(claims.exp) && claims.exp * 1000 > Date.now() + 120_000, 'ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH');
    assert.equal(actual.user.id, seed.subjects?.[label], 'ORIGINAL_CONSUMER_B_APPROVAL_SUBJECT_REQUIRED');
    return actual;
  }
  h.assertWritable();
  const subjects = Object.fromEntries(actors.map(label => [label, session(label).user.id]));
  assert.equal(new Set(Object.values(subjects)).size, 4, 'FOUR_DISTINCT_ACTUAL_AUTH_PROBE_ACTORS_REQUIRED');
  if (afterSelectorFix) {
    const original = h.state.gate3RestoredCredentialProbes;
    assert.equal(original?.stages?.['create-probes']?.state, 'stopped-no-replay');
    assert.equal(Object.keys(original.intents).length, 0);
    assert.equal(Object.keys(original.writeKeys).length, 0, 'FIRST_PREREQUISITE_FAILURE_MUST_HAVE_NO_ALLOCATED_WRITE');
  }
  if (stage === 'create-probes') assert(!h.state[stateKey], 'ORIGINAL_AUTH_PROBE_CREATE_STAGE_PRESENT_NO_REPLAY');
  else assert(h.state[stateKey]?.stages?.['create-probes']?.state === 'succeeded', 'ORIGINAL_APPROVED_AUTH_PROBE_FIXTURES_REQUIRED');
  const g = h.state[stateKey] ??= {
    version: 1, clusterId: cid, workspaceId: wid, consumerId: seed.consumerId, subjects,
    stages: {}, writeKeys: {}, intents: {}, checks: [], routes: {}, plugins: [], probes: {},
    evidenceKey: randomBytes(32).toString('hex'), fixtureSuffix: randomUUID(),
    authEndpointValidation: { ...Object.fromEntries(kinds.map(kind => [kind, 'pending-actual-positive-negative-proxy'])), oauth2: 'pending-actual-TLS-token-chain' },
  };
  assert.equal(g.version, 1); assert.equal(g.clusterId, cid); assert.equal(g.workspaceId, wid); assert.equal(g.consumerId, seed.consumerId);
  assert.deepEqual(g.subjects, subjects); assert(!g.stages[stage], 'ORIGINAL_AUTH_PROBE_STAGE_PRESENT_NO_REPLAY');
  g.stages[stage] = { state: 'started', startedAt: new Date().toISOString() }; h.save();
  const scope = (suffix, extra = {}) => releaseScope(cid, wid, suffix, extra);
  const hmac = value => createHmac('sha256', g.evidenceKey).update(JSON.stringify(value)).digest('hex');
  const read = (path, options = {}) => h.request(session('admin'), path, 'GET', undefined, options);
  function check(name, facts = {}) { g.checks.push({ stage, name, passed: true, ...facts }); h.check(true, name, { stage, ...facts }); }
  async function once(suffix, path, body, actor = 'admin') {
    const label = `m11-restored-auth${variant}-${stage}-${suffix}`;
    assert(!Object.hasOwn(g.writeKeys, label), 'ORIGINAL_AUTH_PROBE_REQUEST_ALREADY_ALLOCATED_NO_REPLAY');
    assert(!h.state.requests.some(packet => packet.label === label), 'ORIGINAL_AUTH_PROBE_REQUEST_PRESENT_NO_REPLAY');
    const key = randomUUID(); assert(!h.state.requests.some(packet => packet.key === key));
    g.writeKeys[label] = key; h.save();
    return (await h.once(label, session(actor), path, 'POST', body, { key })).data;
  }
  function report(passed) {
    const keys = new Set(Object.entries(g.writeKeys).filter(([label]) => label.startsWith(`m11-restored-auth${variant}-${stage}-`)).map(([, key]) => key));
    const packets = h.state.requests.filter(packet => keys.has(packet.key));
    const output = {
      passed, milestone: 'M11', stage, variant: afterSelectorFix ? 'after-selector-order-fix' : 'original', sourceOnly: false, productionDeployment: false, overallM11Accepted: false,
      environment: 'isolated Kong OSS 1.5.x via authenticated BFF and registered business proxy',
      consumerId: g.consumerId, originalCredentialIds: seed.credentialIds, serviceId: g.serviceId ?? null,
      nativeConfigurationWritesExpected: stage === 'create-probes' ? 15 : 0,
      probesExpected: stage === 'probe-auth' ? 10 : 0, checks: g.checks.filter(item => item.stage === stage),
      requests: packets.map(packet => ({ method: packet.method, path: packet.path.split('?')[0], key: packet.key,
        state: packet.state, status: packet.status, requestId: packet.requestId,
        requestHmac: hmac(packet.body), responseHmac: hmac(packet.responseData ?? null),
        ...(typeof packet.errorCode === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(packet.errorCode) ? { errorCode: packet.errorCode } : {}) })),
      results: stage === 'probe-auth' ? Object.values(g.probes).map(item => ({ kind: item.kind, polarity: item.polarity,
        expectedStatus: item.expectedStatus, actualStatus: item.actualStatus ?? null, receiptHmac: item.receiptHmac ?? null })) : [],
      authEndpointValidation: { ...g.authEndpointValidation }, originalServiceOrPluginChanged: false,
      authenticationHeadersRecorded: false, credentialValuesRecorded: false, sessionCookiesRecorded: false,
      oauthTokenRequestsSent: 0, tlsVerificationBypassed: false, directAdminRequestsSent: 0,
      limitations: [
        'The public report contains statuses and keyed summaries only; original credential and signing material remains in the private ledger.',
        'Proxy observations use the registered BFF destination, with no retries, redirects, token endpoint calls or returned response bodies.',
        'Global-plugin checks cover the enumerated active/disabled console workspaces; unclassified or deleted-workspace native objects require independent Root inventory verification.',
        'Dedicated configuration workflows are not browser UI, HA, unknown-result recovery, production deployment or complete M11 acceptance.',
        'OAuth2 HTTPS issuance, authorization-code/access-token/refresh-token and revocation chains remain pending and are not inferred from credential DAO restoration.',
      ],
      ...(!passed ? { errorCode: 'M11_RESTORED_CREDENTIAL_PROBES_STOPPED' } : {}),
    };
    mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(output, null, 2) + '\n', { flag: 'wx' });
  }
  async function prerequisites() {
    const cluster = (await read(`/clusters/${cid}`)).data;
    assert.equal(cluster.execution_mode, 'approval'); assert(/^1\.5\.\d+$/.test(cluster.version), 'ACTUAL_KONG15_REQUIRED');
    assert(Array.isArray(cluster.enabled_plugins)); for (const name of pluginNames) assert(cluster.enabled_plugins.includes(name), 'ACTUAL_AUTH_PLUGIN_REQUIRED');
    const workspace = (await read(`/clusters/${cid}/workspaces/${wid}`)).data;
    assert.equal(workspace.status, 'active'); assert.equal(workspace.code, seed.workspaceCode); assert.equal(workspace.cluster_id, cid);
    const definitions = (await read(scope('workflow-definitions', { size: '100' }))).data;
    assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'ISOLATED_POLICY_PAGE_MUST_BE_COMPLETE');
    const native = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active'); assert.equal(native.length, 1);
    const policy = native[0].policy; assert.equal(native[0].format, 2); assert.equal(policy.version, 2); assert.equal(policy.kind, 'native-change');
    assert.equal(policy.allowSelfApproval, false); assert.equal(policy.distinctAcrossStages, true); assert.equal(policy.stages.length, 2);
    assert.equal(policy.stages[0].mode, 'any'); assert.equal(policy.stages[0].threshold, 1); assert.deepEqual(policy.stages[0].selector, { users: [subjects.a] });
    assert.equal(policy.stages[1].mode, 'all'); assert.equal(policy.stages[1].threshold, null);
    assert.deepEqual(Object.keys(policy.stages[1].selector), ['users']);
    assert.deepEqual([...policy.stages[1].selector.users].sort(), [subjects.b, subjects.c].sort());
    const entryId = seed.intents?.['delete-consumer']?.entryId; assert(uuid(entryId), 'ORIGINAL_CONSUMER_B_ARCHIVE_REQUIRED');
    const archive = (await read(scope('recycle-bin', { type: 'consumers', search: seed.consumerId, size: '20' }))).data;
    assert(Array.isArray(archive.items) && !archive.nextCursor, 'ISOLATED_RECYCLE_PAGE_MUST_BE_COMPLETE');
    const restored = archive.items.filter(item => item.id === entryId); assert.equal(restored.length, 1);
    assert.equal(restored[0].state, 'restored', 'WHOLE_CONSUMER_B_RESTORE_REQUIRED_BEFORE_AUTH_PROBES'); assert.equal(restored[0].original_id, seed.consumerId); assert.equal(restored[0].node_count, 7);
    const consumer = (await read(scope(`entities/consumers/${seed.consumerId}`))).data.entity;
    assert.equal(consumer.username, seed.sourceInputs.consumer.username); assert.equal(consumer.custom_id, seed.sourceInputs.consumer.custom_id);
    for (const kind of allCredentialKinds) {
      const page = (await read(scope(`consumers/${seed.consumerId}/credentials/${kind}`, { size: '20' }))).data;
      assert(Array.isArray(page.items) && !page.nextCursor, 'ISOLATED_CREDENTIAL_PAGE_MUST_BE_COMPLETE');
      assert.deepEqual(page.items.map(item => item.id), [seed.credentialIds[kind]], 'EXACT_ORIGINAL_CREDENTIAL_ID_REQUIRED');
      if (kind === 'oauth2') continue; // No token or TLS claim from DAO presence.
      const credential = (await read(scope(`consumers/${seed.consumerId}/credentials/${kind}/${seed.credentialIds[kind]}`, { reveal: 'true' }))).data.entity;
      assert.equal(credential.id, seed.credentialIds[kind]); assert.equal(referenceId(credential.consumer), seed.consumerId);
      for (const [field, value] of Object.entries(seed.sourceInputs[kind])) assert.equal(hmac(credential[field]), hmac(value), 'ORIGINAL_PRIVATE_CREDENTIAL_MATERIAL_REQUIRED');
      if (kind === 'basic-auth') assert.equal(credential.recovery_capability, 'complete', 'ACTUAL_ORIGINAL_BASIC_CUSTODY_REQUIRED');
    }
    const workspaces = (await read(`/clusters/${cid}/workspaces?size=100`)).data;
    assert(Array.isArray(workspaces.items) && !workspaces.nextCursor, 'ISOLATED_WORKSPACE_PAGE_MUST_BE_COMPLETE');
    for (const current of workspaces.items) {
      assert(uuid(current.id) && ['active', 'disabled'].includes(current.status));
      const global = (await read(releaseScope(cid, current.id, 'plugin-center/instances', { binding_scope: 'global', size: '100' }))).data;
      assert(Array.isArray(global.items) && !global.nextCursor, 'ISOLATED_GLOBAL_PLUGIN_PAGE_MUST_BE_COMPLETE');
      assert(global.items.every(item => item.enabled === false || item.name === 'prometheus'), 'GLOBAL_PLUGIN_INTERFERENCE_BLOCKS_AUTH_PROBES');
    }
    const consumerPlugins = (await read(scope(`entities/consumers/${seed.consumerId}/relations/plugins`, { size: '100' }))).data;
    assert(Array.isArray(consumerPlugins.items) && !consumerPlugins.nextCursor && consumerPlugins.items.every(item => item.enabled === false), 'CONSUMER_PLUGIN_INTERFERENCE_BLOCKS_AUTH_PROBES');
    const capabilities = (await read(scope('toolbox/capabilities'))).data; assert.equal(capabilities.proxyConfigured, true); assert.equal(capabilities.proxyProbe, true);
    check('Original Consumer B seven-node archive is restored; original IDs, private auth material, active scope, actual policy and registered proxy verified');
  }
  async function newApprovedBatch(label, body, count, type) {
    assert(!Object.hasOwn(g.intents, label), 'INDEPENDENT_AUTH_PROBE_INTENT_REQUIRED');
    const record = g.intents[label] = { body }; h.save();
    const intent = await once(`${label}-prepare`, scope('entity-changes/prepare'), body);
    assert(uuid(intent.id)); assert.equal(intent.review.impact.nativePackets, count); assert.equal(intent.review.changes.length, count);
    assert(intent.review.changes.every(item => item.entityType === type && item.action === 'create' && uuid(item.nativeId)));
    record.id = intent.id; record.receipt = intent; h.save();
    const submitted = await once(`${label}-submit`, scope(`entity-changes/${intent.id}/submit`), { revision: intent.revision, materialHmac: intent.materialHmac, confirmed: true, confirm_name: 'native-change' });
    assert(uuid(submitted.workflowId)); assert(!Object.values(g.intents).some(item => item !== record && item.workflowId === submitted.workflowId));
    record.workflowId = submitted.workflowId; h.save();
    for (const [index, reviewer] of ['a', 'b', 'c'].entries()) {
      const before = (await read(scope(`workflows/${record.workflowId}`))).data.entity; assert.equal(before.state, 'pending'); assert.equal(before.approval.format, 2);
      const active = before.approval.stages.find(item => item.state === 'active'); assert(active); assert.equal(active.level, index === 0 ? 1 : 2);
      await once(`${label}-vote-${reviewer}`, scope(`workflows/${record.workflowId}/approve`), { revision: before.revision, planHash: before.planHash,
        confirmed: true, confirm_name: 'native-change', execute: false, level: active.level, stageRevision: active.revision, candidateVersion: before.approval.candidateVersion }, reviewer);
      const after = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
      assert.equal(after.state, index === 2 ? 'approved' : 'pending'); assert.equal(after.approval.stages.reduce((sum, item) => sum + item.votes, 0), index + 1);
    }
    const approved = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, true); assert(uuid(approved.approval.approvalSetId));
    assert(!Object.values(g.intents).some(item => item !== record && item.approvalSetId === approved.approval.approvalSetId));
    record.approvalSetId = approved.approval.approvalSetId; h.save();
    const result = await once(`${label}-execute`, scope(`workflows/${record.workflowId}/execute`), { revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: 'native-change' });
    record.executionId = result.executionId; record.executionReceipt = result; h.save();
    assert.equal(result.state, 'succeeded'); assert(uuid(result.executionId) && uuid(result.baselineId));
    const detail = (await read(scope(`workflows/${record.workflowId}`))).data;
    assert.equal(detail.entity.state, 'succeeded'); assert.equal(detail.nativeChange.packets.length, count);
    for (const packet of detail.nativeChange.packets) { assert.equal(packet.state, 'succeeded'); assert.equal(packet.nativeStatus, 201); }
    assert.equal(detail.nativeChange.baseline.nativeAuthority, false); assert.equal(detail.nativeChange.baseline.baseline.baselineId, result.baselineId);
    assert(Number.isSafeInteger(detail.nativeChange.baseline.baseline.objectCount) && detail.nativeChange.baseline.baseline.objectCount >= count);
    check(`Dedicated ${label} created by a new typed intent and three actual votes`, { workflowId: record.workflowId, executionId: result.executionId, nativePackets: count });
    return intent.review.changes;
  }
  async function verifyProbeFixtures() {
    assert(uuid(g.serviceId) && Object.keys(g.routes).length === 6 && g.plugins.length === 8, 'SIX_ROUTES_EIGHT_PLUGINS_REQUIRED');
    const originalService = (await read(scope(`entities/services/${g.originalServiceId}`))).data.entity;
    assert.equal(hmac(originalService), g.originalServiceHmac, 'ORIGINAL_ECHO_SERVICE_CHANGED_DURING_AUTH_PROBES');
    const dedicatedService = (await read(scope(`entities/services/${g.serviceId}`))).data.entity;
    for (const [field, value] of Object.entries(g.dedicatedServiceBody)) {
      if (field === 'tags') assert.deepEqual([...dedicatedService.tags].sort(), [...value].sort(), 'EXACT_APPROVED_DEDICATED_SERVICE_TAGS_REQUIRED');
      else assert.equal(hmac(dedicatedService[field]), hmac(value), 'EXACT_APPROVED_DEDICATED_SERVICE_REQUIRED');
    }
    const servicePlugins = (await read(scope(`entities/services/${g.serviceId}/relations/plugins`, { size: '100' }))).data;
    assert(Array.isArray(servicePlugins.items) && !servicePlugins.nextCursor && servicePlugins.items.length === 0, 'DEDICATED_SERVICE_MUST_HAVE_NO_PLUGIN_BINDINGS');
    for (const kind of routeKinds) {
      const route = (await read(scope(`entities/routes/${g.routes[kind].id}`))).data.entity;
      assert.equal(referenceId(route.service), g.serviceId); assert.deepEqual(route.hosts, g.routes[kind].hosts); assert.deepEqual(route.paths, g.routes[kind].paths);
      const bindings = (await read(scope(`entities/routes/${route.id}/relations/plugins`, { size: '100' }))).data;
      assert(Array.isArray(bindings.items) && !bindings.nextCursor);
      const expected = g.plugins.filter(item => item.routeKind === kind);
      assert.deepEqual(bindings.items.map(item => item.id).sort(), expected.map(item => item.id).sort(), 'EXACT_APPROVED_ROUTE_PLUGIN_BINDINGS_REQUIRED');
      for (const item of expected) {
        const actual = (await read(scope(`entities/plugins/${item.id}`, { reveal: 'true' }))).data.entity;
        assert.equal(actual.name, item.body.name); assert.equal(referenceId(actual.route), route.id); assert.equal(actual.enabled, true);
        assert(!referenceId(actual.service) && !referenceId(actual.consumer), 'ROUTE_ONLY_PLUGIN_REQUIRED');
        for (const [field, value] of Object.entries(item.body.config)) assert.equal(hmac(actual.config[field]), hmac(value), 'EXACT_APPROVED_PLUGIN_CONFIG_REQUIRED');
      }
    }
  }
  try {
    await prerequisites();
    if (stage === 'create-probes') {
      const originalId = h.state.gate2?.fixtures?.service?.id; assert(uuid(originalId));
      const original = (await read(scope(`entities/services/${originalId}`))).data.entity;
      assert(['http', 'https'].includes(original.protocol) && typeof original.host === 'string' && Number.isSafeInteger(original.port), 'ACTUAL_ECHO_UPSTREAM_REQUIRED');
      const tags = [`workspace:${seed.workspaceCode}`, 'team:m11-acceptance', 'owner:m11-acceptance'];
      const serviceBody = { name: `m11-auth-${g.fixtureSuffix}`, tags };
      for (const field of ['protocol', 'host', 'port', 'path', 'retries', 'connect_timeout', 'write_timeout', 'read_timeout']) if (Object.hasOwn(original, field)) serviceBody[field] = original[field];
      g.originalServiceId = originalId; g.originalServiceHmac = hmac(original); g.dedicatedServiceBody = serviceBody; h.save();
      const services = await newApprovedBatch('service', { change: { kind: 'entity', action: 'create', entityType: 'services', body: serviceBody } }, 1, 'services');
      g.serviceId = services[0].nativeId; h.save();
      const routes = routeKinds.map(kind => ({ kind: 'entity', action: 'create', entityType: 'routes', body: {
        name: `m11-auth-${kind}-${g.fixtureSuffix}`, service: { id: g.serviceId }, protocols: ['http'],
        hosts: [`m11-auth-${kind}-${g.fixtureSuffix}.invalid`], paths: [`/m11-auth-${kind}-${g.fixtureSuffix}`], strip_path: false, tags,
      } }));
      const changedRoutes = await newApprovedBatch('routes', { change: { kind: 'batch', confirmed: true, operations: routes } }, 6, 'routes');
      for (const kind of routeKinds) {
        const input = routes.find(item => item.body.name === `m11-auth-${kind}-${g.fixtureSuffix}`).body;
        const changes = changedRoutes.filter(item => item.after?.name === input.name); assert.equal(changes.length, 1);
        g.routes[kind] = { id: changes[0].nativeId, name: input.name, hosts: input.hosts, paths: input.paths };
      }
      g.deniedGroup = `acl-denied-${randomUUID()}`; assert.notEqual(g.deniedGroup, seed.sourceInputs.acls.group); h.save();
      const configFor = kind => kind === 'key-auth' ? { key_names: ['apikey'], hide_credentials: true }
        : kind === 'basic-auth' ? { hide_credentials: true }
        : kind === 'jwt' ? { key_claim_name: 'iss', claims_to_verify: ['exp'], secret_is_base64: false }
        : kind === 'hmac-auth' ? { algorithms: ['hmac-sha256'], enforce_headers: ['date', 'digest', 'request-line'], validate_request_body: true, hide_credentials: true }
        : { whitelist: [kind === 'acls' ? seed.sourceInputs.acls.group : g.deniedGroup] };
      const plugins = routeKinds.flatMap(kind => (kind.startsWith('acls') ? ['key-auth', 'acl'] : [kind]).map(name => ({ routeKind: kind,
        body: { name, enabled: true, route: { id: g.routes[kind].id }, protocols: ['http'], tags, config: name === 'key-auth' ? configFor('key-auth') : configFor(kind) } })));
      for (const name of pluginNames) {
        const schema = (await read(scope(`plugin-schemas/${name}`))).data, fields = fieldMap(schema);
        const configFields = fields?.config ? fieldMap(fields.config) : fields;
        assert(configFields && typeof configFields === 'object', 'ACTUAL_KONG15_PLUGIN_CONFIG_SCHEMA_REQUIRED');
        for (const candidate of plugins.filter(item => item.body.name === name)) for (const field of Object.keys(candidate.body.config)) assert(Object.hasOwn(configFields, field), 'ACTUAL_PLUGIN_CONFIG_FIELD_REQUIRED');
      }
      const changes = await newApprovedBatch('plugins', { change: { kind: 'batch', confirmed: true, operations: plugins.map(item => ({ kind: 'entity', action: 'create', entityType: 'plugins', body: item.body })) } }, 8, 'plugins');
      for (const item of plugins) {
        const exact = changes.filter(change => change.after?.name === item.body.name && referenceId(change.after?.route) === item.body.route.id); assert.equal(exact.length, 1);
        g.plugins.push({ ...item, id: exact[0].nativeId });
      }
      h.save(); await verifyProbeFixtures();
      g.proxyProbesNotBefore = new Date(Date.now() + 5000).toISOString();
      check('Six dedicated auth Routes and eight route-only Plugins verified; original Service/plugin untouched, OAuth remains pending');
    } else {
      assert(Date.now() >= Date.parse(g.proxyProbesNotBefore), 'DB_CONFIGURATION_PROPAGATION_WAIT_REQUIRED_BEFORE_ORIGINAL_PROBES');
      await verifyProbeFixtures();
      for (const kind of kinds) for (const positive of [true, false]) {
        const polarity = positive ? 'positive' : 'negative', label = `${kind}-${polarity}`;
        assert(!Object.hasOwn(g.probes, label), 'ORIGINAL_AUTH_PROXY_PROBE_PRESENT_NO_REPLAY');
        const route = g.routes[kind === 'acls' && !positive ? 'acls-denied' : kind], requestPath = `${route.paths[0]}/credentials/live`;
        const headers = restoredAuthProbeHeaders(kind, seed.sourceInputs, requestPath, positive);
        const expectedStatus = positive ? 200 : kind === 'acls' ? 403 : 401;
        g.probes[label] = { kind, polarity, expectedStatus, body: { routeId: route.id, input: { method: 'GET', url: `http://${route.hosts[0]}${requestPath}`, headers }, confirmed: true, confirm_name: route.name } }; h.save();
        const result = await once(`proxy-${label}`, scope('toolbox/probes'), g.probes[label].body);
        g.probes[label].actualStatus = result.status; g.probes[label].receiptHmac = hmac(result); g.probes[label].observedAt = result.observedAt; h.save();
        assert.equal(result.bodyReturned, false, 'PROXY_RESPONSE_BODY_MUST_NOT_BE_RETURNED');
        assert.equal(result.status, expectedStatus, 'ACTUAL_AUTH_PROXY_STATUS_REQUIRED_NO_RETRY');
        check(`${kind} ${polarity}: actual registered proxy response`, { expectedStatus, actualStatus: result.status, receiptHmac: g.probes[label].receiptHmac });
        if (!positive) { g.authEndpointValidation[kind] = 'actual-positive-and-negative-proxy-verified'; seed.authEndpointValidation[kind] = g.authEndpointValidation[kind]; h.save(); }
      }
    }
    g.stages[stage] = { state: 'succeeded', finishedAt: new Date().toISOString() }; h.save(); report(true);
    console.log(JSON.stringify({ passed: true, stage, credentialValuesRecorded: false, oauth2: 'pending-actual-TLS-token-chain', overallM11Accepted: false }));
  } catch (error) {
    g.stages[stage] = { state: 'stopped-no-replay', finishedAt: new Date().toISOString() }; h.save(); report(false);
    // Never output assertion operands, upstream text, signing material or headers.
    console.error(JSON.stringify({ passed: false, stage, errorCode: 'M11_RESTORED_CREDENTIAL_PROBES_STOPPED', kind: error?.name === 'AssertionError' ? 'assertion' : 'runtime', originalRequestsRetained: true }));
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { await main(); }
  catch { console.error(JSON.stringify({ passed: false, errorCode: 'M11_RESTORED_CREDENTIAL_PROBE_GATE_STOPPED', privateDetailsRecorded: false })); process.exitCode = 1; }
}
