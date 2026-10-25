import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

// Source-only until Root explicitly invokes an individual stage. Nothing here
// reads any private ledger during syntax checks. Runtime material stays in the
// original M11 private RAM ledger managed by ReleaseHarness's permission/CAS gate.
// This is an independent Consumer B; it never adopts the old all-credentials cycle.
assert.equal(process.env.RELEASE_LAB_M11_PERSISTENT_CREDENTIALS_READY, 'true');
const stage = process.argv[2];
const stages = ['create-consumer', 'create-credentials', 'delete-consumer', 'restore-consumer'];
assert(stages.includes(stage), 'EXPLICIT_PERSISTENT_CREDENTIAL_STAGE_REQUIRED');
assert.equal(process.argv.length, 3, 'NO_ATTEMPT_ALIAS_OR_REPLACEMENT_REPORT_ARGUMENT');
const reportPath = resolve(`artifacts/M11/gate3-persistent-credentials-${stage}-http-original.json`);
assert(!existsSync(reportPath), 'ORIGINAL_PERSISTENT_CREDENTIAL_REPORT_EXISTS');

const h = new ReleaseHarness('M11', { resume: true });
const cid = h.state.cid, wid = h.state.wid;
const reviewers = ['a', 'b', 'c'];
const kinds = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
const dao = { 'key-auth': 'keyauth_credentials', 'basic-auth': 'basicauth_credentials', jwt: 'jwt_secrets', oauth2: 'oauth2_credentials', 'hmac-auth': 'hmacauth_credentials', acls: 'acls' };
const plugin = { 'key-auth': 'key-auth', 'basic-auth': 'basic-auth', jwt: 'jwt', oauth2: 'oauth2', 'hmac-auth': 'hmac-auth', acls: 'acl' };
const requiredFields = { 'key-auth': ['key'], 'basic-auth': ['username', 'password'], jwt: ['key', 'secret', 'algorithm'], oauth2: ['name', 'client_id', 'client_secret', 'redirect_uris'], 'hmac-auth': ['username', 'secret'], acls: ['group'] };
const g = h.state.gate3PersistentCredentials ??= {
  version: 1, clusterId: cid, workspaceId: wid, intents: {}, writeKeys: {}, checks: [], stages: {},
  authEndpointValidation: Object.fromEntries(kinds.map(kind => [kind, 'not-run-source-cycle-only'])),
};
assert.equal(g.version, 1); assert.equal(g.clusterId, cid); assert.equal(g.workspaceId, wid);
const scope = (suffix, extra = {}) => releaseScope(cid, wid, suffix, extra);
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const labelFor = suffix => `m11-persistent-${stage}-${suffix}`;
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

function session(label) {
  const current = h.state.sessions[label];
  assert(current?.user?.id && current.sid && typeof current.cookie === 'string', 'ROOT_PREPARED_ACTUAL_SESSION_REQUIRED');
  const access = current.cookie.split('; ').find(pair => pair.startsWith('kongos_access='));
  assert(access, 'ROOT_PREPARED_ACCESS_COOKIE_REQUIRED');
  let claims;
  try { claims = JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1], 'base64url').toString()); }
  catch { throw Error('ROOT_PREPARED_ACCESS_COOKIE_INVALID'); }
  assert.equal(claims.sub, current.user.id, 'ACTUAL_SESSION_SUBJECT_REQUIRED');
  assert.equal(claims.sid, current.sid, 'ACTUAL_SESSION_ID_REQUIRED');
  // ReleaseHarness would refresh within 90 seconds. This cycle instead stops
  // before that branch; Root owns all fresh logins and auth recovery externally.
  assert(Number.isFinite(claims.exp) && claims.exp * 1000 > Date.now() + 120_000, 'ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH');
  if (g.subjects) assert.equal(current.user.id, g.subjects[label], 'ORIGINAL_PERSISTENT_SUBJECT_CHANGED');
  return current;
}

async function read(path, options = {}) {
  return h.request(session('admin'), path, 'GET', undefined, options);
}

async function once(suffix, path, body, actor = 'admin') {
  const label = labelFor(suffix), key = g.writeKeys[label] ??= randomUUID();
  h.save();
  const prior = h.state.requests.filter(packet => packet.key === key);
  if (prior.length) {
    assert.equal(prior.length, 1, 'ONE_ORIGINAL_PERSISTENT_REQUEST_REQUIRED');
    const packet = prior[0];
    // A successful response without its durable label is also a stop condition.
    // We never reconstruct the label, replay the key or mint a replacement key.
    assert(packet.label === label && packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300,
      'ORIGINAL_PERSISTENT_WRITE_NOT_SUCCESSFUL_NO_REPLAY');
  }
  return h.once(label, session(actor), path, 'POST', body, { key });
}

function check(name, facts = {}) {
  const safe = { stage, name, passed: true, ...facts };
  g.checks.push(safe); h.check(true, name, { stage, ...facts });
}

function report(passed) {
  const keys = new Set(Object.entries(g.writeKeys).filter(([label]) => label.startsWith(`m11-persistent-${stage}-`)).map(([, key]) => key));
  const requests = h.state.requests.filter(packet => keys.has(packet.key)).map(packet => ({
    method: packet.method, path: packet.path.split('?')[0], key: packet.key, state: packet.state,
    status: packet.status, requestId: packet.requestId, bodyHash: packet.bodyHash, responseHash: packet.responseHash,
    ...(typeof packet.errorCode === 'string' && /^[A-Z][A-Z0-9_]{1,127}$/.test(packet.errorCode) ? { errorCode: packet.errorCode } : {}),
  }));
  const body = {
    passed, stage, milestone: 'M11', independentConsumerCycle: 'Consumer B',
    environment: 'isolated actual Kong OSS 1.5.x via authenticated BFF', sourceOnly: false,
    productionDeployment: false, overallM11Accepted: false, credentialValuesRecorded: false,
    consumerId: g.consumerId ?? null, originalCredentialIds: g.credentialIds ?? null,
    credentialKinds: kinds, checks: g.checks.filter(item => item.stage === stage), requests,
    authEndpointValidation: { ...g.authEndpointValidation },
    limitations: [
      'This cycle validates persisted credential DAOs, original IDs, private material and source-bound recycle restoration only.',
      'No authentication probe plugin, route, proxy request or HTTPS OAuth token chain is created or tested.',
      'OAuth client restoration does not establish access-token, refresh-token, authorization-code or session restoration.',
    ],
    ...(!passed ? { errorCode: 'M11_PERSISTENT_CREDENTIAL_CYCLE_STOPPED' } : {}),
  };
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(reportPath, JSON.stringify(body, null, 2) + '\n', { flag: 'wx' });
}

function assertApprovalPolicy(definition) {
  assert.equal(definition.format, 2, 'ACTUAL_V2_APPROVAL_POLICY_REQUIRED');
  const policy = definition.policy;
  assert.equal(policy.version, 2); assert.equal(policy.kind, 'native-change');
  assert.equal(policy.allowSelfApproval, false); assert.equal(policy.distinctAcrossStages, true);
  assert.equal(policy.stages.length, 2, 'ACTUAL_APPROVAL3_TWO_STAGE_POLICY_REQUIRED');
  const [first, second] = policy.stages;
  assert.equal(first.level, 1); assert.equal(first.mode, 'any'); assert.equal(first.threshold, 1);
  assert.deepEqual(first.selector, { users: [g.subjects.a] }, 'ACTUAL_REVIEWER_A_REQUIRED');
  assert.equal(second.level, 2); assert.equal(second.mode, 'all'); assert.equal(second.threshold, null);
  assert.deepEqual([...second.selector.users].sort(), [g.subjects.b, g.subjects.c].sort(), 'ACTUAL_REVIEWERS_B_AND_C_REQUIRED');
  assert.deepEqual(Object.keys(second.selector), ['users']);
}

async function prerequisites() {
  const labels = ['admin', ...reviewers], actual = Object.fromEntries(labels.map(label => [label, session(label).user.id]));
  assert.equal(new Set(Object.values(actual)).size, 4, 'FOUR_DISTINCT_ACTUAL_ACTORS_REQUIRED');
  if (g.subjects) assert.deepEqual(actual, g.subjects, 'ORIGINAL_APPROVAL_ACTORS_REQUIRED');
  else { g.subjects = actual; h.save(); }
  const cluster = (await read(`/clusters/${cid}`)).data;
  assert(/^1\.5\.\d+$/.test(cluster.version), 'ACTUAL_KONG15_REQUIRED');
  assert.equal(cluster.execution_mode, 'approval', 'ACTUAL_APPROVAL_CLUSTER_REQUIRED');
  assert(Array.isArray(cluster.enabled_plugins), 'ACTUAL_ENABLED_PLUGIN_LIST_REQUIRED');
  for (const kind of kinds) assert(cluster.enabled_plugins.includes(plugin[kind]), 'ACTUAL_CREDENTIAL_PLUGIN_REQUIRED');
  const workspace = (await read(`/clusters/${cid}/workspaces/${wid}`)).data;
  assert.equal(workspace.id, wid); assert.equal(workspace.cluster_id, cid); assert.equal(workspace.status, 'active');
  assert(typeof workspace.code === 'string' && workspace.code !== 'default', 'EXPLICIT_TAGGED_WORKSPACE_REQUIRED');
  if (g.workspaceCode) assert.equal(workspace.code, g.workspaceCode, 'ORIGINAL_WORKSPACE_CODE_CHANGED');
  else { g.workspaceCode = workspace.code; h.save(); }
  const definitions = (await read(scope('workflow-definitions', { size: '100' }))).data;
  assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'ISOLATED_DEFINITION_PAGE_MUST_BE_COMPLETE');
  const native = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active');
  assert.equal(native.length, 1, 'ONE_ACTUAL_NATIVE_CHANGE_DEFINITION_REQUIRED'); assertApprovalPolicy(native[0]);
  const approval = { definitionId: native[0].id, version: native[0].version, policyHash: native[0].policyHash };
  if (g.approval) assert.deepEqual(approval, g.approval, 'ORIGINAL_APPROVAL_POLICY_CHANGED');
  else { g.approval = approval; h.save(); }
  for (const kind of kinds) {
    // Public BFF short kinds map to the recorded Kong 1.5 credential DAOs.
    const schema = (await read(scope(`schemas/${kind}`))).data;
    const fields = Array.isArray(schema.fields) ? Object.assign({}, ...schema.fields) : schema.fields;
    assert(fields && typeof fields === 'object', 'ACTUAL_CREDENTIAL_SCHEMA_REQUIRED');
    for (const field of requiredFields[kind]) assert(Object.hasOwn(fields, field), 'ACTUAL_CREDENTIAL_SCHEMA_FIELD_REQUIRED');
    assert.equal(fields.consumer?.reference, 'consumers', 'ACTUAL_CONSUMER_FOREIGN_REFERENCE_REQUIRED');
    if (kind === 'jwt') assert(fields.algorithm.one_of.includes('HS256'), 'ACTUAL_HS256_REQUIRED');
    g.schemas ??= {}; g.schemas[kind] = { dao: dao[kind], schemaHash: digest(schema), fieldNames: Object.keys(fields) }; h.save();
  }
}

function allocatePrivateInputs() {
  if (g.sourceInputs) return;
  const suffix = randomUUID();
  // Created at runtime and saved exclusively in the private ledger. There are
  // no fixed credentials, public source-input files or credential-bearing reports.
  g.sourceInputs = {
    consumer: { username: `consumer-b-${suffix}`, custom_id: randomUUID(),
      tags: [`workspace:${g.workspaceCode}`, 'team:m11-acceptance', `owner:consumer-b-${suffix}`] },
    'key-auth': { key: randomBytes(32).toString('hex') },
    'basic-auth': { username: `basic-b-${randomUUID()}`, password: `Aa7!${randomBytes(32).toString('hex')}` },
    jwt: { key: randomUUID(), secret: randomBytes(32).toString('hex'), algorithm: 'HS256' },
    oauth2: { name: `oauth-b-${randomUUID()}`, client_id: randomUUID(), client_secret: randomBytes(32).toString('hex'), redirect_uris: [`https://${randomUUID()}.invalid/oauth/callback`] },
    'hmac-auth': { username: `hmac-b-${randomUUID()}`, secret: randomBytes(32).toString('hex') },
    acls: { group: `acl-b-${randomUUID()}` },
  };
  h.save();
}

async function prepare(record, count) {
  record.receipt = (await once('prepare', scope('entity-changes/prepare'), record.body)).data;
  assert(uuid(record.receipt.id), 'ACTUAL_TYPED_INTENT_ID_REQUIRED');
  assert.equal(record.receipt.review.impact.nativePackets, count, 'EXACT_TYPED_PACKET_COUNT_REQUIRED');
  assert.equal(record.receipt.review.changes.length, count, 'EXACT_TYPED_CHANGE_COUNT_REQUIRED');
  record.id = record.receipt.id; h.save();
}

async function approveAndExecute(record, count, objectCount, deleting = false) {
  record.submitBody ??= { revision: record.receipt.revision, materialHmac: record.receipt.materialHmac, confirmed: true, confirm_name: 'native-change' }; h.save();
  record.workflowId = (await once('submit', scope(`entity-changes/${record.id}/submit`), record.submitBody)).data.workflowId;
  assert(uuid(record.workflowId), 'ACTUAL_NEW_WORKFLOW_ID_REQUIRED'); h.save();
  const previous = Object.values(g.intents).filter(item => item !== record).map(item => item.workflowId).filter(Boolean);
  assert(!previous.includes(record.workflowId), 'INDEPENDENT_WORKFLOW_PER_STAGE_REQUIRED');
  for (const [index, reviewer] of reviewers.entries()) {
    const before = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(before.state, 'pending'); assert.equal(before.approval.format, 2);
    assert.equal(before.approval.stages.length, 2);
    const active = before.approval.stages.find(item => item.state === 'active');
    assert(active, 'ACTUAL_ACTIVE_APPROVAL_STAGE_REQUIRED');
    assert.equal(active.level, index === 0 ? 1 : 2); assert.equal(active.threshold, index === 0 ? 1 : 2);
    record.voteBodies ??= {};
    record.voteBodies[reviewer] ??= { revision: before.revision, planHash: before.planHash, confirmed: true, confirm_name: 'native-change', execute: false,
      level: active.level, stageRevision: active.revision, candidateVersion: before.approval.candidateVersion }; h.save();
    await once(`vote-${reviewer}`, scope(`workflows/${record.workflowId}/approve`), record.voteBodies[reviewer], reviewer);
    const after = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(after.state, index === 2 ? 'approved' : 'pending');
    assert.equal(after.approval.stages.reduce((total, item) => total + item.votes, 0), index + 1, 'EXACT_ACTUAL_VOTE_COUNT_REQUIRED');
  }
  const approved = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
  assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, true); assert(approved.approval.approvalSetId);
  record.approvalSetId = approved.approval.approvalSetId;
  assert(!Object.values(g.intents).some(item => item !== record && item.approvalSetId === record.approvalSetId), 'NEW_APPROVAL_SET_PER_STAGE_REQUIRED');
  record.executeBody ??= { revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: 'native-change' }; h.save();
  const receipt = (await once('execute', scope(`workflows/${record.workflowId}/execute`), record.executeBody)).data;
  record.executionId = receipt.executionId; record.executionReceipt = receipt; h.save();
  assert.equal(receipt.state, 'succeeded'); assert(uuid(receipt.baselineId));
  const detail = (await read(scope(`workflows/${record.workflowId}`))).data;
  assert.equal(detail.entity.state, 'succeeded'); assert.equal(detail.nativeChange.packets.length, count);
  for (const packet of detail.nativeChange.packets) {
    assert.equal(packet.state, 'succeeded');
    assert(deleting ? packet.nativeStatus === 204 : packet.nativeStatus >= 200 && packet.nativeStatus < 300, 'ACTUAL_NATIVE_RESPONSE_REQUIRED');
  }
  assert.equal(detail.nativeChange.baseline.nativeAuthority, false);
  assert.equal(detail.nativeChange.baseline.baseline.baselineId, receipt.baselineId);
  assert.equal(detail.nativeChange.baseline.baseline.objectCount, objectCount, 'EXACT_COMPLETE_BASELINE_OBJECT_COUNT_REQUIRED');
  record.baselineId = receipt.baselineId; record.nativePacketCount = count; record.baselineObjectCount = objectCount; h.save();
}

async function credentialIds() {
  assert(uuid(g.consumerId), 'NEW_CONSUMER_B_ID_REQUIRED');
  const ids = {};
  for (const kind of kinds) {
    const page = (await read(scope(`consumers/${g.consumerId}/credentials/${kind}`, { size: '20' }))).data;
    assert(Array.isArray(page.items) && !page.nextCursor, 'COMPLETE_ISOLATED_CREDENTIAL_PAGE_REQUIRED');
    ids[kind] = page.items.map(item => item.id).sort();
    assert(ids[kind].every(uuid), 'ACTUAL_NATIVE_CREDENTIAL_IDS_REQUIRED');
  }
  return ids;
}

async function verifyConsumer() {
  const entity = (await read(scope(`entities/consumers/${g.consumerId}`))).data.entity;
  assert.equal(entity.id, g.consumerId);
  assert(digest(entity.username) === digest(g.sourceInputs.consumer.username), 'ORIGINAL_CONSUMER_USERNAME_MISMATCH');
  assert(digest(entity.custom_id) === digest(g.sourceInputs.consumer.custom_id), 'ORIGINAL_CONSUMER_CUSTOM_ID_MISMATCH');
  assert(Array.isArray(entity.tags) && entity.tags.includes(`workspace:${g.workspaceCode}`), 'ACTUAL_CONSUMER_WORKSPACE_TAG_REQUIRED');
}

async function verifyPrivateCredentials() {
  const actual = await credentialIds();
  for (const kind of kinds) {
    assert.deepEqual(actual[kind], [g.credentialIds[kind]], 'ORIGINAL_NATIVE_CREDENTIAL_ID_MISMATCH');
    const entity = (await read(scope(`consumers/${g.consumerId}/credentials/${kind}/${g.credentialIds[kind]}`, { reveal: 'true' }))).data.entity;
    assert.equal(entity.id, g.credentialIds[kind]); assert.equal(entity.consumer.id, g.consumerId);
    for (const [field, original] of Object.entries(g.sourceInputs[kind])) {
      assert(digest(entity[field]) === digest(original), 'ORIGINAL_PRIVATE_CREDENTIAL_MATERIAL_MISMATCH');
    }
    if (kind === 'basic-auth') assert.equal(entity.recovery_capability, 'complete', 'ACTUAL_TRUSTED_BASIC_PASSWORD_REQUIRED');
  }
}

try {
  h.assertWritable(); await prerequisites();
  const priorStage = stages[stages.indexOf(stage) - 1];
  if (priorStage) assert.equal(g.stages[priorStage]?.state, 'succeeded', 'ORIGINAL_PREVIOUS_STAGE_SUCCESS_REQUIRED');
  assert(!g.stages[stage], 'ORIGINAL_PERSISTENT_STAGE_ALREADY_FINISHED_NO_REPLAY');
  if (stage === 'create-consumer') {
    assert(!g.consumerId && !g.credentialIds, 'NEW_INDEPENDENT_CONSUMER_NAMESPACE_REQUIRED'); allocatePrivateInputs();
    await read(scope(`entities/consumers/${g.sourceInputs.consumer.username}`), { expected: [404] });
    const record = g.intents[stage] ??= { body: { change: { kind: 'entity', action: 'create', entityType: 'consumers', body: g.sourceInputs.consumer } } }; h.save();
    await prepare(record, 1);
    const changed = record.receipt.review.changes[0]; assert.equal(changed.entityType, 'consumers'); assert(uuid(changed.nativeId));
    g.consumerId = changed.nativeId; h.save();
    await approveAndExecute(record, 1, 1); await verifyConsumer();
    const ids = await credentialIds(); for (const kind of kinds) assert.equal(ids[kind].length, 0, 'NEW_CONSUMER_SIX_DAOS_MUST_BE_EMPTY');
    check('Independent tagged Consumer B created by one new typed intent and three actual reviewer votes', { workflowId: record.workflowId, executionId: record.executionId, nativePackets: 1, baselineObjects: 1 });
  } else if (stage === 'create-credentials') {
    assert(g.sourceInputs && uuid(g.consumerId) && !g.credentialIds, 'ORIGINAL_NEW_CONSUMER_INPUTS_REQUIRED'); await verifyConsumer();
    const before = await credentialIds(); for (const kind of kinds) assert.equal(before[kind].length, 0, 'SIX_DAOS_MUST_START_EMPTY');
    const record = g.intents[stage] ??= { body: { change: { kind: 'batch', confirmed: true, operations: kinds.map(kind => ({
      kind: 'credential', action: 'create', consumerId: g.consumerId, credentialKind: kind, body: g.sourceInputs[kind],
    })) } } }; h.save(); await prepare(record, 6);
    const allocated = {};
    for (const kind of kinds) {
      const changes = record.receipt.review.changes.filter(item => item.entityType === kind); assert.equal(changes.length, 1); assert(uuid(changes[0].nativeId)); allocated[kind] = changes[0].nativeId;
    }
    g.credentialIds = allocated; h.save(); await approveAndExecute(record, 6, 7); await verifyPrivateCredentials();
    check('All six actual credential DAOs created in one independently approved typed batch', { workflowId: record.workflowId, executionId: record.executionId, nativePackets: 6, baselineObjects: 7, originalPrivateMaterialMatches: true });
  } else if (stage === 'delete-consumer') {
    assert(g.sourceInputs && g.credentialIds, 'ORIGINAL_SIX_CREDENTIAL_MATERIAL_REQUIRED'); await verifyConsumer(); await verifyPrivateCredentials();
    const record = g.intents[stage] ??= { body: { change: { kind: 'recycle', action: 'delete', entityType: 'consumers', entityId: g.consumerId,
      confirmed: true, confirm_name: g.sourceInputs.consumer.username } } }; h.save();
    await prepare(record, 7); await approveAndExecute(record, 7, 7, true);
    await read(scope(`entities/consumers/${g.consumerId}`), { expected: [404] });
    for (const kind of kinds) await read(scope(`consumers/${g.consumerId}/credentials/${kind}/${g.credentialIds[kind]}`), { expected: [404] });
    const page = (await read(scope('recycle-bin', { type: 'consumers', search: g.consumerId, size: '20' }))).data;
    assert(Array.isArray(page.items) && !page.nextCursor, 'COMPLETE_RECYCLE_CANDIDATE_PAGE_REQUIRED');
    const archives = page.items.filter(item => item.original_id === g.consumerId && item.state === 'deleted' && item.node_count === 7 && item.mutation_id === null);
    assert.equal(archives.length, 1, 'ONE_NEW_SOURCE_BOUND_SEVEN_NODE_ARCHIVE_REQUIRED'); assert(uuid(archives[0].id));
    record.entryId = archives[0].id; record.nodeCount = 7; h.save();
    check('Consumer B and its six original credential IDs removed with actual native204 and a complete seven-node recycle archive', { workflowId: record.workflowId, executionId: record.executionId, entryId: record.entryId, nativePackets: 7, nodeCount: 7 });
  } else {
    const deleted = g.intents['delete-consumer']; assert(uuid(deleted?.entryId) && g.sourceInputs && g.credentialIds, 'ORIGINAL_SEVEN_NODE_ARCHIVE_REQUIRED');
    await read(scope(`entities/consumers/${g.consumerId}`), { expected: [404] });
    const record = g.intents[stage] ??= { body: { change: { kind: 'recycle', action: 'restore', entryId: deleted.entryId,
      confirmed: true, confirm_name: g.sourceInputs.consumer.username } } }; h.save();
    await prepare(record, 7); await approveAndExecute(record, 7, 7); await verifyConsumer(); await verifyPrivateCredentials();
    const page = (await read(scope('recycle-bin', { type: 'consumers', search: g.consumerId, size: '20' }))).data;
    assert(Array.isArray(page.items) && !page.nextCursor, 'COMPLETE_RESTORED_ARCHIVE_PAGE_REQUIRED');
    const original = page.items.find(item => item.id === deleted.entryId); assert.equal(original?.state, 'restored'); assert.equal(original.original_id, g.consumerId);
    check('New three-vote restore preserves all seven original native IDs and privately verified six-DAO material', { workflowId: record.workflowId, executionId: record.executionId, entryId: deleted.entryId, nativePackets: 7, nodeCount: 7, originalPrivateMaterialMatches: true, authenticationProbesRun: false });
  }
  g.stages[stage] = { state: 'succeeded', finishedAt: new Date().toISOString() }; h.state.phase = `m11-persistent-credentials-${stage}-complete`; h.save(); report(true);
  console.log(JSON.stringify({ passed: true, stage, overallM11Accepted: false, credentialValuesRecorded: false, authenticationProbesRun: false }));
} catch (error) {
  g.stages[stage] = { state: 'stopped', finishedAt: new Date().toISOString() }; h.state.phase = `m11-persistent-credentials-${stage}-stopped`; h.save(); report(false);
  // Never emit assertion operands, upstream messages, request bodies or inputs.
  console.error(JSON.stringify({ passed: false, stage, errorCode: 'M11_PERSISTENT_CREDENTIAL_CYCLE_STOPPED', kind: error?.name === 'AssertionError' ? 'assertion' : 'runtime' })); process.exitCode = 1;
}
