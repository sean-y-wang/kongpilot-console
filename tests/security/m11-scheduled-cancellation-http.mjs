import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

// Source-only unless Root explicitly invokes the isolated once stage. Syntax
// checks do not evaluate this module or read the private harness. This script
// never logs in, refreshes a session, executes a workflow or ticks a worker.
assert.equal(process.env.RELEASE_LAB_M11_SCHEDULED_CANCELLATION_READY, 'true');
assert.equal(process.argv.length, 3, 'EXACT_SCHEDULED_CANCELLATION_STAGE_REQUIRED');
assert.equal(process.argv[2], 'once', 'ONE_ORIGINAL_CANCELLATION_STAGE_REQUIRED');
const reportPath = resolve('artifacts/M11/gate4-scheduled-cancellation-http-original.json');
assert(!existsSync(reportPath), 'ORIGINAL_SCHEDULED_CANCELLATION_REPORT_EXISTS');

const h = new ReleaseHarness('M11', { resume: true }), cid = h.state.cid, wid = h.state.wid;
assert(!h.state.gate4ScheduledCancellation, 'ORIGINAL_SCHEDULED_CANCELLATION_STAGE_ALREADY_STARTED');
const actors = ['admin', 'a', 'b', 'c'], scope = suffix => releaseScope(cid, wid, suffix);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function session(label) {
  const actual = h.state.sessions[label];
  assert(uuid(actual?.user?.id) && uuid(actual.sid) && typeof actual.cookie === 'string', 'ROOT_ACTUAL_SESSION_REQUIRED');
  const access = actual.cookie.split('; ').find(pair => pair.startsWith('kongos_access='));
  assert(access, 'ROOT_ACTUAL_ACCESS_COOKIE_REQUIRED');
  let claims;
  try { claims = JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1], 'base64url').toString()); }
  catch { throw Error('ROOT_ACTUAL_ACCESS_COOKIE_INVALID'); }
  assert.equal(claims.sub, actual.user.id, 'ORIGINAL_ACTUAL_SUBJECT_REQUIRED');
  assert.equal(claims.sid, actual.sid, 'ORIGINAL_ACTUAL_SESSION_REQUIRED');
  // Stop above the harness's 90-second refresh threshold. Root owns all actual
  // fresh logins outside this stage; a stopped write is never retried here.
  assert(Number.isFinite(claims.exp) && claims.exp * 1000 > Date.now() + 120_000, 'ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH');
  if (h.state.gate4ScheduledCancellation?.subjects) assert.equal(actual.user.id, h.state.gate4ScheduledCancellation.subjects[label], 'ORIGINAL_CANCELLATION_SUBJECT_CHANGED');
  return actual;
}

const subjects = Object.fromEntries(actors.map(label => [label, session(label).user.id]));
assert.equal(new Set(Object.values(subjects)).size, 4, 'FOUR_DISTINCT_ACTUAL_CANCELLATION_ACTORS_REQUIRED');
const serviceId = h.state.gate2?.fixtures?.service?.id;
assert(uuid(cid) && uuid(wid) && uuid(serviceId), 'ORIGINAL_GATE2_SCOPED_SERVICE_REQUIRED');
const g = h.state.gate4ScheduledCancellation = {
  version: 1, stage: 'once', state: 'started', clusterId: cid, workspaceId: wid, serviceId,
  subjects, writeKeys: {}, checks: [], startedAt: new Date().toISOString(),
};
h.save();

const read = path => h.request(session('admin'), path, 'GET');
async function once(label, path, body, actor = 'admin') {
  assert(!Object.hasOwn(g.writeKeys, label), 'ORIGINAL_CANCELLATION_REQUEST_ALREADY_ALLOCATED');
  const key = randomUUID(), actualLabel = `m11-scheduled-cancellation-${label}`;
  assert(!h.state.requests.some(packet => packet.key === key || packet.label === actualLabel), 'ORIGINAL_CANCELLATION_REQUEST_PRESENT_NO_REPLAY');
  g.writeKeys[label] = key; h.save();
  const result = await h.once(actualLabel, session(actor), path, 'POST', body, { key });
  const packets = h.state.requests.filter(packet => packet.key === key);
  assert.equal(packets.length, 1, 'ONE_ORIGINAL_CANCELLATION_HTTP_REQUEST_REQUIRED');
  assert.equal(packets[0].label, actualLabel); assert.equal(packets[0].state, 'response_observed');
  assert(packets[0].status >= 200 && packets[0].status < 300, 'ORIGINAL_CANCELLATION_RECEIPT_SUCCESS_REQUIRED');
  return result.data;
}
function check(name, facts = {}) {
  const safe = { name, passed: true, ...facts }; g.checks.push(safe); h.check(true, name, facts);
}
function report(passed) {
  const keys = new Set(Object.values(g.writeKeys)), packets = h.state.requests.filter(packet => keys.has(packet.key));
  const value = {
    passed, milestone: 'M11', stage: 'gate4-scheduled-cancellation-once', sourceOnly: false,
    environment: 'isolated actual Kong OSS 1.5.x via authenticated BFF', productionDeployment: false, overallM11Accepted: false,
    clusterId: cid, workspaceId: wid, serviceId, intentId: g.intentId ?? null, scheduleId: g.scheduleId ?? null, workflowId: g.workflowId ?? null,
    fourDistinctActualActors: new Set(Object.values(g.subjects)).size === 4, finalScheduleState: g.finalState ?? null,
    checks: g.checks, requests: packets.map(packet => ({ method: packet.method, path: packet.path.split('?')[0], key: packet.key,
      state: packet.state, status: packet.status, requestId: packet.requestId, bodyHash: packet.bodyHash, responseHash: packet.responseHash,
      ...(typeof packet.errorCode === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(packet.errorCode) ? { errorCode: packet.errorCode } : {}) })),
    credentialValuesRecorded: false, sessionCookiesRecorded: false, directWorkerInvoked: false, nativeExecutionEndpointInvoked: false,
    sqlNoSourceExecutionClaimNativeVerification: 'pending-independent-Root-verification',
    limitations: ['HTTP cancellation receipts alone do not prove that no source, workflow execution, claim or native mutation exists. Root must independently verify the exact recorded schedule/workflow/intent in real SQL.'],
    ...(!passed ? { errorCode: 'M11_SCHEDULED_CANCELLATION_HTTP_STOPPED' } : {}),
  };
  mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
}
function assertBeforeDue() {
  assert(Date.now() + 10_000 < Date.parse(g.schedule.notBefore), 'CANCELLATION_STAGE_TOO_CLOSE_TO_DUE_NO_REPLAY');
}

try {
  const cluster = (await read(`/clusters/${cid}`)).data;
  assert.equal(cluster.execution_mode, 'approval', 'ACTUAL_APPROVAL_CLUSTER_REQUIRED'); assert(/^1\.5\.\d+$/.test(cluster.version), 'ACTUAL_KONG15_REQUIRED');
  const workspace = (await read(`/clusters/${cid}/workspaces/${wid}`)).data;
  assert.equal(workspace.id, wid); assert.equal(workspace.cluster_id, cid); assert.equal(workspace.status, 'active');
  const schema = (await read(scope('schemas/services'))).data;
  const fields = Array.isArray(schema.fields) ? Object.assign({}, ...schema.fields) : schema.fields;
  assert(fields && typeof fields === 'object' && Object.hasOwn(fields, 'read_timeout'), 'ACTUAL_SERVICE_TIMEOUT_SCHEMA_REQUIRED');
  g.schemaSha256 = sha(schema); h.save();
  const before = (await read(scope(`entities/services/${serviceId}`))).data.entity;
  assert.equal(before.id, serviceId); assert(Number.isSafeInteger(before.read_timeout) && before.read_timeout > 0 && before.read_timeout < 2147483647, 'ACTUAL_SERVICE_READ_TIMEOUT_REQUIRED');
  const definitions = (await read(releaseScope(cid, wid, 'workflow-definitions', { size: '100' }))).data;
  assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'ISOLATED_DEFINITION_PAGE_REQUIRED');
  const current = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active'); assert.equal(current.length, 1, 'ONE_ACTUAL_ACTIVE_NATIVE_POLICY_REQUIRED');
  const definition = current[0], policy = definition.policy;
  assert.equal(definition.format, 2); assert.equal(policy.version, 2); assert.equal(policy.kind, 'native-change');
  assert.equal(policy.allowSelfApproval, false); assert.equal(policy.distinctAcrossStages, true); assert.equal(policy.stages.length, 2);
  assert.equal(policy.stages[0].mode, 'any'); assert.equal(policy.stages[0].threshold, 1); assert.deepEqual(policy.stages[0].selector, { users: [subjects.a] });
  assert.equal(policy.stages[1].mode, 'all'); assert.equal(policy.stages[1].threshold, null);
  assert.deepEqual(Object.keys(policy.stages[1].selector), ['users']); assert.deepEqual([...policy.stages[1].selector.users].sort(), [subjects.b, subjects.c].sort());
  check('Actual approval cluster, Service schema and independent any/all policy were read through BFF');

  const now = Date.now();
  g.schedule = { version: 1, executorId: subjects.admin, windowStart: new Date(now + 120_000).toISOString(),
    notBefore: new Date(now + 125_000).toISOString(), windowEnd: new Date(now + 20 * 60_000).toISOString() };
  g.prepareBody = { change: { kind: 'entity', action: 'update', entityType: 'services', entityId: serviceId, body: { read_timeout: before.read_timeout + 1 } },
    schedule: g.schedule, ttlHours: 1, confirmed: true, confirm_name: 'scheduled-change' }; h.save();
  const intent = await once('prepare', scope('entity-changes/prepare-scheduled'), g.prepareBody);
  assert(uuid(intent.id) && uuid(intent.schedule?.id), 'ACTUAL_NEW_SCHEDULED_INTENT_REQUIRED');
  assert.equal(intent.executionMode, 'approval'); assert.equal(intent.nativeExecutionAvailable, false); assert.equal(intent.capabilities.scheduleSubmit, true);
  assert.equal(intent.expiresAt, g.schedule.windowEnd); assert.equal(intent.schedule.executorId, subjects.admin);
  for (const field of ['notBefore', 'windowStart', 'windowEnd']) assert.equal(intent.schedule[field], g.schedule[field]);
  g.intentId = intent.id; g.scheduleId = intent.schedule.id; g.intentReceipt = intent;
  assert.notEqual(g.scheduleId, h.state.gate4ScheduledCore?.scheduleId, 'INDEPENDENT_CANCELLATION_SCHEDULE_REQUIRED'); h.save();
  const submitted = await once('submit', scope(`entity-changes/${g.intentId}/submit`),
    { revision: intent.revision, materialHmac: intent.materialHmac, confirmed: true, confirm_name: 'native-change' });
  assert(uuid(submitted.workflowId), 'ACTUAL_NEW_CANCELLATION_WORKFLOW_REQUIRED'); g.workflowId = submitted.workflowId; h.save();
  for (const [index, reviewer] of ['a', 'b', 'c'].entries()) {
    const view = (await read(scope(`workflows/${g.workflowId}`))).data.entity;
    assert.equal(view.state, 'pending'); assert.equal(view.approval.format, 2); assert.equal(view.approval.stages.length, 2);
    const active = view.approval.stages.find(stage => stage.state === 'active'); assert(active, 'ACTUAL_ACTIVE_CANCELLATION_APPROVAL_STAGE_REQUIRED');
    assert.equal(active.level, index === 0 ? 1 : 2); assert.equal(active.threshold, index === 0 ? 1 : 2);
    await once(`vote-${reviewer}`, scope(`workflows/${g.workflowId}/approve`),
      { revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: 'native-change', execute: false,
        level: active.level, stageRevision: active.revision, candidateVersion: view.approval.candidateVersion }, reviewer);
    const after = (await read(scope(`workflows/${g.workflowId}`))).data.entity;
    assert.equal(after.state, index === 2 ? 'approved' : 'pending'); assert.equal(after.approval.stages.reduce((sum, stage) => sum + stage.votes, 0), index + 1);
  }
  const approved = (await read(scope(`workflows/${g.workflowId}`))).data.entity;
  assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, false); assert(uuid(approved.approval.approvalSetId), 'ACTUAL_COMPLETE_APPROVAL_SET_REQUIRED');
  check('New scheduled intent received three independent actual votes without HTTP native execution');

  const pending = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity;
  assert.equal(pending.state, 'pending-approval'); assert.equal(pending.claimId, null); assert.equal(pending.capabilities.activate, true); assert.equal(pending.capabilities.cancel, true);
  assertBeforeDue();
  const activated = await once('activate', scope(`entity-schedules/${g.scheduleId}/activate`), { revision: pending.revision, confirmed: true, confirm_name: 'activate-schedule' });
  assert.equal(activated.commandCompleted, true); assert.equal(activated.entity.id, g.scheduleId); assert.equal(activated.entity.state, 'active'); assert.equal(activated.entity.claimId, null);
  assert.equal(activated.entity.capabilities.activate, false); assert.equal(activated.entity.capabilities.cancel, true);
  const active = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity;
  assert.equal(active.state, 'active'); assert.equal(active.revision, activated.entity.revision); assert.equal(active.claimId, null); assertBeforeDue();
  const cancelled = await once('cancel', scope(`entity-schedules/${g.scheduleId}/cancel`), { revision: active.revision, confirmed: true, confirm_name: 'cancel-schedule' });
  assert.equal(cancelled.commandCompleted, true); assert.equal(cancelled.entity.state, 'cancelled'); assert.equal(cancelled.entity.claimId, null);
  assert.deepEqual(cancelled.entity.capabilities, { activate: false, cancel: false });
  const final = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity;
  assert.equal(final.id, g.scheduleId); assert.equal(final.state, 'cancelled'); assert.equal(final.claimId, null); assert.equal(final.revision, cancelled.entity.revision);
  assert.deepEqual(final.capabilities, { activate: false, cancel: false }); assert.equal(final.nativeAuthority, false);
  g.finalState = final.state; g.finalReceipt = final;
  const after = (await read(scope(`entities/services/${serviceId}`))).data.entity;
  assert.equal(after.read_timeout, before.read_timeout, 'READ_ONLY_SERVICE_TIMEOUT_UNCHANGED_REQUIRED');
  check('Owner activated and cancelled before due using original command keys and revisions; final HTTP state is cancelled with both buttons unavailable');
  check('A subsequent BFF read returns the original Service timeout; independent SQL no-send evidence remains pending');
  g.state = 'http-complete'; g.completedAt = new Date().toISOString(); h.save(); report(true);
  console.log(JSON.stringify({ passed: true, stage: 'gate4-scheduled-cancellation-once', checks: g.checks.length, sqlNoSendVerified: false, overallM11Accepted: false }));
} catch {
  g.state = 'stopped-no-replay'; h.save(); report(false);
  console.error(JSON.stringify({ passed: false, errorCode: 'M11_SCHEDULED_CANCELLATION_HTTP_STOPPED', originalRequestsRetained: true })); process.exitCode = 1;
}
