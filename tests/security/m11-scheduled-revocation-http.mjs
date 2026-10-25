import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

// Source-only until Root invokes one stage. Root must not invoke revocation
// until a legitimate restore path is deployed: current IAM reactivation may
// reject existing bindings into an approval cluster with APPROVAL_REQUIRED.
// This script never changes cluster mode or roles, refreshes/logs in, creates
// an executor identity, invokes a worker or requests native execution.
assert.equal(process.env.RELEASE_LAB_M11_SCHEDULED_REVOCATION_READY, 'true');
assert.equal(process.argv.length, 3, 'EXACT_SCHEDULED_REVOCATION_STAGE_REQUIRED');
const stage = process.argv[2], stages = ['prepare', 'revoke-reviewer', 'restore-reviewer'];
assert(stages.includes(stage), 'FIXED_SCHEDULED_REVOCATION_STAGE_REQUIRED');
const reportPath = resolve(`artifacts/M11/gate4-scheduled-reviewer-revocation-${stage}-http-original.json`);
assert(!existsSync(reportPath), 'ORIGINAL_SCHEDULED_REVOCATION_REPORT_EXISTS');

const h = new ReleaseHarness('M11', { resume: true }), cid = h.state.cid, wid = h.state.wid;
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex'), scope = suffix => releaseScope(cid, wid, suffix);
const serviceId = h.state.gate2?.fixtures?.service?.id;
assert(uuid(cid) && uuid(wid) && uuid(serviceId), 'ORIGINAL_SCOPED_GATE2_SERVICE_REQUIRED');
if (stage === 'prepare') assert(!h.state.gate4ScheduledReviewerRevocation, 'ORIGINAL_REVIEWER_REVOCATION_PREPARE_ALREADY_STARTED');
else assert(h.state.gate4ScheduledReviewerRevocation?.stages?.prepare?.state === 'complete', 'ORIGINAL_REVIEWER_REVOCATION_PREPARE_REQUIRED');
const g = h.state.gate4ScheduledReviewerRevocation ??= { version: 1, clusterId: cid, workspaceId: wid, serviceId, stages: {}, writeKeys: {}, checks: [] };
assert.equal(g.version, 1); assert.equal(g.clusterId, cid); assert.equal(g.workspaceId, wid); assert.equal(g.serviceId, serviceId);
assert(!g.stages[stage], 'ORIGINAL_REVIEWER_REVOCATION_STAGE_ALREADY_STARTED_NO_REPLAY');
if (stage === 'restore-reviewer') assert.equal(g.stages['revoke-reviewer']?.state, 'complete', 'ORIGINAL_REVIEWER_REVOCATION_REQUIRED');

function session(label) {
  const actual = h.state.sessions[label];
  assert(uuid(actual?.user?.id) && uuid(actual.sid) && typeof actual.cookie === 'string', 'ROOT_ACTUAL_SESSION_REQUIRED');
  const access = actual.cookie.split('; ').find(pair => pair.startsWith('kongos_access=')); assert(access, 'ROOT_ACTUAL_ACCESS_COOKIE_REQUIRED');
  let claims; try { claims = JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1], 'base64url').toString()); }
  catch { throw Error('ROOT_ACTUAL_ACCESS_COOKIE_INVALID'); }
  assert.equal(claims.sub, actual.user.id); assert.equal(claims.sid, actual.sid);
  assert(Number.isFinite(claims.exp) && claims.exp * 1000 > Date.now() + 120_000, 'ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH');
  if (g.subjects) assert.equal(actual.user.id, g.subjects[label], 'ORIGINAL_REVIEWER_REVOCATION_SUBJECT_CHANGED');
  return actual;
}
const subjects = stage === 'prepare' ? Object.fromEntries(['admin', 'a', 'b', 'c'].map(label => [label, session(label).user.id])) : g.subjects;
assert.equal(new Set(Object.values(subjects)).size, 4, 'FOUR_DISTINCT_ACTUAL_APPROVAL_ACTORS_REQUIRED');
assert.notEqual(subjects.a, subjects.admin, 'ADMINISTRATOR_MUST_NOT_BE_DISABLED');
g.subjects ??= subjects; session('admin'); g.stages[stage] = { state: 'started', startedAt: new Date().toISOString() }; h.save();

const read = path => h.request(session('admin'), path, 'GET');
async function once(label, path, body, actor = 'admin') {
  const identity = `${stage}:${label}`, actualLabel = `m11-scheduled-reviewer-revocation-${stage}-${label}`;
  assert(!Object.hasOwn(g.writeKeys, identity), 'ORIGINAL_REVIEWER_REVOCATION_KEY_PRESENT_NO_REPLAY');
  const key = randomUUID(); assert(!h.state.requests.some(packet => packet.key === key || packet.label === actualLabel), 'ORIGINAL_REVIEWER_REVOCATION_REQUEST_PRESENT_NO_REPLAY');
  g.writeKeys[identity] = key; h.save();
  const result = await h.once(actualLabel, session(actor), path, 'POST', body, { key });
  const packets = h.state.requests.filter(packet => packet.key === key); assert.equal(packets.length, 1);
  assert.equal(packets[0].label, actualLabel); assert.equal(packets[0].state, 'response_observed'); assert(packets[0].status >= 200 && packets[0].status < 300);
  return result.data;
}
function check(name, facts = {}) { g.checks.push({ stage, name, passed: true, ...facts }); h.check(true, name, { stage, ...facts }); }
function report(passed) {
  const keys = new Set(Object.entries(g.writeKeys).filter(([key]) => key.startsWith(`${stage}:`)).map(([, value]) => value));
  const value = { passed, milestone: 'M11', stage, sourceOnly: false, productionDeployment: false, overallM11Accepted: false,
    environment: 'isolated authenticated BFF and real control-plane IAM', clusterId: cid, workspaceId: wid, serviceId,
    intentId: g.intentId ?? null, workflowId: g.workflowId ?? null, scheduleId: g.scheduleId ?? null, reviewerId: subjects.a,
    checks: g.checks.filter(item => item.stage === stage), requests: h.state.requests.filter(packet => keys.has(packet.key)).map(packet => ({
      method: packet.method, path: packet.path.split('?')[0], key: packet.key, state: packet.state, status: packet.status,
      requestId: packet.requestId, bodyHash: packet.bodyHash, responseHash: packet.responseHash,
      ...(typeof packet.errorCode === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(packet.errorCode) ? { errorCode: packet.errorCode } : {}) })),
    credentialValuesRecorded: false, sessionCookiesRecorded: false, workerInvoked: false, nativeExecutionEndpointInvoked: false,
    sqlNaturalTimerBlockedNoClaimSourceExecutionNativeVerification: 'pending-independent-Root-verification',
    limitations: ['Root must independently observe the natural API timer and prove the exact schedule is blocked with no SQL claim/source/execution/native operation before restoring the reviewer.',
      'Restoring active status does not restore revoked reviewer sessions; Root must log in again outside this script.',
      'Existing approval-cluster role bindings may currently prevent IAM reactivation. This script preserves that denial and never changes cluster mode or bypasses executionScopes.'],
    ...(!passed ? { errorCode: 'M11_SCHEDULED_REVIEWER_REVOCATION_HTTP_STOPPED' } : {}) };
  mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
}
const stableProfile = user => Object.fromEntries(['id', 'username', 'display_name', 'email', 'locale', 'timezone', 'auth_source', 'super_admin', 'force_password_change', 'created_at', 'deleted_at', 'retention_until'].map(key => [key, user[key] ?? null]));
async function roleBindings() {
  const rows = {};
  for (const [name, extra] of [['global', {}], ['workspace', { clusterId: cid, workspaceId: wid }]]) {
    const page = (await read(`/iam/users/${subjects.a}/role-bindings?${new URLSearchParams({ size: '100', ...extra })}`)).data;
    assert(Array.isArray(page.items) && !page.nextCursor, 'ISOLATED_COMPLETE_REVIEWER_BINDING_PAGE_REQUIRED');
    rows[name] = page.items.map(row => Object.fromEntries(['id', 'role_id', 'cluster_id', 'workspace_id', 'status', 'revision', 'expires_at'].map(key => [key, row[key] ?? null]))).sort((a, b) => a.id.localeCompare(b.id));
  }
  return rows;
}
async function otherUsers() {
  const rows = {};
  for (const label of ['admin', 'b', 'c']) { rows[label] = (await read(`/iam/users/${subjects[label]}`)).data; assert.equal(rows[label].status, 'active', 'OTHER_APPROVAL_ACTOR_MUST_REMAIN_ACTIVE'); }
  return rows;
}
function beforeDue() { assert(Date.now() + 10_000 < Date.parse(g.schedule.notBefore), 'REVIEWER_REVOCATION_TOO_CLOSE_TO_DUE_NO_REPLAY'); }

try {
  const cluster = (await read(`/clusters/${cid}`)).data; assert.equal(cluster.execution_mode, 'approval'); assert(/^1\.5\.\d+$/.test(cluster.version));
  if (stage === 'prepare') {
    g.originalReviewer = (await read(`/iam/users/${subjects.a}`)).data; assert.equal(g.originalReviewer.id, subjects.a); assert.equal(g.originalReviewer.status, 'active');
    assert.equal(g.originalReviewer.super_admin, false, 'ONLY_ISOLATED_NON_ADMIN_REVIEWER_MAY_BE_DISABLED');
    g.originalReviewerProfile = stableProfile(g.originalReviewer); g.originalBindings = await roleBindings(); g.originalBindingsSha256 = sha(g.originalBindings); h.save();
    await otherUsers();
    const definitions = (await read(releaseScope(cid, wid, 'workflow-definitions', { size: '100' }))).data;
    assert(Array.isArray(definitions.items) && !definitions.nextCursor); const current = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active'); assert.equal(current.length, 1);
    const definition = current[0], policy = definition.policy; assert.equal(definition.format, 2); assert.equal(policy.version, 2); assert.equal(policy.kind, 'native-change');
    assert.equal(policy.allowSelfApproval, false); assert.equal(policy.distinctAcrossStages, true); assert.equal(policy.stages.length, 2);
    assert.equal(policy.stages[0].mode, 'any'); assert.equal(policy.stages[0].threshold, 1); assert.deepEqual(policy.stages[0].selector, { users: [subjects.a] });
    assert.equal(policy.stages[1].mode, 'all'); assert.equal(policy.stages[1].threshold, null); assert.deepEqual(Object.keys(policy.stages[1].selector), ['users']);
    assert.deepEqual([...policy.stages[1].selector.users].sort(), [subjects.b, subjects.c].sort());
    const before = (await read(scope(`entities/services/${serviceId}`))).data.entity; assert.equal(before.id, serviceId); assert(Number.isSafeInteger(before.read_timeout) && before.read_timeout > 0 && before.read_timeout < 2147483647);
    const schema = (await read(scope('schemas/services'))).data, fields = Array.isArray(schema.fields) ? Object.assign({}, ...schema.fields) : schema.fields;
    assert(fields && Object.hasOwn(fields, 'read_timeout')); g.schemaSha256 = sha(schema); g.originalReadTimeout = before.read_timeout;
    const now = Date.now(); g.schedule = { version: 1, executorId: subjects.admin, windowStart: new Date(now + 120_000).toISOString(), notBefore: new Date(now + 120_000).toISOString(), windowEnd: new Date(now + 20 * 60_000).toISOString() };
    g.prepareBody = { change: { kind: 'entity', action: 'update', entityType: 'services', entityId: serviceId, body: { read_timeout: before.read_timeout + 1 } }, schedule: g.schedule, ttlHours: 1, confirmed: true, confirm_name: 'scheduled-change' }; h.save();
    const intent = await once('prepare', scope('entity-changes/prepare-scheduled'), g.prepareBody); assert(uuid(intent.id) && uuid(intent.schedule?.id)); assert.equal(intent.capabilities.scheduleSubmit, true); assert.equal(intent.nativeExecutionAvailable, false);
    assert.equal(intent.expiresAt, g.schedule.windowEnd); assert.equal(intent.schedule.executorId, subjects.admin); g.intentId = intent.id; g.scheduleId = intent.schedule.id; g.intentReceipt = intent; h.save();
    assert.notEqual(g.scheduleId, h.state.gate4ScheduledCancellation?.scheduleId); assert.notEqual(g.scheduleId, h.state.gate4ScheduledCore?.scheduleId);
    const submitted = await once('submit', scope(`entity-changes/${g.intentId}/submit`), { revision: intent.revision, materialHmac: intent.materialHmac, confirmed: true, confirm_name: 'native-change' });
    assert(uuid(submitted.workflowId)); g.workflowId = submitted.workflowId; h.save();
    for (const [index, reviewer] of ['a', 'b', 'c'].entries()) {
      const view = (await read(scope(`workflows/${g.workflowId}`))).data.entity; assert.equal(view.state, 'pending'); assert.equal(view.approval.format, 2);
      const active = view.approval.stages.find(item => item.state === 'active'); assert(active); assert.equal(active.level, index === 0 ? 1 : 2); assert.equal(active.threshold, index === 0 ? 1 : 2);
      await once(`vote-${reviewer}`, scope(`workflows/${g.workflowId}/approve`), { revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: 'native-change', execute: false,
        level: active.level, stageRevision: active.revision, candidateVersion: view.approval.candidateVersion }, reviewer);
      const after = (await read(scope(`workflows/${g.workflowId}`))).data.entity; assert.equal(after.state, index === 2 ? 'approved' : 'pending'); assert.equal(after.approval.stages.reduce((sum, item) => sum + item.votes, 0), index + 1);
    }
    const approved = (await read(scope(`workflows/${g.workflowId}`))).data.entity; assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, false); assert(uuid(approved.approval.approvalSetId));
    const pending = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity; assert.equal(pending.state, 'pending-approval'); assert.equal(pending.claimId, null); assert.equal(pending.capabilities.activate, true); beforeDue();
    const activated = await once('activate', scope(`entity-schedules/${g.scheduleId}/activate`), { revision: pending.revision, confirmed: true, confirm_name: 'activate-schedule' });
    assert.equal(activated.commandCompleted, true); assert.equal(activated.entity.state, 'active'); assert.equal(activated.entity.claimId, null); beforeDue();
    g.activeReceipt = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity; assert.equal(g.activeReceipt.state, 'active'); assert.equal(g.activeReceipt.claimId, null);
    assert.equal((await read(scope(`entities/services/${serviceId}`))).data.entity.read_timeout, g.originalReadTimeout);
    check('A new scheduled Service intent was approved by three actual independent reviewers and activated before due, without invoking HTTP execute');
  } else {
    const user = (await read(`/iam/users/${subjects.a}`)).data; assert.equal(user.id, subjects.a); assert.deepEqual(stableProfile(user), g.originalReviewerProfile);
    assert.equal(sha(await roleBindings()), g.originalBindingsSha256, 'ORIGINAL_REVIEWER_ROLE_BINDINGS_MUST_REMAIN_UNCHANGED');
    const others = await otherUsers();
    if (stage === 'revoke-reviewer') {
      assert.equal(user.status, 'active'); const schedule = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity;
      assert.equal(schedule.state, 'active'); assert.equal(schedule.claimId, null); beforeDue();
      g.disableBody = { revision: user.revision, confirmed: true, confirm_name: user.username, status: 'disabled' }; h.save();
      const receipt = await once('disable-a', `/iam/users/${subjects.a}/status`, g.disableBody); assert.equal(receipt.status, 'disabled'); assert.equal(receipt.id, subjects.a); assert.equal(receipt.revision, user.revision + 1);
      g.disabledReviewer = (await read(`/iam/users/${subjects.a}`)).data; assert.equal(g.disabledReviewer.status, 'disabled'); assert.equal(g.disabledReviewer.revision, receipt.revision);
      check('Only reviewer A was disabled through the actual global IAM status endpoint; its sessions are revoked by the platform, and Root must now observe the natural due timer');
    } else {
      assert.equal(user.status, 'disabled'); assert.equal(user.revision, g.disabledReviewer.revision, 'ORIGINAL_DISABLED_REVIEWER_REVISION_REQUIRED');
      const schedule = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity; assert.equal(schedule.state, 'blocked', 'NATURAL_TIMER_MUST_ALREADY_HAVE_BLOCKED_THE_SCHEDULE'); assert.equal(schedule.claimId, null);
      assert(Date.now() >= Date.parse(g.schedule.notBefore)); assert(typeof schedule.reasonCode === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(schedule.reasonCode));
      g.blockedHttpReceipt = schedule; g.restoreBody = { revision: user.revision, confirmed: true, confirm_name: user.username, status: 'active' }; h.save();
      const receipt = await once('restore-a', `/iam/users/${subjects.a}/status`, g.restoreBody); assert.equal(receipt.status, 'active'); assert.equal(receipt.id, subjects.a); assert.equal(receipt.revision, user.revision + 1);
      g.restoredReviewer = (await read(`/iam/users/${subjects.a}`)).data; assert.equal(g.restoredReviewer.status, 'active'); assert.equal(g.restoredReviewer.revision, receipt.revision);
      const after = (await read(scope(`entity-schedules/${g.scheduleId}`))).data.entity; assert.equal(after.state, 'blocked'); assert.equal(after.claimId, null); assert.deepEqual(after.capabilities, { activate: false, cancel: false });
      assert.equal((await read(scope(`entities/services/${serviceId}`))).data.entity.read_timeout, g.originalReadTimeout);
      check('Reviewer A was restored with a new metadata key/current revision; the old blocked occurrence stayed blocked and no native endpoint was invoked');
    }
    const finalUser = (await read(`/iam/users/${subjects.a}`)).data; assert.deepEqual(stableProfile(finalUser), g.originalReviewerProfile);
    assert.equal(sha(await roleBindings()), g.originalBindingsSha256); assert.deepEqual(await otherUsers(), others, 'ADMIN_AND_OTHER_REVIEWERS_MUST_NOT_CHANGE');
    check('Reviewer profile/role bindings and the actual administrator/reviewers B/C remained unchanged by the status command');
  }
  g.stages[stage].state = 'complete'; g.stages[stage].completedAt = new Date().toISOString(); h.save(); report(true);
  console.log(JSON.stringify({ passed: true, stage, sqlNaturalTimerNoSendVerified: false, overallM11Accepted: false }));
} catch {
  g.stages[stage].state = 'stopped-no-replay'; h.save(); report(false);
  console.error(JSON.stringify({ passed: false, stage, errorCode: 'M11_SCHEDULED_REVIEWER_REVOCATION_HTTP_STOPPED', originalRequestsRetained: true })); process.exitCode = 1;
}
