import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {closeSync, openSync, writeSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parse, stringify} from 'yaml';
import {ReleaseHarness, releaseScope} from './lib/release-harness.mjs';
import {assertReleaseReportDirectory, selectReleaseReportDirectory} from './lib/release-private-directory.mjs';

// Importing this Source runner performs no runtime, private-ledger or HTTP I/O.
// Root creates three genuinely new Service fixtures and controls its own API
// stop/restart externally. No stage executes a workflow or invokes a worker.
export const BUSINESS_SAFETY_CASES = Object.freeze(['cancel-before-due', 'restart-expiry', 'overlap']);
export const BUSINESS_SAFETY_STAGES = Object.freeze(['preflight', 'prepare', 'author', 'approve', 'activate', 'cancel', 'overlap-check', 'observe', 'inspect']);
const readonly = new Set(['observe', 'inspect']), own = (v, k) => v != null && Object.hasOwn(v, k);
const plain = v => v && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const uuid = v => typeof v === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const hex = v => typeof v === 'string' && /^[a-f\d]{64}$/.test(v);
const sha = v => createHash('sha256').update(v).digest('hex');
const canonical = v => v && typeof v === 'object' ? Array.isArray(v) ? v.map(canonical)
  : Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const fingerprint = v => sha(JSON.stringify(canonical(v))), entity = v => v?.entity ?? v;
const safeCode = e => /^[A-Z][A-Z0-9_]{2,100}$/.test(e?.message ?? '') ? e.message : 'BUSINESS_SAFETY_STAGE_FAILED';
const pause = ms => new Promise(done => setTimeout(done, ms));
const reserved = new Set([...Object.getOwnPropertyNames(Object.prototype), 'prototype']);
const namedCase = value => typeof value === 'string' && /^[a-z][a-z0-9-]{0,47}$/.test(value) && value !== 'original' && !reserved.has(value);

export function businessSafetySelection(env, scenario, stage) {
  assert(env.RELEASE_LAB_M11_BUSINESS_SAFETY_READY === 'true', 'EXPLICIT_BUSINESS_SAFETY_GATE_REQUIRED');
  assert(BUSINESS_SAFETY_CASES.includes(scenario) && BUSINESS_SAFETY_STAGES.includes(stage), 'EXACT_BUSINESS_SAFETY_CASE_AND_STAGE_REQUIRED');
  assert(!(scenario === 'overlap' && ['activate', 'cancel'].includes(stage)) && !(scenario !== 'overlap' && stage === 'overlap-check')
    && !(scenario === 'restart-expiry' && stage === 'cancel'), 'EXACT_BUSINESS_SAFETY_SCENARIO_STAGE_REQUIRED');
  const field = env.RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE;
  assert(typeof field === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(field) && !reserved.has(field), 'EXPLICIT_BUSINESS_SAFETY_FIXTURE_REQUIRED');
  const caseId = env.RELEASE_LAB_M11_BUSINESS_SAFETY_CASE;
  assert(caseId === undefined || namedCase(caseId), 'EXPLICIT_BUSINESS_SAFETY_NAMED_CASE_REQUIRED');
  return Object.freeze({scenario, fixtureField: field, ...(caseId === undefined ? {} : {caseId})});
}

export function businessSafetyWindow(deadlines, now = Date.now()) {
  assert(Array.isArray(deadlines) && deadlines.length > 0 && deadlines.every(v => typeof v === 'string' && Number.isFinite(Date.parse(v)))
    && Number.isSafeInteger(now), 'ORIGINAL_BUSINESS_SAFETY_DEADLINES_REQUIRED');
  const start = now + 180000, end = now + 300000;
  assert(end <= Math.min(now + 14 * 60000, ...deadlines.map(Date.parse)) - 5000, 'ORIGINAL_BUSINESS_SAFETY_DEADLINE_TOO_CLOSE_NO_REARM');
  return Object.freeze({notBefore: new Date(start).toISOString(), windowStart: new Date(start).toISOString(), windowEnd: new Date(end).toISOString()});
}

export function businessSafetyDesiredYaml(raw, fixture, beforeRetries, desiredRetries) {
  assert(typeof raw === 'string' && Buffer.byteLength(raw) > 0 && Buffer.byteLength(raw) <= 2 * 1024 * 1024, 'BOUNDED_BUSINESS_SAFETY_EXPORT_REQUIRED');
  const document = parse(raw);
  assert(document?._format_version === '1.1' && Array.isArray(document.services) && document.services.length === 1
    && uuid(fixture.serviceId) && document.services[0].id === fixture.serviceId && document.services[0].retries === beforeRetries
    && Number.isInteger(desiredRetries) && desiredRetries >= 0 && desiredRetries <= 32767 && desiredRetries !== beforeRetries,
  'EXACT_BUSINESS_SAFETY_EXPORTED_SERVICE_REQUIRED');
  // Partial merge deliberately preserves every other field and dependency.
  // No exported credential, plugin, environment field or key enters this input.
  return stringify({_format_version: '1.1', services: [{id: fixture.serviceId, retries: desiredRetries}]});
}

export function businessSafetyAssertPlan(view, serviceId, desiredRetries) {
  const p = view?.entity, s = view?.items?.[0];
  assert(uuid(p?.id) && Number.isInteger(p.planRevision) && p.planRevision > 0 && hex(p.planHash) && typeof p.name === 'string'
    && p.executionMode === 'approval' && p.approvalRequired === true && p.capabilities?.apply === true && p.stepCount === 1 && p.deleteCount === 0
    && (p.nativePacketCount === undefined || p.nativePacketCount === 1) && view.nextCursor === null && view.items.length === 1
    && s.entityType === 'services' && s.nativeId === serviceId && s.action === 'update' && s.referenceOnly === false
    && Array.isArray(s.blockerCodes) && s.blockerCodes.length === 0 && Array.isArray(s.patch) && s.patch.length === 1
    && s.patch[0].op === 'replace' && s.patch[0].path === '/retries' && s.patch[0].value === desiredRetries,
  'EXACT_ONE_SERVICE_RETRIES_PATCH_REQUIRED');
  if (p.counts) assert(p.counts.update === 1 && !p.counts.create && !p.counts.delete && !p.counts.conflict, 'ONLY_ONE_BUSINESS_SAFETY_UPDATE_REQUIRED');
  return p;
}

export function businessSafetyVoteBody(detail) {
  const row = detail?.entity, stages = row?.approval?.stages?.filter(s => s.state === 'active');
  assert(row?.kind === 'configuration_v2' && row.state === 'pending' && row.approvalRequired === true && row.capabilities?.approve === true
    && Number.isInteger(row.revision) && hex(row.planHash) && row.approval?.format === 2 && Number.isInteger(row.approval.candidateVersion)
    && stages?.length === 1 && Number.isInteger(stages[0].level) && Number.isInteger(stages[0].revision), 'REAL_INDEPENDENT_BUSINESS_SAFETY_FMT2_VOTE_REQUIRED');
  return {revision: row.revision, planHash: row.planHash, level: stages[0].level, stageRevision: stages[0].revision,
    candidateVersion: row.approval.candidateVersion, confirmed: true, confirm_name: 'configuration_v2', execute: false};
}

function session(h, g, reviewer = false) {
  const label = reviewer ? 'reviewer' : 'admin', value = reviewer ? h.state.metadataAcceptance?.reviewerSession : h.state.sessions?.admin;
  assert(uuid(value?.user?.id) && uuid(value.sid) && typeof value.cookie === 'string', 'ORIGINAL_BUSINESS_SAFETY_SESSION_REQUIRED');
  let claims; try { claims = JSON.parse(Buffer.from(value.cookie.split('; ').find(p => p.startsWith('kongos_access=')).slice('kongos_access='.length).split('.')[1], 'base64url').toString()); }
  catch { throw Error('ORIGINAL_BUSINESS_SAFETY_SESSION_REQUIRED'); }
  assert(claims.sub === value.user.id && claims.sid === value.sid && Number.isFinite(claims.exp) && claims.exp * 1000 > Date.now() + 120000,
    'FRESH_ORIGINAL_BUSINESS_SAFETY_SID_REQUIRED_NO_REFRESH');
  if (g) assert.deepEqual({id: value.user.id, sid: value.sid}, g.subjects[label], 'ORIGINAL_BUSINESS_SAFETY_ACTOR_OR_SID_CHANGED');
  return value;
}
function scope(g, path, extra) {return releaseScope(g.clusterId, g.workspaceId, path, extra);}
async function read(h, g, path, reviewer = false, expected = [200]) {return (await h.request(session(h, g, reviewer), path, 'GET', undefined, {expected})).data;}

export async function businessSafetyCommand(h, g, stage, label, path, body, {reviewer = false, expected = [200, 201], raw = false} = {}) {
  assert(BUSINESS_SAFETY_CASES.includes(g.scenario) && BUSINESS_SAFETY_STAGES.includes(stage) && !readonly.has(stage), 'WRITE_BUSINESS_SAFETY_STAGE_REQUIRED');
  const url = new URL(`http://synthetic.invalid${path}`), resource = url.pathname.slice(`/clusters/${g.clusterId}/`.length);
  assert(path.startsWith(`/clusters/${g.clusterId}/`) && !path.includes('://') && !path.includes('\\') && !path.includes('..')
    && url.searchParams.size === 1 && url.searchParams.get('workspaceId') === g.workspaceId,
  'FIXED_BUSINESS_SAFETY_SCOPE_REQUIRED');
  assert(/^(?:snapshots(?:\/[a-f\d-]{36}\/export)?|configuration\/(?:imports|exports\/[a-f\d-]{36}\/download|plans\/[a-f\d-]{36}\/apply)|workflows\/[a-f\d-]{36}\/approve|workflow-schedules(?:\/[a-f\d-]{36}\/(?:activate|cancel))?)$/.test(resource)
    && (!raw || /^configuration\/exports\/[a-f\d-]{36}\/download$/.test(resource)), 'FIXED_BUSINESS_SAFETY_COMMAND_REQUIRED');
  assert(Array.isArray(expected) && expected.length > 0 && expected.every(v => Number.isInteger(v) && (v >= 200 && v < 300 || v >= 400 && v < 500)), 'BUSINESS_SAFETY_UNKNOWN_WRITE_MUST_STAY_FENCED');
  const identity = `${stage}:${label}`, actualLabel = businessSafetyOnceLabel(g, identity);
  assert(!own(g.commands, identity) && !h.state.requests.some(p => p.label === actualLabel), 'ORIGINAL_BUSINESS_SAFETY_COMMAND_PRESENT_NO_REPLAY');
  h.assertWritable(); const actual = session(h, g, reviewer), key = randomUUID(), frozen = structuredClone(body);
  g.commands[identity] = {key, path, label: actualLabel, actor: reviewer ? 'reviewer' : 'admin', bodyHash: sha(JSON.stringify(frozen)), state: 'selected'}; h.save();
  const result = await h.once(actualLabel, actual, path, 'POST', frozen, {key, expected, raw});
  const packets = h.state.requests.filter(p => p.key === key && p.path === path && p.method === 'POST');
  assert(packets.length === 1 && packets[0].state === 'response_observed' && packets[0].label === actualLabel && packets[0].status === result.status
    && packets[0].actorId === actual.user.id && packets[0].sessionId === actual.sid && packets[0].bodyHash === sha(JSON.stringify(frozen))
    && packets[0].requestId === result.requestId, 'ORIGINAL_BUSINESS_SAFETY_PACKET_REQUIRED');
  Object.assign(g.commands[identity], {state: 'response_observed', status: result.status, requestId: result.requestId ?? null}); h.save(); return result;
}

export function businessSafetySelectedFixture(state, selected) {
  assert(BUSINESS_SAFETY_CASES.includes(selected.scenario) && typeof selected.fixtureField === 'string' && !reserved.has(selected.fixtureField)
    && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(selected.fixtureField)
    && (selected.caseId === undefined || namedCase(selected.caseId))
    && uuid(state.cid) && uuid(state.wid) && own(state.metadataAcceptance, selected.fixtureField), 'CURRENT_BUSINESS_SAFETY_FIXTURE_REQUIRED');
  const f = state.metadataAcceptance[selected.fixtureField];
  assert(plain(f) && Object.keys(f).sort().join(',') === 'clusterId,serviceId,workspaceId' && f.clusterId === state.cid && f.workspaceId === state.wid
    && uuid(f.serviceId), 'EXACT_NEW_BUSINESS_SAFETY_SERVICE_FIXTURE_REQUIRED');
  return Object.freeze({version: 1, scenario: selected.scenario, fixtureField: selected.fixtureField,
    clusterId: f.clusterId, workspaceId: f.workspaceId, serviceId: f.serviceId});
}
export function businessSafetyBindCase(selected, binding, subjects) {
  assert(namedCase(selected.caseId) && plain(binding)
    && Object.keys(binding).sort().join(',') === 'clusterId,fixtureField,scenario,serviceId,version,workspaceId'
    && binding.version === 1 && BUSINESS_SAFETY_CASES.includes(binding.scenario)
    && typeof binding.fixtureField === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(binding.fixtureField) && !reserved.has(binding.fixtureField)
    && uuid(binding.clusterId) && uuid(binding.workspaceId) && uuid(binding.serviceId)
    && selected.scenario === binding.scenario && selected.fixtureField === binding.fixtureField,
    'ORIGINAL_BUSINESS_SAFETY_NAMED_CASE_BINDING_REQUIRED');
  assert(plain(subjects) && Object.keys(subjects).sort().join(',') === 'admin,reviewer'
    && ['admin', 'reviewer'].every(role => plain(subjects[role]) && Object.keys(subjects[role]).sort().join(',') === 'id,sid'
      && uuid(subjects[role].id) && uuid(subjects[role].sid)) && subjects.admin.id !== subjects.reviewer.id,
  'ORIGINAL_BUSINESS_SAFETY_NAMED_SUBJECTS_REQUIRED');
  return Object.freeze({version: 1, caseId: selected.caseId, scenario: binding.scenario, fixtureField: binding.fixtureField,
    clusterId: binding.clusterId, workspaceId: binding.workspaceId, serviceId: binding.serviceId, subjects: structuredClone(subjects)});
}

export function businessSafetyOnceLabel(g, identity) {
  if (!g.caseBinding) {
    assert(g.version !== 2, 'ORIGINAL_BUSINESS_SAFETY_NAMED_CASE_BINDING_REQUIRED');
    return `m11-business-safety:${g.scenario}:${identity}`;
  }
  assert(g.version === 2 && g.scenario === g.binding?.scenario && g.clusterId === g.binding.clusterId && g.workspaceId === g.binding.workspaceId,
    'ORIGINAL_BUSINESS_SAFETY_NAMED_CASE_SCOPE_CHANGED');
  const selected = {caseId: g.caseBinding.caseId, scenario: g.scenario, fixtureField: g.binding.fixtureField};
  assert.deepEqual(g.caseBinding, businessSafetyBindCase(selected, g.binding, g.subjects), 'ORIGINAL_BUSINESS_SAFETY_NAMED_CASE_BINDING_CHANGED');
  return `m11-business-safety.case:${g.scenario}:${selected.caseId}:${identity}`;
}

export function businessSafetyCaseOwnership(state, binding, selected = {scenario: binding.scenario, fixtureField: binding.fixtureField}) {
  assert.deepEqual(binding, businessSafetySelectedFixture(state, selected), 'ORIGINAL_BUSINESS_SAFETY_FIXTURE_CHANGED');
  const cases = state.currentBusinessScheduleSafetyCases, named = state.currentBusinessScheduleSafetyNamedCases;
  assert((cases === undefined || plain(cases)) && (named === undefined || plain(named)), 'ORIGINAL_BUSINESS_SAFETY_CASE_STORE_INVALID');
  const occupied = [state.metadataAcceptance?.service?.id, state.currentPortalNaturalOriginal?.fixture?.serviceId,
    state.currentPromoteNaturalOriginal?.fixtures?.source?.nativeId, state.currentPromoteNaturalOriginal?.fixtures?.target?.nativeId];
  for (const g of Object.values(state.currentPortalNaturalCases ?? {})) {
    assert(g?.caseBinding?.fixtureField !== binding.fixtureField, 'BUSINESS_SAFETY_FIXTURE_ALREADY_OWNED'); occupied.push(g?.fixture?.serviceId);
  }
  const entries = Object.entries(cases ?? {}).map(([scenario, value]) => ({scenario, value}));
  for (const [scenario, store] of Object.entries(named ?? {})) {
    assert(BUSINESS_SAFETY_CASES.includes(scenario) && plain(store), 'ORIGINAL_BUSINESS_SAFETY_CASE_STORE_INVALID');
    for (const [caseId, value] of Object.entries(store)) {
      assert(namedCase(caseId), 'ORIGINAL_BUSINESS_SAFETY_CASE_STORE_INVALID'); entries.push({scenario, caseId, value});
    }
  }
  const fields = new Set(), services = new Set();
  for (const {scenario, caseId, value: g} of entries) {
    assert(BUSINESS_SAFETY_CASES.includes(scenario) && plain(g) && g.version === (caseId === undefined ? 1 : 2)
      && g.scenario === scenario && g.binding?.scenario === scenario && g.clusterId === state.cid && g.workspaceId === state.wid
      && plain(g.subjects) && Object.keys(g.subjects).sort().join(',') === 'admin,reviewer'
      && ['admin', 'reviewer'].every(role => plain(g.subjects[role]) && Object.keys(g.subjects[role]).sort().join(',') === 'id,sid'
        && uuid(g.subjects[role].id) && uuid(g.subjects[role].sid)) && g.subjects.admin.id !== g.subjects.reviewer.id
      && plain(g.runs) && plain(g.commands) && plain(g.lanes) && Array.isArray(g.deadlines) && Array.isArray(g.observations),
    'ORIGINAL_BUSINESS_SAFETY_CASE_STORE_INVALID');
    assert.deepEqual(g.binding, businessSafetySelectedFixture(state, g.binding), 'ORIGINAL_BUSINESS_SAFETY_FIXTURE_CHANGED');
    if (caseId === undefined) assert(!own(g, 'caseBinding'), 'ORIGINAL_BUSINESS_SAFETY_CASE_STORE_INVALID');
    else {
      assert(g.caseBinding?.caseId === caseId, 'ORIGINAL_BUSINESS_SAFETY_NAMED_CASE_BINDING_CHANGED');
      businessSafetyOnceLabel(g, 'fixture-ownership');
    }
    assert(!fields.has(g.binding.fixtureField) && !services.has(g.binding.serviceId.toLowerCase()), 'BUSINESS_SAFETY_FIXTURE_ALREADY_OWNED');
    fields.add(g.binding.fixtureField); services.add(g.binding.serviceId.toLowerCase());
    if (scenario !== selected.scenario || caseId !== selected.caseId) {
      assert(g.binding.fixtureField !== binding.fixtureField, 'BUSINESS_SAFETY_FIXTURE_ALREADY_OWNED'); occupied.push(g.binding.serviceId);
    }
  }
  assert(!occupied.some(id => uuid(id) && id.toLowerCase() === binding.serviceId.toLowerCase()), 'BUSINESS_SAFETY_SERVICE_MUST_BE_INDEPENDENT');
}
function retain(g, ...values) {
  for (const v of values) for (const date of [v?.expiresAt, v?.authorityExpiresAt]) if (typeof date === 'string' && Number.isFinite(Date.parse(date)) && !g.deadlines.includes(date)) g.deadlines.push(date);
}
function beforeDue(g, margin = 5000) {
  assert(g.window && Date.now() + margin < Date.parse(g.window.notBefore) && g.deadlines.length > 0
    && g.deadlines.every(v => Date.parse(g.window.windowEnd) <= Date.parse(v)), 'ORIGINAL_BUSINESS_SAFETY_WINDOW_TOO_CLOSE_NO_REARM');
}
function done(g, stage) {assert(g.runs[stage]?.state === 'succeeded', 'PREVIOUS_BUSINESS_SAFETY_STAGE_REQUIRED');}
function singleReviewer(row, id) {
  const p = row?.policy, s = p?.stages?.[0];
  return row?.kind === 'configuration_v2' && row.format === 2 && row.status === 'active' && hex(row.policyHash) && p.version === 2
    && p.kind === row.kind && p.allowSelfApproval === false && p.distinctAcrossStages === true && p.stages.length === 1 && s.level === 1
    && s.mode === 'any' && s.threshold === 1 && Object.keys(s.selector ?? {}).join(',') === 'users'
    && s.selector.users?.length === 1 && s.selector.users[0] === id;
}
async function current(h, g) {
  const cluster = await read(h, g, `/clusters/${g.clusterId}`), service = entity(await read(h, g, scope(g, `entities/services/${g.binding.serviceId}`)));
  assert(cluster.execution_mode === 'approval' && /^1\.5\.\d+$/.test(cluster.version ?? '') && !['disabled', 'incompatible'].includes(cluster.status)
    && service.id === g.binding.serviceId && Number.isInteger(service.retries), 'ACTUAL_BUSINESS_SAFETY_APPROVAL_SCOPE_REQUIRED');
  const definitions = await read(h, g, scope(g, 'workflow-definitions', {size: '100'}));
  const matches = definitions.items?.filter(row => row.kind === 'configuration_v2' && row.status === 'active');
  assert(!definitions.nextCursor && matches?.length === 1 && singleReviewer(matches[0], g.subjects.reviewer.id), 'CURRENT_SINGLE_REVIEWER_CONFIGURATION_POLICY_REQUIRED');
  const observed = {clusterRevision: cluster.revision, serviceFingerprint: fingerprint(service), policyId: matches[0].id,
    policyVersion: matches[0].version, policyHash: matches[0].policyHash};
  if (g.original) assert.deepEqual(observed, g.original, 'ORIGINAL_BUSINESS_SAFETY_NATIVE_SCOPE_OR_POLICY_CHANGED');
  else {g.original = observed; g.beforeRetries = service.retries; h.save();}
}
async function workflow(h, g, lane, reviewer = false) {return read(h, g, scope(g, `workflows/${lane.workflowId}`), reviewer);}
async function schedule(h, g, lane) {return entity(await read(h, g, scope(g, `workflow-schedules/${lane.scheduleId}`)));}
function configurationReceipt(g, value, label, kind) {
  assert(value?.domain === 'configuration' && value.durable === true && value.kind === kind && uuid(value.jobId)
    && value.id === value.jobId && value.clusterId === g.clusterId && value.workspaceId === g.workspaceId
    && value.actorId === g.subjects.admin.id && value.originalScope?.clusterId === g.clusterId && value.originalScope.workspaceId === g.workspaceId
    && value.idempotencyKey === g.commands[`prepare:${label}`].key, 'ORIGINAL_BUSINESS_SAFETY_CONFIGURATION_RECEIPT_REQUIRED');
  return value;
}
async function prepareLane(h, g, name) {
  const captureName = `M11 ${g.scenario} ${name} ${randomUUID().slice(0, 8)}`, root = {scope: 'services', serviceIds: [g.binding.serviceId]};
  const write = (label, path, body, opts) => businessSafetyCommand(h, g, 'prepare', `${name}-${label}`, scope(g, path), body, opts);
  const captured = configurationReceipt(g, (await write('snapshot', 'snapshots', {...root, name: captureName})).data, `${name}-snapshot`, 'capture');
  assert(captured.state === 'succeeded' && uuid(captured.snapshotId), 'REAL_BUSINESS_SAFETY_SNAPSHOT_REQUIRED');
  const exported = configurationReceipt(g, (await write('export', `snapshots/${captured.snapshotId}/export`, {mode: 'deployment', confirmed: true, confirm_name: captureName})).data, `${name}-export`, 'export');
  assert(exported.state === 'succeeded' && uuid(exported.exportId) && Number.isInteger(exported.exportRevision)
    && exported.capabilities?.download === true && exported.confirmationName === captureName, 'REAL_BUSINESS_SAFETY_EXPORT_REQUIRED');
  const downloaded = await write('download', `configuration/exports/${exported.exportId}/download`,
    {revision: exported.exportRevision, confirmed: true, confirm_name: captureName}, {raw: true});
  assert(Buffer.isBuffer(downloaded.bytes), 'COMPLETE_ORIGINAL_BUSINESS_SAFETY_DOWNLOAD_REQUIRED');
  assert(downloaded.headers?.get('cache-control') === 'no-store' && /^application\/yaml\b/.test(downloaded.headers.get('content-type') ?? '')
    && downloaded.headers.get('x-content-type-options') === 'nosniff', 'ORIGINAL_BUSINESS_SAFETY_YAML_STREAM_REQUIRED');
  const downloadReceipt = configurationReceipt(g, await read(h, g, scope(g, `configuration/jobs/by-key/${g.commands[`prepare:${name}-download`].key}`)), `${name}-download`, 'export');
  assert(downloadReceipt.state === 'succeeded' && downloadReceipt.downloadPermitConsumed === true && downloadReceipt.exportId === exported.exportId
    && downloadReceipt.byteCount === downloaded.bytes.length, 'ORIGINAL_BUSINESS_SAFETY_DOWNLOAD_PERMIT_REQUIRED');
  const desired = name === 'A' ? g.beforeRetries === 0 ? 1 : 0 : g.beforeRetries === 2 ? 1 : 2;
  const yaml = businessSafetyDesiredYaml(downloaded.bytes.toString('utf8'), g.binding, g.beforeRetries, desired);
  const imported = configurationReceipt(g, (await write('import', 'configuration/imports', {...root, mode: 'merge', yaml})).data, `${name}-import`, 'import');
  assert(imported.state === 'succeeded' && uuid(imported.planId) && uuid(imported.jobId), 'REAL_BUSINESS_SAFETY_IMPORT_PLAN_REQUIRED'); retain(g, imported);
  const view = await read(h, g, scope(g, `configuration/plans/${imported.planId}`, {size: '100'})), plan = businessSafetyAssertPlan(view, g.binding.serviceId, desired); retain(g, plan);
  const applied = configurationReceipt(g, (await write('apply', `configuration/plans/${plan.id}/apply`, {planRevision: plan.planRevision, planHash: plan.planHash,
    confirmed: true, confirm_name: plan.name, driver: 'bff'})).data, `${name}-apply`, 'apply');
  assert(applied.state === 'waiting_approval' && applied.executionCompleted === false && applied.registrationCompleted === true
    && applied.submissionCompleted === true && uuid(applied.workflowId) && uuid(applied.jobId) && applied.jobId !== imported.jobId,
  'REAL_BUSINESS_SAFETY_APPROVAL_ONLY_WRAPPER_REQUIRED'); retain(g, applied);
  const lane = {name, snapshotId: captured.snapshotId, importJobId: imported.jobId, planId: plan.id, applyJobId: applied.jobId,
    desiredRetries: desired, workflowId: applied.workflowId}; g.lanes[name] = lane; h.save();
  const detail = await workflow(h, g, lane), row = detail.entity;
  assert(row.kind === 'configuration_v2' && row.state === 'pending' && row.approval?.format === 2 && detail.decisions.length === 0
    && detail.steps.length === 1 && detail.steps[0].kind === 'metadata' && detail.steps[0].state === 'pending' && !detail.steps[0].operationId,
  'UNVOTED_BUSINESS_SAFETY_METADATA_WRAPPER_REQUIRED');
  lane.originalWorkflow = {revision: row.revision, planRevision: row.planRevision, planHash: row.planHash, expiresAt: row.expiresAt,
    stepIds: detail.steps.map(s => s.id)}; retain(g, row); h.save();
}
async function cancelLane(h, g, lane, stage) {
  beforeDue(g); const row = await schedule(h, g, lane);
  assert(['pending-approval', 'active'].includes(row.state) && row.claimId === null && row.workflowPlanHash === lane.scheduledWorkflow.planHash,
    'ORIGINAL_UNCLAIMED_BUSINESS_SAFETY_CANCEL_REQUIRED');
  const result = (await businessSafetyCommand(h, g, stage, `${lane.name}-cancel`, scope(g, `workflow-schedules/${row.id}/cancel`),
    {revision: row.revision, confirmed: true, confirm_name: 'cancel-schedule'})).data;
  assert(result.commandCompleted && result.entity?.id === row.id && result.entity.state === 'cancelled' && result.entity.claimId === null
    && result.entity.revision === row.revision + 1, 'ORIGINAL_BUSINESS_SAFETY_CANCEL_CAS_REQUIRED');
  lane.cancelled = {revision: result.entity.revision}; h.save();
}

async function runStage(h, g, stage) {
  if (stage === 'inspect') {
    g.inspections = [];
    for (const lane of Object.values(g.lanes)) {
      const observed = {workflowId: lane.workflowId, workflow: (await workflow(h, g, lane)).entity.state};
      if (lane.scheduleId) observed.schedule = await schedule(h, g, lane);
      g.inspections.push(observed); h.save();
    }
    return;
  }
  await current(h, g);
  if (stage === 'preflight') return;
  if (stage === 'prepare') {done(g, 'preflight'); for (const name of g.scenario === 'overlap' ? ['A', 'B'] : ['A']) await prepareLane(h, g, name); return;}
  if (stage === 'author') {
    done(g, 'prepare'); assert(!g.window, 'ORIGINAL_BUSINESS_SAFETY_WINDOW_PRESENT_NO_REARM'); g.window = businessSafetyWindow(g.deadlines); h.save();
    for (const lane of Object.values(g.lanes)) {
      beforeDue(g, 30000); const detail = await workflow(h, g, lane), row = detail.entity;
      assert(row.state === 'pending' && !row.scheduled && row.planHash === lane.originalWorkflow.planHash && row.planRevision === lane.originalWorkflow.planRevision
        && detail.decisions.length === 0, 'ORIGINAL_BUSINESS_SAFETY_AUTHOR_BEFORE_VOTE_REQUIRED');
      const result = (await businessSafetyCommand(h, g, stage, `${lane.name}-author`, scope(g, 'workflow-schedules'), {workflowId: row.id,
        revision: row.revision, planRevision: row.planRevision, planHash: row.planHash, spec: g.window, confirmed: true, confirm_name: 'schedule-workflow'})).data;
      const s = result.entity; assert(result.commandCompleted && uuid(s?.id) && s.state === 'pending-approval' && s.claimId === null && s.nativeAuthority === false
        && s.workflowId === row.id && s.executorId === g.subjects.admin.id, 'ORIGINAL_BUSINESS_SAFETY_SCHEDULE_REQUIRED');
      for (const field of ['notBefore', 'windowStart', 'windowEnd']) assert.equal(s[field], g.window[field], 'ORIGINAL_BUSINESS_SAFETY_WINDOW_CHANGED');
      lane.scheduleId = s.id; const after = await workflow(h, g, lane), next = after.entity;
      const steps = after.steps.filter(s => !lane.originalWorkflow.stepIds.includes(s.id));
      assert(next.state === 'pending' && next.planRevision === row.planRevision + 1 && next.planHash !== row.planHash && next.expiresAt === row.expiresAt
        && steps.length === 1 && steps.every(s => s.state === 'pending' && !s.operationId) && after.decisions.length === 0,
      'NEW_BUSINESS_SAFETY_REVISION_WITH_ORIGINAL_DEADLINE_REQUIRED');
      lane.scheduledWorkflow = {planRevision: next.planRevision, planHash: next.planHash, stepIds: steps.map(s => s.id)}; h.save();
    }
  } else if (stage === 'approve') {
    done(g, 'author'); beforeDue(g, 15000);
    for (const lane of Object.values(g.lanes)) {
      const detail = await workflow(h, g, lane, true), row = detail.entity;
      assert(row.planHash === lane.scheduledWorkflow.planHash && row.planRevision === lane.scheduledWorkflow.planRevision, 'EXACT_BUSINESS_SAFETY_VOTED_REVISION_REQUIRED');
      const approved = entity((await businessSafetyCommand(h, g, stage, `${lane.name}-vote`, scope(g, `workflows/${lane.workflowId}/approve`),
        businessSafetyVoteBody(detail), {reviewer: true})).data);
      assert(approved.state === 'approved' && approved.capabilities.execute === false, 'ORIGINAL_APPROVED_BUSINESS_SAFETY_SCHEDULE_REQUIRED');
    }
  } else if (stage === 'activate' || stage === 'overlap-check') {
    done(g, 'approve'); beforeDue(g, 30000);
    const activate = async (lane, expected) => {
      const row = await schedule(h, g, lane); assert(row.state === 'pending-approval' && row.claimId === null, 'ORIGINAL_BUSINESS_SAFETY_ACTIVATION_REQUIRED');
      const result = await businessSafetyCommand(h, g, stage, `${lane.name}-activate`, scope(g, `workflow-schedules/${row.id}/activate`),
        {revision: row.revision, confirmed: true, confirm_name: 'activate-schedule'}, {expected}); return {row, result};
    };
    const a = await activate(g.lanes.A, [200, 201]);
    assert(a.result.data.commandCompleted && a.result.data.entity.state === 'active' && a.result.data.entity.claimId === null, 'ACTIVE_ORIGINAL_BUSINESS_SAFETY_SCHEDULE_REQUIRED');
    if (stage === 'overlap-check') {
      let primary, cleanupError;
      try {
        g.lanes.A.activation = a.result.data.entity; h.save();
        const bWorkflowBefore = await workflow(h, g, g.lanes.B);
        const b = await activate(g.lanes.B, [200, 201, 400, 401, 403, 404, 409, 422]), after = await schedule(h, g, g.lanes.B);
        const packet = h.state.requests.find(p => p.key === g.commands[`${stage}:B-activate`].key);
        const exactConflict = b.result.status === 409 && packet?.errorCode === 'WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT'
          && fingerprint(after) === fingerprint(b.row) && fingerprint(await workflow(h, g, g.lanes.B)) === fingerprint(bWorkflowBefore);
        g.overlapObservation = {status: b.result.status, errorCode: /^[A-Z][A-Z0-9_]{2,100}$/.test(packet?.errorCode ?? '') ? packet.errorCode : null,
          originalRevisionUnchanged: after.revision === b.row.revision, originalStateUnchanged: after.state === b.row.state, exactConflict}; h.save();
        assert(exactConflict, 'EXACT_BUSINESS_SAFETY_PHYSICAL_CONFLICT_REQUIRED');
      } catch (error) {primary = error;}
      // Even a known unexpected response must not leave a future executable A.
      // Read failures still enter this cleanup. Unknown/5xx are stopped by the
      // original global fence before selecting any new cleanup command/key.
      for (const lane of Object.values(g.lanes)) try {h.assertWritable(); await cancelLane(h, g, lane, stage);}
      catch (error) {cleanupError ??= error; g.cleanupIncomplete = true;}
      if (primary) throw primary;
      if (cleanupError) throw cleanupError;
    } else {g.lanes.A.activation = a.result.data.entity; h.save();}
  } else if (stage === 'cancel') {done(g, 'activate'); await cancelLane(h, g, g.lanes.A, stage);
  } else if (stage === 'observe') {
    done(g, g.scenario === 'overlap' ? 'overlap-check' : g.scenario === 'cancel-before-due' ? 'cancel' : 'activate');
    assert(Date.now() >= Date.parse(g.window.windowEnd), 'ORIGINAL_BUSINESS_SAFETY_WINDOW_MUST_HAVE_ENDED');
    for (const lane of Object.values(g.lanes)) {
      let row; const deadline = Date.now() + 30000;
      do {row = await schedule(h, g, lane); if (row.state !== 'active') break; await pause(1000);} while (Date.now() < deadline);
      assert(row.state === (g.scenario === 'restart-expiry' ? 'expired' : 'cancelled') && row.claimId === null && row.nativeAuthority === false,
        'EXPECTED_BUSINESS_SAFETY_TERMINAL_WITHOUT_HTTP_CLAIM_REQUIRED');
      if (g.scenario === 'restart-expiry') assert(row.reasonCode === 'WORKFLOW_SCHEDULE_WINDOW_EXPIRED', 'NATURAL_ORIGINAL_BUSINESS_SAFETY_EXPIRY_REQUIRED');
      const detail = await workflow(h, g, lane), job = entity(await read(h, g, scope(g, `configuration/jobs/${lane.applyJobId}`)));
      assert(detail.entity.state === 'approved' && detail.entity.planHash === lane.scheduledWorkflow.planHash
        && detail.steps.every(s => s.state === 'pending' && !s.operationId) && job.state === 'waiting_approval' && job.executionCompleted === false && job.executionId == null,
      'UNCHANGED_BUSINESS_SAFETY_WORKFLOW_AND_JOB_REQUIRED');
      g.observations.push({scheduleId: row.id, state: row.state, claimId: row.claimId, revision: row.revision, reasonCode: row.reasonCode,
        workflowState: detail.entity.state, jobState: job.state, observedAt: new Date().toISOString()}); h.save();
    }
  }
}

export function businessSafetyPublicReport(h, g, selection, stage, passed, start, errorCode) {
  return {milestone: 'M11', scenario: selection.scenario, fixtureField: selection.fixtureField, stage, passed, sourceOnly: false,
    ...(selection.caseId === undefined ? {} : {caseId: selection.caseId}),
    productionDeployment: false, overallM11Accepted: false, rootSqlFactsVerified: false, rootRestartTimelineVerified: false,
    credentialsPublished: false, manualWorkerInvoked: false, workflowExecuteInvoked: false, originalDeadlineExtended: false,
    ...(g ? {clusterId: g.clusterId, workspaceId: g.workspaceId, serviceId: g.binding.serviceId, window: g.window ?? null,
      lanes: Object.values(g.lanes).map(l => ({name: l.name, planId: l.planId, applyJobId: l.applyJobId, workflowId: l.workflowId, scheduleId: l.scheduleId ?? null})),
      overlapObservation: g.overlapObservation ?? null, cleanupIncomplete: g.cleanupIncomplete ?? false, observations: g.observations} : {}),
    requests: (h?.state.requests ?? []).slice(start).map(p => ({method: p.method, path: p.path.split('?')[0], keySha256: sha(p.key ?? ''),
      status: p.status ?? null, state: p.state, requestId: p.requestId ?? null, bodyHash: p.bodyHash ?? null,
      errorCode: /^[A-Z][A-Z0-9_]{2,100}$/.test(p.errorCode ?? '') ? p.errorCode : null})),
    ...(errorCode ? {errorCode, message: '验收未通过，原始请求已保留，请按原键核验。'} : {}),
    limitations: ['BFF terminal/claimId/unchanged Service observations do not independently prove zero SQL claims or Native requests.',
      'Root must verify real claim/lease/W-E-origin/mutations/audit facts, original candidate identity and zero Native transport.',
      'Restart-expiry requires independent proof that Root stopped only its own API before original notBefore and restarted after original windowEnd.',
      'No timer tick, clock change, deadline renewal, SID replacement or historical-case cleanup is performed.']};
}

export async function main(env = process.env, scenario = process.argv[2], stage = process.argv[3]) {
  const selection = businessSafetySelection(env, scenario, stage), reports = selectReleaseReportDirectory('M11');
  assert(reports.custom, 'ISOLATED_BUSINESS_SAFETY_REPORT_DIRECTORY_REQUIRED'); assertReleaseReportDirectory(reports, {create: true});
  const fd = openSync(resolve(reports.directory, `business-schedule-safety-${scenario}${selection.caseId === undefined ? '' : `-${selection.caseId}`}-${stage}.json`), 'wx', 0o644);
  let h, g, start = 0, selected = false, started = false;
  try {
    h = new ReleaseHarness('M11', {resume: true}); start = h.state.requests.length;
    const originalRequest = h.request.bind(h);
    h.request = (who, path, ...args) => {
      assert(!path.startsWith('/auth/'), 'IMPLICIT_BUSINESS_SAFETY_AUTH_TRANSPORT_FORBIDDEN');
      if (readonly.has(stage)) assert(['GET', 'HEAD'].includes(args[0] ?? 'GET'), 'BUSINESS_SAFETY_OBSERVER_IS_READONLY');
      return originalRequest(who, path, ...args);
    };
    if (!readonly.has(stage)) h.assertWritable();
    const binding = businessSafetySelectedFixture(h.state, selection); businessSafetyCaseOwnership(h.state, binding, selection);
    const admin = session(h, null), reviewer = session(h, null, true); assert.notEqual(admin.user.id, reviewer.user.id, 'INDEPENDENT_BUSINESS_SAFETY_REVIEWER_REQUIRED');
    const subjects = {admin: {id: admin.user.id, sid: admin.sid}, reviewer: {id: reviewer.user.id, sid: reviewer.sid}};
    const named = selection.caseId !== undefined;
    const cases = named ? h.state.currentBusinessScheduleSafetyNamedCases?.[scenario] : h.state.currentBusinessScheduleSafetyCases;
    const caseKey = named ? selection.caseId : scenario;
    if (own(cases, caseKey)) {g = cases[caseKey]; assert(plain(g) && g.version === (named ? 2 : 1), 'ORIGINAL_BUSINESS_SAFETY_CASE_INVALID');}
    else {
      assert(stage === 'preflight', 'FRESH_BUSINESS_SAFETY_CASE_MUST_START_AT_PREFLIGHT');
      g = {version: named ? 2 : 1, scenario, clusterId: binding.clusterId, workspaceId: binding.workspaceId, binding, subjects,
        ...(named ? {caseBinding: businessSafetyBindCase(selection, binding, subjects)} : {}),
        runs: {}, commands: {}, lanes: {}, deadlines: [], observations: []};
      let store;
      if (named) {
        h.state.currentBusinessScheduleSafetyNamedCases ??= {};
        if (!own(h.state.currentBusinessScheduleSafetyNamedCases, scenario)) Object.defineProperty(h.state.currentBusinessScheduleSafetyNamedCases, scenario,
          {value: {}, enumerable: true, writable: true});
        store = h.state.currentBusinessScheduleSafetyNamedCases[scenario];
      } else {h.state.currentBusinessScheduleSafetyCases ??= {}; store = h.state.currentBusinessScheduleSafetyCases;}
      Object.defineProperty(store, caseKey, {value: g, enumerable: true, writable: true}); h.save();
    }
    assert.deepEqual(g.binding, binding, 'ORIGINAL_BUSINESS_SAFETY_FIXTURE_CHANGED');
    assert(g.scenario === scenario && g.clusterId === h.state.cid && g.workspaceId === h.state.wid, 'ORIGINAL_BUSINESS_SAFETY_SCOPE_CHANGED');
    if (named) assert.deepEqual(g.caseBinding, businessSafetyBindCase(selection, binding, subjects), 'ORIGINAL_BUSINESS_SAFETY_NAMED_CASE_BINDING_CHANGED');
    session(h, g); session(h, g, true); selected = true;
    assert(!own(g.runs, stage), 'ORIGINAL_BUSINESS_SAFETY_STAGE_PRESENT_NO_REPLAY');
    if (stage === 'observe') assert(g.window && Date.now() >= Date.parse(g.window.windowEnd), 'ORIGINAL_BUSINESS_SAFETY_WINDOW_MUST_HAVE_ENDED');
    start = h.state.requests.length; g.runs[stage] = {state: 'prepared', startedAt: new Date().toISOString()}; h.save(); started = true;
    await runStage(h, g, stage); g.runs[stage].state = 'succeeded'; g.runs[stage].completedAt = new Date().toISOString(); h.save();
    writeSync(fd, JSON.stringify(businessSafetyPublicReport(h, g, selection, stage, true, start), null, 2) + '\n');
    console.log(JSON.stringify({scenario, ...(named ? {caseId: selection.caseId} : {}), stage, passed: true, stageOnly: true, overallM11Accepted: false, rootSqlFactsVerified: false}));
  } catch (error) {
    const code = safeCode(error);
    if (started) {g.runs[stage].state = 'failed'; g.runs[stage].errorCode = code; try {h.save();} catch { /* Never replace original ledger bytes after CAS failure. */ }}
    writeSync(fd, JSON.stringify(businessSafetyPublicReport(h, selected ? g : null, selection, stage, false, start, code), null, 2) + '\n');
    console.error(JSON.stringify({scenario, ...(selection.caseId === undefined ? {} : {caseId: selection.caseId}), stage, passed: false, errorCode: code, message: '验收未通过，原始记录已保留。'})); process.exitCode = 1;
  } finally {closeSync(fd);}
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
