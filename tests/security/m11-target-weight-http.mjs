import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

// Import/syntax checks have no private-ledger, HTTP, SQL or container effects.
// Root explicitly invokes one stage, with already prepared actual sessions.
// No login/refresh, direct Admin access, scheduling, health override or replay.
const stages = ['create', 'update-weight', 'weight0', 'readonly'];
const roles = ['admin', 'a', 'b', 'c'];
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

export function targetWeightInvocation(argv, env) {
  assert.equal(env.RELEASE_LAB_READY, 'true', 'EXPLICIT_RELEASE_LAB_REQUIRED');
  assert.equal(env.RELEASE_LAB_M11_TARGET_WEIGHT_READY, 'true', 'EXPLICIT_TARGET_WEIGHT_FEATURE_REQUIRED');
  assert.equal(argv.length, 3, 'ONE_EXPLICIT_STAGE_NO_ALIAS_REQUIRED');
  assert(stages.includes(argv[2]), 'EXPLICIT_TARGET_WEIGHT_STAGE_REQUIRED');
  return argv[2];
}

export function targetWeightSession(actual, expectedId, now = Date.now()) {
  assert(uuid(actual?.user?.id) && uuid(actual.sid) && typeof actual.cookie === 'string', 'ROOT_ACTUAL_SESSION_REQUIRED');
  if (expectedId) assert.equal(actual.user.id, expectedId, 'ORIGINAL_TARGET_WEIGHT_ACTOR_REQUIRED');
  const pairs = Object.fromEntries(actual.cookie.split('; ').map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at), pair.slice(at + 1)]; }));
  assert(pairs.kongos_access && typeof actual.csrf === 'string' && actual.csrf && pairs.kongos_csrf === actual.csrf, 'ROOT_ACTUAL_COOKIE_REQUIRED');
  let claims;
  try { claims = JSON.parse(Buffer.from(pairs.kongos_access.split('.')[1], 'base64url').toString()); }
  catch { throw Error('ROOT_ACTUAL_ACCESS_FORMAT_REQUIRED'); }
  assert.equal(claims.sub, actual.user.id, 'ACTUAL_ACCESS_SUBJECT_REQUIRED');
  assert.equal(claims.sid, actual.sid, 'ACTUAL_ACCESS_SID_REQUIRED');
  // Parsing is only a lifetime guard. /auth/me must accept the real signed
  // session. Stop above ReleaseHarness's 90s implicit refresh threshold.
  assert(Number.isFinite(claims.exp) && claims.exp * 1000 > now + 120000, 'ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH');
  return actual;
}

export function targetWeightApprovalPolicy(definition, subjects) {
  assert.equal(definition.format, 2); const policy = definition.policy;
  assert.equal(policy.version, 2); assert.equal(policy.kind, 'native-change');
  assert.equal(policy.allowSelfApproval, false); assert.equal(policy.distinctAcrossStages, true);
  assert.equal(policy.stages.length, 2, 'CURRENT_THREE_VOTE_POLICY_REQUIRED');
  const [a, bc] = policy.stages;
  assert.equal(a.level, 1); assert.equal(a.mode, 'any'); assert.equal(a.threshold, 1);
  assert.deepEqual(a.selector, { users: [subjects.a] });
  assert.equal(bc.level, 2); assert.equal(bc.mode, 'all'); assert.equal(bc.threshold, null);
  assert.deepEqual(Object.keys(bc.selector), ['users']);
  assert.deepEqual([...bc.selector.users].sort(), [subjects.b, subjects.c].sort());
  assert(![subjects.a, subjects.b, subjects.c].includes(subjects.admin), 'SUBMITTER_CANNOT_BE_REVIEWER');
}

export function targetWeightPrepared(receipt, operation, oldId) {
  assert(uuid(receipt.id) && Number.isInteger(receipt.revision), 'ACTUAL_TYPED_INTENT_REQUIRED');
  assert.equal(receipt.review.impact.nativePackets, 1); assert.equal(receipt.review.changes.length, 1);
  const change = receipt.review.changes[0]; assert(uuid(change.nativeId));
  assert.equal(change.entityType, operation.kind === 'target' ? 'targets' : 'upstreams');
  assert.equal(change.action, operation.action === 'weight' ? 'update' : 'create');
  if (oldId) { assert.equal(change.originalNativeId, oldId); assert.notEqual(change.nativeId, oldId); assert.equal(change.before.id, oldId); }
  else { assert.equal(change.before, null); assert.equal(change.originalNativeId, undefined); }
  assert.equal(change.after.id, change.nativeId);
  if (operation.kind === 'target') {
    assert.equal(change.after.weight, operation.body.weight);
    if (operation.action === 'create') assert.equal(change.after.target, operation.body.target);
  } else assert.equal(change.after.name, operation.body.name);
  return change.nativeId;
}

export function targetWeightExecution(detail, receipt, record, expectedObjects) {
  assert.equal(receipt.state, 'succeeded'); assert(uuid(receipt.executionId) && uuid(receipt.baselineId));
  assert.equal(detail.entity.state, 'succeeded'); assert.equal(detail.nativeChange.executionId, receipt.executionId);
  assert.equal(detail.nativeChange.packets.length, 1);
  const packet = detail.nativeChange.packets[0];
  assert.equal(packet.state, 'succeeded'); assert.equal(packet.nativeStatus, 201, 'GENUINE_NATIVE201_NOT_BFF_HTTP_STATUS_REQUIRED');
  assert.equal(packet.entityId, record.nativeId); assert(uuid(packet.operationId));
  const baseline = detail.nativeChange.baseline;
  assert.equal(baseline.nativeAuthority, false); assert.equal(baseline.baseline.baselineId, receipt.baselineId);
  assert.equal(baseline.baseline.objectCount, expectedObjects, 'FULL_OWNED_BASELINE_REQUIRED');
  assert.equal(detail.entity.capabilities.rollbackPrepare, false, 'TARGET_APPEND_ROLLBACK_MUST_STAY_CLOSED');
  return { nativeId: packet.entityId, operationId: packet.operationId, nativeStatus: packet.nativeStatus, baselineId: receipt.baselineId };
}

export function targetWeightRows(history, effective, expected, upstreamId, address, currentId, currentWeight) {
  assert.equal(history.selection, 'history'); assert.equal(history.current_selection, false);
  // Kong 1.5 clean_history() can remove the final zero-weight tombstone
  // together with all older rows. This remains physical history absence;
  // callers separately verify the real original native201 execution fact.
  if(currentWeight===0&&history.items.length===0){
    assert.equal(expected.at(-1)?.id,currentId);assert.equal(expected.at(-1)?.weight,0);
    assert.equal(effective.items.length,0,'PRUNED_HISTORY_REQUIRES_NO_EFFECTIVE_TARGET');return;
  }
  assert.equal(history.items.length, expected.length, 'EXACT_OWNED_NATIVE_HISTORY_REQUIRED');
  const ids = new Set();
  for (const row of history.items) {
    assert(uuid(row.id) && !ids.has(row.id), 'UNIQUE_HISTORY_UUID_REQUIRED'); ids.add(row.id);
    assert.equal(row.upstream?.id, upstreamId); assert.equal(row.target, address);
    const original = expected.find(item => item.id === row.id); assert(original, 'FOREIGN_OR_UNRECORDED_HISTORY_REJECTED');
    assert.equal(row.weight, original.weight, 'OLD_HISTORY_MUST_REMAIN_IMMUTABLE');
  }
  assert.equal(effective.items.length, currentWeight === 0 ? 0 : 1, 'OWNED_CURRENT_EFFECTIVE_SELECTION_REQUIRED');
  if (currentWeight !== 0) {
    const row = effective.items[0]; assert.equal(row.id, currentId); assert.equal(row.upstream?.id, upstreamId);
    assert.equal(row.target, address); assert.equal(row.weight, currentWeight);
  }
}

async function run(h, stage) {
  const cid = h.state.cid, wid = h.state.wid;
  assert(uuid(cid) && uuid(wid), 'ORIGINAL_M11_CID_WID_REQUIRED'); h.assertWritable();
  if (stage === 'create') assert(!h.state.gate3TargetWeight, 'FRESH_TARGET_WEIGHT_NAMESPACE_REQUIRED');
  else assert(h.state.gate3TargetWeight, 'ORIGINAL_TARGET_WEIGHT_NAMESPACE_REQUIRED');
  let g = h.state.gate3TargetWeight;
  const subjects = Object.fromEntries(roles.map(role => [role, targetWeightSession(h.state.sessions[role], g?.subjects?.[role]).user.id]));
  assert.equal(new Set(Object.values(subjects)).size, 4, 'FOUR_DISTINCT_ACTUAL_ACTORS_REQUIRED');
  const scope = (suffix, extra = {}) => releaseScope(cid, wid, suffix, extra);
  const session = role => {
    assert.equal(h.state.cid, cid); assert.equal(h.state.wid, wid);
    if (g) { assert.equal(g.clusterId, cid); assert.equal(g.workspaceId, wid); }
    return targetWeightSession(h.state.sessions[role], subjects[role]);
  };
  const read = (path, role = 'admin', options = {}) => h.request(session(role), path, 'GET', undefined, options);
  const startIndex = h.state.requests.length;
  for (const role of roles) {
    const me = (await read('/auth/me', role)).data;
    assert.equal(me.user.id, subjects[role]); assert.equal(me.csrfToken, session(role).csrf, 'CURRENT_SERVER_ACCEPTED_SESSION_REQUIRED');
  }
  const cluster = (await read(`/clusters/${cid}`)).data;
  assert.equal(cluster.id, cid); assert.equal(cluster.execution_mode, 'approval'); assert(/^1\.5\.\d+$/.test(cluster.version));
  const workspace = (await read(`/clusters/${cid}/workspaces/${wid}`)).data;
  assert.equal(workspace.id, wid); assert.equal(workspace.cluster_id, cid); assert.equal(workspace.status, 'active');
  assert(workspace.code && workspace.code !== 'default', 'EXPLICIT_TAGGED_WORKSPACE_REQUIRED');
  const definitions = (await read(scope('workflow-definitions', { size: '100' }))).data;
  assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'BOUNDED_COMPLETE_DEFINITION_PAGE_REQUIRED');
  const native = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active'); assert.equal(native.length, 1);
  targetWeightApprovalPolicy(native[0], subjects);
  const approval = { id: native[0].id, version: native[0].version, policyHash: native[0].policyHash };
  for (const type of ['upstreams', 'targets']) {
    const schema = (await read(scope(`schemas/${type}`))).data, fields = Array.isArray(schema.fields) ? Object.assign({}, ...schema.fields) : schema.fields;
    assert(fields && typeof fields === 'object'); assert(Object.hasOwn(fields, type === 'targets' ? 'weight' : 'name'));
    if (type === 'targets') { assert.equal(fields.upstream.reference, 'upstreams'); assert.deepEqual(fields.weight.between, [0, 1000]); }
  }
  if (!g) {
    const suffix = randomUUID();
    g = h.state.gate3TargetWeight = { version: 1, clusterId: cid, workspaceId: wid, subjects, workspaceCode: workspace.code, approval,
      inputs: { upstream: { name: `m11-target-weight-${suffix}`, tags: [`workspace:${workspace.code}`, 'team:m11-acceptance', `owner:m11-target-weight-${suffix}`] }, target: 'echo:8080' },
      intents: {}, writeKeys: {}, stages: {}, history: [], checks: [] };
  } else { assert.equal(g.version, 1); assert.deepEqual(g.subjects, subjects); assert.equal(g.workspaceCode, workspace.code); assert.deepEqual(g.approval, approval); }
  assert(!g.stages[stage], 'ORIGINAL_STAGE_STARTED_OR_FINISHED_NO_REPLAY');
  if (stage === 'update-weight') assert.equal(g.stages.create?.state, 'succeeded');
  if (stage === 'weight0') assert.equal(g.stages['update-weight']?.state, 'succeeded');
  if (stage === 'readonly') assert.equal(g.stages.create?.state, 'succeeded');
  g.stages[stage] = { state: 'started', startedAt: new Date().toISOString() }; h.save();
  const check = (name, facts = {}) => { const value = { stage, name, passed: true, ...facts }; g.checks.push(value); h.check(true, name, { stage, ...facts }); };
  async function once(label, path, body, role = 'admin') {
    const actor = session(role), actualLabel = `m11-target-weight-${stage}-${label}`; h.assertWritable();
    assert(!g.writeKeys[actualLabel] && !h.state.requests.some(packet => packet.label === actualLabel), 'ORIGINAL_WRITE_EXISTS_NO_REPLAY_OR_ALIAS');
    const key = randomUUID(); assert(!h.state.requests.some(packet => packet.key === key)); g.writeKeys[actualLabel] = key; h.save();
    const result = await h.once(actualLabel, actor, path, 'POST', body, { key });
    const packets = h.state.requests.filter(packet => packet.key === key); assert.equal(packets.length, 1);
    assert.equal(packets[0].state, 'response_observed'); assert.equal(packets[0].label, actualLabel); assert.equal(packets[0].actorId, subjects[role]);
    assert(packets[0].status >= 200 && packets[0].status < 300); return result.data;
  }
  async function pages(suffix, maxPages = 10) {
    const items = [], seen = new Set(); let cursor; let selection;
    for (let n = 0; n < maxPages; n++) {
      const result = (await read(scope(suffix, { size: '20', ...(cursor ? { cursor } : {}) }))).data;
      assert(Array.isArray(result.items) && result.items.length <= 20 && result.total == null);
      if (selection === undefined) selection = { selection: result.selection, current_selection: result.current_selection };
      items.push(...result.items); assert(items.length <= 200, 'OWNED_READ_RECORD_BUDGET_REQUIRED');
      if (!result.nextCursor) return { ...selection, items };
      assert(typeof result.nextCursor === 'string' && !seen.has(result.nextCursor)); seen.add(result.nextCursor); cursor = result.nextCursor;
    } throw Error('OWNED_READ_EOF_BUDGET_EXCEEDED');
  }
  async function change(label, operation, objects, oldId) {
    assert(!g.intents[label], 'NEW_ORIGINAL_TYPED_INTENT_REQUIRED');
    const record = g.intents[label] = { body: { change: operation } }; h.save();
    record.receipt = await once(`${label}-prepare`, scope('entity-changes/prepare'), record.body);
    record.id = record.receipt.id; record.nativeId = targetWeightPrepared(record.receipt, operation, oldId); h.save();
    const submitted = await once(`${label}-submit`, scope(`entity-changes/${record.id}/submit`), { revision: record.receipt.revision, materialHmac: record.receipt.materialHmac, confirmed: true, confirm_name: 'native-change' });
    assert(uuid(submitted.workflowId)); record.workflowId = submitted.workflowId;
    assert(!Object.values(g.intents).some(other => other !== record && other.workflowId === record.workflowId)); h.save();
    for (const [index, role] of ['a', 'b', 'c'].entries()) {
      const view = (await read(scope(`workflows/${record.workflowId}`))).data.entity; assert.equal(view.state, 'pending'); assert.equal(view.approval.format, 2);
      const active = view.approval.stages.find(item => item.state === 'active'); assert(active);
      assert.equal(active.level, index === 0 ? 1 : 2); assert.equal(active.threshold, index === 0 ? 1 : 2);
      await once(`${label}-vote-${role}`, scope(`workflows/${record.workflowId}/approve`), { revision: view.revision, planHash: view.planHash, confirmed: true,
        confirm_name: 'native-change', execute: false, level: active.level, stageRevision: active.revision, candidateVersion: view.approval.candidateVersion }, role);
      const after = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
      assert.equal(after.state, index === 2 ? 'approved' : 'pending'); assert.equal(after.approval.stages.reduce((sum, item) => sum + item.votes, 0), index + 1);
    }
    const approved = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, true); assert(uuid(approved.approval.approvalSetId));
    record.approvalSetId = approved.approval.approvalSetId;
    assert(!Object.values(g.intents).some(other => other !== record && other.approvalSetId === record.approvalSetId));
    record.executeBody = { revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: 'native-change' }; h.save();
    record.executionReceipt = await once(`${label}-execute`, scope(`workflows/${record.workflowId}/execute`), record.executeBody);
    const detail = (await read(scope(`workflows/${record.workflowId}`))).data;
    record.proof = targetWeightExecution(detail, record.executionReceipt, record, objects); h.save();
    check('New typed intent completed only after three actual votes and a genuine native201', { operation: label, workflowId: record.workflowId, ...record.proof }); return record.nativeId;
  }
  async function verify() {
    const parent = (await read(scope(`entities/upstreams/${g.upstreamId}`))).data.entity;
    assert.equal(parent.id, g.upstreamId); assert.equal(parent.name, g.inputs.upstream.name); assert(parent.tags.includes(`workspace:${g.workspaceCode}`));
    const history = await pages(`upstreams/${g.upstreamId}/targets/history`), effective = await pages(`upstreams/${g.upstreamId}/targets`);
    targetWeightRows(history, effective, g.history, g.upstreamId, g.inputs.target, g.currentTargetId, g.currentWeight);
    // This ordinary discovery path can internally read a historical UUID, but
    // its current-effective check must suppress that old ID from navigation.
    const children = await pages('authorization/children');
    const own = children.items.filter(item => item.type === 'targets' && item.parent_id === g.upstreamId);
    assert.deepEqual(own.map(item => item.id), g.currentWeight === 0 ? [] : [g.currentTargetId], 'OLD_HISTORY_CANNOT_BECOME_CURRENT_LEGACY_NAVIGATION');
    check('Actual physical history and current navigation are verified; disabled IDs are excluded', {
      nativeHistoryRows: history.items.length, nativeHistoryRetention: g.currentWeight === 0 && history.items.length === 0 ? 'native-pruned' : 'retained', effectiveRows: effective.items.length, legacyCurrentRows: own.length, currentWeight: g.currentWeight });
  }
  if (stage === 'create') {
    await read(scope(`entities/upstreams/${encodeURIComponent(g.inputs.upstream.name)}`), 'admin', { expected: [404] });
    g.upstreamId = await change('upstream-create', { kind: 'entity', action: 'create', entityType: 'upstreams', body: g.inputs.upstream }, 1); h.save();
    const empty = await pages(`upstreams/${g.upstreamId}/targets/history`); assert.equal(empty.selection, 'history'); assert.equal(empty.items.length, 0);
    g.currentTargetId = await change('target-create', { kind: 'target', action: 'create', upstreamId: g.upstreamId, body: { target: g.inputs.target, weight: 100, tags: g.inputs.upstream.tags } }, 2);
    g.currentWeight = 100; g.history.push({ id: g.currentTargetId, weight: 100 }); h.save(); await verify();
  } else if (stage === 'update-weight' || stage === 'weight0') {
    await verify(); const previous = g.currentTargetId, weight = stage === 'weight0' ? 0 : 80;
    const next = await change(stage, { kind: 'target', action: 'weight', upstreamId: g.upstreamId, targetId: previous, body: { weight, tags: g.inputs.upstream.tags } }, 3, previous);
    assert.notEqual(next, previous); g.currentTargetId = next; g.currentWeight = weight; g.history.push({ id: next, weight }); h.save(); await verify();
  } else { for (const record of Object.values(g.intents)) {
    const detail = (await read(scope(`workflows/${record.workflowId}`))).data;
    targetWeightExecution(detail, record.executionReceipt, record, record === g.intents['upstream-create'] ? 1 : record === g.intents['target-create'] ? 2 : 3);
  } await verify(); }
  const packets = h.state.requests.slice(startIndex);
  assert(packets.every(packet => packet.label?.startsWith(`m11-target-weight-${stage}-`) && packet.state === 'response_observed'), 'ONLY_OWN_ORIGINAL_STAGE_WRITES_REQUIRED');
  if (stage === 'readonly') assert.equal(packets.length, 0, 'READONLY_HAS_ZERO_HTTP_WRITES');
  g.stages[stage].state = 'succeeded'; g.stages[stage].httpWrites = packets.length; h.state.phase = `m11-target-weight-${stage}-complete`; h.save();
  return reportValue(h, g, stage, true);
}

function reportValue(h, g, stage, passed) {
  const keys = new Set(Object.entries(g?.writeKeys ?? {}).filter(([label]) => label.startsWith(`m11-target-weight-${stage}-`)).map(([, key]) => key));
  return { passed, stage, milestone: 'M11', sourceOnly: false, environment: 'isolated actual Kong OSS1.5 via authenticated BFF', productionDeployment: false,
    overallM11Accepted: false, clusterId: g?.clusterId ?? null, workspaceId: g?.workspaceId ?? null, upstreamId: g?.upstreamId ?? null,
    historicalIds: g?.history ?? [], latestNativeId: g?.currentTargetId ?? null,
    currentTargetId: g?.currentWeight === 0 ? null : g?.currentTargetId ?? null, currentWeight: g?.currentWeight ?? null,
    checks: (g?.checks ?? []).filter(item => item.stage === stage),
    requests: h.state.requests.filter(packet => keys.has(packet.key)).map(packet => ({ method: packet.method, path: packet.path.split('?')[0], state: packet.state,
      status: packet.status, requestId: packet.requestId, bodyHash: packet.bodyHash, responseHash: packet.responseHash })),
    credentialsRecorded: false, cookiesRecorded: false, authWritesIssued: false, directAdminRequestsIssued: false,
    schedulingTested: false, healthOverridesTested: false, configurationRollbackTested: false,
    sqlFactsVerified: false, limitations: ['BFF native-status/history receipts do not independently verify SQL immutability or all M11 functionality.'],
    ...(!passed ? { errorCode: 'M11_TARGET_WEIGHT_HTTP_STOPPED' } : {}) };
}

async function main() {
  let h, stage, reportPath;
  try {
    stage = targetWeightInvocation(process.argv, process.env);
    reportPath = resolve(`artifacts/M11/target-weight-${stage}-http-original.json`);
    assert(!existsSync(reportPath), 'ORIGINAL_TARGET_WEIGHT_REPORT_EXISTS_NO_REPLAY');
    h = new ReleaseHarness('M11', { resume: true });
    const report = await run(h, stage);
    mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify({ passed: true, stage, overallM11Accepted: false }));
  } catch {
    if (h) {
      const g = h.state.gate3TargetWeight;
      if (g?.stages?.[stage]?.state === 'started') g.stages[stage].state = 'stopped';
      h.state.phase = 'm11-target-weight-stopped';
      try { h.save(); if (reportPath && !existsSync(reportPath)) { mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(reportValue(h, g, stage, false), null, 2) + '\n', { flag: 'wx' }); } } catch { /* retain original private ledger; no fallback rewrite */ }
    }
    // Do not print raw assertions, response bodies, headers, cookies or tokens.
    console.error(JSON.stringify({ passed: false, stage: stages.includes(stage) ? stage : null, errorCode: 'M11_TARGET_WEIGHT_HTTP_STOPPED' })); process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
