import assert from 'node:assert/strict';
import { UUID } from './m10-release-evidence.mjs';

export function m10RequestPath(value) {
  assert.equal(typeof value, 'string');
  const url = new URL(value, 'http://fixed-bff.invalid');
  assert.equal(url.hostname, 'fixed-bff.invalid');
  const path = url.pathname.replace(/^\/api\/v1(?=\/)/, '');
  assert(path.startsWith('/') && !path.startsWith('//') && !path.includes('\\'));
  return { path, workspaceId: url.searchParams.get('workspaceId') };
}

export function classifyM10AuditRequest(packet) {
  const { path } = m10RequestPath(packet.path + (packet.query ?? ''));
  if (/^\/auth\//.test(path)) return null;
  if (packet.method === 'POST' && path === '/notifications/preferences') return ['notification.preference.create', ['notifications.personal.preferences.save']];
  if (/\/governance\/inspections$/.test(path)) return ['governance.inspection', ['governance.inspection.requested', 'governance.inspection.complete']];
  if (/\/governance\/comparisons$/.test(path)) return ['governance.comparison', ['governance.comparison.requested', 'governance.comparison.complete']];
  if (/\/governance\/comparisons\/[^/]+\/promote-plan$/.test(path)) return ['governance.promote', ['governance.promote.plan.requested']];
  if (/\/governance\/reports\/[^/]+\/findings\/[^/]+\/fix-plan$/.test(path)) return ['governance.fix', ['governance.fix.plan.requested', 'governance.fix.plan']];
  if (/\/governance\/operations\/by-key\/[^/]+\/reconcile$/.test(path)) return ['governance.reconcile', ['governance.fix.plan']];
  if (/\/governance\/(?:rules|schedules)(?:\/[^/]+)?(?:\/(?:restore|clone))?$/.test(path)) {
    const operation = /\/restore$/.test(path) ? 'restore' : packet.method === 'DELETE' ? 'archive' : packet.method === 'PATCH' ? 'update' : 'create';
    return ['governance.metadata', packet.responseData?.domain === 'workflow' ? ['workflow.submit'] : [`iam.*`]];
  }
  if (/\/workflows\/[^/]+\/(?:approve|reject|cancel|execute|reconcile-metadata)$/.test(path)) return ['workflow.' + path.split('/').at(-1), ['workflow.' + (path.endsWith('reconcile-metadata') ? 'reconcile-migration-metadata' : path.split('/').at(-1))]];
  if (/\/configuration\//.test(path) || /\/snapshots(?:\/|$)/.test(path)) return ['configuration', ['configuration.*', 'snapshot.*']];
  if (/\/toolbox\/probes$/.test(path)) return ['proxy.probe', ['toolbox.proxy-probe.intent', 'toolbox.proxy-probe.result']];
  if (/\/toolbox\/routes\/debug$/.test(path)) return ['route.simulation', ['toolbox.route.simulated']];
  if (/\/entities\//.test(path) || /\/credentials\//.test(path)) return ['native', [packet.method === 'POST' ? 'create' : packet.method === 'DELETE' ? 'delete' : 'update']];
  if (/\/recycle-bin\/[^/]+\/restore$/.test(path)) return ['native.restore', ['restore']];
  if (/^\/clusters(?:\/[^/]+)?$/.test(path)) return ['cluster.metadata', [packet.method === 'PATCH' ? 'update' : packet.method === 'DELETE' ? 'archive' : 'create']];
  if (/\/clusters\/[^/]+\/probe$/.test(path)) return ['cluster.probe', ['probe']];
  if (/\/workspaces(?:\/[^/]+)?$/.test(path)) return ['workspace.metadata', [packet.method === 'POST' ? 'create' : packet.method === 'DELETE' ? 'delete' : 'update']];
  const iam = m10FixedIamAuditEvidence(packet);
  if (iam) return ['iam.fixed', ['iam.*']];
  if (/^\/iam\//.test(path)) return ['iam.metadata', ['iam.*']];
  throw Error('M10_BUSINESS_REQUEST_NOT_CLASSIFIED');
}

/** A current M10 request has no historical IP/actor/scope exceptions. Cross-
 * environment child audits require an independently loaded exact parent tuple. */
export function assertM10RequestAuditIdentity(request, row, alternateScope = null) {
  assert.equal(row.request_id, request.requestId); assert.equal(row.actor_id, request.actorId); assert.equal(row.actor_type, 'user');
  assert(typeof row.source_ip === 'string' && row.source_ip.length > 0, 'M10_CURRENT_SOURCE_IP_REQUIRED');
  assert(Number.isFinite(new Date(row.occurred_at).getTime()));
  assert(new Date(row.occurred_at).getTime() >= Date.parse(request.startedAt) - 1000);
  assert(typeof row.entity_type === 'string' && row.entity_type.length > 0);
  if (request.category === 'iam.fixed') {
    const evidence = request.iamAuditIdentity;
    assert(evidence && UUID.test(evidence.operationId ?? '') && Array.isArray(evidence.rules), 'M10_IAM_INDEPENDENT_SCOPE_REQUIRED');
    assert.equal(row.cluster_id, request.clusterId, 'M10_AUDIT_SCOPE_MISMATCH');
    assert.equal(row.workspace_id, request.workspaceId, 'M10_AUDIT_SCOPE_MISMATCH');
    const rule = evidence.rules.find(value => value.action === row.action);
    assert(rule, 'M10_IAM_TYPED_AUDIT_ACTION_REQUIRED');
    assert.equal(row.entity_type, rule.entityType); assert.equal(row.entity_id, rule.entityId); assert.equal(row.result, rule.result);
    if (evidence.sourceIp) assert.equal(row.source_ip, evidence.sourceIp, 'M10_IAM_AUDIT_SOURCE_IP_MISMATCH');
    return;
  }
  if (request.category === 'notification.preference.create') {
    assert.equal(request.method, 'POST'); assert.equal(request.routePath, '/notifications/preferences');
    assert(UUID.test(request.clusterId ?? '') && UUID.test(request.workspaceId ?? '') && UUID.test(request.entityId ?? ''), 'M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
    assert.equal(row.cluster_id, request.clusterId, 'M10_AUDIT_SCOPE_MISMATCH');
    assert.equal(row.workspace_id, request.workspaceId, 'M10_AUDIT_SCOPE_MISMATCH');
    assert.equal(row.entity_type, 'user_notification_subscriptions');
    assert.equal(row.action, 'notifications.personal.preferences.save'); assert.equal(row.result, 'success');
    // Fixed collection POST passes targetId=null; the created ID is in the
    // actual safe after/result entity, not invented from a global route.
    assert.equal(row.entity_id, null); assert.equal(row.before, null);
    assert.equal(row.after?.id, request.entityId); assert.equal(row.after?.userId, request.actorId);
    assert.equal(row.after?.clusterId, request.clusterId); assert.equal(row.after?.workspaceId, request.workspaceId);
    return;
  }
  if (row.cluster_id === request.clusterId && (request.workspaceId === null || row.workspace_id === request.workspaceId)) return;
  if (['cluster.metadata', 'cluster.probe'].includes(request.category) && row.cluster_id === null && row.workspace_id === null
    && row.entity_type === 'clusters' && ['iam.write.requested', 'iam.write'].includes(row.action)) {
    if (row.entity_id === request.clusterId) return;
    // A collection CREATE reserves no target ID until its transaction creates
    // the business row. The same original IAM result must expose that real ID.
    if (request.category === 'cluster.metadata' && request.method === 'POST' && request.routePath === '/clusters'
      && row.entity_id === null && (row.action === 'iam.write.requested' && row.result === 'pending'
        || row.action === 'iam.write' && row.result === 'success' && row.after?.id === request.clusterId)) return;
  }
  if (['governance.promote', 'governance.fix', 'governance.reconcile'].includes(request.category)
    && alternateScope && row.cluster_id === alternateScope.clusterId && row.workspace_id === alternateScope.workspaceId
    && !row.action.startsWith('governance.') && !row.action.startsWith('iam.')) return;
  assert.fail('M10_AUDIT_SCOPE_MISMATCH');
}

/** Only these fixed IAM routes have a tenant hidden by their global URL. No
 * arbitrary IAM alternate scope is accepted; the worker independently loads
 * the exact actor/key operation and its real role or binding. */
export function m10FixedIamAuditEvidence(packet) {
  const { path } = m10RequestPath(packet.path + (packet.query ?? ''));
  let kind, subjectId = null, bindingId = null, allowed;
  if (packet.method === 'POST' && path === '/iam/roles') { kind = 'role-create'; allowed = ['code', 'name', 'description', 'cluster_id', 'workspace_id']; }
  else if (packet.method === 'PUT' && /^\/iam\/roles\/[a-f\d-]{36}\/permissions$/i.test(path)) { kind = 'role-permissions'; subjectId = path.split('/')[3]; allowed = ['revision', 'permissions']; }
  else if (packet.method === 'POST' && /^\/iam\/users\/[a-f\d-]{36}\/role-bindings$/i.test(path)) { kind = 'user-binding-create'; subjectId = path.split('/')[3]; allowed = ['role_id', 'cluster_id', 'workspace_id', 'expires_at']; }
  else if (packet.method === 'DELETE' && /^\/iam\/users\/[a-f\d-]{36}\/role-bindings\/[a-f\d-]{36}$/i.test(path)) { kind = 'user-binding-revoke'; subjectId = path.split('/')[3]; bindingId = path.split('/')[5]; allowed = ['revision', 'confirmed', 'confirm_name']; }
  else if (packet.method === 'POST' && /^\/iam\/users\/[a-f\d-]{36}\/role-bindings\/[a-f\d-]{36}\/restore$/i.test(path)) { kind = 'user-binding-restore'; subjectId = path.split('/')[3]; bindingId = path.split('/')[5]; allowed = ['revision', 'confirmed', 'confirm_name']; }
  else return null;
  if (subjectId !== null) assert(UUID.test(subjectId)); if (bindingId !== null) assert(UUID.test(bindingId));
  assert(packet.body && typeof packet.body === 'object' && !Array.isArray(packet.body));
  assert(Object.keys(packet.body).every(key => allowed.includes(key)), 'M10_IAM_FIXED_ORIGINAL_DTO_REQUIRED');
  const input = JSON.parse(JSON.stringify(packet.body)), source = packet.responseData?.entity ?? packet.responseData;
  const fields = kind === 'role-create' ? ['id', 'cluster_id', 'workspace_id', 'code', 'name']
    : kind === 'role-permissions' ? ['revision'] : ['id', 'cluster_id', 'workspace_id', 'user_id', 'role_id', 'revision', 'status'];
  const result = Object.fromEntries(fields.filter(key => Object.hasOwn(source ?? {}, key)).map(key => [key, source[key]]));
  return { kind, subjectId, bindingId, input, result };
}

/** SQL-loaded sealed payload/result and fixed real subjects establish scope;
 * this pure function grants no API or native authority. */
export function verifyM10FixedIamAuditEvidence(request, operation, role, binding, payload, result) {
  const original = request.iamFixed;
  assert(request.category === 'iam.fixed' && original, 'M10_IAM_FIXED_ORIGINAL_REQUIRED');
  assert(UUID.test(operation?.id ?? '')); assert.equal(operation.actor_id, request.actorId); assert.equal(operation.idempotency_key, request.originalKey);
  assert.equal(operation.state, 'succeeded'); assert.equal(operation.remote_completed, true); assert.equal(operation.module, 'roles');
  const clusterId = operation.cluster_id, workspaceId = operation.workspace_id;
  assert(clusterId === null || UUID.test(clusterId)); assert(workspaceId === null || UUID.test(workspaceId)); assert(workspaceId === null || clusterId !== null);
  assert(role && UUID.test(role.id)); assert.equal(role.cluster_id, clusterId, 'M10_IAM_REAL_ROLE_SCOPE_MISMATCH'); assert.equal(role.workspace_id, workspaceId, 'M10_IAM_REAL_ROLE_SCOPE_MISMATCH');
  const equal = (a, b) => assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
  const rawResult = result?.entity ?? result, scope = { cluster_id: clusterId, workspace_id: workspaceId };
  let targetId, businessAction, businessType, expectedPayload;
  if (original.kind === 'role-create') {
    assert.equal(request.method, 'POST'); assert.equal(request.routePath, '/iam/roles'); assert.equal(operation.target_id, null);
    assert.equal(rawResult.id, role.id); assert.equal(original.result.id, role.id); targetId = null; businessType = 'roles'; businessAction = 'iam.create';
    expectedPayload = { code: original.input.code.trim(), name: original.input.name.trim(), ...scope,
      ...(original.input.description === undefined ? {} : { description: original.input.description.trim() }) };
    for (const name of ['cluster_id', 'workspace_id']) assert.equal(original.input[name] ?? null, scope[name], 'M10_IAM_ORIGINAL_SCOPE_MISMATCH');
  } else if (original.kind === 'role-permissions') {
    assert.equal(request.method, 'PUT'); assert.equal(request.routePath, `/iam/roles/${original.subjectId}/permissions`); assert.equal(role.id, original.subjectId);
    targetId = original.subjectId; businessType = 'roles'; businessAction = 'iam.permissions'; expectedPayload = original.input;
    assert(Number.isInteger(original.input.revision) && Array.isArray(original.input.permissions) && original.input.permissions.length <= 512);
    assert.equal(rawResult.revision, original.input.revision + 1); assert.equal(original.result.revision, rawResult.revision);
  } else {
    assert(['user-binding-create', 'user-binding-revoke', 'user-binding-restore'].includes(original.kind));
    assert(binding && UUID.test(binding.id)); assert.equal(binding.user_id, original.subjectId); assert.equal(binding.role_id, role.id);
    assert.equal(binding.cluster_id, clusterId, 'M10_IAM_REAL_BINDING_SCOPE_MISMATCH'); assert.equal(binding.workspace_id, workspaceId, 'M10_IAM_REAL_BINDING_SCOPE_MISMATCH');
    assert.equal(rawResult.id, binding.id); assert.equal(rawResult.user_id, original.subjectId); assert.equal(rawResult.role_id, role.id);
    targetId = original.subjectId; businessType = 'users';
    if (original.kind === 'user-binding-create') {
      assert.equal(request.method, 'POST'); assert.equal(request.routePath, `/iam/users/${original.subjectId}/role-bindings`);
      assert.equal(original.input.role_id, role.id); for (const name of ['cluster_id', 'workspace_id']) assert.equal(original.input[name] ?? null, scope[name], 'M10_IAM_ORIGINAL_SCOPE_MISMATCH');
      expectedPayload = original.input; businessAction = 'iam.grant';
    } else {
      const restore = original.kind === 'user-binding-restore';
      assert.equal(request.method, restore ? 'POST' : 'DELETE'); assert.equal(request.routePath, `/iam/users/${original.subjectId}/role-bindings/${original.bindingId}${restore ? '/restore' : ''}`);
      assert.equal(binding.id, original.bindingId); assert.equal(original.input.confirmed, true); assert.equal(original.input.confirm_name, role.name);
      expectedPayload = { ...original.input, bindingId: original.bindingId, restore }; businessAction = restore ? 'iam.grant.restore' : 'iam.grant.revoke';
    }
  }
  assert.equal(operation.target_id, targetId, 'M10_IAM_OPERATION_TARGET_MISMATCH');
  const action = original.kind === 'user-binding-revoke' ? 'delete' : 'write'; assert.equal(operation.action, action);
  equal(payload, expectedPayload);
  if (original.kind !== 'role-permissions') {
    for (const [name, value] of Object.entries(original.result)) assert.deepEqual(rawResult[name], value, 'M10_IAM_ORIGINAL_RESULT_MISMATCH');
    assert.equal(rawResult.cluster_id, clusterId, 'M10_IAM_RESULT_SCOPE_MISMATCH'); assert.equal(rawResult.workspace_id, workspaceId, 'M10_IAM_RESULT_SCOPE_MISMATCH');
  }
  return { ...request, clusterId, workspaceId, iamAuditIdentity: { operationId: operation.id, roleId: role.id, bindingId: binding?.id ?? null,
    rules: [{ action: `iam.${action}.requested`, entityType: 'roles', entityId: targetId, result: 'pending' },
      { action: businessAction, entityType: businessType, entityId: original.kind === 'role-create' ? role.id : targetId, result: 'success' },
      { action: `iam.${action}`, entityType: 'roles', entityId: targetId, result: 'success' }] } };
}

/** Only the fixed preference collection POST derives tenant scope from its
 * retained body/result. Conflicting copies never choose a convenient scope. */
export function m10NotificationPreferenceScope(packet) {
  const { path, workspaceId: queryWorkspaceId } = m10RequestPath(packet.path + (packet.query ?? ''));
  assert.equal(packet.method, 'POST'); assert.equal(path, '/notifications/preferences');
  const entity = packet.responseData?.entity;
  assert(entity && typeof entity === 'object' && !Array.isArray(entity) && UUID.test(entity.id ?? ''), 'M10_NOTIFICATION_ORIGINAL_ENTITY_REQUIRED');
  assert.equal(entity.userId, packet.actorId, 'M10_NOTIFICATION_ORIGINAL_OWNER_MISMATCH');
  const sources = [packet.body, entity].filter(value => value && typeof value === 'object' && !Array.isArray(value));
  const scoped = sources.filter(value => Object.hasOwn(value, 'clusterId') || Object.hasOwn(value, 'workspaceId'));
  assert(scoped.length > 0, 'M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
  for (const value of scoped) assert(UUID.test(value.clusterId ?? '') && UUID.test(value.workspaceId ?? ''), 'M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
  const { clusterId, workspaceId } = scoped[0];
  for (const value of scoped) {
    assert.equal(value.clusterId, clusterId, 'M10_NOTIFICATION_ORIGINAL_SCOPE_MISMATCH');
    assert.equal(value.workspaceId, workspaceId, 'M10_NOTIFICATION_ORIGINAL_SCOPE_MISMATCH');
  }
  if (queryWorkspaceId !== null) assert.equal(queryWorkspaceId, workspaceId, 'M10_NOTIFICATION_ORIGINAL_SCOPE_MISMATCH');
  return { clusterId, workspaceId, entityId: entity.id };
}

/** A committed observation and its failed HTTP projection are separate facts.
 * The original outcome is preserved; a client completion flag is never proof. */
export function verifyM10AnalyticalAudit(original, run, record, audits) {
  assert.equal(run.actor_id, original.actorId); assert.equal(run.cluster_id, original.clusterId);
  assert.equal(run.workspace_id, original.workspaceId); assert.equal(run.idempotency_key, original.originalKey);
  assert.equal(run.origin_type, 'http'); assert(['succeeded', 'incomplete'].includes(run.state));
  if (original.sessionId) assert.equal(run.origin_session_id, original.sessionId);
  assert.equal(record.run_id, run.id); assert.equal(record.cluster_id, run.cluster_id); assert.equal(record.workspace_id, run.workspace_id);
  const type = run.kind === 'comparison' ? 'comparison' : run.kind === 'inspection' ? 'inspection' : null;
  assert(type); assert.equal(original.category, `governance.${type}`);
  const action = `governance.${type}.complete`, property = type === 'comparison' ? 'comparisonId' : 'reportId';
  const matches = audits.filter(row => row.action === action && row.entity_type === 'governance_runs' && row.entity_id === run.id
    && row.result === 'success' && row.after?.[property] === record.id);
  assert.equal(matches.length, 1, 'M10_ANALYTICAL_COMMIT_AUDIT_REQUIRED');
  assertM10RequestAuditIdentity(original, matches[0]);
  return { requestId: original.requestId, originalStatus: original.status, runId: run.id, recordId: record.id,
    kind: run.kind, runState: run.state, auditId: matches[0].id, originalResponseRewritten: false,
    responseResolved: false, nativeExecutionRequested: false };
}

export function m10MinimalAuditManifest(harness, browser, verifiedAfter) {
  assert.equal(harness.milestone, 'M10'); assert.equal(browser.milestone, 'M10');
  const manifest = { milestone: 'M10', clusterIds: [harness.cid, harness.targetCid], verifiedAfter,
    requests: [], attempts: [], excludedAuthenticationRequests: 0, unknownOriginalRequests: [], unknownAuthenticationRequests: [], failedOriginalRequests: [] };
  for (const [source, packets] of [['native', harness.requests], ['browser', browser.requests]]) for (const [index, packet] of packets.entries()) {
    if (['GET', 'HEAD'].includes(packet.method)) continue;
    const { path, workspaceId: queryWorkspaceId } = m10RequestPath(packet.path + (packet.query ?? ''));
    let workspaceId = queryWorkspaceId;
    if (path.startsWith('/auth/')) {
      manifest.excludedAuthenticationRequests++;
      if (packet.state !== 'response_observed' || typeof packet.status !== 'number') manifest.unknownAuthenticationRequests.push({
        source, index, method: packet.method, routePath: path, originalState: packet.state, responseResolved: false,
      });
      continue;
    }
    const successful = packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300;
    let category; try { category = classifyM10AuditRequest(packet); } catch (error) {
      if (successful) throw error;
      category = ['denied-or-failed', []];
    }
    let clusterId = path.match(/^\/clusters\/([a-f\d-]{36})(?:\/|$)/i)?.[1] ?? null;
    let notificationEntityId = null;
    if (successful && category[0] === 'notification.preference.create') {
      const scoped = m10NotificationPreferenceScope(packet);
      clusterId = scoped.clusterId; workspaceId = scoped.workspaceId; notificationEntityId = scoped.entityId;
    }
    if (path === '/clusters' && successful) clusterId = packet.responseData?.id;
    if (clusterId !== null) { assert(UUID.test(clusterId)); if (successful) assert(manifest.clusterIds.includes(clusterId)); }
    assert(UUID.test(packet.actorId), 'M10_ORIGINAL_ACTOR_REQUIRED');
    assert(Number.isFinite(Date.parse(packet.startedAt)), 'M10_ORIGINAL_TIME_REQUIRED');
    if (successful) assert(typeof packet.requestId === 'string' && packet.requestId.length > 0, 'M10_ORIGINAL_REQUEST_ID_REQUIRED');
    const request = { source, index, method: packet.method, routePath: path, requestId: packet.requestId ?? null,
      originalKey: packet.key ?? packet.idempotencyKey ?? null, actorId: packet.actorId, clusterId, workspaceId,
      sessionId: UUID.test(packet.sessionId ?? '') ? packet.sessionId : null,
      category: category[0], expectedActions: category[1], startedAt: packet.startedAt,
      status: packet.status ?? null, originalState: packet.state, originalResponseRewritten: false,
      entityId: notificationEntityId ?? (UUID.test(packet.responseData?.id ?? '') ? packet.responseData.id : null) };
    if (successful && category[0] === 'iam.fixed') request.iamFixed = m10FixedIamAuditEvidence(packet);
    manifest.attempts.push(request);
    if (successful) manifest.requests.push(request);
    else if (packet.state !== 'response_observed' || typeof packet.status !== 'number') manifest.unknownOriginalRequests.push(request);
    else manifest.failedOriginalRequests.push(request);
  }
  assert(manifest.requests.length > 0 && manifest.attempts.length <= 1000);
  return manifest;
}
