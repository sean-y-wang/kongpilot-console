import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { UUID } from './lib/m10-release-evidence.mjs';
import { assertM10RequestAuditIdentity, classifyM10AuditRequest, m10FixedIamAuditEvidence, verifyM10FixedIamAuditEvidence } from './lib/m10-audit-policy.mjs';

function fixture(kind = 'role-create') {
  const cid = randomUUID(), wid = randomUUID(), actor = randomUUID(), uid = randomUUID(), rid = randomUUID(), bid = randomUUID(), key = randomUUID();
  const scope = { cluster_id: cid, workspace_id: wid }, role = { id: rid, name: 'Synthetic scoped role', code: 'synthetic_role', ...scope };
  const binding = { id: bid, user_id: uid, role_id: rid, ...scope };
  let method = 'POST', path = '/iam/roles', body = { code: role.code, name: role.name, description: 'Synthetic only', ...scope }, result = { ...role }, targetId = null, payload = { ...body }, action = 'write';
  if (kind === 'role-permissions') { method = 'PUT'; path = `/iam/roles/${rid}/permissions`; body = { revision: 1, permissions: [] }; result = { items: [], revision: 2 }; targetId = rid; payload = body; }
  if (kind === 'user-binding-create') { path = `/iam/users/${uid}/role-bindings`; body = { role_id: rid, ...scope }; result = { ...binding, revision: 1, status: 'active' }; targetId = uid; payload = body; }
  if (kind === 'user-binding-revoke' || kind === 'user-binding-restore') {
    const restore = kind === 'user-binding-restore'; method = restore ? 'POST' : 'DELETE'; path = `/iam/users/${uid}/role-bindings/${bid}${restore ? '/restore' : ''}`;
    body = { revision: restore ? 2 : 1, confirmed: true, confirm_name: role.name }; result = { ...binding, revision: restore ? 3 : 2, status: restore ? 'active' : 'revoked' };
    targetId = uid; payload = { ...body, bindingId: bid, restore }; action = restore ? 'write' : 'delete';
  }
  const packet = { method, path, body, responseData: result }, request = { category: classifyM10AuditRequest(packet)[0], iamFixed: m10FixedIamAuditEvidence(packet), method, routePath: path,
    actorId: actor, originalKey: key, requestId: randomUUID(), startedAt: '2026-10-13T08:00:00.000Z', clusterId: null, workspaceId: null };
  const operation = { id: randomUUID(), actor_id: actor, idempotency_key: key, state: 'succeeded', remote_completed: true, module: 'roles', action, target_id: targetId, ...scope };
  return { request, operation, role, binding: kind.startsWith('user-binding-') ? binding : null, payload, result, cid, wid };
}
const verify = value => verifyM10FixedIamAuditEvidence(value.request, value.operation, value.role, value.binding, value.payload, value.result);
const auditRows = normalized => normalized.iamAuditIdentity.rules.map(rule => ({ request_id: normalized.requestId, actor_id: normalized.actorId, actor_type: 'user', source_ip: '127.0.0.1', occurred_at: '2026-10-13T08:00:00.001Z',
  cluster_id: normalized.clusterId, workspace_id: normalized.workspaceId, entity_type: rule.entityType, entity_id: rule.entityId, action: rule.action, result: rule.result, before: null }));

test('five fixed IAM routes verify their real operation/subject scopes; global users stay global', () => {
  for (const kind of ['role-create', 'role-permissions', 'user-binding-create', 'user-binding-revoke', 'user-binding-restore']) {
    const value = fixture(kind), normalized = verify(value); assert.equal(normalized.clusterId, value.cid); assert.equal(normalized.workspaceId, value.wid);
    for (const row of auditRows(normalized)) assertM10RequestAuditIdentity(normalized, row);
  }
  assert.deepEqual(classifyM10AuditRequest({ method: 'POST', path: '/iam/users', body: { username: 'synthetic', password: 'SyntheticNeverIssued' } }), ['iam.metadata', ['iam.*']]);
  assert.equal(m10FixedIamAuditEvidence({ method: 'POST', path: '/iam/users' }), null);
});
test('foreign role/binding scope and foreign audit rows cannot use a generic IAM alternate scope', () => {
  const role = fixture(); role.role.cluster_id = randomUUID(); assert.throws(() => verify(role), /M10_IAM_REAL_ROLE_SCOPE_MISMATCH/);
  const binding = fixture('user-binding-create'); binding.binding.workspace_id = randomUUID(); assert.throws(() => verify(binding), /M10_IAM_REAL_BINDING_SCOPE_MISMATCH/);
  const normalized = verify(fixture()), row = auditRows(normalized)[0]; row.cluster_id = randomUUID(); assert.throws(() => assertM10RequestAuditIdentity(normalized, row, { clusterId: row.cluster_id, workspaceId: row.workspace_id }), /M10_AUDIT_SCOPE_MISMATCH/);
});
test('wrong operation target, actor/key or typed audit target is rejected', () => {
  const value = fixture('role-permissions'); value.operation.target_id = randomUUID(); assert.throws(() => verify(value), /M10_IAM_OPERATION_TARGET_MISMATCH/);
  const actor = fixture(); actor.operation.actor_id = randomUUID(); assert.throws(() => verify(actor));
  const normalized = verify(fixture('user-binding-create')), row = auditRows(normalized)[1]; row.entity_id = randomUUID(); assert.throws(() => assertM10RequestAuditIdentity(normalized, row));
});
test('forged original DTO/result scope cannot replace the sealed operation evidence', () => {
  const body = fixture(); body.request.iamFixed.input.cluster_id = randomUUID(); assert.throws(() => verify(body), /M10_IAM_ORIGINAL_SCOPE_MISMATCH/);
  const result = fixture('user-binding-create'); result.request.iamFixed.result.workspace_id = randomUUID(); assert.throws(() => verify(result), /M10_IAM_ORIGINAL_RESULT_MISMATCH/);
  const original = fixture(); original.payload.name = 'changed'; assert.throws(() => verify(original));
});
test('exact functions remain independently executable after native Node worker serialization', () => {
  const serializedVerifier = new Function('assert', `const UUID=${UUID.toString()}; return ${verifyM10FixedIamAuditEvidence.toString()};`)(assert);
  const serializedIdentity = new Function('assert', `const UUID=${UUID.toString()}; return ${assertM10RequestAuditIdentity.toString()};`)(assert);
  const value = fixture('user-binding-restore'), normalized = serializedVerifier(value.request, value.operation, value.role, value.binding, value.payload, value.result);
  for (const row of auditRows(normalized)) serializedIdentity(normalized, row);
  const row = auditRows(normalized)[0]; row.entity_type = 'users'; assert.throws(() => serializedIdentity(normalized, row));
});
