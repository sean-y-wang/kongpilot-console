import { vi } from 'vitest';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { portalKeyAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { approvedFixture, actor, cid, eid, id, nativeId, physical, wid, wf } from './m6-approved-fixture';

/** Synthetic SQL facts, real AEAD/HMAC, real immutable step builders and verifier.
 * No Gateway transport, live SQL, container, or private reference is involved. */
export function activationRecoveryFixture() {
  const f = approvedFixture(), sessionId = id(601), originalKey = 'original-activation-execution-key';
  const consumerId = nativeId, aclId = id(602), keyId = id(603), credentialId = id(604);
  const now = Date.now(), key = 'SyntheticPendingKeyOnlyForOfflineReview2026';
  const consumer = { id: consumerId, username: 'kos-portal-offline-review', custom_id: f.application.id, tags: ['kos-ws-pay'] };
  const acl = { id: aclId, group: `kos-portal-api-${f.publication.id}`, tags: ['kos-ws-pay'] };
  const keyAuth = { id: keyId, key, tags: ['kos-ws-pay'] };
  Object.assign(f.grant, { revision: 1, consumer_id: consumerId, acl_id: aclId, acl_group: acl.group, workflow_id: wf,
    current_generation: 0, current_credential_id: null, acl_credential_ref_id: null, reservation_released_at: null });
  const native = new PortalNativeService(f.db, f.secrets, f.kong, f.context, f.authz, {
    resolve: async () => f.workspace,
  } as any);
  const first = native.nativeStep(1, 'consumers', 'create', consumer, null, { workflowId: wf });
  const second = native.nativeStep(2, 'credentials', 'create', acl, null, { parentId: consumerId, credentialKind: 'acls', workflowId: wf, dependencies: [first.id] });
  const third = native.nativeStep(3, 'credentials', 'create', keyAuth, null, { parentId: consumerId, credentialKind: 'key-auth', workflowId: wf, dependencies: [second.id] });
  const metadata = { action: 'issue', generation: 1, credentialId, kongId: keyId, consumerId, aclId, keyFingerprint: f.secrets.fingerprint(key) };
  const last = native.metadataStep(4, 'portal.credential.activate', 'portal_application_grants', f.grant.id, structuredClone(f.grant), metadata, [third.id]);
  f.plan.steps = [first, second, third, last];
  f.plan.generated = { consumerId, aclId, credentialId: keyId, key }; f.seal();
  Object.assign(f.workflow, { state: 'uncertain', revision: 4, request_hash: f.secrets.fingerprint({ request: wf }), updated_at: new Date(now - 20_000) });
  Object.assign(f.execution, { state: 'uncertain', revision: 3, idempotency_key: originalKey, started_at: new Date(now - 60_000),
    completed_at: new Date(now - 20_000), updated_at: new Date(now - 20_000) });
  const credential: any = { id: credentialId, cluster_id: cid, workspace_id: wid, grant_id: f.grant.id, developer_id: f.developer.id,
    consumer_id: consumerId, kong_id: keyId, generation: 1, credential_kind: 'key-auth', state: 'pending', revision: 1,
    workflow_id: wf, previous_credential_id: null, credential_ref_id: null, issue_operation_id: null,
    key_secret: f.secrets.encrypt({ key }, portalKeyAad(cid, wid, credentialId, 1)), key_fingerprint: f.secrets.fingerprint(key) };
  const refs: any[] = [
    { id: id(605), cluster_id: cid, workspace_id: wid, consumer_id: consumerId, credential_type: 'acls', kong_id: aclId, state: 'active' },
    { id: id(606), cluster_id: cid, workspace_id: wid, consumer_id: consumerId, credential_type: 'key-auth', kong_id: keyId, state: 'active' },
  ];
  const session: any = { id: sessionId, user_id: actor.id, credential_epoch: 1, session_credential_epoch: 1,
    status: 'active', revoked_at: null, expires_at: new Date(now + 300_000), force_password_change: false, deleted_at: null };
  for (const [index, step] of [first, second, third].entries()) {
    const opId = id(610 + index), body: any = step.mutationPayload;
    const result = { ...body, created_at: Math.floor(now / 1000), ...(step.parentId ? { consumer: { id: step.parentId } } : {}) };
    const path = `${step.nativeRequests[0].canonicalPath}/${step.nativeRequests[0].nativeId}`;
    f.nativeObjects.set(path, result);
    const binding = { workflowId: wf, executionId: eid, planRevision: 1, planHash: f.execution.plan_hash, stepId: step.id,
      beforeHmac: f.secrets.fingerprint(null) };
    const requestHash = f.secrets.fingerprint({ actor: actor.id, clusterId: cid, workspaceId: wid, entityType: step.entityType,
      entityId: null, action: 'create', payload: body, parentId: step.parentId ?? null, credentialKind: step.credentialKind ?? null, approvedWorkflow: binding });
    f.operations.set(opId, { id: opId, cluster_id: cid, workspace_id: wid, actor_id: actor.id, entity_type: step.entityType,
      entity_id: body.id, action: 'create', parent_id: step.parentId ?? null, credential_kind: step.credentialKind ?? null,
      transport_scope: physical, state: 'succeeded', remote_started: true, remote_completed: true, error_code: null,
      workflow_id: wf, workflow_execution_id: eid, workflow_plan_revision: 1, workflow_plan_hash: f.execution.plan_hash,
      workflow_step_id: step.id, idempotency_key: step.mutationIdempotencyKey, request_hash: requestHash,
      before_secret: f.secrets.encrypt(null, `mutation:${opId}:before`), payload_secret: f.secrets.encrypt(body, `mutation:${opId}:payload`),
      result_secret: f.secrets.encrypt({ entity: result }, `mutation:${opId}:result`) });
    Object.assign(f.rows[index], { state: 'succeeded', operation_id: opId, after_fingerprint: f.secrets.fingerprint(result),
      completed_at: new Date(now - 20_000), receipt_secret: f.secrets.encrypt({ receipt: { operationId: opId, state: 'succeeded', remoteStarted: true, remoteCompleted: true }, result: { entity: result } }, `workflow:${eid}:${step.id}:receipt`) });
    if (index > 0) refs[index - 1].payload_secret = f.secrets.encrypt({ credential: result }, `credential:${cid}:${consumerId}:${step.credentialKind}:${result.id}`);
  }
  Object.assign(f.rows[3], { state: 'uncertain', operation_id: null, error_code: 'WORKFLOW_EXECUTION_FAILED', completed_at: new Date(now - 20_000) });
  const oldOne = f.db.one.getMockImplementation()!, oldQuery = f.db.query.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, params: any[] = []) => {
    if (sql.includes('FROM workflow_executions') && sql.includes('WHERE workflow_id')) return params[0] === wf ? f.execution : null;
    if (sql.includes('FROM auth_sessions')) return params[0] !== session.id || params[1] !== session.user_id
      || session.revoked_at || session.expires_at.getTime() <= Date.now() || session.credential_epoch !== session.session_credential_epoch
      || session.status !== 'active' || session.force_password_change || session.deleted_at ? null : session;
    if (sql.includes('FROM portal_credentials')) return params[0] === credential.id || params[0] === credential.grant_id ? credential : null;
    if (sql.includes('FROM credential_refs')) return refs.find(row => params.includes(row.id) || params.includes(row.kong_id)) ?? null;
    return oldOne(sql, params);
  });
  f.db.query.mockImplementation(async (sql: string, params: any[] = []) => {
    if (sql.includes('FROM credential_refs')) return refs;
    if (sql.includes('FROM portal_credentials')) return [credential];
    if (sql.includes('FROM mutation_operations') && !sql.includes("state IN ('running','uncertain')")) return [...f.operations.values()];
    return oldQuery(sql, params);
  });
  const http = <T>(fn: () => Promise<T>, user: any = actor, sid: string | undefined = sessionId) => f.context.runHttp({ idempotencyKey: originalKey }, async () => {
    f.context.bindHttpActor(user, sid); const close = f.context.captureHttpCloser();
    try { return await f.context.runActor({ actor: user, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write' }, fn); }
    finally { close(); }
  });
  const input = () => ({ handler: last.handler!, actor, clusterId: cid, workspaceId: wid, entityType: last.entityType,
    entityId: last.entityId!, before: structuredClone(f.grant), revision: f.grant.revision, payload: structuredClone(last.metadata) });
  const tx: any = { one: f.db.one, query: f.db.query, exec: f.db.exec, transaction: f.db.transaction };
  return { ...f, originalKey, sessionId, session, credential, refs, last, http, input, key, tx,
    nativeAfter: (index: number) => f.nativeObjects.get(`${f.plan.steps[index].nativeRequests[0].canonicalPath}/${f.plan.steps[index].nativeRequests[0].nativeId}`),
    approvedRun: vi.fn() };
}
