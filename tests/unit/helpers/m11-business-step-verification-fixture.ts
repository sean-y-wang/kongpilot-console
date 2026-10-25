import 'reflect-metadata';
import { scheduledStepKindHintRow } from './m11-scheduled-step-kind-hint-sql';
import { randomUUID } from 'node:crypto';
import { vi } from 'vitest';
import { ApprovedWorkflowExecutionService } from '../../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { KongExecutionContextService } from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../../apps/console-api/src/infrastructure/kong/transport-scope';
import { normalizedNativeRequests } from '../../../apps/console-api/src/modules/workflows/approved-execution.types';
import { planAad, snapshotAad } from '../../../apps/console-api/src/modules/workflows/workflow.types';

/** Synthetic SQL/Root registries, real AEAD plans, service private WeakMaps,
 * Context ancestry and grant matching. No SQL, HTTP, timer or native send. */
export function businessStepVerificationFixture(kind: 'portal-credential-issue' | 'configuration_v2' = 'portal-credential-issue', install = true) {
  const secrets = new SecretService(), context = new KongExecutionContextService();
  const cid = randomUUID(), wid = randomUUID(), wf = randomUUID(), eid = randomUUID(), sid = randomUUID(), subjectId = randomUUID(), serviceId = randomUUID();
  const actor: any = { id: randomUUID(), username: 'accepted-console-executor', superAdmin: false };
  const developerId = randomUUID(), reviewers = [randomUUID(), randomUUID(), randomUUID()];
  const expiry = new Date(Date.now() + 60_000).toISOString(), issued = new Date(Date.now() - 1_000).toISOString();
  const scope = transportScopeFor('http://kong:8001');
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', transport_scope: scope, revision: 1, execution_mode: 'approval', version: '1.5.1', status: 'ready' };
  const service = { id: serviceId, name: 'current-portal-service', tags: ['team-pay', 'kos-ws-own'] };
  const requester = { type: kind === 'configuration_v2' ? 'console' : 'developer', id: kind === 'configuration_v2' ? actor.id : developerId, credentialEpoch: '1' };
  const spec = { version: 1, notBefore: issued, windowStart: issued, windowEnd: expiry, executorId: actor.id };
  const seal: any = { version: 1, scheduleId: randomUUID(), scheduleVersion: 1, occurrenceId: randomUUID(), basePlanHash: 'a'.repeat(64),
    spec, specHmac: secrets.fingerprint(spec), delegationId: randomUUID(), delegationVersion: 1, delegationHmac: 'b'.repeat(64),
    ownerId: actor.id, executorId: actor.id, ownerCredentialEpoch: '1', executorCredentialEpoch: '1', requester, transportScope: scope,
    impactHmac: 'c'.repeat(64), subjectSealHmac: 'd'.repeat(64) };
  const grant: any = { id: subjectId, cluster_id: cid, workspace_id: wid, developer_id: developerId, application_id: randomUUID(), publication_id: randomUUID(), state: 'pending', transport_scope: scope, revision: 1 };
  const before = { id: subjectId, state: 'pending', revision: 1 };
  const nativeStep = (order: number, type: string, id: string, path: string, body: any, parentId?: string, credentialKind?: string): any => ({
    id: randomUUID(), key: `issue-${order}`, order, kind: 'native', entityType: type, entityId: id, parentId, credentialKind,
    permissionAction: 'write', dependencies: [], mutationAction: 'create', mutationPayload: body,
    mutationPayloadHmac: secrets.fingerprint(body), mutationIdempotencyKey: `original-${wf}-${order}`, before: null, beforeFingerprint: secrets.fingerprint(null),
    nativeRequests: [{ method: 'POST', canonicalPath: path, nativeType: type, nativeId: id, parentId, credentialKind, body, bodyHmac: secrets.fingerprint(body) }] });
  const consumerId = randomUUID(), aclId = randomUUID(), keyId = randomUUID();
  const native = [nativeStep(1, 'consumers', consumerId, '/consumers', { id: consumerId, username: `app-${wf}`, tags: ['team-pay'] }),
    nativeStep(2, 'credentials', aclId, `/consumers/${consumerId}/acls`, { id: aclId, group: 'portal-own' }, consumerId, 'acls'),
    nativeStep(3, 'credentials', keyId, `/consumers/${consumerId}/key-auth`, { id: keyId, key: 'synthetic-unit-secret' }, consumerId, 'key-auth')];
  native[1].dependencies = [native[0].id]; native[2].dependencies = [native[1].id];
  const metadata: any = kind === 'configuration_v2' ? { jobId: subjectId, planId: randomUUID(), planRevision: 1, planHash: '9'.repeat(64) }
    : { consumerId, aclId, kongId: keyId, credentialId: randomUUID(), action: 'issue', keyFingerprint: secrets.fingerprint('synthetic-unit-secret') };
  const metadataStep: any = { id: randomUUID(), key: 'activate', order: kind === 'configuration_v2' ? 1 : 4, kind: 'metadata', handler: kind === 'configuration_v2' ? 'configuration_v2' : 'portal.credential.activate',
    entityType: kind === 'configuration_v2' ? 'configuration_jobs' : 'portal_application_grants', entityId: subjectId, permissionAction: 'write',
    dependencies: kind === 'configuration_v2' ? [] : [native[2].id], nativeRequests: [], metadata, metadataBeforeHmac: secrets.fingerprint(before), metadataRevision: 1, metadataPayloadHmac: secrets.fingerprint(metadata) };
  const plan: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId: wf, planRevision: 1, kind, executionMode: 'approval', approvalRequired: true,
    subject: { type: metadataStep.entityType, id: subjectId }, requester: { type: requester.type, id: requester.id }, definition: { id: randomUUID(), version: 1, policyHash: 'f'.repeat(64) },
    issuedAt: issued, expiresAt: expiry, scope: { transportScope: scope, clusterRevision: 1, workspaceRevision: 1 }, scheduling: seal,
    prerequisites: kind === 'configuration_v2' ? [] : [{ type: 'services', id: serviceId, path: `/services/${serviceId}`, before: structuredClone(service), fingerprint: secrets.fingerprint(service) }],
    steps: kind === 'configuration_v2' ? [metadataStep] : [...native, metadataStep] };
  const planHash = secrets.fingerprint(plan);
  const set: any = { format: 2, policyHash: plan.definition.policyHash, setId: randomUUID(), setHmac: '8'.repeat(64), reviewers: reviewers.map(userId => ({ approvalId: randomUUID(), userId, level: 1, candidateVersion: 1 })) };
  const w: any = { id: wf, cluster_id: cid, workspace_id: wid, state: 'executing', kind, subject_type: plan.subject.type, subject_id: subjectId, plan_revision: 1, plan_hash: planHash,
    requester_type: requester.type, requester_user_id: requester.type === 'console' ? actor.id : null, requester_developer_id: requester.type === 'developer' ? developerId : null,
    definition_id: plan.definition.id, definition_version: 1, approved_by: reviewers[0], approval_required: true, execution_mode: 'approval', expires_at: expiry,
    approval_format: 2, approval_set_id: set.setId, approval_set_hmac: set.setHmac };
  const e: any = { ...w, id: eid, workflow_id: wf, execution_actor_id: actor.id, permission_version: 'epoch-1', snapshot_state: 'ready', started_at: new Date().toISOString() };
  const version: any = { ...w, workflow_id: wf, policy_version: 1, step_count: plan.steps.length, steps_hash: secrets.fingerprint(plan.steps), native_request_count: kind === 'configuration_v2' ? 0 : 3,
    payload_secret: secrets.encrypt(plan, planAad(cid, wid, wf, 1)) };
  const rows: any[] = plan.steps.map((step: any) => ({ id: step.id, cluster_id: cid, workspace_id: wid, workflow_id: wf, plan_revision: 1, plan_hash: planHash,
    step_key: step.key, step_order: step.order, kind: step.kind, entity_type: step.entityType, entity_id: step.entityId, parent_id: step.parentId ?? null, credential_kind: step.credentialKind ?? null,
    permission_action: step.permissionAction, mutation_action: step.mutationAction ?? null, handler: step.handler ?? null, mutation_payload_hmac: step.mutationPayloadHmac ?? null,
    mutation_idempotency_key: step.mutationIdempotencyKey ?? null, before_fingerprint: step.beforeFingerprint ?? null, dependencies: step.dependencies,
    native_requests: normalizedNativeRequests(step.nativeRequests, secrets), metadata_before_hmac: step.metadataBeforeHmac ?? null, metadata_payload_hmac: step.metadataPayloadHmac ?? null,
    metadata_revision: step.metadataRevision ?? null, execution_mode: 'approval', approval_required: true, state: 'pending', revision: 1, operation_id: null }));
  const objects = [...plan.prerequisites.map((p: any) => ({ type: p.type, id: p.id, path: p.path, before: p.before, absent: false, fingerprint: p.fingerprint })),
    ...(kind === 'configuration_v2' ? [] : native.map(step => ({ type: step.entityType, id: step.entityId, path: `${step.nativeRequests[0].canonicalPath}/${step.entityId}`, before: null, absent: true, fingerprint: secrets.fingerprint(null) })))];
  const snapshot = { version: 1, workflowId: wf, executionId: eid, clusterId: cid, workspaceId: wid, planRevision: 1, planHash, capturedAt: issued, objects };
  e.snapshot_secret = secrets.encrypt(snapshot, snapshotAad(cid, wid, wf, eid)); e.snapshot_hash = secrets.fingerprint(snapshot);
  const claim: any = { id: randomUUID(), scheduleId: seal.scheduleId, scheduleVersion: 1, occurrenceId: seal.occurrenceId, generation: 1, workerOwnerHmac: '7'.repeat(64),
    workflowId: wf, workflowPlanRevision: 1, workflowPlanHash: planHash, issuedAt: issued, authorityExpiresAt: expiry, initialLeaseUntil: expiry,
    clusterId: cid, workspaceId: wid, ownerId: actor.id, executorId: actor.id, ownerCredentialEpoch: '1', executorCredentialEpoch: '1', delegationId: seal.delegationId,
    delegationVersion: 1, delegationHmac: seal.delegationHmac, specHmac: seal.specHmac, windowStart: spec.windowStart, windowEnd: expiry, impactHmac: seal.impactHmac, subjectSealHmac: seal.subjectSealHmac };
  const ns: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', actor: Object.freeze(actor), sessionId: null, clusterId: cid, workspaceId: wid, kind, transportScope: scope,
    clusterRevision: 1, workspaceRevision: 1, permissionVersion: 'epoch-1', credentialEpoch: '1', expiresAt: expiry, claim,
    workflow: { id: wf, planRevision: 1, planHash }, requester, subjectSealHmac: seal.subjectSealHmac, approvalSet: set });
  const origin: any = { id: randomUUID(), cluster_id: cid, workspace_id: wid, schedule_id: claim.scheduleId, claim_id: claim.id, workflow_id: wf, workflow_plan_revision: 1,
    workflow_plan_hash: planHash, execution_id: eid, executor_id: actor.id };
  const job: any = { id: subjectId, actor_id: actor.id, plan_id: metadata.planId, plan_revision: 1, plan_hash: metadata.planHash, transport_scope: scope,
    execution_mode: 'approval', approval_required: true, workflow_id: wf, state: 'running' };
  const state: any = { live: true, epoch: 'epoch-1', executorEpoch: '1', requesterEpoch: '1', origin, service, job, operations: new Map(), namespace: ns, reviewerRevoked: null, legacy: false,
    namespaceChecks: [], validationCalls: [], validationRoles: [], reviewerReadRevoked: null, dbFailure: false, fullDepth: 0, maxFullDepth: 0 };
  const policies = new Map();
  const db: any = { one: vi.fn(async (sql: string, params: any[] = []) => {
    if (state.dbFailure) throw Error('SYNTHETIC_DB_DOWN');
    if (sql.trimStart().startsWith('SELECT s.kind FROM workflow_steps s')) {
      const original = scheduledStepKindHintRow(sql, params, e, rows);
      const observed = state.hintOverrideEnabled ? structuredClone(state.hintOverride) : original;
      state.hintReads ??= []; state.hintReads.push({ sql, args: structuredClone(params) });
      await state.afterKindHint?.({ sql, args: params, observed });
      return observed;
    }
    if (sql.includes('FROM workflow_execution_origins')) return state.origin && structuredClone(state.origin);
    if (sql.includes('FROM workflow_executions')) return structuredClone(e);
    if (sql.includes('FROM workflow_versions')) return structuredClone(version);
    if (sql.includes('FROM workflows')) return structuredClone(w);
    if (sql.includes('FROM clusters')) return structuredClone(cluster);
    if (sql.includes('FROM iam_epoch')) return { version: 1 };
    if (sql.includes('FROM workflow_definition_versions')) return { mode: 'single', allow_self_approval: false, policy_hash: plan.definition.policyHash };
    if (sql.includes('FROM mutation_operations')) return state.operations.get(params[0]) ?? null;
    if (sql.includes('FROM configuration_jobs')) return structuredClone(state.job);
    if (sql.includes('FROM users')) return params[0] === state.reviewerRevoked ? null : { id: params[0], credential_epoch: state.executorEpoch, super_admin: false };
    if (sql.includes('FROM portal_application_grants')) return structuredClone(grant);
    if (sql.includes('FROM portal_publications')) return { id: grant.publication_id, state: 'published', service_id: serviceId, transport_scope: scope };
    if (sql.includes('FROM portal_applications')) return { id: grant.application_id, status: 'active', developer_id: developerId };
    if (sql.includes('FROM portal_developers')) return { id: developerId, status: 'active', credential_epoch: state.requesterEpoch, must_change_password: false };
    throw Error(`Unplanned synthetic query: ${sql}`);
  }), query: vi.fn(async (sql: string) => {
    if (sql.includes('FROM workflow_steps')) return structuredClone(rows);
    if (sql.includes('FROM workflow_approvals')) return [{ decision: 'approve', approver_id: reviewers[0], plan_hash: e.plan_hash, level: 1 }];
    if (sql.includes('FROM workflow_stages')) return [{ state: 'approved', required_approvals: 1, level: 1, plan_hash: e.plan_hash }];
    if (sql.includes('FROM iam_effective_grants')) return [{ module: 'workflows', action: 'approve', cluster_id: cid, workspace_id: wid,
      scope_type: kind === 'configuration_v2' ? 'workspace' : 'tag_group', scope_values: kind === 'configuration_v2' ? [wid] : ['team-pay'] }];
    throw Error(`Unplanned synthetic query: ${sql}`);
  }), exec: vi.fn(async (sql: string, params: any[]) => {
    if (!sql.startsWith('UPDATE workflow_steps SET operation_id=')) throw Error('Unexpected synthetic write');
    const row = rows.find(row => row.id === params[0]); if (!row || row.revision !== params[2] || row.operation_id) return 0;
    row.operation_id = params[1]; row.revision++; return 1;
  }) };
  const approvals: any = { installScheduledConfigurationCanonicalSqlPolicy: vi.fn(), installReviewerPolicy: vi.fn((k: string, policy: any) => policies.set(k, policy)), verifyApprovalSet: vi.fn(async (p: any, _options: any, tx: any) => {
    for (const id of reviewers) await policies.get(p.kind).verifyCurrent(id, p, tx); return structuredClone(set);
  }) };
  const authz: any = { snapshot: vi.fn(async () => ({ user: actor, version: state.epoch })), permissionVersion: vi.fn(async () => state.epoch),
    assertScopedResource: vi.fn(async (_user: any, _c: any, _module: any, _action: any, _type: any, object: any) => {
      if (!object.tags.includes('team-pay')) throw Error('CURRENT_EXECUTOR_TAG_REVOKED');
    }), assertWholeWorkspace: vi.fn() };
  const redis: any = { assertLeaseOwnership: vi.fn(async () => { if (!state.live) throw Error('CURRENT_LEASE_LOST'); }) };
  const handle = Object.freeze({});
  context.installWorkflowScheduledNamespacePolicy({ assertLive(h) { if (h !== handle || !state.live) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); }, async verifyHandle(h, checkpoint) {
    if (h !== handle || !state.live) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); state.namespaceChecks.push(checkpoint);
    // Full business authorization invokes actual reviewer callbacks. The
    // nested validation read must never re-enter this full verifier.
    if (checkpoint !== 'claim') {
      state.fullDepth++; state.maxFullDepth = Math.max(state.maxFullDepth, state.fullDepth);
      if (state.fullDepth > 1) throw Error('RECURSIVE_FULL_NAMESPACE_VERIFICATION');
      try { await approvals.verifyApprovalSet(plan, {}, db); } finally { state.fullDepth--; }
    }
    return state.namespace;
  } });
  context.installPolicy({ async authorizeRequest() { return {}; }, async authorizeResponse(_ticket, value) { return value; } });
  const reads = new WeakMap<object, any>(), tokens = new WeakMap<object, any>();
  const installReadPolicy = () => context.installWorkflowScheduledValidationReadPolicy({
    async verifyHandle(readHandle: object, original: object, proof: any) {
      const row = reads.get(readHandle); if (!row || original !== handle || proof !== ns || !state.live || state.epoch !== ns.permissionVersion) throw Error('ORIGINAL_VALIDATION_READ_REQUIRED'); return row;
    }, assertLive(h: object) { if (!reads.has(h) || !state.live) throw Error('ORIGINAL_VALIDATION_READ_REQUIRED'); },
    async authorizeRequest(h: object) { const token = Object.freeze({}); tokens.set(token, reads.get(h)); return token; },
    async verifyRequest(token: object) { const row = tokens.get(token); if (!row || !state.live) throw Error('ORIGINAL_VALIDATION_REQUEST_REQUIRED'); return row; },
    async authorizeResponse(_token: object, value: unknown) { return value; },
  });
  installReadPolicy();
  const delegate: any = { assertConfigurationOrigin: vi.fn(async (h: object, p: any, _user: string) => { if (h !== handle || p.kind !== 'configuration_v2' || !state.live) throw Error('ORIGINAL_CONFIGURATION_ORIGIN_REQUIRED'); }),
    runValidationRead: vi.fn(async (h: object, c: string, paths: readonly string[], _tx: any, fn: () => Promise<any>, options?: any) => {
      if (h !== handle || c !== cid || paths.length !== 1 || paths[0] !== `/services/${serviceId}`) throw Error('FIXED_VALIDATION_PATH_REQUIRED');
      if (options && (options.role !== 'reviewer' || !reviewers.includes(options.userId) || options.userId === state.reviewerReadRevoked)) throw Error('CURRENT_REVIEWER_READ_REVOKED');
      const readActor = options ? { id: options.userId, username: 'actual-reviewer', superAdmin: false } : actor;
      state.validationRoles.push(options ?? { role: 'executor', userId: actor.id });
      const readHandle = Object.freeze({}); reads.set(readHandle, Object.freeze({ version: 1, origin: 'workflow-scheduled-validation-read', readOnly: true, actor: readActor, sessionId: null,
        role: options ? 'reviewer' : 'executor', namespace: ns, expiresAt: new Date(Date.now() + 20_000).toISOString(), scope: { version: 1, resources: [{ clusterId: cid, workspaceId: wid,
          path: paths[0], kind: 'point', entityType: 'services', entityId: serviceId, secrets: false }], limits: { maxCalls: 1, maxPages: 1, maxRecords: 1, maxBytes: 32768 } },
        registries: [{ clusterId: cid, workspaceId: wid, transportScope: scope, clusterRevision: 1, workspaceRevision: 1, endpointHmac: '6'.repeat(64) }] }));
      state.validationCalls.push(paths[0]);
      try { return await context.runWorkflowScheduledValidationRead(readHandle, h, fn); } finally { reads.delete(readHandle); }
    }) };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => {
    if (method !== 'GET' || path !== `/services/${serviceId}`) throw Error('NO_NATIVE_SEND_IN_SOURCE_TEST');
    const ticket = await context.authorizeRequest(cluster, method, path, undefined, {});
    return context.authorizeResponse(ticket, structuredClone(state.service));
  }) };
  const workspaces: any = { resolve: vi.fn(async () => ({ id: wid, status: 'active', revision: 1 })) };
  const serviceVerifier = new ApprovedWorkflowExecutionService(db, secrets, authz, workspaces, kong, redis, context, approvals);
  let currentProof: any; const actualVerify = serviceVerifier.verifyExecution.bind(serviceVerifier);
  vi.spyOn(serviceVerifier, 'verifyExecution').mockImplementation(async handle => { currentProof = await actualVerify(handle); return currentProof; });
  serviceVerifier.onModuleInit(); if (install) serviceVerifier.installWorkflowScheduledDelegate(delegate);
  const run = (fn: () => Promise<any>) => context.runWorkflowScheduledNamespace(handle, () => serviceVerifier.runApprovedBusinessExecution(handle, eid, fn));
  const nativeContext = (index = 0): any => { const step = plan.steps[index]; return { actor, clusterId: cid, workspaceId: wid, entityType: step.entityType, entityId: step.entityId,
    action: step.mutationAction, payload: step.mutationPayload, before: step.before, parentId: step.parentId, credentialKind: step.credentialKind, idempotencyKey: step.mutationIdempotencyKey }; };
  const operation = (index = 0): any => { const step = plan.steps[index]; const id = randomUUID(); const row: any = { id, actor_id: actor.id, cluster_id: cid, workspace_id: wid,
    workflow_id: wf, workflow_execution_id: eid, workflow_step_id: step.id, workflow_plan_revision: 1, workflow_plan_hash: planHash, state: 'running', remote_started: false, remote_completed: false,
    payload_secret: secrets.encrypt(step.mutationPayload, `mutation:${id}:payload`), before_secret: secrets.encrypt(step.before, `mutation:${id}:before`) }; state.operations.set(id, row); return row; };
  const resealFixture = () => {
    const hash = secrets.fingerprint(plan); w.plan_hash = e.plan_hash = version.plan_hash = hash; version.payload_secret = secrets.encrypt(plan, planAad(cid, wid, wf, 1));
    version.steps_hash = secrets.fingerprint(plan.steps); rows.forEach(row => { row.plan_hash = hash; });
    snapshot.planHash = hash; e.snapshot_hash = secrets.fingerprint(snapshot); e.snapshot_secret = secrets.encrypt(snapshot, snapshotAad(cid, wid, wf, eid));
    origin.workflow_plan_hash = hash; claim.workflowPlanHash = hash; ns.workflow.planHash = hash;
  };
  return { context, verifier: serviceVerifier, secrets, db, state, handle, run, actor, developerId, reviewers, cid, wid, wf, eid, sid, ns, e, w, version, plan, rows, grant, service, cluster,
    delegate, approvals, authz, redis, kong, nativeContext, operation, metadataStep, metadata, before, origin, resealFixture, proof: () => currentProof };
}
