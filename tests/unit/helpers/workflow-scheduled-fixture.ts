import { randomUUID } from 'node:crypto';
import { vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../../apps/console-api/src/infrastructure/kong/transport-scope';
import { workflowSchedulePlanSeal } from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { WorkflowScheduledAuthorityService } from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';

/** Controlled SQL and fixed business/executor adapters. These fixtures do not
 * send Kong requests, mint a native permit or assert live SQL026 acceptance. */
export function workflowScheduledFixture(kind: 'configuration_v2' | 'portal-credential-issue' | 'portal-credential-rotate' | 'portal-credential-revoke' = 'configuration_v2') {
  const secrets = new SecretService(), now = Date.now(), cid = randomUUID(), wid = randomUUID(), owner = randomUUID(), developer = randomUUID();
  const sid = randomUUID(), workflowId = randomUUID(), subjectId = randomUUID(), scheduleId = randomUUID(), reviewer = randomUUID();
  const issuedAt = new Date(now - 30000).toISOString(), expiresAt = new Date(now + 240000).toISOString();
  const h = (value: unknown) => secrets.fingerprint(value), definition = { id: randomUUID(), version: 1, policyHash: h('policy') };
  const portal = kind.startsWith('portal-credential-');
  const transportScope = transportScopeFor('http://kong:8001'), request = { type: kind === 'configuration_v2' ? 'console' : 'developer', id: kind === 'configuration_v2' ? owner : developer, credentialEpoch: '1' };
  const payload = { jobId: subjectId, planId: randomUUID(), planRevision: 1, planHash: h('config-native-plan') };
  let steps: any[] = [{ id: randomUUID(), key: 'configuration', order: 1, kind: 'metadata', handler: 'configuration_v2', entityType: 'configuration_jobs',
    entityId: subjectId, permissionAction: 'write', dependencies: [], nativeRequests: [], metadata: payload, metadataRevision: 1, metadataPayloadHmac: h(payload), metadataBeforeHmac: h(null) }];
  if (kind === 'portal-credential-issue') {
    const consumer = randomUUID();
    steps = ['consumers', 'acls', 'key-auth'].map((type, index) => { const nativeId = index ? randomUUID() : consumer;
      const body = { id: nativeId, ...(index ? { consumer: { id: consumer } } : { username: 'source-unit-consumer', tags: [] }), ...(type === 'key-auth' ? { key: 'synthetic-unit-key' } : {}) };
      return { id: randomUUID(), key: `native-${index}`, order: index + 1, kind: 'native', entityType: index ? 'credentials' : 'consumers',
        entityId: nativeId, permissionAction: 'write', dependencies: [], mutationAction: 'create', mutationPayload: body,
        mutationPayloadHmac: h(body), beforeFingerprint: h(null), mutationIdempotencyKey: `unit-native-${index}`,
        nativeRequests: [{ method: 'POST', canonicalPath: index ? `/consumers/${consumer}/${type}` : '/consumers', nativeType: type, nativeId,
          ...(index ? { parentId: consumer, credentialKind: type } : {}), body, bodyHmac: h(body), beforeHmac: h(null) }] }; });
    steps[1].dependencies = [steps[0].id]; steps[2].dependencies = [steps[1].id];
    steps.push({ id: randomUUID(), key: 'activate', order: 4, kind: 'metadata', handler: 'portal.credential.activate', entityType: 'portal_application_grants',
      entityId: subjectId, permissionAction: 'write', dependencies: [steps[2].id], nativeRequests: [], metadata: { generation: 1 }, metadataRevision: 1,
      metadataPayloadHmac: h({ generation: 1 }), metadataBeforeHmac: h(null) });
  }
  if (kind === 'portal-credential-rotate' || kind === 'portal-credential-revoke') {
    const consumer = randomUUID(), oldKong = randomUUID(), newKong = randomUUID();
    const natives: any[] = [];
    if (kind === 'portal-credential-rotate') {
      const body = { id: newKong, key: 'synthetic-rotate-key', consumer: { id: consumer } };
      natives.push({ id: randomUUID(), key: 'native-create', order: 1, kind: 'native', entityType: 'credentials', entityId: newKong,
        permissionAction: 'write', dependencies: [], mutationAction: 'create', mutationPayload: body, mutationPayloadHmac: h(body),
        beforeFingerprint: h(null), mutationIdempotencyKey: 'unit-rotate-create', credentialKind: 'key-auth', parentId: consumer,
        nativeRequests: [{ method: 'POST', canonicalPath: `/consumers/${consumer}/key-auth`, nativeType: 'key-auth', nativeId: newKong,
          parentId: consumer, credentialKind: 'key-auth', body, bodyHmac: h(body), beforeHmac: h(null) }] });
    }
    const delBody = { confirmed: true, confirm_name: oldKong, parentId: consumer, credentialKind: 'key-auth' };
    natives.push({ id: randomUUID(), key: 'native-delete', order: natives.length + 1, kind: 'native', entityType: 'credentials', entityId: oldKong,
      permissionAction: 'write', dependencies: natives.length ? [natives[0].id] : [], mutationAction: 'delete', mutationPayload: delBody,
      mutationPayloadHmac: h(delBody), beforeFingerprint: h({ id: oldKong }), mutationIdempotencyKey: 'unit-portal-delete',
      credentialKind: 'key-auth', parentId: consumer,
      nativeRequests: [{ method: 'DELETE', canonicalPath: `/consumers/${consumer}/key-auth/${oldKong}`, nativeType: 'key-auth', nativeId: oldKong,
        parentId: consumer, credentialKind: 'key-auth', body: delBody, bodyHmac: h(delBody), beforeHmac: h({ id: oldKong }) }] });
    const action = kind === 'portal-credential-rotate' ? 'rotate' : 'revoke';
    const meta = { action, retireConsumer: false, credentialId: randomUUID(), kongId: kind === 'portal-credential-rotate' ? newKong : oldKong,
      generation: kind === 'portal-credential-rotate' ? 2 : 1, oldCredentialId: kind === 'portal-credential-rotate' ? randomUUID() : null,
      consumerId: consumer, aclId: randomUUID(), keyFingerprint: h('key') };
    natives.push({ id: randomUUID(), key: action, order: natives.length + 1, kind: 'metadata', handler: `portal.credential.${action}`,
      entityType: 'portal_application_grants', entityId: subjectId, permissionAction: 'write', dependencies: [natives[natives.length - 1].id],
      nativeRequests: [], metadata: meta, metadataRevision: 1, metadataPayloadHmac: h(meta), metadataBeforeHmac: h(null) });
    steps = natives;
  }
  const base: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId, planRevision: 1, kind, executionMode: 'approval', approvalRequired: true,
    subject: { type: portal ? 'portal_application_grants' : 'configuration_jobs', id: subjectId }, requester: { type: request.type, id: request.id },
    definition, issuedAt, expiresAt, scope: { transportScope, clusterRevision: 1, workspaceRevision: 1 }, prerequisites: [], steps };
  const spec = { version: 1, notBefore: new Date(now - 1000).toISOString(), windowStart: new Date(now - 10000).toISOString(), windowEnd: expiresAt, executorId: owner };
  const subjectSeal = { version: 1, driver: kind === 'configuration_v2' ? 'configuration-apply' : kind, subjectId,
    materialHmac: h('actual-private-business-material'), nativeManifestHmac: h('actual-native-manifest'), sourceScopes: [] };
  const delegation: any = { version: 1, id: randomUUID(), revision: 1, clusterId: cid, workspaceId: wid, workflowId, workflowPlanRevision: 1, basePlanHash: h(base), kind,
    subjectType: base.subject.type, subjectId, subjectSealHmac: h(subjectSeal), requester: request, ownerId: owner, executorId: owner,
    ownerCredentialEpoch: '1', executorCredentialEpoch: '1', policyHash: definition.policyHash, specHmac: h(spec), issuedAt, expiresAt,
    statement: 'execute-this-exact-approved-business-workflow-with-my-current-authority' };
  const draft: any = { binding: { clusterId: cid, workspaceId: wid, workflowId, workflowPlanRevision: 1, workflowPlanHash: '', basePlanHash: h(base), kind,
    subjectType: base.subject.type, subjectId, requester: request, definitionId: definition.id, definitionVersion: 1, policyHash: definition.policyHash, subjectSeal },
    scheduleId, scheduleVersion: 1, occurrenceId: randomUUID(), spec, specHmac: h(spec), delegation, delegationHmac: h(delegation), transportScope,
    impact: { version: 1, keyId: h('impact-key'), keys: [h('affected-object')], domains: [], wildcards: [] }, impactHmac: '' };
  draft.impactHmac = h(draft.impact);
  const plan: any = { ...base, scheduling: workflowSchedulePlanSeal(draft) }; draft.binding.workflowPlanHash = h(plan);
  const approvalSet: any = { format: 2, policyHash: definition.policyHash, setId: randomUUID(), setHmac: h('complete-three-vote-set'),
    reviewers: [reviewer, randomUUID(), randomUUID()].map((userId, level) => ({ approvalId: randomUUID(), userId, level: level + 1, candidateVersion: 1 })) };
  const activation = { workflowId, workflowPlanRevision: 1, workflowPlanHash: h(plan), approvalFormat: 2, approvalRequired: true, approvalSetId: approvalSet.setId, approvalSetHmac: approvalSet.setHmac };
  const state: any = { ownerActive: true, epoch: '1', forceChange: false, requesterActive: true, reviewerActive: true, scopeAllowed: true,
    policyChanged: false, conflict: false, migration: true, lease: false, frame: null, principalVersion: '1', workflowState: 'approved',
    stored: { draft, plan, progress: { state: 'active', revision: 1, claimId: null, reasonCode: null }, activation, claim: null, latestLease: null }, outcome: null,
    completionRow: null, directMode: false, beforeExecute: null, forceRequesterChange: false, lifecycleFacts: {}, nativeUnknown: false, nativeSuccess: false, nestedState: null };
  const db: any = { one: vi.fn(async (sql: string, values: any[] = []) => {
    if (sql.includes('FROM schema_migrations')) return state.migration ? { checksum: 'a'.repeat(64) } : null;
    if (sql.includes('FROM iam_epoch')) return { version: state.principalVersion };
    if (sql.includes('FROM users')) { if (!state.ownerActive || state.forceChange || values[0] !== owner && !state.reviewerActive) return null;
      return { id: values[0], username: 'actual-sql-principal', super_admin: false, credential_epoch: state.epoch, permissions_epoch: '1', force_password_change: false }; }
    if (sql.includes('FROM auth_sessions')) return state.frame?.sessionId === sid ? { id: sid, credential_epoch: state.epoch } : null;
    if (sql.includes('FROM portal_developers')) return state.requesterActive && !state.forceRequesterChange ? { id: developer, credential_epoch: '1', must_change_password: false } : null;
    if (sql.includes('FROM clusters')) return { id: cid, version: '1.5.1', revision: 1, execution_mode: state.directMode ? 'direct' : 'approval', status: 'healthy', admin_url: 'http://kong:8001' };
    if (sql.includes('FROM workspaces')) return { id: wid, cluster_id: cid, revision: 1, status: 'active' };
    if (sql.includes('FROM workflow_schedules') || sql.includes('SELECT m.id')) return state.conflict ? { id: randomUUID() } : null;
    if (sql.includes('FROM workflow_schedule_claims')) { const c = state.stored.claim; if (!c) return null; return { id: c.id, cluster_id: cid, workspace_id: wid,
      schedule_id: c.scheduleId, occurrence_id: c.occurrenceId, generation: c.generation, worker_owner_hmac: c.workerOwnerHmac,
      workflow_id: c.workflowId, workflow_plan_revision: c.workflowPlanRevision, workflow_plan_hash: c.workflowPlanHash,
      issued_at: c.issuedAt, authority_expires_at: c.authorityExpiresAt, initial_lease_until: c.initialLeaseUntil }; }
    if (sql.includes('AS execution,') && sql.includes('AS configuration_origin,')) return { execution: false, origin: false, configuration_origin: false, mutation: false, configuration_execution: false, ...state.lifecycleFacts };
    if (sql.includes('AS unknown,') && sql.includes("m.state='succeeded'")) return { unknown: state.nativeUnknown, succeeded: state.nativeSuccess };
    if (sql.includes('FROM workflow_schedule_progress')) return { schedule_id: scheduleId };
    if (sql.includes('FROM workflows')) return { id: workflowId, plan_revision: 1, plan_hash: draft.binding.workflowPlanHash, state: state.workflowState };
    if (sql.includes('FROM workflow_executions')) return state.completionRow;
    throw new Error('Unexpected controlled authority query');
  }), query: vi.fn(async (sql: string) => {
    if (sql.includes('FROM workflow_steps')) return plan.steps.map((step: any, index: number) => ({ id: step.id, step_key: step.key, step_order: index + 1, state: 'pending',
      operation_id: null, receipt_secret: null, recycle_entry_id: null, after_fingerprint: null, started_at: null, completed_at: null }));
    if (sql.includes('FROM workflow_configuration_execution_origins')) return state.nestedState ? [{ id: state.nestedOriginId ??= randomUUID(), configuration_execution_id: state.configurationExecutionId ??= randomUUID(), state: state.nestedState, actor_id: owner, completed_at: issuedAt }] : [];
    throw new Error('Unexpected controlled authority list');
  }), exec: vi.fn(async (sql: string) => { if (sql.includes('pg_advisory_xact_lock')) return 1; throw new Error('Authority must not directly write business/native state'); }),
    transaction: vi.fn(async (fn: any) => fn(db)) };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => { if (state.lease) throw new Error('Recursive lock acquisition'); state.lease = true;
    try { return await fn(); } finally { state.lease = false; } }), assertLeaseActive: vi.fn(() => { if (!state.lease) throw new ForbiddenException({ code: 'LIVE_LEASE_REQUIRED' }); }),
    assertLeaseOwnership: vi.fn(async () => { if (!state.lease) throw new ForbiddenException({ code: 'LIVE_LEASE_REQUIRED' }); }) };
  // This explicit Source capsule models only the new fixed executor callback
  // boundary. Integration with the real Namespace/Context is tested separately.
  const sourceNamespaces=new WeakMap<object,any>();
  const context: any = { peek: vi.fn(() => state.frame),current:vi.fn(()=>{if(!state.frame)throw new Error('SOURCE_FRAME_REQUIRED');return state.frame;}),
    hasWorkflowScheduledNamespace:vi.fn(()=>false),
    requireWorkflowScheduledNamespaceHandle:vi.fn(()=>{const handle=state.frame?.originalNamespaceHandle;if(!handle||!sourceNamespaces.has(handle))throw new Error('SOURCE_ORIGINAL_NAMESPACE_REQUIRED');return handle;}),
    requireWorkflowScheduledCurrentPrincipal:vi.fn((handle:object)=>{const namespace=sourceNamespaces.get(handle);if(!namespace||state.frame?.originalNamespaceHandle!==handle)throw new Error('SOURCE_ORIGINAL_NAMESPACE_REQUIRED');return {namespace,actor:namespace.actor,role:'executor',readOnly:false};}) }, plans: any = { definition: vi.fn(async () => state.policyChanged ? { ...definition, version: 2 } : definition),
    load: vi.fn(async () => ({ plan, row: { state: state.workflowState } })) };
  const approvals: any = { verifyApprovalSet: vi.fn(async () => { if (!state.reviewerActive) throw new ForbiddenException({ code: 'WORKFLOW_APPROVER_SELECTOR_REVOKED' }); return structuredClone(approvalSet); }) };
  // This older explicit approval double keeps its full verifier. The genuine
  // canonical-facts optimization is covered by the separate real-service test.
  approvals.installScheduledEligibilityFactsReader = vi.fn((verifier: any) => async (original: object, p: any, input: any, tx: any) => {
    await verifier.enter(original, p, input.checkpoint, tx);
    try { return await approvals.verifyApprovalSet(p, input, tx); }
    finally { await verifier.leave(original, p, input.checkpoint, tx); }
  });
  // This older adapter deliberately retains its full approval verifier.
  approvals.installScheduledConfigurationEligibilityFactsReader = approvals.installScheduledEligibilityFactsReader;
  // Bootstrap-only compatibility. This old fixture cannot issue a combined
  // Origin comparison; real canonical/all-party closure has its own suite.
  approvals.installScheduledConfigurationOriginSqlReader = vi.fn(() => async () => {
    throw Error('LEGACY_SCHEDULE_FIXTURE_HAS_NO_ORIGIN_SQL_AUTHORITY');
  });
  let delegate: any;
  const receipt = () => ({ id: scheduleId, state: state.stored.progress.state, nativeAuthority: false });
  const repository: any = { installFixedDelegate: vi.fn((value: any) => { delegate = value; }), inspectStored: vi.fn(async () => structuredClone(state.stored)),
    persistDraft: vi.fn(async (value: any, actor: any, proof: object, tx: any) => { await delegate.verifyDraft(value, actor, proof, tx); await delegate.verifyDraft(value, actor, proof, tx); return receipt(); }),
    activate: vi.fn(async (id: string, value: any, proof: object, tx: any, actor: any) => { await delegate.verifyApproved(id, value, proof, tx, actor); await delegate.verifyPhysicalReservation(id, proof, tx);
      state.stored.activation = value; state.stored.progress.state = 'active'; return receipt(); }),
    appendDueClaim: vi.fn(async (id: string, value: any, proof: object, tx: any) => { await delegate.verifyClaim(id, value, proof, tx); await delegate.verifyPhysicalReservation(id, proof, tx);
      state.stored.claim = structuredClone(value); state.stored.latestLease = { id: randomUUID(), claimId: value.id, generation: 1, workerOwnerHmac: value.workerOwnerHmac,
        version: 1, previousId: null, leaseUntil: value.initialLeaseUntil }; state.stored.progress.state = 'claimed'; state.stored.progress.claimId = value.id; return value; }),
    appendBlocked: vi.fn(async (id: string, code: string, proof: object) => { await delegate.verifyBlocked(id, code, proof, db); state.stored.progress.state = 'blocked'; state.stored.progress.reasonCode = code; }),
    finishClaim: vi.fn(async (id: string, outcome: string, proof: object, tx: any) => { const before = await delegate.verifyOutcome(id, outcome, proof, tx);
      state.stored.progress.state = outcome; const after = await delegate.verifyOutcome(id, outcome, proof, tx);
      if (h(before) !== h(after)) throw new Error('Fixed outcome evidence changed'); state.outcomeEvidence = before; return receipt(); }) };
  const policy: any = { isReceiptRead: () => false, assertReceiptRead: vi.fn(async () => { throw new ForbiddenException({ code: 'SOURCE_RECEIPT_SCOPE_REQUIRED' }); }),
    assertDraft: vi.fn(async () => undefined), assertRequester: vi.fn(async () => { if (!state.requesterActive) throw new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_REQUESTER_REVOKED' }); }),
    assertSubject: vi.fn(async () => { if (!state.scopeAllowed) throw new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_SUBJECT_SCOPE_DENIED' }); }),
    assertReviewer: vi.fn(async () => { if (!state.reviewerActive) throw new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_REVIEWER_REVOKED' }); }) };
  const service = new WorkflowScheduledAuthorityService(db, secrets, redis, context, plans, approvals, repository);
  const completions = new WeakSet<object>();
  const complete = (outcome = 'succeeded', wrapperOutcome = outcome) => { state.workflowState = wrapperOutcome; state.nestedState = kind === 'configuration_v2' ? outcome === 'partial' ? 'succeeded' : outcome : null;
    state.completionRow = { id: state.workflowExecutionId ??= randomUUID(), state: wrapperOutcome, workflow_state: wrapperOutcome, claim_id: state.stored.claim.id,
    origin_id: state.originId ??= randomUUID(),
    schedule_id: scheduleId, execution_actor_id: owner, executor_id: owner, completed_at: new Date().toISOString() }; const completion = Object.freeze({}); completions.add(completion); return completion; };
  const beginCallback=(begin:(namespace:object)=>void,handle:object=Object.freeze({}))=>{
    const before=state.frame,principal={id:owner,username:'actual-sql-principal',superAdmin:false},claim=state.stored.claim;
    if(before&&before.originalNamespaceHandle!==handle)throw new Error('SOURCE_CALLBACK_NAMESPACE_MISMATCH');
    const namespace={origin:'scheduled-workflow',sessionId:null,actor:principal,clusterId:cid,workspaceId:wid,workflow:{id:workflowId,planRevision:plan.planRevision,planHash:draft.binding.workflowPlanHash},
      claim:{...claim,executorId:owner,clusterId:cid,workspaceId:wid}};
    sourceNamespaces.set(handle,namespace);state.frame={...before,kind:'scheduled-workflow',module:'workflows',action:'write',clusterId:cid,workspaceId:wid,actor:principal,sessionId:null,originalNamespaceHandle:handle};
    try{begin(handle);}finally{sourceNamespaces.delete(handle);state.frame=before;}
  };
  const executor = { executeClaim: vi.fn(async (handle: object,begin:(namespace:object)=>void) => { beginCallback(begin);await state.beforeExecute?.(handle); await service.verifyClaim(handle, 'before-send'); return complete(); }),
    verifyCompletion: vi.fn(async (_handle: object, completion: object) => { if (!completions.has(completion)) throw new ForbiddenException({ code: 'ORIGINAL_ROOT_COMPLETION_REQUIRED' }); return state.outcome ?? state.completionRow.state; }) };
  const install = () => { service.installBusinessPolicy(kind, policy); service.installRepositoryPolicies('a'.repeat(64)); service.installExecutor(executor); };
  const actor: any = { user: { id: owner, username: 'current-owner', superAdmin: false }, workspaceId: wid }, enterHttp = () => { state.frame = { actor: actor.user, sessionId: sid, clusterId: cid, workspaceId: wid }; };
  return { service, state, secrets, plan, draft, approvalSet, actor, cid, wid, owner, developer, scheduleId, db, context, plans, approvals, repository,
    redis, policy, executor, install, complete, beginCallback, enterHttp, delegate: () => delegate };
}
