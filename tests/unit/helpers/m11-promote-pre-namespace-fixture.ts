import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { vi } from 'vitest';
import { businessAbsenceFixture } from './workflow-business-absence-fixture';
import { promotionForkFixture } from './m11-promotion-fork-fixture';
import { KongExecutionContextService } from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { KongService } from '../../../apps/console-api/src/infrastructure/kong/kong.service';
import { WorkflowScheduledValidationReadService, WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL } from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.service';
import { WorkflowApprovalAuthorityService } from '../../../apps/console-api/src/modules/workflows/workflow-approval-authority.service';
import { WorkflowCandidatesService } from '../../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import { WorkflowScheduledAuthorityService } from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import { WorkflowScheduledNamespaceService } from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';
import { WorkflowScheduleCandidateReadService } from '../../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import { WorkflowBusinessRuntimeService } from '../../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import { ApprovedWorkflowExecutionService } from '../../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { WorkflowBusinessScopedReadService } from '../../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import { workflowSchedulePlanSeal } from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

/** Real canonical Approval/Candidates, Authority private invocation, fixed Root
 * subject, Material AEAD/grants/observations, GET provider and Context. SQL and
 * Kong responses remain controlled Source adapters: no runtime database, HTTP
 * request, business execution, claim INSERT or Native write is performed. */
export async function promotePreNamespaceFixture(kind: 'configuration_v2' = 'configuration_v2', reviewerCount = 1,
  selector: 'user' | 'role' | 'team' = 'user', namespaceMode = false) {
  const f = await promotionForkFixture(await businessAbsenceFixture(kind)), { plan, db, secrets, tables } = f;
  // The new wrapper/window is capped by the original import; configuration
  // P0/P1 retain their distinct original materials and unchanged plan TTL.
  plan.expiresAt = new Date(Math.min(Date.parse(f.originalJob.authority_expires_at), Date.parse(f.originalJob.expires_at), Date.parse(plan.expiresAt))).toISOString();
  const context = new KongExecutionContextService(), checksum = createHash('sha256').update(readFileSync('apps/console-api/src/infrastructure/migrations/026_m11_workflow_schedules.sql')).digest('hex');
  const reviewers = Array.from({ length: reviewerCount }, () => randomUUID());
  const selectorIds = reviewers.map(id => selector === 'user' ? id : randomUUID()), bindingIds = reviewers.map(() => randomUUID());
  f.user.super_admin = true;
  for (const id of reviewers) tables.users.push({ ...f.user, id, username: `source-reviewer-${id}` });
  const policy: any = { version: 2, kind, allowSelfApproval: false, distinctAcrossStages: true, intentTtlHours: 1,
    stages: reviewers.map((_id, index) => ({ level: index + 1, name: `Reviewer ${index + 1}`, mode: 'any', threshold: 1,
      selector: { [selector === 'user' ? 'users' : selector === 'role' ? 'roles' : 'teams']: [selectorIds[index]] } })) };
  plan.definition.policyHash = secrets.fingerprint(policy);
  const { scheduling: _old, ...base } = plan, now = Date.now();
  const spec = { version: 1, notBefore: new Date(now - 1000).toISOString(), windowStart: new Date(now - 1000).toISOString(), windowEnd: plan.expiresAt, executorId: f.actor };
  f.persist();
  const subjectSeal = await f.compiler.subjectSealForPlan(plan, db), requester = { ...plan.requester, credentialEpoch: '1' };
  const delegation: any = { version: 1, id: randomUUID(), revision: 1, clusterId: f.cid, workspaceId: f.wid, workflowId: plan.workflowId,
    workflowPlanRevision: 1, basePlanHash: secrets.fingerprint(base), kind, subjectType: plan.subject.type, subjectId: plan.subject.id,
    subjectSealHmac: secrets.fingerprint(subjectSeal), requester, ownerId: f.actor, executorId: f.actor, ownerCredentialEpoch: '1', executorCredentialEpoch: '1',
    policyHash: plan.definition.policyHash, specHmac: secrets.fingerprint(spec), issuedAt: plan.issuedAt, expiresAt: plan.expiresAt,
    statement: 'execute-this-exact-approved-business-workflow-with-my-current-authority' };
  const draft: any = { binding: { clusterId: f.cid, workspaceId: f.wid, workflowId: plan.workflowId, workflowPlanRevision: 1, workflowPlanHash: '',
    basePlanHash: secrets.fingerprint(base), kind, subjectType: plan.subject.type, subjectId: plan.subject.id, requester, definitionId: plan.definition.id,
    definitionVersion: plan.definition.version, policyHash: plan.definition.policyHash, subjectSeal }, scheduleId: randomUUID(), scheduleVersion: 1,
    occurrenceId: randomUUID(), spec, specHmac: secrets.fingerprint(spec), delegation, delegationHmac: secrets.fingerprint(delegation),
    transportScope: plan.scope.transportScope, impact: { version: 1, keyId: secrets.fingerprint('source-impact-key'), keys: [secrets.fingerprint(plan.subject)], domains: [], wildcards: [] } };
  draft.impactHmac = secrets.fingerprint(draft.impact); plan.scheduling = workflowSchedulePlanSeal(draft); draft.binding.workflowPlanHash = secrets.fingerprint(plan);
  f.persist();
  const hash = draft.binding.workflowPlanHash, manifest: any = { version: 1, clusterId: f.cid, workspaceId: f.wid, workflowId: plan.workflowId,
    planRevision: 1, planHash: hash, definitionId: plan.definition.id, definitionVersion: plan.definition.version, policyHash: plan.definition.policyHash,
    candidateVersion: 1, stages: reviewers.map((userId, index) => ({ level: index + 1, mode: 'any', threshold: 1,
      candidates: [{ userId, credentialEpoch: '1', provenance: [{ kind: selector, selectorId: selectorIds[index],
        ...(selector === 'role' ? { bindingId: bindingIds[index], bindingSource: 'user' } : {}) }] }] })) };
  const manifestHmac = secrets.fingerprint(manifest);
  const votes: any[] = reviewers.map((id, index) => ({ id: randomUUID(), approver_id: id, decision: 'approve', level: index + 1, plan_hash: hash,
    candidate_version: 1, candidate_manifest_hmac: manifestHmac }));
  const members = votes.map(v => ({ approvalId: v.id, userId: v.approver_id, level: v.level, candidateVersion: 1 }));
  const setMaterial = { version: 1, clusterId: f.cid, workspaceId: f.wid, workflowId: plan.workflowId, planRevision: 1, planHash: hash,
    policyHash: plan.definition.policyHash, candidateVersion: 1, candidateManifestHmac: manifestHmac, reviewers: members };
  const set: any = { id: randomUUID(), set_hmac: secrets.fingerprint(setMaterial), manifest: setMaterial };
  Object.assign(tables.workflows[0], { state: 'approved', approval_format: 2, approved_by: reviewers.at(-1), candidate_version: 1,
    candidate_manifest_hmac: manifestHmac, approval_set_id: set.id, approval_set_hmac: set.set_hmac });
  Object.assign(tables.workflow_versions[0], { approval_format: 2 });
  const stages = votes.map(v => ({ level: v.level, state: 'approved', required_approvals: 1, plan_hash: hash, approval_format: 2,
    candidate_version: 1, candidate_manifest_hmac: manifestHmac, stage_mode: 'any' }));
  const candidateRows = manifest.stages.flatMap((stage: any) => stage.candidates.map((c: any) => ({ level: stage.level, user_id: c.userId,
    credential_epoch: c.credentialEpoch, provenance: c.provenance, plan_hash: hash, manifest_hmac: manifestHmac })));
  const setMembers = members.map(v => ({ cluster_id: f.cid, workspace_id: f.wid, workflow_id: plan.workflowId, plan_revision: 1,
    plan_hash: hash, set_hmac: set.set_hmac, approval_id: v.approvalId, user_id: v.userId, level: v.level, candidate_version: 1, candidate_manifest_hmac: manifestHmac }));
  const state: any = { lease: true, invalidated: false, roleLive: true, teamLive: true, callback: undefined, afterReviewer: undefined, beforeSql: undefined, afterSql: undefined, native: [], rootReads: [] };
  const oldOne = db.one.getMockImplementation()!, oldQuery = db.query.getMockImplementation()!;
  db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    await state.beforeSql?.(sql, args);
    let value: any;
    if (sql === WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL) {
      const row = tables.users.find(row => row.id === args[0]);
      value = row?.status === 'active' && !row.deleted_at && !row.force_password_change ? { ...row, iam_version: String(tables.iam_epoch[0].version),
        grants: tables.iam_effective_grants.filter(row => row.user_id === args[0]) } : null;
    }
    else if (sql.includes('FROM schema_migrations')) value = { checksum };
    else if (sql.includes('FROM workflow_definition_versions')) value = { approval_format: 2, mode: 'multi', allow_self_approval: false, policy_hash: plan.definition.policyHash, policy };
    else if (sql.includes('FROM workflow_candidate_versions')) value = { manifest, manifest_hmac: manifestHmac };
    else if (sql.includes('FROM workflow_approval_sets')) value = set;
    else if (sql.includes('FROM workflow_approval_invalidations')) value = state.invalidated ? { id: randomUUID() } : null;
    else if (sql.includes('FROM iam_effective_grants g') && sql.includes('g.binding_id=$3')) {
      const index = reviewers.indexOf(args[0]); value = state.roleLive && index >= 0 && args[1] === selectorIds[index]
        && args[2] === bindingIds[index] && args[3] === 'user' && args[4] === f.cid && args[5] === f.wid ? { selected: 1 } : null;
    }
    else if (sql.includes('FROM team_members m JOIN teams')) value = state.teamLive && reviewers.some((id, index) => id === args[1] && selectorIds[index] === args[0]) ? { selected: 1 } : null;
    else if (sql.includes('FROM workflow_versions') && sql.includes('workflow_id=$1')) value = tables.workflow_versions.find(row => row.workflow_id === args[0]
      && row.cluster_id === args[1] && row.workspace_id === args[2] && row.plan_revision === args[3]);
    else if (sql.includes('FROM users')) { value = tables.users.find(row => row.id === args[0]);
      if (sql.includes("status='active'") && (value?.status !== 'active' || value?.deleted_at || value?.force_password_change)) value = null; }
    else if (sql.includes('FROM workspaces') && sql.includes('id=$1 AND cluster_id=$2')) value = tables.workspaces.find(row => row.id === args[0] && row.cluster_id === args[1]);
    else value = await oldOne(sql, args);
    const observed = value == null ? value : structuredClone(value); await state.afterSql?.(sql, args); return observed;
  });
  db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM workflow_approvals')) return votes;
    if (sql.includes('FROM workflow_stages')) return stages;
    if (sql.includes('FROM workflow_candidates')) return candidateRows;
    if (sql.includes('FROM workflow_approval_set_members')) return setMembers;
    return oldQuery(sql, args);
  });
  db.transaction = vi.fn(async (fn: any) => fn(db));
  const stored: any = { plan, draft, progress: { state: 'active', revision: 1, claimId: null }, activation: null, claim: null, latestLease: null };
  const repository: any = { installFixedDelegate: vi.fn(), inspectStored: vi.fn(async () => stored) };
  const plans: any = { load: vi.fn(async () => ({ plan, row: tables.workflows[0] })), definition: vi.fn(async () => plan.definition) };
  const redis: any = { assertLeaseActive: vi.fn(() => { if (!state.lease) throw Error('SOURCE_LEASE_LOST'); }),
    assertLeaseOwnership: vi.fn(async () => { if (!state.lease) throw Error('SOURCE_LEASE_LOST'); }) };
  const canonicalCandidates = new WorkflowCandidatesService(db), approvals = new WorkflowApprovalAuthorityService(db, secrets, canonicalCandidates);
  const authority = new WorkflowScheduledAuthorityService(db, secrets, redis, context, plans, approvals, repository);
  let sourceInspection: any;
  const sourceAuthorityHandle = Object.freeze({}), sourceIssuer: any = {
    verifyClaim: vi.fn(async (handle: object) => { if (handle !== sourceAuthorityHandle || !sourceInspection) throw Error('SOURCE_ORIGINAL_ISSUER_REQUIRED'); return sourceInspection; }),
    inspect: vi.fn(async (handle: object) => { if (handle !== sourceAuthorityHandle || !sourceInspection) throw Error('SOURCE_ORIGINAL_ISSUER_REQUIRED'); return sourceInspection; }),
  };
  // Namespace tests retain the real Namespace/Context WeakMaps. Only issuance
  // is a controlled Source adapter; no runtime SQL claim or execution exists.
  const namespaces = new WorkflowScheduledNamespaceService(namespaceMode ? sourceIssuer : authority, secrets, redis);
  const candidate = new WorkflowScheduleCandidateReadService(db, secrets, context, plans, repository, canonicalCandidates);
  const noWrite = () => { throw Error('SOURCE_NO_NATIVE_OR_BUSINESS_WRITE'); };
  const closed = () => ({ installStorageContract: vi.fn(), installContextRunner: vi.fn(), installBusinessPolicy: vi.fn(), installAbsentResponseVerifier: vi.fn(),
    installParentAbsencePolicy: vi.fn(), installFixedReader: vi.fn(() => noWrite), verifyHandle: noWrite, assertLive: noWrite, authorizeRequest: noWrite, verifyRequest: noWrite, authorizeResponse: noWrite });
  const fakeKong: any = { verifyScheduledReadAbsentTransport: noWrite, request: vi.fn(async (cid: string, method: string, path: string, body: any, query: any = {}) => {
    if (method !== 'GET' || body !== undefined || cid !== f.cid) return noWrite();
    const ticket = await context.authorizeRequest(f.cluster, method, path, body, query); await context.beforeNativeSend(ticket);
    state.native.push({ path, actorId: context.current().actor!.id });
    let response: any;
    if (path.startsWith('/schemas/')) response = { fields: [] };
    else if (path === `/services/${f.service.id}`) response = { ...f.service };
    else if (path.startsWith('/plugins/')) { const material = await f.compiler.portalMaterial(plan, db);
      response = path.endsWith(material.publicationProof.aclPluginId) ? material.publicationProof.aclPlugin : material.publicationProof.keyAuthPlugin; }
    else response = { data: [], next: null };
    await state.callback?.({ path, actorId: context.current().actor!.id, response });
    return context.authorizeResponse(ticket, response);
  }) };
  redis.rateLimit = vi.fn(async () => ({ allowed: true }));
  const kong = namespaceMode ? new KongService(db, redis, secrets, {} as any, context) : fakeKong;
  const validation = namespaceMode ? new WorkflowScheduledValidationReadService(db, secrets, redis, plans, repository, canonicalCandidates) : closed();
  const approved = new ApprovedWorkflowExecutionService(db, secrets, {} as any, {} as any, kong, redis, context, approvals); approved.onModuleInit();
  const runtime = new WorkflowBusinessRuntimeService(db, redis, secrets, context, kong, { installWorkflowScheduledCurrentIdentityBridge: vi.fn() } as any,
    plans, { installBusinessScheduledDelegate: vi.fn() } as any, approved, repository, authority, namespaces, candidate, validation as any,
    { installRootVerifier: vi.fn() } as any, f.compiler, {} as any, { installProposalPolicy: vi.fn(), installWorkflowOperationPolicy: vi.fn(), receiptReadActive: () => false } as any,
    { installFixedDelegate: vi.fn() } as any, { get: () => ({ installWorkflowScheduledConfigurationOrigin: vi.fn(), installWorkflowScheduledOrigin: vi.fn() }) } as any,
    new WorkflowBusinessScopedReadService());
  runtime.onModuleInit();
  context.installPolicy({ authorizeRequest: async () => noWrite(), authorizeResponse: async () => noWrite() } as any);
  const originalSubject = (runtime as any).subject.bind(runtime);
  vi.spyOn(runtime as any, 'subject').mockImplementation(async (...args: any[]) => {
    state.rootReads.push({ userId: args[1], action: args[2], checkpoint: args[3] });
    const value = await originalSubject(...args); if (args[2] === 'approve') await state.afterReviewer?.(args[1]); return value;
  });
  const run = (checkpoint = 'claim') => (authority as any).eligibility(stored, db, checkpoint);
  const publicFull = () => approvals.verifyApprovalSet(plan, { checkpoint: 'claim' }, db);
  const runInNamespace = async (fn: () => Promise<any> = () => run('before-send')) => {
    if (!namespaceMode) throw Error('SOURCE_NAMESPACE_MODE_REQUIRED');
    const approvalSet = await publicFull(), now = Date.now(), claim: any = { id: randomUUID(), scheduleId: draft.scheduleId, scheduleVersion: 1,
      occurrenceId: draft.occurrenceId, generation: 1, workerOwnerHmac: secrets.fingerprint('source-namespace-canonical-worker'), workflowId: plan.workflowId,
      workflowPlanRevision: plan.planRevision, workflowPlanHash: hash, issuedAt: new Date(now - 100).toISOString(),
      authorityExpiresAt: plan.expiresAt, initialLeaseUntil: plan.expiresAt };
    stored.claim = claim; stored.latestLease = { id: randomUUID(), claimId: claim.id, generation: 1, workerOwnerHmac: claim.workerOwnerHmac,
      version: 1, previousId: null, leaseUntil: claim.initialLeaseUntil };
    stored.progress = { state: 'claimed', revision: 3, claimId: claim.id };
    stored.activation = { workflowId: plan.workflowId, workflowPlanRevision: 1, workflowPlanHash: hash, approvalFormat: 2,
      approvalRequired: true, approvalSetId: approvalSet.setId, approvalSetHmac: approvalSet.setHmac };
    sourceInspection = { version: 1, claim, draft, plan, approvalSet, principal: { id: f.actor, username: f.user.username,
      superAdmin: f.user.super_admin, forcePasswordChange: false }, permissionVersion: `${f.actor}:1:1`, leaseUntil: claim.initialLeaseUntil,
      authorityExpiresAt: claim.authorityExpiresAt };
    state.native.length = 0; state.rootReads.length = 0;
    return namespaces.runOriginalClaim(sourceAuthorityHandle, fn);
  };
  return { ...f, context, reviewers, policy, manifest, votes, stages, candidateRows, set, setMembers, state, stored, draft, authority, approvals,
    candidate, canonicalCandidates, runtime, approved, redis, run, publicFull, repository, plans, validation, namespaces, kong, runInNamespace };
}
