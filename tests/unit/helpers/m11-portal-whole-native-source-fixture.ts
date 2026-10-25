import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { vi } from 'vitest';
import {HttpException} from '@nestjs/common';
import { businessAbsenceFixture } from './workflow-business-absence-fixture';
import { KongExecutionContextService } from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import * as outboundTransport from '../../../apps/console-api/src/infrastructure/kong/outbound';
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
import {AuthorizationService} from '../../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkspaceResolverService} from '../../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {NativeKongPolicyService} from '../../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {WorkflowBusinessCurrentIdentityService} from '../../../apps/console-api/src/modules/workflows/workflow-business-current-identity.service';
import {PortalAuthBoundaryService} from '../../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';
import {publicationProofAad} from '../../../apps/console-api/src/modules/portal/portal-proof';
import {WorkflowBusinessExecutionService} from '../../../apps/console-api/src/modules/workflows/workflow-business-execution.service';
import {snapshotAad} from '../../../apps/console-api/src/modules/workflows/workflow.types';
import {PortalCredentialsService} from '../../../apps/console-api/src/modules/portal/portal-credentials.service';
import {PortalNativeService} from '../../../apps/console-api/src/modules/portal/portal-native.service';
import {CredentialStoreService} from '../../../apps/console-api/src/modules/credentials/credential-store.service';
import {EntityService} from '../../../apps/console-api/src/modules/entities/entities.service';
import {decodeTag} from '../../../apps/console-api/src/infrastructure/kong/tags';
import {WorkflowRegistryService} from '../../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { workflowSchedulePlanSeal } from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

/** Real canonical Approval/Candidates, Authority private invocation, fixed Root
 * subject, Material AEAD/grants/observations, GET provider and Context. SQL and
 * Kong responses and persistent rows remain explicit controlled Source
 * adapters. NativePolicy/SDK may send into the in-memory wire adapter; no
 * production PostgreSQL/Kong HTTP acceptance is claimed. */
async function wholeNativeFoundationFixture(kind: 'configuration_v2' | 'portal-credential-issue' = 'portal-credential-issue', reviewerCount = 1,
  selector: 'user' | 'role' | 'team' = 'user', namespaceMode = false) {
  const f = await businessAbsenceFixture(kind), { plan, db, secrets, tables } = f;
  if(kind==='portal-credential-issue'){
   const row=tables.portal_publication_proofs[0],aad=publicationProofAad(f.cid,f.wid,row.publication_id,1),proof=secrets.decrypt<any>(row.publication_proof_secret,aad);
   // Complete actual Kong auth-graph shapes before sealing the delegated plan.
   // Changing wire DTOs afterwards would invalidate original HMA/AEAD material.
   const grant=tables.portal_application_grants[0],publication=tables.portal_publications[0],group=`kos-portal-api-${publication.id}`;
   grant.acl_group=group;publication.acl_group=group;proof.aclGroup=group;
   Object.assign(f.service,{protocol:'http'});Object.assign(proof.service,{protocol:'http'});
   for(const plugin of [proof.aclPlugin,proof.keyAuthPlugin])plugin.protocols=['http','https'];
   proof.aclPlugin.config.whitelist=[group];
   for(const prerequisite of plan.prerequisites)if(prerequisite.type==='services'){prerequisite.before=f.service;prerequisite.fingerprint=secrets.fingerprint(f.service);}
   const acl=plan.steps.find((step:any)=>step.credentialKind==='acls');acl.mutationPayload.group=group;
   acl.mutationPayloadHmac=secrets.fingerprint(acl.mutationPayload);acl.nativeRequests[0].body.group=group;acl.nativeRequests[0].bodyHmac=secrets.fingerprint(acl.nativeRequests[0].body);
   // Match PortalCredentialsService's real nested POST compilation: the
   // Admin route supplies the FK; it is present in the response, not input.
   for(const step of plan.steps.filter((value:any)=>value.entityType==='credentials')){
    delete (step.mutationPayload as any).consumer;delete (step.nativeRequests[0].body as any).consumer;
    step.mutationPayloadHmac=secrets.fingerprint(step.mutationPayload);
    step.nativeRequests[0].bodyHmac=secrets.fingerprint(step.nativeRequests[0].body);
   }
   const metadata=plan.steps.find((step:any)=>step.kind==='metadata');metadata.before=structuredClone(grant);metadata.metadataBeforeHmac=secrets.fingerprint(metadata.before);
   const string={type:'string'},tags={type:'array',elements:string},consumer={type:'record',fields:[{id:string}]};
   proof.schemas={consumers:{fields:[{id:string},{username:string},{custom_id:string},{tags}]},acls:{fields:[{id:string},{group:string},{consumer},{tags}]},keyAuth:{fields:[{id:string},{key:string},{consumer},{tags}]}};
   row.publication_proof_secret=secrets.encrypt(proof,aad);row.publication_proof_hmac=secrets.fingerprint(proof);
  }
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
  let fixedRepository:any;
  const repository: any = { installFixedDelegate: vi.fn((value:any)=>{fixedRepository=value;}),inspectStored:vi.fn(async()=>structuredClone(stored)),
   appendDueClaim:vi.fn(async(id:string,value:any,proof:object,tx:any)=>{await fixedRepository.verifyClaim(id,value,proof,tx);await fixedRepository.verifyPhysicalReservation(id,proof,tx);
    stored.claim=structuredClone(value);stored.latestLease={id:randomUUID(),claimId:value.id,generation:1,workerOwnerHmac:value.workerOwnerHmac,version:1,previousId:null,leaseUntil:value.initialLeaseUntil};stored.progress={state:'claimed',revision:2,claimId:value.id};return value;}),
   appendBlocked:vi.fn(async(id:string,reason:string,proof:object)=>{await fixedRepository.verifyBlocked(id,reason,proof,db);stored.progress={...stored.progress,state:'blocked',reasonCode:reason};}),
   finishClaim:vi.fn(async(id:string,outcome:string,proof:object,tx:any)=>{await fixedRepository.verifyOutcome(id,outcome,proof,tx);stored.progress={...stored.progress,state:outcome};await fixedRepository.verifyOutcome(id,outcome,proof,tx);return{state:outcome};})};
  const plans: any = { load: vi.fn(async () => ({ plan, row: structuredClone(tables.workflows[0]) })), definition: vi.fn(async () => plan.definition) };
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
  const namespaces = new WorkflowScheduledNamespaceService(authority,secrets,redis,context);
  const candidate = new WorkflowScheduleCandidateReadService(db, secrets, context, plans, repository, canonicalCandidates);
  const noWrite = () => { throw Error('SOURCE_NO_NATIVE_OR_BUSINESS_WRITE'); };
  const closed = () => ({ installStorageContract: vi.fn(), installContextRunner: vi.fn(), installBusinessPolicy: vi.fn(), installAbsentResponseVerifier: vi.fn(),
    installParentAbsencePolicy: vi.fn(), installFixedReader: vi.fn(() => noWrite), verifyHandle: noWrite, assertLive: noWrite, authorizeRequest: noWrite, verifyRequest: noWrite, authorizeResponse: noWrite });
  redis.rateLimit = vi.fn(async () => ({ allowed: true }));
  // The all-role point compiler requires actual SDK 404 provenance. A fake
  // empty collection is neither a point nor an absence witness. Retain real
  // KongService/Context/provider observers and replace only wire transport.
  const kong = new KongService(db, redis, secrets, {} as any, context);
  if (!namespaceMode) vi.spyOn(outboundTransport, 'outboundJson').mockImplementation(async (_base, path, method, body, _query, _auth, _timeout, beforeSend, prepareSend) => {
    if (method !== 'GET' || body !== undefined) return noWrite();
    await prepareSend?.(); beforeSend?.();
    let response: any, status = 200;
    if (path.startsWith('/schemas/')) response = { fields: [] };
    else if (kind === 'portal-credential-issue' && path === `/services/${f.service.id}`) response = { ...f.service };
    else if (kind === 'portal-credential-issue' && path.startsWith('/plugins/')) {
      const material = await f.compiler.portalMaterial(plan, db);
      if (path === `/plugins/${material.publicationProof.aclPluginId}`) response = material.publicationProof.aclPlugin;
      else if (path === `/plugins/${material.publicationProof.keyAuthPluginId}`) response = material.publicationProof.keyAuthPlugin;
      else { status = 404; response = { message: 'Not found' }; }
    } else if (path.split('/').length === 2) response = { data: [], next: null };
    else { status = 404; response = { message: 'Not found' }; }
    const read = { path, actorId: context.current().actor!.id, response };
    state.native.push({ path, actorId: read.actorId }); await state.callback?.(read);
    return { status, body: response, bytes: Buffer.byteLength(JSON.stringify(response)), jsonParsed: true };
  });
  const validation = namespaceMode ? new WorkflowScheduledValidationReadService(db, secrets, redis, plans, repository, canonicalCandidates) : closed();
  const workspaces=new WorkspaceResolverService(db),authz=new AuthorizationService(db,workspaces,kong,context);
  const identity=new WorkflowBusinessCurrentIdentityService(db,secrets,context,redis,repository,plans,canonicalCandidates,validation as any);
  const approved = new ApprovedWorkflowExecutionService(db,secrets,authz,workspaces,kong,redis,context,approvals);approved.onModuleInit();
  let executeBusiness:(claim:object,namespace:object)=>Promise<any>=async()=>{throw Error('SOURCE_FULL_NATIVE_EXECUTOR_REQUIRED');};
  let businessDelegate:any;
  const workflows:any={installBusinessScheduledDelegate:vi.fn((value:any)=>{businessDelegate=value;}),executeBusinessScheduledClaim:(claim:object,namespace:object)=>executeBusiness(claim,namespace),verifyBusinessScheduledCompletion:vi.fn(async()=>{throw Error('SOURCE_NO_WORKFLOW_COMPLETION');})};
  const runtime = new WorkflowBusinessRuntimeService(db, redis, secrets, context,kong,authz,
    plans,workflows,approved, repository, authority, namespaces, candidate, validation as any,
    { installRootVerifier: vi.fn() } as any, f.compiler,identity,{ installProposalPolicy: vi.fn(), installWorkflowOperationPolicy: vi.fn(), receiptReadActive: () => false } as any,
    { installFixedDelegate: vi.fn() } as any, { get: () => ({ installWorkflowScheduledConfigurationOrigin: vi.fn(), installWorkflowScheduledOrigin: vi.fn() }) } as any,
    new WorkflowBusinessScopedReadService());
  runtime.onModuleInit();
  const boundary=new PortalAuthBoundaryService(db,secrets,kong,context,workspaces,approved);
  const nativePolicy=new NativeKongPolicyService(db,secrets,kong,context,authz,workspaces,undefined,boundary);nativePolicy.install();
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
    candidate,canonicalCandidates,runtime,approved,redis,run,publicFull,repository,plans,validation,namespaces,kong,runInNamespace,workspaces,authz,identity,boundary,nativePolicy,workflows,businessDelegate:()=>businessDelegate,execute:(fn:typeof executeBusiness)=>{executeBusiness=fn;} };
}

/** Actual three native issue steps and the original registered credential activation.
 * All business/approval/material/identity,
 * NativePolicy, Context and SDK classes are genuine; SQL rows, lease storage
 * and network wire are explicit Source adapters. Workflow completion is from
 * the actual engine and handler, never a hand-built after DTO or fake activation. */
export async function portalWholeNativeSourceFixture(){
 const f=await wholeNativeFoundationFixture('portal-credential-issue',3,'user',true),{db,plan,secrets,context}=f,h=(v:unknown)=>secrets.fingerprint(v);
 let executionId:string,originId:string;const operations=new Map<string,any>(),receipts=new Map<string,any>();
 const beforeOne=db.one.getMockImplementation()!,beforeQuery=db.query.getMockImplementation()!,beforeExec=db.exec.getMockImplementation()!;
 const source={entered:false,liveConsumer:null as any,liveAcl:null as any,liveKey:null as any,nativeSent:false,packetResults:[]as any[],stopped:Error('SOURCE_UNUSED_STOP_MARKER'),packetResult:null as any,namespaceHandle:undefined as object|undefined,namespaceFrame:null as any,dispatchError:undefined as unknown};
 const credentialRefs:any[]=[],entityParentIndex:any[]=[];Object.assign(f.tables.portal_credentials[0],{revision:1,credential_ref_id:null,issue_operation_id:null,revoke_operation_id:null,recycle_entry_id:null,revoked_at:null,deleted_at:null,last_revealed_at:null});
 let execution:any=null;
 for(const row of f.tables.workflow_steps)Object.assign(row,{state:'pending',revision:1,operation_id:null,receipt_secret:null,recycle_entry_id:null,after_fingerprint:null,started_at:null,completed_at:null});
 f.tables.workflow_versions[0].expires_at=plan.expiresAt;f.tables.workflows[0].revision=1;
 const grantBindings=new Map<string,{id:string;roleId:string}>();
 const effective=(userId:string)=>f.tables.iam_effective_grants.filter((r:any)=>r.user_id===userId);
 for(const user of f.tables.users){if(user.id!==f.actor)f.tables.iam_effective_grants.push(...effective(f.actor).map((g:any)=>({...g,user_id:user.id})));}
 for(const grant of f.tables.iam_effective_grants){let bound=grantBindings.get(grant.user_id);if(!bound){bound={id:randomUUID(),roleId:randomUUID()};grantBindings.set(grant.user_id,bound);}Object.assign(grant,{binding_id:bound.id,role_id:bound.roleId,binding_source:'user'});}
 db.one.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.includes('AS execution,')&&sql.includes('AS configuration_origin,'))return{execution:false,origin:false,configuration_origin:false,mutation:false,configuration_execution:false};
  if(sql.startsWith('SELECT s.id FROM workflow_schedules')||sql.startsWith('SELECT m.id FROM mutation_operations'))return null;
  if(sql.includes("FROM workspaces WHERE cluster_id=$1 AND code='default'"))return structuredClone(f.workspace);
  if(sql.includes('FROM workflow_schedule_progress'))return{schedule_id:f.draft.scheduleId,...f.stored.progress};
  if(sql.includes('FROM workflow_schedule_claims')){const c=f.stored.claim;return c?{id:c.id,cluster_id:f.cid,workspace_id:f.wid,schedule_id:c.scheduleId,occurrence_id:c.occurrenceId,generation:c.generation,worker_owner_hmac:c.workerOwnerHmac,workflow_id:c.workflowId,workflow_plan_revision:c.workflowPlanRevision,workflow_plan_hash:c.workflowPlanHash,issued_at:c.issuedAt,authority_expires_at:c.authorityExpiresAt,initial_lease_until:c.initialLeaseUntil}:null;}
  if(sql.startsWith('SELECT s.kind FROM workflow_steps'))return{kind:f.tables.workflow_steps.find((s:any)=>s.id===args[4])?.kind};
  if(sql.startsWith('SELECT id FROM workflow_executions'))return execution?{id:execution.id}:null;
  if(sql.includes('FROM workflow_steps WHERE workflow_id=$1')&&sql.includes("state='running'"))return f.tables.workflow_steps.find((r:any)=>r.state==='running')??null;
  if(sql.includes('FROM workflow_executions e JOIN workflows w'))return execution?{...structuredClone(execution),workflow_state:f.tables.workflows[0].state,origin_id:originId,claim_id:f.stored.claim.id,schedule_id:f.draft.scheduleId,executor_id:f.actor}:null;
  if(sql.includes('AS unknown,')&&sql.includes("m.state='succeeded'"))return{unknown:[...operations.values()].some(op=>['pending','running','uncertain'].includes(op.state)),succeeded:[...operations.values()].some(op=>op.state==='succeeded')};
  if(sql.startsWith('SELECT * FROM workflow_executions'))return execution?structuredClone(execution):null;
  if(sql.startsWith('SELECT * FROM workflow_versions'))return structuredClone(f.tables.workflow_versions[0]);
  if(sql.startsWith('SELECT * FROM workflows'))return structuredClone(f.tables.workflows[0]);
  if(sql.includes('FROM workflow_execution_origins'))return source.entered?{id:originId,cluster_id:f.cid,workspace_id:f.wid,workflow_id:plan.workflowId,workflow_plan_revision:plan.planRevision,workflow_plan_hash:h(plan),execution_id:executionId,claim_id:f.stored.claim.id,executor_id:f.actor,schedule_id:f.draft.scheduleId}:null;
  if(sql.startsWith('SELECT * FROM mutation_operations'))return operations.get(args[0])??null;
  if(sql.includes('FROM entity_parent_index'))return entityParentIndex.find(row=>row.cluster_id===args[0]&&row.child_type===args[1]&&row.child_id===args[2])??null;
  if(sql.startsWith('SELECT state FROM workflow_executions'))return execution?{state:execution.state}:null;
  if(sql.includes('FROM portal_application_grants')&&sql.includes('id=$1 AND cluster_id=$2'))return structuredClone(f.tables.portal_application_grants.find((r:any)=>r.id===args[0]&&r.cluster_id===args[1]&&r.workspace_id===args[2])??null);
  if(sql.includes('FROM portal_credentials')&&sql.includes('grant_id=$1'))return structuredClone(f.tables.portal_credentials.find((r:any)=>r.grant_id===args[0]&&r.cluster_id===args[1]&&r.workspace_id===args[2]&&r.generation===1)??null);
  if(sql.includes('FROM portal_credentials')&&sql.includes('id=$1 AND grant_id=$2'))return structuredClone(f.tables.portal_credentials.find((r:any)=>r.id===args[0]&&r.grant_id===args[1])??null);
  if(sql==='SELECT * FROM portal_credentials WHERE id=$1')return structuredClone(f.tables.portal_credentials.find((r:any)=>r.id===args[0])??null);
  if(sql.includes('FROM audit_events WHERE workflow_id=$1 AND actor_id=$2')&&sql.includes("action='portal.credential.activate'")){const row=audits.find(r=>r.workflowId===args[0]&&r.actorId===args[1]&&r.action==='portal.credential.activate'&&r.result==='success');return row?{id:row.id}:null;}
  if(sql.includes('FROM credential_refs')){const kind=sql.includes("credential_type='key-auth'")?'key-auth':sql.includes("credential_type='acls'")?'acls':args[2],id=sql.includes("credential_type='")?args[2]:args[3];
   const row=credentialRefs.find(r=>r.cluster_id===args[0]&&r.consumer_id===args[1]&&r.credential_type===kind&&r.kong_id===id&&(!sql.includes("state='active'")||r.state==='active'));return row?structuredClone(row):null;}

  return beforeOne(sql,args);
 });
 db.query.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.includes('FROM iam_effective_grants')&&sql.includes('binding_current'))return effective(args[0]).map((grant:any)=>({grant,binding:{id:grant.binding_id,role_id:grant.role_id,user_id:grant.user_id,status:'active',expires_at:null},binding_current:true,binding_expires_at:null,observed_at:new Date().toISOString()}));
  if(sql.includes('FROM workflow_steps'))return structuredClone(f.tables.workflow_steps);
  if(sql.includes('FROM workflow_configuration_execution_origins'))return[];
  if(sql.includes('FROM portal_publications p LEFT JOIN'))return f.tables.portal_publications.map((p:any)=>({...p,...f.tables.portal_publication_proofs[0],publication_id:p.id,publication_revision:p.published_revision,proof_workflow_id:f.tables.portal_publication_proofs[0].workflow_id,proof_execution_state:'succeeded',proof_workflow_state:'succeeded',proof_workflow_kind:'portal-publication'}));
  if(sql.includes('FROM portal_application_grants WHERE transport_scope'))return f.tables.portal_application_grants;
  if(sql.includes('FROM portal_credentials c JOIN'))return f.tables.portal_credentials;
  return beforeQuery(sql,args);
 });
 db.exec.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.startsWith("UPDATE workflows SET state='executing'")){const w=f.tables.workflows[0];if(w.state!=='approved'||w.revision!==args[1])return 0;w.state='executing';w.expires_at=plan.expiresAt;w.revision++;return 1;}
  if(sql.startsWith('INSERT INTO workflow_executions')){executionId=args[0];execution={id:args[0],cluster_id:args[1],workspace_id:args[2],workflow_id:args[3],plan_revision:args[4],plan_hash:args[5],approved_by:args[6],execution_actor_id:args[7],idempotency_key:args[9],expires_at:args[10],approval_set_id:args[11],approval_set_hmac:args[12],permission_version:args[13],execution_mode:args[14],state:'executing',snapshot_state:'pending',approval_format:2,approval_required:true,started_at:new Date().toISOString()};return 1;}
  if(sql.startsWith('INSERT INTO workflow_execution_origins')){originId=args[0];return 1;}
  if(sql.startsWith("UPDATE workflow_executions SET snapshot_state='ready'")){Object.assign(execution,{snapshot_state:'ready',snapshot_secret:args[1],snapshot_hash:args[2],snapshot_id:args[3]});return 1;}
  if(sql.startsWith("UPDATE workflow_steps SET state='running'")){const row=f.tables.workflow_steps.find((r:any)=>r.id===args[0]);if(!row||row.state!=='pending')return 0;row.state='running';row.revision++;row.started_at=new Date().toISOString();return 1;}
  if(sql.startsWith("UPDATE workflow_steps SET state='succeeded'")){const row=f.tables.workflow_steps.find((r:any)=>r.id===args[0]);if(!row||row.state!=='running')return 0;
   Object.assign(row,{state:'succeeded',safe_result:JSON.parse(args[1]),completed_at:new Date().toISOString(),revision:row.revision+1});
   if(sql.includes('receipt_secret=$3'))Object.assign(row,{receipt_secret:args[2],after_fingerprint:args[3]});return 1;}
  if(sql.startsWith('UPDATE workflow_steps SET state=$2')){Object.assign(f.tables.workflow_steps.find((r:any)=>r.id===args[0]),{state:args[1],error_code:args[2],safe_result:JSON.parse(args[3])});return 1;}
  if(sql.startsWith("UPDATE workflow_executions SET state='succeeded'")){if(execution.state!=='executing')return 0;execution.state='succeeded';execution.completed_at=new Date().toISOString();return 1;}
  if(sql.startsWith("UPDATE workflows SET state='succeeded'")){const row=f.tables.workflows[0];if(row.state!=='executing'||row.revision!==args[3])return 0;row.state='succeeded';row.revision++;return 1;}
  if(sql.startsWith('INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id)')){
   if(args[0]!==f.cid||!['acls','key-auth'].includes(args[1])||args[2]!=='consumers')throw Error('SOURCE_PARENT_INDEX_SCOPE_MISMATCH');
   const rows=JSON.parse(args[3]);if(!Array.isArray(rows)||rows.some((row:any)=>row.parent_id!==plan.generated.consumerId||row.child_id!==(args[1]==='acls'?plan.generated.aclId:plan.generated.credentialId)))throw Error('SOURCE_PARENT_INDEX_ROW_MISMATCH');
   for(const row of rows){const value={cluster_id:args[0],child_type:args[1],child_id:row.child_id,parent_type:args[2],parent_id:row.parent_id},old=entityParentIndex.find(existing=>existing.cluster_id===value.cluster_id&&existing.child_type===value.child_type&&existing.child_id===value.child_id);if(old)Object.assign(old,value);else entityParentIndex.push(value);}return rows.length;
  }
  if(sql.startsWith('INSERT INTO credential_refs')){const old=credentialRefs.find(r=>r.cluster_id===args[1]&&r.consumer_id===args[2]&&r.credential_type===args[3]&&r.kong_id===args[4]);
   const row={id:old?.id??args[0],cluster_id:args[1],consumer_id:args[2],credential_type:args[3],kong_id:args[4],payload_secret:args[5],masked_summary:JSON.parse(args[6]),recovery_capability:args[7],state:'active'};
   if(old)Object.assign(old,row);else credentialRefs.push(row);return 1;}
  if(sql.startsWith("UPDATE portal_credentials SET state='active'")){const row=f.tables.portal_credentials.find((r:any)=>r.id===args[0]&&r.revision===args[3]&&r.state==='pending');if(!row)return 0;
   Object.assign(row,{state:'active',credential_ref_id:args[1],issue_operation_id:args[2],revision:row.revision+1,updated_at:new Date().toISOString()});return 1;}
  if(sql.startsWith("UPDATE portal_application_grants SET state='active'")){const row=f.tables.portal_application_grants.find((r:any)=>r.id===args[0]&&r.revision===args[4]);if(!row)return 0;
   Object.assign(row,{state:'active',current_generation:args[1],current_credential_id:args[2],acl_credential_ref_id:args[3],revision:row.revision+1,updated_at:new Date().toISOString()});return 1;}
  if(sql.startsWith('UPDATE workflow_executions SET state=$2')){execution.state=args[1];execution.completed_at=new Date().toISOString();return 1;}
  if(sql.startsWith('UPDATE workflows SET state=$2')){f.tables.workflows[0].state=args[1];return 1;}
  if(sql.startsWith('INSERT INTO workspaces(cluster_id,code,name,is_default)'))return 0;
  if(sql.includes('pg_advisory_xact_lock'))return 1;
  if(sql.startsWith('UPDATE workflow_steps SET operation_id=')){const row=f.tables.workflow_steps.find((r:any)=>r.id===args[0]);if(!row||row.revision!==args[2]||row.operation_id)return 0;row.operation_id=args[1];row.revision++;return 1;}
  if(sql.startsWith('UPDATE mutation_operations SET entity_id=')){const op=operations.get(args[0]);if(!op)return 0;op.entity_id=args[4];return 1;}
  throw Error('UNEXPECTED_FULL_NATIVE_SOURCE_WRITE:'+sql.slice(0,160));
 });
 f.redis.withLock=vi.fn(async(_key:string,fn:()=>Promise<any>)=>{const prior=f.state.lease;f.state.lease=true;try{return await fn();}finally{f.state.lease=prior;}});
 const audits:any[]=[];const audit:any={append:vi.fn(async(value:any)=>{audits.push({id:randomUUID(),...secrets.redact(value)});})};
 const mutationContext=(p:any,step:any,actor:any):any=>({actor:actor.user,clusterId:f.cid,workspaceId:f.wid,entityType:step.entityType,entityId:step.entityId,action:step.mutationAction,payload:step.mutationPayload,before:null,idempotencyKey:step.mutationIdempotencyKey,parentId:step.parentId,credentialKind:step.credentialKind});
 const registry=new WorkflowRegistryService(),store=new CredentialStoreService(db,secrets),portalNative=new PortalNativeService(db,secrets,f.kong,context,f.authz,f.workspaces);
 const credentials=new PortalCredentialsService(db,secrets,f.authz,audit,{}as any,store,f.approved,f.plans,registry,portalNative);credentials.onModuleInit();
 // Use the production EntityService, including both parent preflights and
 // workspace/authorization checks. MutationService persistence/lifecycle
 // remains an explicit controlled adapter, not a live-service acceptance.
 const mutationAdapter:any={inspectStepReceipt:async(input:any)=>receipts.get(input.idempotencyKey)??null,
  execute:async(m:any,callback:()=>Promise<any>)=>{
   const step=plan.steps.find((value:any)=>value.id===context.currentApprovedStep().stepId)!;
   if(h(m.payload)!==step.mutationPayloadHmac)throw Error('SOURCE_ENTITY_DISPATCH_PAYLOAD_CHANGED');
   return context.runMutationActor(m,async()=>{const binding=await context.approvedMutationBinding(m),operationId=randomUUID();
    const op:any={id:operationId,actor_id:f.actor,cluster_id:f.cid,workspace_id:f.wid,entity_type:step.entityType,entity_id:null,action:step.mutationAction,workflow_id:plan.workflowId,workflow_execution_id:executionId,workflow_step_id:step.id,workflow_plan_revision:plan.planRevision,workflow_plan_hash:h(plan),state:'running',remote_started:false,remote_completed:false,payload_secret:secrets.encrypt(step.mutationPayload,`mutation:${operationId}:payload`),before_secret:secrets.encrypt(null,`mutation:${operationId}:before`),parent_id:step.parentId??null,credential_kind:step.credentialKind??null,transport_scope:plan.scope.transportScope,idempotency_key:step.mutationIdempotencyKey,
     request_hash:h({actor:f.actor,clusterId:f.cid,workspaceId:f.wid,entityType:step.entityType,entityId:null,action:'create',payload:step.mutationPayload??null,parentId:step.parentId??null,credentialKind:step.credentialKind??null,approvedWorkflow:binding})};operations.set(operationId,op);
    await context.bindApprovedOperation(m,binding!,operationId,db);op.remote_started=true;
    let result:any;
    try{result=await context.runOperation({...m,operationId},callback);}
    catch(error){op.state=error instanceof HttpException&&error.getStatus()<500?'failed':'uncertain';receipts.set(step.mutationIdempotencyKey,{operationId,entityId:op.entity_id,state:op.state,remoteStarted:true,remoteCompleted:false});throw error;}
    source.packetResult=result;source.packetResults.push(result);
    op.remote_completed=true;op.state='succeeded';op.entity_id=result.id;op.result_secret=secrets.encrypt({entity:result},`mutation:${operationId}:result`);
    const receipt={operationId,entityId:result.id,state:'succeeded',remoteStarted:true,remoteCompleted:true};receipts.set(step.mutationIdempotencyKey,receipt);return result;
   });
  }};
 const entities=new EntityService(f.kong,f.authz,mutationAdapter,{}as any,store,secrets,audit,{upsert:vi.fn()}as any,f.workspaces,context);
 const engine=new WorkflowBusinessExecutionService({db,redis:f.redis,secrets,context,authz:f.authz,audit,approved:f.approved,plans:f.plans,
  registry,mutations:mutationAdapter,mutationContext,
  dispatch:async(_p:any,step:any,actor:any)=>{
   const child={...actor,idempotencyKey:step.mutationIdempotencyKey},payload=structuredClone(step.mutationPayload),query={workspaceId:f.wid};
   if(Array.isArray(payload.tags))payload.tags=payload.tags.map(decodeTag);
   try{return await (step.entityType==='credentials'
    ?entities.createCredential(f.cid,step.parentId,step.credentialKind,payload,query,child)
    :entities.create(f.cid,step.entityType,payload,query,child));}
   catch(error:any){source.dispatchError={code:error?.getResponse?.()?.code,message:error?.message,stack:error?.stack};throw error;}
  }});
 engine.install(f.businessDelegate());f.workflows.verifyBusinessScheduledCompletion.mockImplementation((claim:object,completion:object,tx:any)=>engine.verifyCompletion(claim,completion,tx));
 f.execute(async(claim,namespace)=>{source.entered=true;source.namespaceHandle=namespace;source.namespaceFrame=context.current();return engine.execute(claim,namespace);});
 const namespaceUsage=()=>{const st=source.namespaceFrame&&(context as any).states.get(source.namespaceFrame);return st?{calls:st.calls,pages:st.pages,records:st.records,bytes:st.bytes}:null;};
 const run=async()=>{
  const approvalSet=await f.publicFull();f.stored.activation={workflowId:plan.workflowId,workflowPlanRevision:1,workflowPlanHash:h(plan),approvalFormat:2,approvalRequired:true,approvalSetId:approvalSet.setId,approvalSetHmac:approvalSet.setHmac};
  const handle=await f.authority.acquireDueClaim(f.draft.scheduleId);if(!handle)throw Error('FULL_NATIVE_SOURCE_CLAIM_REQUIRED:'+f.stored.progress.reasonCode);
  try{await f.authority.executeClaim(handle);}catch(e){if(e!==source.stopped)throw e;}
 };
 return{...f,source,run,operations,audits,namespaceUsage,execution:()=>execution,engine,registry,credentials,store,credentialRefs,entityParentIndex};
}
