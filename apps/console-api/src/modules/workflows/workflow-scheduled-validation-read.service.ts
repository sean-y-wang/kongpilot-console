import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import { ConflictException, ForbiddenException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { DbService, withVerificationReadMemo, freshVerificationRead } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { workflowScheduledValidationBudgetMs } from '../../infrastructure/kong/workflow-scheduled-validation-budget';
import { assertKongPath, validateQuery, entityForPath, ENTITIES } from '../../infrastructure/kong/policy';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { validGrant } from '../authorization/grant-policy';
import { sortByFreshFingerprint } from './workflow-fresh-fingerprint-sort';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowScheduleRepository, assertWorkflowScheduledPlan } from './workflow-schedule.repository';
import { WorkflowCandidatesService } from './workflow-candidates.service';
import { normalizeWorkflowApprovalPolicy } from './workflow-approval-policy';
import type { WorkflowCandidateManifest } from './workflow-approval.types';
import type { WorkflowScheduleStored, WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import type { WorkflowScheduledBusinessKind, WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { WorkflowScheduleCandidatePrincipal, WorkflowScheduleCandidateReadResource, WorkflowScheduleCandidateReadScope,
 WorkflowScheduleCandidateReadInput, WorkflowScheduleCandidateRequest, WorkflowScheduledFutureChildAbsenceWitness } from './workflow-schedule-candidate-read.types';
import type { WorkflowScheduledValidationReadRunner, WorkflowScheduledValidationReadBusinessPolicy, WorkflowScheduledValidationReadOptions, WorkflowScheduledParentAbsencePolicy,
 WorkflowScheduledValidationFixedReader, WorkflowScheduledValidationFixedResult, WorkflowScheduledValidationFixedGroup } from './workflow-scheduled-validation-read.types';
import type { WorkflowScheduledValidationReadProof } from '../../infrastructure/kong/workflow-scheduled-validation-read.types';
import type { ScheduledReadAbsentObservationVerifier } from '../../infrastructure/kong/scheduled-read-absent-transport.types';
import { hasObservedAbsenceWitness, isKongPointNotFound } from './workflow-read-absence-witness';
import {isServiceHostReferencePoint,isServiceHostTargetCollection} from './workflow-service-host-reference';

const denied = (code: string) => new ForbiddenException({ code });
const changed = (code: string) => new ConflictException({ code });
const unavailable = (code: string) => new ServiceUnavailableException({ code });
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex = /^[a-f\d]{64}$/;
import { isPortalCredentialScheduleKind } from '../portal/portal-credential-lifecycle-contract';
const kinds = ['configuration_v2', 'portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'];
const ceilings = { maxCalls: 500, maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024 };
// Keep bigint epochs as typed outer columns; JSON numeric decoding would lose
// precision above 2^53. Only the UUID/text/jsonb grant view is aggregated.
const principalSnapshotSql = `SELECT u.id,u.username,u.super_admin,u.credential_epoch,u.permissions_epoch,
      u.force_password_change,u.display_name,u.locale,u.timezone,u.revision,e.version AS iam_version,
      COALESCE((SELECT jsonb_agg(to_jsonb(g)) FROM iam_effective_grants g WHERE g.user_id=u.id),'[]'::jsonb) AS grants
      FROM users u CROSS JOIN iam_epoch e
      WHERE e.singleton=true AND u.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`;
// Source fixtures/independent SQL proofs can inspect this fixed literal copy;
// the private implementation consumes its own non-exported lexical binding.
export const WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL = principalSnapshotSql;
type Registry = WorkflowScheduledValidationReadProof['registries'][number] & { adminOrigin: string };
interface Cursor { started: boolean; complete: boolean; pending: boolean; next: string | null; offsets: Set<string>; ids: Set<string> }
interface ReadState {
 active: boolean; failed: boolean; readonly namespaceHandle: object; readonly namespace: Readonly<WorkflowScheduledNamespaceProof>;
 readonly actorId: string; readonly role: 'executor' | 'reviewer'; readonly clusterId: string; readonly paths: readonly string[];
 readonly selectedResources?:readonly Readonly<WorkflowScheduleCandidateReadResource>[];
 readonly plan: Readonly<WorkflowScheduledPlanV1>; readonly digest: string; readonly proof: Readonly<WorkflowScheduledValidationReadProof>;
 readonly expiresAt: number; readonly transaction: DbService; readonly cursors: Map<string, Cursor>; readonly seen: Set<string>;
 readonly trueEofs:Set<string>;readonly presentPoints:Set<string>;readonly observedAbsences:Set<string>;readonly sdkObservedAbsences:Set<string>;readonly pendingRequests:Set<object>;
 calls: number; pages: number; records: number; bytes: number;
 readonly fixed?: FixedGroupState;
}
interface FixedGroupState {
 readonly reader: Readonly<WorkflowScheduledValidationFixedReader>; readonly parentFrame: object;
 readonly input: Readonly<WorkflowScheduleCandidateReadInput>; readonly executor: Readonly<WorkflowScheduleCandidatePrincipal>; readonly registries: readonly Registry[];
 phase: 'issued' | 'entered' | 'reading' | 'closing' | 'sealed'; readFrame?: object;
}
interface RequestState { readonly handle: object; readonly state: ReadState; readonly resource: Readonly<WorkflowScheduleCandidateReadResource>; readonly request: Readonly<WorkflowScheduleCandidateRequest>; active: boolean }

/** SQL-only validation capsule nested in a genuine live business Namespace.
 * It never runs the full Authority/reviewer callbacks, creates a SID/claim,
 * exits ALS or grants a native write. Root owns every fixed adapter. */
@Injectable()
export class WorkflowScheduledValidationReadService {
 private readonly handles = new WeakMap<object, ReadState>();
 private readonly requests = new WeakMap<object, RequestState>();
 private readonly policies = new Map<WorkflowScheduledBusinessKind, Readonly<WorkflowScheduledValidationReadBusinessPolicy>>();
 private runner?: Readonly<WorkflowScheduledValidationReadRunner>; private checksum?: string;
 private absentResponseVerifier?:Readonly<ScheduledReadAbsentObservationVerifier>;
 private parentAbsencePolicy?:Readonly<WorkflowScheduledParentAbsencePolicy>;
 private fixedReaderInstalled = false;
 private readonly serviceHostAbsences=new WeakMap<object,Map<string,unknown>>();
 private readonly absenceWitnesses=new WeakMap<object,{readonly handle:object;readonly resource:Readonly<WorkflowScheduleCandidateReadResource>;readonly kind:'sdk404'|'parent-FK-absence'}>();
 constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
  private readonly plans: WorkflowPlansService, private readonly repository: WorkflowScheduleRepository, private readonly candidates: WorkflowCandidatesService) {}
 installStorageContract(checksum: string): void {
  if (this.checksum || !hex.test(checksum ?? '')) throw new Error('Validation reads require one exact SQL026 storage contract'); this.checksum = checksum;
 }
 installAbsentResponseVerifier(verifier:ScheduledReadAbsentObservationVerifier):void{
  if(this.absentResponseVerifier||!verifier||typeof verifier.verifyOriginalResponse!=='function')throw new Error('Validation absence requires one fixed original transport observer');
  this.absentResponseVerifier=Object.freeze({verifyOriginalResponse:verifier.verifyOriginalResponse.bind(verifier)});
 }
 installParentAbsencePolicy(policy:WorkflowScheduledParentAbsencePolicy):void{
  if(this.parentAbsencePolicy||!policy||typeof policy.assertChild!=='function'||Object.keys(policy).some(k=>k!=='assertChild'))throw new Error('Validation parent absence requires one fixed material compiler');
  this.parentAbsencePolicy=Object.freeze({assertChild:policy.assertChild.bind(policy)});
 }
 installContextRunner(runner: WorkflowScheduledValidationReadRunner): void {
  const methods = ['originalNamespaceProof', 'assertNamespaceLive', 'run'] as const;
  if (this.runner || !runner || methods.some(m => typeof runner[m] !== 'function') || Object.keys(runner).some(k => !methods.includes(k as any))) throw new Error('Validation reads require one complete Root bridge');
  this.runner = Object.freeze(Object.fromEntries(methods.map(m => [m, runner[m].bind(runner)]))) as unknown as Readonly<WorkflowScheduledValidationReadRunner>;
 }
 /** The closure is retained only by Root's fixed withLiveReads compiler. A
  * public generic read callback never selects this lifecycle. */
 installFixedReader(reader: WorkflowScheduledValidationFixedReader): WorkflowScheduledValidationFixedGroup {
  if (this.fixedReaderInstalled || !reader || typeof reader.frame !== 'function' || typeof reader.read !== 'function'
   || Object.keys(reader).some(key => !['frame', 'read'].includes(key))) throw new Error('Validation fixed reader requires one complete Root implementation');
  const fixed = Object.freeze({ frame: reader.frame.bind(reader), read: reader.read.bind(reader) }); this.fixedReaderInstalled = true;
  const run: WorkflowScheduledValidationFixedGroup = async (namespaceHandle, clusterId, workspaceId, resources, tx, options) => {
   if (!uuid.test(workspaceId) || !Array.isArray(resources) || !resources.length
    || resources.some(r => r.clusterId !== clusterId || r.workspaceId !== workspaceId)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID');
   const selected = immutableJson(resources);
   return this.runSelectedRead<Readonly<WorkflowScheduledValidationFixedResult>>(namespaceHandle, clusterId, selected.map(r => r.path), tx, undefined, options, selected, fixed);
  };
  return Object.freeze(run);
 }
 installBusinessPolicy(kind: WorkflowScheduledBusinessKind, policy: WorkflowScheduledValidationReadBusinessPolicy): void {
  const methods = ['resolveReadScope', 'assertCurrent', 'authorizeResponse'] as const;
  if (!kinds.includes(kind) || this.policies.has(kind) || !policy || methods.some(m => typeof policy[m] !== 'function') || Object.keys(policy).some(k => !methods.includes(k as any))) throw new Error('Each validation business kind requires one complete fixed policy');
  this.policies.set(kind, Object.freeze(Object.fromEntries(methods.map(m => [m, policy[m].bind(policy)]))) as unknown as Readonly<WorkflowScheduledValidationReadBusinessPolicy>);
 }
 private policy(kind: string): Readonly<WorkflowScheduledValidationReadBusinessPolicy> {
  const policy = this.policies.get(kind as WorkflowScheduledBusinessKind); if (!policy) throw unavailable('WORKFLOW_SCHEDULE_VALIDATION_BUSINESS_UNAVAILABLE'); return policy;
 }
 private key(resource: Pick<WorkflowScheduleCandidateReadResource, 'clusterId' | 'workspaceId' | 'path'>): string { return `${resource.clusterId}:${resource.workspaceId}:${resource.path}`; }
 private state(handle: object): ReadState {
  const state = handle && typeof handle === 'object' && !Array.isArray(handle) ? this.handles.get(handle) : undefined;
  if (!state?.active) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_HANDLE_REQUIRED');
  if (state.failed) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_FAILED'); return state;
 }
 private async checked<T>(state: ReadState, fn: () => Promise<T>): Promise<T> { try { return await fn(); } catch (error) { state.failed = true; throw error; } }
 assertLive(handle: object): void {
  const state = this.state(handle); if (state.expiresAt <= Date.now()) throw denied('WORKFLOW_SCHEDULE_VALIDATION_EXPIRED');
  this.runner!.assertNamespaceLive(state.namespaceHandle); this.redis.assertLeaseActive();
 }
  private async principal(actorId: string, tx: DbService): Promise<Readonly<WorkflowScheduleCandidatePrincipal>> {
    const row = await tx.one<any>(principalSnapshotSql, [actorId]);
    if (!row || row.id !== actorId || row.force_password_change || !Array.isArray(row.grants)
      || typeof row.credential_epoch !== 'string' || typeof row.permissions_epoch !== 'string' || typeof row.iam_version !== 'string')
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_PRINCIPAL_REVOKED');
    const grants = sortByFreshFingerprint((row.grants as unknown[]).filter(validGrant),
      row => this.secrets.fingerprint(row));
    return immutableJson({ user: { id: row.id, username: row.username, superAdmin: row.super_admin === true, forcePasswordChange: false,
      displayName: row.display_name, locale: row.locale, timezone: row.timezone, revision: row.revision }, credentialEpoch: String(row.credential_epoch),
      permissionVersion: `${row.id}:${row.permissions_epoch}:${row.iam_version}`, grants });
  }
  private normalizeScope(value: WorkflowScheduleCandidateReadScope, stored: WorkflowScheduleStored): Readonly<WorkflowScheduleCandidateReadScope> {
    if (!value || value.version !== 1 || value.domain!==undefined&&value.domain!=='scoped-points-v1' || !Array.isArray(value.resources) || !value.resources.length || value.resources.length > 500
      || !value.limits || Object.keys(ceilings).some(key => !Number.isSafeInteger((value.limits as any)[key]) || (value.limits as any)[key] < 1 || (value.limits as any)[key] > (ceilings as any)[key]))
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
    const b = stored.draft.binding, allowed = new Set([`${b.clusterId}:${b.workspaceId}`, ...b.subjectSeal.sourceScopes.map(s => `${s.clusterId}:${s.workspaceId}`)]), seen = new Set<string>();
    for (const r of value.resources) {
      if (!r || !allowed.has(`${r.clusterId}:${r.workspaceId}`)&&!(value.domain==='scoped-points-v1'&&r.clusterId===b.clusterId) || !uuid.test(r.clusterId) || !uuid.test(r.workspaceId)
        || !['point', 'collection', 'schema'].includes(r.kind) || typeof r.secrets !== 'boolean' || typeof r.path !== 'string' || seen.has(this.key(r))
        || r.required !== undefined && typeof r.required !== 'boolean' || r.allowAbsent !== undefined && (typeof r.allowAbsent !== 'boolean' || r.kind !== 'point')) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
      assertKongPath('GET', r.path); seen.add(this.key(r));
      if(r.serviceHostReference!==undefined&&!isServiceHostReferencePoint(r)&&!isServiceHostTargetCollection(r))throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
      const parts = r.path.split('/').filter(Boolean);
      if (r.kind === 'schema') {
        if (!(parts[0] === 'schemas' && parts.length === 2 || parts[0] === 'plugins' && parts[1] === 'schema' && parts.length === 3) || r.secrets || r.query) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
      } else {
        if (!(ENTITIES as readonly string[]).includes(parts[0]) || !isServiceHostReferencePoint(r)&&(parts.includes('enabled') || parts.includes('health')) || entityForPath(r.path) !== r.entityType) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
        if (r.kind === 'point' && (!isServiceHostReferencePoint(r)&&!uuid.test(r.entityId ?? '') || r.query) || r.parentId !== undefined && !uuid.test(r.parentId)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
        if(value.domain==='scoped-points-v1'&&r.kind==='point'&&!isServiceHostReferencePoint(r)&&(r.path!==`/${parts.join('/')}`||(parts.length===2?parts[1]!==r.entityId||r.parentId!==undefined
          :parts.length!==4||parts[3]!==r.entityId||parts[1]!==r.parentId||!uuid.test(parts[1]))))throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
        if (r.kind === 'collection' && (!r.query || !Number.isSafeInteger(r.query.size) || r.query.size < 1 || r.query.size > 100
          || Object.keys(r.query).some(key => !['size', 'tags'].includes(key)))) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID');
        if (r.kind === 'collection') validateQuery(r.query as Record<string, string | number>);
      }
    }
    return immutableJson(value);
  }
  /** Immutable original Namespace facts are the authority anchor; this method
   * independently observes SQL facts without invoking a Native-read reviewer. */
  private async approvalFacts(stored: WorkflowScheduleStored, namespace: Readonly<WorkflowScheduledNamespaceProof>, tx: DbService): Promise<unknown> {
    const p = stored.plan, hash = stored.draft.binding.workflowPlanHash, set = namespace.approvalSet;
    const row = await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [p.workflowId, p.clusterId, p.workspaceId]);
    const version = await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision]);
    const definition = await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4', [p.clusterId, p.workspaceId, p.definition.id, p.definition.version]);
    if (!row || !version || !definition || !['approved', 'executing'].includes(row.state) || row.plan_revision !== p.planRevision || row.plan_hash !== hash
      || version.plan_hash !== hash || row.definition_id !== p.definition.id || row.definition_version !== p.definition.version
      || row.approval_required !== true || version.approval_required !== true || Number(row.approval_format) !== set.format || Number(version.approval_format) !== set.format
      || Number(definition.approval_format) !== set.format || definition.policy_hash !== p.definition.policyHash || this.secrets.fingerprint(definition.policy) !== definition.policy_hash
      || definition.allow_self_approval !== false || set.policyHash !== p.definition.policyHash || !set.reviewers.length)
      throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
    const stages = await tx.query<any>('SELECT * FROM workflow_stages WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision]);
    const votes = await tx.query<any>('SELECT * FROM workflow_approvals WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level,approver_id,id', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision]);
    const actual = votes.map(v => ({ approvalId: v.id, userId: v.approver_id, level: v.level, candidateVersion: v.candidate_version ?? null }));
    if (this.secrets.fingerprint(actual) !== this.secrets.fingerprint(set.reviewers) || votes.some(v => v.plan_hash !== hash || v.decision !== 'approve'
      || p.requester.type === 'console' && v.approver_id === p.requester.id) || stages.some(s => s.plan_hash !== hash || s.state !== 'approved'
      || votes.filter(v => v.level === s.level).length !== s.required_approvals)) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
    let manifest: WorkflowCandidateManifest | undefined;
    if (set.format === 1) {
      if (definition.mode !== 'single' || stages.length !== 1 || stages[0].level !== 1 || stages[0].required_approvals !== 1 || votes.length !== 1
        || row.approved_by !== votes[0].approver_id || set.setId !== null || set.setHmac !== null) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
    } else {
      const policy = normalizeWorkflowApprovalPolicy(definition.policy, p.kind);
      const candidateVersion = await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision, row.candidate_version]);
      manifest = candidateVersion?.manifest;
      if (!manifest || manifest.version !== 1 || manifest.clusterId !== p.clusterId || manifest.workspaceId !== p.workspaceId || manifest.workflowId !== p.workflowId
        || manifest.planRevision !== p.planRevision || manifest.planHash !== hash || manifest.definitionId !== p.definition.id || manifest.definitionVersion !== p.definition.version
        || manifest.policyHash !== p.definition.policyHash || manifest.candidateVersion !== row.candidate_version || candidateVersion.manifest_hmac !== row.candidate_manifest_hmac
        || this.secrets.fingerprint(manifest) !== row.candidate_manifest_hmac || manifest.stages.length !== policy.stages.length || stages.length !== policy.stages.length
        || policy.distinctAcrossStages && new Set(votes.map(v => v.approver_id)).size !== votes.length) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
      const candidates = await tx.query<any>('SELECT * FROM workflow_candidates WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5 ORDER BY level,user_id', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision, row.candidate_version]);
      const expected = manifest.stages.flatMap(stage => stage.candidates.map(candidate => ({ level: stage.level, ...candidate })));
      if (candidates.length !== expected.length || candidates.some((c, i) => c.plan_hash !== hash || c.manifest_hmac !== row.candidate_manifest_hmac || c.level !== expected[i].level
        || c.user_id !== expected[i].userId || String(c.credential_epoch) !== expected[i].credentialEpoch || this.secrets.fingerprint(c.provenance) !== this.secrets.fingerprint(expected[i].provenance))) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
      for (const [i, stage] of stages.entries()) {
        const frozen = manifest.stages[i], rule = policy.stages[i];
        if (stage.level !== i + 1 || stage.approval_format !== 2 || stage.candidate_version !== row.candidate_version || stage.candidate_manifest_hmac !== row.candidate_manifest_hmac
          || stage.stage_mode !== frozen.mode || frozen.mode !== rule.mode || stage.required_approvals !== frozen.threshold
          || frozen.threshold !== (rule.mode === 'all' ? frozen.candidates.length : rule.threshold)) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
      }
      for (const vote of votes) {
        const candidate = manifest.stages.find(stage => stage.level === vote.level)?.candidates.find(c => c.userId === vote.approver_id);
        if (!candidate || vote.candidate_version !== row.candidate_version || vote.candidate_manifest_hmac !== row.candidate_manifest_hmac) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
        await this.candidates.assertCurrent(p, candidate, tx);
      }
      const sqlSet = await tx.one<any>('SELECT * FROM workflow_approval_sets WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6', [set.setId, p.clusterId, p.workspaceId, p.workflowId, p.planRevision, hash]);
      const material = { version: 1, clusterId: p.clusterId, workspaceId: p.workspaceId, workflowId: p.workflowId, planRevision: p.planRevision, planHash: hash,
        policyHash: p.definition.policyHash, candidateVersion: row.candidate_version, candidateManifestHmac: row.candidate_manifest_hmac, reviewers: actual };
      if (!sqlSet || row.approval_set_id !== set.setId || row.approval_set_hmac !== set.setHmac || sqlSet.set_hmac !== set.setHmac
        || this.secrets.fingerprint(sqlSet.manifest) !== set.setHmac || this.secrets.fingerprint(material) !== set.setHmac
        || !actual.some(v => v.userId === row.approved_by && v.level === stages.length)) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
      const members = await tx.query<any>('SELECT * FROM workflow_approval_set_members WHERE set_id=$1 ORDER BY level,user_id,approval_id', [set.setId]);
      if (members.length !== actual.length || members.some((m, i) => m.cluster_id !== p.clusterId || m.workspace_id !== p.workspaceId || m.workflow_id !== p.workflowId
        || m.plan_revision !== p.planRevision || m.plan_hash !== hash || m.set_hmac !== set.setHmac || m.approval_id !== actual[i].approvalId || m.user_id !== actual[i].userId
        || m.level !== actual[i].level || m.candidate_version !== row.candidate_version || m.candidate_manifest_hmac !== row.candidate_manifest_hmac)
        || await tx.one('SELECT id FROM workflow_approval_invalidations WHERE set_id=$1 LIMIT 1', [set.setId])) throw changed('WORKFLOW_SCHEDULE_VALIDATION_APPROVAL_CHANGED');
    }
    const reviewers: WorkflowScheduleCandidatePrincipal[] = [];
    for (const reviewer of set.reviewers) reviewers.push(await this.principal(reviewer.userId, tx));
    return { stages, votes, manifest: manifest ?? null, reviewers };
  }
  /** One verification read: identical non-locking SELECTs inside it share one
   * result; the opening epoch probe and the closing principal/epoch after-check
   * always reach PostgreSQL, so concurrent IAM changes are still detected. */
  private current(namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>, actorId: string,
    role: 'executor' | 'reviewer', clusterId: string, paths: readonly string[], tx: DbService,selectedResources?:readonly Readonly<WorkflowScheduleCandidateReadResource>[]) {
    return withVerificationReadMemo(tx, () => this.currentRead(namespaceHandle, namespace, actorId, role, clusterId, paths, tx, selectedResources));
  }
  private async currentRead(namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>, actorId: string,
    role: 'executor' | 'reviewer', clusterId: string, paths: readonly string[], tx: DbService,selectedResources?:readonly Readonly<WorkflowScheduleCandidateReadResource>[]) {
    if (!this.runner || this.runner.originalNamespaceProof(namespaceHandle) !== namespace) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_NAMESPACE_REQUIRED');
    this.runner.assertNamespaceLive(namespaceHandle); await this.redis.assertLeaseOwnership();
    const migration = await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='026_m11_workflow_schedules.sql'");
    if (!this.checksum || migration?.checksum !== this.checksum) throw unavailable('WORKFLOW_SCHEDULE_VALIDATION_STORAGE_UNAVAILABLE');
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (!epoch) throw unavailable('AUTHORIZATION_UNAVAILABLE');
    const stored = await this.repository.inspectStored(namespace.claim.scheduleId, tx), { plan, draft, claim, latestLease } = stored;
    assertWorkflowScheduledPlan(plan, draft, this.secrets);
    const loaded = await this.plans.load(plan.clusterId, plan.workspaceId, plan.workflowId, tx);
    const d = draft.delegation, b = draft.binding, now = Date.now();
    const claimProjection = claim && { ...claim, clusterId: b.clusterId, workspaceId: b.workspaceId, ownerId: d.ownerId, executorId: d.executorId,
      ownerCredentialEpoch: d.ownerCredentialEpoch, executorCredentialEpoch: d.executorCredentialEpoch, delegationId: d.id, delegationVersion: 1,
      delegationHmac: draft.delegationHmac, specHmac: draft.specHmac, windowStart: draft.spec.windowStart, windowEnd: draft.spec.windowEnd,
      impactHmac: draft.impactHmac, subjectSealHmac: d.subjectSealHmac };
    if (!claim || !latestLease || !stored.activation || !['claimed', 'running'].includes(stored.progress.state) || stored.progress.claimId !== claim.id
      || this.secrets.fingerprint(claimProjection) !== this.secrets.fingerprint(namespace.claim) || latestLease.claimId !== claim.id || latestLease.generation !== 1
      || latestLease.workerOwnerHmac !== claim.workerOwnerHmac || latestLease.version !== 1 || latestLease.previousId !== null
      || latestLease.leaseUntil !== claim.initialLeaseUntil || claim.generation !== 1 || this.secrets.fingerprint(loaded.plan) !== this.secrets.fingerprint(plan)
      || !['approved', 'executing'].includes(loaded.row.state) || namespace.version !== 1 || namespace.origin !== 'scheduled-workflow' || namespace.sessionId !== null
      || namespace.clusterId !== b.clusterId || namespace.workspaceId !== b.workspaceId || namespace.kind !== plan.kind || namespace.actor.id !== d.executorId
      || d.ownerId !== d.executorId || d.ownerCredentialEpoch !== d.executorCredentialEpoch || namespace.credentialEpoch !== d.executorCredentialEpoch
      || namespace.transportScope !== draft.transportScope || namespace.clusterRevision !== plan.scope.clusterRevision || namespace.workspaceRevision !== plan.scope.workspaceRevision
      || this.secrets.fingerprint(namespace.workflow) !== this.secrets.fingerprint({ id: plan.workflowId, planRevision: plan.planRevision, planHash: b.workflowPlanHash })
      || this.secrets.fingerprint(namespace.requester) !== this.secrets.fingerprint(b.requester) || namespace.subjectSealHmac !== d.subjectSealHmac)
      throw changed('WORKFLOW_SCHEDULE_VALIDATION_CLAIM_CHANGED');
    const deadlines = [namespace.expiresAt, claim.authorityExpiresAt, latestLease.leaseUntil, plan.expiresAt, d.expiresAt, draft.spec.windowEnd].map(Date.parse);
    if (deadlines.some(t => !Number.isFinite(t) || t <= now) || now < Date.parse(draft.spec.notBefore) || now < Date.parse(draft.spec.windowStart)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_EXPIRED');
    if (this.secrets.fingerprint(await this.plans.definition(plan.clusterId, plan.workspaceId, plan.kind, tx)) !== this.secrets.fingerprint(plan.definition)) throw changed('WORKFLOW_SCHEDULE_VALIDATION_POLICY_CHANGED');
    const executor = await this.principal(d.executorId, tx);
    if (executor.credentialEpoch !== d.executorCredentialEpoch || executor.permissionVersion !== namespace.permissionVersion
      || this.secrets.fingerprint(executor.user) !== this.secrets.fingerprint(namespace.actor)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_EXECUTOR_REVOKED');
    if (b.requester.type === 'developer') {
      const requester = await tx.one<any>(`SELECT id,credential_epoch,must_change_password FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
        AND status='active' AND deleted_at IS NULL AND NOT must_change_password`, [b.requester.id, b.clusterId, b.workspaceId]);
      if (!requester || requester.id !== b.requester.id || requester.must_change_password || String(requester.credential_epoch) !== b.requester.credentialEpoch || !isPortalCredentialScheduleKind(plan.kind)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_REQUESTER_REVOKED');
    } else if (plan.kind !== 'configuration_v2' || b.requester.id !== d.executorId || b.requester.credentialEpoch !== executor.credentialEpoch) throw denied('WORKFLOW_SCHEDULE_VALIDATION_REQUESTER_REVOKED');
    const approvals = await this.approvalFacts(stored, namespace, tx);
    const activation = { workflowId: plan.workflowId, workflowPlanRevision: plan.planRevision, workflowPlanHash: b.workflowPlanHash,
      approvalFormat: namespace.approvalSet.format, approvalRequired: true, approvalSetId: namespace.approvalSet.setId, approvalSetHmac: namespace.approvalSet.setHmac };
    if (this.secrets.fingerprint(stored.activation) !== this.secrets.fingerprint(activation) || role === 'executor' && actorId !== d.executorId
      || role === 'reviewer' && !namespace.approvalSet.reviewers.some(r => r.userId === actorId)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_PRINCIPAL_REQUIRED');
    const principal = role === 'executor' ? executor : await this.principal(actorId, tx);
    const input: WorkflowScheduleCandidateReadInput = { plan, draft, role, principal, transaction: tx }, policy = this.policy(plan.kind);
    await policy.assertCurrent(input);
    const fullScope = this.normalizeScope(await policy.resolveReadScope(input), stored);
    const resources = fullScope.resources.filter(r => r.clusterId === clusterId && paths.includes(r.path)&&(!selectedResources||selectedResources.some(s=>this.secrets.fingerprint(s)===this.secrets.fingerprint(r))));
    if (resources.length !== paths.length || paths.some(path => resources.filter(r => r.path === path).length !== 1)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN');
    const scope = immutableJson({ ...fullScope, resources }), registries: Registry[] = [];
    for (const resource of scope.resources) {
      if (registries.some(r => r.clusterId === resource.clusterId && r.workspaceId === resource.workspaceId)) continue;
      const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [resource.clusterId]);
      const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [resource.workspaceId, resource.clusterId]);
      if (!cluster || !workspace || cluster.id !== resource.clusterId || workspace.id !== resource.workspaceId || workspace.cluster_id !== resource.clusterId
        || ['disabled', 'incompatible'].includes(cluster.status) || !isSupportedKong(cluster.version ?? '') || workspace.status !== 'active') throw changed('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
      const transportScope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
      if (resource.clusterId === plan.clusterId && resource.workspaceId === plan.workspaceId && (cluster.revision !== plan.scope.clusterRevision
        || workspace.revision !== plan.scope.workspaceRevision || cluster.execution_mode !== plan.executionMode || transportScope !== plan.scope.transportScope)) throw changed('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
      registries.push({ clusterId: resource.clusterId, workspaceId: resource.workspaceId, transportScope, clusterRevision: cluster.revision, workspaceRevision: workspace.revision,
        adminOrigin: new URL(cluster.admin_url).origin, endpointHmac: this.secrets.fingerprint({ endpoint: cluster.admin_url, credential: cluster.connection_secret ?? null, version: cluster.version, transportScope }) });
    }
    const after = await freshVerificationRead(tx, () => this.principal(actorId, tx)), afterEpoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (String(epoch.version) !== String(afterEpoch?.version) || this.secrets.fingerprint(after) !== this.secrets.fingerprint(principal)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_PERMISSIONS_CHANGED');
    await this.redis.assertLeaseOwnership(); this.runner.assertNamespaceLive(namespaceHandle);
    return { input, scope, registries, executor, digest: this.secrets.fingerprint({ plan, draft, claim, latestLease, approvals, executor, principal, scope, registries }) };
  }
  async verifyHandle(handle: object, namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>): Promise<Readonly<WorkflowScheduledValidationReadProof>> {
    const state = this.state(handle);
    if (!state.fixed) return this.verifyCompleteHandle(handle, namespaceHandle, namespace);
    return this.checked(state, async () => {
      const group = state.fixed!;
      if (namespaceHandle !== state.namespaceHandle || namespace !== state.namespace) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_NAMESPACE_REQUIRED');
      if (group.phase === 'closing') {
        await this.verifyCompleteHandle(handle, namespaceHandle, namespace); group.phase = 'sealed'; return state.proof;
      }
      if (!['issued', 'reading'].includes(group.phase)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_PHASE_REQUIRED');
      await this.verifyFixedCurrent(handle, state);
      if (group.phase === 'issued') group.phase = 'entered';
      return state.proof;
    });
  }
  private assertFixedFrame(handle: object, state: ReadState): void {
    this.assertLive(handle); const group = state.fixed;
    if (!group || this.state(handle) !== state) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_ORIGINAL_REQUIRED');
    const reading = group.phase !== 'issued' && group.phase !== 'entered';
    const frame = group.reader.frame(state.namespaceHandle, state.namespace, reading ? { handle, proof: state.proof } : undefined);
    if (frame !== (reading ? group.readFrame : group.parentFrame)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_FRAME_CHANGED');
  }
  /** Fresh typed SQL identities and complete grant sets remain per checkpoint.
   * Only full approval/material reconstruction moves to the two complete
   * group fences; every actual response still uses the original full policy. */
  private async verifyFixedCurrent(handle: object, state: ReadState): Promise<void> {
    const group = state.fixed!;
    const observed = async <T>(fn: () => Promise<T>): Promise<T> => {
      this.assertFixedFrame(handle, state); await this.redis.assertLeaseOwnership(); this.assertFixedFrame(handle, state);
      const value = await fn(); this.assertFixedFrame(handle, state); await this.redis.assertLeaseOwnership(); this.assertFixedFrame(handle, state); return value;
    };
    const principal = await observed(() => this.principal(state.actorId, state.transaction));
    const executor = state.actorId === state.namespace.actor.id ? principal : await observed(() => this.principal(state.namespace.actor.id, state.transaction));
    if (this.secrets.fingerprint(principal) !== this.secrets.fingerprint(group.input.principal)
      || this.secrets.fingerprint(executor) !== this.secrets.fingerprint(group.executor)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_PERMISSIONS_CHANGED');
    for (const original of group.registries) {
      const cluster = await observed(() => state.transaction.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [original.clusterId]));
      const workspace = await observed(() => state.transaction.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [original.workspaceId, original.clusterId]));
      if (!cluster || !workspace || cluster.id !== original.clusterId || workspace.id !== original.workspaceId || workspace.cluster_id !== original.clusterId
       || ['disabled', 'incompatible'].includes(cluster.status) || !isSupportedKong(cluster.version ?? '') || workspace.status !== 'active') throw changed('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
      const transportScope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
      if (original.clusterId === state.plan.clusterId && original.workspaceId === state.plan.workspaceId && cluster.execution_mode !== state.plan.executionMode)
        throw changed('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
      const current = { clusterId: cluster.id, workspaceId: workspace.id, transportScope, clusterRevision: cluster.revision, workspaceRevision: workspace.revision,
       adminOrigin: new URL(cluster.admin_url).origin, endpointHmac: this.secrets.fingerprint({ endpoint: cluster.admin_url, credential: cluster.connection_secret ?? null, version: cluster.version, transportScope }) };
      if (this.secrets.fingerprint(current) !== this.secrets.fingerprint(original)) throw changed('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
    }
    // Close SQL waits as well as the transport/response await. A global IAM
    // change affecting another candidate must poison this original group.
    const after = await observed(() => this.principal(state.actorId, state.transaction));
    if (this.secrets.fingerprint(after) !== this.secrets.fingerprint(group.input.principal)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_PERMISSIONS_CHANGED');
  }
  private async verifyCompleteHandle(handle: object, namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>): Promise<Readonly<WorkflowScheduledValidationReadProof>> {
    const state = this.state(handle); return this.checked(state, async () => {
      if (namespaceHandle !== state.namespaceHandle || namespace !== state.namespace) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_NAMESPACE_REQUIRED');
      if (state.fixed) this.assertFixedFrame(handle, state);
      this.assertLive(handle);
      const current = await this.current(namespaceHandle, namespace, state.actorId, state.role, state.clusterId, state.paths, state.transaction,state.selectedResources);
      if (state.fixed) this.assertFixedFrame(handle, state);
      this.assertLive(handle); if (current.digest !== state.digest) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FACTS_CHANGED'); return state.proof;
    });
  }
  /** Returns an opaque original association only after the SDK observer has
   * recorded the exact parsed404. A caught HttpException alone is useless. */
  async requireObservedAbsentPoint(handle:object,selected:Readonly<WorkflowScheduleCandidateReadResource>):Promise<object>{
    const state=this.state(handle);return this.checked(state,async()=>{
      await this.verifyCompleteHandle(handle,state.namespaceHandle,state.namespace);
      const resource=state.proof.scope.resources.find((d=>(r:any)=>this.secrets.fingerprint(r)===d)(this.secrets.fingerprint(selected)));
      if(!resource||resource.kind!=='point'||resource.allowAbsent!==true||!isServiceHostReferencePoint(resource)&&(state.proof.scope.domain!=='scoped-points-v1'||resource.required!==true)
        ||!state.sdkObservedAbsences.has(this.key(resource))||!state.seen.has(this.key(resource)))throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_ABSENCE_REQUIRED');
      const witness=Object.freeze({});this.absenceWitnesses.set(witness,{handle,resource,kind:'sdk404'});return witness;
    });
  }
  /** Actual parsed SDK404 projection from this live, exact optional
   * Service-name point. It creates no absence from an error or status DTO. */
  async observedServiceHostAbsence(handle:object,selected:Readonly<WorkflowScheduleCandidateReadResource>):Promise<Readonly<{originalWitness:object;response:unknown}>>{
    const originalWitness=await this.requireObservedAbsentPoint(handle,selected),state=this.state(handle),witness=this.absenceWitnesses.get(originalWitness);
    const values=this.serviceHostAbsences.get(handle),key=this.key(selected);
    if(!isServiceHostReferencePoint(selected)||witness?.handle!==handle||!values?.has(key))throw denied('WORKFLOW_SCHEDULE_SERVICE_HOST_ABSENCE_REQUIRED');
    this.assertLive(handle);return Object.freeze({originalWitness,response:values.get(key)});
  }
  /** An absent allocated FK parent cannot have nested stored children. This
   * records that logical proof separately; it never fabricates an HTTP404,
   * EOF, transport observation or Native receipt. */
  async observeFutureChildAbsence(handle:object,selected:Readonly<WorkflowScheduleCandidateReadResource>,originalParentWitness:object):Promise<Readonly<WorkflowScheduledFutureChildAbsenceWitness>>{
    const state=this.state(handle);return this.checked(state,async()=>{
      await this.verifyCompleteHandle(handle,state.namespaceHandle,state.namespace);
      const witness=this.absenceWitnesses.get(originalParentWitness),child=state.proof.scope.resources.find((d=>(r:any)=>this.secrets.fingerprint(r)===d)(this.secrets.fingerprint(selected)));
      const parent=witness?.resource,parts=child?.path.split('/').filter(Boolean)??[];
      if(state.proof.scope.domain!=='scoped-points-v1'||!this.parentAbsencePolicy||witness?.handle!==handle||witness.kind!=='sdk404'||!parent||!child
        ||child.kind!=='point'||child.allowAbsent!==true||child.required!==true||!child.parentId||child.clusterId!==parent.clusterId||child.workspaceId!==parent.workspaceId
        ||parent.kind!=='point'||parent.entityId!==child.parentId||parent.parentId!==undefined||parent.allowAbsent!==true||parent.required!==true
        ||!state.observedAbsences.has(this.key(parent))||!state.seen.has(this.key(parent))||state.seen.has(this.key(child))
        ||state.pendingRequests.size||parts.length!==4||parts[1]!==parent.entityId||parts[3]!==child.entityId
        ||!(parts[0]==='consumers'&&['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(parts[2])&&parent.path===`/consumers/${parent.entityId}`
          ||parts[0]==='upstreams'&&parts[2]==='targets'&&parent.path===`/upstreams/${parent.entityId}`))throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED');
      const current=await this.current(state.namespaceHandle,state.namespace,state.actorId,state.role,state.clusterId,state.paths,state.transaction,state.selectedResources);
      if(current.digest!==state.digest)throw denied('WORKFLOW_SCHEDULE_VALIDATION_FACTS_CHANGED');
      await this.parentAbsencePolicy.assertChild(current.input,child,parent);
      await this.verifyCompleteHandle(handle,state.namespaceHandle,state.namespace);
      if(state.pendingRequests.size||state.seen.has(this.key(child)))throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED');
      if(++state.records>state.proof.scope.limits.maxRecords)throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_BUDGET');
      state.observedAbsences.add(this.key(child));state.seen.add(this.key(child));
      const derived=Object.freeze({kind:'parent-FK-absence' as const,nativeRequestsSent:0 as const});this.absenceWitnesses.set(derived,{handle,resource:child,kind:'parent-FK-absence'});return derived;
    });
  }
  async runValidationRead<T>(namespaceHandle: object, clusterId: string, serverSelectedPaths: readonly string[], tx: DbService,
    fn: (originalReadHandle: object) => Promise<T>, options?: WorkflowScheduledValidationReadOptions): Promise<T> {
    return this.runSelectedRead(namespaceHandle,clusterId,serverSelectedPaths,tx,fn,options);
  }
  /** Selectors only locate current fixed SQL resources. Their complete HMA
   * is compared again on every original request; they confer no authority. */
  async runValidationResources<T>(namespaceHandle:object,clusterId:string,workspaceId:string,serverSelectedResources:readonly Readonly<WorkflowScheduleCandidateReadResource>[],tx:DbService,
    fn:(originalReadHandle:object)=>Promise<T>,options?:WorkflowScheduledValidationReadOptions):Promise<T>{
    if(!uuid.test(workspaceId)||!Array.isArray(serverSelectedResources)||!serverSelectedResources.length
      ||serverSelectedResources.some(r=>r.clusterId!==clusterId||r.workspaceId!==workspaceId))throw denied('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID');
    const selected=immutableJson(serverSelectedResources);
    return this.runSelectedRead(namespaceHandle,clusterId,selected.map(r=>r.path),tx,fn,options,selected);
  }
  private async runSelectedRead<T>(namespaceHandle:object,clusterId:string,serverSelectedPaths:readonly string[],tx:DbService,fn:((originalReadHandle:object)=>Promise<T>)|undefined,
    options?:WorkflowScheduledValidationReadOptions,selectedResources?:readonly Readonly<WorkflowScheduleCandidateReadResource>[],fixedReader?:Readonly<WorkflowScheduledValidationFixedReader>):Promise<T>{
    if (!this.runner) throw unavailable('WORKFLOW_SCHEDULE_VALIDATION_CONTEXT_UNAVAILABLE');
    if (!uuid.test(clusterId) || !Array.isArray(serverSelectedPaths) || !serverSelectedPaths.length || serverSelectedPaths.length > 500
      || serverSelectedPaths.some(path => typeof path !== 'string') || new Set(serverSelectedPaths).size !== serverSelectedPaths.length
      || options!==undefined&&(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(key=>!['role','userId'].includes(key)))
      || !tx || typeof tx.one !== 'function' || (fixedReader ? fn !== undefined : typeof fn !== 'function')) throw denied('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID');
    const namespace = this.runner.originalNamespaceProof(namespaceHandle), role = options?.role ?? 'executor', actorId = options?.userId ?? namespace.actor.id;
    if (!['executor', 'reviewer'].includes(role) || !uuid.test(actorId)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID');
    if (fixedReader && namespace.approvalSet.format !== 2) {
      // Legacy Namespace approval shapes retain every complete old check.
      // The fixed implementation is still the only callback, without fast mode.
      const original = fixedReader; fixedReader = undefined;
      fn = handle => original.read(handle, this.state(handle).proof) as unknown as Promise<T>;
    }
    const paths = Object.freeze([...serverSelectedPaths]);
    const parentFrame = fixedReader?.frame(namespaceHandle, namespace);
    const current = await this.current(namespaceHandle, namespace, actorId, role, clusterId, paths, tx,selectedResources);
    if (fixedReader && fixedReader.frame(namespaceHandle, namespace) !== parentFrame) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_FRAME_CHANGED');
    const expiresAt = Math.min(Date.now() + workflowScheduledValidationBudgetMs(current.input.plan.kind, current.scope), Date.parse(namespace.expiresAt));
    // Keep the exact original Namespace proof reference: JSON freezing the
    // entire object would clone it and erase the private Context association.
    const proof: Readonly<WorkflowScheduledValidationReadProof> = Object.freeze({ version: 1, origin: 'workflow-scheduled-validation-read', readOnly: true,
      actor: current.input.principal.user, sessionId: null, role, namespace, expiresAt: new Date(expiresAt).toISOString(), scope: current.scope,
      registries: immutableJson(current.registries.map(({ adminOrigin, ...registry }) => registry)) });
    const fixed: FixedGroupState | undefined = fixedReader ? { reader: fixedReader, parentFrame: parentFrame!, input: Object.freeze({ ...current.input }), executor: current.executor,
      registries: immutableJson(current.registries), phase: 'issued' } : undefined;
    const handle = Object.freeze({}), state: ReadState = { active: true, failed: false, namespaceHandle, namespace, actorId, role, clusterId, paths,selectedResources,fixed,
      plan: current.input.plan, digest: current.digest, proof, expiresAt, transaction: tx, cursors: new Map(), seen: new Set(),trueEofs:new Set(),presentPoints:new Set(),observedAbsences:new Set(),sdkObservedAbsences:new Set(),pendingRequests:new Set(), calls: 0, pages: 0, records: 0, bytes: 0 };
    this.handles.set(handle, state);
    if (fixed) try {
      const result = await this.runner.run(handle, namespaceHandle, async () => {
        if (fixed.phase !== 'entered') throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_PHASE_REQUIRED');
        fixed.readFrame = fixed.reader.frame(namespaceHandle, namespace, { handle, proof }); fixed.phase = 'reading'; this.assertFixedFrame(handle, state);
        // No caller-supplied callback or opaque handle is returned. The exact
        // fixed reader awaits every response before this phase can close.
        const result = immutableJson(await fixed.reader.read(handle, proof)); this.assertFixedFrame(handle, state);
        if (state.pendingRequests.size) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE');
        for (const resource of proof.scope.resources) if (resource.required !== false && (!state.seen.has(this.key(resource))
          || resource.kind === 'collection' && !state.cursors.get(this.key(resource))?.complete)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE');
        this.fixedResult(result, state); fixed.phase = 'closing';
        // Context's original final verifyHandle performs the complete closing
        // current, then its synchronous ancestry fence, before releasing this.
        return result;
      });
      if (fixed.phase !== 'sealed' || fixed.reader.frame(namespaceHandle, namespace) !== fixed.parentFrame)
        throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_NOT_CLOSED');
      this.assertLive(handle); return result as unknown as T;
    } finally { state.active = false; this.handles.delete(handle); }
    try { return await this.runner.run(handle, namespaceHandle, async () => {
      await this.verifyHandle(handle, namespaceHandle, namespace); const result = await fn!(handle); await this.verifyHandle(handle, namespaceHandle, namespace);
      if(state.pendingRequests.size)throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE');
      for (const resource of state.proof.scope.resources) if (resource.required !== false && (!state.seen.has(this.key(resource))
        || resource.kind === 'collection' && !state.cursors.get(this.key(resource))?.complete)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE');
      return result;
    }); } finally { state.active = false; this.handles.delete(handle); }
  }
  private fixedResult(result: Readonly<WorkflowScheduledValidationFixedResult>, state: ReadState): void {
    if (!result || Object.keys(result).some(key => !['observations', 'usage', 'inferredRecords'].includes(key)) || !Array.isArray(result.observations)
      || !result.usage || Object.keys(result.usage).length !== 4 || Object.keys(result.usage).some(key => !['calls', 'pages', 'records', 'bytes'].includes(key))
      || Object.values(result.usage).some(value => !Number.isSafeInteger(value) || value < 0)
      || !Number.isSafeInteger(result.inferredRecords) || result.inferredRecords < 0) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_RESULT_INVALID');
    const seen = new Set<string>();
    for (const observation of result.observations) {
      if (!observation || Object.keys(observation).some(key => !['resource', 'value', 'absence'].includes(key)) || !Object.hasOwn(observation, 'value')
        || observation.absence !== undefined && !['sdk404', 'parent-FK-absence'].includes(observation.absence)
        || !state.proof.scope.resources.some(resource => this.secrets.fingerprint(resource) === this.secrets.fingerprint(observation.resource))) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_RESULT_INVALID');
      const key = this.key(observation.resource); if (seen.has(key)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FIXED_RESULT_INVALID'); seen.add(key);
    }
  }
  async authorizeRequest(originalReadHandle: object, request: WorkflowScheduleCandidateRequest): Promise<object> {
    const state = this.state(originalReadHandle); return this.checked(state, async () => {
    request = immutableJson(request);
    await this.verifyHandle(originalReadHandle, state.namespaceHandle, state.namespace);
    if (request.method !== 'GET' || request.body !== undefined) throw denied('WORKFLOW_SCHEDULE_VALIDATION_GET_ONLY');
    const resource = state.proof.scope.resources.find(r => r.clusterId === request.clusterId && r.workspaceId === request.workspaceId && r.path === request.path);
    if (!resource) throw denied('WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN'); assertKongPath('GET', request.path); validateQuery(request.query as Record<string, string | number>);
    const key = this.key(resource);
    if (resource.kind === 'collection') {
      const cursor = state.cursors.get(key) ?? { started: false, complete: false, pending: false, next: null, offsets: new Set<string>(), ids: new Set<string>() };
      const expected = { ...resource.query, ...(cursor.started ? { offset: cursor.next } : {}) };
      if (cursor.pending || cursor.complete || this.secrets.fingerprint(request.query) !== this.secrets.fingerprint(expected)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_CURSOR_INVALID');
      if (cursor.started && (!cursor.next || cursor.offsets.has(cursor.next))) throw denied('WORKFLOW_SCHEDULE_VALIDATION_CURSOR_INVALID');
      if (cursor.next) cursor.offsets.add(cursor.next); cursor.pending = true; state.cursors.set(key, cursor);
    } else if (Object.keys(request.query).length) throw denied('WORKFLOW_SCHEDULE_VALIDATION_QUERY_FORBIDDEN');
    if (++state.calls > state.proof.scope.limits.maxCalls) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_BUDGET');
    const token = Object.freeze({}); this.requests.set(token, { handle: originalReadHandle, state, resource, request, active: true });state.pendingRequests.add(token); return token;
    });
  }
  async verifyRequest(originalRequestToken: object): Promise<Readonly<WorkflowScheduledValidationReadProof>> {
    const request = originalRequestToken && this.requests.get(originalRequestToken);
    if (!request?.active || request.state !== this.state(request.handle)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUEST_REQUIRED');
    return this.checked(request.state, async () => {
    const proof = await this.verifyHandle(request.handle, request.state.namespaceHandle, request.state.namespace);
    if (!request.active || request.state !== this.state(request.handle) || request.request.method !== 'GET'
      || !proof.scope.resources.some(r => this.key(r) === this.key(request.resource))) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUEST_REQUIRED');
    return proof;
    });
  }
  async authorizeResponse(originalRequestToken: object, response: unknown, originalAbsenceObservation?:200|object): Promise<unknown> {
    const request = originalRequestToken && this.requests.get(originalRequestToken);
    if (!request?.active) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUEST_REQUIRED');
    const { state, resource, handle } = request; return this.checked(state, async () => {
    this.assertLive(handle); if (state !== this.state(handle)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_HANDLE_REQUIRED');
    let status=200;
    if(originalAbsenceObservation!==undefined&&originalAbsenceObservation!==200){
      if(!this.absentResponseVerifier||!originalAbsenceObservation||typeof originalAbsenceObservation!=='object'||Array.isArray(originalAbsenceObservation))throw denied('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_OBSERVATION_REQUIRED');
      const observed=this.absentResponseVerifier.verifyOriginalResponse(originalRequestToken,originalAbsenceObservation);
      if(observed.status!==404||observed.response!==response)throw denied('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_OBSERVATION_REQUIRED');status=404;
    }
    request.active=false;this.requests.delete(originalRequestToken);state.pendingRequests.delete(originalRequestToken);
    const absent=status===404&&resource.kind==='point'&&resource.allowAbsent===true;
    if(status!==200&&!absent)throw denied('WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID');
    const scoped=state.proof.scope.domain==='scoped-points-v1',scopedWitness=!resource.parentId||state.proof.scope.resources.some(r=>r.entityId===resource.parentId
      &&r.clusterId===resource.clusterId&&r.workspaceId===resource.workspaceId&&r.kind==='point'&&state.presentPoints.has(this.key(r)));
    if(absent&&(!isKongPointNotFound(response)||!isServiceHostReferencePoint(resource)&&!(scoped?scopedWitness:hasObservedAbsenceWitness(resource,state.proof.scope.resources,state.trueEofs,state.presentPoints,state.cursors,state.observedAbsences))))throw denied('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_WITNESS_REQUIRED');
    const raw = immutableJson(response), key = this.key(resource), data = (raw as any)?.data;
    const bytes = state.bytes + Buffer.byteLength(JSON.stringify(raw ?? null));
    let pages = state.pages, records = state.records, next: string | null = null, nextIds: Set<string> | undefined;
    // A non-secret scope cannot return private material merely because the
    // provider mislabeled a credential/plugin/certificate response. Marking
    // secrets=true still requires the actual per-object secret grant callback.
    if (resource.kind !== 'schema' && !resource.secrets && this.secrets.fingerprint(this.secrets.redact(raw)) !== this.secrets.fingerprint(raw))
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_SECRET_SCOPE_REQUIRED');
    if (resource.kind === 'point' && !absent && (!raw || (isServiceHostReferencePoint(resource)?!uuid.test((raw as any).id??'')||(raw as any).name!==resource.serviceHostReference!.host:(raw as any).id !== resource.entityId))) throw denied('WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID');
    if (resource.kind === 'collection') {
      const cursor = state.cursors.get(key); if (!cursor?.pending || !Array.isArray(data) || data.length > resource.query!.size || !Object.hasOwn(raw as object, 'next')) throw denied('WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID');
      pages++; records += data.length; nextIds = new Set(cursor.ids);
      for (const row of data) { if (!row || !uuid.test(row.id ?? '') || nextIds.has(row.id)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_DUPLICATE_ENTITY'); nextIds.add(row.id); }
      if ((raw as any).next !== null) {
        if (typeof (raw as any).next !== 'string') throw denied('WORKFLOW_SCHEDULE_VALIDATION_CURSOR_INVALID');
        const registry = state.proof.registries.find(r => r.clusterId === resource.clusterId && r.workspaceId === resource.workspaceId)!;
        const cluster = await (state.transaction ?? this.db).one<any>('SELECT admin_url FROM clusters WHERE id=$1 AND deleted_at IS NULL', [registry.clusterId]);
        const base = new URL(cluster.admin_url), url = new URL((raw as any).next, base);
        if (url.origin !== base.origin || url.pathname !== resource.path || [...url.searchParams.keys()].some(k => !['offset', 'size', 'tags'].includes(k) || url.searchParams.getAll(k).length !== 1)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_CURSOR_INVALID');
        next = url.searchParams.get('offset'); if (!next || next.length > 8192 || cursor.offsets.has(next)) throw denied('WORKFLOW_SCHEDULE_VALIDATION_CURSOR_INVALID');
        if (url.searchParams.has('size') && Number(url.searchParams.get('size')) !== resource.query!.size || url.searchParams.has('tags') && url.searchParams.get('tags') !== resource.query!.tags) throw denied('WORKFLOW_SCHEDULE_VALIDATION_CURSOR_INVALID');
      }
    }
    if (pages > state.proof.scope.limits.maxPages || records > state.proof.scope.limits.maxRecords || bytes > state.proof.scope.limits.maxBytes) throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_BUDGET');
    const lookup = (tx: DbService) => this.current(state.namespaceHandle, state.namespace, state.actorId, state.role, state.clusterId, state.paths, tx,state.selectedResources);
    if (state.fixed) await this.verifyFixedCurrent(handle, state);
    const current = state.fixed ? { input: state.fixed.input, digest: state.digest }
      : state.transaction ? await lookup(state.transaction) : await this.db.transaction(lookup);
    if (current.digest !== state.digest) throw denied('WORKFLOW_SCHEDULE_VALIDATION_FACTS_CHANGED');
    await this.policy(state.plan.kind).authorizeResponse({ ...current.input, resource, response: raw, status });
    this.assertLive(handle); await this.verifyHandle(handle, state.namespaceHandle, state.namespace);
    if (resource.kind === 'collection') {
      const cursor = state.cursors.get(key)!;
      cursor.pending = false; cursor.started = true; cursor.complete = next === null; cursor.next = next; cursor.ids = nextIds!;
      if((raw as any).next===null)state.trueEofs.add(key);
    }
    if(resource.kind==='point'&&!absent)state.presentPoints.add(key);
    if(absent){state.observedAbsences.add(key);state.sdkObservedAbsences.add(key);if(isServiceHostReferencePoint(resource)){const values=this.serviceHostAbsences.get(handle)??new Map<string,unknown>();values.set(key,raw);this.serviceHostAbsences.set(handle,values);}}
    state.pages = pages; state.records = records; state.bytes = bytes; state.seen.add(key);
    return resource.kind === 'schema' ? stripSensitiveSchemaDefaults(raw, this.secrets) : raw;
    });
  }
}
