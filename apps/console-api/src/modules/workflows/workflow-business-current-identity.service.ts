import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import { AsyncLocalStorage } from 'node:async_hooks';
import { ConflictException, ForbiddenException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowScheduleRepository, assertWorkflowScheduledPlan } from './workflow-schedule.repository';
import { WorkflowCandidatesService } from './workflow-candidates.service';
import { WorkflowScheduledValidationReadService } from './workflow-scheduled-validation-read.service';
import { normalizeWorkflowApprovalPolicy } from './workflow-approval-policy';
import type { AuthUser } from '../../common/auth';
import type { WorkflowCandidateManifest } from './workflow-approval.types';
import type { WorkflowScheduleStored } from './workflow-schedule.contract';
import type { WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { WorkflowScheduledCurrentIdentityBridge } from '../authorization/authorization.service';

export const WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256 = 'a447e5027a9045d2bd72795ed1892de96f1d01a068960cfe03b41f5ca0f46ca4';
const denied = (code: string) => new ForbiddenException({ code });
const changed = (code: string) => new ConflictException({ code });
const unavailable = (code: string) => new ServiceUnavailableException({ code });
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const epochValue = (value: unknown) => /^[1-9]\d*$/.test(String(value ?? ''));
interface Principal { readonly user: Readonly<AuthUser>; readonly credentialEpoch: string; readonly permissionVersion: string }
type Identity = Awaited<ReturnType<WorkflowScheduledCurrentIdentityBridge['currentPrincipal']>>;

/** Root installs this SQL-only observer in AuthorizationService once.
 * Original Context/validation handles are the authority anchor. No HTTP SID,
 * Native permit, business callback, grant substitution or runtime is installed.
 * Genuine readonly reviewer capsules retain their own frozen identity digest. */
@Injectable()
export class WorkflowBusinessCurrentIdentityService implements WorkflowScheduledCurrentIdentityBridge {
  private readonly active = new AsyncLocalStorage<true>();
  constructor(private readonly db: DbService, private readonly secrets: SecretService,
    private readonly context: KongExecutionContextService, private readonly redis: RedisService,
    private readonly repository: WorkflowScheduleRepository, private readonly plans: WorkflowPlansService,
    private readonly candidates: WorkflowCandidatesService, private readonly validation: WorkflowScheduledValidationReadService) {}

  private async principal(actorId: string, tx: DbService): Promise<Readonly<Principal>> {
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const row = await tx.one<any>(`SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
      FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`, [actorId]);
    if (!row || row.id !== actorId || !epoch || row.force_password_change || typeof row.username !== 'string' || !row.username
      || !epochValue(row.credential_epoch) || !epochValue(row.permissions_epoch) || !epochValue(epoch.version))
      throw denied('WORKFLOW_BUSINESS_IDENTITY_PRINCIPAL_REVOKED');
    return immutableJson({ user: { id: row.id, username: row.username, superAdmin: row.super_admin === true, forcePasswordChange: false,
      displayName: row.display_name, locale: row.locale, timezone: row.timezone, revision: row.revision },
      credentialEpoch: String(row.credential_epoch), permissionVersion: `${row.id}:${row.permissions_epoch}:${epoch.version}` });
  }
  /** Close the last validator-to-observer gap with SQL facts that do not
   * necessarily bump the IAM epoch, while retaining the exact old Namespace. */
  private async readonlyAnchorTail(namespace: Readonly<WorkflowScheduledNamespaceProof>, tx: DbService): Promise<void> {
    const stored = await this.repository.inspectStored(namespace.claim.scheduleId, tx), { draft, plan, claim, latestLease } = stored;
    assertWorkflowScheduledPlan(plan, draft, this.secrets);
    const b = draft.binding;
    if (this.secrets.fingerprint(plan) !== namespace.workflow.planHash || !claim || claim.id !== namespace.claim.id || claim.generation !== 1
      || !latestLease || latestLease.version !== 1 || latestLease.generation !== 1 || latestLease.previousId !== null
      || latestLease.workerOwnerHmac !== namespace.claim.workerOwnerHmac || latestLease.claimId !== claim.id || latestLease.leaseUntil !== namespace.claim.initialLeaseUntil
      || !['claimed', 'running'].includes(stored.progress.state) || stored.progress.claimId !== claim.id)
      throw changed('WORKFLOW_BUSINESS_IDENTITY_CLAIM_CHANGED');
    if (this.secrets.fingerprint(await this.plans.definition(plan.clusterId, plan.workspaceId, plan.kind, tx)) !== this.secrets.fingerprint(plan.definition))
      throw changed('WORKFLOW_BUSINESS_IDENTITY_POLICY_CHANGED');
    if (b.requester.type === 'developer') {
      const row = await tx.one<any>(`SELECT id,credential_epoch,must_change_password FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
        AND status='active' AND deleted_at IS NULL AND NOT must_change_password`, [b.requester.id, b.clusterId, b.workspaceId]);
      if (!row || row.id !== b.requester.id || row.must_change_password || String(row.credential_epoch) !== b.requester.credentialEpoch)
        throw denied('WORKFLOW_BUSINESS_IDENTITY_REQUESTER_REVOKED');
    }
    const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [b.clusterId]);
    const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [b.workspaceId, b.clusterId]);
    if (!cluster || !workspace || cluster.id !== namespace.clusterId || workspace.id !== namespace.workspaceId || workspace.cluster_id !== namespace.clusterId
      || ['disabled', 'incompatible'].includes(cluster.status) || !isSupportedKong(cluster.version ?? '') || workspace.status !== 'active'
      || cluster.revision !== namespace.clusterRevision || workspace.revision !== namespace.workspaceRevision || cluster.execution_mode !== plan.executionMode
      || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== namespace.transportScope)
      throw changed('WORKFLOW_BUSINESS_IDENTITY_SCOPE_CHANGED');
  }
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
      throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    const stages = await tx.query<any>('SELECT * FROM workflow_stages WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision]);
    const votes = await tx.query<any>('SELECT * FROM workflow_approvals WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level,approver_id,id', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision]);
    const actual = votes.map(v => ({ approvalId: v.id, userId: v.approver_id, level: v.level, candidateVersion: v.candidate_version ?? null }));
    if (this.secrets.fingerprint(actual) !== this.secrets.fingerprint(set.reviewers) || votes.some(v => v.plan_hash !== hash || v.decision !== 'approve'
      || p.requester.type === 'console' && v.approver_id === p.requester.id) || stages.some(s => s.plan_hash !== hash || s.state !== 'approved'
      || votes.filter(v => v.level === s.level).length !== s.required_approvals)) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    const policy = normalizeWorkflowApprovalPolicy(definition.policy, p.kind);
    const candidateVersion = await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision, row.candidate_version]);
    const manifest: WorkflowCandidateManifest | undefined = candidateVersion?.manifest;
    if (!manifest || manifest.version !== 1 || manifest.clusterId !== p.clusterId || manifest.workspaceId !== p.workspaceId || manifest.workflowId !== p.workflowId
      || manifest.planRevision !== p.planRevision || manifest.planHash !== hash || manifest.definitionId !== p.definition.id || manifest.definitionVersion !== p.definition.version
      || manifest.policyHash !== p.definition.policyHash || manifest.candidateVersion !== row.candidate_version || candidateVersion.manifest_hmac !== row.candidate_manifest_hmac
      || this.secrets.fingerprint(manifest) !== row.candidate_manifest_hmac || manifest.stages.length !== policy.stages.length || stages.length !== policy.stages.length
      || policy.distinctAcrossStages && new Set(votes.map(v => v.approver_id)).size !== votes.length) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    const candidates = await tx.query<any>('SELECT * FROM workflow_candidates WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5 ORDER BY level,user_id', [p.workflowId, p.clusterId, p.workspaceId, p.planRevision, row.candidate_version]);
    const expected = manifest.stages.flatMap(stage => stage.candidates.map(candidate => ({ level: stage.level, ...candidate })));
    if (candidates.length !== expected.length || candidates.some((c, i) => c.plan_hash !== hash || c.manifest_hmac !== row.candidate_manifest_hmac || c.level !== expected[i].level
      || c.user_id !== expected[i].userId || String(c.credential_epoch) !== expected[i].credentialEpoch || this.secrets.fingerprint(c.provenance) !== this.secrets.fingerprint(expected[i].provenance))) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    for (const [i, stage] of stages.entries()) {
      const frozen = manifest.stages[i], rule = policy.stages[i];
      if (stage.level !== i + 1 || stage.approval_format !== 2 || stage.candidate_version !== row.candidate_version || stage.candidate_manifest_hmac !== row.candidate_manifest_hmac
        || stage.stage_mode !== frozen.mode || frozen.mode !== rule.mode || stage.required_approvals !== frozen.threshold
        || frozen.threshold !== (rule.mode === 'all' ? frozen.candidates.length : rule.threshold)) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    }
    for (const vote of votes) {
      const candidate = manifest.stages.find(stage => stage.level === vote.level)?.candidates.find(c => c.userId === vote.approver_id);
      if (!candidate || vote.candidate_version !== row.candidate_version || vote.candidate_manifest_hmac !== row.candidate_manifest_hmac) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
      await this.candidates.assertCurrent(p, candidate, tx);
    }
    const sqlSet = await tx.one<any>('SELECT * FROM workflow_approval_sets WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6', [set.setId, p.clusterId, p.workspaceId, p.workflowId, p.planRevision, hash]);
    const material = { version: 1, clusterId: p.clusterId, workspaceId: p.workspaceId, workflowId: p.workflowId, planRevision: p.planRevision, planHash: hash,
      policyHash: p.definition.policyHash, candidateVersion: row.candidate_version, candidateManifestHmac: row.candidate_manifest_hmac, reviewers: actual };
    if (!sqlSet || row.approval_set_id !== set.setId || row.approval_set_hmac !== set.setHmac || sqlSet.set_hmac !== set.setHmac
      || this.secrets.fingerprint(sqlSet.manifest) !== set.setHmac || this.secrets.fingerprint(material) !== set.setHmac
      || !actual.some(v => v.userId === row.approved_by && v.level === stages.length)) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    const members = await tx.query<any>('SELECT * FROM workflow_approval_set_members WHERE set_id=$1 ORDER BY level,user_id,approval_id', [set.setId]);
    if (members.length !== actual.length || members.some((m, i) => m.cluster_id !== p.clusterId || m.workspace_id !== p.workspaceId || m.workflow_id !== p.workflowId
      || m.plan_revision !== p.planRevision || m.plan_hash !== hash || m.set_hmac !== set.setHmac || m.approval_id !== actual[i].approvalId || m.user_id !== actual[i].userId
      || m.level !== actual[i].level || m.candidate_version !== row.candidate_version || m.candidate_manifest_hmac !== row.candidate_manifest_hmac)
      || await tx.one('SELECT id FROM workflow_approval_invalidations WHERE set_id=$1 LIMIT 1', [set.setId])) throw changed('WORKFLOW_BUSINESS_IDENTITY_APPROVAL_CHANGED');
    const reviewers: Principal[] = [];
    for (const reviewer of set.reviewers) reviewers.push(await this.principal(reviewer.userId, tx));
    return { stages, votes, manifest: manifest ?? null, reviewers };
  }

  async currentPrincipal(originalNamespaceHandle: object, originalNamespaceProof: Readonly<WorkflowScheduledNamespaceProof>,
    actualActorId: string, transaction: DbService = this.db): Promise<Identity> {
    if (this.active.getStore()) throw denied('WORKFLOW_BUSINESS_IDENTITY_REENTRANT');
    if (!originalNamespaceHandle || typeof originalNamespaceHandle !== 'object' || Array.isArray(originalNamespaceHandle)
      || !originalNamespaceProof || !uuid.test(actualActorId ?? '') || !transaction || typeof transaction.one !== 'function' || typeof transaction.query !== 'function')
      throw denied('WORKFLOW_BUSINESS_IDENTITY_ORIGINAL_REQUIRED');
    const frame = this.context.current(), original = this.context.requireWorkflowScheduledCurrentPrincipal(originalNamespaceHandle);
    if (original.namespace !== originalNamespaceProof || original.actor.id !== actualActorId || frame.sessionId != null
      || !['executor', 'reviewer'].includes(original.role) || original.role === 'reviewer' && (!original.readOnly || !original.validationReadHandle)
      || original.readOnly !== !!original.validationReadHandle)
      throw denied('WORKFLOW_BUSINESS_IDENTITY_ORIGINAL_REQUIRED');
    const assertCurrent = () => {
      const current = this.context.requireWorkflowScheduledCurrentPrincipal(originalNamespaceHandle);
      if (this.context.current() !== frame || current.namespace !== originalNamespaceProof || current.actor !== original.actor
        || current.role !== original.role || current.readOnly !== original.readOnly || current.validationReadHandle !== original.validationReadHandle
        || current.actor.id !== actualActorId || frame.sessionId != null) throw denied('WORKFLOW_BUSINESS_IDENTITY_FRAME_CHANGED');
      this.redis.assertLeaseActive();
    };
    const observed = async <T>(fn: () => Promise<T>): Promise<T> => {
      assertCurrent(); await this.redis.assertLeaseOwnership(); assertCurrent();
      const value = await fn(); assertCurrent(); await this.redis.assertLeaseOwnership(); assertCurrent(); return value;
    };
    // All dependent repository/candidate reads stay in the actual transaction
    // and each SQL await receives real Context and Redis ownership fences.
    const tx = new Proxy(transaction, { get: (target, key) => {
      if (key === 'one' || key === 'query') return (sql: string, args?: any[]) => {
        if (typeof sql !== 'string' || !/^\s*SELECT\b/i.test(sql)) throw denied('WORKFLOW_BUSINESS_IDENTITY_SQL_READ_ONLY');
        return observed(() => (target[key] as any).call(target, sql, args));
      };
      if (key === 'exec' || key === 'transaction') return () => { throw denied('WORKFLOW_BUSINESS_IDENTITY_SQL_READ_ONLY'); };
      return Reflect.get(target, key);
    } }) as DbService;
    return this.active.run(true, async () => {
      const ns = originalNamespaceProof;
      assertCurrent();
      // Background identity requires the durable frozen candidate epochs and
      // set membership introduced by format 2. Existing HTTP/V1 flows are
      // untouched; an old single-vote shape cannot lend missing epoch proof.
      if (ns.approvalSet.format !== 2 || !uuid.test(ns.approvalSet.setId ?? '') || !/^[a-f\d]{64}$/.test(ns.approvalSet.setHmac ?? ''))
        throw denied('WORKFLOW_BUSINESS_IDENTITY_FROZEN_APPROVAL_REQUIRED');
      const checkValidation = async () => {
        if (!original.validationReadHandle) return;
        const read = await observed(() => this.validation.verifyHandle(original.validationReadHandle!, originalNamespaceHandle, ns));
        if (read.namespace !== ns || read.actor !== original.actor || read.actor.id !== actualActorId || read.role !== original.role || read.readOnly !== true || read.sessionId !== null)
          throw denied('WORKFLOW_BUSINESS_IDENTITY_VALIDATION_CHANGED');
      };
      await checkValidation();
      const migration = await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='026_m11_workflow_schedules.sql'");
      if (migration?.checksum !== WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256) throw unavailable('WORKFLOW_BUSINESS_IDENTITY_STORAGE_UNAVAILABLE');
      const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
      if (!epoch || !epochValue(epoch.version)) throw unavailable('AUTHORIZATION_UNAVAILABLE');
      if (original.validationReadHandle) {
        // Its private validator independently repeats the complete SQL026,
        // claim/window/approval/candidate and reviewer identity digest checks.
        // Reusing that original keeps the reviewer's frozen PV/epoch, rather
        // than comparing a reviewer with the executor's Namespace version.
        const principal = await this.principal(actualActorId, tx);
        if (this.secrets.fingerprint(principal.user) !== this.secrets.fingerprint(original.actor))
          throw denied('WORKFLOW_BUSINESS_IDENTITY_PRINCIPAL_CHANGED');
        await checkValidation();
        const after = await this.principal(actualActorId, tx);
        if (this.secrets.fingerprint(after) !== this.secrets.fingerprint(principal))
          throw denied('WORKFLOW_BUSINESS_IDENTITY_PERMISSIONS_CHANGED');
        await checkValidation();
        await observed(() => this.readonlyAnchorTail(ns, tx));
        if (this.secrets.fingerprint(await this.principal(actualActorId, tx)) !== this.secrets.fingerprint(principal))
          throw denied('WORKFLOW_BUSINESS_IDENTITY_PERMISSIONS_CHANGED');
        assertCurrent();
        return Object.freeze({ actorId: actualActorId, credentialEpoch: principal.credentialEpoch, permissionVersion: principal.permissionVersion,
          role: original.role, readOnly: true });
      }
      const stored = await observed(() => this.repository.inspectStored(ns.claim.scheduleId, tx));
      const { plan, draft, claim, latestLease } = stored;
      assertWorkflowScheduledPlan(plan, draft, this.secrets);
      // inspectStored already authenticated and decrypted the exact sealed
      // version. Generic Plans.load may dispatch its business-origin policy;
      // identity observation must never recurse through that callback.
      const loaded = await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',
        [plan.workflowId, plan.clusterId, plan.workspaceId]);
      const d = draft.delegation, b = draft.binding, now = Date.now();
      const claimProjection = claim && { ...claim, clusterId: b.clusterId, workspaceId: b.workspaceId, ownerId: d.ownerId, executorId: d.executorId,
        ownerCredentialEpoch: d.ownerCredentialEpoch, executorCredentialEpoch: d.executorCredentialEpoch, delegationId: d.id, delegationVersion: 1,
        delegationHmac: draft.delegationHmac, specHmac: draft.specHmac, windowStart: draft.spec.windowStart, windowEnd: draft.spec.windowEnd,
        impactHmac: draft.impactHmac, subjectSealHmac: d.subjectSealHmac };
      // This Namespace froze the original SQL lease version 1 and deadline.
      // A later SQL lease cannot extend its private authority implicitly;
      // renewed SQL leases need a separate verified Namespace adapter. Redis
      // ownership renewal remains independent of this fail-closed boundary.
      if (!claim || !latestLease || !stored.activation || !['claimed', 'running'].includes(stored.progress.state) || stored.progress.claimId !== claim.id
        || this.secrets.fingerprint(claimProjection) !== this.secrets.fingerprint(ns.claim) || claim.generation !== 1 || claim.scheduleVersion !== 1
        || latestLease.claimId !== claim.id || latestLease.generation !== 1 || latestLease.workerOwnerHmac !== claim.workerOwnerHmac
        || latestLease.version !== 1 || latestLease.previousId !== null || latestLease.leaseUntil !== claim.initialLeaseUntil
        || !loaded || !['approved', 'executing'].includes(loaded.state) || loaded.plan_revision !== plan.planRevision || loaded.plan_hash !== b.workflowPlanHash
        || ns.version !== 1 || ns.origin !== 'scheduled-workflow' || ns.sessionId !== null || ns.clusterId !== b.clusterId || ns.workspaceId !== b.workspaceId
        || ns.kind !== plan.kind || !['configuration_v2', 'portal-credential-issue', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'].includes(plan.kind) || ns.actor.id !== d.executorId || d.ownerId !== d.executorId
        || draft.spec.executorId !== d.executorId || d.ownerCredentialEpoch !== d.executorCredentialEpoch || ns.credentialEpoch !== d.executorCredentialEpoch
        || ns.transportScope !== draft.transportScope || ns.clusterRevision !== plan.scope.clusterRevision || ns.workspaceRevision !== plan.scope.workspaceRevision
        || this.secrets.fingerprint(ns.workflow) !== this.secrets.fingerprint({ id: plan.workflowId, planRevision: plan.planRevision, planHash: b.workflowPlanHash })
        || this.secrets.fingerprint(ns.requester) !== this.secrets.fingerprint(b.requester) || ns.subjectSealHmac !== d.subjectSealHmac)
        throw changed('WORKFLOW_BUSINESS_IDENTITY_CLAIM_CHANGED');
      const deadlines = [ns.expiresAt, claim.authorityExpiresAt, latestLease.leaseUntil, plan.expiresAt, d.expiresAt, draft.spec.windowEnd].map(Date.parse);
      if (deadlines.some(t => !Number.isFinite(t) || t <= now) || !Number.isFinite(Date.parse(draft.spec.notBefore)) || !Number.isFinite(Date.parse(draft.spec.windowStart))
        || now < Date.parse(draft.spec.notBefore) || now < Date.parse(draft.spec.windowStart)) throw denied('WORKFLOW_BUSINESS_IDENTITY_EXPIRED');
      const definition = await observed(() => this.plans.definition(plan.clusterId, plan.workspaceId, plan.kind, tx));
      if (this.secrets.fingerprint(definition) !== this.secrets.fingerprint(plan.definition))
        throw changed('WORKFLOW_BUSINESS_IDENTITY_POLICY_CHANGED');
      const executor = await this.principal(d.executorId, tx);
      if (executor.credentialEpoch !== d.executorCredentialEpoch || executor.permissionVersion !== ns.permissionVersion
        || this.secrets.fingerprint(executor.user) !== this.secrets.fingerprint(ns.actor)) throw denied('WORKFLOW_BUSINESS_IDENTITY_EXECUTOR_REVOKED');
      const requesterSql = `SELECT id,credential_epoch,must_change_password FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
        AND status='active' AND deleted_at IS NULL AND NOT must_change_password`;
      const requester = b.requester.type === 'developer' ? await tx.one<any>(requesterSql, [b.requester.id, b.clusterId, b.workspaceId]) : null;
      if (b.requester.type === 'developer') {
        if (!requester || requester.id !== b.requester.id || requester.must_change_password || String(requester.credential_epoch) !== b.requester.credentialEpoch || plan.kind !== 'portal-credential-issue')
          throw denied('WORKFLOW_BUSINESS_IDENTITY_REQUESTER_REVOKED');
      } else if (plan.kind !== 'configuration_v2' || b.requester.id !== d.executorId || b.requester.credentialEpoch !== executor.credentialEpoch)
        throw denied('WORKFLOW_BUSINESS_IDENTITY_REQUESTER_REVOKED');
      await this.approvalFacts(stored, ns, tx);
      const activation = { workflowId: plan.workflowId, workflowPlanRevision: plan.planRevision, workflowPlanHash: b.workflowPlanHash,
        approvalFormat: ns.approvalSet.format, approvalRequired: true, approvalSetId: ns.approvalSet.setId, approvalSetHmac: ns.approvalSet.setHmac };
      if (this.secrets.fingerprint(stored.activation) !== this.secrets.fingerprint(activation)
        || original.role === 'executor' && actualActorId !== d.executorId
        || original.role === 'reviewer' && !ns.approvalSet.reviewers.some(r => r.userId === actualActorId)) throw denied('WORKFLOW_BUSINESS_IDENTITY_PRINCIPAL_REQUIRED');
      const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [b.clusterId]);
      const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [b.workspaceId, b.clusterId]);
      const registryFacts = (c: any, w: any) => ({ cluster: c ? { id: c.id, version: c.version, revision: c.revision, executionMode: c.execution_mode,
        status: c.status, deletedAt: c.deleted_at, adminUrl: c.admin_url, transportScope: c.transport_scope, connectionSecret: c.connection_secret } : null,
        workspace: w ? { id: w.id, clusterId: w.cluster_id, revision: w.revision, status: w.status, deletedAt: w.deleted_at, code: w.code } : null });
      if (!cluster || !workspace || cluster.id !== b.clusterId || workspace.id !== b.workspaceId || workspace.cluster_id !== b.clusterId
        || ['disabled', 'incompatible'].includes(cluster.status) || !isSupportedKong(cluster.version ?? '') || workspace.status !== 'active'
        || cluster.revision !== ns.clusterRevision || workspace.revision !== ns.workspaceRevision || cluster.execution_mode !== plan.executionMode
        || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== ns.transportScope) throw changed('WORKFLOW_BUSINESS_IDENTITY_SCOPE_CHANGED');
      const principal = original.role === 'executor' ? executor : await this.principal(actualActorId, tx);
      if (this.secrets.fingerprint(principal.user) !== this.secrets.fingerprint(original.actor)) throw denied('WORKFLOW_BUSINESS_IDENTITY_PRINCIPAL_CHANGED');
      await checkValidation();
      const after = await this.principal(actualActorId, tx), afterEpoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
      if (String(epoch.version) !== String(afterEpoch?.version) || this.secrets.fingerprint(after) !== this.secrets.fingerprint(principal))
        throw denied('WORKFLOW_BUSINESS_IDENTITY_PERMISSIONS_CHANGED');
      const finalStored = await observed(() => this.repository.inspectStored(ns.claim.scheduleId, tx));
      const finalLoaded = await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',
        [plan.workflowId, plan.clusterId, plan.workspaceId]);
      if (this.secrets.fingerprint(finalStored) !== this.secrets.fingerprint(stored)
        || !finalLoaded || finalLoaded.plan_revision !== plan.planRevision || finalLoaded.plan_hash !== b.workflowPlanHash
        || !['approved', 'executing'].includes(finalLoaded.state)) throw changed('WORKFLOW_BUSINESS_IDENTITY_CLAIM_CHANGED');
      await this.approvalFacts(finalStored, ns, tx);
      const finalDefinition = await observed(() => this.plans.definition(plan.clusterId, plan.workspaceId, plan.kind, tx));
      if (this.secrets.fingerprint(finalDefinition) !== this.secrets.fingerprint(definition)) throw changed('WORKFLOW_BUSINESS_IDENTITY_POLICY_CHANGED');
      if (b.requester.type === 'developer' && this.secrets.fingerprint(await tx.one<any>(requesterSql, [b.requester.id, b.clusterId, b.workspaceId])) !== this.secrets.fingerprint(requester))
        throw denied('WORKFLOW_BUSINESS_IDENTITY_REQUESTER_REVOKED');
      const finalCluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [b.clusterId]);
      const finalWorkspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [b.workspaceId, b.clusterId]);
      if (this.secrets.fingerprint(registryFacts(finalCluster, finalWorkspace)) !== this.secrets.fingerprint(registryFacts(cluster, workspace)))
        throw changed('WORKFLOW_BUSINESS_IDENTITY_SCOPE_CHANGED');
      if (deadlines.some(t => t <= Date.now())) throw denied('WORKFLOW_BUSINESS_IDENTITY_EXPIRED');
      if (this.secrets.fingerprint(await this.principal(actualActorId, tx)) !== this.secrets.fingerprint(principal))
        throw denied('WORKFLOW_BUSINESS_IDENTITY_PERMISSIONS_CHANGED');
      await checkValidation(); assertCurrent();
      return Object.freeze({ actorId: actualActorId, credentialEpoch: principal.credentialEpoch, permissionVersion: principal.permissionVersion,
        role: original.role, readOnly: original.readOnly });
    });
  }
}
