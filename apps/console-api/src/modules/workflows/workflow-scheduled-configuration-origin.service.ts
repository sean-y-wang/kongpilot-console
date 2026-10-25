import { ConfigurationDurableRepository, configurationDurableMarker } from '../configuration/configuration-durable.repository';
import { configurationJobSubjectMaterial } from './workflow-configuration-job-subject';
import { ForbiddenException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService, type KongExecutionFrame } from '../../infrastructure/kong/execution-context.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { assertKongPath } from '../../infrastructure/kong/policy';
import { SnapshotCryptoService } from '../config-storage/snapshot-crypto.service';
import type { ConfigPlan } from '../configuration/configuration.types';
import { validGrant } from '../authorization/grant-policy';
import { configurationOriginMarker } from './approved-execution.types';
import { assertConfigurationWorkflowPlan, type ConfigurationWorkflowPayload } from './configuration-workflow';
import { WorkflowScheduledNamespaceService } from './workflow-scheduled-namespace.service';
import type { WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import { planAad } from './workflow.types';
import { workflowScheduleDraftAad } from './workflow-schedule.repository';
import type { WorkflowScheduledConfigurationCheckpoint as Checkpoint, WorkflowScheduledConfigurationExecutionHandle as ExecutionHandle,
  WorkflowScheduledConfigurationExecutionProof, WorkflowScheduledConfigurationExecutionAndJobProof, WorkflowScheduledConfigurationExecutionCheckpoint,
  WorkflowScheduledConfigurationInspection as Inspection,
  WorkflowScheduledConfigurationJobHandle as JobHandle, WorkflowScheduledConfigurationJobProof,
  WorkflowScheduledConfigurationMaterial as Material, WorkflowScheduledConfigurationRootVerifier } from './workflow-scheduled-configuration-origin.types';

const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i, hex = /^[a-f\d]{64}$/;
const deny = (code = 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_REQUIRED') => new ForbiddenException({ code });
const phases: readonly Checkpoint[] = ['claim', 'capture', 'ledger', 'step', 'packet', 'before-send'];
const time = (value: unknown): number => new Date(value as any).getTime();
const iso = (value: unknown): string => { if (!Number.isFinite(time(value))) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_TIME_INVALID'); return new Date(value as any).toISOString(); };
const int = (value: unknown): number => { const n = typeof value === 'number' ? value : typeof value === 'string' && /^[1-9][0-9]{0,9}$/.test(value) ? Number(value) : NaN;
  if (!Number.isSafeInteger(n) || n < 1 || n > 2_147_483_647) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_EPOCH_INVALID'); return n; };
interface JobState { active: boolean; namespaceHandle: object; namespace: Readonly<WorkflowScheduledNamespaceProof>; wrapperExecutionId: string;
  jobId: string; materialHmac: string; expiresAt: number; usedExecutions: Set<string>; }
interface ExecutionState { active: boolean; jobHandle: JobHandle; id: string; originId: string; claimHash: string; leaseGeneration: number; }
interface CombinedState { active: boolean; readonly jobHandle: JobHandle; readonly executionHandle: ExecutionHandle;
  readonly job: JobState; readonly execution: ExecutionState; readonly frame: KongExecutionFrame;
  readonly principal: ReturnType<KongExecutionContextService['requireWorkflowScheduledCurrentPrincipal']>;
  readonly checkpoint: WorkflowScheduledConfigurationExecutionCheckpoint; readonly transaction: DbService; }

/** SOURCE-ONLY, deliberately not registered in a module or installed in Core.
 * An HTTP SID, copied proof/UUID, wrapper V1 metadata handle, readonly timer or
 * Portal claim cannot enter this private M8 origin. The original author's HTTP
 * job SID and deadlines remain immutable authoring facts. NULL SID is evidence
 * only for the exact live server-minted scheduled job/nested execution handle.
 * This adapter creates no job, SQL origin, operation, binding or native permit.
 */
@Injectable()
export class WorkflowScheduledConfigurationOriginService {
  private root?: Readonly<WorkflowScheduledConfigurationRootVerifier>;
  private readonly jobHandles = new WeakMap<object, JobState>();
  private readonly executionHandles = new WeakMap<object, ExecutionState>();
  private readonly usedNamespaces = new WeakSet<object>();
  private readonly jobs = new AsyncLocalStorage<JobHandle>();
  private readonly executions = new AsyncLocalStorage<ExecutionHandle>();
  private readonly combined = new AsyncLocalStorage<CombinedState>();
  private readonly crypto: SnapshotCryptoService;
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
    private readonly context: KongExecutionContextService, private readonly namespaces: WorkflowScheduledNamespaceService) {
    this.crypto = new SnapshotCryptoService(secrets);
  }
  installRootVerifier(root: WorkflowScheduledConfigurationRootVerifier): void {
    const methods = ['assertCandidateRead', 'assertCandidateMaterial', 'assertLedgerCurrent', 'assertLiveMaterial',
      'openClosedCheckpoint', 'assertClosedCheckpoint', 'assertClosedCheckpointLive', 'releaseClosedCheckpoint'] as const;
    if (this.root || !root || methods.some(key => typeof root[key] !== 'function') || Object.keys(root).some(key => !methods.includes(key as any) && key !== 'runLiveCheckpoint')
      || (root.runLiveCheckpoint !== undefined && typeof root.runLiveCheckpoint !== 'function'))
      throw new Error('One fixed complete scheduled configuration Root verifier is required');
    this.root = Object.freeze({ assertCandidateRead: root.assertCandidateRead.bind(root), assertCandidateMaterial: root.assertCandidateMaterial.bind(root),
      assertLedgerCurrent: root.assertLedgerCurrent.bind(root), assertLiveMaterial: root.assertLiveMaterial.bind(root),
      openClosedCheckpoint: root.openClosedCheckpoint.bind(root), assertClosedCheckpoint: root.assertClosedCheckpoint.bind(root),
      assertClosedCheckpointLive: root.assertClosedCheckpointLive.bind(root), releaseClosedCheckpoint: root.releaseClosedCheckpoint.bind(root),
      ...(root.runLiveCheckpoint ? { runLiveCheckpoint: root.runLiveCheckpoint.bind(root) } : {}) });
  }
  private installed(): Readonly<WorkflowScheduledConfigurationRootVerifier> {
    if (!this.root) throw new ServiceUnavailableException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ADAPTER_UNAVAILABLE' }); return this.root;
  }
  private same(a: unknown, b: unknown): void { if (this.secrets.fingerprint(a ?? null) !== this.secrets.fingerprint(b ?? null)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_SEAL_CHANGED'); }

  private async material(jobId: string, tx: DbService): Promise<Readonly<Material>> {
    if (!uuid.test(jobId)) throw deny();
    const job = await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1', [jobId]);
    if (!job || !uuid.test(job.actor_id) || !uuid.test(job.origin_session_id ?? '') || job.origin_type !== 'http'
      || !['apply', 'rollback'].includes(job.kind) || job.execution_mode !== 'approval' || job.approval_required !== true
      || !uuid.test(job.plan_id ?? '') || !uuid.test(job.workflow_id ?? '') || !hex.test(job.plan_hash ?? '')
      || !hex.test(job.transport_scope ?? '') || !hex.test(job.request_hmac ?? '') || !Array.isArray(job.root_ids)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_JOB_INVALID');
    const keys = [job.cluster_id, job.workspace_id], planRow = await tx.one<any>('SELECT * FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [...keys, job.plan_id]);
    const version = await tx.one<any>('SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4', [...keys, job.plan_id, job.plan_revision]);
    const material = version && await tx.one<any>('SELECT * FROM configuration_materials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [...keys, version.material_id]);
    if (!planRow || planRow.current_revision !== job.plan_revision || planRow.transport_scope !== job.transport_scope || !version
      || version.plan_hash !== job.plan_hash || !material || material.state !== 'available' || !material.wrapped_key_secret
      || material.job_id !== version.source_job_id || material.artifact_kind !== 'plan' || material.artifact_id !== version.artifact_id) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PLAN_INVALID');
    const identity = { clusterId: keys[0], workspaceId: keys[1], jobId: version.source_job_id, materialId: material.id, artifactId: version.artifact_id, artifactKind: 'plan' as const };
    const plan = await this.crypto.withKey(identity, material.wrapped_key_secret, async key => this.crypto.decrypt<ConfigPlan>(key, identity, { section: 'manifest', key: 'plan' }, version.manifest_ciphertext));
    if (this.secrets.fingerprint(plan) !== job.plan_hash || version.input_hmac !== job.plan_hash || this.secrets.fingerprint(plan.steps) !== version.steps_hmac
      || plan.scope.clusterId !== job.cluster_id || plan.scope.workspaceId !== job.workspace_id || plan.scope.transportScope !== job.transport_scope
      || plan.scope.kind !== job.scope_kind || this.secrets.fingerprint(plan.scope.rootIds) !== this.secrets.fingerprint(job.root_ids)
      || plan.permissionVersion !== job.permission_version || plan.clusterRevision !== job.cluster_revision || plan.workspaceRevision !== job.workspace_revision
      || !/^1\.5\.\d+$/.test(plan.kongVersion) || !plan.recoveryComplete || !Array.isArray(plan.steps) || plan.steps.length > 10000
      || version.step_count !== plan.steps.length || version.schema_hmac !== plan.schemaHmac || version.source_manifest_hmac !== plan.sourceManifestHmac
      || version.baseline_manifest_hmac !== plan.baselineManifestHmac) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PLAN_HMAC_INVALID');
    if(configurationDurableMarker(job)||plan.durableRef!==undefined)await new ConfigurationDurableRepository(this.secrets).verify(job,tx,true,plan);
    const objects = await tx.query<any>('SELECT * FROM configuration_plan_objects WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 ORDER BY step_order', [...keys, job.plan_id, job.plan_revision]);
    if (objects.length !== plan.steps.length) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_OBJECTS_INCOMPLETE');
    let packets = 0; const seen = new Set<string>();
    await this.crypto.withKey(identity, material.wrapped_key_secret, async key => {
      for (const [i, step] of plan.steps.entries()) {
        const object = objects[i];
        if (!uuid.test(step.stepId) || seen.has(step.stepId) || step.stepOrder !== i + 1 || step.referenceOnly || step.blockerCodes.length
          || step.bodyHmac !== this.secrets.fingerprint(step.body) || step.beforeHmac !== this.secrets.fingerprint(step.before ?? null)
          || !uuid.test(step.objectWorkspaceId) || !Array.isArray(step.nativeRequests) || !step.nativeRequests.length
          || object.step_id !== step.stepId || object.step_order !== step.stepOrder || object.object_workspace_id !== step.objectWorkspaceId
          || object.entity_type !== step.entityType || object.mutation_action !== step.mutationAction || object.body_hmac !== step.bodyHmac || object.before_hmac !== step.beforeHmac
          || object.reference_only !== false || object.blocker_codes?.length) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_STEP_INVALID');
        this.same(object.dependencies, step.dependencies);
        this.same(object.native_id ?? null, step.nativeId ?? null); this.same(object.allocated_native_id ?? null, step.allocatedNativeId ?? null);
        this.same(object.parent_id ?? null, step.parentId ?? null); this.same(object.credential_kind ?? null, step.credentialKind ?? null);
        for (const request of step.nativeRequests) { assertKongPath(request.method, request.canonicalPath);
          if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) || !hex.test(request.bodyHmac) || !hex.test(request.beforeHmac)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PACKET_INVALID'); packets++; }
        this.same(object.native_requests, step.nativeRequests.map(request => ({ method: request.method, path_hmac: this.secrets.fingerprint(request.canonicalPath), body_hmac: request.bodyHmac, before_hmac: request.beforeHmac })));
        const decoded = this.crypto.decrypt(key, identity, { section: 'plan-step', key: step.stepId, entityType: step.entityType,
          nativeId: step.nativeId ?? step.allocatedNativeId ?? null, parentId: step.parentId ?? null, credentialKind: step.credentialKind ?? null }, object.payload_ciphertext);
        this.same(decoded, step); seen.add(step.stepId);
      }
    });
    if (packets > 500 || version.native_packet_count !== packets) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PACKET_BUDGET');
    let marker; try { marker = configurationOriginMarker(job); } catch { throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_MARKER_INVALID'); }
    let sourceOrigin: Record<string, any> | null = null;
    if (marker) {
      if (!plan.originRef || plan.originRef.version !== 1 || plan.originRef.kind !== marker.kind || plan.originRef.originId !== marker.id || plan.originRef.materialHmac !== marker.hmac) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_MARKER_INVALID');
      const jobOrigin = await tx.one<any>('SELECT * FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3', [...keys, job.id]);
      const planOrigin = await tx.one<any>('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5', [...keys, job.plan_id, job.plan_revision, job.plan_hash]);
      if (!jobOrigin || !planOrigin || jobOrigin.origin_kind !== marker.kind || jobOrigin.origin_id !== marker.id || jobOrigin.material_hmac !== marker.hmac
        || planOrigin.origin_kind !== marker.kind || planOrigin.origin_id !== marker.id || planOrigin.material_hmac !== marker.hmac
        || planOrigin.job_id !== version.source_job_id || !uuid.test(jobOrigin.source_cluster_id) || !uuid.test(jobOrigin.source_workspace_id)
        || jobOrigin.source_cluster_id === job.cluster_id && jobOrigin.source_workspace_id === job.workspace_id) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_BINDING_INVALID');
      sourceOrigin = { marker, jobOrigin, planOrigin };
    } else if (plan.originRef !== undefined || await tx.one('SELECT 1 FROM configuration_job_origin_bindings WHERE job_id=$1', [job.id])
      || await tx.one('SELECT 1 FROM configuration_plan_origin_bindings WHERE plan_id=$1 AND plan_revision=$2 AND plan_hash=$3', [job.plan_id, job.plan_revision, job.plan_hash])) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FOREIGN_PROMOTE_ORIGIN');
    const subjectSeal = { version: 1 as const, driver: marker ? 'governance-promote' as const : job.kind === 'rollback' ? 'configuration-rollback' as const : 'configuration-apply' as const,
      subjectId: job.id, materialHmac: this.secrets.fingerprint({ version: 1, origin: 'workflow-scheduled-configuration', job: configurationJobSubjectMaterial(job),
        planVersion: { sourceJobId: version.source_job_id, planId: version.plan_id, revision: version.plan_revision, hash: version.plan_hash, inputHmac: version.input_hmac,
          materialId: version.material_id, artifactId: version.artifact_id, stepsHmac: version.steps_hmac, sourceManifestHmac: version.source_manifest_hmac,
          baselineManifestHmac: version.baseline_manifest_hmac, schemaHmac: version.schema_hmac, createdAt: iso(version.created_at), expiresAt: iso(version.expires_at) },
        material: { id: material.id, jobId: material.job_id, artifactId: material.artifact_id, artifactKind: material.artifact_kind, wrappedKey: material.wrapped_key_secret }, sourceOrigin }),
      nativeManifestHmac: this.secrets.fingerprint(plan), sourceScopes: sourceOrigin ? [{ clusterId: sourceOrigin.jobOrigin.source_cluster_id,
        workspaceId: sourceOrigin.jobOrigin.source_workspace_id, materialHmac: marker!.hmac }] : [] };
    return immutableJson({ job, version, planRow, material, plan, sourceOrigin, subjectSeal });
  }
  /** Safe seal only; genuine Source-readable candidate provenance and current
   * native/secret/source/target grants are checked by the fixed Root provider. */
  async readCandidateSubject(originalCandidateHandle: object, jobId: string, actorId: string, tx = this.db): Promise<Readonly<Material['subjectSeal']>> {
    const root = this.installed(); await root.assertCandidateRead(originalCandidateHandle, jobId, actorId, tx);
    const material = await this.material(jobId, tx); if (material.job.actor_id !== actorId) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_CANDIDATE_OWNER');
    await root.assertCandidateMaterial(originalCandidateHandle, material, actorId, tx); return material.subjectSeal;
  }
  private live(handle: JobHandle): JobState {
    const state = this.jobHandles.get(handle); if (!state?.active || state.expiresAt <= Date.now() || this.jobs.getStore() !== handle) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_JOB_REQUIRED');
    const frame = this.context.current(); this.namespaces.assertLive(state.namespaceHandle);
    if (this.context.requireWorkflowScheduledNamespaceHandle() !== state.namespaceHandle || frame.sessionId != null || frame.actor?.id !== state.namespace.actor.id
      || frame.clusterId !== state.namespace.clusterId) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_NAMESPACE_CHANGED'); return state;
  }
  private fullGrant(grants: readonly any[], cid: string, wid: string, module: string, action: string): boolean {
    return grants.some(grant => validGrant(grant) && grant.module === module && grant.action === action && (grant.cluster_id === null || grant.cluster_id === cid)
      && (grant.workspace_id === null || grant.workspace_id === wid) && (grant.scope_type === 'global' || grant.scope_type === 'workspace'
        && grant.cluster_id === cid && grant.workspace_id === wid && grant.scope_values.length === 1 && grant.scope_values[0] === wid));
  }
  private async principal(id: string, namespace: Readonly<WorkflowScheduledNamespaceProof>, tx: DbService, reviewer = false): Promise<any> {
    const row = await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false FOR SHARE", [id]);
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    if (!row || !epoch || row.status !== 'active' || row.deleted_at || row.force_password_change) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PRINCIPAL_REVOKED');
    if (!reviewer && (String(row.credential_epoch) !== namespace.credentialEpoch || `${id}:${row.permissions_epoch}:${epoch.version}` !== namespace.permissionVersion)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PERMISSIONS_CHANGED');
    const grants = await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [id]);
    if (row.super_admin !== true && (!this.fullGrant(grants, namespace.clusterId, namespace.workspaceId, 'workflows', reviewer ? 'approve' : 'write')
      || !this.fullGrant(grants, namespace.clusterId, namespace.workspaceId, 'snapshots', reviewer ? 'read' : 'write'))) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_CURRENT_GRANTS_REQUIRED');
    return row;
  }
  private async fullApproval(state: JobState, checkpoint: Checkpoint, tx: DbService): Promise<void> {
    const namespace = state.namespace, set = namespace.approvalSet;
    if (set.format !== 2 || !uuid.test(set.setId ?? '') || !hex.test(set.setHmac ?? '') || !set.reviewers.length
      || new Set(set.reviewers.map(reviewer => reviewer.approvalId)).size !== set.reviewers.length
      || new Set(set.reviewers.map(reviewer => `${reviewer.level}:${reviewer.userId}`)).size !== set.reviewers.length)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED');
    if (checkpoint === 'ledger') {
      // Ledger inspection grants no Native capability. Root independently
      // repeats the complete current SQL policy/candidate/claim verifier with
      // this original proof, never the JSON-cloned Inspection.namespace.
      await this.installed().assertLedgerCurrent(state.namespaceHandle, namespace, tx);
      return;
    }
    // The genuine Namespace re-enters Root's complete current approval-set
    // verifier. Its sealed policy owns every stage threshold, all-candidate
    // requirement and distinctAcrossStages rule; headcount is not approval.
    // No copied set/handle, stale policy, revoked selector or prior PV can
    // substitute for that original policy-derived verification.
    const current = await this.namespaces.verifyHandle(state.namespaceHandle, checkpoint);
    if (current !== namespace) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED');
  }
  private async inspect(handle: JobHandle, checkpoint: Checkpoint, tx: DbService): Promise<Readonly<Inspection>> {
    this.installed(); if (!phases.includes(checkpoint)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_CHECKPOINT_INVALID');
    const state = this.live(handle), ns = state.namespace, c = ns.claim, keys = [ns.clusterId, ns.workspaceId]; await this.redis.assertLeaseOwnership();
    const material = await this.material(state.jobId, tx), { job, plan, version } = material;
    if (material.subjectSeal.materialHmac !== state.materialHmac || this.secrets.fingerprint(material.subjectSeal) !== ns.subjectSealHmac
      || job.actor_id !== ns.actor.id || job.workflow_id !== ns.workflow.id || job.permission_version !== ns.permissionVersion
      || int(job.credential_epoch) !== int(ns.credentialEpoch)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_SUBJECT_CHANGED');
    const schedule = await tx.one<any>('SELECT * FROM workflow_schedules WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [c.scheduleId, ...keys]);
    const claim = await tx.one<any>('SELECT * FROM workflow_schedule_claims WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [c.id, ...keys]);
    const progress = await tx.one<any>('SELECT * FROM workflow_schedule_progress WHERE schedule_id=$1 AND cluster_id=$2 AND workspace_id=$3', [c.scheduleId, ...keys]);
    const lease = await tx.one<any>('SELECT * FROM workflow_schedule_leases WHERE claim_id=$1 ORDER BY lease_version DESC LIMIT 1', [c.id]);
    if (!schedule || schedule.kind !== 'configuration_v2' || schedule.executor_id !== ns.actor.id || schedule.owner_id !== ns.actor.id
      || schedule.workflow_id !== ns.workflow.id || schedule.workflow_plan_revision !== ns.workflow.planRevision || schedule.workflow_plan_hash !== ns.workflow.planHash
      || String(schedule.executor_credential_epoch) !== ns.credentialEpoch || String(schedule.owner_credential_epoch) !== ns.credentialEpoch
      || schedule.subject_seal_hmac !== ns.subjectSealHmac || schedule.transport_scope !== ns.transportScope || schedule.occurrence_id !== c.occurrenceId
      || !claim || claim.schedule_id !== c.scheduleId || claim.occurrence_id !== c.occurrenceId || claim.generation !== 1 || claim.worker_owner_hmac !== c.workerOwnerHmac
      || claim.workflow_id !== ns.workflow.id || claim.workflow_plan_hash !== ns.workflow.planHash || claim.workflow_plan_revision !== ns.workflow.planRevision
      || iso(claim.issued_at) !== c.issuedAt || iso(claim.authority_expires_at) !== c.authorityExpiresAt
      || !progress || progress.claim_id !== c.id || !['claimed', 'running'].includes(progress.state)
      || !lease || lease.claim_id !== c.id || lease.worker_owner_hmac !== c.workerOwnerHmac || time(lease.lease_until) <= Date.now()
      || time(claim.authority_expires_at) <= Date.now() || time(schedule.window_start) > Date.now() || time(schedule.not_before) > Date.now()
      || time(schedule.window_end) <= Date.now() || time(schedule.expires_at) <= Date.now()) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_CLAIM_CHANGED');
    const draft = this.secrets.decrypt<any>(schedule.draft_ciphertext, workflowScheduleDraftAad(ns.clusterId, ns.workspaceId, c.scheduleId));
    if (this.secrets.fingerprint(draft) !== schedule.draft_hmac) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_DRAFT_HMAC_INVALID');
    this.same(draft.binding.subjectSeal, material.subjectSeal);
    const deadlines = [job.authority_expires_at, job.expires_at, plan.expiresAt, version.expires_at].map(time);
    if (deadlines.some(value => !Number.isFinite(value) || value <= Date.now() || time(schedule.window_end) > value)
      || time(job.created_at) > time(schedule.created_at) || time(version.created_at) > time(schedule.created_at)
      || time(plan.expiresAt) > time(job.authority_expires_at)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_OLD_DEADLINE_NOT_RENEWABLE');
    await this.principal(ns.actor.id, ns, tx);
    const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [ns.clusterId]);
    const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2', keys);
    if (!cluster || !/^1\.5\.\d+$/.test(cluster.version ?? '') || ['disabled', 'incompatible'].includes(cluster.status) || cluster.execution_mode !== 'approval'
      || cluster.revision !== job.cluster_revision || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== job.transport_scope
      || job.transport_scope !== ns.transportScope || !workspace || workspace.status !== 'active' || workspace.revision !== job.workspace_revision) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_SCOPE_CHANGED');
    const wrapperOrigin = await tx.one<any>('SELECT * FROM workflow_execution_origins WHERE execution_id=$1', [state.wrapperExecutionId]);
    const wrapperExecution = await tx.one<any>('SELECT * FROM workflow_executions WHERE id=$1', [state.wrapperExecutionId]);
    const workflow = await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [...keys, ns.workflow.id]);
    const wrapperVersion = await tx.one<any>('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4', [...keys, ns.workflow.id, ns.workflow.planRevision]);
    if (!wrapperOrigin || wrapperOrigin.claim_id !== c.id || wrapperOrigin.schedule_id !== c.scheduleId || wrapperOrigin.executor_id !== ns.actor.id
      || wrapperOrigin.cluster_id !== ns.clusterId || wrapperOrigin.workspace_id !== ns.workspaceId || wrapperOrigin.workflow_id !== ns.workflow.id
      || wrapperOrigin.workflow_plan_revision !== ns.workflow.planRevision || wrapperOrigin.workflow_plan_hash !== ns.workflow.planHash
      || !wrapperExecution || !['claimed', 'executing'].includes(wrapperExecution.state) || wrapperExecution.execution_actor_id !== ns.actor.id
      || wrapperExecution.workflow_id !== ns.workflow.id || wrapperExecution.plan_hash !== ns.workflow.planHash || wrapperExecution.plan_revision !== ns.workflow.planRevision
      || wrapperExecution.cluster_id !== ns.clusterId || wrapperExecution.workspace_id !== ns.workspaceId || time(wrapperExecution.expires_at) > time(claim.authority_expires_at)
      || time(wrapperExecution.expires_at) <= Date.now() || !workflow || workflow.state !== 'executing' || workflow.kind !== 'configuration_v2'
      || workflow.subject_type !== 'configuration_jobs' || workflow.subject_id !== job.id || workflow.requester_type !== 'console' || workflow.requester_user_id !== ns.actor.id
      || workflow.plan_revision !== ns.workflow.planRevision || workflow.plan_hash !== ns.workflow.planHash || !wrapperVersion
      || wrapperVersion.step_count !== 1 || wrapperVersion.native_request_count !== 0 || wrapperVersion.plan_hash !== ns.workflow.planHash) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_WRAPPER_ORIGIN_INVALID');
    const wrapper = this.secrets.decrypt<WorkflowScheduledPlanV1>(wrapperVersion.payload_secret, planAad(...keys as [string, string], ns.workflow.id, ns.workflow.planRevision));
    const step = assertConfigurationWorkflowPlan(wrapper), payload = step.metadata as ConfigurationWorkflowPayload;
    if (this.secrets.fingerprint(wrapper) !== ns.workflow.planHash || this.secrets.fingerprint(wrapper.steps) !== wrapperVersion.steps_hash
      || !wrapper.scheduling || wrapper.scheduling.scheduleId !== c.scheduleId || wrapper.scheduling.subjectSealHmac !== ns.subjectSealHmac
      || wrapper.workflowId !== ns.workflow.id || wrapper.planRevision !== ns.workflow.planRevision || payload.jobId !== job.id
      || payload.planId !== job.plan_id || payload.planRevision !== job.plan_revision || payload.planHash !== job.plan_hash
      || wrapper.scope.transportScope !== job.transport_scope) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_WRAPPER_HMAC_INVALID');
    await this.fullApproval(state, checkpoint, tx);
    const approvals = await tx.query<any>("SELECT * FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND decision='approve' ORDER BY id", [...keys, ns.workflow.id, ns.workflow.planRevision, ns.workflow.planHash]);
    const approvalSet = await tx.one<any>('SELECT * FROM workflow_approval_sets WHERE id=$1', [ns.approvalSet.setId]);
    if (!approvalSet || approvalSet.set_hmac !== ns.approvalSet.setHmac || approvalSet.workflow_id !== ns.workflow.id || approvalSet.plan_hash !== ns.workflow.planHash
      || approvals.length !== ns.approvalSet.reviewers.length || approvals.some(approval => time(approval.created_at) < time(schedule.created_at))) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_APPROVAL_CHANGED');
    for (const reviewer of ns.approvalSet.reviewers) {
      const approval = approvals.find(row => row.id === reviewer.approvalId && row.approver_id === reviewer.userId && row.level === reviewer.level && row.candidate_version === reviewer.candidateVersion);
      if (!approval || reviewer.userId === ns.actor.id) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_REVIEWER_CHANGED'); await this.principal(reviewer.userId, ns, tx, true);
    }
    const result = immutableJson({ ...material, originalNamespaceHandle: undefined, namespace: ns, wrapper, wrapperOrigin, wrapperExecution }) as unknown as Inspection;
    // Keep opaque original references out of JSON cloning; copies never stand
    // in for the actual Context-issued namespace handle.
    const inspection = Object.freeze({ ...result, originalNamespaceHandle: state.namespaceHandle });
    this.live(handle); return inspection;
  }
  async runOriginalJob<T>(originalNamespaceHandle: object, wrapperExecutionId: string, jobId: string, fn: (handle: JobHandle) => Promise<T>): Promise<T> {
    this.installed(); if (!uuid.test(wrapperExecutionId) || !uuid.test(jobId) || typeof fn !== 'function'
      || this.context.requireWorkflowScheduledNamespaceHandle() !== originalNamespaceHandle || this.jobs.getStore() || this.usedNamespaces.has(originalNamespaceHandle)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_NAMESPACE_REQUIRED');
    const namespace = await this.context.verifyWorkflowScheduledNamespace('claim');
    if (!namespace || namespace.kind !== 'configuration_v2' || namespace.sessionId !== null || namespace.origin !== 'scheduled-workflow') throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_NAMESPACE_KIND_INVALID');
    const material = await this.material(jobId, this.db);
    const expiresAt = Math.min(time(namespace.expiresAt), time(material.job.authority_expires_at), time(material.job.expires_at), time(material.plan.expiresAt), time(material.version.expires_at));
    const handle = Object.freeze({}) as JobHandle, state: JobState = { active: true, namespaceHandle: originalNamespaceHandle, namespace,
      wrapperExecutionId, jobId, materialHmac: material.subjectSeal.materialHmac, expiresAt, usedExecutions: new Set() };
    this.usedNamespaces.add(originalNamespaceHandle); this.jobHandles.set(handle, state);
    try { return await this.jobs.run(handle, async () => { const inspection = await this.inspect(handle, 'claim', this.db);
      await this.installed().assertLiveMaterial(inspection, 'claim', this.db); this.live(handle); return fn(handle); }); }
    finally { state.active = false; this.jobHandles.delete(handle); }
  }
  private sqlPreparation(handle:JobHandle){
    const preparation=typeof this.context.scheduledConfigurationPreparationPhase==='function'?this.context.scheduledConfigurationPreparationPhase():null;
    if(!preparation)return null;
    const state=this.live(handle);
    if(preparation.originalJobHandle!==handle||preparation.namespaceHandle!==state.namespaceHandle||preparation.namespace!==state.namespace)
      throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');return preparation;
  }
  currentOriginalJobHandle(): JobHandle { const handle = this.jobs.getStore(); if (!handle) throw deny(); this.live(handle); return handle; }
  /** One checkpoint occurrence: its eligibility executor and material read share one fresh observation. */
  async verifyJobHandle(handle: JobHandle, checkpoint: Checkpoint = 'packet', tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationJobProof>> {
    const root = this.installed();
    if (checkpoint === 'ledger' || checkpoint === 'before-send' || typeof root.runLiveCheckpoint !== 'function' || !this.jobHandles.get(handle)?.active)
      return this.verifyJobHandleInner(handle, checkpoint, tx);
    return root.runLiveCheckpoint(this.live(handle).namespaceHandle, checkpoint as any, tx, () => this.verifyJobHandleInner(handle, checkpoint, tx));
  }
  private async verifyJobHandleInner(handle: JobHandle, checkpoint: Checkpoint = 'packet', tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationJobProof>> {
    if(this.sqlPreparation(handle)&&['step','packet','before-send'].includes(checkpoint)){const execution=this.currentOriginalConfigurationExecutionHandle();return(await this.verifyOriginalExecutionAndJob(handle,execution,checkpoint as WorkflowScheduledConfigurationExecutionCheckpoint,tx)).job;}
    let inspection = await this.inspect(handle, checkpoint, tx);
    if (['step', 'packet', 'before-send'].includes(checkpoint)) {
      const execution = this.executions.getStore(); if (!execution || this.executionHandles.get(execution)?.jobHandle !== handle) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_NESTED_EXECUTION_REQUIRED');
      inspection = await this.nested(execution, checkpoint, tx, inspection);
    }
    if (checkpoint !== 'ledger') await this.installed().assertLiveMaterial(inspection, checkpoint, tx);
    this.live(handle); await this.redis.assertLeaseOwnership(); this.live(handle);
    const { job, namespace: ns } = inspection, state = this.live(handle);
    return Object.freeze({ origin: 'workflow-scheduled-configuration', actor: ns.actor, sessionId: null, clusterId: job.cluster_id, workspaceId: job.workspace_id,
      module: 'snapshots', purpose: job.kind, jobId: job.id, permissionVersion: ns.permissionVersion, credentialEpoch: int(ns.credentialEpoch),
      leaseGeneration: int(job.lease_generation), expiresAt: state.expiresAt, readOnly: false, idempotencyKey: job.idempotency_key,
      namespaceHandle: state.namespaceHandle, claimId: ns.claim.id, wrapperOriginId: inspection.wrapperOrigin.id, wrapperExecutionId: state.wrapperExecutionId,
      planId: job.plan_id, planRevision: job.plan_revision, planHash: job.plan_hash, subjectSealHmac: ns.subjectSealHmac });
  }
  /** One full original Native observation for a single nested checkpoint,
   * followed by fresh material/nested SQL and Root's canonical SQL closure.
   * This private invocation scope never survives a return or issues a permit. */
  /** One combined checkpoint occurrence: its executor material read and its
   * own eligibility parties share ONE fresh Kong observation (fresh grants per
   * party). The round is never inherited by any other checkpoint call. */
  async verifyOriginalExecutionAndJob(jobHandle: JobHandle, executionHandle: ExecutionHandle,
    checkpoint: WorkflowScheduledConfigurationExecutionCheckpoint, transaction = this.db): Promise<Readonly<WorkflowScheduledConfigurationExecutionAndJobProof>> {
    const root = this.installed(), job = this.live(jobHandle);
    if (checkpoint === 'before-send' || typeof root.runLiveCheckpoint !== 'function')
      return this.verifyOriginalExecutionAndJobInner(jobHandle, executionHandle, checkpoint, transaction);
    return root.runLiveCheckpoint(job.namespaceHandle, checkpoint, transaction,
      () => this.verifyOriginalExecutionAndJobInner(jobHandle, executionHandle, checkpoint, transaction));
  }
  private async verifyOriginalExecutionAndJobInner(jobHandle: JobHandle, executionHandle: ExecutionHandle,
    checkpoint: WorkflowScheduledConfigurationExecutionCheckpoint, transaction = this.db): Promise<Readonly<WorkflowScheduledConfigurationExecutionAndJobProof>> {
    const preparation=this.sqlPreparation(jobHandle);
    if(preparation&&checkpoint==='before-send')throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_NATIVE_FORBIDDEN');
    this.installed();
    if (!['step', 'packet', 'before-send'].includes(checkpoint) || this.combined.getStore())
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_CHECKPOINT_INVALID');
    const job = this.live(jobHandle), execution = this.executionHandles.get(executionHandle);
    if (!execution?.active || execution.jobHandle !== jobHandle || this.executions.getStore() !== executionHandle)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    const scope: CombinedState = { active: true, jobHandle, executionHandle, job, execution, frame: this.context.current(),
      principal: this.context.requireWorkflowScheduledCurrentPrincipal(job.namespaceHandle), checkpoint, transaction };
    const assertOriginal = () => {
      const principal = this.context.requireWorkflowScheduledCurrentPrincipal(job.namespaceHandle);
      if (preparation&&this.context.scheduledConfigurationPreparationPhase()!==preparation)throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');
      if (!scope.active || this.combined.getStore() !== scope || this.context.current() !== scope.frame
        || this.live(jobHandle) !== job || this.jobHandles.get(jobHandle) !== job
        || scope.checkpoint !== checkpoint || scope.transaction !== transaction
        || this.executionHandles.get(executionHandle) !== execution || !execution.active
        || this.executions.getStore() !== executionHandle || execution.jobHandle !== jobHandle
        || principal.namespace !== job.namespace || principal.namespace !== scope.principal.namespace
        || principal.actor !== job.namespace.actor || principal.actor !== scope.principal.actor
        || principal.role !== scope.principal.role || principal.role !== 'executor' || principal.readOnly
        || principal.validationReadHandle !== scope.principal.validationReadHandle || principal.validationReadHandle !== undefined
        || scope.frame.sessionId != null || scope.frame.actor?.id !== job.namespace.actor.id)
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_CONTEXT_CHANGED');
    };
    const observed = async <T>(read: () => Promise<T>): Promise<T> => {
      assertOriginal(); const value = await read(); assertOriginal(); return value;
    };
    // Only fixed provider SQL reaches this frozen, invocation-local facade.
    // The shape guard detects accidental misuse; it is not a sandbox for
    // arbitrary SELECT expressions or database function side effects.
    const query = <T>(kind: 'one' | 'query', sql: string, args?: any[]): Promise<T> => {
      if (typeof sql !== 'string' || !/^\s*SELECT\b/i.test(sql) || sql.includes(';'))
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SQL_READ_ONLY');
      return observed(() => (transaction[kind] as any).call(transaction, sql, args));
    };
    const deniedSql = () => { throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SQL_READ_ONLY'); };
    const readOne = <T>(sql: string, args?: any[]) => query<T | null>('one', sql, args);
    const readMany = <T>(sql: string, args?: any[]) => query<T[]>('query', sql, args);
    // Defined getters keep the frozen facade compatible with the fixed
    // CurrentIdentity Proxy, which adds its own guards around these methods.
    const tx = Object.freeze(Object.defineProperties(Object.create(null), {
      one: { get: () => readOne, enumerable: true },
      query: { get: () => readMany, enumerable: true },
      exec: { get: () => deniedSql, enumerable: true },
      transaction: { get: () => deniedSql, enumerable: true },
    })) as DbService;
    const supportedMaterial = (inspection: Readonly<Inspection>) => {
      const bad = () => { throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SOURCE_UNSUPPORTED'); };
      let marker; try { marker = configurationOriginMarker(inspection.job); } catch { return bad(); }
      const origin = inspection.sourceOrigin, source = inspection.subjectSeal.sourceScopes;
      if (!marker) {
        if (origin !== null || source.length || !['configuration-apply', 'configuration-rollback'].includes(inspection.subjectSeal.driver)) bad();
        return;
      }
      if (inspection.job.kind !== 'apply' || inspection.subjectSeal.driver !== 'governance-promote' || !origin || source.length !== 1
        || origin.marker?.kind !== marker.kind || origin.marker?.id !== marker.id || origin.marker?.hmac !== marker.hmac
        || source[0].clusterId !== origin.jobOrigin?.source_cluster_id || source[0].workspaceId !== origin.jobOrigin?.source_workspace_id
        || source[0].materialHmac !== marker.hmac) bad();
    };
    let observation: object | undefined, closingDeadlines: readonly number[] | undefined;
    const assertKnownDeadlines = () => {
      if (!closingDeadlines || closingDeadlines.some(value => !Number.isFinite(value) || value <= Date.now()))
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_CHECKPOINT_EXPIRED');
    };
    try { const result = await this.combined.run(scope, async () => {
      assertOriginal();
      await observed(async () => {
        // Retain a minted token even when the outer post-await fence fails.
        observation = await this.installed().openClosedCheckpoint(job.namespaceHandle, job.namespace, checkpoint, tx);
        return observation;
      });
      if (!observation || typeof observation !== 'object' || Array.isArray(observation))
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_CLOSED_OBSERVATION_REQUIRED');
      let inspection = await observed(() => this.inspect(jobHandle, preparation?'ledger':checkpoint, tx)); supportedMaterial(inspection);
      inspection = await observed(() => this.nested(executionHandle, preparation?'ledger':checkpoint, tx, inspection));
      // Root's complete reader legitimately enters its private validation child.
      // It owns those child fences; retain the exact outer frame around it.
      if(!preparation)await observed(() => this.installed().assertLiveMaterial(inspection, checkpoint, transaction));
      // A fresh inspection owns the final evidence. Ledger's existing original
      // identity observation is retained, then the mandatory canonical callback
      // closes the actual step/packet/before-send approval policy independently.
      inspection = await observed(() => this.inspect(jobHandle, 'ledger', tx)); supportedMaterial(inspection);
      inspection = await observed(() => this.nested(executionHandle, 'ledger', tx, inspection));
      await observed(() => this.redis.assertLeaseOwnership());
      // Canonical/grant closure is the final awaited boundary. The sealed
      // comparison then receives synchronous live fences through return.
      await observed(() => this.installed().assertClosedCheckpoint(observation!, job.namespaceHandle, job.namespace, checkpoint, tx));
      this.installed().assertClosedCheckpointLive(observation!, job.namespaceHandle, job.namespace, checkpoint, tx);
      assertOriginal();
      const { job: row, namespace: ns, configurationExecution: nested, configurationOrigin: origin } = inspection;
      closingDeadlines = Object.freeze([nested!.expires_at, row.lease_until, inspection.wrapperExecution.expires_at].map(time));
      assertKnownDeadlines();
      // Context pins this exact original authority field across refreshes. A
      // live lease heartbeat changes liveness, never the original proof TTL.
      const expiresAt = job.expiresAt;
      const jobProof: Readonly<WorkflowScheduledConfigurationJobProof> = Object.freeze({ origin: 'workflow-scheduled-configuration',
        actor: ns.actor, sessionId: null, clusterId: row.cluster_id, workspaceId: row.workspace_id, module: 'snapshots', purpose: row.kind,
        jobId: row.id, permissionVersion: ns.permissionVersion, credentialEpoch: int(ns.credentialEpoch), leaseGeneration: int(row.lease_generation),
        expiresAt, readOnly: false, idempotencyKey: row.idempotency_key, namespaceHandle: job.namespaceHandle,
        claimId: ns.claim.id, wrapperOriginId: inspection.wrapperOrigin.id, wrapperExecutionId: job.wrapperExecutionId,
        planId: row.plan_id, planRevision: row.plan_revision, planHash: row.plan_hash, subjectSealHmac: ns.subjectSealHmac });
      const executionProof: Readonly<WorkflowScheduledConfigurationExecutionProof> = Object.freeze({ origin: 'workflow-scheduled-configuration',
        sessionId: null, jobHandle, namespaceHandle: job.namespaceHandle, claimId: ns.claim.id, wrapperOriginId: inspection.wrapperOrigin.id,
        wrapperExecutionId: inspection.wrapperExecution.id, configurationOriginId: origin!.id, configurationExecutionId: nested!.id,
        configurationJobId: row.id, configurationPlanId: row.plan_id, configurationPlanRevision: row.plan_revision, configurationPlanHash: row.plan_hash,
        configurationClaimHash: nested!.claim_hash, workflowId: ns.workflow.id, workflowPlanRevision: ns.workflow.planRevision, workflowPlanHash: ns.workflow.planHash,
        actorId: ns.actor.id, clusterId: row.cluster_id, workspaceId: row.workspace_id, permissionVersion: ns.permissionVersion,
        credentialEpoch: int(ns.credentialEpoch), leaseGeneration: int(nested!.lease_generation), expiresAt });
      this.installed().assertClosedCheckpointLive(observation!, job.namespaceHandle, job.namespace, checkpoint, tx);
      assertOriginal(); return Object.freeze({ job: jobProof, execution: executionProof });
    });
      // The async ALS callback has its own return continuation. Reenter the
      // same invocation synchronously to fence this method's final return too.
      this.combined.run(scope, () => {
        assertOriginal(); assertKnownDeadlines();
        this.installed().assertClosedCheckpointLive(observation!, job.namespaceHandle, job.namespace, checkpoint, tx);
        assertOriginal();
      });
      return result;
    } finally {
      scope.active = false;
      if (observation) this.installed().releaseClosedCheckpoint(observation);
    }
  }
  private async nested(handle: ExecutionHandle, checkpoint: Checkpoint, tx: DbService, current?: Readonly<Inspection>): Promise<Readonly<Inspection>> {
    const state = this.executionHandles.get(handle);
    if (!state?.active || this.executions.getStore() !== handle) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    const inspection = current ?? await this.inspect(state.jobHandle, checkpoint, tx), { job, namespace: ns } = inspection;
    const execution = await tx.one<any>('SELECT * FROM configuration_executions WHERE id=$1', [state.id]);
    const origin = await tx.one<any>('SELECT * FROM workflow_configuration_execution_origins WHERE configuration_execution_id=$1', [state.id]);
    if (!execution || execution.state !== 'executing' || execution.execution_mode !== 'approval' || execution.actor_id !== ns.actor.id
      || execution.cluster_id !== job.cluster_id || execution.workspace_id !== job.workspace_id || execution.job_id !== job.id
      || execution.plan_id !== job.plan_id || execution.plan_revision !== job.plan_revision || execution.plan_hash !== job.plan_hash
      || execution.workflow_id !== ns.workflow.id || execution.approved_version !== ns.workflow.planRevision || execution.workflow_plan_hash !== ns.workflow.planHash
      || execution.permission_version !== ns.permissionVersion || execution.claim_hash !== state.claimHash || execution.lease_generation !== state.leaseGeneration
      || job.state !== 'running' || job.lease_generation !== state.leaseGeneration || !hex.test(job.lease_owner_hash ?? '') || time(job.lease_until) <= Date.now()
      || time(execution.expires_at) <= Date.now() || time(execution.expires_at) > time(job.expires_at)
      || !origin || origin.id !== state.originId || origin.wrapper_origin_id !== inspection.wrapperOrigin.id || origin.claim_id !== ns.claim.id
      || origin.workflow_execution_id !== inspection.wrapperExecution.id || origin.workflow_id !== ns.workflow.id || origin.workflow_plan_revision !== ns.workflow.planRevision
      || origin.workflow_plan_hash !== ns.workflow.planHash || origin.configuration_job_id !== job.id || origin.configuration_plan_id !== job.plan_id
      || origin.configuration_plan_revision !== job.plan_revision || origin.configuration_plan_hash !== job.plan_hash
      || origin.cluster_id !== job.cluster_id || origin.workspace_id !== job.workspace_id || origin.workflow_step_id !== inspection.wrapper.steps[0].id) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_NESTED_ORIGIN_INVALID');
    const baseline = await tx.one<any>('SELECT * FROM config_snapshot_versions WHERE cluster_id=$1 AND workspace_id=$2 AND snapshot_id=$3 AND version=$4', [job.cluster_id, job.workspace_id, execution.before_snapshot_id, execution.before_snapshot_version]);
    if (!baseline || baseline.completeness !== 'complete' || baseline.consistency !== 'console_fenced_best_effort' || baseline.manifest_hmac !== inspection.plan.baselineManifestHmac) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_BASELINE_INVALID');
    const rows = await tx.query<any>('SELECT * FROM configuration_job_steps WHERE execution_id=$1 ORDER BY step_order', [execution.id]);
    if (rows.length !== inspection.plan.steps.length || rows.some(row => ['failed', 'uncertain'].includes(row.state)
      || row.job_id !== job.id || row.execution_id !== execution.id || row.plan_revision !== job.plan_revision || row.plan_hash !== job.plan_hash)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_UNKNOWN_NO_RETRY');
    // Own running mutation is permitted only after the actual reciprocal V2
    // operation link. Unknown, unbound and foreign operations are never waived.
    const operations = await tx.query<any>('SELECT * FROM mutation_operations WHERE transport_scope=$1 AND state IN(\'pending\',\'running\',\'uncertain\')', [job.transport_scope]);
    for (const operation of operations) {
      const row = rows.find(item => item.id === operation.configuration_step_id && item.operation_id === operation.id && item.state === 'running');
      if (operation.state !== 'running' || !row || operation.configuration_job_id !== job.id || operation.configuration_execution_id !== execution.id
        || operation.configuration_plan_revision !== job.plan_revision || operation.configuration_plan_hash !== job.plan_hash || operation.actor_id !== ns.actor.id
        || operation.workflow_id !== ns.workflow.id || operation.workflow_execution_id != null || operation.workflow_step_id != null
        || operation.workflow_plan_revision != null || operation.workflow_plan_hash != null) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FOREIGN_OR_UNKNOWN_MUTATION');
    }
    return Object.freeze({ ...inspection, configurationExecution: immutableJson(execution), configurationOrigin: immutableJson(origin), rows: immutableJson(rows) });
  }
  async runOriginalConfigurationExecution<T>(jobHandle: JobHandle, executionId: string, fn: (handle: ExecutionHandle) => Promise<T>): Promise<T> {
    const job = this.live(jobHandle); if (!uuid.test(executionId) || typeof fn !== 'function' || this.executions.getStore() || job.usedExecutions.has(executionId)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_EXECUTION_REPLAY_FORBIDDEN');
    const row = await this.db.one<any>('SELECT * FROM configuration_executions WHERE id=$1', [executionId]);
    const origin = await this.db.one<any>('SELECT * FROM workflow_configuration_execution_origins WHERE configuration_execution_id=$1', [executionId]);
    if (!row || !origin || !hex.test(row.claim_hash ?? '')) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_NESTED_ORIGIN_REQUIRED');
    const handle = Object.freeze({}) as ExecutionHandle, state: ExecutionState = { active: true, jobHandle, id: executionId,
      originId: origin.id, claimHash: row.claim_hash, leaseGeneration: int(row.lease_generation) };
    job.usedExecutions.add(executionId); this.executionHandles.set(handle, state);
    try { return await this.executions.run(handle, async () => { await this.verifyConfigurationExecution(handle, 'step'); return fn(handle); }); }
    finally { state.active = false; this.executionHandles.delete(handle); }
  }
  currentOriginalConfigurationExecutionHandle(): ExecutionHandle { const handle = this.executions.getStore();
    if (!handle || !this.executionHandles.get(handle)?.active) throw deny(); return handle; }
  /** One checkpoint occurrence: its eligibility executor and material read share one fresh observation. */
  async verifyConfigurationExecution(handle: ExecutionHandle, checkpoint: Checkpoint = 'packet', tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationExecutionProof>> {
    const root = this.installed();
    if (checkpoint === 'ledger' || checkpoint === 'before-send' || typeof root.runLiveCheckpoint !== 'function' || !this.executionHandles.get(handle)?.active)
      return this.verifyConfigurationExecutionInner(handle, checkpoint, tx);
    return root.runLiveCheckpoint(this.live(this.executionHandles.get(handle)?.jobHandle as JobHandle).namespaceHandle, checkpoint as any, tx, () => this.verifyConfigurationExecutionInner(handle, checkpoint, tx));
  }
  private async verifyConfigurationExecutionInner(handle: ExecutionHandle, checkpoint: Checkpoint = 'packet', tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationExecutionProof>> {
    const original=this.executionHandles.get(handle);if(original&&this.sqlPreparation(original.jobHandle)&&['step','packet','before-send'].includes(checkpoint))return(await this.verifyOriginalExecutionAndJob(original.jobHandle,handle,checkpoint as WorkflowScheduledConfigurationExecutionCheckpoint,tx)).execution;
    const inspection = await this.nested(handle, checkpoint, tx), state = this.executionHandles.get(handle)!;
    if (checkpoint !== 'ledger') await this.installed().assertLiveMaterial(inspection, checkpoint, tx);
    this.live(state.jobHandle); await this.redis.assertLeaseOwnership(); this.live(state.jobHandle);
    const { namespace: ns, job, configurationExecution: e, configurationOrigin: origin } = inspection;
    return Object.freeze({ origin: 'workflow-scheduled-configuration', sessionId: null, jobHandle: state.jobHandle,
      namespaceHandle: this.live(state.jobHandle).namespaceHandle, claimId: ns.claim.id, wrapperOriginId: inspection.wrapperOrigin.id,
      wrapperExecutionId: inspection.wrapperExecution.id, configurationOriginId: origin!.id, configurationExecutionId: e!.id,
      configurationJobId: job.id, configurationPlanId: job.plan_id, configurationPlanRevision: job.plan_revision, configurationPlanHash: job.plan_hash,
      configurationClaimHash: state.claimHash, workflowId: ns.workflow.id, workflowPlanRevision: ns.workflow.planRevision, workflowPlanHash: ns.workflow.planHash,
      actorId: ns.actor.id, clusterId: job.cluster_id, workspaceId: job.workspace_id, permissionVersion: ns.permissionVersion, credentialEpoch: int(ns.credentialEpoch),
      leaseGeneration: state.leaseGeneration, expiresAt: this.live(state.jobHandle).expiresAt });
  }
}
