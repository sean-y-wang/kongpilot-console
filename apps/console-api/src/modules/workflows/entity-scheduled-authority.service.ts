import { ConflictException, ForbiddenException, HttpException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { workspaceTag } from '../../infrastructure/kong/tags';
import type { AuthUser } from '../../common/auth';
import { validGrant } from '../authorization/grant-policy';
import { assertFrozenChangeGrants } from '../entities/entity-change-subject-policy';
import { entityReferenceId } from '../entities/entity-reference';
import { CREDENTIAL_KINDS, type EntityActor } from '../entities/entities.types';
import { EntityChangeBoundaryService } from '../entities/entity-change-boundary.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import { EntityChangeScheduleRepository } from './entity-change-schedule.repository';
import { EntityScheduledMaterialReader } from './entity-scheduled-material-reader';
import { entityPacketFactAad } from './entity-change-execution-facts.service';
import type { EntityChangePacketFact } from './entity-change-execution-facts.types';
import { assertEntityChangeWorkflowPlan } from './entity-change-workflow';
import type { EntityChangeIntentSchedulingDelegate } from './entity-change-intent.types';
import type { EntityScheduledIntentEnvelopeV2, EntityScheduleActivation, EntityScheduleClaim, EntityScheduleTerminalOutcome } from './entity-change-schedule.contract';
import type { EntityScheduledAuthorityCheckpoint, EntityScheduledAuthorityInspection, EntityScheduledExecutorDelegate } from './entity-scheduled-authority.types';
import type { WorkflowPlanV1 } from './workflow.types';
import { scheduledTargetWeightPacket } from './entity-scheduled-target-weight-packet';
import type { EntityChangePacket } from '../entities/entity-change.types';

const unavailable = (code: string) => new ServiceUnavailableException({ code });
const changed = (code: string) => new ConflictException({ code });
const denied = (code: string) => new ForbiddenException({ code });
const iso = (value: any) => new Date(value).toISOString();
const migrationHash = '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f';
type Stored = Awaited<ReturnType<EntityScheduledMaterialReader['schedule']>>;
type HandleState = { scheduleId: string; claim: Readonly<EntityScheduleClaim>; state: 'issued' | 'executing' | 'closed'; callbackEntered?: boolean };
type Proof = { kind: 'activation' | 'claim' | 'outcome' | 'blocked' | 'no-callback'; scheduleId: string; digest: string; handle?: object; completion?: object };

/** Background metadata eligibility only. Genuine opaque handles identify a
 * single SQL occurrence; they are not HTTP Actors, SIDs or native permits.
 * Root independently installs its scheduled context and actual executor. No
 * timer, module activation, source INSERT or network request exists here. */
@Injectable()
export class EntityScheduledAuthorityService {
  private readonly reader: EntityScheduledMaterialReader;
  private readonly handles = new WeakMap<object, HandleState>();
  private readonly proofs = new WeakMap<object, Proof>();
  private readonly workerOwnerHmac: string;
  private installed = false;
  private executor?: Readonly<EntityScheduledExecutorDelegate>;
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
    private readonly context: KongExecutionContextService, private readonly plans: WorkflowPlansService,
    private readonly approvals: WorkflowApprovalAuthorityService, private readonly repository: EntityChangeScheduleRepository,
    private readonly boundary: EntityChangeBoundaryService, private readonly workspaces: WorkspaceResolverService) {
    this.reader = new EntityScheduledMaterialReader(secrets);
    this.workerOwnerHmac = secrets.fingerprint({ namespace: 'entity-scheduled-worker', instance: randomUUID() });
  }
  installExecutor(delegate: EntityScheduledExecutorDelegate): void {
    if (this.executor || !delegate || typeof delegate.executeClaim !== 'function' || typeof delegate.verifyCompletion !== 'function')
      throw new Error('A single complete scheduled executor must be installed');
    this.executor = Object.freeze({ executeClaim: delegate.executeClaim.bind(delegate), verifyCompletion: delegate.verifyCompletion.bind(delegate) });
  }
  private proof(kind: Proof['kind'], scheduleId: string, value: unknown, extra: Partial<Proof> = {}): object {
    const token = Object.freeze({}); this.proofs.set(token, { kind, scheduleId, digest: this.secrets.fingerprint(value), ...extra }); return token;
  }
  private requireProof(token: object, kind: Proof['kind'], scheduleId: string, value: unknown): Proof {
    const fact = this.proofs.get(token);
    if (!fact || fact.kind !== kind || fact.scheduleId !== scheduleId || fact.digest !== this.secrets.fingerprint(value)) throw denied('ENTITY_SCHEDULE_GENUINE_PROOF_REQUIRED');
    return fact;
  }
  private handle(token: object): HandleState {
    const fact = this.handles.get(token);
    if (!fact || fact.state === 'closed') throw denied('ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED');
    return fact;
  }
  private backgroundEntry(): void {
    // Any inherited HTTP/internal/system frame is disallowed. Root installs
    // its distinct genuine scheduled namespace only inside execute callback;
    // this entry never clears a frame, adopts an Actor or invents a SID.
    if (this.context.peek() !== null) throw denied('ENTITY_SCHEDULE_BACKGROUND_CONTEXT_REQUIRED');
  }
  private async iam(tx: DbService): Promise<void> { if (!await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE')) throw denied('AUTHORIZATION_UNAVAILABLE'); }
  private async schema(tx: DbService): Promise<void> {
    const migration = await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='024_m11_entity_schedules.sql'");
    if (!migration || migration.checksum !== migrationHash || !this.installed) throw unavailable('ENTITY_SCHEDULE_STORAGE_UNAVAILABLE');
  }
  private async available(cid: string, wid: string, tx: DbService): Promise<void> {
    await this.schema(tx);
    if (!await tx.one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL', [cid])) throw denied('ENTITY_SCHEDULE_SCOPE_DENIED');
    await this.workspaces.get(cid, wid, false, tx);
  }
  /** Reads genuine current owner rows independently of a reviewer's HTTP ALS.
   * The returned principal is metadata; this never calls runActor/withActor. */
  private async principal(e: EntityScheduledIntentEnvelopeV2, userId: string, action: 'read' | 'write' | 'approve', tx: DbService): Promise<{ user: AuthUser; version: string }> {
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const row = await tx.one<any>("SELECT id,username,super_admin,permissions_epoch,credential_epoch,display_name,locale,timezone,revision FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [userId]);
    if (!epoch || !row || userId === e.requesterId && String(row.credential_epoch) !== e.credentialEpoch) throw denied('ENTITY_SCHEDULE_OWNER_REVOKED');
    const grants = (await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [userId])).filter(validGrant);
    const subject = assertFrozenChangeGrants(e.prepared, grants, row.super_admin === true, action, userId === e.requesterId);
    const workspace = await this.workspaces.get(e.clusterId, e.workspaceId, false, tx);
    if (action !== 'read' && workspace.status !== 'active') throw denied('ENTITY_CHANGE_WORKSPACE_INACTIVE');
    for (const graph of [subject.before, subject.after]) for (const node of graph.values()) {
      const inherited = node.type === 'targets' || CREDENTIAL_KINDS.includes(node.type as any);
      const owner = inherited ? graph.get(`${node.type === 'targets' ? 'upstreams' : 'consumers'}:${entityReferenceId(node.type === 'targets' ? node.data.upstream : node.data.consumer)}`) : node;
      const tags = owner?.data.tags ?? [], reserved = Array.isArray(tags) ? tags.filter(t => typeof t === 'string' && t.startsWith('kos-ws-')) : [];
      if (!owner || !Array.isArray(tags) || tags.some(t => typeof t !== 'string') || !(workspace.is_default
        ? reserved.length === 0 || reserved.length === 1 && reserved[0] === workspaceTag('default')
        : reserved.length === 1 && reserved[0] === workspaceTag(workspace.code))) throw denied('ENTITY_CHANGE_OBJECT_WORKSPACE_MISMATCH');
    }
    const after = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (!after || String(after.version) !== String(epoch.version)) throw denied('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    return { user: immutableJson({ id: row.id, username: row.username, superAdmin: row.super_admin === true, displayName: row.display_name,
      locale: row.locale, timezone: row.timezone, revision: row.revision }), version: `${row.id}:${row.permissions_epoch}:${epoch.version}` };
  }
  private async actualActor(e: EntityScheduledIntentEnvelopeV2, actor: EntityActor, action: 'read' | 'write' | 'approve', tx: DbService): Promise<void> {
    const frame = this.context.peek();
    if (!frame?.sessionId || frame.actor?.id !== actor.user.id || frame.clusterId !== e.clusterId || frame.workspaceId !== e.workspaceId || actor.workspaceId !== e.workspaceId)
      throw denied('ENTITY_SCHEDULE_ACTUAL_ACTOR_REQUIRED');
    if (!await tx.one(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL
      AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL`, [frame.sessionId, actor.user.id])) throw denied('SESSION_EXPIRED');
    await this.principal(e, actor.user.id, action, tx);
  }
  private async scope(e: EntityScheduledIntentEnvelopeV2, tx: DbService): Promise<void> {
    await this.available(e.clusterId, e.workspaceId, tx);
    const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [e.clusterId]), workspace = await this.workspaces.get(e.clusterId, e.workspaceId, false, tx);
    if (!cluster || ['disabled', 'incompatible'].includes(cluster.status) || !/^1\.5\.\d+$/.test(cluster.version ?? '') || cluster.version !== e.prepared.scope.kongVersion
      || cluster.revision !== e.prepared.scope.clusterRevision || cluster.execution_mode !== e.executionMode || workspace.status !== 'active'
      || workspace.revision !== e.prepared.scope.workspaceRevision || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== e.prepared.scope.transportScope) throw changed('ENTITY_SCHEDULE_SCOPE_CHANGED');
    if (this.secrets.fingerprint(await this.plans.definition(e.clusterId, e.workspaceId, 'native-change', tx)) !== this.secrets.fingerprint(e.definition)) throw changed('ENTITY_SCHEDULE_POLICY_CHANGED');
    if (e.executionMode !== 'approval') throw unavailable('ENTITY_SCHEDULE_DIRECT_CONSENT_UNAVAILABLE');
    if (Date.parse(e.expiresAt) <= Date.now()) throw changed('ENTITY_SCHEDULE_WINDOW_EXPIRED');
  }
  private async approved(stored: Stored, tx: DbService, executing = false): Promise<{ plan: WorkflowPlanV1; approvalSet: EntityScheduledAuthorityInspection['approvalSet'] }> {
    const { envelope: e, draft, row } = stored;
    const submission = await tx.one<any>('SELECT * FROM entity_change_submissions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4', [e.clusterId, e.workspaceId, e.intentId, e.revision]);
    if (!submission || submission.material_hmac !== draft.binding.materialHmac || submission.change_digest !== draft.binding.changeDigest || submission.packet_manifest_hmac !== e.packetManifestHmac) throw changed('ENTITY_SCHEDULE_SUBMISSION_REQUIRED');
    const { plan } = await this.plans.load(e.clusterId, e.workspaceId, submission.workflow_id, tx), step = assertEntityChangeWorkflowPlan(plan);
    if (plan.planRevision !== submission.workflow_plan_revision || this.secrets.fingerprint(plan) !== submission.workflow_plan_hash || plan.requester.id !== e.requesterId
      || plan.executionMode !== 'approval' || !plan.approvalRequired || this.secrets.fingerprint(plan.definition) !== this.secrets.fingerprint(e.definition)
      || this.secrets.fingerprint(step.metadata) !== this.secrets.fingerprint({ intentId: e.intentId, intentRevision: e.revision, materialHmac: draft.binding.materialHmac, changeDigest: draft.binding.changeDigest, packetManifestHmac: e.packetManifestHmac })) throw changed('ENTITY_SCHEDULE_PLAN_CHANGED');
    const workflow = await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [e.clusterId, e.workspaceId, plan.workflowId]);
    if (!workflow || !(executing ? ['approved', 'executing'] : ['approved']).includes(workflow.state) || workflow.plan_revision !== plan.planRevision || workflow.plan_hash !== submission.workflow_plan_hash) throw changed('ENTITY_SCHEDULE_APPROVAL_REQUIRED');
    const approvalSet = await this.approvals.verifyApprovalSet(plan, { checkpoint: executing ? 'packet' : 'claim' }, tx);
    if (!approvalSet.reviewers.length) throw changed('ENTITY_SCHEDULE_APPROVAL_REQUIRED');
    // Legacy V1 shared facts intentionally allow an absent optional reviewer
    // delegate. Scheduled eligibility still explicitly checks every reviewer.
    for (const reviewer of approvalSet.reviewers) await this.boundary.assertReviewer(reviewer.userId, e.prepared, tx);
    if (row.workflow_id && (row.workflow_id !== plan.workflowId || row.workflow_plan_revision !== plan.planRevision || row.workflow_plan_hash !== submission.workflow_plan_hash
      || row.approval_format !== approvalSet.format || row.approval_required !== true || row.approval_set_id !== approvalSet.setId || row.approval_set_hmac !== approvalSet.setHmac)) throw changed('ENTITY_SCHEDULE_APPROVAL_CHANGED');
    return { plan, approvalSet };
  }
  private async physical(stored: Stored, tx: DbService, claimId?: string): Promise<void> {
    const { row, draft } = stored;
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))", [draft.transportScope]);
    if (await tx.one(`SELECT other.id FROM entity_change_schedules other JOIN entity_change_schedule_progress p ON p.schedule_id=other.id
      JOIN entity_change_schedule_activations a ON a.schedule_id=other.id WHERE other.id<>$1 AND other.transport_scope=$2
      AND p.state IN('active','claimed','running','uncertain') AND (p.state='uncertain' OR other.window_start<$4 AND $3<other.window_end)
      AND m6_rejected_impact_collision(other.impact,$5::jsonb) LIMIT 1`, [row.id, draft.transportScope, row.window_start, row.window_end, JSON.stringify(draft.impact)])) throw changed('ENTITY_SCHEDULE_PHYSICAL_IMPACT_CONFLICT');
    if (await tx.one(`SELECT m.id FROM mutation_operations m WHERE m.state IN('pending','running','uncertain') AND (m.transport_scope=$1 OR m.transport_scope IS NULL AND m.cluster_id=$2)
      AND m6_rejected_impact_collision(m.impact,$3::jsonb) AND NOT(m.state IN('pending','running') AND $4::uuid IS NOT NULL AND EXISTS(
        SELECT 1 FROM entity_change_execution_sources s WHERE s.id=m.entity_change_source_id AND s.origin_type='scheduled-entity' AND s.claim_id=$4
          AND s.cluster_id=$2 AND s.workspace_id=$5 AND s.workflow_id=m.workflow_id)) LIMIT 1`, [draft.transportScope, draft.binding.clusterId, JSON.stringify(draft.impact), claimId ?? null, draft.binding.workspaceId])) throw changed('ENTITY_SCHEDULE_PHYSICAL_IMPACT_CONFLICT');
  }
  installRepositoryPolicies(): void {
    if (this.installed) throw new Error('Scheduled repository policies are immutable');
    this.repository.installFixedDelegate({
      verifyDraft: async (draft, actor, tx) => {
        const e = await this.reader.intent(draft.binding.clusterId, draft.binding.workspaceId, draft.binding.intentId, draft.binding.intentRevision, tx);
        if (this.secrets.fingerprint(this.reader.draft(e)) !== this.secrets.fingerprint(draft) || actor.user.id !== e.requesterId) throw denied('ENTITY_SCHEDULE_ACTUAL_OWNER_REQUIRED');
        await this.scope(e, tx); await this.actualActor(e, actor, 'write', tx);
      },
      verifyApproved: async (id, activation, proof, tx) => {
        this.requireProof(proof, 'activation', id, activation); const stored = await this.reader.schedule(id, tx);
        await this.scope(stored.envelope, tx); await this.principal(stored.envelope, stored.envelope.requesterId, 'write', tx);
        const approved = await this.approved(stored, tx);
        if (this.secrets.fingerprint(this.activation(approved.plan, approved.approvalSet)) !== this.secrets.fingerprint(activation)) throw changed('ENTITY_SCHEDULE_APPROVAL_CHANGED');
      },
      verifyClaim: async (id, claim, proof, tx) => {
        this.requireProof(proof, 'claim', id, claim); const stored = await this.reader.schedule(id, tx);
        await this.eligibility(stored, tx); this.due(stored);
        if (claim.scheduleId !== id || claim.occurrenceId !== stored.row.occurrence_id || claim.workerOwnerHmac !== this.workerOwnerHmac || claim.generation !== 1
          || claim.workflowId !== stored.row.workflow_id || claim.workflowPlanHash !== stored.row.workflow_plan_hash || claim.workflowPlanRevision !== stored.row.workflow_plan_revision) throw changed('ENTITY_SCHEDULE_CLAIM_CHANGED');
        await this.redis.assertLeaseOwnership();
      },
      verifyLease: async (_id, _owner, _generation, _until, _proof, _tx) => { throw unavailable('ENTITY_SCHEDULE_LEASE_EXTENSION_UNAVAILABLE'); },
      verifyCancellation: async (id, actor, tx) => { const { envelope: e } = await this.reader.schedule(id, tx); if (actor.user.id !== e.requesterId) throw denied('ENTITY_SCHEDULE_ACTUAL_OWNER_REQUIRED'); await this.actualActor(e, actor, 'write', tx); },
      verifyPhysicalReservation: async (id, proof, tx) => {
        const p = this.proofs.get(proof); if (!p || p.scheduleId !== id || !['activation', 'claim'].includes(p.kind)) throw denied('ENTITY_SCHEDULE_GENUINE_PROOF_REQUIRED');
        await this.physical(await this.reader.schedule(id, tx), tx);
      },
      verifyOutcome: async (claimId, outcome, proof, tx) => {
        const fact = this.proofs.get(proof);
        if (fact?.kind === 'no-callback' && fact.handle) {
          const handle = this.handle(fact.handle); this.requireProof(proof, 'no-callback', handle.scheduleId, { claimId, outcome });
          if (outcome !== 'failed' || handle.claim.id !== claimId || handle.state !== 'executing' || handle.callbackEntered) throw denied('ENTITY_SCHEDULE_NO_CALLBACK_FACT_REQUIRED');
          await this.redis.assertLeaseOwnership(); await this.noCallbackFacts(handle, tx); return;
        }
        if (!fact?.handle || !fact.completion) throw denied('ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED');
        const handle = this.handle(fact.handle); this.requireProof(proof, 'outcome', handle.scheduleId, { claimId, outcome });
        if (!this.executor || handle.claim.id !== claimId || handle.state !== 'executing' || await this.executor.verifyCompletion(fact.handle, fact.completion, tx) !== outcome) throw denied('ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED');
        await this.outcomeFacts(handle, outcome, tx);
      },
      verifyBlocked: async (id, reason, proof, tx) => {
        this.requireProof(proof, 'blocked', id, reason); const stored = await this.reader.schedule(id, tx);
        if (stored.row.claim_id || !['active', 'pending-approval'].includes(stored.row.state)) throw changed('ENTITY_SCHEDULE_ALREADY_CLAIMED');
      },
      assertRead: async (id, actor, tx) => { const { envelope: e } = await this.reader.schedule(id, tx); await this.actualActor(e, actor, 'read', tx); },
    });
    this.installed = true;
  }
  intentSchedulingDelegate(): EntityChangeIntentSchedulingDelegate {
    return Object.freeze({ assertAvailable: (cid: string, wid: string, tx: DbService) => this.available(cid, wid, tx),
      persistDraft: (draft: Parameters<EntityChangeScheduleRepository['persistDraft']>[0], actor: EntityActor, tx: DbService) => this.repository.persistDraft(draft, actor, tx) });
  }
  private activation(plan: WorkflowPlanV1, set: EntityScheduledAuthorityInspection['approvalSet']): EntityScheduleActivation {
    return { workflowId: plan.workflowId, workflowPlanRevision: plan.planRevision, workflowPlanHash: this.secrets.fingerprint(plan), approvalFormat: set.format, approvalRequired: true, approvalSetId: set.setId, approvalSetHmac: set.setHmac };
  }
  async activateApproved(id: string, actualActor: EntityActor, transaction?: DbService): Promise<unknown> {
    const activate = async (tx: DbService): Promise<unknown> => {
      await this.schema(tx); await this.iam(tx); const stored = await this.reader.schedule(id, tx), e = stored.envelope;
      await this.scope(e, tx); await this.actualActor(e, actualActor, actualActor.user.id === e.requesterId ? 'write' : 'approve', tx);
      if (actualActor.user.id !== e.requesterId) await this.boundary.assertReviewer(actualActor.user.id, e.prepared, tx);
      await this.principal(e, e.requesterId, 'write', tx); const approved = await this.approved(stored, tx);
      if (!await this.zeroExecutionFacts(e.clusterId, e.workspaceId, approved.plan.workflowId, e.intentId, e.revision, null, tx)) throw changed('ENTITY_SCHEDULE_ALREADY_EXECUTED');
      const activation = this.activation(approved.plan, approved.approvalSet);
      return this.repository.activate(id, activation, this.proof('activation', id, activation), tx);
    };
    return transaction ? activate(transaction) : this.db.transaction(activate);
  }
  /** UI projection only: no activation/cancellation probe, native request or
   * capability is issued. POST validators repeat every current check. */
  async projection(id: string, actor: EntityActor, transaction?: DbService): Promise<Readonly<{ activate: boolean; cancel: boolean }>> {
    const project = async (tx: DbService) => {
      await this.schema(tx); await this.iam(tx); await this.repository.get(id, actor, tx);
      const stored = await this.reader.schedule(id, tx), e = stored.envelope, capabilities = { activate: false, cancel: false };
      const valid = async (check: () => Promise<void>): Promise<boolean> => {
        try { await check(); return true; }
        catch (error) { if (error instanceof HttpException && error.getStatus() < 500) return false; throw error; }
      };
      if (!stored.row.claim_id && ['pending-approval', 'active'].includes(stored.row.state) && actor.user.id === e.requesterId)
        capabilities.cancel = await valid(() => this.actualActor(e, actor, 'write', tx));
      if (stored.row.state === 'pending-approval' && !stored.row.claim_id && e.executionMode === 'approval') capabilities.activate = await valid(async () => {
        await this.scope(e, tx); await this.actualActor(e, actor, actor.user.id === e.requesterId ? 'write' : 'approve', tx);
        if (actor.user.id !== e.requesterId) await this.boundary.assertReviewer(actor.user.id, e.prepared, tx);
        await this.principal(e, e.requesterId, 'write', tx); const { plan } = await this.approved(stored, tx);
        if (!await this.zeroExecutionFacts(e.clusterId, e.workspaceId, plan.workflowId, e.intentId, e.revision, null, tx)) throw changed('ENTITY_SCHEDULE_ALREADY_EXECUTED');
      });
      return immutableJson(capabilities);
    };
    return transaction ? project(transaction) : this.db.transaction(project);
  }
  private due(stored: Stored): void {
    const now = Date.now(), spec = stored.draft.spec;
    if (now >= Date.parse(spec.windowEnd)) throw changed('ENTITY_SCHEDULE_WINDOW_EXPIRED');
    if (now < Date.parse(spec.windowStart) || now < Date.parse(spec.notBefore)) throw changed('ENTITY_SCHEDULE_NOT_DUE');
  }
  private async eligibility(stored: Stored, tx: DbService, executing = false): Promise<Omit<EntityScheduledAuthorityInspection, 'version' | 'claim' | 'leaseUntil' | 'authorityExpiresAt'>> {
    await this.scope(stored.envelope, tx); const principal = await this.principal(stored.envelope, stored.envelope.requesterId, 'write', tx);
    const approved = await this.approved(stored, tx, executing);
    return { draft: stored.draft, envelope: stored.envelope, ...approved, principal: principal.user, permissionVersion: principal.version };
  }
  async acquireDueClaim(id: string): Promise<object | null> {
    this.backgroundEntry();
    if (!this.executor) throw unavailable('ENTITY_SCHEDULE_EXECUTOR_UNAVAILABLE');
    await this.schema(this.db);
    const original = await this.reader.schedule(id, this.db);
    if (original.row.state !== 'active' || original.row.claim_id) return null;
    return this.redis.withLock(`workflow:${original.row.workflow_id}`, async () => {
      try {
        const claim = await this.db.transaction(async tx => {
          await this.iam(tx); const stored = await this.reader.schedule(id, tx);
          if (stored.row.state !== 'active' || stored.row.claim_id) return null;
          await this.eligibility(stored, tx); this.due(stored); await this.physical(stored, tx); await this.redis.assertLeaseOwnership();
          const now = Date.now(), expiry = Math.min(now + 300000, Date.parse(stored.envelope.expiresAt), Date.parse(stored.draft.spec.windowEnd));
          const claim: EntityScheduleClaim = { id: randomUUID(), scheduleId: id, scheduleVersion: 1, occurrenceId: stored.row.occurrence_id,
            generation: 1, workerOwnerHmac: this.workerOwnerHmac, issuedAt: new Date(now).toISOString(), authorityExpiresAt: new Date(expiry).toISOString(),
            initialLeaseUntil: new Date(expiry).toISOString(), workflowId: stored.row.workflow_id, workflowPlanRevision: stored.row.workflow_plan_revision, workflowPlanHash: stored.row.workflow_plan_hash };
          return this.repository.appendDueClaim(id, claim, this.proof('claim', id, claim), tx);
        });
        if (!claim) return null;
        const handle = Object.freeze({}); this.handles.set(handle, { scheduleId: id, claim: immutableJson(claim), state: 'issued' }); return handle;
      } catch (error: any) {
        const actualCode = error?.getResponse?.()?.code;
        // Candidate service failures are real current-reviewer facts. Map only
        // its two explicit ForbiddenException codes, never an arbitrary DTO,
        // validation failure or caller-supplied reason, to the stored reason.
        const code = error instanceof ForbiddenException && ['WORKFLOW_APPROVER_NO_LONGER_ELIGIBLE', 'WORKFLOW_APPROVER_SELECTOR_REVOKED'].includes(actualCode)
          ? 'ENTITY_CHANGE_REVIEWER_INACTIVE' : actualCode;
        if (['ENTITY_SCHEDULE_OWNER_REVOKED', 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED', 'ENTITY_CHANGE_REVIEWER_INACTIVE', 'ENTITY_SCHEDULE_WINDOW_EXPIRED', 'ENTITY_SCHEDULE_SCOPE_CHANGED', 'ENTITY_SCHEDULE_POLICY_CHANGED', 'ENTITY_SCHEDULE_APPROVAL_REQUIRED', 'ENTITY_SCHEDULE_PHYSICAL_IMPACT_CONFLICT'].includes(code)) {
          // No claim is added on an eligibility failure. Truthful blocking is
          // a private fact of this exact failed check, not a caller reason flag.
          await this.repository.appendBlocked(id, code, this.proof('blocked', id, code)); return null;
        }
        throw error;
      }
    });
  }
  async inspect(handle: object): Promise<Readonly<EntityScheduledAuthorityInspection>> { return this.verifyClaim(handle, 'inspect'); }
  async verifyTargetWeightPacket(originalHandle: object, packetKey: string, checkpoint: 'capture' | 'packet' | 'before-send'):
    Promise<Readonly<{ inspection: Readonly<EntityScheduledAuthorityInspection>; packet: Readonly<EntityChangePacket> }>> {
    if (!['capture', 'packet', 'before-send'].includes(checkpoint)) throw denied('ENTITY_SCHEDULE_CHECKPOINT_INVALID');
    const inspection = await this.verifyClaim(originalHandle, checkpoint);
    return Object.freeze({ inspection, packet: scheduledTargetWeightPacket(inspection, packetKey, this.secrets) });
  }
  async verifyClaim(handle: object, checkpoint: EntityScheduledAuthorityCheckpoint): Promise<Readonly<EntityScheduledAuthorityInspection>> {
    if (!['inspect', 'claim', 'capture', 'packet', 'before-send'].includes(checkpoint)) throw denied('ENTITY_SCHEDULE_CHECKPOINT_INVALID');
    const privateFact = this.handle(handle);
    if (checkpoint !== 'inspect') { if (privateFact.state !== 'executing') throw denied('ENTITY_SCHEDULE_EXECUTOR_CONTEXT_REQUIRED'); await this.redis.assertLeaseOwnership(); }
    const result = await this.db.transaction(async tx => {
      await this.iam(tx); const stored = await this.reader.schedule(privateFact.scheduleId, tx); this.due(stored);
      const claim = await tx.one<any>('SELECT * FROM entity_change_schedule_claims WHERE id=$1', [privateFact.claim.id]);
      const lease = await tx.one<any>('SELECT * FROM entity_change_schedule_leases WHERE claim_id=$1 ORDER BY lease_version DESC LIMIT 1', [privateFact.claim.id]);
      const c = privateFact.claim;
      if (!claim || !lease || !['claimed', 'running'].includes(stored.row.state) || stored.row.claim_id !== c.id || claim.schedule_id !== c.scheduleId
        || claim.cluster_id !== stored.envelope.clusterId || claim.workspace_id !== stored.envelope.workspaceId || claim.schedule_version !== 1 || claim.generation !== 1
        || claim.occurrence_id !== c.occurrenceId || claim.worker_owner_hmac !== c.workerOwnerHmac || claim.workflow_id !== c.workflowId || claim.workflow_plan_revision !== c.workflowPlanRevision
        || claim.workflow_plan_hash !== c.workflowPlanHash || claim.owner_id !== stored.envelope.requesterId || String(claim.owner_credential_epoch) !== stored.envelope.credentialEpoch
        || claim.delegation_id !== stored.draft.delegation.id || claim.delegation_version !== 1 || claim.delegation_hmac !== stored.draft.delegationHmac || claim.spec_hmac !== stored.draft.specHmac
        || iso(claim.window_start) !== stored.draft.spec.windowStart || iso(claim.window_end) !== stored.draft.spec.windowEnd || iso(claim.issued_at) !== c.issuedAt
        || iso(claim.authority_expires_at) !== c.authorityExpiresAt || iso(claim.initial_lease_until) !== c.initialLeaseUntil
        || lease.generation !== 1 || lease.worker_owner_hmac !== c.workerOwnerHmac || lease.cluster_id !== stored.envelope.clusterId || lease.workspace_id !== stored.envelope.workspaceId
        || Date.parse(iso(lease.lease_until)) <= Date.now() || Date.parse(c.authorityExpiresAt) <= Date.now() || Date.parse(iso(lease.lease_until)) > Date.parse(c.authorityExpiresAt)) throw changed('ENTITY_SCHEDULE_CLAIM_EXPIRED_OR_CHANGED');
      const eligibility = await this.eligibility(stored, tx, privateFact.state === 'executing');
      await this.physical(stored, tx, c.id);
      return immutableJson({ version: 1 as const, claim: c, ...eligibility, leaseUntil: iso(lease.lease_until), authorityExpiresAt: c.authorityExpiresAt });
    });
    if (checkpoint !== 'inspect') { await this.redis.assertLeaseOwnership(); this.redis.assertLeaseActive(); }
    return result;
  }
  /** Root must consume the original handle inside this live Redis lease; its
   * executor must not recursively acquire the same workflow lock. */
  async executeClaim(handle: object): Promise<void> {
    this.backgroundEntry();
    if (!this.executor) throw unavailable('ENTITY_SCHEDULE_EXECUTOR_UNAVAILABLE');
    const fact = this.handle(handle); if (fact.state !== 'issued') throw changed('ENTITY_SCHEDULE_EXECUTION_ALREADY_STARTED');
    // Spend locally before awaiting the lock, so concurrent copies of the
    // original reference cannot queue a second execution on this process.
    fact.state = 'executing';
    try { await this.redis.withLock(`workflow:${fact.claim.workflowId}`, async () => {
      await this.verifyClaim(handle, 'claim');
      fact.callbackEntered = true;
      const completion = await this.executor!.executeClaim(handle);
      if (!completion || typeof completion !== 'object') throw denied('ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED');
      await this.db.transaction(async tx => {
        const outcome = await this.executor!.verifyCompletion(handle, completion, tx);
        await this.outcomeFacts(fact, outcome, tx);
        await this.repository.finishClaim(fact.claim.id, outcome, this.proof('outcome', fact.scheduleId, { claimId: fact.claim.id, outcome }, { handle, completion }), tx);
      });
    }); } catch (error) {
      if (!fact.callbackEntered) {
        // A private pre-callback observation, corroborated by exact SQL facts,
        // is distinct from Root's genuine completion. It never alleges an
        // unsent request after the native executor has been entered.
        const code = error instanceof HttpException ? (error.getResponse() as any)?.code : undefined;
        const reason = typeof code === 'string' && /^[A-Z][A-Z\d_]{0,127}$/.test(code) ? code : 'ENTITY_SCHEDULE_PRECALL_METADATA_FAILED';
        try { await this.closeNoCallback(handle, reason); } catch { /* Keep the original failure and unresolved claim; never retry a native callback. */ }
      }
      throw error;
    } finally { fact.state = 'closed'; }
  }
  private async zeroExecutionFacts(cid: string, wid: string, workflowId: string, intentId: string, intentRevision: number, claimId: string | null, tx: DbService): Promise<boolean> {
    const facts = await tx.one<any>(`SELECT
      EXISTS(SELECT 1 FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS execution,
      EXISTS(SELECT 1 FROM entity_change_execution_sources WHERE (cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) OR ($6::uuid IS NOT NULL AND claim_id=$6)) AS source,
      EXISTS(SELECT 1 FROM entity_change_baselines WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS baseline,
      EXISTS(SELECT 1 FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS mutation,
      EXISTS(SELECT 1 FROM entity_change_packet_attempts WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$4 AND intent_revision=$5) AS packet`,
      [cid, wid, workflowId, intentId, intentRevision, claimId]);
    return !!facts && ['execution', 'source', 'baseline', 'mutation', 'packet'].every(key => facts[key] === false);
  }
  private async noCallbackFacts(handle: HandleState, tx: DbService): Promise<Stored> {
    if (handle.state !== 'executing' || handle.callbackEntered) throw denied('ENTITY_SCHEDULE_NO_CALLBACK_FACT_REQUIRED');
    const stored = await this.reader.schedule(handle.scheduleId, tx), e = stored.envelope, c = handle.claim;
    const claim = await tx.one<any>('SELECT * FROM entity_change_schedule_claims WHERE id=$1', [c.id]);
    const wf = await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE', [e.clusterId, e.workspaceId, c.workflowId]);
    if (!claim || stored.row.state !== 'claimed' || stored.row.claim_id !== c.id || claim.schedule_id !== handle.scheduleId
      || claim.cluster_id !== e.clusterId || claim.workspace_id !== e.workspaceId || claim.schedule_version !== 1 || claim.generation !== 1
      || claim.occurrence_id !== c.occurrenceId || claim.worker_owner_hmac !== c.workerOwnerHmac || claim.workflow_id !== c.workflowId
      || claim.workflow_plan_revision !== c.workflowPlanRevision || claim.workflow_plan_hash !== c.workflowPlanHash || claim.owner_id !== e.requesterId
      || String(claim.owner_credential_epoch) !== e.credentialEpoch || claim.delegation_id !== stored.draft.delegation.id || claim.delegation_version !== 1
      || claim.delegation_hmac !== stored.draft.delegationHmac || claim.spec_hmac !== stored.draft.specHmac
      || iso(claim.window_start) !== stored.draft.spec.windowStart || iso(claim.window_end) !== stored.draft.spec.windowEnd
      || iso(claim.issued_at) !== c.issuedAt || iso(claim.authority_expires_at) !== c.authorityExpiresAt || iso(claim.initial_lease_until) !== c.initialLeaseUntil
      || !wf || wf.state !== 'approved' || wf.plan_revision !== c.workflowPlanRevision || wf.plan_hash !== c.workflowPlanHash
      || !await this.zeroExecutionFacts(e.clusterId, e.workspaceId, c.workflowId, e.intentId, e.revision, c.id, tx)) throw changed('ENTITY_SCHEDULE_NO_CALLBACK_FACT_REQUIRED');
    return stored;
  }
  private async closeNoCallback(original: object, reason: string): Promise<void> {
    const handle = this.handle(original);
    await this.redis.withLock(`workflow:${handle.claim.workflowId}`, () => this.db.transaction(async tx => {
      await this.redis.assertLeaseOwnership();
      // Read and authenticate the immutable schedule before taking the same
      // impact lock used by controller/repository mutations. Acquire it before
      // any progress row lock/write to prevent impact/progress lock inversion.
      const locked = await this.reader.schedule(handle.scheduleId, tx);
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))", [locked.draft.transportScope]);
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-claim:'||$1,0))", [handle.claim.id]);
      const stored = await this.noCallbackFacts(handle, tx);
      // Retain original claim identity and store the observed safe rejection
      // reason before the existing outcome path commits its failed event/audit.
      if (await tx.exec(`UPDATE entity_change_schedule_progress SET reason_code=$2,revision=revision+1,updated_at=clock_timestamp()
        WHERE schedule_id=$1 AND claim_id=$3 AND state='claimed' AND revision=$4`, [handle.scheduleId, reason, handle.claim.id, stored.row.revision]) !== 1) throw changed('ENTITY_SCHEDULE_STATE_CHANGED');
      await this.repository.finishClaim(handle.claim.id, 'failed', this.proof('no-callback', handle.scheduleId, { claimId: handle.claim.id, outcome: 'failed' }, { handle: original }), tx);
      await this.redis.assertLeaseOwnership();
    }));
  }
  private async outcomeFacts(handle: HandleState, outcome: EntityScheduleTerminalOutcome, tx: DbService): Promise<void> {
    if (!['succeeded', 'partial', 'failed', 'uncertain'].includes(outcome)) throw denied('ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED');
    const { row, envelope: e } = await this.reader.schedule(handle.scheduleId, tx);
    const sources = await tx.query<any>("SELECT s.*,x.state AS execution_state FROM entity_change_execution_sources s JOIN workflow_executions x ON x.id=s.workflow_execution_id WHERE s.origin_type='scheduled-entity' AND s.claim_id=$1", [handle.claim.id]);
    if (sources.length === 0 && outcome === 'failed') {
      // Root may reject before it creates an execution/source. Its original
      // completion is still mandatory; absence is corroboration, never a
      // caller-supplied no-send assertion or authority to replay the claim.
      const evidence = await tx.one<any>(`SELECT
        EXISTS(SELECT 1 FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS execution,
        EXISTS(SELECT 1 FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS source,
        EXISTS(SELECT 1 FROM entity_change_baselines WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS baseline,
        EXISTS(SELECT 1 FROM mutation_operations WHERE cluster_id=$1 AND workflow_id=$3) AS mutation`, [e.clusterId, e.workspaceId, handle.claim.workflowId]);
      const workflow = await tx.one<any>('SELECT state FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [e.clusterId, e.workspaceId, handle.claim.workflowId]);
      if (!evidence || Object.values(evidence).some(value => value !== false) || !['approved', 'failed'].includes(workflow?.state)) throw changed('ENTITY_SCHEDULE_NO_SEND_COMPLETION_REQUIRED');
      return;
    }
    if (sources.length !== 1) throw changed('ENTITY_SCHEDULE_TERMINAL_SOURCE_REQUIRED');
    const source = sources[0];
    if (source.cluster_id !== e.clusterId || source.workspace_id !== e.workspaceId || source.workflow_id !== handle.claim.workflowId
      || source.workflow_plan_revision !== handle.claim.workflowPlanRevision || source.workflow_plan_hash !== handle.claim.workflowPlanHash || source.intent_id !== e.intentId
      || source.intent_revision !== e.revision || source.material_hmac !== row.material_hmac || source.change_digest !== row.change_digest || source.packet_manifest_hmac !== e.packetManifestHmac
      || source.execution_actor_id !== e.requesterId || String(source.credential_epoch) !== e.credentialEpoch || source.execution_state !== outcome || source.session_id !== null) throw changed('ENTITY_SCHEDULE_TERMINAL_SOURCE_CHANGED');
    const wf = await tx.one<any>('SELECT state FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [e.clusterId, e.workspaceId, handle.claim.workflowId]);
    if (wf?.state !== outcome) throw changed('ENTITY_SCHEDULE_TERMINAL_WORKFLOW_REQUIRED');
    const facts = await tx.query<any>(`SELECT a.id AS attempt_id,a.baseline_id,a.pin_id,a.workflow_execution_id AS attempt_execution_id,a.packet_key,
      ev.outcome,ev.native_status,ev.fact_hmac,ev.fact_ciphertext,m.id AS mutation_id,m.state AS mutation_state,m.remote_completed FROM entity_change_packet_attempts a
      LEFT JOIN entity_change_packet_events ev ON ev.attempt_id=a.id AND ev.event_kind='outcome'
      LEFT JOIN mutation_operations m ON m.entity_change_attempt_id=a.id WHERE a.source_id=$1`, [source.id]);
    const succeeded = facts.filter(f => f.outcome === 'succeeded' && f.mutation_state === 'succeeded' && f.remote_completed === true);
    const unknown = facts.some(f => !f.outcome || f.outcome === 'sent-unknown' || ['pending', 'running', 'uncertain'].includes(f.mutation_state));
    const expected = new Set(e.prepared.packets.map(packet => packet.key));
    const complete = !unknown && facts.length === expected.size && succeeded.length === facts.length
      && new Set(facts.map(f => f.packet_key)).size === facts.length && facts.every(f => expected.has(f.packet_key));
    let metadataIncomplete = false;
    if (outcome === 'partial' && complete) {
      for (const fact of facts) {
        let stored: EntityChangePacketFact;
        try { stored = this.secrets.decrypt<EntityChangePacketFact>(fact.fact_ciphertext, entityPacketFactAad(e.clusterId, e.workspaceId, fact.attempt_id, 'outcome')); }
        catch { throw changed('ENTITY_SCHEDULE_TERMINAL_PACKET_FACTS_REQUIRED'); }
        const evidence = stored && typeof stored.evidence === 'object' && stored.evidence !== null && !Array.isArray(stored.evidence)
          ? stored.evidence as Readonly<Record<string, unknown>> : null;
        if (!stored || typeof stored !== 'object' || this.secrets.fingerprint(stored) !== fact.fact_hmac || stored.version !== 1 || stored.kind !== 'outcome' || stored.outcome !== 'succeeded'
          || stored.binding?.sourceId !== source.id || stored.binding?.attemptId !== fact.attempt_id || stored.binding?.baselineId !== fact.baseline_id
          || stored.binding?.pinId !== fact.pin_id || stored.binding?.packetKey !== fact.packet_key || fact.attempt_execution_id !== source.workflow_execution_id
          || !Number.isInteger(stored.nativeStatus) || stored.nativeStatus! < 200 || stored.nativeStatus! > 299 || stored.nativeStatus !== fact.native_status
          || stored.errorCode !== undefined || !evidence || evidence.operationId !== fact.mutation_id || evidence.mutationState !== 'succeeded'
          || evidence.remoteCompleted !== true || typeof evidence.metadataComplete !== 'boolean') throw changed('ENTITY_SCHEDULE_TERMINAL_PACKET_FACTS_REQUIRED');
        metadataIncomplete ||= evidence.metadataComplete === false;
      }
    }
    if (outcome === 'succeeded' && !complete
      || outcome === 'partial' && (unknown || !succeeded.length || succeeded.length >= e.prepared.packets.length && !metadataIncomplete)
      || outcome === 'failed' && (unknown || succeeded.length > 0)
      || outcome === 'uncertain' && !unknown) throw changed('ENTITY_SCHEDULE_TERMINAL_PACKET_FACTS_REQUIRED');
  }
}
