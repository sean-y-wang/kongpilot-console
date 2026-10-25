import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, NotFoundException, OnModuleInit, Optional, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { AuditService } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { EntityChangeCompilerService } from '../entities/entity-change-compiler.service';
import { entityChangeInput } from '../entities/entity-change-input';
import type { EntityActor } from '../entities/entities.types';
import type { PreparedEntityChange } from '../entities/entity-change.types';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowRegistryService } from './workflow-registry.service';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import { workflowId, workflowKey } from './workflow-validation';
import { portalConfirm, portalObject, portalRevision } from '../portal/portal-input';
import {bindEntityRecyclePayloadReferences} from './entity-change-recycle-payload-reference';
import {assertEntityChangeRecycleRestoreOrigin} from './entity-change-recycle-restore-origin';
import { assertEntityChangeWorkflowPlan, entityChangeIntentAad, normalizedEntityChangePackets } from './entity-change-workflow';
import type { EntityChangeIntentEnvelope, EntityChangeIntentSchedulingDelegate, EntityChangeIntentSubjectPolicy, EntityChangeIntentWorkflowDelegate, EntityChangeWorkflowPayload } from './entity-change-intent.types';
import type { EntityScheduledIntentEnvelopeV2, EntityScheduledDraft } from './entity-change-schedule.contract';
import { normalizeEntityScheduleSpec, entityDelegationAad } from './entity-change-schedule.repository';
import type { EntityChangeIntentCapabilities, WorkflowPlanV1 } from './workflow.types';

const unavailable = () => new ServiceUnavailableException({ code: 'ENTITY_CHANGE_INTENT_POLICY_UNAVAILABLE' });
const changed = (code = 'ENTITY_CHANGE_INTENT_CHANGED') => new ConflictException({ code, message: '变更意图、政策或当前配置已变化，请核验原记录并重新规划' });
const nativeUnavailable = () => new ServiceUnavailableException({ code: 'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED', message: '此工单尚未取得执行前快照及专用执行授权' });
@Injectable()
export class EntityChangeIntentsService implements OnModuleInit {
  private subjectPolicy?: Readonly<EntityChangeIntentSubjectPolicy>;
  private schedulingDelegate?: Readonly<EntityChangeIntentSchedulingDelegate>;
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
    private readonly compiler: EntityChangeCompilerService, private readonly plans: WorkflowPlansService, private readonly registry: WorkflowRegistryService,
    private readonly approval: WorkflowApprovalAuthorityService, private readonly audit: AuditService, private readonly authz: AuthorizationService,
    @Optional() private readonly execution?: KongExecutionContextService) {}
  installSubjectPolicy(policy: EntityChangeIntentSubjectPolicy): void {
    if (this.subjectPolicy || !policy || typeof policy.assertSubject !== 'function' || typeof policy.verifyReviewer !== 'function' || Object.keys(policy).some(key => !['assertSubject', 'verifyReviewer'].includes(key))) throw new ConflictException({ code: 'ENTITY_CHANGE_INTENT_POLICY_ALREADY_INSTALLED' });
    this.subjectPolicy = Object.freeze(policy);
  }
  private policy(): Readonly<EntityChangeIntentSubjectPolicy> { if (!this.subjectPolicy) throw unavailable(); return this.subjectPolicy; }
  installSchedulingDelegate(delegate:EntityChangeIntentSchedulingDelegate):void{
    if(this.schedulingDelegate||!delegate||typeof delegate.assertAvailable!=='function'||typeof delegate.persistDraft!=='function'||Object.keys(delegate).some(key=>!['assertAvailable','persistDraft'].includes(key)))throw changed('ENTITY_SCHEDULE_DELEGATE_ALREADY_INSTALLED');
    this.schedulingDelegate=Object.freeze({assertAvailable:delegate.assertAvailable.bind(delegate),persistDraft:delegate.persistDraft.bind(delegate)});
  }
  private scheduling():Readonly<EntityChangeIntentSchedulingDelegate>{if(!this.schedulingDelegate)throw new ServiceUnavailableException({code:'ENTITY_SCHEDULE_PREPARATION_NOT_ENABLED'});return this.schedulingDelegate;}
  private materialBudget(envelope:EntityChangeIntentEnvelope,review:unknown,packets:unknown):void{
    if([envelope,review,packets].some(value=>Buffer.byteLength(JSON.stringify(value))>2*1024*1024))throw new BadRequestException({code:'ENTITY_CHANGE_INTENT_MATERIAL_BUDGET',message:'变更材料超过 2 MiB 安全预算，请拆分为较小的变更后重试'});
  }
  workflowDelegate(): EntityChangeIntentWorkflowDelegate {
    return Object.freeze({ verifyIntent: (plan: WorkflowPlanV1, tx?: DbService) => this.verifyIntent(plan, tx), assertSubject: (plan: WorkflowPlanV1, id: string, action: 'read' | 'write' | 'approve', tx?: DbService) => this.assertSubject(plan, id, action, tx),
      verifyReviewer: (id: string, plan: WorkflowPlanV1, tx?: DbService) => this.verifyReviewer(id, plan, tx), revalidate: (plan: WorkflowPlanV1, actor: EntityActor, phase: 'submit' | 'approve' | 'claim') => this.revalidate(plan, actor, phase) });
  }
  onModuleInit(): void {
    this.plans.installEntityChangeIntentDelegate(this.workflowDelegate());
    this.approval.installReviewerPolicy('native-change', { verifyCurrent: (id, plan, tx) => this.verifyReviewer(id, plan, tx) });
    this.registry.register('entity.change', {
      authorize: (plan, actor, action) => this.assertSubject(plan, actor.user.id, action),
      inspect: async (input, tx) => { const loaded = await this.boundWorkflow(input.plan, tx); return { before: this.before(loaded.envelope, loaded.version.material_hmac), revision: loaded.envelope.revision }; },
      apply: async () => { throw nativeUnavailable(); }
    });
  }
  private before(envelope: EntityChangeIntentEnvelope, materialHmac: string): Record<string, unknown> { return { intentId: envelope.intentId, intentRevision: envelope.revision, materialHmac, changeDigest: envelope.prepared.changeDigest, packetManifestHmac: envelope.packetManifestHmac }; }
  /** Current SQL/subject projection only. Submission still revalidates real
   * before-state and schema; this boolean never grants execution authority. */
  private async canSubmit(envelope: EntityChangeIntentEnvelope, actor: EntityActor, tx = this.db): Promise<boolean> {
    const expiresAt = Date.parse(envelope.expiresAt);
    if (actor.user.id !== envelope.requesterId || actor.workspaceId !== envelope.workspaceId || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
    if(envelope.version===2&&!this.schedulingDelegate)return false;
    try {
      const permissionVersion = await this.authz.permissionVersion(actor.user, tx);
      await this.identity(actor, tx, envelope.credentialEpoch);
      await this.assertLiveOwner(envelope, tx);
      await this.assertCurrentDefinition(envelope, tx);
      await this.policy().assertSubject(envelope, actor.user.id, 'write', tx);
      const submission = await tx.one('SELECT workflow_id FROM entity_change_submissions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4',
        [envelope.intentId, envelope.clusterId, envelope.workspaceId, envelope.revision]);
      if (submission || await this.authz.permissionVersion(actor.user, tx) !== permissionVersion) return false;
      return expiresAt > Date.now();
    } catch (error) {
      if (error instanceof HttpException && error.getStatus() < 500) return false;
      throw error;
    }
  }
  private async receipt(envelope: EntityChangeIntentEnvelope, materialHmac: string, actor: EntityActor): Promise<Record<string, unknown>> {
    const capabilities: Readonly<EntityChangeIntentCapabilities> = Object.freeze({ submit: await this.canSubmit(envelope, actor) });
    const credentialSubject = this.credentialSubject(envelope);
    const targetSubject = this.targetSubject(envelope);
    return { id: envelope.intentId, revision: envelope.revision, materialHmac, executionMode: envelope.executionMode, issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt, definition: envelope.definition, review: this.secrets.redact(envelope.review), nativeExecutionAvailable: false,
      capabilities:envelope.version===2?{...capabilities,scheduleSubmit:capabilities.submit}:capabilities,
      ...(credentialSubject ? { credentialSubject } : {}),
      ...(targetSubject ? { targetSubject } : {}),
      ...(envelope.version===2?{schedule:{id:envelope.scheduling.scheduleId,...envelope.scheduling.spec}}:{}) };
  }
  /** Public subject identity only, from the authenticated immutable request.
   * It discloses no credential body, native URL, secret or execution permit. */
  private credentialSubject(envelope:EntityChangeIntentEnvelope):Record<string,string>|null {
    const request=envelope.prepared.request;
    const kinds=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
    if(request.kind==='credential'){
      if(!kinds.includes(request.credentialKind)||!['create','update'].includes(request.action))throw changed('ENTITY_CHANGE_CREDENTIAL_SUBJECT_INVALID');
      return {consumerId:workflowId(request.consumerId),credentialKind:request.credentialKind,action:request.action,
        ...(request.action==='update'?{credentialId:workflowId(request.credentialId)}:{})};
    }
    if(request.kind==='recycle'&&request.action==='delete'&&request.entityType==='credentials'){
      if(!kinds.includes(request.credentialKind??''))throw changed('ENTITY_CHANGE_CREDENTIAL_SUBJECT_INVALID');
      return {consumerId:workflowId(request.parentId),credentialKind:request.credentialKind!,action:'delete',credentialId:workflowId(request.entityId)};
    }
    return null;
  }
  /** Original target identity only. The old target UUID for a weight change
   * is deliberately distinct from the newly allocated history packet UUID.
   * This immutable public tuple grants no native or recovery authority. */
  private targetSubject(envelope:EntityChangeIntentEnvelope):Readonly<Record<string,string>>|null {
    const request=envelope.prepared.request;
    if(request.kind!=='target'&&!(request.kind==='recycle'&&request.action==='delete'&&request.entityType==='targets'))return null;
    let normalized:ReturnType<typeof entityChangeInput>;
    try{normalized=entityChangeInput(request);}catch{throw changed('ENTITY_CHANGE_TARGET_SUBJECT_INVALID');}
    if(this.secrets.fingerprint(normalized)!==this.secrets.fingerprint(request))throw changed('ENTITY_CHANGE_TARGET_SUBJECT_INVALID');
    if(normalized.kind==='target'){
      const upstreamId=workflowId(normalized.upstreamId);
      if(normalized.action==='create')return Object.freeze({upstreamId,action:'create'});
      const targetId=workflowId(normalized.targetId);
      return Object.freeze({upstreamId,action:normalized.action,targetId,...(normalized.action==='health'?{state:normalized.state}:{})});
    }
    if(normalized.kind!=='recycle'||normalized.action!=='delete'||normalized.entityType!=='targets')throw changed('ENTITY_CHANGE_TARGET_SUBJECT_INVALID');
    return Object.freeze({upstreamId:workflowId(normalized.parentId),action:'delete',targetId:workflowId(normalized.entityId)});
  }
  private async identity(actor: EntityActor, tx = this.db, expectedEpoch?: string): Promise<string> {
    await this.authz.permissionVersion(actor.user, tx);
    const user = await tx.one<any>("SELECT credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [actor.user.id]);
    if (!user || expectedEpoch !== undefined && String(user.credential_epoch) !== expectedEpoch) throw new ForbiddenException({ code: 'ENTITY_CHANGE_REQUESTER_CREDENTIAL_CHANGED' });
    return String(user.credential_epoch);
  }
  private verifyEnvelope(envelope: EntityChangeIntentEnvelope, version: any, intent: any): void {
    const material = envelope.prepared, { changeDigest, ...original } = material;
    if (![1,2].includes(envelope.version) || envelope.intentId !== intent.id || envelope.intentId !== version.intent_id || envelope.revision !== version.intent_revision || envelope.clusterId !== intent.cluster_id || envelope.workspaceId !== intent.workspace_id
      || envelope.requesterId !== intent.requester_id || envelope.requesterId !== material.requesterId || envelope.credentialEpoch !== String(intent.credential_epoch) || envelope.credentialEpoch !== String(version.credential_epoch)
      || envelope.clusterId !== material.clusterId || envelope.workspaceId !== material.workspaceId || envelope.executionMode !== version.execution_mode
      || envelope.definition.id !== version.definition_id || envelope.definition.version !== version.definition_version || envelope.definition.policyHash !== version.policy_hash
      || new Date(intent.issued_at).toISOString() !== envelope.issuedAt || new Date(intent.expires_at).toISOString() !== envelope.expiresAt
      || new Date(version.issued_at).toISOString() !== envelope.issuedAt || new Date(version.expires_at).toISOString() !== envelope.expiresAt
      || !Number.isInteger(envelope.ttlHours) || envelope.ttlHours < 1 || envelope.ttlHours > 168
      || (envelope.version===1?Date.parse(envelope.expiresAt)-Date.parse(envelope.issuedAt)!==envelope.ttlHours*3600000:
        Date.parse(envelope.expiresAt)<=Date.parse(envelope.issuedAt)||Date.parse(envelope.expiresAt)-Date.parse(envelope.issuedAt)>envelope.ttlHours*3600000)
      || this.secrets.fingerprint(envelope) !== version.material_hmac || this.secrets.fingerprint(original) !== changeDigest || changeDigest !== version.change_digest
      || this.secrets.fingerprint(normalizedEntityChangePackets(material, this.secrets)) !== envelope.packetManifestHmac || envelope.packetManifestHmac !== version.packet_manifest_hmac
      || this.secrets.fingerprint(version.packet_manifest) !== envelope.packetManifestHmac || material.packets.length !== version.packet_count || this.secrets.fingerprint(envelope.review) !== this.secrets.fingerprint(version.safe_review)) throw changed('ENTITY_CHANGE_INTENT_MATERIAL_INVALID');
    if(envelope.version===2)this.verifyScheduledEnvelope(envelope);
  }
  private verifyScheduledEnvelope(envelope:EntityScheduledIntentEnvelopeV2):void{
    const scheduling=envelope.scheduling,delegation=scheduling?.delegation;
    if(!scheduling||scheduling.scheduleVersion!==1||!delegation||delegation.version!==1||delegation.revision!==1)throw changed('ENTITY_SCHEDULE_MATERIAL_INVALID');
    const spec=normalizeEntityScheduleSpec(scheduling.spec,envelope.requesterId);
    if(workflowId(scheduling.scheduleId)!==scheduling.scheduleId||workflowId(delegation.id)!==delegation.id
      ||this.secrets.fingerprint(spec)!==scheduling.specHmac||this.secrets.fingerprint(delegation)!==scheduling.delegationHmac
      ||delegation.clusterId!==envelope.clusterId||delegation.workspaceId!==envelope.workspaceId||delegation.intentId!==envelope.intentId||delegation.intentRevision!==envelope.revision
      ||delegation.changeDigest!==envelope.prepared.changeDigest||delegation.packetManifestHmac!==envelope.packetManifestHmac||delegation.policyHash!==envelope.definition.policyHash
      ||delegation.ownerId!==envelope.requesterId||delegation.executorId!==envelope.requesterId||delegation.ownerCredentialEpoch!==envelope.credentialEpoch||delegation.executorCredentialEpoch!==envelope.credentialEpoch
      ||delegation.specHmac!==scheduling.specHmac||delegation.issuedAt!==envelope.issuedAt||delegation.expiresAt!==envelope.expiresAt
      ||delegation.statement!=='execute-this-exact-approved-entity-intent-with-my-current-authority'||spec.windowEnd!==envelope.expiresAt||Date.parse(spec.notBefore)<Date.parse(envelope.issuedAt))throw changed('ENTITY_SCHEDULE_MATERIAL_INVALID');
  }
  private async verifyScheduledStorage(envelope:EntityScheduledIntentEnvelopeV2,materialHmac:string,tx:DbService):Promise<void>{
    const scheduling=envelope.scheduling,row=await tx.one<any>(`SELECT s.*,d.delegation_ciphertext,d.version AS actual_delegation_version,d.owner_id AS delegation_owner_id,
      d.executor_id,d.owner_credential_epoch AS delegation_owner_epoch,d.executor_credential_epoch,d.issued_at AS delegation_issued_at,d.expires_at AS delegation_expires_at,d.policy_hash
      FROM entity_change_schedules s JOIN entity_change_owner_delegations d ON d.id=s.delegation_id
      WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.intent_id=$3 AND s.intent_revision=$4`,[envelope.clusterId,envelope.workspaceId,envelope.intentId,envelope.revision]);
    if(!row||row.id!==scheduling.scheduleId||row.version!==1||row.material_hmac!==materialHmac||row.change_digest!==envelope.prepared.changeDigest||row.packet_manifest_hmac!==envelope.packetManifestHmac
      ||row.transport_scope!==envelope.prepared.scope.transportScope||row.impact_hmac!==this.secrets.fingerprint(envelope.prepared.impact)||this.secrets.fingerprint(row.impact)!==row.impact_hmac
      ||row.owner_id!==envelope.requesterId||String(row.owner_credential_epoch)!==envelope.credentialEpoch||row.spec_hmac!==scheduling.specHmac||this.secrets.fingerprint(row.spec)!==scheduling.specHmac
      ||new Date(row.not_before).toISOString()!==scheduling.spec.notBefore||new Date(row.window_start).toISOString()!==scheduling.spec.windowStart||new Date(row.window_end).toISOString()!==scheduling.spec.windowEnd
      ||new Date(row.expires_at).toISOString()!==envelope.expiresAt||row.delegation_id!==scheduling.delegation.id||row.delegation_version!==1||row.actual_delegation_version!==1
      ||row.delegation_hmac!==scheduling.delegationHmac||row.delegation_owner_id!==envelope.requesterId||row.executor_id!==envelope.requesterId
      ||String(row.delegation_owner_epoch)!==envelope.credentialEpoch||String(row.executor_credential_epoch)!==envelope.credentialEpoch||row.policy_hash!==envelope.definition.policyHash
      ||new Date(row.delegation_issued_at).toISOString()!==envelope.issuedAt||new Date(row.delegation_expires_at).toISOString()!==envelope.expiresAt
      ||this.secrets.fingerprint(this.secrets.decrypt(row.delegation_ciphertext,entityDelegationAad(envelope.clusterId,envelope.workspaceId,scheduling.delegation.id)))!==scheduling.delegationHmac)throw changed('ENTITY_SCHEDULE_STORAGE_BINDING_INVALID');
  }
  private async load(cid: string, wid: string, id: string, revision = 1, tx = this.db): Promise<{ intent: any; version: any; envelope: EntityChangeIntentEnvelope }> {
    const intent = await tx.one<any>('SELECT * FROM entity_change_intents WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [workflowId(id), cid, wid]);
    if (!intent) throw new NotFoundException({ code: 'ENTITY_CHANGE_INTENT_NOT_FOUND' });
    const version = await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4', [id, cid, wid, revision]);
    if (!version) throw changed('ENTITY_CHANGE_INTENT_VERSION_UNAVAILABLE');
    const envelope = this.secrets.decrypt<EntityChangeIntentEnvelope>(version.envelope_ciphertext, entityChangeIntentAad(cid, wid, id, revision)); this.verifyEnvelope(envelope, version, intent);
    const packets = await tx.query<any>('SELECT * FROM entity_change_intent_packets WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4 ORDER BY packet_order', [id, cid, wid, revision]);
    const normalized = packets.map(packet => ({ key: packet.packet_key, order: packet.packet_order, dependencies: packet.dependencies, method: packet.method, pathHmac: packet.path_hmac, nativeType: packet.native_type, nativeId: packet.native_id, parentId: packet.parent_id, credentialKind: packet.credential_kind, originalNativeId: packet.original_native_id, mutationAction: packet.mutation_action, permissionAction: packet.permission_action, bodyHmac: packet.body_hmac, beforeHmac: packet.before_hmac }));
    if (packets.length !== envelope.prepared.packets.length || packets.some(packet => packet.material_hmac !== version.material_hmac || packet.change_digest !== version.change_digest || packet.packet_manifest_hmac !== version.packet_manifest_hmac) || this.secrets.fingerprint(normalized) !== envelope.packetManifestHmac) throw changed('ENTITY_CHANGE_INTENT_PACKET_SOURCE_INVALID');
    if(envelope.version===2)await this.verifyScheduledStorage(envelope,version.material_hmac,tx);
    return { intent, version, envelope };
  }
  private async boundWorkflow(plan: WorkflowPlanV1, tx = this.db): Promise<{ intent: any; version: any; envelope: EntityChangeIntentEnvelope }> {
    const step = assertEntityChangeWorkflowPlan(plan), payload = step.metadata as EntityChangeWorkflowPayload, loaded = await this.load(plan.clusterId, plan.workspaceId, payload.intentId, payload.intentRevision, tx), { envelope, version } = loaded;
    const binding = await tx.one<any>('SELECT * FROM entity_change_submissions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4', [payload.intentId, plan.clusterId, plan.workspaceId, payload.intentRevision]);
    if (!binding || binding.workflow_id !== plan.workflowId || binding.workflow_plan_revision !== plan.planRevision || binding.workflow_plan_hash !== this.secrets.fingerprint(plan) || binding.actor_id !== plan.requester.id || plan.requester.id !== envelope.requesterId
      || payload.materialHmac !== version.material_hmac || payload.changeDigest !== version.change_digest || payload.packetManifestHmac !== envelope.packetManifestHmac
      || binding.material_hmac !== payload.materialHmac || binding.change_digest !== payload.changeDigest || binding.packet_manifest_hmac !== payload.packetManifestHmac
      || this.secrets.fingerprint(plan.definition) !== this.secrets.fingerprint(envelope.definition) || plan.expiresAt !== envelope.expiresAt || plan.executionMode !== envelope.executionMode || plan.approvalRequired !== (envelope.executionMode === 'approval')
      || this.secrets.fingerprint(step.metadata) !== step.metadataPayloadHmac || this.secrets.fingerprint(this.before(envelope, version.material_hmac)) !== step.metadataBeforeHmac || this.secrets.fingerprint(step.before) !== step.metadataBeforeHmac
      || plan.scope.transportScope !== envelope.prepared.scope.transportScope || plan.scope.clusterRevision !== envelope.prepared.scope.clusterRevision || plan.scope.workspaceRevision !== envelope.prepared.scope.workspaceRevision) throw changed('ENTITY_CHANGE_WORKFLOW_SOURCE_INVALID');
    return loaded;
  }
  async verifyIntent(plan: WorkflowPlanV1, tx = this.db): Promise<void> { await this.boundWorkflow(plan, tx); }
  /** Bootstrap-owned executor reads authenticated material only after actual
   * requester authorization. Returning it is not an execution capability. */
  async executionMaterial(plan:WorkflowPlanV1,actor:EntityActor,tx=this.db):Promise<EntityChangeIntentEnvelope>{
    const loaded=await this.boundWorkflow(plan,tx);await this.assertSubject(plan,actor.user.id,'write',tx);
    await this.identity(actor,tx,loaded.envelope.credentialEpoch);await this.assertLiveOwner(loaded.envelope,tx);await this.assertCurrentDefinition(loaded.envelope,tx);
    if(Date.parse(loaded.envelope.expiresAt)<=Date.now())throw changed('ENTITY_CHANGE_INTENT_EXPIRED');
    return loaded.envelope;
  }
  async assertSubject(plan: WorkflowPlanV1, userId: string, action: 'read' | 'write' | 'approve', tx = this.db): Promise<void> {
    const { envelope } = await this.boundWorkflow(plan, tx); if (action === 'write' && userId !== envelope.requesterId) throw new ForbiddenException({ code: 'ENTITY_CHANGE_REQUESTER_REQUIRED' });
    await this.policy().assertSubject(envelope, workflowId(userId), action, tx);
  }
  async verifyReviewer(userId: string, plan: WorkflowPlanV1, tx = this.db): Promise<void> { const { envelope } = await this.boundWorkflow(plan, tx); await this.policy().verifyReviewer(envelope, workflowId(userId), tx); }
  async revalidate(plan: WorkflowPlanV1, actor: EntityActor, phase: 'submit' | 'approve' | 'claim'): Promise<void> {
    const { envelope } = await this.boundWorkflow(plan); await this.assertLiveOwner(envelope);
    if (Date.parse(envelope.expiresAt) <= Date.now()) throw changed('ENTITY_CHANGE_INTENT_EXPIRED');
    const action = phase === 'approve' ? 'approve' : 'write'; await this.policy().assertSubject(envelope, actor.user.id, action, this.db);
    await this.compiler.revalidateStored(envelope.prepared, actor, action, phase);
  }
  private async assertLiveOwner(envelope: EntityChangeIntentEnvelope, tx = this.db): Promise<void> {
    const owner = await tx.one<any>("SELECT credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [envelope.requesterId]);
    if (!owner || String(owner.credential_epoch) !== envelope.credentialEpoch) throw new ForbiddenException({ code: 'ENTITY_CHANGE_REQUESTER_CREDENTIAL_CHANGED' });
  }
  private async assertCurrentDefinition(envelope: EntityChangeIntentEnvelope, tx = this.db): Promise<void> {
    const current = await this.plans.definition(envelope.clusterId, envelope.workspaceId, 'native-change', tx);
    if (this.secrets.fingerprint(current) !== this.secrets.fingerprint(envelope.definition)) throw changed('ENTITY_CHANGE_INTENT_POLICY_CHANGED');
  }
  async prepare(cid: string, raw: unknown, actor: EntityActor): Promise<any> {
    this.policy(); const wid = workflowId(actor.workspaceId), key = workflowKey(actor.idempotencyKey), value = portalObject(raw, ['change', 'ttlHours']);
    const request = { change: entityChangeInput(value.change), ...(value.ttlHours !== undefined ? { ttlHours: value.ttlHours } : {}) }, requestHmac = this.secrets.fingerprint(request);
    if (value.ttlHours !== undefined && (!Number.isInteger(value.ttlHours) || Number(value.ttlHours) < 1 || Number(value.ttlHours) > 168)) throw new BadRequestException({ code: 'INVALID_ENTITY_CHANGE_INTENT_TTL' });
    await this.authz.assertCluster(actor.user, cid, 'workflows', 'write', wid);
    return this.redis.withLock(`entity-change-prepare:${actor.user.id}:${key}`, async () => {
      const previous = await this.db.one<any>('SELECT * FROM entity_change_intents WHERE requester_id=$1 AND prepare_key=$2', [actor.user.id, key]);
      if (previous) { if (previous.cluster_id !== cid || previous.workspace_id !== wid || previous.request_hmac !== requestHmac) throw changed('IDEMPOTENCY_CONFLICT'); const loaded=await this.load(cid,wid,previous.id);await this.policy().assertSubject(loaded.envelope,actor.user.id,'write',this.db);return this.receipt(loaded.envelope,loaded.version.material_hmac,actor); }
      await assertEntityChangeRecycleRestoreOrigin(this.db, cid, request.change);
      const credentialEpoch = await this.identity(actor), prepared = await this.compiler.prepare(cid, request.change, actor), review = await this.compiler.project(prepared, actor), intentId = randomUUID();
      let envelope: EntityChangeIntentEnvelope | undefined;
      await this.db.transaction(async tx => {
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE'); await this.identity(actor, tx, credentialEpoch); await this.plans.definitions(cid, wid, actor.user.id, tx);
        const definition = await this.plans.definition(cid, wid, 'native-change', tx), policy = await tx.one<any>('SELECT policy,approval_format FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4', [cid, wid, definition.id, definition.version]);
        const maxHours = policy?.approval_format === 2 ? Number(policy.policy.intentTtlHours) : 168, ttlHours = value.ttlHours === undefined ? Math.min(24, maxHours) : Number(value.ttlHours);
        if (!Number.isInteger(maxHours) || ttlHours > maxHours) throw new BadRequestException({ code: 'ENTITY_CHANGE_POLICY_TTL_EXCEEDED' });
        const cluster = await tx.one<any>('SELECT execution_mode,revision FROM clusters WHERE id=$1 AND deleted_at IS NULL', [cid]);
        if (!cluster || cluster.revision !== prepared.scope.clusterRevision) throw changed('ENTITY_CHANGE_INTENT_SCOPE_CHANGED');
        const issuedAt = new Date().toISOString(), expiresAt = new Date(Date.parse(issuedAt) + ttlHours * 3600000).toISOString(), packets = normalizedEntityChangePackets(prepared, this.secrets);
        envelope = { version: 1, intentId, revision: 1, clusterId: cid, workspaceId: wid, requesterId: actor.user.id, credentialEpoch, issuedAt, expiresAt, ttlHours, executionMode: cluster.execution_mode, definition, packetManifestHmac: this.secrets.fingerprint(packets), prepared, review };
        this.materialBudget(envelope,review,packets);
        await this.policy().assertSubject(envelope, actor.user.id, 'write', tx);
        const materialHmac = this.secrets.fingerprint(envelope);
        await tx.exec(`INSERT INTO entity_change_intents(id,cluster_id,workspace_id,requester_id,credential_epoch,prepare_key,request_hmac,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [intentId, cid, wid, actor.user.id, credentialEpoch, key, requestHmac, issuedAt, expiresAt]);
        await tx.exec(`INSERT INTO entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,requester_id,credential_epoch,issued_at,expires_at,execution_mode,definition_id,definition_version,policy_hash,change_digest,material_hmac,packet_manifest_hmac,packet_count,packet_manifest,envelope_ciphertext,safe_review) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18::jsonb)`, [cid, wid, intentId, actor.user.id, credentialEpoch, issuedAt, expiresAt, cluster.execution_mode, definition.id, definition.version, definition.policyHash, prepared.changeDigest, materialHmac, envelope.packetManifestHmac, packets.length, JSON.stringify(packets), this.secrets.encrypt(envelope, entityChangeIntentAad(cid, wid, intentId, 1)), JSON.stringify(review)]);
        await bindEntityRecyclePayloadReferences(envelope,materialHmac,tx,this.secrets);
        for (const packet of packets) await tx.exec(`INSERT INTO entity_change_intent_packets(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,packet_key,packet_order,dependencies,method,path_hmac,native_type,native_id,parent_id,credential_kind,original_native_id,mutation_action,permission_action,body_hmac,before_hmac) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, [cid, wid, intentId, materialHmac, prepared.changeDigest, envelope.packetManifestHmac, packet.key, packet.order, packet.dependencies, packet.method, packet.pathHmac, packet.nativeType, packet.nativeId, packet.parentId, packet.credentialKind, packet.originalNativeId, packet.mutationAction, packet.permissionAction, packet.bodyHmac, packet.beforeHmac]);
        await this.audit.append({ actorId: actor.user.id, clusterId: cid, workspaceId: wid, entityType: 'entity_change_intents', entityId: intentId, action: 'workflow.intent.prepare', requestId: actor.requestId, ip: actor.ip, result: 'success', after: { revision: 1, changeDigest: prepared.changeDigest, nativePackets: packets.length, expiresAt }, scopeHints: { quality: 'verified', module: 'workflows', subject: { type: 'entity_change_intents', id: intentId }, beforeExists: false, afterExists: true, afterWorkspaceId: wid, afterTags: [] } }, tx);
        await this.redis.assertLeaseOwnership();
      });
      if (!envelope) throw changed('ENTITY_CHANGE_INTENT_UNCOMMITTED'); return this.receipt(envelope,this.secrets.fingerprint(envelope),actor);
    });
  }
  async prepareScheduled(cid:string,raw:unknown,actor:EntityActor):Promise<any>{
    const scheduling=this.scheduling();this.policy();const wid=workflowId(actor.workspaceId),key=workflowKey(actor.idempotencyKey),value=portalObject(raw,['change','schedule','ttlHours','confirmed','confirm_name']);
    portalConfirm(value,'scheduled-change');const spec=normalizeEntityScheduleSpec(value.schedule,actor.user.id);
    if(value.ttlHours!==undefined&&(!Number.isInteger(value.ttlHours)||Number(value.ttlHours)<1||Number(value.ttlHours)>168))throw new BadRequestException({code:'INVALID_ENTITY_CHANGE_INTENT_TTL'});
    const request={mode:'scheduled',change:entityChangeInput(value.change),schedule:spec,...(value.ttlHours!==undefined?{ttlHours:value.ttlHours}:{})},requestHmac=this.secrets.fingerprint(request);
    await this.authz.assertCluster(actor.user,cid,'workflows','write',wid);await scheduling.assertAvailable(cid,wid,this.db);
    return this.redis.withLock(`entity-change-prepare:${actor.user.id}:${key}`,async()=>{
      const previous=await this.db.one<any>('SELECT * FROM entity_change_intents WHERE requester_id=$1 AND prepare_key=$2',[actor.user.id,key]);
      if(previous){if(previous.cluster_id!==cid||previous.workspace_id!==wid||previous.request_hmac!==requestHmac)throw changed('IDEMPOTENCY_CONFLICT');
        const loaded=await this.load(cid,wid,previous.id);if(loaded.envelope.version!==2)throw changed('IDEMPOTENCY_CONFLICT');await this.policy().assertSubject(loaded.envelope,actor.user.id,'write',this.db);return this.receipt(loaded.envelope,loaded.version.material_hmac,actor);}
      await assertEntityChangeRecycleRestoreOrigin(this.db,cid,request.change);
      const epoch=await this.identity(actor),prepared=await this.compiler.prepare(cid,request.change,actor),review=await this.compiler.project(prepared,actor),intentId=randomUUID(),scheduleId=randomUUID(),delegationId=randomUUID();
      let envelope:EntityScheduledIntentEnvelopeV2|undefined;
      await this.db.transaction(async tx=>{
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await scheduling.assertAvailable(cid,wid,tx);await this.identity(actor,tx,epoch);await this.plans.definitions(cid,wid,actor.user.id,tx);
        const definition=await this.plans.definition(cid,wid,'native-change',tx),policy=await tx.one<any>('SELECT policy,approval_format FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[cid,wid,definition.id,definition.version]),
          maxHours=policy?.approval_format===2?Number(policy.policy.intentTtlHours):168,ttlHours=value.ttlHours===undefined?Math.min(24,maxHours):Number(value.ttlHours);
        if(!Number.isInteger(maxHours)||maxHours<1||maxHours>168||ttlHours>maxHours)throw new BadRequestException({code:'ENTITY_CHANGE_POLICY_TTL_EXCEEDED'});
        const cluster=await tx.one<any>('SELECT execution_mode,revision FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
        if(!cluster||cluster.revision!==prepared.scope.clusterRevision)throw changed('ENTITY_CHANGE_INTENT_SCOPE_CHANGED');
        const issuedAt=new Date().toISOString(),expiresAt=spec.windowEnd;
        if(Date.parse(spec.notBefore)<Date.parse(issuedAt)||Date.parse(expiresAt)<=Date.parse(issuedAt)||Date.parse(expiresAt)>Date.parse(issuedAt)+ttlHours*3600000)throw new BadRequestException({code:'ENTITY_SCHEDULE_WINDOW_TTL_EXCEEDED'});
        await this.compiler.revalidateStored(prepared,actor,'write','submit');await this.identity(actor,tx,epoch);
        const packets=normalizedEntityChangePackets(prepared,this.secrets),packetManifestHmac=this.secrets.fingerprint(packets),specHmac=this.secrets.fingerprint(spec),
          delegation={version:1 as const,id:delegationId,revision:1 as const,clusterId:cid,workspaceId:wid,intentId,intentRevision:1,changeDigest:prepared.changeDigest,packetManifestHmac,policyHash:definition.policyHash,
            ownerId:actor.user.id,executorId:actor.user.id,ownerCredentialEpoch:epoch,executorCredentialEpoch:epoch,issuedAt,expiresAt,specHmac,statement:'execute-this-exact-approved-entity-intent-with-my-current-authority' as const};
        envelope={version:2,intentId,revision:1,clusterId:cid,workspaceId:wid,requesterId:actor.user.id,credentialEpoch:epoch,issuedAt,expiresAt,ttlHours,executionMode:cluster.execution_mode,definition,packetManifestHmac,prepared,review,
          scheduling:{scheduleId,scheduleVersion:1,spec,specHmac,delegation,delegationHmac:this.secrets.fingerprint(delegation)}};
        this.verifyScheduledEnvelope(envelope);
        this.materialBudget(envelope,review,packets);
        await this.policy().assertSubject(envelope,actor.user.id,'write',tx);const materialHmac=this.secrets.fingerprint(envelope);
        await tx.exec(`INSERT INTO entity_change_intents(id,cluster_id,workspace_id,requester_id,credential_epoch,prepare_key,request_hmac,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[intentId,cid,wid,actor.user.id,epoch,key,requestHmac,issuedAt,expiresAt]);
        await tx.exec(`INSERT INTO entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,requester_id,credential_epoch,issued_at,expires_at,execution_mode,definition_id,definition_version,policy_hash,change_digest,material_hmac,packet_manifest_hmac,packet_count,packet_manifest,envelope_ciphertext,safe_review) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18::jsonb)`,[cid,wid,intentId,actor.user.id,epoch,issuedAt,expiresAt,cluster.execution_mode,definition.id,definition.version,definition.policyHash,prepared.changeDigest,materialHmac,packetManifestHmac,packets.length,JSON.stringify(packets),this.secrets.encrypt(envelope,entityChangeIntentAad(cid,wid,intentId,1)),JSON.stringify(review)]);
        await bindEntityRecyclePayloadReferences(envelope,materialHmac,tx,this.secrets);
        for(const packet of packets)await tx.exec(`INSERT INTO entity_change_intent_packets(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,packet_key,packet_order,dependencies,method,path_hmac,native_type,native_id,parent_id,credential_kind,original_native_id,mutation_action,permission_action,body_hmac,before_hmac) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,[cid,wid,intentId,materialHmac,prepared.changeDigest,packetManifestHmac,packet.key,packet.order,packet.dependencies,packet.method,packet.pathHmac,packet.nativeType,packet.nativeId,packet.parentId,packet.credentialKind,packet.originalNativeId,packet.mutationAction,packet.permissionAction,packet.bodyHmac,packet.beforeHmac]);
        const draft:EntityScheduledDraft={binding:{clusterId:cid,workspaceId:wid,intentId,intentRevision:1,materialHmac,changeDigest:prepared.changeDigest,packetManifestHmac},scheduleId,scheduleVersion:1,spec,specHmac,delegation,delegationHmac:envelope.scheduling.delegationHmac,transportScope:prepared.scope.transportScope,impact:prepared.impact,impactHmac:this.secrets.fingerprint(prepared.impact)};
        await scheduling.persistDraft(draft,actor,tx);await this.verifyScheduledStorage(envelope,materialHmac,tx);
        await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,entityType:'entity_change_intents',entityId:intentId,action:'workflow.intent.prepare-scheduled',requestId:actor.requestId,ip:actor.ip,result:'success',
          after:{revision:1,scheduleId,changeDigest:prepared.changeDigest,nativePackets:packets.length,notBefore:spec.notBefore,windowStart:spec.windowStart,windowEnd:spec.windowEnd,expiresAt},
          scopeHints:{quality:'verified',module:'workflows',subject:{type:'entity_change_intents',id:intentId},beforeExists:false,afterExists:true,afterWorkspaceId:wid,afterTags:[]}},tx);
        if(Date.parse(expiresAt)<=Date.now())throw changed('ENTITY_SCHEDULE_WINDOW_EXPIRED');
        await this.redis.assertLeaseOwnership();
      });
      if(!envelope)throw changed('ENTITY_CHANGE_INTENT_UNCOMMITTED');return this.receipt(envelope,this.secrets.fingerprint(envelope),actor);
    });
  }
  async get(cid: string, id: string, actor: EntityActor): Promise<any> {
    const loaded = await this.load(cid, workflowId(actor.workspaceId), workflowId(id)); await this.policy().assertSubject(loaded.envelope, actor.user.id, 'read', this.db);
    const review = await this.compiler.projectStored(loaded.envelope.prepared, actor, 'read'), submission = await this.db.one<any>('SELECT workflow_id FROM entity_change_submissions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4', [id, cid, actor.workspaceId, loaded.envelope.revision]);
    return { ...await this.receipt(loaded.envelope, loaded.version.material_hmac, actor), workflowId: submission?.workflow_id ?? null, review };
  }
  private async prepareLookupIdentity(cid:string,wid:string,actor:EntityActor):Promise<{frame:object;sessionId:string;credentialEpoch:string;permissionVersion:string}> {
    if(!this.execution)throw new ServiceUnavailableException({code:'ENTITY_CHANGE_PREPARE_LOOKUP_CONTEXT_REQUIRED'});
    const frame=this.execution.current();
    if(!['http','actor'].includes(frame.kind)||frame.actor?.id!==actor.user.id||frame.clusterId!==cid||frame.workspaceId!==wid||actor.workspaceId!==wid
      ||!frame.sessionId||frame.operation||frame.archive||frame.module!=='workflows'||frame.action!=='read'
      ||this.execution.hasEntityScheduledNamespace()||this.execution.hasWorkflowScheduledNamespace())throw new ForbiddenException({code:'ENTITY_CHANGE_PREPARE_LOOKUP_HTTP_REQUIRED'});
    const sessionId=workflowId(frame.sessionId),permissionVersion=await this.authz.permissionVersion(actor.user),credentialEpoch=await this.identity(actor);
    const session=await this.db.one<any>(`SELECT s.id,s.credential_epoch,s.expires_at FROM auth_sessions s JOIN users u ON u.id=s.user_id
      WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND s.credential_epoch=u.credential_epoch
        AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[sessionId,actor.user.id]);
    if(!session||session.id!==sessionId||String(session.credential_epoch)!==credentialEpoch||new Date(session.expires_at).getTime()<=Date.now()
      ||this.execution.current()!==frame||await this.authz.permissionVersion(actor.user)!==permissionVersion)throw new ForbiddenException({code:'ENTITY_CHANGE_PREPARE_LOOKUP_IDENTITY_CHANGED'});
    return {frame,sessionId,credentialEpoch,permissionVersion};
  }
  /** Original prepare-key lookup is deliberately read-only. A missing row is
   * an observation at this read, not proof that an in-flight write never ran.
   * Authenticate current HTTP scope before the lookup and again after every
   * historical projection; neither 404 nor a foreign key grants retry rights. */
  @KongActorScope({module:'workflows',action:'read'})
  async byPrepareKey(cid:string,key:string,actor:EntityActor):Promise<Record<string,unknown>> {
    this.policy();cid=workflowId(cid);const wid=workflowId(actor.workspaceId);key=workflowKey(key);
    const before=await this.prepareLookupIdentity(cid,wid,actor);
    await this.authz.assertCluster(actor.user,cid,'workflows','read',wid);
    const pointer=await this.db.one<any>('SELECT id,cluster_id,workspace_id,requester_id,prepare_key,request_hmac FROM entity_change_intents WHERE requester_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND prepare_key=$4',
      [actor.user.id,cid,wid,key]);
    let result:Record<string,unknown>;
    if(pointer){
      if(pointer.requester_id!==actor.user.id||pointer.cluster_id!==cid||pointer.workspace_id!==wid||pointer.prepare_key!==key||!/^[a-f\d]{64}$/.test(pointer.request_hmac??''))throw changed('ENTITY_CHANGE_PREPARE_KEY_BINDING_INVALID');
      const loaded=await this.load(cid,wid,workflowId(pointer.id));
      if(loaded.intent.prepare_key!==key||loaded.intent.request_hmac!==pointer.request_hmac||loaded.intent.requester_id!==actor.user.id||loaded.envelope.requesterId!==actor.user.id
        ||loaded.envelope.clusterId!==cid||loaded.envelope.workspaceId!==wid||!['direct','approval'].includes(loaded.envelope.executionMode))throw changed('ENTITY_CHANGE_PREPARE_KEY_BINDING_INVALID');
      await this.policy().assertSubject(loaded.envelope,actor.user.id,'read',this.db);
      const review=await this.compiler.projectStored(loaded.envelope.prepared,actor,'read');
      const submission=await this.db.one<any>('SELECT workflow_id FROM entity_change_submissions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4',
        [loaded.intent.id,cid,wid,loaded.envelope.revision]);
      result={...await this.receipt(loaded.envelope,loaded.version.material_hmac,actor),workflowId:submission?.workflow_id??null,review};
      await this.policy().assertSubject(loaded.envelope,actor.user.id,'read',this.db);
    }else result={state:'not_prepared',clusterId:cid,workspaceId:wid,idempotencyKey:key,intentId:null,nativeExecutionAvailable:false,retryWriteAllowed:false,originalOutcome:'not_observed'};
    await this.authz.assertCluster(actor.user,cid,'workflows','read',wid);
    const after=await this.prepareLookupIdentity(cid,wid,actor);
    if(after.frame!==before.frame||after.sessionId!==before.sessionId||after.credentialEpoch!==before.credentialEpoch||after.permissionVersion!==before.permissionVersion)
      throw new ForbiddenException({code:'ENTITY_CHANGE_PREPARE_LOOKUP_IDENTITY_CHANGED'});
    return result;
  }
  async submit(cid: string, id: string, raw: unknown, actor: EntityActor): Promise<any> {
    const wid = workflowId(actor.workspaceId), key = workflowKey(actor.idempotencyKey), value = portalObject(raw, ['revision', 'materialHmac', 'confirmed', 'confirm_name']); portalRevision(value.revision); portalConfirm(value, 'native-change');
    const request = { intentId: workflowId(id), ...value }, requestHmac = this.secrets.fingerprint(request);
    return this.redis.withLock(`entity-change-submit:${id}`, async () => {
      const loaded = await this.load(cid, wid, id, Number(value.revision)); if (value.materialHmac !== loaded.version.material_hmac) throw changed();
      if (actor.user.id !== loaded.envelope.requesterId) throw new ForbiddenException({ code: 'ENTITY_CHANGE_REQUESTER_REQUIRED' });
      await this.policy().assertSubject(loaded.envelope, actor.user.id, 'write', this.db);
      const previous = await this.db.one<any>('SELECT * FROM entity_change_submissions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4', [id, cid, wid, Number(value.revision)]);
      if (previous) { if (previous.actor_id !== actor.user.id || previous.submit_key !== key || previous.request_hmac !== requestHmac) throw changed('IDEMPOTENCY_CONFLICT'); return { workflowId: previous.workflow_id, submissionCompleted: true, nativeExecutionAvailable: false }; }
      const collision = await this.db.one<any>('SELECT id FROM entity_change_submissions WHERE actor_id=$1 AND submit_key=$2', [actor.user.id, key]); if (collision) throw changed('IDEMPOTENCY_CONFLICT');
      await this.identity(actor, this.db, loaded.envelope.credentialEpoch); await this.assertLiveOwner(loaded.envelope); await this.assertCurrentDefinition(loaded.envelope);
      if (Date.parse(loaded.envelope.expiresAt) <= Date.now()) throw changed('ENTITY_CHANGE_INTENT_EXPIRED');
      if(loaded.envelope.version===2)await this.scheduling().assertAvailable(cid,wid,this.db);
      await this.compiler.revalidateStored(loaded.envelope.prepared, actor, 'write', 'submit');
      const { envelope } = loaded, workflowIdValue = randomUUID(), metadata: EntityChangeWorkflowPayload = { intentId: id, intentRevision: envelope.revision, materialHmac: loaded.version.material_hmac, changeDigest: envelope.prepared.changeDigest, packetManifestHmac: envelope.packetManifestHmac }, before = this.before(envelope, metadata.materialHmac);
      const plan: WorkflowPlanV1 = { version: 1, kind: 'native-change', clusterId: cid, workspaceId: wid, workflowId: workflowIdValue, planRevision: 1, executionMode: envelope.executionMode, approvalRequired: envelope.executionMode === 'approval', subject: { type: 'entity_change_intents', id }, requester: { type: 'console', id: actor.user.id }, definition: envelope.definition, issuedAt: new Date().toISOString(), expiresAt: envelope.expiresAt, scope: { transportScope: envelope.prepared.scope.transportScope, clusterRevision: envelope.prepared.scope.clusterRevision, workspaceRevision: envelope.prepared.scope.workspaceRevision }, prerequisites: [], steps: [{ id: randomUUID(), key: 'entity.change', order: 1, kind: 'metadata', handler: 'entity.change', entityType: 'entity_change_intents', entityId: id, permissionAction: 'write', dependencies: [], nativeRequests: [], before, metadataRevision: envelope.revision, metadataBeforeHmac: this.secrets.fingerprint(before), metadata, metadataPayloadHmac: this.secrets.fingerprint(metadata) }] };
      await this.db.transaction(async tx => {
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE'); await this.identity(actor, tx, envelope.credentialEpoch); await this.assertCurrentDefinition(envelope, tx); await this.policy().assertSubject(envelope, actor.user.id, 'write', tx);
        await tx.exec(`INSERT INTO entity_change_submissions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,actor_id,submit_key,request_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12)`, [cid, wid, id, envelope.revision, metadata.materialHmac, metadata.changeDigest, metadata.packetManifestHmac, actor.user.id, key, requestHmac, workflowIdValue, this.secrets.fingerprint(plan)]);
        await this.plans.persist(plan, key, request, tx, { requestId: actor.requestId, ip: actor.ip }); await this.redis.assertLeaseOwnership();
      });
      return { workflowId: workflowIdValue, submissionCompleted: true, nativeExecutionAvailable: false };
    });
  }
}
