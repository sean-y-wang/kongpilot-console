import type {PortalPartyObservationRoundOriginal,PortalPartyObservationRoundRunner,PortalPartyObservationRoundVerifier} from './workflow-portal-party-observation.types';
import type {PortalInspectionInvocationOriginal,PortalInspectionInvocationVerifier} from './workflow-portal-inspection-invocation.types';
import { ConflictException, ForbiddenException, HttpException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { DbService, withVerificationReadMemo } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService, type KongExecutionFrame, type ScheduledPortalPreparationPhase } from '../../infrastructure/kong/execution-context.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import type { AuthUser } from '../../common/auth';
import type { EntityActor } from '../entities/entities.types';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import { WorkflowScheduleRepository, assertWorkflowScheduledPlan, normalizeWorkflowScheduleDraft } from './workflow-schedule.repository';
import { isPortalCredentialScheduleKind } from '../portal/portal-credential-lifecycle-contract';
import { assertKp007AccessIdentity, assertKp007SingleWorkerClaim, isKp007ScheduleKind } from './kp007-access-fault-contract';

import type { WorkflowPlanV1 } from './workflow.types';
import type { WorkflowApprovalCheckpoint, WorkflowApprovalSet, WorkflowScheduledApprovalFactsReader } from './workflow-approval.types';
import type { WorkflowScheduleActivation, WorkflowScheduleClaim, WorkflowScheduleDraft, WorkflowScheduleStored,
  WorkflowScheduleTerminalOutcome, WorkflowScheduleReceipt, WorkflowScheduledPlanV1, WorkflowScheduleOutcomeEvidence } from './workflow-schedule.contract';
import type { WorkflowScheduledAuthorityCheckpoint, WorkflowScheduledAuthorityInspection, WorkflowScheduledBusinessKind,
  WorkflowScheduledBusinessPolicy, WorkflowScheduledExecutorDelegate, WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { WorkflowScheduledConfigurationCheckpoint, WorkflowScheduledConfigurationRootVerifier,
  WorkflowScheduledConfigurationPromoteSqlPolicy } from './workflow-scheduled-configuration-origin.types';
import { sortByFreshFingerprint } from './workflow-fresh-fingerprint-sort';

const deny = (code: string) => new ForbiddenException({ code });
const changed = (code: string) => new ConflictException({ code });
const unavailable = (code: string) => new ServiceUnavailableException({ code });
const hex = /^[a-f\d]{64}$/;
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const checkpoints = ['inspect', 'claim', 'capture', 'step', 'packet', 'before-send'];
const kinds = ['configuration_v2', 'portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'];
type HandleState = { readonly scheduleId: string; readonly claim: Readonly<WorkflowScheduleClaim>; state: 'issued' | 'executing' | 'closed'; executorEntered:boolean;callbackEntered: boolean };
type ProofState = { readonly kind: 'draft' | 'activation' | 'claim' | 'outcome' | 'blocked' | 'no-callback'; readonly scheduleId: string;
  readonly digest: string; readonly sessionId?: string; readonly actorId?: string; readonly actorMetadataHmac?: string; readonly handle?: object; readonly completion?: object; readonly reason?: string };
type EligibilityScope = { readonly stored: WorkflowScheduleStored; readonly plan: WorkflowScheduledPlanV1; readonly tx: DbService;
  readonly checkpoint: WorkflowApprovalCheckpoint; active: boolean };
type ConfigurationNamespaceScope = EligibilityScope & { readonly frame: KongExecutionFrame; readonly namespaceHandle: object;
  readonly namespace: Readonly<WorkflowScheduledNamespaceProof> };
type ConfigurationOriginSqlVerifier = Readonly<Pick<WorkflowScheduledConfigurationRootVerifier,
  'openClosedCheckpoint' | 'assertClosedCheckpoint' | 'assertClosedCheckpointLive' | 'releaseClosedCheckpoint'>>;
type ConfigurationOriginSqlScope = { readonly frame: KongExecutionFrame; readonly frameActor: KongExecutionFrame['actor'];
  readonly frameOperation: KongExecutionFrame['operation']; readonly frameArchive: KongExecutionFrame['archive'];
  readonly frameKind: KongExecutionFrame['kind']; readonly frameAction: KongExecutionFrame['action'];
  readonly frameClusterId: KongExecutionFrame['clusterId']; readonly frameWorkspaceId: KongExecutionFrame['workspaceId'];
  readonly namespaceHandle: object; readonly namespace: Readonly<WorkflowScheduledNamespaceProof>;
  readonly checkpoint: WorkflowScheduledConfigurationCheckpoint; readonly approvalCheckpoint: WorkflowApprovalCheckpoint;
  readonly transaction: DbService; tx: DbService; stored?: Readonly<WorkflowScheduleStored>;
  state: 'opening' | 'open' | 'closing' | 'sealed' | 'poisoned' | 'released'; active: boolean; grantDeadline: number; observationHmac?: string };

type PortalInspectionFrame={readonly frame:KongExecutionFrame;readonly actor:KongExecutionFrame['actor'];readonly operation:KongExecutionFrame['operation'];
 readonly archive:KongExecutionFrame['archive'];readonly kind:KongExecutionFrame['kind'];readonly action:KongExecutionFrame['action'];
 readonly clusterId:KongExecutionFrame['clusterId'];readonly workspaceId:KongExecutionFrame['workspaceId'];readonly namespaceHandle:object;readonly namespace:Readonly<WorkflowScheduledNamespaceProof>;readonly invocation:Readonly<PortalInspectionInvocationOriginal>|null;readonly preparation:Readonly<ScheduledPortalPreparationPhase>|null;readonly containerSql:boolean;readonly observationRound:Readonly<PortalPartyObservationRoundOriginal>|null};
type PortalInspectionFact=PortalInspectionFrame&{readonly handle:object;readonly checkpoint:WorkflowScheduledAuthorityCheckpoint;readonly snapshotHmac:string;deadline:number;grantDeadline:number;readonly generation:number;consumed:boolean;};
type PortalInspectionClosing={readonly fact:PortalInspectionFrame&{readonly deadline:number};readonly current:Readonly<Pick<WorkflowScheduledAuthorityInspection,'plan'>>;readonly tx:DbService;
 readonly checkpoint:WorkflowApprovalCheckpoint;active:boolean;grantDeadline?:number;};

/** Background business eligibility and immutable occurrence identity only.
 * No HTTP Actor, borrowed SID, source INSERT, native request, scheduler timer,
 * readonly snapshot authority or EntityScheduled capability is created here.
 * Every kind requires a once-installed Root policy and true native executor. */
@Injectable()
export class WorkflowScheduledAuthorityService {
  #partyObservationRunner?:Readonly<PortalPartyObservationRoundRunner>;
  readonly #partyObservationResults=new WeakMap<object,{original:Readonly<PortalPartyObservationRoundOriginal>;deadline:number}>();
  readonly #partyInspectionGrants=new WeakMap<object,{handle:object;checkpoint:WorkflowScheduledAuthorityCheckpoint;frame:KongExecutionFrame;namespaceHandle:object;namespace:Readonly<WorkflowScheduledNamespaceProof>;deadline:number}>();
  readonly #partyObservationScope=new AsyncLocalStorage<{original:Readonly<PortalPartyObservationRoundOriginal>;active:boolean;deadline:number}>();
  readonly #partyObservationOriginals=new WeakSet<object>();
  #configurationPartyRunner?:<T>(namespace:object,phase:WorkflowScheduledAuthorityCheckpoint,tx:DbService,fn:()=>Promise<T>)=>Promise<T>;
  /** Business runtime's checkpoint-scoped configuration_v2 party round. */
  installConfigurationPartyCheckpointRunner(run:<T>(namespace:object,phase:WorkflowScheduledAuthorityCheckpoint,tx:DbService,fn:()=>Promise<T>)=>Promise<T>):void{
    if(this.#configurationPartyRunner||typeof run!=='function')throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PARTY_RUNNER_ALREADY_INSTALLED');
    this.#configurationPartyRunner=run;
  }
  installPortalPartyObservationRoundRunner(runner:Readonly<PortalPartyObservationRoundRunner>):Readonly<PortalPartyObservationRoundVerifier>{
    if(this.#partyObservationRunner||!runner||Object.keys(runner).some(key=>key!=='run')||typeof runner.run!=='function')throw deny('WORKFLOW_PORTAL_OBSERVATION_ALREADY_INSTALLED');
    this.#partyObservationRunner=Object.freeze({run:runner.run.bind(runner)});
    return Object.freeze({current:()=>{const state=this.#partyObservationScope.getStore();if(!state)return null;this.#assertPartyObservation(state.original);return state.original;},assert:(original:Readonly<PortalPartyObservationRoundOriginal>)=>this.#assertPartyObservation(original)});
  }
  #assertPartyObservation(original:Readonly<PortalPartyObservationRoundOriginal>):void{
    const state=this.#partyObservationScope.getStore();
    if(!state?.active||state.original!==original||!this.#partyObservationOriginals.has(original)||state.deadline<=performance.now()
      ||this.context.current()!==original.frame||this.context.requireWorkflowScheduledNamespaceHandle()!==original.namespaceHandle
      ||this.context.requireWorkflowScheduledCurrentPrincipal(original.namespaceHandle).namespace!==original.namespace
      ||this.context.scheduledPortalPreparationPhase()||this.context.scheduledPortalFinalNativePhase()!==original.final)
      throw deny('WORKFLOW_PORTAL_OBSERVATION_ORIGINAL_REQUIRED');
    const ancestry=this.context.originalScheduledPortalExecution();
    if((ancestry?.execution??null)!==original.execution||(ancestry?.step??null)!==original.step
      ||!isPortalCredentialScheduleKind(original.namespace.kind)||original.namespace.sessionId!==null||original.namespace.origin!=='scheduled-workflow'
      ||original.namespace.workflow.planHash!==this.secrets.fingerprint(original.plan)
      ||original.namespace.workflow.id!==original.plan.workflowId||original.frame.actor?.id!==original.namespace.actor.id
      ||original.frame.clusterId!==original.namespace.clusterId||original.frame.workspaceId!==original.namespace.workspaceId
      ||original.frame.sessionId!=null||original.frame.archive||Date.parse(original.namespace.expiresAt)<=Date.now())
      throw deny('WORKFLOW_PORTAL_OBSERVATION_ORIGINAL_REQUIRED');
    this.redis.assertLeaseActive();
  }
  async #withPartyObservation<T>(stored:WorkflowScheduleStored,tx:DbService,checkpoint:WorkflowScheduledAuthorityCheckpoint,fn:()=>Promise<T>):Promise<T>{
    if(!this.#partyObservationRunner||!isPortalCredentialScheduleKind(stored.plan.kind)||!this.context.peek()||this.context.scheduledPortalPreparationPhase()
      ||!this.context.hasWorkflowScheduledNamespace()||this.#portalInspectionFrame()?.containerSql)return fn();
    const frame=this.context.current(),namespaceHandle=this.context.requireWorkflowScheduledNamespaceHandle(),principal=this.context.requireWorkflowScheduledCurrentPrincipal(namespaceHandle),namespace=principal.namespace;
    if(frame.sessionId!=null||frame.archive||!['actor','operation','scheduled-workflow','internal-read'].includes(frame.kind)||!isPortalCredentialScheduleKind(namespace.kind)
      ||namespace.approvalSet.format!==2||principal.readOnly||principal.role!=='executor'||principal.validationReadHandle)return fn();
    if(this.#partyObservationScope.getStore())throw deny('WORKFLOW_PORTAL_OBSERVATION_REENTRY');
    const ancestry=this.context.originalScheduledPortalExecution(),handle=Object.freeze({});
    const parties=Object.freeze([{userId:namespace.actor.id,role:'executor' as const},...[...new Set(namespace.approvalSet.reviewers.map(reviewer=>reviewer.userId))].map(userId=>({userId,role:'reviewer' as const}))].map(p=>Object.freeze(p)));
    if(new Set(parties.map(p=>p.userId)).size!==parties.length)throw deny('WORKFLOW_PORTAL_OBSERVATION_PARTIES_INVALID');
    const original:Readonly<PortalPartyObservationRoundOriginal>=Object.freeze({handle,frame,namespaceHandle,namespace,execution:ancestry?.execution??null,step:ancestry?.step??null,
      final:this.context.scheduledPortalFinalNativePhase(),checkpoint,transaction:tx,plan:immutableJson(stored.plan),draft:immutableJson(stored.draft),parties});
    const state={original,active:true,deadline:Math.min(performance.now()+30000,performance.now()+Date.parse(namespace.expiresAt)-Date.now())};
    this.#partyObservationOriginals.add(original);
    try{return await this.#partyObservationScope.run(state,async()=>{this.#assertPartyObservation(original);
      const result=await this.#partyObservationRunner!.run(original,async()=>{this.#assertPartyObservation(original);const value=await fn();this.#assertPartyObservation(original);return value;});
      this.#assertPartyObservation(original);
      if(result&&typeof result==='object')this.#partyObservationResults.set(result,{original,deadline:this.#portalPreparationGrantDeadlines.get(result)??Infinity});
      return result;});}
    finally{state.active=false;this.#partyObservationOriginals.delete(original);}
  }
  private readonly handles = new WeakMap<object, HandleState>();
  readonly #portalInspectionFacts=new WeakMap<object,PortalInspectionFact>();
  readonly #portalInspectionGenerations=new WeakMap<object,number>();
  readonly #portalPreparationGrantDeadlines=new WeakMap<object,number>();
  readonly #portalInspectionClosing=new AsyncLocalStorage<PortalInspectionClosing>();
  readonly #portalInspectionTokens=new WeakMap<object,{scope:PortalInspectionClosing;phase:'issued'|'reading'|'consumed'}>();
  #portalInspectionSql?:WorkflowScheduledApprovalFactsReader;
  private readonly proofs = new WeakMap<object, ProofState>();
  private readonly policies = new Map<WorkflowScheduledBusinessKind, Readonly<WorkflowScheduledBusinessPolicy>>();
  private readonly workerOwnerHmac: string;
  private executor?: Readonly<WorkflowScheduledExecutorDelegate>;
  private storageChecksum?: string;
  private repositoryInstalled = false;
  private approvalFacts?: WorkflowScheduledApprovalFactsReader;
  private readonly eligibilityScope = new AsyncLocalStorage<EligibilityScope>();
  private readonly approvalFactsTokens = new WeakMap<object, { scope: EligibilityScope; state: 'issued' | 'reading' | 'consumed' }>();
  private configurationNamespaceFacts?: WorkflowScheduledApprovalFactsReader;
  private readonly configurationNamespaceScope = new AsyncLocalStorage<ConfigurationNamespaceScope>();
  private readonly configurationNamespaceTokens = new WeakMap<object, { scope: ConfigurationNamespaceScope; state: 'issued' | 'reading' | 'consumed' }>();
  private configurationOriginSqlInstalled = false;
  private configurationPreparationSql?:ConfigurationOriginSqlVerifier;
  private configurationOriginSqlFacts?: WorkflowScheduledApprovalFactsReader;
  private configurationOriginPromoteSql?: Readonly<WorkflowScheduledConfigurationPromoteSqlPolicy>;
  private readonly configurationOriginSqlScope = new AsyncLocalStorage<ConfigurationOriginSqlScope>();
  private readonly configurationOriginSqlWitnesses = new WeakMap<object, ConfigurationOriginSqlScope>();
  private readonly configurationOriginSqlTokens = new WeakMap<object, { scope: ConfigurationOriginSqlScope; state: 'issued' | 'reading' | 'consumed' }>();
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
    private readonly context: KongExecutionContextService, private readonly plans: WorkflowPlansService,
    private readonly approvals: WorkflowApprovalAuthorityService, private readonly repository: WorkflowScheduleRepository) {
    this.workerOwnerHmac = secrets.fingerprint({ namespace: 'business-workflow-scheduled-worker', instance: randomUUID() });
  }

  installBusinessPolicy(kind: WorkflowScheduledBusinessKind, policy: WorkflowScheduledBusinessPolicy): void {
    const methods = ['assertDraft', 'assertRequester', 'assertSubject', 'assertReviewer', 'isReceiptRead', 'assertReceiptRead'] as const;
    if (!kinds.includes(kind) || this.policies.has(kind) || !policy || methods.some(key => typeof policy[key] !== 'function')
      || Object.keys(policy).some(key => !methods.includes(key as any))) throw new Error('Each business kind requires one complete fixed scheduled policy');
    this.policies.set(kind, Object.freeze(Object.fromEntries(methods.map(key => [key, policy[key].bind(policy)]))) as unknown as Readonly<WorkflowScheduledBusinessPolicy>);
  }
  installExecutor(executor: WorkflowScheduledExecutorDelegate): void {
    if (this.executor || !executor || typeof executor.executeClaim !== 'function' || typeof executor.verifyCompletion !== 'function')
      throw new Error('A single complete business scheduled executor must be installed');
    this.executor = Object.freeze({ executeClaim: executor.executeClaim.bind(executor), verifyCompletion: executor.verifyCompletion.bind(executor) });
  }
  private policy(kind: string): Readonly<WorkflowScheduledBusinessPolicy> {
    const value = this.policies.get(kind as WorkflowScheduledBusinessKind);
    if (!value || !kinds.includes(kind)) throw unavailable('WORKFLOW_SCHEDULE_BUSINESS_POLICY_UNAVAILABLE');
    return value;
  }
  private background(): void { if (this.context.peek() !== null) throw deny('WORKFLOW_SCHEDULE_BACKGROUND_CONTEXT_REQUIRED'); }
  private async iam(tx: DbService): Promise<void> {
    if (!await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE')) throw unavailable('AUTHORIZATION_UNAVAILABLE');
  }
  private async available(tx: DbService): Promise<void> {
    if (!this.repositoryInstalled || !this.storageChecksum) throw unavailable('WORKFLOW_SCHEDULE_STORAGE_UNAVAILABLE');
    const migration = await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='026_m11_workflow_schedules.sql'");
    if (!migration || migration.checksum !== this.storageChecksum) throw unavailable('WORKFLOW_SCHEDULE_STORAGE_UNAVAILABLE');
  }
  private digest(value: unknown): string { return this.secrets.fingerprint(value); }
  private same(a: unknown, b: unknown, code: string): void { if (this.digest(a) !== this.digest(b)) throw changed(code); }
  private proof(kind: ProofState['kind'], id: string, value: unknown, extra: Partial<ProofState> = {}): object {
    const token = Object.freeze({}); this.proofs.set(token, { kind, scheduleId: id, digest: this.digest(value), ...extra }); return token;
  }
  private requireProof(token: object, kind: ProofState['kind'], id: string, value: unknown): ProofState {
    const proof = token && this.proofs.get(token);
    if (!proof || proof.kind !== kind || proof.scheduleId !== id || proof.digest !== this.digest(value)) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED');
    return proof;
  }
  private original(handle: object): HandleState {
    if (!handle || typeof handle !== 'object' || Array.isArray(handle)) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED');
    const state = this.handles.get(handle);
    if (!state || state.state === 'closed') throw deny('WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED');
    return state;
  }
  private async principal(id: string, expectedEpoch: string, tx: DbService): Promise<{ user: Readonly<AuthUser>; version: string }> {
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const row = await tx.one<any>(`SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
      FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`, [id]);
    if (!epoch || !row || row.id !== id || String(row.credential_epoch) !== expectedEpoch || row.force_password_change === true) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_REVOKED');
    return { user: immutableJson({ id: row.id, username: row.username, superAdmin: row.super_admin === true, forcePasswordChange: false,
      displayName: row.display_name, locale: row.locale, timezone: row.timezone, revision: row.revision }), version: `${row.id}:${row.permissions_epoch}:${epoch.version}` };
  }
  private async requester(draft: WorkflowScheduleDraft, plan: WorkflowScheduledPlanV1, tx: DbService): Promise<void> {
    const requester = draft.binding.requester;
    if (plan.requester.type !== requester.type || plan.requester.id !== requester.id) throw changed('WORKFLOW_SCHEDULE_REQUESTER_CHANGED');
    if (requester.type === 'developer') {
      if (!isPortalCredentialScheduleKind(plan.kind)) throw changed('WORKFLOW_SCHEDULE_REQUESTER_CHANGED');
      const row = await tx.one<any>(`SELECT id,credential_epoch,must_change_password FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
        AND status='active' AND deleted_at IS NULL AND NOT must_change_password`, [requester.id, plan.clusterId, plan.workspaceId]);
      if (!row || row.must_change_password === true || String(row.credential_epoch) !== requester.credentialEpoch) throw deny('WORKFLOW_SCHEDULE_REQUESTER_REVOKED');
    } else {
      if (plan.kind !== 'configuration_v2' || requester.id !== draft.delegation.ownerId) throw changed('WORKFLOW_SCHEDULE_REQUESTER_CHANGED');
      await this.principal(requester.id, requester.credentialEpoch, tx);
    }
    await this.policy(plan.kind).assertRequester(plan, draft, tx);
  }
  private async scope(draft: WorkflowScheduleDraft, plan: WorkflowScheduledPlanV1, tx: DbService, currentTime = true): Promise<void> {
    await this.available(tx);
    if (!plan.approvalRequired) throw unavailable('WORKFLOW_SCHEDULE_DIRECT_CONSENT_UNAVAILABLE');
    assertWorkflowScheduledPlan(plan, draft, this.secrets); const b = draft.binding, d = draft.delegation;
    if (!kinds.includes(plan.kind) || plan.kind !== b.kind || plan.workflowId !== b.workflowId || plan.planRevision !== b.workflowPlanRevision
      || this.digest(plan) !== b.workflowPlanHash || plan.clusterId !== b.clusterId || plan.workspaceId !== b.workspaceId
      || plan.subject.type !== b.subjectType || plan.subject.id !== b.subjectId || plan.scope.transportScope !== draft.transportScope
      || d.ownerId !== d.executorId || draft.spec.executorId !== d.executorId || d.ownerCredentialEpoch !== d.executorCredentialEpoch
      || this.digest(plan.scheduling) !== this.digest({ version: 1, scheduleId: draft.scheduleId, scheduleVersion: 1, occurrenceId: draft.occurrenceId,
        basePlanHash: b.basePlanHash, spec: draft.spec, specHmac: draft.specHmac, delegationId: d.id, delegationVersion: 1,
        delegationHmac: draft.delegationHmac, ownerId: d.ownerId, ownerCredentialEpoch: d.ownerCredentialEpoch,
        executorId: d.executorId, executorCredentialEpoch: d.executorCredentialEpoch, requester: b.requester,
        transportScope: draft.transportScope, impactHmac: draft.impactHmac, subjectSealHmac: this.digest(b.subjectSeal) })) throw changed('WORKFLOW_SCHEDULE_PLAN_CHANGED');
    const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [plan.clusterId]);
    const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [plan.workspaceId, plan.clusterId]);
    if (!cluster || !workspace || ['disabled', 'incompatible'].includes(cluster.status) || !/^1\.5\.\d+$/.test(cluster.version ?? '')
      || cluster.revision !== plan.scope.clusterRevision || cluster.execution_mode !== plan.executionMode || workspace.status !== 'active'
      || workspace.revision !== plan.scope.workspaceRevision || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== draft.transportScope)
      throw changed('WORKFLOW_SCHEDULE_SCOPE_CHANGED');
    this.same(await this.plans.definition(plan.clusterId, plan.workspaceId, plan.kind, tx), plan.definition, 'WORKFLOW_SCHEDULE_POLICY_CHANGED');
    if (plan.definition.id !== b.definitionId || plan.definition.version !== b.definitionVersion || plan.definition.policyHash !== b.policyHash)
      throw changed('WORKFLOW_SCHEDULE_POLICY_CHANGED');
    const deadlines = [plan.expiresAt, d.expiresAt, draft.spec.windowEnd].map(Date.parse);
    if (deadlines.some(t => !Number.isFinite(t)) || currentTime && Math.min(...deadlines) <= Date.now()) throw changed('WORKFLOW_SCHEDULE_WINDOW_EXPIRED');
  }
  private async actualActor(draft: WorkflowScheduleDraft, plan: WorkflowScheduledPlanV1, actor: EntityActor, action: 'read' | 'write' | 'approve', tx: DbService): Promise<void> {
    if (this.policy(plan.kind).isReceiptRead()) throw deny('WORKFLOW_SCHEDULE_RECEIPT_READ_ONLY');
    const frame = this.context.peek();
    if (!frame?.sessionId || frame.actor?.id !== actor.user.id || frame.clusterId !== plan.clusterId || frame.workspaceId !== plan.workspaceId
      || actor.workspaceId !== plan.workspaceId) throw deny('WORKFLOW_SCHEDULE_ACTUAL_ACTOR_REQUIRED');
    const session = await tx.one<any>(`SELECT s.id,u.credential_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`, [frame.sessionId, actor.user.id]);
    if (!session) throw deny('SESSION_EXPIRED');
    await this.principal(actor.user.id, String(session.credential_epoch), tx);
    await this.policy(plan.kind).assertSubject(plan, actor.user.id, action, 'inspect', tx);
    if (actor.user.id === draft.delegation.ownerId && String(session.credential_epoch) !== draft.delegation.ownerCredentialEpoch)
      throw deny('WORKFLOW_SCHEDULE_EXECUTOR_REVOKED');
  }
  private async currentPlan(stored: WorkflowScheduleStored, tx: DbService): Promise<WorkflowScheduledPlanV1> {
    const b = stored.draft.binding, loaded = await this.plans.load(b.clusterId, b.workspaceId, b.workflowId, tx);
    this.same(loaded.plan, stored.plan, 'WORKFLOW_SCHEDULE_PLAN_CHANGED');
    if (!['approved', 'executing'].includes(loaded.row.state)) throw changed('WORKFLOW_SCHEDULE_APPROVAL_REQUIRED');
    if (stored.progress.state !== 'claimed' && stored.progress.state !== 'running' && loaded.row.state !== 'approved') throw changed('WORKFLOW_SCHEDULE_ALREADY_EXECUTED');
    return stored.plan;
  }
  private activation(plan: WorkflowPlanV1, set: WorkflowApprovalSet): WorkflowScheduleActivation {
    return { workflowId: plan.workflowId, workflowPlanRevision: plan.planRevision, workflowPlanHash: this.digest(plan),
      approvalFormat: set.format, approvalRequired: true, approvalSetId: set.setId, approvalSetHmac: set.setHmac };
  }
  private assertEligibilityScope(scope: EligibilityScope): void {
    if (!scope.active || this.eligibilityScope.getStore() !== scope || this.context.peek() !== null
      || scope.plan !== scope.stored.plan || this.digest(scope.plan) !== scope.stored.draft.binding.workflowPlanHash)
      throw deny('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED');
    this.redis.assertLeaseActive();
  }
  private async approvalFactsGate(original: object, plan: WorkflowPlanV1, checkpoint: WorkflowApprovalCheckpoint,
    tx: DbService, phase: 'enter' | 'leave'): Promise<void> {
    const state = original && this.approvalFactsTokens.get(original);
    if (!state || state.state !== (phase === 'enter' ? 'issued' : 'reading') || state.scope.plan !== plan
      || state.scope.tx !== tx || state.scope.checkpoint !== checkpoint) throw deny('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED');
    this.assertEligibilityScope(state.scope); await this.redis.assertLeaseOwnership(); this.assertEligibilityScope(state.scope);
    if (this.approvalFactsTokens.get(original) !== state || state.state !== (phase === 'enter' ? 'issued' : 'reading'))
      throw deny('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED');
    state.state = phase === 'enter' ? 'reading' : 'consumed';
  }
  private async readApprovalFacts(scope: EligibilityScope): Promise<WorkflowApprovalSet> {
    this.assertEligibilityScope(scope); const token = Object.freeze({});
    this.approvalFactsTokens.set(token, { scope, state: 'issued' });
    try {
      const result = await this.approvalFacts!(token, scope.plan, Object.freeze({ checkpoint: scope.checkpoint }), scope.tx);
      this.assertEligibilityScope(scope);
      if (this.approvalFactsTokens.get(token)?.state !== 'consumed') throw deny('WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED');
      return result;
    } finally { this.approvalFactsTokens.delete(token); }
  }
  private assertConfigurationNamespaceScope(scope: ConfigurationNamespaceScope): void {
    const frame = this.context.current(), namespace = this.context.requireWorkflowScheduledValidationNamespaceProof(scope.namespaceHandle);
    const principal = this.context.requireWorkflowScheduledCurrentPrincipal(scope.namespaceHandle), { draft, plan } = scope.stored;
    if (!scope.active || this.configurationNamespaceScope.getStore() !== scope || frame !== scope.frame || namespace !== scope.namespace
      || principal.namespace !== namespace || principal.actor !== namespace.actor || principal.role !== 'executor' || principal.readOnly
      || principal.validationReadHandle !== undefined || frame.sessionId != null || !['scheduled-workflow', 'actor'].includes(frame.kind)
      || frame.action !== 'write' || frame.operation || frame.archive || frame.actor?.id !== namespace.actor.id
      || frame.clusterId !== namespace.clusterId || frame.workspaceId !== namespace.workspaceId
      || plan !== scope.plan || plan.kind !== 'configuration_v2' || namespace.kind !== 'configuration_v2' || namespace.approvalSet.format !== 2
      || namespace.origin !== 'scheduled-workflow' || namespace.sessionId !== null || namespace.actor.id !== draft.delegation.executorId
      || namespace.workflow.id !== plan.workflowId || namespace.workflow.planRevision !== plan.planRevision
      || namespace.workflow.planHash !== draft.binding.workflowPlanHash || this.digest(plan) !== draft.binding.workflowPlanHash
      || namespace.clusterId !== plan.clusterId || namespace.workspaceId !== plan.workspaceId
      || namespace.claim.scheduleId !== draft.scheduleId || namespace.claim.occurrenceId !== draft.occurrenceId
      || namespace.claim.workflowId !== plan.workflowId || namespace.claim.workflowPlanRevision !== plan.planRevision
      || namespace.claim.workflowPlanHash !== draft.binding.workflowPlanHash || namespace.claim.executorId !== draft.delegation.executorId
      || namespace.credentialEpoch !== draft.delegation.executorCredentialEpoch || namespace.claim.delegationId !== draft.delegation.id
      || namespace.claim.delegationHmac !== draft.delegationHmac || namespace.claim.specHmac !== draft.specHmac
      || namespace.claim.windowStart !== draft.spec.windowStart || namespace.claim.windowEnd !== draft.spec.windowEnd
      || namespace.transportScope !== draft.transportScope || namespace.subjectSealHmac !== this.digest(draft.binding.subjectSeal)
      || !Number.isFinite(Date.parse(namespace.expiresAt)) || Date.parse(namespace.expiresAt) <= Date.now())
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED');
    this.redis.assertLeaseActive();
  }
  private async configurationNamespaceFactsGate(original: object, plan: WorkflowPlanV1, checkpoint: WorkflowApprovalCheckpoint,
    tx: DbService, phase: 'enter' | 'leave'): Promise<void> {
    const state = original && this.configurationNamespaceTokens.get(original);
    if (!state || state.state !== (phase === 'enter' ? 'issued' : 'reading') || state.scope.plan !== plan
      || state.scope.tx !== tx || state.scope.checkpoint !== checkpoint) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED');
    this.assertConfigurationNamespaceScope(state.scope); await this.redis.assertLeaseOwnership(); this.assertConfigurationNamespaceScope(state.scope);
    if (this.configurationNamespaceTokens.get(original) !== state || state.state !== (phase === 'enter' ? 'issued' : 'reading'))
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED');
    state.state = phase === 'enter' ? 'reading' : 'consumed';
  }
  private async readConfigurationNamespaceFacts(scope: ConfigurationNamespaceScope): Promise<WorkflowApprovalSet> {
    this.assertConfigurationNamespaceScope(scope);
    if (!this.configurationNamespaceFacts) throw unavailable('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_UNAVAILABLE');
    const token = Object.freeze({}); this.configurationNamespaceTokens.set(token, { scope, state: 'issued' });
    try {
      const result = await this.configurationNamespaceFacts(token, scope.plan, Object.freeze({ checkpoint: scope.checkpoint }), scope.tx);
      this.assertConfigurationNamespaceScope(scope);
      if (this.configurationNamespaceTokens.get(token)?.state !== 'consumed') throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED');
      return result;
    } finally { this.configurationNamespaceTokens.delete(token); }
  }
  private assertConfigurationOriginSqlScope(scope: ConfigurationOriginSqlScope): void {
    if (!scope.active || this.configurationOriginSqlScope.getStore() !== scope || !['opening', 'closing'].includes(scope.state))
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
    this.assertConfigurationOriginSqlOriginal(scope);
  }
  /** Shared synchronous original-frame/time fence. A sealed comparison witness
   * uses it after the final await without reentering SQL or an ALS reader. */
  private assertConfigurationOriginSqlOriginal(scope: ConfigurationOriginSqlScope): void {
    const frame = this.context.current(), namespace = this.context.requireWorkflowScheduledValidationNamespaceProof(scope.namespaceHandle);
    const principal = this.context.requireWorkflowScheduledCurrentPrincipal(scope.namespaceHandle);
    if (frame !== scope.frame || frame.actor !== scope.frameActor || frame.operation !== scope.frameOperation || frame.archive !== scope.frameArchive
      || frame.kind !== scope.frameKind || frame.action !== scope.frameAction || frame.clusterId !== scope.frameClusterId || frame.workspaceId !== scope.frameWorkspaceId
      || namespace !== scope.namespace || principal.namespace !== namespace
      || principal.actor !== namespace.actor || principal.role !== 'executor' || principal.readOnly !== false || principal.validationReadHandle !== undefined
      || frame.sessionId != null || frame.actor?.id !== namespace.actor.id
      || ['http', 'workflow-candidate-read', 'workflow-validation-read', 'system-read'].includes(frame.kind) || frame.clusterId !== namespace.clusterId
      || namespace.origin !== 'scheduled-workflow' || namespace.sessionId !== null || namespace.kind !== 'configuration_v2'
      || namespace.approvalSet.format !== 2 || !namespace.approvalSet.reviewers.length
      || !['step', 'packet', 'before-send'].includes(scope.checkpoint)
      || !Number.isFinite(Date.parse(namespace.expiresAt)) || Date.parse(namespace.expiresAt) <= Date.now()
      || performance.now() >= scope.grantDeadline)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
    if (scope.stored) {
      const { draft, plan, claim, latestLease, progress, activation } = scope.stored, d = draft.delegation, b = draft.binding;
      const projection = claim && { ...claim, clusterId: b.clusterId, workspaceId: b.workspaceId, ownerId: d.ownerId, executorId: d.executorId,
        ownerCredentialEpoch: d.ownerCredentialEpoch, executorCredentialEpoch: d.executorCredentialEpoch, delegationId: d.id, delegationVersion: 1,
        delegationHmac: draft.delegationHmac, specHmac: draft.specHmac, windowStart: draft.spec.windowStart, windowEnd: draft.spec.windowEnd,
        impactHmac: draft.impactHmac, subjectSealHmac: d.subjectSealHmac };
      const deadlines = [namespace.expiresAt, claim?.authorityExpiresAt, latestLease?.leaseUntil, plan.expiresAt, d.expiresAt, draft.spec.windowEnd].map(value => Date.parse(value ?? ''));
      const source = b.subjectSeal.sourceScopes, promote = b.subjectSeal.driver === 'governance-promote';
      const supportedSubject = promote ? source.length === 1 && uuid.test(source[0].clusterId) && uuid.test(source[0].workspaceId)
        && hex.test(source[0].materialHmac) && (source[0].clusterId !== b.clusterId || source[0].workspaceId !== b.workspaceId)
        : ['configuration-apply', 'configuration-rollback'].includes(b.subjectSeal.driver) && source.length === 0;
      if (plan.kind !== 'configuration_v2' || !plan.approvalRequired || plan.requester.type !== 'console' || plan.requester.id !== namespace.actor.id
        || !supportedSubject
        || plan.clusterId !== namespace.clusterId || plan.workspaceId !== namespace.workspaceId || this.digest(plan) !== namespace.workflow.planHash
        || plan.workflowId !== namespace.workflow.id || plan.planRevision !== namespace.workflow.planRevision
        || namespace.clusterRevision !== plan.scope.clusterRevision || namespace.workspaceRevision !== plan.scope.workspaceRevision
        || namespace.transportScope !== draft.transportScope || namespace.credentialEpoch !== d.executorCredentialEpoch
        || namespace.actor.id !== d.executorId || d.ownerId !== d.executorId || d.ownerCredentialEpoch !== d.executorCredentialEpoch
        || this.digest(namespace.requester) !== this.digest(b.requester) || namespace.subjectSealHmac !== this.digest(b.subjectSeal)
        || !claim || this.digest(projection) !== this.digest(namespace.claim) || claim.generation !== 1 || claim.scheduleVersion !== 1
        || !latestLease || latestLease.version !== 1 || latestLease.generation !== 1 || latestLease.previousId !== null
        || latestLease.claimId !== claim.id || latestLease.workerOwnerHmac !== claim.workerOwnerHmac || latestLease.leaseUntil !== claim.initialLeaseUntil
        || !['claimed', 'running'].includes(progress.state) || progress.claimId !== claim.id || !activation
        || this.digest(activation) !== this.digest(this.activation(plan, namespace.approvalSet))
        || deadlines.some(value => !Number.isFinite(value) || value <= Date.now())
        || !Number.isFinite(Date.parse(draft.spec.windowStart)) || !Number.isFinite(Date.parse(draft.spec.notBefore))
        || Date.now() < Date.parse(draft.spec.windowStart) || Date.now() < Date.parse(draft.spec.notBefore))
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_BINDING_CHANGED');
    }
    this.redis.assertLeaseActive();
    if (Date.parse(namespace.expiresAt) <= Date.now() || performance.now() >= scope.grantDeadline)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_EXPIRED');
  }
  private async observeConfigurationOriginSql<T>(scope: ConfigurationOriginSqlScope, fn: () => Promise<T>): Promise<T> {
    this.assertConfigurationOriginSqlScope(scope); await this.redis.assertLeaseOwnership(); this.assertConfigurationOriginSqlScope(scope);
    const value = await fn(); this.assertConfigurationOriginSqlScope(scope);
    await this.redis.assertLeaseOwnership(); this.assertConfigurationOriginSqlScope(scope); return value;
  }
  private async configurationOriginSqlFactsGate(original: object, plan: WorkflowPlanV1, checkpoint: WorkflowApprovalCheckpoint,
    tx: DbService, phase: 'enter' | 'leave'): Promise<void> {
    const state = original && this.configurationOriginSqlTokens.get(original);
    if (!state || state.state !== (phase === 'enter' ? 'issued' : 'reading') || state.scope.stored?.plan !== plan
      || state.scope.tx !== tx || state.scope.approvalCheckpoint !== checkpoint)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
    await this.observeConfigurationOriginSql(state.scope, async () => undefined);
    if (this.configurationOriginSqlTokens.get(original) !== state || state.state !== (phase === 'enter' ? 'issued' : 'reading'))
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
    state.state = phase === 'enter' ? 'reading' : 'consumed';
  }
  private async readConfigurationOriginSqlFacts(scope: ConfigurationOriginSqlScope): Promise<WorkflowApprovalSet> {
    this.assertConfigurationOriginSqlScope(scope);
    if (!scope.stored || !this.configurationOriginSqlFacts) throw unavailable('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_UNAVAILABLE');
    const token = Object.freeze({}); this.configurationOriginSqlTokens.set(token, { scope, state: 'issued' });
    try {
      const result = await this.observeConfigurationOriginSql(scope, () => this.configurationOriginSqlFacts!(token, scope.stored!.plan,
        Object.freeze({ checkpoint: scope.approvalCheckpoint }), scope.tx));
      if (this.configurationOriginSqlTokens.get(token)?.state !== 'consumed' || result.format !== 2)
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
      this.same(result, scope.namespace.approvalSet, 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED'); return result;
    } finally { this.configurationOriginSqlTokens.delete(token); }
  }
  /** The SQL view uses transaction-stable now(). Observe the actual binding
   * against database wall time and retain a conservative monotonic deadline;
   * an open SQL transaction cannot keep an expired grant in this witness. */
  private limitConfigurationOriginSql(scope: ConfigurationOriginSqlScope, expiry: unknown, databaseTime: unknown, started: number): void {
    if (expiry == null) return;
    const remaining = new Date(expiry as any).getTime() - new Date(databaseTime as any).getTime();
    if (!Number.isFinite(remaining) || remaining <= 0) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_EXPIRED');
    scope.grantDeadline = Math.min(scope.grantDeadline, started + remaining);
    this.assertConfigurationOriginSqlScope(scope);
  }
  private async configurationOriginSqlParties(scope: ConfigurationOriginSqlScope): Promise<unknown> {
    const tx = scope.tx, ids = [...new Set([scope.namespace.actor.id, ...scope.namespace.approvalSet.reviewers.map(reviewer => reviewer.userId)])].sort();
    const parties: unknown[] = [];
    for (const id of ids) {
      const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
      const user = await tx.one<any>(`SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
        FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`, [id]);
      if (!epoch || !user || user.id !== id || user.force_password_change || !/^[1-9]\d*$/.test(String(user.credential_epoch))
        || !/^[1-9]\d*$/.test(String(user.permissions_epoch)) || !/^[1-9]\d*$/.test(String(epoch.version)))
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_PRINCIPAL_REVOKED');
      const actor = { id: user.id, username: user.username, superAdmin: user.super_admin === true, forcePasswordChange: false,
        displayName: user.display_name, locale: user.locale, timezone: user.timezone, revision: user.revision };
      if (id === scope.namespace.actor.id && (String(user.credential_epoch) !== scope.namespace.credentialEpoch
        || `${id}:${user.permissions_epoch}:${epoch.version}` !== scope.namespace.permissionVersion || this.digest(actor) !== this.digest(scope.namespace.actor)))
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_PRINCIPAL_CHANGED');
      const started = performance.now();
      const rows = await tx.query<any>(`SELECT to_jsonb(g) AS grant,
        CASE WHEN g.binding_source='user' THEN to_jsonb(ub) WHEN g.binding_source='team' THEN to_jsonb(tb) END AS binding,
        CASE WHEN g.binding_source='user' THEN ub.expires_at WHEN g.binding_source='team' THEN tb.expires_at END AS binding_expires_at,
        CASE WHEN g.binding_source='user' THEN ub.id IS NOT NULL AND ub.status='active' AND(ub.expires_at IS NULL OR ub.expires_at>clock_timestamp())
          WHEN g.binding_source='team' THEN tb.id IS NOT NULL AND tb.status='active' AND tm.user_id IS NOT NULL AND(tb.expires_at IS NULL OR tb.expires_at>clock_timestamp())
          ELSE false END AS binding_current, clock_timestamp() AS observed_at
        FROM iam_effective_grants g
        LEFT JOIN user_role_bindings ub ON g.binding_source='user' AND ub.id=g.binding_id AND ub.user_id=g.user_id AND ub.role_id=g.role_id
        LEFT JOIN team_role_bindings tb ON g.binding_source='team' AND tb.id=g.binding_id AND tb.role_id=g.role_id
        LEFT JOIN team_members tm ON g.binding_source='team' AND tm.team_id=tb.team_id AND tm.user_id=g.user_id AND tm.status='active'
        WHERE g.user_id=$1`, [id]);
      for (const row of rows) {
        if (!row.grant || !row.binding || row.grant.user_id !== id || row.binding_current !== true
          || row.grant.binding_id !== row.binding.id || row.grant.role_id !== row.binding.role_id
          || row.grant.binding_source === 'user' && row.binding.user_id !== id)
          throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_GRANT_CHANGED');
        this.limitConfigurationOriginSql(scope, row.binding_expires_at, row.observed_at, started);
      }
      // Keep every complete grant/provenance row. No scope, module, secret,
      // field or reviewer selection is removed from the comparison witness.
      const grants = sortByFreshFingerprint(rows.map(row => ({ grant: row.grant, binding: row.binding })), row => this.digest(row));
      parties.push({ user, iamEpoch: String(epoch.version), grants });
    }
    return parties;
  }
  private async configurationOriginPromoteMaterial(scope: ConfigurationOriginSqlScope, job: Record<string, any>): Promise<unknown> {
    const policy = this.configurationOriginPromoteSql, stored = scope.stored!;
    if (!policy) throw unavailable('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_UNAVAILABLE');
    const started = performance.now(), observed = await this.observeConfigurationOriginSql(scope,
      () => policy.observe(stored.plan, stored.draft, scope.tx));
    const source = stored.draft.binding.subjectSeal.sourceScopes[0], lineage = observed?.configurationLineage;
    const origin = observed?.sourceOrigin, jobOrigin = origin?.jobOrigin, planOrigin = origin?.planOrigin;
    const deadlineKeys = ['importAuthority', 'importJob', 'importPlan', 'applyAuthority', 'applyJob', 'applyVersion',
      'configurationPlan', 'wrapperPlan', 'delegation', 'windowEnd'];
    if (!observed || observed.version !== 1 || observed.jobId !== job.id || observed.marker?.kind !== 'governance-promote'
      || observed.marker.id !== job.required_origin_id || observed.marker.hmac !== job.required_origin_hmac
      || !origin || origin.marker?.kind !== observed.marker.kind || origin.marker?.id !== observed.marker.id || origin.marker?.hmac !== observed.marker.hmac
      || !jobOrigin || jobOrigin.job_id !== job.id || jobOrigin.cluster_id !== job.cluster_id || jobOrigin.workspace_id !== job.workspace_id
      || jobOrigin.origin_kind !== observed.marker.kind || jobOrigin.origin_id !== observed.marker.id || jobOrigin.material_hmac !== observed.marker.hmac
      || jobOrigin.source_cluster_id !== source.clusterId || jobOrigin.source_workspace_id !== source.workspaceId || !uuid.test(jobOrigin.comparison_id ?? '')
      || !planOrigin || planOrigin.job_id !== job.id || planOrigin.cluster_id !== job.cluster_id || planOrigin.workspace_id !== job.workspace_id
      || planOrigin.plan_id !== job.plan_id || planOrigin.plan_revision !== job.plan_revision || planOrigin.plan_hash !== job.plan_hash
      || planOrigin.origin_kind !== observed.marker.kind || planOrigin.origin_id !== observed.marker.id || planOrigin.material_hmac !== observed.marker.hmac
      || !lineage || !uuid.test(lineage.importJobId) || !uuid.test(lineage.importPlanId)
      || lineage.importJobId === job.id || lineage.importPlanId === job.plan_id
      || !observed.deadlines || Object.keys(observed.deadlines).sort().join(',') !== [...deadlineKeys].sort().join(',')
      || !Number.isFinite(Date.parse(observed.observedAt)) || !Array.isArray(observed.registries) || observed.registries.length !== 2
      || observed.registries[0]?.cluster?.id !== source.clusterId || observed.registries[0]?.workspace?.id !== source.workspaceId
      || observed.registries[1]?.cluster?.id !== stored.plan.clusterId || observed.registries[1]?.workspace?.id !== stored.plan.workspaceId)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_MATERIAL_REQUIRED');
    this.same(observed.subjectSeal, stored.draft.binding.subjectSeal, 'WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_MATERIAL_CHANGED');
    if (lineage.authorityExpiresAt !== observed.deadlines.importAuthority || lineage.expiresAt !== observed.deadlines.importJob
      || lineage.planExpiresAt !== observed.deadlines.importPlan)
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_MATERIAL_REQUIRED');
    for (const value of Object.values(observed.deadlines)) {
      if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_MATERIAL_REQUIRED');
      this.limitConfigurationOriginSql(scope, value, observed.observedAt, started);
    }
    // The fixed observer owns authenticated lineage and expected physical
    // source/target identities. Its wall-clock sample is an expiry input,
    // never changing comparison material. Keep every other private fact.
    const { observedAt: _clock, ...material } = observed; return material;
  }
  private async configurationOriginSqlSnapshot(scope: ConfigurationOriginSqlScope): Promise<string> {
    const tx = scope.tx, original = scope.stored;
    const stored = await this.observeConfigurationOriginSql(scope, () => this.repository.inspectStored(scope.namespace.claim.scheduleId, tx));
    if (original) this.same(stored, original, 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_BINDING_CHANGED');
    else scope.stored = stored;
    this.assertConfigurationOriginSqlScope(scope);
    const { draft, plan } = scope.stored!;
    const epochBefore = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (!epochBefore) throw unavailable('AUTHORIZATION_UNAVAILABLE');
    const current = async () => {
      await this.observeConfigurationOriginSql(scope, () => this.scope(draft, plan, tx));
      // This fixed installed material policy authenticates/decrypts the exact
      // sealed subject, including ordinary/Promote marker and source scopes.
      await this.observeConfigurationOriginSql(scope, () => this.requester(draft, plan, tx));
      const workflow = await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [plan.workflowId, plan.clusterId, plan.workspaceId]);
      if (!workflow || !['approved', 'executing'].includes(workflow.state) || workflow.plan_revision !== plan.planRevision
        || workflow.plan_hash !== scope.namespace.workflow.planHash || Number(workflow.approval_format) !== 2)
        throw changed('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_BINDING_CHANGED');
      const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [plan.clusterId]);
      const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [plan.workspaceId, plan.clusterId]);
      if (!cluster || !workspace || cluster.id !== plan.clusterId || workspace.id !== plan.workspaceId || workspace.cluster_id !== plan.clusterId
        || ['disabled', 'incompatible'].includes(cluster.status) || !/^1\.5\.\d+$/.test(cluster.version ?? '') || workspace.status !== 'active'
        || cluster.revision !== scope.namespace.clusterRevision || workspace.revision !== scope.namespace.workspaceRevision
        || cluster.execution_mode !== plan.executionMode || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== scope.namespace.transportScope)
        throw changed('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_REGISTRY_CHANGED');
      // Probe observations update timestamps/health without a registry revision.
      // Compare the existing authorization contract's connection/version/scope
      // identity, while every sample separately rejects disabled/incompatible.
      const registry = { cluster: { id: cluster.id, version: cluster.version, revision: cluster.revision, executionMode: cluster.execution_mode,
        deletedAt: cluster.deleted_at, adminUrl: cluster.admin_url, transportScope: cluster.transport_scope, connectionSecret: cluster.connection_secret },
        workspace: { id: workspace.id, clusterId: workspace.cluster_id, revision: workspace.revision, status: workspace.status,
          deletedAt: workspace.deleted_at, code: workspace.code } };
      const started = performance.now();
      const subject = await tx.one<any>(`SELECT to_jsonb(j) AS job,clock_timestamp() AS observed_at FROM configuration_jobs j
        WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3`, [plan.subject.id, plan.clusterId, plan.workspaceId]);
      const promote = draft.binding.subjectSeal.driver === 'governance-promote';
      const supportedOrigin = subject?.job && (promote ? subject.job.kind === 'apply' && subject.job.required_origin_kind === 'governance-promote'
        && uuid.test(subject.job.required_origin_id ?? '') && hex.test(subject.job.required_origin_hmac ?? '')
        && draft.binding.subjectSeal.sourceScopes[0]?.materialHmac === subject.job.required_origin_hmac
        : subject.job.required_origin_kind == null && subject.job.required_origin_id == null && subject.job.required_origin_hmac == null);
      if (!subject?.job || subject.job.state !== 'running' || subject.job.actor_id !== scope.namespace.actor.id || subject.job.workflow_id !== plan.workflowId
        || !supportedOrigin
        || !Number.isSafeInteger(subject.job.lease_generation) || subject.job.lease_generation < 1 || !hex.test(subject.job.lease_owner_hash ?? ''))
        throw changed('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_SUBJECT_CHANGED');
      for (const deadline of [subject.job.authority_expires_at, subject.job.expires_at]) {
        if (deadline == null) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_EXPIRED');
        this.limitConfigurationOriginSql(scope, deadline, subject.observed_at, started);
      }
      // A same-generation heartbeat may refresh lease_until. Its current DB
      // wall-time liveness is required, while fixed authority/grant deadlines
      // above can only shorten. No mutable progress/counter fields are used
      // as immutable evidence; the fixed requester policy rechecks the full
      // existing immutableJob/material/plan subject seal on every round.
      if (subject.job.lease_until == null || !Number.isFinite(Date.parse(subject.job.lease_until))
        || Date.parse(subject.job.lease_until) <= new Date(subject.observed_at).getTime())
        throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_EXPIRED');
      const promotion = promote ? await this.configurationOriginPromoteMaterial(scope, subject.job) : undefined;
      return { workflow, registry, subjectSeal: draft.binding.subjectSeal, ...(promote ? { promotion } : {}),
        job: { state: subject.job.state, leaseGeneration: subject.job.lease_generation, leaseOwnerHash: subject.job.lease_owner_hash,
          authorityExpiresAt: subject.job.authority_expires_at, expiresAt: subject.job.expires_at } };
    };
    const material = await current(), approvalSet = await this.readConfigurationOriginSqlFacts(scope), parties = await this.configurationOriginSqlParties(scope);
    this.same(await current(), material, 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_MATERIAL_CHANGED');
    this.same(await this.readConfigurationOriginSqlFacts(scope), approvalSet, 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
    this.same(await this.configurationOriginSqlParties(scope), parties, 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_GRANT_CHANGED');
    this.same(await this.observeConfigurationOriginSql(scope, () => this.repository.inspectStored(scope.namespace.claim.scheduleId, tx)), stored,
      'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_BINDING_CHANGED');
    this.same(await current(), material, 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_MATERIAL_CHANGED');
    const epochAfter = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (!epochAfter || String(epochAfter.version) !== String(epochBefore.version))
      throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_PRINCIPAL_CHANGED');
    this.assertConfigurationOriginSqlScope(scope);
    return this.digest({ material, approvalSet, parties });
  }
  /** Bootstrap gives Root one fixed open/close pair. The opaque object stores
   * comparison evidence only: every close repeats canonical SQL and every
   * principal/grant/material observation. It grants no Native authority. */
  installScheduledConfigurationOriginSqlVerifier(promoteSql: WorkflowScheduledConfigurationPromoteSqlPolicy): ConfigurationOriginSqlVerifier {
    if (this.configurationOriginSqlInstalled) throw new Error('One fixed scheduled configuration Origin SQL verifier is required');
    if (!promoteSql || typeof promoteSql.observe !== 'function' || Object.keys(promoteSql).some(key => key !== 'observe'))
      throw new Error('One fixed complete scheduled configuration Promote SQL observer is required');
    this.configurationOriginPromoteSql = Object.freeze({ observe: promoteSql.observe.bind(promoteSql) });
    this.configurationOriginSqlFacts = this.approvals.installScheduledConfigurationOriginSqlReader({
      enter: (original, plan, checkpoint, tx) => this.configurationOriginSqlFactsGate(original, plan, checkpoint, tx, 'enter'),
      leave: (original, plan, checkpoint, tx) => this.configurationOriginSqlFactsGate(original, plan, checkpoint, tx, 'leave'),
    });
    this.configurationOriginSqlInstalled = true;
    const verifier:ConfigurationOriginSqlVerifier=Object.freeze({
      openClosedCheckpoint: async (namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>, checkpoint: WorkflowScheduledConfigurationCheckpoint, transaction: DbService): Promise<object> => {
        if (this.configurationOriginSqlScope.getStore() || this.eligibilityScope.getStore() || this.configurationNamespaceScope.getStore()
          || !transaction || typeof transaction.one !== 'function' || typeof transaction.query !== 'function')
          throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
        const frame = this.context.current(), token = Object.freeze({});
        const scope: ConfigurationOriginSqlScope = { frame, frameActor: frame.actor, frameOperation: frame.operation, frameArchive: frame.archive,
          frameKind: frame.kind, frameAction: frame.action, frameClusterId: frame.clusterId, frameWorkspaceId: frame.workspaceId, namespaceHandle, namespace, checkpoint,
          approvalCheckpoint: checkpoint === 'step' ? 'step' : 'packet', transaction, tx: undefined as unknown as DbService,
          state: 'opening', active: true, grantDeadline: Infinity };
        // Capture original bound methods once. The proxy exposes only fixed
        // SELECT reads and never falls through to pool/private/mutation APIs.
        const one = transaction.one.bind(transaction), query = transaction.query.bind(transaction);
        scope.tx = new Proxy(Object.create(null), { get: (_target, key) => {
          if (key === 'one' || key === 'query') return (sql: string, args?: unknown[]) => {
            if (typeof sql !== 'string' || !/^\s*SELECT\b/i.test(sql)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_READ_ONLY');
            return this.observeConfigurationOriginSql(scope, () => key === 'one' ? one(sql, args) : query(sql, args));
          };
          throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_READ_ONLY');
        } }) as DbService;
        this.configurationOriginSqlWitnesses.set(token, scope);
        try {
          return await this.configurationOriginSqlScope.run(scope, async () => {
            this.assertConfigurationOriginSqlScope(scope);
            scope.observationHmac = await this.configurationOriginSqlSnapshot(scope);
            this.assertConfigurationOriginSqlScope(scope); scope.state = 'open'; return token;
          });
        } catch (error) { scope.state = 'released'; this.configurationOriginSqlWitnesses.delete(token); throw error; }
        finally { scope.active = false; }
      },
      assertClosedCheckpoint: async (token: object, namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>, checkpoint: WorkflowScheduledConfigurationCheckpoint, transaction: DbService): Promise<void> => {
        const scope = token && this.configurationOriginSqlWitnesses.get(token);
        if (!scope) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
        if (scope.state !== 'open') {
          scope.state = 'poisoned'; scope.active = false;
          throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
        }
        scope.state = 'closing'; scope.active = true;
        try {
          if (scope.namespaceHandle !== namespaceHandle || scope.namespace !== namespace || scope.checkpoint !== checkpoint
            || scope.transaction !== transaction || this.context.current() !== scope.frame || this.configurationOriginSqlScope.getStore()
            || this.eligibilityScope.getStore() || this.configurationNamespaceScope.getStore())
            throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
          await this.configurationOriginSqlScope.run(scope, async () => {
            this.assertConfigurationOriginSqlScope(scope);
            const current = await this.configurationOriginSqlSnapshot(scope);
            if (!scope.observationHmac || scope.observationHmac !== current) throw changed('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_OBSERVATION_CHANGED');
            await this.observeConfigurationOriginSql(scope, async () => undefined);
          });
          if (scope.state !== 'closing' || !scope.active) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
          this.assertConfigurationOriginSqlOriginal(scope);
          const preparation=typeof this.context.scheduledConfigurationPreparationPhase==='function'?this.context.scheduledConfigurationPreparationPhase():null;
          if(preparation)this.context.limitScheduledConfigurationPreparation(preparation,scope.grantDeadline);
          scope.state = 'sealed';
        } catch (error) { scope.state = 'poisoned'; throw error; }
        finally { scope.active = false; }
      },
      assertClosedCheckpointLive: (token: object, namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>, checkpoint: WorkflowScheduledConfigurationCheckpoint, transaction: DbService): void => {
        const scope = token && this.configurationOriginSqlWitnesses.get(token);
        if (!scope) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
        try {
          if (scope.state !== 'sealed' || scope.active || scope.namespaceHandle !== namespaceHandle || scope.namespace !== namespace
            || scope.checkpoint !== checkpoint || scope.transaction !== transaction || this.configurationOriginSqlScope.getStore()
            || this.eligibilityScope.getStore() || this.configurationNamespaceScope.getStore())
            throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ORIGINAL_REQUIRED');
          this.assertConfigurationOriginSqlOriginal(scope);
        } catch (error) { scope.state = 'poisoned'; scope.active = false; throw error; }
      },
      releaseClosedCheckpoint: (token: object): void => {
        const scope = token && this.configurationOriginSqlWitnesses.get(token);
        if (scope) { scope.state = 'released'; scope.active = false; this.configurationOriginSqlWitnesses.delete(token); }
      },
    });
    this.configurationPreparationSql=verifier;return verifier;
  }

  private async eligibility(stored: WorkflowScheduleStored, tx: DbService, checkpoint: WorkflowScheduledAuthorityCheckpoint): Promise<Omit<WorkflowScheduledAuthorityInspection, 'version' | 'claim' | 'leaseUntil' | 'authorityExpiresAt'>> {
    const current=()=>this.#eligibilityCurrent(stored,tx,checkpoint);
    // configuration_v2: executor + reviewers of THIS eligibility checkpoint
    // share one Kong point observation (fresh grants per party). Never across checkpoints.
    if(stored.plan.kind==='configuration_v2'&&this.#configurationPartyRunner&&this.context.peek()){
      let namespace:object|undefined;
      try{namespace=this.context.requireWorkflowScheduledNamespaceHandle();if(this.context.requireWorkflowScheduledCurrentPrincipal(namespace).namespace.kind!=='configuration_v2')namespace=undefined;}catch{namespace=undefined;}
      if(namespace)return this.#configurationPartyRunner(namespace,checkpoint,tx,current);
    }
    return this.#withPartyObservation(stored,tx,checkpoint,current);
  }
  async #eligibilityCurrent(stored:WorkflowScheduleStored,tx:DbService,checkpoint:WorkflowScheduledAuthorityCheckpoint):Promise<Omit<WorkflowScheduledAuthorityInspection,'version'|'claim'|'leaseUntil'|'authorityExpiresAt'>>{
    if (this.eligibilityScope.getStore() || this.configurationNamespaceScope.getStore()||this.#portalInspectionClosing.getStore()) throw deny('WORKFLOW_SCHEDULE_APPROVAL_FACTS_REENTRANT');
    const { draft } = stored, plan = await this.currentPlan(stored, tx), d = draft.delegation;
    await this.scope(draft, plan, tx); await this.requester(draft, plan, tx);
    const principal = await this.principal(d.executorId, d.executorCredentialEpoch, tx);
    // KP-007: sealed plan/delegation vs current binding must agree on the five
    // access dimensions before any claim/execute/approval-facts read.
    if (isKp007ScheduleKind(plan.kind)) {
      assertKp007AccessIdentity(
        { actorId: d.executorId, clusterId: plan.clusterId, workspaceId: plan.workspaceId,
          entityId: plan.subject.id, originalExecutorId: d.executorId },
        { actorId: principal.user.id, clusterId: draft.binding.clusterId, workspaceId: draft.binding.workspaceId,
          entityId: draft.binding.subjectId, originalExecutorId: draft.spec.executorId });
    }

    const approvalCheckpoint: WorkflowApprovalCheckpoint = checkpoint === 'claim' || checkpoint === 'inspect' ? 'claim' : checkpoint === 'capture' ? 'snapshot' : checkpoint === 'step' ? 'step' : 'packet';
    const frame = this.context.peek();
    // The background facts reader and the narrowly bound configuration
    // Namespace reader have separate original tokens and SQL policies.
    const scope: EligibilityScope | null = frame === null ? { stored, plan, tx, checkpoint: approvalCheckpoint, active: true } : null;
    let configurationScope: ConfigurationNamespaceScope | null = null;
    if (frame && frame.sessionId == null && ['scheduled-workflow', 'actor'].includes(frame.kind) && frame.action === 'write'
      && !frame.operation && !frame.archive && plan.kind === 'configuration_v2' && this.context.hasWorkflowScheduledNamespace()) {
      const namespaceHandle = this.context.requireWorkflowScheduledNamespaceHandle(), namespace = this.context.requireWorkflowScheduledValidationNamespaceProof(namespaceHandle);
      if (namespace.kind === 'configuration_v2' && namespace.approvalSet.format === 2)
        configurationScope = { stored, plan, tx, checkpoint: approvalCheckpoint, active: true, frame, namespaceHandle, namespace };
    }
    const portalFrame=this.#portalInspectionFrame(),partyRound=this.#partyObservationScope.getStore();
    // The true raw round binds current user/team wall-clock grants before SDK
    // observations, then closes the same complete party facts after all reads.
    const observationParties=partyRound?await this.#portalPrincipalSnapshot({draft,approvalSet:partyRound.original.namespace.approvalSet,permissionVersion:principal.version},tx):null;
    if(observationParties){partyRound!.deadline=Math.min(partyRound!.deadline,observationParties.grantDeadline);this.#assertPartyObservation(partyRound!.original);}
    // A genuine SDK preparation phase has no Native authority. Its original
    // packet is verified against all current SQL facts here; the final wire
    // gate remains outside this phase and performs every real party SDK read.
    if(!portalFrame?.preparation&&!portalFrame?.containerSql)await this.policy(plan.kind).assertSubject(plan, d.executorId, 'write', checkpoint, tx);
    if(portalFrame?.invocation&&portalFrame.invocation.checkpoint!==checkpoint)throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_CHECKPOINT_CHANGED');
    const portalScope:PortalInspectionClosing|null=portalFrame&&isPortalCredentialScheduleKind(plan.kind)
      ?{fact:{...portalFrame,deadline:Math.min(performance.now()+30000,performance.now()+Date.parse(portalFrame.namespace.expiresAt)-Date.now())},current:{plan},tx,checkpoint:approvalCheckpoint,active:true}:null;
    const verify = async () => {
      if (portalScope)this.#assertPortalInspectionClosing(portalScope);
      if (scope) this.assertEligibilityScope(scope);
      if (configurationScope) this.assertConfigurationNamespaceScope(configurationScope);
      const approvalSet = scope ? await this.readApprovalFacts(scope) : configurationScope ? await this.readConfigurationNamespaceFacts(configurationScope)
        : portalScope?await this.#readPortalInspectionFacts(portalScope):await this.approvals.verifyApprovalSet(plan, { checkpoint: approvalCheckpoint }, tx);
      if (!approvalSet.reviewers.length || approvalSet.policyHash !== plan.definition.policyHash) throw changed('WORKFLOW_SCHEDULE_APPROVAL_REQUIRED');
      const preparationParties=portalFrame&&(portalFrame.preparation||portalFrame.containerSql)?await this.#portalPrincipalSnapshot({draft,approvalSet,permissionVersion:principal.version},tx):null;
      if(preparationParties){portalScope!.grantDeadline=preparationParties.grantDeadline;
        if(portalFrame!.preparation)this.context.limitScheduledPortalPreparation(portalFrame!.preparation,preparationParties.grantDeadline);this.#assertPortalInspectionClosing(portalScope!);}
      for (const reviewer of approvalSet.reviewers) {
        const user = await tx.one<any>("SELECT id FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [reviewer.userId]);
        if (!user) throw deny('WORKFLOW_SCHEDULE_REVIEWER_REVOKED');
        if(!portalFrame?.preparation&&!portalFrame?.containerSql)await this.policy(plan.kind).assertReviewer(plan, reviewer.userId, checkpoint, tx);
        if (scope) this.assertEligibilityScope(scope);
        if (configurationScope) this.assertConfigurationNamespaceScope(configurationScope);
      }
      if (scope && approvalSet.format === 2) {
        // A second fresh SQL-only observation closes approval/candidate and
        // registry changes during the final real Native reviewer scans.
        await this.scope(draft, plan, tx); await this.requester(draft, plan, tx);
        this.same(await this.readApprovalFacts(scope), approvalSet, 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
      }
      if (configurationScope) {
        // Repeat every canonical SQL-only rule, not just set HMACs: a job
        // state or exact broad approval grant may change during Native reads.
        await this.scope(draft, plan, tx); await this.requester(draft, plan, tx);
        this.same(await this.readConfigurationNamespaceFacts(configurationScope), approvalSet, 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
      }
      if(portalScope){
        // Ordinary checkpoints have just completed every reviewer's genuine
        // SDK scope. A hard-private SDK preparation performs SQL prechecks
        // only; it cannot be selected at the final Native gate. Both paths
        // repeat current candidate/credential/membership and grant facts.
        await this.scope(draft,plan,tx);await this.requester(draft,plan,tx);
        this.same(await this.#readPortalInspectionFacts(portalScope),approvalSet,'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
        this.#assertPortalInspectionClosing(portalScope);
      }
      if (stored.activation) this.same(stored.activation, this.activation(plan, approvalSet), 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
      const current = await this.principal(d.executorId, d.executorCredentialEpoch, tx);
      if (current.version !== principal.version) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_PERMISSIONS_CHANGED');
      if (scope) { await this.redis.assertLeaseOwnership(); this.assertEligibilityScope(scope); }
      if (configurationScope) { await this.redis.assertLeaseOwnership(); this.assertConfigurationNamespaceScope(configurationScope); }
      if(portalScope){await this.redis.assertLeaseOwnership();this.#assertPortalInspectionClosing(portalScope);}
      const result={ draft: immutableJson(draft), plan: immutableJson(plan), approvalSet: immutableJson(approvalSet), principal: principal.user, permissionVersion: principal.version };
      if(preparationParties){const closing=await this.#portalPrincipalSnapshot(result,tx);this.#assertPortalInspectionClosing(portalScope!);
        if(closing.hmac!==preparationParties.hmac)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_PRINCIPAL_CHANGED');
        const deadline=Math.min(preparationParties.grantDeadline,closing.grantDeadline);portalScope!.grantDeadline=deadline;
        if(portalFrame!.preparation)this.context.limitScheduledPortalPreparation(portalFrame!.preparation,deadline);
        this.#portalPreparationGrantDeadlines.set(result,deadline);this.#assertPortalInspectionClosing(portalScope!);}
      if(observationParties){const closing=await this.#portalPrincipalSnapshot(result,tx);this.#assertPartyObservation(partyRound!.original);
        if(closing.hmac!==observationParties.hmac)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_PRINCIPAL_CHANGED');
        partyRound!.deadline=Math.min(partyRound!.deadline,observationParties.grantDeadline,closing.grantDeadline);
        this.#portalPreparationGrantDeadlines.set(result,Math.min(observationParties.grantDeadline,closing.grantDeadline));this.#assertPartyObservation(partyRound!.original);}
      return result;
    };
    if (scope) { try { return await this.eligibilityScope.run(scope, verify); } finally { scope.active = false; } }
    if (configurationScope) { try { return await this.configurationNamespaceScope.run(configurationScope, verify); } finally { configurationScope.active = false; } }
    if(portalScope){try{return await this.#portalInspectionClosing.run(portalScope,verify);}finally{portalScope.active=false;}}
    return verify();
  }
  private due(stored: WorkflowScheduleStored): void {
    const now = Date.now(), spec = stored.draft.spec;
    if ([spec.windowEnd, spec.windowStart, spec.notBefore].some(t => !Number.isFinite(Date.parse(t))) || now >= Date.parse(spec.windowEnd)) throw changed('WORKFLOW_SCHEDULE_WINDOW_EXPIRED');
    if (now < Date.parse(spec.notBefore) || now < Date.parse(spec.windowStart)) throw changed('WORKFLOW_SCHEDULE_NOT_DUE');
  }
  private async physical(stored: WorkflowScheduleStored, tx: DbService, ownClaim?: string): Promise<void> {
    const d = stored.draft;
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))", [d.transportScope]);
    const collision = await tx.one(`SELECT s.id FROM workflow_schedules s JOIN workflow_schedule_progress p ON p.schedule_id=s.id
      WHERE s.id<>$1 AND s.transport_scope=$2 AND p.state IN('active','claimed','running','uncertain')
      AND(p.state='uncertain' OR s.window_start<$4 AND $3<s.window_end) AND m6_rejected_impact_collision(s.impact,$5::jsonb)
      UNION ALL SELECT s.id FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
      WHERE s.transport_scope=$2 AND p.state IN('active','claimed','running','uncertain')
      AND(p.state='uncertain' OR s.window_start<$4 AND $3<s.window_end) AND m6_rejected_impact_collision(s.impact,$5::jsonb) LIMIT 1`,
      [d.scheduleId, d.transportScope, d.spec.windowStart, d.spec.windowEnd, JSON.stringify(d.impact)]);
    if (collision) throw changed('WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT');
    if (await tx.one(`SELECT m.id FROM mutation_operations m WHERE m.state IN('pending','running','uncertain')
      AND(m.transport_scope=$1 OR m.transport_scope IS NULL AND m.cluster_id=$2) AND m6_rejected_impact_collision(m.impact,$3::jsonb)
      AND NOT(m.state IN('pending','running') AND $4::uuid IS NOT NULL AND EXISTS(SELECT 1 FROM workflow_execution_origins o
        WHERE o.claim_id=$4 AND o.cluster_id=$2 AND o.workspace_id=$5 AND o.workflow_id=m.workflow_id AND o.executor_id=$6 AND m.actor_id=$6
        AND(o.execution_id=m.workflow_execution_id OR m.workflow_execution_id IS NULL AND m.configuration_execution_id IS NOT NULL
          AND EXISTS(SELECT 1 FROM workflow_configuration_execution_origins co WHERE co.wrapper_origin_id=o.id AND co.claim_id=o.claim_id
            AND co.cluster_id=o.cluster_id AND co.workspace_id=o.workspace_id AND co.workflow_execution_id=o.execution_id
            AND co.workflow_id=o.workflow_id AND co.workflow_plan_revision=o.workflow_plan_revision AND co.workflow_plan_hash=o.workflow_plan_hash
            AND co.configuration_execution_id=m.configuration_execution_id AND co.configuration_job_id=m.configuration_job_id
            AND co.configuration_plan_revision=m.configuration_plan_revision AND co.configuration_plan_hash=m.configuration_plan_hash)))) LIMIT 1`,
      [d.transportScope, d.binding.clusterId, JSON.stringify(d.impact), ownClaim ?? null, d.binding.workspaceId, d.delegation.executorId])) throw changed('WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT');
  }

  /** Root supplies the frozen migration checksum when installing providers.
   * A missing, modified or not-yet-applied SQL026 remains explicitly closed. */
  installRepositoryPolicies(storageChecksum: string): void {
    if (this.repositoryInstalled || !hex.test(storageChecksum ?? '')) throw new Error('Scheduled business storage requires one exact migration contract');
    this.approvalFacts = this.approvals.installScheduledEligibilityFactsReader({
      enter: (original, plan, checkpoint, tx) => this.approvalFactsGate(original, plan, checkpoint, tx, 'enter'),
      leave: (original, plan, checkpoint, tx) => this.approvalFactsGate(original, plan, checkpoint, tx, 'leave'),
    });
    this.configurationNamespaceFacts = this.approvals.installScheduledConfigurationEligibilityFactsReader({
      enter: (original, plan, checkpoint, tx) => this.configurationNamespaceFactsGate(original, plan, checkpoint, tx, 'enter'),
      leave: (original, plan, checkpoint, tx) => this.configurationNamespaceFactsGate(original, plan, checkpoint, tx, 'leave'),
    });
    if(typeof this.approvals.installScheduledPortalInspectionSqlReader==='function')this.#portalInspectionSql=this.approvals.installScheduledPortalInspectionSqlReader({
      enter:(token,plan,checkpoint,tx)=>this.#portalInspectionFactsGate(token,plan,checkpoint,tx,'enter'),
      leave:(token,plan,checkpoint,tx)=>this.#portalInspectionFactsGate(token,plan,checkpoint,tx,'leave'),
    });
    this.repository.installFixedDelegate({
      verifyDraft: async (draft, actor, proof, tx) => {
        const privateProof = this.requireProof(proof, 'draft', draft.scheduleId, draft);
        const frame = this.context.peek();
        if (!frame?.sessionId || frame.sessionId !== privateProof.sessionId || actor.user.id !== privateProof.actorId || actor.user.id !== draft.delegation.ownerId)
          throw deny('WORKFLOW_SCHEDULE_ACTUAL_OWNER_REQUIRED');
        const { plan } = await this.plans.load(draft.binding.clusterId, draft.binding.workspaceId, draft.binding.workflowId, tx);
        await this.scope(draft, plan as WorkflowScheduledPlanV1, tx); await this.requester(draft, plan as WorkflowScheduledPlanV1, tx);
        await this.actualActor(draft, plan as WorkflowScheduledPlanV1, actor, 'write', tx);
        await this.policy(plan.kind).assertDraft(plan, draft, actor, tx);
      },
      verifyApproved: async (id, activation, proof, tx, actor) => {
        const fact = this.requireProof(proof, 'activation', id, activation), frame = this.context.peek();
        if (!actor || frame?.sessionId !== fact.sessionId || actor.user.id !== fact.actorId || fact.actorMetadataHmac !== this.actorMetadataHmac(actor))
          throw deny('WORKFLOW_SCHEDULE_ACTUAL_ACTOR_REQUIRED');
        const stored = await this.repository.inspectStored(id, tx);
        await this.actualActor(stored.draft, stored.plan, actor, actor.user.id === stored.draft.delegation.ownerId ? 'write' : 'approve', tx);
        const eligible = await this.eligibility(stored, tx, 'claim');
        this.same(activation, this.activation(eligible.plan, eligible.approvalSet), 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
      },
      verifyClaim: async (id, claim, proof, tx) => {
        this.requireProof(proof, 'claim', id, claim); const stored = await this.repository.inspectStored(id, tx);
        await this.eligibility(stored, tx, 'claim'); this.due(stored);
        if (!stored.activation || claim.scheduleId !== id || claim.scheduleVersion !== 1 || claim.occurrenceId !== stored.draft.occurrenceId
          || claim.workerOwnerHmac !== this.workerOwnerHmac || claim.generation !== 1) throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
        this.same({ workflowId: claim.workflowId, workflowPlanRevision: claim.workflowPlanRevision, workflowPlanHash: claim.workflowPlanHash },
          { workflowId: stored.plan.workflowId, workflowPlanRevision: stored.plan.planRevision, workflowPlanHash: stored.draft.binding.workflowPlanHash }, 'WORKFLOW_SCHEDULE_CLAIM_CHANGED');
        await this.redis.assertLeaseOwnership();
      },
      verifyLease: async () => { throw unavailable('WORKFLOW_SCHEDULE_LEASE_EXTENSION_UNAVAILABLE'); },
      verifyCancellation: async (id, actor, tx) => {
        const stored = await this.repository.inspectStored(id, tx);
        if (actor.user.id !== stored.draft.delegation.ownerId) throw deny('WORKFLOW_SCHEDULE_ACTUAL_OWNER_REQUIRED');
        await this.actualActor(stored.draft, stored.plan, actor, 'write', tx);
      },
      verifyPhysicalReservation: async (id, proof, tx) => {
        const actual = this.proofs.get(proof);
        if (!actual || actual.scheduleId !== id || !['activation', 'claim'].includes(actual.kind)) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED');
        await this.physical(await this.repository.inspectStored(id, tx), tx);
      },
      verifyOutcome: async (claimId, outcome, proof, tx) => {
        const p = this.proofs.get(proof);
        if (p?.kind === 'no-callback' && p.handle) {
          const handle = this.original(p.handle); this.requireProof(proof, 'no-callback', handle.scheduleId, { claimId, outcome });
          if (outcome !== 'failed' || handle.state !== 'executing' || handle.callbackEntered || handle.claim.id !== claimId)
            throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
          await this.redis.assertLeaseOwnership();
          const facts = await this.noCallbackFacts(handle, tx);
          return immutableJson({ version: 1, provenance: 'callback-not-entered', evidenceHmac: this.digest({ facts, reason: p.reason ?? null }) });
        }
        if (!p?.handle || !p.completion || !this.executor) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED');
        const handle = this.original(p.handle); this.requireProof(proof, 'outcome', handle.scheduleId, { claimId, outcome });
        if (handle.state !== 'executing' || !handle.callbackEntered || handle.claim.id !== claimId
          || await this.executor.verifyCompletion(p.handle, p.completion, tx) !== outcome) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED');
        return this.outcomeFacts(handle, outcome, tx);
      },
      verifyBlocked: async (id, reason, proof) => { this.requireProof(proof, 'blocked', id, reason); },
      assertRead: async (id, actor, tx) => { const stored = await this.repository.inspectStored(id, tx), policy = this.policy(stored.plan.kind);
        if (policy.isReceiptRead()) await policy.assertReceiptRead(stored, actor, tx);
        else await this.actualActor(stored.draft, stored.plan, actor, 'read', tx); },
    });
    this.storageChecksum = storageChecksum; this.repositoryInstalled = true;
  }
  /** Internal server preparer only. Fixed business compiler and current real
   * HTTP acceptance are rechecked inside the same repository transaction. */
  async persistPreparedDraft(draft: Readonly<WorkflowScheduleDraft>, actor: EntityActor, transaction?: DbService): Promise<WorkflowScheduleReceipt> {
    normalizeWorkflowScheduleDraft(draft, this.secrets);
    const persist = async (tx: DbService) => {
      await this.available(tx); await this.iam(tx);
      const frame = this.context.peek(); if (!frame?.sessionId || frame.actor?.id !== actor.user.id) throw deny('WORKFLOW_SCHEDULE_ACTUAL_ACTOR_REQUIRED');
      const digest = this.digest(draft), token = this.proof('draft', draft.scheduleId, draft, { sessionId: frame.sessionId, actorId: actor.user.id });
      try {
        const value = await this.repository.persistDraft(draft, actor, token, tx);
        if (this.digest(draft) !== digest) throw changed('WORKFLOW_SCHEDULE_DRAFT_CHANGED'); return value;
      } finally { this.proofs.delete(token); }
    };
    return transaction ? persist(transaction) : this.db.transaction(persist);
  }
  async activateApproved(id: string, actor: EntityActor, transaction?: DbService): Promise<WorkflowScheduleReceipt> {
    const activate = async (tx: DbService) => {
      await this.available(tx); await this.iam(tx); const stored = await this.repository.inspectStored(id, tx);
      await this.actualActor(stored.draft, stored.plan, actor, actor.user.id === stored.draft.delegation.ownerId ? 'write' : 'approve', tx);
      const eligible = await this.eligibility(stored, tx, 'claim');
      if (stored.progress.state !== 'pending-approval' || stored.progress.claimId) throw changed('WORKFLOW_SCHEDULE_ALREADY_ACTIVATED');
      const activation = this.activation(eligible.plan, eligible.approvalSet), proof = this.proof('activation', id, activation,
        { actorId: actor.user.id, sessionId: this.context.peek()!.sessionId!, actorMetadataHmac: this.actorMetadataHmac(actor) });
      try { return await this.repository.activate(id, activation, proof, tx, actor); } finally { this.proofs.delete(proof); }
    };
    return transaction ? activate(transaction) : this.db.transaction(activate);
  }
  private actorMetadataHmac(actor: EntityActor): string {
    return this.digest({ userId: actor.user.id, workspaceId: actor.workspaceId, requestId: actor.requestId ?? null, ip: actor.ip ?? null });
  }
  async acquireDueClaim(id: string): Promise<object | null> {
    this.background(); if (!this.executor) throw unavailable('WORKFLOW_SCHEDULE_EXECUTOR_UNAVAILABLE'); await this.available(this.db);
    const original = await this.repository.inspectStored(id, this.db);
    if (original.progress.state !== 'active' || original.progress.claimId) return null;
    return this.redis.withLock(`workflow:${original.plan.workflowId}`, async () => {
      try {
        const claim = await this.db.transaction(async tx => {
          await this.iam(tx); const stored = await this.repository.inspectStored(id, tx);
          if (stored.progress.state !== 'active' || stored.progress.claimId) return null;
          if (!stored.activation) throw changed('WORKFLOW_SCHEDULE_APPROVAL_REQUIRED');
          await this.eligibility(stored, tx, 'claim'); this.due(stored); await this.physical(stored, tx); await this.redis.assertLeaseOwnership();
          const now = Date.now(), expiry = Math.min(now + 300000, Date.parse(stored.plan.expiresAt), Date.parse(stored.draft.delegation.expiresAt), Date.parse(stored.draft.spec.windowEnd));
          const value: WorkflowScheduleClaim = { id: randomUUID(), scheduleId: id, scheduleVersion: 1, occurrenceId: stored.draft.occurrenceId,
            generation: 1, workerOwnerHmac: this.workerOwnerHmac, workflowId: stored.plan.workflowId,
            workflowPlanRevision: stored.plan.planRevision, workflowPlanHash: stored.draft.binding.workflowPlanHash,
            issuedAt: new Date(now).toISOString(), authorityExpiresAt: new Date(expiry).toISOString(), initialLeaseUntil: new Date(expiry).toISOString() };
          const proof = this.proof('claim', id, value);
          try { return await this.repository.appendDueClaim(id, value, proof, tx); } finally { this.proofs.delete(proof); }
        });
        if (!claim) return null;
        assertKp007SingleWorkerClaim([{ scheduleId: id, workerOwnerHmac: claim.workerOwnerHmac, generation: claim.generation }]);
        if (claim.workerOwnerHmac !== this.workerOwnerHmac) throw deny('KP007_SINGLE_CLAIM_OWNER_INVALID');
        const handle = Object.freeze({}); this.handles.set(handle, { scheduleId: id, claim: immutableJson(claim), state: 'issued', executorEntered:false,callbackEntered: false }); return handle;
      } catch (error) {
        const actual = error instanceof HttpException ? (error.getResponse() as any)?.code : undefined;
        const code = error instanceof ForbiddenException && ['WORKFLOW_APPROVER_NO_LONGER_ELIGIBLE', 'WORKFLOW_APPROVER_SELECTOR_REVOKED'].includes(actual)
          ? 'WORKFLOW_SCHEDULE_REVIEWER_REVOKED' : actual;
        // Only a genuine preclaim authorization denial can terminalize these
        // current business-material checks; keep its actual actor-neutral reason.
        const currentAuthorityRevoked = error instanceof ForbiddenException && ['WORKFLOW_BUSINESS_CONFIGURATION_OWNER_CHANGED',
          'WORKFLOW_BUSINESS_SUBJECT_GRANT_REQUIRED', 'WORKFLOW_SCHEDULE_EXECUTOR_PERMISSIONS_CHANGED'].includes(actual);
        if (currentAuthorityRevoked || ['WORKFLOW_SCHEDULE_EXECUTOR_REVOKED', 'WORKFLOW_SCHEDULE_REQUESTER_REVOKED', 'WORKFLOW_SCHEDULE_REVIEWER_REVOKED',
          'WORKFLOW_SCHEDULE_SUBJECT_SCOPE_DENIED',
          'WORKFLOW_SCHEDULE_WINDOW_EXPIRED', 'WORKFLOW_SCHEDULE_SCOPE_CHANGED', 'WORKFLOW_SCHEDULE_POLICY_CHANGED',
          'WORKFLOW_SCHEDULE_APPROVAL_REQUIRED', 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED', 'WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT',
          'KP007_ACCESS_ACTOR_MISMATCH', 'KP007_ACCESS_CLUSTER_MISMATCH', 'KP007_ACCESS_WORKSPACE_MISMATCH',
          'KP007_ACCESS_ENTITY_MISMATCH', 'KP007_ACCESS_EXECUTOR_MISMATCH', 'KP007_ACCESS_EXECUTOR_NOT_ACTOR'].includes(code)) {
          const proof = this.proof('blocked', id, code); try { await this.repository.appendBlocked(id, code, proof); } finally { this.proofs.delete(proof); } return null;
        }
        throw error;
      }
    });
  }
  /** This selector reads Context's real private Namespace ancestry. It is
   * never constructed from the inspection DTO or a caller-supplied frame. */
  #portalInvocationVerifier:Readonly<PortalInspectionInvocationVerifier>|undefined;
  installPortalInspectionInvocationVerifier(verifier:Readonly<PortalInspectionInvocationVerifier>):void{
    if(this.#portalInvocationVerifier||!verifier||Object.keys(verifier).some(k=>!['current','assert'].includes(k))||typeof verifier.current!=='function'||typeof verifier.assert!=='function')
      throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ALREADY_INSTALLED');
    this.#portalInvocationVerifier=Object.freeze({current:verifier.current.bind(verifier),assert:verifier.assert.bind(verifier)});
  }
  #portalInspectionFrame():PortalInspectionFrame|null{
    const frame=this.context.peek(),preparation=typeof this.context.scheduledPortalPreparationPhase==='function'?this.context.scheduledPortalPreparationPhase():null;
    const observationRound=this.#partyObservationScope.getStore()?.original??null;
    if(observationRound)this.#assertPartyObservation(observationRound);
    if(preparation)this.context.assertScheduledPortalPreparationPhase(preparation);
    if(!frame||!['operation','actor','scheduled-workflow',...(preparation||observationRound?['internal-read']:[])].includes(frame.kind)||frame.sessionId!=null||frame.archive||!this.#portalInspectionSql||!this.context.hasWorkflowScheduledNamespace())return null;
    const namespaceHandle=this.context.requireWorkflowScheduledNamespaceHandle(),principal=this.context.requireWorkflowScheduledCurrentPrincipal(namespaceHandle),namespace=principal.namespace;
    if(!isPortalCredentialScheduleKind(namespace.kind)||namespace.approvalSet.format!==2||principal.role!=='executor'||principal.readOnly||principal.validationReadHandle
      ||frame.actor?.id!==namespace.actor.id||frame.clusterId!==namespace.clusterId||frame.workspaceId!==namespace.workspaceId)return null;
    const invocation=this.#portalInvocationVerifier?.current()??null;
    // MutationActor's actual action is create. Only Core's original private
    // mutation frame plus the original NativeStep may enter this SQL-only
    // container; an action string, copied frame or ordinary actor is no key.
    const originalCreate=frame.kind==='actor'&&frame.action==='create'&&invocation?.step?.kind==='native'
      &&typeof this.context.isOriginalPortalNativeMutationFrame==='function'&&this.context.isOriginalPortalNativeMutationFrame(frame);
    if(!preparation&&!observationRound&&(frame.kind==='operation'?!frame.operation:frame.operation||frame.action!=='write'&&!originalCreate||!invocation))return null;
    if(preparation&&(preparation.namespaceHandle!==namespaceHandle||preparation.namespace!==namespace||preparation.execution!==preparation.step.execution
      ||preparation.execution.origin!=='scheduled-workflow'||preparation.execution.sessionId!==null||preparation.execution.scheduleClaimId!==namespace.claim.id
      ||preparation.execution.actorId!==namespace.actor.id||preparation.execution.clusterId!==namespace.clusterId||preparation.execution.workspaceId!==namespace.workspaceId))
      throw deny('WORKFLOW_SCHEDULE_PORTAL_PREPARATION_ORIGINAL_REQUIRED');
    if(invocation){this.#portalInvocationVerifier!.assert(invocation);
      if(invocation.frame!==frame||invocation.namespaceHandle!==namespaceHandle||invocation.namespace!==namespace||invocation.execution.actorId!==namespace.actor.id
        ||invocation.execution.clusterId!==namespace.clusterId||invocation.execution.workspaceId!==namespace.workspaceId||invocation.execution.scheduleClaimId!==namespace.claim.id)
        throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ORIGINAL_REQUIRED');}
    // An already issued original Execution/NativeStep is a container and
    // binding precheck, never a Native permit. Metadata, final physical wire,
    // response and any proofless actor retain complete live SDK authority.
    let containerSql=false;
    if(invocation&&!preparation&&['step','packet'].includes(invocation.checkpoint)
      &&(invocation.step===null||invocation.step.kind==='native')
      &&!(typeof this.context.scheduledPortalFinalNativePhase==='function'&&this.context.scheduledPortalFinalNativePhase())){
      let currentStep:ReturnType<KongExecutionContextService['currentApprovedStep']>|null=null;
      try{currentStep=this.context.currentApprovedStep();}catch(error:any){if(error?.getResponse?.()?.code!=='APPROVED_STEP_REQUIRED')throw error;}
      containerSql=currentStep===null||currentStep.kind==='native';
    }
    return{frame,actor:frame.actor,operation:frame.operation,archive:frame.archive,kind:frame.kind,action:frame.action,clusterId:frame.clusterId,workspaceId:frame.workspaceId,namespaceHandle,namespace,invocation,preparation,containerSql,observationRound};
  }
  #assertPortalInspectionFrame(fact:PortalInspectionFrame):void{
    const current=this.#portalInspectionFrame();
    if(!current||Object.keys(current).some(key=>(current as any)[key]!==(fact as any)[key]))throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    this.redis.assertLeaseActive();
  }
  async #portalPrincipalSnapshot(inspection:Pick<WorkflowScheduledAuthorityInspection,'draft'|'approvalSet'|'permissionVersion'>,tx:DbService):Promise<Readonly<{hmac:string;grantDeadline:number}>>{
    const ids=[inspection.draft.delegation.executorId,...new Set(inspection.approvalSet.reviewers.map(r=>r.userId))];
    if(ids.length<2||new Set(ids).size!==ids.length||inspection.approvalSet.format!==2)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_PARTICIPANTS_INVALID');
    const parties=[];let grantDeadline=Infinity;
    for(const id of ids){
      const row=await tx.one<any>(`SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
        FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`,[id]);
      const epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
      if(!row||row.id!==id||!epoch||row.force_password_change||(!/^[1-9]\d*$/.test(String(row.credential_epoch))||!/^[1-9]\d*$/.test(String(row.permissions_epoch))||!/^[1-9]\d*$/.test(String(epoch.version))))throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_PRINCIPAL_REVOKED');
      const version=`${id}:${row.permissions_epoch}:${epoch.version}`;
      if(id===ids[0]&&(String(row.credential_epoch)!==inspection.draft.delegation.executorCredentialEpoch||version!==inspection.permissionVersion))throw deny('WORKFLOW_SCHEDULE_EXECUTOR_PERMISSIONS_CHANGED');
      // iam_effective_grants uses transaction-stable now(). Observe the
      // original user/team binding against actual database wall time and
      // carry its remaining lifetime into the original Namespace's monotonic
      // fence. Natural expiry cannot survive an open SQL transaction.
      const started=performance.now(),rows=await tx.query<any>(`SELECT to_jsonb(g) AS grant,
        CASE WHEN g.binding_source='user' THEN to_jsonb(ub) WHEN g.binding_source='team' THEN to_jsonb(tb) END AS binding,
        CASE WHEN g.binding_source='user' THEN ub.expires_at WHEN g.binding_source='team' THEN tb.expires_at END AS binding_expires_at,
        CASE WHEN g.binding_source='user' THEN ub.id IS NOT NULL AND ub.status='active' AND(ub.expires_at IS NULL OR ub.expires_at>clock_timestamp())
          WHEN g.binding_source='team' THEN tb.id IS NOT NULL AND tb.status='active' AND tm.user_id IS NOT NULL AND(tb.expires_at IS NULL OR tb.expires_at>clock_timestamp())
          ELSE false END AS binding_current, clock_timestamp() AS observed_at
        FROM iam_effective_grants g
        LEFT JOIN user_role_bindings ub ON g.binding_source='user' AND ub.id=g.binding_id AND ub.user_id=g.user_id AND ub.role_id=g.role_id
        LEFT JOIN team_role_bindings tb ON g.binding_source='team' AND tb.id=g.binding_id AND tb.role_id=g.role_id
        LEFT JOIN team_members tm ON g.binding_source='team' AND tm.team_id=tb.team_id AND tm.user_id=g.user_id AND tm.status='active'
        WHERE g.user_id=$1`,[id]);
      for(const value of rows){
        if(!value.grant||!value.binding||value.grant.user_id!==id||value.binding_current!==true
          ||value.grant.binding_id!==value.binding.id||value.grant.role_id!==value.binding.role_id
          ||value.grant.binding_source==='user'&&value.binding.user_id!==id)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_BINDING_CHANGED');
        if(value.binding_expires_at!=null){const remaining=new Date(value.binding_expires_at).getTime()-new Date(value.observed_at).getTime();
          if(!Number.isFinite(remaining)||remaining<=0)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_BINDING_EXPIRED');
          grantDeadline=Math.min(grantDeadline,started+remaining);
        }
      }
      if(performance.now()>=grantDeadline)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_BINDING_EXPIRED');
      const grants=sortByFreshFingerprint(rows.map(value=>({grant:value.grant,binding:value.binding})),g=>this.digest(g));
      parties.push({row,version,grants});
    }
    return Object.freeze({hmac:this.digest(parties),grantDeadline});
  }
  #assertPortalInspectionClosing(scope:PortalInspectionClosing):void{
    if(!scope.active||this.#portalInspectionClosing.getStore()!==scope||performance.now()>=Math.min(scope.fact.deadline,scope.grantDeadline??Infinity))throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_CLOSED');
    this.#assertPortalInspectionFrame(scope.fact);
  }
  async #portalInspectionFactsGate(token:object,plan:WorkflowPlanV1,checkpoint:WorkflowApprovalCheckpoint,tx:DbService,phase:'enter'|'leave'):Promise<void>{
    const state=token&&this.#portalInspectionTokens.get(token);
    if(!state||state.phase!==(phase==='enter'?'issued':'reading')||state.scope.current.plan!==plan||state.scope.checkpoint!==checkpoint||state.scope.tx!==tx)
      throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    this.#assertPortalInspectionClosing(state.scope);await this.redis.assertLeaseOwnership();this.#assertPortalInspectionClosing(state.scope);
    if(this.#portalInspectionTokens.get(token)!==state)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    state.phase=phase==='enter'?'reading':'consumed';
  }
  async #readPortalInspectionFacts(scope:PortalInspectionClosing):Promise<WorkflowApprovalSet>{
    this.#assertPortalInspectionClosing(scope);if(!this.#portalInspectionSql)throw unavailable('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_SQL_UNAVAILABLE');
    const token=Object.freeze({});this.#portalInspectionTokens.set(token,{scope,phase:'issued'});
    try{const set=await this.#portalInspectionSql(token,scope.current.plan,{checkpoint:scope.checkpoint},scope.tx);this.#assertPortalInspectionClosing(scope);
      if(this.#portalInspectionTokens.get(token)?.phase!=='consumed')throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');return set;
    }finally{this.#portalInspectionTokens.delete(token);}
  }
  /** Carry only the original binding's monotonic MIN to Namespace. This
   * emitted inspection is not a fresh SDK/approval permit, and its private
   * round's 30-second lifetime is never a new business deadline. */
  observedPortalGrantDeadline(handle:object,current:Readonly<WorkflowScheduledAuthorityInspection>,checkpoint:WorkflowScheduledAuthorityCheckpoint,frame:object):number|null{
    const fact=this.#partyInspectionGrants.get(current);if(!fact)return null;
    this.original(handle);
    if(fact.handle!==handle||fact.checkpoint!==checkpoint||fact.frame!==frame||this.context.current()!==fact.frame
      ||this.context.requireWorkflowScheduledNamespaceHandle()!==fact.namespaceHandle||this.context.requireWorkflowScheduledCurrentPrincipal(fact.namespaceHandle).namespace!==fact.namespace
      ||Date.parse(fact.namespace.expiresAt)<=Date.now()||performance.now()>=fact.deadline)throw deny('WORKFLOW_PORTAL_OBSERVATION_GRANT_EXPIRED');
    this.redis.assertLeaseActive();return fact.deadline;
  }
  /** Read-only provenance probe used solely by the fixed Namespace publisher. */
  hasFreshPortalInspection(handle:object,current:Readonly<WorkflowScheduledAuthorityInspection>,checkpoint:WorkflowScheduledAuthorityCheckpoint,frame:object):boolean{
    const fact=this.#portalInspectionFacts.get(current);
    if(!fact||fact.consumed||fact.handle!==handle||fact.checkpoint!==checkpoint||fact.frame!==frame||performance.now()>=fact.deadline||this.#portalInspectionGenerations.get(fact.frame)!==fact.generation)return false;
    this.#assertPortalInspectionFrame(fact);return true;
  }
  /** Only the fixed Namespace may retain this original binding deadline.
   * It is a monotonic upper bound, never a new claim or extension. */
  freshPortalInspectionGrantDeadline(handle:object,current:Readonly<WorkflowScheduledAuthorityInspection>,checkpoint:WorkflowScheduledAuthorityCheckpoint,frame:object):number|null{
    const fact=this.#portalInspectionFacts.get(current);if(!fact)return null;
    if(!this.hasFreshPortalInspection(handle,current,checkpoint,frame))throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_CLOSED');
    return fact.grantDeadline;
  }
  consumedPortalInspectionGrantDeadline(handle:object,current:Readonly<WorkflowScheduledAuthorityInspection>,checkpoint:WorkflowScheduledAuthorityCheckpoint,frame:object):number{
    const fact=this.#portalInspectionFacts.get(current);
    if(!fact||!fact.consumed||fact.handle!==handle||fact.checkpoint!==checkpoint||fact.frame!==frame||this.#portalInspectionGenerations.get(frame)!==fact.generation
      ||performance.now()>=fact.deadline)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_CLOSED');
    this.#assertPortalInspectionFrame(fact);return fact.grantDeadline;
  }
  /** Fresh SQL-only set load for the real original Portal native Step. This
   * does not publish an Authority inspection; the caller must subsequently
   * enter the genuine all-party Namespace checkpoint before any native send. */
  async readPortalOperationApprovalSet(handle:object,namespace:Readonly<WorkflowScheduledNamespaceProof>,plan:WorkflowPlanV1,executionId:string,transaction:DbService):Promise<WorkflowApprovalSet|null>{
    const frame=this.#portalInspectionFrame();if(!frame||!isPortalCredentialScheduleKind(namespace.kind))return null;
    if(frame.invocation&&frame.invocation.transaction!==transaction)throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_TRANSACTION_CHANGED');
    if(frame.preparation&&transaction!==this.db)throw deny('WORKFLOW_SCHEDULE_PORTAL_PREPARATION_TRANSACTION_CHANGED');
    const original=this.original(handle),step=frame.invocation?.step??(frame.kind==='operation'?this.context.currentApprovedStep():null),execution=frame.invocation?.execution??step?.execution;
    if(frame.namespace!==namespace||original.state!=='executing'||!original.callbackEntered||original.claim.id!==namespace.claim.id
      ||!execution||(!frame.invocation&&step?.kind!=='native')||step&&step.execution!==execution
      ||execution.origin!=='scheduled-workflow'||execution.executionId!==executionId||execution.workflowId!==namespace.workflow.id
      ||execution.scheduleClaimId!==namespace.claim.id||execution.actorId!==namespace.actor.id||execution.sessionId!=null
      ||plan.kind!==namespace.kind||plan.clusterId!==namespace.clusterId||plan.workspaceId!==namespace.workspaceId||plan.workflowId!==namespace.workflow.id
      ||plan.planRevision!==namespace.workflow.planRevision||this.digest(plan)!==namespace.workflow.planHash)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    const close=()=>{this.#assertPortalInspectionFrame(frame);if((!frame.invocation&&this.context.currentApprovedStep()!==step)||this.original(handle)!==original)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');};
    close();const result=await transaction.transaction(async tx=>{
      const stored=await this.repository.inspectStored(original.scheduleId,tx);close();
      if(!stored.claim||this.digest(stored.claim)!==this.digest(original.claim)||!stored.latestLease||stored.latestLease.claimId!==original.claim.id
        ||!['claimed','running'].includes(stored.progress.state)||stored.progress.claimId!==original.claim.id||Date.parse(stored.latestLease.leaseUntil)<=Date.now())throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      this.same(stored.plan,plan,'WORKFLOW_SCHEDULE_PLAN_CHANGED');this.due(stored);await this.currentPlan(stored,tx);await this.scope(stored.draft,stored.plan,tx);await this.requester(stored.draft,stored.plan,tx);close();
      const current={plan:stored.plan};
      const fact={...frame,deadline:Math.min(performance.now()+30000,performance.now()+Date.parse(namespace.expiresAt)-Date.now())};
      const scope:PortalInspectionClosing={fact,current,tx,checkpoint:'packet',active:true};
      try{return await this.#portalInspectionClosing.run(scope,async()=>{
        const token=Object.freeze({});this.#portalInspectionTokens.set(token,{scope,phase:'issued'});
        try{const set=await this.#portalInspectionSql!(token,current.plan,{checkpoint:'packet'},tx);close();this.#assertPortalInspectionClosing(scope);
          if(this.#portalInspectionTokens.get(token)?.phase!=='consumed')throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
          this.same(set,namespace.approvalSet,'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');await this.principal(namespace.actor.id,namespace.credentialEpoch,tx);close();return set;
        }finally{this.#portalInspectionTokens.delete(token);}
      });}finally{scope.active=false;}
    });close();return result;
  }
  /** One-time SQL closing of this exact just-returned Authority result. It
   * cannot run a reviewer Native policy, create a Namespace or send a packet. */
  async consumeFreshPortalInspection(handle:object,current:Readonly<WorkflowScheduledAuthorityInspection>,checkpoint:WorkflowScheduledAuthorityCheckpoint,transaction:DbService):Promise<Readonly<WorkflowScheduledAuthorityInspection>>{
    const fact=this.#portalInspectionFacts.get(current),original=this.original(handle);
    if(!fact||fact.consumed||fact.handle!==handle||fact.checkpoint!==checkpoint||original.state!=='executing'||!original.callbackEntered||!this.#portalInspectionSql
      ||performance.now()>=fact.deadline||this.#portalInspectionGenerations.get(fact.frame)!==fact.generation)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    if(fact.invocation&&fact.invocation.transaction!==transaction)throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_TRANSACTION_CHANGED');
    if(fact.preparation&&transaction!==this.db)throw deny('WORKFLOW_SCHEDULE_PORTAL_PREPARATION_TRANSACTION_CHANGED');
    this.#assertPortalInspectionFrame(fact);fact.consumed=true;
    const value=await transaction.transaction(async tx=>{
      const scope:PortalInspectionClosing={fact,current,tx,checkpoint:checkpoint==='claim'?'claim':checkpoint==='capture'?'snapshot':checkpoint==='step'?'step':'packet',active:true};
      try{return await this.#portalInspectionClosing.run(scope,async()=>{
        const close=()=>this.#assertPortalInspectionClosing(scope);close();
        await this.available(tx);await this.iam(tx);close();
        const stored=await this.repository.inspectStored(original.scheduleId,tx);this.due(stored);close();
        if(!stored.claim||!stored.latestLease||!['claimed','running'].includes(stored.progress.state)||stored.progress.claimId!==original.claim.id
          ||this.digest(stored.claim)!==this.digest(original.claim)||this.digest(stored.claim)!==this.digest(current.claim)
          ||stored.latestLease.claimId!==original.claim.id||stored.latestLease.generation!==1||stored.latestLease.workerOwnerHmac!==original.claim.workerOwnerHmac
          ||stored.latestLease.leaseUntil!==current.leaseUntil||Date.parse(current.leaseUntil)<=Date.now()||Date.parse(current.authorityExpiresAt)<=Date.now())throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
        this.same(stored.draft,current.draft,'WORKFLOW_SCHEDULE_PLAN_CHANGED');this.same(stored.plan,current.plan,'WORKFLOW_SCHEDULE_PLAN_CHANGED');
        await this.currentPlan(stored,tx);await this.scope(stored.draft,stored.plan,tx);await this.requester(stored.draft,stored.plan,tx);close();
        const token=Object.freeze({});this.#portalInspectionTokens.set(token,{scope,phase:'issued'});
        try{const set=await this.#portalInspectionSql!(token,current.plan,{checkpoint:scope.checkpoint},tx);close();
          if(this.#portalInspectionTokens.get(token)?.phase!=='consumed')throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
          this.same(set,current.approvalSet,'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
        }finally{this.#portalInspectionTokens.delete(token);}
        {const snapshot=await this.#portalPrincipalSnapshot(current,tx);if(snapshot.hmac!==fact.snapshotHmac)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_PRINCIPAL_CHANGED');
          fact.grantDeadline=Math.min(fact.grantDeadline,snapshot.grantDeadline);fact.deadline=Math.min(fact.deadline,fact.grantDeadline);
          if(fact.preparation)this.context.limitScheduledPortalPreparation(fact.preparation,fact.grantDeadline);close();}
        await this.physical(stored,tx,original.claim.id);await this.redis.assertLeaseOwnership();close();
        await this.currentPlan(stored,tx);await this.scope(stored.draft,stored.plan,tx);await this.requester(stored.draft,stored.plan,tx);close();
        {const snapshot=await this.#portalPrincipalSnapshot(current,tx);if(snapshot.hmac!==fact.snapshotHmac)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_PRINCIPAL_CHANGED');
          fact.grantDeadline=Math.min(fact.grantDeadline,snapshot.grantDeadline);fact.deadline=Math.min(fact.deadline,fact.grantDeadline);
          if(fact.preparation)this.context.limitScheduledPortalPreparation(fact.preparation,fact.grantDeadline);close();}
        return current;
      });}finally{scope.active=false;}
    });
    this.#assertPortalInspectionFrame(fact);if(this.original(handle)!==original||performance.now()>=fact.deadline)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_CLOSED');
    return value;
  }
  async inspect(handle: object): Promise<Readonly<WorkflowScheduledAuthorityInspection>> { return this.verifyClaim(handle, 'inspect'); }
  async verifyClaim(handle: object, checkpoint: WorkflowScheduledAuthorityCheckpoint): Promise<Readonly<WorkflowScheduledAuthorityInspection>> {
    if (!checkpoints.includes(checkpoint)) throw deny('WORKFLOW_SCHEDULE_CHECKPOINT_INVALID');
    const privateFact = this.original(handle);
    if (checkpoint !== 'inspect') {
      // Namespace construction needs a fresh claim checkpoint after the fixed
      // executor has begun, before Context.make and the actual business fn.
      // Capture/steps/packets/final wire remain closed until the one-shot fn
      // boundary has checked the genuine original namespace below.
      if (privateFact.state !== 'executing' || !privateFact.executorEntered || checkpoint!=='claim'&&!privateFact.callbackEntered) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_CALLBACK_REQUIRED');
      await this.redis.assertLeaseOwnership(); this.redis.assertLeaseActive();
    }
    const portalFrame=this.#portalInspectionFrame();let portalSnapshot:Readonly<{hmac:string;grantDeadline:number}>|undefined;
    const portalGeneration=portalFrame?(this.#portalInspectionGenerations.get(portalFrame.frame)??0)+1:0;
    if(portalFrame)this.#portalInspectionGenerations.set(portalFrame.frame,portalGeneration);
    let observedParties:{original:Readonly<PortalPartyObservationRoundOriginal>;deadline:number}|undefined;
    // One claim verification is one read under iam_epoch FOR SHARE: identical
    // non-locking SELECTs inside it share a result (epoch probes stay live).
    const value = await this.db.transaction(async tx => withVerificationReadMemo(tx, async () => {
      await this.available(tx); await this.iam(tx); const stored = await this.repository.inspectStored(privateFact.scheduleId, tx); this.due(stored);
      if (!['claimed', 'running'].includes(stored.progress.state) || stored.progress.claimId !== privateFact.claim.id || !stored.claim || !stored.latestLease)
        throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      this.same(stored.claim, privateFact.claim, 'WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      const c = privateFact.claim, lease = stored.latestLease;
      const row = await tx.one<any>('SELECT * FROM workflow_schedule_claims WHERE id=$1 AND schedule_id=$2', [c.id, privateFact.scheduleId]);
      if (!row || row.cluster_id !== stored.draft.binding.clusterId || row.workspace_id !== stored.draft.binding.workspaceId
        || row.id !== c.id || row.schedule_id !== c.scheduleId || row.occurrence_id !== c.occurrenceId || row.generation !== c.generation
        || row.worker_owner_hmac !== c.workerOwnerHmac || row.workflow_id !== c.workflowId || row.workflow_plan_revision !== c.workflowPlanRevision
        || row.workflow_plan_hash !== c.workflowPlanHash || new Date(row.issued_at).toISOString() !== c.issuedAt
        || new Date(row.authority_expires_at).toISOString() !== c.authorityExpiresAt || new Date(row.initial_lease_until).toISOString() !== c.initialLeaseUntil)
        throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      if (c.workerOwnerHmac !== this.workerOwnerHmac || c.generation !== 1 || lease.claimId !== c.id || lease.generation !== 1 || lease.workerOwnerHmac !== c.workerOwnerHmac
        || [lease.leaseUntil, c.authorityExpiresAt].some(t => !Number.isFinite(Date.parse(t))) || Date.parse(lease.leaseUntil) <= Date.now() || Date.parse(c.authorityExpiresAt) <= Date.now()
        || Date.parse(lease.leaseUntil) > Date.parse(c.authorityExpiresAt)) throw changed('WORKFLOW_SCHEDULE_CLAIM_EXPIRED');
      const eligible = await this.eligibility(stored, tx, checkpoint); await this.physical(stored, tx, c.id);
      observedParties=this.#partyObservationResults.get(eligible);
      if(portalFrame){this.#assertPortalInspectionFrame(portalFrame);portalSnapshot=await this.#portalPrincipalSnapshot(eligible,tx);
        if(portalFrame.preparation||portalFrame.containerSql||this.#portalPreparationGrantDeadlines.has(eligible)){const deadline=Math.min(portalSnapshot.grantDeadline,this.#portalPreparationGrantDeadlines.get(eligible)??Infinity);
          if(portalFrame.preparation)this.context.limitScheduledPortalPreparation(portalFrame.preparation,deadline);portalSnapshot=Object.freeze({...portalSnapshot,grantDeadline:deadline});}
        this.#assertPortalInspectionFrame(portalFrame);}
      return immutableJson({ version: 1 as const, claim: c, ...eligible, leaseUntil: lease.leaseUntil, authorityExpiresAt: c.authorityExpiresAt });
    }));
    if (this.original(handle) !== privateFact) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED');
    if (checkpoint !== 'inspect') { await this.redis.assertLeaseOwnership(); this.redis.assertLeaseActive(); }
    if(observedParties&&checkpoint!=='inspect'){
      const original=observedParties.original;
      if(this.context.current()!==original.frame||this.context.requireWorkflowScheduledNamespaceHandle()!==original.namespaceHandle
        ||this.context.requireWorkflowScheduledCurrentPrincipal(original.namespaceHandle).namespace!==original.namespace||performance.now()>=observedParties.deadline)
        throw deny('WORKFLOW_PORTAL_OBSERVATION_GRANT_EXPIRED');
      this.#partyInspectionGrants.set(value,{handle,checkpoint,frame:original.frame,namespaceHandle:original.namespaceHandle,namespace:original.namespace,deadline:observedParties.deadline});
    }
    if(portalFrame&&portalSnapshot&&checkpoint!=='inspect'){this.#assertPortalInspectionFrame(portalFrame);this.#portalInspectionFacts.set(value,{...portalFrame,handle,checkpoint,snapshotHmac:portalSnapshot.hmac,grantDeadline:portalSnapshot.grantDeadline,generation:portalGeneration,
      deadline:Math.min(performance.now()+30000,performance.now()+Date.parse(portalFrame.namespace.expiresAt)-Date.now(),portalSnapshot.grantDeadline),consumed:false});}
    return value;
  }
  assertConfigurationSqlPreparationLive(handle:object,namespaceHandle:object,namespace:Readonly<WorkflowScheduledNamespaceProof>):void{
    const preparation=this.context.scheduledConfigurationPreparationPhase(),original=this.original(handle);
    if(!preparation||preparation.namespaceHandle!==namespaceHandle||preparation.namespace!==namespace||original.state!=='executing'
      ||!original.executorEntered||!original.callbackEntered||original.claim.id!==namespace.claim.id||original.scheduleId!==namespace.claim.scheduleId)
      throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');this.redis.assertLeaseActive();
  }
  async verifyConfigurationSqlPreparation(handle:object,namespaceHandle:object,namespace:Readonly<WorkflowScheduledNamespaceProof>,checkpoint:'packet'):Promise<void>{
    const preparation=typeof this.context.scheduledConfigurationPreparationPhase==='function'?this.context.scheduledConfigurationPreparationPhase():null;
    if(checkpoint!=='packet'||!preparation||preparation.namespaceHandle!==namespaceHandle||preparation.namespace!==namespace||!this.configurationPreparationSql)throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');
    const privateFact = this.original(handle);
    const originalClaim=privateFact.claim,projected=namespace.claim;
    if(privateFact.scheduleId!==projected.scheduleId||['id','scheduleId','scheduleVersion','occurrenceId','generation','workerOwnerHmac','workflowId',
      'workflowPlanRevision','workflowPlanHash','issuedAt','authorityExpiresAt','initialLeaseUntil'].some(key=>(originalClaim as any)[key]!==(projected as any)[key]))
      throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');
    {
      // Namespace construction needs a fresh claim checkpoint after the fixed
      // executor has begun, before Context.make and the actual business fn.
      // Capture/steps/packets/final wire remain closed until the one-shot fn
      // boundary has checked the genuine original namespace below.
      if (privateFact.state !== 'executing' || !privateFact.executorEntered || !privateFact.callbackEntered) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_CALLBACK_REQUIRED');
      await this.redis.assertLeaseOwnership(); this.redis.assertLeaseActive();
    }
    await this.db.transaction(async tx => {
      await this.available(tx); await this.iam(tx); const stored = await this.repository.inspectStored(privateFact.scheduleId, tx); this.due(stored);
      if (!['claimed', 'running'].includes(stored.progress.state) || stored.progress.claimId !== privateFact.claim.id || !stored.claim || !stored.latestLease)
        throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      this.same(stored.claim, privateFact.claim, 'WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      const c = privateFact.claim, lease = stored.latestLease;
      const row = await tx.one<any>('SELECT * FROM workflow_schedule_claims WHERE id=$1 AND schedule_id=$2', [c.id, privateFact.scheduleId]);
      if (!row || row.cluster_id !== stored.draft.binding.clusterId || row.workspace_id !== stored.draft.binding.workspaceId
        || row.id !== c.id || row.schedule_id !== c.scheduleId || row.occurrence_id !== c.occurrenceId || row.generation !== c.generation
        || row.worker_owner_hmac !== c.workerOwnerHmac || row.workflow_id !== c.workflowId || row.workflow_plan_revision !== c.workflowPlanRevision
        || row.workflow_plan_hash !== c.workflowPlanHash || new Date(row.issued_at).toISOString() !== c.issuedAt
        || new Date(row.authority_expires_at).toISOString() !== c.authorityExpiresAt || new Date(row.initial_lease_until).toISOString() !== c.initialLeaseUntil)
        throw changed('WORKFLOW_SCHEDULE_CLAIM_CHANGED');
      if (c.workerOwnerHmac !== this.workerOwnerHmac || c.generation !== 1 || lease.claimId !== c.id || lease.generation !== 1 || lease.workerOwnerHmac !== c.workerOwnerHmac
        || [lease.leaseUntil, c.authorityExpiresAt].some(t => !Number.isFinite(Date.parse(t))) || Date.parse(lease.leaseUntil) <= Date.now() || Date.parse(c.authorityExpiresAt) <= Date.now()
        || Date.parse(lease.leaseUntil) > Date.parse(c.authorityExpiresAt)) throw changed('WORKFLOW_SCHEDULE_CLAIM_EXPIRED');
      const verifier=this.configurationPreparationSql!;let token:object|undefined;
      try{token=await verifier.openClosedCheckpoint(namespaceHandle,namespace,'packet',tx);
        await this.physical(stored,tx,c.id);
        await verifier.assertClosedCheckpoint(token,namespaceHandle,namespace,'packet',tx);
        verifier.assertClosedCheckpointLive(token,namespaceHandle,namespace,'packet',tx);
        if(this.context.scheduledConfigurationPreparationPhase()!==preparation||this.original(handle)!==privateFact
          ||privateFact.state!=='executing'||!privateFact.executorEntered||!privateFact.callbackEntered)throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');
      }finally{if(token)verifier.releaseClosedCheckpoint(token);}
    });
    if (this.original(handle) !== privateFact) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED');
    await this.redis.assertLeaseOwnership();this.redis.assertLeaseActive();
    if(this.context.scheduledConfigurationPreparationPhase()!==preparation||this.original(handle)!==privateFact
      ||privateFact.state!=='executing'||!privateFact.executorEntered||!privateFact.callbackEntered)throw deny('WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED');
  }
  private async noCallbackFacts(handle: HandleState, tx: DbService): Promise<Readonly<Record<string, unknown>>> {
    if (handle.state !== 'executing' || handle.callbackEntered) throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    await this.available(tx); const stored = await this.repository.inspectStored(handle.scheduleId, tx), d = stored.draft, c = handle.claim;
    if (!stored.claim || stored.progress.claimId !== c.id || !['claimed', 'failed'].includes(stored.progress.state)) throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    this.same(stored.claim, c, 'WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    assertWorkflowScheduledPlan(stored.plan, d, this.secrets);
    const wf = await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE', [c.workflowId, d.binding.clusterId, d.binding.workspaceId]);
    if (!wf || !['approved', 'cancelled'].includes(wf.state) || wf.plan_revision !== c.workflowPlanRevision || wf.plan_hash !== c.workflowPlanHash) throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    const facts = await tx.one<any>(`SELECT
      EXISTS(SELECT 1 FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS execution,
      EXISTS(SELECT 1 FROM workflow_execution_origins WHERE claim_id=$4 OR cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS origin,
      EXISTS(SELECT 1 FROM workflow_configuration_execution_origins WHERE claim_id=$4 OR cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3) AS configuration_origin,
      EXISTS(SELECT 1 FROM mutation_operations WHERE cluster_id=$1 AND(workflow_id=$3 OR $5::boolean AND configuration_job_id=$6::uuid)) AS mutation,
      EXISTS(SELECT 1 FROM configuration_executions WHERE cluster_id=$1 AND(workflow_id=$3 OR $5::boolean AND job_id=$6::uuid)) AS configuration_execution`,
      [d.binding.clusterId, d.binding.workspaceId, c.workflowId, c.id, d.binding.kind === 'configuration_v2', d.binding.subjectId]);
    if (!facts || ['execution', 'origin', 'configuration_origin', 'mutation', 'configuration_execution'].some(key => facts[key] !== false))
      throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    const steps = await tx.query<any>(`SELECT id,step_key,step_order,state,operation_id,receipt_secret,recycle_entry_id,after_fingerprint,started_at,completed_at
      FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND plan_hash=$5 ORDER BY step_order FOR SHARE`,
      [d.binding.clusterId, d.binding.workspaceId, c.workflowId, c.workflowPlanRevision, c.workflowPlanHash]);
    if (steps.length !== stored.plan.steps.length || steps.some((row, index) => row.id !== stored.plan.steps[index].id || row.step_key !== stored.plan.steps[index].key
      || row.step_order !== index + 1 || row.state !== 'pending' || [row.operation_id, row.receipt_secret, row.recycle_entry_id, row.after_fingerprint, row.started_at, row.completed_at].some(value => value !== null)))
      throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    return immutableJson({ version: 1, claim: c, draftHmac: this.digest(d), planHash: c.workflowPlanHash, workflowState: wf.state, steps, absence: facts,executorEntered:handle.executorEntered, callbackEntered: false });
  }
  private async closeNoCallback(original: object, reason: string): Promise<void> {
    const handle = this.original(original);
    if (handle.callbackEntered || handle.state !== 'executing') throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
    await this.redis.withLock(`workflow:${handle.claim.workflowId}`, () => this.db.transaction(async tx => {
      await this.redis.assertLeaseOwnership(); const stored = await this.repository.inspectStored(handle.scheduleId, tx);
      // Same physical→progress lock order as activation/cancellation. No
      // append-only row is SELECT FOR UPDATE and no expired lease is renewed.
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))", [stored.draft.transportScope]);
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('workflow-schedule-claim:'||$1,0))", [handle.claim.id]);
      if (!await tx.one('SELECT schedule_id FROM workflow_schedule_progress WHERE schedule_id=$1 FOR UPDATE', [handle.scheduleId]))
        throw deny('WORKFLOW_SCHEDULE_NO_CALLBACK_FACTS_REQUIRED');
      await this.noCallbackFacts(handle, tx);
      const proof = this.proof('no-callback', handle.scheduleId, { claimId: handle.claim.id, outcome: 'failed' }, { handle: original, reason });
      try { await this.repository.finishClaim(handle.claim.id, 'failed', proof, tx); } finally { this.proofs.delete(proof); }
    }));
  }
  private async outcomeFacts(handle: HandleState, outcome: WorkflowScheduleTerminalOutcome, tx: DbService): Promise<Readonly<WorkflowScheduleOutcomeEvidence>> {
    const stored = await this.repository.inspectStored(handle.scheduleId, tx), d = stored.draft, c = handle.claim;
    if (!['succeeded', 'partial', 'failed', 'uncertain'].includes(outcome) || stored.progress.claimId !== c.id || !stored.claim) throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID');
    this.same(stored.claim, c, 'WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID');
    const row = await tx.one<any>(`SELECT e.*,w.state AS workflow_state,o.claim_id,o.schedule_id,o.executor_id,o.id AS origin_id
      FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id AND w.cluster_id=e.cluster_id AND w.workspace_id=e.workspace_id
      JOIN workflow_execution_origins o ON o.execution_id=e.id AND o.cluster_id=e.cluster_id AND o.workspace_id=e.workspace_id
      WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.workflow_id=$3 AND e.plan_revision=$4 AND e.plan_hash=$5 AND o.claim_id=$6`,
      [d.binding.clusterId, d.binding.workspaceId, c.workflowId, c.workflowPlanRevision, c.workflowPlanHash, c.id]);
    if (!row || !['succeeded', 'partial', 'failed', 'uncertain'].includes(row.state) || row.workflow_state !== row.state || row.claim_id !== c.id || row.schedule_id !== d.scheduleId
      || row.execution_actor_id !== d.delegation.executorId || row.executor_id !== d.delegation.executorId || !row.completed_at)
      throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID');
    const nested = await tx.query<any>(`SELECT co.*,e.state,e.completed_at,e.actor_id FROM workflow_configuration_execution_origins co
      JOIN configuration_executions e ON e.id=co.configuration_execution_id AND e.cluster_id=co.cluster_id AND e.workspace_id=co.workspace_id
      WHERE co.wrapper_origin_id=$1 AND co.claim_id=$2`, [row.origin_id, c.id]);
    if (nested.length > 1 || isPortalCredentialScheduleKind(d.binding.kind) && nested.length
      || nested.some(n => n.actor_id !== d.delegation.executorId || !n.completed_at || !['succeeded', 'partial', 'failed', 'uncertain'].includes(n.state)))
      throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID');
    const native = await tx.one<any>(`SELECT
      EXISTS(SELECT 1 FROM mutation_operations m WHERE m.cluster_id=$1 AND(m.workflow_execution_id=$2::uuid OR $3::uuid IS NOT NULL AND m.configuration_execution_id=$3)
        AND m.state IN('pending','running','uncertain')) AS unknown,
      EXISTS(SELECT 1 FROM mutation_operations m WHERE m.cluster_id=$1 AND(m.workflow_execution_id=$2::uuid OR $3::uuid IS NOT NULL AND m.configuration_execution_id=$3)
        AND m.state='succeeded') AS succeeded`, [d.binding.clusterId, row.id, nested[0]?.configuration_execution_id ?? null]);
    if (!native || typeof native.unknown !== 'boolean' || typeof native.succeeded !== 'boolean') throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID');
    const config = nested[0], unknown = native.unknown || row.state === 'uncertain' || config?.state === 'uncertain';
    if (unknown && outcome !== 'uncertain'
      || outcome === 'succeeded' && (row.state !== 'succeeded' || d.binding.kind === 'configuration_v2' && config?.state !== 'succeeded')
      || outcome === 'failed' && (row.state !== 'failed' || native.succeeded || config && config.state !== 'failed')
      || outcome === 'partial' && (!['failed', 'partial'].includes(row.state) || !native.succeeded && !['succeeded', 'partial'].includes(config?.state)))
      throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_INVALID');
    // Complete native/baseline/metadata evidence is kind-specific and verified
    // by Root's original completion callback twice in this same transaction.
    return immutableJson({ version: 1, provenance: 'original-execution', evidenceHmac: this.digest({ claim: c, draftHmac: this.digest(d), outcome,
      wrapper: row, nested, native }) });
  }
  async executeClaim(handle: object): Promise<void> {
    this.background(); if (!this.executor) throw unavailable('WORKFLOW_SCHEDULE_EXECUTOR_UNAVAILABLE');
    const state = this.original(handle); if (state.state !== 'issued') throw changed('WORKFLOW_SCHEDULE_EXECUTION_ALREADY_STARTED');
    state.state = 'executing';let executorActive=false;
    const beginBusinessCallback=(namespaceHandle:object):void=>{
      if(!executorActive||this.original(handle)!==state||state.state!=='executing'||!state.executorEntered||state.callbackEntered)
        throw deny('WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED');
      const actualHandle=this.context.requireWorkflowScheduledNamespaceHandle(),principal=this.context.requireWorkflowScheduledCurrentPrincipal(actualHandle),namespace=principal.namespace,frame=this.context.current();
      if(namespaceHandle!==actualHandle||principal.readOnly||principal.role!=='executor'||namespace.origin!=='scheduled-workflow'||namespace.sessionId!==null||frame.sessionId!=null
        ||frame.kind!=='scheduled-workflow'||frame.module!=='workflows'||frame.action!=='write'||frame.operation||frame.archive||frame.clusterId!==namespace.clusterId||frame.workspaceId!==namespace.workspaceId
        ||frame.actor?.id!==namespace.actor.id||namespace.claim.executorId!==namespace.actor.id||namespace.claim.clusterId!==namespace.clusterId||namespace.claim.workspaceId!==namespace.workspaceId
        ||namespace.workflow.id!==state.claim.workflowId||namespace.workflow.planRevision!==state.claim.workflowPlanRevision||namespace.workflow.planHash!==state.claim.workflowPlanHash)
        throw deny('WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED');
      this.same(Object.fromEntries(Object.keys(state.claim).map(key=>[key,(namespace.claim as any)[key]])),state.claim,'WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED');
      this.redis.assertLeaseActive();state.callbackEntered=true;
    };
    try {
      await this.redis.withLock(`workflow:${state.claim.workflowId}`, async () => {
        // Private pre-callback state may be inspected; non-inspect admission
        // remains closed until the actual fixed Root executor is entered.
        await this.verifyClaim(handle, 'inspect'); await this.redis.assertLeaseOwnership();
        state.executorEntered=true;executorActive=true;
        let completion:object;
        try{completion=await this.executor!.executeClaim(handle,beginBusinessCallback);}finally{executorActive=false;}
        if(!state.callbackEntered)throw deny('WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED');
        if (!completion || typeof completion !== 'object' || Array.isArray(completion)) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED');
        await this.db.transaction(async tx => {
          const outcome = await this.executor!.verifyCompletion(handle, completion, tx); await this.outcomeFacts(state, outcome, tx);
          const proof = this.proof('outcome', state.scheduleId, { claimId: state.claim.id, outcome }, { handle, completion });
          try { await this.repository.finishClaim(state.claim.id, outcome, proof, tx); } finally { this.proofs.delete(proof); }
        });
      });
    } catch (error) {
      if (!state.callbackEntered) {
        const actual = error instanceof HttpException ? (error.getResponse() as any)?.code : undefined;
        const reason = typeof actual === 'string' && /^[A-Z][A-Z\d_]{0,127}$/.test(actual) ? actual : 'WORKFLOW_SCHEDULE_PRECALL_METADATA_FAILED';
        try { await this.closeNoCallback(handle, reason); } catch { /* Preserve original failure and held claim; never replay or infer absence from a failed read. */ }
      }
      throw error;
    } finally { executorActive=false;state.state = 'closed'; }
    // Failure without an authentic Root completion stays unresolved, never
    // synthesizes a successful/known-unsent result and is never auto-reclaimed.
  }
}
