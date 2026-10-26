import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import type {PortalInspectionInvocationOriginal,PortalInspectionInvocationVerifier} from './workflow-portal-inspection-invocation.types';
import {isIP} from 'node:net';
import { ConflictException, ForbiddenException, Injectable, OnModuleInit, Optional } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { CONFIGURATION_TIMEOUT_MS } from '../../infrastructure/kong/configuration-budget';
import { KongExecutionContextService, type ScheduledPortalFinalNativePhase } from '../../infrastructure/kong/execution-context.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath } from '../../infrastructure/kong/policy';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { coarseGrantMatches, grantMatchesEntity, validGrant } from '../authorization/grant-policy';
import type { MutationContext } from '../mutations/mutation.service';
import { normalizedNativeRequests, isConfigurationBinding } from './approved-execution.types';
import { ConfigurationApprovedVerifier, type ConfigurationApprovedLoaded,type ConfigurationNativeBeforeBinding } from './configuration-approved-verifier';
import { assertToolboxWorkflowPlan, type ToolboxWorkflowPayload } from './toolbox-workflow';
import { assertWorkspaceMigrationWorkflowPlan, migrationNativeRequests, type WorkspaceMigrationWorkflowPayload } from './workspace-migration-workflow';
import type { WorkspaceMigrationMaterial } from '../workspaces/workspace-migration.service';
import { assertConfigurationWorkflowPlan } from './configuration-workflow';
import { assertConfigurationMetadataWorkflowPlan, CONFIGURATION_METADATA_RESOURCES, configurationMetadataAction, configurationMetadataLedgerInput, type ConfigurationMetadataPayload } from './configuration-metadata-workflow';
import type { ApprovedWorkflowScheduledConfigurationDelegate, ApprovedWorkflowScheduledDelegate, ApprovedWorkflowScheduledReviewerReadPolicy, ConfigurationApprovedDelegate, GovernanceMetadataApprovedDelegate, WorkflowPolicyMetadataApprovedDelegate } from './approved-execution.types';
import type { WorkflowScheduledNamespaceCheckpoint, WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { WorkflowScheduledConfigurationCheckpoint, WorkflowScheduledConfigurationExecutionHandle,
  WorkflowScheduledConfigurationExecutionProof, WorkflowScheduledConfigurationJobHandle } from './workflow-scheduled-configuration-origin.types';
import type { WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import { assertGovernanceMetadataPlan } from '../governance/governance-workflow';
import type {ConfigurationNativeBeforeInput,ConfigurationNativeBeforeReadHandle,ConfigurationNativeBeforeReadIntent,ConfigurationNativeBeforeReadResult} from './approved-execution.types';
import type { ApprovedExecutionHandle, ApprovedExecutionPolicy, ApprovedExecutionProof, ApprovedStepProof, ApprovedMutationBinding, ApprovedNativeRequest, ApprovedNativeStage, ApprovedMetadataInput, PortalNativePacket, IssueActivationRecoveryHandle, IssueActivationRecoveryProof } from './approved-execution.types';
import { loadPortalIssueNativeEvidence, type PortalIssueNativeEvidence } from '../portal/portal-native-evidence';
import { WORKFLOW_KINDS, planAad, snapshotAad } from './workflow.types';
import type { WorkflowPlanV1, WorkflowSnapshotV1, WorkflowStep } from './workflow.types';
import { assertEventWorkflowPlan, eventWorkflowHandler } from './event-workflow';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import type { WorkflowApprovalSet } from './workflow-approval.types';
import { assertWorkflowPolicyMetadataPlan } from './workflow-policy-metadata';
import { assertIamMetadataPlan } from '../iam/iam-workflow-plan';
import type { IamMetadataApprovedDelegate } from '../iam/iam-workflow.types';
import { assertControlMetadataPlan } from '../control-plane/control-metadata-plan';
import type { ControlMetadataApprovedDelegate } from '../control-plane/control-metadata.types';
import type { EntityActor } from '../entities/entities.types';
import { assertMetricsSetupPlan } from '../vitals/vitals-setup-plan';
import type { MetricsSetupApprovedDelegate } from '../vitals/vitals-setup.types';
import { assertEntityAnnotationPlan } from '../annotations/entity-annotation-workflow-plan';
import type { EntityAnnotationApprovedDelegate } from '../annotations/entity-annotation-workflow.types';

const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const digest = /^[a-f\d]{64}$/;
const deny = (code = 'APPROVED_EXECUTION_INVALID') => new ForbiddenException({ code, message: '当前已批准执行证明无效，操作已停止' });
const stale = (code = 'APPROVED_PLAN_STALE') => new ConflictException({ code, message: '批准计划或当前依赖发生变化，需核验原工作流' });
const subjects: Record<string, string> = { entity_annotation_requests:'annotations',control_metadata_requests:'clusters',iam_metadata_requests:'iam',metrics_setup_requests:'monitoring',workflow_policy_requests:'workflows',governance_metadata_requests:'governance',workspace_migration_plans:'workspaces',toolbox_operations:'toolbox', configuration_jobs: 'snapshots', config_snapshots: 'snapshots', config_snapshot_schedules: 'snapshots', configuration_gitops_runs: 'gitops', portal_publications: 'portal', portal_application_grants: 'portal', portal_developers: 'developers', portal_applications: 'applications', portal_settings: 'portal', portal_content: 'portal', notification_channels: 'events', event_subscriptions: 'events', event_deliveries: 'events' };
interface Loaded { execution: any; workflow: any; version: any; plan: WorkflowPlanV1; snapshot: WorkflowSnapshotV1; rows: any[]; approvalSet?: WorkflowApprovalSet; }
interface HandleState { proof: ApprovedExecutionProof; active: boolean; scheduled?: { handle: object; namespace: Readonly<WorkflowScheduledNamespaceProof>; originId: string };
  scheduledConfiguration?: { jobHandle: WorkflowScheduledConfigurationJobHandle; executionHandle: WorkflowScheduledConfigurationExecutionHandle;
    origin: Readonly<WorkflowScheduledConfigurationExecutionProof> }; }
/** One fixed Namespace consumer. A non-null result means that the exact
 * current Namespace verification has closed the same SQL tuple. Ordinary
 * checkpoints also perform full live SDK authorization for all parties; a
 * genuine SDK preparation phase supplies current SQL prechecks only and
 * cannot be used as the final Native gate.
 * This is never accepted from HTTP, an execution proof or a DTO. */
export interface WorkflowScheduledAuthorityInspectionPolicy {
  consume(namespaceHandle:object,namespace:Readonly<WorkflowScheduledNamespaceProof>,checkpoint:WorkflowScheduledNamespaceCheckpoint,transaction:DbService):
    Promise<Readonly<{approvalSet:WorkflowApprovalSet}>|null>;
  loadApprovalSet?(plan:Readonly<WorkflowPlanV1>,executionId:string,namespaceHandle:object,transaction:DbService):Promise<WorkflowApprovalSet|null>;
}
interface RecoveryState { proof: IssueActivationRecoveryProof; active: boolean; key: string; revision: number; planHash: string; keySecret: string; }

/** All capability inputs are re-read from immutable SQL and encrypted plans.
 * HTTP IDs only locate rows; only this service mints private execution proofs. */
@Injectable()
export class ApprovedWorkflowExecutionService implements OnModuleInit, ApprovedExecutionPolicy {
  readonly #portalInvocation=new AsyncLocalStorage<{original:Readonly<PortalInspectionInvocationOriginal>;active:boolean;actor:unknown;operation:unknown;archive:unknown;kind:unknown;action:unknown;clusterId:unknown;workspaceId:unknown}>();
  readonly #portalInvocationHandles=new WeakMap<object,{original:Readonly<PortalInspectionInvocationOriginal>;active:boolean;actor:unknown;operation:unknown;archive:unknown;kind:unknown;action:unknown;clusterId:unknown;workspaceId:unknown}>();
  #portalInvocationVerifierInstalled=false;
  #assertPortalInvocation(original:Readonly<PortalInspectionInvocationOriginal>):void{
    const scope=this.#portalInvocationHandles.get(original.handle),frame=this.context.current(),state=this.executions.get(original.execution);
    if(!scope||!scope.active||this.#portalInvocation.getStore()!==scope||scope.original!==original||frame!==original.frame
      ||frame.actor!==scope.actor||frame.operation!==scope.operation||frame.archive!==scope.archive||frame.kind!==scope.kind||frame.action!==scope.action
      ||frame.clusterId!==scope.clusterId||frame.workspaceId!==scope.workspaceId||frame.sessionId!=null||frame.archive
      ||!state?.active||state.proof!==original.execution||!state.scheduled||state.scheduled.handle!==original.namespaceHandle||state.scheduled.namespace!==original.namespace
      ||original.execution.origin!=='scheduled-workflow'||original.execution.sessionId!==null||original.execution.expiresAt<=Date.now()
      ||this.context.requireWorkflowScheduledNamespaceHandle()!==original.namespaceHandle)throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ORIGINAL_REQUIRED');
    const principal=this.context.requireWorkflowScheduledCurrentPrincipal(original.namespaceHandle);
    if(principal.namespace!==original.namespace||principal.actor!==original.namespace.actor||principal.role!=='executor'||principal.readOnly||principal.validationReadHandle
      ||original.namespace.kind!=='portal-credential-issue'||frame.actor?.id!==original.execution.actorId||frame.clusterId!==original.execution.clusterId||frame.workspaceId!==original.execution.workspaceId
      ||original.execution.scheduleClaimId!==original.namespace.claim.id||original.execution.workflowId!==original.namespace.workflow.id)throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ORIGINAL_REQUIRED');
    if(original.step){const bound=this.steps.get(original.step);if(!bound||bound.execution!==original.execution||original.step.execution!==original.execution||bound.stepId!==original.step.stepId)
      throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ORIGINAL_REQUIRED');}
    let currentStep:ApprovedStepProof|null=null;try{currentStep=this.context.currentApprovedStep();}catch(error:any){if(error?.getResponse?.()?.code!=='APPROVED_STEP_REQUIRED')throw error;}
    if(currentStep&&(currentStep.execution!==original.execution||original.step&&currentStep!==original.step))throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ORIGINAL_REQUIRED');
    this.redis.assertLeaseActive();
  }
  /** Fixed Root bootstrap only; no caller can mint the selector's private ALS
   * handle or turn an original execution projection into a new invocation. */
  installPortalInspectionInvocationVerifier():Readonly<PortalInspectionInvocationVerifier>{
    if(this.#portalInvocationVerifierInstalled)throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_ALREADY_INSTALLED');this.#portalInvocationVerifierInstalled=true;
    return Object.freeze({current:()=>{const scope=this.#portalInvocation.getStore();if(!scope)return null;this.#assertPortalInvocation(scope.original);return scope.original;},
      assert:(original:Readonly<PortalInspectionInvocationOriginal>)=>this.#assertPortalInvocation(original)});
  }
  async #withPortalInvocation<T>(proof:ApprovedExecutionProof,checkpoint:WorkflowScheduledNamespaceCheckpoint,step:ApprovedStepProof|null,fn:()=>Promise<T>,transaction:DbService=this.db):Promise<T>{
    const state=this.executions.get(proof);
    if(!this.#portalInvocationVerifierInstalled||!state?.active||!state.scheduled||proof.origin!=='scheduled-workflow'||proof.sessionId!==null
      ||state.scheduled.namespace.kind!=='portal-credential-issue')return fn();
    if(this.#portalInvocation.getStore())throw deny('WORKFLOW_SCHEDULE_PORTAL_INVOCATION_REENTRANT');
    const frame=this.context.current(),original=Object.freeze({handle:Object.freeze({}),frame,namespaceHandle:state.scheduled.handle,namespace:state.scheduled.namespace,execution:proof,step,checkpoint,transaction});
    const scope={original,active:true,actor:frame.actor,operation:frame.operation,archive:frame.archive,kind:frame.kind,action:frame.action,clusterId:frame.clusterId,workspaceId:frame.workspaceId};
    this.#portalInvocationHandles.set(original.handle,scope);
    try{return await this.#portalInvocation.run(scope,async()=>{this.#assertPortalInvocation(original);const result=await fn();this.#assertPortalInvocation(original);return result;});}
    finally{scope.active=false;this.#portalInvocationHandles.delete(original.handle);}
  }
  private readonly handles = new WeakMap<object, HandleState>();
  private readonly executions = new WeakMap<object, HandleState>();
  private readonly steps = new WeakMap<object, { execution: ApprovedExecutionProof; stepId: string }>();
  private readonly bindings = new WeakMap<object, { step: ApprovedStepProof; contextHash: string }>();
  private readonly recoveryHandles = new WeakMap<object, RecoveryState>();
  private readonly recoveryStorage = new AsyncLocalStorage<RecoveryState>();
  private readonly configuration: ConfigurationApprovedVerifier;
  private readonly configurationHandles = new WeakMap<object, HandleState>();
  private readonly configurationExecutions = new WeakMap<object, HandleState>();
  private readonly configurationSteps = new WeakMap<object, {execution:ApprovedExecutionProof;stepId:string}>();
  private readonly configurationBindings = new WeakMap<object, {step:ApprovedStepProof;contextHash:string}>();
  private governance?:GovernanceMetadataApprovedDelegate;
  private workflowPolicyMetadata?: WorkflowPolicyMetadataApprovedDelegate;
  private iamMetadata?:Readonly<IamMetadataApprovedDelegate>;
  private metricsSetup?:Readonly<MetricsSetupApprovedDelegate>;
  private controlMetadata?:Readonly<ControlMetadataApprovedDelegate>;
  private annotationMetadata?:Readonly<EntityAnnotationApprovedDelegate>;
  installEntityAnnotationDelegate(delegate:EntityAnnotationApprovedDelegate):void{
    const names=['verifyIntent','assertSubject','verifyReviewer','assertWorkflowAdmission'] as const;
    if(this.annotationMetadata||!delegate||names.some(key=>typeof delegate[key]!=='function')||Object.keys(delegate).some(key=>!names.includes(key as any)))throw deny('ENTITY_ANNOTATION_POLICY_ALREADY_INSTALLED');
    this.annotationMetadata=Object.freeze({verifyIntent:delegate.verifyIntent.bind(delegate),assertSubject:delegate.assertSubject.bind(delegate),verifyReviewer:delegate.verifyReviewer.bind(delegate),assertWorkflowAdmission:delegate.assertWorkflowAdmission.bind(delegate)});
  }
  private annotationPolicy(plan:WorkflowPlanV1):Readonly<EntityAnnotationApprovedDelegate>{
    assertEntityAnnotationPlan(plan);if(!this.annotationMetadata)throw deny('ENTITY_ANNOTATION_POLICY_UNAVAILABLE');return this.annotationMetadata;
  }
  async assertEntityAnnotationWorkflowAdmission(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx:DbService=this.db):Promise<void>{
    if(actor.workspaceId!==plan.workspaceId)throw deny('ANNOTATION_SCOPE_SELECTOR_DENIED');
    const policy=this.annotationPolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertWorkflowAdmission(plan,actor,action,tx);
  }
  installControlMetadataDelegate(delegate:ControlMetadataApprovedDelegate):void {
    const names=['verifyIntent','assertSubject','verifyReviewer','assertWorkflowAdmission'] as const;
    if(this.controlMetadata||!delegate||names.some(key=>typeof delegate[key]!=='function')||Object.keys(delegate).some(key=>!names.includes(key as any)))throw deny('CONTROL_METADATA_POLICY_ALREADY_INSTALLED');
    this.controlMetadata=Object.freeze({verifyIntent:delegate.verifyIntent.bind(delegate),assertSubject:delegate.assertSubject.bind(delegate),verifyReviewer:delegate.verifyReviewer.bind(delegate),assertWorkflowAdmission:delegate.assertWorkflowAdmission.bind(delegate)});
  }
  private controlPolicy(plan:WorkflowPlanV1):Readonly<ControlMetadataApprovedDelegate> {
    assertControlMetadataPlan(plan);if(!this.controlMetadata)throw deny('CONTROL_METADATA_POLICY_UNAVAILABLE');return this.controlMetadata;
  }
  async assertControlWorkflowAdmission(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx:DbService=this.db):Promise<void> {
    const policy=this.controlPolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertWorkflowAdmission(plan,actor,action,tx);
  }
  private workflowScheduled?: ApprovedWorkflowScheduledDelegate;
  private workflowScheduledInspection?:Readonly<WorkflowScheduledAuthorityInspectionPolicy>;
  readonly #deferredPortalApprovalLoads=new WeakMap<Loaded,{proof:ApprovedExecutionProof;namespaceHandle:object}>();
  private workflowScheduledReviewerRead?: Readonly<ApprovedWorkflowScheduledReviewerReadPolicy>;
  private readonly scheduledReviewerReadStorage = new AsyncLocalStorage<boolean>();
  private workflowScheduledConfiguration?: Readonly<ApprovedWorkflowScheduledConfigurationDelegate>;
  private readonly usedScheduledConfigurationExecutions = new WeakSet<object>();
  private configurationServiceBeforeObserver?: (handle:ConfigurationNativeBeforeReadHandle)=>Promise<Readonly<ConfigurationNativeBeforeReadResult>>;
  private readonly configurationBeforeReads=new WeakMap<object,{active:boolean;phase:'issued'|'reading';readDeadline:number;step:ApprovedStepProof;execution:HandleState;frame:ReturnType<KongExecutionContextService['current']>;transaction:DbService;binding:Readonly<ConfigurationNativeBeforeBinding>;intent:Readonly<ConfigurationNativeBeforeReadIntent>}>();
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly authz: AuthorizationService,
    private readonly workspaces: WorkspaceResolverService, private readonly kong: KongService, private readonly redis: RedisService,
    private readonly context: KongExecutionContextService,
    @Optional() private readonly approvals?: WorkflowApprovalAuthorityService) {this.configuration=new ConfigurationApprovedVerifier(db,secrets,authz,kong,redis,context,approvals);
      this.configuration.installNativeBeforeReader({read:(step,binding)=>this.readBoundConfigurationNativeBefore(step,binding)});
      }
  onModuleInit(): void {
    this.context.installApprovedPolicy(this);
    // These are fixed server delegates. They inspect a real reviewer's SQL
    // grants without adopting that reviewer's session in the executor's ALS.
    if (this.approvals) for (const kind of WORKFLOW_KINDS) {
      if (kind === 'native-change') continue;
      if (String(kind) === 'workflow-policy-metadata') continue;
      this.approvals.installReviewerPolicy(kind, { verifyCurrent: (id, plan, tx) => this.verifyCurrentReviewer(id, plan, tx) });
    }
    this.approvals?.installScheduledConfigurationCanonicalSqlPolicy({ verifyCurrent: async (id, plan, tx) => {
      if (plan.kind !== 'configuration_v2' || !('scheduling' in plan)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED');
      const user = await tx.one<any>("SELECT id,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false", [id]);
      if (!user) throw deny('APPROVED_APPROVER_REVOKED');
      await this.configurationCanonicalReviewerSql(user, plan, tx);
    } });
  }
  installConfigurationDelegate(delegate:ConfigurationApprovedDelegate):void{this.configuration.install(delegate);}
  installWorkflowScheduledDelegate(delegate: ApprovedWorkflowScheduledDelegate): void {
    if (this.workflowScheduled || !delegate || typeof delegate.runValidationRead !== 'function' || typeof delegate.assertConfigurationOrigin !== 'function') throw deny('WORKFLOW_SCHEDULE_APPROVED_POLICY_ALREADY_INSTALLED');
    this.workflowScheduled = Object.freeze(delegate);
    if(delegate.readConfigurationNativeBefore&&typeof this.context.installConfigurationServiceBeforeObserver==='function')this.configurationServiceBeforeObserver=this.context.installConfigurationServiceBeforeObserver({read:handle=>{
      if(!this.workflowScheduled?.readConfigurationNativeBefore)throw deny('CONFIGURATION_BEFORE_READER_REQUIRED');return this.workflowScheduled.readConfigurationNativeBefore(handle);
    }});
  }
  installWorkflowScheduledAuthorityInspectionPolicy(policy:WorkflowScheduledAuthorityInspectionPolicy):void{
    if(this.workflowScheduledInspection||!policy||Object.keys(policy).some(key=>!['consume','loadApprovalSet'].includes(key))||typeof policy.consume!=='function'||policy.loadApprovalSet!==undefined&&typeof policy.loadApprovalSet!=='function')throw deny('WORKFLOW_SCHEDULE_FRESH_INSPECTION_POLICY_ALREADY_INSTALLED');
    this.workflowScheduledInspection=Object.freeze({consume:policy.consume.bind(policy),...(policy.loadApprovalSet?{loadApprovalSet:policy.loadApprovalSet.bind(policy)}:{})});
  }
  installWorkflowScheduledReviewerReadPolicy(policy: ApprovedWorkflowScheduledReviewerReadPolicy): void {
    if (this.workflowScheduledReviewerRead || !policy || typeof policy.verifyCurrent !== 'function'
      || Object.keys(policy).some(key => key !== 'verifyCurrent')) throw deny('WORKFLOW_SCHEDULE_REVIEWER_READ_POLICY_ALREADY_INSTALLED');
    this.workflowScheduledReviewerRead = Object.freeze({ verifyCurrent: policy.verifyCurrent.bind(policy) });
  }
  installWorkflowScheduledConfigurationDelegate(delegate: ApprovedWorkflowScheduledConfigurationDelegate): void {
    if (this.workflowScheduledConfiguration || !delegate || typeof delegate.verifyExecution !== 'function') throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_APPROVED_POLICY_ALREADY_INSTALLED');
    this.workflowScheduledConfiguration = Object.freeze({ verifyExecution: delegate.verifyExecution.bind(delegate) });
  }
  private originalConfigurationBeforeRead(handle:ConfigurationNativeBeforeReadHandle,tx:DbService){
    const state=this.configurationBeforeReads.get(handle),frame=this.context.current(),bound=state&&this.configurationSteps.get(state.step);
    if(!state?.active||state.transaction!==tx||state.frame!==frame||!bound||bound.execution!==state.step.execution||bound.stepId!==state.step.stepId
      ||this.configurationExecutions.get(state.step.execution)!==state.execution||!state.execution.active||!state.execution.scheduledConfiguration
      ||this.context.currentApprovedStep()!==state.step||frame.operation?.operationId!==state.intent.operationId||frame.sessionId!=null
      ||this.context.requireWorkflowScheduledNamespaceHandle()!==state.intent.namespaceHandle||state.intent.expiresAt<=Date.now()||performance.now()>=state.readDeadline)throw deny('CONFIGURATION_BEFORE_ORIGINAL_READ_REQUIRED');
    return state;
  }
  async beginConfigurationNativeBeforeRead(handle:ConfigurationNativeBeforeReadHandle,tx:DbService):Promise<Readonly<ConfigurationNativeBeforeReadIntent>>{
    const state=this.originalConfigurationBeforeRead(handle,tx);if(state.phase!=='issued')throw deny('CONFIGURATION_BEFORE_READ_ALREADY_ENTERED');state.phase='reading';
    await this.configuration.assertNativeBeforeBinding(state.binding,tx);if(this.originalConfigurationBeforeRead(handle,tx)!==state)throw deny('CONFIGURATION_BEFORE_ORIGINAL_READ_REQUIRED');return state.intent;
  }
  /** Root's new finite read round may only shorten this invocation. This
   * private-state fence survives the delegate's final Promise continuation;
   * it never renews an ancestor frame, claim, namespace or SQL proof. */
  limitConfigurationNativeBeforeRead(handle:ConfigurationNativeBeforeReadHandle,tx:DbService,deadline:number):void{
    const state=this.originalConfigurationBeforeRead(handle,tx);
    if(state.phase!=='reading'||!Number.isFinite(deadline)||deadline<=performance.now()||deadline>performance.now()+30000)
      throw deny('CONFIGURATION_BEFORE_READ_DEADLINE_INVALID');
    state.readDeadline=Math.min(state.readDeadline,deadline);
  }
  async assertConfigurationNativeBeforeRead(handle:ConfigurationNativeBeforeReadHandle,tx:DbService):Promise<void>{
    const state=this.originalConfigurationBeforeRead(handle,tx);if(state.phase!=='reading')throw deny('CONFIGURATION_BEFORE_READ_NOT_ENTERED');
    await this.configuration.assertNativeBeforeBinding(state.binding,tx);if(this.originalConfigurationBeforeRead(handle,tx)!==state)throw deny('CONFIGURATION_BEFORE_ORIGINAL_READ_REQUIRED');
  }
  assertConfigurationNativeBeforeReadLive(handle:ConfigurationNativeBeforeReadHandle,tx:DbService):void{
    const state=this.originalConfigurationBeforeRead(handle,tx);if(state.phase!=='reading'||!Number.isFinite(state.readDeadline))throw deny('CONFIGURATION_BEFORE_READ_NOT_ENTERED');this.redis.assertLeaseActive();
  }
  async readConfigurationNativeBefore(proof:ApprovedStepProof,input:Readonly<ConfigurationNativeBeforeInput>,observation?:'service-destination'):Promise<Readonly<ConfigurationNativeBeforeReadResult>>{
    const state=this.configurationExecutions.get(proof.execution),bound=this.configurationSteps.get(proof);
    if(!state?.active||!state.scheduledConfiguration||!bound||bound.execution!==proof.execution||bound.stepId!==proof.stepId
      ||this.context.currentApprovedStep()!==proof||proof.kind!=='native')throw deny('CONFIGURATION_BEFORE_ORIGINAL_STEP_REQUIRED');
    const binding=await this.configuration.nativeBeforeBinding(proof.execution,proof.stepId,input);
    return this.readBoundConfigurationNativeBefore(proof,binding,observation);
  }
  private async readBoundConfigurationNativeBefore(proof:ApprovedStepProof,binding:Readonly<ConfigurationNativeBeforeBinding>,observation?:'service-destination'):Promise<Readonly<ConfigurationNativeBeforeReadResult>>{
    const state=this.configurationExecutions.get(proof.execution),bound=this.configurationSteps.get(proof),frame=this.context.current(),original=state?.scheduledConfiguration;
    if(!state?.active||!original||!bound||bound.execution!==proof.execution||bound.stepId!==proof.stepId||proof.kind!=='native'
      ||this.context.currentApprovedStep()!==proof||binding.input.frame!==frame||frame.operation?.operationId!==binding.input.operationId
      ||binding.loaded.execution.id!==proof.execution.executionId||binding.row.id!==proof.stepId||binding.step.stepId!==binding.row.plan_step_id
      ||proof.execution.origin!=='scheduled-configuration'||proof.execution.sessionId!==null||frame.sessionId!=null
      ||!this.workflowScheduled?.readConfigurationNativeBefore)throw deny('CONFIGURATION_BEFORE_ORIGINAL_STEP_REQUIRED');
    if(observation!==undefined&&observation!=='service-destination'||observation&&!(binding.step.entityType==='services'&&binding.request.method==='PATCH'))throw deny('CONFIGURATION_SERVICE_OBSERVATION_INVALID');
    const{loaded,step,request,input}=binding,namespace=this.context.requireWorkflowScheduledCurrentPrincipal(original.origin.namespaceHandle).namespace;
    const append=step.entityType==='targets'&&step.mutationAction==='update'&&step.allocatedNativeId!==step.nativeId;
    const intent:Readonly<ConfigurationNativeBeforeReadIntent>=Object.freeze({namespaceHandle:original.origin.namespaceHandle,namespace,clusterId:input.clusterId,workspaceId:step.objectWorkspaceId,
      actorId:proof.execution.actorId,workflowId:proof.execution.workflowId,jobId:loaded.job.id,executionId:loaded.execution.id,jobStepId:binding.row.id,planStepId:step.stepId,
      ...(observation?{observation}:{}),planId:loaded.job.plan_id,planRevision:loaded.job.plan_revision,planHash:loaded.job.plan_hash,operationId:input.operationId,method:request.method,canonicalPath:request.canonicalPath,
      beforePath:append?`${request.canonicalPath}/${step.nativeId}`:request.method==='POST'?`${request.canonicalPath}/${step.allocatedNativeId??step.nativeId}`:request.canonicalPath,
      ...(append?{allocatedPath:`${request.canonicalPath}/${step.allocatedNativeId}`}:{}),entityType:step.entityType,
      ...(step.nativeId?{nativeId:step.nativeId}:{}),...(step.allocatedNativeId?{allocatedNativeId:step.allocatedNativeId}:{}),...(step.parentId?{parentId:step.parentId}:{}),...(step.credentialKind?{credentialKind:step.credentialKind}:{}),
      bodyHmac:request.bodyHmac,beforeHmac:request.beforeHmac,mutationAction:step.mutationAction,expiresAt:Math.min(proof.execution.expiresAt,loaded.claimExpiresAt,Date.parse(namespace.expiresAt))});
    const handle=Object.freeze({})as ConfigurationNativeBeforeReadHandle,read={active:true,phase:'issued'as const,readDeadline:Infinity,step:proof,execution:state,frame,transaction:this.db,binding,intent};
    this.configurationBeforeReads.set(handle,read);
    try{if(step.entityType==='services'&&request.method==='PATCH'&&!this.configurationServiceBeforeObserver)throw deny('CONFIGURATION_SERVICE_BEFORE_OBSERVER_REQUIRED');
      const result=await (this.configurationServiceBeforeObserver?this.configurationServiceBeforeObserver(handle):this.workflowScheduled.readConfigurationNativeBefore(handle));this.originalConfigurationBeforeRead(handle,this.db);this.assertConfigurationNativeBeforeReadLive(handle,this.db);
      if(!result||Object.keys(result).some(key=>!['before','allocatedAbsent','serviceHostUpstream','serviceTargets','serviceReferences'].includes(key))||!Object.hasOwn(result,'before')
        ||append&&typeof result.allocatedAbsent!=='boolean'||!append&&result.allocatedAbsent!==undefined
        ||step.entityType!=='services'&&(result.serviceHostUpstream!==undefined||result.serviceTargets!==undefined)
        ||observation!=='service-destination'&&result.serviceTargets!==undefined||result.serviceTargets!==undefined&&!Array.isArray(result.serviceTargets))throw deny('CONFIGURATION_BEFORE_RESULT_INVALID');
      const service=step.entityType==='services'&&request.method==='PATCH',effective:any={...(result.before as any),...(step.body as any)};
      if(service){
        if(!Array.isArray(result.serviceReferences))throw deny('CONFIGURATION_SERVICE_TLS_RESULT_REQUIRED');
        const expected=new Set<string>(),id=(v:any)=>typeof v==='string'?v:v?.id;
        if(id(effective.client_certificate))expected.add(`certificates:${id(effective.client_certificate)}`);
        if(Array.isArray(effective.ca_certificates))for(const v of effective.ca_certificates)if(id(v))expected.add(`ca_certificates:${id(v)}`);
        const actual=new Set<string>();for(const ref of result.serviceReferences){const value=ref as any,key=`${value?.entityType}:${value?.entity?.id}`;
          if(!value||Object.keys(value).some(k=>!['entityType','entity'].includes(k))||!['certificates','ca_certificates'].includes(value.entityType)||!uuid.test(value.entity?.id??'')||actual.has(key)||!expected.has(key))throw deny('CONFIGURATION_SERVICE_TLS_RESULT_INVALID');actual.add(key);}
        if(actual.size!==expected.size)throw deny('CONFIGURATION_SERVICE_TLS_RESULT_INVALID');
      }else if(Object.hasOwn(result,'serviceReferences'))throw deny('CONFIGURATION_SERVICE_TLS_RESULT_INVALID');
      const named=service&&typeof effective.host==='string'&&!isIP(effective.host.replace(/^\[|\]$/g,''));
      if(named){const upstream=result.serviceHostUpstream as any;
        if(!Object.hasOwn(result,'serviceHostUpstream')||upstream===undefined||upstream!==null&&(!upstream||typeof upstream!=='object'||Array.isArray(upstream)
          ||!uuid.test(upstream.id??'')||upstream.name!==effective.host))throw deny('CONFIGURATION_SERVICE_REFERENCE_RESULT_INVALID');
        if(observation==='service-destination'&&(!Array.isArray(result.serviceTargets)||upstream===null&&result.serviceTargets.length!==0))throw deny('CONFIGURATION_SERVICE_DESTINATION_RESULT_INVALID');
      }else if(Object.hasOwn(result,'serviceHostUpstream')||Object.hasOwn(result,'serviceTargets'))throw deny('CONFIGURATION_SERVICE_REFERENCE_RESULT_INVALID');
      return immutableJson(result);
    }finally{read.active=false;this.configurationBeforeReads.delete(handle);}
  }
  private originalScheduledHandle(): object | null {
    if (typeof this.context.hasWorkflowScheduledNamespace !== 'function' || !this.context.hasWorkflowScheduledNamespace()) return null;
    if (!this.workflowScheduled || this.context.current().sessionId != null) throw deny('WORKFLOW_SCHEDULE_APPROVED_POLICY_UNAVAILABLE');
    return this.context.requireWorkflowScheduledNamespaceHandle();
  }
  private async validationRead<T>(clusterId: string, path: string, fn: () => Promise<T>, tx = this.db, reviewerId?: string): Promise<T> {
    assertKongPath('GET', path);
    const handle = this.originalScheduledHandle();
    const read = () => this.context.runInternalRead(clusterId, 'authorization', fn, { paths: [path], maxCalls: 1 });
    return handle ? this.workflowScheduled!.runValidationRead(handle, clusterId, Object.freeze([path]), tx, read,
      reviewerId ? Object.freeze({ role: 'reviewer' as const, userId: reviewerId }) : undefined) : read();
  }
  assertConfigurationOrigin(plan:WorkflowPlanV1,actorId:string,action:'read'|'write'|'approve',tx:DbService=this.db):Promise<void>{
    const handle = this.originalScheduledHandle();
    return handle ? this.workflowScheduled!.assertConfigurationOrigin(handle, plan, actorId, action, tx) : this.configuration.assertOrigin(plan,actorId,action,tx);
  }
  installGovernanceMetadataDelegate(delegate:GovernanceMetadataApprovedDelegate):void{
    if(this.governance||!delegate||typeof delegate.verifyIntent!=='function'||typeof delegate.assertSubject!=='function'||typeof delegate.verifyReviewer!=='function')throw deny('GOVERNANCE_WORKFLOW_POLICY_ALREADY_INSTALLED');
    this.governance=Object.freeze(delegate);
  }
  private governancePolicy(plan:WorkflowPlanV1):GovernanceMetadataApprovedDelegate{
    assertGovernanceMetadataPlan(plan);if(!this.governance)throw deny('GOVERNANCE_WORKFLOW_POLICY_UNAVAILABLE');return this.governance;
  }
  installWorkflowPolicyMetadataDelegate(delegate: WorkflowPolicyMetadataApprovedDelegate): void {
    if (this.workflowPolicyMetadata || !delegate || typeof delegate.verifyIntent !== 'function' || typeof delegate.assertSubject !== 'function' || typeof delegate.verifyReviewer !== 'function') throw deny('WORKFLOW_POLICY_DELEGATE_ALREADY_INSTALLED');
    this.workflowPolicyMetadata = Object.freeze(delegate);
  }
  private workflowPolicy(plan: WorkflowPlanV1): WorkflowPolicyMetadataApprovedDelegate {
    assertWorkflowPolicyMetadataPlan(plan);
    if (!this.workflowPolicyMetadata) throw deny('WORKFLOW_POLICY_DELEGATE_UNAVAILABLE');
    return this.workflowPolicyMetadata;
  }
  installIamMetadataDelegate(delegate:IamMetadataApprovedDelegate):void{
    if(this.iamMetadata||!delegate||['verifyIntent','assertSubject','verifyReviewer'].some(key=>typeof(delegate as any)[key]!=='function'))throw deny('IAM_WORKFLOW_POLICY_ALREADY_INSTALLED');
    this.iamMetadata=Object.freeze({verifyIntent:delegate.verifyIntent.bind(delegate),assertSubject:delegate.assertSubject.bind(delegate),verifyReviewer:delegate.verifyReviewer.bind(delegate)});
  }
  private iamPolicy(plan:WorkflowPlanV1):Readonly<IamMetadataApprovedDelegate>{
    assertIamMetadataPlan(plan);if(!this.iamMetadata)throw deny('IAM_WORKFLOW_POLICY_UNAVAILABLE');return this.iamMetadata;
  }
  installMetricsSetupDelegate(delegate:MetricsSetupApprovedDelegate):void{
    if(this.metricsSetup||!delegate||['verifyIntent','assertSubject','verifyReviewer','nativeWorkspace'].some(key=>typeof(delegate as any)[key]!=='function'))throw deny('METRICS_SETUP_POLICY_ALREADY_INSTALLED');
    this.metricsSetup=Object.freeze(delegate);
  }
  private metricsPolicy(plan:WorkflowPlanV1):Readonly<MetricsSetupApprovedDelegate>{
    assertMetricsSetupPlan(plan);if(!this.metricsSetup)throw deny('METRICS_SETUP_POLICY_UNAVAILABLE');return this.metricsSetup;
  }
  async verifyMetricsSetupExecution(plan:WorkflowPlanV1,executionId:string,phase:'native'|'metadata',tx:DbService=this.db):Promise<void>{
    if(!['native','metadata'].includes(phase))throw deny('METRICS_SETUP_PHASE_INVALID');
    const original=this.context.currentApprovedStep(),{loaded,step}=await this.step(original,tx);
    const policy=this.metricsPolicy(loaded.plan);
    if(plan.kind!=='metrics-setup'||loaded.execution.id!==executionId||!this.same(plan,loaded.plan)||step.kind!==phase
      ||original.execution.origin!==undefined||!original.execution.sessionId||original.execution.sessionId!==this.context.current().sessionId)throw deny('METRICS_SETUP_ORIGINAL_EXECUTION_REQUIRED');
    if(phase==='native'&&await policy.nativeWorkspace(loaded.plan,step,tx)!==loaded.plan.workspaceId)throw deny('METRICS_SETUP_PLUGIN_WORKSPACE_REQUIRED');
    await this.redis.assertLeaseOwnership();this.context.current();
  }
  private same(left: unknown, right: unknown): boolean { return this.secrets.fingerprint(left ?? null) === this.secrets.fingerprint(right ?? null); }
  private bounded(value: unknown): void { if (Buffer.byteLength(JSON.stringify(value), 'utf8') > 2 * 1024 * 1024) throw deny('APPROVED_PLAN_BUDGET'); }
  private nativePath(request: { canonicalPath: string; nativeId?: string; method: string }): string {
    return request.method === 'POST' ? `${request.canonicalPath}/${request.nativeId}` : request.canonicalPath;
  }
  /** One load is one party checkpoint: scheduled configuration_v2 executor +
   * reviewers share one SDK observation round inside it (fresh grants each). */
  private async load(executionId: string, tx = this.db, lock = false, purpose: 'execution' | 'issue-recovery' = 'execution', originalScheduledProof?:ApprovedExecutionProof): Promise<Loaded> {
    const run=()=>this.loadInner(executionId,tx,lock,purpose,originalScheduledProof);
    if(!this.workflowScheduled?.runConfigurationPartyCheckpoint||typeof this.context.hasWorkflowScheduledNamespace!=='function'||!this.context.hasWorkflowScheduledNamespace())return run();
    let handle:object;try{handle=this.context.requireWorkflowScheduledNamespaceHandle();
      if(this.context.requireWorkflowScheduledCurrentPrincipal(handle).namespace.kind!=='configuration_v2')return run();}catch{return run();}
    return this.workflowScheduled.runConfigurationPartyCheckpoint(handle,'step',tx,run);
  }
  private async loadInner(executionId: string, tx: DbService, lock: boolean, purpose: 'execution' | 'issue-recovery', originalScheduledProof?:ApprovedExecutionProof): Promise<Loaded> {
    if (!uuid.test(executionId ?? '')) throw deny();
    if (lock) await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    const execution = await tx.one<any>(`SELECT * FROM workflow_executions WHERE id=$1${lock ? ' FOR UPDATE' : ''}`, [executionId]);
    const requiredState = purpose === 'issue-recovery' ? 'uncertain' : 'executing';
    if (!execution || execution.state !== requiredState || execution.snapshot_state !== 'ready' || !execution.snapshot_secret || !digest.test(execution.snapshot_hash ?? '')) throw deny('APPROVED_EXECUTION_NOT_READY');
    const keys = [execution.cluster_id, execution.workspace_id, execution.workflow_id, execution.plan_revision];
    const workflow = await tx.one<any>(`SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3${lock ? ' FOR UPDATE' : ''}`, keys.slice(0, 3));
    const version = await tx.one<any>('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4', keys);
    if (!workflow || !version || workflow.state !== requiredState || workflow.plan_revision !== execution.plan_revision || workflow.plan_hash !== execution.plan_hash
      || version.plan_hash !== execution.plan_hash || !digest.test(execution.plan_hash ?? '') || execution.approval_required !== true
      || workflow.approval_required !== true || version.approval_required !== true || !uuid.test(execution.approved_by ?? '')
      || execution.approved_by !== workflow.approved_by || execution.execution_mode !== version.execution_mode || workflow.execution_mode !== version.execution_mode) throw deny('APPROVED_VERSION_MISMATCH');
    let plan: WorkflowPlanV1, snapshot: WorkflowSnapshotV1;
    try {
      plan = this.secrets.decrypt(version.payload_secret, planAad(...keys as [string, string, string, number]));
      snapshot = this.secrets.decrypt(execution.snapshot_secret, snapshotAad(execution.cluster_id, execution.workspace_id, execution.workflow_id, execution.id));
    } catch { throw deny('APPROVED_PLAN_INVALID'); }
    this.bounded(plan); this.bounded(snapshot);
    if (!plan || plan.version !== 1 || plan.clusterId !== keys[0] || plan.workspaceId !== keys[1] || plan.workflowId !== keys[2] || plan.planRevision !== keys[3]
      || plan.approvalRequired !== true || plan.executionMode !== version.execution_mode || !WORKFLOW_KINDS.includes(plan.kind)
      || this.secrets.fingerprint(plan) !== version.plan_hash || !Object.hasOwn(subjects, plan.subject?.type ?? '') || !uuid.test(plan.subject.id ?? '')
      || !Array.isArray(plan.steps) || plan.steps.length < 1 || plan.steps.length > 16 || version.step_count !== plan.steps.length
      || this.secrets.fingerprint(plan.steps) !== version.steps_hash || !Array.isArray(plan.prerequisites) || plan.prerequisites.length > 128
      || !['direct', 'approval'].includes(plan.executionMode)) throw deny('APPROVED_PLAN_INVALID');
    for (const value of [plan.expiresAt, version.expires_at, execution.expires_at, workflow.expires_at]) if (!Number.isFinite(new Date(value).getTime()) || new Date(value).getTime() <= Date.now()) throw deny('APPROVED_EXECUTION_EXPIRED');
    if (workflow.subject_type !== plan.subject.type || workflow.subject_id !== plan.subject.id || workflow.kind !== plan.kind
      || workflow.requester_type !== plan.requester?.type || !uuid.test(plan.requester?.id ?? '')
      || (plan.requester.type === 'console' ? workflow.requester_user_id : workflow.requester_developer_id) !== plan.requester.id
      || workflow.definition_id !== plan.definition?.id || workflow.definition_version !== plan.definition?.version
      || version.policy_version !== plan.definition?.version || !digest.test(plan.definition?.policyHash ?? '')) throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='control-metadata')await this.controlPolicy(plan).verifyIntent(plan,tx);
    else if(plan.subject.type==='control_metadata_requests'||plan.steps.some(step=>step.handler==='control.metadata'||step.entityType==='control_metadata_requests'))throw deny('APPROVED_PLAN_INVALID');
    if (plan.kind === 'configuration_v2') assertConfigurationWorkflowPlan(plan);
    else if (plan.subject.type === 'configuration_jobs'||plan.steps.some(step=>step.handler==='configuration_v2')) throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='toolbox-operation')assertToolboxWorkflowPlan(plan);
    else if(plan.subject.type==='toolbox_operations'||plan.steps.some(step=>step.handler==='toolbox.execute'))throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='workspace-migration')assertWorkspaceMigrationWorkflowPlan(plan);
    else if(plan.subject.type==='workspace_migration_plans'||plan.migration!==undefined||plan.steps.some(step=>step.mutationAction==='migrate'||step.entityType==='workspace_migration'))throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='configuration-metadata')assertConfigurationMetadataWorkflowPlan(plan);
    else if((CONFIGURATION_METADATA_RESOURCES as readonly string[]).includes(plan.subject.type)||plan.steps.some(step=>step.handler==='configuration.metadata'))throw deny('APPROVED_SUBJECT_MISMATCH');
    if (plan.kind === 'event-metadata') assertEventWorkflowPlan(plan);
    else if (subjects[plan.subject.type] === 'events') throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='governance-metadata')await this.governancePolicy(plan).verifyIntent(plan,tx);
    else if(plan.subject.type==='governance_metadata_requests'||plan.steps.some(step=>step.handler==='governance.metadata'||step.entityType==='governance_metadata_requests'))throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='iam-metadata')await this.iamPolicy(plan).verifyIntent(plan,tx);
    else if(plan.subject.type==='iam_metadata_requests'||plan.steps.some(step=>step.handler==='iam.metadata'||step.entityType==='iam_metadata_requests'))throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='metrics-setup')await this.metricsPolicy(plan).verifyIntent(plan,tx);
    else if(plan.subject.type==='metrics_setup_requests'||plan.steps.some(step=>step.handler==='metrics.setup.settings'||step.entityType==='metrics_setup_requests'))throw deny('APPROVED_SUBJECT_MISMATCH');
    if(plan.kind==='entity-annotation')await this.annotationPolicy(plan).verifyIntent(plan,tx);
    else if(plan.subject.type==='entity_annotation_requests'||plan.steps.some(step=>step.handler==='entity.annotation'||step.entityType==='entity_annotation_requests'))throw deny('APPROVED_SUBJECT_MISMATCH');
    const rows = await tx.query<any>('SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order', keys);
    const ids = new Set<string>(); let nativeCount = 0;
    if (rows.length !== plan.steps.length) throw deny('APPROVED_STEPS_INCOMPLETE');
    for (let index = 0; index < plan.steps.length; index++) {
      const step = plan.steps[index], row = rows[index];
      if (!uuid.test(step?.id ?? '') || ids.has(step.id) || !Number.isInteger(step.order) || step.order !== index + 1 || !Array.isArray(step.dependencies)
        || step.dependencies.some(id => !ids.has(id)) || new Set(step.dependencies).size !== step.dependencies.length || !Array.isArray(step.nativeRequests)) throw deny('APPROVED_STEP_INVALID');
      ids.add(step.id); nativeCount += step.nativeRequests.length;
      if (row.id !== step.id || row.plan_hash !== execution.plan_hash || row.step_key !== step.key || row.step_order !== step.order || row.kind !== step.kind
        || row.entity_type !== step.entityType || (row.entity_id ?? null) !== (step.entityId ?? null) || (row.parent_id ?? null) !== (step.parentId ?? null)
        || (row.credential_kind ?? null) !== (step.credentialKind ?? null) || row.permission_action !== step.permissionAction
        || (row.mutation_action ?? null) !== (step.mutationAction ?? null) || (row.handler ?? null) !== (step.handler ?? null)
        || (row.mutation_payload_hmac ?? null) !== (step.mutationPayloadHmac ?? null) || (row.mutation_idempotency_key ?? null) !== (step.mutationIdempotencyKey ?? null)
        || (row.before_fingerprint ?? null) !== (step.beforeFingerprint ?? null) || !this.same(row.dependencies, step.dependencies)
        || !this.same(row.native_requests, normalizedNativeRequests(step.nativeRequests, this.secrets))
        || (row.metadata_before_hmac ?? null) !== (step.metadataBeforeHmac ?? null) || (row.metadata_payload_hmac ?? null) !== (step.metadataPayloadHmac ?? null)
        || (row.metadata_revision ?? null) !== (step.metadataRevision ?? null) || row.execution_mode !== plan.executionMode || row.approval_required !== true) throw deny('APPROVED_NORMALIZED_STEP_MISMATCH');
      if (step.kind === 'native') {
        if (step.nativeRequests.length < 1 || !(plan.kind==='workspace-migration'?['migrate']:['create', 'update', 'delete', 'restore']).includes(step.mutationAction ?? '') || !step.mutationIdempotencyKey
          || step.mutationPayloadHmac !== this.secrets.fingerprint(step.mutationPayload ?? null) || step.beforeFingerprint !== this.secrets.fingerprint(step.before ?? null)) throw deny('APPROVED_NATIVE_STEP_INVALID');
        for (const request of step.nativeRequests) {
          assertKongPath(request.method, request.canonicalPath);
          if (!['POST', 'PATCH', 'DELETE'].includes(request.method) || !uuid.test(request.nativeId ?? '') || request.bodyHmac !== this.secrets.fingerprint(request.body ?? null)) throw deny('APPROVED_NATIVE_REQUEST_INVALID');
          if (request.method === 'POST' && (request.body as any)?.id !== request.nativeId) throw deny('APPROVED_CREATED_ID_MISMATCH');
        }
      } else if (step.kind !== 'metadata' || step.nativeRequests.length || row.operation_id || step.mutationAction || !step.handler
        || step.metadataPayloadHmac !== this.secrets.fingerprint(step.metadata ?? null) || !digest.test(step.metadataBeforeHmac ?? '') || !Number.isInteger(step.metadataRevision)) throw deny('APPROVED_METADATA_STEP_INVALID');
    }
    if (nativeCount > 32 || version.native_request_count !== nativeCount) throw deny('APPROVED_PLAN_BUDGET');
    if (purpose === 'issue-recovery' && (plan.kind !== 'portal-credential-issue' || plan.subject.type !== 'portal_application_grants'
      || plan.steps.length !== 4 || nativeCount !== 3 || plan.steps.slice(0, 3).some(step => step.kind !== 'native')
      || plan.steps[3].kind !== 'metadata' || plan.steps[3].handler !== 'portal.credential.activate'
      || rows.slice(0, 3).some(row => row.state !== 'succeeded') || rows[3].state !== 'uncertain' || rows[3].operation_id
      || rows[3].after_fingerprint || rows[3].recycle_entry_id || rows[3].receipt_secret || Object.keys(rows[3].safe_result ?? {}).length)) throw deny('PORTAL_RECOVERY_NOT_ELIGIBLE');
    if (!snapshot || snapshot.version !== 1 || snapshot.clusterId !== keys[0] || snapshot.workspaceId !== keys[1] || snapshot.workflowId !== keys[2]
      || snapshot.executionId !== execution.id || snapshot.planRevision !== execution.plan_revision || snapshot.planHash !== execution.plan_hash
      || this.secrets.fingerprint(snapshot) !== execution.snapshot_hash || !Array.isArray(snapshot.objects) || snapshot.objects.length > 256) throw deny('APPROVED_SNAPSHOT_INVALID');
    const objectPaths = new Set<string>();
    for (const object of snapshot.objects) {
      if (!object || typeof object.path !== 'string' || objectPaths.has(object.path) || object.fingerprint !== this.secrets.fingerprint(object.before ?? null)
        || object.absent !== (object.before === null)) throw deny('APPROVED_SNAPSHOT_INVALID');
      assertKongPath('GET', object.path); objectPaths.add(object.path);
    }
    for (const prerequisite of plan.prerequisites) {
      const object = snapshot.objects.find(item => item.path === prerequisite.path && item.type === prerequisite.type && item.id === prerequisite.id);
      if (!object || object.absent || object.fingerprint !== prerequisite.fingerprint || !this.same(object.before, prerequisite.before)) throw deny('APPROVED_SNAPSHOT_INCOMPLETE');
    }
    for (const step of plan.steps) for (const request of step.nativeRequests) {
      const object = snapshot.objects.find(item => item.path === this.nativePath(request) && item.type === request.nativeType && item.id === request.nativeId);
      if (!object || request.method === 'POST' && !object.absent || request.method !== 'POST' && (object.absent || object.fingerprint !== (request.beforeHmac ?? step.beforeFingerprint))) throw deny('APPROVED_SNAPSHOT_INCOMPLETE');
    }
    const approvalFormat = version.approval_format ?? 1;
    if (![1, 2].includes(approvalFormat) || (workflow.approval_format ?? 1) !== approvalFormat || (execution.approval_format ?? 1) !== approvalFormat) throw deny('APPROVED_DECISION_INVALID');
    if(plan.kind==='entity-annotation'&&approvalFormat!==2)throw deny('ENTITY_ANNOTATION_APPROVAL_FORMAT_REQUIRED');
    let approvalSet: WorkflowApprovalSet | undefined;
    let deferredPortalApproval:{proof:ApprovedExecutionProof;namespaceHandle:object}|undefined;
    if (approvalFormat === 2) {
      if (!this.approvals) throw deny('WORKFLOW_APPROVAL_POLICY_UNAVAILABLE');
      // SQL canonical approval facts may replace this redundant SDK pass
      // only inside an ALREADY issued original Portal Native operation. The
      // fresh Namespace all-party SDK check and one-shot SQL closing below
      // remain mandatory before this Loaded value can authorize a packet.
      const original=originalScheduledProof&&this.executions.get(originalScheduledProof),frame=this.context.current();
      const invocation=this.#portalInvocation.getStore();if(invocation)this.#assertPortalInvocation(invocation.original);
      if(purpose==='execution'&&plan.kind==='portal-credential-issue'&&originalScheduledProof?.origin==='scheduled-workflow'
        &&original?.active&&original.scheduled&&(frame.kind==='operation'&&frame.operation||invocation?.original.execution===originalScheduledProof)&&frame.sessionId==null
        &&execution.id===originalScheduledProof.executionId&&frame.actor?.id===originalScheduledProof.actorId){
        const eligible=invocation?.original.execution===originalScheduledProof&&invocation.original.namespaceHandle===original.scheduled.handle;
        const step=eligible?invocation.original.step:this.context.currentApprovedStep(),bound=step&&this.steps.get(step);
        if((eligible||step?.kind==='native'&&step.execution===originalScheduledProof&&bound?.execution===originalScheduledProof&&bound.stepId===step.stepId)
          &&this.context.requireWorkflowScheduledNamespaceHandle()===original.scheduled.handle){
          const canonical=await this.workflowScheduledInspection?.loadApprovalSet?.(plan,execution.id,original.scheduled.handle,tx);
          if(canonical){approvalSet=canonical;deferredPortalApproval={proof:originalScheduledProof,namespaceHandle:original.scheduled.handle};}
        }
      }
      approvalSet??=await this.approvals.verifyApprovalSet(plan,{executionId:execution.id,checkpoint:'step'},tx);
      if (approvalSet.format !== 2 || !approvalSet.setId || !approvalSet.setHmac) throw deny('APPROVED_DECISION_INVALID');
    } else {
      // Preserve the exact V1 single-decision branch; no V2 fallback can use
      // this legacy display approver as a complete approval set.
      const approvals = await tx.query<any>('SELECT * FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4', keys);
      const stages = await tx.query<any>('SELECT * FROM workflow_stages WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4', keys);
      const definition = await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4', [plan.clusterId, plan.workspaceId, plan.definition.id, plan.definition.version]);
      if (approvals.length !== 1 || approvals[0].decision !== 'approve' || approvals[0].approver_id !== execution.approved_by || approvals[0].plan_hash !== execution.plan_hash
        || approvals[0].level !== 1 || stages.length !== 1 || stages[0].state !== 'approved' || stages[0].required_approvals !== 1 || stages[0].level !== 1
        || stages[0].plan_hash !== execution.plan_hash || !definition || definition.mode !== 'single' || definition.allow_self_approval !== false || definition.policy_hash !== plan.definition.policyHash
        || workflow.requester_type === 'console' && workflow.requester_user_id === execution.approved_by && workflow.self_approved !== true) throw deny('APPROVED_DECISION_INVALID');
      // SQL052: self-approved facts are re-validated (flag on + active super-admin) by verifyApprovalSet below/at seal.
    }
    if(plan.kind==='control-metadata') {
      // The fixed Native-zero handler can repair an unreachable Admin URL.
      // Original SQL scope and live/scheduled identity replace only this transport gate.
      const frame=this.context.current();
      if(!frame.actor||(!frame.sessionId&&!(typeof this.context.hasWorkflowScheduledNamespace==='function'&&this.context.hasWorkflowScheduledNamespace())))throw deny('CONTROL_ACTOR_CONTEXT_REQUIRED');
      await this.assertControlWorkflowAdmission(plan,{user:frame.actor,workspaceId:frame.workspaceId,requestId:frame.requestId,ip:frame.ip},'write',tx);
      return {execution,workflow,version,plan,snapshot,rows,...(approvalSet?{approvalSet}:{})};
    }
    const cluster = await tx.one<any>('SELECT id,admin_url,transport_scope,revision,execution_mode,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL', [plan.clusterId]);
    const workspace = await this.workspaces.resolve(plan.clusterId, plan.workspaceId);
    if (!cluster || cluster.status === 'disabled' || cluster.revision !== plan.scope.clusterRevision || cluster.execution_mode !== plan.executionMode || !isSupportedKong(cluster.version ?? '')
      || workspace.status !== 'active' || workspace.revision !== plan.scope.workspaceRevision || transportScopeFor(cluster.admin_url, cluster.transport_scope) !== plan.scope.transportScope) throw stale();
    if(plan.kind==='configuration_v2')await this.assertConfigurationOrigin(plan,execution.execution_actor_id,'write',tx);
    const loaded:Loaded={execution,workflow,version,plan,snapshot,rows,...(approvalSet?{approvalSet}:{})};
    if(deferredPortalApproval)this.#deferredPortalApprovalLoads.set(loaded,deferredPortalApproval);return loaded;
  }

  private async recoveryEvidence(loaded: Loaded, tx: DbService, stage: 'before' | 'after', keySecret?: string): Promise<PortalIssueNativeEvidence> {
    const evidence = await loadPortalIssueNativeEvidence(tx, this.secrets, { clusterId: loaded.plan.clusterId, workspaceId: loaded.plan.workspaceId,
      grantId: loaded.plan.subject.id, executionId: loaded.execution.id, parentState: 'uncertain', lock: tx !== this.db });
    const step = loaded.plan.steps[3], before: any = step.before, grant = evidence.grant, credential = evidence.credential;
    if (evidence.workflow.id !== loaded.workflow.id || evidence.workflow.plan_hash !== loaded.workflow.plan_hash || grant.workflow_id !== loaded.workflow.id
      || keySecret !== undefined && credential.key_secret !== keySecret || credential.workflow_id !== loaded.workflow.id
      || credential.generation !== 1 || credential.previous_credential_id || credential.revoke_operation_id || credential.revoke_workflow_id
      || credential.recycle_entry_id || credential.revoked_at || credential.deleted_at || credential.last_revealed_at) throw deny('PORTAL_RECOVERY_STATE_CHANGED');
    const refs = await tx.query<any>(`SELECT * FROM credential_refs WHERE cluster_id=$1 AND consumer_id=$2 AND ((credential_type='acls' AND kong_id=$3) OR (credential_type='key-auth' AND kong_id=$4))${tx !== this.db ? ' FOR UPDATE' : ''}`, [loaded.plan.clusterId, grant.consumer_id, grant.acl_id, credential.kong_id]);
    const aclRef = refs.find(row => row.credential_type === 'acls'), keyRef = refs.find(row => row.credential_type === 'key-auth');
    if (refs.length !== 2 || !aclRef || !keyRef || refs.some(row => row.state !== 'active')) throw deny('PORTAL_RECOVERY_REF_INVALID');
    for (const [ref, raw] of [[aclRef, evidence.acl], [keyRef, evidence.keyCredential]]) {
      let value: any; try { value = this.secrets.decrypt(ref.payload_secret, `credential:${loaded.plan.clusterId}:${grant.consumer_id}:${ref.credential_type}:${ref.kong_id}`); } catch { throw deny('PORTAL_RECOVERY_REF_INVALID'); }
      if (!this.same(value?.credential, raw)) throw deny('PORTAL_RECOVERY_REF_INVALID');
    }
    if (stage === 'before') {
      if (grant.state !== 'pending' || grant.current_generation !== 0 || grant.current_credential_id || grant.acl_credential_ref_id
        || grant.revision !== step.metadataRevision || !this.same(grant, before) || credential.state !== 'pending'
        || credential.revision !== 1 || credential.credential_ref_id || credential.issue_operation_id) throw deny('PORTAL_RECOVERY_STATE_CHANGED');
    } else {
      const expected = { ...before, state: 'active', current_generation: 1, current_credential_id: credential.id, acl_credential_ref_id: aclRef.id,
        revision: before.revision + 1, updated_at: grant.updated_at };
      if (grant.state !== 'active' || !this.same(grant, expected) || credential.state !== 'active' || credential.revision !== 2
        || credential.credential_ref_id !== keyRef.id || credential.issue_operation_id !== evidence.operationIds[2]) throw deny('PORTAL_RECOVERY_STATE_CHANGED');
    }
    return evidence;
  }

  private async recoverySession(tx: DbService, proof?: IssueActivationRecoveryProof): Promise<void> {
    const frame = this.context.current();
    if (!frame.actor || !frame.sessionId || proof && (frame.actor.id !== proof.actorId || frame.sessionId !== proof.sessionId || proof.expiresAt <= Date.now())) throw deny('PORTAL_RECOVERY_SESSION_INVALID');
    const session = await tx.one<any>(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
      AND u.status='active' AND u.deleted_at IS NULL AND u.force_password_change=false${tx !== this.db ? ' FOR SHARE OF s,u' : ''}`, [frame.sessionId, frame.actor.id]);
    if (!session || session.id !== frame.sessionId) throw deny('PORTAL_RECOVERY_SESSION_INVALID');
    this.context.current();
  }

  async canIssueActivationRecovery(executionId: string): Promise<boolean> {
    try {
      await this.recoverySession(this.db);
      const loaded = await this.load(executionId, this.db, false, 'issue-recovery');
      await this.authority(loaded); await this.recoveryEvidence(loaded, this.db, 'before');
      await this.recoverySession(this.db); return true;
    } catch (error) { if (error instanceof ForbiddenException || error instanceof ConflictException) return false; throw error; }
  }

  async runIssueActivationRecovery<T>(executionId: string, originalExecutionKey: string, workflowRevision: number, planHash: string, fn: () => Promise<T>): Promise<T> {
    if (this.recoveryStorage.getStore() || !/^[A-Za-z\d_.:-]{8,128}$/.test(originalExecutionKey)) throw deny('PORTAL_RECOVERY_CONTEXT_INVALID');
    await this.recoverySession(this.db);
    const loaded = await this.load(executionId, this.db, false, 'issue-recovery');
    if (loaded.execution.idempotency_key !== originalExecutionKey || loaded.workflow.revision !== workflowRevision || loaded.workflow.plan_hash !== planHash
      || this.context.current().idempotencyKey !== originalExecutionKey) throw deny('PORTAL_RECOVERY_REQUEST_MISMATCH');
    const current = await this.authority(loaded), evidence = await this.recoveryEvidence(loaded, this.db, 'before');
    await this.assertPrerequisites(loaded); await this.redis.assertLeaseOwnership();
    const frame = this.context.current();
    const proof = Object.freeze({ executionId, workflowId: loaded.plan.workflowId, clusterId: loaded.plan.clusterId, workspaceId: loaded.plan.workspaceId,
      transportScope: loaded.plan.scope.transportScope, actorId: current.actor.id, sessionId: frame.sessionId!, permissionVersion: current.version,
      stepId: loaded.plan.steps[3].id, expiresAt: Math.min(Date.now() + 120_000, new Date(loaded.execution.expires_at).getTime(), new Date(loaded.plan.expiresAt).getTime()) });
    const handle = Object.freeze({}) as IssueActivationRecoveryHandle;
    const state: RecoveryState = { proof, active: true, key: originalExecutionKey, revision: workflowRevision, planHash, keySecret: evidence.credential.key_secret };
    this.recoveryHandles.set(handle, state);
    try { return await this.recoveryStorage.run(state, () => this.context.runIssueActivationRecovery(handle, fn)); }
    finally { state.active = false; this.recoveryHandles.delete(handle); }
  }

  async verifyIssueActivationRecovery(handle: IssueActivationRecoveryHandle): Promise<IssueActivationRecoveryProof> {
    const state = handle && this.recoveryHandles.get(handle);
    if (!state?.active || this.recoveryStorage.getStore() !== state) throw deny('PORTAL_RECOVERY_REQUIRED');
    await this.recoverySession(this.db, state.proof);
    const loaded = await this.load(state.proof.executionId, this.db, false, 'issue-recovery');
    if (loaded.execution.idempotency_key !== state.key || loaded.workflow.revision !== state.revision || loaded.workflow.plan_hash !== state.planHash
      || this.context.current().idempotencyKey !== state.key) throw deny('PORTAL_RECOVERY_REQUEST_MISMATCH');
    await this.authority(loaded, state.proof); await this.recoveryEvidence(loaded, this.db, 'before', state.keySecret);
    await this.recoverySession(this.db, state.proof); await this.redis.assertLeaseOwnership(); this.context.current(); return state.proof;
  }

  async assertIssueActivationRecovery(input: Readonly<ApprovedMetadataInput>, tx: DbService, stage: 'before' | 'after'): Promise<void> {
    const state = this.recoveryStorage.getStore();
    if (!state?.active || tx === this.db) throw deny('PORTAL_RECOVERY_REQUIRED');
    await this.recoverySession(tx, state.proof);
    const loaded = await this.load(state.proof.executionId, tx, true, 'issue-recovery'), step = loaded.plan.steps[3];
    if (loaded.execution.idempotency_key !== state.key || loaded.workflow.revision !== state.revision || loaded.workflow.plan_hash !== state.planHash
      || this.context.current().idempotencyKey !== state.key || input.handler !== 'portal.credential.activate' || input.actor.id !== state.proof.actorId
      || input.clusterId !== loaded.plan.clusterId || input.workspaceId !== loaded.plan.workspaceId || input.entityType !== 'portal_application_grants'
      || input.entityId !== step.entityId || input.revision !== step.metadataRevision || !this.same(input.before, step.before)
      || !this.same(input.payload, step.metadata)) throw deny('PORTAL_RECOVERY_REQUEST_MISMATCH');
    await this.authority(loaded, state.proof); await this.recoveryEvidence(loaded, tx, stage, state.keySecret);
    await this.recoverySession(tx, state.proof); await this.redis.assertLeaseOwnership(); this.context.current();
  }

  /** An archived subject is usable only through its exact, persisted restore
   * plan. This permits workflow review, not a general deleted-object read. */
  private async archivedMetadataRestore(plan: WorkflowPlanV1, row: any, tx: DbService): Promise<boolean> {
    const handler = plan.subject.type === 'portal_content' ? 'portal.page.draft'
      : plan.subject.type === 'portal_publications' ? 'portal.publication.draft' : null;
    const step = plan.steps?.[0], payload = step?.metadata as Record<string, unknown> | undefined;
    if (!handler || plan.version !== 1 || plan.kind !== 'portal-metadata' || plan.executionMode !== 'approval' || plan.approvalRequired !== true
      || plan.requester?.type !== 'console' || plan.steps?.length !== 1 || !Array.isArray(plan.prerequisites) || plan.prerequisites.length || plan.generated !== undefined
      || step.kind !== 'metadata' || step.handler !== handler || step.entityType !== plan.subject.type || step.entityId !== plan.subject.id
      || step.order !== 1 || step.permissionAction !== 'write' || !Array.isArray(step.dependencies) || step.dependencies.length
      || !Array.isArray(step.nativeRequests) || step.nativeRequests.length || step.parentId !== undefined || step.credentialKind !== undefined
      || step.mutationAction !== undefined || step.mutationPayload !== undefined || step.mutationPayloadHmac !== undefined || step.mutationIdempotencyKey !== undefined || step.beforeFingerprint !== undefined
      || !payload || Array.isArray(payload) || Object.keys(payload).length !== 1 || !Object.hasOwn(payload, 'archive') || payload.archive !== false
      || row.state !== 'deleted' || row.id !== plan.subject.id || row.cluster_id !== plan.clusterId || row.workspace_id !== plan.workspaceId
      || !Number.isInteger(step.metadataRevision) || step.metadataRevision !== row.revision || !this.same(step.before, row)
      || step.metadataBeforeHmac !== this.secrets.fingerprint(row) || step.metadataPayloadHmac !== this.secrets.fingerprint(payload)) return false;
    const keys = [plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision], hash = this.secrets.fingerprint(plan);
    const workflow = await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', keys.slice(0, 3));
    const version = await tx.one<any>('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4', keys);
    if (!workflow || !version || workflow.kind !== plan.kind || workflow.subject_type !== plan.subject.type || workflow.subject_id !== plan.subject.id
      || workflow.plan_revision !== plan.planRevision || workflow.plan_hash !== hash || workflow.execution_mode !== 'approval' || workflow.approval_required !== true
      || workflow.requester_type !== 'console' || workflow.requester_user_id !== plan.requester.id
      || workflow.definition_id !== plan.definition.id || workflow.definition_version !== plan.definition.version
      || version.plan_hash !== hash || version.execution_mode !== 'approval' || version.approval_required !== true || version.policy_version !== plan.definition.version
      || version.step_count !== 1 || version.native_request_count !== 0 || version.steps_hash !== this.secrets.fingerprint(plan.steps)) return false;
    try { if (!this.same(this.secrets.decrypt(version.payload_secret, planAad(...keys as [string, string, string, number])), plan)) return false; }
    catch { return false; }
    const rows = await tx.query<any>('SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order', keys);
    const normalized = rows[0];
    return rows.length === 1 && !!normalized && normalized.id === step.id && normalized.plan_hash === hash
      && normalized.execution_mode === 'approval' && normalized.approval_required === true && normalized.step_key === step.key && normalized.step_order === 1
      && normalized.kind === 'metadata' && normalized.handler === handler && normalized.entity_type === plan.subject.type && normalized.entity_id === plan.subject.id
      && normalized.permission_action === 'write' && !normalized.operation_id && !normalized.parent_id && !normalized.credential_kind
      && !normalized.mutation_action && !normalized.mutation_payload_hmac && !normalized.mutation_idempotency_key && !normalized.before_fingerprint
      && this.same(normalized.dependencies, []) && this.same(normalized.native_requests, [])
      && normalized.metadata_revision === step.metadataRevision && normalized.metadata_before_hmac === step.metadataBeforeHmac
      && normalized.metadata_payload_hmac === step.metadataPayloadHmac;
  }
  private async subject(plan: WorkflowPlanV1, tx = this.db, reviewerId?: string): Promise<{ row: any; service: any | null }> {
    const table = plan.subject.type;
    if (!Object.hasOwn(subjects, table)) throw deny('APPROVED_SUBJECT_MISMATCH');
    if (table === 'workflow_policy_requests') {
      await this.workflowPolicy(plan).verifyIntent(plan, tx);
      const row = await tx.one<any>('SELECT * FROM workflow_policy_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [plan.subject.id, plan.clusterId, plan.workspaceId]);
      if (!row || row.actor_id !== plan.requester.id || row.workflow_id !== plan.workflowId) throw deny('WORKFLOW_POLICY_BINDING_INVALID');
      return { row, service: null };
    }
    if(table==='governance_metadata_requests'){
      await this.governancePolicy(plan).verifyIntent(plan,tx);
      const row=await tx.one<any>('SELECT * FROM governance_metadata_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!row||row.actor_id!==plan.requester.id||row.workflow_id!==plan.workflowId)throw deny('GOVERNANCE_WORKFLOW_BINDING_INVALID');return{row,service:null};
    }
    if(table==='workspace_migration_plans'){
      const step=assertWorkspaceMigrationWorkflowPlan(plan),payload=step.mutationPayload as WorkspaceMigrationWorkflowPayload;
      const row=await tx.one<any>('SELECT * FROM workspace_migration_plans WHERE id=$1 AND cluster_id=$2 AND source_workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      const binding=await tx.one<any>('SELECT * FROM workspace_migration_workflow_bindings WHERE cluster_id=$1 AND migration_plan_id=$2 AND workflow_id=$3',[plan.clusterId,plan.subject.id,plan.workflowId]);
      if(!row||!binding||row.actor_id!==plan.requester.id||binding.actor_id!==row.actor_id||binding.source_workspace_id!==plan.workspaceId||binding.target_workspace_id!==row.target_workspace_id||row.target_workspace_id!==plan.migration!.targetWorkspaceId||binding.migration_plan_hash!==row.plan_hash||row.plan_hash!==payload.plan_hash||binding.material_hmac!==plan.migration!.materialHmac||Date.parse(String(row.expires_at))<Date.parse(plan.expiresAt))throw deny('MIGRATION_WORKFLOW_BINDING_INVALID');
      const material=this.secrets.decrypt<WorkspaceMigrationMaterial>(row.payload_secret,`workspace-migration:${row.id}`);
      if(material.source.id!==plan.workspaceId||material.target.id!==row.target_workspace_id||material.target.revision!==plan.migration!.targetWorkspaceRevision||material.target.name!==payload.confirm_name||material.source.cluster_id!==plan.clusterId||material.target.cluster_id!==plan.clusterId||material.conflicts.length||this.secrets.fingerprint(material)!==plan.migration!.materialHmac||this.secrets.fingerprint({cid:plan.clusterId,actor:row.actor_id,payload:material})!==row.plan_hash||!this.same(step.nativeRequests,migrationNativeRequests(material,this.secrets)))throw deny('MIGRATION_WORKFLOW_MATERIAL_INVALID');
      const prerequisites=[...material.referenceNodes,...material.nodes.filter(node=>node.inheritedOnly)].map(node=>({type:node.type,id:node.id,path:node.path,before:node.data,fingerprint:this.secrets.fingerprint(node.data)}));
      if(!this.same(plan.prerequisites,prerequisites))throw deny('MIGRATION_WORKFLOW_MATERIAL_INVALID');
      return {row:{...row,migrationMaterial:material},service:null};
    }
    if(table==='toolbox_operations'){
      const step=assertToolboxWorkflowPlan(plan),payload=step.metadata as ToolboxWorkflowPayload,row=await tx.one<any>('SELECT * FROM toolbox_operations WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!row||row.actor_id!==plan.requester.id||row.workflow_id!==plan.workflowId||row.kind!=='cache-invalidate'||row.cache_key!==payload.cacheKey||row.execution_mode!==plan.executionMode||row.transport_scope!==plan.scope.transportScope||row.cluster_revision!==plan.scope.clusterRevision||row.workspace_revision!==plan.scope.workspaceRevision||['failed','uncertain'].includes(row.state))throw deny('CACHE_WORKFLOW_BINDING_INVALID');return{row,service:null};
    }
    if(table==='configuration_jobs'){
      const step=assertConfigurationWorkflowPlan(plan),payload=step.metadata as {jobId:string;planId:string;planRevision:number;planHash:string};
      const row=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!row||row.actor_id!==plan.requester.id||row.plan_id!==payload.planId||row.plan_revision!==payload.planRevision||row.plan_hash!==payload.planHash
        ||row.transport_scope!==plan.scope.transportScope||row.execution_mode!==plan.executionMode||row.approval_required!==plan.approvalRequired
        ||row.workflow_id&&row.workflow_id!==plan.workflowId||['cancelled','expired','failed','uncertain'].includes(row.state))throw deny('CONFIGURATION_APPROVED_WRAPPER_INVALID');
      return{row,service:null};
    }
    if(plan.kind==='configuration-metadata'){
      const step=assertConfigurationMetadataWorkflowPlan(plan),metadata=step.metadata as ConfigurationMetadataPayload;
      const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[metadata.jobId,plan.clusterId,plan.workspaceId]);
      if(!job||job.kind!=='compare'||job.plan_id!=null||job.actor_id!==plan.requester.id||job.transport_scope!==plan.scope.transportScope
        ||job.cluster_revision!==plan.scope.clusterRevision||job.workspace_revision!==plan.scope.workspaceRevision||job.execution_mode!==plan.executionMode
        ||job.approval_required!==plan.approvalRequired||job.workflow_id&&job.workflow_id!==plan.workflowId
        ||['cancelled','expired','failed','uncertain','succeeded'].includes(job.state))throw deny('CONFIGURATION_METADATA_WORKFLOW_BINDING_INVALID');
      const input=configurationMetadataLedgerInput(metadata),scope={clusterId:job.cluster_id,workspaceId:job.workspace_id,transportScope:job.transport_scope,kind:job.scope_kind,rootIds:job.root_ids};
      if(!job.input_secret||!this.same(this.secrets.decrypt(job.input_secret,`configuration-job:${job.id}`),input)
        ||job.request_hmac!==this.secrets.fingerprint({scope,kind:'compare',input}))throw deny('CONFIGURATION_METADATA_WORKFLOW_BINDING_INVALID');
      const row=await tx.one<any>(`SELECT * FROM ${table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[metadata.resourceId,plan.clusterId,plan.workspaceId]);
      if(metadata.operation==='create'){
        if(row)throw deny('CONFIGURATION_METADATA_RESOURCE_OCCUPIED');
        if(table==='configuration_gitops_runs'){
          const source=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[metadata.payload.sourceJobId,plan.clusterId,plan.workspaceId]);
          if(!source||source.actor_id!==plan.requester.id||source.transport_scope!==plan.scope.transportScope)throw deny('CONFIGURATION_METADATA_SOURCE_JOB_DENIED');
        }
        return{row:null,service:null};
      }
      const owner=table==='config_snapshot_schedules'?row?.owner_user_id:row?.created_by;
      if(!row||owner!==plan.requester.id||row.transport_scope!==plan.scope.transportScope||row.revision!==step.metadataRevision||row.purged_at
        ||metadata.operation==='archive'&&!['ready','active','paused'].includes(row.state)
        ||['restore','purge'].includes(metadata.operation)&&row.state!=='deleted'
        ||metadata.operation==='update'&&!['active','paused'].includes(row.state))throw deny('CONFIGURATION_METADATA_SUBJECT_CHANGED');
      return{row,service:null};
    }
    if((CONFIGURATION_METADATA_RESOURCES as readonly string[]).includes(table))throw deny('APPROVED_SUBJECT_MISMATCH');
    if (plan.kind === 'event-metadata') {
      const step = assertEventWorkflowPlan(plan);
      const row = await tx.one<any>(`SELECT * FROM ${table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`, [plan.subject.id, plan.clusterId, plan.workspaceId]);
      if (!row || row.status === 'deleted' && !['event.channel.restore', 'event.subscription.restore', 'event.channel.delete', 'event.subscription.delete'].includes(step.handler!))
        throw deny('APPROVED_SUBJECT_UNAVAILABLE');
      return { row, service: null };
    }
    if (subjects[table] === 'events') throw deny('APPROVED_SUBJECT_MISMATCH');
    const row = await tx.one<any>(`SELECT * FROM ${table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`, [plan.subject.id, plan.clusterId, plan.workspaceId]);
    if (!row || (row.status ?? row.state) === 'rejected'
      || (row.status ?? row.state) === 'deleted' && !await this.archivedMetadataRestore(plan, row, tx)) throw deny('APPROVED_SUBJECT_UNAVAILABLE');
    let publication = table === 'portal_publications' ? row : null;
    if (table === 'portal_application_grants') {
      publication = await tx.one<any>('SELECT * FROM portal_publications WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [row.publication_id, plan.clusterId, plan.workspaceId]);
      const app = await tx.one<any>('SELECT * FROM portal_applications WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [row.application_id, plan.clusterId, plan.workspaceId]);
      const developer = await tx.one<any>('SELECT * FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [row.developer_id, plan.clusterId, plan.workspaceId]);
      if (!publication || publication.state !== 'published' || !app || app.status !== 'active' || !developer || developer.status !== 'active' || app.developer_id !== row.developer_id) throw deny('APPROVED_SUBJECT_UNAVAILABLE');
      if (this.originalScheduledHandle() && (plan.kind !== 'portal-credential-issue' || plan.requester.type !== 'developer' || row.developer_id !== plan.requester.id
        || developer.deleted_at || developer.must_change_password)) throw deny('WORKFLOW_SCHEDULE_REQUESTER_REVOKED');
    }
    if (publication) {
      if (publication.transport_scope !== plan.scope.transportScope || row.transport_scope && row.transport_scope !== plan.scope.transportScope || !uuid.test(publication.service_id ?? '')) throw deny('APPROVED_SUBJECT_MISMATCH');
      const path = `/services/${publication.service_id}`;
      const service = await this.validationRead(plan.clusterId, path, () => this.kong.request(plan.clusterId, 'GET', path), tx, reviewerId);
      if (service.id !== publication.service_id) throw deny('APPROVED_SUBJECT_MISMATCH');
      return { row, service };
    }
    return { row, service: null };
  }
  async assertSubject(plan: WorkflowPlanV1, actor: AuthUser, action: 'read' | 'write' | 'approve', tx:DbService=this.db): Promise<void> {
    if(plan.kind==='entity-annotation'){const policy=this.annotationPolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertSubject(plan,actor.id,action,tx);return;}
    if(plan.kind==='control-metadata'){const policy=this.controlPolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertSubject(plan,actor.id,action,tx);return;}
    if(plan.kind==='metrics-setup'){
      const policy=this.metricsPolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertSubject(plan,actor.id,action,tx);return;
    }
    if(plan.kind==='iam-metadata'){
      const policy=this.iamPolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertSubject(plan,actor.id,action,tx);return;
    }
    if (plan.kind === 'workflow-policy-metadata') {
      const policy = this.workflowPolicy(plan); await policy.verifyIntent(plan, tx); await policy.assertSubject(plan, actor.id, action, tx); return;
    }
    if(plan.kind==='configuration_v2')await this.assertConfigurationOrigin(plan,actor.id,action,tx);
    if(plan.kind==='governance-metadata'){
      const policy=this.governancePolicy(plan);await policy.verifyIntent(plan,tx);await policy.assertSubject(plan,actor.id,action,tx);return;
    }
    if(plan.kind==='workspace-migration'){
      const {row}=await this.subject(plan),material=row.migrationMaterial as WorkspaceMigrationMaterial;
      if(action==='write'&&actor.id!==plan.requester.id)throw deny('MIGRATION_EXECUTOR_MISMATCH');
      const version=await this.authz.permissionVersion(actor);
      for(const original of [material.source,material.target]){
        const current=await this.workspaces.get(plan.clusterId,original.id);
        if(action!=='read'&&(current.status!=='active'||current.revision!==original.revision||current.code!==original.code))throw stale('MIGRATION_WORKSPACE_CHANGED');
        await this.authz.assertWholeWorkspace(actor,plan.clusterId,original.id,'workflows',action);
        await this.authz.assertCluster(actor,plan.clusterId,'workspaces',action==='write'?'write':'read',original.id);
      }
      const sourceGraph=[...material.nodes,...material.referenceNodes],targetGraph=[...material.nodes.map(node=>({...node,data:node.inheritedOnly?node.data:{...node.data,tags:node.afterTags}})),...material.referenceNodes];
      for(const node of material.nodes){
        await this.authz.assertMigrationEntity(actor,plan.clusterId,node.type,action==='write'?'write':'read',node.data,material.source.id,sourceGraph);
        await this.authz.assertMigrationEntity(actor,plan.clusterId,node.type,action==='write'?'write':'read',node.inheritedOnly?node.data:{...node.data,tags:node.afterTags},material.target.id,targetGraph);
      }
      for(const node of material.referenceNodes){if(!node.workspaceId)throw deny('MIGRATION_REFERENCE_SCOPE_INVALID');await this.authz.assertEntity(actor,plan.clusterId,node.type,'read',node.data,node.workspaceId);}
      if(version!==await this.authz.permissionVersion(actor))throw deny('PERMISSIONS_CHANGED');return;
    }
    if(plan.kind==='toolbox-operation'){
      assertToolboxWorkflowPlan(plan);await this.subject(plan);if(action==='write'&&actor.id!==plan.requester.id)throw deny('CACHE_EXECUTOR_MISMATCH');
      await this.authz.assertWholeCluster(actor,plan.clusterId,'toolbox',action);await this.authz.assertWholeWorkspace(actor,plan.clusterId,plan.workspaceId,'workflows',action);return;
    }
    if(plan.kind==='configuration-metadata'){
      const step=assertConfigurationMetadataWorkflowPlan(plan),metadata=step.metadata as ConfigurationMetadataPayload;await this.subject(plan);
      if(action==='write'&&actor.id!==plan.requester.id)throw deny('CONFIGURATION_METADATA_EXECUTOR_MISMATCH');
      await this.authz.assertWholeWorkspace(actor,plan.clusterId,plan.workspaceId,'workflows',action);
      if(action!=='approve')await this.authz.assertWholeWorkspace(actor,plan.clusterId,plan.workspaceId,subjects[plan.subject.type],action==='write'?configurationMetadataAction(metadata):'read');
      return;
    }
    if (plan.kind === 'event-metadata') {
      const step = assertEventWorkflowPlan(plan); await this.subject(plan);
      await this.authz.assertWholeWorkspace(actor, plan.clusterId, plan.workspaceId, 'workflows', action);
      if (action !== 'approve') await this.authz.assertWholeWorkspace(actor, plan.clusterId, plan.workspaceId, 'events', action === 'write' ? eventWorkflowHandler(step.handler).action : 'read');
      return;
    }
    const { service } = await this.subject(plan, this.originalScheduledHandle() ? tx : this.db);
    if (service) {
      if (action !== 'write' || plan.approvalRequired) await this.authz.assertScopedResource(actor, plan.clusterId, 'workflows', action, 'services', service, plan.workspaceId);
      if (action === 'write') await this.authz.assertScopedResource(actor, plan.clusterId, 'portal', 'write', 'services', service, plan.workspaceId);
    } else {
      // Approval records a decision and does not edit the metadata subject.
      // The eventual executor independently needs its exact module write grant.
      await this.authz.assertWholeWorkspace(actor, plan.clusterId, plan.workspaceId, 'workflows', action);
      if (action !== 'approve') await this.authz.assertWholeWorkspace(actor, plan.clusterId, plan.workspaceId, subjects[plan.subject.type], action);
    }
  }
  /** Original canonical-only rules, shared verbatim by full verification and
   * the private configuration Namespace reader. Scoped entity permission is
   * deliberately insufficient for this exact whole-workspace approval gate. */
  private async configurationCanonicalReviewerSql(approvedBy: { id: string; super_admin: boolean }, plan: WorkflowPlanV1, tx: DbService): Promise<void> {
    if (approvedBy.super_admin) return;
    const grants = (await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [approvedBy.id])).filter(validGrant);
    await this.subject(plan, tx, approvedBy.id);
    const allowed = grants.some(grant => grant.module === 'workflows' && grant.action === 'approve' && (grant.cluster_id === null || grant.cluster_id === plan.clusterId)
      && (grant.workspace_id === null || grant.workspace_id === plan.workspaceId) && (grant.scope_type === 'global' || grant.scope_type === 'workspace'
        && grant.cluster_id === plan.clusterId && grant.workspace_id === plan.workspaceId && grant.scope_values.length === 1 && grant.scope_values[0] === plan.workspaceId));
    if (!allowed) throw deny('APPROVED_APPROVER_REVOKED');
  }
  private async verifyCurrentReviewer(reviewerId: string, plan: WorkflowPlanV1, tx: DbService = this.db): Promise<void> {
    if(plan.kind==='entity-annotation'){const policy=this.annotationPolicy(plan);await policy.verifyIntent(plan,tx);await policy.verifyReviewer(reviewerId,plan,tx);return;}
    if(plan.kind==='control-metadata'){const policy=this.controlPolicy(plan);await policy.verifyIntent(plan,tx);await policy.verifyReviewer(reviewerId,plan,tx);return;}
    if(plan.kind==='metrics-setup'){
      const policy=this.metricsPolicy(plan);await policy.verifyIntent(plan,tx);await policy.verifyReviewer(reviewerId,plan,tx);return;
    }
    if(plan.kind==='iam-metadata'){
      const policy=this.iamPolicy(plan);await policy.verifyIntent(plan,tx);await policy.verifyReviewer(reviewerId,plan,tx);return;
    }
    if (this.context.peek() === null && 'scheduling' in plan
      && (plan.kind === 'configuration_v2' || plan.kind === 'portal-credential-issue')) {
      const scheduled = immutableJson(plan as WorkflowScheduledPlanV1), policy = this.workflowScheduledReviewerRead;
      if (!policy) throw deny('WORKFLOW_SCHEDULE_REVIEWER_READ_POLICY_UNAVAILABLE');
      if (!uuid.test(reviewerId) || !scheduled.scheduling || !uuid.test(scheduled.scheduling.scheduleId)
        || this.scheduledReviewerReadStorage.getStore()) throw deny('WORKFLOW_SCHEDULE_REVIEWER_READ_INVALID');
      // This does not create an HTTP identity, namespace, claim or write
      // permit. The fixed Root reader must verify the sealed original plan
      // and the actual reviewer's current SQL authority in its own capsule.
      await this.scheduledReviewerReadStorage.run(true, async () => {
        try { await policy.verifyCurrent(reviewerId, scheduled, tx); }
        finally { if (this.context.peek() !== null) throw deny('WORKFLOW_SCHEDULE_REVIEWER_READ_CONTEXT_CHANGED'); }
      });
      return;
    }
    const approvedBy = await tx.one<any>("SELECT id,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false", [reviewerId]);
    if (!approvedBy) throw deny('APPROVED_APPROVER_REVOKED');
    if(plan.kind==='workspace-migration'){
      const {row}=await this.subject(plan,tx);
      await this.authz.assertMigrationWorkflowReviewerEligibility(approvedBy.id,plan.clusterId,row.migrationMaterial as WorkspaceMigrationMaterial);
    }
    if(plan.kind==='governance-metadata')await this.governancePolicy(plan).verifyReviewer(approvedBy.id,plan,tx);
    if(plan.kind==='workflow-policy-metadata')await this.workflowPolicy(plan).verifyReviewer(approvedBy.id,plan,tx);
    if(plan.kind==='configuration_v2'){
      await this.assertConfigurationOrigin(plan,approvedBy.id,'approve',tx);
      await this.configurationCanonicalReviewerSql(approvedBy,plan,tx);return;
    }
    if (!approvedBy.super_admin) {
      const grants = (await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [approvedBy.id])).filter(validGrant);
      const subject = await this.subject(plan,tx,approvedBy.id);
      const allowed = subject.service ? grants.some(grant => grantMatchesEntity(grant, 'workflows', 'approve', { clusterId: plan.clusterId, workspaceId: plan.workspaceId, entityType: 'services', entity: subject.service }))
        : grants.some(grant => ['global', 'workspace'].includes(grant.scope_type) && coarseGrantMatches(grant, 'workflows', 'approve', { clusterId: plan.clusterId, workspaceId: plan.workspaceId }));
      if (!allowed) throw deny('APPROVED_APPROVER_REVOKED');
    }
  }
  private async authority(loaded: Loaded, proof?: ApprovedExecutionProof, tx:DbService=this.db): Promise<{ actor: AuthUser; version: string }> {
    if (proof?.origin === 'scheduled-workflow') {
      const state = this.executions.get(proof);
      if (!state?.active || !state.scheduled) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
      return this.scheduledAuthority(loaded, state.scheduled.handle, proof, tx);
    }
    const frame = this.context.current(), actor = frame.actor;
    if (!actor || !frame.sessionId || actor.id !== loaded.execution.execution_actor_id || frame.kind === 'system-read'
      || frame.clusterId && frame.clusterId !== loaded.plan.clusterId || frame.workspaceId && frame.workspaceId !== loaded.plan.workspaceId && loaded.plan.kind!=='control-metadata') throw deny('APPROVED_EXECUTOR_MISMATCH');
    if(loaded.plan.kind==='control-metadata')await this.assertControlWorkflowAdmission(loaded.plan,{user:actor,workspaceId:frame.workspaceId,requestId:frame.requestId,ip:frame.ip},'write',tx);
    const current = await this.authz.snapshot(actor);
    if (current.user.forcePasswordChange || proof && (proof.actorId !== actor.id || proof.sessionId !== frame.sessionId || proof.permissionVersion !== current.version || proof.expiresAt <= Date.now())) throw deny('APPROVED_EXECUTOR_CHANGED');
    await this.assertSubject(loaded.plan, current.user, 'write',tx);
    if ((loaded.version.approval_format ?? 1) === 2) {
      if (!this.approvals) throw deny('WORKFLOW_APPROVAL_POLICY_UNAVAILABLE');
      const set = await this.approvals.verifyApprovalSet(loaded.plan, { executionId: loaded.execution.id, checkpoint: 'packet' }, tx);
      if (set.format !== 2 || !set.setId || !set.setHmac || proof && (proof.approvalFormat !== 2 || proof.approvalSetId !== set.setId || proof.approvalSetHmac !== set.setHmac)) throw deny('APPROVED_APPROVAL_SET_CHANGED');
    } else {
      if (proof && (proof.approvalFormat !== undefined && proof.approvalFormat !== 1 || proof.approvalSetId != null || proof.approvalSetHmac != null)) throw deny('APPROVED_APPROVAL_SET_CHANGED');
      await this.verifyCurrentReviewer(loaded.execution.approved_by, loaded.plan, tx);
    }
    if (await this.authz.permissionVersion(actor) !== current.version) throw deny('APPROVED_EXECUTOR_CHANGED');
    this.context.current(); return { actor: current.user, version: current.version };
  }
  private async scheduledAuthority(loaded: Loaded, originalNamespaceHandle: object, proof?: ApprovedExecutionProof, tx: DbService = this.db,
    checkpoint: WorkflowScheduledNamespaceCheckpoint = 'step'): Promise<{ actor: AuthUser; version: string; namespace: Readonly<WorkflowScheduledNamespaceProof>; originId: string }> {
    if (!this.workflowScheduled || !originalNamespaceHandle || this.context.requireWorkflowScheduledNamespaceHandle() !== originalNamespaceHandle) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
    const deferred=this.#deferredPortalApprovalLoads.get(loaded);
    if(deferred&&(deferred.proof!==proof||deferred.namespaceHandle!==originalNamespaceHandle))throw deny('WORKFLOW_SCHEDULE_FRESH_INSPECTION_INVALID');
    const namespace = await this.context.verifyWorkflowScheduledNamespace(checkpoint), frame = this.context.current();
    const { plan, execution, workflow, version, approvalSet } = loaded;
    const seal = (plan as WorkflowScheduledPlanV1).scheduling;
    if (!namespace || namespace.origin !== 'scheduled-workflow' || namespace.sessionId !== null || frame.sessionId != null
      || !['configuration_v2', 'portal-credential-issue', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'].includes(plan.kind) || namespace.kind !== plan.kind
      || namespace.clusterId !== plan.clusterId || namespace.workspaceId !== plan.workspaceId || namespace.actor.id !== execution.execution_actor_id
      || frame.actor?.id !== namespace.actor.id || namespace.permissionVersion !== execution.permission_version
      || namespace.workflow.id !== plan.workflowId || namespace.workflow.planRevision !== plan.planRevision || namespace.workflow.planHash !== execution.plan_hash
      || namespace.transportScope !== plan.scope.transportScope || namespace.clusterRevision !== plan.scope.clusterRevision || namespace.workspaceRevision !== plan.scope.workspaceRevision
      || namespace.requester.type !== plan.requester.type || namespace.requester.id !== plan.requester.id || !digest.test(namespace.subjectSealHmac ?? '')
      || namespace.claim.id == null || namespace.claim.generation !== 1 || namespace.claim.clusterId !== plan.clusterId || namespace.claim.workspaceId !== plan.workspaceId
      || namespace.claim.executorId !== namespace.actor.id || namespace.claim.executorCredentialEpoch !== namespace.credentialEpoch
      || namespace.claim.workflowId !== plan.workflowId || namespace.claim.workflowPlanRevision !== plan.planRevision || namespace.claim.workflowPlanHash !== execution.plan_hash
      || !Number.isFinite(Date.parse(namespace.expiresAt)) || Date.parse(namespace.expiresAt) <= Date.now()
      || !Number.isFinite(Date.parse(namespace.claim.authorityExpiresAt)) || Date.parse(namespace.expiresAt) > Date.parse(namespace.claim.authorityExpiresAt)
      || !Number.isFinite(new Date(execution.started_at).getTime()) || new Date(execution.started_at).getTime() < Date.parse(namespace.claim.issuedAt)
      || new Date(execution.expires_at).getTime() > Date.parse(namespace.claim.authorityExpiresAt)
      || execution.approval_format !== 2 || workflow.approval_format !== 2 || version.approval_format !== 2
      || !approvalSet || approvalSet.format !== 2 || !this.same(approvalSet, namespace.approvalSet)) throw deny('WORKFLOW_SCHEDULE_EXECUTION_CHANGED');
    if (!seal || seal.version !== 1 || seal.scheduleId !== namespace.claim.scheduleId || seal.scheduleVersion !== 1 || seal.occurrenceId !== namespace.claim.occurrenceId
      || seal.ownerId !== namespace.claim.ownerId || seal.executorId !== namespace.actor.id || seal.ownerCredentialEpoch !== namespace.claim.ownerCredentialEpoch
      || seal.executorCredentialEpoch !== namespace.credentialEpoch || seal.delegationId !== namespace.claim.delegationId || seal.delegationVersion !== 1
      || seal.delegationHmac !== namespace.claim.delegationHmac || seal.specHmac !== namespace.claim.specHmac || !this.same(seal.requester, namespace.requester)
      || seal.transportScope !== namespace.transportScope || seal.impactHmac !== namespace.claim.impactHmac || seal.subjectSealHmac !== namespace.subjectSealHmac
      || namespace.claim.subjectSealHmac !== namespace.subjectSealHmac || !seal.spec || seal.spec.version !== 1 || seal.spec.executorId !== namespace.actor.id
      || this.secrets.fingerprint(seal.spec) !== seal.specHmac || seal.spec.windowStart !== namespace.claim.windowStart || seal.spec.windowEnd !== namespace.claim.windowEnd
      || [seal.spec.windowStart, seal.spec.windowEnd, seal.spec.notBefore].some(value => !Number.isFinite(Date.parse(value)))
      || Date.now() < Date.parse(seal.spec.windowStart) || Date.now() < Date.parse(seal.spec.notBefore) || Date.now() >= Date.parse(seal.spec.windowEnd)) throw deny('WORKFLOW_SCHEDULE_PLAN_SEAL_CHANGED');
    // A configuration wrapper can dispatch its sealed metadata handler only.
    // The separately branded V2 nested execution owns every native request.
    if (plan.kind === 'configuration_v2' && (plan.requester.type !== 'console' || plan.steps.some(step => step.kind !== 'metadata' || step.nativeRequests.length))) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_WRAPPER_NATIVE_FORBIDDEN');
    if (plan.kind === 'portal-credential-issue' && (plan.requester.type !== 'developer' || plan.subject.type !== 'portal_application_grants'
      || plan.steps.length !== 4 || plan.steps.slice(0, 3).some(step => step.kind !== 'native') || plan.steps[3].kind !== 'metadata'
      || plan.steps[3].handler !== 'portal.credential.activate')) throw deny('WORKFLOW_SCHEDULE_PORTAL_PLAN_INVALID');
    const origin = await tx.one<any>('SELECT * FROM workflow_execution_origins WHERE execution_id=$1 AND cluster_id=$2 AND workspace_id=$3', [execution.id, plan.clusterId, plan.workspaceId]);
    if (!origin || !uuid.test(origin.id ?? '') || origin.execution_id !== execution.id || origin.cluster_id !== plan.clusterId || origin.workspace_id !== plan.workspaceId
      || origin.workflow_id !== plan.workflowId || origin.workflow_plan_revision !== plan.planRevision || origin.workflow_plan_hash !== execution.plan_hash
      || origin.claim_id !== namespace.claim.id || origin.schedule_id !== namespace.claim.scheduleId || origin.executor_id !== namespace.actor.id) throw deny('WORKFLOW_SCHEDULE_WRAPPER_ORIGIN_REQUIRED');
    if (proof) {
      const state = this.executions.get(proof);
      if (!state?.active || !state.scheduled || state.scheduled.handle !== originalNamespaceHandle || state.scheduled.namespace !== namespace || state.scheduled.originId !== origin.id
        || proof.origin !== 'scheduled-workflow' || proof.sessionId !== null || proof.executionId !== execution.id || proof.workflowId !== plan.workflowId
        || proof.clusterId !== plan.clusterId || proof.workspaceId !== plan.workspaceId || proof.actorId !== namespace.actor.id || proof.permissionVersion !== namespace.permissionVersion
        || proof.workflowOriginId !== origin.id || proof.scheduleClaimId !== namespace.claim.id || proof.expiresAt <= Date.now() || proof.expiresAt > Date.parse(namespace.expiresAt)
        || proof.approvalFormat !== 2 || proof.approvalSetId !== approvalSet.setId || proof.approvalSetHmac !== approvalSet.setHmac) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
    }
    const executor = await tx.one<any>("SELECT id,credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false", [namespace.actor.id]);
    if (!executor || executor.id !== namespace.actor.id || String(executor.credential_epoch) !== namespace.credentialEpoch) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_REVOKED');
    if (namespace.requester.type === 'developer') {
      const developer = await tx.one<any>(`SELECT id,credential_epoch FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
        AND status='active' AND deleted_at IS NULL AND must_change_password=false`, [namespace.requester.id, plan.clusterId, plan.workspaceId]);
      if (!developer || developer.id !== namespace.requester.id || String(developer.credential_epoch) !== namespace.requester.credentialEpoch) throw deny('WORKFLOW_SCHEDULE_REQUESTER_REVOKED');
    }
    const current = await this.authz.snapshot(frame.actor!);
    if (current.user.forcePasswordChange || current.user.id !== namespace.actor.id || current.version !== namespace.permissionVersion) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_REVOKED');
    // Only this exact Portal Native frame can consume a fresh, one-shot
    // Namespace inspection. Ordinary and final checkpoints perform full
    // current SDK reads. A genuine SDK preparation can perform current SQL
    // prechecks only; the original phase cannot authorize final Native send.
    // The fixed consumer closes all parties/current SQL in both cases.
    const invocation=this.#portalInvocation.getStore();if(invocation)this.#assertPortalInvocation(invocation.original);
    const inspected=plan.kind==='portal-credential-issue'&&(frame.kind==='operation'&&frame.operation||invocation&&invocation.original.execution===proof)
      ?await this.workflowScheduledInspection?.consume(originalNamespaceHandle,namespace,checkpoint,tx):null;
    if(deferred&&!inspected)throw deny('WORKFLOW_SCHEDULE_FRESH_INSPECTION_REQUIRED');
    let currentSet:WorkflowApprovalSet;
    if(inspected){
      if(Object.keys(inspected).some(key=>key!=='approvalSet')||!inspected.approvalSet)throw deny('WORKFLOW_SCHEDULE_FRESH_INSPECTION_INVALID');
      currentSet=inspected.approvalSet;
    }else{
      // Legacy/ineligible frames keep the complete live verification path.
      if (!this.approvals) throw deny('WORKFLOW_APPROVAL_POLICY_UNAVAILABLE');
      const parties=async()=>{await this.assertSubject(plan, current.user, 'write', tx);
        return this.approvals!.verifyApprovalSet(plan,{executionId:execution.id,checkpoint:'packet'},tx);};
      // configuration_v2: executor + reviewers of THIS checkpoint share one SDK
      // observation round (fresh grants per party); never across checkpoints.
      currentSet=plan.kind==='configuration_v2'&&this.workflowScheduled.runConfigurationPartyCheckpoint
        ?await this.workflowScheduled.runConfigurationPartyCheckpoint(originalNamespaceHandle,checkpoint,tx,parties):await parties();
    }
    if (!this.same(currentSet, namespace.approvalSet) || await this.authz.permissionVersion(current.user) !== current.version) throw deny('WORKFLOW_SCHEDULE_EXECUTION_CHANGED');
    await this.redis.assertLeaseOwnership();
    if (this.context.requireWorkflowScheduledNamespaceHandle() !== originalNamespaceHandle) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
    this.context.current();
    return { actor: current.user, version: current.version, namespace, originId: origin.id };
  }
  private proofApproval(row: any): Pick<ApprovedExecutionProof, 'approvalFormat' | 'approvalSetId' | 'approvalSetHmac'> {
    if ((row.approval_format ?? 1) === 1) return { approvalFormat: 1, approvalSetId: null, approvalSetHmac: null };
    if (row.approval_format !== 2 || !uuid.test(row.approval_set_id ?? '') || !digest.test(row.approval_set_hmac ?? '')) throw deny('APPROVED_APPROVAL_SET_CHANGED');
    return { approvalFormat: 2, approvalSetId: row.approval_set_id, approvalSetHmac: row.approval_set_hmac };
  }
  async runApprovedExecution<T>(executionId: string, fn: () => Promise<T>): Promise<T> {
    if (typeof this.context.hasWorkflowScheduledNamespace === 'function' && this.context.hasWorkflowScheduledNamespace()) throw deny('WORKFLOW_SCHEDULE_EXPLICIT_EXECUTION_REQUIRED');
    const loaded = await this.load(executionId), current = await this.authority(loaded);
    await this.redis.assertLeaseOwnership();
    const frame = this.context.current();
    const proof = Object.freeze({ executionId, workflowId: loaded.plan.workflowId, clusterId: loaded.plan.clusterId, workspaceId: loaded.plan.workspaceId,
      ...this.proofApproval(loaded.execution),
      actorId: current.actor.id, sessionId: frame.sessionId!, permissionVersion: current.version, expiresAt: Math.min(Date.now() + (loaded.plan.kind==='configuration_v2'?CONFIGURATION_TIMEOUT_MS:120_000), new Date(loaded.execution.expires_at).getTime(), new Date(loaded.plan.expiresAt).getTime()) });
    const handle = Object.freeze({}) as ApprovedExecutionHandle, state = { proof, active: true };
    this.handles.set(handle, state); this.executions.set(proof, state);
    try { return await this.context.runApprovedWorkflow(handle, fn); }
    finally { state.active = false; this.handles.delete(handle); this.executions.delete(proof); }
  }
  async runApprovedBusinessExecution<T>(originalNamespaceHandle: object, executionId: string, fn: () => Promise<T>): Promise<T> {
    if (typeof fn !== 'function' || !originalNamespaceHandle || this.context.requireWorkflowScheduledNamespaceHandle() !== originalNamespaceHandle) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
    if (!this.workflowScheduled) throw deny('WORKFLOW_SCHEDULE_APPROVED_POLICY_UNAVAILABLE');
    // Portal entry performs no business/native action before scheduledAuthority.
    // That load's mandatory fresh Namespace checkpoint follows its SQL/read-only
    // checks; avoid a second identical full SDK traversal before that load.
    if(this.context.requireWorkflowScheduledCurrentPrincipal(originalNamespaceHandle).namespace.kind!=='portal-credential-issue')
      await this.context.verifyWorkflowScheduledNamespace('step');
    const loaded = await this.load(executionId), current = await this.scheduledAuthority(loaded, originalNamespaceHandle);
    const proof: Readonly<ApprovedExecutionProof> = Object.freeze({ executionId, workflowId: loaded.plan.workflowId, clusterId: loaded.plan.clusterId, workspaceId: loaded.plan.workspaceId,
      ...this.proofApproval(loaded.execution), actorId: current.actor.id, sessionId: null, origin: 'scheduled-workflow', scheduleClaimId: current.namespace.claim.id,
      workflowOriginId: current.originId, permissionVersion: current.version,
      // The genuine original Namespace already bounds claim/lease/window.
      // Rewrapping it must neither renew time nor introduce another 120s cap.
      expiresAt: Math.min(Date.parse(current.namespace.expiresAt), new Date(loaded.execution.expires_at).getTime(), Date.parse(loaded.plan.expiresAt)) });
    const handle = Object.freeze({}) as ApprovedExecutionHandle, state: HandleState = { proof, active: true,
      scheduled: { handle: originalNamespaceHandle, namespace: current.namespace, originId: current.originId } };
    this.handles.set(handle, state); this.executions.set(proof, state);
    try { return await this.context.runApprovedWorkflow(handle, fn); }
    finally { state.active = false; this.handles.delete(handle); this.executions.delete(proof); }
  }
  async verifyWorkflowScheduledExecution(proof: ApprovedExecutionProof, originalNamespaceHandle: object): Promise<void> {
    const state = proof && this.executions.get(proof);
    if (!state?.active || !state.scheduled || state.scheduled.handle !== originalNamespaceHandle || proof.origin !== 'scheduled-workflow' || proof.sessionId !== null) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
    await this.#withPortalInvocation(proof,'step',null,async()=>{
      const loaded=await this.load(proof.executionId,this.db,false,'execution',proof);
      await this.scheduledAuthority(loaded,originalNamespaceHandle,proof);
    });
  }
  private sameScheduledConfigurationOrigin(actual: Readonly<WorkflowScheduledConfigurationExecutionProof>, expected: Readonly<WorkflowScheduledConfigurationExecutionProof>): boolean {
    const keys = ['origin', 'sessionId', 'claimId', 'wrapperOriginId', 'wrapperExecutionId', 'configurationOriginId', 'configurationExecutionId',
      'configurationJobId', 'configurationPlanId', 'configurationPlanRevision', 'configurationPlanHash', 'configurationClaimHash',
      'workflowId', 'workflowPlanRevision', 'workflowPlanHash', 'actorId', 'clusterId', 'workspaceId', 'permissionVersion',
      'credentialEpoch', 'leaseGeneration', 'expiresAt'] as const;
    return actual.jobHandle === expected.jobHandle && actual.namespaceHandle === expected.namespaceHandle && keys.every(key => actual[key] === expected[key]);
  }
  private async originalScheduledConfiguration(jobHandle: WorkflowScheduledConfigurationJobHandle, executionHandle: WorkflowScheduledConfigurationExecutionHandle,
    executionId: string, checkpoint: WorkflowScheduledConfigurationCheckpoint, tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationExecutionProof>> {
    if (!this.workflowScheduledConfiguration) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_APPROVED_POLICY_UNAVAILABLE');
    if (!jobHandle || !executionHandle || !uuid.test(executionId) || !this.context.hasWorkflowScheduledNamespace()) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    const origin = await this.workflowScheduledConfiguration.verifyExecution(executionHandle, checkpoint, tx), frame = this.context.current();
    const namespaceHandle = this.context.requireWorkflowScheduledNamespaceHandle();
    // No cast, copied proof or workflow ID supplies either private handle.
    if (!origin || origin.origin !== 'workflow-scheduled-configuration' || origin.sessionId !== null || origin.jobHandle !== jobHandle
      || origin.namespaceHandle !== namespaceHandle || frame.sessionId != null || frame.actor?.id !== origin.actorId
      || frame.clusterId !== origin.clusterId || !uuid.test(frame.workspaceId ?? '') || origin.configurationExecutionId !== executionId
      || [origin.actorId, origin.clusterId, origin.workspaceId, origin.claimId, origin.wrapperOriginId, origin.wrapperExecutionId,
        origin.configurationOriginId, origin.configurationJobId, origin.configurationPlanId, origin.workflowId].some(value => !uuid.test(value ?? ''))
      || [origin.configurationPlanHash, origin.configurationClaimHash, origin.workflowPlanHash].some(value => !digest.test(value ?? ''))
      || [origin.configurationPlanRevision, origin.workflowPlanRevision, origin.credentialEpoch, origin.leaseGeneration].some(value => !Number.isSafeInteger(value) || value < 1)
      || typeof origin.permissionVersion !== 'string' || !origin.permissionVersion || !Number.isFinite(origin.expiresAt) || origin.expiresAt <= Date.now()) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    return origin;
  }
  private assertScheduledConfigurationLoaded(loaded: ConfigurationApprovedLoaded, origin: Readonly<WorkflowScheduledConfigurationExecutionProof>, proof?: ApprovedExecutionProof): void {
    const { execution, job, workflow } = loaded;
    const claimOrigin = loaded.scheduledOrigin;
    if (!claimOrigin || !this.sameScheduledConfigurationOrigin(claimOrigin, origin)
      || execution.id !== origin.configurationExecutionId || execution.job_id !== origin.configurationJobId || execution.plan_id !== origin.configurationPlanId
      || execution.plan_revision !== origin.configurationPlanRevision || execution.plan_hash !== origin.configurationPlanHash || execution.claim_hash !== origin.configurationClaimHash
      || execution.actor_id !== origin.actorId || execution.permission_version !== origin.permissionVersion || execution.lease_generation !== origin.leaseGeneration
      || execution.workflow_id !== origin.workflowId || execution.approved_version !== origin.workflowPlanRevision || execution.workflow_plan_hash !== origin.workflowPlanHash
      || execution.cluster_id !== origin.clusterId || execution.workspace_id !== origin.workspaceId || job.id !== origin.configurationJobId
      || !uuid.test(job.origin_session_id ?? '') || job.actor_id !== origin.actorId || job.plan_id !== origin.configurationPlanId
      || job.plan_revision !== origin.configurationPlanRevision || job.plan_hash !== origin.configurationPlanHash || job.workflow_id !== origin.workflowId
      || workflow.id !== origin.workflowId || workflow.kind !== 'configuration_v2' || workflow.approval_format !== 2
      || workflow.plan_revision !== origin.workflowPlanRevision || workflow.plan_hash !== origin.workflowPlanHash
      || workflow.subject_id !== origin.configurationJobId || workflow.subject_type !== 'configuration_jobs'
      || workflow.requester_type !== 'console' || workflow.requester_user_id !== origin.actorId
      || !Number.isFinite(loaded.claimExpiresAt) || loaded.claimExpiresAt <= Date.now() || loaded.claimExpiresAt > origin.expiresAt) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_MISMATCH');
    if (proof && (proof.origin !== 'scheduled-configuration' || proof.sessionId !== null || proof.executionId !== origin.configurationExecutionId
      || proof.workflowId !== origin.workflowId || proof.clusterId !== origin.clusterId || proof.workspaceId !== origin.workspaceId || proof.actorId !== origin.actorId
      || proof.permissionVersion !== origin.permissionVersion || proof.scheduleClaimId !== origin.claimId || proof.workflowOriginId !== origin.wrapperOriginId
      || proof.configurationOriginId !== origin.configurationOriginId || proof.expiresAt <= Date.now() || proof.expiresAt > origin.expiresAt
      || proof.approvalFormat !== 2 || proof.approvalSetId !== workflow.approval_set_id || proof.approvalSetHmac !== workflow.approval_set_hmac)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
  }
  private async scheduledConfigurationAuthority(state: HandleState, checkpoint: WorkflowScheduledConfigurationCheckpoint = 'step', tx = this.db): Promise<void> {
    const original = state.scheduledConfiguration;
    if (!state.active || !original || this.configurationExecutions.get(state.proof) !== state) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    const origin = await this.originalScheduledConfiguration(original.jobHandle, original.executionHandle, state.proof.executionId, checkpoint, tx);
    if(!state.active||this.configurationExecutions.get(state.proof)!==state)throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    if (!this.sameScheduledConfigurationOrigin(origin, original.origin)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_CHANGED');
    const loaded = await this.configuration.load(state.proof.executionId, tx, false, state.proof);
    if(!state.active||this.configurationExecutions.get(state.proof)!==state)throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    this.assertScheduledConfigurationLoaded(loaded, origin, state.proof); this.context.current();
  }
  /** A scheduled configuration wrapper dispatches metadata only. This entry
   * requires the original job and nested V2 execution handles; it cannot adopt
   * the wrapper's execution proof or resurrect the author's stored HTTP SID. */
  async runScheduledConfigurationExecution<T>(originalJobHandle: WorkflowScheduledConfigurationJobHandle,
    originalExecutionHandle: WorkflowScheduledConfigurationExecutionHandle, executionId: string, fn: () => Promise<T>): Promise<T> {
    if (!this.workflowScheduledConfiguration) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_APPROVED_POLICY_UNAVAILABLE');
    if (typeof fn !== 'function' || !originalExecutionHandle || this.usedScheduledConfigurationExecutions.has(originalExecutionHandle)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_EXECUTION_REPLAY_FORBIDDEN');
    const origin = await this.originalScheduledConfiguration(originalJobHandle, originalExecutionHandle, executionId, 'step');
    // Entry starts at the original job anchor. Later V2 steps may enter their
    // sealed object workspace; ConfigurationApprovedVerifier.step checks that
    // exact row, active workspace and current write grant before each packet.
    if(this.context.current().workspaceId!==origin.workspaceId)throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    const loaded = await this.configuration.load(executionId);
    this.assertScheduledConfigurationLoaded(loaded, origin);
    const proof: Readonly<ApprovedExecutionProof> = Object.freeze({ executionId, workflowId: origin.workflowId, clusterId: origin.clusterId, workspaceId: origin.workspaceId,
      ...this.proofApproval(loaded.workflow), actorId: origin.actorId, sessionId: null, origin: 'scheduled-configuration', scheduleClaimId: origin.claimId,
      workflowOriginId: origin.wrapperOriginId, configurationOriginId: origin.configurationOriginId, permissionVersion: origin.permissionVersion,
      expiresAt: Math.min(Date.now() + CONFIGURATION_TIMEOUT_MS, loaded.claimExpiresAt, origin.expiresAt) });
    const handle = Object.freeze({}) as ApprovedExecutionHandle, state: HandleState = { proof, active: true,
      scheduledConfiguration: { jobHandle: originalJobHandle, executionHandle: originalExecutionHandle, origin: Object.freeze({ ...origin }) } };
    this.usedScheduledConfigurationExecutions.add(originalExecutionHandle); this.configurationHandles.set(handle, state); this.configurationExecutions.set(proof, state);
    try { return await this.context.runApprovedScheduledConfigurationWorkflow(handle, originalJobHandle, fn); }
    finally { state.active = false; this.configurationHandles.delete(handle); this.configurationExecutions.delete(proof); }
  }
  async verifyWorkflowScheduledConfigurationExecution(proof: ApprovedExecutionProof, originalNamespaceHandle: object,
    originalJobHandle: WorkflowScheduledConfigurationJobHandle): Promise<void> {
    const state = proof && this.configurationExecutions.get(proof), original = state?.scheduledConfiguration;
    if (!state?.active || !original || original.jobHandle !== originalJobHandle || original.origin.namespaceHandle !== originalNamespaceHandle
      || this.context.requireWorkflowScheduledNamespaceHandle() !== originalNamespaceHandle || proof.origin !== 'scheduled-configuration' || proof.sessionId !== null) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED');
    await this.scheduledConfigurationAuthority(state);
  }
  async runConfigurationExecution<T>(executionId:string,fn:()=>Promise<T>):Promise<T>{
    if (typeof this.context.hasWorkflowScheduledNamespace === 'function' && this.context.hasWorkflowScheduledNamespace()) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_ADAPTER_REQUIRED');
    const loaded=await this.configuration.load(executionId),frame=this.context.current();
    const proof=Object.freeze({executionId,workflowId:loaded.workflow.id,clusterId:loaded.job.cluster_id,workspaceId:loaded.job.workspace_id,
      ...this.proofApproval(loaded.workflow),
      actorId:loaded.execution.actor_id,sessionId:frame.sessionId!,permissionVersion:loaded.execution.permission_version,expiresAt:Math.min(Date.now()+CONFIGURATION_TIMEOUT_MS,loaded.claimExpiresAt)});
    const handle=Object.freeze({})as ApprovedExecutionHandle,state={proof,active:true};
    this.configurationHandles.set(handle,state);this.configurationExecutions.set(proof,state);
    try{return await this.context.runApprovedWorkflow(handle,fn);}finally{state.active=false;this.configurationHandles.delete(handle);this.configurationExecutions.delete(proof);}
  }
  private async assertConfigurationStepAuthority(proof:ApprovedStepProof,tx=this.db,checkpoint:WorkflowScheduledConfigurationCheckpoint='step'):Promise<void>{
    const bound=this.configurationSteps.get(proof),state=this.configurationExecutions.get(proof.execution);
    if(!bound||bound.execution!==proof.execution||bound.stepId!==proof.stepId||proof.kind!=='native'||!state?.active)throw deny('CONFIGURATION_APPROVED_STEP_REQUIRED');
    if(state.scheduledConfiguration)await this.scheduledConfigurationAuthority(state,checkpoint,tx);
    // An awaited original-authority check may resume after its callback has
    // closed. Keep the exact private step and execution identities live.
    if(this.configurationSteps.get(proof)!==bound||this.configurationExecutions.get(proof.execution)!==state||!state.active)
      throw deny('CONFIGURATION_APPROVED_STEP_REQUIRED');
  }
  private async configurationStep(proof:ApprovedStepProof,tx=this.db,lock=false,checkpoint:WorkflowScheduledConfigurationCheckpoint='step'){
    await this.assertConfigurationStepAuthority(proof,tx,checkpoint);
    return this.configuration.step(proof.execution,proof.stepId,tx,lock);
  }
  async verifyExecution(handle: ApprovedExecutionHandle): Promise<ApprovedExecutionProof> {
    const config=this.configurationHandles.get(handle);
    if(config){if(!config.active)throw deny();if(config.scheduledConfiguration)await this.scheduledConfigurationAuthority(config);
      else await this.configuration.load(config.proof.executionId,this.db,false,config.proof);return config.proof;}
    const state = handle && this.handles.get(handle); if (!state?.active) throw deny();
    return this.#withPortalInvocation(state.proof,'step',null,async()=>{const loaded=await this.load(state.proof.executionId,this.db,false,'execution',state.scheduled?state.proof:undefined);
      await this.authority(loaded,state.proof);this.context.current();return state.proof;});
  }
  private async trusted(proof: ApprovedExecutionProof, tx = this.db, lock = false, checkpoint: WorkflowScheduledNamespaceCheckpoint = 'step',originalStep:ApprovedStepProof|null=null): Promise<Loaded> {
    const state = proof && this.executions.get(proof); if (!state?.active) throw deny();
    return this.#withPortalInvocation(proof,checkpoint,originalStep,async()=>{
      const loaded=await this.load(proof.executionId,tx,lock,'execution',state.scheduled?proof:undefined);
      if(state.scheduled)await this.scheduledAuthority(loaded,state.scheduled.handle,proof,tx,checkpoint);else await this.authority(loaded,proof,tx);
      return loaded;
    },tx);
  }
  private async step(proof: ApprovedStepProof, tx = this.db, lock = false, checkpoint: WorkflowScheduledNamespaceCheckpoint = 'step'): Promise<{ loaded: Loaded; step: WorkflowStep; row: any }> {
    const bound = proof && this.steps.get(proof); if (!bound || bound.execution !== proof.execution || bound.stepId !== proof.stepId) throw deny('APPROVED_STEP_REQUIRED');
    const loaded = await this.trusted(proof.execution, tx, lock, checkpoint,proof), step = loaded.plan.steps.find(item => item.id === proof.stepId), row = loaded.rows.find(item => item.id === proof.stepId);
    if (!step || !row || step.kind !== proof.kind || row.state !== 'running') throw deny('APPROVED_STEP_NOT_RUNNING');
    for (const dependency of step.dependencies) {
      const previous = loaded.rows.find(item => item.id === dependency);
      if (!previous || previous.state !== 'succeeded') throw deny('APPROVED_DEPENDENCY_UNACKNOWLEDGED');
      if (previous.kind === 'native') {
        const operation = await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1', [previous.operation_id]);
        if (!operation || operation.state !== 'succeeded' || operation.remote_completed !== true || operation.workflow_execution_id !== loaded.execution.id || operation.workflow_step_id !== previous.id || operation.workflow_plan_hash !== loaded.execution.plan_hash) throw deny('APPROVED_DEPENDENCY_UNACKNOWLEDGED');
      }
    }
    return { loaded, step, row };
  }
  async verifyStep(execution: ApprovedExecutionProof, stepId: string): Promise<ApprovedStepProof> {
    const config=this.configurationExecutions.get(execution);
    if(config){if(!config.active)throw deny();if(config.scheduledConfiguration)await this.scheduledConfigurationAuthority(config);
      await this.configuration.step(execution,stepId);
      const proof=Object.freeze({execution,stepId,kind:'native'as const});this.configurationSteps.set(proof,{execution,stepId});return proof;}
    const original = execution && this.executions.get(execution); if (!original?.active) throw deny();
    // Scheduled V2 needs a kind hint to construct its still-private step
    // proof. The hint grants no authority: the fresh step(proof) below must
    // authenticate the complete current plan/rows and reject any mismatch.
    // Other origins retain their original first full authority validation.
    const scheduled = original.scheduled && execution.origin === 'scheduled-workflow' && execution.sessionId === null && execution.approvalFormat === 2;
    let kind: WorkflowStep['kind'];
    if (scheduled) {
      if (!uuid.test(stepId ?? '')) throw deny('APPROVED_STEP_REQUIRED');
      const hint = await this.db.one<{ kind: unknown }>(`SELECT s.kind FROM workflow_steps s
        JOIN workflow_executions e ON e.cluster_id=s.cluster_id AND e.workspace_id=s.workspace_id
        AND e.workflow_id=s.workflow_id AND e.plan_revision=s.plan_revision AND e.plan_hash=s.plan_hash
        WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND s.id=$5`,
        [execution.executionId, execution.workflowId, execution.clusterId, execution.workspaceId, stepId]);
      if (hint?.kind !== 'native' && hint?.kind !== 'metadata') throw deny('APPROVED_STEP_REQUIRED');
      kind = hint.kind;
    } else {
      const loaded = await this.trusted(execution), step = loaded.plan.steps.find(item => item.id === stepId);
      if (!step) throw deny('APPROVED_STEP_REQUIRED');
      kind = step.kind;
    }
    const proof = Object.freeze({ execution, stepId, kind }); this.steps.set(proof, { execution, stepId });
    await this.step(proof); return proof;
  }
  private logical(step: WorkflowStep, context: Readonly<MutationContext>, loaded: Loaded): void {
    let expectedEntityId = step.entityId ?? null;
    if (loaded.plan.kind === 'metrics-setup' && step.kind === 'native' && step.entityType === 'plugins' && step.mutationAction === 'create') {
      // EntityService's original CREATE contract keeps the logical identity
      // empty until the real response acknowledges the preallocated native ID.
      // Metrics retains that ID in its immutable plan and SQL032 manifest.
      // Normalize only this comparison; neither input nor sealed plan changes.
      assertMetricsSetupPlan(loaded.plan);
      const request = step.nativeRequests[0], payload = step.mutationPayload as Record<string, unknown>;
      if (context.entityId != null || !uuid.test(step.entityId ?? '') || !payload || payload.id !== step.entityId
        || step.nativeRequests.length !== 1 || request.method !== 'POST' || request.canonicalPath !== '/plugins'
        || request.nativeType !== 'plugins' || request.nativeId !== step.entityId
        || step.parentId != null || step.credentialKind != null || request.parentId != null || request.credentialKind != null
        || step.before !== null || context.before != null || step.beforeFingerprint !== this.secrets.fingerprint(null)
        || request.beforeHmac !== step.beforeFingerprint || request.bodyHmac !== step.mutationPayloadHmac
        || this.secrets.fingerprint(payload) !== step.mutationPayloadHmac || this.secrets.fingerprint(request.body ?? null) !== step.mutationPayloadHmac) {
        throw deny('APPROVED_MUTATION_MISMATCH');
      }
      expectedEntityId = null;
    }
    if (context.actor.id !== loaded.execution.execution_actor_id || context.clusterId !== loaded.plan.clusterId || context.workspaceId !== loaded.plan.workspaceId
      || context.entityType !== step.entityType || (context.entityId ?? null) !== expectedEntityId || context.action !== step.mutationAction
      || (context.parentId ?? null) !== (step.parentId ?? null) || (context.credentialKind ?? null) !== (step.credentialKind ?? null)
      || context.idempotencyKey !== step.mutationIdempotencyKey || this.secrets.fingerprint(context.payload ?? null) !== step.mutationPayloadHmac
      || this.secrets.fingerprint(context.before ?? null) !== step.beforeFingerprint) throw deny('APPROVED_MUTATION_MISMATCH');
  }
  private async assertPrerequisites(loaded: Loaded): Promise<void> {
    for (const prerequisite of loaded.plan.prerequisites) {
      // A previous acknowledged step can intentionally change an object also
      // used as a dependency. Its fresh raw readback replaces the initial
      // snapshot fingerprint; display-redacted receipts never prove a match.
      const completed = loaded.plan.steps.filter(step => loaded.rows.some(row => row.id === step.id && row.state === 'succeeded')
        && step.nativeRequests.some(request => this.nativePath(request) === prerequisite.path)).at(-1);
      const expected = completed ? loaded.rows.find(row => row.id === completed.id)?.after_fingerprint : prerequisite.fingerprint;
      if (!digest.test(expected ?? '')) throw stale('APPROVED_DEPENDENCY_UNACKNOWLEDGED');
      let actual: unknown;
      try {
        actual = await this.validationRead(loaded.plan.clusterId, prerequisite.path, () => this.kong.request(loaded.plan.clusterId, 'GET', prerequisite.path));
      } catch (error: any) {
        if (error?.getStatus?.() !== 404 && error?.status !== 404) throw error;
        actual = null;
      }
      if (this.secrets.fingerprint(actual ?? null) !== expected) throw stale();
    }
  }
  async mutationBinding(proof: ApprovedStepProof, context: Readonly<MutationContext>): Promise<ApprovedMutationBinding> {
    if(this.configurationSteps.has(proof)){
      const{loaded,step,row}=await this.configurationStep(proof,this.db,false,'packet');this.configuration.logical(loaded,step,row,context);
      const binding=Object.freeze({version:2 as const,workflowId:loaded.workflow.id,configurationJobId:loaded.job.id,configurationExecutionId:loaded.execution.id,
        configurationStepId:row.id,configurationPlanRevision:loaded.execution.plan_revision,configurationPlanHash:loaded.execution.plan_hash,beforeHmac:step.beforeHmac});
      this.configurationBindings.set(binding,{step:proof,contextHash:this.secrets.fingerprint({...context,actor:context.actor.id,operationId:null})});return binding;
    }
    const { loaded, step } = await this.step(proof, this.db, false, 'packet'); if (step.kind !== 'native') throw deny('APPROVED_NATIVE_STEP_REQUIRED'); this.logical(step, context, loaded);
    const binding = Object.freeze({ workflowId: loaded.plan.workflowId, executionId: loaded.execution.id, planRevision: loaded.plan.planRevision, planHash: loaded.execution.plan_hash, stepId: step.id, beforeHmac: step.beforeFingerprint! });
    this.bindings.set(binding, { step: proof, contextHash: this.secrets.fingerprint({ ...context, actor: context.actor.id, operationId: null }) }); return binding;
  }
  async bindOperation(proof: ApprovedStepProof, context: Readonly<MutationContext>, binding: ApprovedMutationBinding, operationId: string, tx: DbService): Promise<void> {
    if(this.configurationSteps.has(proof)){
      const bound=this.configurationBindings.get(binding),step=this.configurationSteps.get(proof),state=this.configurationExecutions.get(proof.execution);
      if(!isConfigurationBinding(binding)||!bound||bound.step!==proof||step?.execution!==proof.execution||step.stepId!==proof.stepId||proof.kind!=='native'||!state?.active
        ||bound.contextHash!==this.secrets.fingerprint({...context,actor:context.actor.id,operationId:null}))throw deny('CONFIGURATION_APPROVED_BINDING_INVALID');
      // bind establishes the exact reciprocal link before re-entering the
      // current job verifier; its full checks stay inside this same transaction.
      await this.configuration.bind(proof.execution,proof.stepId,context,binding,operationId,tx);
      // A just-inserted operation is deliberately not exempted from origin
      // validation. Establish its actual reciprocal V2 link first, then check
      // the original namespace/job/execution in the same rollbackable tx.
      if(state.scheduledConfiguration)await this.scheduledConfigurationAuthority(state,'packet',tx);
      return;
    }
    if(isConfigurationBinding(binding))throw deny('APPROVED_BINDING_INVALID');
    const bound = this.bindings.get(binding); if (!bound || bound.step !== proof) throw deny('APPROVED_BINDING_INVALID');
    const { loaded, step, row } = await this.step(proof, tx, true, 'packet'); this.logical(step, context, loaded);
    if (proof.execution.origin === 'scheduled-workflow' && bound.contextHash !== this.secrets.fingerprint({ ...context, actor: context.actor.id, operationId: null })) throw deny('APPROVED_BINDING_INVALID');
    if (binding.executionId !== loaded.execution.id || binding.planHash !== loaded.execution.plan_hash || binding.stepId !== step.id || row.operation_id) throw deny('APPROVED_BINDING_INVALID');
    const operation = await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1', [operationId]);
    if (!operation || operation.actor_id !== proof.execution.actorId || operation.cluster_id !== loaded.plan.clusterId || operation.workspace_id !== loaded.plan.workspaceId
      || operation.workflow_id !== binding.workflowId || operation.workflow_execution_id !== binding.executionId || operation.workflow_step_id !== binding.stepId
      || operation.workflow_plan_revision !== binding.planRevision || operation.workflow_plan_hash !== binding.planHash || operation.state !== 'running') throw deny('APPROVED_BINDING_INVALID');
    if (await tx.exec("UPDATE workflow_steps SET operation_id=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND operation_id IS NULL AND revision=$3", [step.id, operationId, row.revision]) !== 1) throw stale('APPROVED_OPERATION_LINK_CONFLICT');
    await this.redis.assertLeaseOwnership(); this.context.current();
  }
  async assertNative(proof: ApprovedStepProof, input: Readonly<ApprovedNativeRequest>, stage: ApprovedNativeStage): Promise<void> {
    return this.#assertNativeCore(proof,input,stage,false);
  }
  async #assertNativeCore(proof:ApprovedStepProof,input:Readonly<ApprovedNativeRequest>,stage:ApprovedNativeStage,portalBoundary:boolean):Promise<void>{
    // native owns its fresh complete step load and its post-currentBefore
    // recheck. Do not perform and discard an identical load before entering it.
    if(this.configurationSteps.has(proof)){await this.assertConfigurationStepAuthority(proof,this.db,stage==='before-send'?'before-send':'packet');return this.configuration.native(proof.execution,proof.stepId,input,stage,proof);}
    const final=typeof this.context.scheduledPortalFinalNativePhase==='function'?this.context.scheduledPortalFinalNativePhase():null;
    if(final&&!this.context.scheduledPortalPreparationPhase())return this.#assertPortalFinalNative(proof,input,stage,portalBoundary,final);
    const { loaded, step, row } = await this.step(proof, this.db, false, stage === 'before-send' ? 'before-send' : 'packet');
    await this.#assertNativePacket(proof,input,stage,portalBoundary,{loaded,step,row});
    const preparation=this.context.scheduledPortalPreparationPhase();
    if(preparation)this.context.assertScheduledPortalPreparationPhase(preparation);
    if (stage === 'before-send'&&!preparation) {
      await this.assertPrerequisites(loaded);
      // Dependency reads introduce awaits. Recheck cancellation, current
      // executor/approver grants and the exact running step after those reads.
      await this.step(proof, this.db, false, 'before-send');
    }
    await this.redis.assertLeaseOwnership(); this.context.current();
  }
  async #assertNativePacket(proof:ApprovedStepProof,input:Readonly<ApprovedNativeRequest>,stage:ApprovedNativeStage,portalBoundary:boolean,
    current:{loaded:Loaded;step:WorkflowStep;row:any}):Promise<void>{
    const {loaded,step,row}=current;
    if(portalBoundary&&!['portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke'].includes(loaded.plan.kind))throw deny('PORTAL_MANAGED_OBJECT');
    if (step.kind !== 'native' || input.clusterId !== loaded.plan.clusterId || input.workspaceId !== loaded.plan.workspaceId || input.transportScope !== loaded.plan.scope.transportScope
      || input.operationId !== row.operation_id || input.frame.actor?.id !== proof.execution.actorId
      || (proof.execution.origin === 'scheduled-workflow' ? input.frame.sessionId != null : input.frame.sessionId !== proof.execution.sessionId)
      || input.mutationAction !== step.mutationAction || Object.keys(input.query).length) throw deny('APPROVED_NATIVE_REQUEST_MISMATCH');
    const request = step.nativeRequests.find(item => item.method === input.method && item.canonicalPath === input.canonicalPath);
    if (!request || request.bodyHmac !== this.secrets.fingerprint(input.body ?? null) || (request.parentId ?? null) !== (input.parentId ?? null)
      || (request.credentialKind ?? step.credentialKind ?? null) !== (input.credentialKind ?? null) || (request.beforeHmac ?? step.beforeFingerprint) !== this.secrets.fingerprint(input.before ?? null)) throw deny('APPROVED_NATIVE_REQUEST_MISMATCH');
    const operation = await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1', [input.operationId]);
    if (!operation || operation.state !== 'running' || operation.remote_started !== true || operation.actor_id !== proof.execution.actorId || operation.workspace_id !== loaded.plan.workspaceId
      || operation.cluster_id !== loaded.plan.clusterId || operation.workflow_execution_id !== loaded.execution.id || operation.workflow_step_id !== step.id
      || operation.workflow_plan_hash !== loaded.execution.plan_hash || operation.workflow_plan_revision !== loaded.plan.planRevision || operation.workflow_id !== loaded.plan.workflowId
      || this.secrets.fingerprint(this.secrets.decrypt(operation.payload_secret, `mutation:${operation.id}:payload`)) !== step.mutationPayloadHmac
      || this.secrets.fingerprint(this.secrets.decrypt(operation.before_secret, `mutation:${operation.id}:before`)) !== step.beforeFingerprint) throw deny('APPROVED_OPERATION_INVALID');
    if (stage === 'response' && request.method === 'POST' && (input.result as any)?.id !== request.nativeId) throw deny('APPROVED_CREATED_ID_MISMATCH');
  }
  /** The original physical final gate owns this sequence. SQL prechecks
   * grant no Native permission. Exactly one fresh all-party SDK step follows
   * the required prerequisite GETs, then current packet/operation SQL closes
   * every await before the Context's synchronous transport fence. */
  async #assertPortalFinalNative(proof:ApprovedStepProof,input:Readonly<ApprovedNativeRequest>,stage:ApprovedNativeStage,portalBoundary:boolean,
    final:ScheduledPortalFinalNativePhase):Promise<void>{
    this.context.assertScheduledPortalFinalNativePhase(final);
    const original=this.executions.get(proof.execution),bound=this.steps.get(proof);
    if(!original?.active||!original.scheduled||original.scheduled.handle!==final.namespaceHandle||original.scheduled.namespace!==final.namespace
      ||bound?.execution!==proof.execution||bound.stepId!==proof.stepId||proof!==final.step||proof.execution!==final.execution
      ||proof.kind!=='native'||stage!==final.stage||input.frame!==final.frame||input.cluster!==final.cluster
      ||input.clusterId!==final.namespace.clusterId||input.workspaceId!==final.namespace.workspaceId||input.operationId!==final.operation.operationId
      ||input.transportScope!==final.transportScope||input.method!==final.method||input.canonicalPath!==final.path||input.body!==final.body||input.query!==final.query)
      throw deny('PORTAL_FINAL_NATIVE_ORIGINAL_REQUIRED');
    const checkpoint=stage==='before-send'?'before-send':'packet';
    const before=await this.context.runPortalFinalNativePrecheck(final,async()=>{
      const current=await this.step(proof,this.db,false,checkpoint);await this.#assertNativePacket(proof,input,stage,portalBoundary,current);return current;
    });
    this.context.assertScheduledPortalFinalNativePhase(final);
    if(stage==='before-send'){await this.assertPrerequisites(before.loaded);this.context.assertScheduledPortalFinalNativePhase(final);}
    // Preparation mode is closed here: this is the real current executor and
    // every reviewer's SDK scope, followed by the original SQL consumer.
    await this.step(proof,this.db,false,checkpoint);this.context.assertScheduledPortalFinalNativePhase(final);
    await this.context.runPortalFinalNativePrecheck(final,async()=>{
      const current=await this.step(proof,this.db,false,checkpoint);await this.#assertNativePacket(proof,input,stage,portalBoundary,current);
    });
    this.context.assertScheduledPortalFinalNativePhase(final);
  }
  async assertNativeWrite(input: Readonly<PortalNativePacket>): Promise<void> {
    const proof = this.context.currentApprovedStep();
    if(this.configurationSteps.has(proof))throw deny('PORTAL_MANAGED_OBJECT');
    const original=this.executions.get(proof.execution),scheduled=original?.scheduled;
    const portalScheduled=original?.active&&scheduled&&proof.execution.origin==='scheduled-workflow'&&proof.execution.sessionId===null
      &&this.context.requireWorkflowScheduledNamespaceHandle()===scheduled.handle
      &&this.context.requireWorkflowScheduledCurrentPrincipal(scheduled.handle).namespace.kind==='portal-credential-issue';
    if(!portalScheduled){const {loaded}=await this.step(proof);
      if(!['portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke'].includes(loaded.plan.kind))throw deny('PORTAL_MANAGED_OBJECT');}
    const frame = this.context.current(), cluster = await this.db.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [input.clusterId]);
    if (!cluster) throw deny('PORTAL_MANAGED_OBJECT');
    // The private core's first mandatory fresh step checks the Portal kind.
    // Its final fresh step after prerequisites remains unchanged.
    await this.#assertNativeCore(proof, { ...input, frame, cluster, query: {} }, 'before-send', !!portalScheduled);
  }
  async assertMetadata(proof: ApprovedStepProof, input: Readonly<ApprovedMetadataInput>, tx: DbService): Promise<void> {
    if(this.configurationSteps.has(proof))throw deny('CONFIGURATION_NATIVE_ONLY');
    const { loaded, step, row } = await this.step(proof, tx, true);
    if (loaded.plan.kind === 'event-metadata') {
      assertEventWorkflowPlan(loaded.plan);
      const subject = await this.subject(loaded.plan, tx);
      if (!this.same(subject.row, input.before) || subject.row.revision !== input.revision) throw deny('APPROVED_METADATA_REQUEST_MISMATCH');
      await this.authz.assertWholeWorkspace(input.actor, loaded.plan.clusterId, loaded.plan.workspaceId, 'events', eventWorkflowHandler(step.handler).action);
    }
    if (step.kind !== 'metadata' || row.operation_id || input.actor.id !== proof.execution.actorId || input.clusterId !== loaded.plan.clusterId || input.workspaceId !== loaded.plan.workspaceId
      || input.handler !== step.handler || input.entityType !== step.entityType || input.entityId !== step.entityId || input.revision !== step.metadataRevision
      || this.secrets.fingerprint(input.before ?? null) !== step.metadataBeforeHmac || this.secrets.fingerprint(input.payload ?? null) !== step.metadataPayloadHmac) throw deny('APPROVED_METADATA_REQUEST_MISMATCH');
    await this.redis.assertLeaseOwnership(); this.context.current();
  }
  assertStep(input: Readonly<ApprovedMetadataInput>, tx: DbService): Promise<void> { return this.context.assertApprovedMetadataStep(input, tx); }
}
