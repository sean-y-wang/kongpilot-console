import { ConflictException, ForbiddenException, Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import {performance} from 'node:perf_hooks';
import type { AuthUser } from '../../common/auth';
import { assertKongPath, ENTITIES } from './policy';
import { transportScopeFor } from './transport-scope';
import { CONFIGURATION_TIMEOUT_MS } from './configuration-budget';
import { isEntityActorDomainScope } from './actor-scope';
import { workflowScheduledValidationBudgetMs } from './workflow-scheduled-validation-budget';
import { canonicalJson } from '../secret.service';
import type { DbService } from '../db.service';
import type { MutationContext } from '../../modules/mutations/mutation.service';
import type {EntityChangePacketExecutionPolicy,EntityChangePacketExecutionProof} from './entity-change-execution-policy';
import type {EntityScheduledNamespaceCheckpoint,EntityScheduledNamespaceProof} from '../../modules/workflows/entity-scheduled-namespace.types';
import type {WorkflowScheduledNamespaceCheckpoint,WorkflowScheduledNamespaceProof} from '../../modules/workflows/workflow-scheduled-authority.types';
import type {WorkflowScheduledConfigurationJobHandle,WorkflowScheduledConfigurationJobProof} from '../../modules/workflows/workflow-scheduled-configuration-origin.types';
import type {WorkflowScheduleCandidateReadPolicy,WorkflowScheduleCandidateReadProof,WorkflowScheduleCandidateReadResource,WorkflowCandidateHttpAdmissionPolicy} from '../../modules/workflows/workflow-schedule-candidate-read.types';
import type {WorkflowScheduledValidationReadPolicy,WorkflowScheduledValidationReadProof} from './workflow-scheduled-validation-read.types';
import type {ConfigurationNativeBeforeReadHandle,ConfigurationNativeBeforeReadResult,ApprovedMutationBindingV3,ApprovedNativeRequest} from '../../modules/workflows/approved-execution.types';
import type { ApprovedExecutionHandle, ApprovedExecutionPolicy, ApprovedExecutionProof, ApprovedStepProof, ApprovedMutationBinding, ApprovedNativeStage, ApprovedMetadataInput, PortalBoundaryReadPermit, IssueActivationRecoveryHandle, IssueActivationRecoveryProof } from '../../modules/workflows/approved-execution.types';

export type KongReadPurpose = 'authorization' | 'entity-preflight' | 'capture' | 'migration' | 'inventory' | 'operation-check' | 'recycle-check' | 'workspace-empty' | 'probe' | 'metrics-scrape' | 'metrics-catalog' | 'event-observation' | 'portal-boundary' | 'portal-recovery-boundary' | 'governance' | 'promotion-recovery' | 'promotion-planning';
export interface KongReadLimits {
  paths?: readonly string[];
  maxCalls?: number;
  maxPages?: number;
  maxRecords?: number;
  maxBytes?: number;
  timeoutMs?: number;
  workspaceId?: string;
}
export interface KongActorScope { actor: AuthUser; clusterId: string; workspaceId?: string; module?: string; action?: string; requestId?: string; purpose?: 'configuration'; }
export interface KongOperationScope extends KongActorScope {
  operationId: string; entityType: string; entityId?: string; parentId?: string;
  credentialKind?: string; migrationPlanId?: string; targetWorkspaceId?: string;
}
export interface KongArchiveScope {
  entryId: string; operationId: string; clusterId: string; workspaceId: string;
  nodes: ReadonlyArray<{ path: string; type: string; id: string }>;
}
export interface KongExecutionFrame {
  readonly kind: 'http' | 'actor' | 'scheduled-entity' | 'scheduled-workflow' | 'workflow-candidate-read' | 'workflow-validation-read' | 'system-read' | 'internal-read' | 'operation' | 'archive-delete';
  readonly actor?: Readonly<AuthUser>;
  readonly sessionId?: string;
  readonly requestId?: string;
  readonly ip?: string;
  /** Trusted HTTP correlation only; this key never grants native authority. */
  readonly idempotencyKey?: string;
  readonly clusterId?: string;
  readonly workspaceId?: string;
  readonly module?: string;
  readonly action?: string;
  readonly purpose?: KongReadPurpose | 'indexer' | 'configuration';
  readonly operation?: Readonly<KongOperationScope>;
  readonly archive?: Readonly<KongArchiveScope>;
  readonly limits: Readonly<Required<Omit<KongReadLimits, 'paths' | 'workspaceId'>> & { paths?: readonly string[] }>;
}
export interface KongPolicyCluster { id: string; admin_url: string; version: string | null; execution_mode: string; transport_scope?: string | null; [key: string]: unknown; }
export interface KongPolicyHooks {
  authorizeRequest(frame: KongExecutionFrame, cluster: KongPolicyCluster, method: string, path: string, body: unknown, query: Record<string, string | number>): Promise<unknown>;
  authorizeResponse(ticket: unknown, result: any): Promise<any>;
  beforeNativeSend?(frame: KongExecutionFrame, cluster: KongPolicyCluster, method: string, path: string, body: unknown, query: Record<string, string | number>, decision: unknown, permit: PortalBoundaryReadPermit): Promise<void>;
}
export interface KongPolicyDecision { platformAdmin?: boolean; before?: any; [key: string]: unknown; }
/** Root's job authority owns the opaque handle and verifies its durable tuple.
 * This DTO is evidence returned by that verifier, never caller authority. */
export interface ConfigurationJobExecutionProof {
  actor: AuthUser; sessionId?: string | null; clusterId: string; workspaceId: string;
  module: string; purpose: 'capture' | 'compare' | 'export' | 'import' | 'apply' | 'rollback';
  jobId: string; permissionVersion: string; credentialEpoch: number; leaseGeneration: number;
  expiresAt: number; readOnly: boolean; requestId?: string; ip?: string; idempotencyKey?: string;
  /** Evidence returned only by the fixed private access provider. */
  origin?: 'workflow-scheduled-configuration'; namespaceHandle?: object; claimId?: string;
  wrapperOriginId?: string; wrapperExecutionId?: string; planId?: string; planRevision?: number; planHash?: string;
  subjectSealHmac?: string; originalScheduledJobHandle?: WorkflowScheduledConfigurationJobHandle;
}
export interface ConfigurationJobExecutionPolicy {
  verifyHandle(handle: object): Promise<ConfigurationJobExecutionProof>;
  beforeNativeSend?(handle:object,packet:{clusterId:string;method:string;path:string;body:unknown;query:Readonly<Record<string,string|number>>}):Promise<void>;
}
export interface ToolboxOperationProof {
  operationId:string;actorId:string;sessionId:string;clusterId:string;workspaceId:string;transportScope:string;
  canonicalPath:string;permissionVersion:string;expiresAt:number;executionMode:'direct'|'approval';workflowExecutionId?:string;workflowStepId?:string;
}
export interface ToolboxOperationPolicy {
  verifyHandle(handle:object):Promise<ToolboxOperationProof>;
  beforeSend(handle:object):Promise<void>;
}
export interface GovernanceReadProof {
  actor: AuthUser; sessionId?:string; clusterId:string; workspaceId:string; transportScope:string;
  module:'governance'|'drift'|'promote'; permissionVersion:string; credentialEpoch:number; expiresAt:number;
  origin:'http'|'timer'; projection:boolean; kind:'cluster'|'workspace'|'services'; rootIds:readonly string[];
}
export interface GovernanceReadPolicy {
  verifyHandle(handle:object):Promise<GovernanceReadProof>;
  startRead(handle:object):Promise<{proof:GovernanceReadProof;limits:KongReadLimits}>;
  endRead(handle:object,usage:{calls:number;pages:number;records:number;bytes:number}):void;
  filterResponse(handle:object,path:string,result:any):Promise<any>;
}
/** Only the fixed provider can authenticate its bootstrap claim / attached
 * genuine source ConfigAccess handle. These returned fields are never HTTP
 * authority. Bootstrap exposes a SQL-only source namespace with empty paths. */
export interface PromotionRecoveryReadProof {
  mode:'bootstrap'|'read';actor:AuthUser;sessionId:string;clusterId:string;workspaceId:string;transportScope:string;
  permissionVersion:string;credentialEpoch:number;expiresAt:number;originFrame:KongExecutionFrame;
  pointPaths:readonly string[];credentialCollections:readonly string[];schemaPaths:readonly string[];
}
export interface PromotionRecoveryReadPolicy {
  verifyHandle(handle:object):Promise<PromotionRecoveryReadProof>;
  /** Fixed raw-material + current-grants validation, never a response filter
   * chosen by HTTP. Raw values stay inside the server's private compiler. */
  assertResponse(handle:object,path:string,result:unknown):Promise<void>;
}
/** A fixed provider owns the private claim. The returned identity allows
 * target-side planning and reads, never an Admin API mutation. */
export interface PromotionPlanningProof {
  promotionId:string;actor:AuthUser;sessionId:string;sourceClusterId:string;sourceWorkspaceId:string;
  clusterId:string;workspaceId:string;transportScope:string;permissionVersion:string;credentialEpoch:number;
  expiresAt:number;originFrame:KongExecutionFrame;
}
export interface PromotionPlanningPolicy {verifyHandle(handle:object):Promise<PromotionPlanningProof>;}
export interface EntityScheduledNamespacePolicy {
  verifyHandle(handle:object,checkpoint:EntityScheduledNamespaceCheckpoint):Promise<Readonly<EntityScheduledNamespaceProof>>;
  assertLive(handle:object):void;
}
export interface WorkflowScheduledNamespacePolicy {
  verifyHandle(handle:object,checkpoint:WorkflowScheduledNamespaceCheckpoint):Promise<Readonly<WorkflowScheduledNamespaceProof>>;
  assertLive(handle:object):void;
  /** SQL preparation only; never an alternative final Native gate. */
  verifySqlPreparation?(handle:object,checkpoint:'packet'):Promise<Readonly<WorkflowScheduledNamespaceProof>>;
}
export interface EntityScheduleReservationPolicy {
  assertNativeWrite(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string):Promise<void>;
}
declare const ticketBrand: unique symbol;
export type KongPolicyTicket = Readonly<{ [ticketBrand]: true }>;
/** Evidence selected only by the SDK's original private Portal write ticket.
 * This preparation scope never grants a Native send or an entity read. */
export interface ScheduledPortalPreparationPhase {
  readonly stage:'sql-preflight';readonly purpose:'authorize'|'prepare'|'refresh'|'schema'|'before-send'|'response-closing';
  readonly ticket:KongPolicyTicket;readonly frame:KongExecutionFrame;readonly operation:Readonly<KongOperationScope>;
  readonly namespaceHandle:object;readonly namespace:Readonly<WorkflowScheduledNamespaceProof>;
  readonly execution:ApprovedExecutionProof;readonly step:ApprovedStepProof;
  readonly cluster:KongPolicyCluster;readonly transportScope:string;
  readonly method:string;readonly path:string;readonly body:unknown;readonly query:Readonly<Record<string,string|number>>;
}
export type ScheduledPortalFinalNativePhase=Readonly<Omit<ScheduledPortalPreparationPhase,'stage'|'purpose'>&{readonly stage:'before-send'|'response'}>;
interface PortalPreparationState {active:boolean;deadline:number;readonly proof:Readonly<ScheduledPortalPreparationPhase>;readonly packet:string;schemaFrame?:KongExecutionFrame;parentFrame?:KongExecutionFrame;}
interface ConfigurationSqlPreparationIdentity {
  readonly frame:KongExecutionFrame;readonly namespaceHandle:object;readonly namespace:Readonly<WorkflowScheduledNamespaceProof>;
  readonly originalJobHandle:WorkflowScheduledConfigurationJobHandle;readonly execution:ApprovedExecutionProof;readonly step:ApprovedStepProof;
}
type ConfigurationSqlPreparation=ConfigurationSqlPreparationIdentity&(
  |Readonly<{stage:'authorize'|'prepare'|'refresh';operation:Readonly<KongOperationScope>}>
  |Readonly<{stage:'mutation-binding';operation:undefined}>);
interface ConfigurationSqlPreparationState {active:boolean;deadline:number;readonly proof:Readonly<ConfigurationSqlPreparation>;readonly packet:string;readonly ticket?:KongPolicyTicket;
  readonly binding?:Readonly<{policy:ApprovedExecutionPolicy;context:Readonly<MutationContext>}>;}
interface State { closed: boolean; calls: number; pages: number; records: number; bytes: number; deadline: number; parent?: KongExecutionFrame; }
interface WorkflowValidationReadClaim {
  readonly handle: object; readonly proof: Readonly<WorkflowScheduledValidationReadProof>; readonly namespaceHandle: object;
  readonly namespaceProof: Readonly<WorkflowScheduledNamespaceProof>; readonly namespaceFrame: KongExecutionFrame;
  /** Existing single-path observers own their planned GET, while this
   * independent support read belongs to its validation and aggregate meters. */
  readonly localReadBudgets: readonly KongExecutionFrame[];
}
interface ScheduledReadResourceSelection {active:boolean;frame:KongExecutionFrame;handle:object;resource:Readonly<WorkflowScheduleCandidateReadResource>;}
interface TicketState { frame: KongExecutionFrame; value: unknown; method: string; path: string; cluster: KongPolicyCluster; body: unknown; query: Record<string, string | number>; candidateReadToken?:object; validationReadToken?:object; resourceSelection?:ScheduledReadResourceSelection; }
export interface ScheduledReadAbsentTransportFact {
  readonly clusterId:string;readonly transportScope:string;readonly clusterRevision:number;
  readonly method:'GET';readonly path:string;readonly query:Readonly<Record<string,string|number>>;
  readonly status:404;readonly response:unknown;
}
interface PromotionRecoveryMeter {proof:PromotionRecoveryReadProof;identity:string;busy:boolean;calls:number;pages:number;records:number;bytes:number;deadline:number;}
interface PromotionRecoveryCursor {next?:string;size?:number;started:boolean;complete:boolean;pending:boolean;seen:Set<string>;ids:Set<string>;}
interface PromotionRecoveryFrame {handle:object;meter:PromotionRecoveryMeter;proof:PromotionRecoveryReadProof;cursors:Map<string,PromotionRecoveryCursor>;endpointOrigin?:string;}
interface PromotionPlanningFrame {handle:object;proof:PromotionPlanningProof;rootFrame:KongExecutionFrame;}
const nativeTypes = new Set<string>([...ENTITIES, 'targets', 'credentials', 'workspace_migration']);
const writeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/** User-approved 2026-10-24: only scheduled configuration_v2 workflow
 * executions (and their own configuration-purpose descendants) get 1000 Kong
 * calls; every checkpoint keeps its own full fresh read. All else stays 500. */
export const SCHEDULED_CONFIGURATION_MAX_CALLS = 1000;
const defaults = { maxCalls: 500, maxPages: 100, maxRecords: 10_000, maxBytes: 32 * 1024 * 1024, timeoutMs: 120_000 };
const unavailable = () => new ServiceUnavailableException({ code: 'KONG_POLICY_UNAVAILABLE', message: '网关执行策略尚未就绪，操作已停止' });
const denied = (code = 'KONG_EXECUTION_CONTEXT_REQUIRED') => new ForbiddenException({ code, message: '网关调用缺少有效的受限执行上下文' });

/** Packet identity only. This does not authorize a migration or mint a proof:
 * the sealed step, durable migration graph and native policy still validate
 * every path, payload, before state and both workspace grants independently.
 * A migration's logical receipt belongs to its source workspace while each
 * credential packet retains its actual Consumer identity. */
export function approvedNativePacketScope(frame: KongExecutionFrame, method: string, path: string): {
  workspaceId: string | undefined; parentId: string | undefined; credentialKind: string | undefined;
} {
  const operation = frame.operation;
  if (operation?.entityType !== 'workspace_migration') return {
    workspaceId: frame.workspaceId, parentId: operation?.parentId, credentialKind: operation?.credentialKind,
  };
  if (operation.action !== 'migrate' || method !== 'PATCH' || !frame.workspaceId || operation.workspaceId !== frame.workspaceId
    || operation.parentId !== undefined || operation.credentialKind !== undefined) throw denied('KONG_MIGRATION_PACKET_INVALID');
  const uuid = '[\\da-fA-F]{8}-[\\da-fA-F]{4}-[1-8][\\da-fA-F]{3}-[89abAB][\\da-fA-F]{3}-[\\da-fA-F]{12}';
  if (new RegExp(`^/(?:${ENTITIES.join('|')})/${uuid}$`).test(path)) return {
    workspaceId: frame.workspaceId, parentId: undefined, credentialKind: undefined,
  };
  const nested = new RegExp(`^/consumers/(${uuid})/(key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)/${uuid}$`).exec(path);
  if (!nested) throw denied('KONG_MIGRATION_PACKET_INVALID');
  return { workspaceId: frame.workspaceId, parentId: nested[1], credentialKind: nested[2] };
}

/** Identity and capabilities originate in trusted server code. HTTP payloads,
 * serialized frames and copied tickets never become native execution rights. */
@Injectable()
export class KongExecutionContextService {
  private readonly logger = new Logger(KongExecutionContextService.name);
  private portalEntityParentReadPolicy?:Readonly<{run<T>(namespace:object,clusterId:string,path:string,read:()=>Promise<T>):Promise<T>}>;
  #configurationRequestRoundRunner?:<T>(namespace:object,fn:()=>Promise<T>)=>Promise<T>;
  /** Approved 2026-10-25: one Kong business request = one shared per-party
   * verification round for scheduled configuration_v2 (before-send excluded). */
  installConfigurationRequestRoundRunner(runner:<T>(namespace:object,fn:()=>Promise<T>)=>Promise<T>):void{
    if(this.#configurationRequestRoundRunner||typeof runner!=='function')throw new ForbiddenException({code:'KONG_CONFIGURATION_REQUEST_ROUND_POLICY_INVALID',message:'配置请求核验轮次策略无效'});
    this.#configurationRequestRoundRunner=runner;
  }
  runConfigurationRequestRound<T>(fn:()=>Promise<T>):Promise<T>{
    const runner=this.#configurationRequestRoundRunner;
    if(!runner||!this.hasWorkflowScheduledNamespace())return fn();
    return runner(this.requireWorkflowScheduledNamespaceHandle(),fn);
  }
  installPortalEntityParentReadPolicy(policy:{run<T>(namespace:object,clusterId:string,path:string,read:()=>Promise<T>):Promise<T>}):void{
    if(this.portalEntityParentReadPolicy||!policy||Object.keys(policy).some(key=>key!=='run')||typeof policy.run!=='function')throw unavailable();
    this.portalEntityParentReadPolicy=Object.freeze({run:policy.run.bind(policy)});
  }
  private portalMetadataReadPolicy?:Readonly<{run<T>(namespace:object,clusterId:string,path:string,read:()=>Promise<T>):Promise<T>}>;
  installPortalMetadataReadPolicy(policy:{run<T>(namespace:object,clusterId:string,path:string,read:()=>Promise<T>):Promise<T>}):void{
    if(this.portalMetadataReadPolicy||!policy||Object.keys(policy).some(key=>key!=='run')||typeof policy.run!=='function')throw unavailable();
    this.portalMetadataReadPolicy=Object.freeze({run:policy.run.bind(policy)});
  }
  /** The original Portal activation's support GETs use the fixed Validation
   * provider. Ordinary HTTP reads keep their existing authorization path. */
  async runPortalMetadataRead<T>(clusterId:string,path:string,read:()=>Promise<T>):Promise<T>{
    const frame=this.current(),namespace=this.workflowScheduledNamespace(frame);
    if(!namespace)return read();
    const ancestry=this.originalScheduledPortalExecution();
    const live=()=>{
      if(!this.portalMetadataReadPolicy||this.current()!==frame||this.workflowScheduledNamespace(frame)!==namespace
        ||namespace.proof.kind!=='portal-credential-issue'||!ancestry||ancestry.step?.kind!=='metadata'
        ||this.currentApprovedStep()!==ancestry.step||ancestry.execution!==ancestry.step.execution
        ||ancestry.execution.origin!=='scheduled-workflow'||frame.sessionId!=null||frame.actor?.id!==namespace.proof.actor.id
        ||clusterId!==namespace.proof.clusterId||frame.clusterId!==namespace.proof.clusterId||frame.workspaceId!==namespace.proof.workspaceId)
        throw denied('WORKFLOW_PORTAL_ACTIVATION_READ_REQUIRED');
    };
    live();const value=await this.portalMetadataReadPolicy!.run(namespace.handle,clusterId,path,read);live();return value;
  }
  private readonly storage = new AsyncLocalStorage<KongExecutionFrame>();
  readonly #portalPreparationSupportFrames=new WeakMap<KongExecutionFrame,{scope:PortalPreparationState;permit:PortalBoundaryReadPermit;paths:readonly string[]}>();
  #portalPreparationSupportPolicy?:Readonly<{assertPaths(original:Readonly<ScheduledPortalPreparationPhase>,paths:readonly string[]):Promise<void>}>;
  #portalPreparations=new AsyncLocalStorage<PortalPreparationState|null>();
  private readonly sqlPreparations = new AsyncLocalStorage<ConfigurationSqlPreparationState | null>();
  private readonly finalNativeStages = new AsyncLocalStorage<{active:boolean;frame:KongExecutionFrame;ticket:KongPolicyTicket;stage:'before-send'|'response'}>();
  readonly #portalFinalNativeStages=new AsyncLocalStorage<{active:boolean;proof:ScheduledPortalFinalNativePhase}|null>();
  private readonly scheduledReadResources=new AsyncLocalStorage<ScheduledReadResourceSelection>();
  private serviceBeforeObserverInstalled=false;
  private serviceDestinationObserver?:Readonly<{observe(ticket:KongPolicyTicket,result:Readonly<ConfigurationNativeBeforeReadResult>,body:unknown):Promise<void>}>;
  private readonly serviceObservations=new AsyncLocalStorage<{active:boolean;frame:KongExecutionFrame;step:ApprovedStepProof;namespace:object;ticket?:KongPolicyTicket;started:boolean;deadline:number;calls:number;pages:number;records:number}>();
  private readonly states = new WeakMap<KongExecutionFrame, State>();
  private readonly expiredContexts = new WeakSet<KongExecutionFrame>();
  /** Deadline provenance only; authority and every ancestor meter stay live. */
  private readonly businessDelegatedFrames = new WeakSet<KongExecutionFrame>();
  #businessNativeActors = new WeakSet<KongExecutionFrame>();
  #businessNativeOperations = new WeakSet<KongExecutionFrame>();
  private readonly httpActors = new WeakMap<KongExecutionFrame, { actor?: Readonly<AuthUser>; sessionId?: string }>();
  readonly #portalPendingTickets=new WeakSet<object>();
  private readonly tickets = new WeakMap<object, TicketState>();
  private scheduledAbsentObserver?:Readonly<{verifyTransport(ticket:KongPolicyTicket,originalProof:object):Readonly<ScheduledReadAbsentTransportFact>}>;
  private readonly scheduledAbsentObservations=new WeakMap<object,{ticket:KongPolicyTicket;token:object;fact:Readonly<ScheduledReadAbsentTransportFact>}>();
  private readonly managedMetricsProvisions = new WeakMap<KongExecutionFrame, { clusterId: string }>();
  private readonly eventObservationReads = new WeakSet<KongExecutionFrame>();
  private readonly approvedExecutions = new WeakMap<KongExecutionFrame, ApprovedExecutionProof>();
  private readonly approvedSteps = new WeakMap<KongExecutionFrame, ApprovedStepProof>();
  private readonly scheduledConfigurationBoundaries = new WeakSet<KongExecutionFrame>();
  private readonly portalPermits = new WeakMap<object, { ticket: KongPolicyTicket; frame: KongExecutionFrame; transportScope: string; active: boolean }>();
  private readonly portalReads = new WeakMap<KongExecutionFrame, PortalBoundaryReadPermit>();
  private readonly issueRecoveries = new WeakMap<KongExecutionFrame, { handle: IssueActivationRecoveryHandle; proof: IssueActivationRecoveryProof }>();
  private readonly issueRecoveryReads = new WeakMap<KongExecutionFrame, IssueActivationRecoveryHandle>();
  private readonly configurationJobs = new WeakMap<KongExecutionFrame, { handle: object; proof: Readonly<ConfigurationJobExecutionProof> }>();
  /** Budget provenance only. No Native request, SQL proof or grant is cached. */
  private readonly configurationMutationActors=new WeakMap<KongExecutionFrame,{active:boolean;frame:KongExecutionFrame;
    job:{handle:object;proof:Readonly<ConfigurationJobExecutionProof>};step:ApprovedStepProof;execution:ApprovedExecutionProof;namespaceHandle:object;
    deadline:number;context:Readonly<MutationContext>;scope:Readonly<{actorId:string;clusterId:string;workspaceId:string;entityType:string;entityId?:string;action:string;parentId?:string;credentialKind?:string;idempotencyKey?:string}>;operationEntered:boolean;operationId?:string;binding?:ApprovedMutationBinding;transaction?:DbService}>();

  private configurationJobPolicy?: ConfigurationJobExecutionPolicy;
  private readonly toolboxOperations=new WeakMap<KongExecutionFrame,{handle:object;proof:ToolboxOperationProof}>();
  private toolboxOperationPolicy?:ToolboxOperationPolicy;
  private governanceReadPolicy?:GovernanceReadPolicy;
  private readonly governanceReads=new WeakMap<KongExecutionFrame,{handle:object;proof:GovernanceReadProof}>();
  private promotionRecoveryPolicy?:PromotionRecoveryReadPolicy;
  private readonly promotionRecoveryMeters=new WeakMap<object,PromotionRecoveryMeter>();
  private readonly promotionRecoveryFrames=new WeakMap<KongExecutionFrame,PromotionRecoveryFrame>();
  private promotionPlanningPolicy?:PromotionPlanningPolicy;
  private readonly promotionPlanningFrames=new WeakMap<KongExecutionFrame,PromotionPlanningFrame>();
  private readonly usedPromotionPlanningHandles=new WeakSet<object>();
  private approvedPolicy?: ApprovedExecutionPolicy;
  private entityChangePolicy?:EntityChangePacketExecutionPolicy;
  private scheduledNamespacePolicy?:EntityScheduledNamespacePolicy;
  private scheduleReservationPolicy?:EntityScheduleReservationPolicy;
  private readonly scheduledNamespaces=new WeakMap<KongExecutionFrame,{handle:object;proof:Readonly<EntityScheduledNamespaceProof>}>();
  private workflowScheduledPolicy?:WorkflowScheduledNamespacePolicy;
  private readonly workflowScheduledNamespaces=new WeakMap<KongExecutionFrame,{handle:object;proof:Readonly<WorkflowScheduledNamespaceProof>}>();
  private readonly usedWorkflowScheduledNamespaces=new WeakSet<object>();
  private workflowCandidateReadPolicy?:WorkflowScheduleCandidateReadPolicy;
  private workflowCandidateHttpAdmission?:Readonly<WorkflowCandidateHttpAdmissionPolicy>;
  private readonly workflowCandidateReads=new WeakMap<KongExecutionFrame,{handle:object;proof:Readonly<WorkflowScheduleCandidateReadProof>;httpParent?:KongExecutionFrame}>();
  private readonly usedWorkflowCandidateReads=new WeakSet<object>();
  private workflowValidationReadPolicy?:Readonly<WorkflowScheduledValidationReadPolicy>;
  private readonly workflowValidationReads=new WeakMap<KongExecutionFrame,WorkflowValidationReadClaim>();
  private readonly usedWorkflowValidationReads=new WeakSet<object>();
  private readonly entityChangePackets=new WeakMap<KongExecutionFrame,{handle:object;proof:EntityChangePacketExecutionProof;ticket?:KongPolicyTicket}>();
  private hooks?: KongPolicyHooks;

  installPolicy(hooks: KongPolicyHooks): void {
    if (!hooks || typeof hooks.authorizeRequest !== 'function' || typeof hooks.authorizeResponse !== 'function' || this.hooks && this.hooks !== hooks) throw unavailable();
    this.hooks = hooks;
  }
  installScheduledReadAbsentTransportObserver(observer:{verifyTransport(ticket:KongPolicyTicket,originalProof:object):Readonly<ScheduledReadAbsentTransportFact>}):void {
    if(this.scheduledAbsentObserver||!observer||typeof observer.verifyTransport!=='function'||Object.keys(observer).some(k=>k!=='verifyTransport'))throw unavailable();
    this.scheduledAbsentObserver=Object.freeze({verifyTransport:observer.verifyTransport.bind(observer)});
  }
  /** Only an original transport proof and original GET ticket can produce this
   * short-lived observation. It does not acknowledge a mutation or grant a write. */
  async observeScheduledReadAbsent(ticket:KongPolicyTicket,originalProof:object):Promise<boolean>{
    const state=this.tickets.get(ticket),token=state?.validationReadToken??state?.candidateReadToken;
    if(!token)return false;
    this.assertTicketActive(ticket);
    if(!state||state.method!=='GET'||state.body!==undefined||!this.scheduledAbsentObserver)throw denied('WORKFLOW_SCHEDULE_ABSENCE_TRANSPORT_REQUIRED');
    const fact=this.scheduledAbsentObserver.verifyTransport(ticket,originalProof);
    const sameQuery=Object.keys(fact.query).length===Object.keys(state.query).length&&Object.entries(state.query).every(([k,v])=>fact.query[k]===v);
    if(fact.status!==404||fact.method!=='GET'||fact.clusterId!==state.cluster.id||fact.path!==state.path||!sameQuery
      ||fact.clusterRevision!==Number(state.cluster.revision)||fact.transportScope!==transportScopeFor(state.cluster.admin_url,state.cluster.transport_scope))
      throw denied('WORKFLOW_SCHEDULE_ABSENCE_TRANSPORT_CHANGED');
    await this.refreshAuthorization(ticket);this.assertTicketActive(ticket);
    const observation=Object.freeze({});this.scheduledAbsentObservations.set(observation,{ticket,token,fact});
    try{
      this.chargeResponse(state,fact.response);
      if(state.validationReadToken)await this.workflowValidationReadPolicy!.authorizeResponse(token,fact.response,observation);
      else await this.workflowCandidateReadPolicy!.authorizeResponse(token,fact.response,observation);
      this.assertTicketActive(ticket);this.tickets.delete(ticket);return true;
    }finally{this.scheduledAbsentObservations.delete(observation);}
  }
  verifyScheduledReadAbsentObservation(originalRequestToken:object,originalObservation:object):Readonly<{status:404;response:unknown}>{
    const value=originalObservation&&this.scheduledAbsentObservations.get(originalObservation);
    if(!value||value.token!==originalRequestToken)throw denied('WORKFLOW_SCHEDULE_ORIGINAL_ABSENCE_OBSERVATION_REQUIRED');
    this.assertTicketActive(value.ticket);
    const state=this.tickets.get(value.ticket);
    if(!state||state.method!=='GET'||(state.validationReadToken??state.candidateReadToken)!==originalRequestToken)throw denied('WORKFLOW_SCHEDULE_ORIGINAL_ABSENCE_OBSERVATION_REQUIRED');
    return Object.freeze({status:404,response:value.fact.response});
  }
  installEntityChangePacketPolicy(policy:EntityChangePacketExecutionPolicy):void{
    if(this.entityChangePolicy||!policy||['verifyHandle','mutationBinding','bindOperation','assertNative','beforeNativeSend','observeTransportResponse','spendTransport'].some(key=>typeof (policy as any)[key]!=='function'))throw unavailable();
    this.entityChangePolicy=policy;
  }
  installEntityScheduledNamespacePolicy(policy:EntityScheduledNamespacePolicy):void{
    if(this.scheduledNamespacePolicy||!policy||typeof policy.verifyHandle!=='function'||typeof policy.assertLive!=='function')throw unavailable();
    this.scheduledNamespacePolicy=policy;
  }
  installEntityScheduleReservationPolicy(policy:EntityScheduleReservationPolicy):void{
    if(this.scheduleReservationPolicy||!policy||typeof policy.assertNativeWrite!=='function')throw unavailable();this.scheduleReservationPolicy=policy;
  }
  private scheduledNamespace(frame:KongExecutionFrame){
    for(const ancestor of this.chain(frame)){const claim=this.scheduledNamespaces.get(ancestor);if(claim)return claim;}return undefined;
  }
  requireEntityScheduledNamespaceHandle():object{
    const claim=this.scheduledNamespace(this.current());if(!claim)throw denied('ENTITY_SCHEDULE_NAMESPACE_REQUIRED');return claim.handle;
  }
  hasEntityScheduledNamespace():boolean{return!!this.scheduledNamespace(this.current());}
  async verifyEntityScheduledNamespace(checkpoint:EntityScheduledNamespaceCheckpoint):Promise<Readonly<EntityScheduledNamespaceProof>|null>{
    const frame=this.current(),claim=this.scheduledNamespace(frame);if(!claim)return null;
    if(!this.scheduledNamespacePolicy)throw unavailable();
    const current=await this.scheduledNamespacePolicy.verifyHandle(claim.handle,checkpoint);this.chain(frame);
    if(current!==claim.proof||frame.actor?.id!==current.actor.id||frame.sessionId!=null||frame.clusterId!==current.clusterId||frame.workspaceId!==current.workspaceId)
      throw denied('ENTITY_SCHEDULE_NAMESPACE_SCOPE_CHANGED');
    return current;
  }
  async runEntityScheduledNamespace<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    if(this.storage.getStore())throw denied('ENTITY_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN');
    if(!this.scheduledNamespacePolicy)throw unavailable();
    const proof=await this.scheduledNamespacePolicy.verifyHandle(handle,'claim');
    if(this.storage.getStore()||proof.origin!=='scheduled-entity'||proof.sessionId!==null||!proof.actor?.id
      ||Date.parse(proof.expiresAt)<=Date.now())throw denied('ENTITY_SCHEDULE_NAMESPACE_REQUIRED');
    const frame=this.make({kind:'scheduled-entity',actor:proof.actor,clusterId:proof.clusterId,workspaceId:proof.workspaceId,module:'workflows',action:'write'},
      {timeoutMs:Math.min(120000,Date.parse(proof.expiresAt)-Date.now())},undefined);
    this.scheduledNamespaces.set(frame,{handle,proof});
    try{return await this.run(frame,fn);}finally{this.scheduledNamespaces.delete(frame);}
  }
  installWorkflowScheduledNamespacePolicy(policy:WorkflowScheduledNamespacePolicy):void{
    if(this.workflowScheduledPolicy||!policy||typeof policy.verifyHandle!=='function'||typeof policy.assertLive!=='function')throw unavailable();
    this.workflowScheduledPolicy=policy;
  }
  private workflowScheduledNamespace(frame:KongExecutionFrame){
    for(const ancestor of this.chain(frame)){const claim=this.workflowScheduledNamespaces.get(ancestor);if(claim)return claim;}return undefined;
  }
  hasWorkflowScheduledNamespace():boolean{return!!this.workflowScheduledNamespace(this.current());}
  /** Interactive HTTP keeps a tight 5s authorization point budget. Nested
   * scheduled-workflow already holds the parent Namespace envelope; NativeKongPolicy
   * parent GETs (via runPortalNativeParentRead) and Authz.fresh must not race that
   * with a 5s child after SQL/lease work under the same claim. After CALL_LIMIT
   * pin, KP-005 Target append failed CONTEXT_EXPIRED at metadata-prepare with
   * purpose=authorization timeoutMs=5000 from the portal-parent ordinary path.
   * Ceiling is limits() authorization timeoutMs:10_000 — do not pass 30s (that
   * throws KONG_EXECUTION_BUDGET_INVALID). Keep maxCalls:500 (scheduled configuration_v2: 1000, user-approved). */
  authorizationPointTimeoutMs():number{
    try{
      if(this.hasWorkflowScheduledNamespace())return 10_000;
      if(this.peek())return 10_000;
    }catch{/* no live frame */}
    return 5_000;
  }
  requireWorkflowScheduledNamespaceHandle():object{
    const claim=this.workflowScheduledNamespace(this.current());if(!claim)throw denied('WORKFLOW_SCHEDULE_NAMESPACE_REQUIRED');return claim.handle;
  }
  /** Fixed provider bootstrap only: original identity plus synchronous live
   * ancestor fences. Fresh SQL remains the provider's responsibility; this
   * method does not perform full business verification or grant any packet. */
  requireWorkflowScheduledValidationNamespaceProof(originalNamespaceHandle:object):Readonly<WorkflowScheduledNamespaceProof>{
    const frame=this.current(),claim=this.workflowScheduledNamespace(frame);
    if(!claim||claim.handle!==originalNamespaceHandle||this.workflowValidationRead(frame)||this.workflowCandidateRead(frame)
      ||frame.sessionId!=null||frame.actor?.id!==claim.proof.actor.id||claim.proof.origin!=='scheduled-workflow'||claim.proof.sessionId!==null)
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');return claim.proof;
  }
  /** Fixed identity bridge only. The private validation association selects
   * its real reviewer, while ordinary business execution retains its executor.
   * SQL eligibility/epochs remain mandatory and grant no Native capability. */
  requireWorkflowScheduledCurrentPrincipal(originalNamespaceHandle:object):Readonly<{namespace:Readonly<WorkflowScheduledNamespaceProof>;actor:Readonly<AuthUser>;role:'executor'|'reviewer';readOnly:boolean;validationReadHandle?:object}>{
    const frame=this.current(),namespace=this.workflowScheduledNamespace(frame),validation=this.workflowValidationRead(frame);
    if(!namespace||namespace.handle!==originalNamespaceHandle||frame.sessionId!=null||!frame.actor||this.workflowCandidateRead(frame))throw denied('WORKFLOW_SCHEDULE_CURRENT_PRINCIPAL_REQUIRED');
    if(validation){
      if(validation.namespaceHandle!==namespace.handle||validation.namespaceProof!==namespace.proof||validation.proof.namespace!==namespace.proof
        ||frame.actor.id!==validation.proof.actor.id||validation.proof.readOnly!==true)throw denied('WORKFLOW_SCHEDULE_CURRENT_PRINCIPAL_REQUIRED');
      return Object.freeze({namespace:namespace.proof,actor:validation.proof.actor,role:validation.proof.role,readOnly:true,validationReadHandle:validation.handle});
    }
    if(frame.actor.id!==namespace.proof.actor.id)throw denied('WORKFLOW_SCHEDULE_CURRENT_PRINCIPAL_REQUIRED');
    return Object.freeze({namespace:namespace.proof,actor:namespace.proof.actor,role:'executor',readOnly:false});
  }
  /** Private phase evidence only. No caller can enter a phase or turn its
   * SQL observations into a Native permit. A nested frame never inherits it. */
  scheduledConfigurationPreparationPhase():Readonly<ConfigurationSqlPreparation>|null{
    const state=this.sqlPreparations.getStore();if(!state||!state.active)return null;
    const scope=state.proof,frame=this.current();if(frame!==scope.frame)return null;
    const final=this.finalNativeStages.getStore();if(final?.active)return null;
    const namespace=this.workflowScheduledNamespace(frame),job=this.configurationJob(frame),execution=this.executionProof(frame),step=this.optionalApprovedStep(frame);
    if(frame.operation!==scope.operation||namespace?.handle!==scope.namespaceHandle||namespace.proof!==scope.namespace
      ||job?.proof.origin!=='workflow-scheduled-configuration'||job.proof.originalScheduledJobHandle!==scope.originalJobHandle
      ||execution!==scope.execution||step!==scope.step||step.execution!==execution||execution.origin!=='scheduled-configuration'
      ||execution.sessionId!==null||execution.expiresAt<=Date.now()||frame.sessionId!=null||performance.now()>=state.deadline)
      throw denied('CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED');
    if(scope.stage==='mutation-binding'){
      const binding=state.binding,budget=this.configurationMutationActors.get(frame);
      if(!binding||binding.policy!==this.approvedPolicy||!budget||budget.context!==binding.context||budget.operationId!==undefined||budget.operationEntered
        ||binding.context.operationId!=null||state.ticket||frame.operation!==undefined
        ||state.packet!==canonicalJson({...binding.context,actor:binding.context.actor.id,operationId:null}))
        throw denied('CONFIGURATION_MUTATION_BINDING_SQL_CONTEXT_CHANGED');
      this.assertConfigurationMutationActor(budget);
    }else if(state.binding||!scope.operation)throw denied('CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED');
    if(state.ticket)this.assertTicketActive(state.ticket);return scope;
  }
  /** A private original ticket selects preparation identity; DTOs cannot mint
   * a phase. Only the fixed schema capsule may inherit this identity. */
  installPortalPreparationSupportPolicy(policy:{assertPaths(original:Readonly<ScheduledPortalPreparationPhase>,paths:readonly string[]):Promise<void>}):void{
    if(this.#portalPreparationSupportPolicy||!policy||typeof policy.assertPaths!=='function'||Object.keys(policy).some(k=>k!=='assertPaths'))throw denied('PORTAL_PREPARATION_SUPPORT_INSTALL_INVALID');
    this.#portalPreparationSupportPolicy=Object.freeze({assertPaths:policy.assertPaths.bind(policy)});
  }
  scheduledPortalPreparationPhase():Readonly<ScheduledPortalPreparationPhase>|null{
    const state=this.#portalPreparations.getStore();if(!state||!state.active)return null;
    const proof=state.proof,frame=this.current(),support=this.#portalPreparationSupportFrames.get(frame);
    if(frame!==proof.frame&&frame!==state.schemaFrame&&frame!==state.parentFrame&&support?.scope!==state)return null;
    this.assertTicketActive(proof.ticket);const ticket=this.tickets.get(proof.ticket)!;
    const namespace=this.workflowScheduledNamespace(frame),step=this.optionalApprovedStep(frame),execution=this.executionProof(frame);
    if(!this.#businessNativeOperations.has(proof.frame)||proof.frame.operation!==proof.operation||namespace?.handle!==proof.namespaceHandle
      ||namespace.proof!==proof.namespace||namespace.proof.kind!=='portal-credential-issue'||step!==proof.step||execution!==proof.execution
      ||step?.execution!==execution||execution?.origin!=='scheduled-workflow'||execution.sessionId!==null
      ||execution.actorId!==namespace.proof.actor.id||execution.workflowId!==namespace.proof.workflow.id||execution.scheduleClaimId!==namespace.proof.claim.id
      ||execution.expiresAt<=Date.now()||frame.sessionId!=null||frame.actor?.id!==namespace.proof.actor.id
      ||ticket.frame!==proof.frame||ticket.cluster!==proof.cluster||ticket.method!==proof.method||ticket.path!==proof.path
      ||ticket.body!==proof.body||ticket.query!==proof.query||transportScopeFor(ticket.cluster.admin_url,ticket.cluster.transport_scope)!==proof.transportScope||state.packet!==this.preparationPacket(ticket.method,ticket.path,ticket.body,ticket.query)
      ||performance.now()>=state.deadline)throw denied('PORTAL_SQL_PREPARATION_CONTEXT_CHANGED');
    if(frame===state.schemaFrame&&(frame.kind!=='internal-read'||frame.purpose!=='entity-preflight'||this.states.get(frame)?.parent!==proof.frame
      ||frame.limits.paths?.length!==1||frame.limits.paths[0]!==this.#portalSchemaPath(ticket)))throw denied('PORTAL_SQL_PREPARATION_SCHEMA_CHANGED');
    if(frame===state.parentFrame&&(frame.kind!=='internal-read'||frame.purpose!=='authorization'||this.states.get(frame)?.parent!==proof.frame
      ||frame.operation!==proof.operation||frame.limits.paths?.length!==1||frame.limits.paths[0]!==this.#portalParentPath(proof)))throw denied('PORTAL_SQL_PREPARATION_PARENT_CHANGED');
    if(support){const permit=this.portalPermit(support.permit);
      if(support.scope!==state||proof.purpose!=='before-send'||frame.purpose!=='portal-boundary'||frame.kind!=='internal-read'
        ||this.states.get(frame)?.parent!==proof.frame||frame.operation!==proof.operation||frame.limits.paths!==support.paths
        ||permit.ticket!==proof.ticket||permit.frame!==proof.frame||permit.transportScope!==proof.transportScope
        ||this.portalReads.get(frame)!==support.permit)throw denied('PORTAL_SQL_PREPARATION_SUPPORT_CHANGED');
    }
    return proof;
  }
  assertScheduledPortalPreparationPhase(original:object):void{
    if(this.scheduledPortalPreparationPhase()!==original)throw denied('PORTAL_SQL_PREPARATION_ORIGINAL_REQUIRED');
  }
  limitScheduledPortalPreparation(original:object,deadline:number):void{
    const state=this.#portalPreparations.getStore();if(!state||Number.isNaN(deadline)||deadline===-Infinity)throw denied('PORTAL_SQL_PREPARATION_CONTEXT_CHANGED');
    this.assertScheduledPortalPreparationPhase(original);state.deadline=Math.min(state.deadline,deadline);this.assertScheduledPortalPreparationPhase(original);
  }
  #portalSchemaPath(ticket:TicketState):string|null{
    if(ticket.method!=='POST')return null;
    if(ticket.path==='/consumers')return'/schemas/consumers';
    if(/^\/consumers\/[\da-f-]{36}\/acls$/i.test(ticket.path))return'/schemas/acls';
    if(/^\/consumers\/[\da-f-]{36}\/key-auth$/i.test(ticket.path))return'/schemas/keyauth_credentials';
    return null;
  }
  async #portalPreparation<T>(ticket:KongPolicyTicket,purpose:ScheduledPortalPreparationPhase['purpose'],fn:()=>Promise<T>):Promise<T>{
    this.assertTicketActive(ticket);const original=this.tickets.get(ticket)!,frame=this.current();
    if(original.frame!==frame||!this.#businessNativeOperations.has(frame)||!writeMethods.has(original.method))return fn();
    const namespace=this.workflowScheduledNamespace(frame),execution=this.executionProof(frame),step=this.optionalApprovedStep(frame);
    if(this.#portalPreparations.getStore()?.active)throw denied('PORTAL_SQL_PREPARATION_REENTRANT');
    if(original.frame!==frame||!this.#businessNativeOperations.has(frame)||!frame.operation||frame.sessionId!=null
      ||!writeMethods.has(original.method)||namespace?.proof.kind!=='portal-credential-issue'||!step||step.kind!=='native'||!execution
      ||step.execution!==execution||execution.origin!=='scheduled-workflow'||execution.sessionId!==null)return fn();
    const proof:Readonly<ScheduledPortalPreparationPhase>=Object.freeze({stage:'sql-preflight',purpose,ticket,frame,operation:frame.operation,
      namespaceHandle:namespace.handle,namespace:namespace.proof,execution,step,cluster:original.cluster,
      transportScope:transportScopeFor(original.cluster.admin_url,original.cluster.transport_scope),method:original.method,path:original.path,body:original.body,query:original.query});
    const state:PortalPreparationState={active:true,deadline:Infinity,proof,packet:this.preparationPacket(original.method,original.path,original.body,original.query)};
    try{return await this.#portalPreparations.run(state,async()=>{this.assertScheduledPortalPreparationPhase(proof);const result=await fn();
      this.assertScheduledPortalPreparationPhase(proof);await this.verifyWorkflowScheduledNamespace('packet');this.assertScheduledPortalPreparationPhase(proof);return result;});}
    finally{state.active=false;state.schemaFrame=undefined;state.parentFrame=undefined;}
  }
  #portalParentPath(proof:Readonly<ScheduledPortalPreparationPhase>):string|null{
    const match=/^\/consumers\/([\da-f-]{36})\/(acls|key-auth)$/i.exec(proof.path);
    if(!match||proof.method!=='POST'||proof.operation.entityType!=='credentials'||proof.operation.parentId!==match[1]
      ||proof.operation.credentialKind!==match[2])return null;
    return`/consumers/${match[1]}`;
  }
  /** Same existing authorization point read, constrained to the Consumer
   * parent of this original scheduled credential POST. Every actual GET and
   * current membership/resource guard still executes through the real SDK. */
  async runPortalNativeParentRead<T>(clusterId:string,path:string,fn:()=>Promise<T>):Promise<T>{
    // Target append parent upstream GET uses this ordinary path (#portalParentPath
    // only matches consumer credential POSTs). Under scheduled-workflow the
    // interactive 5s point budget races claim/SQL (KP-005 CONTEXT_EXPIRED).
    const pointMs=this.authorizationPointTimeoutMs();
    const ordinary=()=>this.runInternalRead(clusterId,'authorization',fn,{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:4*1024*1024,timeoutMs:pointMs});
    const scope=this.#portalPreparations.getStore(),proof=this.scheduledPortalPreparationPhase();
    if(!scope||!proof||this.current()!==proof.frame)return ordinary();
    const parentPath=this.#portalParentPath(proof);if(!parentPath)return ordinary();
    if(clusterId!==proof.namespace.clusterId||path!==parentPath||scope.parentFrame)throw denied('PORTAL_SQL_PREPARATION_PARENT_CHANGED');
    const parent=this.current(),frame=this.make({kind:'internal-read',purpose:'authorization',actor:parent.actor,sessionId:parent.sessionId,
      clusterId,workspaceId:parent.workspaceId,requestId:parent.requestId,ip:parent.ip,idempotencyKey:parent.idempotencyKey,
      module:parent.module,action:parent.action,operation:parent.operation},{paths:[parentPath],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:4*1024*1024,timeoutMs:pointMs},parent);
    scope.parentFrame=frame;try{return await this.run(frame,fn);}finally{scope.parentFrame=undefined;this.assertScheduledPortalPreparationPhase(proof);}
  }
  /** Fixed SDK schema capsule. The path is derived from the original ticket,
   * never a caller-provided schema name, entity, permission or skip flag. */
  async runPortalWriteSchemaRead<T>(ticket:KongPolicyTicket,fn:()=>Promise<T>):Promise<T>{
    this.assertTicketActive(ticket);const original=this.tickets.get(ticket)!,path=this.#portalSchemaPath(original);
    if(!path||original.frame!==this.current())return fn();
    return this.#portalPreparation(ticket,'schema',async()=>{
      const scope=this.#portalPreparations.getStore();if(!scope)return fn();
      const parent=this.current(),frame=this.make({kind:'internal-read',purpose:'entity-preflight',actor:parent.actor,sessionId:parent.sessionId,
        clusterId:parent.clusterId,workspaceId:parent.workspaceId,requestId:parent.requestId,ip:parent.ip,idempotencyKey:parent.idempotencyKey,
        module:parent.module,action:parent.action,operation:parent.operation},{paths:[path],maxCalls:4},parent);
      scope.schemaFrame=frame;try{return await this.run(frame,fn);}finally{scope.schemaFrame=undefined;}
    });
  }
  /** A fixed SQL provider may only shorten the current private phase. An
   * observation cannot renew this bound or activate a copied/closed phase. */
  limitScheduledConfigurationPreparation(original:object,deadline:number):void{
    const state=this.sqlPreparations.getStore();
    if(!state||this.scheduledConfigurationPreparationPhase()!==original||!Number.isFinite(deadline))throw denied('CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED');
    state.deadline=Math.min(state.deadline,deadline);this.scheduledConfigurationPreparationPhase();
  }
  private preparationPacket(method:string,path:string,body:unknown,query:Readonly<Record<string,string|number>>):string{
    return canonicalJson({method,path,body:body??null,query});
  }
  private async sqlPreparation<T>(stage:'authorize'|'prepare'|'refresh',method:string,path:string,body:unknown,query:Readonly<Record<string,string|number>>,
    ticket:KongPolicyTicket|undefined,allowInner:boolean,fn:()=>Promise<T>):Promise<T>{
    const frame=this.current(),outer=this.sqlPreparations.getStore(),final=this.finalNativeStages.getStore();
    // Every actual nested GET retains its original full Native guards. This
    // shadows only this private phase cell; execution ALS/ancestors stay intact.
    if(!writeMethods.has(method))return outer?this.sqlPreparations.run(null,fn):fn();
    if(final?.active)return fn();
    const current=this.scheduledConfigurationPreparationPhase(),packet=this.preparationPacket(method,path,body,query);
    if(current){if(current.stage==='mutation-binding'||!allowInner||!outer||outer.proof!==current||outer.packet!==packet||ticket!==undefined)
      throw denied('CONFIGURATION_SQL_PREPARATION_REENTRANT');return fn();}
    const namespace=this.workflowScheduledNamespace(frame),job=this.configurationJob(frame),execution=this.executionProof(frame),step=this.optionalApprovedStep(frame);
    if(!namespace||namespace.proof.kind!=='configuration_v2'||namespace.proof.approvalSet?.format!==2
      ||job?.proof.origin!=='workflow-scheduled-configuration'||!job.proof.originalScheduledJobHandle
      ||job.proof.namespaceHandle!==namespace.handle||!execution||execution.origin!=='scheduled-configuration'||execution.sessionId!==null
      ||!step||step.kind!=='native'||step.execution!==execution||!frame.operation||frame.sessionId!=null
      ||frame.operation.actor.id!==namespace.proof.actor.id||execution.actorId!==namespace.proof.actor.id
      ||execution.scheduleClaimId!==namespace.proof.claim.id||execution.workflowOriginId!==job.proof.wrapperOriginId
      ||execution.workflowId!==namespace.proof.workflow.id||execution.expiresAt<=Date.now()
      ||!this.workflowScheduledPolicy?.verifySqlPreparation)return fn();
    const proof:Readonly<ConfigurationSqlPreparation>=Object.freeze({stage,frame,operation:frame.operation,namespaceHandle:namespace.handle,namespace:namespace.proof,
      originalJobHandle:job.proof.originalScheduledJobHandle,execution,step});
    const scope:ConfigurationSqlPreparationState={active:true,deadline:Infinity,proof,packet,...(ticket?{ticket}:{})};
    try{return await this.sqlPreparations.run(scope,async()=>{
      this.scheduledConfigurationPreparationPhase();const result=await fn();this.scheduledConfigurationPreparationPhase();
      const proof=await this.workflowScheduledPolicy!.verifySqlPreparation!(scope.proof.namespaceHandle,'packet');
      if(this.scheduledConfigurationPreparationPhase()!==scope.proof||proof!==scope.proof.namespace)throw denied('CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED');
      return result;
    });}finally{scope.active=false;}
  }
  scheduledPortalFinalNativePhase():ScheduledPortalFinalNativePhase|null{
    const state=this.#portalFinalNativeStages.getStore();if(!state?.active)return null;
    const proof=state.proof,frame=this.current();if(frame!==proof.frame)return null;
    this.assertTicketActive(proof.ticket);const ticket=this.tickets.get(proof.ticket)!,namespace=this.workflowScheduledNamespace(frame);
    if(!this.#businessNativeOperations.has(frame)||frame.operation!==proof.operation||namespace?.handle!==proof.namespaceHandle||namespace.proof!==proof.namespace
      ||this.executionProof(frame)!==proof.execution||this.optionalApprovedStep(frame)!==proof.step||proof.execution.expiresAt<=Date.now()
      ||ticket.frame!==frame||ticket.method!==proof.method||ticket.path!==proof.path||ticket.body!==proof.body||ticket.query!==proof.query
      ||transportScopeFor(ticket.cluster.admin_url,ticket.cluster.transport_scope)!==proof.transportScope)throw denied('PORTAL_FINAL_NATIVE_CONTEXT_CHANGED');
    return proof;
  }
  assertScheduledPortalFinalNativePhase(original:object):void{
    if(this.scheduledPortalFinalNativePhase()!==original)throw denied('PORTAL_FINAL_NATIVE_ORIGINAL_REQUIRED');
  }
  /** SQL-only checks remain bounded to this original physical final gate.
   * The caller must still execute its actual full party SDK step outside it. */
  async runPortalFinalNativePrecheck<T>(original:object,fn:()=>Promise<T>):Promise<T>{
    this.assertScheduledPortalFinalNativePhase(original);const proof=this.scheduledPortalFinalNativePhase()!;
    const result=await this.#portalPreparation(proof.ticket,proof.stage==='response'?'response-closing':'before-send',fn);
    this.assertScheduledPortalFinalNativePhase(original);return result;
  }
  async #finalNativeStage<T>(ticket:KongPolicyTicket,stage:'before-send'|'response',fn:()=>Promise<T>):Promise<T>{
    this.assertTicketActive(ticket);if(this.#portalPreparations.getStore()?.active)throw denied('PORTAL_SQL_PREPARATION_NATIVE_FORBIDDEN');if(this.scheduledConfigurationPreparationPhase())throw denied('CONFIGURATION_SQL_PREPARATION_NATIVE_FORBIDDEN');
    const frame=this.current(),state=this.tickets.get(ticket)!,namespace=this.workflowScheduledNamespace(frame),eligible=this.#businessNativeOperations.has(frame)&&writeMethods.has(state.method);
    const execution=eligible?this.executionProof(frame):null,step=eligible?this.optionalApprovedStep(frame):null;
    const portal=eligible&&namespace?.proof.kind==='portal-credential-issue'&&execution?.origin==='scheduled-workflow'
      &&execution.sessionId===null&&step?.kind==='native'&&step.execution===execution&&frame.operation&&state.frame===frame
      ?Object.freeze({stage,ticket,frame,operation:frame.operation,namespaceHandle:namespace.handle,namespace:namespace.proof,execution,step,
        cluster:state.cluster,transportScope:transportScopeFor(state.cluster.admin_url,state.cluster.transport_scope),method:state.method,path:state.path,body:state.body,query:state.query}):undefined;
    const scope={active:true,frame,ticket,stage},privateFinal=portal?{active:true,proof:portal}:null;
    try{return await this.finalNativeStages.run(scope,()=>this.#portalFinalNativeStages.run(privateFinal,fn));}finally{scope.active=false;if(privateFinal)privateFinal.active=false;}
  }
  async verifyWorkflowScheduledNamespace(checkpoint:WorkflowScheduledNamespaceCheckpoint):Promise<Readonly<WorkflowScheduledNamespaceProof>|null>{
    const frame=this.current(),claim=this.workflowScheduledNamespace(frame);if(!claim)return null;
    if(this.workflowValidationRead(frame))throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY');
    if(!this.workflowScheduledPolicy)throw unavailable();
    const preparation=this.scheduledConfigurationPreparationPhase();
    const current=preparation?await this.workflowScheduledPolicy.verifySqlPreparation!(claim.handle,'packet'):await this.workflowScheduledPolicy.verifyHandle(claim.handle,checkpoint);this.chain(frame);
    if(preparation&&this.scheduledConfigurationPreparationPhase()!==preparation)throw denied('CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED');
    // A real nested V2 Native step may target a sealed object workspace. Its
    // independently installed verifier checks that exact step/object grant;
    // the wrapper, Portal and arbitrary actor frames retain their anchor.
    let objectWorkspace=false;
    if(frame.workspaceId!==current.workspaceId&&frame.operation&&current.kind==='configuration_v2'){
      const execution=this.executionProof(frame),step=this.optionalApprovedStep(frame),job=this.configurationJob(frame);
      objectWorkspace=!!job&&job.proof.origin==='workflow-scheduled-configuration'&&job.proof.namespaceHandle===claim.handle
        &&execution?.origin==='scheduled-configuration'&&execution.scheduleClaimId===current.claim.id
        &&execution.workflowId===current.workflow.id&&execution.workflowOriginId===job.proof.wrapperOriginId
        &&step?.kind==='native'&&step.execution===execution&&frame.operation.workspaceId===frame.workspaceId;
      if(objectWorkspace){if(!this.approvedPolicy?.verifyWorkflowScheduledConfigurationExecution||!job!.proof.originalScheduledJobHandle)throw denied('CONFIGURATION_SCHEDULED_NESTED_CONTEXT_REQUIRED');
        await this.approvedPolicy.verifyWorkflowScheduledConfigurationExecution(execution!,claim.handle,job!.proof.originalScheduledJobHandle);this.chain(frame);}
    }
    if(current!==claim.proof||current.origin!=='scheduled-workflow'||current.sessionId!==null||frame.sessionId!=null
      ||frame.actor?.id!==current.actor.id||frame.clusterId!==current.clusterId||frame.workspaceId!==current.workspaceId&&!objectWorkspace)
      throw denied('WORKFLOW_SCHEDULE_NAMESPACE_SCOPE_CHANGED');
    return current;
  }
  async runWorkflowScheduledNamespace<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    if(this.storage.getStore())throw denied('WORKFLOW_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN');
    if(!this.workflowScheduledPolicy)throw unavailable();
    if(!handle||typeof handle!=='object'||this.usedWorkflowScheduledNamespaces.has(handle)||typeof fn!=='function')throw denied('WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED');
    const proof=await this.workflowScheduledPolicy.verifyHandle(handle,'claim');
    if(this.storage.getStore()||proof.origin!=='scheduled-workflow'||proof.sessionId!==null||!proof.actor?.id
      ||!['configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(proof.kind)||proof.actor.forcePasswordChange
      ||Date.parse(proof.expiresAt)<=Date.now()||!Number.isFinite(Date.parse(proof.expiresAt)))throw denied('WORKFLOW_SCHEDULE_NAMESPACE_REQUIRED');
    this.usedWorkflowScheduledNamespaces.add(handle);
    const frame=this.make({kind:'scheduled-workflow',actor:proof.actor,clusterId:proof.clusterId,workspaceId:proof.workspaceId,module:'workflows',action:'write',
      ...(proof.kind==='configuration_v2'?{purpose:'configuration'}:{})},
      {},undefined,{handle,proof});
    this.workflowScheduledNamespaces.set(frame,{handle,proof});
    try{return await this.run(frame,fn);}finally{this.workflowScheduledNamespaces.delete(frame);}
  }
  installWorkflowScheduleCandidateReadPolicy(policy:WorkflowScheduleCandidateReadPolicy):void{
    if(this.workflowCandidateReadPolicy||!policy||['verifyHandle','verifyRequest','assertLive','authorizeRequest','authorizeResponse'].some(key=>typeof(policy as any)[key]!=='function'))throw unavailable();
    this.workflowCandidateReadPolicy=policy;
  }
  installWorkflowCandidateHttpAdmissionPolicy(policy:WorkflowCandidateHttpAdmissionPolicy):void{
    if(this.workflowCandidateHttpAdmission||!policy||typeof policy.verifyParent!=='function'||Object.keys(policy).some(k=>k!=='verifyParent'))throw unavailable();
    this.workflowCandidateHttpAdmission=Object.freeze({verifyParent:policy.verifyParent.bind(policy)});
  }
  private assertCandidateHttpParent(frame:KongExecutionFrame):void{
    if(!this.workflowCandidateHttpAdmission||frame.kind!=='actor'||frame.module!=='workflows'||!['write','approve'].includes(frame.action??'')
      ||!frame.actor?.id||frame.actor.forcePasswordChange||typeof frame.sessionId!=='string'||!frame.sessionId
      ||!frame.clusterId||!frame.workspaceId||frame.purpose)throw denied('WORKFLOW_CANDIDATE_EXISTING_CONTEXT_FORBIDDEN');
    const chain=this.chain(frame),root=chain.at(-1),identity=root&&this.httpActors.get(root);
    if(!root||root.kind!=='http'||!identity?.actor||identity.actor!==frame.actor||identity.sessionId!==frame.sessionId
      ||chain.some(ancestor=>ancestor.kind!=='http'&&ancestor.kind!=='actor'||ancestor.operation||ancestor.archive||ancestor.purpose
        ||this.scheduledNamespaces.has(ancestor)||this.workflowScheduledNamespaces.has(ancestor)||this.workflowCandidateReads.has(ancestor)
        ||this.workflowValidationReads.has(ancestor)||this.entityChangePackets.has(ancestor)||this.approvedExecutions.has(ancestor)
        ||this.configurationJobs.has(ancestor)||this.toolboxOperations.has(ancestor)||this.governanceReads.has(ancestor)
        ||this.promotionRecoveryFrames.has(ancestor)||this.promotionPlanningFrames.has(ancestor)||this.issueRecoveries.has(ancestor)))
      throw denied('WORKFLOW_CANDIDATE_EXISTING_CONTEXT_FORBIDDEN');
  }
  /** Separate from Namespace admission: a private HTTP ancestor may host only
   * the fixed readonly reader while keeping its close and budget fences. */
  assertWorkflowScheduleCandidateReadAdmission():void{
    const frame=this.storage.getStore();if(!frame)return;this.assertCandidateHttpParent(frame);
  }
  /** SQL-only fixed admission getter. A copied frame, HTTP role/header or an
   * unrelated original read handle cannot stand in for this private chain. */
  requireWorkflowScheduleCandidateHttpParent(handle:object,actualFrame:Readonly<KongExecutionFrame>):Readonly<KongExecutionFrame>{
    const current=this.current(),candidate=this.workflowCandidateRead(current);
    if(candidate){
      if(candidate.handle!==handle||candidate.httpParent!==actualFrame||!this.chain(current).includes(actualFrame))throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HTTP_PARENT_REQUIRED');
    }else if(current!==actualFrame)throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HTTP_PARENT_REQUIRED');
    this.assertCandidateHttpParent(actualFrame);return actualFrame;
  }
  private async verifyCandidateHttpParent(handle:object,parent:KongExecutionFrame,origin:KongExecutionFrame):Promise<void>{
    this.assertCandidateHttpParent(parent);
    if(!this.chain(origin).includes(parent))throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HTTP_PARENT_REQUIRED');
    await this.workflowCandidateHttpAdmission!.verifyParent(handle,parent);
    this.assertCandidateHttpParent(parent);
    if(this.storage.getStore()!==origin||!this.chain(origin).includes(parent))throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HTTP_PARENT_REQUIRED');
  }
  private workflowCandidateRead(frame:KongExecutionFrame){
    for(const ancestor of this.chain(frame)){const claim=this.workflowCandidateReads.get(ancestor);if(claim)return claim;}return undefined;
  }
  async runWorkflowScheduleCandidateRead<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    this.assertWorkflowScheduleCandidateReadAdmission();const parent=this.storage.getStore();
    if(!this.workflowCandidateReadPolicy)throw unavailable();
    if(!handle||typeof handle!=='object'||this.usedWorkflowCandidateReads.has(handle)||typeof fn!=='function')throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED');
    const proof=await this.workflowCandidateReadPolicy.verifyHandle(handle);
    if(this.storage.getStore()!==parent||proof.origin!=='workflow-schedule-candidate-read'||proof.readOnly!==true||proof.sessionId!==null
      ||!proof.actor?.id||proof.actor.forcePasswordChange||!Number.isFinite(Date.parse(proof.expiresAt))||Date.parse(proof.expiresAt)<=Date.now()
      ||Date.parse(proof.expiresAt)>Date.now()+30000||!proof.scope||proof.scope.domain!==undefined&&proof.scope.domain!=='scoped-points-v1'||!proof.registries.length)throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED');
    if(parent)await this.verifyCandidateHttpParent(handle,parent,parent);
    this.usedWorkflowCandidateReads.add(handle);
    // Each GET is bound by the private provider to an exact source/target
    // registry. This frame cannot choose a cluster or lend write authority.
    const frame=this.make({kind:'workflow-candidate-read',actor:proof.actor,module:'workflows',action:'read'},
      {...proof.scope.limits,timeoutMs:Math.min(30000,Date.parse(proof.expiresAt)-Date.now())},parent);
    this.workflowCandidateReads.set(frame,{handle,proof,httpParent:parent});
    try{return await this.run(frame,async()=>{
      const result=await fn();if(parent)await this.verifyCandidateHttpParent(handle,parent,frame);return result;
    });}finally{this.workflowCandidateReads.delete(frame);}
  }
  private async verifyWorkflowCandidateRead(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,body:unknown):Promise<Readonly<WorkflowScheduleCandidateReadProof>|null>{
    const claim=this.workflowCandidateRead(frame);if(!claim)return null;if(!this.workflowCandidateReadPolicy)throw unavailable();
    if(method!=='GET'||body!==undefined||frame.operation||frame.archive||frame.sessionId!=null)throw denied('WORKFLOW_CANDIDATE_READ_ONLY');
    const proof=await this.workflowCandidateReadPolicy.verifyHandle(claim.handle);this.chain(frame);
    if(claim.httpParent)await this.verifyCandidateHttpParent(claim.handle,claim.httpParent,frame);
    const registry=proof.registries.find(r=>r.clusterId===cluster.id);
    if(proof!==claim.proof||frame.actor?.id!==proof.actor.id||!registry
      ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==registry.transportScope
      ||Number(cluster.revision)!==registry.clusterRevision)throw denied('WORKFLOW_CANDIDATE_SCOPE_CHANGED');
    return proof;
  }
  /** A server descriptor only selects a member of the current original read
   * scope. It neither creates a workspace identity nor changes Admin query
   * parameters. This is needed when two workspaces share a schema path. */
  async runWorkflowScheduledReadResource<T>(originalReadHandle:object,resource:Readonly<WorkflowScheduleCandidateReadResource>,fn:()=>Promise<T>):Promise<T>{
    const frame=this.current(),candidate=this.workflowCandidateRead(frame),validation=this.workflowValidationRead(frame);
    if((!candidate&&!validation)||candidate&&validation||typeof fn!=='function'||this.scheduledReadResources.getStore())throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');
    const claim=candidate??validation!;
    if(claim.handle!==originalReadHandle)throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');
    const proof=candidate?await this.workflowCandidateReadPolicy!.verifyHandle(claim.handle)
      :await this.workflowValidationReadPolicy!.verifyHandle(validation!.handle,validation!.namespaceHandle,validation!.namespaceProof);
    this.chain(frame);
    if(proof!==claim.proof)throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');
    const resources=proof.scope.resources.filter(r=>canonicalJson(r)===canonicalJson(resource));
    if(resources.length!==1)throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');
    const selection:ScheduledReadResourceSelection={active:true,frame,handle:originalReadHandle,resource:resources[0]};
    try{return await this.scheduledReadResources.run(selection,fn);}finally{selection.active=false;}
  }
  private selectedScheduledReadResource(frame:KongExecutionFrame,handle:object,resources:readonly Readonly<WorkflowScheduleCandidateReadResource>[],cid:string,path:string){
    const selection=this.scheduledReadResources.getStore(),matches=resources.filter(r=>r.clusterId===cid&&r.path===path);
    if(!selection){if(matches.length>1)throw denied('WORKFLOW_SCHEDULE_READ_RESOURCE_AMBIGUOUS');return{resource:matches[0],selection:undefined};}
    if(!selection.active||selection.handle!==handle||!this.chain(frame).includes(selection.frame)||selection.resource.clusterId!==cid||selection.resource.path!==path)
      throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');
    const selected=matches.filter(r=>canonicalJson(r)===canonicalJson(selection.resource));
    if(selected.length!==1)throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');return{resource:selected[0],selection};
  }
  installWorkflowScheduledValidationReadPolicy(policy:WorkflowScheduledValidationReadPolicy):void{
    const methods=['verifyHandle','assertLive','authorizeRequest','verifyRequest','authorizeResponse'] as const;
    if(this.workflowValidationReadPolicy||!policy||methods.some(method=>typeof policy[method]!=='function'))throw unavailable();
    this.workflowValidationReadPolicy=Object.freeze(Object.fromEntries(methods.map(method=>[method,policy[method].bind(policy)]))) as unknown as Readonly<WorkflowScheduledValidationReadPolicy>;
  }
  private workflowValidationRead(frame:KongExecutionFrame){
    for(const ancestor of this.chain(frame)){const claim=this.workflowValidationReads.get(ancestor);if(claim)return claim;}return undefined;
  }
  private validationProof(value:Readonly<WorkflowScheduledValidationReadProof>,namespace:Readonly<WorkflowScheduledNamespaceProof>):void{
    const until=Date.parse(value?.expiresAt),now=Date.now();
    if(!value||value.version!==1||value.origin!=='workflow-scheduled-validation-read'||value.readOnly!==true||value.sessionId!==null
      ||!value.actor?.id||value.actor.forcePasswordChange||!['executor','reviewer'].includes(value.role)||value.namespace!==namespace
      ||value.role==='executor'&&value.actor.id!==namespace.actor.id||!Number.isFinite(until)||until<=now||until>Date.parse(namespace.expiresAt)
      ||!value.scope||value.scope.version!==1||value.scope.domain!==undefined&&value.scope.domain!=='scoped-points-v1'||!Array.isArray(value.scope.resources)||!value.scope.resources.length||!Array.isArray(value.registries)||!value.registries.length)
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');
    if(until>now+workflowScheduledValidationBudgetMs(namespace.kind,value.scope))throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');
    const pairs=new Set<string>();
    for(const registry of value.registries){const key=`${registry.clusterId}:${registry.workspaceId}`;
      if(!registry.clusterId||!registry.workspaceId||pairs.has(key)||!(/^[a-f\d]{64}$/.test(registry.transportScope))
        ||!Number.isSafeInteger(registry.clusterRevision)||registry.clusterRevision<1||!Number.isSafeInteger(registry.workspaceRevision)||registry.workspaceRevision<1)
        throw denied('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');pairs.add(key);
    }
    for(const resource of value.scope.resources){
      if(!pairs.has(`${resource.clusterId}:${resource.workspaceId}`)||typeof resource.path!=='string')throw denied('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
      assertKongPath('GET',resource.path);
    }
  }
  /** Short, private GET validation nested in the genuine business Namespace.
   * It keeps all ancestors, lease fences and aggregate counters. No ALS exit, copied
   * namespace, browser SID or callback-selected path can confer authority. */
  async runWorkflowScheduledValidationRead<T>(handle:object,originalNamespaceHandle:object,fn:()=>Promise<T>):Promise<T>{
    const parent=this.current(),namespace=this.workflowScheduledNamespace(parent);
    if(!namespace||namespace.handle!==originalNamespaceHandle||this.workflowValidationRead(parent)||this.workflowCandidateRead(parent)
      ||parent.sessionId!=null||this.entityChangePacket(parent)
      ||!handle||typeof handle!=='object'||this.usedWorkflowValidationReads.has(handle)||typeof fn!=='function')throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');
    if(!this.workflowValidationReadPolicy)throw unavailable();
    const proof=await this.workflowValidationReadPolicy.verifyHandle(handle,namespace.handle,namespace.proof);this.chain(parent);
    this.validationProof(proof,namespace.proof);this.usedWorkflowValidationReads.add(handle);
    const frame=this.make({kind:'workflow-validation-read',actor:proof.actor,module:'workflows',action:'read',
      ...(namespace.proof.kind==='configuration_v2'?{purpose:'configuration'}:{})},
      {...proof.scope.limits,timeoutMs:Math.min(workflowScheduledValidationBudgetMs(namespace.proof.kind,proof.scope),Date.parse(proof.expiresAt)-Date.now())},parent);
    const ancestors=this.chain(parent),namespaceFrame=ancestors.find(ancestor=>this.workflowScheduledNamespaces.get(ancestor)===namespace);
    if(!namespaceFrame)throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');
    // Pin exact original bounded observers. Keep the one-call rule and include
    // the SDK's single-path entity preflight with its four-call retry
    // budget; the business GET and retries still charge that original frame.
    // Real operation/approved/job frames and the Namespace remain aggregate.
    const localReadBudgets=Object.freeze(ancestors.slice(0,ancestors.indexOf(namespaceFrame)).filter(ancestor=>ancestor.kind==='internal-read'
      &&(ancestor.limits.maxCalls===1||ancestor.purpose==='entity-preflight'&&ancestor.limits.maxCalls===4)
      &&ancestor.limits.paths?.length===1&&!this.configurationJobs.has(ancestor)&&!this.approvedExecutions.has(ancestor)
      &&!this.approvedSteps.has(ancestor)&&!this.scheduledConfigurationBoundaries.has(ancestor)));
    const claim:WorkflowValidationReadClaim=Object.freeze({handle,proof,namespaceHandle:namespace.handle,namespaceProof:namespace.proof,namespaceFrame,localReadBudgets});this.workflowValidationReads.set(frame,claim);
    try{return await this.run(frame,async()=>{const result=await fn();
      const current=await this.workflowValidationReadPolicy!.verifyHandle(handle,namespace.handle,namespace.proof);this.chain(frame);
      if(current!==proof)throw denied('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');return result;
    });}finally{this.workflowValidationReads.delete(frame);}
  }
  private async verifyWorkflowValidationRead(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,body:unknown):Promise<Readonly<WorkflowScheduledValidationReadProof>|null>{
    const claim=this.workflowValidationRead(frame);if(!claim)return null;if(!this.workflowValidationReadPolicy)throw unavailable();
    const proof=await this.workflowValidationReadPolicy.verifyHandle(claim.handle,claim.namespaceHandle,claim.namespaceProof);
    return this.assertWorkflowValidationReadProof(frame,cluster,method,body,proof);
  }
  /** The original provider already performed the current SQL check for this
   * request checkpoint. Validate that exact returned proof synchronously;
   * never memoize it across an await, ticket, stage or response. */
  private assertWorkflowValidationReadProof(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,body:unknown,
    proof:Readonly<WorkflowScheduledValidationReadProof>):Readonly<WorkflowScheduledValidationReadProof>{
    const claim=this.workflowValidationRead(frame);if(!claim||!this.workflowValidationReadPolicy)throw denied('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
    if(method!=='GET'||body!==undefined||frame.operation||frame.archive||frame.sessionId!=null)throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY');
    const namespace=this.workflowScheduledNamespace(frame);
    if(!namespace||namespace.handle!==claim.namespaceHandle||namespace.proof!==claim.namespaceProof)throw denied('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');
    this.chain(frame);
    this.validationProof(proof,namespace.proof);
    const registry=proof.registries.find(r=>r.clusterId===cluster.id);
    if(proof!==claim.proof||frame.actor?.id!==proof.actor.id||!registry
      ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==registry.transportScope||Number(cluster.revision)!==registry.clusterRevision)
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED');return proof;
  }
  private entityChangePacket(frame:KongExecutionFrame):{handle:object;proof:EntityChangePacketExecutionProof;ticket?:KongPolicyTicket}|undefined{
    for(const ancestor of this.chain(frame)){const claim=this.entityChangePackets.get(ancestor);if(claim)return claim;}return undefined;
  }
  /** Server policy hook. A frame-shaped DTO or historical frame cannot obtain
   * a handle; Root's live WeakMap identity remains the only packet authority. */
  requireEntityChangePacketFrame(frame:KongExecutionFrame):object{
    if(frame!==this.current())throw denied('ENTITY_CHANGE_PACKET_CONTEXT_INVALID');
    const entity=this.entityChangePacket(frame);if(!entity)throw denied('ENTITY_CHANGE_PACKET_CONTEXT_INVALID');
    return entity.handle;
  }
  async runEntityChangePacket<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    this.forbidRecoveryNative();const parent=this.current();
    const scheduled=await this.verifyEntityScheduledNamespace('packet');
    if(!this.entityChangePolicy||!['actor','scheduled-entity'].includes(parent.kind)||!parent.actor||(!parent.sessionId&&!scheduled)||parent.operation||parent.archive||parent.purpose==='configuration'
      ||this.configurationJob(parent)||this.toolboxOperation(parent)||this.governanceRead(parent)||this.promotionRecovery(parent)||this.planning(parent)
      ||this.entityChangePacket(parent)||this.executionProof(parent))throw denied('ENTITY_CHANGE_PACKET_CONTEXT_INVALID');
    const proof=Object.freeze({...await this.entityChangePolicy.verifyHandle(handle)});this.chain(parent);
    if(proof.actorId!==parent.actor.id||(scheduled?proof.origin!=='scheduled-entity'||proof.sessionId!==null:proof.origin!==undefined||proof.sessionId!==parent.sessionId)||proof.clusterId!==parent.clusterId||proof.workspaceId!==parent.workspaceId
      ||!Number.isFinite(proof.expiresAt)||proof.expiresAt<=Date.now())throw denied('ENTITY_CHANGE_PACKET_SCOPE_INVALID');
    const frame=this.make({...parent,kind:'actor'},{},parent);this.entityChangePackets.set(frame,{handle,proof});
    try{return await this.run(frame,fn);}finally{this.entityChangePackets.delete(frame);}
  }
  private entityChangeInput(state:TicketState):ApprovedNativeRequest{
    const scope=state.frame.operation;if(!scope)throw denied('ENTITY_CHANGE_NATIVE_OPERATION_REQUIRED');
    return{frame:state.frame,cluster:state.cluster,clusterId:state.cluster.id,transportScope:transportScopeFor(state.cluster.admin_url,state.cluster.transport_scope),
      workspaceId:state.frame.workspaceId!,operationId:scope.operationId,method:state.method,canonicalPath:state.path,body:state.body,before:(state.value as KongPolicyDecision)?.before,
      mutationAction:scope.action??'',parentId:scope.parentId,credentialKind:scope.credentialKind,query:state.query};
  }
  observeEntityChangeTransportResponse(ticket:KongPolicyTicket,status:number,result:unknown):void{
    // Called by the fixed transport after a real response. Recording it is
    // not an authorization refresh and survives live permission revocation.
    const state=this.tickets.get(ticket);if(!state)return;
    let entity:ReturnType<KongExecutionContextService['entityChangePacket']>;
    // A truthful response remains recordable after the original HTTP frame
    // closes. This traversal supplies no new authorization or ticket.
    for(let ancestor:KongExecutionFrame|undefined=state.frame;ancestor;ancestor=this.states.get(ancestor)?.parent){
      entity=this.entityChangePackets.get(ancestor);if(entity)break;
    }
    if(!entity)return;
    if(!this.entityChangePolicy||entity.ticket!==ticket)throw denied('ENTITY_CHANGE_RESPONSE_TICKET_INVALID');
    this.entityChangePolicy.observeTransportResponse(entity.handle,this.entityChangeInput(state),status,result);
  }
  observeEntityChangeReadResponse(ticket:KongPolicyTicket,status:number):void{
    const state=this.tickets.get(ticket);
    if(!state||state.method!=='GET'||state.frame.kind!=='internal-read'||state.frame.purpose!=='recycle-check'||!state.frame.operation)return;
    const entity=this.entityChangePacket(state.frame);if(!entity)return;
    // A live issued read ticket and the exact original ancestor packet are
    // mandatory. This is an observation, never an additional write permit.
    this.assertTicketActive(ticket);
    if(!this.entityChangePolicy?.observeVerificationResponse)throw denied('ENTITY_CHANGE_VERIFICATION_OBSERVER_REQUIRED');
    this.entityChangePolicy.observeVerificationResponse(entity.handle,this.entityChangeInput(state),status);
  }
  spendEntityChangeTransport(ticket:KongPolicyTicket):void{
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!;
    const entity=this.entityChangePacket(state.frame);if(!entity)return;
    if(!this.entityChangePolicy||entity.ticket!==ticket)throw denied('ENTITY_CHANGE_TRANSPORT_TICKET_INVALID');
    this.entityChangePolicy.spendTransport(entity.handle,this.entityChangeInput(state));
  }
  installApprovedPolicy(policy: ApprovedExecutionPolicy): void {
    if (!policy || ['verifyExecution', 'verifyStep', 'mutationBinding', 'bindOperation', 'assertNative', 'assertMetadata'].some(key => typeof policy[key as keyof ApprovedExecutionPolicy] !== 'function') || this.approvedPolicy && this.approvedPolicy !== policy) throw unavailable();
    this.approvedPolicy = policy;
  }
  installConfigurationJobPolicy(policy: ConfigurationJobExecutionPolicy): void {
    if (!policy || typeof policy.verifyHandle !== 'function' || this.configurationJobPolicy && this.configurationJobPolicy !== policy) throw unavailable();
    this.configurationJobPolicy = policy;
  }
  installToolboxOperationPolicy(policy:ToolboxOperationPolicy):void{
    if(!policy||typeof policy.verifyHandle!=='function'||typeof policy.beforeSend!=='function'||this.toolboxOperationPolicy&&this.toolboxOperationPolicy!==policy)throw unavailable();this.toolboxOperationPolicy=policy;
  }
  installGovernanceReadPolicy(policy:GovernanceReadPolicy):void{
    if(!policy||['verifyHandle','startRead','endRead','filterResponse'].some(key=>typeof (policy as any)[key]!=='function')||this.governanceReadPolicy&&this.governanceReadPolicy!==policy)throw unavailable();
    this.governanceReadPolicy=policy;
  }
  installPromotionRecoveryReadPolicy(policy:PromotionRecoveryReadPolicy):void{
    if(this.promotionRecoveryPolicy||!policy||typeof policy.verifyHandle!=='function'||typeof policy.assertResponse!=='function')throw unavailable();
    this.promotionRecoveryPolicy=Object.freeze({...policy});
  }
  installPromotionPlanningPolicy(policy:PromotionPlanningPolicy):void{
    if(this.promotionPlanningPolicy||!policy||typeof policy.verifyHandle!=='function')throw unavailable();
    this.promotionPlanningPolicy=Object.freeze({...policy});
  }
  private planning(frame:KongExecutionFrame):PromotionPlanningFrame|undefined{
    // Ordinary durable configuration jobs may intentionally detach from a
    // closed HTTP caller. Only a genuine planning ancestor imposes this
    // additional lifetime restriction; its marker also survives closure.
    for(let ancestor:KongExecutionFrame|undefined=frame;ancestor;ancestor=this.states.get(ancestor)?.parent){
      const claim=this.promotionPlanningFrames.get(ancestor);if(claim){this.chain(frame);return claim;}
    }
    return undefined;
  }
  private planningProof(value:PromotionPlanningProof):PromotionPlanningProof{
    const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
    if(!value||![value.promotionId,value.actor?.id,value.sessionId,value.sourceClusterId,value.sourceWorkspaceId,value.clusterId,value.workspaceId].every(id=>typeof id==='string'&&uuid.test(id))
      ||!(/^[a-f\d]{64}$/.test(value.transportScope??''))||typeof value.permissionVersion!=='string'||!value.permissionVersion
      ||!Number.isSafeInteger(value.credentialEpoch)||value.credentialEpoch<1||!Number.isFinite(value.expiresAt)||value.expiresAt<=Date.now())throw denied('PROMOTION_PLANNING_PROOF_INVALID');
    this.assertGovernanceOrigin(value.originFrame,value.actor.id,value.sessionId);
    if(value.originFrame.clusterId!==value.sourceClusterId||value.originFrame.workspaceId!==value.sourceWorkspaceId)throw denied('PROMOTION_PLANNING_SOURCE_MISMATCH');
    return Object.freeze({...value,actor:Object.freeze({...value.actor})});
  }
  private planningIdentity(proof:PromotionPlanningProof):string{
    return JSON.stringify({promotion:proof.promotionId,actor:proof.actor.id,sid:proof.sessionId,source:proof.sourceClusterId,sourceWorkspace:proof.sourceWorkspaceId,
      target:proof.clusterId,workspace:proof.workspaceId,transport:proof.transportScope,permissions:proof.permissionVersion,epoch:proof.credentialEpoch});
  }
  private async currentPlanning(claim:PromotionPlanningFrame):Promise<PromotionPlanningProof>{
    if(!this.promotionPlanningPolicy)throw denied('PROMOTION_PLANNING_REQUIRED');
    this.chain(claim.rootFrame);
    const proof=this.planningProof(await this.storage.exit(()=>this.promotionPlanningPolicy!.verifyHandle(claim.handle)));
    this.chain(claim.rootFrame);
    if(proof.originFrame!==claim.proof.originFrame||this.planningIdentity(proof)!==this.planningIdentity(claim.proof))throw denied('PROMOTION_PLANNING_CHANGED');
    return proof;
  }
  async runPromotionPlanning<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    const caller=this.current();
    if(this.workflowValidationRead(caller))throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY');
    if(!this.promotionPlanningPolicy||!handle||typeof handle!=='object'||this.usedPromotionPlanningHandles.has(handle)||caller.operation||caller.archive)throw denied('PROMOTION_PLANNING_REQUIRED');
    const proof=this.planningProof(await this.storage.exit(()=>this.promotionPlanningPolicy!.verifyHandle(handle)));
    if(caller!==proof.originFrame||caller.actor?.id!==proof.actor.id||caller.sessionId!==proof.sessionId)throw denied('PROMOTION_PLANNING_IDENTITY_MISMATCH');
    this.usedPromotionPlanningHandles.add(handle);
    const frame=this.storage.exit(()=>this.make({kind:'actor',actor:proof.actor,sessionId:proof.sessionId,clusterId:proof.clusterId,workspaceId:proof.workspaceId,
      module:'snapshots',action:'read',purpose:'promotion-planning',requestId:caller.requestId,ip:caller.ip,idempotencyKey:caller.idempotencyKey},
      {timeoutMs:Math.min(defaults.timeoutMs,Math.floor(proof.expiresAt-Date.now()))},undefined));
    const claim={handle,proof,rootFrame:frame};this.promotionPlanningFrames.set(frame,claim);
    try{return await this.run(frame,async()=>{const result=await fn();await this.currentPlanning(claim);return result;});}
    finally{this.states.get(frame)!.closed=true;}
  }
  private async assertPlanningRequest(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string):Promise<void>{
    const claim=this.planning(frame);if(!claim)return;
    if(method!=='GET')throw denied('PROMOTION_PLANNING_NATIVE_FORBIDDEN');
    const proof=await this.currentPlanning(claim);
    if(cluster.id!==proof.clusterId||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==proof.transportScope)throw denied('PROMOTION_PLANNING_TARGET_CHANGED');
  }
  private promotionRecovery(frame:KongExecutionFrame):PromotionRecoveryFrame|undefined{
    for(const ancestor of this.chain(frame)){const claim=this.promotionRecoveryFrames.get(ancestor);if(claim)return claim;}return undefined;
  }
  private recoveryProof(value:PromotionRecoveryReadProof):PromotionRecoveryReadProof{
    const id=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i,hex=/^[a-f\d]{64}$/;
    if(!value||!['bootstrap','read'].includes(value.mode)||!id.test(value.actor?.id??'')||!id.test(value.sessionId??'')||!id.test(value.clusterId??'')||!id.test(value.workspaceId??'')
      ||!hex.test(value.transportScope??'')||typeof value.permissionVersion!=='string'||!value.permissionVersion||!Number.isSafeInteger(value.credentialEpoch)||value.credentialEpoch<1
      ||!Number.isFinite(value.expiresAt)||value.expiresAt<=Date.now())throw denied('PROMOTION_RECOVERY_PROOF_INVALID');
    this.assertGovernanceOrigin(value.originFrame,value.actor.id,value.sessionId);
    const u='[\\da-f]{8}-[\\da-f]{4}-[1-8][\\da-f]{3}-[89ab][\\da-f]{3}-[\\da-f]{12}',cred='(?:key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)';
    const point=new RegExp(`^/(?:${ENTITIES.join('|')})/${u}$|^/upstreams/${u}/targets/${u}$|^/consumers/${u}/${cred}/${u}$`,'i');
    const collection=new RegExp(`^/consumers/${u}/${cred}$`,'i');
    const schema=new RegExp(`^/schemas/(?:${ENTITIES.join('|')}|targets|keyauth_credentials|basicauth_credentials|jwt_secrets|oauth2_credentials|hmacauth_credentials|acls)$|^/plugins/schema/[a-z][a-z0-9_-]{0,63}$`);
    const paths=(list:readonly string[],shape:RegExp):readonly string[]=>{
      if(!Array.isArray(list)||list.length>10000||new Set(list).size!==list.length||list.some(path=>typeof path!=='string'||path.length>256||!shape.test(path)))throw denied('PROMOTION_RECOVERY_PATH_INVALID');
      for(const path of list)assertKongPath('GET',path);return Object.freeze([...list].sort());
    };
    const pointPaths=paths(value.pointPaths,point),credentialCollections=paths(value.credentialCollections,collection),schemaPaths=paths(value.schemaPaths,schema);
    if(value.mode==='bootstrap'&&(pointPaths.length||credentialCollections.length||schemaPaths.length))throw denied('PROMOTION_RECOVERY_MODE_INVALID');
    return Object.freeze({...value,actor:Object.freeze({...value.actor}),pointPaths,credentialCollections,schemaPaths});
  }
  private recoveryIdentity(proof:PromotionRecoveryReadProof,paths=true):string{
    return JSON.stringify({actor:proof.actor.id,session:proof.sessionId,cluster:proof.clusterId,workspace:proof.workspaceId,transport:proof.transportScope,
      permissions:proof.permissionVersion,epoch:proof.credentialEpoch,...(paths?{mode:proof.mode,points:proof.pointPaths,collections:proof.credentialCollections,schemas:proof.schemaPaths}:{})});
  }
  private async currentRecovery(claim:PromotionRecoveryFrame):Promise<PromotionRecoveryReadProof>{
    if(!this.promotionRecoveryPolicy||Date.now()>claim.meter.deadline)throw denied('PROMOTION_RECOVERY_EXPIRED');
    const proof=this.recoveryProof(await this.storage.exit(()=>this.promotionRecoveryPolicy!.verifyHandle(claim.handle)));
    if(proof.originFrame!==claim.proof.originFrame||this.recoveryIdentity(proof)!==this.recoveryIdentity(claim.proof))throw denied('PROMOTION_RECOVERY_CHANGED');
    claim.meter.deadline=Math.min(claim.meter.deadline,proof.expiresAt);return proof;
  }
  async runPromotionRecoveryRead<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    const caller=this.current();if(!this.promotionRecoveryPolicy||!handle||typeof handle!=='object'||!caller.actor||!caller.sessionId)throw denied('PROMOTION_RECOVERY_REQUIRED');
    const proof=this.recoveryProof(await this.storage.exit(()=>this.promotionRecoveryPolicy!.verifyHandle(handle)));
    if(proof.actor.id!==caller.actor.id||proof.sessionId!==caller.sessionId)throw denied('PROMOTION_RECOVERY_IDENTITY_MISMATCH');
    let meter=this.promotionRecoveryMeters.get(handle);
    if(meter){
      if(meter.busy||Date.now()>meter.deadline||meter.proof.originFrame!==proof.originFrame||this.recoveryIdentity(meter.proof,false)!==this.recoveryIdentity(proof,false))throw denied('PROMOTION_RECOVERY_CHANGED');
      if(meter.identity!==this.recoveryIdentity(proof)){
        if(meter.proof.mode!=='bootstrap'||proof.mode!=='read'||meter.calls||meter.pages||meter.records||meter.bytes)throw denied('PROMOTION_RECOVERY_CHANGED');
        meter.identity=this.recoveryIdentity(proof);meter.proof=proof;
      }
      meter.deadline=Math.min(meter.deadline,proof.expiresAt);
    }else{meter={proof,identity:this.recoveryIdentity(proof),busy:false,calls:0,pages:0,records:0,bytes:0,deadline:Math.min(proof.expiresAt,Date.now()+defaults.timeoutMs)};this.promotionRecoveryMeters.set(handle,meter);}
    const limits={maxCalls:defaults.maxCalls-meter.calls,maxPages:defaults.maxPages-meter.pages,maxRecords:defaults.maxRecords-meter.records,maxBytes:defaults.maxBytes-meter.bytes,timeoutMs:Math.floor(meter.deadline-Date.now())};
    if(Object.values(limits).some(value=>value<1))throw denied('PROMOTION_RECOVERY_BUDGET_EXHAUSTED');meter.busy=true;
    const frame=this.storage.exit(()=>this.make({kind:'actor',actor:proof.actor,sessionId:proof.sessionId,clusterId:proof.clusterId,workspaceId:proof.workspaceId,module:'promote',action:'read',purpose:'promotion-recovery',requestId:proof.originFrame.requestId,ip:proof.originFrame.ip},limits,undefined));
    this.states.get(frame)!.deadline=meter.deadline;
    const claim:PromotionRecoveryFrame={handle,meter,proof,cursors:new Map(proof.credentialCollections.map(path=>[path,{started:false,complete:false,pending:false,seen:new Set(),ids:new Set()}]))};
    this.promotionRecoveryFrames.set(frame,claim);
    try{return await this.run(frame,async()=>{const result=await fn();
      if(proof.mode==='read'){
        if([...claim.cursors.values()].some(cursor=>!cursor.started||!cursor.complete||cursor.pending))throw denied('PROMOTION_RECOVERY_PAGINATION_INCOMPLETE');
        await this.currentRecovery(claim);
      }
      return result;
    });}finally{meter.busy=false;this.promotionRecoveryFrames.delete(frame);}
  }
  /** Planning metadata only. Counters belong to the same original opaque
   * claim and cannot be reset by a new scope or a copied DTO. */
  async promotionRecoveryUsage(handle:object):Promise<Readonly<{calls:number;pages:number;records:number;bytes:number;deadline:number}>>{
    const caller=this.current(),meter=this.promotionRecoveryMeters.get(handle);
    if(!meter||!caller.actor||caller.actor.id!==meter.proof.actor.id||caller.sessionId!==meter.proof.sessionId)throw denied('PROMOTION_RECOVERY_REQUIRED');
    await this.currentRecovery({handle,meter,proof:meter.proof,cursors:new Map()});
    return Object.freeze({calls:meter.calls,pages:meter.pages,records:meter.records,bytes:meter.bytes,deadline:meter.deadline});
  }
  async assertPromotionRecoveryRequest(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string,body:unknown,query:Record<string,string|number>):Promise<boolean>{
    const claim=this.promotionRecovery(frame);if(!claim)return false;const proof=await this.currentRecovery(claim);
    if(proof.mode!=='read'||method!=='GET'||body!==undefined||cluster.id!==proof.clusterId||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==proof.transportScope
      ||!/^1\.5\.\d+$/.test(cluster.version??'')||['disabled','incompatible'].includes(String(cluster.status)))throw denied('PROMOTION_RECOVERY_REQUEST_FORBIDDEN');
    const endpoint=new URL(cluster.admin_url).origin;if(claim.endpointOrigin&&claim.endpointOrigin!==endpoint)throw denied('PROMOTION_RECOVERY_CHANGED');claim.endpointOrigin=endpoint;
    const cursor=claim.cursors.get(path);
    if(cursor){
      const size=query.size??100;
      if(Object.keys(query).some(key=>!['size','offset'].includes(key))||typeof size!=='number'&&typeof size!=='string'||typeof size==='string'&&!/^[1-9][0-9]{0,2}$/.test(size)||!Number.isInteger(Number(size))||Number(size)<1||Number(size)>100
        ||query.offset!==undefined&&(typeof query.offset!=='string'||!query.offset||query.offset.length>8192)||query.offset!==cursor.next||cursor.complete)throw denied('PROMOTION_RECOVERY_QUERY_FORBIDDEN');
    }else if(!proof.pointPaths.includes(path)&&!proof.schemaPaths.includes(path)||Object.keys(query).length)throw denied('PROMOTION_RECOVERY_PATH_FORBIDDEN');
    this.chain(frame);return true;
  }
  private recoveryNewRequest(frame:KongExecutionFrame,path:string,query:Record<string,string|number>):void{
    const claim=this.promotionRecovery(frame);if(!claim)return;const cursor=claim.cursors.get(path);
    if(cursor?.pending)throw denied('PROMOTION_RECOVERY_PAGE_ALREADY_PENDING');if(cursor){cursor.started=true;cursor.pending=true;cursor.size=Number(query.size??100);}
    if(++claim.meter.calls>defaults.maxCalls)throw denied('PROMOTION_RECOVERY_BUDGET_EXHAUSTED');
  }
  async promotionRecoveryResponse(frame:KongExecutionFrame,path:string,result:unknown):Promise<unknown>{
    const claim=this.promotionRecovery(frame);if(!claim||!this.promotionRecoveryPolicy)throw denied('PROMOTION_RECOVERY_REQUIRED');await this.currentRecovery(claim);
    const cursor=claim.cursors.get(path),response=result as any;
    if(cursor){
      const consumer=path.split('/')[2],id=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
      if(!cursor.pending||!Array.isArray(response?.data)||response.data.length>100||response.data.some((item:any)=>!id.test(item?.id??'')||cursor.ids.has(item.id)||item.consumer?.id&&item.consumer.id!==consumer)||new Set(response.data.map((item:any)=>item.id)).size!==response.data.length)throw denied('PROMOTION_RECOVERY_RESPONSE_INVALID');
      for(const item of response.data)cursor.ids.add(item.id);
    }else if(claim.proof.pointPaths.includes(path)&&response?.id!==path.split('/').at(-1))throw denied('PROMOTION_RECOVERY_RESPONSE_INVALID');
    const records=cursor?response.data.length:claim.proof.pointPaths.includes(path)?1:0,bytes=Buffer.byteLength(JSON.stringify(result??null),'utf8');
    claim.meter.records+=records;claim.meter.bytes+=bytes;if(cursor)claim.meter.pages++;
    if(claim.meter.records>defaults.maxRecords||claim.meter.bytes>defaults.maxBytes||claim.meter.pages>defaults.maxPages)throw denied('PROMOTION_RECOVERY_BUDGET_EXHAUSTED');
    await this.storage.exit(()=>this.promotionRecoveryPolicy!.assertResponse(claim.handle,path,result));await this.currentRecovery(claim);
    if(cursor){
      if(response.next===null||response.next===undefined){cursor.complete=true;cursor.next=undefined;}
      else{
        if(typeof response.next!=='string'||response.next.length>16384)throw denied('PROMOTION_RECOVERY_CURSOR_INVALID');
        let next:URL;try{next=new URL(response.next,claim.endpointOrigin);}catch{throw denied('PROMOTION_RECOVERY_CURSOR_INVALID');}
        const offset=next.searchParams.get('offset');
        const sizes=next.searchParams.getAll('size');
        if(next.origin!==claim.endpointOrigin||next.username||next.password||next.pathname!==path||next.hash||next.searchParams.getAll('offset').length!==1||sizes.length>1||sizes.length===1&&Number(sizes[0])!==cursor.size||[...next.searchParams.keys()].some(key=>!['size','offset'].includes(key))||!offset||offset.length>8192||cursor.seen.has(offset))throw denied('PROMOTION_RECOVERY_CURSOR_INVALID');
        cursor.seen.add(offset);cursor.next=offset;
      }cursor.pending=false;
    }
    return result;
  }
  /** Liveness only; a frame cannot mint a governance capability. */
  assertGovernanceOrigin(frame:KongExecutionFrame,actorId:string,sessionId:string):void{
    if(!['http','actor'].includes(frame.kind)||frame.actor?.id!==actorId||frame.sessionId!==sessionId||frame.operation||frame.archive)throw denied('GOVERNANCE_ORIGIN_INVALID');
    this.chain(frame);
  }
  private governanceRead(frame:KongExecutionFrame){for(const ancestor of this.chain(frame)){const claim=this.governanceReads.get(ancestor);if(claim)return claim;}return undefined;}
  async runGovernanceRead<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    const caller=this.storage.getStore();if(caller&&this.workflowValidationRead(caller))throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY');
    if(!this.governanceReadPolicy)throw unavailable();
    const {proof,limits}=await this.storage.exit(()=>this.governanceReadPolicy!.startRead(handle));
    let frame:KongExecutionFrame|undefined;
    try{
      if(!proof.actor?.id||!proof.clusterId||!proof.workspaceId||!proof.transportScope||proof.expiresAt<=Date.now()||!['http','timer'].includes(proof.origin)||proof.origin==='http'&&!proof.sessionId||proof.origin==='timer'&&proof.sessionId)throw denied('GOVERNANCE_READ_INVALID');
      frame=this.storage.exit(()=>this.make({kind:'actor',actor:Object.freeze({...proof.actor}),sessionId:proof.sessionId,clusterId:proof.clusterId,workspaceId:proof.workspaceId,module:proof.module,action:'read',purpose:'governance'},limits,undefined));
      this.states.get(frame)!.deadline=Math.min(this.states.get(frame)!.deadline,proof.expiresAt);
      this.governanceReads.set(frame,{handle,proof:Object.freeze({...proof,rootIds:Object.freeze([...proof.rootIds])})});
      return await this.run(frame,fn);
    }finally{
      const state=frame?this.states.get(frame):undefined;
      this.governanceReadPolicy.endRead(handle,{calls:state?.calls??0,pages:state?.pages??0,records:state?.records??0,bytes:state?.bytes??0});
      if(frame)this.governanceReads.delete(frame);
    }
  }
  async assertGovernanceRequest(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string,body:unknown,query:Record<string,string|number>):Promise<boolean>{
    const claim=this.governanceRead(frame);if(!claim)return false;if(!this.governanceReadPolicy)throw unavailable();
    const current=await this.storage.exit(()=>this.governanceReadPolicy!.verifyHandle(claim.handle));
    if(JSON.stringify(current)!==JSON.stringify(claim.proof)||cluster.id!==current.clusterId||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==current.transportScope||method!=='GET'||body!==undefined)throw denied('GOVERNANCE_READ_CHANGED');
    const uuid='[\\da-f]{8}-[\\da-f]{4}-[1-8][\\da-f]{3}-[89ab][\\da-f]{3}-[\\da-f]{12}';
    const allowed=new RegExp(`^/$|^/plugins/enabled$|^/schemas/(?:${[...ENTITIES,'targets'].join('|')})$|^/plugins/schema/[a-z][a-z0-9_-]{0,63}$|^/(?:${ENTITIES.join('|')})(?:/${uuid})?$|^/upstreams/${uuid}/targets$|^/services/${uuid}/routes$`,'i');
    if(!allowed.test(path))throw denied('GOVERNANCE_READ_PATH_FORBIDDEN');
    const collection=new RegExp(`^/(?:${ENTITIES.join('|')})$|^/upstreams/${uuid}/targets$|^/services/${uuid}/routes$`,'i').test(path);
    if(collection?Object.keys(query).some(key=>!['size','offset','tags'].includes(key))||!Number.isInteger(Number(query.size??100))||Number(query.size??100)<1||Number(query.size??100)>100:Object.keys(query).length)throw denied('GOVERNANCE_READ_QUERY_FORBIDDEN');
    this.chain(frame);return true;
  }
  async governanceResponse(frame:KongExecutionFrame,path:string,result:any):Promise<any>{
    const claim=this.governanceRead(frame);if(!claim||!this.governanceReadPolicy)throw denied('GOVERNANCE_READ_REQUIRED');
    await this.storage.exit(()=>this.governanceReadPolicy!.verifyHandle(claim.handle));
    // Authorization's private parent lookup remains a raw server-only read;
    // its caller proves the real object before exposing any configuration.
    return frame.purpose==='authorization'?result:this.governanceReadPolicy.filterResponse(claim.handle,path,result);
  }
  async assertGovernanceBeforeSend(ticket:KongPolicyTicket):Promise<void>{
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!;
    await this.assertPlanningRequest(state.frame,state.cluster,state.method);
    if(this.governanceRead(state.frame))await this.assertGovernanceRequest(state.frame,state.cluster,state.method,state.path,state.body,state.query);
    if(this.promotionRecovery(state.frame))await this.assertPromotionRecoveryRequest(state.frame,state.cluster,state.method,state.path,state.body,state.query);
    this.assertTicketActive(ticket);
  }
  private toolboxOperation(frame:KongExecutionFrame){for(const ancestor of this.chain(frame)){const claim=this.toolboxOperations.get(ancestor);if(claim)return claim;}return undefined;}
  async runToolboxOperation<T>(handle:object,fn:()=>Promise<T>):Promise<T>{
    const parent=this.current();if(!this.toolboxOperationPolicy||!parent.actor||!parent.sessionId||parent.operation||parent.archive||this.recovery(parent))throw denied('TOOLBOX_OPERATION_REQUIRED');
    const proof=await this.toolboxOperationPolicy.verifyHandle(handle);
    if(proof.actorId!==parent.actor.id||proof.sessionId!==parent.sessionId||proof.clusterId!==parent.clusterId||proof.workspaceId!==parent.workspaceId||!/^\/cache\/[A-Za-z0-9_.:%-]+$/.test(proof.canonicalPath)||proof.expiresAt<=Date.now())throw denied('TOOLBOX_OPERATION_SCOPE_MISMATCH');
    const frame=this.make({...parent,kind:'actor',module:'toolbox',action:'write'}, {maxCalls:8,maxBytes:524288,timeoutMs:10000},parent);
    this.toolboxOperations.set(frame,{handle,proof:Object.freeze({...proof})});try{return await this.run(frame,fn);}finally{this.toolboxOperations.delete(frame);}
  }
  async assertToolboxRequest(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string,body:unknown,query:Record<string,string|number>,beforeSend=false):Promise<boolean>{
    const claim=this.toolboxOperation(frame);if(!claim)return false;if(!this.toolboxOperationPolicy)throw unavailable();
    const proof=await this.toolboxOperationPolicy.verifyHandle(claim.handle);
    if(JSON.stringify(proof)!==JSON.stringify(claim.proof)||method!=='DELETE'||path!==proof.canonicalPath||body!==undefined||Object.keys(query).length||cluster.id!==proof.clusterId||cluster.execution_mode!==proof.executionMode||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==proof.transportScope||proof.expiresAt<=Date.now())throw denied('TOOLBOX_OPERATION_CHANGED');
    if(proof.executionMode==='approval'){
      const step=this.currentApprovedStep();if(!this.approvedPolicy||step.kind!=='metadata'||step.stepId!==proof.workflowStepId||step.execution.executionId!==proof.workflowExecutionId)throw denied('TOOLBOX_APPROVED_STEP_REQUIRED');
      const current=await this.approvedPolicy.verifyStep(step.execution,step.stepId);if(current.kind!=='metadata'||current.stepId!==proof.workflowStepId||current.execution.executionId!==proof.workflowExecutionId)throw denied('TOOLBOX_APPROVED_STEP_REQUIRED');
    }
    if(beforeSend)await this.toolboxOperationPolicy.beforeSend(claim.handle);this.chain(frame);return true;
  }
  private configurationJob(frame: KongExecutionFrame): { handle: object; proof: Readonly<ConfigurationJobExecutionProof> } | undefined {
    for (const ancestor of this.chain(frame)) { const claim = this.configurationJobs.get(ancestor); if (claim) return claim; }
    return undefined;
  }
  /** A detached ordinary durable job can start after its HTTP caller closes.
   * Only a real private scheduled/read marker contributes an ancestor fence;
   * never validate an unrelated closed HTTP chain before fresh job authority. */
  private hasLinkedFrame(frame:KongExecutionFrame,contains:(ancestor:KongExecutionFrame)=>boolean):boolean{
    for(let ancestor:KongExecutionFrame|undefined=frame;ancestor;ancestor=this.states.get(ancestor)?.parent){
      if(contains(ancestor)){this.chain(frame);return true;}
    }
    return false;
  }
  private validateConfigurationJob(proof: ConfigurationJobExecutionProof, scheduled=false): void {
    const id = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
    if (!proof?.actor || !id.test(proof.actor.id) || !id.test(proof.clusterId) || !id.test(proof.workspaceId) || !id.test(proof.jobId)
      || typeof proof.module !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(proof.module) || typeof proof.permissionVersion !== 'string' || !proof.permissionVersion
      || !Number.isSafeInteger(proof.credentialEpoch) || proof.credentialEpoch < 1 || !Number.isSafeInteger(proof.leaseGeneration) || proof.leaseGeneration < 1
      || !Number.isFinite(proof.expiresAt) || proof.expiresAt <= Date.now() || typeof proof.readOnly !== 'boolean'
      || !['capture', 'compare', 'export', 'import', 'apply', 'rollback'].includes(proof.purpose)
      || proof.sessionId != null && !id.test(proof.sessionId)
      || (!proof.sessionId && !scheduled || ['capture', 'compare', 'export'].includes(proof.purpose)) && !proof.readOnly
      || ['apply', 'rollback'].includes(proof.purpose) && proof.readOnly) throw denied('CONFIGURATION_JOB_AUTHORITY_INVALID');
    if(scheduled&& (proof.origin!=='workflow-scheduled-configuration'||proof.sessionId!==null||proof.readOnly||proof.module!=='snapshots'
      ||!['apply','rollback'].includes(proof.purpose)||!proof.namespaceHandle||!proof.originalScheduledJobHandle
      ||![proof.claimId,proof.wrapperOriginId,proof.wrapperExecutionId,proof.planId].every(value=>typeof value==='string'&&id.test(value))
      ||!Number.isSafeInteger(proof.planRevision)||proof.planRevision!<1||!(/^[a-f\d]{64}$/.test(proof.planHash??''))
      ||!(/^[a-f\d]{64}$/.test(proof.subjectSealHmac??''))))throw denied('CONFIGURATION_JOB_AUTHORITY_INVALID');
    if(!scheduled&&proof.origin!==undefined)throw denied('CONFIGURATION_JOB_AUTHORITY_INVALID');
  }
  private assertScheduledConfigurationProof(frame:KongExecutionFrame,proof:ConfigurationJobExecutionProof):void{
    const namespace=this.workflowScheduledNamespace(frame),wrapper=this.executionProof(frame);
    if(!namespace||proof.namespaceHandle!==namespace.handle||namespace.proof.kind!=='configuration_v2'||frame.sessionId!=null
      ||frame.actor?.id!==namespace.proof.actor.id||proof.actor.id!==namespace.proof.actor.id||proof.clusterId!==namespace.proof.clusterId
      ||proof.workspaceId!==namespace.proof.workspaceId||proof.claimId!==namespace.proof.claim.id||proof.permissionVersion!==namespace.proof.permissionVersion
      ||proof.expiresAt>Date.parse(namespace.proof.expiresAt)||proof.subjectSealHmac!==namespace.proof.subjectSealHmac
      ||!wrapper||!['scheduled-workflow','scheduled-configuration'].includes(wrapper.origin??'')||wrapper.workflowId!==namespace.proof.workflow.id
      ||wrapper.actorId!==proof.actor.id||wrapper.scheduleClaimId!==proof.claimId||wrapper.workflowOriginId!==proof.wrapperOriginId
      ||wrapper.origin==='scheduled-workflow'&&wrapper.executionId!==proof.wrapperExecutionId)throw denied('CONFIGURATION_SCHEDULED_JOB_SCOPE_MISMATCH');
    this.validateConfigurationJob(proof,true);
  }
  /** Starts from a freshly verified private job handle, with no copied HTTP
   * frame or parent. An inherited closed ALS frame contributes no authority. */
  async runConfigurationJob<T>(handle: object, fn: () => Promise<T>): Promise<T> {
    if (!handle || !this.configurationJobPolicy) throw unavailable();
    const caller=this.storage.getStore(),planning=caller?this.planning(caller):undefined;
    if(caller&&this.hasLinkedFrame(caller,frame=>this.workflowCandidateReads.has(frame)))throw denied('WORKFLOW_CANDIDATE_JOB_ADOPTION_FORBIDDEN');
    if(caller&&this.hasLinkedFrame(caller,frame=>this.workflowValidationReads.has(frame)))throw denied('WORKFLOW_SCHEDULE_VALIDATION_JOB_ADOPTION_FORBIDDEN');
    const namespace=caller&&this.hasLinkedFrame(caller,frame=>this.workflowScheduledNamespaces.has(frame))?this.workflowScheduledNamespace(caller):undefined;
    if(namespace){
      if(!caller||caller.operation||caller.archive||this.configurationJob(caller))throw denied('CONFIGURATION_SCHEDULED_JOB_CONTEXT_INVALID');
      const proof=await this.configurationJobPolicy.verifyHandle(handle);this.chain(caller);this.assertScheduledConfigurationProof(caller,proof);
      const immutable=Object.freeze({...proof,actor:Object.freeze({...proof.actor})});
      const frame=this.make({kind:'actor',actor:immutable.actor,clusterId:immutable.clusterId,workspaceId:immutable.workspaceId,module:immutable.module,
        action:'write',purpose:'configuration',requestId:immutable.requestId,ip:immutable.ip,idempotencyKey:immutable.idempotencyKey},{},caller,undefined,true);
      this.states.get(frame)!.deadline=Math.min(this.states.get(frame)!.deadline,immutable.expiresAt);
      this.configurationJobs.set(frame,{handle,proof:immutable});
      try{return await this.run(frame,fn);}finally{this.configurationJobs.delete(frame);}
    }
    const proof = await this.storage.exit(() => this.configurationJobPolicy!.verifyHandle(handle));
    this.validateConfigurationJob(proof);
    if(planning){
      const current=await this.currentPlanning(planning);
      if(!proof.readOnly)throw denied('PROMOTION_PLANNING_NATIVE_FORBIDDEN');
      if(proof.actor.id!==current.actor.id||proof.sessionId!==current.sessionId||proof.clusterId!==current.clusterId||proof.workspaceId!==current.workspaceId)
        throw denied('PROMOTION_PLANNING_IDENTITY_MISMATCH');
    }
    const immutable = Object.freeze({ ...proof, actor: Object.freeze({ ...proof.actor }) });
    const frame = this.storage.exit(() => this.make({ kind: 'actor', actor: immutable.actor, sessionId: immutable.sessionId ?? undefined, clusterId: immutable.clusterId,
      workspaceId: immutable.workspaceId, module: immutable.module, action: immutable.readOnly ? 'read' : 'write',
      requestId: immutable.requestId, ip: immutable.ip, idempotencyKey: immutable.idempotencyKey, purpose: 'configuration' }, {}, planning?.rootFrame));
    this.states.get(frame)!.deadline = Math.min(this.states.get(frame)!.deadline, immutable.expiresAt);
    this.configurationJobs.set(frame, { handle, proof: immutable });
    try { return await this.run(frame, fn); } finally { this.configurationJobs.delete(frame); }
  }
  private async assertConfigurationJob(frame: KongExecutionFrame, write: boolean): Promise<void> {
    const claim = this.configurationJob(frame); if (!claim) return;
    if (!this.configurationJobPolicy || write && claim.proof.readOnly) throw denied('CONFIGURATION_JOB_READ_ONLY');
    const current = await this.configurationJobPolicy.verifyHandle(claim.handle); this.chain(frame);
    if(claim.proof.origin==='workflow-scheduled-configuration')this.assertScheduledConfigurationProof(frame,current);else this.validateConfigurationJob(current);
    if (current.actor.id !== claim.proof.actor.id || ['sessionId', 'clusterId', 'workspaceId', 'module', 'purpose', 'jobId', 'permissionVersion', 'credentialEpoch', 'leaseGeneration', 'expiresAt', 'readOnly', 'requestId', 'ip', 'idempotencyKey']
      .some(key => (current as any)[key] !== (claim.proof as any)[key])) throw denied('CONFIGURATION_JOB_AUTHORITY_CHANGED');
    if(claim.proof.origin==='workflow-scheduled-configuration'&&['origin','namespaceHandle','claimId','wrapperOriginId','wrapperExecutionId','planId','planRevision','planHash','subjectSealHmac','originalScheduledJobHandle']
      .some(key=>(current as any)[key]!==(claim.proof as any)[key]))throw denied('CONFIGURATION_JOB_AUTHORITY_CHANGED');
  }
  private executionProof(frame = this.current()): ApprovedExecutionProof | null {
    for (const ancestor of this.chain(frame)) { const claim = this.approvedExecutions.get(ancestor); if (claim) return claim; }
    return null;
  }
  /** Read-only original ancestry. No handle is issued and no authorization is
   * performed here; every provider must still verify its current SQL facts.
   * In particular an execution container is distinct from a Native step. */
  originalScheduledPortalExecution():Readonly<{execution:ApprovedExecutionProof;step:ApprovedStepProof|null}>|null{
    const frame=this.storage.getStore();if(!frame)return null;
    const chain=this.chain(frame),namespace=this.workflowScheduledNamespace(frame),execution=this.executionProof(frame);
    if(!namespace||namespace.proof.kind!=='portal-credential-issue'||namespace.proof.origin!=='scheduled-workflow'
      ||namespace.proof.sessionId!==null||frame.sessionId!=null||this.workflowValidationRead(frame)||this.workflowCandidateRead(frame)
      ||this.configurationJob(frame)||chain.some(ancestor=>this.scheduledConfigurationBoundaries.has(ancestor))
      ||!execution||execution.origin!=='scheduled-workflow'||execution.sessionId!==null
      ||frame.actor?.id!==namespace.proof.actor.id||execution.actorId!==namespace.proof.actor.id
      ||frame.clusterId!==namespace.proof.clusterId||frame.workspaceId!==namespace.proof.workspaceId
      ||execution.clusterId!==namespace.proof.clusterId||execution.workspaceId!==namespace.proof.workspaceId
      ||execution.workflowId!==namespace.proof.workflow.id||execution.scheduleClaimId!==namespace.proof.claim.id
      ||execution.permissionVersion!==namespace.proof.permissionVersion||!Number.isFinite(execution.expiresAt)
      ||execution.expiresAt<=Date.now()||execution.expiresAt>Date.parse(namespace.proof.expiresAt))return null;
    let step:ApprovedStepProof|null=null;for(const ancestor of chain){const original=this.approvedSteps.get(ancestor);if(original){step=original;break;}}
    if(step&&step.execution!==execution)return null;
    return Object.freeze({execution,step});
  }
  currentApprovedStep(): ApprovedStepProof {
    const frame = this.current();
    for (const ancestor of this.chain(frame)) { const step = this.approvedSteps.get(ancestor); if (step) return step;if(this.scheduledConfigurationBoundaries.has(ancestor))break; }
    throw denied('APPROVED_STEP_REQUIRED');
  }
  private optionalApprovedStep(frame = this.current()): ApprovedStepProof | null {
    for (const ancestor of this.chain(frame)) { const step = this.approvedSteps.get(ancestor); if (step) return step;if(this.scheduledConfigurationBoundaries.has(ancestor))break; }
    if (this.executionProof(frame)) throw denied('APPROVED_STEP_REQUIRED');
    return null;
  }
  private recovery(frame = this.current()): { handle: IssueActivationRecoveryHandle; proof: IssueActivationRecoveryProof } | null {
    for (const ancestor of this.chain(frame)) { const claim = this.issueRecoveries.get(ancestor); if (claim) return claim; }
    return null;
  }
  private forbidRecoveryNative(frame = this.current()): void {
    if (this.recovery(frame)) throw denied('PORTAL_RECOVERY_NATIVE_FORBIDDEN');
    if (this.planning(frame)) throw denied('PROMOTION_PLANNING_NATIVE_FORBIDDEN');
  }
  async runIssueActivationRecovery<T>(handle: IssueActivationRecoveryHandle, fn: () => Promise<T>): Promise<T> {
    const parent = this.current();
    if (!this.approvedPolicy?.verifyIssueActivationRecovery) throw unavailable();
    if (!parent.actor || !parent.sessionId || parent.operation || parent.archive || this.executionProof(parent) || this.recovery(parent)) throw denied('PORTAL_RECOVERY_CONTEXT_INVALID');
    const proof = await this.approvedPolicy.verifyIssueActivationRecovery(handle); this.chain(parent);
    if (proof.actorId !== parent.actor.id || proof.sessionId !== parent.sessionId || parent.clusterId && parent.clusterId !== proof.clusterId
      || parent.workspaceId && parent.workspaceId !== proof.workspaceId || !Number.isFinite(proof.expiresAt) || proof.expiresAt <= Date.now()) throw denied('PORTAL_RECOVERY_SCOPE_MISMATCH');
    const frame = this.make({ ...parent, kind: 'actor', clusterId: proof.clusterId, workspaceId: proof.workspaceId }, {}, parent);
    this.issueRecoveries.set(frame, { handle, proof: Object.freeze({ ...proof }) });
    try { return await this.run(frame, fn); } finally { this.issueRecoveries.delete(frame); }
  }
  async currentIssueActivationRecovery(): Promise<IssueActivationRecoveryProof> {
    const frame = this.current(), claim = this.recovery(frame);
    if (!claim || !this.approvedPolicy?.verifyIssueActivationRecovery) throw denied('PORTAL_RECOVERY_REQUIRED');
    const proof = await this.approvedPolicy.verifyIssueActivationRecovery(claim.handle); this.chain(frame);
    const original = claim.proof;
    if (proof.executionId !== original.executionId || proof.workflowId !== original.workflowId || proof.stepId !== original.stepId
      || proof.clusterId !== original.clusterId || proof.workspaceId !== original.workspaceId || proof.transportScope !== original.transportScope
      || proof.actorId !== original.actorId || proof.sessionId !== original.sessionId || proof.permissionVersion !== original.permissionVersion
      || proof.expiresAt !== original.expiresAt || proof.expiresAt <= Date.now() || frame.actor?.id !== proof.actorId || frame.sessionId !== proof.sessionId
      || frame.clusterId !== proof.clusterId || frame.workspaceId !== proof.workspaceId) throw denied('PORTAL_RECOVERY_SCOPE_MISMATCH');
    return proof;
  }
  async assertPortalRecoveryBoundaryRead(frame: KongExecutionFrame): Promise<void> {
    const claim = this.recovery(frame), handle = this.issueRecoveryReads.get(frame);
    if (!claim || !handle || handle !== claim.handle || frame.kind !== 'internal-read' || frame.purpose !== 'portal-recovery-boundary'
      || frame.operation || frame.archive || !this.chain(this.current()).includes(frame)) throw denied('PORTAL_RECOVERY_READ_REQUIRED');
    const proof = await this.currentIssueActivationRecovery();
    if (frame.actor?.id !== proof.actorId || frame.sessionId !== proof.sessionId || frame.clusterId !== proof.clusterId || frame.workspaceId !== proof.workspaceId) throw denied('PORTAL_RECOVERY_SCOPE_MISMATCH');
  }
  async runPortalRecoveryBoundaryRead<T>(paths: readonly string[], fn: () => Promise<T>, limits: Omit<KongReadLimits, 'paths' | 'workspaceId'> = {}): Promise<T> {
    const parent = this.current(), claim = this.recovery(parent), proof = await this.currentIssueActivationRecovery();
    if (!claim || !Array.isArray(paths) || !paths.length || paths.length > 128) throw denied('PORTAL_RECOVERY_PATH_INVALID');
    const id = '[\\da-f]{8}-[\\da-f]{4}-[1-8][\\da-f]{3}-[89ab][\\da-f]{3}-[\\da-f]{12}';
    const allowed = new RegExp(`^/(?:services|routes|plugins)(?:/${id})?$|^/consumers/${id}(?:/acls(?:/${id})?|/key-auth/${id})?$`, 'i');
    if (paths.some(path => typeof path !== 'string' || !allowed.test(path))) throw denied('PORTAL_RECOVERY_PATH_INVALID');
    const frame = this.make({ kind: 'internal-read', purpose: 'portal-recovery-boundary', actor: parent.actor, sessionId: parent.sessionId,
      clusterId: proof.clusterId, workspaceId: proof.workspaceId, requestId: parent.requestId, ip: parent.ip, idempotencyKey: parent.idempotencyKey,
      module: parent.module, action: parent.action }, { maxCalls: 250, ...limits, paths }, parent);
    this.issueRecoveryReads.set(frame, claim.handle);
    try { return await this.run(frame, fn); } finally { this.issueRecoveryReads.delete(frame); }
  }
  async runApprovedWorkflow<T>(handle: ApprovedExecutionHandle, fn: () => Promise<T>): Promise<T> {
    this.forbidRecoveryNative();
    if (!this.approvedPolicy) throw unavailable();
    const parent = this.current();
    const scheduled=this.workflowScheduledNamespace(parent);
    if(this.workflowValidationRead(parent)||this.workflowCandidateRead(parent)||!parent.actor||(!parent.sessionId&&!scheduled)||parent.operation||parent.archive||this.executionProof(parent))throw denied('APPROVED_EXECUTION_CONTEXT_INVALID');
    const proof = await this.approvedPolicy.verifyExecution(handle); this.chain(parent);
    if(scheduled){
      if(parent.sessionId!=null||scheduled.proof.actor.id!==parent.actor.id||proof.origin!=='scheduled-workflow'||proof.sessionId!==null
        ||proof.actorId!==scheduled.proof.actor.id||proof.clusterId!==scheduled.proof.clusterId||proof.workspaceId!==scheduled.proof.workspaceId
        ||proof.workflowId!==scheduled.proof.workflow.id||proof.scheduleClaimId!==scheduled.proof.claim.id
        ||proof.permissionVersion!==scheduled.proof.permissionVersion||proof.expiresAt>Date.parse(scheduled.proof.expiresAt))throw denied('APPROVED_EXECUTION_SCOPE_MISMATCH');
      if(!this.approvedPolicy.verifyWorkflowScheduledExecution)throw denied('WORKFLOW_SCHEDULE_APPROVED_POLICY_UNAVAILABLE');
      await this.approvedPolicy.verifyWorkflowScheduledExecution(proof,scheduled.handle);this.chain(parent);
    }else if(proof.origin!==undefined||typeof proof.sessionId!=='string'||proof.sessionId!==parent.sessionId)throw denied('APPROVED_EXECUTION_SCOPE_MISMATCH');
    if (proof.actorId !== parent.actor.id || parent.clusterId && parent.clusterId !== proof.clusterId || parent.workspaceId && parent.workspaceId !== proof.workspaceId
      ||!Number.isFinite(proof.expiresAt)||proof.expiresAt <= Date.now()) throw denied('APPROVED_EXECUTION_SCOPE_MISMATCH');
    const frame = this.make({ ...parent, kind: 'actor', clusterId: proof.clusterId, workspaceId: proof.workspaceId }, {}, parent,undefined,!!scheduled);
    if(scheduled)this.states.get(frame)!.deadline=Math.min(this.states.get(frame)!.deadline,proof.expiresAt);
    this.approvedExecutions.set(frame, proof);
    return this.run(frame, fn);
  }
  /** Genuine nested V2 execution only. Keeps the real scheduled job/Namespace
   * ancestors and shadows the enclosing metadata step without lending its
   * V1 Native authority to configuration mutations. */
  async runApprovedScheduledConfigurationWorkflow<T>(handle:ApprovedExecutionHandle, originalJobHandle:WorkflowScheduledConfigurationJobHandle, fn:()=>Promise<T>):Promise<T>{
    const parent=this.current(),namespace=this.workflowScheduledNamespace(parent),job=this.configurationJob(parent),wrapper=this.executionProof(parent),step=this.optionalApprovedStep(parent);
    if(!this.approvedPolicy?.verifyWorkflowScheduledConfigurationExecution||!namespace||!job||job.proof.origin!=='workflow-scheduled-configuration'
      ||job.proof.originalScheduledJobHandle!==originalJobHandle||this.workflowValidationRead(parent)||this.workflowCandidateRead(parent)
      ||parent.operation||parent.archive||parent.sessionId!=null||!wrapper||wrapper.origin!=='scheduled-workflow'
      ||wrapper.executionId!==job.proof.wrapperExecutionId||wrapper.workflowOriginId!==job.proof.wrapperOriginId
      ||!step||step.kind!=='metadata'||step.execution!==wrapper)throw denied('CONFIGURATION_SCHEDULED_NESTED_CONTEXT_REQUIRED');
    await this.assertConfigurationJob(parent,true);
    const proof=await this.approvedPolicy.verifyExecution(handle);this.chain(parent);
    if(proof.origin!=='scheduled-configuration'||proof.sessionId!==null||proof.executionId===wrapper.executionId
      ||proof.workflowId!==wrapper.workflowId||proof.actorId!==namespace.proof.actor.id||proof.clusterId!==namespace.proof.clusterId
      ||proof.workspaceId!==namespace.proof.workspaceId||proof.scheduleClaimId!==namespace.proof.claim.id
      ||proof.workflowOriginId!==wrapper.workflowOriginId||typeof proof.configurationOriginId!=='string'
      ||proof.permissionVersion!==job.proof.permissionVersion||!Number.isFinite(proof.expiresAt)||proof.expiresAt<=Date.now()
      ||proof.expiresAt>job.proof.expiresAt)throw denied('CONFIGURATION_SCHEDULED_NESTED_SCOPE_MISMATCH');
    await this.approvedPolicy.verifyWorkflowScheduledConfigurationExecution(proof,namespace.handle,originalJobHandle);this.chain(parent);
    const frame=this.make({...parent,kind:'actor'},{},parent,undefined,true);this.states.get(frame)!.deadline=Math.min(this.states.get(frame)!.deadline,proof.expiresAt);
    this.approvedExecutions.set(frame,proof);this.scheduledConfigurationBoundaries.add(frame);
    try{return await this.run(frame,fn);}finally{this.scheduledConfigurationBoundaries.delete(frame);this.approvedExecutions.delete(frame);}
  }
  async runApprovedStep<T>(stepId: string, fn: () => Promise<T>): Promise<T> {
    this.forbidRecoveryNative();
    const parent = this.current(), proof = this.executionProof(parent);
    let activeStep=false;for(const ancestor of this.chain(parent)){if(this.approvedSteps.has(ancestor)){activeStep=true;break;}if(this.scheduledConfigurationBoundaries.has(ancestor))break;}
    if (!proof || !this.approvedPolicy || activeStep) throw denied('APPROVED_STEP_REQUIRED');
    const step = await this.approvedPolicy.verifyStep(proof, stepId); this.chain(parent);
    const frame = this.make({ ...parent, kind: 'actor' }, {}, parent,undefined,!!this.workflowScheduledNamespace(parent)); this.approvedSteps.set(frame, step);
    return this.run(frame, fn);
  }
  async approvedMutationBinding(context: Readonly<MutationContext>): Promise<ApprovedMutationBinding | null> {
    this.forbidRecoveryNative();
    const frame = this.current(),entity=this.entityChangePacket(frame);
    if(entity){if(!this.entityChangePolicy)throw unavailable();return this.entityChangePolicy.mutationBinding(entity.handle,context);}
    const step = this.optionalApprovedStep(frame);
    if (!step) return null;
    if (!this.approvedPolicy || step.kind !== 'native') throw denied('APPROVED_NATIVE_STEP_REQUIRED');
    const binding = await this.configurationMutationBinding(context,step); this.chain(frame); return binding;
  }
  /** Pre-INSERT local binding only. This fixed invocation never accepts a
   * business callback, transaction DTO, Native packet or caller phase flag.
   * Each canonical issuer still opens/closes its own SQL verification window
   * against its original transaction object; this stage is neither a SQL
   * witness nor permission to send a request. */
  private async configurationMutationBinding(context:Readonly<MutationContext>,step:ApprovedStepProof):Promise<ApprovedMutationBinding>{
    const frame=this.current(),policy=this.approvedPolicy!,budget=this.configurationMutationActors.get(frame),outer=this.sqlPreparations.getStore();
    // Reject before every fallback: a copied context or changed operation ID
    // must not borrow an outer binding invocation's SQL-only observations.
    if(outer?.active&&outer.proof.stage==='mutation-binding')throw denied('CONFIGURATION_MUTATION_BINDING_SQL_REENTRANT');
    if(!budget||budget.context!==context||budget.operationId!==undefined||budget.operationEntered||frame.operation||context.operationId!=null
      ||this.finalNativeStages.getStore()?.active)return policy.mutationBinding(step,context);
    this.assertConfigurationMutationActor(budget);
    if(step!==budget.step||this.sqlPreparations.getStore()?.active)throw denied('CONFIGURATION_MUTATION_BINDING_SQL_REENTRANT');
    const namespace=this.workflowScheduledNamespace(frame),job=this.configurationJob(frame);
    if(!namespace||!job||!job.proof.originalScheduledJobHandle||namespace.proof.kind!=='configuration_v2'||namespace.proof.approvalSet?.format!==2
      ||!this.workflowScheduledPolicy?.verifySqlPreparation)return policy.mutationBinding(step,context);
    const proof:Readonly<ConfigurationSqlPreparation>=Object.freeze({stage:'mutation-binding',frame,operation:undefined,namespaceHandle:namespace.handle,namespace:namespace.proof,
      originalJobHandle:job.proof.originalScheduledJobHandle,execution:budget.execution,step});
    const scope:ConfigurationSqlPreparationState={active:true,deadline:Infinity,proof,packet:canonicalJson({...context,actor:context.actor.id,operationId:null}),
      binding:Object.freeze({policy,context})};
    try{const result=await this.sqlPreparations.run(scope,async()=>{
      this.scheduledConfigurationPreparationPhase();const binding=await policy.mutationBinding(step,context);this.scheduledConfigurationPreparationPhase();
      if(!binding||!('version'in binding)||binding.version!==2||binding.configurationJobId!==job.proof.jobId
        ||binding.configurationExecutionId!==budget.execution.executionId||binding.configurationStepId!==step.stepId||binding.workflowId!==budget.execution.workflowId
        ||binding.configurationPlanRevision!==job.proof.planRevision||binding.configurationPlanHash!==job.proof.planHash)
        throw denied('CONFIGURATION_MUTATION_BINDING_SQL_RESULT_INVALID');
      const current=await this.workflowScheduledPolicy!.verifySqlPreparation!(namespace.handle,'packet');
      if(this.scheduledConfigurationPreparationPhase()!==proof||current!==namespace.proof)throw denied('CONFIGURATION_MUTATION_BINDING_SQL_CONTEXT_CHANGED');
      if(!Number.isFinite(scope.deadline))throw denied('CONFIGURATION_MUTATION_BINDING_SQL_CLOSING_REQUIRED');
      return binding;
    });
      // The ALS callback and this method have distinct Promise continuations.
      // Recheck the same original invocation after the final awaited return.
      this.sqlPreparations.run(scope,()=>{if(this.scheduledConfigurationPreparationPhase()!==proof)throw denied('CONFIGURATION_MUTATION_BINDING_SQL_CONTEXT_CHANGED');});
      return result;
    }finally{scope.active=false;}
  }
  async bindApprovedOperation(context: Readonly<MutationContext>, binding: ApprovedMutationBinding, operationId: string, tx: DbService): Promise<void> {
    this.forbidRecoveryNative();
    const frame=this.current(),entity=this.entityChangePacket(frame);
    if(entity){if(!this.entityChangePolicy||!('version'in binding)||binding.version!==3)throw denied('ENTITY_CHANGE_BINDING_INVALID');await this.entityChangePolicy.bindOperation(entity.handle,context,binding as ApprovedMutationBindingV3,operationId,tx);this.chain(frame);return;}
    if('version'in binding&&binding.version===3)throw denied('ENTITY_CHANGE_PACKET_REQUIRED');
    const step = this.currentApprovedStep();
    if (!this.approvedPolicy || step.kind !== 'native') throw denied('APPROVED_NATIVE_STEP_REQUIRED');
    await this.approvedPolicy.bindOperation(step, context, binding, operationId, tx); this.chain(frame);
    const budget=this.configurationMutationActors.get(frame);
    if(budget){
      this.assertConfigurationMutationActor(budget);
      if(context!==budget.context||!('version'in binding)||binding.version!==2||binding.workflowId!==budget.execution.workflowId
        ||binding.configurationJobId!==budget.job.proof.jobId||binding.configurationExecutionId!==budget.execution.executionId
        ||binding.configurationStepId!==budget.step.stepId||binding.configurationPlanRevision!==budget.job.proof.planRevision
        ||binding.configurationPlanHash!==budget.job.proof.planHash||budget.operationId!==undefined)
        throw denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH');
      budget.operationId=operationId;budget.binding=binding;budget.transaction=tx;
    }
  }
  async assertApprovedMetadataStep(input: Readonly<ApprovedMetadataInput>, tx: DbService): Promise<void> {
    const frame = this.current(), step = this.currentApprovedStep();
    if (!this.approvedPolicy || step.kind !== 'metadata') throw denied('APPROVED_METADATA_STEP_REQUIRED');
    await this.approvedPolicy.assertMetadata(step, input, tx); this.chain(frame);
  }
  async assertApprovedNativeRequest(ticket: KongPolicyTicket, stage: ApprovedNativeStage, result?: unknown): Promise<void> {
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!;
    if(stage==='authorize'||stage==='prepare')return this.#portalPreparation(ticket,stage,()=>this.sqlPreparation(stage,state.method,state.path,state.body,state.query,ticket,false,()=>this.assertApprovedNativeRequestCore(ticket,stage,result)));
    if(this.scheduledConfigurationPreparationPhase())throw denied('CONFIGURATION_SQL_PREPARATION_NATIVE_FORBIDDEN');
    return this.assertApprovedNativeRequestCore(ticket,stage,result);
  }
  private async assertApprovedNativeRequestCore(ticket: KongPolicyTicket, stage: ApprovedNativeStage, result?: unknown): Promise<void> {
    this.forbidRecoveryNative();
    this.assertTicketActive(ticket);
    const state = this.tickets.get(ticket)!;
    if(await this.assertToolboxRequest(state.frame,state.cluster,state.method,state.path,state.body,state.query))return;
    const entity=this.entityChangePacket(state.frame);
    if(entity){if(!this.entityChangePolicy)throw unavailable();await this.entityChangePolicy.assertNative(entity.handle,{...this.entityChangeInput(state),result},stage);this.assertTicketActive(ticket);return;}
    const step = this.optionalApprovedStep(state.frame);
    if (!step) {
      if (state.cluster.execution_mode === 'approval') throw new ConflictException({ code: 'APPROVAL_REQUIRED', message: '集群采用审批模式，需当前有效的已批准步骤' });
      return;
    }
    if (!this.approvedPolicy || !state.frame.operation) throw denied('APPROVED_NATIVE_STEP_REQUIRED');
    const packetScope = approvedNativePacketScope(state.frame, state.method, state.path);
    await this.approvedPolicy.assertNative(step, { frame: state.frame, cluster: state.cluster, clusterId: state.cluster.id,
      transportScope: transportScopeFor(state.cluster.admin_url, state.cluster.transport_scope), workspaceId: packetScope.workspaceId!, operationId: state.frame.operation.operationId,
      method: state.method, canonicalPath: state.path, body: state.body, before: (state.value as KongPolicyDecision)?.before,
      mutationAction: state.frame.operation.action ?? '', parentId: packetScope.parentId, credentialKind: packetScope.credentialKind,
      query: state.query, result }, stage);
    this.assertTicketActive(ticket);
  }
  /** A constraint on an original scheduled packet, never a read or send
   * authority. The one monotonic meter survives every child capsule, retry,
   * return continuation and asynchronous destination/DNS check. */
  private async runConfigurationServiceObservation<T>(fn:()=>Promise<T>,ticket?:KongPolicyTicket):Promise<T>{
    const frame=this.current(),step=this.optionalApprovedStep(frame),job=this.configurationJob(frame);
    if(this.serviceObservations.getStore()||step?.execution.origin!=='scheduled-configuration'||step.kind!=='native'||!job||frame.sessionId!=null
      ||frame.operation?.entityType!=='services'||frame.operation.action!=='update')throw denied('CONFIGURATION_SERVICE_OBSERVATION_ORIGINAL_REQUIRED');
    if(ticket)this.assertTicketActive(ticket);
    const state={active:true,frame,step,namespace:this.requireWorkflowScheduledNamespaceHandle(),ticket,started:false,deadline:Infinity,calls:0,pages:0,records:0};
    try{const result=await this.serviceObservations.run(state,async()=>{const value=await fn();this.assertConfigurationServiceObservation();
      if(!state.started||!Number.isFinite(state.deadline))throw denied('CONFIGURATION_SERVICE_OBSERVATION_NOT_STARTED');return value;});
      // The run() Promise has a distinct continuation. The same invocation,
      // frame and absolute deadline must still be live immediately at return.
      this.serviceObservations.run(state,()=>{this.assertConfigurationServiceObservation();if(!state.started||!Number.isFinite(state.deadline))throw denied('CONFIGURATION_SERVICE_OBSERVATION_NOT_STARTED');});
      return result;
    }finally{state.active=false;}
  }
  /** Bootstrap-only fixed Approved consumer. The returned closure accepts
   * only its original opaque read handle; callers cannot supply a callback,
   * packet, GET path, status or deadline. Direct verifier/final-before reads
   * and primary reads therefore share the same private budget lifecycle. */
  installConfigurationServiceBeforeObserver(observer:{read(handle:ConfigurationNativeBeforeReadHandle):Promise<Readonly<ConfigurationNativeBeforeReadResult>>}):(handle:ConfigurationNativeBeforeReadHandle)=>Promise<Readonly<ConfigurationNativeBeforeReadResult>>{
    if(this.serviceBeforeObserverInstalled||!observer||typeof observer.read!=='function'||Object.keys(observer).some(key=>key!=='read'))throw denied('CONFIGURATION_SERVICE_BEFORE_OBSERVER_INSTALL_INVALID');
    this.serviceBeforeObserverInstalled=true;const read=observer.read.bind(observer);
    return Object.freeze(async(handle:ConfigurationNativeBeforeReadHandle)=>{
      const frame=this.current();if(frame.operation?.entityType!=='services'||frame.operation.action!=='update')return read(handle);
      const existing=this.serviceObservations.getStore();if(existing){this.assertConfigurationServiceObservation();if(existing.frame!==frame||existing.started)throw denied('CONFIGURATION_SERVICE_OBSERVATION_REENTRY');return read(handle);}
      return this.runConfigurationServiceObservation(()=>read(handle));
    });
  }
  startConfigurationServiceObservation():void{
    const state=this.serviceObservations.getStore();if(!state||state.started)throw denied('CONFIGURATION_SERVICE_OBSERVATION_ALREADY_STARTED');
    this.assertConfigurationServiceObservation();state.started=true;state.deadline=performance.now()+10000;
  }
  assertConfigurationServiceObservation():void{
    const state=this.serviceObservations.getStore();if(!state?.active||!this.chain(this.current()).includes(state.frame)
      ||this.optionalApprovedStep(state.frame)!==state.step||this.requireWorkflowScheduledNamespaceHandle()!==state.namespace
      ||state.started&&performance.now()>=state.deadline)throw denied('CONFIGURATION_SERVICE_OBSERVATION_EXPIRED');
    if(state.calls>8)throw denied('CONFIGURATION_SERVICE_OBSERVATION_CALL_BUDGET');
    if(state.pages>5||state.records>500)throw denied('CONFIGURATION_SERVICE_OBSERVATION_RECORD_BUDGET');
    // chain() rechecks the original Namespace/claim lease; the fixed Kong
    // consumer separately checks its actual Redis write lease after each DNS.
    if(state.ticket){const ticket=this.tickets.get(state.ticket);if(!ticket||ticket.frame!==state.frame||ticket.method!=='PATCH'
      ||ticket.path!==`/services/${state.frame.operation?.entityId}`)throw denied('CONFIGURATION_SERVICE_OBSERVATION_PACKET_CHANGED');}
  }
  private chargeServiceObservation(kind:'calls'|'response',result?:any):void{
    const state=this.serviceObservations.getStore();if(!state?.started)return;this.assertConfigurationServiceObservation();
    if(kind==='calls'){if(++state.calls>8)throw denied('CONFIGURATION_SERVICE_OBSERVATION_CALL_BUDGET');}
    else if(Array.isArray(result?.data)){state.pages++;state.records+=result.data.length;if(state.pages>5||state.records>500)throw denied('CONFIGURATION_SERVICE_OBSERVATION_RECORD_BUDGET');}
  }
  /** The observer's values never grant a send. Only this original write
   * ticket can retain its one invocation through Root's GETs and Kong DNS. */
  installConfigurationServiceDestinationObserver(observer:{observe(ticket:KongPolicyTicket,result:Readonly<ConfigurationNativeBeforeReadResult>,body:unknown):Promise<void>}):void{
    if(this.serviceDestinationObserver||!observer||typeof observer.observe!=='function'||Object.keys(observer).some(key=>key!=='observe'))throw denied('CONFIGURATION_SERVICE_OBSERVER_INSTALL_INVALID');
    this.serviceDestinationObserver=Object.freeze({observe:observer.observe.bind(observer)});
  }
  async protectScheduledConfigurationServiceDestination(ticket:KongPolicyTicket):Promise<boolean>{
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!,step=this.optionalApprovedStep(state.frame);
    if(step?.execution.origin!=='scheduled-configuration'||state.frame.operation?.entityType!=='services'||state.method!=='PATCH')return false;
    if(state.frame!==this.current()||!this.approvedPolicy?.readConfigurationNativeBefore||!this.serviceDestinationObserver)throw denied('CONFIGURATION_SERVICE_OBSERVER_REQUIRED');
    await this.runConfigurationServiceObservation(async()=>{
      const scope=approvedNativePacketScope(state.frame,state.method,state.path),result=await this.approvedPolicy!.readConfigurationNativeBefore!(step,{frame:state.frame,cluster:state.cluster,
        clusterId:state.cluster.id,transportScope:transportScopeFor(state.cluster.admin_url,state.cluster.transport_scope),workspaceId:scope.workspaceId!,operationId:state.frame.operation!.operationId,
        method:state.method,canonicalPath:state.path,body:state.body,mutationAction:state.frame.operation!.action??'',parentId:scope.parentId,credentialKind:scope.credentialKind,query:state.query},'service-destination');
      this.assertTicketActive(ticket);this.assertConfigurationServiceObservation();await this.serviceDestinationObserver!.observe(ticket,result,state.body);this.assertTicketActive(ticket);this.assertConfigurationServiceObservation();
    },ticket);return true;
  }
  /** Fixed primary-packet preflight bridge. It cannot select an arbitrary
   * GET path or lend a frame-shaped DTO to an approved read capability. */
  async readScheduledConfigurationNativeBefore(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string,body:unknown,query:Readonly<Record<string,string|number>>):Promise<Readonly<ConfigurationNativeBeforeReadResult>|null>{
    if(frame!==this.current())throw denied('CONFIGURATION_BEFORE_ORIGINAL_FRAME_REQUIRED');
    const step=this.optionalApprovedStep(frame),job=this.configurationJob(frame);
    if(step?.execution.origin!=='scheduled-configuration')return null;
    if(step.kind!=='native'||!job||job.proof.origin!=='workflow-scheduled-configuration'||frame.sessionId!=null||!frame.operation
      ||!this.approvedPolicy?.readConfigurationNativeBefore)throw denied('CONFIGURATION_BEFORE_READER_REQUIRED');
    const scope=approvedNativePacketScope(frame,method,path);
    const input={frame,cluster,clusterId:cluster.id,transportScope:transportScopeFor(cluster.admin_url,cluster.transport_scope),
      workspaceId:scope.workspaceId!,operationId:frame.operation.operationId,method,canonicalPath:path,body,mutationAction:frame.operation.action??'',
      parentId:scope.parentId,credentialKind:scope.credentialKind,query};
    const read=()=>this.approvedPolicy!.readConfigurationNativeBefore!(step,input);
    const result=await read();this.chain(frame);return result;
  }
  async assertApprovedOperation(frame: KongExecutionFrame, cluster: KongPolicyCluster, input: Omit<import('../../modules/workflows/approved-execution.types').ApprovedNativeRequest, 'frame' | 'cluster'>, stage: ApprovedNativeStage): Promise<void> {
    if((stage==='authorize'||stage==='prepare')&&frame===this.current())return this.sqlPreparation(stage,input.method,input.canonicalPath,input.body,input.query,undefined,true,()=>this.assertApprovedOperationCore(frame,cluster,input,stage));
    if(this.scheduledConfigurationPreparationPhase())throw denied('CONFIGURATION_SQL_PREPARATION_NATIVE_FORBIDDEN');
    return this.assertApprovedOperationCore(frame,cluster,input,stage);
  }
  private async assertApprovedOperationCore(frame: KongExecutionFrame, cluster: KongPolicyCluster, input: Omit<import('../../modules/workflows/approved-execution.types').ApprovedNativeRequest, 'frame' | 'cluster'>, stage: ApprovedNativeStage): Promise<void> {
    this.forbidRecoveryNative();
    if (!this.chain(this.current()).includes(frame)) throw denied('APPROVED_EXECUTION_SCOPE_MISMATCH');
    const entity=this.entityChangePacket(frame);
    if(entity){if(!this.entityChangePolicy)throw unavailable();await this.entityChangePolicy.assertNative(entity.handle,{...input,frame,cluster},stage);this.chain(frame);return;}
    const step = this.optionalApprovedStep(frame);
    if (!step) {
      if (cluster.execution_mode === 'approval') throw new ConflictException({ code: 'APPROVAL_REQUIRED', message: '集群采用审批模式，需当前有效的已批准步骤' });
      return;
    }
    if (!this.approvedPolicy) throw unavailable();
    await this.approvedPolicy.assertNative(step, { ...input, frame, cluster }, stage); this.chain(frame);
  }
  private limits(input: KongReadLimits = {}, purpose?: string, scheduledConfiguration = false): KongExecutionFrame['limits'] {
    const caps = scheduledConfiguration && purpose === 'configuration' ? { ...defaults, maxCalls: SCHEDULED_CONFIGURATION_MAX_CALLS, timeoutMs: CONFIGURATION_TIMEOUT_MS }
      : purpose === 'metrics-scrape' ? { maxCalls: 3, maxPages: 1, maxRecords: 1, maxBytes: 2 * 1024 * 1024, timeoutMs: 5000 }
      : purpose === 'portal-recovery-boundary' ? { maxCalls: 250, maxPages: 100, maxRecords: 10_000, maxBytes: 32 * 1024 * 1024, timeoutMs: 120_000 }
      : purpose === 'authorization' ? { maxCalls: 32, maxPages: 8, maxRecords: 800, maxBytes: 4 * 1024 * 1024, timeoutMs: 10_000 }
      : purpose === 'configuration' ? { ...defaults, timeoutMs: CONFIGURATION_TIMEOUT_MS } : defaults;
    const result: any = {};
    for (const key of Object.keys(defaults) as Array<keyof typeof defaults>) {
      const value = input[key] ?? caps[key];
      if (!Number.isInteger(value) || value < 1 || value > caps[key]) throw denied('KONG_EXECUTION_BUDGET_INVALID');
      result[key] = value;
    }
    if (input.paths) {
      if (!Array.isArray(input.paths) || input.paths.length > 128) throw denied('KONG_EXECUTION_PATH_INVALID');
      for (const path of input.paths) assertKongPath('GET', path, purpose === 'metrics-scrape');
      result.paths = Object.freeze([...input.paths]);
    }
    if (purpose === 'authorization' && !result.paths?.length) throw denied('KONG_AUTHORIZATION_PATHS_REQUIRED');
    return Object.freeze(result);
  }
  private make(input: Omit<KongExecutionFrame, 'limits'>, limits: KongReadLimits = {}, parent = this.storage.getStore(),
    namespaceAdmission?:Readonly<{handle:object;proof:Readonly<WorkflowScheduledNamespaceProof>}>,delegateBusiness=false): KongExecutionFrame {
    const scheduledConfiguration=input.purpose==='configuration'&&input.sessionId==null&&(namespaceAdmission
      ?namespaceAdmission.proof.kind==='configuration_v2'&&input.kind==='scheduled-workflow'&&!parent
      :!!parent&&parent.sessionId==null&&this.workflowScheduledNamespace(parent)?.proof.kind==='configuration_v2');
    const now=Date.now(),ordinaryLimits=this.limits(limits,input.purpose,scheduledConfiguration);let delegatedDeadline:number|undefined;
    if(namespaceAdmission){
      // Only runWorkflowScheduledNamespace supplies this private admission,
      // immediately after authenticating the original, one-shot handle.
      const proof=namespaceAdmission.proof;
      if(parent||input.kind!=='scheduled-workflow'||input.actor!==proof.actor||input.sessionId!=null
        ||input.clusterId!==proof.clusterId||input.workspaceId!==proof.workspaceId
        ||proof.origin!=='scheduled-workflow'||proof.sessionId!==null
        ||!['configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(proof.kind))throw denied('WORKFLOW_SCHEDULE_NAMESPACE_REQUIRED');
      delegatedDeadline=Date.parse(proof.expiresAt);
    }else if(parent&&['actor','operation','archive-delete'].includes(input.kind)&&limits.timeoutMs===undefined){
      const ancestors=this.chain(parent),namespace=ancestors.map(frame=>this.workflowScheduledNamespaces.get(frame)).find(Boolean);
      // Internal fixed entry points alone select the original longer envelope.
      // Ordinary actor/operation wrappers retain their own shorter cap, even
      // below a genuine Namespace. All original ancestors still constrain both.
      if(namespace&&input.sessionId==null&&parent.sessionId==null&&input.actor?.id===namespace.proof.actor.id
        &&input.clusterId===namespace.proof.clusterId&&parent.clusterId===namespace.proof.clusterId
        &&input.workspaceId===parent.workspaceId
        &&!ancestors.some(frame=>frame.kind==='workflow-validation-read'||frame.kind==='workflow-candidate-read'))
        delegatedDeadline=Math.min(Date.parse(namespace.proof.expiresAt),...ancestors.map(frame=>this.states.get(frame)!.deadline),
          ...(delegateBusiness?[]:[now+Math.min(120000,ordinaryLimits.timeoutMs)]));
    }
    if(delegatedDeadline!==undefined&&(!Number.isFinite(delegatedDeadline)||delegatedDeadline<=now))throw denied('WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED');
    const value = { ...input, limits: delegatedDeadline===undefined?ordinaryLimits:Object.freeze({...ordinaryLimits,timeoutMs:delegatedDeadline-now}) };
    // The guard resumes after authenticate() awaits. Updating this private
    // identity cell binds the existing request context, including callers of
    // the guard; enterWith() inside the guard would only bind its continuation.
    const identity = input.kind === 'http' ? { actor: input.actor, sessionId: input.sessionId } : undefined;
    if (identity) Object.defineProperties(value, { actor: { enumerable: true, get: () => identity.actor }, sessionId: { enumerable: true, get: () => identity.sessionId } });
    const frame = Object.freeze(value);
    if (identity) this.httpActors.set(frame, identity);
    this.states.set(frame, { closed: false, calls: 0, pages: 0, records: 0, bytes: 0, deadline: delegatedDeadline??now + frame.limits.timeoutMs, parent });
    if(delegatedDeadline!==undefined)this.businessDelegatedFrames.add(frame);
    return frame;
  }
  private expiredContext(frame: KongExecutionFrame, state?: State): never {
    if (!this.expiredContexts.has(frame)) {
      this.expiredContexts.add(frame);
      // Structural facts only. Never serialize the frame, operation, request,
      // actor, session, endpoint, payload or transport exception.
      try { this.logger.warn({ event: 'kong_execution_context_expired',
        frame: { kind: frame.kind, purpose: frame.purpose ?? null },
        reason: !state ? 'missing' : state.closed ? 'closed' : 'deadline',
        timeoutMs: frame.limits.timeoutMs,
        usage:state?{calls:state.calls,pages:state.pages,records:state.records,bytes:state.bytes}:null,
        overdueMs: state && !state.closed ? Math.max(0, Date.now() - state.deadline) : null }); }
      catch { /* A failed diagnostic sink cannot replace the original denial. */ }
    }
    throw denied('KONG_EXECUTION_CONTEXT_EXPIRED');
  }
  private chain(frame: KongExecutionFrame): KongExecutionFrame[] {
    const result: KongExecutionFrame[] = [];
    for (let current: KongExecutionFrame | undefined = frame; current; current = this.states.get(current)?.parent) {
      const state = this.states.get(current);
      if (!state || state.closed || Date.now() > state.deadline) this.expiredContext(current, state);
      const scheduled=this.scheduledNamespaces.get(current);if(scheduled){if(!this.scheduledNamespacePolicy)throw unavailable();this.scheduledNamespacePolicy.assertLive(scheduled.handle);}
      const business=this.workflowScheduledNamespaces.get(current);if(business){if(!this.workflowScheduledPolicy)throw unavailable();this.workflowScheduledPolicy.assertLive(business.handle);}
      const candidate=this.workflowCandidateReads.get(current);if(candidate){if(!this.workflowCandidateReadPolicy)throw unavailable();this.workflowCandidateReadPolicy.assertLive(candidate.handle);}
      const validation=this.workflowValidationReads.get(current);if(validation){if(!this.workflowValidationReadPolicy)throw unavailable();this.workflowValidationReadPolicy.assertLive(validation.handle);}
      result.push(current);
    }
    return result;
  }
  current(): KongExecutionFrame {
    const frame = this.storage.getStore();
    if (!frame) throw denied();
    this.chain(frame); return frame;
  }
  currentUsage(): Readonly<{ calls: number; pages: number; records: number; bytes: number }> {
    const frame = this.current(), state = this.states.get(frame)!;
    return Object.freeze({ calls: state.calls, pages: state.pages, records: state.records, bytes: state.bytes });
  }
  /** Read-only diagnostic of the original aggregate meter, including child
   * reads. It returns no frame, handle, deadline or mutable budget state. */
  currentScheduledWorkflowUsage(): Readonly<{ calls: number; pages: number; records: number; bytes: number }> {
    const frame = this.current(), root = this.chain(frame).find(value => this.workflowScheduledNamespaces.has(value));
    if (!root) throw denied('WORKFLOW_SCHEDULE_NAMESPACE_REQUIRED');
    const state = this.states.get(root)!;
    return Object.freeze({ calls: state.calls, pages: state.pages, records: state.records, bytes: state.bytes });
  }
  peek(): KongExecutionFrame | null {
    const frame = this.storage.getStore();
    if (!frame) return null;
    this.chain(frame); return frame;
  }
  private async run<T>(frame: KongExecutionFrame, fn: () => Promise<T>): Promise<T> {
    try { const result=await this.storage.run(frame, fn);
      // Close the final await/outer-continuation gap without caching grants.
      if(this.businessDelegatedFrames.has(frame))for(let ancestor:KongExecutionFrame|undefined=frame;ancestor;ancestor=this.states.get(ancestor)?.parent){
        const state=this.states.get(ancestor);if(!state||state.closed||Date.now()>state.deadline)this.expiredContext(ancestor,state);
      }return result; }
    finally { this.states.get(frame)!.closed = true;this.businessDelegatedFrames.delete(frame); }
  }
  runHttp<T>(options: { requestId?: string; ip?: string; idempotencyKey?: string; configurationWait?: boolean }, fn: () => T): T {
    const caller=this.storage.getStore();if(caller&&this.workflowValidationRead(caller))throw denied('WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY');
    if(caller&&this.workflowCandidateRead(caller))throw denied('WORKFLOW_CANDIDATE_READ_ONLY');
    return this.storage.run(this.make({ kind: 'http', requestId: options.requestId, ip: options.ip, idempotencyKey: options.idempotencyKey,
      ...(options.configurationWait ? {purpose:'configuration' as const} : {}) }, {}, undefined), fn);
  }
  bindHttpActor(actor: AuthUser, sessionId?: string): void {
    const frame = this.current();
    if (frame.kind !== 'http' || frame.actor || !actor?.id) throw denied('KONG_HTTP_ACTOR_INVALID');
    const identity = this.httpActors.get(frame);
    if (!identity) throw denied('KONG_HTTP_ACTOR_INVALID');
    identity.actor = Object.freeze({ ...actor }); identity.sessionId = sessionId;
  }
  captureHttpCloser(): () => void {
    const frame = this.current(), frames = this.chain(frame);
    return () => { for (const item of frames) this.states.get(item)!.closed = true; };
  }
  private assertConfigurationMutationActor(budget:NonNullable<ReturnType<typeof this.configurationMutationActors.get>>):void{
    const frame=this.current(),job=this.configurationJob(frame),execution=this.executionProof(frame),step=this.optionalApprovedStep(frame),namespace=this.workflowScheduledNamespace(frame);
    if(!budget.active||frame!==budget.frame||job!==budget.job||execution!==budget.execution||step!==budget.step||!namespace||namespace.handle!==budget.namespaceHandle
      ||frame.sessionId!=null||frame.actor?.id!==budget.scope.actorId||frame.clusterId!==budget.scope.clusterId||frame.workspaceId!==budget.scope.workspaceId
      ||budget.context.actor.id!==budget.scope.actorId||budget.context.clusterId!==budget.scope.clusterId||budget.context.workspaceId!==budget.scope.workspaceId
      ||budget.context.entityType!==budget.scope.entityType||budget.context.action!==budget.scope.action||(budget.context.entityId??null)!==(budget.scope.entityId??null)
      ||(budget.context.parentId??null)!==(budget.scope.parentId??null)||(budget.context.credentialKind??null)!==(budget.scope.credentialKind??null)
      ||(budget.context.idempotencyKey??null)!==(budget.scope.idempotencyKey??null)
      ||Date.now()>budget.deadline)throw denied('CONFIGURATION_MUTATION_ACTOR_ORIGINAL_REQUIRED');
    this.assertScheduledConfigurationProof(frame,job.proof);
  }
  /** Only a genuine scheduled configuration Native step can retain its
   * existing execution envelope through MutationService's actor wrapper.
   * Ordinary actor scopes and caller-supplied purpose/kind never select it. */
  async runMutationActor<T>(context:Readonly<MutationContext>,fn:()=>Promise<T>):Promise<T>{
    const parent=this.current(),job=this.configurationJob(parent);
    const ordinary=()=>this.runActor({actor:context.actor,clusterId:context.clusterId,workspaceId:context.workspaceId,module:context.entityType,action:context.action},fn);
    if(job?.proof.origin!=='workflow-scheduled-configuration'){
      const options={actor:context.actor,clusterId:context.clusterId,workspaceId:context.workspaceId,module:context.entityType,action:context.action};
      return this.portalNativeActorAdmission(parent,options)?this.runActorFrame(options,fn,true):ordinary();
    }
    const execution=this.executionProof(parent),step=this.optionalApprovedStep(parent),namespace=this.workflowScheduledNamespace(parent),chain=this.chain(parent);
    if(parent.kind!=='actor'||parent.operation||parent.archive||parent.sessionId!=null||this.workflowValidationRead(parent)||this.workflowCandidateRead(parent)
      ||this.configurationMutationActors.has(parent)||!namespace||!execution||execution.origin!=='scheduled-configuration'||execution.sessionId!==null
      ||!step||step.kind!=='native'||step.execution!==execution||!chain.some(frame=>this.scheduledConfigurationBoundaries.has(frame)&&this.approvedExecutions.get(frame)===execution)
      ||job.proof.readOnly||context.actor?.id!==parent.actor?.id||context.actor.id!==job.proof.actor.id||context.clusterId!==parent.clusterId
      ||context.clusterId!==job.proof.clusterId||execution.actorId!==context.actor.id||execution.clusterId!==context.clusterId)
      throw denied('CONFIGURATION_MUTATION_NATIVE_STEP_REQUIRED');
    this.assertScheduledConfigurationProof(parent,job.proof);
    // A different object workspace needs its own sealed scope selector. Keep
    // that legacy actor contract; a supplied workspace cannot buy more time.
    if(context.workspaceId!==parent.workspaceId||context.workspaceId!==job.proof.workspaceId)return ordinary();
    const deadline=Math.min(...chain.map(frame=>this.states.get(frame)!.deadline),job.proof.expiresAt,execution.expiresAt,Date.parse(namespace.proof.expiresAt));
    if(!Number.isFinite(deadline)||deadline<=Date.now())throw denied('CONFIGURATION_MUTATION_ACTOR_EXPIRED');
    const frame=this.make({kind:'actor',actor:parent.actor,sessionId:parent.sessionId,requestId:parent.requestId,ip:parent.ip,idempotencyKey:parent.idempotencyKey,
      clusterId:context.clusterId,workspaceId:context.workspaceId,module:context.entityType,action:context.action,purpose:'configuration'},{},parent,undefined,true);
    this.states.get(frame)!.deadline=Math.min(this.states.get(frame)!.deadline,deadline);
    const scope=Object.freeze({actorId:context.actor.id,clusterId:context.clusterId,workspaceId:context.workspaceId!,entityType:context.entityType,entityId:context.entityId,action:context.action,parentId:context.parentId,credentialKind:context.credentialKind,idempotencyKey:context.idempotencyKey});
    const budget={active:true,frame,job,step,execution,namespaceHandle:namespace.handle,deadline,context,scope,operationEntered:false};this.configurationMutationActors.set(frame,budget);
    try{return await this.run(frame,fn);}finally{budget.active=false;this.configurationMutationActors.delete(frame);}
  }
  private portalNativeActorAdmission(parent:KongExecutionFrame,options:KongActorScope):boolean{
    const namespace=this.workflowScheduledNamespace(parent),execution=this.executionProof(parent);
    let step:ApprovedStepProof|undefined;for(const ancestor of this.chain(parent)){step=this.approvedSteps.get(ancestor);if(step||this.scheduledConfigurationBoundaries.has(ancestor))break;}
    return !!namespace&&namespace.proof.kind==='portal-credential-issue'&&parent.kind==='actor'&&!parent.operation&&!parent.archive
      &&parent.sessionId==null&&!this.workflowValidationRead(parent)&&!this.workflowCandidateRead(parent)
      &&!!execution&&execution.origin==='scheduled-workflow'&&execution.sessionId===null
      &&execution.actorId===namespace.proof.actor.id&&execution.clusterId===namespace.proof.clusterId&&execution.workspaceId===namespace.proof.workspaceId
      &&execution.workflowId===namespace.proof.workflow.id&&execution.scheduleClaimId===namespace.proof.claim.id
      &&execution.permissionVersion===namespace.proof.permissionVersion&&execution.expiresAt<=Date.parse(namespace.proof.expiresAt)
      &&!!step&&step.kind==='native'&&step.execution===execution&&parent.actor?.id===execution.actorId
      &&options.actor?.id===execution.actorId&&options.clusterId===execution.clusterId&&parent.clusterId===execution.clusterId
      &&options.workspaceId===execution.workspaceId&&parent.workspaceId===execution.workspaceId;
  }
  /** Original mutation actor identity only; this neither authorizes a write
   * nor accepts an action or proof chosen by a caller. */
  isOriginalPortalNativeMutationFrame(frame:KongExecutionFrame):boolean{
    const current=this.storage.getStore();if(!current||current!==frame||!this.#businessNativeActors.has(frame)||frame.kind!=='actor'||frame.operation||frame.archive)return false;
    this.chain(frame);
    return this.portalNativeActorAdmission(frame,{actor:frame.actor as AuthUser,clusterId:frame.clusterId!,workspaceId:frame.workspaceId,module:frame.module,action:frame.action});
  }
  runActor<T>(options: KongActorScope, fn: () => Promise<T>): Promise<T> {
    const parent=this.current();
    return this.runActorFrame(options,fn,isEntityActorDomainScope(options)&&this.portalNativeActorAdmission(parent,options));
  }
  private runActorFrame<T>(options: KongActorScope, fn: () => Promise<T>,delegateBusiness:boolean):Promise<T>{
    const parent = this.current();
    if (!parent.actor || parent.actor.id !== options.actor?.id || parent.clusterId && parent.clusterId !== options.clusterId) throw denied('KONG_ACTOR_SCOPE_MISMATCH');
    const frame=this.make({ kind: 'actor', actor: parent.actor, sessionId: parent.sessionId, requestId: options.requestId ?? parent.requestId, ip: parent.ip, idempotencyKey: parent.idempotencyKey,
      clusterId: options.clusterId, workspaceId: options.workspaceId, module: options.module, action: options.action, purpose: options.purpose,
      operation: parent.operation, archive: parent.archive },{},parent,undefined,delegateBusiness);
    if(delegateBusiness)this.#businessNativeActors.add(frame);
    return this.run(frame,fn).finally(()=>this.#businessNativeActors.delete(frame));
  }
  runSystemRead<T>(clusterId: string, purpose: 'probe' | 'indexer' | 'metrics-scrape' | 'metrics-catalog', fn: () => Promise<T>, limits: KongReadLimits = {}): Promise<T> {
    if (this.storage.getStore()) throw denied('KONG_SYSTEM_CONTEXT_FORBIDDEN');
    return this.run(this.make({ kind: 'system-read', clusterId, purpose }, limits, undefined), fn);
  }
  /** Fixed internal observer only; no HTTP actor, native write or arbitrary URL. */
  async runEventObservationRead<T>(clusterId: string, paths: readonly string[], fn: () => Promise<T>): Promise<T> {
    if (this.storage.getStore() || !Array.isArray(paths) || !paths.length || paths.length > 5) throw denied('OBSERVATION_CONTEXT_INVALID');
    const id = '[\\da-f]{8}-[\\da-f]{4}-[1-8][\\da-f]{3}-[89ab][\\da-f]{3}-[\\da-f]{12}';
    const allowed = new RegExp(`^/$|^/(?:certificates|ca_certificates|upstreams)(?:/${id})?$|^/upstreams/${id}/(?:targets/all|health)$`, 'i');
    if (paths.some(path => typeof path !== 'string' || !allowed.test(path))) throw denied('OBSERVATION_PATH_INVALID');
    const frame = this.make({ kind: 'system-read', clusterId, purpose: 'event-observation' },
      { paths, maxCalls: 32, maxPages: 28, maxRecords: 2500, maxBytes: 8 * 1024 * 1024, timeoutMs: 12_000 }, undefined);
    this.eventObservationReads.add(frame);
    try { return await this.run(frame, fn); } finally { this.eventObservationReads.delete(frame); }
  }
  assertEventObservationRead(frame: KongExecutionFrame): void {
    if (!this.eventObservationReads.has(frame) || frame.actor || frame.kind !== 'system-read' || frame.purpose !== 'event-observation'
      || !this.chain(this.current()).includes(frame)) throw denied('OBSERVATION_CAPABILITY_REQUIRED');
  }
  /** Only the Vitals server provisioner mints this private ancestor claim.
   * A copied frame or an HTTP field cannot authorize credential-bearing URLs. */
  runManagedMetricsProvision<T>(clusterId: string, fn: () => Promise<T>): Promise<T> {
    this.forbidRecoveryNative();
    const parent = this.current();
    if (parent.kind !== 'actor' || !parent.actor || parent.clusterId !== clusterId) throw denied('KONG_MANAGED_PROVISION_CONTEXT_INVALID');
    const frame = this.make({ ...parent, kind: 'actor' }, {}, parent);
    this.managedMetricsProvisions.set(frame, Object.freeze({ clusterId }));
    return this.run(frame, fn);
  }
  runInternalRead<T>(clusterId: string, purpose: KongReadPurpose, fn: () => Promise<T>, limits: KongReadLimits = {}): Promise<T> {
    const parent = this.current();
    if (purpose === 'portal-boundary' || purpose === 'portal-recovery-boundary') throw denied('PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    if (parent.clusterId && parent.clusterId !== clusterId || parent.kind === 'system-read' && purpose !== parent.purpose || parent.kind === 'internal-read' && parent.purpose === 'authorization') throw denied('KONG_INTERNAL_SCOPE_MISMATCH');
    const original=purpose==='entity-preflight'&&!this.scheduledPortalPreparationPhase()?this.originalScheduledPortalExecution():null;
    if(original?.step?.kind==='native'&&limits.paths?.length===1&&/^\/consumers\/[\da-f-]{36}$/i.test(limits.paths[0])){
      const namespace=this.workflowScheduledNamespace(parent)!,path=limits.paths[0],fixedLimits={...limits,paths:Object.freeze([path])};
      const live=()=>{
        if(!this.portalEntityParentReadPolicy||this.current()!==parent||this.currentApprovedStep()!==original.step
          ||this.originalScheduledPortalExecution()?.execution!==original.execution||clusterId!==namespace.proof.clusterId
          ||(limits.workspaceId??parent.workspaceId)!==namespace.proof.workspaceId)throw denied('WORKFLOW_PORTAL_ENTITY_PARENT_READ_REQUIRED');
        this.chain(parent);
      };
      live();
      // Re-enter only beneath the actual Validation frame, which cannot
      // qualify as an original Portal execution or recursively mint a reader.
      return this.portalEntityParentReadPolicy!.run(namespace.handle,clusterId,path,
        ()=>this.runInternalRead(clusterId,purpose,fn,fixedLimits)).then(value=>{live();return value;});
    }
    return this.run(this.make({ kind: 'internal-read', clusterId, purpose, actor: parent.actor, sessionId: parent.sessionId, requestId: parent.requestId, ip: parent.ip, idempotencyKey: parent.idempotencyKey,
      workspaceId: limits.workspaceId ?? parent.workspaceId, module: parent.module, action: parent.action, operation: parent.operation, archive: parent.archive }, limits), fn);
  }
  private portalPermit(permit: PortalBoundaryReadPermit): { ticket: KongPolicyTicket; frame: KongExecutionFrame; transportScope: string; active: boolean } {
    const state = permit && this.portalPermits.get(permit);
    if (!state?.active) throw denied('PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    this.assertTicketActive(state.ticket);
    if (!this.chain(this.current()).includes(state.frame)) throw denied('PORTAL_BOUNDARY_READ_SCOPE_MISMATCH');
    return state;
  }
  assertPortalBoundaryRead(frame: KongExecutionFrame): void {
    const permit = this.portalReads.get(frame);
    if (!permit || frame.kind !== 'internal-read' || frame.purpose !== 'portal-boundary' || !frame.operation) throw denied('PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    const state = this.portalPermit(permit), original = this.tickets.get(state.ticket)!;
    if (frame.actor?.id !== state.frame.actor?.id || frame.sessionId !== state.frame.sessionId || frame.clusterId !== original.cluster.id
      || frame.workspaceId !== state.frame.workspaceId || frame.operation.operationId !== state.frame.operation?.operationId
      || state.transportScope !== transportScopeFor(original.cluster.admin_url, original.cluster.transport_scope)) throw denied('PORTAL_BOUNDARY_READ_SCOPE_MISMATCH');
  }
  /** Own data-only snapshot before any await. Accessors, sparse slots and
   * caller array mutations can never enlarge a validated private read frame. */
  #portalBoundaryPaths(input:readonly string[]):readonly string[]{
    if(!Array.isArray(input))throw denied('PORTAL_BOUNDARY_READ_PATH_INVALID');
    const descriptors=Object.getOwnPropertyDescriptors(input as object),length=descriptors.length?.value;
    if(typeof length!=='number'||!Number.isInteger(length)||length<1||length>128||Reflect.ownKeys(descriptors).length!==length+1)throw denied('PORTAL_BOUNDARY_READ_PATH_INVALID');
    const paths:string[]=[];for(let index=0;index<length;index++){
      const descriptor=descriptors[String(index)];
      if(!descriptor||!Object.hasOwn(descriptor,'value')||typeof descriptor.value!=='string')throw denied('PORTAL_BOUNDARY_READ_PATH_INVALID');
      paths.push(descriptor.value);
    }
    return Object.freeze(paths);
  }
  async runPortalBoundaryRead<T>(permit: PortalBoundaryReadPermit, paths: readonly string[], fn: () => Promise<T>, limits: Omit<KongReadLimits, 'paths' | 'workspaceId'> = {}): Promise<T> {
    const state = this.portalPermit(permit), parent = this.current();
    const exactPaths=this.#portalBoundaryPaths(paths);
    const uuid = '[\\da-f]{8}-[\\da-f]{4}-[1-8][\\da-f]{3}-[89ab][\\da-f]{3}-[\\da-f]{12}';
    const allowed = new RegExp(`^/(?:services|routes|plugins)(?:/${uuid})?$|^/consumers/${uuid}(?:/acls(?:/${uuid})?|/key-auth/${uuid})?$`, 'i');
    if (exactPaths.some(path => !allowed.test(path))) throw denied('PORTAL_BOUNDARY_READ_PATH_INVALID');
    const preparation=this.#portalPreparations.getStore();
    const inherit=preparation?.active&&preparation.proof.purpose==='before-send'&&parent===preparation.proof.frame
      &&state.ticket===preparation.proof.ticket&&state.frame===parent;
    if(inherit){
      this.assertScheduledPortalPreparationPhase(preparation.proof);
      if(!this.#portalPreparationSupportPolicy)throw denied('PORTAL_PREPARATION_SUPPORT_UNAVAILABLE');
      await this.#portalPreparationSupportPolicy.assertPaths(preparation.proof,exactPaths);
      this.assertScheduledPortalPreparationPhase(preparation.proof);if(this.current()!==parent||this.portalPermit(permit)!==state)throw denied('PORTAL_PREPARATION_SUPPORT_CHANGED');
    }
    const frame = this.make({ kind: 'internal-read', purpose: 'portal-boundary', actor: parent.actor, sessionId: parent.sessionId,
      clusterId: state.frame.clusterId, workspaceId: state.frame.workspaceId, operation: state.frame.operation,
      requestId: parent.requestId, ip: parent.ip, idempotencyKey: parent.idempotencyKey, module: parent.module, action: parent.action }, { ...limits, paths:exactPaths }, parent);
    this.portalReads.set(frame, permit);
    if(inherit)this.#portalPreparationSupportFrames.set(frame,{scope:preparation,permit,paths:frame.limits.paths!});
    try{return await this.run(frame,fn);}finally{this.#portalPreparationSupportFrames.delete(frame);this.portalReads.delete(frame);}
  }
  runOperation<T>(options: KongOperationScope, fn: () => Promise<T>): Promise<T> {
    this.forbidRecoveryNative();
    const parent = this.current();
    if (!nativeTypes.has(options.entityType) || !options.operationId || !parent.actor || parent.actor.id !== options.actor.id || parent.clusterId && parent.clusterId !== options.clusterId) throw denied('KONG_NATIVE_OPERATION_INVALID');
    const budget=this.configurationMutationActors.get(parent);
    if(budget){
      this.assertConfigurationMutationActor(budget);const expected=budget.scope;
      if(budget.operationEntered||!budget.operationId||!budget.binding||!budget.transaction||options.operationId!==budget.operationId||options.actor.id!==expected.actorId
        ||options.clusterId!==expected.clusterId||options.workspaceId!==expected.workspaceId||options.entityType!==expected.entityType
        ||options.action!==expected.action||(options.entityId??null)!==(expected.entityId??null)||(options.parentId??null)!==(expected.parentId??null)
        ||(options.credentialKind??null)!==(expected.credentialKind??null))throw denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH');
      budget.operationEntered=true;
      const frame=this.make({kind:'operation',actor:parent.actor,sessionId:parent.sessionId,requestId:parent.requestId,ip:parent.ip,idempotencyKey:parent.idempotencyKey,
        clusterId:options.clusterId,workspaceId:options.workspaceId,action:options.action,module:parent.module,purpose:'configuration',operation:Object.freeze({...options,actor:parent.actor})},{},parent,undefined,true);
      this.states.get(frame)!.deadline=Math.min(this.states.get(frame)!.deadline,budget.deadline,this.states.get(parent)!.deadline);
      this.#businessNativeOperations.add(frame);
      return this.run(frame,fn).finally(()=>this.#businessNativeOperations.delete(frame));
    }
    const nativeActor=this.#businessNativeActors.has(parent)&&this.portalNativeActorAdmission(parent,options);
    const frame=this.make({ kind: 'operation', actor: parent.actor, sessionId: parent.sessionId, requestId: parent.requestId, ip: parent.ip, idempotencyKey: parent.idempotencyKey, clusterId: options.clusterId,
      workspaceId: options.workspaceId, action: options.action, module: parent.module, operation: Object.freeze({ ...options, actor: parent.actor }) },{},parent,undefined,nativeActor);
    if(nativeActor)this.#businessNativeOperations.add(frame);
    return this.run(frame,fn).finally(()=>this.#businessNativeOperations.delete(frame));
  }
  runArchiveDelete<T>(options: KongArchiveScope, fn: () => Promise<T>): Promise<T> {
    this.forbidRecoveryNative();
    const parent = this.current();
    if (!parent.operation || parent.operation.operationId !== options.operationId || parent.clusterId !== options.clusterId || parent.workspaceId !== options.workspaceId || !options.entryId || !options.nodes.length || options.nodes.length > 10_000) throw denied('KONG_RECYCLE_CAPABILITY_INVALID');
    const archive = Object.freeze({ ...options, nodes: Object.freeze(options.nodes.map(node => Object.freeze({ ...node }))) });
    for (const node of archive.nodes) assertKongPath('DELETE', node.path);
    return this.run(this.make({ ...parent, kind: 'archive-delete', archive },{},parent,undefined,this.#businessNativeOperations.has(parent)), fn);
  }
  private allowRead(frame: KongExecutionFrame, method: string, path: string, query: Record<string, string | number>): void {
    if (frame.kind !== 'system-read' && frame.kind !== 'internal-read') return;
    if (method !== 'GET') throw denied('KONG_READ_CAPABILITY_WRITE_FORBIDDEN');
    if (frame.limits.paths && !frame.limits.paths.includes(path)) throw denied('KONG_INTERNAL_PATH_FORBIDDEN');
    if (frame.purpose === 'probe' && !(/^\/(?:status|plugins\/enabled|schemas\/(?:services|routes|consumers|plugins|upstreams|certificates|ca_certificates|snis))$/.test(path) || path === '/')) throw denied('KONG_PROBE_PATH_FORBIDDEN');
    if (frame.purpose === 'portal-boundary' || frame.purpose === 'portal-recovery-boundary') {
      if (frame.purpose === 'portal-boundary') this.assertPortalBoundaryRead(frame);
      const collection = /^\/(?:services|routes|plugins)$/.test(path) || /^\/consumers\/[^/]+\/acls$/.test(path);
      if (collection ? Object.keys(query).some(key => !['size', 'offset'].includes(key)) || !Number.isInteger(Number(query.size || 100)) || Number(query.size || 100) > 100 || Number(query.size || 100) < 1 : Object.keys(query).length > 0) throw denied('PORTAL_BOUNDARY_READ_QUERY_INVALID');
    }
    if (frame.purpose === 'indexer' && (!new RegExp(`^/(?:${ENTITIES.join('|')})$`).test(path) || Number(query.size || 20) > 100)) throw denied('KONG_INDEXER_PATH_FORBIDDEN');
    if (frame.purpose === 'metrics-scrape' && (frame.kind !== 'system-read' || path !== '/metrics' || Object.keys(query).length)) throw denied('KONG_METRICS_PATH_FORBIDDEN');
    if (frame.purpose === 'metrics-catalog') {
      const collection = /^\/(?:services|routes|consumers)$/.test(path);
      const identity = /^\/(?:services|routes|consumers)\/[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(path);
      if (frame.kind !== 'system-read' || !collection && !identity || collection && (Number(query.size || 20) > 100 || Object.keys(query).some(key => !['size', 'offset'].includes(key))) || identity && Object.keys(query).length) throw denied('KONG_METRICS_CATALOG_PATH_FORBIDDEN');
    }
    if (frame.purpose === 'event-observation') {
      this.assertEventObservationRead(frame);
      const collection = /^\/(?:certificates|ca_certificates|upstreams)$|^\/upstreams\/[^/]+\/(?:targets\/all|health)$/.test(path);
      if (collection ? Object.keys(query).some(key => !['size', 'offset'].includes(key)) || !Number.isInteger(Number(query.size || 20)) || Number(query.size || 20) < 1 || Number(query.size || 20) > 100 : Object.keys(query).length > 0) throw denied('OBSERVATION_QUERY_INVALID');
    }
    if (frame.purpose !== 'probe' && frame.purpose !== 'authorization' && frame.purpose !== 'metrics-scrape' && /^\/(?:cache|tags|status|endpoints|metrics)(?:\/|$)/.test(path)) throw denied('KONG_INTERNAL_PATH_FORBIDDEN');
  }
  /** Always inspect the complete live ancestor chain first. Only a genuine
   * provider-owned validation claim may select its exact pre-existing local
   * observers; newly nested reads, ordinary reads and all aggregate meters
   * retain their original limits. Nothing leaves the actual ALS ancestry. */
  private meteredFrames(origin:KongExecutionFrame,validation?:WorkflowValidationReadClaim):KongExecutionFrame[]{
    const chain=this.chain(origin);if(!validation)return chain;
    const actual=this.workflowValidationRead(origin),namespace=this.workflowScheduledNamespaces.get(validation.namespaceFrame);
    if(actual!==validation||!chain.includes(validation.namespaceFrame)||namespace?.handle!==validation.namespaceHandle||namespace.proof!==validation.namespaceProof)
      throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');
    return chain.filter(frame=>!validation.localReadBudgets.includes(frame));
  }
  private ticketValidationMeter(ticket:TicketState):WorkflowValidationReadClaim|undefined{
    if(!ticket.validationReadToken)return undefined;
    const claim=this.workflowValidationRead(ticket.frame);if(!claim)throw denied('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED');return claim;
  }
  private budgetExceeded(frame:KongExecutionFrame,budgetKind:'calls'|'bytes'|'records'|'pages',limit:number,current:number):never{
    // A synchronous structural diagnostic only: no paths, actor/session
    // identifiers, payloads, headers, URLs, credentials or exception stack.
    try{this.logger.warn({event:'kong_execution_budget_exceeded',frame:{kind:frame.kind,purpose:frame.purpose??null},budgetKind,limit,current});}catch{/* Preserve the original public denial if a log sink fails. */}
    throw denied(budgetKind==='calls'?'KONG_EXECUTION_CALL_LIMIT':'KONG_EXECUTION_RESPONSE_LIMIT');
  }
  async authorizeRequest(cluster: KongPolicyCluster, method: string, path: string, body: unknown, query: Record<string, string | number>): Promise<KongPolicyTicket> {
    const frame=this.current();
    if(writeMethods.has(method)&&this.#portalPreparations.getStore()?.active)throw denied('PORTAL_SQL_PREPARATION_NATIVE_FORBIDDEN');
    if(writeMethods.has(method)&&this.#businessNativeOperations.has(frame)&&this.workflowScheduledNamespace(frame)?.proof.kind==='portal-credential-issue'){
      // An original request identity, not an allow decision or a send permit.
      // No caller supplies this opaque ticket; failures destroy it immediately.
      const ticket=Object.freeze({})as KongPolicyTicket;
      this.tickets.set(ticket,{frame,value:null,method,path,cluster,body,query});this.#portalPendingTickets.add(ticket);
      try{return await this.#portalPreparation(ticket,'authorize',()=>this.authorizeRequestCore(cluster,method,path,body,query,ticket));}
      catch(error){this.tickets.delete(ticket);throw error;}finally{this.#portalPendingTickets.delete(ticket);}
    }
    return this.sqlPreparation('authorize',method,path,body,query,undefined,false,()=>this.authorizeRequestCore(cluster,method,path,body,query));
  }
  private async authorizeRequestCore(cluster: KongPolicyCluster, method: string, path: string, body: unknown, query: Record<string, string | number>,originalTicket?:KongPolicyTicket): Promise<KongPolicyTicket> {
    const portalPreparation=this.scheduledPortalPreparationPhase();
    if(portalPreparation&&this.current()!==portalPreparation.frame&&(method!=='GET'||body!==undefined))throw denied('PORTAL_SQL_PREPARATION_READ_ONLY');
    if(method==='GET')this.chargeServiceObservation('calls');
    if (!this.hooks) throw unavailable();
    const frame = this.current();
    const validation=await this.verifyWorkflowValidationRead(frame,cluster,method,body);
    if(validation){
      const claim=this.workflowValidationRead(frame)!,{resource,selection}=this.selectedScheduledReadResource(frame,claim.handle,validation.scope.resources,cluster.id,path);
      if(!resource)throw denied('WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN');this.allowRead(frame,method,path,query);
      for(const scope of this.meteredFrames(frame,claim)){const state=this.states.get(scope)!;if(++state.calls>scope.limits.maxCalls)this.budgetExceeded(scope,'calls',scope.limits.maxCalls,state.calls);}
      const token=await this.workflowValidationReadPolicy!.authorizeRequest(claim.handle,{clusterId:cluster.id,workspaceId:resource.workspaceId,method,path,body,query});this.chain(frame);
      const ticket=Object.freeze({}) as KongPolicyTicket;this.tickets.set(ticket,{frame,value:null,method,path,cluster,body,query:{...query},validationReadToken:token,resourceSelection:selection});return ticket;
    }
    const candidate=await this.verifyWorkflowCandidateRead(frame,cluster,method,body);
    if(candidate){
      const claim=this.workflowCandidateRead(frame)!;
      const {resource,selection}=this.selectedScheduledReadResource(frame,claim.handle,candidate.scope.resources,cluster.id,path);
      if(!resource)throw denied('WORKFLOW_CANDIDATE_PATH_FORBIDDEN');
      for(const scope of this.chain(frame)){const state=this.states.get(scope)!;if(++state.calls>scope.limits.maxCalls)this.budgetExceeded(scope,'calls',scope.limits.maxCalls,state.calls);}
      const token=await this.workflowCandidateReadPolicy!.authorizeRequest(claim.handle,{clusterId:cluster.id,workspaceId:resource.workspaceId,method,path,body,query});this.chain(frame);
      const ticket=Object.freeze({}) as KongPolicyTicket;this.tickets.set(ticket,{frame,value:null,method,path,cluster,body,query:{...query},candidateReadToken:token,resourceSelection:selection});return ticket;
    }
    await this.verifyEntityScheduledNamespace(writeMethods.has(method)?'packet':'capture');
    await this.verifyWorkflowScheduledNamespace(writeMethods.has(method)?'packet':'capture');
    await this.assertPlanningRequest(frame,cluster,method);
    await this.assertConfigurationJob(frame, writeMethods.has(method));
    if (writeMethods.has(method)) this.forbidRecoveryNative(frame);
    if (frame.purpose === 'portal-recovery-boundary') await this.assertPortalRecoveryBoundaryRead(frame);
    if (frame.kind === 'http' || frame.clusterId !== cluster.id) throw denied('KONG_CLUSTER_SCOPE_MISMATCH');
    this.allowRead(frame, method, path, query);
    const toolbox=writeMethods.has(method)&&await this.assertToolboxRequest(frame,cluster,method,path,body,query);
    if (writeMethods.has(method) && !toolbox && (!frame.operation || frame.kind === 'internal-read' || frame.kind === 'system-read')) throw denied('KONG_NATIVE_OPERATION_REQUIRED');
    if (method === 'DELETE' && !toolbox && (!frame.archive || !frame.archive.nodes.some(node => node.path === path))) throw denied('KONG_RECYCLE_CAPABILITY_REQUIRED');
    for (const scope of this.chain(frame)) { const state = this.states.get(scope)!; if (++state.calls > scope.limits.maxCalls) this.budgetExceeded(scope,'calls',scope.limits.maxCalls,state.calls); }
    const value = await this.hooks.authorizeRequest(frame, cluster, method, path, body, query);
    this.chain(frame);
    this.recoveryNewRequest(frame,path,query);
    const ticket=originalTicket??Object.freeze({})as KongPolicyTicket;
    if(originalTicket){const pending=this.tickets.get(originalTicket);
      if(!this.#portalPendingTickets.has(originalTicket)||!pending||pending.frame!==frame||pending.cluster!==cluster||pending.method!==method||pending.path!==path
        ||pending.body!==body||pending.query!==query||pending.value!==null)throw denied('PORTAL_ORIGINAL_REQUEST_TICKET_REQUIRED');
    }
    if(writeMethods.has(method)){
      const entity=this.entityChangePacket(frame);
      if(entity){if(entity.ticket)throw denied('ENTITY_CHANGE_NATIVE_PACKET_ALREADY_ALLOCATED');entity.ticket=ticket;}
    }
    if(originalTicket)this.tickets.get(originalTicket)!.value=value;else this.tickets.set(ticket,{frame,value,method,path,cluster,body,query});
    return ticket;
  }
  assertTicketActive(ticket: KongPolicyTicket): void {
    const state = this.tickets.get(ticket);
    const current = this.storage.getStore();
    if (!state || !current || !this.chain(current).includes(state.frame)) throw denied('KONG_EXECUTION_TICKET_INVALID');
    this.chain(state.frame);
    if(this.serviceObservations.getStore()?.started)this.assertConfigurationServiceObservation();
    if(state.resourceSelection&&(!state.resourceSelection.active||this.scheduledReadResources.getStore()!==state.resourceSelection||!this.chain(state.frame).includes(state.resourceSelection.frame)))
      throw denied('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED');
  }
  chargeRetry(ticket: KongPolicyTicket): void {
    this.assertTicketActive(ticket);
    const ticketState = this.tickets.get(ticket)!;
    this.chargeServiceObservation('calls');
    if (ticketState.method !== 'GET') throw denied('KONG_NATIVE_RETRY_FORBIDDEN');
    const recovery=this.promotionRecovery(ticketState.frame);if(recovery&&++recovery.meter.calls>defaults.maxCalls)throw denied('PROMOTION_RECOVERY_BUDGET_EXHAUSTED');
    for (const frame of this.meteredFrames(ticketState.frame,this.ticketValidationMeter(ticketState))) {
      const state = this.states.get(frame)!;
      if (++state.calls > frame.limits.maxCalls) this.budgetExceeded(frame,'calls',frame.limits.maxCalls,state.calls);
    }
  }
  async refreshAuthorization(ticket: KongPolicyTicket): Promise<void> {
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!;
    return this.#portalPreparation(ticket,'refresh',()=>this.sqlPreparation('refresh',state.method,state.path,state.body,state.query,ticket,false,()=>this.refreshAuthorizationCore(ticket)));
  }
  private async refreshAuthorizationCore(ticket: KongPolicyTicket): Promise<void> {
    if (!this.hooks) throw unavailable();
    this.assertTicketActive(ticket);
    const state = this.tickets.get(ticket)!;
    if(state.validationReadToken){const proof=await this.workflowValidationReadPolicy!.verifyRequest(state.validationReadToken);
      this.assertWorkflowValidationReadProof(state.frame,state.cluster,state.method,state.body,proof);this.assertTicketActive(ticket);return;}
    if(state.candidateReadToken){const proof=await this.verifyWorkflowCandidateRead(state.frame,state.cluster,state.method,state.body);
      if(await this.workflowCandidateReadPolicy!.verifyRequest(state.candidateReadToken)!==proof)throw denied('WORKFLOW_CANDIDATE_SCOPE_CHANGED');this.assertTicketActive(ticket);return;}
    await this.verifyEntityScheduledNamespace(writeMethods.has(state.method)?'packet':'capture');
    await this.verifyWorkflowScheduledNamespace(writeMethods.has(state.method)?'packet':'capture');
    await this.assertPlanningRequest(state.frame,state.cluster,state.method);
    await this.assertConfigurationJob(state.frame, writeMethods.has(state.method));
    const decision = await this.hooks.authorizeRequest(state.frame, state.cluster, state.method, state.path, state.body, state.query);
    this.assertTicketActive(ticket);
    state.value = decision;
  }
  verifiedPlatformAdmin(ticket: KongPolicyTicket): boolean {
    this.assertTicketActive(ticket);
    return (this.tickets.get(ticket)!.value as KongPolicyDecision | null)?.platformAdmin === true;
  }
  verifiedManagedMetricsProvision(ticket: KongPolicyTicket): boolean {
    this.assertTicketActive(ticket);
    const state = this.tickets.get(ticket)!;
    return this.verifiedPlatformAdmin(ticket) && this.chain(state.frame).some(frame => this.managedMetricsProvisions.get(frame)?.clusterId === state.cluster.id);
  }
  authorizedBefore(ticket: KongPolicyTicket): any | null {
    this.assertTicketActive(ticket);
    return (this.tickets.get(ticket)!.value as KongPolicyDecision | null)?.before ?? null;
  }
  async prepareNativeSend(ticket:KongPolicyTicket):Promise<void>{
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!;
    if(this.#businessNativeOperations.has(state.frame)&&this.workflowScheduledNamespace(state.frame)?.proof.kind==='portal-credential-issue')
      return this.#portalPreparation(ticket,'before-send',()=>this.beforeNativeSendCore(ticket,true));
    return this.beforeNativeSend(ticket);
  }
  async beforeNativeSend(ticket: KongPolicyTicket): Promise<void> {
    if(this.#portalPreparations.getStore()?.active)throw denied('PORTAL_SQL_PREPARATION_NATIVE_FORBIDDEN');
    const state=this.tickets.get(ticket);this.assertTicketActive(ticket);
    if(state&&this.#businessNativeOperations.has(state.frame)&&this.workflowScheduledNamespace(state.frame)?.proof.kind==='portal-credential-issue'){
      await this.#portalPreparation(ticket,'before-send',()=>this.beforeNativeSendCore(ticket,true));
      return this.#finalNativeStage(ticket,'before-send',async()=>{
        await this.assertApprovedNativeRequest(ticket,'before-send');this.assertTicketActive(ticket);
      });
    }
    return this.#finalNativeStage(ticket,'before-send',()=>this.beforeNativeSendCore(ticket));
  }
  private async beforeNativeSendCore(ticket: KongPolicyTicket,portalPreparation=false): Promise<void> {
    if (!this.hooks) throw unavailable();
    this.assertTicketActive(ticket);
    const state = this.tickets.get(ticket)!;
    if(state.validationReadToken){const proof=await this.workflowValidationReadPolicy!.verifyRequest(state.validationReadToken);
      this.assertWorkflowValidationReadProof(state.frame,state.cluster,state.method,state.body,proof);this.assertTicketActive(ticket);return;}
    if(state.candidateReadToken){const proof=await this.verifyWorkflowCandidateRead(state.frame,state.cluster,state.method,state.body);
      if(await this.workflowCandidateReadPolicy!.verifyRequest(state.candidateReadToken)!==proof)throw denied('WORKFLOW_CANDIDATE_SCOPE_CHANGED');this.assertTicketActive(ticket);return;}
    await this.verifyEntityScheduledNamespace('before-send');
    await this.verifyWorkflowScheduledNamespace('before-send');
    await this.assertPlanningRequest(state.frame,state.cluster,state.method);
    if(this.promotionRecovery(state.frame))await this.assertPromotionRecoveryRequest(state.frame,state.cluster,state.method,state.path,state.body,state.query);
    await this.assertConfigurationJob(state.frame, writeMethods.has(state.method));
    if (writeMethods.has(state.method)) this.forbidRecoveryNative(state.frame);
    if (state.frame.purpose === 'portal-recovery-boundary') await this.assertPortalRecoveryBoundaryRead(state.frame);
    if (writeMethods.has(state.method)) {
      await this.scheduleReservationPolicy?.assertNativeWrite(state.frame,state.cluster,state.method,state.path);
      await this.assertApprovedNativeRequest(ticket, 'before-send');
      const permit = Object.freeze({}) as PortalBoundaryReadPermit;
      const claim = { ticket, frame: state.frame, transportScope: transportScopeFor(state.cluster.admin_url, state.cluster.transport_scope), active: true };
      this.portalPermits.set(permit, claim);
      try { await this.hooks.beforeNativeSend?.(state.frame, state.cluster, state.method, state.path, state.body, state.query, state.value, permit); }
      finally { claim.active = false; this.portalPermits.delete(permit); }
      if(!portalPreparation)await this.assertApprovedNativeRequest(ticket, 'before-send');
    }
    if(writeMethods.has(state.method)){
      const entity=this.entityChangePacket(state.frame);
      if(entity){if(!this.entityChangePolicy)throw unavailable();await this.entityChangePolicy.beforeNativeSend(entity.handle,this.entityChangeInput(state));}
      const claim=this.configurationJob(state.frame);
      if(claim&&this.configurationJobPolicy?.beforeNativeSend)await this.configurationJobPolicy.beforeNativeSend(claim.handle,{clusterId:state.cluster.id,method:state.method,path:state.path,body:state.body,query:state.query});
    }
    await this.assertConfigurationJob(state.frame, writeMethods.has(state.method));
    this.assertTicketActive(ticket);
  }
  async authorizeResponse(ticket: KongPolicyTicket, result: any): Promise<any> {
    this.assertTicketActive(ticket);const state=this.tickets.get(ticket)!;
    return writeMethods.has(state.method)?this.#finalNativeStage(ticket,'response',()=>this.authorizeResponseCore(ticket,result))
      :this.sqlPreparations.run(null,()=>this.authorizeResponseCore(ticket,result));
  }
  private async authorizeResponseCore(ticket: KongPolicyTicket, result: any): Promise<any> {
    if (!this.hooks) throw unavailable();
    const ticketState = this.tickets.get(ticket);
    this.assertTicketActive(ticket);
    if (!ticketState) throw denied();
    if(ticketState.validationReadToken){
      const proof=await this.workflowValidationReadPolicy!.verifyRequest(ticketState.validationReadToken);
      this.assertWorkflowValidationReadProof(ticketState.frame,ticketState.cluster,ticketState.method,ticketState.body,proof);
      this.chargeResponse(ticketState,result);
      const authorized=await this.workflowValidationReadPolicy!.authorizeResponse(ticketState.validationReadToken,result);this.assertTicketActive(ticket);this.tickets.delete(ticket);return authorized;
    }
    const candidate=ticketState.candidateReadToken?await this.verifyWorkflowCandidateRead(ticketState.frame,ticketState.cluster,ticketState.method,ticketState.body):null;
    if(!this.scheduledPortalFinalNativePhase())await this.verifyWorkflowScheduledNamespace(writeMethods.has(ticketState.method)?'packet':'capture');
    await this.assertPlanningRequest(ticketState.frame,ticketState.cluster,ticketState.method);
    await this.assertConfigurationJob(ticketState.frame, writeMethods.has(ticketState.method));
    if (writeMethods.has(ticketState.method)) await this.assertApprovedNativeRequest(ticket, 'response', result);
    this.chargeResponse(ticketState,result);
    const finish=async()=>{
      const authorized=candidate?await this.workflowCandidateReadPolicy!.authorizeResponse(ticketState.candidateReadToken!,result):await this.hooks!.authorizeResponse(ticketState.value,result);
      await this.assertConfigurationJob(ticketState.frame,writeMethods.has(ticketState.method));return authorized;
    };
    const finalPortal=this.scheduledPortalFinalNativePhase();
    const authorized=finalPortal?await this.runPortalFinalNativePrecheck(finalPortal,finish):await finish();
    this.assertTicketActive(ticket);
    this.tickets.delete(ticket);
    return authorized;
  }
  private chargeResponse(ticket:TicketState,result:any):void{
    this.chargeServiceObservation('response',result);
    const records = Array.isArray(result?.data) ? result.data.length : 0;
    const bytes = Buffer.byteLength(typeof result === 'string' ? result : JSON.stringify(result ?? null), 'utf8');
    for (const frame of this.meteredFrames(ticket.frame,this.ticketValidationMeter(ticket))) {
      const state = this.states.get(frame)!;
      state.bytes += bytes; state.records += records; if (Array.isArray(result?.data)) state.pages++;
      if (state.bytes > frame.limits.maxBytes) this.budgetExceeded(frame,'bytes',frame.limits.maxBytes,state.bytes);
      if (state.records > frame.limits.maxRecords) this.budgetExceeded(frame,'records',frame.limits.maxRecords,state.records);
      if (state.pages > frame.limits.maxPages) this.budgetExceeded(frame,'pages',frame.limits.maxPages,state.pages);
    }
  }
}
