import { ConflictException, ForbiddenException, Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import {randomUUID} from 'node:crypto';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService, type ConfigurationJobExecutionProof } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { grantMatchesEntity } from '../authorization/grant-policy';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { CredentialStoreService } from '../credentials/credential-store.service';
import type { CaptureFence, CaptureGraph, CaptureObject, CaptureOwnership, CaptureReadBudget, ConfigurationAccessAcquireInput,
  ConfigurationAccessHandle, ConfigurationAccessPolicy, ConfigurationRecovery, ConfigurationScope, ConfigurationStorageAccess } from './configuration.types';
import { configurationId, configurationKey, CONFIGURATION_UUID } from './configuration-input';
import { historicalConfigurationAllowed } from './configuration-history-policy';
import {scheduleAuthorityQuery} from './configuration-schedule-queries';
import {ConfigurationOriginService} from './configuration-origin.service';
import type { WorkflowScheduledConfigurationOriginService } from '../workflows/workflow-scheduled-configuration-origin.service';
import type { WorkflowScheduledConfigurationJobHandle, WorkflowScheduledConfigurationExecutionHandle, WorkflowScheduledConfigurationJobProof, WorkflowScheduledConfigurationCheckpoint } from '../workflows/workflow-scheduled-configuration-origin.types';

interface Authority {
  actor: AuthUser; sessionId: string | null; credentialEpoch: number; permissionVersion: string;
  scope: ConfigurationScope; purpose: ConfigurationAccessAcquireInput['purpose']; module: 'snapshots'|'gitops';
  kindOfJob: string; key: string; expiresAt: number; jobId?: string; leaseGeneration?: number;
  clusterRevision: number; workspaceRevision: number; endpointHmac: string; captureEpoch: string;
  durableIssueId?: string; requestId?: string; ip?: string; scheduleRunId?: string; deckSessionId?: string; receiptOnly?: boolean;
  schedule?:{id:string;version:number;policyHmac:string;scheduledAt:string;registering:boolean};
}
const deny = (code = 'CONFIGURATION_AUTHORITY_REQUIRED') => new ForbiddenException({code, message: '配置操作的当前授权或范围证明无效'});
const changed = (code = 'CONFIGURATION_SOURCE_CHANGED') => new ConflictException({code, message: '配置、身份或范围已变化，请核验原回执后重新预览'});
const childTypes = new Set(['targets','credentials']);
// node-postgres returns SQL005 bigint epochs as decimal strings. The M8
// immutable ledger stores an int4 epoch, so reject overflow before minting a
// handle rather than relying on coercion or a later database error.
function databaseCredentialEpoch(value: unknown): number | null {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^[1-9][0-9]{0,9}$/.test(value))) return null;
  const epoch = typeof value === 'number' ? value : Number(value);
  return Number.isSafeInteger(epoch) && epoch >= 1 && epoch <= 2_147_483_647 ? epoch : null;
}

/** Only this server provider mints handles; copied JSON/UUIDs and old HTTP
 * continuations cannot establish configuration access or approval authority. */
@Injectable()
export class ConfigurationAccessService implements ConfigurationAccessPolicy, OnModuleInit {
  private readonly authorities = new WeakMap<object, Authority>();
  private durablePolicy?:Readonly<{verifyJob(handle:ConfigurationAccessHandle,row:any,phase:string,tx:DbService):Promise<void>;verifyPlan(handle:ConfigurationAccessHandle,row:any,plan:import('./configuration.types').ConfigPlan,tx:DbService):Promise<void>}>;
  installDurableConfigurationPolicy(policy:NonNullable<ConfigurationAccessService['durablePolicy']>):void{
    if(this.durablePolicy||!policy||typeof policy.verifyJob!=='function'||typeof policy.verifyPlan!=='function')throw deny('CONFIGURATION_DURABLE_POLICY_ALREADY_INSTALLED');
    this.durablePolicy=Object.freeze({verifyJob:policy.verifyJob.bind(policy),verifyPlan:policy.verifyPlan.bind(policy)});
  }
  private async durableJob(handle:ConfigurationAccessHandle,row:any,phase:string,tx:DbService):Promise<void>{
    if(row.authority_domain==null&&row.durable_issue_id==null)return;
    if(!this.durablePolicy)throw deny('CONFIGURATION_DURABLE_POLICY_UNAVAILABLE');
    await this.durablePolicy.verifyJob(handle,row,phase,tx);this.state(handle).durableIssueId=row.durable_issue_id;
  }
  async verifyDurablePlan(handle:ConfigurationAccessHandle,row:any,plan:import('./configuration.types').ConfigPlan,tx:DbService):Promise<void>{
    if(row.authority_domain==null&&row.durable_issue_id==null&&plan.durableRef===undefined&&!this.state(handle).durableIssueId)return;
    if(!this.durablePolicy)throw deny('CONFIGURATION_DURABLE_POLICY_UNAVAILABLE');await this.durablePolicy.verifyPlan(handle,row,plan,tx);
  }
  private scheduledOrigin?: WorkflowScheduledConfigurationOriginService;
  private readonly scheduledJobs = new WeakMap<object, { originalJobHandle: WorkflowScheduledConfigurationJobHandle; namespaceHandle: object; authoringSessionId: string }>();
  private readonly scheduledExecutions = new AsyncLocalStorage<{ handle: ConfigurationAccessHandle; originalExecutionHandle: WorkflowScheduledConfigurationExecutionHandle }>();
  /** Bootstrap-only adapter. Absence never falls back to HTTP authority. */
  installWorkflowScheduledConfigurationOrigin(origin: WorkflowScheduledConfigurationOriginService): void {
    if (this.scheduledOrigin || !origin || ['verifyJobHandle', 'verifyConfigurationExecution', 'verifyOriginalExecutionAndJob', 'runOriginalConfigurationExecution', 'currentOriginalJobHandle'].some(key => typeof (origin as any)[key] !== 'function'))
      throw deny('CONFIGURATION_SCHEDULE_ORIGIN_ALREADY_INSTALLED');
    this.scheduledOrigin = origin;
  }
  isWorkflowScheduledConfigurationJob(handle: ConfigurationAccessHandle): boolean { this.state(handle); return this.scheduledJobs.has(handle); }
  originalWorkflowScheduledConfigurationJobHandle(handle: ConfigurationAccessHandle): WorkflowScheduledConfigurationJobHandle {
    this.state(handle); const scheduled = this.scheduledJobs.get(handle);
    if (!scheduled || this.execution.requireWorkflowScheduledNamespaceHandle() !== scheduled.namespaceHandle) throw deny('CONFIGURATION_SCHEDULE_ORIGINAL_JOB_REQUIRED');
    return scheduled.originalJobHandle;
  }
  /** One step/packet checkpoint occurrence per configuration job step: the
   * first caller (storage authorize, failure ledger, verifier load, handle
   * verification) performs the complete fresh origin checkpoint for every
   * party; later callers inside the SAME step scope reuse that occurrence's
   * proof. before-send, ledger, capture and claim are never consolidated. */
  private readonly executionCheckpoints = new WeakMap<object, Map<string, Promise<any>>>();
  private readonly stepCheckpoints = new WeakMap<object, Map<string, Promise<Readonly<WorkflowScheduledConfigurationJobProof>>>>();
  private async verifyScheduledJob(handle: ConfigurationAccessHandle, phase: string, tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationJobProof>> {
    const nested = this.scheduledExecutions.getStore(), current = this.jobs.getStore();
    const checkpoint = phase === 'packet' ? 'packet' : phase === 'step' && nested ? 'step' : null;
    const owner = this.occurrenceOwner(handle);
    if (!checkpoint || !owner || !nested || nested.handle !== handle)
      return this.verifyScheduledJobFresh(handle, phase, tx);
    let occurrences = this.stepCheckpoints.get(owner);
    if (!occurrences) { occurrences = new Map(); this.stepCheckpoints.set(owner, occurrences); }
    const key = `${checkpoint}:${this.scheduledJobs.get(handle) ? 'scheduled' : 'none'}`;
    let pending = occurrences.get(key);
    if (!pending) {
      pending = this.verifyScheduledJobFresh(handle, phase, tx);
      occurrences.set(key, pending);
      pending.catch(() => { if (occurrences!.get(key) === pending) occurrences!.delete(key); });
    }
    const proof = await pending;
    // Reused occurrence: still the exact original handle/namespace/lease.
    const scheduled = this.scheduledJobs.get(handle);
    if (!scheduled || this.execution.requireWorkflowScheduledNamespaceHandle() !== scheduled.namespaceHandle
      || this.scheduledExecutions.getStore() !== nested || this.jobs.getStore() !== current || this.occurrenceOwner(handle) !== owner
      || proof.namespaceHandle !== scheduled.namespaceHandle || proof.expiresAt <= Date.now()) throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
    return proof;
  }
  /** Explicit single-call occurrence (e.g. one approved-verifier load) or the
   * current configuration job step scope; null means always fresh. */
  private readonly occurrences = new AsyncLocalStorage<{handle: ConfigurationAccessHandle; active: boolean}>();
  private occurrenceOwner(handle: ConfigurationAccessHandle): object | null {
    const explicit = this.occurrences.getStore();
    if (explicit?.active && explicit.handle === handle) return explicit;
    const current = this.jobs.getStore();
    return current?.jobStepId && current.handle === handle ? current : null;
  }
  async runCheckpointOccurrence<T>(fn: () => Promise<T>): Promise<T> {
    const current = this.jobs.getStore();
    const outer = this.occurrences.getStore();
    if (!current || !this.scheduledJobs.has(current.handle) || outer?.active && outer.handle === current.handle) return fn();
    const occurrence = { handle: current.handle, active: true };
    try { return await this.occurrences.run(occurrence, fn); } finally { occurrence.active = false; this.stepCheckpoints.delete(occurrence); }
  }
  private async verifyScheduledJobFresh(handle: ConfigurationAccessHandle, phase: string, tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationJobProof>> {
    const scheduled = this.scheduledJobs.get(handle), state = this.state(handle);
    if (!scheduled || !this.scheduledOrigin || this.execution.requireWorkflowScheduledNamespaceHandle() !== scheduled.namespaceHandle) throw deny('CONFIGURATION_SCHEDULE_ORIGINAL_JOB_REQUIRED');
    const nested = this.scheduledExecutions.getStore();
    if (nested && nested.handle !== handle) throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
    const checkpoint: WorkflowScheduledConfigurationCheckpoint = phase === 'before-send' ? 'before-send' : phase === 'packet' ? 'packet'
      : phase === 'step' && nested ? 'step' : ['capture-page', 'seal'].includes(phase) ? 'capture' : 'ledger';
    let proof: Readonly<WorkflowScheduledConfigurationJobProof>;
    if (checkpoint === 'step' || checkpoint === 'packet' || checkpoint === 'before-send') {
      if (!nested) throw deny('CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
      const frame = this.execution.current(), origin = this.scheduledOrigin;
      const assertOriginal = () => {
        if (this.state(handle) !== state || this.scheduledJobs.get(handle) !== scheduled || this.scheduledExecutions.getStore() !== nested
          || this.execution.current() !== frame || this.execution.requireWorkflowScheduledNamespaceHandle() !== scheduled.namespaceHandle
          || this.scheduledOrigin !== origin) throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
      };
      assertOriginal();
      const marker = await tx.one<any>('SELECT required_origin_kind,required_origin_id,required_origin_hmac FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',
        [state.jobId, state.scope.clusterId, state.scope.workspaceId]);
      assertOriginal(); if (!marker) throw deny('CONFIGURATION_SCHEDULE_JOB_PROOF_CHANGED');
      // Origin.material derives sourceOrigin/sourceScopes only from a complete
      // required-origin tuple. Unmarked plan refs or SQL origin bindings fail
      // there. Reinspect after selection; any concurrent marker change fails
      // the chosen verifier and never triggers a fallback.
      const marked = marker.required_origin_kind != null || marker.required_origin_id != null || marker.required_origin_hmac != null;
      const promote = marker.required_origin_kind === 'governance-promote'
        && /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(marker.required_origin_id ?? '')
        && /^[a-f\d]{64}$/.test(marker.required_origin_hmac ?? '');
      if (marked && !promote) {
        // Unknown/partial origins stay on the original verifier selected
        // before the group. A selected combined failure never falls back.
        const original = await origin.verifyConfigurationExecution(nested.originalExecutionHandle, checkpoint, tx); assertOriginal();
        if (original.jobHandle !== scheduled.originalJobHandle || original.namespaceHandle !== scheduled.namespaceHandle || original.configurationJobId !== state.jobId)
          throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
        proof = await origin.verifyJobHandle(scheduled.originalJobHandle, checkpoint, tx); assertOriginal();
      } else {
        const pair = await origin.verifyOriginalExecutionAndJob(scheduled.originalJobHandle, nested.originalExecutionHandle, checkpoint, tx); assertOriginal();
        proof = pair.job; const original = pair.execution;
        if (original.origin !== proof.origin || original.sessionId !== null || original.jobHandle !== scheduled.originalJobHandle
          || original.namespaceHandle !== scheduled.namespaceHandle || original.namespaceHandle !== proof.namespaceHandle
          || original.configurationJobId !== state.jobId || original.configurationJobId !== proof.jobId
          || original.configurationPlanId !== proof.planId || original.configurationPlanRevision !== proof.planRevision || original.configurationPlanHash !== proof.planHash
          || original.claimId !== proof.claimId || original.wrapperOriginId !== proof.wrapperOriginId || original.wrapperExecutionId !== proof.wrapperExecutionId
          || original.actorId !== proof.actor.id || original.clusterId !== proof.clusterId || original.workspaceId !== proof.workspaceId
          || original.permissionVersion !== proof.permissionVersion || original.credentialEpoch !== proof.credentialEpoch
          || original.leaseGeneration !== proof.leaseGeneration || original.expiresAt !== proof.expiresAt)
          throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
      }
    } else proof = await this.scheduledOrigin.verifyJobHandle(scheduled.originalJobHandle, checkpoint, tx);
    if (proof.namespaceHandle !== scheduled.namespaceHandle || proof.sessionId !== null || proof.readOnly || proof.actor.id !== state.actor.id
      || proof.jobId !== state.jobId || proof.clusterId !== state.scope.clusterId || proof.workspaceId !== state.scope.workspaceId
      || proof.permissionVersion !== state.permissionVersion || proof.credentialEpoch !== state.credentialEpoch || proof.expiresAt > state.expiresAt)
      throw deny('CONFIGURATION_SCHEDULE_JOB_PROOF_CHANGED');
    return proof;
  }
  async workflowScheduledConfigurationJobProof(handle: ConfigurationAccessHandle, tx = this.db): Promise<Readonly<WorkflowScheduledConfigurationJobProof>> { return this.verifyScheduledJob(handle, 'ledger', tx); }
  async runWorkflowScheduledConfigurationExecution<T>(handle: ConfigurationAccessHandle, executionId: string,
    fn: (originalJobHandle: WorkflowScheduledConfigurationJobHandle, originalExecutionHandle: WorkflowScheduledConfigurationExecutionHandle) => Promise<T>): Promise<T> {
    const originalJobHandle = this.originalWorkflowScheduledConfigurationJobHandle(handle);
    if (!this.scheduledOrigin || this.scheduledExecutions.getStore()) throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
    return this.scheduledOrigin.runOriginalConfigurationExecution(originalJobHandle, executionId, originalExecutionHandle =>
      this.scheduledExecutions.run({ handle, originalExecutionHandle }, () => fn(originalJobHandle, originalExecutionHandle)));
  }
  async workflowScheduledConfigurationExecutionProof(handle: ConfigurationAccessHandle, executionId: string, tx = this.db, checkpoint: 'packet' | 'ledger' = 'packet') {
    const scheduled = this.scheduledJobs.get(handle), nested = this.scheduledExecutions.getStore();
    if (!scheduled || !nested || nested.handle !== handle || !this.scheduledOrigin) throw deny('CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED');
    const owner = checkpoint === 'packet' ? this.occurrenceOwner(handle) : null;
    let proof: Awaited<ReturnType<NonNullable<typeof this.scheduledOrigin>['verifyConfigurationExecution']>>;
    if (owner) {
      let occurrences = this.executionCheckpoints.get(owner);
      if (!occurrences) { occurrences = new Map(); this.executionCheckpoints.set(owner, occurrences); }
      let pending = occurrences.get(executionId);
      if (!pending) { pending = this.scheduledOrigin.verifyConfigurationExecution(nested.originalExecutionHandle, checkpoint, tx); occurrences.set(executionId, pending);
        const map = occurrences, mine = pending; pending.catch(() => { if (map.get(executionId) === mine) map.delete(executionId); }); }
      proof = await pending;
      if (this.occurrenceOwner(handle) !== owner || this.scheduledExecutions.getStore() !== nested || proof.expiresAt <= Date.now()) throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
    } else proof = await this.scheduledOrigin.verifyConfigurationExecution(nested.originalExecutionHandle, checkpoint, tx);
    if (proof.configurationExecutionId !== executionId || proof.configurationJobId !== this.state(handle).jobId || proof.jobHandle !== scheduled.originalJobHandle || proof.namespaceHandle !== scheduled.namespaceHandle) throw deny('CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED');
    return proof;
  }
  private readonly readMeters = new AsyncLocalStorage<{handle: ConfigurationAccessHandle; usage: () => CaptureReadBudget}>();
  private readonly jobs = new AsyncLocalStorage<{handle: ConfigurationAccessHandle; jobId: string; step?: import('./configuration.types').ConfigurationPlanStep; jobStepId?: string}>();
  private readonly verifyingJobs=new AsyncLocalStorage<ConfigurationAccessHandle>();
  constructor(private readonly db: DbService, private readonly secrets: SecretService,
    private readonly authz: AuthorizationService, private readonly workspaces: WorkspaceResolverService,
    private readonly kong: KongService, private readonly execution: KongExecutionContextService,
    private readonly credentials: CredentialStoreService,private readonly origins?:ConfigurationOriginService) {}
  onModuleInit(): void { this.execution.installConfigurationJobPolicy({verifyHandle: handle => this.verifyHandle(handle),beforeNativeSend:async handle=>{
    const state=this.state(handle);if(!state.jobId)return;
    if(this.scheduledJobs.has(handle))await this.verifyScheduledJob(handle as ConfigurationAccessHandle,'before-send');
    const row=await this.db.one<any>('SELECT required_origin_kind FROM configuration_jobs WHERE id=$1',[state.jobId]);
    if(row?.required_origin_kind){if(!this.origins)throw deny('CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE');await this.origins.beforeNativeSend(state.jobId,state.actor.id);}
  }}); }
  private state(handle: unknown): Authority {
    const state = handle && typeof handle === 'object' ? this.authorities.get(handle) : undefined;
    if (!state || state.expiresAt <= Date.now()) throw deny();
    return state;
  }
  private mint(value: Authority): ConfigurationAccessHandle {
    const handle = Object.freeze({}) as ConfigurationAccessHandle;
    this.authorities.set(handle, {...value, actor: Object.freeze({...value.actor}), scope: Object.freeze({...value.scope, rootIds: Object.freeze([...value.scope.rootIds])})});
    return handle;
  }
  private async identity(actorId: string, sid: string | null, db: DbService, lock = false): Promise<{actor: AuthUser; epoch: number; expiresAt: number}> {
    const row = await db.one<any>(`SELECT id,username,super_admin,credential_epoch,force_password_change FROM users
      WHERE id=$1 AND status='active' AND deleted_at IS NULL${lock?' FOR SHARE':''}`, [actorId]);
    const epoch = databaseCredentialEpoch(row?.credential_epoch);
    if (!row || row.force_password_change || epoch === null) throw deny('CONFIGURATION_ACTOR_INACTIVE');
    let expiresAt = Date.now() + 15 * 60_000;
    if (sid) {
      const session = await db.one<any>(`SELECT expires_at,credential_epoch FROM auth_sessions WHERE id=$1 AND user_id=$2
        AND revoked_at IS NULL AND expires_at>now()${lock?' FOR SHARE':''}`, [sid, actorId]);
      if (!session || databaseCredentialEpoch(session.credential_epoch) !== epoch) throw deny('CONFIGURATION_SESSION_EXPIRED');
      expiresAt = Math.min(expiresAt, new Date(session.expires_at).getTime());
    }
    return {actor: {id: row.id, username: row.username, superAdmin: row.super_admin === true}, epoch, expiresAt};
  }
  private async registry(cid: string, wid: string, db: DbService, lock = false): Promise<{cluster: any; workspace: any; scope: string; endpoint: string}> {
    const cluster = await db.one<any>(`SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL${lock?' FOR SHARE':''}`, [cid]);
    const workspace = await db.one<any>(`SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2${lock?' FOR SHARE':''}`, [cid, wid]);
    if (!cluster || !workspace) throw new NotFoundException({code:'CONFIGURATION_SCOPE_NOT_FOUND',message:'所选集群或工作区不存在'});
    if (!/^1\.5\.\d+$/.test(cluster.version ?? '') || ['disabled','incompatible'].includes(cluster.status) || workspace.status !== 'active') throw deny('CONFIGURATION_SCOPE_UNAVAILABLE');
    const scope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
    return {cluster, workspace, scope, endpoint: this.secrets.fingerprint({url:cluster.admin_url,transportScope:scope,version:cluster.version,secret:cluster.connection_secret??null})};
  }
  private async epoch(cid: string, physical: string, db: DbService, lock = false, allowOperationIds: readonly string[] = [], rejectPending = true): Promise<string> {
    if (lock) await db.exec('SELECT pg_advisory_xact_lock(hashtext($1))', [`kongos:metrics-transport:${physical}`]);
    const aliases = await db.query<any>(`SELECT id,admin_url,transport_scope FROM clusters WHERE deleted_at IS NULL ORDER BY id LIMIT 10001${lock?' FOR SHARE':''}`);
    if (aliases.length > 10000) throw changed('CONFIGURATION_CLUSTER_BUDGET');
    const ids = aliases.filter(row => transportScopeFor(row.admin_url,row.transport_scope) === physical).map(row=>row.id);
    if (!ids.includes(cid)) throw deny();
    const fences = await db.one<any>(`SELECT count(*)::text AS count,max(f.created_at)::text AS latest_time,
      (SELECT id::text FROM metrics_write_fences WHERE transport_scope=$1 ORDER BY created_at DESC,id DESC LIMIT 1) AS latest_id,
      count(*) FILTER(WHERE NOT(f.operation_id=ANY($2::uuid[])) AND(m.id IS NULL OR m.transport_scope IS DISTINCT FROM f.transport_scope OR m.state IS NULL OR m.state NOT IN('succeeded','failed')))::text AS unsettled
      FROM metrics_write_fences f LEFT JOIN mutation_operations m ON m.id=f.operation_id AND m.cluster_id=f.cluster_id WHERE f.transport_scope=$1`,[physical,allowOperationIds]);
    const unfinished = await db.one<any>(`SELECT count(*)::text AS count FROM mutation_operations WHERE
      (transport_scope=$1 OR(transport_scope IS NULL AND cluster_id=ANY($2::uuid[]))) AND state IN('pending','running','uncertain')
      AND NOT(id=ANY($3::uuid[]))`,[physical,ids,allowOperationIds]);
    if (!fences || rejectPending && (fences.unsettled !== '0' || unfinished?.count !== '0')) throw changed('CONFIGURATION_NATIVE_CHANGE_PENDING');
    return this.secrets.fingerprint({physical,count:fences.count,time:fences.latest_time,id:fences.latest_id});
  }
  private async moduleAccess(state: Authority, action: 'read'|'write'|'delete' = 'read', tx?: DbService): Promise<void> {
    // Reuse a caller's locked transaction. Borrowing the pool here lets SDK
    // readers waiting on the same session exhaust all ten connections while
    // the lock owner waits for an eleventh to verify current permissions.
    if (state.scope.kind === 'cluster') await this.authz.assertWholeCluster(state.actor,state.scope.clusterId,state.module,action,...(tx?[tx]:[]));
    else if (state.scope.kind === 'workspace') await this.authz.assertWholeWorkspace(state.actor,state.scope.clusterId,state.scope.workspaceId,state.module,action,...(tx?[tx]:[]));
    else await this.authz.assertCluster(state.actor,state.scope.clusterId,state.module,action,state.scope.workspaceId,...(tx?[tx]:[]));
  }
  async acquireJob(input: ConfigurationAccessAcquireInput & {kindOfJob: string; idempotencyKey: string; module?:'snapshots'|'gitops'}): Promise<ConfigurationAccessHandle> {
    const frame = this.execution.current();
    if (!frame.actor || !frame.sessionId || frame.actor.id !== input.actor?.id || frame.clusterId && frame.clusterId !== input.clusterId) throw deny();
    const cid = configurationId(input.clusterId), ws = await this.workspaces.resolve(cid,input.workspaceId), roots = [...(input.rootIds??[])].map(configurationId);
    if (!['cluster','workspace','services'].includes(input.kind) || roots.length > 100 || new Set(roots).size !== roots.length || (input.kind==='services') !== (roots.length>0)
      || !['capture','import','compare','export','apply','rollback','reconcile'].includes(input.kindOfJob)) throw deny('CONFIGURATION_INVALID_SCOPE');
    const key = configurationKey(input.idempotencyKey), identity = await this.identity(input.actor.id,frame.sessionId,this.db), snapshot = await this.authz.snapshot(identity.actor);
    const registry = await this.registry(cid,ws.id,this.db), captureEpoch = await this.epoch(cid,registry.scope,this.db,false,[],input.kindOfJob==='capture');
    const handle = this.mint({actor:snapshot.user,sessionId:frame.sessionId,credentialEpoch:identity.epoch,permissionVersion:snapshot.version,
      scope:{clusterId:cid,workspaceId:ws.id,transportScope:registry.scope,kind:input.kind,rootIds:roots},purpose:input.purpose,module:input.module??'snapshots',
      kindOfJob:input.kindOfJob,key,expiresAt:identity.expiresAt,clusterRevision:registry.cluster.revision,workspaceRevision:registry.workspace.revision,
      endpointHmac:registry.endpoint,captureEpoch,requestId:frame.requestId,ip:frame.ip});
    await this.moduleAccess(this.state(handle),['apply','rollback','import','capture'].includes(input.purpose)?'write':'read');
    return handle;
  }
  private jobModule(row:any):'snapshots'|'gitops'{
    const input=row.input_secret?this.secrets.decrypt<any>(row.input_secret,`configuration-job:${row.id}`):null;
    return input?.action==='metadata'&&input.resourceType==='configuration_gitops_runs'?'gitops':'snapshots';
  }
  async acquire(jobId: string): Promise<ConfigurationAccessHandle> {
    const row = await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[configurationId(jobId)]);
    const frame = this.execution.current();
    if(this.execution.hasWorkflowScheduledNamespace()){
      if(!this.scheduledOrigin)throw deny('CONFIGURATION_SCHEDULE_ORIGIN_UNAVAILABLE');
      return this.acquireWorkflowScheduledConfiguration(row, this.scheduledOrigin.currentOriginalJobHandle());
    }
    if (!row || frame.actor?.id !== row.actor_id || !frame.sessionId || frame.sessionId !== row.origin_session_id
      || frame.clusterId && frame.clusterId !== row.cluster_id || frame.workspaceId && frame.workspaceId !== row.workspace_id) throw deny('CONFIGURATION_JOB_ACCESS_DENIED');
    const handle = await this.acquireJob({actor:frame.actor!,clusterId:row.cluster_id,workspaceId:row.workspace_id,kind:row.scope_kind,rootIds:row.root_ids,
      purpose:row.kind==='reconcile'?'compare':row.kind,kindOfJob:row.kind,idempotencyKey:row.idempotency_key,module:this.jobModule(row)});
    const state = this.state(handle); state.jobId = row.id; state.leaseGeneration = row.lease_generation;
    await this.durableJob(handle,row,'read',this.db);
    state.expiresAt = Math.min(state.expiresAt,new Date(row.authority_expires_at).getTime());
    // Historical receipts stay readable after permission epochs change. Native
    // execution/capture claims remain bound to the original epoch below.
    return handle;
  }
  private async acquireWorkflowScheduledConfiguration(row: any, originalJobHandle: WorkflowScheduledConfigurationJobHandle): Promise<ConfigurationAccessHandle> {
    if (!row || !this.scheduledOrigin || row.origin_type !== 'http' || !CONFIGURATION_UUID.test(row.origin_session_id ?? '')
      || !['apply','rollback'].includes(row.kind) || row.execution_mode !== 'approval' || row.approval_required !== true) throw deny('CONFIGURATION_SCHEDULE_JOB_INVALID');
    const proof = await this.scheduledOrigin.verifyJobHandle(originalJobHandle, 'claim'), frame = this.execution.current();
    if (frame.sessionId != null || frame.actor?.id !== row.actor_id || proof.sessionId !== null || proof.readOnly
      || proof.jobId !== row.id || proof.actor.id !== row.actor_id || proof.clusterId !== row.cluster_id || proof.workspaceId !== row.workspace_id
      || proof.namespaceHandle !== this.execution.requireWorkflowScheduledNamespaceHandle() || proof.planId !== row.plan_id
      || proof.planRevision !== row.plan_revision || proof.planHash !== row.plan_hash) throw deny('CONFIGURATION_SCHEDULE_JOB_INVALID');
    const identity = await this.identity(row.actor_id, null, this.db), snapshot = await this.authz.snapshot(identity.actor), registry = await this.registry(row.cluster_id,row.workspace_id,this.db);
    const deadline = Math.min(proof.expiresAt, new Date(row.authority_expires_at).getTime(), new Date(row.expires_at).getTime());
    if (identity.epoch !== proof.credentialEpoch || snapshot.version !== proof.permissionVersion || row.permission_version !== proof.permissionVersion
      || databaseCredentialEpoch(row.credential_epoch) !== proof.credentialEpoch || registry.scope !== row.transport_scope
      || !Number.isFinite(deadline) || deadline <= Date.now()) throw deny('CONFIGURATION_SCHEDULE_JOB_INVALID');
    const handle = this.mint({actor:snapshot.user,sessionId:null,credentialEpoch:identity.epoch,permissionVersion:snapshot.version,
      scope:{clusterId:row.cluster_id,workspaceId:row.workspace_id,transportScope:registry.scope,kind:row.scope_kind,rootIds:row.root_ids},purpose:row.kind,module:'snapshots',
      kindOfJob:row.kind,key:row.idempotency_key,expiresAt:deadline,jobId:row.id,leaseGeneration:row.lease_generation,
      clusterRevision:registry.cluster.revision,workspaceRevision:registry.workspace.revision,endpointHmac:registry.endpoint,captureEpoch:row.capture_epoch});
    this.scheduledJobs.set(handle,{originalJobHandle,namespaceHandle:proof.namespaceHandle,authoringSessionId:row.origin_session_id});
    await this.durableJob(handle,row,'claim',this.db);
    await this.moduleAccess(this.state(handle),'write'); await this.verifyScheduledJob(handle,'ledger'); return handle;
  }
  /** A new active session can inspect its user's original safe receipt. It
   * cannot renew that job's expired execution or decrypt its native inputs. */
  async acquireReceipt(jobId: string): Promise<ConfigurationAccessHandle> {
    const row=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[configurationId(jobId)]),frame=this.execution.current();
    if(!row||!frame.actor||!frame.sessionId||frame.actor.id!==row.actor_id||frame.clusterId&&frame.clusterId!==row.cluster_id
      ||frame.workspaceId&&frame.workspaceId!==row.workspace_id)throw deny('CONFIGURATION_JOB_ACCESS_DENIED');
    const handle=await this.acquireJob({actor:frame.actor,clusterId:row.cluster_id,workspaceId:row.workspace_id,kind:row.scope_kind,
      rootIds:row.root_ids,purpose:'compare',kindOfJob:'compare',idempotencyKey:row.idempotency_key,module:this.jobModule(row)});
    const state=this.state(handle);state.receiptOnly=true;state.jobId=row.id;state.kindOfJob=row.kind;await this.durableJob(handle,row,'receipt',this.db);
    return handle;
  }
  async acquireReadJob(jobId:string):Promise<ConfigurationAccessHandle>{
    const row=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[configurationId(jobId)]),frame=this.execution.current();
    if(!row||!frame.actor||!frame.sessionId||frame.actor.id!==row.actor_id||frame.sessionId!==row.origin_session_id)throw deny('CONFIGURATION_JOB_ACCESS_DENIED');
    const handle=await this.acquireJob({actor:frame.actor,clusterId:row.cluster_id,workspaceId:row.workspace_id,kind:row.scope_kind,rootIds:row.root_ids,
      purpose:'compare',kindOfJob:'compare',idempotencyKey:row.idempotency_key,module:this.jobModule(row)});
    const state=this.state(handle);state.kindOfJob=row.kind;state.jobId=row.id;state.leaseGeneration=row.lease_generation;await this.durableJob(handle,row,'read',this.db);
    state.expiresAt=Math.min(state.expiresAt,new Date(row.authority_expires_at).getTime());return handle;
  }
  /** Timer-only readonly authority. The locator is re-read against actual
   * policy/owner data; it cannot create a native write or a pretend login. */
  async acquireDueSchedule(locator:{scheduleId:string;clusterId:string;workspaceId:string;ownerUserId:string;version:number;revision:number;scheduledAt:string}):Promise<{handle:ConfigurationAccessHandle;jobId:string;runId:string;name:string;scope:ConfigurationScope}>{
    if(this.execution.peek())throw deny('CONFIGURATION_SCHEDULE_TIMER_REQUIRED');
    const row=await this.db.one<any>(`SELECT s.*,v.scope_kind,v.root_ids,v.policy_hmac FROM config_snapshot_schedules s JOIN config_snapshot_schedule_versions v
      ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=s.current_version
      WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3 AND s.state='active' AND s.purged_at IS NULL AND s.next_run_at<=now()`,[configurationId(locator.scheduleId),configurationId(locator.clusterId),configurationId(locator.workspaceId)]);
    if(!row||row.owner_user_id!==locator.ownerUserId||row.current_version!==locator.version||row.revision!==locator.revision||new Date(row.next_run_at).toISOString()!==locator.scheduledAt)throw changed('CONFIGURATION_SCHEDULE_CHANGED');
    const identity=await this.identity(row.owner_user_id,null,this.db),snapshot=await this.authz.snapshot(identity.actor),registry=await this.registry(row.cluster_id,row.workspace_id,this.db);
    const jobId=randomUUID(),runId=randomUUID(),scope:ConfigurationScope={clusterId:row.cluster_id,workspaceId:row.workspace_id,transportScope:registry.scope,kind:row.scope_kind,rootIds:row.root_ids};
    const handle=this.mint({actor:snapshot.user,sessionId:null,credentialEpoch:identity.epoch,permissionVersion:snapshot.version,scope,purpose:'capture',module:'snapshots',kindOfJob:'capture',
      key:`schedule-${runId}`,expiresAt:identity.expiresAt,jobId,leaseGeneration:1,clusterRevision:registry.cluster.revision,workspaceRevision:registry.workspace.revision,endpointHmac:registry.endpoint,
      captureEpoch:await this.epoch(scope.clusterId,scope.transportScope,this.db),scheduleRunId:runId,requestId:`schedule-${runId}`,schedule:{id:row.id,version:row.current_version,policyHmac:row.policy_hmac,scheduledAt:locator.scheduledAt,registering:true}});
    await this.moduleAccess(this.state(handle),'write');return{handle,jobId,runId,name:row.name,scope};
  }
  async completeScheduleRegistration(handle:ConfigurationAccessHandle):Promise<void>{
    const state=this.state(handle);if(!state.schedule?.registering||!state.jobId)throw deny();
    await this.assertCurrent(handle,{phase:'capture-page',jobId:state.jobId});state.schedule.registering=false;
  }
  async assertCurrent(handle: ConfigurationAccessHandle, input: {phase: string;jobId?: string;scope?: ConfigurationScope;manifestHash?: string}, tx?: DbService): Promise<CaptureFence> {
    const state = this.state(handle), db = tx??this.db, scheduled = this.scheduledJobs.get(handle);
    if(scheduled)await this.verifyScheduledJob(handle,input.phase,db);
    if(state.receiptOnly&&input.phase!=='read')throw deny('CONFIGURATION_RECEIPT_READ_ONLY');
    if(input.phase==='ledger'&&['compare','export'].includes(state.purpose)&&!['compare','export','reconcile'].includes(state.kindOfJob))throw deny('CONFIGURATION_READ_LEDGER_DENIED');
    if (input.scope && canonicalJson(input.scope)!==canonicalJson(state.scope)) throw deny('CONFIGURATION_SCOPE_MISMATCH');
    const frame = this.execution.peek();
    if (frame?.actor && frame.actor.id !== state.actor.id || frame?.sessionId && frame.sessionId !== state.sessionId) throw deny('CONFIGURATION_ACTOR_MISMATCH');
    const identity = await this.identity(state.actor.id,state.sessionId,db,!!tx);
    if (identity.epoch !== state.credentialEpoch) throw deny('CONFIGURATION_CREDENTIALS_CHANGED');
    if (tx) await db.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    const permissionVersion = await this.authz.permissionVersion(identity.actor,...(tx?[tx]:[]));
    if (permissionVersion !== state.permissionVersion) throw deny('CONFIGURATION_PERMISSIONS_CHANGED');
    const registry = await this.registry(state.scope.clusterId,state.scope.workspaceId,db,!!tx);
    if (registry.scope !== state.scope.transportScope || registry.endpoint !== state.endpointHmac) throw changed('SOURCE_SCOPE_CHANGED');
    if(state.schedule){
      if(!['read','capture-page','seal','ledger'].includes(input.phase)||state.sessionId)throw deny('CONFIGURATION_SCHEDULE_READ_ONLY');
      const policy=await db.one<any>(scheduleAuthorityQuery(!!tx),[state.schedule.id,state.scope.clusterId,state.scope.workspaceId]);
      if(!policy||policy.owner_user_id!==state.actor.id||policy.state!=='active'||policy.current_version!==state.schedule.version||policy.policy_hmac!==state.schedule.policyHmac||policy.transport_scope!==state.scope.transportScope)throw deny('CONFIGURATION_SCHEDULE_CHANGED');
      await this.moduleAccess(state,'write',tx);
      if(!state.schedule.registering){const run=await db.one<any>('SELECT job_id,schedule_version,creator_id,state FROM config_snapshot_schedule_runs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND schedule_id=$4',[state.scheduleRunId,state.scope.clusterId,state.scope.workspaceId,state.schedule.id]);
        if(!run||run.job_id!==state.jobId||run.schedule_version!==state.schedule.version||run.creator_id!==state.actor.id||!['running','succeeded','failed'].includes(run.state))throw deny('CONFIGURATION_SCHEDULE_RUN_CHANGED');}
    }
    await this.moduleAccess(state,input.phase==='purge'?'delete':['step','metadata-write'].includes(input.phase)||input.phase==='ledger'&&!['compare','export'].includes(state.purpose)?'write':'read',tx);
    if(state.durableIssueId&&!input.jobId){
      const durableRow=await db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[state.jobId,state.scope.clusterId,state.scope.workspaceId]);
      if(!durableRow)throw deny();await this.durableJob(handle,durableRow,state.receiptOnly?'receipt':input.phase,db);
    }
    let row: any;
    if (input.jobId) {
      row = await db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[input.jobId,state.scope.clusterId,state.scope.workspaceId]);
      if (!row || row.actor_id!==state.actor.id || !state.receiptOnly&&row.origin_session_id!==(scheduled?.authoringSessionId??state.sessionId) || row.idempotency_key!==state.key || row.kind!==state.kindOfJob
        || canonicalJson(row.root_ids)!==canonicalJson(state.scope.rootIds) || row.scope_kind!==state.scope.kind || row.transport_scope!==state.scope.transportScope) throw deny('CONFIGURATION_JOB_BINDING_INVALID');
      if (state.jobId && state.jobId !== row.id) throw deny('CONFIGURATION_JOB_MISMATCH');
      state.jobId = row.id;
      await this.durableJob(handle,row,state.receiptOnly?'receipt':input.phase,db);
      if (['capture-page','seal','step','ledger'].includes(input.phase) && (row.permission_version!==state.permissionVersion || row.credential_epoch!==state.credentialEpoch
        || new Date(row.authority_expires_at).getTime()<=Date.now() || ['cancelled','expired','uncertain','failed'].includes(row.state))) throw deny('CONFIGURATION_JOB_AUTHORITY_EXPIRED');
      if (state.leaseGeneration!==undefined && row.lease_generation!==state.leaseGeneration) throw changed('CONFIGURATION_LEASE_CHANGED');
      state.leaseGeneration = row.lease_generation;
      if(row.required_origin_kind||row.required_origin_id||row.required_origin_hmac){
        if(!this.origins)throw deny('CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE');
        if(scheduled)await this.origins.assertJob(row,input.phase,state.actor.id,db,false);
        else if(this.verifyingJobs.getStore()===handle)await this.origins.assertJobVerifier(row,input.phase,state.actor.id,state.sessionId!,db);
        else await this.origins.assertJob(row,input.phase,state.actor.id,db,state.receiptOnly===true);
      }
    }
    const capturePhase = ['capture-page','seal'].includes(input.phase);
    const own = input.phase==='step' ? await this.currentNativeOperation(handle,db) : [];
    const captureEpoch = await this.epoch(state.scope.clusterId,state.scope.transportScope,db,input.phase==='seal'&&!!tx,own,capturePhase||input.phase==='step');
    if (capturePhase && (captureEpoch!==state.captureEpoch || registry.cluster.revision!==state.clusterRevision || registry.workspace.revision!==state.workspaceRevision)) throw changed('CONFIGURATION_CAPTURE_CHANGED');
    const meter = this.readMeters.getStore();
    const usage = meter?.handle===handle ? meter.usage() : undefined;
    return {actorId:identity.actor.id,sessionId:state.sessionId,permissionVersion,scope:state.scope,expiresAt:Math.min(state.expiresAt,identity.expiresAt),
      captureEpoch,clusterRevision:registry.cluster.revision,workspaceRevision:registry.workspace.revision,credentialEpoch:identity.epoch,
      kongVersion:registry.cluster.version,adapterVersion:'kong-oss-1.5-v1',enabledPlugins:registry.cluster.enabled_plugins??[],...(scheduled?{origin:'pipeline' as const}:state.schedule?{origin:'schedule' as const,scheduleRunId:state.scheduleRunId}:{origin:'http' as const}),
      ...(state.jobId?{jobId:state.jobId,leaseGeneration:state.leaseGeneration}:{}),...(usage?{nativeUsage:{calls:usage.calls,pages:usage.pages,records:usage.records,bytes:usage.bytes}}:{})};
  }
  async assertStorage(handle: ConfigurationAccessHandle, input: Readonly<ConfigurationStorageAccess>, tx: DbService): Promise<CaptureFence> {
    const proof = await this.assertCurrent(handle,input,tx), state=this.state(handle);
    if (input.leaseGeneration!==undefined && input.leaseGeneration!==state.leaseGeneration) throw changed('CONFIGURATION_LEASE_CHANGED');
    if (input.planId) {
      const plan=await tx.one<any>('SELECT * FROM configuration_plans WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[input.planId,state.scope.clusterId,state.scope.workspaceId]);
      if (!plan || plan.transport_scope!==state.scope.transportScope || input.planRevision!==undefined && plan.current_revision!==input.planRevision) throw deny('CONFIGURATION_PLAN_ACCESS_DENIED');
      if (input.planHash && !await tx.one('SELECT plan_id FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',
        [state.scope.clusterId,state.scope.workspaceId,input.planId,input.planRevision,input.planHash])) throw deny('CONFIGURATION_PLAN_CHANGED');
    }
    return proof;
  }
  async runRead<T>(handle: ConfigurationAccessHandle, paths: readonly string[], fn: (usage: () => CaptureReadBudget) => Promise<T>): Promise<T> {
    const state=this.state(handle), startedAt=Date.now(); await this.assertCurrent(handle,{phase:'read'});
    return this.execution.runActor({actor:state.actor,clusterId:state.scope.clusterId,workspaceId:state.scope.workspaceId,module:state.module,action:'read'},()=>
      this.execution.runInternalRead(state.scope.clusterId,'capture',async()=>{
        const usage=()=>Object.freeze({...this.execution.currentUsage(),startedAt});
        return this.readMeters.run({handle,usage},async()=>{
          if (state.scope.kind==='services') for (const id of state.scope.rootIds) {
            const service=await this.kong.request<any>(state.scope.clusterId,'GET',`/services/${id}`);
            this.workspaces.assertMembership(await this.workspaces.listScope(state.scope.clusterId,state.scope.workspaceId),service);
            await this.authz.assertScopedResource(state.actor,state.scope.clusterId,state.module,'read','services',service,state.scope.workspaceId);
            await this.authz.assertEntity(state.actor,state.scope.clusterId,'services','read',service,state.scope.workspaceId);
          }
          const result=await fn(usage);await this.assertCurrent(handle,{phase:'read'});return result;
        });
      },{...(paths.length?{paths}:{}),maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432,timeoutMs:120000,workspaceId:state.scope.workspaceId}));
  }
  async resolveOwnership(handle: ConfigurationAccessHandle, input: Parameters<ConfigurationAccessPolicy['resolveOwnership']>[1]): Promise<CaptureOwnership> {
    const state=this.state(handle);await this.assertCurrent(handle,{phase:'capture-page'});
    if (input.payload.id!==input.nativeId || !CONFIGURATION_UUID.test(input.nativeId)) throw deny('CONFIGURATION_OBJECT_ID_MISMATCH');
    let owner=input.payload;
    if (childTypes.has(input.entityType)) {
      const parentType=input.entityType==='targets'?'upstreams':'consumers', field=input.entityType==='targets'?'upstream':'consumer';
      if (!input.parentId || !CONFIGURATION_UUID.test(input.parentId) || (input.payload[field] as any)?.id!==input.parentId) throw deny('CONFIGURATION_PARENT_MISMATCH');
      // Caller-supplied parent shapes never authorize child ownership.
      owner=await this.kong.request<any>(state.scope.clusterId,'GET',`/${parentType}/${input.parentId}`);
    }
    const resolved=await this.workspaces.classify(state.scope.clusterId,owner.tags);
    if (resolved.state!=='resolved' || !resolved.workspace || resolved.workspace.status!=='active'
      || state.scope.kind!=='cluster' && !input.referenceOnly && resolved.workspace.id!==state.scope.workspaceId) throw deny('CONFIGURATION_OBJECT_SCOPE_MISMATCH');
    await this.authz.assertEntity(state.actor,state.scope.clusterId,input.credentialKind??input.entityType,'read',input.payload,resolved.workspace.id);
    const boundary=await this.managedBoundary(state.scope.transportScope,input);
    return {workspaceId:resolved.workspace.id,workspaceRevision:resolved.workspace.revision,physicalTags:[...(owner.tags as string[]??[])],managedBoundary:boundary};
  }
  async assertObject(handle: ConfigurationAccessHandle, input: Parameters<ConfigurationAccessPolicy['assertObject']>[1]): Promise<void> {
    const state=this.state(handle), type=input.credentialKind??input.entityType;
    if (input.secrets) await this.authz.assertSecretRead(state.actor,state.scope.clusterId,type,input.payload,state.scope.kind==='cluster'?undefined:state.scope.workspaceId);
    else await this.authz.assertEntity(state.actor,state.scope.clusterId,type,'read',input.payload,state.scope.kind==='cluster'?undefined:state.scope.workspaceId);
    await this.assertCurrent(handle,{phase:'read'});
  }
  async freezeRecovery(handle: ConfigurationAccessHandle, input: Parameters<ConfigurationAccessPolicy['freezeRecovery']>[1]): Promise<ConfigurationRecovery> {
    const state=this.state(handle);
    const hasSecrets=canonicalJson(this.secrets.redact(input.payload))!==canonicalJson(input.payload);
    await this.assertObject(handle,{...input,secrets:hasSecrets});
    if (input.payload.ttl!==undefined && input.payload.ttl!==null) return {state:'nonrestorable',blockerCodes:['NATIVE_TTL_EXPIRY_UNKNOWN']};
    if (input.entityType!=='credentials') {
      const payload=structuredClone(input.payload);delete payload.created_at;delete payload.updated_at;
      return {state:'complete',blockerCodes:[],restorePayload:payload};
    }
    if (!input.parentId || !input.credentialKind) throw deny();
    try {
      const restorePayload=await this.credentials.getRestorePayload(state.scope.clusterId,input.parentId,input.credentialKind,input.nativeId,input.payload);
      const source=await this.db.one<any>('SELECT id FROM credential_refs WHERE cluster_id=$1 AND consumer_id=$2 AND credential_type=$3 AND kong_id=$4',[state.scope.clusterId,input.parentId,input.credentialKind,input.nativeId]);
      return {state:'complete',blockerCodes:input.credentialKind==='oauth2'?['OAUTH_CLIENT_ONLY_NO_TOKENS']:[],restorePayload,
        ...(source?{sourceCredentialRefId:source.id}:{}),...(input.credentialKind==='basic-auth'?{sourceHashHmac:this.secrets.fingerprint(input.payload.password)}:{})};
    } catch (error) {
      if (!(error instanceof ConflictException)) throw error;
      return {state:'requires_secret_input',blockerCodes:[input.credentialKind==='basic-auth'?'BASIC_AUTH_NOT_RECOVERABLE':'CREDENTIAL_SECRET_NOT_RECOVERABLE']};
    }
  }
  private async managedBoundary(physical: string, input: {entityType:string;nativeId:string;parentId?:string;payload?:Record<string,unknown>}): Promise<'none'|'portal'|'metrics'> {
    if (await this.db.one(`SELECT id FROM portal_application_grants WHERE transport_scope=$1 AND(consumer_id=$2::uuid OR acl_id=$2::uuid OR consumer_id=$3::uuid)
      UNION ALL SELECT c.id FROM portal_credentials c JOIN portal_application_grants g ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.grant_id
      WHERE g.transport_scope=$1 AND(c.kong_id=$2::uuid OR c.consumer_id=$3::uuid)
      UNION ALL SELECT id FROM portal_publications WHERE transport_scope=$1 AND(service_id=$2::uuid OR acl_plugin_id=$2::uuid OR key_auth_plugin_id=$2::uuid) LIMIT 1`,[physical,input.nativeId,input.parentId??null])) return 'portal';
    if(input.entityType==='plugins'){
      const p=input.payload;
      if(p?.name==='prometheus'&&!p.service&&!p.route&&!p.consumer)return 'metrics';
      if(await this.db.one("SELECT id FROM mutation_operations WHERE transport_scope=$1 AND entity_type='plugins' AND entity_id=$2 AND idempotency_key LIKE 'metrics:%' AND state='succeeded' LIMIT 1",[physical,input.nativeId]))return 'metrics';
      const endpoint=(p?.config as any)?.http_endpoint;
      if(p?.name==='http-log'&&typeof endpoint==='string')try{if(['telemetry-collector','metrics-collector'].includes(new URL(endpoint).hostname))return 'metrics';}catch{/* An invalid captured URI does not establish a managed identity. */}
    }
    return 'none';
  }
  /** A safe read of an immutable graph never grants its secrets or restores
   * deleted IDs. Every entity is checked against current complete grant rows. */
  async assertHistoricalGraph(handle: ConfigurationAccessHandle, graph: CaptureGraph, secretsRequired=false): Promise<void> {
    const state=this.state(handle), snapshot=await this.authz.snapshot(state.actor);
    if (canonicalJson(graph.scope)!==canonicalJson(state.scope)) throw deny('CONFIGURATION_HISTORY_SCOPE_MISMATCH');
    for (const o of graph.objects) {
      const type=o.credentialKind??o.entityType, target={clusterId:state.scope.clusterId,workspaceId:o.objectWorkspaceId,entityType:type,entity:{...o.payload,tags:[...o.ownershipTags]}};
      if (!snapshot.user.superAdmin && !historicalConfigurationAllowed(snapshot.grants,state.scope.clusterId,o,graph.objects)) throw deny('CONFIGURATION_HISTORICAL_ENTITY_DENIED');
      if (secretsRequired && canonicalJson(this.secrets.redact(o.payload))!==canonicalJson(o.payload)
        && !snapshot.user.superAdmin && !snapshot.grants.some(g=>grantMatchesEntity(g,'secrets','read',target))) throw deny('CONFIGURATION_HISTORICAL_SECRET_DENIED');
    }
    await this.assertCurrent(handle,{phase:'read'});
  }
  async runJob<T>(handle: ConfigurationAccessHandle, fn: () => Promise<T>): Promise<T> {
    const state=this.state(handle);if(!state.jobId||state.receiptOnly)throw deny('CONFIGURATION_JOB_REQUIRED');
    return this.execution.runConfigurationJob(handle,()=>this.jobs.run({handle,jobId:state.jobId!},fn));
  }
  async runStep<T>(handle: ConfigurationAccessHandle, step: import('./configuration.types').ConfigurationPlanStep, jobStepId: string, fn: () => Promise<T>): Promise<T> {
    const state=this.state(handle), current=this.currentJob();
    if(current.handle!==handle||current.jobId!==state.jobId)throw deny('CONFIGURATION_STEP_CONTEXT_REQUIRED');
    const row=await this.db.one<any>(`SELECT s.*,p.body_hmac,p.before_hmac AS plan_before_hmac,p.native_requests,e.state AS execution_state,j.execution_mode
      FROM configuration_job_steps s JOIN configuration_plan_objects p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id
      AND p.plan_id=s.plan_id AND p.plan_revision=s.plan_revision AND p.plan_hash=s.plan_hash AND p.step_id=s.plan_step_id
      JOIN configuration_executions e ON e.id=s.execution_id AND e.job_id=s.job_id AND e.cluster_id=s.cluster_id AND e.workspace_id=s.workspace_id
        AND e.plan_id=s.plan_id AND e.plan_revision=s.plan_revision AND e.plan_hash=s.plan_hash
      JOIN configuration_jobs j ON j.id=s.job_id AND j.plan_id=s.plan_id AND j.plan_revision=s.plan_revision AND j.plan_hash=s.plan_hash
      WHERE s.id=$1 AND s.job_id=$2 AND s.cluster_id=$3 AND s.workspace_id=$4`,[jobStepId,state.jobId,state.scope.clusterId,state.scope.workspaceId]);
    if(!row||row.execution_state!=='executing'||row.state!=='running'||row.plan_step_id!==step.stepId||row.body_hmac!==this.secrets.fingerprint(step.body)
      ||row.plan_before_hmac!==this.secrets.fingerprint(step.before)||row.object_workspace_id!==step.objectWorkspaceId)throw deny('CONFIGURATION_STEP_CHANGED');
    return this.jobs.run({...current,step:structuredClone(step),jobStepId},fn);
  }
  private async currentNativeOperation(handle:ConfigurationAccessHandle,db:DbService):Promise<string[]> {
    const current=this.jobs.getStore(), scope=this.execution.peek()?.operation, state=this.state(handle);
    if(current?.handle!==handle||!current.step||!current.jobStepId||current.jobId!==state.jobId){if(scope)throw deny('CONFIGURATION_NATIVE_STEP_REQUIRED');return [];}
    const step=current.step, key=`configuration-${state.jobId}-${current.jobStepId}`;
    const op=scope?await db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[scope.operationId]):
      await db.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND idempotency_key=$2',[state.scope.clusterId,key]);
    if(!op)return [];
    const row=await db.one<any>(`SELECT s.*,j.execution_mode,e.state AS execution_state FROM configuration_job_steps s
      JOIN configuration_jobs j ON j.id=s.job_id AND j.cluster_id=s.cluster_id AND j.workspace_id=s.workspace_id
        AND j.plan_id=s.plan_id AND j.plan_revision=s.plan_revision AND j.plan_hash=s.plan_hash
      JOIN configuration_executions e ON e.id=s.execution_id AND e.job_id=s.job_id AND e.cluster_id=s.cluster_id AND e.workspace_id=s.workspace_id
        AND e.plan_id=s.plan_id AND e.plan_revision=s.plan_revision AND e.plan_hash=s.plan_hash
      WHERE s.id=$1 AND s.job_id=$2 AND s.cluster_id=$3 AND s.workspace_id=$4`,[current.jobStepId,state.jobId,state.scope.clusterId,state.scope.workspaceId]);
    if(!row||row.state!=='running'||row.execution_state!=='executing'||row.plan_step_id!==step.stepId||row.object_workspace_id!==step.objectWorkspaceId)throw deny('CONFIGURATION_NATIVE_STEP_CHANGED');
    const v2=['configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'];
    const v1=['workflow_execution_id','workflow_step_id','workflow_plan_revision','workflow_plan_hash'];
    if(row.execution_mode==='approval'){
      if(row.operation_id!==op.id||op.configuration_job_id!==row.job_id||op.configuration_execution_id!==row.execution_id||op.configuration_step_id!==row.id
        ||op.configuration_plan_revision!==row.plan_revision||op.configuration_plan_hash!==row.plan_hash||v1.some(k=>op[k]!=null))throw deny('CONFIGURATION_NATIVE_BINDING_CHANGED');
    }else if(row.execution_mode!=='direct'||[...v1,...v2].some(k=>op[k]!=null))throw deny('CONFIGURATION_NATIVE_BINDING_CHANGED');
    const expectedId=step.mutationAction==='create'?step.allocatedNativeId:step.nativeId;
    const targetAppend=step.entityType==='targets'&&step.mutationAction==='update'&&op.remote_completed===true&&op.entity_id===step.allocatedNativeId;
    if(!op||!['running','succeeded'].includes(op.state)||op.actor_id!==state.actor.id||op.cluster_id!==state.scope.clusterId||op.transport_scope!==state.scope.transportScope
      ||op.workspace_id!==step.objectWorkspaceId||op.entity_type!==step.entityType||op.entity_id!==expectedId&&!targetAppend||op.action!==step.mutationAction
      ||op.idempotency_key!==key||op.parent_id!==(step.parentId??null)||op.credential_kind!==(step.credentialKind??null)
      ||!op.payload_secret||this.secrets.fingerprint(this.secrets.decrypt(op.payload_secret,`mutation:${op.id}:payload`))!==step.bodyHmac
      ||this.secrets.fingerprint(op.before_secret?this.secrets.decrypt(op.before_secret,`mutation:${op.id}:before`):null)!==step.beforeHmac)throw deny('CONFIGURATION_NATIVE_OPERATION_MISMATCH');
    return op.state==='running'?[op.id]:[];
  }
  async description(handle:ConfigurationAccessHandle):Promise<Readonly<Authority>> {await this.assertCurrent(handle,{phase:'read'});return Object.freeze({...this.state(handle)});}
  async verifyHandle(handle: unknown): Promise<ConfigurationJobExecutionProof> {
    const state=this.state(handle);if(!state.jobId)throw deny('CONFIGURATION_JOB_REQUIRED');
    const scheduled=this.scheduledJobs.get(handle as ConfigurationAccessHandle);
    const proof=await this.verifyingJobs.run(handle as ConfigurationAccessHandle,()=>this.assertCurrent(handle as ConfigurationAccessHandle,{phase:['apply','rollback'].includes(state.purpose)?'step':'read',...(state.schedule?.registering?{}:{jobId:state.jobId})}));
    if(scheduled){const original=await this.verifyScheduledJob(handle as ConfigurationAccessHandle,'packet');
      return Object.freeze({...original,originalScheduledJobHandle:scheduled.originalJobHandle});}
    return {actor:state.actor,sessionId:state.sessionId,clusterId:state.scope.clusterId,workspaceId:state.scope.workspaceId,module:state.module,purpose:state.purpose,
      jobId:state.jobId,permissionVersion:proof.permissionVersion,credentialEpoch:proof.credentialEpoch,leaseGeneration:state.leaseGeneration!,expiresAt:proof.expiresAt,
      readOnly:!['apply','rollback'].includes(state.purpose),requestId:state.requestId,ip:state.ip,idempotencyKey:state.key};
  }
  currentJob(): {handle: ConfigurationAccessHandle;jobId:string} {
    const job=this.jobs.getStore();if(!job)throw deny('CONFIGURATION_JOB_CONTEXT_REQUIRED');return job;
  }
}
