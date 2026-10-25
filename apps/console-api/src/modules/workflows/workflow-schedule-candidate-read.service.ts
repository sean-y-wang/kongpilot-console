import { BadRequestException, ConflictException, ForbiddenException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongExecutionContextService, type KongExecutionFrame } from '../../infrastructure/kong/execution-context.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath, validateQuery, entityForPath, ENTITIES } from '../../infrastructure/kong/policy';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { validGrant, coarseGrantMatches } from '../authorization/grant-policy';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowScheduleRepository, assertWorkflowScheduledPlan } from './workflow-schedule.repository';
import { WorkflowCandidatesService } from './workflow-candidates.service';
import { normalizeWorkflowApprovalPolicy } from './workflow-approval-policy';
import { sortByFreshFingerprint } from './workflow-fresh-fingerprint-sort';
import type { ScheduledReadAbsentObservationVerifier } from '../../infrastructure/kong/scheduled-read-absent-transport.types';
import { hasObservedAbsenceWitness, isKongPointNotFound } from './workflow-read-absence-witness';
import { isServiceHostReferencePoint, isServiceHostTargetCollection } from './workflow-service-host-reference';
import type { WorkflowCandidateManifest, WorkflowFrozenCandidate } from './workflow-approval.types';
import type { WorkflowScheduledPlanV1, WorkflowScheduleStored } from './workflow-schedule.contract';
import type { WorkflowScheduledBusinessKind } from './workflow-scheduled-authority.types';
import type { WorkflowScheduleCandidateBusinessPolicy, WorkflowScheduleCandidateContextRunner, WorkflowScheduleCandidatePrincipal,
  WorkflowScheduleCandidateReadInput, WorkflowScheduleCandidateReadProof, WorkflowScheduleCandidateReadResource, WorkflowScheduleCandidateReadScope,
  WorkflowScheduleCandidateRequest, WorkflowScheduleCandidateRole, WorkflowScheduledParentAbsencePolicy,
  WorkflowScheduledFutureChildAbsenceWitness, WorkflowScheduleCandidateFixedReader,
  WorkflowScheduleCandidateFixedGroup } from './workflow-schedule-candidate-read.types';

const denied = (code: string) => new ForbiddenException({ code });
const changed = (code: string) => new ConflictException({ code });
const unavailable = (code: string) => new ServiceUnavailableException({ code });
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex = /^[a-f\d]{64}$/;
const kinds = ['configuration_v2', 'portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'];
const ceilings = { maxCalls: 500, maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024 };
type Registry = WorkflowScheduleCandidateReadProof['registries'][number] & { adminOrigin: string };
interface Cursor { started: boolean; complete: boolean; pending: boolean; next: string | null; offsets: Set<string>; ids: Set<string> }
interface ReadState {
  active: boolean; failed: boolean; readonly actorId: string; readonly role: WorkflowScheduleCandidateRole; readonly plan: Readonly<WorkflowScheduledPlanV1>;
  readonly digest: string; readonly proof: Readonly<WorkflowScheduleCandidateReadProof>; readonly expiresAt: number;
  readonly transaction?: DbService; readonly cursors: Map<string, Cursor>; readonly seen: Set<string>;
  httpAcceptance?:Readonly<{frame:Readonly<KongExecutionFrame>;digest:string}>;
  readonly trueEofs:Set<string>;readonly presentPoints:Set<string>;readonly observedAbsences:Set<string>;readonly sdkObservedAbsences:Set<string>;readonly pendingRequests:Set<object>;
  calls: number; pages: number; records: number; bytes: number;
  readonly fixed?: FixedGroupState;
}
interface FixedGroupState {
  readonly reader: Readonly<WorkflowScheduleCandidateFixedReader>; readonly parentFrame: Readonly<KongExecutionFrame>;
  readonly input: Readonly<WorkflowScheduleCandidateReadInput>; readonly executor: Readonly<WorkflowScheduleCandidatePrincipal>;
  readonly workflowBinding: string; readonly frozen: string; readonly membership: string; readonly registries: readonly Registry[];
  phase: 'issued' | 'entered' | 'reading' | 'closing' | 'sealed'; readFrame?: Readonly<KongExecutionFrame>; pendingChecks: number;
}
interface RequestState { readonly handle: object; readonly state: ReadState; readonly resource: Readonly<WorkflowScheduleCandidateReadResource>; readonly request: Readonly<WorkflowScheduleCandidateRequest>; active: boolean }

/** Independent, short, original READ capability. It never calls runActor,
 * uses a browser SID, borrows Entity/M8 namespaces, creates a scheduled claim,
 * source or write permit. Root installs its genuine Context/NativePolicy bridge
 * and fixed business scope/response authorizers; absent adapters stay closed. */
@Injectable()
export class WorkflowScheduleCandidateReadService {
  private readonly handles = new WeakMap<object, ReadState>();
  private readonly requests = new WeakMap<object, RequestState>();
  private readonly policies = new Map<WorkflowScheduledBusinessKind, Readonly<WorkflowScheduleCandidateBusinessPolicy>>();
  private runner?: Readonly<WorkflowScheduleCandidateContextRunner>;
  private checksum?: string;
  private absentResponseVerifier?:Readonly<ScheduledReadAbsentObservationVerifier>;
  private parentAbsencePolicy?:Readonly<WorkflowScheduledParentAbsencePolicy>;
  private fixedReaderInstalled = false;
  private readonly absenceWitnesses=new WeakMap<object,{readonly handle:object;readonly resource:Readonly<WorkflowScheduleCandidateReadResource>}>();
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly context: KongExecutionContextService,
    private readonly plans: WorkflowPlansService, private readonly repository: WorkflowScheduleRepository, private readonly candidates: WorkflowCandidatesService) {}

  installStorageContract(checksum: string): void {
    if (this.checksum || !hex.test(checksum ?? '')) throw new Error('Candidate reads require one exact applied storage contract'); this.checksum = checksum;
  }
  installAbsentResponseVerifier(verifier:ScheduledReadAbsentObservationVerifier):void{
    if(this.absentResponseVerifier||!verifier||typeof verifier.verifyOriginalResponse!=='function')throw new Error('Candidate absence requires one fixed original transport observer');
    this.absentResponseVerifier=Object.freeze({verifyOriginalResponse:verifier.verifyOriginalResponse.bind(verifier)});
  }
  installParentAbsencePolicy(policy:WorkflowScheduledParentAbsencePolicy):void{
    if(this.parentAbsencePolicy||!policy||typeof policy.assertChild!=='function'||Object.keys(policy).some(key=>key!=='assertChild'))
      throw new Error('Candidate child absence requires one fixed current material policy');
    this.parentAbsencePolicy=Object.freeze({assertChild:policy.assertChild.bind(policy)});
  }
  installContextRunner(runner: WorkflowScheduleCandidateContextRunner): void {
    if (this.runner || !runner || typeof runner.assertNoFrame !== 'function' || typeof runner.run !== 'function') throw new Error('Candidate reads require one complete fixed Root runner');
    this.runner = Object.freeze({ assertNoFrame: runner.assertNoFrame.bind(runner), run: runner.run.bind(runner) });
  }
  /** Only Root retains this void closure. Public generic callbacks cannot opt
   * into its shorter metadata checkpoints or choose its GET resources. */
  installFixedReader(reader: WorkflowScheduleCandidateFixedReader): WorkflowScheduleCandidateFixedGroup {
    if (this.fixedReaderInstalled || !reader || typeof reader.read !== 'function' || Object.keys(reader).some(key => key !== 'read'))
      throw new Error('Candidate fixed reader requires one complete Root implementation');
    const fixed = Object.freeze({ read: reader.read.bind(reader) }); this.fixedReaderInstalled = true;
    const run: WorkflowScheduleCandidateFixedGroup = async (plan, actorId, role, tx) => {
      await this.runRead<void>(plan, actorId, role, undefined, tx, fixed);
    };
    return Object.freeze(run);
  }
  installBusinessPolicy(kind: WorkflowScheduledBusinessKind, policy: WorkflowScheduleCandidateBusinessPolicy): void {
    const methods = ['resolveReadScope', 'assertCurrent', 'authorizeResponse'] as const;
    if (!kinds.includes(kind) || this.policies.has(kind) || !policy || methods.some(method => typeof policy[method] !== 'function')
      || Object.keys(policy).some(key => !methods.includes(key as any))) throw new Error('Each candidate business kind requires one complete fixed policy');
    this.policies.set(kind, Object.freeze(Object.fromEntries(methods.map(method => [method, policy[method].bind(policy)]))) as unknown as Readonly<WorkflowScheduleCandidateBusinessPolicy>);
  }
  private policy(kind: string): Readonly<WorkflowScheduleCandidateBusinessPolicy> {
    const policy = this.policies.get(kind as WorkflowScheduledBusinessKind);
    if (!policy) throw unavailable('WORKFLOW_CANDIDATE_BUSINESS_POLICY_UNAVAILABLE'); return policy;
  }
  private key(resource: Pick<WorkflowScheduleCandidateReadResource, 'clusterId' | 'workspaceId' | 'path'>): string { return `${resource.clusterId}:${resource.workspaceId}:${resource.path}`; }
  private canonicalPoint(resource:Readonly<WorkflowScheduleCandidateReadResource>):boolean{
    if(resource.kind!=='point'||!uuid.test(resource.entityId??'')||resource.query)return false;
    const parts=resource.path.split('/').filter(Boolean);
    if(parts.length===2)return resource.parentId===undefined&&parts[1]===resource.entityId
      &&resource.path===`/${parts[0]}/${resource.entityId}`&&(ENTITIES as readonly string[]).includes(parts[0])&&entityForPath(resource.path)===resource.entityType;
    return parts.length===4&&parts[1]===resource.parentId&&uuid.test(resource.parentId??'')&&parts[3]===resource.entityId
      &&resource.path===`/${parts[0]}/${resource.parentId}/${parts[2]}/${resource.entityId}`&&entityForPath(resource.path)===resource.entityType&&(parts[0]==='consumers'&&['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(parts[2])
        ||parts[0]==='upstreams'&&parts[2]==='targets');
  }
  private scopedAbsentPoint(state:ReadState,resource:Readonly<WorkflowScheduleCandidateReadResource>):boolean{
    if(!this.canonicalPoint(resource))return false;
    if(resource.parentId===undefined)return true;
    const parts=resource.path.split('/').filter(Boolean);
    return state.proof.scope.resources.some(parent=>parent.kind==='point'&&parent.clusterId===resource.clusterId&&parent.workspaceId===resource.workspaceId
      &&parent.entityId===resource.parentId&&parent.parentId===undefined&&parent.path===`/${parts[0]}/${resource.parentId}`
      &&this.canonicalPoint(parent)&&state.presentPoints.has(this.key(parent)));
  }
  private state(handle: object): ReadState {
    if (!handle || typeof handle !== 'object' || Array.isArray(handle)) throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED');
    const state = this.handles.get(handle); if (!state?.active) throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED');
    if (state.failed) throw denied('WORKFLOW_CANDIDATE_READ_FAILED'); return state;
  }
  /** A failed authentic read is never recoverable inside this capsule. Caller
   * catch/filtered subsets cannot convert an authorization failure into EOF. */
  private async checked<T>(state: ReadState, fn: () => Promise<T>): Promise<T> {
    if(state.fixed)state.fixed.pendingChecks++;
    try { return await fn(); } catch (error) { state.failed = true; throw error; }
    finally{if(state.fixed)state.fixed.pendingChecks--;}
  }
  assertLive(originalReadHandle: object): void { if (this.state(originalReadHandle).expiresAt <= Date.now()) throw denied('WORKFLOW_CANDIDATE_EXPIRED'); }
  private async principal(actorId: string, tx: DbService): Promise<Readonly<WorkflowScheduleCandidatePrincipal>> {
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const row = await tx.one<any>(`SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
      FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`, [actorId]);
    if (!row || row.id !== actorId || !epoch || row.force_password_change) throw denied('WORKFLOW_CANDIDATE_PRINCIPAL_REVOKED');
    const grants = sortByFreshFingerprint((await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [actorId])).filter(validGrant), row => this.secrets.fingerprint(row));
    return immutableJson({ user: { id: row.id, username: row.username, superAdmin: row.super_admin === true, forcePasswordChange: false,
      displayName: row.display_name, locale: row.locale, timezone: row.timezone, revision: row.revision }, credentialEpoch: String(row.credential_epoch),
      permissionVersion: `${row.id}:${row.permissions_epoch}:${epoch.version}`, grants });
  }
  private async reviewer(stored: WorkflowScheduleStored, principal: WorkflowScheduleCandidatePrincipal, row: any, tx: DbService): Promise<unknown> {
    const p = stored.plan, id = principal.user.id;
    if (p.requester.type === 'console' && p.requester.id === id) throw denied('WORKFLOW_CANDIDATE_REVIEWER_REQUIRED');
    const definition = await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',
      [p.clusterId, p.workspaceId, p.definition.id, p.definition.version]);
    if (!definition || definition.policy_hash !== p.definition.policyHash || this.secrets.fingerprint(definition.policy) !== definition.policy_hash) throw changed('WORKFLOW_CANDIDATE_POLICY_CHANGED');
    if (Number(definition.approval_format) === 1) {
      if (definition.mode !== 'single' || definition.allow_self_approval !== false || definition.policy.version !== 1
        || definition.policy.mode !== 'single' || definition.policy.allowSelfApproval !== false || definition.policy.kind !== p.kind)
        throw changed('WORKFLOW_CANDIDATE_POLICY_CHANGED');
      return { format: 1, currentSubjectRequired: true };
    }
    const policy = normalizeWorkflowApprovalPolicy(definition.policy, p.kind);
    if (row.candidate_version !== null && row.candidate_version !== undefined) {
      const version = await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND candidate_version=$5',
        [p.clusterId, p.workspaceId, p.workflowId, p.planRevision, row.candidate_version]);
      const manifest = version?.manifest as WorkflowCandidateManifest | undefined;
      if (!manifest || this.secrets.fingerprint(manifest) !== version.manifest_hmac || version.manifest_hmac !== row.candidate_manifest_hmac
        || manifest.planHash !== stored.draft.binding.workflowPlanHash || manifest.clusterId !== p.clusterId || manifest.workspaceId !== p.workspaceId
        || manifest.version !== 1 || manifest.workflowId !== p.workflowId || manifest.planRevision !== p.planRevision || manifest.policyHash !== p.definition.policyHash
        || manifest.definitionId !== p.definition.id || manifest.definitionVersion !== p.definition.version || manifest.candidateVersion !== row.candidate_version
        || !Array.isArray(manifest.stages) || manifest.stages.length !== policy.stages.length)
        throw changed('WORKFLOW_CANDIDATE_MANIFEST_INVALID');
      const matching = manifest.stages.flatMap(stage => stage.candidates.filter((candidate: WorkflowFrozenCandidate) => candidate.userId === id));
      for (const candidate of matching) {
        try { await this.candidates.assertCurrent(p, candidate, tx); return { format: 2, candidateVersion: manifest.candidateVersion, candidate }; }
        catch (error) { if (!(error instanceof ForbiddenException)) throw error; }
      }
      throw denied('WORKFLOW_CANDIDATE_REVIEWER_REQUIRED');
    }
    // Before candidate freezing, selection membership is real current SQL.
    // This reader does not recursively resolve candidates or call a reviewer
    // policy that needs the same read context to finish resolving itself.
    const provenance: WorkflowFrozenCandidate['provenance'][number][] = [];
    for (const stage of policy.stages) {
      if (stage.selector.users?.includes(id)) provenance.push({ kind: 'user', selectorId: id });
      for (const teamId of stage.selector.teams ?? []) if (await tx.one(`SELECT 1 FROM team_members m JOIN teams t ON t.id=m.team_id
        WHERE t.id=$1 AND m.user_id=$2 AND t.status='active' AND t.deleted_at IS NULL AND m.status='active'
          AND(t.cluster_id IS NULL OR t.cluster_id=$3) AND(t.workspace_id IS NULL OR t.workspace_id=$4)`, [teamId, id, p.clusterId, p.workspaceId])) provenance.push({ kind: 'team', selectorId: teamId });
      for (const roleId of stage.selector.roles ?? []) for (const grant of principal.grants) if (grant.role_id === roleId && uuid.test(grant.binding_id ?? '')
        && ['user', 'team'].includes(grant.binding_source ?? '') && (grant.cluster_id === null || grant.cluster_id === p.clusterId)
        && (grant.workspace_id === null || grant.workspace_id === p.workspaceId)) provenance.push({ kind: 'role', selectorId: roleId,
          bindingId: grant.binding_id, bindingSource: grant.binding_source });
    }
    if (!provenance.length) throw denied('WORKFLOW_CANDIDATE_REVIEWER_REQUIRED');
    await this.candidates.assertCurrent(p, { userId: id, credentialEpoch: principal.credentialEpoch, provenance }, tx);
    return { format: 2, selecting: true, provenance };
  }
  private normalizeScope(value: WorkflowScheduleCandidateReadScope, stored: WorkflowScheduleStored): Readonly<WorkflowScheduleCandidateReadScope> {
    if (!value || value.version !== 1 || value.domain!==undefined&&value.domain!=='scoped-points-v1' || !Array.isArray(value.resources) || !value.resources.length || value.resources.length > 500
      || !value.limits || Object.keys(ceilings).some(key => !Number.isSafeInteger((value.limits as any)[key]) || (value.limits as any)[key] < 1 || (value.limits as any)[key] > (ceilings as any)[key]))
      throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
    const b = stored.draft.binding, allowed = new Set([`${b.clusterId}:${b.workspaceId}`, ...b.subjectSeal.sourceScopes.map(s => `${s.clusterId}:${s.workspaceId}`)]), seen = new Set<string>();
    for (const r of value.resources) {
      if (!r || !allowed.has(`${r.clusterId}:${r.workspaceId}`)&&!(value.domain==='scoped-points-v1'&&r.clusterId===b.clusterId) || !uuid.test(r.clusterId) || !uuid.test(r.workspaceId)
        || !['point', 'collection', 'schema'].includes(r.kind) || typeof r.secrets !== 'boolean' || typeof r.path !== 'string' || seen.has(this.key(r))
        || r.required !== undefined && typeof r.required !== 'boolean' || r.allowAbsent !== undefined && (typeof r.allowAbsent !== 'boolean' || r.kind !== 'point')) throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
      assertKongPath('GET', r.path); seen.add(this.key(r));
      const parts = r.path.split('/').filter(Boolean);
      const hostPoint=isServiceHostReferencePoint(r),hostTargets=isServiceHostTargetCollection(r);
      if(r.serviceHostReference!==undefined&&!hostPoint&&!hostTargets)throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
      if (r.kind === 'schema') {
        if (!(parts[0] === 'schemas' && parts.length === 2 || parts[0] === 'plugins' && parts[1] === 'schema' && parts.length === 3) || r.secrets || r.query) throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
      } else {
        if (!(ENTITIES as readonly string[]).includes(parts[0]) || !hostPoint&&(parts.includes('enabled') || parts.includes('health')) || entityForPath(r.path) !== r.entityType) throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
        if (r.kind === 'point' && !hostPoint&&(!uuid.test(r.entityId ?? '') || r.query) || r.parentId !== undefined && !uuid.test(r.parentId)) throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
        if(value.domain==='scoped-points-v1'&&r.kind==='point'&&!hostPoint&&!this.canonicalPoint(r))throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
        if (r.kind === 'collection' && (!r.query || !Number.isSafeInteger(r.query.size) || r.query.size < 1 || r.query.size > 100
          || Object.keys(r.query).some(key => !['size', 'tags'].includes(key)))) throw denied('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID');
        if (r.kind === 'collection') validateQuery(r.query as Record<string, string | number>);
      }
    }
    return immutableJson(value);
  }
  private async current(plan: WorkflowScheduledPlanV1, actorId: string, role: WorkflowScheduleCandidateRole, tx: DbService): Promise<{
    input: WorkflowScheduleCandidateReadInput; scope: Readonly<WorkflowScheduleCandidateReadScope>; registries: readonly Registry[]; digest: string;
    row: any; executor: Readonly<WorkflowScheduleCandidatePrincipal>; membership: unknown }> {
    if (!this.checksum) throw unavailable('WORKFLOW_CANDIDATE_STORAGE_UNAVAILABLE');
    const migration = await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='026_m11_workflow_schedules.sql'");
    if (!migration || migration.checksum !== this.checksum) throw unavailable('WORKFLOW_CANDIDATE_STORAGE_UNAVAILABLE');
    if (!await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE')) throw unavailable('AUTHORIZATION_UNAVAILABLE');
    const loaded = await this.plans.load(plan.clusterId, plan.workspaceId, plan.workflowId, tx);
    if (this.secrets.fingerprint(loaded.plan) !== this.secrets.fingerprint(plan) || !['pending', 'approved', 'executing'].includes(loaded.row.state)) throw changed('WORKFLOW_CANDIDATE_PLAN_CHANGED');
    const stored = await this.repository.inspectStored(plan.scheduling.scheduleId, tx); assertWorkflowScheduledPlan(plan, stored.draft, this.secrets);
    if (Date.parse(plan.expiresAt) <= Date.now() || Date.parse(stored.draft.delegation.expiresAt) <= Date.now()) throw denied('WORKFLOW_CANDIDATE_EXPIRED');
    if (this.secrets.fingerprint(await this.plans.definition(plan.clusterId, plan.workspaceId, plan.kind, tx)) !== this.secrets.fingerprint(plan.definition)) throw changed('WORKFLOW_CANDIDATE_POLICY_CHANGED');
    const principal = await this.principal(actorId, tx), owner = await this.principal(stored.draft.delegation.executorId, tx);
    if (owner.credentialEpoch !== stored.draft.delegation.executorCredentialEpoch || stored.draft.delegation.ownerId !== owner.user.id) throw denied('WORKFLOW_CANDIDATE_EXECUTOR_REVOKED');
    const requester = stored.draft.binding.requester;
    if (requester.type === 'developer') {
      const row = await tx.one<any>(`SELECT credential_epoch,must_change_password FROM portal_developers WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3
        AND status='active' AND deleted_at IS NULL AND NOT must_change_password`, [plan.clusterId, plan.workspaceId, requester.id]);
      if (!row || row.must_change_password || String(row.credential_epoch) !== requester.credentialEpoch) throw denied('WORKFLOW_CANDIDATE_REQUESTER_REVOKED');
    } else if (requester.id !== owner.user.id || requester.credentialEpoch !== owner.credentialEpoch) throw denied('WORKFLOW_CANDIDATE_REQUESTER_REVOKED');
    if (role === 'executor' && actorId !== owner.user.id) throw denied('WORKFLOW_CANDIDATE_EXECUTOR_REQUIRED');
    const membership = role === 'reviewer' ? await this.reviewer(stored, principal, loaded.row, tx) : { executor: true };
    const input: WorkflowScheduleCandidateReadInput = { plan: immutableJson(plan), draft: immutableJson(stored.draft), role, principal, transaction: tx };
    const policy = this.policy(plan.kind); await policy.assertCurrent(input);
    const scope = this.normalizeScope(await policy.resolveReadScope(input), stored), registries: Registry[] = [];
    for (const resource of scope.resources) {
      if (registries.some(r => r.clusterId === resource.clusterId && r.workspaceId === resource.workspaceId)) continue;
      const cluster = await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL', [resource.clusterId]);
      const workspace = await tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL', [resource.workspaceId, resource.clusterId]);
      if (!cluster || !workspace || ['disabled', 'incompatible'].includes(cluster.status) || !/^1\.5\.\d+$/.test(cluster.version ?? '') || workspace.status !== 'active') throw changed('WORKFLOW_CANDIDATE_SCOPE_CHANGED');
      const transportScope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
      if (resource.clusterId === plan.clusterId && resource.workspaceId === plan.workspaceId && (cluster.revision !== plan.scope.clusterRevision
        || workspace.revision !== plan.scope.workspaceRevision || cluster.execution_mode !== plan.executionMode || transportScope !== plan.scope.transportScope)) throw changed('WORKFLOW_CANDIDATE_SCOPE_CHANGED');
      registries.push({ clusterId: resource.clusterId, workspaceId: resource.workspaceId, transportScope, clusterRevision: cluster.revision, workspaceRevision: workspace.revision,
        adminOrigin: new URL(cluster.admin_url).origin, endpointHmac: this.secrets.fingerprint({ endpoint: cluster.admin_url, credential: cluster.connection_secret ?? null, version: cluster.version, transportScope }) });
    }
    const after = await this.principal(actorId, tx); if (this.secrets.fingerprint(after) !== this.secrets.fingerprint(principal)) throw denied('WORKFLOW_CANDIDATE_PERMISSIONS_CHANGED');
    return { input, scope, registries, row: loaded.row, executor: owner, membership,
      digest: this.secrets.fingerprint({ plan, draft: stored.draft, principal, membership, scope, registries }) };
  }
  async verifyHandle(originalReadHandle: object): Promise<Readonly<WorkflowScheduleCandidateReadProof>> {
    const state = this.state(originalReadHandle);
    if (!state.fixed) return this.verifyCompleteHandle(originalReadHandle);
    return this.checked(state, async () => {
      const group = state.fixed!;
      if (!['issued', 'reading'].includes(group.phase)) throw denied('WORKFLOW_CANDIDATE_FIXED_PHASE_REQUIRED');
      await this.verifyFixedCurrent(originalReadHandle, state);
      if (group.phase === 'issued') group.phase = 'entered';
      return state.proof;
    });
  }
  private async verifyCompleteHandle(originalReadHandle: object): Promise<Readonly<WorkflowScheduleCandidateReadProof>> {
    const state = this.state(originalReadHandle); return this.checked(state, async () => {
    if (state.fixed) this.assertFixedFrame(originalReadHandle, state);
    this.assertLive(originalReadHandle);
    const verify = (tx: DbService) => this.current(state.plan as WorkflowScheduledPlanV1, state.actorId, state.role, tx);
    const current = state.transaction ? await verify(state.transaction) : await this.db.transaction(verify);
    if (state.fixed) this.assertFixedFrame(originalReadHandle, state);
    this.assertLive(originalReadHandle);
    if (current.digest !== state.digest) throw denied('WORKFLOW_CANDIDATE_FACTS_CHANGED'); return state.proof;
    });
  }
  /** SQL-only admission for the fixed Root HTTP-parent hook. The reader keeps
   * its own principal and NULL SID. These original caller facts admit only a
   * linked readonly capsule, never a claim, Namespace or Native packet. */
  async assertOriginalHttpAcceptance(handle:object,actualFrame:Readonly<KongExecutionFrame>):Promise<void>{
    const state=this.state(handle);return this.checked(state,async()=>{
      this.context.requireWorkflowScheduleCandidateHttpParent(handle,actualFrame);this.assertLive(handle);
      if(state.fixed){
        if(state.fixed.parentFrame!==actualFrame)throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HTTP_PARENT_REQUIRED');
        await this.verifyFixedCurrent(handle,state);return;
      }
      const inspect=async(tx:DbService)=>{
        const current=await this.current(state.plan as WorkflowScheduledPlanV1,state.actorId,state.role,tx);
        if(current.digest!==state.digest)throw denied('WORKFLOW_CANDIDATE_FACTS_CHANGED');
        return this.inspectHttpAcceptance(state,actualFrame,current.input,tx);
      };
      const digest=state.transaction?await inspect(state.transaction):await this.db.transaction(inspect);
      this.context.requireWorkflowScheduleCandidateHttpParent(handle,actualFrame);this.assertLive(handle);
      if(state.httpAcceptance&&(state.httpAcceptance.frame!==actualFrame||state.httpAcceptance.digest!==digest))throw denied('WORKFLOW_CANDIDATE_HTTP_IDENTITY_CHANGED');
      state.httpAcceptance??=Object.freeze({frame:actualFrame,digest});
    });
  }
  /** The generic branch retains Plans.load and its complete Origin checks.
   * Only a private fixed group supplies its freshly bound actual SQL row. */
  private async inspectHttpAcceptance(state:ReadState,actualFrame:Readonly<KongExecutionFrame>,
    input:WorkflowScheduleCandidateReadInput,tx:DbService,fixedRow?:any):Promise<string>{
        const {plan,draft}=input,callerId=actualFrame.actor?.id;
        if(!uuid.test(callerId??'')||!uuid.test(actualFrame.sessionId??'')||actualFrame.clusterId!==plan.clusterId||actualFrame.workspaceId!==plan.workspaceId
          ||actualFrame.module!=='workflows'||!['write','approve'].includes(actualFrame.action??''))throw denied('WORKFLOW_CANDIDATE_HTTP_SCOPE_REQUIRED');
        const caller=await this.principal(callerId!,tx);
        const session=await tx.one<any>(`SELECT s.id AS session_id,s.user_id,s.credential_epoch AS session_credential_epoch,
          u.credential_epoch AS user_credential_epoch,u.permissions_epoch,i.version AS iam_version
          FROM auth_sessions s JOIN users u ON u.id=s.user_id CROSS JOIN iam_epoch i
          WHERE s.id=$1 AND s.user_id=$2 AND i.singleton=true AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
            AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change
          FOR SHARE OF s,u,i`,[actualFrame.sessionId,callerId]);
        if(!session||session.session_id!==actualFrame.sessionId||session.user_id!==callerId
          ||String(session.session_credential_epoch)!==caller.credentialEpoch||String(session.user_credential_epoch)!==caller.credentialEpoch
          ||`${callerId}:${session.permissions_epoch}:${session.iam_version}`!==caller.permissionVersion
          ||actualFrame.actor?.permissionsVersion!==caller.permissionVersion||actualFrame.actor.superAdmin!==caller.user.superAdmin
          ||actualFrame.actor.username!==caller.user.username||actualFrame.actor.forcePasswordChange)
          throw denied('WORKFLOW_CANDIDATE_HTTP_IDENTITY_CHANGED');
        const action=actualFrame.action as 'write'|'approve';
        if(!caller.user.superAdmin&&!caller.grants.some(g=>coarseGrantMatches(g,'workflows',action,{clusterId:plan.clusterId,workspaceId:plan.workspaceId})))
          throw denied('WORKFLOW_CANDIDATE_HTTP_GRANT_REQUIRED');
        let membership:unknown;
        if(action==='write'){
          if(callerId!==draft.delegation.ownerId||callerId!==draft.delegation.executorId
            ||caller.credentialEpoch!==draft.delegation.ownerCredentialEpoch||caller.credentialEpoch!==draft.delegation.executorCredentialEpoch)
            throw denied('WORKFLOW_CANDIDATE_HTTP_OWNER_REQUIRED');
          membership={owner:true};
        }else{
          const loaded=fixedRow?{plan,row:fixedRow}:await this.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId,tx),row=loaded.row;
          if(Number(row.approval_format)!==2||!Number.isSafeInteger(row.candidate_version)||row.candidate_version<1
            ||!hex.test(row.candidate_manifest_hmac??'')||row.plan_hash!==draft.binding.workflowPlanHash
            ||row.plan_revision!==plan.planRevision||this.secrets.fingerprint(loaded.plan)!==this.secrets.fingerprint(plan))
            throw denied('WORKFLOW_CANDIDATE_HTTP_FROZEN_REVIEWER_REQUIRED');
          const eligibility:any=await this.reviewer({plan:state.plan,draft} as WorkflowScheduleStored,caller,row,tx);
          if(eligibility.format!==2||eligibility.candidateVersion!==row.candidate_version||!eligibility.candidate)
            throw denied('WORKFLOW_CANDIDATE_HTTP_FROZEN_REVIEWER_REQUIRED');
          const version=await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND candidate_version=$5',
            [plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,row.candidate_version]);
          const votes=await tx.query<any>('SELECT * FROM workflow_approvals WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND approver_id=$5 ORDER BY level,id',
            [plan.workflowId,plan.clusterId,plan.workspaceId,plan.planRevision,callerId]);
          if(!version?.manifest||version.manifest_hmac!==row.candidate_manifest_hmac||this.secrets.fingerprint(version.manifest)!==row.candidate_manifest_hmac||!votes.length)
            throw denied('WORKFLOW_CANDIDATE_HTTP_APPROVED_REVIEWER_REQUIRED');
          for(const vote of votes){
            const stage=version.manifest.stages.find((s:any)=>s.level===vote.level),candidate=stage?.candidates.find((c:any)=>c.userId===callerId);
            if(!uuid.test(vote.id??'')||vote.approver_id!==callerId||vote.decision!=='approve'||vote.plan_hash!==draft.binding.workflowPlanHash
              ||vote.candidate_version!==row.candidate_version||vote.candidate_manifest_hmac!==row.candidate_manifest_hmac||!candidate)
              throw denied('WORKFLOW_CANDIDATE_HTTP_APPROVED_REVIEWER_REQUIRED');
            await this.candidates.assertCurrent(plan,candidate,tx);
          }
          membership={eligibility,votes};
        }
        const after=await this.principal(callerId!,tx);
        if(this.secrets.fingerprint(after)!==this.secrets.fingerprint(caller))throw denied('WORKFLOW_CANDIDATE_HTTP_IDENTITY_CHANGED');
        return this.secrets.fingerprint({planHash:state.proof.workflowPlanHash,caller,session,membership,clusterId:plan.clusterId,workspaceId:plan.workspaceId,action});
  }
  private acceptHttpDigest(state:ReadState,actualFrame:Readonly<KongExecutionFrame>,digest:string):void{
    if(state.httpAcceptance&&(state.httpAcceptance.frame!==actualFrame||state.httpAcceptance.digest!==digest))
      throw denied('WORKFLOW_CANDIDATE_HTTP_IDENTITY_CHANGED');
    state.httpAcceptance??=Object.freeze({frame:actualFrame,digest});
  }
  private workflowBinding(row:any):string{
    const keys=['id','cluster_id','workspace_id','kind','subject_type','subject_id','requester_type','requester_user_id','requester_developer_id',
      'definition_id','definition_version','plan_revision','plan_hash','execution_mode','approval_required','approval_format','candidate_version','candidate_manifest_hmac','expires_at'];
    return this.secrets.fingerprint(Object.fromEntries(keys.map(key=>[key,row?.[key]])));
  }
  private fixedRow(plan:Readonly<WorkflowScheduledPlanV1>,draft:WorkflowScheduleCandidateReadInput['draft'],row:any):boolean{
    return !!row&&row.id===plan.workflowId&&row.cluster_id===plan.clusterId&&row.workspace_id===plan.workspaceId
      &&row.kind==='configuration_v2'&&row.subject_type===plan.subject.type&&row.subject_id===plan.subject.id
      &&row.requester_type==='console'&&plan.requester.type==='console'&&row.requester_user_id===plan.requester.id&&row.requester_developer_id===null
      &&row.definition_id===plan.definition.id&&row.definition_version===plan.definition.version&&row.plan_revision===plan.planRevision
      &&row.plan_hash===draft.binding.workflowPlanHash&&row.execution_mode===plan.executionMode&&row.approval_required===true
      &&Number(row.approval_format)===2&&Number.isSafeInteger(row.candidate_version)&&row.candidate_version>0&&hex.test(row.candidate_manifest_hmac??'')
      &&Number.isFinite(Date.parse(row.expires_at))&&new Date(row.expires_at).toISOString()===plan.expiresAt
      &&['pending','approved','executing'].includes(row.state);
  }
  private async frozenFacts(input:WorkflowScheduleCandidateReadInput,row:any,tx:DbService):Promise<string>{
    const p=input.plan,definition=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',
      [p.clusterId,p.workspaceId,p.definition.id,p.definition.version]);
    if(!definition||Number(definition.approval_format)!==2||definition.policy_hash!==p.definition.policyHash
      ||this.secrets.fingerprint(definition.policy)!==definition.policy_hash)throw changed('WORKFLOW_CANDIDATE_POLICY_CHANGED');
    const policy=normalizeWorkflowApprovalPolicy(definition.policy,p.kind);
    const version=await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND candidate_version=$5',
      [p.clusterId,p.workspaceId,p.workflowId,p.planRevision,row.candidate_version]);
    const manifest=version?.manifest as WorkflowCandidateManifest|undefined;
    if(!manifest||manifest.version!==1||this.secrets.fingerprint(manifest)!==version.manifest_hmac||version.manifest_hmac!==row.candidate_manifest_hmac
      ||manifest.clusterId!==p.clusterId||manifest.workspaceId!==p.workspaceId||manifest.workflowId!==p.workflowId||manifest.planRevision!==p.planRevision
      ||manifest.planHash!==input.draft.binding.workflowPlanHash||manifest.definitionId!==p.definition.id||manifest.definitionVersion!==p.definition.version
      ||manifest.policyHash!==p.definition.policyHash||manifest.candidateVersion!==row.candidate_version||!Array.isArray(manifest.stages)
      ||manifest.stages.length!==policy.stages.length)throw changed('WORKFLOW_CANDIDATE_MANIFEST_INVALID');
    return this.secrets.fingerprint({definition,version});
  }
  private assertFixedFrame(handle:object,state:ReadState):void{
    this.assertLive(handle);const group=state.fixed;
    if(!group||this.state(handle)!==state)throw denied('WORKFLOW_CANDIDATE_FIXED_ORIGINAL_REQUIRED');
    const frame=this.context.current(),reading=!['issued','entered'].includes(group.phase);
    if(frame!==(reading?group.readFrame:group.parentFrame)||reading&&(frame.kind!=='workflow-candidate-read'||frame.actor!==state.proof.actor||frame.sessionId!=null))
      throw denied('WORKFLOW_CANDIDATE_FIXED_FRAME_CHANGED');
    // Context proves the private original child handle/HTTP-parent association;
    // an equal copied frame or proof actor cannot satisfy this check.
    this.context.requireWorkflowScheduleCandidateHttpParent(handle,group.parentFrame);
  }
  /** A bounded closed GET group rereads complete grant/identity snapshots,
   * selectors, authenticated schedule binding and current endpoint credentials.
   * Full material reconstruction remains at entry, every actual response and
   * explicit closing. This does not promise identical intermediate traces. */
  private async verifyFixedCurrent(handle:object,state:ReadState):Promise<void>{
    const group=state.fixed!;
    const inspect=async(tx:DbService)=>{
      const observed=async<T>(fn:()=>Promise<T>):Promise<T>=>{this.assertFixedFrame(handle,state);const value=await fn();this.assertFixedFrame(handle,state);return value;};
      const migration=await observed(()=>tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='026_m11_workflow_schedules.sql'"));
      if(!this.checksum||migration?.checksum!==this.checksum)throw unavailable('WORKFLOW_CANDIDATE_STORAGE_UNAVAILABLE');
      if(!await observed(()=>tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE')))throw unavailable('AUTHORIZATION_UNAVAILABLE');
      const row=await observed(()=>tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',
        [state.plan.workflowId,state.plan.clusterId,state.plan.workspaceId]));
      if(!this.fixedRow(state.plan,group.input.draft,row)||this.workflowBinding(row)!==group.workflowBinding)throw changed('WORKFLOW_CANDIDATE_PLAN_CHANGED');
      const stored=await observed(()=>this.repository.inspectStored(state.plan.scheduling.scheduleId,tx));
      assertWorkflowScheduledPlan(state.plan,stored.draft,this.secrets);
      if(this.secrets.fingerprint(stored.draft)!==this.secrets.fingerprint(group.input.draft))throw denied('WORKFLOW_CANDIDATE_FACTS_CHANGED');
      if(this.secrets.fingerprint(await observed(()=>this.plans.definition(state.plan.clusterId,state.plan.workspaceId,state.plan.kind,tx)))
        !==this.secrets.fingerprint(state.plan.definition))throw changed('WORKFLOW_CANDIDATE_POLICY_CHANGED');
      const principal=await observed(()=>this.principal(state.actorId,tx));
      const executor=state.actorId===group.executor.user.id?principal:await observed(()=>this.principal(group.executor.user.id,tx));
      const samePrincipals=(actor:WorkflowScheduleCandidatePrincipal,owner:WorkflowScheduleCandidatePrincipal)=>{
        if(this.secrets.fingerprint(actor)!==this.secrets.fingerprint(group.input.principal)||this.secrets.fingerprint(owner)!==this.secrets.fingerprint(group.executor))
          throw denied('WORKFLOW_CANDIDATE_PERMISSIONS_CHANGED');
      };
      samePrincipals(principal,executor);
      const input:WorkflowScheduleCandidateReadInput={...group.input,principal,transaction:tx};
      if(await observed(()=>this.frozenFacts(input,row,tx))!==group.frozen)throw changed('WORKFLOW_CANDIDATE_MANIFEST_INVALID');
      const membership=state.role==='reviewer'?await observed(()=>this.reviewer(stored,principal,row,tx)):{executor:true};
      if(this.secrets.fingerprint(membership)!==group.membership)throw denied('WORKFLOW_CANDIDATE_REVIEWER_REQUIRED');
      for(const original of group.registries){
        const cluster=await observed(()=>tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL',[original.clusterId]));
        const workspace=await observed(()=>tx.one<any>('SELECT * FROM workspaces WHERE id=$1 AND cluster_id=$2 AND deleted_at IS NULL',[original.workspaceId,original.clusterId]));
        if(!cluster||!workspace||cluster.id!==original.clusterId||workspace.id!==original.workspaceId||workspace.cluster_id!==original.clusterId
          ||['disabled','incompatible'].includes(cluster.status)||!/^1\.5\.\d+$/.test(cluster.version??'')||workspace.status!=='active')throw changed('WORKFLOW_CANDIDATE_SCOPE_CHANGED');
        const transportScope=transportScopeFor(cluster.admin_url,cluster.transport_scope);
        if(original.clusterId===state.plan.clusterId&&original.workspaceId===state.plan.workspaceId&&cluster.execution_mode!==state.plan.executionMode)
          throw changed('WORKFLOW_CANDIDATE_SCOPE_CHANGED');
        const registry={clusterId:cluster.id,workspaceId:workspace.id,transportScope,clusterRevision:cluster.revision,workspaceRevision:workspace.revision,
          adminOrigin:new URL(cluster.admin_url).origin,endpointHmac:this.secrets.fingerprint({endpoint:cluster.admin_url,credential:cluster.connection_secret??null,version:cluster.version,transportScope})};
        if(this.secrets.fingerprint(registry)!==this.secrets.fingerprint(original))throw changed('WORKFLOW_CANDIDATE_SCOPE_CHANGED');
      }
      const digest=await observed(()=>this.inspectHttpAcceptance(state,group.parentFrame,input,tx,row));
      this.acceptHttpDigest(state,group.parentFrame,digest);
      const after=await observed(()=>this.principal(state.actorId,tx));
      const ownerAfter=state.actorId===group.executor.user.id?after:await observed(()=>this.principal(group.executor.user.id,tx));
      samePrincipals(after,ownerAfter);
    };
    this.assertFixedFrame(handle,state);
    if(state.transaction)await inspect(state.transaction);else await this.db.transaction(inspect);
    this.assertFixedFrame(handle,state);
  }
  /** Only a genuine accepted original SDK JSON404 can mint this private
   * witness. A derived FK absence, copied projection or caught error cannot. */
  async requireObservedAbsentPoint(handle:object,selected:Readonly<WorkflowScheduleCandidateReadResource>):Promise<object>{
    const state=this.state(handle);return this.checked(state,async()=>{
      await this.verifyHandle(handle);
      if(state.fixed)await this.verifyCompleteHandle(handle);
      const resource=state.proof.scope.resources.find((d=>(r:any)=>this.secrets.fingerprint(r)===d)(this.secrets.fingerprint(selected)));
      if(state.proof.scope.domain!=='scoped-points-v1'||!resource||!this.canonicalPoint(resource)||resource.allowAbsent!==true
        ||!state.sdkObservedAbsences.has(this.key(resource))||!state.seen.has(this.key(resource)))throw denied('WORKFLOW_CANDIDATE_ORIGINAL_ABSENCE_REQUIRED');
      const witness=Object.freeze({});this.absenceWitnesses.set(witness,{handle,resource});return witness;
    });
  }
  /** An absent allocated Consumer/Upstream cannot own persisted credentials
   * or Targets. This records that FK fact without sending a nested GET or
   * inventing an HTTP404, cursor EOF, transport result or Native receipt. */
  async observeFutureChildAbsence(handle:object,selected:Readonly<WorkflowScheduleCandidateReadResource>,originalParentWitness:object):Promise<Readonly<WorkflowScheduledFutureChildAbsenceWitness>>{
    const state=this.state(handle);return this.checked(state,async()=>{
      await this.verifyHandle(handle);
      if(state.fixed)await this.verifyCompleteHandle(handle);
      const witness=this.absenceWitnesses.get(originalParentWitness),child=state.proof.scope.resources.find((d=>(r:any)=>this.secrets.fingerprint(r)===d)(this.secrets.fingerprint(selected)));
      const parent=witness?.resource,parts=child?.path.split('/').filter(Boolean)??[];
      if(state.proof.scope.domain!=='scoped-points-v1'||!this.parentAbsencePolicy||witness?.handle!==handle||!parent||!child
        ||!this.canonicalPoint(child)||child.allowAbsent!==true||child.required!==true||!child.parentId
        ||child.clusterId!==parent.clusterId||child.workspaceId!==parent.workspaceId||!this.canonicalPoint(parent)
        ||parent.entityId!==child.parentId||parent.parentId!==undefined||parent.allowAbsent!==true||parent.required!==true
        ||!state.sdkObservedAbsences.has(this.key(parent))||!state.seen.has(this.key(parent))||state.seen.has(this.key(child))
        ||state.pendingRequests.size||parts.length!==4||parts[1]!==parent.entityId||parts[3]!==child.entityId
        ||!(parts[0]==='consumers'&&['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(parts[2])&&parent.path===`/consumers/${parent.entityId}`
          ||parts[0]==='upstreams'&&parts[2]==='targets'&&parent.path===`/upstreams/${parent.entityId}`))throw denied('WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED');
      const lookup=(tx:DbService)=>this.current(state.plan as WorkflowScheduledPlanV1,state.actorId,state.role,tx);
      const current=state.transaction?await lookup(state.transaction):await this.db.transaction(lookup);
      if(current.digest!==state.digest)throw denied('WORKFLOW_CANDIDATE_FACTS_CHANGED');
      await this.parentAbsencePolicy.assertChild(current.input,child,parent);
      await this.verifyHandle(handle);
      if(state.fixed)await this.verifyCompleteHandle(handle);
      if(state.pendingRequests.size||state.seen.has(this.key(child)))throw denied('WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED');
      if(++state.records>state.proof.scope.limits.maxRecords)throw denied('WORKFLOW_CANDIDATE_READ_BUDGET');
      state.observedAbsences.add(this.key(child));state.seen.add(this.key(child));
      return Object.freeze({kind:'parent-FK-absence',nativeRequestsSent:0});
    });
  }
  async runOriginalPlan<T>(plan: WorkflowScheduledPlanV1, actorId: string, role: WorkflowScheduleCandidateRole,
    fn: (originalReadHandle: object) => Promise<T>, tx?: DbService): Promise<T> {
    return this.runRead(plan,actorId,role,fn,tx);
  }
  private async runRead<T>(plan:WorkflowScheduledPlanV1,actorId:string,role:WorkflowScheduleCandidateRole,
    fn:((originalReadHandle:object)=>Promise<T>)|undefined,tx?:DbService,fixedReader?:Readonly<WorkflowScheduleCandidateFixedReader>):Promise<T>{
    if (!this.runner) throw unavailable('WORKFLOW_CANDIDATE_CONTEXT_UNAVAILABLE');
    if (!plan?.scheduling || !kinds.includes(plan.kind) || !uuid.test(actorId) || !['executor', 'reviewer'].includes(role)
      ||(fixedReader?fn!==undefined||!tx:typeof fn!=='function')||tx&&(typeof tx.one!=='function'||typeof tx.query!=='function'))throw denied('WORKFLOW_CANDIDATE_INPUT_INVALID');
    this.runner.assertNoFrame();const originalParent=this.context.peek();
    if(originalParent!==null){if(typeof this.context.assertWorkflowScheduleCandidateReadAdmission!=='function')throw denied('WORKFLOW_CANDIDATE_EMPTY_CONTEXT_REQUIRED');this.context.assertWorkflowScheduleCandidateReadAdmission();}
    const sealedPlan = immutableJson(plan);
    const resolve = (transaction: DbService) => this.current(sealedPlan, actorId, role, transaction), current = tx ? await resolve(tx) : await this.db.transaction(resolve);
    this.runner.assertNoFrame();if(this.context.peek()!==originalParent)throw denied('WORKFLOW_CANDIDATE_EMPTY_CONTEXT_REQUIRED');
    if(originalParent!==null)this.context.assertWorkflowScheduleCandidateReadAdmission();
    const draft=current.input.draft,windowStart=Date.parse(draft.spec.windowStart),windowEnd=Date.parse(draft.spec.windowEnd),now=Date.now();
    const canFix=!!fixedReader&&!!tx&&originalParent!==null&&sealedPlan.kind==='configuration_v2'&&this.fixedRow(sealedPlan,draft,current.row)
      &&[windowStart,windowEnd,Date.parse(sealedPlan.expiresAt),Date.parse(draft.delegation.expiresAt)].every(Number.isFinite)
      &&new Date(windowStart).toISOString()===draft.spec.windowStart&&new Date(windowEnd).toISOString()===draft.spec.windowEnd
      &&new Date(Date.parse(sealedPlan.expiresAt)).toISOString()===sealedPlan.expiresAt
      &&new Date(Date.parse(draft.delegation.expiresAt)).toISOString()===draft.delegation.expiresAt
      &&windowStart<=now&&now<windowEnd;
    // The full business admission proves W <= all original J1/J0/plan/version
    // deadlines. An immutable E <= W therefore bounds them without renewing
    // any deadline. Mutable material is checked by each response and closing.
    const expiresAt = Math.min(now + 30000, Date.parse(sealedPlan.expiresAt), Date.parse(draft.delegation.expiresAt),canFix?windowEnd:Infinity);
    const handle = Object.freeze({}), proof: WorkflowScheduleCandidateReadProof = immutableJson({ version: 1, origin: 'workflow-schedule-candidate-read', readOnly: true,
      actor: current.input.principal.user, sessionId: null, credentialEpoch: current.input.principal.credentialEpoch, permissionVersion: current.input.principal.permissionVersion,
      workflowId: sealedPlan.workflowId, workflowPlanRevision: sealedPlan.planRevision, workflowPlanHash: current.input.draft.binding.workflowPlanHash,
      scheduleId: sealedPlan.scheduling.scheduleId, role, expiresAt: new Date(expiresAt).toISOString(), scope: current.scope,
      registries: current.registries.map(({ adminOrigin, ...registry }) => registry) });
    const fixed:FixedGroupState|undefined=canFix?{reader:fixedReader!,parentFrame:originalParent!,input:Object.freeze({...current.input}),executor:current.executor,
      workflowBinding:this.workflowBinding(current.row),frozen:await this.frozenFacts(current.input,current.row,tx!),membership:this.secrets.fingerprint(current.membership),
      registries:immutableJson(current.registries),phase:'issued',pendingChecks:0}:undefined;
    // Unsupported modes still execute the installed Root implementation using
    // every original full-current checkpoint; callers never supply a callback.
    if(fixedReader&&!fixed)fn=async handle=>{await fixedReader.read(handle,await this.verifyHandle(handle),current.input);return undefined as T;};
    const state: ReadState = { active: true, failed: false, actorId, role, plan: sealedPlan, digest: current.digest, proof, expiresAt, transaction: tx,fixed,
      cursors: new Map(), seen: new Set(),trueEofs:new Set(),presentPoints:new Set(),observedAbsences:new Set(),sdkObservedAbsences:new Set(),pendingRequests:new Set(), calls: 0, pages: 0, records: 0, bytes: 0 };
    this.handles.set(handle, state);
    if(fixed)try{
      await this.runner.run(handle,async()=>{
        if(fixed.phase!=='entered')throw denied('WORKFLOW_CANDIDATE_FIXED_PHASE_REQUIRED');
        const frame=this.context.current();
        if(frame.kind!=='workflow-candidate-read'||frame.actor!==proof.actor||frame.sessionId!=null)throw denied('WORKFLOW_CANDIDATE_FIXED_FRAME_CHANGED');
        fixed.readFrame=frame;fixed.phase='reading';this.assertFixedFrame(handle,state);
        await fixed.reader.read(handle,proof,fixed.input);this.assertFixedFrame(handle,state);
        if(state.pendingRequests.size||fixed.pendingChecks)throw denied('WORKFLOW_CANDIDATE_READ_INCOMPLETE');
        for(const resource of proof.scope.resources)if(resource.required!==false&&(!state.seen.has(this.key(resource))
          ||resource.kind==='collection'&&!state.cursors.get(this.key(resource))?.complete))throw denied('WORKFLOW_CANDIDATE_READ_INCOMPLETE');
        fixed.phase='closing';await this.verifyCompleteHandle(handle);await this.verifyFixedCurrent(handle,state);
        if(state.pendingRequests.size||fixed.pendingChecks)throw denied('WORKFLOW_CANDIDATE_READ_INCOMPLETE');
        this.assertFixedFrame(handle,state);fixed.phase='sealed';
      });
      // Await the original Context HTTP-parent tail before restoring its
      // original live ancestor and resolving only void. There is no automatic
      // Candidate final verifyHandle in Context to substitute for closing.
      if(fixed.phase!=='sealed'||this.context.peek()!==fixed.parentFrame)throw denied('WORKFLOW_CANDIDATE_FIXED_NOT_CLOSED');
      this.context.assertWorkflowScheduleCandidateReadAdmission();this.context.current();this.assertLive(handle);
      return undefined as T;
    }catch(error){state.failed=true;throw error;}finally{
      state.active=false;for(const token of state.pendingRequests){const request=this.requests.get(token);if(request)request.active=false;this.requests.delete(token);}
      state.pendingRequests.clear();this.handles.delete(handle);
    }
    try {
      return await this.runner.run(handle, async () => {
        await this.verifyHandle(handle); const result = await fn!(handle); await this.verifyHandle(handle);
        if(state.pendingRequests.size)throw denied('WORKFLOW_CANDIDATE_READ_INCOMPLETE');
        for (const resource of state.proof.scope.resources) if (resource.required !== false && (!state.seen.has(this.key(resource))
          || resource.kind === 'collection' && !state.cursors.get(this.key(resource))?.complete)) throw denied('WORKFLOW_CANDIDATE_READ_INCOMPLETE');
        return result;
      });
    } finally { state.active = false; this.handles.delete(handle); }
  }
  async authorizeRequest(originalReadHandle: object, request: WorkflowScheduleCandidateRequest): Promise<object> {
    const state = this.state(originalReadHandle); return this.checked(state, async () => {
    request = immutableJson(request);
    await this.verifyHandle(originalReadHandle);
    if (request.method !== 'GET' || request.body !== undefined && request.body !== null) throw denied('WORKFLOW_CANDIDATE_GET_ONLY');
    const resource = state.proof.scope.resources.find(r => r.clusterId === request.clusterId && r.workspaceId === request.workspaceId && r.path === request.path);
    if (!resource||resource.serviceHostReference!==undefined) throw denied('WORKFLOW_CANDIDATE_PATH_FORBIDDEN'); assertKongPath('GET', request.path); validateQuery(request.query as Record<string, string | number>);
    const key = this.key(resource);
    if (resource.kind === 'collection') {
      const cursor = state.cursors.get(key) ?? { started: false, complete: false, pending: false, next: null, offsets: new Set<string>(), ids: new Set<string>() };
      const expected = { ...resource.query, ...(cursor.started ? { offset: cursor.next } : {}) };
      if (cursor.pending || cursor.complete || this.secrets.fingerprint(request.query) !== this.secrets.fingerprint(expected)) throw denied('WORKFLOW_CANDIDATE_CURSOR_INVALID');
      if (cursor.started && (!cursor.next || cursor.offsets.has(cursor.next))) throw denied('WORKFLOW_CANDIDATE_CURSOR_INVALID');
      if (cursor.next) cursor.offsets.add(cursor.next); cursor.pending = true; state.cursors.set(key, cursor);
    } else if (Object.keys(request.query).length) throw denied('WORKFLOW_CANDIDATE_QUERY_FORBIDDEN');
    if (++state.calls > state.proof.scope.limits.maxCalls) throw denied('WORKFLOW_CANDIDATE_READ_BUDGET');
    const token = Object.freeze({}); this.requests.set(token, { handle: originalReadHandle, state, resource, request, active: true });state.pendingRequests.add(token); return token;
    });
  }
  async verifyRequest(originalRequestToken: object): Promise<Readonly<WorkflowScheduleCandidateReadProof>> {
    const request = originalRequestToken && this.requests.get(originalRequestToken);
    if (!request?.active || request.state !== this.state(request.handle)) throw denied('WORKFLOW_CANDIDATE_ORIGINAL_REQUEST_REQUIRED');
    return this.checked(request.state, async () => {
    const proof = await this.verifyHandle(request.handle);
    if (!request.active || request.state !== this.state(request.handle) || request.request.method !== 'GET'
      || !proof.scope.resources.some(r => this.key(r) === this.key(request.resource))) throw denied('WORKFLOW_CANDIDATE_ORIGINAL_REQUEST_REQUIRED');
    return proof;
    });
  }
  async authorizeResponse(originalRequestToken: object, response: unknown, originalAbsenceObservation?:200|object): Promise<unknown> {
    const request = originalRequestToken && this.requests.get(originalRequestToken);
    if (!request?.active) throw denied('WORKFLOW_CANDIDATE_ORIGINAL_REQUEST_REQUIRED');
    const { state, resource, handle } = request; return this.checked(state, async () => {
    this.assertLive(handle); if (state !== this.state(handle)) throw denied('WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED');
    let status=200;
    if(originalAbsenceObservation!==undefined&&originalAbsenceObservation!==200){
      if(!this.absentResponseVerifier||!originalAbsenceObservation||typeof originalAbsenceObservation!=='object'||Array.isArray(originalAbsenceObservation))throw denied('WORKFLOW_CANDIDATE_ABSENT_OBSERVATION_REQUIRED');
      const observed=this.absentResponseVerifier.verifyOriginalResponse(originalRequestToken,originalAbsenceObservation);
      if(observed.status!==404||observed.response!==response)throw denied('WORKFLOW_CANDIDATE_ABSENT_OBSERVATION_REQUIRED');status=404;
    }
    request.active=false;this.requests.delete(originalRequestToken);
    // A response in progress is still pending until its full material policy
    // and final fences finish. An unawaited response cannot look complete.
    if(!state.fixed)state.pendingRequests.delete(originalRequestToken);
    const absent = status === 404 && resource.kind === 'point' && resource.allowAbsent === true;
    if (!Number.isInteger(status) || !absent && (status < 200 || status > 299)) throw denied('WORKFLOW_CANDIDATE_RESPONSE_INVALID');
    if(absent&&(!isKongPointNotFound(response)||!(state.proof.scope.domain==='scoped-points-v1'?this.scopedAbsentPoint(state,resource)
      :hasObservedAbsenceWitness(resource,state.proof.scope.resources,state.trueEofs,state.presentPoints,state.cursors,state.observedAbsences))))throw denied('WORKFLOW_CANDIDATE_ABSENT_WITNESS_REQUIRED');
    const raw = immutableJson(response), key = this.key(resource), data = (raw as any)?.data;
    const bytes = state.bytes + Buffer.byteLength(JSON.stringify(raw ?? null));
    let pages = state.pages, records = state.records, next: string | null = null, nextIds: Set<string> | undefined;
    // A non-secret scope cannot return private material merely because the
    // provider mislabeled a credential/plugin/certificate response. Marking
    // secrets=true still requires the actual per-object secret grant callback.
    if (resource.kind !== 'schema' && !resource.secrets && this.secrets.fingerprint(this.secrets.redact(raw)) !== this.secrets.fingerprint(raw))
      throw denied('WORKFLOW_CANDIDATE_SECRET_SCOPE_REQUIRED');
    if (resource.kind === 'point' && !absent && (!raw || (raw as any).id !== resource.entityId)) throw denied('WORKFLOW_CANDIDATE_RESPONSE_INVALID');
    if (resource.kind === 'collection') {
      const cursor = state.cursors.get(key); if (!cursor?.pending || !Array.isArray(data) || data.length > resource.query!.size || !Object.hasOwn(raw as object, 'next')) throw denied('WORKFLOW_CANDIDATE_RESPONSE_INVALID');
      pages++; records += data.length; nextIds = new Set(cursor.ids);
      for (const row of data) { if (!row || !uuid.test(row.id ?? '') || nextIds.has(row.id)) throw denied('WORKFLOW_CANDIDATE_DUPLICATE_ENTITY'); nextIds.add(row.id); }
      if ((raw as any).next !== null && (raw as any).next !== undefined) {
        if (typeof (raw as any).next !== 'string') throw denied('WORKFLOW_CANDIDATE_CURSOR_INVALID');
        const registry = state.proof.registries.find(r => r.clusterId === resource.clusterId && r.workspaceId === resource.workspaceId)!;
        const cluster = await (state.transaction ?? this.db).one<any>('SELECT admin_url FROM clusters WHERE id=$1 AND deleted_at IS NULL', [registry.clusterId]);
        const base = new URL(cluster.admin_url), url = new URL((raw as any).next, base);
        if (url.origin !== base.origin || url.pathname !== resource.path || [...url.searchParams.keys()].some(k => !['offset', 'size', 'tags'].includes(k) || url.searchParams.getAll(k).length !== 1)) throw denied('WORKFLOW_CANDIDATE_CURSOR_INVALID');
        next = url.searchParams.get('offset'); if (!next || next.length > 8192 || cursor.offsets.has(next)) throw denied('WORKFLOW_CANDIDATE_CURSOR_INVALID');
        if (url.searchParams.has('size') && Number(url.searchParams.get('size')) !== resource.query!.size || url.searchParams.has('tags') && url.searchParams.get('tags') !== resource.query!.tags) throw denied('WORKFLOW_CANDIDATE_CURSOR_INVALID');
      }
    }
    if (pages > state.proof.scope.limits.maxPages || records > state.proof.scope.limits.maxRecords || bytes > state.proof.scope.limits.maxBytes) throw denied('WORKFLOW_CANDIDATE_READ_BUDGET');
    if(state.fixed)await this.verifyFixedCurrent(handle,state);
    const lookup = (tx: DbService) => this.current(state.plan as WorkflowScheduledPlanV1, state.actorId, state.role, tx);
    const current = state.fixed&&status!==404?{input:state.fixed.input,digest:state.digest}
      :state.transaction ? await lookup(state.transaction) : await this.db.transaction(lookup);
    if (current.digest !== state.digest) throw denied('WORKFLOW_CANDIDATE_FACTS_CHANGED');
    await this.policy(state.plan.kind).authorizeResponse({ ...current.input, resource, response: raw, status });
    this.assertLive(handle); await this.verifyHandle(handle);
    if (resource.kind === 'collection') {
      const cursor = state.cursors.get(key)!;
      cursor.pending = false; cursor.started = true; cursor.complete = next === null; cursor.next = next; cursor.ids = nextIds!;
      if((raw as any).next===null)state.trueEofs.add(key);
    }
    if(resource.kind==='point'&&!absent)state.presentPoints.add(key);
    if(absent){state.observedAbsences.add(key);state.sdkObservedAbsences.add(key);}
    state.pages = pages; state.records = records; state.bytes = bytes; state.seen.add(key);
    if(state.fixed)state.pendingRequests.delete(originalRequestToken);
    return resource.kind === 'schema' ? stripSensitiveSchemaDefaults(raw, this.secrets) : raw;
    });
  }
}
