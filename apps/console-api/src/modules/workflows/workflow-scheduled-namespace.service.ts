import { ForbiddenException, Injectable, Optional, ServiceUnavailableException } from '@nestjs/common';
import type {WorkflowPlanV1} from './workflow.types';
import {performance} from 'node:perf_hooks';
import {DbService} from '../../infrastructure/db.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { WorkflowScheduledAuthorityService } from './workflow-scheduled-authority.service';
import type { WorkflowScheduledAuthorityInspection, WorkflowScheduledContextRunner, WorkflowScheduledNamespaceCheckpoint,
  WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import { isPortalCredentialScheduleKind } from '../portal/portal-credential-lifecycle-contract';

const deny = (code: string) => new ForbiddenException({ code });
const checkpoints = ['claim', 'capture', 'step', 'packet', 'before-send'];
interface NamespaceState {
  readonly authorityHandle: object;
  readonly digest: string;
  readonly proof: Readonly<WorkflowScheduledNamespaceProof>;
  readonly expiresAt: number;
  active: boolean;
  grantDeadline:number;
}

/** Separate business-workflow namespace. Entity scheduled handles, HTTP
 * Actors, inspection copies, readonly snapshot timers and old SIDs cannot
 * enter it. Only the actual original Authority callback supplies provenance.
 * Root independently installs Context/native adapters; none is enabled here. */
@Injectable()
export class WorkflowScheduledNamespaceService {
  private runner?: Readonly<WorkflowScheduledContextRunner>;
  private readonly namespaces = new WeakMap<object, NamespaceState>();
  private readonly usedAuthority = new WeakSet<object>();
  readonly #freshPortalInspections=new WeakMap<object,{namespaceHandle:object;proof:Readonly<WorkflowScheduledNamespaceProof>;checkpoint:WorkflowScheduledNamespaceCheckpoint;current:Readonly<WorkflowScheduledAuthorityInspection>}>();
  constructor(private readonly authority: WorkflowScheduledAuthorityService, private readonly secrets: SecretService,
    private readonly redis: RedisService,@Optional() private readonly context?:KongExecutionContextService) {}

  installContextRunner(runner: WorkflowScheduledContextRunner): void {
    if (this.runner || !runner || typeof runner.assertNoFrame !== 'function' || typeof runner.run !== 'function')
      throw new Error('A single complete business scheduled context runner must be installed');
    this.runner = Object.freeze({ assertNoFrame: runner.assertNoFrame.bind(runner), run: runner.run.bind(runner) });
  }
  private installed(): Readonly<WorkflowScheduledContextRunner> {
    if (!this.runner) throw new ServiceUnavailableException({ code: 'WORKFLOW_SCHEDULE_NAMESPACE_UNAVAILABLE' });
    return this.runner;
  }
  private original(handle: object): void {
    if (!handle || typeof handle !== 'object' || Array.isArray(handle)) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED');
  }
  private state(handle: object): NamespaceState {
    this.original(handle); const state = this.namespaces.get(handle);
    if (!state?.active) throw deny('WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED');
    return state;
  }
  private digest(value: Readonly<WorkflowScheduledAuthorityInspection>): string {
    return this.secrets.fingerprint({ claim: value.claim, draft: value.draft, plan: value.plan, approvalSet: value.approvalSet,
      principal: value.principal, permissionVersion: value.permissionVersion, leaseUntil: value.leaseUntil, authorityExpiresAt: value.authorityExpiresAt });
  }
  private projection(value: Readonly<WorkflowScheduledAuthorityInspection>): Readonly<WorkflowScheduledNamespaceProof> {
    const { draft: d, plan: p, claim: c, principal: actor } = value, b = d.binding, delegation = d.delegation, seal = p.scheduling;
    if (value.version !== 1 || p.version !== 1 || !['configuration_v2', 'portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'].includes(p.kind) || !seal
      || seal.version !== 1 || !p.approvalRequired || !value.approvalSet.reviewers.length || actor.forcePasswordChange
      || actor.id !== delegation.ownerId || actor.id !== delegation.executorId || actor.id !== d.spec.executorId
      || p.kind !== b.kind || p.workflowId !== b.workflowId || p.planRevision !== b.workflowPlanRevision || this.secrets.fingerprint(p) !== b.workflowPlanHash
      || p.clusterId !== b.clusterId || p.workspaceId !== b.workspaceId || p.subject.type !== b.subjectType || p.subject.id !== b.subjectId
      || p.requester.type !== b.requester.type || p.requester.id !== b.requester.id || this.secrets.fingerprint(b.requester) !== this.secrets.fingerprint(delegation.requester)
      || b.requester.type === 'console' && b.requester.id !== actor.id || p.kind === 'configuration_v2' && b.requester.type !== 'console'
      || isPortalCredentialScheduleKind(p.kind) && b.requester.type !== 'developer' || value.approvalSet.policyHash !== p.definition.policyHash
      || delegation.ownerCredentialEpoch !== delegation.executorCredentialEpoch || delegation.version !== 1 || delegation.revision !== 1
      || this.secrets.fingerprint(delegation) !== d.delegationHmac || this.secrets.fingerprint(d.spec) !== d.specHmac
      || seal.scheduleId !== d.scheduleId || seal.scheduleVersion !== 1 || seal.occurrenceId !== d.occurrenceId || seal.basePlanHash !== b.basePlanHash
      || seal.ownerId !== actor.id || seal.executorId !== actor.id || seal.ownerCredentialEpoch !== delegation.ownerCredentialEpoch
      || seal.executorCredentialEpoch !== delegation.executorCredentialEpoch || seal.delegationId !== delegation.id || seal.delegationVersion !== 1
      || seal.delegationHmac !== d.delegationHmac || seal.specHmac !== d.specHmac || this.secrets.fingerprint(seal.spec) !== d.specHmac
      || this.secrets.fingerprint(seal.requester) !== this.secrets.fingerprint(b.requester) || seal.transportScope !== d.transportScope || seal.impactHmac !== d.impactHmac
      || seal.subjectSealHmac !== delegation.subjectSealHmac || seal.subjectSealHmac !== this.secrets.fingerprint(b.subjectSeal)
      || c.scheduleId !== d.scheduleId || c.scheduleVersion !== 1 || c.occurrenceId !== d.occurrenceId || c.generation !== 1
      || c.workflowId !== p.workflowId || c.workflowPlanRevision !== p.planRevision || c.workflowPlanHash !== b.workflowPlanHash
      || c.authorityExpiresAt !== value.authorityExpiresAt) throw deny('WORKFLOW_SCHEDULE_NAMESPACE_FACTS_INVALID');
    const now = Date.now(), limits = [value.authorityExpiresAt, value.leaseUntil, p.expiresAt, delegation.expiresAt, d.spec.windowEnd].map(Date.parse);
    if (limits.some(t => !Number.isFinite(t)) || now < Date.parse(d.spec.windowStart) || now < Date.parse(d.spec.notBefore)
      || limits.some(t => t <= now)) throw deny('WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED');
    const expiresAt = new Date(Math.min(...limits)).toISOString();
    // SQL041 metadata kinds remain typed but not yet executable here.
    // SQL045 admits portal-credential-rotate / revoke alongside issue.
    if (p.kind !== 'configuration_v2' && !isPortalCredentialScheduleKind(p.kind)) throw deny('WORKFLOW_SCHEDULE_NAMESPACE_KIND_UNSUPPORTED');
    const kind = p.kind as 'configuration_v2' | 'portal-credential-issue' | 'portal-credential-rotate' | 'portal-credential-revoke';
    return immutableJson({ version: 1, origin: 'scheduled-workflow', actor, sessionId: null,
      clusterId: p.clusterId, workspaceId: p.workspaceId, kind, transportScope: d.transportScope,
      clusterRevision: p.scope.clusterRevision, workspaceRevision: p.scope.workspaceRevision, permissionVersion: value.permissionVersion,
      credentialEpoch: delegation.executorCredentialEpoch, expiresAt,
      claim: { ...c, clusterId: p.clusterId, workspaceId: p.workspaceId, ownerId: delegation.ownerId, executorId: delegation.executorId,
        ownerCredentialEpoch: delegation.ownerCredentialEpoch, executorCredentialEpoch: delegation.executorCredentialEpoch,
        delegationId: delegation.id, delegationVersion: 1, delegationHmac: d.delegationHmac, specHmac: d.specHmac,
        windowStart: d.spec.windowStart, windowEnd: d.spec.windowEnd, impactHmac: d.impactHmac, subjectSealHmac: seal.subjectSealHmac },
      workflow: { id: p.workflowId, planRevision: p.planRevision, planHash: b.workflowPlanHash }, requester: b.requester,
      subjectSealHmac: seal.subjectSealHmac, approvalSet: value.approvalSet });
  }

  /** Only a final synchronous fence, never a substitute for fresh SQL review. */
  assertLive(originalNamespaceHandle: object): void {
    const state = this.state(originalNamespaceHandle);
    if (state.expiresAt <= Date.now()) throw deny('WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED');
    if(performance.now()>=state.grantDeadline)throw deny('WORKFLOW_SCHEDULE_NAMESPACE_GRANT_EXPIRED');
    this.redis.assertLeaseActive();
  }
  private async currentInspection(originalNamespaceHandle: object, checkpoint: WorkflowScheduledNamespaceCheckpoint,
    originalAuthorityHandle?: object): Promise<Readonly<{ current: Readonly<WorkflowScheduledAuthorityInspection>; proof: Readonly<WorkflowScheduledNamespaceProof> }>> {
    if (!checkpoints.includes(checkpoint)) throw deny('WORKFLOW_SCHEDULE_CHECKPOINT_INVALID');
    const state = this.state(originalNamespaceHandle); this.assertLive(originalNamespaceHandle);
    if (originalAuthorityHandle !== undefined && state.authorityHandle !== originalAuthorityHandle)
      throw deny('WORKFLOW_SCHEDULE_ORIGINAL_AUTHORITY_REQUIRED');
    await this.redis.assertLeaseOwnership();
    const current = await this.authority.verifyClaim(state.authorityHandle, checkpoint);
    // Awaited policy checks can outlive a returned callback. Never resurrect
    // the namespace from a copied inspection or a still-valid timestamp.
    this.assertLive(originalNamespaceHandle);
    if (this.digest(current) !== state.digest || this.secrets.fingerprint(this.projection(current)) !== this.secrets.fingerprint(state.proof))
      throw deny('WORKFLOW_SCHEDULE_NAMESPACE_FACTS_CHANGED');
    const frame=this.context?.peek();
    if(frame&&isPortalCredentialScheduleKind(state.proof.kind)){
      const deadline=typeof this.authority.observedPortalGrantDeadline==='function'?this.authority.observedPortalGrantDeadline(state.authorityHandle,current,checkpoint,frame):null;
      // Original-current inspection only publishes an actual binding upper
      // bound. It is not a new approval inspection or a Native permission.
      if(deadline!==null){state.grantDeadline=Math.min(state.grantDeadline,deadline);this.assertLive(originalNamespaceHandle);}
    }
    await this.redis.assertLeaseOwnership(); this.assertLive(originalNamespaceHandle);
    return Object.freeze({ current, proof: state.proof });
  }
  /** SQL preparation only. The original Authority handle and all durable
   * claim/physical/canonical approval facts remain mandatory on every call. */
  async verifySqlPreparation(originalNamespaceHandle:object,checkpoint:'packet'):Promise<Readonly<WorkflowScheduledNamespaceProof>>{
    const state=this.state(originalNamespaceHandle);this.assertLive(originalNamespaceHandle);
    await this.authority.verifyConfigurationSqlPreparation(state.authorityHandle,originalNamespaceHandle,state.proof,checkpoint);
    if(this.state(originalNamespaceHandle)!==state)throw deny('WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED');
    this.authority.assertConfigurationSqlPreparationLive(state.authorityHandle,originalNamespaceHandle,state.proof);
    this.assertLive(originalNamespaceHandle);return state.proof;
  }
  async verifyHandle(originalNamespaceHandle: object, checkpoint: WorkflowScheduledNamespaceCheckpoint): Promise<Readonly<WorkflowScheduledNamespaceProof>> {
    const initialFrame=this.context?.peek();if(initialFrame)this.#freshPortalInspections.delete(initialFrame);
    const result=await this.currentInspection(originalNamespaceHandle,checkpoint),frame=this.context?.peek();
    if(frame&&isPortalCredentialScheduleKind(result.proof.kind)){
      const state=this.state(originalNamespaceHandle);
      const deadline=this.authority.freshPortalInspectionGrantDeadline(state.authorityHandle,result.current,checkpoint,frame);
      if(deadline!==null){state.grantDeadline=Math.min(state.grantDeadline,deadline);this.assertLive(originalNamespaceHandle);
        this.#freshPortalInspections.set(frame,{namespaceHandle:originalNamespaceHandle,proof:result.proof,checkpoint,current:result.current});}
    }
    return result.proof;
  }
  async readPortalOperationApprovalSet(plan:WorkflowPlanV1,executionId:string,originalNamespaceHandle:object,transaction:DbService){
    const state=this.state(originalNamespaceHandle);this.assertLive(originalNamespaceHandle);
    if(!this.context||!isPortalCredentialScheduleKind(plan.kind))return null;
    const result=await this.authority.readPortalOperationApprovalSet(state.authorityHandle,state.proof,plan,executionId,transaction);
    if(this.state(originalNamespaceHandle)!==state)throw deny('WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED');this.assertLive(originalNamespaceHandle);return result;
  }
  /** Same original frame and same just-completed checkpoint only. Missing
   * capability keeps Approved's ordinary full path; a mismatched one fails
   * closed. No inspection DTO, copied frame or old Namespace can mint it. */
  async consumeFreshPortalInspection(originalNamespaceHandle:object,proof:Readonly<WorkflowScheduledNamespaceProof>,checkpoint:WorkflowScheduledNamespaceCheckpoint,
    transaction:DbService):Promise<Readonly<{approvalSet:WorkflowScheduledAuthorityInspection['approvalSet']}>|null>{
    const frame=this.context?.peek();if(!frame||!isPortalCredentialScheduleKind(proof.kind))return null;
    const pending=this.#freshPortalInspections.get(frame);if(!pending)return null;
    this.#freshPortalInspections.delete(frame);
    const state=this.state(originalNamespaceHandle);this.assertLive(originalNamespaceHandle);
    if(pending.namespaceHandle!==originalNamespaceHandle||pending.proof!==proof||state.proof!==proof||pending.checkpoint!==checkpoint
      ||!this.authority.hasFreshPortalInspection(state.authorityHandle,pending.current,checkpoint,frame))throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    const current=await this.authority.consumeFreshPortalInspection(state.authorityHandle,pending.current,checkpoint,transaction);
    if(this.context?.current()!==frame||this.state(originalNamespaceHandle)!==state||current!==pending.current)throw deny('WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED');
    state.grantDeadline=Math.min(state.grantDeadline,this.authority.consumedPortalInspectionGrantDeadline(state.authorityHandle,current,checkpoint,frame));
    this.assertLive(originalNamespaceHandle);return Object.freeze({approvalSet:current.approvalSet});
  }
  /** The fixed Root delegate consumes this genuine fresh Authority result.
   * An external inspection/DTO cannot replace the original private handles;
   * every call retains the complete frozen Namespace digest and projection. */
  async inspectOriginalClaim(originalAuthorityHandle: object, originalNamespaceHandle: object,
    checkpoint: WorkflowScheduledNamespaceCheckpoint): Promise<Readonly<WorkflowScheduledAuthorityInspection>> {
    this.original(originalAuthorityHandle);
    return (await this.currentInspection(originalNamespaceHandle, checkpoint, originalAuthorityHandle)).current;
  }
  async runOriginalClaim<T>(originalAuthorityHandle: object, fn: () => Promise<T>): Promise<T> {
    const runner = this.installed(); this.original(originalAuthorityHandle);
    if (typeof fn !== 'function') throw deny('WORKFLOW_SCHEDULE_NAMESPACE_CALLBACK_INVALID');
    runner.assertNoFrame();
    const current = await this.authority.verifyClaim(originalAuthorityHandle, 'claim');
    if (this.usedAuthority.has(originalAuthorityHandle)) throw deny('WORKFLOW_SCHEDULE_NAMESPACE_ALREADY_ISSUED');
    this.usedAuthority.add(originalAuthorityHandle);
    const inspected = await this.authority.inspect(originalAuthorityHandle);
    if (this.digest(inspected) !== this.digest(current)) throw deny('WORKFLOW_SCHEDULE_NAMESPACE_FACTS_CHANGED');
    const proof = this.projection(current); await this.redis.assertLeaseOwnership(); runner.assertNoFrame();
    const handle = Object.freeze({}), state: NamespaceState = { authorityHandle: originalAuthorityHandle, digest: this.digest(current),
      proof, expiresAt: Date.parse(proof.expiresAt), active: true,grantDeadline:Infinity };
    this.namespaces.set(handle, state);
    try {
      this.assertLive(handle);
      return await runner.run(handle, async () => { await this.verifyHandle(handle, 'claim'); return fn(); });
    } finally { state.active = false; this.namespaces.delete(handle); }
  }
}
