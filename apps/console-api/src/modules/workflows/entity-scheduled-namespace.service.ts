import { ForbiddenException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { EntityScheduledAuthorityService } from './entity-scheduled-authority.service';
import type { EntityScheduledAuthorityInspection } from './entity-scheduled-authority.types';
import type { EntityScheduledContextRunner, EntityScheduledNamespaceCheckpoint, EntityScheduledNamespaceProof, EntityScheduledTargetWeightPacketProof } from './entity-scheduled-namespace.types';

const denied = (code: string) => new ForbiddenException({ code });
interface NamespaceState {
  readonly authorityHandle: object;
  readonly digest: string;
  readonly proof: Readonly<EntityScheduledNamespaceProof>;
  readonly expiresAt: number;
  active: boolean;
}
/** One private namespace per original live scheduled occurrence. The only
 * authority source is the installed real Authority's dynamic original-handle
 * verifier. No inspection/principal/source DTO is accepted as authority. */
@Injectable()
export class EntityScheduledNamespaceService {
  private runner?: Readonly<EntityScheduledContextRunner>;
  private readonly namespaces = new WeakMap<object, NamespaceState>();
  private readonly usedAuthority = new WeakSet<object>();
  constructor(private readonly authority: EntityScheduledAuthorityService, private readonly secrets: SecretService,
    private readonly redis: RedisService) {}

  installContextRunner(runner: EntityScheduledContextRunner): void {
    if (this.runner || !runner || typeof runner.run !== 'function' || typeof runner.assertNoFrame !== 'function')
      throw new Error('A single complete scheduled context runner must be installed');
    this.runner = Object.freeze({ run: runner.run.bind(runner), assertNoFrame: runner.assertNoFrame.bind(runner),
      ...(typeof runner.requireCurrentHandle === 'function' ? { requireCurrentHandle: runner.requireCurrentHandle.bind(runner) } : {}) });
  }
  private contextRunner(): Readonly<EntityScheduledContextRunner> {
    if (!this.runner) throw new ServiceUnavailableException({ code: 'ENTITY_SCHEDULE_NAMESPACE_NOT_ENABLED' });
    return this.runner;
  }
  private original(handle: object): void {
    if (!handle || typeof handle !== 'object' || Array.isArray(handle)) throw denied('ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED');
  }
  private state(handle: object): NamespaceState {
    this.original(handle); const state = this.namespaces.get(handle);
    if (!state?.active) throw denied('ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED');
    return state;
  }
  private digest(value: Readonly<EntityScheduledAuthorityInspection>): string {
    return this.secrets.fingerprint({ claim: value.claim, draft: value.draft, envelope: value.envelope, plan: value.plan,
      principal: value.principal, permissionVersion: value.permissionVersion, authorityExpiresAt: value.authorityExpiresAt,
      leaseUntil: value.leaseUntil, approvalSet: value.approvalSet });
  }
  private projection(value: Readonly<EntityScheduledAuthorityInspection>): Readonly<EntityScheduledNamespaceProof> {
    const { envelope: e, draft: d, plan, claim: c, principal: actor } = value, delegation = e.scheduling?.delegation;
    if (value.version !== 1 || e.version !== 2 || !delegation || actor.id !== e.requesterId || actor.forcePasswordChange
      || delegation.ownerId !== actor.id || delegation.executorId !== actor.id || delegation.ownerCredentialEpoch !== e.credentialEpoch
      || delegation.executorCredentialEpoch !== e.credentialEpoch || plan.requester.type !== 'console' || plan.requester.id !== actor.id
      || e.clusterId !== d.binding.clusterId || e.workspaceId !== d.binding.workspaceId || plan.clusterId !== e.clusterId || plan.workspaceId !== e.workspaceId
      || plan.kind !== 'native-change' || !plan.approvalRequired || plan.executionMode !== 'approval' || e.executionMode !== 'approval'
      || c.scheduleId !== d.scheduleId || c.workflowId !== plan.workflowId || c.workflowPlanRevision !== plan.planRevision
      || c.workflowPlanHash !== this.secrets.fingerprint(plan) || c.generation !== 1 || c.scheduleVersion !== 1
      || !value.approvalSet.reviewers.length || value.authorityExpiresAt !== c.authorityExpiresAt) throw denied('ENTITY_SCHEDULE_NAMESPACE_FACTS_INVALID');
    const times = [value.authorityExpiresAt, value.leaseUntil, e.expiresAt, plan.expiresAt, d.spec.windowEnd].map(Date.parse);
    if (times.some(time => !Number.isFinite(time))) throw denied('ENTITY_SCHEDULE_NAMESPACE_FACTS_INVALID');
    const expiresAt = new Date(Math.min(...times)).toISOString();
    if (Date.parse(expiresAt) <= Date.now()) throw denied('ENTITY_SCHEDULE_NAMESPACE_EXPIRED');
    return immutableJson({ version: 1, origin: 'scheduled-entity', actor, sessionId: null, clusterId: e.clusterId, workspaceId: e.workspaceId,
      transportScope: e.prepared.scope.transportScope, clusterRevision: e.prepared.scope.clusterRevision, workspaceRevision: e.prepared.scope.workspaceRevision,
      permissionVersion: value.permissionVersion, credentialEpoch: e.credentialEpoch, expiresAt,
      claim: { ...c, clusterId: e.clusterId, workspaceId: e.workspaceId, ownerId: actor.id, ownerCredentialEpoch: e.credentialEpoch,
        delegationId: delegation.id, delegationVersion: 1, delegationHmac: e.scheduling.delegationHmac, specHmac: e.scheduling.specHmac,
        windowStart: d.spec.windowStart, windowEnd: d.spec.windowEnd },
      intent: { id: e.intentId, revision: e.revision, materialHmac: d.binding.materialHmac, changeDigest: d.binding.changeDigest, packetManifestHmac: d.binding.packetManifestHmac },
      approvalSet: value.approvalSet });
  }
  /** Synchronous final-send fence only. Redis ownership and current SQL
   * eligibility are checked asynchronously by verifyHandle before this. */
  assertLive(originalNamespaceHandle: object): void {
    const state = this.state(originalNamespaceHandle);
    if (state.expiresAt <= Date.now()) throw denied('ENTITY_SCHEDULE_NAMESPACE_EXPIRED');
    this.redis.assertLeaseActive();
  }
  async verifyHandle(originalNamespaceHandle: object, checkpoint: EntityScheduledNamespaceCheckpoint): Promise<Readonly<EntityScheduledNamespaceProof>> {
    if (!['claim', 'capture', 'packet', 'before-send'].includes(checkpoint)) throw denied('ENTITY_SCHEDULE_NAMESPACE_CHECKPOINT_INVALID');
    const state = this.state(originalNamespaceHandle); this.assertLive(originalNamespaceHandle);
    await this.redis.assertLeaseOwnership();
    const current = await this.authority.verifyClaim(state.authorityHandle, checkpoint);
    // An await can outlive its namespace callback. Never return a verification
    // after finally invalidated the original handle or the lease was lost.
    this.assertLive(originalNamespaceHandle);
    if (this.digest(current) !== state.digest || this.secrets.fingerprint(this.projection(current)) !== this.secrets.fingerprint(state.proof))
      throw denied('ENTITY_SCHEDULE_NAMESPACE_FACTS_CHANGED');
    await this.redis.assertLeaseOwnership(); this.assertLive(originalNamespaceHandle);
    return state.proof;
  }
  async verifyTargetWeightPacket(originalNamespaceHandle: object, packetKey: string, checkpoint: 'capture' | 'packet' | 'before-send' = 'packet'):
    Promise<Readonly<EntityScheduledTargetWeightPacketProof>> {
    const runner = this.contextRunner(), state = this.state(originalNamespaceHandle);
    const current = () => { this.assertLive(originalNamespaceHandle); if (!runner.requireCurrentHandle || runner.requireCurrentHandle() !== originalNamespaceHandle) throw denied('ENTITY_SCHEDULE_TARGET_WEIGHT_FRAME_REQUIRED'); };
    current(); await this.verifyHandle(originalNamespaceHandle, checkpoint); current();
    const observed = await this.authority.verifyTargetWeightPacket(state.authorityHandle, packetKey, checkpoint); current();
    if (this.digest(observed.inspection) !== state.digest) throw denied('ENTITY_SCHEDULE_NAMESPACE_FACTS_CHANGED');
    await this.redis.assertLeaseOwnership(); current();
    return Object.freeze({ namespace: state.proof, packet: observed.packet });
  }
  async runOriginalClaim<T>(originalAuthorityHandle: object, fn: () => Promise<T>): Promise<T> {
    const runner = this.contextRunner(); this.original(originalAuthorityHandle);
    if (typeof fn !== 'function') throw denied('ENTITY_SCHEDULE_NAMESPACE_CALLBACK_INVALID');
    runner.assertNoFrame();
    // Outside Authority.executeClaim's original fixed callback this fails:
    // its private executing state and actual Redis lease are mandatory.
    const verified = await this.authority.verifyClaim(originalAuthorityHandle, 'claim');
    if (this.usedAuthority.has(originalAuthorityHandle)) throw denied('ENTITY_SCHEDULE_NAMESPACE_ALREADY_ISSUED');
    this.usedAuthority.add(originalAuthorityHandle);
    const inspected = await this.authority.inspect(originalAuthorityHandle);
    if (this.digest(inspected) !== this.digest(verified)) throw denied('ENTITY_SCHEDULE_NAMESPACE_FACTS_CHANGED');
    const proof = this.projection(verified); await this.redis.assertLeaseOwnership(); runner.assertNoFrame();
    const handle = Object.freeze({}), state: NamespaceState = { authorityHandle: originalAuthorityHandle,
      digest: this.digest(verified), proof, expiresAt: Date.parse(proof.expiresAt), active: true };
    this.namespaces.set(handle, state);
    try {
      this.assertLive(handle);
      return await runner.run(handle, async () => {
        await this.verifyHandle(handle, 'claim');
        return fn();
      });
    } finally { state.active = false; this.namespaces.delete(handle); }
  }
}
