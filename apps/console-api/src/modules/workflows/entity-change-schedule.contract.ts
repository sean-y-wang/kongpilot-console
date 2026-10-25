import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { EntityChangeInput } from '../entities/entity-change.types';
import type { MutationImpact } from '../mutations/mutation-impact';
import type { EntityChangeIntentEnvelopeV1, EntityChangeExecutionSource } from './entity-change-intent.types';

/** Draft Gate4 contract only: importing these types enables no scheduler,
 * origin, HTTP route, SQL migration, context namespace or native capability. */
export interface EntityScheduledSpecV1 {
  readonly version: 1;
  readonly notBefore: string;
  readonly windowStart: string;
  readonly windowEnd: string;
  /** All three fields are canonical UTC ISO instants. The window is [start,end). */
  readonly executorId: string;
}
export interface PrepareScheduledEntityChangeDto {
  readonly change: EntityChangeInput;
  readonly schedule: EntityScheduledSpecV1;
  readonly confirmed: true;
  readonly confirm_name: 'scheduled-change';
  readonly ttlHours?: number;
}
export interface EntityOwnerDelegationV1 {
  readonly version: 1;
  readonly id: string;
  readonly revision: 1;
  readonly clusterId: string;
  readonly workspaceId: string;
  /** Non-circular scope commitment; the outer envelope materialHmac binds
   * this delegation's HMAC after these fields are fixed. */
  readonly intentId: string;
  readonly intentRevision: number;
  readonly changeDigest: string;
  readonly packetManifestHmac: string;
  readonly policyHash: string;
  readonly ownerId: string;
  readonly executorId: string;
  readonly ownerCredentialEpoch: string;
  readonly executorCredentialEpoch: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly specHmac: string;
  readonly statement: 'execute-this-exact-approved-entity-intent-with-my-current-authority';
}
/** Every new time window/executor/delegation creates a new envelope/intent and
 * approval. V1 has no additional fields and retains its exact old hash. */
export interface EntityScheduledIntentEnvelopeV2 extends Omit<EntityChangeIntentEnvelopeV1,'version'> {
  readonly version: 2;
  readonly scheduling: {
    readonly scheduleId: string;
    readonly scheduleVersion: 1;
    readonly spec: EntityScheduledSpecV1;
    readonly specHmac: string;
    readonly delegation: EntityOwnerDelegationV1;
    readonly delegationHmac: string;
  };
}
export interface EntityScheduledIntentBinding {
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly intentId: string;
  readonly intentRevision: number;
  readonly materialHmac: string;
  readonly changeDigest: string;
  readonly packetManifestHmac: string;
}
export interface EntityScheduledDraft {
  readonly binding: EntityScheduledIntentBinding;
  readonly scheduleId: string;
  readonly scheduleVersion: 1;
  readonly spec: EntityScheduledSpecV1;
  readonly specHmac: string;
  readonly delegation: EntityOwnerDelegationV1;
  readonly delegationHmac: string;
  readonly impactHmac: string;
  readonly transportScope: string;
  readonly impact: MutationImpact;
}
export interface EntityScheduleClaim {
  readonly id: string;
  readonly scheduleId: string;
  readonly scheduleVersion: 1;
  readonly occurrenceId: string;
  readonly generation: 1;
  readonly workerOwnerHmac: string;
  readonly issuedAt: string;
  readonly authorityExpiresAt: string;
  readonly initialLeaseUntil: string;
  readonly workflowId: string;
  readonly workflowPlanRevision: number;
  readonly workflowPlanHash: string;
}
/** New crypto format only. HTTP sources keep the old shape with no origin or
 * format field; scheduled sources never borrow or fabricate an HTTP SID. */
export interface EntityScheduledExecutionSourceV2 extends Omit<EntityChangeExecutionSource,'sessionId'> {
  readonly format: 2;
  readonly origin: 'scheduled-entity';
  readonly sessionId: null;
  readonly scheduleId: string;
  readonly scheduleVersion: 1;
  readonly specHmac: string;
  readonly delegationId: string;
  readonly delegationVersion: 1;
  readonly delegationHmac: string;
  readonly occurrenceId: string;
  readonly claimId: string;
  readonly claimGeneration: 1;
  readonly workerOwnerHmac: string;
  readonly windowStart: string;
  readonly windowEnd: string;
}
export type EntityExecutionSourceByOrigin = EntityChangeExecutionSource | EntityScheduledExecutionSourceV2;
export type EntityScheduleState = 'pending-approval'|'active'|'claimed'|'running'|'succeeded'|'partial'|'failed'|'uncertain'|'blocked'|'cancelled'|'expired';
export interface EntityScheduleActivation {
  readonly workflowId: string;
  readonly workflowPlanRevision: number;
  readonly workflowPlanHash: string;
  readonly approvalFormat: 1 | 2;
  readonly approvalRequired: boolean;
  readonly approvalSetId: string | null;
  readonly approvalSetHmac: string | null;
}
export interface EntityScheduleReceipt {
  readonly id: string;
  readonly revision: number;
  readonly state: EntityScheduleState;
  readonly intentId: string;
  readonly notBefore: string;
  readonly windowStart: string;
  readonly windowEnd: string;
  readonly workflowId: string | null;
  readonly claimId: string | null;
  readonly reasonCode: string | null;
  readonly nativeAuthority: false;
}
export type EntityScheduleTerminalOutcome = 'succeeded' | 'partial' | 'failed' | 'uncertain';

/** Root verifies actual HTTP owner during drafting, full current approval set
 * before activation, and current owner/grants/epoch/reviewers/window/impact
 * before claiming. Returned/storage shapes are not execution authority. */
export interface EntityScheduleRepositoryDelegate {
  verifyDraft(draft: Readonly<EntityScheduledDraft>, actor: EntityActor, tx: DbService): Promise<void>;
  verifyApproved(scheduleId: string, activation: Readonly<EntityScheduleActivation>, rootProof: object, tx: DbService): Promise<void>;
  verifyClaim(scheduleId: string, claim: Readonly<EntityScheduleClaim>, rootProof: object, tx: DbService): Promise<void>;
  verifyLease(claimId: string, workerOwnerHmac: string, generation: number, leaseUntil: string, rootProof: object, tx: DbService): Promise<void>;
  verifyCancellation(scheduleId: string, actor: EntityActor, tx: DbService): Promise<void>;
  verifyPhysicalReservation(scheduleId: string, rootProof: object, tx: DbService): Promise<void>;
  verifyOutcome(claimId: string, outcome: EntityScheduleTerminalOutcome, rootProof: object, tx: DbService): Promise<void>;
  verifyBlocked(scheduleId: string, reasonCode: string, rootProof: object, tx: DbService): Promise<void>;
  assertRead(scheduleId: string, actor: EntityActor, tx: DbService): Promise<void>;
}
/** A worker passes IDs and an opaque handle between two Root methods. It does
 * not construct AuthUser, actor, SID, approved flags, sources or permits. No
 * installed delegate means the worker cannot execute anything. */
export interface EntityScheduleWorkerDelegate {
  acquireDueClaim(scheduleId: string): Promise<object | null>;
  executeClaim(genuineClaim: object): Promise<void>;
}
