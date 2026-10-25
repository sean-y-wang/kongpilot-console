import type { AuthUser } from '../../common/auth';
import type { WorkflowApprovalSet } from './workflow-approval.types';
import type { EntityScheduleClaim } from './entity-change-schedule.contract';
import type { EntityChangePacket } from '../entities/entity-change.types';

export type EntityScheduledNamespaceCheckpoint = 'claim' | 'capture' | 'packet' | 'before-send';
/** The complete immutable SQL024 claim tuple, including the owner/delegation
 * and window fields omitted from the repository's short claim receipt. */
export interface EntityScheduledNamespaceClaim extends EntityScheduleClaim {
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly ownerId: string;
  readonly ownerCredentialEpoch: string;
  readonly delegationId: string;
  readonly delegationVersion: 1;
  readonly delegationHmac: string;
  readonly specHmac: string;
  readonly windowStart: string;
  readonly windowEnd: string;
}
/** Current genuine SQL facts only. This copied shape is never a namespace
 * handle, HTTP identity, context, session, source or native capability. */
export interface EntityScheduledNamespaceProof {
  readonly version: 1;
  readonly origin: 'scheduled-entity';
  readonly actor: Readonly<AuthUser>;
  readonly sessionId: null;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly transportScope: string;
  readonly clusterRevision: number;
  readonly workspaceRevision: number;
  readonly permissionVersion: string;
  readonly credentialEpoch: string;
  readonly expiresAt: string;
  readonly claim: Readonly<EntityScheduledNamespaceClaim>;
  readonly intent: Readonly<{ id: string; revision: number; materialHmac: string; changeDigest: string; packetManifestHmac: string }>;
  readonly approvalSet: Readonly<WorkflowApprovalSet>;
}
/** Root checks its actual Context.peek(), then installs its private frame→NS
 * handle relation. The service never clears or manufactures an ALS frame. */
export interface EntityScheduledContextRunner {
  assertNoFrame(): void;
  run<T>(originalNamespaceHandle: object, fn: () => Promise<T>): Promise<T>;
  /** New Target append validation stays closed when the fixed Root runner
   * cannot attest its actual current private frame → namespace association. */
  requireCurrentHandle?(): object;
}
export interface EntityScheduledTargetWeightPacketProof {
  readonly namespace: Readonly<EntityScheduledNamespaceProof>;
  readonly packet: Readonly<EntityChangePacket>;
}
