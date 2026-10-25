import type { DbService } from '../../infrastructure/db.service';
import type { PreparedEntityChange, EntityChangeReview } from '../entities/entity-change.types';
import type { WorkflowPlanV1 } from './workflow.types';
import type { EntityActor } from '../entities/entities.types';
import type { EntityScheduledIntentEnvelopeV2, EntityScheduledDraft, EntityScheduleReceipt } from './entity-change-schedule.contract';

export interface EntityChangeIntentEnvelopeV1 {
  readonly version: 1;
  readonly intentId: string;
  readonly revision: number;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly requesterId: string;
  readonly credentialEpoch: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly ttlHours: number;
  readonly executionMode: 'direct' | 'approval';
  readonly definition: WorkflowPlanV1['definition'];
  readonly packetManifestHmac: string;
  readonly prepared: PreparedEntityChange;
  readonly review: EntityChangeReview;
}
/** V1 retains its exact original fields and hour deadline. A V2 is a newly
 * sealed intent, never additional schedule flags attached to an old V1 hash. */
export type EntityChangeIntentEnvelope = EntityChangeIntentEnvelopeV1 | EntityScheduledIntentEnvelopeV2;
export interface EntityChangeIntentSchedulingDelegate {
  assertAvailable(clusterId: string, workspaceId: string, tx: DbService): Promise<void>;
  persistDraft(draft: Readonly<EntityScheduledDraft>, actualActor: EntityActor, tx: DbService): Promise<EntityScheduleReceipt>;
}
export interface EntityChangeWorkflowPayload {
  readonly intentId: string;
  readonly intentRevision: number;
  readonly materialHmac: string;
  readonly changeDigest: string;
  readonly packetManifestHmac: string;
}
export interface EntityChangeNormalizedPacket {
  readonly key: string; readonly order: number; readonly dependencies: readonly string[];
  readonly method: 'POST' | 'PATCH' | 'DELETE'; readonly pathHmac: string;
  readonly nativeType: string; readonly nativeId: string; readonly parentId: string | null;
  readonly credentialKind: string | null; readonly originalNativeId: string | null;
  readonly mutationAction: string; readonly permissionAction: 'write' | 'delete';
  readonly bodyHmac: string; readonly beforeHmac: string;
}
/** Bootstrap-only current SQL/grant policy. A user ID is a subject to inspect,
 * never an instruction to swap the executor's HTTP identity or session. */
export interface EntityChangeIntentSubjectPolicy {
  assertSubject(envelope: EntityChangeIntentEnvelope, userId: string, action: 'read' | 'write' | 'approve', tx: DbService): Promise<void>;
  verifyReviewer(envelope: EntityChangeIntentEnvelope, userId: string, tx: DbService): Promise<void>;
}
export interface EntityChangeIntentWorkflowDelegate {
  verifyIntent(plan: WorkflowPlanV1, tx?: DbService): Promise<void>;
  assertSubject(plan: WorkflowPlanV1, userId: string, action: 'read' | 'write' | 'approve', tx?: DbService): Promise<void>;
  verifyReviewer(userId: string, plan: WorkflowPlanV1, tx?: DbService): Promise<void>;
  revalidate(plan: WorkflowPlanV1, actor: EntityActor, phase: 'submit' | 'approve' | 'claim'): Promise<void>;
}
/** Future Root-owned short execution fact. Saving this row is not a permit and
 * the durable repository deliberately has no method that creates one. */
export interface EntityChangeExecutionSource {
  readonly id: string; readonly clusterId: string; readonly workspaceId: string;
  readonly intentId: string; readonly intentRevision: number; readonly materialHmac: string;
  readonly changeDigest: string; readonly packetManifestHmac: string;
  readonly workflowId: string; readonly workflowPlanRevision: number; readonly workflowPlanHash: string;
  readonly workflowExecutionId: string; readonly executionActorId: string;
  readonly credentialEpoch: string; readonly sessionId: string; readonly permissionVersionHmac: string;
  readonly issuedAt: string; readonly expiresAt: string;
}
