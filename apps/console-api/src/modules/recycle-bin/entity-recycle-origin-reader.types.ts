import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { PreparedEntityChange, StoredEntitySubjectAction } from '../entities/entity-change.types';

/** Server-only identity/scope input. It supplies no session, native path,
 * archive capability, caller proof or substitute encrypted materials. */
export interface EntityRecycleOriginReadInput {
  readonly clusterId: string; readonly workspaceId: string; readonly entryId: string;
  readonly actor: EntityActor; readonly subjectAction: StoredEntitySubjectAction;
}
export interface EntityRecycleClosedOrigin {
  readonly kind: 'entity-change'; readonly id: string; readonly workspace_id: string;
  readonly workflow_id: string; readonly workflow_state: string; readonly execution_state: string;
  readonly state: 'succeeded'; readonly unresolved_steps: false;
  readonly graphHmac: string; readonly nodeManifestHmac: string; readonly sourceFactsHmac: string;
  readonly closedRestoreCoverage?: EntityRecycleClosedRestoreCoverage;
}
/** Historical evidence only. No Source SID, native handle, renewed grant,
 * plaintext credential or transport permission crosses this boundary. */
export interface EntityRecyclePresentNodeHistory {
  readonly nodeKey: string; readonly nativeType: string; readonly nativeId: string;
  readonly parentId: string | null; readonly credentialKind: string | null;
  readonly packetKey: string; readonly attemptId: string; readonly operationId: string;
  readonly operationKey: string; readonly resultHmac: string; readonly outcomeFactHmac: string;
}
export interface EntityRecycleRemainingNodeHistory {
  readonly nodeKey: string; readonly nativeType: string; readonly nativeId: string;
  readonly parentId: string | null; readonly credentialKind: string | null;
  readonly classification: 'failed-known-not-sent' | 'unattempted'; readonly packetKey: string;
  readonly attemptId: string | null; readonly operationId: string | null; readonly outcomeFactHmac: string | null;
}
export interface EntityRecycleClosedRestoreCoverage {
  readonly version: 1; readonly clusterId: string; readonly workspaceId: string; readonly entryId: string;
  readonly graphHmac: string; readonly nodeManifestHmac: string;
  readonly sourceId: string; readonly intentId: string; readonly intentRevision: number;
  readonly baselineId: string; readonly pinId: string; readonly workflowId: string; readonly workflowExecutionId: string;
  readonly materialHmac: string; readonly changeDigest: string; readonly packetManifestHmac: string;
  readonly terminalMetadataAudit: Readonly<{ id: string; eventHash: string; proofHmac: string;
    outcomeEventId: string; outcomeFactHmac: string; requestHmac: string }>;
  readonly presentNodes: readonly EntityRecyclePresentNodeHistory[];
  readonly remainingNodes: readonly EntityRecycleRemainingNodeHistory[];
  /** Secret fingerprint of the entire summary with this field omitted. */
  readonly coverageHmac: string;
}
/** SELECT-only certificate for the fixed failed two-packet, zero-send source.
 * It contains no current authority, native receipt, source SID or plaintext.
 * Projection state is descriptive and is excluded from the immutable proof. */
export interface EntityRecycleKnownNoSendPartialSource {
  readonly version: 1; readonly clusterId: string; readonly workspaceId: string;
  readonly entryId: string; readonly sourceId: string; readonly sourceHmac: string;
  readonly workflowId: string; readonly workflowExecutionId: string;
  readonly intentId: string; readonly intentRevision: number;
  readonly baselineId: string; readonly pinId: string; readonly materialHmac: string;
  readonly changeDigest: string; readonly packetManifestHmac: string;
  readonly historyCoverageHmac: string; readonly oldSourceId: string; readonly graphHmac: string;
  readonly failedNodeKey: string; readonly failedPacketKey: string;
  readonly operationId: string; readonly attemptId: string;
  readonly outcomeEventId: string; readonly outcomeFactHmac: string;
  readonly proofHmac: string; readonly alreadyClosed: boolean;
}
export interface EntityRecycleOriginReaderDelegate {
  /** Root verifies the genuine current request identity/SID and CID/WID. An
   * old Source SID is historical evidence and is never renewed or reused.
   * The final current-grant fence uses fresh authority outside the supplied
   * repeatable-read evidence transaction, which cannot observe new revocations. */
  assertCurrentScope(input: Readonly<EntityRecycleOriginReadInput>, tx: DbService): Promise<void>;
  /** Optional Root-only evidence exception for first-packet revalidation of
   * the actual current, unsent HTTP V1 restore execution for this exact entry.
   * Root derives its UUID from private execution/packet registries plus the
   * real ALS identity, current source/approvals and baseline, never an HTTP
   * parameter or copied source row. Return null outside that narrow phase.
   * Fresh authority reads happen outside this read-only evidence snapshot.
   * The UUID can exclude only that executing source's pending evidence; it
   * creates no native permit and never suppresses any unknown outcome. */
  activeRestoreRevalidation?(input: Readonly<EntityRecycleOriginReadInput>, tx: DbService): Promise<string | null>;
  /** Called only after the immutable stored source/whole graph/native facts
   * have been verified. Current historical read/child-private closure is checked
   * by Root, independent of subjectAction. New restore/write authority is
   * checked by the subsequent Recycle prepare; old DELETE grants are not that
   * authority. Neither original permissionVersion nor caller DTO is a grant. */
  assertFrozenSubject(input: Readonly<{ request: EntityRecycleOriginReadInput; material: PreparedEntityChange;
    sourceId: string; workflowId: string; packetKeys: readonly string[]; graphHmac: string }>, tx: DbService): Promise<void>;
}
export interface EntityRecycleOriginLookup {
  readClosedOrigin(input: EntityRecycleOriginReadInput): Promise<EntityRecycleClosedOrigin>;
}
/** Kept inside authenticated encrypted SQL021 outcome evidence only. A copy
 * supplied by a client is not actual transport/GET404 proof or any authority. */
/** Ordinary entities: exact point GET404. Kong 1.5 targets: archive-sealed
 * dual history/effective list EOF poststate (never bare GET404). */
export type EntityRecycleDeleteVerification =
  | {
      readonly version: 1; readonly clusterId: string; readonly workspaceId: string; readonly entryId: string;
      readonly nodeKey: string; readonly packetKey: string; readonly attemptId: string; readonly operationId: string;
      readonly canonicalPath: string; readonly nativeId: string; readonly status: 404;
      readonly kind?: 'get404';
    }
  | {
      readonly version: 1; readonly clusterId: string; readonly workspaceId: string; readonly entryId: string;
      readonly nodeKey: string; readonly packetKey: string; readonly attemptId: string; readonly operationId: string;
      readonly canonicalPath: string; readonly nativeId: string; readonly status: 'target-poststate';
      readonly kind: 'target-poststate';
      readonly historyRetention: 'weight-zero-overlay' | 'native-pruned';
      readonly observationHmac: string; readonly archiveGraphHmac: string;
      readonly address: string;
    }
