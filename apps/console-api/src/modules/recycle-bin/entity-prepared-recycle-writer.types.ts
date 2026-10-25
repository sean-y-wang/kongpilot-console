import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { EntityChangeMetadataObligation, EntityChangePacket } from '../entities/entity-change.types';
import type { EntityChangeExecutionSource } from '../workflows/entity-change-intent.types';
import type { EntityChangeBaselineReceipt } from '../workflows/entity-change-execution-facts.types';

declare const archiveHandleBrand: unique symbol;
declare const recyclePacketHandleBrand: unique symbol;
declare const repairHandleBrand: unique symbol;
/** Brands are compile-time labels. Runtime authority comes only from Root's
 * private issued-handle registries and real source/approval/receipt checks. */
export type EntityPreparedRecycleArchiveHandle = object & { readonly [archiveHandleBrand]: true };
export type EntityPreparedRecyclePacketHandle = object & { readonly [recyclePacketHandleBrand]: true };
export type EntityPreparedRecycleRepairHandle = object & { readonly [repairHandleBrand]: true };
export type PreparedRecycleArchiveObligation = Extract<EntityChangeMetadataObligation, { kind: 'recycle-archive' }>;
export type PreparedRecycleRestoreObligation = Extract<EntityChangeMetadataObligation, { kind: 'recycle-restore' }>;
export type PreparedRecycleObligation = PreparedRecycleArchiveObligation | PreparedRecycleRestoreObligation;
export interface PreparedRecycleSourceBinding {
  readonly source: EntityChangeExecutionSource;
  readonly baseline: EntityChangeBaselineReceipt;
  readonly actor: EntityActor;
}
export interface EntityPreparedRecycleArchiveGrant extends PreparedRecycleSourceBinding {
  /** Allocated once by Root and sealed to the real source. Never allocated in
   * the storage writer or accepted as an HTTP archive identifier. */
  readonly entryId: string;
  readonly expiresAt: string;
  readonly obligation: PreparedRecycleArchiveObligation;
  readonly packets: readonly Readonly<EntityChangePacket>[];
}
export interface EntityPreparedRecycleArchiveReceipt {
  readonly entryId: string;
  readonly graphHmac: string;
  readonly payloadHmac: string;
  readonly nodeManifestHmac: string;
  readonly nodeCount: number;
  readonly packetCount: number;
}
export interface EntityPreparedRecyclePacketGrant extends PreparedRecycleSourceBinding {
  readonly entryId: string;
  readonly nodeKey: string;
  readonly operationKey: string;
  readonly packet: Readonly<EntityChangePacket>;
  readonly obligation: PreparedRecycleObligation;
  /** Whole immutable plan subset, so missing/extra graph packets and their
   * dependency order cannot be accepted as a one-node completion proof. */
  readonly packets: readonly Readonly<EntityChangePacket>[];
}
export interface EntityPreparedRecyclePacketReceipt {
  readonly entryId: string;
  readonly nodeKey: string;
  readonly packetKey: string;
  readonly operationKey: string;
  readonly operationId: string;
  readonly nativeId: string;
  readonly state: 'succeeded';
  readonly metadata: 'complete';
}
export interface EntityPreparedRecycleRepairGrant extends EntityPreparedRecyclePacketGrant {
  /** Root loads and verifies the original succeeded, remote_completed
   * operation + attempt + source. No caller-provided result/receipt qualifies. */
  readonly originalOperationId: string;
  readonly knownNativeComplete: true;
  readonly nativeResult: unknown;
}
export interface EntityPreparedRecycleWriterDelegate {
  verifyCurrentRestore(handle:EntityPreparedRecyclePacketHandle,operationId:string,nativeResult:unknown):Promise<void>;
  runArchive<T>(handle: EntityPreparedRecycleArchiveHandle, store: (grant: Readonly<EntityPreparedRecycleArchiveGrant>) => Promise<T>): Promise<T>;
  /** Restore grants require the full fixed POST subset to be durably bound
   * before the first callback; no per-node late allocation or new capture. */
  runPacket<T>(handle: EntityPreparedRecyclePacketHandle, write: (grant: Readonly<EntityPreparedRecyclePacketGrant>) => Promise<T>): Promise<T>;
  runRepair<T>(handle: EntityPreparedRecycleRepairHandle, repair: (grant: Readonly<EntityPreparedRecycleRepairGrant>) => Promise<T>): Promise<T>;
  /** Bootstrap verifies actual source/baseline and archive/node manifest in
   * this transaction. It cannot replace graph bytes, allocate another entry,
   * supply an HTTP proof, or bind a fake aggregate mutation. */
  linkArchive(handle: EntityPreparedRecycleArchiveHandle, receipt: Readonly<EntityPreparedRecycleArchiveReceipt>, tx: DbService): Promise<void>;
  /** Root installs the genuine one-node archive scope for the exact bound
   * packet operation. The writer itself never creates an archive capability. */
  runVerifiedDelete<T>(handle: EntityPreparedRecyclePacketHandle, operationId: string, send: () => Promise<T>): Promise<T>;
  /** One fixed GET verification under the real packet operation. Root derives
   * its allowed point path from the issued packet; there is no path parameter.
   * Target DELETE may instead seal Kong 1.5 poststate via recordTargetDeletePoststate. */
  runVerificationRead<T>(handle: EntityPreparedRecyclePacketHandle, operationId: string, read: () => Promise<T>): Promise<T>;
  /** Seal Kong 1.5 Target DELETE poststate into Root's private packet claim.
   * Must follow a successful observeTargetDeletePoststate under runVerificationRead. */
  recordTargetDeletePoststate(handle: EntityPreparedRecyclePacketHandle, observation: Readonly<{
    historyRetention: 'weight-zero-overlay' | 'native-pruned';
    observationHmac: string; archiveGraphHmac: string;
    originalNativeId: string; address: string;
  }>): void;
  /** Before any mutable node status is committed, Root verifies the real
   * operation/attempt tuple and its known complete native evidence. This
   * callback records SQL023 completion facts in the same metadata transaction. */
  linkNodeReceipt(handle: EntityPreparedRecyclePacketHandle | EntityPreparedRecycleRepairHandle,
    receipt: Readonly<EntityPreparedRecyclePacketReceipt>, tx: DbService): Promise<void>;
}

/** SQL023's normalized whole archive graph. It contains identities and keyed
 * hashes, never the private reference configuration or raw recovery secrets. */
export interface EntityPreparedRecycleNodeManifest {
  readonly key: string; readonly order: number; readonly nativeType: string; readonly nativeId: string;
  readonly parentId: string | null; readonly credentialKind: string | null;
  readonly affected: boolean; readonly dependencies: readonly string[];
  readonly pathHmac: string; readonly dataHmac: string; readonly restoreHmac: string | null;
}
