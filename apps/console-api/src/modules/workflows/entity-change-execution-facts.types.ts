import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor, CredentialKind } from '../entities/entities.types';
import type { RecycleGraph } from '../recycle-bin/graph-capturer.service';
import type { EntityChangeNormalizedPacket } from './entity-change-intent.types';
import type { EntityExecutionSourceByOrigin } from './entity-change-schedule.contract';

/** Facts supplied by the fixed Root capturer, not an HTTP DTO or authority.
 * Basic restorePayload contains verified plaintext; before retains Kong's
 * real salted hash. Missing recovery material never becomes a ready baseline. */
export interface EntityChangeBaselineObject {
  readonly key: string;
  readonly nativeType: string;
  readonly nativeId: string;
  readonly parentId?: string;
  readonly credentialKind?: CredentialKind;
  readonly affected: boolean;
  readonly present: boolean;
  readonly dependencies: readonly string[];
  readonly before: unknown | null;
  readonly restorePayload?: unknown;
  readonly schemaMaterial: unknown;
  readonly trustedProvenance: unknown;
  readonly recovery: 'complete' | 'absent' | 'reference';
}
export interface EntityChangeBaselineCapture {
  readonly version: 1;
  readonly observedFrom: string;
  readonly observedUntil: string;
  /** Real complete affected/subordinate graphs; create-only absence evidence
   * belongs to objects. Packet count is never a graph completeness proof. */
  readonly graphs: readonly RecycleGraph[];
  readonly objects: readonly EntityChangeBaselineObject[];
  readonly blockerCodes: readonly string[];
  /** Executable node-health observations cannot reconstruct the original
   * manual override. These keys explicitly prohibit automatic rollback. */
  readonly nonreversiblePacketKeys: readonly string[];
}
export interface EntityChangeBaselineEnvelope {
  readonly version: 1;
  readonly baselineId: string;
  readonly source: EntityExecutionSourceByOrigin;
  readonly capture: EntityChangeBaselineCapture;
}
export interface EntityChangeBaselineNormalizedObject {
  readonly key: string; readonly nativeType: string; readonly nativeId: string;
  readonly parentId: string | null; readonly credentialKind: string | null;
  readonly affected: boolean; readonly present: boolean; readonly dependencies: readonly string[];
  readonly beforeHmac: string; readonly restoreHmac: string | null;
  readonly schemaHmac: string; readonly provenanceHmac: string;
  readonly recovery: 'complete' | 'absent' | 'reference';
}
export interface EntityChangeBaselineReceipt {
  readonly baselineId: string; readonly sourceId: string; readonly pinId: string;
  readonly baselineHmac: string; readonly captureHmac: string; readonly objectManifestHmac: string;
  readonly objectCount: number; readonly graphCount: number; readonly protectedUntil: string;
}
export interface EntityChangePacketAttemptBinding {
  readonly sourceId: string; readonly baselineId: string; readonly pinId: string;
  readonly packetKey: string; readonly attemptId: string;
}
export type EntityChangePacketOutcome =
  | 'succeeded' | 'native-rejected' | 'sent-unknown'
  | 'rejected-before-send' | 'failed-known-not-sent';
/** evidence is encrypted as server evidence, never interpreted as a permit.
 * Its truth and no-send/native outcome provenance require Root's genuine
 * WeakMap verifier; passing a copied raw result does not satisfy the callback. */
export type EntityChangePacketFact = {
  readonly version: 1; readonly binding: EntityChangePacketAttemptBinding;
  readonly observedAt: string; readonly evidence: unknown;
} & (
  | { readonly kind: 'send-intent' }
  | { readonly kind: 'outcome'; readonly outcome: EntityChangePacketOutcome;
      readonly nativeStatus?: number; readonly errorCode?: string }
);
export interface EntityChangeRecoveryLink {
  readonly baselineId: string; readonly pinId: string;
  readonly clusterId: string; readonly workspaceId: string;
  readonly newIntentId: string; readonly newIntentRevision: number;
  readonly newMaterialHmac: string; readonly newChangeDigest: string; readonly newPacketManifestHmac: string;
  readonly actorId: string; readonly idempotencyKey: string; readonly requestHmac: string;
}
export type EntityChangeFactsCheckpoint = 'capture' | 'packet' | 'before-send' | 'outcome' | 'retention' | 'recovery';
/** Installed exactly once at bootstrap. No default delegate, source writer,
 * HTTP route, session impersonation, worker, native request or permit minting
 * belongs to this repository. Proof object identity is retained for Root. */
export interface EntityChangeExecutionFactsDelegate {
  verifySource(sourceId: string, checkpoint: EntityChangeFactsCheckpoint, tx: DbService): Promise<void>;
  verifyCapture(sourceId: string, capture: Readonly<EntityChangeBaselineCapture>, rootProof: object, tx: DbService): Promise<void>;
  verifyPacketFact(binding: Readonly<EntityChangePacketAttemptBinding>, fact: Readonly<EntityChangePacketFact> | null, rootProof: object, tx: DbService): Promise<void>;
  assertHistoricalRead(baselineId: string, actor: EntityActor, tx: DbService): Promise<void>;
  verifyRetention(baselineId: string, protectedUntil: string, rootProof: object, tx: DbService): Promise<void>;
  verifyRecovery(link: Readonly<EntityChangeRecoveryLink>, rootProof: object, tx: DbService): Promise<void>;
}
/** Frozen Root/kernel repository contract. Returned values remain stored facts. */
export interface EntityChangeExecutionFactsRepository {
  installFixedDelegate(delegate: EntityChangeExecutionFactsDelegate): void;
  persistReady(sourceId: string, capture: Readonly<EntityChangeBaselineCapture>, rootProof: object, tx?: DbService): Promise<EntityChangeBaselineReceipt>;
  assertReadyForPacket(sourceId: string, baselineId: string, packetKey: string, tx?: DbService): Promise<{
    source: EntityExecutionSourceByOrigin; baseline: EntityChangeBaselineReceipt;
    capture: EntityChangeBaselineCapture; packet: EntityChangeNormalizedPacket;
  }>;
  appendAttempt(binding: Readonly<EntityChangePacketAttemptBinding>, rootProof: object, tx?: DbService): Promise<EntityChangePacketAttemptBinding>;
  appendSendIntent(fact: Extract<EntityChangePacketFact, {kind:'send-intent'}>, rootProof: object, tx?: DbService): Promise<{eventId:string;factHmac:string}>;
  appendOutcome(fact: Extract<EntityChangePacketFact, {kind:'outcome'}>, rootProof: object, tx?: DbService): Promise<{eventId:string;factHmac:string}>;
  historicalProjection(clusterId: string, workspaceId: string, baselineId: string, actor: EntityActor, tx?: DbService): Promise<unknown>;
  extendRetention(baselineId: string, protectedUntil: string, rootProof: object, tx?: DbService): Promise<EntityChangeBaselineReceipt>;
  linkRecovery(link: Readonly<EntityChangeRecoveryLink>, rootProof: object, tx?: DbService): Promise<{linkId:string}>;
}
