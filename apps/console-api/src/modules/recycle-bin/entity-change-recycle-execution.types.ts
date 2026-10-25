import type { EntityRecycleCurrentWitnessHandle } from './entity-recycle-current-witness.types';
import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { EntityChangePacket, PreparedEntityChange } from '../entities/entity-change.types';
import type { EntityChangeBaselineReceipt, EntityChangePacketAttemptBinding } from '../workflows/entity-change-execution-facts.types';
import type { EntityExecutionSourceByOrigin } from '../workflows/entity-change-schedule.contract';
import type { EntityRecycleOriginReadInput, EntityRecycleOriginReaderDelegate } from './entity-recycle-origin-reader.types';
import type { EntityChangeRecycleDeleteVerification } from './entity-change-recycle-facts.types';

/** Immutable inspection only. The original opaque handle, verified in Root's
 * private registries on every checkpoint, remains the sole authority. */
export interface EntityRecycleExecutionInspection {
  readonly source: EntityExecutionSourceByOrigin;
  readonly baseline: EntityChangeBaselineReceipt;
  readonly actor: EntityActor;
  readonly prepared: PreparedEntityChange;
}
export interface EntityRecyclePacketInspection extends EntityRecycleExecutionInspection {
  readonly packet: EntityChangePacket;
  readonly binding: EntityChangePacketAttemptBinding;
  readonly operationKey: string;
  readonly operationId?: string;
  readonly sent: boolean;
  readonly wireSpent: boolean;
  readonly transportStatus?: number;
  readonly responseHmac?: string;
  readonly transportHmac?: string;
  /** Read-only projection of Root's actual transport-ticket observation,
   * never a callback return or caller supplied status. */
  readonly verificationStatus?: number;
  readonly verificationPath?: string;
  /** Kong 1.5 Target DELETE poststate seal (weight=0 overlay / prune). */
  readonly targetPoststate?: Readonly<{
    historyRetention: 'weight-zero-overlay' | 'native-pruned';
    observationHmac: string; archiveGraphHmac: string;
    originalNativeId: string; address: string;
  }>;
}

/** Root installs this once; no handler, HTTP route or copied inspection can
 * substitute for a real execution/packet handle. appendKnownOutcome requires
 * actual succeeded V3 mutation, recorded raw transport, and actual point GET404
 * when supplied; it never derives provenance from a status-shaped object. */
export interface EntityChangeRecycleKernelBridge {
  execution(originalHandle: object): Readonly<EntityRecycleExecutionInspection>;
  packet(originalHandle: object): Readonly<EntityRecyclePacketInspection>;
  verifyExecution(originalHandle: object, checkpoint: string, tx?: DbService): Promise<void>;
  verifyPacket(originalHandle: object, checkpoint: string, tx?: DbService): Promise<void>;
  assertCurrentGraphParties(originalExecution:object,currentWitness:EntityRecycleCurrentWitnessHandle,tx?:DbService):Promise<void>;
  appendKnownOutcome(originalHandle: object, deleteVerification: EntityChangeRecycleDeleteVerification | undefined, tx: DbService): Promise<void>;
  observeTargetDeletePoststate(originalHandle: object, observation: Readonly<{
    historyRetention: 'weight-zero-overlay' | 'native-pruned';
    observationHmac: string; archiveGraphHmac: string;
    originalNativeId: string; address: string;
  }>): void;
  assertCurrentOriginScope(input: Readonly<EntityRecycleOriginReadInput>, tx?: DbService): Promise<void>;
  assertFrozenOriginSubject(input: Parameters<EntityRecycleOriginReaderDelegate['assertFrozenSubject']>[0], tx?: DbService): Promise<void>;
  /** Narrow read-only revalidation evidence supplied by the genuine current
   * Root execution claim. Missing implementation preserves the closed reader. */
  activeRestoreRevalidation?(input: Readonly<EntityRecycleOriginReadInput>, tx?: DbService): Promise<string | null>;
  /** SQL/AEAD/old receipt checking only. It cannot issue current graph
   * authority. The fixed opaque witness subsequently supplies actual reads. */
  verifyPartialRestoreFacts?(originalExecutionHandle:object,
    checkpoint:'capture'|'packet'|'before-send'|'outcome'|'current-response',tx?:DbService):Promise<void>;
  /** Optional, bootstrap-only current verifier. It must resolve the ORIGINAL
   * execution handle in Root's private registry and verify real ALS/SID/grants,
   * approvals/lease/full baseline, prior 5 receipts and preserved reservation
   * known-not-sent audit, plus fresh raw Kong/Basic custody. Copied HMA/SQL/DTO
   * facts never substitute for it. Missing callback keeps partial restore shut. */
  verifyPartialRestoreCurrent?(originalExecutionHandle: object,
    checkpoint: 'capture' | 'packet' | 'before-send' | 'outcome', tx?: DbService): Promise<void>;
}
