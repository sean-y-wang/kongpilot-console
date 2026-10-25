import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { EntityChangePacket } from '../entities/entity-change.types';
import type { EntityChangeBaselineReceipt, EntityChangePacketAttemptBinding } from '../workflows/entity-change-execution-facts.types';
import type { EntityExecutionSourceByOrigin } from '../workflows/entity-change-schedule.contract';
import type { EntityPreparedRecycleArchiveGrant, EntityPreparedRecycleArchiveReceipt, EntityPreparedRecyclePacketGrant,
  EntityPreparedRecyclePacketReceipt, PreparedRecycleRestoreObligation } from './entity-prepared-recycle-writer.types';

export interface EntityChangeRecycleFactsBinding {
  readonly source: EntityExecutionSourceByOrigin; readonly baseline: EntityChangeBaselineReceipt; readonly actor: EntityActor;
}
export interface EntityChangeRecycleArchiveFactsInput {
  readonly grant: Omit<EntityPreparedRecycleArchiveGrant, 'source'> & { readonly source: EntityExecutionSourceByOrigin };
  readonly receipt: EntityPreparedRecycleArchiveReceipt;
}
export interface EntityChangeRecycleRestoreFactsInput extends EntityChangeRecycleFactsBinding {
  readonly entryId: string; readonly obligation: PreparedRecycleRestoreObligation;
  readonly packets: readonly Readonly<EntityChangePacket>[];
}
/** Fixed delete-completion observation, sealed by Root after actual raw 204/null.
 * Ordinary entities use exact point GET404. Kong 1.5 targets use archive-sealed
 * dual history/effective list EOF poststate (never bare GET404). Saving either
 * shape cannot establish its provenance or grant native rights. */
export type EntityChangeRecycleDeleteVerification =
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
export interface EntityChangeRecycleCompletionFactsInput {
  readonly grant: Omit<EntityPreparedRecyclePacketGrant, 'source'> & { readonly source: EntityExecutionSourceByOrigin };
  readonly attempt: EntityChangePacketAttemptBinding; readonly receipt: EntityPreparedRecyclePacketReceipt;
  readonly nativeResult: unknown; readonly deleteVerification?: EntityChangeRecycleDeleteVerification;
}
/** Once-installed genuine Root proof verifiers. No data-shaped/copy proof,
 * asserted status, receipt or encrypted result can replace their private
 * source/packet/transport observation registries. No verifier mints a permit. */
export interface EntityChangeRecycleFactsDelegate {
  verifyArchive(input: Readonly<EntityChangeRecycleArchiveFactsInput>, proof: object, tx: DbService): Promise<void>;
  verifyRestore(input: Readonly<EntityChangeRecycleRestoreFactsInput>, proof: object, tx: DbService): Promise<void>;
  verifyCompletion(input: Readonly<EntityChangeRecycleCompletionFactsInput>, proof: object, tx: DbService): Promise<void>;
}
