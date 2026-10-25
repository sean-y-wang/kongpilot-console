import type { TransferDiff } from './transfer.types';
import { transferFail } from './transfer.types';

/** Pure public projection: no raw payload, password intent or unkeyed secret hash. */
export function formatSafeDiff(diff: TransferDiff, redact: (value: unknown) => unknown): Record<string, unknown> {
  if (typeof redact !== 'function') transferFail('CONFIGURATION_REDACTOR_REQUIRED');
  return {
    mode: diff.mode, changeCount: diff.changes.length, unchangedCount: diff.unchangedCount,
    referenceCount: diff.referenceCount, recoveryComplete: diff.recoveryComplete,
    blockerCodes: [...diff.blockerCodes],
    changes: diff.changes.map(change => ({
      objectKey: change.objectKey, entityType: change.entityType, nativeId: change.nativeId,
      parentId: change.parentId ?? null, credentialKind: change.credentialKind ?? null,
      action: change.action, blockerCodes: [...change.blockerCodes],
      recovery: change.before?.recovery.state ?? 'new', patch: redact(change.patch),
      clearMap: [...change.clearMap],
    })),
  };
}
