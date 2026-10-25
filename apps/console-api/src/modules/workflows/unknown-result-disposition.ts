/** Pure KP-003 / historical SQL042 unknown-result disposition helpers.
 * Root supplies verified evidence; this module never sends Native and never
 * invents KnownNotSent from unchanged config or zero mutation counts. */

export type UnknownResultDispositionKind = 'verified-applied' | 'verified-not-applied' | 'verification-rejected' | 'abandoned';

export interface UnknownResultOriginalReceipt {
  readonly executionState: 'uncertain';
  readonly mutationId?: string | null;
  readonly mutationState?: 'uncertain' | null;
  readonly remoteStarted?: boolean | null;
  readonly remoteCompleted?: boolean | null;
  readonly errorCode?: string | null;
}

export interface UnknownResultDispositionEvidence {
  readonly version: 1;
  readonly disposition: UnknownResultDispositionKind;
  readonly scheduleId: string;
  readonly claimId: string;
  readonly workflowId: string;
  readonly workflowExecutionId: string;
  readonly workflowPlanRevision: number;
  readonly workflowPlanHash: string;
  readonly requestHmac: string;
  readonly evidenceHmac: string;
  readonly original: UnknownResultOriginalReceipt;
  /** SQL050: two-person abandon request (abandoned only; mutation path). */
  readonly abandonRequestId?: string;
  /** SQL051: two-person unsent abandon request (abandoned only; no mutation). */
  readonly unsentAbandonRequestId?: string;
  /** SQL051: never-sent configuration job closed alongside the disposition. */
  readonly unsentJobId?: string;
  /** Must always be 0 — disposition is metadata-only. */
  readonly nativeRequestsSent: 0;
}

export class UnknownResultDispositionRejected extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'UnknownResultDispositionRejected';
  }
}

const hex = /^[a-f\d]{64}$/;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function expectedMetadataState(disposition: UnknownResultDispositionKind): 'succeeded' | 'failed' | 'uncertain' {
  if (disposition === 'verified-applied') return 'succeeded';
  if (disposition === 'verified-not-applied' || disposition === 'abandoned') return 'failed';
  return 'uncertain';
}

/** Fail-closed evidence shape check before any SQL write. */
export function assertUnknownResultDispositionEvidence(input: UnknownResultDispositionEvidence): void {
  const o = input.original;
  if (input.version !== 1) throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_EVIDENCE_VERSION');
  if (!['verified-applied', 'verified-not-applied', 'verification-rejected', 'abandoned'].includes(input.disposition))
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_DISPOSITION_INVALID');
  if (!uuid.test(input.scheduleId) || !uuid.test(input.claimId) || !uuid.test(input.workflowId) || !uuid.test(input.workflowExecutionId))
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_IDENTITY_INVALID');
  if (!Number.isInteger(input.workflowPlanRevision) || input.workflowPlanRevision < 1)
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_PLAN_REVISION_INVALID');
  if (!hex.test(input.workflowPlanHash) || !hex.test(input.requestHmac) || !hex.test(input.evidenceHmac))
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_HMAC_INVALID');
  if (input.nativeRequestsSent !== 0) throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_NATIVE_REPLAY_FORBIDDEN');
  if (o.executionState !== 'uncertain') throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_EXECUTION_NOT_UNCERTAIN');
  const hasMutation = o.mutationId != null && o.mutationId !== '';
  if (hasMutation) {
    if (!uuid.test(o.mutationId!) || o.mutationState !== 'uncertain')
      throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
    if (typeof o.remoteStarted !== 'boolean' || typeof o.remoteCompleted !== 'boolean')
      throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
    // remote_started=true with incomplete remote is the classic unknown; still not KnownNotSent.
    if (o.remoteStarted === false && o.remoteCompleted === true)
      throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
  } else if (o.mutationState != null || o.remoteStarted != null || o.remoteCompleted != null || o.errorCode != null) {
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
  }
  // verified-applied always needs a mutation receipt. verified-not-applied /
  // abandoned may close a never-sent schedule-origin execution (SQL051) with
  // mutationId null; verification-rejected remains non-closing.
  if (input.disposition === 'verified-applied' && !hasMutation)
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_CLOSING_REQUIRES_MUTATION');
  const hasMutationAbandon = typeof input.abandonRequestId === 'string' && uuid.test(input.abandonRequestId);
  const hasUnsentAbandon = typeof input.unsentAbandonRequestId === 'string' && uuid.test(input.unsentAbandonRequestId);
  if (input.disposition === 'abandoned') {
    if (hasMutationAbandon === hasUnsentAbandon) // need exactly one
      throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_ABANDON_REQUEST_REQUIRED');
    if (hasUnsentAbandon && hasMutation)
      throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_ABANDON_REQUEST_REQUIRED');
    if (hasMutationAbandon && !hasMutation)
      throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_ABANDON_REQUEST_REQUIRED');
  } else if (hasMutationAbandon || hasUnsentAbandon) {
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_ABANDON_REQUEST_REQUIRED');
  }
  if (input.unsentJobId != null && (typeof input.unsentJobId !== 'string' || !uuid.test(input.unsentJobId) || hasMutation))
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_UNSENT_JOB_INVALID');
  if ((input.disposition === 'verified-not-applied' || input.disposition === 'abandoned') && !hasMutation && input.unsentJobId == null)
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_UNSENT_JOB_REQUIRED');
}

/** Match a live mutation row against the frozen original receipt snapshot. */
export function assertOriginalMutationReceiptMatch(
  original: UnknownResultOriginalReceipt,
  row: Readonly<{ id: string; state: string; remote_started: boolean; remote_completed: boolean; error_code: string | null; workflow_execution_id: string | null }>,
  workflowExecutionId: string,
  /** SQL049: caller proved the exact workflow_configuration_execution_origins link in-transaction. */
  configurationOriginLinked = false,
): void {
  if (!original.mutationId || row.id !== original.mutationId)
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
  if ((row.workflow_execution_id === null ? !configurationOriginLinked : row.workflow_execution_id !== workflowExecutionId) || row.state !== 'uncertain' || original.mutationState !== 'uncertain')
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
  if (row.remote_started !== original.remoteStarted || row.remote_completed !== original.remoteCompleted
    || (row.error_code ?? null) !== (original.errorCode ?? null))
    throw new UnknownResultDispositionRejected('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
}

export function closingDispositionForState(state: 'succeeded' | 'failed'): Exclude<UnknownResultDispositionKind, 'verification-rejected'> {
  return state === 'succeeded' ? 'verified-applied' : 'verified-not-applied';
}
