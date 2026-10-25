/** Pure, fail-closed decision for an uncertain schedule-origin configuration_v2
 * Kong 1.5 targets mutation (create or append-update with an allocated id).
 * Only an unambiguous fresh readback may close it; everything else is
 * 'ambiguous' and leaves the receipt untouched. */
export type ConfigurationTargetDecision = 'verified-applied' | 'verified-not-applied' | 'ambiguous';
export interface ConfigurationTargetObservedEntry { readonly id: string; readonly target: string; readonly weight: number }
export interface ConfigurationTargetDecisionInput {
  readonly action: 'create' | 'update';
  /** Kong-normalised address the mutation targets. */
  readonly address: string;
  readonly desiredWeight: number;
  readonly allocatedId: string;
  /** update only: the pre-change effective record captured before the send. */
  readonly before: ConfigurationTargetObservedEntry | null;
  /** Current effective entry for the address (Kong lists weight>0 only), complete traversal. */
  readonly effective: ConfigurationTargetObservedEntry | null;
  /** Every history (/targets/all) entry whose id is the allocated id, complete traversal. */
  readonly historyAllocated: readonly ConfigurationTargetObservedEntry[];
  readonly historyComplete: boolean;
  readonly effectiveComplete: boolean;
  /** Parent upstream is gone (Kong cascades its targets): nothing left to prove either way. */
  readonly parentAbsent?: boolean;
}
export interface ConfigurationTargetDecisionResult { readonly decision: ConfigurationTargetDecision; readonly reason: string }

const same = (a: ConfigurationTargetObservedEntry | null, b: ConfigurationTargetObservedEntry | null) =>
  !!a && !!b && a.id === b.id && a.target === b.target && a.weight === b.weight;
const weightOk = (w: unknown) => Number.isInteger(w) && (w as number) >= 0 && (w as number) <= 1000;

export function decideConfigurationTargetResult(input: ConfigurationTargetDecisionInput): ConfigurationTargetDecisionResult {
  const r = (decision: ConfigurationTargetDecision, reason: string) => Object.freeze({ decision, reason });
  if (!input || !['create', 'update'].includes(input.action) || typeof input.address !== 'string' || !input.address
    || typeof input.allocatedId !== 'string' || !input.allocatedId || !weightOk(input.desiredWeight)) return r('ambiguous', 'input-invalid');
  if (input.parentAbsent) return r('ambiguous', 'parent-absent');
  if (!input.historyComplete || !input.effectiveComplete) return r('ambiguous', 'readback-incomplete');
  if (input.action === 'update') {
    if (!input.before || input.before.target !== input.address || input.before.id === input.allocatedId) return r('ambiguous', 'before-invalid');
  } else if (input.before !== null) return r('ambiguous', 'before-invalid');
  if (input.historyAllocated.length > 1) return r('ambiguous', 'allocated-duplicated');
  const written = input.historyAllocated[0] ?? null;
  if (written) {
    if (written.target !== input.address || written.weight !== input.desiredWeight) return r('ambiguous', 'allocated-differs');
    if (input.desiredWeight === 0) return input.effective === null ? r('verified-applied', 'allocated-written-disabled') : r('ambiguous', 'effective-superseded');
    return same(input.effective, written) ? r('verified-applied', 'allocated-effective') : r('ambiguous', 'effective-superseded');
  }
  if (input.action === 'update')
    return same(input.effective, input.before) ? r('verified-not-applied', 'before-still-effective') : r('ambiguous', 'effective-changed');
  return input.effective === null ? r('verified-not-applied', 'address-absent') : r('ambiguous', 'effective-changed');
}

/** Unsent (no mutation_operations row) settle: parent-absent is verified-not-applied
 * because the send ledger never opened. A verified-applied readback without a
 * mutation is returned as-is so the caller can fail closed. */
export function decideConfigurationUnsentTargetResult(input: ConfigurationTargetDecisionInput): ConfigurationTargetDecisionResult {
  if (input?.parentAbsent) return Object.freeze({ decision: 'verified-not-applied' as const, reason: 'unsent-parent-absent' });
  return decideConfigurationTargetResult(input);
}

export type ConfigurationUnsentAggregateDecision = 'verified-not-applied' | 'ambiguous' | 'appears-applied';

/** Combine per-step unsent decisions. Any verified-applied ⇒ appears-applied (fail closed). */
export function aggregateConfigurationUnsentDecisions(
  steps: readonly ConfigurationTargetDecisionResult[],
): { decision: ConfigurationUnsentAggregateDecision; reason: string } {
  if (!steps.length) return Object.freeze({ decision: 'ambiguous', reason: 'no-steps' });
  if (steps.some(s => s.decision === 'verified-applied'))
    return Object.freeze({ decision: 'appears-applied', reason: 'allocated-present-without-mutation' });
  if (steps.some(s => s.decision === 'ambiguous'))
    return Object.freeze({ decision: 'ambiguous', reason: steps.find(s => s.decision === 'ambiguous')!.reason });
  return Object.freeze({ decision: 'verified-not-applied', reason: steps.every(s => s.reason === 'unsent-parent-absent') ? 'unsent-parent-absent' : 'unsent-not-applied' });
}
