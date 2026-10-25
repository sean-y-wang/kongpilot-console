import { describe, expect, it } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import {
  assertOriginalMutationReceiptMatch,
  assertUnknownResultDispositionEvidence,
  closingDispositionForState,
  expectedMetadataState,
  UnknownResultDispositionRejected,
  type UnknownResultDispositionEvidence,
} from '../../apps/console-api/src/modules/workflows/unknown-result-disposition';

const hex = (s: string) => createHash('sha256').update(s).digest('hex');
const base = (): UnknownResultDispositionEvidence => ({
  version: 1,
  disposition: 'verified-applied',
  scheduleId: randomUUID(),
  claimId: randomUUID(),
  workflowId: randomUUID(),
  workflowExecutionId: randomUUID(),
  workflowPlanRevision: 1,
  workflowPlanHash: hex('plan'),
  requestHmac: hex('req'),
  evidenceHmac: hex('ev'),
  nativeRequestsSent: 0,
  original: {
    executionState: 'uncertain',
    mutationId: randomUUID(),
    mutationState: 'uncertain',
    remoteStarted: true,
    remoteCompleted: false,
    errorCode: 'MUTATION_RESULT_UNCERTAIN',
  },
});

describe('unknown-result disposition evidence (KP-003 / SQL044)', () => {
  it('accepts closing evidence with original uncertain mutation receipt and zero native sends', () => {
    expect(() => assertUnknownResultDispositionEvidence(base())).not.toThrow();
    expect(expectedMetadataState('verified-applied')).toBe('succeeded');
    expect(expectedMetadataState('verified-not-applied')).toBe('failed');
    expect(expectedMetadataState('verification-rejected')).toBe('uncertain');
    expect(closingDispositionForState('succeeded')).toBe('verified-applied');
    expect(closingDispositionForState('failed')).toBe('verified-not-applied');
  });

  it('rejects native replay, non-uncertain execution, and receipt mismatches', () => {
    expect(() => assertUnknownResultDispositionEvidence({ ...base(), nativeRequestsSent: 1 as 0 }))
      .toThrow(UnknownResultDispositionRejected);
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), original: { ...base().original, executionState: 'succeeded' as 'uncertain' },
    })).toThrow(/UNKNOWN_RESULT_EXECUTION_NOT_UNCERTAIN/);
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), disposition: 'verified-applied', original: { executionState: 'uncertain' },
    })).toThrow(/UNKNOWN_RESULT_CLOSING_REQUIRES_MUTATION/);
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), original: { executionState: 'uncertain', mutationState: 'uncertain', remoteStarted: true },
    })).toThrow(/UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH/);
  });

  it('allows verified-not-applied without mutation when unsentJobId is bound (SQL051)', () => {
    const jobId = randomUUID();
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), disposition: 'verified-not-applied', unsentJobId: jobId, original: { executionState: 'uncertain' },
    })).not.toThrow();
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), disposition: 'verified-not-applied', original: { executionState: 'uncertain' },
    })).toThrow(/UNKNOWN_RESULT_UNSENT_JOB_REQUIRED/);
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), disposition: 'verified-applied', original: { executionState: 'uncertain' },
    })).toThrow(/UNKNOWN_RESULT_CLOSING_REQUIRES_MUTATION/);
  });

  it('allows verification-rejected without mutation and still forbids fabricated mutation fields', () => {
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), disposition: 'verification-rejected', original: { executionState: 'uncertain' },
    })).not.toThrow();
    expect(() => assertUnknownResultDispositionEvidence({
      ...base(), disposition: 'verification-rejected',
      original: { executionState: 'uncertain', remoteStarted: false },
    })).toThrow(/UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH/);
  });

  it('matches live mutation rows only when identity and remote flags are unchanged', () => {
    const evidence = base();
    const row = {
      id: evidence.original.mutationId!,
      state: 'uncertain',
      remote_started: true,
      remote_completed: false,
      error_code: 'MUTATION_RESULT_UNCERTAIN',
      workflow_execution_id: evidence.workflowExecutionId,
    };
    expect(() => assertOriginalMutationReceiptMatch(evidence.original, row, evidence.workflowExecutionId)).not.toThrow();
    expect(() => assertOriginalMutationReceiptMatch(evidence.original, { ...row, remote_completed: true }, evidence.workflowExecutionId))
      .toThrow(/UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH/);
    expect(() => assertOriginalMutationReceiptMatch(evidence.original, { ...row, state: 'failed' }, evidence.workflowExecutionId))
      .toThrow(/UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH/);
  });
});
