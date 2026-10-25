// @ts-nocheck -- narrow pure verification of an unchanged closed attempt.
import { describe, expect, it } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { m10BrowserContinuationRootPacket, m10FinalBrowserEvidenceNames, validateM10ReadOnlyPreviousAttempt } from '../security/lib/m10-auth-journal-coverage.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const bytes = value => Buffer.from(JSON.stringify(value));
const clone = value => structuredClone(value);
const fixture = () => {
  const requests = ['m10-browser-original', 'm10-browser-after-visible-select-fix'].map(sourceCycle => ({ method: 'POST', path: '/api/v1/auth/login', sourceCycle, state: 'response_observed', status: 201 }));
  const previous = { milestone: 'M10', passed: false, sourceCycle: 'm10-browser-readonly-recheck', requests, retainedOriginalEvidence: { originalResponseRewritten: false },
    readOnlyRecheckEvidence: { previousFailurePreserved: true }, readOnlySessionVerification: { requestId: randomUUID() } };
  const previousMaterial = { milestone: 'M10', issuedPackets: clone(requests), responseCookies: ['SyntheticActuallyIssuedCookie'] };
  const report = { passed: false, actualBackend: true, mocksUsed: false, nativeWritesPerformed: false, sourceCycle: 'm10-browser-readonly-recheck', observedWrites: 2, currentCycleObservedWrites: 0, unknownWrites: 0,
    retainedOriginalEvidence: clone(previous.retainedOriginalEvidence), readOnlyRecheckEvidence: clone(previous.readOnlyRecheckEvidence), failure: { errorType: 'TimeoutError', code: 'M10_BROWSER_VERIFICATION_FAILED', failedRequests: [] } };
  const original = { previousReadOnlyJournalBytes: bytes(previous), previousReadOnlyMaterialBytes: bytes(previousMaterial), previousReadOnlyReportBytes: bytes(report) };
  const evidence = { journalName: 'm10-browser-readonly-recheck-journal.json', journalSha256: hash(original.previousReadOnlyJournalBytes), materialName: 'm10-browser-readonly-recheck-secret-material.json', materialSha256: hash(original.previousReadOnlyMaterialBytes),
    reportPath: 'artifacts/M10/browser-readonly-recheck/verification.json', reportSha256: hash(original.previousReadOnlyReportBytes), verificationAttempt: 1, originalPassed: false,
    observedWrites: 2, currentCycleObservedWrites: 0, unknownWrites: 0, originalFailurePreserved: true, originalResponseRewritten: false, originalRequestsReplayed: false };
  const journal = { ...clone(previous), passed: true, verificationAttempt: 2, readOnlyPreviousAttemptEvidence: evidence, readOnlySessionVerification: { requestId: randomUUID() } };
  const material = { ...clone(previousMaterial), readOnlyPreviousAttemptEvidence: clone(evidence), retainedPreviousReadOnlyJournal: clone(previous), retainedPreviousReadOnlyMaterial: clone(previousMaterial) };
  return { journal, material, original };
};
const validate = value => validateM10ReadOnlyPreviousAttempt(value.journal, value.material, value.original);
describe('fixed readonly browser verification attempt 2', () => {
  it('selects exactly one actual Root refresh packet using its retained WAL identity', () => {
    const requestId = randomUUID(), key = randomUUID(), packet = { requestId, key, label: 'm10-browser-actual-same-sid-refresh', method: 'POST', path: '/auth/refresh', state: 'response_observed', status: 201 };
    const harness = { browserContinuationRefresh: { requestId, key, sameActualSid: true }, requests: [{ requestId: randomUUID(), key: randomUUID() }, packet] };
    expect(m10BrowserContinuationRootPacket(harness)).toBe(packet);
    harness.requests.push({ ...packet }); expect(() => m10BrowserContinuationRootPacket(harness)).toThrow('M10_ACTUAL_REFRESH_ROOT_PACKET_REQUIRED');
  });
  it('rejects a missing or falsely claimed Root refresh rather than fabricating a browser write', () => {
    const harness = { browserContinuationRefresh: { requestId: randomUUID(), key: randomUUID(), sameActualSid: true }, requests: [] };
    expect(() => m10BrowserContinuationRootPacket(harness)).toThrow('M10_ACTUAL_REFRESH_ROOT_PACKET_REQUIRED');
    harness.browserContinuationRefresh.sameActualSid = false; expect(() => m10BrowserContinuationRootPacket(harness)).toThrow('M10_ACTUAL_REFRESH_ROOT_JOURNAL_REQUIRED');
  });
  it('accepts only its fixed filename pair and retains the failed first readonly attempt', () => {
    expect(m10FinalBrowserEvidenceNames({ nativeVerified: true, finalJournalName: 'm10-browser-readonly-recheck-attempt2-journal.json', finalMaterialName: 'm10-browser-readonly-recheck-attempt2-secret-material.json' })).toMatchObject({ readOnlyRecheck: true, verificationAttempt: 2 });
    expect(validate(fixture())).toMatchObject({ originalPassed: false, originalFailurePreserved: true, originalResponseRewritten: false, originalRequestsReplayed: false, previousPacketsUnchanged: true, newWritePackets: 0 });
    expect(() => m10FinalBrowserEvidenceNames({ nativeVerified: true, finalJournalName: 'm10-browser-readonly-recheck-attempt2-journal.json', finalMaterialName: 'm10-browser-readonly-recheck-secret-material.json' })).toThrow('M10_FINAL_BROWSER_EVIDENCE_PAIR_NOT_ALLOWED');
  });
  it('rejects a changed closed artifact hash', () => {
    const value = fixture(); value.original.previousReadOnlyReportBytes = Buffer.concat([value.original.previousReadOnlyReportBytes, Buffer.from('\n')]); expect(() => validate(value)).toThrow('M10_PREVIOUS_READONLY_ATTEMPT_EVIDENCE_CHANGED');
  });
  it('rejects any unknown historical write even if a caller recomputes its claimed digest', () => {
    const value = fixture(), previous = JSON.parse(value.original.previousReadOnlyJournalBytes); previous.requests[1].state = 'response_unknown';
    value.original.previousReadOnlyJournalBytes = bytes(previous); value.journal.readOnlyPreviousAttemptEvidence.journalSha256 = hash(value.original.previousReadOnlyJournalBytes);
    expect(() => validate(value)).toThrow('M10_PREVIOUS_READONLY_ATTEMPT_UNKNOWN_WRITE');
  });
  it('rejects an appended new browser write and missing retained material', () => {
    const value = fixture(); value.journal.requests.push({ ...clone(value.journal.requests[1]) }); expect(() => validate(value)).toThrow('M10_READONLY_ATTEMPT_ADDITIONAL_WRITE');
    const dropped = fixture(); delete dropped.material.retainedPreviousReadOnlyMaterial; expect(() => validate(dropped)).toThrow('M10_PREVIOUS_READONLY_ATTEMPT_MATERIAL_NOT_RETAINED');
  });
  it('requires a new actual GET verification receipt instead of copying the previous GET', () => {
    const value = fixture(); value.journal.readOnlySessionVerification.requestId = JSON.parse(value.original.previousReadOnlyJournalBytes).readOnlySessionVerification.requestId;
    expect(() => validate(value)).toThrow('M10_READONLY_ATTEMPT_ACTUAL_NEW_GET_REQUIRED');
  });
});
