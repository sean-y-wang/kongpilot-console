// @ts-nocheck -- pure original-report binding; no private/runtime/environment.
import { describe, expect, it } from 'vitest';
import { M7_SCAN_PROVENANCE_CONTINUATION as fixed, readM7FinalScanContinuation } from './lib/m7-final-scan-continuation.mjs';
import { sha256 } from './lib/m7-harness.mjs';

const original = Buffer.from(JSON.stringify({ performedAt: '2026-10-11T10:36:22.505Z', milestone: 'M7', testTag: 'm7-security-b81047b2', allPassed: false,
  failureClassification: 'FINAL_SCAN_INCOMPLETE_PRIVATE_RETAINED', privateReferenceRemoved: false, secretsPublished: false, rawLogsPublished: false }, null, 2) + '\n');
function fixture() {
  const r = { testTag: 'm7-security-b81047b2', requests: [{ index: 0, key: 'SyntheticPublicOperation' }], privateHistoryRefs: [{ sha256: 'a'.repeat(64) }], secrets: ['SyntheticSecretOnly'],
    finalScanStarted: { at: 'SyntheticOriginal', evidence: { cleanup: { sha256: 'b'.repeat(64) } } }, finalScanHandoff: { evidence: { cleanup: { sha256: 'b'.repeat(64) } } } };
  const requestsSha256 = sha256(JSON.stringify(r.requests)), historyDescriptorsSha256 = sha256(JSON.stringify(r.privateHistoryRefs)), registrySha256 = sha256(JSON.stringify(r.secrets));
  const proof = { testTag: r.testTag, allPassed: true, errorCode: null, requestsSha256, historyDescriptorsSha256, registrySha256, verifiedPrivateHistories: 1, secretCount: 1,
    businessWrites: 0, authenticationWrites: 0, nativeRequests: 0, originalReferenceUnchanged: true, originalHistoryUnchanged: true };
  const bytes = Buffer.from(JSON.stringify(proof));
  r.finalScanProvenanceContinuation = { version: 1, phase: 'ready', originalFailurePath: fixed.originalPath, originalFailureSha256: fixed.originalSha256,
    collectorPath: fixed.collectorPath, collectorSha256: sha256(bytes), originalStartedSha256: sha256(JSON.stringify(r.finalScanStarted)), requestsSha256, historyDescriptorsSha256, registrySha256 };
  const reader = path => path === fixed.originalPath ? original : path === fixed.collectorPath ? bytes : (() => { throw Error('Unexpected path'); })();
  return { r, proof, reader };
}
describe('one exact final scanner provenance continuation', () => {
  it('retains the original failed report and selects a distinct new report without changing state', () => {
    const { r, reader } = fixture(), snapshot = JSON.stringify(r);
    expect(sha256(original)).toBe(fixed.originalSha256);
    expect(readM7FinalScanContinuation(r, reader).reportPath).not.toBe(fixed.originalPath);
    expect(JSON.stringify(r)).toBe(snapshot);
  });
  for (const field of ['phase', 'originalFailurePath', 'originalFailureSha256', 'collectorPath', 'collectorSha256', 'originalStartedSha256', 'requestsSha256', 'historyDescriptorsSha256', 'registrySha256']) {
    it(`refuses altered ${field} instead of rearming an old attempt`, () => {
      const { r, reader } = fixture(); r.finalScanProvenanceContinuation[field] = 'Changed';
      expect(() => readM7FinalScanContinuation(r, reader)).toThrow();
    });
  }
  it('a changed original packet, secret registry, history descriptor or original start invalidates the once marker', () => {
    for (const mutate of [r => r.requests[0].key = 'Changed', r => r.secrets.push('Uncaptured'), r => r.privateHistoryRefs[0].sha256 = 'c'.repeat(64), r => r.finalScanStarted.at = 'Changed', r => r.finalScanHandoff.evidence = {}]) {
      const { r, reader } = fixture(); mutate(r); expect(() => readM7FinalScanContinuation(r, reader)).toThrow();
    }
  });
  it('cannot claim another failed report or replace original failed bytes with green bytes', () => {
    const { r, reader } = fixture(); expect(() => readM7FinalScanContinuation(r, p => p === fixed.originalPath ? Buffer.from('{}') : reader(p))).toThrow('ORIGINAL_SCAN_FAILURE_CHANGED');
  });
  it('a self-consistent proof with omitted histories, secrets, changed packets or runtime writes still fails', () => {
    for (const [field, value] of [['allPassed', false], ['errorCode', 'BUDGET'], ['verifiedPrivateHistories', 0], ['secretCount', 0], ['requestsSha256', 'c'.repeat(64)], ['businessWrites', 1], ['authenticationWrites', 1], ['nativeRequests', 1], ['originalHistoryUnchanged', false]]) {
      const { r, proof, reader } = fixture(); proof[field] = value; const bytes = Buffer.from(JSON.stringify(proof)); r.finalScanProvenanceContinuation.collectorSha256 = sha256(bytes);
      expect(() => readM7FinalScanContinuation(r, p => p === fixed.collectorPath ? bytes : reader(p))).toThrow('COLLECTOR_PROOF_CHANGED');
    }
  });
});
