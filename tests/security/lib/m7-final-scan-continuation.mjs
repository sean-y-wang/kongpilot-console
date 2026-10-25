import { sha256 } from './m7-harness.mjs';

export const M7_SCAN_PROVENANCE_CONTINUATION = Object.freeze({
  originalPath: 'artifacts/M7/runtime-secret-artifact-scan.json',
  originalSha256: 'd4c4cb0e7c46d8cc29c1f4e643400fbce6e85bbf75ca5ae1b00ac28e3d8276de',
  collectorPath: 'artifacts/M7/final-scan-provenance-collector-final.json',
  reportPath: 'artifacts/M7/runtime-secret-artifact-scan-provenance-continuation.json',
});

/** Resume only the exact scanner that stopped before files/logs/deletion. The
 * current successful business packets and all private histories stay intact. */
export function readM7FinalScanContinuation(reference, reader) {
  const fixed = M7_SCAN_PROVENANCE_CONTINUATION, marker = reference.finalScanProvenanceContinuation;
  if (reference.testTag !== 'm7-security-b81047b2' || marker?.version !== 1 || marker.phase !== 'ready'
    || marker.originalFailurePath !== fixed.originalPath || marker.originalFailureSha256 !== fixed.originalSha256
    || marker.collectorPath !== fixed.collectorPath || !/^[a-f\d]{64}$/.test(marker.collectorSha256 ?? '')
    || !reference.finalScanStarted || marker.originalStartedSha256 !== sha256(JSON.stringify(reference.finalScanStarted))
    || marker.requestsSha256 !== sha256(JSON.stringify(reference.requests))
    || marker.historyDescriptorsSha256 !== sha256(JSON.stringify(reference.privateHistoryRefs))
    || marker.registrySha256 !== sha256(JSON.stringify(reference.secrets))
    || JSON.stringify(reference.finalScanStarted.evidence) !== JSON.stringify(reference.finalScanHandoff.evidence)) throw new Error('M7_FINAL_SCAN_CONTINUATION_NOT_EXACT');
  const originalBytes = reader(fixed.originalPath), original = JSON.parse(originalBytes);
  if (sha256(originalBytes) !== fixed.originalSha256 || original.testTag !== reference.testTag || original.allPassed !== false
    || original.failureClassification !== 'FINAL_SCAN_INCOMPLETE_PRIVATE_RETAINED' || original.privateReferenceRemoved !== false) throw new Error('M7_ORIGINAL_SCAN_FAILURE_CHANGED');
  const collectorBytes = reader(fixed.collectorPath), collector = JSON.parse(collectorBytes);
  if (sha256(collectorBytes) !== marker.collectorSha256 || collector.testTag !== reference.testTag || collector.allPassed !== true || collector.errorCode !== null
    || collector.requestsSha256 !== marker.requestsSha256 || collector.historyDescriptorsSha256 !== marker.historyDescriptorsSha256 || collector.registrySha256 !== marker.registrySha256
    || collector.verifiedPrivateHistories !== reference.privateHistoryRefs.length || collector.secretCount !== reference.secrets.length
    || collector.businessWrites !== 0 || collector.authenticationWrites !== 0 || collector.nativeRequests !== 0
    || collector.originalReferenceUnchanged !== true || collector.originalHistoryUnchanged !== true) throw new Error('M7_FINAL_SCAN_COLLECTOR_PROOF_CHANGED');
  return { reportPath: fixed.reportPath, originalFailurePath: fixed.originalPath, originalFailureSha256: fixed.originalSha256, collectorPath: fixed.collectorPath, collectorSha256: marker.collectorSha256 };
}
