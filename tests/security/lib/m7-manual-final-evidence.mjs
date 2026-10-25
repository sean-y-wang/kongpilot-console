import { readFileSync } from 'node:fs';
import { sha256 } from './m7-harness.mjs';

export const M7_POST_WRITE_UI_FAILURE = Object.freeze({ path: 'artifacts/M7/manual-ui-post-writes-readonly-failure.json',
  sha256: 'cdc5fca6818601d8ab275802ce2d5890cf91bdb104d058f01c17aba5b2df0167' });

/** The pure GET completion is a distinct green artifact. Earlier raw failed
 * UI evidence remains immutable and cannot be silently declared successful. */
export function readM7ManualFinalEvidence(reference, manual, reader = readFileSync) {
  const prior = M7_POST_WRITE_UI_FAILURE, handoff = reference?.manualUiHandoff;
  if (manual?.stage !== 'actual-manual-ui-readonly-closure' || manual.testTag !== reference?.testTag || manual.allPassed !== true || manual.failed !== 0 ||
    manual.successfulUiWrites !== 12 || manual.unknownUiWrites !== 0 || manual.unresolvedUiWrites !== 0 || manual.blockedBeforePacketAttempts !== 0 || manual.inheritedBlockedBeforePacketAttempts !== 1 ||
    manual.additionalBusinessWrites !== 0 || manual.additionalLoginWrites !== 0 || manual.additionalRefreshWrites !== 0 || manual.newApprovalWrites !== 0 || manual.loginWrites !== 0 || manual.refreshWrites !== 0 || manual.nativeTransportWrites !== 0 ||
    manual.inheritedHttpReportPath !== handoff?.securityReportPath || manual.inheritedHttpSha256 !== handoff?.securityReportSha256 ||
    manual.inheritedProducerReportPath !== handoff?.producerReportPath || manual.inheritedProducerSha256 !== handoff?.producerReportSha256 ||
    manual.originalPostWriteFailure?.path !== prior.path || manual.originalPostWriteFailure.sha256 !== prior.sha256) throw new Error('M7_FINAL_MANUAL_INHERITANCE_NOT_EXACT');
  const bytes = reader(prior.path), old = JSON.parse(bytes);
  if (sha256(bytes) !== prior.sha256 || old.stage !== 'actual-manual-ui' || old.testTag !== reference.testTag || old.allPassed !== false || old.failed !== 1 || old.successfulUiWrites !== 12 ||
    old.unknownUiWrites !== 0 || old.unresolvedUiWrites !== 0 || old.blockedBeforePacketAttempts !== 0 || old.inheritedBlockedBeforePacketAttempts !== 1) throw new Error('M7_FINAL_MANUAL_OLD_FAILURE_CHANGED');
  return { distinctReadOnlyGreenArtifact: true, originalRawUiFailureRetained: true, originalFailurePath: prior.path, originalFailureSha256: prior.sha256, originalTwelveWritesNotReplayed: true };
}
