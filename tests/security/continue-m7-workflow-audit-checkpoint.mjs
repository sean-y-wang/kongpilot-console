import { readFileSync } from 'node:fs';
import { M7Harness, sha256 } from './lib/m7-harness.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';
import { freshWorkflowRequestMetadataAcceptance } from './lib/m7-workflow-request-metadata-acceptance.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_WORKFLOW_AUDIT_CONTINUATION_READY !== 'true') throw new Error('M7_EXACT_LEGACY_AUDIT_AND_FRESH_METADATA_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
const checkpoint = Object.freeze({ version: 1, packetCount: 258,
  packetSha256: '51f81f3ec02fd640e528b996ca80888706d80613acd410e481baf96b9d037eb9',
  failedArtifactSha256: '22638c9d5e3bf267232b4c582690bda3ed4316abae52ed735cc98cc0b4d7531e',
  legacyReadonlyProofSha256: '6ac9fa7203ccd429c4e92fa05a844d44c65ba06ffef762a27f6520c25bd0253e' });
const failureArchive = { path: 'artifacts/M7/security-live-workflow-submission-audit-failure.json', sha256: checkpoint.failedArtifactSha256,
  diagnosisPath: 'artifacts/M7/legacy-workflow-submission-audit-readonly-proof.json', diagnosisSha256: checkpoint.legacyReadonlyProofSha256 };
try {
  const failedBytes = readFileSync(failureArchive.path), proofBytes = readFileSync(failureArchive.diagnosisPath), failed = JSON.parse(failedBytes), proof = JSON.parse(proofBytes);
  h.check(sha256(failedBytes) === checkpoint.failedArtifactSha256 && sha256(proofBytes) === checkpoint.legacyReadonlyProofSha256 &&
    failed.testTag === h.state.testTag && failed.allPassed === false && failed.passed === 3329 && failed.failed === 1 &&
    failed.successfulWrites === 250 && failed.unknownWrites === 0 && proof.allPassed === true,
    'exact fifth failure and original immutable legacy metadata diagnosis remain byte-preserved');
  h.check(h.state.phase === 'stopped-failure' && h.state.inFlight == null && h.state.requests.length === checkpoint.packetCount &&
    h.state.requests.every(packet => packet.state === 'response_observed') && !h.state.workflowAuditContinuation &&
    h.state.auditAcceptance && h.state.portalTerminalAuditAcceptance && h.state.c2ModeRestored === true &&
    sha256(JSON.stringify(h.state.requests.slice(0, checkpoint.packetCount))) === checkpoint.packetSha256,
    'audit-only checkpoint retains all original 258 known packets without repeating completed fixtures or exports');
  retainM7History(h.state, 'workflowAuditContinuationHistory');
  h.state.workflowAuditContinuation = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), checkpoint, failureArchive,
    sourceFiles: [...new Set([...h.state.sourceFiles.map(value => value.path), 'tests/security/continue-m7-workflow-audit-checkpoint.mjs', 'tests/security/lib/m7-workflow-request-metadata-acceptance.mjs', 'tests/security/lib/m7-audit-acceptance.mjs', 'tests/security/lib/m7-legacy-submission-audit.mjs'])].map(path => ({ path, sha256: sha256(readFileSync(path)) })) };
  h.save({ phase: 'fresh-workflow-request-metadata-and-original-legacy-coverage' });
  const actors = { admin: h.state.sessions.admin, bootstrap: h.state.sessions['bootstrap-provisioner'], approver: h.state.sessions.approver,
    readonly: h.state.sessions['read-only'], owner: h.state.sessions.owner, other: h.state.sessions['other-owner'], ...h.state.scopes };
  await freshWorkflowRequestMetadataAcceptance(h, actors);
  h.state.httpAuditWriteCoverage = await auditAllWritesCoverage(h, actors, checkpoint); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, checkpoint.packetCount))) === checkpoint.packetSha256,
    'all original 258 packets including each known failure remain byte-equivalent after fresh proof');
  for (const name of ['workflowAuditContinuation', 'auditDownloadContinuation', 'lateAckContinuation', 'preferencePatchContinuation', 'catalogContinuation']) h.state[name].state = 'completed';
  h.save();
  h.public = { ...(h.public ?? {}), scope: 'fresh-approval-request-metadata-and-explicit-immutable-legacy-audit-coverage',
    originalPacketsRetained: 258, successfulOriginalPacketsReplayed: false, originalExportsRecreated: false,
    historicalAuditRecordsBackfilled: false, legacyMissingRequestMetadata: 12,
    failureArchives: [h.state.catalogContinuation.failureArchive, h.state.preferencePatchContinuation.failureArchive, h.state.lateAckContinuation.failureArchive, h.state.auditDownloadContinuation.failureArchive, failureArchive],
    completedChecksInherited: [{ path: failureArchive.path, passed: 3329, originalFailedCheckPreserved: true }],
    actualUiComplete: false, detectorProducerComplete: false, cleanupComplete: false, finalSecretScanComplete: false,
    nativeTransportWritesOutsideBff: 0, originalClusterModeRestored: h.state.c2ModeRestored, terminalAuditWriteCoverage: h.state.httpAuditWriteCoverage };
} catch (error) { failure = error; }
// The original failure is archived above before this allowlisted current view
// can become green; all immutable failure reports remain separately available.
process.exitCode = h.finish(failure, 'artifacts/M7/security-live-audit-download-continuation.json');
