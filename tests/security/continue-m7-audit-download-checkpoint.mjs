import { readFileSync } from 'node:fs';
import { M7Harness, sha256 } from './lib/m7-harness.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';
import { auditDownloadTailAcceptance, auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';
import { portalTerminalAuditAcceptance } from './lib/m7-portal-audit-acceptance.mjs';
if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_AUDIT_DOWNLOAD_CONTINUATION_READY !== 'true') throw new Error('M7_EXACT_ORIGINAL_EXPORT_UNUSED_TAIL_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
const failureArchive = { path: 'artifacts/M7/security-live-audit-download-failure.json', sha256: 'bda2b13cb49a5c7d651f54feffd3a8a6d25b2b2febaaf8efa012693f1d7f20a3',
  diagnosisPath: 'artifacts/M7/audit-export-download-readonly-diagnosis.json', diagnosisSha256: '0d8c263c6770a364dae7563fd86c1ae6a0e0d4426dd2e4ca0330ba7e86f696d4' };
try {
  const bytes = readFileSync(failureArchive.path), diagnosisBytes = readFileSync(failureArchive.diagnosisPath), failed = JSON.parse(bytes), diagnosis = JSON.parse(diagnosisBytes), packet = h.state.requests[251];
  h.check(sha256(bytes) === failureArchive.sha256 && sha256(diagnosisBytes) === failureArchive.diagnosisSha256 && failed.testTag === h.state.testTag && failed.allPassed === false && failed.passed === 674 && failed.failed === 1 && failed.successfulWrites === 244 && failed.unknownWrites === 0,
    'exact original download representation failure and pure read-only diagnosis remain immutable');
  h.check(h.state.phase === 'stopped-failure' && h.state.inFlight == null && h.state.requests.length === 252 && h.state.requests.every(p => p.state === 'response_observed') && !h.state.auditDownloadContinuation && !h.state.auditDownloadTail && !h.state.auditAcceptance && h.state.c2ModeRestored === true,
    'download continuation starts once after all known original writes and restored C2 mode');
  h.check(packet.index === 251 && packet.key === '49053f17-888a-4db7-93be-1ef79d5ebe1f' && packet.requestId === '58bc6531-f56c-4b25-9d46-f91afe5c3f91' && packet.method === 'POST' && packet.status === 201 && packet.body.format === 'ndjson' && sha256(JSON.stringify(packet.body)) === packet.bodySha256 && packet.responseData.domain === 'audit-export' && packet.responseData.jobId === '3bd33d99-3f3b-4235-bc62-f551dda969bb',
    'original successful NDJSON create retains its exact packet and durable job without replay');
  const owner = h.state.sessions['audit-tag-complete'];
  h.check(owner.user.id === packet.actorId && owner.sid === packet.sessionId && packet.clusterId === h.state.scopes.direct.cid && packet.workspaceId === h.state.scopes.direct.wid && diagnosis.allPassed === true && diagnosis.jobId === packet.responseData.jobId && diagnosis.ownerId === packet.actorId && diagnosis.bytesEqual && diagnosis.lengthEqual && diagnosis.filenameSafeExpected && diagnosis.noStore && diagnosis.businessWrites === 0 && diagnosis.authenticationWrites === 0 && h.state.auditDownloadReadOnlyDiagnosis.state === 'completed',
    'actual original owner SID scope complete bytes and safe attachment are proved before unused tail');
  const originalPacketsSha256 = sha256(JSON.stringify(h.state.requests)); retainM7History(h.state, 'auditDownloadContinuationHistory');
  h.state.auditDownloadContinuation = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalPackets: 252, originalPacketsSha256, failureArchive,
    sourceFiles: [...new Set([...h.state.sourceFiles.map(v => v.path), 'tests/security/continue-m7-audit-download-checkpoint.mjs', 'tests/security/lib/m7-private-history.mjs', 'tests/security/lib/m7-portal-audit-acceptance.mjs'])].map(path => ({ path, sha256: sha256(readFileSync(path)) })) }; h.save({ phase: 'exact-original-export-unused-tail' });
  const actors = { admin: h.state.sessions.admin, bootstrap: h.state.sessions['bootstrap-provisioner'], approver: h.state.sessions.approver, readonly: h.state.sessions['read-only'], owner: h.state.sessions.owner, other: h.state.sessions['other-owner'], ...h.state.scopes };
  h.state.auditAcceptance = await auditDownloadTailAcceptance(h, actors); h.save();
  h.state.portalTerminalAuditAcceptance = await portalTerminalAuditAcceptance(h, actors); h.save();
  h.state.httpAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, 252))) === originalPacketsSha256, 'all original 252 packets including every known failure remain byte-equivalent');
  for (const name of ['auditDownloadContinuation', 'lateAckContinuation', 'preferencePatchContinuation', 'catalogContinuation']) h.state[name].state = 'completed'; h.save();
  h.public = { ...(h.public ?? {}), scope: 'original-NDJSON-export-and-unused-Audit-Portal-tail', originalPacketsRetained: 252, successfulOriginalPacketsReplayed: false, originalNdjsonExportRecreated: false, deliberateOriginalFailedSqlRetry: 1,
    failureArchives: [h.state.catalogContinuation.failureArchive, h.state.preferencePatchContinuation.failureArchive, h.state.lateAckContinuation.failureArchive, failureArchive],
    completedChecksInherited: [{path:'artifacts/M7/security-live-fanout-source-patch-failure.json',passed:1202,originalFailedCheckPreserved:true},{path:'artifacts/M7/security-live-late-ack-fence-failure.json',passed:138,originalFailedCheckPreserved:true},{path:failureArchive.path,passed:674,originalFailedCheckPreserved:true}],
    actualUiComplete: false, detectorProducerComplete: false, cleanupComplete: false, finalSecretScanComplete: false, nativeTransportWritesOutsideBff: 0, originalClusterModeRestored: h.state.c2ModeRestored, terminalAuditWriteCoverage: h.state.httpAuditWriteCoverage };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/security-live-audit-download-continuation.json');
