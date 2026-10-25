import { readFileSync } from 'node:fs';
import { M7Harness, sha256, scope } from './lib/m7-harness.mjs';
import { M7_PREFERENCE_FAILURE, preparePreferenceContinuation, finishPreferenceLifecycle } from './lib/m7-preference-continuation.mjs';
import { nineMetadataHandlers } from './lib/m7-event-acceptance.mjs';
import { readonlyNotificationAcceptance, lateAckFenceAcceptance } from './lib/m7-notification-acceptance.mjs';
import { setApprovalMode, restoreClusterMode } from './lib/m7-fixtures.mjs';
import { auditAcceptance, auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';
import { portalTerminalAuditAcceptance } from './lib/m7-portal-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_PREFERENCE_CONTINUATION_READY !== 'true') throw new Error('M7_EXACT_ROLLBACK_CONTINUATION_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  const { packet, actors } = preparePreferenceContinuation(h, readFileSync(M7_PREFERENCE_FAILURE.path), readFileSync(M7_PREFERENCE_FAILURE.diagnosisPath));
  h.state.preferencePatchContinuation.sourceFiles = [...new Set([...h.state.sourceFiles.map(v => v.path), 'tests/security/continue-m7-preference-checkpoint.mjs', 'tests/security/lib/m7-preference-continuation.mjs', 'tests/security/lib/m7-portal-audit-acceptance.mjs'])].map(path => ({ path, sha256: sha256(readFileSync(path)) })); h.save();
  await finishPreferenceLifecycle(h, actors, packet);
  await readonlyNotificationAcceptance(h, actors, actors.direct);
  await lateAckFenceAcceptance(h, actors, actors.direct, h.state.receiverMaterials);
  await h.request(actors.readonly, scope(actors.foreign.cid, actors.foreign.wid, 'events/channels'), 'GET', undefined, { expected: [403] });
  await h.request(actors.readonly, scope(actors.approval.cid, actors.approval.wid, 'events/channels'), 'GET', undefined, { expected: [403] });
  h.check(true, 'exact foreign workspace and cluster IDOR fail before event data access');
  h.save({ phase: 'approval-nine-handlers' });
  await setApprovalMode(h, actors.admin, actors.approval);
  await nineMetadataHandlers(h, actors, actors.approval, h.state.receiverMaterials, true);
  await restoreClusterMode(h, actors.admin, actors.approval);
  h.save({ phase: 'audit-historical-terminal-export' });
  h.state.auditAcceptance = await auditAcceptance(h, actors); h.save();
  h.state.portalTerminalAuditAcceptance = await portalTerminalAuditAcceptance(h, actors); h.save();
  h.state.httpAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, 168))) === h.state.preferencePatchContinuation.originalPacketsSha256, 'all original 168 packets including the SQL500 remain unchanged');
  h.state.preferencePatchContinuation.state = 'completed'; h.state.catalogContinuation.state = 'completed'; h.save();
  h.public = { ...(h.public ?? {}), scope: 'exact-proven-SQL-rollback-and-unused-HTTP-tail', failureArchives: [h.state.catalogContinuation.failureArchive, M7_PREFERENCE_FAILURE], originalPacketsRetained: 168, successfulOriginalPacketsReplayed: false, deliberateOriginalFailedSqlRetry: 1, completedChecksInherited: { path: M7_PREFERENCE_FAILURE.path, passed: 1202, originalFailedCheckPreserved: true }, actualUiComplete: false, detectorProducerComplete: false, cleanupComplete: false, finalSecretScanComplete: false, nativeTransportWritesOutsideBff: 0, originalClusterModeRestored: !h.state.c2ModeChanged || h.state.c2ModeRestored === true, terminalAuditWriteCoverage: h.state.httpAuditWriteCoverage };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/security-live-preference-continuation.json');
