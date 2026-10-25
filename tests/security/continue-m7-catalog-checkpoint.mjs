import { readFileSync } from 'node:fs';
import { M7Harness, sha256, scope } from './lib/m7-harness.mjs';
import { prepareCatalogContinuation, M7_CATALOG_FAILURE } from './lib/m7-catalog-continuation.mjs';
import { setApprovalMode, restoreClusterMode } from './lib/m7-fixtures.mjs';
import { eventRead, fourProviderDelivery, nineMetadataHandlers } from './lib/m7-event-acceptance.mjs';
import { notificationAcceptance, readonlyNotificationAcceptance, lateAckFenceAcceptance } from './lib/m7-notification-acceptance.mjs';
import { auditAcceptance, auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_CATALOG_CONTINUATION_READY !== 'true') throw new Error('M7_EXACT_CATALOG_CONTINUATION_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  const sourceFiles = h.state.sourceFiles.map(v => ({ path: v.path, sha256: sha256(readFileSync(v.path)) }));
  const actors = prepareCatalogContinuation(h, readFileSync(M7_CATALOG_FAILURE.path), sourceFiles), materials = h.state.receiverMaterials;
  const catalog = await eventRead(h, actors.admin, actors.direct, 'catalog');
  h.check(catalog.providers.length === 4 && catalog.providers.every(v => v.available), 'repaired real query exposes four current local providers');
  h.state.catalogContinuation.catalogReadProven = true; h.save();
  const channels = await fourProviderDelivery(h, actors, actors.direct, materials);
  await nineMetadataHandlers(h, actors, actors.direct, materials, false);
  h.save({ phase: 'notification-owner-and-fanout' });
  await notificationAcceptance(h, actors, actors.direct, channels[0]);
  await readonlyNotificationAcceptance(h, actors, actors.direct);
  await lateAckFenceAcceptance(h, actors, actors.direct, materials);
  await h.request(actors.readonly, scope(actors.foreign.cid, actors.foreign.wid, 'events/channels'), 'GET', undefined, { expected: [403] });
  await h.request(actors.readonly, scope(actors.approval.cid, actors.approval.wid, 'events/channels'), 'GET', undefined, { expected: [403] });
  h.check(true, 'exact foreign workspace and cluster IDOR fail before event data access');
  h.save({ phase: 'approval-nine-handlers' });
  await setApprovalMode(h, actors.admin, actors.approval);
  await nineMetadataHandlers(h, actors, actors.approval, materials, true);
  await restoreClusterMode(h, actors.admin, actors.approval);
  h.save({ phase: 'audit-historical-terminal-export' });
  h.state.auditAcceptance = await auditAcceptance(h, actors); h.save();
  h.state.httpAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, 27))) === h.state.catalogContinuation.originalPacketsSha256, 'original 27 successful write packets remain byte-identical and were never replayed');
  h.state.catalogContinuation.state = 'completed'; h.save();
  h.public = { scope: 'known-catalog-failure-unused-HTTP-continuation', failureArchive: M7_CATALOG_FAILURE, originalProvisioningWrites: 27, originalProvisioningReplayed: false, actualUiComplete: false, detectorProducerComplete: false, cleanupComplete: false, finalSecretScanComplete: false, nativeTransportWritesOutsideBff: 0, originalClusterModeRestored: !h.state.c2ModeChanged || h.state.c2ModeRestored === true, terminalAuditWriteCoverage: h.state.httpAuditWriteCoverage };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/security-live-catalog-continuation.json');
