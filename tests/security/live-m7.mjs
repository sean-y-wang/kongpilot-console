import { lstatSync, readFileSync } from 'node:fs';
import { M7Harness, sha256, scope } from './lib/m7-harness.mjs';
import { bootstrapM7, setApprovalMode, restoreClusterMode } from './lib/m7-fixtures.mjs';
import { nineMetadataHandlers, fourProviderDelivery, eventRead } from './lib/m7-event-acceptance.mjs';
import { notificationAcceptance, lateAckFenceAcceptance, readonlyNotificationAcceptance } from './lib/m7-notification-acceptance.mjs';
import { auditAcceptance, auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

// Root's sole writer handoff is mandatory. There is no automatic restart,
// previously executed write replay, historical M6 reference or native writer.
const h = new M7Harness(); let failure;
try {
  const sourcePaths = ['tests/security/live-m7.mjs', 'tests/security/lib/m7-harness.mjs', 'tests/security/lib/m7-fixtures.mjs', 'tests/security/lib/m7-event-acceptance.mjs', 'tests/security/lib/m7-notification-acceptance.mjs', 'tests/security/lib/m7-audit-acceptance.mjs'];
  h.state.sourceFiles = sourcePaths.map(path => ({ path, sha256: sha256(readFileSync(path)) })); h.save({ phase: 'fresh-fixture-bootstrap' });
  const materialsPath = 'deploy/private/event-delivery/test-only-materials.json', stat = lstatSync(materialsPath);
  h.check(stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 && stat.size < 16384, 'fresh local receiver purpose materials have safe exact file identity and mode');
  const materials = JSON.parse(readFileSync(materialsPath, 'utf8'));
  h.check(materials.testOnly === true && materials.secrets.length === 3 && typeof materials.httpBearer === 'string' && typeof materials.httpBasic?.password === 'string' && typeof materials.smtp?.password === 'string', 'receiver credentials are fresh synthetic materials with exactly three distinct secret families');
  h.state.receiverMaterials = materials; h.state.secrets.push(...materials.secrets, materials.httpBearer, materials.httpBasic.password, materials.smtp.password); h.save();
  const actors = await bootstrapM7(h); h.save({ phase: 'direct-provider-delivery' });
  const catalog = await eventRead(h, actors.admin, actors.direct, 'catalog');
  h.check(catalog.providers.length === 4 && catalog.providers.every(v => v.available), 'four local providers are configured and current capability catalog exposes them');
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
  const audit = await auditAcceptance(h, actors);
  h.state.auditAcceptance = audit; h.save();
  h.state.httpAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.public ??= {}; Object.assign(h.public, { scope: 'real-BFF-providers-notifications-audit', actualUiComplete: false, detectorProducerComplete: false, cleanupComplete: false, finalSecretScanComplete: false, nativeTransportWritesOutsideBff: 0, originalClusterModeRestored: !h.state.c2ModeChanged || h.state.c2ModeRestored === true });
} catch (error) { failure = error; }
process.exitCode = h.finish(failure);
