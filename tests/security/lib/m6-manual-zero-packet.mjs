import { createHash } from 'node:crypto';
import { manualUuid } from './m6-manual-journal.mjs';

export const MANUAL_PRE_LAUNCH_FAILURE_SHA256 = 'eb7a57f7675f56ea5ebd1c6cc7dcba9c462b9a463e75ceb5189f7622d73d1f4b';
export const MANUAL_CATALOG_FILTER_FAILURE_SHA256 = 'cce8f501b35e235f3958fe294f057f8603bccabe10934a89302eb6429d356d0e';
export const MANUAL_CATALOG_BOOTSTRAP_REQUEST_ID = '89ddccd6-23ac-43cc-98b7-482b9fad6bc9';
const roles = ['owner', 'administrator', 'approver'];
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const emptyObject = value => object(value) && Object.keys(value).length === 0;
const emptyArray = value => Array.isArray(value) && value.length === 0;
const exactKeys = (value, names) => object(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const digest = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
const reject = () => { throw new Error('M6_MANUAL_ZERO_PACKET_CONTINUATION_REJECTED'); };
const sameActors = (actual, expected) => exactKeys(actual, roles) && roles.every(role => exactKeys(actual[role], ['id', 'username', 'password']) && ['id', 'username', 'password'].every(key => actual[role][key] === expected?.[role]?.[key]));
const sameContent = (actual, expected) => exactKeys(actual, ['slug', 'title', 'markdown']) && ['slug', 'title', 'markdown'].every(key => actual[key] === expected?.[key]);
const originalFields = ['manualJournal', 'manualMetadata', 'manualWriteAttempts', 'manualWriteEvidence'];
const snapshot = reference => Object.fromEntries(originalFields.map(field => [field, reference[field]]));

/** Match playwright.config.ts without reading process.env or statting paths inside the helper. */
export function manualChromiumLaunchOptions(env, exists) {
  const chromiumPath = env.CHROMIUM_EXECUTABLE_PATH || (exists('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined);
  return { ...(chromiumPath ? { executablePath: chromiumPath } : {}) };
}
export function prepareManualZeroPacketContinuation(reference, failureBytes, expected, explicitFlag) {
  if (explicitFlag !== true || digest(failureBytes) !== MANUAL_PRE_LAUNCH_FAILURE_SHA256 || !object(reference) || !object(expected)
    || Object.hasOwn(reference, 'manualZeroPacketContinuation') || Object.hasOwn(reference, 'manualZeroPacketHistory') || !manualUuid(expected.clusterId) || !manualUuid(expected.workspaceId)
    || !exactKeys(expected.actors, roles) || !roles.every(role => manualUuid(expected.actors[role]?.id) && typeof expected.actors[role]?.username === 'string' && !!expected.actors[role].username && typeof expected.actors[role]?.password === 'string' && !!expected.actors[role].password)
    || new Set(roles.map(role => expected.actors[role].id)).size !== 3 || !sameContent(expected.content, expected.content)) reject();
  let failure; try { failure = JSON.parse(String(failureBytes)); } catch { reject(); }
  const boundary = failure.writeBoundary, journal = reference.manualJournal;
  if (failure.stage !== 'actual-manual' || failure.testTag !== expected.testTag || reference.testTag !== expected.testTag || failure.allPassed !== false || failure.passed !== 0 || failure.failed !== 1
    || !Array.isArray(failure.checks) || failure.checks.length !== 1 || failure.checks[0].name !== 'harness stopped after preflight' || failure.checks[0].passed !== false || failure.checks[0].errorName !== 'Error'
    || !['screenshots', 'readEvidence', 'fixtureJournal', 'workspaces'].every(field => emptyArray(failure[field])) || !object(boundary) || boundary.complete !== false || boundary.plannedWrites !== 0 || boundary.successfulPlannedWrites !== 0 || boundary.expectedDeniedAnonymousBootstrapWrites !== 0 || boundary.stoppedWithoutReplay !== true || !emptyArray(boundary.actions)
    || !originalFields.every(field => Object.hasOwn(reference, field)) || !['manualMetadata', 'manualWriteAttempts', 'manualWriteEvidence'].every(field => emptyArray(reference[field]))
    || !object(journal) || journal.version !== 1 || journal.source !== 'manual-ui' || journal.phase !== 'stopped-without-replay' || journal.stopReason !== 'manual-harness-stopped'
    || journal.clusterId !== expected.clusterId || journal.workspaceId !== expected.workspaceId || !sameActors(journal.actors, expected.actors) || !sameContent(journal.content, expected.content)
    || journal.nextIndex !== 0 || journal.inFlight !== null || journal.pageId !== null || journal.pageRevision !== null || !emptyObject(journal.authenticated) || !emptyObject(journal.freshContexts) || !emptyArray(journal.attempts)
    || !Array.isArray(journal.priorKeys) || !Array.isArray(journal.forbiddenEntityIds) || !Number.isFinite(Date.parse(journal.startedAt)) || !Number.isFinite(Date.parse(journal.stoppedAt))
    || Object.hasOwn(journal, 'zeroPacketContinuation')) reject();
  const original = structuredClone(snapshot(reference));
  return Object.freeze({ version: 1, failureReportSha256: MANUAL_PRE_LAUNCH_FAILURE_SHA256, originalSnapshotSha256: digest(original), snapshot: original, testTag: expected.testTag, clusterId: expected.clusterId, workspaceId: expected.workspaceId });
}
/** Return a complete reference for one atomic write: archive old state and consume the exception together. */
export function preserveManualZeroPacketContinuation(latest, prepared, activeJournal) {
  if (!object(latest) || !object(prepared) || prepared.version !== 1 || prepared.failureReportSha256 !== MANUAL_PRE_LAUNCH_FAILURE_SHA256 || digest(prepared.snapshot) !== prepared.originalSnapshotSha256
    || latest.testTag !== prepared.testTag || activeJournal?.clusterId !== prepared.clusterId || activeJournal?.workspaceId !== prepared.workspaceId || !sameActors(activeJournal.actors, prepared.snapshot.manualJournal.actors) || !sameContent(activeJournal.content, prepared.snapshot.manualJournal.content) || !Number.isFinite(Date.parse(activeJournal.startedAt))) reject();
  const marker = { version: 1, failureReportSha256: prepared.failureReportSha256, originalSnapshotSha256: prepared.originalSnapshotSha256, activeJournalStartedAt: activeJournal.startedAt };
  const history = { version: 1, failureReportSha256: prepared.failureReportSha256, originalSnapshotSha256: prepared.originalSnapshotSha256, snapshot: prepared.snapshot };
  const hasMarker = Object.hasOwn(latest, 'manualZeroPacketContinuation'), hasHistory = Object.hasOwn(latest, 'manualZeroPacketHistory');
  if (hasMarker || hasHistory) {
    if (!hasMarker || !hasHistory || digest(latest.manualZeroPacketContinuation) !== digest(marker) || digest(latest.manualZeroPacketHistory) !== digest(history)) reject();
    return latest;
  }
  if (digest(snapshot(latest)) !== prepared.originalSnapshotSha256) reject();
  return { ...latest, manualZeroPacketHistory: history, manualZeroPacketContinuation: marker };
}

const catalogFields = [...originalFields, 'manualZeroPacketHistory', 'manualZeroPacketContinuation'];
const catalogSnapshot = reference => Object.fromEntries(catalogFields.map(field => [field, reference[field]]));
export function prepareManualCatalogFilterContinuation(reference, failureBytes, preLaunchFailureBytes, expected, explicitFlag) {
  if (explicitFlag !== true || digest(failureBytes) !== MANUAL_CATALOG_FILTER_FAILURE_SHA256 || !object(reference) || Object.hasOwn(reference, 'manualCatalogFilterContinuation') || Object.hasOwn(reference, 'manualCatalogFilterHistory') || !sameContent(expected?.originalContent, expected?.originalContent) || !sameContent(expected?.plannedContent, expected?.plannedContent) || expected.originalContent.slug !== expected.plannedContent.slug || expected.originalContent.title !== expected.plannedContent.title || typeof expected.originalContent.markdown !== 'string' || typeof expected.plannedContent.markdown !== 'string' || !expected.plannedContent.markdown) reject();
  const failure = JSON.parse(String(failureBytes)), journal = reference.manualJournal, boundary = failure.writeBoundary, read = failure.readEvidence?.[0], action = boundary?.actions?.[0];
  if (failure.stage !== 'actual-manual' || failure.testTag !== expected.testTag || reference.testTag !== expected.testTag || failure.allPassed !== false || failure.passed !== 2 || failure.failed !== 1 || failure.checks?.length !== 3 || !emptyArray(failure.screenshots) || !emptyArray(failure.fixtureJournal) || !emptyArray(failure.workspaces)
    || boundary?.complete !== false || boundary.plannedWrites !== 0 || boundary.successfulPlannedWrites !== 0 || boundary.expectedDeniedAnonymousBootstrapWrites !== 1 || boundary.stoppedWithoutReplay !== true || boundary.actions?.length !== 1 || action.category !== 'anonymous-bootstrap' || action.action !== 'owner-anonymous-bootstrap' || action.state !== 'expected-auth-missing-rejection' || action.status !== 401 || action.requestId !== MANUAL_CATALOG_BOOTSTRAP_REQUEST_ID
    || failure.readEvidence?.length !== 1 || read.kind !== 'catalog' || read.method !== 'GET' || read.path !== '/api/v1/portal/publications' || read.clusterId !== expected.clusterId || read.workspaceId !== expected.workspaceId || read.targetId !== expected.publicationId || read.safeDto !== true || read.filter !== 'all-categories'
    || !catalogFields.every(field => Object.hasOwn(reference, field)) || !emptyArray(reference.manualMetadata) || !emptyArray(reference.manualWriteEvidence) || reference.manualWriteAttempts?.length !== 1
    || !object(journal) || journal.version !== 1 || journal.source !== 'manual-ui' || journal.phase !== 'stopped-without-replay' || journal.stopReason !== 'manual-harness-stopped' || journal.clusterId !== expected.clusterId || journal.workspaceId !== expected.workspaceId || !sameActors(journal.actors, expected.actors) || !sameContent(journal.content, expected.originalContent)
    || journal.nextIndex !== 0 || journal.inFlight !== null || journal.pageId !== null || journal.pageRevision !== null || !emptyObject(journal.authenticated) || !exactKeys(journal.freshContexts, ['owner']) || journal.attempts?.length !== 1 || digest(journal.attempts) !== digest(reference.manualWriteAttempts) || Object.hasOwn(journal, 'catalogFilterContinuation')) reject();
  const attempt = journal.attempts[0], fresh = journal.freshContexts.owner;
  let query, rawBody; try { query = new URLSearchParams(attempt.query); rawBody = JSON.parse(attempt.rawBody); } catch { reject(); }
  if (attempt.category !== 'anonymous-bootstrap' || attempt.action !== 'owner-anonymous-bootstrap' || attempt.role !== 'owner' || attempt.actorId !== null || attempt.expectedLoginActorId !== expected.actors.owner.id || attempt.method !== 'POST' || attempt.origin !== 'http://127.0.0.1:8082' || attempt.path !== '/api/v1/portal/auth/refresh'
    || attempt.clusterId !== expected.clusterId || attempt.workspaceId !== expected.workspaceId || attempt.status !== 401 || attempt.errorCode !== 'PORTAL_SESSION_EXPIRED' || attempt.requestId !== MANUAL_CATALOG_BOOTSTRAP_REQUEST_ID || attempt.state !== 'expected-auth-missing-rejection' || !manualUuid(attempt.key) || attempt.headers?.['x-idempotency-key'] !== attempt.key
    || [...query].length !== 2 || query.getAll('clusterId').length !== 1 || query.getAll('workspaceId').length !== 1 || query.get('clusterId') !== expected.clusterId || query.get('workspaceId') !== expected.workspaceId || !exactKeys(rawBody, ['clusterId', 'workspaceId']) || rawBody.clusterId !== expected.clusterId || rawBody.workspaceId !== expected.workspaceId || digest(rawBody) !== digest(attempt.body)
    || !object(fresh) || fresh.initialCookieCount !== 0 || fresh.authenticationCookiesAbsent !== true || fresh.expectedLoginActorId !== expected.actors.owner.id || fresh.bootstrapAttempted !== true || fresh.bootstrapOutcome !== 'known-401-authentication-missing') reject();
  const zeroHistory = reference.manualZeroPacketHistory, zeroMarker = reference.manualZeroPacketContinuation;
  const zero = prepareManualZeroPacketContinuation({ testTag: reference.testTag, ...zeroHistory?.snapshot }, preLaunchFailureBytes, { ...expected, content: expected.originalContent }, true);
  if (zeroHistory.version !== 1 || zeroHistory.failureReportSha256 !== MANUAL_PRE_LAUNCH_FAILURE_SHA256 || zeroHistory.originalSnapshotSha256 !== zero.originalSnapshotSha256 || digest(zeroHistory.snapshot) !== zero.originalSnapshotSha256 || digest(journal.zeroPacketContinuation) !== digest(zero)
    || !exactKeys(zeroMarker, ['version', 'failureReportSha256', 'originalSnapshotSha256', 'activeJournalStartedAt']) || zeroMarker.version !== 1 || zeroMarker.failureReportSha256 !== MANUAL_PRE_LAUNCH_FAILURE_SHA256 || zeroMarker.originalSnapshotSha256 !== zero.originalSnapshotSha256 || zeroMarker.activeJournalStartedAt !== journal.startedAt) reject();
  const original = structuredClone(catalogSnapshot(reference));
  return Object.freeze({ version: 1, failureReportSha256: MANUAL_CATALOG_FILTER_FAILURE_SHA256, originalSnapshotSha256: digest(original), snapshot: original, testTag: expected.testTag, clusterId: expected.clusterId, workspaceId: expected.workspaceId, originalContent: structuredClone(expected.originalContent), plannedContent: structuredClone(expected.plannedContent), plannedContentSha256: digest(expected.plannedContent) });
}
export function preserveManualCatalogFilterContinuation(latest, prepared, activeJournal) {
  if (!object(latest) || !object(prepared) || prepared.version !== 1 || prepared.failureReportSha256 !== MANUAL_CATALOG_FILTER_FAILURE_SHA256 || digest(prepared.snapshot) !== prepared.originalSnapshotSha256 || digest(prepared.plannedContent) !== prepared.plannedContentSha256 || !sameContent(prepared.originalContent, prepared.snapshot.manualJournal.content) || latest.testTag !== prepared.testTag || activeJournal?.clusterId !== prepared.clusterId || activeJournal?.workspaceId !== prepared.workspaceId || !sameActors(activeJournal.actors, prepared.snapshot.manualJournal.actors) || !sameContent(activeJournal.content, prepared.plannedContent) || !Number.isFinite(Date.parse(activeJournal.startedAt))) reject();
  const marker = { version: 1, failureReportSha256: prepared.failureReportSha256, originalSnapshotSha256: prepared.originalSnapshotSha256, plannedContentSha256: prepared.plannedContentSha256, activeJournalStartedAt: activeJournal.startedAt }, history = { version: 1, failureReportSha256: prepared.failureReportSha256, originalSnapshotSha256: prepared.originalSnapshotSha256, snapshot: prepared.snapshot };
  const hasMarker = Object.hasOwn(latest, 'manualCatalogFilterContinuation'), hasHistory = Object.hasOwn(latest, 'manualCatalogFilterHistory');
  if (hasMarker || hasHistory) { if (!hasMarker || !hasHistory || digest(latest.manualCatalogFilterContinuation) !== digest(marker) || digest(latest.manualCatalogFilterHistory) !== digest(history) || digest(latest.manualZeroPacketHistory) !== digest(prepared.snapshot.manualZeroPacketHistory) || digest(latest.manualZeroPacketContinuation) !== digest(prepared.snapshot.manualZeroPacketContinuation)) reject(); return latest; }
  if (digest(catalogSnapshot(latest)) !== prepared.originalSnapshotSha256) reject();
  return { ...latest, manualCatalogFilterHistory: history, manualCatalogFilterContinuation: marker };
}
