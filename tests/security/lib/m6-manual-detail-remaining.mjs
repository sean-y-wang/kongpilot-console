import { createHash } from 'node:crypto';
import { authorizeFreshBootstrap, beforeManualMutation, completeManualMutation, createManualJournal, manualUuid } from './m6-manual-journal.mjs';
import { prepareManualCatalogFilterContinuation, preserveManualCatalogFilterContinuation } from './m6-manual-zero-packet.mjs';

export const MANUAL_DETAIL_FAILURE_SHA256 = '85df06d7c7da28037b857c8fe68211e0e113cf348b9f73add1a914b3e02791b9';
export const MANUAL_DETAIL_LOGIN_REQUESTS = Object.freeze({ owner: 'c3fa0725-8c7d-4c41-bb6c-8243f94c7459', administrator: '74e72d8d-9e41-4969-8a79-5d7d10b30d78' });
export const MANUAL_DETAIL_BOOTSTRAP_REQUEST = '1b8a8af0-9797-4a37-aae8-677746f2379b';
const fields = ['manualJournal', 'manualMetadata', 'manualWriteAttempts', 'manualWriteEvidence', 'manualZeroPacketHistory', 'manualZeroPacketContinuation', 'manualCatalogFilterHistory', 'manualCatalogFilterContinuation'];
const priorHistoryFields = fields.slice(4);
const digest = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
const snapshot = reference => Object.fromEntries(fields.map(field => [field, reference[field]]));
const reject = () => { throw new Error('M6_MANUAL_DETAIL_REMAINING_REJECTED'); };
const same = (a, b) => digest(a) === digest(b);
const empty = a => Array.isArray(a) && a.length === 0;

/** Only this immutable two-login stop can release the five untouched intents. */
export function prepareManualDetailRemaining(reference, failureBytes, catalogBytes, zeroBytes, expected, explicitFlag) {
  if (explicitFlag !== true || digest(failureBytes) !== MANUAL_DETAIL_FAILURE_SHA256 || !reference || reference.testTag !== expected?.testTag || Object.hasOwn(reference, 'manualDetailRemainingHistory') || Object.hasOwn(reference, 'manualDetailRemainingContinuation') || !fields.every(field => Object.hasOwn(reference, field))) reject();
  const failure = JSON.parse(String(failureBytes)), journal = reference.manualJournal, boundary = failure.writeBoundary;
  if (failure.stage !== 'actual-manual' || failure.testTag !== expected.testTag || failure.allPassed !== false || failure.passed !== 25 || failure.failed !== 1 || failure.checks?.length !== 26 || failure.checks.slice(0, 25).some(row => row.passed !== true)
    || failure.checks[25]?.name !== 'harness stopped after console developer Configuration: actual safe DTO and original CID/WID' || failure.checks[25].passed !== false || failure.checks[25].errorName !== 'Error' || failure.screenshots?.length !== 5 || failure.readEvidence?.length !== 3
    || boundary?.complete !== false || boundary.plannedWrites !== 2 || boundary.successfulPlannedWrites !== 2 || boundary.expectedDeniedAnonymousBootstrapWrites !== 1 || boundary.stoppedWithoutReplay !== true || boundary.actions?.length !== 3
    || journal?.version !== 1 || journal.source !== 'manual-ui' || journal.phase !== 'stopped-without-replay' || journal.stopReason !== 'manual-harness-stopped' || journal.nextIndex !== 2 || journal.inFlight !== null || journal.pageId !== null || journal.pageRevision !== null
    || journal.clusterId !== expected.clusterId || journal.workspaceId !== expected.workspaceId || !same(journal.actors, expected.actors) || !same(journal.content, expected.content) || !same(journal.attempts, reference.manualWriteAttempts) || journal.attempts?.length !== 3 || !empty(reference.manualMetadata) || reference.manualWriteEvidence?.length !== 2
    || !same(journal.authenticated, { owner: expected.actors.owner.id, administrator: expected.actors.administrator.id }) || Object.hasOwn(journal, 'detailRemainingContinuation') || Object.hasOwn(journal, 'restoredSessions')) reject();
  for (const read of failure.readEvidence) if (read.clusterId !== expected.clusterId || read.workspaceId !== expected.workspaceId || read.safeDto !== true || !manualUuid(read.requestId)) reject();
  if (failure.readEvidence[2].kind !== 'developer' || failure.readEvidence[2].entityId !== expected.actors.owner.id || failure.readEvidence.slice(0, 2).some(read => read.targetId !== expected.publicationId)) reject();
  const prior = prepareManualCatalogFilterContinuation({ testTag: reference.testTag, ...reference.manualCatalogFilterHistory?.snapshot }, catalogBytes, zeroBytes, { ...expected, originalContent: journal.catalogFilterContinuation?.originalContent, plannedContent: expected.content }, true);
  if (!same(prior, journal.catalogFilterContinuation)) reject();
  preserveManualCatalogFilterContinuation(reference, prior, journal);
  // Validate the original packets through the real guard; never send or replace them.
  const replay = createManualJournal({ clusterId: expected.clusterId, workspaceId: expected.workspaceId, actors: expected.actors, content: expected.content, priorKeys: journal.priorKeys, forbiddenEntityIds: journal.forbiddenEntityIds });
  authorizeFreshBootstrap(replay, 'owner', [], () => {});
  for (let index = 0; index < 3; index++) {
    const original = journal.attempts[index], role = index < 2 ? 'owner' : 'administrator';
    if (index === 2) authorizeFreshBootstrap(replay, role, [], () => {});
    const attempt = beforeManualMutation(replay, role, { url: `${original.origin}${original.path}${original.query ? `?${original.query}` : ''}`, method: original.method, headers: original.headers, rawBody: original.rawBody }, [], () => {});
    const requestId = index === 0 ? MANUAL_DETAIL_BOOTSTRAP_REQUEST : MANUAL_DETAIL_LOGIN_REQUESTS[role];
    completeManualMutation(replay, attempt, index === 0 ? 401 : 201, index === 0 ? { meta: { requestId }, error: { code: 'PORTAL_SESSION_EXPIRED' } } : { meta: { requestId }, data: role === 'owner' ? { developer: { ...expected.actors.owner, clusterId: expected.clusterId, workspaceId: expected.workspaceId, status: 'active' } } : { user: expected.actors.administrator } }, () => {});
    for (const field of ['category', 'action', 'role', 'actorId', 'expectedLoginActorId', 'method', 'origin', 'path', 'query', 'key', 'rawBody', 'body', 'headers', 'clusterId', 'workspaceId', 'state', 'status', 'requestId']) if (!same(original[field], attempt[field])) reject();
    if (!same(boundary.actions[index], Object.fromEntries(['category', 'action', 'state', 'status', 'requestId'].map(field => [field, original[field]])))) reject();
  }
  if (!same(Object.keys(journal.freshContexts).sort(), ['administrator', 'owner'])) reject();
  for (const role of ['owner', 'administrator']) for (const field of ['initialCookieCount', 'authenticationCookiesAbsent', 'expectedLoginActorId', 'bootstrapAttempted', 'bootstrapOutcome']) if (!same(journal.freshContexts[role]?.[field], replay.freshContexts[role][field])) reject();
  for (const role of ['owner', 'administrator']) {
    const path = role === 'owner' ? '/api/v1/portal/auth/login' : '/api/v1/auth/login', evidence = reference.manualWriteEvidence.filter(row => row.requestId === MANUAL_DETAIL_LOGIN_REQUESTS[role]);
    if (evidence.length !== 1 || evidence[0].method !== 'POST' || evidence[0].path !== path || evidence[0].status !== 201) reject();
  }
  const original = structuredClone(snapshot(reference));
  return Object.freeze({ version: 1, failureReportSha256: MANUAL_DETAIL_FAILURE_SHA256, originalSnapshotSha256: digest(original), snapshot: original, originalFailure: failure, originalFailureBytes: String(failureBytes), testTag: expected.testTag, clusterId: expected.clusterId, workspaceId: expected.workspaceId, continuedAt: new Date().toISOString() });
}

/** The untouched history and single-use marker are committed with the active journal before launch. */
export function preserveManualDetailRemaining(latest, prepared, activeJournal) {
  const old = prepared?.snapshot?.manualJournal;
  if (!latest || prepared?.version !== 1 || prepared.failureReportSha256 !== MANUAL_DETAIL_FAILURE_SHA256 || digest(prepared.originalFailureBytes) !== MANUAL_DETAIL_FAILURE_SHA256 || !same(JSON.parse(prepared.originalFailureBytes), prepared.originalFailure) || digest(prepared.snapshot) !== prepared.originalSnapshotSha256 || latest.testTag !== prepared.testTag
    || activeJournal?.clusterId !== prepared.clusterId || activeJournal.workspaceId !== prepared.workspaceId || activeJournal.startedAt !== old?.startedAt || !same(activeJournal.actors, old.actors) || !same(activeJournal.content, old.content) || activeJournal.nextIndex < 2 || !same(activeJournal.attempts?.slice(0, 3), old.attempts)
    || activeJournal.authenticated?.owner !== old.authenticated.owner || activeJournal.authenticated?.administrator !== old.authenticated.administrator || !same(activeJournal.catalogFilterContinuation, old.catalogFilterContinuation)) reject();
  const marker = { version: 1, failureReportSha256: prepared.failureReportSha256, originalSnapshotSha256: prepared.originalSnapshotSha256, originalJournalStartedAt: old.startedAt, continuedAt: prepared.continuedAt };
  const history = { ...marker, snapshot: prepared.snapshot, originalFailure: prepared.originalFailure, originalFailureBytes: prepared.originalFailureBytes };
  const hasMarker = Object.hasOwn(latest, 'manualDetailRemainingContinuation'), hasHistory = Object.hasOwn(latest, 'manualDetailRemainingHistory');
  if (hasMarker || hasHistory) {
    if (!hasMarker || !hasHistory || !same(latest.manualDetailRemainingContinuation, marker) || !same(latest.manualDetailRemainingHistory, history) || priorHistoryFields.some(field => !same(latest[field], prepared.snapshot[field]))) reject();
    return latest;
  }
  if (digest(snapshot(latest)) !== prepared.originalSnapshotSha256) reject();
  return { ...latest, manualDetailRemainingHistory: history, manualDetailRemainingContinuation: marker };
}
