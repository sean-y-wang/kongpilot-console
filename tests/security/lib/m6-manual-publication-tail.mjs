import { createHash } from 'node:crypto';
import { beforeManualMutation, MANUAL_ACTIONS, manualUuid, stopManualJournal } from './m6-manual-journal.mjs';
import { preserveManualDetailRemaining } from './m6-manual-detail-remaining.mjs';

export const MANUAL_PUBLICATION_FAILURE_SHA256 = '707dcb2d00dbc9c640927b4cc9eba28091ead01f704ef4050f36355795c80211';
export const MANUAL_PUBLICATION_PROOF_SHA256 = '82b89a7a6c7bb7232eeb37065fab9e481a6ca294a5527f9cd8483021a6836abc';
const fields = ['manualJournal', 'manualMetadata', 'manualWriteAttempts', 'manualWriteEvidence', 'manualZeroPacketHistory', 'manualZeroPacketContinuation', 'manualCatalogFilterHistory', 'manualCatalogFilterContinuation', 'manualDetailRemainingHistory', 'manualDetailRemainingContinuation'];
const digest = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
const same = (a, b) => digest(a) === digest(b);
const reject = () => { throw new Error('M6_MANUAL_PUBLICATION_TAIL_REJECTED'); };
const snapshot = reference => Object.fromEntries(fields.map(field => [field, reference[field]]));

export function publicationTailRenewalEvidence(reference, reportBytes) {
  const marker = reference.manualTailSessionRenewal, history = reference.manualTailSessionRenewalHistory;
  if (!marker && !history && reportBytes === undefined) return { externalNormalSessionRenewalWrites: 0 };
  if (marker?.version !== 1 || marker.state !== 'completed' || marker.authWrites !== 2 || marker.reportPath !== 'artifacts/M6/manual-tail-normal-session-renewal.json' || !/^[a-f0-9]{64}$/.test(marker.reportSha256 ?? '') || !history || reportBytes === undefined || digest(reportBytes) !== marker.reportSha256) reject();
  const report = JSON.parse(String(reportBytes)), audit = report.auditCoverage;
  if (report.allPassed !== true || report.authWrites !== 2 || report.normalSessionRenewalWrites !== 2 || report.successfulNormalSessionRenewalWrites !== 2 || report.transportBusinessWrites !== 0 || report.nativeRequests !== 0 || report.loginRequests !== 0 || report.revealRequests !== 0 || audit?.successfulProductWrites !== 2 || audit.distinctRequestIds !== 2 || audit.auditedRequestIds !== 2 || audit.allPassed !== true) reject();
  return { externalNormalSessionRenewalWrites: 2, reportPath: marker.reportPath, reportSha256: marker.reportSha256, auditCoverage: { successfulProductWrites: 2, distinctRequestIds: 2, auditedRequestIds: 2, allPassed: true }, markerSha256: digest(marker), historySha256: digest(history) };
}
export function prepareManualPublicationTail(reference, failureBytes, proofBytes, expected, explicitFlag, renewalReportBytes) {
  if (explicitFlag !== true || digest(failureBytes) !== MANUAL_PUBLICATION_FAILURE_SHA256 || digest(proofBytes) !== MANUAL_PUBLICATION_PROOF_SHA256 || !reference || reference.testTag !== expected?.testTag || Object.hasOwn(reference, 'manualPublicationTailHistory') || Object.hasOwn(reference, 'manualPublicationTailContinuation') || !fields.every(field => Object.hasOwn(reference, field))) reject();
  const failure = JSON.parse(String(failureBytes)), proof = JSON.parse(String(proofBytes)), journal = reference.manualJournal, publish = journal?.attempts?.at(-1), operation = proof.databaseProof?.operation;
  if (failure.testTag !== expected.testTag || failure.passed !== 50 || failure.failed !== 1 || failure.allPassed !== false || failure.checks?.length !== 51 || failure.checks.slice(0, 50).some(row => row.passed !== true) || failure.checks[50]?.name !== 'harness stopped after Markdown publish: actual 2xx' || failure.screenshots?.length !== 11 || failure.readEvidence?.length !== 7
    || proof.allPassed !== true || proof.originalPublishProvenSucceeded !== true || proof.productFailure !== false || proof.sourceFailureSha256 !== MANUAL_PUBLICATION_FAILURE_SHA256 || proof.privateJournalChanged !== false || proof.transportWriteRequests !== 0 || proof.loginRequests !== 0 || proof.refreshRequests !== 0 || proof.nativeRequests !== 0 || proof.revealRequests !== 0
    || journal?.source !== 'manual-ui' || journal.version !== 1 || journal.phase !== 'stopped-without-replay' || journal.nextIndex !== 3 || journal.clusterId !== expected.clusterId || journal.workspaceId !== expected.workspaceId || !same(journal.actors, expected.actors) || !same(journal.content, expected.content) || !same(journal.attempts, reference.manualWriteAttempts) || journal.attempts?.length !== 7 || reference.manualWriteEvidence?.length !== 6 || reference.manualMetadata?.length !== 1
    || !manualUuid(journal.pageId) || journal.pageId !== proof.pageId || journal.pageRevision !== 2 || proof.clusterId !== journal.clusterId || proof.workspaceId !== journal.workspaceId || publish?.action !== 'page-publish' || publish.category !== 'planned' || publish.state !== 'metadata-receipt-not-proven' || publish.status !== 201 || publish.requestId !== proof.originalRequestId || journal.inFlight !== publish.key || digest(publish.key) !== proof.originalKeySha256
    || publish.role !== 'administrator' || publish.actorId !== expected.actors.administrator.id || publish.clusterId !== journal.clusterId || publish.workspaceId !== journal.workspaceId || publish.origin !== 'http://127.0.0.1:8080' || publish.method !== 'POST' || publish.path !== `/api/v1/clusters/${journal.clusterId}/portal/pages/${journal.pageId}/publish` || publish.query !== `workspaceId=${journal.workspaceId}` || publish.headers?.['x-idempotency-key'] !== publish.key
    || !same(publish.body, JSON.parse(publish.rawBody)) || Object.keys(publish.body).length !== 3 || publish.body.revision !== 2 || publish.body.confirmed !== true || publish.body.confirm_name !== journal.content.title
    || operation?.state !== 'succeeded' || operation.remote_completed !== true || operation.actor_matches !== true || operation.key_matches !== true || operation.content_identity_matches !== true || operation.target_id !== journal.pageId || operation.cluster_id !== journal.clusterId || operation.workspace_id !== journal.workspaceId || operation.module !== 'portal' || operation.action !== 'write' || operation.error_code !== null || operation.entity_state !== 'published' || operation.entity_revision !== '3' || operation.entity_document_revision !== '2'
    || proof.databaseProof.audits?.[0]?.actor_id !== expected.actors.administrator.id || proof.databaseProof.page?.revision !== 3 || proof.databaseProof.page.published_revision !== 2 || proof.databaseProof.page.content_identity_matches !== true) reject();
  if (!same(journal.attempts.map(({ category, action, state, status, requestId }) => ({ category, action, state, status, requestId })), failure.writeBoundary?.actions)) reject();
  const planned = journal.attempts.filter(row => row.category === 'planned'), refresh = journal.attempts.filter(row => row.category === 'continuation-session-refresh');
  if (planned.length !== 4 || planned.some((row, index) => row.action !== MANUAL_ACTIONS[index]) || planned.slice(0, 3).some(row => row.state !== 'response-observed-success') || !manualUuid(planned[2].workflowId) || planned[2].entityId !== journal.pageId || refresh.length !== 2 || refresh.some(row => row.state !== 'response-observed-success') || new Set(refresh.map(row => row.role)).size !== 2) reject();
  preserveManualDetailRemaining(reference, journal.detailRemainingContinuation, journal);
  const original = structuredClone(snapshot(reference));
  return Object.freeze({ version: 1, failureReportSha256: MANUAL_PUBLICATION_FAILURE_SHA256, diagnosticProofSha256: MANUAL_PUBLICATION_PROOF_SHA256, originalSnapshotSha256: digest(original), snapshot: original, externalRenewal: publicationTailRenewalEvidence(reference, renewalReportBytes), originalFailureBytes: String(failureBytes), originalFailure: failure, originalProofBytes: String(proofBytes), originalProof: proof, testTag: expected.testTag, clusterId: journal.clusterId, workspaceId: journal.workspaceId, createWorkflowId: planned[2].workflowId, publishedEntity: { id: journal.pageId, slug: journal.content.slug, title: journal.content.title, revision: 3, documentRevision: 2, state: 'published' }, continuedAt: new Date().toISOString() });
}
export function activateManualPublicationTail(prepared) {
  const journal = structuredClone(prepared.snapshot.manualJournal); journal.phase = 'active'; delete journal.stopReason; delete journal.stoppedAt;
  journal.publicationTailContinuation = prepared; journal.attempts.at(-1).acknowledgedEntity = { ...prepared.publishedEntity }; journal.attempts.at(-1).state = 'metadata-acknowledged-awaiting-original-iam-proof';
  return journal;
}
export function preserveManualPublicationTail(latest, prepared, journal) {
  const old = prepared?.snapshot?.manualJournal;
  if (!latest || digest(prepared.snapshot) !== prepared.originalSnapshotSha256 || digest(prepared.originalFailureBytes) !== MANUAL_PUBLICATION_FAILURE_SHA256 || digest(prepared.originalProofBytes) !== MANUAL_PUBLICATION_PROOF_SHA256 || latest.testTag !== prepared.testTag || journal.clusterId !== old.clusterId || journal.workspaceId !== old.workspaceId || journal.startedAt !== old.startedAt || !same(journal.actors, old.actors) || !same(journal.content, old.content) || !same(journal.attempts.slice(0, 6), old.attempts.slice(0, 6)) || journal.nextIndex < 3 || journal.pageId !== old.pageId || !same(journal.restoredSessions, old.restoredSessions)) reject();
  if (prepared.externalRenewal?.externalNormalSessionRenewalWrites === 2 ? digest(latest.manualTailSessionRenewal) !== prepared.externalRenewal.markerSha256 || digest(latest.manualTailSessionRenewalHistory) !== prepared.externalRenewal.historySha256 : Object.hasOwn(latest, 'manualTailSessionRenewal') || Object.hasOwn(latest, 'manualTailSessionRenewalHistory')) reject();
  const original = old.attempts[6], current = journal.attempts[6];
  for (const field of ['action', 'category', 'role', 'actorId', 'method', 'origin', 'path', 'query', 'key', 'rawBody', 'body', 'headers', 'status', 'requestId']) if (!same(current?.[field], original[field])) reject();
  const marker = { version: 1, failureReportSha256: prepared.failureReportSha256, diagnosticProofSha256: prepared.diagnosticProofSha256, originalSnapshotSha256: prepared.originalSnapshotSha256, continuedAt: prepared.continuedAt };
  const history = { ...marker, snapshot: prepared.snapshot, originalFailureBytes: prepared.originalFailureBytes, originalProofBytes: prepared.originalProofBytes };
  if (Object.hasOwn(latest, 'manualPublicationTailContinuation') || Object.hasOwn(latest, 'manualPublicationTailHistory')) {
    if (!same(latest.manualPublicationTailContinuation, marker) || !same(latest.manualPublicationTailHistory, history) || fields.slice(4).some(field => !same(latest[field], prepared.snapshot[field]))) reject();
    return latest;
  }
  if (digest(snapshot(latest)) !== prepared.originalSnapshotSha256) reject();
  return { ...latest, manualPublicationTailContinuation: marker, manualPublicationTailHistory: history };
}
export function publicationTailSessionCookies(journal, role, now = Date.now()) {
  const session = journal.restoredSessions?.[role], names = role === 'owner' ? ['kongos_portal_access', 'kongos_portal_refresh', 'kongos_portal_csrf'] : ['kongos_access', 'kongos_refresh', 'kongos_csrf'], cookies = session?.latestCookies;
  if (!['owner', 'administrator'].includes(role) || !journal.publicationTailContinuation || session?.refreshAttempted !== true || session.refreshed !== true || session.actorId !== journal.actors[role].id || journal.authenticated[role] !== session.actorId || !Array.isArray(cookies) || cookies.length !== 3 || new Set(cookies.map(cookie => cookie.name)).size !== 3 || cookies.some(cookie => !names.includes(cookie.name) || !cookie.value)) reject();
  let claims; try { claims = JSON.parse(Buffer.from(cookies.find(cookie => cookie.name === names[0]).value.split('.')[1], 'base64url').toString()); } catch { reject(); }
  if (claims.sid !== session.sessionId || claims.sub !== session.actorId || !Number.isFinite(claims.exp) || claims.exp <= now / 1000 || cookies.find(cookie => cookie.name === names[1]).value.split('.')[0] !== session.sessionId || role === 'owner' && (claims.cid !== journal.clusterId || claims.wid !== journal.workspaceId)) reject();
  return structuredClone(cookies);
}
export function beforePublicationTailMutation(journal, role, packet, cookies, persist) {
  const action = MANUAL_ACTIONS[journal.nextIndex], allowedRole = action === 'console-approver-login' ? 'approver' : 'administrator';
  if (!journal.publicationTailContinuation || !['page-archive', 'page-restore-draft', 'console-approver-login'].includes(action) || role !== allowedRole) { stopManualJournal(journal, 'outside-three-unused-tail-intents', persist); throw new Error('M6_MANUAL_PUBLICATION_TAIL_WRITE_BLOCKED'); }
  return beforeManualMutation(journal, role, packet, cookies, persist);
}
