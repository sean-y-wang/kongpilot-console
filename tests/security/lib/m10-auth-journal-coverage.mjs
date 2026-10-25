import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { UUID } from './m10-release-evidence.mjs';
import { validateM10BrowserContinuationRefresh } from './m10-fresh-browser-intent.mjs';

export const M10_AUTH_JOURNAL_EVIDENCE_PATH = 'artifacts/M10/auth-journal-concurrency-verification.json';
/** Frozen original read-only evidence, not a reconstructed private HTTP packet. */
export const M10_AUTH_JOURNAL_EVIDENCE_SHA256 = '277eea0a80df5d2b0b8811e5ba07818c96ddb2ede8bb45753251fba316cb85e7';
export const M10_AUTH_JOURNAL_LIMITATION = 'One historical auth refresh receipt and its issued token material are unavailable in the private test journal. The original application audit is preserved, the old session was revoked, and business write journals are intact. Secret byte scanning covers retained actual material only; it does not verify all historically issued token material.';

/** Root selects a reviewed successful browser cycle; no caller-controlled
 * private filename or arbitrary second prefix is accepted by report tools. */
export function m10FinalBrowserEvidenceNames(handoff) {
  assert(handoff?.nativeVerified === true, 'VERIFIED_M10_NATIVE_HANDOFF_REQUIRED');
  const original = { journalName: 'm10-browser-journal.json', materialName: 'm10-browser-secret-material.json', freshCycle: false };
  if (handoff.finalJournalName === undefined && handoff.finalMaterialName === undefined) return original;
  const pairs = [original,
    { journalName: 'm10-browser-after-visible-select-fix-journal.json', materialName: 'm10-browser-after-visible-select-fix-secret-material.json', freshCycle: true },
    { journalName: 'm10-browser-readonly-recheck-journal.json', materialName: 'm10-browser-readonly-recheck-secret-material.json', freshCycle: true, readOnlyRecheck: true },
    { journalName: 'm10-browser-readonly-recheck-attempt2-journal.json', materialName: 'm10-browser-readonly-recheck-attempt2-secret-material.json', freshCycle: true, readOnlyRecheck: true, verificationAttempt: 2 }];
  const selected = pairs.find(value => value.journalName === handoff.finalJournalName && value.materialName === handoff.finalMaterialName);
  assert(selected, 'M10_FINAL_BROWSER_EVIDENCE_PAIR_NOT_ALLOWED');
  return { ...selected };
}

/** Verify completed fresh browser evidence against the unchanged original
 * private bytes. This preserves the failed cycle without replaying its login
 * or manufacturing a material file that was never written. */
export function validateM10FinalBrowserRetention(files, journal, material, original = {}) {
  assert.equal(journal?.milestone, 'M10'); assert.equal(journal?.passed, true, 'ACTUAL_FINAL_M10_BROWSER_REQUIRED');
  assert.equal(material?.milestone, 'M10'); assert(Array.isArray(journal.requests));
  if (!files.freshCycle) return { ...files, retainedOriginalBrowserCycle: false };
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  assert(Buffer.isBuffer(original.journalBytes) && Buffer.isBuffer(original.reportBytes), 'M10_ORIGINAL_BROWSER_BYTES_REQUIRED');
  const old = JSON.parse(original.journalBytes.toString('utf8')), report = JSON.parse(original.reportBytes.toString('utf8'));
  assert.equal(old.milestone, 'M10'); assert.equal(old.passed, false); assert.equal(report.passed, false);
  assert.equal(report.actualBackend, true); assert.equal(report.mocksUsed, false); assert.equal(report.nativeWritesPerformed, false);
  assert.equal(report.observedWrites, 1); assert.equal(report.unknownWrites, 0);
  assert.equal(old.requests?.length, 1, 'M10_ORIGINAL_BROWSER_AUTH_ONLY_REQUIRED');
  const oldPacket = old.requests[0];
  assert.equal(oldPacket.method, 'POST'); assert.equal(oldPacket.path, '/api/v1/auth/login');
  assert.equal(oldPacket.state, 'response_observed'); assert.equal(oldPacket.status, 201);
  assert.equal(oldPacket.sourceCycle, undefined); assert(Array.isArray(oldPacket.responseHeaders));
  const present = original.materialBytes !== null && original.materialBytes !== undefined;
  if (present) assert(Buffer.isBuffer(original.materialBytes), 'M10_ORIGINAL_BROWSER_MATERIAL_BYTES_REQUIRED');
  const oldMaterial = present ? JSON.parse(original.materialBytes.toString('utf8')) : null;
  const expected = { journalName: 'm10-browser-journal.json', journalSha256: hash(original.journalBytes),
    reportPath: 'artifacts/M10/browser/verification.json', reportSha256: hash(original.reportBytes),
    materialName: present ? 'm10-browser-secret-material.json' : null, materialSha256: present ? hash(original.materialBytes) : null,
    originalMaterialPresent: present, originalResponseHeadersRetained: true, originalResponseRewritten: false, originalRequestsReplayed: false };
  assert.deepEqual(journal.retainedOriginalEvidence, expected, 'M10_ORIGINAL_BROWSER_EVIDENCE_CHANGED');
  assert.deepEqual(material.retainedOriginalEvidence, expected, 'M10_ORIGINAL_BROWSER_MATERIAL_EVIDENCE_CHANGED');
  assert.deepEqual(material.retainedOriginalJournal, old, 'M10_ORIGINAL_BROWSER_JOURNAL_NOT_RETAINED');
  assert.deepEqual(material.retainedOriginalMaterial, oldMaterial, 'M10_ORIGINAL_BROWSER_MATERIAL_NOT_RETAINED');
  assert(journal.requests.length > old.requests.length, 'M10_FRESH_BROWSER_ACTUAL_AUTH_REQUIRED');
  for (const [index, packet] of journal.requests.entries()) {
    assert.equal(packet.sourceCycle, index < old.requests.length ? 'm10-browser-original' : 'm10-browser-after-visible-select-fix', 'M10_BROWSER_SOURCE_CYCLE_MISMATCH');
    assert.equal(packet.method, 'POST'); assert(['/api/v1/auth/login', '/api/v1/auth/refresh'].includes(packet.path), 'M10_BROWSER_AUTH_ONLY_REQUIRED');
    assert.equal(packet.state, 'response_observed'); assert(packet.status >= 200 && packet.status < 300, 'M10_BROWSER_ACTUAL_AUTH_RESPONSE_REQUIRED');
    if (index < old.requests.length) {
      const { sourceCycle: _cycle, ...retained } = packet;
      assert.deepEqual(retained, old.requests[index], 'M10_ORIGINAL_BROWSER_PACKET_CHANGED');
    }
  }
  assert.deepEqual(material.issuedPackets, journal.requests, 'M10_BROWSER_ISSUED_PACKETS_NOT_RETAINED');
  const responseCookies = journal.requests.flatMap(packet => (packet.responseHeaders ?? []).filter(header => typeof header?.name === 'string' && header.name.toLowerCase() === 'set-cookie').map(header => header.value));
  assert(responseCookies.length > 0 && responseCookies.every(value => typeof value === 'string' && value.length > 0), 'M10_BROWSER_ACTUAL_RESPONSE_COOKIES_REQUIRED');
  assert(Array.isArray(material.responseCookies), 'M10_BROWSER_RESPONSE_COOKIES_NOT_RETAINED');
  assert.deepEqual([...new Set(material.responseCookies)].sort(), [...new Set(responseCookies)].sort(), 'M10_BROWSER_RESPONSE_COOKIES_NOT_RETAINED');
  const readOnlyRecheck = files.readOnlyRecheck ? validateM10ReadOnlyBrowserRetention(journal, material, original) : null;
  const previousReadOnlyAttempt = files.verificationAttempt === 2 ? validateM10ReadOnlyPreviousAttempt(journal, material, original) : null;
  return { ...files, retainedOriginalBrowserCycle: true, retainedOriginalEvidence: expected,
    originalObservedAuthRequests: old.requests.length, finalObservedAuthRequests: journal.requests.length,
    originalPacketsUnchanged: true, originalResponseHeadersRetained: true, originalMaterialPresent: present,
    originalResponseRewritten: false, originalRequestsReplayed: false,
    ...(readOnlyRecheck ? { readOnlyRecheckEvidence: readOnlyRecheck } : {}),
    ...(previousReadOnlyAttempt ? { readOnlyPreviousAttemptEvidence: previousReadOnlyAttempt } : {}) };
}

/** The third fixed cycle reuses actual still-valid cookies. A successful
 * readonly recheck must preserve both prior closed cycles and append no write
 * packet; the fixed runner stops rather than silently logging in or refreshing. */
export function validateM10ReadOnlyBrowserRetention(journal, material, original) {
  for (const name of ['previousJournalBytes', 'previousMaterialBytes', 'previousReportBytes', 'freshIntentBytes']) assert(Buffer.isBuffer(original[name]), 'M10_PREVIOUS_BROWSER_BYTES_REQUIRED');
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const previous = JSON.parse(original.previousJournalBytes.toString('utf8'));
  const previousMaterial = JSON.parse(original.previousMaterialBytes.toString('utf8'));
  const previousReport = JSON.parse(original.previousReportBytes.toString('utf8'));
  const freshIntent = JSON.parse(original.freshIntentBytes.toString('utf8'));
  assert.equal(previous.milestone, 'M10'); assert.equal(previous.passed, false); assert(UUID.test(previous.actorId ?? ''));
  assert.equal(previousMaterial.milestone, 'M10'); assert(Array.isArray(previousMaterial.cookies) && previousMaterial.cookies.length > 0);
  assert.equal(previousReport.passed, false); assert.equal(previousReport.actualBackend, true); assert.equal(previousReport.mocksUsed, false);
  assert.equal(previousReport.nativeWritesPerformed, false); assert.equal(previousReport.unknownWrites, 0);
  assert.equal(previousReport.observedWrites, previous.requests?.length); assert.equal(previousReport.currentCycleObservedWrites, 1);
  assert.equal(previousReport.sourceCycle, 'm10-browser-after-visible-select-fix');
  assert.equal(freshIntent.version, 1); assert.equal(freshIntent.prefix, 'm10-browser-after-visible-select-fix');
  assert.equal(freshIntent.actorId, previous.actorId); assert.equal(freshIntent.freshAuthenticationOnly, true);
  assert.equal(freshIntent.originalRequestsReplayed, false); assert.equal(freshIntent.originalResponseRewritten, false);
  const refreshCookie = previousMaterial.cookies.find(cookie => cookie?.name === 'kongos_refresh');
  assert(typeof refreshCookie?.value === 'string', 'M10_PREVIOUS_BROWSER_ACTUAL_REFRESH_COOKIE_REQUIRED');
  const sessionId = refreshCookie.value.split('.')[0]; assert(UUID.test(sessionId), 'M10_PREVIOUS_BROWSER_ACTUAL_SESSION_REQUIRED');
  const expected = { journalName: 'm10-browser-after-visible-select-fix-journal.json', journalSha256: hash(original.previousJournalBytes),
    materialName: 'm10-browser-after-visible-select-fix-secret-material.json', materialSha256: hash(original.previousMaterialBytes),
    reportPath: 'artifacts/M10/browser-after-visible-select-fix/verification.json', reportSha256: hash(original.previousReportBytes),
    freshIntentName: 'm10-browser-fresh-intent.json', freshIntentSha256: hash(original.freshIntentBytes),
    cookieJarSha256: hash(JSON.stringify(previousMaterial.cookies)), actorId: previous.actorId, sessionId,
    previousFailurePreserved: true, previousResponseRewritten: false, previousRequestsReplayed: false, newLoginRequested: false };
  assert.deepEqual(journal.readOnlyRecheckEvidence, expected, 'M10_READONLY_BROWSER_PREVIOUS_EVIDENCE_CHANGED');
  assert.deepEqual(material.readOnlyRecheckEvidence, expected, 'M10_READONLY_BROWSER_MATERIAL_EVIDENCE_CHANGED');
  assert.deepEqual(material.retainedPreviousJournal, previous, 'M10_PREVIOUS_BROWSER_JOURNAL_NOT_RETAINED');
  assert.deepEqual(material.retainedPreviousMaterial, previousMaterial, 'M10_PREVIOUS_BROWSER_MATERIAL_NOT_RETAINED');
  assert.equal(journal.actorId, previous.actorId, 'M10_READONLY_BROWSER_ACTOR_CHANGED');
  assert.deepEqual(journal.requests, previous.requests, 'M10_READONLY_BROWSER_WRITE_ORIGINALS_CHANGED');
  assert.deepEqual(material.issuedPackets, previous.requests, 'M10_READONLY_BROWSER_ISSUED_PACKETS_CHANGED');
  assert.deepEqual(previousMaterial.issuedPackets, previous.requests, 'M10_PREVIOUS_BROWSER_ISSUED_PACKETS_CHANGED');
  for (const field of ['retainedOriginalEvidence', 'retainedOriginalJournal', 'retainedOriginalMaterial']) assert.deepEqual(material[field], previousMaterial[field], 'M10_READONLY_BROWSER_FIRST_CYCLE_NOT_RETAINED');
  assert.deepEqual(journal.retainedOriginalEvidence, previous.retainedOriginalEvidence, 'M10_READONLY_BROWSER_FIRST_EVIDENCE_CHANGED');
  assert.deepEqual(previousReport.retainedOriginalEvidence, previous.retainedOriginalEvidence, 'M10_PREVIOUS_BROWSER_REPORT_ORIGIN_CHANGED');
  assert.deepEqual(material.responseCookies, previousMaterial.responseCookies, 'M10_READONLY_BROWSER_ISSUED_COOKIES_CHANGED');
  const orderedCookies = values => [...values].sort((a, b) => `${a.name}:${a.domain}:${a.path}`.localeCompare(`${b.name}:${b.domain}:${b.path}`));
  let continuation = null;
  if (journal.freshCookieEvidence || material.freshCookieEvidence) {
    assert(Buffer.isBuffer(original.continuationRefreshBrowserBytes) && Buffer.isBuffer(original.rawContinuationRefreshBytes), 'M10_ACTUAL_BROWSER_REFRESH_BYTES_REQUIRED');
    continuation = validateM10BrowserContinuationRefresh({ proofBytes: original.continuationRefreshBrowserBytes, rawProofBytes: original.rawContinuationRefreshBytes,
      rootPacket: original.rootRefreshPacket, previousMaterial, actorId: previous.actorId, sessionId });
    assert.equal(continuation.proof.previousMaterialSha256, hash(original.previousMaterialBytes), 'M10_ACTUAL_REFRESH_PREVIOUS_MATERIAL_CHANGED');
    const metadata = original.rootRefreshMetadata;
    assert(metadata?.sameActualSid === true, 'M10_ACTUAL_REFRESH_ROOT_JOURNAL_REQUIRED');
    assert.equal(metadata.requestId, continuation.evidence.requestId); assert.equal(metadata.key, continuation.evidence.key);
    assert.equal(metadata.evidenceSha256, continuation.evidence.rawEvidenceSha256);
    assert.equal(metadata.browserEvidenceName, continuation.evidence.evidenceName); assert.equal(metadata.browserEvidenceSha256, continuation.evidence.evidenceSha256);
    assert.deepEqual(journal.freshCookieEvidence, continuation.evidence, 'M10_BROWSER_ACTUAL_REFRESH_EVIDENCE_CHANGED');
    assert.deepEqual(material.freshCookieEvidence, continuation.evidence, 'M10_BROWSER_ACTUAL_REFRESH_MATERIAL_EVIDENCE_CHANGED');
    assert.deepEqual(material.continuationRefreshEvidence, continuation.proof, 'M10_BROWSER_ACTUAL_REFRESH_NOT_RETAINED');
    assert.deepEqual(material.rawContinuationRefreshEvidence, continuation.rawProof, 'M10_BROWSER_RAW_ACTUAL_REFRESH_NOT_RETAINED');
  }
  assert(Array.isArray(material.cookies)); assert.deepEqual(orderedCookies(material.cookies), orderedCookies(continuation?.cookies ?? previousMaterial.cookies), 'M10_READONLY_BROWSER_COOKIE_JAR_CHANGED');
  const verified = journal.readOnlySessionVerification;
  assert(verified && typeof verified === 'object' && !Array.isArray(verified), 'M10_READONLY_BROWSER_ACTUAL_SESSION_VERIFICATION_REQUIRED');
  assert.deepEqual(Object.keys(verified).sort(), ['method', 'path', 'status', 'actorId', 'sessionId', 'requestId', 'responseHash', 'verifiedAt'].sort());
  assert.equal(verified.method, 'GET'); assert.equal(verified.path, '/api/v1/auth/me'); assert.equal(verified.status, 200);
  assert.equal(verified.actorId, previous.actorId); assert.equal(verified.sessionId, sessionId);
  assert(UUID.test(verified.requestId ?? '') && typeof verified.responseHash === 'string' && /^[a-f\d]{64}$/.test(verified.responseHash), 'M10_READONLY_BROWSER_ACTUAL_RESPONSE_REQUIRED');
  assert(typeof verified.verifiedAt === 'string' && Number.isFinite(Date.parse(verified.verifiedAt)) && new Date(verified.verifiedAt).toISOString() === verified.verifiedAt, 'M10_READONLY_BROWSER_ACTUAL_TIME_REQUIRED');
  return { ...expected, previousObservedAuthRequests: previous.requests.length, newWritePackets: 0,
    actualPreviousCookiesRetained: true, previousPacketsUnchanged: true, readOnlySessionVerification: { ...verified },
    ...(continuation ? { freshCookieEvidence: continuation.evidence, actualSameSessionRootRefreshVerified: true } : {}) };
}

/** Select an existing actual Root WAL packet, never an invented browser write. */
export function m10BrowserContinuationRootPacket(harness) {
  const metadata = harness?.browserContinuationRefresh;
  assert(metadata?.sameActualSid === true && UUID.test(metadata.requestId ?? '') && UUID.test(metadata.key ?? ''), 'M10_ACTUAL_REFRESH_ROOT_JOURNAL_REQUIRED');
  assert(Array.isArray(harness.requests));
  const packets = harness.requests.filter(packet => packet.requestId === metadata.requestId && packet.key === metadata.key);
  assert.equal(packets.length, 1, 'M10_ACTUAL_REFRESH_ROOT_PACKET_REQUIRED');
  return packets[0];
}

/** A second pure GET verification may use a new fixed report destination, but
 * the closed first readonly attempt remains an unchanged failed fact. */
export function validateM10ReadOnlyPreviousAttempt(journal, material, original) {
  for (const field of ['previousReadOnlyJournalBytes', 'previousReadOnlyMaterialBytes', 'previousReadOnlyReportBytes']) assert(Buffer.isBuffer(original[field]), 'M10_PREVIOUS_READONLY_ATTEMPT_BYTES_REQUIRED');
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const previous = JSON.parse(original.previousReadOnlyJournalBytes.toString('utf8'));
  const previousMaterial = JSON.parse(original.previousReadOnlyMaterialBytes.toString('utf8'));
  const report = JSON.parse(original.previousReadOnlyReportBytes.toString('utf8'));
  assert.equal(journal.verificationAttempt, 2); assert.equal(previous.milestone, 'M10'); assert.equal(previous.passed, false);
  assert.equal(previous.sourceCycle, 'm10-browser-readonly-recheck'); assert.equal(previousMaterial.milestone, 'M10');
  assert.equal(report.passed, false); assert.equal(report.actualBackend, true); assert.equal(report.mocksUsed, false);
  assert.equal(report.nativeWritesPerformed, false); assert.equal(report.sourceCycle, 'm10-browser-readonly-recheck');
  assert.equal(report.observedWrites, 2); assert.equal(report.currentCycleObservedWrites, 0); assert.equal(report.unknownWrites, 0);
  assert.equal(report.failure?.errorType, 'TimeoutError'); assert.equal(report.failure?.code, 'M10_BROWSER_VERIFICATION_FAILED');
  assert.deepEqual(report.failure.failedRequests, []);
  assert.equal(previous.requests?.length, 2); assert(previous.requests.every(packet => packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300), 'M10_PREVIOUS_READONLY_ATTEMPT_UNKNOWN_WRITE');
  const expected = { journalName: 'm10-browser-readonly-recheck-journal.json', journalSha256: hash(original.previousReadOnlyJournalBytes),
    materialName: 'm10-browser-readonly-recheck-secret-material.json', materialSha256: hash(original.previousReadOnlyMaterialBytes),
    reportPath: 'artifacts/M10/browser-readonly-recheck/verification.json', reportSha256: hash(original.previousReadOnlyReportBytes),
    verificationAttempt: 1, originalPassed: false, observedWrites: 2, currentCycleObservedWrites: 0, unknownWrites: 0,
    originalFailurePreserved: true, originalResponseRewritten: false, originalRequestsReplayed: false };
  assert.deepEqual(journal.readOnlyPreviousAttemptEvidence, expected, 'M10_PREVIOUS_READONLY_ATTEMPT_EVIDENCE_CHANGED');
  assert.deepEqual(material.readOnlyPreviousAttemptEvidence, expected, 'M10_PREVIOUS_READONLY_ATTEMPT_MATERIAL_EVIDENCE_CHANGED');
  assert.deepEqual(material.retainedPreviousReadOnlyJournal, previous, 'M10_PREVIOUS_READONLY_ATTEMPT_JOURNAL_NOT_RETAINED');
  assert.deepEqual(material.retainedPreviousReadOnlyMaterial, previousMaterial, 'M10_PREVIOUS_READONLY_ATTEMPT_MATERIAL_NOT_RETAINED');
  assert.deepEqual(journal.requests, previous.requests, 'M10_READONLY_ATTEMPT_ADDITIONAL_WRITE');
  assert.deepEqual(material.issuedPackets, previousMaterial.issuedPackets, 'M10_READONLY_ATTEMPT_ISSUED_MATERIAL_CHANGED');
  assert.deepEqual(material.responseCookies, previousMaterial.responseCookies, 'M10_READONLY_ATTEMPT_ISSUED_COOKIES_CHANGED');
  assert.deepEqual(journal.retainedOriginalEvidence, previous.retainedOriginalEvidence);
  assert.deepEqual(journal.readOnlyRecheckEvidence, previous.readOnlyRecheckEvidence);
  assert.deepEqual(report.retainedOriginalEvidence, previous.retainedOriginalEvidence); assert.deepEqual(report.readOnlyRecheckEvidence, previous.readOnlyRecheckEvidence);
  assert.notEqual(journal.readOnlySessionVerification?.requestId, previous.readOnlySessionVerification?.requestId, 'M10_READONLY_ATTEMPT_ACTUAL_NEW_GET_REQUIRED');
  return { ...expected, previousPacketsUnchanged: true, newWritePackets: 0 };
}

/** Pure validation. The optional digest is only for synthetic evidence tests;
 * actual report tools always use the frozen original evidence digest above. */
export function validateM10AuthJournalCoverage(bytes, expectedSha256 = M10_AUTH_JOURNAL_EVIDENCE_SHA256) {
  assert(Buffer.isBuffer(bytes) || typeof bytes === 'string', 'M10_AUTH_JOURNAL_EVIDENCE_BYTES_REQUIRED');
  const original = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  assert(original.length > 0 && original.length <= 16 * 1024, 'M10_AUTH_JOURNAL_EVIDENCE_SIZE');
  assert(typeof expectedSha256 === 'string' && /^[a-f\d]{64}$/.test(expectedSha256), 'M10_AUTH_JOURNAL_EXPECTED_DIGEST_REQUIRED');
  const evidenceSha256 = createHash('sha256').update(original).digest('hex');
  assert.equal(evidenceSha256, expectedSha256, 'M10_AUTH_JOURNAL_EVIDENCE_CHANGED');
  let evidence; try { evidence = JSON.parse(original.toString('utf8')); } catch { throw Error('M10_AUTH_JOURNAL_EVIDENCE_INVALID'); }
  assert(evidence && typeof evidence === 'object' && !Array.isArray(evidence), 'M10_AUTH_JOURNAL_EVIDENCE_INVALID');
  const fields = ['milestone', 'issue', 'productionDeployment', 'originalHttpSuccessObserved', 'originalHttpStatus', 'originalJournalPacketReconstructed', 'overwrittenIssuedTokenMaterialAvailable', 'businessWriteJournalPreserved', 'kongNativeReplay', 'actualAudit', 'consoleReadOnly', 'auditPreserved', 'oldSessionRevoked', 'newActualSessionActive', 'nativeMutationCount', 'scopeLimit'];
  assert.deepEqual(Object.keys(evidence).sort(), fields.sort(), 'M10_AUTH_JOURNAL_EVIDENCE_FIELDS');
  assert.equal(evidence.milestone, 'M10'); assert.equal(evidence.issue, 'test-operator-auth-only-journal-overlap');
  assert.equal(evidence.originalHttpStatus, 201); assert.equal(evidence.nativeMutationCount, 0);
  for (const field of ['originalHttpSuccessObserved', 'businessWriteJournalPreserved', 'consoleReadOnly', 'auditPreserved', 'oldSessionRevoked', 'newActualSessionActive']) assert.equal(evidence[field], true, `M10_AUTH_JOURNAL_${field}_REQUIRED`);
  for (const field of ['productionDeployment', 'originalJournalPacketReconstructed', 'overwrittenIssuedTokenMaterialAvailable', 'kongNativeReplay']) assert.equal(evidence[field], false, `M10_AUTH_JOURNAL_${field}_FORBIDDEN`);
  assert.equal(evidence.scopeLimit, 'One auth refresh receipt was overwritten in the private test ledger by parallel operator saves; application audit remains intact. Byte scanning covers retained actual material only.');
  const audit = evidence.actualAudit;
  assert(audit && typeof audit === 'object' && !Array.isArray(audit), 'M10_AUTH_JOURNAL_AUDIT_REQUIRED');
  assert.deepEqual(Object.keys(audit).sort(), ['id', 'actor_id', 'entity_id', 'action', 'result', 'request_id', 'occurred_at'].sort());
  for (const field of ['id', 'actor_id', 'entity_id', 'request_id']) assert(UUID.test(audit[field] ?? ''), 'M10_AUTH_JOURNAL_AUDIT_ID_REQUIRED');
  assert.equal(audit.action, 'refresh'); assert.equal(audit.result, 'success');
  assert(typeof audit.occurred_at === 'string' && Number.isFinite(Date.parse(audit.occurred_at)) && new Date(audit.occurred_at).toISOString() === audit.occurred_at, 'M10_AUTH_JOURNAL_AUDIT_TIME_REQUIRED');
  return { validated: true, evidencePath: M10_AUTH_JOURNAL_EVIDENCE_PATH, evidenceSha256,
    issue: evidence.issue, originalHttpSuccessObserved: true, originalHttpStatus: 201,
    originalJournalPacketReconstructed: false, overwrittenIssuedTokenMaterialAvailable: false,
    businessWriteJournalPreserved: true, applicationAuditPreserved: true, oldSessionRevoked: true,
    newActualSessionActive: true, nativeMutationCount: 0, kongNativeReplay: false,
    actualAudit: { ...audit }, secretByteScanCoversRetainedActualMaterialOnly: true,
    allHistoricalIssuedTokenMaterialScanned: false, limitation: M10_AUTH_JOURNAL_LIMITATION };
}
