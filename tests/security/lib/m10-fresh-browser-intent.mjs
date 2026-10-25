import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const FRESH_BROWSER_PREFIX = 'm10-browser-after-visible-select-fix';
export const M10_ORIGINAL_BROWSER = Object.freeze({ journalName: 'm10-browser-journal.json', materialName: 'm10-browser-secret-material.json', directory: 'artifacts/M10/browser', reportPath: 'artifacts/M10/browser/verification.json' });
export const M10_FRESH_BROWSER = Object.freeze({ journalName: `${FRESH_BROWSER_PREFIX}-journal.json`, materialName: `${FRESH_BROWSER_PREFIX}-secret-material.json`, directory: 'artifacts/M10/browser-after-visible-select-fix', reportPath: 'artifacts/M10/browser-after-visible-select-fix/verification.json' });
export const READONLY_BROWSER_PREFIX = 'm10-browser-readonly-recheck';
export const M10_READONLY_BROWSER = Object.freeze({ journalName: `${READONLY_BROWSER_PREFIX}-journal.json`, materialName: `${READONLY_BROWSER_PREFIX}-secret-material.json`, directory: 'artifacts/M10/browser-readonly-recheck', reportPath: 'artifacts/M10/browser-readonly-recheck/verification.json' });
const sha = value => createHash('sha256').update(value).digest('hex');
const hex = value => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(value);

export function m10BrowserHandoffSha256(handoff) {
  assert.equal(handoff?.nativeVerified, true); assert(Number.isFinite(Date.parse(handoff.verifiedAt)));
  for (const field of ['clusterId', 'workspaceId', 'reportId', 'comparisonId']) assert(uuid(handoff[field]));
  for (const field of ['ruleName', 'scheduleName', 'sourceConsumerName']) assert(typeof handoff[field] === 'string' && handoff[field].length > 0);
  return sha(JSON.stringify(Object.fromEntries(['nativeVerified', 'verifiedAt', 'clusterId', 'workspaceId', 'reportId', 'comparisonId', 'ruleName', 'scheduleName', 'sourceConsumerName'].map(field => [field, handoff[field]]))));
}

/** Explicit authorization for a new auth-only browser cycle, never a replay of
 * the original login or a repair of its failed report. No filesystem or HTTP. */
export function validateFreshBrowserIntent({ intent, originalJournalBytes, originalReportBytes, originalMaterialBytes = null, actorId, username, handoff }) {
  assert(intent && intent.version === 1 && intent.prefix === FRESH_BROWSER_PREFIX, 'FIXED_ROOT_FRESH_BROWSER_INTENT_REQUIRED');
  assert.equal(intent.cause, 'visible-ant-select-click-timeout'); assert(uuid(actorId)); assert.equal(intent.actorId, actorId);
  for (const field of ['clusterId', 'workspaceId', 'reportId', 'comparisonId']) assert.equal(intent[field], handoff[field]);
  assert.equal(intent.handoffSha256, m10BrowserHandoffSha256(handoff), 'EXACT_REVIEWED_NATIVE_HANDOFF_REQUIRED');
  for (const field of ['originalResponseRewritten', 'originalRequestsReplayed']) assert.equal(intent[field], false);
  assert.equal(intent.freshAuthenticationOnly, true);
  const journalBytes = Buffer.from(originalJournalBytes), reportBytes = Buffer.from(originalReportBytes);
  assert(hex(intent.originalJournalSha256) && hex(intent.originalReportSha256));
  assert.equal(intent.originalJournalSha256, sha(journalBytes), 'ORIGINAL_BROWSER_JOURNAL_BYTES_CHANGED');
  assert.equal(intent.originalReportSha256, sha(reportBytes), 'ORIGINAL_BROWSER_REPORT_BYTES_CHANGED');
  const original = JSON.parse(journalBytes.toString('utf8')), report = JSON.parse(reportBytes.toString('utf8'));
  assert.equal(original.version, 1); assert.equal(original.milestone, 'M10'); assert.equal(original.source, 'actual-browser'); assert.equal(original.actorId, actorId); assert.equal(original.passed, false);
  assert.equal(original.failure?.errorType, 'TimeoutError'); assert.equal(original.failure?.code, 'M10_BROWSER_VERIFICATION_FAILED');
  assert.equal(original.privateFailure?.errorType, 'TimeoutError');
  const message = original.privateFailure.message;
  assert(typeof message === 'string' && ['发布对象范围', 'ant-select-selection-item', 'intercepts pointer events'].every(text => message.includes(text)), 'EXACT_VISIBLE_SELECT_TOOL_TIMEOUT_REQUIRED');
  assert(Array.isArray(original.requests) && original.requests.length > 0 && original.requests.length <= 20);
  for (const packet of original.requests) {
    assert.equal(packet.method, 'POST'); assert(['/api/v1/auth/login', '/api/v1/auth/refresh'].includes(packet.path), 'ORIGINAL_BROWSER_AUTH_ONLY_REQUIRED');
    assert(!packet.query); assert.equal(packet.actorId, actorId); assert.equal(packet.state, 'response_observed'); assert.equal(packet.status, 201);
    assert(hex(packet.bodyHash) && hex(packet.responseHash)); assert.equal(packet.bodyHash, sha(JSON.stringify(packet.body)));
    assert(Number.isFinite(Date.parse(packet.startedAt))); assert(!packet.sourceCycle, 'ORIGINAL_BROWSER_PACKET_ALREADY_WRAPPED');
    if (packet.path.endsWith('/login')) { assert.equal(packet.body.username, username); assert.equal(packet.responseData?.user?.id, actorId); }
  }
  assert.equal(original.requests[0].path, '/api/v1/auth/login');
  const issuedCookies = retainedBrowserResponseCookies([original.requests[0]]), issuedCsrf = original.requests[0].responseData?.csrfToken;
  assert(typeof issuedCsrf === 'string' && issuedCsrf.length >= 16, 'ACTUAL_ORIGINAL_ISSUED_CSRF_REQUIRED');
  for (const name of ['kongos_access', 'kongos_refresh', 'kongos_csrf']) {
    const cookie = issuedCookies.find(value => value.startsWith(`${name}=`));
    assert(cookie && cookie.split(';')[0].slice(name.length + 1).length >= 16, 'ACTUAL_ORIGINAL_SET_COOKIE_REQUIRED');
    if (name === 'kongos_csrf') assert.equal(decodeURIComponent(cookie.split(';')[0].slice(name.length + 1)), issuedCsrf);
  }
  for (const field of ['passed', 'mocksUsed', 'credentialsRecorded', 'nativeWritesPerformed', 'traceRecorded']) assert.equal(report[field], false);
  assert.equal(report.actualBackend, true); assert.equal(report.unknownWrites, 0); assert.equal(report.observedWrites, original.requests.length);
  assert.equal(report.failure?.errorType, 'TimeoutError'); assert.equal(report.failure?.code, 'M10_BROWSER_VERIFICATION_FAILED'); assert.deepEqual(report.failure.failedRequests, []);
  assert.equal(report.checks?.length, 4); assert(report.checks.every(check => check.passed === true));
  assert.equal(report.screenshots?.length, 4); assert(report.screenshots.every(path => typeof path === 'string' && /^artifacts\/M10\/browser\/[a-z-]+\.png$/.test(path)));
  const present = originalMaterialBytes !== null; assert.equal(intent.originalMaterialPresent, present);
  let originalMaterial = null;
  if (present) { assert.equal(intent.originalMaterialSha256, sha(Buffer.from(originalMaterialBytes))); originalMaterial = JSON.parse(Buffer.from(originalMaterialBytes).toString('utf8')); assert.equal(originalMaterial.milestone, 'M10'); }
  else assert.equal(intent.originalMaterialSha256, null, 'ABSENT_ORIGINAL_MATERIAL_MUST_NOT_BE_INVENTED');
  const evidence = { journalName: M10_ORIGINAL_BROWSER.journalName, journalSha256: intent.originalJournalSha256, reportPath: M10_ORIGINAL_BROWSER.reportPath, reportSha256: intent.originalReportSha256,
    materialName: present ? M10_ORIGINAL_BROWSER.materialName : null, materialSha256: intent.originalMaterialSha256, originalMaterialPresent: present, originalResponseHeadersRetained: true, originalResponseRewritten: false, originalRequestsReplayed: false };
  return { ...M10_FRESH_BROWSER, prefix: FRESH_BROWSER_PREFIX, original, originalMaterial, retainedOriginalEvidence: evidence,
    retainedRequests: original.requests.map(packet => ({ ...structuredClone(packet), sourceCycle: 'm10-browser-original' })) };
}

export function retainedBrowserResponseCookies(requests) {
  return [...new Set(requests.flatMap(packet => (packet.responseHeaders ?? []).filter(header => typeof header.name === 'string' && header.name.toLowerCase() === 'set-cookie' && typeof header.value === 'string').map(header => header.value)))];
}

/** Recheck UI readiness using the same actual issued cookie jar. JWT decoding
 * only binds retained provenance; the runner must GET /auth/me for server auth. */
export function validateReadOnlyBrowserRecheckIntent({ intent, previousJournalBytes, previousMaterialBytes, previousReportBytes, freshIntentBytes,
  originalJournalBytes, originalReportBytes, originalMaterialBytes = null, actorId, username, handoff, now = Date.now(), continuationRefreshBytes = null, rawContinuationRefreshBytes = null, rootRefreshPacket = null }) {
  assert(intent && intent.version === 1 && intent.prefix === READONLY_BROWSER_PREFIX, 'FIXED_ROOT_READONLY_BROWSER_INTENT_REQUIRED');
  assert.equal(intent.cause, 'global-background-spinner-readiness-timeout'); assert.equal(intent.actorId, actorId);
  for (const field of ['clusterId', 'workspaceId', 'reportId', 'comparisonId']) assert.equal(intent[field], handoff[field]);
  assert.equal(intent.handoffSha256, m10BrowserHandoffSha256(handoff));
  for (const field of ['newLoginRequested', 'previousResponseRewritten', 'previousRequestsReplayed']) assert.equal(intent[field], false);
  const bytes = { previousJournalBytes, previousMaterialBytes, previousReportBytes, freshIntentBytes };
  for (const [field, value] of Object.entries(bytes)) { const digestField = field.replace('Bytes', 'Sha256'); assert(hex(intent[digestField])); assert.equal(intent[digestField], sha(Buffer.from(value)), 'PREVIOUS_BROWSER_EVIDENCE_BYTES_CHANGED'); }
  const freshIntent = JSON.parse(Buffer.from(freshIntentBytes).toString('utf8'));
  const fresh = validateFreshBrowserIntent({ intent: freshIntent, originalJournalBytes, originalReportBytes, originalMaterialBytes, actorId, username, handoff });
  const previous = JSON.parse(Buffer.from(previousJournalBytes).toString('utf8')), material = JSON.parse(Buffer.from(previousMaterialBytes).toString('utf8')), report = JSON.parse(Buffer.from(previousReportBytes).toString('utf8'));
  assert.equal(previous.milestone, 'M10'); assert.equal(previous.actorId, actorId); assert.equal(previous.source, 'actual-browser'); assert.equal(previous.sourceCycle, FRESH_BROWSER_PREFIX); assert.equal(previous.passed, false);
  assert.equal(previous.failure?.errorType, 'Error'); assert.equal(previous.failure?.code, 'M10_BROWSER_VERIFICATION_FAILED');
  assert.equal(previous.privateFailure?.errorType, 'Error');
  assert(['.ant-spin-spinning:visible', 'Expected: 0', 'Received: 1', 'Timeout:  5000ms'].every(text => previous.privateFailure.message?.includes(text)), 'EXACT_GLOBAL_SPINNER_TOOL_TIMEOUT_REQUIRED');
  assert.deepEqual(previous.retainedOriginalEvidence, fresh.retainedOriginalEvidence);
  assert.equal(previous.requests?.length, 2); assert.deepEqual(previous.requests.slice(0, 1), fresh.retainedRequests);
  const packet = previous.requests[1]; assert.equal(packet.sourceCycle, FRESH_BROWSER_PREFIX); assert.equal(packet.method, 'POST'); assert.equal(packet.path, '/api/v1/auth/login'); assert.equal(packet.actorId, actorId);
  assert.equal(packet.state, 'response_observed'); assert.equal(packet.status, 201); assert.equal(packet.body?.username, username); assert.equal(packet.bodyHash, sha(JSON.stringify(packet.body))); assert(hex(packet.responseHash)); assert.equal(packet.responseData?.user?.id, actorId);
  for (const field of ['passed', 'mocksUsed', 'credentialsRecorded', 'nativeWritesPerformed', 'traceRecorded']) assert.equal(report[field], false);
  assert.equal(report.actualBackend, true); assert.equal(report.sourceCycle, FRESH_BROWSER_PREFIX); assert.equal(report.unknownWrites, 0); assert.equal(report.observedWrites, 2); assert.equal(report.currentCycleObservedWrites, 1); assert.deepEqual(report.checks, []); assert.deepEqual(report.screenshots, []);
  assert.equal(report.failure?.errorType, 'Error'); assert.equal(report.failure?.code, 'M10_BROWSER_VERIFICATION_FAILED'); assert.deepEqual(report.failure.failedRequests, []);
  assert.deepEqual(report.retainedOriginalEvidence, fresh.retainedOriginalEvidence);
  assert.equal(material.milestone, 'M10'); assert.equal(material.sourceCycle, FRESH_BROWSER_PREFIX); assert.deepEqual(material.retainedOriginalEvidence, fresh.retainedOriginalEvidence);
  assert.deepEqual(material.retainedOriginalJournal, fresh.original); assert.deepEqual(material.retainedOriginalMaterial, fresh.originalMaterial); assert.deepEqual(material.issuedPackets, previous.requests); assert.deepEqual(material.responseCookies, retainedBrowserResponseCookies(previous.requests));
  assert(Array.isArray(material.cookies) && material.cookies.length === 3); assert.equal(intent.cookieJarSha256, sha(JSON.stringify(material.cookies)));
  const latestSetCookies = retainedBrowserResponseCookies([packet]);
  for (const name of ['kongos_access', 'kongos_refresh', 'kongos_csrf']) {
    const matches = material.cookies.filter(cookie => cookie.name === name); assert.equal(matches.length, 1); const cookie = matches[0];
    assert.equal(cookie.domain, '127.0.0.1'); assert.equal(cookie.path, name === 'kongos_refresh' ? '/api/v1/auth' : '/api'); assert.equal(cookie.httpOnly, true); assert.equal(cookie.sameSite, 'Strict');
    const header = latestSetCookies.find(value => value.startsWith(`${name}=`)); assert(header && decodeURIComponent(header.split(';')[0].slice(name.length + 1)) === cookie.value, 'ACTUAL_ISSUED_COOKIE_JAR_REQUIRED');
  }
  const access = material.cookies.find(cookie => cookie.name === 'kongos_access').value, parts = access.split('.'); assert.equal(parts.length, 3);
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); assert.equal(payload.sub, actorId); assert(uuid(payload.sid)); assert.equal(payload.iss, 'kongos-console'); assert.equal(payload.aud, 'kongos-api');
  assert.equal(intent.sessionId, payload.sid);
  assert(material.cookies.find(cookie => cookie.name === 'kongos_refresh').value.startsWith(`${payload.sid}.`)); assert.equal(material.cookies.find(cookie => cookie.name === 'kongos_csrf').value, packet.responseData.csrfToken);
  const continuation = continuationRefreshBytes === null ? null : validateM10BrowserContinuationRefresh({ proofBytes: continuationRefreshBytes, rawProofBytes: rawContinuationRefreshBytes, rootPacket: rootRefreshPacket, previousMaterial: material, actorId, sessionId: payload.sid });
  if (continuation) assert.equal(continuation.proof.previousMaterialSha256, intent.previousMaterialSha256);
  const liveCookies = continuation?.cookies ?? material.cookies, liveAccess = liveCookies.find(cookie => cookie.name === 'kongos_access').value;
  const livePayload = JSON.parse(Buffer.from(liveAccess.split('.')[1], 'base64url').toString('utf8')); assert.equal(livePayload.sub, actorId); assert.equal(livePayload.sid, payload.sid);
  assert(Number.isFinite(now) && Number.isSafeInteger(livePayload.exp) && livePayload.exp * 1000 - now > 30000, 'EXISTING_BROWSER_ACCESS_EXPIRED_NO_NEW_LOGIN');
  const evidence = { journalName: M10_FRESH_BROWSER.journalName, journalSha256: intent.previousJournalSha256, materialName: M10_FRESH_BROWSER.materialName, materialSha256: intent.previousMaterialSha256, reportPath: M10_FRESH_BROWSER.reportPath, reportSha256: intent.previousReportSha256,
    freshIntentName: 'm10-browser-fresh-intent.json', freshIntentSha256: intent.freshIntentSha256, cookieJarSha256: intent.cookieJarSha256, actorId, sessionId: payload.sid, previousFailurePreserved: true, previousResponseRewritten: false, previousRequestsReplayed: false, newLoginRequested: false };
  return { ...M10_READONLY_BROWSER, prefix: READONLY_BROWSER_PREFIX, ...Object.fromEntries(['original', 'originalMaterial', 'retainedOriginalEvidence'].map(field => [field, fresh[field]])),
    readOnlyRecheckEvidence: evidence, previous, previousMaterial: material, retainedRequests: structuredClone(previous.requests), seedCookies: structuredClone(liveCookies), seedSessionId: payload.sid,
    ...(continuation ? { freshCookieEvidence: continuation.evidence, continuationRefreshEvidence: continuation.proof, rawContinuationRefreshEvidence: continuation.rawProof } : {}) };
}

export const M10_BROWSER_CONTINUATION_REFRESH_SHA256 = 'a38072c2919a795af90ac8bfbd72fce18b67e53439951cec85619d527f773d77';
export function validateM10BrowserContinuationRefresh({ proofBytes, rawProofBytes, rootPacket, previousMaterial, actorId, sessionId, expectedSha256 = M10_BROWSER_CONTINUATION_REFRESH_SHA256 }) {
  const bytes = Buffer.from(proofBytes), rawBytes = Buffer.from(rawProofBytes); assert.equal(sha(bytes), expectedSha256, 'EXACT_ROOT_ACTUAL_REFRESH_BYTES_REQUIRED');
  const proof = JSON.parse(bytes.toString('utf8')), rawProof = JSON.parse(rawBytes.toString('utf8'));
  assert.equal(proof.version, 1); assert.equal(proof.kind, 'actual-same-session-refresh'); assert.equal(proof.actorId, actorId); assert.equal(proof.sessionId, sessionId); assert.equal(proof.rawRefreshEvidenceSha256, sha(rawBytes));
  assert.equal(proof.originalCookieJarSha256, sha(JSON.stringify(previousMaterial.cookies))); assert.equal(proof.cookieJarSha256, sha(JSON.stringify(proof.cookies)));
  for (const field of ['originalSessionPreserved', 'cookieAttributesFromActualSetCookie', 'csrfCookieUnchangedByActualRefresh']) assert.equal(proof[field], true);
  for (const field of ['originalFilesChanged', 'newLoginRequested']) assert.equal(proof[field], false);
  assert.deepEqual(proof.refreshPacket, rootPacket); const packet = proof.refreshPacket;
  assert.equal(packet.label, 'm10-browser-actual-same-sid-refresh'); assert.equal(packet.method, 'POST'); assert.equal(packet.path, '/auth/refresh'); assert.equal(packet.state, 'response_observed'); assert.equal(packet.status, 201);
  assert.equal(packet.actorId, actorId); assert.equal(packet.sessionId, sessionId); assert.equal(packet.responseData?.user?.id, actorId); assert(uuid(packet.key) && uuid(packet.requestId) && hex(packet.responseHash));
  assert.equal(packet.body, null); assert.equal(packet.bodyHash, sha('null')); assert(Number.isFinite(Date.parse(packet.startedAt)));
  const cookieValues = Object.fromEntries(packet.headers.Cookie.split('; ').map(value => { const at = value.indexOf('='); return [value.slice(0, at), value.slice(at + 1)]; }));
  for (const cookie of previousMaterial.cookies) assert.equal(cookieValues[cookie.name], cookie.value, 'ACTUAL_REFRESH_ORIGINAL_COOKIE_REQUIRED');
  const oldCsrf = previousMaterial.cookies.find(cookie => cookie.name === 'kongos_csrf'); assert.equal(packet.headers['X-CSRF-Token'], oldCsrf.value);
  assert(Array.isArray(proof.cookies) && proof.cookies.length === 3); assert(Array.isArray(packet.responseCookies) && packet.responseCookies.length === 2);
  const responses = new Map(packet.responseCookies.map(value => { const at = value.indexOf('='); return [value.slice(0, at), value]; })); assert.deepEqual([...responses.keys()].sort(), ['kongos_access', 'kongos_refresh']);
  for (const name of ['kongos_access', 'kongos_refresh', 'kongos_csrf']) {
    const previous = previousMaterial.cookies.find(cookie => cookie.name === name), matches = proof.cookies.filter(cookie => cookie.name === name); assert.equal(matches.length, 1); const cookie = matches[0];
    assert.equal(cookie.domain, previous.domain); assert.equal(cookie.path, previous.path); assert.equal(cookie.httpOnly, previous.httpOnly); assert.equal(cookie.secure, previous.secure); assert.equal(cookie.sameSite, previous.sameSite);
    if (name === 'kongos_csrf') { assert.deepEqual(cookie, previous); continue; }
    const header = responses.get(name), tokens = header.split(';').map(value => value.trim()), attributes = Object.fromEntries(tokens.slice(1).map(value => { const at = value.indexOf('='); return at < 0 ? [value.toLowerCase(), true] : [value.slice(0, at).toLowerCase(), value.slice(at + 1)]; }));
    assert.equal(cookie.value, decodeURIComponent(tokens[0].slice(name.length + 1))); assert.notEqual(cookie.value, previous.value); assert.equal(cookie.path, attributes.path); assert.equal(cookie.expires, Date.parse(attributes.expires) / 1000); assert.equal(cookie.httpOnly, attributes.httponly === true); assert.equal(cookie.sameSite.toLowerCase(), attributes.samesite.toLowerCase());
  }
  const access = proof.cookies.find(cookie => cookie.name === 'kongos_access').value, payload = JSON.parse(Buffer.from(access.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(payload.sub, actorId); assert.equal(payload.sid, sessionId); assert.equal(payload.iss, 'kongos-console'); assert.equal(payload.aud, 'kongos-api'); assert(proof.cookies.find(cookie => cookie.name === 'kongos_refresh').value.startsWith(`${sessionId}.`));
  const evidence = { evidenceName: 'm10-browser-continuation-refresh-browser.json', evidenceSha256: expectedSha256, rawEvidenceName: 'm10-browser-continuation-refresh.json', rawEvidenceSha256: proof.rawRefreshEvidenceSha256, previousMaterialSha256: proof.previousMaterialSha256,
    originalCookieJarSha256: proof.originalCookieJarSha256, cookieJarSha256: proof.cookieJarSha256, actorId, sessionId, requestId: packet.requestId, key: packet.key, responseHash: packet.responseHash, originalSessionPreserved: true, newLoginRequested: false };
  return { cookies: structuredClone(proof.cookies), evidence, proof, rawProof };
}
