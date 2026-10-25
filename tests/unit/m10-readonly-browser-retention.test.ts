// @ts-nocheck -- pure evidence validation with wholly synthetic closed cycles.
import { describe, expect, it } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { m10FinalBrowserEvidenceNames, validateM10FinalBrowserRetention } from '../security/lib/m10-auth-journal-coverage.mjs';
import { collectSecretMaterial } from '../security/lib/m9-secret-scan.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const bytes = value => Buffer.from(JSON.stringify(value));
const clone = value => structuredClone(value);
const fixture = () => {
  const actorId = randomUUID(), sessionId = randomUUID();
  const oldPacket = { method: 'POST', path: '/api/v1/auth/login', actorId, state: 'response_observed', status: 201,
    body: { username: 'synthetic', password: 'SyntheticRetainedOriginalPassword' },
    responseHeaders: [{ name: 'set-cookie', value: 'kongos_access=SyntheticOriginalIssuedAccess; Path=/api; HttpOnly' }] };
  const old = { milestone: 'M10', passed: false, requests: [oldPacket] };
  const oldReport = { passed: false, actualBackend: true, mocksUsed: false, nativeWritesPerformed: false, observedWrites: 1, unknownWrites: 0 };
  const original = { journalBytes: bytes(old), reportBytes: bytes(oldReport), materialBytes: null };
  const originalEvidence = { journalName: 'm10-browser-journal.json', journalSha256: hash(original.journalBytes), reportPath: 'artifacts/M10/browser/verification.json', reportSha256: hash(original.reportBytes),
    materialName: null, materialSha256: null, originalMaterialPresent: false, originalResponseHeadersRetained: true, originalResponseRewritten: false, originalRequestsReplayed: false };
  const freshPacket = { method: 'POST', path: '/api/v1/auth/login', actorId, state: 'response_observed', status: 201, sourceCycle: 'm10-browser-after-visible-select-fix',
    body: { username: 'synthetic', password: 'SyntheticRetainedCurrentPassword' }, responseHeaders: [{ name: 'Set-Cookie', value: 'kongos_access=SyntheticSecondIssuedAccess; Path=/api; HttpOnly' }] };
  const previous = { milestone: 'M10', actorId, passed: false, retainedOriginalEvidence: originalEvidence,
    requests: [{ ...clone(oldPacket), sourceCycle: 'm10-browser-original' }, freshPacket], sourceCycle: 'm10-browser-after-visible-select-fix' };
  const previousMaterial = { milestone: 'M10', retainedOriginalEvidence: clone(originalEvidence), retainedOriginalJournal: clone(old), retainedOriginalMaterial: null,
    issuedPackets: clone(previous.requests), responseCookies: [oldPacket.responseHeaders[0].value, freshPacket.responseHeaders[0].value],
    cookies: [{ name: 'kongos_access', value: 'SyntheticSecondIssuedAccess', domain: '127.0.0.1', path: '/api', expires: 1990000000 },
      { name: 'kongos_refresh', value: `${sessionId}.SyntheticActuallyRetainedRefresh`, domain: '127.0.0.1', path: '/api/v1/auth', expires: 1990000000 },
      { name: 'kongos_csrf', value: 'SyntheticActuallyRetainedCsrf', domain: '127.0.0.1', path: '/api', expires: 1990000000 }] };
  const previousReport = { passed: false, actualBackend: true, mocksUsed: false, nativeWritesPerformed: false, observedWrites: 2, currentCycleObservedWrites: 1, unknownWrites: 0,
    sourceCycle: 'm10-browser-after-visible-select-fix', retainedOriginalEvidence: clone(originalEvidence) };
  const freshIntent = { version: 1, prefix: 'm10-browser-after-visible-select-fix', actorId, freshAuthenticationOnly: true, originalRequestsReplayed: false, originalResponseRewritten: false };
  Object.assign(original, { previousJournalBytes: bytes(previous), previousMaterialBytes: bytes(previousMaterial), previousReportBytes: bytes(previousReport), freshIntentBytes: bytes(freshIntent) });
  const recheckEvidence = { journalName: 'm10-browser-after-visible-select-fix-journal.json', journalSha256: hash(original.previousJournalBytes),
    materialName: 'm10-browser-after-visible-select-fix-secret-material.json', materialSha256: hash(original.previousMaterialBytes),
    reportPath: 'artifacts/M10/browser-after-visible-select-fix/verification.json', reportSha256: hash(original.previousReportBytes),
    freshIntentName: 'm10-browser-fresh-intent.json', freshIntentSha256: hash(original.freshIntentBytes), cookieJarSha256: hash(JSON.stringify(previousMaterial.cookies)), actorId, sessionId,
    previousFailurePreserved: true, previousResponseRewritten: false, previousRequestsReplayed: false, newLoginRequested: false };
  const journal = { ...clone(previous), passed: true, sourceCycle: 'm10-browser-readonly-recheck', readOnlyRecheckEvidence: recheckEvidence,
    readOnlySessionVerification: { method: 'GET', path: '/api/v1/auth/me', status: 200, actorId, sessionId, requestId: randomUUID(), responseHash: hash('SyntheticAuthMeActualResponse'), verifiedAt: '2026-10-13T08:20:00.000Z' } };
  const material = { ...clone(previousMaterial), readOnlyRecheckEvidence: clone(recheckEvidence), retainedPreviousJournal: clone(previous), retainedPreviousMaterial: clone(previousMaterial) };
  const files = m10FinalBrowserEvidenceNames({ nativeVerified: true, finalJournalName: 'm10-browser-readonly-recheck-journal.json', finalMaterialName: 'm10-browser-readonly-recheck-secret-material.json' });
  return { files, journal, material, original };
};
const validate = value => validateM10FinalBrowserRetention(value.files, value.journal, value.material, value.original);

describe('fixed third readonly browser evidence cycle', () => {
  it('accepts the exact fixed third pair while preserving both failed cycles and issuing no new write', () => {
    const value = fixture(), before = JSON.stringify(value.journal.requests), proof = validate(value);
    expect(proof).toMatchObject({ readOnlyRecheck: true, originalPacketsUnchanged: true, originalResponseRewritten: false, originalRequestsReplayed: false,
      readOnlyRecheckEvidence: { previousFailurePreserved: true, previousResponseRewritten: false, previousRequestsReplayed: false, newLoginRequested: false,
        newWritePackets: 0, previousObservedAuthRequests: 2, actualPreviousCookiesRetained: true, previousPacketsUnchanged: true } });
    expect(JSON.stringify(value.journal.requests)).toBe(before); expect(proof.readOnlyRecheckEvidence.readOnlySessionVerification).toEqual(value.journal.readOnlySessionVerification);
  });
  it.each([
    ['m10-browser-readonly-recheck-journal.json', 'm10-browser-secret-material.json'],
    ['m10-browser-after-visible-select-fix-journal.json', 'm10-browser-readonly-recheck-secret-material.json'],
    ['../m10-browser-readonly-recheck-journal.json', 'm10-browser-readonly-recheck-secret-material.json'],
    ['m10-browser-readonly-other-journal.json', 'm10-browser-readonly-other-secret-material.json'],
  ])('rejects cross-cycle or arbitrary private names %s / %s', (finalJournalName, finalMaterialName) => {
    expect(() => m10FinalBrowserEvidenceNames({ nativeVerified: true, finalJournalName, finalMaterialName })).toThrow('M10_FINAL_BROWSER_EVIDENCE_PAIR_NOT_ALLOWED');
  });
  it('continues scanning all actually retained prior passwords/cookies instead of manufacturing a new issue', () => {
    const value = fixture(); validate(value);
    const collected = collectSecretMaterial({ requests: value.journal.requests }, {}, value.material).map(row => row.value);
    for (const expected of ['SyntheticRetainedOriginalPassword', 'SyntheticRetainedCurrentPassword', 'SyntheticOriginalIssuedAccess', 'SyntheticSecondIssuedAccess', 'SyntheticActuallyRetainedCsrf']) expect(collected).toContain(expected);
    expect(value.journal.requests).toHaveLength(2); expect(value.material.issuedPackets).toEqual(value.journal.requests);
  });
  it.each(['previousJournalBytes', 'previousMaterialBytes', 'previousReportBytes', 'freshIntentBytes'])('rejects changed exact prior %s bytes', field => {
    const value = fixture(); value.original[field] = Buffer.concat([value.original[field], Buffer.from('\n')]); expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_PREVIOUS_EVIDENCE_CHANGED');
  });
  it.each(['previousJournalBytes', 'previousMaterialBytes', 'previousReportBytes', 'freshIntentBytes'])('requires the actual prior %s bytes', field => {
    const value = fixture(); delete value.original[field]; expect(() => validate(value)).toThrow('M10_PREVIOUS_BROWSER_BYTES_REQUIRED');
  });
  it.each(['actorId', 'sessionId', 'cookieJarSha256', 'freshIntentSha256', 'journalSha256', 'materialSha256', 'reportSha256'])('rejects forged readonly origin %s', field => {
    const value = fixture(); value.journal.readOnlyRecheckEvidence[field] = randomUUID(); expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_PREVIOUS_EVIDENCE_CHANGED');
  });
  it.each(['previousFailurePreserved', 'previousResponseRewritten', 'previousRequestsReplayed', 'newLoginRequested'])('rejects a false historical/result claim in %s', field => {
    const value = fixture(); value.journal.readOnlyRecheckEvidence[field] = !value.journal.readOnlyRecheckEvidence[field]; expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_PREVIOUS_EVIDENCE_CHANGED');
  });
  it('rejects missing second journal/material or omission of a historical issued packet', () => {
    for (const field of ['retainedPreviousJournal', 'retainedPreviousMaterial']) { const value = fixture(); value.material[field] = {}; expect(() => validate(value)).toThrow(); }
    const dropped = fixture(); dropped.journal.requests.pop(); expect(() => validate(dropped)).toThrow();
  });
  it.each(['/api/v1/auth/login', '/api/v1/auth/refresh'])('rejects an additional %s write even if its response is observed', path => {
    const value = fixture(); value.journal.requests.push({ ...clone(value.journal.requests[1]), path }); value.material.issuedPackets = clone(value.journal.requests);
    expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_WRITE_ORIGINALS_CHANGED');
  });
  it('rejects relabelled or rewritten second-cycle packets', () => {
    const value = fixture(); value.journal.requests[1].body.password = 'SyntheticFakeReplacement'; value.material.issuedPackets = clone(value.journal.requests);
    expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_WRITE_ORIGINALS_CHANGED');
    const relabelled = fixture(); relabelled.journal.requests[1].sourceCycle = 'm10-browser-readonly-recheck'; expect(() => validate(relabelled)).toThrow('M10_BROWSER_SOURCE_CYCLE_MISMATCH');
  });
  it.each(['value', 'domain', 'path', 'expires'])('rejects a changed retained cookie %s', field => {
    const value = fixture(); value.material.cookies[0][field] = field === 'expires' ? 123 : 'changed'; expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_COOKIE_JAR_CHANGED');
  });
  it('accepts actual cookie ordering changes without changing any cookie object or value', () => {
    const value = fixture(); value.material.cookies.reverse(); expect(() => validate(value)).not.toThrow();
  });
  it.each(['method', 'path', 'status', 'actorId', 'sessionId', 'requestId', 'responseHash', 'verifiedAt'])('rejects an invalid actual readonly /auth/me %s fact', field => {
    const value = fixture(); value.journal.readOnlySessionVerification[field] = field === 'status' ? 201 : 'changed'; expect(() => validate(value)).toThrow();
  });
  it('rejects missing actual /auth/me evidence or invented token fields', () => {
    const value = fixture(); delete value.journal.readOnlySessionVerification; expect(() => validate(value)).toThrow('M10_READONLY_BROWSER_ACTUAL_SESSION_VERIFICATION_REQUIRED');
    const extra = fixture(); extra.journal.readOnlySessionVerification.accessToken = 'SyntheticNotIssued'; expect(() => validate(extra)).toThrow();
  });
  it('rejects rewritten previous report or a previous unknown response even when digests are recomputed', () => {
    const value = fixture(), report = JSON.parse(value.original.previousReportBytes); report.passed = true;
    value.original.previousReportBytes = bytes(report); value.journal.readOnlyRecheckEvidence.reportSha256 = hash(value.original.previousReportBytes); value.material.readOnlyRecheckEvidence = clone(value.journal.readOnlyRecheckEvidence);
    expect(() => validate(value)).toThrow();
    const unknown = fixture(), previous = JSON.parse(unknown.original.previousJournalBytes); previous.requests[1].state = 'response_unknown';
    unknown.original.previousJournalBytes = bytes(previous); expect(() => validate(unknown)).toThrow();
  });
  it('keeps the unchanged original cycle material absence branch, rather than creating a nonexistent old file', () => {
    const value = fixture(); value.material.retainedOriginalMaterial = { cookies: [] }; expect(() => validate(value)).toThrow('M10_ORIGINAL_BROWSER_MATERIAL_NOT_RETAINED');
  });
});
