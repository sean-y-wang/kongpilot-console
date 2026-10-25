import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { m10ControlIdentityCollectionShadow, m10SecretMaterial, m10TypedBrowserMetadataShadow } from './lib/m10-release-evidence.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
function fixture() {
  const key = randomUUID(), sourceKey = randomUUID(), targetKey = randomUUID(), label = 'm10-optin-key-auth-comparison';
  const harness = { milestone: 'M10', cid: randomUUID(), targetCid: randomUUID(), fixtureKeys: { source: sourceKey, target: targetKey },
    browserHandoff: { secretValues: [key] }, optin: { inputs: { [`${label}:identity`]: { key } } },
    requests: [{ label, key, headers: { 'X-Idempotency-Key': key }, state: 'response_observed', status: 201, requestId: randomUUID(), path: '/synthetic', method: 'POST', body: { password: 'SyntheticActualPassword' } }] };
  const browser = { milestone: 'M10', requests: [] }, browserMaterial = { cookies: [{ name: 'kongos_csrf', value: 'SyntheticActualCsrf' }] }, environment = { APP_SECRET: 'SyntheticActuallyRetainedEnvironmentSecret' };
  const proof = { milestone: 'M10', kind: 'secret-collector-control-identity-preflight', scannerFilesScanned: 0, scannerBytesScanned: 0, secretExclusionsApplied: false,
    originalMaterialsChanged: false, findingsDoNotProveZeroLeaks: true, collisions: [{ sha256: hash(key), fixtureKeyMatch: false, requestLabels: [label], handoffIndex: 0,
      harnessPaths: ['harness.requests[0].key', 'harness.requests[0].headers.X-Idempotency-Key', `harness.optin.inputs.${label}:identity.key`, 'harness.browserHandoff.secretValues[0]'], browserMaterialPaths: [] }] };
  const proofBytes = Buffer.from(JSON.stringify(proof));
  return { harness, browser, browserMaterial, environment, key, sourceKey, targetKey, normalization: { proofBytes, expectedSha256: hash(proofBytes) } };
}
const collect = value => m10SecretMaterial(value.harness, value.browser, value.environment, value.browserMaterial, undefined, value.normalization);
test('only proven exact control metadata normalizes; actual UUID API keys/passwords/CSRF/ENV remain scanned and originals remain unchanged', () => {
  const value = fixture(), before = JSON.stringify(value), result = collect(value), secrets = result.secrets.map(row => row.value);
  assert(!secrets.includes(value.key)); for (const actual of [value.sourceKey, value.targetKey, 'SyntheticActualPassword', 'SyntheticActualCsrf', 'SyntheticActuallyRetainedEnvironmentSecret']) assert(secrets.includes(actual));
  assert.equal(JSON.stringify(value), before); assert.equal(result.material.requests[0].key, value.key);
  assert.equal(result.controlIdentifierNormalization.genericUuidExclusion, false); assert.equal(result.controlIdentifierNormalization.credentialExclusionsAdded, false);
});
test('a true payload/fixture/ENV credential equal to an original control ID fails closed', () => {
  for (const alter of [value => { value.harness.requests[0].body.key = value.key; }, value => { value.harness.fixtureKeys.source = value.key; }, value => { value.environment.APP_SECRET = value.key; }]) {
    const value = fixture(); alter(value); assert.throws(() => collect(value));
  }
});
test('parsed Cookie/raw credential response collisions remain genuine credentials instead of being filtered by UUID', () => {
  const cookie = fixture(); cookie.browserMaterial.cookies[0].value = cookie.key; assert.throws(() => collect(cookie));
  const raw = fixture(); raw.harness.requests[0].path = '/consumers/synthetic/credentials/key-auth'; raw.harness.requests[0].rawResponseText = JSON.stringify({ key: raw.key });
  assert.throws(() => collect(raw), /M10_CONTROL_ID_IS_ACTUAL_CREDENTIAL_CANNOT_BE_EXCLUDED/);
  const changed = fixture(); changed.normalization.proofBytes = Buffer.concat([changed.normalization.proofBytes, Buffer.from('\n')]); assert.throws(() => collect(changed), /M10_CONTROL_ID_PROOF_BYTES_CHANGED/);
});
test('typed cookie metadata requires exact verified schema and preserves actual cookie-bearing payloads', () => {
  const cookies = [{ name: 'kongos_access', value: 'SyntheticActualAccess' }], cookieJarSha256 = hash(JSON.stringify(cookies));
  const fresh = { evidenceName: 'm10-browser-continuation-refresh-browser.json', evidenceSha256: 'a'.repeat(64), rawEvidenceName: 'm10-browser-continuation-refresh.json', rawEvidenceSha256: 'b'.repeat(64),
    previousMaterialSha256: 'c'.repeat(64), originalCookieJarSha256: 'd'.repeat(64), cookieJarSha256, actorId: randomUUID(), sessionId: randomUUID(), requestId: randomUUID(), key: randomUUID(), responseHash: 'f'.repeat(64), originalSessionPreserved: true, newLoginRequested: false };
  const readonly = { journalName: 'prior', journalSha256: '1'.repeat(64), materialName: 'prior-material', materialSha256: '2'.repeat(64), reportPath: 'prior-report', reportSha256: '3'.repeat(64), freshIntentName: 'prior-intent', freshIntentSha256: '4'.repeat(64), cookieJarSha256: 'd'.repeat(64), actorId: fresh.actorId, sessionId: fresh.sessionId, previousFailurePreserved: true, previousResponseRewritten: false, previousRequestsReplayed: false, newLoginRequested: false };
  const rawProof = { version: 1, kind: 'actual-same-session-refresh', actorId: fresh.actorId, sessionId: fresh.sessionId, previousMaterialSha256: fresh.previousMaterialSha256,
    originalCookieJarSha256: fresh.originalCookieJarSha256, cookieJarSha256, cookies,
    refreshPacket: { body: { password: 'SyntheticActualRawPassword' }, responseCookies: ['kongos_csrf=SyntheticActualRawCsrf'] },
    originalSessionPreserved: true, originalFilesChanged: false, newLoginRequested: false };
  const original = { freshCookieEvidence: fresh, readOnlyRecheckEvidence: readonly, retainedPreviousReadOnlyMaterial: { readOnlyRecheckEvidence: structuredClone(readonly) }, retainedPreviousReadOnlyJournal: { readOnlyRecheckEvidence: structuredClone(readonly) },
    continuationRefreshEvidence: { ...structuredClone(rawProof), rawRefreshEvidenceSha256: fresh.rawEvidenceSha256, cookieAttributesFromActualSetCookie: true, csrfCookieUnchangedByActualRefresh: true },
    rawContinuationRefreshEvidence: rawProof };
  const verified = { readOnlyRecheck: true, readOnlyRecheckEvidence: { ...readonly, freshCookieEvidence: fresh } }, shadow = structuredClone(original);
  m10TypedBrowserMetadataShadow(original, shadow, verified); assert.equal(shadow.freshCookieEvidence, undefined); assert.equal(shadow.readOnlyRecheckEvidence.cookieJarSha256, undefined);
  assert.deepEqual(shadow.continuationRefreshEvidence.cookies, original.continuationRefreshEvidence.cookies); assert.deepEqual(shadow.continuationRefreshEvidence.refreshPacket, original.continuationRefreshEvidence.refreshPacket);
  assert.deepEqual(shadow.rawContinuationRefreshEvidence.refreshPacket, original.rawContinuationRefreshEvidence.refreshPacket);
  const extra = structuredClone(original); extra.freshCookieEvidence.password = 'SyntheticUnexpectedActualSecret'; assert.throws(() => m10TypedBrowserMetadataShadow(extra, structuredClone(extra), verified), /M10_TYPED_BROWSER_METADATA_UNKNOWN_FIELD/);
  const journal = fixture(), packet = journal.harness.requests[0]; packet.label = 'm10-browser-actual-same-sid-refresh'; packet.path = '/auth/refresh';
  delete journal.harness.optin; journal.harness.browserContinuationRefresh = { requestId: packet.requestId, key: packet.key };
  journal.browserMaterial = structuredClone(original); journal.browserMaterial.freshCookieEvidence.key = packet.key; journal.browserMaterial.freshCookieEvidence.requestId = packet.requestId;
  journal.browserMaterial.continuationRefreshEvidence.refreshPacket = structuredClone(packet); journal.browserMaterial.rawContinuationRefreshEvidence.refreshPacket = structuredClone(packet);
  journal.browser.freshCookieEvidence = structuredClone(journal.browserMaterial.freshCookieEvidence);
  const proof = JSON.parse(journal.normalization.proofBytes); proof.collisions[0].requestLabels = [packet.label]; proof.collisions[0].harnessPaths = ['harness.requests[0].key', 'harness.requests[0].headers.X-Idempotency-Key', 'harness.browserHandoff.secretValues[0]', 'harness.browserContinuationRefresh.key'];
  proof.collisions[0].browserMaterialPaths = ['browserMaterial.freshCookieEvidence.key', 'browserMaterial.continuationRefreshEvidence.refreshPacket.key', 'browserMaterial.continuationRefreshEvidence.refreshPacket.headers.X-Idempotency-Key', 'browserMaterial.rawContinuationRefreshEvidence.refreshPacket.key', 'browserMaterial.rawContinuationRefreshEvidence.refreshPacket.headers.X-Idempotency-Key'];
  const proofBytes = Buffer.from(JSON.stringify(proof)), receipt = { readOnlyRecheck: true, readOnlyRecheckEvidence: { freshCookieEvidence: journal.browser.freshCookieEvidence } };
  const collectJournal = () => m10ControlIdentityCollectionShadow(journal.harness, journal.browser, journal.environment, journal.browserMaterial, undefined, proofBytes, hash(proofBytes), receipt);
  const before = JSON.stringify(journal); assert.equal(collectJournal().evidence.normalizedControlIdentifiers[0].journalMetadataReceipt.path, 'browser.freshCookieEvidence.key'); assert.equal(JSON.stringify(journal), before);
  journal.browser.body = { key: packet.key }; assert.throws(collectJournal, /M10_CONTROL_ID_ACTUAL_CREDENTIAL_OR_ENV_COLLISION/); delete journal.browser.body;
  journal.browser.freshCookieEvidence.requestId = randomUUID(); assert.throws(collectJournal, /M10_TYPED_BROWSER_METADATA_PROVENANCE_MISMATCH/);
});
