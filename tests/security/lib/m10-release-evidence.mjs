import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { collectSecretMaterial, excludeControlledRejectedDraftProbe } from './m9-secret-scan.mjs';

export const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export const M10_CONTROL_ID_PROOF_PATH = 'artifacts/M10/secret-control-id-classification-beforefix.json';
export const M10_CONTROL_ID_PROOF_SHA256 = '9b36c0016532a7d6410602620fda8e88efedb0335dedfdc858b658d957ab7379';

/** A collector-only clone normalizes the frozen exact control occurrences.
 * Actual payloads, issued credentials and original journals stay untouched.
 * Any additional credential/ENV/Cookie occurrence fails closed. */
export function m10ControlIdentityCollectionShadow(harness, browser, environment, browserMaterial, legacy, proofBytes, expectedSha256 = M10_CONTROL_ID_PROOF_SHA256, verifiedRetention) {
  const hash = value => createHash('sha256').update(value).digest('hex');
  assert(Buffer.isBuffer(proofBytes) || typeof proofBytes === 'string');
  const bytes = Buffer.from(proofBytes); assert.equal(hash(bytes), expectedSha256, 'M10_CONTROL_ID_PROOF_BYTES_CHANGED');
  const proof = JSON.parse(bytes.toString('utf8')); assert.equal(proof.milestone, 'M10'); assert.equal(proof.kind, 'secret-collector-control-identity-preflight');
  assert.equal(proof.scannerFilesScanned, 0); assert.equal(proof.scannerBytesScanned, 0); assert.equal(proof.findingsDoNotProveZeroLeaks, true);
  assert.equal(proof.secretExclusionsApplied, false); assert.equal(proof.originalMaterialsChanged, false);
  assert(Array.isArray(proof.collisions) && proof.collisions.length > 0 && proof.collisions.length <= 10);
  const shadowHarness = structuredClone(harness), shadowBrowserMaterial = structuredClone(browserMaterial), before = JSON.stringify({ harness, browser, environment, browserMaterial, legacy });
  const fixtureKeys = ['source', 'target'].flatMap(side => [harness.fixtureKeys?.[side], harness.fixtures?.[side]?.key]).filter(value => typeof value === 'string');
  const controls = new Set(), evidence = [];
  const occurrences = (source, root, value) => {
    const found = []; let nodes = 0;
    const visit = (item, path, parent, key) => {
      if (++nodes > 250000) throw Error('M10_CONTROL_ID_PROVENANCE_NODE_BUDGET');
      if (typeof item === 'string') { if (item === value) found.push({ path, parent, key }); return; }
      if (Array.isArray(item)) { item.forEach((child, index) => visit(child, `${path}[${index}]`, item, index)); return; }
      if (item && typeof item === 'object') for (const [name, child] of Object.entries(item)) visit(child, `${path}.${name}`, item, name);
    }; visit(source, root, null, null); return found;
  };
  for (const row of proof.collisions) {
    assert(typeof row.sha256 === 'string' && /^[a-f\d]{64}$/.test(row.sha256)); assert.equal(row.fixtureKeyMatch, false);
    const packets = harness.requests.filter(packet => typeof packet.key === 'string' && hash(packet.key) === row.sha256);
    assert.equal(packets.length, 1, 'M10_CONTROL_ID_EXACT_ORIGINAL_REQUEST_REQUIRED'); const packet = packets[0], value = packet.key;
    assert(UUID.test(value) && !controls.has(value)); assert.equal(packet.state, 'response_observed'); assert(typeof packet.status === 'number');
    assert.equal(packet.headers?.['X-Idempotency-Key'], value); assert.deepEqual(row.requestLabels, [packet.label]);
    assert(!fixtureKeys.includes(value), 'M10_CONTROL_ID_ACTUAL_FIXTURE_CREDENTIAL_COLLISION');
    const actualHarness = occurrences(shadowHarness, 'harness', value), actualBrowserMaterial = occurrences(shadowBrowserMaterial, 'browserMaterial', value);
    assert.deepEqual(actualHarness.map(item => item.path).sort(), [...row.harnessPaths].sort(), 'M10_CONTROL_ID_UNREVIEWED_HARNESS_OCCURRENCE');
    assert.deepEqual(actualBrowserMaterial.map(item => item.path).sort(), [...row.browserMaterialPaths].sort(), 'M10_CONTROL_ID_UNREVIEWED_BROWSER_OCCURRENCE');
    const other = occurrences({ browser, environment, legacy }, 'other', value);
    let journalMetadataReceipt;
    if (other.length && packet.label === 'm10-browser-actual-same-sid-refresh') {
      assert.equal(packet.method, 'POST'); assert.equal(packet.path, '/auth/refresh'); assert.equal(packet.status, 201);
      assert.deepEqual(other.map(item => item.path), ['other.browser.freshCookieEvidence.key'], 'M10_CONTROL_ID_ACTUAL_CREDENTIAL_OR_ENV_COLLISION');
      const fresh = verifiedRetention?.readOnlyRecheckEvidence?.freshCookieEvidence;
      assert.equal(verifiedRetention?.readOnlyRecheck, true, 'M10_VERIFIED_BROWSER_METADATA_REQUIRED');
      const fields = ['evidenceName', 'evidenceSha256', 'rawEvidenceName', 'rawEvidenceSha256', 'previousMaterialSha256', 'originalCookieJarSha256', 'cookieJarSha256', 'actorId', 'sessionId', 'requestId', 'key', 'responseHash', 'originalSessionPreserved', 'newLoginRequested'];
      assert.deepEqual(Object.keys(browser.freshCookieEvidence).sort(), fields.sort(), 'M10_TYPED_BROWSER_METADATA_UNKNOWN_FIELD');
      assert.deepEqual(browser.freshCookieEvidence, fresh, 'M10_TYPED_BROWSER_METADATA_PROVENANCE_MISMATCH');
      assert.deepEqual(browserMaterial.freshCookieEvidence, fresh, 'M10_TYPED_BROWSER_METADATA_PROVENANCE_MISMATCH');
      assert.equal(fresh.key, value); assert.equal(fresh.requestId, packet.requestId);
      assert.deepEqual(browserMaterial.continuationRefreshEvidence.refreshPacket, packet, 'M10_EXACT_ROOT_REFRESH_PACKET_REQUIRED');
      journalMetadataReceipt = { path: 'browser.freshCookieEvidence.key', exactTypedProvenanceVerified: true, originalRequestId: packet.requestId };
    } else assert.equal(other.length, 0, 'M10_CONTROL_ID_ACTUAL_CREDENTIAL_OR_ENV_COLLISION');
    const packetIndex = harness.requests.indexOf(packet), requestPrefix = `harness.requests[${packetIndex}]`;
    const allowed = new Set([`${requestPrefix}.key`, `${requestPrefix}.headers.X-Idempotency-Key`, `${requestPrefix}.responseData.idempotencyKey`,
      `harness.acceptanceInputs.${packet.label}:key`, `harness.optin.inputs.${packet.label}:identity.key`]);
    if (row.handoffIndex >= 0) { assert(Number.isInteger(row.handoffIndex)); allowed.add(`harness.browserHandoff.secretValues[${row.handoffIndex}]`); }
    else assert.equal(row.handoffIndex, -1);
    if (packet.label === 'm10-optin-key-auth-plan') allowed.add('harness.freshKeyAuthIntent.originalKey');
    if (packet.label === 'm10-optin-key-auth-after-adapter-label-fix-apply') allowed.add('harness.optin.handoffs.keyAuth.executed.proof.idempotencyKey');
    if (packet.label === 'm10-browser-actual-same-sid-refresh') {
      assert.equal(harness.browserContinuationRefresh.requestId, packet.requestId); assert.equal(harness.browserContinuationRefresh.key, value);
      allowed.add('harness.browserContinuationRefresh.key');
      for (const path of ['browserMaterial.freshCookieEvidence.key', 'browserMaterial.continuationRefreshEvidence.refreshPacket.key', 'browserMaterial.continuationRefreshEvidence.refreshPacket.headers.X-Idempotency-Key', 'browserMaterial.rawContinuationRefreshEvidence.refreshPacket.key', 'browserMaterial.rawContinuationRefreshEvidence.refreshPacket.headers.X-Idempotency-Key']) allowed.add(path);
    }
    for (const item of [...actualHarness, ...actualBrowserMaterial]) {
      assert(allowed.has(item.path), 'M10_CONTROL_ID_CREDENTIAL_LEAF_CANNOT_BE_NORMALIZED');
      if (Array.isArray(item.parent)) item.parent[item.key] = null; else delete item.parent[item.key];
    }
    controls.add(value); evidence.push({ sha256: row.sha256, originalRequestIndex: packetIndex, requestId: packet.requestId, requestLabel: packet.label,
      exactMetadataOccurrences: actualHarness.length + actualBrowserMaterial.length, handoffIndex: row.handoffIndex,
      credentialLeafOccurrencesNormalized: 0, issuedFixtureCredentialMatch: false, originalPacketsChanged: false,
      ...(journalMetadataReceipt ? { journalMetadataReceipt } : {}) });
  }
  assert.equal(JSON.stringify({ harness, browser, environment, browserMaterial, legacy }), before, 'M10_ORIGINAL_SCAN_MATERIAL_CHANGED');
  return { harness: shadowHarness, browserMaterial: shadowBrowserMaterial, controls,
    evidence: { proofPath: M10_CONTROL_ID_PROOF_PATH, proofSha256: hash(bytes), normalizedControlIdentifiers: evidence,
      collectorShadowOnly: true, originalMaterialsChanged: false, actualCredentialLeavesPreserved: true,
      genericUuidExclusion: false, failedPasswordExclusion: false, credentialExclusionsAdded: false } };
}

/** The completed browser verifier establishes these fixed provenance DTOs.
 * The frozen M9 collector treats names containing cookie as secret context;
 * only this exact validated metadata is omitted from its private shadow. */
export function m10TypedBrowserMetadataShadow(original, shadow, verifiedRetention) {
  assert(verifiedRetention?.readOnlyRecheck === true && verifiedRetention.readOnlyRecheckEvidence, 'M10_VERIFIED_BROWSER_METADATA_REQUIRED');
  const values = new Set(), evidence = [];
  const at = (root, path) => path.reduce((value, key) => value?.[key], root);
  const record = (path, fields, expected) => {
    const source = at(original, path), target = at(shadow, path); assert(source && target, 'M10_TYPED_BROWSER_METADATA_SOURCE_REQUIRED');
    assert.deepEqual(Object.keys(source).sort(), [...fields].sort(), 'M10_TYPED_BROWSER_METADATA_UNKNOWN_FIELD');
    assert.deepEqual(source, expected, 'M10_TYPED_BROWSER_METADATA_PROVENANCE_MISMATCH');
    for (const value of Object.values(source)) if (typeof value === 'string') values.add(value);
    delete at(shadow, path.slice(0, -1))[path.at(-1)]; evidence.push({ path: `browserMaterial.${path.join('.')}`, fields: fields.length, validatedProvenance: true });
  };
  const freshFields = ['evidenceName', 'evidenceSha256', 'rawEvidenceName', 'rawEvidenceSha256', 'previousMaterialSha256', 'originalCookieJarSha256', 'cookieJarSha256', 'actorId', 'sessionId', 'requestId', 'key', 'responseHash', 'originalSessionPreserved', 'newLoginRequested'];
  const fresh = verifiedRetention.readOnlyRecheckEvidence.freshCookieEvidence;
  assert(fresh, 'M10_VERIFIED_BROWSER_FRESH_COOKIE_METADATA_REQUIRED');
  record(['freshCookieEvidence'], freshFields, fresh);
  const readonlyFields = ['journalName', 'journalSha256', 'materialName', 'materialSha256', 'reportPath', 'reportSha256', 'freshIntentName', 'freshIntentSha256', 'cookieJarSha256', 'actorId', 'sessionId', 'previousFailurePreserved', 'previousResponseRewritten', 'previousRequestsReplayed', 'newLoginRequested'];
  const readonly = Object.fromEntries(readonlyFields.map(key => [key, verifiedRetention.readOnlyRecheckEvidence[key]]));
  for (const path of [['readOnlyRecheckEvidence'], ['retainedPreviousReadOnlyMaterial', 'readOnlyRecheckEvidence'], ['retainedPreviousReadOnlyJournal', 'readOnlyRecheckEvidence']]) {
    const source = at(original, path), target = at(shadow, path); assert(source && target); assert.deepEqual(Object.keys(source).sort(), [...readonlyFields].sort()); assert.deepEqual(source, readonly);
    values.add(source.cookieJarSha256); delete target.cookieJarSha256; evidence.push({ path: `browserMaterial.${path.join('.')}.cookieJarSha256`, fields: 1, validatedProvenance: true });
  }
  const proof = original.continuationRefreshEvidence;
  assert(proof && fresh.evidenceName === 'm10-browser-continuation-refresh-browser.json');
  const rawFields = ['version', 'kind', 'actorId', 'sessionId', 'previousMaterialSha256', 'originalCookieJarSha256', 'cookieJarSha256', 'cookies', 'refreshPacket', 'originalSessionPreserved', 'originalFilesChanged', 'newLoginRequested'];
  assert.deepEqual(Object.keys(proof).sort(), [...rawFields, 'rawRefreshEvidenceSha256', 'cookieAttributesFromActualSetCookie', 'csrfCookieUnchangedByActualRefresh'].sort(), 'M10_TYPED_REFRESH_PROOF_UNKNOWN_FIELD');
  for (const key of ['originalCookieJarSha256', 'cookieJarSha256']) {
    assert.equal(proof[key], fresh[key]); values.add(proof[key]); delete shadow.continuationRefreshEvidence[key];
    evidence.push({ path: `browserMaterial.continuationRefreshEvidence.${key}`, fields: 1, validatedProvenance: true });
  }
  // Raw proof hash fields are projected separately from its genuine cookies,
  // CSRF and actual Root refresh packet; their schema is fixed by its writer.
  const raw = original.rawContinuationRefreshEvidence, rawShadow = shadow.rawContinuationRefreshEvidence;
  assert(raw && rawShadow);
  assert.deepEqual(Object.keys(raw).sort(), [...rawFields].sort(), 'M10_TYPED_RAW_REFRESH_PROOF_UNKNOWN_FIELD');
  for (const key of ['version', 'kind', 'actorId', 'sessionId', 'previousMaterialSha256', 'originalCookieJarSha256', 'originalSessionPreserved', 'originalFilesChanged', 'newLoginRequested']) assert.deepEqual(raw[key], proof[key], 'M10_TYPED_RAW_REFRESH_PROVENANCE_MISMATCH');
  assert.equal(raw.cookieJarSha256, createHash('sha256').update(JSON.stringify(raw.cookies)).digest('hex'), 'M10_RAW_BROWSER_COOKIE_HASH_REQUIRED');
  for (const key of ['originalCookieJarSha256', 'cookieJarSha256']) {
    values.add(raw[key]); delete rawShadow[key]; evidence.push({ path: `browserMaterial.rawContinuationRefreshEvidence.${key}`, fields: 1, validatedProvenance: true });
  }
  return { values, evidence: { records: evidence, typedProvenanceOnly: true, actualCookiePayloadsPreserved: true, unknownFieldsExcluded: false } };
}
export function m10DockerEnvironment(source = process.env) {
  const environment = { ...source, GOMAXPROCS: '2' };
  for (const name of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete environment[name];
  return environment;
}
export function m10ClusterIds(harness) {
  assert.equal(harness.milestone, 'M10');
  assert(UUID.test(harness.cid ?? '') && UUID.test(harness.targetCid ?? ''));
  assert.notEqual(harness.cid, harness.targetCid);
  return [harness.cid, harness.targetCid];
}

/** Both fixture layouts are supported explicitly. No failed password or other
 * rejected request field is discarded while assembling M10 secret material. */
export function m10SecretMaterial(harness, browser, environment, browserMaterial, legacy, normalization) {
  m10ClusterIds(harness); assert(Array.isArray(harness.requests) && Array.isArray(browser.requests));
  const explicitKeys = [...new Set(['source', 'target'].flatMap(side => [harness.fixtureKeys?.[side], harness.fixtures?.[side]?.key]).filter(value => typeof value === 'string'))];
  assert(explicitKeys.length >= 2, 'INDEPENDENT_ACTUAL_FIXTURE_KEYS_REQUIRED');
  const material = { ...harness, requests: [...harness.requests, ...browser.requests, ...(legacy?.material.requests ?? [])],
    ...(legacy ? { retainedLegacy: { ...legacy.material, requests: undefined } } : {}),
    credentials: explicitKeys.map(key => ({ key })) };
  const shadow = normalization ? m10ControlIdentityCollectionShadow(harness, browser, environment, browserMaterial, legacy, normalization.proofBytes, normalization.expectedSha256, normalization.verifiedBrowserRetention) : null;
  const typedMetadata = shadow && normalization.verifiedBrowserRetention ? m10TypedBrowserMetadataShadow(browserMaterial, shadow.browserMaterial, normalization.verifiedBrowserRetention) : null;
  const collectionHarness = shadow?.harness ?? harness, collectionMaterial = shadow ? { ...material, ...collectionHarness,
    requests: [...collectionHarness.requests, ...browser.requests, ...(legacy?.material.requests ?? [])], credentials: material.credentials,
    ...(legacy ? { retainedLegacy: material.retainedLegacy } : {}) } : material;
  const secretValues = [...explicitKeys, ...(collectionHarness.browserHandoff?.secretValues ?? [])].filter(value => typeof value === 'string');
  const secrets = collectSecretMaterial(collectionMaterial, environment, { currentBrowser: shadow?.browserMaterial ?? browserMaterial,
    retainedLegacyBrowser: legacy?.browserMaterial, secretMaterial: secretValues });
  if (shadow) assert(secrets.every(row => !shadow.controls.has(row.value)), 'M10_CONTROL_ID_IS_ACTUAL_CREDENTIAL_CANNOT_BE_EXCLUDED');
  if (typedMetadata) assert(secrets.every(row => !typedMetadata.values.has(row.value)), 'M10_TYPED_METADATA_IS_ACTUAL_CREDENTIAL_CANNOT_BE_EXCLUDED');
  assert(explicitKeys.every(value => secrets.some(row => row.value === value && row.kinds.includes('api-key'))));
  return { material, secrets, explicitFixtureKeyCount: explicitKeys.length,
    ...(shadow ? { controlIdentifierNormalization: { ...shadow.evidence, ...(typedMetadata ? { typedBrowserMetadataProjection: typedMetadata.evidence } : {}) } } : {}) };
}

/** The previous accepted M9 provenance is the authority for its one exact
 * public rejection probe. Its retained bytes and AST are checked again against
 * all current issued materials. No fixed M9 request ID or generic exclusion. */
export function retainedM9ScanMaterial(harness, browser, browserMaterial, acceptedReport, sourceText, environment, currentMaterial) {
  assert.equal(harness.milestone, 'M9'); assert.equal(acceptedReport.milestone, 'M9'); assert.equal(acceptedReport.passed, true);
  const originals = acceptedReport.excludedNonCredentialProbes ?? [];
  assert.equal(originals.length, 1);
  const evidence = originals[0];
  assert.equal(evidence.kind, 'controlled-public-noncredential-draft-rejection-probe');
  assert.equal(evidence.sourceLiteralLinked, true); assert.equal(evidence.issuedFixtureCredentialMatch, false);
  assert.equal(evidence.originalPacketsChanged, false); assert.equal(evidence.genericFailedPasswordExclusion, false);
  const packet = harness.requests[evidence.index]; assert(packet && packet.requestId === evidence.requestId);
  const result = excludeControlledRejectedDraftProbe({ ...harness, requests: [...harness.requests, ...browser.requests] },
    environment, { previous: browserMaterial, current: currentMaterial }, sourceText, {
      index: evidence.index, requestId: evidence.requestId, actorId: packet.actorId,
      path: packet.path, method: packet.method, startedAt: packet.startedAt,
      sourcePath: evidence.sourcePath, sourceByteOffset: evidence.sourceByteOffset,
    });
  assert.equal(result.evidence.sourceSha256, evidence.sourceSha256);
  return { material: result.material, browserMaterial, evidence: result.evidence };
}
