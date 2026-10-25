// @ts-nocheck -- pure ESM acceptance helpers; synthetic evidence only.
import { describe, expect, it } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { M10_AUTH_JOURNAL_EVIDENCE_PATH, M10_AUTH_JOURNAL_EVIDENCE_SHA256, m10FinalBrowserEvidenceNames, validateM10AuthJournalCoverage, validateM10FinalBrowserRetention } from '../security/lib/m10-auth-journal-coverage.mjs';
import { collectSecretMaterial } from '../security/lib/m9-secret-scan.mjs';
import { assertM10RequestAuditIdentity, classifyM10AuditRequest, m10MinimalAuditManifest, m10NotificationPreferenceScope } from '../security/lib/m10-audit-policy.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value));
const evidence = () => ({ milestone: 'M10', issue: 'test-operator-auth-only-journal-overlap', productionDeployment: false,
  originalHttpSuccessObserved: true, originalHttpStatus: 201, originalJournalPacketReconstructed: false,
  overwrittenIssuedTokenMaterialAvailable: false, businessWriteJournalPreserved: true, kongNativeReplay: false,
  actualAudit: { id: randomUUID(), actor_id: randomUUID(), entity_id: randomUUID(), action: 'refresh', result: 'success', request_id: randomUUID(), occurred_at: '2026-10-13T06:53:46.557Z' },
  consoleReadOnly: true, auditPreserved: true, oldSessionRevoked: true, newActualSessionActive: true, nativeMutationCount: 0,
  scopeLimit: 'One auth refresh receipt was overwritten in the private test ledger by parallel operator saves; application audit remains intact. Byte scanning covers retained actual material only.' });
const validateSynthetic = value => { const bytes = encode(value); return validateM10AuthJournalCoverage(bytes, digest(bytes)); };

describe('Root-selected successful browser evidence filenames', () => {
  it('supports only the exact original or visible-selector-fix pair', () => {
    expect(m10FinalBrowserEvidenceNames({ nativeVerified: true })).toEqual({ journalName: 'm10-browser-journal.json', materialName: 'm10-browser-secret-material.json', freshCycle: false });
    expect(m10FinalBrowserEvidenceNames({ nativeVerified: true, finalJournalName: 'm10-browser-after-visible-select-fix-journal.json', finalMaterialName: 'm10-browser-after-visible-select-fix-secret-material.json' })).toMatchObject({ freshCycle: true });
  });
  it.each([
    { finalJournalName: 'm10-browser-after-visible-select-fix-journal.json' },
    { finalMaterialName: 'm10-browser-after-visible-select-fix-secret-material.json' },
    { finalJournalName: 'm10-browser-journal.json', finalMaterialName: 'm10-browser-after-visible-select-fix-secret-material.json' },
    { finalJournalName: '../outside.json', finalMaterialName: 'm10-browser-secret-material.json' },
    { finalJournalName: 'm10-browser-other-journal.json', finalMaterialName: 'm10-browser-other-secret-material.json' },
  ])('rejects incomplete, cross-cycle or arbitrary private path selection %#', selection => {
    expect(() => m10FinalBrowserEvidenceNames({ nativeVerified: true, ...selection })).toThrow('M10_FINAL_BROWSER_EVIDENCE_PAIR_NOT_ALLOWED');
  });
  it('rejects a missing or unverified native handoff', () => {
    expect(() => m10FinalBrowserEvidenceNames(null)).toThrow('VERIFIED_M10_NATIVE_HANDOFF_REQUIRED');
    expect(() => m10FinalBrowserEvidenceNames({ nativeVerified: false })).toThrow('VERIFIED_M10_NATIVE_HANDOFF_REQUIRED');
  });
});

const freshBrowser = (present = false) => {
  const oldPacket = { method: 'POST', path: '/api/v1/auth/login', state: 'response_observed', status: 201,
    body: { username: 'synthetic', password: 'SyntheticRetainedPassword2026' }, responseHeaders: [{ name: 'set-cookie', value: 'kongpilot_access=SyntheticOldToken2026; HttpOnly; Path=/' }] };
  const old = { milestone: 'M10', passed: false, requests: [oldPacket] }, report = { passed: false, actualBackend: true, mocksUsed: false, nativeWritesPerformed: false, observedWrites: 1, unknownWrites: 0 };
  const oldMaterial = present ? { milestone: 'M10', cookies: [{ name: 'kongpilot_access', value: 'SyntheticPriorCookie2026' }] } : null;
  const original = { journalBytes: encode(old), reportBytes: encode(report), materialBytes: present ? encode(oldMaterial) : null };
  const metadata = { journalName: 'm10-browser-journal.json', journalSha256: digest(original.journalBytes), reportPath: 'artifacts/M10/browser/verification.json', reportSha256: digest(original.reportBytes),
    materialName: present ? 'm10-browser-secret-material.json' : null, materialSha256: present ? digest(original.materialBytes) : null, originalMaterialPresent: present,
    originalResponseHeadersRetained: true, originalResponseRewritten: false, originalRequestsReplayed: false };
  const journal = { milestone: 'M10', passed: true, retainedOriginalEvidence: metadata, requests: [{ ...oldPacket, sourceCycle: 'm10-browser-original' },
    { method: 'POST', path: '/api/v1/auth/login', state: 'response_observed', status: 201, sourceCycle: 'm10-browser-after-visible-select-fix', responseHeaders: [{ name: 'Set-Cookie', value: 'kongpilot_access=SyntheticNewToken2026; HttpOnly; Path=/' }] }] };
  const material = { milestone: 'M10', retainedOriginalEvidence: structuredClone(metadata), retainedOriginalJournal: structuredClone(old), retainedOriginalMaterial: oldMaterial,
    issuedPackets: structuredClone(journal.requests), responseCookies: ['kongpilot_access=SyntheticOldToken2026; HttpOnly; Path=/', 'kongpilot_access=SyntheticNewToken2026; HttpOnly; Path=/'], cookies: [{ name: 'kongpilot_access', value: 'SyntheticNewToken2026' }] };
  return { files: { journalName: 'm10-browser-after-visible-select-fix-journal.json', materialName: 'm10-browser-after-visible-select-fix-secret-material.json', freshCycle: true }, journal, material, original };
};
const validateBrowser = fixture => validateM10FinalBrowserRetention(fixture.files, fixture.journal, fixture.material, fixture.original);
describe('completed fresh browser original evidence and token retention', () => {
  it.each([false, true])('retains actual old packets and the real existing/absent material branch (present=%s)', present => {
    const fixture = freshBrowser(present); expect(validateBrowser(fixture)).toMatchObject({ retainedOriginalBrowserCycle: true, originalPacketsUnchanged: true, originalMaterialPresent: present, originalResponseRewritten: false, originalRequestsReplayed: false });
    const values = collectSecretMaterial({ requests: fixture.journal.requests }, {}, fixture.material).map(row => row.value);
    expect(values).toContain('SyntheticOldToken2026'); expect(values).toContain('SyntheticNewToken2026');
    if (present) expect(values).toContain('SyntheticPriorCookie2026');
  });
  it.each(['journalBytes', 'reportBytes'])('rejects changed original %s rather than overwriting its previous fact', field => {
    const fixture = freshBrowser(); fixture.original[field] = Buffer.concat([fixture.original[field], Buffer.from('\n')]); expect(() => validateBrowser(fixture)).toThrow('M10_ORIGINAL_BROWSER_EVIDENCE_CHANGED');
  });
  it('rejects changed existing old material bytes and invented material for the absent branch', () => {
    const fixture = freshBrowser(true); fixture.original.materialBytes = encode({ milestone: 'M10', cookies: [] }); expect(() => validateBrowser(fixture)).toThrow('M10_ORIGINAL_BROWSER_EVIDENCE_CHANGED');
    const missing = freshBrowser(false); missing.material.retainedOriginalMaterial = { cookies: [] }; expect(() => validateBrowser(missing)).toThrow('M10_ORIGINAL_BROWSER_MATERIAL_NOT_RETAINED');
  });
  it('rejects omission or modification of an original successful auth packet', () => {
    const fixture = freshBrowser(); fixture.journal.requests.shift(); expect(() => validateBrowser(fixture)).toThrow();
    const changed = freshBrowser(); changed.journal.requests[0].status = 200; expect(() => validateBrowser(changed)).toThrow('M10_ORIGINAL_BROWSER_PACKET_CHANGED');
  });
  it('rejects an unknown new response, an application write or a mislabelled cycle', () => {
    for (const mutation of [packet => { packet.state = 'response_unknown'; }, packet => { packet.path = '/api/v1/clusters/synthetic/entities/services'; }, packet => { packet.sourceCycle = 'other'; }]) {
      const fixture = freshBrowser(); mutation(fixture.journal.requests[1]); expect(() => validateBrowser(fixture)).toThrow();
    }
  });
  it.each(['retainedOriginalJournal', 'issuedPackets', 'responseCookies'])('rejects dropped actual %s material', field => {
    const fixture = freshBrowser(); fixture.material[field] = field === 'retainedOriginalJournal' ? {} : []; expect(() => validateBrowser(fixture)).toThrow();
  });
  it('rejects a fake additional response cookie or rewritten original outcome claim', () => {
    const fixture = freshBrowser(); fixture.material.responseCookies.push('kongpilot_access=SyntheticInventedNeverIssued; Path=/'); expect(() => validateBrowser(fixture)).toThrow('M10_BROWSER_RESPONSE_COOKIES_NOT_RETAINED');
    const altered = freshBrowser(); altered.journal.retainedOriginalEvidence.originalResponseRewritten = true; expect(() => validateBrowser(altered)).toThrow('M10_ORIGINAL_BROWSER_EVIDENCE_CHANGED');
  });
  it('does not accept a failed final cycle', () => {
    const fixture = freshBrowser(); fixture.journal.passed = false; expect(() => validateBrowser(fixture)).toThrow('ACTUAL_FINAL_M10_BROWSER_REQUIRED');
  });
});

describe('frozen auth-only journal coverage evidence', () => {
  it('records unavailable historical token material without reconstructing a packet or weakening retained byte coverage', () => {
    const source = evidence(), bytes = encode(source), before = bytes.toString(), proof = validateM10AuthJournalCoverage(bytes, digest(bytes));
    expect(bytes.toString()).toBe(before); expect(proof).toMatchObject({ validated: true, evidencePath: M10_AUTH_JOURNAL_EVIDENCE_PATH,
      evidenceSha256: digest(bytes), originalJournalPacketReconstructed: false, overwrittenIssuedTokenMaterialAvailable: false,
      businessWriteJournalPreserved: true, applicationAuditPreserved: true, oldSessionRevoked: true, newActualSessionActive: true,
      nativeMutationCount: 0, kongNativeReplay: false, secretByteScanCoversRetainedActualMaterialOnly: true, allHistoricalIssuedTokenMaterialScanned: false });
    expect(proof.actualAudit).toEqual(source.actualAudit); expect(proof).not.toHaveProperty('issuedToken');
    expect(M10_AUTH_JOURNAL_EVIDENCE_SHA256).toMatch(/^[a-f\d]{64}$/);
  });
  it('rejects changed bytes even when semantic content and the safe projection would otherwise match', () => {
    const bytes = encode(evidence()); expect(() => validateM10AuthJournalCoverage(Buffer.concat([bytes, Buffer.from('\n')]), digest(bytes))).toThrow('M10_AUTH_JOURNAL_EVIDENCE_CHANGED');
  });
  it('cannot replace the pinned original artifact with a different valid synthetic record', () => {
    expect(() => validateM10AuthJournalCoverage(encode(evidence()))).toThrow('M10_AUTH_JOURNAL_EVIDENCE_CHANGED');
  });
  it.each(['originalHttpSuccessObserved', 'businessWriteJournalPreserved', 'consoleReadOnly', 'auditPreserved', 'oldSessionRevoked', 'newActualSessionActive'])('rejects missing or false %s even under a matching synthetic byte digest', field => {
    const value = evidence(); delete value[field]; expect(() => validateSynthetic(value)).toThrow(); value[field] = false; expect(() => validateSynthetic(value)).toThrow();
  });
  it.each(['productionDeployment', 'originalJournalPacketReconstructed', 'overwrittenIssuedTokenMaterialAvailable', 'kongNativeReplay'])('rejects a false coverage claim in %s', field => {
    const value = evidence(); value[field] = true; expect(() => validateSynthetic(value)).toThrow();
  });
  it.each(['milestone', 'issue', 'scopeLimit', 'originalHttpStatus', 'nativeMutationCount'])('rejects a changed fixed %s fact', field => {
    const value = evidence(); value[field] = typeof value[field] === 'number' ? value[field] + 1 : 'changed'; expect(() => validateSynthetic(value)).toThrow();
  });
  it.each(['id', 'actor_id', 'entity_id', 'request_id', 'occurred_at', 'action', 'result'])('rejects malformed actual audit %s rather than passing it through', field => {
    const value = evidence(); value.actualAudit[field] = 'malformed'; expect(() => validateSynthetic(value)).toThrow();
  });
  it('rejects injected extra token fields before constructing a public report', () => {
    const value = evidence(); value.actualAudit.issuedToken = 'SyntheticNeverIssued'; expect(() => validateSynthetic(value)).toThrow();
    delete value.actualAudit.issuedToken; value.reconstructedPacket = { synthetic: true }; expect(() => validateSynthetic(value)).toThrow();
  });
  it('rejects invalid JSON, nonbytes, missing digest and oversized evidence without consuming other material', () => {
    expect(() => validateM10AuthJournalCoverage(null)).toThrow(); expect(() => validateM10AuthJournalCoverage(Buffer.alloc(17000))).toThrow();
    const bytes = Buffer.from('not-json'); expect(() => validateM10AuthJournalCoverage(bytes, digest(bytes))).toThrow('M10_AUTH_JOURNAL_EVIDENCE_INVALID');
    expect(() => validateM10AuthJournalCoverage(bytes, '')).toThrow('M10_AUTH_JOURNAL_EXPECTED_DIGEST_REQUIRED');
  });
});

const preferencePacket = () => {
  const actorId = randomUUID(), clusterId = randomUUID(), workspaceId = randomUUID(), id = randomUUID();
  return { method: 'POST', path: '/api/v1/notifications/preferences', actorId, sessionId: randomUUID(), requestId: randomUUID(),
    state: 'response_observed', status: 201, startedAt: '2026-10-13T07:00:00.000Z', key: 'synthetic-preference-intent',
    body: { clusterId, workspaceId, name: 'Synthetic only', eventTypes: ['config.drift'], inAppEnabled: true },
    responseData: { entity: { id, userId: actorId, clusterId, workspaceId, name: 'Synthetic only' } } };
};
const manifestFor = packet => m10MinimalAuditManifest({ milestone: 'M10', cid: packet.body.clusterId, targetCid: randomUUID(), requests: [packet] }, { milestone: 'M10', requests: [] }, '2026-10-13T06:00:00.000Z');
const rowFor = (request, packet) => ({ request_id: request.requestId, actor_id: request.actorId, actor_type: 'user', source_ip: '127.0.0.1',
  occurred_at: '2026-10-13T07:00:00.001Z', cluster_id: request.clusterId, workspace_id: request.workspaceId,
  entity_type: 'user_notification_subscriptions', entity_id: null, action: 'notifications.personal.preferences.save', result: 'success', before: null, after: packet.responseData.entity });

describe('fixed personal preference POST audit tenant scope', () => {
  it('classifies only the exact collection POST with the actual fixed business action', () => {
    const packet = preferencePacket(); expect(classifyM10AuditRequest(packet)).toEqual(['notification.preference.create', ['notifications.personal.preferences.save']]);
    for (const candidate of [{ ...packet, method: 'PATCH' }, { ...packet, method: 'DELETE' }, { ...packet, path: '/notifications/preferences/other' }, { ...packet, path: '/notifications/batch-read' }]) expect(() => classifyM10AuditRequest(candidate)).toThrow('M10_BUSINESS_REQUEST_NOT_CLASSIFIED');
  });
  it('derives exact body/result scope and checks it against the actual created audit entity', () => {
    const packet = preferencePacket(), manifest = manifestFor(packet), request = manifest.requests[0];
    expect(request).toMatchObject({ category: 'notification.preference.create', clusterId: packet.body.clusterId, workspaceId: packet.body.workspaceId, entityId: packet.responseData.entity.id });
    expect(() => assertM10RequestAuditIdentity(request, rowFor(request, packet))).not.toThrow();
  });
  it('retains UUID validation when the exact identity function is transferred into the read-only audit worker', () => {
    const packet = preferencePacket(), request = manifestFor(packet).requests[0];
    // Native Node imports avoid Vitest's SSR-rewritten function text. This
    // subprocess only evaluates public pure helpers and synthetic JSON.
    const policyUrl = new URL('../security/lib/m10-audit-policy.mjs', import.meta.url).href;
    const evidenceUrl = new URL('../security/lib/m10-release-evidence.mjs', import.meta.url).href;
    const script = `import assert from 'node:assert/strict'; import { UUID } from ${JSON.stringify(evidenceUrl)}; import { assertM10RequestAuditIdentity } from ${JSON.stringify(policyUrl)};
      const transferred=new Function('assert','const UUID='+UUID.toString()+'; return '+assertM10RequestAuditIdentity.toString()+';')(assert);
      const request=${JSON.stringify(request)},row=${JSON.stringify(rowFor(request, packet))};
      transferred(request,row);assert.throws(()=>transferred({...request,workspaceId:null},row),/M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED/);
      process.stdout.write('SYNTHETIC_TRANSFER_PASSED');`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 });
    expect(result.error).toBeUndefined(); expect(result.status).toBe(0); expect(result.stdout).toBe('SYNTHETIC_TRANSFER_PASSED');
  });
  it('permits a retained response entity as scope source when the original body is unavailable', () => {
    const packet = preferencePacket(); delete packet.body;
    expect(m10NotificationPreferenceScope(packet)).toEqual({ clusterId: packet.responseData.entity.clusterId, workspaceId: packet.responseData.entity.workspaceId, entityId: packet.responseData.entity.id });
  });
  it.each(['clusterId', 'workspaceId'])('rejects a forged body/result %s disagreement', field => {
    const packet = preferencePacket(); packet.responseData.entity[field] = randomUUID(); expect(() => manifestFor(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_SCOPE_MISMATCH');
  });
  it.each(['clusterId', 'workspaceId'])('rejects incomplete original %s scope rather than allowing global audit wildcard matching', field => {
    const packet = preferencePacket(); delete packet.body[field]; expect(() => manifestFor(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
    delete packet.responseData.entity[field]; expect(() => m10NotificationPreferenceScope(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
  });
  it('rejects absent scope from both original body and actual response', () => {
    const packet = preferencePacket(); delete packet.body; delete packet.responseData.entity.clusterId; delete packet.responseData.entity.workspaceId;
    expect(() => m10NotificationPreferenceScope(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
  });
  it('rejects query/body disagreement, foreign response owner and an unbound response entity', () => {
    const packet = preferencePacket(); packet.path += `?workspaceId=${randomUUID()}`; expect(() => manifestFor(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_SCOPE_MISMATCH');
    packet.path = '/notifications/preferences'; packet.responseData.entity.userId = randomUUID(); expect(() => manifestFor(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_OWNER_MISMATCH');
    delete packet.responseData.entity; expect(() => manifestFor(packet)).toThrow('M10_NOTIFICATION_ORIGINAL_ENTITY_REQUIRED');
  });
  it('rejects a valid tenant outside the two actual verification clusters', () => {
    const packet = preferencePacket(); expect(() => m10MinimalAuditManifest({ milestone: 'M10', cid: randomUUID(), targetCid: randomUUID(), requests: [packet] }, { milestone: 'M10', requests: [] }, packet.startedAt)).toThrow();
  });
  it.each(['cluster_id', 'workspace_id', 'actor_id', 'request_id', 'entity_type', 'entity_id', 'action', 'result', 'source_ip'])('rejects a mismatched real audit %s', field => {
    const packet = preferencePacket(), request = manifestFor(packet).requests[0], row = rowFor(request, packet); row[field] = field === 'source_ip' ? '' : randomUUID();
    expect(() => assertM10RequestAuditIdentity(request, row, { clusterId: row.cluster_id, workspaceId: row.workspace_id })).toThrow();
  });
  it.each(['id', 'userId', 'clusterId', 'workspaceId'])('rejects forged safe after %s even with a correct top-level audit tenant', field => {
    const packet = preferencePacket(), request = manifestFor(packet).requests[0], row = rowFor(request, packet); row.after = { ...row.after, [field]: randomUUID() };
    expect(() => assertM10RequestAuditIdentity(request, row)).toThrow();
  });
  it('rejects a historical before object or missing workspace in the manifest', () => {
    const packet = preferencePacket(), request = manifestFor(packet).requests[0], row = rowFor(request, packet); row.before = { id: randomUUID() };
    expect(() => assertM10RequestAuditIdentity(request, row)).toThrow(); row.before = null;
    expect(() => assertM10RequestAuditIdentity({ ...request, workspaceId: null }, row)).toThrow('M10_NOTIFICATION_ORIGINAL_SCOPE_REQUIRED');
  });
});
