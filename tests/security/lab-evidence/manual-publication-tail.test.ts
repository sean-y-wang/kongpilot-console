// @ts-nocheck -- source-only synthetic cookies/packets; never execute the runtime entry.
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';
import { beforePublicationTailMutation, prepareManualPublicationTail, preserveManualPublicationTail, publicationTailSessionCookies, publicationTailRenewalEvidence, MANUAL_PUBLICATION_FAILURE_SHA256, MANUAL_PUBLICATION_PROOF_SHA256 } from './lib/m6-manual-publication-tail.mjs';
import { createManualJournal, interruptManualMutation, stopManualJournal } from './lib/m6-manual-journal.mjs';

const source = readFileSync('tests/security/continue-m6-manual-publication-tail.mjs', 'utf8'), tree = ts.createSourceFile('tail.mjs', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const fn = name => tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name).getText(tree);
const failureBytes = readFileSync('artifacts/M6/UI-review-pre-publish-receipt-attempt.json'), proofBytes = readFileSync('artifacts/M6/manual-publish-original-receipt-readonly-diagnostic.json');
const digest = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
function fixture() {
  const actors = Object.fromEntries(['owner', 'administrator', 'approver'].map(role => [role, { id: randomUUID(), username: `source-${role}`, password: `source-${role}-password` }]));
  const journal = createManualJournal({ clusterId: randomUUID(), workspaceId: randomUUID(), actors, content: { title: 'Source tail', slug: 'source-tail', markdown: '# Source' }, priorKeys: [], forbiddenEntityIds: [] });
  journal.startedAt = '2026-10-11T05:30:00.000Z'; journal.pageId = randomUUID(); journal.pageRevision = 2; journal.nextIndex = 3; journal.authenticated = { owner: actors.owner.id, administrator: actors.administrator.id };
  journal.attempts = Array.from({ length: 7 }, (_, index) => ({ category: index === 0 ? 'anonymous-bootstrap' : index === 3 || index === 4 ? 'continuation-session-refresh' : 'planned', action: ['anonymous', 'portal-owner-login', 'console-administrator-login', 'owner-original-session-refresh', 'administrator-original-session-refresh', 'page-create', 'page-publish'][index], role: 'administrator', actorId: actors.administrator.id, method: 'POST', origin: 'http://127.0.0.1:8080', path: `/source/${index}`, query: `workspaceId=${journal.workspaceId}`, key: randomUUID(), rawBody: '{}', body: {}, headers: {}, status: 201, requestId: randomUUID(), state: index === 6 ? 'metadata-receipt-not-proven' : 'response-observed-success' }));
  journal.inFlight = journal.attempts[6].key; journal.restoredSessions = {};
  for (const role of ['owner', 'administrator']) { const sid = randomUUID(), claims = { sid, sub: actors[role].id, exp: Math.floor(Date.now() / 1000) + 900, ...(role === 'owner' ? { cid: journal.clusterId, wid: journal.workspaceId } : {}) }, prefix = role === 'owner' ? 'kongos_portal_' : 'kongos_', token = `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.source-only-not-signature`;
    journal.restoredSessions[role] = { actorId: actors[role].id, sessionId: sid, refreshAttempted: true, refreshed: true, latestCookies: [{ name: `${prefix}access`, value: token }, { name: `${prefix}refresh`, value: `${sid}.source-refresh` }, { name: `${prefix}csrf`, value: 'source-csrf' }] }; }
  const fields = ['manualJournal', 'manualMetadata', 'manualWriteAttempts', 'manualWriteEvidence', 'manualZeroPacketHistory', 'manualZeroPacketContinuation', 'manualCatalogFilterHistory', 'manualCatalogFilterContinuation', 'manualDetailRemainingHistory', 'manualDetailRemainingContinuation'];
  const reference = { testTag: 'source-tail', manualJournal: journal, manualMetadata: [{ id: journal.pageId }], manualWriteAttempts: journal.attempts, manualWriteEvidence: [], ...Object.fromEntries(fields.slice(4).map(field => [field, { sourceOnly: field, old: true }])) };
  const snapshot = structuredClone(Object.fromEntries(fields.map(field => [field, reference[field]]))), prepared = { version: 1, testTag: reference.testTag, failureReportSha256: MANUAL_PUBLICATION_FAILURE_SHA256, diagnosticProofSha256: MANUAL_PUBLICATION_PROOF_SHA256, originalFailureBytes: String(failureBytes), originalProofBytes: String(proofBytes), originalSnapshotSha256: digest(snapshot), snapshot, continuedAt: '2026-10-11T06:00:00.000Z' };
  const active = structuredClone(journal); active.publicationTailContinuation = prepared; active.phase = 'active'; active.attempts[6].state = 'metadata-acknowledged-awaiting-original-iam-proof';
  return { journal: active, original: reference, prepared };
}
function archivePacket(journal) { return { url: `http://127.0.0.1:8080/api/v1/clusters/${journal.clusterId}/portal/pages/${journal.pageId}?workspaceId=${journal.workspaceId}`, method: 'DELETE', headers: { 'x-idempotency-key': randomUUID() }, rawBody: JSON.stringify({ revision: 3, confirmed: true, confirm_name: journal.content.title }) }; }
describe('M6 publication tail narrow source delta', () => {
  it('external auth-only renewal is optional, SHA-bound and reported separately without leaking its private history', () => {
    expect(publicationTailRenewalEvidence({})).toEqual({ externalNormalSessionRenewalWrites: 0 });
    const report = { allPassed: true, authWrites: 2, normalSessionRenewalWrites: 2, successfulNormalSessionRenewalWrites: 2, transportBusinessWrites: 0, nativeRequests: 0, loginRequests: 0, revealRequests: 0, auditCoverage: { successfulProductWrites: 2, distinctRequestIds: 2, auditedRequestIds: 2, allPassed: true } }, bytes = Buffer.from(JSON.stringify(report)), reference = { manualTailSessionRenewal: { version: 1, state: 'completed', authWrites: 2, reportPath: 'artifacts/M6/manual-tail-normal-session-renewal.json', reportSha256: digest(bytes) }, manualTailSessionRenewalHistory: { oldCookies: 'source-private-placeholder' } };
    const result = publicationTailRenewalEvidence(reference, bytes); expect(result.externalNormalSessionRenewalWrites).toBe(2); expect(JSON.stringify(result)).not.toContain('source-private-placeholder');
    for (const altered of [{ ...reference, manualTailSessionRenewal: { ...reference.manualTailSessionRenewal, state: 'active' } }, { ...reference, manualTailSessionRenewalHistory: undefined }, { ...reference, manualTailSessionRenewal: { ...reference.manualTailSessionRenewal, authWrites: 3 } }]) expect(() => publicationTailRenewalEvidence(altered, bytes)).toThrow(); expect(() => publicationTailRenewalEvidence(reference, Buffer.from(String(bytes) + ' '))).toThrow();
  });
  it('pins immutable actual failure/proof and rejects changed bytes, missing flag and previous tail entry', () => {
    expect(digest(failureBytes)).toBe(MANUAL_PUBLICATION_FAILURE_SHA256); expect(digest(proofBytes)).toBe(MANUAL_PUBLICATION_PROOF_SHA256); const f = fixture(), expected = { testTag: f.original.testTag };
    expect(() => prepareManualPublicationTail(f.original, Buffer.from(String(failureBytes) + ' '), proofBytes, expected, true)).toThrow(); expect(() => prepareManualPublicationTail(f.original, failureBytes, Buffer.from(String(proofBytes) + ' '), expected, true)).toThrow(); expect(() => prepareManualPublicationTail(f.original, failureBytes, proofBytes, expected, false)).toThrow(); expect(() => prepareManualPublicationTail({ ...f.original, manualPublicationTailContinuation: {} }, failureBytes, proofBytes, expected, true)).toThrow();
  });
  it('seals every old family and packet without changing original snapshots; repeat saving requires the same marker', () => {
    const f = fixture(), before = JSON.stringify(f.original), retained = preserveManualPublicationTail(f.original, f.prepared, f.journal); expect(JSON.stringify(f.original)).toBe(before); expect(retained.manualPublicationTailHistory.snapshot).toEqual(f.prepared.snapshot); expect(retained.manualPublicationTailHistory.originalFailureBytes).toBe(String(failureBytes)); expect(preserveManualPublicationTail(retained, f.prepared, f.journal)).toBe(retained);
    for (const change of [r => r.manualZeroPacketHistory.old = false, r => r.manualPublicationTailContinuation.continuedAt = 'foreign', r => r.manualPublicationTailHistory.snapshot.manualWriteEvidence.push({ foreign: true })]) { const altered = structuredClone(retained); change(altered); expect(() => preserveManualPublicationTail(altered, f.prepared, f.journal)).toThrow(); }
    const altered = structuredClone(f.journal); altered.attempts[6].rawBody = '{"revision":999}'; expect(() => preserveManualPublicationTail(retained, f.prepared, altered)).toThrow();
  });
  it('restores only the two latest original SIDs and fails closed before launch when access has expired', () => {
    const f = fixture(); expect(publicationTailSessionCookies(f.journal, 'owner')).toEqual(f.journal.restoredSessions.owner.latestCookies); expect(() => publicationTailSessionCookies(f.journal, 'owner', Date.now() + 901_000)).toThrow(); const altered = structuredClone(f.journal); altered.restoredSessions.administrator.latestCookies[1].value = `${randomUUID()}.foreign`; expect(() => publicationTailSessionCookies(altered, 'administrator')).toThrow();
    const start = source.indexOf('  retain();\n  const ownerCookies'), end = source.indexOf('  const portal = await browser.newContext', start), prefix = source.slice(start, end), launches = vi.fn();
    const run = retain => vm.runInNewContext(`(async()=>{${prefix}})()`, { retain, publicationTailSessionCookies, journal: f.journal, browser: undefined, chromium: { launch: launches }, manualChromiumLaunchOptions: () => ({}), process: { env: {} }, existsSync: () => false });
    return expect(run(() => { throw new Error('durable-save-failed'); })).rejects.toThrow().then(() => expect(launches).not.toHaveBeenCalled());
  });
  it('actual route awaits trusted actor/body journaling before continue and aborts globally on failed persistence', async () => {
    for (const fail of [false, true]) { const f = fixture(); f.journal.nextIndex = 4; f.journal.pageRevision = 3; f.journal.inFlight = null; const events = [], packet = archivePacket(f.journal); let handler;
      const context = { cookies: async () => [], route: async (_, callback) => { handler = callback; } }, route = { request: () => ({ url: () => packet.url, method: () => packet.method, allHeaders: async () => packet.headers, postData: () => packet.rawBody }), continue: async () => { events.push('packet'); }, abort: async () => { events.push('abort'); } };
      const retain = () => { events.push('durable'); if (fail) throw new Error('disk'); };
      const boundary = vm.runInNewContext(`(${fn('boundary')})`, { journal: f.journal, secrets: new Set(), URL, beforePublicationTailMutation, stopManualJournal, interruptManualMutation, retain, authorizeFreshBootstrap: () => { throw Error('fresh forbidden'); } }); await boundary(context, 'administrator'); await handler(route);
      if (fail) { expect(events).not.toContain('packet'); expect(events).toContain('abort'); expect(f.journal.phase).toBe('stopped-without-replay'); } else { expect(events).toEqual(['durable', 'packet']); expect(f.journal.attempts.at(-1)).toMatchObject({ actorId: f.journal.actors.administrator.id, rawBody: packet.rawBody, category: 'planned', action: 'page-archive' }); }
    }
  });
  it('does not release any mutation before original IAM proof and never sends a third refresh or old login', () => {
    const f = fixture(); expect(() => beforePublicationTailMutation(f.journal, 'administrator', archivePacket(f.journal), [], () => {})).toThrow(); expect(f.journal.attempts).toHaveLength(7);
    for (const path of ['/api/v1/auth/refresh', '/api/v1/auth/login', '/api/v1/portal/auth/refresh', `/api/v1/clusters/${f.journal.clusterId}/portal/pages/${f.journal.pageId}/publish`]) { const fresh = fixture(); fresh.journal.nextIndex = 4; fresh.journal.pageRevision = 3; fresh.journal.inFlight = null; expect(() => beforePublicationTailMutation(fresh.journal, 'administrator', { ...archivePacket(fresh.journal), url: `http://127.0.0.1:8080${path}`, method: 'POST' }, [], () => {})).toThrow(); expect(fresh.journal.attempts).toHaveLength(7); }
  });
  it('actual runner uses protected original-key GET, expected PageWF403 and states audit limitations', () => {
    expect(source).toContain('await context.request.get(url, { maxRetries: 0 })'); expect(source).toContain('await proveOriginalIam(admin, journal.attempts[6])'); expect(source).toContain("denied.error?.code === 'PERMISSION_DENIED'"); expect(source).toContain('acceptanceCriterion11Complete: false'); expect(source).not.toContain('readOriginalManualSessionCookies'); expect(source).not.toContain('process.loadEnvFile'); expect(source).not.toContain("'pages', 'POST'");
  });
});
