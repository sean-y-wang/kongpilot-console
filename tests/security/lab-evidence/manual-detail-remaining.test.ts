import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { authorizeFreshBootstrap, authorizeRestoredManualSession, beforeManualMutation, completeManualMutation, createManualJournal, manualJournalSummary, stopManualJournal } from './lib/m6-manual-journal.mjs';
import { prepareManualZeroPacketContinuation, preserveManualZeroPacketContinuation, prepareManualCatalogFilterContinuation, preserveManualCatalogFilterContinuation } from './lib/m6-manual-zero-packet.mjs';
import { MANUAL_DETAIL_BOOTSTRAP_REQUEST, MANUAL_DETAIL_LOGIN_REQUESTS, prepareManualDetailRemaining, preserveManualDetailRemaining } from './lib/m6-manual-detail-remaining.mjs';

const source = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8');
const tree = ts.createSourceFile('runner.mjs', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const literal = (name: string) => { let value = ''; const visit = (node: ts.Node) => { if (ts.isVariableDeclaration(node) && node.name.getText(tree) === name && node.initializer && ts.isStringLiteral(node.initializer)) value = node.initializer.text; ts.forEachChild(node, visit); }; visit(tree); return value; };
const functionText = (name: string) => tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name)!.getText(tree);
const zeroBytes = readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json'), catalogBytes = readFileSync('artifacts/M6/UI-review-pre-catalog-filter-attempt.json'), detailBytes = readFileSync('artifacts/M6/UI-review-third-attempt.json');
const failure = JSON.parse(String(detailBytes));
const cid = failure.readEvidence[0].clusterId, wid = failure.readEvidence[0].workspaceId, publicationId = failure.readEvidence[0].targetId, ownerId = failure.readEvidence[2].entityId;
const actors = { owner: { id: ownerId, username: 'source-owner', password: 'source-owner-password' }, administrator: { id: '665d539d-388b-484f-8e76-9a6c692e2e24', username: 'source-admin', password: 'source-admin-password' }, approver: { id: 'd058e5c6-67e4-41a6-ae8d-5f5a6e43c317', username: 'source-approver', password: 'source-approver-password' } };
const content = { slug: `${failure.testTag}-manual-ui-page`, title: `${failure.testTag} Manual UI Page`, markdown: literal('safeMarkdown') };
const expected = { testTag: failure.testTag, clusterId: cid, workspaceId: wid, publicationId, actors, content };
const config = (markdown = content.markdown) => ({ clusterId: cid, workspaceId: wid, actors, content: { ...content, markdown }, priorKeys: [], forbiddenEntityIds: [] });
const packet = (role: string, path: string, body: any, headers: any = {}) => ({ url: `${role === 'owner' ? 'http://127.0.0.1:8082' : 'http://127.0.0.1:8080'}${path}${role === 'owner' ? `?clusterId=${cid}&workspaceId=${wid}` : ''}`, method: 'POST', headers: { 'x-idempotency-key': randomUUID(), ...headers }, rawBody: JSON.stringify(body) });
const completeLogin = (journal: any, role: 'owner' | 'administrator') => {
  if (role === 'administrator') authorizeFreshBootstrap(journal, role, [], () => {});
  const actor = actors[role], body = role === 'owner' ? { username: actor.username, password: actor.password, clusterId: cid, workspaceId: wid } : { username: actor.username, password: actor.password };
  const attempt = beforeManualMutation(journal, role, packet(role, role === 'owner' ? '/api/v1/portal/auth/login' : '/api/v1/auth/login', body), [], () => {});
  completeManualMutation(journal, attempt, 201, { meta: { requestId: MANUAL_DETAIL_LOGIN_REQUESTS[role] }, data: role === 'owner' ? { developer: { ...actor, clusterId: cid, workspaceId: wid, status: 'active' } } : { user: actor } }, () => {});
};
function fixture() {
  const oldContent = { ...content, markdown: literal('originalMarkdown') }, zeroJournal = createManualJournal(config(oldContent.markdown));
  stopManualJournal(zeroJournal, 'manual-harness-stopped', () => {});
  let ref: any = { testTag: failure.testTag, secrets: ['source-only-cookie-placeholder'], manualJournal: zeroJournal, manualMetadata: [], manualWriteAttempts: [], manualWriteEvidence: [] };
  const zero = prepareManualZeroPacketContinuation(ref, zeroBytes, { ...expected, content: oldContent }, true), first = createManualJournal(config(oldContent.markdown)); first.zeroPacketContinuation = zero;
  ref = preserveManualZeroPacketContinuation(ref, zero, first);
  authorizeFreshBootstrap(first, 'owner', [], () => {});
  const originalAnon = beforeManualMutation(first, 'owner', packet('owner', '/api/v1/portal/auth/refresh', { clusterId: cid, workspaceId: wid }), [], () => {});
  completeManualMutation(first, originalAnon, 401, { meta: { requestId: '89ddccd6-23ac-43cc-98b7-482b9fad6bc9' }, error: { code: 'PORTAL_SESSION_EXPIRED' } }, () => {});
  stopManualJournal(first, 'manual-harness-stopped', () => {}); ref = { ...ref, manualJournal: first, manualWriteAttempts: first.attempts };
  const catalog = prepareManualCatalogFilterContinuation(ref, catalogBytes, zeroBytes, { ...expected, originalContent: oldContent, plannedContent: content }, true), current = createManualJournal(config()); current.catalogFilterContinuation = catalog;
  ref = preserveManualCatalogFilterContinuation(ref, catalog, current);
  authorizeFreshBootstrap(current, 'owner', [], () => {});
  const anon = beforeManualMutation(current, 'owner', packet('owner', '/api/v1/portal/auth/refresh', { clusterId: cid, workspaceId: wid }), [], () => {});
  completeManualMutation(current, anon, 401, { meta: { requestId: MANUAL_DETAIL_BOOTSTRAP_REQUEST }, error: { code: 'PORTAL_SESSION_EXPIRED' } }, () => {});
  completeLogin(current, 'owner'); completeLogin(current, 'administrator'); stopManualJournal(current, 'manual-harness-stopped', () => {});
  const evidence = current.attempts.filter((row: any) => row.category === 'planned').map(({ method, path, requestId, status }: any) => ({ method, path, requestId, status }));
  ref = { ...ref, manualJournal: current, manualWriteAttempts: current.attempts, manualWriteEvidence: evidence, writeEvidence: structuredClone(evidence) };
  const prepared = prepareManualDetailRemaining(ref, detailBytes, catalogBytes, zeroBytes, expected, true), active = structuredClone(current);
  active.phase = 'ready'; delete active.stopReason; delete active.stoppedAt; active.detailRemainingContinuation = prepared;
  return { ref, prepared, active };
}
const token = (claims: any) => `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.source-only-not-a-signature`;
function restored(f: ReturnType<typeof fixture>, role: 'owner' | 'administrator', expired = true) {
  const sid = randomUUID(), iat = Math.floor(Date.now() / 1000) - 901, names = role === 'owner' ? ['kongos_portal_access', 'kongos_portal_refresh', 'kongos_portal_csrf'] : ['kongos_access', 'kongos_refresh', 'kongos_csrf'];
  const claims = { sid, sub: actors[role].id, iat, exp: expired ? iat + 900 : iat + 1800, ...(role === 'owner' ? { cid, wid } : {}) };
  const values = [token(claims), `${sid}.source-original-refresh`, 'source-original-csrf'], cookies = names.map((name, index) => ({ name, value: values[index] }));
  const proof = { sessionId: sid, issuedAt: iat, accessExpired: expired, originalLoginAudited: true, currentSessionVerified: true, refreshVerified: true, csrfVerified: true };
  authorizeRestoredManualSession(f.active, role, proof, cookies, () => {});
  const request = packet(role, role === 'owner' ? '/api/v1/portal/auth/refresh' : '/api/v1/auth/refresh', role === 'owner' ? { clusterId: cid, workspaceId: wid } : {}, { cookie: cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; '), [role === 'owner' ? 'x-portal-csrf' : 'x-csrf-token']: values[2] });
  const nextClaims = { ...claims, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 900 }, next = [token(nextClaims), `${sid}.source-new-refresh`, role === 'owner' ? 'source-new-csrf' : values[2]];
  const nextCookies = names.map((name, index) => ({ name, value: next[index] }));
  const response = { meta: { requestId: randomUUID() }, data: role === 'owner' ? { developer: { ...actors.owner, clusterId: cid, workspaceId: wid, status: 'active' }, csrfToken: next[2] } : { user: actors.administrator } };
  return { sid, cookies, request, nextCookies, response };
}

describe('manual third-stop remaining-only source delta', () => {
  it('uses the real bordered Descriptions th/tr/td and ancestor-free actual Playwright locator', async () => {
    const require = createRequire(import.meta.url), Row = require('../../../node_modules/antd/lib/descriptions/Row.js').default;
    const html = renderToStaticMarkup(React.createElement('table', {}, React.createElement('tbody', {}, React.createElement(Row, { prefixCls: 'ant-descriptions', vertical: false, row: [{ label: '开发者账号', children: 'source-owner' }], index: 0, bordered: true }))));
    expect(html).toContain('<tr class="ant-descriptions-row"><th class="ant-descriptions-item-label'); expect(html).toMatch(/<td class="ant-descriptions-item-content(?: [^"]*)?"/);
    const { Locator } = require('../../../node_modules/playwright-core/lib/client/locator.js'), captured: any[] = [], frame = { _platform: {} };
    const fn = vm.runInNewContext(`(${functionText('descriptionValue')})`, { expect: (locator: any) => ({ toHaveCount: async (n: number) => captured.push([locator._selector, n]), toHaveText: async (value: string) => captured.push([locator._selector, value]) }) });
    await fn(new Locator(frame, 'internal:testid=[data-testid="portal-admin-developer-detail"s]'), '开发者账号', 'source-owner');
    expect(captured[2][0]).toContain('th.ant-descriptions-item-label'); expect(captured[2][0]).toContain('xpath=.. >> td.ant-descriptions-item-content'); expect(captured[2][0]).not.toContain('internal:has='); expect(captured[2][1]).toBe('source-owner');
  });
  it('seals all three prior attempts, original failed bytes and both old history families before a one-use resume', () => {
    const f = fixture(), original = JSON.stringify(f.ref), retained = preserveManualDetailRemaining(f.ref, f.prepared, f.active);
    expect(JSON.stringify(f.ref)).toBe(original); expect(retained.manualDetailRemainingHistory.originalFailureBytes).toBe(String(detailBytes)); expect(retained.manualDetailRemainingHistory.originalFailure.passed).toBe(25);
    expect(f.active.nextIndex).toBe(2); expect(f.active.attempts).toEqual(f.ref.manualWriteAttempts); expect(retained.manualZeroPacketHistory).toEqual(f.ref.manualZeroPacketHistory); expect(retained.manualCatalogFilterHistory).toEqual(f.ref.manualCatalogFilterHistory);
    expect(() => prepareManualDetailRemaining(retained, detailBytes, catalogBytes, zeroBytes, expected, true)).toThrow();
    expect(preserveManualDetailRemaining(retained, f.prepared, f.active)).toBe(retained);
  });
  it('rejects any foreign scope/report/nonzero metadata/unknown state, explicit-flag omission and old-history drift', () => {
    const f = fixture();
    for (const mutate of [(r: any) => r.manualMetadata.push({ id: randomUUID() }), (r: any) => r.manualJournal.nextIndex = 3, (r: any) => r.manualJournal.attempts[1].state = 'response-unknown', (r: any) => r.manualJournal.inFlight = randomUUID(), (r: any) => r.manualJournal.workspaceId = randomUUID()]) { const r = structuredClone(f.ref); mutate(r); expect(() => prepareManualDetailRemaining(r, detailBytes, catalogBytes, zeroBytes, expected, true)).toThrow(); }
    expect(() => prepareManualDetailRemaining(f.ref, Buffer.from(String(detailBytes) + ' '), catalogBytes, zeroBytes, expected, true)).toThrow(); expect(() => prepareManualDetailRemaining(f.ref, detailBytes, catalogBytes, zeroBytes, expected, false)).toThrow();
    const retained = preserveManualDetailRemaining(f.ref, f.prepared, f.active); retained.manualZeroPacketHistory = { ...retained.manualZeroPacketHistory, version: 2 }; expect(() => preserveManualDetailRemaining(retained, f.prepared, f.active)).toThrow();
  });
  it('allows only the original expired SID refresh once per role, retains durable raw packet, and never advances planned index', () => {
    for (const role of ['owner', 'administrator'] as const) {
      const f = fixture(), r = restored(f, role), order: string[] = [], attempt = beforeManualMutation(f.active, role, r.request, r.cookies, () => order.push('durable'));
      order.push('packet'); expect(order).toEqual(['durable', 'packet']); expect(attempt.category).toBe('continuation-session-refresh'); expect(attempt.actorId).toBe(actors[role].id); expect(attempt.rawBody).toBe(r.request.rawBody);
      completeManualMutation(f.active, attempt, 201, r.response, () => {}, r.nextCookies); expect(f.active.nextIndex).toBe(2); expect(f.active.attempts.slice(0, 3)).toEqual(f.ref.manualWriteAttempts); expect(manualJournalSummary(f.active).continuationSessionRefreshWrites).toBe(1);
      expect(() => beforeManualMutation(f.active, role, { ...r.request, headers: { ...r.request.headers, 'x-idempotency-key': randomUUID() } }, r.nextCookies, () => {})).toThrow();
    }
  });
  it('rejects unexpired proof, wrong CSRF/SID/header and any owner/admin login, Native or reveal packet', () => {
    const f = fixture(), unexpired = restored(f, 'owner', false); expect(() => beforeManualMutation(f.active, 'owner', unexpired.request, unexpired.cookies, () => {})).toThrow();
    for (const change of [(r: any) => r.request.headers['x-portal-csrf'] = 'foreign', (r: any) => r.cookies[1].value = `${randomUUID()}.foreign`, (r: any) => r.request.headers.cookie += '; kongos_access=foreign']) { const fresh = fixture(), r = restored(fresh, 'owner'); change(r); expect(() => beforeManualMutation(fresh.active, 'owner', r.request, r.cookies, () => {})).toThrow(); }
    for (const path of ['/api/v1/auth/login', `/api/v1/clusters/${cid}/workflows/${randomUUID()}/execute`, '/api/v1/portal/credentials/x/reveal']) { const fresh = fixture(); expect(() => beforeManualMutation(fresh.active, 'administrator', packet('administrator', path, {}), [], () => {})).toThrow(); }
  });
  it('stops globally on unknown refresh, foreign response cookie SID or failed prepacket persistence', () => {
    for (const mode of ['unknown', 'foreign-cookie', 'save-failed']) {
      const f = fixture(), r = restored(f, 'administrator');
      if (mode === 'save-failed') expect(() => beforeManualMutation(f.active, 'administrator', r.request, r.cookies, () => { throw Error('disk-failure'); })).toThrow();
      else { const attempt = beforeManualMutation(f.active, 'administrator', r.request, r.cookies, () => {}); if (mode === 'foreign-cookie') r.nextCookies[1].value = `${randomUUID()}.foreign`; expect(() => completeManualMutation(f.active, attempt, mode === 'unknown' ? 504 : 201, mode === 'unknown' ? undefined : r.response, () => {}, r.nextCookies)).toThrow(); }
      expect(f.active.phase).toBe('stopped-without-replay'); expect(() => beforeManualMutation(f.active, 'administrator', packet('administrator', `/api/v1/clusters/${cid}/portal/pages?workspaceId=${wid}`, content), [], () => {})).toThrow();
    }
  });
  it('actual retain atomically preserves history and original login evidence; source branches skip both logins and never overwrite original screenshots', () => {
    const f = fixture(), outputs: any[] = [];
    const retain = vm.runInNewContext(`(${functionText('retain')})`, { privateReference: () => f.ref, M6_REFERENCE: 'memory-only', journal: f.active, manualMetadata: [], manualAttempts: f.active.attempts, newSecrets: new Set(), writes: f.ref.manualWriteEvidence, preserveManualDetailRemaining, mergeManualWriteEvidence: (prior: any) => prior, writeManualReferenceAtomic: (_: any, value: any) => outputs.push(value) });
    retain(); expect(outputs[0].manualDetailRemainingHistory.snapshot.manualWriteEvidence).toEqual(f.ref.manualWriteEvidence); expect(outputs[0].manualJournal.nextIndex).toBe(2); expect(outputs[0].writeEvidence).toEqual(f.ref.writeEvidence);
    expect(source).toContain("if (detailRemainingRequested) name = name.replace(/^manual-/, 'manual-remaining-')"); expect(source).toContain("if (!detailRemainingRequested) {"); expect(source).toContain("await boundary(portal, 'owner', detailRemainingRequested)"); expect(source).toContain("await boundary(admin, 'administrator', detailRemainingRequested)"); expect(source).toContain("} else { await consoleLogin(consolePage");
    expect(source.indexOf('  retain();\n  let recoveredCookies')).toBeLessThan(source.indexOf('browser = await chromium.launch'));
  });
});
