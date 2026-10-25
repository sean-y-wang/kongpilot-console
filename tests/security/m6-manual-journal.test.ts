import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { authorizeFreshBootstrap, beforeManualMutation, completeManualMutation, createManualJournal, interruptManualMutation, MANUAL_ACTIONS, manualAttemptForPacket, manualJournalSummary, stopManualJournal, writeManualReferenceAtomic } from './lib/m6-manual-journal.mjs';

function fixture() {
  const actors = Object.fromEntries(['owner', 'administrator', 'approver'].map(role => [role, { id: randomUUID(), username: `synthetic-${role}`, password: `synthetic-${role}-password-only` }]));
  const originalKey = randomUUID(), existingId = randomUUID();
  const journal = createManualJournal({ clusterId: randomUUID(), workspaceId: randomUUID(), actors, content: { slug: 'synthetic-manual-page', title: 'Synthetic manual page', markdown: '# Synthetic public test only\n\nNo real secret.' }, priorKeys: [originalKey], forbiddenEntityIds: [existingId] });
  const saved: any[] = [], persist = vi.fn(() => saved.push(structuredClone(journal)));
  function packet(role: string, action = MANUAL_ACTIONS[journal.nextIndex], extra: Record<string, any> = {}) {
    const portal = role === 'owner', origin = portal ? 'http://127.0.0.1:8082' : 'http://127.0.0.1:8080', actor = journal.actors[role];
    let path: string, body: any, method = 'POST', query = '';
    if (action === 'bootstrap') { path = portal ? '/api/v1/portal/auth/refresh' : '/api/v1/auth/refresh'; body = portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {}; query = portal ? `?clusterId=${journal.clusterId}&workspaceId=${journal.workspaceId}` : ''; }
    else if (action.endsWith('-login')) { path = portal ? '/api/v1/portal/auth/login' : '/api/v1/auth/login'; body = { username: actor.username, password: actor.password, ...(portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {}) }; query = portal ? `?clusterId=${journal.clusterId}&workspaceId=${journal.workspaceId}` : ''; }
    else {
      path = `/api/v1/clusters/${journal.clusterId}/portal/pages${action === 'page-create' ? '' : `/${journal.pageId}${action === 'page-publish' ? '/publish' : action === 'page-restore-draft' ? '/restore' : ''}`}`;
      body = action === 'page-create' ? { ...journal.content } : { revision: journal.pageRevision, confirmed: true, confirm_name: journal.content.title };
      query = `?workspaceId=${journal.workspaceId}`; if (action === 'page-archive') method = 'DELETE';
    }
    return { url: origin + path + query, method, rawBody: JSON.stringify(body), headers: { 'x-idempotency-key': randomUUID(), 'content-type': 'application/json' }, ...extra };
  }
  function response(attempt: any, extra: Record<string, any> = {}) {
    const actor = journal.actors[attempt.role];
    let data;
    if (attempt.action.endsWith('-login')) data = attempt.role === 'owner' ? { developer: { ...actor, status: 'active', clusterId: journal.clusterId, workspaceId: journal.workspaceId }, csrfToken: 'synthetic-csrf-only' } : { user: { id: actor.id, username: actor.username }, csrfToken: 'synthetic-csrf-only' };
    else {
      const workflowId = randomUUID(), id = journal.pageId ?? randomUUID();
      data = { workflowId, entity: { id, ...journal.content, state: ({ 'page-create': 'draft', 'page-publish': 'published', 'page-archive': 'deleted', 'page-restore-draft': 'draft' } as any)[attempt.action], revision: (journal.pageRevision ?? 0) + 1 }, receipt: { workflowId, clusterId: journal.clusterId, workspaceId: journal.workspaceId, idempotencyKey: attempt.key, state: 'succeeded' } };
    }
    return { meta: { requestId: randomUUID() }, data, ...extra };
  }
  function login(role: string) { authorizeFreshBootstrap(journal, role, [], persist); const p = packet(role), a = beforeManualMutation(journal, role, p, [], persist); completeManualMutation(journal, a, 201, response(a), persist); return a; }
  function readyMetadata() { login('owner'); login('administrator'); }
  function metadata() { const p = packet('administrator'), a = beforeManualMutation(journal, 'administrator', p, [], persist); completeManualMutation(journal, a, 201, response(a), persist); return a; }
  return { journal, actors, originalKey, existingId, saved, persist, packet, response, login, readyMetadata, metadata };
}

describe('manual UI durable before-packet write boundary', () => {
  it('records the complete original login body/key/query and trusted actor before any packet can continue', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const packet = f.packet('owner');
    packet.rawBody = JSON.stringify(JSON.parse(packet.rawBody), null, 2); const continued = vi.fn();
    const persist = vi.fn(() => { expect(continued).not.toHaveBeenCalled(); f.persist(); });
    const attempt = beforeManualMutation(f.journal, 'owner', packet, [], persist); continued();
    expect(f.saved.at(-1).attempts[0]).toMatchObject({ actorId: f.actors.owner.id, expectedLoginActorId: f.actors.owner.id, key: packet.headers['x-idempotency-key'], query: new URL(packet.url).search.slice(1), rawBody: packet.rawBody, body: JSON.parse(packet.rawBody), clusterId: f.journal.clusterId, workspaceId: f.journal.workspaceId, state: 'before-single-send' });
    expect(attempt).toBe(f.journal.attempts[0]); expect(continued).toHaveBeenCalledOnce();
  });
  it('never continues a packet when private persistence fails and retains a stopped in-memory intent', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const continued = vi.fn();
    expect(() => { beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], () => { throw new Error('synthetic disk failure'); }); continued(); }).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(continued).not.toHaveBeenCalled(); expect(f.journal.phase).toBe('stopped-without-replay'); expect(f.journal.attempts[0].state).toBe('private-save-failed-before-packet');
  });
  it('requires an actually empty fresh context before the first login', () => {
    const f = fixture(); expect(() => authorizeFreshBootstrap(f.journal, 'owner', [{ name: 'kongos_portal_access', value: 'synthetic-old-value' }], f.persist)).toThrow();
    expect(f.journal.phase).toBe('stopped-without-replay'); expect(f.journal.attempts).toHaveLength(0);
  });
  it('does not authorize a second context for the same login actor', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); expect(() => authorizeFreshBootstrap(f.journal, 'owner', [], f.persist)).toThrow();
  });
  it.each(['cookie-jar', 'cookie-header'])('rechecks absence of all old auth cookies in the %s immediately before the login packet', source => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const p = f.packet('owner'), cookies = source === 'cookie-jar' ? [{ name: 'kongos_portal_access', value: 'synthetic-old-access' }] : [];
    if (source === 'cookie-header') (p.headers as any).cookie = 'kongos_refresh=synthetic-old-refresh';
    expect(() => beforeManualMutation(f.journal, 'owner', p, cookies, f.persist)).toThrow(); expect(f.journal.attempts).toHaveLength(0);
  });
  it.each([
    ['foreign origin', (f: any, p: any) => p.url = p.url.replace(':8082', ':8001')],
    ['missing original key', (_f: any, p: any) => delete p.headers['x-idempotency-key']],
    ['old key', (f: any, p: any) => p.headers['x-idempotency-key'] = f.originalKey],
    ['wrong tenant body', (_f: any, p: any) => p.rawBody = JSON.stringify({ ...JSON.parse(p.rawBody), workspaceId: randomUUID() })],
    ['wrong query', (_f: any, p: any) => p.url += '&workspaceId=' + randomUUID()],
    ['wrong password', (_f: any, p: any) => p.rawBody = JSON.stringify({ ...JSON.parse(p.rawBody), password: 'different-synthetic-password' })],
    ['extra body property', (_f: any, p: any) => p.rawBody = JSON.stringify({ ...JSON.parse(p.rawBody), execute: true })],
    ['wrong method', (_f: any, p: any) => p.method = 'PUT'],
    ['unknown native endpoint', (_f: any, p: any) => p.url = p.url.replace('/auth/login', '/requests')],
    ['unparseable body', (_f: any, p: any) => p.rawBody = '{'],
  ])('rejects %s before journaling or sending any new packet and globally stops', (_name, change) => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const p = f.packet('owner'); change(f, p);
    expect(() => beforeManualMutation(f.journal, 'owner', p, [], f.persist)).toThrow(); expect(f.journal.attempts).toHaveLength(0); expect(f.journal.phase).toBe('stopped-without-replay');
    expect(() => beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist)).toThrow();
  });
  it('blocks an overlapping or repeated intent even with a fresh retry key', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const first = beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist);
    expect(() => beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist)).toThrow(); expect(f.journal.attempts).toHaveLength(1); expect(first.state).toBe('before-single-send');
  });
  it('completes exactly three fresh logins and four sequential content metadata mutations without any bootstrap packet', () => {
    const f = fixture(); f.readyMetadata(); const page = f.metadata(); f.metadata(); f.metadata(); f.metadata(); f.login('approver');
    expect(f.journal.pageId).toBe(page.entityId); expect(f.journal.pageRevision).toBe(4); expect(f.journal.attempts.map((a: any) => a.action)).toEqual(MANUAL_ACTIONS);
    expect(manualJournalSummary(f.journal)).toMatchObject({ complete: true, plannedWrites: 7, successfulPlannedWrites: 7, expectedDeniedAnonymousBootstrapWrites: 0 });
    expect(() => beforeManualMutation(f.journal, 'approver', f.packet('approver', 'console-approver-login'), [], f.persist)).toThrow();
  });
  it('accepts only the actual response-created page UUID and response revision for later publish/archive/restore', () => {
    const f = fixture(); f.readyMetadata(); const created = f.metadata(), p = f.packet('administrator');
    expect(new URL(p.url).pathname).toContain(created.entityId); expect(JSON.parse(p.rawBody).revision).toBe(f.journal.pageRevision);
    const a = beforeManualMutation(f.journal, 'administrator', p, [], f.persist), payload = f.response(a); payload.data.entity.id = randomUUID();
    expect(() => completeManualMutation(f.journal, a, 201, payload, f.persist)).toThrow(); expect(f.journal.pageId).toBe(created.entityId); expect(f.journal.phase).toBe('stopped-without-replay');
  });
  it.each(['id-is-parent', 'id-already-existed', 'stale-revision', 'receipt-key', 'receipt-scope', 'partial-receipt', 'wrong-page-state'])('stops on %s metadata result without admitting a later operation', reason => {
    const f = fixture(); f.readyMetadata(); const a = beforeManualMutation(f.journal, 'administrator', f.packet('administrator'), [], f.persist), p = f.response(a);
    if (reason === 'id-is-parent') p.data.entity.id = p.data.workflowId;
    if (reason === 'id-already-existed') p.data.entity.id = f.existingId;
    if (reason === 'stale-revision') p.data.entity.revision = 0;
    if (reason === 'receipt-key') p.data.receipt.idempotencyKey = randomUUID();
    if (reason === 'receipt-scope') p.data.receipt.workspaceId = randomUUID();
    if (reason === 'partial-receipt') p.data.receipt.state = 'partial';
    if (reason === 'wrong-page-state') p.data.entity.state = 'published';
    expect(() => completeManualMutation(f.journal, a, 201, p, f.persist)).toThrow(); expect(f.journal.pageId).toBeNull(); expect(f.journal.phase).toBe('stopped-without-replay');
  });
  it.each([409, 500, 503])('globally stops on a planned HTTP %d without resetting, replaying or replacing its key', status => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const a = beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist), before = structuredClone(a);
    expect(() => completeManualMutation(f.journal, a, status, { meta: { requestId: randomUUID() }, error: { code: 'SYNTHETIC_FAILURE' } }, f.persist)).toThrow();
    expect(a.key).toBe(before.key); expect(a.rawBody).toBe(before.rawBody); expect(a.body).toEqual(before.body); expect(f.journal.nextIndex).toBe(0); expect(f.journal.phase).toBe('stopped-without-replay');
  });
  it('retains an interrupted original request and blocks even a different later context', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const p = f.packet('owner'), a = beforeManualMutation(f.journal, 'owner', p, [], f.persist);
    expect(manualAttemptForPacket(f.journal, 'owner', p)).toBe(a); interruptManualMutation(f.journal, a, f.persist);
    expect(a.state).toBe('transport-interrupted'); expect(() => authorizeFreshBootstrap(f.journal, 'administrator', [], f.persist)).toThrow(); expect(f.journal.attempts).toHaveLength(1);
  });
  it('never binds an altered body or query to a previously journaled key/path', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const p = f.packet('owner'), a = beforeManualMutation(f.journal, 'owner', p, [], f.persist);
    expect(manualAttemptForPacket(f.journal, 'owner', p)).toBe(a);
    expect(manualAttemptForPacket(f.journal, 'owner', { ...p, rawBody: p.rawBody + ' ' })).toBeUndefined();
    expect(manualAttemptForPacket(f.journal, 'owner', { ...p, url: p.url + '&other=1' })).toBeUndefined();
  });
  it('validates the successful login response against the trusted pre-send actor, never a guessed post-login identity', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const a = beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist), p = f.response(a); p.data.developer.id = randomUUID();
    expect(a.actorId).toBe(f.actors.owner.id); expect(() => completeManualMutation(f.journal, a, 201, p, f.persist)).toThrow(); expect(f.journal.authenticated.owner).toBeUndefined();
  });
});

describe('bounded real anonymous bootstrap exceptions', () => {
  it('journals one anonymous bootstrap with actor null and trusted expected actor, then accepts only the exact missing-session 401', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const p = f.packet('owner', 'bootstrap'), a = beforeManualMutation(f.journal, 'owner', p, [{ name: 'kongos_portal_csrf', value: 'synthetic-csrf-only' }], f.persist);
    expect(a).toMatchObject({ category: 'anonymous-bootstrap', actorId: null, expectedLoginActorId: f.actors.owner.id, rawBody: p.rawBody, body: { clusterId: f.journal.clusterId, workspaceId: f.journal.workspaceId } });
    completeManualMutation(f.journal, a, 401, { meta: { requestId: randomUUID() }, error: { code: 'PORTAL_SESSION_EXPIRED' } }, f.persist);
    expect(f.journal.nextIndex).toBe(0); expect(manualJournalSummary(f.journal).expectedDeniedAnonymousBootstrapWrites).toBe(1);
    const login = beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist); completeManualMutation(f.journal, login, 201, f.response(login), f.persist); expect(f.journal.authenticated.owner).toBe(f.actors.owner.id);
  });
  it.each([['wrong-code', 401, 'CSRF_INVALID'], ['unexpected-success', 201, 'PORTAL_SESSION_EXPIRED'], ['outage', 503, 'PORTAL_SESSION_EXPIRED']])('stops on %s, rather than assuming the bootstrap had no effects', (_reason, status, code) => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const a = beforeManualMutation(f.journal, 'owner', f.packet('owner', 'bootstrap'), [], f.persist);
    expect(() => completeManualMutation(f.journal, a, status, { meta: { requestId: randomUUID() }, error: { code } }, f.persist)).toThrow(); expect(f.journal.phase).toBe('stopped-without-replay');
  });
  it('never permits a second bootstrap or post-login refresh', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const a = beforeManualMutation(f.journal, 'owner', f.packet('owner', 'bootstrap'), [], f.persist);
    completeManualMutation(f.journal, a, 401, { meta: { requestId: randomUUID() }, error: { code: 'PORTAL_SESSION_EXPIRED' } }, f.persist);
    expect(() => beforeManualMutation(f.journal, 'owner', f.packet('owner', 'bootstrap'), [], f.persist)).toThrow();
    const second = fixture(); second.login('owner'); expect(() => beforeManualMutation(second.journal, 'owner', second.packet('owner', 'bootstrap'), [], second.persist)).toThrow();
  });
  it.each(['cookie-jar', 'cookie-header'])('rejects an old access/refresh in the %s before anonymous packet continuation', source => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const p = f.packet('owner', 'bootstrap'), cookies = source === 'cookie-jar' ? [{ name: 'kongos_refresh', value: 'synthetic-old-refresh' }] : [];
    if (source === 'cookie-header') p.headers.cookie = 'kongos_portal_refresh=synthetic-old-refresh';
    expect(() => beforeManualMutation(f.journal, 'owner', p, cookies, f.persist)).toThrow(); expect(f.journal.attempts).toHaveLength(0);
  });
  it('counts optional Console known-denied bootstrap separately and never requires creating one', () => {
    const f = fixture(); f.login('owner'); authorizeFreshBootstrap(f.journal, 'administrator', [], f.persist); const p = f.packet('administrator', 'bootstrap'), a = beforeManualMutation(f.journal, 'administrator', p, [], f.persist);
    completeManualMutation(f.journal, a, 401, { meta: { requestId: randomUUID() }, error: { code: 'SESSION_EXPIRED' } }, f.persist);
    expect(manualJournalSummary(f.journal)).toMatchObject({ successfulPlannedWrites: 1, expectedDeniedAnonymousBootstrapWrites: 1 });
  });
});

describe('private journal atomic durability and actual runner wiring', () => {
  function io() {
    const calls: any[] = [], fake = { openSync: vi.fn((path: string, flags: string, mode?: number) => { calls.push(['open', path, flags, mode]); return flags === 'wx' ? 41 : 42; }), writeFileSync: vi.fn((fd: number, text: string) => calls.push(['write', fd, text])), fsyncSync: vi.fn((fd: number) => calls.push(['sync', fd])), closeSync: vi.fn((fd: number) => calls.push(['close', fd])), renameSync: vi.fn((from: string, to: string) => calls.push(['rename', from, to])), unlinkSync: vi.fn((path: string) => calls.push(['unlink', path])) }; return { calls, fake };
  }
  it('writes an exclusive 0600 file, syncs it before rename, then syncs the parent directory', () => {
    const f = io(), original = { secrets: ['synthetic-original-cookie'], priorFixtureRuns: [{ id: randomUUID() }], manualJournal: { rawBody: '{"password":"synthetic-only"}' } };
    writeManualReferenceAtomic('/synthetic/private.json', original, f.fake, () => 'unique');
    expect(f.calls).toEqual([['open', '/synthetic/private.json.unique.manual.tmp', 'wx', 0o600], ['write', 41, JSON.stringify(original)], ['sync', 41], ['close', 41], ['rename', '/synthetic/private.json.unique.manual.tmp', '/synthetic/private.json'], ['open', '/synthetic', 'r', undefined], ['sync', 42], ['close', 42]]);
  });
  it('does not replace the original private reference after a failed file sync', () => {
    const f = io(); f.fake.fsyncSync.mockImplementation(() => { throw new Error('synthetic sync failure'); });
    expect(() => writeManualReferenceAtomic('/synthetic/private.json', { secrets: ['keep'] }, f.fake, () => 'unique')).toThrow();
    expect(f.fake.renameSync).not.toHaveBeenCalled(); expect(f.fake.closeSync).toHaveBeenCalledWith(41); expect(f.fake.unlinkSync).toHaveBeenCalledWith('/synthetic/private.json.unique.manual.tmp');
  });
  it('preserves the first stop reason and emits no body/key/cookie/actor in the public summary', () => {
    const f = fixture(); authorizeFreshBootstrap(f.journal, 'owner', [], f.persist); const a = beforeManualMutation(f.journal, 'owner', f.packet('owner'), [], f.persist); stopManualJournal(f.journal, 'first-unknown', f.persist); stopManualJournal(f.journal, 'later-observation', f.persist);
    const summary = JSON.stringify(manualJournalSummary(f.journal)); expect(f.journal.stopReason).toBe('first-unknown'); expect(summary).not.toContain(a.key); expect(summary).not.toContain(f.actors.owner.password); expect(summary).not.toContain(f.actors.owner.id); expect(summary).not.toContain('rawBody');
  });
  it('wires BrowserContext interception before page creation, journals before continuation and preserves the exact active credential locator', () => {
    const source = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8');
    expect(source.indexOf("await boundary(portal, 'owner')")).toBeLessThan(source.indexOf('await portal.newPage()'));
    expect(source.indexOf('attempt = beforeManualMutation')).toBeLessThan(source.indexOf('await route.continue();', source.indexOf('attempt = beforeManualMutation')));
    expect(source).toContain('rawBody: request.postData()'); expect(source).toContain('writeManualReferenceAtomic(M6_REFERENCE'); expect(source).toContain('manualJournal: journal');
    expect(source).toContain('tr.ant-table-row[data-row-key="${published.activeCredentialId}"]'); expect(source).not.toContain("let actorId;"); expect(source).not.toContain("state: 'not_observed'");
    expect(source).toContain("page.getByRole('link', { name: '已有账号，返回登录', exact: true }).click()"); expect(source).not.toContain("await page.goto('/register')");
  });
});
