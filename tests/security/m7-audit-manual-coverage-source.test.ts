// @ts-nocheck -- complete original UI journal, synthetic transport only.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { auditAllWritesCoverage, auditManualUiReceiptsAcceptance } from './lib/m7-audit-acceptance.mjs';
import { M7_UI_ACTIONS, createM7UiJournal, proveM7UiActor, m7UiCookies, beforeM7UiPacket, observeM7UiAck, confirmM7UiReceipt, m7UiReceiptPath, bindM7UiDelivery, bindM7UiNotifications } from './lib/m7-manual-journal.mjs';

const origin = 'http://127.0.0.1:8080';
function session(role) {
  const id = randomUUID(), sid = randomUUID(), exp = Math.floor(Date.now() / 1000) + 900, csrf = `SyntheticCSRF-${role}`;
  const jwt = `synthetic.${Buffer.from(JSON.stringify({ sub: id, sid, exp })).toString('base64url')}.signature`;
  return { user: { id, username: `synthetic-${role}` }, sid, csrf, expiresAt: exp * 1000, cookie: `kongos_access=${jwt}; kongos_refresh=${sid}.opaque; kongos_csrf=${csrf}` };
}
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), sessions = { admin: session('admin'), owner: session('owner'), readonly: session('readonly') };
  const journal = createM7UiJournal({ testTag: 'm7-security-abcdef01', scope: { cid, wid }, sessions, endpoint: 'https://event-receiver:9087/hook', bearer: 'SyntheticWebhookBearer', priorKeys: [], approvedActions: M7_UI_ACTIONS });
  for (const role of Object.keys(sessions)) proveM7UiActor(journal, role, { user: { ...sessions[role].user, permissionsVersion: 'actual:source' }, csrfToken: sessions[role].csrf }, () => {});
  const ledgers = new Map(), auditRows = new Map();
  const baseEntity = (id, name) => ({ id, ...(name === undefined ? {} : { name }), clusterId: cid, workspaceId: wid, revision: 1, status: 'active' });
  const preference = { ...baseEntity(randomUUID(), journal.names.preference), userId: sessions.owner.user.id, inAppEnabled: true, eventTypes: ['channel.test', 'delivery.replay'], nativeType: null, nativeIds: [], tags: [] };
  const channel = baseEntity(randomUUID(), journal.names.channel), testQueue = { eventId: randomUUID(), deliveryId: randomUUID() }, replayQueue = { eventId: randomUUID(), deliveryId: randomUUID() };
  const personal = `clusterId=${cid}&workspaceId=${wid}`, shared = `workspaceId=${wid}`, channelBase = `/clusters/${cid}/events/channels/${channel.id}`;
  const prefInput = { clusterId: cid, workspaceId: wid, name: preference.name, eventTypes: ['channel.test', 'delivery.replay'], nativeIds: [], tags: [] }, confirm = row => ({ revision: row.revision, confirmed: true, confirm_name: row.name ?? row.id });
  function execute(role, method, path, body, result, action) {
    const actor = sessions[role], key = randomUUID(), packet = { method, url: origin + '/api/v1' + path, rawBody: JSON.stringify(body), headers: { 'x-idempotency-key': key, 'x-csrf-token': actor.csrf, 'content-type': 'application/json', cookie: actor.cookie } };
    const attempt = beforeM7UiPacket(journal, role, packet, m7UiCookies(actor), () => {});
    const writeId = randomUUID(); observeM7UiAck(journal, attempt, { status: method === 'POST' ? 201 : 200, requestId: writeId, data: result, cookies: [] }, () => {});
    const receipt = attempt.namespace === 'events' ? { domain: 'iam', id: randomUUID(), idempotencyKey: key, clusterId: cid, workspaceId: wid, handler: attempt.handler, state: 'succeeded', configurationCommitted: true, executionCompleted: true, deliverySucceeded: false, queued: !!result.queued, result }
      : attempt.namespace === 'audit-export' ? result : { id: randomUUID(), clusterId: cid, workspaceId: wid, state: 'succeeded', remote_completed: true, result };
    confirmM7UiReceipt(journal, role, { method: 'GET', url: origin + m7UiReceiptPath(journal, attempt) }, receipt, randomUUID(), () => {});
    ledgers.set(key, { actorId: actor.user.id, sessionId: actor.sid, receipt: structuredClone(receipt) });
    const after = result.entity ?? result.items ?? result.queued ?? { jobId: result.jobId };
    const view = { id: randomUUID(), actorId: actor.user.id, actorType: 'user', sourceIp: '127.0.0.1', clusterId: cid, workspaceId: wid, entityType: attempt.namespace === 'notifications' ? 'user_notification_subscriptions' : 'notification_channels', entityId: result.entity?.id ?? null,
      action: action ?? attempt.handler ?? 'audit.export.create', before: null, after: structuredClone(after), jsonPatch: [{ op: 'replace', path: '', value: structuredClone(after) }], workflowId: null, result: 'success', requestId: writeId, occurredAt: new Date().toISOString(), scopeQuality: 'legacy_unknown' };
    auditRows.set(writeId, view); return attempt;
  }
  execute('owner', 'POST', `/notifications/preferences?${personal}`, { ...prefInput, inAppEnabled: true }, { entity: preference }, 'notifications.personal.preferences.save');
  execute('admin', 'POST', `/clusters/${cid}/events/channels?${shared}`, journal.channelInput, { entity: channel });
  execute('admin', 'POST', `${channelBase}/test?${shared}`, confirm(channel), { queued: testQueue });
  const delivery = { ...baseEntity(testQueue.deliveryId, undefined), eventId: testQueue.eventId, revision: 8, state: 'succeeded', capabilities: { replay: true } };
  bindM7UiDelivery(journal, delivery, () => {});
  execute('admin', 'POST', `/clusters/${cid}/events/deliveries/${delivery.id}/replay?${shared}`, confirm(delivery), { queued: replayQueue });
  const notifications = [testQueue, replayQueue].map(queue => ({ ...baseEntity(randomUUID(), undefined), eventId: queue.eventId, readAt: null, dismissedAt: null, capabilities: { write: true } }));
  bindM7UiNotifications(journal, notifications, () => {});
  execute('owner', 'POST', `/notifications/read-batch?${personal}`, { clusterId: cid, workspaceId: wid, items: notifications.map(({ id, revision }) => ({ id, revision })), confirmed: true }, { items: notifications.map(row => ({ ...row, revision: 2, readAt: '2026-10-01T01:00:00Z' })) }, 'notifications.personal.read');
  execute('owner', 'PATCH', `/notifications/preferences/${preference.id}?${personal}`, { ...prefInput, inAppEnabled: false, revision: 1 }, { entity: { ...preference, inAppEnabled: false, revision: 2 } }, 'notifications.personal.preferences.save');
  execute('owner', 'DELETE', `/notifications/preferences/${preference.id}?${personal}`, { ...confirm(preference), revision: 2 }, { entity: { ...preference, inAppEnabled: false, revision: 3, status: 'deleted' } }, 'notifications.personal.preferences.delete');
  execute('owner', 'POST', `/notifications/preferences/${preference.id}/restore?${personal}`, { ...confirm(preference), revision: 3 }, { entity: { ...preference, inAppEnabled: false, revision: 4 } }, 'notifications.personal.preferences.restore');
  const jobId = randomUUID(); execute('admin', 'POST', `/clusters/${cid}/audit/exports?${shared}`, { actorId: sessions.owner.user.id, workspaceId: wid, format: 'csv', confirmed: true }, { domain: 'audit-export', durable: true, jobId, job: { id: jobId, format: 'csv', state: 'queued', complete: false } });
  execute('admin', 'DELETE', `${channelBase}?${shared}`, confirm(channel), { entity: { ...channel, revision: 2, status: 'deleted' } });
  execute('admin', 'POST', `${channelBase}/restore?${shared}`, { ...confirm(channel), revision: 2 }, { entity: { ...channel, revision: 3, status: 'disabled' } });
  execute('admin', 'POST', `${channelBase}/status?${shared}`, { ...confirm(channel), revision: 3, status: 'active' }, { entity: { ...channel, revision: 4 } });
  const h = { state: { testTag: journal.testTag, sessions, manualUiJournal: journal, requests: journal.attempts.map(attempt => ({ ...structuredClone(attempt), source: 'manual-ui', manualIndex: attempt.index, expected: [200, 201] })), fixtures: [], scopes: { direct: { cid, wid } }, secrets: [] },
    save: vi.fn(), check(ok, name) { if (!ok) throw Error(name); }, data(result) { return result.payload.data; } };
  const calls = [], disabled = new Set();
  h.request = vi.fn(async (actor, path, method = 'GET') => {
    if (method !== 'GET') throw Error('NO_SYNTHETIC_WRITES_ALLOWED');
    if (disabled.has(actor.user.id)) throw Error('ORIGINAL_ACTOR_DISABLED');
    const url = new URL('https://synthetic.invalid' + path); calls.push({ actorId: actor.user.id, sid: actor.sid, path, method });
    let data;
    if (url.pathname.includes('/by-key/')) {
      const actual = ledgers.get(url.pathname.split('/').at(-1));
      if (!actual || actual.actorId !== actor.user.id || actual.sessionId !== actor.sid) throw Error('REAL_OWN_RECEIPT_NOT_FOUND');
      data = structuredClone(actual.receipt);
    } else if (url.pathname.endsWith('/audit') || url.pathname === '/audit/global') {
      if (url.searchParams.get('scope') === 'cluster' && url.searchParams.has('workspaceId')) throw Error('ACTUAL_AUDIT_SCOPE_INVALID');
      if (url.searchParams.has('workspaceId') && url.searchParams.get('result') !== 'success') throw Error('ACTUAL_PROOF_MUST_FILTER_TERMINAL_NOT_REQUESTED');
      const row = auditRows.get(url.searchParams.get('requestId'));
      data = { items: row ? [structuredClone(row)] : [], total: null, nextCursor: null };
    } else throw Error('UNPLANNED_SYNTHETIC_READ');
    return { status: 200, requestId: randomUUID(), payload: { success: true, data } };
  });
  return { h, actors: { ...sessions, direct: { cid, wid } }, journal, sessions, ledgers, auditRows, calls, disabled };
}

describe('manual UI audit two phase closure, source only', () => {
  it('corroborates all12 receipts while actors active, then includes all12 immutable terminals through bootstrap after disable', async () => {
    const f = fixture(), proof = await auditManualUiReceiptsAcceptance(f.h, f.actors);
    expect(proof).toMatchObject({ confirmedWrites: 12 }); expect(proof.auditEventIds).toHaveLength(12);
    expect(f.calls.filter(row => row.path.includes('/by-key/'))).toHaveLength(12);
    expect(f.h.state.manualUiAuditProof).toMatchObject({ version: 1, state: 'complete', records: expect.any(Array) });
    const bootstrap = session('bootstrap'); f.disabled.add(f.sessions.admin.user.id); f.disabled.add(f.sessions.owner.user.id); f.h.state.cleanupStarted = true;
    f.calls.length = 0;
    expect(await auditAllWritesCoverage(f.h, { ...f.actors, admin: bootstrap })).toMatchObject({ successfulWrites: 12, coveredWrites: 12, terminalAuditRows: 12, allCovered: true });
    expect(f.calls).toHaveLength(12); expect(f.calls.every(row => row.actorId === bootstrap.user.id && row.method === 'GET' && !row.path.includes('/by-key/'))).toBe(true);
    expect(JSON.stringify(proof)).not.toMatch(/cookie|csrf|SyntheticWebhookBearer/);
  });
  it.each(['actor', 'sid', 'key', 'requestId', 'bodyHash', 'body', 'CID', 'WID', 'path', 'query', 'status', 'unconfirmed', 'missing-receipt', 'original-unknown', 'extra-succeeded'])('rejects %s packet proof before any BFF read', async variant => {
    const f = fixture(), packet = f.h.state.requests[0], attempt = f.journal.attempts[0];
    if (variant === 'actor') packet.actorId = randomUUID();
    if (variant === 'sid') packet.sessionId = randomUUID();
    if (variant === 'key') packet.key = randomUUID();
    if (variant === 'requestId') packet.requestId = randomUUID();
    if (variant === 'bodyHash') packet.bodySha256 = '0'.repeat(64);
    if (variant === 'body') packet.body.name = 'forged';
    if (variant === 'CID') packet.clusterId = randomUUID();
    if (variant === 'WID') packet.workspaceId = randomUUID();
    if (variant === 'path') packet.path += '/foreign';
    if (variant === 'query') packet.query += '&extra=true';
    if (variant === 'status') { packet.status = attempt.status = 500; }
    if (variant === 'unconfirmed') { packet.state = attempt.state = 'response-observed'; }
    if (variant === 'missing-receipt') { delete packet.receiptData; delete attempt.receiptData; }
    if (variant === 'original-unknown') attempt.state = 'response_unknown';
    if (variant === 'extra-succeeded') f.h.state.requests.push({ method: 'POST', state: 'succeeded', status: 201, requestId: randomUUID() });
    await expect(auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow(); expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.public).toBeUndefined();
  });
  it('a complete client journal and receipt JSON alone cannot establish cleanup coverage', async () => {
    const f = fixture(); await expect(auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow('earlier actual protected receipt'); expect(f.h.request).not.toHaveBeenCalled();
  });
  it('a thirteenth arbitrary blocked-before-packet record cannot bypass the exact sealed unsent classifier', async () => {
    const f = fixture(); f.h.state.requests.push({ source: 'manual-ui', index: 12, manualIndex: 8, method: 'POST', state: 'blocked-before-packet', key: randomUUID() });
    await expect(auditManualUiReceiptsAcceptance(f.h, f.actors)).rejects.toThrow('complete original confirmed journal'); expect(f.h.request).not.toHaveBeenCalled();
    await expect(auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow('complete original confirmed journal'); expect(f.h.request).not.toHaveBeenCalled();
  });
  it('an ordinary observed packet with missing HTTP status is rejected even after all twelve UI receipts were independently proved', async () => {
    const f = fixture(); await auditManualUiReceiptsAcceptance(f.h, f.actors); f.h.request.mockClear();
    f.h.state.requests.push({ index: 12, method: 'POST', path: '/api/v1/iam/roles', state: 'response_observed', requestId: randomUUID(), actorId: f.sessions.admin.user.id });
    await expect(auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow('arbitrary succeeded states'); expect(f.h.request).not.toHaveBeenCalled();
    expect(f.h.public.auditWriteCoverage).toBeUndefined();
  });
  it.each(['absent', 'wrong-id', 'incomplete', 'wrong-result', 'wrong-key', 'wrong-scope'])('current actual %s receipt prevents proof completion even with retained succeeded JSON', async variant => {
    const f = fixture(), first = f.journal.attempts[0], actual = f.ledgers.get(first.key).receipt;
    if (variant === 'absent') f.ledgers.delete(first.key);
    if (variant === 'wrong-id') actual.id = randomUUID();
    if (variant === 'incomplete') actual.remote_completed = false;
    if (variant === 'wrong-result') actual.result.entity.name = 'forged';
    if (variant === 'wrong-key') { const event = f.ledgers.get(f.journal.attempts[1].key).receipt; event.idempotencyKey = randomUUID(); }
    if (variant === 'wrong-scope') actual.workspaceId = randomUUID();
    await expect(auditManualUiReceiptsAcceptance(f.h, f.actors)).rejects.toThrow();
    expect(f.h.state.manualUiAuditProof?.state).not.toBe('complete'); expect(f.h.public).toBeUndefined();
    await expect(auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow('earlier actual protected receipt');
  });
  it.each(['requestId', 'actor', 'WID', 'action', 'subject', 'transition', 'removed-row', 'partial-proof'])('final live %s change refuses100 percent closure', async variant => {
    const f = fixture(); await auditManualUiReceiptsAcceptance(f.h, f.actors);
    const packet = f.h.state.requests[0], row = f.auditRows.get(packet.requestId);
    if (variant === 'requestId') row.requestId = randomUUID();
    if (variant === 'actor') row.actorId = randomUUID();
    if (variant === 'WID') row.workspaceId = randomUUID();
    if (variant === 'action') row.action = 'not.the.original.action';
    if (variant === 'subject') row.entityId = randomUUID();
    if (variant === 'transition') { row.after.revision = 999; row.jsonPatch[0].value.revision = 999; }
    if (variant === 'removed-row') f.auditRows.delete(packet.requestId);
    if (variant === 'partial-proof') f.h.state.manualUiAuditProof.state = 'building';
    await expect(auditAllWritesCoverage(f.h, { ...f.actors, admin: session('bootstrap') })).rejects.toThrow();
    expect(f.h.public.auditWriteCoverage).toBeUndefined();
  });
  it('refuses new protected receipt proofs after cleanup rather than restoring or logging in an original actor', async () => {
    const f = fixture(); f.h.state.cleanupStarted = true;
    await expect(auditManualUiReceiptsAcceptance(f.h, f.actors)).rejects.toThrow('before cleanup'); expect(f.h.request).not.toHaveBeenCalled();
  });
});
