// @ts-nocheck -- Actual Node .mjs guard exports; all materials below are synthetic.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import {
  authorizeFreshBootstrap, authorizeRestoredManualSession, beforeManualMutation, completeManualMutation,
  createManualJournal, interruptManualMutation, manualJournalSummary,
} from './lib/m6-manual-journal.mjs';

const origin = role => role === 'owner' ? 'http://127.0.0.1:8082' : 'http://127.0.0.1:8080';
const cookieNames = role => role === 'owner' ? ['kongos_portal_access', 'kongos_portal_refresh', 'kongos_portal_csrf'] : ['kongos_access', 'kongos_refresh', 'kongos_csrf'];
const jwtShape = claims => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.synthetic-signature`;
function fixture() {
  const actors = Object.fromEntries(['owner', 'administrator', 'approver'].map(role => [role, { id: randomUUID(), username: `synthetic-${role}`, password: 'Synthetic!Manual2026' }]));
  const journal = createManualJournal({ clusterId: randomUUID(), workspaceId: randomUUID(), actors, content: { slug: 'synthetic-manual-page', title: 'Synthetic page', markdown: '# Safe page' } });
  const packet = (role, path, body, headers = {}) => ({ method: 'POST', url: `${origin(role)}${path}`, rawBody: JSON.stringify(body), headers: { 'x-idempotency-key': randomUUID(), ...headers } });
  for (const role of ['owner', 'administrator']) {
    authorizeFreshBootstrap(journal, role, [], () => {});
    const portal = role === 'owner', query = portal ? `?clusterId=${journal.clusterId}&workspaceId=${journal.workspaceId}` : '';
    if (portal) {
      const bootstrap = beforeManualMutation(journal, role, packet(role, `/api/v1/portal/auth/refresh${query}`, { clusterId: journal.clusterId, workspaceId: journal.workspaceId }), [], () => {});
      completeManualMutation(journal, bootstrap, 401, { meta: { requestId: randomUUID() }, error: { code: 'PORTAL_SESSION_EXPIRED' } }, () => {});
    }
    const body = { username: actors[role].username, password: actors[role].password, ...(portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {}) };
    const login = beforeManualMutation(journal, role, packet(role, `/api/v1/${portal ? 'portal/' : ''}auth/login${query}`, body), [], () => {});
    completeManualMutation(journal, login, 201, { meta: { requestId: randomUUID() }, data: portal ? { developer: { ...actors.owner, clusterId: journal.clusterId, workspaceId: journal.workspaceId, status: 'active' } } : { user: actors[role] } }, () => {});
  }
  // The separate immutable-checkpoint helper authorizes this marker in the
  // runner. These tests exercise only its new packet/refresh guard boundary.
  journal.detailRemainingContinuation = { version: 1, originalSnapshotSha256: 'a'.repeat(64) };
  const originals = structuredClone(journal.attempts);
  function material(role, expired = true) {
    const now = Math.floor(Date.now() / 1000), issuedAt = now - (expired ? 1800 : 1), sessionId = randomUUID(), portal = role === 'owner';
    const claims = { sid: sessionId, sub: actors[role].id, iat: issuedAt, exp: issuedAt + 900, ...(portal ? { cid: journal.clusterId, wid: journal.workspaceId } : {}) };
    const names = cookieNames(role), cookies = names.map((name, index) => ({ name, value: index === 0 ? jwtShape(claims) : index === 1 ? `${sessionId}.${'r'.repeat(64)}` : 'c'.repeat(64) }));
    const proof = { sessionId, issuedAt, accessExpired: expired, currentSessionVerified: true, originalLoginAudited: true, refreshVerified: true, csrfVerified: true };
    return { role, sessionId, claims, cookies, proof };
  }
  function refreshPacket(m) {
    const portal = m.role === 'owner', query = portal ? `?clusterId=${journal.clusterId}&workspaceId=${journal.workspaceId}` : '';
    return packet(m.role, `/api/v1/${portal ? 'portal/' : ''}auth/refresh${query}`, portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {}, {
      cookie: m.cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; '),
      [portal ? 'x-portal-csrf' : 'x-csrf-token']: m.cookies[2].value,
    });
  }
  function completeRefresh(m, attempt) {
    const portal = m.role === 'owner', now = Math.floor(Date.now() / 1000), names = cookieNames(m.role);
    const cookies = names.map((name, index) => ({ name, value: index === 0 ? jwtShape({ ...m.claims, iat: now, exp: now + 900 }) : index === 1 ? `${m.sessionId}.${'n'.repeat(64)}` : portal ? 'd'.repeat(64) : m.cookies[2].value }));
    const payload = { meta: { requestId: randomUUID() }, data: portal ? { developer: { id: actors.owner.id, username: actors.owner.username, clusterId: journal.clusterId, workspaceId: journal.workspaceId, status: 'active' }, csrfToken: cookies[2].value } : { user: actors.administrator } };
    completeManualMutation(journal, attempt, 201, payload, () => {}, cookies);
    return cookies;
  }
  const metadataPacket = () => packet('administrator', `/api/v1/clusters/${journal.clusterId}/portal/pages?workspaceId=${journal.workspaceId}`, journal.content);
  return { journal, originals, material, packet, refreshPacket, completeRefresh, metadataPacket };
}

describe('M6 original manual-session continuation delta', () => {
  it('durably binds both original sessions and each one refresh without advancing five unused intent positions', () => {
    const f = fixture(), saved = [];
    for (const role of ['owner', 'administrator']) {
      const m = f.material(role);
      authorizeRestoredManualSession(f.journal, role, m.proof, m.cookies, () => saved.push(structuredClone(f.journal)));
      expect(saved.at(-1).restoredSessions[role].sessionId).toBe(m.sessionId);
      const packet = f.refreshPacket(m), attempt = beforeManualMutation(f.journal, role, packet, m.cookies, () => saved.push(structuredClone(f.journal)));
      expect(saved.at(-1).inFlight).toBe(packet.headers['x-idempotency-key']);
      expect(saved.at(-1).attempts.at(-1)).toMatchObject({ key: packet.headers['x-idempotency-key'], rawBody: packet.rawBody, category: 'continuation-session-refresh', actorId: f.journal.actors[role].id });
      f.completeRefresh(m, attempt);
      expect(f.journal.nextIndex).toBe(2);
    }
    expect(f.journal.attempts.slice(0, 3)).toEqual(f.originals);
    expect(manualJournalSummary(f.journal)).toMatchObject({ plannedWrites: 2, continuationSessionRefreshWrites: 2, successfulContinuationSessionRefreshWrites: 2, complete: false });
  });

  it('does not refresh unexpired access even with a valid current same-SID proof', () => {
    const f = fixture(), m = f.material('administrator', false);
    authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
    expect(() => beforeManualMutation(f.journal, m.role, f.refreshPacket(m), m.cookies, () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(f.journal.attempts).toEqual(f.originals); expect(f.journal.phase).toBe('stopped-without-replay');
  });

  it('rejects a second refresh before sending it, preserving the first observed original-session result', () => {
    const f = fixture(), m = f.material('owner'); authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
    const first = beforeManualMutation(f.journal, m.role, f.refreshPacket(m), m.cookies, () => {}); f.completeRefresh(m, first);
    expect(() => beforeManualMutation(f.journal, m.role, f.refreshPacket(m), m.cookies, () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(first.state).toBe('response-observed-success'); expect(f.journal.attempts).toHaveLength(4); expect(f.journal.nextIndex).toBe(2);
  });

  it('keeps interrupted original key/body and globally blocks a different metadata endpoint or fallback login', () => {
    const f = fixture(), m = f.material('administrator'); authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
    const packet = f.refreshPacket(m), attempt = beforeManualMutation(f.journal, m.role, packet, m.cookies, () => {});
    interruptManualMutation(f.journal, attempt, () => {});
    expect(attempt).toMatchObject({ key: packet.headers['x-idempotency-key'], rawBody: packet.rawBody, state: 'transport-interrupted' });
    expect(() => beforeManualMutation(f.journal, 'administrator', f.metadataPacket(), m.cookies, () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(() => beforeManualMutation(f.journal, 'administrator', f.packet('administrator', '/api/v1/auth/login', { username: 'synthetic-administrator', password: 'Synthetic!Manual2026' }), [], () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(f.journal.attempts).toHaveLength(4); expect(f.journal.nextIndex).toBe(2);
  });

  it('private before-packet persistence failure closes the entire continuation without a sendable return', () => {
    const f = fixture(), m = f.material('administrator'); authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
    let sendable = false;
    expect(() => { beforeManualMutation(f.journal, m.role, f.refreshPacket(m), m.cookies, () => { throw new Error('synthetic fsync failure'); }); sendable = true; }).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(sendable).toBe(false); expect(f.journal.attempts.at(-1).state).toBe('private-save-failed-before-packet');
    expect(() => beforeManualMutation(f.journal, 'administrator', f.metadataPacket(), m.cookies, () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
  });

  it('rejects substituted SID, scope, original Cookie header, and Native/reveal endpoints before journaling a packet', () => {
    for (const vector of ['sid', 'scope', 'cookie', 'native', 'reveal']) {
      const f = fixture(), m = f.material('owner'); authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
      const packet = f.refreshPacket(m), cookies = structuredClone(m.cookies);
      if (vector === 'sid') cookies[1].value = `${randomUUID()}.${'r'.repeat(64)}`;
      if (vector === 'scope') packet.url = packet.url.replace(f.journal.workspaceId, randomUUID());
      if (vector === 'cookie') packet.headers.cookie += '; kongos_access=foreign-console-material';
      if (vector === 'native') packet.url = `${origin('owner')}/api/v1/clusters/${f.journal.clusterId}/entities/consumers`;
      if (vector === 'reveal') packet.url = `${origin('owner')}/api/v1/portal/applications/${randomUUID()}/grants/${randomUUID()}/credentials/${randomUUID()}/reveal`;
      expect(() => beforeManualMutation(f.journal, m.role, packet, cookies, () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
      expect(f.journal.attempts).toEqual(f.originals); expect(f.journal.nextIndex).toBe(2);
    }
  });

  it('a known refresh rejection stops the continuation without rearming or advancing any planned intent', () => {
    const f = fixture(), m = f.material('administrator'); authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
    const attempt = beforeManualMutation(f.journal, m.role, f.refreshPacket(m), m.cookies, () => {});
    expect(() => completeManualMutation(f.journal, attempt, 401, { meta: { requestId: randomUUID() }, error: { code: 'SESSION_EXPIRED' } }, () => {}, m.cookies)).toThrow('M6_MANUAL_WRITE_BLOCKED');
    expect(f.journal.nextIndex).toBe(2); expect(manualJournalSummary(f.journal).complete).toBe(false);
    expect(() => beforeManualMutation(f.journal, 'administrator', f.metadataPacket(), m.cookies, () => {})).toThrow('M6_MANUAL_WRITE_BLOCKED');
  });

  it('HTTP success with a different actor or new SID never proves original-session continuation', () => {
    for (const vector of ['actor', 'sid']) {
      const f = fixture(), m = f.material('owner'); authorizeRestoredManualSession(f.journal, m.role, m.proof, m.cookies, () => {});
      const attempt = beforeManualMutation(f.journal, m.role, f.refreshPacket(m), m.cookies, () => {}), now = Math.floor(Date.now() / 1000);
      const cookies = structuredClone(m.cookies); cookies[0].value = jwtShape({ ...m.claims, iat: now, exp: now + 900, ...(vector === 'sid' ? { sid: randomUUID() } : {}) }); cookies[1].value = `${m.sessionId}.${'n'.repeat(64)}`;
      const developer = { id: vector === 'actor' ? randomUUID() : f.journal.actors.owner.id, username: f.journal.actors.owner.username, clusterId: f.journal.clusterId, workspaceId: f.journal.workspaceId, status: 'active' };
      expect(() => completeManualMutation(f.journal, attempt, 201, { meta: { requestId: randomUUID() }, data: { developer, csrfToken: cookies[2].value } }, () => {}, cookies)).toThrow('M6_MANUAL_WRITE_BLOCKED');
      expect(f.journal.nextIndex).toBe(2); expect(f.journal.restoredSessions.owner.refreshed).toBe(false);
    }
  });
});
