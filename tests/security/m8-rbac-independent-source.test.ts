// @ts-nocheck -- real acceptance functions; pure RAM transport DTOs only.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { M8Harness, sha256 } from './lib/m8-harness.mjs';
import { m8RbacAcceptance, m8RbacStableAcceptance } from './lib/m8-rbac-acceptance.mjs';

function fixture(change = '') {
  const area = { cid: randomUUID(), wid: randomUUID() }, approval = { cid: randomUUID(), wid: randomUUID() }, foreign = { cid: area.cid, wid: randomUUID() };
  const actor = label => ({ label, user: { id: randomUUID(), username: `synthetic-${label}` }, sid: randomUUID(), cookie: `synthetic-${label}=ram`, csrf: `synthetic-${label}-csrf` });
  const actors = { admin: actor('admin'), owner: actor('owner'), other: actor('other-owner') }, readonly = actor('read-only');
  const oldSid = actors.owner.sid, role = { id: randomUUID(), name: 'Synthetic original workspace role' };
  let binding = { id: randomUUID(), role_id: role.id, role_name: role.name, user_id: actors.owner.user.id, cluster_id: area.cid, workspace_id: area.wid, status: 'active', revision: 1 };
  let currentSid = oldSid, oldLoggedOut = false;
  const jobs = new Map(), byKey = new Map(), calls = [], saves = [];
  const state = { version: 1, milestone: 'M8', testTag: 'm8-source-rbac-synthetic', phase: 'created', inFlight: null,
    scopes: { direct: area, approval, foreign }, nativeFixture: { area, service: { id: randomUUID(), retries: 2 }, consumer: { id: randomUUID() }, credentials: { 'key-auth': { id: randomUUID() } } },
    baseline: { snapshotId: randomUUID(), name: 'Synthetic original sealed baseline' },
    sessions: { admin: actors.admin, owner: actors.owner, 'other-owner': actors.other, 'read-only': readonly }, accounts: [{ label: 'owner', userId: actors.owner.user.id, username: actors.owner.user.username, password: 'SyntheticAa7!ownerPass', cid: area.cid, wid: area.wid, role, binding: structuredClone(binding) }],
    requests: [], configurationOperations: [], secrets: [], fixtures: [], cliIntents: [], proxyChecks: [],
    directTransfer: { importJobId: randomUUID(), applyJobId: randomUUID(), rollbackPlanJobId: randomUUID(), rollbackJobId: randomUUID() },
    approvalTransfer: { nativeSteps: 17 }, deckAcceptance: { actualProxyCredentialKinds: 6 } };
  const h = { state, public: {}, checks: [],
    check: M8Harness.prototype.check, data: M8Harness.prototype.data, assertWritable: M8Harness.prototype.assertWritable,
    login: M8Harness.prototype.login, updateSessionIdentity: M8Harness.prototype.updateSessionIdentity,
    remember: M8Harness.prototype.remember, cookies: M8Harness.prototype.cookies,
    save(extra = {}) { Object.assign(state, extra); saves.push({ phase: state.phase, journal: state.rbacJournal && structuredClone(state.rbacJournal) }); },
    async poll(read, predicate) { const value = await read(); h.check(predicate(value), 'synthetic one-page terminal job'); return value; },
    async request(session, path, method = 'GET', body, options = {}) {
      const url = new URL(`http://synthetic.invalid/api/v1${path}`), pathname = url.pathname;
      const operation = state.rbacJournal?.operations[state.rbacJournal.inFlight];
      calls.push({ session: session && structuredClone(session), path, method, body: body && structuredClone(body), options: structuredClone(options), prepared: operation && structuredClone(operation), saveCount: saves.length });
      if (operation) expect(saves.at(-1)?.journal?.operations[operation.index].state).toBe('prepared');
      const write = !['GET', 'HEAD'].includes(method);
      if (write) h.assertWritable();
      const packet = write ? { index: state.requests.length, key: options.key ?? randomUUID(), path: pathname, query: url.search, method,
        body: body === undefined ? undefined : structuredClone(body), bodySha256: sha256(body === undefined ? 'null' : JSON.stringify(body)),
        actorId: session?.user?.id ?? null, sessionId: session?.sid ?? null, clusterId: pathname.match(/\/clusters\/([a-f\d-]{36})/)?.[1] ?? null,
        workspaceId: url.searchParams.get('workspaceId'), headers: { ...(session ? { Cookie: session.cookie } : {}), 'X-Idempotency-Key': options.key ?? '' }, state: 'prepared' } : undefined;
      if (packet) { state.requests.push(packet); h.save({ phase: 'request-in-flight', inFlight: packet.index }); }
      if (change === 'unknownFirstWrite' && operation?.name === 'read-only-capture-denied'
        || change === 'unknownRestore' && operation?.name === 'restore-original-owner-binding') {
        packet.state = 'response_unknown'; h.save({ phase: 'stopped-unknown' }); throw Error('synthetic lost response');
      }
      let status = 200, data, code, setCookies = [];
      const deny = (value, errorCode = 'FORBIDDEN') => { status = value; code = errorCode; };
      if (pathname === '/api/v1/auth/me') {
        if (oldLoggedOut && session?.sid === oldSid) deny(401, 'SESSION_EXPIRED');
        else data = { user: session.user, csrfToken: session.csrf };
      } else if (pathname === '/api/v1/auth/me/sessions') {
        data = { items: [{ id: change === 'wrongPublicSid' ? randomUUID() : currentSid, current: true }], nextCursor: null, total: null, size: 100 };
      } else if (pathname === '/api/v1/auth/logout') {
        expect(options.renew).toBe(false); expect(session.sid).toBe(oldSid); oldLoggedOut = true; status = 201; data = { loggedOut: true };
      } else if (pathname === '/api/v1/auth/login') {
        expect(session).toBeNull(); expect(options.renew).toBe(false);
        expect(body).toEqual({ username: state.accounts[0].username, password: state.accounts[0].password });
        currentSid = change === 'sameLoginSid' ? oldSid : randomUUID();
        const jwt = `ram.${Buffer.from(JSON.stringify({ sub: actors.owner.user.id, sid: currentSid, exp: 4102444800 })).toString('base64url')}.ram`;
        setCookies = [`kongos_access=${jwt}; HttpOnly; SameSite=Strict`, 'kongos_csrf=synthetic-current-csrf; SameSite=Strict', 'kongos_refresh=synthetic-current-refresh; HttpOnly'];
        status = 201; data = { user: actors.owner.user, csrfToken: 'synthetic-current-csrf' };
      } else if (pathname.includes('/iam/users/') && pathname.endsWith('/role-bindings') && method === 'GET') {
        expect(session.user.id).toBe(actors.admin.user.id);
        expect(url.searchParams.get('clusterId')).toBe(area.cid); expect(url.searchParams.get('workspaceId')).toBe(area.wid);
        expect(url.searchParams.get('size')).toBe('100'); expect(url.searchParams.get('status')).toBe(binding.status);
        data = { items: [structuredClone(binding)], nextCursor: null, total: null, size: 100 };
      } else if (pathname.includes(`/role-bindings/${binding.id}`)) {
        expect(session.user.id).toBe(actors.admin.user.id);
        expect(body).toEqual({ revision: binding.revision, confirmed: true, confirm_name: role.name });
        binding = { ...binding, status: method === 'DELETE' ? 'revoked' : 'active', revision: binding.revision + 1 };
        status = method === 'DELETE' ? 200 : 201; data = structuredClone(binding);
      } else if (session.user.id === readonly.user.id) {
        if (change === 'successfulDenial') data = { accidentallyAllowed: true };
        else deny(403);
      } else if (pathname.includes(`/clusters/${approval.cid}/`) || url.searchParams.get('workspaceId') === foreign.wid) {
        pathname.includes('/snapshots/') ? deny(404, 'SNAPSHOT_NOT_FOUND') : deny(403);
      } else if (pathname.endsWith(`/snapshots/${state.nativeFixture.service.id}`)) {
        deny(404, 'SNAPSHOT_NOT_FOUND');
      } else if (pathname.endsWith('/snapshots') && method === 'POST' || /\/snapshots\/[a-f\d-]{36}\/export$/.test(pathname) && method === 'POST') {
        const capture = pathname.endsWith('/snapshots');
        const receipt = { domain: 'configuration', durable: true, jobId: randomUUID(), actorId: session.user.id, clusterId: area.cid, workspaceId: area.wid,
          originalScope: { clusterId: area.cid, workspaceId: area.wid }, idempotencyKey: packet.key, kind: capture ? 'capture' : 'export', state: 'succeeded',
          executionCompleted: true, capabilities: { download: !capture }, ...(capture ? { snapshotId: randomUUID() } : { exportId: randomUUID(), exportRevision: 1 }) };
        receipt.id = receipt.jobId; jobs.set(receipt.jobId, receipt); byKey.set(packet.key, receipt); status = 201; data = structuredClone(receipt);
        if (change === 'foreignOwnerReceipt' && capture) data.workspaceId = foreign.wid;
      } else if (pathname.includes('/configuration/jobs/by-key/')) {
        if (session.user.id === actors.other.user.id) deny(404, 'CONFIGURATION_RECEIPT_NOT_FOUND');
        else if (binding.status === 'revoked') deny(403);
        else { const key = pathname.split('/').at(-1); data = structuredClone(byKey.get(key)); h.check(data, 'known synthetic original receipt key'); }
      } else if (pathname.includes('/configuration/jobs/')) {
        if (session.user.id === actors.other.user.id || binding.status === 'revoked') deny(403, 'CONFIGURATION_JOB_ACCESS_DENIED');
        else { const id = pathname.split('/').at(-1); const job = jobs.get(id); if (job) data = { entity: structuredClone(job) }; else deny(403, 'CONFIGURATION_JOB_ACCESS_DENIED'); }
      } else if (/\/configuration\/exports\/[a-f\d-]{36}\/download$/.test(pathname)) {
        expect(session.user.id).toBe(actors.other.user.id); deny(404, 'CONFIGURATION_EXPORT_NOT_FOUND');
      } else if (pathname.endsWith('/configuration/deck-sessions')) {
        expect(body.purpose).toBe('read'); expect(jobs.get(body.jobId)?.kind).toBe('capture');
        expect(binding.status === 'revoked' || session.sid !== oldSid).toBe(true); deny(403, 'CONFIGURATION_JOB_ACCESS_DENIED');
      } else throw Error(`unexpected synthetic path: ${method} ${pathname}`);
      const requestId = randomUUID(), payload = code ? { success: false, error: { code } } : { success: true, data };
      if (packet) {
        Object.assign(packet, { state: 'response_observed', status, requestId }); h.save({ phase: 'request-observed', inFlight: null });
        if (change === 'wrongOwnerPacketSid' && operation?.name === 'owner-capture') packet.sessionId = randomUUID();
        if (change === 'missingLoginPacket' && pathname === '/api/v1/auth/login') state.requests.splice(state.requests.indexOf(packet), 1);
      }
      const result = { status, requestId, payload, bytes: Buffer.from(JSON.stringify(payload)), response: { headers: { getSetCookie: () => setCookies } } };
      h.check((options.expected ?? [200, 201]).includes(status), 'RAM transport exact endpoint status'); return result;
    } };
  return { h, state, actors, area, calls, saves, oldSid, binding: () => binding };
}

describe('independent SOURCE M8 RBAC acceptance, original packets and real-login boundary', () => {
  it('stable phase proves exact denials without mutating accounts, grants or sessions', async () => {
    const { h, state, actors, calls, oldSid } = fixture();
    const result = await m8RbacStableAcceptance(h, actors);
    expect(result).toMatchObject({ complete: false, stableCompleted: true, deniedCases: 13, identityChanges: 0 });
    expect(state.rbacJournal.phase).toBe('stable-complete'); expect(state.rbacJournal.inFlight).toBeNull();
    expect(actors.owner.sid).toBe(oldSid);
    expect(calls.some(call => /\/iam\/|\/auth\/(login|logout)/.test(call.path))).toBe(false);
    const writes = state.requests.filter(packet => packet.status < 300);
    expect(writes).toHaveLength(2); expect(writes.every(packet => packet.actorId === actors.owner.user.id && packet.sessionId === oldSid)).toBe(true);
    expect(state.fixtures).toHaveLength(1); expect(state.fixtures[0].type).toBe('config_snapshots');
    for (const packet of state.requests) expect(packet).toMatchObject({ state: 'response_observed', bodySha256: sha256(JSON.stringify(packet.body)) });
    expect(JSON.stringify(result)).not.toContain(state.accounts[0].password);
  });
  it('lost initial denial response durably stops at the original packet and cannot be replayed', async () => {
    const { h, state, actors, calls } = fixture('unknownFirstWrite');
    await expect(m8RbacStableAcceptance(h, actors)).rejects.toThrow('M8_RBAC_ORIGINAL_REQUEST_STOP_NO_REPLAY');
    expect(state.rbacJournal.phase).toBe('stopped-original-retained'); expect(state.requests).toHaveLength(1);
    expect(state.requests[0].state).toBe('response_unknown'); expect(state.rbacJournal.operations.at(-1).state).toBe('response_unknown');
    const count = calls.length; await expect(m8RbacStableAcceptance(h, actors)).rejects.toThrow();
    expect(calls).toHaveLength(count); expect(state.rbacJournal.identityPlan.phase).toBe('not-started');
  });
  it('rejects a substituted public SID before the first business write', async () => {
    const { h, state, actors } = fixture('wrongPublicSid');
    await expect(m8RbacStableAcceptance(h, actors)).rejects.toThrow('STOP_NO_REPLAY');
    expect(state.requests).toHaveLength(0); expect(state.rbacJournal.stableCompleted).toBeUndefined();
  });
  it('a successful write in a denial case can never be reported as an authorization success', async () => {
    const { h, state, actors } = fixture('successfulDenial');
    await expect(m8RbacStableAcceptance(h, actors)).rejects.toThrow('STOP_NO_REPLAY');
    expect(state.requests).toHaveLength(1); expect(state.requests[0].status).toBe(200); expect(state.rbacJournal.denied).toBe(0);
    expect(h.public.rbacStable).toBeUndefined();
  });
  it('requires exact original packet SID and the exact protected receipt scope', async () => {
    for (const change of ['wrongOwnerPacketSid', 'foreignOwnerReceipt']) {
      const { h, state, actors } = fixture(change);
      await expect(m8RbacStableAcceptance(h, actors), change).rejects.toThrow('STOP_NO_REPLAY');
      expect(state.requests.filter(packet => packet.status < 300)).toHaveLength(1);
      expect(state.rbacJournal.resources).toBeUndefined(); expect(h.public.rbacStable).toBeUndefined();
    }
  });
  it('does not start identity work until the original direct/approval/actual CLI executions finish', async () => {
    for (const incomplete of ['direct', 'approval', 'deck']) {
      const { h, state, actors, calls } = fixture();
      if (incomplete === 'direct') delete state.directTransfer;
      if (incomplete === 'approval') state.approvalTransfer.nativeSteps = 16;
      if (incomplete === 'deck') state.deckAcceptance.actualProxyCredentialKinds = 5;
      await expect(m8RbacAcceptance(h, actors), incomplete).rejects.toThrow('only after');
      expect(calls).toHaveLength(0); expect(state.rbacJournal).toBeUndefined();
    }
  });
  it('continues stable proof once, revokes/restores only the original binding, and uses real normal login parsing', async () => {
    const { h, state, actors, calls, oldSid, binding } = fixture();
    await m8RbacStableAcceptance(h, actors);
    const before = state.requests.length, result = await m8RbacAcceptance(h, actors);
    expect(result).toMatchObject({ complete: true, originalBindingRestored: true, originalSidRetainedAcrossGrantChange: true, normalNewSidProved: true,
      oldJobSafeReceiptReadable: true, oldJobNativeReadSessionDenied: true, oldJobExecutionAttempted: false, fakeSidsUsed: 0,
      newAccountsCreated: 0, newWorkspacesCreated: 0, identityChanges: 4, deniedCases: 17 });
    expect(binding()).toMatchObject({ status: 'active', revision: 3 }); expect(actors.owner.sid).not.toBe(oldSid); expect(state.sessions.owner.sid).toBe(actors.owner.sid);
    const tail = state.requests.slice(before), mutations = tail.filter(packet => packet.status < 300);
    expect(mutations.map(packet => [packet.method, packet.path.split('/').at(-1), packet.status])).toEqual([
      ['DELETE', binding().id, 200], ['POST', 'restore', 201], ['POST', 'logout', 201], ['POST', 'login', 201] ]);
    expect(tail.filter(packet => packet.path.endsWith('/deck-sessions'))).toHaveLength(2);
    expect(tail.some(packet => /\/execute$|\/apply$/.test(packet.path))).toBe(false);
    const logins = calls.filter(call => call.path === '/auth/login'); expect(logins).toHaveLength(1); expect(logins[0].options.renew).toBe(false);
    expect(state.rbacJournal.originalOwnerSession.sid).toBe(oldSid); expect(state.rbacJournal.identityPlan.newOwnerSid).toBe(actors.owner.sid);
    expect(state.rbacJournal.operations.every(operation => operation.state === 'response_observed')).toBe(true);
    const count = calls.length; await expect(m8RbacAcceptance(h, actors)).rejects.toThrow('only the exact'); expect(calls).toHaveLength(count);
    expect(JSON.stringify(result)).not.toContain(state.accounts[0].password);
  });
  it('stops an unknown binding restore without logout, login, automatic retry or falsely claiming restoration', async () => {
    const { h, state, actors, calls, binding } = fixture('unknownRestore');
    await expect(m8RbacAcceptance(h, actors)).rejects.toThrow('STOP_NO_REPLAY');
    expect(binding().status).toBe('revoked'); expect(state.rbacJournal.identityPlan.bindingRestored).toBeUndefined();
    expect(calls.some(call => ['/auth/logout', '/auth/login'].includes(call.path))).toBe(false);
    expect(state.requests.at(-1).state).toBe('response_unknown'); expect(state.rbacJournal.operations.at(-1).state).toBe('response_unknown');
    const count = calls.length; await expect(m8RbacAcceptance(h, actors)).rejects.toThrow(); expect(calls).toHaveLength(count);
  });
  it('rejects a same-SID login or an absent original login packet before any old job is read under the new session', async () => {
    for (const change of ['sameLoginSid', 'missingLoginPacket']) {
      const { h, state, actors, calls } = fixture(change);
      await expect(m8RbacAcceptance(h, actors), change).rejects.toThrow('STOP_NO_REPLAY');
      const login = calls.findIndex(call => call.path === '/auth/login'); expect(login).toBeGreaterThan(-1); expect(calls.slice(login + 1)).toHaveLength(0);
      expect(state.rbacAcceptance).toBeUndefined(); expect(state.rbacJournal.identityCompleted).toBeUndefined();
    }
  });
  it('never replays a completed stable phase or a foreign prepared identity boundary', async () => {
    const { h, state, actors, calls } = fixture(); await m8RbacStableAcceptance(h, actors);
    const count = calls.length; await expect(m8RbacStableAcceptance(h, actors)).rejects.toThrow('cannot be replayed'); expect(calls).toHaveLength(count);
    state.rbacJournal.identityPlan.phase = 'prepared'; await expect(m8RbacAcceptance(h, actors)).rejects.toThrow('only the exact'); expect(calls).toHaveLength(count);
  });
});
