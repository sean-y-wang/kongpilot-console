import * as fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';

export const MANUAL_ACTIONS = Object.freeze(['portal-owner-login', 'console-administrator-login', 'page-create', 'page-publish', 'page-archive', 'page-restore-draft', 'console-approver-login']);
export const manualUuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const roles = ['owner', 'administrator', 'approver'];
const authCookie = /^(?:kongos|kongos_portal)_(?:access|refresh)$/;
const exactKeys = (body, keys) => body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === keys.length && keys.every(key => Object.hasOwn(body, key));
function queryMatches(url, expected) {
  const entries = [...url.searchParams];
  return entries.length === Object.keys(expected).length && entries.every(([key, value]) => Object.hasOwn(expected, key) && expected[key] === value) && new Set(entries.map(([key]) => key)).size === entries.length;
}
function noAuthenticationCookies(cookies) {
  return Array.isArray(cookies) && cookies.every(cookie => cookie && typeof cookie.name === 'string' && !authCookie.test(cookie.name));
}
function cookieHeaderHasAuthentication(headers) {
  return String(headers.cookie ?? '').split(';').some(pair => authCookie.test(pair.trim().split('=')[0]));
}
export function collectManualUuidValues(value, found = new Set()) {
  if (manualUuid(value)) found.add(value);
  else if (Array.isArray(value)) for (const child of value) collectManualUuidValues(child, found);
  else if (value && typeof value === 'object') for (const child of Object.values(value)) collectManualUuidValues(child, found);
  return [...found];
}
export function createManualJournal(config) {
  if (!manualUuid(config?.clusterId) || !manualUuid(config.workspaceId) || !roles.every(role => manualUuid(config.actors?.[role]?.id) && typeof config.actors[role].username === 'string' && config.actors[role].username.length > 0 && typeof config.actors[role].password === 'string' && config.actors[role].password.length > 0)
    || new Set(roles.map(role => config.actors[role].id)).size !== 3 || !exactKeys(config.content, ['slug', 'title', 'markdown']) || !/^[a-z0-9][a-z0-9-]{0,79}$/.test(config.content.slug) || typeof config.content.title !== 'string' || !config.content.title || typeof config.content.markdown !== 'string' || !config.content.markdown) throw new Error('M6_MANUAL_CONTEXT_INVALID');
  const actors = Object.fromEntries(roles.map(role => [role, Object.freeze({ ...config.actors[role] })]));
  return { version: 1, source: 'manual-ui', phase: 'ready', clusterId: config.clusterId, workspaceId: config.workspaceId, actors: Object.freeze(actors), content: Object.freeze({ ...config.content }),
    priorKeys: [...new Set(config.priorKeys ?? [])], forbiddenEntityIds: [...new Set(config.forbiddenEntityIds ?? [])], nextIndex: 0, inFlight: null, pageId: null, pageRevision: null,
    authenticated: {}, freshContexts: {}, attempts: [], startedAt: new Date().toISOString() };
}
export function stopManualJournal(journal, reason, persist) {
  if (journal.phase !== 'stopped-without-replay') { journal.phase = 'stopped-without-replay'; journal.stopReason = reason; journal.stoppedAt = new Date().toISOString(); }
  persist();
}
function blocked(journal, reason, persist) {
  try { stopManualJournal(journal, reason, persist); } catch {}
  throw new Error('M6_MANUAL_WRITE_BLOCKED');
}
export function authorizeFreshBootstrap(journal, role, cookies, persist) {
  const expectedRole = { 'portal-owner-login': 'owner', 'console-administrator-login': 'administrator', 'console-approver-login': 'approver' }[MANUAL_ACTIONS[journal.nextIndex]];
  if (journal.phase === 'stopped-without-replay' || journal.inFlight || expectedRole !== role || journal.freshContexts[role] || !Array.isArray(cookies) || cookies.length !== 0) blocked(journal, 'fresh-context-proof-rejected', persist);
  journal.freshContexts[role] = { authorizedAt: new Date().toISOString(), initialCookieCount: 0, authenticationCookiesAbsent: true, expectedLoginActorId: journal.actors[role].id, bootstrapAttempted: false, bootstrapOutcome: null };
  try { persist(); } catch { blocked(journal, 'fresh-context-save-failed', persist); }
}
const restoredRoles = ['owner', 'administrator'];
const cookieNames = role => role === 'owner' ? ['kongos_portal_access', 'kongos_portal_refresh', 'kongos_portal_csrf'] : ['kongos_access', 'kongos_refresh', 'kongos_csrf'];
function namedCookies(cookies, role) {
  const names = cookieNames(role);
  if (!Array.isArray(cookies) || cookies.length !== 3 || new Set(cookies.map(cookie => cookie.name)).size !== 3 || cookies.some(cookie => !names.includes(cookie.name) || typeof cookie.value !== 'string' || !cookie.value)) throw new Error('M6_MANUAL_RESTORED_COOKIES_INVALID');
  return Object.fromEntries(cookies.map(cookie => [cookie.name, cookie.value]));
}
function accessClaims(value) { const parts = value.split('.'); if (parts.length !== 3) throw new Error(); return JSON.parse(Buffer.from(parts[1], 'base64url').toString()); }
export function authorizeRestoredManualSession(journal, role, proof, cookies, persist) {
  if (!journal.detailRemainingContinuation || !restoredRoles.includes(role) || journal.phase === 'stopped-without-replay' || journal.nextIndex !== 2 || journal.inFlight || journal.restoredSessions?.[role] || journal.authenticated[role] !== journal.actors[role].id
    || proof?.currentSessionVerified !== true || proof.originalLoginAudited !== true || proof.refreshVerified !== true || proof.csrfVerified !== true || !manualUuid(proof.sessionId) || typeof proof.accessExpired !== 'boolean') blocked(journal, 'original-session-proof-rejected', persist);
  let values, claims; try { values = namedCookies(cookies, role); claims = accessClaims(values[cookieNames(role)[0]]); } catch { blocked(journal, 'original-session-cookie-shape-rejected', persist); }
  if (claims.sid !== proof.sessionId || claims.sub !== journal.actors[role].id || claims.iat !== proof.issuedAt || values[cookieNames(role)[1]].split('.')[0] !== proof.sessionId || role === 'owner' && (claims.cid !== journal.clusterId || claims.wid !== journal.workspaceId)) blocked(journal, 'original-session-cookie-identity-rejected', persist);
  const login = journal.attempts.find(attempt => attempt.category === 'planned' && attempt.role === role && attempt.action.endsWith('-login'));
  journal.restoredSessions ??= {};
  journal.restoredSessions[role] = { actorId: journal.actors[role].id, sessionId: proof.sessionId, originalLoginRequestId: login.requestId, accessExpired: proof.accessExpired, originalCookies: structuredClone(cookies), refreshAttempted: false, refreshed: false };
  try { persist(); } catch { blocked(journal, 'original-session-proof-save-failed', persist); }
}
/** This function must complete its durable callback before route.continue(). */
export function beforeManualMutation(journal, role, packet, cookies, persist) {
  if (journal.phase === 'stopped-without-replay' || journal.phase === 'complete' || journal.inFlight || !roles.includes(role)) blocked(journal, 'write-window-not-ready', persist);
  let url, body;
  try {
    url = new URL(packet.url);
    if (url.username || url.password || url.hash || typeof packet.rawBody !== 'string' || Buffer.byteLength(packet.rawBody) > 512 * 1024) throw new Error();
    body = JSON.parse(packet.rawBody);
  } catch { blocked(journal, 'packet-shape-rejected', persist); }
  const headers = Object.fromEntries(Object.entries(packet.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
  const key = headers['x-idempotency-key'], actor = journal.actors[role], current = MANUAL_ACTIONS[journal.nextIndex];
  if (!manualUuid(key) || journal.priorKeys.includes(key) || journal.attempts.some(attempt => attempt.key === key)) blocked(journal, 'original-key-reused-or-invalid', persist);
  const portal = role === 'owner', origin = portal ? 'http://127.0.0.1:8082' : 'http://127.0.0.1:8080';
  if (url.origin !== origin) blocked(journal, 'packet-origin-rejected', persist);
  const refreshPath = portal ? '/api/v1/portal/auth/refresh' : '/api/v1/auth/refresh';
  const loginAction = portal ? 'portal-owner-login' : role === 'administrator' ? 'console-administrator-login' : 'console-approver-login';
  let action = current, category = 'planned', actorId = actor.id;
  if (url.pathname === refreshPath && journal.restoredSessions?.[role]) {
    const restored = journal.restoredSessions[role];
    let values; try { values = namedCookies(cookies, role); } catch { blocked(journal, 'restored-refresh-cookies-rejected', persist); }
    const original = Object.fromEntries(restored.originalCookies.map(cookie => [cookie.name, cookie.value]));
    const headerCookies = Object.fromEntries(String(headers.cookie ?? '').split(';').filter(Boolean).map(pair => { const index = pair.indexOf('='); return [pair.slice(0, index).trim(), pair.slice(index + 1)]; }));
    if (!journal.detailRemainingContinuation || packet.method !== 'POST' || restored.accessExpired !== true || restored.refreshAttempted || journal.authenticated[role] !== actor.id || restored.actorId !== actor.id
      || !queryMatches(url, portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {}) || !exactKeys(body, portal ? ['clusterId', 'workspaceId'] : []) || portal && (body.clusterId !== journal.clusterId || body.workspaceId !== journal.workspaceId)
      || String(headers.cookie ?? '').split(';').filter(Boolean).length !== 3 || Object.keys(headerCookies).length !== 3 || cookieNames(role).some(name => values[name] !== original[name] || headerCookies[name] !== original[name])
      || values[cookieNames(role)[1]].split('.')[0] !== restored.sessionId || headers[portal ? 'x-portal-csrf' : 'x-csrf-token'] !== original[cookieNames(role)[2]]) blocked(journal, 'restored-refresh-not-original-single-session', persist);
    category = 'continuation-session-refresh'; action = `${role}-original-session-refresh`; restored.refreshAttempted = true;
  } else if (url.pathname === refreshPath) {
    const fresh = journal.freshContexts[role];
    if (packet.method !== 'POST' || current !== loginAction || !fresh || fresh.bootstrapAttempted || journal.authenticated[role] || !noAuthenticationCookies(cookies) || cookieHeaderHasAuthentication(headers)
      || !queryMatches(url, portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {})
      || !exactKeys(body, portal ? ['clusterId', 'workspaceId'] : []) || portal && (body.clusterId !== journal.clusterId || body.workspaceId !== journal.workspaceId)) blocked(journal, 'anonymous-bootstrap-rejected', persist);
    action = `${role}-anonymous-bootstrap`; category = 'anonymous-bootstrap'; actorId = null; fresh.bootstrapAttempted = true;
  } else if (current === loginAction) {
    const loginPath = portal ? '/api/v1/portal/auth/login' : '/api/v1/auth/login';
    if (packet.method !== 'POST' || url.pathname !== loginPath || !journal.freshContexts[role] || !noAuthenticationCookies(cookies) || cookieHeaderHasAuthentication(headers) || !queryMatches(url, portal ? { clusterId: journal.clusterId, workspaceId: journal.workspaceId } : {})
      || !exactKeys(body, portal ? ['username', 'password', 'clusterId', 'workspaceId'] : ['username', 'password']) || body.username !== actor.username || body.password !== actor.password
      || portal && (body.clusterId !== journal.clusterId || body.workspaceId !== journal.workspaceId)) blocked(journal, 'trusted-login-rejected', persist);
  } else {
    const base = `/api/v1/clusters/${journal.clusterId}/portal/pages`;
    const expected = { 'page-create': ['POST', base], 'page-publish': ['POST', `${base}/${journal.pageId}/publish`], 'page-archive': ['DELETE', `${base}/${journal.pageId}`], 'page-restore-draft': ['POST', `${base}/${journal.pageId}/restore`] }[current];
    if (role !== 'administrator' || journal.authenticated.administrator !== actor.id || !expected || packet.method !== expected[0] || url.pathname !== expected[1] || !queryMatches(url, { workspaceId: journal.workspaceId })) blocked(journal, 'metadata-endpoint-rejected', persist);
    if (current === 'page-create') {
      if (journal.pageId || !exactKeys(body, ['slug', 'title', 'markdown']) || Object.keys(journal.content).some(field => body[field] !== journal.content[field])) blocked(journal, 'metadata-create-body-rejected', persist);
    } else if (!manualUuid(journal.pageId) || !exactKeys(body, ['revision', 'confirmed', 'confirm_name']) || body.revision !== journal.pageRevision || body.confirmed !== true || body.confirm_name !== journal.content.title) blocked(journal, 'metadata-fresh-revision-rejected', persist);
  }
  const attempt = { source: 'manual-ui', category, action, role, actorId, expectedLoginActorId: actor.id, method: packet.method, origin: url.origin, path: url.pathname, query: url.search.slice(1), key,
    rawBody: packet.rawBody, body, headers, clusterId: journal.clusterId, workspaceId: journal.workspaceId, state: 'before-single-send', startedAt: new Date().toISOString() };
  journal.attempts.push(attempt); journal.inFlight = key; journal.phase = 'active';
  try { persist(); } catch { attempt.state = 'private-save-failed-before-packet'; blocked(journal, 'before-packet-save-failed', persist); }
  return attempt;
}
export function manualAttemptForPacket(journal, role, packet) {
  try {
    const url = new URL(packet.url), headers = Object.fromEntries(Object.entries(packet.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
    return journal.attempts.find(attempt => attempt.role === role && attempt.method === packet.method && attempt.origin === url.origin && attempt.path === url.pathname && attempt.query === url.search.slice(1) && attempt.key === headers['x-idempotency-key'] && attempt.rawBody === packet.rawBody);
  } catch { return undefined; }
}
export function completeManualMutation(journal, attempt, status, payload, persist, cookies) {
  if (!journal.attempts.includes(attempt) || journal.inFlight !== attempt.key || journal.phase === 'stopped-without-replay') blocked(journal, 'response-without-original-attempt', persist);
  attempt.status = status; attempt.responseObservedAt = new Date().toISOString();
  if (manualUuid(payload?.meta?.requestId)) attempt.requestId = payload.meta.requestId;
  if (typeof payload?.error?.code === 'string' && /^[A-Z0-9_]{1,80}$/.test(payload.error.code)) attempt.errorCode = payload.error.code;
  if (attempt.category === 'continuation-session-refresh') {
    const restored = journal.restoredSessions?.[attempt.role], portal = attempt.role === 'owner', identity = portal ? payload?.data?.developer : payload?.data?.user;
    let values, claims; try { values = namedCookies(cookies, attempt.role); claims = accessClaims(values[cookieNames(attempt.role)[0]]); } catch { attempt.state = 'refresh-cookie-result-not-proven'; blocked(journal, 'original-session-refresh-result-unknown', persist); }
    if (status < 200 || status >= 300 || !attempt.requestId || !restored?.refreshAttempted || restored.refreshed || identity?.id !== restored.actorId || identity.username !== journal.actors[attempt.role].username
      || portal && (identity.clusterId !== journal.clusterId || identity.workspaceId !== journal.workspaceId || identity.status !== 'active' || payload.data.csrfToken !== values[cookieNames(attempt.role)[2]])
      || claims.sid !== restored.sessionId || claims.sub !== restored.actorId || portal && (claims.cid !== journal.clusterId || claims.wid !== journal.workspaceId) || values[cookieNames(attempt.role)[1]].split('.')[0] !== restored.sessionId || values[cookieNames(attempt.role)[1]] === restored.originalCookies.find(cookie => cookie.name === cookieNames(attempt.role)[1]).value || !Number.isFinite(claims.exp) || claims.exp <= Date.now() / 1000) {
      attempt.state = 'refresh-result-not-proven'; blocked(journal, 'original-session-refresh-result-unknown', persist);
    }
    restored.refreshed = true; restored.latestCookies = structuredClone(cookies); attempt.state = 'response-observed-success'; journal.inFlight = null;
    try { persist(); } catch { blocked(journal, 'original-session-refresh-save-failed', persist); }
    return true;
  }
  if (attempt.category === 'anonymous-bootstrap') {
    const code = attempt.role === 'owner' ? 'PORTAL_SESSION_EXPIRED' : 'SESSION_EXPIRED';
    if (status !== 401 || attempt.errorCode !== code || !attempt.requestId) { attempt.state = 'bootstrap-result-not-proven'; blocked(journal, 'anonymous-bootstrap-result-unknown', persist); }
    attempt.state = 'expected-auth-missing-rejection'; journal.freshContexts[attempt.role].bootstrapOutcome = 'known-401-authentication-missing'; journal.inFlight = null;
    try { persist(); } catch { blocked(journal, 'bootstrap-result-save-failed', persist); }
    return true;
  }
  if (status < 200 || status >= 300 || !payload || !attempt.requestId) { attempt.state = status >= 500 || !payload ? 'response-unknown' : 'failed-observed'; blocked(journal, 'planned-write-not-succeeded', persist); }
  const data = payload.data, actor = journal.actors[attempt.role];
  if (attempt.action.endsWith('-login')) {
    const identity = attempt.role === 'owner' ? data?.developer : data?.user;
    if (identity?.id !== actor.id || identity.username !== actor.username || attempt.role === 'owner' && (identity.clusterId !== journal.clusterId || identity.workspaceId !== journal.workspaceId || identity.status !== 'active')) { attempt.state = 'login-identity-not-proven'; blocked(journal, 'trusted-login-response-mismatch', persist); }
    journal.authenticated[attempt.role] = actor.id;
  } else {
    const entity = data?.entity, receipt = data?.receipt, expectedState = { 'page-create': 'draft', 'page-publish': 'published', 'page-archive': 'deleted', 'page-restore-draft': 'draft' }[attempt.action];
    // Direct changes of an existing page return the entity ACK, not a Workflow receipt.
    // Keep the original packet locked until a separate protected GET proves its IAM result.
    if (attempt.action !== 'page-create' && exactKeys(data, ['entity']) && exactKeys(entity, ['id', 'slug', 'title', 'revision', 'documentRevision', 'state']) && manualUuid(entity.id) && entity.id === journal.pageId && entity.slug === journal.content.slug && entity.title === journal.content.title && entity.state === expectedState && Number.isSafeInteger(entity.revision) && entity.revision === journal.pageRevision + 1) {
      attempt.acknowledgedEntity = structuredClone(entity); attempt.state = 'metadata-acknowledged-awaiting-original-iam-proof';
      try { persist(); } catch { blocked(journal, 'metadata-ack-save-failed', persist); }
      return false;
    }
    if (!manualUuid(entity?.id) || !manualUuid(data?.workflowId) || entity.id === data.workflowId || entity.slug !== journal.content.slug || entity.title !== journal.content.title || entity.state !== expectedState
      || !Number.isSafeInteger(entity.revision) || entity.revision < 1 || receipt?.state !== 'succeeded' || receipt.workflowId !== data.workflowId || receipt.clusterId !== journal.clusterId || receipt.workspaceId !== journal.workspaceId || receipt.idempotencyKey !== attempt.key
      || attempt.action === 'page-create' && (journal.pageId || journal.forbiddenEntityIds.includes(entity.id))
      || attempt.action !== 'page-create' && (entity.id !== journal.pageId || entity.revision !== journal.pageRevision + 1)) { attempt.state = 'metadata-receipt-not-proven'; blocked(journal, 'metadata-response-mismatch', persist); }
    if (attempt.action === 'page-create') journal.pageId = entity.id;
    journal.pageRevision = entity.revision; attempt.entityId = entity.id; attempt.workflowId = data.workflowId;
  }
  attempt.state = 'response-observed-success'; journal.inFlight = null; journal.nextIndex++;
  if (journal.nextIndex === MANUAL_ACTIONS.length) journal.phase = 'complete';
  try { persist(); } catch { blocked(journal, 'planned-result-save-failed', persist); }
  return true;
}
/** No POST replay: only the exact protected original-key IAM GET can finish an entity ACK. */
export function confirmManualIamMetadata(journal, attempt, read, persist) {
  let url; try { url = new URL(read.url); } catch { blocked(journal, 'iam-original-read-path-rejected', persist); }
  const receipt = read.payload?.data?.receipt, entity = receipt?.safe_result?.entity, expectedState = { 'page-publish': 'published', 'page-archive': 'deleted', 'page-restore-draft': 'draft' }[attempt?.action];
  if (journal.phase === 'stopped-without-replay' || journal.phase === 'complete' || !journal.attempts.includes(attempt) || journal.inFlight !== attempt.key || attempt.state !== 'metadata-acknowledged-awaiting-original-iam-proof' || attempt.role !== 'administrator' || attempt.action !== MANUAL_ACTIONS[journal.nextIndex]
    || read.method !== 'GET' || read.status !== 200 || url.origin !== 'http://127.0.0.1:8080' || url.pathname !== `/api/v1/clusters/${journal.clusterId}/portal/operations/by-key/${attempt.key}` || url.username || url.password || url.hash || !queryMatches(url, { workspaceId: journal.workspaceId })
    || read.actorId !== journal.actors.administrator.id || journal.authenticated.administrator !== read.actorId || !manualUuid(read.payload?.meta?.requestId) || read.payload?.data?.kind !== 'iam' || read.payload.data.state !== 'succeeded'
    || !manualUuid(receipt?.id) || receipt.state !== 'succeeded' || receipt.remote_completed !== true || receipt.error_code !== null || receipt.module !== 'portal' || receipt.action !== 'write' || receipt.target_id !== journal.pageId || receipt.cluster_id !== journal.clusterId || receipt.workspace_id !== journal.workspaceId
    || !expectedState || !exactKeys(entity, ['id', 'slug', 'title', 'revision', 'documentRevision', 'state']) || entity.id !== journal.pageId || entity.slug !== journal.content.slug || entity.title !== journal.content.title || entity.state !== expectedState || !Number.isSafeInteger(entity.revision) || entity.revision !== journal.pageRevision + 1 || Object.keys(entity).some(field => entity[field] !== attempt.acknowledgedEntity?.[field])) blocked(journal, 'iam-original-result-not-proven', persist);
  attempt.iamOperationId = receipt.id; attempt.iamReadRequestId = read.payload.meta.requestId; attempt.iamProofActorId = read.actorId; attempt.state = 'response-observed-success'; journal.pageRevision = entity.revision; journal.inFlight = null; journal.nextIndex++;
  if (journal.nextIndex === MANUAL_ACTIONS.length) journal.phase = 'complete';
  try { persist(); } catch { blocked(journal, 'iam-original-proof-save-failed', persist); }
  return true;
}
export function interruptManualMutation(journal, attempt, persist) {
  if (attempt && !['response-observed-success', 'expected-auth-missing-rejection'].includes(attempt.state)) attempt.state = 'transport-interrupted';
  stopManualJournal(journal, 'transport-interrupted', persist);
}
export function manualJournalSummary(journal) {
  const planned = journal.attempts.filter(attempt => attempt.category === 'planned'), bootstrap = journal.attempts.filter(attempt => attempt.category === 'anonymous-bootstrap'), refreshes = journal.attempts.filter(attempt => attempt.category === 'continuation-session-refresh');
  return { complete: journal.phase === 'complete' && journal.nextIndex === 7 && !journal.inFlight && planned.length === 7 && planned.every((attempt, index) => attempt.action === MANUAL_ACTIONS[index] && attempt.state === 'response-observed-success') && bootstrap.length <= 3 && bootstrap.every(attempt => attempt.state === 'expected-auth-missing-rejection') && refreshes.length <= 2 && new Set(refreshes.map(attempt => attempt.role)).size === refreshes.length && refreshes.every(attempt => restoredRoles.includes(attempt.role) && attempt.state === 'response-observed-success') && journal.attempts.length === planned.length + bootstrap.length + refreshes.length,
    plannedWrites: planned.length, successfulPlannedWrites: planned.filter(attempt => attempt.state === 'response-observed-success').length, expectedDeniedAnonymousBootstrapWrites: bootstrap.filter(attempt => attempt.state === 'expected-auth-missing-rejection').length,
    ...(refreshes.length ? { continuationSessionRefreshWrites: refreshes.length, successfulContinuationSessionRefreshWrites: refreshes.filter(attempt => attempt.state === 'response-observed-success').length } : {}),
    stoppedWithoutReplay: journal.phase === 'stopped-without-replay', actions: journal.attempts.map(({ category, action, state, status, requestId }) => ({ category, action, state, status, requestId })) };
}
/** Exclusive private file, file sync, atomic replacement, then directory sync. */
export function writeManualReferenceAtomic(path, value, io = fs, unique = randomUUID) {
  const content = JSON.stringify(value);
  if (Buffer.byteLength(content) > 16 * 1024 * 1024) throw new Error('M6_MANUAL_REFERENCE_TOO_LARGE');
  const temporary = `${path}.${unique()}.manual.tmp`; let file, directory, created = false, renamed = false;
  try {
    file = io.openSync(temporary, 'wx', 0o600); created = true;
    io.writeFileSync(file, content, 'utf8'); io.fsyncSync(file); io.closeSync(file); file = undefined;
    io.renameSync(temporary, path); renamed = true;
    directory = io.openSync(dirname(path), 'r'); io.fsyncSync(directory); io.closeSync(directory); directory = undefined;
  } finally {
    if (file !== undefined) try { io.closeSync(file); } catch {}
    if (directory !== undefined) try { io.closeSync(directory); } catch {}
    if (created && !renamed) try { io.unlinkSync(temporary); } catch {}
  }
}
