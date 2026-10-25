import { isDeepStrictEqual } from 'node:util';
import { sha256 } from './m8-harness.mjs';

export const M8_UI_ACTIONS = Object.freeze(['snapshot.capture', 'review.export', 'review.download', 'schedule.create', 'schedule.pause', 'schedule.archive', 'schedule.restore', 'gitops.record', 'snapshot.archive', 'snapshot.restore', 'noop.import', 'plan.reconcile']);
export const M8_UI_NOOP_YAML = '_format_version: "1.1"\nservices: []\n';
export const m8UiUuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const roles = ['admin', 'owner', 'readonly'];
const positive = value => Number.isSafeInteger(value) && value > 0;
const exactQuery = (url, expected) => [...url.searchParams].length === Object.keys(expected).length && [...url.searchParams].every(([key, value]) => expected[key] === value);
const confirm = row => ({ revision: row.revision, confirmed: true, confirm_name: row.name });
const secretNames = /^(?:password|current_password|new_password|secret|token|tokenSecret|authorization|csrfToken|client_secret|accessToken|refreshToken|access_token|refresh_token|id_token|rsa_private_key)$/i;

export function m8UiRemember(value, found = new Set()) {
  if (!value || typeof value !== 'object') return found;
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string' && secretNames.test(key) && !/^\[REDACTED(?::[a-f\d]{16})?\]$/.test(item)) found.add(item);
    else if (item && typeof item === 'object') m8UiRemember(item, found);
  }
  return found;
}

export function m8UiCookies(session, now = Date.now(), minimumSeconds = 300) {
  if (!m8UiUuid(session?.user?.id) || !m8UiUuid(session.sid) || !Number.isFinite(session.expiresAt) || session.expiresAt < now + minimumSeconds * 1000 || typeof session.cookie !== 'string') throw Error('M8_UI_ORIGINAL_SESSION_LIFETIME_REQUIRED');
  const pairs = session.cookie.split('; ').map(pair => { const at = pair.indexOf('='); return { name: pair.slice(0, at), value: pair.slice(at + 1) }; });
  if (pairs.length !== 3 || new Set(pairs.map(row => row.name)).size !== 3 || !['kongos_access', 'kongos_refresh', 'kongos_csrf'].every(name => pairs.some(row => row.name === name && row.value))) throw Error('M8_UI_EXACT_ORIGINAL_COOKIES_REQUIRED');
  let claims; try { claims = JSON.parse(Buffer.from(pairs.find(row => row.name === 'kongos_access').value.split('.')[1], 'base64url')); } catch { throw Error('M8_UI_ORIGINAL_ACCESS_FORMAT_INVALID'); }
  if (claims.sub !== session.user.id || claims.sid !== session.sid || claims.exp * 1000 !== session.expiresAt || pairs.find(row => row.name === 'kongos_refresh').value.split('.')[0] !== session.sid || pairs.find(row => row.name === 'kongos_csrf').value !== session.csrf) throw Error('M8_UI_ORIGINAL_COOKIE_IDENTITY_CHANGED');
  // Signature/current session validation is inherited from Security's real
  // handoff; the browser proves the current same actor through its own GET/me.
  return pairs.map(row => ({ ...row, domain: '127.0.0.1', path: row.name === 'kongos_refresh' ? '/api/v1/auth' : '/api', httpOnly: row.name !== 'kongos_csrf', secure: false, sameSite: 'Strict' }));
}

export function createM8UiJournal({ handoff, sessions, priorKeys = [], now = Date.now() }) {
  if (handoff?.version !== 1 || handoff.phase !== 'ready' || !/^m8-security-[a-f\d]{8}$/.test(handoff.testTag) || !m8UiUuid(handoff.direct?.cid) || !m8UiUuid(handoff.direct.wid) || typeof handoff.directWorkspaceName !== 'string' || !handoff.directWorkspaceName || !isDeepStrictEqual(handoff.approvedActions, M8_UI_ACTIONS) || !roles.every(role => sessions?.[role]?.user?.username) || new Set(roles.map(role => sessions[role].user.id)).size !== 3 || !['snapshotId', 'planId', 'jobId', 'exportId', 'approvalWorkflowId'].every(key => m8UiUuid(handoff[key])) || handoff.approvalMode !== 'completed-read-only') throw Error('M8_UI_TRUSTED_HANDOFF_REQUIRED');
  for (const role of roles) m8UiCookies(sessions[role], now);
  const prefix=handoff.manualNamePrefix??handoff.testTag;
  if(prefix!==handoff.testTag&&(!prefix.startsWith(`${handoff.testTag}-fresh-`)||!/^[a-z\d-]{1,64}$/.test(prefix)))throw Error('M8_UI_FRESH_NAME_PREFIX_REQUIRED');
  return { version: 1, milestone: 'M8', source: 'manual-ui', phase: 'ready', testTag: handoff.testTag, scope: structuredClone(handoff.direct), sessions: structuredClone(sessions), workspaceName: handoff.directWorkspaceName, names: { snapshot: `${prefix}-ui-snapshot`, schedule: `${prefix}-ui-schedule`, repository: `${prefix}/ui-config` }, seed: { planId: handoff.planId, jobId: handoff.jobId, snapshotId: handoff.snapshotId }, priorKeys: [...priorKeys], authenticated: {}, bindings: {}, attempts: [], nextIndex: 0, inFlight: null, startedAt: new Date(now).toISOString() };
}

export function stopM8Ui(journal, reason, persist) { journal.phase = 'stopped-without-replay'; journal.stopReason ??= reason; journal.stoppedAt ??= new Date().toISOString(); persist(); }
function reject(journal, reason, persist) { try { stopM8Ui(journal, reason, persist); } catch { /* Never permit transport after a persistence failure. */ } throw Error('M8_UI_ORIGINAL_PACKET_STOPPED'); }
function currentSession(journal,role){const original=journal.sessions[role],current=journal.currentSessions?.[role]??original;if(current?.user?.id!==original?.user.id||current.sid!==original.sid||current.user.username!==original.user.username)throw Error('M8_UI_NORMAL_SESSION_IDENTITY_CHANGED');return current;}
export function proveM8UiActor(journal, role, data, persist) {
  const session = currentSession(journal,role);
  if (!roles.includes(role) || journal.phase === 'stopped-without-replay' || data?.user?.id !== session?.user.id || data.user.username !== session.user.username || data.csrfToken !== session.csrf || typeof data.user.permissionsVersion !== 'string' || !data.user.permissionsVersion) reject(journal, 'current-original-actor-not-proven', persist);
  journal.authenticated[role] = { id: data.user.id, sid: session.sid, permissionsVersion: data.user.permissionsVersion, observedAt: new Date().toISOString() }; persist();
}
export function bindM8UiEntity(journal, name, value, persist) {
  const allowed = { snapshot: ['snapshot.capture', 'snapshot.archive', 'snapshot.restore'], schedule: ['schedule.create', 'schedule.pause', 'schedule.archive', 'schedule.restore'], export: ['review.export'], plan: ['seed-read'] };
  if (!allowed[name] || !m8UiUuid(value?.id) || value.clusterId !== journal.scope.cid || value.workspaceId !== journal.scope.wid || !positive(value.revision) || name === 'snapshot' && value.id !== journal.bindings.captureId || name === 'plan' && (value.id !== journal.seed.planId || !positive(value.planRevision) || !/^[a-f\d]{64}$/i.test(value.planHash)) || journal.bindings[name] && journal.bindings[name].id !== value.id) reject(journal, 'current-safe-entity-scope-not-matched', persist);
  journal.bindings[name] = structuredClone(value); persist();
}

export function m8UiExpected(journal) {
  const root = `/api/v1/clusters/${journal.scope.cid}`, query = { workspaceId: journal.scope.wid }, b = journal.bindings, selection = { scope: 'workspace', serviceIds: [] }, shared = { intervalMinutes: 60, timezone: 'UTC', retentionDays: 30 };
  switch (M8_UI_ACTIONS[journal.nextIndex]) {
    case 'snapshot.capture': return { method: 'POST', path: `${root}/snapshots`, query, kind: 'capture', body: { ...selection, name: journal.names.snapshot, description: '' } };
    case 'review.export': return { method: 'POST', path: `${root}/configuration/exports`, query, kind: 'export', body: { ...selection, mode: 'review', confirmed: true, confirm_name: journal.workspaceName } };
    case 'review.download': return b.export && { method: 'POST', path: `${root}/configuration/exports/${b.export.exportId}/download`, query, kind: 'export', binary: true, body: { revision: b.export.exportRevision, confirmed: true, confirm_name: b.export.confirmationName } };
    case 'schedule.create': return { method: 'POST', path: `${root}/snapshots/schedules`, query, kind: 'compare', body: { ...selection, ...shared, name: journal.names.schedule, confirmed: true, confirm_name: journal.names.schedule } };
    case 'schedule.pause': return b.schedule && { method: 'PATCH', path: `${root}/snapshots/schedules/${b.schedule.id}`, query, kind: 'compare', body: { ...selection, ...shared, name: b.schedule.name, revision: b.schedule.revision, paused: true, confirmed: true, confirm_name: b.schedule.name } };
    case 'schedule.archive': return b.schedule && { method: 'DELETE', path: `${root}/snapshots/schedules/${b.schedule.id}`, query, kind: 'compare', body: confirm(b.schedule) };
    case 'schedule.restore': return b.schedule && { method: 'POST', path: `${root}/snapshots/schedules/${b.schedule.id}/restore`, query, kind: 'compare', body: confirm(b.schedule) };
    case 'gitops.record': return { method: 'POST', path: `${root}/configuration/gitops/runs`, query, kind: 'compare', body: { jobId: journal.seed.jobId, repositoryLabel: journal.names.repository, commitSha: 'a'.repeat(40), pipelineReference: 'manual-ui/source-check' } };
    case 'snapshot.archive': return b.snapshot && { method: 'POST', path: `${root}/snapshots/${b.snapshot.id}/archive`, query, kind: 'compare', body: confirm(b.snapshot) };
    case 'snapshot.restore': return b.snapshot && { method: 'POST', path: `${root}/snapshots/${b.snapshot.id}/restore`, query, kind: 'compare', body: confirm(b.snapshot) };
    case 'noop.import': return { method: 'POST', path: `${root}/configuration/imports`, query, kind: 'import', body: { ...selection, mode: 'merge', yaml: M8_UI_NOOP_YAML } };
    case 'plan.reconcile': return b.plan && { method: 'POST', path: `${root}/configuration/plans/${b.plan.id}/reconcile`, query, kind: 'reconcile', body: { revision: b.plan.revision, planHash: b.plan.planHash } };
  }
}

export function beforeM8UiPacket(journal, role, packet, cookies, persist, now = Date.now()) {
  const expected = m8UiExpected(journal), session = currentSession(journal,role), headers = Object.fromEntries(Object.entries(packet.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
  const attempt = { index: journal.attempts.length, action: M8_UI_ACTIONS[journal.nextIndex] ?? null, role, actorId: journal.authenticated[role]?.id ?? null, sessionId: session?.sid ?? null, method: packet.method, url: packet.url, key: headers['x-idempotency-key'] ?? null, rawBody: packet.rawBody ?? null, headers, clusterId: journal.scope.cid, workspaceId: journal.scope.wid, state: 'blocked-before-packet', startedAt: new Date(now).toISOString() }; journal.attempts.push(attempt);
  if (journal.phase !== 'ready' || journal.inFlight !== null || !expected || role !== 'admin' || !journal.authenticated[role] || !m8UiUuid(attempt.key) || journal.priorKeys.includes(attempt.key) || journal.attempts.slice(0, -1).some(row => row.key === attempt.key)) reject(journal, 'only-unused-frozen-metadata-intent', persist);
  let url, body; try { url = new URL(packet.url); body = JSON.parse(packet.rawBody); } catch { reject(journal, 'original-wire-not-json', persist); }
  if (url.origin !== 'http://127.0.0.1:8080' || url.hash || url.username || url.password || packet.method !== expected.method || url.pathname !== expected.path || !exactQuery(url, expected.query) || !isDeepStrictEqual(body, expected.body) || !/^application\/json(?:\s*;|$)/i.test(headers['content-type'] ?? '') || headers.authorization) reject(journal, 'exact-endpoint-query-body-required', persist);
  const originals = Object.fromEntries(session.cookie.split('; ').map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at), pair.slice(at + 1)]; })), sent = Object.fromEntries(String(headers.cookie ?? '').split(';').map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at).trim(), pair.slice(at + 1)]; }));
  if (session.expiresAt <= now || headers['x-csrf-token'] !== session.csrf || !Array.isArray(cookies) || ['kongos_access', 'kongos_csrf'].some(name => sent[name] !== originals[name] || !cookies.some(row => row.name === name && row.value === originals[name]))) reject(journal, 'original-actor-session-csrf-required', persist);
  Object.assign(attempt, { state: 'prepared', path: url.pathname, query: url.search, body, bodySha256: sha256(packet.rawBody), kind: expected.kind, binary: expected.binary === true, originalSession:structuredClone(session) }); journal.inFlight = attempt.index;
  try { persist(); } catch { reject(journal, 'durable-before-packet-save-failed', persist); } return attempt;
}
export function m8UiAttemptFor(journal, packet) { const headers = Object.fromEntries(Object.entries(packet.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])); return journal.attempts.find(row => row.state === 'prepared' && row.method === packet.method && row.url === packet.url && row.rawBody === packet.rawBody && row.key === headers['x-idempotency-key']); }
export function observeM8UiAck(journal, attempt, { status, requestId, data, binary }, persist) {
  if (journal.phase !== 'ready' || !attempt || journal.attempts[journal.inFlight] !== attempt || attempt.state !== 'prepared' || ![200, 201, 202].includes(status) || !m8UiUuid(requestId)) reject(journal, 'known-original-acknowledgement-required', persist);
  if (attempt.binary && (!binary || !positive(binary.bytes) || binary.bytes > 32 * 1024 * 1024 || !/^[a-f\d]{64}$/.test(binary.sha256) || binary.noStore !== true || binary.nosniff !== true || binary.yaml !== true || binary.exportId !== journal.bindings.export.exportId)) reject(journal, 'bounded-original-file-response-required', persist);
  Object.assign(attempt, { state: 'acknowledged', status, requestId, responseData: data ?? null, ...(attempt.binary ? { binary } : {}) }); persist();
}
export function m8UiReceiptPath(journal, attempt) { return `/api/v1/clusters/${journal.scope.cid}/configuration/jobs/by-key/${attempt.key}?workspaceId=${journal.scope.wid}`; }
export function confirmM8UiReceipt(journal, role, packet, receipt, requestId, persist) {
  const attempt = journal.attempts[journal.inFlight];
  if (journal.phase !== 'ready' || role !== 'admin' || !attempt || attempt.state !== 'acknowledged' || packet.method !== 'GET' || packet.url !== `http://127.0.0.1:8080${m8UiReceiptPath(journal, attempt)}` || !m8UiUuid(requestId)) reject(journal, 'original-protected-receipt-required', persist);
  const job = receipt?.job;
  if (receipt?.domain !== 'configuration' || receipt.durable !== true || receipt.idempotencyKey !== attempt.key || receipt.actorId !== attempt.actorId || receipt.clusterId !== journal.scope.cid || receipt.workspaceId !== journal.scope.wid || receipt.originalScope?.clusterId !== journal.scope.cid || receipt.originalScope.workspaceId !== journal.scope.wid || !m8UiUuid(receipt.jobId) || receipt.jobId !== job?.id || job.actorId !== attempt.actorId || job.clusterId !== journal.scope.cid || job.workspaceId !== journal.scope.wid || receipt.kind !== attempt.kind || job.kind !== attempt.kind || receipt.state !== job.state) reject(journal, 'original-receipt-authority-not-matched', persist);
  if (['pending', 'running', 'capturing', 'planning', 'ready'].includes(receipt.state)) return false;
  if (receipt.state !== 'succeeded' || receipt.executionCompleted !== true || receipt.workflowId) reject(journal, 'terminal-direct-metadata-receipt-not-proven', persist);
  if (attempt.binary && (receipt.exportId !== journal.bindings.export.exportId || receipt.downloadPermitConsumed !== true || receipt.byteCount !== attempt.binary.bytes)) reject(journal, 'download-permit-does-not-match-received-file', persist);
  const action = attempt.action;
  if (action === 'snapshot.capture') {
    if (!m8UiUuid(receipt.snapshotId)) reject(journal, 'actual-capture-snapshot-id-required', persist);
    journal.bindings.captureId = receipt.snapshotId;
  }
  if (action === 'review.export') {
    if (!m8UiUuid(receipt.exportId) || !positive(receipt.exportRevision) || receipt.mode !== 'review' || receipt.capabilities?.download !== true || typeof receipt.confirmationName !== 'string') reject(journal, 'actual-artifact-revision-and-capability-required', persist);
    bindM8UiEntity(journal, 'export', receipt.job, persist);
  }
  if (action.startsWith('schedule.') || ['snapshot.archive', 'snapshot.restore'].includes(action) || action === 'gitops.record') {
    const entity = attempt.responseData?.entity;
    if (!m8UiUuid(receipt.resourceId) || entity?.id !== receipt.resourceId || entity.clusterId !== journal.scope.cid || entity.workspaceId !== journal.scope.wid) reject(journal, 'metadata-resource-ack-and-receipt-required', persist);
    if (action.startsWith('schedule.')) {
      const state = action === 'schedule.create' ? 'active' : action === 'schedule.archive' ? 'deleted' : 'paused';
      if (entity.name !== journal.names.schedule || entity.state !== state || entity.scopeKind !== 'workspace' || entity.rootIds?.length !== 0 || entity.ownerUserId !== attempt.actorId) reject(journal, 'exact-schedule-state-owner-and-scope-required', persist);
      bindM8UiEntity(journal, 'schedule', entity, persist);
    }
    if (action.startsWith('snapshot.')) {
      if (entity.name !== journal.names.snapshot || entity.state !== (action === 'snapshot.archive' ? 'deleted' : 'ready')) reject(journal, 'exact-snapshot-restoration-state-required', persist);
      bindM8UiEntity(journal, 'snapshot', entity, persist);
    }
  }
  if (action === 'plan.reconcile') {
    const progress = job.safeProgress;
    if (progress?.readOnly !== true || progress.executionChanged !== false || progress.reconciledPlanId !== journal.seed.planId || !Array.isArray(progress.observations) || progress.observations.length !== journal.bindings.plan.stepCount || progress.observations.some(row => row.causalOutcomeUnproven !== true)) reject(journal, 'read-only-observation-not-original-write-proof', persist);
  }
  if (action === 'noop.import' && (receipt.deleteCount !== 0 || receipt.stepCount !== 0 || !m8UiUuid(receipt.planId))) reject(journal, 'empty-merge-must-have-zero-native-plan', persist);
  Object.assign(attempt, { state: 'succeeded', receiptRequestId: requestId, jobId: receipt.jobId, receipt: structuredClone(receipt), completedAt: new Date().toISOString() }); journal.nextIndex++; journal.inFlight = null;
  if (journal.nextIndex === M8_UI_ACTIONS.length) journal.phase = 'complete'; persist(); return true;
}
export function interruptM8Ui(journal, attempt, persist) { if (attempt?.state === 'prepared') attempt.state = 'response_unknown'; reject(journal, 'original-response-unknown-no-replay', persist); }
