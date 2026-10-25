import { readFileSync } from 'node:fs';
import { M7Harness, durableJson, sha256 } from './lib/m7-harness.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_UI_UNUSED_TAIL_SESSION_MAINTENANCE_READY !== 'true') throw new Error('M7_EXCLUSIVE_ORIGINAL_SESSION_MAINTENANCE_REQUIRED');
const h = new M7Harness({ resume: true }), path = 'artifacts/M7/manual-ui-unused-tail-session-maintenance.json';
let failure;
try {
  const journal = h.state.manualUiJournal, priorPhase = h.state.phase, digest = sha256(JSON.stringify(h.state.requests));
  const bytes = readFileSync('artifacts/M7/manual-ui.json'), originalFailureSha256 = sha256(bytes), report = JSON.parse(bytes);
  h.check(originalFailureSha256 === '2a0bb39ed2ec5c41c90e75998ab37b88cf3c72a1b27a67a5c6ae86c0d4cef71d' && report.allPassed === false && report.testTag === h.state.testTag,
    'normal maintenance retains the exact five-success unused-tail UI failure');
  h.check(priorPhase === 'stopped-ui-no-replay' && journal?.phase === 'stopped-without-replay' && journal.attempts.length === 5 && journal.nextIndex === 5 && journal.attempts.every(a => a.state === 'succeeded' && typeof a.receiptRequestId === 'string' && a.receiptData != null) && journal.inFlight === null && h.state.inFlight === null &&
    !h.state.manualUiUnusedTailSessionRenewal && h.state.manualUiNormalRenewal?.state === 'completed' && h.state.requests.length === h.state.manualUiNormalRenewal.originalPackets + h.state.manualUiNormalRenewal.authWrites + 5 && h.state.requests.every(p => p.state === 'response_observed' || p.source === 'manual-ui' && p.state === 'succeeded' && journal.attempts.some(a => a.index === p.manualIndex && ['key', 'requestId', 'bodySha256', 'actorId', 'sessionId', 'path', 'query', 'method', 'clusterId', 'workspaceId', 'receiptRequestId'].every(k => a[k] === p[k]))), 'normal maintenance follows only the original five-success unused-tail stop');
  const journalDigest = sha256(JSON.stringify(journal)), historyDigest = sha256(JSON.stringify(h.state.manualUiHistory));
  retainM7History(h.state, 'manualUiUnusedTailSessionRenewalHistory');
  h.state.manualUiUnusedTailSessionRenewal = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalFailureSha256, originalPackets: h.state.requests.length, originalPacketsSha256: digest,
    originalJournalSha256: journalDigest, originalHistorySha256: historyDigest, authWrites: 0, requestIds: [] };
  h.save({ phase: 'normal-original-session-maintenance' });
  for (const label of ['admin', 'owner', 'read-only']) {
    const session = h.state.sessions[label], actorId = session?.user?.id, username = session?.user?.username, sid = session?.sid;
    h.check(session && typeof actorId === 'string' && typeof sid === 'string', 'normal maintenance uses a captured original named session', { label });
    if (session.expiresAt <= Date.now() + 300000) {
      const result = await h.request(session, '/auth/refresh', 'POST', {}, { expected: [201], renew: false }), data = h.data(result);
      h.check(data.user?.id === actorId && data.user?.username === username, 'normal maintenance retains the exact original actor and username', { label });
      session.csrf = session.cookie.split('; ').find(v => v.startsWith('kongos_csrf='))?.slice(12); session.user = data.user;
      h.check(typeof session.csrf === 'string' && session.csrf.length > 0, 'normal maintenance obtains the current CSRF cookie', { label });
      h.updateSessionIdentity(session); h.cookies(session.cookie); h.remember({ csrfToken: session.csrf }); h.save();
      h.check(session.sid === sid, 'normal maintenance retains the exact original SID', { label });
      h.state.manualUiUnusedTailSessionRenewal.authWrites++; h.state.manualUiUnusedTailSessionRenewal.requestIds.push(result.requestId); h.save();
    }
    const me = h.data(await h.request(session, '/auth/me', 'GET', undefined, { renew: false }));
    h.check(me.user?.id === actorId && session.sid === sid && session.expiresAt > Date.now() + 300000, 'current protected original session has at least five minutes remaining', { label });
  }
  const auditEventIds = [];
  for (const requestId of h.state.manualUiUnusedTailSessionRenewal.requestIds) {
    const packet = h.state.requests.findLast(p => p.requestId === requestId);
    const query = new URLSearchParams({ requestId, result: 'success', size: '100' });
    const page = h.data(await h.request(h.state.sessions.admin, `/audit/global?${query}`, 'GET', undefined, { renew: false }));
    h.check(Array.isArray(page?.items) && !page.nextCursor && page.items.length === 1 && page.items[0].requestId === requestId && page.items[0].actorId === packet.actorId && page.items[0].entityId === packet.sessionId &&
      page.items[0].entityType === 'auth_sessions' && page.items[0].action === 'refresh' && page.items[0].result === 'success' && page.items[0].clusterId === null && page.items[0].workspaceId === null,
      'each normal renewal has its exact immutable successful original actor and SID audit', { requestId });
    auditEventIds.push(page.items[0].id);
  }
  const auditWriteCoverage = { successfulWrites: h.state.manualUiUnusedTailSessionRenewal.authWrites, coveredWrites: auditEventIds.length, auditEventIds, allCovered: auditEventIds.length === h.state.manualUiUnusedTailSessionRenewal.authWrites, scope: 'this-normal-session-maintenance-only' };
  h.check(sha256(JSON.stringify(journal)) === journalDigest && sha256(JSON.stringify(h.state.manualUiHistory)) === historyDigest &&
    sha256(JSON.stringify(h.state.requests.slice(0, h.state.manualUiUnusedTailSessionRenewal.originalPackets))) === digest && h.state.requests.slice(h.state.manualUiUnusedTailSessionRenewal.originalPackets).every(p => p.path === '/api/v1/auth/refresh' && p.method === 'POST' && p.status === 201),
    'normal maintenance preserves original five successful UI packets, journal, history and complete packet prefix');
  h.check(['admin', 'owner', 'read-only'].every(label => h.state.sessions[label].expiresAt > Date.now() + 300000), 'all original UI sessions remain sufficient after immutable audit reconciliation');
  h.public = { scope: 'same-original-SID-normal-maintenance-after-five-success-unused-tail-stop', originalFailure: { path: 'artifacts/M7/manual-ui.json', sha256: originalFailureSha256 }, authenticationWrites: h.state.manualUiUnusedTailSessionRenewal.authWrites,
    normalRenewalRequestIds: h.state.manualUiUnusedTailSessionRenewal.requestIds, businessWrites: 0, nativeTransportWrites: 0, freshLoginPerformed: false, originalSidsPreserved: true, originalCompletedUiWritesPreserved: 5,
    auditWriteCoverage, sessions: ['admin', 'owner', 'read-only'].map(label => { const s = h.state.sessions[label]; return { label, actorId: s.user.id, sid: s.sid, sessionExpiresAt: new Date(s.expiresAt).toISOString(), remainingSeconds: Math.floor((s.expiresAt - Date.now()) / 1000) }; }) };
  const safe = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: h.state.testTag, allPassed: true, passed: h.checks.length, failed: 0, checks: h.checks, secretsPublished: false, ...h.public };
  durableJson(path, safe, 0o644, true);
  Object.assign(h.state.manualUiUnusedTailSessionRenewal, { state: 'completed', completedAt: new Date().toISOString(), reportPath: path, reportSha256: sha256(readFileSync(path)) }); h.save({ phase: priorPhase });
  console.log(JSON.stringify({ allPassed: true, authenticationWrites: safe.authenticationWrites, businessWrites: 0, nativeTransportWrites: 0, reportPath: path, reportSha256: h.state.manualUiUnusedTailSessionRenewal.reportSha256, sessions: safe.sessions }));
} catch (error) { failure = error; }
if (failure) {
  h.save({ phase: h.state.inFlight == null ? 'stopped-failure' : 'stopped-unknown' });
  durableJson(path, { performedAt: new Date().toISOString(), milestone: 'M7', testTag: h.state.testTag, allPassed: false, failed: 1, failureClassification: 'ORIGINAL_SESSION_MAINTENANCE_STOP_PRIVATE_RETAINED', secretsPublished: false }, 0o644, true);
  console.log(JSON.stringify({ allPassed: false, failureClassification: 'ORIGINAL_SESSION_MAINTENANCE_STOP_PRIVATE_RETAINED' })); process.exitCode = 1;
}
