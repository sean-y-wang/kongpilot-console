import { readFileSync } from 'node:fs';
import { M7Harness, durableJson, sha256 } from './lib/m7-harness.mjs';
import { m7KnownWritePacket } from './lib/m7-secret-scan-policy.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_UI_AUDIT_SESSION_MAINTENANCE_READY !== 'true') throw new Error('M7_EXCLUSIVE_ORIGINAL_SESSION_MAINTENANCE_REQUIRED');
const h = new M7Harness({ resume: true }), path = 'artifacts/M7/manual-ui-audit-session-maintenance.json';
let failure;
try {
  const journal = h.state.manualUiJournal, priorPhase = h.state.phase, digest = sha256(JSON.stringify(h.state.requests));
  h.check(priorPhase === 'ui-complete' && journal?.phase === 'complete' && journal.attempts.length === 12 && journal.nextIndex === 12 && journal.attempts.every(a => a.state === 'succeeded' && typeof a.receiptRequestId === 'string' && a.receiptData != null) && journal.inFlight === null && h.state.inFlight === null && !h.state.manualUiAuditClose && !h.state.manualUiAuditSessionRenewal && h.state.requests.every(p => m7KnownWritePacket(h.state, p)), 'normal maintenance follows the complete original twelve-write UI journal without unresolved transport');
  const journalDigest = sha256(JSON.stringify(journal)), historyDigest = sha256(JSON.stringify(h.state.manualUiHistory));
  h.state.manualUiAuditSessionRenewalHistory = { version: 1, originalPhase: priorPhase, originalRequestsSha256: digest, originalUiJournal: structuredClone(journal), originalUiJournalSha256: journalDigest };
  h.state.manualUiAuditSessionRenewal = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalPackets: h.state.requests.length, originalPacketsSha256: digest,
    originalJournalSha256: journalDigest, originalHistorySha256: historyDigest, authWrites: 0, requestIds: [] };
  h.save({ phase: 'normal-original-session-maintenance' });
  for (const label of ['admin', 'owner']) {
    const session = h.state.sessions[label], actorId = session?.user?.id, username = session?.user?.username, sid = session?.sid;
    h.check(session && typeof actorId === 'string' && typeof sid === 'string', 'normal maintenance uses a captured original named session', { label });
    if (session.expiresAt <= Date.now() + 300000) {
      const result = await h.request(session, '/auth/refresh', 'POST', {}, { expected: [201], renew: false }), data = h.data(result);
      h.check(data.user?.id === actorId && data.user?.username === username, 'normal maintenance retains the exact original actor and username', { label });
      session.csrf = session.cookie.split('; ').find(v => v.startsWith('kongos_csrf='))?.slice(12); session.user = data.user;
      h.check(typeof session.csrf === 'string' && session.csrf.length > 0, 'normal maintenance obtains the current CSRF cookie', { label });
      h.updateSessionIdentity(session); h.cookies(session.cookie); h.remember({ csrfToken: session.csrf }); h.save();
      h.check(session.sid === sid, 'normal maintenance retains the exact original SID', { label });
      h.state.manualUiAuditSessionRenewal.authWrites++; h.state.manualUiAuditSessionRenewal.requestIds.push(result.requestId); h.save();
    }
    const me = h.data(await h.request(session, '/auth/me', 'GET', undefined, { renew: false }));
    h.check(me.user?.id === actorId && session.sid === sid && session.expiresAt > Date.now() + 300000, 'current protected original session has at least five minutes remaining', { label });
  }
  const auditEventIds = [];
  for (const requestId of h.state.manualUiAuditSessionRenewal.requestIds) {
    const packet = h.state.requests.findLast(p => p.requestId === requestId);
    const query = new URLSearchParams({ requestId, result: 'success', size: '100' });
    const page = h.data(await h.request(h.state.sessions.admin, `/audit/global?${query}`, 'GET', undefined, { renew: false }));
    h.check(Array.isArray(page?.items) && !page.nextCursor && page.items.length === 1 && page.items[0].requestId === requestId && page.items[0].actorId === packet.actorId && page.items[0].entityId === packet.sessionId &&
      page.items[0].entityType === 'auth_sessions' && page.items[0].action === 'refresh' && page.items[0].result === 'success' && page.items[0].clusterId === null && page.items[0].workspaceId === null,
      'each normal renewal has its exact immutable successful original actor and SID audit', { requestId });
    auditEventIds.push(page.items[0].id);
  }
  const auditWriteCoverage = { successfulWrites: h.state.manualUiAuditSessionRenewal.authWrites, coveredWrites: auditEventIds.length, auditEventIds, allCovered: auditEventIds.length === h.state.manualUiAuditSessionRenewal.authWrites, scope: 'this-normal-session-maintenance-only' };
  h.check(sha256(JSON.stringify(journal)) === journalDigest && sha256(JSON.stringify(h.state.manualUiHistory)) === historyDigest &&
    sha256(JSON.stringify(h.state.requests.slice(0, h.state.manualUiAuditSessionRenewal.originalPackets))) === digest && h.state.requests.slice(h.state.manualUiAuditSessionRenewal.originalPackets).every(p => p.path === '/api/v1/auth/refresh' && p.method === 'POST' && p.status === 201),
    'normal maintenance preserves original twelve successful UI packets, journal, history and complete packet prefix');
  h.check(['admin', 'owner'].every(label => h.state.sessions[label].expiresAt > Date.now() + 300000), 'all original UI sessions remain sufficient after immutable audit reconciliation');
  h.public = { scope: 'same-original-SID-normal-maintenance-before-pure-read-only-twelve-receipt-audit-close', authenticationWrites: h.state.manualUiAuditSessionRenewal.authWrites,
    normalRenewalRequestIds: h.state.manualUiAuditSessionRenewal.requestIds, businessWrites: 0, nativeTransportWrites: 0, freshLoginPerformed: false, originalSidsPreserved: true, originalCompletedUiWritesPreserved: 12,
    auditWriteCoverage, sessions: ['admin', 'owner'].map(label => { const s = h.state.sessions[label]; return { label, actorId: s.user.id, sid: s.sid, sessionExpiresAt: new Date(s.expiresAt).toISOString(), remainingSeconds: Math.floor((s.expiresAt - Date.now()) / 1000) }; }) };
  const safe = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: h.state.testTag, allPassed: true, passed: h.checks.length, failed: 0, checks: h.checks, secretsPublished: false, ...h.public };
  durableJson(path, safe, 0o644, true);
  Object.assign(h.state.manualUiAuditSessionRenewal, { state: 'completed', completedAt: new Date().toISOString(), reportPath: path, reportSha256: sha256(readFileSync(path)) }); h.save({ phase: priorPhase });
  console.log(JSON.stringify({ allPassed: true, authenticationWrites: safe.authenticationWrites, businessWrites: 0, nativeTransportWrites: 0, reportPath: path, reportSha256: h.state.manualUiAuditSessionRenewal.reportSha256, sessions: safe.sessions }));
} catch (error) { failure = error; }
if (failure) {
  h.save({ phase: h.state.inFlight == null ? 'stopped-failure' : 'stopped-unknown' });
  durableJson(path, { performedAt: new Date().toISOString(), milestone: 'M7', testTag: h.state.testTag, allPassed: false, failed: 1, failureClassification: 'ORIGINAL_SESSION_MAINTENANCE_STOP_PRIVATE_RETAINED', secretsPublished: false }, 0o644, true);
  console.log(JSON.stringify({ allPassed: false, failureClassification: 'ORIGINAL_SESSION_MAINTENANCE_STOP_PRIVATE_RETAINED' })); process.exitCode = 1;
}
