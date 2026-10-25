import { M7Harness, durableJson, sha256 } from './lib/m7-harness.mjs';
import { auditManualUiReceiptsAcceptance, auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';
import { m7KnownWritePacket } from './lib/m7-secret-scan-policy.mjs';
import { isKnownM7BlockedUiExport, readM7BlockedUiExportEvidence, M7_BLOCKED_UI_EXPORT } from './lib/m7-ui-blocked-export.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_UI_AUDIT_CLOSE_READY !== 'true') throw new Error('M7_EXCLUSIVE_UI_AUDIT_CLOSE_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  h.check(h.state.phase === 'ui-complete' && !h.state.cleanupStarted && !h.state.manualUiAuditClose && !h.state.manualUiAuditProof && h.state.inFlight == null && h.state.requests.every(p => m7KnownWritePacket(h.state, p)),
    'protected UI audit closure begins once after known completed original browser intents');
  const requestDigest = sha256(JSON.stringify(h.state.requests));
  // All prior full original captures remain retained and verified. This
  // read-only closure cannot alter original packets, so avoid duplicating a
  // complete multi-megabyte journal beyond the fixed history byte budget.
  h.state.manualUiAuditCloseHistory = { version: 1, originalPhase: h.state.phase, originalRequestsSha256: requestDigest,
    originalRequests: h.state.requests.length, originalUiJournal: structuredClone(h.state.manualUiJournal), originalUiJournalSha256: sha256(JSON.stringify(h.state.manualUiJournal)) };
  h.state.manualUiAuditClose = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), requestDigest, originalRequests: h.state.requests.length }; h.save();
  const actors = { admin: h.state.sessions.admin, owner: h.state.sessions.owner, ...h.state.scopes };
  h.check([actors.admin, actors.owner].every(actor => actor?.expiresAt > Date.now() + 90000), 'original active UI proof sessions have enough remaining access lifetime');
  // This stage cannot introduce transport writes or rotate an original nonce.
  // The two-stage owner proof precedes Root's separate cleanup authorization.
  const originalRequest = h.request.bind(h);
  h.request = (actor, path, method = 'GET', body, options = {}) => {
    if (method !== 'GET' || body !== undefined) throw new Error('M7_UI_AUDIT_CLOSE_READ_ONLY');
    return originalRequest(actor, path, method, body, { ...options, renew: false });
  };
  let blockedBeforeTransport;
  if (h.state.requests.some(p => isKnownM7BlockedUiExport(h.state, p))) {
    blockedBeforeTransport = readM7BlockedUiExportEvidence(h.state);
    const f = M7_BLOCKED_UI_EXPORT, denied = await h.request(actors.admin, `/clusters/${f.clusterId}/audit/exports/by-key/${f.key}?workspaceId=${f.workspaceId}`, 'GET', undefined, { expected: [404] });
    h.check(denied.status === 404 && /^[a-f\d-]{36}$/.test(denied.requestId), 'exact route-aborted export has no durable server export receipt');
    blockedBeforeTransport.receiptAbsenceReadRequestId = denied.requestId;
    h.state.manualUiBlockedExportProof = { version: 1, state: 'completed', ...blockedBeforeTransport }; h.save();
  }
  const receiptProof = await auditManualUiReceiptsAcceptance(h, actors);
  const auditWriteCoverage = await auditAllWritesCoverage(h, actors);
  h.check(sha256(JSON.stringify(h.state.requests)) === requestDigest, 'pure read-only UI audit closure preserves every original business and authentication packet');
  Object.assign(h.state.manualUiAuditClose, { state: 'completed', completedAt: new Date().toISOString(), receiptProof, auditWriteCoverage }); h.save();
  h.public = { scope: 'active-original-SID-protected-UI-receipts-and-immutable-audit', receiptProof, auditWriteCoverage, blockedBeforeTransport, businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, originalPacketsPreserved: true };
} catch (error) { failure = error; }
if (failure) h.checks.push({ name: failure.safeEvidenceMessage ? failure.message : 'Unexpected read-only UI audit closure failure; original state retained', passed: false });
h.save({ phase: failure ? 'stopped-failure' : 'ui-complete' });
const report = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: h.state.testTag, allPassed: !failure,
  passed: h.checks.filter(v => v.passed).length, failed: h.checks.filter(v => !v.passed).length, checks: h.checks,
  privateReferenceRetained: true, secretsPublished: false, ...(h.public ?? {}) };
durableJson('artifacts/M7/manual-ui-audit-closure.json', report, 0o644, true);
console.log(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, businessWrites: 0, authenticationWrites: 0 }));
process.exitCode = failure ? 1 : 0;
