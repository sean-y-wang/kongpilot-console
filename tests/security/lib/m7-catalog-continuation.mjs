import { M7_CLUSTERS, sha256 } from './m7-harness.mjs';

export const M7_CATALOG_FAILURE = Object.freeze({
  path: 'artifacts/M7/security-live-first-catalog-failure.json',
  sha256: 'd0e0430c7a30f7348a8d518e2eb9d47565b55d7065b9dca1d077c538dacf2f84',
  checkpointWrites: 27,
});

/** This is one exact known read-only failure checkpoint, never a generic retry.
 * The complete old journal is durably retained before resetting the write gate.
 * No role/account/workspace or successful original packet is issued again. */
export function prepareCatalogContinuation(h, failureBytes, sourceFiles) {
  const s = h.state, report = JSON.parse(failureBytes);
  h.check(sha256(failureBytes) === M7_CATALOG_FAILURE.sha256 && report.testTag === s.testTag && report.allPassed === false && report.passed === 102 && report.failed === 1 && report.successfulWrites === 27 && report.unknownWrites === 0,
    'continuation binds the immutable original 102/1 known catalog failure');
  h.check(report.checks.filter(v => !v.passed).length === 1 && report.checks.some(v => !v.passed && v.name === 'expected BFF HTTP 200/201 received 400 INVALID_EVENT_BODY'), 'only original null-prototype catalog validation failure is eligible');
  h.check(s.version === 1 && s.milestone === 'M7' && s.phase === 'stopped-failure' && s.inFlight == null && !s.catalogContinuation && s.requests.length === 27 && s.requests.every(v => v.state === 'response_observed' && v.status >= 200 && v.status < 300),
    'exact original 27 successful packets have no unknown or pending write');
  h.check(!s.c2ModeChanged && !s.eventOperations?.length && !s.samplingIntents.length && !s.providerControls.length && s.fixtures.every(v => ['roles', 'users', 'workspaces'].includes(v.type)),
    'checkpoint contains provisioning only and no provider native or approval action');
  h.check(s.scopes.direct.cid === M7_CLUSTERS.direct && s.scopes.approval.cid === M7_CLUSTERS.approval && s.scopes.foreign.cid === M7_CLUSTERS.direct && new Set(Object.values(s.scopes).map(v => v.wid)).size === 3 && Object.values(s.scopes).every(v => s.fixtures.some(f => f.type === 'workspaces' && f.id === v.wid && f.cid === v.cid && f.name.startsWith(s.testTag))),
    'continuation reuses only the three original fresh M7 workspace identities');
  const actors = { admin: s.sessions.admin, bootstrap: s.sessions['bootstrap-provisioner'], approver: s.sessions.approver, readonly: s.sessions['read-only'], owner: s.sessions.owner, other: s.sessions['other-owner'], ...s.scopes };
  h.check(['admin', 'approver', 'readonly', 'owner', 'other'].every(name => {
    const session = actors[name], account = s.accounts.find(v => v.label === session?.label);
    return session?.sid && session?.cookie && session?.csrf && account?.userId === session.user.id && account.username === session.user.username && account.username.startsWith(s.testTag);
  }) && actors.bootstrap?.sid, 'all business actors reuse captured original M7 SID and account identity');
  h.check(sourceFiles.length === s.sourceFiles.length && sourceFiles.every(v => s.sourceFiles.some(old => old.path === v.path && old.sha256 === v.sha256)), 'original acceptance helpers are unchanged at the bounded continuation checkpoint');
  const snapshot = structuredClone(s), originalPacketsSha256 = sha256(JSON.stringify(s.requests));
  s.catalogContinuationHistory = { version: 1, original: snapshot, originalPacketsSha256, failureArchive: M7_CATALOG_FAILURE };
  s.catalogContinuation = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalWrites: 27, originalPacketsSha256, failureArchive: M7_CATALOG_FAILURE };
  h.save({ phase: 'direct-provider-delivery' });
  return actors;
}
