import { sha256, entity, scope } from './m7-harness.mjs';
import { confirmation, eventRead } from './m7-event-acceptance.mjs';

export const M7_PREFERENCE_FAILURE = Object.freeze({
  path: 'artifacts/M7/security-live-fanout-source-patch-failure.json',
  sha256: 'ee990888fcb25a58edcf57bdf117f4a56c06696d39ca4d03852d4976699e0064',
  diagnosisPath: 'artifacts/M7/notification-preference-patch-readonly-diagnosis.json',
  diagnosisSha256: 'c56c2d7395aa22c4a703cec58740e17c9a12a7d1e3f1cb2b3245552dceccaa38',
});

export function preparePreferenceContinuation(h, failureBytes, diagnosisBytes) {
  const s = h.state, report = JSON.parse(failureBytes), diagnosis = JSON.parse(diagnosisBytes), packet = s.requests.at(-1), owner = s.sessions.owner;
  h.check(sha256(failureBytes) === M7_PREFERENCE_FAILURE.sha256 && sha256(diagnosisBytes) === M7_PREFERENCE_FAILURE.diagnosisSha256 && report.testTag === s.testTag && report.allPassed === false && report.passed === 1202 && report.failed === 1 && report.successfulWrites === 165 && report.unknownWrites === 0,
    'exact known notification SQL rollback failure and immutable diagnosis are retained');
  h.check(s.phase === 'stopped-failure' && s.inFlight == null && !s.preferencePatchContinuation && s.requests.length === 168 && s.requests.every(p => p.state === 'response_observed') && packet.index === 167 && packet.method === 'PATCH' && packet.status === 500 && packet.errorCode === 'INTERNAL_ERROR' && packet.key === 'fc842755-db0d-4b02-a175-1c237320db03' && packet.bodySha256 === 'ddd370b32665106fae59ab583d1b014476bf9a329aee3677de7d5d1b31dc0db2' && sha256(JSON.stringify(packet.body)) === packet.bodySha256 && packet.path === '/api/v1/notifications/preferences/06ec3518-350d-4085-93dd-a5fb8ee13c7e',
    'only the deliberate exact original failed SQL packet can be continued once');
  h.check(diagnosis.allPassed === true && diagnosis.businessWrites === 0 && diagnosis.authenticationWrites === 0 && diagnosis.originalPacketIndex === packet.index && diagnosis.originalKey === packet.key && diagnosis.originalBodySha256 === packet.bodySha256 && diagnosis.receipt.operationAbsent === true && diagnosis.preference.mutationUnchanged === true && diagnosis.preference.scopeMatched === true && s.preferencePatchDiagnosis?.state === 'completed' && s.preferencePatchDiagnosis.operationAbsent === true && s.preferencePatchDiagnosis.mutationUnchanged === true,
    'actual original-key404 and unchanged owner revision prove full SQL rollback');
  h.check(packet.actorId === owner.user.id && packet.sessionId === owner.sid && packet.clusterId === s.scopes.direct.cid && packet.workspaceId === s.scopes.direct.wid && !s.c2ModeChanged && s.fixtures.filter(f => f.type === 'preferences').length === 55 && s.fixtures.filter(f => f.type === 'subscriptions' && f.name.startsWith(s.testTag + '-fanout-')).length === 55,
    'all completed 55 fanout fixtures and the original owner identity are reused');
  h.check(sha256(JSON.stringify(s.requests)) === sha256(JSON.stringify(s.preferencePatchDiagnosisHistory.original.requests)), 'read-only diagnosis did not alter any original write packet');
  const original = structuredClone(s), originalPacketsSha256 = sha256(JSON.stringify(s.requests));
  s.preferencePatchContinuationHistory = { version: 1, original, originalPacketsSha256, failureArchive: M7_PREFERENCE_FAILURE };
  s.preferencePatchContinuation = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalPacketsSha256, originalPacketIndex: packet.index, rollbackProven: true, deliberateRetryIssued: false, failureArchive: M7_PREFERENCE_FAILURE };
  h.save({ phase: 'exact-rolled-back-preference-continuation' });
  return { packet, actors: { admin: s.sessions.admin, bootstrap: s.sessions['bootstrap-provisioner'], approver: s.sessions.approver, readonly: s.sessions['read-only'], owner, other: s.sessions['other-owner'], ...s.scopes } };
}

/** Root authorized exactly one same-key, same-body retry of the SQL-only
 * rolled-back operation. Original successful fanout/read/dismiss stay untouched. */
export async function finishPreferenceLifecycle(h, actors, packet) {
  const owner = actors.owner, id = packet.path.split('/').at(-1), prefPath = `/notifications/preferences/${id}`;
  const receipt = await h.request(owner, `/notifications/operations/by-key/${packet.key}`, 'GET', undefined, { expected: [404] });
  h.check(receipt.payload?.error?.code === 'NOTIFICATION_OPERATION_NOT_FOUND', 'original failed key still has no committed personal ledger after repair');
  const current = h.data(await h.request(owner, prefPath));
  h.check(current.id === id && current.userId === owner.user.id && current.clusterId === packet.body.clusterId && current.workspaceId === packet.body.workspaceId && current.revision === packet.body.revision && current.name === packet.body.name && current.status === 'active' && current.inAppEnabled === true,
    'exact owner source remains at the original pre-update revision before deliberate retry');
  h.state.preferencePatchContinuation.deliberateRetryIssued = true; h.save();
  let pref = entity(h.data(await h.request(owner, prefPath, 'PATCH', packet.body, { key: packet.key })));
  h.check(pref.id === id && pref.userId === owner.user.id && pref.revision === packet.body.revision + 1 && pref.inAppEnabled === false, 'original rolled-back SQL intent now succeeds exactly once with unchanged body and key');
  const proven = h.data(await h.request(owner, `/notifications/operations/by-key/${packet.key}`));
  h.check(proven.state === 'succeeded' && proven.remote_completed === true && proven.clusterId === packet.body.clusterId && proven.workspaceId === packet.body.workspaceId && proven.result?.entity?.id === id && proven.result.entity.revision === pref.revision, 'original key now proves the one successful exact personal mutation');
  pref = entity(h.data(await h.request(owner, prefPath, 'DELETE', confirmation(pref))));
  h.check(pref.status === 'deleted', 'unused personal preference delete preserves a soft tombstone');
  pref = entity(h.data(await h.request(owner, prefPath + '/restore', 'POST', confirmation(pref))));
  h.check(pref.status === 'active' && pref.inAppEnabled === false, 'unused preference restore retains the actual prior muted setting');
  const fixture = h.state.fixtures.find(f => f.type === 'channels' && f.name === `${h.state.testTag}-webhook`);
  h.check(fixture?.cid === actors.direct.cid && fixture.wid === actors.direct.wid, 'remaining read-only check reuses the original provider channel');
  const channel = await eventRead(h, actors.admin, actors.direct, `channels/${fixture.id}`);
  await h.request(actors.readonly, scope(actors.direct.cid, actors.direct.wid, `events/channels/${channel.id}/test`), 'POST', confirmation(channel), { expected: [403] });
  const visible = await eventRead(h, actors.readonly, actors.direct, `channels/${channel.id}`);
  h.check(Object.values(visible.capabilities).every(v => v === false), 'actual read-only channel view has no mutation capabilities');
  h.public ??= {}; h.public.fanout = { sharedSubscriptions: 55, successfulDeliveries: 55, personalPreferences: 55, deduplicatedOwnerNotifications: 1, inheritedCompletedProof: M7_PREFERENCE_FAILURE.path };
}
