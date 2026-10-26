// @ts-nocheck -- actual bounded continuation with synthetic state and no runtime.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { M7_PREFERENCE_FAILURE, preparePreferenceContinuation, finishPreferenceLifecycle } from './lib/m7-preference-continuation.mjs';
const failureBytes = readFileSync(M7_PREFERENCE_FAILURE.path), diagnosisBytes = readFileSync(M7_PREFERENCE_FAILURE.diagnosisPath);
const report = JSON.parse(failureBytes), diagnosis = JSON.parse(diagnosisBytes);
function fixture() {
  const area = { cid: diagnosis.preference.clusterId, wid: diagnosis.preference.workspaceId }, actorId = diagnosis.preference.userId, sid = randomUUID();
  const service = report.fixtures.find(f => f.type === 'services' && f.name === report.testTag + '-fanout');
  const body = { clusterId: area.cid, workspaceId: area.wid, name: report.testTag + '-owner-0', eventTypes: ['entity.updated'], nativeType: 'services', nativeIds: [service.id], inAppEnabled: false, revision: 1 };
  const requests = Array.from({ length: 168 }, (_, index) => ({ index, key: randomUUID(), state: 'response_observed', status: 201 }));
  Object.assign(requests[167], { method: 'PATCH', status: 500, errorCode: 'INTERNAL_ERROR', key: diagnosis.originalKey, bodySha256: diagnosis.originalBodySha256, body, path: '/api/v1/notifications/preferences/' + diagnosis.preference.id, actorId, sessionId: sid, clusterId: area.cid, workspaceId: area.wid });
  const owner = { label: 'owner', sid, user: { id: actorId } }, actors = { owner, admin: { user: { id: randomUUID() } }, readonly: { user: { id: randomUUID() } }, direct: area };
  const state = { testTag: report.testTag, phase: 'stopped-failure', inFlight: null, requests, sessions: { owner, admin: actors.admin, 'read-only': actors.readonly }, scopes: { direct: area }, fixtures: [
    ...Array.from({ length: 55 }, (_, i) => ({ type: 'preferences', name: report.testTag + '-owner-' + i })),
    ...Array.from({ length: 55 }, (_, i) => ({ type: 'subscriptions', name: report.testTag + '-fanout-' + i })),
    { type: 'channels', id: randomUUID(), name: report.testTag + '-webhook', ...area },
  ], preferencePatchDiagnosis: { state: 'completed', operationAbsent: true, mutationUnchanged: true }, preferencePatchDiagnosisHistory: { original: { requests: structuredClone(requests) } } };
  const h = { state, check: (ok, name) => { if (!ok) throw Error(name); }, save: vi.fn(extra => Object.assign(state, extra)), data: r => r.payload.data };
  return { h, actors, packet: requests[167], body, area };
}
describe('one exact SQL rollback continuation', () => {
  it('retains full old journal and original failed packet before resetting the stop gate', () => {
    const { h } = fixture(), old = structuredClone(h.state); preparePreferenceContinuation(h, failureBytes, diagnosisBytes);
    expect(h.state.preferencePatchContinuationHistory.original).toEqual(old); expect(h.save).toHaveBeenCalledOnce();
    expect(h.state.requests).toEqual(old.requests); expect(h.state.preferencePatchContinuation.deliberateRetryIssued).toBe(false);
  });
  it('an unknown write, changed original body or re-entry cannot release a new write', () => {
    for (const mutate of [h => h.state.requests[166].state = 'response_unknown', h => h.state.requests[167].body.revision = 2, h => h.state.preferencePatchContinuation = {}]) {
      const { h } = fixture(); mutate(h); expect(() => preparePreferenceContinuation(h, failureBytes, diagnosisBytes)).toThrow(); expect(h.save).not.toHaveBeenCalled();
    }
  });
  it('unproven rollback or another original owner rejects without a packet', () => {
    for (const mutate of [h => h.state.preferencePatchDiagnosis.operationAbsent = false, h => h.state.sessions.owner.user.id = randomUUID(), h => h.state.preferencePatchDiagnosisHistory.original.requests[0].status = 500]) {
      const { h } = fixture(); mutate(h); expect(() => preparePreferenceContinuation(h, failureBytes, diagnosisBytes)).toThrow(); expect(h.save).not.toHaveBeenCalled();
    }
  });
  it('completed current ledger or changed pre-update revision stops before the deliberate PATCH', async () => {
    for (const changed of [false, true]) {
      const { h, actors, packet, body } = fixture(); h.state.preferencePatchContinuation = {};
      h.request = vi.fn(async (_actor, path, method = 'GET') => {
        if (path.includes('/operations/')) return { payload: { error: { code: changed ? 'NOTIFICATION_OPERATION_NOT_FOUND' : 'NOTIFICATION_OPERATION_UNCERTAIN' } } };
        return { payload: { data: { ...body, id: diagnosis.preference.id, userId: actors.owner.user.id, status: 'active', revision: 2, inAppEnabled: true } } };
      });
      await expect(finishPreferenceLifecycle(h, actors, packet)).rejects.toThrow(); expect(h.request.mock.calls.every(call => !call[2] || call[2] === 'GET')).toBe(true);
    }
  });
  it('one retry uses exactly the original key and body while only the unused lifecycle continues', async () => {
    const { h, actors, packet, body, area } = fixture(); h.state.preferencePatchContinuation = {}; let revision = 1, patched = false;
    const pref = () => ({ ...body, id: diagnosis.preference.id, userId: actors.owner.user.id, clusterId: area.cid, workspaceId: area.wid, status: 'active', revision, inAppEnabled: !patched });
    h.request = vi.fn(async (_actor, path, method = 'GET', payload, options) => {
      if (path.includes('/operations/')) return patched ? { payload: { data: { state: 'succeeded', remote_completed: true, clusterId: area.cid, workspaceId: area.wid, result: { entity: pref() } } } } : { payload: { error: { code: 'NOTIFICATION_OPERATION_NOT_FOUND' } } };
      if (path.includes('/events/channels/')) return { payload: { data: { entity: { id: path.split('/').at(-1)?.split('?')[0], name: 'synthetic', revision: 1, capabilities: { write: false, delete: false, test: false } } } } };
      if (method === 'PATCH') { expect(options.key).toBe(packet.key); expect(payload).toBe(packet.body); patched = true; revision++; }
      if (method === 'DELETE') return { payload: { data: { entity: { ...pref(), status: 'deleted', revision: ++revision } } } };
      if (method === 'POST') return { payload: { data: { entity: { ...pref(), revision: ++revision } } } };
      return { payload: { data: method === 'PATCH' ? { entity: pref() } : pref() } };
    });
    await finishPreferenceLifecycle(h, actors, packet);
    expect(h.request.mock.calls.filter(call => call[2] === 'PATCH')).toHaveLength(1);
    expect(h.request.mock.calls.some(call => call[1].includes('/entities/') || call[1] === '/notifications/preferences' && call[2] === 'POST')).toBe(false);
  });
});
