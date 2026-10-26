// @ts-nocheck -- pure actual checkpoint helper, synthetic journals only.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { prepareCatalogContinuation, M7_CATALOG_FAILURE } from './lib/m7-catalog-continuation.mjs';
import { M7_CLUSTERS, sha256 } from './lib/m7-harness.mjs';

const failureBytes = readFileSync(M7_CATALOG_FAILURE.path), report = JSON.parse(failureBytes);
function harness() {
  const state = { version: 1, milestone: 'M7', testTag: report.testTag, phase: 'stopped-failure', inFlight: null,
    requests: Array.from({ length: 27 }, (_, index) => ({ index, key: randomUUID(), state: 'response_observed', status: 201, body: { synthetic: index } })), sessions: {}, accounts: [], fixtures: [], samplingIntents: [], providerControls: [],
    sourceFiles: [{ path: 'synthetic-source', sha256: 'unchanged' }], scopes: { direct: { cid: M7_CLUSTERS.direct, wid: randomUUID() }, approval: { cid: M7_CLUSTERS.approval, wid: randomUUID() }, foreign: { cid: M7_CLUSTERS.direct, wid: randomUUID() } } };
  for (const scope of Object.values(state.scopes)) state.fixtures.push({ type: 'workspaces', id: scope.wid, cid: scope.cid, name: state.testTag + ' synthetic' });
  for (const label of ['admin', 'approver', 'read-only', 'owner', 'other-owner']) {
    const id = randomUUID(), username = state.testTag + '-' + label;
    state.accounts.push({ label, userId: id, username });
    state.sessions[label] = { label, sid: randomUUID(), cookie: 'SyntheticCapturedCookie', csrf: 'SyntheticCSRF', user: { id, username } };
  }
  state.sessions['bootstrap-provisioner'] = { sid: randomUUID() };
  const h = { state, check: (ok, name) => { if (!ok) throw Error(name); }, save: vi.fn(extra => Object.assign(state, extra)) };
  return h;
}
describe('exact known catalog checkpoint continuation', () => {
  it('durably retains the complete original journal before any runtime can proceed', () => {
    const h = harness(), original = structuredClone(h.state), sources = h.state.sourceFiles;
    const actors = prepareCatalogContinuation(h, failureBytes, sources);
    expect(h.save).toHaveBeenCalledTimes(1); expect(h.state.phase).toBe('direct-provider-delivery');
    expect(h.state.catalogContinuationHistory.original).toEqual(original);
    expect(h.state.catalogContinuation.originalPacketsSha256).toBe(sha256(JSON.stringify(original.requests)));
    expect(actors.admin).toBe(h.state.sessions.admin); expect(actors.direct).toBe(h.state.scopes.direct);
    expect(h.state.requests).toEqual(original.requests);
  });
  it('prepared or unknown original packet never releases the stop gate', () => {
    for (const state of ['prepared', 'response_unknown']) { const h = harness(); h.state.requests[0].state = state;
      expect(() => prepareCatalogContinuation(h, failureBytes, h.state.sourceFiles)).toThrow('no unknown'); expect(h.save).not.toHaveBeenCalled(); }
  });
  it('a previous provider/native write or C2 mode mutation cannot use this checkpoint', () => {
    for (const mutation of [h => h.state.providerControls.push({ state: 'observed' }), h => h.state.fixtures.push({ type: 'services' }), h => h.state.c2ModeChanged = true]) {
      const h = harness(); mutation(h); expect(() => prepareCatalogContinuation(h, failureBytes, h.state.sourceFiles)).toThrow('provisioning only'); expect(h.save).not.toHaveBeenCalled(); }
  });
  it('the one-shot continuation marker rejects re-entry without replay', () => {
    const h = harness(); prepareCatalogContinuation(h, failureBytes, h.state.sourceFiles); h.state.phase = 'stopped-failure';
    expect(() => prepareCatalogContinuation(h, failureBytes, h.state.sourceFiles)).toThrow('no unknown'); expect(h.save).toHaveBeenCalledTimes(1);
  });
  it('foreign scope, account identity and changed source all reject before save', () => {
    for (const mutation of [h => h.state.scopes.direct.cid = randomUUID(), h => h.state.sessions.owner.user.id = randomUUID()]) {
      const h = harness(); mutation(h); expect(() => prepareCatalogContinuation(h, failureBytes, h.state.sourceFiles)).toThrow(); expect(h.save).not.toHaveBeenCalled(); }
    const h = harness(); expect(() => prepareCatalogContinuation(h, failureBytes, [{ path: 'synthetic-source', sha256: 'changed' }])).toThrow('unchanged'); expect(h.save).not.toHaveBeenCalled();
  });
  it('an altered public failure cannot become an eligible known checkpoint', () => {
    const h = harness(), changed = Buffer.from(JSON.stringify({ ...report, allPassed: true }));
    expect(() => prepareCatalogContinuation(h, changed, h.state.sourceFiles)).toThrow('immutable'); expect(h.save).not.toHaveBeenCalled();
  });
});
