import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EventObserverService } from '../../apps/console-api/src/modules/event-observers/event-observer.service';
import { EventRepositoryService, detectorStateDigest, observationDigest, observationScopeDigest } from '../../apps/console-api/src/modules/event-core/event-repository.service';

const cid = '11111111-1111-4111-8111-111111111111', wid = '22222222-2222-4222-8222-222222222222',
  sid = '33333333-3333-4333-8333-333333333333', oid = '44444444-4444-4444-8444-444444444444';
function observation() {
  return { observationId: oid, actorType: 'system', actorId: null, clusterId: cid, workspaceId: wid,
    detectorKey: 'upstream.health.v1', subjectType: 'upstreams', subjectId: sid, transportScope: 'a'.repeat(64),
    observedNodeId: 'synthetic-original-node', clusterRevision: 1, workspaceRevision: 1, configFingerprint: 'b'.repeat(64),
    scopeEpoch: 'c'.repeat(64), observedAt: '2026-10-11T00:00:00.000Z', quality: 'verified',
    sourceScope: { version: 1, quality: 'verified', module: 'events', nativeType: 'upstreams', nativeId: sid,
      before: { workspaceId: wid, physicalTags: ['team:original'] }, after: { workspaceId: wid, physicalTags: ['team:original'] } },
    observationSafe: { kind: 'upstream_health', health: 'healthy' }, beforeBaselineRevision: null, sourceProof: {} } as any;
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'a9'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

function scheduler(code?: string) {
  const secrets = new SecretService(), input = observation(), release = vi.fn(), rows: any[] = [];
  const db: any = { one: vi.fn(async () => rows[0] ?? null), transaction: vi.fn(async (fn: any) => {
    await fn(db); throw Object.assign(new Error('Synthetic acknowledgement unavailable'), code ? { code } : {});
  }) };
  const authority: any = { observe: vi.fn(async () => ({ input, release })), noteGap: vi.fn() };
  const events: any = { enqueueObservation: vi.fn(async () => ({ observationId: oid })) };
  const observer = new EventObserverService(db, {} as any, {} as any, authority, events, secrets);
  vi.spyOn((observer as any).logger, 'warn').mockImplementation(() => undefined);
  return { secrets, input, rows, db, authority, events, release, observer,
    sample: () => (observer as any).sample(cid, 'upstreams', [sid]) };
}
describe('M7 independent original observation COMMIT ambiguity adversaries', () => {
  it.each([undefined, '08006', '08003', '08P01', '57P01', '40003', '23514'])('retains the original ID/HMAC on callback-complete failure with SQLSTATE %s', async code => {
    const f = scheduler(code); await f.sample();
    const marker = (f.observer as any).unresolved.get(`${cid}:upstreams:${sid}`);
    expect(marker).toEqual({ observationId: oid, observationHmac: observationDigest(f.secrets, f.input) });
    expect(f.release).toHaveBeenCalledExactlyOnceWith(false);
    await f.sample(); expect(f.db.one).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('WHERE id=$1'), [oid]);
    expect(f.authority.observe).toHaveBeenCalledTimes(1); expect(f.events.enqueueObservation).toHaveBeenCalledTimes(1);
    expect((f.observer as any).unresolved.get(`${cid}:upstreams:${sid}`)).toEqual(marker);
  });
  it('does not observe or enqueue again when the original read-only receipt has a different HMAC', async () => {
    const f = scheduler('08006'); await f.sample(); f.rows.push({ observation_hmac: 'f'.repeat(64) });
    await f.sample(); expect(f.authority.observe).toHaveBeenCalledTimes(1); expect(f.events.enqueueObservation).toHaveBeenCalledTimes(1);
  });
  it('allows a new real observation only after exact original immutable receipt reconciliation', async () => {
    const f = scheduler('08006'); await f.sample();
    f.rows.push({ observation_hmac: observationDigest(f.secrets, f.input) });
    f.db.transaction.mockImplementation(async (fn: any) => fn(f.db));
    await f.sample(); expect(f.db.one).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('WHERE id=$1'), [oid]);
    expect(f.authority.observe).toHaveBeenCalledTimes(2); expect(f.release).toHaveBeenLastCalledWith(true);
    expect((f.observer as any).unresolved.size).toBe(0);
  });
  it('preserves a full unresolved budget and stops a new subject instead of evicting any original', async () => {
    const f = scheduler(), pending: Map<string, any> = (f.observer as any).unresolved;
    for (let n = 0; n < 1000; n++) pending.set(`synthetic:${n}`, { observationId: oid, observationHmac: 'a'.repeat(64) });
    const original = [...pending]; await f.sample();
    expect([...pending]).toEqual(original); expect(f.authority.observe).not.toHaveBeenCalled(); expect(f.events.enqueueObservation).not.toHaveBeenCalled();
  });
});

function detector() {
  const secrets = new SecretService(), input = observation(), progress = { version: 1, baseline: { observationId: oid, value: input.observationSafe }, candidate: null };
  const row: any = { id: oid, cluster_id: cid, workspace_id: wid, detector_key: input.detectorKey,
    subject_type: input.subjectType, subject_id: sid, transport_scope: input.transportScope, observed_node_id: input.observedNodeId,
    cluster_revision: 1, workspace_revision: 1, config_fingerprint: input.configFingerprint, scope_epoch: input.scopeEpoch,
    observed_at: input.observedAt, quality: input.quality, source_scope: input.sourceScope, observation_safe: input.observationSafe,
    source_scope_hmac: observationScopeDigest(secrets, input), observation_hmac: observationDigest(secrets, input) };
  const state: any = { cluster_id: cid, workspace_id: wid, detector_key: input.detectorKey, subject_type: input.subjectType,
    subject_id: sid, transport_scope: input.transportScope, observed_node_id: input.observedNodeId, config_fingerprint: input.configFingerprint,
    scope_epoch: input.scopeEpoch, last_observation_id: oid, last_observed_at: input.observedAt, revision: 1, last_observation_safe: progress };
  state.observation_fingerprint = detectorStateDigest(secrets, { clusterId: cid, workspaceId: wid, detectorKey: input.detectorKey,
    subjectType: input.subjectType, subjectId: sid, transportScope: input.transportScope, observedNodeId: input.observedNodeId,
    configFingerprint: input.configFingerprint, scopeEpoch: input.scopeEpoch, lastObservationId: oid, lastObservedAt: input.observedAt,
    revision: 1, progress });
  const db: any = { one: vi.fn(async () => row) }, repo = new EventRepositoryService(db, secrets, {} as any);
  return { secrets, input, row, state, db, verify: () => (repo as any).verifyState(state, db) };
}
describe('M7 independent detector baseline immutable proof adversaries', () => {
  it('verifies the exact original baseline state and its referenced observation proofs', async () => {
    const f = detector(); await expect(f.verify()).resolves.toBeUndefined();
    expect(f.db.one).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('WHERE id=$1'), [oid]);
  });
  it.each(['progress', 'physical-tags', 'node', 'observation-hmac'])('rejects altered %s before using it as a verified baseline', async field => {
    const f = detector();
    if (field === 'progress') f.state.last_observation_safe.baseline.value = { kind: 'upstream_health', health: 'unhealthy' };
    if (field === 'physical-tags') f.row.source_scope.after.physicalTags = ['team:foreign'];
    if (field === 'node') f.row.observed_node_id = 'synthetic-replacement-node';
    if (field === 'observation-hmac') f.row.observation_hmac = 'f'.repeat(64);
    await expect(f.verify()).rejects.toMatchObject({ response: { code: 'DETECTOR_STATE_PROOF_INVALID' } });
  });
});
