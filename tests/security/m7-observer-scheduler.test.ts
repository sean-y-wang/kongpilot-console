import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventObserverService } from '../../apps/console-api/src/modules/event-observers/event-observer.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { observationDigest } from '../../apps/console-api/src/modules/event-core/event-repository.service';
import type { DetectorObservationInput } from '../../apps/console-api/src/modules/event-core/event.types';

const cid = 'e37a22ba-fc78-48e3-9ea5-3cfc6a2a1553';
const wid = '30e705c5-b4a0-40bc-b10c-a49a5f34ef1e';
const id = '4bfa1196-c881-4c0b-9b44-68c12e1b4cba';
const oid = '30b4fbf0-800a-4886-9d73-478b729c39c4';

describe('M7 observer original-commit reconciliation', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ac'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  function fixture() {
    const secrets = new SecretService();
    const input: DetectorObservationInput = {
      observationId: oid, actorType: 'system', actorId: null, clusterId: cid,
      workspaceId: wid, detectorKey: 'upstream.health.v1', subjectType: 'upstreams', subjectId: id,
      transportScope: 'test-transport', observedNodeId: 'test-node', clusterRevision: 1,
      workspaceRevision: 1, configFingerprint: 'a'.repeat(64), scopeEpoch: 'b'.repeat(64),
      observedAt: new Date().toISOString(), quality: 'verified',
      sourceScope: { version: 1, quality: 'verified', module: 'upstreams', nativeType: 'upstreams', nativeId: id,
        before: { workspaceId: wid, physicalTags: [] }, after: { workspaceId: wid, physicalTags: [] } },
      observationSafe: { kind: 'upstream_health', health: 'healthy' }, beforeBaselineRevision: null,
      sourceProof: {} as any,
    };
    const release = vi.fn();
    const authority: any = { observe: vi.fn().mockResolvedValue({ input, release }), noteGap: vi.fn() };
    const events: any = { enqueueObservation: vi.fn().mockResolvedValue({ observationId: oid }) };
    const db: any = { one: vi.fn().mockResolvedValue(null), transaction: vi.fn(async (fn: any) => fn(db)) };
    const service = new EventObserverService(db, {} as any, {} as any, authority, events, secrets);
    // Silence fixed safe diagnostic messages without changing service logic.
    (service as any).logger = { warn: vi.fn() };
    const sample = () => (service as any).sample(cid, 'upstreams', [id]);
    return { input, authority, events, db, service, sample, release, secrets };
  }
  it('does not start a new network observation while the original immutable receipt is absent', async () => {
    const f = fixture();
    f.db.transaction.mockImplementationOnce(async (fn: any) => { await fn(f.db); throw new Error('COMMIT acknowledgement lost'); });
    await f.sample(); await f.sample();
    expect(f.authority.observe).toHaveBeenCalledTimes(1);
    expect(f.events.enqueueObservation).toHaveBeenCalledTimes(1);
    expect(f.db.one).toHaveBeenCalledWith(expect.stringContaining('WHERE id=$1'), [oid]);
    expect(f.release).toHaveBeenCalledWith(false);
  });
  it('requires the exact original HMAC before a new real sample, and never reenqueues the old receipt', async () => {
    const f = fixture();
    f.db.transaction.mockImplementationOnce(async (fn: any) => { await fn(f.db); throw new Error('COMMIT acknowledgement lost'); });
    await f.sample();
    f.db.one.mockResolvedValueOnce({ observation_hmac: '0'.repeat(64) });
    await f.sample();
    expect(f.authority.observe).toHaveBeenCalledTimes(1);
    f.db.one.mockResolvedValueOnce({ observation_hmac: observationDigest(f.secrets, f.input) });
    const next = { ...f.input, observationId: 'b812f9d9-443c-4e1a-80dc-9f72ebc4c31b' };
    f.authority.observe.mockResolvedValueOnce({ input: next, release: f.release });
    await f.sample();
    expect(f.events.enqueueObservation.mock.calls.map(([i]: any[]) => i.observationId)).toEqual([oid, next.observationId]);
    expect((f.service as any).unresolved.size).toBe(0);
    expect(f.release).toHaveBeenLastCalledWith(true);
  });
  it('retains all unresolved originals at capacity and stops new subjects before any network call', async () => {
    const f = fixture(), pending = (f.service as any).unresolved as Map<string, unknown>;
    for (let n = 0; n < 1000; n++) pending.set(`pending-${n}`, { observationId: oid, observationHmac: 'a'.repeat(64) });
    await f.sample();
    expect(pending.size).toBe(1000);
    expect(pending.has('pending-0')).toBe(true);
    expect(f.authority.observe).not.toHaveBeenCalled();
    expect(f.db.transaction).not.toHaveBeenCalled();
    expect(f.authority.noteGap).toHaveBeenCalledWith(cid, 'upstreams', id);
  });
  it('can reconcile an existing subject at capacity without discarding another original', async () => {
    const f = fixture(), pending = (f.service as any).unresolved as Map<string, unknown>;
    for (let n = 0; n < 999; n++) pending.set(`pending-${n}`, { observationId: oid, observationHmac: 'a'.repeat(64) });
    pending.set(`${cid}:upstreams:${id}`, { observationId: oid, observationHmac: observationDigest(f.secrets, f.input) });
    f.db.one.mockResolvedValueOnce({ observation_hmac: observationDigest(f.secrets, f.input) });
    await f.sample();
    expect(pending.size).toBe(999);
    expect(pending.has('pending-0')).toBe(true);
    expect(f.authority.observe).toHaveBeenCalledTimes(1);
    expect(f.release).toHaveBeenCalledWith(true);
  });
  it('records a source gap without ambiguous-commit state when the transaction callback itself failed', async () => {
    const f = fixture(); f.events.enqueueObservation.mockRejectedValueOnce(new Error('current source revoked'));
    await f.sample();
    expect((f.service as any).unresolved.size).toBe(0);
    expect(f.authority.noteGap).toHaveBeenCalledWith(cid, 'upstreams', id);
    expect(f.release).toHaveBeenCalledWith(false);
  });
});
