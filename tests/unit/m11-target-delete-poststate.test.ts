import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import {
  assertTargetDeleteArchiveSeal,
  observeTargetDeletePoststate,
} from '../../apps/console-api/src/infrastructure/kong/target-delete-poststate';

const cid = randomUUID(), upstream = randomUUID(), originalId = randomUUID(), address = 'echo:8080';
const secrets = { fingerprint: (v: unknown) => createHash('sha256').update(canonicalJson(v)).digest('hex') };
const archive = { entryId: randomUUID(), graphHmac: 'a'.repeat(64), nodeCount: 2 };
const before = { id: originalId, target: address, weight: 100, upstream: { id: upstream }, tags: ['owner:test'] };
const row = (weight: number, created_at: number, id = randomUUID()) => ({
  id, target: address, weight, created_at, upstream: { id: upstream }, tags: ['owner:test'],
});

function fixture(history: any[] = [], effective: any[] = []) {
  const kong = {
    list: vi.fn(async (_cid: string, path: string, q: any) => ({
      items: structuredClone(path.endsWith('/all') ? history : effective),
      size: q.size,
      nextCursor: null,
    })),
    request: vi.fn(),
  };
  const run = (options: any = {}) => observeTargetDeletePoststate(kong, secrets, {
    clusterId: cid,
    upstreamId: upstream,
    originalNativeId: originalId,
    address,
    weightBefore: 100,
    archive,
    nativeDeleteResult: null,
    approvedBefore: before,
  }, options);
  return { kong, run, history, effective };
}

describe('KP-005 Target DELETE poststate (Kong 1.5 history/effective EOF)', () => {
  it('rejects missing archive seal before any list observation', () => {
    expect(() => assertTargetDeleteArchiveSeal({ entryId: 'x', graphHmac: 'a'.repeat(64), nodeCount: 1 }, before as any))
      .toThrow(/TARGET_DELETE_ARCHIVE_REQUIRED|回收站归档/);
    expect(() => assertTargetDeleteArchiveSeal({ ...archive, nodeCount: 0 }, before as any)).toThrow();
  });

  it('certifies native-pruned delete through four parent-scoped list EOFs without GET404', async () => {
    const f = fixture();
    const result = await f.run();
    expect(result).toMatchObject({
      archiveEntryId: archive.entryId,
      originalNativeId: originalId,
      address,
      historyRetention: 'native-pruned',
      currentEffectiveAbsent: true,
      restoreRequiresSealedReplacement: true,
      observedOverlayHmac: null,
      archiveGraphHmac: archive.graphHmac,
      budget: { pages: 4, records: 0 },
    });
    expect(f.kong.list.mock.calls.map(c => c[1])).toEqual([
      `/upstreams/${upstream}/targets/all`,
      `/upstreams/${upstream}/targets`,
      `/upstreams/${upstream}/targets/all`,
      `/upstreams/${upstream}/targets`,
    ]);
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('certifies weight-zero overlay when latest same-address history row is weight 0', async () => {
    const overlay = row(0, 1791927041.5);
    const history = [row(100, 1791927020), row(80, 1791927030), overlay];
    const f = fixture(history, []);
    const result = await f.run();
    expect(result.historyRetention).toBe('weight-zero-overlay');
    expect(result.observedOverlayHmac).toBe(secrets.fingerprint(overlay));
    expect(result.currentEffectiveAbsent).toBe(true);
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('rejects non-null native delete body and positive latest history weight', async () => {
    await expect(observeTargetDeletePoststate(fixture().kong, secrets, {
      clusterId: cid, upstreamId: upstream, originalNativeId: originalId, address, weightBefore: 100,
      archive, nativeDeleteResult: null as any, approvedBefore: before,
    })).resolves.toBeDefined();
    await expect(observeTargetDeletePoststate(fixture().kong, secrets, {
      clusterId: cid, upstreamId: upstream, originalNativeId: originalId, address, weightBefore: 100,
      archive, nativeDeleteResult: {} as any, approvedBefore: before,
    })).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_INVALID' } });

    const f = fixture([row(100, 1791927020)], []);
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_CHANGED' } });
  });

  it('rejects effective retention of the deleted address or original UUID', async () => {
    const active = row(80, 1791927042);
    await expect(fixture([], [active]).run()).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_CHANGED' } });
    const reused = { ...row(80, 1791927042, originalId), target: 'other:8080' };
    await expect(fixture([], [reused]).run()).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_CHANGED' } });
  });

  it('rejects collection drift across the four EOF observations', async () => {
    const f = fixture();
    let calls = 0;
    f.kong.list.mockImplementation(async (_c, path, q) => {
      calls++;
      const history = calls >= 3 ? [row(0, 1)] : [];
      return { items: path.endsWith('/all') ? history : [], size: q.size, nextCursor: null };
    });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_CHANGED' } });
  });

  it('fails closed at shared page/record ceilings without treating a partial page as complete', async () => {
    const empty = fixture();
    await expect(empty.run({ maxPages: 0 })).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_LIMIT' } });
    expect(empty.kong.list).not.toHaveBeenCalled();
    const pages = fixture();
    await expect(pages.run({ maxPages: 3 })).rejects.toMatchObject({ response: { code: 'TARGET_DELETE_POSTSTATE_LIMIT' } });
    expect(pages.kong.list).toHaveBeenCalledTimes(3);
  });
});
