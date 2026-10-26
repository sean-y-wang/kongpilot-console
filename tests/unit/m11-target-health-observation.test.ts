import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { assertTargetHealthObservation, readTargetHealthObservation } from '../../apps/console-api/src/infrastructure/kong/target-health-observation';

const clusterId = '873b55af-b17b-4ef1-a42b-2850fe13d274';
const upstreamId = '3a813f3d-1cfa-4e3a-a506-dabb3d1e39ab';
const targetId = 'c638752e-53b4-412e-90e5-f3c56b6ab886';
const otherId = 'd0304e99-0428-4109-bcf6-c5fa5dd03d68';
const otherClusterId = 'c3fa8c31-8a4e-4a26-bc13-a5db4a0504b3';
const target = () => ({ id: targetId, target: 'business.example:8080', weight: 100,
  upstream: { id: upstreamId }, tags: ['kos-ws-pay', 'kos-tag-dGVhbTpwYXk'], created_at: 1700000000 });
const row = (changes: Record<string, unknown> = {}) => ({ ...target(), health: 'HEALTHY', ...changes });
const otherRow = (changes: Record<string, unknown> = {}) => row({ id: otherId, target: 'secondary.example:8080', ...changes });
const page = (items: any[] = [row()], nextCursor: string | null = null, size = 100) => ({ items, nextCursor, size });

function fixture(pages = [page(), page()]) {
  const calls: any[] = [], roots = [{ version: '1.5.1', node_id: 'actual-node-one' }, { version: '1.5.1', node_id: 'actual-node-one' }];
  let rootIndex = 0, pageIndex = 0;
  // These controlled response fixtures exercise a real reader's parsing and
  // bounds. They are not native transport/approval/production evidence.
  const kong = {
    request: vi.fn(async (...args: any[]) => { calls.push(args); return structuredClone(roots[rootIndex++]); }),
    list: vi.fn(async (...args: any[]) => { calls.push(args); return structuredClone(pages[pageIndex++]); }),
  };
  const secrets = new SecretService(), input = { clusterId, upstreamId, target: target() };
  const read = (options: Parameters<typeof readTargetHealthObservation>[3] = {}) => readTargetHealthObservation(kong as any, secrets, input, options);
  return { kong, secrets, input, roots, pages, calls, read };
}

describe('M11 bounded target-health observation, source-only reader fixtures', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ac'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());

  it('fences two complete health scans with actual root node/version and seals the unchanged real row', async () => {
    const f = fixture(), observed = await f.read();
    expect(f.calls).toEqual([
      [clusterId, 'GET', '/'],
      [clusterId, `/upstreams/${upstreamId}/health`, { size: 100 }, undefined, 'target-health-observation'],
      [clusterId, `/upstreams/${upstreamId}/health`, { size: 100 }, undefined, 'target-health-observation'],
      [clusterId, 'GET', '/'],
    ]);
    expect(observed).toMatchObject({ version: 1, kind: 'kong-1.5-target-health-observation', upstreamId, targetId,
      targetAddress: 'business.example:8080', nodeId: 'actual-node-one', health: 'HEALTHY', targetRow: row(),
      targetHmac: f.secrets.fingerprint(target()), nodeScope: 'current_admin_node', recoverableOverride: false });
    const { observationHmac, ...facts } = observed;
    expect(observationHmac).toBe(f.secrets.fingerprint(facts));
    expect(Object.keys(observed).some(key => /time|date|at$/i.test(key))).toBe(false);
    expect(Object.isFrozen(observed)).toBe(true);
    expect(Object.isFrozen(observed.targetRow)).toBe(true);
    expect(Object.isFrozen(observed.targetRow.tags)).toBe(true);
    expect(Object.isFrozen(observed.targetRow.upstream)).toBe(true);
    expect(f.pages[1].items[0]).toEqual(row());
  });

  it('requires complete cursor EOF and tolerates a changed pagination layout of the identical collection', async () => {
    const f = fixture([page([row()], 'first', 1), page([otherRow()], null, 1),
      page([otherRow()], 'second', 1), page([row()], null, 1)]);
    const observed = await f.read({ pageSize: 1 });
    expect(observed.targetRow).toEqual(row());
    expect(f.kong.list.mock.calls.map(call => call[3])).toEqual([undefined, 'first', undefined, 'second']);
    expect(f.kong.request).toHaveBeenCalledTimes(2);
  });

  it('does not cache status; a new call performs fresh scans and reports the newly observed real state', async () => {
    const first = fixture(), second = fixture([page([row({ health: 'UNHEALTHY' })]), page([row({ health: 'UNHEALTHY' })])]);
    const initial = await first.read(), next = await second.read();
    expect(initial.health).toBe('HEALTHY'); expect(next.health).toBe('UNHEALTHY');
    expect(next.observationHmac).not.toBe(initial.observationHmac);
    expect(first.kong.list).toHaveBeenCalledTimes(2); expect(second.kong.list).toHaveBeenCalledTimes(2);
    expect(next.recoverableOverride).toBe(false);
  });

  it.each([
    ['node_id', 'changed-node', 'TARGET_HEALTH_NODE_CHANGED'],
    ['version', '1.5.2', 'TARGET_HEALTH_NODE_CHANGED'],
    ['version', '2.0.0', 'TARGET_HEALTH_KONG_VERSION_UNSUPPORTED'],
    ['node_id', '', 'TARGET_HEALTH_NODE_ID_UNAVAILABLE'],
  ])('rejects changed ending root %s', async (field, value, code) => {
    const f = fixture(); (f.roots[1] as any)[field] = value;
    await expect(f.read()).rejects.toMatchObject({ status: 409, response: { code } });
    expect(f.kong.list).toHaveBeenCalledTimes(2);
  });

  it.each([
    { version: '1.2.0', node_id: 'node' }, { version: '1.5.1-enterprise', node_id: 'node' },
    { version: undefined, node_id: 'node' },
  ])('rejects unsupported initial version before health reads (%j)', async root => {
    const f = fixture(); f.roots[0] = root as any;
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_KONG_VERSION_UNSUPPORTED' } });
    expect(f.kong.list).not.toHaveBeenCalled();
  });

  it.each([undefined, null, '', 42, 'x'.repeat(257)])('requires an actual bounded node_id: %s', async nodeId => {
    const f = fixture(); (f.roots[0] as any).node_id = nodeId;
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_NODE_ID_UNAVAILABLE' } });
    expect(f.kong.list).not.toHaveBeenCalled();
  });

  it('rejects a projected root instead of treating its node label as actual node evidence', async () => {
    const f = fixture(); (f.roots[0] as any).console_permission_projection = true;
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_NODE_UNVERIFIABLE' } });
    expect(f.kong.list).not.toHaveBeenCalled();
  });

  it.each([
    [{ weight: 80 }, 'TARGET_HEALTH_TARGET_CHANGED'],
    [{ created_at: 1700000001 }, 'TARGET_HEALTH_TARGET_CHANGED'],
    [{ tags: ['different-physical-tag'] }, 'TARGET_HEALTH_TARGET_CHANGED'],
    [{ tags: null }, 'TARGET_HEALTH_TARGET_CHANGED'],
    [{ target: 'changed.example:8080' }, 'TARGET_HEALTH_TARGET_CHANGED'],
    [{ upstream: { id: otherId } }, 'TARGET_HEALTH_NATIVE_ROW_INVALID'],
    [{ upstream: { id: upstreamId, name: 'extra' } }, 'TARGET_HEALTH_NATIVE_ROW_INVALID'],
    [{ extra: 'never-waived' }, 'TARGET_HEALTH_NATIVE_ROW_INVALID'],
    [{ id: 'invalid-id' }, 'TARGET_HEALTH_NATIVE_ROW_INVALID'],
    [{ weight: 1001 }, 'TARGET_HEALTH_NATIVE_ROW_INVALID'],
    [{ health: undefined }, 'TARGET_HEALTH_NATIVE_ROW_INVALID'],
  ] as const)('rejects changed/foreign/extra native configuration %j', async (changes, code) => {
    const f = fixture([page([row(changes)])]);
    await expect(f.read()).rejects.toMatchObject({ status: 409, response: { code } });
    expect(f.kong.list).toHaveBeenCalledOnce();
  });

  it.each([
    ['HEALTHCHECKS_OFF', 'TARGET_HEALTH_CHECKS_DISABLED'], ['DNS_ERROR', 'TARGET_HEALTH_STATE_UNVERIFIABLE'],
    ['healthy', 'TARGET_HEALTH_STATE_UNVERIFIABLE'], ['UNKNOWN', 'TARGET_HEALTH_STATE_UNVERIFIABLE'],
  ])('closes unverifiable current health %s instead of inventing rollback provenance', async (health, code) => {
    const f = fixture([page([row({ health })])]);
    await expect(f.read()).rejects.toMatchObject({ response: { code,...(health==='HEALTHCHECKS_OFF'?{message:expect.stringContaining('未启用健康检查')}:{}) } });
    expect(f.kong.request).toHaveBeenCalledOnce();
  });

  it('requires the exact physical original target rather than a new append-history ID at the same address', async () => {
    const f = fixture([page([row({ id: otherId })])]);
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_TARGET_CHANGED' } });
  });

  it('closes an absent target after a complete EOF read', async () => {
    const f = fixture([page([otherRow()])]);
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_TARGET_ABSENT' } });
  });

  it.each([page([row(), row()]), page([row(), row({ id: otherId })]),
    page([row(), row({ id: targetId.toUpperCase(), target: 'distinct.example:8080' })]),
    page([row(), row({ id: otherId, target: 'BUSINESS.EXAMPLE:8080' })])])('rejects ambiguous duplicate target IDs or addresses', async initial => {
    const f = fixture([initial]);
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_MEMBERSHIP_AMBIGUOUS' } });
  });

  it('checks an unselected trailing row for foreign upstream instead of stopping when the selected target is found', async () => {
    const f = fixture([page([row()], 'tail', 1), page([otherRow({ upstream: { id: otherId } })], null, 1)]);
    await expect(f.read({ pageSize: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_NATIVE_ROW_INVALID' } });
    expect(f.kong.list).toHaveBeenCalledTimes(2);
  });

  it.each([
    { items: null, nextCursor: null, size: 100 },
    { items: [row()], nextCursor: undefined, size: 100 },
    { items: [row()], nextCursor: '', size: 100 },
    { items: [row()], nextCursor: 7, size: 100 },
    { items: [row()], nextCursor: null, size: 99 },
    { items: [row()], nextCursor: null, size: 100, console_permission_projection: true },
  ])('rejects a partial/malformed projected list %j', async initial => {
    const f = fixture([initial as any]);
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_MEMBERSHIP_INCOMPLETE' } });
  });

  it('rejects cursor cycles before any unbounded repeat', async () => {
    const third = otherRow({ id: clusterId, target: 'third.example:8080' });
    const f = fixture([page([row()], 'a', 1), page([otherRow()], 'b', 1), page([third], 'a', 1)]);
    await expect(f.read({ pageSize: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_CURSOR_STALLED' } });
    expect(f.kong.list).toHaveBeenCalledTimes(3);
  });

  it('rejects a non-EOF empty page rather than treating it as a complete membership', async () => {
    const f = fixture([page([], 'next')]);
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_CURSOR_STALLED' } });
  });

  it.each([
    page([row({ health: 'UNHEALTHY' })]),
    page([row(), otherRow({ health: 'UNHEALTHY' })]),
    page([row()]),
  ])('rejects selected health or collection membership changes between complete scans', async secondPage => {
    const f = fixture([page([row(), otherRow()]), secondPage]);
    await expect(f.read()).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_READ_RACE' } });
  });

  it.each([
    { maxPages: 1 }, { maxCalls: 3 }, { maxPages: 101 }, { maxRecords: 10001 }, { maxBytes: 32 * 1024 * 1024 + 1 },
    { maxCalls: 103 }, { pageSize: 1001 }, { maxRecords: 0 }, { pageSize: 1.5 }, { inventedBudget: 1 },
  ])('rejects invalid budgets before any read %j', async options => {
    const f = fixture();
    await expect(f.read(options as any)).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_READ_BUDGET_INVALID' } });
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
  });

  it('enforces aggregate row and byte budgets across both scans', async () => {
    const rows = fixture();
    await expect(rows.read({ maxRecords: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_READ_BUDGET_EXCEEDED' } });
    expect(rows.kong.list).toHaveBeenCalledTimes(2); expect(rows.kong.request).toHaveBeenCalledOnce();
    const bytes = fixture();
    await expect(bytes.read({ maxBytes: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_READ_BUDGET_EXCEEDED' } });
    expect(bytes.kong.list).not.toHaveBeenCalled();
  });

  it('enforces page/call limits before the next read, without declaring a partial scan complete', async () => {
    for (const options of [{ maxPages: 2 }, { maxCalls: 4 }]) {
      const third = otherRow({ id: clusterId, target: 'third.example:8080' });
      const f = fixture([page([row()], 'a', 1), page([otherRow()], 'b', 1), page([third], 'c', 1)]);
      await expect(f.read({ ...options, pageSize: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_READ_BUDGET_EXCEEDED' } });
      expect(f.kong.request).toHaveBeenCalledOnce();
      expect(f.kong.list.mock.calls.length).toBe(options.maxPages ? 2 : 3);
    }
  });

  it('snapshots the original scope/Target before awaits, so caller mutation cannot change the read subject', async () => {
    const f = fixture(), originalRequest = f.kong.request.getMockImplementation()!;
    f.kong.request.mockImplementation(async (...args: any[]) => {
      f.input.clusterId = otherClusterId; f.input.upstreamId = otherId; f.input.target.weight = 80;
      return originalRequest(...args);
    });
    const observed = await f.read();
    expect(observed).toMatchObject({ upstreamId, targetId, targetHmac: f.secrets.fingerprint(target()) });
    expect(f.kong.list.mock.calls.every(call => call[0] === clusterId && call[1] === `/upstreams/${upstreamId}/health`)).toBe(true);
    expect(f.kong.request.mock.calls.every(call => call[0] === clusterId)).toBe(true);
  });

  it('propagates a real reader denial without fabricating response evidence', async () => {
    const f = fixture(), denied = new Error('FIXTURE_REAL_READ_DENIED'); f.kong.list.mockRejectedValueOnce(denied);
    await expect(f.read()).rejects.toBe(denied);
    expect(f.kong.request).toHaveBeenCalledOnce();
  });

  it('rejects malformed input/foreign upstream before any read', async () => {
    for (const change of [{ clusterId: 'foreign' }, { upstreamId: 'foreign' }, { target: { ...target(), upstream: { id: otherId } } },
      { target: { ...target(), health: 'HEALTHY' } }]) {
      const f = fixture(); Object.assign(f.input, change);
      await expect(f.read()).rejects.toMatchObject({ status: 409 });
      expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
    }
  });
});

describe('M11 target-health sealed content checker, no authority claim', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ac'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());

  it('checks serialized baseline facts without pretending this content check is a fresh GET', async () => {
    const f = fixture(), observed = await f.read(), copied = JSON.parse(JSON.stringify(observed));
    const checked = assertTargetHealthObservation(copied, { upstreamId, target: target() }, f.secrets);
    expect(checked).toEqual(observed); expect(checked).not.toBe(copied); expect(Object.isFrozen(checked)).toBe(true);
    expect(f.kong.request).toHaveBeenCalledTimes(2); expect(f.kong.list).toHaveBeenCalledTimes(2);
  });

  it.each([
    { version: 2 }, { kind: 'invented' }, { upstreamId: otherId }, { targetId: otherId },
    { targetAddress: 'changed.example:8080' }, { nodeId: '' }, { health: 'HEALTHCHECKS_OFF' },
    { targetHmac: '0'.repeat(64) }, { observationHmac: '0'.repeat(64) },
    { nodeScope: 'entire_cluster' }, { recoverableOverride: true }, { extra: 'unsealed' },
  ])('rejects altered sealed facts %j', async change => {
    const f = fixture(), observed = await f.read();
    expect(() => assertTargetHealthObservation({ ...observed, ...change }, { upstreamId, target: target() }, f.secrets)).toThrow();
  });

  it('checks targetRow and native configuration independently of the outer HMA', async () => {
    const f = fixture(), observed = await f.read();
    for (const targetRow of [row({ weight: 80 }), row({ health: 'UNHEALTHY' }), row({ extra: 'waived' })]) {
      const { observationHmac: _old, ...facts } = { ...observed, targetRow };
      const rehashed = { ...facts, observationHmac: f.secrets.fingerprint(facts) };
      expect(() => assertTargetHealthObservation(rehashed, { upstreamId, target: target() }, f.secrets)).toThrow();
    }
    expect(() => assertTargetHealthObservation(observed, { upstreamId, target: { ...target(), weight: 80 } }, f.secrets)).toThrow();
  });
});
