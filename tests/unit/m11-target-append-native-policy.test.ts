import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { TargetAppendNativePolicy, type TargetAppendPolicyInput } from '../../apps/console-api/src/modules/authorization/target-append-native-policy';

// Real keyed fingerprints and bounded effective-collection traversal;
// scope/grant callbacks are source fixtures. This is not a SQL/HTTP/SID test
// and these helper results cannot act as Root native execution capabilities.
const cid = 'a35313a2-9968-4818-9f31-7b3066ce1728';
const wid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const actorId = '414191a0-90c2-4cf0-b2cc-ad5ab2668949';
const sessionId = '83b737fc-f02f-4dc3-b5f0-470fdb4c82c7';
const upstreamId = 'd0350b4a-f011-4c8a-9eb3-5e65479e4d6b';
const oldId = '109621c2-cf81-4e25-b87b-4cdecc148ad5';
const newId = 'b06ca9f4-98cf-49de-aa71-f58220d5375b';
const tags = ['kos-ws-pay', 'owner-pay'];
const before = () => ({ id: oldId, target: 'echo.example:8080', weight: 100, tags: [...tags], upstream: { id: upstreamId }, created_at: 1 });
const body = (weight = 80) => ({ id: newId, target: 'echo.example:8080', weight, tags: [...tags] });
const page = (items: unknown[], nextCursor: string | null = null) => ({ items, nextCursor, size: 100 });

function fixture(weight = 80) {
  const secrets = new SecretService();
  const list = vi.fn().mockResolvedValue(page([before()]));
  const runFreshRead = vi.fn(async (_scope: unknown, lookup: () => Promise<any>) => lookup());
  const assertWorkspaceAndWrite = vi.fn().mockResolvedValue(undefined);
  const policy = new TargetAppendNativePolicy({ secrets, kong: { list } as any, runFreshRead, assertWorkspaceAndWrite });
  const input: TargetAppendPolicyInput = { origin: 'http', actorId, sessionId, clusterId: cid, workspaceId: wid, upstreamId,
    originalNativeId: oldId, method: 'POST', mutationAction: 'update', canonicalPath: `/upstreams/${upstreamId}/targets`,
    body: body(weight), approvedBody: body(weight), approvedBefore: before() };
  return { policy, input, list, runFreshRead, assertWorkspaceAndWrite };
}
const refused = (promise: Promise<unknown>, code: string) => expect(promise).rejects.toMatchObject({ response: { code } });

describe('M11 Target weight append source policy', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'a7'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());

  it('reads only the scoped effective collection to EOF and returns the genuine full before', async () => {
    const f = fixture();
    f.list.mockResolvedValueOnce(page([before()], 'page-2')).mockResolvedValueOnce(page([]));
    const authorization = await f.policy.authorize(f.input);
    expect(authorization.before).toEqual(before());
    expect(authorization.nativeId).toBe(newId); expect(authorization.originalNativeId).toBe(oldId);
    expect(f.runFreshRead).toHaveBeenCalledWith(expect.objectContaining({ clusterId: cid, workspaceId: wid, actorId, sessionId,
      paths: [`/upstreams/${upstreamId}/targets`], maxCalls: 100, maxPages: 100, maxRecords: 10000, maxBytes: 33554432, timeoutMs: 120000 }), expect.any(Function));
    expect(f.list.mock.calls.map(call => call.slice(1, 4))).toEqual([
      [`/upstreams/${upstreamId}/targets`, { size: 100 }, undefined], [`/upstreams/${upstreamId}/targets`, { size: 100 }, 'page-2'],
    ]);
    expect(f.assertWorkspaceAndWrite.mock.calls.map(([input]) => [input.phase, input.entity.id, input.entity.weight])).toEqual([
      ['before', oldId, 100], ['prospective', newId, 80],
    ]);
    expect(f.assertWorkspaceAndWrite.mock.calls.every(([input]) => input.entity.upstream.id === upstreamId)).toBe(true);
    expect(Object.isFrozen(authorization.before.tags)).toBe(true);
  });

  it('accepts only raw reflected row fields, without changing the response or old before', async () => {
    const f = fixture(), grant = await f.policy.authorize(f.input);
    const result = { ...body(), upstream: { id: upstreamId }, created_at: 2, tags: [...tags].reverse() };
    const snapshot = structuredClone(result);
    expect(f.policy.assertRawResponse(grant, result)).toBeUndefined();
    expect(result).toEqual(snapshot); expect(grant.before).toEqual(before());
  });

  it('allows weight=0 as an appended disabled receipt, without requiring a new effective UUID', async () => {
    const f = fixture(0), grant = await f.policy.authorize(f.input);
    expect(() => f.policy.assertRawResponse(grant, { ...body(0), upstream: { id: upstreamId } })).not.toThrow();
    expect(f.list).toHaveBeenCalledTimes(1);
    expect(grant.body.weight).toBe(0); expect(grant.before.weight).toBe(100);
  });

  it('does not extend an old-ID-only grant to the newly allocated historical UUID', async () => {
    const f = fixture();
    f.assertWorkspaceAndWrite.mockImplementation(async input => { if (input.entity.id !== oldId) throw new ForbiddenException({ code: 'ENTITY_GRANT_DENIED' }); });
    await refused(f.policy.authorize(f.input), 'ENTITY_GRANT_DENIED');
    expect(f.assertWorkspaceAndWrite).toHaveBeenCalledTimes(2);
  });

  it('preserves proposed tags for current prospective authorization', async () => {
    const f = fixture();
    f.input.body = f.input.approvedBody = { ...body(), tags: ['kos-ws-pay', 'owner-other'] };
    f.assertWorkspaceAndWrite.mockImplementation(async input => { if (!input.entity.tags.includes('owner-pay')) throw new ForbiddenException({ code: 'TAG_GRANT_DENIED' }); });
    await refused(f.policy.authorize(f.input), 'TAG_GRANT_DENIED');
  });

  it.each(['omitted', 'null'])('does not inherit old tag grants when POST tags are %s', async mode => {
    const f = fixture(), candidate: any = body();
    if (mode === 'omitted') delete candidate.tags; else candidate.tags = null;
    f.input.body = f.input.approvedBody = candidate;
    f.assertWorkspaceAndWrite.mockImplementation(async input => {
      if (!input.entity.tags.includes('owner-pay')) throw new ForbiddenException({ code: 'TAG_GRANT_DENIED' });
    });
    await refused(f.policy.authorize(f.input), 'TAG_GRANT_DENIED');
    expect(f.assertWorkspaceAndWrite.mock.calls[0][0].entity.tags).toEqual(tags);
    expect(f.assertWorkspaceAndWrite.mock.calls[1][0].entity.tags).toEqual([]);
  });

  it('authorizes an actually empty new tag set and compares empty raw tags without rewriting POST body', async () => {
    const f = fixture(), candidate: any = body(); delete candidate.tags;
    f.input.body = f.input.approvedBody = candidate;
    const grant = await f.policy.authorize(f.input);
    expect(f.assertWorkspaceAndWrite.mock.calls[1][0].entity).not.toHaveProperty('created_at');
    expect(grant.body).not.toHaveProperty('tags');
    expect(() => f.policy.assertRawResponse(grant, { ...candidate, tags: null, upstream: { id: upstreamId } })).not.toThrow();
  });

  it.each([
    { origin: 'scheduled' }, { sessionId: '' }, { actorId: '' }, { mutationAction: 'mark_healthy' }, { method: 'PATCH' },
    { canonicalPath: `/upstreams/${upstreamId}/targets/all` }, { canonicalPath: `/upstreams/${upstreamId}/targets/${oldId}/healthy` },
    { upstreamId: newId }, { originalNativeId: newId },
  ])('rejects unsupported operation/identity shape before reading %j', async patch => {
    const f = fixture();
    await refused(f.policy.authorize({ ...f.input, ...patch } as any), 'TARGET_APPEND_PACKET_INVALID');
    expect(f.runFreshRead).not.toHaveBeenCalled();
  });

  it.each([
    { id: oldId }, { id: 'not-a-uuid' }, { target: 'another.example:8080' }, { weight: -1 }, { weight: 1001 },
    { weight: 0.5 }, { upstream: { id: upstreamId } }, { created_at: 1 }, { tags: ['duplicate', 'duplicate'] },
  ])('rejects out-of-contract body fields even if an input claims them approved %j', async patch => {
    const f = fixture(), candidate = { ...body(), ...patch };
    await refused(f.policy.authorize({ ...f.input, body: candidate, approvedBody: candidate }), 'TARGET_APPEND_PACKET_INVALID');
    expect(f.list).not.toHaveBeenCalled();
  });

  it('rejects a body differing from the authenticated operation payload before any fresh read', async () => {
    const f = fixture(); f.input.body = body(81);
    await refused(f.policy.authorize(f.input), 'TARGET_APPEND_PACKET_INVALID'); expect(f.list).not.toHaveBeenCalled();
  });

  it.each([{ ...before(), id: newId }, { ...before(), weight: 101 }, { ...before(), tags: ['kos-ws-other'] }, null])(
    'requires the same complete current before and original effective UUID %j', async current => {
      const f = fixture(); f.list.mockResolvedValue(page(current ? [current] : []));
      await refused(f.policy.authorize(f.input), 'TARGET_APPEND_BEFORE_CHANGED');
      expect(f.assertWorkspaceAndWrite).not.toHaveBeenCalled();
    });

  it('does not accept a first-page match when EOF later reveals a duplicate address', async () => {
    const f = fixture();
    f.list.mockResolvedValueOnce(page([before()], 'page-2')).mockResolvedValueOnce(page([{ ...before(), id: newId }]));
    await refused(f.policy.authorize(f.input), 'KONG_INVALID_TARGET_LIST');
    expect(f.assertWorkspaceAndWrite).not.toHaveBeenCalled();
  });

  it('refuses a found before when the remaining collection exceeds its fixed page budget', async () => {
    const f = fixture(); let cursor = 0;
    f.list.mockImplementation(async () => page(cursor++ === 0 ? [before()] : [], `page-${cursor}`));
    await refused(f.policy.authorize(f.input), 'TARGET_LOOKUP_LIMIT');
    expect(f.list).toHaveBeenCalledTimes(100); expect(f.assertWorkspaceAndWrite).not.toHaveBeenCalled();
  });

  it('propagates scope/session, membership and read failures instead of fabricating before', async () => {
    const f = fixture(), failure = new Error('synthetic provider failure');
    f.runFreshRead.mockRejectedValueOnce(failure);
    await expect(f.policy.authorize(f.input)).rejects.toBe(failure); expect(f.list).not.toHaveBeenCalled();
    f.list.mockRejectedValueOnce(failure);
    await expect(f.policy.authorize(f.input)).rejects.toBe(failure);
    f.assertWorkspaceAndWrite.mockRejectedValueOnce(failure);
    await expect(f.policy.authorize(f.input)).rejects.toBe(failure);
  });

  it('requires a new fresh lookup on final reauthorization; it never caches the sealed before', async () => {
    const f = fixture(); await f.policy.authorize(f.input);
    f.list.mockResolvedValueOnce(page([{ ...before(), id: newId }]));
    await refused(f.policy.authorize(f.input), 'TARGET_APPEND_BEFORE_CHANGED'); expect(f.list).toHaveBeenCalledTimes(2);
  });

  it('snapshots both input and current data before awaited permission checks', async () => {
    const f = fixture(); const current = before(); f.list.mockResolvedValue(page([current]));
    f.assertWorkspaceAndWrite.mockImplementation(async input => {
      if (input.phase === 'before') { (f.input.body as any).weight = 1; current.weight = 2; }
    });
    const grant = await f.policy.authorize(f.input);
    expect(grant.before.weight).toBe(100); expect(grant.body.weight).toBe(80);
    expect(f.assertWorkspaceAndWrite.mock.calls[1][0].entity.weight).toBe(80);
  });

  it.each([{ id: oldId }, { upstream: { id: newId } }, { target: 'other.example:8080' }, { weight: 100 },
    { tags: ['kos-ws-other'] }, { tags: ['owner-pay', 'owner-pay'] }])('rejects actual response reflection mismatch %j', async patch => {
    const f = fixture(), grant = await f.policy.authorize(f.input);
    expect(() => f.policy.assertRawResponse(grant, { ...body(), upstream: { id: upstreamId }, ...patch })).toThrowError(expect.objectContaining({ response: { code: 'TARGET_APPEND_RESPONSE_MISMATCH', message: expect.any(String) } }));
  });

  it('rejects a manufactured result envelope and an unissued/copied policy result', async () => {
    const f = fixture(), grant = await f.policy.authorize(f.input), result = { ...body(), upstream: { id: upstreamId } };
    expect(() => f.policy.assertRawResponse(grant, { entity: result })).toThrowError(expect.objectContaining({ response: { code: 'TARGET_APPEND_RESPONSE_MISMATCH', message: expect.any(String) } }));
    expect(() => f.policy.assertRawResponse({ ...grant }, result)).toThrowError(expect.objectContaining({ response: { code: 'TARGET_APPEND_AUTHORIZATION_REQUIRED', message: expect.any(String) } }));
    expect(() => fixture().policy.assertRawResponse(grant, result)).toThrow();
  });
});
