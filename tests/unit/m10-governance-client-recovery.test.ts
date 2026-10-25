import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { safeRecoveryReferences, validRecoveryScope, workspaceSelectionForScope } from '../../apps/console-web/src/api/workspace-scope';

const actor = '11111111-1111-4111-8111-111111111111', cid = '22222222-2222-4222-8222-222222222222', wid = '33333333-3333-4333-8333-333333333333', key = '44444444-4444-4444-8444-444444444444', other = '55555555-5555-4555-8555-555555555555', path = `/clusters/${cid}/governance/inspections?workspaceId=${wid}`;
let client: typeof import('../../apps/console-web/src/api/client'), events: ReturnType<typeof vi.fn>;
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
beforeEach(async () => { vi.resetModules(); events = vi.fn(); vi.stubGlobal('window', { dispatchEvent: events }); vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } }); client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('synthetic-csrf'); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('M10 real shared HTTP original-key recovery', () => {
  it('preserves governance kind and original actor/source scope when a write response is lost', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('closed')); vi.stubGlobal('fetch', fetch);
    const error = await client.api(path, { method: 'POST', body: '{"scope":"workspace"}', headers: { 'X-Idempotency-Key': key } }).catch(error => error);
    expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'governance', scope: 'workspace', clusterId: cid, workspaceId: wid, idempotencyKey: key, state: 'uncertain' } });
    expect(fetch).toHaveBeenCalledTimes(1); expect(events.mock.calls[0][0].detail.actorId).toBe(actor);
  });
  it('keeps 500 and malformed success unresolved without reflecting private errors or retrying', async () => {
    for (const response of [json({ error: { message: 'never-private-password', fields: { key: 'never-private-password' }, code: 'never-private-password' } }, 500), new Response('never-private-password', { status: 201 })]) {
      const fetch = vi.fn().mockResolvedValue(response); vi.stubGlobal('fetch', fetch);
      const error = await client.api(path, { method: 'POST', body: '{}', headers: { 'X-Idempotency-Key': key } }).catch(error => error);
      expect(error.code).toBe('WRITE_RESULT_UNKNOWN'); expect(JSON.stringify(error)).not.toContain('never-private-password'); expect(fetch).toHaveBeenCalledTimes(1);
    }
  });
  it('single same-session refresh reuses the original POST key and exact source workspace', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({ error: { code: 'SESSION_EXPIRED' } }, 401)).mockResolvedValueOnce(json({ data: {} })).mockResolvedValueOnce(json({ data: { id: key } })); vi.stubGlobal('fetch', fetch);
    await client.api(path, { method: 'POST', body: '{}', headers: { 'X-Idempotency-Key': key } });
    expect(fetch.mock.calls.map(call => call[0])).toEqual([`/api/v1${path}`, '/api/v1/auth/refresh', `/api/v1${path}`]);
    expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key); expect(new Headers(fetch.mock.calls[2][1].headers).get('X-Idempotency-Key')).toBe(key);
  });
  it('does not replay the old actor write when the actor changes during session refresh', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({}, 401)).mockImplementationOnce(async () => { client.setApiActorId(other); return json({ data: {} }); }); vi.stubGlobal('fetch', fetch);
    const error = await client.api(path, { method: 'POST', body: '{}', headers: { 'X-Idempotency-Key': key } }).catch(error => error);
    expect(error.code).toBe('SESSION_CHANGED'); expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('persists only original identifiers, with scope and actor validation', () => {
    const row = { actor_id: actor, cid, wid, kind: 'governance', scope: 'workspace', idempotencyKey: key, state: 'uncertain', created_at: new Date().toISOString(), yaml: 'never-private', sourceProof: 'never-private' };
    expect(safeRecoveryReferences([row], actor)).toHaveLength(1); expect(JSON.stringify(safeRecoveryReferences([row], actor))).not.toContain('never-private');
    expect(safeRecoveryReferences([row], other)).toEqual([]); expect(validRecoveryScope({ ...row, scope: 'global' })).toBe(false); expect(validRecoveryScope({ ...row, wid: undefined })).toBe(false);
  });
  it('overwrites the target in-memory workspace before a cluster switch without disturbing the source', () => {
    const previous = { [cid]: wid, [other]: actor };
    expect(workspaceSelectionForScope(previous, [cid, other], other, key)).toEqual({ [cid]: wid, [other]: key });
    expect(previous[other]).toBe(actor);
    for (const [cluster, workspace] of [[actor, key], [other, '../workspaces'], ['../clusters', key]]) expect(() => workspaceSelectionForScope(previous, [cid, other], cluster, workspace)).toThrow();
  });
});
