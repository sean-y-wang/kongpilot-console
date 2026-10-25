import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], cleanup: [] as Array<() => void>, actor: '', user: null as any, cid: '', wid: '', version: '', references: [] as any[], queries: [] as any[], api: vi.fn(), invalidate: vi.fn(), events: vi.fn() }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(), useState: (initial: any) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = initial; return [frame.slots[index], (value: any) => { frame.slots[index] = typeof value === 'function' ? value(frame.slots[index]) : value; }]; }, useRef: (value: any) => { const index = frame.index++; return frame.slots[index] ??= { current: value }; }, useEffect: (effect: () => void | (() => void)) => { const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } }));
vi.mock('@tanstack/react-query', () => ({ useQueryClient: () => ({ invalidateQueries: frame.invalidate }), useQuery: (options: any) => { frame.queries.push(options); return { data: undefined, isFetching: false }; } }));
vi.mock('../../apps/console-web/src/api/client', async original => ({ ...await original<typeof import('../../apps/console-web/src/api/client')>(), api: frame.api, getApiActorId: () => frame.actor }));
vi.mock('../../apps/console-web/src/api/idempotency', () => ({ newIdempotencyKey: () => 'fc843d08-7627-46f5-8cd0-93fc49f1af22' }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: frame.user }) }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => ({ clusterId: frame.cid }) }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => ({ workspaceId: frame.wid, references: frame.references }) }));
vi.mock('../../apps/console-web/src/app/Permissions', () => ({ usePermissions: () => ({ version: frame.version }) }));
import { useM7Scope, useM7Mutation, useM7Page } from '../../apps/console-web/src/features/m7.hooks';
const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', other = '8d0fcfe8-f993-4d97-829f-e3e9b4cfb113', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22', path = `/clusters/${cid}/events/channels?workspaceId=${wid}`;
function render(mode: 'workspace' | 'global' = 'workspace') { frame.index = 0; const scope = useM7Scope(mode); return { scope, mutation: useM7Mutation(scope) }; }
function grant(overrides: any = {}) { return { module: 'events', action: 'read', scope_type: 'workspace', scope_values: [wid], workspace_id: wid, cluster_id: cid, ...overrides }; }
beforeEach(() => { frame.index = 0; frame.slots = []; frame.cleanup = []; frame.actor = actor; frame.cid = cid; frame.wid = wid; frame.version = 'actor:7'; frame.references = []; frame.queries = []; frame.api.mockReset(); frame.invalidate.mockReset(); frame.events.mockReset(); frame.user = { id: actor, capabilities: { platformAdmin: false, grants: [grant()] } }; vi.stubGlobal('window', { dispatchEvent: frame.events }); vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } }); });
afterEach(() => { vi.unstubAllGlobals(); });
describe('actual M7 hook mutation/read boundaries', () => {
  it('matches a complete grant without combining foreign module/action/CID/WID ceilings', () => {
    expect(render().scope.whole('events')).toBe(true);
    for (const foreign of [{ cluster_id: other }, { workspace_id: other }, { scope_values: [other] }, { action: 'write' }, { module: 'notifications' }, { scope_type: 'tag_group', scope_values: ['team:pay'] }]) { frame.user.capabilities.grants = [grant(foreign)]; expect(render().scope.whole('events')).toBe(false); }
    frame.user.capabilities.grants = [grant({ action: 'read', workspace_id: other }), grant({ action: 'write' })]; expect(render().scope.whole('events')).toBe(false); expect(render().scope.whole('events', 'read', true)).toBe(false);
  });
  it('GETs the original ledger only after one ACK and preserves queued meaning', async () => {
    frame.api.mockResolvedValueOnce({ entity: { id: other } }).mockResolvedValueOnce({ domain: 'iam', idempotencyKey: key, clusterId: cid, workspaceId: wid, state: 'succeeded', executionCompleted: true, configurationCommitted: true, queued: true });
    const { mutation } = render(), result = await mutation.mutate(path, 'POST', { name: 'unit' }, 'events'); expect(frame.api.mock.calls.map(c => c[0])).toEqual([path, `/clusters/${cid}/events/operations/by-key/${key}?workspaceId=${wid}`]); expect(frame.api.mock.calls[0][1].headers).toEqual({ 'X-Idempotency-Key': key }); expect(result.verified.label).toContain('排队'); expect(frame.invalidate).toHaveBeenCalledTimes(1);
  });
  it('converts post-ACK receipt loss to durable original unknown reference without a new packet', async () => {
    frame.api.mockResolvedValueOnce({ entity: {} }).mockRejectedValueOnce(new Error('read connection failed'));
    await expect(render().mutation.mutate(path, 'POST', { token: 'do-not-store' }, 'events')).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'events', idempotencyKey: key, clusterId: cid, workspaceId: wid } }); expect(frame.api).toHaveBeenCalledTimes(2); expect(frame.events).toHaveBeenCalledTimes(1); expect(JSON.stringify(frame.events.mock.calls[0][0].detail)).not.toContain('do-not-store'); expect(frame.invalidate).not.toHaveBeenCalled();
  });
  it('blocks duplicate invocation before React commits the busy state', async () => {
    let ack!: (value: any) => void; frame.api.mockImplementationOnce(() => new Promise(resolve => { ack = resolve; })).mockResolvedValue({ domain: 'iam', idempotencyKey: key, clusterId: cid, workspaceId: wid, state: 'succeeded', executionCompleted: true, configurationCommitted: true }); const { mutation } = render(), first = mutation.mutate(path, 'POST', {}, 'events'); await expect(mutation.mutate(path, 'POST', {}, 'events')).rejects.toThrow(); expect(frame.api).toHaveBeenCalledTimes(1); ack({}); await first;
  });
  it('blocks stale scope/unmounted confirmations and attributes delayed ACK to original actor', async () => {
    const initial = render(); frame.wid = other; render(); await expect(initial.mutation.mutate(path, 'POST', {}, 'events')).rejects.toMatchObject({ code: 'SCOPE_CHANGED' }); expect(frame.api).not.toHaveBeenCalled();
    frame.wid = wid; const current = render(); frame.cleanup.forEach(fn => fn()); await expect(current.mutation.mutate(path, 'POST', {}, 'events')).rejects.toMatchObject({ code: 'SCOPE_CHANGED' }); expect(frame.api).not.toHaveBeenCalled();
    frame.slots = []; frame.cleanup = []; const final = render(); frame.api.mockImplementationOnce(async () => { frame.actor = other; return {}; }); await expect(final.mutation.mutate(path, 'POST', {}, 'events')).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN' }); expect(frame.api).toHaveBeenCalledTimes(1); expect(frame.events.mock.calls[0][0].detail.actorId).toBe(actor);
  });
  it('blocks original row scope unknown writes even in aggregate personal mode', async () => {
    frame.references = [{ actor_id: actor, kind: 'notifications', cid, wid, idempotencyKey: key }]; await expect(render('global').mutation.mutate(`/notifications/${other}/read?clusterId=${cid}&workspaceId=${wid}`, 'POST', { revision: 2 }, 'notifications')).rejects.toThrow(); expect(frame.api).not.toHaveBeenCalled();
  });
  it('keys reads by actor/version/scope, forwards cancellation and resets cursor when filters change', async () => {
    const { scope } = render(); useM7Page(scope.identity, 'records', f => scope.path('events/records', f), { eventType: 'entity.updated' }, true); const first = frame.queries.at(-1); const controller = new AbortController(); frame.api.mockResolvedValue({ items: [], nextCursor: null }); await first.queryFn({ signal: controller.signal }); expect(frame.api.mock.calls[0][1].signal).toBe(controller.signal); expect(first.queryKey[1]).toContain(actor); expect(first.queryKey[1]).toContain('actor:7'); expect(first.queryKey[1]).toContain(wid); expect(first.queryKey[2]).toBeUndefined();
  });
});
