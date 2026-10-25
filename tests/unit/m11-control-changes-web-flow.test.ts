import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanup: [] as Array<() => void>, user: null as any, cluster: null as any, workspace: null as any, receipt: null as any, scopeSelected: vi.fn(), clusterSelected: vi.fn(), navigate: vi.fn(), reload: vi.fn(), invalidate: vi.fn(), success: vi.fn() }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = typeof initial === 'function' ? initial() : initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = typeof value === 'function' ? value(frame.slots[index]) : value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ message: { success: frame.success } }) } }));
vi.mock('react-router-dom', async original => ({ ...await original<typeof import('react-router-dom')>(), useNavigate: () => frame.navigate }));
vi.mock('@tanstack/react-query', () => ({ useQueryClient: () => ({ invalidateQueries: frame.invalidate }) }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: frame.user, reloadCapabilities: frame.reload }) }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => frame.cluster }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => frame.workspace }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError', formatTime: (value: unknown) => String(value ?? '') }));
import { setApiActorId } from '../../apps/console-web/src/api/client';
import { readControlAttempt, storeControlAttempt } from '../../apps/console-web/src/api/control-changes.model';
import { ControlMetadataChanges, useControlMetadataChanges } from '../../apps/console-web/src/features/ControlMetadataChanges';
import { actor, anchor, attempt, capabilities, change, cid, csrf, failure, id, identity, intent, json, key, rawReceipt, target, workflow } from './helpers/control-web-fixture';
const options = () => ({ change, clusterId: cid, targetWorkspaceId: target, subject: { id: target, cluster_id: cid, status: 'deleted', revision: 2 }, allowed: true });
const nodes = (tree: any): any[] => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children), ...nodes(tree.props?.extra)] : [];
function hook() { frame.index = 0; return useControlMetadataChanges(); }
function setupFetch(intercept?: (url: string, init: any) => Promise<Response | undefined> | Response | undefined) {
  const fetcher = vi.fn(async (url: string, init: any) => {
    const override = await intercept?.(url, init); if (override) return override;
    if (url === '/api/v1/auth/me') return json({ user: frame.user, csrfToken: csrf });
    if (url.endsWith('/control-changes/prepare') || url.endsWith(`/control-changes/${intent}`) || url.endsWith(`/control-changes/by-key/${key}`)) return json(frame.receipt);
    if (url.endsWith(`/control-changes/${intent}/submit`)) return json({ ...frame.receipt, state: 'pending', workflowId: workflow, revision: 1, planHash: 'b'.repeat(64) });
    return failure();
  }); vi.stubGlobal('fetch', fetcher); return fetcher;
}
beforeEach(async () => {
  frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanup = []; for (const fn of [frame.scopeSelected, frame.clusterSelected, frame.navigate, frame.reload, frame.invalidate, frame.success]) fn.mockReset();
  frame.user = { id: actor, permissionsVersion: identity.version, capabilities: capabilities() };
  frame.cluster = { clusterId: cid, cluster: { execution_mode: 'approval' }, selectCluster: frame.clusterSelected };
  frame.workspace = { ready: false, readonlyWorkspace: true, workspaceId: target, defaultWorkspaceId: undefined, references: [], selectScopeWorkspace: frame.scopeSelected };
  frame.receipt = rawReceipt(); const storage = new Map<string, string>(); vi.stubGlobal('sessionStorage', { getItem: (k: string) => storage.get(k) ?? null, setItem: (k: string, v: string) => storage.set(k, v), removeItem: (k: string) => storage.delete(k) });
  vi.stubGlobal('crypto', { randomUUID: vi.fn().mockReturnValueOnce(key).mockReturnValueOnce(id(20)).mockReturnValue(id(21)) }); vi.stubGlobal('React', await import('react')); vi.stubGlobal('window', { dispatchEvent: vi.fn() }); setApiActorId(actor);
});
afterEach(() => { for (const cleanup of frame.cleanup) cleanup(); setApiActorId(undefined); vi.unstubAllGlobals(); });
describe('Source-only actual Control prepare/review/submit hook', () => {
  it('uses actual deleted target permissions, then prepares under the original rejected Direct key', async () => {
    const fetcher = setupFetch(); await expect(hook().execute(options())).resolves.toBe('prepared'); const row = hook();
    expect(row.prepared?.workspaceId).toBe(anchor); expect(row.prepared?.preview?.affectedScopes[0].workspaceId).toBe(target); expect(row.canSubmit).toBe(true); expect(frame.workspace.ready).toBe(false);
    const packets = fetcher.mock.calls.filter(([, init]) => init.method !== 'GET'); expect(packets).toHaveLength(2); expect(packets[0][1].headers['X-Idempotency-Key']).toBe(packets[1][1].headers['X-Idempotency-Key']);
    expect(JSON.parse(packets[0][1].body)).toEqual(change.input); expect(JSON.parse(packets[1][1].body)).toEqual(change); expect(crypto.randomUUID).toHaveBeenCalledOnce(); expect(readControlAttempt(actor)).toMatchObject({ key, phase: 'prepared', targetWorkspaceId: target, anchorWorkspaceId: anchor });
  });
  it('does not claim saved metadata after preparing, and requires typed confirmation and fresh identical intent before submit', async () => {
    const fetcher = setupFetch(); await hook().execute(options()); const flow = hook(), view = ControlMetadataChanges({ flow });
    expect(frame.success).not.toHaveBeenCalled(); expect(nodes(view).find(node => node.props?.children === '提交审批').props.disabled).toBe(true);
    flow.setTyped('Payments'); await hook().submit(); const row = hook(); expect(row.prepared).toBeUndefined(); expect(row.result?.workflowId).toBe(workflow); expect(readControlAttempt(actor)).toBeUndefined();
    const submit = fetcher.mock.calls.filter(([url, init]) => url.endsWith('/submit') && init.method === 'POST'); expect(submit).toHaveLength(1); expect(submit[0][1].headers['X-Idempotency-Key']).toBe(id(20)); expect(JSON.parse(submit[0][1].body)).toEqual({ confirmed: true, materialHmac: 'a'.repeat(64) });
    row.openWorkflow(); expect(frame.scopeSelected).toHaveBeenCalledWith(cid, target); expect(frame.navigate).toHaveBeenCalledWith(`/workflows/${workflow}?workspaceId=${target}`);
  });
  it('refreshes genuine capabilities after known Direct workspace creation, without replaying the write', async () => {
    frame.user.capabilities = capabilities(anchor); frame.workspace.defaultWorkspaceId = anchor;
    const fetcher = setupFetch((url, init) => init.method === 'POST' && url.includes('/workspaces?') ? json({ id: id(30), cluster_id: cid, revision: 1 }) : undefined);
    const create = { ...options(), change: { resource: 'workspaces' as const, operation: 'create' as const, input: { code: 'new', name: 'New' } }, targetWorkspaceId: anchor, subject: undefined };
    await expect(hook().execute(create)).resolves.toBe('direct'); expect(frame.reload).toHaveBeenCalledOnce(); expect(fetcher.mock.calls.filter(([, init]) => init.method === 'POST')).toHaveLength(1); expect(readControlAttempt(actor)).toBeUndefined();
  });
  it.each(['401', 'lost-direct', 'lost-prepare', 'invalid-prepare'] as const)('retains %s original key and never automatically refreshes/reposts the write', async variant => {
    const fetcher = setupFetch((url, init) => {
      if (init.method !== 'POST') return;
      if (variant === '401' && url.includes('/workspaces/')) return failure('SESSION_EXPIRED', 401);
      if (variant === 'lost-direct' && url.includes('/workspaces/')) throw new Error('controlled loss');
      if (url.endsWith('/prepare') && variant === 'lost-prepare') throw new Error('controlled loss');
      if (url.endsWith('/prepare') && variant === 'invalid-prepare') return json({});
    });
    await expect(hook().execute(options())).rejects.toThrow(); const original = readControlAttempt(actor)!;
    if (variant === '401') { expect(original).toBeUndefined(); expect(fetcher.mock.calls.filter(([, init]) => init.method === 'POST')).toHaveLength(1); }
    else { expect(original).toMatchObject({ key, phase: variant === 'lost-direct' ? 'direct' : 'prepare', state: 'unknown' }); frame.slots = []; frame.deps = []; expect(hook().blocked).toBe(true); await expect(hook().execute(options())).rejects.toThrow(); expect(crypto.randomUUID).toHaveBeenCalledOnce(); }
  });
  it.each([404, 403, 401])('a missing/denied original GET %i keeps the retained key closed to new writes', async status => {
    storeControlAttempt({ ...attempt('prepare'), state: 'unknown' }); const fetcher = setupFetch(url => url.includes('/by-key/') ? failure('CONTROL_CHANGE_INTENT_NOT_FOUND', status) : undefined);
    await hook().verify(); expect(readControlAttempt(actor)?.key).toBe(key); expect(hook().blocked).toBe(true); expect(fetcher.mock.calls.every(([, init]) => init.method === 'GET')).toBe(true); expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('lost submit is checked only by the exact original intent; prepared alone cannot release the submit fence', async () => {
    const fetcher = setupFetch(url => { if (url.endsWith('/submit')) throw new Error('controlled loss'); }); await hook().execute(options()); hook().setTyped('Payments'); await hook().submit();
    expect(readControlAttempt(actor)).toMatchObject({ phase: 'submit', state: 'unknown', key: id(20), intentId: intent }); const count = fetcher.mock.calls.length; await hook().verify();
    expect(fetcher.mock.calls.slice(count).map(([url]) => url)).toEqual([`/api/v1/clusters/${cid}/control-changes/${intent}`]); expect(readControlAttempt(actor)?.key).toBe(id(20)); expect(fetcher.mock.calls.filter(([url]) => url.endsWith('/submit'))).toHaveLength(1);
    frame.receipt = { ...frame.receipt, state: 'pending', workflowId: workflow, revision: 1, planHash: 'b'.repeat(64) }; await hook().verify(); expect(readControlAttempt(actor)).toBeUndefined(); expect(hook().result?.state).toBe('pending'); expect(fetcher.mock.calls.filter(([url]) => url.endsWith('/submit'))).toHaveLength(1);
  });
  it('minimal succeeded own receipt still closes original submit after target disappears and grants change', async () => {
    storeControlAttempt({ ...attempt('submit'), state: 'unknown' }); frame.workspace.workspaceId = undefined; frame.user.permissionsVersion = 'new-PV'; frame.user.capabilities = capabilities(anchor); frame.receipt = { ...frame.receipt, state: 'succeeded', workflowId: workflow, revision: 4, planHash: 'b'.repeat(64), preview: null };
    const fetcher = setupFetch(); await hook().verify(); expect(readControlAttempt(actor)).toBeUndefined(); const flow = hook(); expect(flow.result?.preview).toBeNull(); expect(flow.canSubmit).toBe(false); flow.openWorkflow(); expect(frame.navigate).not.toHaveBeenCalled(); expect(fetcher.mock.calls.every(([, init]) => init.method === 'GET')).toBe(true);
  });
  it.each(['scope', 'actor', 'permission', 'unmount', 'original-reference'] as const)('rejects Direct pre-send when %s changes during fresh session read', async variant => {
    const fetcher = setupFetch(url => { if (url !== '/api/v1/auth/me') return; if (variant === 'scope') { frame.workspace.workspaceId = anchor; hook(); } if (variant === 'actor') setApiActorId(id(99)); if (variant === 'permission') { frame.user.permissionsVersion = 'PV2'; hook(); } if (variant === 'unmount') for (const cleanup of frame.cleanup) cleanup(); if (variant === 'original-reference') { frame.workspace.references = [{ domain: 'iam' }]; hook(); } return json({ user: { ...frame.user, permissionsVersion: identity.version }, csrfToken: csrf }); });
    await expect(hook().execute(options())).rejects.toThrow(); expect(fetcher.mock.calls.every(([, init]) => init.method === 'GET')).toBe(true); expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('refuses a stale captured data source/workspace handler after its selected CID changes', async () => { frame.cluster.clusterId = id(99); const fetcher = setupFetch(); await expect(hook().execute(options())).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled(); expect(crypto.randomUUID).not.toHaveBeenCalled(); });
  it('rechecks current real target and workflow grants after each submit read, excluding anchor-only authority', async () => {
    let revoke = false; const fetcher = setupFetch(url => { if (revoke && url.endsWith(`/control-changes/${intent}`)) { frame.user.capabilities = capabilities(anchor); hook(); return json(frame.receipt); } });
    await hook().execute(options()); hook().setTyped('Payments'); revoke = true; await hook().submit(); expect(fetcher.mock.calls.some(([url]) => url.endsWith('/submit'))).toBe(false); expect(readControlAttempt(actor)?.phase).toBe('prepared');
  });
  it('closing a review during submit reads prevents sending and keeps the known prepared record', async () => {
    let close = false; const fetcher = setupFetch(url => { if (close && url.endsWith(`/control-changes/${intent}`)) { hook().closeReview(); hook(); return json(frame.receipt); } });
    await hook().execute(options()); hook().setTyped('Payments'); close = true; await hook().submit(); expect(fetcher.mock.calls.some(([url]) => url.endsWith('/submit'))).toBe(false); expect(readControlAttempt(actor)?.phase).toBe('prepared');
  });
});
