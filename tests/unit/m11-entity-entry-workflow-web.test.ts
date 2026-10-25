import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanups: [] as Array<() => void>, dialogs: [] as any[], navigate: vi.fn(), user: null as any, cluster: null as any, workspace: null as any, storage: new Map<string, string>(), nativeAllowed: true, mutations: [] as any[], form: { resetFields: vi.fn(), setFieldsValue: vi.fn(), setFieldValue: vi.fn(), getFieldValue: vi.fn(), getFieldsValue: vi.fn(), submit: vi.fn() }, success: vi.fn(), invalidate: vi.fn(), selectedWid: undefined as string | undefined, detailId: undefined as string | undefined }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = typeof initial === 'function' ? initial() : initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = typeof value === 'function' ? value(frame.slots[index]) : value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanups.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ modal: {}, message: { success: frame.success, error: vi.fn() } }) }, Form: { useForm: () => [frame.form], useWatch: () => undefined } }));
vi.mock('react-router-dom', async original => ({ ...await original<typeof import('react-router-dom')>(), useNavigate: () => frame.navigate, useParams: () => ({ entityType: 'services', entityId: frame.detailId }), useSearchParams: () => [new URLSearchParams(frame.selectedWid ? { workspaceId: frame.selectedWid } : {}), vi.fn()] }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: frame.user }) }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => frame.cluster }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => frame.workspace }));
vi.mock('../../apps/console-web/src/app/Permissions', () => ({ usePermissions: () => ({ version: frame.user.permissionsVersion, platformAdmin: false, has: () => frame.nativeAllowed, create: () => frame.nativeAllowed, can: (module: string, action: string) => frame.nativeAllowed && !(module === 'recycle-bin' && action === 'delete') }) }));
vi.mock('../../apps/console-web/src/app/EntityPermissions', () => ({ useEntityPermissions: (references: any[]) => ({ can: (_type: string, id: string) => frame.nativeAllowed && references.some(row => row.id === id), query: {} }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_: unknown, options: any) => { frame.dialogs.push(options); } }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError', NoCluster: 'NoCluster', PageHeading: 'PageHeading', formatTime: (value: string) => value }));
vi.mock('../../apps/console-web/src/components/CursorPagination', () => ({ CursorPagination: 'CursorPagination', useCursorPages: () => ({}) }));
vi.mock('../../apps/console-web/src/components/KongSchemaForm', () => ({ KongSchemaForm: 'KongSchemaForm', prepareFormValues: (_: unknown, value: unknown) => value ?? {}, formPayload: (_: unknown, value: unknown) => value, schemaFields: (schema: any) => schema.fields.map((field: any) => Object.entries(field)[0]) }));
vi.mock('../../apps/console-web/src/features/EntityDetails', () => ({ EntityDetails: 'EntityDetails' }));
vi.mock('../../apps/console-web/src/features/RecycleReconciliation', () => ({ RecycleReconciliation: 'RecycleReconciliation' }));
vi.mock('@tanstack/react-query', () => ({
  useQueryClient: () => ({ invalidateQueries: frame.invalidate }), useInfiniteQuery: () => ({ data: { pages: [] } }),
  useQuery: (options: any) => ({ data: options.queryKey[0] === 'schema' ? { fields: [{ name: { type: 'string' } }, { host: { type: 'string' } }] } : options.queryKey[0] === 'archive-workspace' ? { id: frame.selectedWid ?? frame.workspace.workspaceId, status: 'active', name: 'test workspace' } : options.queryKey[0] === 'entities' ? { items: [entity], nextCursor: null } : options.queryKey[0] === 'recycle' ? { items: [archive], nextCursor: null } : undefined, refetch: vi.fn() }),
  useMutation: (options: any) => { const mutation = { options, isPending: false, mutate: vi.fn(async (value: unknown) => { try { const result = await options.mutationFn(value); await options.onSuccess?.(result); } catch (error) { options.onError?.(error); } }) }; frame.mutations.push(mutation); return mutation; },
}));

import { api, setApiActorId, setCsrfToken } from '../../apps/console-web/src/api/client';
import { EntityEditor, useEntityChangePreparation } from '../../apps/console-web/src/features/EntityEditor';
import { EntitiesPage } from '../../apps/console-web/src/features/EntitiesPage';
import { RecycleBinPage } from '../../apps/console-web/src/features/RecycleBinPage';
import { entityEntryIntentHref, entityEntryPreparationBody } from '../../apps/console-web/src/features/entity-entry-change.model';
import { readWorkflowAttempt, workflowAttemptStorageKey } from '../../apps/console-web/src/features/workflow-entity-change.model';

const actor = '30b6d312-a9b8-4ac4-b49d-d8d87e1eeccf', cid = 'a949b292-2e4a-4326-b30d-3a883b5ef3d7', wid = '306a8d36-d1f9-4542-8972-9b30aa1bd67c';
const id = '35b60072-927d-4f3b-bba1-dbc31bd345e4', key = 'f02f0f79-03bb-4494-9b2c-f3fa4a28a28a', foreign = 'c6439d99-75a0-4f2b-b6d7-a2d3f0c87177';
const entity = { id, name: 'unit Service', host: 'localhost', tags: ['unit'] }, archive = { id, root_name: entity.name, original_id: foreign, root_type: 'services', state: 'active' };
const change = { kind: 'entity' as const, action: 'create' as const, entityType: 'services', body: { name: 'unit', host: 'localhost', client_secret: 'synthetic-secret-body-not-journalled' } };
const json = (data: unknown) => new Response(JSON.stringify({ data }), { headers: { 'Content-Type': 'application/json' } });
function intent(): any { return { id, revision: 1, materialHmac: 'b'.repeat(64), executionMode: 'approval', issuedAt: '2026-10-13T00:00:00Z', expiresAt: '2099-01-01T00:00:00Z', nativeExecutionAvailable: false, capabilities: { submit: true }, review: { changes: [{ entityType: 'services', nativeId: id, action: 'create', before: null, after: { name: 'unit' } }], impact: { changedObjects: 1, nativePackets: 1, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: { state: 'baseline-required', blockerCodes: [] } } }; }
function treeNodes(tree: any): any[] { return Array.isArray(tree) ? tree.flatMap(treeNodes) : tree && typeof tree === 'object' ? [tree, ...treeNodes(tree.props?.children)] : []; }
function renderHook(enabled = true) { frame.index = 0; return useEntityChangePreparation({ clusterId: frame.cluster.clusterId, workspaceId: frame.workspace.workspaceId, enabled }); }
function renderEditor() { frame.index = 0; return EntityEditor({ type: 'services', entity, open: true, onClose: vi.fn(), onSaved: frame.success }); }
function renderPage(component: () => any) { frame.index = 0; return component(); }
function tableAction(tree: any, name: string, row: any) { const table = treeNodes(tree).find(node => node.props?.columns?.some((column: any) => column.title === '操作')); return treeNodes(table.props.columns.find((column: any) => column.title === '操作').render(undefined, row)).find(node => node.props?.children === name); }

beforeEach(async () => {
  frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanups = []; frame.dialogs = []; frame.storage.clear(); frame.mutations = []; frame.nativeAllowed = true; frame.selectedWid = undefined; frame.detailId = undefined;
  frame.navigate.mockReset(); frame.success.mockReset(); frame.invalidate.mockReset();
  frame.user = { id: actor, permissionsVersion: 'PV1', capabilities: { platformAdmin: false, grants: [{ module: 'workflows', action: 'write', scope_type: 'workspace', scope_values: [wid], cluster_id: cid, workspace_id: wid }] } };
  frame.cluster = { clusterId: cid, cluster: { id: cid, execution_mode: 'approval' } };
  frame.workspace = { workspaceId: wid, workspace: { id: wid, name: 'test workspace', status: 'active' }, ready: true, writeBlocked: false, readonlyWorkspace: false, references: [], workspaces: [] };
  vi.stubGlobal('React', await import('react')); vi.stubGlobal('crypto', { randomUUID: vi.fn(() => key) });
  vi.stubGlobal('window', { dispatchEvent: vi.fn() }); vi.stubGlobal('sessionStorage', { getItem: (name: string) => frame.storage.get(name) ?? null, setItem: (name: string, value: string) => frame.storage.set(name, value), removeItem: (name: string) => frame.storage.delete(name) });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: any) { super(type); this.detail = options?.detail; } });
  setApiActorId(actor); setCsrfToken('unit-only-csrf');
});
afterEach(() => { for (const cleanup of frame.cleanups) cleanup(); setApiActorId(undefined); setCsrfToken(''); vi.unstubAllGlobals(); });

describe('M11 typed entity entry preparation model and original key transport', () => {
  it('projects only typed create/update/delete/restore intent fields; never accepts path/authority or emits execution input', () => {
    expect(entityEntryPreparationBody({ ...change, canonicalPath: '/vaults', nativeAuthority: true } as any)).toEqual({ change });
    expect(entityEntryPreparationBody({ ...change, action: 'update', entityId: id })).toEqual({ change: { ...change, action: 'update', entityId: id } });
    expect(entityEntryPreparationBody({ kind: 'recycle', action: 'delete', entityType: 'services', entityId: id, confirmed: true, confirm_name: 'unit' })).toEqual({ change: { kind: 'recycle', action: 'delete', entityType: 'services', entityId: id, confirmed: true, confirm_name: 'unit' } });
    expect(entityEntryPreparationBody({ kind: 'recycle', action: 'restore', entryId: id, confirmed: true, confirm_name: 'unit' }).change).not.toHaveProperty('entityId');
    expect(entityEntryIntentHref(id)).toBe(`/workflows?tab=changes&intent=${id}`);
  });
  it('rejects invalid IDs, unconfirmed deletion and unsupported entity types before POST', async () => {
    vi.stubGlobal('fetch', vi.fn());
    for (const patch of [{ entityType: 'vaults' }, { body: [] }, { action: 'update', entityId: 'bad' }, { entityId: id }]) expect(() => entityEntryPreparationBody({ ...change, ...patch } as any)).toThrow();
    expect(() => entityEntryPreparationBody({ kind: 'recycle', action: 'delete', entityType: 'services', entityId: id, confirmed: false, confirm_name: 'unit' } as any)).toThrow();
    expect(() => entityEntryIntentHref('bad')).toThrow(); await expect(renderHook().prepare({ ...change, entityType: 'keys' })).rejects.toThrow(); expect(fetch).not.toHaveBeenCalled();
  });
  it('requires actual workflow write grants and valid current scope, independent from native capability', async () => {
    frame.user.capabilities.grants = []; vi.stubGlobal('fetch', vi.fn()); const hook = renderHook(); expect(hook.allowed).toBe(false); await expect(hook.prepare(change)).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_BLOCKED' }); expect(fetch).not.toHaveBeenCalled();
  });
  it('retains safe original identifiers before exactly one prepare POST, then hands off actual intent without native authority', async () => {
    const fetch = vi.fn(async () => { const stored = [...frame.storage.values()].join(''); expect(stored).toContain(key); expect(stored).not.toContain('synthetic-secret'); return json(intent()); }); vi.stubGlobal('fetch', fetch);
    const result = await renderHook().prepare(change); expect(result.nativeExecutionAvailable).toBe(false); expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/entity-changes/prepare?workspaceId=${wid}`); expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ change }); expect(frame.storage.size).toBe(0); expect(frame.success).not.toHaveBeenCalled();
  });
  it('keeps an interrupted prepare at the original key across reload and blocks every new POST', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('lost response')); vi.stubGlobal('fetch', fetch); await expect(renderHook().prepare(change)).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_RESULT_UNKNOWN' });
    const retained = readWorkflowAttempt({ actor, cid, wid, version: 'PV1' }, 'prepare'); expect(retained).toMatchObject({ key, state: 'unknown' }); expect(JSON.stringify(retained)).not.toContain('synthetic-secret');
    frame.index = 0; frame.slots = []; frame.deps = []; const reopened = renderHook(); expect(reopened.attempt?.key).toBe(key); await expect(reopened.prepare(change)).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_BLOCKED' }); expect(fetch).toHaveBeenCalledOnce();
  });
  it('blocks concurrent preparation even before React publishes the pending state', async () => {
    let resolve!: (value: Response) => void; const fetch = vi.fn(() => new Promise<Response>(done => { resolve = done; })); vi.stubGlobal('fetch', fetch); const hook = renderHook(), pending = hook.prepare(change);
    await expect(hook.prepare(change)).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_BLOCKED' }); expect(fetch).toHaveBeenCalledOnce(); resolve(json(intent())); await pending;
  });
  it.each(['actor', 'workspace', 'permission', 'unmount', 'disabled'])('rejects a late prepared result after %s change and retains only the original safe key/intent', async variant => {
    let resolve!: (value: Response) => void; const fetch = vi.fn(() => new Promise<Response>(done => { resolve = done; })); vi.stubGlobal('fetch', fetch); const pending = renderHook().prepare(change);
    if (variant === 'actor') setApiActorId(foreign);
    if (variant === 'workspace') { frame.workspace.workspaceId = foreign; renderHook(); }
    if (variant === 'permission') { frame.user.permissionsVersion = 'PV2'; renderHook(); }
    if (variant === 'unmount') for (const cleanup of frame.cleanups) cleanup();
    if (variant === 'disabled') renderHook(false);
    resolve(json(intent())); await expect(pending).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_RESULT_UNKNOWN' });
    expect(readWorkflowAttempt({ actor, cid, wid, version: 'PV1' }, 'prepare')?.state).toBe('unknown'); expect(frame.navigate).not.toHaveBeenCalled(); expect(fetch).toHaveBeenCalledOnce();
  });
  it('clears a known rejected preparation without inventing a native receipt or automatically replaying it', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'SCHEMA_INVALID', message: 'invalid' } }), { status: 400, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetch);
    await expect(renderHook().prepare(change)).rejects.toMatchObject({ status: 400 }); expect(frame.storage.size).toBe(0); expect(fetch).toHaveBeenCalledOnce();
  });
  it('retains invalid successful responses as unknown rather than navigating or claiming execution', async () => {
    const fetch = vi.fn().mockResolvedValue(json({ id, revision: 1 })); vi.stubGlobal('fetch', fetch); await expect(renderHook().prepare(change)).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_RESULT_UNKNOWN' });
    expect(frame.storage.get(workflowAttemptStorageKey({ actor, cid, wid }, 'prepare'))).toContain('unknown'); expect(fetch).toHaveBeenCalledOnce(); expect(frame.navigate).not.toHaveBeenCalled();
  });
});

describe('actual M11 entity editor/list/recycle approval entries', () => {
  it('creates a schema-backed entity preparation without sending a caller-selected entity ID or executing it', async () => {
    const fetch = vi.fn().mockResolvedValue(json(intent())); vi.stubGlobal('fetch', fetch); frame.index = 0;
    const tree = EntityEditor({ type: 'services', open: true, onClose: vi.fn(), onSaved: frame.success });
    treeNodes(tree).find(node => node.type === 'KongSchemaForm').props.onFinish({ name: 'new unit', host: 'localhost' });
    expect(frame.dialogs[0].expected).toBe('new unit'); await frame.dialogs[0].onConfirm();
    expect(JSON.parse(fetch.mock.calls[0][1].body).change).toEqual({ kind: 'entity', action: 'create', entityType: 'services', body: { name: 'new unit', host: 'localhost' } });
    expect(frame.navigate).toHaveBeenCalledWith(entityEntryIntentHref(id)); expect(frame.success).not.toHaveBeenCalled();
  });
  it('schema update first confirms, then only prepares and navigates to intent; never direct PATCH/onSaved/propagation', async () => {
    const fetch = vi.fn().mockResolvedValue(json(intent())); vi.stubGlobal('fetch', fetch); const tree = renderEditor(), schema = treeNodes(tree).find(node => node.type === 'KongSchemaForm');
    expect(treeNodes(tree.props.extra).find(node => node.props?.children === '提交变更工单').props.disabled).toBe(false); schema.props.onFinish({ name: entity.name, host: 'changed.example' });
    expect(fetch).not.toHaveBeenCalled(); expect(frame.dialogs[0].expected).toBe(entity.name); await frame.dialogs[0].onConfirm();
    expect(JSON.parse(fetch.mock.calls[0][1].body).change).toEqual({ kind: 'entity', action: 'update', entityType: 'services', entityId: id, body: { name: entity.name, host: 'changed.example' } });
    expect(frame.navigate).toHaveBeenCalledWith(entityEntryIntentHref(id)); expect(frame.invalidate).not.toHaveBeenCalled(); expect(frame.success).not.toHaveBeenCalled(); expect(frame.mutations[0].mutate).not.toHaveBeenCalled();
  });
  it('keeps read-only/native-denied and workflow-denied editor buttons disabled', () => {
    frame.nativeAllowed = false; const denied = renderEditor(); expect(treeNodes(denied.props.extra).find(node => node.props?.children === '提交变更工单').props.disabled).toBe(true);
    frame.nativeAllowed = true; frame.user.capabilities.grants = []; const workflowDenied = renderEditor(); expect(treeNodes(workflowDenied.props.extra).find(node => node.props?.children === '提交变更工单').props.disabled).toBe(true);
  });
  it('keeps the original interrupted editor preparation locked and does not issue a second POST', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('lost prepare response')); vi.stubGlobal('fetch', fetch);
    treeNodes(renderEditor()).find(node => node.type === 'KongSchemaForm').props.onFinish({ name: entity.name, host: 'localhost' });
    await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'ENTITY_PREPARATION_RESULT_UNKNOWN' });
    const reopened = renderEditor(); expect(treeNodes(reopened.props.extra).find(node => node.props?.children === '提交变更工单').props.disabled).toBe(true);
    treeNodes(reopened).find(node => node.type === 'KongSchemaForm').props.onFinish({ name: entity.name, host: 'localhost' });
    expect(frame.dialogs).toHaveLength(1); expect(fetch).toHaveBeenCalledOnce(); expect(frame.navigate).not.toHaveBeenCalled();
  });
  it('refuses a confirmed editor submit after account switch, before creating any new key or POST', async () => {
    vi.stubGlobal('fetch', vi.fn()); treeNodes(renderEditor()).find(node => node.type === 'KongSchemaForm').props.onFinish({ name: entity.name, host: 'localhost' });
    setApiActorId(foreign); await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'SCOPE_CHANGED' });
    expect(fetch).not.toHaveBeenCalled(); expect(crypto.randomUUID).not.toHaveBeenCalled(); expect(frame.storage.size).toBe(0);
  });
  it('entity deletion still requires typed name confirmation and sends recycle delete preparation only', async () => {
    const fetch = vi.fn().mockResolvedValue(json(intent())); vi.stubGlobal('fetch', fetch); const tree = renderPage(EntitiesPage), button = tableAction(tree, '提交删除工单', entity);
    expect(button.props.disabled).toBe(false); button.props.onClick(); expect(fetch).not.toHaveBeenCalled(); expect(frame.dialogs[0].expected).toBe(entity.name); await frame.dialogs[0].onConfirm();
    expect(fetch).toHaveBeenCalledOnce(); expect(JSON.parse(fetch.mock.calls[0][1].body).change).toEqual({ kind: 'recycle', action: 'delete', entityType: 'services', entityId: id, confirmed: true, confirm_name: entity.name });
    expect(frame.navigate).toHaveBeenCalledWith(entityEntryIntentHref(id)); expect(frame.success).not.toHaveBeenCalled();
  });
  it('includes a deep-linked detail outside the current list cursor in the real projection input, without relying on a child boolean', async () => {
    frame.detailId = foreign; const fetch = vi.fn().mockResolvedValue(json(intent())); vi.stubGlobal('fetch', fetch);
    const tree = renderPage(EntitiesPage), detail = treeNodes(tree).find(node => node.type === 'EntityDetails');
    detail.props.onDelete({ id: foreign, name: 'outside current page' }); await frame.dialogs[0].onConfirm();
    expect(fetch).toHaveBeenCalledOnce(); expect(JSON.parse(fetch.mock.calls[0][1].body).change.entityId).toBe(foreign);
  });
  it('recycle restore still confirms root name and sends only original entry ID preparation; purge remains protected without a delete grant', async () => {
    const fetch = vi.fn().mockResolvedValue(json(intent())); vi.stubGlobal('fetch', fetch); const tree = renderPage(RecycleBinPage), restore = tableAction(tree, '提交恢复工单', archive);
    expect(restore.props.disabled).toBe(false); expect(tableAction(tree, '提交清除工单', archive).props.disabled).toBe(true); restore.props.onClick(); expect(fetch).not.toHaveBeenCalled();
    expect(frame.dialogs[0].expected).toBe(entity.name); await frame.dialogs[0].onConfirm(); expect(JSON.parse(fetch.mock.calls[0][1].body).change).toEqual({ kind: 'recycle', action: 'restore', entryId: id, confirmed: true, confirm_name: entity.name });
    expect(frame.navigate).toHaveBeenCalledWith(entityEntryIntentHref(id)); expect(frame.success).not.toHaveBeenCalled();
  });
  it('requires the selected workspace anchor for approval restore, rather than navigating a foreign intent under current scope', () => {
    frame.selectedWid = foreign; const tree = renderPage(RecycleBinPage); expect(tableAction(tree, '提交恢复工单', archive).props.disabled).toBe(true);
    expect(treeNodes(tree).some(node => node.props?.message === '请先切换到归档对象所属工作区，再提交恢复工单')).toBe(true);
  });
  it('rechecks delete permission after typed confirmation rather than treating a rendered button as a grant', async () => {
    vi.stubGlobal('fetch', vi.fn()); tableAction(renderPage(EntitiesPage), '提交删除工单', entity).props.onClick(); frame.nativeAllowed = false;
    await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'FORBIDDEN' }); expect(fetch).not.toHaveBeenCalled();
  });
  it('does not offer an approval entry when the workspace is disabled/read-only', () => {
    frame.workspace.readonlyWorkspace = true;
    const tree = renderPage(EntitiesPage); expect(tableAction(tree, '提交删除工单', entity).props.disabled).toBe(true);
    const heading = treeNodes(tree).find(node => node.type === 'PageHeading'); expect(heading.props.extra.props.disabled).toBe(true);
  });
  it('retains direct-mode delete behavior without fabricating an approval intent', async () => {
    frame.cluster.cluster.execution_mode = 'direct'; const fetch = vi.fn().mockResolvedValue(json({ archived: true })); vi.stubGlobal('fetch', fetch); tableAction(renderPage(EntitiesPage), '删除', entity).props.onClick(); await frame.dialogs[0].onConfirm();
    expect(fetch.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/entities/services/${id}?workspaceId=${wid}`); expect(fetch.mock.calls[0][1].method).toBe('DELETE'); expect(frame.success).toHaveBeenCalledWith('对象已移入回收站');
  });
});
