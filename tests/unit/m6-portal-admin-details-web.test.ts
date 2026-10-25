import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], effects: [] as Array<() => void>, scope: null as any, actor: '', queries: [] as any[], queryResult: null as any, pages: [] as any[], cursor: null as any, request: vi.fn() }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = typeof value === 'function' ? value(frame.slots[index]) : value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void)) => { const cleanup = effect(); if (cleanup) frame.effects.push(cleanup); },
}));
vi.mock('@tanstack/react-query', () => ({ useQuery: (options: any) => { frame.queries.push(options); return frame.queryResult; } }));
vi.mock('../../apps/console-web/src/api/client', async original => ({ ...await original<typeof import('../../apps/console-web/src/api/client')>(), api: frame.request, getApiActorId: () => frame.actor }));
vi.mock('../../apps/console-web/src/features/portal-hooks', () => ({ usePortalScope: () => frame.scope, usePortalPage: (resource: string, filters: unknown, enabled: unknown) => { frame.pages.push({ resource, filters, enabled }); return { data: { items: [] }, page: 1, isFetching: false }; } }));
vi.mock('../../apps/console-web/src/features/WorkflowsPage', () => ({ PortalPager: 'PortalPager' }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError' }));
vi.mock('../../apps/portal-web/src/app/PortalContext', () => ({ usePortal: () => ({ tenant: { slug: 'unit-tenant' } }) }));
vi.mock('../../apps/portal-web/src/components/Shared', async original => ({ ...await original<typeof import('../../apps/portal-web/src/components/Shared')>(), useCursor: () => frame.cursor }));

import { ApplicationGrants, ApplicationRequests, PortalAdminDetails, PortalDetailPanel, portalDetailQueryKey, portalDetailScopeKey, validatePortalAdminDetail } from '../../apps/console-web/src/features/PortalAdminDetails';
import { CatalogPage, CatalogScanNotice } from '../../apps/portal-web/src/features/PublicPages';
import { CursorPagination } from '../../apps/portal-web/src/components/Shared';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', id = 'bc7bd065-9372-405d-9782-015d31a30aa1';
function nodes(tree: any): any[] { return Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []; }
function detail(readGrants = false, readRequests = false) { return { entity: { id, clusterId: cid, workspaceId: wid, developerId: actor, name: 'unit application', description: '', state: 'archived' as const, revision: 3, createdAt: '2026-10-11T00:00:00Z', capabilities: { readGrants, readRequests } } }; }
function selection(kind: 'application' | 'developer' = 'application') { return { kind, id, label: 'unit safe name', scopeKey: portalDetailScopeKey(frame.scope) }; }
function render() { frame.index = 0; return PortalDetailPanel({ selection: selection(), onClose: vi.fn() }); }
const tabs = (tree: any) => nodes(tree).find(node => node.props?.items?.some((item: any) => item.key === 'configuration'));

beforeEach(async () => {
  frame.index = 0; frame.slots = []; frame.effects = []; frame.queries = []; frame.pages = []; frame.request.mockReset(); frame.actor = actor;
  frame.scope = { cid, wid, actor, version: 'actor:7', ready: true, permission: { can: () => true }, path: (resource: string) => `/clusters/${frame.scope.cid}/${resource}?workspaceId=${frame.scope.wid}` };
  frame.queryResult = { data: detail(), isFetching: false, refetch: vi.fn() };
  frame.cursor = { data: { items: [], nextCursor: null }, page: 1, isFetching: false };
  vi.stubGlobal('React', await import('react'));
});
afterEach(() => { vi.unstubAllGlobals(); });

describe('actual Console Portal root and relation detail controls', () => {
  it('allows an application-only root while both relationships remain independently forbidden, with zero relation reads', () => {
    const tree = render(), items = tabs(tree).props.items;
    expect(frame.queries[0].enabled).toBe(true); expect(items.find((item: any) => item.key === 'grants').children.props.message).toBe('授权记录未授权');
    expect(items.find((item: any) => item.key === 'requests').children.props.message).toBe('申请记录未授权'); expect(frame.pages).toHaveLength(0);
  });
  it('loads the grant tab only after explicit selection and does not widen permission to requests', () => {
    frame.queryResult.data = detail(true, false); const initial = render(); expect(tabs(initial).props.items.find((item: any) => item.key === 'grants').children).toBe(false);
    tabs(initial).props.onChange('grants'); const selected = render(), children = tabs(selected).props.items.find((item: any) => item.key === 'grants').children;
    expect(children.type).toBe(ApplicationGrants); children.type(children.props); expect(frame.pages).toEqual([{ resource: `portal/applications/${id}/grants`, filters: undefined, enabled: undefined }]);
    expect(tabs(selected).props.items.find((item: any) => item.key === 'requests').children.props.message).toBe('申请记录未授权');
  });
  it('uses the independent request capability and links safe request IDs to the existing workflow page', () => {
    frame.queryResult.data = detail(false, true); const initial = render(); tabs(initial).props.onChange('requests'); const selected = render();
    const children = tabs(selected).props.items.find((item: any) => item.key === 'requests').children; expect(children.type).toBe(ApplicationRequests);
    const requestTable = nodes(children.type(children.props)).find(node => node.props?.columns); const link = requestTable.props.columns.at(-1).render(undefined, { id: actor }).props.children;
    expect(link.props.to).toBe(`/workflows/${actor}`); expect(frame.pages[0].resource).toBe(`portal/applications/${id}/requests`);
  });
  it('fails closed if capabilities are absent or merely truthy rather than explicit booleans', () => {
    frame.queryResult.data.entity.capabilities = { readGrants: 'true', readRequests: 1 }; const items = tabs(render()).props.items;
    expect(items.find((item: any) => item.key === 'grants').children.props.message).toBe('授权记录未授权'); expect(items.find((item: any) => item.key === 'requests').children.props.message).toBe('申请记录未授权');
  });
  it('keys every root cache by account, permission epoch, cluster, workspace, type and ID, retaining no inactive cache', () => {
    render(); expect(frame.queries[0].queryKey).toEqual(['portal-admin-detail', cid, wid, actor, 'actor:7', 'application', id]); expect(frame.queries[0]).toMatchObject({ gcTime: 0, staleTime: 0, retry: false });
    for (const field of ['cid', 'wid', 'actor', 'version']) expect(portalDetailQueryKey({ ...frame.scope, [field]: 'changed' }, selection())).not.toEqual(frame.queries[0].queryKey);
  });
  it.each(['cid', 'wid', 'actor', 'version'])('closes and renders no old drawer after %s changes, before any new requests', field => {
    const original = selection(), close = vi.fn(); frame.scope = { ...frame.scope, [field]: 'changed' }; frame.index = 0;
    expect(PortalAdminDetails({ selection: original, onClose: close })).toBeNull(); expect(close).toHaveBeenCalledOnce(); expect(frame.queries).toHaveLength(0); expect(frame.request).not.toHaveBeenCalled();
  });
  it('passes abort through the BFF and rejects a late root response after actor change', async () => {
    let resolve!: (value: unknown) => void; frame.request.mockImplementation(() => new Promise(done => { resolve = done; })); render();
    const controller = new AbortController(), pending = frame.queries[0].queryFn({ signal: controller.signal });
    expect(frame.request).toHaveBeenCalledWith(`/clusters/${cid}/portal/applications/${id}?workspaceId=${wid}`, { signal: controller.signal });
    frame.actor = 'changed'; resolve(detail()); await expect(pending).rejects.toMatchObject({ code: 'SESSION_CHANGED' });
  });
  it.each(['unmount', 'abort'])('rejects late data on %s without admitting stale detail', async reason => {
    let resolve!: (value: unknown) => void; frame.request.mockImplementation(() => new Promise(done => { resolve = done; })); render();
    const controller = new AbortController(), pending = frame.queries[0].queryFn({ signal: controller.signal });
    if (reason === 'unmount') for (const cleanup of frame.effects) cleanup(); else controller.abort(); resolve(detail());
    await expect(pending).rejects.toMatchObject({ code: 'SESSION_CHANGED' });
  });
  it('does not render arbitrary secret fields and never offers a credential or native-object endpoint', () => {
    const root = render(), config = tabs(root).props.items[0].children, configTree = config.type({ detail: { ...detail(), entity: { ...detail().entity, key: 'must-not-render', nativeConsumerId: id } } });
    const safeText = JSON.stringify(configTree); expect(safeText).not.toContain('must-not-render'); expect(safeText).not.toContain('nativeConsumerId'); expect(frame.pages).toHaveLength(0);
  });
  it('keeps a released failed reservation separate from credential issue success', () => {
    const tree = ApplicationGrants({ applicationId: id }); const notice = nodes(tree).find(node => node.props?.message === '保留历史授权状态，不显示凭证');
    expect(notice.props.description).toContain('不代表凭证发放成功'); expect(nodes(tree).find(node => node.props?.columns).props.columns.some((column: any) => /密钥|工作流/.test(column.title))).toBe(false);
  });
  it('rejects another tenant or another entity root even when the cached object has matching safe fields', () => {
    for (const patch of [{ id: actor }, { clusterId: actor }, { workspaceId: actor }]) expect(() => validatePortalAdminDetail({ entity: { ...detail().entity, ...patch } }, selection(), frame.scope)).toThrow();
  });
});

describe('actual public Catalog partial proof scanning', () => {
  it('labels empty partial results as unfinished instead of claiming no API matches', () => {
    const alert = CatalogScanNotice({ page: { items: [], nextCursor: 'bounded-next', scanIncomplete: true, searchedRows: 500 } });
    expect(alert!.props['data-testid']).toBe('portal-catalog-partial'); expect(alert!.props.message).toContain('尚未找到'); expect(JSON.stringify(alert)).toContain('继续筛选下一页');
    expect(alert!.props.message).not.toContain('没有已发布');
  });
  it('continues only after an explicit cursor button click and never invents a missing next cursor', () => {
    const next = vi.fn(); frame.cursor = { ...frame.cursor, data: { items: [], nextCursor: 'bounded-next', scanIncomplete: true, searchedRows: 500 }, next };
    frame.index = 0; const tree = CatalogPage(), pagination = nodes(tree).find(node => node.type === CursorPagination); expect(next).not.toHaveBeenCalled(); expect(pagination.props.nextLabel).toBe('继续筛选下一页');
    const controls = nodes(CursorPagination(pagination.props)), button = controls.find(node => node.props?.children === '继续筛选下一页'); expect(button.props.disabled).toBe(false); button.props.onClick(); expect(next).toHaveBeenCalledOnce();
    frame.cursor.next = undefined; frame.index = 0; const noCursor = nodes(CatalogPage()).find(node => node.type === CursorPagination); expect(nodes(CursorPagination(noCursor.props)).find(node => node.props?.children === '继续筛选下一页').props.disabled).toBe(true);
  });
  it('uses an empty notice only for completed scans and suppresses premature empty results during loading', () => {
    expect(CatalogScanNotice({ page: { items: [], nextCursor: null, scanIncomplete: false, searchedRows: 9 } })!.props['data-testid']).toBe('portal-catalog-empty');
    expect(CatalogScanNotice({ page: { items: [], nextCursor: null }, loading: true })).toBeNull(); expect(CatalogScanNotice({})).toBeNull();
  });
  it('retains partial status even when some matches are visible, without claiming a total count', () => {
    const row = { id, name: 'safe API' } as any; const alert = CatalogScanNotice({ page: { items: [row], nextCursor: 'next', scanIncomplete: true, searchedRows: 500 } });
    expect(alert!.props.message).toBe('目录筛选尚未完成'); expect(JSON.stringify(alert)).not.toContain('总计');
  });
});
