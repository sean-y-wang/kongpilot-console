import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const frame = vi.hoisted(() => ({ area: 'parent', index: 0, hooks: { parent: [] as any[], drawer: [] as any[] }, effects: [] as any[], mutations: [] as any[], dialogs: [] as any[],
  actor: '5f587b41-bad2-4232-a7b5-08b8d42756f0', cid: 'df710589-3b87-4198-94ba-4abf818de2e1', wid: 'fa2c5ef7-448a-449d-aaf9-97bec18e5370', parent: '058e1839-a66e-4faf-9d99-32c7b615f131', targetId: 'e7df6ec4-cd6d-4f57-8de0-108111094491',
  version: 'current-target-version', mode: 'approval', allowed: true, readonly: false, writeBlocked: false, healthState: 'HEALTHY', healthError: false,
  api: vi.fn(), success: vi.fn(), invalidate: vi.fn(), navigate: vi.fn(), values: new Map<string, string>(), rows: [] as any[], receipt: {} as any,
  form: { resetFields: vi.fn(), setFieldsValue: vi.fn(), submit: vi.fn() } }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState(initial: any) { const hooks = frame.hooks[frame.area as 'parent' | 'drawer'], n = frame.index++; if (!(n in hooks)) hooks[n] = typeof initial === 'function' ? initial() : initial; return [hooks[n], (value: any) => { hooks[n] = typeof value === 'function' ? value(hooks[n]) : value; }]; },
  useRef(initial: any) { const hooks = frame.hooks[frame.area as 'parent' | 'drawer'], n = frame.index++; return hooks[n] ?? (hooks[n] = { current: initial }); },
  useMemo(fn: any, deps: any[]) { const hooks = frame.hooks[frame.area as 'parent' | 'drawer'], n = frame.index++, previous = hooks[n]; if (!previous || !deps || deps.some((value: any, i: number) => value !== previous.deps[i])) hooks[n] = { deps, value: fn() }; return hooks[n].value; }, useEffect(fn: any) { frame.effects.push(fn); } }));
vi.mock('antd', () => ({ Alert: 'Alert', Button: 'Button', Descriptions: 'Descriptions', Drawer: 'Drawer', Input: 'Input', InputNumber: 'InputNumber', Modal: 'Modal', Select: 'Select', Space: 'Space', Table: 'Table', Tag: 'Tag',
  Typography: { Text: 'TypographyText', Paragraph: 'TypographyParagraph', Title: 'TypographyTitle' }, Form: Object.assign(() => null, { Item: 'FormItem', useForm: () => [frame.form] }), App: { useApp: () => ({ message: { success: frame.success, error: vi.fn() }, modal: {} }) } }));
vi.mock('@ant-design/icons', () => ({ PlusOutlined: 'PlusIcon', ReloadOutlined: 'ReloadIcon' }));
vi.mock('@tanstack/react-query', () => ({ useQueryClient: () => ({ invalidateQueries: frame.invalidate }),
  useQuery: (options: any) => options.queryKey[0] === 'target-health' ? { data: { data: frame.rows.map(row => ({ ...row, health: frame.healthState })) }, isError: frame.healthError, refetch: vi.fn() }
    : { data: { items: frame.rows, nextCursor: null }, isError: false, refetch: vi.fn() },
  useMutation(options: any) { const mutation = { ...options, mutateAsync: vi.fn(async (variables: any) => { const result = await options.mutationFn(variables); await options.onSuccess?.(result); return result; }) }; frame.mutations.push(mutation); return { isPending: false, mutateAsync: mutation.mutateAsync }; } }));
vi.mock('react-router-dom', () => ({ useNavigate: () => frame.navigate }));
vi.mock('../../apps/console-web/src/api/client', async original => ({ ...await original<typeof import('../../apps/console-web/src/api/client')>(), api: (...args: any[]) => frame.api(...args), getApiActorId: () => frame.actor }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => ({ clusterId: frame.cid, cluster: { id: frame.cid, execution_mode: frame.mode } }) }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => ({ workspaceId: frame.wid, ready: true, readonlyWorkspace: frame.readonly, writeBlocked: frame.writeBlocked, workspace: { status: 'active' } }) }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { id: frame.actor, permissionsVersion: frame.version, capabilities: { platformAdmin: frame.allowed, grants: [] } } }) }));
vi.mock('../../apps/console-web/src/app/EntityPermissions', () => ({ useEntityPermissions: () => ({ can: () => frame.allowed, query: { isError: false } }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_: unknown, options: any) => frame.dialogs.push(options) }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError', formatTime: (value: string) => value }));
vi.mock('../../apps/console-web/src/components/CursorPagination', () => ({ CursorPagination: 'CursorPagination', useCursorPages: () => ({}) }));
import { TargetManager } from '../../apps/console-web/src/features/TargetManager';
import { readTargetWorkflowAttempt, targetWorkflowStorageKey, type TargetWorkflowScope } from '../../apps/console-web/src/features/target-workflow.model';
const nodes = (tree: any): any[] => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : [];
const button = (tree: any, text: string) => nodes(tree).find(node => node.type === 'Button' && node.props.children === text);
const scope = (): TargetWorkflowScope => ({ actor: frame.actor, version: frame.version, cid: frame.cid, wid: frame.wid, mode: frame.mode as 'approval' | 'direct', upstreamId: frame.parent });
function render() { frame.area = 'parent'; frame.index = 0; frame.mutations = []; return TargetManager({ upstreamId: frame.parent, parentEntity: { id: frame.parent } }); }
function formNode(tree: any) { return nodes(tree).find(node => typeof node.props?.onFinish === 'function'); }
function rowAction(tree: any, name: string, row = frame.rows[0]) { const table = nodes(tree).find(node => node.type === 'Table'); return button(table.props.columns.at(-1).render(undefined, row), name); }
function drawerNode(tree: any) { return nodes(tree).find(node => typeof node.type === 'function' && node.type.name === 'TargetApprovalDrawer'); }
function renderDrawer(node: any) { frame.area = 'drawer'; frame.index = 0; return node.type(node.props); }
beforeEach(async () => {
  frame.area = 'parent'; frame.index = 0; frame.hooks = { parent: [], drawer: [] }; frame.effects = []; frame.dialogs = []; frame.mutations = [];
  frame.mode = 'approval'; frame.allowed = true; frame.readonly = false; frame.writeBlocked = false; frame.healthState = 'HEALTHY'; frame.healthError = false; frame.values.clear();
  frame.version = 'current-target-version'; frame.cid = 'df710589-3b87-4198-94ba-4abf818de2e1'; frame.rows = [{ id: frame.targetId, target: 'api.internal:8080', weight: 100, upstream: { id: frame.parent }, tags: ['workspace:pay', 'kos-ws-pay', 'owner:pay'] }];
  frame.form.resetFields.mockReset(); frame.form.setFieldsValue.mockReset(); frame.success.mockReset(); frame.navigate.mockReset(); frame.invalidate.mockReset();
  frame.receipt = { id: 'cdd7534c-f877-4418-8998-ab51735f31e2', revision: 1, materialHmac: 'a'.repeat(64), executionMode: 'approval',
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString(), nativeExecutionAvailable: false, capabilities: { submit: true }, workflowId: null,
    targetSubject: { upstreamId: frame.parent, action: 'create' }, review: { clusterId: frame.cid, workspaceId: frame.wid,
      changes: [{ entityType: 'targets', nativeId: '56732743-a9e1-4db9-b221-8599b37ba75e', action: 'create', before: null,
        after: { id: '56732743-a9e1-4db9-b221-8599b37ba75e', target: 'api.internal:8080', weight: 80, upstream: { id: frame.parent }, tags: [] } }],
      impact: { changedObjects: 1, nativePackets: 1, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: { state: 'baseline-required', blockerCodes: ['TARGET_RESTORE_APPENDS_HISTORY'] } } };
  frame.api.mockReset().mockImplementation(async (path: string) => {
    if (path === '/auth/me') return { user: { id: frame.actor, permissionsVersion: frame.version }, csrfToken: 'source-current-controlled-csrf' };
    if (path.includes('/entity-changes/prepare?')) return structuredClone(frame.receipt);
    if (path.includes('/entity-changes/' + frame.receipt.id + '/submit?')) { frame.receipt.workflowId = 'd9a81cb2-5f4e-4438-b586-0b9fb608f235'; return { workflowId: frame.receipt.workflowId, submissionCompleted: true, nativeExecutionAvailable: false }; }
    if (path.includes('/entity-changes/' + frame.receipt.id + '?')) return structuredClone(frame.receipt);
    if (path.includes('/targets')) return { entity: frame.rows[0] };
    throw new Error('UNEXPECTED_SOURCE_HTTP');
  });
  vi.stubGlobal('sessionStorage', { getItem: (key: string) => frame.values.get(key) ?? null, setItem: (key: string, value: string) => { frame.values.set(key, value); }, removeItem: (key: string) => { frame.values.delete(key); } });
  vi.stubGlobal('crypto', { randomUUID }); vi.stubGlobal('React', await import('react'));
});
afterEach(() => vi.unstubAllGlobals());
describe('Source-only actual TargetManager approval and Direct wiring', () => {
  it('enables authorized approval create and opens a fixed parent draft without Direct POST', () => { let tree = render(); expect(button(tree, '添加 Target').props.disabled).toBe(false); button(tree, '添加 Target').props.onClick(); tree = render();
    formNode(tree).props.onFinish({ target: frame.rows[0].target, weight: 80, tags: ['owner:pay'] });
    expect(drawerNode(render()).props.draft).toEqual({ action: 'create', body: { target: 'api.internal:8080', weight: 80, tags: ['owner:pay'] }, targetName: 'api.internal:8080' }); expect(frame.api).not.toHaveBeenCalled(); });
  it('prepares, re-reads, typed-confirms and submits one actual linked workflow without executing a native Target', async () => {
    let tree = render(); button(tree, '添加 Target').props.onClick(); formNode(render()).props.onFinish({ target: 'api.internal:8080', weight: 80, tags: [] }); const node = drawerNode(render());
    let drawer = renderDrawer(node); button(drawer, '生成审批预览').props.onClick(); await vi.waitFor(() => expect(readTargetWorkflowAttempt(scope())?.state).toBe('prepared'));
    drawer = renderDrawer(node); button(drawer, '提交审批').props.onClick(); expect(frame.dialogs[0].expected).toBe('api.internal:8080'); await frame.dialogs[0].onConfirm();
    drawer = renderDrawer(node); button(drawer, '查看变更工单').props.onClick(); expect(frame.navigate).toHaveBeenCalledWith(`/workflows/${frame.receipt.workflowId}?workspaceId=${frame.wid}`);
    const writes = frame.api.mock.calls.filter(call => call[1]?.method === 'POST'); expect(writes).toHaveLength(2); expect(writes.every(call => call[0].includes('/entity-changes/') && call[2] === true)).toBe(true); expect(readTargetWorkflowAttempt(scope())).toBeUndefined();
  });
  it('preserves business tags, fixes the original Target UUID and makes edited address readonly', () => { rowAction(render(), '编辑').props.onClick(); let tree = render(); expect(frame.form.setFieldsValue).toHaveBeenCalledWith({ target: 'api.internal:8080', weight: 100, tags: ['owner:pay'] });
    expect(nodes(tree).find(node => node.type === 'Input').props.disabled).toBe(true); expect(nodes(tree).find(node => node.type === 'InputNumber').props.max).toBe(1000);
    formNode(tree).props.onFinish({ target: 'api.internal:8080', weight: 80, tags: ['team:pay'] }); expect(drawerNode(render()).props.draft).toMatchObject({ action: 'weight', targetId: frame.targetId, body: { tags: ['team:pay'], weight: 80 } }); expect(frame.api).not.toHaveBeenCalled(); });
  it('requires typed confirmation before even preparing weight zero', async () => { rowAction(render(), '编辑').props.onClick(); formNode(render()).props.onFinish({ target: 'api.internal:8080', weight: 0, tags: [] });
    expect(drawerNode(render())).toBeUndefined(); expect(frame.dialogs[0].expected).toBe('api.internal:8080'); expect(frame.dialogs[0].danger).toBe(true); expect(frame.api).not.toHaveBeenCalled();
    await frame.dialogs[0].onConfirm(); expect(drawerNode(render()).props.draft.body.weight).toBe(0); });
  it.each(['健康', '不健康'] as const)('%s uses typed approval preparation and states current node, 204 and unavailable rollback', async name => { const tree = render(); expect(rowAction(tree, name).props.disabled).toBe(false); rowAction(tree, name).props.onClick();
    expect(frame.dialogs[0].description).toContain('当前 Admin API 节点'); expect(frame.dialogs[0].description).toContain('204 空响应'); expect(frame.dialogs[0].description).toContain('不可自动回滚'); expect(frame.dialogs[0].description).toContain('不支持定时执行');
    await frame.dialogs[0].onConfirm(); expect(drawerNode(render()).props.draft).toEqual({ action: 'health', targetId: frame.targetId, healthState: name === '健康' ? 'healthy' : 'unhealthy', targetName: 'api.internal:8080' }); expect(frame.api).not.toHaveBeenCalled(); });
  it('approval delete keeps recycle semantics and never issues Direct DELETE', async () => { rowAction(render(), '删除').props.onClick(); expect(frame.dialogs[0].expected).toBe('api.internal:8080'); await frame.dialogs[0].onConfirm(); expect(drawerNode(render()).props.draft).toEqual({ action: 'delete', targetId: frame.targetId, targetName: 'api.internal:8080' }); expect(frame.api).not.toHaveBeenCalled(); });
  it.each(['HEALTHCHECKS_OFF', 'DNS_ERROR', 'missing-health'])('closes %s health entry, including a forced disabled-button callback', async state => { frame.healthState = state; const tree = render(); expect(rowAction(tree, '健康').props.disabled).toBe(true); rowAction(tree, '健康').props.onClick(); expect(frame.dialogs).toHaveLength(0); expect(frame.api).not.toHaveBeenCalled(); });
  it('closes health entry on a failed current health query', () => { frame.healthError = true; const tree = render(); expect(rowAction(tree, '健康').props.disabled).toBe(true); rowAction(tree, '健康').props.onClick(); expect(frame.dialogs).toHaveLength(0); });
  it.each(['denied', 'readonly', 'unknown', 'damaged'])('blocks %s before opening a write or allocating a packet', reason => {
    if (reason === 'denied') frame.allowed = false; if (reason === 'readonly') frame.readonly = true;
    if (reason === 'unknown') sessionStorage.setItem(targetWorkflowStorageKey(scope()), JSON.stringify({ ...scope(), action: 'create', key: randomUUID(), stage: 'prepare', state: 'unknown' }));
    if (reason === 'damaged') sessionStorage.setItem(targetWorkflowStorageKey(scope()), '{damaged');
    const tree = render(); expect(button(tree, '添加 Target').props.disabled).toBe(true); expect(rowAction(tree, '编辑').props.disabled).toBe(true); expect(rowAction(tree, '删除').props.disabled).toBe(true); expect(frame.api).not.toHaveBeenCalled(); });
  it('does not replace a stale selected Target UUID with a new row at the same address', () => { rowAction(render(), '编辑').props.onClick(); const oldForm = formNode(render()); frame.rows = [{ ...frame.rows[0], id: randomUUID(), weight: 90 }]; render();
    oldForm.props.onFinish({ target: 'api.internal:8080', weight: 80, tags: [] }); expect(drawerNode(render())).toBeUndefined(); expect(frame.api).not.toHaveBeenCalled(); });
  it('retains Direct PATCH with tags and the selected old UUID, using a one-shot authenticated packet', async () => { frame.mode = 'direct'; rowAction(render(), '编辑').props.onClick(); formNode(render()).props.onFinish({ target: 'api.internal:8080', weight: 80, tags: ['team:pay'] });
    await vi.waitFor(() => expect(frame.api.mock.calls.some(call => call[1]?.method === 'PATCH')).toBe(true)); const write = frame.api.mock.calls.find(call => call[1]?.method === 'PATCH')!;
    expect(write[0]).toBe(`/clusters/${frame.cid}/upstreams/${frame.parent}/targets/${frame.targetId}?workspaceId=${frame.wid}`); expect(write[2]).toBe(true); expect(JSON.parse(write[1].body).tags).toEqual(['team:pay']); expect(drawerNode(render())).toBeUndefined(); });
  it.each(['健康', '删除'] as const)('preserves Direct %s endpoint with typed confirmation and no 401 replay', async name => { frame.mode = 'direct'; rowAction(render(), name).props.onClick(); await frame.dialogs[0].onConfirm(); const write = frame.api.mock.calls.find(call => ['POST', 'DELETE'].includes(call[1]?.method))!;
    expect(write[0]).toBe(`/clusters/${frame.cid}/upstreams/${frame.parent}/targets/${frame.targetId}${name === '健康' ? '/healthy' : ''}?workspaceId=${frame.wid}`); expect(write[2]).toBe(true); expect(write[1].method).toBe(name === '健康' ? 'POST' : 'DELETE'); });
  it('does not apply an old Direct success toast/form reset to a new scope', async () => { frame.mode = 'direct'; render(); const mutation = frame.mutations[0], originalScope = scope();
    frame.cid = randomUUID(); render(); const resets = frame.form.resetFields.mock.calls.length; await mutation.onSuccess(originalScope);
    expect(frame.form.resetFields).toHaveBeenCalledTimes(resets); expect(frame.success).not.toHaveBeenCalled(); const predicate = frame.invalidate.mock.calls[0][0].predicate; expect(predicate({ queryKey: [originalScope.cid] })).toBe(true); expect(predicate({ queryKey: [frame.cid] })).toBe(false); });
  it('blocks a stale edit after the current permission version changes', () => { rowAction(render(), '编辑').props.onClick(); const previousForm = formNode(render()); frame.version = 'new-permission-version'; render();
    previousForm.props.onFinish({ target: 'api.internal:8080', weight: 80, tags: [] }); expect(drawerNode(render())).toBeUndefined(); expect(frame.api).not.toHaveBeenCalled(); });
});
