import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const frame = vi.hoisted(() => ({ area: 'parent', index: 0, hooks: { parent: [] as any[], drawer: [] as any[] }, effects: [] as any[], mutations: [] as any[], dialogs: [] as any[],
  actor: 'b0d46823-d29f-45c3-a744-5d332b066555', cid: 'cd69757e-8f3e-4b7a-a671-3bb113d365d6', wid: 'ef4d7bda-a50c-4e97-bf58-a10c7fedc132', entityId: '6b09d997-d36b-47d8-9ded-4bc2b28546e4',
  version: 'current-annotation-version', mode: 'approval', allowed: true, readonly: false, writeBlocked: false, api: vi.fn(), success: vi.fn(), invalidate: vi.fn(), navigate: vi.fn(),
  values: new Map<string, string>(), row: {} as any, receipt: {} as any,
  form: { resetFields: vi.fn(), setFieldsValue: vi.fn(), submit: vi.fn(), setFieldValue: vi.fn() } }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState(initial: any) { const hooks = frame.hooks[frame.area as 'parent' | 'drawer'], n = frame.index++; if (!(n in hooks)) hooks[n] = typeof initial === 'function' ? initial() : initial;
    return [hooks[n], (value: any) => { hooks[n] = typeof value === 'function' ? value(hooks[n]) : value; }]; },
  useRef(initial: any) { const hooks = frame.hooks[frame.area as 'parent' | 'drawer'], n = frame.index++; return hooks[n] ?? (hooks[n] = { current: initial }); },
  useMemo(fn: any, deps: any[]) { const hooks = frame.hooks[frame.area as 'parent' | 'drawer'], n = frame.index++, previous = hooks[n];
    if (!previous || !deps || deps.some((value: any, i: number) => value !== previous.deps[i])) hooks[n] = { deps, value: fn() }; return hooks[n].value; },
  useEffect(fn: any) { frame.effects.push(fn); },
}));
vi.mock('antd', () => ({ Alert: 'Alert', Button: 'Button', Card: 'Card', Descriptions: 'Descriptions', Drawer: 'Drawer', Input: Object.assign('Input', { TextArea: 'TextArea' }), Modal: 'Modal', Space: 'Space', Tag: 'Tag',
  Typography: { Text: 'TypographyText', Paragraph: 'TypographyParagraph', Title: 'TypographyTitle' },
  Form: Object.assign(() => null, { Item: 'FormItem', useForm: () => [frame.form] }), App: { useApp: () => ({ message: { success: frame.success }, modal: {} }) } }));
vi.mock('@tanstack/react-query', () => ({ useQueryClient: () => ({ invalidateQueries: frame.invalidate }),
  useQuery: () => ({ data: frame.row, refetch: vi.fn(), isError: false }),
  useMutation(options: any) { const mutate = vi.fn(); frame.mutations.push({ ...options, mutate }); return { isPending: false, mutate }; } }));
vi.mock('react-router-dom', () => ({ useNavigate: () => frame.navigate }));
vi.mock('../../apps/console-web/src/api/client', async original => ({ ...await original<typeof import('../../apps/console-web/src/api/client')>(),
  api: (...args: any[]) => frame.api(...args), getApiActorId: () => frame.actor }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => ({ clusterId: frame.cid, cluster: { execution_mode: frame.mode } }) }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => ({ workspaceId: frame.wid, ready: true, readonlyWorkspace: frame.readonly, writeBlocked: frame.writeBlocked, workspace: { status: 'active' } }) }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { id: frame.actor, username: 'source-actor', permissionsVersion: frame.version, capabilities: { platformAdmin: frame.allowed, grants: [] } } }) }));
vi.mock('../../apps/console-web/src/app/Permissions', () => ({ usePermissions: () => ({ can: () => frame.allowed }) }));
vi.mock('../../apps/console-web/src/app/EntityPermissions', () => ({ useEntityPermissions: () => ({ can: () => frame.allowed }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_: unknown, options: any) => frame.dialogs.push(options) }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError', formatTime: (value: string) => value }));
vi.mock('../../apps/console-web/src/features/IAMLookups', () => ({ PagedIAMLookup: 'PagedIAMLookup' }));
import { EntityAnnotations } from '../../apps/console-web/src/features/EntityAnnotations';
import { annotationWorkflowStorageKey, readAnnotationWorkflowAttempt, type AnnotationWorkflowScope } from '../../apps/console-web/src/features/entity-annotation-workflow.model';

const nodes = (tree: any): any[] => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object'
  ? [tree, ...nodes(tree.props?.children), ...nodes(tree.props?.extra)] : [];
const button = (tree: any, text: string) => nodes(tree).find(node => node.type === 'Button' && node.props.children === text);
const entity = () => ({ id: frame.entityId, name: 'payments', tags: ['workspace:payments', 'owner:pay'] });
const scope = (): AnnotationWorkflowScope => ({ actor: frame.actor, version: frame.version, cid: frame.cid, wid: frame.wid, mode: frame.mode as 'approval' | 'direct', entityType: 'services', entityId: frame.entityId });
function render() { frame.area = 'parent'; frame.index = 0; frame.mutations = []; return EntityAnnotations({ type: 'services', entity: entity() }); }
function editForm(tree: any) { return nodes(tree).find(node => typeof node.props?.onFinish === 'function'); }
function drawerNode(tree: any) { return nodes(tree).find(node => typeof node.type === 'function' && node.type.name === 'AnnotationApprovalDrawer'); }
function renderDrawer(node: any) { frame.area = 'drawer'; frame.index = 0; return node.type(node.props); }
beforeEach(async () => {
  frame.area = 'parent'; frame.index = 0; frame.hooks = { parent: [], drawer: [] }; frame.effects = []; frame.mutations = []; frame.dialogs = [];
  frame.version = 'current-annotation-version'; frame.mode = 'approval'; frame.allowed = true; frame.readonly = false; frame.writeBlocked = false; frame.values.clear();
  frame.row = { cluster_id: frame.cid, entity_type: 'services', kong_id: frame.entityId, description: 'original note', owner_user_id: null,
    metadata: { team: 'pay', api_key: '[REDACTED]' }, revision: 3, status: 'active' };
  frame.receipt = { intentId: 'a7d13665-be4e-4438-8424-007e763646fe', clusterId: frame.cid, workspaceId: frame.wid, entityType: 'services', entityId: frame.entityId,
    operation: 'set', state: 'prepared', revision: null, annotationRevision: 3, materialHmac: 'a'.repeat(64), workflowId: null, planHash: null,
    expiresAt: new Date(Date.now() + 3600000).toISOString(), nativeRequestsSent: 0, nativeExecutionAvailable: false, capabilities: { submit: true },
    preview: { before: structuredClone(frame.row), after: { entityType: 'services', entityId: frame.entityId, operation: 'set', input: { revision: 3, description: 'new note', owner_user_id: null } }, confirmationName: 'payments', retentionDays: null } };
  frame.api.mockReset().mockImplementation(async (path: string, options: RequestInit = {}) => {
    if (path === '/auth/me') return { user: { id: frame.actor, permissionsVersion: frame.version }, csrfToken: 'source-controlled-current-csrf' };
    if (path.includes('/annotation-changes/prepare?')) return structuredClone(frame.receipt);
    if (path.includes('/annotation-changes/' + frame.receipt.intentId + '/submit?')) { Object.assign(frame.receipt, { state: 'pending', revision: 1,
      workflowId: 'c891822b-4b9c-41a6-bf0b-adfb50972914', planHash: 'b'.repeat(64), capabilities: { submit: false } }); return structuredClone(frame.receipt); }
    if (path.includes('/annotation-changes/' + frame.receipt.intentId + '?')) return structuredClone(frame.receipt);
    if (path.includes('/entity-annotations/') && ['PUT', 'DELETE', 'POST'].includes(options.method ?? 'GET')) return frame.row;
    throw new Error('UNEXPECTED_SOURCE_HTTP');
  });
  vi.stubGlobal('sessionStorage', { getItem: (key: string) => frame.values.get(key) ?? null, setItem: (key: string, value: string) => { frame.values.set(key, value); }, removeItem: (key: string) => { frame.values.delete(key); } });
  vi.stubGlobal('React', await import('react')); vi.stubGlobal('crypto', { randomUUID: () => '93b8908f-9817-4337-82ef-0dfc3be6b4cb' });
});
afterEach(() => vi.unstubAllGlobals());

describe('Source-only actual entity annotation component approval wiring', () => {
  it('enables an authorized approval edit and carries the exact original CAS while preserving omitted masked metadata', () => {
    let tree = render(); expect(button(tree, '编辑说明').props.disabled).toBe(false); button(tree, '编辑说明').props.onClick(); tree = render();
    editForm(tree).props.onFinish({ description: 'new note', owner_user_id: '', metadata: JSON.stringify(frame.row.metadata, null, 2) });
    tree = render(); const drawer = drawerNode(tree); expect(drawer.props.draft).toEqual({ operation: 'set', annotationRevision: 3,
      input: { revision: 3, description: 'new note', owner_user_id: null }, confirmationName: 'payments' });
    expect(frame.mutations[0].mutate).not.toHaveBeenCalled(); expect(frame.api).not.toHaveBeenCalled();
  });
  it('sends exactly one explicit prepare and typed confirmed submit, then offers only the linked workflow', async () => {
    let tree = render(); button(tree, '编辑说明').props.onClick(); tree = render();
    editForm(tree).props.onFinish({ description: 'new note', owner_user_id: '', metadata: JSON.stringify(frame.row.metadata, null, 2) });
    const node = drawerNode(render()); let drawer = renderDrawer(node); button(drawer, '生成审批预览').props.onClick();
    await vi.waitFor(() => expect(readAnnotationWorkflowAttempt(scope())?.state).toBe('prepared'));
    drawer = renderDrawer(node); expect(button(drawer, '提交审批').props.disabled).toBe(false); button(drawer, '提交审批').props.onClick();
    expect(frame.dialogs).toHaveLength(1); expect(frame.dialogs[0].expected).toBe('payments');
    expect(frame.api.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1);
    await frame.dialogs[0].onConfirm(); drawer = renderDrawer(node); button(drawer, '查看变更工单').props.onClick();
    expect(frame.navigate).toHaveBeenCalledWith(`/workflows/${frame.receipt.workflowId}?workspaceId=${frame.wid}`);
    expect(frame.api.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(2);
    expect(frame.api.mock.calls.filter(call => call[1]?.method === 'POST').every(call => call[2] === true)).toBe(true);
    expect(frame.api.mock.calls.every(call => !['PUT', 'DELETE'].includes(call[1]?.method ?? 'GET'))).toBe(true); expect(readAnnotationWorkflowAttempt(scope())).toBeUndefined();
  });
  it.each(['delete', 'restore'] as const)('keeps typed %s confirmation and prepares a metadata workflow instead of Direct mutation', async action => {
    if (action === 'restore') frame.row.status = 'deleted';
    const tree = render(); button(tree, action === 'delete' ? '删除说明' : '恢复说明').props.onClick();
    expect(frame.dialogs[0].expected).toBe('payments'); expect(frame.api).not.toHaveBeenCalled();
    await frame.dialogs[0].onConfirm(); const drawer = drawerNode(render());
    expect(drawer.props.draft).toEqual({ operation: action === 'delete' ? 'remove' : 'restore', annotationRevision: 3,
      input: { revision: 3, confirmed: true, confirm_name: 'payments' }, confirmationName: 'payments' });
    expect(frame.api).not.toHaveBeenCalled();
  });
  it('preserves Direct edit endpoint, revision, current session check and one-shot write', async () => {
    frame.mode = 'direct'; let tree = render(); button(tree, '编辑说明').props.onClick(); tree = render();
    editForm(tree).props.onFinish({ description: 'direct note', owner_user_id: '', metadata: JSON.stringify(frame.row.metadata, null, 2) });
    const mutation = frame.mutations[0], params = mutation.mutate.mock.calls[0][0]; await mutation.mutationFn(params);
    expect(frame.api).toHaveBeenCalledWith('/auth/me', {}, true);
    const write = frame.api.mock.calls.find(call => call[1]?.method === 'PUT')!;
    expect(write[0]).toBe(`/clusters/${frame.cid}/entity-annotations/services/${frame.entityId}?workspaceId=${frame.wid}`);
    expect(write[2]).toBe(true); expect(JSON.parse(write[1].body)).toEqual({ revision: 3, description: 'direct note', owner_user_id: null });
    expect(drawerNode(render())).toBeUndefined();
  });
  it.each(['delete', 'restore'] as const)('preserves original Direct %s soft lifecycle endpoint and typed confirmation', async action => {
    frame.mode = 'direct'; if (action === 'restore') frame.row.status = 'deleted';
    button(render(), action === 'delete' ? '删除说明' : '恢复说明').props.onClick(); await frame.dialogs[0].onConfirm();
    const write = frame.api.mock.calls.find(call => ['POST', 'DELETE'].includes(call[1]?.method))!;
    expect(write[0]).toBe(`/clusters/${frame.cid}/entity-annotations/services/${frame.entityId}${action === 'restore' ? '/restore' : ''}?workspaceId=${frame.wid}`);
    expect(write[1].method).toBe(action === 'restore' ? 'POST' : 'DELETE'); expect(write[2]).toBe(true);
    expect(JSON.parse(write[1].body)).toEqual({ revision: 3, confirmed: true, confirm_name: 'payments' });
  });
  it.each(['denied', 'readonly', 'unknown', 'damaged'])('blocks %s writes on the initial render before another request', reason => {
    if (reason === 'denied') frame.allowed = false;
    if (reason === 'readonly') frame.readonly = true;
    if (reason === 'unknown') sessionStorage.setItem(annotationWorkflowStorageKey(scope()), JSON.stringify({ ...scope(), operation: 'set', annotationRevision: 3,
      stage: 'prepare', state: 'unknown', key: '93b8908f-9817-4337-82ef-0dfc3be6b4cb' }));
    if (reason === 'damaged') sessionStorage.setItem(annotationWorkflowStorageKey(scope()), '{damaged');
    const tree = render(); expect(button(tree, '编辑说明').props.disabled).toBe(true); expect(button(tree, '删除说明').props.disabled).toBe(true); expect(frame.api).not.toHaveBeenCalled();
  });
  it('does not use a stale open form after current permission version changes', () => {
    let tree = render(); button(tree, '编辑说明').props.onClick(); const original = editForm(render());
    frame.version = 'new-current-permission-version'; render();
    original.props.onFinish({ description: 'stale note', owner_user_id: '', metadata: '{}' });
    expect(drawerNode(render())).toBeUndefined(); expect(frame.api).not.toHaveBeenCalled(); expect(frame.mutations[0].mutate).not.toHaveBeenCalled();
  });
});
