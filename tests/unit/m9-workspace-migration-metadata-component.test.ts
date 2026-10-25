import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanup: [] as Array<() => void>, dialogs: [] as any[], scope: null as any, detail: null as any, message: { success: vi.fn() } }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ modal: {}, message: frame.message }) } }));
vi.mock('@tanstack/react-query', async original => ({ ...await original<typeof import('@tanstack/react-query')>(), useQuery: () => ({ data: frame.detail, refetch: vi.fn(), error: undefined }) }));
vi.mock('react-router-dom', async original => ({ ...await original<typeof import('react-router-dom')>(), useParams: () => ({ id: 'bc7bd065-9372-405d-9782-015d31a30aa1' }), useSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock('../../apps/console-web/src/features/portal-hooks', () => ({ usePortalScope: () => frame.scope, usePortalPage: vi.fn() }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { id: frame.scope?.actor, capabilities: { platformAdmin: false, grants: [] } } }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_modal: unknown, options: unknown) => { frame.dialogs.push(options); } }));

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40';
const key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22', workflowId = 'bc7bd065-9372-405d-9782-015d31a30aa1', executionId = '631dde84-fd98-47a0-aa35-45f458595231';
const stepId = '9303db34-99cb-4ce3-b6f2-67b74370e01e', operationId = 'fc5d7a72-dbec-43af-abcd-c65b0497641c', foreignId = 'b4eaee06-9e7f-44fa-bfd4-cddc703c43dd';
const hash = 'a'.repeat(64), byKey = `/api/v1/clusters/${cid}/workflows/receipts/by-key/${key}?workspaceId=${wid}`, reconcile = `/api/v1/clusters/${cid}/workflows/${workflowId}/reconcile-metadata?workspaceId=${wid}`;
const workflow: any = { id: workflowId, clusterId: cid, workspaceId: wid, name: 'workspace-migration', kind: 'workspace-migration', state: 'uncertain', revision: 5, planHash: hash, capabilities: { reconcileMetadata: true } };
function receipt(succeeded = false): any { return { id: executionId, executionId, workflowId, clusterId: cid, workspaceId: wid, idempotencyKey: key, state: succeeded ? 'succeeded' : 'uncertain', action: 'execute', revision: succeeded ? 6 : 5, planHash: hash, metadataRecovery: { eligible: !succeeded, kind: 'workspace-migration', knownNativeComplete: true, executionId, originalExecutionKeyRequired: true, ...(succeeded ? { completed: true } : {}) }, steps: [{ id: stepId, name: 'workspace-migration', state: 'succeeded', operationId, remoteStarted: true, remoteCompleted: true }], propagation: succeeded ? 'acknowledged' : 'pending' }; }
const json = (data: unknown) => new Response(JSON.stringify({ data }), { headers: { 'Content-Type': 'application/json' } });
function treeNodes(node: any): any[] { if (Array.isArray(node)) return node.flatMap(treeNodes); return !node || typeof node !== 'object' ? [] : [node, ...treeNodes(node.props?.children)]; }
const button = (tree: any, text: string) => treeNodes(tree).find(node => node.props?.children === text && typeof node.props?.onClick === 'function');
let client: typeof import('../../apps/console-web/src/api/client');
let pages: typeof import('../../apps/console-web/src/features/WorkflowsPage');
let render: (override?: Record<string, unknown>) => any;
let complete: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  vi.resetModules(); frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanup = []; frame.dialogs = []; frame.message.success.mockReset(); frame.detail = undefined;
  vi.stubGlobal('window', { dispatchEvent: vi.fn() }); vi.stubGlobal('React', await import('react'));
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: { detail: unknown }) { super(type); this.detail = options.detail; } });
  vi.stubGlobal('crypto', { randomUUID: vi.fn(() => { throw new Error('no replacement execution keys allowed'); }) });
  client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('unit-only-csrf');
  const reference = { actor_id: actor, cid, wid, kind: 'workflow', idempotencyKey: key, state: 'uncertain' };
  frame.scope = { cid, wid, actor, version: 'actor:9', ready: true, path: (path: string) => `/clusters/${cid}/${path}?workspaceId=${wid}`, permission: { has: () => true }, workspace: { writeBlocked: true, readonlyWorkspace: false, references: [reference], resolveReference: vi.fn() } };
  pages = await import('../../apps/console-web/src/features/WorkflowsPage'); complete = vi.fn().mockResolvedValue(undefined);
  const error = new client.ApiError('uncertain original execution', 503, 'WORKFLOW_STEP_UNCERTAIN', undefined, undefined, { kind: 'workflow', clusterId: cid, workspaceId: wid, idempotencyKey: key, state: 'uncertain' });
  render = (override = {}) => { frame.index = 0; return pages.WorkflowMetadataRecovery({ workflow: { ...workflow, ...override }, sourceError: error, onComplete: complete }); };
}, 30000);
afterEach(() => { for (const cleanup of frame.cleanup) cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function verified() {
  button(render(), '核验原执行回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
  const tree = render(); expect(button(tree, '只对账迁移元数据').props.disabled).toBe(false); button(tree, '只对账迁移元数据').props.onClick();
  expect(frame.dialogs).toHaveLength(1); return frame.dialogs[0];
}

describe('actual workspace-migration metadata recovery component with controlled hooks/transport', () => {
  it('renders migration-specific recovery in uncertain and partial workflow details, while portal keeps its own four-step recovery', () => {
    for (const state of ['uncertain', 'partial']) {
      frame.detail = { ...workflow, state }; frame.index = 0;
      expect(treeNodes(pages.WorkflowDetailPage()).some(node => node.type === pages.WorkflowMetadataRecovery && node.props.workflow.kind === 'workspace-migration')).toBe(true);
    }
    frame.detail = { ...workflow, kind: 'portal-credential-issue', name: 'portal-credential-issue', state: 'partial' }; frame.index = 0;
    expect(treeNodes(pages.WorkflowDetailPage()).some(node => node.type === pages.WorkflowMetadataRecovery)).toBe(false);
  });
  it('GET-verifies, requires typed migration confirmation, sends one fixed original-key metadata POST then GET-proves completion', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json({ ...receipt(true), idempotencyKey: foreignId, action: 'submit' })).mockResolvedValueOnce(json(receipt(true))); vi.stubGlobal('fetch', fetch);
    const dialog = await verified(); expect(dialog.title).toBe('确认对账已完成的工作区迁移'); expect(dialog.expected).toBe('workspace-migration');
    await dialog.onConfirm();
    expect(fetch.mock.calls.map(call => call[0])).toEqual([byKey, byKey, reconcile, byKey]); expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1);
    expect(JSON.parse(fetch.mock.calls[2][1].body)).toEqual({ revision: 5, planHash: hash, executionId, confirmed: true, confirm_name: 'workspace-migration' });
    expect(new Headers(fetch.mock.calls[2][1].headers).get('X-Idempotency-Key')).toBe(key); expect(crypto.randomUUID).not.toHaveBeenCalled();
    expect(complete).toHaveBeenCalledTimes(1); expect(frame.scope.workspace.resolveReference).toHaveBeenCalledTimes(1);
    expect(window.dispatchEvent).toHaveBeenCalledWith(expect.objectContaining({ detail: expect.objectContaining({ completed: true, state: 'succeeded', idempotencyKey: key }) }));
  });
  it.each(['native-unknown', 'missing-operation', 'foreign-kind', 'extra-step'])('cannot open confirmation from %s proof', async variant => {
    const invalid = receipt();
    if (variant === 'native-unknown') invalid.steps[0].remoteCompleted = false;
    if (variant === 'missing-operation') invalid.steps[0].operationId = null;
    if (variant === 'foreign-kind') invalid.metadataRecovery.kind = 'portal-credential-issue';
    if (variant === 'extra-step') invalid.steps.push({ ...invalid.steps[0], id: foreignId });
    const fetch = vi.fn().mockResolvedValue(json(invalid)); vi.stubGlobal('fetch', fetch);
    button(render(), '核验原执行回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
    expect(button(render(), '只对账迁移元数据').props.disabled).toBe(true); expect(frame.dialogs).toHaveLength(0);
    expect(fetch).toHaveBeenCalledTimes(1); expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it.each(['actor', 'cluster', 'workspace', 'permission-epoch', 'original-key', 'plan-revision', 'plan-hash', 'workflow-kind', 'unmount'])('denies an open confirmation after %s changes without additional requests', async variant => {
    const fetch = vi.fn().mockResolvedValue(json(receipt())); vi.stubGlobal('fetch', fetch); const dialog = await verified();
    if (variant === 'actor') client.setApiActorId(foreignId);
    if (variant === 'cluster') { frame.scope = { ...frame.scope, cid: foreignId }; render(); }
    if (variant === 'workspace') { frame.scope = { ...frame.scope, wid: foreignId }; render(); }
    if (variant === 'permission-epoch') { frame.scope = { ...frame.scope, version: 'actor:10' }; render(); }
    if (variant === 'original-key') { treeNodes(render()).find(node => node.props?.['aria-label'] === '原执行幂等键').props.onChange({ target: { value: foreignId } }); render(); }
    if (variant === 'plan-revision') render({ revision: 6 });
    if (variant === 'plan-hash') render({ planHash: 'b'.repeat(64) });
    if (variant === 'workflow-kind') render({ kind: 'portal-credential-issue', name: 'portal-credential-issue' });
    if (variant === 'unmount') for (const cleanup of frame.cleanup) cleanup();
    await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'SESSION_CHANGED' }); expect(fetch).toHaveBeenCalledTimes(1);
    expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it('rejects a fresh receipt bound to another execution after the confirmation opens, without POST', async () => {
    const wrong = receipt(); wrong.executionId = wrong.id = wrong.metadataRecovery.executionId = foreignId;
    const fetch = vi.fn().mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(wrong)); vi.stubGlobal('fetch', fetch);
    const dialog = await verified(); await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'MIGRATION_RECOVERY_REQUEST_MISMATCH' });
    expect(fetch.mock.calls.map(call => call[0])).toEqual([byKey, byKey]); expect(complete).not.toHaveBeenCalled();
  });
  it('never releases an uncertain reference from a completed receipt whose original plan hash changed', async () => {
    const wrong = receipt(true); wrong.planHash = 'b'.repeat(64);
    const fetch = vi.fn().mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(receipt(true))).mockResolvedValueOnce(json(wrong)); vi.stubGlobal('fetch', fetch);
    const dialog = await verified(); await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { idempotencyKey: key, workspaceId: wid } });
    expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1); expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it('locks inputs during a lost metadata POST and later uses only original-key GET to prove completion even after write capability is gone', async () => {
    let rejectPost!: (error: Error) => void;
    const fetch = vi.fn().mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(receipt())).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectPost = reject; })); vi.stubGlobal('fetch', fetch);
    const dialog = await verified(), pending = dialog.onConfirm(); await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
    const busy = render(); expect(button(busy, '核验原执行回执').props.disabled).toBe(true); expect(treeNodes(busy).find(node => node.props?.['aria-label'] === '原执行幂等键').props.disabled).toBe(true);
    rejectPost(new Error('response interrupted')); await expect(pending).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', idempotencyKey: key, clusterId: cid, workspaceId: wid } });
    expect(button(render(), '只对账迁移元数据').props.disabled).toBe(true); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
    fetch.mockResolvedValueOnce(json(receipt(true))); const readOnly = render({ capabilities: { reconcileMetadata: false } });
    expect(button(readOnly, '核验原执行回执').props.disabled).toBe(false); button(readOnly, '核验原执行回执').props.onClick();
    await vi.waitFor(() => expect(complete).toHaveBeenCalledTimes(1)); expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1);
    expect(fetch.mock.calls[3][0]).toBe(byKey); expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('keeps writes blocked if another original uncertain operation remains in the same scope', async () => {
    frame.scope.workspace.references.push({ actor_id: actor, cid, wid, kind: 'workflow', idempotencyKey: foreignId, state: 'uncertain' });
    const fetch = vi.fn().mockResolvedValue(json(receipt())); vi.stubGlobal('fetch', fetch);
    button(render(), '核验原执行回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
    expect(button(render(), '只对账迁移元数据').props.disabled).toBe(true); expect(frame.dialogs).toHaveLength(0); expect(fetch).toHaveBeenCalledTimes(1);
  });
});
