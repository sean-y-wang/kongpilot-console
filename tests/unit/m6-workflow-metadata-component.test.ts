import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanup: [] as Array<() => void>, dialogs: [] as any[], scope: null as any, message: { success: vi.fn() } }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ modal: {}, message: frame.message }) } }));
vi.mock('../../apps/console-web/src/features/portal-hooks', () => ({ usePortalScope: () => frame.scope }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_modal: unknown, options: unknown) => { frame.dialogs.push(options); } }));

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40';
const key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22', workflowId = 'bc7bd065-9372-405d-9782-015d31a30aa1', executionId = '631dde84-fd98-47a0-aa35-45f458595231';
const ids = ['9303db34-99cb-4ce3-b6f2-67b74370e01e', 'fc5d7a72-dbec-43af-abcd-c65b0497641c', 'b4eaee06-9e7f-44fa-bfd4-cddc703c43dd', '27a847b3-e2e1-4e6b-8245-4e2f6cc99b08'];
const byKey = `/api/v1/clusters/${cid}/workflows/receipts/by-key/${key}?workspaceId=${wid}`;
const reconcile = `/api/v1/clusters/${cid}/workflows/${workflowId}/reconcile-metadata?workspaceId=${wid}`;
function receipt(succeeded = false) { return { id: executionId, executionId, workflowId, clusterId: cid, workspaceId: wid, idempotencyKey: key, state: succeeded ? 'succeeded' : 'uncertain', action: 'execute', revision: succeeded ? 6 : 5, planHash: 'a'.repeat(64), metadataRecovery: { eligible: !succeeded, kind: 'portal-credential-issue', executionId, originalExecutionKeyRequired: true }, steps: ['consumers.create.1', 'credentials.create.2', 'credentials.create.3', 'portal.credential.activate'].map((name, index) => ({ id: ids[index], name, state: index === 3 && !succeeded ? 'uncertain' : 'succeeded', operationId: index === 3 ? null : ids[index], remoteStarted: true, remoteCompleted: index !== 3 || succeeded })), propagation: succeeded ? 'acknowledged' : 'pending' }; }
const workflow: any = { id: workflowId, clusterId: cid, workspaceId: wid, name: 'portal-credential-issue', kind: 'portal-credential-issue', state: 'uncertain', revision: 5, planHash: 'a'.repeat(64), capabilities: { reconcileMetadata: true } };
const abandonmentWorkflow: any = { ...workflow, state: 'failed', capabilities: { abandonRejectedIssue: true } };
function abandonmentReceipt(completed = false) { return { ...receipt(), state: 'failed', revision: completed ? 6 : 5, metadataRecovery: undefined,
  issueAbandonment: { eligible: !completed, completed, reservationReleased: completed, kind: 'portal-credential-issue', executionId, grantId: ids[1], originalExecutionKeyRequired: true, ...(completed ? { certificateId: ids[2] } : {}) },
  steps: receipt().steps.map((step, index) => ({ ...step, state: index === 0 ? 'failed' : 'pending', operationId: index === 0 ? ids[0] : null, errorCode: index === 0 ? 'KONG_VALIDATION_ERROR' : null, remoteStarted: index === 0, remoteCompleted: false })) }; }
const json = (data: unknown) => new Response(JSON.stringify({ data }), { headers: { 'Content-Type': 'application/json' } });
function treeNodes(node: any): any[] { if (Array.isArray(node)) return node.flatMap(treeNodes); return !node || typeof node !== 'object' ? [] : [node, ...treeNodes(node.props?.children)]; }
const button = (tree: any, text: string) => treeNodes(tree).find(node => node.props?.children === text && typeof node.props?.onClick === 'function');
let client: typeof import('../../apps/console-web/src/api/client');
let render: () => any;
let renderAbandonment: (override?: Record<string, unknown>) => any;
let complete: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  // The first isolated React/Ant Design module transform can exceed 10s when
  // the entire suite runs concurrently. Only setup gets this cold-import
  // budget; request ordering, one-write and unknown-result assertions retain
  // their original timeouts and strict expectations.
  vi.resetModules(); frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanup = []; frame.dialogs = []; frame.message.success.mockReset();
  vi.stubGlobal('window', { dispatchEvent: vi.fn() }); vi.stubGlobal('React', await import('react'));
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: { detail: unknown }) { super(type); this.detail = options.detail; } });
  vi.stubGlobal('crypto', { randomUUID: vi.fn(() => { throw new Error('no replacement keys allowed'); }) });
  client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('unit-only-csrf');
  const reference = { actor_id: actor, cid, wid, kind: 'workflow', idempotencyKey: key, state: 'uncertain' };
  frame.scope = { cid, wid, actor, version: 'actor:9', permission: { has: () => true }, workspace: { readonlyWorkspace: false, references: [reference], resolveReference: vi.fn() } };
  const { WorkflowMetadataRecovery, WorkflowIssueAbandonment } = await import('../../apps/console-web/src/features/WorkflowsPage');
  complete = vi.fn().mockResolvedValue(undefined);
  const error = new client.ApiError('uncertain original execution', 503, 'WORKFLOW_STEP_UNCERTAIN', undefined, undefined, { kind: 'workflow', clusterId: cid, workspaceId: wid, idempotencyKey: key, state: 'uncertain' });
  render = () => { frame.index = 0; return WorkflowMetadataRecovery({ workflow, sourceError: error, onComplete: complete }); };
  renderAbandonment = (override = {}) => { frame.index = 0; return WorkflowIssueAbandonment({ workflow: { ...abandonmentWorkflow, ...override }, sourceError: error, onComplete: complete }); };
}, 30000);

async function verifiedAbandonment() {
  button(renderAbandonment(), '核验失败执行回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
  const tree = renderAbandonment(); expect(button(tree, '关闭明确失败申请').props.disabled).toBe(false); button(tree, '关闭明确失败申请').props.onClick();
  expect(frame.dialogs).toHaveLength(1); return frame.dialogs[0];
}

describe('actual known-rejected issue abandonment component', () => {
  const endpoint = `/api/v1/clusters/${cid}/workflows/${workflowId}/abandon-rejected-issue?workspaceId=${wid}`;
  it('requires explicit confirmation and one original-key closure POST followed by original certificate GET, preserving failed history', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(abandonmentReceipt())).mockResolvedValueOnce(json(abandonmentReceipt())).mockResolvedValueOnce(json(abandonmentReceipt(true))).mockResolvedValueOnce(json(abandonmentReceipt(true))); vi.stubGlobal('fetch', fetch);
    const dialog = await verifiedAbandonment(); expect(dialog.title).toBe('确认关闭明确失败的凭证申请'); expect(dialog.expected).toBe('portal-credential-issue');
    await dialog.onConfirm();
    expect(fetch.mock.calls.map(call => call[0])).toEqual([byKey, byKey, endpoint, byKey]); expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1);
    expect(new Headers(fetch.mock.calls[2][1].headers).get('X-Idempotency-Key')).toBe(key);
    expect(complete).toHaveBeenCalledTimes(1); expect(frame.scope.workspace.resolveReference).toHaveBeenCalledTimes(1);
    expect(window.dispatchEvent).toHaveBeenCalledWith(expect.objectContaining({ detail: expect.objectContaining({ completed: true, state: 'failed', idempotencyKey: key }) }));
    expect(abandonmentReceipt(true).steps.map(step => step.state)).toEqual(['failed', 'pending', 'pending', 'pending']); expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('only GET-verifies a completed certificate when server POST capability is no longer available, without another request', async () => {
    const fetch = vi.fn().mockResolvedValue(json(abandonmentReceipt(true))); vi.stubGlobal('fetch', fetch);
    const closed = renderAbandonment({ capabilities: { abandonRejectedIssue: false } }); expect(button(closed, '核验失败执行回执').props.disabled).toBe(false); button(closed, '核验失败执行回执').props.onClick();
    await vi.waitFor(() => expect(complete).toHaveBeenCalledTimes(1)); expect(fetch).toHaveBeenCalledTimes(1);
    expect(frame.dialogs).toHaveLength(0); expect(frame.scope.workspace.resolveReference).toHaveBeenCalledTimes(1);
    expect(treeNodes(renderAbandonment({ capabilities: { abandonRejectedIssue: false } })).some(node => node.props?.message === '预留关闭证书已核验')).toBe(true);
  });
  it('a native unknown/progress result cannot open closure confirmation or release the original reference', async () => {
    const invalid = abandonmentReceipt(); invalid.steps[0].errorCode = 'WRITE_RESULT_UNKNOWN';
    const fetch = vi.fn().mockResolvedValue(json(invalid)); vi.stubGlobal('fetch', fetch);
    button(renderAbandonment(), '核验失败执行回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
    expect(button(renderAbandonment(), '关闭明确失败申请').props.disabled).toBe(true); expect(frame.dialogs).toHaveLength(0);
    expect(fetch).toHaveBeenCalledTimes(1); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it('does not POST if the fresh actor-bound receipt changes the grant identity after typed confirmation opened', async () => {
    const foreign = abandonmentReceipt(); foreign.issueAbandonment.grantId = ids[3];
    const fetch = vi.fn().mockResolvedValueOnce(json(abandonmentReceipt())).mockResolvedValueOnce(json(foreign)); vi.stubGlobal('fetch', fetch);
    const dialog = await verifiedAbandonment(); await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'PORTAL_ABANDONMENT_REQUEST_MISMATCH' });
    expect(fetch.mock.calls.map(call => call[0])).toEqual([byKey, byKey]); expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it.each(['actor', 'workspace', 'permission-epoch', 'unmount'])('refuses stale closure confirmation after %s changes with zero additional requests', async variant => {
    const fetch = vi.fn().mockResolvedValue(json(abandonmentReceipt())); vi.stubGlobal('fetch', fetch); const dialog = await verifiedAbandonment();
    if (variant === 'actor') client.setApiActorId(ids[0]);
    if (variant === 'workspace') { frame.scope = { ...frame.scope, wid: ids[0] }; renderAbandonment(); }
    if (variant === 'permission-epoch') { frame.scope = { ...frame.scope, version: 'actor:10' }; renderAbandonment(); }
    if (variant === 'unmount') for (const cleanup of frame.cleanup) cleanup();
    await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'SESSION_CHANGED' }); expect(fetch).toHaveBeenCalledTimes(1); expect(complete).not.toHaveBeenCalled();
  });
  it('locks inputs during closure, preserves unknown original key, and uses only GET for its later certificate proof', async () => {
    let rejectPost!: (error: Error) => void;
    const fetch = vi.fn().mockResolvedValueOnce(json(abandonmentReceipt())).mockResolvedValueOnce(json(abandonmentReceipt())).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectPost = reject; })); vi.stubGlobal('fetch', fetch);
    const dialog = await verifiedAbandonment(), pending = dialog.onConfirm(); await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
    const busy = renderAbandonment(); expect(button(busy, '核验失败执行回执').props.disabled).toBe(true); expect(treeNodes(busy).find(node => node.props?.['aria-label'] === '原失败执行幂等键').props.disabled).toBe(true);
    rejectPost(new Error('response interrupted')); await expect(pending).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', idempotencyKey: key, clusterId: cid, workspaceId: wid } });
    expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled(); expect(button(renderAbandonment(), '关闭明确失败申请').props.disabled).toBe(true);
    fetch.mockResolvedValueOnce(json(abandonmentReceipt(true))); button(renderAbandonment({ capabilities: { abandonRejectedIssue: false } }), '核验失败执行回执').props.onClick();
    await vi.waitFor(() => expect(complete).toHaveBeenCalledTimes(1)); expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1); expect(fetch.mock.calls[3][0]).toBe(byKey);
  });
});
afterEach(() => { for (const cleanup of frame.cleanup) cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function verified() {
  button(render(), '核验原执行回执').props.onClick();
  await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
  const tree = render(); expect(button(tree, '只提交门户元数据').props.disabled).toBe(false); button(tree, '只提交门户元数据').props.onClick();
  expect(frame.dialogs).toHaveLength(1); return frame.dialogs[0];
}

describe('actual WorkflowsPage recovery component controlled hook/transport regression', () => {
  it('GET-verifies, confirms, sends exactly one metadata POST with the original key, then proves the original receipt before unlocking', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json({ ...receipt(true), idempotencyKey: ids[0], action: 'submit' })).mockResolvedValueOnce(json(receipt(true))); vi.stubGlobal('fetch', fetch);
    const dialog = await verified(); expect(dialog.title).toBe('只提交已创建凭证的门户元数据'); expect(dialog.expected).toBe('portal-credential-issue');
    await dialog.onConfirm();
    expect(fetch.mock.calls.map(call => call[0])).toEqual([byKey, byKey, reconcile, byKey]);
    expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1);
    expect(new Headers(fetch.mock.calls[2][1].headers).get('X-Idempotency-Key')).toBe(key);
    expect(complete).toHaveBeenCalledTimes(1); expect(frame.scope.workspace.resolveReference).toHaveBeenCalledTimes(1);
    expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('does not offer a confirm dialog or POST when even one native step lacks ACK', async () => {
    const invalid = receipt(); invalid.steps[2].remoteCompleted = false;
    const fetch = vi.fn().mockResolvedValue(json(invalid)); vi.stubGlobal('fetch', fetch);
    button(render(), '核验原执行回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[3]).toBe(false));
    expect(button(render(), '只提交门户元数据').props.disabled).toBe(true); expect(frame.dialogs).toHaveLength(0); expect(fetch).toHaveBeenCalledTimes(1);
    expect(complete).not.toHaveBeenCalled();
  });
  it.each(['actor', 'workspace', 'permission-epoch', 'unmount'])('rejects an already-open confirmation after %s changes, without another request', async variant => {
    const fetch = vi.fn().mockResolvedValue(json(receipt())); vi.stubGlobal('fetch', fetch); const dialog = await verified();
    if (variant === 'actor') client.setApiActorId(ids[0]);
    if (variant === 'workspace') { frame.scope = { ...frame.scope, wid: ids[0] }; render(); }
    if (variant === 'permission-epoch') { frame.scope = { ...frame.scope, version: 'actor:10' }; render(); }
    if (variant === 'unmount') for (const cleanup of frame.cleanup) cleanup();
    await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'SESSION_CHANGED' });
    expect(fetch).toHaveBeenCalledTimes(1); expect(complete).not.toHaveBeenCalled();
  });
  it('locks original-key/read controls during the explicit recovery and leaves lost responses at original-key verification with no second POST', async () => {
    let rejectPost!: (error: Error) => void;
    const fetch = vi.fn().mockResolvedValueOnce(json(receipt())).mockResolvedValueOnce(json(receipt())).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectPost = reject; })); vi.stubGlobal('fetch', fetch);
    const dialog = await verified(), pending = dialog.onConfirm();
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
    const busy = render(); expect(button(busy, '核验原执行回执').props.disabled).toBe(true);
    expect(treeNodes(busy).find(node => node.props?.['aria-label'] === '原执行幂等键').props.disabled).toBe(true);
    rejectPost(new Error('response interrupted')); await expect(pending).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', idempotencyKey: key, clusterId: cid, workspaceId: wid } });
    expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1); expect(button(render(), '只提交门户元数据').props.disabled).toBe(true);
    expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
});
