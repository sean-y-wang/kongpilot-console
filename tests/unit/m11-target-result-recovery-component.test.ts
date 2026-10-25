import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { targetRecoveryAttempt, targetRecoveryIds as ids, targetRecoveryIdentity, targetRecoveryReceipt, targetRecoveryWorkflow } from './fixtures/m11-target-result-recovery';
import type { Workflow } from '../../apps/console-web/src/features/portal.types';
const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanup: [] as Array<() => void>, dialogs: [] as any[], scope: null as any,
  message: { success: vi.fn() }, workflow: null as any }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ modal: {}, message: frame.message }) } }));
vi.mock('../../apps/console-web/src/features/portal-hooks', () => ({ usePortalScope: () => frame.scope }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_modal: unknown, options: unknown) => { frame.dialogs.push(options); } }));
const detailPath = `/api/v1/clusters/${ids.cid}/workflows/${ids.workflow}?workspaceId=${ids.wid}`;
const receiptPath = `/api/v1/clusters/${ids.cid}/workflows/receipts/by-key/${ids.key}?workspaceId=${ids.wid}`;
const metadataPath = `/api/v1/clusters/${ids.cid}/workflows/${ids.workflow}/reconcile-target-result?workspaceId=${ids.wid}`;
const json = (data: unknown) => new Response(JSON.stringify({ data }), { headers: { 'Content-Type': 'application/json' } });
// Workflow detail uses the actual BFF envelope. Exercise the history allowlist
// at the component boundary rather than passing an already normalized detail.
const detailJson = (workflow: Workflow) => { const { nativeChange, ...entity } = workflow; return json({ entity, nativeChange }); };
function treeNodes(node: any): any[] { if (Array.isArray(node)) return node.flatMap(treeNodes); return !node || typeof node !== 'object' ? [] : [node, ...treeNodes(node.props?.children)]; }
const button = (tree: any, text: string) => treeNodes(tree).find(node => node.props?.children === text && typeof node.props?.onClick === 'function');
let client: typeof import('../../apps/console-web/src/api/client');
let model: typeof import('../../apps/console-web/src/features/workflow-entity-change.model');
let render: () => any, complete: ReturnType<typeof vi.fn>;
beforeEach(async () => {
  vi.resetModules(); frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanup = []; frame.dialogs = []; frame.message.success.mockReset();
  const values = new Map<string, string>(); vi.stubGlobal('sessionStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  vi.stubGlobal('window', { dispatchEvent: vi.fn() }); vi.stubGlobal('React', await import('react'));
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: { detail: unknown }) { super(type); this.detail = options.detail; } });
  vi.stubGlobal('crypto', { randomUUID: vi.fn(() => { throw new Error('replacement keys forbidden'); }) });
  client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(ids.actor); client.setCsrfToken('unit-only-csrf');
  model = await import('../../apps/console-web/src/features/workflow-entity-change.model'); model.storeWorkflowAttempt(targetRecoveryAttempt());
  const reference = { actor_id: ids.actor, cid: ids.cid, wid: ids.wid, kind: 'workflow', idempotencyKey: ids.key, state: 'uncertain' };
  frame.scope = { cid: ids.cid, wid: ids.wid, actor: ids.actor, version: 'actor:9', permission: { has: () => true },
    workspace: { writeBlocked: true, readonlyWorkspace: false, references: [reference], resolveReference: vi.fn() } };
  frame.workflow = targetRecoveryWorkflow(); complete = vi.fn().mockResolvedValue(undefined);
  const { WorkflowTargetResultRecovery } = await import('../../apps/console-web/src/features/WorkflowsPage');
  render = () => { frame.index = 0; return WorkflowTargetResultRecovery({ workflow: frame.workflow, onComplete: complete }); };
}, 30000);
afterEach(() => { for (const cleanup of frame.cleanup) cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
async function verify() {
  button(render(), '核验原 Target 回执').props.onClick(); await vi.waitFor(() => expect(frame.slots[1]).toBe(false)); return render();
}
async function confirmation() {
  const tree = await verify(); expect(button(tree, '仅核验结果元数据').props.disabled).toBe(false);
  button(tree, '仅核验结果元数据').props.onClick(); expect(frame.dialogs).toHaveLength(1); return frame.dialogs[0];
}
function mockPendingReads() { return vi.fn().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow())).mockResolvedValueOnce(json(targetRecoveryReceipt())); }
describe('actual Target recovery component with controlled BFF transport', () => {
  it('requires explicit confirmation, makes one original-key metadata POST, then proves both final receipt and new certificate', async () => {
    const fetch = mockPendingReads().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow())).mockResolvedValueOnce(json(targetRecoveryReceipt()))
      .mockResolvedValueOnce(json({ state: 'succeeded', nativeRequestsSent: 0 })).mockResolvedValueOnce(detailJson(targetRecoveryWorkflow(true)))
      .mockResolvedValueOnce(json(targetRecoveryReceipt(true))); vi.stubGlobal('fetch', fetch);
    const dialog = await confirmation(); expect(dialog.expected).toBe('native-change'); expect(dialog.danger).toBe(false);
    button(render(), '仅核验结果元数据').props.onClick(); expect(frame.dialogs).toHaveLength(1);
    await dialog.onConfirm();
    expect(fetch.mock.calls.map(call => call[0])).toEqual([detailPath, receiptPath, detailPath, receiptPath, metadataPath, detailPath, receiptPath]);
    const writes = fetch.mock.calls.filter(call => call[1].method === 'POST'); expect(writes).toHaveLength(1);
    expect(new Headers(writes[0][1].headers).get('X-Idempotency-Key')).toBe(ids.key);
    expect(JSON.parse(writes[0][1].body)).toEqual({ revision: 5, planHash: 'a'.repeat(64), executionId: ids.execution, confirmed: true, confirm_name: 'native-change' });
    expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)).toBeUndefined(); expect(frame.scope.workspace.resolveReference).toHaveBeenCalledTimes(1);
    expect(complete).toHaveBeenCalledTimes(1); expect(crypto.randomUUID).not.toHaveBeenCalled();
    expect(targetRecoveryWorkflow(true).nativeChange!.packets[0]).toMatchObject({ state: 'sent-unknown', nativeStatus: null, errorCode: 'MUTATION_RESULT_UNCERTAIN' });
  });
  it('a new device without this tab original execute journal gets no key input, confirmation, GET or replacement execute key', () => {
    model.clearWorkflowAttempt(targetRecoveryAttempt()); const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    const tree = render(); expect(button(tree, '核验原 Target 回执')).toBeUndefined(); expect(treeNodes(tree).some(node => node.props?.['aria-label']?.includes('幂等键'))).toBe(false);
    expect(fetch).not.toHaveBeenCalled(); expect(frame.dialogs).toHaveLength(0); expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('readonly can verify a certified completion through GET without opening a metadata write', async () => {
    frame.scope.workspace.readonlyWorkspace = true;
    const fetch = vi.fn().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow(true))).mockResolvedValueOnce(json(targetRecoveryReceipt(true))); vi.stubGlobal('fetch', fetch);
    await verify(); expect(fetch.mock.calls.map(call => call[0])).toEqual([detailPath, receiptPath]);
    expect(frame.dialogs).toHaveLength(0); expect(complete).toHaveBeenCalledTimes(1); expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)).toBeUndefined();
  });
  it.each(['receipt-actor-key', 'missing-wrapper-step', 'capability-absent'])('cannot enable metadata closure from %s', async variant => {
    const row = targetRecoveryWorkflow(), receipt = targetRecoveryReceipt();
    if (variant === 'receipt-actor-key') receipt.idempotencyKey = ids.other;
    if (variant === 'missing-wrapper-step') receipt.steps = [];
    if (variant === 'capability-absent') row.nativeChange!.targetResultReconciliationAvailable = false;
    const fetch = vi.fn().mockResolvedValueOnce(detailJson(row)).mockResolvedValueOnce(json(receipt)); vi.stubGlobal('fetch', fetch);
    expect(button(await verify(), '仅核验结果元数据').props.disabled).toBe(true); expect(fetch).toHaveBeenCalledTimes(2);
    expect(frame.dialogs).toHaveLength(0); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it.each(['actor', 'workspace', 'permission-version', 'original-journal', 'other-unknown', 'readonly', 'unmount'])('rejects open confirmation after %s changes before additional requests', async variant => {
    const fetch = mockPendingReads(); vi.stubGlobal('fetch', fetch); const dialog = await confirmation();
    if (variant === 'actor') client.setApiActorId(ids.other);
    if (variant === 'workspace') { frame.scope = { ...frame.scope, wid: ids.other }; render(); }
    if (variant === 'permission-version') { frame.scope = { ...frame.scope, version: 'actor:10' }; render(); }
    if (variant === 'original-journal') model.storeWorkflowAttempt({ ...targetRecoveryAttempt(), key: ids.other });
    if (variant === 'other-unknown') frame.scope.workspace.references.push({ actor_id: ids.actor, cid: ids.cid, wid: ids.wid, kind: 'workflow', idempotencyKey: ids.other });
    if (variant === 'readonly') frame.scope.workspace.readonlyWorkspace = true;
    if (variant === 'unmount') for (const cleanup of frame.cleanup) cleanup();
    await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'WORKFLOW_SCOPE_CHANGED' }); expect(fetch).toHaveBeenCalledTimes(2);
    expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it('fresh detail revision or execution mismatch after typed confirmation causes two GETs and zero POSTs', async () => {
    const changed = targetRecoveryWorkflow(); changed.revision = 6;
    const fetch = mockPendingReads().mockResolvedValueOnce(detailJson(changed)).mockResolvedValueOnce(json(targetRecoveryReceipt())); vi.stubGlobal('fetch', fetch);
    const dialog = await confirmation(); await expect(dialog.onConfirm()).rejects.toThrow();
    expect(fetch.mock.calls.map(call => call[0])).toEqual([detailPath, receiptPath, detailPath, receiptPath]);
    expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(0); expect(complete).not.toHaveBeenCalled();
  });
  it('lost metadata response retains the original fence and later uses only GET proof, never another native or metadata POST', async () => {
    let rejectPost!: (error: Error) => void;
    const fetch = mockPendingReads().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow())).mockResolvedValueOnce(json(targetRecoveryReceipt()))
      .mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectPost = reject; })); vi.stubGlobal('fetch', fetch);
    const dialog = await confirmation(), pending = dialog.onConfirm(); await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(5));
    expect(button(render(), '核验原 Target 回执').props.disabled).toBe(true);
    rejectPost(new Error('interrupted response')); await expect(pending).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { idempotencyKey: ids.key } });
    expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)?.key).toBe(ids.key); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
    expect(button(render(), '仅核验结果元数据').props.disabled).toBe(true);
    fetch.mockResolvedValueOnce(detailJson(targetRecoveryWorkflow(true))).mockResolvedValueOnce(json(targetRecoveryReceipt(true)));
    await verify(); expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1); expect(complete).toHaveBeenCalledTimes(1);
  });
  it('a metadata 401 never refreshes a session or automatically reissues the confirmed POST', async () => {
    const fetch = mockPendingReads().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow())).mockResolvedValueOnce(json(targetRecoveryReceipt()))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'SESSION_EXPIRED', message: 'Session expired' } }),
        { status: 401, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetch);
    const dialog = await confirmation(); await expect(dialog.onConfirm()).rejects.toMatchObject({ status: 401, code: 'SESSION_EXPIRED' });
    expect(fetch.mock.calls.map(call => call[0])).toEqual([detailPath, receiptPath, detailPath, receiptPath, metadataPath]);
    expect(fetch.mock.calls.filter(call => call[1].method === 'POST')).toHaveLength(1);
    expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)?.key).toBe(ids.key);
    expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled(); expect(complete).not.toHaveBeenCalled();
  });
  it('a certified completion resolves only this tab original reference when another unknown write remains', async () => {
    const unrelated = { actor_id: ids.actor, cid: ids.cid, wid: ids.wid, kind: 'workflow', idempotencyKey: ids.other, state: 'uncertain' };
    frame.scope.workspace.references.push(unrelated);
    const fetch = vi.fn().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow(true))).mockResolvedValueOnce(json(targetRecoveryReceipt(true))); vi.stubGlobal('fetch', fetch);
    await verify(); expect(frame.scope.workspace.resolveReference).toHaveBeenCalledTimes(1);
    expect(frame.scope.workspace.resolveReference.mock.calls[0][0]).toMatchObject({ actor_id: ids.actor, cid: ids.cid, wid: ids.wid, idempotencyKey: ids.key });
    expect(frame.scope.workspace.references).toContain(unrelated); expect(complete).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls.every(call => call[1].method === 'GET')).toBe(true);
  });
  it.each(['actor', 'workspace', 'permission-version', 'original-journal'])('a %s change while the metadata POST is in flight cannot release the original fence', async variant => {
    let resolvePost!: (value: Response) => void;
    const fetch = mockPendingReads().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow())).mockResolvedValueOnce(json(targetRecoveryReceipt()))
      .mockImplementationOnce(() => new Promise(resolve => { resolvePost = resolve; })); vi.stubGlobal('fetch', fetch);
    const dialog = await confirmation(), pending = dialog.onConfirm(); await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(5));
    if (variant === 'actor') client.setApiActorId(ids.other);
    if (variant === 'workspace') { frame.scope = { ...frame.scope, wid: ids.other }; render(); }
    if (variant === 'permission-version') { frame.scope = { ...frame.scope, version: 'actor:10' }; render(); }
    if (variant === 'original-journal') model.storeWorkflowAttempt({ ...targetRecoveryAttempt(), key: ids.other });
    resolvePost(json({ state: 'succeeded', nativeRequestsSent: 0 }));
    await expect(pending).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN' });
    expect(fetch).toHaveBeenCalledTimes(5); expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
    expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)?.key).toBe(variant === 'original-journal' ? ids.other : ids.key);
  });
  it('a succeeded metadata POST response without the authenticated certificate cannot release a fence', async () => {
    const final = targetRecoveryWorkflow(true); delete final.nativeChange!.packets[0].targetResultObservation;
    const fetch = mockPendingReads().mockResolvedValueOnce(detailJson(targetRecoveryWorkflow())).mockResolvedValueOnce(json(targetRecoveryReceipt()))
      .mockResolvedValueOnce(json({ state: 'succeeded' })).mockResolvedValueOnce(detailJson(final)).mockResolvedValueOnce(json(targetRecoveryReceipt(true))); vi.stubGlobal('fetch', fetch);
    const dialog = await confirmation(); await expect(dialog.onConfirm()).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN' });
    expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)?.key).toBe(ids.key); expect(complete).not.toHaveBeenCalled(); expect(frame.scope.workspace.resolveReference).not.toHaveBeenCalled();
  });
  it('a stale read resolving after an actor switch leaves the original fence and does not fetch receipt', async () => {
    let resolveDetail!: (value: Response) => void;
    const fetch = vi.fn().mockImplementationOnce(() => new Promise(resolve => { resolveDetail = resolve; })); vi.stubGlobal('fetch', fetch);
    button(render(), '核验原 Target 回执').props.onClick(); expect(fetch).toHaveBeenCalledTimes(1);
    client.setApiActorId(ids.other); resolveDetail(detailJson(targetRecoveryWorkflow())); await vi.waitFor(() => expect(frame.slots[1]).toBe(false));
    expect(fetch).toHaveBeenCalledTimes(1); expect(model.readWorkflowAttempt(targetRecoveryIdentity(), ids.workflow)?.key).toBe(ids.key); expect(complete).not.toHaveBeenCalled();
  });
});
