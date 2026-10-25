import * as React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => ({ platform: true, actor: '', references: [] as any[], queries: [] as any[], confirm: undefined as any,
  api: vi.fn(), post: vi.fn(), resolve: vi.fn(), success: vi.fn(), queryOptions: [] as any[] }));
vi.mock('react', async original => ({ ...await original<typeof React>(), useState: (value: any) => [value, vi.fn()] }));
vi.mock('antd', () => ({ Alert: 'alert', Button: 'button', Space: 'space', Typography: { Paragraph: 'paragraph', Text: 'text' }, App: { useApp: () => ({ modal: {}, message: { success: fixture.success } }) } }));
vi.mock('@tanstack/react-query', () => ({ useQueries: ({ queries }: any) => { fixture.queryOptions = queries; return queries.map((_: any, index: number) => fixture.queries[index] ?? {}); } }));
vi.mock('../../apps/console-web/src/api/client', async original => ({ ...await original<any>(), api: fixture.api, post: fixture.post, getApiActorId: () => fixture.actor }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { id: fixture.actor } }) }));
vi.mock('../../apps/console-web/src/app/Permissions', () => ({ usePermissions: () => ({ platformAdmin: fixture.platform, version: 'current-version' }) }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => ({ references: fixture.references, resolveReference: fixture.resolve }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_: any, options: any) => { fixture.confirm = options; } }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'query-error' }));
import { RecycleReconciliation } from '../../apps/console-web/src/features/RecycleReconciliation';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7';
const actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', root = '3a00a193-bf24-49d4-8d65-c8e15ecf6874';
const op = 'bc7bd065-9372-405d-9782-015d31a30aa1', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22';
const entry = { id: root, root_type: 'services', original_id: root, root_name: 'reviewed-service', mutation_id: op, state: 'partially_deleted' };
const unknown = { id: op, cluster_id: cid, workspace_id: wid, action: 'delete', entity_type: 'services', entity_id: root, state: 'uncertain', remote_completed: false };
function findButton(element: any): any {
  if (!element || typeof element !== 'object') return undefined;
  if (element.type === 'button') return element;
  const candidates = [element.props?.description, ...React.Children.toArray(element.props?.children)];
  for (const node of candidates) { const found = findButton(node); if (found) return found; }
}
const render = (approval = false, onResult = vi.fn().mockResolvedValue(undefined)) => RecycleReconciliation({ entry, clusterId: cid, workspaceId: wid, approval, onResult });

beforeEach(() => {
  vi.stubGlobal('React', React); vi.stubGlobal('window', { dispatchEvent: vi.fn() });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } });
  fixture.platform = true; fixture.actor = actor; fixture.references = [{ actor_id: actor, cid, wid, idempotencyKey: key, state: 'uncertain' }];
  fixture.queries = [{ data: unknown }, { data: unknown }]; fixture.confirm = undefined;
  fixture.api.mockReset(); fixture.post.mockReset(); fixture.resolve.mockReset(); fixture.success.mockReset();
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('M5 actual recycle reconciliation UI', () => {
  it('hides graph recovery from ordinary users and refuses unrelated or already-terminal operations', () => {
    fixture.platform = false; expect(render()).toBeNull(); expect(fixture.queryOptions.every(row => row.enabled === false)).toBe(true);
    fixture.platform = true;
    for (const receipt of [{ ...unknown, entity_id: op }, { ...unknown, action: 'update' }, { ...unknown, state: 'succeeded', remote_completed: true }]) {
      fixture.queries = [{ data: receipt }, { data: receipt }]; expect(render()).toBeNull();
    }
    expect(fixture.post).not.toHaveBeenCalled();
  });
  it('blocks approval-cluster reconciliation and stages the exact archive confirmation without sending a write', () => {
    expect(findButton(render(true)).props.disabled).toBe(true);
    const button = findButton(render()); expect(button.props.children).toBe('核验结果'); button.props.onClick();
    expect(fixture.confirm).toMatchObject({ expected: entry.root_name, okText: '确认核验', danger: false });
    expect(fixture.confirm.description).toContain('不重发'); expect(fixture.confirm.description).toContain('15 秒'); expect(fixture.post).not.toHaveBeenCalled();
  });
  it('observes the original operation then resolves every matching reference only after a terminal durable receipt', async () => {
    const onResult = vi.fn().mockResolvedValue(undefined), result = { operationId: op, entryId: root, state: 'failed', observedOutcome: 'partially_applied' };
    fixture.post.mockResolvedValue(result); fixture.api.mockResolvedValue({ ...unknown, state: 'failed', remote_completed: true });
    findButton(render(false, onResult)).props.onClick(); await fixture.confirm.onConfirm();
    expect(fixture.post).toHaveBeenCalledExactlyOnceWith(`/clusters/${cid}/mutations/${op}/reconcile?workspaceId=${wid}`, { confirmed: true, confirm_name: entry.root_name });
    expect(fixture.api).toHaveBeenCalledExactlyOnceWith(`/clusters/${cid}/mutations/${op}?workspaceId=${wid}`);
    expect(fixture.resolve).toHaveBeenCalledExactlyOnceWith(fixture.references[0]); expect(onResult).toHaveBeenCalledExactlyOnceWith(result);
    expect(fixture.success).toHaveBeenCalledOnce();
  });
  it('retains the original write block when graph evidence or the follow-up receipt is incomplete', async () => {
    fixture.post.mockResolvedValue({ operationId: op, state: 'failed' }); fixture.api.mockResolvedValue(unknown);
    findButton(render()).props.onClick(); await expect(fixture.confirm.onConfirm()).rejects.toMatchObject({ code: 'RECONCILIATION_PROOF_INCOMPLETE' });
    expect(fixture.post).toHaveBeenCalledTimes(1); expect(fixture.resolve).not.toHaveBeenCalled(); expect(fixture.success).not.toHaveBeenCalled();
  });
});
