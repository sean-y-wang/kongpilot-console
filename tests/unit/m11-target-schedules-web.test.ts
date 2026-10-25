import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanup: [] as Array<() => void>, scope: null as any, cluster: null as any, dialogs: [] as any[], queryOptions: [] as any[], row: null as any, canPrepare: true, storage: new Map<string, string>(), completed: vi.fn(), navigate: vi.fn(), schemaForm: { resetFields: vi.fn(), setFieldsValue: vi.fn(), setFieldValue: vi.fn(), getFieldValue: vi.fn(), getFieldsValue: vi.fn(() => ({})) }, afterRead: undefined as (() => void) | undefined }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = typeof initial === 'function' ? initial() : initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = typeof value === 'function' ? value(frame.slots[index]) : value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ modal: {}, message: { success: vi.fn() } }) }, Form: { useForm: () => [frame.schemaForm], useWatch: () => undefined } }));
vi.mock('react-router-dom', async original => ({ ...await original<typeof import('react-router-dom')>(), useNavigate: () => frame.navigate, useSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock('../../apps/console-web/src/features/portal-hooks', () => ({ usePortalScope: () => frame.scope }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => ({ cluster: frame.cluster }) }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { capabilities: { platformAdmin: frame.canPrepare, grants: [] } } }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_: unknown, options: any) => { frame.dialogs.push(options); } }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError', formatTime: (value: string) => value }));
vi.mock('../../apps/console-web/src/features/IAMLookups', () => ({ ScopedEntityLookup: 'ScopedEntityLookup' }));
vi.mock('../../apps/console-web/src/components/CursorPagination', () => ({ CursorPagination: 'CursorPagination', useCursorPages: () => ({ cursor: undefined }) }));
vi.mock('../../apps/console-web/src/components/KongSchemaForm', () => ({ KongSchemaForm: 'KongSchemaForm', prepareFormValues: (_: unknown, value: unknown) => value ?? {}, schemaFields: (schema: any) => schema.fields.map((field: any) => Object.entries(field)[0]) }));
vi.mock('@tanstack/react-query', () => ({ useQuery: (options: any) => {
  frame.queryOptions.push(options);
  const schema = options.queryKey[0] === 'workflow-entity-schema';
  return { data: schema ? { fields: options.queryKey.at(-1) === 'targets' ? [{ target: { type: 'string' } }, { weight: { type: 'integer', between: [0, 1000] } }, { tags: { type: 'set', elements: { type: 'string' } } }] : [{ name: { type: 'string' } }, { host: { type: 'string' } }] } : options.queryKey[0] === 'entity-schedule-detail' ? frame.row : undefined,
    refetch: vi.fn(async () => { frame.afterRead?.(); return { data: frame.row }; }) };
} }));

import { setApiActorId, setCsrfToken } from '../../apps/console-web/src/api/client';
import { EntityScheduleDetail, EntitySchedulesPage } from '../../apps/console-web/src/features/EntitySchedulesPage';
import { EntityChangePrepareDrawer, usePreparationWrite } from '../../apps/console-web/src/features/WorkflowEntityChanges';
import { canonicalScheduleInstant, defaultScheduleLocal, entityScheduleCommandBody, formatScheduleTime, normalizeEntitySchedule, normalizeEntityScheduleCommand, scheduledIntentMatchesRequest, scheduledPreparationPayload, shanghaiLocalToUtc, validateScheduleWindow, scheduledTargetChangeValid, scheduledTargetReviewMatchesRequest } from '../../apps/console-web/src/features/entity-schedules.model';
import { entityChangeSubmitPayload, normalizeEntityChangeIntent, readWorkflowAttempt, sameWorkflowIdentity, storeWorkflowAttempt } from '../../apps/console-web/src/features/workflow-entity-change.model';

const actor = '30b6d312-a9b8-4ac4-b49d-d8d87e1eeccf', cid = 'a949b292-2e4a-4326-b30d-3a883b5ef3d7', wid = '306a8d36-d1f9-4542-8972-9b30aa1bd67c', id = '35b60072-927d-4f3b-bba1-dbc31bd345e4', intentId = 'c6439d99-75a0-4f2b-b6d7-a2d3f0c87177', key = 'f02f0f79-03bb-4494-9b2c-f3fa4a28a28a';
const times = { notBefore: '2099-01-01T00:15:00.000Z', windowStart: '2099-01-01T00:10:00.000Z', windowEnd: '2099-01-01T01:00:00.000Z' };
const rawRow = () => ({ id, revision: 2, state: 'pending-approval', intentId, ...times, workflowId: null, claimId: null, reasonCode: null, nativeAuthority: false, capabilities: { activate: true, cancel: true } });
const entityChange = { kind: 'entity', action: 'create', entityType: 'services', body: { name: 'controlled', host: 'localhost' } };
const json = (data: unknown) => new Response(JSON.stringify({ data }), { headers: { 'Content-Type': 'application/json' } });
function rawIntent(schedule = false): any { return { id: intentId, revision: 1, materialHmac: 'b'.repeat(64), executionMode: 'approval', issuedAt: '2026-10-13T00:00:00Z', expiresAt: '2099-01-01T01:00:00.000Z', nativeExecutionAvailable: false, capabilities: { submit: true, ...(schedule ? { scheduleSubmit: true } : {}) }, ...(schedule ? { schedule: { id, version: 1, executorId: actor, ...times } } : {}), review: { changes: [], impact: { changedObjects: 0, nativePackets: 0, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: { state: 'baseline-required', blockerCodes: [] } } }; }
function nodes(tree: any): any[] { return Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []; }
const button = (tree: any, label: string) => nodes(tree).find(node => node.props?.children === label && typeof node.props?.onClick === 'function');
function renderDetail() { frame.index = 0; return EntityScheduleDetail({ id, onClose: vi.fn() }); }
function renderDrawer(open = true) { frame.index = 0; return EntityChangePrepareDrawer({ open, onClose: vi.fn(), onPrepared: frame.completed }); }
function renderHook() { frame.index = 0; return usePreparationWrite(id); }

beforeEach(async () => {
  frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanup = []; frame.dialogs = []; frame.queryOptions = []; frame.storage.clear(); frame.afterRead = undefined; frame.completed.mockReset(); frame.navigate.mockReset();
  frame.canPrepare = true; frame.schemaForm.getFieldsValue.mockReset().mockReturnValue({}); frame.cluster = { execution_mode: 'approval' }; frame.row = normalizeEntitySchedule(rawRow());
  frame.scope = { cid, wid, actor, version: 'PV1', ready: true, permission: { has: () => true }, workspace: { workspace: { status: 'active' }, readonlyWorkspace: false, writeBlocked: false }, path: (resource: string) => `/clusters/${frame.scope.cid}/${resource}${resource.includes('?') ? '&' : '?'}workspaceId=${frame.scope.wid}` };
  vi.stubGlobal('React', await import('react')); vi.stubGlobal('crypto', { randomUUID: vi.fn(() => key) }); vi.stubGlobal('window', { dispatchEvent: vi.fn() });
  vi.stubGlobal('sessionStorage', { getItem: (name: string) => frame.storage.get(name) ?? null, setItem: (name: string, value: string) => frame.storage.set(name, value), removeItem: (name: string) => frame.storage.delete(name) });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: any) { super(type); this.detail = options?.detail; } }); setApiActorId(actor); setCsrfToken('unit-only-csrf');
});
afterEach(() => { for (const cleanup of frame.cleanup) cleanup(); setApiActorId(undefined); setCsrfToken(''); vi.unstubAllGlobals(); });

// Controlled component/client adapters exercise Source contracts; they are not runtime receipts.
const originalTarget = { id, target: 'echo.internal:8080', weight: 100, upstream: { id: intentId }, tags: ['owner:console'] };
const local = { notBefore: '2099-01-01T08:15', windowStart: '2099-01-01T08:10', windowEnd: '2099-01-01T09:00' };
const targetChange = (weight = 80) => ({ kind: 'target', action: 'weight', upstreamId: intentId, targetId: id, body: { weight } });
function selectTarget(editing = true) {
  nodes(renderDrawer()).find(node => node.props?.['aria-label'] === '变更对象类别').props.onChange('target');
  if (editing) nodes(renderDrawer()).find(node => node.props?.['aria-label'] === '变更操作').props.onChange('update');
  nodes(renderDrawer()).find(node => node.type === 'ScopedEntityLookup' && node.props.label === '选择所属对象').props.onChange(intentId);
  if (editing) {
    const lookup = nodes(renderDrawer()).find(node => node.type === 'ScopedEntityLookup' && node.props.label === '选择变更对象');
    lookup.props.onChange(id); lookup.props.onSelected(originalTarget);
  }
  const toggle = nodes(renderDrawer()).find(node => node.props?.title?.props?.children === '定时变更').props.title;
  toggle.props.onChange({ target: { checked: true } }); return renderDrawer();
}
function scheduledReply(body: any) {
  const creating = body.change.action === 'create', weight = body.change.body.weight, next = { id: key, target: creating ? body.change.body.target : originalTarget.target, weight };
  return { ...rawIntent(true), schedule: { id, ...body.schedule }, review: { changes: [{ entityType: 'targets', nativeId: key, action: creating ? 'create' : 'update', ...(creating ? {} : { originalNativeId: id }), before: creating ? null : originalTarget, after: next }], impact: { changedObjects: 1, nativePackets: 1, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: { state: 'baseline-required', blockerCodes: ['TARGET_RESTORE_APPENDS_HISTORY'] } } };
}
async function confirmWeight(weight = 80) {
  await nodes(selectTarget()).find(node => node.type === 'KongSchemaForm').props.onFinish({ weight });
  return frame.dialogs[0].onConfirm();
}

describe('Target scheduled typed payload and append receipt identity', () => {
  it.each([100, 80, 0])('accepts numeric weight %i with the actual upstream and original Target ID', weight => {
    const payload = scheduledPreparationPayload(targetChange(weight), local, actor, 24, Date.parse('2099-01-01T00:00:00.000Z'));
    expect(payload.change).toEqual(targetChange(weight)); expect(payload.change.action).toBe('weight'); expect(payload.schedule.executorId).toBe(actor);
    expect(scheduledTargetReviewMatchesRequest(scheduledReply(payload).review.changes, payload.change)).toBe(true);
  });
  it('creates a Target without any caller-chosen native ID and freezes the original body', () => {
    const change = { kind: 'target', action: 'create', upstreamId: intentId, body: { target: 'echo.internal:8080', weight: 100 } };
    const payload = scheduledPreparationPayload(change, local, actor, 24, Date.parse('2099-01-01T00:00:00.000Z'));
    change.body.weight = 0; expect(payload.change.body.weight).toBe(100); expect(scheduledTargetReviewMatchesRequest(scheduledReply(payload).review.changes, payload.change)).toBe(true);
    expect(scheduledTargetChangeValid({ ...payload.change, targetId: id })).toBe(false);
  });
  it.each([
    { action: 'health', state: 'unhealthy' }, { action: 'update' }, { upstreamId: intentId.toUpperCase() }, { targetId: id.toUpperCase() },
    { upstreamId: `${intentId} ` }, { targetId: undefined }, { body: { weight: '0' } }, { body: { weight: -1 } }, { body: { weight: 1001 } },
    { body: { weight: 0.5 } }, { body: { weight: 80, state: 'healthy' } }, { body: { weight: 80, target: 'other.internal:80' } }, { body: { weight: 80, id: key } },
  ])('rejects health, invalid IDs, altered address and unauthorized extra fields %j', patch => {
    expect(() => scheduledPreparationPayload({ ...targetChange(), ...patch }, local, actor, 24, Date.parse('2099-01-01T00:00:00.000Z'))).toThrow();
  });
  it.each([
    { originalNativeId: key }, { nativeId: id }, { action: 'mark_unhealthy' }, { entityType: 'services' },
    { before: { ...originalTarget, upstream: { id: key } } }, { after: { id: key, target: 'other.internal:80', weight: 80 } },
    { after: { id: key, target: originalTarget.target, weight: 0 } },
  ])('rejects substituted append review %j without demanding that the new UUID equal the old ID', patch => {
    const payload = { change: targetChange(), schedule: { version: 1, executorId: actor, ...times } }, row = scheduledReply(payload).review.changes[0];
    expect(scheduledTargetReviewMatchesRequest([{ ...row, ...patch }], payload.change)).toBe(false);
  });
});

describe('actual Target scheduling drawer and original-key fence', () => {
  it.each([100, 80, 0])('confirms weight %i then sends one typed scheduled prepare and no native writes', async weight => {
    const fetch = vi.fn(async (_path: string, options: any) => json(scheduledReply(JSON.parse(options.body)))); vi.stubGlobal('fetch', fetch);
    const tree = selectTarget(), schema = nodes(tree).find(node => node.type === 'KongSchemaForm');
    expect(schema.props.schema.fields.map((entry: any) => Object.keys(entry)[0])).toEqual(['weight']);
    const summary = nodes(tree).find(node => node.props?.title === 'Upstream → Target'); expect(summary).toBeTruthy();
    expect(summary.props.children.props.items.find((item: any) => item.key === 'parent').children.props.children).toBe(intentId);
    expect(frame.queryOptions.filter(options => options.queryKey[0] === 'workflow-entity-before').at(-1).enabled).toBe(false);
    await schema.props.onFinish({ weight, target: 'ignored-address', id: 'caller-id' }); expect(fetch).not.toHaveBeenCalled();
    expect(frame.dialogs[0]).toMatchObject({ expected: 'scheduled-change', danger: weight === 0 }); expect(frame.dialogs[0].description).toContain(`权重 100 → ${weight}`); expect(frame.dialogs[0].description).toContain('窗口');
    await frame.dialogs[0].onConfirm(); expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/entity-changes/prepare-scheduled?workspaceId=${wid}`);
    const options = fetch.mock.calls[0][1], payload = JSON.parse(options.body); expect(payload.change).toEqual(targetChange(weight));
    expect(new Headers(options.headers).get('X-Idempotency-Key')).toBe(key); expect(frame.completed).toHaveBeenCalledOnce(); expect(frame.storage.size).toBe(0);
  });
  it('exposes Target creation and weight entries while excluding health from all operation options', async () => {
    const fetch = vi.fn(async (_path: string, options: any) => json(scheduledReply(JSON.parse(options.body)))); vi.stubGlobal('fetch', fetch);
    const tree = selectTarget(false), operation = nodes(tree).find(node => node.props?.['aria-label'] === '变更操作');
    expect(operation.props.options).toEqual([{ value: 'create', label: '创建' }, { value: 'update', label: '调整权重' }]);
    await nodes(tree).find(node => node.type === 'KongSchemaForm').props.onFinish({ target: 'new.internal:8080', weight: 100 }); await frame.dialogs[0].onConfirm();
    expect(JSON.parse(fetch.mock.calls[0][1].body).change).toEqual({ kind: 'target', action: 'create', upstreamId: intentId, body: { target: 'new.internal:8080', weight: 100 } });
  });
  it.each(['parent', 'target', 'window', 'ttl', 'action', 'closed', 'form', 'grants', 'readonly', 'permission', 'actor', 'cluster', 'mode'] as const)('refuses a captured Target confirmation after %s changes without a new key or POST', async variant => {
    vi.stubGlobal('fetch', vi.fn()); await nodes(selectTarget()).find(node => node.type === 'KongSchemaForm').props.onFinish({ weight: 80 });
    const tree = renderDrawer();
    if (variant === 'parent') nodes(tree).find(node => node.type === 'ScopedEntityLookup' && node.props.label === '选择所属对象').props.onChange(key);
    if (variant === 'target') nodes(tree).find(node => node.type === 'ScopedEntityLookup' && node.props.label === '选择变更对象').props.onChange(key);
    if (variant === 'window') nodes(tree).find(node => node.props?.['aria-label'] === '计划执行时间（上海）').props.onChange({ target: { value: '2099-01-01T08:20' } });
    if (variant === 'ttl') nodes(tree).find(node => node.props?.['aria-label'] === '准备记录有效期小时').props.onChange(48);
    if (variant === 'action') nodes(tree).find(node => node.props?.['aria-label'] === '变更操作').props.onChange('create');
    if (variant === 'form') frame.schemaForm.getFieldsValue.mockReturnValue({ weight: 0 });
    if (variant === 'grants') frame.canPrepare = false;
    if (variant === 'readonly') frame.scope.workspace.readonlyWorkspace = true;
    if (variant === 'permission') frame.scope = { ...frame.scope, version: 'PV2' };
    if (variant === 'actor') setApiActorId(key);
    if (variant === 'cluster') frame.scope = { ...frame.scope, cid: key };
    if (variant === 'mode') frame.cluster.execution_mode = 'direct';
    renderDrawer(variant !== 'closed'); await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'WORKFLOW_SCOPE_CHANGED' });
    expect(fetch).not.toHaveBeenCalled(); expect(crypto.randomUUID).not.toHaveBeenCalled(); expect(frame.storage.size).toBe(0);
  });
  it('rejects a wrong-parent current page row before form submission', async () => {
    vi.stubGlobal('fetch', vi.fn()); selectTarget(); const lookup = nodes(renderDrawer()).find(node => node.type === 'ScopedEntityLookup' && node.props.label === '选择变更对象');
    lookup.props.onSelected({ ...originalTarget, upstream: { id: key } }); const tree = renderDrawer();
    expect(tree.props.extra.props.disabled).toBe(true); await nodes(tree).find(node => node.type === 'KongSchemaForm').props.onFinish({ weight: 80 }); expect(frame.dialogs).toHaveLength(0); expect(fetch).not.toHaveBeenCalled();
  });
  it('keeps a lost original prepare key across reload and blocks a second Target request', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('lost controlled response')); vi.stubGlobal('fetch', fetch);
    await expect(confirmWeight(0)).rejects.toMatchObject({ code: 'WORKFLOW_PREPARATION_RESULT_UNKNOWN' });
    const original = readWorkflowAttempt({ actor, cid, wid }, 'prepare'); expect(original).toMatchObject({ key, action: 'prepare', state: 'unknown' }); expect(JSON.stringify(original)).not.toContain('echo.internal');
    frame.slots = []; frame.deps = []; const reopened = selectTarget(); expect(reopened.props.extra.props.disabled).toBe(true);
    await nodes(reopened).find(node => node.type === 'KongSchemaForm').props.onFinish({ weight: 80 }); expect(frame.dialogs).toHaveLength(1); expect(fetch).toHaveBeenCalledOnce();
  });
  it('does not refresh or automatically POST again after a 401 and retains the original key', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'SESSION_EXPIRED', message: 'expired' } }), { status: 401, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetch);
    await expect(confirmWeight()).rejects.toMatchObject({ status: 401 }); expect(fetch).toHaveBeenCalledOnce(); expect(fetch.mock.calls[0][0]).toContain('prepare-scheduled');
    expect(readWorkflowAttempt({ actor, cid, wid }, 'prepare')?.key).toBe(key); expect(frame.completed).not.toHaveBeenCalled();
  });
  it('keeps the original key when the controlled returned append names a different old Target', async () => {
    const fetch = vi.fn(async (_path: string, options: any) => { const reply = scheduledReply(JSON.parse(options.body)); reply.review.changes[0].originalNativeId = key; return json(reply); }); vi.stubGlobal('fetch', fetch);
    await expect(confirmWeight()).rejects.toMatchObject({ code: 'WORKFLOW_PREPARATION_RESULT_UNKNOWN' }); expect(frame.completed).not.toHaveBeenCalled(); expect(readWorkflowAttempt({ actor, cid, wid }, 'prepare')?.key).toBe(key); expect(fetch).toHaveBeenCalledOnce();
  });
  it('retains the original key when a late result arrives after the Target selection changes', async () => {
    let resolve!: (value: Response) => void; const fetch = vi.fn(() => new Promise<Response>(done => { resolve = done; })); vi.stubGlobal('fetch', fetch);
    const pending = confirmWeight(); await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    nodes(renderDrawer()).find(node => node.type === 'ScopedEntityLookup' && node.props.label === '选择所属对象').props.onChange(key); renderDrawer();
    resolve(json(scheduledReply(JSON.parse(fetch.mock.calls[0][1].body)))); await expect(pending).rejects.toMatchObject({ code: 'WORKFLOW_PREPARATION_RESULT_UNKNOWN' });
    expect(frame.completed).not.toHaveBeenCalled(); expect(readWorkflowAttempt({ actor, cid, wid }, 'prepare')?.key).toBe(key); expect(fetch).toHaveBeenCalledOnce();
  });
});
