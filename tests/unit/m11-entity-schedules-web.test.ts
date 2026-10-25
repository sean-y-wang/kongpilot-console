import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const frame = vi.hoisted(() => ({ index: 0, slots: [] as any[], deps: [] as any[], cleanup: [] as Array<() => void>, scope: null as any, cluster: null as any, dialogs: [] as any[], queryOptions: [] as any[], row: null as any, storage: new Map<string, string>(), completed: vi.fn(), navigate: vi.fn(), schemaForm: { resetFields: vi.fn(), setFieldsValue: vi.fn(), setFieldValue: vi.fn(), getFieldValue: vi.fn(), getFieldsValue: vi.fn(() => ({})) }, afterRead: undefined as (() => void) | undefined }));
vi.mock('react', async original => ({ ...await original<typeof import('react')>(),
  useState: (initial: unknown) => { const index = frame.index++; if (!(index in frame.slots)) frame.slots[index] = typeof initial === 'function' ? initial() : initial; return [frame.slots[index], (value: unknown) => { frame.slots[index] = typeof value === 'function' ? value(frame.slots[index]) : value; }]; },
  useRef: (initial: unknown) => { const index = frame.index++; return frame.slots[index] ??= { current: initial }; },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => { const index = frame.index++; if (JSON.stringify(frame.deps[index]) !== JSON.stringify(deps)) { frame.deps[index] = deps; const cleanup = effect(); if (cleanup) frame.cleanup.push(cleanup); } },
}));
vi.mock('antd', async original => ({ ...await original<typeof import('antd')>(), App: { useApp: () => ({ modal: {}, message: { success: vi.fn() } }) }, Form: { useForm: () => [frame.schemaForm], useWatch: () => undefined } }));
vi.mock('react-router-dom', async original => ({ ...await original<typeof import('react-router-dom')>(), useNavigate: () => frame.navigate, useSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock('../../apps/console-web/src/features/portal-hooks', () => ({ usePortalScope: () => frame.scope }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => ({ cluster: frame.cluster }) }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { capabilities: { platformAdmin: true } } }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ mutationConfirm: (_: unknown, options: any) => { frame.dialogs.push(options); } }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'QueryError', formatTime: (value: string) => value }));
vi.mock('../../apps/console-web/src/features/IAMLookups', () => ({ ScopedEntityLookup: 'ScopedEntityLookup' }));
vi.mock('../../apps/console-web/src/components/CursorPagination', () => ({ CursorPagination: 'CursorPagination', useCursorPages: () => ({ cursor: undefined }) }));
vi.mock('../../apps/console-web/src/components/KongSchemaForm', () => ({ KongSchemaForm: 'KongSchemaForm', prepareFormValues: (_: unknown, value: unknown) => value ?? {}, schemaFields: (schema: any) => schema.fields.map((field: any) => Object.entries(field)[0]) }));
vi.mock('@tanstack/react-query', () => ({ useQuery: (options: any) => {
  frame.queryOptions.push(options);
  const schema = options.queryKey[0] === 'workflow-entity-schema';
  return { data: schema ? { fields: [{ name: { type: 'string' } }, { host: { type: 'string' } }] } : options.queryKey[0] === 'entity-schedule-detail' ? frame.row : undefined,
    refetch: vi.fn(async () => { frame.afterRead?.(); return { data: frame.row }; }) };
} }));

import { setApiActorId, setCsrfToken } from '../../apps/console-web/src/api/client';
import { EntityScheduleDetail, EntitySchedulesPage } from '../../apps/console-web/src/features/EntitySchedulesPage';
import { EntityChangePrepareDrawer, usePreparationWrite } from '../../apps/console-web/src/features/WorkflowEntityChanges';
import { canonicalScheduleInstant, defaultScheduleLocal, entityScheduleCommandBody, formatScheduleTime, normalizeEntitySchedule, normalizeEntityScheduleCommand, scheduledIntentMatchesRequest, scheduledPreparationPayload, shanghaiLocalToUtc, validateScheduleWindow } from '../../apps/console-web/src/features/entity-schedules.model';
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
function renderDrawer() { frame.index = 0; return EntityChangePrepareDrawer({ open: true, onClose: vi.fn(), onPrepared: frame.completed }); }
function renderHook() { frame.index = 0; return usePreparationWrite(id); }

beforeEach(async () => {
  frame.index = 0; frame.slots = []; frame.deps = []; frame.cleanup = []; frame.dialogs = []; frame.queryOptions = []; frame.storage.clear(); frame.afterRead = undefined; frame.completed.mockReset(); frame.navigate.mockReset();
  frame.cluster = { execution_mode: 'approval' }; frame.row = normalizeEntitySchedule(rawRow());
  frame.scope = { cid, wid, actor, version: 'PV1', ready: true, permission: { has: () => true }, workspace: { workspace: { status: 'active' }, readonlyWorkspace: false, writeBlocked: false }, path: (resource: string) => `/clusters/${frame.scope.cid}/${resource}${resource.includes('?') ? '&' : '?'}workspaceId=${frame.scope.wid}` };
  vi.stubGlobal('React', await import('react')); vi.stubGlobal('crypto', { randomUUID: vi.fn(() => key) }); vi.stubGlobal('window', { dispatchEvent: vi.fn() });
  vi.stubGlobal('sessionStorage', { getItem: (name: string) => frame.storage.get(name) ?? null, setItem: (name: string, value: string) => frame.storage.set(name, value), removeItem: (name: string) => frame.storage.delete(name) });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: any) { super(type); this.detail = options?.detail; } }); setApiActorId(actor); setCsrfToken('unit-only-csrf');
});
afterEach(() => { for (const cleanup of frame.cleanup) cleanup(); setApiActorId(undefined); setCsrfToken(''); vi.unstubAllGlobals(); });

describe('M11 fixed Shanghai inputs and safe V1/V2 schedule DTOs', () => {
  it('converts Shanghai calendar input with explicit +08 independently of machine-local timezone and across UTC day boundaries', () => {
    expect(shanghaiLocalToUtc('2026-10-13T08:15')).toBe('2026-10-13T00:15:00.000Z'); expect(shanghaiLocalToUtc('2026-10-13T00:15')).toBe('2026-10-12T16:15:00.000Z');
    expect(formatScheduleTime('2026-10-13T00:15:00.000Z')).toContain('08:15:00'); expect(canonicalScheduleInstant('2026-10-13T00:15:00Z')).toBe(false);
  });
  it.each(['2026-02-29T08:15', '2026-13-01T08:15', '2026-01-32T08:15', '2026-01-01T24:00', '2026-01-01T08:60', '2026-01-01T08:15Z', '2026-01-01T08:15+08:00'])('rejects invalid/nonlocal calendar input %s instead of Date rollover', value => { expect(() => shanghaiLocalToUtc(value)).toThrow(); });
  it('allows equality at window start but excludes exact end and reversed boundaries', () => {
    expect(() => validateScheduleWindow({ ...times, notBefore: times.windowStart })).not.toThrow(); expect(() => validateScheduleWindow({ ...times, notBefore: times.windowEnd })).toThrow(); expect(() => validateScheduleWindow({ ...times, windowStart: times.windowEnd })).toThrow();
  });
  it('pins executor from current actor and normalizes local input/TTL without native paths or permissions', () => {
    const now = Date.parse('2026-10-13T00:00:00.000Z'), payload = scheduledPreparationPayload(entityChange, { notBefore: '2026-10-13T08:15', windowStart: '2026-10-13T08:10', windowEnd: '2026-10-13T09:00' }, actor, 24, now);
    expect(payload).toMatchObject({ change: entityChange, ttlHours: 24, confirmed: true, confirm_name: 'scheduled-change', schedule: { version: 1, executorId: actor, notBefore: '2026-10-13T00:15:00.000Z' } }); expect(payload).not.toHaveProperty('authority'); expect(defaultScheduleLocal(now).notBefore).toBe('2026-10-13T08:15');
    expect(() => scheduledPreparationPayload(entityChange, { notBefore: '2026-10-13T08:00', windowStart: '2026-10-13T08:00', windowEnd: '2026-10-13T09:00' }, actor, 24, now)).toThrow();
  });
  it('rejects incomplete Target/recycle/batch, missing update IDs and windows exceeding the selected intent TTL', () => {
    const now = Date.parse('2099-01-01T00:00:00.000Z'), local = { notBefore: '2099-01-01T08:15', windowStart: '2099-01-01T08:10', windowEnd: '2099-01-01T09:00' };
    for (const kind of ['target', 'recycle', 'batch']) expect(() => scheduledPreparationPayload({ ...entityChange, kind }, local, actor, 24, now)).toThrow();
    expect(() => scheduledPreparationPayload({ ...entityChange, action: 'update' }, local, actor, 24, now)).toThrow(); expect(() => scheduledPreparationPayload(entityChange, { ...local, windowEnd: '2099-01-02T09:00' }, actor, 24, now)).toThrow();
    expect(scheduledPreparationPayload({ kind: 'credential', action: 'update', consumerId: id, credentialKind: 'key-auth', credentialId: intentId, body: {} }, local, actor, 24, now).schedule.executorId).toBe(actor);
  });
  it('keeps V1 intent projection exact while requiring separate scheduleSubmit for V2', () => {
    const v1 = normalizeEntityChangeIntent(rawIntent()); expect(v1).not.toHaveProperty('schedule'); expect(Object.keys(v1.capabilities)).toEqual(['submit']);
    const v2 = normalizeEntityChangeIntent(rawIntent(true)); expect(v2.schedule?.id).toBe(id); expect(entityChangeSubmitPayload(v2).materialHmac).toBe('b'.repeat(64));
    expect(() => entityChangeSubmitPayload({ ...v2, capabilities: { submit: true, scheduleSubmit: false } })).toThrow();
    for (const patch of [{ executionMode: 'direct' }, { nativeExecutionAvailable: true }, { schedule: { ...v2.schedule, version: 2 } }]) expect(() => normalizeEntityChangeIntent({ ...rawIntent(true), ...patch })).toThrow();
  });
  it('does not infer command capabilities from role/state; drops all private origin material and false authority', () => {
    const row = normalizeEntitySchedule({ ...rawRow(), capabilities: undefined, ownerId: actor, sourceCipher: 'private-cipher', body: { key: 'private-key' } }); expect(row.capabilities).toEqual({ activate: false, cancel: false }); expect(JSON.stringify(row)).not.toContain('private-');
    expect(() => entityScheduleCommandBody(row, 'activate')).toThrow(); expect(() => normalizeEntitySchedule({ ...rawRow(), nativeAuthority: true })).toThrow();
    expect(normalizeEntitySchedule({ ...rawRow(), capabilities: { activate: 'true', cancel: 1 } }).capabilities).toEqual({ activate: false, cancel: false });
  });
  it('accepts command completion only with literal acknowledgement and exact schedule ID, not just active state', () => {
    expect(normalizeEntityScheduleCommand({ entity: rawRow(), commandCompleted: true }, id).id).toBe(id);
    expect(() => normalizeEntityScheduleCommand({ entity: rawRow(), commandCompleted: false }, id)).toThrow(); expect(() => normalizeEntityScheduleCommand({ entity: rawRow(), commandCompleted: true }, intentId)).toThrow();
    expect(entityScheduleCommandBody(normalizeEntitySchedule(rawRow()), 'cancel')).toEqual({ revision: 2, confirmed: true, confirm_name: 'cancel-schedule' });
  });
  it('binds returned V2 execution account and all window instants to the exact confirmed request', () => {
    const requested = { version: 1 as const, executorId: actor, ...times }, actual = { id, ...requested };
    expect(scheduledIntentMatchesRequest(actual, requested)).toBe(true);
    for (const patch of [{ executorId: intentId }, { notBefore: times.windowStart }, { windowEnd: '2099-01-01T02:00:00.000Z' }]) expect(scheduledIntentMatchesRequest({ ...actual, ...patch }, requested)).toBe(false);
  });
});

describe('actual schedule list/details and owned original-key write fence', () => {
  it('uses actual20-row cursor scope/epoch/mode keys and rejects stale list admission after selector change', async () => {
    frame.index = 0; EntitySchedulesPage(); const options = frame.queryOptions.find(value => value.queryKey[0] === 'entity-schedules');
    expect(options.queryKey).toEqual(['entity-schedules', actor, 'PV1', cid, wid, 'approval', undefined]);
    let resolve!: (value: Response) => void; const fetch = vi.fn(() => new Promise<Response>(done => { resolve = done; })); vi.stubGlobal('fetch', fetch); const pending = options.queryFn({ signal: new AbortController().signal });
    expect(fetch.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/entity-schedules?size=20&workspaceId=${wid}`); frame.scope = { ...frame.scope, wid: intentId }; frame.index = 0; EntitySchedulesPage(); resolve(json({ items: [rawRow()], size: 20, total: null, nextCursor: null })); await expect(pending).rejects.toMatchObject({ code: 'WORKFLOW_SCOPE_CHANGED' });
  });
  it('leaves activation/cancellation buttons disabled without actual response caps, even for a platform user', () => {
    frame.row = normalizeEntitySchedule({ ...rawRow(), capabilities: undefined }); const tree = renderDetail(); expect(button(tree, '激活定时变更').props.disabled).toBe(true); expect(button(tree, '撤销定时变更').props.disabled).toBe(true); expect(frame.dialogs).toHaveLength(0);
  });
  it.each(['activate', 'cancel'] as const)('typed-confirmed %s refreshes CAS/cap then sends only the exact command with original key', async action => {
    const fetch = vi.fn(async () => { expect([...frame.storage.values()].join('')).toContain(key); return json({ entity: { ...rawRow(), state: action === 'activate' ? 'active' : 'cancelled', revision: 3 }, commandCompleted: true }); }); vi.stubGlobal('fetch', fetch);
    button(renderDetail(), action === 'activate' ? '激活定时变更' : '撤销定时变更').props.onClick(); expect(fetch).not.toHaveBeenCalled(); expect(frame.dialogs[0].expected).toBe(`${action}-schedule`); await frame.dialogs[0].onConfirm();
    expect(fetch).toHaveBeenCalledOnce(); expect(fetch.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/entity-schedules/${id}/${action}?workspaceId=${wid}`); expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ revision: 2, confirmed: true, confirm_name: `${action}-schedule` }); expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key); expect(frame.storage.size).toBe(0);
  });
  it.each(['actor', 'workspace', 'permission', 'mode', 'disabled', 'unmount'])('refuses a captured schedule command after %s changes, before POST', async variant => {
    vi.stubGlobal('fetch', vi.fn()); button(renderDetail(), '激活定时变更').props.onClick();
    if (variant === 'actor') setApiActorId(intentId);
    if (variant === 'workspace') { frame.scope = { ...frame.scope, wid: intentId }; renderDetail(); }
    if (variant === 'permission') { frame.scope = { ...frame.scope, version: 'PV2' }; renderDetail(); }
    if (variant === 'mode') { frame.cluster.execution_mode = 'direct'; renderDetail(); }
    if (variant === 'disabled') { frame.scope.workspace.workspace.status = 'disabled'; renderDetail(); }
    if (variant === 'unmount') for (const cleanup of frame.cleanup) cleanup();
    await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'WORKFLOW_SCOPE_CHANGED' }); expect(fetch).not.toHaveBeenCalled();
  });
  it('refuses fresh capability/revision drift after confirmation without generating a request key', async () => {
    vi.stubGlobal('fetch', vi.fn()); button(renderDetail(), '撤销定时变更').props.onClick(); frame.row = { ...frame.row, revision: 3 };
    await expect(frame.dialogs[0].onConfirm()).rejects.toThrow('已变化'); expect(fetch).not.toHaveBeenCalled(); expect(crypto.randomUUID).not.toHaveBeenCalled();
  });
  it('persists only original IDs on lost command response, locks both actions across reload and never POST-retries', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('lost response')); vi.stubGlobal('fetch', fetch); button(renderDetail(), '激活定时变更').props.onClick(); await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'WORKFLOW_PREPARATION_RESULT_UNKNOWN' });
    const reference = readWorkflowAttempt({ actor, cid, wid, version: 'PV1' }, id); expect(reference).toMatchObject({ key, state: 'unknown', action: 'scheduleActivate', mode: 'approval' }); expect(JSON.stringify(reference)).not.toContain('windowEnd');
    frame.slots = []; frame.deps = []; frame.index = 0; const reopened = renderDetail(); expect(button(reopened, '激活定时变更').props.disabled).toBe(true); expect(button(reopened, '撤销定时变更').props.disabled).toBe(true); expect(fetch).toHaveBeenCalledOnce();
  });
  it('preserves unknown schedule command across mode/permission changes without treating latest state as its original receipt', () => {
    storeWorkflowAttempt({ actor, cid, wid, version: 'PV1', mode: 'approval', subject: id, action: 'scheduleCancel', key, state: 'unknown' }); frame.cluster.execution_mode = 'direct'; frame.scope.version = 'PV2'; const hook = renderHook(); expect(hook.attempt?.key).toBe(key); expect(sameWorkflowIdentity({ actor, cid, wid, version: 'PV1', mode: 'approval' }, hook.identity)).toBe(false);
  });
  it('refuses a late command ACK after execution mode changes and preserves original key without resending', async () => {
    let resolve!: (value: Response) => void; const fetch = vi.fn(() => new Promise<Response>(done => { resolve = done; })); vi.stubGlobal('fetch', fetch);
    button(renderDetail(), '激活定时变更').props.onClick(); const pending = frame.dialogs[0].onConfirm(); await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    frame.cluster.execution_mode = 'direct'; renderDetail(); resolve(json({ entity: { ...rawRow(), state: 'active', revision: 3 }, commandCompleted: true }));
    await expect(pending).rejects.toMatchObject({ code: 'WORKFLOW_PREPARATION_RESULT_UNKNOWN' }); expect(readWorkflowAttempt({ actor, cid, wid }, id)?.key).toBe(key); expect(fetch).toHaveBeenCalledOnce();
  });
  it('scheduled entity drawer uses typed scheduled-change confirmation then prepares only V2, no submit/activate/execute', async () => {
    const fetch = vi.fn(async (_path: string, options: any) => json({ ...rawIntent(true), schedule: { id, ...JSON.parse(options.body).schedule } })); vi.stubGlobal('fetch', fetch); const initial = renderDrawer();
    const toggle = nodes(initial).find(node => node.props?.title?.props?.children === '定时变更').props.title; toggle.props.onChange({ target: { checked: true } });
    const schema = nodes(renderDrawer()).find(node => node.type === 'KongSchemaForm'); await schema.props.onFinish({ name: 'unit', host: 'localhost' }); expect(fetch).not.toHaveBeenCalled(); expect(frame.dialogs[0].expected).toBe('scheduled-change'); await frame.dialogs[0].onConfirm();
    expect(fetch).toHaveBeenCalledOnce(); expect(fetch.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/entity-changes/prepare-scheduled?workspaceId=${wid}`); const body = JSON.parse(fetch.mock.calls[0][1].body); expect(body.schedule.executorId).toBe(actor); expect(canonicalScheduleInstant(body.schedule.notBefore)).toBe(true); expect(frame.completed).toHaveBeenCalledOnce(); expect(frame.storage.size).toBe(0);
  });
  it('shows scheduled input for Target creation only in approval mode', () => {
    frame.cluster.execution_mode = 'direct'; expect(nodes(renderDrawer()).some(node => node.props?.title?.props?.children === '定时变更')).toBe(false);
    frame.cluster.execution_mode = 'approval'; const drawer = renderDrawer(); nodes(drawer).find(node => node.props?.['aria-label'] === '变更对象类别').props.onChange('target'); expect(nodes(renderDrawer()).some(node => node.props?.title?.props?.children === '定时变更')).toBe(true);
  });
  it('does not admit a mismatched scheduled preview after POST and leaves the original key locked', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(rawIntent(true))));
    const initial = renderDrawer(), toggle = nodes(initial).find(node => node.props?.title?.props?.children === '定时变更').props.title; toggle.props.onChange({ target: { checked: true } });
    await nodes(renderDrawer()).find(node => node.type === 'KongSchemaForm').props.onFinish({ name: 'unit', host: 'localhost' }); await expect(frame.dialogs[0].onConfirm()).rejects.toMatchObject({ code: 'WORKFLOW_PREPARATION_RESULT_UNKNOWN' });
    expect(frame.completed).not.toHaveBeenCalled(); expect(fetch).toHaveBeenCalledOnce(); expect(readWorkflowAttempt({ actor, cid, wid }, 'prepare')?.key).toBe(key);
  });
});
