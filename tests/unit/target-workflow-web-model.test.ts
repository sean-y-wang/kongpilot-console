import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../apps/console-web/src/api/client';
import { createTargetWorkflowClient, normalizeTargetWorkflowIntent, readTargetWorkflowAttempt, storeTargetWorkflowAttempt, targetManualHealthAvailable,
  targetWorkflowChange, targetWorkflowFormDefaults, targetWorkflowScope, targetWorkflowSelection, targetWorkflowStorageKey,
  type TargetWorkflowAction, type TargetWorkflowScope } from '../../apps/console-web/src/features/target-workflow.model';

/** Source-only transport/storage tests. No actual BFF, native HTTP, SQL, login,
 * timer execution, browser or commercial acceptance is claimed. */
function fixture(action: TargetWorkflowAction = 'create', healthState: 'healthy' | 'unhealthy' = 'healthy') {
  let scope: TargetWorkflowScope = { actor: randomUUID(), version: 'actual-current-source-version', cid: randomUUID(), wid: randomUUID(), mode: 'approval', upstreamId: randomUUID() };
  const originalScope = { ...scope }, oldId = randomUUID(), newId = randomUUID(), intentId = randomUUID(), workflowId = randomUUID();
  const row = { id: oldId, upstream: { id: scope.upstreamId }, target: 'api.internal:8080', weight: 100, tags: ['owner:pay', 'workspace:payments'] };
  const selection = targetWorkflowSelection(scope, action, action === 'create' ? undefined : row, action === 'health' ? healthState : undefined);
  const body = action === 'create' ? { target: row.target, weight: 80, tags: ['owner:pay'] } : action === 'weight' ? { weight: 80, tags: ['owner:pay'] } : undefined;
  const subject = { upstreamId: scope.upstreamId, action, ...(selection.targetId ? { targetId: selection.targetId } : {}), ...(selection.healthState ? { state: selection.healthState } : {}) };
  const intent: any = { id: intentId, revision: 1, materialHmac: 'a'.repeat(64), executionMode: 'approval', issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString(),
    nativeExecutionAvailable: false, capabilities: { submit: true }, workflowId: null, targetSubject: subject,
    review: { clusterId: scope.cid, workspaceId: scope.wid, changes: [{ entityType: 'targets', nativeId: action === 'create' || action === 'weight' ? newId : oldId,
      ...(action === 'weight' ? { originalNativeId: oldId } : {}), action: action === 'weight' ? 'update' : action === 'health' ? `mark_${healthState}` : action,
      before: action === 'create' ? null : row, after: action === 'create' || action === 'weight' ? { ...row, id: newId, weight: 80, password: 'must-not-be-displayed' } : null }],
      impact: { changedObjects: 1, nativePackets: 1, trafficAvailability: 'unavailable', globalPlugin: false },
      recovery: { state: 'baseline-required', blockerCodes: [action === 'health' ? 'TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE' : 'TARGET_RESTORE_APPENDS_HISTORY'] } } };
  const values = new Map<string, string>(), storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); }, removeItem: (key: string) => { values.delete(key); } };
  const state: any = { writable: true, active: true, csrf: 'current-controlled-csrf-token', postError: null, submitUnknown: false, notPrepared: false, afterPost: undefined, receiptPatch: undefined, gate: undefined };
  const keys: string[] = [], key = vi.fn(() => { const value = randomUUID(); keys.push(value); return value; });
  const transport = vi.fn(async (path: string, options: RequestInit = {}, retried = false) => {
    if (path === '/auth/me') return { user: { id: scope.actor, permissionsVersion: scope.version }, csrfToken: state.csrf };
    if (options.method === 'POST') {
      if (state.gate) await state.gate; if (state.postError) throw state.postError;
      if (path.includes('/prepare?')) { state.afterPost?.(); return structuredClone(intent); }
      if (path.includes('/submit?')) { intent.workflowId = workflowId; state.afterPost?.(); if (state.submitUnknown) throw new ApiError('private-server-value', 503, 'UNKNOWN');
        return { workflowId, submissionCompleted: true, nativeExecutionAvailable: false }; }
      throw new Error('UNEXPECTED_SOURCE_WRITE');
    }
    if (path.includes('/by-prepare-key/')) return state.notPrepared ? { state: 'not_prepared', clusterId: scope.cid, workspaceId: scope.wid, idempotencyKey: keys[0], intentId: null,
      nativeExecutionAvailable: false, retryWriteAllowed: false, originalOutcome: 'not_observed' } : structuredClone(intent);
    if (path.includes('/entity-changes/' + intentId + '?')) return structuredClone(intent);
    if (path.includes('/workflows/receipts/by-key/')) return { id: workflowId, workflowId, clusterId: scope.cid, workspaceId: scope.wid, idempotencyKey: keys.at(-1), action: 'submit',
      state: 'pending', approvalRequired: true, submissionCompleted: true, steps: [], ...state.receiptPatch };
    throw new Error('UNEXPECTED_SOURCE_READ');
  });
  const client = createTargetWorkflowClient({ scope: () => scope, storage, key, transport: transport as any,
    assertCurrent(captured, writing) { if (!state.active || captured.actor !== scope.actor || writing && !state.writable) throw new ApiError('current actor denied', 403, 'DENIED'); } });
  return { client, storage, values, state, key, keys, transport, intent, intentId, workflowId, oldId, newId, row, selection, body, originalScope,
    scope: () => scope, changeScope: (patch: Partial<TargetWorkflowScope>) => { scope = { ...scope, ...patch }; },
    prepare: () => client.prepare(selection, body, action === 'delete' ? row.target : undefined), attempt: () => readTargetWorkflowAttempt(scope, storage),
    posts: () => transport.mock.calls.filter(call => call[1]?.method === 'POST') };
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T08:00:00Z')); });
afterEach(() => vi.useRealTimers());

describe('Target public immutable parent/old/new-ID workflow contract', () => {
  it.each(['create', 'weight', 'health', 'delete'] as const)('prepares %s through one typed entity-change packet', async action => {
    const f = fixture(action), row = await f.prepare(), call = f.posts()[0], change = JSON.parse(call[1]!.body as string).change;
    expect(call[0]).toBe(`/clusters/${f.scope().cid}/entity-changes/prepare?workspaceId=${f.scope().wid}`); expect(call[2]).toBe(true);
    expect(new Headers(call[1]!.headers).get('X-Idempotency-Key')).toBe(f.keys[0]);
    expect(new Headers(call[1]!.headers).get('X-CSRF-Token')).toBe(f.state.csrf);
    if (action === 'delete') expect(change).toEqual({ kind: 'recycle', action: 'delete', entityType: 'targets', entityId: f.oldId, parentId: f.scope().upstreamId, confirmed: true, confirm_name: f.row.target });
    else if (action === 'health') expect(change).toEqual({ kind: 'target', action: 'health', upstreamId: f.scope().upstreamId, targetId: f.oldId, state: 'healthy' });
    else expect(change).toEqual({ kind: 'target', action, upstreamId: f.scope().upstreamId, ...(action === 'weight' ? { targetId: f.oldId } : {}), body: f.body });
    expect(row.nativeExecutionAvailable).toBe(false); expect(JSON.stringify(row.review)).not.toContain('must-not-be-displayed'); expect(f.attempt()?.state).toBe('prepared');
  });
  it('supports unhealthy only with explicit state and keeps native after null', async () => { const f = fixture('health', 'unhealthy'); const row = await f.prepare(); expect(row.review.changes[0].action).toBe('mark_unhealthy'); expect(row.review.changes[0].after).toBeNull(); });
  it('accepts the new append UUID while retaining the original UUID in review', async () => { const f = fixture('weight'); const row = await f.prepare(); expect(row.review.changes[0]).toMatchObject({ nativeId: f.newId, originalNativeId: f.oldId }); expect(f.newId).not.toBe(f.oldId); });
  it('strips only inherited workspace tags from form defaults and keeps business tag editing', () => {
    const f = fixture('weight'), defaults = targetWorkflowFormDefaults({ ...f.row, tags: ['workspace:payments', 'kos-ws-payments', 'owner:pay', 'team:pay'] });
    expect(defaults.tags).toEqual(['owner:pay', 'team:pay']); expect(targetWorkflowChange(f.scope(), f.selection, defaults)).toMatchObject({ body: { target: f.row.target, weight: 100, tags: ['owner:pay', 'team:pay'] } });
  });
  it.each([-1, 1001, 65535, 0.5, NaN])('rejects unsupported weight %s before creating an auth request or key', async value => {
    const f = fixture('weight'); await expect(f.client.prepare(f.selection, { weight: value })).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled(); expect(f.key).not.toHaveBeenCalled();
  });
  it('requires an explicit create weight so the reviewed append packet contains the exact value', async () => { const f = fixture();
    await expect(f.client.prepare(f.selection, { target: f.row.target })).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled(); expect(f.key).not.toHaveBeenCalled(); });
  it.each([0, 80, 1000])('keeps valid append weight %s', value => { const f = fixture('weight'); expect(targetWorkflowChange(f.scope(), f.selection, { weight: value })).toMatchObject({ body: { weight: value } }); });
  it.each(['id', 'upstream', 'created_at', 'ttl', 'nativePath', 'scheduled'])('rejects client-owned %s target payload field', field => { const f = fixture(); expect(() => targetWorkflowChange(f.scope(), f.selection, { target: f.row.target, [field]: f.oldId })).toThrow(); });
  it('rejects reserved workspace tags and a copied foreign Upstream row', () => { const f = fixture('weight'); expect(() => targetWorkflowChange(f.scope(), f.selection, { weight: 80, tags: ['workspace:foreign'] })).toThrow(); expect(() => targetWorkflowSelection(f.scope(), 'weight', { ...f.row, upstream: { id: randomUUID() } })).toThrow(); expect(() => targetWorkflowSelection(f.scope(), 'weight', { ...f.row, upstream: undefined })).toThrow(); });
  it.each(['missing', 'foreign-parent', 'foreign-target', 'action', 'health-state', 'cid', 'wid', 'schedule', 'native', 'extra-packet'])('rejects %s subject substitution', reason => {
    const f = fixture('health'), raw = structuredClone(f.intent);
    if (reason === 'missing') delete raw.targetSubject;
    if (reason === 'foreign-parent') raw.targetSubject.upstreamId = randomUUID();
    if (reason === 'foreign-target') raw.targetSubject.targetId = randomUUID();
    if (reason === 'action') raw.targetSubject.action = 'delete';
    if (reason === 'health-state') raw.targetSubject.state = 'unhealthy';
    if (reason === 'cid') raw.review.clusterId = randomUUID();
    if (reason === 'wid') raw.review.workspaceId = randomUUID();
    if (reason === 'schedule') raw.schedule = {};
    if (reason === 'native') raw.nativeExecutionAvailable = true;
    if (reason === 'extra-packet') raw.review.changes.push(raw.review.changes[0]);
    expect(() => normalizeTargetWorkflowIntent(raw, f.scope(), f.selection)).toThrow();
  });
  it.each(['old-id-as-new', 'missing-original', 'wrong-before-id', 'wrong-before-parent', 'changed-address', 'wrong-weight'])('rejects %s append result', reason => {
    const f = fixture('weight'), raw = structuredClone(f.intent), change = raw.review.changes[0];
    if (reason === 'old-id-as-new') { change.nativeId = f.oldId; change.after.id = f.oldId; }
    if (reason === 'missing-original') delete change.originalNativeId;
    if (reason === 'wrong-before-id') change.before.id = randomUUID();
    if (reason === 'wrong-before-parent') change.before.upstream.id = randomUUID();
    if (reason === 'changed-address') change.after.target = 'another:8080';
    if (reason === 'wrong-weight') change.after.weight = 7;
    expect(() => normalizeTargetWorkflowIntent(raw, f.scope(), f.selection, f.body)).toThrow();
  });
  it('refuses health review without the explicit nonreversible blocker', () => { const f = fixture('health'); f.intent.review.recovery.blockerCodes = []; expect(() => normalizeTargetWorkflowIntent(f.intent, f.scope(), f.selection)).toThrow(); });
  it('rejects delete without typed original target address or health with a body', async () => { const f = fixture('delete'); await expect(f.client.prepare(f.selection)).rejects.toThrow(); const h = fixture('health'); await expect(h.client.prepare(h.selection, { weight: 0 })).rejects.toThrow(); expect(f.key).not.toHaveBeenCalled(); expect(h.key).not.toHaveBeenCalled(); });
  it.each(['HEALTHY', 'UNHEALTHY'])('enables health entry only from actual %s row with exact UUID, address and parent', state => {
    const f = fixture('health'), health = { ...f.row, health: state };
    expect(targetManualHealthAvailable([health], f.row, f.scope().upstreamId)).toBe(true);
    expect(targetManualHealthAvailable([{ ...health, id: randomUUID() }], f.row, f.scope().upstreamId)).toBe(false);
    expect(targetManualHealthAvailable([{ ...health, upstream: { id: randomUUID() } }], f.row, f.scope().upstreamId)).toBe(false);
    expect(targetManualHealthAvailable([{ ...health, weight: 0 }], f.row, f.scope().upstreamId)).toBe(false);
    expect(targetManualHealthAvailable([health, health], f.row, f.scope().upstreamId)).toBe(false);
  });
  it.each(['HEALTHCHECKS_OFF', 'DNS_ERROR', 'UNDEFINED', '', 'OFF'])('does not infer manual health availability from %s', state => { const f = fixture('health'); expect(targetManualHealthAvailable([{ ...f.row, health: state }], f.row, f.scope().upstreamId)).toBe(false); });
});

describe('Target original-key and current-session workflow state machine', () => {
  it('submits only the fresh immutable preview, re-reads its linked workflow and clears the local fence', async () => {
    const f = fixture(), prepared = await f.prepare(); await expect(f.client.submit(f.attempt()!, prepared)).resolves.toBe(f.workflowId);
    expect(f.posts()).toHaveLength(2); expect(f.posts()[1][2]).toBe(true); expect(JSON.parse(f.posts()[1][1]!.body as string)).toEqual({ revision: 1, materialHmac: 'a'.repeat(64), confirmed: true, confirm_name: 'native-change' }); expect(f.attempt()).toBeUndefined();
  });
  it.each([0, 401, 403, 503])('does not replay a %s request or create another key after failure', async status => {
    const f = fixture(); f.state.postError = new ApiError('private-server-value', status, status === 0 || status >= 500 ? 'UNKNOWN' : 'DENIED');
    await expect(f.prepare()).rejects.toThrow(); await expect(f.prepare()).rejects.toThrow(); expect(f.posts()).toHaveLength(1); expect(f.posts()[0][2]).toBe(true); expect(f.key).toHaveBeenCalledOnce(); expect([...f.values.values()].join()).not.toContain('private-server-value');
  });
  it('recovers a lost prepare by its original read-only key', async () => { const f = fixture('weight'); f.state.postError = new Error('controlled packet loss'); await expect(f.prepare()).rejects.toThrow(); const original = f.attempt()!; f.state.postError = null;
    await expect(f.client.recover(original)).resolves.toMatchObject({ intent: { id: f.intentId } }); expect(f.transport.mock.calls.at(-1)![0]).toBe(`/clusters/${f.scope().cid}/entity-changes/by-prepare-key/${original.key}?workspaceId=${f.scope().wid}`); expect(f.posts()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce(); });
  it('keeps not_prepared/not_observed as unknown and cannot discard or repost it', async () => { const f = fixture(); f.state.postError = new Error('controlled loss'); await expect(f.prepare()).rejects.toThrow(); const original = f.attempt()!; f.state.notPrepared = true;
    await expect(f.client.recover(original)).resolves.toEqual({ notObserved: true }); await expect(f.client.discardPrepared(original)).rejects.toThrow(); await expect(f.prepare()).rejects.toThrow(); expect(f.attempt()?.key).toBe(original.key); expect(f.posts()).toHaveLength(1); });
  it('recovers unknown submit only through the actual receipts/by-key endpoint plus matching intent', async () => {
    const f = fixture('delete'), prepared = await f.prepare(); f.state.submitUnknown = true; await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); const original = f.attempt()!;
    await expect(f.client.recover(original)).resolves.toMatchObject({ workflowId: f.workflowId });
    expect(f.transport.mock.calls.some(call => call[0] === `/clusters/${f.scope().cid}/workflows/receipts/by-key/${original.key}?workspaceId=${f.scope().wid}`)).toBe(true); expect(f.posts()).toHaveLength(2); expect(f.attempt()).toBeUndefined();
  });
  it.each(['wrong-key', 'wrong-workflow', 'wrong-workspace', 'incomplete'])('keeps unknown submit on %s recovery proof', async reason => { const f = fixture(), prepared = await f.prepare(); f.state.submitUnknown = true;
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); const original = f.attempt()!; f.state.receiptPatch = reason === 'wrong-key' ? { idempotencyKey: randomUUID() } : reason === 'wrong-workflow' ? { workflowId: randomUUID() } : reason === 'wrong-workspace' ? { workspaceId: randomUUID() } : { submissionCompleted: false };
    await expect(f.client.recover(original)).rejects.toThrow(); expect(f.attempt()?.key).toBe(original.key); expect(f.posts()).toHaveLength(2); });
  it.each(['expired', 'denied', 'revision', 'material', 'session'])('does not submit a %s prepared intent', async reason => { const f = fixture(), prepared = await f.prepare();
    if (reason === 'expired') f.intent.expiresAt = new Date(Date.now() - 1).toISOString(); if (reason === 'denied') f.intent.capabilities.submit = false;
    if (reason === 'revision') f.intent.revision++; if (reason === 'material') f.intent.materialHmac = 'b'.repeat(64); if (reason === 'session') f.state.csrf = 'another-genuine-current-session';
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); expect(f.posts()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce(); });
  it.each(['actor', 'version', 'cid', 'wid', 'mode', 'upstreamId'])('retains original unknown without adopting %s changed during POST', async field => { const f = fixture(); f.state.afterPost = () => f.changeScope({ [field]: field === 'mode' ? 'direct' : field === 'version' ? 'changed' : randomUUID() });
    await expect(f.prepare()).rejects.toThrow(); expect(readTargetWorkflowAttempt(f.originalScope, f.storage)?.state).toBe('unknown'); expect(f.posts()).toHaveLength(1); });
  it('denies readonly current actor before session I/O or key allocation', async () => { const f = fixture(); f.state.writable = false; await expect(f.prepare()).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled(); expect(f.key).not.toHaveBeenCalled(); });
  it('allows original-key observation under changed current permissions without reviving its old submit authority', async () => { const f = fixture(); f.state.postError = new Error('controlled response loss'); await expect(f.prepare()).rejects.toThrow();
    f.changeScope({ version: 'new-current-version' }); f.state.writable = false; f.state.postError = null; const result = await f.client.recover(f.attempt()!);
    expect(result.intent?.id).toBe(f.intentId); expect(f.attempt()?.version).toBe(f.originalScope.version);
    await expect(f.client.submit(f.attempt()!, result.intent!)).rejects.toThrow(); expect(f.posts()).toHaveLength(1); });
  it('does not clear or adopt a same-key record with a substituted Target selection', async () => { const f = fixture('weight'), prepared = await f.prepare(), original = f.attempt()!;
    f.storage.setItem(targetWorkflowStorageKey(f.scope()), JSON.stringify({ ...original, targetId: randomUUID() }));
    await expect(f.client.submit(original, prepared)).rejects.toThrow(); await expect(f.client.discardPrepared(original)).rejects.toThrow(); expect(f.posts()).toHaveLength(1); });
  it('cannot clear an original POST while it is still in flight', async () => { const f = fixture(); let release!: () => void; f.state.gate = new Promise<void>(resolve => { release = resolve; });
    const pending = f.prepare(); await vi.waitFor(() => expect(f.attempt()?.state).toBe('pending')); await expect(f.client.recover(f.attempt()!)).rejects.toThrow(); release(); await pending; expect(f.attempt()?.state).toBe('prepared'); });
  it('stores only original public IDs/enums/key/HMA, never target body, address, cookie, CSRF or secret', () => { const f = fixture(); storeTargetWorkflowAttempt({ ...f.scope(), ...f.selection, stage: 'prepare', state: 'unknown', key: randomUUID(), body: f.body, csrf: 'csrf-value', cookie: 'cookie-value', sessionId: randomUUID(), secret: 'private-value' } as any, f.storage);
    const raw = [...f.values.values()].join(); for (const forbidden of ['api.internal', 'body', 'csrf', 'cookie', 'sessionId', 'secret', 'private-value']) expect(raw).not.toContain(forbidden); });
  it('fails closed for damaged, incomplete or foreign original records', () => { const f = fixture(); f.storage.setItem(targetWorkflowStorageKey(f.scope()), '{damaged'); expect(f.attempt).toThrow();
    expect(() => storeTargetWorkflowAttempt({ ...f.scope(), ...f.selection, stage: 'prepare', state: 'prepared', key: randomUUID() }, f.storage)).toThrow(); });
});
