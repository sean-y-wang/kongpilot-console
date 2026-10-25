import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../apps/console-web/src/api/client';
import { annotationEntityTypes, annotationWorkflowRequest, annotationWorkflowScope, annotationWorkflowStorageKey,
  createAnnotationWorkflowClient, normalizeAnnotationWorkflowIntent, readAnnotationWorkflowAttempt, storeAnnotationWorkflowAttempt,
  type AnnotationOperation, type AnnotationWorkflowScope } from '../../apps/console-web/src/features/entity-annotation-workflow.model';

/** Source-only state-machine checks with explicit controlled BFF observations.
 * They do not claim actual authentication, SQL, native requests or browser E2E. */
function fixture(operation: AnnotationOperation = 'set', type = 'services', beforeRevision = operation === 'set' ? 0 : 3) {
  let scope: AnnotationWorkflowScope = { actor: randomUUID(), version: 'current-source-permission-version', cid: randomUUID(), wid: randomUUID(),
    mode: 'approval', entityType: type, entityId: randomUUID() };
  const intentId = randomUUID(), workflowId = randomUUID(), originalScope = { ...scope }, selection = { operation, annotationRevision: beforeRevision };
  const input = operation === 'set' ? { revision: beforeRevision, description: 'reviewed business description', owner_user_id: null,
    metadata: { owner: 'payments', api_key: 'must-never-be-displayed' } } : { revision: beforeRevision, confirmed: true, confirm_name: 'business-service' };
  const intent: any = { intentId, clusterId: scope.cid, workspaceId: scope.wid, entityType: type, entityId: scope.entityId, operation,
    state: 'prepared', revision: null, annotationRevision: beforeRevision, materialHmac: 'a'.repeat(64), workflowId: null, planHash: null,
    expiresAt: new Date(Date.now() + 3600000).toISOString(), nativeRequestsSent: 0, nativeExecutionAvailable: false, capabilities: { submit: true },
    preview: { request: { nativeSecret: 'not-a-public-preview-property' },
      before: beforeRevision === 0 ? null : { cluster_id: scope.cid, entity_type: type, kong_id: scope.entityId, description: 'before',
        owner_user_id: null, metadata: { password: 'must-never-be-displayed' }, revision: beforeRevision, status: operation === 'restore' ? 'deleted' : 'active',
        nativeSecret: 'not-a-public-preview-property' },
      after: { entityType: type, entityId: scope.entityId, operation, input: { ...input, sealed: 'not-a-public-preview-property' } },
      affectedScopes: [{ clusterId: scope.cid, workspaceId: scope.wid, clusterRevision: 2, workspaceRevision: 3 }],
      confirmationName: 'business-service', retentionDays: operation === 'remove' ? 30 : null } };
  const values = new Map<string, string>(), storage = { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); }, removeItem: (key: string) => { values.delete(key); } };
  const state: any = { writable: true, active: true, csrf: 'controlled-current-csrf-token', postError: null, submitUnknown: false,
    afterPost: undefined, missing: false, authError: null, authVersion: undefined, receiptPatch: undefined, afterSession: undefined, afterIntent: undefined,
    gate: undefined };
  const keys: string[] = [], key = vi.fn(() => { const next = randomUUID(); keys.push(next); return next; });
  const transport = vi.fn(async (path: string, options: RequestInit = {}, retried = false) => {
    const method = options.method ?? 'GET';
    if (path === '/auth/me') {
      if (state.authError) throw state.authError;
      state.afterSession?.(); return { user: { id: scope.actor, permissionsVersion: state.authVersion ?? scope.version }, csrfToken: state.csrf };
    }
    if (method === 'POST') {
      if (state.gate) await state.gate;
      if (state.postError) throw state.postError;
      if (path.includes('/prepare?')) { state.afterPost?.(); return structuredClone(intent); }
      if (path.includes('/submit?')) {
        Object.assign(intent, { state: 'pending', workflowId, revision: 1, planHash: 'b'.repeat(64), capabilities: { submit: false } });
        state.afterPost?.(); if (state.submitUnknown) throw new ApiError('private-server-value', 503, 'RESULT_UNKNOWN'); return structuredClone(intent);
      }
      throw new Error('UNEXPECTED_SOURCE_WRITE');
    }
    if (path.includes('/annotation-changes/by-key/')) {
      if (state.missing) throw new ApiError('not found', 404, 'ANNOTATION_CHANGE_INTENT_NOT_FOUND'); return structuredClone(intent);
    }
    if (path.includes('/annotation-changes/' + intentId + '?')) { state.afterIntent?.(); return structuredClone(intent); }
    if (path.includes('/workflows/receipts/')) return { id: workflowId, workflowId, clusterId: scope.cid, workspaceId: scope.wid, idempotencyKey: keys.at(-1),
      action: 'submit', state: 'pending', approvalRequired: true, submissionCompleted: true, steps: [], ...state.receiptPatch };
    throw new Error('UNEXPECTED_SOURCE_READ');
  });
  const client = createAnnotationWorkflowClient({ scope: () => scope, storage, key, transport: transport as any,
    assertCurrent(captured, writing) { if (!state.active || captured.actor !== scope.actor || writing && !state.writable) throw new ApiError('current grant denied', 403, 'CURRENT_SCOPE_DENIED'); } });
  const prepare = () => client.prepare(selection, input, operation === 'set' ? undefined : 'business-service');
  const attempt = () => readAnnotationWorkflowAttempt(scope, storage);
  const postCalls = () => transport.mock.calls.filter(call => call[1]?.method === 'POST');
  return { client, transport, storage, values, state, key, keys, intent, intentId, workflowId, input, selection, prepare, attempt, postCalls,
    scope: () => scope, originalScope, changeScope: (patch: Partial<AnnotationWorkflowScope>) => { scope = { ...scope, ...patch }; } };
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T02:00:00Z')); });
afterEach(() => { vi.useRealTimers(); });

describe('entity annotation workflow public review', () => {
  it.each(annotationEntityTypes)('prepares %s metadata against the original current tuple without a native write', async type => {
    const f = fixture('set', type), row = await f.prepare(), [path, options, retried] = f.postCalls()[0];
    expect(path).toBe(`/clusters/${f.scope().cid}/annotation-changes/prepare?workspaceId=${f.scope().wid}`);
    expect(retried).toBe(true); expect(options.method).toBe('POST');
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(f.state.csrf);
    expect(new Headers(options.headers).get('X-Idempotency-Key')).toBe(f.keys[0]);
    expect(JSON.parse(options.body as string)).toEqual({ entityType: type, entityId: f.scope().entityId, operation: 'set', input: f.input });
    expect(row.nativeRequestsSent).toBe(0); expect(row.nativeExecutionAvailable).toBe(false); expect(row.revision).toBeNull();
    expect(JSON.stringify(row.preview)).not.toContain('must-never-be-displayed'); expect(JSON.stringify(row)).not.toContain('not-a-public-preview-property');
    expect(f.attempt()?.state).toBe('prepared');
  });
  it.each(['remove', 'restore'] as const)('%s keeps the real typed confirmation and original annotation revision', async operation => {
    const f = fixture(operation); await f.prepare();
    expect(JSON.parse(f.postCalls()[0][1]!.body as string)).toEqual({ entityType: 'services', entityId: f.scope().entityId, operation,
      input: { revision: 3, confirmed: true, confirm_name: 'business-service' } });
    expect(f.postCalls()).toHaveLength(1); expect(f.transport.mock.calls.every(call => !['PUT', 'DELETE'].includes(call[1]?.method ?? 'GET'))).toBe(true);
  });
  it('does not turn omitted metadata into an empty replacement', () => {
    const f = fixture(); const raw = annotationWorkflowRequest(f.scope(), f.selection, { revision: 0, description: 'only description' });
    expect(raw.input).toEqual({ revision: 0, description: 'only description' }); expect(Object.hasOwn(raw.input, 'metadata')).toBe(false);
  });
  it.each(['targets', 'key-auth', 'vaults', '../services', 'services/x'])('closes unsupported entity %s', entityType => {
    const f = fixture(); expect(() => annotationWorkflowScope({ ...f.scope(), entityType })).toThrow();
  });
  it.each(['revision', 'missing-confirmation', 'wrong-name', 'zero-revision'])('rejects %s remove request before any session or key', async reason => {
    const f = fixture('remove'), input = { ...f.input } as any;
    if (reason === 'revision') input.revision++;
    if (reason === 'missing-confirmation') delete input.confirmed;
    if (reason === 'wrong-name') input.confirm_name = 'another-service';
    if (reason === 'zero-revision') input.revision = 0;
    await expect(f.client.prepare(f.selection, input, 'business-service')).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled(); expect(f.key).not.toHaveBeenCalled();
  });
  it.each(['retentionDays', 'workflowId', 'entityId', 'clusterId', 'confirmed', 'nativeRequests'])('refuses body-controlled %s in set', field => {
    const f = fixture(); expect(() => annotationWorkflowRequest(f.scope(), f.selection, { revision: 0, [field]: randomUUID() })).toThrow();
  });
  it('refuses invalid owners, redacted replacement metadata, deep JSON and prototype keys', () => {
    const f = fixture();
    for (const input of [{ revision: 0, owner_user_id: 'not-a-user' }, { revision: 0, metadata: { password: '[REDACTED]' } },
      { revision: 0, metadata: JSON.parse('{"constructor":{"danger":true}}') }, { revision: 0, metadata: { x: Infinity } },
      { revision: 0, metadata: Array.from({ length: 22 }).reduce(value => ({ x: value }), {} as any) }]) {
      expect(() => annotationWorkflowRequest(f.scope(), f.selection, input)).toThrow();
    }
  });
  it.each(['cid', 'wid', 'entityType', 'entityId', 'operation', 'annotationRevision', 'native', 'before', 'after', 'revision', 'planHash'])('refuses substituted %s receipt', reason => {
    const f = fixture('set', 'services', 3), raw = structuredClone(f.intent);
    if (reason === 'cid') raw.clusterId = randomUUID();
    if (reason === 'wid') raw.workspaceId = randomUUID();
    if (reason === 'entityType') raw.entityType = 'routes';
    if (reason === 'entityId') raw.entityId = randomUUID();
    if (reason === 'operation') raw.operation = 'remove';
    if (reason === 'annotationRevision') raw.annotationRevision++;
    if (reason === 'native') raw.nativeExecutionAvailable = true;
    if (reason === 'before') raw.preview.before.kong_id = randomUUID();
    if (reason === 'after') raw.preview.after.entityId = randomUUID();
    if (reason === 'revision') raw.revision = 1;
    if (reason === 'planHash') raw.planHash = 'b'.repeat(64);
    expect(() => normalizeAnnotationWorkflowIntent(raw, f.scope(), f.selection)).toThrow();
  });
});

describe('entity annotation workflow original-key transport and session fences', () => {
  it('submits only the freshly re-read exact preview and returns the actual linked pending workflow', async () => {
    const f = fixture(), prepared = await f.prepare();
    await expect(f.client.submit(f.attempt()!, prepared)).resolves.toBe(f.workflowId);
    expect(f.postCalls()).toHaveLength(2); expect(f.postCalls()[1][2]).toBe(true);
    expect(JSON.parse(f.postCalls()[1][1]!.body as string)).toEqual({ confirmed: true, materialHmac: 'a'.repeat(64) });
    expect(f.transport.mock.calls.filter(call => call[0] === '/auth/me')).toHaveLength(2);
    expect(f.attempt()).toBeUndefined();
  });
  it.each(['expired', 'hmac', 'revision', 'already-submitted', 'denied', 'session', 'permission'])('does not submit a %s preview', async reason => {
    const f = fixture(), prepared = await f.prepare();
    if (reason === 'expired') f.intent.expiresAt = new Date(Date.now() - 1).toISOString();
    if (reason === 'hmac') f.intent.materialHmac = 'b'.repeat(64);
    if (reason === 'revision') f.intent.annotationRevision++;
    if (reason === 'already-submitted') Object.assign(f.intent, { workflowId: f.workflowId, state: 'pending', revision: 1, planHash: 'b'.repeat(64) });
    if (reason === 'denied') f.intent.capabilities.submit = false;
    if (reason === 'session') f.state.csrf = 'another-genuine-session-csrf';
    if (reason === 'permission') f.state.authVersion = 'changed-current-permission-version';
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); expect(f.postCalls()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce();
  });
  it.each([0, 401, 403, 503])('retains original key after a %s error without POST replay or new key', async status => {
    const f = fixture(); f.state.postError = new ApiError('private-server-value', status, status === 0 || status >= 500 ? 'UNKNOWN' : 'DENIED');
    await expect(f.prepare()).rejects.toThrow(); await expect(f.prepare()).rejects.toThrow();
    expect(f.postCalls()).toHaveLength(1); expect(f.postCalls()[0][2]).toBe(true); expect(f.key).toHaveBeenCalledOnce();
    expect(f.attempt()?.key).toBe(f.keys[0]); expect(JSON.stringify([...f.values.values()])).not.toContain('private-server-value');
  });
  it('recovers a lost preparation response by GET of its original key only', async () => {
    const f = fixture(); f.state.postError = new Error('controlled packet loss'); await expect(f.prepare()).rejects.toThrow();
    const original = f.attempt()!; f.state.postError = null;
    await expect(f.client.recover(original)).resolves.toMatchObject({ intent: { intentId: f.intentId } });
    expect(f.transport.mock.calls.at(-1)![0]).toBe(`/clusters/${f.scope().cid}/annotation-changes/by-key/${original.key}?workspaceId=${f.scope().wid}`);
    expect(f.postCalls()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce(); expect(f.attempt()?.state).toBe('prepared');
  });
  it('keeps unknown preparation blocked on current 404 and cannot discard it', async () => {
    const f = fixture(); f.state.postError = new Error('controlled packet loss'); await expect(f.prepare()).rejects.toThrow();
    const original = f.attempt()!; f.state.missing = true;
    await expect(f.client.recover(original)).rejects.toMatchObject({ status: 404, code: 'ANNOTATION_CHANGE_INTENT_NOT_FOUND' });
    await expect(f.client.discardPrepared(original)).rejects.toThrow(); await expect(f.prepare()).rejects.toThrow();
    expect(f.attempt()?.key).toBe(original.key); expect(f.postCalls()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce();
  });
  it('closes unknown submit only from original submit-key receipt plus matching intent', async () => {
    const f = fixture(), prepared = await f.prepare(); f.state.submitUnknown = true;
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); const original = f.attempt()!;
    await expect(f.client.recover(original)).resolves.toMatchObject({ workflowId: f.workflowId });
    expect(f.transport.mock.calls.some(call => call[0] === `/clusters/${f.scope().cid}/workflows/receipts/by-key/${original.key}?workspaceId=${f.scope().wid}`)).toBe(true);
    expect(f.postCalls()).toHaveLength(2); expect(f.key).toHaveBeenCalledTimes(2); expect(f.attempt()).toBeUndefined();
  });
  it.each(['key', 'workflow', 'cid', 'wid', 'incomplete'])('retains unknown submit when %s proof does not match', async reason => {
    const f = fixture(), prepared = await f.prepare(); f.state.submitUnknown = true;
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); const original = f.attempt()!;
    f.state.receiptPatch = reason === 'key' ? { idempotencyKey: randomUUID() } : reason === 'workflow' ? { workflowId: randomUUID() }
      : reason === 'cid' ? { clusterId: randomUUID() } : reason === 'wid' ? { workspaceId: randomUUID() } : { submissionCompleted: false };
    await expect(f.client.recover(original)).rejects.toThrow(); expect(f.attempt()?.key).toBe(original.key); expect(f.postCalls()).toHaveLength(2);
  });
  it.each(['actor', 'version', 'cid', 'wid', 'mode', 'entityType', 'entityId'])('does not adopt %s changed during the original POST', async field => {
    const f = fixture(); f.state.afterPost = () => f.changeScope({ [field]: field === 'version' ? 'changed' : field === 'mode' ? 'direct' : field === 'entityType' ? 'routes' : randomUUID() });
    await expect(f.prepare()).rejects.toThrow(); expect(readAnnotationWorkflowAttempt(f.originalScope, f.storage)?.state).toBe('unknown');
    expect(f.postCalls()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce();
  });
  it('blocks a denied current actor before allocating a key or performing session I/O', async () => {
    const f = fixture(); f.state.writable = false; await expect(f.prepare()).rejects.toThrow(); expect(f.key).not.toHaveBeenCalled(); expect(f.transport).not.toHaveBeenCalled();
  });
  it('does not allocate a request key when the original authentication session is no longer current', async () => {
    const f = fixture(); f.state.authError = new ApiError('expired', 401, 'SESSION_EXPIRED');
    await expect(f.prepare()).rejects.toMatchObject({ status: 401 }); expect(f.key).not.toHaveBeenCalled(); expect(f.postCalls()).toHaveLength(0);
  });
  it('keeps an unparseable accepted prepare response as unknown rather than allowing a second POST', async () => {
    const f = fixture(); f.intent.materialHmac = 'bad-response';
    await expect(f.prepare()).rejects.toMatchObject({ code: 'ANNOTATION_WORKFLOW_RESULT_UNKNOWN' });
    expect(f.attempt()?.state).toBe('unknown'); await expect(f.prepare()).rejects.toThrow(); expect(f.postCalls()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce();
  });
  it('does not clear an unknown original when current server-side entity authorization rejects its GET', async () => {
    const f = fixture(); f.state.postError = new Error('controlled packet loss'); await expect(f.prepare()).rejects.toThrow();
    const original = f.attempt()!, base = f.transport.getMockImplementation()!;
    f.transport.mockImplementation(async (...args) => { if (args[0].includes('/annotation-changes/by-key/')) throw new ApiError('current entity denied', 403, 'PERMISSION_DENIED'); return base(...args); });
    await expect(f.client.recover(original)).rejects.toMatchObject({ status: 403 }); expect(f.attempt()?.key).toBe(original.key);
    expect(f.postCalls()).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce();
  });
  it('keeps original public reference after permission changes and allows GET observation without reviving old write permission', async () => {
    const f = fixture(); f.state.postError = new Error('controlled packet loss'); await expect(f.prepare()).rejects.toThrow();
    f.changeScope({ version: 'new-current-permission-version' }); f.state.postError = null; f.state.writable = false;
    await expect(f.client.recover(f.attempt()!)).resolves.toMatchObject({ intent: { intentId: f.intentId } });
    await expect(f.client.submit(f.attempt()!, normalizeAnnotationWorkflowIntent(f.intent, f.scope(), f.selection))).rejects.toThrow();
    expect(f.postCalls()).toHaveLength(1); expect(f.attempt()?.version).toBe(f.originalScope.version);
  });
  it('only discards an observed known unsubmitted preview after a fresh GET', async () => {
    const f = fixture(); await f.prepare(); await f.client.discardPrepared(f.attempt()!); expect(f.attempt()).toBeUndefined(); expect(f.postCalls()).toHaveLength(1);
    const g = fixture(); await g.prepare(); Object.assign(g.intent, { state: 'pending', workflowId: g.workflowId, revision: 1, planHash: 'b'.repeat(64) });
    await expect(g.client.discardPrepared(g.attempt()!)).rejects.toThrow(); expect(g.attempt()?.state).toBe('prepared');
  });
  it('cannot let read recovery clear an original in-flight POST', async () => {
    const f = fixture(); let release!: () => void;
    f.state.gate = new Promise<void>(resolve => { release = resolve; });
    const pending = f.prepare(); await vi.waitFor(() => expect(f.attempt()?.state).toBe('pending'));
    await expect(f.client.recover(f.attempt()!)).rejects.toThrow(); expect(f.postCalls()).toHaveLength(1);
    release(); await pending; expect(f.attempt()?.state).toBe('prepared');
  });
});

describe('entity annotation workflow public tab storage', () => {
  it('stores only tuple, original key, annotation CAS and sealed reference; no notes, CSRF, credentials, session or previews', () => {
    const f = fixture(); storeAnnotationWorkflowAttempt({ ...f.scope(), ...f.selection, key: randomUUID(), stage: 'prepare', state: 'unknown',
      input: f.input, preview: f.intent.preview, csrf: 'secret-csrf', sessionId: 'secret-session', cookie: 'secret-cookie', password: 'secret-password' } as any, f.storage);
    const raw = [...f.values.values()][0];
    for (const value of ['reviewed business description', 'must-never-be-displayed', 'csrf', 'sessionId', 'cookie', 'password', 'preview', 'input']) expect(raw).not.toContain(value);
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(['actor', 'version', 'cid', 'wid', 'mode', 'entityType', 'entityId', 'operation', 'annotationRevision', 'stage', 'state', 'key'].sort());
  });
  it('fails closed on corrupt, cross-entity and incomplete prepared records', () => {
    const f = fixture(); f.storage.setItem(annotationWorkflowStorageKey(f.scope()), 'damaged'); expect(f.attempt).toThrow();
    f.storage.setItem(annotationWorkflowStorageKey(f.scope()), JSON.stringify({ ...f.scope(), ...f.selection, entityId: randomUUID(), key: randomUUID(), stage: 'prepare', state: 'unknown' })); expect(f.attempt).toThrow();
    expect(() => storeAnnotationWorkflowAttempt({ ...f.scope(), ...f.selection, key: randomUUID(), stage: 'prepare', state: 'prepared' }, f.storage)).toThrow();
  });
});
