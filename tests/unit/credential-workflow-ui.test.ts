import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../apps/console-web/src/api/client';
import { credentialWorkflowKinds, credentialWorkflowScope, credentialWorkflowSelection, credentialWorkflowChange, credentialWorkflowFormDefaults, normalizeCredentialWorkflowIntent,
  readCredentialWorkflowAttempt, storeCredentialWorkflowAttempt, credentialWorkflowStorageKey, createCredentialWorkflowClient,
  type CredentialWorkflowScope, type CredentialWorkflowKind, type CredentialWorkflowSelection } from '../../apps/console-web/src/features/credential-workflow.model';

/** Source-only frontend state machine with controlled transport/storage.
 * No actual BFF/Kong HTTP, SQL, authentication or browser acceptance claimed. */
function fixture(kind: CredentialWorkflowKind = 'key-auth', action: 'create' | 'update' | 'delete' = 'create') {
  let scope: CredentialWorkflowScope = { actor: randomUUID(), cid: randomUUID(), wid: randomUUID(), version: 'actual-source-permission-version',
    mode: 'approval', consumerId: randomUUID(), credentialKind: kind };
  const cid = scope.cid!, wid = scope.wid!, actor = scope.actor!, nativeId = randomUUID(), intentId = randomUUID(), workflowId = randomUUID();
  const row = { id: nativeId, consumer: { id: scope.consumerId }, username: 'source-public-name', password: '[REDACTED]' };
  const selection = credentialWorkflowSelection(scope, action, action === 'create' ? undefined : row);
  const intent: any = { id: intentId, revision: 1, materialHmac: 'a'.repeat(64), executionMode: 'approval', issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(), nativeExecutionAvailable: false, capabilities: { submit: true }, workflowId: null,
    credentialSubject: { consumerId: scope.consumerId, credentialKind: kind, action, ...(action !== 'create' ? { credentialId: nativeId } : {}) },
    review: { clusterId: cid, workspaceId: wid, changes: [{ entityType: kind, nativeId, action, before: action === 'create' ? null : row,
      after: action === 'delete' ? null : { id: nativeId, key: 'source-secret-key', password: 'source-secret-password', client_secret: 'source-oauth-secret' } }],
      impact: { changedObjects: 1, nativePackets: 1, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: { state: 'baseline-required', blockerCodes: ['EXECUTION_BASELINE_REQUIRED'] } } };
  const values = new Map<string, string>(), storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); }, removeItem: (key: string) => { values.delete(key); } };
  const state: any = { writable: true, active: true, preparedMissing: false, postFailure: null, receiptFailure: false, malformed: false, afterPost: undefined, submitUnknown: false };
  const keys: string[] = [], key = vi.fn(() => { const next = randomUUID(); keys.push(next); return next; });
  const transport = vi.fn(async (path: string, options: RequestInit = {}, retried = false) => {
    const method = options.method ?? 'GET';
    if (method === 'POST') {
      if (state.postFailure) throw state.postFailure;
      if (path.includes('/prepare?')) { state.afterPost?.(); return state.malformed ? {} : structuredClone(intent); }
      if (path.includes('/submit?')) { intent.workflowId = workflowId; state.afterPost?.(); if (state.submitUnknown) throw new ApiError('secret-value-must-not-persist', 503, 'UNKNOWN');
        return { workflowId, submissionCompleted: true, nativeExecutionAvailable: false }; }
      throw new Error('UNEXPECTED_SOURCE_WRITE');
    }
    if (path.includes('/by-prepare-key/')) return state.preparedMissing ? { state: 'not_prepared', clusterId: cid, workspaceId: wid, idempotencyKey: keys[0],
      intentId: null, nativeExecutionAvailable: false, retryWriteAllowed: false, originalOutcome: 'not_observed' } : structuredClone(intent);
    if (path === `/clusters/${cid}/workflows/receipts/by-key/${keys.at(-1)}?workspaceId=${wid}`) {
      if (state.receiptFailure) throw new ApiError('not-found', 404, 'WORKFLOW_RECEIPT_NOT_FOUND');
      return { id: workflowId, workflowId, clusterId: cid, workspaceId: wid, idempotencyKey: keys.at(-1), action: 'submit', state: 'pending',
        approvalRequired: true, submissionCompleted: true, steps: [] };
    }
    if (path.includes('/entity-changes/' + intentId + '?')) return structuredClone(intent);
    throw new Error('UNEXPECTED_SOURCE_READ');
  });
  const client = createCredentialWorkflowClient({ scope: () => scope, storage, key, transport: transport as any,
    assertCurrent(captured, writing) { if (!state.active || captured.actor !== scope.actor || writing && !state.writable) throw new ApiError('current authority denied', 403, 'CURRENT_SCOPE_DENIED'); } });
  const prepare = () => client.prepare(selection, action === 'delete' ? undefined : { username: 'source-public-name', password: 'source-secret-input' }, action === 'delete' ? row.username : undefined);
  return { client, transport, storage, values, state, key, keys, intent, selection, row, nativeId, intentId, workflowId, cid, wid, actor, prepare,
    scope: () => scope, changeScope: (patch: Partial<CredentialWorkflowScope>) => { scope = { ...scope, ...patch }; },
    attempt: () => readCredentialWorkflowAttempt(scope, storage) };
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T19:00:00Z')); });
afterEach(() => { vi.useRealTimers(); });

describe('independent Consumer credential approval UI model', () => {
  it.each(credentialWorkflowKinds)('can edit %s with server workspace tags while retaining business tags and refusing explicit scope reassignment', kind => {
    const f = fixture(kind, 'update'), original = { tags: ['workspace:payments', 'kos-ws-payments', 'owner:pay', 'team:pay'], username: 'business-user' };
    const defaults = credentialWorkflowFormDefaults(original);
    expect(defaults.tags).toEqual(['owner:pay', 'team:pay']);
    expect(credentialWorkflowChange(f.scope(), f.selection, defaults)).toMatchObject({ body: { tags: ['owner:pay', 'team:pay'], username: 'business-user' } });
    expect(() => credentialWorkflowChange(f.scope(), f.selection, original)).toThrow();
    expect(original.tags).toEqual(['workspace:payments', 'kos-ws-payments', 'owner:pay', 'team:pay']);
  });
  it.each(credentialWorkflowKinds)('prepares %s with a fixed Consumer tuple and one-shot metadata POST', async kind => {
    const f = fixture(kind), intent = await f.prepare(), call = f.transport.mock.calls[0];
    expect(call[0]).toBe('/clusters/' + f.cid + '/entity-changes/prepare?workspaceId=' + f.wid);
    expect(call[2]).toBe(true); expect(JSON.parse(call[1]!.body as string)).toEqual({ change: { kind: 'credential', action: 'create',
      consumerId: f.scope().consumerId, credentialKind: kind, body: { username: 'source-public-name', password: 'source-secret-input' } } });
    expect(new Headers(call[1]!.headers).get('X-Idempotency-Key')).toBe(f.keys[0]);
    expect(intent.nativeExecutionAvailable).toBe(false); expect(JSON.stringify(intent.review)).not.toContain('source-secret');
    expect(JSON.stringify([...f.values.values()])).not.toContain('source-secret'); expect(f.attempt()?.state).toBe('prepared');
  });
  it.each(credentialWorkflowKinds)('prepares %s update against the actual current row and parent', async kind => {
    const f = fixture(kind, 'update'); await f.prepare();
    expect(JSON.parse(f.transport.mock.calls[0][1]!.body as string).change).toMatchObject({ kind: 'credential', action: 'update', consumerId: f.scope().consumerId,
      credentialKind: kind, credentialId: f.nativeId });
  });
  it.each(credentialWorkflowKinds)('uses typed credential recycle for %s deletion', async kind => {
    const f = fixture(kind, 'delete'); await f.prepare();
    expect(JSON.parse(f.transport.mock.calls[0][1]!.body as string).change).toEqual({ kind: 'recycle', action: 'delete', entityType: 'credentials',
      entityId: f.nativeId, parentId: f.scope().consumerId, credentialKind: kind, confirmed: true, confirm_name: f.row.username });
    expect(f.transport.mock.calls.every(call => call[1]?.method !== 'DELETE')).toBe(true);
  });
  it('requires delete confirmation and refuses a copied foreign Consumer row', () => {
    const f = fixture('basic-auth', 'delete');
    expect(() => credentialWorkflowChange(f.scope(), f.selection)).toThrow();
    expect(() => credentialWorkflowSelection(f.scope(), 'delete', { ...f.row, consumer: { id: randomUUID() } })).toThrow();
    expect(() => credentialWorkflowSelection(f.scope(), 'update', { id: f.nativeId })).toThrow();
  });
  it.each(['ldap-auth', 'vaults', 'keys', 'targets', 'session'])('closes unsupported credential kind %s', kind => {
    const f = fixture(); expect(() => credentialWorkflowScope({ ...f.scope(), credentialKind: kind as any })).toThrow();
  });
  it.each(['id', 'consumer', 'consumer_id', 'created_at', 'ttl', 'constructor'])('refuses body-controlled field %s', field => {
    const f = fixture(); expect(() => credentialWorkflowChange(f.scope(), f.selection, { [field]: f.nativeId })).toThrow();
  });
  it('refuses masked secrets and reserved workspace tags without posting', async () => {
    const f = fixture(); await expect(f.client.prepare(f.selection, { key: '[REDACTED:abc]' })).rejects.toThrow();
    await expect(f.client.prepare(f.selection, { tags: ['workspace:other'] })).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled(); expect(f.key).not.toHaveBeenCalled();
  });
  it.each(['parent', 'kind', 'action', 'credential-id', 'cluster', 'workspace', 'native-capability', 'foreign-change', 'extra-object'])('refuses %s substitution in a prepared receipt', cause => {
    const f = fixture('jwt', 'update'), raw = structuredClone(f.intent);
    if (cause === 'parent') raw.credentialSubject.consumerId = randomUUID();
    if (cause === 'kind') raw.credentialSubject.credentialKind = 'key-auth';
    if (cause === 'action') raw.credentialSubject.action = 'delete';
    if (cause === 'credential-id') raw.credentialSubject.credentialId = randomUUID();
    if (cause === 'cluster') raw.review.clusterId = randomUUID();
    if (cause === 'workspace') raw.review.workspaceId = randomUUID();
    if (cause === 'native-capability') raw.nativeExecutionAvailable = true;
    if (cause === 'foreign-change') raw.review.changes[0].entityType = 'consumers';
    if (cause === 'extra-object') raw.review.changes.push(raw.review.changes[0]);
    expect(() => normalizeCredentialWorkflowIntent(raw, f.scope(), f.selection)).toThrow();
  });
  it('submits a freshly re-read immutable preview, then verifies its linked workflow before clearing', async () => {
    const f = fixture(), prepared = await f.prepare(), attempt = f.attempt()!;
    await expect(f.client.submit(attempt, prepared)).resolves.toBe(f.workflowId);
    const posts = f.transport.mock.calls.filter(call => call[1]?.method === 'POST'); expect(posts).toHaveLength(2);
    expect(posts[1][2]).toBe(true); expect(JSON.parse(posts[1][1]!.body as string)).toEqual({ revision: 1, materialHmac: 'a'.repeat(64), confirmed: true, confirm_name: 'native-change' });
    expect(f.attempt()).toBeUndefined(); expect(f.transport.mock.calls.filter(call => !call[1]?.method)).toHaveLength(2);
  });
  it.each(['revision', 'hash', 'expired', 'denied', 'already-submitted'])('does not submit a %s preview', async reason => {
    const f = fixture(), prepared = await f.prepare(), attempt = f.attempt()!;
    if (reason === 'revision') f.intent.revision++;
    if (reason === 'hash') f.intent.materialHmac = 'b'.repeat(64);
    if (reason === 'expired') f.intent.expiresAt = new Date(Date.now() - 1).toISOString();
    if (reason === 'denied') f.intent.capabilities.submit = false;
    if (reason === 'already-submitted') f.intent.workflowId = f.workflowId;
    await expect(f.client.submit(attempt, prepared)).rejects.toThrow();
    expect(f.transport.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1); expect(f.key).toHaveBeenCalledOnce();
  });
  it.each([401, 403, 503, 0])('does not replay a %s POST or mint another key after failure', async status => {
    const f = fixture(); f.state.postFailure = new ApiError('private-secret-server-error', status, status >= 500 || status === 0 ? 'UNKNOWN' : 'DENIED');
    await expect(f.prepare()).rejects.toThrow(); const attempt = f.attempt()!;
    expect(attempt.key).toBe(f.keys[0]); await expect(f.prepare()).rejects.toThrow();
    expect(f.transport).toHaveBeenCalledOnce(); expect(f.transport.mock.calls[0][2]).toBe(true); expect(f.key).toHaveBeenCalledOnce();
    expect(JSON.stringify([...f.values.values()])).not.toContain('private-secret');
  });
  it('retains an unknown original prepare key and only GETs that key during recovery', async () => {
    const f = fixture(); f.state.postFailure = new Error('controlled network loss'); await expect(f.prepare()).rejects.toThrow();
    const attempt = f.attempt()!; f.state.postFailure = null;
    const result = await f.client.recover(attempt); expect(result.intent?.id).toBe(f.intentId); expect(f.attempt()?.state).toBe('prepared');
    expect(f.transport.mock.calls[1][0]).toBe('/clusters/' + f.cid + '/entity-changes/by-prepare-key/' + attempt.key + '?workspaceId=' + f.wid);
    expect(f.transport.mock.calls[1][1]?.method).toBeUndefined(); expect(f.key).toHaveBeenCalledOnce();
  });
  it('does not clear or repost on not_prepared / not_observed', async () => {
    const f = fixture(); f.state.postFailure = new Error('controlled network loss'); await expect(f.prepare()).rejects.toThrow();
    const attempt = f.attempt()!; f.state.preparedMissing = true;
    await expect(f.client.recover(attempt)).resolves.toEqual({ notPrepared: true }); expect(f.attempt()?.key).toBe(attempt.key);
    await expect(f.prepare()).rejects.toThrow(); expect(f.key).toHaveBeenCalledOnce();
  });
  it('does not treat a generic 404 as unsubmitted or allow clearing an unknown fence', async () => {
    const f = fixture(); f.state.submitUnknown = true; const prepared = await f.prepare();
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); const original = f.attempt()!; f.state.receiptFailure = true;
    await expect(f.client.recover(original)).rejects.toMatchObject({ status: 404 });
    await expect(f.client.discardPrepared(original)).rejects.toThrow(); expect(f.attempt()?.key).toBe(original.key);
  });
  it('recovers unknown submit from original-key receipt plus matching current intent without a POST', async () => {
    const f = fixture(); f.state.submitUnknown = true; const prepared = await f.prepare();
    await expect(f.client.submit(f.attempt()!, prepared)).rejects.toThrow(); const attempt = f.attempt()!, posts = f.transport.mock.calls.filter(call => call[1]?.method === 'POST').length;
    await expect(f.client.recover(attempt)).resolves.toMatchObject({ workflowId: f.workflowId });
    expect(f.transport.mock.calls).toEqual(expect.arrayContaining([[`/clusters/${f.cid}/workflows/receipts/by-key/${attempt.key}?workspaceId=${f.wid}`]]));
    expect(f.transport.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(posts); expect(f.attempt()).toBeUndefined();
  });
  it.each(['actor', 'cid', 'wid', 'consumerId', 'credentialKind', 'version', 'mode'])('preserves original fence if %s changes during prepare', async field => {
    const f = fixture(), originalScope = f.scope(); f.state.afterPost = () => f.changeScope({ [field]: field === 'credentialKind' ? 'jwt' : field === 'version' ? 'changed' : field === 'mode' ? 'direct' : randomUUID() });
    await expect(f.prepare()).rejects.toThrow();
    expect(readCredentialWorkflowAttempt(originalScope, f.storage)?.state).toBe('unknown'); expect(f.transport).toHaveBeenCalledOnce();
  });
  it('blocks an actual readonly/denied user before allocating any request key', async () => {
    const f = fixture(); f.state.writable = false; await expect(f.prepare()).rejects.toThrow();
    expect(f.key).not.toHaveBeenCalled(); expect(f.transport).not.toHaveBeenCalled();
  });
  it('only discards a known unsubmitted current preview after a fresh GET', async () => {
    const f = fixture(); await f.prepare(); const attempt = f.attempt()!;
    await f.client.discardPrepared(attempt); expect(f.attempt()).toBeUndefined(); expect(f.transport.mock.calls.at(-1)![1]?.method).toBeUndefined();
    const g = fixture(); await g.prepare(); g.intent.workflowId = g.workflowId;
    await expect(g.client.discardPrepared(g.attempt()!)).rejects.toThrow(); expect(g.attempt()?.state).toBe('prepared');
  });
  it('stores only the allowlisted public reference, never extra body/review/key/password fields', () => {
    const f = fixture(); storeCredentialWorkflowAttempt({ ...f.scope(), ...f.selection, stage: 'prepare', state: 'unknown', key: randomUUID(),
      body: { password: 'source-secret' }, review: f.intent.review, apiKey: 'source-secret' } as any, f.storage);
    const stored = [...f.values.values()][0]; expect(stored).not.toContain('source-secret'); expect(stored).not.toContain('review');
    expect(stored).not.toContain('password'); expect(stored).not.toContain('apiKey');
  });
  it('fails closed on corrupt or incomplete prepared tab records', () => {
    const f = fixture(); f.storage.setItem(credentialWorkflowStorageKey(f.scope()), 'broken'); expect(() => f.attempt()).toThrow();
    expect(() => storeCredentialWorkflowAttempt({ ...f.scope(), ...f.selection, stage: 'prepare', state: 'prepared', key: randomUUID() }, f.storage)).toThrow();
  });
});
