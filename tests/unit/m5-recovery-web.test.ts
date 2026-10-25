import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7';
const otherWid = '37c31bd6-a804-4b8b-a2f2-0b79b5d9857a';
const actorId = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', otherActor = '8d0fcfe8-f993-4d97-829f-e3e9b4cfb113';
const childOp = 'bc7bd065-9372-405d-9782-015d31a30aa1', settingsOp = '9d179d4a-0acb-43b3-adcd-a31533dcf239';
const key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22', rootId = '3a00a193-bf24-49d4-8d65-c8e15ecf6874';
const now = Date.parse('2026-10-10T12:00:00Z');
const setupPath = `/clusters/${cid}/vitals/setup?workspaceId=${wid}`;
const setup = { method: 'POST', body: JSON.stringify({ sourceId: rootId, mode: 'collector', confirmed: true, confirm_name: 'test-cluster' }) };
let client: typeof import('../../apps/console-web/src/api/client');
let recoveryHelpers: typeof import('../../apps/console-web/src/api/recovery');
let scopeHelpers: typeof import('../../apps/console-web/src/api/workspace-scope');
let events: ReturnType<typeof vi.fn>;
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const recovery = () => ({ kind: 'vitals-setup' as const, clusterId: cid, workspaceId: wid, idempotencyKey: key, operationId: childOp, state: 'uncertain' });
const completed = () => ({ clusterId: cid, workspaceId: wid, idempotencyKey: key, parentState: 'succeeded', steps: [
  { name: 'prometheus', id: childOp, state: 'succeeded', remoteCompleted: true },
  { name: 'settings', id: settingsOp, state: 'succeeded', remoteCompleted: true },
] });

beforeEach(async () => {
  vi.resetModules(); events = vi.fn(); vi.stubGlobal('window', { dispatchEvent: events });
  vi.stubGlobal('crypto', { randomUUID: () => key });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } });
  client = await import('../../apps/console-web/src/api/client');
  recoveryHelpers = await import('../../apps/console-web/src/api/recovery');
  scopeHelpers = await import('../../apps/console-web/src/api/workspace-scope');
  client.setApiActorId(actorId); client.setCsrfToken('test-csrf');
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('M5 browser setup recovery uses the original parent receipt and never infers completion', () => {
  it('classifies a lost setup response under its original account/scope/key and retains only safe recovery identifiers', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('controlled lost response')); vi.stubGlobal('fetch', fetch);
    const error = await client.api(setupPath, setup).catch(value => value);
    expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'vitals-setup', clusterId: cid,
      workspaceId: wid, idempotencyKey: key, state: 'uncertain' } });
    // There is no child ID when no response was delivered.
    expect(error.recovery.operationId).toBeUndefined(); expect(events).toHaveBeenCalledOnce();
    expect(events.mock.calls[0][0].detail.actorId).toBe(actorId);
    expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);
    const stored = scopeHelpers.safeRecoveryReferences([{ actor_id: actorId, cid, wid, kind: error.recovery.kind,
      idempotencyKey: key, created_at: new Date(now).toISOString(), state: error.recovery.state,
      body: { secret: 'DO-NOT-PERSIST' }, url: 'http://kong:8001/plugins', token: 'DO-NOT-PERSIST' }], actorId, now);
    expect(stored).toEqual([{ actor_id: actorId, cid, wid, kind: 'vitals-setup', idempotencyKey: key,
      created_at: new Date(now).toISOString(), state: 'uncertain' }]);
    expect(JSON.stringify(stored)).not.toContain('DO-NOT-PERSIST'); expect(JSON.stringify(stored)).not.toContain('8001');
  });

  it.each(['partial', 'uncertain'] as const)('retains a known %s setup response for its parent receipt rather than treating a child operation as completion', async state => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: { code: 'METRICS_SETUP_PROGRESS_UNCONFIRMED', message: 'read original receipt', operationId: childOp, state } }, 503)));
    const error = await client.api(setupPath, setup).catch(value => value);
    expect(error).toMatchObject({ recovery: { ...recovery(), state } }); expect(events).toHaveBeenCalledOnce();
    expect(recoveryHelpers.vitalsSetupReceiptPath(error.recovery)).toBe(`/clusters/${cid}/vitals/setup/receipts/by-key/${key}?workspaceId=${wid}`);
    expect(recoveryHelpers.vitalsSetupReceiptPath(error.recovery)).not.toContain(childOp);
  });

  it('preserves the initiating account when a late setup error arrives after another account signs in', async () => {
    let reject!: (reason: Error) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise((_resolve, fail) => { reject = fail; })));
    const pending = client.api(setupPath, setup).catch(value => value); client.setApiActorId(otherActor); reject(new Error('controlled disconnect'));
    const error = await pending; expect(error.recovery.kind).toBe('vitals-setup');
    expect(events.mock.calls[0][0].detail.actorId).toBe(actorId);
    expect(scopeHelpers.safeRecoveryReferences([{ actor_id: actorId, cid, wid, kind: 'vitals-setup', idempotencyKey: key,
      created_at: new Date(now).toISOString(), state: 'uncertain' }], otherActor, now)).toEqual([]);
  });

  it('classifies only exact POST operation reconciliation as interrupted review without creating an unknown-write reference', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('controlled disconnect')));
    const path = `/clusters/${cid}/mutations/${childOp}/reconcile?workspaceId=${wid}`;
    const error = await client.api(path, { method: 'POST', body: JSON.stringify({ confirmed: true, confirm_name: 'orders' }) }).catch(value => value);
    expect(error).toMatchObject({ code: 'NETWORK_REVIEW_INTERRUPTED' }); expect(error.recovery).toBeUndefined(); expect(events).not.toHaveBeenCalled();
    for (const [url, method] of [[path, 'PATCH'], [path.replace('/reconcile?', '/reconcile/extra?'), 'POST']]) {
      const unsafe = await client.api(url, { method, body: '{}' }).catch(value => value);
      expect(unsafe.code).toBe('WRITE_RESULT_UNKNOWN'); expect(unsafe.recovery.kind).toBeUndefined();
    }
    expect(events).toHaveBeenCalledTimes(2);
  });

  it('requires an explicit original setup anchor and refuses IAM, generic or malformed recovery routing', () => {
    expect(recoveryHelpers.vitalsSetupReceiptPath(recovery())).toBe(`/clusters/${cid}/vitals/setup/receipts/by-key/${key}?workspaceId=${wid}`);
    for (const bad of [{ ...recovery(), workspaceId: undefined }, { ...recovery(), idempotencyKey: '../../plugins' },
      { ...recovery(), domain: 'iam' as const }, { ...recovery(), kind: undefined }]) {
      expect(() => recoveryHelpers.vitalsSetupReceiptPath(bad)).toThrow();
    }
    const rows = [{ actor_id: actorId, cid, wid, kind: 'vitals-setup', idempotencyKey: key, created_at: new Date(now).toISOString(), state: 'partial' }];
    expect(scopeHelpers.safeRecoveryReferences(rows, actorId, now)[0].kind).toBe('vitals-setup');
    expect(scopeHelpers.safeRecoveryReferences([{ ...rows[0], domain: 'iam' }, { ...rows[0], kind: 'arbitrary-provider' }], actorId, now)).toEqual([]);
  });

  it('accepts completion only after the matching parent and every required step have durable successful acknowledgements', () => {
    const result = completed(); expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion(result, recovery())).toBe(true);
    const withCollector = { ...result, steps: [...result.steps, { name: 'http-log', id: rootId, state: 'succeeded', remoteCompleted: true }] };
    expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion(withCollector, recovery())).toBe(true);
    for (const parentState of ['not_sent', 'partial', 'uncertain', 'failed']) {
      expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion({ ...result, parentState }, recovery())).toBe(false);
    }
    for (const step of [{ ...result.steps[0], state: 'uncertain' }, { ...result.steps[0], remoteCompleted: false }, { ...result.steps[0], id: null }]) {
      expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion({ ...result, steps: [step, result.steps[1]] }, recovery())).toBe(false);
    }
    expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion({ ...result, steps: result.steps.slice(0, 1) }, recovery())).toBe(false);
    expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion({ ...result, steps: result.steps.slice(1) }, recovery())).toBe(false);
  });

  it('does not release a recovery from another original scope/key or from duplicated, invented or malformed steps', () => {
    const result = completed();
    for (const bad of [{ ...result, workspaceId: otherWid }, { ...result, clusterId: rootId }, { ...result, idempotencyKey: childOp },
      { ...result, steps: [result.steps[0], result.steps[0], result.steps[1]] },
      { ...result, steps: [...result.steps, { name: 'vault', id: rootId, state: 'succeeded', remoteCompleted: true }] },
      { ...result, steps: [null] }, { ...result, steps: 'succeeded' }]) {
      expect(recoveryHelpers.isVitalsSetupReceipt(bad, recovery())).toBe(false);
      expect(recoveryHelpers.vitalsSetupReceiptProvesCompletion(bad, recovery())).toBe(false);
    }
  });

  it('offers recycle reconciliation only for the same unknown root/action in its original cluster/workspace', () => {
    const entry = { id: rootId, root_type: 'services', original_id: rootId };
    const receipt = { id: childOp, cluster_id: cid, workspace_id: wid, entity_type: 'services', entity_id: rootId, action: 'delete', state: 'uncertain' };
    expect(recoveryHelpers.recycleReceiptMatchesEntry(receipt, entry, cid, wid)).toBe(true);
    expect(recoveryHelpers.recycleReceiptMatchesEntry({ ...receipt, action: 'restore' }, entry, cid, wid)).toBe(true);
    for (const patch of [{ workspace_id: otherWid }, { cluster_id: rootId }, { entity_id: childOp }, { entity_type: 'consumers' }, { action: 'update' }, { state: 'running' }, { state: 'succeeded' }, { id: 'untrusted' }]) {
      expect(recoveryHelpers.recycleReceiptMatchesEntry({ ...receipt, ...patch }, entry, cid, wid)).toBe(false);
    }
  });
});
