import { afterEach, describe, expect, it, vi } from 'vitest';
import { workflowMetadataReceiptPath, workflowMetadataRecoveryContextMatches, workflowMetadataRecoveryEligible, workflowMetadataRecoveryProvesCompletion, workflowMetadataRecoveryRequest } from '../../apps/console-web/src/api/workflow-recovery';
import type { Workflow, WorkflowReceipt } from '../../apps/console-web/src/features/portal.types';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7';
const actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22';
const workflowId = 'bc7bd065-9372-405d-9782-015d31a30aa1', executionId = '631dde84-fd98-47a0-aa35-45f458595231';
const ids = ['9303db34-99cb-4ce3-b6f2-67b74370e01e', 'fc5d7a72-dbec-43af-abcd-c65b0497641c', 'b4eaee06-9e7f-44fa-bfd4-cddc703c43dd', '27a847b3-e2e1-4e6b-8245-4e2f6cc99b08'];
const reference = { actorId: actor, clusterId: cid, workspaceId: wid, workflowId, idempotencyKey: key, permissionsVersion: 'actor:9' };
function view(): Workflow { return { id: workflowId, kind: 'portal-credential-issue', name: 'portal-credential-issue', clusterId: cid, workspaceId: wid, revision: 5, planRevision: 1, planHash: 'a'.repeat(64), state: 'uncertain', executionMode: 'direct', approvalRequired: true, createdAt: new Date(0).toISOString(), expiresAt: new Date(86400000).toISOString(), capabilities: { approve: false, reject: false, cancel: false, execute: false, reconcileMetadata: true } }; }
function receipt(): WorkflowReceipt { return { id: executionId, workflowId, executionId, clusterId: cid, workspaceId: wid, idempotencyKey: key, revision: 5, planHash: 'a'.repeat(64), state: 'uncertain', action: 'execute', metadataRecovery: { eligible: true, kind: 'portal-credential-issue', executionId, originalExecutionKeyRequired: true }, steps: ['consumers.create.1', 'credentials.create.2', 'credentials.create.3', 'portal.credential.activate'].map((name, index) => ({ id: ids[index], name, state: index === 3 ? 'uncertain' : 'succeeded', operationId: index === 3 ? null : ids[index], remoteStarted: true, remoteCompleted: index !== 3 })), propagation: 'pending' }; }
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('source-backed Console portal issuance metadata recovery gates', () => {
  it('requires both current backend capabilities and the actor-bound original execution receipt with three ACKs', () => {
    expect(workflowMetadataRecoveryEligible(receipt(), view(), reference)).toBe(true);
    const projection = view(); delete projection.capabilities.reconcileMetadata;
    expect(workflowMetadataRecoveryEligible(receipt(), projection, reference)).toBe(false);
    expect(workflowMetadataRecoveryEligible({ ...receipt(), metadataRecovery: undefined }, view(), reference)).toBe(false);
    expect(workflowMetadataRecoveryEligible({ ...receipt(), metadataRecovery: { ...receipt().metadataRecovery, eligible: false } }, view(), reference)).toBe(false);
  });
  it.each(['clusterId', 'workspaceId', 'workflowId', 'idempotencyKey'] as const)('denies a receipt for another %s', field => {
    expect(workflowMetadataRecoveryEligible({ ...receipt(), [field]: ids[3] }, view(), reference)).toBe(false);
  });
  it('rejects submission/approval keys, missing execution binding, stale revision/hash and other recovery kinds', () => {
    for (const patch of [{ action: 'submit' }, { action: 'approve' }, { executionId: null }, { id: ids[3] }, { revision: 4 }, { planHash: 'b'.repeat(64) }, { metadataRecovery: { ...receipt().metadataRecovery, kind: 'portal-credential-rotate' } }, { metadataRecovery: { ...receipt().metadataRecovery, executionId: ids[3] } }, { metadataRecovery: { ...receipt().metadataRecovery, originalExecutionKeyRequired: false } }]) {
      expect(workflowMetadataRecoveryEligible({ ...receipt(), ...patch }, view(), reference)).toBe(false);
    }
  });
  it('cannot use another workflow kind/name/state or an absent actor/permission epoch as authority', () => {
    for (const patch of [{ kind: 'portal-credential-rotate' }, { name: 'another-confirmation' }, { state: 'partial' }, { state: 'executing' }, { state: 'succeeded' }, { revision: 0 }, { revision: 2.5 }]) expect(workflowMetadataRecoveryEligible(receipt(), { ...view(), ...patch }, reference)).toBe(false);
    for (const patch of [{ actorId: '' }, { permissionsVersion: '' }, { clusterId: 'kong' }, { idempotencyKey: '' }, { idempotencyKey: '../execute' }]) expect(workflowMetadataRecoveryEligible(receipt(), view(), { ...reference, ...patch })).toBe(false);
  });
  it.each([0, 1, 2])('rejects missing native ACK, changed order or missing bound operation for step %s', index => {
    for (const patch of [{ state: 'uncertain' }, { state: 'failed' }, { remoteCompleted: false }, { remoteStarted: false }, { operationId: null }, { name: 'another-native-action' }]) {
      const value = receipt(); Object.assign(value.steps[index], patch); expect(workflowMetadataRecoveryEligible(value, view(), reference)).toBe(false);
    }
  });
  it('requires exactly one final uncertain metadata step without a native operation or completed receipt', () => {
    for (const patch of [{ name: 'portal.credential.rotate' }, { state: 'failed' }, { state: 'running' }, { state: 'succeeded' }, { operationId: ids[3] }, { remoteCompleted: true }]) {
      const value = receipt(); Object.assign(value.steps[3], patch); expect(workflowMetadataRecoveryEligible(value, view(), reference)).toBe(false);
    }
    for (const steps of [receipt().steps.slice(0, 3), [...receipt().steps, receipt().steps[3]], receipt().steps.map((step, index) => ({ ...step, id: index === 1 ? ids[0] : step.id }))]) expect(workflowMetadataRecoveryEligible({ ...receipt(), steps }, view(), reference)).toBe(false);
  });
  it('captures the original actor, cluster, workspace, workflow and permission epoch through selector/account changes', () => {
    expect(workflowMetadataRecoveryContextMatches(reference, reference)).toBe(true);
    for (const field of ['actorId', 'clusterId', 'workspaceId', 'workflowId', 'permissionsVersion'] as const) expect(workflowMetadataRecoveryContextMatches(reference, { ...reference, [field]: 'different' })).toBe(false);
  });
  it('builds only the metadata endpoint with the original key and exact CAS/confirmation payload', () => {
    const request = workflowMetadataRecoveryRequest(receipt(), view(), reference);
    expect(request.path).toBe(`/clusters/${cid}/workflows/${workflowId}/reconcile-metadata?workspaceId=${wid}`);
    expect(request.options.method).toBe('POST'); expect(new Headers(request.options.headers).get('X-Idempotency-Key')).toBe(key);
    expect(JSON.parse(request.options.body as string)).toEqual({ revision: 5, planHash: 'a'.repeat(64), executionId, confirmed: true, confirm_name: 'portal-credential-issue' });
    expect(JSON.stringify(request)).not.toMatch(/consumerId|credentialId|apiKey|"key"|\/execute\?/);
    expect(() => workflowMetadataRecoveryRequest({ ...receipt(), state: 'partial' }, view(), reference)).toThrow();
  });
  it('preserves original key bytes even when a valid UUID key uses uppercase; missing keys never manufacture a replacement', () => {
    const uppercase = { ...reference, idempotencyKey: key.toUpperCase() };
    expect(workflowMetadataReceiptPath(uppercase)).toContain(`/by-key/${uppercase.idempotencyKey}?`);
    expect(new Headers(workflowMetadataRecoveryRequest({ ...receipt(), idempotencyKey: uppercase.idempotencyKey }, view(), uppercase).options.headers).get('X-Idempotency-Key')).toBe(uppercase.idempotencyKey);
    expect(() => workflowMetadataReceiptPath({ ...reference, idempotencyKey: '' })).toThrow();
  });
  it('only accepts the completed original execution after all four steps are acknowledged, independent of submission receipt', () => {
    const final = receipt(); final.state = 'succeeded'; final.steps[3].state = 'succeeded'; final.steps[3].remoteCompleted = true;
    expect(workflowMetadataRecoveryProvesCompletion(final, reference, executionId)).toBe(true);
    for (const patch of [{ idempotencyKey: ids[0] }, { workflowId: ids[0] }, { executionId: ids[0] }, { action: 'submit' }, { state: 'uncertain' }]) expect(workflowMetadataRecoveryProvesCompletion({ ...final, ...patch }, reference, executionId)).toBe(false);
    final.steps[3].remoteCompleted = false; expect(workflowMetadataRecoveryProvesCompletion(final, reference, executionId)).toBe(false);
  });
  it('uses the actual client without generating a new key and retains the original scope on a lost metadata response', async () => {
    vi.stubGlobal('window', { dispatchEvent: vi.fn() });
    vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: { detail: unknown }) { super(type); this.detail = options.detail; } });
    const freshKey = vi.fn(() => { throw new Error('must not generate another key'); }); vi.stubGlobal('crypto', { randomUUID: freshKey });
    const fetch = vi.fn().mockRejectedValue(new Error('response interrupted')); vi.stubGlobal('fetch', fetch);
    const client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('unit-only-csrf');
    const request = workflowMetadataRecoveryRequest(receipt(), view(), reference);
    const error = await client.api(request.path, request.options).catch(value => value);
    expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', clusterId: cid, workspaceId: wid, idempotencyKey: key, state: 'uncertain' } });
    expect(freshKey).not.toHaveBeenCalled(); expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][0]).toBe(`/api/v1${request.path}`); expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);
    expect(window.dispatchEvent).toHaveBeenCalledTimes(1);
  });
});
