import { afterEach, describe, expect, it, vi } from 'vitest';
import { workflowMetadataReceiptPath, workflowMetadataRecoveryEligible, workflowMetadataRecoveryProvesCompletion, workflowMetadataRecoveryRequest } from '../../apps/console-web/src/api/workflow-recovery';
import type { Workflow, WorkflowReceipt } from '../../apps/console-web/src/features/portal.types';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7';
const actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22';
const workflowId = 'bc7bd065-9372-405d-9782-015d31a30aa1', executionId = '631dde84-fd98-47a0-aa35-45f458595231';
const stepId = '9303db34-99cb-4ce3-b6f2-67b74370e01e', operationId = 'fc5d7a72-dbec-43af-abcd-c65b0497641c', foreignId = 'b4eaee06-9e7f-44fa-bfd4-cddc703c43dd';
const hash = 'a'.repeat(64);
const reference = { actorId: actor, clusterId: cid, workspaceId: wid, workflowId, idempotencyKey: key, permissionsVersion: 'actor:9' };
function view(state = 'uncertain'): Workflow { return { id: workflowId, kind: 'workspace-migration', name: 'workspace-migration', clusterId: cid, workspaceId: wid, revision: 5, planRevision: 1, planHash: hash, state, executionMode: 'approval', approvalRequired: true, createdAt: new Date(0).toISOString(), expiresAt: new Date(86400000).toISOString(), capabilities: { approve: false, reject: false, cancel: false, execute: false, reconcileMetadata: true } }; }
function receipt(state = 'uncertain'): WorkflowReceipt { return { id: executionId, workflowId, executionId, clusterId: cid, workspaceId: wid, idempotencyKey: key, revision: 5, planHash: hash, state, action: 'execute', metadataRecovery: { eligible: true, kind: 'workspace-migration', knownNativeComplete: true, executionId, originalExecutionKeyRequired: true }, steps: [{ id: stepId, name: 'workspace-migration', state: 'succeeded', operationId, remoteStarted: true, remoteCompleted: true }], propagation: 'pending' }; }
function complete(): WorkflowReceipt { const row = receipt('succeeded'); row.revision = 6; row.propagation = 'acknowledged'; row.metadataRecovery = { eligible: false, kind: 'workspace-migration', knownNativeComplete: true, completed: true, executionId, originalExecutionKeyRequired: true }; return row; }
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('fixed workspace-migration known-native metadata recovery boundary', () => {
  it.each(['uncertain', 'partial'])('admits %s only with current capability and the original actor-bound complete native receipt', state => {
    expect(workflowMetadataRecoveryEligible(receipt(state), view(state), reference)).toBe(true);
    expect(workflowMetadataRecoveryEligible(receipt(state), { ...view(state), capabilities: { ...view(state).capabilities, reconcileMetadata: false } }, reference)).toBe(false);
    expect(workflowMetadataRecoveryEligible(receipt(state), view(state === 'partial' ? 'uncertain' : 'partial'), reference)).toBe(false);
  });
  it.each(['clusterId', 'workspaceId', 'workflowId', 'idempotencyKey'] as const)('rejects another %s without constructing a write', field => {
    const wrong = { ...receipt(), [field]: foreignId };
    expect(workflowMetadataRecoveryEligible(wrong, view(), reference)).toBe(false);
    expect(() => workflowMetadataRecoveryRequest(wrong, view(), reference)).toThrow();
  });
  it('rejects submission/approval receipts, stale CAS/hash, missing actor/epoch and nonrecoverable parent states', () => {
    for (const patch of [{ action: 'submit' }, { action: 'approve' }, { id: foreignId }, { executionId: null }, { revision: 4 }, { planHash: 'b'.repeat(64) }, { state: 'failed' }]) expect(workflowMetadataRecoveryEligible({ ...receipt(), ...patch }, view(), reference)).toBe(false);
    for (const state of ['failed', 'pending', 'executing', 'succeeded', 'expired']) expect(workflowMetadataRecoveryEligible(receipt(state), view(state), reference)).toBe(false);
    for (const patch of [{ actorId: '' }, { permissionsVersion: '' }, { idempotencyKey: '../execute' }]) expect(workflowMetadataRecoveryEligible(receipt(), view(), { ...reference, ...patch })).toBe(false);
  });
  it('requires the migration-specific server proof and rejects completed proof as new recovery eligibility', () => {
    for (const patch of [{ kind: 'portal-credential-issue' }, { eligible: false }, { knownNativeComplete: false }, { executionId: foreignId }, { originalExecutionKeyRequired: false }, { completed: true }]) {
      const row = receipt(); row.metadataRecovery = { ...row.metadataRecovery, ...patch } as any;
      expect(workflowMetadataRecoveryEligible(row, view(), reference)).toBe(false);
    }
    expect(workflowMetadataRecoveryEligible({ ...receipt(), metadataRecovery: undefined }, view(), reference)).toBe(false);
  });
  it('requires exactly the original logical migration step, operation and complete ACK; partial native results never qualify', () => {
    for (const patch of [{ name: 'services.patch.1' }, { state: 'partial' }, { state: 'uncertain' }, { state: 'failed' }, { operationId: null }, { remoteStarted: false }, { remoteCompleted: false }]) {
      const row = receipt(); Object.assign(row.steps[0], patch); expect(workflowMetadataRecoveryEligible(row, view(), reference)).toBe(false);
    }
    for (const steps of [[], [receipt().steps[0], { ...receipt().steps[0], id: foreignId }]]) expect(workflowMetadataRecoveryEligible({ ...receipt(), steps }, view(), reference)).toBe(false);
  });
  it('never treats a portal four-step receipt as a migration or a one-step migration receipt as portal completion', () => {
    const portalSteps = ['consumers.create.1', 'credentials.create.2', 'credentials.create.3', 'portal.credential.activate'].map((name, index) => ({ id: [stepId, operationId, foreignId, key][index], name, state: 'succeeded', operationId: index === 3 ? null : [stepId, operationId, foreignId][index], remoteStarted: true, remoteCompleted: true }));
    expect(workflowMetadataRecoveryEligible({ ...receipt(), steps: portalSteps }, view(), reference)).toBe(false);
    expect(workflowMetadataRecoveryProvesCompletion(complete(), reference, executionId)).toBe(false);
    expect(workflowMetadataRecoveryProvesCompletion({ ...complete(), steps: portalSteps }, reference, executionId, 'workspace-migration', hash)).toBe(false);
    expect(workflowMetadataRecoveryProvesCompletion({ ...complete(), steps: portalSteps }, reference, executionId, 'portal-credential-issue', hash)).toBe(false);
  });
  it('constructs only the fixed metadata endpoint with the original execution key and immutable plan/CAS body', () => {
    const request = workflowMetadataRecoveryRequest(receipt(), view(), reference);
    expect(request.path).toBe(`/clusters/${cid}/workflows/${workflowId}/reconcile-metadata?workspaceId=${wid}`);
    expect(request.options.method).toBe('POST'); expect(new Headers(request.options.headers).get('X-Idempotency-Key')).toBe(key);
    expect(JSON.parse(request.options.body as string)).toEqual({ revision: 5, planHash: hash, executionId, confirmed: true, confirm_name: 'workspace-migration' });
    expect(request.options.body).not.toMatch(/targetWorkspace|tags|payload|method|operationId|\/execute/);
    const uppercase = { ...reference, idempotencyKey: key.toUpperCase() };
    expect(workflowMetadataReceiptPath(uppercase)).toContain(`/by-key/${uppercase.idempotencyKey}?`);
    expect(new Headers(workflowMetadataRecoveryRequest({ ...receipt(), idempotencyKey: uppercase.idempotencyKey }, view(), uppercase).options.headers).get('X-Idempotency-Key')).toBe(uppercase.idempotencyKey);
  });
  it('accepts completed metadata only for explicit migration kind, exact original hash/key/execution and server completed proof', () => {
    expect(workflowMetadataRecoveryProvesCompletion(complete(), reference, executionId, 'workspace-migration', hash)).toBe(true);
    expect(workflowMetadataRecoveryProvesCompletion(complete(), reference, executionId, 'workspace-migration')).toBe(false);
    for (const patch of [{ idempotencyKey: foreignId }, { workflowId: foreignId }, { executionId: foreignId }, { planHash: 'b'.repeat(64) }, { action: 'submit' }, { state: 'uncertain' }]) expect(workflowMetadataRecoveryProvesCompletion({ ...complete(), ...patch }, reference, executionId, 'workspace-migration', hash)).toBe(false);
    for (const patch of [{ completed: undefined }, { knownNativeComplete: false }, { eligible: true }, { executionId: foreignId }]) {
      const row = complete(); row.metadataRecovery = { ...row.metadataRecovery, ...patch } as any;
      expect(workflowMetadataRecoveryProvesCompletion(row, reference, executionId, 'workspace-migration', hash)).toBe(false);
    }
  });
  it('preserves a lost metadata response at its original workflow key through the actual API client, without retries or fresh execution', async () => {
    vi.stubGlobal('window', { dispatchEvent: vi.fn() });
    vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: { detail: unknown }) { super(type); this.detail = options.detail; } });
    vi.stubGlobal('crypto', { randomUUID: vi.fn(() => { throw new Error('no new execution key'); }) });
    const fetch = vi.fn().mockRejectedValue(new Error('response interrupted')); vi.stubGlobal('fetch', fetch);
    const client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('unit-only-csrf');
    const request = workflowMetadataRecoveryRequest(receipt(), view(), reference);
    await expect(client.api(request.path, request.options)).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', clusterId: cid, workspaceId: wid, idempotencyKey: key, state: 'uncertain' } });
    expect(fetch).toHaveBeenCalledTimes(1); expect(crypto.randomUUID).not.toHaveBeenCalled();
    expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);
  });
});
