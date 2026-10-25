import { afterEach, describe, expect, it, vi } from 'vitest';
import { workflowIssueAbandonmentEligible, workflowIssueAbandonmentProvesCompletion, workflowIssueAbandonmentRequest, workflowMetadataRecoveryProvesCompletion, workflowReceiptProvesCompletion } from '../../apps/console-web/src/api/workflow-recovery';
import type { Workflow, WorkflowReceipt } from '../../apps/console-web/src/features/portal.types';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7';
const actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22';
const workflowId = 'bc7bd065-9372-405d-9782-015d31a30aa1', executionId = '631dde84-fd98-47a0-aa35-45f458595231';
const ids = ['9303db34-99cb-4ce3-b6f2-67b74370e01e', 'fc5d7a72-dbec-43af-abcd-c65b0497641c', 'b4eaee06-9e7f-44fa-bfd4-cddc703c43dd', '27a847b3-e2e1-4e6b-8245-4e2f6cc99b08'];
const reference = { actorId: actor, clusterId: cid, workspaceId: wid, workflowId, idempotencyKey: key, permissionsVersion: 'actor:9' };
function view(): Workflow { return { id: workflowId, kind: 'portal-credential-issue', name: 'portal-credential-issue', clusterId: cid, workspaceId: wid, revision: 5, planRevision: 1, planHash: 'a'.repeat(64), state: 'failed', executionMode: 'direct', approvalRequired: true, createdAt: new Date(0).toISOString(), expiresAt: new Date(86400000).toISOString(), capabilities: { approve: false, reject: false, cancel: false, execute: false, abandonRejectedIssue: true } }; }
function receipt(completed = false): WorkflowReceipt { return { id: executionId, executionId, workflowId, clusterId: cid, workspaceId: wid, idempotencyKey: key, revision: completed ? 6 : 5, planHash: 'a'.repeat(64), state: 'failed', action: 'execute', issueAbandonment: { eligible: !completed, completed, kind: 'portal-credential-issue', executionId, grantId: ids[1], reservationReleased: completed, originalExecutionKeyRequired: true, ...(completed ? { certificateId: ids[2] } : {}) }, steps: ['consumers.create.1', 'credentials.create.2', 'credentials.create.3', 'portal.credential.activate'].map((name, index) => ({ id: ids[index], name, state: index === 0 ? 'failed' : 'pending', operationId: index === 0 ? ids[0] : null, errorCode: index === 0 ? 'KONG_VALIDATION_ERROR' : null, remoteStarted: index === 0, remoteCompleted: false })), propagation: 'pending' }; }
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('known-rejected first Consumer issuance abandonment source gates', () => {
  it('requires current server capability and current eligible proof; failed alone is never release', () => {
    expect(workflowIssueAbandonmentEligible(receipt(), view(), reference)).toBe(true);
    const hidden = view(); delete hidden.capabilities.abandonRejectedIssue;
    expect(workflowIssueAbandonmentEligible(receipt(), hidden, reference)).toBe(false);
    for (const issueAbandonment of [undefined, { ...receipt().issueAbandonment, eligible: false }, { ...receipt().issueAbandonment, completed: true }, { ...receipt().issueAbandonment, reservationReleased: true }, { ...receipt().issueAbandonment, certificateId: ids[2] }, { ...receipt().issueAbandonment, certificateId: null }, { ...receipt().issueAbandonment, certificateId: 0 }]) expect(workflowIssueAbandonmentEligible({ ...receipt(), issueAbandonment }, view(), reference)).toBe(false);
    expect(workflowReceiptProvesCompletion(receipt(), { ...reference, kind: 'workflow' })).toBe(false);
  });
  it.each(['clusterId', 'workspaceId', 'workflowId', 'idempotencyKey'] as const)('denies foreign %s and mismatched target scope', field => {
    expect(workflowIssueAbandonmentEligible({ ...receipt(), [field]: ids[3] }, view(), reference)).toBe(false);
    expect(workflowIssueAbandonmentProvesCompletion({ ...receipt(true), [field]: ids[3] }, reference, executionId)).toBe(false);
  });
  it('rejects wrong actor/version inputs, other workflow kinds/states, stale CAS and submission/approval receipts', () => {
    for (const patch of [{ actorId: '' }, { permissionsVersion: '' }, { idempotencyKey: '' }, { workspaceId: 'invalid' }]) expect(workflowIssueAbandonmentEligible(receipt(), view(), { ...reference, ...patch })).toBe(false);
    for (const patch of [{ state: 'uncertain' }, { state: 'partial' }, { state: 'succeeded' }, { kind: 'portal-credential-rotate' }, { name: 'wrong-confirmation' }, { revision: 0 }]) expect(workflowIssueAbandonmentEligible(receipt(), { ...view(), ...patch }, reference)).toBe(false);
    for (const patch of [{ action: 'submit' }, { action: 'approve' }, { executionId: null }, { id: ids[3] }, { revision: 4 }, { planHash: 'b'.repeat(64) }]) expect(workflowIssueAbandonmentEligible({ ...receipt(), ...patch }, view(), reference)).toBe(false);
  });
  it('requires exact known-rejected first Consumer operation rather than unknown transport or ACK success', () => {
    for (const patch of [{ name: 'credentials.create.1' }, { state: 'uncertain' }, { state: 'succeeded' }, { operationId: null }, { errorCode: 'WRITE_RESULT_UNKNOWN' }, { remoteStarted: false }, { remoteCompleted: true }]) {
      const row = receipt(); Object.assign(row.steps[0], patch); expect(workflowIssueAbandonmentEligible(row, view(), reference)).toBe(false);
    }
  });
  it.each([1, 2, 3])('requires later step %s to stay pristine; any native progress or metadata attempt blocks closure', index => {
    for (const patch of [{ state: 'running' }, { state: 'uncertain' }, { state: 'succeeded' }, { operationId: ids[0] }, { remoteStarted: true }, { remoteCompleted: true }]) {
      const row = receipt(); Object.assign(row.steps[index], patch); expect(workflowIssueAbandonmentEligible(row, view(), reference)).toBe(false);
    }
    const reordered = receipt(); [reordered.steps[1], reordered.steps[2]] = [reordered.steps[2], reordered.steps[1]]; expect(workflowIssueAbandonmentEligible(reordered, view(), reference)).toBe(false);
  });
  it('rejects duplicate/extra steps and proof execution/grant/kind mismatch', () => {
    for (const patch of [{ executionId: ids[0] }, { grantId: 'missing' }, { kind: 'portal-credential-revoke' }, { originalExecutionKeyRequired: false }]) expect(workflowIssueAbandonmentEligible({ ...receipt(), issueAbandonment: { ...receipt().issueAbandonment, ...patch } }, view(), reference)).toBe(false);
    for (const steps of [receipt().steps.slice(0, 3), [...receipt().steps, receipt().steps[3]], receipt().steps.map((step, index) => ({ ...step, id: index === 1 ? ids[0] : step.id }))]) expect(workflowIssueAbandonmentEligible({ ...receipt(), steps }, view(), reference)).toBe(false);
  });
  it('builds one exact abandonment POST with original execution key and no executable native/application/credential payload', () => {
    const request = workflowIssueAbandonmentRequest(receipt(), view(), reference);
    expect(request.path).toBe(`/clusters/${cid}/workflows/${workflowId}/abandon-rejected-issue?workspaceId=${wid}`);
    expect(request.options.method).toBe('POST'); expect(new Headers(request.options.headers).get('X-Idempotency-Key')).toBe(key);
    expect(JSON.parse(request.options.body as string)).toEqual({ revision: 5, planHash: 'a'.repeat(64), executionId, confirmed: true, confirm_name: 'portal-credential-issue' });
    expect(JSON.stringify(request)).not.toMatch(/consumerId|credentialId|apiKey|"key"|\/execute\?/);
    expect(() => workflowIssueAbandonmentRequest({ ...receipt(), issueAbandonment: undefined }, view(), reference)).toThrow();
  });
  it('accepts only completed reservation-release certificate while preserving failed/pending history; never claims issuance succeeded', () => {
    const closed = receipt(true);
    expect(workflowIssueAbandonmentProvesCompletion(closed, reference, executionId)).toBe(true);
    expect(workflowReceiptProvesCompletion(closed, { ...reference, kind: 'workflow' })).toBe(true);
    expect(workflowMetadataRecoveryProvesCompletion(closed, reference, executionId)).toBe(false);
    expect(closed.state).toBe('failed'); expect(closed.steps.map(step => step.state)).toEqual(['failed', 'pending', 'pending', 'pending']);
    expect(workflowIssueAbandonmentProvesCompletion(closed, reference, executionId, ids[1])).toBe(true);
    expect(workflowIssueAbandonmentProvesCompletion(closed, reference, executionId, ids[3])).toBe(false);
    for (const patch of [{ completed: false }, { reservationReleased: false }, { certificateId: undefined }, { certificateId: 'invalid' }, { executionId: ids[3] }, { grantId: 'invalid' }, { originalExecutionKeyRequired: false }]) {
      const row = { ...closed, issueAbandonment: { ...closed.issueAbandonment, ...patch } };
      expect(workflowIssueAbandonmentProvesCompletion(row, reference, executionId)).toBe(false); expect(workflowReceiptProvesCompletion(row, { ...reference, kind: 'workflow' })).toBe(false);
    }
  });
  it('keeps original execution ID/action/scope bound for closure and cannot conflate certificate with a successful native receipt', () => {
    for (const patch of [{ state: 'succeeded' }, { action: 'submit' }, { id: ids[3] }, { executionId: ids[3] }]) expect(workflowIssueAbandonmentProvesCompletion({ ...receipt(true), ...patch }, reference, executionId)).toBe(false);
    const fakeNative = receipt(true); fakeNative.steps[1].state = 'succeeded'; fakeNative.steps[1].remoteCompleted = true;
    expect(workflowIssueAbandonmentProvesCompletion(fakeNative, reference, executionId)).toBe(false);
  });
  it('actual transport sends one original-key POST and retains original scope for lost closure response', async () => {
    vi.stubGlobal('window', { dispatchEvent: vi.fn() });
    vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options: { detail: unknown }) { super(type); this.detail = options.detail; } });
    vi.stubGlobal('crypto', { randomUUID: vi.fn(() => { throw new Error('no new execution keys allowed'); }) });
    const fetch = vi.fn().mockRejectedValue(new Error('response interrupted')); vi.stubGlobal('fetch', fetch);
    const client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('unit-only-csrf');
    const request = workflowIssueAbandonmentRequest(receipt(), view(), reference), error = await client.api(request.path, request.options).catch(value => value);
    expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', clusterId: cid, workspaceId: wid, idempotencyKey: key, state: 'uncertain' } });
    expect(fetch).toHaveBeenCalledTimes(1); expect(crypto.randomUUID).not.toHaveBeenCalled();
    expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);
  });
});
