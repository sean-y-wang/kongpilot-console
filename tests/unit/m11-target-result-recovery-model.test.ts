import { describe, expect, it } from 'vitest';
import { workflowTargetResultOriginalReference, workflowTargetResultPacketObservation, workflowTargetResultReceiptPath,
  workflowTargetResultRecoveryReference, workflowTargetResultRecoveryRequest } from '../../apps/console-web/src/features/workflow-target-result-recovery.model';
import { normalizeNativeChangeHistory } from '../../apps/console-web/src/features/workflow-entity-change.model';
import { workflowTargetResultProvesCompletion } from '../../apps/console-web/src/api/workflow-recovery';
import { targetRecoveryAttempt, targetRecoveryIds as ids, targetRecoveryIdentity, targetRecoveryReceipt, targetRecoveryWorkflow } from './fixtures/m11-target-result-recovery';
const context = () => ({ identity: targetRecoveryIdentity(), authenticatedActorId: ids.actor, readonlyWorkspace: false, writeBlocked: true });
const reference = () => workflowTargetResultRecoveryReference(targetRecoveryWorkflow(), context(), targetRecoveryAttempt(), targetRecoveryReceipt())!;
describe('Target metadata UI uses original actor-bound execute proof', () => {
  it('locates only this tab original journal and requires the matching current receipt before any write reference', () => {
    expect(workflowTargetResultOriginalReference(targetRecoveryWorkflow(), context(), targetRecoveryAttempt())?.originalExecutionKey).toBe(ids.key);
    expect(workflowTargetResultRecoveryReference(targetRecoveryWorkflow(), context(), targetRecoveryAttempt(), undefined)).toBeUndefined();
    expect(reference()).toMatchObject({ actorId: ids.actor, originalExecutionKey: ids.key, executionId: ids.execution, workflowRevision: 5 });
    expect(Object.isFrozen(reference())).toBe(true);
    expect(workflowTargetResultReceiptPath(reference())).toBe(`/clusters/${ids.cid}/workflows/receipts/by-key/${ids.key}?workspaceId=${ids.wid}`);
  });
  it.each(['actor', 'cid', 'wid', 'subject', 'key', 'planHash', 'action'] as const)('rejects a journal with a different %s', field => {
    expect(workflowTargetResultRecoveryReference(targetRecoveryWorkflow(), context(), { ...targetRecoveryAttempt(), [field]: field === 'action' ? 'approve' : ids.other }, targetRecoveryReceipt())).toBeUndefined();
  });
  it.each(['id', 'executionId', 'workflowId', 'clusterId', 'workspaceId', 'idempotencyKey', 'action', 'state', 'revision', 'planHash'] as const)('rejects wrong current receipt %s', field => {
    expect(workflowTargetResultRecoveryReference(targetRecoveryWorkflow(), context(), targetRecoveryAttempt(), { ...targetRecoveryReceipt(), [field]: field === 'revision' ? 4 : ids.other })).toBeUndefined();
  });
  it('does not turn an approval receipt, incomplete wrapper, multiple packets, missing capability or readonly scope into metadata authority', () => {
    const missing = targetRecoveryWorkflow(); delete missing.nativeChange!.targetResultReconciliationAvailable;
    const duplicate = targetRecoveryWorkflow(); duplicate.nativeChange!.packets.push(duplicate.nativeChange!.packets[0]);
    for (const row of [missing, duplicate, { ...targetRecoveryWorkflow(), state: 'approved' }]) expect(workflowTargetResultRecoveryReference(row, context(), targetRecoveryAttempt(), targetRecoveryReceipt())).toBeUndefined();
    expect(workflowTargetResultRecoveryReference(targetRecoveryWorkflow(), { ...context(), readonlyWorkspace: true }, targetRecoveryAttempt(), targetRecoveryReceipt())).toBeUndefined();
    for (const patch of [{ name: 'portal.credential.activate' }, { operationId: ids.operation }, { remoteStarted: false }, { remoteCompleted: true }]) {
      const receipt = targetRecoveryReceipt(); Object.assign(receipt.steps[0], patch);
      expect(workflowTargetResultRecoveryReference(targetRecoveryWorkflow(), context(), targetRecoveryAttempt(), receipt)).toBeUndefined();
    }
  });
  it('sends exact metadata body with the original key only after explicit native-change confirmation', () => {
    const request = workflowTargetResultRecoveryRequest(reference(), targetRecoveryWorkflow(), context(), targetRecoveryReceipt(), { confirmed: true, confirmName: 'native-change' });
    expect(request.path).toBe(`/clusters/${ids.cid}/workflows/${ids.workflow}/reconcile-target-result?workspaceId=${ids.wid}`);
    expect(request.options.method).toBe('POST'); expect(new Headers(request.options.headers).get('X-Idempotency-Key')).toBe(ids.key);
    expect(JSON.parse(request.options.body as string)).toEqual({ revision: 5, planHash: 'a'.repeat(64), executionId: ids.execution, confirmed: true, confirm_name: 'native-change' });
    for (const confirmation of [{ confirmed: false, confirmName: 'native-change' }, { confirmed: true, confirmName: ids.workflow }])
      expect(() => workflowTargetResultRecoveryRequest(reference(), targetRecoveryWorkflow(), context(), targetRecoveryReceipt(), confirmation)).toThrow();
  });
  it.each(['actor', 'version', 'cid', 'wid'] as const)('rejects an opened confirmation after current identity %s changes', field => {
    expect(() => workflowTargetResultRecoveryRequest(reference(), targetRecoveryWorkflow(), { ...context(), identity: { ...targetRecoveryIdentity(), [field]: ids.other } }, targetRecoveryReceipt(), { confirmed: true, confirmName: 'native-change' })).toThrow();
  });
  it('cannot recover on a changed revision, different execution, new hash or changed actor-bound receipt', () => {
    for (const row of [{ ...targetRecoveryWorkflow(), revision: 6 }, { ...targetRecoveryWorkflow(), planHash: 'c'.repeat(64) }, { ...targetRecoveryWorkflow(), nativeChange: { ...targetRecoveryWorkflow().nativeChange!, executionId: ids.other } }])
      expect(() => workflowTargetResultRecoveryRequest(reference(), row, context(), targetRecoveryReceipt(), { confirmed: true, confirmName: 'native-change' })).toThrow();
    expect(() => workflowTargetResultRecoveryRequest(reference(), targetRecoveryWorkflow(), context(), { ...targetRecoveryReceipt(), idempotencyKey: ids.other }, { confirmed: true, confirmName: 'native-change' })).toThrow();
  });
});
describe('new Target observation preserves the original unknown native history', () => {
  it('allowlists the authenticated public certificate without rewriting sent-unknown, NULL or old error', () => {
    const raw = targetRecoveryWorkflow(true).nativeChange!;
    const value = normalizeNativeChangeHistory({ ...raw, ciphertext: 'untrusted', packets: [{ ...raw.packets[0], secret: 'untrusted', targetResultObservation: { ...raw.packets[0].targetResultObservation, arbitrary: 'untrusted' } }] })!;
    expect(value.targetResultReconciliationAvailable).toBe(false); expect(value.packets[0]).toMatchObject({ state: 'sent-unknown', nativeStatus: null, errorCode: 'MUTATION_RESULT_UNCERTAIN' });
    expect(JSON.stringify(value)).not.toContain('untrusted');
    expect(workflowTargetResultPacketObservation(value.packets[0])).toEqual({ state: 'sent-unknown', nativeStatus: null, observationKnown: true, observationLabel: '原结果已核验' });
  });
  it('a truthy capability or observationKnown flag cannot supply a server certificate', () => {
    expect(normalizeNativeChangeHistory({ ...targetRecoveryWorkflow().nativeChange, targetResultReconciliationAvailable: 'true' })?.targetResultReconciliationAvailable).toBe(false);
    expect(workflowTargetResultPacketObservation({ ...targetRecoveryWorkflow().nativeChange!.packets[0], observationKnown: true } as any).observationKnown).toBe(false);
    expect(workflowTargetResultPacketObservation(targetRecoveryWorkflow().nativeChange!.packets[0]).observationKnown).toBe(false);
  });
  it.each(['id', 'auditId', 'eventHash', 'observedAt', 'kind', 'nativeRequestsSent', 'originalNativeStatus', 'operationId', 'workflowStepId', 'operationState'] as const)('rejects malformed certificate %s', field => {
    const raw = targetRecoveryWorkflow(true).nativeChange!;
    (raw.packets[0].targetResultObservation as any)[field] = field === 'nativeRequestsSent' ? 1 : field === 'originalNativeStatus' ? 201 : field === 'operationId' ? ids.other : 'invalid';
    expect(() => normalizeNativeChangeHistory(raw)).toThrow();
  });
  it('only closes the current original-key fence from four succeeded states and exact execution/step/operation bindings', () => {
    expect(workflowTargetResultProvesCompletion(targetRecoveryReceipt(true), targetRecoveryWorkflow(true), reference())).toBe(true);
    const alreadyClosedRef = workflowTargetResultOriginalReference(targetRecoveryWorkflow(true), context(), targetRecoveryAttempt())!;
    expect(workflowTargetResultProvesCompletion(targetRecoveryReceipt(true), targetRecoveryWorkflow(true), alreadyClosedRef)).toBe(true);
    const missing = targetRecoveryWorkflow(true); delete missing.nativeChange!.packets[0].targetResultObservation;
    expect(workflowTargetResultProvesCompletion(targetRecoveryReceipt(true), missing, reference())).toBe(false);
    for (const patch of [{ state: 'uncertain' }, { planRevision: 2 }, { revision: 7 }, { workspaceId: ids.other }])
      expect(workflowTargetResultProvesCompletion(targetRecoveryReceipt(true), { ...targetRecoveryWorkflow(true), ...patch }, reference())).toBe(false);
    for (const patch of [{ id: ids.other }, { name: 'another-step' }, { state: 'uncertain' }, { operationId: ids.operation }, { remoteStarted: false }, { remoteCompleted: false }]) {
      const receipt = targetRecoveryReceipt(true); Object.assign(receipt.steps[0], patch);
      expect(workflowTargetResultProvesCompletion(receipt, targetRecoveryWorkflow(true), reference())).toBe(false);
    }
    for (const patch of [{ idempotencyKey: ids.other }, { action: 'approve' as const }, { revision: 5 }, { executionId: ids.other }, { workflowId: ids.other }])
      expect(workflowTargetResultProvesCompletion({ ...targetRecoveryReceipt(true), ...patch }, targetRecoveryWorkflow(true), reference())).toBe(false);
  });
});
