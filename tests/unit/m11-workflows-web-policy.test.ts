import { afterEach, describe, expect, it, vi } from 'vitest';
// Controlled response fixtures test frontend contract/fail-closed behavior.
// They are not actual sessions, approvals, BFF grants or native authority.
import { api, setApiActorId, setCsrfToken } from '../../apps/console-web/src/api/client';
import { normalizeWorkflowDetail, type Workflow } from '../../apps/console-web/src/features/portal.types';
import { activeWorkflowStage, workflowDecisionPayload } from '../../apps/console-web/src/features/workflows.model';
import { entityChangeSubmitPayload, nativeRollbackPayload, nativeWorkflowCan, normalizeEntityChangeIntent, normalizeNativeChangeHistory,
  readWorkflowAttempt, sameWorkflowIdentity, storeWorkflowAttempt, workflowActionReceiptComplete, workflowExecutionReceiptClosed, workflowCanPrepare, type WorkflowWriteAttempt } from '../../apps/console-web/src/features/workflow-entity-change.model';

const actor = '30b6d312-a9b8-4ac4-b49d-d8d87e1eeccf', cid = 'a949b292-2e4a-4326-b30d-3a883b5ef3d7';
const wid = '306a8d36-d1f9-4542-8972-9b30aa1bd67c', id = '35b60072-927d-4f3b-bba1-dbc31bd345e4', execution = 'c6439d99-75a0-4f2b-b6d7-a2d3f0c87177';
const identity = { actor, cid, wid, version: 'real-server-PV-1' }, key = 'f02f0f79-03bb-4494-9b2c-f3fa4a28a28a';
function history(): any { return { executionId: execution, baseline: { baseline: { baselineId: id, sourceId: id, pinId: id, objectCount: 3, graphCount: 1, protectedUntil: '2099-01-01T00:00:00Z' },
  observedFrom: '2026-10-13T13:00:00Z', observedUntil: '2026-10-13T13:00:01Z', recovery: { state: 'complete', totalObjects: 3, affectedObjects: 2, presentObjects: 3, absentObjects: 0, referenceObjects: 1 }, nativeAuthority: false },
  packets: [{ key: 'packet-1', order: 1, entityType: 'services', entityId: id, operationId: execution, state: 'succeeded', nativeStatus: 201, errorCode: null }] }; }
function workflow(overrides: Partial<Workflow> = {}): Workflow { return { id, kind: 'native-change', clusterId: cid, workspaceId: wid, name: 'native-change', revision: 3, planRevision: 1, planHash: 'a'.repeat(64), state: 'approved', executionMode: 'approval', approvalRequired: true, createdAt: '2026-10-13T12:00:00Z', expiresAt: '2099-01-01T00:00:00Z', capabilities: { approve: false, reject: false, cancel: true, execute: true }, ...overrides }; }
function intent(): any { return { id, revision: 1, materialHmac: 'b'.repeat(64), executionMode: 'approval', issuedAt: '2026-10-13T12:00:00Z', expiresAt: '2099-01-01T00:00:00Z', nativeExecutionAvailable: false,
  capabilities: { submit: true }, review: { changes: [{ entityType: 'services', nativeId: id, action: 'update', before: { host: 'before.example' }, after: { host: 'after.example', api_key: 'never-display-this-secret' } }],
    impact: { changedObjects: 1, nativePackets: 1, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: { state: 'baseline-required', blockerCodes: [] } } }; }
function attempt(action: WorkflowWriteAttempt['action'] = 'execute'): WorkflowWriteAttempt { return { ...identity, subject: id, action, key, planHash: 'a'.repeat(64), revision: 3, state: 'unknown' }; }
function receipt(action = 'execute'): any { return { id: execution, executionId: execution, workflowId: id, clusterId: cid, workspaceId: wid, idempotencyKey: key, planHash: 'a'.repeat(64), action, state: 'succeeded',
  steps: [{ id: execution, name: 'entity.change', state: 'succeeded', remoteStarted: true, remoteCompleted: true }] }; }

describe('M11 console workflow real-contract capability and source policy', () => {
  afterEach(() => { setApiActorId(undefined); setCsrfToken(''); vi.unstubAllGlobals(); });
  it('missing capabilities are false; approval and execution are separate, and failure/unknown cannot be resent', () => {
    const row = workflow(); expect(nativeWorkflowCan(row, 'execute')).toBe(true);
    for (const state of ['failed', 'partial', 'uncertain', 'executing', 'rejected', 'cancelled', 'expired']) expect(nativeWorkflowCan(workflow({ state }), 'execute')).toBe(false);
    expect(nativeWorkflowCan(workflow({ state: 'pending' }), 'execute')).toBe(false);
    expect(nativeWorkflowCan(workflow({ state: 'pending', approvalRequired: false }), 'execute')).toBe(true);
    expect(nativeWorkflowCan(workflow({ capabilities: { ...row.capabilities, execute: false } }), 'execute')).toBe(false);
    expect(nativeWorkflowCan(row, 'entityPreflight')).toBe(false); expect(nativeWorkflowCan(row, 'rollbackPrepare')).toBe(false);
    expect(nativeWorkflowCan(workflow({ nativeChange: normalizeNativeChangeHistory({ ...history(), packets: [{ ...history().packets[0], state: 'sent-unknown' }] }) }), 'execute')).toBe(false);
  });
  it('uses current server stage/candidate revisions and never auto-executes a third-stage approval', () => {
    const row = workflow({ state: 'pending', capabilities: { approve: true, reject: true, cancel: false, execute: false }, approval: { format: 2, policyHash: 'c'.repeat(64), candidateVersion: 4, distinctAcrossStages: true, approvalSetId: null,
      stages: [1, 2, 3].map(level => ({ level, name: `阶段 ${level}`, mode: 'quorum', threshold: 2, state: level === 3 ? 'active' : 'approved', revision: 6, candidateCount: 3, votes: level === 3 ? 1 : 2 })) } });
    expect(activeWorkflowStage(row)?.level).toBe(3);
    expect(workflowDecisionPayload(row, 'approve', '确认')).toEqual({ revision: 3, planHash: row.planHash, reason: '确认', confirmed: true, confirm_name: 'native-change', execute: false, level: 3, stageRevision: 6, candidateVersion: 4 });
    row.approval!.stages[0].state = 'pending'; expect(() => workflowDecisionPayload(row, 'approve', '')).toThrow();
  });
  it('normalizes the actual intent and requires explicit submit capability and original immutable material', () => {
    const parsed = normalizeEntityChangeIntent(intent());
    expect(JSON.stringify(parsed)).not.toContain('never-display-this-secret');
    expect(entityChangeSubmitPayload(parsed)).toEqual({ revision: 1, materialHmac: 'b'.repeat(64), confirmed: true, confirm_name: 'native-change' });
    const absent = intent(); delete absent.capabilities;
    expect(() => entityChangeSubmitPayload(normalizeEntityChangeIntent(absent))).toThrow();
    expect(() => entityChangeSubmitPayload({ ...parsed, workflowId: id })).toThrow();
    expect(() => normalizeEntityChangeIntent({ ...intent(), revision: '1' })).toThrow();
  });
  it('preserves safe baseline and packet projection while dropping secret graphs, parent configs and arbitrary authority fields', () => {
    const raw = history(); raw.baseline.objects = [{ password: 'private-plaintext' }]; raw.baseline.graph = { key: 'encrypted-private-key' }; raw.packets[0].body = { password: 'private-response' };
    const detail = normalizeWorkflowDetail({ entity: workflow(), nativeChange: raw });
    expect(detail.nativeChange?.baseline?.recovery.referenceObjects).toBe(1);
    const encoded = JSON.stringify(detail.nativeChange); expect(encoded).not.toContain('private-plaintext'); expect(encoded).not.toContain('encrypted-private-key'); expect(encoded).not.toContain('private-response');
    expect(detail.nativeChange?.packets[0].operationId).toBe(execution);
    raw.baseline.nativeAuthority = true; expect(() => normalizeNativeChangeHistory(raw)).toThrow();
    expect(normalizeNativeChangeHistory({ baseline: null, packets: [] })?.baseline).toBeNull();
  });
  it('rollback is a new intent preparation requiring real closed-outcome capability and execution ID', () => {
    const row = workflow({ state: 'partial', capabilities: { approve: false, reject: false, cancel: false, execute: false, rollbackPrepare: true }, nativeChange: normalizeNativeChangeHistory(history()) });
    expect(nativeRollbackPayload(row)).toEqual({ revision: 3, planHash: 'a'.repeat(64), executionId: execution, confirmed: true, confirm_name: 'native-change' });
    const unknown = { ...row, nativeChange: normalizeNativeChangeHistory({ ...history(), packets: [{ ...history().packets[0], state: 'uncertain' }] }) };
    expect(nativeWorkflowCan(unknown, 'rollbackPrepare')).toBe(false);
    expect(nativeWorkflowCan({ ...row, nativeChange: { ...row.nativeChange!, executionId: undefined } }, 'rollbackPrepare')).toBe(false);
  });
  it('requires exact actor-bound scope/key/action/workflow/plan for a readonly receipt and handles pending-stage decisions', () => {
    expect(workflowActionReceiptComplete(receipt(), attempt())).toBe(true);
    for (const change of [{ clusterId: id }, { workspaceId: id }, { idempotencyKey: id }, { workflowId: execution }, { planHash: 'd'.repeat(64) }, { action: 'approve' }]) expect(workflowActionReceiptComplete({ ...receipt(), ...change }, attempt())).toBe(false);
    const vote = { ...receipt('approve'), state: 'pending', decisionCompleted: true, executionRequested: false };
    expect(workflowActionReceiptComplete(vote, attempt('approve'))).toBe(true);
    expect(workflowActionReceiptComplete({ ...vote, decisionCompleted: false }, attempt('approve'))).toBe(false);
  });
  it('closed failure releases only the original-key local fence and cannot grant execute', () => {
    const row = workflow({ state: 'failed', capabilities: { approve: false, reject: false, cancel: false, execute: false, rollbackPrepare: true }, nativeChange: normalizeNativeChangeHistory(history()) });
    expect(workflowActionReceiptComplete({ ...receipt(), state: 'failed' }, attempt())).toBe(false);
    expect(workflowExecutionReceiptClosed({ ...receipt(), state: 'failed' }, attempt(), row)).toBe(true);
    expect(nativeWorkflowCan(row, 'execute')).toBe(false);
    expect(workflowExecutionReceiptClosed({ ...receipt(), state: 'failed', executionId: id }, attempt(), row)).toBe(false);
  });
  it('stores only original-key metadata, survives permission-version changes and keeps actors/clusters/workspaces separate', () => {
    const values = new Map<string, string>(); vi.stubGlobal('sessionStorage', { getItem: (name: string) => values.get(name) ?? null, setItem: (name: string, value: string) => values.set(name, value), removeItem: (name: string) => values.delete(name) });
    storeWorkflowAttempt({ ...attempt(), body: { password: 'never-persist' }, reason: 'private business note' } as any);
    expect([...values.values()].join()).not.toContain('never-persist'); expect([...values.values()].join()).not.toContain('private business note');
    expect(readWorkflowAttempt({ ...identity, version: 'real-server-PV-2' }, id)?.key).toBe(key);
    expect(readWorkflowAttempt({ ...identity, actor: id }, id)).toBeUndefined(); expect(readWorkflowAttempt({ ...identity, wid: id }, id)).toBeUndefined();
    expect(sameWorkflowIdentity(identity, { ...identity, version: 'real-server-PV-2' })).toBe(false);
  });
  it('preparation entry uses actual current-scope grants, including small entity exceptions', () => {
    const capabilities: any = { platformAdmin: false, grants: [{ module: 'workflows', action: 'write', cluster_id: cid, workspace_id: wid, scope_type: 'entity', scope_values: [{ entity_type: 'consumers', entity_id: id }] }] };
    expect(workflowCanPrepare(capabilities, identity)).toBe(true); expect(workflowCanPrepare(capabilities, { ...identity, cid: id })).toBe(false);
    capabilities.grants[0].action = 'read'; expect(workflowCanPrepare(capabilities, identity)).toBe(false); expect(workflowCanPrepare(undefined, identity)).toBe(false);
  });
  it('routes interrupted submission to its real workflow receipt while zero-native preparations keep their feature journal', async () => {
    const dispatchEvent = vi.fn(); vi.stubGlobal('window', { dispatchEvent }); vi.stubGlobal('CustomEvent', class { constructor(public type: string, public detail: unknown) {} });
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('controlled network interruption'); })); setApiActorId(actor); setCsrfToken('test-csrf');
    for (const resource of ['entity-changes/prepare', 'entity-changes/prepare-scheduled', `entity-schedules/${id}/activate`, `entity-schedules/${id}/cancel`, `workflows/${id}/rollback-prepare`]) {
      await expect(api(`/clusters/${cid}/${resource}?workspaceId=${wid}`, { method: 'POST', headers: { 'X-Idempotency-Key': key }, body: '{}' })).rejects.toMatchObject({ code: 'NETWORK_ERROR', status: 0 });
    }
    expect(dispatchEvent).not.toHaveBeenCalled();
    await expect(api(`/clusters/${cid}/entity-changes/${id}/submit?workspaceId=${wid}`, { method: 'POST', headers: { 'X-Idempotency-Key': key }, body: '{}' })).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'workflow', idempotencyKey: key, clusterId: cid, workspaceId: wid } });
    expect(dispatchEvent).toHaveBeenCalledOnce();
  });
});
