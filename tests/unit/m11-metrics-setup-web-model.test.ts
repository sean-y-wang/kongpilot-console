import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { beginMetricsSetupSubmit, clearMetricsSetupAttempt, markMetricsSetupPrepared, metricsSetupPath, metricsSetupReceiptMatchesAttempt, metricsSetupSubmissionAllowed, metricsSetupWorkflowStatus, normalizeMetricsSetupReceipt, normalizeMetricsSetupRequest, normalizeMetricsSetupSubmission, readMetricsSetupAttempt, storeMetricsSetupAttempt, type MetricsSetupAttempt } from '../../apps/console-web/src/features/metrics-setup.model';

// Source-only fixtures exercise client fences; no real session, grant, SQL,
// Gateway packet or approved completion is manufactured by these tests.
const id = (n: number) => `93000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const identity = { actor: id(1), version: 'source-PV', clusterId: id(2), workspaceId: id(3) };
const request = () => ({ sourceId: id(4), mode: 'native_prometheus' as const, confirmed: true as const, confirm_name: 'Production' });
const receipt = () => ({ intentId: id(5), clusterId: id(2), workspaceId: id(3), sourceId: id(4), mode: 'native_prometheus', materialHmac: 'a'.repeat(64), state: 'prepared', workflowId: null, revision: 1, planHash: null, expiresAt: new Date(Date.now() + 60000).toISOString(), preview: { confirmationName: 'Production', source: { id: id(4), name: 'Metrics', type: 'prometheus', revision: 1 }, before: { plugins: [], settings: { enabled: false } }, after: { plugins: [{ name: 'prometheus' }], settings: { enabled: true } }, nativeRequestsPlanned: 1, scope: { workspaceId: id(3), defaultWorkspaceOnly: true, affectsAllWorkspaces: true }, credentialsExposed: false, notices: ['全局配置影响集群全部工作区。', '原生模式保留已有采集器配置。', '部分执行或未知结果仅核验原回执。'] } });
const attempt = (): MetricsSetupAttempt => ({ ...identity, key: id(6), phase: 'prepare', state: 'pending', createdAt: new Date().toISOString() });
let storage: Map<string, string>;
beforeEach(() => { storage = new Map(); vi.stubGlobal('sessionStorage', { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => storage.set(key, value), removeItem: (key: string) => storage.delete(key) }); });
afterEach(() => vi.unstubAllGlobals());

describe('Source-only exact metrics setup identity and safe review', () => {
  it('uses only the fixed BFF setup paths and captured cluster/workspace', () => {
    expect(metricsSetupPath(identity, 'setup')).toBe(`/clusters/${id(2)}/vitals/setup?workspaceId=${id(3)}`);
    expect(metricsSetupPath(identity, 'prepare')).toContain('/vitals/setup/prepare?');
    expect(metricsSetupPath(identity, 'intent-key', id(6))).toContain(`/intents/by-key/${id(6)}?`);
    expect(metricsSetupPath(identity, 'submit-receipt', id(5))).toContain(`/intents/${id(5)}/receipt?`);
  });
  it.each([undefined, '../clustering', 'http://kong:8001', 'ABCDEFAB-0000-4000-8000-000000000005'])('rejects invalid receipt identifier %s before constructing a path', value => { expect(() => metricsSetupPath(identity, 'intent', value)).toThrow(); });
  it.each(['actor', 'clusterId', 'workspaceId'])('rejects a missing %s rather than accepting undefined equality', field => { expect(() => metricsSetupPath({ ...identity, [field]: undefined } as any, 'setup')).toThrow(); });
  it('permits only source, mode and real typed confirmation in a setup request', () => {
    expect(normalizeMetricsSetupRequest(request())).toEqual(request());
    for (const body of [{ ...request(), executorId: id(8) }, { ...request(), sourceId: undefined }, { ...request(), confirmed: false }, { ...request(), mode: 'enterprise-vitals' }]) expect(() => normalizeMetricsSetupRequest(body as any)).toThrow();
  });
  it('requires explicit prepared revision and exact plugin count, keeps absent fields closed', () => {
    const row = normalizeMetricsSetupReceipt(receipt()); expect(row.revision).toBe(1); expect(row.preview?.nativeRequestsPlanned).toBe(1);
    for (const raw of [{ ...receipt(), revision: null }, { ...receipt(), intentId: undefined }, { ...receipt(), workspaceId: id(9), workflowId: undefined }, { ...receipt(), preview: null }, { ...receipt(), preview: { ...receipt().preview, nativeRequestsPlanned: 2 } }, { ...receipt(), preview: { ...receipt().preview, source: { ...receipt().preview.source, id: id(9) } } }]) expect(() => normalizeMetricsSetupReceipt(raw)).toThrow();
  });
  it('allows a terminal workflow receipt without reauthorizing its intent', () => {
    const row = normalizeMetricsSetupReceipt({ ...receipt(), workflowId: id(8), state: 'succeeded', planHash: 'b'.repeat(64), preview: null });
    expect(metricsSetupSubmissionAllowed(row, identity, false)).toBe(false);
  });
  it.each(['submitted', 'partial', 'uncertain', 'failed'])('accepts actual backend workflow state %s while never reopening submit or inventing completed UI', state => {
    const row = normalizeMetricsSetupReceipt({ ...receipt(), workflowId: id(8), state, planHash: 'b'.repeat(64), ...(state === 'submitted' ? {} : { preview: null }) });
    expect(metricsSetupSubmissionAllowed(row, identity, false)).toBe(false);
    if (['partial', 'uncertain', 'failed'].includes(state)) expect(metricsSetupWorkflowStatus(state).type).not.toBe('success');
  });
  it('rejects overly deep or oversized previews before rendering a recursive JSON view', () => {
    let deep: any = {}; for (let i = 0; i < 34; i++) deep = { nested: deep };
    for (const before of [deep, Array(1001).fill(null), { excessive: 'a'.repeat(524289) }]) expect(() => normalizeMetricsSetupReceipt({ ...receipt(), preview: { ...receipt().preview, before } })).toThrow();
  });
  it.each([{ clusterId: id(9) }, { workspaceId: id(9) }, { state: 'approved', workflowId: id(8), planHash: 'b'.repeat(64) }, { expiresAt: new Date(Date.now() - 1).toISOString() }])('does not submit changed or expired scope %j', patch => { const raw = receipt(), changed = { ...raw, ...patch, preview: { ...raw.preview, scope: { ...raw.preview.scope, workspaceId: patch.workspaceId ?? raw.workspaceId } } }, row = normalizeMetricsSetupReceipt(changed); expect(metricsSetupSubmissionAllowed(row, identity, false)).toBe(false); });
  it('blocks an otherwise valid review when scope is readonly or fenced', () => { expect(metricsSetupSubmissionAllowed(normalizeMetricsSetupReceipt(receipt()), identity, true)).toBe(false); });
  it('links submit GET receipt to the original immutable material', () => {
    const original = normalizeMetricsSetupReceipt(receipt()), raw = { intentId: original.intentId, clusterId: original.clusterId, workspaceId: original.workspaceId, materialHmac: original.materialHmac, workflowId: id(8), state: 'submitted', steps: [] };
    expect(normalizeMetricsSetupSubmission(raw, original).workflowId).toBe(id(8));
    for (const patch of [{ intentId: id(9) }, { workspaceId: id(9) }, { materialHmac: 'c'.repeat(64) }, { workflowId: null }, { state: 'fabricated-success' }]) expect(() => normalizeMetricsSetupSubmission({ ...raw, ...patch }, original)).toThrow();
  });
});

describe('Source-only original metrics setup journal', () => {
  it('persists only original identifiers and never payloads, CSRF or managed credentials', () => {
    const original = attempt(); storeMetricsSetupAttempt({ ...original, sourceId: id(4), input: request(), csrfToken: 'sensitive', token: 'sensitive', preview: receipt().preview } as any);
    const row = readMetricsSetupAttempt(identity.actor); expect(row).toEqual(original);
    const raw = [...storage.values()][0]; for (const key of ['input', 'csrfToken', 'token', 'preview', 'confirm_name', 'sourceId']) expect(raw).not.toContain(key);
  });
  it('an unknown request cannot be replaced with a fresh key or downgraded to pending', () => {
    const original = attempt(); storeMetricsSetupAttempt(original); storeMetricsSetupAttempt({ ...original, state: 'unknown' });
    expect(() => storeMetricsSetupAttempt({ ...original, key: id(7) })).toThrow(); expect(() => storeMetricsSetupAttempt(original)).toThrow();
  });
  it('a verified original prepare alone creates the prepared state and a distinct submit key', () => {
    const original = attempt(); storeMetricsSetupAttempt(original); const reviewed = normalizeMetricsSetupReceipt(receipt());
    const prepared = markMetricsSetupPrepared(identity.actor, original.key, reviewed); expect(prepared.phase).toBe('prepared'); expect(metricsSetupReceiptMatchesAttempt(reviewed, prepared)).toBe(true);
    expect(() => beginMetricsSetupSubmit(identity.actor, original.key, original.key)).toThrow();
    const command = beginMetricsSetupSubmit(identity.actor, original.key, id(7)); expect(command.phase).toBe('submit'); expect(command.state).toBe('pending'); expect(command.intentId).toBe(reviewed.intentId);
  });
  it('refuses another workspace receipt or an unlinked HMAC', () => {
    const original = attempt(); storeMetricsSetupAttempt(original);
    expect(() => markMetricsSetupPrepared(identity.actor, original.key, normalizeMetricsSetupReceipt({ ...receipt(), workspaceId: id(9) }))).toThrow();
    const prepared = markMetricsSetupPrepared(identity.actor, original.key, normalizeMetricsSetupReceipt(receipt()));
    expect(metricsSetupReceiptMatchesAttempt(normalizeMetricsSetupReceipt({ ...receipt(), materialHmac: 'c'.repeat(64) }), prepared)).toBe(false);
  });
  it('cannot clear an original record with another actor or key', () => { const original = attempt(); storeMetricsSetupAttempt(original); expect(() => clearMetricsSetupAttempt(identity.actor, id(9))).toThrow(); expect(() => clearMetricsSetupAttempt(id(9), original.key)).toThrow(); expect(readMetricsSetupAttempt(identity.actor)).toBeDefined(); });
  it.each(['broken-json', JSON.stringify({ ...attempt(), phase: 'unknown-kind' }), JSON.stringify({ ...attempt(), actor: id(9) })])('a damaged stored record %s remains closed', raw => { storage.set(`kongpilot.metricsSetupAttempt:${identity.actor}`, raw); expect(() => readMetricsSetupAttempt(identity.actor)).toThrow(); });
});
