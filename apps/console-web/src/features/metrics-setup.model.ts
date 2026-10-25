import { canonicalId } from '../api/workspace-scope';

export type MetricsSetupMode = 'native_prometheus' | 'collector';
export interface MetricsSetupIdentity { actor: string; version: string; clusterId: string; workspaceId: string; }
export interface MetricsSetupRequest { sourceId: string; mode: MetricsSetupMode; confirmed: true; confirm_name: string; }
export interface MetricsSetupAttempt extends MetricsSetupIdentity { key: string; phase: 'direct' | 'prepare' | 'prepared' | 'submit'; state: 'pending' | 'unknown' | 'prepared'; createdAt: string; intentId?: string; materialHmac?: string; }
export interface MetricsSetupPreview { confirmationName: string; source: { id: string; name: string; type: 'prometheus'; revision: number }; before: unknown; after: unknown; nativeRequestsPlanned: 1 | 2; scope: { workspaceId: string; defaultWorkspaceOnly: true; affectsAllWorkspaces: true }; credentialsExposed: false; notices: string[]; }
export interface MetricsSetupReceipt { intentId: string; clusterId: string; workspaceId: string; sourceId: string; mode: MetricsSetupMode; materialHmac: string; state: string; workflowId: string | null; revision: number; planHash: string | null; expiresAt: string; preview: MetricsSetupPreview | null; }
export interface MetricsSetupSubmission { intentId: string; clusterId: string; workspaceId: string; materialHmac: string; workflowId: string | null; state: string; steps: Array<{ id: string; name: string; state: string; operationId: string | null; remoteStarted: boolean; remoteCompleted: boolean; errorCode: string | null }>; }

const hex = /^[a-f\d]{64}$/;
const isId = (value: unknown): value is string => typeof value === 'string' && canonicalId(value) === value;
function fail(): never { throw new Error('监控配置记录无效，请核验原请求。'); }
export function validMetricsSetupIdentity(value: MetricsSetupIdentity): boolean { return !!value && ['actor', 'clusterId', 'workspaceId'].every(k => isId(value[k as keyof MetricsSetupIdentity])) && typeof value.version === 'string' && !!value.version && value.version.length <= 256; }
export function sameMetricsSetupIdentity(a: MetricsSetupIdentity, b: MetricsSetupIdentity): boolean { return validMetricsSetupIdentity(a) && validMetricsSetupIdentity(b) && a.actor === b.actor && a.version === b.version && a.clusterId === b.clusterId && a.workspaceId === b.workspaceId; }
export function normalizeMetricsSetupRequest(raw: MetricsSetupRequest): MetricsSetupRequest {
  if (!raw || Object.keys(raw).some(k => !['sourceId', 'mode', 'confirmed', 'confirm_name'].includes(k)) || !isId(raw.sourceId) || !['native_prometheus', 'collector'].includes(raw.mode) || raw.confirmed !== true || typeof raw.confirm_name !== 'string' || !raw.confirm_name.trim() || raw.confirm_name.length > 128) fail();
  return { sourceId: raw.sourceId, mode: raw.mode, confirmed: true, confirm_name: raw.confirm_name };
}
export function metricsSetupPath(identity: MetricsSetupIdentity, resource: 'setup' | 'prepare' | 'intent' | 'intent-key' | 'direct-key' | 'submit' | 'submit-receipt', id?: string): string {
  if (!validMetricsSetupIdentity(identity) || !['setup', 'prepare', 'intent', 'intent-key', 'direct-key', 'submit', 'submit-receipt'].includes(resource) || !['setup', 'prepare'].includes(resource) && !isId(id)) fail();
  const suffix = { setup: '', prepare: '/prepare', intent: `/intents/${id}`, 'intent-key': `/intents/by-key/${id}`, 'direct-key': `/receipts/by-key/${id}`, submit: `/intents/${id}/submit`, 'submit-receipt': `/intents/${id}/receipt` }[resource];
  return `/clusters/${identity.clusterId}/vitals/setup${suffix}?workspaceId=${identity.workspaceId}`;
}
function safeJson(raw: unknown): unknown {
  let text: string; try { text = JSON.stringify(raw); } catch { return fail(); } if (!text! || text.length > 524288) fail();
  const value = JSON.parse(text); let nodes = 0;
  const visit = (node: unknown, depth: number) => { if (++nodes > 10000 || depth > 32) fail(); if (Array.isArray(node)) { if (node.length > 1000) fail(); for (const item of node) visit(item, depth + 1); } else if (node && typeof node === 'object') { const items = Object.values(node); if (items.length > 512) fail(); for (const item of items) visit(item, depth + 1); } };
  visit(value, 0); return value;
}
export function normalizeMetricsSetupReceipt(raw: any): MetricsSetupReceipt {
  if (!raw || !['intentId', 'clusterId', 'workspaceId', 'sourceId'].every(k => isId(raw[k])) || !['native_prometheus', 'collector'].includes(raw.mode) || !hex.test(raw.materialHmac ?? '')
    || !['prepared', 'submitted', 'pending', 'approved', 'executing', 'succeeded', 'partial', 'uncertain', 'failed', 'rejected', 'cancelled', 'expired'].includes(raw.state) || typeof raw.expiresAt !== 'string' || !Number.isFinite(Date.parse(raw.expiresAt))
    || raw.revision !== 1 || raw.workflowId !== null && !isId(raw.workflowId) || raw.workflowId === null && (raw.state !== 'prepared' || raw.planHash !== null)
    || raw.workflowId !== null && (raw.state === 'prepared' || !hex.test(raw.planHash ?? ''))) fail();
  let preview: MetricsSetupPreview | null = null;
  if (raw.preview !== null) {
    const p = raw.preview;
    if (!p || typeof p.confirmationName !== 'string' || !p.confirmationName.trim() || p.confirmationName.length > 128 || !p.source || p.source.id !== raw.sourceId || p.source.type !== 'prometheus' || typeof p.source.name !== 'string' || !p.source.name.trim() || p.source.name.length > 128 || !Number.isSafeInteger(p.source.revision) || p.source.revision < 1
      || !Object.hasOwn(p, 'before') || !Object.hasOwn(p, 'after') || p.nativeRequestsPlanned !== (raw.mode === 'collector' ? 2 : 1) || p.scope?.workspaceId !== raw.workspaceId || p.scope?.defaultWorkspaceOnly !== true || p.scope?.affectsAllWorkspaces !== true || p.credentialsExposed !== false
      || !Array.isArray(p.notices) || !p.notices.length || p.notices.length > 8 || p.notices.some((notice: unknown) => typeof notice !== 'string' || !notice.trim() || notice.length > 512)) fail();
    preview = { confirmationName: p.confirmationName, source: { id: p.source.id, name: p.source.name, type: 'prometheus', revision: p.source.revision }, before: safeJson(p.before), after: safeJson(p.after), nativeRequestsPlanned: p.nativeRequestsPlanned, scope: { workspaceId: raw.workspaceId, defaultWorkspaceOnly: true, affectsAllWorkspaces: true }, credentialsExposed: false, notices: [...p.notices] };
  } else if (raw.workflowId === null || !['succeeded', 'partial', 'uncertain', 'failed', 'rejected', 'cancelled', 'expired'].includes(raw.state)) fail();
  return { intentId: raw.intentId, clusterId: raw.clusterId, workspaceId: raw.workspaceId, sourceId: raw.sourceId, mode: raw.mode, materialHmac: raw.materialHmac, state: raw.state, workflowId: raw.workflowId, revision: raw.revision, planHash: raw.planHash, expiresAt: raw.expiresAt, preview };
}
export function normalizeMetricsSetupSubmission(raw: any, original: Pick<MetricsSetupReceipt, 'intentId' | 'clusterId' | 'workspaceId' | 'materialHmac'>): MetricsSetupSubmission {
  if (!raw || ['intentId', 'clusterId', 'workspaceId', 'materialHmac'].some(k => raw[k] !== original[k as keyof typeof original]) || !isId(raw.intentId) || !isId(raw.clusterId) || !isId(raw.workspaceId) || !hex.test(raw.materialHmac ?? '') || raw.workflowId !== null && !isId(raw.workflowId)
    || !['prepared', 'submitted', 'approved', 'executing', 'succeeded', 'partial', 'uncertain', 'failed', 'rejected', 'cancelled', 'expired'].includes(raw.state) || (raw.workflowId === null) !== (raw.state === 'prepared') || !Array.isArray(raw.steps) || raw.steps.length > 8) fail();
  const steps = raw.steps.map((s: any) => {
    if (!s || !isId(s.id) || typeof s.name !== 'string' || !s.name || s.name.length > 128 || !['pending', 'running', 'succeeded', 'failed', 'uncertain', 'skipped'].includes(s.state) || s.operationId !== null && !isId(s.operationId) || typeof s.remoteStarted !== 'boolean' || typeof s.remoteCompleted !== 'boolean' || s.errorCode !== null && (typeof s.errorCode !== 'string' || !/^[A-Z0-9_]{1,100}$/.test(s.errorCode))) fail();
    return { id: s.id, name: s.name, state: s.state, operationId: s.operationId, remoteStarted: s.remoteStarted, remoteCompleted: s.remoteCompleted, errorCode: s.errorCode };
  });
  return { intentId: raw.intentId, clusterId: raw.clusterId, workspaceId: raw.workspaceId, materialHmac: raw.materialHmac, workflowId: raw.workflowId, state: raw.state, steps };
}
const storageKey = (actor: string): string => { if (!isId(actor)) fail(); return `kongpilot.metricsSetupAttempt:${actor}`; };
function cleanAttempt(raw: any): MetricsSetupAttempt {
  if (!validMetricsSetupIdentity(raw) || !isId(raw.key) || !['direct', 'prepare', 'prepared', 'submit'].includes(raw.phase) || !['pending', 'unknown', 'prepared'].includes(raw.state) || typeof raw.createdAt !== 'string' || !Number.isFinite(Date.parse(raw.createdAt))
    || raw.intentId !== undefined && !isId(raw.intentId) || raw.materialHmac !== undefined && !hex.test(raw.materialHmac) || ['prepared', 'submit'].includes(raw.phase) && (!raw.intentId || !raw.materialHmac) || (raw.phase === 'prepared') !== (raw.state === 'prepared')) fail();
  return { actor: raw.actor, version: raw.version, clusterId: raw.clusterId, workspaceId: raw.workspaceId, key: raw.key, phase: raw.phase, state: raw.state, createdAt: raw.createdAt, ...(raw.intentId ? { intentId: raw.intentId } : {}), ...(raw.materialHmac ? { materialHmac: raw.materialHmac } : {}) };
}
/** The journal contains original identifiers only. It never stores inputs, previews, CSRF or deployment credentials. */
export function readMetricsSetupAttempt(actor: string): MetricsSetupAttempt | undefined {
  const text = sessionStorage.getItem(storageKey(actor)); if (text === null) return;
  let row: MetricsSetupAttempt; try { row = cleanAttempt(JSON.parse(text)); } catch { throw new Error('原监控配置请求记录损坏，请核验审计记录。'); } if (row.actor !== actor) fail(); return row;
}
export function storeMetricsSetupAttempt(raw: MetricsSetupAttempt): void {
  const row = cleanAttempt(raw), prior = readMetricsSetupAttempt(row.actor);
  if (prior && (prior.key !== row.key || prior.state === 'unknown' && row.state !== 'unknown' || JSON.stringify({ ...prior, state: row.state }) !== JSON.stringify(row))) throw new Error('原监控请求尚未核验，不能更换请求键。');
  sessionStorage.setItem(storageKey(row.actor), JSON.stringify(row));
}
export function clearMetricsSetupAttempt(actor: string, key: string): void { const prior = readMetricsSetupAttempt(actor); if (!prior || prior.key !== key) fail(); sessionStorage.removeItem(storageKey(actor)); }
export function markMetricsSetupPrepared(actor: string, key: string, receipt: MetricsSetupReceipt): MetricsSetupAttempt {
  const prior = readMetricsSetupAttempt(actor);
  if (!prior || prior.key !== key || prior.phase !== 'prepare' || receipt.clusterId !== prior.clusterId || receipt.workspaceId !== prior.workspaceId || receipt.state !== 'prepared' || receipt.workflowId !== null || !receipt.preview) fail();
  const row: MetricsSetupAttempt = { ...prior, phase: 'prepared', state: 'prepared', intentId: receipt.intentId, materialHmac: receipt.materialHmac }; sessionStorage.setItem(storageKey(actor), JSON.stringify(row)); return row;
}
export function beginMetricsSetupSubmit(actor: string, priorKey: string, key: string): MetricsSetupAttempt {
  const prior = readMetricsSetupAttempt(actor); if (!prior || prior.key !== priorKey || prior.phase !== 'prepared' || prior.state !== 'prepared' || !isId(key) || key === priorKey) fail();
  const row: MetricsSetupAttempt = { ...prior, key, phase: 'submit', state: 'pending', createdAt: new Date().toISOString() }; sessionStorage.setItem(storageKey(actor), JSON.stringify(row)); return row;
}
export function metricsSetupReceiptMatchesAttempt(receipt: MetricsSetupReceipt, attempt: MetricsSetupAttempt): boolean { return receipt.clusterId === attempt.clusterId && receipt.workspaceId === attempt.workspaceId && (!attempt.intentId || attempt.intentId === receipt.intentId) && (!attempt.materialHmac || attempt.materialHmac === receipt.materialHmac) && (attempt.phase === 'submit' ? receipt.workflowId !== null && receipt.state !== 'prepared' : true); }
export function metricsSetupSubmissionAllowed(receipt: MetricsSetupReceipt | undefined, identity: MetricsSetupIdentity, blocked: boolean, now = Date.now()): boolean { return validMetricsSetupIdentity(identity) && !blocked && !!receipt?.preview && receipt.clusterId === identity.clusterId && receipt.workspaceId === identity.workspaceId && receipt.state === 'prepared' && receipt.workflowId === null && Date.parse(receipt.expiresAt) > now; }
export function metricsSetupWorkflowStatus(state: string): { type: 'success' | 'info' | 'warning' | 'error'; message: string } {
  const statuses: Record<string, { type: 'success' | 'info' | 'warning' | 'error'; message: string }> = {
    submitted: { type: 'success', message: '监控配置已提交审批' }, pending: { type: 'success', message: '监控配置已提交审批' }, approved: { type: 'info', message: '监控配置审批已通过' }, executing: { type: 'info', message: '监控配置正在执行' },
    succeeded: { type: 'success', message: '监控配置工单已完成' }, partial: { type: 'warning', message: '监控配置部分执行，待核验' }, uncertain: { type: 'warning', message: '监控配置执行结果待核验' }, failed: { type: 'error', message: '监控配置工单执行失败' }, rejected: { type: 'warning', message: '监控配置审批已驳回' }, cancelled: { type: 'info', message: '监控配置工单已撤销' }, expired: { type: 'warning', message: '监控配置工单已过期' },
  };
  return statuses[state] ?? { type: 'warning', message: '监控配置工单状态待核验' };
}
