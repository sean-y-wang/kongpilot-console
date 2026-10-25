import { canonicalId } from './workspace-scope';

export const iamChangeOperations = ['create', 'update', 'status', 'archive', 'restore', 'permissions', 'clone', 'binding.grant', 'binding.revoke', 'binding.restore', 'member.add', 'member.revoke', 'member.restore'] as const;
export interface IamChangeIdentity { actor: string; version: string; }
export interface IamChangeRequest { resource: 'users' | 'teams' | 'roles'; operation: typeof iamChangeOperations[number]; resourceId?: string; relatedId?: string; input: Record<string, unknown>; }
export interface IamChangeAttempt extends IamChangeIdentity { key: string; phase: 'direct' | 'prepare' | 'prepared' | 'submit'; state: 'pending' | 'unknown' | 'prepared'; createdAt: string; intentId?: string; materialHmac?: string; }
export interface IamChangeScope { clusterId: string; workspaceId: string | null; executionMode: 'direct' | 'approval'; revision: number; workspaceRevision: number | null; }
export interface IamChangePreview { request: IamChangeRequest; before: unknown; after: unknown; affectedScopes: IamChangeScope[]; confirmationName: string; }
export interface IamChangeReceipt { intentId: string; resource: IamChangeRequest['resource']; operation: IamChangeRequest['operation']; resourceId: string | null; materialHmac: string; state: string; workflowId: string | null; revision: number | null; planHash: string | null; clusterId: string; workspaceId: string; expiresAt: string; nativeRequestsSent: 0; preview: IamChangePreview | null; }

const hex = /^[a-f\d]{64}$/;
function fail(): never { throw new Error('身份变更记录无效，请核验原请求。'); }
export function validIamIdentity(value: IamChangeIdentity): boolean { return canonicalId(value.actor) === value.actor && typeof value.version === 'string' && !!value.version && value.version.length <= 256; }
export function normalizeIamChangeRequest(raw: IamChangeRequest): IamChangeRequest {
  if (!raw || !['users', 'teams', 'roles'].includes(raw.resource) || !iamChangeOperations.includes(raw.operation) || !raw.input || typeof raw.input !== 'object' || Array.isArray(raw.input)
    || Object.keys(raw).some(k => !['resource', 'operation', 'resourceId', 'relatedId', 'input'].includes(k)) || (raw.operation !== 'create') !== !!raw.resourceId || raw.resourceId !== undefined && canonicalId(raw.resourceId) !== raw.resourceId
    || ['binding.revoke', 'binding.restore', 'member.revoke', 'member.restore'].includes(raw.operation) !== !!raw.relatedId || raw.relatedId !== undefined && canonicalId(raw.relatedId) !== raw.relatedId
    || raw.operation.startsWith('member.') && raw.resource !== 'teams' || ['permissions', 'clone'].includes(raw.operation) && raw.resource !== 'roles' || raw.operation.startsWith('binding.') && raw.resource === 'roles') fail();
  const fields: Record<string, readonly string[]> = {
    create: raw.resource === 'users' ? ['username', 'password', 'display_name', 'email'] : ['code', 'name', 'description', 'cluster_id', 'workspace_id'],
    update: raw.resource === 'users' ? ['revision', 'display_name', 'email'] : ['revision', 'name', 'description'], status: ['revision', 'confirmed', 'confirm_name', 'status'],
    archive: ['revision', 'confirmed', 'confirm_name'], restore: ['revision', 'confirmed', 'confirm_name'], permissions: ['revision', 'permissions'],
    clone: ['code', 'name', 'cluster_id', 'workspace_id'], 'binding.grant': ['role_id', 'cluster_id', 'workspace_id', 'expires_at'],
    'binding.revoke': ['revision', 'confirmed', 'confirm_name'], 'binding.restore': ['revision', 'confirmed', 'confirm_name'],
    'member.add': ['user_id'], 'member.revoke': ['revision', 'confirmed', 'confirm_name'], 'member.restore': ['revision', 'confirmed', 'confirm_name'],
  };
  if (Object.keys(raw.input).some(k => !fields[raw.operation].includes(k))) fail();
  let input: Record<string, unknown>; try { const text = JSON.stringify(raw.input); if (text.length > 524288) fail(); input = JSON.parse(text); } catch { return fail(); }
  return { resource: raw.resource, operation: raw.operation, ...(raw.resourceId ? { resourceId: raw.resourceId } : {}), ...(raw.relatedId ? { relatedId: raw.relatedId } : {}), input };
}
export function iamDirectCommand(raw: IamChangeRequest): { path: string; method: 'POST' | 'PATCH' | 'PUT' | 'DELETE'; body: Record<string, unknown> } {
  const r = normalizeIamChangeRequest(raw), base = `/iam/${r.resource}${r.resourceId ? `/${r.resourceId}` : ''}`, suffix: Record<string, string> = { status: '/status', restore: '/restore', permissions: '/permissions', clone: '/clone', 'binding.grant': '/role-bindings', 'binding.revoke': `/role-bindings/${r.relatedId}`, 'binding.restore': `/role-bindings/${r.relatedId}/restore`, 'member.add': '/members', 'member.revoke': `/members/${r.relatedId}`, 'member.restore': `/members/${r.relatedId}/restore` };
  return { path: `${base}${suffix[r.operation] ?? ''}`, method: r.operation === 'update' ? 'PATCH' : r.operation === 'permissions' ? 'PUT' : ['archive', 'binding.revoke', 'member.revoke'].includes(r.operation) ? 'DELETE' : 'POST', body: r.input };
}
export function normalizeIamChangeReceipt(raw: any): IamChangeReceipt {
  if (!raw || !['intentId', 'clusterId', 'workspaceId'].every(k => canonicalId(raw[k]) === raw[k]) || !['users', 'teams', 'roles'].includes(raw.resource) || !iamChangeOperations.includes(raw.operation)
    || raw.resourceId !== null && canonicalId(raw.resourceId) !== raw.resourceId || !hex.test(raw.materialHmac ?? '') || !['prepared', 'pending', 'approved', 'executing', 'succeeded', 'partial', 'uncertain', 'failed', 'rejected', 'cancelled', 'expired'].includes(raw.state)
    || raw.nativeRequestsSent !== 0 || typeof raw.expiresAt !== 'string' || !Number.isFinite(Date.parse(raw.expiresAt)) || raw.workflowId !== null && canonicalId(raw.workflowId) !== raw.workflowId
    || raw.workflowId === null && (raw.revision !== null || raw.planHash !== null || raw.state !== 'prepared') || raw.workflowId !== null && (raw.state === 'prepared' || !Number.isSafeInteger(raw.revision) || raw.revision < 1 || !hex.test(raw.planHash ?? ''))) fail();
  const p = raw.preview;
  if (p === null && raw.workflowId !== null && ['succeeded', 'failed', 'cancelled', 'rejected', 'expired'].includes(raw.state)) return { intentId: raw.intentId, resource: raw.resource, operation: raw.operation, resourceId: raw.resourceId, materialHmac: raw.materialHmac, state: raw.state, workflowId: raw.workflowId, revision: raw.revision, planHash: raw.planHash, clusterId: raw.clusterId, workspaceId: raw.workspaceId, expiresAt: raw.expiresAt, nativeRequestsSent: 0, preview: null };
  if (!p || !Object.hasOwn(p, 'before') || !Object.hasOwn(p, 'after') || !Array.isArray(p.affectedScopes) || !p.affectedScopes.length || p.affectedScopes.length > 512
    || typeof p.confirmationName !== 'string' || !p.confirmationName.trim() || p.confirmationName.length > 128) fail();
  const request = normalizeIamChangeRequest(p.request);
  if (request.resource !== raw.resource || request.operation !== raw.operation || (request.resourceId ?? null) !== raw.resourceId || request.resource === 'users' && !request.operation.startsWith('binding.')) fail();
  const affectedScopes = p.affectedScopes.map((s: any) => {
    if (!s || canonicalId(s.clusterId) !== s.clusterId || s.workspaceId !== null && canonicalId(s.workspaceId) !== s.workspaceId || !['direct', 'approval'].includes(s.executionMode) || !Number.isSafeInteger(s.revision) || s.revision < 1 || s.workspaceRevision !== null && (!Number.isSafeInteger(s.workspaceRevision) || s.workspaceRevision < 1) || (s.workspaceId === null) !== (s.workspaceRevision === null)) fail();
    return { clusterId: s.clusterId, workspaceId: s.workspaceId, executionMode: s.executionMode, revision: s.revision, workspaceRevision: s.workspaceRevision };
  });
  return { intentId: raw.intentId, resource: raw.resource, operation: raw.operation, resourceId: raw.resourceId, materialHmac: raw.materialHmac, state: raw.state, workflowId: raw.workflowId, revision: raw.revision, planHash: raw.planHash, clusterId: raw.clusterId, workspaceId: raw.workspaceId, expiresAt: raw.expiresAt, nativeRequestsSent: 0, preview: { request, before: p.before, after: p.after, affectedScopes, confirmationName: p.confirmationName } };
}
const keyFor = (actor: string): string => { if (canonicalId(actor) !== actor) fail(); return `kongpilot.iamChangeAttempt:${actor}`; };
function cleanAttempt(raw: any): IamChangeAttempt {
  if (!raw || !validIamIdentity(raw) || canonicalId(raw.key) !== raw.key || !['direct', 'prepare', 'prepared', 'submit'].includes(raw.phase) || !['pending', 'unknown', 'prepared'].includes(raw.state)
    || typeof raw.createdAt !== 'string' || !Number.isFinite(Date.parse(raw.createdAt)) || raw.intentId !== undefined && canonicalId(raw.intentId) !== raw.intentId || raw.materialHmac !== undefined && !hex.test(raw.materialHmac)
    || ['prepared', 'submit'].includes(raw.phase) && (!raw.intentId || !raw.materialHmac) || (raw.phase === 'prepared') !== (raw.state === 'prepared')) fail();
  return { actor: raw.actor, version: raw.version, key: raw.key, phase: raw.phase, state: raw.state, createdAt: raw.createdAt, ...(raw.intentId ? { intentId: raw.intentId } : {}), ...(raw.materialHmac ? { materialHmac: raw.materialHmac } : {}) };
}
/** Only original identifiers persist. Inputs, passwords, CSRF, previews and grant rows never enter the journal. */
export function readIamAttempt(actor: string): IamChangeAttempt | undefined {
  const text = sessionStorage.getItem(keyFor(actor)); if (text === null) return;
  let row: IamChangeAttempt; try { row = cleanAttempt(JSON.parse(text)); } catch { throw new Error('原身份请求记录损坏，请核验审计记录。'); }
  if (row.actor !== actor) fail(); return row;
}
export function storeIamAttempt(raw: IamChangeAttempt): void { const row = cleanAttempt(raw), prior = readIamAttempt(row.actor); if (prior && (prior.key !== row.key || prior.state === 'unknown' && row.state !== 'unknown' || JSON.stringify({ ...prior, state: row.state }) !== JSON.stringify(row))) throw new Error('原请求尚未核验，不能更换请求键。'); sessionStorage.setItem(keyFor(row.actor), JSON.stringify(row)); }
export function clearIamAttempt(actor: string, key: string): void { const prior = readIamAttempt(actor); if (!prior || prior.key !== key) fail(); sessionStorage.removeItem(keyFor(actor)); }
export function markIamPrepared(actor: string, key: string, receipt: IamChangeReceipt): IamChangeAttempt {
  const prior = readIamAttempt(actor); if (!prior || prior.key !== key || prior.phase !== 'prepare' || receipt.state !== 'prepared' || receipt.workflowId !== null) fail();
  const row: IamChangeAttempt = { ...prior, phase: 'prepared', state: 'prepared', intentId: receipt.intentId, materialHmac: receipt.materialHmac }; sessionStorage.setItem(keyFor(actor), JSON.stringify(row)); return row;
}
export function beginIamSubmit(actor: string, priorKey: string, key: string): IamChangeAttempt {
  const prior = readIamAttempt(actor); if (!prior || prior.key !== priorKey || prior.phase !== 'prepared' || prior.state !== 'prepared' || canonicalId(key) !== key || key === priorKey) fail();
  const row: IamChangeAttempt = { ...prior, key, phase: 'submit', state: 'pending', createdAt: new Date().toISOString() }; sessionStorage.setItem(keyFor(actor), JSON.stringify(row)); return row;
}
export function iamReceiptMatchesAttempt(receipt: IamChangeReceipt, attempt: IamChangeAttempt): boolean { return (!attempt.intentId || attempt.intentId === receipt.intentId) && (!attempt.materialHmac || attempt.materialHmac === receipt.materialHmac) && (attempt.phase === 'submit' ? receipt.workflowId !== null && receipt.state !== 'prepared' : true); }
export function iamPreparedSubmissionAllowed(receipt: IamChangeReceipt | undefined, blockedByOriginalIam: boolean, readonlyScopes: readonly { clusterId: string; workspaceId: string }[], now = Date.now()): boolean {
  return !!receipt && receipt.state === 'prepared' && receipt.workflowId === null && !!receipt.preview && Date.parse(receipt.expiresAt) > now && !blockedByOriginalIam
    && !readonlyScopes.some(s => s.clusterId === receipt.clusterId && s.workspaceId === receipt.workspaceId || receipt.preview!.affectedScopes.some(a => a.clusterId === s.clusterId && a.workspaceId === s.workspaceId));
}
