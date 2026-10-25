import { canonicalId } from './workspace-scope';
import { canInScope, canManageRegistry, grantMatches } from './permissions';
import { redactForDisplay } from './redaction';
import type { Capabilities } from './types';

export type ControlResource = 'clusters' | 'data-sources' | 'workspaces' | 'recycle-bin';
export type ControlOperation = 'create' | 'update' | 'deactivate' | 'archive' | 'restore' | 'purge';
export interface ControlIdentity { actor: string; version: string; }
export interface ControlChange { resource: ControlResource; operation: ControlOperation; resourceId?: string; input: Record<string, unknown>; }
export interface ControlScope { clusterId: string; workspaceId: string | null; clusterRevision: number; workspaceRevision: number; }
export interface ControlReceipt {
  intentId: string; resource: ControlResource; operation: ControlOperation; resourceId: string; materialHmac: string; state: string;
  workflowId: string | null; revision: number | null; planHash: string | null; clusterId: string; workspaceId: string; expiresAt: string; nativeRequestsSent: 0;
  preview: null | { request: ControlChange; before: unknown; after: { resource: ControlResource; operation: ControlOperation; resourceId: string; input: unknown; authentication?: { mode: 'none' | 'bearer' | 'basic' | 'header'; materialHmac: string }; builtInRoles?: string[]; roleAssignments?: 0 }; affectedScopes: ControlScope[]; confirmationName: string };
}
export interface ControlAttempt extends ControlIdentity {
  key: string; phase: 'direct' | 'prepare' | 'prepared' | 'submit'; state: 'pending' | 'unknown' | 'prepared'; createdAt: string;
  resource: ControlResource; operation: ControlOperation; clusterId: string | null; resourceId: string | null; targetWorkspaceId: string | null;
  intentId?: string; materialHmac?: string; anchorWorkspaceId?: string; allocatedResourceId?: string;
}
const object = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
const id = (v: unknown): v is string => typeof v === 'string' && canonicalId(v) === v;
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f\d]{64}$/.test(v);
const positive = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) > 0;
function fail(): never { throw new Error('配置变更记录无效，请核验原请求。'); }
export function validControlIdentity(v: ControlIdentity) { return id(v.actor) && typeof v.version === 'string' && !!v.version && v.version.length <= 256; }
export function normalizeControlChange(raw: ControlChange, allowClusterCreate = false): ControlChange {
  if (!object(raw) || !['clusters', 'data-sources', 'workspaces', 'recycle-bin'].includes(raw.resource) || !object(raw.input)
    || Object.keys(raw).some(k => !['resource', 'operation', 'resourceId', 'input'].includes(k))
    || !({ clusters: allowClusterCreate ? ['create', 'update', 'deactivate'] : ['update', 'deactivate'], 'data-sources': ['create', 'update', 'deactivate'], workspaces: ['create', 'update', 'archive', 'restore'], 'recycle-bin': ['purge'] }[raw.resource]).includes(raw.operation)
    || (raw.operation !== 'create') !== !!raw.resourceId || raw.resourceId !== undefined && !id(raw.resourceId)) fail();
  const fields = raw.resource === 'recycle-bin' ? ['revision', 'confirmed', 'confirm_name', 'workspaceId'] : raw.operation === 'deactivate' ? ['revision', 'confirm', 'confirm_name'] : ['archive', 'restore', 'purge'].includes(raw.operation) ? ['revision', 'confirmed', 'confirm_name']
    : raw.resource === 'clusters' ? ['name', 'environment', 'admin_url', 'proxy_origin', 'labels', 'execution_mode', 'connection_auth', ...(raw.operation === 'update' ? ['revision'] : [])]
    : raw.resource === 'data-sources' ? ['name', 'type', 'base_url', 'enabled', 'auth', ...(raw.operation === 'update' ? ['revision'] : [])]
    : raw.operation === 'create' ? ['code', 'name', 'owner_user_id', 'description'] : ['revision', 'name', 'owner_user_id', 'description', 'status'];
  if (Object.keys(raw.input).some(k => !fields.includes(k)) || raw.operation !== 'create' && !positive(raw.input.revision)
    || raw.operation === 'deactivate' && (raw.input.confirm !== true || typeof raw.input.confirm_name !== 'string' || !raw.input.confirm_name)
    || ['archive', 'restore', 'purge'].includes(raw.operation) && (raw.input.confirmed !== true || typeof raw.input.confirm_name !== 'string' || !raw.input.confirm_name)) fail();
  if (raw.resource === 'recycle-bin' && !id(raw.input.workspaceId)) fail();
  let input: Record<string, unknown>; try { const text = JSON.stringify(raw.input); if (text.length > 1048576) fail(); input = JSON.parse(text); } catch { return fail(); }
  return { resource: raw.resource, operation: raw.operation, ...(raw.resourceId ? { resourceId: raw.resourceId } : {}), input };
}
export function controlDirectCommand(raw: ControlChange, cid: string | null, originalWorkspaceId: string | null) {
  const r = normalizeControlChange(raw, true), creating = r.operation === 'create';
  if (!(r.resource === 'clusters' && creating) && !id(cid) || r.resource === 'clusters' && !creating && r.resourceId !== cid) fail();
  const base = r.resource === 'clusters' ? `/clusters${creating ? '' : `/${r.resourceId}`}` : `/clusters/${cid}/${r.resource}${creating ? '' : `/${r.resourceId}`}`;
  let path = `${base}${r.operation === 'deactivate' ? '/deactivate' : r.operation === 'restore' ? '/restore' : r.operation === 'purge' ? '/purge' : ''}`;
  if (r.resource === 'recycle-bin') { if (!id(originalWorkspaceId) || originalWorkspaceId !== r.input.workspaceId) fail(); path += `?workspaceId=${originalWorkspaceId}`; }
  if (r.resource === 'workspaces') { if (!id(originalWorkspaceId) || !creating && originalWorkspaceId !== r.resourceId) fail(); path += `?workspaceId=${originalWorkspaceId}`; }
  return { path, method: (r.operation === 'update' ? 'PATCH' : r.operation === 'archive' ? 'DELETE' : 'POST') as 'POST' | 'PATCH' | 'DELETE', body: r.input };
}
export function normalizeControlReceipt(raw: any): ControlReceipt {
  if (!object(raw) || !['intentId', 'resourceId', 'clusterId', 'workspaceId'].every(k => id(raw[k])) || !hex(raw.materialHmac) || raw.nativeRequestsSent !== 0
    || !['prepared', 'pending', 'approved', 'executing', 'succeeded', 'partial', 'uncertain', 'failed', 'rejected', 'cancelled', 'expired'].includes(raw.state)
    || typeof raw.expiresAt !== 'string' || !Number.isFinite(Date.parse(raw.expiresAt)) || raw.workflowId !== null && !id(raw.workflowId)
    || raw.workflowId === null && (raw.state !== 'prepared' || raw.revision !== null || raw.planHash !== null)
    || raw.workflowId !== null && (raw.state === 'prepared' || !positive(raw.revision) || !hex(raw.planHash))) fail();
  const base = { intentId: raw.intentId, resource: raw.resource, operation: raw.operation, resourceId: raw.resourceId, materialHmac: raw.materialHmac, state: raw.state, workflowId: raw.workflowId, revision: raw.revision, planHash: raw.planHash, clusterId: raw.clusterId, workspaceId: raw.workspaceId, expiresAt: raw.expiresAt, nativeRequestsSent: 0 as const };
  if (!['clusters', 'data-sources', 'workspaces', 'recycle-bin'].includes(raw.resource) || !['create', 'update', 'deactivate', 'archive', 'restore', 'purge'].includes(raw.operation)
    || raw.resource === 'clusters' && (!['update', 'deactivate'].includes(raw.operation) || raw.resourceId !== raw.clusterId)
    || raw.resource === 'data-sources' && !['create', 'update', 'deactivate'].includes(raw.operation)
    || raw.resource === 'workspaces' && !['create', 'update', 'archive', 'restore'].includes(raw.operation)) fail();
  if (raw.preview === null && raw.state === 'succeeded' && raw.workflowId !== null) return { ...base, preview: null };
  const p = raw.preview;
  if (!object(p) || !Object.hasOwn(p, 'before') || !object(p.after) || !Array.isArray(p.affectedScopes) || p.affectedScopes.length !== 1
    || typeof p.confirmationName !== 'string' || !p.confirmationName.trim() || p.confirmationName.length > (raw.resource === 'recycle-bin' ? 1024 : 128)) fail();
  const request = normalizeControlChange(p.request);
  if (request.resource !== raw.resource || request.operation !== raw.operation || request.resourceId !== undefined && request.resourceId !== raw.resourceId
    || p.after.resource !== raw.resource || p.after.operation !== raw.operation || p.after.resourceId !== raw.resourceId || !object(p.after.input)
    || request.operation === 'create' && p.before !== null || request.operation !== 'create' && (!object(p.before) || p.before.id !== raw.resourceId || p.before.revision !== request.input.revision)) fail();
  const affectedScopes = p.affectedScopes.map((s: any) => {
    if (!object(s) || s.clusterId !== raw.clusterId || s.workspaceId !== null && !id(s.workspaceId) || !positive(s.clusterRevision) || !positive(s.workspaceRevision)
      || s.workspaceId !== (request.resource === 'recycle-bin' ? request.input.workspaceId : request.resource === 'workspaces' && request.operation !== 'create' ? request.resourceId : null)) fail();
    return { clusterId: s.clusterId, workspaceId: s.workspaceId, clusterRevision: s.clusterRevision, workspaceRevision: s.workspaceRevision };
  });
  let authentication: NonNullable<ControlReceipt['preview']>['after']['authentication'];
  if (p.after.authentication !== undefined) { const a = p.after.authentication; if (!['clusters', 'data-sources'].includes(request.resource) || !object(a) || !['none', 'bearer', 'basic', 'header'].includes(a.mode) || !hex(a.materialHmac) || Object.keys(a).some(k => !['mode', 'materialHmac'].includes(k))) fail(); authentication = { mode: a.mode, materialHmac: a.materialHmac }; }
  let roles: string[] | undefined;
  if (request.resource === 'workspaces' && request.operation === 'create' || p.after.builtInRoles !== undefined || p.after.roleAssignments !== undefined) { if (request.resource !== 'workspaces' || request.operation !== 'create' || JSON.stringify(p.after.builtInRoles) !== JSON.stringify(['workspace-super-admin', 'workspace-admin', 'workspace-read-only']) || p.after.roleAssignments !== 0) fail(); roles = [...p.after.builtInRoles]; }
  if (object(p.before) && p.before.authenticationConfigured !== undefined && typeof p.before.authenticationConfigured !== 'boolean') fail();
  return { ...base, preview: { request: { ...request, input: redactForDisplay(request.input) as Record<string, unknown> }, before: redactForDisplay(p.before), after: { resource: p.after.resource, operation: p.after.operation, resourceId: p.after.resourceId, input: redactForDisplay(p.after.input), ...(authentication ? { authentication } : {}), ...(roles ? { builtInRoles: roles, roleAssignments: 0 as const } : {}) }, affectedScopes, confirmationName: p.confirmationName } };
}
function whole(cap: Capabilities | undefined, module: string, action: 'write', cid: string, wid: string | null) {
  return !!cap && (cap.platformAdmin || cap.grants.some(g => grantMatches(g, module, action, { clusterId: cid, workspaceId: wid ?? undefined })
    && (g.scope_type === 'global' && g.workspace_id === null || wid !== null && g.scope_type === 'workspace' && g.cluster_id === cid && g.workspace_id === wid && g.scope_values.length === 1 && g.scope_values[0] === wid)));
}
/** The target scope remains distinct from the BFF's active workflow anchor. */
export function controlPreparedAllowed(row: ControlReceipt | undefined, capabilities: Capabilities | undefined, blocked: boolean, now = Date.now()) {
  if (!row?.preview || row.state !== 'prepared' || row.workflowId !== null || Date.parse(row.expiresAt) <= now || blocked) return false;
  const target = row.preview.affectedScopes[0].workspaceId, r = row.preview.request, action = ['archive', 'deactivate', 'purge'].includes(r.operation) ? 'delete' : 'write';
  const subject = r.resource === 'workspaces' ? r.operation === 'create' ? whole(capabilities, 'workspaces', 'write', row.clusterId, null)
    : canInScope(capabilities, 'workspaces', action, { clusterId: row.clusterId, workspaceId: target ?? undefined, entityType: 'workspaces', entity: row.preview.before as any })
    : r.resource === 'recycle-bin' ? canInScope(capabilities, 'recycle-bin', 'delete', {clusterId:row.clusterId,workspaceId:target??undefined,potential:true,entityType:(row.preview.before as any)?.root_type,entity:{id:(row.preview.before as any)?.original_id}})
    : canManageRegistry(capabilities, r.resource, action, row.clusterId);
  return subject && whole(capabilities, 'workflows', 'write', row.clusterId, target);
}
const keyFor = (actor: string) => { if (!id(actor)) fail(); return `kongpilot.controlChangeAttempt:${actor}`; };
function cleanAttempt(v: any): ControlAttempt {
  if (!object(v) || !validControlIdentity(v as ControlIdentity) || !id(v.key) || !['direct', 'prepare', 'prepared', 'submit'].includes(v.phase)
    || !['pending', 'unknown', 'prepared'].includes(v.state) || !['clusters', 'data-sources', 'workspaces', 'recycle-bin'].includes(v.resource) || !['create', 'update', 'deactivate', 'archive', 'restore', 'purge'].includes(v.operation)
    || v.clusterId !== null && !id(v.clusterId) || v.resourceId !== null && !id(v.resourceId) || v.targetWorkspaceId !== null && !id(v.targetWorkspaceId)
    || (v.resource === 'recycle-bin') !== (v.operation === 'purge')
    || v.clusterId === null && !(v.resource === 'clusters' && v.operation === 'create') || (v.operation !== 'create') !== (v.resourceId !== null)
    || typeof v.createdAt !== 'string' || !Number.isFinite(Date.parse(v.createdAt)) || ['intentId', 'anchorWorkspaceId', 'allocatedResourceId'].some(k => v[k] !== undefined && !id(v[k]))
    || v.materialHmac !== undefined && !hex(v.materialHmac) || ['prepared', 'submit'].includes(v.phase) && (!v.intentId || !v.materialHmac || !v.anchorWorkspaceId || !v.allocatedResourceId)
    || (v.phase === 'prepared') !== (v.state === 'prepared')) fail();
  return { actor: v.actor, version: v.version, key: v.key, phase: v.phase, state: v.state, createdAt: v.createdAt, resource: v.resource, operation: v.operation, clusterId: v.clusterId, resourceId: v.resourceId, targetWorkspaceId: v.targetWorkspaceId,
    ...(v.intentId ? { intentId: v.intentId } : {}), ...(v.materialHmac ? { materialHmac: v.materialHmac } : {}), ...(v.anchorWorkspaceId ? { anchorWorkspaceId: v.anchorWorkspaceId } : {}), ...(v.allocatedResourceId ? { allocatedResourceId: v.allocatedResourceId } : {}) };
}
export function readControlAttempt(actor: string): ControlAttempt | undefined { const text = sessionStorage.getItem(keyFor(actor)); if (text === null) return; let row: ControlAttempt; try { row = cleanAttempt(JSON.parse(text)); } catch { throw new Error('原配置请求记录损坏，请核验原记录。'); } if (row.actor !== actor) fail(); return row; }
export function storeControlAttempt(raw: ControlAttempt) { const row = cleanAttempt(raw), prior = readControlAttempt(row.actor); if (prior && (prior.key !== row.key || prior.state === 'unknown' && row.state !== 'unknown' || JSON.stringify({ ...prior, state: row.state }) !== JSON.stringify(row))) fail(); sessionStorage.setItem(keyFor(row.actor), JSON.stringify(row)); }
export function clearControlAttempt(actor: string, key: string) { const prior = readControlAttempt(actor); if (!prior || prior.key !== key) fail(); sessionStorage.removeItem(keyFor(actor)); }
export function advanceControlPrepare(actor: string, key: string) { const prior = readControlAttempt(actor); if (!prior || prior.key !== key || prior.phase !== 'direct' || prior.state !== 'pending' || prior.resource === 'clusters' && prior.operation === 'create') fail(); const row: ControlAttempt = { ...prior, phase: 'prepare' }; sessionStorage.setItem(keyFor(actor), JSON.stringify(row)); return row; }
export function controlReceiptMatches(row: ControlReceipt, attempt: ControlAttempt) { return row.clusterId === attempt.clusterId && row.resource === attempt.resource && row.operation === attempt.operation && (attempt.resourceId === null || row.resourceId === attempt.resourceId)
  && (!attempt.intentId || row.intentId === attempt.intentId) && (!attempt.materialHmac || row.materialHmac === attempt.materialHmac) && (!attempt.anchorWorkspaceId || row.workspaceId === attempt.anchorWorkspaceId)
  && (!attempt.allocatedResourceId || row.resourceId === attempt.allocatedResourceId) && (attempt.phase !== 'submit' || row.workflowId !== null && row.state !== 'prepared'); }
export function markControlPrepared(actor: string, key: string, row: ControlReceipt) { const prior = readControlAttempt(actor); if (!prior || prior.key !== key || prior.phase !== 'prepare' || !controlReceiptMatches(row, prior) || row.state !== 'prepared' || row.workflowId !== null || !row.preview) fail(); const next: ControlAttempt = { ...prior, phase: 'prepared', state: 'prepared', intentId: row.intentId, materialHmac: row.materialHmac, anchorWorkspaceId: row.workspaceId, allocatedResourceId: row.resourceId }; sessionStorage.setItem(keyFor(actor), JSON.stringify(next)); return next; }
export function beginControlSubmit(actor: string, key: string, newKey: string) { const prior = readControlAttempt(actor); if (!prior || prior.key !== key || prior.phase !== 'prepared' || prior.state !== 'prepared' || !id(newKey) || key === newKey) fail(); const next: ControlAttempt = { ...prior, phase: 'submit', state: 'pending', key: newKey, createdAt: new Date().toISOString() }; sessionStorage.setItem(keyFor(actor), JSON.stringify(next)); return next; }
