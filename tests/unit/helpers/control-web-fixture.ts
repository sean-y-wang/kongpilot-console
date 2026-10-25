import type { ControlAttempt, ControlChange } from '../../../apps/console-web/src/api/control-changes.model';

// Source-only controlled DTOs. These are not actual sessions or runtime evidence.
export const id = (n: number) => `96000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const actor = id(1), cid = id(2), target = id(3), anchor = id(4), key = id(5), intent = id(6), workflow = id(7), csrf = 'source-only-control-csrf-value';
export const identity = { actor, version: 'source-PV-1' };
export const change: ControlChange = { resource: 'workspaces', operation: 'restore', resourceId: target, input: { revision: 2, confirmed: true, confirm_name: 'Payments' } };
export function rawReceipt(request = change): any {
  const resourceId = request.resourceId ?? id(8), workspaceId = request.resource === 'workspaces' && request.operation !== 'create' ? target : null;
  const before = request.operation === 'create' ? null : { id: resourceId, cluster_id: cid, name: 'Payments', revision: 2, status: request.operation === 'restore' ? 'deleted' : 'active', is_default: false };
  return { intentId: intent, resource: request.resource, operation: request.operation, resourceId, materialHmac: 'a'.repeat(64), state: 'prepared', workflowId: null, revision: null, planHash: null, clusterId: cid, workspaceId: anchor, expiresAt: new Date(Date.now() + 60000).toISOString(), nativeRequestsSent: 0,
    preview: { request, before, after: { resource: request.resource, operation: request.operation, resourceId, input: request.input,
      ...(request.resource === 'workspaces' && request.operation === 'create' ? { builtInRoles: ['workspace-super-admin', 'workspace-admin', 'workspace-read-only'], roleAssignments: 0 } : {}) }, affectedScopes: [{ clusterId: cid, workspaceId, clusterRevision: 3, workspaceRevision: 1 }], confirmationName: 'Payments' } };
}
export function submitted(request = change): any { return { ...rawReceipt(request), state: 'pending', workflowId: workflow, revision: 1, planHash: 'b'.repeat(64) }; }
export function attempt(phase: ControlAttempt['phase'] = 'direct', request = change): ControlAttempt {
  return { ...identity, key, phase, state: phase === 'prepared' ? 'prepared' : 'pending', createdAt: new Date().toISOString(), resource: request.resource, operation: request.operation, clusterId: cid, resourceId: request.resourceId ?? null, targetWorkspaceId: request.resource === 'workspaces' ? target : null,
    ...(['prepared', 'submit'].includes(phase) ? { intentId: intent, materialHmac: 'a'.repeat(64), anchorWorkspaceId: anchor, allocatedResourceId: request.resourceId ?? id(8) } : {}) };
}
export const json = (data: unknown) => new Response(JSON.stringify({ data }), { headers: { 'Content-Type': 'application/json' } });
export const failure = (code = 'APPROVAL_REQUIRED', status = 409) => new Response(JSON.stringify({ error: { code } }), { status, headers: { 'Content-Type': 'application/json' } });
export function capabilities(workspaceId: string | null = target, platformAdmin = false): any {
  return { platformAdmin, modules: {}, clusters: [cid], grants: ['workspaces', 'workflows'].map(module => ({ module, action: 'write', scope_type: workspaceId ? 'workspace' : 'global', cluster_id: cid, workspace_id: workspaceId, scope_values: workspaceId ? [workspaceId] : [] })) };
}
