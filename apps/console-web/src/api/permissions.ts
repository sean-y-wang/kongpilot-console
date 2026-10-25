import type { Capabilities, EffectiveGrant, PermissionAction } from './types';

export interface PermissionScope { clusterId?: string; workspaceId?: string; entityType?: string; entity?: { id?: string; tags?: string[] }; potential?: boolean; }
export function permissionModule(value: string): string {
  if (value === 'targets') return 'upstreams';
  if (['credentials', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'].includes(value)) return 'consumers';
  if (['workspace-migrations', 'workspace_migrations'].includes(value)) return 'workspaces';
  return value;
}
export function permissionEntityTypes(module: string): string[] {
  const core = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'];
  if (module === 'portal') return ['services', 'routes'];
  if (module === 'monitoring') return ['services', 'routes', 'consumers'];
  if (module === 'annotations') return core;
  const all = [...core, 'targets', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
  return module === 'secrets' || module === 'workflows' ? all : all.filter(type => permissionModule(type) === module);
}
export function logicalGrantTag(value: string): string {
  if (value.startsWith('kos-ws-')) return `workspace:${value.slice(7)}`;
  if (!value.startsWith('kos-tag-')) return value;
  try { return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(value.slice(8).replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))); } catch { return value; }
}
export function grantMatches(grant: EffectiveGrant, module: string, action: PermissionAction, scope: PermissionScope): boolean {
  if (grant.module !== permissionModule(module) || grant.action !== action) return false;
  if (grant.cluster_id && grant.cluster_id !== scope.clusterId) return false;
  if (grant.workspace_id && grant.workspace_id !== scope.workspaceId) return false;
  if (grant.scope_type === 'global') return true;
  if (grant.scope_type === 'workspace') return !!scope.workspaceId && grant.scope_values.some(value => typeof value === 'string' && value === scope.workspaceId);
  if (grant.scope_type === 'tag_group') {
    if (scope.potential) return true;
    if (!scope.entity) return false;
    return grant.scope_values.some(value => typeof value === 'string' && scope.entity!.tags?.some(tag => tag === value || tag === logicalGrantTag(value)));
  }
  if (grant.scope_type === 'entity') return !!scope.entity?.id && grant.scope_values.some(value => typeof value !== 'string' && value.entity_type === (scope.entityType ?? module) && value.entity_id === scope.entity!.id);
  return false;
}
export function canInScope(capabilities: Capabilities | undefined, module: string, action: PermissionAction, scope: PermissionScope = {}): boolean {
  if (!capabilities) return false;
  if (capabilities.platformAdmin) return true;
  return capabilities.grants.some(grant => grantMatches(grant, module, action, scope));
}
export function hasModule(capabilities: Capabilities | undefined, module: string, action: PermissionAction = 'read'): boolean { return !!capabilities && (capabilities.platformAdmin || capabilities.modules[permissionModule(module)]?.[action] === true); }
export function canManageRegistry(capabilities: Capabilities | undefined, module: 'clusters' | 'data-sources', action: PermissionAction, clusterId?: string): boolean {
  if (!capabilities) return false;
  if (capabilities.platformAdmin) return true;
  return capabilities.grants.some(grant => grant.module === module && grant.action === action && grant.scope_type === 'global' && !grant.workspace_id && (module === 'clusters' ? !grant.cluster_id : !grant.cluster_id || grant.cluster_id === clusterId));
}
