export type PermissionAction = 'read' | 'write' | 'delete' | 'approve';
export interface EffectiveGrant { cluster_id: string | null; workspace_id: string | null; module: string; action: PermissionAction; scope_type: 'global' | 'workspace' | 'tag_group' | 'entity'; scope_values: Array<string | { entity_type: string; entity_id: string }>; role_id?: string; role_code?: string; binding_source?: 'user' | 'team'; }
export interface Capabilities { modules: Record<string, Record<PermissionAction, boolean>>; grants: EffectiveGrant[]; clusters: string[]; platformAdmin: boolean; }
export interface User { id: string; username: string; superAdmin: boolean; permissionsVersion?: string; capabilities?: Capabilities; displayName?: string | null; locale?: string; timezone?: string; revision?: number; forcePasswordChange?: boolean; }
export interface Session { user: User; csrfToken: string; }
export interface Cluster {
  id: string;
  name: string;
  environment: string;
  admin_url: string;
  proxy_origin?: string | null;
  labels: string[];
  execution_mode: 'direct' | 'approval';
  status: string;
  version?: string | null;
  capabilities: Record<string, unknown>;
  enabled_plugins: string[];
  last_probed_at?: string | null;
  created_at?: string;
  revision?: number;
}
export interface DataSource {
  id: string;
  cluster_id: string;
  name: string;
  type: 'prometheus' | 'loki';
  base_url: string;
  enabled: boolean;
  last_status: string;
  last_probed_at?: string | null;
  revision?: number;
}

export function listData<T>(value: T[] | { items?: T[]; data?: T[] }): T[] {
  return Array.isArray(value) ? value : value.items ?? value.data ?? [];
}

export function normalizeCluster(raw: any): Cluster {
  return {
    ...raw,
    admin_url: raw.admin_url ?? raw.adminUrl,
    execution_mode: raw.execution_mode ?? raw.executionMode,
    labels: raw.labels ?? [],
    capabilities: raw.capabilities ?? {},
    enabled_plugins: raw.enabled_plugins ?? raw.enabledPlugins ?? [],
    last_probed_at: raw.last_probed_at ?? raw.lastProbedAt,
  };
}
