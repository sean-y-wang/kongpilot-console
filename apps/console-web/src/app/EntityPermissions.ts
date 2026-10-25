import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { scopeQuery } from '../api/workspace-scope';
import type { PermissionAction } from '../api/types';
import { useAuth } from './AuthContext';
import { useCluster } from './ClusterContext';
import { useWorkspace } from './WorkspaceContext';

export interface EntityReference { type: string; id: string; parent_id?: string; }
interface EntityAbility extends EntityReference { read: boolean; write: boolean; delete: boolean; approve: boolean; reveal: boolean; }
export function useEntityPermissions(references: EntityReference[]) {
  const { clusterId } = useCluster(), { workspaceId, ready } = useWorkspace(), { user } = useAuth();
  const serialized = JSON.stringify(references.filter(item => item.id).map(item => ({ type: item.type, id: item.id, ...(item.parent_id ? { parent_id: item.parent_id } : {}) })).sort((a, b) => `${a.type}:${a.id}`.localeCompare(`${b.type}:${b.id}`)));
  const query = useQuery({ queryKey: ['entity-permissions', clusterId, workspaceId, user?.permissionsVersion, serialized], queryFn: async () => {
    const entities: EntityReference[] = JSON.parse(serialized), items: EntityAbility[] = [];
    for (let start = 0; start < entities.length; start += 50) { const result = await api<{ items: EntityAbility[]; permissionsVersion: string }>(scopeQuery(`/clusters/${clusterId}/authorization/entity-capabilities`, clusterId, workspaceId), { method: 'POST', body: JSON.stringify({ entities: entities.slice(start, start + 50) }) }); if (result.permissionsVersion !== user?.permissionsVersion) { window.dispatchEvent(new CustomEvent('kongos:permission-stale', { detail: { actorId: user?.id } })); return []; } items.push(...result.items); }
    return items;
  }, enabled: ready && serialized !== '[]' });
  return { query, can: (type: string, id: string | undefined, action: PermissionAction | 'reveal') => !!id && query.data?.some(item => item.type === type && item.id === id && item[action] === true) === true };
}
