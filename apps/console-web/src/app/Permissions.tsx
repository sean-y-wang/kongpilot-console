import { Alert } from 'antd';
import { useAuth } from './AuthContext';
import { useOptionalCluster } from './ClusterContext';
import { useOptionalWorkspace } from './WorkspaceContext';
import { canInScope, canManageRegistry, hasModule, type PermissionScope } from '../api/permissions';
import type { PermissionAction } from '../api/types';

export function usePermissions() {
  const { user } = useAuth();
  const cluster = useOptionalCluster(), workspace = useOptionalWorkspace();
  const current = { clusterId: cluster?.clusterId, workspaceId: workspace?.workspaceId };
  return {
    version: user?.permissionsVersion,
    platformAdmin: !!user?.capabilities?.platformAdmin,
    has: (module: string, action: PermissionAction = 'read') => hasModule(user?.capabilities, module, action),
    registry: (module: 'clusters' | 'data-sources', action: PermissionAction, clusterId?: string) => canManageRegistry(user?.capabilities, module, action, clusterId),
    can: (module: string, action: PermissionAction, entity?: any, scope: PermissionScope = {}) => canInScope(user?.capabilities, module, action, { ...current, entityType: module, entity, ...scope }),
    create: (module: string, scope: PermissionScope = {}) => canInScope(user?.capabilities, module, 'write', { ...current, entityType: module, potential: true, ...scope }),
  };
}
export function PermissionGate({ module, children }: { module: string; children: React.ReactNode }) { const permission = usePermissions(); return permission.has(module) ? <>{children}</> : <Alert showIcon type="warning" message="当前账号没有此模块的读取权限" description="请联系有权管理此范围的管理员。后端会继续校验集群、工作区与对象权限。" />; }
