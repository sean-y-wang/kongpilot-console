import { EntityIdText } from './EntityReference';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';

/** Renders an IAM scope (workspace / cluster / global) by name; unknown ids fall back to an abbreviated id. */
export function ScopeLabel({ clusterId, workspaceId }: { clusterId?: string | null; workspaceId?: string | null }) {
  const { clusters } = useCluster(), { workspaces } = useWorkspace();
  if (workspaceId) { const ws = workspaces.find(item => item.id === workspaceId); return ws?.name ? <span title={workspaceId}>工作区 · {ws.name}</span> : <span>工作区 · <EntityIdText id={workspaceId} /></span>; }
  if (clusterId) { const cluster = clusters.find(item => item.id === clusterId); return cluster?.name ? <span title={clusterId}>集群 · {cluster.name}</span> : <span>集群 · <EntityIdText id={clusterId} /></span>; }
  return <span>全局</span>;
}
