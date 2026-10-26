import { Button, Tag, Tooltip, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { scopeQuery } from '../api/workspace-scope';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';

export interface EntityRefLabel { type: string; id: string; visible: boolean; label?: string; detail?: string; expires_at?: string; expired?: boolean }
export type EntityRefMap = Map<string, EntityRefLabel>;
export const refKey = (type: string, id: string) => `${type}:${id}`;

/** One batched request per page/drawer resolves every referenced ID to a
 * readable label; the server applies the same read permissions as detail
 * reads, so entities the actor cannot see come back ID-only. */
export function useEntityReferences(refs: Array<{ type: string; id?: string | null }>): EntityRefMap {
  const { clusterId } = useCluster();
  const { workspaceId, ready } = useWorkspace();
  const unique = [...new Map(refs.filter(r => r.id).map(r => [refKey(r.type, r.id!), { type: r.type, id: r.id! }])).values()].sort((a, b) => refKey(a.type, a.id).localeCompare(refKey(b.type, b.id))).slice(0, 100);
  const query = useQuery({
    queryKey: ['entity-references', clusterId, workspaceId, unique.map(r => refKey(r.type, r.id)).join(',')],
    queryFn: () => api<{ items: EntityRefLabel[] }>(scopeQuery(`/clusters/${clusterId}/entity-references/resolve`, clusterId, workspaceId), { method: 'POST', body: JSON.stringify({ refs: unique }) }),
    enabled: ready && !!clusterId && unique.length > 0, staleTime: 30_000,
  });
  return new Map((query.data?.items ?? []).map(item => [refKey(item.type, item.id), item]));
}

const shortId = (id: string) => id.length > 12 ? `${id.slice(0, 8)}…` : id;

/** Readable reference: name first, ID as secondary text/tooltip, click to open. */
export function EntityRef({ type, id, refs, compact }: { type: string; id?: string | null; refs: EntityRefMap; compact?: boolean }) {
  const navigate = useNavigate();
  if (!id) return <Typography.Text type="secondary">—</Typography.Text>;
  const ref = refs.get(refKey(type, id));
  const named = ref?.visible && ref.label && ref.label !== id;
  const title = <span className="mono">{id}{ref?.detail ? <><br />{ref.detail}</> : null}{ref?.expires_at ? <><br />到期 {ref.expires_at.slice(0, 10)}</> : null}{ref && !ref.visible ? <><br />无权查看或已不存在，仅显示 ID</> : null}</span>;
  return <Tooltip title={title}><span className="entity-ref" data-testid="entity-ref">
    <Button type="link" size="small" className="entity-ref-link" disabled={ref ? !ref.visible : false} onClick={() => navigate(`/entities/${type}/${id}`)}>{named ? ref!.label : <span className="mono">{compact ? shortId(id) : id}</span>}</Button>
    {named && !compact && <Typography.Text type="secondary" className="entity-ref-id mono">{shortId(id)}</Typography.Text>}
    {ref?.expires_at && <Tag color={ref.expired ? 'red' : 'default'} className="entity-ref-exp">{ref.expired ? '已过期' : `到期 ${ref.expires_at.slice(0, 10)}`}</Tag>}
  </span></Tooltip>;
}
