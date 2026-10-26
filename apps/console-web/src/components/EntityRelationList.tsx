import { Alert, Button, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { scopeQuery } from '../api/workspace-scope';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { entityDisplayName, type EntityPageData } from '../features/entities';
import { EntityIdText } from './EntityReference';
import { CursorPagination, useCursorPages } from './CursorPagination';
import { QueryError } from './Shared';

export function relationUnavailableMessage(data: { availability?: string } | undefined) {
  return data?.availability === 'forbidden' ? '此关联范围未授权' : data?.availability === 'missing' ? '关联已不存在' : undefined;
}

export function EntityRelationList({ parentType, parentId, relation, initial }: { parentType: string; parentId: string; relation: string; initial?: EntityPageData | { availability: 'forbidden' | 'missing'; items: never[]; total: null } }) {
  const { clusterId } = useCluster(), { workspaceId, ready } = useWorkspace(), navigate = useNavigate();
  const pages = useCursorPages(`${clusterId}:${workspaceId}:${parentType}:${parentId}:${relation}`);
  const params = new URLSearchParams({ size: '20' }); if (pages.cursor) params.set('cursor', pages.cursor);
  const unavailableInitially = relationUnavailableMessage(initial);
  const query = useQuery({ queryKey: ['relations', clusterId, workspaceId, parentType, parentId, relation, pages.cursor], queryFn: () => api<EntityPageData>(scopeQuery(`/clusters/${clusterId}/entities/${parentType}/${parentId}/relations/${relation}?${params}`, clusterId, workspaceId)), enabled: ready && !unavailableInitially, initialData: pages.cursor || unavailableInitially ? undefined : initial as EntityPageData | undefined });
  const unavailable = unavailableInitially ?? relationUnavailableMessage(query.data);
  if (unavailable) return <Alert showIcon type="info" message={unavailable} description="主体配置仍可访问；本视图不显示该关联的对象内容或数量。刷新主体详情可重新核验关联可用性。" />;
  if (query.isError) return <QueryError error={query.error} retry={() => void query.refetch()} />;
  return <><Table size="small" rowKey="id" loading={query.isFetching} pagination={false} dataSource={query.data?.items ?? []} columns={[{ title: '对象', render: (_, entity) => <Button type="link" onClick={() => navigate(`/entities/${relation}/${entity.id}`)}>{entityDisplayName(entity) || <span className="table-name-empty"> </span>}</Button> }, { title: 'ID', dataIndex: 'id', render: value => <EntityIdText id={value} /> }, { title: '标签', render: (_, entity) => entity.tags?.map((tag: string) => <Tag key={tag}>{tag}</Tag>) }]} /><CursorPagination pages={pages} size={20} count={query.data?.items.length ?? 0} nextCursor={query.data?.nextCursor} loading={query.isFetching} /></>;
}
