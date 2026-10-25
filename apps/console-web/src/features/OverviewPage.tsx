import { Alert, Button, Card, Col, Empty, Row, Space, Statistic, Tag, Typography } from 'antd';
import { PilotIcon } from '../../../../packages/contracts/src/PilotIcon';
import { Link } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useAuth } from '../app/AuthContext';
import { usePermissions } from '../app/Permissions';
import { useWorkspace } from '../app/WorkspaceContext';
import { scopeQuery } from '../api/workspace-scope';
import { useCluster } from '../app/ClusterContext';
import { api, post } from '../api/client';
import { listData, type DataSource } from '../api/types';
import { formatTime, NoCluster, PageHeading, QueryError, StatusBadge } from '../components/Shared';
import { entityLabels, entityTypes } from './entities';

export function OverviewPage() {
  const { cluster, clusters, clusterId, query } = useCluster();
  const { workspaceId, workspace, ready, writeBlocked } = useWorkspace();
  const { user } = useAuth();
  const permission = usePermissions();
  const sourcesQuery = useQuery({ queryKey: ['data-sources', clusterId], queryFn: async () => listData(await api<DataSource[]>(`/clusters/${clusterId}/data-sources`)), enabled: !!clusterId && permission.has('data-sources') });
  const inventory = useQuery({ queryKey: ['inventory', clusterId, workspaceId], queryFn: () => api<{ counts: Record<string, number>; observed_at?: string; source: string; quarantined_count?: number; traffic?: { available: boolean; reason?: string } }>(scopeQuery(`/clusters/${clusterId}/inventory`, clusterId, workspaceId)), enabled: ready });
  const syncInventory = useMutation({ mutationFn: () => post(scopeQuery(`/clusters/${clusterId}/inventory/refresh`, clusterId, workspaceId)), onSuccess: () => { void inventory.refetch(); } });
  const sources = sourcesQuery.data ?? [];
  const connected = clusters.filter(item => ['healthy', 'connected', 'ok', 'online', 'compatible'].includes(item.status)).length;
  const incompatible = !!cluster?.version && !/^1\.5\./.test(cluster.version);
  return <>
    <PageHeading title="网关总览" extra={<Button icon={<PilotIcon name="reload" />} loading={query.isFetching} onClick={() => { void query.refetch(); void sourcesQuery.refetch(); }}>刷新状态</Button>} />
    {query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {incompatible && <Alert type="warning" showIcon message={`当前集群版本 ${cluster?.version} 不在 Kong 1.5.x 兼容范围内`} description="网关配置写入已受版本策略限制。请连接受支持的集群。" style={{ marginBottom: 24 }} />}
    <Row gutter={[20, 20]} className="stat-row">
      <Col xs={12} sm={12} xl={6}><Card className="stat-card"><div className="stat-icon blue"><PilotIcon name="cluster" /></div><Statistic title="已登记集群" value={query.isError && !query.data ? '—' : clusters.length} loading={query.isLoading} /></Card></Col>
      <Col xs={12} sm={12} xl={6}><Card className="stat-card"><div className="stat-icon green"><PilotIcon name="check-circle" /></div><Statistic title="连接正常" value={query.isError && !query.data ? '—' : connected} loading={query.isLoading} /></Card></Col>
      <Col xs={12} sm={12} xl={6}><Card className="stat-card"><div className="stat-icon violet"><PilotIcon name="plugin" /></div><Statistic title="当前集群可用插件" value={cluster?.last_probed_at ? cluster.enabled_plugins.length : '—'} loading={query.isLoading} /></Card></Col>
      <Col xs={12} sm={12} xl={6}><Card className="stat-card"><div className="stat-icon orange"><PilotIcon name="database" /></div><Statistic title="当前集群数据源" value={cluster && permission.has('data-sources') && !sourcesQuery.isError ? sources.length : '—'} loading={sourcesQuery.isLoading} /></Card></Col>
    </Row>
    {!cluster && !query.isLoading ? <NoCluster /> : <Row gutter={[24, 24]}>
      <Col xs={24} xl={12}><Card className="connection-card" title={<Space><span className="card-title-icon"><PilotIcon name="cluster" /></span>当前集群</Space>} extra={permission.has('clusters') ? <Link to="/clusters">管理集群 <PilotIcon name="arrow-right" /></Link> : null} loading={query.isLoading}><div className="cluster-overview-head"><div><div className="cluster-overview-name">{cluster?.name}</div><Space size={8}><Tag>{cluster?.environment}</Tag><Tag color={cluster?.execution_mode === 'approval' ? 'gold' : 'cyan'}>{cluster?.execution_mode === 'approval' ? '工单审批' : '直接执行'}</Tag></Space></div><StatusBadge status={cluster?.status} /></div><dl className="info-grid"><div><dt>Admin API 地址</dt><dd className="mono">{cluster?.admin_url}</dd></div><div><dt>Gateway 版本</dt><dd>{cluster?.version ?? '等待版本探测'}</dd></div><div><dt>最近探测</dt><dd>{formatTime(cluster?.last_probed_at)}</dd></div><div><dt>集群标签</dt><dd>{cluster?.labels.length ? cluster.labels.map(tag => <Tag key={tag}>{tag}</Tag>) : '未设置'}</dd></div></dl></Card></Col>
      <Col xs={24} xl={12}><Card className="data-channel-card" title="数据通道" extra={permission.has('data-sources') ? <Link to="/data-sources">配置 <PilotIcon name="arrow-right" /></Link> : null} loading={sourcesQuery.isLoading}>{!permission.has('data-sources') ? <Typography.Text type="secondary">当前账号没有数据源读取权限。</Typography.Text> : sourcesQuery.isError ? <QueryError error={sourcesQuery.error} retry={() => void sourcesQuery.refetch()} /> : sources.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未绑定监控或日志数据源"><Link to="/data-sources"><Button>添加数据源</Button></Link></Empty> : <div className="source-summary-list">{sources.map(source => <div key={source.id} className="source-summary"><div className={`source-icon ${source.type}`}><PilotIcon name="database" /></div><div className="source-summary-info"><strong>{source.name}</strong><span>{source.type === 'prometheus' ? 'Prometheus · 指标' : 'Loki · 日志'}</span></div><StatusBadge status={source.last_status} /></div>)}</div>}</Card></Col>
    </Row>}
    {clusterId && <Card className="baseline-card" title={`工作区配置概况 · ${workspace?.name ?? '正在加载'}`} extra={<Button size="small" icon={<PilotIcon name="reload" />} loading={syncInventory.isPending} disabled={!ready || writeBlocked || !permission.can('overview', 'write')} onClick={() => syncInventory.mutate()}>刷新统计</Button>}><div className="inventory-observed-at">最近更新：{inventory.data?.observed_at ? formatTime(inventory.data.observed_at) : '尚未更新'}</div>{inventory.isError && <QueryError error={inventory.error} retry={() => void inventory.refetch()} />}{syncInventory.isError && <QueryError error={syncInventory.error} />}{user?.superAdmin && !!inventory.data?.quarantined_count && <Alert type="warning" showIcon message={`归属异常对象：${inventory.data.quarantined_count}`} description="含无效、多个或指向已删除工作区的保留归属标签，已从工作区列表与统计中排除。平台管理员需核验这些配置；网关运行仍按现有配置执行。" style={{ marginBottom: 18 }} />}{inventory.data?.traffic?.available === false && <Alert type="info" showIcon message="监控数据通道尚未启用" description="数据源连通性与流量数据通道分别判断；流量统计尚不可用。" style={{ marginBottom: 18 }} />}<div className="inventory-grid">{entityTypes.filter(type => permission.has(type)).map(type => <Link key={type} to={`/entities/${type}`} className="inventory-item"><span>{entityLabels[type]}</span><strong>{inventory.data?.observed_at ? inventory.data.counts[type] ?? 0 : '—'}</strong></Link>)}</div></Card>}
    <div className="overview-shortcuts">
      {permission.has('clusters') && <Link to="/clusters" className="overview-shortcut"><PilotIcon name="cluster" /><div><strong>{permission.can('clusters', 'write') ? '登记集群' : '查看集群'}</strong></div><PilotIcon name="arrow-right" /></Link>}
      {permission.has('plugins') && <Link to="/plugin-center" className="overview-shortcut"><PilotIcon name="plugin" /><div><strong>{permission.can('plugins', 'write') ? '配置插件' : '查看插件'}</strong></div><PilotIcon name="arrow-right" /></Link>}
      {permission.has('snapshots') && <Link to="/snapshots" className="overview-shortcut"><PilotIcon name="database" /><div><strong>查看快照</strong></div><PilotIcon name="arrow-right" /></Link>}
    </div>
  </>;
}
