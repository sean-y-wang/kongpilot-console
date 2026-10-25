import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Badge, Button, Card, Descriptions, Drawer, Empty, Form, Select, Space, Spin, Switch, Table, Tabs, Tag, Typography } from 'antd';
import { BarChartOutlined, ReloadOutlined, SettingOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ApiError, getApiActorId } from '../api/client';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { usePermissions } from '../app/Permissions';
import { MetricChart } from '../components/MetricChart';
import { VitalsEntitySelect } from '../components/VitalsEntitySelect';
import { mutationConfirm } from '../components/MutationConfirm';
import { NoCluster, PageHeading, QueryError, StatusBadge, formatTime } from '../components/Shared';
import { createVitalsWindow, formatMetric, sameVitalsScope, VITALS_RANGES, vitalsPath, vitalsQueryKey, type MetricUnit, type VitalsDuration, type VitalsScope } from './vitals-model';
import { requestVitals, validateVitalsCapabilities, validateVitalsOverview } from './vitals-response';
import type { VitalsAvailability, VitalsCapabilities, VitalsMetric, VitalsOverview } from './vitals.types';
import { useMetricsSetupChange } from './MetricsSetupReview';

const availabilityLabels: Record<VitalsAvailability, string> = { available: '采样可用', unavailable: '暂不可用', insufficient_samples: '等待采样', unsupported: '通道不支持', partial: '部分采样' };
const reasonLabels: Record<string, string> = {
  SOURCE_NOT_CONFIGURED: '尚未配置监控数据源', SOURCE_UNAVAILABLE: '监控数据源暂不可用', INSUFFICIENT_SAMPLES: '样本不足，等待后续采集', NO_SAMPLES: '此范围尚无样本',
  COLLECTOR_REQUIRED: '此指标需要日志采集通道', NODE_PERMISSION_REQUIRED: '节点指标需要整个集群的监控权限', CURRENT_EPOCH_ONLY: '仅展示当前归属与授权周期的采样',
  CATALOG_INCOMPLETE: '归属目录验证尚未完成', METRICS_WRITE_FENCED: '配置变更尚在核验，相关采样暂时隔离',
  NO_VERIFIED_TRAFFIC_ASSIGNMENT: '此范围尚无已验证的流量归属', CONSUMER_COLLECTOR_UNAVAILABLE: 'Consumer 采集通道暂无可用采样', NODE_METRICS_CLUSTER_PERMISSION_REQUIRED: '节点指标需要整个集群的监控权限',
  METRICS_SOURCE_NOT_CONFIGURED: '尚未配置监控数据源', METRICS_CATALOG_UNAVAILABLE: '归属目录尚未准备完成', METRICS_SOURCE_QUERY_FAILED: '监控数据源查询失败，未展示旧值',
  LOKI_NODE_METRICS_UNSUPPORTED: 'Loki 日志通道不提供节点指标', LOKI_LOG_DELIVERY_AT_LEAST_ONCE: '日志指标按至少一次投递统计，可能包含重复采样', LOKI_COLLECTOR_NOT_ENABLED: 'Loki 日志采集通道尚未启用', LOKI_CURRENT_EPOCH_WINDOW_INCOMPLETE: '当前归属周期尚未覆盖完整查询窗口，空缺保持为空值',
  LOKI_EVALUATION_GRID_ALIGNED: 'Loki 已按采样步长向内对齐实际评估窗口，原请求范围已保留',
};
function MetricCard({ name, metric, title, unit }: { name: string; metric?: VitalsMetric; title: string; unit: MetricUnit }) {
  const availability = metric?.availability ?? 'unavailable';
  const shown = ['available', 'partial'].includes(availability) ? metric?.value : null;
  return <Card className="vitals-stat-card" data-testid={`vitals-card-${name}`} data-availability={availability}><div className="vitals-stat-title">{title}<span>{unit === 'ms' ? 'ms' : '请求/秒'}</span></div><div className="vitals-stat-value">{formatMetric(shown, unit)}</div><div className="vitals-stat-note"><span className={availability === 'available' ? 'vitals-ready-dot' : 'vitals-wait-dot'} />{availabilityLabels[availability]}{metric?.reasonCode && <span title={metric.reasonCode}> · {reasonLabels[metric.reasonCode] ?? metric.reasonCode}</span>}</div></Card>;
}

export function VitalsPage() {
  const { clusterId } = useCluster(), workspace = useWorkspace(), { user } = useAuth();
  if (!clusterId) return <NoCluster />;
  if (!workspace.ready || !workspace.workspaceId || !user) return <div className="empty-panel"><Spin /><p>正在加载监控范围…</p></div>;
  return <ScopedVitals key={`${user.id}:${user.permissionsVersion}:${clusterId}:${workspace.workspaceId}`} actorId={user.id} clusterId={clusterId} workspaceId={workspace.workspaceId} />;
}

function ScopedVitals({ actorId, clusterId, workspaceId }: { actorId: string; clusterId: string; workspaceId: string }) {
  const { t } = useTranslation(), permission = usePermissions(), { cluster } = useCluster(), workspace = useWorkspace(), { modal, message } = App.useApp();
  const [sourceId, setSourceId] = useState<string>(), [serviceId, setServiceId] = useState<string>(), [routeId, setRouteId] = useState<string>();
  const [metricsScope, setMetricsScope] = useState<'workspace' | 'cluster'>('workspace');
  const [duration, setDuration] = useState<VitalsDuration>(300), [window, setWindow] = useState(() => createVitalsWindow(300));
  const [autoRefresh, setAutoRefresh] = useState(false), [latency, setLatency] = useState<'Request' | 'Upstream' | 'Kong'>('Request');
  const [setupOpen, setSetupOpen] = useState(false), [propagating, setPropagating] = useState(false);
  const [setupForm] = Form.useForm<{ sourceId: string; mode: 'native_prometheus' | 'collector' }>();
  const scope = useMemo<VitalsScope>(() => ({ actorId, clusterId, workspaceId, permissionVersion: permission.version ?? '', metricsScope, sourceId, serviceId, routeId }), [actorId, clusterId, workspaceId, permission.version, metricsScope, sourceId, serviceId, routeId]);
  const currentScope = useRef(scope); currentScope.current = scope;
  const capabilities = useQuery({ queryKey: vitalsQueryKey('capabilities', scope), queryFn: ({ signal }) => requestVitals<VitalsCapabilities>(vitalsPath('capabilities', scope), scope, () => currentScope.current, signal, validateVitalsCapabilities), staleTime: 0, gcTime: 0, retry: false });
  const caps = capabilities.data;
  const overview = useQuery({ queryKey: vitalsQueryKey('overview', scope, window), queryFn: ({ signal }) => requestVitals<VitalsOverview>(vitalsPath('overview', scope, { window }), scope, () => currentScope.current, signal, validateVitalsOverview), enabled: !!caps?.configured, staleTime: 0, gcTime: 0, retry: false });
  // Re-querying deliberately clears the previous chart instead of showing obsolete samples.
  const data = !caps?.configured || overview.isFetching || overview.isError ? undefined : overview.data;
  const setupAllowed = permission.platformAdmin && caps?.permissions.setup === true;
  const setupChange = useMetricsSetupChange({ scope, allowed: setupAllowed, blocked: workspace.readonlyWorkspace || workspace.writeBlocked, onSaved: async savedSourceId => { setPropagating(true); setSetupOpen(false); selectSource(savedSourceId); void message.success('监控设置已提交，等待配置传播与采样'); await capabilities.refetch(); } });
  const setupBlocked = setupChange.blocked, settingUp = setupChange.busy;
  const series = useMemo(() => ({
    qps: [{ name: 'QPS', points: data?.series.qps ?? [], color: '#3b6c99' }],
    status: [{ name: '2xx', points: data?.series.status2xx ?? [], color: '#15966b' }, { name: '4xx', points: data?.series.status4xx ?? [], color: '#e7a63e' }, { name: '5xx', points: data?.series.status5xx ?? [], color: '#df6464' }],
    latency: (['50', '95', '99'] as const).map((quantile, index) => ({ name: `P${quantile}`, points: data?.series[`latency${latency}P${quantile}`] ?? [], color: ['#3b6c99', '#7396b6', '#a6b9ca'][index] })),
    bandwidth: [{ name: '入站', points: data?.series.bandwidthIngress ?? [], color: '#3b6c99' }, { name: '出站', points: data?.series.bandwidthEgress ?? [], color: '#7396b6' }],
  }), [data, latency]);
  useEffect(() => { if (!autoRefresh) return; const timer = globalThis.setInterval(() => setWindow(createVitalsWindow(duration)), 30_000); return () => globalThis.clearInterval(timer); }, [autoRefresh, duration]);
  useEffect(() => { if (caps && !caps.permissions.clusterMetrics && metricsScope === 'cluster') { setMetricsScope('workspace'); setServiceId(undefined); setRouteId(undefined); } }, [caps?.permissions.clusterMetrics, metricsScope]);
  useEffect(() => {
    const verified = (event: Event) => {
      const proof = (event as CustomEvent).detail;
      if (proof?.kind !== 'vitals-setup' || proof.cid !== clusterId || proof.wid !== workspaceId || proof.completed !== true || getApiActorId() !== actorId) return;
      setSetupOpen(false); setPropagating(true); setWindow(createVitalsWindow(duration));
    };
    globalThis.window.addEventListener('kongos:receipt-verified', verified);
    return () => globalThis.window.removeEventListener('kongos:receipt-verified', verified);
  }, [actorId, clusterId, workspaceId, duration]);
  function selectSource(id?: string) { setSourceId(id); setServiceId(undefined); setRouteId(undefined); setWindow(createVitalsWindow(duration)); }
  function selectScope(value: 'workspace' | 'cluster') { setMetricsScope(value); setServiceId(undefined); setRouteId(undefined); setWindow(createVitalsWindow(duration)); }
  function selectService(id?: string) { setServiceId(id); setRouteId(undefined); setWindow(createVitalsWindow(duration)); }
  function selectRoute(id?: string) { setRouteId(id); setServiceId(undefined); setWindow(createVitalsWindow(duration)); }
  function refresh() { const next = createVitalsWindow(duration); if (next.end === window.end && caps?.configured) void overview.refetch(); else setWindow(next); void capabilities.refetch(); }
  function configure(values: { sourceId: string; mode: 'native_prometheus' | 'collector' }) {
    if (setupBlocked || !cluster) return;
    const captured = scope, clusterName = cluster.name;
    mutationConfirm(modal, { title: '确认启用监控数据通道', expected: clusterName, danger: false, description: values.mode === 'collector' ? '将启用全局日志采集插件并更新集群监控设置。事件只保留监控必要字段；Consumer 指标按至少一次投递统计，可能包含重复采样。' : '将启用全局 prometheus 插件并更新集群监控设置。抓取凭证由后端部署通道管理；此页面不会显示连接地址或秘密。', onConfirm: async () => {
      if (!sameVitalsScope(captured, currentScope.current) || getApiActorId() !== captured.actorId) throw new ApiError('监控范围已变化，请重新审阅。', 0, 'METRICS_SCOPE_CHANGED');
      const result = await setupChange.execute({ sourceId: values.sourceId, mode: values.mode, confirmed: true, confirm_name: clusterName }); if (result === 'prepared' && sameVitalsScope(captured, currentScope.current) && getApiActorId() === captured.actorId) setSetupOpen(false);
    } });
  }
  const unavailable = !caps?.configured ? t('vitals.unconfigured') : t('vitals.waiting');
  return <div className="vitals-page">
    <PageHeading title={t('vitals.title')} extra={<>{setupAllowed && <Button icon={<SettingOutlined />} disabled={setupBlocked} onClick={() => { const active = sourceId ?? caps?.source?.id; setupForm.setFieldsValue({ sourceId: caps?.sources.some(row => row.id === active && row.type === 'prometheus') ? active : undefined, mode: caps?.collectorEnabled ? 'collector' : 'native_prometheus' }); setSetupOpen(true); }}>配置监控通道</Button>}<Button icon={<ReloadOutlined />} loading={capabilities.isFetching || overview.isFetching} onClick={refresh} aria-label="刷新监控">刷新监控</Button></>} />
    {capabilities.isError && <QueryError error={capabilities.error} retry={() => void capabilities.refetch()} />}
    {overview.isError && <QueryError error={overview.error} retry={() => void overview.refetch()} />}
    {setupChange.review}
    {propagating && <Alert type="info" showIcon message="配置生效中，等待 DB 模式传播与抓取采样" description="配置传播约需数秒。图表只展示实际采集值；采样不足时继续显示等待状态。" closable onClose={() => setPropagating(false)} style={{ marginBottom: 18 }} />}
    <Card className="vitals-filter-card"><div className="vitals-filters">
      <div><label>聚合范围</label><Select aria-label="监控聚合范围" value={metricsScope} onChange={selectScope} options={[{ value: 'workspace', label: `工作区 · ${workspace.workspace?.name ?? ''}` }, ...(caps?.permissions.clusterMetrics ? [{ value: 'cluster', label: '整个集群 · 全部工作区' }] : [])]} /></div>
      <div><label>数据源</label><Select aria-label="监控数据源" value={sourceId ?? caps?.source?.id} onChange={selectSource} loading={capabilities.isFetching} options={(caps?.sources ?? []).map(row => ({ value: row.id, label: `${row.name} · ${row.type}` }))} placeholder="尚未配置" allowClear /></div>
      <div><label>Service</label><VitalsEntitySelect scope={scope} type="services" value={serviceId} onChange={selectService} label="监控服务" disabled={!caps} /></div>
      <div><label>Route</label><VitalsEntitySelect scope={scope} type="routes" value={routeId} onChange={selectRoute} label="监控路由" disabled={!caps?.capabilities.routeDrilldown} /></div>
      <div><label>时间范围</label><Select aria-label="监控时间范围" value={duration} onChange={value => { setDuration(value); setWindow(createVitalsWindow(value)); }} options={VITALS_RANGES.map(row => ({ ...row }))} /></div>
    </div><div className="vitals-filter-meta"><Space wrap>{caps?.source && <><Tag icon={<BarChartOutlined />}>{caps.source.name}</Tag><StatusBadge status={caps.source.status} /></>}<Typography.Text type="secondary">{workspace.workspace?.name} · {metricsScope === 'cluster' ? '整个集群' : '工作区'}{serviceId ? ' / Service' : routeId ? ' / Route' : ''}</Typography.Text></Space><Space><Typography.Text type="secondary">每 30 秒刷新</Typography.Text><Switch size="small" aria-label="自动刷新监控" checked={autoRefresh} onChange={setAutoRefresh} /></Space></div></Card>
    <div data-testid="vitals-quality" className="vitals-quality">
      {!caps?.configured && !capabilities.isFetching && <Alert type="info" showIcon message={t('vitals.unconfigured')} description="由平台管理员配置数据源与抓取通道；数据源连通性和指标采样可用性分别核验。" />}
      {caps && <Alert showIcon type={data?.quality.complete ? 'success' : 'info'} message={data?.quality.complete ? '当前范围的采样已完成校验' : '仅展示已验证的实际采样'} description={<><p>{t('vitals.epoch')}</p>{data?.quality.reasonCodes.length ? <p>{data.quality.reasonCodes.map(code => reasonLabels[code] ?? code).join('；')}</p> : null}{data?.quality.gaps.length ? <p>{data.quality.gaps.join('；')}</p> : null}{caps.limitations.map((note, index) => <p key={index}>{note}</p>)}</>} />}
    </div>
    <div className="vitals-stat-grid"><MetricCard name="qps" title="吞吐率 · QPS" metric={data?.cards.qps} unit="requests/s" /><MetricCard name="p50" title="请求延迟 · P50" metric={data?.cards.p50} unit="ms" /><MetricCard name="p95" title="请求延迟 · P95" metric={data?.cards.p95} unit="ms" /><MetricCard name="p99" title="请求延迟 · P99" metric={data?.cards.p99} unit="ms" /></div>
    <div className="vitals-chart-grid"><Card title="QPS 趋势" loading={overview.isFetching}><MetricChart id="qps" series={series.qps} unit="requests/s" unavailableReason={unavailable} /></Card><Card title="状态码分布" extra={<Tag>请求/秒</Tag>} loading={overview.isFetching}><MetricChart id="status" series={series.status} unit="requests/s" stacked unavailableReason={unavailable} /></Card>
      <Card title="延迟分位数" loading={overview.isFetching} className="vitals-latency-card"><Tabs size="small" activeKey={latency} onChange={value => setLatency(value as typeof latency)} items={[{ key: 'Request', label: '代理请求' }, { key: 'Upstream', label: '上游' }, { key: 'Kong', label: 'Kong 处理' }]} /><MetricChart id="latency" series={series.latency} unit="ms" unavailableReason={unavailable} /><Typography.Text type="secondary" className="small-note">{caps?.provider === 'loki' ? '按已净化日志计算经验分位数，单位为毫秒' : '按原生直方图桶插值计算，单位为毫秒'}</Typography.Text></Card>
      <Card title="带宽" loading={overview.isFetching} extra={<Tag>B/s</Tag>}><div className="vitals-bandwidth-summary"><span>入站 <strong>{formatMetric(data?.cards.ingressBytesPerSecond.value, 'bytes/s')}</strong></span><span>出站 <strong>{formatMetric(data?.cards.egressBytesPerSecond.value, 'bytes/s')}</strong></span></div><MetricChart id="bandwidth" series={series.bandwidth} unit="bytes/s" unavailableReason={unavailable} /></Card></div>
    <div className="vitals-topn-grid"><Card title="Service TopN" extra={<Tag>请求/秒</Tag>} loading={overview.isFetching}><Table size="small" rowKey="id" pagination={false} dataSource={data?.topN.services ?? []} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="此范围尚无可用 Service 采样" /> }} columns={[{ title: 'Service', dataIndex: 'name', ellipsis: true }, { title: 'QPS', dataIndex: 'value', align: 'right', render: value => formatMetric(value, 'requests/s') }, { title: '下钻', align: 'right', render: (_, row) => <Button type="link" size="small" onClick={() => selectService(row.id)}>查看趋势</Button> }]} /></Card>
      <Card title="Consumer TopN" extra={<Tag color="gold">至少一次投递 · 近似</Tag>} loading={overview.isFetching}><Typography.Paragraph type="secondary" className="small-note">原生 Prometheus 插件不含 Consumer 维度；采集通道可能重复投递，此处显示近似请求率。</Typography.Paragraph><Table size="small" rowKey="id" pagination={false} dataSource={data?.topN.consumers ?? []} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={caps?.collectorEnabled ? '此范围尚无可用 Consumer 采样' : '启用日志采集通道后提供 Consumer 指标'} /> }} columns={[{ title: 'Consumer', dataIndex: 'name', ellipsis: true }, { title: '近似 QPS', dataIndex: 'value', align: 'right', render: value => formatMetric(value, 'requests/s') }]} /></Card></div>
    <Card title="节点连通状态" className="vitals-node-card" extra={caps?.capabilities.nodes && <Tag>在线节点：{formatMetric(data?.cards.onlineNodes.value)}</Tag>} loading={overview.isFetching}>
      <Typography.Paragraph type="secondary" className="small-note">注册的 Admin API 地址代表当前被探测的逻辑节点，不代表整个 Kong 节点拓扑。</Typography.Paragraph>
      {caps?.permissions.nodeMetrics ? caps.provider === 'loki' ? <Alert type="info" showIcon message="Loki 日志通道不提供节点指标" description="可切换至 Prometheus 通道查看已登记逻辑节点的采样。" /> : <Table size="small" rowKey="id" pagination={false} dataSource={data?.nodes ?? []} locale={{ emptyText: '尚无节点状态采样' }} columns={[{ title: '逻辑节点', dataIndex: 'id', ellipsis: true }, { title: '在线', dataIndex: 'online', render: value => <Badge status={value === 1 ? 'success' : value === 0 ? 'error' : 'default'} text={value === 1 ? '在线' : value === 0 ? '离线' : '等待采样'} /> }, { title: '数据存储', dataIndex: 'datastoreReachable', render: value => <Badge status={value === 1 ? 'success' : value === 0 ? 'error' : 'default'} text={value === 1 ? '可达' : value === 0 ? '不可达' : '等待采样'} /> }]} /> : <Alert type="info" showIcon message="节点指标需要整个集群的监控读取权限" />}
    </Card>
    <div className="vitals-observation"><span>评估时间：{data ? formatTime(data.evaluationAt) : '等待采样'}</span><span>采样间隔：{data?.timeWindow.step ?? window.step} 秒 · {data ? '实际评估范围' : '请求范围'}：{formatTime(data?.timeWindow.start ?? window.start)} — {formatTime(data?.timeWindow.end ?? window.end)}</span></div>
    {data?.requestedWindow && <Typography.Paragraph type="secondary" className="small-note">原请求范围：{formatTime(data.requestedWindow.start)} — {formatTime(data.requestedWindow.end)}。Loki 将起止时间向内对齐至采样步长，统计基于上方实际范围。</Typography.Paragraph>}
    <Drawer title="配置监控数据通道" width={580} open={setupOpen} onClose={() => setSetupOpen(false)} destroyOnClose extra={<Button type="primary" disabled={setupBlocked} loading={settingUp} onClick={() => setupForm.submit()}>提交监控配置</Button>}>
      <Alert type="info" showIcon message="控制台提供自研监控数据通道" description="Kong 1.5 OSS 没有原生 Vitals；此页面通过 Prometheus 或安全日志采集查询实际指标。部署凭证不会在浏览器返回。" style={{ marginBottom: 24 }} />
      {caps?.executionMode === 'approval' && <Alert type="info" showIcon message="此集群使用工单审批模式" description="先生成并审阅监控变更，再提交工单；审批通过后执行全局插件与监控设置变更。" style={{ marginBottom: 24 }} />}
      <Descriptions size="small" column={1} items={[{ key: 'version', label: 'Kong / 插件', children: `${caps?.nativeVersion ?? '待探测'} / prometheus ${caps?.pluginVersion ?? '0.6.0'}` }]} style={{ marginBottom: 24 }} />
      <Form form={setupForm} layout="vertical" onFinish={configure}><Form.Item name="sourceId" label="监控数据源" rules={[{ required: true, message: '请选择已经登记的 Prometheus 数据源' }]}><Select aria-label="配置监控数据源" options={(caps?.sources ?? []).filter(row => row.type === 'prometheus').map(row => ({ value: row.id, label: `${row.name} · ${row.type}` }))} /></Form.Item><Form.Item name="mode" label="采集方式" rules={[{ required: true }]}><Select aria-label="监控采集方式" options={[{ value: 'native_prometheus', label: '原生 Prometheus · 服务 / 路由' }, { value: 'collector', label: '日志采集通道 · Consumer 近似指标' }]} /></Form.Item><Typography.Paragraph type="secondary">提交后需输入集群名称二次确认。Prometheus 抓取与采集器登记由部署工具完成；若数据未到达，页面显示等待采样。部署后的 Loki 备选通道可在监控数据源选择器中切换查询。</Typography.Paragraph></Form>
    </Drawer>
  </div>;
}
