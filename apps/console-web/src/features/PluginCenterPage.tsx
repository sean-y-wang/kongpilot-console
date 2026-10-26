import { useEffect, useState } from 'react';
import { Alert, App, Button, Card, Empty, Input, Select, Space, Statistic, Switch, Table, Tabs, Tag, Typography } from 'antd';
import { ArrowRightOutlined, EditOutlined, PlusOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, ApiError, post } from '../api/client';
import { scopeQuery } from '../api/workspace-scope';
import { useWorkspace } from '../app/WorkspaceContext';
import { useCluster } from '../app/ClusterContext';
import { usePermissions } from '../app/Permissions';
import { useEntityPermissions } from '../app/EntityPermissions';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { ForeignLookup } from '../components/KongSchemaForm';
import { mutationConfirm } from '../components/MutationConfirm';
import { NoCluster, PageHeading, QueryError, formatTime } from '../components/Shared';
import { EntityEditor } from './EntityEditor';
import { entityName, type EntityPageData } from './entities';
import { requiresPlatformPlugin } from '../api/plugin-policy';

const categoryLabels: Record<string, string> = { authentication: '认证', security: '安全', traffic: '流量控制', transformation: '请求与响应转换', logging: '日志', serverless: 'Serverless', observability: '可观测性', unknown: '未分类' };
const scopeLabels: Record<string, string> = { 'consumer-route-service': 'Consumer + Route + Service', 'consumer-route': 'Consumer + Route', 'consumer-service': 'Consumer + Service', 'route-service': 'Route + Service', consumer: 'Consumer', route: 'Route', service: 'Service', global: '全局' };
const scopeCodes: Record<string, string> = { 'consumer-route-service': 'RSC', 'consumer-route': 'RC', 'consumer-service': 'SC', 'route-service': 'RS', consumer: 'C', route: 'R', service: 'S', global: 'Global' };
interface PluginMeta { name: string; category: string; priority: number | null; priority_label?: string; constraints?: { known: boolean; service: boolean | null; route: boolean | null; consumer: boolean | null; protocols: string[] }; }
interface CatalogItem extends PluginMeta { counts: null | { total: number; enabled: number; by_scope: Record<string, { total: number; enabled: number }> }; }
interface Catalog { items: CatalogItem[]; observed_at: string | null; sync_error?: string; counts_source: string; }
interface ContextCandidate { name: string; entity: any; scope: string; rank?: number; applicable?: boolean; selected?: boolean; reason?: string; priority?: number | null; priority_label?: string; }
interface PluginContext { complete: boolean; selected: ContextCandidate[]; candidates: ContextCandidate[]; execution_chain: ContextCandidate[]; warnings: string[]; }
function scopeOf(entity: any) { return [['consumer', !!entity.consumer], ['route', !!entity.route], ['service', !!entity.service]].filter(([, exists]) => exists).map(([key]) => key).join('-') || 'global'; }
function priorityOf(item: PluginMeta | ContextCandidate) { return item.priority_label ?? (item.priority == null ? '未知' : String(item.priority)); }

export function PluginCenterPage() {
  const { clusterId, cluster, kong } = useCluster();
  const { workspaceId, workspace, ready, writeBlocked, readonlyWorkspace } = useWorkspace();
  const permission = usePermissions();
  const scoped = (path: string) => scopeQuery(path, clusterId, workspaceId);
  const blocked = !ready || writeBlocked || readonlyWorkspace || cluster?.execution_mode === 'approval';
  const queryClient = useQueryClient();
  const { message, modal } = App.useApp();
  const [tab, setTab] = useState('market');
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');
  const [name, setName] = useState('');
  const [binding, setBinding] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [size, setSize] = useState(20);
  const [editor, setEditor] = useState<{ entity?: any; initialValues?: Record<string, any> }>();
  const [propagation, setPropagation] = useState(false);
  const [operationError, setOperationError] = useState<unknown>();
  const uncertain = operationError instanceof ApiError && (operationError.recovery?.state === 'uncertain' || /UNKNOWN|UNCERTAIN/.test(operationError.code ?? ''));
  const [contextDraft, setContextDraft] = useState<Record<string, string>>({});
  const [context, setContext] = useState<Record<string, string>>();
  useEffect(() => { setEditor(undefined); setName(''); setBinding(''); setTags([]); setContextDraft({}); setContext(undefined); setOperationError(undefined); }, [clusterId, workspaceId]);
  const base = `/clusters/${clusterId}/plugin-center`;
  const catalog = useQuery({ queryKey: ['plugin-catalog', clusterId, workspaceId], queryFn: () => api<Catalog>(scoped(`${base}/catalog`)), enabled: ready });
  const precedence = useQuery({ queryKey: ['plugin-precedence', clusterId, workspaceId], queryFn: () => api<{ levels: { scope: string; rank: number; label: string }[]; execution_order: PluginMeta[]; disabled_fallback: boolean }>(scoped(`${base}/precedence`)), enabled: ready });
  const pages = useCursorPages(JSON.stringify([clusterId, workspaceId, name, binding, tags, size]));
  const params = new URLSearchParams({ size: String(size) });
  if (pages.cursor) params.set('cursor', pages.cursor);
  if (name) params.set('name', name);
  if (binding) params.set('binding_scope', binding);
  if (tags.length) params.set('tags', tags.join(','));
  const instances = useQuery({ queryKey: ['plugin-instances', clusterId, workspaceId, params.toString()], queryFn: () => api<EntityPageData & { scan_budget_exhausted?: boolean }>(scoped(`${base}/instances?${params}`)), enabled: ready && tab === 'instances' });
  const resolved = useQuery({ queryKey: ['plugin-context', clusterId, workspaceId, context], queryFn: () => api<PluginContext>(scoped(`${base}/context?${new URLSearchParams(context)}`)), enabled: ready && context !== undefined });
  async function refreshAll() { await queryClient.invalidateQueries({ predicate: query => query.queryKey.includes(clusterId) }); }
  const toggle = useMutation({ mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => post(scoped(`${base}/instances/${id}/toggle`), { enabled }), onSuccess: async () => { setPropagation(true); setOperationError(undefined); await refreshAll(); void message.success('插件状态已提交'); }, onError: error => setOperationError(error) });
  function archive(entity: any) {
    mutationConfirm(modal, { title: '将插件移入回收站', expected: entityName(entity), description: '后端先归档插件配置与绑定引用，再从网关移除。', onConfirm: async () => { try { await api(scoped(`/clusters/${clusterId}/entities/plugins/${entity.id}`), { method: 'DELETE', body: JSON.stringify({ confirmed: true, confirm_name: entityName(entity) }) }); setPropagation(true); await refreshAll(); } catch (e) { setOperationError(e); throw e; } } });
  }
  const filtered = (catalog.data?.items ?? []).filter(item => (!category || item.category === category) && (!search || item.name.toLowerCase().includes(search.toLowerCase())));
  const indexed = !!catalog.data?.items.length && catalog.data.items.every(item => item.counts !== null);
  const total = indexed ? catalog.data!.items.reduce((sum, item) => sum + (item.counts?.total ?? 0), 0) : undefined;
  const enabled = indexed ? catalog.data!.items.reduce((sum, item) => sum + (item.counts?.enabled ?? 0), 0) : undefined;
  const levels = precedence.data?.levels ?? [];
  const abilities = useEntityPermissions((instances.data?.items ?? []).map(entity => ({ type: 'plugins', id: entity.id })));
  const instanceColumns: any[] = [
    { title: '插件 / 实例 ID', width: 255, render: (_: any, entity: any) => <div><Link className="table-name" to={`/entities/plugins/${entity.id}`}>{entity.name}</Link><div className="table-secondary mono">{entity.id}</div></div> },
    { title: '绑定层级', width: 255, render: (_: any, entity: any) => <div><Tag color={scopeOf(entity) === 'global' ? 'purple' : 'blue'}>{scopeLabels[scopeOf(entity)]}</Tag><div className="plugin-binding-refs">{(['service', 'route', 'consumer'] as const).filter(key => entity[key]).map(key => <Link key={key} to={`/entities/${key === 'consumer' ? 'consumers' : `${key}s`}/${entity[key].id}`}>{key}: {entity[key].id.slice(0, 8)}</Link>)}</div></div> },
    { title: '标签', width: 180, render: (_: any, entity: any) => <Space wrap size={2}>{(entity.tags ?? []).map((tag: string) => <Tag key={tag}>{tag}</Tag>)}</Space> },
    { title: '启用', width: 105, render: (_: any, entity: any) => <Switch aria-label={`启停 ${entity.name} ${entity.id}`} checked={entity.enabled} loading={toggle.isPending && toggle.variables?.id === entity.id} disabled={toggle.isPending || uncertain || blocked || !abilities.can('plugins', entity.id, 'write')} onChange={value => toggle.mutate({ id: entity.id, enabled: value })} /> },
    { title: '操作', width: 145, fixed: 'right', render: (_: any, entity: any) => <Space size={0}><Button type="link" size="small" icon={<EditOutlined />} disabled={!abilities.can('plugins', entity.id, 'write')} onClick={() => setEditor({ entity })}>编辑</Button><Button type="link" danger size="small" disabled={blocked || uncertain || !abilities.can('plugins', entity.id, 'delete')} onClick={() => archive(entity)}>删除</Button></Space> },
  ];
  return <>
    <PageHeading title="插件中心" extra={<Button type="primary" icon={<PlusOutlined />} disabled={blocked || uncertain || !permission.has('plugins', 'write')} onClick={() => setEditor({})}>添加插件</Button>} />
    {propagation && <Alert type="info" showIcon closable onClose={() => setPropagation(false)} message="配置生效中" description="状态与配置已提交，各节点可能需要数秒同步。请重新读取实例或执行真实请求核验。" style={{ marginBottom: 20 }} />}
    <Alert type="info" showIcon message={`当前管理工作区：${workspace?.name ?? '正在加载'}`} description="全局绑定插件仍作用于整个网关，工作区标签只限制控制台管理范围。" style={{ marginBottom: 20 }} />
    {!permission.platformAdmin && <Alert type="warning" showIcon message="部分插件仅允许平台管理员变更" description="全局绑定、pre-function / post-function 脚本插件、file-log 文件写入插件和未知自定义插件的创建、编辑、启停与删除均受保护。普通插件仍按实际绑定对象权限校验。" style={{ marginBottom: 20 }} />}
    {!!operationError && <QueryError error={operationError} />}
    {!clusterId ? <NoCluster /> : <>
      <div className="plugin-summary-grid"><Card><Statistic title="集群可用插件" value={catalog.data?.items.length ?? '—'} prefix={<ThunderboltOutlined />} /></Card><Card><Statistic title="工作区插件实例 · 索引统计" value={total ?? '—'} /></Card><Card><Statistic title="工作区已启用实例 · 索引统计" value={enabled ?? '—'} /></Card></div>
      <div className="index-status plugin-index-status">实例统计来自控制台索引，最近同步 {formatTime(catalog.data?.observed_at)}{catalog.data?.sync_error && <span> · {catalog.data.sync_error}</span>}</div>
      <Tabs activeKey={tab} onChange={setTab} items={[
        { key: 'market', label: '插件市场', children: <>
          {catalog.isError && <QueryError error={catalog.error} retry={() => void catalog.refetch()} />}
          <div className="plugin-market-toolbar"><Input.Search aria-label="搜索插件市场" value={search} onChange={event => setSearch(event.target.value)} allowClear placeholder="搜索插件名称" style={{ width: 300 }} /><Select aria-label="插件分类" value={category} onChange={setCategory} options={[{ value: '', label: '全部分类' }, ...Object.entries(categoryLabels).map(([value, label]) => ({ value, label }))]} style={{ width: 205 }} /><Button icon={<ReloadOutlined />} loading={catalog.isFetching} onClick={() => void catalog.refetch()}>刷新</Button></div>
          <div className="plugin-market-grid">{filtered.map(item => <Card key={item.name} className="plugin-market-card" loading={catalog.isLoading} title={<span className="plugin-card-title"><ThunderboltOutlined />{item.name}</span>} extra={<Tag>{categoryLabels[item.category] ?? item.category}</Tag>}><div className="plugin-card-stats"><div><strong>{item.counts?.enabled ?? '—'}</strong><span>已启用 / {item.counts?.total ?? '—'} 个实例</span></div><div><span>执行 Priority</span><strong className="plugin-priority-number">{priorityOf(item)}</strong></div></div><div className="plugin-scope-distribution">{item.counts ? Object.entries(item.counts.by_scope ?? {}).filter(([, count]) => count.total > 0).map(([scope, count]) => <Tag key={scope} title={scopeLabels[scope]}>{scopeCodes[scope] ?? scope} {count.enabled}/{count.total}</Tag>) : <Typography.Text type="secondary">实例索引尚未同步</Typography.Text>}{item.counts?.total === 0 && <Typography.Text type="secondary">暂无绑定实例</Typography.Text>}</div><div className="plugin-supported-scopes">支持范围：{item.constraints?.known ? ['全局', ...(['service', 'route', 'consumer'] as const).filter(key => item.constraints?.[key]).map(key => key[0].toUpperCase() + key.slice(1))].join(' / ') : '由网关 schema 校验'}</div><div className="plugin-card-actions"><Button size="small" type="primary" ghost disabled={blocked || uncertain || !permission.has('plugins', 'write') || !permission.platformAdmin && requiresPlatformPlugin(item.name, item.constraints?.known)} onClick={() => setEditor({ initialValues: { name: item.name } })}>配置 {item.name}</Button><Button size="small" type="link" onClick={() => { setName(item.name); setTab('instances'); }}>查看实例</Button></div></Card>)}</div>{!catalog.isFetching && filtered.length === 0 && <Empty description="没有符合条件的插件" />}
        </> },
        { key: 'instances', label: '插件实例', children: <>
          {abilities.query.isError && <QueryError error={abilities.query.error} retry={() => void abilities.query.refetch()} />}{instances.isError && <QueryError error={instances.error} retry={() => void instances.refetch()} />}
          {instances.data?.scan_budget_exhausted && <Alert type="warning" showIcon message="本次过滤已达到扫描预算" description="当前页可能不足指定条数，仍可用下一页游标继续查询；不会全量拉取插件。" style={{ marginBottom: 20 }} />}
          <Card className="table-card"><div className="entity-filter-bar"><Select aria-label="按插件名过滤" showSearch value={name} onChange={setName} options={[{ value: '', label: '全部插件' }, ...(catalog.data?.items ?? []).map(item => ({ value: item.name, label: item.name }))]} style={{ width: 230 }} /><Select aria-label="按绑定层级过滤" value={binding} onChange={setBinding} options={[{ value: '', label: '全部绑定层级' }, ...Object.entries(scopeLabels).map(([value, label]) => ({ value, label }))]} style={{ width: 260 }} /><Select aria-label="按插件标签过滤" mode="tags" tokenSeparators={[',']} value={tags} onChange={setTags} placeholder="按标签过滤" style={{ width: 210 }} /><Button icon={<ReloadOutlined />} loading={instances.isFetching} onClick={() => void instances.refetch()}>刷新</Button></div><Table rowKey="id" dataSource={instances.data?.items ?? []} columns={instanceColumns} loading={instances.isFetching} pagination={false} scroll={{ x: 980 }} /><CursorPagination pages={pages} nextCursor={instances.data?.nextCursor} loading={instances.isFetching} count={instances.data?.items.length ?? 0} size={size} onSizeChange={setSize} /></Card>
        </> },
        { key: 'precedence', label: '优先级与冲突', children: <>
          {precedence.isError && <QueryError error={precedence.error} retry={() => void precedence.refetch()} />}
          <Card title="同名插件：从高到低选择一个已启用实例" className="plugin-precedence-card"><div className="plugin-precedence-flow" data-testid="plugin-precedence-flow">{levels.map((level, index) => <div key={level.scope} className="plugin-precedence-step"><div className="plugin-precedence-box"><span>{level.rank}</span><strong>{scopeCodes[level.scope] ?? level.scope}</strong><small>{scopeLabels[level.scope] ?? level.label}</small></div>{index < levels.length - 1 && <ArrowRightOutlined className="plugin-precedence-arrow" />}</div>)}</div><Typography.Paragraph className="small-note">同名插件的绑定层级决定使用哪份配置；已停用的高层实例会回退到下一份适用且已启用的配置。不同名称的插件按 handler 的 Priority 从高到低执行，与这八层实例选择顺序分别判断。</Typography.Paragraph></Card>
          <Card title="请求上下文核验" className="plugin-context-card" extra={<Tag>后端按页读取</Tag>}><p className="plugin-context-intro">选择实际 Route、Service 或 Consumer，展示适用实例、被覆盖的配置与插件执行链。空上下文仅检查全局实例。</p><div className="plugin-context-selectors">{(['route', 'service', 'consumer'] as const).map(key => <div key={key}><label>{key[0].toUpperCase() + key.slice(1)}</label><ForeignLookup reference={key === 'consumer' ? 'consumers' : `${key}s`} value={contextDraft[`${key}Id`] ? { id: contextDraft[`${key}Id`] } : undefined} label={`核验 ${key}`} onChange={value => setContextDraft(prev => { const next = { ...prev }; if (value?.id) next[`${key}Id`] = value.id; else delete next[`${key}Id`]; return next; })} /></div>)}</div><Button type="primary" loading={resolved.isFetching} onClick={() => setContext({ ...contextDraft })} data-testid="resolve-plugin-context">核验上下文</Button>{resolved.isError && <QueryError error={resolved.error} retry={() => void resolved.refetch()} />}{resolved.data && <div className="plugin-context-result">{!resolved.data.complete && <Alert type="warning" showIcon message="工作区视图不能完整代表网关运行时插件链" description="其他工作区的全局插件仍可能作用于本次请求；扫描预算或读取错误也会限制结果。请结合实际代理请求核验。" />}{resolved.data.warnings.map((warning, index) => <Alert key={index} type="warning" showIcon message={warning} />)}<h4>当前工作区可见的配置与执行顺序</h4><div className="plugin-execution-chain" data-testid="plugin-execution-chain">{resolved.data.execution_chain.map((item, index) => <div key={item.entity.id}><span className="plugin-chain-order">{index + 1}</span><strong>{item.name}</strong><Tag>{scopeCodes[item.scope]}</Tag><small>Priority {priorityOf(item)}</small></div>)}{resolved.data.execution_chain.length === 0 && <Typography.Text type="secondary">没有已启用且适用的实例</Typography.Text>}</div><Table size="small" pagination={false} rowKey={(item: ContextCandidate) => item.entity.id} dataSource={resolved.data.candidates} scroll={{ x: 780 }} columns={[{ title: '插件', dataIndex: 'name' }, { title: '绑定层级', render: (_, item: ContextCandidate) => scopeLabels[item.scope] }, { title: '状态', render: (_, item: ContextCandidate) => <Tag color={item.selected ? 'green' : 'default'}>{item.selected ? '使用此配置' : item.entity.enabled === false ? '已停用' : item.applicable ? '被更高层覆盖' : '不适用'}</Tag> }, { title: '说明', dataIndex: 'reason' }, { title: '实例', render: (_, item: ContextCandidate) => <Link to={`/entities/plugins/${item.entity.id}`}>{item.entity.id.slice(0, 8)}</Link> }]} /></div>}</Card>
          <Card title="不同插件：handler 执行 Priority" className="plugin-handler-card"><div className="plugin-handler-priorities">{precedence.data?.execution_order.map(item => <Tag key={item.name}>{item.name}<strong>{priorityOf(item)}</strong></Tag>)}</div><Typography.Paragraph className="small-note">Priority 来自 Kong OSS 1.5.1 handler 源码{kong.full ? '' : `；当前集群 Kong ${cluster?.version ?? ''} 为有限支持，个别内置插件优先级可能不同`}。未知第三方插件保持“未知”；阶段钩子和协议仍由网关运行时决定。</Typography.Paragraph></Card>
        </> },
      ]} />
    </>}
    {editor && <EntityEditor type="plugins" open entity={editor.entity} initialValues={editor.initialValues} onClose={() => setEditor(undefined)} onSaved={() => setPropagation(true)} />}
  </>;
}
