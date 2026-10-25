import { useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Form, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined, SearchOutlined, ReloadOutlined, ApiOutlined, EditOutlined, StopOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useCluster, clustersQueryKey } from '../app/ClusterContext';
import { api, errorMessage } from '../api/client';
import type { Cluster } from '../api/types';
import { connectionAddressFields } from '../api/registry-payload';
import { usePermissions } from '../app/Permissions';
import { useWorkspace } from '../app/WorkspaceContext';
import { mutationConfirm } from '../components/MutationConfirm';
import { ConnectionAuthFields, connectionAuth } from '../components/ConnectionAuthFields';
import { PageHeading, QueryError, StatusBadge, formatTime } from '../components/Shared';
import { ControlMetadataChanges, useControlMetadataChanges } from './ControlMetadataChanges';

export function ClustersPage() {
  const { clusters, query, selectCluster, clusterId } = useCluster();
  const queryClient = useQueryClient();
  const permission = usePermissions();
  const changes = useControlMetadataChanges(), blocked = useWorkspace().references.some(ref => ref.domain === 'iam') || changes.blocked;
  const [operationError, setOperationError] = useState<unknown>();
  const { message, modal } = App.useApp();
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<Cluster | undefined>();
  const [open, setOpen] = useState(false);
  const [details, setDetails] = useState<Cluster | undefined>();
  const [form] = Form.useForm();
  const save = useMutation({ mutationFn: async (values: Record<string, any>) => {
    const body = { name: values.name.trim(), environment: values.environment.trim(), ...connectionAddressFields('admin_url', values.admin_url, !!editing), ...(values.proxy_origin !== undefined ? { proxy_origin: values.proxy_origin?.trim() || null } : {}), labels: values.labels ?? [], execution_mode: values.execution_mode, ...(connectionAuth(values) ? { connection_auth: connectionAuth(values) } : {}), ...(editing?.revision != null ? { revision: editing.revision } : {}) };
    return changes.execute({ change: { resource: 'clusters', operation: editing ? 'update' : 'create', ...(editing ? { resourceId: editing.id } : {}), input: body }, clusterId: editing?.id ?? null, targetWorkspaceId: null, allowed: !blocked && permission.registry('clusters', 'write') });
  }, onSuccess: async mode => { setOpen(false); form.resetFields(); if (mode === 'direct') { await queryClient.invalidateQueries({ queryKey: clustersQueryKey }); void message.success(editing ? '集群配置已保存' : '集群已登记，可进行连通性探测'); } }, onError: (e) => { setOperationError(e); void message.error(errorMessage(e)); } });
  const probe = useMutation({ mutationFn: (id: string) => api(`/clusters/${id}/probe`, { method: 'POST', body: '{}' }, true), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: clustersQueryKey }); void message.info('探测已完成，请查看集群状态与能力信息'); }, onError: (e) => { setOperationError(e); void message.error(errorMessage(e)); } });
  function showForm(item?: Cluster) {
    setEditing(item); form.resetFields();
    form.setFieldsValue(item ? { ...item, auth_type: 'keep' } : { environment: 'dev', admin_url: 'http://kong:8001', execution_mode: 'direct', labels: [], auth_type: 'none' });
    setOpen(true);
  }
  function deactivate(item: Cluster) {
    mutationConfirm(modal, { title: `确认停用“${item.name}”？`, expected: item.name, description: '停用集群登记，网关继续运行；审批模式下先生成变更预览。', okText: '确认停用', onConfirm: async () => { const mode = await changes.execute({ change: { resource: 'clusters', operation: 'deactivate', resourceId: item.id, input: { confirm: true, confirm_name: item.name, revision: item.revision } }, clusterId: item.id, targetWorkspaceId: null, allowed: !blocked && permission.registry('clusters', 'delete') }); if (mode === 'direct') { await queryClient.invalidateQueries({ queryKey: clustersQueryKey }); void message.success('集群已停用'); } } });
  }
  const filtered = clusters.filter(item => `${item.name} ${item.environment} ${item.labels.join(' ')}`.toLowerCase().includes(search.toLowerCase()));
  return <>
    <PageHeading title="集群管理" extra={<Button type="primary" icon={<PlusOutlined />} disabled={blocked || !permission.registry('clusters', 'write')} onClick={() => showForm()}>登记集群</Button>} />
    <ControlMetadataChanges flow={changes} />{operationError ? <QueryError error={operationError} /> : null}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    <Card className="table-card"><div className="table-toolbar"><Input allowClear prefix={<SearchOutlined />} placeholder="搜索名称、环境或标签" value={search} onChange={e => setSearch(e.target.value)} style={{ maxWidth: 360 }} /><Space><Typography.Text type="secondary">共 {filtered.length} 个集群</Typography.Text><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></Space></div><Table<Cluster> rowKey="id" loading={query.isLoading} dataSource={filtered} scroll={{ x: 1040 }} pagination={{ pageSize: 10, hideOnSinglePage: true }} columns={[
      { title: '集群', dataIndex: 'name', width: 220, render: (_, item) => <div><Button type="link" className="table-name" onClick={() => setDetails(item)}>{item.name}</Button>{item.id === clusterId && <Tag color="cyan" className="current-tag">当前</Tag>}<div className="table-secondary">{item.environment}{item.labels.map(tag => <Tag key={tag}>{tag}</Tag>)}</div></div> },
      { title: 'Admin API', dataIndex: 'admin_url', width: 260, render: value => <Typography.Text className="mono" ellipsis={{ tooltip: value }} style={{ maxWidth: 245 }}>{value ?? '连接地址受保护'}</Typography.Text> },
      { title: '版本 / 状态', width: 190, render: (_, item) => <div><StatusBadge status={item.status} /><div className="table-secondary">{item.version ? `Kong ${item.version}` : '版本待探测'}</div></div> },
      { title: '执行模式', width: 120, render: (_, item) => <Tag color={item.execution_mode === 'approval' ? 'gold' : 'cyan'}>{item.execution_mode === 'approval' ? '工单审批' : '直接执行'}</Tag> },
      { title: '操作', width: 265, fixed: 'right', render: (_, item) => <Space size={0}><Button type="link" size="small" icon={<ApiOutlined />} loading={probe.isPending && probe.variables === item.id} disabled={blocked || !permission.registry('clusters', 'write')} onClick={() => probe.mutate(item.id)}>探测</Button><Button type="link" size="small" icon={<EditOutlined />} disabled={blocked || !permission.registry('clusters', 'write')} onClick={() => showForm(item)}>编辑</Button><Button type="link" size="small" danger disabled={blocked || !permission.registry('clusters', 'delete')} onClick={() => deactivate(item)}>停用</Button></Space> },
    ]} /></Card>
    <Alert className="page-footnote" type="info" showIcon message="Admin API 网络隔离" description="登记地址仅供后端连接。前端不会直接请求 Kong 8001；连接地址还受后端出站访问策略校验。" />
    <Modal title={editing ? '编辑集群' : '登记 Kong 集群'} open={open} onCancel={() => { setOpen(false); form.resetFields(); }} onOk={() => form.submit()} okText="保存集群" cancelText="取消" confirmLoading={save.isPending} okButtonProps={{ disabled: blocked || (editing ? !permission.registry('clusters', 'write') : !permission.registry('clusters', 'write')) }} destroyOnClose width={580}><Form form={form} layout="vertical" onFinish={values => save.mutate(values)} requiredMark={false}><div className="form-two-col"><Form.Item label="集群名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入集群名称' }, { max: 100, message: '名称不能超过 100 字符' }]}><Input placeholder="例如：支付生产集群" /></Form.Item><Form.Item label="环境" name="environment" rules={[{ required: true, whitespace: true, message: '请输入环境' }]}><Input placeholder="dev / staging / prod" /></Form.Item></div><Form.Item label="Admin API 地址" name="admin_url" extra={editing && !editing.admin_url ? '保留当前连接地址；留空不修改。如需变更，请显式输入新的后端可达地址。' : '使用后端可达的地址，无需向浏览器或公网开放。'} rules={[{ required: !editing || !!editing.admin_url, message: '请输入 Admin API 地址' }, { pattern: /^https?:\/\/[^\s]+$/, message: '请输入 http:// 或 https:// 地址' }]}><Input placeholder={editing && !editing.admin_url ? '保留当前连接地址' : 'http://kong:8001'} /></Form.Item><Form.Item label="代理地址" name="proxy_origin" rules={[{ pattern: /^https?:\/\/[^\s]+$/, message: '请输入 HTTP/HTTPS 代理 origin' }]}><Input placeholder="http://kong:8000" allowClear /></Form.Item><Form.Item label="执行模式" name="execution_mode"><Select options={[{ value: 'direct', label: '直接执行：授权后执行变更' }, { value: 'approval', label: '工单审批：审批通过后执行变更' }]} /></Form.Item><Form.Item label="标签" name="labels"><Select mode="tags" tokenSeparators={[',']} placeholder="输入标签，回车确认" /></Form.Item><ConnectionAuthFields editing={!!editing} /><Typography.Paragraph type="secondary" className="small-note">连接秘密在后端加密保存；编辑时不回显原秘密。</Typography.Paragraph></Form></Modal>
    <Drawer title="集群详情" open={!!details} onClose={() => setDetails(undefined)} width={620}>{details && <><Space style={{ marginBottom: 24 }}><Typography.Title level={3} style={{ margin: 0 }}>{details.name}</Typography.Title><StatusBadge status={details.status} /></Space><Descriptions bordered column={1} size="small" items={[{ key: 'id', label: '集群 ID', children: <Typography.Text copyable className="mono">{details.id}</Typography.Text> }, { key: 'env', label: '环境', children: details.environment }, { key: 'url', label: 'Admin API', children: details.admin_url }, { key: 'version', label: '版本', children: details.version ?? '未探测' }, { key: 'probe', label: '最近探测', children: formatTime(details.last_probed_at) }, { key: 'mode', label: '执行模式', children: details.execution_mode === 'approval' ? '工单审批' : '直接执行' }]} /><Typography.Title level={5}>可用插件 · {details.enabled_plugins.length}</Typography.Title><div>{details.enabled_plugins.length ? details.enabled_plugins.map(name => <Tag key={name} style={{ marginBottom: 8 }}>{name}</Tag>) : <Typography.Text type="secondary">尚未获取插件清单</Typography.Text>}</div><Typography.Title level={5}>能力探测结果</Typography.Title><pre className="json-preview">{JSON.stringify(details.capabilities, null, 2)}</pre><Button type="primary" onClick={() => { selectCluster(details.id); setDetails(undefined); }}>切换至此集群</Button></>}</Drawer>
  </>;
}
