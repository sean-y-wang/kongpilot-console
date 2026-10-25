import { useEffect, useState } from 'react';
import { Alert, App, Button, Card, Form, Input, Modal, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { ApiOutlined, DatabaseOutlined, EditOutlined, PlusOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCluster } from '../app/ClusterContext';
import { api, errorMessage } from '../api/client';
import { listData, type DataSource } from '../api/types';
import { connectionAddressFields } from '../api/registry-payload';
import { usePermissions } from '../app/Permissions';
import { useWorkspace } from '../app/WorkspaceContext';
import { mutationConfirm } from '../components/MutationConfirm';
import { ConnectionAuthFields, connectionAuth } from '../components/ConnectionAuthFields';
import { PageHeading, NoCluster, QueryError, StatusBadge, formatTime } from '../components/Shared';
import { ControlMetadataChanges, useControlMetadataChanges } from './ControlMetadataChanges';

export function DataSourcesPage() {
  const { clusterId, cluster, query: clusterQuery } = useCluster();
  const queryClient = useQueryClient();
  const permission = usePermissions();
  const changes = useControlMetadataChanges(), blocked = useWorkspace().references.some(ref => ref.domain === 'iam') || changes.blocked;
  const [operationError, setOperationError] = useState<unknown>();
  const { message, modal } = App.useApp();
  const [form] = Form.useForm();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DataSource | undefined>();
  useEffect(() => { setOpen(false); setEditing(undefined); form.resetFields(); }, [clusterId, form]);
  const sourceType = Form.useWatch('type', form);
  const key = ['data-sources', clusterId];
  const query = useQuery({ queryKey: key, queryFn: async () => listData(await api<DataSource[]>(`/clusters/${clusterId}/data-sources`)), enabled: !!clusterId });
  const sources = query.data ?? [];
  const save = useMutation({ mutationFn: async (values: Record<string, any>) => {
    const body = { name: values.name.trim(), type: values.type, ...connectionAddressFields('base_url', values.base_url, !!editing), enabled: values.enabled, ...(connectionAuth(values) ? { auth: connectionAuth(values) } : {}), ...(editing?.revision != null ? { revision: editing.revision } : {}) };
    return changes.execute({ change: { resource: 'data-sources', operation: editing ? 'update' : 'create', ...(editing ? { resourceId: editing.id } : {}), input: body }, clusterId: clusterId ?? null, targetWorkspaceId: null, allowed: !blocked && !!clusterId && permission.registry('data-sources', 'write', clusterId) });
  }, onSuccess: async mode => { setOpen(false); form.resetFields(); if (mode === 'direct') { await queryClient.invalidateQueries({ queryKey: key }); void message.success('数据源配置已保存'); } }, onError: e => { setOperationError(e); void message.error(errorMessage(e)); } });
  const probe = useMutation({ mutationFn: (id: string) => api(`/clusters/${clusterId}/data-sources/${id}/probe`, { method: 'POST', body: '{}' }, true), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: key }); void message.info('连通性测试已完成，请查看数据源状态'); }, onError: e => { setOperationError(e); void message.error(errorMessage(e)); } });
  function showForm(item?: DataSource) {
    setEditing(item); form.resetFields();
    form.setFieldsValue(item ? { ...item, auth_type: 'keep' } : { type: 'prometheus', enabled: true, auth_type: 'none' });
    setOpen(true);
  }
  function deactivate(item: DataSource) {
    mutationConfirm(modal, { title: `确认移除“${item.name}”？`, expected: item.name, description: '停用此数据源绑定，数据源服务继续运行；审批模式下先生成变更预览。', okText: '确认移除', onConfirm: async () => { const mode = await changes.execute({ change: { resource: 'data-sources', operation: 'deactivate', resourceId: item.id, input: { confirm: true, confirm_name: item.name, revision: item.revision } }, clusterId: item.cluster_id, targetWorkspaceId: null, allowed: !blocked && clusterId === item.cluster_id && permission.registry('data-sources', 'delete', item.cluster_id) }); if (mode === 'direct') { await queryClient.invalidateQueries({ queryKey: key }); void message.success('数据源已移除'); } } });
  }
  return <>
    <PageHeading title="数据源管理" extra={<Button type="primary" icon={<PlusOutlined />} disabled={blocked || !clusterId || !permission.registry('data-sources', 'write', clusterId)} onClick={() => showForm()}>添加数据源</Button>} />
    {clusterQuery.isError && <QueryError error={clusterQuery.error} retry={() => void clusterQuery.refetch()} />}
    <ControlMetadataChanges flow={changes} />{operationError ? <QueryError error={operationError} /> : null}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {!clusterId && !clusterQuery.isLoading ? <NoCluster /> : <><div className="provider-intro"><div><span className="provider-symbol prometheus">P</span><div><strong>Prometheus</strong><p>网关指标与时序查询</p></div></div><div><span className="provider-symbol loki">L</span><div><strong>Loki</strong><p>结构化访问日志与检索</p></div></div><div className="provider-note"><DatabaseOutlined /><span>数据源按集群绑定，连接仅由后端发起。</span></div></div><Card className="table-card"><div className="table-toolbar"><Typography.Text type="secondary">{sources.length} 个已绑定数据源</Typography.Text><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></div><Table<DataSource> rowKey="id" loading={query.isLoading} dataSource={sources} scroll={{ x: 900 }} pagination={{ pageSize: 10, hideOnSinglePage: true }} columns={[
      { title: '数据源', width: 200, render: (_, item) => <div><strong>{item.name}</strong><div className="table-secondary"><Tag color={item.type === 'prometheus' ? 'orange' : 'purple'}>{item.type === 'prometheus' ? 'Prometheus' : 'Loki'}</Tag>{!item.enabled && <Tag>已禁用</Tag>}</div></div> },
      { title: '服务地址', dataIndex: 'base_url', width: 260, render: value => <Typography.Text className="mono" ellipsis={{ tooltip: value }} style={{ maxWidth: 245 }}>{value ?? '连接地址受保护'}</Typography.Text> },
      { title: '连接状态', width: 160, render: (_, item) => <StatusBadge status={item.enabled ? item.last_status : 'disabled'} /> },
      { title: '最后探测时间', width: 195, render: (_, item) => <Typography.Text type="secondary">{formatTime(item.last_probed_at)}</Typography.Text> },
      { title: '操作', width: 245, fixed: 'right', render: (_, item) => <Space size={0}><Button type="link" size="small" icon={<ApiOutlined />} loading={probe.isPending && probe.variables === item.id} disabled={blocked || !permission.registry('data-sources', 'write', clusterId)} onClick={() => probe.mutate(item.id)}>测试</Button><Button type="link" size="small" icon={<EditOutlined />} disabled={blocked || !permission.registry('data-sources', 'write', clusterId)} onClick={() => showForm(item)}>编辑</Button><Button type="link" size="small" danger disabled={blocked || !permission.registry('data-sources', 'delete', clusterId)} onClick={() => deactivate(item)}>移除</Button></Space> },
    ]} /></Card><Alert type="info" showIcon className="page-footnote" message="连接正常只代表服务可访问" description="Kong 指标需要启用 prometheus 插件并配置抓取；日志需要日志插件与采集链路。监控与日志数据将在后续模块验证。" /></>}
    <Modal title={editing ? '编辑数据源' : '添加数据源'} open={open} onCancel={() => { setOpen(false); form.resetFields(); }} onOk={() => form.submit()} okText="保存数据源" cancelText="取消" confirmLoading={save.isPending} okButtonProps={{ disabled: blocked || (editing ? !permission.registry('data-sources', 'write', clusterId) : !permission.registry('data-sources', 'write', clusterId)) }} destroyOnClose width={560}><Form form={form} layout="vertical" requiredMark={false} onFinish={values => save.mutate(values)}><Form.Item label="数据源名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入数据源名称' }]}><Input placeholder="例如：生产指标平台" /></Form.Item><Form.Item label="数据源类型" name="type" rules={[{ required: true }]}><Select options={[{ value: 'prometheus', label: 'Prometheus · 指标' }, { value: 'loki', label: 'Loki · 日志' }]} /></Form.Item><Form.Item label="服务地址" name="base_url" rules={[{ required: !editing || !!editing.base_url, message: '请输入服务地址' }, { pattern: /^https?:\/\/[^\s]+$/, message: '请输入 http:// 或 https:// 地址' }]} extra={editing && !editing.base_url ? '保留当前连接地址；留空不修改。如需变更，请显式输入新的服务地址。' : '使用控制台后端可达的服务地址。'}><Input placeholder={editing && !editing.base_url ? '保留当前连接地址' : sourceType === 'loki' ? 'http://loki:3100' : 'http://prometheus:9090'} /></Form.Item><ConnectionAuthFields editing={!!editing} /><Form.Item name="enabled" label="启用连接" valuePropName="checked"><Switch checkedChildren="启用" unCheckedChildren="禁用" /></Form.Item><Typography.Paragraph type="secondary" className="small-note">认证信息只提交至后端加密保存，编辑时不回显。</Typography.Paragraph></Form></Modal>
  </>;
}
