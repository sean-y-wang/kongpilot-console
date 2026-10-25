import { useEffect, useState } from 'react';
import { Alert, App, Button, Card, Form, Input, Modal, Select, Space, Table, Tabs, Tag, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace, type Workspace, type WorkspacePageData } from '../app/WorkspaceContext';
import { useAuth } from '../app/AuthContext';
import { usePermissions } from '../app/Permissions';
import { api } from '../api/client';
import { canonicalId } from '../api/workspace-scope';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { PagedIAMLookup } from './IAMLookups';
import { NoCluster, PageHeading, QueryError, formatTime } from '../components/Shared';
import { ControlMetadataChanges, useControlMetadataChanges } from './ControlMetadataChanges';

export function WorkspacesPage() {
  const { clusterId, cluster } = useCluster();
  const context = useWorkspace();
  const { user } = useAuth();
  const permission = usePermissions();
  const { message, modal } = App.useApp();
  const client = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const deleted = searchParams.get('tab') === 'trash';
  const [status, setStatus] = useState('active');
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<Workspace>();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<unknown>();
  const [form] = Form.useForm();
  const pages = useCursorPages(JSON.stringify([clusterId, context.workspaceId, deleted, status, search]));
  const params = new URLSearchParams({ size: '20', status: deleted ? 'deleted' : status });
  if (search) params.set('search', search);
  if (pages.cursor) params.set('cursor', pages.cursor);
  const base = `/clusters/${clusterId}/workspaces`;
  const query = useQuery({ queryKey: ['workspace-registry', clusterId, context.workspaceId, params.toString()], queryFn: () => api<WorkspacePageData>(`${base}?${params}`), enabled: !!clusterId });
  const changes = useControlMetadataChanges(), blocked = !clusterId || context.references.some(ref => ref.cid === clusterId) || changes.blocked;
  useEffect(() => { setOpen(false); setEditing(undefined); setSearch(''); }, [clusterId]);
  async function refresh() { await client.invalidateQueries({ predicate: query => query.queryKey.includes(clusterId) }); await context.refresh(); }
  const save = useMutation({ mutationFn: (values: any) => changes.execute({ change: { resource: 'workspaces', operation: editing ? 'update' : 'create', ...(editing ? { resourceId: editing.id } : {}), input: editing ? { revision: editing.revision, name: values.name, description: values.description ?? '', owner_user_id: values.owner_user_id || null, status: values.status } : { code: values.code, name: values.name, description: values.description ?? '', ...(values.owner_user_id ? { owner_user_id: values.owner_user_id } : {}) } }, clusterId: clusterId ?? null, targetWorkspaceId: editing?.id ?? context.defaultWorkspaceId ?? null, subject: editing, allowed: !blocked && (editing ? permission.can('workspaces', 'write', editing, { workspaceId: editing.id }) : !!context.defaultWorkspaceId && permission.create('workspaces', { workspaceId: context.defaultWorkspaceId })) }), onSuccess: async mode => { setOpen(false); if (mode === 'direct') { await refresh(); void message.success('工作区已保存'); } }, onError: setError });
  function show(row?: Workspace) { setEditing(row); setError(undefined); form.resetFields(); form.setFieldsValue(row ?? { status: 'active', owner_user_id: user?.id }); setOpen(true); }
  function change(row: Workspace, action: 'delete' | 'restore') {
    mutationConfirm(modal, { title: action === 'delete' ? '将工作区移入回收站' : '恢复工作区', expected: row.name, description: action === 'delete' ? '仅空工作区可删除。工作区元数据进入回收站，网关实体不会随之删除；默认工作区受保护。' : '恢复工作区元数据，代码与原工作区 ID 保持一致。', danger: action === 'delete', onConfirm: async () => { try { const mode = await changes.execute({ change: { resource: 'workspaces', operation: action === 'delete' ? 'archive' : 'restore', resourceId: row.id, input: { revision: row.revision, confirmed: true, confirm_name: row.name } }, clusterId: row.cluster_id, targetWorkspaceId: row.id, subject: row, allowed: !blocked && clusterId === row.cluster_id && permission.can('workspaces', action === 'delete' ? 'delete' : 'write', row, { clusterId: row.cluster_id, workspaceId: row.id }) }); if (mode === 'direct') await refresh(); } catch (e) { setError(e); throw e; } } });
  }
  return <>
    <PageHeading title="工作区管理" extra={<><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void refresh()}>刷新</Button><Button type="primary" icon={<PlusOutlined />} disabled={blocked || !context.defaultWorkspaceId || !permission.create('workspaces', { workspaceId: context.defaultWorkspaceId })} onClick={() => show()}>创建工作区</Button></>} />
    <ControlMetadataChanges flow={changes} />
    <Alert type="warning" showIcon className="workspace-isolation-notice" message="工作区采用标签软隔离" description={<><p>Kong OSS 1.5 没有原生工作区。控制台使用保留标签限制管理范围，直连 Admin API 可以绕过；历史未打标实体属于默认工作区，可通过迁移流程归属到团队。</p><p>全局插件仍作用于整个网关。标签不会限制网关流量或提供运行时安全边界。</p><Typography.Text type="secondary">逻辑标签 workspace:code 在 Kong 中编码为 kos-ws-code；归属标签由系统维护。</Typography.Text></>} style={{ marginBottom: 24 }} />
    {!!error && <QueryError error={error} />}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {!clusterId ? <NoCluster /> : <Tabs activeKey={deleted ? 'trash' : 'active'} onChange={key => setSearchParams(key === 'trash' ? { tab: 'trash' } : {})} items={[{ key: 'active', label: '工作区', children: <Card className="table-card"><div className="entity-filter-bar"><Input.Search aria-label="搜索工作区" placeholder="搜索名称或代码" allowClear onSearch={setSearch} /><Select aria-label="工作区状态" value={status} onChange={setStatus} options={[{ value: 'active', label: '已启用' }, { value: 'disabled', label: '已停用' }]} /></div><WorkspaceTable rows={query.data?.items ?? []} loading={query.isFetching} blocked={blocked} onEdit={show} onDelete={row => change(row, 'delete')} onSelect={context.selectWorkspace} selectedId={context.workspaceId} /><CursorPagination pages={pages} nextCursor={query.data?.nextCursor} loading={query.isFetching} count={query.data?.items.length ?? 0} size={20} /></Card> }, { key: 'trash', label: '工作区回收站', children: <Card className="table-card"><Alert type="info" showIcon message="工作区仅软删除" description="此处可按原 ID 恢复；不提供物理删除工作区的接口。" style={{ margin: 20 }} /><WorkspaceTable rows={query.data?.items ?? []} loading={query.isFetching} blocked={blocked} onRestore={row => change(row, 'restore')} /><CursorPagination pages={pages} nextCursor={query.data?.nextCursor} loading={query.isFetching} count={query.data?.items.length ?? 0} size={20} /></Card> }]} />}
    <Modal title={editing ? '编辑工作区' : '创建工作区'} open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} okText="保存工作区" cancelText="取消" confirmLoading={save.isPending} okButtonProps={{ disabled: blocked || (editing ? !permission.can('workspaces', 'write', editing, { workspaceId: editing.id }) : !permission.create('workspaces', { workspaceId: context.defaultWorkspaceId })) }} destroyOnClose>{error ? <QueryError error={error} /> : null}<Form form={form} layout="vertical" onFinish={values => save.mutate(values)}><Form.Item name="code" label="工作区代码" rules={[{ required: !editing, pattern: /^[a-z][a-z0-9_-]{0,47}$/, message: '使用小写字母、数字、下划线或连字符，以字母开头' }]}><Input aria-label="code" disabled={!!editing} placeholder="如 payment" /></Form.Item><Form.Item name="name" label="工作区名称" rules={[{ required: true, message: '请输入工作区名称' }]}><Input aria-label="name" maxLength={128} /></Form.Item><Form.Item name="owner_user_id" label="负责人用户 ID" rules={[{ validator: (_, value) => !value || canonicalId(value) ? Promise.resolve() : Promise.reject(new Error('请输入有效用户 UUID')) }]}><PagedIAMLookup resource="users" label="owner_user_id" clusterId={clusterId} workspaceId={editing?.id ?? context.defaultWorkspaceId} /></Form.Item><Button type="link" size="small" onClick={() => form.setFieldValue('owner_user_id', user?.id)}>设为我（{user?.username}）</Button><Form.Item name="description" label="工作区说明"><Input.TextArea aria-label="description" rows={3} maxLength={8192} /></Form.Item>{editing && <Form.Item name="status" label="状态"><Select disabled={editing.is_default} options={[{ value: 'active', label: '已启用' }, { value: 'disabled', label: '已停用' }]} /></Form.Item>}</Form></Modal>
  </>;
}
function WorkspaceTable({ rows, loading, blocked, onEdit, onDelete, onRestore, onSelect, selectedId }: { rows: Workspace[]; loading: boolean; blocked: boolean; onEdit?: (row: Workspace) => void; onDelete?: (row: Workspace) => void; onRestore?: (row: Workspace) => void; onSelect?: (id: string) => void; selectedId?: string }) {
  const permission = usePermissions();
  return <Table rowKey="id" dataSource={rows} loading={loading} pagination={false} scroll={{ x: 1000 }} columns={[{ title: '名称 / 代码', width: 230, render: (_, row) => <div><strong>{row.name}</strong>{row.is_default && <Tag style={{ marginLeft: 8 }}>默认</Tag>}{row.id === selectedId && <Tag color="cyan">当前</Tag>}<div className="table-secondary mono">{row.code}</div></div> }, { title: '负责人', width: 280, dataIndex: 'owner_user_id', render: value => value ?? '未设置' }, { title: '说明', dataIndex: 'description', width: 220, render: value => value || '未填写' }, { title: '状态', width: 120, render: (_, row) => <Tag color={row.status === 'active' ? 'green' : 'default'}>{row.status === 'active' ? '已启用' : row.status === 'deleted' ? '已回收' : '已停用'}</Tag> }, { title: '更新时间', width: 170, render: (_, row) => formatTime(row.updated_at) }, { title: '操作', fixed: 'right', width: 180, render: (_, row) => <Space size={0}>{onRestore ? <Button type="link" disabled={blocked || !permission.can('workspaces', 'write', row, { clusterId: row.cluster_id, workspaceId: row.id })} onClick={() => onRestore(row)}>恢复</Button> : <><Button type="link" disabled={row.status === 'deleted'} onClick={() => onSelect?.(row.id)}>切换</Button><Button type="link" disabled={blocked || !permission.can('workspaces', 'write', row, { clusterId: row.cluster_id, workspaceId: row.id })} onClick={() => onEdit?.(row)}>编辑</Button><Button type="link" danger disabled={blocked || row.is_default || !permission.can('workspaces', 'delete', row, { clusterId: row.cluster_id, workspaceId: row.id })} onClick={() => onDelete?.(row)}>删除</Button></>}</Space> }]} />;
}
