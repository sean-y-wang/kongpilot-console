import { ScopeLabel } from '../components/ScopeLabel';
import { useEffect, useState } from 'react';
import { Alert, App, Button, Drawer, Form, Input, Modal, Select, Space, Table, Tabs, Tag } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { usePermissions } from '../app/Permissions';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError, formatTime } from '../components/Shared';
import { IAMWorkspaceLookup, PagedIAMLookup } from './IAMLookups';
import { iamRowName, type IAMPageData, type IAMRow } from './iam.types';
import { useIamChanges } from './IAMChanges';

export function IAMBindings({ type, row, open, onClose }: { type: 'users' | 'teams'; row: IAMRow; open: boolean; onClose: () => void }) {
  const { modal } = App.useApp(), { reloadCapabilities } = useAuth(), permission = usePermissions(), context = useWorkspace(), { clusterId, clusters } = useCluster();
  const changes = useIamChanges();
  const [tab, setTab] = useState('role-bindings'), [status, setStatus] = useState('active'), [adding, setAdding] = useState(false), [working, setWorking] = useState(false), [error, setError] = useState<unknown>();
  const [bindingScope, setBindingScope] = useState(permission.can('users', 'read', undefined, { clusterId: undefined, workspaceId: undefined }) && permission.can('roles', 'read', undefined, { clusterId: undefined, workspaceId: undefined }) ? 'global' : 'current');
  const scope = type === 'users' ? { clusterId: bindingScope === 'global' ? undefined : clusterId, workspaceId: bindingScope === 'current' ? context.workspaceId : undefined } : { clusterId: row.cluster_id ?? undefined, workspaceId: row.workspace_id ?? undefined };
  const [form] = Form.useForm(), cid = Form.useWatch('cluster_id', form), wid = Form.useWatch('workspace_id', form);
  const pages = useCursorPages(JSON.stringify([type, row.id, tab, status, scope, permission.version]));
  const base = `/iam/${type}/${row.id}/${tab}`;
  const params = new URLSearchParams({ size: '20', status }); if (pages.cursor) params.set('cursor', pages.cursor); if (type === 'users' && scope.clusterId) params.set('clusterId', scope.clusterId); if (type === 'users' && scope.workspaceId) params.set('workspaceId', scope.workspaceId);
  const query = useQuery({ queryKey: ['iam-bindings', type, row.id, tab, status, scope, permission.version, pages.cursor], queryFn: () => api<IAMPageData<any>>(`${base}?${params}`), enabled: open && (type !== 'users' || bindingScope === 'global' || !!scope.clusterId && (bindingScope !== 'current' || !!scope.workspaceId)) });
  const hasGlobalUserWrite = permission.can('users', 'write', undefined, { clusterId: undefined, workspaceId: undefined });
  const allowedBinding = (action: 'write' | 'delete', binding: { clusterId?: string; workspaceId?: string }) => !(binding.workspaceId === context.workspaceId && context.readonlyWorkspace) && permission.can(type === 'users' ? 'roles' : type, action, row, binding) && (type !== 'users' || !!binding.clusterId || hasGlobalUserWrite);
  const blocked = changes.blocked || !allowedBinding('write', scope) || context.references.some(ref => ref.domain === 'iam') || scope.workspaceId === context.workspaceId && context.readonlyWorkspace;
  const proposedBlocked = blocked || tab === 'role-bindings' && type === 'users' && !allowedBinding('write', { clusterId: cid, workspaceId: wid });
  useEffect(() => { setTab('role-bindings'); setStatus('active'); setError(undefined); }, [row.id]);
  async function refresh() { await query.refetch(); await reloadCapabilities(); }
  function add() { form.resetFields(); form.setFieldsValue({ cluster_id: scope.clusterId, workspace_id: scope.workspaceId }); setAdding(true); setError(undefined); }
  function change(item: any, restore: boolean) {
    const name = tab === 'members' ? item.username : item.role_name;
    const itemId = tab === 'members' ? item.user_id : item.id;
    mutationConfirm(modal, { title: restore ? '恢复授权关系' : '撤销授权关系', expected: name, description: '关系只进入可恢复的撤销状态；有效权限会按用户及团队当前状态重新计算。', danger: !restore, onConfirm: async () => { try { const body = { revision: item.revision, confirmed: true, confirm_name: name }; await changes.execute({ change: { resource: type, operation: tab === 'members' ? restore ? 'member.restore' : 'member.revoke' : restore ? 'binding.restore' : 'binding.revoke', resourceId: row.id, relatedId: itemId, input: body }, allowed: !changes.blocked && !context.references.some(ref => ref.domain === 'iam') && allowedBinding(restore ? 'write' : 'delete', type === 'users' ? { clusterId: item.cluster_id ?? undefined, workspaceId: item.workspace_id ?? undefined } : scope), onSaved: refresh }); } catch (e) { setError(e); throw e; } } });
  }
  return <Drawer title={`${iamRowName(row)} · ${type === 'users' ? '角色授权' : '团队成员与角色'}`} width={880} open={open} onClose={onClose} destroyOnClose>
    <Alert type="info" showIcon message="授权关系保留历史" description="撤销的角色绑定与成员关系可在历史标签中恢复；内置 super-admin 角色只允许受保护的直接授权，不能通过团队间接授予。" style={{ marginBottom: 20 }} />
    <Tabs activeKey={tab} onChange={setTab} items={[{ key: 'role-bindings', label: '角色授权' }, ...(type === 'teams' ? [{ key: 'members', label: '团队成员' }] : [])]} />
    {error ? <QueryError error={error} /> : null}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    <div className="embedded-toolbar"><Space wrap>{type === 'users' && <Select aria-label="用户授权范围" value={bindingScope} onChange={value => { setBindingScope(value); setError(undefined); }} options={[{ value: 'global', label: '全局授权关系' }, { value: 'cluster', label: '当前集群授权关系' }, { value: 'current', label: '当前工作区授权关系' }]} />}<Select aria-label="授权关系状态" value={status} onChange={setStatus} options={[{ value: 'active', label: '有效关系' }, { value: 'revoked', label: '已撤销 / 回收记录' }]} /></Space><Space><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void refresh()}>刷新</Button><Button type="primary" icon={<PlusOutlined />} disabled={blocked} onClick={add}>{tab === 'members' ? '添加成员' : '授予角色'}</Button></Space></div>
    <Table rowKey={item => item.id ?? item.user_id} size="small" pagination={false} dataSource={query.data?.items ?? []} loading={query.isFetching} scroll={{ x: 700 }} columns={[{ title: tab === 'members' ? '成员' : '角色', render: (_, item) => tab === 'members' ? item.username : item.role_name }, { title: '范围', render: (_, item) => <ScopeLabel clusterId={item.cluster_id} workspaceId={item.workspace_id} /> }, { title: '状态', render: (_, item) => <Tag color={item.status === 'active' ? 'green' : 'default'}>{item.status === 'active' ? '有效' : '已撤销'}</Tag> }, ...(tab === 'role-bindings' ? [{ title: '到期时间', render: (_: any, item: any) => item.expires_at ? formatTime(item.expires_at) : '不设到期' }] : []), { title: '操作', render: (_, item) => <Button type="link" danger={item.status === 'active'} disabled={changes.blocked || context.readonlyWorkspace && scope.workspaceId === context.workspaceId || context.references.some(ref => ref.domain === 'iam') || !allowedBinding(item.status === 'active' ? 'delete' : 'write', type === 'users' ? { clusterId: item.cluster_id ?? undefined, workspaceId: item.workspace_id ?? undefined } : scope)} onClick={() => change(item, item.status !== 'active')}>{item.status === 'active' ? '撤销' : '恢复'}</Button> }]} /><CursorPagination pages={pages} size={20} count={query.data?.items.length ?? 0} nextCursor={query.data?.nextCursor} loading={query.isFetching} />
    <Modal title={tab === 'members' ? '添加团队成员' : '授予角色'} open={adding} onCancel={() => setAdding(false)} onOk={() => form.submit()} okText="审阅并确认" cancelText="取消" confirmLoading={working} okButtonProps={{ disabled: proposedBlocked }} destroyOnClose><Form form={form} layout="vertical" onFinish={values => { if (proposedBlocked) return; mutationConfirm(modal, { title: tab === 'members' ? '确认加入团队' : '确认授予角色', expected: iamRowName(row), description: '此操作会改变目标用户或团队成员的有效访问范围。后端会校验授权者权限上限与受保护角色约束。', danger: false, onConfirm: async () => { setWorking(true); try { const body = tab === 'members' ? { user_id: values.user_id } : { role_id: values.role_id, ...(values.cluster_id ? { cluster_id: values.cluster_id } : {}), ...(values.workspace_id ? { workspace_id: values.workspace_id } : {}), ...(values.expires_at ? { expires_at: new Date(values.expires_at).toISOString() } : {}) }; await changes.execute({ change: { resource: type, operation: tab === 'members' ? 'member.add' : 'binding.grant', resourceId: row.id, input: body }, allowed: !proposedBlocked, onSaved: refresh }); setAdding(false); } catch (e) { setError(e); throw e; } finally { setWorking(false); } } }); }}>
      {tab === 'members' ? <Form.Item name="user_id" label="用户" rules={[{ required: true }]}><PagedIAMLookup label="user_id" resource="users" clusterId={scope.clusterId} workspaceId={scope.workspaceId} /></Form.Item> : <><Form.Item name="cluster_id" label="授权集群"><Select aria-label="binding_cluster_id" allowClear placeholder="全局（须有授权）" options={clusters.map(item => ({ value: item.id, label: item.name }))} onChange={() => form.setFieldsValue({ workspace_id: undefined, role_id: undefined })} /></Form.Item><Form.Item name="workspace_id" label="授权工作区"><IAMWorkspaceLookup clusterId={cid} label="binding_workspace_id" onChange={() => form.setFieldValue('role_id', undefined)} /></Form.Item><Form.Item name="role_id" label="角色" rules={[{ required: true }]}><PagedIAMLookup label="role_id" resource="roles" clusterId={cid} workspaceId={wid} /></Form.Item><Form.Item name="expires_at" label="授权到期时间" rules={[{ validator: (_, value) => !value || Number.isFinite(Date.parse(value)) && Date.parse(value) > Date.now() ? Promise.resolve() : Promise.reject(new Error('请输入未来的 ISO 日期时间')) }]}><Input placeholder="可选，如 2027-01-01T00:00:00Z" /></Form.Item></>}
    </Form></Modal>
  </Drawer>;
}
