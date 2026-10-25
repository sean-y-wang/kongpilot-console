import { useEffect, useState } from 'react';
import { Alert, App, Button, Card, Drawer, Form, Input, InputNumber, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, patch } from '../api/client';
import { redactForDisplay } from '../api/redaction';
import { scopeQuery } from '../api/workspace-scope';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { NoCluster, PageHeading, QueryError } from '../components/Shared';
import { EntityEditor } from './EntityEditor';
import { entityName, type EntityPageData } from './entities';

interface ChildRow { type: string; id: string; parent_id: string; entity: any; read: boolean; write: boolean; delete: boolean; approve: boolean; reveal: boolean; }
interface ChildPage extends EntityPageData { items: ChildRow[]; permissionsVersion: string; discovery: 'observed-parent-index'; }
const kinds = ['targets', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
export function AuthorizedChildrenPage() {
  const { user } = useAuth(), { clusterId, cluster } = useCluster(), workspace = useWorkspace(), client = useQueryClient(), { modal } = App.useApp();
  const [type, setType] = useState(''), [editing, setEditing] = useState<ChildRow>(), [preview, setPreview] = useState<ChildRow>(), [revealed, setRevealed] = useState<any>(), [error, setError] = useState<unknown>(), [saving, setSaving] = useState(false);
  const [form] = Form.useForm();
  const pages = useCursorPages(`${clusterId}:${workspace.workspaceId}:${type}:${user?.permissionsVersion}`);
  const params = new URLSearchParams({ size: '20' }); if (type) params.set('type', type); if (pages.cursor) params.set('cursor', pages.cursor);
  const scoped = (path: string) => scopeQuery(path, clusterId, workspace.workspaceId);
  const query = useQuery({ queryKey: ['authorized-children', clusterId, workspace.workspaceId, user?.permissionsVersion, params.toString()], queryFn: () => api<ChildPage>(scoped(`/clusters/${clusterId}/authorization/children?${params}`)), enabled: workspace.ready });
  const blocked = workspace.writeBlocked || workspace.readonlyWorkspace || cluster?.execution_mode === 'approval';
  useEffect(() => { setEditing(undefined); setPreview(undefined); setRevealed(undefined); setError(undefined); form.resetFields(); }, [clusterId, workspace.workspaceId, form]);
  useEffect(() => { if (query.data && query.data.permissionsVersion !== user?.permissionsVersion) window.dispatchEvent(new CustomEvent('kongos:permission-stale', { detail: { actorId: user?.id } })); }, [query.data?.permissionsVersion, user?.permissionsVersion, user?.id]);
  const items = query.data && query.data.permissionsVersion === user?.permissionsVersion ? query.data.items : [];
  const endpoint = (row: ChildRow) => row.type === 'targets' ? `/clusters/${clusterId}/upstreams/${row.parent_id}/targets` : `/clusters/${clusterId}/consumers/${row.parent_id}/credentials/${row.type}`;
  async function refresh() { await client.invalidateQueries({ predicate: q => q.queryKey.includes(clusterId) && q.queryKey.includes(workspace.workspaceId) }); }
  function edit(row: ChildRow) { setError(undefined); setEditing(row); if (row.type === 'targets') { form.resetFields(); form.setFieldsValue({ target: row.entity.target, weight: row.entity.weight, tags: (row.entity.tags ?? []).filter((tag: string) => !tag.startsWith('workspace:')) }); } }
  function remove(row: ChildRow) { mutationConfirm(modal, { title: '删除授权子实体并归档', expected: entityName(row.entity), description: '删除前会捕获对象并进入当前工作区回收站；所属对象继续保留。', onConfirm: async () => { try { await api(scoped(`${endpoint(row)}/${row.id}`), { method: 'DELETE', body: JSON.stringify({ confirmed: true, confirm_name: entityName(row.entity) }) }); await refresh(); } catch (cause) { setError(cause); throw cause; } } }); }
  async function reveal(row: ChildRow) { try { setRevealed(await api(scoped(`${endpoint(row)}/${row.id}?reveal=true`))); } catch (cause) { setError(cause); } }
  function setHealth(row: ChildRow, state: 'healthy' | 'unhealthy') { mutationConfirm(modal, { title: state === 'healthy' ? '手动标记 Target 健康' : '手动标记 Target 不健康', expected: entityName(row.entity), description: '健康置位作用于当前 Admin 节点，其他节点可能不同；请结合真实代理请求核验。', danger: state === 'unhealthy', onConfirm: async () => { try { await api(scoped(`${endpoint(row)}/${row.id}/${state}`), { method: 'POST', body: '{}' }); await refresh(); } catch (cause) { setError(cause); throw cause; } } }); }
  return <>
    <PageHeading title="授权子实体" />
    <Alert showIcon type="info" message="仅展示已发现且当前获准访问的子实体" description="历史对象若尚未出现，请管理员先访问所属 Upstream 的 Targets 或 Consumer 的凭证列表，再刷新此页。导航关系不授予额外权限。" style={{ marginBottom: 20 }} />
    {error ? <QueryError error={error} /> : null}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {!clusterId ? <NoCluster /> : <Card className="table-card"><div className="entity-filter-bar"><Select aria-label="授权子实体类型" value={type} onChange={setType} style={{ minWidth: 230 }} options={[{ value: '', label: '全部子实体类型' }, ...kinds.map(value => ({ value, label: value }))]} /><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></div><Table rowKey={row => `${row.type}:${row.id}`} pagination={false} loading={query.isFetching} dataSource={items} scroll={{ x: 1150 }} columns={[{ title: '子实体', width: 260, render: (_, row) => <div><Button type="link" className="table-name" onClick={() => setPreview(row)}>{entityName(row.entity)}</Button><Tag>{row.type}</Tag><div className="mono table-secondary">{row.id}</div></div> }, { title: '所属对象 ID', width: 310, render: (_, row) => <Typography.Text className="mono">{row.parent_id}</Typography.Text> }, { title: '授权操作', width: 230, render: (_, row) => <Space wrap>{['read', 'write', 'delete', 'reveal'].filter(action => row[action as keyof ChildRow] === true).map(action => <Tag key={action}>{{ read: '读取', write: '写入', delete: '删除', reveal: '查看秘密' }[action]}</Tag>)}</Space> }, { title: '操作', width: 300, render: (_, row) => <Space size={0}><Button type="link" disabled={blocked || !row.write} onClick={() => edit(row)}>编辑</Button>{row.type === 'targets' && <><Button type="link" disabled={blocked || !row.write} onClick={() => setHealth(row, 'healthy')}>健康</Button><Button type="link" disabled={blocked || !row.write} onClick={() => setHealth(row, 'unhealthy')}>不健康</Button></>}{row.type !== 'targets' && <Button type="link" disabled={!row.reveal} onClick={() => void reveal(row)}>查看秘密</Button>}<Button type="link" danger disabled={blocked || !row.delete} onClick={() => remove(row)}>删除</Button></Space> }]} /><CursorPagination pages={pages} size={20} count={items.length} nextCursor={query.data?.nextCursor} loading={query.isFetching} /></Card>}
    <Drawer title={`子实体配置 · ${preview?.type ?? ''}`} width={680} open={!!preview} onClose={() => setPreview(undefined)} destroyOnClose><pre className="json-preview">{JSON.stringify(redactForDisplay(preview?.entity), null, 2)}</pre></Drawer>
    {editing && editing.type !== 'targets' && <EntityEditor type={editing.type} parentId={editing.parent_id} entity={editing.entity} endpoint={endpoint(editing)} omitFields={['consumer']} open onClose={() => setEditing(undefined)} onSaved={refresh} />}
    <Modal title="编辑授权 Target" open={editing?.type === 'targets'} onCancel={() => setEditing(undefined)} onOk={() => form.submit()} okText="保存 Target" confirmLoading={saving} okButtonProps={{ disabled: blocked || !editing?.write }} destroyOnClose>{error ? <QueryError error={error} /> : null}<Form form={form} layout="vertical" onFinish={async values => { setSaving(true); try { await patch(scoped(`${endpoint(editing!)}/${editing!.id}`), values); setEditing(undefined); await refresh(); } catch (cause) { setError(cause); } finally { setSaving(false); } }}><Form.Item name="target" label="Target 地址" rules={[{ required: true }]}><Input aria-label="授权 Target 地址" /></Form.Item><Form.Item name="weight" label="权重" rules={[{ required: true }]}><InputNumber min={0} max={1000} style={{ width: '100%' }} /></Form.Item><Form.Item name="tags" label="业务标签"><Select mode="tags" tokenSeparators={[',']} /></Form.Item></Form></Modal>
    <Modal title="授权查看的凭证秘密" open={!!revealed} onCancel={() => setRevealed(undefined)} footer={<Button onClick={() => setRevealed(undefined)}>关闭并清除</Button>} destroyOnClose><Alert showIcon type="warning" message="此内容包含凭证秘密，请妥善保管。" style={{ marginBottom: 16 }} /><pre className="json-preview">{JSON.stringify(revealed, null, 2)}</pre></Modal>
  </>;
}
