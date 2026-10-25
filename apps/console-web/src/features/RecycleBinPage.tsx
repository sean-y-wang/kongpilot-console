import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Select, Space, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, ReloadOutlined, RollbackOutlined } from '@ant-design/icons';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useWorkspace, type Workspace, type WorkspacePageData } from '../app/WorkspaceContext';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { useCluster } from '../app/ClusterContext';
import { usePermissions } from '../app/Permissions';
import { api, ApiError, errorMessage, getApiActorId, post } from '../api/client';
import { redactForDisplay } from '../api/redaction';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { NoCluster, PageHeading, QueryError, formatTime } from '../components/Shared';
import { entityLabels, type EntityPageData } from './entities';
import { ControlMetadataChanges, useControlMetadataChanges } from './ControlMetadataChanges';
import { RecycleReconciliation } from './RecycleReconciliation';
import { useEntityChangePreparation } from './EntityEditor';
import { entityEntryIntentHref } from './entity-entry-change.model';

const stateLabels: Record<string, string> = { archived: '已归档', deleted: '已移除', active: '可恢复', captured: '已捕获', pending: '处理中', deleting: '移除中', partially_deleted: '部分移除', failed: '执行失败', restoring: '恢复中', restored: '已恢复', partially_restored: '部分恢复', purged: '已永久删除' };
export function RecycleBinPage() {
  const { clusterId, cluster } = useCluster();
  const permission = usePermissions();
  const purgeFlow = useControlMetadataChanges();
  const workspace = useWorkspace();
  const [searchParams, setSearchParams] = useSearchParams();
  const cid = canonicalId(searchParams.get('clusterId')) ?? clusterId;
  const wid = canonicalId(searchParams.get('workspaceId')) ?? workspace.workspaceId;
  const actor = getApiActorId(), navigate = useNavigate(), approval = cid === clusterId && cluster?.execution_mode === 'approval', sameAnchor = cid === clusterId && wid === workspace.workspaceId;
  const scoped = (path: string) => scopeQuery(path, cid, wid);
  const ready = !!cid && !!wid;
  const archiveWorkspace = useQuery({ queryKey: ['archive-workspace', actor, permission.version, cid, wid], queryFn: ({ signal }) => api<Workspace>(`/clusters/${cid}/workspaces/${wid}`, { signal }), enabled: ready });
  const deletedWorkspaces = useInfiniteQuery({ queryKey: ['archive-workspace-options', actor, permission.version, clusterId, workspace.workspaceId, 'deleted'], initialPageParam: undefined as string | undefined, queryFn: ({ pageParam, signal }) => api<WorkspacePageData>(`/clusters/${clusterId}/workspaces?status=deleted&size=20${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ''}`, { signal }), getNextPageParam: page => page.nextCursor ?? undefined, enabled: ready });
  const archivedOptions = deletedWorkspaces.data?.pages.flatMap(page => page.items) ?? [];
  const blocked = !ready || cid !== clusterId || workspace.references.some(ref => ref.cid === cid && ref.wid === wid);
  const preparation = useEntityChangePreparation({ clusterId: cid, workspaceId: wid, enabled: ready && sameAnchor && approval && !workspace.writeBlocked && !workspace.readonlyWorkspace && archiveWorkspace.data?.status === 'active' });
  const restoreBlocked = blocked || archiveWorkspace.data?.status !== 'active' || approval && (!sameAnchor || !preparation.allowed || !!preparation.attempt || preparation.busy);
  const scopeIdentity = JSON.stringify([actor, permission.version, cid, wid, clusterId, workspace.workspaceId, cluster?.execution_mode, archiveWorkspace.data?.status]), liveScope = useRef(scopeIdentity), mounted = useRef(true); liveScope.current = scopeIdentity;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const assertScope = () => { if (!mounted.current || getApiActorId() !== actor || liveScope.current !== scopeIdentity) throw new ApiError('账号或归档范围已切换，请重新审阅。', 409, 'SCOPE_CHANGED'); };
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const [state, setState] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [selected, setSelected] = useState<any>();
  const [previewNode, setPreviewNode] = useState<any>();
  const [result, setResult] = useState<any>();
  const [operationError, setOperationError] = useState<unknown>();
  useEffect(() => { const id = searchParams.get('entryId'); if (id) { setSelected({ id }); setPreviewNode(undefined); } }, [searchParams, cid, wid]);
  useEffect(() => { if (!searchParams.get('entryId')) setSelected(undefined); setPreviewNode(undefined); setResult(undefined); }, [cid, wid]);
  const pages = useCursorPages(`${actor}:${permission.version}:${cid}:${wid}:${state}:${typeFilter}`);
  const params = new URLSearchParams({ size: '20' });
  if (pages.cursor) params.set('cursor', pages.cursor);
  if (state) params.set('state', state);
  if (typeFilter) params.set('type', typeFilter);
  const base = `/clusters/${cid}/recycle-bin`;
  const query = useQuery({ queryKey: ['recycle', actor, permission.version, cid, wid, params.toString()], queryFn: ({ signal }) => api<EntityPageData>(scoped(`${base}?${params}`), { signal }), enabled: ready });
  const preview = useQuery({ queryKey: ['recycle-preview', actor, permission.version, cid, wid, selected?.id], queryFn: ({ signal }) => api<any>(scoped(`${base}/${selected.id}`), { signal }), enabled: ready && !!selected });
  async function refresh() { await queryClient.invalidateQueries({ predicate: query => query.queryKey.includes(cid) }); }
  const canPurge = (entry:any) => permission.can('recycle-bin','delete',{id:entry.original_id},{clusterId:cid,workspaceId:wid,entityType:entry.root_type,potential:true});
  function execute(entry: any, action: 'restore' | 'purge') {
    const name = entry.root_name || entry.original_id;
    mutationConfirm(modal, { title: action === 'restore' ? approval ? '确认准备恢复工单' : '恢复对象图' : approval ? '确认准备永久清除工单' : '永久删除回收站记录', expected: name, description: action === 'restore' ? approval ? '只生成归档对象图的恢复预览。请在工单页审阅并提交，审批后再恢复网关对象。' : '按依赖关系恢复原 ID；存在不同配置的 ID 冲突时不会覆盖。逐对象结果将在完成后展示。' : approval ? '只准备永久清除工单。独立审批通过后才销毁该记录的恢复材料，历史事实继续保留。' : '永久删除会销毁加密恢复材料，无法通过此回收站记录恢复。保留期到期只表示可清理，仍需此确认。', danger: action === 'purge', okText: action === 'restore' ? approval ? '生成恢复预览' : '确认恢复' : approval ? '生成清除预览' : '永久删除', onConfirm: async () => {
      try {
        assertScope();
        if ((action === 'restore' ? restoreBlocked : blocked || purgeFlow.busy || !!purgeFlow.attempt) || !(action === 'purge' ? canPurge(entry) : permission.can('recycle-bin', 'write', entry, {clusterId:cid,workspaceId:wid}))) throw new ApiError('当前归档范围不可执行此操作。', 403, 'FORBIDDEN');
        if (action === 'purge' && approval) { await purgeFlow.execute({change:{resource:'recycle-bin',operation:'purge',resourceId:entry.id,input:{revision:entry.revision,workspaceId:wid,confirmed:true,confirm_name:name}},clusterId:cid??null,targetWorkspaceId:wid??null,allowed:true,subject:entry}); assertScope(); return; }
        if (action === 'restore' && approval) { const intent = await preparation.prepare({ kind: 'recycle', action: 'restore', entryId: entry.id, confirmed: true, confirm_name: name }); assertScope(); navigate(entityEntryIntentHref(intent.id)); return; }
        const result = await post(scoped(`${base}/${entry.id}/${action}`), { confirmed: true, confirm_name: name }); assertScope(); setResult(result); await refresh(); void message.success(action === 'restore' ? '恢复执行已完成，请查看逐对象结果' : '恢复材料已永久删除');
      } catch (e) { setOperationError(e); await refresh(); void message.error(errorMessage(e)); throw e; }
    } });
  }
  const nodes = preview.data?.graph?.nodes ?? [];
  const edges = preview.data?.graph?.edges ?? nodes.flatMap((node: any) => (node.dependencies ?? []).map((dependency: string) => ({ from: node.key, depends_on: dependency })));
  return <>
    <PageHeading title="回收站" extra={<><Link to="/workspaces?tab=trash"><Button>工作区回收站</Button></Link>{['users', 'teams', 'roles'].filter(type => permission.has(type)).map(type => <Link key={type} to={`/access?tab=${type}&status=deleted`}><Button>{{ users: '用户', teams: '团队', roles: '角色' }[type]}回收记录</Button></Link>)}<Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></>} />
    <Alert showIcon type="info" message="先归档，再移除" description="所有网关删除由回收站执行器处理。共享依赖保留为引用；恢复顺序依据依赖图生成，Consumer 在其插件和凭证之前恢复。" style={{ marginBottom: 24 }} />
    <Card size="small" style={{ marginBottom: 20 }}><Space wrap><span>归档范围</span><Select aria-label="回收站工作区" value={wid} style={{ minWidth: 220 }} options={[...new Map([...workspace.workspaces, ...archivedOptions, ...(archiveWorkspace.data ? [archiveWorkspace.data] : [])].map(row => [row.id, { value: row.id, label: `${row.name}${row.status === 'deleted' ? ' · 已删除' : row.status === 'disabled' ? ' · 已停用' : ''}` }])).values()]} onChange={id => { setSelected(undefined); setSearchParams({ workspaceId: id }); }} popupRender={menu => <>{menu}{deletedWorkspaces.hasNextPage && <Button block type="text" loading={deletedWorkspaces.isFetchingNextPage} onMouseDown={e => e.preventDefault()} onClick={() => void deletedWorkspaces.fetchNextPage()}>加载更多已删除工作区</Button>}</>} />{(wid !== workspace.workspaceId || cid !== clusterId) && <Button onClick={() => setSearchParams({})}>回到当前工作区</Button>}</Space><Typography.Paragraph type="secondary" className="small-note">平台管理员可以预览及销毁原工作区的归档；停用或已删除工作区必须先在工作区回收站恢复并启用，才能恢复网关对象。</Typography.Paragraph></Card>
    <ControlMetadataChanges flow={purgeFlow} />
    {!!operationError && <QueryError error={operationError} />}
    {!!preparation.error && <QueryError error={preparation.error} />}
    {approval && !sameAnchor && <Alert type="info" showIcon message="请先切换到归档对象所属工作区，再提交恢复工单" style={{ marginBottom: 20 }} />}
    {approval && preparation.attempt && <Alert type="warning" showIcon message="原准备请求需要核验，不能重新提交" description={<>原请求键：<code>{preparation.attempt.key}</code>。请在审计记录中核验原准备请求。</>} style={{ marginBottom: 20 }} />}
    {query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {!clusterId ? <NoCluster /> : <Card className="table-card"><div className="entity-filter-bar"><Select aria-label="回收站对象类型" value={typeFilter} onChange={setTypeFilter} style={{ width: 230 }} options={[{ value: '', label: '全部对象类型' }, ...Object.entries(entityLabels).map(([value, label]) => ({ value, label })), ...['targets', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'].map(value => ({ value, label: value }))]} /><Select aria-label="回收站状态" value={state} onChange={setState} style={{ width: 200 }} options={[{ value: '', label: '全部状态' }, ...Object.entries(stateLabels).map(([value, label]) => ({ value, label }))]} /></div><Table rowKey="id" pagination={false} loading={query.isFetching} dataSource={query.data?.items ?? []} scroll={{ x: 1000 }} columns={[{ title: '对象', width: 250, render: (_, entry) => <div><Button type="link" className="table-name" onClick={() => { setSelected(entry); setPreviewNode(undefined); }}>{entry.root_name || entry.original_id}</Button><div className="table-secondary">{entityLabels[entry.root_type] ?? entry.root_type}</div></div> }, { title: '状态', width: 150, render: (_, entry) => <Tag color={entry.state === 'restored' ? 'green' : /partial|fail/.test(entry.state) ? 'orange' : 'default'}>{stateLabels[entry.state] ?? entry.state}</Tag> }, { title: '归档对象数', dataIndex: 'node_count', width: 110 }, { title: '删除时间', width: 180, render: (_, entry) => formatTime(entry.created_at) }, { title: '保留至', width: 180, render: (_, entry) => formatTime(entry.expires_at) }, { title: '操作', width: 180, fixed: 'right', render: (_, entry) => <Space size={0}><Button type="link" icon={<RollbackOutlined />} size="small" disabled={restoreBlocked || !permission.can('recycle-bin', 'write', entry, { clusterId: cid, workspaceId: wid }) || ['restored', 'purged', 'restoring', 'deleting'].includes(entry.state)} onClick={() => execute(entry, 'restore')}>{approval ? '提交恢复工单' : '恢复'}</Button><Button type="link" danger size="small" icon={<DeleteOutlined />} disabled={blocked || purgeFlow.busy || !!purgeFlow.attempt || !canPurge(entry) || ['purged', 'restoring', 'deleting'].includes(entry.state)} onClick={() => execute(entry, 'purge')}>{approval ? '提交清除工单' : '永久删除'}</Button></Space> }]} /><CursorPagination pages={pages} count={query.data?.items.length ?? 0} size={20} nextCursor={query.data?.nextCursor} loading={query.isFetching} /></Card>}
    <Drawer title={`归档对象图 · ${preview.data?.entry?.root_name || selected?.root_name || selected?.original_id || ''}`} width={960} open={!!selected} onClose={() => { setSelected(undefined); setPreviewNode(undefined); setSearchParams({}); }} destroyOnClose>{preview.isError && <QueryError error={preview.error} />}<Descriptions size="small" bordered column={1} items={[{ key: 'id', label: '记录 ID', children: selected?.id }, { key: 'original', label: '原对象 ID', children: selected?.original_id }, { key: 'state', label: '状态', children: stateLabels[preview.data?.entry?.state] ?? preview.data?.entry?.state }, { key: 'dependencies', label: '依赖边', children: edges.length }]} />{preview.data?.recoveryEntryId && cid && wid && <Alert type="info" showIcon style={{ marginTop: 16 }} message="此记录属于批量回收" action={<Link to={`/recycle-bin?clusterId=${cid}&workspaceId=${wid}&entryId=${preview.data.recoveryEntryId}`}><Button size="small">查看完整回收图</Button></Link>} />}{preview.data?.entry && !preview.data?.recoveryEntryId && cid && wid && <RecycleReconciliation key={`${cid}:${wid}:${preview.data.entry.id}`} entry={preview.data.entry} clusterId={cid} workspaceId={wid} approval={cid === clusterId && cluster?.execution_mode === 'approval'} onResult={async result => { setResult(result); await refresh(); }} />}<Typography.Title level={5}>归档节点 · {nodes.length}</Typography.Title><Table size="small" loading={preview.isFetching} rowKey={(node, index) => node.key ?? node.originalId ?? node.original_id ?? String(index)} dataSource={nodes} pagination={{ pageSize: 10 }} columns={[{ title: '类型', render: (_, node) => node.type ?? node.entityType ?? node.entity_type }, { title: '原 ID', render: (_, node) => <Typography.Text className="mono">{node.id ?? node.originalId ?? node.original_id ?? node.entity?.id ?? node.payload?.id}</Typography.Text> }, { title: '归属', render: (_, node) => <Tag>{node.affected === false || node.owned === false || node.ownership === 'reference' || node.shared ? '共享引用' : '受影响对象'}</Tag> }, { title: '配置', render: (_, node) => <Button type="link" size="small" onClick={() => setPreviewNode(node)}>查看脱敏 JSON</Button> }]} />{previewNode && <pre className="json-preview">{JSON.stringify(redactForDisplay(previewNode), null, 2)}</pre>}<Typography.Title level={5}>依赖关系</Typography.Title><pre className="json-preview">{JSON.stringify(edges, null, 2)}</pre><Alert type="info" showIcon message="归档内容已脱敏" description="私钥与凭证秘密不会在对象预览中回显；完整恢复材料在后端加密保存。" /></Drawer>
    <Drawer title="恢复 / 清理执行结果" open={!!result} onClose={() => setResult(undefined)} width={760}><pre className="json-preview">{JSON.stringify(redactForDisplay(result), null, 2)}</pre></Drawer>
  </>;
}
