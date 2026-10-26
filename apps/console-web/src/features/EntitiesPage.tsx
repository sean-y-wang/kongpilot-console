import { useEffect, useRef, useState } from 'react';
import { EntityRef, useEntityReferences } from '../components/EntityReference';
import { Alert, App, Button, Card, Input, Select, Space, Table, Tag, Typography } from 'antd';
import { PilotIcon } from '../../../../packages/contracts/src/PilotIcon';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { scopeQuery } from '../api/workspace-scope';
import { api, ApiError, errorMessage, getApiActorId } from '../api/client';
import { NoCluster, PageHeading, QueryError, formatTime } from '../components/Shared';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { entityDisplayName, entityLabels, entityName, entityTime, isEntityType, type EntityPageData } from './entities';
import { EntityIdText } from '../components/EntityReference';
import { EntityEditor, useEntityChangePreparation } from './EntityEditor';
import { entityEntryIntentHref } from './entity-entry-change.model';
import { EntityDetails } from './EntityDetails';
import { usePermissions } from '../app/Permissions';
import { useEntityPermissions } from '../app/EntityPermissions';

export function EntitiesPage() {
  const { entityType: type = 'services', entityId } = useParams();
  const { clusterId, cluster } = useCluster();
  const permission = usePermissions();
  const { workspaceId, workspace, ready, writeBlocked, readonlyWorkspace } = useWorkspace();
  const actor = getApiActorId(), approval = cluster?.execution_mode === 'approval';
  const preparation = useEntityChangePreparation({ clusterId, workspaceId, enabled: ready && workspace?.status === 'active' && !writeBlocked && !readonlyWorkspace && approval });
  const scopeIdentity=JSON.stringify([actor,clusterId,workspaceId,type,permission.version,cluster?.execution_mode]),liveScope=useRef(scopeIdentity),mounted=useRef(true);liveScope.current=scopeIdentity;
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
  const assertScope=()=>{if(!mounted.current||getApiActorId()!==actor||liveScope.current!==scopeIdentity||!ready)throw new ApiError('账号或操作范围已切换，请重新审阅当前对象。',409,'SCOPE_CHANGED');};
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { modal, message } = App.useApp();
  const [search, setSearch] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [sort, setSort] = useState('');
  const [size, setSize] = useState(20);
  const [editor, setEditor] = useState<{ entity?: any } | undefined>();
  const [selected, setSelected] = useState<React.Key[]>([]);
  const [propagation, setPropagation] = useState(false);
  const [operationError, setOperationError] = useState<unknown>();
  const pages = useCursorPages(JSON.stringify([actor, clusterId, workspaceId, permission.version, type, search, tags, sort, size]));
  useEffect(() => { setSelected([]); setEditor(undefined); setSearch(''); setTags([]); setSort(''); setOperationError(undefined); }, [actor, clusterId, workspaceId, permission.version, type]);
  const params = new URLSearchParams({ size: String(size) });
  if (pages.cursor) params.set('cursor', pages.cursor);
  if (search) params.set('search', search);
  if (tags.length) params.set('tags', tags.join(','));
  if (sort) params.set('sort', sort);
  const query = useQuery({ queryKey: ['entities', actor, clusterId, workspaceId, permission.version, type, params.toString()], queryFn: ({ signal }) => api<EntityPageData>(scopeQuery(`/clusters/${clusterId}/entities/${type}?${params}`, clusterId, workspaceId), { signal }), enabled: ready && isEntityType(type) && permission.has(type) });
  const items = query.data?.items ?? [];
  const abilityReferences = [...new Map([...items.map(item => ({ type, id: item.id })), ...(entityId ? [{ type, id: entityId }] : [])].map(item => [`${item.type}:${item.id}`, item])).values()];
  const abilities = useEntityPermissions(abilityReferences);
  async function refreshAll() { await queryClient.invalidateQueries({ predicate: query => query.queryKey.includes(clusterId) }); }
  function deleteEntity(entity: any) {
    mutationConfirm(modal, { title: approval ? '确认准备删除工单' : '移入回收站', expected: entityName(entity), description: approval ? '先生成删除影响与回收图预览，再到工单页提交并审批。此步骤不会删除网关对象。' : '后端会先完整归档对象及受影响依赖，再将配置从网关移除。共享引用不会随所属对象误删。', onConfirm: async () => {
      try {
        assertScope();
        if (writeBlocked || readonlyWorkspace || !abilities.can(type, entity?.id, 'delete')) throw new ApiError('当前对象不可删除。',403,'FORBIDDEN');
        if (approval) { const intent = await preparation.prepare({ kind: 'recycle', action: 'delete', entityType: type, entityId: entity.id, confirmed: true, confirm_name: entityName(entity) }); assertScope(); navigate(entityEntryIntentHref(intent.id)); return; }
        await api(scopeQuery(`/clusters/${clusterId}/entities/${type}/${entity.id}`, clusterId, workspaceId), { method: 'DELETE', body: JSON.stringify({ confirmed: true, confirm_name: entityName(entity) }) }); assertScope(); await refreshAll(); setPropagation(true); if (entityId === entity.id) navigate(`/entities/${type}`); void message.success('对象已移入回收站');
      } catch (e) { setOperationError(e); void message.error(errorMessage(e)); throw e; }
    } });
  }
  function batchDelete() {
    const affected = items.filter(item => selected.includes(item.id));
    mutationConfirm(modal, { title: `预览 ${affected.length} 个对象的删除`, expected: 'DELETE', description: '先生成完整依赖与配置差异；在变更计划中确认后执行或提交审批。', onConfirm: async () => {
      assertScope();
      try{const result=await api<any>(scopeQuery(`/clusters/${clusterId}/batches/plan`,clusterId,workspaceId),{method:'POST',body:JSON.stringify({action:'delete',roots:affected.map(entity=>({type,id:entity.id}))})});assertScope();
        const planId=result.planId??result.safeProgress?.planId;if(planId)navigate(`/configuration/plans/${planId}`);else if(result.id)navigate(`/configuration/jobs/${result.id}`);else throw new ApiError('删除计划未生成，请检查对象与恢复材料。',409,'BATCH_PLAN_UNAVAILABLE');
      }catch(error){setOperationError(error);throw error;}
    } });
  }
  const refs = useEntityReferences(items.flatMap((entity: any) => [
    ...(type === 'plugins' ? (['service', 'route', 'consumer'] as const).map(key => ({ type: `${key}s`, id: entity[key]?.id })) : []),
    ...(type === 'routes' ? [{ type: 'services', id: entity.service?.id }] : []),
    ...(type === 'snis' ? [{ type: 'certificates', id: entity.certificate?.id }] : []),
    ...(type === 'services' ? [{ type: 'certificates', id: entity.client_certificate?.id }] : []),
  ]));
  const columns: any[] = [{ title: '名称 / ID', width: 245, render: (_: any, entity: any) => {
    const display = entityDisplayName(entity);
    return <div><Button type="link" className="table-name" onClick={() => navigate(`/entities/${type}/${entity.id}`)}>{display || <span className="table-name-empty"> </span>}</Button><div className="table-secondary"><EntityIdText id={entity.id} /></div></div>;
  } }];
  if (type === 'services') columns.push({ title: '连接', width: 250, render: (_: any, entity: any) => <span className="mono">{entity.protocol}://{entity.host}:{entity.port}{entity.path ?? ''}</span> });
  if (type === 'routes') columns.push({ title: '匹配规则', width: 290, render: (_: any, entity: any) => <div><Space wrap size={2}>{[...(entity.hosts ?? []), ...(entity.paths ?? [])].map((value: string) => <Tag key={value}>{value}</Tag>)}</Space><div className="table-secondary">{(entity.protocols ?? []).join(' / ')} · {(entity.methods ?? []).join(', ') || '全部方法'}</div></div> });
  if (type === 'routes') columns.push({ title: 'Service', width: 220, render: (_: any, entity: any) => <EntityRef type="services" id={entity.service?.id} refs={refs} /> });
  if (type === 'consumers') columns.push({ title: '业务标识', dataIndex: 'custom_id', width: 200, render: (value: string) => value ?? '—' });
  if (type === 'plugins') columns.push({ title: '范围 / 状态', width: 240, render: (_: any, entity: any) => <Space wrap><Tag color={entity.enabled ? 'green' : 'default'}>{entity.enabled ? '启用' : '停用'}</Tag>{(['service', 'route', 'consumer'] as const).filter(key => entity[key]?.id).map(key => <span key={key} className="entity-ref-scope"><Tag>{key}</Tag><EntityRef type={`${key}s`} id={entity[key].id} refs={refs} compact /></span>)}{!entity.service && !entity.route && !entity.consumer && <Tag color="purple">全局</Tag>}</Space> });
  if (type === 'upstreams') columns.push({ title: '算法', dataIndex: 'algorithm', width: 190 });
  if (type === 'snis') columns.push({ title: '证书', width: 240, render: (_: any, entity: any) => (entity.certificate?.id ? <EntityRef type="certificates" id={entity.certificate.id} refs={refs} /> : <Typography.Text type="secondary">无证书引用</Typography.Text>) });
  columns.push({ title: '标签', width: 190, render: (_: any, entity: any) => <Space className="entity-tags" wrap size={2}>{entity.tags?.length ? entity.tags.map((tag: string) => <Tag key={tag}>{tag}</Tag>) : <Typography.Text type="secondary">—</Typography.Text>}</Space> }, { title: '创建时间', width: 185, render: (_: any, entity: any) => <Typography.Text type="secondary">{entityTime(entity.created_at)}</Typography.Text> }, { title: '操作', width: approval ? 200 : 140, fixed: 'right', render: (_: any, entity: any) => <Space size={0}><Button type="link" size="small" icon={<PilotIcon name="edit" />} disabled={!ready || writeBlocked || readonlyWorkspace || !abilities.can(type, entity?.id, 'write') || approval && (!preparation.allowed || !!preparation.attempt || preparation.busy)} onClick={() => setEditor({ entity })}>编辑</Button><Button danger type="link" size="small" onClick={() => deleteEntity(entity)} disabled={!ready || writeBlocked || readonlyWorkspace || !abilities.can(type, entity?.id, 'delete') || approval && (!preparation.allowed || !!preparation.attempt || preparation.busy)}>{approval ? '提交删除工单' : '删除'}</Button></Space> });
  if (!isEntityType(type)) return <Alert type="error" message="不支持的实体类型" />;
  return <>
    <PageHeading title={entityLabels[type]}  extra={<Button type="primary" icon={<PilotIcon name="plus" />} disabled={!ready || writeBlocked || readonlyWorkspace || !(permission.create(type) || ['plugins', 'routes'].includes(type) && permission.has(type, 'write')) || approval && (!preparation.allowed || !!preparation.attempt || preparation.busy)} onClick={() => setEditor({})}>{approval ? '提交创建工单' : `创建 ${entityLabels[type]}`}</Button>} />
    {propagation && <Alert type="info" showIcon closable onClose={() => setPropagation(false)} message="配置生效中" description="变更已提交；DB 模式下各 Kong 节点可能需要数秒同步，请刷新核验。" style={{ marginBottom: 20 }} />}
    {!!operationError && <QueryError error={operationError} />}
    {!!preparation.error && <QueryError error={preparation.error} />}
    {approval && preparation.attempt && <Alert type="warning" showIcon message="原准备请求需要核验，不能重新提交" description={<>原请求键：<code>{preparation.attempt.key}</code>。请在审计记录中核验原准备请求。</>} style={{ marginBottom: 20 }} />}
    {abilities.query.isError && <QueryError error={abilities.query.error} retry={() => void abilities.query.refetch()} />}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {!clusterId ? <NoCluster /> : <Card className="table-card"><div className="entity-filter-bar"><Input.Search key={`${clusterId}:${workspaceId}:${type}`} aria-label="搜索实体" allowClear enterButton={<Button aria-label="执行实体搜索" icon={<PilotIcon name="search" />} />} placeholder={entitySearchPlaceholder(type)} title={entitySearchPlaceholder(type)} onSearch={value => setSearch(value.trim())} style={{ width: 320 }} /><Select aria-label="按标签过滤" mode="tags" tokenSeparators={[',']} value={tags} onChange={setTags} placeholder="按标签过滤" style={{ width: 240 }} /><Select aria-label="排序" value={sort} onChange={setSort} style={{ width: 190 }} options={[{ value: '', label: '默认排序' }, { value: 'name:asc', label: '名称 A → Z' }, { value: 'name:desc', label: '名称 Z → A' }, { value: 'created_at:desc', label: '创建时间 · 最新优先' }, { value: 'created_at:asc', label: '创建时间 · 最早优先' }]} /><Button icon={<PilotIcon name="reload" />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button>{selected.length > 0 && <Button danger disabled={!ready || writeBlocked || readonlyWorkspace || selected.length > 50 || !permission.has('batches','write') || !permission.has('snapshots','write') || !permission.has('snapshots','read') || items.some(item => selected.includes(item.id) && !abilities.can(type, item.id, 'delete'))} icon={<PilotIcon name="trash" />} onClick={batchDelete}>删除 {selected.length} 项</Button>}</div>{query.data?.indexed && <div className="index-status">最近更新 {formatTime(query.data.observed_at)}{query.data.sync_error && <span> · 更新异常：{query.data.sync_error}</span>}</div>}<Table rowKey="id" loading={query.isFetching} dataSource={items} columns={columns} scroll={{ x: 1080 }} pagination={false} rowSelection={{ selectedRowKeys: selected, onChange: setSelected, getCheckboxProps: entity => ({ disabled: !abilities.can(type, entity?.id, 'delete') }) }} /><CursorPagination pages={pages} nextCursor={query.data?.nextCursor} loading={query.isFetching} count={items.length} size={size} onSizeChange={setSize} /></Card>}
    {editor && <EntityEditor key={`${actor}:${clusterId}:${workspaceId}:${permission.version}:${type}:${editor.entity?.id ?? 'new'}`} type={type} open entity={editor.entity} onClose={() => setEditor(undefined)} onSaved={() => setPropagation(true)} />}
    <EntityDetails type={type} id={entityId} onClose={() => navigate(`/entities/${type}`)} onEdit={entity => setEditor({ entity })} onDelete={deleteEntity} />
  </>;
}

/** Lists the dimensions the server-side fuzzy search matches (see console-api entity-search.ts). */
export function entitySearchPlaceholder(type: string): string {
  if (type === 'services') return '搜索名称 / ID / 端口 / 上游主机';
  if (type === 'routes') return '搜索 Host / Path / 名称 / ID';
  return '搜索名称或 ID';
}
