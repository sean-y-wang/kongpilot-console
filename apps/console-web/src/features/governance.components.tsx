import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Form, Select, Space, Tag, Typography } from 'antd';
import type { NamePath } from 'antd/es/form/interface';
import { api, ApiError, getApiActorId } from '../api/client';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { QueryError } from '../components/Shared';
import { currentCursor, nextCursorPage, type CursorState } from './m7.cursor';
import { governanceCan, type GovernanceModule } from './governance.model';

export function GovernanceState({ state }: { state?: string | null }) {
  const labels: Record<string, string> = { complete: '完整', incomplete: '不完整', projection: '授权对象范围', changed: '范围已变化', ready: '已就绪', succeeded: '已完成', failed: '失败', running: '执行中', pending: '待处理', pending_approval: '待审批', waiting_approval: '待审批', active: '启用', paused: '暂停', paused_authority: '授权暂停', deleted: '已归档', uncertain: '待核验', partial: '部分完成' };
  return <Tag color={['complete', 'succeeded', 'ready'].includes(state ?? '') ? 'green' : ['incomplete', 'projection', 'partial', 'uncertain', 'paused_authority', 'changed'].includes(state ?? '') ? 'orange' : state === 'failed' ? 'red' : undefined}>{state ? labels[state] ?? state : '—'}</Tag>;
}
export function GovernanceSeverity({ value }: { value: string }) { return <Tag color={value === 'error' ? 'red' : value === 'warn' ? 'orange' : undefined}>{({ error: '错误', warn: '警告', info: '提示' } as Record<string, string>)[value] ?? value}</Tag>; }
export function GovernanceQuality({ complete, projection, reasons }: { complete?: boolean; projection?: boolean; reasons?: readonly string[] }) {
  if (complete === true && !projection) return null;
  return <Alert type="warning" showIcon style={{ marginBottom: 16 }} message={projection ? '报告仅覆盖当前授权对象' : '本次检查未证明完整覆盖'} description={reasons?.length ? reasons.join('、') : '请缩小范围或检查权限与连通性后重新运行。'} />;
}
export function GovernancePager({ query }: { query: { page: number; previous?: () => void; next?: () => void; isFetching: boolean } }) { return <Space className="governance-pager" style={{ marginTop: 16 }}><Button disabled={!query.previous || query.isFetching} onClick={query.previous}>上一页</Button><Typography.Text type="secondary">第 {query.page} 页</Typography.Text><Button disabled={!query.next || query.isFetching} onClick={query.next}>下一页</Button></Space>; }

/** Independent environment selectors never change the global console cluster behind a user's back. */
export function GovernanceEnvironmentFields({ prefix, module, disabled = false, label }: { prefix: string; module: GovernanceModule; disabled?: boolean; label: string }) {
  const { clusters } = useCluster(), { user } = useAuth(), form = Form.useFormInstance(), cid = canonicalId(Form.useWatch([prefix, 'clusterId'], form)), wid = canonicalId(Form.useWatch([prefix, 'workspaceId'], form)), kind = Form.useWatch([prefix, 'scope'], form) ?? 'workspace';
  return <div aria-label={label}>
    <Form.Item name={[prefix, 'clusterId']} label={`${label}集群`} rules={[{ required: true }]}><Select aria-label={`${label}集群`} disabled={disabled} options={clusters.map(cluster => ({ value: cluster.id, label: `${cluster.name} · ${cluster.environment}` }))} onChange={() => { form.setFieldValue([prefix, 'workspaceId'], undefined); form.setFieldValue([prefix, 'serviceIds'], []); }} /></Form.Item>
    <Form.Item name={[prefix, 'workspaceId']} label={`${label}工作区`} rules={[{ required: true }]}><GovernanceWorkspaceSelect clusterId={cid} module={module} disabled={disabled || !cid} label={`${label}工作区`} onScopeChange={() => form.setFieldValue([prefix, 'serviceIds'], [])} /></Form.Item>
    <Form.Item name={[prefix, 'scope']} label={`${label}范围`} rules={[{ required: true }]}><Select aria-label={`${label}范围`} disabled={disabled} onChange={() => form.setFieldValue([prefix, 'serviceIds'], [])} options={[{ value: 'workspace', label: '工作区' }, { value: 'services', label: '指定 Services' }]} /></Form.Item>
    {kind === 'services' && <Form.Item name={[prefix, 'serviceIds']} label={`${label}Services`} rules={[{ required: true, type: 'array', min: 1, max: 100 }]}><GovernanceServiceSelect clusterId={cid} workspaceId={wid} disabled={disabled || !cid || !wid || !governanceCan(user?.capabilities, module, 'read', { clusterId: cid, workspaceId: wid })} label={`${label}Services`} /></Form.Item>}
  </div>;
}

function useSelectorFence() {
  const { user } = useAuth(), current = useRef({ actor: user?.id, version: user?.permissionsVersion }), mounted = useRef(true); current.current = { actor: user?.id, version: user?.permissionsVersion };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  return { actor: user?.id, version: user?.permissionsVersion, assert: (actor?: string, version?: string) => { if (!mounted.current || getApiActorId() !== actor || current.current.actor !== actor || current.current.version !== version) throw new ApiError('账号或权限已变化。', 409, 'SCOPE_CHANGED'); } };
}
function GovernanceWorkspaceSelect({ clusterId, module, disabled, value, onChange, label, onScopeChange }: { clusterId?: string; module: GovernanceModule; disabled: boolean; value?: string; onChange?: (value: string) => void; label: string; onScopeChange: () => void }) {
  const fence = useSelectorFence(), { user } = useAuth(), currentCid = useRef(clusterId); currentCid.current = clusterId;
  const key = JSON.stringify([fence.actor, fence.version, clusterId, module]), [stored, setStored] = useState<CursorState>({ key, cursors: [undefined], page: 0 }), state = currentCursor(stored, key), cursor = state.cursors[state.page];
  const query = useQuery({ queryKey: ['m10', 'workspace-options', key, cursor], queryFn: async ({ signal }) => { const captured = { actor: fence.actor, version: fence.version, cid: clusterId }; const page = await api<{ items: Array<{ id: string; name: string; status: string }>; nextCursor: string | null }>(`/clusters/${captured.cid}/workspaces?size=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal }); fence.assert(captured.actor, captured.version); if (currentCid.current !== captured.cid) throw new ApiError('环境范围已变化。', 409, 'SCOPE_CHANGED'); return page; }, enabled: !!clusterId && !!fence.actor && !!fence.version, retry: false, gcTime: 0, staleTime: 0 });
  const options = (query.data?.items ?? []).filter(row => row.status === 'active' && governanceCan(user?.capabilities, module, 'read', { clusterId, workspaceId: row.id })).map(row => ({ value: row.id, label: row.name }));
  if (value && !options.some(option => option.value === value)) options.unshift({ value, label: value });
  return <Select aria-label={label} disabled={disabled} value={value} onChange={id => { onScopeChange(); onChange?.(id); }} options={options} loading={query.isFetching} popupRender={menu => <>{menu}<div style={{ padding: 12 }}><GovernancePager query={{ page: state.page + 1, previous: state.page ? () => setStored({ ...state, page: state.page - 1 }) : undefined, next: query.data?.nextCursor ? () => setStored(nextCursorPage(state, query.data!.nextCursor!)) : undefined, isFetching: query.isFetching }} />{query.error && <QueryError error={query.error} />}</div></>} />;
}
export function GovernanceServiceSelect({ clusterId, workspaceId, disabled, value, onChange, label }: { clusterId?: string; workspaceId?: string; disabled: boolean; value?: string[]; onChange?: (value: string[]) => void; label: string }) {
  const fence = useSelectorFence(), current = useRef({ clusterId, workspaceId }); current.current = { clusterId, workspaceId };
  const [search, setSearch] = useState(''), key = JSON.stringify([fence.actor, fence.version, clusterId, workspaceId, search]), [stored, setStored] = useState<CursorState>({ key, cursors: [undefined], page: 0 }), state = currentCursor(stored, key), cursor = state.cursors[state.page];
  const query = useQuery({ queryKey: ['m10', 'service-options', key, cursor], queryFn: async ({ signal }) => { const captured = { actor: fence.actor, version: fence.version, cid: clusterId, wid: workspaceId }; const params = new URLSearchParams({ size: '20', ...(search ? { search } : {}), ...(cursor ? { cursor } : {}) }); const page = await api<{ items: Array<{ id: string; name?: string }>; nextCursor: string | null }>(scopeQuery(`/clusters/${captured.cid}/entities/services?${params}`, captured.cid, captured.wid), { signal }); fence.assert(captured.actor, captured.version); if (current.current.clusterId !== captured.cid || current.current.workspaceId !== captured.wid) throw new ApiError('环境范围已变化。', 409, 'SCOPE_CHANGED'); return page; }, enabled: !disabled && !!clusterId && !!workspaceId && !!fence.actor && !!fence.version, retry: false, gcTime: 0, staleTime: 0 });
  const options = (query.data?.items ?? []).map(row => ({ value: row.id, label: row.name ?? row.id })); for (const id of value ?? []) if (!options.some(option => option.value === id)) options.unshift({ value: id, label: id });
  return <Select aria-label={label} mode="multiple" disabled={disabled} showSearch filterOption={false} value={value} onChange={onChange} onSearch={setSearch} options={options} loading={query.isFetching} popupRender={menu => <>{menu}<div style={{ padding: 12 }}><GovernancePager query={{ page: state.page + 1, previous: state.page ? () => setStored({ ...state, page: state.page - 1 }) : undefined, next: query.data?.nextCursor ? () => setStored(nextCursorPage(state, query.data!.nextCursor!)) : undefined, isFetching: query.isFetching }} />{query.error && <QueryError error={query.error} />}</div></>} />;
}

export const governanceName = (prefix: string, field: string): NamePath => [prefix, field];
