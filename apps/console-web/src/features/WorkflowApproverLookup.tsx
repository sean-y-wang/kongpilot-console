import { useEffect, useState } from 'react';
import { Button, Select, Space, Typography } from 'antd';
import { abbreviateId, entityOptionLabel } from '../lib/abbreviate-id';
import { useQueries, useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { QueryError } from '../components/Shared';
import { usePortalScope } from './portal-hooks';
import type { IAMPageData, IAMRow } from './iam.types';

/** Existing IAM endpoints, cursor pages and actual caller permissions only.
 * A selector is a pool definition; this lookup never claims vote eligibility. */
export function WorkflowApproverLookup({ resource, value = [], onChange, label, disabled }: {
  resource: 'users' | 'teams' | 'roles'; value?: string[]; onChange?: (ids: string[]) => void; label: string; disabled?: boolean;
}) {
  const scope = usePortalScope(), [realm, setRealm] = useState('workspace');
  const binding = JSON.stringify([scope.cid, scope.wid, scope.actor, scope.version, resource, realm]);
  const [state, setState] = useState<{ binding: string; search: string; cursor?: string; options: Array<{ value: string; label: string }> }>({ binding, search: '', options: [] });
  const current = state.binding === binding ? state : { binding, search: '', options: [] };
  const params = new URLSearchParams({ size: '20', search: current.search });
  if (resource !== 'users') params.set('status', 'active');
  if (realm !== 'global') params.set('clusterId', scope.cid ?? '');
  if (realm === 'workspace') params.set('workspaceId', scope.wid ?? '');
  if (current.cursor) params.set('cursor', current.cursor);
  const query = useQuery({ queryKey: ['workflow-approver-lookup', binding, current.search, current.cursor],
    queryFn: ({ signal }) => api<IAMPageData>(`/iam/${resource === 'users' ? 'lookups/users' : resource}?${params}`, { signal }),
    enabled: scope.ready && !disabled, retry: false, staleTime: 0, gcTime: 0 });
  useEffect(() => {
    if (!query.data) return;
    const loaded = query.data.items.map((row: IAMRow) => ({ value: row.id, label: row.display_name ? `${row.display_name} · ${row.username}` : row.username ?? row.name ?? row.code ?? '身份记录' }));
    setState(previous => ({ binding, search: current.search, cursor: current.cursor,
      options: [...new Map([...(previous.binding === binding ? previous.options : []), ...loaded].map(option => [option.value, option])).values()] }));
  }, [query.data, binding, current.search, current.cursor]);
  const missing = value.filter(id => !current.options.some(option => option.value === id)).slice(0, 100);
  // Resolve names for preselected ids (editing an existing policy) instead of showing raw ids.
  const resolved = useQueries({ queries: missing.map(id => ({ queryKey: ['workflow-approver-name', scope.actor, scope.version, resource, id],
    queryFn: ({ signal }: { signal: AbortSignal }) => api<IAMRow>(`/iam/${resource}/${encodeURIComponent(id)}`, { signal }), enabled: scope.ready, retry: false, staleTime: 60000 })) });
  const kindLabel = { users: '用户', teams: '团队', roles: '角色' }[resource];
  const options = [...current.options, ...missing.map((id, index) => { const row = resolved[index]?.data as any; const named = row?.user ?? row?.role ?? row?.team ?? row;
    const name = named?.display_name ? `${named.display_name} · ${named.username}` : named?.username ?? named?.name ?? named?.code;
    return { value: id, label: name ? entityOptionLabel(name, id) : `已选${kindLabel} · ${abbreviateId(id)}` }; })];
  return <><Space.Compact block><Select aria-label={`${label}范围`} value={realm} disabled={disabled} style={{ width: 135, flexShrink: 0 }}
    onChange={setRealm} options={[{ value: 'workspace', label: '当前工作区' }, { value: 'cluster', label: '当前集群' }, { value: 'global', label: '全局目录' }]} />
    <Select mode="multiple" aria-label={label} value={value} disabled={disabled} style={{ width: '100%' }} showSearch maxCount={100} filterOption={false}
      loading={query.isFetching} options={options} onSearch={search => setState(previous => ({ binding, search, cursor: undefined, options: previous.binding === binding ? previous.options : [] }))}
      onChange={ids => onChange?.(ids)} placeholder="按名称搜索并选择" popupRender={menu => <>{menu}{query.data?.nextCursor && <Button type="text" block
        onMouseDown={event => event.preventDefault()} onClick={() => setState({ ...current, cursor: query.data!.nextCursor! })}>加载下一页</Button>}</>} /></Space.Compact>
    {query.error && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {query.data && !query.data.items.length && <Typography.Text type="secondary">当前目录没有可读取的匹配记录</Typography.Text>}</>;
}
