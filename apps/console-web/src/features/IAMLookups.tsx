import { useEffect, useState } from 'react';
import { Button, Select } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { scopeQuery } from '../api/workspace-scope';
import { usePermissions } from '../app/Permissions';
import { useAuth } from '../app/AuthContext';
import { VitalsEntitySelect } from '../components/VitalsEntitySelect';
import { QueryError } from '../components/Shared';
import type { IAMPageData, IAMRow } from './iam.types';
import { entityName } from './entities';

type Option = { value: string; label: string; row?: IAMRow };
export function MonitoringEntityLookup({ type, clusterId, workspaceId, value, onChange, label }: { type: string; clusterId?: string; workspaceId?: string; value?: string; onChange?: (id?: string) => void; label: string }) {
  const { user } = useAuth();
  const supported = ['services', 'routes', 'consumers'].includes(type);
  return <VitalsEntitySelect scope={{ actorId: user?.id ?? '', permissionVersion: user?.permissionsVersion ?? '', clusterId: clusterId ?? '', workspaceId: workspaceId ?? '', metricsScope: 'workspace' }} type={supported ? type as 'services' | 'routes' | 'consumers' : 'services'} value={value} onChange={onChange} label={label} disabled={!supported || !clusterId || !workspaceId} allowClear />;
}
function useScopedOptions(scope: string) {
  const [state, setState] = useState<{ scope: string; search: string; cursor?: string; options: Option[] }>({ scope, search: '', options: [] });
  const active = state.scope === scope ? state : { scope, search: '', cursor: undefined, options: [] };
  const onSearch = (search: string) => setState({ scope, search, cursor: undefined, options: [] });
  const next = (cursor: string) => setState({ ...active, cursor });
  const receive = (items: Option[]) => setState(previous => ({ ...active, options: [...new Map([...(active.cursor && previous.scope === scope && previous.search === active.search ? previous.options : []), ...items].map(item => [item.value, item])).values()] }));
  return { ...active, onSearch, next, receive };
}

export function PagedIAMLookup({ resource = 'users', value, onChange, onSelected, label, clusterId, workspaceId }: { resource?: 'users' | 'roles'; value?: string; onChange?: (value?: string) => void; onSelected?: (row?: IAMRow) => void; label: string; clusterId?: string; workspaceId?: string }) {
  const { version } = usePermissions();
  const scope = JSON.stringify([resource, clusterId, workspaceId, version]);
  const { search, cursor, options, onSearch, next, receive } = useScopedOptions(scope);
  const params = new URLSearchParams({ size: '20', search });
  if (clusterId) params.set('clusterId', clusterId); if (workspaceId) params.set('workspaceId', workspaceId); if (cursor) params.set('cursor', cursor);
  const query = useQuery({ queryKey: ['iam-lookup', resource, clusterId, workspaceId, version, search, cursor], queryFn: () => api<IAMPageData>(`/iam/${resource === 'users' ? 'lookups/users' : 'roles'}?${params}`) });
  useEffect(() => { if (query.data) receive(query.data.items.map(row => ({ value: row.id, label: row.username ?? row.name ?? row.id, row }))); }, [query.data, scope, search, cursor]);
  return <><Select key={scope} aria-label={label} value={value} showSearch allowClear filterOption={false} loading={query.isFetching} options={options} onSearch={onSearch} onChange={id => { onChange?.(id); onSelected?.(options.find(option => option.value === id)?.row); }} placeholder="按名称搜索并从授权结果中选择" popupRender={menu => <>{menu}{query.data?.nextCursor && <Button block type="text" onMouseDown={event => event.preventDefault()} onClick={() => next(query.data!.nextCursor!)}>加载下一页</Button>}</>} />{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}</>;
}
export function ScopedEntityLookup({ type, clusterId, workspaceId, parentId, value, onChange, onSelected, label }: { type: string; clusterId?: string; workspaceId?: string; parentId?: string; value?: string; onChange?: (value?: string) => void; onSelected?: (entity?: Record<string, any>) => void; label: string }) {
  const { version } = usePermissions(), { user } = useAuth();
  const nested = ['targets', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'].includes(type);
  const scope = JSON.stringify([user?.id, clusterId, workspaceId, type, parentId, version]);
  const { search, cursor, options, onSearch, next, receive } = useScopedOptions(scope);
  const params = new URLSearchParams({ size: '20' }); if (!nested && search) params.set('search', search); if (cursor) params.set('cursor', cursor);
  const resource = nested ? type === 'targets' ? `upstreams/${parentId}/targets` : `consumers/${parentId}/credentials/${type}` : `entities/${type}`;
  const query = useQuery({ queryKey: ['iam-entity-lookup', user?.id, clusterId, workspaceId, type, parentId, version, search, cursor], queryFn: () => api<IAMPageData<any>>(scopeQuery(`/clusters/${clusterId}/${resource}?${params}`, clusterId, workspaceId)), enabled: !!clusterId && !!workspaceId && !!type && (!nested || !!parentId) });
  useEffect(() => { if (query.data) receive(query.data.items.map(entity => ({ value: entity.id, label: `${entityName(entity)} · ${entity.id.slice(0, 8)}`, row: entity }))); }, [query.data, scope, search, cursor]);
  return <><Select key={scope} aria-label={label} value={value} showSearch allowClear filterOption={nested ? true : false} optionFilterProp="label" loading={query.isFetching} disabled={!clusterId || !workspaceId || nested && !parentId} options={options} onSearch={nested ? undefined : onSearch} onChange={id => { onChange?.(id); onSelected?.(options.find(option => option.value === id)?.row); }} placeholder={nested ? '在当前已加载分页内选择；可加载下一页' : '按名称搜索授权实体'} popupRender={menu => <>{menu}{query.data?.nextCursor && <Button block type="text" onMouseDown={event => event.preventDefault()} onClick={() => next(query.data!.nextCursor!)}>加载下一页</Button>}</>} />{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}</>;
}
export function IAMWorkspaceLookup({ clusterId, value, onChange, multiple = false, label }: { clusterId?: string; value?: string | string[]; onChange?: (value: any) => void; multiple?: boolean; label: string }) {
  const { version } = usePermissions();
  const scope = JSON.stringify([clusterId, version]);
  const { cursor, options, next, receive } = useScopedOptions(scope);
  const query = useQuery({ queryKey: ['iam-workspace-lookup', clusterId, version, cursor], queryFn: () => api<IAMPageData>(`/clusters/${clusterId}/workspaces?size=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`), enabled: !!clusterId });
  useEffect(() => { if (query.data) receive(query.data.items.map(row => ({ value: row.id, label: row.name ?? row.id }))); }, [query.data, scope, cursor]);
  return <><Select key={scope} aria-label={label} mode={multiple ? 'multiple' : undefined} allowClear value={value} options={options} disabled={!clusterId} loading={query.isFetching} onChange={onChange} placeholder="选择工作区" popupRender={menu => <>{menu}{query.data?.nextCursor && <Button block type="text" onMouseDown={event => event.preventDefault()} onClick={() => next(query.data!.nextCursor!)}>加载更多工作区</Button>}</>} />{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}</>;
}

export function PortalEntityLookup({ type, module, purpose = 'permission', disabled, clusterId, workspaceId, value, onChange, label }: { type: string; module: 'portal' | 'workflows'; purpose?: 'permission' | 'publication'; disabled?: boolean; clusterId?: string; workspaceId?: string; value?: string; onChange?: (id?: string) => void; label: string }) {
  const { user } = useAuth(), { version } = usePermissions(), supported = ['services', 'routes'].includes(type);
  const scope = JSON.stringify([user?.id, clusterId, workspaceId, module, type, purpose, version]), { search, cursor, options, onSearch, next, receive } = useScopedOptions(scope);
  const params = new URLSearchParams({ size: '20', search }); if (cursor) params.set('cursor', cursor); if (purpose !== 'publication') { params.set('type', type); params.set('module', module); }
  const resource = purpose === 'publication' ? 'service-identities' : 'entity-identities';
  const query = useQuery({ queryKey: ['portal-identity-lookup', user?.id, version, clusterId, workspaceId, module, type, purpose, search, cursor], queryFn: ({ signal }) => api<IAMPageData<any>>(scopeQuery(`/clusters/${clusterId}/portal/${resource}?${params}`, clusterId, workspaceId), { signal }), enabled: !!clusterId && !!workspaceId && supported, retry: false, gcTime: 0 });
  useEffect(() => { if (query.data) receive(query.data.items.map(row => ({ value: row.id, label: `${row.name ?? row.id} · ${row.id.slice(0, 8)}` }))); }, [query.data, scope, search, cursor]);
  return <><Select key={scope} value={value} aria-label={label} showSearch allowClear filterOption={false} disabled={disabled || !clusterId || !workspaceId || !supported} loading={query.isFetching} options={options} onSearch={onSearch} onChange={onChange} placeholder="搜索有权管理的最小实体身份" popupRender={menu => <>{menu}{query.data?.nextCursor && <Button block type="text" onMouseDown={event => event.preventDefault()} onClick={() => next(query.data!.nextCursor!)}>加载下一页</Button>}</>} />{query.error && <QueryError error={query.error} retry={() => void query.refetch()} />}</>;
}
