import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Descriptions, Drawer, Space, Spin, Table, Tabs, Tag } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, ApiError, getApiActorId } from '../api/client';
import { QueryError } from '../components/Shared';
import { usePortalPage, usePortalScope } from './portal-hooks';
import type { PortalApplicationDetail, PortalApplicationGrant, PortalApplicationRequest, PortalDeveloperDetail } from './portal.types';
import { portalStateLabels } from './portal.types';
import { PortalPager } from './WorkflowsPage';

type DetailScope = Pick<ReturnType<typeof usePortalScope>, 'cid' | 'wid' | 'actor' | 'version'>;
export interface PortalDetailSelection { kind: 'developer' | 'application'; id: string; label: string; scopeKey: string; }
export function portalDetailScopeKey(scope: DetailScope) { return JSON.stringify([scope.cid, scope.wid, scope.actor, scope.version]); }
export function portalDetailQueryKey(scope: DetailScope, selection: PortalDetailSelection) { return ['portal-admin-detail', scope.cid, scope.wid, scope.actor, scope.version, selection.kind, selection.id] as const; }
export function validatePortalAdminDetail(value: PortalDeveloperDetail | PortalApplicationDetail, selection: PortalDetailSelection, scope: DetailScope) {
  const entity = value?.entity;
  if (!entity || entity.id !== selection.id || entity.clusterId !== scope.cid || entity.workspaceId !== scope.wid) throw new ApiError('详情范围已变化，请重新打开当前对象。', 409, 'PORTAL_DETAIL_SCOPE_CHANGED');
  return value;
}

const stateTag = (state: string) => <Tag>{portalStateLabels[state] ?? state}</Tag>;
const time = (value: string) => new Date(value).toLocaleString('zh-CN', { hour12: false });

/** An old selection cannot start requests against a newly selected tenant or account. */
export function PortalAdminDetails({ selection, onClose }: { selection: PortalDetailSelection; onClose: () => void }) {
  const scope = usePortalScope(), key = portalDetailScopeKey(scope), current = key === selection.scopeKey;
  useEffect(() => { if (!current) onClose(); }, [current, onClose]);
  return current ? <PortalDetailPanel key={`${key}:${selection.kind}:${selection.id}`} selection={selection} onClose={onClose} /> : null;
}

export function PortalDetailPanel({ selection, onClose }: { selection: PortalDetailSelection; onClose: () => void }) {
  const scope = usePortalScope(), key = portalDetailScopeKey(scope), context = useRef(key), alive = useRef(true), [tab, setTab] = useState('configuration');
  context.current = key;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const module = selection.kind === 'developer' ? 'developers' : 'applications';
  const resource = selection.kind === 'developer' ? 'developers' : 'applications';
  const canRead = scope.permission.can(module, 'read');
  const query = useQuery({
    queryKey: portalDetailQueryKey(scope, selection),
    enabled: scope.ready && canRead && selection.scopeKey === key,
    retry: false, staleTime: 0, gcTime: 0,
    queryFn: async ({ signal }) => {
      const response = await api<PortalDeveloperDetail | PortalApplicationDetail>(scope.path(`portal/${resource}/${selection.id}`), { signal });
      if (signal.aborted || !alive.current || context.current !== key || getApiActorId() !== scope.actor) throw new ApiError('账号或工作区已切换，请重新打开详情。', 409, 'SESSION_CHANGED');
      return validatePortalAdminDetail(response, selection, scope);
    },
  });
  const entity = query.data?.entity;
  const application = selection.kind === 'application' ? query.data as PortalApplicationDetail | undefined : undefined;
  return <Drawer open title={`${selection.kind === 'developer' ? '开发者详情' : '应用详情'} · ${selection.label}`} width={920} onClose={onClose} destroyOnClose data-testid={`portal-admin-${selection.kind}-detail`} extra={<Button disabled={!canRead} loading={query.isFetching} onClick={() => void query.refetch()}>刷新详情</Button>}>
    {!canRead ? <Alert type="info" message="当前工作区未授予此详情的读取权限" /> : <>
      {query.error && <QueryError error={query.error} />}
      {!entity && query.isFetching && <Spin aria-label="加载门户详情" />}
      {entity && <Tabs activeKey={tab} onChange={setTab} destroyOnHidden items={[
        { key: 'configuration', label: 'Configuration / 配置', children: selection.kind === 'developer' ? <DeveloperConfiguration detail={query.data as PortalDeveloperDetail} /> : <ApplicationConfiguration detail={application!} /> },
        ...(application ? [
          { key: 'grants', label: '授权记录', children: application.entity.capabilities?.readGrants === true ? tab === 'grants' && <ApplicationGrants applicationId={selection.id} /> : <Alert type="info" message="授权记录未授权" description="需要当前整个工作区的应用及门户读取权限；应用配置仍可独立查看。" /> },
          { key: 'requests', label: '申请 / 工作流', children: application.entity.capabilities?.readRequests === true ? tab === 'requests' && <ApplicationRequests applicationId={selection.id} /> : <Alert type="info" message="申请记录未授权" description="需要当前整个工作区的应用及工作流读取权限。" /> },
        ] : []),
      ]} />}
    </>}
  </Drawer>;
}

function DeveloperConfiguration({ detail }: { detail: PortalDeveloperDetail }) {
  const row = detail.entity;
  return <Descriptions bordered column={1} size="small" items={[
    { key: 'username', label: '开发者账号', children: row.username }, { key: 'displayName', label: '显示名称', children: row.displayName },
    { key: 'email', label: '邮箱', children: row.email }, { key: 'status', label: '状态', children: stateTag(row.status) },
    { key: 'passwordChange', label: '下次登录修改密码', children: row.mustChangePassword ? '需要' : '无需' },
    { key: 'createdAt', label: '注册时间', children: time(row.createdAt) }, { key: 'revision', label: '资料版本', children: row.revision },
    { key: 'id', label: '开发者 ID', children: <code>{row.id}</code> },
  ]} />;
}

function ApplicationConfiguration({ detail }: { detail: PortalApplicationDetail }) {
  const row = detail.entity;
  return <><Alert type="info" showIcon message="这里只显示应用与授权元数据" description="停用或归档不代表凭证已吊销。旧凭证失效后需重新申请新访问；详情不会读取或显示密钥。" style={{ marginBottom: 16 }} /><Descriptions bordered column={1} size="small" items={[
    { key: 'name', label: '应用名称', children: row.name }, { key: 'description', label: '说明', children: row.description || '—' },
    { key: 'state', label: '状态', children: stateTag(row.state) }, { key: 'createdAt', label: '创建时间', children: time(row.createdAt) },
    { key: 'revision', label: '资料版本', children: row.revision }, { key: 'developerId', label: '所属开发者 ID', children: <code>{row.developerId}</code> },
    { key: 'id', label: '应用 ID', children: <code>{row.id}</code> },
  ]} /></>;
}

export function ApplicationGrants({ applicationId }: { applicationId: string }) {
  const query = usePortalPage<PortalApplicationGrant>(`portal/applications/${applicationId}/grants`);
  return <><Alert type="info" showIcon message="保留历史授权状态，不显示凭证" description="预留已释放表示从未发放的申请已关闭；它不代表凭证发放成功，也不恢复旧 Key。" style={{ marginBottom: 16 }} />{query.error && <QueryError error={query.error} />}<Table<PortalApplicationGrant> rowKey="id" loading={query.isFetching} dataSource={query.data?.items ?? []} pagination={false} scroll={{ x: 760 }} columns={[
    { title: '发布 API', dataIndex: 'publicationName' }, { title: '授权状态', render: (_, row) => stateTag(row.state) },
    { title: '凭证代次', dataIndex: 'generation' }, { title: '预留已释放', render: (_, row) => row.reservationReleased ? '是' : '否' },
    { title: '创建时间', render: (_, row) => time(row.createdAt) }, { title: '授权记录 ID', render: (_, row) => <code>{row.id}</code> },
  ]} /><PortalPager query={query} /></>;
}

export function ApplicationRequests({ applicationId }: { applicationId: string }) {
  const query = usePortalPage<PortalApplicationRequest>(`portal/applications/${applicationId}/requests`);
  return <>{query.error && <QueryError error={query.error} />}<Table<PortalApplicationRequest> rowKey="id" loading={query.isFetching} dataSource={query.data?.items ?? []} pagination={false} scroll={{ x: 760 }} columns={[
    { title: '申请类型', dataIndex: 'kind' }, { title: '状态', render: (_, row) => stateTag(row.state) },
    { title: '执行模式', render: (_, row) => row.approvalRequired ? '需审批' : '直接执行' },
    { title: '创建时间', render: (_, row) => time(row.createdAt) }, { title: '有效期', render: (_, row) => time(row.expiresAt) },
    { title: '记录', render: (_, row) => <Space><Link to={`/workflows/${row.id}`}>查看申请链</Link></Space> },
  ]} /><PortalPager query={query} /></>;
}
