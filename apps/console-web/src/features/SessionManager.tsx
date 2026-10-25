import { useState } from 'react';
import { Alert, App, Button, Space, Table, Tag } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, authWriteNeedsVerification, post } from '../api/client';
import { useAuth } from '../app/AuthContext';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError, formatTime } from '../components/Shared';

interface SessionRow { id: string; ip: string | null; user_agent: string | null; created_at: string; expires_at: string; current: boolean; }
export function SessionManager({ userId, username, writable = true }: { userId?: string; username?: string; writable?: boolean }) {
  const auth = useAuth(), { modal, message } = App.useApp();
  const [error, setError] = useState<unknown>();
  const uncertain = error instanceof ApiError && error.code === 'SESSION_REVOKE_RESULT_UNKNOWN';
  const base = userId ? `/auth/users/${userId}/sessions` : '/auth/me/sessions';
  const targetName = username ?? auth.user?.username ?? '';
  const ownAccount = !userId || userId === auth.user?.id;
  const pages = useCursorPages(`${base}:${auth.user?.permissionsVersion}`);
  const query = useQuery({ queryKey: ['account-sessions', auth.user?.id, userId, auth.user?.permissionsVersion, pages.cursor], queryFn: () => api<{ items: SessionRow[]; nextCursor: string | null; size: number }>(`${base}?size=20${pages.cursor ? `&cursor=${encodeURIComponent(pages.cursor)}` : ''}`) });
  function revoke(row?: SessionRow) {
    const endsOwnSession = ownAccount && (!row || row.current);
    mutationConfirm(modal, { title: row ? '确认撤销会话' : '确认撤销全部会话', expected: auth.user?.username ?? '', danger: true, description: endsOwnSession ? '当前登录会立即失效，必须重新登录。' : '选定会话的访问令牌与刷新令牌会立即失效。', onConfirm: async () => {
      setError(undefined);
      try {
        await post(row ? `${base}/${row.id}/revoke` : `${base}/revoke-all`, { confirmed: true, confirm_name: auth.user?.username });
        if (endsOwnSession) auth.endSession(); else await query.refetch();
      } catch (cause) {
        if (authWriteNeedsVerification(cause)) {
          if (endsOwnSession) { auth.endSession(); void message.warning('撤销响应未送达，请重新登录核验会话状态。'); return; }
          const unknown = new ApiError('撤销响应未送达，请关闭确认框并刷新会话列表核验；本次不会自动重发。', cause instanceof ApiError ? cause.status : 0, 'SESSION_REVOKE_RESULT_UNKNOWN');
          setError(unknown); throw unknown;
        }
        setError(cause); throw cause;
      }
    } });
  }
  return <>
    <Alert showIcon type="info" message={`服务端会话管理 · ${targetName}`} description="会话最多保留 10 个；撤销会立即使对应访问和刷新令牌失效。列表不包含令牌、密钥或令牌哈希。" style={{ marginBottom: 16 }} />
    {error ? <QueryError error={error} /> : null}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    <div className="embedded-toolbar"><span>有效会话</span><Space><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={async () => { const result = await query.refetch(); if (result.isSuccess) setError(undefined); }}>刷新会话</Button><Button danger disabled={!writable || uncertain || !query.data?.items.length} onClick={() => revoke()}>撤销全部会话</Button></Space></div>
    <Table rowKey="id" pagination={false} size="small" loading={query.isFetching} scroll={{ x: 980 }} dataSource={query.data?.items ?? []} columns={[{ title: '来源', width: 330, render: (_, row) => <div>{row.ip ?? '未知来源'}{row.current && <Tag color="blue" style={{ marginLeft: 8 }}>当前会话</Tag>}<div className="table-secondary">{row.user_agent ?? '未提供客户端信息'}</div></div> }, { title: '登录时间', width: 190, render: (_, row) => formatTime(row.created_at) }, { title: '到期时间', width: 190, render: (_, row) => formatTime(row.expires_at) }, { title: '操作', width: 130, render: (_, row) => <Button type="link" danger disabled={!writable || uncertain} onClick={() => revoke(row)}>撤销会话</Button> }]} />
    <CursorPagination pages={pages} size={20} count={query.data?.items.length ?? 0} nextCursor={query.data?.nextCursor} loading={query.isFetching} />
  </>;
}
