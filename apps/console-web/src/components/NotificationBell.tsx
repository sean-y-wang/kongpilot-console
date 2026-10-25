import { useEffect, useState } from 'react';
import { Badge, Button, Drawer, Empty, List, Space, Tag, Tooltip, Typography } from 'antd';
import { PilotIcon } from '../../../../packages/contracts/src/PilotIcon';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { QueryError, formatTime } from './Shared';
import { useM7Scope } from '../features/m7.hooks';
import { m7QueryIdentity } from '../features/m7.cursor';
import { NotificationDetails } from '../features/NotificationsPage';
import type { M7Page, NotificationView, NotificationUnread } from '../features/m7.types';

export function NotificationBell() {
  const scope = useM7Scope(), [open, setOpen] = useState(false), [visible, setVisible] = useState(document.visibilityState === 'visible'), [detail, setDetail] = useState<NotificationView>();
  useEffect(() => { const listener = () => setVisible(document.visibilityState === 'visible'); document.addEventListener('visibilitychange', listener); return () => document.removeEventListener('visibilitychange', listener); }, []);
  const identityKey = m7QueryIdentity(scope.identity, 'bell', {});
  useEffect(() => { setOpen(false); setDetail(undefined); }, [identityKey]);
  const enabled = scope.ready && scope.permission.has('notifications'), count = useQuery({ queryKey: ['m7', identityKey, 'unread'], queryFn: ({ signal }) => api<NotificationUnread>(scope.personal('unread-count'), { signal }), enabled: enabled && visible, refetchInterval: visible ? 30_000 : false, retry: false, gcTime: 0 });
  const recent = useQuery({ queryKey: ['m7', identityKey, 'recent'], queryFn: ({ signal }) => api<M7Page<NotificationView>>(scope.personal('', { size: '5', unreadOnly: 'true', dismissed: 'false' }), { signal }), enabled: enabled && open, retry: false, gcTime: 0 });
  if (!scope.permission.has('notifications')) return null;
  const available = !!count.data && !count.error, label = available ? `${count.data!.complete ? '' : '至少 '}${count.data!.unreadCount} 条未读${count.data!.complete ? '' : '（扫描未完成）'}` : '未读计数不可用';
  return <><Tooltip title={label}><Button type="text" aria-label="打开本人通知" onClick={() => setOpen(true)}><Badge count={available ? count.data!.unreadCount : '?'} overflowCount={99} showZero><PilotIcon name="bell" style={{ fontSize: 20 }} /></Badge></Button></Tooltip><Drawer title="本人未读通知" open={open} onClose={() => setOpen(false)} width={420} destroyOnHidden extra={<Link to="/notifications" onClick={() => setOpen(false)}>全部消息</Link>}><Space style={{ marginBottom: 15 }}><Tag color={available && count.data!.complete ? 'blue' : 'orange'}>{label}</Tag><Button onClick={() => { void count.refetch(); void recent.refetch(); }}>刷新</Button></Space>{recent.error && <QueryError error={recent.error} />}<List loading={recent.isFetching} locale={{ emptyText: recent.error ? '消息不可用' : <Empty description="当前范围没有未读消息" /> }} dataSource={recent.data?.items ?? []} renderItem={row => <List.Item><Button type="text" style={{ height: 'auto', textAlign: 'left', width: '100%', whiteSpace: 'normal' }} onClick={() => setDetail(row)}><Typography.Text strong>{row.title}</Typography.Text><Typography.Paragraph ellipsis={{ rows: 2 }} style={{ margin: '5px 0' }}>{row.summary}</Typography.Paragraph><Typography.Text type="secondary">{formatTime(row.createdAt)}</Typography.Text></Button></List.Item>} /></Drawer>{detail && <NotificationDetails row={detail} onClose={() => setDetail(undefined)} />}</>;
}
