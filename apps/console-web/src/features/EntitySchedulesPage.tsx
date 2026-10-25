import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Space, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api, ApiError, getApiActorId } from '../api/client';
import { canonicalId } from '../api/workspace-scope';
import { useCluster } from '../app/ClusterContext';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { QueryError } from '../components/Shared';
import { mutationConfirm } from '../components/MutationConfirm';
import { usePortalScope } from './portal-hooks';
import { usePreparationWrite } from './WorkflowEntityChanges';
import { entityScheduleCommandBody, entityScheduleStateLabels, formatScheduleTime, normalizeEntitySchedule, normalizeEntityScheduleCommand, type EntitySchedule } from './entity-schedules.model';

export function EntitySchedulesPage() {
  const scope = usePortalScope(), { cluster } = useCluster(), [params, setParams] = useSearchParams();
  const readable = scope.permission.has('workflows', 'read'), selectedId = canonicalId(params.get('schedule'));
  const identityKey = JSON.stringify([scope.actor, scope.version, scope.cid, scope.wid, cluster?.execution_mode]);
  const current = useRef(identityKey), mounted = useRef(true); current.current = identityKey;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const pages = useCursorPages(identityKey), queryParams = new URLSearchParams({ size: '20' }); if (pages.cursor) queryParams.set('cursor', pages.cursor);
  const query = useQuery({ queryKey: ['entity-schedules', scope.actor, scope.version, scope.cid, scope.wid, cluster?.execution_mode, pages.cursor],
    queryFn: async ({ signal }) => {
      const raw = await api<{ items: unknown[]; nextCursor: string | null; total: null; size: number }>(scope.path(`entity-schedules?${queryParams}`), { signal });
      if (signal.aborted || !mounted.current || getApiActorId() !== scope.actor || current.current !== identityKey) throw new ApiError('定时记录范围已变化，请刷新当前范围。', 409, 'WORKFLOW_SCOPE_CHANGED');
      if (!raw || !Array.isArray(raw.items) || raw.items.length > 20 || raw.size !== 20 || raw.total !== null || raw.nextCursor !== null && typeof raw.nextCursor !== 'string') throw new Error('定时记录分页响应无效。');
      return { ...raw, items: raw.items.map(normalizeEntitySchedule) };
    }, enabled: scope.ready && readable, retry: false, staleTime: 0, gcTime: 0,
  });
  if (!readable) return <Alert type="info" message="当前范围未授予定时变更读取权限" />;
  return <><Alert type="info" showIcon message="定时变更需要审批并显式激活" description="所有时间按 Asia/Shanghai 展示。调度器只在半开变更窗口内领取执行；激活记录不代表网关已执行，最终结果以记录与工单回执为准。" style={{ marginBottom: 20 }} />
    <Space className="list-toolbar"><Button onClick={() => void query.refetch()} loading={query.isFetching}>刷新定时记录</Button></Space>
    {query.error && <QueryError error={query.error} />}
    <Card className="table-card"><Table<EntitySchedule> data-testid="entity-schedules-list" rowKey="id" dataSource={query.data?.items ?? []} loading={query.isFetching} pagination={false} scroll={{ x: 1050 }} columns={[
      { title: '计划执行 · 上海', render: (_, row) => <Button type="link" onClick={() => setParams({ tab: 'schedules', schedule: row.id })}>{formatScheduleTime(row.notBefore)}</Button> },
      { title: '变更窗口 · 上海', render: (_, row) => <div>{formatScheduleTime(row.windowStart)}<div className="table-secondary">至 {formatScheduleTime(row.windowEnd)}（不含）</div></div> },
      { title: '状态', render: (_, row) => <Tag>{entityScheduleStateLabels[row.state]}</Tag> },
      { title: '工单', render: (_, row) => row.workflowId ? <Link to={`/workflows/${row.workflowId}`}>查看工单</Link> : '尚未提交' },
      { title: '原因', render: (_, row) => row.reasonCode ?? '—' },
      { title: '操作', render: (_, row) => <Button type="link" onClick={() => setParams({ tab: 'schedules', schedule: row.id })}>详情</Button> },
    ]} /><CursorPagination pages={pages} nextCursor={query.data?.nextCursor} count={query.data?.items.length ?? 0} size={20} loading={query.isFetching} /></Card>
    {selectedId && <EntityScheduleDetail key={`${identityKey}:${selectedId}`} id={selectedId} onClose={() => setParams({ tab: 'schedules' })} />}
  </>;
}

export function EntityScheduleDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const scope = usePortalScope(), { cluster } = useCluster(), { modal, message } = App.useApp();
  const readable = scope.permission.has('workflows', 'read'), active = scope.workspace.workspace?.status === 'active' && !scope.workspace.readonlyWorkspace && !scope.workspace.writeBlocked;
  const write = usePreparationWrite(id, scope.ready && readable && active), current = useRef({ identity: write.identity, mounted: true }), [result, setResult] = useState<EntitySchedule>();
  current.current.identity = write.identity;
  useEffect(() => { current.current.mounted = true; return () => { current.current.mounted = false; }; }, []);
  const query = useQuery({ queryKey: ['entity-schedule-detail', scope.actor, scope.version, scope.cid, scope.wid, cluster?.execution_mode, id],
    queryFn: async ({ signal }) => {
      const captured = { ...write.identity }, raw = await api<{ entity: unknown }>(scope.path(`entity-schedules/${id}`), { signal });
      if (signal.aborted || !current.current.mounted || getApiActorId() !== captured.actor || JSON.stringify(current.current.identity) !== JSON.stringify(captured)) throw new ApiError('账号或定时记录范围已变化。', 409, 'WORKFLOW_SCOPE_CHANGED');
      const entity = normalizeEntitySchedule(raw?.entity); if (entity.id !== id) throw new Error('定时详情记录不匹配。'); return entity;
    }, enabled: scope.ready && readable && !!canonicalId(id), retry: false, staleTime: 0, gcTime: 0, refetchInterval: 15000,
  });
  const row = query.data, blocked = !active || !scope.ready || write.busy || !!write.attempt;
  function command(action: 'activate' | 'cancel') {
    if (!row || row.capabilities[action] !== true || blocked) return;
    const captured = { ...write.identity }, revision = row.revision;
    mutationConfirm(modal, { title: action === 'activate' ? '确认激活定时变更' : '确认撤销定时变更', expected: `${action}-schedule`, danger: action === 'cancel', okText: '确认提交', description: action === 'activate' ? '登记当前已批准的计划供调度器在窗口内核验领取。此操作不会立即执行网关变更。' : '只撤销尚未领取执行的定时记录。已领取、部分执行或结果不确定时，后端会拒绝撤销。', onConfirm: async () => {
      write.assertCurrent(captured); const fresh = await query.refetch(); write.assertCurrent(captured);
      if (!fresh.data || fresh.data.id !== id || fresh.data.revision !== revision || fresh.data.capabilities[action] !== true) throw new Error('定时记录或操作权限已变化，请重新审阅。');
      const entity = await write.write(action === 'activate' ? 'scheduleActivate' : 'scheduleCancel', `entity-schedules/${id}/${action}`, entityScheduleCommandBody(fresh.data, action), raw => normalizeEntityScheduleCommand(raw, id));
      write.assertCurrent(captured); setResult(entity); await query.refetch(); void message.success(action === 'activate' ? '激活请求已完成；执行结果请以最新记录为准' : '撤销请求已完成');
    } });
  }
  return <Drawer title="定时变更详情" width={850} open onClose={onClose} destroyOnHidden data-testid="entity-schedule-detail" extra={<Button onClick={() => void query.refetch()} loading={query.isFetching}>只读刷新状态</Button>}>
    {query.error && <QueryError error={query.error} />}{!!write.error && <QueryError error={write.error} />}
    {write.attempt && <Alert type="warning" showIcon message="原定时操作需要核验，不能重新提交" description={<>原请求键：<code>{write.attempt.key}</code>。只读刷新只能查看当前状态，不能证明原命令已完成；请在审计记录中核验原请求。</>} style={{ marginBottom: 20 }} />}
    {row && <><Descriptions bordered size="small" column={1} items={[
      { key: 'id', label: '定时记录 ID', children: <code>{row.id}</code> }, { key: 'state', label: '状态', children: <Tag>{entityScheduleStateLabels[row.state]}</Tag> },
      { key: 'notBefore', label: '计划执行 · Asia/Shanghai', children: formatScheduleTime(row.notBefore) },
      { key: 'start', label: '窗口开始（含）', children: formatScheduleTime(row.windowStart) }, { key: 'end', label: '窗口结束（不含）', children: formatScheduleTime(row.windowEnd) },
      { key: 'intent', label: '变更预览', children: <Link to={`/workflows?tab=changes&intent=${row.intentId}`}>查看原变更预览</Link> },
      { key: 'workflow', label: '工单', children: row.workflowId ? <Link to={`/workflows/${row.workflowId}`}>查看审批与执行记录</Link> : '尚未提交' },
      { key: 'claim', label: '领取记录 ID', children: row.claimId ?? '尚未领取' }, { key: 'reason', label: '状态原因', children: row.reasonCode ?? '—' },
      { key: 'revision', label: '记录版本', children: row.revision },
    ]} /><Space wrap style={{ marginTop: 20 }}><Button type="primary" disabled={blocked || row.capabilities.activate !== true} onClick={() => command('activate')}>激活定时变更</Button><Button danger disabled={blocked || row.capabilities.cancel !== true} onClick={() => command('cancel')}>撤销定时变更</Button></Space>
      {!row.capabilities.activate && !row.capabilities.cancel && <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>当前记录暂无可用操作。</Typography.Paragraph>}
    </>}
    {result && <Alert type="success" showIcon message="操作已确认" description={`记录状态：${entityScheduleStateLabels[result.state]}。`} style={{ marginTop: 20 }} />}
  </Drawer>;
}
