import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Button, Descriptions, Drawer, Form, Input, InputNumber, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { useAuth } from '../app/AuthContext';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { api, ApiError, errorMessage, getApiActorId } from '../api/client';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError, formatTime } from '../components/Shared';
import { useEntityPermissions } from '../app/EntityPermissions';
import type { EntityPageData } from './entities';
import { EntityRefById } from '../components/EntityReference';
import { workflowCanPrepare, type EntityChangeIntent } from './workflow-entity-change.model';
import { safeJsonPreview } from './m7.redaction';
import { createTargetWorkflowClient, freshTargetWorkflowSession, readTargetWorkflowAttempt, sameTargetWorkflowScope, targetManualHealthAvailable,
  targetWorkflowChange, targetWorkflowFormDefaults, targetWorkflowScope, targetWorkflowSelection, type TargetWorkflowScope,
  type TargetWorkflowSelection } from './target-workflow.model';

interface TargetDraft extends TargetWorkflowSelection { body?: Record<string, unknown>; targetName: string; }
const healthNotice = '仅作用于当前 Admin API 节点。须启用健康检查（主动或被动）且当前健康状态可核验；Kong 成功响应为 204 空响应。手动置位不可自动回滚，不支持定时执行。';

export function TargetManager({ upstreamId, parentEntity }: { upstreamId: string; parentEntity?: any }) {
  const { clusterId, cluster } = useCluster(), workspace = useWorkspace(), { workspaceId, ready, writeBlocked, readonlyWorkspace } = workspace;
  const { user } = useAuth(), parentAbility = useEntityPermissions([{ type: 'upstreams', id: upstreamId }]);
  const { message, modal } = App.useApp(), queryClient = useQueryClient(), [form] = Form.useForm();
  const [operationError, setOperationError] = useState<unknown>(), [editing, setEditing] = useState<any>(), [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<TargetDraft>(), [reviewOpen, setReviewOpen] = useState(false), [journalVersion, setJournalVersion] = useState(0);
  const scope = ready && canonicalId(user?.id) && user?.permissionsVersion && canonicalId(clusterId) && canonicalId(workspaceId) && canonicalId(upstreamId) && cluster
    ? targetWorkflowScope({ actor: user!.id, version: user!.permissionsVersion, cid: clusterId, wid: workspaceId, mode: cluster.execution_mode, upstreamId }) : undefined;
  const journal = useMemo(() => { try { return { attempt: scope ? readTargetWorkflowAttempt(scope) : undefined, error: undefined }; }
    catch (error) { return { attempt: undefined, error }; } }, [scope?.actor, scope?.version, scope?.cid, scope?.wid, scope?.mode, upstreamId, journalVersion]);
  useEffect(() => { setEditing(undefined); setOpen(false); setDraft(undefined); setReviewOpen(false); setOperationError(undefined); form.resetFields(); },
    [clusterId, workspaceId, upstreamId, user?.id, user?.permissionsVersion, cluster?.execution_mode, form]);
  const uncertain = operationError instanceof ApiError && (operationError.recovery?.state === 'uncertain' || /UNKNOWN|UNCERTAIN/.test(operationError.code ?? ''));
  const pages = useCursorPages(`${user?.id}:${user?.permissionsVersion}:${clusterId}:${workspaceId}:${upstreamId}`), base = `/clusters/${clusterId}/upstreams/${upstreamId}`;
  const scoped = (path: string) => scopeQuery(path, clusterId, workspaceId);
  const query = useQuery({ queryKey: ['targets', user?.id, user?.permissionsVersion, clusterId, workspaceId, upstreamId, pages.cursor], queryFn: () => api<EntityPageData>(scoped(`${base}/targets?size=20${pages.cursor ? `&cursor=${encodeURIComponent(pages.cursor)}` : ''}`)), enabled: !!scope, retry: false });
  const health = useQuery({ queryKey: ['target-health', user?.id, user?.permissionsVersion, clusterId, workspaceId, upstreamId], queryFn: () => api<any>(scoped(`${base}/health`)), enabled: !!scope, refetchInterval: 15000, retry: false });
  const abilities = useEntityPermissions((query.data?.items ?? []).map(entity => ({ type: 'targets', id: entity.id, parent_id: upstreamId })));
  const healthItems = health.data?.items ?? health.data?.data ?? [];
  const approvalMode = cluster?.execution_mode === 'approval', workflowAllowed = !!scope && workflowCanPrepare(user?.capabilities, scope);
  const blocked = !scope || writeBlocked || readonlyWorkspace || uncertain || !!journal.attempt || !!journal.error || approvalMode && !workflowAllowed;
  const latest = useRef({ scope, blocked, active: true, rows: query.data?.items, healthItems, canCreate: false, canTargets: abilities.can, healthError: health.isError });
  latest.current = { scope, blocked, active: true, rows: query.data?.items, healthItems, canCreate: parentAbility.can('upstreams', upstreamId, 'write'), canTargets: abilities.can, healthError: health.isError };
  const editScope = useRef<{ scope: TargetWorkflowScope; selection: TargetWorkflowSelection; targetName?: string }>();
  useEffect(() => { latest.current.active = true; return () => { latest.current.active = false; }; }, []);
  function assertCurrent(captured: TargetWorkflowScope, selection: TargetWorkflowSelection) {
    const live = latest.current, currentRow = selection.targetId ? live.rows?.find(row => row.id === selection.targetId) : undefined;
    if (!live.active || live.blocked || getApiActorId() !== captured.actor || !live.scope || !sameTargetWorkflowScope(captured, live.scope)
      || (selection.action === 'create' ? !live.canCreate : !currentRow || currentRow.upstream?.id !== captured.upstreamId || !live.canTargets('targets', selection.targetId, selection.action === 'delete' ? 'delete' : 'write'))) {
      throw new ApiError('账号、权限或当前 Target 已变化，请刷新。', 409, 'TARGET_WORKFLOW_SCOPE_CHANGED');
    }
    if (selection.action === 'health' && (live.healthError || !targetManualHealthAvailable(live.healthItems, currentRow, captured.upstreamId))) throw new ApiError('请启用健康检查（主动或被动）并核验当前节点的目标健康状态。', 409, 'TARGET_HEALTH_STATE_UNAVAILABLE');
  }
  function displayCurrent(captured: TargetWorkflowScope) { return latest.current.active && getApiActorId() === captured.actor && !!latest.current.scope && sameTargetWorkflowScope(captured, latest.current.scope); }
  async function refresh(cid = clusterId) { await queryClient.invalidateQueries({ predicate: query => query.queryKey.includes(cid) }); }
  const save = useMutation({ mutationFn: async ({ captured, selection, values }: { captured: TargetWorkflowScope; selection: TargetWorkflowSelection; values: Record<string, unknown> }) => {
    assertCurrent(captured, selection); if (captured.mode !== 'direct' || !['create', 'weight'].includes(selection.action)) throw new ApiError('此变更须提交审批。', 409, 'APPROVAL_REQUIRED');
    targetWorkflowChange(captured, selection, values); const csrf = await freshTargetWorkflowSession(captured); assertCurrent(captured, selection);
    const path = `/clusters/${captured.cid}/upstreams/${captured.upstreamId}/targets${selection.action === 'weight' ? `/${selection.targetId}` : ''}`;
    await api(scopeQuery(path, captured.cid, captured.wid), { method: selection.action === 'weight' ? 'PATCH' : 'POST', body: JSON.stringify(values), headers: { 'X-CSRF-Token': csrf } }, true);
    return captured;
  }, onSuccess: async captured => { await refresh(captured.cid); if (!displayCurrent(captured)) return; setOpen(false); form.resetFields(); void message.success('Target 已提交，配置生效中'); }, onError: (error, variables) => { if (displayCurrent(variables.captured)) setOperationError(error); } });
  function showForm(row?: any) {
    try { if (!scope || blocked) return; const selection = targetWorkflowSelection(scope, row ? 'weight' : 'create', row); assertCurrent(scope, selection);
      editScope.current = { scope, selection, targetName: row?.target }; setEditing(row); form.resetFields(); form.setFieldsValue(targetWorkflowFormDefaults(row)); setOpen(true);
    } catch (error) { setOperationError(error); }
  }
  function applyForm(values: Record<string, unknown>) {
    try {
      const captured = editScope.current; if (!captured) return; assertCurrent(captured.scope, captured.selection);
      const frozen = structuredClone(values); targetWorkflowChange(captured.scope, captured.selection, frozen);
      if (captured.selection.action === 'weight' && frozen.target !== captured.targetName) throw new ApiError('修改地址请创建新 Target。', 400, 'TARGET_ADDRESS_IMMUTABLE');
      const name = String(captured.targetName ?? frozen.target);
      const proceed = async () => { assertCurrent(captured.scope, captured.selection);
        if (captured.scope.mode === 'approval') { setDraft({ ...captured.selection, body: frozen, targetName: name }); setOpen(false); form.resetFields(); setReviewOpen(true); }
        else await save.mutateAsync({ captured: captured.scope, selection: captured.selection, values: frozen }); };
      if (frozen.weight === 0) mutationConfirm(modal, { title: '将 Target 权重设为 0', expected: name, description: '权重为 0 时，目标不再接收新的负载均衡请求。', onConfirm: proceed, danger: true, okText: approvalMode ? '确认并预览' : '确认提交' });
      else void proceed().catch(setOperationError);
    } catch (error) { setOperationError(error); }
  }
  function action(row: any, operation: 'healthy' | 'unhealthy' | 'delete') {
    try {
      if (!scope) return; const captured = scope, selection = targetWorkflowSelection(captured, operation === 'delete' ? 'delete' : 'health', row, operation === 'delete' ? undefined : operation); assertCurrent(captured, selection);
      mutationConfirm(modal, { title: operation === 'delete' ? '将 Target 移入回收站' : `将 ${row.target} 手动置为${operation === 'healthy' ? '健康' : '不健康'}`, expected: row.target,
        description: operation === 'delete' ? '先归档 Target，再从有效负载均衡配置中移除。' : healthNotice, danger: operation !== 'healthy', onConfirm: async () => {
          try {
            assertCurrent(captured, selection);
            if (captured.mode === 'approval') { setDraft({ ...selection, targetName: row.target }); setReviewOpen(true); return; }
            const csrf = await freshTargetWorkflowSession(captured); assertCurrent(captured, selection);
            const path = `/clusters/${captured.cid}/upstreams/${captured.upstreamId}/targets/${selection.targetId}${operation === 'delete' ? '' : `/${operation}`}`;
            await api(scopeQuery(path, captured.cid, captured.wid), { method: operation === 'delete' ? 'DELETE' : 'POST', body: JSON.stringify({ confirmed: true, confirm_name: row.target }), headers: { 'X-CSRF-Token': csrf } }, true);
            await refresh(captured.cid); if (displayCurrent(captured)) void message.success(operation === 'delete' ? 'Target 已移入回收站' : '当前节点健康状态已提交');
          } catch (error) { if (displayCurrent(captured)) { setOperationError(error); void message.error(errorMessage(error)); } throw error; }
        } });
    } catch (error) { setOperationError(error); }
  }
  return <><div className="embedded-toolbar"><Typography.Text type="secondary">实时健康状态每 15 秒刷新</Typography.Text><Space>
    <Button icon={<ReloadOutlined />} onClick={() => { void query.refetch(); void health.refetch(); }}>刷新</Button>
    <Button type="primary" icon={<PlusOutlined />} disabled={blocked || !parentAbility.can('upstreams', upstreamId, 'write')} onClick={() => showForm()}>添加 Target</Button>
  </Space></div>{!!operationError && <QueryError error={operationError} />}{!!journal.error && <QueryError error={journal.error} />}
    {journal.attempt && <Alert showIcon type="warning" message={journal.attempt.state === 'prepared' ? '已有 Target 变更预览' : '原 Target 请求需要核验'}
      description={<Space wrap><Typography.Text className="mono" copyable>{journal.attempt.key}</Typography.Text><Button onClick={() => { setDraft(undefined); setReviewOpen(true); }}>查看与核验</Button></Space>} style={{ marginBottom: 16 }} />}
    {abilities.query.isError && <QueryError error={abilities.query.error} retry={() => void abilities.query.refetch()} />}{query.isError && <QueryError error={query.error} />}{health.isError && <QueryError error={health.error} />}
    <Table size="small" rowKey="id" pagination={false} loading={query.isFetching} dataSource={query.data?.items ?? []} scroll={{ x: 760 }} columns={[
      { title: 'Target', dataIndex: 'target', render: value => <Typography.Text className="mono">{value}</Typography.Text> }, { title: '权重', dataIndex: 'weight', width: 80 },
      { title: '节点健康', width: 180, render: (_, row) => { const state = healthItems.find((item: any) => item.id === row.id)?.health; return <Tag color={state === 'HEALTHY' ? 'green' : state === 'UNHEALTHY' ? 'red' : 'default'}>{state ?? '未取得状态'}</Tag>; } },
      { title: '操作', width: 280, render: (_, row) => <Space size={0}>
        <Button type="link" size="small" disabled={blocked || !abilities.can('targets', row.id, 'write')} onClick={() => showForm(row)}>编辑</Button>
        <Button type="link" size="small" disabled={blocked || !abilities.can('targets', row.id, 'write') || health.isError || !targetManualHealthAvailable(healthItems, row, upstreamId)} onClick={() => action(row, 'healthy')}>健康</Button>
        <Button type="link" size="small" disabled={blocked || !abilities.can('targets', row.id, 'write') || health.isError || !targetManualHealthAvailable(healthItems, row, upstreamId)} onClick={() => action(row, 'unhealthy')}>不健康</Button>
        <Button type="link" danger size="small" disabled={blocked || !abilities.can('targets', row.id, 'delete')} onClick={() => action(row, 'delete')}>删除</Button>
      </Space> },
    ]} />
    <CursorPagination pages={pages} count={query.data?.items.length ?? 0} size={20} loading={query.isFetching} nextCursor={query.data?.nextCursor} />
    <Alert type="info" showIcon message="Target 历史记录" description={`${cluster?.version ? `Kong ${cluster.version}` : '当前 Kong 版本'} 的权重与标签修改追加新的有效历史行，原 Target ID 与新有效 ID 不同。`} style={{ marginTop: 18 }} />
    <Modal title={editing ? '编辑 Target' : '添加 Target'} open={open} onCancel={() => { setOpen(false); form.resetFields(); }} onOk={() => form.submit()} confirmLoading={save.isPending}
      okButtonProps={{ disabled: blocked || (editing ? !abilities.can('targets', editing.id, 'write') : !parentAbility.can('upstreams', upstreamId, 'write')) }} okText={approvalMode ? '预览变更' : '保存 Target'} cancelText="取消">
      {operationError ? <QueryError error={operationError} /> : null}<Form form={form} layout="vertical" requiredMark={false} onFinish={applyForm}>
        <Form.Item name="target" label="目标地址" rules={[{ required: true, message: '请输入 host:port' }]}><Input disabled={!!editing} placeholder="api.internal:8080 或 [::1]:8080" /></Form.Item>
        <Form.Item name="weight" label="权重" rules={[{ required: true }]}><InputNumber min={0} max={1000} precision={0} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="tags" label="标签"><Select mode="tags" tokenSeparators={[',']} /></Form.Item>
      </Form>
    </Modal>
    {reviewOpen && scope && <TargetApprovalDrawer key={[scope.actor, scope.version, scope.cid, scope.wid, scope.mode, upstreamId, draft?.action, draft?.targetId, draft?.healthState].join(':')}
      scope={scope} draft={draft} parentEntity={parentEntity} rows={query.data?.items ?? []} healthItems={health.isError ? [] : healthItems}
      onChange={() => setJournalVersion(value => value + 1)} onClose={() => { setDraft(undefined); setReviewOpen(false); }} />}
  </>;
}

function TargetApprovalDrawer({ scope, draft, rows, healthItems, onChange, onClose }: { scope: TargetWorkflowScope; draft?: TargetDraft; parentEntity?: any; rows: any[]; healthItems: any[]; onChange: () => void; onClose: () => void }) {
  const { user } = useAuth(), workspace = useWorkspace(), { clusterId, cluster } = useCluster(), { modal } = App.useApp(), navigate = useNavigate();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [intent, setIntent] = useState<EntityChangeIntent>(), [workflowId, setWorkflowId] = useState<string>();
  const [journalVersion, setJournalVersion] = useState(0), [notObserved, setNotObserved] = useState(false);
  const journal = useMemo(() => { try { return { attempt: readTargetWorkflowAttempt(scope), error: undefined }; } catch (error) { return { attempt: undefined, error }; } }, [scope, journalVersion]);
  const attempt = journal.attempt, selection = attempt ?? draft;
  const ability = useEntityPermissions(selection?.targetId ? [{ type: 'targets', id: selection.targetId, parent_id: scope.upstreamId }] : [{ type: 'upstreams', id: scope.upstreamId }]);
  const currentRow = rows.find(row => row.id === selection?.targetId && row.upstream?.id === scope.upstreamId);
  const writable = !!selection && clusterId === scope.cid && cluster?.execution_mode === 'approval' && scope.mode === 'approval'
    && !!user && user.id === scope.actor && user.permissionsVersion === scope.version && workspace.ready && workspace.workspaceId === scope.wid
    && !workspace.writeBlocked && !workspace.readonlyWorkspace && workspace.workspace?.status === 'active' && workflowCanPrepare(user.capabilities, scope)
    && (selection.action === 'create' ? ability.can('upstreams', scope.upstreamId, 'write') : !!currentRow && ability.can('targets', selection.targetId, selection.action === 'delete' ? 'delete' : 'write'))
    && (selection.action !== 'health' || targetManualHealthAvailable(healthItems, currentRow, scope.upstreamId));
  const latest = useRef({ scope, writable, active: true }); latest.current = { scope, writable, active: true };
  useEffect(() => { latest.current.active = true; return () => { latest.current.active = false; }; }, []);
  const client = useMemo(() => createTargetWorkflowClient({ scope: () => latest.current.scope, assertCurrent(captured, writing) {
    if (!latest.current.active || getApiActorId() !== captured.actor || !sameTargetWorkflowScope(captured, latest.current.scope) || writing && !latest.current.writable) throw new ApiError('账号、权限或 Target 范围已变化。', 409, 'TARGET_WORKFLOW_SCOPE_CHANGED');
  }, onChange() { if (latest.current.active) { setJournalVersion(value => value + 1); onChange(); } } }), []);
  useEffect(() => { if (!attempt?.intentId || attempt.state !== 'prepared') return; let active = true;
    void client.inspect(attempt).then(value => { if (active) { setIntent(value); setWorkflowId(value.workflowId ?? undefined); } }, error => { if (active) setError(error); }); return () => { active = false; };
  }, [attempt?.intentId, attempt?.revision, attempt?.materialHmac, client]);
  async function run(callback: () => Promise<void>) { if (busy) return; setBusy(true); setError(undefined); try { await callback(); } catch (error) { if (latest.current.active) setError(error); } finally { if (latest.current.active) setBusy(false); } }
  function submit() {
    if (!attempt || !intent || !writable || !intent.capabilities.submit) return;
    const change = intent.review.changes[0], after = change.after as any, before = change.before as any, name = String(after?.target ?? before?.target ?? '');
    if (!name) return;
    mutationConfirm(modal, { title: '提交 Target 变更工单', expected: name, danger: selection?.action === 'delete' || selection?.healthState === 'unhealthy' || after?.weight === 0,
      description: selection?.action === 'health' ? healthNotice : selection?.action === 'delete' ? '审批执行后将原 Target 归档到回收站，再从有效配置移除。' : after?.weight === 0 ? '审批执行后权重变为 0，目标不再接收新的负载均衡请求。' : '审批执行后追加 Target 历史记录，以执行结果中的新有效 ID 为准。',
      okText: '确认提交工单', onConfirm: async () => { setBusy(true); setError(undefined);
        try { const id = await client.submit(attempt, intent); if (latest.current.active) { setWorkflowId(id); setIntent(undefined); } }
        catch (error) { if (latest.current.active) setError(error); throw error; }
        finally { if (latest.current.active) setBusy(false); }
      } });
  }
  return <Drawer title="Target 变更审批" open width={760} onClose={onClose} destroyOnClose>
    {!!journal.error && <QueryError error={journal.error} />}{!!error && <QueryError error={error} />}
    <Descriptions size="small" column={1} items={[{ key: 'parent', label: 'Upstream', children: <EntityRefById type="upstreams" id={scope.upstreamId} /> },
      { key: 'target', label: '原 Target ID', children: selection?.targetId ?? '创建新 Target' },
      { key: 'operation', label: '操作', children: selection?.action === 'create' ? '添加 Target' : selection?.action === 'weight' ? '更新权重与标签' : selection?.action === 'delete' ? '移入回收站' : selection?.healthState === 'healthy' ? '置为健康' : '置为不健康' },
      ...(intent ? [{ key: 'expiry', label: '预览有效期', children: formatTime(intent.expiresAt) }] : [])]} />
    {selection?.action === 'health' && <Alert showIcon type="warning" message="当前节点手动健康置位" description={healthNotice} style={{ margin: '16px 0' }} />}
    {attempt && <Alert showIcon type="warning" message={attempt.state === 'prepared' ? '审批预览已准备' : '原请求待核验'} description={<Typography.Text className="mono" copyable>{attempt.key}</Typography.Text>} style={{ margin: '16px 0' }} />}
    {notObserved && <Alert showIcon type="warning" message="尚未观察到原准备回执" description="已保留原请求键，请稍后继续只读核验。此状态不能用于重新提交。" style={{ marginBottom: 16 }} />}
    {intent ? <><Typography.Title level={5}>变更前</Typography.Title><pre className="json-preview">{safeJsonPreview(intent.review.changes[0].before)}</pre>
      <Typography.Title level={5}>变更后</Typography.Title><pre className="json-preview">{safeJsonPreview(intent.review.changes[0].after)}</pre>
      {selection?.action === 'weight' && <Typography.Paragraph type="secondary">新 Target ID：<Typography.Text className="mono">{intent.review.changes[0].nativeId}</Typography.Text></Typography.Paragraph>}</>
      : draft && !attempt && draft.body ? <pre className="json-preview">{safeJsonPreview(draft.body)}</pre> : null}
    <Space wrap style={{ marginTop: 20 }}>
      {!attempt && !journal.error && !workflowId && draft && <Button type="primary" disabled={!writable} loading={busy} onClick={() => void run(async () => {
        const prepared = await client.prepare(draft, draft.body, draft.action === 'delete' ? draft.targetName : undefined); if (latest.current.active) setIntent(prepared);
      })}>生成审批预览</Button>}
      {attempt && <Button loading={busy} onClick={() => void run(async () => { const result = await client.recover(attempt);
        if (latest.current.active) { setNotObserved(result.notObserved === true); if (result.intent) setIntent(result.intent); if (result.workflowId) setWorkflowId(result.workflowId); }
      })}>核验原请求</Button>}
      {attempt?.stage === 'prepare' && attempt.state === 'prepared' && intent && !workflowId && <><Button type="primary" disabled={!writable || !intent.capabilities.submit || Date.parse(intent.expiresAt) <= Date.now()} loading={busy} onClick={submit}>提交审批</Button>
        <Button disabled={busy} onClick={() => void run(async () => { await client.discardPrepared(attempt); if (latest.current.active) onClose(); })}>放弃此预览</Button></>}
      {workflowId && <Button type="primary" onClick={() => navigate(`/workflows/${workflowId}?workspaceId=${scope.wid}`)}>查看变更工单</Button>}
    </Space>
  </Drawer>;
}
