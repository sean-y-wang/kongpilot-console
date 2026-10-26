import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Checkbox, Descriptions, Drawer, Form, Input, InputNumber, Select, Space, Spin, Steps, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { mutationConfirm } from '../components/MutationConfirm';
import { KongSchemaForm, prepareFormValues, schemaFields, type KongSchema } from '../components/KongSchemaForm';
import { QueryError, formatTime } from '../components/Shared';
import { ScopedEntityLookup } from './IAMLookups';
import { entityLabels, entityTypes } from './entities';
import { usePortalScope } from './portal-hooks';
import type { Workflow } from './portal.types';
import { clearWorkflowAttempt, entityChangeSubmitPayload, nativeRollbackPayload, nativeRollbackUnavailableReason, nativeWorkflowCan, normalizeEntityChangeIntent, normalizeNativeChangePreflight, targetHealthRollbackUnavailableReason,
  readWorkflowAttempt, sameWorkflowIdentity, storeWorkflowAttempt, workflowCanPrepare, type EntityChangeIntent, type NativeChangePreflight, type WorkflowIdentity, type WorkflowWriteAttempt } from './workflow-entity-change.model';
import { defaultScheduleLocal, formatScheduleTime, scheduledIntentMatchesRequest, scheduledPreparationPayload, scheduledTargetReviewMatchesRequest, type ScheduleLocalInput } from './entity-schedules.model';
import { EntityIdText } from '../components/EntityReference';

const credentials = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
export function workflowIdentity(scope: ReturnType<typeof usePortalScope>): WorkflowIdentity { return { actor: scope.actor, version: scope.version, cid: scope.cid, wid: scope.wid }; }

/** No business bodies, credentials or server authority are written to storage.
 * The original key is retained before POST and cannot become another POST. */
export function usePreparationWrite(subject: string, enabled = true) {
  const scope = usePortalScope(), { cluster } = useCluster(), identity = { ...workflowIdentity(scope), mode: cluster?.execution_mode }, identityKey = JSON.stringify(identity);
  const [state, setState] = useState<{ identityKey: string; attempt?: WorkflowWriteAttempt }>({ identityKey, attempt: scope.ready ? readWorkflowAttempt(identity, subject) : undefined });
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>();
  const current = useRef(identity), boundary = useRef({ scope, enabled }), mounted = useRef(true), running = useRef(false); current.current = identity; boundary.current = { scope, enabled };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setBusy(false); setError(undefined); setState({ identityKey, attempt: scope.ready ? readWorkflowAttempt(identity, subject) : undefined }); }, [identityKey, subject, scope.ready]);
  const attempt = state.identityKey === identityKey ? state.attempt : scope.ready ? readWorkflowAttempt(identity, subject) : undefined;
  const assertCurrent = (captured: WorkflowIdentity) => {
    const active = boundary.current;
    if (!mounted.current || !active.enabled || !active.scope.ready || active.scope.workspace.workspace?.status !== 'active' || active.scope.workspace.readonlyWorkspace || active.scope.workspace.writeBlocked || getApiActorId() !== captured.actor || !sameWorkflowIdentity(captured, current.current)) throw new ApiError('账号、权限、执行模式或操作范围已变化，请重新审阅。', 409, 'WORKFLOW_SCOPE_CHANGED');
  };
  const retain = (value?: WorkflowWriteAttempt) => { if (value) storeWorkflowAttempt(value); else if (attempt) clearWorkflowAttempt(attempt); if (mounted.current) setState({ identityKey, attempt: value }); };
  async function write<T>(action: WorkflowWriteAttempt['action'], resource: string, body: unknown, parse: (raw: unknown) => T): Promise<T> {
    const captured = { ...identity }; assertCurrent(captured);
    if (!scope.ready || running.current || attempt || readWorkflowAttempt(captured, subject) || scope.workspace.readonlyWorkspace || scope.workspace.writeBlocked) throw new Error('已有原请求待核验，不能重新提交。');
    const original: WorkflowWriteAttempt = { ...captured, subject, action, key: newIdempotencyKey(), state: 'pending', ...(canonicalId(subject) ? { intentId: subject } : {}) };
    running.current = true; retain(original); setBusy(true); setError(undefined);
    try {
      const raw = await api<unknown>(scopeQuery(`/clusters/${captured.cid}/${resource}`, captured.cid, captured.wid), { method: 'POST', body: JSON.stringify(body), headers: { 'X-Idempotency-Key': original.key } }, true);
      assertCurrent(captured); const result = parse(raw); clearWorkflowAttempt(original); if (mounted.current) setState({ identityKey, attempt: undefined }); return result;
    } catch (cause) {
      const uncertain = !(cause instanceof ApiError) || cause.status === 0 || cause.status >= 500 || /UNKNOWN|UNCERTAIN|INVALID_RESPONSE|SCOPE_CHANGED|SESSION_CHANGED/.test(cause.code ?? '');
      const retained = { ...original, state: uncertain ? 'unknown' as const : 'failed' as const }; storeWorkflowAttempt(retained);
      const error = uncertain ? new ApiError(`原请求结果尚未确认，请核验后再操作。原请求键：${original.key}`, cause instanceof ApiError ? cause.status : 0, 'WORKFLOW_PREPARATION_RESULT_UNKNOWN', undefined, cause instanceof ApiError ? cause.requestId : undefined) : cause;
      if (mounted.current && sameWorkflowIdentity(captured, current.current)) { setState({ identityKey, attempt: retained }); setError(error); } throw error;
    } finally { running.current = false; if (mounted.current && sameWorkflowIdentity(captured, current.current)) setBusy(false); }
  }
  return { scope, identity, attempt, busy, error, write, assertCurrent };
}

export function WorkflowEntityChanges() {
  const scope = usePortalScope(), [params, setParams] = useSearchParams(), [open, setOpen] = useState(false);
  const { user } = useAuth();
  const intentId = canonicalId(params.get('intent'));
  const canPrepare = workflowCanPrepare(user?.capabilities, workflowIdentity(scope));
  return <><Space className="list-toolbar" wrap><Button type="primary" disabled={!scope.ready || !canPrepare || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace} onClick={() => setOpen(true)}>准备网关变更</Button>
    {intentId && <Button onClick={() => setParams({ tab: 'changes' })}>返回发起变更</Button>}</Space>
    {intentId ? <WorkflowIntentReview key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}:${intentId}`} intentId={intentId} />
      : <Card><Typography.Text type="secondary">选择网关对象并生成变更预览，确认后提交工单。</Typography.Text></Card>}
    <EntityChangePrepareDrawer key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}`} open={open} onClose={() => setOpen(false)}
      onPrepared={intent => { setOpen(false); setParams({ tab: 'changes', intent: intent.id }); }} />
  </>;
}

export function EntityChangePrepareDrawer({ open, onClose, onPrepared }: { open: boolean; onClose: () => void; onPrepared: (intent: EntityChangeIntent) => void }) {
  const write = usePreparationWrite('prepare'), scope = write.scope, [form] = Form.useForm();
  const { user } = useAuth();
  const { cluster } = useCluster(), { modal } = App.useApp();
  const [scheduled, setScheduled] = useState(false), [scheduleInput, setScheduleInput] = useState<ScheduleLocalInput>(() => defaultScheduleLocal()), [scheduleError, setScheduleError] = useState<unknown>();
  const [kind, setKind] = useState('entity'), [type, setType] = useState('services'), [action, setAction] = useState('create');
  const [nativeId, setNativeId] = useState<string>(), [parentId, setParentId] = useState<string>(), [ttlHours, setTtl] = useState(24);
  const [targetSelection, setTargetSelection] = useState<{ identity: WorkflowIdentity; upstreamId: string; entity: Record<string, any> }>();
  const scheduleSupported = cluster?.execution_mode === 'approval' && ['entity', 'credential', 'target'].includes(kind) && ['create', 'update'].includes(action);
  useEffect(() => { if (!scheduleSupported) setScheduled(false); setScheduleError(undefined); }, [scheduleSupported, kind, type, action]);
  // BFF accepts the credential kind and maps it to Kong 1.5's fixed DAO name.
  const pluginName = Form.useWatch('name', form), schemaType = type;
  const requestResource = kind === 'credential' ? `consumers/${parentId}/credentials/${type}/${nativeId}` : kind === 'target' ? `upstreams/${parentId}/targets/${nativeId}` : `entities/${type}/${nativeId}`;
  const before = useQuery({ queryKey: ['workflow-entity-before', scope.cid, scope.wid, scope.actor, scope.version, kind, type, parentId, nativeId],
    queryFn: ({ signal }) => api<any>(scope.path(requestResource), { signal }), enabled: open && scope.ready && kind !== 'target' && action === 'update' && !!nativeId && (kind === 'entity' || !!parentId), retry: false, staleTime: 0, gcTime: 0 });
  const schema = useQuery({ queryKey: ['workflow-entity-schema', scope.cid, scope.wid, scope.actor, scope.version, schemaType],
    queryFn: ({ signal }) => api<KongSchema>(scope.path(`schemas/${schemaType}`), { signal }), enabled: open && scope.ready && !!schemaType, retry: false, staleTime: 0, gcTime: 0 });
  const plugin = useQuery({ queryKey: ['workflow-entity-plugin-schema', scope.cid, scope.wid, scope.actor, scope.version, pluginName],
    queryFn: ({ signal }) => api<{ form_schema: KongSchema }>(scope.path(`plugin-center/schemas/${encodeURIComponent(pluginName)}`), { signal }),
    enabled: open && scope.ready && kind === 'entity' && type === 'plugins' && !!pluginName, retry: false, staleTime: 0, gcTime: 0 });
  const selectedTarget = targetSelection && sameWorkflowIdentity(targetSelection.identity, write.identity) && targetSelection.upstreamId === parentId
    && targetSelection.entity.id === nativeId && targetSelection.entity.upstream?.id === parentId ? targetSelection.entity : undefined;
  const previous = kind === 'target' ? selectedTarget : before.data?.entity ?? before.data;
  useEffect(() => { form.resetFields(); setNativeId(undefined); setTargetSelection(undefined); }, [kind, type, action, parentId, form]);
  useEffect(() => {
    if (!open || !schema.data || action === 'update' && !previous) return;
    form.resetFields();
    const values = prepareFormValues(schema.data, action === 'update' ? previous : {}, action === 'update');
    if (Array.isArray(values.tags)) values.tags = values.tags.filter((tag: string) => !/^workspace:|^kos-ws-/i.test(tag));
    form.setFieldsValue(values);
  }, [open, schema.data, previous, action, form]);
  useEffect(() => { if (plugin.data) form.setFieldValue('config', prepareFormValues(plugin.data.form_schema, form.getFieldValue('config'), action === 'update', false)); }, [plugin.data, action, form]);
  const renderedSchema = schema.data ? { ...schema.data, fields: schemaFields(schema.data).filter(([name]) => !['id', 'created_at', 'updated_at', 'ttl', ...(kind === 'credential' ? ['consumer'] : kind === 'target' ? ['upstream'] : [])].includes(name) && (kind !== 'target' || action !== 'update' || name === 'weight'))
    .map(([name, field]) => ({ [name]: type === 'plugins' && name === 'config' && plugin.data ? { ...field, type: 'record', ...plugin.data.form_schema } : field })) } : undefined;
  const blocked = write.busy || !!write.attempt || !scope.ready || scope.workspace.workspace?.status !== 'active' || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace || scheduled && !scheduleSupported || !workflowCanPrepare(user?.capabilities, workflowIdentity(scope))
    || !renderedSchema || action === 'update' && (!nativeId || !previous) || kind !== 'entity' && !canonicalId(parentId) || type === 'plugins' && !plugin.data;
  const preparationTuple = JSON.stringify({ open, kind, type, action, parentId, nativeId, ttlHours, scheduled, scheduleInput,
    target: selectedTarget ? { id: selectedTarget.id, target: selectedTarget.target, weight: selectedTarget.weight, upstreamId: selectedTarget.upstream.id } : null });
  const livePreparation = useRef({ tuple: preparationTuple, allowed: false });
  livePreparation.current = { tuple: preparationTuple, allowed: open && !!renderedSchema && (action !== 'update' || !!nativeId && !!previous)
    && workflowCanPrepare(user?.capabilities, workflowIdentity(scope)) && (kind === 'entity' || !!canonicalId(parentId)) && (!scheduled || scheduleSupported) };
  async function prepare(body: Record<string, any>) {
    if (blocked) return;
    const change = kind === 'entity' ? { kind, action, entityType: type, ...(action === 'update' ? { entityId: nativeId } : {}), body }
      : kind === 'credential' ? { kind, action, consumerId: parentId, credentialKind: type, ...(action === 'update' ? { credentialId: nativeId } : {}), body }
      : action === 'update' ? { kind: 'target', action: 'weight', upstreamId: parentId, targetId: nativeId, body: { weight: body.weight } }
      : { kind: 'target', action: 'create', upstreamId: parentId, body };
    if (scheduled) {
      try {
        const payload = scheduledPreparationPayload(change, scheduleInput, write.identity.actor, ttlHours), captured = { ...write.identity }, tuple = preparationTuple, formSnapshot = JSON.stringify(form.getFieldsValue(true));
        const assertSelectedCurrent = () => { write.assertCurrent(captured); if (!livePreparation.current.allowed || livePreparation.current.tuple !== tuple || JSON.stringify(form.getFieldsValue(true)) !== formSnapshot) throw new ApiError('变更对象、表单或执行窗口已变化，请重新确认。', 409, 'WORKFLOW_SCOPE_CHANGED'); };
        const targetSummary = kind === 'target' ? `Upstream ${parentId} → Target ${action === 'update' ? `${selectedTarget!.target}（${nativeId}），权重 ${selectedTarget!.weight} → ${body.weight}` : body.target}。` : '';
        mutationConfirm(modal, { title: '确认准备定时变更', expected: 'scheduled-change', danger: kind === 'target' && body.weight === 0, okText: '生成定时预览', description: `${targetSummary}计划执行：${formatScheduleTime(payload.schedule.notBefore)}；窗口：${formatScheduleTime(payload.schedule.windowStart)} 至 ${formatScheduleTime(payload.schedule.windowEnd)}（Asia/Shanghai，不含结束时间）。提交审批并激活后按窗口执行。`, onConfirm: async () => {
          assertSelectedCurrent(); const intent = await write.write('prepare', 'entity-changes/prepare-scheduled', payload, raw => { assertSelectedCurrent(); const value = normalizeEntityChangeIntent(raw); if (!scheduledIntentMatchesRequest(value.schedule, payload.schedule) || kind === 'target' && !scheduledTargetReviewMatchesRequest(value.review.changes, payload.change)) throw new Error('定时准备回执与所选对象、执行账号或窗口不一致，请核验原请求。'); return value; }); form.resetFields(); onPrepared(intent);
        } });
      } catch (error) { setScheduleError(error); }
      return;
    }
    try { const intent = await write.write('prepare', 'entity-changes/prepare', { change, ttlHours }, normalizeEntityChangeIntent); form.resetFields(); onPrepared(intent); } catch { /* Original error/key remain visible; no automatic resend. */ }
  }
  return <Drawer title="准备网关变更" width={840} open={open} destroyOnHidden onClose={() => { form.resetFields(); onClose(); }} extra={<Button type="primary" loading={write.busy} disabled={blocked} onClick={() => form.submit()}>生成变更预览</Button>}>
    <Space wrap style={{ marginBottom: 20 }}><Select aria-label="变更对象类别" value={kind} onChange={value => { setKind(value); setType(value === 'credential' ? 'key-auth' : value === 'target' ? 'targets' : 'services'); setAction('create'); setParentId(undefined); }} options={[{ value: 'entity', label: '网关资源' }, { value: 'credential', label: 'Consumer 凭证' }, { value: 'target', label: 'Upstream Target' }]} />
      {kind !== 'target' && <Select aria-label="变更对象类型" style={{ width: 190 }} value={type} onChange={setType} options={(kind === 'credential' ? credentials : entityTypes).map(value => ({ value, label: entityLabels[value] ?? value }))} />}
      <Select aria-label="变更操作" value={action} onChange={setAction} options={[{ value: 'create', label: '创建' }, { value: 'update', label: kind === 'target' ? '调整权重' : '编辑' }]} />
      <InputNumber aria-label="准备记录有效期小时" min={1} max={168} value={ttlHours} onChange={value => setTtl(value ?? 24)} suffix="小时" /></Space>
    {scheduleSupported && <Card size="small" style={{ marginBottom: 20 }} title={<Checkbox checked={scheduled} disabled={write.busy || !!write.attempt} onChange={event => { setScheduled(event.target.checked); setScheduleError(undefined); }}>定时变更</Checkbox>}>
      <Typography.Paragraph type="secondary">时间统一按 Asia/Shanghai（UTC+08:00）输入；发送时转换为 UTC。执行账号为当前账号，变更窗口包含开始时间、不包含结束时间。</Typography.Paragraph>
      {scheduled && <Space direction="vertical" style={{ width: '100%' }}>{(['notBefore', 'windowStart', 'windowEnd'] as const).map(field => <label key={field} style={{ display: 'block' }}>{{ notBefore: '计划执行时间', windowStart: '窗口开始时间', windowEnd: '窗口结束时间' }[field]}（Asia/Shanghai）<Input type="datetime-local" lang="zh-CN" step={60} aria-label={field === 'notBefore' ? '计划执行时间（上海）' : field === 'windowStart' ? '窗口开始时间（上海）' : '窗口结束时间（上海）'} value={scheduleInput[field]} disabled={write.busy || !!write.attempt} onChange={event => setScheduleInput(current => ({ ...current, [field]: event.target.value }))} /></label>)}<Typography.Text type="secondary">窗口结束须在工单有效期内；审批政策可以进一步限制有效期。</Typography.Text></Space>}
    </Card>}
    {!!scheduleError && <QueryError error={scheduleError} />}
    {kind !== 'entity' && <div style={{ marginBottom: 20 }}><ScopedEntityLookup type={kind === 'credential' ? 'consumers' : 'upstreams'} clusterId={scope.cid} workspaceId={scope.wid} value={parentId} onChange={setParentId} label="选择所属对象" /></div>}
    {action === 'update' && <div style={{ marginBottom: 20 }}><ScopedEntityLookup type={type} clusterId={scope.cid} workspaceId={scope.wid} parentId={parentId} value={nativeId} onChange={setNativeId}
      onSelected={kind === 'target' ? entity => setTargetSelection(entity && canonicalId(parentId) ? { identity: { ...write.identity }, upstreamId: parentId!, entity: structuredClone(entity) } : undefined) : undefined} label="选择变更对象" /></div>}
    {kind === 'target' && parentId && <Card size="small" title="Upstream → Target" style={{ marginBottom: 20 }}><Descriptions size="small" column={1} items={[
      { key: 'parent', label: 'Upstream', children: <Typography.Text className="mono">{parentId}</Typography.Text> },
      { key: 'target', label: 'Target', children: action === 'create' ? '新建 Target' : selectedTarget ? <>{selectedTarget.target}<div className="table-secondary mono">{selectedTarget.id}</div></> : '请选择当前 Target' },
      ...(selectedTarget ? [{ key: 'weight', label: '当前权重', children: selectedTarget.weight }] : []),
    ]} /></Card>}
    {write.attempt && <Alert showIcon type="warning" message="原准备请求需要核验，不能重新提交" description={<><div>原请求键：<Typography.Text className="mono" copyable>{write.attempt.key}</Typography.Text></div><div>请管理员在审计记录中核对原准备请求。</div></>} style={{ marginBottom: 20 }} />}
    {!!write.error && <QueryError error={write.error} />}{schema.error && <QueryError error={schema.error} />}{before.error && <QueryError error={before.error} />}{plugin.error && <QueryError error={plugin.error} />}
    {schema.isFetching || before.isFetching ? <Spin /> : renderedSchema && <KongSchemaForm schema={renderedSchema} form={form} editing={action === 'update'} entityType={type} onFinish={values => void prepare(values)} />}
  </Drawer>;
}

export function WorkflowIntentReview({ intentId, readonly = false }: { intentId: string; readonly?: boolean }) {
  const write = usePreparationWrite(intentId), scope = write.scope, navigate = useNavigate(), { modal } = App.useApp();
  const query = useQuery({ queryKey: ['workflow-intent', scope.cid, scope.wid, scope.actor, scope.version, intentId], queryFn: ({ signal }) => api<unknown>(scope.path(`entity-changes/${intentId}`), { signal }).then(normalizeEntityChangeIntent),
    enabled: scope.ready && !!canonicalId(intentId), retry: false, staleTime: 0, gcTime: 0, refetchInterval: 15000 });
  const intent = query.data, [selected, setSelected] = useState<EntityChangeIntent['review']['changes'][number]>();
  const submit = () => { if (!intent || intent.capabilities.submit !== true || intent.schedule && intent.capabilities.scheduleSubmit !== true || write.attempt || write.busy || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace) return;
    const identity = { ...write.identity }, originalId = intent.id, originalHmac = intent.materialHmac;
    mutationConfirm(modal, { title: '确认提交变更工单', expected: 'native-change', description: '提交封存的变更预览。审批与网关执行分别完成，不会在此自动执行。', onConfirm: async () => {
      write.assertCurrent(identity); const fresh = await query.refetch(); write.assertCurrent(identity);
      if (!fresh.data || fresh.data.id !== originalId || fresh.data.materialHmac !== originalHmac) throw new Error('变更预览已变化，请重新审阅。');
      const result = await write.write('submit', `entity-changes/${originalId}/submit`, entityChangeSubmitPayload(fresh.data), raw => {
        if (!raw || typeof raw !== 'object' || !canonicalId((raw as any).workflowId) || (raw as any).submissionCompleted !== true) throw new Error('提交回执不完整，请只读核验原准备记录。'); return (raw as any).workflowId as string;
      }); navigate(`/workflows/${result}`);
    } }); };
  return <>{query.error && <QueryError error={query.error} />}{!!write.error && <QueryError error={write.error} />}
    {write.attempt && <Alert type="warning" showIcon message="原提交结果尚需核验，不会重新提交" description={<>原请求键：<Typography.Text className="mono" copyable>{write.attempt.key}</Typography.Text>；刷新准备记录查看已登记的工单。</>} style={{ marginBottom: 20 }} />}
    {intent && <><Card title="变更预览" extra={<Space><Button onClick={() => void query.refetch()} loading={query.isFetching}>刷新</Button>{!readonly && (intent.workflowId ? <Link to={`/workflows/${intent.workflowId}`}>查看已提交工单</Link>
      : <Button type="primary" onClick={submit} disabled={write.busy || !!write.attempt || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace || intent.capabilities.submit !== true || intent.schedule && intent.capabilities.scheduleSubmit !== true || Date.parse(intent.expiresAt) <= Date.now()}>提交变更工单</Button>)}</Space>}>
      <Descriptions size="small" column={{ xs: 1, md: 2 }} items={[{ key: 'mode', label: '执行模式', children: intent.executionMode === 'approval' ? '工单审批' : '直接执行' }, { key: 'expiry', label: intent.schedule ? '有效期 · Asia/Shanghai' : '有效期', children: intent.schedule ? formatScheduleTime(intent.expiresAt) : formatTime(intent.expiresAt) },
        { key: 'changes', label: '变更对象', children: intent.review.impact.changedObjects }, { key: 'packets', label: '网关步骤', children: intent.review.impact.nativePackets }]} />
      {intent.schedule && <Alert type="info" showIcon message="定时变更预览 · Asia/Shanghai" description={<><p>计划执行：{formatScheduleTime(intent.schedule.notBefore)}</p><p>窗口：{formatScheduleTime(intent.schedule.windowStart)} 至 {formatScheduleTime(intent.schedule.windowEnd)}（不含结束时间）</p><p>执行账号：<code>{intent.schedule.executorId}</code>；提交审批后还需在<Link to={`/workflows?tab=schedules&schedule=${intent.schedule.id}`}>定时变更记录</Link>中显式激活。</p></>} style={{ marginTop: 16 }} />}
      {intent.review.recovery.blockerCodes.includes(targetHealthRollbackUnavailableReason) && <NativeRollbackNotice reason={targetHealthRollbackUnavailableReason} />}
      {!readonly && intent.review.recovery.blockerCodes.some(code => code !== 'EXECUTION_BASELINE_REQUIRED' && code !== targetHealthRollbackUnavailableReason) && <Alert type="warning" message="此变更存在安全执行限制" description="请核对恢复条件和当前权限。是否可以执行，以工单的最新状态为准。" style={{ marginTop: 16 }} />}
      {!readonly && intent.review.recovery.blockerCodes.includes('EXECUTION_BASELINE_REQUIRED') && <Alert type="info" message="执行前将保存恢复基线" style={{ marginTop: 16 }} />}
    </Card><Card title="逐对象变更" style={{ marginTop: 20 }}><Table rowKey={row => `${row.entityType}:${row.nativeId}`} dataSource={intent.review.changes} scroll={{ x: 720 }} pagination={{ pageSize: 20, showSizeChanger: false }} columns={[
      { title: '对象类型', dataIndex: 'entityType', render: type => entityLabels[type] ?? type }, { title: '操作', dataIndex: 'action', render: action => ({ create: '创建', update: '编辑', delete: '移入回收站', restore: '恢复' })[action as string] ?? action },
      { title: '对象 ID', dataIndex: 'nativeId', render: value => <Typography.Text className="mono" copyable>{value}</Typography.Text> }, { title: '配置差异', render: (_, row) => <Button type="link" onClick={() => setSelected(row)}>查看</Button> },
    ]} /></Card></>}
    <Drawer title="配置差异" open={!!selected} width={800} destroyOnHidden onClose={() => setSelected(undefined)}>{selected && <Space direction="vertical" style={{ width: '100%' }}><Card title="变更前"><pre className="json-preview">{JSON.stringify(selected.before, null, 2)}</pre></Card><Card title="变更后"><pre className="json-preview">{JSON.stringify(selected.after, null, 2)}</pre></Card></Space>}</Drawer>
  </>;
}

export function WorkflowNativeDetails({ workflow }: { workflow: Workflow }) {
  const history = workflow.nativeChange, baseline = history?.baseline, rollbackReason = nativeRollbackUnavailableReason(workflow);
  return <>{history?.intentId && <div style={{ marginTop: 20 }}><WorkflowIntentReview readonly intentId={history.intentId} /></div>}<Card title="变更进度" style={{ marginTop: 20 }}><Steps size="small" items={[
    { title: '准备', status: 'finish' }, { title: workflow.approvalRequired ? '审批' : '确认', status: !workflow.approvalRequired || ['approved', 'executing', 'succeeded', 'partial', 'uncertain', 'failed'].includes(workflow.state) ? 'finish' : workflow.state === 'rejected' ? 'error' : 'process' },
    { title: '执行', status: workflow.state === 'succeeded' ? 'finish' : ['failed', 'partial', 'uncertain'].includes(workflow.state) ? 'error' : workflow.state === 'executing' ? 'process' : 'wait' },
  ]} /></Card><Card title="执行前恢复基线" style={{ marginTop: 20 }}>{baseline ? <Descriptions size="small" column={{ xs: 1, md: 2 }} items={[
    { key: 'objects', label: '完整对象图', children: `${baseline.recovery.totalObjects} 个对象 / ${baseline.baseline.graphCount} 个对象图` }, { key: 'affected', label: '受影响对象', children: baseline.recovery.affectedObjects },
    { key: 'before', label: '已有 / 尚未创建', children: `${baseline.recovery.presentObjects} / ${baseline.recovery.absentObjects}` }, { key: 'retention', label: '恢复材料保护至', children: formatTime(baseline.baseline.protectedUntil) },
    { key: 'observed', label: '观察时间', children: `${formatTime(baseline.observedFrom)} — ${formatTime(baseline.observedUntil)}` },
  ]} /> : <Typography.Text type="secondary">尚未取得已持久化的执行前恢复基线。</Typography.Text>}{rollbackReason && <NativeRollbackNotice reason={rollbackReason} />}</Card>
    <Card title="网关逐步结果" style={{ marginTop: 20 }}><Table rowKey="key" dataSource={history?.packets ?? []} pagination={{ pageSize: 20, showSizeChanger: false }} scroll={{ x: 800 }} columns={[
      { title: '顺序', dataIndex: 'order', width: 70 }, { title: '对象', render: (_, packet) => <>{entityLabels[packet.entityType] ?? packet.entityType}{packet.entityId ? <div className="table-secondary"><EntityIdText id={packet.entityId} /></div> : null}</> },
      { title: '结果', dataIndex: 'state', render: state => <Tag color={state === 'succeeded' ? 'green' : ['uncertain', 'sent-unknown'].includes(state) ? 'orange' : undefined}>{({ succeeded: '已确认完成', 'native-rejected': '网关已拒绝', 'sent-unknown': '结果未知', 'rejected-before-send': '发送前拒绝', 'failed-known-not-sent': '未发送', not_sent: '未发送', uncertain: '待核验' } as Record<string, string>)[state] ?? state}</Tag> },
      { title: 'HTTP', dataIndex: 'nativeStatus', render: value => value ?? '—' }, { title: '操作回执', dataIndex: 'operationId', render: value => value ? <Typography.Text className="mono" copyable>{value}</Typography.Text> : '—' }, { title: '结果代码', dataIndex: 'errorCode', render: value => value ?? '—' },
    ]} /></Card></>;
}
export function NativeRollbackNotice({ reason }: { reason: string }) {
  return <Alert type="warning" showIcon message={reason === targetHealthRollbackUnavailableReason ? 'Target 健康置位不能自动回滚' : '此变更包含不可自动回滚的操作'}
    description={reason === targetHealthRollbackUnavailableReason ? '节点健康观测无法还原置位前的手动状态。此工单不支持准备回滚；如需调整，请发起新的健康置位变更。' : '此工单不支持准备回滚，请审阅操作的恢复限制。'} style={{ marginTop: 16 }} />;
}

export function WorkflowNativeControls({ workflow, onRefresh }: { workflow: Workflow; onRefresh: () => Promise<{ data?: Workflow }> }) {
  const write = usePreparationWrite(workflow.id), scope = write.scope, { modal } = App.useApp(), navigate = useNavigate();
  const [preflight, setPreflight] = useState<NativeChangePreflight>(), [error, setError] = useState<unknown>(), [checking, setChecking] = useState(false);
  const live = useRef(workflow); live.current = workflow;
  useEffect(() => { setPreflight(undefined); setError(undefined); }, [workflow.id, workflow.revision, workflow.planHash, scope.cid, scope.wid, scope.actor, scope.version]);
  const check = async () => {
    if (!nativeWorkflowCan(workflow, 'entityPreflight') || checking) return;
    const captured = { ...write.identity }, revision = workflow.revision, hash = workflow.planHash; setChecking(true); setError(undefined);
    try { write.assertCurrent(captured); const result = await api<any>(scope.path(`workflows/${workflow.id}/entity-preflight`)); write.assertCurrent(captured);
      if (live.current.revision !== revision || live.current.planHash !== hash || !nativeWorkflowCan(live.current, 'entityPreflight')) throw new Error('执行前检查结果不完整，请重新读取工单。');
      setPreflight(normalizeNativeChangePreflight(result));
    } catch (cause) { setError(cause); } finally { setChecking(false); }
  };
  const rollback = () => {
    if (!nativeWorkflowCan(workflow, 'rollbackPrepare') || preflight?.recoverable === false || write.attempt || write.busy || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace) return;
    const captured = { ...write.identity }, revision = workflow.revision, hash = workflow.planHash;
    mutationConfirm(modal, { title: '确认准备回滚工单', expected: 'native-change', description: '依据原执行前基线生成新的变更预览。新工单仍需确认和审批，不会在此立即回滚。', onConfirm: async () => {
      write.assertCurrent(captured); const refreshed = await onRefresh(); write.assertCurrent(captured); const fresh = refreshed.data;
      if (!fresh || fresh.id !== workflow.id || fresh.clusterId !== captured.cid || fresh.workspaceId !== captured.wid || fresh.revision !== revision || fresh.planHash !== hash) throw new Error('原执行记录已变化，请重新审阅。');
      const intent = await write.write('rollbackPrepare', `workflows/${workflow.id}/rollback-prepare`, nativeRollbackPayload(fresh), raw => {
        if (!raw || typeof raw !== 'object' || (raw as any).submissionRequired !== true || (raw as any).originalWorkflowId !== workflow.id) throw new Error('回滚准备回执不完整，请保留原请求键核验。');
        return normalizeEntityChangeIntent((raw as any).intent);
      }); navigate(`/workflows?tab=changes&intent=${intent.id}`);
    } });
  };
  return <Card title="执行前检查与回滚" style={{ marginTop: 20 }}><Space wrap>
    <Button loading={checking} disabled={!nativeWorkflowCan(workflow, 'entityPreflight') || checking || scope.workspace.readonlyWorkspace} onClick={() => void check()}>检查当前恢复条件</Button>
    <Button disabled={!nativeWorkflowCan(workflow, 'rollbackPrepare') || preflight?.recoverable === false || !!write.attempt || write.busy || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace} onClick={rollback}>准备回滚工单</Button>
  </Space>{preflight && (preflight.recoverable ? <Alert type="info" showIcon message={`当前恢复条件检查通过：${preflight.objects} 个对象、${preflight.graphs} 个对象图`} description="执行时将重新检查并保存恢复基线。" style={{ marginTop: 16 }} /> : <NativeRollbackNotice reason={preflight.rollbackUnavailableReason!} />)}
    {!preflight && nativeRollbackUnavailableReason(workflow) && <NativeRollbackNotice reason={nativeRollbackUnavailableReason(workflow)!} />}
    {write.attempt && <Alert type="warning" message="原回滚准备请求待核验，不能重新提交" description={<Typography.Text className="mono" copyable>{write.attempt.key}</Typography.Text>} style={{ marginTop: 16 }} />}
    {!!error && <QueryError error={error} />}{!!write.error && <QueryError error={write.error} />}
  </Card>;
}
