import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Collapse, Descriptions, Form, Input, Segmented, Select, Space, Table, Tabs, Tag, Typography } from 'antd';
import { abbreviateId, entityOptionLabel } from '../lib/abbreviate-id';
import { useQuery } from '@tanstack/react-query';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { api, ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { useAuth } from '../app/AuthContext';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { workflowMetadataReceiptPath, workflowMetadataRecoveryContextMatches, workflowMetadataRecoveryEligible, workflowMetadataRecoveryRequest, workflowMetadataRecoveryProvesCompletion, workflowIssueAbandonmentEligible, workflowIssueAbandonmentProvesCompletion, workflowIssueAbandonmentRequest, workflowTargetResultProvesCompletion, type WorkflowMetadataRecoveryReference } from '../api/workflow-recovery';
import { redactForDisplay } from '../api/redaction';
import { mutationConfirm } from '../components/MutationConfirm';
import { NoCluster, PageHeading, QueryError, formatTime } from '../components/Shared';
import { usePortalPage, usePortalScope } from './portal-hooks';
import { normalizeWorkflowDetail } from './portal.types';
import { controlWorkflowScopeMatches, controlWorkflowReadonlyWriteAllowed, controlWorkflowActionReceiptComplete, workflowDetailScopeMatches } from './control-workflow-scope.model';
import { portalStateLabels, type Workflow, type WorkflowMetadataRecoveryKind, type WorkflowReceipt } from './portal.types';
import { WorkflowPolicies } from './WorkflowPolicies';
import { WorkflowApprovalProgress } from './WorkflowApprovalProgress';
import { EntitySchedulesPage } from './EntitySchedulesPage';
import { WorkflowBusinessSchedulesPanel } from '../pages/WorkflowBusinessSchedulesPanel';
import { activeWorkflowStage, workflowDecisionPayload, workflowKindLabels } from './workflows.model';
import { WorkflowEntityChanges, WorkflowNativeControls, WorkflowNativeDetails, workflowIdentity } from './WorkflowEntityChanges';
import { clearWorkflowAttempt, workflowRejectionIsDefinitive, nativeWorkflowCan, readWorkflowAttempt, storeWorkflowAttempt, workflowActionReceiptComplete, workflowExecutionReceiptClosed, workflowCanPrepare, type WorkflowWriteAttempt } from './workflow-entity-change.model';
import { workflowBoardColumn, workflowBoardColumns, workflowOverdue } from './workflow-board.model';
import { workflowTargetResultOriginalReference, workflowTargetResultRecoveryReference, workflowTargetResultRecoveryRequest, workflowTargetResultReceiptPath, workflowTargetResultPacketObservation, type WorkflowTargetResultRecoveryReference } from './workflow-target-result-recovery.model';
function Pager({ query }: { query: { page: number; previous?: () => void; next?: () => void; isFetching: boolean } }) {
  return <div className="cursor-footer"><span>第 {query.page} 页</span><Space><Button disabled={!query.previous || query.isFetching} onClick={query.previous}>上一页</Button><Button disabled={!query.next || query.isFetching} onClick={query.next}>下一页</Button></Space></div>;
}
export function WorkflowsPage() {
  const scope = usePortalScope(), [params, setParams] = useSearchParams();
  const { user } = useAuth();
  const policiesReadable = scope.permission.can('workflows', 'read', undefined, { clusterId: scope.cid, workspaceId: scope.wid });
  const changesReadable = policiesReadable || workflowCanPrepare(user?.capabilities, workflowIdentity(scope));
  const schedulesReadable = scope.ready&&scope.permission.has('workflows', 'read');
  const tab = params.get('tab') === 'policies' && policiesReadable ? 'policies' : params.get('tab') === 'changes' && changesReadable ? 'changes' : params.get('tab') === 'schedules' && schedulesReadable ? 'schedules' : params.get('tab')==='business-schedules'&&schedulesReadable&&user?'business-schedules':'orders';
  if (!scope.cid) return <NoCluster />;
  return <><PageHeading title="变更审批" /><Tabs activeKey={tab} onChange={value => setParams(value === 'orders' ? {} : { tab: value })}
    items={[{ key: 'orders', label: '变更工单', children: <WorkflowOrders /> }, ...(changesReadable ? [{ key: 'changes', label: '发起变更', children: <WorkflowEntityChanges key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}`} /> }] : []), ...(schedulesReadable ? [{ key: 'schedules', label: '定时变更', children: <EntitySchedulesPage key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}`} /> }] : []), ...(schedulesReadable&&user&&scope.wid?[{key:'business-schedules',label:'业务排程',children:<WorkflowBusinessSchedulesPanel key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}`} clusterId={scope.cid} workspaceId={scope.wid} actor={user} readonly={scope.workspace.writeBlocked||scope.workspace.readonlyWorkspace}/>}]:[]), ...(policiesReadable ? [{ key: 'policies', label: '审批政策', children: <WorkflowPolicies key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}`} /> }] : [])]} destroyOnHidden />
  </>;
}
function WorkflowOrders() {
  const [state, setState] = useState(''), [mine, setMine] = useState('');
  const [display, setDisplay] = useState<'table' | 'board'>('table'), [now, setNow] = useState(Date.now);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 30_000); return () => window.clearInterval(timer); }, []);
  const filters = { ...(state ? { state } : {}), ...(mine ? { view: mine } : {}) }, query = usePortalPage<Workflow>('workflows', filters);
  return <><Space wrap className="list-toolbar"><Select aria-label="工单状态" style={{ width: 170 }} value={state} onChange={setState}
    options={[{ value: '', label: '全部状态' }, ...['pending', 'approved', 'executing', 'succeeded', 'partial', 'uncertain', 'failed', 'rejected', 'cancelled', 'expired'].map(value => ({ value, label: portalStateLabels[value] }))]} />
    <Select aria-label="我的工单" style={{ width: 160 }} value={mine} onChange={setMine} options={[{ value: '', label: '当前授权范围' }, { value: 'submitted', label: '我提交的' }, { value: 'pending-my-approval', label: '待我审批' }]} />
    <Button onClick={() => void query.refetch()}>刷新</Button>
    <Segmented aria-label="工单展示方式" value={display} onChange={value => setDisplay(value as 'table' | 'board')} options={[{ value: 'table', label: '列表' }, { value: 'board', label: '看板' }]} />
    </Space>{query.error && <QueryError error={query.error} />}
    {display === 'table' ? <Table data-testid="workflow-list" rowKey="id" pagination={false} loading={query.isFetching} dataSource={query.data?.items ?? []} scroll={{ x: 900 }} columns={[
      { title: '工单', render: (_, row) => <Link to={`/workflows/${row.id}`}>{workflowKindLabels[row.kind] ?? row.name} · <span className="mono" title={row.id}>{abbreviateId(row.id)}</span></Link> },
      { title: '执行模式', render: (_, row) => row.approvalRequired ? '工单审批' : '直接执行' },
      { title: '状态', render: (_, row) => <Space size={4}><Tag>{portalStateLabels[row.state] ?? row.state}</Tag>{workflowOverdue(row, now) && <Tag color="warning">已逾期</Tag>}</Space> },
      { title: '审批进度', render: (_, row) => workflowListProgress(row) },
      { title: '提交时间', render: (_, row) => formatTime(row.createdAt) },
    ]} /> : <div data-testid="workflow-board" aria-busy={query.isFetching}>
      <Typography.Text type="secondary">第 {query.page} 页工单</Typography.Text>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', alignItems: 'start', gap: 16, marginTop: 12 }}>
        {workflowBoardColumns.map(column => {
          const rows = (query.data?.items ?? []).filter(row => workflowBoardColumn(row.state) === column.key);
          return <Card key={column.key} size="small" title={<Space>{column.title}<Tag>{rows.length}</Tag></Space>}>
            <div className="workflow-board-column-list" tabIndex={0} aria-label={`${column.title}工单列表`}><Space direction="vertical" size={12} style={{ width: '100%' }}>
              {rows.map(row => <Card key={row.id} size="small">
                <Link to={`/workflows/${row.id}`}>{workflowKindLabels[row.kind] ?? row.name} · <span className="mono" title={row.id}>{abbreviateId(row.id)}</span></Link>
                <div style={{ marginTop: 8 }}><Tag>{portalStateLabels[row.state] ?? row.state}</Tag>{workflowOverdue(row, now) && <Tag color="warning">已逾期</Tag>}</div>
                <Typography.Text type="secondary">{formatTime(row.createdAt)}</Typography.Text>
              </Card>)}
              {!rows.length && <Typography.Text type="secondary">本页暂无工单</Typography.Text>}
            </Space></div>
          </Card>;
        })}
      </div>
    </div>}<Pager query={query} />
  </>;
}
export function WorkflowDetailPage() {
  const { id } = useParams(), selectedScope = usePortalScope(), [scopeParams] = useSearchParams(), { modal, message } = App.useApp();
  const lookupWid = canonicalId(scopeParams.get('workspaceId')) ?? selectedScope.wid;
  // A URL is a lookup selector only. The detail below must prove this exact
  // fixed Control selector before it can survive a deleted-workspace fallback.
  const scope = { ...selectedScope, wid: lookupWid, ready: !!selectedScope.cid && !!lookupWid,
    path: (resource: string) => scopeQuery(`/clusters/${selectedScope.cid}/${resource}`, selectedScope.cid, lookupWid),
    workspace: { ...selectedScope.workspace,
      readonlyWorkspace: selectedScope.wid !== lookupWid || selectedScope.workspace.readonlyWorkspace,
      writeBlocked: selectedScope.workspace.references.some(item => item.cid === selectedScope.cid && item.wid === lookupWid) } };

  const {user}=useAuth();
  const [error, setError] = useState<unknown>(), [reason, setReason] = useState(''), [busy, setBusy] = useState(false);
  const query = useQuery({ queryKey: ['workflow-detail', scope.cid, scope.wid, scope.actor, scope.version, id],
    queryFn: async ({ signal }) => { const row = normalizeWorkflowDetail(await api<any>(scope.path(`workflows/${id}`), { signal })); if (row.id !== id || !workflowDetailScopeMatches(row, scope.cid, scope.wid, selectedScope.wid)) throw new Error('工单响应范围不匹配。'); return row; }, enabled: scope.ready && !!canonicalId(id), retry: false, staleTime: 0, gcTime: 0, refetchInterval: 15_000 });
  const identityKey = JSON.stringify([scope.actor, scope.cid, scope.wid, id]), identity = workflowIdentity(scope);
  const [attemptState, setAttemptState] = useState<{ identityKey: string; attempt?: WorkflowWriteAttempt }>({ identityKey, attempt: scope.ready && id ? readWorkflowAttempt(identity, id) : undefined });
  const attempt = attemptState.identityKey === identityKey ? attemptState.attempt : scope.ready && id ? readWorkflowAttempt(identity, id) : undefined;
  const row = query.data, fixedMetadata = controlWorkflowReadonlyWriteAllowed(row, scope.cid, scope.wid), blocked = busy || !!attempt || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace && !fixedMetadata;
  const stage = row ? activeWorkflowStage(row) : undefined, canVote = !row?.approval || row.approval.format !== 2 || !!stage;
  const live = useRef({ scope, row, mounted: true }); live.current = { scope, row, mounted: live.current.mounted };
  useEffect(() => { live.current.mounted = true; return () => { live.current.mounted = false; }; }, []);
  useEffect(() => { setReason(''); setError(undefined); setAttemptState({ identityKey, attempt: scope.ready && id ? readWorkflowAttempt(identity, id) : undefined }); }, [scope.cid, scope.wid, scope.actor, scope.version, id]);
  const releaseAttempt = (original: WorkflowWriteAttempt) => {
    clearWorkflowAttempt(original); setAttemptState({ identityKey, attempt: undefined });
    for (const reference of scope.workspace.references) if (reference.actor_id === original.actor && reference.cid === original.cid && reference.wid === original.wid && reference.kind === 'workflow' && reference.idempotencyKey === original.key) scope.workspace.resolveReference(reference);
  };
  async function verifyAttempt() {
    if (!attempt || !row || busy) return;
    const original = { ...attempt }, current = { ...identity }; setBusy(true); setError(undefined);
    try {
      const receipt = await api<unknown>(scope.path(`workflows/receipts/by-key/${original.key}`));
      if (!live.current.mounted || getApiActorId() !== current.actor || live.current.scope.actor !== current.actor || live.current.scope.version !== current.version || live.current.scope.cid !== current.cid || live.current.scope.wid !== current.wid) throw new ApiError('当前范围已变化。', 409, 'WORKFLOW_SCOPE_CHANGED');
      const fresh = await query.refetch();
      if (!live.current.mounted || getApiActorId() !== current.actor || live.current.scope.actor !== current.actor || live.current.scope.version !== current.version || live.current.scope.cid !== current.cid || live.current.scope.wid !== current.wid) throw new ApiError('当前范围已变化。', 409, 'WORKFLOW_SCOPE_CHANGED');
      const targetUnknown = original.action === 'execute' && row.kind === 'native-change' && row.nativeChange?.packets.some(packet => packet.entityType === 'targets' && ['sent-unknown', 'uncertain'].includes(packet.state) && packet.nativeStatus === null);
      const targetReference = targetUnknown ? workflowTargetResultOriginalReference(row,
        { authenticatedActorId: getApiActorId(), identity: current, readonlyWorkspace: scope.workspace.readonlyWorkspace }, original) : undefined;
      const completed = targetUnknown ? !!targetReference && !!fresh.data && workflowTargetResultProvesCompletion(receipt, fresh.data, targetReference)
        : (row.kind === 'control-metadata' ? controlWorkflowActionReceiptComplete(receipt, original, row) : workflowActionReceiptComplete(receipt, original)) || fresh.data && workflowExecutionReceiptClosed(receipt, original, fresh.data);
      if (completed) { releaseAttempt(original); void message.success('原请求记录已核验，请核对工单最新结果'); }
      else throw new Error('原回执尚未证明此请求已完成或执行已闭合，不会重新发送。');
    } catch (cause) { if (live.current.mounted) setError(cause); } finally { if (live.current.mounted) setBusy(false); }
  }
  function act(action: 'approve' | 'reject' | 'cancel' | 'execute') {
    if (!row || row.capabilities?.[action] !== true || blocked || action === 'execute' && row.kind === 'native-change' && !nativeWorkflowCan(row, 'execute') || ['approve', 'reject'].includes(action) && !canVote) return;
    if (action === 'reject' && !reason.trim()) { void message.warning('请填写驳回原因'); return; }
    const original = { actor: scope.actor, version: scope.version, cid: scope.cid, wid: scope.wid, id: row.id, revision: row.revision, hash: row.planHash }, decisionReason = reason;
    const assertCurrent = (checkRevision = true) => {
      const now = live.current;
      if (!now.mounted || getApiActorId() !== original.actor || now.scope.actor !== original.actor || (checkRevision || !controlWorkflowScopeMatches(now.row, now.scope.cid, now.scope.wid)) && now.scope.version !== original.version || now.scope.cid !== original.cid || now.scope.wid !== original.wid
        || now.row?.id !== original.id || checkRevision && now.row.revision !== original.revision || now.row.planHash !== original.hash || checkRevision && now.scope.workspace.writeBlocked || now.scope.workspace.readonlyWorkspace && !(checkRevision ? controlWorkflowReadonlyWriteAllowed(now.row, now.scope.cid, now.scope.wid) : controlWorkflowScopeMatches(now.row, now.scope.cid, now.scope.wid)))
        throw new ApiError('账号、权限、范围或审批版本已变化，请重新审阅工单。', 409, 'WORKFLOW_SCOPE_CHANGED');
    };
    mutationConfirm(modal, { title: ({ approve: '确认批准当前审批阶段', reject: '确认驳回变更', cancel: '确认撤销变更', execute: '确认执行变更' })[action], expected: row.name, danger: action !== 'approve',
      description: action === 'approve' ? '保存当前阶段的审批决定；全部阶段通过后，由具备执行权限的账号单独执行。' : action === 'execute' ? '按已确认的不可变计划执行。结果未知时先核验原回执。' : '审批与撤销记录将追加保留。',
      onConfirm: async () => {
        try {
          assertCurrent(); setBusy(true); setError(undefined);
          const refreshed = await query.refetch(); assertCurrent(); const fresh = refreshed.data;
          if (!fresh || fresh.revision !== original.revision || fresh.planHash !== original.hash || fresh.capabilities?.[action] !== true || action === 'execute' && fresh.kind === 'native-change' && !nativeWorkflowCan(fresh, 'execute')) throw new Error('工单状态或当前操作资格已变化，请刷新后重试。');
          const payload = action === 'approve' || action === 'reject' ? workflowDecisionPayload(fresh, action, decisionReason)
            : { revision: fresh.revision, ...(action === 'execute' ? { planHash: fresh.planHash } : {}), confirmed: true, confirm_name: fresh.name };
          const reference: WorkflowWriteAttempt = { ...identity, subject: original.id, action, key: newIdempotencyKey(), revision: original.revision, planHash: original.hash, state: 'pending' };
          if (readWorkflowAttempt(identity, original.id)) throw new Error('原请求需要核验，不能重新提交。');
          storeWorkflowAttempt(reference); setAttemptState({ identityKey, attempt: reference });
          try {
            try { await api(scope.path(`workflows/${original.id}/${action}`), { method: 'POST', body: JSON.stringify(payload), headers: { 'X-Idempotency-Key': reference.key } }, fresh.kind === 'control-metadata'); }
            catch (rejected) { if (workflowRejectionIsDefinitive(rejected)) { releaseAttempt(reference); throw Object.assign(rejected as object, { definitiveRejection: true, recovery: undefined }); } throw rejected; }
            assertCurrent(false); const receipt = await api<unknown>(scope.path(`workflows/receipts/by-key/${reference.key}`)); assertCurrent(false);
            if (!(fresh.kind === 'control-metadata' ? controlWorkflowActionReceiptComplete(receipt, reference, fresh) : workflowActionReceiptComplete(receipt, reference))) throw new Error('请求已返回，原回执仍未证明完成，请只读核验。');
            releaseAttempt(reference);
          } catch (cause) { if ((cause as { definitiveRejection?: boolean })?.definitiveRejection) throw cause; const retained = { ...reference, state: cause instanceof ApiError && cause.status > 0 && cause.status < 500 && !/UNKNOWN|UNCERTAIN/.test(cause.code ?? '') ? 'failed' as const : 'unknown' as const }; storeWorkflowAttempt(retained); setAttemptState({ identityKey, attempt: retained }); throw cause; }
          if (live.current.mounted && live.current.scope.actor === original.actor && live.current.scope.cid === original.cid && live.current.scope.wid === original.wid) { await query.refetch(); void message.success(action === 'approve' || action === 'reject' ? '当前审批决定已保存' : '操作已处理，请核对最新状态'); }
        } catch (cause) { if (live.current.mounted) setError(cause); throw cause; }
        finally { if (live.current.mounted) setBusy(false); }
      } });
  }
  if (!scope.cid) return <NoCluster />;
  return <><Link to="/workflows">← 变更审批</Link><PageHeading title={row ? workflowKindLabels[row.kind] ?? row.name : '工单详情'} extra={<Button loading={query.isFetching} onClick={() => void query.refetch()}>刷新状态</Button>} />
    {query.error && <QueryError error={query.error} />}{!!error && <QueryError error={error} />}{row && <>
      <Descriptions bordered size="small" column={{ xs: 1, md: 2 }} items={[{ key: 'id', label: '工单 ID', children: <Typography.Text className="mono" copyable>{row.id}</Typography.Text> },
        { key: 'state', label: '状态', children: <Tag data-testid="workflow-state">{portalStateLabels[row.state] ?? row.state}</Tag> }, { key: 'mode', label: '执行模式', children: row.approvalRequired ? '工单审批' : '直接执行' },
        { key: 'revision', label: '计划版本', children: row.planRevision }, { key: 'expiry', label: '工单有效期', children: formatTime(row.expiresAt) }, { key: 'hash', label: '计划指纹', children: <Typography.Text className="mono" copyable>{row.planHash}</Typography.Text> }]} />
      <WorkflowApprovalProgress workflow={row} />
      {user&&scope.ready&&scope.wid&&['configuration_v2','portal-credential-issue'].includes(row.kind)&&<WorkflowBusinessSchedulesPanel key={`business:${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}:${row.id}`} clusterId={scope.cid} workspaceId={scope.wid} actor={user} workflowDetail={row} readonly={blocked} onChanged={async()=>{await query.refetch();}}/>}
      {row.kind === 'native-change' && <><WorkflowNativeDetails workflow={row} /><WorkflowNativeControls workflow={row} onRefresh={() => query.refetch()} /></>}
      {attempt && <Alert type="warning" showIcon message="原操作需要核验，禁止重新提交" description={<Space wrap><Typography.Text className="mono" copyable>{attempt.key}</Typography.Text><Button loading={busy} onClick={() => void verifyAttempt()}>只读核验原请求</Button></Space>} style={{ marginTop: 20 }} />}
      {row.kind === 'native-change' && <WorkflowTargetResultRecovery key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}:${row.id}`} workflow={row} onComplete={async () => { setAttemptState({ identityKey, attempt: undefined }); await query.refetch(); }} />}
      {['partial', 'uncertain', 'executing'].includes(row.state) && <Alert type="warning" showIcon message="当前变更尚未得到完整执行证明" description="先核验原操作回执，不会自动重发步骤。部分完成可能已改变网关配置。" style={{ marginTop: 20 }} />}
      {(row.kind === 'portal-credential-issue' && row.state === 'uncertain' || row.kind === 'workspace-migration' && ['uncertain', 'partial'].includes(row.state)) && <WorkflowMetadataRecovery key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}:${row.id}:${row.revision}`} workflow={row} sourceError={error} onComplete={() => query.refetch()} />}
      {row.kind === 'portal-credential-issue' && row.state === 'failed' && <WorkflowIssueAbandonment key={`${scope.cid}:${scope.wid}:${scope.actor}:${scope.version}:${row.id}:${row.revision}`} workflow={row} sourceError={error} onComplete={() => query.refetch()} />}
      {row.kind === 'native-change' ? <Collapse style={{ marginTop: 22 }} items={[{ key: 'plan', label: '计划与影响详情', children: <pre className="json-preview">{JSON.stringify(redactForDisplay(row.plan ?? { diff: row.diff, impact: row.impact, steps: row.steps }), null, 2)}</pre> }]} /> : <Card title="变更计划与影响" style={{ marginTop: 22 }}><pre className="json-preview">{JSON.stringify(redactForDisplay(row.plan ?? { diff: row.diff, impact: row.impact, steps: row.steps }), null, 2)}</pre></Card>}
      {row.snapshot && <Card title="执行前快照与回滚记录" style={{ marginTop: 20 }}><pre className="json-preview">{JSON.stringify(redactForDisplay(row.snapshot), null, 2)}</pre></Card>}
      {(['approve', 'reject', 'execute', 'cancel'] as const).some(action => row.capabilities?.[action] === true) && <Card title="审批操作" style={{ marginTop: 20 }}>{(row.capabilities?.approve === true || row.capabilities?.reject === true) && <Input.TextArea aria-label="审批原因" value={reason} onChange={event => setReason(event.target.value)} rows={3} maxLength={2048} placeholder="审批 / 驳回原因" />}
        <Space wrap style={{ marginTop: 16 }}>{row.capabilities?.approve === true && row.approvalRequired && <Button type="primary" disabled={blocked || !canVote} loading={busy} onClick={() => act('approve')}>{stage ? `批准第 ${stage.level} 阶段` : '批准变更'}</Button>}
          {row.capabilities?.reject === true && <Button danger disabled={blocked || !canVote} onClick={() => act('reject')}>驳回变更</Button>}
          {row.capabilities?.execute === true && <Button type="primary" disabled={blocked || row.kind === 'native-change' && !nativeWorkflowCan(row, 'execute')} onClick={() => act('execute')}>执行已确认计划</Button>}
          {row.capabilities?.cancel === true && <Button disabled={blocked} onClick={() => act('cancel')}>撤销工单</Button>}
        </Space></Card>}
      {(row.events || row.decisions) && (row.kind === 'native-change' ? <Collapse style={{ marginTop: 20 }} items={[{ key: 'decisions', label: '审批与执行明细', children: <pre className="json-preview">{JSON.stringify(redactForDisplay(row.events ?? row.decisions), null, 2)}</pre> }]} /> : <Card title="审批与执行记录" style={{ marginTop: 20 }}><pre className="json-preview">{JSON.stringify(redactForDisplay(row.events ?? row.decisions), null, 2)}</pre></Card>)}
    </>}
  </>;
}
export { Pager as PortalPager };

export function WorkflowTargetResultRecovery({ workflow, onComplete }: { workflow: Workflow; onComplete: () => Promise<unknown> }) {
  const scope = usePortalScope(), { modal, message } = App.useApp(), identity = workflowIdentity(scope);
  const context = { authenticatedActorId: getApiActorId(), identity, readonlyWorkspace: scope.workspace.readonlyWorkspace };
  const attempt = readWorkflowAttempt(identity, workflow.id), locator = workflowTargetResultOriginalReference(workflow, context, attempt);
  const [verified, setVerified] = useState<{ reference: WorkflowTargetResultRecoveryReference; receipt: WorkflowReceipt }>();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>();
  const live = useRef({ scope, workflow }), alive = useRef(true), pending = useRef<AbortController>();
  const working = useRef(false), dialogOpen = useRef(false);
  live.current = { scope, workflow };
  useEffect(() => { alive.current = true; return () => { alive.current = false; pending.current?.abort(); }; }, []);
  useEffect(() => { setVerified(undefined); setError(undefined); }, [scope.actor, scope.version, scope.cid, scope.wid, workflow.id, workflow.revision, workflow.planHash]);
  const packet = workflow.nativeChange?.packets.length === 1 ? workflow.nativeChange.packets[0] : undefined;
  const observation = packet?.targetResultObservation, known = packet && workflowTargetResultPacketObservation(packet).observationKnown;
  const anotherWrite = scope.workspace.references.some(item => item.cid === scope.cid && item.wid === scope.wid && item.idempotencyKey !== locator?.originalExecutionKey);
  const unknownBlockWithoutOriginal = scope.workspace.writeBlocked && !scope.workspace.references.some(item => item.actor_id === scope.actor
    && item.cid === scope.cid && item.wid === scope.wid && item.kind === 'workflow' && item.idempotencyKey === locator?.originalExecutionKey);
  const eligible = !anotherWrite && !unknownBlockWithoutOriginal && scope.permission.has('workflows', 'write') && !!verified && !!workflowTargetResultRecoveryReference(workflow, context, attempt, verified.receipt);
  const mayRead = !!locator && (scope.permission.has('workflows', 'read') || scope.permission.has('workflows', 'write'));
  function assertCurrent(reference: WorkflowTargetResultRecoveryReference, forWrite = false) {
    const now = live.current, currentIdentity = workflowIdentity(now.scope), retained = readWorkflowAttempt(currentIdentity, reference.workflowId);
    if (!alive.current || getApiActorId() !== reference.actorId || currentIdentity.actor !== reference.actorId
      || currentIdentity.version !== reference.permissionsVersion || currentIdentity.cid !== reference.clusterId || currentIdentity.wid !== reference.workspaceId
      || now.workflow.id !== reference.workflowId || now.workflow.planHash !== reference.planHash || now.workflow.planRevision !== reference.planRevision
      || now.workflow.nativeChange?.executionId !== reference.executionId || now.workflow.revision !== reference.workflowRevision
        && !(now.workflow.state === 'succeeded' && now.workflow.revision === reference.workflowRevision + 1)
      || !retained || retained.action !== 'execute' || retained.key !== reference.originalExecutionKey || retained.planHash !== reference.planHash
      || forWrite && (now.scope.workspace.readonlyWorkspace || !now.scope.permission.has('workflows', 'write')
        || now.scope.workspace.writeBlocked && !now.scope.workspace.references.some(item => item.actor_id === reference.actorId && item.cid === reference.clusterId
          && item.wid === reference.workspaceId && item.kind === 'workflow' && item.idempotencyKey === reference.originalExecutionKey)
        || now.scope.workspace.references.some(item => item.cid === reference.clusterId
        && item.wid === reference.workspaceId && item.idempotencyKey !== reference.originalExecutionKey)))
      throw new ApiError('账号、权限、范围或原执行记录已变化，请重新核验。', 409, 'WORKFLOW_SCOPE_CHANGED');
    return retained;
  }
  async function read(reference: WorkflowTargetResultRecoveryReference, kind: 'detail' | 'receipt') {
    assertCurrent(reference); pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    const value = await api<unknown>(kind === 'receipt' ? workflowTargetResultReceiptPath(reference)
      : scopeQuery(`/clusters/${reference.clusterId}/workflows/${reference.workflowId}`, reference.clusterId, reference.workspaceId), { signal: controller.signal });
    assertCurrent(reference); return value;
  }
  async function finish(reference: WorkflowTargetResultRecoveryReference, detail: Workflow, receipt: unknown) {
    if (!workflowTargetResultProvesCompletion(receipt, detail, reference)) throw new Error('原执行及新核验记录尚未提供完整完成证明，请保留原执行键。');
    const retained = assertCurrent(reference); clearWorkflowAttempt(retained);
    const saved = live.current.scope.workspace.references.find(item => item.actor_id === reference.actorId && item.cid === reference.clusterId
      && item.wid === reference.workspaceId && item.kind === 'workflow' && item.idempotencyKey === reference.originalExecutionKey);
    if (saved) live.current.scope.workspace.resolveReference(saved);
    window.dispatchEvent(new CustomEvent('kongos:receipt-verified', { detail: { kind: 'workflow', cid: reference.clusterId, wid: reference.workspaceId,
      idempotencyKey: reference.originalExecutionKey, completed: true, state: 'succeeded' } }));
    setVerified(undefined); void message.success('原 Target 结果已核验');
    try { await onComplete(); } catch (cause) { if (alive.current) setError(cause); }
  }
  async function verify() {
    if (!locator || !mayRead || working.current) return;
    const original = locator; working.current = true; setBusy(true); setError(undefined); setVerified(undefined);
    try {
      const detail = normalizeWorkflowDetail(await read(original, 'detail')), receipt = await read(original, 'receipt');
      if (workflowTargetResultProvesCompletion(receipt, detail, original)) { await finish(original, detail, receipt); return; }
      const reference = workflowTargetResultRecoveryReference(detail, context, assertCurrent(original), receipt);
      if (!reference || reference.workflowRevision !== original.workflowRevision) throw new Error('当前原执行回执不符合 Target 结果核验条件。');
      setVerified({ reference, receipt: receipt as WorkflowReceipt });
    } catch (cause) { if (alive.current) setError(cause); }
    finally { working.current = false; if (alive.current) setBusy(false); }
  }
  function reconcile() {
    if (!eligible || !verified || working.current || dialogOpen.current) return;
    const original = verified.reference; dialogOpen.current = true;
    const controlledModal = { confirm: (options: any) => modal.confirm({ ...options, onCancel: () => { dialogOpen.current = false; options.onCancel?.(); } }) };
    mutationConfirm(controlledModal, { title: '确认核验原 Target 结果', expected: 'native-change', danger: false,
      description: '沿用原执行键，只追加结果核验记录。服务端重新验证原回执、审批和当前授权，不会重新发送网关变更。',
      onConfirm: async () => {
        if (working.current) throw new Error('原请求仍在核验中。');
        working.current = true; setBusy(true); setError(undefined); setVerified(undefined);
        let posted = false;
        try {
          assertCurrent(original, true);
          const detail = normalizeWorkflowDetail(await read(original, 'detail')), receipt = await read(original, 'receipt');
          const now = live.current.scope, request = workflowTargetResultRecoveryRequest(original, detail,
            { authenticatedActorId: getApiActorId(), identity: workflowIdentity(now), readonlyWorkspace: now.workspace.readonlyWorkspace }, receipt,
            { confirmed: true, confirmName: 'native-change' });
          // This is one confirmed metadata request. A 401 must close it rather
          // than silently refreshing the session and reissuing its POST.
          assertCurrent(original, true); await api(request.path, request.options, true); posted = true;
          const finalDetail = normalizeWorkflowDetail(await read(original, 'detail')), finalReceipt = await read(original, 'receipt');
          await finish(original, finalDetail, finalReceipt);
        } catch (cause) {
          const error = posted ? new ApiError('核验响应已收到，原执行终态仍待确认。请保留原键继续只读核验。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined,
            { kind: 'workflow', clusterId: original.clusterId, workspaceId: original.workspaceId, idempotencyKey: original.originalExecutionKey, state: 'uncertain' }) : cause;
          if (posted && alive.current && getApiActorId() === original.actorId) window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: original.actorId, error } }));
          if (alive.current) setError(error); throw error;
        } finally { working.current = false; dialogOpen.current = false; if (alive.current) setBusy(false); }
      } });
  }
  if (!packet || packet.entityType !== 'targets' || !workflow.nativeChange?.targetResultReconciliationAvailable && !known && !locator) return null;
  return <Card title="Target 结果核验" style={{ marginTop: 20 }} data-testid="workflow-target-result-recovery">
    {known && observation && <Alert type="success" showIcon message="原结果已核验" description={<span>原网关回执状态与 HTTP 记录保留不变。核验记录：<code>{observation.id}</code> · {formatTime(observation.observedAt)}</span>} style={{ marginBottom: 16 }} />}
    {!!error && <QueryError error={error} />}
    {locator ? <><Typography.Paragraph>原执行键：<Typography.Text className="mono" copyable>{locator.originalExecutionKey}</Typography.Text></Typography.Paragraph>
      <Space wrap><Button loading={busy} disabled={!mayRead || busy} onClick={() => void verify()}>核验原 Target 回执</Button>
        <Button type="primary" disabled={!eligible || busy} onClick={reconcile}>仅核验结果元数据</Button></Space></>
      : !known && <Typography.Text type="secondary">当前浏览器未保留原执行键，请返回原操作窗口核验。</Typography.Text>}
    {anotherWrite && locator && <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>当前范围另有待核验写入，请先核验其原操作。</Typography.Paragraph>}
  </Card>;
}

export function WorkflowMetadataRecovery({ workflow, sourceError, onComplete }: { workflow: Workflow; sourceError: unknown; onComplete: () => Promise<unknown> }) {
  const scope = usePortalScope(), { modal, message } = App.useApp();
  const migration = workflow.kind === 'workspace-migration', kind: WorkflowMetadataRecoveryKind = migration ? 'workspace-migration' : 'portal-credential-issue';
  const supported = workflow.kind === kind && workflow.name === kind;
  const recovery = sourceError instanceof ApiError ? sourceError.recovery : undefined;
  const retained = scope.workspace.references.filter(item => item.kind === 'workflow' && item.actor_id === scope.actor && item.cid === scope.cid && item.wid === scope.wid);
  const originalKey = recovery?.kind === 'workflow' && recovery.clusterId === scope.cid && recovery.workspaceId === scope.wid && canonicalId(recovery.idempotencyKey)
    ? recovery.idempotencyKey! : retained.length === 1 ? retained[0].idempotencyKey : '';
  const [key, setKey] = useState(originalKey), [receipt, setReceipt] = useState<WorkflowReceipt>(), [error, setError] = useState<unknown>(), [busy, setBusy] = useState(false);
  const alive = useRef(true), pending = useRef<AbortController>();
  const current = useRef({ actorId: scope.actor ?? '', clusterId: scope.cid ?? '', workspaceId: scope.wid ?? '', workflowId: workflow.id, permissionsVersion: scope.version ?? '', idempotencyKey: key, kind: workflow.kind, revision: workflow.revision, planHash: workflow.planHash });
  current.current = { actorId: scope.actor ?? '', clusterId: scope.cid ?? '', workspaceId: scope.wid ?? '', workflowId: workflow.id, permissionsVersion: scope.version ?? '', idempotencyKey: key, kind: workflow.kind, revision: workflow.revision, planHash: workflow.planHash };
  useEffect(() => { alive.current = true; return () => { alive.current = false; pending.current?.abort(); }; }, []);
  useEffect(() => { if (originalKey) { setKey(originalKey); setReceipt(undefined); } }, [originalKey]);
  const reference: WorkflowMetadataRecoveryReference = { ...current.current, idempotencyKey: key };
  const mayRead = supported && scope.permission.has('workflows', 'write');
  const allowed = mayRead && workflow.capabilities?.reconcileMetadata === true && !scope.workspace.readonlyWorkspace;
  const anotherUncertainWrite = scope.workspace.references.some(item => item.cid === scope.cid && item.wid === scope.wid && item.idempotencyKey !== key);
  const eligible = allowed && !anotherUncertainWrite && workflowMetadataRecoveryEligible(receipt, workflow, reference);
  function assertCurrent(original: WorkflowMetadataRecoveryReference) {
    if (!alive.current || getApiActorId() !== original.actorId || original.idempotencyKey !== current.current.idempotencyKey
      || current.current.kind !== kind || current.current.revision !== workflow.revision || current.current.planHash !== workflow.planHash
      || !workflowMetadataRecoveryContextMatches(original, current.current)) throw new ApiError('账号、工作区、权限或原执行记录已变化，请重新核验原执行回执。', 401, 'SESSION_CHANGED');
  }
  async function read(original: WorkflowMetadataRecoveryReference) {
    assertCurrent(original); pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    const value = await api<WorkflowReceipt>(workflowMetadataReceiptPath(original), { signal: controller.signal }); assertCurrent(original); return value;
  }
  function release(original: WorkflowMetadataRecoveryReference) {
    const saved = scope.workspace.references.find(item => item.actor_id === original.actorId && item.cid === original.clusterId && item.wid === original.workspaceId && item.kind === 'workflow' && item.idempotencyKey === original.idempotencyKey);
    if (saved) scope.workspace.resolveReference(saved);
    window.dispatchEvent(new CustomEvent('kongos:receipt-verified', { detail: { kind: 'workflow', cid: original.clusterId, wid: original.workspaceId, idempotencyKey: original.idempotencyKey, completed: true, state: 'succeeded' } }));
  }
  async function verify() {
    const original = { ...reference }; setBusy(true); setError(undefined); setReceipt(undefined);
    try {
      const value = await read(original);
      if (value.executionId && workflowMetadataRecoveryProvesCompletion(value, original, value.executionId, kind, workflow.planHash)) {
        release(original); void message.success('原执行已完整完成'); await onComplete(); return;
      }
      if (!workflowMetadataRecoveryEligible(value, workflow, original)) throw new ApiError(migration
        ? '原回执未证明工作区迁移全部完成且仅剩工单元数据待对账，请保留原执行键核验。'
        : '原回执不符合恢复条件：需要当前原执行人、三个已确认原生步骤和仅剩不确定的门户元数据步骤。', 409, migration ? 'MIGRATION_RECOVERY_NOT_ELIGIBLE' : 'PORTAL_RECOVERY_NOT_ELIGIBLE');
      setReceipt(value);
    } catch (e) { if (alive.current) setError(e); }
    finally { if (alive.current) setBusy(false); }
  }
  function reconcile() {
    if (!eligible || !receipt) return;
    const original = { ...reference }, executionId = receipt.executionId!;
    mutationConfirm(modal, {
      title: migration ? '确认对账已完成的工作区迁移' : '只提交已创建凭证的门户元数据', expected: kind, danger: false,
      description: migration
        ? '只将已完整确认的工作区迁移结果记入原工单，沿用原执行幂等键。后端重新核验原执行人、审批、当前授权和原生回执；不会重新迁移对象。'
        : '将已确认创建的 Consumer、ACL 与 API Key 对应的门户授权元数据提交完成。沿用原执行幂等键，后端重新检查原执行人、审批与当前授权；此操作不展示密钥。',
      onConfirm: async () => {
        let posted = false; setBusy(true); setError(undefined); setReceipt(undefined);
        try {
          const fresh = await read(original), request = workflowMetadataRecoveryRequest(fresh, workflow, original);
          if (fresh.executionId !== executionId) throw new ApiError('原执行记录已变化，请重新核验。', 409, migration ? 'MIGRATION_RECOVERY_REQUEST_MISMATCH' : 'PORTAL_RECOVERY_REQUEST_MISMATCH');
          assertCurrent(original); await api<WorkflowReceipt>(request.path, request.options); posted = true;
          const final = await read(original);
          if (!workflowMetadataRecoveryProvesCompletion(final, original, executionId, kind, workflow.planHash)) throw new Error('原执行尚未得到完整结束证明。');
          release(original); void message.success(migration ? '原工作区迁移工单已完成对账' : '门户授权元数据已完成，请以最新凭证状态为准'); await onComplete();
        } catch (cause) {
          const e = posted ? new ApiError(migration ? '迁移元数据对账响应已收到，但原执行终态尚未核验。请保留原键继续只读核验。' : '门户元数据提交响应已收到，但原执行终态尚未核验。请保留原键继续只读核验。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { kind: 'workflow', clusterId: original.clusterId, workspaceId: original.workspaceId, idempotencyKey: original.idempotencyKey, state: 'uncertain' }) : cause;
          if (posted && alive.current && getApiActorId() === original.actorId) window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: original.actorId, error: e } }));
          if (alive.current) setError(e); throw e;
        } finally { if (alive.current) setBusy(false); }
      },
    });
  }
  return <Card title={migration ? '工作区迁移结果对账' : '门户凭证元数据恢复'} style={{ marginTop: 20 }} data-testid="workflow-metadata-recovery">
    <Alert type="warning" showIcon message={migration ? '仅对账已完整确认的工作区迁移' : '仅恢复已确认创建凭证的门户授权记录'} description="只有原执行人可使用原执行幂等键核验。所有原生步骤必须已有完整确认，最终资格以服务端最新校验为准。" style={{ marginBottom: 16 }} />
    <Form layout="vertical"><Form.Item label="原执行幂等键" extra="仅填写原 execute 请求的 X-Idempotency-Key；审批键和申请键不适用。"><Input aria-label="原执行幂等键" autoComplete="off" value={key} disabled={busy} onChange={event => { pending.current?.abort(); setKey(event.target.value.trim()); setReceipt(undefined); setError(undefined); }} /></Form.Item></Form>
    {!!error && <QueryError error={error} />}
    <Space wrap><Button loading={busy} disabled={busy || !mayRead || !canonicalId(key)} onClick={() => void verify()}>核验原执行回执</Button><Button type="primary" disabled={!eligible || busy} onClick={reconcile}>{migration ? '只对账迁移元数据' : '只提交门户元数据'}</Button></Space>
    {!allowed && <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>当前账号或工作流未获得服务端元数据恢复资格。</Typography.Paragraph>}
    {anotherUncertainWrite && <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>当前范围另有待核验写入，请先核验其原操作回执。</Typography.Paragraph>}
    {receipt && <Descriptions size="small" column={1} style={{ marginTop: 16 }} items={[{ key: 'execution', label: '原执行 ID', children: <code>{receipt.executionId}</code> }, { key: 'native', label: '原生步骤', children: migration ? '原迁移步骤及全部对象已完整确认' : '3 个步骤已完整确认' }, { key: 'metadata', label: migration ? '工单元数据' : '门户元数据', children: '待显式确认提交' }]} />}
  </Card>;
}

export function WorkflowIssueAbandonment({ workflow, sourceError, onComplete }: { workflow: Workflow; sourceError: unknown; onComplete: () => Promise<unknown> }) {
  const scope = usePortalScope(), { modal, message } = App.useApp();
  const recovery = sourceError instanceof ApiError ? sourceError.recovery : undefined;
  const retained = scope.workspace.references.filter(item => item.kind === 'workflow' && item.actor_id === scope.actor && item.cid === scope.cid && item.wid === scope.wid);
  const originalKey = recovery?.kind === 'workflow' && recovery.clusterId === scope.cid && recovery.workspaceId === scope.wid && canonicalId(recovery.idempotencyKey)
    ? recovery.idempotencyKey! : retained.length === 1 ? retained[0].idempotencyKey : '';
  const [key, setKey] = useState(originalKey), [receipt, setReceipt] = useState<WorkflowReceipt>(), [error, setError] = useState<unknown>(), [busy, setBusy] = useState(false), [certificate, setCertificate] = useState<WorkflowReceipt['issueAbandonment']>();
  const alive = useRef(true), pending = useRef<AbortController>();
  const current = useRef({ actorId: scope.actor ?? '', clusterId: scope.cid ?? '', workspaceId: scope.wid ?? '', workflowId: workflow.id, permissionsVersion: scope.version ?? '' });
  current.current = { actorId: scope.actor ?? '', clusterId: scope.cid ?? '', workspaceId: scope.wid ?? '', workflowId: workflow.id, permissionsVersion: scope.version ?? '' };
  useEffect(() => { alive.current = true; return () => { alive.current = false; pending.current?.abort(); }; }, []);
  useEffect(() => { if (originalKey) { setKey(originalKey); setReceipt(undefined); setCertificate(undefined); } }, [originalKey]);
  const reference: WorkflowMetadataRecoveryReference = { ...current.current, idempotencyKey: key };
  const mayRead = scope.permission.has('workflows', 'write');
  const allowed = mayRead && workflow.capabilities?.abandonRejectedIssue === true && !scope.workspace.readonlyWorkspace;
  const anotherUncertainWrite = scope.workspace.references.some(item => item.cid === scope.cid && item.wid === scope.wid && item.idempotencyKey !== key);
  const eligible = allowed && !anotherUncertainWrite && workflowIssueAbandonmentEligible(receipt, workflow, reference);
  function assertCurrent(original: WorkflowMetadataRecoveryReference) {
    if (!alive.current || getApiActorId() !== original.actorId || !workflowMetadataRecoveryContextMatches(original, current.current)) throw new ApiError('账号、工作区或权限已变化，请重新核验原失败执行回执。', 401, 'SESSION_CHANGED');
  }
  async function read(original: WorkflowMetadataRecoveryReference) {
    assertCurrent(original); pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    const value = await api<WorkflowReceipt>(workflowMetadataReceiptPath(original), { signal: controller.signal }); assertCurrent(original); return value;
  }
  async function complete(original: WorkflowMetadataRecoveryReference, value: WorkflowReceipt) {
    assertCurrent(original); setCertificate(value.issueAbandonment);
    const saved = scope.workspace.references.find(item => item.actor_id === original.actorId && item.cid === original.clusterId && item.wid === original.workspaceId && item.kind === 'workflow' && item.idempotencyKey === original.idempotencyKey);
    if (saved) scope.workspace.resolveReference(saved);
    window.dispatchEvent(new CustomEvent('kongos:receipt-verified', { detail: { kind: 'workflow', cid: original.clusterId, wid: original.workspaceId, idempotencyKey: original.idempotencyKey, completed: true, state: 'failed' } }));
    void message.success('失败申请的预留已关闭；原执行仍保留为失败'); await onComplete();
  }
  async function verify() {
    const original = { ...reference }; setBusy(true); setError(undefined); setReceipt(undefined); setCertificate(undefined);
    try {
      const value = await read(original);
      if (value.executionId && workflowIssueAbandonmentProvesCompletion(value, original, value.executionId)) { await complete(original, value); return; }
      if (!workflowIssueAbandonmentEligible(value, workflow, original)) throw new ApiError('原回执未证明首个 Consumer 创建明确失败、后续步骤未执行且当前申请可安全关闭，请保留原键。', 409, 'PORTAL_ABANDONMENT_NOT_ELIGIBLE');
      setReceipt(value);
    } catch (e) { if (alive.current) setError(e); }
    finally { if (alive.current) setBusy(false); }
  }
  function abandon() {
    if (!eligible || !receipt) return;
    const original = { ...reference }, executionId = receipt.executionId!, grantId = receipt.issueAbandonment!.grantId;
    mutationConfirm(modal, {
      title: '确认关闭明确失败的凭证申请', expected: workflow.name,
      description: '关闭未发放凭证的预留，保留原计划与失败执行记录。后端重新验证三个原生对象均不存在且没有引用；如需访问，之后由开发者显式申请全新凭证。沿用原执行幂等键。',
      onConfirm: async () => {
        let posted = false; setBusy(true); setError(undefined); setReceipt(undefined);
        try {
          const fresh = await read(original), request = workflowIssueAbandonmentRequest(fresh, workflow, original);
          if (fresh.executionId !== executionId || fresh.issueAbandonment?.grantId !== grantId) throw new ApiError('原失败执行或授权记录已变化，请重新核验。', 409, 'PORTAL_ABANDONMENT_REQUEST_MISMATCH');
          assertCurrent(original); await api<WorkflowReceipt>(request.path, request.options); posted = true;
          const final = await read(original);
          if (!workflowIssueAbandonmentProvesCompletion(final, original, executionId, grantId)) throw new Error('原失败执行尚未提供完整关闭证书。');
          await complete(original, final);
        } catch (cause) {
          const e = posted ? new ApiError('关闭响应已收到，但原执行的关闭证书尚未核验。请保留原键继续只读核验，不会重新申请或执行。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { kind: 'workflow', clusterId: original.clusterId, workspaceId: original.workspaceId, idempotencyKey: original.idempotencyKey, state: 'uncertain' }) : cause;
          if (posted && alive.current && getApiActorId() === original.actorId) window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: original.actorId, error: e } }));
          if (alive.current) setError(e); throw e;
        } finally { if (alive.current) setBusy(false); }
      },
    });
  }
  return <Card title="关闭明确失败的凭证申请" style={{ marginTop: 20 }} data-testid="workflow-issue-abandonment">
    <Alert type="warning" showIcon message="失败状态本身不能证明预留已经释放" description="仅首个 Consumer 创建已明确失败、后续步骤保持未执行并由服务端证明没有原生对象与引用的申请可关闭。原失败执行与原生步骤记录始终保留。" style={{ marginBottom: 16 }} />
    <Form layout="vertical"><Form.Item label="原失败执行幂等键" extra="使用原 execute 请求的 X-Idempotency-Key，审批与申请键不适用。"><Input aria-label="原失败执行幂等键" autoComplete="off" value={key} disabled={busy} onChange={event => { pending.current?.abort(); setKey(event.target.value.trim()); setReceipt(undefined); setCertificate(undefined); setError(undefined); }} /></Form.Item></Form>
    {!!error && <QueryError error={error} />}
    <Space wrap><Button loading={busy} disabled={busy || !mayRead || !canonicalId(key)} onClick={() => void verify()}>核验失败执行回执</Button><Button danger disabled={busy || !eligible} onClick={abandon}>关闭明确失败申请</Button></Space>
    {anotherUncertainWrite && <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>当前范围另有待核验写入，请先核验其原操作回执。</Typography.Paragraph>}
    {!allowed && !certificate && <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>当前工作流或账号未获得服务端关闭资格，仍可核验原执行回执。</Typography.Paragraph>}
    {receipt && <Descriptions size="small" column={1} style={{ marginTop: 16 }} items={[{ key: 'execution', label: '原执行 ID', children: <code>{receipt.executionId}</code> }, { key: 'first', label: 'Consumer 创建', children: '明确失败' }, { key: 'later', label: '后续步骤', children: '3 个步骤未执行' }]} />}
    {certificate && <Alert style={{ marginTop: 16 }} type="success" showIcon message="预留关闭证书已核验" description={<span>证书：<code>{certificate.certificateId}</code>。原执行仍为失败，原 Key 未发放。如需访问，请由开发者重新申请并审批全新凭证。</span>} />}
  </Card>;
}

export function workflowListProgress(row: Workflow) {
  const stage = row.approval?.stages?.find(item => item.state === 'active');
  if (stage) return `${stage.name} · ${stage.votes}/${stage.threshold}`;
  if (row.approval?.stages?.length) return `${row.approval.stages.filter(item => item.state === 'approved').length}/${row.approval.stages.length} 阶段通过`;
  if (!row.approvalRequired) return <Typography.Text type="secondary">无需审批</Typography.Text>;
  const tally = row.approvalTally;
  if (!tally) return '—';
  if (tally.rejections > 0) return <Tag color="red">已驳回</Tag>;
  if (tally.approvals >= tally.required) return <Space size={4}><Tag color="green">已批准 {tally.approvals}/{tally.required}</Tag>{row.selfApproved && <Tag color="orange">自审批</Tag>}</Space>;
  return row.state === 'pending' ? <Tag color="processing">待审批 0/{tally.required}</Tag> : <Typography.Text type="secondary">未审批 0/{tally.required}</Typography.Text>;
}
