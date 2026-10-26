import { useEffect, useRef, useState } from 'react';
import { App, Alert, Button, Card, Checkbox, Descriptions, Drawer, Form, Input, InputNumber, Select, Space, Table, Tag, Typography } from 'antd';
import { ArrowDownOutlined, ArrowUpOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { api, ApiError, errorMessage, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canonicalId } from '../api/workspace-scope';
import { workflowReceiptProvesCompletion } from '../api/workflow-recovery';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError } from '../components/Shared';
import { usePortalPage, usePortalScope } from './portal-hooks';
import { WorkflowApproverLookup } from './WorkflowApproverLookup';
import { SelfApprovalSetting } from './SelfApprovalSetting';
import { workflowKindLabels, workflowPolicyPayload, workflowStageModeLabels, type WorkflowDefinition, type WorkflowPolicy } from './workflows.model';

type OriginalPolicyRequest = { actor: string; version?: string; cid: string; wid: string; key: string; definitionId?: string };
const same = (left: OriginalPolicyRequest, right: Pick<OriginalPolicyRequest, 'actor' | 'version' | 'cid' | 'wid'>) => left.actor === right.actor && left.version === right.version && left.cid === right.cid && left.wid === right.wid;

/** This first UI slice consumes only registered definitions and existing
 * IAM/workflow receipts. It does not create an independent approval engine. */
export function WorkflowPolicies() {
  const scope = usePortalScope(), query = usePortalPage<WorkflowDefinition>('workflow-definitions'), { modal, message } = App.useApp();
  const [editing, setEditing] = useState<WorkflowDefinition>(), [error, setError] = useState<unknown>(), [busy, setBusy] = useState(false);
  const [submittedWorkflow, setSubmittedWorkflow] = useState<string>(), [original, setOriginal] = useState<OriginalPolicyRequest>();
  const [form] = Form.useForm(), alive = useRef(true), current = useRef(scope); current.current = scope;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const retained = scope.workspace.references.filter(item => item.actor_id === scope.actor && item.cid === scope.cid && item.wid === scope.wid && !item.kind && !item.domain);
  const recovery = original ?? (retained.length === 1 ? { actor: scope.actor!, version: scope.version, cid: scope.cid!, wid: scope.wid!, key: retained[0].idempotencyKey } : undefined);
  const blocked = busy || !!recovery || scope.workspace.writeBlocked || scope.workspace.readonlyWorkspace;
  const allowed = (action: 'write' | 'delete') => scope.permission.can('workflows', action, undefined, { clusterId: scope.cid, workspaceId: scope.wid });
  function capture(key: string, definitionId?: string): OriginalPolicyRequest { return { actor: scope.actor!, version: scope.version, cid: scope.cid!, wid: scope.wid!, key, definitionId }; }
  function assertCurrent(request: OriginalPolicyRequest): void {
    const active = current.current;
    if (!alive.current || getApiActorId() !== request.actor || !same(request, { actor: active.actor!, version: active.version, cid: active.cid!, wid: active.wid! })) throw new ApiError('账号、权限或工作区已变化，请重新审阅审批政策。', 409, 'SCOPE_CHANGED');
  }
  function edit(row: WorkflowDefinition) {
    setError(undefined); setSubmittedWorkflow(undefined); setEditing(row);
    const existing = row.format === 2 && row.policy.version === 2 ? row.policy as WorkflowPolicy : undefined;
    form.setFieldsValue(existing ?? { distinctAcrossStages: true, intentTtlHours: 24, stages: [{ name: '管理员审批', mode: 'any', threshold: 1, selector: { users: [], teams: [], roles: [] } }] });
  }
  function change(row: WorkflowDefinition, operation: 'version' | 'archive' | 'restore', policy?: WorkflowPolicy) {
    if (blocked || !allowed(operation === 'archive' ? 'delete' : 'write')) return;
    const request = capture(newIdempotencyKey(), row.id), pathname = `/clusters/${request.cid}/workflow-definitions/${row.id}/${operation === 'version' ? 'versions' : operation}?workspaceId=${request.wid}`;
    mutationConfirm(modal, { title: operation === 'version' ? '确认发布审批政策新版本' : operation === 'archive' ? '确认归档审批政策' : '确认恢复审批政策',
      expected: row.name, danger: operation === 'archive', okText: '确认提交',
      description: operation === 'version' ? '新政策用于后续新工单；现有工单保留已绑定的政策版本。审批模式集群会先生成政策变更工单。' : operation === 'archive' ? '归档后停止新工单使用此政策，已有工单和历史审批记录继续保留。' : '恢复此政策供后续新工单使用。',
      onConfirm: async () => {
        assertCurrent(request);
        if (current.current.workspace.writeBlocked || current.current.workspace.readonlyWorkspace || !current.current.permission.can('workflows', operation === 'archive' ? 'delete' : 'write', undefined, { clusterId: request.cid, workspaceId: request.wid })) throw new Error('当前范围不可修改审批政策。');
        setBusy(true); setError(undefined); let sent = false;
        try {
          const latest = await query.refetch(); assertCurrent(request);
          const currentRow = latest.data?.items.find(item => item.id === row.id);
          if (!currentRow || currentRow.revision !== row.revision || currentRow.policyHash !== row.policyHash || currentRow.status !== row.status) throw new Error('审批政策已变化，请刷新并重新编辑。');
          sent = true;
          const result = await api<any>(pathname, { method: 'POST', headers: { 'X-Idempotency-Key': request.key }, body: JSON.stringify({ revision: row.revision, ...(policy ? { policy } : {}), confirmed: true, confirm_name: row.name }) });
          assertCurrent(request);
          if (canonicalId(result?.workflowId) && result.submissionCompleted === true && result.nativeExecutionRequested === false) { setSubmittedWorkflow(result.workflowId); void message.success('政策变更已提交审批'); }
          else if (result?.entity?.id === row.id || result?.configurationCommitted === true && result?.state === 'succeeded') void message.success('审批政策已保存');
          else throw new ApiError('政策变更响应尚未证明完成，请核验原操作。', 0, 'WRITE_RESULT_UNKNOWN');
          setEditing(undefined); await query.refetch();
        } catch (cause) {
          const uncertain = sent && cause instanceof ApiError && (/UNKNOWN|UNCERTAIN|SCOPE_CHANGED/.test(cause.code ?? '') || cause.status >= 500);
          if (uncertain && getApiActorId() === request.actor) {
            if (alive.current) setOriginal(request);
            window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: request.actor,
              error: new ApiError('审批政策结果待核验，请保留原操作标识。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined,
                { clusterId: request.cid, workspaceId: request.wid, idempotencyKey: request.key, state: 'uncertain' }) } }));
          }
          if (alive.current) setError(cause); throw cause;
        } finally { if (alive.current) setBusy(false); }
      } });
  }
  async function verify() {
    if (!recovery) return; const request = { ...recovery }; setBusy(true); setError(undefined);
    try {
      assertCurrent(request);
      let receipt: any;
      try { receipt = await api<any>(`/iam/operations/by-key/${request.key}`); }
      catch (cause) { if (!(cause instanceof ApiError) || cause.status !== 404) throw cause; }
      assertCurrent(request);
      if (receipt) {
        if (!canonicalId(receipt.id) || !canonicalId(receipt.target_id) || receipt.module !== 'workflows' || receipt.cluster_id !== request.cid || receipt.workspace_id !== request.wid
          || receipt.safe_result?.entity?.id !== receipt.target_id || receipt.safe_result?.nativeExecutionRequested !== false
          || request.definitionId && receipt.target_id !== request.definitionId || receipt.state !== 'succeeded' || receipt.remote_completed !== true) throw new Error('原政策变更尚未得到已提交的事务回执，不会重新发送。');
      } else {
        receipt = await api<any>(`/clusters/${request.cid}/workflows/receipts/by-key/${request.key}?workspaceId=${request.wid}`); assertCurrent(request);
        if (!workflowReceiptProvesCompletion(receipt, { kind: 'workflow', clusterId: request.cid, workspaceId: request.wid, idempotencyKey: request.key })
          || receipt.action !== 'submit' || !canonicalId(receipt.workflowId) || receipt.steps?.length !== 1 || receipt.steps[0].name !== 'workflow.policy') throw new Error('原政策审批提交尚未得到完整回执，不会重新发送。');
        setSubmittedWorkflow(receipt.workflowId);
      }
      for (const ref of current.current.workspace.references.filter(ref => ref.actor_id === request.actor && ref.cid === request.cid && ref.wid === request.wid && ref.idempotencyKey === request.key && !ref.kind && !ref.domain)) current.current.workspace.resolveReference(ref);
      window.dispatchEvent(new CustomEvent('kongos:receipt-verified', { detail: { cid: request.cid, wid: request.wid, idempotencyKey: request.key, completed: true, state: receipt.state } }));
      setOriginal(undefined); setEditing(undefined); await query.refetch(); void message.success(receipt.workflowId ? '原政策变更已提交审批' : '原政策变更已完成');
    } catch (cause) { if (alive.current) setError(cause); }
    finally { if (alive.current) setBusy(false); }
  }
  return <><SelfApprovalSetting /><Space className="list-toolbar"><Button loading={query.isFetching} onClick={() => void query.refetch()}>刷新政策</Button></Space>
    {query.error && <QueryError error={query.error} />}{!!error && <Alert type="error" showIcon message={errorMessage(error)} style={{ marginBottom: 16 }} />}
    {submittedWorkflow && <Alert type="success" showIcon message={<span>审批政策变更已登记 · <Link to={`/workflows/${submittedWorkflow}`}>查看真实工单</Link></span>} style={{ marginBottom: 16 }} />}
    {recovery && <Alert type="warning" showIcon message={original ? '审批政策写入结果待核验' : '当前范围有写入结果待核验'} description={<Space wrap><Typography.Text className="mono" copyable>{recovery.key}</Typography.Text><Button loading={busy} onClick={() => void verify()}>只读检查原政策回执</Button></Space>} style={{ marginBottom: 16 }} />}
    <Table rowKey="id" pagination={false} loading={query.isFetching} dataSource={query.data?.items ?? []} scroll={{ x: 1000 }}
      columns={[{ title: '审批政策', render: (_, row) => <div><strong>{row.name}</strong><div className="table-secondary">{workflowKindLabels[row.kind] ?? row.kind}</div></div> },
        { title: '版本', render: (_, row) => <Tag>v{row.version}</Tag> }, { title: '审批阶段', render: (_, row) => row.format === 2 && Array.isArray(row.policy.stages) ? <Space direction="vertical" size={4}>{(row.policy as WorkflowPolicy).stages.map(stage => <Typography.Text key={stage.level}>{stage.level}. {stage.name} · {workflowStageModeLabels[stage.mode]}{stage.mode === 'quorum' ? `（${stage.threshold} 人）` : ''}</Typography.Text>)}</Space> : '原版单级审批' },
        { title: '状态', render: (_, row) => <Tag color={row.status === 'active' ? 'green' : undefined}>{row.status === 'active' ? '已启用' : '已归档'}</Tag> },
        { title: '操作', render: (_, row) => <Space>{row.status === 'active' ? <><Button type="link" disabled={blocked || !allowed('write')} onClick={() => edit(row)}>编辑政策</Button><Button type="link" danger disabled={blocked || !allowed('delete') || row.kind === 'workflow-policy-metadata'} onClick={() => change(row, 'archive')}>归档</Button></> : <Button type="link" disabled={blocked || !allowed('write')} onClick={() => change(row, 'restore')}>恢复</Button>}</Space> }]} />
    <div className="cursor-footer"><span>第 {query.page} 页</span><Space><Button disabled={!query.previous || query.isFetching} onClick={query.previous}>上一页</Button><Button disabled={!query.next || query.isFetching} onClick={query.next}>下一页</Button></Space></div>
    <Drawer title={`编辑审批政策 · ${editing?.name ?? ''}`} open={!!editing} width={800} onClose={() => setEditing(undefined)} destroyOnHidden>
      {editing && <><Descriptions size="small" column={2} items={[{ key: 'kind', label: '工单类型', children: workflowKindLabels[editing.kind] ?? editing.kind }, { key: 'version', label: '当前版本', children: `v${editing.version}` }]} />
        {!!error && <Alert type="error" showIcon message={errorMessage(error)} style={{ marginBlock: 16 }} />}
        <Form form={form} layout="vertical" disabled={blocked || !allowed('write')} onFinish={values => { try { change(editing, 'version', workflowPolicyPayload(editing.kind, values)); } catch (cause) { setError(cause); } }}>
          <Space align="start" wrap style={{ marginTop: 20 }}><Form.Item name="intentTtlHours" label="工单有效期（小时）" rules={[{ required: true }]}><InputNumber min={1} max={168} precision={0} /></Form.Item>
            <Form.Item name="distinctAcrossStages" valuePropName="checked" label="审批人规则"><Checkbox>不同阶段使用不同审批人</Checkbox></Form.Item></Space>
          <Form.Item><Checkbox checked disabled>提交人不可审批自己的工单</Checkbox></Form.Item>
          <Form.List name="stages">{(fields, { add, remove, move }) => <>{fields.map((field, index) => <Card key={field.key} size="small" title={`第 ${index + 1} 阶段`} style={{ marginBottom: 16 }}
            extra={<Space size={0}><Button type="text" aria-label={`上移第${index + 1}阶段`} disabled={blocked || index === 0} icon={<ArrowUpOutlined />} onClick={() => move(index, index - 1)} /><Button type="text" aria-label={`下移第${index + 1}阶段`} disabled={blocked || index === fields.length - 1} icon={<ArrowDownOutlined />} onClick={() => move(index, index + 1)} /><Button type="text" danger aria-label={`删除第${index + 1}阶段`} disabled={blocked || fields.length === 1} icon={<DeleteOutlined />} onClick={() => remove(field.name)} /></Space>}>
            <WorkflowPolicyStage index={field.name} disabled={blocked || !allowed('write')} /></Card>)}
            <Button icon={<PlusOutlined />} disabled={blocked || !allowed('write') || fields.length >= 8} onClick={() => add({ name: `第 ${fields.length + 1} 阶段审批`, mode: 'any', threshold: 1, selector: { users: [], teams: [], roles: [] } })}>添加审批阶段</Button></>}</Form.List>
          <Button type="primary" htmlType="submit" loading={busy} disabled={blocked || !allowed('write')} style={{ marginTop: 24 }}>发布新版本</Button>
        </Form></>}
    </Drawer></>;
}
function WorkflowPolicyStage({ index, disabled }: { index: number; disabled: boolean }) {
  const form = Form.useFormInstance(), mode = Form.useWatch(['stages', index, 'mode'], form);
  return <><Form.Item name={[index, 'name']} label="阶段名称" rules={[{ required: true, whitespace: true, message: '请输入阶段名称' }]}><Input maxLength={128} /></Form.Item>
    <Space align="start" wrap><Form.Item name={[index, 'mode']} label="通过方式" rules={[{ required: true }]}><Select style={{ minWidth: 190 }} options={Object.entries(workflowStageModeLabels).map(([value, label]) => ({ value, label }))} /></Form.Item>
      {mode === 'quorum' && <Form.Item name={[index, 'threshold']} label="所需人数" rules={[{ required: true }]}><InputNumber min={1} max={100} precision={0} /></Form.Item>}</Space>
    {(['users', 'teams', 'roles'] as const).map(resource => <Form.Item key={resource} name={[index, 'selector', resource]} label={{ users: '指定用户', teams: '团队成员', roles: '角色成员' }[resource]}><WorkflowApproverLookup resource={resource} label={`第${index + 1}阶段${resource}`} disabled={disabled} /></Form.Item>)}
  </>;
}
