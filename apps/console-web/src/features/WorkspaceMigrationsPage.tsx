import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Form, Input, Select, Space, Table, Tag, Typography } from 'antd';
import { abbreviateId, entityOptionLabel } from '../lib/abbreviate-id';
import { DeleteOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError, getApiActorId, post } from '../api/client';
import { canonicalId, receiptProvesCompletion, scopeQuery } from '../api/workspace-scope';
import { useCluster } from '../app/ClusterContext';
import { usePermissions } from '../app/Permissions';
import { useWorkspace } from '../app/WorkspaceContext';
import { ForeignLookup } from '../components/KongSchemaForm';
import { mutationConfirm } from '../components/MutationConfirm';
import { PageHeading, QueryError, formatTime } from '../components/Shared';
import { entityLabels, entityTypes, entityName, type EntityPageData } from './entities';

interface MigrationRoot { type: string; id: string; parent_id?: string; credential_kind?: string; }
interface MigrationPlan {
  id: string; cluster_id: string; source_workspace_id: string; target_workspace_id: string; target_workspace_name: string;
  workflow_id?: string; state: 'planned' | 'running' | 'partial' | 'succeeded' | 'failed' | 'expired'; plan_hash: string; expires_at: string; operation_id?: string;
  affected: { key: string; type: string; id: string; name: string; before_tags: string[]; after_tags: string[]; status: string; inherited_only: boolean; source_workspace_id: string; target_workspace_id: string }[];
  references: { type: string; id: string; name: string; workspace_id: string; affected: boolean }[];
  conflicts: { code: string; message: string; objects: string[] }[]; budget: { pages: number; records: number; nodes: number }; warnings: string[]; steps?: unknown;
}
const credentials = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
const stateLabels: Record<string, string> = { planned: '待执行', running: '执行中', partial: '部分完成', succeeded: '已完成', failed: '执行失败', expired: '已过期', pending: '待迁移', uncertain: '待核验' };

/** Only one native cursor page is loaded at a time; nested lookup never scans the entire gateway. */
function NestedLookup({ type, parentId, kind, value, onChange }: { type: string; parentId?: string; kind?: string; value?: string; onChange?: (id?: string) => void }) {
  const { clusterId } = useCluster();
  const { workspaceId, ready } = useWorkspace();
  const [cursor, setCursor] = useState<string>();
  const [term, setTerm] = useState('');
  const path = type === 'targets' ? `/clusters/${clusterId}/upstreams/${parentId}/targets` : `/clusters/${clusterId}/consumers/${parentId}/credentials/${kind}`;
  const query = useQuery({ queryKey: ['migration-nested-lookup', clusterId, workspaceId, type, parentId, kind, cursor], queryFn: () => api<EntityPageData>(scopeQuery(`${path}?size=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, clusterId, workspaceId)), enabled: ready && !!parentId && (type === 'targets' || !!kind) });
  useEffect(() => { setCursor(undefined); setTerm(''); }, [clusterId, workspaceId, type, parentId, kind]);
  const options = (query.data?.items ?? []).map(item => ({ value: item.id, label: entityOptionLabel(entityName(item), item.id) }));
  if (canonicalId(term) && !options.some(item => item.value === term)) options.unshift({ value: term, label: `使用 ID ${term}` });
  if (value && !options.some(item => item.value === value)) options.unshift({ value, label: value });
  return <><Select aria-label="id" value={value} options={options} showSearch allowClear disabled={!parentId} loading={query.isFetching} placeholder="选择当前页对象，或输入完整 UUID" onSearch={setTerm} onChange={onChange} filterOption={(input, option) => String(option?.label).toLowerCase().includes(input.toLowerCase())} popupRender={menu => <>{menu}{query.data?.nextCursor && <Button block type="text" onMouseDown={event => event.preventDefault()} onClick={() => setCursor(query.data!.nextCursor!)}>加载下一页</Button>}</>} /><Typography.Text type="secondary" className="small-note">按页选择；凭证秘密不会显示。也可输入从详情复制的原对象 ID。</Typography.Text>{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}</>;
}
function RootRow({ index, fieldName, remove, disabled }: { index: number; fieldName: number; remove: () => void; disabled: boolean }) {
  const form = Form.useFormInstance();
  const type = Form.useWatch(['roots', fieldName, 'type'], form) ?? 'services';
  const parentId = Form.useWatch(['roots', fieldName, 'parent_id'], form);
  const kind = Form.useWatch(['roots', fieldName, 'credential_kind'], form);
  const nested = type === 'targets' || type === 'credentials';
  return <div className="migration-root" data-testid={`migration-root-${index}`}>
    <div className="migration-root-number">{index + 1}</div><div className="migration-root-fields">
      <Form.Item name={[fieldName, 'type']} label="对象类型" rules={[{ required: true }]}><Select aria-label="type" disabled={disabled} options={[...entityTypes.map(type => ({ value: type, label: entityLabels[type] })), { value: 'targets', label: 'Targets' }, { value: 'credentials', label: '认证凭证' }]} onChange={() => { form.setFieldValue(['roots', fieldName, 'id'], undefined); form.setFieldValue(['roots', fieldName, 'parent_id'], undefined); }} /></Form.Item>
      {nested && <Form.Item name={[fieldName, 'parent_id']} label={type === 'targets' ? '所属 Upstream' : '所属 Consumer'} rules={[{ required: true, message: '请选择父对象' }]} getValueFromEvent={value => value?.id}><ForeignLookup reference={type === 'targets' ? 'upstreams' : 'consumers'} label="parent_id" /></Form.Item>}
      {type === 'credentials' && <Form.Item name={[fieldName, 'credential_kind']} label="凭证类型" rules={[{ required: true }]}><Select aria-label="credential_kind" options={credentials.map(value => ({ value, label: value }))} onChange={() => form.setFieldValue(['roots', fieldName, 'id'], undefined)} /></Form.Item>}
      <Form.Item name={[fieldName, 'id']} label="原对象" rules={[{ required: true, message: '请选择一个对象' }, { validator: (_, value) => !value || canonicalId(value) || canonicalId(value?.id) ? Promise.resolve() : Promise.reject(new Error('对象 ID 必须为 UUID')) }]} getValueFromEvent={value => typeof value === 'string' ? value : value?.id}>{nested ? <NestedLookup type={type} parentId={parentId} kind={kind} /> : <ForeignLookup reference={type} label="id" />}</Form.Item>
    </div><Button aria-label={`移除迁移对象 ${index + 1}`} icon={<DeleteOutlined />} disabled={disabled} onClick={remove} />
  </div>;
}

export function WorkspaceMigrationsPage() {
  const { clusterId, cluster } = useCluster();
  const permission = usePermissions();
  const workspace = useWorkspace();
  const { modal, message } = App.useApp();
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const navigate=useNavigate();
  const alive=useRef(true);
  const live=useRef({cid:clusterId,wid:workspace.workspaceId,actor:getApiActorId(),version:permission.version});
  live.current={cid:clusterId,wid:workspace.workspaceId,actor:getApiActorId(),version:permission.version};
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  const stillCurrent=(saved:typeof live.current)=>alive.current&&saved.cid===live.current.cid&&saved.wid===live.current.wid&&saved.actor===live.current.actor&&saved.version===live.current.version;
  const [form] = Form.useForm();
  const [working, setWorking] = useState<'plan' | 'apply' | 'reconcile'>();
  const [error, setError] = useState<unknown>();
  const [receiptInspected, setReceiptInspected] = useState(false);
  const [receiptCompleted, setReceiptCompleted] = useState(false);
  const [inspectedKey, setInspectedKey] = useState<string>();
  const [resumeReady, setResumeReady] = useState(false);
  const planId = canonicalId(params.get('planId'));
  const sourceId = canonicalId(params.get('sourceWorkspaceId')) ?? workspace.workspaceId;
  const cid = canonicalId(params.get('clusterId')) ?? clusterId;
  const base = `/clusters/${cid}/workspace-migrations`;
  const planKey = ['workspace-migration-plan', cid, sourceId, planId,getApiActorId(),permission.version];
  const planQuery = useQuery({ queryKey: planKey, queryFn: () => api<MigrationPlan>(scopeQuery(`${base}/${planId}`, cid, sourceId)), enabled: !!planId && !!cid && !!sourceId });
  const plan = planQuery.data;
  const sourceBlocked = workspace.references.some(ref => ref.cid === cid && ref.wid === sourceId);
  const scopeMismatch = !!planId && (cid !== clusterId || sourceId !== workspace.workspaceId);
  const unknown = error instanceof ApiError && (error.recovery?.state === 'uncertain' || /UNKNOWN|UNCERTAIN/.test(error.code ?? ''));
  const partial = plan?.state === 'partial' || plan?.state === 'failed';
  const expired = !!plan && (plan.state === 'expired' || Date.parse(plan.expires_at) <= Date.now());
  const blocked = !permission.create('workspaces') || cluster?.execution_mode==='approval'&&!permission.create('workflows') || !workspace.ready || scopeMismatch || sourceBlocked || workspace.readonlyWorkspace ;
  const canApply = !!plan && !plan.workflow_id && !blocked && !working && !expired && !plan.conflicts.length && (plan.state === 'planned' || partial && resumeReady && receiptCompleted && !plan.affected.some(node => node.status === 'uncertain'));
  useEffect(() => { form.resetFields(); form.setFieldsValue({ roots: [{ type: 'services' }] });setWorking(undefined);setError(undefined); }, [clusterId, workspace.workspaceId,permission.version]);
  useEffect(() => { setReceiptInspected(false); setReceiptCompleted(false); setInspectedKey(undefined); setResumeReady(false); }, [planId]);
  useEffect(() => {
    const received = (event: Event) => { const proof = (event as CustomEvent).detail; if (proof?.cid === cid && proof?.wid === sourceId && (proof.operationId === plan?.operation_id || error instanceof ApiError && proof.idempotencyKey === error.recovery?.idempotencyKey)) { setReceiptInspected(true); setReceiptCompleted(proof.completed === true); setInspectedKey(proof.idempotencyKey); void planQuery.refetch(); } };
    window.addEventListener('kongos:receipt-verified', received); return () => window.removeEventListener('kongos:receipt-verified', received);
  }, [cid, sourceId, plan?.operation_id, error]);
  async function preview(values: { target_workspace_id: string; roots: any[] }) {
    if (!workspace.ready) return;
    setWorking('plan'); setError(undefined);
    const originalCid = clusterId, originalWid = workspace.workspaceId,original={...live.current};
    try {
      const roots: MigrationRoot[] = values.roots.map(root => ({ type: root.type, id: typeof root.id === 'string' ? root.id : root.id.id, ...(root.parent_id ? { parent_id: typeof root.parent_id === 'string' ? root.parent_id : root.parent_id.id } : {}), ...(root.credential_kind ? { credential_kind: root.credential_kind } : {}) }));
      const result = await post<MigrationPlan>(scopeQuery(`/clusters/${originalCid}/workspace-migrations/plan`, originalCid, originalWid), { source_workspace_id: originalWid, target_workspace_id: values.target_workspace_id, roots });
      if(!stillCurrent(original))return;
      client.setQueryData(['workspace-migration-plan', originalCid, originalWid, result.id,original.actor,original.version], result);
      setParams({ planId: result.id, sourceWorkspaceId: originalWid!, clusterId: originalCid! }); setResumeReady(false); setReceiptInspected(false); setReceiptCompleted(false);
    } catch(e){if(stillCurrent(original))setError(e);}finally{if(stillCurrent(original))setWorking(undefined);}
  }
  async function refresh() { await planQuery.refetch(); }
  function apply() {
    if (!plan || !canApply) return;
    const captured = plan,original={...live.current},approval=cluster?.execution_mode==='approval';
    mutationConfirm(modal, { title: approval?'确认提交迁移审批':partial ? '确认继续迁移' : '确认执行工作区迁移', expected: captured.target_workspace_name, danger: false, description: `将 ${captured.affected.length} 个关联对象迁移至 ${captured.target_workspace_name}。请核对下方完整差异与共享引用；归属改变不限制实际流量或全局插件。`, onConfirm: async () => {
      if(!stillCurrent(original))throw new Error('账号或工作区已变化，请重新查看迁移计划');
      setWorking('apply'); setError(undefined); setResumeReady(false);
      try {
        if(approval){const result=await post<{entity:{id:string}}>(scopeQuery(`/clusters/${captured.cluster_id}/workspace-migrations/${captured.id}/submit`,captured.cluster_id,captured.source_workspace_id),{confirmed:true,confirm_name:captured.target_workspace_name,plan_hash:captured.plan_hash});if(!stillCurrent(original))return;await planQuery.refetch();void message.success('迁移工单已提交，批准后由提交人执行');navigate(`/workflows/${result.entity.id}`);}
        else{const result=await post<MigrationPlan>(scopeQuery(`/clusters/${captured.cluster_id}/workspace-migrations/${captured.id}/apply`,captured.cluster_id,captured.source_workspace_id),{confirmed:true,confirm_name:captured.target_workspace_name,plan_hash:captured.plan_hash});if(!stillCurrent(original))return;client.setQueryData(['workspace-migration-plan',captured.cluster_id,captured.source_workspace_id,captured.id,original.actor,original.version],result);await client.invalidateQueries({predicate:query=>query.queryKey.includes(captured.cluster_id)});void message.success(result.state==='succeeded'?'工作区迁移已完成':'迁移执行已结束，请查看逐步结果');}
      } catch(e){if(stillCurrent(original)){setError(e);await planQuery.refetch();}throw e;}finally{if(stillCurrent(original))setWorking(undefined);}
    } });
  }
  async function reconcile() {
    if (!plan) return;
    const original={...live.current};
    setWorking('reconcile'); setError(undefined);
    try { const result = await post<MigrationPlan>(scopeQuery(`/clusters/${plan.cluster_id}/workspace-migrations/${plan.id}/reconcile`, plan.cluster_id, plan.source_workspace_id), { plan_hash: plan.plan_hash });if(!stillCurrent(original))return; client.setQueryData(planKey, result); setResumeReady(!result.affected.some(node => node.status === 'uncertain') && result.conflicts.length === 0);
      if (result.operation_id) {
        const receipt = await api<any>(scopeQuery(`/clusters/${result.cluster_id}/mutations/${result.operation_id}`, result.cluster_id, result.source_workspace_id));
        if(!stillCurrent(original))return;
        const completed = receiptProvesCompletion(receipt); setReceiptCompleted(completed);
        if (completed) for (const ref of workspace.references) if (ref.cid === result.cluster_id && ref.wid === result.source_workspace_id && (ref.operationId === result.operation_id || ref.idempotencyKey === inspectedKey)) workspace.resolveReference(ref);
      }
      void message.success('迁移状态已重新核验；请重新审阅差异与目标名称'); }
    catch(e){if(stillCurrent(original))setError(e);}finally{if(stillCurrent(original))setWorking(undefined);}
  }
  const terminalReceiptError = plan?.operation_id && partial && !receiptCompleted ? new ApiError('部分执行需要先核验原操作回执，再核验迁移状态。', 409, 'MIGRATION_RECEIPT_REQUIRED', undefined, undefined, { clusterId: cid, workspaceId: sourceId, operationId: plan.operation_id }) : undefined;
  return <>
    <PageHeading title="工作区迁移" extra={planId ? <Button icon={<ReloadOutlined />} loading={planQuery.isFetching} onClick={() => void refresh()}>刷新计划</Button> : undefined} />
    <Alert type="warning" showIcon message="迁移改变管理归属，采用标签软隔离" description="服务关联路由与插件等会按依赖关系纳入预览。Targets 和凭证继承父对象归属；Target 历史标签可能不同。共享引用、跨区依赖和冲突必须在执行前确认。" style={{ marginBottom: 20 }} />
    {scopeMismatch && <Alert type="info" showIcon message="当前正在查看原工作区的迁移计划" description={`原工作区：${sourceId}。切换选择器不会重发此操作；返回原工作区后才能执行新的迁移。`} style={{ marginBottom: 20 }} />}
    {error ? unknown && sourceBlocked ? <Alert type="warning" showIcon message="执行结果待核验，已阻止重复提交" description="请使用页面上方保存的原操作标识核验回执。刷新或切换工作区不会再次执行迁移。" style={{ marginBottom: 20 }} /> : <QueryError error={error} /> : null}
    {planQuery.isError && <QueryError error={planQuery.error} retry={() => void refresh()} />}
    <Card title={`选择源对象 · ${workspace.workspace?.name ?? '正在加载'}`} className="migration-form-card">
      <Form form={form} layout="vertical" initialValues={{ roots: [{ type: 'services' }] }} onFinish={preview}>
        <Form.Item name="target_workspace_id" label="目标工作区" rules={[{ required: true, message: '请选择目标工作区' }]}><Select aria-label="target_workspace_id" style={{ maxWidth: 460 }} disabled={!workspace.ready || !!working} options={workspace.workspaces.filter(row => row.id !== workspace.workspaceId && row.status === 'active').map(row => ({ value: row.id, label: row.name }))} popupRender={menu => <>{menu}{workspace.hasMore && <Button block type="text" onMouseDown={event => event.preventDefault()} onClick={() => void workspace.loadMore()}>加载更多工作区</Button>}</>} /></Form.Item>
        <Form.List name="roots" rules={[{ validator: (_, roots) => roots?.length >= 1 && roots.length <= 50 ? Promise.resolve() : Promise.reject(new Error('请选择 1–50 个迁移根对象')) }]}>{(fields, { add, remove }, { errors }) => <>{fields.map((field, index) => <RootRow key={field.key} index={index} fieldName={field.name} remove={() => remove(field.name)} disabled={!!working} />)}<Form.ErrorList errors={errors} /><Space wrap><Button icon={<PlusOutlined />} disabled={fields.length >= 50 || !!working} onClick={() => add({ type: 'services' })}>添加迁移对象</Button><Button type="primary" htmlType="submit" loading={working === 'plan'} disabled={!workspace.ready || !!working}>预览迁移差异</Button></Space></>}</Form.List>
      </Form>
    </Card>
    {plan && <Card title="迁移差异与执行计划" className="migration-plan-card" extra={<Tag color={plan.state === 'succeeded' ? 'green' : partial ? 'orange' : 'blue'}>{stateLabels[plan.state] ?? plan.state}</Tag>}>
      <Descriptions size="small" column={{ xs: 1, md: 2 }} items={[{ key: 'id', label: '计划 ID', children: <Typography.Text copyable className="mono">{plan.id}</Typography.Text> }, { key: 'target', label: '目标工作区', children: plan.target_workspace_name }, { key: 'expires', label: '有效至', children: formatTime(plan.expires_at) }, { key: 'budget', label: '读取预算', children: `${plan.budget.pages} 页 / ${plan.budget.records} 条 / ${plan.budget.nodes} 节点` }]} />
      {expired && <Alert type="warning" showIcon message="计划已过期，请重新预览" style={{ margin: '16px 0' }} />}
      {plan.warnings.map((warning, index) => <Alert key={index} type="warning" showIcon message={warning} style={{ margin: '12px 0' }} />)}
      {plan.conflicts.map((conflict, index) => <Alert key={index} type="error" showIcon message={conflict.message} description={<><span className="mono">{conflict.code}</span>{conflict.objects.length > 0 && <div className="mono">{conflict.objects.join(', ')}</div>}</>} style={{ margin: '12px 0' }} />)}
      <Table rowKey="key" pagination={{ pageSize: 10 }} size="small" dataSource={plan.affected} scroll={{ x: 1000 }} columns={[{ title: '对象', width: 240, render: (_, row) => <div><strong>{row.name || row.id}</strong><div className="table-secondary">{entityLabels[row.type] ?? row.type} · {row.id}</div></div> }, { title: '迁移前标签', width: 240, render: (_, row) => <Space wrap>{row.before_tags.map(tag => <Tag key={tag}>{tag}</Tag>)}</Space> }, { title: '迁移后标签', width: 240, render: (_, row) => <Space wrap>{row.after_tags.map(tag => <Tag key={tag} color="green">{tag}</Tag>)}</Space> }, { title: '处理方式', width: 140, render: (_, row) => <Tag>{row.inherited_only ? '继承父对象归属' : '更新归属标签'}</Tag> }, { title: '执行状态', width: 110, render: (_, row) => stateLabels[row.status] ?? row.status }]} />
      {plan.references.length > 0 && <><Typography.Title level={5}>依赖与共享引用</Typography.Title><Table rowKey={row => `${row.type}:${row.id}`} size="small" pagination={{ pageSize: 10 }} dataSource={plan.references} scroll={{ x: 750 }} columns={[{ title: '类型', dataIndex: 'type' }, { title: '对象', render: (_, row) => row.name || row.id }, { title: '工作区', dataIndex: 'workspace_id' }, { title: '归属', render: (_, row) => <Tag color={row.affected ? 'blue' : 'default'}>{row.affected ? '随对象迁移' : '保留共享引用'}</Tag> }]} /></>}
      {terminalReceiptError && !sourceBlocked && <QueryError error={terminalReceiptError} />}
      <Space wrap style={{ marginTop: 20 }}><Button type="primary" disabled={!canApply} loading={working === 'apply'} onClick={apply}>{cluster?.execution_mode==='approval'?'提交审批':partial ? '继续迁移' : '执行迁移'}</Button>{plan.workflow_id&&<Link to={`/workflows/${plan.workflow_id}`}><Button>查看迁移工单</Button></Link>}<Button disabled={!!working || !plan.operation_id || !receiptInspected} loading={working === 'reconcile'} onClick={() => void reconcile()}>核验迁移状态</Button><Button onClick={() => { setParams({}); setError(undefined); setResumeReady(false); }}>新建迁移计划</Button></Space>
      <Typography.Paragraph type="secondary" className="small-note">预览与核验不修改网关配置。继续部分迁移须先核验原回执和全部步骤，再审阅最新差异、输入目标名称，并显式使用新的幂等键；不会自动重试或继续。</Typography.Paragraph>
    </Card>}
  </>;
}
