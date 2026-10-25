import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Button, Card, Checkbox, Descriptions, Drawer, Form, Modal, Space, Spin, Table, Tabs, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { useEntityPermissions } from '../app/EntityPermissions';
import { usePermissions } from '../app/Permissions';
import { useAuth } from '../app/AuthContext';
import { api, ApiError, errorMessage, getApiActorId } from '../api/client';
import { CursorPagination, useCursorPages } from '../components/CursorPagination';
import { mutationConfirm } from '../components/MutationConfirm';
import { KongSchemaForm, prepareFormValues, schemaFields, type KongSchema } from '../components/KongSchemaForm';
import { QueryError } from '../components/Shared';
import { EntityEditor } from './EntityEditor';
import { entityName, entityTime, type EntityPageData } from './entities';
import { workflowCanPrepare, type EntityChangeIntent } from './workflow-entity-change.model';
import { credentialWorkflowKinds, credentialWorkflowScope, credentialWorkflowSelection, credentialWorkflowFormDefaults, createCredentialWorkflowClient,
  readCredentialWorkflowAttempt, sameCredentialWorkflowScope, type CredentialWorkflowScope, type CredentialWorkflowKind,
  type CredentialWorkflowSelection } from './credential-workflow.model';

export function CredentialManager({ consumerId, parentEntity }: { consumerId: string; parentEntity?: any }) {
  const { clusterId, cluster } = useCluster(), workspace = useWorkspace(), { workspaceId, ready, writeBlocked, readonlyWorkspace } = workspace;
  const { user } = useAuth(), permission = usePermissions(), parentAbility = useEntityPermissions([{ type: 'consumers', id: consumerId }]);
  const { message, modal } = App.useApp(), queryClient = useQueryClient();
  const [operationError, setOperationError] = useState<unknown>(), [kind, setKind] = useState<CredentialWorkflowKind>('key-auth');
  const [editor, setEditor] = useState<{ entity?: any }>(), [approval, setApproval] = useState<CredentialWorkflowSelection>();
  const [reveal, setReveal] = useState(false), [revealed, setRevealed] = useState<any>(), [journalVersion, setJournalVersion] = useState(0);
  const scoped = ready && !!canonicalId(user?.id) && !!user?.permissionsVersion && !!canonicalId(consumerId) && !!cluster?.execution_mode;
  const scope = scoped ? credentialWorkflowScope({ actor: user!.id, version: user!.permissionsVersion, cid: clusterId, wid: workspaceId,
    mode: cluster!.execution_mode, consumerId, credentialKind: kind }) : undefined;
  const journal = useMemo(() => {
    try { return { attempt: scope ? readCredentialWorkflowAttempt(scope) : undefined, error: undefined }; }
    catch (error) { return { attempt: undefined, error }; }
  }, [scope?.actor, scope?.version, scope?.cid, scope?.wid, scope?.mode, consumerId, kind, journalVersion]);
  const attempt = journal.attempt;
  useEffect(() => { setEditor(undefined); setApproval(undefined); setReveal(false); setRevealed(undefined); setOperationError(undefined); },
    [clusterId, workspaceId, consumerId, kind, user?.id, user?.permissionsVersion, cluster?.execution_mode]);
  const pages = useCursorPages([clusterId, workspaceId, user?.id, user?.permissionsVersion, consumerId, kind].join(':'));
  const base = '/clusters/' + clusterId + '/consumers/' + consumerId + '/credentials/' + kind;
  const query = useQuery({ queryKey: ['credentials', clusterId, workspaceId, user?.id, user?.permissionsVersion, consumerId, kind, pages.cursor],
    queryFn: ({ signal }) => api<EntityPageData>(scopeQuery(base + '?size=20' + (pages.cursor ? '&cursor=' + encodeURIComponent(pages.cursor) : ''), clusterId, workspaceId), { signal }),
    enabled: scoped, retry: false });
  const abilities = useEntityPermissions((query.data?.items ?? []).map(entity => ({ type: kind, id: entity.id, parent_id: consumerId })));
  const approvalMode = cluster?.execution_mode === 'approval', blocked = !scoped || writeBlocked || readonlyWorkspace || !!attempt || !!journal.error;
  const workflowAllowed = !!scope && workflowCanPrepare(user?.capabilities, scope);
  const latest = useRef({ scope, blocked }); latest.current = { scope, blocked };
  function open(action: 'create' | 'update' | 'delete', entity?: any) {
    try {
      if (blocked || !scope || approvalMode && !workflowAllowed) return;
      const selection = credentialWorkflowSelection(scope, action, entity);
      setReveal(false); if (approvalMode) setApproval(selection); else if (action === 'delete') remove(entity); else setEditor(entity ? { entity } : {});
    } catch (error) { setOperationError(error); }
  }
  function remove(entity: any) {
    const captured = scope;
    mutationConfirm(modal, { title: '将凭证移入回收站', expected: entityName(entity),
      description: '删除后凭证将失效。Basic-auth 仅在已保存原密码时支持可恢复删除。', onConfirm: async () => {
        try {
          if (!captured || getApiActorId() !== captured.actor || !latest.current.scope || latest.current.blocked
            || !sameCredentialWorkflowScope(captured, latest.current.scope)) throw new ApiError('操作范围已变化。', 409, 'CREDENTIAL_WORKFLOW_SCOPE_CHANGED');
          await api(scopeQuery(base + '/' + entity.id, captured.cid, captured.wid), { method: 'DELETE',
            body: JSON.stringify({ confirmed: true, confirm_name: entityName(entity) }) }, true);
          await queryClient.invalidateQueries({ predicate: query => query.queryKey.includes(clusterId) }); void message.success('凭证已移入回收站');
        } catch (error) { setOperationError(error); void message.error(errorMessage(error)); throw error; }
      } });
  }
  return <>
    <Tabs activeKey={kind} onChange={value => setKind(value as CredentialWorkflowKind)} items={credentialWorkflowKinds.map(value => ({ key: value, label: value }))} />
    <div className="embedded-toolbar"><Space><Button icon={<ReloadOutlined />} onClick={() => void query.refetch()}>刷新</Button>
      <Button type="primary" icon={<PlusOutlined />} disabled={blocked || !parentAbility.can('consumers', consumerId, 'write') || approvalMode && !workflowAllowed} onClick={() => open('create')}>创建凭证</Button></Space></div>
    {attempt && <Alert type="warning" showIcon message={attempt.state === 'prepared' ? '已有凭证变更预览' : '原凭证请求需要核验'}
      description={<Space wrap><Typography.Text className="mono" copyable>{attempt.key}</Typography.Text>
        <Button onClick={() => setApproval({ action: attempt.action, credentialId: attempt.credentialId })}>查看与核验</Button></Space>} style={{ marginBottom: 16 }} />}
    {!!journal.error && <QueryError error={journal.error} />}{!!operationError && <QueryError error={operationError} />}
    {abilities.query.isError && <QueryError error={abilities.query.error} retry={() => void abilities.query.refetch()} />}{query.isError && <QueryError error={query.error} />}
    <Table size="small" rowKey="id" pagination={false} loading={query.isFetching} dataSource={query.data?.items ?? []} scroll={{ x: 700 }} columns={[
      { title: '凭证 ID', dataIndex: 'id', width: 320, render: value => <Typography.Text copyable className="mono">{value}</Typography.Text> },
      { title: '公开标识', render: (_, entity) => entity.username ?? entity.name ?? entity.group ?? entity.algorithm ?? '—' },
      { title: '创建时间', render: (_, entity) => entityTime(entity.created_at) },
      { title: '操作', width: 120, render: (_, entity) => <Space size={0}>
        <Button type="link" size="small" disabled={blocked || !abilities.can(kind, entity.id, 'write') || approvalMode && !workflowAllowed} onClick={() => open('update', entity)}>编辑</Button>
        <Button danger type="link" size="small" disabled={blocked || !abilities.can(kind, entity.id, 'delete') || approvalMode && !workflowAllowed} onClick={() => open('delete', entity)}>删除</Button>
      </Space> },
    ]} />
    <CursorPagination pages={pages} count={query.data?.items.length ?? 0} size={20} nextCursor={query.data?.nextCursor} loading={query.isFetching} />
    {editor && !approvalMode && <EntityEditor type={kind} schemaType={kind} endpoint={base} entity={editor.entity} parentEntity={parentEntity} parentId={consumerId} open omitFields={['consumer']}
      requestQuery={reveal ? '?reveal=true' : ''} onClose={() => setEditor(undefined)} onSaved={result => { if (reveal) setRevealed(result.entity ?? result); }}>
      {(editor.entity ? abilities.can(kind, editor.entity.id, 'reveal') : permission.can('secrets', 'read')) &&
        <Checkbox checked={reveal} onChange={event => setReveal(event.target.checked)}>本次保存后授权显示凭证秘密</Checkbox>}
    </EntityEditor>}
    {approval && scope && <CredentialApprovalDrawer key={[scope.actor, scope.version, scope.cid, scope.wid, scope.mode, consumerId, kind, approval.action, approval.credentialId ?? 'new'].join(':')}
      scope={scope} selection={approval} onClose={() => setApproval(undefined)} onChange={() => setJournalVersion(value => value + 1)} />}
    <Modal title="本次授权的凭证内容" open={!!revealed} footer={<Button onClick={() => setRevealed(undefined)}>关闭并清除</Button>} onCancel={() => setRevealed(undefined)} destroyOnClose>
      <Alert type="warning" showIcon message="此内容包含敏感凭证，请妥善保管。" style={{ marginBottom: 16 }} /><pre className="json-preview">{JSON.stringify(revealed, null, 2)}</pre>
    </Modal>
  </>;
}

function CredentialApprovalDrawer({ scope, selection, onClose, onChange }: { scope: CredentialWorkflowScope; selection: CredentialWorkflowSelection; onClose: () => void; onChange: () => void }) {
  const { user } = useAuth(), workspace = useWorkspace(), { modal } = App.useApp(), navigate = useNavigate(), [form] = Form.useForm();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [intent, setIntent] = useState<EntityChangeIntent>();
  const [journalVersion, setJournalVersion] = useState(0), [notObserved, setNotObserved] = useState(false);
  const ability = useEntityPermissions(selection.credentialId ? [{ type: scope.credentialKind, id: selection.credentialId, parent_id: scope.consumerId }] : [{ type: 'consumers', id: scope.consumerId }]);
  const writable = scope.mode==='approval' && workspace.ready && !workspace.writeBlocked && !workspace.readonlyWorkspace && workspace.workspace?.status === 'active'
    && workflowCanPrepare(user?.capabilities, scope) && ability.can(selection.credentialId ? scope.credentialKind : 'consumers',
      selection.credentialId ?? scope.consumerId, selection.action === 'delete' ? 'delete' : 'write');
  const latest = useRef({ scope, writable, active: true }); latest.current = { scope, writable, active: true };
  useEffect(() => { latest.current.active = true; return () => { latest.current.active = false; form.resetFields(); }; }, [form]);
  const client = useMemo(() => createCredentialWorkflowClient({ scope: () => latest.current.scope,
    assertCurrent(captured, writing) {
      if (!latest.current.active || getApiActorId() !== captured.actor || !sameCredentialWorkflowScope(captured, latest.current.scope)
        || writing && !latest.current.writable) throw new ApiError('账号、权限或凭证范围已变化。', 409, 'CREDENTIAL_WORKFLOW_SCOPE_CHANGED');
    }, onChange() { if (latest.current.active) { setJournalVersion(value => value + 1); onChange(); } } }), []);
  const attempt = useMemo(() => readCredentialWorkflowAttempt(scope), [scope, journalVersion]);
  const scopedPath = (resource: string) => scopeQuery('/clusters/' + scope.cid + '/' + resource, scope.cid, scope.wid);
  const parent = useQuery({ queryKey: ['credential-workflow-parent', scope.actor, scope.version, scope.cid, scope.wid, scope.consumerId],
    queryFn: ({ signal }) => api<any>(scopedPath('entities/consumers/' + scope.consumerId), { signal }), retry: false, staleTime: 0, gcTime: 0 });
  const before = useQuery({ queryKey: ['credential-workflow-before', scope.actor, scope.version, scope.cid, scope.wid, scope.consumerId, scope.credentialKind, selection.credentialId],
    queryFn: ({ signal }) => api<any>(scopedPath('consumers/' + scope.consumerId + '/credentials/' + scope.credentialKind + '/' + selection.credentialId), { signal }),
    enabled: !!selection.credentialId && !attempt, retry: false, staleTime: 0, gcTime: 0 });
  const schema = useQuery({ queryKey: ['credential-workflow-schema', scope.actor, scope.version, scope.cid, scope.wid, scope.credentialKind],
    queryFn: ({ signal }) => api<KongSchema>(scopedPath('schemas/' + scope.credentialKind), { signal }), enabled: selection.action !== 'delete' && !attempt, retry: false, staleTime: 0, gcTime: 0 });
  useEffect(() => { if (schema.data) form.setFieldsValue(credentialWorkflowFormDefaults(prepareFormValues(schema.data, before.data?.entity ?? {}, !!selection.credentialId))); }, [schema.data, before.data, form, selection.credentialId]);
  useEffect(() => {
    if (!attempt?.intentId || attempt.state !== 'prepared') return;
    let active = true; void client.inspect(attempt).then(value => { if (active) setIntent(value); }, value => { if (active) setError(value); });
    return () => { active = false; };
  }, [attempt?.intentId, attempt?.revision, attempt?.materialHmac, client]);
  const renderedSchema = schema.data ? { ...schema.data, fields: schemaFields(schema.data).filter(([name]) =>
    !['id', 'consumer', 'created_at', 'updated_at', 'ttl'].includes(name)).map(([name, value]) => ({ [name]: value })) } : undefined;
  async function prepare(payload?: unknown) {
    setBusy(true); setError(undefined);
    try {
      if (!writable || attempt) throw new Error('当前凭证变更尚不可准备。');
      const freshParent = await parent.refetch();
      if (freshParent.error || freshParent.data?.entity?.id !== scope.consumerId) throw freshParent.error ?? new Error('Consumer 已变化，请刷新。');
      let name: string = scope.credentialKind;
      if (selection.credentialId) {
        const fresh = await before.refetch(); if (fresh.error) throw fresh.error;
        const row = fresh.data?.entity, tuple = credentialWorkflowSelection(scope, selection.action, row);
        if (tuple.credentialId !== selection.credentialId) throw new Error('当前凭证已变化。'); name = entityName(row);
      }
      const result = await client.prepare(selection, payload, selection.action === 'delete' ? name : undefined);
      if (latest.current.active) { setIntent(result); form.resetFields(); }
    } catch (value) { if (latest.current.active) setError(value); throw value; }
    finally { if (latest.current.active) setBusy(false); }
  }
  function confirmPrepare(payload?: unknown) {
    mutationConfirm(modal, { title: selection.action === 'delete' ? '准备凭证回收站工单' : '准备凭证变更',
      expected: selection.credentialId ?? scope.credentialKind, danger: selection.action === 'delete', okText: '生成变更预览',
      description: selection.action === 'delete' ? '审批通过并执行后，凭证将失效并移入回收站。Basic-auth 需要已保存原密码才能恢复。' : '生成安全变更预览，审阅后提交工单。此步骤不修改网关凭证。',
      onConfirm: () => prepare(payload) });
  }
  function submit() {
    if (!attempt || !intent || !writable || busy) return;
    mutationConfirm(modal, { title: selection.action === 'delete' ? '确认提交凭证删除工单' : '确认提交凭证变更工单',
      expected: 'native-change', danger: selection.action === 'delete', okText: '提交工单', description: '提交当前封存预览，审批与网关执行在工单中完成。',
      onConfirm: async () => {
        setBusy(true); setError(undefined);
        try { const workflowId = await client.submit(attempt, intent); if (latest.current.active) { onClose(); navigate('/workflows/' + workflowId); } }
        catch (value) { if (latest.current.active) setError(value); throw value; }
        finally { if (latest.current.active) setBusy(false); }
      } });
  }
  async function recover() {
    if (!attempt || busy) return; setBusy(true); setError(undefined);
    try {
      const result = await client.recover(attempt); if (!latest.current.active) return;
      setNotObserved(result.notPrepared === true); if (result.intent) setIntent(result.intent);
      if (result.workflowId) { onClose(); navigate('/workflows/' + result.workflowId); }
    } catch (value) { if (latest.current.active) setError(value); }
    finally { if (latest.current.active) setBusy(false); }
  }
  function discardPrepared() {
    if(!attempt||attempt.state!=='prepared'||busy)return;
    mutationConfirm(modal,{title:'关闭未提交的凭证预览',expected:'discard-preview',danger:false,okText:'关闭预览',
      description:'只关闭当前标签页的未提交预览。已提交的工单与未知请求不能通过此操作清除。',onConfirm:async()=>{
        setBusy(true);try{await client.discardPrepared(attempt);if(latest.current.active)onClose();}
        catch(value){if(latest.current.active)setError(value);throw value;}finally{if(latest.current.active)setBusy(false);}
      }});
  }
  return <Drawer open title={selection.action === 'delete' ? '凭证删除工单' : '凭证变更工单'} width={820} destroyOnHidden onClose={() => { form.resetFields(); onClose(); }}
    extra={intent ? <Space><Button disabled={busy||attempt?.state!=='prepared'||!!intent.workflowId} onClick={discardPrepared}>关闭预览</Button><Button type="primary" loading={busy} disabled={!writable || attempt?.state !== 'prepared' || intent.capabilities.submit !== true || !!intent.workflowId} onClick={submit}>提交工单</Button></Space>
      : <Button type="primary" loading={busy} disabled={!writable || !!attempt || !!parent.error || selection.action !== 'delete' && !renderedSchema || !!before.error || !!selection.credentialId && !before.data}
        onClick={() => selection.action === 'delete' ? confirmPrepare() : form.submit()}>生成变更预览</Button>}>
    <Descriptions size="small" column={1} items={[{ key: 'consumer', label: 'Consumer', children: <Typography.Text className="mono">{scope.consumerId}</Typography.Text> },
      { key: 'kind', label: '凭证类型', children: scope.credentialKind }, { key: 'credential', label: '凭证 ID', children: selection.credentialId ?? '执行时创建' }]} />
    {attempt && attempt.state !== 'prepared' && <Alert type="warning" showIcon message="原请求结果待核验，不会重新提交"
      description={<Space wrap><Typography.Text className="mono" copyable>{attempt.key}</Typography.Text><Button loading={busy} onClick={() => void recover()}>只读核验原请求</Button></Space>} style={{ marginTop: 16 }} />}
    {notObserved && <Alert type="warning" showIcon message="当前尚未观察到原准备记录" description="保留原请求键继续核验，不能据此重复提交。" style={{ marginTop: 16 }} />}
    {!!error && <QueryError error={error} />}{parent.error && <QueryError error={parent.error} />}{before.error && <QueryError error={before.error} />}{schema.error && <QueryError error={schema.error} />}{ability.query.error && <QueryError error={ability.query.error} />}
    {intent ? <Space direction="vertical" style={{ width: '100%', marginTop: 20 }}><Card title="安全变更预览">
      <Descriptions size="small" column={2} items={[{ key: 'revision', label: '预览版本', children: intent.revision }, { key: 'mode', label: '执行模式', children: '工单审批' }]} />
      {intent.review.changes.map(row => <div key={row.nativeId}><Typography.Text className="mono">{row.nativeId}</Typography.Text>
        <Card size="small" title="变更前" style={{ marginTop: 12 }}><pre className="json-preview">{JSON.stringify(row.before, null, 2)}</pre></Card>
        <Card size="small" title="变更后" style={{ marginTop: 12 }}><pre className="json-preview">{JSON.stringify(row.after, null, 2)}</pre></Card></div>)}
    </Card>{intent.review.recovery.blockerCodes.filter(code => code !== 'EXECUTION_BASELINE_REQUIRED').length > 0 &&
      <Alert type="warning" showIcon message="当前变更存在恢复限制" description={intent.review.recovery.blockerCodes.filter(code => code !== 'EXECUTION_BASELINE_REQUIRED').join('、')} />}</Space>
      : parent.isFetching || before.isFetching || schema.isFetching ? <Spin />
        : !attempt && renderedSchema && <KongSchemaForm schema={renderedSchema} form={form} editing={!!selection.credentialId} entityType={scope.credentialKind} onFinish={confirmPrepare} />}
  </Drawer>;
}
