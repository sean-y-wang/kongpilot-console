import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Form, Input, Modal, Space, Tag, Typography } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { useAuth } from '../app/AuthContext';
import { usePermissions } from '../app/Permissions';
import { useEntityPermissions } from '../app/EntityPermissions';
import { api, ApiError, getApiActorId } from '../api/client';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { redactForDisplay } from '../api/redaction';
import { hasHiddenValue } from '../components/schema-patch';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError, formatTime } from '../components/Shared';
import { entityName } from './entities';
import { PagedIAMLookup } from './IAMLookups';
import { workflowCanPrepare } from './workflow-entity-change.model';
import { safeJsonPreview } from './m7.redaction';
import { annotationWorkflowRequest, annotationWorkflowScope, createAnnotationWorkflowClient, freshAnnotationSession,
  readAnnotationWorkflowAttempt, sameAnnotationWorkflowScope, type AnnotationOperation, type AnnotationWorkflowIntent,
  type AnnotationWorkflowScope, type AnnotationWorkflowSelection } from './entity-annotation-workflow.model';

interface Annotation { description: string; owner_user_id: string | null; metadata: Record<string, unknown>; revision: number; status: 'active' | 'deleted'; deleted_at?: string | null; retention_until?: string | null; }
interface AnnotationDraft extends AnnotationWorkflowSelection { input: Record<string, unknown>; confirmationName: string; }
export function EntityAnnotations({ type, entity }: { type: string; entity: any }) {
  const { clusterId, cluster } = useCluster();
  const { workspaceId, ready, writeBlocked, readonlyWorkspace } = useWorkspace();
  const { user } = useAuth();
  const permission = usePermissions();
  const ability = useEntityPermissions([{ type, id: entity.id }]);
  const { message, modal } = App.useApp();
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<unknown>();
  const [draft, setDraft] = useState<AnnotationDraft>(), [reviewOpen, setReviewOpen] = useState(false), [journalVersion, setJournalVersion] = useState(0);
  const [form] = Form.useForm();
  const scope = ready && canonicalId(user?.id) && user?.permissionsVersion && canonicalId(entity.id) && cluster
    ? annotationWorkflowScope({ actor: user!.id, version: user!.permissionsVersion!, cid: clusterId!, wid: workspaceId!, mode: cluster.execution_mode, entityType: type, entityId: entity.id }) : undefined;
  const journal = useMemo(() => { try { return { attempt: scope ? readAnnotationWorkflowAttempt(scope) : undefined, error: undefined }; }
    catch (error) { return { attempt: undefined, error }; } }, [scope?.actor, scope?.version, scope?.cid, scope?.wid, scope?.mode, type, entity.id, journalVersion]);
  const base = `/clusters/${clusterId}/entity-annotations/${type}/${entity.id}`;
  const query = useQuery({ queryKey: ['annotations', user?.id, user?.permissionsVersion, clusterId, workspaceId, type, entity.id], queryFn: () => api<Annotation>(scopeQuery(base, clusterId, workspaceId)), enabled: !!scope && permission.can('annotations', 'read', entity, { entityType: type }) && ability.can(type, entity.id, 'read'), retry: false });
  const row = query.data;
  const safe = row ? redactForDisplay(row) as Annotation : undefined;
  const metadataText = JSON.stringify(safe?.metadata ?? {}, null, 2);
  const approvalMode = cluster?.execution_mode === 'approval';
  const workflowAllowed = !!scope && workflowCanPrepare(user?.capabilities, scope);
  const structuralBlocked = !scope || writeBlocked || readonlyWorkspace || !!journal.attempt || !!journal.error || approvalMode && !workflowAllowed;
  const blocked = structuralBlocked || !permission.can('annotations', 'write', entity, { entityType: type }) || !ability.can(type, entity.id, 'write');
  const deleteBlocked = structuralBlocked || !permission.can('annotations', 'delete', entity, { entityType: type }) || !ability.can(type, entity.id, 'delete');
  const latest = useRef({ scope, blocked, deleteBlocked, active: true, revision: row?.revision });
  latest.current = { scope, blocked, deleteBlocked, active: true, revision: row?.revision };
  const editing = useRef<{ scope: AnnotationWorkflowScope; revision: number; metadataText: string }>();
  useEffect(() => { setOpen(false); setDraft(undefined); setReviewOpen(false); setError(undefined); editing.current = undefined; form.resetFields(); },
    [clusterId, workspaceId, type, entity.id, user?.id, user?.permissionsVersion, cluster?.execution_mode, form]);
  useEffect(() => { latest.current.active = true; return () => { latest.current.active = false; }; }, []);
  function assertCurrent(captured: AnnotationWorkflowScope, action: 'write' | 'delete') {
    if (!latest.current.active || getApiActorId() !== captured.actor || !latest.current.scope || !sameAnnotationWorkflowScope(captured, latest.current.scope)
      || (action === 'delete' ? latest.current.deleteBlocked : latest.current.blocked)) throw new ApiError('账号、权限或实体说明范围已变化。', 409, 'ANNOTATION_WORKFLOW_SCOPE_CHANGED');
  }
  async function refresh() { await client.invalidateQueries({ predicate: query => query.queryKey.includes(clusterId) && query.queryKey.includes(workspaceId) }); }
  const save = useMutation({ mutationFn: async ({ captured, body }: { captured: AnnotationWorkflowScope; body: Record<string, unknown> }) => {
    assertCurrent(captured, 'write'); if (captured.mode !== 'direct' || latest.current.revision !== body.revision) throw new ApiError('实体说明版本已变化，请刷新。', 409, 'ANNOTATION_REVISION_CONFLICT');
    annotationWorkflowRequest(captured, { operation: 'set', annotationRevision: body.revision as number }, body);
    const csrf = await freshAnnotationSession(captured); assertCurrent(captured, 'write');
    await api(scopeQuery(`/clusters/${captured.cid}/entity-annotations/${captured.entityType}/${captured.entityId}`, captured.cid, captured.wid),
      { method: 'PUT', body: JSON.stringify(body), headers: { 'X-CSRF-Token': csrf } }, true); assertCurrent(captured, 'write');
  }, onSuccess: async () => { setOpen(false); form.resetFields(); await refresh(); void message.success('实体说明已保存'); }, onError: setError });
  function edit() { if (!scope || blocked || !row) return; editing.current = { scope, revision: row.revision, metadataText }; form.resetFields(); form.setFieldsValue({ description: safe?.description ?? '', owner_user_id: safe?.owner_user_id ?? '', metadata: metadataText }); setError(undefined); setOpen(true); }
  function changeStatus(action: 'delete' | 'restore') {
    if (!scope || !row || (action === 'delete' ? deleteBlocked : blocked)) return;
    const captured = scope, capturedRevision = row.revision, expected = String(entity.name || entity.username || entity.id);
    mutationConfirm(modal, { title: action === 'delete' ? '将实体说明移入回收状态' : '恢复实体说明', expected: entityName(entity), description: action === 'delete' ? '负责人、说明与扩展元数据进入可恢复状态，网关对象保持有效。' : '恢复此实体的控制台说明与负责人。', danger: action === 'delete', onConfirm: async () => {
      try {
        assertCurrent(captured, action === 'delete' ? 'delete' : 'write'); if (latest.current.revision !== capturedRevision) throw new ApiError('实体说明版本已变化，请刷新。', 409, 'ANNOTATION_REVISION_CONFLICT');
        const operation: AnnotationOperation = action === 'delete' ? 'remove' : 'restore';
        const body = { revision: capturedRevision, confirmed: true, confirm_name: expected };
        annotationWorkflowRequest(captured, { operation, annotationRevision: capturedRevision }, body, expected);
        if (captured.mode === 'approval') { setDraft({ operation, annotationRevision: capturedRevision, input: body, confirmationName: expected }); setReviewOpen(true); return; }
        const csrf = await freshAnnotationSession(captured); assertCurrent(captured, action === 'delete' ? 'delete' : 'write');
        const capturedBase = `/clusters/${captured.cid}/entity-annotations/${captured.entityType}/${captured.entityId}`;
        await api(scopeQuery(action === 'delete' ? capturedBase : `${capturedBase}/restore`, captured.cid, captured.wid),
          { method: action === 'delete' ? 'DELETE' : 'POST', body: JSON.stringify(body), headers: { 'X-CSRF-Token': csrf } }, true);
        assertCurrent(captured, action === 'delete' ? 'delete' : 'write'); await refresh();
      }
      catch (e) { setError(e); throw e; }
    } });
  }
  return <Card size="small" className="annotation-card" title={<Space>实体说明<Tag>{row?.status === 'deleted' ? '元数据回收站' : '控制台元数据'}</Tag></Space>} extra={<Space>{row?.status === 'deleted' ? <Button size="small" disabled={blocked} onClick={() => changeStatus('restore')}>恢复说明</Button> : <><Button size="small" disabled={blocked || !row} onClick={edit}>编辑说明</Button>{!!row?.revision && <Button size="small" danger disabled={deleteBlocked} onClick={() => changeStatus('delete')}>删除说明</Button>}</>}</Space>}>
    {query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}{error ? <QueryError error={error} /> : null}
    {!!journal.error && <QueryError error={journal.error} />}
    {journal.attempt && <Alert type="warning" showIcon message={journal.attempt.state === 'prepared' ? '已有实体说明审批预览' : '原实体说明请求需要核验'}
      description={<Space wrap><Typography.Text className="mono" copyable>{journal.attempt.key}</Typography.Text><Button onClick={() => { setDraft(undefined); setReviewOpen(true); }}>查看与核验</Button></Space>} style={{ marginBottom: 14 }} />}
    {row?.status === 'deleted' && <Alert type="warning" showIcon message="此实体说明已软删除，可在此恢复" description={`删除时间：${formatTime(row.deleted_at)}；保留至：${formatTime(row.retention_until)}`} style={{ marginBottom: 14 }} />}
    <Descriptions size="small" column={1} items={[{ key: 'owner', label: '负责人', children: safe?.owner_user_id ?? '未设置' }, { key: 'description', label: '说明', children: <span style={{ whiteSpace: 'pre-wrap' }}>{safe?.description || '未填写'}</span> }, { key: 'metadata', label: '扩展元数据', children: Object.keys(safe?.metadata ?? {}).length ? <pre className="detail-value-json">{metadataText}</pre> : '未设置' }]} />
    <Modal title="编辑实体说明" open={open} onCancel={() => { setOpen(false); form.resetFields(); }} onOk={() => form.submit()} okText={approvalMode ? '预览变更' : '保存说明'} cancelText="取消" confirmLoading={save.isPending} okButtonProps={{ disabled: blocked }} width={660} destroyOnClose>
      {error ? <QueryError error={error} /> : null}<Alert showIcon type="info" message="请勿在说明或元数据中存放凭证" style={{ marginBottom: 20 }} />
      <Form form={form} layout="vertical" onFinish={values => {
        try {
          const captured = editing.current; if (!captured) throw new Error('编辑范围已变化，请重新打开。'); assertCurrent(captured.scope, 'write');
          if (latest.current.revision !== captured.revision) throw new ApiError('实体说明版本已变化，请刷新。', 409, 'ANNOTATION_REVISION_CONFLICT');
          const body: Record<string, unknown> = { revision: captured.revision, description: values.description ?? '', owner_user_id: values.owner_user_id || null };
          if (values.metadata !== captured.metadataText) { const metadata = JSON.parse(values.metadata); if (hasHiddenValue(metadata)) throw new ApiError('隐藏占位值不能作为新元数据提交。', 400, 'REDACTED_METADATA'); body.metadata = metadata; }
          annotationWorkflowRequest(captured.scope, { operation: 'set', annotationRevision: captured.revision }, body);
          if (captured.scope.mode === 'approval') { setDraft({ operation: 'set', annotationRevision: captured.revision, input: body, confirmationName: String(entity.name || entity.username || entity.id) }); setReviewOpen(true); setOpen(false); form.resetFields(); }
          else save.mutate({ captured: captured.scope, body });
        } catch (error) { setError(error); }
      }}>
        <Form.Item name="description" label="说明"><Input.TextArea rows={4} maxLength={8192} /></Form.Item>
        <Form.Item name="owner_user_id" label="负责人用户 ID" rules={[{ validator: (_, value) => !value || canonicalId(value) ? Promise.resolve() : Promise.reject(new Error('请输入有效的用户 UUID')) }]}><PagedIAMLookup resource="users" label="owner_user_id" clusterId={clusterId} workspaceId={workspaceId} /></Form.Item><Button type="link" size="small" onClick={() => form.setFieldValue('owner_user_id', user?.id)}>设为我（{user?.username}）</Button>
        <Form.Item name="metadata" label="扩展元数据 JSON" rules={[{ validator: (_, value) => { try { const parsed = JSON.parse(value); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(); return Promise.resolve(); } catch { return Promise.reject(new Error('请输入 JSON 对象')); } } }]}><Input.TextArea rows={8} className="mono" spellCheck={false} /></Form.Item>
      </Form>
    </Modal>
    {reviewOpen && scope && <AnnotationApprovalDrawer key={[scope.actor, scope.version, scope.cid, scope.wid, scope.mode, scope.entityType, scope.entityId].join(':')}
      scope={scope} entity={entity} draft={draft} onClose={() => { setReviewOpen(false); setDraft(undefined); }}
      onChange={() => setJournalVersion(value => value + 1)} />}
  </Card>;
}

function AnnotationApprovalDrawer({ scope, entity, draft, onClose, onChange }: {
  scope: AnnotationWorkflowScope; entity: any; draft?: AnnotationDraft; onClose: () => void; onChange: () => void;
}) {
  const { user } = useAuth(), workspace = useWorkspace(), permission = usePermissions(), ability = useEntityPermissions([{ type: scope.entityType, id: scope.entityId }]);
  const { cluster, clusterId } = useCluster(), { modal } = App.useApp(), navigate = useNavigate();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [intent, setIntent] = useState<AnnotationWorkflowIntent>();
  const [journalVersion, setJournalVersion] = useState(0), [workflowId, setWorkflowId] = useState<string>();
  const read = useMemo(() => { try { return { attempt: readAnnotationWorkflowAttempt(scope), error: undefined }; }
    catch (error) { return { attempt: undefined, error }; } }, [scope, journalVersion]);
  const attempt = read.attempt, operation = attempt?.operation ?? draft?.operation;
  const action = operation === 'remove' ? 'delete' : 'write';
  const writable = !!operation && scope.mode === 'approval' && cluster?.execution_mode === 'approval' && clusterId === scope.cid
    && workspace.ready && workspace.workspaceId === scope.wid && !workspace.writeBlocked && !workspace.readonlyWorkspace && workspace.workspace?.status === 'active'
    && user?.id === scope.actor && user.permissionsVersion === scope.version && workflowCanPrepare(user.capabilities, scope)
    && permission.can('annotations', action, entity, { entityType: scope.entityType }) && ability.can(scope.entityType, scope.entityId, action);
  const latest = useRef({ scope, writable, active: true }); latest.current = { scope, writable, active: true };
  useEffect(() => { latest.current.active = true; return () => { latest.current.active = false; }; }, []);
  const client = useMemo(() => createAnnotationWorkflowClient({ scope: () => latest.current.scope,
    assertCurrent(captured, writing) {
      if (!latest.current.active || getApiActorId() !== captured.actor || !sameAnnotationWorkflowScope(captured, latest.current.scope)
        || writing && !latest.current.writable) throw new ApiError('账号、权限或实体说明范围已变化。', 409, 'ANNOTATION_WORKFLOW_SCOPE_CHANGED');
    }, onChange() { if (latest.current.active) { setJournalVersion(value => value + 1); onChange(); } } }), []);
  useEffect(() => {
    if (!attempt?.intentId || attempt.state !== 'prepared') return;
    let active = true; void client.inspect(attempt).then(row => { if (active) { setIntent(row); setWorkflowId(row.workflowId ?? undefined); } }, error => { if (active) setError(error); });
    return () => { active = false; };
  }, [attempt?.intentId, attempt?.materialHmac, client]);
  async function run(callback: () => Promise<void>) { if (busy) return; setBusy(true); setError(undefined); try { await callback(); } catch (error) { if (latest.current.active) setError(error); } finally { if (latest.current.active) setBusy(false); } }
  function submit() {
    if (!attempt || !intent?.preview || !writable || !intent.capabilities.submit) return;
    mutationConfirm(modal, { title: '提交实体说明变更工单', expected: intent.preview.confirmationName,
      description: operation === 'remove' ? '审批执行后，实体说明进入可恢复状态。' : operation === 'restore' ? '审批执行后，恢复此实体的说明与负责人。' : '审批执行后，更新此实体的说明、负责人和扩展元数据。',
      danger: operation === 'remove', okText: '确认提交工单', onConfirm: async () => {
        setBusy(true); setError(undefined);
        try { const id = await client.submit(attempt, intent); if (latest.current.active) { setWorkflowId(id); setIntent(undefined); } }
        catch (error) { if (latest.current.active) setError(error); throw error; }
        finally { if (latest.current.active) setBusy(false); }
      } });
  }
  const prepared = attempt?.stage === 'prepare' && attempt.state === 'prepared';
  return <Drawer title="实体说明变更审批" open width={760} onClose={onClose} destroyOnClose>
    {!!read.error && <QueryError error={read.error} />}{!!error && <QueryError error={error} />}
    <Descriptions size="small" column={1} items={[{ key: 'entity', label: '实体', children: `${scope.entityType} / ${scope.entityId}` },
      { key: 'operation', label: '操作', children: operation === 'set' ? '更新说明' : operation === 'remove' ? '删除说明' : operation === 'restore' ? '恢复说明' : '核验原请求' },
      { key: 'revision', label: '原备注版本', children: attempt?.annotationRevision ?? draft?.annotationRevision ?? '—' },
      ...(intent ? [{ key: 'expires', label: '预览有效期', children: formatTime(intent.expiresAt) }] : [])]} />
    {attempt && <Alert type={prepared ? 'info' : 'warning'} showIcon message={prepared ? '预览已准备' : '按原请求键核验结果'}
      description={<Typography.Text className="mono" copyable>{attempt.key}</Typography.Text>} style={{ margin: '16px 0' }} />}
    {intent?.preview ? <><Typography.Title level={5}>变更前</Typography.Title><pre className="json-preview">{safeJsonPreview(intent.preview.before)}</pre>
      <Typography.Title level={5}>变更后</Typography.Title><pre className="json-preview">{safeJsonPreview(intent.preview.after)}</pre>
      {intent.preview.retentionDays !== undefined && <Typography.Paragraph type="secondary">回收保留期：{intent.preview.retentionDays} 天</Typography.Paragraph>}</>
      : draft && !attempt ? <><Typography.Title level={5}>待预览的变更</Typography.Title><pre className="json-preview">{safeJsonPreview(draft.input)}</pre></> : null}
    <Space wrap style={{ marginTop: 20 }}>
      {!attempt && !read.error && !workflowId && draft && <Button type="primary" disabled={!writable} loading={busy} onClick={() => void run(async () => {
        const row = await client.prepare(draft, draft.input, draft.confirmationName); if (latest.current.active) setIntent(row);
      })}>生成审批预览</Button>}
      {attempt && <Button loading={busy} onClick={() => void run(async () => {
        const result = await client.recover(attempt); if (latest.current.active) { if (result.intent) setIntent(result.intent); if (result.workflowId) setWorkflowId(result.workflowId); }
      })}>核验原请求</Button>}
      {prepared && intent?.preview && !workflowId && <><Button type="primary" loading={busy} disabled={!writable || !intent.capabilities.submit || Date.parse(intent.expiresAt) <= Date.now()} onClick={submit}>提交审批</Button>
        <Button disabled={busy} onClick={() => void run(async () => { await client.discardPrepared(attempt!); if (latest.current.active) { setIntent(undefined); onClose(); } })}>放弃此预览</Button></>}
      {workflowId && <Button type="primary" disabled={busy} onClick={() => navigate(`/workflows/${workflowId}?workspaceId=${scope.wid}`)}>查看变更工单</Button>}
    </Space>
  </Drawer>;
}
