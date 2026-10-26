import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Drawer, Form, Space, Spin, Tag } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { scopeQuery } from '../api/workspace-scope';
import { api, ApiError, getApiActorId, patch, post } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { redactForDisplay } from '../api/redaction';
import { KongSchemaForm, prepareFormValues, formPayload, schemaFields, type KongSchema } from '../components/KongSchemaForm';
import { hasHiddenValue, omitUnchangedHiddenMaps } from '../components/schema-patch';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError } from '../components/Shared';
import { entityLabels, entityName, isEntityType } from './entities';
import { usePermissions } from '../app/Permissions';
import { useEntityPermissions } from '../app/EntityPermissions';
import { permissionModule } from '../api/permissions';
import { requiresPlatformPlugin } from '../api/plugin-policy';
import { publicDraftMaterial } from './draft-material';
import { entityEntryIntentHref, entityEntryPreparationBody, entityEntryScopeReady, type EntityEntryChange } from './entity-entry-change.model';
import { clearWorkflowAttempt, normalizeEntityChangeIntent, readWorkflowAttempt, sameWorkflowIdentity, storeWorkflowAttempt, workflowCanPrepare, type WorkflowIdentity, type WorkflowWriteAttempt } from './workflow-entity-change.model';

/** Shared entity/recycle entry: only prepares a server-owned intent. The
 * original key is retained before POST; no native request or automatic retry. */
export function useEntityChangePreparation({ clusterId, workspaceId, enabled }: { clusterId?: string; workspaceId?: string; enabled: boolean }) {
  const { user } = useAuth(), identity: WorkflowIdentity = { actor: user?.id, version: user?.permissionsVersion, cid: clusterId, wid: workspaceId };
  const identityKey = JSON.stringify(identity), current = useRef(identity), available = useRef(enabled), mounted = useRef(true), running = useRef(false); current.current = identity; available.current = enabled;
  const [state, setState] = useState<{ identityKey: string; attempt?: WorkflowWriteAttempt }>({ identityKey, attempt: readWorkflowAttempt(identity, 'prepare') });
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>();
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setBusy(false); setError(undefined); setState({ identityKey, attempt: readWorkflowAttempt(identity, 'prepare') }); }, [identityKey]);
  const attempt = state.identityKey === identityKey ? state.attempt : readWorkflowAttempt(identity, 'prepare');
  const allowed = enabled && entityEntryScopeReady(identity) && workflowCanPrepare(user?.capabilities, identity);
  function assertCurrent(captured: WorkflowIdentity = identity) {
    if (!mounted.current || !available.current || getApiActorId() !== captured.actor || !sameWorkflowIdentity(captured, current.current)) throw new ApiError('账号、权限或操作范围已切换，请重新审阅。', 409, 'WORKFLOW_SCOPE_CHANGED');
  }
  async function prepare(change: EntityEntryChange) {
    const captured = { ...identity }; assertCurrent(captured);
    if (!allowed || running.current || attempt || readWorkflowAttempt(captured, 'prepare')) throw new ApiError('当前范围无法准备变更，或原请求尚待核验。', 409, 'ENTITY_PREPARATION_BLOCKED');
    const body = entityEntryPreparationBody(change), original: WorkflowWriteAttempt = { ...captured, subject: 'prepare', action: 'prepare', key: newIdempotencyKey(), state: 'pending' };
    storeWorkflowAttempt(original); running.current = true; setBusy(true); setError(undefined); setState({ identityKey, attempt: original });
    let receivedIntentId: string | undefined;
    try {
      const raw = await api<unknown>(scopeQuery(`/clusters/${captured.cid}/entity-changes/prepare`, captured.cid, captured.wid), { method: 'POST', body: JSON.stringify(body), headers: { 'X-Idempotency-Key': original.key } });
      const intent = normalizeEntityChangeIntent(raw); receivedIntentId = intent.id; assertCurrent(captured);
      clearWorkflowAttempt(original); setState({ identityKey, attempt: undefined }); return intent;
    } catch (cause) {
      const unknown = !(cause instanceof ApiError) || cause.status === 0 || cause.status >= 500 || /UNKNOWN|UNCERTAIN|INVALID_RESPONSE|SCOPE_CHANGED|SESSION_CHANGED/.test(cause.code ?? '');
      const retained = unknown ? { ...original, state: 'unknown' as const, ...(receivedIntentId ? { intentId: receivedIntentId } : {}) } : undefined;
      if (retained) storeWorkflowAttempt(retained); else clearWorkflowAttempt(original);
      // This preparation has no native mutation receipt. The local unknown
      // code locks the confirmation without inventing a by-key API domain.
      const error = unknown ? new ApiError(`准备结果尚未确认，请核验原请求后再操作。原请求键：${original.key}`, cause instanceof ApiError ? cause.status : 0, 'ENTITY_PREPARATION_RESULT_UNKNOWN', undefined, cause instanceof ApiError ? cause.requestId : undefined) : cause;
      if (mounted.current && sameWorkflowIdentity(captured, current.current)) { setState({ identityKey, attempt: retained }); setError(error); }
      throw error;
    } finally { running.current = false; if (mounted.current && sameWorkflowIdentity(captured, current.current)) setBusy(false); }
  }
  return { allowed, attempt, busy, error, prepare, assertCurrent };
}

export function EntityEditor({ type, entity, parentEntity, parentId, initialValues, initialDraft, open, onClose, onSaved, endpoint, schemaType, omitFields = [], requestQuery = '', children }: { type: string; entity?: any; parentEntity?: any; parentId?: string; initialValues?: Record<string, any>; initialDraft?: {id:string;revision:number;name:string}; open: boolean; onClose: () => void; onSaved?: (result: any) => void; endpoint?: string; schemaType?: string; omitFields?: string[]; requestQuery?: string; children?: React.ReactNode }) {
  const { clusterId, cluster, kong: kongSupport } = useCluster();
  const kongVersion = cluster?.version;
  const { workspaceId, workspace, ready, writeBlocked, readonlyWorkspace } = useWorkspace();
  const permission = usePermissions();
  const navigate = useNavigate(), actor = getApiActorId(), approval = cluster?.execution_mode === 'approval';
  const preparation = useEntityChangePreparation({ clusterId, workspaceId, enabled: ready && workspace?.status === 'active' && !writeBlocked && !readonlyWorkspace && approval && isEntityType(type) });
  const editorIdentity = JSON.stringify([clusterId, workspaceId, actor, permission.version, type, entity?.id, cluster?.execution_mode]), initialEditorIdentity = useRef(editorIdentity), liveEditorIdentity = useRef(editorIdentity), editorMounted = useRef(true); liveEditorIdentity.current = editorIdentity;
  useEffect(() => { editorMounted.current = true; return () => { editorMounted.current = false; }; }, []);
  const assertEditorScope = () => { if (!editorMounted.current || getApiActorId() !== actor || initialEditorIdentity.current !== liveEditorIdentity.current || !ready || writeBlocked || readonlyWorkspace) throw new ApiError('账号或操作范围已变化，请重新打开表单。', 409, 'SCOPE_CHANGED'); };
  const ability = useEntityPermissions(entity ? [{ type, id: entity.id, ...(parentId ? { parent_id: parentId } : {}) }] : parentEntity ? [{ type: permissionModule(type), id: parentEntity.id }] : []);
  const initialScope = useRef({ clusterId, workspaceId });
  const scopeMismatch = initialScope.current.clusterId !== clusterId || initialScope.current.workspaceId !== workspaceId || initialEditorIdentity.current !== editorIdentity;
  const queryClient = useQueryClient();
  const { message, modal } = App.useApp();
  const [form] = Form.useForm();
  const selectedService = Form.useWatch('service', form), selectedRoute = Form.useWatch('route', form), selectedConsumer = Form.useWatch('consumer', form);
  const bindings = type === 'plugins' ? [{ type: 'services', id: selectedService?.id }, { type: 'routes', id: selectedRoute?.id }, { type: 'consumers', id: selectedConsumer?.id }].filter(item => item.id) : type === 'routes' && selectedService?.id ? [{ type: 'services', id: selectedService.id }] : [];
  const boundAbilities = useEntityPermissions(bindings);
  const bindingWrite = bindings.some(item => boundAbilities.can(item.type, item.id, 'write'));
  const bindingsReadable = bindings.every(item => boundAbilities.can(item.type, item.id, 'read'));
  const nativeCanSave = bindingsReadable && (entity ? ability.can(type, entity.id, 'write') : parentEntity ? ability.can(permissionModule(type), parentEntity.id, 'write') : permission.create(type) || bindingWrite);
  const [serverError, setServerError] = useState<unknown>();
  const [clearHeaders, setClearHeaders] = useState(false);
  const [draft, setDraft] = useState(initialDraft);
  const uncertain = serverError instanceof ApiError && (serverError.recovery?.state === 'uncertain' || /UNCERTAIN|UNKNOWN/.test(serverError.code ?? ''));
  const hiddenHeaders = type === 'routes' && !!entity && hasHiddenValue((redactForDisplay(entity) as Record<string, any>).headers);
  const pluginName = Form.useWatch('name', form);
  const query = useQuery({ queryKey: ['schema', clusterId, workspaceId, actor, permission.version, schemaType ?? type], queryFn: ({ signal }) => api<KongSchema>(scopeQuery(`/clusters/${clusterId}/schemas/${schemaType ?? type}`, clusterId, workspaceId), { signal }), enabled: open && ready && !scopeMismatch });
  const pluginQuery = useQuery({ queryKey: ['plugin-schema', clusterId, workspaceId, actor, permission.version, pluginName], queryFn: ({ signal }) => api<{ form_schema: KongSchema; metadata: any; rules: { notes: string[]; semantic: { description: string }[] } }>(scopeQuery(`/clusters/${clusterId}/plugin-center/schemas/${encodeURIComponent(pluginName)}`, clusterId, workspaceId), { signal }), enabled: open && ready && !scopeMismatch && type === 'plugins' && !!pluginName });
  const platformPlugin = type === 'plugins' && requiresPlatformPlugin(pluginName, pluginQuery.data?.metadata?.known, !!bindings.length);
  const canSave = nativeCanSave && (!platformPlugin || permission.platformAdmin) && (type !== 'plugins' || !!pluginQuery.data);
  const pluginSchema = pluginQuery.data?.form_schema;
  const constraints = pluginQuery.data?.metadata?.constraints;
  const supportedBindings = constraints?.known ? ['全局', ...(['service', 'route', 'consumer'] as const).filter(key => constraints[key]).map(key => key[0].toUpperCase() + key.slice(1))].join(' / ') : '由当前网关 schema 决定';
  const schema = query.data ? { ...query.data, fields: schemaFields(query.data).filter(([name]) => !omitFields.includes(name) && !(clearHeaders && name === 'headers')).map(([name, field]) => ({ [name]: type === 'plugins' && name === 'name' ? { ...field, one_of: cluster?.enabled_plugins } : type === 'plugins' && name === 'config' && pluginSchema ? { ...field, type: 'record', ...pluginSchema } : field })) } : undefined;
  useEffect(() => { if (open && query.data) { form.resetFields(); const values = prepareFormValues(query.data, entity ? { ...(redactForDisplay(entity) as Record<string, any>), ...initialValues } : initialValues, !!entity); if (Array.isArray(values.tags)) values.tags = values.tags.filter((tag: string) => !/^workspace:|^kos-ws-/i.test(tag)); form.setFieldsValue(values); setServerError(undefined); setClearHeaders(false); } }, [open, query.data, entity, initialValues, form]);
  useEffect(() => { if (pluginSchema) form.setFieldValue('config', prepareFormValues(pluginSchema, form.getFieldValue('config'), !!entity, false)); }, [pluginSchema, form, entity]);
  const save = useMutation({ mutationFn: (payload: Record<string, any>) => {
    assertEditorScope();
    if (approval) throw new ApiError('请先生成变更预览并提交工单。', 409, 'APPROVAL_REQUIRED');
    const base = endpoint ?? `/clusters/${clusterId}/entities/${type}`;
    const scoped = scopeQuery(entity ? `${base}/${entity.id}${requestQuery}` : `${base}${requestQuery}`, initialScope.current.clusterId, initialScope.current.workspaceId);
    if (!canSave) throw new ApiError('当前账号没有此对象的写入权限。', 403, 'FORBIDDEN');
    return entity ? patch(scoped, payload) : post(scoped, payload);
  }, onSuccess: async result => { await queryClient.invalidateQueries({ predicate: query => query.queryKey.includes(clusterId) }); void message.success('配置已提交，网关生效可能需要数秒'); onSaved?.(result); onClose(); form.resetFields(); }, onError: error => { setServerError(error); } });
  const saveDraft = useMutation({ mutationFn: async () => {
    if (!schema || scopeMismatch || !permission.has('drafts', 'write')) throw new ApiError('当前范围无法保存草稿。', 403, 'DRAFT_FORBIDDEN');
    const raw = formPayload(schema, form.getFieldsValue(true), !!entity);
    const payload = publicDraftMaterial(raw), name = draft?.name ?? `${form.getFieldValue('name') || form.getFieldValue('username') || entityLabels[type] || type} 草稿`;
    const body = draft ? { revision: draft.revision, name, payload } : { name, entityType: type, ...(entity?.id ? { nativeId: entity.id } : {}), payload };
    return api<any>(scopeQuery(`/clusters/${clusterId}/drafts${draft ? `/${draft.id}` : ''}`,initialScope.current.clusterId,initialScope.current.workspaceId), { method: draft ? 'PATCH' : 'POST', body: JSON.stringify(body) });
  }, onSuccess: result => { if (initialScope.current.clusterId !== clusterId || initialScope.current.workspaceId !== workspaceId) return; setDraft(result.entity); void message.success('公开配置草稿已保存，秘密字段未保存'); }, onError: error => setServerError(error) });
  function stageHeaderClear() {
    mutationConfirm(modal, { title: '清空全部请求头匹配', expected: entityName(entity), description: '此操作会移除公开与隐藏的全部请求头匹配条件，可能扩大路由的匹配范围。确认后仅暂存清空意图，点击“保存配置”才会提交；后端仍会校验凭证查看权限。', okText: '暂存清空', onConfirm: async () => { form.setFieldValue('headers', []); setClearHeaders(true); } });
  }
  function cancelHeaderClear() {
    setClearHeaders(false);
    form.setFieldValue('headers', prepareFormValues(query.data!, redactForDisplay(entity) as Record<string, any>, true).headers);
  }
  return <Drawer title={entity ? `编辑 ${entityLabels[type] ?? type} · ${entityName(entity)}` : `创建 ${entityLabels[type] ?? type}`} width={820} open={open} onClose={() => { onClose(); form.resetFields(); }} destroyOnClose extra={<Space>{permission.has('drafts','write') && ['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'].includes(type) && <Button loading={saveDraft.isPending} disabled={!ready || readonlyWorkspace || scopeMismatch || uncertain || !schema || !nativeCanSave || preparation.busy} onClick={() => saveDraft.mutate()}>保存草稿</Button>}<Button type="primary" loading={save.isPending || preparation.busy} disabled={!ready || writeBlocked || readonlyWorkspace || !canSave || scopeMismatch || uncertain || !query.data || approval && (!preparation.allowed || !!preparation.attempt) || (type === 'plugins' && (!!pluginName && !pluginQuery.data))} onClick={() => form.submit()}>{approval ? '提交变更工单' : '保存配置'}</Button></Space>}>
    <div className="editor-workspace-note">所属工作区：<Tag color="cyan">{workspace?.name ?? '正在加载'}</Tag>归属通过迁移流程变更；普通标签不包含保留的工作区标签。</div>
    {scopeMismatch && <Alert type="warning" showIcon message="操作范围已切换，请关闭表单后在新的工作区重新编辑。" style={{ marginBottom: 20 }} />}
    {type === 'plugins' && <Alert type="warning" showIcon message="全局插件仍会全局运行" description="没有 Service、Route 或 Consumer 绑定的插件作用于整个网关。工作区标签只限制控制台管理归属。" style={{ marginBottom: 20 }} />}
    <Alert type="info" showIcon message="配置生效中提示" description="DB 模式下，成功写入后各节点同步存在数秒延迟。操作结果可在实体详情中重新读取核验。" style={{ marginBottom: 20 }} />
    {approval && <Alert type="info" showIcon message="先预览变更，再提交工单" description={isEntityType(type) ? '确认表单后只生成变更预览；请在工单页面审阅并提交，审批通过后再执行。' : '此子实体请在变更工单的“发起变更”页准备；本表单不会直接执行。'} style={{ marginBottom: 20 }} />}
    {approval && preparation.attempt && <Alert type="warning" showIcon message="原准备请求需要核验，不能重新提交" description={<>原请求键：<code>{preparation.attempt.key}</code>。请在审计记录中核验原准备请求。</>} style={{ marginBottom: 20 }} />}
    {!!preparation.error && <QueryError error={preparation.error} />}
    {!!serverError && <QueryError error={serverError} />}
    {query.isLoading && <Spin />}
    {ability.query.isError && <QueryError error={ability.query.error} retry={() => void ability.query.refetch()} />}{boundAbilities.query.isError && <QueryError error={boundAbilities.query.error} retry={() => void boundAbilities.query.refetch()} />}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}
    {platformPlugin && !permission.platformAdmin && <Alert showIcon type="warning" message="此插件配置需要平台管理员" description="全局插件、pre-function / post-function 脚本插件、file-log 文件写入插件及未知自定义插件仅允许平台管理员修改。选择已授权的绑定对象后，普通插件仍按对象权限校验。" style={{ marginBottom: 20 }} />}{pluginQuery.isError && <QueryError error={pluginQuery.error} retry={() => void pluginQuery.refetch()} />}
    {hiddenHeaders && <Alert type="warning" showIcon message={clearHeaders ? '保存后将清空全部请求头匹配' : '此路由含隐藏的请求头匹配'} description={<><p>{clearHeaders ? '公开与隐藏的请求头条件将一并移除。当前表单已锁定该字段，取消清空可恢复原有条件。' : '修改其他字段时会保留隐藏条件。若要移除所有请求头条件，请明确确认清空；直接删除隐藏行不会清除秘密匹配。'}</p><Space><Button danger disabled={uncertain || save.isPending || clearHeaders || !ability.can(type, entity?.id, 'reveal')} onClick={stageHeaderClear}>清空全部请求头匹配</Button>{clearHeaders && <Button disabled={uncertain || save.isPending} onClick={cancelHeaderClear}>取消清空</Button>}</Space></>} style={{ marginBottom: 20 }} />}
    {pluginQuery.data && <Alert className="plugin-schema-help" type="info" showIcon message={<><Tag>{pluginQuery.data.metadata?.name}</Tag>四种基础绑定可组合使用</>} description={<><p>该插件支持范围：{supportedBindings}。组合绑定按实例选择优先级生效，同名插件仅使用最高层级的已启用实例。</p>{[...(pluginQuery.data.rules?.notes ?? []), ...(pluginQuery.data.rules?.semantic ?? []).map(rule => rule.description)].map((note, index) => <p key={index}>{note}</p>)}<p>条件提示来自 Kong OSS 1.5.1 源码辅助规则{kongSupport.full ? '' : `（当前集群 Kong ${kongVersion ?? ''} 为有限支持，表单字段以该集群 schema 为准）`}；最终校验以网关响应为准。</p></>} style={{ marginBottom: 20 }} />}
    {schema && <KongSchemaForm schema={schema} form={form} editing={!!entity} entityType={type} onFinish={payload => {
      if (Array.isArray(payload.tags) && payload.tags.some((tag: string) => /^workspace:|^kos-ws-/i.test(tag))) { setServerError(new ApiError('工作区标签由系统管理，请通过工作区迁移变更归属。', 400, 'RESERVED_WORKSPACE_TAG', { tags: '请移除手工输入的工作区标签' })); return; }
      const safePayload = entity ? omitUnchangedHiddenMaps(schema, payload, entity) : payload;
      if (clearHeaders) safePayload.headers = null;
      if (approval) {
        if (!canSave || !preparation.allowed || preparation.busy || preparation.attempt || scopeMismatch || uncertain) return;
        mutationConfirm(modal, { title: '确认准备变更工单', expected: entity ? entityName(entity) : entityName(safePayload), danger: false, okText: '生成变更预览', description: '只生成当前配置的变更预览。随后需在工单页面审阅并提交；此步骤不会修改网关。', onConfirm: async () => {
          try { assertEditorScope(); const intent = await preparation.prepare({ kind: 'entity', action: entity ? 'update' : 'create', entityType: type, ...(entity ? { entityId: entity.id } : {}), body: safePayload }); assertEditorScope(); onClose(); form.resetFields(); navigate(entityEntryIntentHref(intent.id)); } catch (error) { setServerError(error); throw error; }
        } });
      } else save.mutate(safePayload);
    }}>{children}</KongSchemaForm>}
  </Drawer>;
}
