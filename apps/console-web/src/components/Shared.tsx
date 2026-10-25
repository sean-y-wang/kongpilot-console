import { useRef, useState } from 'react';
import { Alert, App, Badge, Button, Empty, Space, Typography } from 'antd';
import { ReloadOutlined, PlusOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { api, ApiError, errorMessage, getApiActorId } from '../api/client';
import { redactForDisplay } from '../api/redaction';
import { useOptionalCluster } from '../app/ClusterContext';
import { useOptionalWorkspace } from '../app/WorkspaceContext';
import { receiptProvesCompletion, scopeQuery } from '../api/workspace-scope';
import { usePermissions } from '../app/Permissions';
import type { Session } from '../api/types';
import { mutationConfirm } from './MutationConfirm';
import { portalWorkflowReceiptPath, workflowRecoveryProvesCompletion } from '../api/workflow-recovery';
import { governanceCan, governanceReconcileConfirmation, governanceRecoveryReference, governanceReceiptPath, governanceReceiptResult, governanceSafeValue } from '../features/governance.model';
import { isToolboxKind, toolboxReceiptPath, toolboxReceiptComplete } from '../features/m9.model';
import { isVitalsSetupReceipt, vitalsSetupReceiptPath, vitalsSetupReceiptProvesCompletion } from '../api/recovery';
import { isM7Kind, m7ReceiptPath, m7ReceiptResult } from '../features/m7.results';
import { isConfigurationKind, configurationReceiptPath, configurationReceiptResult, redactConfigurationValue, configurationOriginalJobPath, configurationOriginalJobResult, configurationAbandonmentAuthority, configurationAbandonmentReferencesToResolve, sameConfigurationIdentity } from '../features/m8.model';

export function PageHeading({ title, description, extra }: { title: string; description?: string; extra?: React.ReactNode }) {
  return <div className="page-heading"><div><Typography.Title level={2}>{title}</Typography.Title>{description && <Typography.Paragraph type="secondary">{description}</Typography.Paragraph>}</div><Space wrap>{extra}</Space></div>;
}

export function QueryError({ error, retry, persistent = false }: { error: unknown; retry?: () => void; persistent?: boolean }) {
  const context = useOptionalCluster();
  const workspace = useOptionalWorkspace();
  const { modal, message } = App.useApp();
  const queryClient = useQueryClient();
  const permission = usePermissions(), selected = { actor: getApiActorId(), version: permission.version, cid: context?.clusterId, wid: workspace?.workspaceId }, current = useRef({ selected, workspace });
  current.current = { selected, workspace };
  const [checking, setChecking] = useState(false);
  const recovery = error instanceof ApiError ? error.recovery : undefined;
  const savedReference = recovery?.idempotencyKey && workspace?.references.some(ref => ref.idempotencyKey === recovery.idempotencyKey && ref.kind === recovery.kind && ref.domain === recovery.domain && ref.cid === recovery.clusterId && ref.wid === recovery.workspaceId);
  async function checkReceipt() {
    setChecking(true);
    const explicitScope = isM7Kind(recovery?.kind) || isConfigurationKind(recovery?.kind) || isToolboxKind(recovery?.kind) || recovery?.kind === 'governance';
    const clusterId = explicitScope ? recovery?.clusterId : recovery?.clusterId ?? context?.clusterId;
    const endpoint = recovery?.operationId ? recovery.operationId : `by-key/${recovery?.idempotencyKey}`;
    const originalActorId = getApiActorId();
    try {
      const path = recovery?.domain === 'iam' ? `/iam/operations/${endpoint}` : `/clusters/${clusterId}/mutations/${endpoint}`;
      const originalWorkspaceId = explicitScope ? recovery?.workspaceId : recovery?.workspaceId ?? (clusterId === context?.clusterId ? workspace?.workspaceId : undefined);
      if (isConfigurationKind(recovery?.kind) && recovery?.originalJobId) {
        const reference = { ...recovery, actorId: originalActorId }, originalPath = configurationOriginalJobPath(reference), receipt = await api<unknown>(originalPath);
        if (getApiActorId() !== originalActorId) throw new ApiError('登录账号已切换，请重新核验。', 401, 'SESSION_CHANGED');
        const proof = configurationOriginalJobResult(receipt, reference), steps = await api<unknown>(originalPath.replace(/\?/, '/steps?size=20&'));
        if (getApiActorId() !== originalActorId) throw new ApiError('登录账号已切换，请重新核验。', 401, 'SESSION_CHANGED');
        const captured = { ...selected }, inOriginalScope = captured.cid === recovery.clusterId && captured.wid === recovery.workspaceId;
        modal.info({ title: '原作业只读核验', width: 720, content: <><Typography.Paragraph>{proof.label}。读取不会自动解除未决请求。</Typography.Paragraph><Typography.Paragraph type="secondary">逐对象结果仅展示服务器第一页；其余结果请在原作业详情继续按游标读取。</Typography.Paragraph><pre className="json-preview">{JSON.stringify(redactConfigurationValue({ job: receipt, firstStepsPage: steps }), null, 2)}</pre>{reference.abandonmentIntent && reference.originalJobKey && <Button danger disabled={!inOriginalScope || !!workspace?.readonlyWorkspace || !permission.has('snapshots', 'write')} onClick={() => mutationConfirm(modal, { title: '确认停止重试原请求', expected: `abandon:${reference.originalJobId}`, okText: '确认停止重试这一条', description: '这只解除已经收口的这一条原请求阻止。原配置结果仍未决，成功结果和审计永久保留；不重发、不回滚，其他未知请求继续阻止。后续须按当前图重新审阅独立 Diff 并审批。', onConfirm: async () => {
          if (getApiActorId() !== originalActorId || !sameConfigurationIdentity(captured, current.current.selected)) throw new ApiError('当前账号、权限或范围已变化。', 409, 'SCOPE_CHANGED');
          const fresh = await api<Session>('/auth/me'), readback = await api<unknown>(originalPath);
          await api<unknown>(originalPath.replace(/\?/, '/steps?size=20&'));
          if (getApiActorId() !== originalActorId || !sameConfigurationIdentity(captured, current.current.selected)) throw new ApiError('当前账号、权限或范围已变化。', 409, 'SCOPE_CHANGED');
          const authority = configurationAbandonmentAuthority(fresh.user, captured, !current.current.workspace?.readonlyWorkspace);
          const matches = configurationAbandonmentReferencesToResolve(current.current.workspace?.references ?? [], readback, reference, captured, authority, `abandon:${reference.originalJobId}`);
          for (const match of matches) current.current.workspace?.resolveReference(match);
          await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'm8' });
          modal.warning({ title: '原执行已停止重试，保留未决事实', content: '只解除与原作业/原键对应的请求引用。原状态仍为 uncertain；没有把网关结果改为成功，其他未知请求仍保持阻止。' });
        } })}>确认停止重试原请求</Button>}{!inOriginalScope && <Typography.Paragraph type="secondary">回到原集群和原工作区后才能进行显式停止重试确认。</Typography.Paragraph>}</> });
        return;
      }
      const receipt = await api<any>(recovery?.kind === 'governance' ? governanceReceiptPath(governanceRecoveryReference(recovery, originalActorId)) : isToolboxKind(recovery?.kind) ? toolboxReceiptPath(recovery!) : isConfigurationKind(recovery?.kind) ? configurationReceiptPath(recovery!) : isM7Kind(recovery?.kind) ? m7ReceiptPath(recovery!) : recovery?.kind === 'portal' || recovery?.kind === 'workflow' ? portalWorkflowReceiptPath(recovery) : recovery?.kind === 'vitals-setup' ? vitalsSetupReceiptPath(recovery) : recovery?.domain === 'iam' ? path : originalWorkspaceId ? scopeQuery(path, clusterId, originalWorkspaceId) : path);
      if (getApiActorId() !== originalActorId) throw new ApiError('登录账号已切换，请使用当前账号重新核验。', 401, 'SESSION_CHANGED');
      if (recovery?.kind === 'vitals-setup' && !isVitalsSetupReceipt(receipt, recovery)) throw new ApiError('监控回执与原操作范围不一致，仍保留写入阻止。', 0, 'INVALID_SETUP_RECEIPT');
      const governanceReference = recovery?.kind === 'governance' ? governanceRecoveryReference(recovery, originalActorId) : undefined, governanceProof = governanceReference ? governanceReceiptResult(receipt, governanceReference) : undefined;
      const m7Result = governanceProof ?? (isConfigurationKind(recovery?.kind) ? configurationReceiptResult(receipt, { ...recovery!, actorId: originalActorId }) : isM7Kind(recovery?.kind) ? m7ReceiptResult(receipt, recovery!) : undefined);
      const completed = isToolboxKind(recovery?.kind) ? toolboxReceiptComplete(receipt,recovery!,originalActorId) : m7Result ? m7Result.complete : recovery?.kind === 'portal' || recovery?.kind === 'workflow' ? workflowRecoveryProvesCompletion(receipt, recovery) : recovery?.kind === 'vitals-setup' ? vitalsSetupReceiptProvesCompletion(receipt, recovery) : receiptProvesCompletion(receipt);
      window.dispatchEvent(new CustomEvent('kongos:receipt-verified', { detail: { kind: recovery?.kind, domain: recovery?.domain, cid: recovery?.domain === 'iam' ? undefined : clusterId, wid: recovery?.domain === 'iam' ? undefined : originalWorkspaceId, idempotencyKey: recovery?.idempotencyKey, operationId: recovery?.kind ? undefined : receipt?.id ?? recovery?.operationId, completed, state: recovery?.kind === 'vitals-setup' ? receipt.parentState : receipt?.state, result: recovery?.kind === 'vitals-setup' && completed ? receipt.result : undefined } }));
      if (completed && recovery?.idempotencyKey) {
        const reference = workspace?.references.find(item => item.kind === recovery.kind && item.domain === recovery.domain && (recovery.domain === 'iam' || item.cid === clusterId && item.wid === originalWorkspaceId) && item.idempotencyKey === recovery.idempotencyKey);
        if (reference) workspace?.resolveReference(reference);
      }
      if (completed && (recovery?.kind === 'portal' || recovery?.kind === 'workflow')) await queryClient.invalidateQueries({ predicate: query => String(query.queryKey[0]).includes('portal') || String(query.queryKey[0]).includes('workflow') });
      if (completed && recovery?.kind === 'vitals-setup') await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'vitals' && query.queryKey.includes(clusterId) && query.queryKey.includes(originalWorkspaceId) });
      if (completed && m7Result) await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === (recovery?.kind === 'governance' ? 'm10' : isConfigurationKind(recovery?.kind) ? 'm8' : 'm7') });
      modal.info({ title: recovery?.kind === 'vitals-setup' ? '监控配置核验结果' : '操作核验结果', width: 720, content: <><Typography.Paragraph type="secondary">这是只读核验。{m7Result ? `${m7Result.label}。${completed ? recovery?.kind === 'governance' ? '原治理请求已登记；网关变更须在实际配置作业中另行确认。' : isConfigurationKind(recovery?.kind) ? '原配置操作已核验；完整性、产物与逐对象结果请查看作业详情。' : '请求登记已确认，后续任务与投递状态另行读取。' : '保留原操作标识，不能用新键重复提交。'}` : completed ? '回执已证明执行结束，原范围的写入阻止已解除。' : '执行尚未得到完整证明，请保留原操作标识，避免用新的幂等键重复提交。'}{recovery?.kind === 'vitals-setup' && !completed ? ' 插件或设置步骤仍未全部成功，不会自动重发任何步骤。' : ''}</Typography.Paragraph>{governanceProof?.receipt.kind === 'fix-plan' && governanceProof.receipt.metadataReconciliationPending === true && governanceReference && <Button disabled={selected.cid !== governanceReference.clusterId || selected.wid !== governanceReference.workspaceId || !!workspace?.readonlyWorkspace || !permission.has('governance', 'write')} onClick={() => {
        const captured = { ...selected }, reference = governanceReference;
        mutationConfirm(modal, { title: '确认记录已知子结果', expected: `reconcile:${reference.idempotencyKey}`, okText: '确认记录', description: '仅将已经确认的原子结果关联到原请求，不重新生成计划或发送网关变更。', onConfirm: async () => {
          if (getApiActorId() !== reference.actorId || !sameConfigurationIdentity(captured, current.current.selected) || current.current.workspace?.readonlyWorkspace) throw new ApiError('账号或原操作范围已变化。', 409, 'SCOPE_CHANGED');
          const fresh = await api<Session>('/auth/me');
          if (fresh.user.id !== reference.actorId || fresh.user.permissionsVersion !== captured.version || !governanceCan(fresh.user.capabilities, 'governance', 'write', { clusterId: reference.clusterId, workspaceId: reference.workspaceId })) throw new ApiError('当前账号没有原范围记录权限。', 403, 'PERMISSION_DENIED');
          await api(governanceReceiptPath(reference).replace(/\?/, '/reconcile?'), { method: 'POST', headers: { 'X-Idempotency-Key': reference.idempotencyKey }, body: JSON.stringify(governanceReconcileConfirmation(governanceProof.receipt, reference, `reconcile:${reference.idempotencyKey}`)) });
          const observed = await api<unknown>(governanceReceiptPath(reference)), proof = governanceReceiptResult(observed, reference);
          if (getApiActorId() !== reference.actorId || !sameConfigurationIdentity(captured, current.current.selected)) throw new ApiError('账号或原操作范围已变化。', 409, 'SCOPE_CHANGED');
          if (!proof.complete) throw new ApiError('原结果仍未完成关联，请保留原键继续核验。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { kind: 'governance', scope: 'workspace', clusterId: reference.clusterId, workspaceId: reference.workspaceId, idempotencyKey: reference.idempotencyKey, state: 'uncertain' });
          const stored = current.current.workspace?.references.find(item => item.actor_id === reference.actorId && item.kind === 'governance' && item.cid === reference.clusterId && item.wid === reference.workspaceId && item.idempotencyKey === reference.idempotencyKey); if (stored) current.current.workspace?.resolveReference(stored);
          await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'm10' }); modal.info({ title: '原结果已核验', content: proof.label });
        } });
      }}>确认记录已知子结果</Button>}<pre className="json-preview">{JSON.stringify(recovery?.kind === 'governance' ? governanceSafeValue(receipt) : isConfigurationKind(recovery?.kind) ? redactConfigurationValue(receipt) : redactForDisplay(receipt), null, 2)}</pre></> });
    }
    catch (e) { if (e instanceof ApiError && e.status === 404 && recovery?.idempotencyKey) modal.warning({ title: '尚未找到操作记录', content: recovery.originalJobId ? '尚未读取到当前账号可见的原作业，不能据此认定收口未发生；保留原作业和原执行键，不再次发送收口。' : '未找到当前账号可见的持久化回执，不能据此认定写入未发生。请保留原幂等键继续核验；需要重发时必须使用原键，不能生成新键盲目重试。' }); else void message.error(errorMessage(e)); }
    finally { setChecking(false); }
  }
  return <Alert type="error" showIcon message={(error as { definitiveRejection?: boolean } | undefined)?.definitiveRejection === true ? '请求已被服务端明确拒绝（无需核验原请求）' : '请求未完成'} description={<div>{errorMessage(error)}{recovery?.domain === 'iam' && <div className="small-note">控制台元数据操作；核验使用当前账号私有的 IAM 回执。</div>}{(recovery?.kind === 'portal' || recovery?.kind === 'workflow') && <div className="small-note">门户与审批使用原父操作回执；审批决定完成后仍需显式执行，单个网关步骤成功不能代表流程完成。</div>}{recovery?.kind === 'vitals-setup' && <div className="small-note">监控配置使用原幂等键核验全部步骤；单个插件成功不代表监控设置完成。</div>}{recovery?.originalJobId && <div className="small-note">收口只读取原作业：<span className="mono">{recovery.originalJobId}</span>；原执行键：<span className="mono">{recovery.originalJobKey ?? '尚未提供，仅可读取'}</span>。不以收口请求的新键查新作业，不重发。</div>}{recovery?.workspaceId && <div className="small-note">原工作区：<span className="mono">{recovery.workspaceId}</span>；核验始终使用原操作范围。</div>}{(recovery?.operationId || recovery?.idempotencyKey) && (!savedReference || persistent) && <div className="recovery-reference">{!recovery.kind && recovery.operationId ? '操作 ID' : '原幂等键'}：<Typography.Text copyable className="mono">{recovery.kind ? recovery.idempotencyKey : recovery.operationId ?? recovery.idempotencyKey}</Typography.Text><Button size="small" type="link" loading={checking} disabled={isM7Kind(recovery.kind) ? !recovery.idempotencyKey : recovery.kind ? !recovery.clusterId || !recovery.workspaceId || !recovery.idempotencyKey : recovery.domain !== 'iam' && !recovery.clusterId && !context?.clusterId} onClick={() => void checkReceipt()}>核验操作</Button></div>}{recovery?.entryId && <div className="recovery-reference">回收记录：<Typography.Text copyable className="mono">{recovery.entryId}</Typography.Text><Link to={`/recycle-bin?${new URLSearchParams({ entryId: recovery.entryId, ...(recovery.clusterId ? { clusterId: recovery.clusterId } : {}), ...(recovery.workspaceId ? { workspaceId: recovery.workspaceId } : {}) })}`}>查看归档</Link></div>}{recovery?.state && <div className="small-note">执行状态：{recovery.state}。结果未确认前，请先核验操作或查看归档记录。</div>}</div>} action={retry && !recovery?.originalJobId ? <Button size="small" icon={<ReloadOutlined />} onClick={retry}>重试</Button> : undefined} style={{ marginBottom: 20 }} />;
}

export function UncertainOperationsBanner() {
  const context = useOptionalWorkspace();
  if (!context?.references.length) return null;
  return <div data-testid="uncertain-operations"><Alert type="warning" showIcon message="存在需要核验的变更" description="仅保存操作标识，不保存配置或凭证。切换工作区或刷新不会重新提交；原范围的写入在回执证明执行结束前保持阻止。" style={{ marginBottom: 12 }} />{context.references.map(item => <div key={`${item.domain}:${item.kind}:${item.cid}:${item.wid}:${item.idempotencyKey}`} data-testid={`uncertain-operation-${item.idempotencyKey}`}><QueryError persistent error={new ApiError('写入结果待核验。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { domain: item.domain, kind: item.kind, scope: item.scope, clusterId: item.cid, workspaceId: item.wid, idempotencyKey: item.idempotencyKey, operationId: item.operationId, originalJobId: item.originalJobId, originalJobKey: item.originalJobKey, abandonmentIntent: item.abandonmentIntent, state: item.state })} /></div>)}</div>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  const good = ['healthy', 'connected', 'online', 'ok', 'success', 'reachable', 'compatible'].includes(status ?? '');
  const pending = ['pending', 'unknown', 'unprobed', 'unconfigured', 'never', 'unchecked'].includes(status ?? '') || !status;
  const warning = ['incompatible', 'degraded', 'stale', 'unsupported', 'version_mismatch'].includes(status ?? '');
  const labels: Record<string, string> = { healthy: '连接正常', connected: '连接正常', online: '在线', ok: '连接正常', success: '连接正常', reachable: '连接正常', compatible: '兼容', pending: '待探测', unknown: '未探测', unprobed: '未探测', unconfigured: '未配置', never: '未探测', unchecked: '未探测', incompatible: '版本不兼容', version_mismatch: '版本不兼容', unsupported: '版本不支持', degraded: '异常', stale: '结果过期', offline: '不可达', failed: '连接失败', error: '异常', unreachable: '不可达', unhealthy: '连接失败', disabled: '已停用', unauthorized: '认证失败' };
  return <Badge status={good ? 'success' : pending ? 'default' : warning ? 'warning' : 'error'} text={status ? labels[status] ?? status : '未探测'} />;
}

export function formatTime(value?: string | null) {
  if (!value) return '尚未探测';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false });
}

export function NoCluster() {
  const permission = usePermissions();
  return <div className="empty-panel"><Empty description={<><strong>当前账号没有可访问的集群</strong><p>请登记集群，或联系管理员授予相应访问范围。</p></>}>{permission.registry('clusters', 'write') && <Link to="/clusters"><Button type="primary" icon={<PlusOutlined />}>登记集群</Button></Link>}</Empty></div>;
}
