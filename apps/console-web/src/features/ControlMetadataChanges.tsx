import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Input, Space, Table, Typography } from 'antd';
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canInScope, canManageRegistry } from '../api/permissions';
import { advanceControlPrepare, beginControlSubmit, clearControlAttempt, controlPreparedAllowed, controlReceiptMatches, markControlPrepared, normalizeControlChange, readControlAttempt, storeControlAttempt, type ControlAttempt, type ControlChange, type ControlIdentity, type ControlReceipt } from '../api/control-changes.model';
import { controlDirectReceiptCompleted, controlNeedsVerification, freshControlSession, prepareControlOnce, readControlOriginal, submitControlOnce, writeControlDirectOnce } from '../api/control-changes';
import type { Session } from '../api/types';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { QueryError, formatTime } from '../components/Shared';
import { safeJsonPreview } from './m7.redaction';

interface ChangeOptions { change: ControlChange; clusterId: string | null; targetWorkspaceId: string | null; allowed: boolean; subject?: Record<string, any>; }
export function useControlMetadataChanges() {
  const auth = useAuth(), cluster = useCluster(), workspace = useWorkspace(), queries = useQueryClient(), navigate = useNavigate(), { message } = App.useApp();
  const journal = (() => { try { return { row: auth.user ? readControlAttempt(auth.user.id) : undefined, error: undefined as unknown }; } catch (error) { return { row: undefined, error }; } })();
  const [attempt, setAttempt] = useState<ControlAttempt | undefined>(journal.row), [prepared, setPrepared] = useState<ControlReceipt>(), [result, setResult] = useState<ControlReceipt>();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(journal.error), [typed, setTyped] = useState(''), [damaged, setDamaged] = useState(!!journal.error);
  const running = useRef(false), mounted = useRef(true), csrf = useRef(''), reviewedScope = useRef('');
  const otherOriginalBlocked = workspace.references.some(r => r.domain === 'iam' || r.cid === cluster.clusterId);
  const live = useRef({ actor: auth.user?.id, version: auth.user?.permissionsVersion, clusterId: cluster.clusterId, selected: '', blocked: otherOriginalBlocked, capabilities: auth.user?.capabilities });
  live.current = { actor: auth.user?.id, version: auth.user?.permissionsVersion, clusterId: cluster.clusterId, selected: `${cluster.clusterId ?? ''}:${workspace.workspaceId ?? ''}`, blocked: otherOriginalBlocked, capabilities: auth.user?.capabilities };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setPrepared(undefined); setResult(undefined); setAttempt(undefined); setError(undefined); setTyped(''); setDamaged(false); csrf.current = ''; if (auth.user) try { setAttempt(readControlAttempt(auth.user.id)); } catch (e) { setError(e); setDamaged(true); } }, [auth.user?.id]);
  useEffect(() => { setPrepared(undefined); setTyped(''); csrf.current = ''; }, [cluster.clusterId, workspace.workspaceId, auth.user?.permissionsVersion]);
  function identity(): ControlIdentity { if (!auth.user) throw new Error('请先登录。'); return { actor: auth.user.id, version: auth.user.permissionsVersion ?? '' }; }
  function assertLive(original: ControlIdentity, selected: string) { if (!mounted.current || getApiActorId() !== original.actor || live.current.actor !== original.actor || live.current.version !== original.version || live.current.selected !== selected || live.current.blocked) throw new ApiError('账号、权限或页面范围已变化，请重新审阅。', 409, 'CONTROL_SESSION_CHANGED'); }
  function load(actor: string) { const row = readControlAttempt(actor); if (mounted.current && live.current.actor === actor) setAttempt(row); return row; }
  function unknown(row: ControlAttempt) { storeControlAttempt({ ...row, state: 'unknown' }); if (mounted.current && live.current.actor === row.actor) setAttempt({ ...row, state: 'unknown' }); }
  async function refresh() { await queries.invalidateQueries({ predicate: q => ['clusters', 'data-sources', 'workspace-registry', 'workspace-options', 'workspace-selection', 'workflows', 'control-changes', 'recycle', 'recycle-preview'].some(k => q.queryKey.includes(k)) }); await auth.reloadCapabilities(); }
  function subjectAllowed(session: Session, options: ChangeOptions) {
    const r = options.change, action = ['deactivate', 'archive', 'purge'].includes(r.operation) ? 'delete' : 'write', cap = session.user.capabilities;
    return r.resource === 'workspaces' ? canInScope(cap, 'workspaces', action, { clusterId: options.clusterId ?? undefined, workspaceId: options.targetWorkspaceId ?? undefined, entityType: 'workspaces', entity: options.subject, potential: r.operation === 'create' }) : r.resource === 'recycle-bin' ? canInScope(cap, 'recycle-bin', 'delete', {clusterId:options.clusterId??undefined,workspaceId:options.targetWorkspaceId??undefined,potential:true,entityType:options.subject?.root_type,entity:{id:options.subject?.original_id}}) : canManageRegistry(cap, r.resource, action, options.clusterId ?? undefined);
  }
  async function execute(options: ChangeOptions): Promise<'direct' | 'prepared'> {
    const original = identity(), selected = live.current.selected, change = normalizeControlChange(options.change, true);
    if (!options.allowed || change.resource !== 'clusters' && options.clusterId !== live.current.clusterId || running.current || damaged || readControlAttempt(original.actor) || live.current.blocked) throw new Error('请先核验原配置请求。');
    running.current = true; setBusy(true); setError(undefined); let command: ControlAttempt | undefined;
    try {
      const session = await freshControlSession(original); assertLive(original, selected); if (!subjectAllowed(session, { ...options, change })) throw new ApiError('当前账号无权修改此对象。', 403, 'CONTROL_SUBJECT_DENIED');
      command = { ...original, key: newIdempotencyKey(), phase: 'direct', state: 'pending', createdAt: new Date().toISOString(), resource: change.resource, operation: change.operation, clusterId: options.clusterId, resourceId: change.resourceId ?? null, targetWorkspaceId: options.targetWorkspaceId };
      storeControlAttempt(command); load(original.actor); let approval = false;
      try { await writeControlDirectOnce(original, change, options.clusterId, options.targetWorkspaceId, command.key, session.csrfToken); assertLive(original, selected); }
      catch (e) {
        if (controlNeedsVerification(e) || e instanceof ApiError && e.code === 'CONTROL_SESSION_CHANGED') { unknown(command); command = undefined; throw e; }
        if (e instanceof ApiError && e.status === 409 && e.code === 'APPROVAL_REQUIRED' && !(change.resource === 'clusters' && change.operation === 'create')) approval = true;
        else { clearControlAttempt(original.actor, command.key); command = undefined; load(original.actor); throw e; }
      }
      if (!approval) { clearControlAttempt(original.actor, command.key); command = undefined; load(original.actor); try { await refresh(); } catch (e) { if (mounted.current) setError(e); } return 'direct'; }
      const fresh = await freshControlSession(original); assertLive(original, selected); if (fresh.csrfToken !== session.csrfToken || !subjectAllowed(fresh, { ...options, change })) throw new ApiError('会话或权限已变化，请重新审阅。', 409, 'CONTROL_SESSION_CHANGED');
      command = advanceControlPrepare(original.actor, command.key); load(original.actor);
      const row = await prepareControlOnce(original, change, command, fresh.csrfToken); assertLive(original, selected);
      setAttempt(markControlPrepared(original.actor, command.key, row)); command = undefined; setPrepared(row); setTyped(''); csrf.current = fresh.csrfToken; reviewedScope.current = selected; return 'prepared';
    } catch (e) {
      if (command) { if (controlNeedsVerification(e) || command.phase === 'prepare' && e instanceof ApiError && e.code === 'CONTROL_SESSION_CHANGED') unknown(command); else { clearControlAttempt(original.actor, command.key); load(original.actor); } }
      if (mounted.current && live.current.actor === original.actor) setError(e); throw e;
    } finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  async function verify() {
    if (!auth.user || running.current) return; running.current = true; setBusy(true); setError(undefined);
    try {
      const original = identity(), row = readControlAttempt(original.actor); if (!row) throw new Error('未找到原配置请求。');
      const receipt = await readControlOriginal(original, row);
      if (row.phase === 'direct') { if (!controlDirectReceiptCompleted(receipt, row)) throw new Error('原操作仍待核验。'); clearControlAttempt(original.actor, row.key); load(original.actor); await refresh(); void message.success('原操作已核验'); }
      else {
        const state = receipt as ControlReceipt; if (!controlReceiptMatches(state, row)) throw new Error('回执与原配置请求不一致。');
        if (state.workflowId !== null) { clearControlAttempt(original.actor, row.key); load(original.actor); setResult(state); setPrepared(undefined); if (state.state === 'succeeded') await refresh(); }
        else if (row.phase === 'prepare' || row.phase === 'prepared') { const current = await freshControlSession(original); if (getApiActorId() !== original.actor || live.current.actor !== original.actor || live.current.version !== original.version) throw new ApiError('账号或权限已变化。', 409, 'CONTROL_SESSION_CHANGED'); const next = row.phase === 'prepare' ? markControlPrepared(original.actor, row.key, state) : row; setAttempt(next); setPrepared(state); setTyped(''); csrf.current = current.csrfToken; reviewedScope.current = live.current.selected; }
        else throw new Error('提交结果尚未确认，请继续核验原请求。');
      }
    } catch (e) { if (mounted.current) setError(e); } finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  const canSubmit = controlPreparedAllowed(prepared, auth.user?.capabilities, otherOriginalBlocked || damaged);
  const reviewed = useRef({ prepared, typed }); reviewed.current = { prepared, typed };
  async function submit() {
    if (!auth.user || running.current || !canSubmit || !prepared?.preview || typed !== prepared.preview.confirmationName) return;
    const original = identity(), selected = reviewedScope.current, seen = prepared, prior = readControlAttempt(original.actor);
    if (!prior || prior.phase !== 'prepared' || !controlReceiptMatches(seen, prior)) return;
    const assertSubmission = () => { assertLive(original, selected); if (!controlPreparedAllowed(reviewed.current.prepared, live.current.capabilities, live.current.blocked) || reviewed.current.prepared?.materialHmac !== seen.materialHmac || reviewed.current.typed !== seen.preview!.confirmationName) throw new Error('当前配置意图不可提交，请重新核验。'); };
    running.current = true; setBusy(true); setError(undefined); let command: ControlAttempt | undefined;
    try {
      const current = await freshControlSession(original); assertSubmission(); if (current.csrfToken !== csrf.current) throw new ApiError('登录会话已变化，请重新审阅。', 409, 'CONTROL_SESSION_CHANGED');
      const fresh = await readControlOriginal(original, prior) as ControlReceipt; assertSubmission();
      if (!controlReceiptMatches(fresh, prior) || fresh.state !== 'prepared' || fresh.workflowId !== null || JSON.stringify(fresh.preview) !== JSON.stringify(seen.preview) || fresh.expiresAt !== seen.expiresAt || !controlPreparedAllowed(fresh, current.user.capabilities, false)) throw new Error('配置预览已变化或过期，请重新核验。');
      const final = await freshControlSession(original); assertSubmission(); if (final.csrfToken !== current.csrfToken || !controlPreparedAllowed(fresh, final.user.capabilities, false)) throw new ApiError('会话或权限已变化，请重新审阅。', 409, 'CONTROL_SESSION_CHANGED');
      command = beginControlSubmit(original.actor, prior.key, newIdempotencyKey()); setAttempt(command);
      const receipt = await submitControlOnce(original, fresh, command, final.csrfToken); assertLive(original, selected); clearControlAttempt(original.actor, command.key); command = undefined; load(original.actor); setPrepared(undefined); setTyped(''); csrf.current = ''; setResult(receipt);
    } catch (e) { if (command) { if (controlNeedsVerification(e) || e instanceof ApiError && e.code === 'CONTROL_SESSION_CHANGED') unknown(command); else { clearControlAttempt(original.actor, command.key); load(original.actor); setPrepared(undefined); } } if (mounted.current) setError(e); }
    finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  function discard() { if (auth.user && attempt?.phase === 'prepared' && attempt.state === 'prepared' && !busy) { clearControlAttempt(auth.user.id, attempt.key); load(auth.user.id); setPrepared(undefined); setTyped(''); csrf.current = ''; } }
  function openWorkflow() { if (!result?.workflowId || !result.preview) return; try { const selector = result.preview.affectedScopes[0].workspaceId ?? result.workspaceId; workspace.selectScopeWorkspace(result.clusterId, selector); cluster.selectCluster(result.clusterId); navigate(`/workflows/${result.workflowId}?workspaceId=${selector}`); } catch (e) { setError(e); } }
  return { blocked: !!journal.row || !!journal.error || !!attempt || busy || damaged || !auth.user || otherOriginalBlocked, execute, attempt, prepared, result, busy, error, typed, canSubmit, setTyped, verify, submit, discard, openWorkflow,
    closeReview: () => { setPrepared(undefined); setTyped(''); csrf.current = ''; }, closeResult: () => setResult(undefined) };
}
export function ControlMetadataChanges({ flow }: { flow: ReturnType<typeof useControlMetadataChanges> }) {
  const p = flow.prepared?.preview;
  return <>{flow.attempt && !flow.prepared && <Alert style={{ marginBottom: 16 }} type={flow.attempt.phase === 'prepared' ? 'info' : 'warning'} showIcon message={flow.attempt.phase === 'prepared' ? '有一项配置变更待提交' : '配置变更结果待核验'} action={<Button loading={flow.busy} onClick={() => void flow.verify()}>{flow.attempt.phase === 'prepared' ? '继续审阅' : '核验原请求'}</Button>} />}
    {!!flow.error && <QueryError error={flow.error} />}
    {flow.result?.workflowId && <Alert showIcon style={{ marginBottom: 16 }} type={flow.result.state === 'succeeded' ? 'success' : 'info'} message={flow.result.state === 'succeeded' ? '配置变更已完成' : '配置变更已提交'} description={flow.result.preview === null ? '原工单已完成。' : undefined} action={flow.result.preview !== null ? <Button onClick={flow.openWorkflow}>查看工单</Button> : undefined} closable onClose={flow.closeResult} />}
    <Drawer title="审阅配置变更" width={960} open={!!flow.prepared} onClose={flow.closeReview} destroyOnClose extra={<Space><Button disabled={flow.busy || flow.attempt?.phase !== 'prepared'} onClick={flow.discard}>放弃未提交意图</Button><Button type="primary" loading={flow.busy} disabled={flow.attempt?.phase !== 'prepared' || !flow.canSubmit || !p || flow.typed !== p.confirmationName} onClick={() => void flow.submit()}>提交审批</Button></Space>}>
      {flow.attempt && flow.attempt.phase !== 'prepared' && <Alert type="warning" showIcon message="提交结果待核验" action={<Button loading={flow.busy} onClick={() => void flow.verify()}>核验原请求</Button>} style={{ marginBottom: 16 }} />}
      {!!flow.error && <QueryError error={flow.error} />}
      <Descriptions size="small" column={2} items={[{ key: 'cluster', label: '集群', children: flow.prepared?.clusterId }, { key: 'anchor', label: '工单工作区', children: flow.prepared?.workspaceId }, { key: 'expiry', label: '有效期', children: formatTime(flow.prepared?.expiresAt) }]} />
      {p && <><Card title="影响范围" size="small" style={{ marginTop: 16 }}><Table size="small" pagination={false} rowKey={r => `${r.clusterId}:${r.workspaceId}`} dataSource={p.affectedScopes} columns={[{ title: '集群', dataIndex: 'clusterId' }, { title: '变更工作区', render: (_, r) => r.workspaceId ?? '集群配置' }]} /></Card>
        {p.after.authentication && <Descriptions size="small" style={{ marginTop: 16 }} column={2} items={[{ key: 'currentAuth', label: '当前认证', children: (p.before as any)?.authenticationConfigured ? '已配置' : '未配置' }, { key: 'nextAuth', label: '拟用认证方式', children: { none: '无认证', bearer: 'Bearer', basic: 'Basic', header: '自定义请求头' }[p.after.authentication.mode] }]} />}
        {p.after.builtInRoles && <Alert type="info" showIcon message="初始化三个工作区内置角色" description="仅创建角色和权限，用户与团队绑定为 0。" style={{ marginTop: 16 }} />}
        <div className="profile-grid" style={{ marginTop: 16 }}><Card title="现有配置" size="small"><pre className="json-preview">{safeJsonPreview(p.before)}</pre></Card><Card title="拟提交配置" size="small"><pre className="json-preview">{safeJsonPreview(p.after)}</pre></Card></div>
        <Typography.Paragraph style={{ marginTop: 20 }}>输入 <Typography.Text strong>{p.confirmationName}</Typography.Text> 确认提交：</Typography.Paragraph><Input aria-label="配置工单确认名称" value={flow.typed} onChange={e => flow.setTyped(e.target.value)} placeholder={p.confirmationName} autoComplete="off" disabled={flow.busy} />
      </>}
    </Drawer>
  </>;
}
