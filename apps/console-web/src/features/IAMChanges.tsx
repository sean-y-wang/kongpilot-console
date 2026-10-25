import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Input, Space, Table, Tag, Typography } from 'antd';
import { useNavigate } from 'react-router-dom';
import { ApiError, getApiActorId } from '../api/client';
import { freshIamSession, iamWriteNeedsVerification, prepareIamChangeOnce, readIamChangeReceipt, readIamPrepared, submitIamChangeOnce, writeIamDirectOnce } from '../api/iam-changes';
import { beginIamSubmit, clearIamAttempt, iamPreparedSubmissionAllowed, iamReceiptMatchesAttempt, markIamPrepared, readIamAttempt, storeIamAttempt, type IamChangeAttempt, type IamChangeIdentity, type IamChangeReceipt, type IamChangeRequest } from '../api/iam-changes.model';
import { newIdempotencyKey } from '../api/idempotency';
import { receiptProvesCompletion } from '../api/workspace-scope';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { QueryError, formatTime } from '../components/Shared';
import { safeJsonPreview } from './m7.redaction';

interface ChangeOptions { change: IamChangeRequest; allowed: boolean; onSaved: () => Promise<void>; }
interface IamChangesValue { blocked: boolean; execute: (options: ChangeOptions) => Promise<'direct' | 'prepared'>; }
const Context = createContext<IamChangesValue | null>(null);
const isUnknown = iamWriteNeedsVerification;
export function IAMChangesProvider({ children }: { children: ReactNode }) {
  const auth = useAuth(), cluster = useCluster(), workspace = useWorkspace(), navigate = useNavigate(), { message } = App.useApp();
  const [attempt, setAttempt] = useState<IamChangeAttempt>(), [prepared, setPrepared] = useState<IamChangeReceipt>(), [result, setResult] = useState<IamChangeReceipt>();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [typed, setTyped] = useState(''), [damaged, setDamaged] = useState(false);
  const iamBlocked = workspace.references.some(r => r.domain === 'iam');
  const readonlyScopes = cluster.clusterId ? workspace.workspaces.filter(w => w.status === 'disabled').map(w => ({ clusterId: cluster.clusterId!, workspaceId: w.id })) : [];
  if (cluster.clusterId && workspace.workspaceId && workspace.readonlyWorkspace && !readonlyScopes.some(s => s.workspaceId === workspace.workspaceId)) readonlyScopes.push({ clusterId: cluster.clusterId, workspaceId: workspace.workspaceId });
  const submissionAllowed = iamPreparedSubmissionAllowed(prepared, iamBlocked, readonlyScopes);
  const running = useRef(false), csrf = useRef(''), afterSaved = useRef<() => Promise<void>>(), live = useRef({ actor: auth.user?.id, version: auth.user?.permissionsVersion, scope: `${cluster.clusterId}:${workspace.workspaceId}`, iamBlocked, submissionAllowed });
  live.current = { actor: auth.user?.id, version: auth.user?.permissionsVersion, scope: `${cluster.clusterId}:${workspace.workspaceId}`, iamBlocked, submissionAllowed };
  useEffect(() => { setPrepared(undefined); setResult(undefined); setAttempt(undefined); setError(undefined); setDamaged(false); setTyped(''); csrf.current = ''; afterSaved.current = undefined; if (auth.user) try { setAttempt(readIamAttempt(auth.user.id)); } catch (e) { setError(e); setDamaged(true); } }, [auth.user?.id]);
  useEffect(() => { setPrepared(undefined); setTyped(''); csrf.current = ''; }, [cluster.clusterId, workspace.workspaceId, auth.user?.permissionsVersion]);
  const identity = (): IamChangeIdentity => ({ actor: auth.user!.id, version: auth.user?.permissionsVersion ?? '' });
  function assertLive(original: IamChangeIdentity, scope: string) { if (getApiActorId() !== original.actor || live.current.actor !== original.actor || live.current.version !== original.version || live.current.scope !== scope || live.current.iamBlocked) throw new ApiError('账号、权限或页面范围已变化，请重新审阅。', 409, 'IAM_CHANGE_SESSION_CHANGED'); }
  function assertSubmissionLive(original: IamChangeIdentity, scope: string) { assertLive(original, scope); if (!live.current.submissionAllowed) throw new Error('此范围当前不可提交，请先核验原请求与工作区状态。'); }
  function loadAttempt(actor: string) { const value = readIamAttempt(actor); if (live.current.actor === actor) setAttempt(value); return value; }
  function unknown(original: IamChangeAttempt) { storeIamAttempt({ ...original, state: 'unknown' }); if (live.current.actor === original.actor) setAttempt({ ...original, state: 'unknown' }); }
  async function saved() { await afterSaved.current?.(); await auth.reloadCapabilities(); }
  async function execute(options: ChangeOptions): Promise<'direct' | 'prepared'> {
    if (!auth.user || !options.allowed || running.current || readIamAttempt(auth.user.id) || workspace.references.some(r => r.domain === 'iam')) throw new Error('当前操作不可提交，请先核验原请求。');
    const original = identity(), selectedScope = live.current.scope; running.current = true; setBusy(true); setError(undefined); afterSaved.current = options.onSaved;
    try {
      const current = await freshIamSession(original); assertLive(original, selectedScope);
      const direct: IamChangeAttempt = { ...original, key: newIdempotencyKey(), phase: 'direct', state: 'pending', createdAt: new Date().toISOString() }; storeIamAttempt(direct); loadAttempt(original.actor);
      let approvalRequired = false;
      try { await writeIamDirectOnce(original, options.change, direct.key, current.csrfToken); }
      catch (e) { if (isUnknown(e)) { unknown(direct); throw e; } clearIamAttempt(original.actor, direct.key); loadAttempt(original.actor); if (!(e instanceof ApiError && e.code === 'APPROVAL_REQUIRED')) throw e; approvalRequired = true; }
      if (!approvalRequired) { clearIamAttempt(original.actor, direct.key); loadAttempt(original.actor); await saved(); return 'direct'; }
      const fresh = await freshIamSession(original); assertLive(original, selectedScope); if (fresh.csrfToken !== current.csrfToken) throw new ApiError('登录会话已变化，请重新审阅。', 409, 'IAM_CHANGE_SESSION_CHANGED');
      const prep: IamChangeAttempt = { ...original, key: newIdempotencyKey(), phase: 'prepare', state: 'pending', createdAt: new Date().toISOString() }; storeIamAttempt(prep); loadAttempt(original.actor);
      try { const receipt = await prepareIamChangeOnce(original, options.change, prep.key, fresh.csrfToken); assertLive(original, selectedScope); const row = markIamPrepared(original.actor, prep.key, receipt); setAttempt(row); setPrepared(receipt); setTyped(''); csrf.current = fresh.csrfToken; return 'prepared'; }
      catch (e) { if (isUnknown(e) || e instanceof ApiError && e.code === 'IAM_CHANGE_SESSION_CHANGED') unknown(prep); else { clearIamAttempt(original.actor, prep.key); loadAttempt(original.actor); } throw e; }
    } catch (e) { setError(e); throw e; } finally { running.current = false; setBusy(false); }
  }
  async function verify() {
    if (!auth.user || running.current) return; running.current = true; setBusy(true); setError(undefined);
    try {
      const original = identity(), row = readIamAttempt(original.actor); if (!row) throw new Error('未找到原请求。');
      const receipt = await readIamChangeReceipt(original, row);
      if (row.phase === 'direct') { if (!receiptProvesCompletion(receipt)) throw new Error('原操作仍待核验。'); clearIamAttempt(original.actor, row.key); loadAttempt(original.actor); await saved(); void message.success('原操作已核验'); }
      else {
        const state = receipt as IamChangeReceipt; if (!iamReceiptMatchesAttempt(state, row)) throw new Error('回执与原请求不一致。');
        if (state.workflowId !== null) { clearIamAttempt(original.actor, row.key); loadAttempt(original.actor); setResult(state); setPrepared(undefined); await saved(); }
        else if (row.phase === 'prepare' || row.phase === 'prepared') { const current = await freshIamSession(original); const reference = row.phase === 'prepare' ? markIamPrepared(original.actor, row.key, state) : row; setAttempt(reference); setPrepared(state); setTyped(''); csrf.current = current.csrfToken; }
        else throw new Error('提交结果尚未确认，请保留原请求并稍后核验。');
      }
    } catch (e) { setError(e); } finally { running.current = false; setBusy(false); }
  }
  async function submit() {
    if (!auth.user || running.current || !submissionAllowed || !prepared?.preview || typed !== prepared.preview.confirmationName) return;
    const original = identity(), selectedScope = live.current.scope, reviewed = prepared, prior = readIamAttempt(original.actor);
    if (!prior || prior.phase !== 'prepared' || prior.intentId !== reviewed.intentId || prior.materialHmac !== reviewed.materialHmac) return;
    running.current = true; setBusy(true); setError(undefined); let command: IamChangeAttempt | undefined;
    try {
      const current = await freshIamSession(original); assertSubmissionLive(original, selectedScope); if (current.csrfToken !== csrf.current) throw new ApiError('会话已变化，请核验原意图后重新确认。', 409, 'IAM_CHANGE_SESSION_CHANGED');
      const fresh = await readIamPrepared(original, reviewed.intentId); assertSubmissionLive(original, selectedScope);
      if (fresh.state !== 'prepared' || fresh.materialHmac !== reviewed.materialHmac || fresh.clusterId !== reviewed.clusterId || fresh.workspaceId !== reviewed.workspaceId || JSON.stringify(fresh.preview) !== JSON.stringify(reviewed.preview) || Date.parse(fresh.expiresAt) <= Date.now()) throw new Error('变更意图已变化或过期，请重新核验。');
      const finalSession = await freshIamSession(original); assertSubmissionLive(original, selectedScope); if (finalSession.csrfToken !== current.csrfToken) throw new ApiError('会话已变化，请重新审阅。', 409, 'IAM_CHANGE_SESSION_CHANGED');
      command = beginIamSubmit(original.actor, prior.key, newIdempotencyKey()); setAttempt(command);
      const receipt = await submitIamChangeOnce(original, fresh, command.key, finalSession.csrfToken); clearIamAttempt(original.actor, command.key); command = undefined; loadAttempt(original.actor); setPrepared(undefined); setTyped(''); csrf.current = ''; setResult(receipt); await saved();
    } catch (e) { if (command) { if (isUnknown(e)) unknown(command); else { clearIamAttempt(original.actor, command.key); loadAttempt(original.actor); setPrepared(undefined); } } setError(e); } finally { running.current = false; setBusy(false); }
  }
  function discard() { if (auth.user && attempt?.phase === 'prepared' && attempt.state === 'prepared' && !busy) { clearIamAttempt(auth.user.id, attempt.key); loadAttempt(auth.user.id); setPrepared(undefined); setTyped(''); csrf.current = ''; } }
  function openWorkflow() { if (!result?.workflowId) return; try { workspace.selectScopeWorkspace(result.clusterId, result.workspaceId); cluster.selectCluster(result.clusterId); navigate(`/workflows/${result.workflowId}`); } catch (e) { setError(e); } }
  const blocked = !!attempt || busy || damaged || !auth.user || workspace.references.some(r => r.domain === 'iam');
  const preview = prepared?.preview;
  return <Context.Provider value={{ blocked, execute }}>
    {attempt && !prepared && <Alert style={{ marginBottom: 16 }} type={attempt.phase === 'prepared' ? 'info' : 'warning'} showIcon message={attempt.phase === 'prepared' ? '有一项身份变更待提交' : '身份变更结果待核验'} action={<Button loading={busy} onClick={() => void verify()}>{attempt.phase === 'prepared' ? '继续审阅' : '核验原请求'}</Button>} />}
    {error ? <QueryError error={error} /> : null}
    {result?.workflowId && <Alert style={{ marginBottom: 16 }} type="success" showIcon message="身份变更已提交" action={<Button onClick={openWorkflow}>查看工单</Button>} closable onClose={() => setResult(undefined)} />}
    {children}
    <Drawer title="审阅身份与权限变更" width={960} open={!!prepared} onClose={() => { setPrepared(undefined); setTyped(''); csrf.current = ''; }} destroyOnClose extra={<Space><Button disabled={busy || attempt?.phase !== 'prepared'} onClick={discard}>放弃未提交意图</Button><Button type="primary" loading={busy} disabled={attempt?.phase !== 'prepared' || !submissionAllowed || !preview || typed !== preview.confirmationName} onClick={() => void submit()}>提交审批</Button></Space>}>
      {attempt && attempt.phase !== 'prepared' && <Alert type="warning" showIcon message="提交结果待核验" style={{ marginBottom: 16 }} action={<Button loading={busy} onClick={() => void verify()}>核验原请求</Button>} />}
      {error ? <QueryError error={error} /> : null}
      <Descriptions size="small" column={2} items={[{ key: 'scope', label: '工作区', children: prepared?.workspaceId }, { key: 'expiry', label: '有效期', children: formatTime(prepared?.expiresAt) }]} />
      {preview && <><Card size="small" title="影响范围" style={{ marginTop: 16 }}><Table size="small" pagination={false} rowKey={r => `${r.clusterId}:${r.workspaceId}`} dataSource={preview.affectedScopes} columns={[{ title: '集群', render: (_, r) => cluster.clusters.find(c => c.id === r.clusterId)?.name ?? r.clusterId }, { title: '工作区', render: (_, r) => r.workspaceId === workspace.workspaceId ? workspace.workspace?.name ?? r.workspaceId : r.workspaceId ?? '集群全部工作区' }, { title: '执行模式', render: (_, r) => <Tag>{r.executionMode === 'approval' ? '工单审批' : '直接执行'}</Tag> }]} /></Card>
        <div className="profile-grid" style={{ marginTop: 16 }}><Card size="small" title="现有配置"><pre className="json-preview">{safeJsonPreview(preview.before)}</pre></Card><Card size="small" title="拟提交配置"><pre className="json-preview">{safeJsonPreview(preview.after)}</pre></Card></div>
        <Typography.Paragraph style={{ marginTop: 20 }}>输入 <Typography.Text strong>{preview.confirmationName}</Typography.Text> 确认提交：</Typography.Paragraph><Input aria-label="身份工单确认名称" autoComplete="off" value={typed} onChange={event => setTyped(event.target.value)} placeholder={preview.confirmationName} disabled={busy} />
      </>}
    </Drawer>
  </Context.Provider>;
}
export function useIamChanges(): IamChangesValue { const value = useContext(Context); if (!value) throw new Error('IAMChangesProvider is required'); return value; }
