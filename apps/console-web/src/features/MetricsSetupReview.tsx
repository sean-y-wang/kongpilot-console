import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Drawer, Input, Space, Tag, Typography } from 'antd';
import { useNavigate } from 'react-router-dom';
import { ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { QueryError, formatTime } from '../components/Shared';
import { safeJsonPreview } from './m7.redaction';
import { sameVitalsScope, type VitalsScope } from './vitals-model';
import { beginMetricsSetupSubmit, clearMetricsSetupAttempt, markMetricsSetupPrepared, metricsSetupReceiptMatchesAttempt, metricsSetupSubmissionAllowed, metricsSetupWorkflowStatus, readMetricsSetupAttempt, sameMetricsSetupIdentity, storeMetricsSetupAttempt, type MetricsSetupAttempt, type MetricsSetupIdentity, type MetricsSetupReceipt, type MetricsSetupRequest, type MetricsSetupSubmission } from './metrics-setup.model';
import { freshMetricsSetupSession, metricsSetupDirectReceiptCompleted, metricsSetupNeedsVerification, prepareMetricsSetupOnce, readMetricsSetupPrepared, readMetricsSetupReceipt, submitMetricsSetupOnce, writeMetricsSetupDirectOnce } from './metrics-setup.transport';

interface SetupOptions { scope: VitalsScope; allowed: boolean; blocked: boolean; onSaved: (sourceId: string) => Promise<void>; }
/** Feature-local recovery keeps setup writes out of the shared automatic-refresh transport. */
export function useMetricsSetupChange(options: SetupOptions) {
  const navigate = useNavigate(), { message } = App.useApp();
  const [attempt, setAttempt] = useState<MetricsSetupAttempt>(), [prepared, setPrepared] = useState<MetricsSetupReceipt>(), [result, setResult] = useState<MetricsSetupSubmission>();
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [typed, setTyped] = useState(''), [damaged, setDamaged] = useState(false);
  const running = useRef(false), mounted = useRef(true), csrf = useRef(''), capturedReview = useRef<VitalsScope>(), live = useRef(options); live.current = options;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const identity = (): MetricsSetupIdentity => ({ actor: options.scope.actorId, version: options.scope.permissionVersion, clusterId: options.scope.clusterId, workspaceId: options.scope.workspaceId });
  const blockedByScope = !options.allowed || options.blocked;
  const submissionAllowed = metricsSetupSubmissionAllowed(prepared, identity(), blockedByScope);
  useEffect(() => {
    setAttempt(undefined); setPrepared(undefined); setResult(undefined); setTyped(''); setError(undefined); setDamaged(false); csrf.current = ''; capturedReview.current = undefined;
    try { setAttempt(readMetricsSetupAttempt(options.scope.actorId)); } catch (e) { setError(e); setDamaged(true); }
  }, [options.scope.actorId]);
  useEffect(() => { setPrepared(undefined); setTyped(''); csrf.current = ''; capturedReview.current = undefined; }, [options.scope.clusterId, options.scope.workspaceId, options.scope.permissionVersion, options.scope.metricsScope, options.scope.sourceId, options.scope.serviceId, options.scope.routeId]);
  function assertLive(original: MetricsSetupIdentity, scope: VitalsScope) {
    const current = live.current;
    if (!mounted.current || getApiActorId() !== original.actor || !sameMetricsSetupIdentity(original, { actor: current.scope.actorId, version: current.scope.permissionVersion, clusterId: current.scope.clusterId, workspaceId: current.scope.workspaceId }) || !sameVitalsScope(scope, current.scope) || !current.allowed || current.blocked) throw new ApiError('账号、权限或监控范围已变化，请重新审阅。', 409, 'METRICS_SETUP_SESSION_CHANGED');
  }
  function loadAttempt(actor: string) { const row = readMetricsSetupAttempt(actor); if (live.current.scope.actorId === actor) setAttempt(row); return row; }
  function unknown(original: MetricsSetupAttempt) { storeMetricsSetupAttempt({ ...original, state: 'unknown' }); if (live.current.scope.actorId === original.actor) setAttempt({ ...original, state: 'unknown' }); }
  async function execute(request: MetricsSetupRequest): Promise<'direct' | 'prepared'> {
    if (running.current || damaged || blockedByScope || readMetricsSetupAttempt(options.scope.actorId)) throw new Error('当前不可提交，请先核验原监控请求。');
    const original = identity(), captured = options.scope; running.current = true; setBusy(true); setError(undefined); setResult(undefined);
    try {
      const session = await freshMetricsSetupSession(original); assertLive(original, captured);
      const direct: MetricsSetupAttempt = { ...original, key: newIdempotencyKey(), phase: 'direct', state: 'pending', createdAt: new Date().toISOString() }; storeMetricsSetupAttempt(direct); loadAttempt(original.actor);
      let needsApproval = false;
      try { await writeMetricsSetupDirectOnce(original, request, direct.key, session.csrfToken); assertLive(original, captured); }
      catch (e) {
        if (metricsSetupNeedsVerification(e) || e instanceof ApiError && e.code === 'METRICS_SETUP_SESSION_CHANGED') { unknown(direct); throw e; }
        clearMetricsSetupAttempt(original.actor, direct.key); loadAttempt(original.actor);
        if (!(e instanceof ApiError && e.status === 409 && e.code === 'APPROVAL_REQUIRED')) throw e;
        needsApproval = true;
      }
      if (!needsApproval) { clearMetricsSetupAttempt(original.actor, direct.key); loadAttempt(original.actor); await live.current.onSaved(request.sourceId); return 'direct'; }
      const fresh = await freshMetricsSetupSession(original); assertLive(original, captured);
      if (fresh.csrfToken !== session.csrfToken) throw new ApiError('登录会话已变化，请重新审阅。', 409, 'METRICS_SETUP_SESSION_CHANGED');
      const prep: MetricsSetupAttempt = { ...original, key: newIdempotencyKey(), phase: 'prepare', state: 'pending', createdAt: new Date().toISOString() }; storeMetricsSetupAttempt(prep); loadAttempt(original.actor);
      try {
        const receipt = await prepareMetricsSetupOnce(original, request, prep.key, fresh.csrfToken); assertLive(original, captured);
        setAttempt(markMetricsSetupPrepared(original.actor, prep.key, receipt)); setPrepared(receipt); setTyped(''); csrf.current = fresh.csrfToken; capturedReview.current = captured; return 'prepared';
      } catch (e) { if (metricsSetupNeedsVerification(e) || e instanceof ApiError && e.code === 'METRICS_SETUP_SESSION_CHANGED') unknown(prep); else { clearMetricsSetupAttempt(original.actor, prep.key); loadAttempt(original.actor); } throw e; }
    } catch (e) { if (live.current.scope.actorId === original.actor) setError(e); throw e; }
    finally { running.current = false; setBusy(false); }
  }
  async function verify() {
    if (running.current || damaged) return;
    const original = identity(), captured = options.scope, row = readMetricsSetupAttempt(original.actor); if (!row) return;
    running.current = true; setBusy(true); setError(undefined);
    try {
      const receipt = await readMetricsSetupReceipt(original, row);
      if (!mounted.current || getApiActorId() !== original.actor || live.current.scope.actorId !== original.actor || live.current.scope.clusterId !== row.clusterId || live.current.scope.workspaceId !== row.workspaceId) throw new Error('页面范围已变化，请切回原范围核验。');
      if (row.phase === 'direct') {
        if (!metricsSetupDirectReceiptCompleted(receipt)) throw new Error('原监控配置仍待核验，不会自动重发。');
        clearMetricsSetupAttempt(original.actor, row.key); loadAttempt(original.actor); await live.current.onSaved(receipt.result.sourceId); void message.success('原监控配置已核验');
      } else if (row.phase === 'submit') {
        const submitted = receipt as MetricsSetupSubmission;
        if (!submitted.workflowId || submitted.state === 'prepared') throw new Error('原工单提交仍待核验，不会重复提交。');
        clearMetricsSetupAttempt(original.actor, row.key); loadAttempt(original.actor); setPrepared(undefined); setResult(submitted);
      } else {
        const state = receipt as MetricsSetupReceipt;
        if (!metricsSetupReceiptMatchesAttempt(state, row)) throw new Error('回执与原监控请求不一致。');
        if (state.workflowId !== null) {
          clearMetricsSetupAttempt(original.actor, row.key); loadAttempt(original.actor); setPrepared(undefined); setResult({ intentId: state.intentId, clusterId: state.clusterId, workspaceId: state.workspaceId, materialHmac: state.materialHmac, workflowId: state.workflowId, state: state.state, steps: [] });
        } else {
          const session = await freshMetricsSetupSession(original); assertLive(original, captured);
          if (row.version !== original.version) throw new Error('原意图的权限版本已变化，请核验审计记录。');
          setAttempt(row.phase === 'prepare' ? markMetricsSetupPrepared(original.actor, row.key, state) : row); setPrepared(state); setTyped(''); csrf.current = session.csrfToken; capturedReview.current = captured;
        }
      }
    } catch (e) { if (live.current.scope.actorId === original.actor) setError(e); }
    finally { running.current = false; setBusy(false); }
  }
  async function submit() {
    if (running.current || !submissionAllowed || !prepared?.preview || typed !== prepared.preview.confirmationName || !capturedReview.current) return;
    const original = identity(), captured = capturedReview.current, reviewed = prepared, prior = readMetricsSetupAttempt(original.actor);
    if (!prior || prior.phase !== 'prepared' || prior.intentId !== reviewed.intentId || prior.materialHmac !== reviewed.materialHmac || !sameMetricsSetupIdentity(prior, original)) return;
    running.current = true; setBusy(true); setError(undefined); let command: MetricsSetupAttempt | undefined;
    try {
      const session = await freshMetricsSetupSession(original); assertLive(original, captured);
      if (session.csrfToken !== csrf.current) throw new ApiError('会话已变化，请核验原意图后重新确认。', 409, 'METRICS_SETUP_SESSION_CHANGED');
      const fresh = await readMetricsSetupPrepared(original, reviewed.intentId); assertLive(original, captured);
      if (fresh.state !== 'prepared' || fresh.workflowId !== null || fresh.materialHmac !== reviewed.materialHmac || fresh.sourceId !== reviewed.sourceId || fresh.mode !== reviewed.mode || fresh.revision !== reviewed.revision || JSON.stringify(fresh.preview) !== JSON.stringify(reviewed.preview) || Date.parse(fresh.expiresAt) <= Date.now()) throw new Error('监控意图已变化或过期，请重新核验。');
      const finalSession = await freshMetricsSetupSession(original); assertLive(original, captured);
      if (finalSession.csrfToken !== session.csrfToken) throw new ApiError('登录会话已变化，请重新审阅。', 409, 'METRICS_SETUP_SESSION_CHANGED');
      command = beginMetricsSetupSubmit(original.actor, prior.key, newIdempotencyKey()); setAttempt(command);
      const receipt = await submitMetricsSetupOnce(original, fresh, command.key, finalSession.csrfToken); assertLive(original, captured);
      clearMetricsSetupAttempt(original.actor, command.key); command = undefined; loadAttempt(original.actor); setPrepared(undefined); setTyped(''); csrf.current = ''; capturedReview.current = undefined; setResult(receipt);
    } catch (e) {
      if (command) { if (metricsSetupNeedsVerification(e) || e instanceof ApiError && e.code === 'METRICS_SETUP_SESSION_CHANGED') unknown(command); else { clearMetricsSetupAttempt(original.actor, command.key); loadAttempt(original.actor); setPrepared(undefined); } }
      if (live.current.scope.actorId === original.actor) setError(e);
    } finally { running.current = false; setBusy(false); }
  }
  function discard() {
    if (!busy && attempt?.phase === 'prepared' && attempt.state === 'prepared' && attempt.actor === options.scope.actorId) { clearMetricsSetupAttempt(attempt.actor, attempt.key); loadAttempt(attempt.actor); setPrepared(undefined); setTyped(''); csrf.current = ''; capturedReview.current = undefined; }
  }
  const originalScopeSelected = !attempt || attempt.clusterId === options.scope.clusterId && attempt.workspaceId === options.scope.workspaceId;
  const preview = prepared?.preview;
  const review = <>
    {attempt && !prepared && <Alert style={{ marginBottom: 16 }} showIcon type={attempt.phase === 'prepared' ? 'info' : 'warning'} message={attempt.phase === 'prepared' ? '有一项监控配置待审阅' : '监控配置结果待核验'} description={!originalScopeSelected ? '请切回原集群与工作区核验。' : undefined} action={<Button loading={busy} disabled={!originalScopeSelected} onClick={() => void verify()}>{attempt.phase === 'prepared' ? '继续审阅' : '核验原请求'}</Button>} />}
    {error ? <QueryError error={error} /> : null}
    {result?.workflowId && <Alert style={{ marginBottom: 16 }} showIcon {...metricsSetupWorkflowStatus(result.state)} action={<Button onClick={() => navigate(`/workflows/${result.workflowId}`)}>查看工单</Button>} closable onClose={() => setResult(undefined)} />}
    <Drawer title="审阅监控通道变更" width={900} open={!!prepared} onClose={() => { setPrepared(undefined); setTyped(''); csrf.current = ''; capturedReview.current = undefined; }} destroyOnClose extra={<Space><Button disabled={busy || attempt?.phase !== 'prepared' || attempt.state !== 'prepared'} onClick={discard}>放弃未提交意图</Button><Button type="primary" loading={busy} disabled={!submissionAllowed || attempt?.phase !== 'prepared' || attempt.state !== 'prepared' || !preview || typed !== preview.confirmationName} onClick={() => void submit()}>提交审批</Button></Space>}>
      {attempt?.phase === 'submit' && <Alert showIcon type="warning" message="工单提交结果待核验" style={{ marginBottom: 16 }} action={<Button loading={busy} onClick={() => void verify()}>核验原请求</Button>} />}
      {error ? <QueryError error={error} /> : null}
      {preview && <><Alert type="info" showIcon message="全局采集插件影响集群内全部工作区" description={<ul style={{ paddingLeft: 18, marginBottom: 0 }}>{preview.notices.map((notice, index) => <li key={index}>{notice}</li>)}</ul>} style={{ marginBottom: 16 }} />
        <Descriptions size="small" column={2} items={[{ key: 'source', label: '数据源', children: preview.source.name }, { key: 'mode', label: '采集方式', children: prepared.mode === 'collector' ? '日志采集通道' : '原生 Prometheus' }, { key: 'native', label: '网关变更', children: <Tag>{preview.nativeRequestsPlanned} 个插件配置</Tag> }, { key: 'expiry', label: '意图有效期', children: formatTime(prepared.expiresAt) }]} />
        <div className="profile-grid" style={{ marginTop: 16 }}><Card size="small" title="现有配置"><pre className="json-preview">{safeJsonPreview(preview.before)}</pre></Card><Card size="small" title="拟提交配置"><pre className="json-preview">{safeJsonPreview(preview.after)}</pre></Card></div>
        <Typography.Paragraph style={{ marginTop: 20 }}>输入 <Typography.Text strong>{preview.confirmationName}</Typography.Text> 确认提交：</Typography.Paragraph><Input aria-label="监控工单确认集群名称" autoComplete="off" placeholder={preview.confirmationName} value={typed} onChange={event => setTyped(event.target.value)} disabled={busy} />
      </>}
    </Drawer>
  </>;
  return { blocked: !!attempt || busy || damaged || blockedByScope, busy, execute, review };
}
