import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Card, Descriptions, Space, Table, Typography } from 'antd';
import { Link, useParams } from 'react-router-dom';
import { api, apiConfigurationAbandon, ApiError } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import type { Session } from '../api/types';
import { canonicalId } from '../api/workspace-scope';
import { PageHeading, QueryError, formatTime } from '../components/Shared';
import { mutationConfirm, closeMutationConfirmDialogs } from '../components/MutationConfirm';
import { configurationQueryIdentity, safeConfigurationPreview, configurationDownloadIntent, configurationAbandonmentIntent, configurationAbandonmentBody, configurationAbandonmentAuthority, configurationAbandonmentResult, configurationAbandonmentReadback, configurationAbandonmentReferencesToResolve, configurationOriginalJobPath, sameConfigurationIdentity, type ConfigurationReference } from './m8.model';
import { useM8Scope, useM8Detail, useM8Page, M8Pager } from './m8.hooks';
import { M8State, M8Quality } from './m8.components';
import { downloadConfigurationExport } from './m8.download';
import type { ConfigurationJob, ConfigurationStepResult, ConfigurationIdentity, ConfigurationAbandonmentResult } from './m8.types';

export function ConfigurationJobPage() {
  const scope = useM8Scope(), { id: rawId } = useParams(), id = canonicalId(rawId), query = useM8Detail<ConfigurationJob>(scope, `configuration/jobs/${id}`, id, scope.permission.has('snapshots') || scope.permission.has('gitops')), [downloading, setDownloading] = useState(false), [downloadError, setDownloadError] = useState<unknown>(), downloads = useRef<AbortController>(), { modal } = App.useApp(), signature = configurationQueryIdentity(scope.identity, 'job-download');
  const latest = useRef(scope), latestJob = useRef(query.data), abandonmentRequest = useRef<AbortController>(), attempted = useRef(new Set<string>()), [stepRefresh, setStepRefresh] = useState(0);
  const [abandonment, setAbandonment] = useState<{ identity: ConfigurationIdentity; key: string; jobId: string; state: 'sending' | 'recorded' | 'unknown' | 'rejected'; result?: ConfigurationAbandonmentResult; error?: unknown }>();
  latest.current = scope; latestJob.current = query.data;
  useEffect(() => () => { downloads.current?.abort(); abandonmentRequest.current?.abort(); closeMutationConfirmDialogs(); }, [signature]);
  const row = query.data;
  const authority = { writable: scope.writable, snapshotsWrite: scope.whole('snapshots', 'write'), workflowsWrite: scope.whole('workflows', 'write') };
  const intent = row && configurationAbandonmentIntent(row, scope.identity, authority), currentAbandonment = abandonment && sameConfigurationIdentity(abandonment.identity, scope.identity) && abandonment.jobId === row?.id ? abandonment : undefined;
  const alreadyAttempted = !!intent && attempted.current.has(`${scope.actor}:${scope.cid}:${scope.wid}:${intent.executionId}`);
  const savedAbandonment = row && scope.workspace.references.some(ref => ref.kind === 'configuration' && ref.originalJobId === row.id && ref.cid === row.clusterId && ref.wid === row.workspaceId);
  function abandon(job: ConfigurationJob) {
    const captured = { ...scope.identity }, expected = configurationAbandonmentIntent(job, captured, authority);
    if (!expected || alreadyAttempted || savedAbandonment) return;
    mutationConfirm(modal, { title: '确认收口过期执行', expected: expected.confirmationName, okText: '确认停止重试原执行', description: '停止重试这一条旧请求；保留全部已成功对象、原回执和未决事实。收口不回滚、不重发、不修改网关。后续变更须按当前图重新审阅独立 Diff 并审批；其他未知请求仍保持阻止。', onConfirm: async () => {
      latest.current.assertCurrent(captured);
      const fresh = await api<Session>('/auth/me'); latest.current.assertCurrent(captured);
      const currentAuthority = configurationAbandonmentAuthority(fresh.user, captured, latest.current.writable), actual = latestJob.current;
      if (!actual || actual.idempotencyKey !== job.idempotencyKey) throw new ApiError('原作业执行键已变化，请重新读取。', 409, 'CONFIGURATION_JOB_CHANGED');
      const body = configurationAbandonmentBody(actual, captured, latest.current.identity, expected, currentAuthority, expected.confirmationName), attemptId = `${captured.actor}:${captured.cid}:${captured.wid}:${expected.executionId}`;
      if (attempted.current.has(attemptId) || latest.current.workspace.references.some(ref => ref.originalJobId === job.id && ref.cid === captured.cid && ref.wid === captured.wid)) throw new ApiError('此原执行已有收口请求，只能读取原作业，不能重复发送。', 409, 'CONFIGURATION_ABANDON_ALREADY_SENT');
      const key = newIdempotencyKey(), ref: ConfigurationReference = { kind: 'configuration', actorId: captured.actor, clusterId: captured.cid, workspaceId: captured.wid, idempotencyKey: key, originalJobId: job.id, originalJobKey: job.idempotencyKey, abandonmentIntent: expected }, controller = new AbortController();
      attempted.current.add(attemptId); abandonmentRequest.current = controller; setAbandonment({ identity: captured, key, jobId: job.id, state: 'sending' });
      let acknowledged = false;
      try {
        const response = await apiConfigurationAbandon<unknown>(configurationOriginalJobPath(ref).replace(/\?/, '/abandon?'), body, key, { originalJobKey: job.idempotencyKey!, intent: expected }, controller.signal);
        acknowledged = true; latest.current.assertCurrent(captured);
        const result = configurationAbandonmentResult(response, job, expected), readback = await api<unknown>(configurationOriginalJobPath(ref), { signal: controller.signal }); latest.current.assertCurrent(captured);
        const currentSession = await api<Session>('/auth/me'); latest.current.assertCurrent(captured);
        const readAuthority = configurationAbandonmentAuthority(currentSession.user, captured, latest.current.writable);
        configurationAbandonmentReadback(readback, ref, captured, readAuthority);
        for (const reference of configurationAbandonmentReferencesToResolve(latest.current.workspace.references, readback, ref, captured, readAuthority, expected.confirmationName)) latest.current.workspace.resolveReference(reference);
        setAbandonment({ identity: captured, key, jobId: job.id, state: 'recorded', result });
        void query.refetch(); setStepRefresh(value => value + 1);
      } catch (caught) {
        const unknown = acknowledged || caught instanceof ApiError && (caught.code === 'WRITE_RESULT_UNKNOWN' || /UNKNOWN|UNCERTAIN/.test(caught.code ?? ''));
        const error = unknown ? new ApiError('原执行收口回执尚未完整核验。只读取原作业与原执行键；不换键、不再次收口。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...ref, kind: 'configuration', scope: 'workspace', state: 'uncertain' }) : caught;
        if (unknown) window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: captured.actor, error } }));
        if (sameConfigurationIdentity(captured, latest.current.identity)) setAbandonment({ identity: captured, key, jobId: job.id, state: unknown ? 'unknown' : 'rejected', error });
        throw error;
      } finally { controller.abort(); abandonmentRequest.current = undefined; }
    } });
  }
  function download(job: ConfigurationJob) {
    const captured = { ...scope.identity }, intent = configurationDownloadIntent(job);
    if (!intent) return;
    const { name } = intent;
    mutationConfirm(modal, { title: job.mode === 'deployment' ? '确认下载包含秘密的部署文件' : '确认下载脱敏配置摘要', expected: name, danger: false, description: job.mode === 'deployment' ? '文件包含私钥与凭证。当前授权会在流出前及各分块重新核验；请保存到受保护位置，不提交到普通 Git 仓库。' : '这是不可直接 sync 的审阅摘要，不包含可用秘密。', onConfirm: async () => { scope.assertCurrent(captured); const controller = new AbortController(); downloads.current = controller; setDownloading(true); setDownloadError(undefined); try { await downloadConfigurationExport({ ...intent, identity: captured, current: () => scope.current.current, signal: controller.signal }); scope.assertCurrent(captured); } catch (error) { if (!controller.signal.aborted) setDownloadError(error); throw error; } finally { if (downloads.current === controller) downloads.current = undefined; setDownloading(false); } } });
  }
  if (!id) return <Alert type="error" message="作业 ID 无效" />;
  return <><PageHeading title="配置作业详情" description="执行结果以全部步骤完成为准。" extra={<Link to="/configuration">返回配置管理</Link>} />{!!(query.error || downloadError) && <QueryError error={query.error ?? downloadError} />}{currentAbandonment?.error && <QueryError error={currentAbandonment.error} />}{currentAbandonment?.state === 'recorded' && <Alert type="warning" showIcon message="原执行已停止重试，保留未决事实" description={`已保留 ${currentAbandonment.result!.completedSteps} 个成功步骤和 ${currentAbandonment.result!.unresolvedSteps} 个未决步骤。这是失败事实记账，网关结果仍未决；后续须按当前图重新审阅独立 Diff 并审批。其他未知请求仍保持阻止。`} style={{ marginBottom: 20 }} />}{row && <><Card style={{ marginBottom: 20 }}><Descriptions bordered column={1} items={[{ key: 'id', label: '作业 ID', children: row.id }, { key: 'scope', label: '原集群 / 工作区', children: `${row.clusterId} / ${row.workspaceId}` }, { key: 'kind', label: '类型 / 模式', children: `${row.kind} · ${row.mode ?? '—'}` }, { key: 'state', label: '父状态', children: <M8State state={row.state} /> }, { key: 'progress', label: '处理进度', children: row.progress ? `已处理 ${row.progress.processed} / 成功 ${row.progress.succeeded} / 失败 ${row.progress.failed} / 剩余 ${row.progress.remaining}` : '尚未提供' }, { key: 'requirements', label: '审批要求', children: row.approvalRequired ? '当前计划须真实工单审批' : '按服务器当前执行模式' }, { key: 'created', label: '创建时间', children: formatTime(row.createdAt) }, { key: 'error', label: '安全错误码', children: row.errorCode ?? '—' }, { key: 'omissions', label: 'decK 1.1 格式投影', children: row.formatOmissionCount !== undefined ? `${row.formatOmissionCount} 个 optional null 字段省略；加密快照仍保存原 null，merge 不表示清空旧值` : '以服务器导出清单为准' }]} /><div style={{ marginTop: 20 }}>{(row.quality || row.credentialRecovery) && <M8Quality quality={row.quality} recovery={row.credentialRecovery} />}<Typography.Paragraph type="secondary">{row.executionCompleted === true ? row.state !== 'succeeded' ? '父作业已结束，请检查失败或未执行的逐对象结果。' : ['apply', 'rollback'].includes(row.kind) ? '已完成逐对象执行与父作业终态提交。' : '配置作业处理已结束，未执行网关变更。' : row.submissionCompleted === true ? '登记或提交已完成；完整性与执行结果请按作业类型核验。' : '尚未完成登记/执行核验，保留原作业与原键。'}</Typography.Paragraph><Typography.Title level={5}>服务端安全进度</Typography.Title><pre className="json-preview">{safeConfigurationPreview(row.safeProgress)}</pre></div><Space wrap><Button onClick={() => { void query.refetch(); setStepRefresh(value => value + 1); }} loading={query.isFetching}>刷新真实状态</Button>{intent && <Button danger disabled={alreadyAttempted || !!savedAbandonment || currentAbandonment?.state === 'sending'} loading={currentAbandonment?.state === 'sending'} onClick={() => abandon(row)}>确认收口过期执行</Button>}{row.planId && <Link to={`/configuration/plans/${row.planId}`}>审阅不可变 Diff</Link>}{row.snapshotId && <Link to={`/snapshots/${row.snapshotId}`}>关联快照</Link>}{row.workflowId && scope.permission.has('workflows') && <Link to={`/workflows/${row.workflowId}`}>真实工单</Link>}{row.exportId && <Button type="primary" disabled={!configurationDownloadIntent(row) || !scope.writable || downloading || scope.workspace.writeBlocked} loading={downloading} onClick={() => download(row)}>确认并下载文件</Button>}</Space>{row.state === 'uncertain' && <Alert type="warning" showIcon message="原作业有未知结果，不提供新键重试" description="请使用原幂等键回执或计划只读 reconcile 查看实际结果。已成功对象不会重发。" style={{ marginTop: 20 }} />}</Card><ConfigurationSteps jobId={row.id} refreshVersion={stepRefresh} /></>}</>;
}
function ConfigurationSteps({ jobId, refreshVersion = 0 }: { jobId: string; refreshVersion?: number }) {
  const scope = useM8Scope(), query = useM8Page<ConfigurationStepResult>(scope, `configuration/jobs/${jobId}/steps`);
  const { refetch } = query;
  useEffect(() => { if (refreshVersion > 0) void refetch(); }, [refreshVersion, refetch]);
  return <Card title="逐对象执行与实际验证">{query.error && <QueryError error={query.error} />}<Table<ConfigurationStepResult> rowKey="id" dataSource={query.data?.items ?? []} loading={query.isFetching} pagination={false} scroll={{ x: 1250 }} expandable={{ expandedRowRender: row => <pre className="json-preview">{safeConfigurationPreview(row.result)}</pre> }} columns={[{ title: '对象', render: (_, row) => `${row.type ?? '封存逻辑步骤'} · ${row.objectId ?? row.planStepId}` }, { title: '操作 / 顺序', render: (_, row) => `${row.action ?? '见封存计划'} · ${row.stepOrder}` }, { title: '结果', render: (_, row) => <M8State state={row.state} /> }, { title: '实际核验', render: (_, row) => row.verified === true ? '已有完成时只读证据' : row.verified === false ? '尚未证明' : row.state === 'succeeded' ? '服务端已记录终态成功' : '尚未完成' }, { title: '原 ID → 有效 ID', render: (_, row) => row.effectiveId ? `${row.originalId ?? '新增'} → ${row.effectiveId}` : row.originalId ?? '—' }, { title: 'Native 回执 / 回收图', render: (_, row) => <>{row.operationId ?? '—'}{(row.completeRecycleEntryId || row.recycleEntryId) && <div><Link to={`/recycle-bin?entryId=${row.completeRecycleEntryId ?? row.recycleEntryId}&clusterId=${scope.cid}&workspaceId=${row.recycleWorkspaceId ?? row.objectWorkspaceId}`}>{row.completeRecycleEntryId ? '完整回收图' : '归档'} {row.completeRecycleEntryId ?? row.recycleEntryId}</Link></div>}</> }, { title: '错误码', dataIndex: 'errorCode' }]} /><M8Pager query={query} /></Card>;
}
