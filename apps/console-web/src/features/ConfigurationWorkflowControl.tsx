import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Drawer, Form, Input, Space, Typography } from 'antd';
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { newIdempotencyKey } from '../api/idempotency';
import { ApiError } from '../api/client';
import { QueryError } from '../components/Shared';
import { configurationDurableSubmitBlocker } from './m8.model';
import { useM8Scope } from './m8.hooks';
import { clearConfigurationWorkflowAttempt, configurationCanCreateWorkflow, configurationWorkflowAttempt, configurationWorkflowConfirmation, configurationWorkflowSourceMatches,
  readConfigurationWorkflowAttempt, readConfigurationWorkflowRejectedSource, settleConfigurationWorkflowRejection, storeConfigurationWorkflowAttempt, validConfigurationWorkflowIdentity,
  type ConfigurationWorkflowAttempt, type ConfigurationWorkflowIdentity, type ConfigurationWorkflowPlan, type ConfigurationWorkflowSettledRejection } from './configuration-workflow.model';
import { fetchConfigurationWorkflowPlan, freshConfigurationWorkflowSession, postConfigurationWorkflowOnce, readConfigurationWorkflowDisposition } from './configuration-workflow.transport';

/** An explicit metadata command. The existing Diff page remains the review
 * destination, and approval/scheduling remain separate user actions. */
export function ConfigurationWorkflowControl({ plan }: { plan?: ConfigurationWorkflowPlan }) {
  const scope = useM8Scope(), client = useQueryClient(), navigate = useNavigate(), [form] = Form.useForm<{ name: string; deletion?: string }>();
  const [reviewed, setReviewed] = useState<ConfigurationWorkflowPlan>(), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [journalVersion, setJournalVersion] = useState(0);
  const [settled, setSettled] = useState<ConfigurationWorkflowSettledRejection>();
  const mounted = useRef(true), running = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  const ready = validConfigurationWorkflowIdentity(scope.identity);
  let attempt: ConfigurationWorkflowAttempt | undefined, rejected: ConfigurationWorkflowSettledRejection | undefined, journalError: unknown;
  if (ready) try {
    attempt = readConfigurationWorkflowAttempt(scope.identity);
    rejected = plan ? readConfigurationWorkflowRejectedSource(scope.identity, plan) : settled && settled.original.actor === scope.identity.actor && settled.original.cid === scope.identity.cid && settled.original.wid === scope.identity.wid ? settled : undefined;
  } catch (cause) { journalError = cause; }
  void journalVersion;
  const eligible = !!plan && !rejected && configurationCanCreateWorkflow(plan, scope.identity), blocked = busy || !!attempt || !!journalError || !scope.writable || scope.workspace.writeBlocked;
  const reason = configurationDurableSubmitBlocker(plan?.capabilities)?.reason;
  async function completed(original: ConfigurationWorkflowAttempt, captured: ConfigurationWorkflowIdentity) {
    const assertCurrent = () => { if (!mounted.current) throw new Error('原页面已关闭，请重新核验原请求。'); scope.assertCurrent(captured); };
    const result = await readConfigurationWorkflowDisposition(original, assertCurrent);
    assertCurrent();
    if (result.kind === 'rejected') setSettled(settleConfigurationWorkflowRejection(original, result.rejection));
    else clearConfigurationWorkflowAttempt(original);
    setJournalVersion(value => value + 1); setReviewed(undefined); form.resetFields();
    await client.invalidateQueries({ predicate: query => query.queryKey[0] === 'm8' });
    assertCurrent(); if (result.kind === 'registered') navigate(`/configuration/plans/${result.proof.planId}`);
  }
  async function verifyOriginal(original: ConfigurationWorkflowAttempt) {
    if (running.current || !ready) return;
    const captured = { ...scope.identity } as ConfigurationWorkflowIdentity; running.current = true; setBusy(true); setError(undefined);
    try { scope.assertCurrent(captured); await freshConfigurationWorkflowSession(captured); scope.assertCurrent(captured); await completed(original, captured); }
    catch (cause) { if (mounted.current) setError(cause); }
    finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  async function submit(values: { name: string; deletion?: string }) {
    if (running.current || blocked || !ready || !reviewed) return;
    const captured = { ...scope.identity } as ConfigurationWorkflowIdentity, source = reviewed;
    let original: ConfigurationWorkflowAttempt | undefined;
    running.current = true; setBusy(true); setError(undefined);
    try {
      scope.assertCurrent(captured); const session = await freshConfigurationWorkflowSession(captured); scope.assertCurrent(captured);
      const fresh = await fetchConfigurationWorkflowPlan(captured, source.id); scope.assertCurrent(captured);
      if (readConfigurationWorkflowRejectedSource(captured, source)) throw new Error('原配置计划已被拒绝，请重新预览后创建配置工单。');
      original = configurationWorkflowAttempt(captured, source, newIdempotencyKey());
      if (!configurationWorkflowSourceMatches(original, fresh) || !configurationCanCreateWorkflow(fresh, captured)) throw new Error('计划或操作资格已变化，请重新审阅配置差异。');
      const body = configurationWorkflowConfirmation(fresh, captured, values.name, values.deletion);
      if (readConfigurationWorkflowAttempt(captured)) throw new Error('原配置工单请求尚未核验。');
      storeConfigurationWorkflowAttempt(original); setJournalVersion(value => value + 1);
      await postConfigurationWorkflowOnce(original, body, session.csrfToken); scope.assertCurrent(captured);
      await completed(original, captured);
    } catch (cause) {
      // The transport spent the original journal before sending. A late catch
      // must never recreate a journal another mounted reader already resolved.
      // A typed POST409 is only a reason to read the exact original key. The
      // independent typed GET and original journal CAS decide disposition.
      if (original && cause instanceof ApiError && cause.status === 409 && cause.code === 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED') {
        try { await completed(original, captured); }
        catch (verificationError) { if (mounted.current) setError(verificationError); }
      } else if (mounted.current) setError(cause);
    } finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  if (!ready || !eligible && !attempt && !journalError && !reason && !error && !rejected) return null;
  return <div style={{ marginBottom: 16 }} data-testid="configuration-workflow-control">
    {!!error && <QueryError error={error} />}{!!journalError && <QueryError error={journalError} />}
    {rejected && <Alert type="warning" showIcon message="当前配置已变化，请重新预览后创建配置工单" description={<Space wrap><Typography.Text className="mono" copyable>{rejected.original.key}</Typography.Text><Typography.Text type="secondary">原拒绝回执已保留</Typography.Text><Button onClick={() => navigate('/configuration')}>重新预览配置</Button></Space>} style={{ marginBottom: 12 }} />}
    {attempt && <Alert type="warning" showIcon message="原配置工单请求尚未核验" description={<Space wrap><Typography.Text className="mono" copyable>{attempt.key}</Typography.Text><Button loading={busy} onClick={() => void verifyOriginal(attempt!)}>核验原请求</Button></Space>} style={{ marginBottom: 12 }} />}
    <Space wrap>{eligible && <Button type="primary" disabled={blocked} onClick={() => { setError(undefined); setReviewed(plan); }}>创建配置工单</Button>}{reason && <Typography.Text type="secondary">{reason}</Typography.Text>}</Space>
    <Drawer open={!!reviewed} title="创建配置工单" width={620} destroyOnHidden onClose={() => { setReviewed(undefined); form.resetFields(); }} extra={<Button type="primary" danger={(reviewed?.deleteCount ?? 0) > 0} disabled={blocked || !reviewed} loading={busy} onClick={() => form.submit()}>确认创建</Button>}>
      <Typography.Paragraph>创建待审批工单后，请核对新配置差异。</Typography.Paragraph>
      <Form form={form} layout="vertical" preserve={false} onFinish={values => void submit(values)}>
        <Form.Item name="name" label={`输入计划名称：${reviewed?.name ?? ''}`} rules={[{ required: true, validator: (_, value) => reviewed && value === reviewed.name ? Promise.resolve() : Promise.reject(new Error('名称必须完全一致。')) }]}><Input aria-label="创建配置工单确认名称" autoComplete="off" disabled={blocked} /></Form.Item>
        {!!reviewed?.deleteCount && <Form.Item name="deletion" label={`单独输入删除确认值：${reviewed.deleteConfirmName ?? '尚未提供'}`} rules={[{ required: true, validator: (_, value) => reviewed.deleteConfirmName && value === reviewed.deleteConfirmName ? Promise.resolve() : Promise.reject(new Error('删除确认值必须完全一致。')) }]}><Input aria-label="配置工单删除确认值" autoComplete="off" disabled={blocked} /></Form.Item>}
      </Form>
    </Drawer>
  </div>;
}
