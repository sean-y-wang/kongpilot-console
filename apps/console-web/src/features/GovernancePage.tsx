import { Alert, Card, Empty, Space, Tabs, Typography } from 'antd';
import { Link, useSearchParams } from 'react-router-dom';
import { PageHeading, QueryError } from '../components/Shared';
import { useGovernanceQuery, useGovernanceScope } from './governance.hooks';
import { governanceIdentityKey, governanceSafeValue } from './governance.model';
import type { GovernanceCapabilities, GovernanceCatalog } from './governance.types';
import { GovernanceReports } from './GovernanceReports';
import { GovernanceRules } from './GovernanceRules';
import { GovernanceEnvironments } from './GovernanceEnvironments';
import { GovernanceSchedules } from './GovernanceSchedules';

export function GovernancePage() {
  const scope = useGovernanceScope(), [params, setParams] = useSearchParams(), capabilities = useGovernanceQuery<GovernanceCapabilities>(scope, 'capabilities'), catalog = useGovernanceQuery<GovernanceCatalog>(scope, 'catalog'), cap = capabilities.data;
  const items = [
    { key: 'reports', label: '巡检报告', visible: scope.permission.has('governance'), children: <GovernanceReports capabilities={cap} catalog={catalog.data} /> },
    { key: 'rules', label: 'Lint 规则', visible: scope.permission.has('lint'), children: <GovernanceRules capabilities={cap} catalog={catalog.data} /> },
    { key: 'drift', label: '配置漂移', visible: scope.permission.has('drift'), children: <GovernanceEnvironments mode="drift" capabilities={cap} /> },
    { key: 'promote', label: '环境发布', visible: scope.permission.has('promote'), children: <GovernanceEnvironments mode="promote" capabilities={cap} /> },
    { key: 'schedules', label: '调度', visible: scope.permission.has('governance') || scope.permission.has('drift'), children: <GovernanceSchedules capabilities={cap} catalog={catalog.data} /> },
  ].filter(item => item.visible);
  const requested = params.get('tab') ?? (params.has('reportId') ? 'reports' : params.has('comparisonId') ? 'drift' : undefined), active = items.some(item => item.key === requested) ? requested : items[0]?.key;
  return <><PageHeading title="配置治理" extra={<Link to="/configuration">配置变更记录</Link>} />{(capabilities.error || catalog.error) && <QueryError error={capabilities.error ?? catalog.error} retry={() => { void capabilities.refetch(); void catalog.refetch(); }} />}{cap && !cap.adapterAvailable && <Alert type="warning" showIcon message="当前集群适配能力不可用，请先检查版本探测结果" style={{ marginBottom: 16 }} />}{items.length ? <Card><Tabs key={governanceIdentityKey(scope.identity, 'tabs')} activeKey={active} onChange={tab => { const next = new URLSearchParams(params); next.set('tab', tab); setParams(next, { replace: true }); }} destroyOnHidden items={items.map(({ visible: _visible, ...item }) => item)} /></Card> : <Empty description="当前账号没有治理权限" />}</>;
}
export function GovernanceEvidence({ value }: { value: unknown }) { return <pre className="json-preview" style={{ maxHeight: 280, overflow: 'auto' }}>{JSON.stringify(governanceSafeValue(value), null, 2)}</pre>; }
export function GovernanceOperationNotice({ mutation }: { mutation: ReturnType<typeof import('./governance.hooks').useGovernanceMutation> }) {
  return <>{mutation.error && <QueryError error={mutation.error} />}{mutation.result && <Alert style={{ marginBottom: 16 }} showIcon type={mutation.result.success ? 'success' : 'warning'} message={mutation.result.label} description={<Space wrap>{mutation.result.receipt.workflowId && <Link to={`/workflows/${mutation.result.receipt.workflowId}`}>查看审批工单</Link>}{mutation.result.receipt.jobId && <Typography.Text type="secondary">配置作业：{mutation.result.receipt.jobId}</Typography.Text>}</Space>} />}{mutation.unresolved && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="原请求结果待核验" description={<Space wrap><Typography.Text copyable>{mutation.unresolved.idempotencyKey}</Typography.Text><a onClick={() => void mutation.observe()}>读取原操作回执</a></Space>} />}</>;
}
