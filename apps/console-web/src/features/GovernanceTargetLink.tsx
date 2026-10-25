import { Alert, Button, Space } from 'antd';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useGovernanceScope } from './governance.hooks';
import { canonicalId } from '../api/workspace-scope';
import type { GovernancePlanLink } from './governance.types';

export function GovernanceTargetLink({ value }: { value: GovernancePlanLink }) {
  const scope = useGovernanceScope(), { selectCluster } = useCluster(), navigate = useNavigate();
  const cid = canonicalId(value.targetClusterId) ?? scope.cid, wid = canonicalId(value.targetWorkspaceId) ?? scope.wid;
  function open(kind: 'plans' | 'jobs', id: string) { scope.assertCurrent(); if (!cid || !wid || !canonicalId(id)) return; scope.workspace.selectScopeWorkspace(cid, wid); selectCluster(cid); navigate(`/configuration/${kind}/${id}`); }
  return <Alert style={{ marginBottom: 16 }} type={value.blockerCodes?.length ? 'warning' : 'info'} showIcon message={value.blockerCodes?.length ? '预览存在阻止项' : '已生成目标变更预览'} description={<>{value.blockerCodes?.join('、')}<Space wrap>{value.planId && <Button type="link" onClick={() => open('plans', value.planId!)}>审阅目标 Diff</Button>}{value.jobId && <Button type="link" onClick={() => open('jobs', value.jobId)}>查看配置作业</Button>}</Space></>} />;
}
