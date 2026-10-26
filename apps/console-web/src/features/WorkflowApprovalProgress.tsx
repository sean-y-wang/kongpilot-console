import { EntityIdText } from '../components/EntityReference';
import { Card, Descriptions, Table, Tag, Typography } from 'antd';
import type { Workflow } from './portal.types';
import { workflowStageModeLabels, workflowStageStateLabels } from './workflows.model';

export function WorkflowApprovalProgress({ workflow }: { workflow: Workflow }) {
  const approval = workflow.approval;
  const selfApproved = (workflow as Workflow & { selfApproved?: boolean }).selfApproved === true;
  if (!approval || !Array.isArray(approval.stages)) return selfApproved ? <Card title="审批进度" style={{ marginTop: 20 }} data-testid="workflow-approval-progress">
    <Descriptions size="small" column={1} items={[{ key: 'self', label: '审批方式', children: <Tag color="orange">超级管理员自审批</Tag> }]} />
  </Card> : null;
  return <Card title="审批进度" style={{ marginTop: 20 }} data-testid="workflow-approval-progress">
    <Descriptions size="small" column={{ xs: 1, md: 2 }} items={[
      ...(selfApproved ? [{ key: 'self', label: '审批方式', children: <Tag color="orange">超级管理员自审批</Tag> }] : []),
      { key: 'candidate', label: '候选人版本', children: approval.candidateVersion == null ? '—' : `v${approval.candidateVersion}` },
      { key: 'distinct', label: '审批人规则', children: approval.distinctAcrossStages ? '各阶段由不同审批人完成' : '允许跨阶段重复审批人' },
      ...(approval.approvalSetId ? [{ key: 'set', label: '审批记录集合', children: <EntityIdText id={approval.approvalSetId} /> }] : []),
    ]} />
    <Table rowKey="level" size="small" pagination={false} scroll={{ x: 640 }} dataSource={approval.stages} columns={[
      { title: '阶段', render: (_, stage) => <strong>{stage.level}. {stage.name}</strong> },
      { title: '通过方式', render: (_, stage) => workflowStageModeLabels[stage.mode] ?? stage.mode },
      { title: '已通过 / 所需', render: (_, stage) => `${stage.votes} / ${stage.threshold}` },
      { title: '候选人数', render: (_, stage) => stage.candidateCount ?? '—' },
      { title: '状态', render: (_, stage) => <Tag color={stage.state === 'active' ? 'processing' : stage.state === 'approved' ? 'green' : stage.state === 'rejected' ? 'red' : undefined}>{workflowStageStateLabels[stage.state] ?? stage.state}</Tag> },
    ]} />
  </Card>;
}
