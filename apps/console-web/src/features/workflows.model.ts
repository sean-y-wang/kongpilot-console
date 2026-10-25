import type { Workflow } from './portal.types';

export type WorkflowStageMode = 'any' | 'quorum' | 'all';
export interface WorkflowStagePolicy { level: number; name: string; mode: WorkflowStageMode; threshold: number | null; selector: { users?: string[]; teams?: string[]; roles?: string[] }; }
export interface WorkflowPolicy { version: 2; kind: string; allowSelfApproval: false; distinctAcrossStages: boolean; intentTtlHours: number; stages: WorkflowStagePolicy[]; }
export interface WorkflowDefinition { id: string; code: string; name: string; kind: string; revision: number; version: number; status: 'active' | 'deleted'; format: number; policyHash: string; policy: WorkflowPolicy | Record<string, unknown>; }
export interface WorkflowApprovalStage { level: number; name: string; mode: WorkflowStageMode; threshold: number; state: string; revision: number; candidateCount: number | null; votes: number; }
export interface WorkflowApproval { format: number; policyHash: string; candidateVersion: number | null; distinctAcrossStages: boolean; stages: WorkflowApprovalStage[]; approvalSetId: string | null; }
export const workflowKindLabels: Record<string, string> = {
  'portal-publication': '门户 API 发布', 'portal-credential-issue': '门户凭证申请', 'portal-credential-rotate': '门户凭证轮换',
  'portal-credential-revoke': '门户凭证吊销', 'portal-developer-review': '开发者审核', 'portal-metadata': '门户配置',
  'event-metadata': '事件与通知配置', configuration_v2: '配置发布', 'configuration-metadata': '快照与 GitOps 配置',
  'toolbox-operation': '运维工具操作', 'workspace-migration': '工作区迁移', 'governance-metadata': '配置治理',
  'workflow-policy-metadata': '审批政策变更', 'native-change': '网关实体变更', 'iam-metadata': '身份与权限变更', 'metrics-setup': '监控通道配置', 'control-metadata': '集群与工作区配置变更', 'entity-annotation': '实体备注变更',
};
export const workflowStageModeLabels = { any: '任一人通过', quorum: '达到指定人数', all: '全部候选人会签' };
export const workflowStageStateLabels: Record<string, string> = { active: '当前审批', pending: '待上一阶段通过', approved: '已通过', rejected: '已驳回', skipped: '已跳过' };

/** The active stage is a real server projection. A malformed or ambiguous
 * projection never supplies a vote level or grants button eligibility. */
export function activeWorkflowStage(row: Workflow): WorkflowApprovalStage | undefined {
  const approval = row.approval;
  if (approval?.format !== 2 || !Number.isSafeInteger(approval.candidateVersion) || Number(approval.candidateVersion) < 1 || !Array.isArray(approval.stages)) return undefined;
  const active = approval.stages.filter(stage => stage.state === 'active');
  if (active.length !== 1) return undefined;
  const stage = active[0];
  if (!Number.isSafeInteger(stage.level) || stage.level < 1 || stage.level > 8 || !Number.isSafeInteger(stage.revision) || stage.revision < 1
    || !Number.isSafeInteger(stage.threshold) || stage.threshold < 1 || !Number.isSafeInteger(stage.votes) || stage.votes < 0
    || approval.stages.some(previous => previous.level < stage.level && previous.state !== 'approved')) return undefined;
  return stage;
}
export function workflowDecisionPayload(row: Workflow, decision: 'approve' | 'reject', reason: string): Record<string, unknown> {
  if (row.state !== 'pending' || row.capabilities?.[decision] !== true || !row.approvalRequired) throw new Error('此工单当前不可投票，请刷新审批状态。');
  const stage = row.approval?.format === 2 ? activeWorkflowStage(row) : undefined;
  if (row.approval?.format === 2 && !stage) throw new Error('当前审批阶段不完整，请刷新后重试。');
  return { revision: row.revision, planHash: row.planHash, reason: reason.trim(), confirmed: true, confirm_name: row.name, execute: false,
    ...(stage ? { level: stage.level, stageRevision: stage.revision, candidateVersion: row.approval!.candidateVersion } : {}) };
}
export function workflowPolicyPayload(kind: string, values: any): WorkflowPolicy {
  if (!Array.isArray(values.stages) || !values.stages.length || values.stages.length > 8) throw new Error('审批政策需要 1–8 个阶段。');
  if (!Number.isInteger(values.intentTtlHours) || values.intentTtlHours < 1 || values.intentTtlHours > 168) throw new Error('工单有效期需要为 1–168 小时。');
  return { version: 2, kind, allowSelfApproval: false, distinctAcrossStages: values.distinctAcrossStages !== false,
    intentTtlHours: values.intentTtlHours, stages: values.stages.map((stage: any, index: number) => {
      const selector: WorkflowStagePolicy['selector'] = {};
      for (const key of ['users', 'teams', 'roles'] as const) {
        const selected = stage.selector?.[key] ?? [];
        if (!Array.isArray(selected) || selected.some((id: unknown) => typeof id !== 'string') || selected.length > 100) throw new Error(`第 ${index + 1} 阶段的审批人选择无效。`);
        if (selected.length) selector[key] = [...new Set<string>(selected)];
      }
      if (!Object.values(selector).some(ids => ids.length)) throw new Error(`第 ${index + 1} 阶段至少选择一名用户、一个团队或一个角色。`);
      if (typeof stage.name !== 'string' || !stage.name.trim() || !['any', 'quorum', 'all'].includes(stage.mode)) throw new Error(`第 ${index + 1} 阶段名称或通过方式无效。`);
      if (stage.mode === 'quorum' && (!Number.isInteger(stage.threshold) || stage.threshold < 1 || stage.threshold > 100)) throw new Error(`第 ${index + 1} 阶段需要 1–100 名审批人。`);
      return { level: index + 1, name: stage.name.trim(), mode: stage.mode,
        threshold: stage.mode === 'all' ? null : stage.mode === 'any' ? 1 : stage.threshold, selector };
    }) };
}
