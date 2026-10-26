import { BadRequestException, ConflictException } from '@nestjs/common';
import { WORKFLOW_KINDS, type WorkflowKind } from './workflow.types';
import { workflowId } from './workflow-validation';
import type { WorkflowApprovalPolicyV2, WorkflowApprovalSelector, WorkflowCandidateManifest } from './workflow-approval.types';

const exact = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) throw new BadRequestException({ code: 'INVALID_WORKFLOW_APPROVAL_POLICY' });
  return value as Record<string, unknown>;
};
export function normalizeWorkflowSelector(input: unknown): WorkflowApprovalSelector {
  const value = exact(input, ['users', 'teams', 'roles']), output: Record<string, string[]> = {};
  for (const key of ['users', 'teams', 'roles']) {
    if (value[key] === undefined) continue;
    if (!Array.isArray(value[key]) || (value[key] as unknown[]).length > 100) throw new BadRequestException({ code: 'INVALID_WORKFLOW_APPROVAL_SELECTOR' });
    output[key] = [...new Set((value[key] as unknown[]).map(workflowId))].sort();
  }
  if (!Object.values(output).some(ids => ids.length)) throw new BadRequestException({ code: 'WORKFLOW_APPROVAL_SELECTOR_EMPTY' });
  return Object.freeze(output);
}
export function normalizeWorkflowApprovalPolicy(input: unknown, kind?: WorkflowKind): WorkflowApprovalPolicyV2 {
  const value = exact(input, ['version', 'kind', 'allowSelfApproval', 'distinctAcrossStages', 'intentTtlHours', 'stages']);
  if (value.version !== 2 || !(WORKFLOW_KINDS as readonly unknown[]).includes(value.kind) || kind !== undefined && value.kind !== kind || value.allowSelfApproval !== false
    || value.distinctAcrossStages !== undefined && typeof value.distinctAcrossStages !== 'boolean'
    || !Array.isArray(value.stages) || !value.stages.length || value.stages.length > 8) throw new BadRequestException({ code: 'INVALID_WORKFLOW_APPROVAL_POLICY' });
  const ttl = value.intentTtlHours === undefined ? 24 : value.intentTtlHours;
  if (!Number.isInteger(ttl) || Number(ttl) < 1 || Number(ttl) > 168) throw new BadRequestException({ code: 'INVALID_WORKFLOW_INTENT_TTL' });
  const stages = value.stages.map((inputStage, index) => {
    const stage = exact(inputStage, ['level', 'name', 'mode', 'threshold', 'selector']);
    if (stage.level !== index + 1 || typeof stage.name !== 'string' || !stage.name.trim() || stage.name.trim().length > 128 || !['any', 'quorum', 'all'].includes(String(stage.mode))) throw new BadRequestException({ code: 'INVALID_WORKFLOW_APPROVAL_STAGE' });
    if (stage.mode === 'all' ? stage.threshold !== null : !Number.isInteger(stage.threshold) || Number(stage.threshold) < 1 || Number(stage.threshold) > 100 || stage.mode === 'any' && stage.threshold !== 1) throw new BadRequestException({ code: 'INVALID_WORKFLOW_APPROVAL_THRESHOLD' });
    return Object.freeze({ level: index + 1, name: stage.name.trim(), mode: stage.mode as 'any' | 'quorum' | 'all', threshold: stage.threshold as number | null, selector: normalizeWorkflowSelector(stage.selector) });
  });
  return Object.freeze({ version: 2, kind: value.kind as WorkflowKind, allowSelfApproval: false, distinctAcrossStages: value.distinctAcrossStages !== false, intentTtlHours: Number(ttl), stages: Object.freeze(stages) });
}

const unsatisfiable = () => new ConflictException({ code: 'WORKFLOW_APPROVAL_CANDIDATES_UNSATISFIABLE', message: '没有可用的审批人：审批阶段需要申请人以外的审批人' });
/** Hall-style matching permits overlapping selector pools while proving enough
 * distinct actual reviewers remain for every stage's required vote slots. */
export function assertWorkflowCandidateFeasibility(stages: WorkflowCandidateManifest['stages'], distinct: boolean, used: ReadonlySet<string> = new Set()): void {
  if (!stages.length || stages.length > 8) throw unsatisfiable();
  const slots: string[][] = [];
  for (const stage of stages) {
    const candidates = [...new Set(stage.candidates.map(candidate => candidate.userId))].filter(id => !distinct || !used.has(id));
    if (!Number.isInteger(stage.threshold) || stage.threshold < 1 || candidates.length < stage.threshold || stage.candidates.length > 100) throw unsatisfiable();
    if (distinct) for (let index = 0; index < stage.threshold; index++) slots.push(candidates);
  }
  if (!distinct) return;
  const assigned = new Map<string, number>();
  const assign = (slot: number, seen: Set<string>): boolean => {
    for (const user of slots[slot]) {
      if (seen.has(user)) continue; seen.add(user);
      const previous = assigned.get(user);
      if (previous === undefined || assign(previous, seen)) { assigned.set(user, slot); return true; }
    }
    return false;
  };
  for (let slot = 0; slot < slots.length; slot++) if (!assign(slot, new Set())) throw unsatisfiable();
}
