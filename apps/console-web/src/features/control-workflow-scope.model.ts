import { canonicalId } from '../api/workspace-scope';
import type { Workflow } from './portal.types';
import { workflowActionReceiptComplete, type WorkflowWriteAttempt } from './workflow-entity-change.model';

/** The selector locates a sealed Control target. It never changes the plan's
 * actual anchor or authorizes a native operation. The BFF verifies both. */
export function controlWorkflowScopeMatches(row: Workflow | undefined, cid: string | undefined, wid: string | undefined): boolean {
  return !!row && !!canonicalId(cid) && !!canonicalId(wid) && !!canonicalId(row.workspaceId)
    && row.kind === 'control-metadata' && row.name === row.kind && row.clusterId === cid
    && row.scopeSelectorWorkspaceId === wid && row.executionMode === 'approval' && row.approvalRequired === true
    && row.scheduled !== true;
}

export function workflowDetailScopeMatches(row: Workflow, cid: string | undefined, wid: string | undefined, selectedWid: string | undefined): boolean {
  if (controlWorkflowScopeMatches(row, cid, wid)) return true;
  return !!cid && !!wid && selectedWid === wid && row.clusterId === cid && row.workspaceId === wid && row.kind !== 'control-metadata';
}

export function controlWorkflowReadonlyWriteAllowed(row: Workflow | undefined, cid: string | undefined, wid: string | undefined): boolean {
  if (!controlWorkflowScopeMatches(row, cid, wid) || !row || !['pending', 'approved'].includes(row.state)) return false;
  const impact = row.impact as { nativeRequests?: unknown } | undefined;
  return impact?.nativeRequests === 0 && Array.isArray(row.steps) && row.steps.length === 1
    && row.steps[0].name === 'control.metadata' && row.steps[0].kind === 'metadata';
}

export function controlWorkflowActionReceiptComplete(raw: unknown, attempt: WorkflowWriteAttempt, row: Workflow | undefined): boolean {
  if (!row || !controlWorkflowScopeMatches(row, attempt.cid, attempt.wid)) return false;
  const receipt = raw as Record<string, any> | null;
  if (!receipt || receipt.kind !== 'control-metadata' || receipt.scopeSelectorWorkspaceId !== attempt.wid
    || receipt.clusterId !== attempt.cid || receipt.workspaceId !== row.workspaceId || receipt.workflowId !== row.id
    || receipt.planHash !== row.planHash || !Array.isArray(receipt.steps) || receipt.steps.length !== 1
    || receipt.steps[0]?.name !== 'control.metadata') return false;
  // The common receipt verifier uses the true anchor. Only this fixed kind's
  // authenticated selector may connect a local original-key journal to it.
  return workflowActionReceiptComplete(receipt, { ...attempt, wid: row.workspaceId });
}
