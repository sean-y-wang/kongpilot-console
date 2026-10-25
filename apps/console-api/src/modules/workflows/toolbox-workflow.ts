import { BadRequestException } from '@nestjs/common';
import type { WorkflowPlanV1, WorkflowStep } from './workflow.types';
import { cacheKey, toolboxId } from '../toolbox/toolbox-input';
export interface ToolboxWorkflowPayload { operationId:string; cacheKey:string; kind:'cache-invalidate'; }
export function assertToolboxWorkflowPlan(plan:WorkflowPlanV1):WorkflowStep{
  const fail=():never=>{throw new BadRequestException({code:'INVALID_TOOLBOX_WORKFLOW'});};
  if(plan.kind!=='toolbox-operation'||plan.subject.type!=='toolbox_operations'||plan.requester.type!=='console'||plan.steps.length!==1||plan.prerequisites.length)fail();
  const step=plan.steps[0],payload=step.metadata as ToolboxWorkflowPayload;
  if(step.kind!=='metadata'||step.handler!=='toolbox.execute'||step.entityType!=='toolbox_operations'||step.entityId!==plan.subject.id||step.permissionAction!=='write'||step.nativeRequests.length||step.dependencies.length||step.mutationAction||step.metadataRevision!==1||!payload||Object.keys(payload).some(key=>!['operationId','cacheKey','kind'].includes(key))||payload.kind!=='cache-invalidate'||payload.operationId!==plan.subject.id)fail();
  toolboxId(payload.operationId);cacheKey(payload.cacheKey);return step;
}
