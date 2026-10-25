import { BadRequestException } from '@nestjs/common';
import type { WorkflowPlanV1, WorkflowStep } from './workflow.types';

export interface ConfigurationWorkflowPayload { jobId:string; planId:string; planRevision:number; planHash:string }
const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
/** V1 is solely the small approval wrapper. No native DAG is smuggled into it. */
export function assertConfigurationWorkflowPlan(plan:WorkflowPlanV1):WorkflowStep{
  const fail=():never=>{throw new BadRequestException({code:'CONFIGURATION_WORKFLOW_INVALID'});};
  const step=plan.steps?.[0],payload=step?.metadata as ConfigurationWorkflowPayload;
  if(plan.kind!=='configuration_v2'||plan.subject.type!=='configuration_jobs'||plan.requester.type!=='console'
    ||plan.steps.length!==1||plan.prerequisites.length||plan.generated!==undefined||!step||step.kind!=='metadata'||step.handler!=='configuration_v2'
    ||step.entityType!==plan.subject.type||step.entityId!==plan.subject.id||step.order!==1||step.permissionAction!=='write'||step.dependencies.length||step.nativeRequests.length
    ||step.parentId!==undefined||step.credentialKind!==undefined||step.mutationAction!==undefined||step.mutationPayload!==undefined||step.mutationPayloadHmac!==undefined
    ||step.mutationIdempotencyKey!==undefined||step.beforeFingerprint!==undefined||!payload||typeof payload!=='object'||Array.isArray(payload)
    ||Object.keys(payload).length!==4||!['jobId','planId','planRevision','planHash'].every(key=>Object.hasOwn(payload,key))
    ||!uuid.test(payload.jobId)||payload.jobId!==plan.subject.id||!uuid.test(payload.planId)||!Number.isSafeInteger(payload.planRevision)||payload.planRevision<1
    ||!/^[a-f\d]{64}$/.test(payload.planHash))fail();
  return step;
}
export const configurationMutationKey=(jobId:string,stepId:string):string=>`configuration-${jobId}-${stepId}`;
