import { ForbiddenException } from '@nestjs/common';
import type { SecretService } from '../../infrastructure/secret.service';
import type { WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import type { WorkflowStep } from './workflow.types';

/** Receipt comparison only. The caller must hold the original live claim and
 * approved Native step before and after reading these current SQL rows. */
export function portalReadbackReceipt(
  plan:Readonly<WorkflowScheduledPlanV1>,step:Readonly<WorkflowStep>,executionId:string,
  row:any,operation:any,secrets:SecretService,
):Readonly<{operation:string;result:string}> {
  const deny=():never=>{throw new ForbiddenException({code:'WORKFLOW_BUSINESS_PORTAL_READBACK_RECEIPT_REQUIRED'});};
  const request=step.nativeRequests[0],hash=secrets.fingerprint(plan);
  if(!request?.nativeId||step.nativeRequests.length!==1||!row||row.id!==step.id||row.state!=='running'||row.plan_hash!==hash
    ||!operation||row.operation_id!==operation.id||operation.state!=='succeeded'
    ||operation.remote_started!==true||operation.remote_completed!==true||operation.actor_id!==plan.scheduling.executorId
    ||operation.workflow_id!==plan.workflowId||operation.workflow_execution_id!==executionId||operation.workflow_step_id!==step.id
    ||operation.workflow_plan_revision!==plan.planRevision||operation.workflow_plan_hash!==hash
    ||operation.cluster_id!==plan.clusterId||operation.workspace_id!==plan.workspaceId||operation.entity_type!==step.entityType
    ||operation.entity_id!==request.nativeId||operation.action!==step.mutationAction
    ||(operation.parent_id??null)!==(step.parentId??null)||(operation.credential_kind??null)!==(step.credentialKind??null))deny();
  try{
    if(secrets.fingerprint(secrets.decrypt(operation.payload_secret,`mutation:${operation.id}:payload`))!==step.mutationPayloadHmac
      ||secrets.fingerprint(secrets.decrypt(operation.before_secret,`mutation:${operation.id}:before`))!==step.beforeFingerprint)deny();
    // MutationService persists the callback's original result. Entity callers
    // may wrap it for the API later; the durable receipt can be either shape.
    const result=secrets.decrypt<any>(operation.result_secret,`mutation:${operation.id}:result`),entity=result?.entity??result;
    if(!entity||typeof entity!=='object'||Array.isArray(entity)||entity.id!==request.nativeId)deny();
    return Object.freeze({operation:secrets.fingerprint(operation),result:secrets.fingerprint(entity)});
  }catch{return deny();}
}
