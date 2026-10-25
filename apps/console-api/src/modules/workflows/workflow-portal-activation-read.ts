import {ForbiddenException} from '@nestjs/common';
import type {ApprovedStepProof} from './approved-execution.types';
import type {WorkflowScheduledPlanV1} from './workflow-schedule.contract';

/** Select only the original issue plan's Native objects. This is not a
 * grant: the Runtime still opens the real Validation read provider. */
export function portalActivationReadPaths(
 plan:Readonly<WorkflowScheduledPlanV1>,current:Readonly<ApprovedStepProof>,clusterId:string,path:string,
):readonly string[]{
 const deny=():never=>{throw new ForbiddenException({code:'WORKFLOW_PORTAL_ACTIVATION_READ_REQUIRED'});};
 const step=plan.steps.find(value=>value.id===current.stepId),execution=current.execution;
 if(plan.kind!=='portal-credential-issue'||plan.clusterId!==clusterId||current.kind!=='metadata'
  ||step?.kind!=='metadata'||step.handler!=='portal.credential.activate'||step.entityId!==plan.subject.id
  ||execution.workflowId!==plan.workflowId||execution.actorId!==plan.scheduling.executorId
  ||execution.clusterId!==plan.clusterId||execution.workspaceId!==plan.workspaceId||execution.origin!=='scheduled-workflow'
  ||execution.sessionId!==null||step.nativeRequests.length!==0)deny();
 const native=plan.steps.filter(value=>value.kind==='native'),request=native.flatMap(value=>value.nativeRequests)
  .find(value=>value.method==='POST'&&value.nativeId&&`${value.canonicalPath}/${value.nativeId}`===path);
 if(native.length!==3||!request||!['consumers','acls','key-auth'].includes(request.nativeType))return deny();
 const parent=request.parentId?`/consumers/${request.parentId}`:undefined;
 return Object.freeze(parent?[parent,path]:[path]);
}

/** EntityService reads the Consumer before preparing and again immediately
 * before dispatching a credential. Select only that sealed step's parent.
 * The real provider still checks current READ and workspace membership. */
export function portalEntityParentReadPaths(
 plan:Readonly<WorkflowScheduledPlanV1>,current:Readonly<ApprovedStepProof>,clusterId:string,path:string,
):readonly string[]{
 const step=plan.steps.find(value=>value.id===current.stepId),execution=current.execution;
 const request=step?.nativeRequests[0];
 if(plan.kind!=='portal-credential-issue'||plan.clusterId!==clusterId||current.kind!=='native'
  ||step?.kind!=='native'||step.entityType!=='credentials'||step.mutationAction!=='create'
  ||!['acls','key-auth'].includes(step.credentialKind??'')||step.nativeRequests.length!==1
  ||!step.parentId||step.parentId!==plan.generated?.consumerId||request?.method!=='POST'
  ||request.parentId!==step.parentId||request.nativeType!==step.credentialKind
  ||request.canonicalPath!==`/consumers/${step.parentId}/${step.credentialKind}`||path!==`/consumers/${step.parentId}`
  ||execution.workflowId!==plan.workflowId||execution.actorId!==plan.scheduling.executorId
  ||execution.clusterId!==plan.clusterId||execution.workspaceId!==plan.workspaceId||execution.origin!=='scheduled-workflow'
  ||execution.sessionId!==null)throw new ForbiddenException({code:'WORKFLOW_PORTAL_ENTITY_PARENT_READ_REQUIRED'});
 return Object.freeze([path]);
}
