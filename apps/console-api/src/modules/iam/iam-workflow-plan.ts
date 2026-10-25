import {BadRequestException} from '@nestjs/common';
import type { WorkflowPlanV1,WorkflowStep } from '../workflows/workflow.types';
import {iamBody,iamId} from './iam.types';
import {IAM_CHANGE_OPERATIONS,type IamChangeRequest,type IamMetadataPayload} from './iam-workflow.types';
import {immutableJson} from '../../infrastructure/kong/immutable-json';

const fail=()=>new BadRequestException({code:'IAM_WORKFLOW_PLAN_INVALID'}),hex=/^[a-f\d]{64}$/;
function operationMatches(resource:string,operation:string):boolean{return !(operation.startsWith('member.')&&resource!=='teams'
 ||['permissions','clone'].includes(operation)&&resource!=='roles'||operation.startsWith('binding.')&&resource==='roles');}
export function normalizeIamChangeRequest(raw:unknown):Readonly<IamChangeRequest>{
 const value=iamBody(raw,['resource','operation','resourceId','relatedId','input']);
 if(!['users','teams','roles'].includes(value.resource)||!IAM_CHANGE_OPERATIONS.includes(value.operation)||!value.input||typeof value.input!=='object'||Array.isArray(value.input))throw fail();
 if(value.resourceId!==undefined)iamId(value.resourceId);if(value.relatedId!==undefined)iamId(value.relatedId);
 const needsId=value.operation!=='create';if(needsId!==!!value.resourceId)throw fail();
 if(!operationMatches(value.resource,value.operation)
  ||!!value.relatedId!==['member.revoke','member.restore','binding.revoke','binding.restore'].includes(value.operation))throw fail();
 return immutableJson({resource:value.resource,operation:value.operation,...(value.resourceId?{resourceId:value.resourceId}:{}),...(value.relatedId?{relatedId:value.relatedId}:{}),input:value.input});
}
/** IAM approval is one fixed metadata operation. Identity changes can never
 * carry a Kong packet, a user-supplied handler or another workflow kind. */
export function assertIamMetadataPlan(plan:WorkflowPlanV1):WorkflowStep{
 if(!plan||(plan.kind as string)!=='iam-metadata'||(plan.subject.type as string)!=='iam_metadata_requests'||plan.requester.type!=='console'
  ||plan.executionMode!=='approval'||plan.approvalRequired!==true||!Array.isArray(plan.steps)||plan.steps.length!==1||!Array.isArray(plan.prerequisites)||plan.prerequisites.length||plan.generated!==undefined||plan.migration!==undefined)throw fail();
 const step=plan.steps[0],payload=step.metadata as IamMetadataPayload;
 if(step.kind!=='metadata'||step.handler!=='iam.metadata'||step.key!=='iam.metadata'||step.entityType!=='iam_metadata_requests'||step.entityId!==plan.subject.id
  ||!Array.isArray(step.nativeRequests)||step.nativeRequests.length||!Array.isArray(step.dependencies)||step.dependencies.length||step.parentId!=null||step.credentialKind!=null||step.mutationAction!==undefined||step.mutationPayload!==undefined
  ||step.beforeFingerprint!==undefined||step.mutationIdempotencyKey!==undefined||step.mutationPayloadHmac!==undefined||!payload||typeof payload!=='object'||Array.isArray(payload)
  ||Object.keys(payload).length!==4||!['intentId','resource','operation','materialHmac'].every(k=>Object.hasOwn(payload,k))||payload.intentId!==plan.subject.id
  ||!['users','teams','roles'].includes(payload.resource)||!IAM_CHANGE_OPERATIONS.includes(payload.operation)||!operationMatches(payload.resource,payload.operation)||!hex.test(payload.materialHmac)
  ||!hex.test(step.metadataBeforeHmac??'')||!hex.test(step.metadataPayloadHmac??'')||!Number.isSafeInteger(step.metadataRevision)||Number(step.metadataRevision)<0
  ||step.permissionAction!==(payload.operation==='archive'||payload.operation==='binding.revoke'||payload.operation==='member.revoke'?'delete':'write'))throw fail();
 iamId(payload.intentId);return step;
}
