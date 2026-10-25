import {BadRequestException} from '@nestjs/common';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {iamBody,iamId} from '../iam/iam.types';
import type {WorkflowPlanV1,WorkflowStep} from '../workflows/workflow.types';
import {CONTROL_CHANGE_OPERATIONS,CONTROL_CHANGE_RESOURCES,type ControlChangeRequest,type ControlMetadataPayload} from './control-metadata.types';

const fail=()=>new BadRequestException({code:'CONTROL_METADATA_PLAN_INVALID'}),hex=/^[a-f\d]{64}$/;
function assertJson(value:unknown,seen=new WeakSet<object>(),depth=0):void {
 if(depth>50)throw fail();
 if(value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number'&&Number.isFinite(value))return;
 if(!value||typeof value!=='object'||seen.has(value)||(Array.isArray(value)?Object.getPrototypeOf(value)!==Array.prototype:![Object.prototype,null].includes(Object.getPrototypeOf(value))))throw fail();
 seen.add(value);
 for(const [key,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
  if(Array.isArray(value)&&key==='length')continue;
  if(['__proto__','prototype','constructor'].includes(key)||descriptor.get||descriptor.set||Array.isArray(value)&&!/^(0|[1-9]\d*)$/.test(key))throw fail();
  assertJson(descriptor.value,seen,depth+1);
 }
 seen.delete(value);
}
export function controlOperationMatches(resource:string,operation:string):boolean {
 return resource==='clusters'?['update','deactivate'].includes(operation):resource==='data-sources'?['create','update','deactivate'].includes(operation)
  :resource==='workspaces'?['create','update','archive','restore'].includes(operation):resource==='recycle-bin'&&operation==='purge';
}
export function normalizeControlChangeRequest(raw:unknown):Readonly<ControlChangeRequest>{
 assertJson(raw);
 const value=iamBody(immutableJson(raw),['resource','operation','resourceId','input']);
 if(!CONTROL_CHANGE_RESOURCES.includes(value.resource)||!CONTROL_CHANGE_OPERATIONS.includes(value.operation)||!controlOperationMatches(value.resource,value.operation)
  ||!value.input||typeof value.input!=='object'||Array.isArray(value.input)||![Object.prototype,null].includes(Object.getPrototypeOf(value.input))||!!value.resourceId!==(value.operation!=='create'))throw fail();
 if(value.resourceId!==undefined)value.resourceId=iamId(value.resourceId).toLowerCase();
 if(value.resource==='recycle-bin'){
  if(Object.keys(value.input).some(k=>!['revision','workspaceId','confirmed','confirm_name'].includes(k))||!Number.isSafeInteger(value.input.revision)||value.input.revision<1
   ||value.input.confirmed!==true||typeof value.input.confirm_name!=='string'||!value.input.confirm_name.length||value.input.confirm_name.length>1024)throw fail();
  value.input={...value.input,workspaceId:iamId(value.input.workspaceId).toLowerCase()};
 }
 return immutableJson({resource:value.resource,operation:value.operation,...(value.resourceId?{resourceId:value.resourceId}:{}),input:value.input});
}
export function assertControlMetadataPlan(plan:WorkflowPlanV1):WorkflowStep {
 if(!plan||(plan.kind as string)!=='control-metadata'||(plan.subject.type as string)!=='control_metadata_requests'||plan.requester.type!=='console'
  ||plan.executionMode!=='approval'||plan.approvalRequired!==true||!Array.isArray(plan.steps)||plan.steps.length!==1||!Array.isArray(plan.prerequisites)||plan.prerequisites.length
  ||plan.generated!==undefined||plan.migration!==undefined)throw fail();
 const step=plan.steps[0],payload=step.metadata as ControlMetadataPayload;
 if(step.kind!=='metadata'||step.handler!=='control.metadata'||step.key!=='control.metadata'||step.entityType!=='control_metadata_requests'||step.entityId!==plan.subject.id
  ||!Array.isArray(step.nativeRequests)||step.nativeRequests.length||!Array.isArray(step.dependencies)||step.dependencies.length||step.order!==1||step.parentId!=null||step.credentialKind!=null
  ||step.mutationAction!==undefined||step.mutationPayload!==undefined||step.beforeFingerprint!==undefined||step.mutationIdempotencyKey!==undefined||step.mutationPayloadHmac!==undefined
  ||!payload||typeof payload!=='object'||Array.isArray(payload)||Object.keys(payload).length!==4||!['intentId','resource','operation','materialHmac'].every(k=>Object.hasOwn(payload,k))
  ||payload.intentId!==plan.subject.id||!CONTROL_CHANGE_RESOURCES.includes(payload.resource)||!CONTROL_CHANGE_OPERATIONS.includes(payload.operation)||!controlOperationMatches(payload.resource,payload.operation)
  ||typeof payload.materialHmac!=='string'||!hex.test(payload.materialHmac)||typeof step.metadataBeforeHmac!=='string'||!hex.test(step.metadataBeforeHmac)||typeof step.metadataPayloadHmac!=='string'||!hex.test(step.metadataPayloadHmac)||!Number.isSafeInteger(step.metadataRevision)||Number(step.metadataRevision)<0
  ||step.permissionAction!==(['archive','deactivate','purge'].includes(payload.operation)?'delete':'write'))throw fail();
 iamId(payload.intentId);return step;
}
