import {BadRequestException} from '@nestjs/common';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {entityType} from '../entities/entities.types';
import {iamBody,iamId} from '../iam/iam.types';
import type {WorkflowPlanV1,WorkflowStep} from '../workflows/workflow.types';
import {ANNOTATION_CHANGE_OPERATIONS,type AnnotationChangeRequest,type AnnotationMetadataPayload} from './entity-annotation-workflow.types';
const fail=()=>new BadRequestException({code:'ENTITY_ANNOTATION_PLAN_INVALID'}),hex=/^[a-f\d]{64}$/;
function json(value:unknown,seen=new WeakSet<object>(),depth=0):void {
 if(depth>25)throw fail();
 if(value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number'&&Number.isFinite(value))return;
 if(!value||typeof value!=='object'||seen.has(value)||Object.getOwnPropertySymbols(value).length
  ||(Array.isArray(value)?Object.getPrototypeOf(value)!==Array.prototype||Object.getOwnPropertyNames(value).length!==value.length+1:![Object.prototype,null].includes(Object.getPrototypeOf(value))))throw fail();
 seen.add(value);for(const [key,d] of Object.entries(Object.getOwnPropertyDescriptors(value))){if(Array.isArray(value)&&key==='length')continue;
  if(['__proto__','constructor','prototype'].includes(key)||d.get||d.set||Array.isArray(value)&&!/^(0|[1-9]\d*)$/.test(key))throw fail();json(d.value,seen,depth+1);}
 seen.delete(value);
}
export function normalizeAnnotationChangeRequest(raw:unknown):Readonly<AnnotationChangeRequest>{
 json(raw);const v=iamBody(immutableJson(raw),['entityType','entityId','operation','input']);
 if(!ANNOTATION_CHANGE_OPERATIONS.includes(v.operation)||!v.input||typeof v.input!=='object'||Array.isArray(v.input))throw fail();
 const type=entityType(v.entityType),id=iamId(v.entityId).toLowerCase();
 if(Buffer.byteLength(JSON.stringify(v.input),'utf8')>131072)throw fail();
 return immutableJson({entityType:type,entityId:id,operation:v.operation,input:v.input});
}
export function assertEntityAnnotationPlan(plan:WorkflowPlanV1):WorkflowStep {
 if(!plan||(plan.kind as string)!=='entity-annotation'||(plan.subject.type as string)!=='entity_annotation_requests'||plan.requester.type!=='console'
  ||plan.executionMode!=='approval'||plan.approvalRequired!==true||!Array.isArray(plan.steps)||plan.steps.length!==1||!Array.isArray(plan.prerequisites)||plan.prerequisites.length
  ||plan.generated!==undefined||plan.migration!==undefined||(plan as any).scheduling!==undefined)throw fail();
 const s=plan.steps[0],p=s.metadata as AnnotationMetadataPayload;
 if(s.kind!=='metadata'||s.handler!=='entity.annotation'||s.key!=='entity.annotation'||s.entityType!=='entity_annotation_requests'||s.entityId!==plan.subject.id
  ||!Array.isArray(s.nativeRequests)||s.nativeRequests.length||!Array.isArray(s.dependencies)||s.dependencies.length||s.order!==1||s.parentId!=null||s.credentialKind!=null
  ||['mutationAction','mutationPayload','beforeFingerprint','mutationIdempotencyKey','mutationPayloadHmac'].some(k=>(s as any)[k]!==undefined)
  ||!p||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==5||!['intentId','entityType','entityId','operation','materialHmac'].every(k=>Object.hasOwn(p,k))
  ||p.intentId!==plan.subject.id||!ANNOTATION_CHANGE_OPERATIONS.includes(p.operation)||typeof p.materialHmac!=='string'||!hex.test(p.materialHmac)
  ||typeof s.metadataBeforeHmac!=='string'||!hex.test(s.metadataBeforeHmac)||typeof s.metadataPayloadHmac!=='string'||!hex.test(s.metadataPayloadHmac)
  ||!Number.isSafeInteger(s.metadataRevision)||Number(s.metadataRevision)<0||Number(s.metadataRevision)>=2147483647||s.permissionAction!==(p.operation==='remove'?'delete':'write'))throw fail();
 iamId(p.intentId);iamId(p.entityId);entityType(p.entityType);return s;
}
