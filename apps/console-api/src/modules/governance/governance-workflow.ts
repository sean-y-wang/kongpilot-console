import {BadRequestException} from '@nestjs/common';
import type {WorkflowPlanV1,WorkflowStep} from '../workflows/workflow.types';
import type {GovernanceFixedMetadataPayload,GovernanceMetadataOperation,GovernanceMetadataResource} from './governance-storage.types';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i,digest=/^[a-f0-9]{64}$/;
const fail=():never=>{throw new BadRequestException({code:'GOVERNANCE_METADATA_WORKFLOW_INVALID'});};
export const GOVERNANCE_METADATA_RESOURCES=['governance_rules','governance_schedules','entity_annotations'] as const;
export function governanceMetadataModule(resource:GovernanceMetadataResource):'lint'|'governance'|'annotations'{return resource==='governance_rules'?'lint':resource==='entity_annotations'?'annotations':'governance';}
export function governanceMetadataAction(operation:GovernanceMetadataOperation):'write'|'delete'{return operation==='archive'?'delete':'write';}
/** Fixed console metadata only. This plan cannot carry a native packet, callback or chosen table. */
export function assertGovernanceMetadataPlan(plan:WorkflowPlanV1):WorkflowStep{
 if(!plan||(plan.kind as string)!=='governance-metadata'||(plan.subject.type as string)!=='governance_metadata_requests'||plan.requester.type!=='console'||plan.executionMode!=='approval'||plan.approvalRequired!==true||plan.steps.length!==1||plan.prerequisites.length||plan.generated!==undefined||plan.migration!==undefined)fail();
 const step=plan.steps[0],m=step.metadata as GovernanceFixedMetadataPayload;
 if(step.kind!=='metadata'||step.handler!=='governance.metadata'||step.entityType!=='governance_metadata_requests'||step.entityId!==plan.subject.id||step.parentId!=null||step.credentialKind!=null||step.nativeRequests.length||step.dependencies.length||step.mutationAction!==undefined||step.mutationPayload!==undefined||step.mutationIdempotencyKey!==undefined||step.beforeFingerprint!==undefined)fail();
 if(!m||typeof m!=='object'||Array.isArray(m)||![Object.prototype,null].includes(Object.getPrototypeOf(m))||Object.keys(m).length!==5||!['intentId','resourceType','resourceId','operation','payloadHmac'].every(k=>Object.hasOwn(m,k))||m.intentId!==plan.subject.id||!uuid.test(m.resourceId)||!uuid.test(m.intentId)||!(GOVERNANCE_METADATA_RESOURCES as readonly string[]).includes(m.resourceType)||!['create','update','archive','restore'].includes(m.operation)||!digest.test(m.payloadHmac)||!digest.test(step.metadataPayloadHmac??'')||!digest.test(step.metadataBeforeHmac??''))fail();
 if(step.permissionAction!==governanceMetadataAction(m.operation)||!Number.isSafeInteger(step.metadataRevision)||Number(step.metadataRevision)<0||m.operation==='create'&&(step.before!==null||step.metadataRevision!==0)||m.resourceType==='entity_annotations'&&!['create','update'].includes(m.operation))fail();
 return step;
}
export function governanceMetadataLedgerInput(payload:GovernanceFixedMetadataPayload):GovernanceFixedMetadataPayload{return{intentId:payload.intentId,resourceType:payload.resourceType,resourceId:payload.resourceId,operation:payload.operation,payloadHmac:payload.payloadHmac};}
export function governanceMetadataProjection(value:unknown):Record<string,unknown>|null{
 if(value===null||value===undefined)return null;if(typeof value!=='object'||Array.isArray(value))return{};const v=value as Record<string,unknown>,out:Record<string,unknown>={};
 for(const key of ['id','code','name','state','revision','current_version','enabled','resourceType','resourceId','operation','description','severity','entityType','nativeId'])if(Object.hasOwn(v,key)&&(['string','number','boolean'].includes(typeof v[key])||v[key]===null))out[key]=v[key];
 if(v.content&&typeof v.content==='object'&&!Array.isArray(v.content)){const c=v.content as Record<string,unknown>;out.content=Object.fromEntries(['code','name','description','severity','given','then','enabled','kind','scope','serviceIds','ruleCodes','intervalMinutes','timezone','threshold','paused','includeEnvironmentFields'].filter(k=>Object.hasOwn(c,k)).map(k=>[k,structuredClone(c[k])]));}
 if(v.content&&typeof v.content==='object'&&!Array.isArray(v.content)){const target=(v.content as Record<string,any>).target;if(target&&typeof target==='object'&&!Array.isArray(target))((out.content??={}) as Record<string,unknown>).target=Object.fromEntries(['clusterId','workspaceId','scope','serviceIds'].filter(k=>Object.hasOwn(target,k)).map(k=>[k,structuredClone(target[k])]));}
 return out;
}
