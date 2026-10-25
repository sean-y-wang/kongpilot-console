import { BadRequestException } from '@nestjs/common';
import type { WorkflowNativeRequest, WorkflowPlanV1, WorkflowStep } from './workflow.types';
import type { WorkspaceMigrationMaterial } from '../workspaces/workspace-migration.service';

const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const digest=/^[a-f0-9]{64}$/;
const roots=new Set(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis']);
const credentials=new Set(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
export interface WorkspaceMigrationWorkflowPayload { plan_id:string;plan_hash:string;confirmed:true;confirm_name:string; }
export function migrationNativeRequests(material:WorkspaceMigrationMaterial,secrets:{fingerprint(value:unknown):string}):WorkflowNativeRequest[]{
 return material.nodes.filter(node=>!node.inheritedOnly).map(node=>{
  const body={tags:node.afterTags},parentId=credentials.has(node.type)?node.path.split('/')[2]:undefined;
  return {method:'PATCH',canonicalPath:node.path,nativeType:node.type,nativeId:node.id,...(parentId?{parentId,credentialKind:node.type}:{}),body,bodyHmac:secrets.fingerprint(body),beforeHmac:node.beforeFingerprint};
 });
}
/** Restricts the logical migration to the server's existing M3 implementation.
 * Matching this shape alone grants no authority: the SQL binding and original
 * encrypted M3 material are compared again by the private execution verifier. */
export function assertWorkspaceMigrationWorkflowPlan(plan:WorkflowPlanV1):WorkflowStep {
 const fail=():never=>{throw new BadRequestException({code:'INVALID_WORKSPACE_MIGRATION_WORKFLOW'});};
 if(plan.kind!=='workspace-migration'||plan.subject.type!=='workspace_migration_plans'||plan.requester.type!=='console'||plan.executionMode!=='approval'||!plan.approvalRequired||plan.steps.length!==1||plan.generated!==undefined)fail();
 const migration=plan.migration;
 if(!migration||Object.keys(migration).some(key=>!['sourceWorkspaceId','targetWorkspaceId','targetWorkspaceRevision','materialHmac'].includes(key))||migration.sourceWorkspaceId!==plan.workspaceId||!uuid.test(migration.targetWorkspaceId)||migration.targetWorkspaceId===plan.workspaceId||!Number.isInteger(migration.targetWorkspaceRevision)||migration.targetWorkspaceRevision<1||!digest.test(migration.materialHmac))fail();
 const step=plan.steps[0],payload=step.mutationPayload as WorkspaceMigrationWorkflowPayload,before=step.before as {id?:string;workspace_id?:string};
 if(step.kind!=='native'||step.key!=='workspace-migration'||step.handler!==undefined||step.entityType!=='workspace_migration'||step.entityId!==plan.subject.id||step.mutationAction!=='migrate'||step.permissionAction!=='write'||step.dependencies.length||step.parentId!==undefined||step.credentialKind!==undefined||step.metadata!==undefined||step.metadataRevision!==undefined||step.metadataBeforeHmac!==undefined||step.metadataPayloadHmac!==undefined)fail();
 if(!payload||Object.keys(payload).length!==4||Object.keys(payload).some(key=>!['plan_id','plan_hash','confirmed','confirm_name'].includes(key))||payload.plan_id!==plan.subject.id||!digest.test(payload.plan_hash)||payload.confirmed!==true||typeof payload.confirm_name!=='string'||payload.confirm_name.length<1||payload.confirm_name.length>160)fail();
 if(!before||Object.keys(before).length!==2||before.id!==plan.subject.id||before.workspace_id!==plan.workspaceId||!digest.test(step.beforeFingerprint??'')||!digest.test(step.mutationPayloadHmac??'')||!step.mutationIdempotencyKey||step.nativeRequests.length<1||step.nativeRequests.length>32)fail();
 const paths=new Set<string>();
 for(const request of step.nativeRequests){
  if(Object.keys(request).some(key=>!['method','canonicalPath','nativeType','nativeId','parentId','credentialKind','body','bodyHmac','beforeHmac'].includes(key))||request.method!=='PATCH'||!uuid.test(request.nativeId??'')||!digest.test(request.beforeHmac??'')||!digest.test(request.bodyHmac)||paths.has(request.canonicalPath))fail();
  const parts=request.canonicalPath.split('/').slice(1);
  if(roots.has(request.nativeType)){
   if(parts.length!==2||parts[0]!==request.nativeType||parts[1]!==request.nativeId||request.parentId!==undefined||request.credentialKind!==undefined)fail();
  }else if(credentials.has(request.nativeType)){
   if(parts.length!==4||parts[0]!=='consumers'||parts[1]!==request.parentId||!uuid.test(request.parentId??'')||parts[2]!==request.nativeType||parts[3]!==request.nativeId||request.credentialKind!==request.nativeType)fail();
  }else fail();
  const body=request.body as {tags?:unknown};
  if(!body||Object.keys(body).length!==1||!Array.isArray(body.tags)||!body.tags.length||body.tags.some(tag=>typeof tag!=='string'||!tag.length||tag.length>128)||new Set(body.tags).size!==body.tags.length||body.tags.filter(tag=>String(tag).startsWith('kos-ws-')).length!==1)fail();
  paths.add(request.canonicalPath);
 }
 if(!Array.isArray(plan.prerequisites)||plan.prerequisites.length>64)fail();
 const referencePaths=new Set<string>();
 for(const reference of plan.prerequisites){
  if(!reference||typeof reference!=='object'||Array.isArray(reference)||Object.keys(reference).length!==5
    ||Object.keys(reference).some(key=>!['type','id','path','before','fingerprint'].includes(key))||!uuid.test(reference.id)
    ||typeof reference.path!=='string'||!digest.test(reference.fingerprint)||!reference.before||typeof reference.before!=='object'
    ||Array.isArray(reference.before)||reference.before.id!==reference.id||paths.has(reference.path)||referencePaths.has(reference.path))fail();
  const parts=reference.path.split('/').slice(1);
  if(roots.has(reference.type)){
   if(parts.length!==2||parts[0]!==reference.type||parts[1]!==reference.id)fail();
  }else if(credentials.has(reference.type)){
   if(parts.length!==4||parts[0]!=='consumers'||!uuid.test(parts[1])||parts[2]!==reference.type||parts[3]!==reference.id
     ||reference.before.consumer?.id!==parts[1])fail();
  }else if(reference.type==='targets'){
   if(parts.length!==4||parts[0]!=='upstreams'||!uuid.test(parts[1])||parts[2]!=='targets'||parts[3]!==reference.id
     ||reference.before.upstream?.id!==parts[1])fail();
  }else fail();
  referencePaths.add(reference.path);
 }
 return step;
}
