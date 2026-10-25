import { ForbiddenException, Injectable } from '@nestjs/common';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath, entityForPath } from '../../infrastructure/kong/policy';
import { grantMatchesEntity, coarseGrantMatches, validGrant } from '../authorization/grant-policy';
import type { WorkflowBusinessMaterial } from './workflow-business-material.types';
import type { WorkflowScheduleCandidateReadInput as Input, WorkflowScheduleCandidateReadScope as Scope, WorkflowScheduleCandidateReadResource as Resource } from './workflow-schedule-candidate-read.types';
import type { WorkflowBusinessScopedReadBridge, WorkflowBusinessScopedDescriptor as Descriptor, WorkflowBusinessScopedSubject as Subject } from './workflow-business-scoped-read.types';

const deny=(code:string)=>new ForbiddenException({code});
const credentialKinds=new Set(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
/** Exact points remove unrelated workspace rows from the actor's data channel.
 * The original Material provider still verifies SQL/AEAD, real raw READ and
 * secrets, parent ownership and every proposed action after all observations.
 * Promote retains complete original coverage; unsupported scoped closure is
 * rejected by actual every-row grants rather than hiding possible drift.
 * Compilation does not grant READ or mutations, including for super-admin;
 * its current identity/member/workspace checks remain in Material/provider. */
@Injectable()
export class WorkflowBusinessScopedReadService implements WorkflowBusinessScopedReadBridge {
  private allowed(input:Input,module:string,action:'read'|'write'|'approve',subject:Subject):boolean {
    return input.principal.grants.some(grant=>grantMatchesEntity(grant,module,action,{clusterId:subject.clusterId,workspaceId:subject.workspaceId,
      entityType:subject.entityType,entity:subject.entity}));
  }
  async assertSubject(input:Input,material:Readonly<WorkflowBusinessMaterial>,descriptors:readonly Readonly<Descriptor>[],observed?:readonly Readonly<Subject>[]):Promise<void>{
    if(input.principal.user.superAdmin)throw deny('WORKFLOW_BUSINESS_SCOPED_PRINCIPAL_REQUIRED');
    const feature=material.kind==='configuration_v2'?'snapshots':'portal',workflowAction=input.role==='reviewer'?'approve':'write',featureAction=input.role==='reviewer'?'read':'write';
    // This is pre-read admission only. It grants no point or Native request;
    // exact current feature scopes are checked after real READ observations.
    for(const [module,action]of [['workflows',workflowAction],[feature,featureAction]]as const)if(!input.principal.grants.some(g=>validGrant(g)
      &&coarseGrantMatches(g,module,action,{clusterId:input.plan.clusterId,workspaceId:input.plan.workspaceId})))throw deny('WORKFLOW_BUSINESS_SCOPED_FEATURE_DENIED');
    if(material.kind==='configuration_v2'&&material.promotion)for(const inventory of [material.promotion.source,material.promotion.target])
      if(!input.principal.grants.some(g=>coarseGrantMatches(g,'promote',input.role==='executor'?'write':'read',inventory.scope)))throw deny('WORKFLOW_BUSINESS_PROMOTION_READ_REQUIRED');
    if(!observed)return;
    const subjects=material.kind==='portal-credential-issue'?observed.filter(s=>s.entityType==='services'&&s.entity.id===material.publicationProof.serviceId):observed;
    if(!subjects.length&&descriptors.length)throw deny('WORKFLOW_BUSINESS_SCOPED_SUBJECT_UNOBSERVED');
    // Empty native plans have no tag/entity subject to intersect. Metadata
    // still needs an actual complete feature grant, never a coarse tag match.
    if(!subjects.length)for(const [module,action]of [['workflows',workflowAction],[feature,featureAction]]as const)
      if(!input.principal.grants.some(g=>coarseGrantMatches(g,module,action,{clusterId:input.plan.clusterId,workspaceId:input.plan.workspaceId})
        &&(g.scope_type==='global'||g.scope_type==='workspace'&&g.scope_values.includes(input.plan.workspaceId))))throw deny('WORKFLOW_BUSINESS_SCOPED_FEATURE_DENIED');
    for(const subject of subjects)if(!this.allowed(input,'workflows',workflowAction,subject)||!this.allowed(input,feature,featureAction,subject))throw deny('WORKFLOW_BUSINESS_SCOPED_FEATURE_DENIED');
    if(material.kind==='configuration_v2'&&material.promotion)for(const subject of subjects)
      if(!this.allowed(input,'promote',input.role==='executor'?'write':'read',subject))throw deny('WORKFLOW_BUSINESS_PROMOTION_READ_REQUIRED');
  }
  async resolveReadScope(input:Input,material:Readonly<WorkflowBusinessMaterial>,descriptors:readonly Readonly<Descriptor>[],original:Readonly<Scope>):Promise<Readonly<Scope>>{
    if(material.kind==='configuration_v2'&&material.promotion)return immutableJson({...original,domain:'scoped-points-v1'});
    const resources=new Map<string,Resource>(),add=(resource:Resource)=>{
      assertKongPath('GET',resource.path);const key=`${resource.clusterId}:${resource.workspaceId}:${resource.path}`,old=resources.get(key);
      if(old&&old.entityId!==resource.entityId)throw deny('WORKFLOW_BUSINESS_SCOPED_RESOURCE_CONFLICT');
      resources.set(key,old?{...old,secrets:old.secrets||resource.secrets,required:old.required||resource.required,allowAbsent:old.allowAbsent||resource.allowAbsent}:resource);
    };
    for(const resource of original.resources)if(resource.kind!=='collection')add({...resource,required:true});
    for(const descriptor of descriptors){
      const type=descriptor.type,path=type==='targets'?`/upstreams/${descriptor.parentId}/targets/${descriptor.id}`:credentialKinds.has(type)?`/consumers/${descriptor.parentId}/${type}/${descriptor.id}`:`/${type}/${descriptor.id}`;
      add({clusterId:input.plan.clusterId,workspaceId:descriptor.workspaceId,path,kind:'point',entityType:entityForPath(path)??type,entityId:descriptor.id,
        ...(descriptor.parentId?{parentId:descriptor.parentId}:{}),secrets:credentialKinds.has(type)||['plugins','certificates'].includes(type),required:true,...(descriptor.create?{allowAbsent:true}:{})});
      if(descriptor.appendAllocatedId){if(type!=='targets'||descriptor.create||descriptor.appendAllocatedId===descriptor.id)throw deny('WORKFLOW_BUSINESS_SCOPED_RESOURCE_CONFLICT');
        add({clusterId:input.plan.clusterId,workspaceId:descriptor.workspaceId,path:`/upstreams/${descriptor.parentId}/targets/${descriptor.appendAllocatedId}`,kind:'point',
          entityType:'targets',entityId:descriptor.appendAllocatedId,parentId:descriptor.parentId,secrets:false,required:true,allowAbsent:true});}
    }
    if(!resources.size||resources.size>500)throw deny('WORKFLOW_BUSINESS_SCOPED_RESOURCE_BUDGET');
    // Real parents before children, then schemas. Raw Route references retain
    // the original order needed for the established Service-read inheritance.
    const order=(r:Resource)=>r.kind==='schema'?100:r.entityType==='routes'?10:r.entityType==='services'?20:r.entityType==='consumers'?30
      :r.entityType==='upstreams'?40:r.entityType==='certificates'?50:r.entityType==='ca_certificates'?60:r.entityType==='snis'?70:r.entityType==='plugins'?80:90;
    return immutableJson({version:1,domain:'scoped-points-v1',resources:[...resources.values()].sort((a,b)=>order(a)-order(b)||a.clusterId.localeCompare(b.clusterId)||a.path.localeCompare(b.path)),limits:original.limits});
  }
}
