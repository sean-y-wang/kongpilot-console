import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { EntityActor, objectBody } from '../entities/entities.types';
import { WorkspaceMigrationService } from '../workspaces/workspace-migration.service';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowService } from './workflow.service';
import { workflowKey } from './workflow-validation';
import { migrationNativeRequests } from './workspace-migration-workflow';
import type { WorkflowPlanV1 } from './workflow.types';

/** Only authenticates and seals the existing M3 migration. This service never
 * sends a native write and cannot turn a caller body into a native packet. */
@Injectable()
export class WorkspaceMigrationWorkflowService {
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly kong:KongService,private readonly authz:AuthorizationService,private readonly migrations:WorkspaceMigrationService,
  private readonly plans:WorkflowPlansService,private readonly workflows:WorkflowService,private readonly execution:KongExecutionContextService){}
 @KongActorScope({module:'workspaces',action:'write'})
 async submit(cid:string,id:string,input:unknown,actor:EntityActor):Promise<any>{
  const body=objectBody(input),key=workflowKey(actor.idempotencyKey);
  if(Object.keys(body).some(field=>!['confirmed','confirm_name','plan_hash'].includes(field)))throw new BadRequestException({code:'INVALID_MIGRATION_FIELD'});
  const requestHash=this.secrets.fingerprint({migrationId:id,input:body});
  return this.redis.withLock(`workspace-migration-workflow:${cid}:${id}`,async()=>{
   const previous=await this.db.one<any>('SELECT b.*,w.idempotency_key FROM workspace_migration_workflow_bindings b JOIN workflows w ON w.id=b.workflow_id WHERE b.cluster_id=$1 AND b.migration_plan_id=$2',[cid,id]);
   if(previous){
    if(previous.actor_id!==actor.user.id||previous.source_workspace_id!==actor.workspaceId||previous.idempotency_key!==key||previous.request_hash!==requestHash)throw new ConflictException({code:'MIGRATION_WORKFLOW_ALREADY_SUBMITTED',message:'迁移已有冻结工单，请核验原提交回执'});
    return this.workflows.get(cid,previous.workflow_id,actor);
   }
   const {row,material}=await this.migrations.workflowMaterial(cid,id,body,actor);
   for(const wid of [material.source.id,material.target.id])await this.authz.assertWholeWorkspace(actor.user,cid,wid,'workflows','write');
   const cluster=await this.db.one<any>('SELECT revision,execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
   if(!cluster||cluster.execution_mode!=='approval')throw new ConflictException({code:'MIGRATION_WORKFLOW_MODE_REQUIRED',message:'直接执行集群请使用迁移执行入口'});
   const nativeRequests=migrationNativeRequests(material,this.secrets),prerequisites=[...material.referenceNodes,...material.nodes.filter(node=>node.inheritedOnly)].map(node=>({type:node.type,id:node.id,path:node.path,before:node.data,fingerprint:this.secrets.fingerprint(node.data)}));
   if(!nativeRequests.length||nativeRequests.length>32||prerequisites.length>64)throw new BadRequestException({code:'MIGRATION_WORKFLOW_CAPTURE_LIMIT',message:'审批迁移限 32 个需写对象、64 个共享或继承对象，请缩小选择范围'});
   const payload={plan_id:id,plan_hash:row.plan_hash,confirmed:true as const,confirm_name:material.target.name},before={id,workspace_id:material.source.id};
   const workflowId=randomUUID(),expiresAt=new Date(Math.min(Date.parse(String(row.expires_at)),Date.now()+14*60*1000)).toISOString(),transport=await this.kong.transportScope(cid);
   await this.db.transaction(async tx=>{
    const locked=await tx.one<any>('SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,id]);
    if(!locked||locked.actor_id!==actor.user.id||locked.plan_hash!==row.plan_hash||locked.state!=='planned'||locked.operation_id||locked.payload_secret!==row.payload_secret||Date.parse(locked.expires_at)<=Date.now())throw new ConflictException({code:'MIGRATION_PLAN_CHANGED'});
    await this.plans.definitions(cid,material.source.id,actor.user.id,tx);
    const definition=await this.plans.definition(cid,material.source.id,'workspace-migration',tx);
    const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:material.source.id,workflowId,planRevision:1,kind:'workspace-migration',executionMode:'approval',approvalRequired:true,
     subject:{type:'workspace_migration_plans',id},requester:{type:'console',id:actor.user.id},definition,issuedAt:new Date().toISOString(),expiresAt,
     scope:{transportScope:transport,clusterRevision:cluster.revision,workspaceRevision:material.source.revision},
     migration:{sourceWorkspaceId:material.source.id,targetWorkspaceId:material.target.id,targetWorkspaceRevision:material.target.revision,materialHmac:this.secrets.fingerprint(material)},prerequisites,
     steps:[{id:randomUUID(),key:'workspace-migration',order:1,kind:'native',entityType:'workspace_migration',entityId:id,permissionAction:'write',dependencies:[],mutationAction:'migrate',mutationPayload:payload,mutationPayloadHmac:this.secrets.fingerprint(payload),mutationIdempotencyKey:`migration-${workflowId}`,before,beforeFingerprint:this.secrets.fingerprint(before),nativeRequests}]};
    await tx.exec(`INSERT INTO workspace_migration_workflow_bindings(cluster_id,source_workspace_id,target_workspace_id,migration_plan_id,workflow_id,actor_id,migration_plan_hash,material_hmac,request_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[cid,material.source.id,material.target.id,id,workflowId,actor.user.id,row.plan_hash,plan.migration!.materialHmac,requestHash]);
    await this.plans.persist(plan,key,{migrationId:id,input:body},tx,{requestId:actor.requestId,ip:actor.ip});
   });
   return this.workflows.get(cid,workflowId,{...actor,workspaceId:material.source.id});
  });
 }
}
