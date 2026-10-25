import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService, type ToolboxOperationProof } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { AuditService } from '../audit/audit.service';
import type { EntityActor } from '../entities/entities.types';
import { WorkflowPlansService } from '../workflows/workflow-plans.service';
import { WorkflowRegistryService } from '../workflows/workflow-registry.service';
import { assertToolboxWorkflowPlan, type ToolboxWorkflowPayload } from '../workflows/toolbox-workflow';
import type { WorkflowPlanV1 } from '../workflows/workflow.types';
import { workflowKey } from '../workflows/workflow-validation';
import { portalConfirm, requirePortalCas } from '../portal/portal-input';
import { cacheKey, toolboxId, toolboxObject } from './toolbox-input';

export function cacheOperationProjection(row:any){return{operationId:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,cacheKey:row.cache_key,kind:row.kind,executionMode:row.execution_mode,clusterRevision:row.cluster_revision,workspaceRevision:row.workspace_revision};}
type Claim={proof:ToolboxOperationProof;actor:EntityActor;key:string;clusterRevision:number;workspaceRevision:number;active:boolean};
@Injectable()
export class CacheOperationsService implements OnModuleInit {
  private readonly handles=new WeakMap<object,Claim>();
  private readonly prepared=new Map<string,{operationId:string;payloadHmac:string;result:Record<string,unknown>}>();
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly redis:RedisService,
    private readonly kong:KongService,private readonly context:KongExecutionContextService,private readonly authz:AuthorizationService,
    private readonly workspaces:WorkspaceResolverService,private readonly audit:AuditService,private readonly plans:WorkflowPlansService,private readonly registry:WorkflowRegistryService){}
  onModuleInit():void{
    this.context.installToolboxOperationPolicy({verifyHandle:handle=>this.verifyHandle(handle),beforeSend:handle=>this.beforeSend(handle)});
    this.registry.register('toolbox.execute',{
      authorize:async(plan,actor,action)=>{assertToolboxWorkflowPlan(plan);await this.authz.assertWholeCluster(actor.user,plan.clusterId,'toolbox',action==='approve'?'approve':action);await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,plan.workspaceId,'workflows',action);if(action==='write'&&actor.user.id!==plan.requester.id)throw new ForbiddenException({code:'CACHE_EXECUTOR_MISMATCH'});},
      inspect:async({plan,step},tx)=>{assertToolboxWorkflowPlan(plan);const row=await this.operation(plan.clusterId,plan.workspaceId,(step.metadata as ToolboxWorkflowPayload).operationId,tx);this.binding(row,plan);return{before:cacheOperationProjection(row),revision:1};},
      prepare:async({plan,step,actor,executionId})=>{
        assertToolboxWorkflowPlan(plan);const row=await this.operation(plan.clusterId,plan.workspaceId,plan.subject.id);this.binding(row,plan);
        const result=await this.executeOperation(row,{...actor,workspaceId:plan.workspaceId},{executionId,stepId:step.id,workflowId:plan.workflowId,planHash:this.secrets.fingerprint(plan)});
        this.prepared.set(executionId,{operationId:row.id,payloadHmac:this.secrets.fingerprint(step.metadata),result});
      },
      apply:async({plan,step,executionId})=>{
        const claim=this.prepared.get(executionId);if(!claim||claim.operationId!==plan.subject.id||claim.payloadHmac!==this.secrets.fingerprint(step.metadata))throw new ForbiddenException({code:'CACHE_METADATA_RESULT_REQUIRED'});
        this.prepared.delete(executionId);return claim.result;
      },
    });
  }
  private async operation(cid:string,wid:string,id:string,db=this.db){const row=await db.one<any>('SELECT * FROM toolbox_operations WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[cid,wid,toolboxId(id)]);if(!row)throw new NotFoundException({code:'TOOLBOX_OPERATION_NOT_FOUND'});return row;}
  private binding(row:any,plan:WorkflowPlanV1){const step=assertToolboxWorkflowPlan(plan),payload=step.metadata as ToolboxWorkflowPayload;
    if(row.id!==plan.subject.id||row.workflow_id!==plan.workflowId||row.actor_id!==plan.requester.id||row.cache_key!==payload.cacheKey||row.execution_mode!==plan.executionMode||row.transport_scope!==plan.scope.transportScope||row.cluster_revision!==plan.scope.clusterRevision||row.workspace_revision!==plan.scope.workspaceRevision||this.secrets.fingerprint(cacheOperationProjection(row))!==step.metadataBeforeHmac||this.secrets.fingerprint(payload)!==step.metadataPayloadHmac)throw new ConflictException({code:'CACHE_WORKFLOW_BINDING_INVALID'});
  }
  private summary(row:any){return{id:row.id,actorId:row.actor_id,idempotencyKey:row.idempotency_key,kind:row.kind,clusterId:row.cluster_id,workspaceId:row.workspace_id,key:row.cache_key,state:row.state,revision:row.revision,executionMode:row.execution_mode,workflowId:row.workflow_id,remoteStarted:row.remote_started,remoteCompleted:row.remote_completed,errorCode:row.error_code,nodeLocal:true,rollbackSupported:false,expiresAt:row.expires_at,result:row.safe_result};}
  private hints(wid:string,id:string){return{quality:'verified' as const,module:'toolbox',subject:{type:'toolbox_operations',id},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid};}
  private async observed(cid:string,key:string){try{return{found:true,value:await this.kong.request(cid,'GET',`/cache/${encodeURIComponent(key)}`)};}catch(error){if(error instanceof HttpException&&error.getStatus()===404)return{found:false,value:null};throw error;}}
  async invalidate(cid:string,body:unknown,actor:EntityActor){const value=toolboxObject(body,['key','confirmed','confirm_name']),name=cacheKey(value.key);portalConfirm(value,name);
    return this.context.runActor({actor:actor.user,clusterId:toolboxId(cid),workspaceId:actor.workspaceId,module:'toolbox',action:'write'},async()=>{
      const ws=await this.workspaces.resolve(cid,actor.workspaceId);if(ws.status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED'});
      await this.authz.assertWholeCluster(actor.user,cid,'toolbox','read');await this.authz.assertWholeCluster(actor.user,cid,'toolbox','write');
      const key=workflowKey(actor.idempotencyKey),hmac=this.secrets.fingerprint({cid,wid:ws.id,actor:actor.user.id,value}),version=await this.authz.permissionVersion(actor.user);
      const old=await this.db.one<any>('SELECT * FROM toolbox_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
      if(old){if(old.request_hmac!==hmac||old.cluster_id!==cid||old.workspace_id!==ws.id)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return this.summary(old);}
      const cluster=await this.db.one<any>('SELECT revision,execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND'});
      if(cluster.execution_mode==='approval')await this.authz.assertWholeWorkspace(actor.user,cid,ws.id,'workflows','write');
      const observed=await this.observed(cid,name);if(Buffer.byteLength(JSON.stringify(observed))>262144)throw new BadRequestException({code:'CACHE_CAPTURE_BUDGET'});
      const id=randomUUID(),transport=await this.kong.transportScope(cid),expiresAt=new Date(Date.now()+14*60000).toISOString();
      const row=await this.db.transaction(async tx=>{
        if(await this.authz.permissionVersion(actor.user,tx)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
        const duplicate=await tx.one<any>('SELECT * FROM toolbox_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);if(duplicate){if(duplicate.request_hmac!==hmac)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return duplicate;}
        const workflowId=cluster.execution_mode==='approval'?randomUUID():null;
        await tx.exec(`INSERT INTO toolbox_operations(id,cluster_id,workspace_id,transport_scope,actor_id,idempotency_key,kind,cache_key,request_hmac,before_hmac,before_secret,cluster_revision,workspace_revision,execution_mode,workflow_id,state,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,'cache-invalidate',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,[id,cid,ws.id,transport,actor.user.id,key,name,hmac,this.secrets.fingerprint(observed),this.secrets.encrypt(observed,`toolbox-cache:${id}:before`),cluster.revision,ws.revision,cluster.execution_mode,workflowId,workflowId?'pending-approval':'planned',expiresAt]);
        const created=await this.operation(cid,ws.id,id,tx);
        if(workflowId){await this.plans.definitions(cid,ws.id,actor.user.id,tx);const definition=await this.plans.definition(cid,ws.id,'toolbox-operation',tx),payload:ToolboxWorkflowPayload={operationId:id,cacheKey:name,kind:'cache-invalidate'};
          const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:ws.id,workflowId,planRevision:1,kind:'toolbox-operation',executionMode:'approval',approvalRequired:true,subject:{type:'toolbox_operations',id},requester:{type:'console',id:actor.user.id},definition,issuedAt:new Date().toISOString(),expiresAt,scope:{transportScope:transport,clusterRevision:cluster.revision,workspaceRevision:ws.revision},prerequisites:[],steps:[{id:randomUUID(),key:'cache-invalidate',order:1,kind:'metadata',handler:'toolbox.execute',entityType:'toolbox_operations',entityId:id,permissionAction:'write',dependencies:[],nativeRequests:[],before:cacheOperationProjection(created),metadata:payload,metadataRevision:1,metadataBeforeHmac:this.secrets.fingerprint(cacheOperationProjection(created)),metadataPayloadHmac:this.secrets.fingerprint(payload)}]};
          await this.plans.persist(plan,`cache-workflow-${id}`,{operationId:id},tx,{requestId:actor.requestId,ip:actor.ip});
        }
        await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'toolbox_operations',entityId:id,workflowId:workflowId??undefined,action:'toolbox.cache.invalidate.requested',requestId:actor.requestId,ip:actor.ip,after:{key:name,nodeLocal:true,found:observed.found,executionMode:cluster.execution_mode},result:'pending',scopeHints:this.hints(ws.id,id)},tx);
        return created;
      });
      if(row.state==='planned')return this.executeOperation(row,{...actor,workspaceId:ws.id});return this.summary(row);
    });
  }
  async get(cid:string,id:string,actor:EntityActor){return this.context.runActor({actor:actor.user,clusterId:toolboxId(cid),workspaceId:actor.workspaceId,module:'toolbox',action:'read'},async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),epoch=await this.authz.permissionVersion(actor.user);await this.authz.assertWholeCluster(actor.user,cid,'toolbox','read');const row=await this.operation(cid,ws.id,id);if(row.actor_id!==actor.user.id)throw new NotFoundException({code:'TOOLBOX_OPERATION_NOT_FOUND'});if(await this.authz.permissionVersion(actor.user)!==epoch)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});return this.summary(row);
  });}
  async byKey(cid:string,key:string,actor:EntityActor){return this.context.runActor({actor:actor.user,clusterId:toolboxId(cid),workspaceId:actor.workspaceId,module:'toolbox',action:'read'},async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),epoch=await this.authz.permissionVersion(actor.user);await this.authz.assertWholeCluster(actor.user,cid,'toolbox','read');const row=await this.db.one<any>('SELECT * FROM toolbox_operations WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4',[cid,ws.id,actor.user.id,workflowKey(key)]);
    if(!row)throw new NotFoundException({code:'TOOLBOX_OPERATION_NOT_FOUND'});if(await this.authz.permissionVersion(actor.user)!==epoch)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});return this.summary(row);
  });}
  private async verifyHandle(handle:object):Promise<ToolboxOperationProof>{
    const claim=this.handles.get(handle),frame=this.context.current();if(!claim?.active||!frame.actor||frame.actor.id!==claim.proof.actorId||frame.sessionId!==claim.proof.sessionId||claim.proof.expiresAt<=Date.now())throw new ForbiddenException({code:'CACHE_EXECUTION_HANDLE_REQUIRED'});
    const row=await this.operation(claim.proof.clusterId,claim.proof.workspaceId,claim.proof.operationId),cluster=await this.db.one<any>('SELECT revision,execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[row.cluster_id]),ws=await this.workspaces.get(row.cluster_id,row.workspace_id);
    if(row.state!=='running'||row.remote_completed||row.actor_id!==claim.actor.user.id||row.execution_actor_id!==claim.actor.user.id||row.cache_key!==claim.key||row.transport_scope!==claim.proof.transportScope||row.execution_mode!==claim.proof.executionMode||cluster?.revision!==claim.clusterRevision||cluster?.execution_mode!==claim.proof.executionMode||ws.revision!==claim.workspaceRevision||ws.status!=='active')throw new ForbiddenException({code:'CACHE_EXECUTION_CHANGED'});
    await this.authz.assertWholeCluster(claim.actor.user,row.cluster_id,'toolbox','write');if(await this.authz.permissionVersion(claim.actor.user)!==claim.proof.permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});await this.redis.assertLeaseOwnership();
    if(claim.proof.executionMode==='approval'){
      const step=this.context.currentApprovedStep(),wf=await this.db.one<any>(`SELECT w.state,w.plan_hash,e.state AS execution_state,e.snapshot_state,s.state AS step_state,s.handler,s.metadata_payload_hmac FROM workflows w JOIN workflow_executions e ON e.workflow_id=w.id JOIN workflow_steps s ON s.workflow_id=w.id AND s.plan_revision=w.plan_revision WHERE w.id=$1 AND e.id=$2 AND s.id=$3 AND e.execution_actor_id=$4`,[row.workflow_id,claim.proof.workflowExecutionId,claim.proof.workflowStepId,claim.actor.user.id]);
      if(step.stepId!==claim.proof.workflowStepId||step.execution.executionId!==claim.proof.workflowExecutionId||!wf||wf.state!=='executing'||wf.execution_state!=='executing'||wf.snapshot_state!=='ready'||wf.step_state!=='running'||wf.handler!=='toolbox.execute')throw new ForbiddenException({code:'CACHE_APPROVAL_EXECUTION_REQUIRED'});
    }
    return claim.proof;
  }
  private async beforeSend(handle:object){const proof=await this.verifyHandle(handle),row=await this.operation(proof.clusterId,proof.workspaceId,proof.operationId);
    if(!row.remote_started)requirePortalCas(await this.db.exec("UPDATE toolbox_operations SET remote_started=true,revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND revision=$2 AND remote_started=false",[row.id,row.revision]));await this.verifyHandle(handle);
  }
  private async executeOperation(row:any,actor:EntityActor,approved?:{executionId:string;stepId:string;workflowId:string;planHash:string}):Promise<any>{
    return this.context.runActor({actor:actor.user,clusterId:row.cluster_id,workspaceId:row.workspace_id,module:'toolbox',action:'write'},()=>this.redis.withLock(`toolbox-operation:${row.id}`,()=>this.redis.withLock(`mutation:${row.transport_scope}`,async()=>{
      const current=await this.operation(row.cluster_id,row.workspace_id,row.id);if(current.state==='succeeded')return this.summary(current);
      if(!['planned','pending-approval'].includes(current.state)||current.remote_started||Date.parse(current.expires_at)<=Date.now()||current.execution_mode==='approval'&&!approved||current.workflow_id!==(approved?.workflowId??null))throw new ConflictException({code:'CACHE_OPERATION_NOT_EXECUTABLE'});
      await this.authz.assertWholeCluster(actor.user,current.cluster_id,'toolbox','read');await this.authz.assertWholeCluster(actor.user,current.cluster_id,'toolbox','write');
      const observed=await this.observed(current.cluster_id,current.cache_key);if(this.secrets.fingerprint(observed)!==current.before_hmac)throw new ConflictException({code:'CACHE_BEFORE_CHANGED',message:'缓存内容已变化，请重新生成失效计划'});
      const frame=this.context.current();if(!frame.sessionId)throw new ForbiddenException({code:'CACHE_SESSION_REQUIRED'});
      const proof:ToolboxOperationProof={operationId:current.id,actorId:actor.user.id,sessionId:frame.sessionId,clusterId:current.cluster_id,workspaceId:current.workspace_id,transportScope:current.transport_scope,canonicalPath:`/cache/${encodeURIComponent(current.cache_key)}`,permissionVersion:await this.authz.permissionVersion(actor.user),expiresAt:Math.min(Date.now()+10000,Date.parse(current.expires_at)),executionMode:current.execution_mode,...(approved?{workflowExecutionId:approved.executionId,workflowStepId:approved.stepId}:{})};
      requirePortalCas(await this.db.exec("UPDATE toolbox_operations SET state='running',execution_actor_id=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$3 AND state=$4 AND remote_started=false",[current.id,actor.user.id,current.revision,current.state]));
      const handle=Object.freeze({}),claim:Claim={proof,actor,key:current.cache_key,clusterRevision:current.cluster_revision,workspaceRevision:current.workspace_revision,active:true};this.handles.set(handle,claim);
      try{
        await this.context.runToolboxOperation(handle,()=>this.kong.request(current.cluster_id,'DELETE',proof.canonicalPath));
        const result={key:current.cache_key,invalidated:true,nodeLocal:true,rollbackSupported:false,remoteStarted:true,remoteCompleted:true,observedAt:new Date().toISOString()};
        await this.db.transaction(async tx=>{
          requirePortalCas(await tx.exec("UPDATE toolbox_operations SET state='succeeded',remote_completed=true,safe_result=$2::jsonb,revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND remote_started=true AND execution_actor_id=$3",[current.id,JSON.stringify(result),actor.user.id]));
          await this.audit.append({actorId:actor.user.id,clusterId:current.cluster_id,workspaceId:current.workspace_id,entityType:'toolbox_operations',entityId:current.id,workflowId:current.workflow_id??undefined,action:'toolbox.cache.invalidate',requestId:actor.requestId,ip:actor.ip,before:{key:current.cache_key,found:observed.found},after:result,result:'success',scopeHints:this.hints(current.workspace_id,current.id)},tx);
        });return this.summary(await this.operation(current.cluster_id,current.workspace_id,current.id));
      }catch(error){
        const actual=await this.operation(current.cluster_id,current.workspace_id,current.id);if(actual.state==='succeeded')return this.summary(actual);
        const known=error instanceof HttpException&&error.getStatus()<500,uncertain=actual.remote_started&&!known,detail=error instanceof HttpException?error.getResponse():null;
        const code=typeof detail==='object'&&detail&&(detail as any).code?String((detail as any).code).replace(/[^A-Z0-9_]/g,'').slice(0,80):'CACHE_RESULT_UNKNOWN';
        await this.db.transaction(async tx=>{requirePortalCas(await tx.exec("UPDATE toolbox_operations SET state=$2,error_code=$3,revision=revision+1,updated_at=now() WHERE id=$1 AND state='running'",[current.id,uncertain?'uncertain':'failed',code]));
          await this.audit.append({actorId:actor.user.id,clusterId:current.cluster_id,workspaceId:current.workspace_id,entityType:'toolbox_operations',entityId:current.id,workflowId:current.workflow_id??undefined,action:'toolbox.cache.invalidate',requestId:actor.requestId,ip:actor.ip,after:{key:current.cache_key,code},result:uncertain?'uncertain':'failed',scopeHints:this.hints(current.workspace_id,current.id)},tx);});throw error;
      }finally{claim.active=false;this.handles.delete(handle);}
    })));
  }
}
