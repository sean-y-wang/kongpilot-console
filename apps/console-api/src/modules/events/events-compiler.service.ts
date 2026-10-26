import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { IamMutationsService } from '../iam/iam-mutations.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import type { EntityActor } from '../entities/entities.types';
import { DeliveryPolicyService } from '../event-delivery/delivery-policy.service';
import type { DeliveryChannelAuth, DeliveryProviderType } from '../event-delivery/delivery.types';
import { EVENT_TYPES } from '../event-core/event.types';
import { WorkflowPlansService } from '../workflows/workflow-plans.service';
import { eventMetadataProjection, eventWorkflowHandler, type EventWorkflowHandlerName } from '../workflows/event-workflow';
import type { WorkflowPlanV1, WorkflowSummary } from '../workflows/workflow.types';
import { eventConfirm, eventId, eventKey, eventNativeType, eventObject, eventRevision, eventStatus, eventStrings, eventTags, eventText } from './events-input';
import { EventsMetadataService, type SharedEventRow } from './events-metadata.service';
import type { EventMetadataPayload, EventMutationResult, EventOperationReceipt, EventRequestIdentity, EventScopeSnapshot } from './events.types';

@Injectable()
export class EventsCompilerService {
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly authz:AuthorizationService,private readonly iam:IamMutationsService,private readonly workspaces:WorkspaceResolverService,
    private readonly policy:DeliveryPolicyService,private readonly metadata:EventsMetadataService,private readonly plans:WorkflowPlansService) {}
  private async scope(cid:string,actor:EntityActor,action:'read'|'write'|'delete') {
    cid=eventId(cid);const wid=eventId(actor.workspaceId),workspace=await this.workspaces.get(cid,wid);
    await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',action);
    const cluster=await this.db.one<{admin_url:string;transport_scope:string;revision:number;execution_mode:'direct'|'approval';version:string;status:string}>('SELECT admin_url,transport_scope,revision,execution_mode,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
    if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND'});
    if(action!=='read'&&(workspace.status!=='active'||cluster.status==='disabled'))throw new ConflictException({code:'EVENT_SCOPE_UNAVAILABLE'});
    return{cid,wid,workspace,cluster};
  }
  private identity(handler:EventWorkflowHandlerName,id:string|undefined,body:Record<string,unknown>,action=false):EventRequestIdentity {
    return{handler,createOrUpdate:action?'action':id?'update':'create',targetIdOrCollection:id??(handler==='event.channel.save'?'notification_channels':'event_subscriptions'),originalRequestHmac:this.secrets.fingerprint(body)};
  }
  private async assertSnapshot(cid:string,wid:string,snapshot:EventScopeSnapshot,tx=this.db,lock=false):Promise<void>{
    const suffix=lock?' FOR SHARE':'',cluster=await tx.one<{admin_url:string;transport_scope:string;revision:number;execution_mode:string;version:string;status:string}>('SELECT admin_url,transport_scope,revision,execution_mode,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL'+suffix,[cid]);
    const workspace=await tx.one<{revision:number;status:string}>('SELECT revision,status FROM workspaces WHERE cluster_id=$1 AND id=$2'+suffix,[cid,wid]);
    if(!cluster||!workspace||cluster.status==='disabled'||workspace.status!=='active'
      ||cluster.execution_mode!==snapshot.executionMode||cluster.revision!==snapshot.clusterRevision||workspace.revision!==snapshot.workspaceRevision
      ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==snapshot.transportScope)throw new ConflictException({code:'EVENT_SCOPE_CHANGED'});
  }
  private sameIdentity(payload:unknown,identity:EventRequestIdentity):boolean {
    if(!payload||typeof payload!=='object')return false;const value=payload as Record<string,unknown>;
    return this.secrets.fingerprint(Object.fromEntries(Object.keys(identity).map(key=>[key,value[key]])))===this.secrets.fingerprint(identity);
  }
  private async receiptAuthority(actor:EntityActor,cid:string,wid:string,action:'write'|'delete',readProof:boolean):Promise<void>{
    if(readProof&&await this.authz.hasWholeWorkspace(actor.user,cid,wid,'events','read'))return;
    await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',action);
  }
  private receiptResult(result:EventMutationResult|undefined):EventMutationResult|undefined{
    if(!result?.entity)return result;
    // A stored success is a historical business result, never a cached grant
    // for another UI action. The live directory owns current action controls.
    const entity=structuredClone(result.entity);entity.capabilities=Object.fromEntries(Object.keys(entity.capabilities).map(key=>[key,false])) as typeof entity.capabilities;
    return{...result,entity};
  }
  /** Real ledgers are searched before revision, UUID allocation, DNS or mode.
   * This intentionally detects collisions with a foreign scope/namespace. */
  private async prior(cid:string,wid:string,actor:EntityActor,identity?:EventRequestIdentity,readProof=false):Promise<EventOperationReceipt|null> {
    const key=eventKey(actor.idempotencyKey);
    const iam=await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
    const workflows=await this.db.query<any>('SELECT * FROM workflows WHERE requester_user_id=$1 AND idempotency_key=$2 ORDER BY created_at LIMIT 2',[actor.user.id,key]);
    if(iam&&workflows.length||workflows.length>1)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
    if(iam){
      if(iam.module!=='events'||iam.cluster_id!==cid||iam.workspace_id!==wid)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
      const payload=this.secrets.decrypt<EventMetadataPayload>(iam.payload_secret,`iam:${iam.id}:payload`),mapping=eventWorkflowHandler(payload.handler);
      if(identity&&!this.sameIdentity(payload,identity))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
      await this.receiptAuthority(actor,cid,wid,mapping.action,readProof);
      const complete=iam.state==='succeeded'&&iam.remote_completed===true;
      const result=this.receiptResult(complete&&iam.result_secret?this.secrets.decrypt<EventMutationResult>(iam.result_secret,`iam:${iam.id}:result`):undefined);
      return{domain:'iam',id:iam.id,clusterId:cid,workspaceId:wid,idempotencyKey:key,handler:payload.handler,state:iam.state,
        configurationCommitted:complete,submissionCompleted:false,executionCompleted:complete,queued:!!result?.queued,deliverySucceeded:false,
        ...(result?{result}:{}),errorCode:iam.error_code??null};
    }
    const workflow=workflows[0];if(!workflow)return null;
    if(workflow.kind!=='event-metadata'||workflow.cluster_id!==cid||workflow.workspace_id!==wid)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
    const loaded=await this.plans.load(cid,wid,workflow.id),step=loaded.plan.steps[0],payload=step.metadata as EventMetadataPayload,mapping=eventWorkflowHandler(payload.handler);
    if(identity&&!this.sameIdentity(payload,identity))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
    // Submission-only proof is the submitter's original events permission. It
    // exposes no plan, other workflow, approval or execution capability.
    await this.receiptAuthority(actor,cid,wid,mapping.action,readProof);
    const terminal=await this.db.one<{state:string;safe_result:EventMutationResult}>('SELECT state,safe_result FROM workflow_steps WHERE id=$1 AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4',[step.id,workflow.id,workflow.plan_revision,workflow.plan_hash]);
    const complete=workflow.state==='succeeded'&&terminal?.state==='succeeded';
    const result=this.receiptResult(complete?terminal!.safe_result:undefined);
    const entity:WorkflowSummary={id:workflow.id,kind:'event-metadata',clusterId:cid,workspaceId:wid,name:'event-metadata',revision:workflow.revision,planRevision:workflow.plan_revision,planHash:workflow.plan_hash,state:workflow.state,executionMode:workflow.execution_mode,approvalRequired:true,createdAt:new Date(workflow.created_at).toISOString(),expiresAt:new Date(workflow.expires_at).toISOString(),capabilities:{approve:false,reject:false,cancel:false,execute:false}};
    return{domain:'workflow',id:workflow.id,clusterId:cid,workspaceId:wid,idempotencyKey:key,handler:payload.handler,state:workflow.state,workflowId:workflow.id,
      revision:workflow.revision,planHash:workflow.plan_hash,configurationCommitted:complete,submissionCompleted:true,executionCompleted:complete,queued:!!result?.queued,deliverySucceeded:false,entity,...(result?{result}:{})};
  }
  async receipt(cid:string,key:string,actor:EntityActor):Promise<EventOperationReceipt> {
    const wid=eventId(actor.workspaceId);await this.workspaces.get(eventId(cid),wid);
    const version=await this.authz.permissionVersion(actor.user),prior=await this.prior(cid,wid,{...actor,idempotencyKey:key},undefined,true);
    if(!prior)throw new NotFoundException({code:'EVENT_OPERATION_NOT_FOUND'});
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});return prior;
  }
  async channel(cid:string,id:string|undefined,body:unknown,actor:EntityActor):Promise<EventOperationReceipt> {
    const handler='event.channel.save',value=eventObject(body,id?['revision','endpoint','auth','options','status']:['name','type','endpoint','auth','options','status']);
    const wid=eventId(actor.workspaceId),identity=this.identity(handler,id?eventId(id):undefined,value);
    return this.submit(cid,wid,id,identity,actor,async before=>{
      if(id){eventRevision(value.revision);if(!before||before.revision!==value.revision)throw new ConflictException({code:'EVENT_REVISION_CONFLICT'});}
      const type=id?before!.type:String(value.type) as DeliveryProviderType;
      if(!type||!['webhook','email','slack','feishu'].includes(type))throw new BadRequestException({code:'INVALID_EVENT_PROVIDER'});
      const payload:EventMetadataPayload={...identity,...(!id?{name:eventText(value.name),type}:{}),...(value.status!==undefined?{desiredStatus:eventStatus(value.status)}:{})};
      if(!id||Object.hasOwn(value,'endpoint')||Object.hasOwn(value,'auth')||Object.hasOwn(value,'options')){
        if(id&&Object.hasOwn(value,'endpoint')&&!Object.hasOwn(value,'auth'))throw new BadRequestException({code:'EVENT_NEW_TARGET_AUTH_REQUIRED',message:'更换目标时请明确选择新认证或无认证'});
        const old=id?this.metadata.material(before!):null;
        payload.desiredConfigSecret=await this.policy.validateChannelConfig({type,
          endpoint:(value.endpoint??(old?('url'in old.endpoint?old.endpoint.url:{recipients:[...old.endpoint.recipients]}):undefined)) as string|{recipients:string[]},
          auth:(value.auth??old?.auth??{type:'none'}) as DeliveryChannelAuth,...(value.options===undefined?{}:{options:value.options as Record<string,never>})});
      }
      return payload;
    });
  }
  async subscription(cid:string,id:string|undefined,body:unknown,actor:EntityActor):Promise<EventOperationReceipt> {
    const handler='event.subscription.save',value=eventObject(body,id?['revision','eventTypes','nativeType','nativeIds','tags','status']:['name','channelId','eventTypes','nativeType','nativeIds','tags','status']);
    const wid=eventId(actor.workspaceId),identity=this.identity(handler,id?eventId(id):undefined,value);
    return this.submit(cid,wid,id,identity,actor,async before=>{
      if(id){eventRevision(value.revision);if(!before||before.revision!==value.revision)throw new ConflictException({code:'EVENT_REVISION_CONFLICT'});}
      const eventTypes=eventStrings(value.eventTypes??before?.event_types,32,type=>{if(typeof type!=='string'||!(EVENT_TYPES as readonly string[]).includes(type))throw new BadRequestException({code:'INVALID_EVENT_TYPE'});return type;});
      if(!eventTypes.length)throw new BadRequestException({code:'EVENT_TYPES_REQUIRED'});
      const nativeType=eventNativeType(Object.hasOwn(value,'nativeType')?value.nativeType:before?.native_type),nativeIds=eventStrings(value.nativeIds??before?.native_ids??[],256,eventId);
      if(nativeIds.length&&!nativeType)throw new BadRequestException({code:'EVENT_NATIVE_TYPE_REQUIRED'});
      const channelId=id?before!.channel_id!:eventId(value.channelId);
      const channel=await this.metadata.row('event.channel.save',cid,wid,channelId);
      if(!channel||channel.status!=='active')throw new ConflictException({code:'EVENT_CHANNEL_INACTIVE'});
      return{...identity,...(!id?{name:eventText(value.name),channelId}:{}),eventTypes,nativeType,nativeIds,
        physicalTags:Object.hasOwn(value,'tags')?eventTags(value.tags):before?.physical_tags??[],...(value.status!==undefined?{desiredStatus:eventStatus(value.status)}:{})};
    });
  }
  async action(cid:string,id:string,handler:Exclude<EventWorkflowHandlerName,'event.channel.save'|'event.subscription.save'>,body:unknown,actor:EntityActor):Promise<EventOperationReceipt> {
    const value=eventObject(body,handler==='event.channel.status'?['revision','status','confirmed','confirm_name']:['revision','confirmed','confirm_name']),wid=eventId(actor.workspaceId),identity=this.identity(handler,eventId(id),value,true);
    return this.submit(cid,wid,id,identity,actor,async before=>{
      if(!before)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});eventConfirm(value,before.name??before.id);
      if(before.revision!==value.revision)throw new ConflictException({code:'EVENT_REVISION_CONFLICT'});
      return{...identity,...(handler==='event.channel.status'?{desiredStatus:eventStatus(value.status)}:{})};
    });
  }
  private async submit(cid:string,wid:string,id:string|undefined,identity:EventRequestIdentity,actor:EntityActor,compile:(before:SharedEventRow|null)=>Promise<EventMetadataPayload>):Promise<EventOperationReceipt> {
    cid=eventId(cid);eventKey(actor.idempotencyKey);const mapping=eventWorkflowHandler(identity.handler);
    return this.redis.withLock(`event-operation:${actor.user.id}:${actor.idempotencyKey}`,async()=>{
      await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',mapping.action);
      const prior=await this.prior(cid,wid,actor,identity);if(prior)return prior;
      const scope=await this.scope(cid,actor,mapping.action),permissionVersion=await this.authz.permissionVersion(actor.user),before=id?await this.metadata.row(identity.handler,cid,wid,eventId(id)):null;
      const snapshot:EventScopeSnapshot={executionMode:scope.cluster.execution_mode,clusterRevision:scope.cluster.revision,workspaceRevision:scope.workspace.revision,transportScope:transportScopeFor(scope.cluster.admin_url,scope.cluster.transport_scope)};
      if(id&&!before)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});
      const payload=await compile(before);
      await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',mapping.action);
      if(await this.authz.permissionVersion(actor.user)!==permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
      await this.assertSnapshot(cid,wid,snapshot);
      const target=id?eventId(id):randomUUID();
      if(scope.cluster.execution_mode==='direct')await this.iam.execute({module:'events',action:mapping.action,targetId:id?target:undefined,cluster_id:cid,workspace_id:wid,payload,actor},async(tx,operationId,setBusinessAudit)=>{
        const result=await this.metadata.applyDirect(identity.handler,cid,wid,target,before,payload,actor,operationId,tx,snapshot);
        setBusinessAudit({entityType:mapping.subject,entityId:target,before:eventMetadataProjection(before),after:result,
          scopeHints:{quality:'verified',module:'events',subject:{type:mapping.subject,id:target},beforeExists:before!==null,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid}});
        return result;
      });
      else await this.db.transaction(async tx=>{
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        await this.assertSnapshot(cid,wid,snapshot,tx,true);
        await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',mapping.action);
        await this.redis.assertLeaseOwnership();
        const workflowId=randomUUID(),actual=id?await this.metadata.row(identity.handler,cid,wid,target,tx,true):await this.metadata.reserve(identity.handler,cid,wid,target,payload,actor,workflowId,tx);
        if(id&&this.secrets.fingerprint(actual)!==this.secrets.fingerprint(before))throw new ConflictException({code:'EVENT_REVISION_CONFLICT'});
        await this.plans.definitions(cid,wid,actor.user.id,tx);const definition=await this.plans.definition(cid,wid,'event-metadata',tx);
        const plan:WorkflowPlanV1={version:1,kind:'event-metadata',clusterId:cid,workspaceId:wid,workflowId,planRevision:1,executionMode:'approval',approvalRequired:true,subject:{type:mapping.subject,id:target},requester:{type:'console',id:actor.user.id},definition,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),scope:{transportScope:transportScopeFor(scope.cluster.admin_url,scope.cluster.transport_scope),clusterRevision:scope.cluster.revision,workspaceRevision:scope.workspace.revision},prerequisites:[],steps:[{id:randomUUID(),key:identity.handler,order:1,kind:'metadata',handler:identity.handler,entityType:mapping.subject,entityId:target,permissionAction:mapping.action,dependencies:[],nativeRequests:[],before:actual,metadataRevision:actual!.revision,metadataBeforeHmac:this.secrets.fingerprint(actual),metadata:payload,metadataPayloadHmac:this.secrets.fingerprint(payload)}]};
        await this.plans.persist(plan,eventKey(actor.idempotencyKey),identity,tx,{requestId:actor.requestId,ip:actor.ip});
        await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',mapping.action);await this.redis.assertLeaseOwnership();
        if(await this.authz.permissionVersion(actor.user)!==permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
      });
      const receipt=await this.prior(cid,wid,actor,identity);if(!receipt)throw new ConflictException({code:'EVENT_RESULT_UNCERTAIN'});return receipt;
    });
  }
}
