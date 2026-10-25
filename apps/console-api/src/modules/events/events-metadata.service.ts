import { ConflictException, Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService, type AuditOutboxReceipt } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { DeliveryPolicyService } from '../event-delivery/delivery-policy.service';
import type { DeliveryProviderType, ValidatedDeliveryChannel } from '../event-delivery/delivery.types';
import { EventRepositoryService } from '../event-core/event-repository.service';
import type { QueueMetadataReceipt } from '../event-core/event.types';
import type { EntityActor } from '../entities/entities.types';
import { decodeTag } from '../../infrastructure/kong/tags';
import { retentionDays } from '../iam/iam.types';
import { ApprovedWorkflowExecutionService } from '../workflows/approved-workflow-execution.service';
import { eventExecutionAuditProof, eventMetadataProjection, eventWorkflowHandler, EVENT_WORKFLOW_HANDLERS, type EventWorkflowHandlerName } from '../workflows/event-workflow';
import { WorkflowRegistryService } from '../workflows/workflow-registry.service';
import type { WorkflowHandlerInput } from '../workflows/workflow.types';
import { eventCas } from './events-input';
import type { EventMetadataPayload, EventMutationResult, EventScopeSnapshot, SafeChannel, SafeSubscription, SharedEventStatus } from './events.types';

export interface SharedEventRow {
  id:string;cluster_id:string;workspace_id:string;name?:string;status?:SharedEventStatus;revision:number;
  created_by?:string;updated_by?:string;workflow_id?:string|null;created_at:Date|string;updated_at:Date|string;
  deleted_at?:Date|string|null;retention_until?:Date|string|null;
  type?:DeliveryProviderType;endpoint_secret?:string|null;auth_secret?:string|null;options_safe?:Record<string,never>;credential_generation?:number;
  channel_id?:string;event_types?:string[];native_type?:string|null;native_ids?:string[];physical_tags?:string[];
  state?:string;event_id?:string;intent_started_at?:Date|string|null;
}
interface ApplyContext {
  cid:string;wid:string;id:string;handler:EventWorkflowHandlerName;payload:EventMetadataPayload;before:SharedEventRow|null;
  actor:EntityActor;tx:DbService;source:Pick<QueueMetadataReceipt,'iamOperationId'|'workflow'>;
  operationProof:Record<string,unknown>;
  scope:EventScopeSnapshot;
}
export const eventChannelAad=(row:Pick<SharedEventRow,'id'|'cluster_id'|'workspace_id'>,generation:number,purpose:'endpoint'|'auth')=>`event-channel:${row.id}:${row.cluster_id}:${row.workspace_id}:${generation}:${purpose}`;

@Injectable()
export class EventsMetadataService implements OnModuleInit {
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly audit:AuditService,
    private readonly authz:AuthorizationService,private readonly policy:DeliveryPolicyService,private readonly events:EventRepositoryService,
    private readonly approved:ApprovedWorkflowExecutionService,private readonly registry:WorkflowRegistryService) {}
  onModuleInit():void {
    for(const handler of Object.keys(EVENT_WORKFLOW_HANDLERS) as EventWorkflowHandlerName[])this.registry.register(handler,{
      authorize:(plan,actor,action)=>this.approved.assertSubject(plan,actor.user,action),
      prepare:input=>this.prepare(input),inspect:(input,tx)=>this.inspect(input,tx),apply:input=>this.applyApproved(input),
    });
  }
  private table(handler:EventWorkflowHandlerName):string{return eventWorkflowHandler(handler).subject;}
  async row(handler:EventWorkflowHandlerName,cid:string,wid:string,id:string,tx=this.db,lock=false):Promise<SharedEventRow|null> {
    return tx.one<SharedEventRow>(`SELECT * FROM ${this.table(handler)} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3${lock?' FOR UPDATE':''}`,[id,cid,wid]);
  }
  private async prepare(input:Omit<WorkflowHandlerInput,'transaction'>):Promise<void> {
    const payload=input.step.metadata as EventMetadataPayload;
    if(payload.desiredConfigSecret){const material=payload.desiredConfigSecret;
      await this.policy.validateChannelConfig({type:material.type,endpoint:'url'in material.endpoint?material.endpoint.url:{recipients:[...material.endpoint.recipients]},auth:material.auth,options:{}});
      await this.approved.assertSubject(input.plan,input.actor.user,'write');
    }
  }
  private async inspect(input:Omit<WorkflowHandlerInput,'transaction'>,tx:DbService):Promise<{before:unknown;revision:number}> {
    const row=await this.row(input.step.handler as EventWorkflowHandlerName,input.plan.clusterId,input.plan.workspaceId,input.step.entityId!,tx,true);
    if(!row)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});return{before:row,revision:row.revision};
  }
  async writableScope(row:Pick<SharedEventRow,'cluster_id'|'workspace_id'>):Promise<boolean>{
    const scope=await this.db.one<{status:string;version:string;workspace_status:string}>(`SELECT c.status,c.version,w.status AS workspace_status FROM clusters c JOIN workspaces w ON w.cluster_id=c.id AND w.id=$2 WHERE c.id=$1 AND c.deleted_at IS NULL`,[row.cluster_id,row.workspace_id]);
    return!!scope&&scope.workspace_status==='active'&&scope.status!=='disabled'&&/^1\.5\.\d+$/.test(scope.version??'');
  }
  async channelView(row:SharedEventRow,actor?:EntityActor):Promise<SafeChannel> {
    const material=row.endpoint_secret?this.material(row):null;
    const summary=material?this.policy.safeSummary(material):{destinationHost:null,maskedDestination:'尚未配置',authConfigured:false};
    const active=!!actor&&await this.writableScope(row),can=async(action:'write'|'delete')=>active&&await this.authz.hasWholeWorkspace(actor!.user,row.cluster_id,row.workspace_id,'events',action);
    const write=await can('write'),del=await can('delete');
    return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,name:row.name!,type:row.type!,status:row.status!,revision:row.revision,
      credentialGeneration:row.credential_generation!,configured:!!row.endpoint_secret,options:row.options_safe??{},...summary,createdAt:new Date(row.created_at).toISOString(),
      capabilities:{write:write&&row.status!=='deleted'&&row.status!=='pending',delete:del&&row.status!=='deleted'&&row.status!=='pending',restore:write&&row.status==='deleted',test:write&&row.status==='active'}};
  }
  async subscriptionView(row:SharedEventRow,actor?:EntityActor):Promise<SafeSubscription> {
    const active=!!actor&&await this.writableScope(row),write=active&&await this.authz.hasWholeWorkspace(actor!.user,row.cluster_id,row.workspace_id,'events','write'),del=active&&await this.authz.hasWholeWorkspace(actor!.user,row.cluster_id,row.workspace_id,'events','delete');
    return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,name:row.name!,channelId:row.channel_id!,status:row.status!,revision:row.revision,
      eventTypes:[...(row.event_types??[])],nativeType:row.native_type??null,nativeIds:[...(row.native_ids??[])],tags:(row.physical_tags??[]).map(decodeTag),createdAt:new Date(row.created_at).toISOString(),
      capabilities:{write:write&&row.status!=='deleted'&&row.status!=='pending',delete:del&&row.status!=='deleted'&&row.status!=='pending',restore:write&&row.status==='deleted'}};
  }
  material(row:SharedEventRow):ValidatedDeliveryChannel {
    if(!row.endpoint_secret||!row.type||!row.credential_generation)throw new ConflictException({code:'EVENT_CHANNEL_NOT_CONFIGURED'});
    const endpoint=this.secrets.decrypt<ValidatedDeliveryChannel['endpoint']>(row.endpoint_secret,eventChannelAad(row,row.credential_generation,'endpoint'));
    const auth=row.auth_secret?this.secrets.decrypt<ValidatedDeliveryChannel['auth']>(row.auth_secret,eventChannelAad(row,row.credential_generation,'auth')):{type:'none' as const};
    return{type:row.type,endpoint,auth,optionsSafe:row.options_safe??{},safeSummary:this.policy.safeSummary({type:row.type,endpoint,auth})};
  }
  private async version(handler:EventWorkflowHandlerName,row:SharedEventRow,actorId:string,tx:DbService):Promise<void> {
    if(this.table(handler)==='notification_channels')await tx.exec(`INSERT INTO notification_channel_versions(cluster_id,workspace_id,channel_id,revision,status,type,endpoint_secret,auth_secret,options_safe,credential_generation,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,[row.cluster_id,row.workspace_id,row.id,row.revision,row.status,row.type,row.endpoint_secret??null,row.auth_secret??null,JSON.stringify(row.options_safe??{}),row.credential_generation,actorId]);
    else await tx.exec(`INSERT INTO event_subscription_versions(cluster_id,workspace_id,subscription_id,revision,channel_id,status,event_types,native_type,native_ids,physical_tags,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[row.cluster_id,row.workspace_id,row.id,row.revision,row.channel_id,row.status,row.event_types,row.native_type??null,row.native_ids??[],row.physical_tags??[],actorId]);
  }
  async reserve(handler:EventWorkflowHandlerName,cid:string,wid:string,id:string,payload:EventMetadataPayload,actor:EntityActor,workflowId:string,tx:DbService):Promise<SharedEventRow> {
    if(handler==='event.channel.save')await tx.exec(`INSERT INTO notification_channels(id,cluster_id,workspace_id,name,type,status,created_by,updated_by,workflow_id) VALUES($1,$2,$3,$4,$5,'pending',$6,$6,$7)`,[id,cid,wid,payload.name,payload.type,actor.user.id,workflowId]);
    else if(handler==='event.subscription.save')await tx.exec(`INSERT INTO event_subscriptions(id,cluster_id,workspace_id,name,channel_id,event_types,status,created_by,updated_by,workflow_id) VALUES($1,$2,$3,$4,$5,ARRAY['channel.test'],'pending',$6,$6,$7)`,[id,cid,wid,payload.name,payload.channelId,actor.user.id,workflowId]);
    else throw new ConflictException({code:'EVENT_RESERVATION_INVALID'});
    const row=await this.row(handler,cid,wid,id,tx,true);if(!row)throw new Error('Event reservation missing');await this.version(handler,row,actor.user.id,tx);return row;
  }
  async applyDirect(handler:EventWorkflowHandlerName,cid:string,wid:string,id:string,before:SharedEventRow|null,payload:EventMetadataPayload,actor:EntityActor,operationId:string,tx:DbService,scope:EventScopeSnapshot):Promise<EventMutationResult> {
    const operation=await tx.one<{request_hash:string;actor_id:string;module:string;cluster_id:string;workspace_id:string}>('SELECT request_hash,actor_id,module,cluster_id,workspace_id FROM iam_operations WHERE id=$1',[operationId]);
    if(!operation||operation.actor_id!==actor.user.id||operation.module!=='events'||operation.cluster_id!==cid||operation.workspace_id!==wid)throw new ConflictException({code:'EVENT_IAM_OPERATION_INVALID'});
    const outcome=await this.apply({cid,wid,id,handler,before,payload,actor,tx,scope,source:{iamOperationId:operationId},operationProof:{version:1,handler,requestHmac:operation.request_hash,beforeHmac:this.secrets.fingerprint(before),payloadHmac:this.secrets.fingerprint(payload),iamOperationId:operationId}});
    return outcome.result;
  }
  private async applyApproved(input:WorkflowHandlerInput):Promise<Record<string,unknown>> {
    const{plan,step,actor,executionId,transaction:tx}=input;
    return this.apply({cid:plan.clusterId,wid:plan.workspaceId,id:step.entityId!,handler:step.handler as EventWorkflowHandlerName,before:step.before as SharedEventRow,payload:step.metadata as EventMetadataPayload,actor,tx,
      scope:{executionMode:'approval',...plan.scope},
      source:{workflow:{id:plan.workflowId,executionId,planRevision:plan.planRevision,planHash:this.secrets.fingerprint(plan),stepId:step.id}},
      operationProof:eventExecutionAuditProof(plan,step,executionId,this.secrets.fingerprint(plan)) as unknown as Record<string,unknown>});
  }
  private async apply(context:ApplyContext):Promise<{result:EventMutationResult;auditReceipt:AuditOutboxReceipt}> {
    const{cid,wid,id,handler,payload,actor,tx}=context,mapping=eventWorkflowHandler(handler),version=await this.authz.permissionVersion(actor.user);
    await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',mapping.action);
    const cluster=await tx.one<{admin_url:string;transport_scope:string;revision:number;execution_mode:string;version:string;status:string}>('SELECT admin_url,transport_scope,revision,execution_mode,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[cid]);
    const workspace=await tx.one<{revision:number;status:string}>('SELECT revision,status FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR SHARE',[cid,wid]);
    if(!cluster||!workspace||cluster.status==='disabled'||workspace.status!=='active'||!/^1\.5\.\d+$/.test(cluster.version??'')
      ||cluster.execution_mode!==context.scope.executionMode||cluster.revision!==context.scope.clusterRevision||workspace.revision!==context.scope.workspaceRevision
      ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==context.scope.transportScope)throw new ConflictException({code:'EVENT_SCOPE_CHANGED'});
    let current=await this.row(handler,cid,wid,id,tx,true);
    if(this.secrets.fingerprint(current)!==this.secrets.fingerprint(context.before))throw new ConflictException({code:'EVENT_REVISION_CONFLICT'});
    let result:EventMutationResult={};
    if(handler.startsWith('event.channel.')){
      if(handler==='event.channel.save'){
        const desired=payload.desiredConfigSecret;
        if(!current){if(payload.createOrUpdate!=='create'||!desired)throw new ConflictException({code:'EVENT_CHANNEL_CONFIG_REQUIRED'});
          const identity={id,cluster_id:cid,workspace_id:wid};await tx.exec(`INSERT INTO notification_channels(id,cluster_id,workspace_id,name,type,status,endpoint_secret,auth_secret,options_safe,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$10)`,[id,cid,wid,payload.name,payload.type,payload.desiredStatus??'active',this.secrets.encrypt(desired.endpoint,eventChannelAad(identity,1,'endpoint')),this.secrets.encrypt(desired.auth,eventChannelAad(identity,1,'auth')),JSON.stringify(desired.optionsSafe),actor.user.id]);
        }else{
          if(current.status==='deleted'||current.status==='pending'&&payload.createOrUpdate!=='create')throw new ConflictException({code:'EVENT_OBJECT_UNAVAILABLE'});
          const generation=current.credential_generation!+(desired?1:0);
          eventCas(await tx.exec(`UPDATE notification_channels SET status=$4,endpoint_secret=$5,auth_secret=$6,options_safe=$7::jsonb,credential_generation=$8,revision=revision+1,updated_by=$9,updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revision=$10`,[id,cid,wid,payload.desiredStatus??(current.status==='pending'?'active':current.status),desired?this.secrets.encrypt(desired.endpoint,eventChannelAad(current,generation,'endpoint')):current.endpoint_secret,desired?this.secrets.encrypt(desired.auth,eventChannelAad(current,generation,'auth')):current.auth_secret,JSON.stringify(desired?.optionsSafe??current.options_safe??{}),generation,actor.user.id,current.revision]));
        }
      }else{
        if(!current)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});
        if(handler==='event.channel.test'){if(current.status!=='active')throw new ConflictException({code:'EVENT_CHANNEL_INACTIVE'});}
        else await this.transition(context,current);
      }
      const saved=await this.row(handler,cid,wid,id,tx);if(!saved)throw new Error('Event channel readback missing');
      if(handler!=='event.channel.test')await this.version(handler,saved,actor.user.id,tx);
      result=handler==='event.channel.test'?{}:{entity:await this.channelView(saved,actor)};current=saved;
    }else if(handler.startsWith('event.subscription.')){
      if(handler==='event.subscription.save'){
        const channel=await tx.one<SharedEventRow>('SELECT * FROM notification_channels WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE',[payload.channelId??current?.channel_id,cid,wid]);
        if(!channel||channel.status!=='active')throw new ConflictException({code:'EVENT_CHANNEL_INACTIVE'});
        if(!current)await tx.exec(`INSERT INTO event_subscriptions(id,cluster_id,workspace_id,name,channel_id,event_types,native_type,native_ids,physical_tags,status,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,[id,cid,wid,payload.name,payload.channelId,payload.eventTypes,payload.nativeType??null,payload.nativeIds??[],payload.physicalTags??[],payload.desiredStatus??'active',actor.user.id]);
        else{if(current.status==='deleted'||current.status==='pending'&&payload.createOrUpdate!=='create')throw new ConflictException({code:'EVENT_OBJECT_UNAVAILABLE'});
          eventCas(await tx.exec(`UPDATE event_subscriptions SET event_types=$4,native_type=$5,native_ids=$6,physical_tags=$7,status=$8,revision=revision+1,updated_by=$9,updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revision=$10`,[id,cid,wid,payload.eventTypes??current.event_types,payload.nativeType===undefined?current.native_type:payload.nativeType,payload.nativeIds??current.native_ids,payload.physicalTags??current.physical_tags,payload.desiredStatus??(current.status==='pending'?'active':current.status),actor.user.id,current.revision]));}
      }else{if(!current)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});await this.transition(context,current);}
      current=await this.row(handler,cid,wid,id,tx);if(!current)throw new Error('Event subscription readback missing');await this.version(handler,current,actor.user.id,tx);result={entity:await this.subscriptionView(current,actor)};
    }else if(!current)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});
    const queue=handler==='event.channel.test'||handler==='event.delivery.replay';
    const auditReceipt=await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:context.source.workflow?.id,entityType:mapping.subject,entityId:id,action:handler,
      before:eventMetadataProjection(context.before),after:{result:queue?{queued:true}:result,operationProof:context.operationProof},result:'success',requestId:actor.requestId,ip:actor.ip,
      scopeHints:{quality:'verified',module:'events',subject:{type:mapping.subject,id},beforeExists:context.before!==null,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid}},tx);
    const proof={actorId:actor.user.id,clusterId:cid,workspaceId:wid,auditReceipt,...context.source};
    if(handler==='event.channel.test')result={queued:await this.events.enqueueTest({...proof,channelId:id,channelRevision:current!.revision,credentialGeneration:current!.credential_generation!},tx)};
    if(handler==='event.delivery.replay')result={queued:await this.events.enqueueReplay({...proof,deliveryId:id,expectedRevision:context.before!.revision},tx)};
    await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events',mapping.action);
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ConflictException({code:'PERMISSIONS_CHANGED'});
    return{result,auditReceipt};
  }
  private async transition(context:ApplyContext,current:SharedEventRow):Promise<void> {
    const{handler,cid,wid,id,tx,actor,payload}=context,deleted=handler.endsWith('.delete'),restore=handler.endsWith('.restore');
    if(restore?current.status!=='deleted':current.status==='deleted'||current.status==='pending')throw new ConflictException({code:'EVENT_OBJECT_UNAVAILABLE'});
    const status=deleted?'deleted':restore?'disabled':payload.desiredStatus;
    if(!status)throw new ConflictException({code:'INVALID_EVENT_TRANSITION'});
    eventCas(await tx.exec(`UPDATE ${this.table(handler)} SET status=$4,deleted_at=CASE WHEN $4='deleted' THEN now() ELSE NULL END,retention_until=CASE WHEN $4='deleted' THEN now()+($5::text||' days')::interval ELSE NULL END,revision=revision+1,updated_by=$6,updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revision=$7`,[id,cid,wid,status,retentionDays(),actor.user.id,current.revision]));
  }
}
