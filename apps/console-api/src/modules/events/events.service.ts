import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { DeliveryPolicyService } from '../event-delivery/delivery-policy.service';
import { EVENT_ACCESS, type EventAccess } from '../event-core/event-access';
import { EventRepositoryService } from '../event-core/event-repository.service';
import { EVENT_TYPES, type EventListQuery, type SafeDelivery } from '../event-core/event.types';
import type { EntityActor } from '../entities/entities.types';
import { EventsMetadataService, type SharedEventRow } from './events-metadata.service';
import { EventCursor, eventId, eventObject, eventPageSize, eventText } from './events-input';
import type { SafeChannel, SafeSubscription } from './events.types';

interface DeliveryRow extends SharedEventRow {
  event_id:string;delivery_kind:string;channel_id:string;subscription_id:string|null;state:SafeDelivery['state'];
  attempt_count:number;replay_generation:number;error_code:string|null;creator_id:string;
}
@Injectable()
export class EventsService {
  private readonly cursors=new EventCursor();
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly authz:AuthorizationService,
    private readonly workspaces:WorkspaceResolverService,private readonly policy:DeliveryPolicyService,private readonly metadata:EventsMetadataService,
    private readonly events:EventRepositoryService,@Inject(EVENT_ACCESS)private readonly access:EventAccess) {}
  private async scope(cid:string,actor:EntityActor,whole=false,history=false) {
    cid=eventId(cid);const wid=eventId(actor.workspaceId);await this.workspaces.get(cid,wid,history);
    if(whole)await this.authz.assertWholeWorkspace(actor.user,cid,wid,'events','read');else await this.authz.assertCluster(actor.user,cid,'events','read',wid);
    return{cid,wid,version:await this.authz.permissionVersion(actor.user)};
  }
  private async end(scope:{cid:string;wid:string;version:string},actor:EntityActor,whole=false):Promise<void> {
    if(whole)await this.authz.assertWholeWorkspace(actor.user,scope.cid,scope.wid,'events','read');
    else await this.authz.assertCluster(actor.user,scope.cid,'events','read',scope.wid);
    if(await this.authz.permissionVersion(actor.user)!==scope.version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
  }
  async catalog(cid:string,actor:EntityActor) {
    const scope=await this.scope(cid,actor);const providers=this.policy.describeProviders();await this.end(scope,actor);
    const labels:Record<string,string>={'entity.created':'实体创建','entity.updated':'实体修改','entity.deleted':'实体归档','entity.restored':'实体恢复','workflow.submitted':'工单提交','workflow.approval.progress':'审批进度','workflow.approved':'审批通过','workflow.rejected':'审批驳回','workflow.cancelled':'工单撤销','workflow.executed':'工单执行完成','workflow.failed':'工单执行失败','certificate.expiring':'证书到期预警','upstream.health.changed':'上游健康变化','config.drift':'配置漂移','channel.test':'渠道测试','delivery.replay':'投递重放'};
    return{eventTypes:EVENT_TYPES.map(type=>({type,label:labels[type],availability:type==='certificate.expiring'||type==='upstream.health.changed'?'observation_required':'supported'})),providers,
      subscriptionLimits:{eventTypes:32,nativeIds:256,tags:256},deliverySemantics:'at_least_once'};
  }
  async directory(kind:'channels'|'subscriptions',cid:string,query:Record<string,unknown>,actor:EntityActor):Promise<{items:(SafeChannel|SafeSubscription)[];size:number;nextCursor:string|null;total:null}> {
    const value=eventObject(query,kind==='channels'?['workspaceId','size','cursor','search','status']:['workspaceId','size','cursor','search','status','channelId','eventType']),scope=await this.scope(cid,actor,true),size=eventPageSize(value.size);
    const search=value.search===undefined?null:eventText(value.search),status=value.status===undefined?null:String(value.status);
    if(status!==null&&!['pending','active','disabled','deleted'].includes(status))throw new BadRequestException({code:'INVALID_EVENT_STATUS'});
    const channelId=value.channelId===undefined?null:eventId(value.channelId),eventType=value.eventType===undefined?null:eventText(value.eventType);
    const binding=this.secrets.fingerprint({scope,actorId:actor.user.id,kind,size,search,status,channelId,eventType}),prior=this.cursors.decode(value.cursor,binding);
    const table=kind==='channels'?'notification_channels':'event_subscriptions';
    const rows=await this.db.query<SharedEventRow&{cursor_at:string}>(`SELECT *,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_at FROM ${table} WHERE cluster_id=$1 AND workspace_id=$2
      AND ($3::text IS NULL AND status NOT IN ('pending','deleted') OR status=$3) AND ($4::text IS NULL OR strpos(lower(name),lower($4))>0)
      ${kind==='subscriptions'?'AND ($5::uuid IS NULL OR channel_id=$5) AND ($6::text IS NULL OR $6=ANY(event_types))':'AND $5::uuid IS NULL AND $6::text IS NULL'}
      AND ($7::timestamptz IS NULL OR (created_at,id)<($7::timestamptz,$8::uuid)) ORDER BY created_at DESC,id DESC LIMIT $9`,[scope.cid,scope.wid,status,search,channelId,eventType,prior?.createdAt??null,prior?.id??null,size+1]);
    const items=[];for(const row of rows.slice(0,size))items.push(kind==='channels'?await this.metadata.channelView(row,actor):await this.metadata.subscriptionView(row,actor));
    await this.end(scope,actor,true);const last=rows[Math.min(size,rows.length)-1];return{items,size,total:null,nextCursor:rows.length>size&&last?this.cursors.encode(binding,{id:last.id,createdAt:last.cursor_at}):null};
  }
  async detail(kind:'channels'|'subscriptions',cid:string,id:string,actor:EntityActor) {
    const scope=await this.scope(cid,actor,true),row=await this.metadata.row(kind==='channels'?'event.channel.save':'event.subscription.save',scope.cid,scope.wid,eventId(id));
    if(!row)throw new NotFoundException({code:'EVENT_OBJECT_NOT_FOUND'});
    const entity=kind==='channels'?await this.metadata.channelView(row,actor):await this.metadata.subscriptionView(row,actor);await this.end(scope,actor,true);return{entity};
  }
  async records(cid:string,query:Record<string,unknown>,actor:EntityActor) {
    const value=eventObject(query,['workspaceId','size','cursor','eventType','nativeType','nativeId','from','to']),scope=await this.scope(cid,actor,false,true);
    const result=await this.events.list(actor.user,{...value,clusterId:scope.cid,workspaceId:scope.wid} as EventListQuery);await this.end(scope,actor);return result;
  }
  async record(cid:string,id:string,actor:EntityActor) {
    const scope=await this.scope(cid,actor,false,true),event=await this.events.get(eventId(id));
    if(!event||event.clusterId!==scope.cid||event.workspaceId!==scope.wid)throw new NotFoundException({code:'EVENT_RECORD_NOT_FOUND'});
    await this.access.assertSourceRead(actor.user,event,'events');await this.end(scope,actor);
    return{entity:{id:event.id,clusterId:event.clusterId,workspaceId:event.workspaceId,eventType:event.eventType,phase:event.phase,actorId:event.actorId,actorType:event.actorType,occurredAt:event.occurredAt,payload:event.payloadSafe}};
  }
  private async deliverySource(row:DeliveryRow,actor:EntityActor):Promise<void> {
    const event=await this.events.get(row.event_id);
    if(!event||event.clusterId!==row.cluster_id||event.workspaceId!==row.workspace_id)throw new ConflictException({code:'EVENT_DELIVERY_SOURCE_INVALID'});
    await this.access.assertSourceRead(actor.user,event,'events');
  }
  private async deliveryView(row:DeliveryRow,actor:EntityActor) {
    const write=await this.metadata.writableScope(row)&&await this.authz.hasWholeWorkspace(actor.user,row.cluster_id,row.workspace_id,'events','write');
    // Authority withdrawal can pause an already-sent, uncertain attempt.
    // Reflect the immutable attempt just as enqueueReplay does; a paused
    // status alone never means that the original external result is known.
    const candidate=write&&['succeeded','exhausted','cancelled','paused_authority'].includes(row.state)&&!row.intent_started_at;
    const last=candidate&&row.attempt_count>0?await this.db.one<{outcome:string}>('SELECT outcome FROM event_delivery_attempts WHERE delivery_id=$1 AND cluster_id=$2 AND workspace_id=$3 ORDER BY attempt_no DESC LIMIT 1',[row.id,row.cluster_id,row.workspace_id]):null;
    const replay=candidate&&(row.attempt_count===0||last?.outcome==='succeeded'||last?.outcome==='failed');
    return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,eventId:row.event_id,deliveryKind:row.delivery_kind,channelId:row.channel_id,
      subscriptionId:row.subscription_id,state:row.state,revision:row.revision,attemptCount:row.attempt_count,replayGeneration:row.replay_generation,errorCode:row.error_code,
      createdAt:new Date(row.created_at).toISOString(),capabilities:{replay}};
  }
  async deliveries(cid:string,query:Record<string,unknown>,actor:EntityActor) {
    const value=eventObject(query,['workspaceId','size','cursor','state','channelId','subscriptionId','eventId','from','to']),scope=await this.scope(cid,actor,false,true),size=eventPageSize(value.size);
    const filters={state:value.state??null,channelId:value.channelId===undefined?null:eventId(value.channelId),subscriptionId:value.subscriptionId===undefined?null:eventId(value.subscriptionId),eventId:value.eventId===undefined?null:eventId(value.eventId),
      from:value.from===undefined?new Date(Date.now()-7*86400000).toISOString():String(value.from),to:value.to===undefined?null:String(value.to)};
    if(!Number.isFinite(Date.parse(filters.from))||filters.to&&!Number.isFinite(Date.parse(filters.to))||filters.state!==null&&!['pending','claimed','sending','retrying','uncertain','paused_authority','succeeded','exhausted','cancelled'].includes(String(filters.state)))throw new BadRequestException({code:'INVALID_EVENT_FILTER'});
    // Cursor identity uses an omitted-from marker rather than a moving default
    // date, while its signed position carries the fixed first-page lower bound.
    const binding=this.secrets.fingerprint({scope,actorId:actor.user.id,kind:'deliveries',size,...filters,from:value.from??'last-seven-days'}),prior=this.cursors.decode(value.cursor,binding);
    const rows=await this.db.query<DeliveryRow&{cursor_at:string}>(`SELECT *,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_at FROM event_deliveries WHERE cluster_id=$1 AND workspace_id=$2
      AND ($3::text IS NULL OR state=$3) AND ($4::uuid IS NULL OR channel_id=$4) AND ($5::uuid IS NULL OR subscription_id=$5) AND ($6::uuid IS NULL OR event_id=$6)
      AND created_at>=$7::timestamptz AND ($8::timestamptz IS NULL OR created_at<=$8) AND ($9::timestamptz IS NULL OR (created_at,id)<($9::timestamptz,$10::uuid)) ORDER BY created_at DESC,id DESC LIMIT $11`,[scope.cid,scope.wid,filters.state,filters.channelId,filters.subscriptionId,filters.eventId,prior?.lowerBound??filters.from,filters.to,prior?.createdAt??null,prior?.id??null,size]);
    const items=[];for(const row of rows){try{await this.deliverySource(row,actor);items.push(await this.deliveryView(row,actor));}catch(error){if(!(error instanceof ForbiddenException))throw error;}}
    await this.end(scope,actor);const last=rows.at(-1);return{items,size,total:null,nextCursor:rows.length===size&&last?this.cursors.encode(binding,{id:last.id,createdAt:last.cursor_at,lowerBound:prior?.lowerBound??filters.from}):null};
  }
  async delivery(cid:string,id:string,actor:EntityActor) {
    const scope=await this.scope(cid,actor,false,true),row=await this.db.one<DeliveryRow>('SELECT * FROM event_deliveries WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[eventId(id),scope.cid,scope.wid]);
    if(!row)throw new NotFoundException({code:'EVENT_DELIVERY_NOT_FOUND'});await this.deliverySource(row,actor);const entity=await this.deliveryView(row,actor);await this.end(scope,actor);return{entity};
  }
  async attempts(cid:string,id:string,query:Record<string,unknown>,actor:EntityActor) {
    const value=eventObject(query,['workspaceId','size','cursor']),scope=await this.scope(cid,actor,false,true),size=eventPageSize(value.size);
    await this.delivery(cid,id,actor);const binding=this.secrets.fingerprint({scope,actorId:actor.user.id,kind:'attempts',id:eventId(id),size}),prior=this.cursors.decode(value.cursor,binding);
    const rows=await this.db.query<Record<string,unknown>&{id:string;cursor_at:string}>(`SELECT id,attempt_no AS "attemptNo",started_at AS "startedAt",finished_at AS "finishedAt",outcome,send_started AS "sendStarted",http_status AS "httpStatus",duration_ms AS "durationMs",error_code AS "errorCode",retryable,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_at FROM event_delivery_attempts WHERE delivery_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND ($4::timestamptz IS NULL OR (created_at,id)<($4::timestamptz,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT $6`,[id,scope.cid,scope.wid,prior?.createdAt??null,prior?.id??null,size+1]);
    await this.delivery(cid,id,actor);await this.end(scope,actor);const last=rows[Math.min(size,rows.length)-1];return{items:rows.slice(0,size).map(({cursor_at:_,...item})=>item),size,total:null,nextCursor:rows.length>size&&last?this.cursors.encode(binding,{id:last.id,createdAt:last.cursor_at}):null};
  }
}
