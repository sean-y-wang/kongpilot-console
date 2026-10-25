import { BadRequestException,ForbiddenException,Inject,Injectable,NotFoundException,UnauthorizedException } from '@nestjs/common';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import type { AuditRow,AuditScope } from '../audit/audit.types';
import { EVENT_OBSERVATION_AUTHORITY,type DeliveryAuthorityProof,type EventAccess,type ObservationAuthority } from '../event-core/event-access';
import type { DeliveryClaim,DetectorObservationInput,EventRecord } from '../event-core/event.types';
import { equalDigest,eventAuditScopeDigest,eventFromRow,eventSourceScopeDigest,EVENT_SELECT } from '../event-core/event-utils';
import { isRegisteredDeliveryClaim } from '../event-core/delivery-repository.service';
import { AuthorizationService,type AuthorizationSnapshot } from './authorization.service';
import { historicalAllows,historyScopeValid,HISTORY_UUID,type HistoricalIdentity,type HistoryModule,wholeHistoryGrant } from './historical-scope-policy';

const denied=()=>new ForbiddenException({code:'PERMISSION_DENIED',message:'当前账号无此历史范围权限'});
const invalidScope=()=>new ForbiddenException({code:'HISTORY_SCOPE_INVALID',message:'历史归属证明无效'});

/** Current DB identities plus immutable historical proofs; never queries Kong. */
@Injectable()
export class HistoricalEventAccessService implements EventAccess {
  constructor(private readonly db:DbService,private readonly authz:AuthorizationService,private readonly secrets:SecretService,
    @Inject(EVENT_OBSERVATION_AUTHORITY) private readonly observations:ObservationAuthority){}
  permissionVersion(actor:AuthUser):Promise<string>{return this.authz.permissionVersion(actor);}
  async assertVersion(actor:AuthUser,version:string):Promise<void>{if(await this.permissionVersion(actor)!==version)throw denied();}
  async loadBackgroundActor(id:string):Promise<AuthUser>{
    if(!HISTORY_UUID.test(id))throw denied();
    const row=await this.db.one<{id:string;username:string;super_admin:boolean}>(
      "SELECT id,username,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL",[id]);
    if(!row)throw new UnauthorizedException({code:'ACTOR_INACTIVE',message:'配置创建者已停用'});
    // Real persisted account, no invented session, JWT, role or super-admin flag.
    return (await this.authz.snapshot({id:row.id,username:row.username,superAdmin:row.super_admin===true})).user;
  }
  isWholeAudit(snapshot:AuthorizationSnapshot,clusterId:string|null):boolean {
    return snapshot.user.superAdmin||snapshot.grants.some(grant=>wholeHistoryGrant(grant,'audit','read',clusterId));
  }
  private async tenant(clusterId:string|null,workspaceId:string|null,allowDeletedWorkspace=true):Promise<void>{
    if(clusterId===null){if(workspaceId!==null)throw invalidScope();return;}
    if(!HISTORY_UUID.test(clusterId)||workspaceId!==null&&!HISTORY_UUID.test(workspaceId))throw new BadRequestException({code:'INVALID_SCOPE_ID'});
    if(!await this.db.one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL',[clusterId]))throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
    if(workspaceId!==null){
      const row=await this.db.one<{status:string}>('SELECT status FROM workspaces WHERE cluster_id=$1 AND id=$2',[clusterId,workspaceId]);
      if(!row||!allowDeletedWorkspace&&row.status==='deleted')throw new NotFoundException({code:'WORKSPACE_NOT_FOUND',message:'工作区不可用'});
    }
  }
  async assertAuditScope(actor:AuthUser,scope:AuditScope):Promise<AuthorizationSnapshot>{
    const snapshot=await this.authz.snapshot(actor);
    const coarse=snapshot.user.superAdmin||snapshot.grants.some(grant=>grant.module==='audit'&&grant.action==='read'
      &&(scope.clusterId===null?wholeHistoryGrant(grant,'audit','read',null):
        (grant.cluster_id===null||grant.cluster_id===scope.clusterId)
        &&(grant.workspace_id===null||grant.workspace_id===scope.workspaceId)));
    if(!coarse||scope.mode!=='workspace'&&!this.isWholeAudit(snapshot,scope.clusterId))throw denied();
    await this.tenant(scope.clusterId,scope.workspaceId);
    await this.assertVersion(actor,snapshot.version);return snapshot;
  }
  async assertWholeAudit(actor:AuthUser,clusterId:string|null):Promise<AuthorizationSnapshot>{
    const snapshot=await this.authz.snapshot(actor);if(!this.isWholeAudit(snapshot,clusterId))throw denied();
    await this.tenant(clusterId,null);await this.assertVersion(actor,snapshot.version);return snapshot;
  }
  private auditIdentity(row:AuditRow):HistoricalIdentity {
    if(row.history_scope===null||row.history_scope===undefined)return {clusterId:row.cluster_id,workspaceId:row.workspace_id,
      scope:{version:1,quality:'legacy_unknown',module:row.entity_type,before:null,after:null}};
    if(!historyScopeValid(row.history_scope)||row.history_audit_hash!==row.event_hash||!row.history_scope_hmac
      ||!equalDigest(row.history_scope_hmac,eventAuditScopeDigest(this.secrets,{auditEventId:row.id,auditEventHash:row.event_hash,
        clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:row.history_scope})))throw invalidScope();
    return {clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:row.history_scope};
  }
  canAuditReadSnapshot(snapshot:AuthorizationSnapshot,row:AuditRow):boolean {
    return historicalAllows(snapshot,'audit',this.auditIdentity(row));
  }
  private checkedEvent(event:EventRecord):HistoricalIdentity {
    if(!historyScopeValid(event.sourceScope)||!equalDigest(event.sourceScopeHmac,eventSourceScopeDigest(this.secrets,event))
      ||!equalDigest(event.payloadDigest,this.secrets.fingerprint(event.payloadSafe)))throw invalidScope();
    return {clusterId:event.clusterId,workspaceId:event.workspaceId,scope:event.sourceScope};
  }
  private async actualEvent(id:string):Promise<EventRecord>{
    if(!HISTORY_UUID.test(id))throw invalidScope();
    const row=await this.db.one(`${EVENT_SELECT} WHERE e.id=$1`,[id]);
    if(!row)throw new NotFoundException({code:'EVENT_NOT_FOUND',message:'事件不存在'});return eventFromRow(row);
  }
  async assertSourceRead(actor:AuthUser,event:EventRecord,module:HistoryModule):Promise<void>{
    const actual=await this.actualEvent(event.id),identity=this.checkedEvent(actual),snapshot=await this.authz.snapshot(actor);
    if(!historicalAllows(snapshot,module,identity))throw denied();
    await this.tenant(actual.clusterId,actual.workspaceId);await this.assertVersion(actor,snapshot.version);
  }
  async canSourceRead(actor:AuthUser,event:EventRecord,module:'events'|'notifications'):Promise<boolean>{
    try{await this.assertSourceRead(actor,event,module);return true;}
    catch(error){if(error instanceof ForbiddenException&&error.getResponse()&&typeof error.getResponse()==='object'
      &&(error.getResponse() as {code?:string}).code==='PERMISSION_DENIED')return false;throw error;}
  }
  async assertWholeWorkspace(actor:AuthUser,cid:string,wid:string,module:'events'|'notifications',action:'read'|'write'|'delete'):Promise<void>{
    const snapshot=await this.authz.snapshot(actor);
    if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>wholeHistoryGrant(grant,module,action,cid,wid)))throw denied();
    await this.tenant(cid,wid,action==='read'&&module==='notifications');
    const ws=await this.db.one<{status:string}>('SELECT status FROM workspaces WHERE cluster_id=$1 AND id=$2',[cid,wid]);
    if(!ws||action!=='read'&&ws.status!=='active')throw denied();
    await this.assertVersion(actor,snapshot.version);
  }
  async assertNotificationOwner(actor:AuthUser,ownerId:string,cid:string|null,wid:string|null,action:'read'|'write'|'delete'):Promise<void>{
    if(actor.id!==ownerId)throw denied();
    const snapshot=await this.authz.snapshot(actor);
    if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>grant.module==='notifications'&&grant.action===action
      &&(cid===null?wholeHistoryGrant(grant,'notifications',action,null):
        (grant.cluster_id===null||grant.cluster_id===cid)&&(grant.workspace_id===null||grant.workspace_id===wid))))throw denied();
    await this.tenant(cid,wid);
    if(action!=='read'&&wid!==null){const ws=await this.db.one<{status:string}>('SELECT status FROM workspaces WHERE cluster_id=$1 AND id=$2',[cid,wid]);if(ws?.status!=='active')throw denied();}
    await this.assertVersion(actor,snapshot.version);
  }
  assertObservationCurrent(input:DetectorObservationInput,tx:DbService):Promise<void>{
    return this.observations.assertCurrent(input,tx);
  }
  async assertDeliveryCurrent(claim:DeliveryClaim):Promise<DeliveryAuthorityProof>{
    if(!isRegisteredDeliveryClaim(claim))throw invalidScope();
    const row=await this.db.one<{
      id:string;event_id:string;cluster_id:string;workspace_id:string;delivery_kind:string;subscription_id:string|null;
      subscription_revision:number|null;channel_id:string;channel_revision:number;credential_generation:number;creator_id:string;
      lease_owner_hash:string;lease_generation:number;lease_until:Date|string;state:string;idempotency_key:string;payload_digest:string;
      attempt_count:number;intent_attempt_no:number|null;channel_status:string;current_channel_revision:number;current_generation:number;
      channel_creator:string;subscription_status:string|null;current_subscription_revision:number|null;subscription_channel_id:string|null;
    }>(`SELECT d.*,c.status AS channel_status,c.revision AS current_channel_revision,c.credential_generation AS current_generation,
      c.created_by AS channel_creator,s.status AS subscription_status,s.revision AS current_subscription_revision,s.channel_id AS subscription_channel_id
      FROM event_deliveries d JOIN notification_channels c ON c.id=d.channel_id AND c.cluster_id=d.cluster_id AND c.workspace_id=d.workspace_id
      LEFT JOIN event_subscriptions s ON s.id=d.subscription_id AND s.cluster_id=d.cluster_id AND s.workspace_id=d.workspace_id WHERE d.id=$1`,[claim.deliveryId]);
    if(!row||row.event_id!==claim.eventId||row.cluster_id!==claim.clusterId||row.workspace_id!==claim.workspaceId
      ||row.delivery_kind!==claim.deliveryKind||row.subscription_id!==claim.subscriptionId||row.subscription_revision!==claim.subscriptionRevision
      ||row.channel_id!==claim.channelId||row.channel_revision!==claim.channelRevision||row.credential_generation!==claim.credentialGeneration
      ||row.creator_id!==claim.creatorId||row.lease_generation!==claim.leaseGeneration||!equalDigest(row.lease_owner_hash,this.secrets.fingerprint(claim.leaseOwner))
      ||new Date(row.lease_until).getTime()<=Date.now()||!['claimed','sending'].includes(row.state)||row.idempotency_key!==claim.idempotencyKey
      ||!equalDigest(row.payload_digest,claim.payloadDigest)||!equalDigest(claim.payloadDigest,this.secrets.fingerprint(claim.payloadSafe))
      ||row.channel_status!=='active'||row.current_channel_revision!==claim.channelRevision||row.current_generation!==claim.credentialGeneration
      ||claim.deliveryKind==='subscription'&&(row.subscription_status!=='active'||row.current_subscription_revision!==claim.subscriptionRevision||row.subscription_channel_id!==claim.channelId)
      ||claim.deliveryKind==='test'&&(claim.subscriptionId!==null||claim.subscriptionRevision!==null)
      ||row.state==='sending'&&row.intent_attempt_no!==claim.attemptNo
      ||row.state==='claimed'&&Number(row.attempt_count)+1!==claim.attemptNo)throw denied();
    const event=await this.actualEvent(row.event_id),identity=this.checkedEvent(event);
    if(event.clusterId!==claim.clusterId||event.workspaceId!==claim.workspaceId)throw invalidScope();
    const creator=await this.loadBackgroundActor(row.creator_id),channelCreator=await this.loadBackgroundActor(row.channel_creator);
    const author=await this.authz.snapshot(creator),channelAuthor=creator.id===channelCreator.id?author:await this.authz.snapshot(channelCreator);
    for(const snapshot of [author,channelAuthor]){
      if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>wholeHistoryGrant(grant,'events','write',row.cluster_id,row.workspace_id)))throw denied();
      if(!historicalAllows(snapshot,'events',identity))throw denied();
    }
    await this.tenant(row.cluster_id,row.workspace_id,false);
    const ws=await this.db.one<{status:string}>('SELECT status FROM workspaces WHERE cluster_id=$1 AND id=$2',[row.cluster_id,row.workspace_id]);if(ws?.status!=='active')throw denied();
    await this.assertVersion(creator,author.version);await this.assertVersion(channelCreator,channelAuthor.version);
    // Configuration can change while account/grant reads await. The final SQL observation
    // binds both current author epochs, active tenant, exact config and the same live lease.
    const current=await this.db.one<{valid:boolean}>(`SELECT true AS valid FROM event_deliveries d
      JOIN notification_channels c ON c.id=d.channel_id AND c.cluster_id=d.cluster_id AND c.workspace_id=d.workspace_id
      LEFT JOIN event_subscriptions s ON s.id=d.subscription_id AND s.cluster_id=d.cluster_id AND s.workspace_id=d.workspace_id
      JOIN clusters k ON k.id=d.cluster_id AND k.deleted_at IS NULL AND k.status NOT IN ('disabled','incompatible')
      JOIN workspaces w ON w.cluster_id=d.cluster_id AND w.id=d.workspace_id AND w.status='active'
      JOIN users u ON u.id=d.creator_id AND u.status='active' AND u.deleted_at IS NULL
      JOIN users cu ON cu.id=c.created_by AND cu.status='active' AND cu.deleted_at IS NULL
      JOIN iam_epoch ie ON ie.singleton=true
      WHERE d.id=$1 AND d.state IN ('claimed','sending') AND d.lease_generation=$2 AND d.lease_owner_hash=$3
      AND d.lease_until>clock_timestamp() AND c.status='active' AND c.revision=$4 AND c.credential_generation=$5
      AND (d.subscription_id IS NULL OR(s.status='active' AND s.revision=$6 AND s.channel_id=c.id))
      AND u.id::text||':'||u.permissions_epoch::text||':'||ie.version::text=$7
      AND cu.id::text||':'||cu.permissions_epoch::text||':'||ie.version::text=$8`,
      [claim.deliveryId,claim.leaseGeneration,this.secrets.fingerprint(claim.leaseOwner),claim.channelRevision,
        claim.credentialGeneration,claim.subscriptionRevision,author.version,channelAuthor.version]);
    if(!current?.valid)throw denied();
    return Object.freeze({actorId:creator.id,permissionVersion:`${author.version}|${channelAuthor.version}`,channelRevision:claim.channelRevision,
      subscriptionRevision:claim.subscriptionRevision,credentialGeneration:claim.credentialGeneration,sourceProofDigest:event.sourceScopeHmac});
  }
}
