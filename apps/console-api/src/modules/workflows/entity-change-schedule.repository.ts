import { ConflictException, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { AuditService } from '../audit/audit.service';
import { validImpact } from '../mutations/mutation-impact';
import type { EntityActor } from '../entities/entities.types';
import type { EntityOwnerDelegationV1, EntityScheduledDraft, EntityScheduledSpecV1, EntityScheduleActivation, EntityScheduleClaim,
  EntityScheduleReceipt, EntityScheduleRepositoryDelegate, EntityScheduleTerminalOutcome } from './entity-change-schedule.contract';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex=/^[a-f\d]{64}$/;
const changed=(code='ENTITY_SCHEDULE_FACT_INVALID')=>new ConflictException({code});
const required=['verifyDraft','verifyApproved','verifyClaim','verifyLease','verifyCancellation','verifyPhysicalReservation','verifyOutcome','verifyBlocked','assertRead'] as const;
const iso=(value:any):string=>{const date=new Date(value);if(!Number.isFinite(date.getTime()))throw changed();return date.toISOString();};
export const entityDelegationAad=(cid:string,wid:string,id:string)=>`entity-owner-delegation:${cid}:${wid}:${id}:material`;
export function normalizeEntityScheduleSpec(value:unknown,ownerId:string):Readonly<EntityScheduledSpecV1>{
  const spec=value as any;
  if(!spec||Array.isArray(spec)||Object.keys(spec).some(key=>!['version','notBefore','windowStart','windowEnd','executorId'].includes(key))
    ||spec.version!==1||!uuid.test(ownerId)||spec.executorId!==ownerId
    ||['notBefore','windowStart','windowEnd'].some(key=>typeof spec[key]!=='string'||iso(spec[key])!==spec[key])
    ||Date.parse(spec.windowStart)>Date.parse(spec.notBefore)||Date.parse(spec.notBefore)>=Date.parse(spec.windowEnd))throw changed('ENTITY_SCHEDULE_SPEC_INVALID');
  return immutableJson({version:1,notBefore:spec.notBefore,windowStart:spec.windowStart,windowEnd:spec.windowEnd,executorId:ownerId});
}
/** SQL-only schedule evidence. No HTTP routes, actor/SID construction, due
 * native execution, source INSERT or capability minting is implemented here.
 * Every change requires Root's once-installed fixed verifier and IAM fencing. */
@Injectable()
export class EntityChangeScheduleRepository {
  private delegate?:Readonly<EntityScheduleRepositoryDelegate>;
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly audit:AuditService){}
  installFixedDelegate(delegate:EntityScheduleRepositoryDelegate):void{
    if(this.delegate||!delegate||required.some(key=>typeof delegate[key]!=='function'))throw new Error('Scheduled entities require one complete fixed delegate');
    this.delegate=Object.freeze(Object.fromEntries(required.map(key=>[key,delegate[key].bind(delegate)]))) as unknown as Readonly<EntityScheduleRepositoryDelegate>;
  }
  private policy():Readonly<EntityScheduleRepositoryDelegate>{if(!this.delegate)throw new ServiceUnavailableException({code:'ENTITY_SCHEDULE_POLICY_UNAVAILABLE'});return this.delegate;}
  private proof(value:object):void{if(!value||typeof value!=='object'||Array.isArray(value))throw changed('ENTITY_SCHEDULE_GENUINE_PROOF_REQUIRED');}
  private unchanged(value:unknown,hmac:string):void{if(this.secrets.fingerprint(value)!==hmac)throw changed('ENTITY_SCHEDULE_FACT_MUTATED');}
  private transaction<T>(tx:DbService|undefined,fn:(tx:DbService)=>Promise<T>):Promise<T>{return tx?fn(tx):this.db.transaction(fn);}
  private async iam(tx:DbService):Promise<void>{await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');}
  private normalizeDraft(value:Readonly<EntityScheduledDraft>):Readonly<EntityScheduledDraft>{
    if(!value||value.scheduleVersion!==1||!uuid.test(value.scheduleId))throw changed();
    const b=value.binding,d=value.delegation;
    if(!b||['clusterId','workspaceId','intentId'].some(key=>!uuid.test((b as any)[key]))||!Number.isInteger(b.intentRevision)||b.intentRevision<1
      ||['materialHmac','changeDigest','packetManifestHmac'].some(key=>!hex.test((b as any)[key]))
      ||!d||d.version!==1||d.revision!==1||!uuid.test(d.id)||!uuid.test(d.ownerId)||d.ownerId!==d.executorId
      ||d.clusterId!==b.clusterId||d.workspaceId!==b.workspaceId||d.intentId!==b.intentId||d.intentRevision!==b.intentRevision
      ||d.changeDigest!==b.changeDigest||d.packetManifestHmac!==b.packetManifestHmac||!hex.test(d.policyHash)
      ||!/^\d+$/.test(d.ownerCredentialEpoch)||BigInt(d.ownerCredentialEpoch)<1n||d.executorCredentialEpoch!==d.ownerCredentialEpoch
      ||d.statement!=='execute-this-exact-approved-entity-intent-with-my-current-authority'
      ||iso(d.issuedAt)!==d.issuedAt||iso(d.expiresAt)!==d.expiresAt||Date.parse(d.expiresAt)<=Date.parse(d.issuedAt)
      ||Date.parse(d.expiresAt)-Date.parse(d.issuedAt)>168*3600000||d.specHmac!==value.specHmac
      ||!hex.test(value.transportScope)||!validImpact(value.impact)||value.impact.keys.length+value.impact.domains.length+value.impact.wildcards.length>100000
      ||this.secrets.fingerprint(value.impact)!==value.impactHmac||this.secrets.fingerprint(d)!==value.delegationHmac)throw changed();
    const spec=normalizeEntityScheduleSpec(value.spec,d.ownerId);
    if(this.secrets.fingerprint(spec)!==value.specHmac||Date.parse(spec.windowEnd)>Date.parse(d.expiresAt))throw changed();
    return immutableJson(value);
  }
  private async load(id:string,tx:DbService):Promise<any>{
    if(!uuid.test(id))throw changed();
    const row=await tx.one<any>(`SELECT s.*,p.state,p.revision,p.claim_id,p.reason_code,a.workflow_id,
      d.delegation_ciphertext,d.policy_hash,d.executor_id,d.executor_credential_epoch,d.issued_at AS delegation_issued_at
      FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
      JOIN entity_change_owner_delegations d ON d.id=s.delegation_id LEFT JOIN entity_change_schedule_activations a ON a.schedule_id=s.id WHERE s.id=$1`,[id]);
    if(!row)throw new NotFoundException({code:'ENTITY_SCHEDULE_NOT_FOUND'});
    const delegation=this.secrets.decrypt<EntityOwnerDelegationV1>(row.delegation_ciphertext,entityDelegationAad(row.cluster_id,row.workspace_id,row.delegation_id));
    const draft:EntityScheduledDraft={binding:{clusterId:row.cluster_id,workspaceId:row.workspace_id,intentId:row.intent_id,intentRevision:row.intent_revision,
      materialHmac:row.material_hmac,changeDigest:row.change_digest,packetManifestHmac:row.packet_manifest_hmac},scheduleId:row.id,scheduleVersion:1,
      spec:row.spec,specHmac:row.spec_hmac,delegation,delegationHmac:row.delegation_hmac,impactHmac:row.impact_hmac,transportScope:row.transport_scope,impact:row.impact};
    this.normalizeDraft(draft);
    if(row.version!==1||delegation.ownerId!==row.owner_id||delegation.ownerCredentialEpoch!==String(row.owner_credential_epoch)
      ||delegation.id!==row.delegation_id||delegation.revision!==row.delegation_version||delegation.policyHash!==row.policy_hash
      ||delegation.executorId!==row.executor_id||delegation.executorCredentialEpoch!==String(row.executor_credential_epoch)
      ||delegation.issuedAt!==iso(row.delegation_issued_at)||delegation.expiresAt!==iso(row.expires_at)
      ||draft.spec.notBefore!==iso(row.not_before)||draft.spec.windowStart!==iso(row.window_start)||draft.spec.windowEnd!==iso(row.window_end))throw changed('ENTITY_SCHEDULE_STORED_MATERIAL_INVALID');
    return row;
  }
  private receipt(row:any):EntityScheduleReceipt{return immutableJson({id:row.id,revision:row.revision,state:row.state,intentId:row.intent_id,
    notBefore:iso(row.not_before),windowStart:iso(row.window_start),windowEnd:iso(row.window_end),workflowId:row.workflow_id??null,claimId:row.claim_id??null,reasonCode:row.reason_code??null,nativeAuthority:false});}
  private async lock(id:string,tx:DbService):Promise<any>{
    const row=await this.load(id,tx);
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))",[row.transport_scope]);
    await tx.one('SELECT schedule_id FROM entity_change_schedule_progress WHERE schedule_id=$1 FOR UPDATE',[id]);
    return this.load(id,tx);
  }
  private async event(row:any,kind:string,tx:DbService,actor?:EntityActor,reason?:string):Promise<void>{
    const eventId=randomUUID();await tx.exec(`INSERT INTO entity_change_schedule_events(id,cluster_id,workspace_id,schedule_id,schedule_version,event_kind,actor_id,claim_id,reason_code)
      VALUES($1,$2,$3,$4,1,$5,$6,$7,$8)`,[eventId,row.cluster_id,row.workspace_id,row.id,kind,actor?.user.id??row.owner_id,row.claim_id??null,reason??null]);
    await this.audit.append({actorId:actor?.user.id??row.owner_id,clusterId:row.cluster_id,workspaceId:row.workspace_id,workflowId:row.workflow_id??null,
      entityType:'workflows',entityId:row.workflow_id??null,action:`workflow.schedule.${kind}`,result:['blocked','failed','partial'].includes(kind)?'failed':kind==='uncertain'?'uncertain':'success',
      requestId:actor?.requestId,ip:actor?.ip,after:{scheduleId:row.id,state:row.state,claimId:row.claim_id??null,...(reason?{reasonCode:reason}:{})},
      ...(row.workflow_id?{scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id:row.workflow_id},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:row.workspace_id,afterWorkspaceId:row.workspace_id}}:{})},tx);
  }
  async persistDraft(draft:Readonly<EntityScheduledDraft>,actor:EntityActor,tx?:DbService):Promise<EntityScheduleReceipt>{
    const policy=this.policy(),hash=this.secrets.fingerprint(draft),value=this.normalizeDraft(draft),b=value.binding,d=value.delegation;
    return this.transaction(tx,async db=>{
      await this.iam(db);await policy.verifyDraft(draft,actor,db);this.unchanged(draft,hash);
      if(actor.user.id!==d.ownerId||actor.workspaceId!==b.workspaceId)throw changed('ENTITY_SCHEDULE_ACTUAL_OWNER_REQUIRED');
      const prior=await db.one<any>('SELECT id FROM entity_change_schedules WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4',[b.clusterId,b.workspaceId,b.intentId,b.intentRevision]);
      if(prior){const stored=await this.load(prior.id,db);if(prior.id!==value.scheduleId||stored.spec_hmac!==value.specHmac||stored.delegation_hmac!==value.delegationHmac||stored.material_hmac!==b.materialHmac)throw changed('ENTITY_SCHEDULE_INTENT_ALREADY_BOUND');return this.receipt(stored);}
      await db.exec(`INSERT INTO entity_change_owner_delegations(id,version,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,policy_hash,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,spec_hmac,delegation_hmac,delegation_ciphertext,issued_at,expires_at)
        VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11,$11,$12,$13,$14,$15,$16)`,[d.id,b.clusterId,b.workspaceId,b.intentId,b.intentRevision,b.materialHmac,b.changeDigest,b.packetManifestHmac,d.policyHash,d.ownerId,d.ownerCredentialEpoch,value.specHmac,value.delegationHmac,this.secrets.encrypt(d,entityDelegationAad(b.clusterId,b.workspaceId,d.id)),d.issuedAt,d.expiresAt]);
      await db.exec(`INSERT INTO entity_change_schedules(id,version,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,spec,not_before,window_start,window_end,expires_at,occurrence_id,transport_scope,impact_hmac,impact)
        VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13,$14::jsonb,$15,$16,$17,$18,$19,$20,$21,$22::jsonb)`,[value.scheduleId,b.clusterId,b.workspaceId,b.intentId,b.intentRevision,b.materialHmac,b.changeDigest,b.packetManifestHmac,d.ownerId,d.ownerCredentialEpoch,d.id,value.delegationHmac,value.specHmac,JSON.stringify(value.spec),value.spec.notBefore,value.spec.windowStart,value.spec.windowEnd,d.expiresAt,randomUUID(),value.transportScope,value.impactHmac,JSON.stringify(value.impact)]);
      await db.exec('INSERT INTO entity_change_schedule_progress(schedule_id,cluster_id,workspace_id,schedule_version) VALUES($1,$2,$3,1)',[value.scheduleId,b.clusterId,b.workspaceId]);
      const row=await this.load(value.scheduleId,db);await this.event(row,'draft',db,actor);await policy.verifyDraft(draft,actor,db);this.unchanged(draft,hash);return this.receipt(row);
    });
  }
  async activate(id:string,activation:Readonly<EntityScheduleActivation>,rootProof:object,tx?:DbService):Promise<EntityScheduleReceipt>{
    this.proof(rootProof);const policy=this.policy(),hash=this.secrets.fingerprint(activation),value=immutableJson(activation);
    if(!uuid.test(value.workflowId)||!Number.isInteger(value.workflowPlanRevision)||value.workflowPlanRevision<1||!hex.test(value.workflowPlanHash)
      ||![1,2].includes(value.approvalFormat)||typeof value.approvalRequired!=='boolean'
      ||(value.approvalFormat===2&&value.approvalRequired?(!uuid.test(value.approvalSetId??'')||!hex.test(value.approvalSetHmac??'')):value.approvalSetId!==null||value.approvalSetHmac!==null))throw changed();
    return this.transaction(tx,async db=>{
      await this.iam(db);const row=await this.lock(id,db);await policy.verifyApproved(id,activation,rootProof,db);this.unchanged(activation,hash);
      if(row.state!=='pending-approval')throw changed('ENTITY_SCHEDULE_ALREADY_ACTIVATED');
      await policy.verifyPhysicalReservation(id,rootProof,db);
      await db.exec(`INSERT INTO entity_change_schedule_activations(schedule_id,cluster_id,workspace_id,schedule_version,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,approval_format,approval_required,approval_set_id,approval_set_hmac)
        VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[row.id,row.cluster_id,row.workspace_id,row.intent_id,row.intent_revision,row.material_hmac,row.change_digest,row.packet_manifest_hmac,value.workflowId,value.workflowPlanRevision,value.workflowPlanHash,value.approvalFormat,value.approvalRequired,value.approvalSetId,value.approvalSetHmac]);
      if(await db.exec("UPDATE entity_change_schedule_progress SET state='active',revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id=$1 AND state='pending-approval' AND revision=$2",[id,row.revision])!==1)throw changed('ENTITY_SCHEDULE_STATE_CHANGED');
      const current=await this.load(id,db);await this.event(current,'activated',db);this.unchanged(activation,hash);return this.receipt(current);
    });
  }
  async appendDueClaim(id:string,claim:Readonly<EntityScheduleClaim>,rootProof:object,tx?:DbService):Promise<EntityScheduleClaim>{
    this.proof(rootProof);const policy=this.policy(),hash=this.secrets.fingerprint(claim),value=immutableJson(claim);
    if(!uuid.test(value.id)||value.scheduleId!==id||value.scheduleVersion!==1||value.generation!==1||!uuid.test(value.occurrenceId)||!hex.test(value.workerOwnerHmac)
      ||!uuid.test(value.workflowId)||!Number.isInteger(value.workflowPlanRevision)||value.workflowPlanRevision<1||!hex.test(value.workflowPlanHash)
      ||['issuedAt','authorityExpiresAt','initialLeaseUntil'].some(key=>iso((value as any)[key])!==(value as any)[key])
      ||Date.parse(value.authorityExpiresAt)<=Date.parse(value.issuedAt)||Date.parse(value.authorityExpiresAt)-Date.parse(value.issuedAt)>300000
      ||Date.parse(value.initialLeaseUntil)<=Date.parse(value.issuedAt)||Date.parse(value.initialLeaseUntil)>Date.parse(value.authorityExpiresAt))throw changed();
    return this.transaction(tx,async db=>{
      await this.iam(db);const row=await this.lock(id,db);await policy.verifyClaim(id,claim,rootProof,db);this.unchanged(claim,hash);
      if(row.state!=='active'||row.claim_id||row.occurrence_id!==value.occurrenceId)throw changed('ENTITY_SCHEDULE_OCCURRENCE_ALREADY_CLAIMED');
      const prior=await db.one('SELECT id FROM entity_change_schedule_claims WHERE schedule_id=$1 OR occurrence_id=$2',[id,value.occurrenceId]);if(prior)throw changed('ENTITY_SCHEDULE_OCCURRENCE_ALREADY_CLAIMED');
      await policy.verifyPhysicalReservation(id,rootProof,db);
      await db.exec(`INSERT INTO entity_change_schedule_claims(id,cluster_id,workspace_id,schedule_id,schedule_version,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end,issued_at,authority_expires_at,initial_lease_until)
        VALUES($1,$2,$3,$4,1,$5,1,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,$17,$18,$19)`,[value.id,row.cluster_id,row.workspace_id,id,value.occurrenceId,value.workerOwnerHmac,value.workflowId,value.workflowPlanRevision,value.workflowPlanHash,row.owner_id,row.owner_credential_epoch,row.delegation_id,row.delegation_hmac,row.spec_hmac,row.window_start,row.window_end,value.issuedAt,value.authorityExpiresAt,value.initialLeaseUntil]);
      await db.exec(`INSERT INTO entity_change_schedule_leases(id,cluster_id,workspace_id,claim_id,generation,worker_owner_hmac,lease_version,previous_id,lease_until) VALUES($1,$2,$3,$4,1,$5,1,NULL,$6)`,[randomUUID(),row.cluster_id,row.workspace_id,value.id,value.workerOwnerHmac,value.initialLeaseUntil]);
      if(await db.exec("UPDATE entity_change_schedule_progress SET state='claimed',claim_id=$2,revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id=$1 AND state='active' AND revision=$3 AND claim_id IS NULL",[id,value.id,row.revision])!==1)throw changed('ENTITY_SCHEDULE_STATE_CHANGED');
      await this.event(await this.load(id,db),'claimed',db);this.unchanged(claim,hash);return value;
    });
  }
  async extendLease(claimId:string,workerOwnerHmac:string,generation:number,until:string,rootProof:object,tx?:DbService):Promise<{leaseId:string;leaseVersion:number;leaseUntil:string}>{
    this.proof(rootProof);const policy=this.policy();if(!uuid.test(claimId)||!hex.test(workerOwnerHmac)||generation!==1||iso(until)!==until)throw changed();
    return this.transaction(tx,async db=>{
      await this.iam(db);await db.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-claim:'||$1,0))",[claimId]);
      const claim=await db.one<any>('SELECT * FROM entity_change_schedule_claims WHERE id=$1',[claimId]);
      if(!claim||claim.worker_owner_hmac!==workerOwnerHmac||claim.generation!==generation)throw changed('ENTITY_SCHEDULE_LEASE_OWNER_CHANGED');
      const row=await this.load(claim.schedule_id,db);if(!['claimed','running'].includes(row.state)||row.claim_id!==claimId)throw changed('ENTITY_SCHEDULE_CLAIM_NOT_ACTIVE');
      const previous=await db.one<any>('SELECT * FROM entity_change_schedule_leases WHERE claim_id=$1 ORDER BY lease_version DESC LIMIT 1',[claimId]);
      if(!previous||Date.parse(iso(previous.lease_until))<=Date.now()||Date.parse(until)<=Date.parse(iso(previous.lease_until))||Date.parse(until)>Date.parse(iso(claim.authority_expires_at)))throw changed('ENTITY_SCHEDULE_LEASE_CANNOT_RECLAIM');
      await policy.verifyLease(claimId,workerOwnerHmac,generation,until,rootProof,db);
      const leaseId=randomUUID(),version=previous.lease_version+1;
      await db.exec('INSERT INTO entity_change_schedule_leases(id,cluster_id,workspace_id,claim_id,generation,worker_owner_hmac,lease_version,previous_id,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[leaseId,claim.cluster_id,claim.workspace_id,claimId,generation,workerOwnerHmac,version,previous.id,until]);
      await this.event(row,'lease-extended',db);return{leaseId,leaseVersion:version,leaseUntil:until};
    });
  }
  async cancel(id:string,actor:EntityActor,tx?:DbService):Promise<EntityScheduleReceipt>{
    const policy=this.policy();return this.transaction(tx,async db=>{await this.iam(db);const row=await this.lock(id,db);await policy.verifyCancellation(id,actor,db);
      if(actor.user.id!==row.owner_id||actor.workspaceId!==row.workspace_id||!['pending-approval','active'].includes(row.state)||row.claim_id)throw changed('ENTITY_SCHEDULE_CANCEL_NOT_AVAILABLE');
      if(await db.exec("UPDATE entity_change_schedule_progress SET state='cancelled',revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id=$1 AND revision=$2 AND claim_id IS NULL",[id,row.revision])!==1)throw changed('ENTITY_SCHEDULE_STATE_CHANGED');
      const current=await this.load(id,db);await this.event(current,'cancelled',db,actor);return this.receipt(current);});
  }
  async finishClaim(claimId:string,outcome:EntityScheduleTerminalOutcome,rootProof:object,tx?:DbService):Promise<EntityScheduleReceipt>{
    this.proof(rootProof);const policy=this.policy();if(!uuid.test(claimId)||!['succeeded','partial','failed','uncertain'].includes(outcome))throw changed();
    return this.transaction(tx,async db=>{const claim=await db.one<any>('SELECT * FROM entity_change_schedule_claims WHERE id=$1',[claimId]);if(!claim)throw changed();
      const row=await this.lock(claim.schedule_id,db);await policy.verifyOutcome(claimId,outcome,rootProof,db);
      if(!['claimed','running'].includes(row.state)||row.claim_id!==claimId)throw changed('ENTITY_SCHEDULE_OUTCOME_ALREADY_CLOSED');
      // A truthful already-observed outcome survives revocation/lease expiry;
      // this callback never grants another packet or a second occurrence.
      if(await db.exec('UPDATE entity_change_schedule_progress SET state=$2,revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id=$1 AND revision=$3',[row.id,outcome,row.revision])!==1)throw changed();
      const current=await this.load(row.id,db);await this.event(current,outcome,db,undefined,current.reason_code??undefined);return this.receipt(current);});
  }
  async appendBlocked(id:string,reason:string,rootProof:object,tx?:DbService):Promise<EntityScheduleReceipt>{
    this.proof(rootProof);const policy=this.policy();if(!/^[A-Z0-9_]{1,128}$/.test(reason))throw changed();
    return this.transaction(tx,async db=>{await this.iam(db);const row=await this.lock(id,db);await policy.verifyBlocked(id,reason,rootProof,db);
      if(!['pending-approval','active'].includes(row.state)||row.claim_id)throw changed('ENTITY_SCHEDULE_ALREADY_CLAIMED');
      const state=reason==='ENTITY_SCHEDULE_WINDOW_EXPIRED'?'expired':'blocked';
      if(await db.exec('UPDATE entity_change_schedule_progress SET state=$2,reason_code=$3,revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id=$1 AND revision=$4 AND claim_id IS NULL',[id,state,reason,row.revision])!==1)throw changed();
      const current=await this.load(id,db);await this.event(current,state,db,undefined,reason);return this.receipt(current);});
  }
  async get(id:string,actor:EntityActor,tx?:DbService):Promise<EntityScheduleReceipt>{const db=tx??this.db;await this.policy().assertRead(id,actor,db);const row=await this.load(id,db);if(row.workspace_id!==actor.workspaceId)throw changed();return this.receipt(row);}
  async listDue(limit=25):Promise<string[]>{
    this.policy();if(!Number.isInteger(limit)||limit<1||limit>25)throw changed();
    const rows=await this.db.query<any>(`SELECT s.id FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
      WHERE p.state='active' AND p.claim_id IS NULL AND s.not_before<=clock_timestamp() ORDER BY s.not_before,s.id LIMIT $1`,[limit]);
    return rows.map(row=>row.id);
  }
}
