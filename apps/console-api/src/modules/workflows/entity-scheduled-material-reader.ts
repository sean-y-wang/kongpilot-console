import { ConflictException, NotFoundException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import type { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { entityChangeIntentAad, normalizedEntityChangePackets } from './entity-change-workflow';
import { entityDelegationAad, normalizeEntityScheduleSpec } from './entity-change-schedule.repository';
import type { EntityScheduledDraft, EntityScheduledIntentEnvelopeV2 } from './entity-change-schedule.contract';
const invalid=()=>new ConflictException({code:'ENTITY_SCHEDULE_AUTHENTIC_MATERIAL_REQUIRED'});
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const iso=(value:any)=>{const date=new Date(value);if(!Number.isFinite(date.getTime()))throw invalid();return date.toISOString();};

/** Fixed encrypted entity V2 evidence only; no generic plan format, Actor,
 * HTTP context, scheduler, query forwarding or native authority is created. */
export class EntityScheduledMaterialReader {
  constructor(private readonly secrets:SecretService){}
  async intent(cid:string,wid:string,id:string,revision:number,tx:DbService):Promise<EntityScheduledIntentEnvelopeV2>{
    if(![cid,wid,id].every(value=>uuid.test(value))||!Number.isSafeInteger(revision)||revision<1)throw invalid();
    const intent=await tx.one<any>('SELECT * FROM entity_change_intents WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[cid,wid,id]);
    const row=await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4',[cid,wid,id,revision]);
    if(!intent||!row)throw new NotFoundException({code:'ENTITY_SCHEDULE_INTENT_NOT_FOUND'});
    const e=this.secrets.decrypt<EntityScheduledIntentEnvelopeV2>(row.envelope_ciphertext,entityChangeIntentAad(cid,wid,id,revision)),s=e.scheduling,d=s?.delegation;
    if(e.version!==2||!s||!d||s.scheduleVersion!==1||d.version!==1||d.revision!==1||!uuid.test(s.scheduleId)||!uuid.test(d.id)
      ||e.clusterId!==cid||e.workspaceId!==wid||e.intentId!==id||e.revision!==revision||e.requesterId!==intent.requester_id||e.requesterId!==row.requester_id
      ||e.credentialEpoch!==String(intent.credential_epoch)||e.credentialEpoch!==String(row.credential_epoch)
      ||e.issuedAt!==iso(intent.issued_at)||e.issuedAt!==iso(row.issued_at)||e.expiresAt!==iso(intent.expires_at)||e.expiresAt!==iso(row.expires_at)
      ||e.executionMode!==row.execution_mode||e.definition.id!==row.definition_id||e.definition.version!==row.definition_version||e.definition.policyHash!==row.policy_hash
      ||!Number.isInteger(e.ttlHours)||e.ttlHours<1||e.ttlHours>168||Date.parse(e.expiresAt)<=Date.parse(e.issuedAt)||Date.parse(e.expiresAt)-Date.parse(e.issuedAt)>e.ttlHours*3600000
      ||this.secrets.fingerprint(e)!==row.material_hmac||e.prepared.clusterId!==cid||e.prepared.workspaceId!==wid||e.prepared.requesterId!==e.requesterId||e.prepared.version!==1)throw invalid();
    const spec=normalizeEntityScheduleSpec(s.spec,e.requesterId),{changeDigest,...original}=e.prepared;
    if(this.secrets.fingerprint(original)!==changeDigest||changeDigest!==row.change_digest||this.secrets.fingerprint(spec)!==s.specHmac
      ||this.secrets.fingerprint(d)!==s.delegationHmac||d.clusterId!==cid||d.workspaceId!==wid||d.intentId!==id||d.intentRevision!==revision
      ||d.ownerId!==e.requesterId||d.executorId!==e.requesterId||d.ownerCredentialEpoch!==e.credentialEpoch||d.executorCredentialEpoch!==e.credentialEpoch
      ||d.specHmac!==s.specHmac||d.policyHash!==e.definition.policyHash||d.changeDigest!==changeDigest||d.packetManifestHmac!==e.packetManifestHmac
      ||d.issuedAt!==e.issuedAt||d.expiresAt!==e.expiresAt||d.statement!=='execute-this-exact-approved-entity-intent-with-my-current-authority'
      ||spec.windowEnd!==e.expiresAt||Date.parse(spec.notBefore)<Date.parse(e.issuedAt))throw invalid();
    const expected=normalizedEntityChangePackets(e.prepared,this.secrets),rows=await tx.query<any>('SELECT * FROM entity_change_intent_packets WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4 ORDER BY packet_order',[cid,wid,id,revision]);
    const actual=rows.map(p=>({key:p.packet_key,order:p.packet_order,dependencies:p.dependencies,method:p.method,pathHmac:p.path_hmac,nativeType:p.native_type,nativeId:p.native_id,parentId:p.parent_id,credentialKind:p.credential_kind,originalNativeId:p.original_native_id,mutationAction:p.mutation_action,permissionAction:p.permission_action,bodyHmac:p.body_hmac,beforeHmac:p.before_hmac}));
    if(expected.length!==row.packet_count||rows.length!==expected.length||rows.some(p=>p.material_hmac!==row.material_hmac||p.change_digest!==changeDigest||p.packet_manifest_hmac!==e.packetManifestHmac)
      ||this.secrets.fingerprint(expected)!==e.packetManifestHmac||this.secrets.fingerprint(actual)!==e.packetManifestHmac||row.packet_manifest_hmac!==e.packetManifestHmac||this.secrets.fingerprint(row.packet_manifest)!==e.packetManifestHmac
      ||this.secrets.fingerprint(e.review)!==this.secrets.fingerprint(row.safe_review))throw invalid();
    return immutableJson(e);
  }
  draft(e:EntityScheduledIntentEnvelopeV2):EntityScheduledDraft{return immutableJson({binding:{clusterId:e.clusterId,workspaceId:e.workspaceId,intentId:e.intentId,intentRevision:e.revision,materialHmac:this.secrets.fingerprint(e),changeDigest:e.prepared.changeDigest,packetManifestHmac:e.packetManifestHmac},
    scheduleId:e.scheduling.scheduleId,scheduleVersion:1,spec:e.scheduling.spec,specHmac:e.scheduling.specHmac,delegation:e.scheduling.delegation,delegationHmac:e.scheduling.delegationHmac,
    transportScope:e.prepared.scope.transportScope,impact:e.prepared.impact,impactHmac:this.secrets.fingerprint(e.prepared.impact)});}
  async schedule(id:string,tx:DbService):Promise<{row:any;envelope:EntityScheduledIntentEnvelopeV2;draft:EntityScheduledDraft}>{
    if(!uuid.test(id))throw invalid();
    const row=await tx.one<any>(`SELECT s.*,p.state,p.revision,p.claim_id,p.reason_code,a.workflow_id,a.workflow_plan_revision,a.workflow_plan_hash,
      a.approval_format,a.approval_required,a.approval_set_id,a.approval_set_hmac,d.delegation_ciphertext FROM entity_change_schedules s
      JOIN entity_change_schedule_progress p ON p.schedule_id=s.id JOIN entity_change_owner_delegations d ON d.id=s.delegation_id
      LEFT JOIN entity_change_schedule_activations a ON a.schedule_id=s.id WHERE s.id=$1`,[id]);
    if(!row)throw new NotFoundException({code:'ENTITY_SCHEDULE_NOT_FOUND'});
    const envelope=await this.intent(row.cluster_id,row.workspace_id,row.intent_id,row.intent_revision,tx),draft=this.draft(envelope),d=envelope.scheduling.delegation;
    if(row.version!==1||row.id!==draft.scheduleId||row.material_hmac!==draft.binding.materialHmac||row.change_digest!==draft.binding.changeDigest||row.packet_manifest_hmac!==draft.binding.packetManifestHmac
      ||row.owner_id!==d.ownerId||String(row.owner_credential_epoch)!==d.ownerCredentialEpoch||row.delegation_id!==d.id||row.delegation_version!==1||row.delegation_hmac!==draft.delegationHmac
      ||row.spec_hmac!==draft.specHmac||this.secrets.fingerprint(row.spec)!==draft.specHmac||iso(row.not_before)!==draft.spec.notBefore||iso(row.window_start)!==draft.spec.windowStart||iso(row.window_end)!==draft.spec.windowEnd||iso(row.expires_at)!==d.expiresAt
      ||row.transport_scope!==draft.transportScope||row.impact_hmac!==draft.impactHmac||this.secrets.fingerprint(row.impact)!==draft.impactHmac||!uuid.test(row.occurrence_id)
      ||this.secrets.fingerprint(this.secrets.decrypt(row.delegation_ciphertext,entityDelegationAad(row.cluster_id,row.workspace_id,d.id)))!==draft.delegationHmac)throw invalid();
    return{row,envelope,draft};
  }
}
