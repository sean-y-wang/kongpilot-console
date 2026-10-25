import { ConflictException } from '@nestjs/common';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import type { EntityExecutionSourceByOrigin } from './entity-change-schedule.contract';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex=/^[a-f\d]{64}$/;
const scheduledColumns=['schedule_id','schedule_version','spec_hmac','delegation_id','delegation_version','delegation_hmac','occurrence_id','claim_id','claim_generation','worker_owner_hmac','window_start','window_end'] as const;
const invalid=()=>new ConflictException({code:'ENTITY_CHANGE_SOURCE_ORIGIN_INVALID'});
const iso=(value:unknown):string=>{const date=new Date(value as any);if(!Number.isFinite(date.getTime()))throw invalid();return date.toISOString();};
/** Strict origin decoding only. A decoded row is evidence, not an actor,
 * session, claim handle or native capability. The HTTP branch deliberately
 * retains the exact Gate2/Gate3 JSON shape and therefore its original HMAC. */
export function decodeEntityExecutionSource(row:any):Readonly<EntityExecutionSourceByOrigin>{
  if(!row||['id','cluster_id','workspace_id','intent_id','workflow_id','workflow_execution_id','execution_actor_id'].some(key=>!uuid.test(row[key]))
    ||['material_hmac','change_digest','packet_manifest_hmac','workflow_plan_hash','permission_version_hmac'].some(key=>!hex.test(row[key]))
    ||!Number.isInteger(row.intent_revision)||row.intent_revision<1||!Number.isInteger(row.workflow_plan_revision)||row.workflow_plan_revision<1
    ||!/^\d+$/.test(String(row.credential_epoch))||BigInt(row.credential_epoch)<1n)throw invalid();
  const common={id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,intentId:row.intent_id,intentRevision:row.intent_revision,
    materialHmac:row.material_hmac,changeDigest:row.change_digest,packetManifestHmac:row.packet_manifest_hmac,workflowId:row.workflow_id,
    workflowPlanRevision:row.workflow_plan_revision,workflowPlanHash:row.workflow_plan_hash,workflowExecutionId:row.workflow_execution_id,
    executionActorId:row.execution_actor_id,credentialEpoch:String(row.credential_epoch),permissionVersionHmac:row.permission_version_hmac,
    issuedAt:iso(row.issued_at),expiresAt:iso(row.expires_at)};
  if(Date.parse(common.expiresAt)<=Date.parse(common.issuedAt)||Date.parse(common.expiresAt)-Date.parse(common.issuedAt)>300000)throw invalid();
  // undefined is only the pre-023 schema/mock compatibility case.
  if(row.origin_type===undefined||row.origin_type==='http'){
    if(!uuid.test(row.session_id)||scheduledColumns.some(key=>row[key]!==undefined&&row[key]!==null))throw invalid();
    return immutableJson({...common,sessionId:row.session_id});
  }
  if(row.origin_type!=='scheduled-entity'||row.session_id!==null||scheduledColumns.some(key=>row[key]===undefined||row[key]===null)
    ||['schedule_id','delegation_id','occurrence_id','claim_id'].some(key=>!uuid.test(row[key]))
    ||['spec_hmac','delegation_hmac','worker_owner_hmac'].some(key=>!hex.test(row[key]))
    ||row.schedule_version!==1||row.delegation_version!==1||row.claim_generation!==1)throw invalid();
  const windowStart=iso(row.window_start),windowEnd=iso(row.window_end);
  if(Date.parse(windowStart)>Date.parse(common.issuedAt)||Date.parse(windowEnd)<=Date.parse(common.issuedAt)||Date.parse(common.expiresAt)>Date.parse(windowEnd))throw invalid();
  return immutableJson({...common,format:2,origin:'scheduled-entity',sessionId:null,scheduleId:row.schedule_id,scheduleVersion:1,
    specHmac:row.spec_hmac,delegationId:row.delegation_id,delegationVersion:1,delegationHmac:row.delegation_hmac,
    occurrenceId:row.occurrence_id,claimId:row.claim_id,claimGeneration:1,workerOwnerHmac:row.worker_owner_hmac,windowStart,windowEnd});
}
