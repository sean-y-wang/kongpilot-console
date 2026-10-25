import {ConflictException} from '@nestjs/common';
import type {DbService} from '../../infrastructure/db.service';
import type {SecretService} from '../../infrastructure/secret.service';
import type {EntityChangeIntentEnvelope} from './entity-change-intent.types';

/** Append one exact original restore-source reference in the same transaction
 * as the actual immutable version, before its normalized packet rows. Never
 * infer an archive cycle from a reusable native entity UUID. No plaintext or
 * payload ciphertext is copied into this reference. It issues no authority. */
export async function bindEntityRecyclePayloadReferences(envelope:Readonly<EntityChangeIntentEnvelope>,materialHmac:string,tx:DbService,secrets:SecretService):Promise<void>{
 const restores=envelope.prepared.metadataObligations.filter(o=>o.kind==='recycle-restore'),seen=new Set<string>();
 if(!restores.length)return;
 if(secrets.fingerprint(envelope)!==materialHmac)throw new ConflictException({code:'RECYCLE_PAYLOAD_REFERENCE_MATERIAL_CHANGED'});
 for(const obligation of restores){
  if(seen.has(obligation.entryId)||obligation.sealedEntry.entryId!==obligation.entryId||obligation.sealedEntry.clusterId!==envelope.clusterId
   ||obligation.sealedEntry.workspaceId!==envelope.workspaceId||obligation.sealedEntry.payloadHmac!==obligation.graphHmac
   ||secrets.fingerprint(obligation.graph)!==obligation.graphHmac)throw new ConflictException({code:'RECYCLE_PAYLOAD_REFERENCE_INVALID'});
  seen.add(obligation.entryId);
 }
 for(const obligation of restores){
  const row=await tx.one<any>(`SELECT id,cluster_id,workspace_id,revision,state,payload_secret,expires_at FROM recycle_entries
   WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR SHARE`,[envelope.clusterId,envelope.workspaceId,obligation.entryId]);
  if(!row||!Number.isSafeInteger(row.revision)||row.revision<1||row.state!==obligation.sealedEntry.state||typeof row.payload_secret!=='string'
   ||new Date(row.expires_at).toISOString()!==obligation.sealedEntry.expiresAt
   ||secrets.fingerprint(secrets.decrypt(row.payload_secret,`recycle:${row.id}`))!==obligation.graphHmac)throw new ConflictException({code:'RECYCLE_PAYLOAD_REFERENCE_CHANGED'});
  await tx.exec(`INSERT INTO entity_change_recycle_payload_references(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,
   change_digest,packet_manifest_hmac,entry_id,entry_revision,payload_hmac,graph_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
  [envelope.clusterId,envelope.workspaceId,envelope.intentId,envelope.revision,materialHmac,envelope.prepared.changeDigest,envelope.packetManifestHmac,
   row.id,row.revision,secrets.fingerprint(row.payload_secret),obligation.graphHmac]);
 }
}
