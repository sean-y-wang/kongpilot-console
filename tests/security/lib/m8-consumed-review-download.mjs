import{sha256}from'./m8-harness.mjs';
export const M8_CONSUMED_REVIEW_DOWNLOAD=Object.freeze({index:180,prefixCount:181,prefixSha256:'b7c0bd63238b97a124f5f647418fe8044e02aeb6dbb9a998b48a43008c659194',packetSha256:'774a4f5acc9b2925f12ad960afc9af2ebf1f8318df4e5d9104f262a5d1577f1c',attemptSha256:'71782ef3f100d5b0512307bb00237c1e405ddd9ac6b862296eb78792d6c4510f',key:'63af9f08-6b9d-4d39-a881-40e1401bdba9',jobId:'169c0652-2f17-4227-92dd-8ce4aeecb5fb',exportId:'b5ae988b-e110-4bb3-a202-1d47cfac870d',grantId:'01cf539f-ed4b-4075-8e14-a0ad7aefb143',serverRequestId:'d0b74112-b47b-4c13-b408-63b136ed302a',actorId:'b5f796fa-9515-47de-9123-89a903a48224',sid:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',bytes:13377});
/** Records only the already committed server consumption, never HTTP ACK,
 * delivery, received bytes or Native success. The old packet stays unknown. */
export function isM8ProvenConsumedUnknownDownload(r,p,index){
 const c=M8_CONSUMED_REVIEW_DOWNLOAD,m=r.consumedReviewDownloadRecovery,q=m?.serverProof?.rows?.[0],role=m?.serverProof?.role;
 if(index!==c.index||p!==r.requests[index]||m?.state!=='server-consumed-client-unconfirmed'||sha256(JSON.stringify(r.requests.slice(0,181)))!==c.prefixSha256
  ||sha256(JSON.stringify(p))!==c.packetSha256||p.state!=='response_unknown'||p.key!==c.key||p.actorId!==c.actorId||p.sessionId!==c.sid||p.clusterId!==c.cid||p.workspaceId!==c.wid
  ||p.path!==`/api/v1/clusters/${c.cid}/configuration/exports/${c.exportId}/download`||p.method!=='POST'||p.query!==`?workspaceId=${c.wid}`
  ||m.originalPacketSha256!==c.packetSha256||m.clientDeliveryProven!==false||m.originalRequestReplayed!==false||m.serverProof?.rows?.length!==1
  ||role?.name!=='kongos_app'||role.rolsuper!==false||role.rolbypassrls!==false||q?.id!==c.jobId||q.kind!=='export'||q.state!=='succeeded'
  ||!['actor_matches','sid_matches','scope_matches','original_request_matches','export_matches','consumed','delivery_unconfirmed','grant_owner_matches'].every(k=>q[k]===true)
  ||q.byte_count!==c.bytes||q.grant_id!==c.grantId||q.grant_state!=='consumed'||m.serverOriginalRequestId!==c.serverRequestId)return false;
 return true;
}
