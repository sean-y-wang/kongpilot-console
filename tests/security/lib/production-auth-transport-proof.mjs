import{createHash}from'node:crypto';
export function productionAuthNoCommitResolved(packet,proofs){
 if(packet.state!=='response_unknown'||packet.method!=='POST'||packet.path!=='/api/v1/auth/refresh'||packet.observedStatus!=null||packet.observedRequestId!=null||JSON.stringify(packet.body)!=='{}')return false;
 const digest=createHash('sha256').update(JSON.stringify(packet)).digest('hex');
 return proofs?.some(p=>p.originalKey===packet.key&&p.originalPacketSha256===digest&&p.originalPath===packet.path&&p.originalBodySha256===packet.bodySha256&&p.actorId===packet.actorId&&p.sessionId===packet.sessionId
  &&p.originalHeadersObserved===false&&p.noCommitProven===true&&p.originalRequestReplayed===false&&p.originalRawUnknownPreserved===true
  &&p.facts?.id===packet.sessionId&&p.facts.user_id===packet.actorId&&['active','refresh_hash_matches','csrf_hash_matches','refresh_unused','no_rotation_after_original','signed_original_access_verified','read_only_transaction'].every(k=>p.facts[k]===true))===true;
}
