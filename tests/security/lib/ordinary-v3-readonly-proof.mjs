// Pure verifier. Rows/decrypt/fingerprint are provided explicitly; no I/O.
const insist=(condition,code)=>{if(!condition)throw Error(code);};
export function ordinaryV3ReceiptProof({source,baseline,packet,attempt,mutation,events,receipt,entryId},crypto) {
  const {fingerprint:f,decrypt}=crypto;
  insist(source&&baseline&&packet&&attempt&&mutation&&receipt&&events?.length===2,'V3_SQL_COMPLETE_MEMBER_REQUIRED');
  for(const row of [attempt,receipt])insist(row.cluster_id===source.clusterId&&row.workspace_id===source.workspaceId
    &&row.source_id===source.id&&row.baseline_id===baseline.baselineId&&row.pin_id===baseline.pinId
    &&row.workflow_execution_id===source.workflowExecutionId,'V3_SQL_MEMBER_SOURCE_MISMATCH');
  insist(attempt.id===receipt.attempt_id&&attempt.packet_key===packet.key&&receipt.packet_key===packet.key
    &&receipt.entry_id===entryId&&receipt.operation_id===mutation.id&&receipt.native_id===packet.nativeId,'V3_SQL_RECIPROCAL_RECEIPT_REQUIRED');
  const columns={packet_order:packet.order,method:packet.method,path_hmac:f(packet.canonicalPath),native_type:packet.nativeType,native_id:packet.nativeId,
    parent_id:packet.parentId??null,credential_kind:packet.credentialKind??null,original_native_id:packet.originalNativeId??null,
    permission_action:packet.permissionAction,mutation_action:packet.mutationAction,body_hmac:packet.bodyHmac,before_hmac:packet.beforeHmac};
  insist(Object.entries(columns).every(([k,v])=>(attempt[k]??null)===v),'V3_SQL_EXACT_ATTEMPT_PACKET_REQUIRED');
  insist(mutation.state==='succeeded'&&mutation.remote_started===true&&mutation.remote_completed===true
    &&mutation.entity_change_source_id===source.id&&mutation.entity_change_baseline_id===baseline.baselineId
    &&mutation.entity_change_attempt_id===attempt.id&&mutation.entity_change_packet_key===packet.key
    &&mutation.cluster_id===source.clusterId&&mutation.workspace_id===source.workspaceId&&mutation.actor_id===source.executionActorId
    &&mutation.workflow_id===source.workflowId&&mutation.entity_id===packet.nativeId
    &&mutation.entity_type===(packet.credentialKind?'credentials':packet.nativeType)&&mutation.action===packet.mutationAction
    &&(mutation.parent_id??null)===(packet.parentId??null)&&(mutation.credential_kind??null)===(packet.credentialKind??null), 'V3_SQL_REAL_SUCCEEDED_MUTATION_REQUIRED');
  insist(['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].every(k=>mutation[k]==null),'V3_SQL_OTHER_NAMESPACE_FORBIDDEN');
  insist(mutation.idempotency_key===`entity-${source.workflowExecutionId}-${packet.order}`&&receipt.operation_key===mutation.idempotency_key,'V3_SQL_ORIGINAL_OPERATION_KEY_REQUIRED');
  insist(f(decrypt(mutation.before_secret,`mutation:${mutation.id}:before`))===packet.beforeHmac
    &&f(decrypt(mutation.payload_secret,`mutation:${mutation.id}:payload`))===packet.bodyHmac,'V3_SQL_ORIGINAL_AEAD_PACKET_REQUIRED');
  const raw=decrypt(mutation.result_secret,`mutation:${mutation.id}:result`),resultHmac=f(raw),facts=new Map();
  for(const event of events){
    insist(['send-intent','outcome'].includes(event.event_kind)&&!facts.has(event.event_kind)
      &&event.attempt_id===attempt.id&&event.source_id===source.id&&event.baseline_id===baseline.baselineId
      &&event.pin_id===baseline.pinId&&event.workflow_execution_id===source.workflowExecutionId
      &&event.cluster_id===source.clusterId&&event.workspace_id===source.workspaceId,'V3_SQL_TWO_ORIGINAL_EVENTS_REQUIRED');
    const fact=decrypt(event.fact_ciphertext,`entity-change-packet-fact:${source.clusterId}:${source.workspaceId}:${attempt.id}:${event.event_kind}`);
    insist(f(fact)===event.fact_hmac&&fact.version===1&&fact.kind===event.event_kind
      &&fact.binding?.sourceId===source.id&&fact.binding.baselineId===baseline.baselineId&&fact.binding.pinId===baseline.pinId
      &&fact.binding.attemptId===attempt.id&&fact.binding.packetKey===packet.key,'V3_SQL_EVENT_AEAD_BINDING_REQUIRED');
    insist(f(fact.binding)===f({sourceId:source.id,baselineId:baseline.baselineId,pinId:baseline.pinId,packetKey:packet.key,attemptId:attempt.id})
      &&fact.observedAt===new Date(event.observed_at).toISOString()&&Date.parse(fact.observedAt)>=Date.parse(attempt.created_at)
      &&Date.parse(fact.observedAt)<=Date.parse(event.created_at),'V3_SQL_EXACT_EVENT_TIME_AND_BINDING_REQUIRED');
    if(event.event_kind==='outcome')insist(fact.outcome===event.outcome&&fact.nativeStatus===event.native_status&&(fact.errorCode??null)===(event.error_code??null),'V3_SQL_EVENT_COLUMNS_MISMATCH');
    else insist(event.outcome===null&&event.native_status===null&&event.error_code===null,'V3_SQL_SEND_COLUMNS_MISMATCH');
    facts.set(event.event_kind,fact);
  }
  const sent=facts.get('send-intent'),out=facts.get('outcome'),status=packet.method==='DELETE'?204:201;
  insist(sent&&out&&out.outcome==='succeeded'&&out.nativeStatus===status&&out.evidence?.operationId===mutation.id
    &&out.evidence.mutationState==='succeeded'&&out.evidence.remoteCompleted===true&&out.evidence.responseHmac===resultHmac
    &&out.evidence.metadataComplete!==false&&receipt.result_hmac===resultHmac,'V3_SQL_ORIGINAL_TRANSPORT_RESULT_REQUIRED');
  insist(Date.parse(sent.observedAt)>=Date.parse(source.issuedAt)&&Date.parse(sent.observedAt)<=Date.parse(source.expiresAt)
    &&Date.parse(out.observedAt)>=Date.parse(sent.observedAt),'V3_SQL_REAL_ORIGINAL_SEND_WINDOW_REQUIRED');
  insist(f(sent.evidence)===f({operationId:mutation.id,method:packet.method,pathHmac:f(packet.canonicalPath),bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac}),'V3_SQL_ORIGINAL_SEND_INTENT_REQUIRED');
  if(packet.method==='DELETE'){
    insist(raw===null&&receipt.direction==='delete','V3_SQL_REAL_DELETE204_REQUIRED');
    const v=out.evidence.deleteVerification;
    insist(v?.version===1&&v.clusterId===source.clusterId&&v.workspaceId===source.workspaceId&&v.entryId===entryId
      &&v.nodeKey===receipt.node_key&&v.packetKey===packet.key&&v.attemptId===attempt.id&&v.operationId===mutation.id
      &&v.nativeId===packet.nativeId&&v.canonicalPath===packet.canonicalPath&&v.status===404&&f(v)===receipt.verification_hmac,'V3_SQL_ORIGINAL_DELETE404_REQUIRED');
  }else{
    insist(raw?.id===packet.nativeId&&receipt.direction==='restore','V3_SQL_REAL_RESTORE201_REQUIRED');
    const parent=packet.credentialKind?raw.consumer:packet.nativeType==='targets'?raw.upstream:null;
    if(packet.parentId)insist((typeof parent==='string'?parent:parent?.id)===packet.parentId,'V3_SQL_REAL_PARENT_REQUIRED');
  }
  return Object.freeze({nativeStatus:status,resultHmac,attemptId:attempt.id,operationId:mutation.id,configurationVerified:true,functionalVerification:'pending'});
}
