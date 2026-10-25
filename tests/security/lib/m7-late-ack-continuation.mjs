import { sha256, scope, rows } from './m7-harness.mjs';
import { eventRead, confirmation } from './m7-event-acceptance.mjs';
import { retainM7History } from './m7-private-history.mjs';

export const M7_LATE_ACK_FAILURE = Object.freeze({ path: 'artifacts/M7/security-live-late-ack-fence-failure.json',
  sha256: 'cf9f2425609f91b78ec000cc3581b66c15fe381ee31f42309409f04371013f06',
  diagnosisPath: 'artifacts/M7/late-ack-fence-readonly-exact-diagnosis.json',
  diagnosisSha256: '48fa70429caaefbaaa082b36cd91f61660990fb022a27410b196e99859102ce9' });
export function prepareLateAckContinuation(h, failureBytes, diagnosisBytes) {
  const s=h.state, failure=JSON.parse(failureBytes), diagnosis=JSON.parse(diagnosisBytes), created=s.requests[183], test=s.requests[184], rotated=s.requests[185];
  h.check(sha256(failureBytes)===M7_LATE_ACK_FAILURE.sha256 && sha256(diagnosisBytes)===M7_LATE_ACK_FAILURE.diagnosisSha256 && failure.allPassed===false && failure.passed===138 && failure.failed===1 && failure.successfulWrites===181 && failure.unknownWrites===0 && failure.testTag===s.testTag,
    'exact third known late ACK contract failure and read-only evidence are retained');
  h.check(s.phase==='stopped-failure' && s.inFlight==null && !s.lateAckContinuation && s.requests.length===186 && s.requests.every(p=>p.state==='response_observed') && !s.c2ModeChanged && s.preferencePatchContinuation?.deliberateRetryIssued===true,
    'late ACK continuation reuses all original known packets without replaying any successful operation');
  h.check(created.status===201 && created.responseData.handler==='event.channel.save' && test.status===201 && test.responseData.handler==='event.channel.test' && rotated.status===200 && rotated.responseData.handler==='event.channel.save' && [created,test,rotated].every(p=>p.clusterId===s.scopes.direct.cid && p.workspaceId===s.scopes.direct.wid && sha256(JSON.stringify(p.body))===p.bodySha256) && test.actorId===s.sessions.owner.user.id && test.sessionId===s.sessions.owner.sid && rotated.actorId===s.sessions.admin.user.id && rotated.sessionId===s.sessions.admin.sid,
    'original channel create test and generation rotation bind exact body actor SID and scope');
  const queued=test.responseData.result.queued, channel=rotated.responseData.result.entity;
  h.check(diagnosis.allPassed===true && diagnosis.businessWrites===0 && diagnosis.authenticationWrites===0 && diagnosis.deliveryId===queued.deliveryId && diagnosis.eventId===queued.eventId && diagnosis.channelId===channel.id && diagnosis.clusterId===s.scopes.direct.cid && diagnosis.workspaceId===s.scopes.direct.wid && diagnosis.state==='paused_authority' && diagnosis.attempts.length===1 && diagnosis.attempts[0].outcome==='uncertain' && diagnosis.attempts[0].sendStarted===true && diagnosis.receiverMatches===1 && s.lateAckExactReadOnlyDiagnosis?.state==='completed',
    'actual protected delivery attempt and receiver prove one immutable uncertain intent');
  const originalPacketsSha256=sha256(JSON.stringify(s.requests));retainM7History(s,'lateAckContinuationHistory');
  s.lateAckContinuation={version:1,state:'prepared',startedAt:new Date().toISOString(),originalPacketsSha256,originalPackets:186,failureArchive:M7_LATE_ACK_FAILURE};h.save({phase:'exact-unused-late-ack-tail'});
  return {queued,channel,actors:{admin:s.sessions.admin,bootstrap:s.sessions['bootstrap-provisioner'],approver:s.sessions.approver,readonly:s.sessions['read-only'],owner:s.sessions.owner,other:s.sessions['other-owner'],...s.scopes}};
}
export async function finishOriginalLateAck(h, actors, queued, channel) {
  const area=actors.direct, delivery=await eventRead(h,actors.admin,area,`deliveries/${queued.deliveryId}`);
  h.check(delivery.id===queued.deliveryId && delivery.eventId===queued.eventId && delivery.channelId===channel.id && delivery.clusterId===area.cid && delivery.workspaceId===area.wid && ['uncertain','paused_authority'].includes(delivery.state) && delivery.capabilities.replay===false,
    'current fixed delivery view disables replay of the original unresolved immutable intent');
  const attempts=rows(await eventRead(h,actors.admin,area,`deliveries/${delivery.id}/attempts`,{size:20}));
  h.check(attempts.length===1 && attempts[0].sendStarted===true && attempts[0].outcome==='uncertain', 'one original uncertain sent attempt cannot become succeeded');
  const records=h.receiver('event-receiver',{action:'stats'}).records.filter(v=>v.deliveryId===delivery.id);
  h.check(records.length===1 && records[0].eventId===queued.eventId && records[0].clusterId===area.cid && records[0].workspaceId===area.wid,'receiver still proves exactly one original external intent');
  const denied=await h.request(actors.admin,scope(area.cid,area.wid,`events/deliveries/${delivery.id}/replay`),'POST',confirmation(delivery),{expected:[409]});
  h.check(denied.payload?.error?.code==='DELIVERY_UNRESOLVED','current typed original unresolved delivery rejects replay before enqueuing another external intent');
  h.receiver('event-receiver',{action:'fault',fault:{times:0,delayMs:0}});
  h.public??={};h.public.lateAckFence={deliveryId:delivery.id,state:delivery.state,attempts:1,sendStarted:true,outcome:'uncertain',receiverMatches:1,replayCapability:false,replayStatus:denied.status,replayCode:denied.payload.error.code,replayRequestId:denied.requestId,originalSuccessfulOperationsReplayed:false};
}
