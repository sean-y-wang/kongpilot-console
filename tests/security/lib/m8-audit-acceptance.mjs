import { isDeepStrictEqual } from 'node:util';
import jsonPatch from 'fast-json-patch';
import { sha256 } from './m8-harness.mjs';
import { isM8ProvenCommittedExportPacket } from './m8-export-commit-continuation.mjs';
import {isM8ProvenFailureClosurePacket,M8_EXPIRED_EXECUTION} from './m8-expired-execution-recovery.mjs';
import {isM8ProvenPreparedDeckClosurePacket,M8_DECK_WIRE_BODY_CONTINUATION} from './m8-deck-wire-body-continuation.mjs';
import {isM8ProvenSetUnknownSyncClosurePacket,M8_DECK_SET_CHECKPOINT} from './m8-deck-set-continuation.mjs';
import {isM8ProvenConsumedUnknownDownload,M8_CONSUMED_REVIEW_DOWNLOAD} from './m8-consumed-review-download.mjs';

const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
/** Console metadata has no native tag-history sampling proof. These rows
 * retain legacy_unknown and stay readable only through the product's whole
 * historical-scope authorization. Never treat them as verified native rows. */
export function m8LegacyConsoleMetadataScopeMatches(view,packet,authorizedChainCluster=null){
 if(view.scopeQuality!=='legacy_unknown'||view.requestId!==packet.requestId||view.clusterId!==(packet.clusterId??packet.body?.cluster_id??packet.body?.clusterId??authorizedChainCluster)
  ||packet.actorId!==null&&view.actorId!==packet.actorId||!['success','succeeded'].includes(view.result))return false;
 const path=packet.path;
 if(view.entityType==='authentication'||view.entityType==='auth_sessions')return /^\/api\/v1\/auth\/(login|logout|refresh)$/.test(path);
 if(view.entityType==='roles'||view.entityType==='users')return /^\/api\/v1\/iam\/(roles|users)(?:\/|$)/.test(path);
 if(view.entityType==='workspaces')return /^\/api\/v1\/clusters\/[a-f\d-]{36}\/workspaces(?:\/|$)/.test(path);
 if(view.entityType==='cluster')return /^\/api\/v1\/clusters\/[a-f\d-]{36}$/.test(path);
 if(view.entityType==='recycle_entries'||view.entityType==='mutation_operations')return /^\/api\/v1\/clusters\/[a-f\d-]{36}\/(entities|consumers|upstreams|recycle-bin)(?:\/|$)/.test(path);
 return false;
}
/** Independent RFC6902 application; this does not call the product diff code. */
export function m8AuditPatchMatches(view) {
  try{return Array.isArray(view?.jsonPatch)&&isDeepStrictEqual(jsonPatch.applyPatch(structuredClone(view.before),structuredClone(view.jsonPatch),true,false,true).newDocument,view.after);}catch{return false;}
}
function validateView(h,view,packet,clusterId,failureClosure=false,preparedNotIssuedClosure=false,unknownCliClosure=false) {
  h.check(uuid(view?.id)&&view.requestId===packet.requestId&&view.clusterId===clusterId
    &&['verified','legacy_unknown'].includes(view.scopeQuality)&&(clusterId===null||view.scopeQuality==='verified'||!failureClosure&&m8LegacyConsoleMetadataScopeMatches(view,packet,clusterId))
    &&(failureClosure?view.result==='uncertain': ['success','succeeded'].includes(view.result)), 'actual terminal audit belongs to the original request and current authorized chain scope');
  if(failureClosure&&!preparedNotIssuedClosure&&!unknownCliClosure)h.check(view.action==='configuration.execution.abandon'&&view.entityType==='configuration_jobs'&&view.entityId===M8_EXPIRED_EXECUTION.jobId
    &&view.workflowId===M8_EXPIRED_EXECUTION.workflowId&&view.after?.state==='uncertain'&&view.after.abandoned===true
    &&view.after.executionId===M8_EXPIRED_EXECUTION.executionId&&view.after.planHash===M8_EXPIRED_EXECUTION.planHash
    &&view.after.planRevision===packet.body.planRevision&&view.after.leaseGeneration===packet.body.leaseGeneration
    &&view.after.completedSteps===16&&view.after.unresolvedSteps===1,'only the exact explicit closure request may be covered by its immutable uncertain audit, without claiming Native success');
  if(preparedNotIssuedClosure||unknownCliClosure){const c=unknownCliClosure?M8_DECK_SET_CHECKPOINT:M8_DECK_WIRE_BODY_CONTINUATION;
    h.check(view.action==='configuration.execution.abandon'&&view.entityType==='configuration_jobs'&&view.entityId===c.jobId&&view.workflowId===null
      &&view.before?.jobId===c.jobId&&view.before.executionId===c.executionId&&view.before.state==='running'
      &&view.before.revision===packet.body.revision&&view.before.executionRevision===packet.body.executionRevision
      &&view.after?.jobId===c.jobId&&view.after.executionId===c.executionId&&view.after.state==='uncertain'&&view.after.abandoned===true
      &&view.after.revision===packet.body.revision+1&&view.after.executionRevision===packet.body.executionRevision+1
      &&view.after.planHash===c.planHash&&view.after.planRevision===c.planRevision&&view.after.leaseGeneration===packet.body.leaseGeneration
      &&view.after.completedSteps===0&&view.after.unresolvedSteps===1,
      'only the exact original unstarted Native job is closed by its immutable uncertain audit; issued CLI uncertainty remains distinct');
  }
  h.check(!['sequence','eventHash','event_hash','prevHash','prev_hash','history_scope_hmac','sourceScopeHmac'].some(k=>Object.hasOwn(view,k)), 'audit DTO withholds private chain and authorization proofs');
  h.check(m8AuditPatchMatches(view), 'independent RFC6902 reproduces the actual complete audit after-state', {auditId:view.id});
}
/** Only GETs supplied by the sole runtime harness. No legacy/null-request
 * fallback: M8 successful writes must all have original server request IDs. */
export async function m8AllWritesAuditAcceptance(h,actors) {
  h.check(h.state.inFlight==null&&h.state.requests.every((p,index)=>p.state==='response_observed'&&Number.isInteger(p.status)&&p.status>=100&&p.status<=599||isM8ProvenConsumedUnknownDownload(h.state,p,index)), 'M8 audit refuses unproven unknown or fabricated HTTP status; one exact server-consumed download remains delivery-unconfirmed');
  const ids=new Set(),metadataIds=new Set(),records=[];let successful=0,submissions=0,recovered=0,failureClosureWrites=0,preparedNotIssuedClosureWrites=0,preparedExecutionRegistrationWrites=0,nativeNotStartedUnknownCliClosureWrites=0,serverConsumedDeliveryUnconfirmedWrites=0;
  const known=[...new Set(Object.values(h.state.scopes).map(a=>a.cid))];
  for(let index=0;index<h.state.requests.length;index++) {
    h.check(index<10000,'audit closure retains a fixed original-write budget');
    const originalPacket=h.state.requests[index],consumedDownload=isM8ProvenConsumedUnknownDownload(h.state,originalPacket,index);
    // Only a query locator derived from independently confirmed server state.
    // No ACK/status or received bytes are added to the original packet.
    const packet=consumedDownload?{...originalPacket,requestId:M8_CONSUMED_REVIEW_DOWNLOAD.serverRequestId}:originalPacket;
    if(['GET','HEAD'].includes(packet.method))continue;
    const committedHTTPFailure=isM8ProvenCommittedExportPacket(h.state,packet,index);
    const oldFailureClosure=isM8ProvenFailureClosurePacket(h.state,packet,index);
    const preparedNotIssuedClosure=isM8ProvenPreparedDeckClosurePacket(h.state,packet,index);
    const unknownCliClosure=isM8ProvenSetUnknownSyncClosurePacket(h.state,packet,index);
    h.check([oldFailureClosure,preparedNotIssuedClosure,unknownCliClosure].filter(Boolean).length<=1,'the three fixed historical closure proofs cannot overlap');
    const failureClosure=oldFailureClosure||preparedNotIssuedClosure||unknownCliClosure;
    if(!committedHTTPFailure&&!consumedDownload&&(packet.status<200||packet.status>=300))continue;
    if(/\/configuration\/jobs\/[a-f\d-]{36}\/abandon$/.test(packet.path))h.check(failureClosure,'an uncertain failure closure requires its exact original fixed tuple and protected read proof; generic HTTP success is insufficient');
    if(consumedDownload)serverConsumedDeliveryUnconfirmedWrites++;else if(committedHTTPFailure)recovered++;else successful++;
    if(failureClosure)failureClosureWrites++;
    if(preparedNotIssuedClosure)preparedNotIssuedClosureWrites++;
    if(unknownCliClosure)nativeNotStartedUnknownCliClosureWrites++;
    h.check(uuid(packet.requestId),'every successful BFF write retains its actual server request ID');
    const fixture=h.state.fixtures.find(f=>['roles','teams'].includes(f.type)&&packet.path.includes(`/${f.id}`));
    const primary=packet.clusterId??packet.body?.cluster_id??packet.body?.clusterId??fixture?.cid;
    const candidates=[...new Set(primary?[primary,...known,null]:[null,...known])];let matched;
    for(const clusterId of candidates) {
      let cursor;const seen=new Set(),views=[];
      for(let page=0;page<12;page++) {
        const query=new URLSearchParams({...(clusterId?{scope:'cluster'}:{}),requestId:packet.requestId,result:failureClosure?'uncertain':'success',size:'100',...(cursor?{cursor}:{})});
        const data=h.data(await h.request(actors.admin,`${clusterId?`/clusters/${clusterId}/audit`:'/audit/global'}?${query}`));
        h.check(Array.isArray(data?.items)&&data.items.length<=100&&data.total===null,'actual original-request audit pagination is server bounded');
        for(const view of data.items){validateView(h,view,packet,clusterId,failureClosure,preparedNotIssuedClosure,unknownCliClosure);views.push(view);}
        if(!data.nextCursor)break;
        h.check(page<11&&typeof data.nextCursor==='string'&&!seen.has(data.nextCursor),'original-request audit cursor reaches bounded terminal EOF');
        seen.add(data.nextCursor);cursor=data.nextCursor;
      }
      const actorViews=views.filter(v=>(packet.actorId==null||v.actorId===packet.actorId)
        &&(packet.clusterId==null||v.clusterId===packet.clusterId)&&(packet.workspaceId==null||v.workspaceId===packet.workspaceId));
      if(actorViews.length){matched=actorViews;break;}
    }
    h.check(matched?.length>0,'every successful original BFF write has an actual successful terminal audit',{requestId:packet.requestId});
    if(/^\/api\/v1\/clusters\/[a-f\d-]{36}\/(entities|consumers|upstreams)(?:\/|$)/.test(packet.path))h.check(matched.some(v=>v.scopeQuality==='verified'), 'native entity writes require at least one actual verified historical-scope audit; metadata intent rows are insufficient');
    const pending=packet.responseData?.executionCompleted===false&&packet.responseData?.workflowId;
    if(pending){h.check(matched.some(v=>v.action==='workflow.submit'&&v.workflowId===packet.responseData.workflowId),'approval submission is audited separately from subsequent configuration execution');submissions++;}
    const preparedExecutionRegistration=/\/configuration\/plans\/[a-f\d-]{36}\/apply$/.test(packet.path)
      &&packet.responseData?.executionCompleted===false&&packet.responseData?.workflowId==null;
    if(preparedExecutionRegistration){const receipt=packet.responseData;
      h.check(uuid(receipt.jobId)&&matched.some(v=>v.action==='configuration.job.requested'&&v.entityType==='configuration_jobs'&&v.entityId===receipt.jobId
        &&v.before===null&&v.after?.id===receipt.jobId&&['apply','rollback'].includes(v.after.kind)&&['pending','running'].includes(v.after.state)),
        'a prepared direct apply is covered by its actual durable registration audit, separately from any subsequent Native completion');preparedExecutionRegistrationWrites++;
    }
    matched.forEach(v=>{ids.add(v.id);if(v.scopeQuality==='legacy_unknown')metadataIds.add(v.id);});records.push({index,requestId:packet.requestId,actorId:packet.actorId,committedHTTPFailure,failureClosure,preparedNotIssuedClosure,unknownCliClosure,preparedExecutionRegistration,serverConsumedDeliveryUnconfirmed:consumedDownload,auditIds:matched.map(v=>v.id),viewSha256:sha256(JSON.stringify(matched))});
  }
  const result={successfulWrites:successful,failureClosureWrites,preparedNotIssuedClosureWrites,nativeNotStartedUnknownCliClosureWrites,preparedExecutionRegistrationWrites,successfulExecutionOrMetadataWrites:successful-failureClosureWrites-preparedExecutionRegistrationWrites,recoveredSuccessfulCommits:recovered,serverConsumedDeliveryUnconfirmedWrites,requestMatchedWrites:successful+recovered+serverConsumedDeliveryUnconfirmedWrites,coveredWrites:successful+recovered+serverConsumedDeliveryUnconfirmedWrites,submissionOnlyWrites:submissions,terminalAuditRows:ids.size,legacyConsoleMetadataAuditRows:metadataIds.size,verifiedAuditRows:ids.size-metadataIds.size,auditEventIds:[...ids],allCovered:true,legacyMissingRequestMetadata:0};
  h.state.auditWriteCoverage={...result,records};h.public??={};h.public.auditWriteCoverage=result;h.save();return result;
}
