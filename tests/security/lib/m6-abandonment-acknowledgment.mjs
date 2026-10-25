import {canonical} from './m4-harness.mjs';
import {scope} from './m6-harness.mjs';
import {checkpointSha} from './m6-isolated-transition.mjs';
import {FAILED_ISSUE_TUPLE as T} from './m6-failed-issue-key-capture.mjs';
import {readFailedIssueContinuation,assertFailedIssueReceipt,verifyOriginalAbandonment} from './m6-failed-issue-continuation.mjs';

const path=`/api/v1/clusters/${T.clusterId}/workflows/${T.workflowId}/abandon-rejected-issue`;
const equal=(a,b)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));
export function abandonmentAcknowledgmentCheckpoint(reference,evidence){
 const saved=reference.failedIssueContinuation,attempts=reference.writeAttempts?.filter(a=>a.path===path)??[],attempt=attempts[0],report=evidence?.report,proof=evidence?.proof;
 const started=Date.parse(attempt?.startedAt),error=evidence?.databaseErrors?.errors?.find(e=>e.errorClass==='DATABASE_PERMISSION_DENIED'&&e.targetType==='table'&&e.safeIdentifier==='portal_publication_proofs'&&(e.sqlState==='42501'||e.inferredSqlState==='42501')&&Date.parse(e.time)>=started&&Date.parse(e.time)<=started+15000);
 const valid=!reference.abandonmentAcknowledgment&&saved?.phase==='abandonment-request-started'&&!saved.newRequest&&saved.originalExecutionKey===T.executionKey&&saved.workflowId===T.workflowId&&saved.executionId===T.executionId&&saved.grantId===T.grantId&&saved.credentialId===T.credentialId&&
  attempts.length===1&&attempt.method==='POST'&&attempt.key===T.executionKey&&attempt.state==='response_observed'&&attempt.httpStatus===503&&attempt.errorCode==='PORTAL_ISSUE_ABANDONMENT_UNKNOWN'&&attempt.actorId===reference.consoleAdministrator?.user.id&&new URLSearchParams(attempt.query).get('workspaceId')===T.workspaceId&&equal(attempt.body,saved.body)&&
  report?.testTag===reference.testTag&&report.passed===491&&report.failed===1&&report.lastHttpRequest?.method==='POST'&&report.lastHttpRequest.path===path.replace('/api/v1','')&&report.lastHttpRequest.status===503&&
  proof?.readOnly===true&&proof.noPostRetry===true&&proof.requestId===attempt.requestId&&proof.httpStatus===503&&proof.errorCode==='PORTAL_ISSUE_ABANDONMENT_UNKNOWN'&&proof.privatePhase==='abandonment-request-started'&&proof.newRequestCreated===false&&proof.receipt?.status===200&&proof.receipt.state==='failed'&&proof.receipt.workflowId===T.workflowId&&proof.receipt.executionId===T.executionId&&
  proof.database?.exactTupleCount===1&&proof.database.grantState==='pending'&&proof.database.reservationReleased===false&&proof.database.credentialState==='pending'&&proof.database.generation===1&&proof.database.originalCipherUnchanged===true&&proof.database.nativeOperationCount===1&&proof.database.unexpectedNativeResults===0&&proof.database.credentialRefs===0&&proof.database.certificateCount===0&&proof.database.nativeUnresolved===0&&proof.database.portalUnresolved===0&&proof.database.scopeGrants===2&&proof.database.scopeCredentials===2&&proof.database.workflowState==='failed'&&proof.database.executionState==='failed'&&error;
 if(!valid)throw new Error('Acknowledgment continuation requires exact preserved original 503 and independently observed rollback facts');
 return{originalJournal:structuredClone(saved),originalJournalSha256:checkpointSha(saved),originalAttempt:structuredClone(attempt),originalAttemptSha256:checkpointSha(attempt)};
}
export async function guardAbandonmentAcknowledgment(h,evidence){
 h.requireLive();const preserved=abandonmentAcknowledgmentCheckpoint(h.referenceData,evidence);
 // This shallow read view is only for the original checkpoint guard. It does
 // not reset or replace the retained started journal or any write attempt.
 const context=await readFailedIssueContinuation(h,{...h.referenceData,failedIssueContinuation:undefined});
 h.check(equal(context.abandonmentBody,preserved.originalJournal.body)&&context.before.cipher_sha===preserved.originalJournal.before.cipher_sha&&context.before.plan_hash===preserved.originalJournal.before.plan_hash&&context.before.consumer_id===preserved.originalJournal.before.consumer_id&&context.before.acl_id===preserved.originalJournal.before.acl_id&&context.before.kong_id===preserved.originalJournal.before.kong_id,'AbandonmentAck/CurrentFacts','fresh original body, scope, allocated identities and unused Key remain unchanged');
 h.check(checkpointSha(h.referenceData.failedIssueContinuation)===preserved.originalJournalSha256&&checkpointSha(h.referenceData.writeAttempts.find(a=>a.path===path))===preserved.originalAttemptSha256,'AbandonmentAck/History','all original 503 attempt and started-journal bytes remain immutable through recheck');
 const acknowledgment={...preserved,phase:context.alreadyClosed?'certificate-observed':'before-single-original-key-post',originalExecutionKey:T.executionKey,body:structuredClone(preserved.originalJournal.body),before:context.before,previousFormalPosts:1};
 h.saveReference({abandonmentAcknowledgment:acknowledgment});return{...context,acknowledgment};
}
export async function settleAbandonmentAcknowledgment(h,context){
 const ack=h.referenceData.abandonmentAcknowledgment;
 h.check(ack&&['certificate-observed','before-single-original-key-post'].includes(ack.phase)&&ack.originalExecutionKey===T.executionKey&&equal(ack.body,context.abandonmentBody)&&checkpointSha(h.referenceData.failedIssueContinuation)===ack.originalJournalSha256&&checkpointSha(h.referenceData.writeAttempts.find(a=>a.path===path))===ack.originalAttemptSha256,'AbandonmentAck/Journal','independent acknowledged recheck retains exact old bytes and admits at most one original-key POST');
 let requestId,additionalPosts=0;
 if(context.alreadyClosed){
  h.check(ack.phase==='certificate-observed','AbandonmentAck/Observation','a complete original certificate uses GET observation without another POST');
  h.saveReference({abandonmentAcknowledgment:{...ack,phase:'verifying-observed-certificate',additionalFormalPosts:0}});
 }else{
  h.check(ack.phase==='before-single-original-key-post','AbandonmentAck/Attempt','eligible original request can execute only this separately confirmed recheck');
  h.saveReference({abandonmentAcknowledgment:{...ack,phase:'original-key-post-started',additionalFormalPosts:1}});
  const response=await h.request(context.admin,scope(path.replace('/api/v1',''),T.workspaceId),'POST',ack.body,{key:T.executionKey});
  assertFailedIssueReceipt(h,h.ok(response,'AbandonmentAck/Formal','one separately authorized same-body original-key metadata closure'),true);requestId=response.payload?.meta?.requestId;additionalPosts=1;
 }
 const receipt=h.ok(await h.request(context.admin,scope(`/clusters/${T.clusterId}/workflows/receipts/by-key/${T.executionKey}`,T.workspaceId)),'AbandonmentAck/Receipt','current certificate from the original failed execution key');
 const result=await verifyOriginalAbandonment(h,context,receipt,requestId);
 h.saveReference({abandonmentAcknowledgment:{...h.referenceData.abandonmentAcknowledgment,phase:'certificate-verified',additionalFormalPosts:additionalPosts,totalFormalPosts:1+additionalPosts,certificateId:receipt.issueAbandonment.certificateId}});
 return result;
}
