import {createHash} from 'node:crypto';
import {FAILED_ISSUE_TUPLE as T} from './m6-failed-issue-key-capture.mjs';
import {PENDING_KEY_TUPLE as FIRST} from './m6-pending-key-capture.mjs';
import {FAILED_ISSUE_DATABASE_SQL} from './m6-failed-issue-continuation.mjs';
import {checkpointSha} from './m6-isolated-transition.mjs';
import {fixtureRuns} from './m6-fixture-runs.mjs';

export const evidenceSha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export const READONLY_CURRENT_GRANTS_SQL=`SELECT g.id,g.cluster_id,g.workspace_id,g.state,g.current_generation,g.current_credential_id,g.consumer_id,g.acl_id,
 c.id AS credential_id,c.kong_id,c.state AS credential_state,c.generation
 FROM portal_application_grants g JOIN portal_credentials c ON c.grant_id=g.id AND c.cluster_id=g.cluster_id AND c.workspace_id=g.workspace_id
 WHERE g.id=ANY($1::uuid[]) AND c.id=ANY($2::uuid[])`;
export function readonlyVerificationCheckpoint(r,evidence){
 fixtureRuns(r);const report=evidence.report,pin=evidence.pin;
 const failure=report?.checks?.filter(c=>!c.passed)??[];
 const valid=report?.passed===1012&&report.failed===1&&failure.length===1&&failure[0].id==='GATE'&&failure[0].name==='Audit/M4: current fixture audit before/after/patch contain no known password, token or gateway credential'&&
  report.testTag===r.testTag&&r.phase==='HTTP-complete'&&r.grants?.length===6&&r.fixtures?.length===3&&r.portalUsers?.length===3&&r.retiredLifecycleContinuation?.phase==='tail-actions-started'&&
  report.auditCoverage?.distinctRequestIds===145&&report.auditCoverage.auditedRequestIds===145&&report.auditCoverage.missing?.length===0&&
  evidenceSha(r.writeAttempts)===pin?.writeAttemptsSha256&&evidenceSha(r.writeEvidence)===pin.writeEvidenceSha256&&evidenceSha(r.grants)===pin.grantsSha256&&
  checkpointSha(r.abandonmentAcknowledgment)===pin.acknowledgmentSha256&&checkpointSha(r.metadataRecovery)===pin.metadataRecoverySha256&&
  r.abandonmentAcknowledgment?.totalFormalPosts===2&&r.abandonmentAcknowledgment?.phase==='certificate-verified'&&r.metadataRecovery?.phase==='metadata-succeeded-original-execution'&&
  r.browser?.activeGrantId===report.fixturesForBrowser?.activeGrantId&&r.browser.activeCredentialId===report.fixturesForBrowser.activeCredentialId&&r.browser.clusterId===T.clusterId&&r.browser.workspaceId===T.workspaceId&&
  r.writeEvidence.every(w=>typeof w.requestId==='string'&&w.requestId)&&r.grants.every(g=>g.apiKey&&r.secrets.includes(g.apiKey));
 if(!valid)throw new Error('Read-only verification requires the exact completed HTTP checkpoint and preserved audit-classification failure');
 return{grants:r.grants,clusterIds:[...new Set([...(report.canonicalClusters??[]),...r.fixtures.map(f=>f.cluster.id)])],workspaceIds:r.fixtures.map(f=>f.workspace.id)};
}
/** No actor refresh, network request, reveal, lifecycle entry or ledger write. */
export function guardM6ReadonlyVerification(h,evidence){
 h.requireLive();const context=readonlyVerificationCheckpoint(h.referenceData,evidence),r=h.referenceData;
 const rows=h.consoleRead(READONLY_CURRENT_GRANTS_SQL,[context.grants.map(g=>g.grant.id),context.grants.map(g=>g.credential.id)]);
 h.check(rows.length===6,'Readonly/Current','all six exact completed grant and credential tuples still exist');
 for(const saved of context.grants){const row=rows.find(x=>x.id===saved.grant.id&&x.credential_id===saved.credential.id),first=saved.grant.id===FIRST.grantId,fixture=r.fixtures.find(f=>f.publications.some(p=>p.id===saved.grant.publicationId));
  h.check(row&&fixture&&row.cluster_id===fixture.cluster.id&&row.workspace_id===fixture.workspace.id&&row.consumer_id===saved.managed.consumer_id&&row.acl_id===saved.managed.acl_id&&row.kong_id===saved.managed.kong_id&&row.state===(first?'revoked':'active')&&row.credential_state===(first?'revoked':'active')&&row.current_generation===(first?2:1)&&row.generation===saved.credential.generation&&(!first?row.current_credential_id===saved.credential.id:true),'Readonly/Current','current first grant remains retired and every fresh owned tuple remains active');
 }
 const proof=h.consoleRead(FAILED_ISSUE_DATABASE_SQL,[T.credentialId,T.grantId,T.clusterId,T.workspaceId,T.workflowId,T.executionId,T.executionKey,context.clusterIds,context.workspaceIds]);
 const old=proof[0];
 h.check(proof.length===1&&old.grant_state==='disabled'&&old.current_generation===0&&old.current_credential_id===null&&old.reservation_released_at!==null&&old.certificates===1&&old.credential_state==='pending'&&old.generation===1&&old.credential_ref_id===null&&old.last_revealed_at===null&&old.native_operation_count===1&&old.unexpected_native_results===0&&old.credential_refs===0&&old.native_unresolved===0&&old.portal_unresolved===0&&old.cipher_sha===r.failedIssueContinuation.before.cipher_sha&&old.workflow_state==='failed'&&old.execution_state==='failed','Readonly/History','closed failed certificate, unused immutable Key and all completed native history remain unchanged without unresolved writes');
 return context;
}
