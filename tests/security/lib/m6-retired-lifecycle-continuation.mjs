import {createHash} from 'node:crypto';
import {canonical} from './m4-harness.mjs';
import {M6_C1,M6_C2,entity,rows,scope,portalScope} from './m6-harness.mjs';
import {checkpointSha} from './m6-isolated-transition.mjs';
import {fixtureRuns} from './m6-fixture-runs.mjs';
import {originalConsoleSession} from './m6-publication-continuation.mjs';
import {originalPortalSession} from './m6-credential-continuation.mjs';
import {FAILED_ISSUE_TUPLE as T} from './m6-failed-issue-key-capture.mjs';
import {PENDING_KEY_TUPLE as FIRST} from './m6-pending-key-capture.mjs';
import {FAILED_ISSUE_DATABASE_SQL,assertFailedIssueReceipt} from './m6-failed-issue-continuation.mjs';

export const RETIRED_KEY_ARCHIVE='fae27bd9-0dba-4b6a-82cd-b59f6b95354b';
export const HISTORICAL_KEY_CIPHER_SQL=`SELECT c.id,c.grant_id,c.cluster_id,c.workspace_id,c.consumer_id,c.kong_id,c.state,c.generation,g.state AS grant_state,g.current_credential_id,
 encode(sha256(convert_to(c.key_secret,'UTF8')),'hex') AS cipher_sha
 FROM portal_credentials c JOIN portal_application_grants g ON g.id=c.grant_id AND g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id
 WHERE c.cluster_id=$1 AND c.workspace_id=$2 AND g.id=$3 AND c.id=$4 AND c.consumer_id=$5 AND c.kong_id=$6`;
export function captureHistoricalKeyCipherBeforeRetirement(h,context,a){
 h.check(!h.referenceData.historicalKeyCipherBeforeRetirement,'Credential/BeforeCipher','historical cipher capture is not overwritten or repeated');
 const{primary}=context,cid=primary.cluster.id,wid=primary.workspace.id;
 const rows=h.consoleRead(HISTORICAL_KEY_CIPHER_SQL,[cid,wid,a.grant.id,a.credential.id,a.managed.consumer_id,a.managed.kong_id]),row=rows[0];
 h.check(rows.length===1&&row.id===a.credential.id&&row.grant_id===a.grant.id&&row.cluster_id===cid&&row.workspace_id===wid&&row.consumer_id===a.managed.consumer_id&&row.kong_id===a.managed.kong_id&&row.state==='active'&&row.grant_state==='active'&&row.generation===a.credential.generation&&row.current_credential_id===a.credential.id&&/^[a-f0-9]{64}$/.test(row.cipher_sha),'Credential/BeforeCipher','one exact active original Key ciphertext is fingerprinted before rotation or retirement');
 const proof={phase:'before-rotation-and-retirement',clusterId:cid,workspaceId:wid,grantId:a.grant.id,credentialId:a.credential.id,consumerId:a.managed.consumer_id,nativeKeyId:a.managed.kong_id,cipherSha256:row.cipher_sha};
 h.saveReference({historicalKeyCipherBeforeRetirement:proof});return proof;
}
export function expectedHistoricalKeyCipher(h,context){
 const saved=h.referenceData.historicalKeyCipherBeforeRetirement,{primary,a}=context;
 if(saved){h.check(saved.phase==='before-rotation-and-retirement'&&saved.clusterId===primary.cluster.id&&saved.workspaceId===primary.workspace.id&&saved.grantId===a.grant.id&&saved.credentialId===a.credential.id&&saved.consumerId===a.managed.consumer_id&&saved.nativeKeyId===a.managed.kong_id&&/^[a-f0-9]{64}$/.test(saved.cipherSha256),'Credential/BeforeCipher','pre-retirement cipher proof is bound to the exact original tenant and Key');return saved.cipherSha256;}
 // The current real repair run predates this fresh-run capture and retains its
 // independently verified immutable metadata-recovery fingerprint instead.
 const legacy=h.referenceData.metadataRecovery;
 h.check(legacy?.phase==='metadata-succeeded-original-execution'&&legacy.workflowId===FIRST.workflowId&&legacy.executionId===FIRST.executionId&&a.grant.id===FIRST.grantId&&a.credential.id===FIRST.credentialId&&/^[a-f0-9]{64}$/.test(legacy.after?.immutable_key_cipher_sha),'Credential/BeforeCipher','legacy repair uses only its independently verified exact original immutable Key fingerprint');
 return legacy.after.immutable_key_cipher_sha;
}
const restorePath='/api/v1/clusters/'+T.clusterId+'/recycle-bin/'+RETIRED_KEY_ARCHIVE+'/restore';
const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const equal=(a,b)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));
const comparable=v=>canonical(Object.fromEntries(Object.entries(v).filter(([key])=>!key.startsWith('console_')&&!key.startsWith('_console'))));
export const RETIRED_RESTORE_DATABASE_SQL=`SELECT c.id AS credential_id,c.grant_id,c.consumer_id,c.kong_id,c.state AS credential_state,c.generation,g.state AS grant_state,g.current_generation,g.current_credential_id,e.state AS archive_state,e.root_type,e.original_id,e.parent_id,e.credential_kind,e.workspace_id,
 m.id AS operation_id,m.state AS operation_state,m.error_code,m.remote_started,m.remote_completed,m.result_secret IS NOT NULL AS has_result,
 (SELECT count(*)::int FROM recycle_nodes n WHERE n.entry_id=e.id AND n.affected) AS affected_nodes,
 (SELECT count(*)::int FROM recycle_nodes n WHERE n.entry_id=e.id AND NOT n.affected AND n.entity_type='consumers' AND n.original_id=c.consumer_id::text) AS shared_consumer_nodes,
 (SELECT count(*)::int FROM recycle_nodes n WHERE n.entry_id=e.id AND n.affected AND (n.delete_state<>'deleted' OR n.restore_state<>'pending' OR n.restored_id IS NOT NULL)) AS changed_archive_nodes,
 (SELECT count(*)::int FROM credential_refs x WHERE x.cluster_id=c.cluster_id AND x.consumer_id=c.consumer_id AND x.state='active') AS active_credential_refs,
 (SELECT count(*)::int FROM mutation_operations x WHERE x.cluster_id=c.cluster_id AND x.request_id=$8) AS same_request_operations,
 (SELECT count(*)::int FROM mutation_operations x WHERE x.cluster_id=c.cluster_id AND x.request_id=$8 AND (x.remote_completed OR x.result_secret IS NOT NULL)) AS same_request_completed_results,
 (SELECT count(*)::int FROM mutation_operations x WHERE x.cluster_id=c.cluster_id AND x.state IN('running','uncertain')) AS native_unresolved,
 (SELECT count(*)::int FROM portal_operations x WHERE x.cluster_id=c.cluster_id AND x.state IN('running','uncertain')) AS portal_unresolved,
 (SELECT x.state FROM portal_credentials x WHERE x.id=$9 AND x.grant_id=g.id) AS original_credential_state,
 (SELECT encode(sha256(convert_to(x.key_secret,'UTF8')),'hex') FROM portal_credentials x WHERE x.id=$9 AND x.grant_id=g.id) AS original_key_cipher_sha
 FROM portal_credentials c JOIN portal_application_grants g ON g.id=c.grant_id AND g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id
 JOIN recycle_entries e ON e.id=c.recycle_entry_id AND e.cluster_id=c.cluster_id AND e.workspace_id=c.workspace_id
 JOIN mutation_operations m ON m.cluster_id=c.cluster_id AND m.workspace_id=c.workspace_id AND m.idempotency_key=$7 AND m.request_id=$8
 WHERE c.cluster_id=$1 AND c.workspace_id=$2 AND e.id=$3 AND c.id=$4 AND g.id=$5 AND c.consumer_id=$6`;

export function retiredLifecycleCheckpoint(r,evidence){
 fixtureRuns(r);
 const proof=evidence?.proof,report=evidence?.report,attempts=r.writeAttempts?.filter(a=>a.path===restorePath)??[],attempt=attempts[0],primary=r.fixtures?.[0],secondary=r.fixtures?.[1];
 const a=r.grants?.find(x=>x.grant.id===FIRST.grantId&&x.credential.id===FIRST.credentialId),b=r.grants?.find(x=>x.grant.publicationId===primary?.publications[1]?.id),c=r.grants?.find(x=>x.grant.publicationId===secondary?.publications[0]?.id);
 const d=proof?.database,rotatedReveal=r.writeAttempts?.filter(x=>x.path.endsWith('/credentials/'+d?.credential_id+'/reveal')&&x.httpStatus>=200&&x.httpStatus<300).at(-1),newKey=rotatedReveal?.responseData?.key;
 const rotation=r.writeAttempts?.filter(x=>x.path.endsWith('/credentials/'+FIRST.credentialId+'/rotate')),revocations=r.writeAttempts?.filter(x=>x.path.endsWith('/credentials/'+d?.credential_id+'/revoke'));
 const ack=r.abandonmentAcknowledgment,journal=r.failedIssueContinuation;
 const material=(r.tokens??[]).length===8&&[[M6_C1,2],[M6_C2,1]].every(([cid,generation])=>Object.entries({native_scrape:'bff',collector_scrape:'collector',collector_catalog:'bff',collector_ingest:'collector'}).every(([purpose,audience])=>r.tokens.filter(x=>x.clusterId===cid&&x.generation===generation&&x.purpose===purpose&&x.audience===audience).length===1));
 const valid=!r.retiredLifecycleContinuation&&r.phase==='dual-cluster-approved-credentials'&&r.fixtures?.length===3&&r.grants?.length===3&&r.portalUsers?.length===3&&primary.cluster.id===T.clusterId&&primary.workspace.id===T.workspaceId&&secondary.cluster.id===M6_C2&&material&&a&&b&&c&&
  r.metadataRecovery?.phase==='metadata-succeeded-original-execution'&&ack?.phase==='certificate-verified'&&ack.totalFormalPosts===2&&ack.additionalFormalPosts===1&&checkpointSha(ack.originalJournal)===ack.originalJournalSha256&&checkpointSha(ack.originalAttempt)===ack.originalAttemptSha256&&journal?.phase==='new-second-issue-complete'&&journal.newGrantId===b.grant.id&&journal.newCredentialId===b.credential.id&&journal.certificateId===ack.certificateId&&
  attempts.length===1&&attempt.method==='POST'&&attempt.actorId===r.consoleAdministrator?.user.id&&attempt.state==='response_observed'&&attempt.httpStatus===404&&attempt.errorCode==='KONG_VALIDATION_ERROR'&&new URLSearchParams(attempt.query).get('workspaceId')===T.workspaceId&&sha(attempt)===proof?.originalAttemptSha256&&attempt.requestId===proof.originalRequestId&&
  proof?.allPassed===true&&proof.readOnly===true&&proof.noPostReplay===true&&proof.originalStatus===404&&proof.originalErrorCode==='KONG_VALIDATION_ERROR'&&proof.entryId===RETIRED_KEY_ARCHIVE&&proof.receipt?.status===200&&proof.operation?.state==='failed'&&proof.operation.error_code==='KONG_VALIDATION_ERROR'&&proof.operation.remote_started===true&&proof.operation.remote_completed===false&&proof.operation.has_result===false&&d?.grant_id===FIRST.grantId&&d.consumer_id===FIRST.consumerId&&d.archive_state==='deleted'&&d.credential_state==='revoked'&&d.grant_state==='revoked'&&d.generation===2&&d.affected_nodes===1&&d.shared_consumer_nodes===1&&d.attempted_restored_nodes===0&&d.active_credential_refs===0&&d.same_request_completed_results===0&&d.native_unresolved===0&&d.portal_unresolved===0&&proof.currentArchiveStatus===200&&proof.currentParentStatus===404&&proof.proxyStatuses?.originalFirstKey===401&&proof.proxyStatuses.retiredRotatedKey===401&&proof.proxyStatuses.activeSecondPublication===200&&proof.proxyStatuses.activeOtherCluster===200&&
  report?.testTag===r.testTag&&report.passed===750&&report.failed===1&&report.lastHttpRequest?.path===restorePath.replace('/api/v1','')&&report.lastHttpRequest.method==='POST'&&report.lastHttpRequest.status===404&&report.failedIssueAbandonment?.formalAbandonmentPosts===2&&
  rotation.length===1&&rotation[0].httpStatus===201&&revocations.length===1&&revocations[0].httpStatus===201&&revocations[0].body.retireConsumer===true;
 // Developer IDs are deliberately not in public grant DTOs; bind the reveal to
 // the current saved tenant principal rather than inventing a grant field.
 const developer=r.portalUsers?.find(x=>x.label==='developer-a'&&x.tenant.clusterId===T.clusterId&&x.tenant.workspaceId===T.workspaceId);
 // The exact actor binding is checked separately from the complete predicate.
 const structural=typeof newKey==='string'&&newKey.length>=32&&newKey!==a?.apiKey&&rotatedReveal?.actorId===developer?.id&&[newKey,a?.apiKey,b?.apiKey,c?.apiKey].every(key=>r.secrets?.includes(key));
 if(!valid||!structural)throw new Error('Retired lifecycle tail requires the exact preserved denial and current completed rotation/retirement checkpoint');
 const other=r.portalUsers.find(x=>x.label==='developer-b'&&x.tenant.clusterId===T.clusterId&&x.tenant.workspaceId===T.workspaceId),c2Developer=r.portalUsers.find(x=>x.label==='developer-c2'&&x.tenant.clusterId===M6_C2&&x.tenant.workspaceId===secondary.workspace.id);
 const legacy=r.writeAttempts.filter(x=>x.path==='/api/v1/clusters/'+T.clusterId+'/entities/plugins'&&x.httpStatus===201&&new URLSearchParams(x.query).get('workspaceId')===T.workspaceId).map(x=>entity(x.responseData));
 const legacyKeyAuth=legacy.find(x=>x?.name==='key-auth'),legacyAcl=legacy.find(x=>x?.name==='acl');
 if(!other||!c2Developer||!r.accounts?.['approver-only']?.session||!r.accounts?.['approver-c2']?.session)throw new Error('Original exact tenant actors missing');
 if(!legacyKeyAuth||!legacyAcl)throw new Error('Exact original legacy plugin records missing');
 return{admin:r.consoleAdministrator,fixtures:r.fixtures,primary,secondary,otherFixture:r.fixtures[2],developer,other,c2Developer,app:a.app,c2App:c.app,approver:r.accounts['approver-only'],secondaryApprover:r.accounts['approver-c2'],legacyKeyAuth,legacyAcl,a,b,c,rotated:{id:d.credential_id,generation:2},newKey,attempt,restoreAttemptSha256:sha(attempt),acknowledgmentSha256:checkpointSha(ack),metadataRecoverySha256:checkpointSha(r.metadataRecovery),proof};
}

export async function proveRetiredParentRestore404(h,context,response,entryId,attempt){
 const {admin,primary,a,rotated,newKey}=context,cid=primary.cluster.id,wid=primary.workspace.id;
 const expectedCipher=expectedHistoricalKeyCipher(h,context);
 h.check(response.status===404&&response.payload?.error?.code==='KONG_VALIDATION_ERROR'&&attempt?.path==='/api/v1/clusters/'+cid+'/recycle-bin/'+entryId+'/restore'&&attempt.method==='POST'&&attempt.actorId===admin.user.id&&attempt.state==='response_observed'&&attempt.httpStatus===404&&new URLSearchParams(attempt.query).get('workspaceId')===wid,'Credential/History404','only this matched restore route and authoritative retired-parent error admit a qualified 404');
 const receipt=h.ok(await h.request(admin,scope('/clusters/'+cid+'/mutations/by-key/'+attempt.key,wid)),'Credential/History404','original failed restore operation receipt');
 h.check(receipt.state==='failed'&&receipt.remote_completed===false,'Credential/History404','failed callback has no completed native result; it is never described as not_sent');
 const db=h.consoleRead(RETIRED_RESTORE_DATABASE_SQL,[cid,wid,entryId,rotated.id,a.grant.id,a.managed.consumer_id,attempt.key,attempt.requestId,a.credential.id]);
 const d=db[0];h.check(db.length===1&&receipt.id===d.operation_id&&receipt.error_code==='KONG_VALIDATION_ERROR'&&d.credential_id===rotated.id&&d.grant_id===a.grant.id&&d.consumer_id===a.managed.consumer_id&&d.credential_state==='revoked'&&d.grant_state==='revoked'&&d.generation===2&&d.archive_state==='deleted'&&d.root_type==='credentials'&&d.credential_kind==='key-auth'&&d.parent_id===a.managed.consumer_id&&d.remote_started===true&&d.remote_completed===false&&!d.has_result&&d.operation_state==='failed'&&d.error_code==='KONG_VALIDATION_ERROR'&&d.affected_nodes===1&&d.shared_consumer_nodes===1&&d.changed_archive_nodes===0&&d.active_credential_refs===0&&d.same_request_operations===1&&d.same_request_completed_results===0&&d.native_unresolved===0&&d.portal_unresolved===0&&d.original_credential_state==='revoked'&&d.original_key_cipher_sha===expectedCipher,'Credential/History404','retired parent and original key remain archived with zero restored nodes, completed results and unresolved operations');
 const bin=h.ok(await h.request(admin,scope('/clusters/'+cid+'/recycle-bin/'+entryId,wid)),'Credential/History404','unchanged encrypted historical archive');
 h.check(bin.entry.id===entryId&&bin.entry.state==='deleted'&&bin.entry.original_id===d.kong_id&&bin.entry.parent_id===a.managed.consumer_id&&bin.nodes.filter(n=>n.affected).every(n=>n.delete_state==='deleted'&&n.restore_state==='pending'&&!n.restored_id),'Credential/History404','the affected Key archive has never entered restoring');
 const parent=await h.request(admin,scope('/clusters/'+cid+'/entities/consumers/'+a.managed.consumer_id,wid));
 h.check(parent.status===404&&parent.payload?.error?.code==='KONG_VALIDATION_ERROR','Credential/History404','the actual retired Consumer is absent; a wrong Nest route or present parent is not accepted');
 for(const key of[a.apiKey,newKey])h.check(await h.proxy(primary.cluster,primary.routes[0].paths[0],'GET',undefined,{apikey:key})===401,'Credential/History404','each already-private retired generation remains unusable');
 return d;
}
export async function assertRetiredKeyRestoreDenial(h,context,response,entryId){
 if([403,409].includes(response.status)){h.check(true,'Credential/History','managed historical Key restore is rejected by the current boundary');return;}
 const attempt=h.referenceData.writeAttempts.filter(a=>a.path==='/api/v1/clusters/'+context.primary.cluster.id+'/recycle-bin/'+entryId+'/restore').at(-1);
 await proveRetiredParentRestore404(h,context,response,entryId,attempt);
}
export async function guardRetiredLifecycleContinuation(h,evidence){
 h.requireLive();const state=retiredLifecycleCheckpoint(h.referenceData,evidence);
 for(const session of[state.admin,state.approver.session,state.secondaryApprover.session])await originalConsoleSession(h,session);
 for(const developer of[state.developer,state.other,state.c2Developer])await originalPortalSession(h,developer);
 for(const f of state.fixtures){const read=async p=>h.ok(await h.request(state.admin,scope('/clusters/'+f.cluster.id+'/'+p,f.workspace.id)),'LifecycleTail/Config','current original fixture configuration');
  const ws=h.ok(await h.request(state.admin,'/clusters/'+f.cluster.id+'/workspaces/'+f.workspace.id),'LifecycleTail/Workspace','current exact workspace');h.check(ws.id===f.workspace.id&&ws.revision===f.workspace.revision&&ws.status==='active','LifecycleTail/Workspace','current workspace is unchanged and active');
  const settings=(await read('portal/settings')).settings;h.check(settings.id===f.settings.id&&settings.revision===f.settings.revision&&settings.published,'LifecycleTail/Config','original tenant settings remain published');
  for(const type of['services','routes'])for(const saved of f[type])h.check(equal(comparable(entity(await read('entities/'+type+'/'+saved.id))),comparable(saved)),'LifecycleTail/Config','current native fixture topology is unchanged');
  for(const saved of f.publications){const actual=entity(await read('portal/publications/'+saved.id));h.check(actual.id===saved.id&&actual.revision===saved.revision&&actual.documentRevision===saved.documentRevision&&actual.status==='published','LifecycleTail/Config','current published proof is unchanged');}
 }
 for(const saved of[state.legacyKeyAuth,state.legacyAcl])h.check(equal(comparable(entity(h.ok(await h.request(state.admin,scope('/clusters/'+T.clusterId+'/entities/plugins/'+saved.id,T.workspaceId)),'LifecycleTail/Legacy','current original controlled legacy plugin'))),comparable(saved)),'LifecycleTail/Legacy','original legacy plugin configuration remains unchanged and is preserved for browser/cleanup');
 for(const[g,developer]of[[state.a,state.developer],[state.b,state.developer],[state.c,state.c2Developer]]){
  const app=entity(h.ok(await h.portal(developer.session,portalScope('/applications/'+g.app.id,developer.tenant)),'LifecycleTail/App','current exact owned app'));h.check(app.id===g.app.id&&app.revision===g.app.revision&&app.state==='active','LifecycleTail/App','owned app remains unchanged');
  const grant=rows(h.ok(await h.portal(developer.session,portalScope('/applications/'+g.app.id+'/grants',developer.tenant)),'LifecycleTail/Grants','current masked grant history')).find(x=>x.id===g.grant.id);
  const creds=rows(h.ok(await h.portal(developer.session,portalScope('/applications/'+g.app.id+'/grants/'+g.grant.id+'/credentials',developer.tenant)),'LifecycleTail/Keys','current masked credential history'));
  h.check(grant?.state===(g===state.a?'revoked':'active')&&grant.generation===(g===state.a?2:1)&&creds.length===(g===state.a?2:1)&&creds.every(x=>x.state===(g===state.a?'revoked':'active')&&x.maskedKey==='••••••••'&&!('key'in x))&&(g===state.a?creds.some(x=>x.id===state.rotated.id&&x.capabilities.reveal===false):creds[0].id===g.credential.id),'LifecycleTail/Current','first grant is now legitimately retired while the other two current grants remain active without reveal');
 }
 const receipt=h.ok(await h.request(state.admin,scope('/clusters/'+T.clusterId+'/workflows/receipts/by-key/'+T.executionKey,T.workspaceId)),'LifecycleTail/Certificate','original failed execution certificate');assertFailedIssueReceipt(h,receipt,true);
 const old=h.consoleRead(FAILED_ISSUE_DATABASE_SQL,[T.credentialId,T.grantId,T.clusterId,T.workspaceId,T.workflowId,T.executionId,T.executionKey,[M6_C1,M6_C2,T.clusterId],state.fixtures.map(x=>x.workspace.id)])[0];
 h.check(old?.grant_state==='disabled'&&old.current_generation===0&&old.reservation_released_at!==null&&old.certificates===1&&old.credential_state==='pending'&&old.generation===1&&old.last_revealed_at===null&&old.credential_ref_id===null&&old.credential_refs===0&&old.native_operation_count===1&&old.unexpected_native_results===0&&old.native_unresolved===0&&old.portal_unresolved===0&&old.cipher_sha===h.referenceData.failedIssueContinuation.before.cipher_sha&&receipt.issueAbandonment.certificateId===h.referenceData.abandonmentAcknowledgment.certificateId,'LifecycleTail/NoReplay','closed unused failed reservation and pending immutable Key remain protected without closure replay');
 await proveRetiredParentRestore404(h,state,{status:404,payload:{error:{code:'KONG_VALIDATION_ERROR'}}},RETIRED_KEY_ARCHIVE,state.attempt);
 for(const g of[state.b,state.c]){const f=g===state.b?state.primary:state.secondary,route=g===state.b?f.routes[1]:f.routes[0];h.check(await h.proxy(f.cluster,route.paths[0],'GET',undefined,{apikey:g.apiKey})===200,'LifecycleTail/Active','each existing active dual-cluster Key still works');}
 h.check(sha(h.referenceData.writeAttempts.find(a=>a.path===restorePath))===state.restoreAttemptSha256&&checkpointSha(h.referenceData.abandonmentAcknowledgment)===state.acknowledgmentSha256&&checkpointSha(h.referenceData.metadataRecovery)===state.metadataRecoverySha256,'LifecycleTail/History','all old restore and completed recovery journals remain unchanged');
 h.saveReference({retiredLifecycleContinuation:{phase:'before-new-tail-actions',restoreAttemptSha256:state.restoreAttemptSha256,originalRestoreAttempt:structuredClone(state.attempt),acknowledgmentSha256:state.acknowledgmentSha256,metadataRecoverySha256:state.metadataRecoverySha256,originalRestoreReplayed:false}});return state;
}
export function beginRetiredLifecycleTail(h,state){
 const journal=h.referenceData.retiredLifecycleContinuation;
 h.check(journal?.phase==='before-new-tail-actions'&&journal.restoreAttemptSha256===sha(state.attempt)&&sha(h.referenceData.writeAttempts.find(a=>a.path===restorePath))===journal.restoreAttemptSha256&&checkpointSha(h.referenceData.abandonmentAcknowledgment)===journal.acknowledgmentSha256&&checkpointSha(h.referenceData.metadataRecovery)===journal.metadataRecoverySha256,'LifecycleTail/Journal','the exact original denial is observed once before only new unfinished lifecycle actions');
 h.saveReference({retiredLifecycleContinuation:{...journal,phase:'tail-actions-started'}});
}

export async function proveManagedConsumerIdentityDenied(h,context,response){
 const {admin,primary,a,newKey}=context,cid=primary.cluster.id,wid=primary.workspace.id,path='/api/v1/clusters/'+cid+'/entities/consumers';
 const attempt=h.referenceData.writeAttempts.filter(x=>x.path===path&&x.body?.id===a.managed.consumer_id).at(-1);
 h.check(response.status===403&&response.payload?.error?.code==='PORTAL_MANAGED_OBJECT'&&attempt?.method==='POST'&&attempt.actorId===admin.user.id&&attempt.body.id===a.managed.consumer_id&&new URLSearchParams(attempt.query).get('workspaceId')===wid&&attempt.state==='response_observed'&&attempt.httpStatus===403,'Lifecycle/Identity','ordinary Consumer creation cannot reuse the retired managed UUID');
 const receipt=h.ok(await h.request(admin,scope('/clusters/'+cid+'/mutations/by-key/'+attempt.key,wid)),'Lifecycle/Identity','original rejected identity request receipt');
 h.check(receipt.state==='failed'&&receipt.remote_completed===false,'Lifecycle/Identity','current identity rejection is knownfailed without completed native result');
 const operations=h.consoleRead('SELECT state,action,entity_type,error_code,remote_completed,result_secret IS NOT NULL AS has_result FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND idempotency_key=$3 AND request_id=$4',[cid,wid,attempt.key,attempt.requestId]);
 h.check(operations.length===1&&operations[0].state==='failed'&&operations[0].action==='create'&&operations[0].entity_type==='consumers'&&operations[0].error_code==='PORTAL_MANAGED_OBJECT'&&!operations[0].remote_completed&&!operations[0].has_result,'Lifecycle/Identity','the protected identity has no completed new native operation');
 const parent=await h.request(admin,scope('/clusters/'+cid+'/entities/consumers/'+a.managed.consumer_id,wid));h.check(parent.status===404&&parent.payload?.error?.code==='KONG_VALIDATION_ERROR','Lifecycle/Identity','the archived managed Consumer remains absent on the actual entity route');
 for(const key of[a.apiKey,newKey])h.check(await h.proxy(primary.cluster,primary.routes[0].paths[0],'GET',undefined,{apikey:key})===401,'Lifecycle/Identity','historical keys cannot be recovered through ordinary identity creation');
}
