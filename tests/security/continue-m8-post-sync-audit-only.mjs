import{readFileSync}from'node:fs';
import{readM8Reference,sha256,entity}from'./lib/m8-harness.mjs';
import{configurationRead}from'./lib/m8-configuration-acceptance.mjs';
import{M8_DECK_SET_CHECKPOINT as c,assertM8UnknownSyncOriginal,M8DeckSetContinuedHarness}from'./lib/m8-deck-set-continuation.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
import{M8_UI_ACTIONS}from'./lib/m8-manual-journal.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_POST_SYNC_AUDIT_ONLY_READY!=='true')throw Error('M8_POST_SYNC_AUDIT_ONLY_RELEASE_REQUIRED');
const failurePath=c.successPath,output='artifacts/M8/security-live-http-closed.json',r=readM8Reference(),previous=JSON.parse(readFileSync(failurePath));
assertM8UnknownSyncOriginal(r);
if(r.phase!=='stopped-failure'||r.requests.length!==172||sha256(JSON.stringify(r.requests))!=='4817037b1d37bbc66f04874961a7813ddf03a40d86f00d7406c89c9934774fa3'
 ||sha256(JSON.stringify(r.cliIntents))!=='ee0ebf053e39ce70ff5959ee72c43a8f3f5e4ef7a82cd1b4069993a961932ebe'||previous.passed!==2430||previous.failed!==1
 ||previous.allPassed!==false||r.deckAcceptance?.desiredRetries!==4||r.deckAcceptance.actualProxyCredentialKinds!==6||r.rbacAcceptance?.complete!==true
 ||r.rbacJournal?.phase!=='complete'||r.uiSessionHandoff?.state!=='completed'||r.postSyncAuditContinuation||r.manualUiJournal)throw Error('M8_EXACT_COMPLETED_SYNC_RBAC_172_CHECKPOINT_REQUIRED');
const h=new M8DeckSetContinuedHarness({resume:true,reference:r});let failure;
try{
 const originalCount=r.requests.length,originalPrefix=sha256(JSON.stringify(r.requests));
 h.checks=previous.checks.filter(v=>v.passed);h.public=Object.fromEntries(Object.entries(previous).filter(([key])=>!['performedAt','checks','passed','failed','allPassed','successfulWrites','unknownWrites','businessWrites','authenticationWrites','fixtures','currentSessionHandoff'].includes(key)));
 r.postSyncAuditContinuation={version:1,state:'prepared',originalCount,originalPrefix,originalSyncOrRbacReplayed:false,sessionMaintenance:{state:'prepared',originalCount,normalWrites:[]}};h.save({phase:'post-sync-audit-unused-tail',inFlight:null});
 const actors={...r.sessions,other:r.sessions['other-owner'],direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
 const current=[];
 for(const[role,label]of[['admin','admin'],['owner','owner'],['readonly','read-only']]){
  const actor=r.sessions[label],old={id:actor.user.id,sid:actor.sid};
  if(actor.expiresAt<Date.now()+600000){const result=h.data(await h.request(actor,'/auth/refresh','POST',{}, {renew:false}));actor.user=result.user;actor.csrf=actor.cookie.split('; ').find(v=>v.startsWith('kongos_csrf='))?.slice(12);h.updateSessionIdentity(actor);h.cookies(actor.cookie);h.remember({csrfToken:actor.csrf});h.save();
   h.check(actor.user.id===old.id&&actor.sid===old.sid,'necessary normal maintenance preserves each actual current actor and SID');r.postSyncAuditContinuation.sessionMaintenance.normalWrites.push(r.requests.at(-1).requestId);}
  const me=h.data(await h.request(actor,'/auth/me','GET',undefined,{renew:false}));h.check(me.user?.id===old.id&&actor.sid===old.sid&&me.csrfToken===actor.csrf&&actor.expiresAt>Date.now()+600000,'current protected UI actor SID and real session expiry have ten minutes');
  current.push({role,actorId:actor.user.id,sessionId:actor.sid,sessionExpiresAt:new Date(actor.expiresAt).toISOString(),remainingSeconds:Math.floor((actor.expiresAt-Date.now())/1000),currentUserProven:true});
 }
 r.postSyncAuditContinuation.sessionMaintenance.state='completed';r.postSyncAuditContinuation.currentSessions=current;h.save();
 const coverage=await m8AllWritesAuditAcceptance(h,actors);
 h.check(coverage.allCovered&&coverage.coveredWrites===coverage.successfulWrites+coverage.recoveredSuccessfulCommits&&coverage.recoveredSuccessfulCommits===1&&coverage.failureClosureWrites===3
  &&coverage.preparedNotIssuedClosureWrites===1&&coverage.nativeNotStartedUnknownCliClosureWrites===1&&coverage.legacyMissingRequestMetadata===0,'actual successful writes and three exact uncertainty closures have complete terminal audit without relabeling console metadata as native history');
 const applied=r.configurationOperations.find(op=>op.jobId===r.deckAcceptance.applyJobId&&op.state==='succeeded'),capture=r.configurationOperations.find(op=>op.jobId===r.deckAcceptance.captureJobId&&op.state==='succeeded');
 h.check(!!applied?.receipt?.planId&&!!capture?.receipt?.snapshotId,'UI resources are the genuine completed standard CLI and earlier capture');
 const job=await configurationRead(h,actors.admin,actors.direct,`configuration/jobs/by-key/${applied.key}`);h.check(job.state==='succeeded'&&job.jobId===applied.jobId&&job.planId===applied.receipt.planId&&job.completedSteps===1&&job.driver==='deck','protected original new CLI receipt is still independently terminal');
 const directCluster=entity(h.data(await h.request(actors.admin,`/clusters/${actors.direct.cid}`))),approvalCluster=entity(h.data(await h.request(actors.admin,`/clusters/${actors.approval.cid}`)));
 h.check(directCluster.execution_mode==='direct'&&approvalCluster.execution_mode===r.originalClusterModes[actors.approval.cid].mode,'actual cluster modes remain at their original configured values');
 const directWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.direct.cid}/workspaces/${actors.direct.wid}`))),approvalWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.approval.cid}/workspaces/${actors.approval.wid}`))),foreignWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.foreign.cid}/workspaces/${actors.foreign.wid}`)));
 h.check(current.every(v=>Date.parse(v.sessionExpiresAt)>Date.now()+300000),'three real current sessions have five minutes after complete audit closure');
 h.check(sha256(JSON.stringify(r.requests.slice(0,originalCount)))===originalPrefix,'all original172 packets including completed sync and RBAC remain unchanged');
 r.httpAcceptanceComplete=true;r.finalHttpUnusedTail.state='completed';r.postSyncAuditContinuation.state='completed';
 r.manualUiHandoff={version:1,phase:'ready',testTag:r.testTag,approvedActions:[...M8_UI_ACTIONS],securityReportPath:output,direct:{...actors.direct},directClusterLabel:`${directCluster.name} · ${directCluster.environment}`,directWorkspaceName:directWorkspace.name,foreignWorkspaceName:foreignWorkspace.name,approvalClusterLabel:`${approvalCluster.name} · ${approvalCluster.environment}`,approvalWorkspaceName:approvalWorkspace.name,approvalWorkflowId:r.approvalTransfer.workflowId,approvalMode:'completed-read-only',snapshotId:capture.receipt.snapshotId,planId:job.planId,jobId:job.jobId,exportId:r.downloads.at(-1).exportId,currentSessions:current};
 Object.assign(h.public,{httpAcceptanceComplete:true,actualM8Complete:false,currentSessionHandoff:current,originalUnknownCliRetained:1,originalUnknownCliClosureReportSha256:c.closeSha256,nativeUnresolvedHistoricalExecutions:1,originalSyncOrRbacReplayed:false});h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,output);if(!failure){r.manualUiHandoff.securityReportSha256=sha256(readFileSync(output));h.save();}
