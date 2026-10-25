import{readFileSync}from'node:fs';
import{readM8Reference,sha256,entity}from'./lib/m8-harness.mjs';
import{configurationRead}from'./lib/m8-configuration-acceptance.mjs';
import{M8_DECK_SET_CHECKPOINT as c,assertM8UnknownSyncOriginal,M8DeckSetContinuedHarness}from'./lib/m8-deck-set-continuation.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
import{M8_UI_ACTIONS}from'./lib/m8-manual-journal.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_POST_SYNC_READONLY_AUDIT_READY!=='true')throw Error('M8_POST_SYNC_READONLY_AUDIT_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-http-closed.json',output='artifacts/M8/security-live-http-verified.json',r=readM8Reference(),previous=JSON.parse(readFileSync(failurePath));
assertM8UnknownSyncOriginal(r);
if(sha256(readFileSync(failurePath))!=='257813fc53929522fb2a15ee13bcea974a5b221fd671c14c9e607039d59a6bb5'||r.phase!=='stopped-failure'||r.requests.length!==175||sha256(JSON.stringify(r.requests))!=='4ca583a5ebc139809fbcfd6f41cc641efb3833fedf8753c528cb292f287cbb77'
 ||sha256(JSON.stringify(r.cliIntents))!=='ee0ebf053e39ce70ff5959ee72c43a8f3f5e4ef7a82cd1b4069993a961932ebe'||previous.passed!==2582||previous.failed!==1||previous.allPassed!==false||r.deckAcceptance?.desiredRetries!==4||r.rbacAcceptance?.complete!==true||r.postSyncAuditContinuation?.sessionMaintenance?.state!=='completed'||r.postSyncReadonlyAudit||r.manualUiJournal)throw Error('M8_EXACT175_READONLY_AUDIT_CHECKPOINT_REQUIRED');
const h=new M8DeckSetContinuedHarness({resume:true,reference:r}),originalRequest=h.request.bind(h);let failure;
h.request=(actor,path,method='GET',body,options={})=>{if(method!=='GET')throw Error('M8_AUDIT_FINAL_READONLY_ONLY');return originalRequest(actor,path,method,body,{...options,renew:false});};
try{
 const originalCount=r.requests.length,originalPrefix=sha256(JSON.stringify(r.requests));
 h.checks=previous.checks.filter(v=>v.passed);h.public=Object.fromEntries(Object.entries(previous).filter(([key])=>!['performedAt','checks','passed','failed','allPassed','successfulWrites','unknownWrites','businessWrites','authenticationWrites','fixtures','currentSessionHandoff'].includes(key)));
 r.postSyncReadonlyAudit={version:1,state:'prepared',originalCount,originalPrefix,newWrites:0,newNative:0,newCli:0};h.save({phase:'post-sync-final-readonly-audit',inFlight:null});
 const actors={...r.sessions,other:r.sessions['other-owner'],direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},current=[];
 for(const[role,label]of[['admin','admin'],['owner','owner'],['readonly','read-only']]){const actor=r.sessions[label],me=h.data(await h.request(actor,'/auth/me'));h.check(me.user?.id===actor.user.id&&me.csrfToken===actor.csrf&&actor.expiresAt>Date.now()+300000,'actual current same-SID UI session has five minutes before readonly final audit');current.push({role,actorId:actor.user.id,sessionId:actor.sid,sessionExpiresAt:new Date(actor.expiresAt).toISOString(),remainingSeconds:Math.floor((actor.expiresAt-Date.now())/1000),currentUserProven:true});}
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
 r.httpAcceptanceComplete=true;r.finalHttpUnusedTail.state='completed';r.postSyncAuditContinuation.state='completed';r.postSyncReadonlyAudit.state='completed';
 r.manualUiHandoff={version:1,phase:'ready',testTag:r.testTag,approvedActions:[...M8_UI_ACTIONS],securityReportPath:output,direct:{...actors.direct},directClusterLabel:`${directCluster.name} · ${directCluster.environment}`,directWorkspaceName:directWorkspace.name,foreignWorkspaceName:foreignWorkspace.name,approvalClusterLabel:`${approvalCluster.name} · ${approvalCluster.environment}`,approvalWorkspaceName:approvalWorkspace.name,approvalWorkflowId:r.approvalTransfer.workflowId,approvalMode:'completed-read-only',snapshotId:capture.receipt.snapshotId,planId:job.planId,jobId:job.jobId,exportId:r.downloads.at(-1).exportId,currentSessions:current};
 Object.assign(h.public,{httpAcceptanceComplete:true,actualM8Complete:false,currentSessionHandoff:current,originalUnknownCliRetained:1,originalUnknownCliClosureReportSha256:c.closeSha256,nativeUnresolvedHistoricalExecutions:1,originalSyncOrRbacReplayed:false});h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,output);if(!failure){r.manualUiHandoff.securityReportSha256=sha256(readFileSync(output));h.save();}
