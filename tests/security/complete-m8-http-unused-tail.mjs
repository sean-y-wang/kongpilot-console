import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256,entity}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{configurationRead}from'./lib/m8-configuration-acceptance.mjs';
import{m8DeckAcceptance}from'./lib/m8-deck-acceptance.mjs';
import{m8RbacAcceptance}from'./lib/m8-rbac-acceptance.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
import{prepareM8UiCurrentSessions}from'./lib/m8-ui-session-handoff.mjs';
import{M8_UI_ACTIONS}from'./lib/m8-manual-journal.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_HTTP_FINAL_UNUSED_TAIL_READY!=='true')throw Error('M8_HTTP_FINAL_UNUSED_RELEASE_REQUIRED');
const previousPath='artifacts/M8/security-live-expired-execution-recovery.json',previousBytes=readFileSync(previousPath),previous=JSON.parse(previousBytes),r=readM8Reference();
if(previous.milestone!=='M8'||previous.testTag!==r.testTag||previous.allPassed!==true||previous.failed!==0||previous.unknownWrites!==0
 ||r.phase!=='http-complete'||r.inFlight!==null||r.v2WrapperUnusedTail?.state!=='completed'||r.currentApproverRepairTail?.state!=='completed'||r.nullCreateBeforeRepairTail?.state!=='completed'||r.reciprocalBindingRepairTail?.state!=='completed'||!r.directTransfer
 ||r.expiredExecutionRecovery?.state!=='completed'||previous.independent17Complete!==true||r.expiredExecutionRecovery.newScenario?.actualCompleteNativeReceipts!==17
 ||r.approvalTransfer?.nativeSteps!==17||!r.c2ModeRestored||r.fiveClassRecovery?.length!==5||!r.naturalTimerProven
 ||r.finalHttpUnusedTail||r.deckAcceptance||r.rbacJournal||r.cliIntents.length||r.requests.some(p=>p.state!=='response_observed'))throw Error('M8_ACTUAL_DIRECT_ROLLBACK_AND_V2_GREEN_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const originalPacketCount=r.requests.length,originalPrefixSha256=sha256(JSON.stringify(r.requests)),history=retainM8History(r,'finalHttpUnusedTailHistory');
 r.finalHttpUnusedTail={version:1,state:'fixed-cli-unused',history,originalPacketCount,originalPrefixSha256,previousPath,previousSha256:sha256(previousBytes)};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'http-final-unused-tail',inFlight:null});
 const actors={...r.sessions,other:r.sessions['other-owner'],direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
 h.public={actualM8Complete:false,inheritedHttpReportPath:previousPath,inheritedHttpReportSha256:sha256(previousBytes),originalFailuresRetained:true,fiveClassRecovery:r.fiveClassRecovery,directTransfer:r.directTransfer,approvalTransfer:r.approvalTransfer,naturalTimer:r.naturalTimerProven,recoveredCommittedHTTPFailures:1,nativeAdminBypassRequests:0,remaining:['browser','soft-cleanup-secret-scan']};
 await m8DeckAcceptance(h,actors);r.finalHttpUnusedTail.state='current-rbac-session-unused';h.save();
 await m8RbacAcceptance(h,actors);r.finalHttpUnusedTail.state='current-ui-session-proof';h.save();
 await prepareM8UiCurrentSessions(h);r.finalHttpUnusedTail.state='actual-write-audit';h.save();
 const coverage=await m8AllWritesAuditAcceptance(h,actors);
 h.check(coverage.allCovered&&coverage.coveredWrites===coverage.successfulWrites+coverage.recoveredSuccessfulCommits
  &&coverage.recoveredSuccessfulCommits===1&&coverage.failureClosureWrites===1&&coverage.legacyMissingRequestMetadata===0,'every actual successful write, the one proved committed HTTP failure and the one separate uncertain failure closure have full terminal audit coverage');
 const applied=r.configurationOperations.find(op=>op.jobId===r.deckAcceptance.applyJobId&&op.state==='succeeded'),capture=r.configurationOperations.find(op=>op.jobId===r.deckAcceptance.captureJobId&&op.state==='succeeded');
 h.check(applied?.receipt?.planId&&capture?.receipt?.snapshotId,'manual handoff derives immutable IDs from the actual successful CLI execution and capture receipts');
 const job=await configurationRead(h,actors.admin,actors.direct,`configuration/jobs/by-key/${applied.key}`);
 h.check(job.state==='succeeded'&&job.jobId===applied.jobId&&job.planId===applied.receipt.planId&&job.completedSteps===1,'final handoff actual job is the successful one-step real CLI execution');
 const directCluster=entity(h.data(await h.request(actors.admin,`/clusters/${actors.direct.cid}`))),approvalCluster=entity(h.data(await h.request(actors.admin,`/clusters/${actors.approval.cid}`)));
 h.check(directCluster.execution_mode==='direct'&&approvalCluster.execution_mode===r.originalClusterModes[actors.approval.cid].mode,'final actual cluster modes match the durable original modes');
 const directWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.direct.cid}/workspaces/${actors.direct.wid}`))),approvalWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.approval.cid}/workspaces/${actors.approval.wid}`))),foreignWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.foreign.cid}/workspaces/${actors.foreign.wid}`)));
 h.check([directWorkspace,approvalWorkspace,foreignWorkspace].every((w,i)=>w.id===[actors.direct.wid,actors.approval.wid,actors.foreign.wid][i]&&typeof w.name==='string'),'manual scope labels come from current exact protected workspace reads');
 h.check(sha256(JSON.stringify(r.requests.slice(0,originalPacketCount)))===originalPrefixSha256,'all pre-existing BFF packets and failures remain byte-equivalent through the unused final HTTP tail');
 r.httpAcceptanceComplete=true;r.finalHttpUnusedTail.state='completed';
 r.manualUiHandoff={version:1,phase:'ready',testTag:r.testTag,approvedActions:[...M8_UI_ACTIONS],securityReportPath:'artifacts/M8/security-live-final.json',direct:{...actors.direct},directClusterLabel:`${directCluster.name} · ${directCluster.environment}`,directWorkspaceName:directWorkspace.name,foreignWorkspaceName:foreignWorkspace.name,approvalClusterLabel:`${approvalCluster.name} · ${approvalCluster.environment}`,approvalWorkspaceName:approvalWorkspace.name,approvalWorkflowId:r.approvalTransfer.workflowId,approvalMode:'completed-read-only',snapshotId:capture.receipt.snapshotId,planId:job.planId,jobId:job.jobId,exportId:r.downloads.at(-1).exportId,currentSessions:r.uiSessionHandoff.sessions};
 h.public.httpAcceptanceComplete=true;h.public.actualM8Complete=false;h.public.currentSessionHandoff=r.uiSessionHandoff.sessions;h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-final.json');
if(!failure){r.manualUiHandoff.securityReportSha256=sha256(readFileSync('artifacts/M8/security-live-final.json'));h.save();}
