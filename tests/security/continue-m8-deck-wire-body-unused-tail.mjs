import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256,entity}from'./lib/m8-harness.mjs';
import{configurationRead}from'./lib/m8-configuration-acceptance.mjs';
import{M8_DECK_WIRE_BODY_CONTINUATION,assertM8ClosedPreparedDeckCheckpoint,assertM8DeckWireBodyRelease,m8DeckFreshRetry3Acceptance}from'./lib/m8-deck-wire-body-continuation.mjs';
import{m8RbacAcceptance}from'./lib/m8-rbac-acceptance.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
import{prepareM8UiCurrentSessions}from'./lib/m8-ui-session-handoff.mjs';
import{M8_UI_ACTIONS}from'./lib/m8-manual-journal.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_DECK_WIRE_BODY_UNUSED_TAIL_READY!=='true')throw Error('M8_DECK_WIRE_BODY_UNUSED_TAIL_RELEASE_REQUIRED');
const c=M8_DECK_WIRE_BODY_CONTINUATION,previousBytes=readFileSync(c.failurePath),diagnosisBytes=readFileSync(c.diagnosisPath),sdkBytes=readFileSync(c.sdkProofPath),closeBytes=readFileSync(c.closeReportPath),r=readM8Reference();
const{failed:previous,close:closed}=assertM8ClosedPreparedDeckCheckpoint(r,closeBytes,previousBytes,diagnosisBytes,sdkBytes),h=new M8Harness({resume:true,reference:r});let failure;
try{
 assertM8DeckWireBodyRelease(h);
 const originalPacketCount=r.requests.length,originalPrefixSha256=sha256(JSON.stringify(r.requests));
 Object.assign(r.deckWireBodyContinuation,{unusedTail:{state:'prepared',originalPacketCount,originalPrefixSha256,closeReportSha256:c.closeReportSha256}});
 h.checks=[...previous.checks.filter(v=>v.passed),...closed.checks.filter(v=>v.passed)];h.save({phase:'deck-wire-body-unused-tail',inFlight:null});
 const actors={...r.sessions,other:r.sessions['other-owner'],direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
 h.public={actualM8Complete:false,inheritedHttpReportPath:c.failurePath,inheritedHttpReportSha256:c.failureSha256,originalFailuresRetained:true,
  fiveClassRecovery:r.fiveClassRecovery,directTransfer:r.directTransfer,approvalTransfer:r.approvalTransfer,naturalTimer:r.naturalTimerProven,recoveredCommittedHTTPFailures:1,
  nativeAdminBypassRequests:0,remaining:['browser','soft-cleanup-secret-scan']};
 h.public.originalPreparedClosure=r.deckWireBodyContinuation.originalClosure;
 const admin=actors.admin,start=r.requests.length,prior={actorId:admin.user.id,sessionId:admin.sid,expiresAt:admin.expiresAt};
 r.deckWireBodyContinuation.unusedTail.sessionMaintenance={state:'prepared',...prior,originalPacketCount:start};h.save();
 await h.renewIfNeeded(admin,{minimumRemainingMs:300000});
 const authSuffix=r.requests.slice(start);
 h.check(authSuffix.length<=1&&authSuffix.every(p=>p.path==='/api/v1/auth/refresh'&&p.method==='POST'&&p.state==='response_observed'&&p.status===201&&p.actorId===prior.actorId&&p.sessionId===prior.sessionId)
  &&admin.user.id===prior.actorId&&admin.sid===prior.sessionId&&admin.expiresAt>Date.now()+300000,'initial independent retry3 session uses at most one genuine same-SID normal renewal and has five minutes');
 const me=h.data(await h.request(admin,'/auth/me','GET',undefined,{renew:false}));
 h.check(me.user?.id===prior.actorId&&me.csrfToken===admin.csrf,'initial retry3 protected current user matches the original actor and current CSRF');
 const auditEventIds=[];
 for(const p of authSuffix){const page=h.data(await h.request(admin,`/audit/global?requestId=${p.requestId}&result=success&size=100`,'GET',undefined,{renew:false})),rows=page.items?.filter(v=>v.requestId===p.requestId&&v.actorId===prior.actorId&&v.entityType==='auth_sessions'&&v.entityId===prior.sessionId&&v.action==='refresh'&&['success','succeeded'].includes(v.result));
  h.check(page.nextCursor===null&&page.items?.length<=100&&rows?.length===1,'initial same-SID renewal has one actual immutable original-request audit');auditEventIds.push(rows[0].id);}
 Object.assign(r.deckWireBodyContinuation.unusedTail.sessionMaintenance,{state:'completed',normalAuthenticationWrites:authSuffix.length,requestIds:authSuffix.map(p=>p.requestId),auditEventIds,currentExpiresAt:admin.expiresAt,sameActor:true,sameSID:true});h.save();
 await m8DeckFreshRetry3Acceptance(h,actors);r.finalHttpUnusedTail.state='current-rbac-session-unused';h.save();
 await m8RbacAcceptance(h,actors);r.finalHttpUnusedTail.state='current-ui-session-proof';h.save();
 await prepareM8UiCurrentSessions(h);r.finalHttpUnusedTail.state='actual-write-audit';h.save();
 const coverage=await m8AllWritesAuditAcceptance(h,actors);
 h.check(coverage.allCovered&&coverage.coveredWrites===coverage.successfulWrites+coverage.recoveredSuccessfulCommits&&coverage.recoveredSuccessfulCommits===1
  &&coverage.failureClosureWrites===2&&coverage.preparedNotIssuedClosureWrites===1&&coverage.legacyMissingRequestMetadata===0,
  'all genuine successful writes, original committed HTTP failure and two exact uncertain closures have actual terminal audit, without equating prepared close to Native success');
 const applied=r.configurationOperations.find(op=>op.jobId===r.deckAcceptance.applyJobId&&op.state==='succeeded'),capture=r.configurationOperations.find(op=>op.jobId===r.deckAcceptance.captureJobId&&op.state==='succeeded');
 h.check(applied?.receipt?.planId&&capture?.receipt?.snapshotId,'UI immutable IDs derive from actual successful new CLI job and earlier genuine capture');
 const job=await configurationRead(h,actors.admin,actors.direct,`configuration/jobs/by-key/${applied.key}`);
 h.check(job.state==='succeeded'&&job.jobId===applied.jobId&&job.planId===applied.receipt.planId&&job.completedSteps===1&&job.driver==='deck','current handoff job is the real successful one-step CLI execution');
 const directCluster=entity(h.data(await h.request(actors.admin,`/clusters/${actors.direct.cid}`))),approvalCluster=entity(h.data(await h.request(actors.admin,`/clusters/${actors.approval.cid}`)));
 h.check(directCluster.execution_mode==='direct'&&approvalCluster.execution_mode===r.originalClusterModes[actors.approval.cid].mode,'current final cluster modes preserve the durable original values');
 const directWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.direct.cid}/workspaces/${actors.direct.wid}`))),approvalWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.approval.cid}/workspaces/${actors.approval.wid}`))),foreignWorkspace=entity(h.data(await h.request(actors.admin,`/clusters/${actors.foreign.cid}/workspaces/${actors.foreign.wid}`)));
 h.check([directWorkspace,approvalWorkspace,foreignWorkspace].every((w,i)=>w.id===[actors.direct.wid,actors.approval.wid,actors.foreign.wid][i]&&typeof w.name==='string'),'UI labels are current protected exact workspace names');
 h.check(sha256(JSON.stringify(r.requests.slice(0,originalPacketCount)))===originalPrefixSha256,'all original147 packets and already completed close remain byte-equivalent through independent retry3');
 r.httpAcceptanceComplete=true;r.finalHttpUnusedTail.state='completed';r.deckWireBodyContinuation.state='completed';
 r.manualUiHandoff={version:1,phase:'ready',testTag:r.testTag,approvedActions:[...M8_UI_ACTIONS],securityReportPath:c.successPath,direct:{...actors.direct},
  directClusterLabel:`${directCluster.name} · ${directCluster.environment}`,directWorkspaceName:directWorkspace.name,foreignWorkspaceName:foreignWorkspace.name,
  approvalClusterLabel:`${approvalCluster.name} · ${approvalCluster.environment}`,approvalWorkspaceName:approvalWorkspace.name,approvalWorkflowId:r.approvalTransfer.workflowId,
  approvalMode:'completed-read-only',snapshotId:capture.receipt.snapshotId,planId:job.planId,jobId:job.jobId,exportId:r.downloads.at(-1).exportId,currentSessions:r.uiSessionHandoff.sessions};
 h.public.httpAcceptanceComplete=true;h.public.actualM8Complete=false;h.public.currentSessionHandoff=r.uiSessionHandoff.sessions;h.public.preparedNotIssuedClosureWrites=1;
 h.public.nativeUnresolvedHistoricalExecutions=1;h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,c.successPath);
if(!failure){r.manualUiHandoff.securityReportSha256=sha256(readFileSync(c.successPath));h.save();}
