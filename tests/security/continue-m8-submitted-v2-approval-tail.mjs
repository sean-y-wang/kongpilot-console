import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{configurationRead,assertConfigurationReceipt}from'./lib/m8-configuration-acceptance.mjs';
import{finishM8SubmittedApproval}from'./lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_SUBMITTED_V2_APPROVAL_TAIL_READY!=='true')throw Error('M8_SUBMITTED_V2_UNUSED_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-v2-wrapper-unused-tail.json',failureBytes=readFileSync(failurePath),previous=JSON.parse(failureBytes);
const diagnosticPath='artifacts/M8/original-v2-wrapper-detail-shape-diagnosis.json',diagnosticBytes=readFileSync(diagnosticPath),d=JSON.parse(diagnosticBytes);
const r=readM8Reference(),p=r.requests[94],prefix='b68c76a560ec946331b1fc321e415d5987042bbccfba890c3b5e2499fdf2402d';
if(sha256(failureBytes)!=='62ea161c2175c1a7b1c1e0dbfe2bc3b01549dfb1b13188c472b4ca3b973145c3'
 ||sha256(diagnosticBytes)!=='d2d0e50bc808f8ea16b818215d963318eb55263ceb5d13ede62afada1fb9e4e7'
 ||previous.passed!==1043||previous.failed!==1||previous.unknownWrites!==0||r.requests.length!==95||sha256(JSON.stringify(r.requests))!==prefix
 ||r.phase!=='stopped-failure'||r.inFlight!==null||r.submittedV2ApprovalTail||r.approvalTransfer||!r.directTransfer||r.c2ModeRestored||r.cliIntents.length
 ||r.requests.some(p=>p.state!=='response_observed')||p.status!==201||p.key!=='e43217fc-c7ac-4f2a-8aeb-8347357930e9'
 ||p.responseData.workflowId!=='80b3b831-5522-44e5-ac2d-a538b032a0a2'||p.responseData.jobId!=='f514b7da-b84c-459e-94ee-d10e77b33d1b'
 ||d.state!=='pending'||d.steps?.length!==1||d.steps[0].kind!=='metadata'||d.workflowId!==p.responseData.workflowId
 ||r.requests.some(v=>v.path?.includes(`/workflows/${p.responseData.workflowId}/`)&&['approve','execute'].some(s=>v.path.endsWith('/'+s))))throw Error('M8_EXACT_SUBMITTED_WRAPPER_WITH_UNUSED_DECISIONS_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'submittedV2ApprovalTailHistory');r.submittedV2ApprovalTail={version:1,state:'original-pending-read',history,originalPacketCount:95,originalPrefixSha256:prefix,failurePath,failureSha256:sha256(failureBytes),diagnosticPath,diagnosticSha256:sha256(diagnosticBytes),originalApplyReplayed:false,originalImportReplayed:false,originalModeWriteReplayed:false};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'submitted-v2-unused-decisions',inFlight:null});
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},area=actors.approval;
 const pending=await configurationRead(h,actors.admin,area,`configuration/jobs/by-key/${p.key}`);assertConfigurationReceipt(h,pending,{actor:actors.admin,area,key:p.key,jobId:p.responseData.jobId,kind:'apply'});
 h.check(pending.workflowId===p.responseData.workflowId&&pending.state==='waiting_approval'&&pending.executionCompleted===false,'same original successful apply remains pending its untouched genuine approval');
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:failurePath,sha256:sha256(failureBytes)}],directTransfer:r.directTransfer,fiveClassRecovery:r.fiveClassRecovery,naturalTimer:r.naturalTimerProven,originalApplyReplayed:false,originalImportReplayed:false,originalModeWriteReplayed:false,recoveredCommittedHTTPFailures:1,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 await finishM8SubmittedApproval(h,actors,pending);
 h.check(sha256(JSON.stringify(r.requests.slice(0,95)))===prefix,'all ninety-five original packets retain their exact bytes including original successful pending apply');
 r.v2WrapperUnusedTail.state='completed';r.submittedV2ApprovalTail.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-submitted-v2-approval-tail.json');
