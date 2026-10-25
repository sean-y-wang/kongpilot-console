import{readFileSync}from'node:fs';
import{readM8Reference,durableJson,sha256}from'./lib/m8-harness.mjs';
import{M8DeckSetContinuedHarness}from'./lib/m8-deck-set-continuation.mjs';
import{beginM8Cleanup,m8CleanupConfiguration,m8CleanupNative,m8CleanupIdentity}from'./lib/m8-cleanup-acceptance.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
import{finalizeM8ManualUiAuditAcceptance}from'./lib/m8-manual-audit-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_SOFT_CLEANUP_READY!=='true')throw Error('M8_EXCLUSIVE_SOFT_CLEANUP_HANDOFF_REQUIRED');
const r=readM8Reference(),manual=JSON.parse(readFileSync('artifacts/M8/manual-ui-unused-tail.json')),audit=JSON.parse(readFileSync('artifacts/M8/manual12-actual-verified-audit.json'));
if(r.phase!=='ui-complete'||r.inFlight!==null||r.manualUiJournal?.phase!=='complete'||r.manualUiAuditProof?.state!=='complete'||manual.allPassed!==true||manual.successfulUiWrites!==12||manual.unknownUiWrites!==0||audit.allPassed!==true||audit.confirmedWrites!==12||r.cleanupJournal)throw Error('M8_REAL12_AND_ACTUAL_AUDIT_COMPLETE_REQUIRED');
const h=new M8DeckSetContinuedHarness({resume:true,reference:r}),actors={...r.sessions,other:r.sessions['other-owner'],bootstrap:r.sessions['bootstrap-provisioner'],direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};let error,result;
try{
 h.public={actualM8Complete:false,actualManual12Complete:true,originalUnknownCliRetained:1,historicalConsumedDownloadDeliveryUnconfirmed:1,productionAcceptanceComplete:false};
 await beginM8Cleanup(h,actors,{pageSize:20});await m8CleanupConfiguration(h,actors);await m8CleanupNative(h,actors);
 result=await m8CleanupIdentity(h,actors,{beforeIdentity:async()=>{await m8AllWritesAuditAcceptance(h,actors);},afterIdentity:async()=>{
  await h.renewIfNeeded(actors.bootstrap);await finalizeM8ManualUiAuditAcceptance(h,actors.bootstrap);await m8AllWritesAuditAcceptance(h,{...actors,admin:actors.bootstrap});
 }});
 h.public.cleanup=result;h.public.actualM8FunctionalComplete=true;h.public.auditWriteCoverage=r.auditWriteCoverage;h.public.manualUiAuditClosure=r.manualUiAuditProof.finalization;h.save({phase:'cleanup-complete',inFlight:null});
}catch(e){error=e;}
const report={version:1,milestone:'M8',testTag:r.testTag,performedAt:new Date().toISOString(),allPassed:!error,passed:h.checks.filter(c=>c.passed).length,failed:error?1:0,checks:[...h.checks,...(error?[{name:error.safeEvidenceMessage?error.message:'Original soft cleanup stopped; all private facts retained',passed:false}]:[])],cleanup:result??null,auditWriteCoverage:r.auditWriteCoverage?Object.fromEntries(Object.entries(r.auditWriteCoverage).filter(([k])=>k!=='records')):null,originalUnknownCliRetained:1,historicalConsumedDownloadDeliveryUnconfirmed:1,physicalPurges:0,newAdminBypassRequests:0,privateReferenceRetained:true,productionAcceptanceComplete:false};
const out='artifacts/M8/soft-cleanup-actual.json';durableJson(out,report,0o644,true);console.log(JSON.stringify({path:out,sha256:sha256(readFileSync(out)),allPassed:report.allPassed,passed:report.passed,failed:report.failed,phase:r.phase,error:error?.safeEvidenceMessage?error.message:null}));if(error)process.exitCode=1;
