import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {lstatSync,readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {applyAuditPatch} from './lib/m9-native-audit-worker.mjs';
import {assertM10RequestAuditIdentity,m10MinimalAuditManifest,verifyM10AnalyticalAudit,verifyM10FixedIamAuditEvidence} from './lib/m10-audit-policy.mjs';
import {verifyProductionAuditChain} from './lib/production-audit-integrity.mjs';
import {UUID,m10DockerEnvironment} from './lib/m10-release-evidence.mjs';
import {M10_AUTH_JOURNAL_EVIDENCE_PATH,M10_AUTH_JOURNAL_EVIDENCE_SHA256,M10_AUTH_JOURNAL_LIMITATION,m10BrowserContinuationRootPacket,m10FinalBrowserEvidenceNames,validateM10AuthJournalCoverage,validateM10FinalBrowserRetention} from './lib/m10-auth-journal-coverage.mjs';

const repository=resolve(dirname(new URL(import.meta.url).pathname),'../..'),privateDirectory='/dev/shm/kongpilot-release-lab',reportPath=resolve(repository,'artifacts/M10/audit-verification.json');
const privateBytes=name=>{const path=`${privateDirectory}/${name}`,stat=lstatSync(path);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600);assert(stat.size<=32*1024*1024);return readFileSync(path);};
const privateJSON=name=>JSON.parse(privateBytes(name).toString('utf8'));
const persist=report=>{mkdirSync(dirname(reportPath),{recursive:true});if(existsSync(reportPath)){let suffix=1;while(existsSync(reportPath.replace('.json',`.attempt-${suffix}.json`)))suffix++;writeFileSync(reportPath.replace('.json',`.attempt-${suffix}.json`),readFileSync(reportPath));}writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');};
let authenticationJournalCoverage,browserEvidenceRetention;
try{
 authenticationJournalCoverage=validateM10AuthJournalCoverage(readFileSync(resolve(repository,M10_AUTH_JOURNAL_EVIDENCE_PATH)));
 assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_M10_DEPLOYED,'true');assert.equal(process.env.RELEASE_LAB_AUDIT_READY,'true');
 const verifiedAfter=process.env.RELEASE_LAB_VERIFIED_AFTER;assert(typeof verifiedAfter==='string'&&Number.isFinite(Date.parse(verifiedAfter)));
 const harness=privateJSON('m10-harness.json'),browserFiles=m10FinalBrowserEvidenceNames(harness.browserHandoff),browser=privateJSON(browserFiles.journalName),browserMaterial=privateJSON(browserFiles.materialName);
 assert.equal(browser.passed,true,'ACTUAL_FINAL_M10_BROWSER_REQUIRED');
 browserEvidenceRetention=validateM10FinalBrowserRetention(browserFiles,browser,browserMaterial,browserFiles.freshCycle?{
   journalBytes:privateBytes('m10-browser-journal.json'),reportBytes:readFileSync(resolve(repository,'artifacts/M10/browser/verification.json')),
   materialBytes:existsSync(`${privateDirectory}/m10-browser-secret-material.json`)?privateBytes('m10-browser-secret-material.json'):null,
   ...(browserFiles.readOnlyRecheck?{previousJournalBytes:privateBytes('m10-browser-after-visible-select-fix-journal.json'),
     previousMaterialBytes:privateBytes('m10-browser-after-visible-select-fix-secret-material.json'),
     previousReportBytes:readFileSync(resolve(repository,'artifacts/M10/browser-after-visible-select-fix/verification.json')),
     freshIntentBytes:privateBytes('m10-browser-fresh-intent.json')}:{}) ,
   ...(browserFiles.verificationAttempt===2?{previousReadOnlyJournalBytes:privateBytes('m10-browser-readonly-recheck-journal.json'),
     previousReadOnlyMaterialBytes:privateBytes('m10-browser-readonly-recheck-secret-material.json'),
     previousReadOnlyReportBytes:readFileSync(resolve(repository,'artifacts/M10/browser-readonly-recheck/verification.json'))}:{}) ,
   ...(browser.freshCookieEvidence?{continuationRefreshBrowserBytes:privateBytes('m10-browser-continuation-refresh-browser.json'),
     rawContinuationRefreshBytes:privateBytes('m10-browser-continuation-refresh.json'),rootRefreshPacket:m10BrowserContinuationRootPacket(harness),
     rootRefreshMetadata:harness.browserContinuationRefresh}:{})}:{});
 const manifest=m10MinimalAuditManifest(harness,browser,verifiedAfter);
 const base=new URL(process.env.RELEASE_LAB_API??'http://172.29.250.10:5445/api/v1');assert(base.protocol==='http:'&&base.port==='5445'&&base.pathname==='/api/v1');
 const session=harness.sessions.admin;assert(session?.cookie&&session.user?.id);
 const reader={request:async(actor,path)=>{assert.equal(actor,session);assert(path.startsWith('/api/v1/')&&!path.includes('://'));const response=await fetch(base.origin+path,{method:'GET',headers:{Cookie:actor.cookie},redirect:'manual',signal:AbortSignal.timeout(20000)});assert.equal(response.status,200);const data=await response.json();assert(data.data&&data.meta?.requestId);return{data:data.data,requestId:data.meta.requestId};}};
 const integrity=[];for(const cid of [...manifest.clusterIds,null])integrity.push({scope:cid?`cluster:${cid}`:'global',...await verifyProductionAuditChain(reader,session,cid)});
 let worker=readFileSync(resolve(repository,'tests/security/lib/m10-native-audit-worker.mjs'),'utf8');
 for(const line of ["import { applyAuditPatch } from './m9-native-audit-worker.mjs';","import { assertM10RequestAuditIdentity, verifyM10AnalyticalAudit, verifyM10FixedIamAuditEvidence } from './m10-audit-policy.mjs';"]){assert.equal(worker.split(line).length,2);worker=worker.replace(line,'');}
 const input=worker+'\nconst UUID='+UUID.toString()+';\n'+applyAuditPatch.toString()+'\n'+assertM10RequestAuditIdentity.toString()+'\n'+verifyM10AnalyticalAudit.toString()+'\n'+verifyM10FixedIamAuditEvidence.toString()+'\nawait runM10Audit('+JSON.stringify(manifest)+');\n';
 const result=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2','-i','kongos-ram-tool-m08-20261012-a3','docker','--host=unix:///run/docker-production.sock','exec','-i','-e','RELEASE_LAB_READY=true','-e','RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1','kongpilot-release-lab-console-api-1','node','--input-type=module'],{env:m10DockerEnvironment(),input,encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024});
 if(result.error)throw Error('OWNED_M10_AUDIT_WORKER_FAILED');let report;try{report=JSON.parse(result.stdout);}catch{throw Error('PUBLIC_M10_AUDIT_REPORT_UNAVAILABLE');}assert.equal(report.milestone,'M10');report.bffIntegrity=integrity;report.authenticationJournalCoverage=authenticationJournalCoverage;report.browserEvidenceRetention=browserEvidenceRetention;report.limits=[...(report.limits??[]),M10_AUTH_JOURNAL_LIMITATION];
 persist(report);
 process.stdout.write(JSON.stringify({passed:report.passed,checks:report.checks.length,businessRequests:manifest.requests.length,auditRows:report.auditRows,nativeCompletions:report.nativeCompletionCoverage.length,failedOriginalRequests:manifest.failedOriginalRequests.length,unknownOriginalResponses:manifest.unknownOriginalRequests.length,originalResponseRewritten:false})+'\n');if(!report.passed||result.status!==0)process.exitCode=1;
}catch(error){const failure={code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:error?.code==='ERR_ASSERTION'?'M10_AUDIT_HANDOFF_ASSERTION_FAILED':'M10_AUDIT_TOOL_FAILED'};persist({passed:false,milestone:'M10',productionDeployment:false,credentialsRecorded:false,nativeKongRequests:false,checks:[],failure,originalResponseRewritten:false,authenticationJournalCoverage:authenticationJournalCoverage??{validated:false,evidencePath:M10_AUTH_JOURNAL_EVIDENCE_PATH,expectedEvidenceSha256:M10_AUTH_JOURNAL_EVIDENCE_SHA256},...(browserEvidenceRetention?{browserEvidenceRetention}:{}),limits:[M10_AUTH_JOURNAL_LIMITATION]});process.stderr.write(JSON.stringify({passed:false,...failure,credentialsRecorded:false})+'\n');process.exitCode=1;}
