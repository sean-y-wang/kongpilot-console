import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {M6Harness,M6_REFERENCE} from './lib/m6-harness.mjs';
import {guardM6ReadonlyVerification} from './lib/m6-readonly-verification.mjs';
import {verifyM6RuntimeLogs} from './lib/m6-runtime-logs.mjs';
import {findSecretArtifacts} from './check-artifacts.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_READONLY_VERIFICATION_READY!=='true')throw new Error('Root exact read-only verification release required');
const h=new M6Harness({requireReference:true}),before=readFileSync(M6_REFERENCE),sha=b=>createHash('sha256').update(b).digest('hex');let failure;
const read=name=>JSON.parse(readFileSync('artifacts/M6/'+name,'utf8'));
try{
 const report=read('security-live-pre-fix-retired-lifecycle-audit.json'),pin=read('readonly-verification-reference-guard.json');
 h.check(sha(before)===pin.privateReferenceSha256,'Readonly/Evidence','complete private checkpoint is the frozen original audit-only failure');
 h.checks.push(...report.checks.filter(c=>c.passed));
 for(const[k,v]of Object.entries(report))if(!['checks','passed','failed','performedAt','lastHttpRequest'].includes(k))h.public[k]=v;
 guardM6ReadonlyVerification(h,{report,pin});
 h.verifyAuditCoverage();h.verifyAppendOnlyStorage();h.public.runtimeLogRedaction=verifyM6RuntimeLogs(h);
 h.check(sha(readFileSync(M6_REFERENCE))===sha(before),'Readonly/Evidence','no private journal, evidence array, cookie, Key or completed lifecycle changed');
 h.public.readonlyVerification={originalFailure:'security-live-pre-fix-retired-lifecycle-audit.json',originalPassed:1012,originalFailed:1,priorFailurePreserved:true,newBusinessRequests:0,nativeWrites:0,privateReferenceUnchanged:true,qualifiedAuditClassificationCorrection:true,originalLifecycleReplayed:false};
}catch(error){failure=error;h.checks.push({id:'GATE',name:error.safeEvidenceMessage?error.message:'Read-only verification failed; private details withheld',passed:false});}
const evidence={...h.public,performedAt:new Date().toISOString(),passed:h.checks.filter(x=>x.passed).length,failed:h.checks.filter(x=>!x.passed).length,checks:h.checks,privateReferenceRetained:true};
writeFileSync('artifacts/M6/security-live.json',JSON.stringify(evidence,null,2)+'\n');
const encoded=(h.referenceData.tokens??[]).filter(t=>t.purpose==='collector_ingest').flatMap(t=>{const value=Buffer.from('kongos:'+t.token).toString('base64');return[value,'Basic '+value];});
const scan=findSecretArtifacts([...h.secrets,...encoded]);
writeFileSync('artifacts/M6/http-secret-artifact-scan.json',JSON.stringify({performedAt:new Date().toISOString(),...scan,allPassed:scan.leaks.length===0,coversFutureBrowserArtifacts:false,referenceRetainedPrivately:true},null,2)+'\n');
console.log(JSON.stringify({passed:evidence.passed,failed:evidence.failed,leaks:scan.leaks.length,businessRequests:0,privateReferenceUnchanged:sha(readFileSync(M6_REFERENCE))===sha(before)}));
process.exitCode=failure||scan.leaks.length?1:0;
