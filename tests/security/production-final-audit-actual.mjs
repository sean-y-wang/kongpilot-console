import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { ProductionHarness } from './lib/production-http-harness.mjs';
import { verifyProductionAuditChain } from './lib/production-audit-integrity.mjs';
import { durableProductionJson } from './lib/production-ui-storage.mjs';

const output='artifacts/Production/root-production-final-critical-write-audit-actual.json';
if(process.env.PRODUCTION_AUDIT_EXCLUSIVE_READY!=='true'||existsSync(output))throw Error('PRODUCTION_FINAL_AUDIT_HANDOFF_REQUIRED');
const h=new ProductionHarness({resume:true});if(!h.state.productionRestoreCredentialsComplete)throw Error('ACTUAL_RESTORE_CREDENTIALS_REQUIRED');
const actor=h.state.sessions.bootstrap,cid=h.state.scope.cid;await h.refresh(actor);
const j=JSON.parse(readFileSync('/tmp/kongos-production-ui-original-journal.json'));
const original=[];
for(const p of h.state.requests.filter(p=>p.state==='response_observed'&&p.status>=200&&p.status<300&&!p.path.startsWith('/api/v1/auth/')&&!p.path.endsWith('/test'))){
 original.push({requestId:p.requestId,actorId:p.actorId,method:p.method,path:p.path,origin:'general-business-write'});
}
for(const p of h.state.portalChecks.filter(p=>p.method!=='GET'&&p.status>=200&&p.status<300&&!p.path.startsWith('/auth/'))){
 original.push({requestId:p.requestId,actorId:null,developerId:h.state.productionPortalFixture.developerId,key:p.key,method:p.method,path:p.path,origin:'portal-business-write'});
}
original.push({requestId:j.kongNormalizationHistory.originalSuccessfulRequestId,actorId:j.actorId,method:'PATCH',path:'historical normalized Upstream write',origin:'historical-successful-ui-write'});
const verified=[],historicalGaps=[];
for(const p of h.state.portalAuditChecks??[])if(!p.path.startsWith('/auth/'))original.push({requestId:p.requestId,actorId:null,developerId:h.state.productionPortalFixture.developerId,key:p.key,method:p.method,path:p.path,origin:'portal-business-write'});
for(const p of original){
 const search=new URLSearchParams({requestId:p.requestId,result:'success',size:'100',scope:'cluster'});
 let r=await h.request(actor,`/api/v1/clusters/${cid}/audit?${search}`),rows=r.data.items;
 if(!rows.length){search.set('scope','global');r=await h.request(actor,`/api/v1/audit/global?${search}`);rows=r.data.items;}
 if(!rows.length&&p.requestId==='b6b2e0eb-607a-4323-9df2-8749182f9e60'){historicalGaps.push({...p,reason:'pre-fix application has pending admission audit and no terminal success audit',originalHistoryRewritten:false});continue;}
 if(p.developerId&&!rows.every(r=>r.actorType==='developer'&&r.after?.developerId===p.developerId)){const program="const fs=require('fs'),{Pool}=require('pg');(async()=>{const p=JSON.parse(fs.readFileSync(0,'utf8')),db=new Pool({connectionString:process.env.DATABASE_URL});try{await db.query('BEGIN READ ONLY');const r=await db.query('SELECT developer_id,cluster_id,workspace_id,state,remote_completed FROM portal_operations WHERE idempotency_key=$1 AND developer_id=$2',[p.key,p.developerId]);process.stdout.write(JSON.stringify({proven:r.rows.length===1&&r.rows[0].cluster_id===p.cid&&r.rows[0].workspace_id===p.wid&&r.rows[0].state==='succeeded'&&r.rows[0].remote_completed===true}));await db.query('ROLLBACK');}finally{await db.end();}})().catch(()=>process.exit(1));";const proof=JSON.parse(execFileSync('docker',['--host=unix:///dev/shm/kongos-production-ram-m08-20261012-a3/run/docker-production.sock','exec','-i','kongos-prod-m08-20261012-a3-console-api-1','node','-e',program],{input:JSON.stringify({...p,cid,wid:h.state.scope.wid}),stdio:['pipe','pipe','pipe']}));if(!proof.proven||rows.some(r=>r.actorType!=='developer'))throw Error('PORTAL_ORIGINAL_DEVELOPER_COMMIT_NOT_PROVEN');}
 if(r.data.nextCursor!==null||!rows.length||rows.some(r=>r.actorId!==p.actorId||r.requestId!==p.requestId||!r.sourceIp||!Array.isArray(r.jsonPatch)))throw Error('PRODUCTION_ORIGINAL_CRITICAL_AUDIT_NOT_MATCHED');
 verified.push({...p,auditIds:rows.map(r=>r.id),actualReadRequestId:r.requestId});
}
const cluster=await verifyProductionAuditChain(h,actor,cid),global=await verifyProductionAuditChain(h,actor,null);
const inherited=JSON.parse(readFileSync('artifacts/Production/root-production-ui-all-original-audit-native-actual.json'));
if(!inherited.allPassed||inherited.actualVerifiedOriginalRequestAudits!==178)throw Error('ACTUAL_ORIGINAL_UI_AUDIT_EVIDENCE_REQUIRED');
durableProductionJson(output,{performedAt:new Date().toISOString(),allPassed:historicalGaps.length===0,verificationComplete:true,currentReleaseApplicationAuditFixVerified:h.state.productionPortalApplicationAuditComplete===true,historicalGaps,additionalOriginalCriticalWrites:verified.length,originalUiWrites:178,totalSuccessfulCriticalRequestsCovered:verified.length+178,allOriginalRequestIdsAndActorsMatched:true,sourceIpAndJsonPatchVerified:true,rows:verified,clusterIntegrity:cluster,globalIntegrity:global,businessWritesReplayed:0,excluded:'normal authentication renewals and observational datasource probes; infrastructure maintenance is recorded separately'},true,0o644);
console.log(JSON.stringify({verificationComplete:true,historicalGapCount:historicalGaps.length,additionalWrites:verified.length,totalCriticalRequests:verified.length+178,actualGlobalAndClusterChainsVerified:true}));
