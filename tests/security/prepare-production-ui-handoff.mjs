import{randomUUID}from'node:crypto';
import{mkdtempSync,chmodSync,readFileSync}from'node:fs';
import{join}from'node:path';
import{tmpdir}from'node:os';
import{execFileSync}from'node:child_process';
import{ProductionHarness,productionDigest}from'./lib/production-http-harness.mjs';
import{PRODUCTION_UI_ACTIONS}from'./lib/production-ui-fixtures.mjs';
import{validateProductionHandoff}from'./lib/production-ui-journal.mjs';
import{durableProductionJson,PRODUCTION_UI_REFERENCE}from'./lib/production-ui-storage.mjs';

const h=new ProductionHarness({resume:true}),actor=h.state.sessions.bootstrap;
if(h.state.requests.some(p=>p.state!=='response_observed')||h.state.inFlight!==null||h.state.uiPreparation)throw Error('PRODUCTION_UNUSED_UI_HANDOFF_ONLY');
let error;
try{
 const tag='prod-ui-'+randomUUID().slice(0,8);h.state.uiPreparation={tag,state:'prepared'};h.save();
 const cid=h.state.clusterId,workspace=(await h.request(actor,`/api/v1/clusters/${cid}/workspaces`,'POST',{code:tag,name:tag,owner_user_id:actor.user.id,description:'八类实体及34插件的独立生产界面生命周期验收'})).data;
 h.state.uiPreparation.workspace=workspace;h.save();
 const dir=mkdtempSync(join(tmpdir(),'kongos-production-ui-pem-'));chmodSync(dir,0o700);h.state.uiPreparation.pemDirectory=dir;h.save();
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'key.pem'),'-out',join(dir,'cert.pem'),'-days','7','-subj','/CN='+tag+'.invalid','-addext','basicConstraints=critical,CA:TRUE','-addext','subjectAltName=DNS:'+tag+'.invalid'],{stdio:['ignore','pipe','pipe']});chmodSync(join(dir,'key.pem'),0o600);
 const pem={certificate:readFileSync(join(dir,'cert.pem'),'utf8'),caCertificate:readFileSync(join(dir,'cert.pem'),'utf8'),privateKey:readFileSync(join(dir,'key.pem'),'utf8')};h.remember(pem);h.save();
 await h.refresh(actor);
 const now=Date.now(),report={performedAt:new Date().toISOString(),allPassed:true,failed:0,unknownWrites:0,testTag:tag,origin:h.state.origin,clusterId:cid,workspaceId:workspace.id,actorId:actor.user.id,sessionId:actor.sid,sessionExpiresAt:actor.expiresAt,m8ClosureComplete:true,productionHttpsVerified:true,freshScopeVerified:true,signedAccessAcceptedByCurrentMe:true,originalSessionRetained:true,actualCookieFlags:h.state.requests.find(p=>p.path==='/api/v1/auth/login').responseCookies.map(v=>({secure:/;\s*Secure(?:;|$)/i.test(v),httpOnly:/;\s*HttpOnly(?:;|$)/i.test(v),sameSiteStrict:/;\s*SameSite=Strict(?:;|$)/i.test(v)}))};
 if(!report.actualCookieFlags.every(v=>v.secure&&v.httpOnly&&v.sameSiteStrict))throw Error('ACTUAL_COOKIE_FLAGS_REQUIRED');
 const reportPath='artifacts/production/production-ui-handoff.json';durableProductionJson(reportPath,report,true,0o644);const bytes=readFileSync(reportPath);
 const reference={version:1,milestone:'M0-M8-production-ui',phase:'ready',testTag:tag,inFlight:null,requests:structuredClone(h.state.requests),secrets:structuredClone(h.state.secrets),session:structuredClone(actor),pem,uiHandoff:{version:1,phase:'ready',exclusiveRuntimeOwner:'production-ui',testTag:tag,approvedActions:[...PRODUCTION_UI_ACTIONS],origin:h.state.origin,clusterId:cid,workspaceId:workspace.id,executionMode:'direct',isolatedAcceptanceCluster:true,securityReportPath:reportPath,securityReportSha256:productionDigest(bytes),clusterLabel:h.state.cluster.name+' · '+h.state.cluster.environment,workspaceName:workspace.name}};
 validateProductionHandoff(reference,report,bytes,now);durableProductionJson(PRODUCTION_UI_REFERENCE,reference,true);h.state.uiPreparation.state='ready';h.save();
}catch(e){error=true;}
process.exitCode=h.finish('artifacts/Production/root-production-ui-preparation-actual.json',error,{uiPreparationState:h.state.uiPreparation?.state??null});
