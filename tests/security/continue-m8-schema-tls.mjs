import {readFileSync} from 'node:fs';
import {M8Harness,readM8Reference,sha256,scope,entity} from './lib/m8-harness.mjs';
import {retainM8History} from './lib/m8-private-history.mjs';
import {configurationWrite,boundedSnapshotObjects,downloadConfiguration,configurationRead} from './lib/m8-configuration-acceptance.mjs';
import {CREDENTIAL_KINDS,nativeRead,proxyRequest,waitProxy} from './lib/m8-native-acceptance.mjs';
import {fiveClassRecoveryAcceptance,directImportRollbackAcceptance,approvalV2AndMetadataAcceptance} from './lib/m8-transfer-acceptance.mjs';

if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_SCHEMA_TLS_CONTINUATION_READY!=='true')throw Error('M8_SCHEMA_TLS_ACTUAL_RELEASE_REQUIRED');
for(const [path,hash]of [
 ['artifacts/M8/certificate-relation-capture-repair-continuity.json','75b69445d184e1774d71734fc8750923a19af36705d741f29d8e6f0ebeac8105'],
 ['artifacts/M8/proxy-tls-controlled-recreate-continuity.json','85b0937cf33eb05e56acbbaf69286a00a7056f32c73da49d3955449f5e912587'],
 ['artifacts/M8/original-fixture-ca-verified-tls-handshake.json','a49a023118b203bc570faea7d1778fc0273a6a79b5774c2d2149d1ef6bd46fb2']]){
 const bytes=readFileSync(path);if(sha256(bytes)!==hash||JSON.parse(bytes).allPassed!==true)throw Error('M8_EXACT_DEPLOYMENT_ORIGINAL_TLS_PROOF_REQUIRED');
}
const failedBytes=readFileSync('artifacts/M8/security-live-capture-epoch-continuation.json'),previous=JSON.parse(failedBytes),r=readM8Reference(),original=r.requests[55];
if(sha256(failedBytes)!=='5d85eadb48e808fbb10ac3a25fd47b5b0defb957f1cc7a57d1675e208f3efa19'
 ||r.phase!=='stopped-failure'||r.schemaTlsContinuation||r.baseline||r.requests.length!==56
 ||sha256(JSON.stringify(r.requests))!=='88abcf88c74f3f0ec5c122f1a08124d4f9e69ba05bc9fe2d4496b3b8bd39abfb'
 ||sha256(JSON.stringify(original))!=='c3388c501e6d7f79e646156b1c34d88d849254ebc77b02631e782227af3bb0fc'
 ||original.status!==502||original.errorCode!=='CONFIGURATION_SCHEMA_FIELD_MISMATCH'||original.state!=='response_observed'
 ||r.tlsHandshake?.state!=='completed'||r.tlsHandshake.authorized!==true||r.tlsHandshake.sameOriginalCertificate!==true
 ||r.requests.some(p=>['prepared','response_unknown'].includes(p.state))||previous.unknownWrites!==0)throw Error('M8_EXACT_KNOWN_FAILED_CAPTURE_56_PREFIX_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'schemaTlsContinuationHistory'),area=r.scopes.direct,actor=r.sessions.admin,f=r.nativeFixture;
 r.schemaTlsContinuation={version:1,state:'started',history,originalFailureSha256:sha256(failedBytes),originalPrefixCount:56,originalPrefixSha256:sha256(JSON.stringify(r.requests)),captureKey:null};
 h.checks=previous.checks.filter(c=>c.passed);h.save({phase:'schema-tls-known-terminal-continuation',inFlight:null});
 const failed=await configurationRead(h,actor,area,`configuration/jobs/by-key/${original.key}`);
 h.check(failed.jobId==='a109c9ef-2363-4596-bd77-fe8e62efed91'&&failed.state==='failed'&&failed.errorCode===original.errorCode&&failed.idempotencyKey===original.key
  &&failed.snapshotId==='e4eb9135-719f-4bfa-a2aa-66d07a3addaf'&&failed.actorId===actor.user.id&&failed.clusterId===area.cid&&failed.workspaceId===area.wid,
  'original failed capture remains immutable at its original key and incomplete snapshot');
 r.schemaTlsContinuation.originalFailedJobId=failed.jobId;h.save();
 const before=await nativeRead(h,actor,area,'routes',f.routes.oauth2.id);
 h.check(before.id==='ad8b741e-76c4-4164-a465-9e9ecf5a3d74'&&before.service?.id===f.service.id&&JSON.stringify(before.protocols)==='["http"]','TLS protocol change selects only the original current OAuth Route');
 const patched=entity(h.data(await h.request(actor,scope(area.cid,area.wid,`entities/routes/${before.id}`),'PATCH',{protocols:['http','https']})));
 h.check(patched.id===before.id&&JSON.stringify(patched.protocols)==='["http","https"]','one BFF packet enables real HTTPS for the original OAuth Route');
 r.oauthTlsReady=true;r.schemaTlsContinuation.oauthRoutePatchRequestId=r.requests.at(-1).requestId;h.save();
 await waitProxy(h,area,f.routes.oauth2.proxyPath+'/echo',{tls:true,headers:{},expected:401});
 const token=await proxyRequest(h,area,f.routes.oauth2.proxyPath+'/oauth2/token',{method:'POST',tls:true,headers:{'Content-Type':'application/json'},body:{grant_type:'client_credentials',client_id:f.inputs.oauth2.client_id,client_secret:f.inputs.oauth2.client_secret},expected:200});
 h.check(typeof token.payload?.access_token==='string'&&token.payload.access_token.length>=16,'real verified-TLS OAuth2 returns a new token');
 await waitProxy(h,area,f.routes.oauth2.proxyPath+'/echo',{tls:true,headers:{Authorization:`Bearer ${token.payload.access_token}`},expected:200,consumerId:f.consumer.id});
 r.oauthTlsProof={state:'completed',consumerId:f.consumer.id,certificateId:f.certificate.id,routeId:before.id,at:new Date().toISOString()};h.save();
 const name=`${r.testTag} verified-TLS baseline`,captured=await configurationWrite(h,actor,area,'snapshots',{scope:'workspace',name,description:'Actual 1.5 complete graph after explicit TLS protocol change'},{kind:'capture'});
 r.schemaTlsContinuation.captureKey=captured.idempotencyKey;h.save();
 const graph=await boundedSnapshotObjects(h,actor,area,captured.snapshotId);
 h.check(graph.summary.completeness==='complete'&&graph.objects.length===graph.summary.objectCount&&graph.objects.every(o=>o.recovery==='complete'),'actual complete sealed snapshot recovers every captured object');
 for(const kind of CREDENTIAL_KINDS)h.check(graph.objects.some(o=>o.credentialKind===kind&&o.nativeId===f.credentials[kind].id&&o.parentId===f.consumer.id),'actual snapshot includes each original typed credential',{kind});
 const schedule=await configurationWrite(h,actor,area,'snapshots/schedules',{scope:'workspace',name:`${r.testTag} real five-minute timer`,intervalMinutes:5,timezone:'UTC',retentionDays:7},{kind:'compare'});
 const policies=await configurationRead(h,actor,area,'snapshots/schedules',{scope:'workspace',size:100}),policy=policies.items.find(s=>s.name===`${r.testTag} real five-minute timer`);
 h.check(policy?.ownerUserId===actor.user.id&&policy.intervalMinutes===5&&Number.isFinite(Date.parse(policy.nextRunAt)),'real server-owned five-minute schedule starts without synthetic due-time');
 r.timerPolicy={area,id:policy.id,name:policy.name,jobId:schedule.jobId,createdAt:policy.createdAt,nextRunAt:policy.nextRunAt,revision:policy.revision};r.fixtures.push({...area,type:'config_snapshot_schedules',id:policy.id,name:policy.name});h.save();
 const exported=await configurationWrite(h,actor,area,`snapshots/${captured.snapshotId}/export`,{mode:'deployment',confirmed:true,confirm_name:name},{kind:'export'}),yaml=await downloadConfiguration(h,actor,area,exported,name);
 r.baseline={area,name,snapshotId:captured.snapshotId,captureJobId:captured.jobId,exportJobId:exported.jobId,yaml,yamlSha256:sha256(yaml)};h.save();
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:'artifacts/M8/security-live-initial.json',sha256:'d6fa6ea7f144d6a7d55c2d983e2cbc7efc6b0edebeff3bab2d42e33bf0440cc2'},
  {path:'artifacts/M8/security-live-https-pending.json',sha256:'370dc942c0d8bf6de7e515e9980c2cbd2662501ea525edb8ba71d73c84b9e46e'},{path:'artifacts/M8/security-live-capture-epoch-continuation.json',sha256:sha256(failedBytes)}],
  actualOAuthTlsProxyComplete:true,snapshot:{id:captured.snapshotId,objectCount:graph.objects.length,displayPages:graph.pages,displayTerminalObserved:true,completeness:graph.summary.completeness},timer:{id:policy.id,nextRunAt:policy.nextRunAt,syntheticTime:false},nativeAdminBypassRequests:0};
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
 await fiveClassRecoveryAcceptance(h,actors);await directImportRollbackAcceptance(h,actors);await approvalV2AndMetadataAcceptance(h,actors);
 r.schemaTlsContinuation.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-schema-tls-continuation.json');
