import { readFileSync } from 'node:fs';
import { M8Harness, readM8Reference, sha256, scope } from './lib/m8-harness.mjs';
import { retainM8History } from './lib/m8-private-history.mjs';
import { configurationWrite, boundedSnapshotObjects, downloadConfiguration } from './lib/m8-configuration-acceptance.mjs';
import { CREDENTIAL_KINDS } from './lib/m8-native-acceptance.mjs';

if (process.env.M8_RUNTIME_READY !== 'true' || process.env.M8_DEPLOYMENT_READY !== 'true' || process.env.M8_EPOCH_CAPTURE_CONTINUATION_READY !== 'true') throw Error('M8_ORIGINAL_CAPTURE_EPOCH_CONTINUATION_REQUIRED');
const failurePath='artifacts/M8/security-live-https-pending.json', bytes=readFileSync(failurePath), report=JSON.parse(bytes),r=readM8Reference(),p=r.requests[53];
if(sha256(bytes)!=='370dc942c0d8bf6de7e515e9980c2cbd2662501ea525edb8ba71d73c84b9e46e'
  ||r.phase!=='stopped-failure'||r.captureEpochContinuation||r.baseline||r.requests.length!==54
  ||sha256(JSON.stringify(r.requests))!=='1eda8f04b814e35e6baebcf8c72faf81f899dd22699f5d5da1adf66e1a3d89f0'
  ||sha256(JSON.stringify(p))!=='652e461efd857ae0fb05c45a16e023499c39d135a51dadefb86f0eb774759ec0'
  ||p.status!==403||p.errorCode!=='CONFIGURATION_ACTOR_INACTIVE'||p.state!=='response_observed'||p.path!==`/api/v1/clusters/${r.scopes.direct.cid}/snapshots`
  ||p.actorId!==r.sessions.admin.user.id||p.sessionId!==r.sessions.admin.sid||p.clusterId!==r.scopes.direct.cid||p.workspaceId!==r.scopes.direct.wid
  ||r.requests.some(x=>['prepared','response_unknown'].includes(x.state))||report.unknownWrites!==0)throw Error('M8_EXACT_DENIED_CAPTURE_54_PREFIX_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
  const history=retainM8History(r,'captureEpochContinuationHistory');
  r.captureEpochContinuation={version:1,state:'checking-original-absence',originalFailurePath:failurePath,originalFailureSha256:sha256(bytes),originalPacketIndex:53,originalPacketSha256:sha256(JSON.stringify(p)),originalKey:p.key,history};
  h.checks=report.checks.filter(c=>c.passed);h.save({phase:'capture-epoch-known-denied-continuation',inFlight:null});
  const actor=r.sessions.admin,area=r.scopes.direct,absence=await h.request(actor,scope(area.cid,area.wid,`configuration/jobs/by-key/${p.key}`),'GET',undefined,{expected:[404]});
  h.check(absence.payload?.error?.code==='CONFIGURATION_RECEIPT_NOT_FOUND','original denied capture has no durable registration at its original key');
  r.captureEpochContinuation.absence={status:absence.status,errorCode:absence.payload.error.code,requestId:absence.requestId};r.captureEpochContinuation.state='before-exact-original-packet-retry';h.save();
  const captured=await configurationWrite(h,actor,area,'snapshots',structuredClone(p.body),{kind:'capture',key:p.key});
  const graph=await boundedSnapshotObjects(h,actor,area,captured.snapshotId);
  h.check(graph.summary.completeness==='complete'&&graph.objects.length===graph.summary.objectCount&&graph.objects.every(o=>o.recovery==='complete'),'real sealed snapshot has complete original objects and recovery');
  for(const kind of CREDENTIAL_KINDS)h.check(graph.objects.some(o=>o.credentialKind===kind&&o.nativeId===r.nativeFixture.credentials[kind].id&&o.parentId===r.nativeFixture.consumer.id),'real sealed snapshot has each typed original credential',{kind});
  const exported=await configurationWrite(h,actor,area,`snapshots/${captured.snapshotId}/export`,{mode:'deployment',confirmed:true,confirm_name:p.body.name},{kind:'export'});
  const yaml=await downloadConfiguration(h,actor,area,exported,p.body.name);
  r.baseline={area,name:p.body.name,snapshotId:captured.snapshotId,captureJobId:captured.jobId,exportJobId:exported.jobId,yaml,yamlSha256:sha256(yaml)};
  const schedule=await configurationWrite(h,actor,area,'snapshots/schedules',{scope:'workspace',name:`${r.testTag} real five-minute timer`,intervalMinutes:5,timezone:'UTC',retentionDays:7},{kind:'compare'});
  const schedules=h.data(await h.request(actor,scope(area.cid,area.wid,'snapshots/schedules',{scope:'workspace',size:100}))),policy=schedules.items.find(s=>s.name===`${r.testTag} real five-minute timer`);
  h.check(policy&&policy.ownerUserId===actor.user.id&&policy.intervalMinutes===5&&Number.isFinite(Date.parse(policy.nextRunAt)),'real server schedule starts its original five-minute timer without synthetic due-time');
  r.timerPolicy={area,id:policy.id,name:policy.name,jobId:schedule.jobId,createdAt:policy.createdAt,nextRunAt:policy.nextRunAt,revision:policy.revision};r.fixtures.push({...area,type:'config_snapshot_schedules',id:policy.id,name:policy.name});
  r.captureEpochContinuation.state='completed';h.save();
  h.public={actualM8Complete:false,phaseScope:'exact-denied-capture-recovery-real-complete-sealed-baseline',oauthTlsProxyComplete:false,
    originalFailuresRetained:[{path:'artifacts/M8/security-live-initial.json',sha256:'d6fa6ea7f144d6a7d55c2d983e2cbc7efc6b0edebeff3bab2d42e33bf0440cc2'},
      {path:failurePath,sha256:sha256(bytes)}],originalCaptureRetry:{originalKey:p.key,originalRequestId:p.requestId,absenceRequestId:absence.requestId,afterJobId:captured.jobId,deliberateOnce:true},
    snapshot:{id:captured.snapshotId,objectCount:graph.objects.length,displayPages:graph.pages,displayTerminalObserved:graph.terminalObserved,completeness:graph.summary.completeness},nativeAdminBypassRequests:0};
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-capture-epoch-continuation.json');
