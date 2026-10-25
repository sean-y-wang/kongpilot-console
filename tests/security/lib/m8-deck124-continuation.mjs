import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {M8_COMPOSE,sha256} from './m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt} from './m8-configuration-acceptance.mjs';
import {runM8FixedDeck,m8DeckReadSyncUnusedTail} from './m8-deck-acceptance.mjs';

export const M8_DECK124_CONTINUATION=Object.freeze({
 packetCount:133,prefix:'b0940124842772fc9957198d84bac425d6fb698bc84f6ffe77fc094319a63bf9',
 packet132Sha256:'7085a43f89462bfb3cc49af801b417b1a56c3c011db7e58a05585ff60e3d1417',
 failedPath:'artifacts/M8/security-live-final.json',failedSha256:'44b215d5189c9742e6d4b7bea2c4d0dfe5bee340c6c16dd8a68b07bc4c510456',
 diagnosisPath:'artifacts/M8/deck-validate-offline-readonly-diagnosis.json',diagnosisSha256:'7e775841a348104507fc063e18ec0732d601d683ef45987658b0e335aa4874da',
 inputSha256:'89fcd51dd141b46a48cdd1a83775f5285a2b3bfaa32be942fa3be20b75ca9d3a',
 captureJobId:'5441fe66-833a-4625-8493-e7b66afd5d4c',captureSnapshotId:'9363f644-d6b1-4c2c-a1a2-94ec4076d433',captureKey:'c2051f8a-f379-44a6-b9a4-ac625c81d625',
 runtimePath:'artifacts/M8/deck124-fixed-runner-runtime-ready.json',runtimeSha256:'971658833a44e250a03b9cd9f996d254cdae812e348c1d40df94be743da7dc73',imageId:'sha256:f9502473fd3c3fbd9f93535df86897fcaafe05c0a2d8e3def142b53a7b9df959',
 freezeSha256:'683def101b95a8d874a415d12586a9d1a1a14b613d7f046381bc7acfe878797d',binarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed',toolVersion:'1.2.4',toolCommit:'8e68931',
 archiveFailurePath:'artifacts/M8/security-live-deck11-validate-failure.json',successPath:'artifacts/M8/security-live-deck124-compatibility.json',
});
const oldTool='61394e30ebc92599fbccc9807e558cec018ab407d78e644c0bff5bcb0011554b';
const frozen=r=>sha256(JSON.stringify(r.requests));
export function assertM8Deck124Checkpoint(r,failedBytes,diagnosisBytes){
 const c=M8_DECK124_CONTINUATION,failed=JSON.parse(failedBytes),diagnosis=JSON.parse(diagnosisBytes),p=r.requests?.[132],cli=r.cliIntents?.[0];
 if(r.version!==1||r.milestone!=='M8'||r.phase!=='stopped-failure'||r.inFlight!==null||r.requests?.length!==133||frozen(r)!==c.prefix
  ||sha256(JSON.stringify(p))!==c.packet132Sha256||r.requests.some(x=>x.state!=='response_observed')
  ||r.finalHttpUnusedTail?.state!=='fixed-cli-unused'||r.deck124Continuation||r.deckAcceptance||r.rbacJournal||r.deckSessions?.length
  ||r.cliIntents?.length!==1||cli.command!=='validate'||cli.state!=='response_observed'||cli.dockerExitCode!==1
  ||cli.safeResult?.exitCode!==1||cli.safeResult.toolBinarySha256!==oldTool||cli.safeResult.possibleUnknown!==false||cli.safeResult.stderrBytes!==141
  ||cli.inputSha256!==c.inputSha256||sha256(JSON.stringify(cli.input))!==c.inputSha256||Buffer.byteLength(cli.input.stateYaml)!==15722
  ||sha256(failedBytes)!==c.failedSha256||failed.allPassed!==false||failed.passed!==1711||failed.failed!==1||failed.unknownWrites!==0
  ||sha256(diagnosisBytes)!==c.diagnosisSha256||diagnosis.classification!=='DECK11_PASSIVE_TYPE_UNSUPPORTED'||diagnosis.exitCode!==1||diagnosis.network!=='none'
  ||diagnosis.newBusinessWrites!==0||diagnosis.newAuthWrites!==0||diagnosis.newNativeRequests!==0||diagnosis.originalPrefixUnchanged!==true
  ||r.cliDiagnostics?.length!==1||r.cliDiagnostics[0].state!=='response_observed'||r.cliDiagnostics[0].classification!==diagnosis.classification
  ||r.expiredExecutionRecovery?.state!=='completed'||r.approvalTransfer?.nativeSteps!==17||!r.c2ModeRestored)throw Error('M8_EXACT_133_KNOWN_CLI_FAILURE_CHECKPOINT_REQUIRED');
 const capture=r.configurationOperations.find(x=>x.jobId===c.captureJobId);
 if(!capture||capture.key!==c.captureKey||capture.state!=='succeeded'||capture.receipt?.snapshotId!==c.captureSnapshotId||capture.receipt?.kind!=='capture'
  ||p.responseData?.jobId!==c.captureJobId||p.responseData?.snapshotId!==c.captureSnapshotId||p.status!==201||p.actorId!==r.sessions.admin.user.id||p.sessionId!==r.sessions.admin.sid
  ||p.clusterId!==r.scopes.direct.cid||p.workspaceId!==r.scopes.direct.wid)throw Error('M8_ORIGINAL_133_CAPTURE_TUPLE_REQUIRED');
 return {failed,diagnosis,capture};
}
export function assertM8Deck124Runtime(h){
 const c=M8_DECK124_CONTINUATION,bytes=readFileSync(c.runtimePath),v=JSON.parse(bytes);
 h.check(/^[a-f\d]{64}$/.test(c.runtimeSha256)&&sha256(bytes)===c.runtimeSha256&&v.allPassed===true&&v.imageId===c.imageId
  &&v.toolVersion===c.toolVersion&&v.toolCommit===c.toolCommit&&v.toolBinarySha256===c.binarySha256
  &&v.networkNoneValidatePassed===true&&v.sourceFreezeSha256===c.freezeSha256,'fixed decK1.2.4 image comes only from the independently produced, SHA-bound runtime readiness');
 const env={...process.env};for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
 const image=execFileSync('docker',['--host=unix:///var/run/docker.sock','image','inspect','kongos/deck-runner:1.2.4','--format','{{.Id}}'],{env,shell:false,encoding:'utf8',timeout:10000,maxBuffer:1024}).trim();
 h.check(image===c.imageId,'current local fixed decK1.2.4 image exactly matches the sealed runtime image ID');return v;
}
export function assertM8DeckCaptureAuthority(value,receipt,actor,area){
 const c=M8_DECK124_CONTINUATION;
 if(value?.ok!==true||value.nonOwnerReadOnly!==true||value.job?.id!==c.captureJobId||value.job.kind!=='capture'||value.job.state!=='succeeded'
  ||value.job.same_sid!==true||value.job.same_actor!==true||value.job.same_scope!==true||value.job.same_key!==true||value.job.same_snapshot!==true
  ||typeof value.job.authority_expired!=='boolean'||typeof value.job.job_expired!=='boolean'
  ||receipt.jobId!==c.captureJobId||receipt.snapshotId!==c.captureSnapshotId||receipt.idempotencyKey!==c.captureKey||receipt.actorId!==actor.user.id
  ||receipt.clusterId!==area.cid||receipt.workspaceId!==area.wid)throw Error('M8_CAPTURE_AUTHORITY_CURRENT_EXACT_TUPLE_REQUIRED');
 return value.job.authority_expired||value.job.job_expired;
}
export function readM8DeckCaptureAuthority(h,actor,area){
 const c=M8_DECK124_CONTINUATION;
 const program=`const{Client}=require('pg');let text='';process.stdin.on('data',b=>text+=b);process.stdin.on('end',async()=>{const p=JSON.parse(text),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const who=(await db.query('SELECT current_user AS role,current_database() AS name')).rows[0];if(who.role!=='kongos_app'||who.name!=='kongos')throw Error('NONOWNER_REQUIRED');const job=(await db.query("SELECT id,kind,state,origin_session_id=$5::uuid AS same_sid,actor_id=$4::uuid AS same_actor,cluster_id=$1::uuid AND workspace_id=$2::uuid AS same_scope,idempotency_key=$6 AS same_key,safe_progress->>'snapshotId'=$7 AS same_snapshot,authority_expires_at<=now() AS authority_expired,expires_at<=now() AS job_expired FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND actor_id=$4 AND origin_session_id=$5",[p.cid,p.wid,p.jobId,p.actorId,p.sid,p.idempotencyKey,p.snapshotId])).rows[0];await db.query('COMMIT');console.log(JSON.stringify({ok:true,nonOwnerReadOnly:true,job}));}catch(e){try{await db.query('ROLLBACK');}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'READONLY_FAILED'}));process.exitCode=1;}finally{await db.end();}});`;
 const env={...process.env};for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
 const input={cid:area.cid,wid:area.wid,jobId:c.captureJobId,actorId:actor.user.id,sid:actor.sid,idempotencyKey:c.captureKey,snapshotId:c.captureSnapshotId};
 return JSON.parse(execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'exec','-T','console-api','node','-e',program],{env,shell:false,input:JSON.stringify(input),encoding:'utf8',timeout:10000,maxBuffer:4096}));
}
export async function m8Deck124UnusedAcceptance(h,actors){
 h.check(h.state.deck124Continuation?.state==='prepared'&&h.state.cliIntents.length===1&&!h.state.deckAcceptance,'only the original unused fixed CLI tail may start once');
 assertM8Deck124Runtime(h);const c=M8_DECK124_CONTINUATION,actor=actors.admin,area=actors.direct;
 let captured=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.captureKey}`);
 assertConfigurationReceipt(h,captured,{actor,area,key:c.captureKey,jobId:c.captureJobId,kind:'capture'});
 const authority=readM8DeckCaptureAuthority(h,actor,area),expired=assertM8DeckCaptureAuthority(authority,captured,actor,area);
 h.state.deck124Continuation.captureAuthorityProbe=authority;h.state.deck124Continuation.oldCaptureExpired=expired;h.save();
 if(expired){h.state.deck124Continuation.captureIntent='independent-new-read-capture-after-proven-expiry';h.save();
  captured=await configurationWrite(h,actor,area,'snapshots',{scope:'workspace',name:`${h.state.testTag} decK1.2.4 new current read`,description:'Independent new current read authority; original capture and failed CLI remain historical'},{kind:'capture'});
  h.check(captured.jobId!==c.captureJobId&&captured.idempotencyKey!==c.captureKey,'naturally expired old capture is not replayed or extended');
 }else{h.state.deck124Continuation.captureIntent='reuse-original-current-authorized-capture';h.save();}
 h.state.deck124Continuation.selectedCaptureJobId=captured.jobId;h.state.deck124Continuation.state='new-tool-independent-validate';h.save();
 await runM8FixedDeck(h,actor,area,{command:'validate',stateYaml:h.state.baseline.yaml});
 h.state.deck124Continuation.state='unused-diff-sync';h.save();const result=await m8DeckReadSyncUnusedTail(h,actors,captured);
 h.state.deck124Continuation.state='cli-completed';h.public.fixedToolCompatibility={toolVersion:c.toolVersion,toolBinarySha256:c.binarySha256,formatVersion:'1.1',originalCLIValidateFailureRetained:true,
  originalRawErrorNotRetainedByRunner:true,independentOfflineDiagnosisSha256:c.diagnosisSha256,passiveTypePreserved:true,sixCredentialKindsPreserved:true,oldCaptureExpired:expired};h.save();return result;
}
