import {spawn,execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {M8_COMPOSE,sha256} from './m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt} from './m8-configuration-acceptance.mjs';
import {M8_DECK124_CONTINUATION,assertM8Deck124Runtime} from './m8-deck124-continuation.mjs';
import {m8DeckReadSyncUnusedTail} from './m8-deck-acceptance.mjs';

export const M8_DECK_POOL_CONTINUATION=Object.freeze({
 packetCount:137,prefix:'6eb9da45cfe27d28338c34c1c8dc6ba8597ceb6c4891294ade93e75e15016029',
 packet136Sha256:'47cbe0fce649f22f3ca648ccf74234fae0f514fa4d6230dceffdd92f8cfa5495',
 diagnosticStateSha256:'c077b385cafead3166f60b361d7d8d749667e23d04e8c6021b0b92c4f1600d24',
 failurePath:'artifacts/M8/security-live-deck124-compatibility.json',failureSha256:'498e34f2e222e898b74f5ececbd433fc31407c9e122ffc71a66f1d8a2e5e186a',
 diagnosisPath:'artifacts/M8/deck124-diff-readonly-diagnosis.json',diagnosisSha256:'f55b8f68d32beb11d307a5414ab1fa0840e68835a51972274b1e63b181fa1fa2',
 logsPath:'artifacts/M8/deck124-diff-bounded-log-diagnosis.json',logsSha256:'5b9b29dab73389218e17772f77010d37412d132983168f78052934343b930f90',
 captureJobId:'0d420e8a-2dc8-44db-ae9c-eecf282700ac',captureKey:'ac7fabb3-0530-4520-b720-5d0c321f70be',captureSnapshotId:'55c5f346-64a8-448b-b163-c5c9cfcd543f',
 successPath:'artifacts/M8/security-live-deck-pool-transaction.json',
 // Root-authored release evidence is intentionally required before runtime.
 sourceFreezePath:'artifacts/M8/root-deck-pool-transaction-fix-freeze.json',sourceFreezeSha256:'c76114ad109ee0167d7917c0df2ab7b702f797a57a4cb1de74c5c29fe97d8e8d',
 continuityPath:'artifacts/M8/deck-pool-transaction-api-repair-continuity.json',continuitySha256:'13c50a12d4ef8ce45ae88254eaa4b238f3cd44fc441d59bf1c16c48ee0a7ff3b',
});
const c=M8_DECK_POOL_CONTINUATION,hex=v=>typeof v==='string'&&/^[a-f\d]{64}$/.test(v);
export function assertM8DeckPoolCheckpoint(r,failedBytes,diagnosisBytes,logBytes){
 const failed=JSON.parse(failedBytes),diagnosis=JSON.parse(diagnosisBytes),logs=JSON.parse(logBytes),p=r.requests?.[136],d=r.deckDiffReadonlyDiagnosis,cli=r.cliIntents;
 if(r.version!==1||r.milestone!=='M8'||r.phase!=='stopped-readonly-diff-diagnosis'||r.inFlight!==null||r.requests?.length!==c.packetCount
  ||sha256(JSON.stringify(r.requests))!==c.prefix||sha256(JSON.stringify(p))!==c.packet136Sha256||r.requests.some(v=>v.state!=='response_observed')
  ||sha256(JSON.stringify(d))!==c.diagnosticStateSha256||d?.state!=='completed'||d.originalPrefixSha256!=='6b5b4f60de043e8a6328c6509a52ff04b222f0808544c4f95b8ebcc8c9a11693'
  ||sha256(failedBytes)!==c.failureSha256||failed.allPassed!==false||failed.passed!==1745||failed.failed!==1||failed.unknownWrites!==0
  ||sha256(diagnosisBytes)!==c.diagnosisSha256||diagnosis.allDiagnosticTransportPassed!==true||diagnosis.exitCode!==1||diagnosis.newMetadataWrites!==1||diagnosis.newAuthWrites!==0||diagnosis.newNativeWrites!==0
  ||sha256(logBytes)!==c.logsSha256||logs.classification!=='SAFE_CAUSE_UNAVAILABLE'||logs.currentPacketCount!==137
  ||cli?.length!==3||cli[0].safeResult?.toolVersion!=='1.1.0'||cli[0].safeResult?.exitCode!==1
  ||cli[1].command!=='validate'||cli[1].state!=='response_observed'||cli[1].safeResult?.exitCode!==0||cli[1].safeResult?.toolBinarySha256!==M8_DECK124_CONTINUATION.binarySha256
  ||cli[2].command!=='diff'||cli[2].state!=='response_observed'||cli[2].safeResult?.exitCode!==1||cli[2].safeResult?.possibleUnknown!==false
  ||r.deckAcceptance||r.rbacJournal||r.deckPoolContinuation||r.deckSessions?.length!==2||!r.c2ModeRestored
  ||r.expiredExecutionRecovery?.state!=='completed'||r.approvalTransfer?.nativeSteps!==17||r.finalHttpUnusedTail?.state!=='fixed-cli-unused'
  ||r.deck124Continuation?.state!=='unused-diff-sync')throw Error('M8_EXACT_137_KNOWN_DIFF_CHECKPOINT_REQUIRED');
 const op=r.configurationOperations.find(v=>v.jobId===c.captureJobId);
 if(op?.key!==c.captureKey||op.state!=='succeeded'||op.receipt?.snapshotId!==c.captureSnapshotId||p.status!==201||p.requestId!=='d0c4321b-29ec-430a-9a44-b57be784b0de'
  ||p.actorId!==r.sessions.admin.user.id||p.sessionId!==r.sessions.admin.sid||p.clusterId!==r.scopes.direct.cid||p.workspaceId!==r.scopes.direct.wid
  ||d.actorId!==p.actorId||d.sessionId!==p.sessionId||d.captureJobId!==op.jobId||d.deckSessionId!==r.deckSessions[1].id
  ||d.input.sessionId!==d.deckSessionId||d.input.tokenSecret!==r.deckSessions[1].tokenSecret||d.input.stateYaml!==cli[2].input.stateYaml
  ||sha256(JSON.stringify(d.input))!==d.inputSha256||r.baseline.yaml!==cli[1].input.stateYaml||r.baseline.yaml!==cli[2].input.stateYaml)throw Error('M8_ORIGINAL_137_SCOPE_AND_PRIVATE_CLI_REQUIRED');
 return{failed,diagnosis,logs,capture:op};
}
export function assertM8DeckPoolRelease(h){
 for(const [path,digest]of[[c.sourceFreezePath,c.sourceFreezeSha256],[c.continuityPath,c.continuitySha256]]){
  h.check(typeof path==='string'&&path.startsWith('artifacts/M8/')&&hex(digest),'Root freeze and actual continuity must exist before the pending source may run');
  const b=readFileSync(path),v=JSON.parse(b),source=path===c.sourceFreezePath;
  h.check(sha256(b)===digest&&(source?v.stage==='SOURCE_READY_DECK_CURRENT_AUTHORIZATION_SAME_TRANSACTION'&&v.sourceOnly===true&&v.validation?.apiTypecheckExitCode===0
   &&v.validation.apiBuildExitCode===0&&v.validation.gitDiffCheckExitCode===0&&v.validation.wholeSourceFailed===0&&v.validation.wholeSourceSkipped===0&&v.transactionRepair?.poolMaxUnchanged===10
   &&v.transactionRepair.sessionRowLockPreserved===true&&v.transactionRepair.currentActorSidIamModuleAndScopeChecksPreserved===true:v.allPassed===true),
   'Root-authored source and runtime repair evidence is SHA-bound and green');
 }
 assertM8Deck124Runtime(h);
}
export function readM8DeckPoolCaptureAuthority(h,actor,area){
 const p={cid:area.cid,wid:area.wid,jobId:c.captureJobId,actorId:actor.user.id,sid:actor.sid,key:c.captureKey,snapshotId:c.captureSnapshotId};
 const code=`const{Client}=require('pg');let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',async()=>{const p=JSON.parse(s),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const who=(await db.query('SELECT current_user AS role,current_database() AS name')).rows[0];if(who.role!=='kongos_app'||who.name!=='kongos')throw Error('NONOWNER_REQUIRED');const job=(await db.query(\"SELECT id,kind,state,actor_id=$4::uuid AS actor_matches,origin_session_id=$5::uuid AS sid_matches,idempotency_key=$6 AS key_matches,safe_progress->>'snapshotId'=$7 AS snapshot_matches,authority_expires_at<=now() AS authority_expired,expires_at<=now() AS job_expired FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND actor_id=$4 AND origin_session_id=$5 AND idempotency_key=$6\",[p.cid,p.wid,p.jobId,p.actorId,p.sid,p.key,p.snapshotId])).rows[0];await db.query('COMMIT');console.log(JSON.stringify({ok:true,nonOwnerReadOnly:true,job}));}catch(e){try{await db.query('ROLLBACK')}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'READONLY_FAILED'}));process.exitCode=1}finally{await db.end()}});`;
 const env={...process.env};for(const k of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
 return JSON.parse(execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'exec','-T','console-api','node','-e',code],{env,input:JSON.stringify(p),timeout:10000,maxBuffer:4096,encoding:'utf8'}));
}
export function assertM8DeckPoolCaptureAuthority(value,receipt,actor,area){
 const j=value?.job;
 if(value?.ok!==true||value.nonOwnerReadOnly!==true||j?.id!==c.captureJobId||j.kind!=='capture'||j.state!=='succeeded'||!j.actor_matches||!j.sid_matches||!j.key_matches||!j.snapshot_matches
  ||typeof j.authority_expired!=='boolean'||typeof j.job_expired!=='boolean'||receipt.jobId!==c.captureJobId||receipt.idempotencyKey!==c.captureKey||receipt.snapshotId!==c.captureSnapshotId
  ||receipt.actorId!==actor.user.id||receipt.clusterId!==area.cid||receipt.workspaceId!==area.wid)throw Error('M8_EXACT_CURRENT_CAPTURE_AUTHORITY_REQUIRED');
 return j.authority_expired||j.job_expired;
}
/** Same fixed runDeck/binary/origin as the standard entrypoint. There is no
 * observer, HTTP proxy or alternative Admin address. The only extension is a
 * private-fsync ACK before the trusted caller disposes bounded CLI stderr. */
export async function runM8FixedDeckPrivateStderr(h,actor,area,input,{jobId=null}={}){
 h.assertWritable();h.check(['diff','sync'].includes(input.command)&&typeof input.stateYaml==='string'&&Buffer.byteLength(input.stateYaml)<=8*1024*1024,'only the original unused standard-origin network CLI may run');
 h.check(typeof input.sessionId==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(input.sessionId)
  &&typeof input.tokenSecret==='string'&&/^[A-Za-z\d_-]{43}$/.test(input.tokenSecret),'network CLI requires a real issued current opaque session');
 const text=JSON.stringify(input),frozen=JSON.parse(text),intent={key:randomUUID(),command:frozen.command,jobId,actorId:actor.user.id,sessionId:actor.sid,clusterId:area.cid,workspaceId:area.wid,
  input:frozen,inputSha256:sha256(text),state:'prepared',startedAt:new Date().toISOString(),fixedOrigin:'http://console-web:8080',observer:false};
 h.remember({tokenSecret:frozen.tokenSecret});h.state.cliIntents.push(intent);h.save();
 const code=`import{createInterface}from'node:readline';import{runDeck}from'/opt/kongos/runner.mjs';const lines=createInterface({input:process.stdin}),it=lines[Symbol.asyncIterator]();const first=await it.next(),v=JSON.parse(first.value);if(!['diff','sync'].includes(v.command))throw Error('NETWORK_CLI_ONLY');const result=await runDeck(v,{origin:'http://console-web:8080'});try{process.stdout.write(JSON.stringify({safe:result.safe,stderrBase64:result.stderr.toString('base64')})+'\\n');const ack=await it.next();if(ack.value!=='PRIVATE_FSYNC_ACK')throw Error('PRIVATE_ACK_MISSING')}finally{result.dispose();lines.close()}`;
 const env={...process.env};for(const k of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
 const args=['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'-f','deploy/compose/compose.gitops.yml','-f','tests/security/fixtures/m8-deck-runtime-no-build.yml','--profile','gitops-runner','run','--rm','--no-deps','--pull','never','-T','--name',`kongos-m8-deck-${intent.key}`,'--entrypoint','node','console-deck-runner','--input-type=module','-e',code];
 let safe,exit=null,unknown=false,observed=false;
 await new Promise(resolve=>{
  let settled=false,out='',err=0,timer,killTimer,closeTimer,child;
  const settle=n=>{if(settled)return;settled=true;exit=n;clearTimeout(timer);clearTimeout(killTimer);clearTimeout(closeTimer);resolve()};
  const stop=()=>{unknown=true;try{child?.kill('SIGTERM')}catch{}if(!killTimer)killTimer=setTimeout(()=>{try{child?.kill('SIGKILL')}catch{}},1000);if(!closeTimer)closeTimer=setTimeout(()=>settle(null),3000)};
  try{child=spawn('docker',args,{env,shell:false,stdio:['pipe','pipe','pipe']});child.once('error',stop);child.once('close',settle);for(const stream of[child.stdout,child.stderr,child.stdin])stream.on('error',stop);
   child.stderr.on('data',b=>{err+=b.length;if(err>65536)stop()});
   child.stdout.on('data',b=>{out+=b.toString('utf8');if(Buffer.byteLength(out)>4*1024*1024){stop();return}const n=out.indexOf('\n');if(n<0||observed)return;try{const v=JSON.parse(out.slice(0,n)),raw=Buffer.from(v.stderrBase64,'base64');safe=v.safe;
    if(safe?.command!==frozen.command||safe.toolBinarySha256!==M8_DECK124_CONTINUATION.binarySha256||safe.toolVersion!=='1.2.4'||safe.toolCommit!=='8e68931'
     ||!Number.isSafeInteger(safe.exitCode)||typeof safe.possibleUnknown!=='boolean'||typeof safe.timedOut!=='boolean'||typeof safe.outputLimitReached!=='boolean'
     ||safe.consoleJobSuccessProved!==false||!Number.isSafeInteger(safe.stderrBytes)||raw.length!==safe.stderrBytes||raw.length>2*1024*1024)throw Error('PRIVATE_CLI_RESULT_INVALID');
    Object.assign(intent,{safeResult:safe,rawCliStderr:raw.toString('utf8'),rawCliStderrSha256:sha256(raw),rawStderrPrivatelyFsyncedBeforeDispose:false});
    h.save();raw.fill(0);intent.rawStderrPrivatelyFsyncedBeforeDispose=true;h.save();observed=true;child.stdin.end('PRIVATE_FSYNC_ACK\n');
   }catch{stop()}});timer=setTimeout(stop,150000);child.stdin.write(text+'\n');
  }catch{if(child)stop();else{unknown=true;settle(null)}}
 });
 intent.dockerExitCode=exit;
 if(unknown||!observed||safe.possibleUnknown===true||safe.timedOut||safe.outputLimitReached||exit!==0){intent.state='response_unknown';h.save({phase:'stopped-cli-unknown'});throw Error('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');}
 intent.state='response_observed';h.save();h.check(safe.exitCode===0&&safe.consoleJobSuccessProved===false,'fixed CLI success is independent of the configuration job and current Native proof');return safe;
}
export async function m8DeckPoolUnusedAcceptance(h,actors){
 assertM8DeckPoolRelease(h);h.check(h.state.deckPoolContinuation?.state==='prepared','the fixed original 137 checkpoint may continue once');
 const actor=actors.admin,area=actors.direct;
 let receipt=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.captureKey}`);assertConfigurationReceipt(h,receipt,{actor,area,key:c.captureKey,jobId:c.captureJobId,kind:'capture'});
 const probe=readM8DeckPoolCaptureAuthority(h,actor,area),expired=assertM8DeckPoolCaptureAuthority(probe,receipt,actor,area);h.state.deckPoolContinuation.originalCaptureAuthorityProbe=probe;h.save();
 if(expired){receipt=await configurationWrite(h,actor,area,'snapshots',{scope:'workspace',name:`${h.state.testTag} pool repair current read`,description:'Independent read capture after exact original authority naturally expired'},{kind:'capture'});
  h.check(receipt.jobId!==c.captureJobId&&receipt.idempotencyKey!==c.captureKey,'expired capture is never replayed or extended');}
 h.state.deckPoolContinuation.selectedCaptureJobId=receipt.jobId;h.state.deckPoolContinuation.state='unused-standard-diff-sync';h.save();
 const result=await m8DeckReadSyncUnusedTail(h,actors,receipt,{run:runM8FixedDeckPrivateStderr,validatedIntentIndex:1});
 h.state.deckPoolContinuation.state='cli-completed';h.public??={};h.public.fixedToolCompatibility={toolVersion:'1.2.4',formatVersion:'1.1',originalCLIValidateFailureRetained:true,originalCLIDiffFailureRetained:true,
  readonlyDiagnosticRetained:true,standardOrigin:true,observer:false,passiveTypePreserved:true,sixCredentialKindsPreserved:true};h.save();return result;
}
