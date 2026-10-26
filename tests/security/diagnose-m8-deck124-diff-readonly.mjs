import {spawn,execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {M8Harness,M8_REFERENCE,M8_COMPOSE,readM8Reference,durableJson,sha256,scope} from './lib/m8-harness.mjs';
import {assertM8Deck124Runtime,M8_DECK124_CONTINUATION} from './lib/m8-deck124-continuation.mjs';
import {assertM8DeckSession} from './lib/m8-deck-acceptance.mjs';
import {assertConfigurationReceipt} from './lib/m8-configuration-acceptance.mjs';

// This is a separate, read-only diagnostic, never a replay of the failed CLI.
if(process.env.M8_DECK_DIFF_DIAGNOSIS_READY!=='true')throw Error('M8_READONLY_DIAGNOSTIC_RELEASE_REQUIRED');
const count=136,prefix='6b5b4f60de043e8a6328c6509a52ff04b222f0808544c4f95b8ebcc8c9a11693';
const failurePath='artifacts/M8/security-live-deck124-compatibility.json',failureSha='498e34f2e222e898b74f5ececbd433fc31407c9e122ffc71a66f1d8a2e5e186a';
const reportPath='artifacts/M8/deck124-diff-readonly-diagnosis.json',r=readM8Reference(),failureBytes=readFileSync(failurePath),old=r.cliIntents?.[2];
if(r.phase!=='stopped-failure'||r.inFlight!==null||r.requests.length!==count||sha256(JSON.stringify(r.requests))!==prefix
 ||r.requests.some(p=>p.state!=='response_observed')||sha256(failureBytes)!==failureSha||r.deckDiffReadonlyDiagnosis
 ||r.cliIntents.length!==3||old?.command!=='diff'||old.state!=='response_observed'||old.safeResult?.exitCode!==1
 ||old.safeResult?.toolBinarySha256!==M8_DECK124_CONTINUATION.binarySha256||old.safeResult?.possibleUnknown!==false
 ||sha256(JSON.stringify(old.input))!==old.inputSha256||old.inputSha256!=='90f24c6e6a4d95a527496fd29fec784b2c9abba0b8acbcee91bf7732d96344d1'
 ||old.jobId!=='0d420e8a-2dc8-44db-ae9c-eecf282700ac'||r.deckSessions?.length!==1
 ||r.deckSessions[0].id!==old.input.sessionId||r.deckSessions[0].jobId!==old.jobId||r.deckAcceptance||r.rbacJournal)throw Error('M8_EXACT_136_DIFF_FAILURE_REQUIRED');
const actor=r.sessions.admin,area=r.scopes.direct,priorSession=r.deckSessions[0],priorCapture=r.configurationOperations.find(p=>p.jobId===old.jobId);
if(actor.user.id!==old.actorId||actor.sid!==old.sessionId||area.cid!==old.clusterId||area.wid!==old.workspaceId
 ||priorCapture?.state!=='succeeded'||priorCapture.receipt?.snapshotId===undefined)throw Error('M8_EXACT_DIAGNOSTIC_ORIGINAL_TUPLE_REQUIRED');
const h=new M8Harness({resume:true,reference:r}),env={...process.env};
for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
assertM8Deck124Runtime(h);
const intent={id:randomUUID(),purpose:'independent-readonly-diff-diagnosis',state:'prepared',originalPacketCount:count,originalPrefixSha256:prefix,
 originalFailurePath:failurePath,originalFailureSha256:failureSha,originalCliInputSha256:old.inputSha256,originalRawStderrUnavailable:true,
 originalPhase:r.phase,actorId:actor.user.id,sessionId:actor.sid,area:{...area},newNativeWrites:0,newSyncIntents:0};
r.deckDiffReadonlyDiagnosis=intent;h.save();
let failure;
try{
 const program=`const{Client}=require('pg');let b='';process.stdin.on('data',v=>b+=v);process.stdin.on('end',async()=>{const p=JSON.parse(b),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const who=(await db.query('SELECT current_user AS role,current_database() AS name')).rows[0];if(who.role!=='kongos_app'||who.name!=='kongos')throw Error('NONOWNER_REQUIRED');const v=[p.cid,p.wid,p.jobId,p.actorId,p.sid,p.key,p.snapshotId,p.deckSessionId];const job=(await db.query(\"SELECT id,kind,state,actor_id=$4::uuid AS actor_matches,origin_session_id=$5::uuid AS sid_matches,idempotency_key=$6 AS key_matches,safe_progress->>'snapshotId'=$7 AS snapshot_matches,authority_expires_at<=now() AS authority_expired,expires_at<=now() AS job_expired FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND actor_id=$4 AND origin_session_id=$5 AND idempotency_key=$6\",v.slice(0,7))).rows[0];const session=(await db.query(\"SELECT id,state,purpose,revision,expires_at<=now() AS expired,extract(epoch FROM expires_at-now())::integer AS remaining_seconds FROM configuration_deck_sessions WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 AND actor_id=$4 AND session_id=$5 AND id=$6 AND purpose='read'\",[p.cid,p.wid,p.jobId,p.actorId,p.sid,p.deckSessionId])).rows[0];await db.query('COMMIT');console.log(JSON.stringify({ok:true,nonOwnerReadOnly:true,job,session}));}catch(e){try{await db.query('ROLLBACK')}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'READONLY_DIAGNOSTIC_FAILED'}));process.exitCode=1}finally{await db.end()}});`;
 const probeInput={cid:area.cid,wid:area.wid,jobId:old.jobId,actorId:actor.user.id,sid:actor.sid,key:priorCapture.key,snapshotId:priorCapture.receipt.snapshotId,deckSessionId:priorSession.id};
 const probe=JSON.parse(execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'exec','-T','console-api','node','-e',program],{env,input:JSON.stringify(probeInput),timeout:10000,maxBuffer:4096,encoding:'utf8'}));
 intent.originalAuthorityProbe=probe;h.save();
 h.check(probe.ok===true&&probe.nonOwnerReadOnly===true&&probe.job?.id===old.jobId&&probe.job.kind==='capture'&&probe.job.state==='succeeded'
  &&probe.job.actor_matches&&probe.job.sid_matches&&probe.job.key_matches&&probe.job.snapshot_matches
  &&typeof probe.job.authority_expired==='boolean'&&typeof probe.job.job_expired==='boolean'&&probe.session?.id===priorSession.id
  &&probe.session.purpose==='read'&&typeof probe.session.expired==='boolean','exact original capture and read session are classified only through non-owner read-only metadata');
 h.check(actor.expiresAt>Date.now()+90000,'diagnosis cannot issue an implicit Auth refresh or change SID');
 h.save({phase:'independent-readonly-deck-diagnosis',inFlight:null});
 const get=async path=>h.data(await h.request(actor,scope(area.cid,area.wid,path),'GET',undefined,{renew:false}));
 const me=h.data(await h.request(actor,'/auth/me','GET',undefined,{renew:false}));
 h.check((me.user??me).id===actor.user.id,'diagnosis uses the existing current authenticated actor');
 let captured=await get(`configuration/jobs/by-key/${priorCapture.key}`);
 assertConfigurationReceipt(h,captured,{actor,area,key:priorCapture.key,jobId:old.jobId,kind:'capture'});
 if(probe.job.authority_expired||probe.job.job_expired){
  const key=randomUUID(),body={scope:'workspace',name:`${r.testTag} independent diff diagnosis`,description:'Read-only diagnostic; original capture/CLI and failure remain historical'};
  const op={key,area:{...area},path:'snapshots',method:'POST',bodySha256:sha256(JSON.stringify(body)),actorId:actor.user.id,sessionId:actor.sid,state:'prepared',diagnosticOnly:true};
  r.configurationOperations.push(op);intent.independentCaptureKey=key;h.save();
  const initial=h.data(await h.request(actor,scope(area.cid,area.wid,'snapshots'),'POST',body,{key,renew:false,expected:[200,201,202]}));
  assertConfigurationReceipt(h,initial,{actor,area,key,kind:'capture'});Object.assign(op,{jobId:initial.jobId,state:'submitted'});h.save();
  captured=await h.poll(()=>get(`configuration/jobs/by-key/${key}`),v=>['succeeded','failed','uncertain','partial','cancelled'].includes(v.state),'new diagnostic read capture reaches a known terminal receipt',60000);
  assertConfigurationReceipt(h,captured,{actor,area,key,jobId:initial.jobId,kind:'capture'});
  h.check(captured.state==='succeeded'&&captured.jobId!==old.jobId,'naturally expired read authority uses an explicitly independent new capture');
  Object.assign(op,{state:captured.state,receipt:captured});h.save();
 }
 // Never probe an expired old token. A new metadata issue is a separate intent.
 const sessionKey=randomUUID(),body={jobId:captured.jobId,purpose:'read'};
 intent.issueKey=sessionKey;intent.captureJobId=captured.jobId;h.save();
 const issued=assertM8DeckSession(h,h.data(await h.request(actor,scope(area.cid,area.wid,'configuration/deck-sessions'),'POST',body,{key:sessionKey,renew:false})),{purpose:'read',jobId:captured.jobId,actor,area});
 h.check(issued.id!==priorSession.id,'independent diagnostic issue never reuses an expired opaque session');
 r.deckSessions.push({...issued,diagnosticOnly:true});r.fixtures.push({...area,type:'configuration_deck_sessions',id:issued.id,name:issued.id});
 intent.deckSessionId=issued.id;intent.expiresAt=issued.expiresAt;h.save();
 const input={command:'diff',sessionId:issued.id,tokenSecret:issued.tokenSecret,stateYaml:old.input.stateYaml},inputText=JSON.stringify(input);
 intent.input=input;intent.inputSha256=sha256(inputText);intent.imageId=M8_DECK124_CONTINUATION.imageId;intent.state='cli-prepared';h.remember(input);h.save();
 // A local trusted read-only recorder forwards only GETs to this exact BFF
 // namespace. No direct gateway transport or additional credentials exist.
 const childCode=`import{createServer,request}from'node:http';import{createInterface}from'node:readline';import{runDeck}from'/opt/kongos/runner.mjs';const lines=createInterface({input:process.stdin}),it=lines[Symbol.asyncIterator](),first=await it.next(),v=JSON.parse(first.value);if(v.command!=='diff')throw Error('DIFF_ONLY');const records=[],base='/api/v1/deck/'+v.sessionId;const server=createServer((q,s)=>{if(q.method!=='GET'||!(q.url===base||q.url.startsWith(base+'/'))||q.headers.authorization!=='KongOS-Deck '+v.tokenSecret){s.writeHead(405);s.end();return}const u=new URL(q.url,'http://console-web:8080'),suffix=u.pathname.slice(base.length),safePath='/api/v1/deck/[session]'+(/^[a-z0-9_/-]{0,256}$/i.test(suffix)?suffix:'/[redacted]');const n={method:'GET',path:safePath,status:null,code:null};records.push(n);if(records.length>100){s.writeHead(429);s.end();return}const upstream=request({hostname:'console-web',port:8080,path:q.url,method:'GET',headers:{Authorization:q.headers.authorization}},p=>{n.status=p.statusCode;if(p.statusCode>=300&&p.statusCode<400){n.code='DIAGNOSTIC_REDIRECT_FORBIDDEN';p.resume();s.writeHead(409);s.end();return}const a=[];let size=0;p.on('data',b=>{size+=b.length;if(size<=2097152)a.push(b);else{p.destroy();s.destroy()}});p.on('end',()=>{const bytes=Buffer.concat(a);try{const x=JSON.parse(bytes.toString());const c=x.message??x.error?.code;if(typeof c==='string'&&/^[A-Z0-9_]{2,128}$/.test(c))n.code=c;if(suffix===''||suffix==='/'){if(typeof x.version==='string'&&/^[0-9.a-z-]{1,64}$/i.test(x.version))n.rootVersion=x.version}}catch{}s.writeHead(p.statusCode,p.headers);s.end(bytes);for(const b of a)b.fill(0)});p.on('error',()=>{n.transportError=true;s.destroy()})});upstream.on('error',()=>{n.transportError=true;s.writeHead(502);s.end()});upstream.end()});await new Promise(ok=>server.listen(0,'127.0.0.1',ok));let result;try{result=await runDeck(v,{origin:'http://127.0.0.1:'+server.address().port,allowLocalTestBff:true,timeoutMs:30000});process.stdout.write(JSON.stringify({safe:result.safe,stderrBase64:result.stderr.toString('base64'),records})+'\\n');const ack=await it.next();if(ack.value!=='PRIVATE_FSYNC_ACK')throw Error('MISSING_PRIVATE_ACK')}finally{result?.dispose();await new Promise(ok=>server.close(ok));lines.close()}`;
 const args=['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'-f','deploy/compose/compose.gitops.yml','-f','tests/security/fixtures/m8-deck-runtime-no-build.yml','--profile','gitops-runner','run','--rm','--no-deps','--pull','never','-T','--entrypoint','node','console-deck-runner','--input-type=module','-e',childCode];
 let observed=false,childResult,transportUnknown=false;
 await new Promise((resolve,reject)=>{
  const child=spawn('docker',args,{env,stdio:['pipe','pipe','pipe'],shell:false});let output='',errorBytes=0,done=false;
  const timer=setTimeout(()=>{transportUnknown=true;child.kill('SIGTERM');reject(Error('DIAGNOSTIC_TIMEOUT'))},40000);
  child.once('error',()=>{clearTimeout(timer);transportUnknown=true;reject(Error('DIAGNOSTIC_START_UNKNOWN'))});
  child.stderr.on('data',b=>{errorBytes+=b.length;if(errorBytes>65536){transportUnknown=true;child.kill('SIGTERM')}});
  child.stdout.on('data',b=>{output+=b.toString();if(Buffer.byteLength(output)>3*1024*1024){transportUnknown=true;child.kill('SIGTERM');return}const at=output.indexOf('\n');if(at<0||observed)return;try{
   childResult=JSON.parse(output.slice(0,at));const raw=Buffer.from(childResult.stderrBase64,'base64');
   if(childResult.safe.command!=='diff'||childResult.safe.toolBinarySha256!==M8_DECK124_CONTINUATION.binarySha256||childResult.safe.possibleUnknown!==false||raw.length>2*1024*1024)throw Error('DIAGNOSTIC_RESULT_INVALID');
   Object.assign(intent,{state:'cli-response-observed',safeResult:childResult.safe,rawStderr:raw.toString('utf8'),stderrSha256:sha256(raw),bffReadRecords:childResult.records});h.save();raw.fill(0);
   observed=true;child.stdin.end('PRIVATE_FSYNC_ACK\n');
  }catch(e){transportUnknown=true;child.kill('SIGTERM');reject(e)}});
  child.once('close',(code)=>{clearTimeout(timer);if(done)return;done=true;if(!observed||transportUnknown||code!==0)reject(Error('DIAGNOSTIC_TRANSPORT_UNKNOWN'));else resolve()});
  child.stdin.write(inputText+'\n');
 });
 const raw=intent.rawStderr,records=intent.bffReadRecords;
 const code=records.find(x=>x.status>=400&&x.code)?.code;
 intent.classification=code?'BFF_'+code:records.some(x=>x.status===404)?'BFF_READ_NOT_FOUND':records.some(x=>x.status>=400)?'BFF_READ_DENIED':/403 Forbidden/.test(raw)?'CLI_HTTP_403':/404 Not Found/.test(raw)?'CLI_HTTP_404':intent.safeResult.exitCode===0?'DIAGNOSTIC_DIFF_SUCCEEDED':'UNCLASSIFIED_DIFF_FAILURE';
 intent.state='completed';h.save({phase:'stopped-readonly-diff-diagnosis'});
 h.check(sha256(JSON.stringify(r.requests.slice(0,count)))===prefix,'all original 136 packets remain byte-equivalent');
 const report={milestone:'M8',performedAt:new Date().toISOString(),testTag:r.testTag,diagnosticOnly:true,allDiagnosticTransportPassed:true,
  originalFailurePath:failurePath,originalFailureSha256:failureSha,originalPacketCount:count,originalPrefixSha256:prefix,originalPrefixUnchanged:true,
  originalRawStderrUnavailable:true,independentDiagnosticId:intent.id,originalAuthorityProbe:probe,independentCaptureCreated:captured.jobId!==old.jobId,
  captureJobId:captured.jobId,deckSessionId:issued.id,toolVersion:intent.safeResult.toolVersion,toolBinarySha256:intent.safeResult.toolBinarySha256,imageId:intent.imageId,
  command:'diff',exitCode:intent.safeResult.exitCode,actualStderrBytes:intent.safeResult.stderrBytes,classification:intent.classification,bffReadRecords:records,
  bffReadCount:records.length,newMetadataWrites:r.requests.length-count,newAuthWrites:0,newSyncIntents:0,newNativeWrites:0,rawPublished:false,
  rawStderrPrivatelyFsyncedBeforeDispose:true,originalCLIResultRewritten:false};
 durableJson(reportPath,report,0o644,true);console.log(JSON.stringify({reportPath,reportSha256:sha256(readFileSync(reportPath)),classification:report.classification,exitCode:report.exitCode,bffReadCount:records.length,newMetadataWrites:report.newMetadataWrites,newAuthWrites:0,newNativeWrites:0}));
}catch(error){failure=error;intent.state=intent.state==='cli-prepared'?'response_unknown':'stopped';intent.errorCode=/^[A-Z0-9_]{2,128}$/.test(error.message??'')?error.message:'DIAGNOSTIC_STOP';h.save({phase:'stopped-readonly-diff-diagnosis'});
 const report={milestone:'M8',testTag:r.testTag,diagnosticOnly:true,allDiagnosticTransportPassed:false,state:intent.state,errorCode:intent.errorCode,originalPrefixUnchanged:sha256(JSON.stringify(r.requests.slice(0,count)))===prefix,newMetadataWrites:r.requests.length-count,newAuthWrites:0,newNativeWrites:0,rawPublished:false};durableJson(reportPath,report,0o644,true);console.log(JSON.stringify({reportPath,reportSha256:sha256(readFileSync(reportPath)),state:report.state,errorCode:report.errorCode}));process.exitCode=1;}
