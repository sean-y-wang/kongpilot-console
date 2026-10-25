import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {readM8Reference,durableJson,M8_REFERENCE,sha256} from './lib/m8-harness.mjs';
if(process.env.M8_DECK_OFFLINE_DIAGNOSIS_READY!=='true')throw Error('M8_OFFLINE_DIAGNOSIS_RELEASE_REQUIRED');
const r=readM8Reference(),original=r.cliIntents?.[0],failurePath='artifacts/M8/security-live-final.json',failureBytes=readFileSync(failurePath);
if(r.requests.length!==133||r.phase!=='stopped-failure'||r.inFlight!==null||r.cliIntents.length!==1||original.state!=='response_observed'||original.command!=='validate'
 ||original.safeResult?.exitCode!==1||original.safeResult?.possibleUnknown!==false||original.safeResult?.toolBinarySha256!=='61394e30ebc92599fbccc9807e558cec018ab407d78e644c0bff5bcb0011554b'
 ||sha256(failureBytes)!=='44b215d5189c9742e6d4b7bea2c4d0dfe5bee340c6c16dd8a68b07bc4c510456'||r.cliDiagnostics?.length)throw Error('M8_EXACT_OFFLINE_DIAGNOSIS_CHECKPOINT_REQUIRED');
const beforeSha=sha256(JSON.stringify(r.requests)),input={command:'validate',stateYaml:original.input.stateYaml},serialized=JSON.stringify(input);
if(Buffer.byteLength(input.stateYaml)!==15722||sha256(serialized)!==original.inputSha256)throw Error('M8_ORIGINAL_DIAGNOSTIC_INPUT_REQUIRED');
const intent={diagnosticId:randomUUID(),purpose:'independent-offline-readonly-diagnosis',command:'validate',inputSha256:sha256(serialized),originalIntentInputSha256:original.inputSha256,
 originalPacketCount:133,originalPrefixSha256:beforeSha,originalFailureSha256:sha256(failureBytes),network:'none',sessionOrTokenProvided:false,timeoutMs:15000,state:'prepared'};
r.cliDiagnostics=[intent];durableJson(M8_REFERENCE,r);
const env={...process.env};for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
const childCode=`import{runDeck}from'/opt/kongos/runner.mjs';let n=0;const a=[];for await(const b of process.stdin){n+=b.length;if(n>32768)throw Error('INPUT_LIMIT');a.push(b)}const b=Buffer.concat(a);let v;try{v=JSON.parse(b.toString())}finally{b.fill(0);for(const x of a)x.fill(0)}if(v.command!=='validate'||Object.keys(v).some(k=>!['command','stateYaml'].includes(k)))throw Error('VALIDATE_ONLY');const result=await runDeck(v,{timeoutMs:15000});try{process.stdout.write(JSON.stringify({safe:result.safe,stderrBase64:result.stderr.toString('base64')})+'\\n')}finally{result.dispose()}`;
try{
 const image=execFileSync('docker',['--host=unix:///var/run/docker.sock','image','inspect','kongos/deck-runner:1.1.0','--format','{{.Id}}'],{env,encoding:'utf8',timeout:5000,maxBuffer:1024}).trim();
 if(image!=='sha256:2fa04b665d762cb17faf583ee085a616958e30694ea0cb2b982f0c900339fb6c')throw Error('DIAGNOSTIC_IMAGE_CHANGED');
 const bytes=execFileSync('docker',['--host=unix:///var/run/docker.sock','run','--rm','--pull','never','--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-i','--entrypoint','node','kongos/deck-runner:1.1.0','--input-type=module','-e',childCode],{env,input:serialized,timeout:20000,maxBuffer:2*1024*1024,stdio:['pipe','pipe','pipe']});
 const result=JSON.parse(bytes.toString('utf8')),stderr=Buffer.from(result.stderrBase64,'base64');
 if(result.safe.command!=='validate'||result.safe.toolBinarySha256!==original.safeResult.toolBinarySha256||result.safe.possibleUnknown!==false||stderr.length>2*1024*1024)throw Error('DIAGNOSTIC_RESULT_INVALID');
 const raw=stderr.toString('utf8'),unsupportedPassiveType=/healthchecks\.passive[^\n]*Additional property type is not allowed/.test(raw);
 Object.assign(intent,{state:'response_observed',safeResult:result.safe,stderrSha256:sha256(stderr),rawStderr:raw,classification:unsupportedPassiveType?'DECK11_PASSIVE_TYPE_UNSUPPORTED':'UNCLASSIFIED_VALIDATE_FAILURE'});
 stderr.fill(0);bytes.fill(0);durableJson(M8_REFERENCE,r);
 if(sha256(JSON.stringify(r.requests))!==beforeSha)throw Error('ORIGINAL_HTTP_PACKET_CHANGED');
 const report={milestone:'M8',testTag:r.testTag,diagnosticOnly:true,originalCLIStillFailed:true,originalRawErrorNotRetainedByRunner:true,diagnosticId:intent.diagnosticId,
  originalFailurePath:failurePath,originalFailureSha256:intent.originalFailureSha256,originalPacketCount:133,originalPrefixUnchanged:true,
  inputByteCount:15722,inputSha256:intent.inputSha256,imageId:image,toolBinarySha256:result.safe.toolBinarySha256,toolVersion:result.safe.toolVersion,
  command:'validate',exitCode:result.safe.exitCode,timedOut:result.safe.timedOut,outputLimitReached:result.safe.outputLimitReached,actualStderrBytes:result.safe.stderrBytes,
  classification:intent.classification,fieldPaths:unsupportedPassiveType?['upstreams[0].healthchecks.passive.type']:[],rawPublished:false,network:'none',newBusinessWrites:0,newAuthWrites:0,newNativeRequests:0,
  originalCaptureReused:true,sessionOrTokenProvided:false,originalCLIResultRewritten:false};
 durableJson('artifacts/M8/deck-validate-offline-readonly-diagnosis.json',report,0o644,true);
 console.log(JSON.stringify({reportPath:'artifacts/M8/deck-validate-offline-readonly-diagnosis.json',classification:report.classification,exitCode:report.exitCode,fieldPaths:report.fieldPaths,newWrites:0}));
}catch(error){if(intent.state==='prepared'){intent.state='response_unknown';intent.errorCode=/^[A-Z0-9_]{2,80}$/.test(error.message??'')?error.message:'OFFLINE_DIAGNOSTIC_TRANSPORT_UNKNOWN';durableJson(M8_REFERENCE,r)}process.exitCode=1;console.log(JSON.stringify({diagnosticState:intent.state,originalBusinessStillStopped:true,newWrites:0}));}
