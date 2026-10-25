import { execFileSync,spawnSync } from 'node:child_process';
import { constants,closeSync,existsSync,fstatSync,lstatSync,openSync,readFileSync,readdirSync,rmSync,rmdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseEnv } from 'node:util';
import { findSecretArtifacts } from './check-artifacts.mjs';
import { collectEnvironmentSecrets } from '../../deploy/scripts/collect-environment-secrets.mjs';
import { M8_REFERENCE,M8_COMPOSE,readM8Reference,durableJson,sha256 } from './lib/m8-harness.mjs';
import { M8_HISTORY_DIRECTORY,readM8PrivateHistories } from './lib/m8-private-history.mjs';
import { m8CapturedSecrets,m8SecretForms,M8_LOG_SERVICES } from './lib/m8-secret-scan-policy.mjs';
import{isM8ProvenConsumedUnknownDownload}from'./lib/m8-consumed-review-download.mjs';
import{M8_DECK_SET_CHECKPOINT,isM8ProvenSetUnknownSyncClosurePacket}from'./lib/m8-deck-set-continuation.mjs';

if(process.env.M8_FINAL_SCAN_READY!=='true'||!process.argv.includes('--evidence-complete'))throw Error('M8_EXCLUSIVE_FINAL_SCAN_HANDOFF_REQUIRED');
const r=readM8Reference(),handoff=r.finalScanHandoff;
const continuation=process.argv.includes('--transport-provenance-continuation');
if(continuation){
 const original=safeRead('artifacts/M8/runtime-secret-artifact-scan.json',16*1024*1024);
 if(sha256(original)!=='9463d92940ce03477ac7bfd2f01d03890bae17bbdc0cf1d4a91c3c5b375bf727'||JSON.parse(original).allPassed!==false
  ||!r.finalScanStarted||r.finalScanContinuationStarted)throw Error('M8_SCAN_CONTINUATION_ORIGINAL_REQUIRED');
 const checkpointBytes=safeRead('artifacts/M8/secret-transport-classifier-original-scan-checkpoint.json',65536);
 if(sha256(checkpointBytes)!=='5fb6fb7516e4d0bdff999c2edf563db78a3e9b893f5484c4ef5cda66acaa8e67')throw Error('M8_SCAN_CONTINUATION_CHECKPOINT_CHANGED');
 const checkpoint=JSON.parse(checkpointBytes);
 if(checkpoint.originalFailedScan.sha256!==sha256(original)||checkpoint.testTag!==r.testTag||checkpoint.requestCount!==r.requests.length
  ||checkpoint.requestsSha256!==sha256(JSON.stringify(r.requests))||checkpoint.proxyChecksSha256!==sha256(JSON.stringify(r.proxyChecks))
  ||checkpoint.cliIntentsSha256!==sha256(JSON.stringify(r.cliIntents))||checkpoint.privateHistoryRefsSha256!==sha256(JSON.stringify(r.privateHistoryRefs))
  ||checkpoint.finalScanStartedSha256!==sha256(JSON.stringify(r.finalScanStarted))||JSON.stringify(checkpoint.evidence)!==JSON.stringify(handoff?.evidence))throw Error('M8_SCAN_CONTINUATION_JOURNAL_CHANGED');
}
if(handoff?.version!==1||handoff.phase!=='ready'||handoff.testTag!==r.testTag||!continuation&&r.finalScanStarted||r.phase!=='cleanup-complete'||r.inFlight!==null
 ||r.requests.some((p,i)=>!['response_observed','succeeded'].includes(p.state)&&!isM8ProvenConsumedUnknownDownload(r,p,i))||r.proxyChecks.some(p=>p.state==='response_unknown')
 ||r.cliIntents.some((p,i)=>p.state!=='response_observed'&&!(i===4&&sha256(JSON.stringify(p))===M8_DECK_SET_CHECKPOINT.cliSha256&&isM8ProvenSetUnknownSyncClosurePacket(r,r.requests[r.deckSetContinuation.abandonAttempt.index],r.deckSetContinuation.abandonAttempt.index)))||!r.httpAcceptanceComplete||!r.deckAcceptance||!r.rbacAcceptance||!r.cleanup?.businessCompleted
 ||r.c2ModeChanged&&r.c2ModeRestored!==true)throw Error('M8_FINAL_UNKNOWN_OR_INCOMPLETE');
function safeRead(path,max){const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const s=fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size>max)throw Error('M8_SCAN_FILE_INVALID');return readFileSync(fd);}finally{closeSync(fd);}}
const evidence={};
for(const name of['http','manual','cleanup']){
 const spec=handoff.evidence?.[name];if(!/^artifacts\/M8\/[a-zA-Z0-9-]+\.json$/.test(spec?.path??'')||!/^[a-f\d]{64}$/.test(spec?.sha256??''))throw Error('M8_FINAL_EVIDENCE_BINDING_REQUIRED');
 const bytes=safeRead(spec.path,16*1024*1024);if(sha256(bytes)!==spec.sha256)throw Error('M8_FINAL_EVIDENCE_CHANGED');const report=JSON.parse(bytes);
 if(report.allPassed!==true||report.failed!==0||report.testTag!==r.testTag)throw Error('M8_FINAL_EVIDENCE_NOT_GREEN');evidence[name]=report;
}
if(evidence.http.actualM8Complete!==true||evidence.cleanup.auditWriteCoverage?.allCovered!==true
 ||evidence.cleanup.auditWriteCoverage.coveredWrites!==evidence.cleanup.auditWriteCoverage.successfulWrites+evidence.cleanup.auditWriteCoverage.recoveredSuccessfulCommits+(evidence.cleanup.auditWriteCoverage.serverConsumedDeliveryUnconfirmedWrites??0)
 ||!Array.isArray(evidence.manual.plannedActions)||evidence.manual.plannedActions.length!==12||evidence.manual.successfulUiWrites!==12
 ||evidence.manual.unknownUiWrites!==0||r.manualUiJournal?.phase!=='complete'||r.manualUiJournal?.attempts?.length!==12
 ||r.manualUiJournal.attempts.some(p=>p.state!=='succeeded'))throw Error('M8_FINAL_ACTUAL_COVERAGE_REQUIRED');
if(continuation)r.finalScanContinuationStarted={version:1,at:new Date().toISOString(),evidence:handoff.evidence,originalFailedScanSha256:'9463d92940ce03477ac7bfd2f01d03890bae17bbdc0cf1d4a91c3c5b375bf727'};
else r.finalScanStarted={version:1,at:new Date().toISOString(),evidence:handoff.evidence};durableJson(M8_REFERENCE,r);
let report;
try{
 const histories=readM8PrivateHistories(r),collected=m8CapturedSecrets(r,histories),values=[...collected.values],environmentFiles=readdirSync('.').filter(name=>/^\.env(?:\.[a-zA-Z\d.-]+)?$/.test(name)&&!/(?:example|sample|template)$/.test(name));
 for(const path of environmentFiles){const env=parseEnv(safeRead(path,1024*1024).toString());values.push(...collectEnvironmentSecrets(Object.fromEntries(Object.entries(env).filter(([name])=>!/(?:_FILE|_PATH)$/.test(name)))));}
 const walk=directory=>!existsSync(directory)?[]:readdirSync(directory,{withFileTypes:true}).flatMap(e=>{const p=join(directory,e.name);if(e.isSymbolicLink())throw Error('M8_SCAN_SYMLINK_REJECTED');return e.isDirectory()?walk(p):e.isFile()?[p]:[];});
 let protectedMaterialFiles=0;
 for(const path of walk('deploy/private/metrics').filter(p=>p.endsWith('.token'))){values.push(safeRead(path,16384).toString().trim());protectedMaterialFiles++;}
 const collector='deploy/private/metrics/collector/credentials.json';if(existsSync(collector)){const v=JSON.parse(safeRead(collector,1024*1024));if(!Array.isArray(v.clusters))throw Error('M8_METRICS_PROVIDER_CAPTURE_INVALID');for(const row of v.clusters){if(typeof row.catalogToken!=='string'||!row.catalogToken)throw Error('M8_METRICS_PROVIDER_CAPTURE_INVALID');values.push(row.catalogToken);}protectedMaterialFiles++;}
 for(const path of walk('deploy/private/event-delivery').filter(p=>p.endsWith('.key'))){const key=safeRead(path,32768).toString();if(!/-----BEGIN (?:RSA |EC |)PRIVATE KEY-----/.test(key))throw Error('M8_PROVIDER_KEY_CAPTURE_INVALID');values.push(key);protectedMaterialFiles++;}
 const materials='deploy/private/event-delivery/test-only-materials.json';if(existsSync(materials)){const v=JSON.parse(safeRead(materials,65536));if(v.testOnly!==true||!Array.isArray(v.secrets))throw Error('M8_PROVIDER_CAPTURE_INVALID');values.push(...v.secrets,v.httpBearer,v.httpBasic?.password,v.smtp?.password);for(const pair of[v.httpBasic,v.smtp])if(typeof pair?.username==='string'&&typeof pair.password==='string')values.push(Buffer.from(`${pair.username}:${pair.password}`).toString('base64'),Buffer.from(`\0${pair.username}\0${pair.password}`).toString('base64'));protectedMaterialFiles++;}
 const old='/tmp/kongos-m5-runtime-secrets.json';if(existsSync(old)){const s=lstatSync(old);if(s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.isSymbolicLink())throw Error('M8_PROTECTED_TELEMETRY_CAPTURE_INVALID');const v=JSON.parse(safeRead(old,2*1024*1024));if(!Array.isArray(v.secrets)||!Array.isArray(v.tokens))throw Error('M8_PROTECTED_TELEMETRY_CAPTURE_INVALID');values.push(...v.secrets);for(const row of v.tokens){values.push(row.token);if(row.purpose==='collector_ingest')values.push(Buffer.from(`kongos:${row.token}`).toString('base64'));}protectedMaterialFiles++;}
 const secrets=m8SecretForms(values),source=execFileSync('git',['ls-files','-z','--cached','--others','--exclude-standard'],{encoding:'utf8'}).split('\0').filter(Boolean);
 const compiled=['apps/console-api/dist','apps/console-web/dist','apps/portal-web/dist','packages/contracts/dist'].flatMap(walk),extra=['test-results','playwright-report','artifacts/playwright-results','artifacts/playwright-report'].flatMap(walk);
 const scan=findSecretArtifacts(secrets,[...source,...compiled,...extra]);
 const since=r.requests[0]?.startedAt;if(!Number.isFinite(Date.parse(since)))throw Error('M8_ORIGINAL_LOG_START_REQUIRED');
 const environment={...process.env};for(const name of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete environment[name];
 const docker=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:environment,encoding:'utf8',timeout:15000,maxBuffer:65536});
 const api=docker([...M8_COMPOSE,'ps','-q','console-api']).trim();if(!/^[a-f\d]{64}$/.test(api))throw Error('M8_LOG_API_IDENTITY_INVALID');
 const project=docker(['inspect','-f','{{index .Config.Labels "com.docker.compose.project"}}',api]).trim();if(!/^[a-zA-Z\d_-]{1,100}$/.test(project))throw Error('M8_LOG_PROJECT_INVALID');
 const services=docker(['ps','--filter',`label=com.docker.compose.project=${project}`,'--format','{{.Label "com.docker.compose.service"}}']).trim().split('\n').filter(Boolean);
 if(M8_LOG_SERVICES.some(name=>!services.includes(name))||new Set(services).size!==services.length||services.length>32)throw Error('M8_COMPLETE_SERVICE_LOG_SET_REQUIRED');
 const runtimeLogs=[];
 for(const service of services){if(!/^[a-zA-Z\d_-]{1,100}$/.test(service))throw Error('M8_LOG_SERVICE_INVALID');const ids=docker(['ps','--filter',`label=com.docker.compose.project=${project}`,'--filter',`label=com.docker.compose.service=${service}`,'--format','{{.ID}}']).trim().split('\n').filter(Boolean);if(ids.length!==1)throw Error('M8_LOG_SERVICE_IDENTITY_INVALID');const log=spawnSync('docker',['--host=unix:///var/run/docker.sock','logs','--since',since,ids[0]],{env:environment,encoding:'utf8',timeout:15000,maxBuffer:32*1024*1024});if(log.status!==0||log.error)throw Error('M8_LOG_COLLECTION_FAILED');const text=`${log.stdout??''}${log.stderr??''}`;runtimeLogs.push({service,freshStdoutAndStderr:true,knownSecretDetected:secrets.some(v=>text.includes(v))});}
 report={performedAt:new Date().toISOString(),milestone:'M8',testTag:r.testTag,allPassed:scan.leaks.length===0&&runtimeLogs.every(v=>!v.knownSecretDetected),...scan,compiledFiles:compiled.length,additionalReportFiles:extra.length,
  historyCount:histories.length,currentAndAllHistoricalSecretsIncluded:true,rawDeploymentYAMLSecretsIncluded:true,base64AndEscapedFormsIncluded:true,classifiedPublic:collected.classifiedPublic,
  originalFailuresAndBlockedMaterialsIncluded:true,environmentFiles:environmentFiles.length,protectedMaterialFiles,runtimeLogs,logsSince:since,rawLogsPublished:false,secretsPublished:false,
  protectedProductionMaterialsRetained:true,privateReferenceRemoved:false,ephemeralPrivateMaterialsRemoved:false};
}catch{report={performedAt:new Date().toISOString(),milestone:'M8',testTag:r.testTag,allPassed:false,failureClassification:'FINAL_SCAN_INCOMPLETE_PRIVATE_RETAINED',privateReferenceRemoved:false,rawLogsPublished:false,secretsPublished:false};}
const path=continuation?'artifacts/M8/runtime-secret-artifact-scan-provenance-corrected.json':'artifacts/M8/runtime-secret-artifact-scan.json';
if(continuation)Object.assign(report,{originalFailedScanRetained:true,originalFailedScanSha256:'9463d92940ce03477ac7bfd2f01d03890bae17bbdc0cf1d4a91c3c5b375bf727',noNewBusinessRequests:true});
durableJson(path,report,0o644,true);
if(report.allPassed){
 try{
  readM8PrivateHistories(r);
  if(!/^\/tmp\/kongos-m8-pem-[a-zA-Z\d]+$/.test(r.pemDirectory??''))throw Error('M8_PEM_EPHEMERAL_PATH_INVALID');const s=lstatSync(r.pemDirectory);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700)throw Error('M8_PEM_EPHEMERAL_IDENTITY_INVALID');
  for(const name of readdirSync(r.pemDirectory)){if(!['key.pem','cert.pem'].includes(name))throw Error('M8_PEM_EPHEMERAL_UNEXPECTED_FILE');const f=lstatSync(join(r.pemDirectory,name));if(!f.isFile()||f.isSymbolicLink()||f.uid!==process.getuid())throw Error('M8_PEM_EPHEMERAL_IDENTITY_INVALID');}
  rmSync(r.pemDirectory,{recursive:true});for(const ref of r.privateHistoryRefs??[])rmSync(join(M8_HISTORY_DIRECTORY,ref.file));rmdirSync(M8_HISTORY_DIRECTORY);rmSync(M8_REFERENCE);
  report.privateReferenceRemoved=!existsSync(M8_REFERENCE);report.ephemeralPrivateMaterialsRemoved=true;
 }catch{report.allPassed=false;report.privateRemovalFailed=true;report.privateReferenceRemoved=!existsSync(M8_REFERENCE);}
 durableJson(path,report,0o644);
}
console.log(JSON.stringify({allPassed:report.allPassed,scannedFiles:report.scannedFiles??0,leakCount:report.leaks?.length??null,freshLogServices:report.runtimeLogs?.length??0,privateReferenceRemoved:report.privateReferenceRemoved}));process.exitCode=report.allPassed?0:1;
