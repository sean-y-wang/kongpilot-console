#!/usr/bin/env node
/** Source quality CI. It does not deploy, contact a real gateway, or upload raw logs/builds/evidence. */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PCRE1_RELEASE } from './prepare-pcre1-engine.mjs';
import { checkedToolDirectory, DECK_TEST_TOOLCHAIN } from './prepare-test-toolchain.mjs';
const fail=code=>{throw new Error(code);};const sha=value=>createHash('sha256').update(value).digest('hex');
const MAX_STREAM=4*1024*1024,MAX_REPORT=128*1024*1024;
export const QUALITY_STAGES=Object.freeze([
 {id:'install',command:'npm',args:['ci','--no-audit','--no-fund']},
 {id:'toolchain',command:'node',args:['deploy/scripts/prepare-test-toolchain.mjs']},
 {id:'browser',command:'node',args:['node_modules/playwright/cli.js','install','--with-deps','chromium','--only-shell']},
 {id:'pcre1',command:'node',args:['deploy/scripts/prepare-pcre1-ci.mjs']},
 {id:'tests',command:'npm',args:['test','--','--maxWorkers=2','--reporter=json']},
 ...['api','web','portal-web'].map(name=>({id:`typecheck-${name}`,command:'npm',args:['run','typecheck','-w',`@kongpilot/${name}`]})),
 ...['api','web','portal-web'].map(name=>({id:`build-${name}`,command:'npm',args:['run','build','-w',`@kongpilot/${name}`]})),
 {id:'production-dependency-audit',command:'npm',args:['audit','--omit=dev','--json']},
].map(stage=>Object.freeze({...stage,args:Object.freeze(stage.args)})));
export function qualityEnvironment(parent,privateHome,privateTmp){const result={PATH:parent.PATH??'/usr/local/bin:/usr/bin:/bin',HOME:privateHome,TMPDIR:privateTmp,CI:'true',TZ:'UTC',LANG:'C.UTF-8',NPM_CONFIG_USERCONFIG:join(privateHome,'.npmrc'),NPM_CONFIG_GLOBALCONFIG:join(privateHome,'global.npmrc'),NPM_CONFIG_CACHE:join(privateHome,'npm-cache'),NPM_CONFIG_UPDATE_NOTIFIER:'false'};return result;}
export async function boundedQualityCommand(command,args,{cwd,env,timeoutMs=15*60*1000}={}){
 const stdout=[],stderr=[];let outBytes=0,errBytes=0,outputLimitReached=false,timedOut=false,spawnFailed=false,terminationFailed=false,termination;
 const grouped=process.platform==='linux',child=spawn(command,args,{cwd,env,shell:false,detached:grouped,stdio:['ignore','pipe','pipe']});
 const signalOwnGroup=signal=>{try{if(grouped&&Number.isInteger(child.pid)&&child.pid>1)process.kill(-child.pid,signal);else if(child.pid)child.kill(signal);}catch(error){if(error.code!=='ESRCH')terminationFailed=true;}};
 const stop=()=>{if(termination)return;signalOwnGroup('SIGTERM');termination=new Promise(done=>setTimeout(()=>{signalOwnGroup('SIGKILL');done();},1000));};
 const timer=setTimeout(()=>{timedOut=true;stop();},timeoutMs);
 const accept=(target,isError,chunk)=>{if(isError)errBytes+=chunk.length;else outBytes+=chunk.length;if((isError?errBytes:outBytes)>MAX_STREAM){outputLimitReached=true;stop();return;}target.push(chunk);};
 child.stdout.on('data',chunk=>accept(stdout,false,chunk));child.stderr.on('data',chunk=>accept(stderr,true,chunk));
 let code=null,signal=null;try{[code,signal]=await new Promise(ok=>{child.once('error',()=>{spawnFailed=true;ok([null,null]);});child.once('close',(code,signal)=>ok([code,signal]));});}finally{clearTimeout(timer);if(termination)await termination;}
 return{exitCode:code,signal,spawnFailed,timedOut,outputLimitReached,terminationFailed,stdout:Buffer.concat(stdout),stderr:Buffer.concat(stderr),stdoutBytes:outBytes,stderrBytes:errBytes};
}
function privateFile(path,bytes){const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}}
function parsedFile(path,max=MAX_REPORT){const s=lstatSync(path);if(s.isSymbolicLink()||!s.isFile()||s.size>max)fail('CI_QUALITY_PRIVATE_REPORT_INVALID');try{return JSON.parse(readFileSync(path,'utf8'));}catch{fail('CI_QUALITY_PRIVATE_REPORT_INVALID');}}
function count(value){if(!Number.isSafeInteger(value)||value<0)fail('CI_QUALITY_COUNT_INVALID');return value;}
export function safeTestTotals(raw){const result={total:count(raw.numTotalTests),passed:count(raw.numPassedTests),failed:count(raw.numFailedTests),skipped:count(raw.numPendingTests),todo:count(raw.numTodoTests??0),failedSuites:count(raw.numFailedTestSuites),totalSuites:count(raw.numTotalTestSuites)};const countsConsistent=result.total===result.passed+result.failed+result.skipped+result.todo;return{...result,countsConsistent,passedWithoutSkippedTests:countsConsistent&&result.passed===result.total&&raw.success===true&&result.total>0&&result.passed>0&&result.failed===0&&result.skipped===0&&result.todo===0&&result.failedSuites===0&&result.totalSuites>0};}
// Only repository-owned paths and integer source positions can leave the private
// Vitest report. Test names, messages, diffs, stack text and values stay private.
export function safeTestDiagnostics(raw,repository){
 const repo=resolve(repository),known=new Map();
 const visit=(directory,depth=0)=>{if(depth>12||known.size>=4096)return;let entries;try{const s=lstatSync(directory);if(s.isSymbolicLink()||!s.isDirectory())return;entries=readdirSync(directory,{withFileTypes:true});}catch{return;}for(const entry of entries){const path=join(directory,entry.name);if(entry.isSymbolicLink())continue;if(entry.isDirectory())visit(path,depth+1);else if(entry.isFile()){const name=relative(repo,path).split('\\').join('/');if(/^tests\/(?:unit|security)\/[A-Za-z0-9_./-]+\.test\.ts$/.test(name)&&!name.split('/').includes('..')){const s=lstatSync(path);if(!s.isSymbolicLink()&&s.isFile()&&s.size<=2*1024*1024)known.set(name,{path,lines:readFileSync(path,'utf8').split('\n').length});}}}};
 for(const scope of ['unit','security'])visit(join(repo,'tests',scope));
 const files=[],seen=new Set();let failedFiles=0,unmappedFailedFiles=0;
 for(const suite of Array.isArray(raw?.testResults)?raw.testResults:[]){
  const assertions=Array.isArray(suite?.assertionResults)?suite.assertionResults:[],failed=assertions.filter(a=>a?.status==='failed');if(suite?.status!=='failed'&&failed.length===0)continue;failedFiles++;
  const name=typeof suite.name==='string'?relative(repo,resolve(repo,suite.name)).split('\\').join('/'):null,source=known.get(name);if(!source||seen.has(name)){unmappedFailedFiles++;continue;}seen.add(name);if(files.length>=32)continue;
  const categories={},lines=new Set(),escaped=source.path.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),position=new RegExp(escaped+':([0-9]{1,6}):([0-9]{1,5})','g');
  for(const assertion of failed){const messages=Array.isArray(assertion.failureMessages)?assertion.failureMessages.filter(v=>typeof v==='string').join('\n'):'';const text=messages.slice(0,256*1024);const category=/\b(?:Test|Hook) timed out\b|TimeoutError|timed out in/i.test(text)?'timeout':/\b(?:EACCES|EPERM)\b/.test(text)?'filesystem-permission':/\bENOENT\b/.test(text)?'missing-file':/Cannot find module|ERR_MODULE_NOT_FOUND/.test(text)?'module-resolution':/Snapshot|toMatchSnapshot/.test(text)?'snapshot':/AssertionError|expected .+ to /i.test(text)?'assertion':'other';categories[category]=(categories[category]??0)+1;for(const match of text.matchAll(position)){const line=Number(match[1]);if(line>0&&line<=source.lines&&lines.size<8)lines.add(line);}}
  files.push({file:name,failedAssertions:failed.length,categories,sourceLines:[...lines].sort((a,b)=>a-b)});
 }
 return{failedFiles,unmappedFailedFiles,omittedFiles:Math.max(0,failedFiles-unmappedFailedFiles-files.length),files:files.sort((a,b)=>a.file.localeCompare(b.file)),rawMessagesIncluded:false,testNamesIncluded:false};
}
export function safeAuditTotals(raw){const values=raw?.metadata?.vulnerabilities;if(!values)fail('CI_QUALITY_AUDIT_REPORT_INVALID');const counts=Object.fromEntries(['info','low','moderate','high','critical','total'].map(name=>[name,count(values[name])]));return{...counts,knownProductionDependencyVulnerabilities:counts.total,passed:counts.total===0&&['info','low','moderate','high','critical'].every(k=>counts[k]===0),scope:'npm-production-dependencies-only',containerOrOperatingSystemScanExecuted:false};}
/** Optional CI shard "i/n" (1<=i<=n<=8). Coverage is preserved by the merge
 * job, which requires every shard and compares the summed total to the
 * unsharded `vitest list` inventory. */
export function qualityTestShard(value){if(value===undefined||value==='')return undefined;const m=/^([1-8])\/([1-8])$/.exec(String(value));if(!m||Number(m[1])>Number(m[2]))fail('CI_QUALITY_TEST_SHARD_INVALID');return Object.freeze({index:Number(m[1]),count:Number(m[2])});}
export function shardTestFiles(raw,repo){const rows=raw?.testResults;if(!Array.isArray(rows))fail('CI_QUALITY_TEST_FILES_INVALID');const root=resolve(repo)+'/';return rows.map(r=>{const n=String(r?.name??'');if(!n.startsWith(root))fail('CI_QUALITY_TEST_FILES_INVALID');return n.slice(root.length);}).sort();}
export async function runQuality({repository=process.cwd(),privateRoot,reportDirectory,run=boundedQualityCommand,runtimeVersion=process.version,parentEnvironment=process.env}={}){
 const repo=checkedToolDirectory(repository),work=privateRoot?checkedToolDirectory(privateRoot):mkdtempSync(join(tmpdir(),'kongpilot-quality-private-'));chmodSync(work,0o700);
 const reportDir=checkedToolDirectory(reportDirectory??join(process.env.RUNNER_TEMP??tmpdir(),'kongpilot-quality-report'),{create:true}),summaryPath=join(reportDir,'summary.json');if(existsSync(summaryPath))fail('CI_QUALITY_NEW_REPORT_REQUIRED');
 const shard=qualityTestShard(parentEnvironment.KONGPILOT_TEST_SHARD);
 const summary={schemaVersion:1,testShard:shard??null,completed:false,allPassed:false,scope:'unit-security-typecheck-build-production-dependencies',nodeVersion:runtimeVersion,lockfileUnchanged:false,stages:[],realKongIntegrationExecuted:false,browserE2eExecuted:false,restoreExecuted:false,productionDeploymentExecuted:false,commercialAcceptance:false,rawLogsUploaded:false,buildOutputsUploaded:false,externalCredentialsForwarded:false};
 try{
  const pinned=readFileSync(join(repo,'.node-version'),'utf8').trim();if(!/^22\.\d+\.\d+$/.test(pinned)||runtimeVersion!==`v${pinned}`)fail('CI_QUALITY_PINNED_NODE22_REQUIRED');
  const before=sha(readFileSync(join(repo,'package-lock.json'))),home=join(work,'home'),privateTmp=join(work,'tmp');mkdirSync(home,{mode:0o700});mkdirSync(privateTmp,{mode:0o700});privateFile(join(home,'.npmrc'),'');privateFile(join(home,'global.npmrc'),'');const env=qualityEnvironment(parentEnvironment,home,privateTmp);let installed=false,toolReady=false,pcreReady=false,browserReady=false;
  for(const stage of QUALITY_STAGES){
   if(stage.id!=='install'&&!installed||stage.id==='tests'&&(!toolReady||!pcreReady||!browserReady)){summary.stages.push({id:stage.id,status:'blocked',exitCode:null,reason:!installed?'install-not-passed':!toolReady?'fixed-toolchain-not-passed':!pcreReady?'fixed-pcre1-security-not-passed':'fixed-browser-not-passed'});continue;}
   const args=[...stage.args];if(stage.id==='tests'){args.push(`--outputFile=${join(work,'vitest.raw.json')}`);if(shard)args.push(`--shard=${shard.index}/${shard.count}`);}
   const started=Date.now();const result=await run(stage.command,args,{cwd:repo,env});const safe={id:stage.id,status:'failed',exitCode:Number.isInteger(result.exitCode)?result.exitCode:null,timedOut:result.timedOut===true,outputLimitReached:result.outputLimitReached===true,spawnFailed:result.spawnFailed===true,terminationFailed:result.terminationFailed===true,elapsedMs:Math.max(0,Date.now()-started),stdoutBytes:count(result.stdoutBytes??result.stdout?.length??0),stderrBytes:count(result.stderrBytes??result.stderr?.length??0)};
   privateFile(join(work,`${stage.id}.stdout.raw`),result.stdout??Buffer.alloc(0));privateFile(join(work,`${stage.id}.stderr.raw`),result.stderr??Buffer.alloc(0));
   let passed=safe.exitCode===0&&!safe.timedOut&&!safe.outputLimitReached&&!safe.spawnFailed&&!safe.terminationFailed;
   try{
    if(stage.id==='toolchain'){const parsed=JSON.parse(result.stdout.toString('utf8'));toolReady=passed&&parsed.completed===true&&parsed.binaryVerified===true&&parsed.credentialsUsed===false&&parsed.version===DECK_TEST_TOOLCHAIN.version&&parsed.binarySha256===DECK_TEST_TOOLCHAIN.binarySha256;passed=toolReady;safe.toolchain={version:DECK_TEST_TOOLCHAIN.version,binarySha256:DECK_TEST_TOOLCHAIN.binarySha256,verified:toolReady};}
    if(stage.id==='pcre1'){const p=JSON.parse(result.stdout.toString('utf8'));pcreReady=passed&&p.format==='kongpilot-pcre1-ci-v1'&&p.completed===true&&p.credentialsUsed===false&&p.kongContacted===false&&p.version===PCRE1_RELEASE.version&&p.archiveSha256===PCRE1_RELEASE.sha256&&p.jit===false&&/^[a-f0-9]{64}$/.test(p.binarySha256)&&p.nativeSandbox?.tests===15&&p.nativeSandbox?.passed===15&&p.nativeSandbox?.failed===0&&p.nativeSandbox?.skipped===0&&p.nativeSandbox?.actualExit===0;passed=pcreReady;safe.pcre1={version:PCRE1_RELEASE.version,archiveSha256:PCRE1_RELEASE.sha256,binarySha256:typeof p.binarySha256==='string'&&/^[a-f0-9]{64}$/.test(p.binarySha256)?p.binarySha256:null,nativeSandboxTests:15,verified:pcreReady};}
    if(stage.id==='tests'){const report=parsedFile(join(work,'vitest.raw.json'));safe.tests=safeTestTotals(report);safe.testDiagnostics=safeTestDiagnostics(report,repo);if(shard)safe.testFiles=shardTestFiles(report,repo);passed=passed&&safe.tests.passedWithoutSkippedTests;}
    if(stage.id==='production-dependency-audit'){safe.audit=safeAuditTotals(JSON.parse(result.stdout.toString('utf8')));passed=passed&&safe.audit.passed;}
   }catch{safe.summaryInvalid=true;passed=false;}
   safe.status=passed?'passed':'failed';summary.stages.push(safe);if(stage.id==='install')installed=passed;if(stage.id==='browser')browserReady=passed;
  }
  summary.lockfileUnchanged=sha(readFileSync(join(repo,'package-lock.json')))===before;summary.completed=true;summary.allPassed=summary.lockfileUnchanged&&summary.stages.length===QUALITY_STAGES.length&&summary.stages.every(s=>s.status==='passed');
 }catch(error){summary.failureCode=/^CI_QUALITY_[A-Z0-9_]+$/.test(error?.message??'')?error.message:'CI_QUALITY_PRIVATE_FAILURE';}
 privateFile(summaryPath,JSON.stringify(summary,null,2)+'\n');return summary;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==2){process.stderr.write('{"allPassed":false,"failureCode":"CI_QUALITY_ARGUMENTS_FORBIDDEN"}\n');process.exitCode=1;}
 else runQuality().then(summary=>{process.stdout.write(JSON.stringify(summary)+'\n');if(!summary.allPassed)process.exitCode=1;}).catch(()=>{process.stderr.write('{"allPassed":false,"failureCode":"CI_QUALITY_PRIVATE_FAILURE"}\n');process.exitCode=1;});
}
