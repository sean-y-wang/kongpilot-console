#!/usr/bin/env node
/** Public fixed native build/security prerequisite; no real gateway or external credential. */
import {createHash} from 'node:crypto';
import {lstatSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {downloadPcre1,preparePcre1,PCRE1_RELEASE} from './prepare-pcre1-engine.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),fail=code=>{throw Error(code);};
export async function boundedPcre1SecurityCommand(args,{cwd,run=spawn,timeoutMs=60000}={}){
 if(!Number.isFinite(timeoutMs)||timeoutMs<=0||timeoutMs>60000)fail('PCRE_CI_SECURITY_DEADLINE_INVALID');
 const child=run('/usr/bin/python3',args,{cwd,env:{PATH:process.env.PATH??'/usr/local/bin:/usr/bin:/bin',LANG:'C',TZ:'UTC'},shell:false,detached:process.platform==='linux',stdio:['ignore','pipe','pipe']});
 const chunks=[[],[]];let sizes=[0,0],limited=false,timed=false,failed=false;const stop=()=>{try{if(process.platform==='linux'&&Number.isInteger(child.pid)&&child.pid>1)process.kill(-child.pid,'SIGKILL');else if(child.pid)child.kill('SIGKILL');}catch(e){if(e.code!=='ESRCH')failed=true;}};
 const timer=setTimeout(()=>{timed=true;stop();},timeoutMs);for(const [n,stream]of[child.stdout,child.stderr].entries())stream.on('data',chunk=>{sizes[n]+=chunk.length;if(sizes[n]>2*1024*1024){limited=true;stop();return;}chunks[n].push(chunk);});
 let code=null,signal=null;try{[code,signal]=await new Promise(done=>{child.once('error',()=>{failed=true;done([null,null]);});child.once('close',(c,s)=>done([c,s]));});}finally{clearTimeout(timer);}
 return{exitCode:code,signal,limited,timed,failed,stdout:Buffer.concat(chunks[0]),stderr:Buffer.concat(chunks[1])};
}
export async function preparePcre1Ci({repository=resolve(fileURLToPath(new URL('../../',import.meta.url))),download=downloadPcre1,prepare=preparePcre1,runSecurity=boundedPcre1SecurityCommand}={}){
 const work=mkdtempSync(join(tmpdir(),'kongpilot-pcre1-ci-private-')),archivePath=join(work,'pcre-8.45.tar.gz'),report=join(work,'native-sandbox-original.json');
 const archive=await download();if(!Buffer.isBuffer(archive)||archive.length>4*1024*1024||sha(archive)!==PCRE1_RELEASE.sha256)fail('PCRE_CI_FIXED_ARCHIVE_INVALID');writeFileSync(archivePath,archive,{mode:0o600});
 const built=await prepare({directory:join(repository,'apps/console-api/native-bin'),archiveFile:archivePath});if(built.completed!==true||built.version!==PCRE1_RELEASE.version||built.archiveSha256!==PCRE1_RELEASE.sha256||built.jit!==false||!/^[a-f0-9]{64}$/.test(built.binarySha256)||!/^[a-f0-9]{64}$/.test(built.helperSourceSha256))fail('PCRE_CI_BUILD_PROOF_INVALID');
 const child=await runSecurity(['tests/security/m9-pcre1-sandbox.test.py','--archive',archivePath,'--report-file',report],{cwd:repository});writeFileSync(join(work,'native-sandbox-stdout-original.raw'),child.stdout??Buffer.alloc(0),{mode:0o600});writeFileSync(join(work,'native-sandbox-stderr-original.raw'),child.stderr??Buffer.alloc(0),{mode:0o600});
 let tests;try{const st=lstatSync(report);if(!st.isFile()||st.isSymbolicLink()||st.size>16384)throw Error();tests=JSON.parse(readFileSync(report,'utf8'));}catch{fail('PCRE_CI_NATIVE_REPORT_INVALID');}
 if(child.exitCode!==0||child.signal||child.limited||child.timed||child.failed||tests.format!=='kongpilot-pcre1-native-sandbox-tests-v1'||tests.completed!==true||tests.tests!==15||tests.passed!==15||tests.failed!==0||tests.errors!==0||tests.skipped!==0||tests.actualExit!==0||tests.kongContacted!==false)fail('PCRE_CI_NATIVE_SECURITY_FAILED');
 return{format:'kongpilot-pcre1-ci-v1',completed:true,version:PCRE1_RELEASE.version,archiveSha256:PCRE1_RELEASE.sha256,binarySha256:built.binarySha256,helperSourceSha256:built.helperSourceSha256,jit:false,nativeSandbox:{tests:15,passed:15,failed:0,skipped:0,actualExit:0},credentialsUsed:false,kongContacted:false,dockerExecuted:false,realKongRecordedCorpus:false};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==2){process.stderr.write('{"completed":false,"code":"PCRE_CI_ARGUMENTS_FORBIDDEN"}\n');process.exitCode=1;}
 else preparePcre1Ci().then(v=>process.stdout.write(JSON.stringify(v)+'\n')).catch(e=>{process.stderr.write(JSON.stringify({completed:false,code:/^(PCRE_CI|PCRE_BUILD)_[A-Z0-9_]+$/.test(e?.message??'')?e.message:'PCRE_CI_PRIVATE_FAILURE'})+'\n');process.exitCode=1;});
}
