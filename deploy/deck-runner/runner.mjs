import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {chmodSync,closeSync,constants,fstatSync,mkdtempSync,openSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const DECK_BINARY_SHA256='642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed';
const UUID=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const fail=()=>new Error('DECK_RUNNER_INPUT_INVALID');
export function runnerInput(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype&&Object.getPrototypeOf(value)!==null||Object.keys(value).some(k=>!['command','sessionId','tokenSecret','stateYaml'].includes(k)))throw fail();
 if(!['validate','dump','diff','sync'].includes(value.command))throw fail();
 if(value.command!=='validate'&&(typeof value.sessionId!=='string'||typeof value.tokenSecret!=='string'||!UUID.test(value.sessionId)||! /^[A-Za-z\d_-]{43}$/.test(value.tokenSecret)))throw fail();
 if(value.command==='validate'&&(value.sessionId!==undefined||value.tokenSecret!==undefined))throw fail();
 if(value.command==='dump'&&value.stateYaml!==undefined||value.command!=='dump'&&(typeof value.stateYaml!=='string'||!value.stateYaml.length||Buffer.byteLength(value.stateYaml)>8*1024*1024))throw fail();
 return value;
}
export function consoleOrigin(value,allowLocalTestBff=false){
 try{const u=new URL(value);if(u.username||u.password||u.pathname!=='/'||u.search||u.hash||!['http:','https:'].includes(u.protocol))throw fail();
  const internal=u.protocol==='http:'&&u.hostname==='console-web'&&u.port==='8080';
  const local=allowLocalTestBff&&u.protocol==='http:'&&['127.0.0.1','localhost'].includes(u.hostname)&&Number(u.port)>0;
  if(!internal&&!local&&u.protocol!=='https:')throw fail();return u.origin;
 }catch{throw fail();}
}
export function deckEnvironment(env){
 const result={};for(const key of ['PATH','HOME','LANG','LC_ALL','HTTP_PROXY','HTTPS_PROXY','NO_PROXY','http_proxy','https_proxy','no_proxy','SSL_CERT_FILE','SSL_CERT_DIR'])if(typeof env[key]==='string')result[key]=env[key];
 // Viper automatically overrides config from every DECK_* variable. Nothing
 // from the parent may select a host, header, workspace, verbose or TLS bypass.
 result.DECK_ANALYTICS='off';return result;
}
function binaryDescriptor(path){const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let bytes;try{const stat=fstatSync(fd);if(!stat.isFile()||stat.nlink!==1||stat.size>64*1024*1024||stat.size<1||(stat.mode&0o022)!==0)throw fail();bytes=readFileSync(fd);if(createHash('sha256').update(bytes).digest('hex')!==DECK_BINARY_SHA256)throw fail();return fd;}catch{closeSync(fd);throw new Error('DECK_RUNNER_TOOLCHAIN_INVALID');}finally{bytes?.fill(0);}}

/** Fixed official executable, private config/state, bounded output in RAM only.
 * The trusted caller must encrypt/persist any needed output then call dispose.
 * This safe result never implies that the BFF configuration job succeeded. */
export async function runDeck(raw,{binaryPath='/usr/local/bin/deck',origin='http://console-web:8080',allowLocalTestBff=false,environment=process.env,timeoutMs=120000}={}){
 const input=runnerInput(raw);if(!Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>120000)throw fail();
 const address=input.command==='validate'?'http://127.0.0.1:9':consoleOrigin(origin,allowLocalTestBff)+'/api/v1/deck/'+input.sessionId;
 let directory,descriptor;try{
  descriptor=binaryDescriptor(binaryPath);directory=mkdtempSync(resolve(tmpdir(),'kongos-deck-'));chmodSync(directory,0o700);
  const config=resolve(directory,'config.json'),state=resolve(directory,'state.yaml');
  writeFileSync(config,JSON.stringify({'kong-addr':address,'headers':input.command==='validate'?[]:['Authorization: KongOS-Deck '+input.tokenSecret],'tls-skip-verify':false,verbose:0,'no-color':true}),{mode:0o600,flag:'wx'});
  if(input.stateYaml!==undefined)writeFileSync(state,input.stateYaml,{mode:0o600,flag:'wx'});
  const args=['--config',config,'--verbose','0','--tls-skip-verify=false','--no-color',input.command];
  if(input.command==='dump')args.push('--output-file','-');else args.push('--state',state);
  if(['diff','sync'].includes(input.command))args.push('--parallelism','1');
  const stdout=[],stderr=[];let outBytes=0,errorBytes=0,limitReached=false,timedOut=false,killTimer;
  // Execute the verified open inode via inherited descriptor, not a writable
  // temporary executable or a path that can be swapped after verification.
  const child=spawn('/proc/self/fd/3',args,{cwd:directory,env:deckEnvironment(environment),shell:false,stdio:['ignore','pipe','pipe',descriptor]});
  const stop=()=>{child.kill('SIGTERM');if(!killTimer)killTimer=setTimeout(()=>child.kill('SIGKILL'),1000);};
  const timer=setTimeout(()=>{timedOut=true;stop();},timeoutMs);
  child.stdout.on('data',chunk=>{outBytes+=chunk.length;if(outBytes>32*1024*1024){chunk.fill(0);limitReached=true;stop();return;}stdout.push(chunk);});
  child.stderr.on('data',chunk=>{errorBytes+=chunk.length;if(errorBytes>2*1024*1024){chunk.fill(0);limitReached=true;stop();return;}stderr.push(chunk);});
  let exitCode,signal;try{[exitCode,signal]=await new Promise((ok,reject)=>{child.once('error',()=>reject(new Error('DECK_RUNNER_START_FAILED')));child.once('close',(code,sig)=>ok([code,sig]));});}catch{for(const chunk of [...stdout,...stderr])chunk.fill(0);throw new Error('DECK_RUNNER_START_FAILED');}finally{clearTimeout(timer);clearTimeout(killTimer);}
  const output=Buffer.concat(stdout),error=Buffer.concat(stderr);for(const chunk of [...stdout,...stderr])chunk.fill(0);
  return{safe:{toolVersion:'1.2.4',toolCommit:'8e68931',toolBinarySha256:DECK_BINARY_SHA256,command:input.command,exitCode,signal:signal??null,timedOut,outputLimitReached:limitReached,stdoutBytes:outBytes,stderrBytes:errorBytes,possibleUnknown:input.command==='sync'&&(exitCode!==0||timedOut||limitReached),consoleJobSuccessProved:false},stdout:output,stderr:error,dispose(){output.fill(0);error.fill(0);}};
 }finally{if(descriptor!==undefined)closeSync(descriptor);if(directory)rmSync(directory,{recursive:true,force:true});}
}
async function main(){
 let size=0;const chunks=[];for await(const chunk of process.stdin){size+=chunk.length;if(size>12*1024*1024)throw fail();chunks.push(chunk);}const body=Buffer.concat(chunks);let input;try{input=JSON.parse(body.toString('utf8'));}finally{body.fill(0);for(const chunk of chunks)chunk.fill(0);}
 const result=await runDeck(input,{origin:process.env.DECK_CONSOLE_ORIGIN??'http://console-web:8080'});try{process.stdout.write(JSON.stringify(result.safe)+'\n');if(result.safe.exitCode!==0||result.safe.timedOut||result.safe.outputLimitReached)process.exitCode=1;}finally{result.dispose();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{process.stderr.write('DECK_RUNNER_FAILED; no raw CLI output or credential values published.\n');process.exitCode=1;});
