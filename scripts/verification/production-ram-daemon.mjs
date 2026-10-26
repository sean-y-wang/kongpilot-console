import {spawn,execFileSync} from 'node:child_process';
import {mkdirSync,writeFileSync,readFileSync,existsSync,readlinkSync,statfsSync,rmSync,chmodSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {PUBLIC_TOOLS,validateRamGate,ramOptions} from './production-ram-policy.mjs';
import {startFixedTlsPassthrough} from './production-ram-tls-passthrough.mjs';
const STATUS='/run/daemon-readiness.json',STATE='/var/lib/kongos-docker';
const hash=value=>createHash('sha256').update(value).digest('hex');
const safe=error=>/^RAM_[A-Z0-9_]+$/.test(error?.message??'')?error.message:'RAM_PRIVATE_DAEMON_FAILED';
const environment=()=>{const env={...process.env,TMPDIR:STATE+'/tmp',DOCKER_CONFIG:'/root/.docker'};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];return env;};
const docker=args=>execFileSync(PUBLIC_TOOLS.docker,['--host=unix:///var/run/docker.sock',...args],{env:environment(),stdio:['pipe','pipe','pipe'],encoding:'utf8',timeout:10000,maxBuffer:65536});
export function overlayProbeCommands(root=STATE+'/overlay-probe'){
 if(root!==STATE+'/overlay-probe')throw new Error('RAM_OVERLAY_PROBE_PATH_INVALID');
 return {mount:['-t','overlay','overlay','-o',`lowerdir=${root}/lower,upperdir=${root}/upper,workdir=${root}/work`,root+'/merged'],unmount:[root+'/merged']};
}
function probeOverlay(){
 const root=STATE+'/overlay-probe',commands=overlayProbeCommands();mkdirSync(root,{mode:0o700});for(const name of ['lower','upper','work','merged'])mkdirSync(root+'/'+name,{mode:0o700});writeFileSync(root+'/lower/control','PUBLIC_OVERLAY_POSITIVE_CONTROL',{flag:'wx',mode:0o444});let mounted=false;
 try{execFileSync('/usr/bin/mount',commands.mount,{stdio:'ignore',timeout:5000});mounted=true;if(readFileSync(root+'/merged/control','utf8')!=='PUBLIC_OVERLAY_POSITIVE_CONTROL')throw new Error('RAM_OVERLAY_CONTROL_FAILED');writeFileSync(root+'/merged/new','PUBLIC_OVERLAY_WRITE_CONTROL',{flag:'wx',mode:0o600});if(readFileSync(root+'/upper/new','utf8')!=='PUBLIC_OVERLAY_WRITE_CONTROL')throw new Error('RAM_OVERLAY_CONTROL_FAILED');return true;}catch{return false;}finally{if(mounted)execFileSync('/usr/bin/umount',commands.unmount,{stdio:'ignore',timeout:5000});rmSync(root,{recursive:true});}
}
export function privateDaemonArguments(driver){
 if(!['overlay2','vfs'].includes(driver))throw new Error('RAM_PRIVATE_DRIVER_INVALID');
 return ['--config-file','/run/daemon-config.json','--host=unix:///var/run/docker.sock','--group=node','--data-root',STATE,'--exec-root','/run/docker-exec','--pidfile','/run/private-dockerd.pid','--storage-driver',driver,'--init-path='+PUBLIC_TOOLS.init,'--bridge=none','--iptables=false','--ip6tables=false','--ip-forward=false','--ip-masq=false','--userland-proxy=true','--log-level=error','--containerd-namespace=kongos-acceptance','--containerd-plugins-namespace=kongos-acceptance-plugins'];
}
export function runtimeToolDirectoryPlan(){
 return {directory:STATE+'/public-runtime-tools',mountTarget:'/usr/local/bin',sources:[...Object.entries(PUBLIC_TOOLS).filter(([,path])=>path.startsWith('/usr/local/bin/')),['node','/usr/local/bin/node']],readonly:true};
}
function prepareExecutableTools(gate){
 // runc seals its executable through a lower directory. Individual file
 // bind mounts expose the underlying placeholder to that overlay, so use
 // verified copies in a dedicated read-only directory within this namespace.
 const p=runtimeToolDirectoryPlan();mkdirSync(p.directory,{mode:0o700});let total=0;
 for(const[name,path]of p.sources){const b=readFileSync(path);total+=b.length;if(total>512*1024**2)throw Error('RAM_PUBLIC_RUNTIME_TOOLS_BUDGET');if(name!=='node'&&hash(b)!==gate.toolSha256[name])throw Error('RAM_PUBLIC_TOOL_SHA_MISMATCH');writeFileSync(p.directory+'/'+path.split('/').pop(),b,{flag:'wx',mode:0o555});}
 chmodSync(p.directory,0o555);execFileSync('/usr/bin/mount',['--bind',p.directory,p.mountTarget],{stdio:'ignore',timeout:5000});execFileSync('/usr/bin/mount',['-o','remount,bind,ro',p.mountTarget],{stdio:'ignore',timeout:5000});
 for(const[name,path]of p.sources)if(name!=='node'&&hash(readFileSync(path))!==gate.toolSha256[name])throw Error('RAM_PUBLIC_TOOL_SHA_MISMATCH');return{publicToolsReadonlyDirectory:true,publicToolsCopied:p.sources.length,privateFilesCopied:0};
}
export function readPrivateDaemonStatus(){
 if(!existsSync(STATUS))return{allPassed:false,safeCode:'RAM_PRIVATE_DAEMON_STARTING'};
 const status=JSON.parse(readFileSync(STATUS,'utf8'));if(!status.allPassed||!Number.isSafeInteger(status.daemonPid)||status.daemonPid<2)return{allPassed:false,safeCode:'RAM_PRIVATE_DAEMON_FAILED'};
 try{if(readlinkSync(`/proc/${status.daemonPid}/exe`)!==PUBLIC_TOOLS.dockerd)throw new Error();const info=JSON.parse(docker(['info','--format','{"driver":{{json .Driver}},"version":{{json .ServerVersion}}}']));if(info.driver!==status.driver||info.version!=='28.4.0')throw new Error();}catch{return{allPassed:false,safeCode:'RAM_PRIVATE_DAEMON_UNAVAILABLE'};}
 return status;
}
export async function startPrivateDaemon(){
 if(process.getuid()!==0||process.pid!==1)throw new Error('RAM_TOOL_HOST_IDENTITY_INVALID');
 const runId=process.env.KONGOS_RAM_RUN_ID,gate=JSON.parse(readFileSync('/run/kongos-output/runtime-gate.json','utf8'));validateRamGate(gate,runId);ramOptions(runId);
 if(Number(statfsSync(STATE).type)!==0x01021994)throw new Error('RAM_PRIVATE_DATA_ROOT_NOT_TMPFS');
 for(const [name,path] of Object.entries(PUBLIC_TOOLS))if(hash(readFileSync(path))!==gate.toolSha256[name])throw new Error('RAM_PUBLIC_TOOL_SHA_MISMATCH');
 if(hash(readFileSync('/etc/ssl/certs/ca-certificates.crt'))!==gate.publicTrustSha256)throw new Error('RAM_PUBLIC_TRUST_SHA_MISMATCH');
 const toolDirectory=prepareExecutableTools(gate);
 for(const path of [STATE+'/tmp','/run/docker-exec'])mkdirSync(path,{mode:0o700});writeFileSync('/run/daemon-config.json','{}\n',{flag:'wx',mode:0o600});
 const overlayMountProved=probeOverlay(),driver=overlayMountProved?'overlay2':'vfs';if(!overlayMountProved&&gate.fallbackDriver!=='vfs')throw new Error('RAM_OVERLAY_REQUIRED_BUT_UNAVAILABLE');
 const child=spawn(PUBLIC_TOOLS.dockerd,privateDaemonArguments(driver),{env:environment(),stdio:'ignore'});let exited=false;child.once('exit',()=>{exited=true;});child.once('error',()=>{exited=true;});
 let info;const deadline=Date.now()+50000;while(Date.now()<deadline&&!exited){try{info=JSON.parse(docker(['info','--format','{"driver":{{json .Driver}},"version":{{json .ServerVersion}}}']));if(info.driver===driver&&info.version==='28.4.0')break;}catch{}await new Promise(resolve=>setTimeout(resolve,500));}
 if(exited||info?.driver!==driver){child.kill('SIGTERM');throw new Error('RAM_PRIVATE_DAEMON_START_FAILED');}
 const compose=docker(['compose','version','--short']).trim();if(compose!=='2.40.3'&&compose!=='v2.40.3'){child.kill('SIGTERM');throw new Error('RAM_COMPOSE_VERSION_MISMATCH');}
 const relay=startFixedTlsPassthrough();try{await relay.ready;}catch(error){child.kill('SIGTERM');throw error;}
 const status={allPassed:true,runId,daemonPid:child.pid,driver,version:info.version,composeVersion:compose,overlayMountProved,privateLocalSocket:true,mainDockerSocketMounted:false,dataRootTmpfs:true,daemonTmpDir:environment().TMPDIR,...toolDirectory,fixedTcpRelaysReady:true,realTlsEndpointsVerified:false,productionAcceptancePassed:false};writeFileSync(STATUS,JSON.stringify(status)+'\n',{flag:'wx',mode:0o600});
 const stop=()=>{relay.close();child.kill('SIGTERM');};process.once('SIGTERM',stop);process.once('SIGINT',stop);await new Promise(resolve=>child.once('exit',resolve));relay.close();
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){if(process.argv.slice(2).join(' ')==='--status')console.log(JSON.stringify(readPrivateDaemonStatus()));else if(process.argv.length!==2){console.error('RAM_PRIVATE_DAEMON_ARGUMENTS_INVALID');process.exitCode=1;}else startPrivateDaemon().catch(error=>{console.error(safe(error));process.exitCode=1;});}
