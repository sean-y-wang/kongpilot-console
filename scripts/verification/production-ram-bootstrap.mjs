import {spawn,execFileSync} from 'node:child_process';
import {constants,readFileSync,writeFileSync,openSync,closeSync,fstatSync,lstatSync,mkdirSync,statfsSync,readlinkSync,rmSync,chmodSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,dirname,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {RAM_BASE_IMAGE,RAM_LIMITS,PUBLIC_TOOLS,ramOptions,validateRamGate,publicContextPath,assertNewNetwork,assertMainCapacity,assertRamHeadroom,toolHostArgs,assertToolHostFacts} from './production-ram-policy.mjs';
import {estimateBaseArchiveAllocation} from './production-ram-image-bound.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>{throw new Error(code);};
const safe=error=>/^(?:RAM_[A-Z0-9_]+)$/.test(error?.message??'')?error.message:'RAM_BOOTSTRAP_FAILED';
const environment=()=>{const env={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];return env;};
const docker=(args,timeout=20000)=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:environment(),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout,maxBuffer:4*1024**2});
const capacity=path=>{const s=statfsSync(path,{bigint:true});return{available:Number(s.bavail*s.bsize),block:Number(s.bsize),type:Number(s.type)};};
export function readRegularPublicFile(filename,{maxBytes=32*1024**2}={}){
 const fd=openSync(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const s=fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size>maxBytes||(s.mode&0o022))fail('RAM_PUBLIC_FILE_INVALID');return readFileSync(fd);}finally{closeSync(fd);}
}
function verifyParents(root,relative){let dir=root;for(const part of relative.split('/').slice(0,-1)){dir=join(dir,part);const s=lstatSync(dir);if(!s.isDirectory()||s.isSymbolicLink())fail('RAM_PUBLIC_CONTEXT_SYMLINK');}}
export function validateRamEvidencePath(filename){const path=resolve(filename);if(!/^\/opt\/(?:kongpilot-console|kongos-console)\/artifacts\/Production\/root-private-ram-[a-z0-9-]+\.json$/.test(path))fail('RAM_PUBLIC_EVIDENCE_PATH_INVALID');return path;}
export function copyFrozenPublicContext(repository,destination,manifest){
 if(!manifest||typeof manifest!=='object'||!['/opt/kongpilot-console','/opt/kongpilot-console'].includes(resolve(repository))&&process.env.NODE_ENV!=='test')fail('RAM_PUBLIC_CONTEXT_INVALID');
 const rootStat=lstatSync(repository);if(!rootStat.isDirectory()||rootStat.isSymbolicLink())fail('RAM_PUBLIC_CONTEXT_SYMLINK');
 mkdirSync(dirname(destination),{recursive:true,mode:0o755});mkdirSync(destination,{mode:0o755});chmodSync(destination,0o755);
 let copiedBytes=0,copiedFiles=0;const selected=Object.entries(manifest).filter(([path])=>publicContextPath(path)).sort(([a],[b])=>a.localeCompare(b));
 if(!selected.length)fail('RAM_PUBLIC_CONTEXT_EMPTY');
 for(const [relative,sha] of selected){verifyParents(repository,relative);const bytes=readRegularPublicFile(join(repository,relative));if(hash(bytes)!==sha)fail('RAM_PUBLIC_CONTEXT_SHA_MISMATCH');copiedBytes+=bytes.length;if(copiedBytes>RAM_LIMITS.context)fail('RAM_PUBLIC_CONTEXT_BUDGET_EXCEEDED');mkdirSync(dirname(join(destination,relative)),{recursive:true,mode:0o755});let parent=destination;for(const part of relative.split('/').slice(0,-1)){parent=join(parent,part);chmodSync(parent,0o755);}writeFileSync(join(destination,relative),bytes,{flag:'wx',mode:0o444});chmodSync(join(destination,relative),0o444);copiedFiles++;}
 return{files:copiedFiles,bytes:copiedBytes,wholeRepositoryMounted:false,privateFilesCopied:false};
}
export function protectedContainerMetadata(){
 const ids=docker(['ps','-aq']).trim().split(/\s+/).filter(Boolean);if(ids.some(id=>!/^[a-f0-9]{12,64}$/.test(id)))fail('RAM_MAIN_METADATA_INVALID');
 return ids.map(id=>JSON.parse(docker(['inspect','--format','{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"status":{{json .State.Status}},"pid":{{json .State.Pid}},"startedAt":{{json .State.StartedAt}},"networks":{{json .NetworkSettings.Networks}}}',id]))).sort((a,b)=>a.id.localeCompare(b.id));
}
function toolFacts(options,id){
 const row=JSON.parse(docker(['inspect','--format','{"image":{{json .Image}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"hc":{{json .HostConfig}},"networks":{{json .NetworkSettings.Networks}},"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}}}',id]));
 return{image:row.image,name:row.name.slice(1),labels:row.labels,hostConfig:{privileged:row.hc.Privileged,networkMode:row.hc.NetworkMode,pidMode:row.hc.PidMode,ipcMode:row.hc.IpcMode,cgroupnsMode:row.hc.CgroupnsMode,readOnlyRootfs:row.hc.ReadonlyRootfs,memory:row.hc.Memory,pidsLimit:row.hc.PidsLimit,nanoCpus:row.hc.NanoCpus,devices:row.hc.Devices,deviceRequests:row.hc.DeviceRequests,tmpfs:row.hc.Tmpfs},networks:Object.entries(row.networks).map(([name,f])=>({name,ip:f.IPAddress})),mounts:row.mounts.map(m=>({type:m.Type,source:m.Source,destination:m.Destination,readOnly:!m.RW})),published:Object.entries(row.ports).flatMap(([port,bindings])=>(bindings??[]).map(b=>({containerPort:Number(port.split('/')[0]),hostIp:b.HostIp,hostPort:Number(b.HostPort)})))};
}
async function exportBoundedPublicBase(filename){
 const fd=openSync(filename,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL,0o600);let bytes=0;
 try{await new Promise((resolve,reject)=>{const child=spawn('docker',['--host=unix:///var/run/docker.sock','image','save',RAM_BASE_IMAGE],{env:environment(),stdio:['ignore','pipe','pipe']});const timeout=setTimeout(()=>{child.kill();reject(new Error('RAM_BASE_EXPORT_TIMEOUT'));},60000);child.stderr.resume();child.once('error',()=>{clearTimeout(timeout);reject(new Error('RAM_BASE_EXPORT_FAILED'));});child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>RAM_LIMITS.archive){child.kill();return reject(new Error('RAM_BASE_EXPORT_BUDGET_EXCEEDED'));}try{writeFileSync(fd,chunk);}catch{child.kill();reject(new Error('RAM_BASE_EXPORT_FAILED'));}});child.once('close',code=>{clearTimeout(timeout);code===0?resolve():reject(new Error('RAM_BASE_EXPORT_FAILED'));});});}finally{closeSync(fd);}return bytes;
}
export function parseBootstrapArgs(argv){const options={};for(let i=0;i<argv.length;i++){const arg=argv[i];if(!['--run-id','--gate','--gate-sha'].includes(arg)||options[arg]!==undefined||!argv[i+1])fail('RAM_BOOTSTRAP_ARGUMENTS_INVALID');options[arg]=argv[++i];}if(Object.keys(options).length!==3||!/^[a-f0-9]{64}$/.test(options['--gate-sha']))fail('RAM_BOOTSTRAP_ARGUMENTS_INVALID');return{runId:options['--run-id'],gate:validateRamEvidencePath(options['--gate']),gateSha:options['--gate-sha']};}
export function parseCleanupArgs(argv){if(argv[0]!=='--cleanup')fail('RAM_CLEANUP_ARGUMENTS_INVALID');const input={};for(let i=1;i<argv.length;i++){const key=argv[i];if(!['--run-id','--evidence','--evidence-sha'].includes(key)||input[key]!==undefined||!argv[i+1])fail('RAM_CLEANUP_ARGUMENTS_INVALID');input[key]=argv[++i];}if(Object.keys(input).length!==3||!/^[a-f0-9]{64}$/.test(input['--evidence-sha']))fail('RAM_CLEANUP_ARGUMENTS_INVALID');return{runId:input['--run-id'],evidencePath:validateRamEvidencePath(input['--evidence']),evidenceSha256:input['--evidence-sha']};}
export function validateOwnedCleanup(options,ownership,runtime,evidence){
 if(ownership?.runId!==options.runId||ownership?.uid!==process.getuid()||ownership?.name!==options.name||ownership?.network!==options.network||runtime?.runId!==options.runId||runtime?.gateSha!==ownership.gateSha||!/^([a-f0-9]{64})$/.test(runtime?.id??'')||!/^([a-f0-9]{64})$/.test(runtime?.networkId??''))fail('RAM_CLEANUP_OWNERSHIP_INVALID');
 if(evidence?.runId!==options.runId||evidence.gateSha!==ownership.gateSha||evidence.allowDestroyOwnedToolHost!==true||evidence.finalPublicEvidenceFrozen!==true||evidence.projectsStopped!==true||evidence.authenticatedBackupVerified!==true||evidence.releaseImagesRecoverable!==true||!/^([a-f0-9]{64})$/.test(evidence.backupSha256??'')||typeof evidence.backupPath!=='string'||!evidence.backupPath.startsWith(`/opt/kongpilot-private-backups/${options.runId}/`)||evidence.backupPath!==resolve(evidence.backupPath))fail('RAM_CLEANUP_BACKUP_EVIDENCE_INVALID');
 return{containerId:runtime.id,networkId:runtime.networkId,backupPath:evidence.backupPath,backupSha256:evidence.backupSha256};
}
/** Explicit separate operator call only after authenticated backup has left RAM.
 * Does not enumerate/delete any main volumes, images or foreign resources. */
export function cleanupOwnedRam({runId,evidencePath,evidenceSha256}){
 evidencePath=validateRamEvidencePath(evidencePath);verifyParents('/opt/kongpilot-console',evidencePath.slice('/opt/kongpilot-console/'.length));
 const options=ramOptions(runId),bytes=readRegularPublicFile(evidencePath,{maxBytes:65536});if(hash(bytes)!==evidenceSha256)fail('RAM_CLEANUP_EVIDENCE_SHA_MISMATCH');
 const ownership=JSON.parse(readRegularPublicFile(join(options.root,'ownership.json'),{maxBytes:65536})),runtime=JSON.parse(readRegularPublicFile(join(options.root,'runtime-ownership.json'),{maxBytes:65536})),approved=validateOwnedCleanup(options,ownership,runtime,JSON.parse(bytes));
 let dir=options.root;const stat=lstatSync(dir);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o077))fail('RAM_CLEANUP_ROOT_INVALID');
 const backupParent=lstatSync(dirname(approved.backupPath));if(!backupParent.isDirectory()||backupParent.isSymbolicLink()||backupParent.uid!==process.getuid()||(backupParent.mode&0o077))fail('RAM_CLEANUP_BACKUP_EVIDENCE_INVALID');
 if(hash(readRegularPublicFile(approved.backupPath,{maxBytes:RAM_LIMITS.backup}))!==approved.backupSha256)fail('RAM_CLEANUP_BACKUP_HASH_MISMATCH');
 assertToolHostFacts(options,toolFacts(options,approved.containerId));
 const network=JSON.parse(docker(['network','inspect','--format','{"labels":{{json .Labels}},"name":{{json .Name}},"members":{{json .Containers}}}',approved.networkId]));if(network.name!==options.network||network.labels?.[options.ownershipLabel]!==runId||Object.keys(network.members).join(',')!==approved.containerId)fail('RAM_CLEANUP_NETWORK_OWNERSHIP_INVALID');
 if(docker(['exec',approved.containerId,'docker','--host=unix:///var/run/docker.sock','ps','-q']).trim())fail('RAM_CLEANUP_PROJECTS_STILL_RUNNING');
 const before=protectedContainerMetadata().filter(row=>row.id!==approved.containerId);docker(['stop','--time','40',approved.containerId],50000);docker(['rm',approved.containerId]);docker(['network','rm',approved.networkId]);
 if(JSON.stringify(before)!==JSON.stringify(protectedContainerMetadata()))fail('RAM_CLEANUP_MAIN_CONTAINER_CHANGED');
 rmSync(options.root,{recursive:true});return{ownedContainerRemoved:true,ownedNetworkRemoved:true,ownedRamRemoved:true,mainImagesAndVolumesRemoved:0,backupOutsideRamRetained:true};
}
export async function bootstrapRam({runId,gate:gatePath,gateSha}){
 gatePath=validateRamEvidencePath(gatePath);verifyParents('/opt/kongpilot-console',gatePath.slice('/opt/kongpilot-console/'.length));
 const gateBytes=readRegularPublicFile(gatePath,{maxBytes:2*1024**2});if(hash(gateBytes)!==gateSha)fail('RAM_RELEASE_GATE_SHA_MISMATCH');const gate=JSON.parse(gateBytes),options=validateRamGate(gate,runId);
 if(capacity('/dev/shm').type!==0x01021994)fail('RAM_PRIVATE_DATA_ROOT_NOT_TMPFS');
 const memory=/^MemAvailable:\s+(\d+) kB$/m.exec(readFileSync('/proc/meminfo','utf8'));if(!memory)fail('RAM_MEMORY_HEADROOM_UNPROVEN');assertRamHeadroom({tmpfsAvailableBytes:capacity('/dev/shm').available,memAvailableBytes:Number(memory[1])*1024});
 for(const [name,path] of Object.entries(PUBLIC_TOOLS))if(hash(readRegularPublicFile(path,{maxBytes:128*1024**2}))!==gate.toolSha256[name])fail('RAM_PUBLIC_TOOL_SHA_MISMATCH');
 if(hash(readRegularPublicFile('/etc/ssl/certs/ca-certificates.crt',{maxBytes:4*1024**2}))!==gate.publicTrustSha256)fail('RAM_PUBLIC_TRUST_SHA_MISMATCH');
 for(const [relative,sha] of Object.entries(gate.sourceSha256).filter(([path])=>publicContextPath(path))){verifyParents('/opt/kongpilot-console',relative);if(hash(readRegularPublicFile(join('/opt/kongpilot-console',relative)))!==sha)fail('RAM_PUBLIC_CONTEXT_SHA_MISMATCH');}
 const info=JSON.parse(docker(['info','--format','{"driver":{{json .Driver}},"version":{{json .ServerVersion}}}']));if(info.driver!=='vfs'||info.version!=='28.4.0')fail('RAM_MAIN_ENGINE_CHANGED');
 const image=JSON.parse(docker(['image','inspect','--format','{{json .Id}}',RAM_BASE_IMAGE]));if(image!==RAM_BASE_IMAGE)fail('RAM_PUBLIC_BASE_ID_MISMATCH');
 const networkIds=docker(['network','ls','-q']).trim().split(/\s+/).filter(Boolean);const subnets=networkIds.flatMap(id=>(JSON.parse(docker(['network','inspect','--format','{{json .IPAM.Config}}',id]))??[]).map(row=>row.Subnet));assertNewNetwork(options,subnets);
 const before=protectedContainerMetadata();if(before.some(c=>c.name===`/${options.name}`))fail('RAM_TOOL_HOST_ALREADY_EXISTS');
 mkdirSync(options.root,{mode:0o700});mkdirSync(dirname(options.output),{mode:0o700});for(const path of [options.run,options.private,options.output])mkdirSync(path,{mode:0o700});
 const write=(filename,value)=>writeFileSync(filename,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
 write(join(options.root,'ownership.json'),{runId,gateSha,uid:process.getuid(),name:options.name,network:options.network,createdAt:new Date().toISOString()});
 const result={scope:'SOURCE_FROZEN_PRIVATE_RAM_BOOTSTRAP',runId,gateSha,allPassed:false,steps:[],productionAcceptancePassed:false};
 try{
  const context=copyFrozenPublicContext('/opt/kongpilot-console',options.context,gate.sourceSha256);result.steps.push({phase:'public-context',...context});write(join(options.output,'runtime-gate.json'),gate);
  const archive=join(options.output,'public-node-base.tar');await exportBoundedPublicBase(archive);const bound=estimateBaseArchiveAllocation(archive,{blockBytes:capacity('/workspace').block}),budget=assertMainCapacity({availableBytes:capacity('/workspace').available,allocatedRootfsUpperBytes:bound.allocatedRootfsUpperBytes,evidenceAllowanceBytes:gate.evidenceAllowanceBytes});result.steps.push({phase:'fresh-node-allocation-bound',bound,budget});
  const networkId=docker(['network','create','--driver','bridge','--subnet',options.subnet,'--label',`${options.ownershipLabel}=${runId}`,options.network]).trim();if(!/^[a-f0-9]{64}$/.test(networkId))fail('RAM_OWNED_NETWORK_ID_INVALID');
  const id=docker(toolHostArgs(options).slice(1),60000).trim();if(!/^[a-f0-9]{64}$/.test(id))fail('RAM_OWNED_CONTAINER_ID_INVALID');write(join(options.root,'runtime-ownership.json'),{id,networkId,gateSha,runId});
  assertToolHostFacts(options,toolFacts(options,id));result.steps.push({phase:'tool-host-exact-boundary',id,networkId});
  let ready;const deadline=Date.now()+60000;while(Date.now()<deadline){try{ready=JSON.parse(docker(['exec',id,'node','scripts/verification/production-ram-daemon.mjs','--status'],10000));if(ready.allPassed)break;}catch{}await new Promise(resolve=>setTimeout(resolve,500));}if(!ready?.allPassed)fail('RAM_PRIVATE_DAEMON_NOT_READY');
  const currentNs=docker(['exec',id,'readlink','/proc/self/ns/net']).trim();if(!/^net:\[\d+\]$/.test(currentNs)||currentNs===readlinkSync('/proc/self/ns/net'))fail('RAM_TOOL_HOST_NETWORK_NAMESPACE_NOT_ISOLATED');
  const after=protectedContainerMetadata().filter(c=>c.id!==id);if(JSON.stringify(before)!==JSON.stringify(after))fail('RAM_PROTECTED_MAIN_CONTAINER_CHANGED');
  const ownNetwork=JSON.parse(docker(['network','inspect','--format','{"driver":{{json .Driver}},"internal":{{json .Internal}},"labels":{{json .Labels}},"members":{{json .Containers}}}',networkId]));if(ownNetwork.driver!=='bridge'||ownNetwork.internal||ownNetwork.labels?.[options.ownershipLabel]!==runId||Object.keys(ownNetwork.members).join(',')!==id)fail('RAM_OWNED_BUILD_NETWORK_BOUNDARY_INVALID');
  result.steps.push({phase:'private-daemon-ready',...ready,mainOriginalContainersRetained:before.length,mainSocketMounted:false,toolNetworkNamespaceIsolated:true});result.allPassed=true;
 }catch(error){result.safeCode=safe(error);throw error;}finally{write(join(options.output,'bootstrap-result.json'),result);}
 return{allPassed:true,runId,report:join(options.output,'bootstrap-result.json'),socket:options.socket,productionAcceptancePassed:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{const task=process.argv[2]==='--cleanup'?Promise.resolve().then(()=>cleanupOwnedRam(parseCleanupArgs(process.argv.slice(2)))):bootstrapRam(parseBootstrapArgs(process.argv.slice(2)));task.then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(safe(error));process.exitCode=1;});}catch(error){console.error(safe(error));process.exitCode=1;}}
