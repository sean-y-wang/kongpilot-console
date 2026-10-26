import {describe,it,expect,afterEach} from 'vitest';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,symlinkSync,rmSync,chmodSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {EventEmitter} from 'node:events';
// @ts-expect-error deployment-only JavaScript module
import {RAM_BASE_IMAGE,RAM_LIMITS,RAM_RESERVE,PUBLIC_TOOLS,REQUIRED_CONTEXT,ramOptions,validateRamGate,publicContextPath,assertNewNetwork,assertMainCapacity,expectedToolMounts,toolHostArgs,assertToolHostFacts} from '../../../scripts/verification/production-ram-policy.mjs';
// @ts-expect-error deployment-only JavaScript module
import {copyFrozenPublicContext,readRegularPublicFile,parseBootstrapArgs,validateOwnedCleanup,parseCleanupArgs,validateRamEvidencePath} from '../../../scripts/verification/production-ram-bootstrap.mjs';
// @ts-expect-error deployment-only JavaScript module
import {estimateBaseArchiveAllocation} from '../../../scripts/verification/production-ram-image-bound.mjs';
// @ts-expect-error deployment-only JavaScript module
import {privateDaemonArguments,overlayProbeCommands,runtimeToolDirectoryPlan} from '../../../scripts/verification/production-ram-daemon.mjs';
// @ts-expect-error deployment-only JavaScript module
import {startFixedTlsPassthrough,FIXED_TLS_PORTS} from '../../../scripts/verification/production-ram-tls-passthrough.mjs';

const sha=(b:any)=>createHash('sha256').update(b).digest('hex'),digest='a'.repeat(64),options=()=>ramOptions('synthetic-001');
const temporary:string[]=[];const temp=()=>{const p=mkdtempSync(join(tmpdir(),'kongos-ram-source-test-'));temporary.push(p);return p;};afterEach(()=>{for(const p of temporary.splice(0))rmSync(p,{recursive:true,force:true});});
const gate=()=>({scope:'M0-M8-private-ram-production-acceptance',runtimeAuthorized:true,m8Closed:true,runId:'synthetic-001',baseImageId:RAM_BASE_IMAGE,fallbackDriver:'vfs',publicTrustSha256:digest,sourceSha256:Object.fromEntries(REQUIRED_CONTEXT.map((p:string)=>[p,digest])),toolSha256:Object.fromEntries(Object.keys(PUBLIC_TOOLS).map(p=>[p,digest])),evidenceAllowanceBytes:1024**2});
const facts=()=>{const o=options();return{image:RAM_BASE_IMAGE,name:o.name,labels:{[o.ownershipLabel]:o.runId},hostConfig:{privileged:true,networkMode:o.network,pidMode:'',ipcMode:'private',cgroupnsMode:'private',readOnlyRootfs:true,memory:10*1024**3,pidsLimit:4096,nanoCpus:4e9,devices:[],deviceRequests:[],tmpfs:{'/var/lib/kongos-docker':`rw,nosuid,nodev,size=${RAM_LIMITS.data}`,'/tmp':'rw,size=134217728','/root/.docker':'rw,size=1048576'}},networks:[{name:o.network,ip:o.toolIp}],mounts:[...expectedToolMounts(o),{source:'/etc/ssl/certs/ca-certificates.crt',destination:'/etc/ssl/certs/ca-certificates.crt',readOnly:true}].map(m=>({...m,type:'bind'})),published:[[18443,28443],[19443,29443],[21443,31443],[22443,32443]].map(([hostPort,containerPort])=>({hostIp:'127.0.0.1',hostPort,containerPort}))};};
describe('Source-only isolated RAM bootstrap failclosed policy',()=>{
 it('requires explicit M8 closure/Root scope/fixed base and complete source/tool pins',()=>{
  expect(validateRamGate(gate(),'synthetic-001').socket).toContain('/dev/shm/kongos-production-ram-synthetic-001/');
  const changes=[(g:any)=>g.runtimeAuthorized=false,(g:any)=>g.m8Closed=false,(g:any)=>g.scope='generic',(g:any)=>g.runId='foreign',(g:any)=>g.baseImageId='node:latest',(g:any)=>delete g.sourceSha256[REQUIRED_CONTEXT[0]],(g:any)=>delete g.toolSha256.init,(g:any)=>g.publicTrustSha256='bad',(g:any)=>g.fallbackDriver='unknown'];
  for(const change of changes){const g=gate();change(g);expect(()=>validateRamGate(g,'synthetic-001')).toThrow();}
 });
 it('never accepts mutable paths/run names or incomplete CLI selectors',()=>{
  for(const name of ['../old','synthetic\n001','a','kongos/old'])expect(()=>ramOptions(name)).toThrow();
  expect(parseBootstrapArgs(['--run-id','synthetic-001','--gate','/opt/kongpilot-console/artifacts/Production/root-private-ram-runtime-release-gate.json','--gate-sha',digest])).toMatchObject({runId:'synthetic-001',gateSha:digest});
  for(const path of ['.env','deploy/private/capture.json','/etc/shadow','artifacts/M8/root-private-ram-any.json'])expect(()=>validateRamEvidencePath(path)).toThrow();
  for(const args of [[],['--run-id','synthetic-001'],['--env-file','.env'],['--gate-sha','bad'],['--run-id','a','--run-id','b','--gate','x','--gate-sha',digest]])expect(()=>parseBootstrapArgs(args)).toThrow();
 });
 it('requires allocated filesystem evidence plus a real 250MiB reserve, not logical image size',()=>{
  expect(assertMainCapacity({availableBytes:926445568,allocatedRootfsUpperBytes:300000000,evidenceAllowanceBytes:1024**2})).toMatchObject({reserveBytes:RAM_RESERVE});
  expect(()=>assertMainCapacity({availableBytes:500000000,allocatedRootfsUpperBytes:300000000,evidenceAllowanceBytes:1024**2})).toThrow('RAM_MAIN_CAPACITY_INSUFFICIENT');
  expect(()=>assertMainCapacity({availableBytes:900000000,imageSizeBytes:226953768})).toThrow('RAM_MAIN_CAPACITY_UNPROVEN');
 });
 it('rejects both containing and contained existing IPv4 subnets',()=>{
  assertNewNetwork(options(),['172.28.11.0/24','172.30.0.0/16','fd00::/64']);
  for(const subnet of ['172.29.0.0/16','172.29.250.0/25','172.29.250.10/32'])expect(()=>assertNewNetwork(options(),[subnet])).toThrow('RAM_BUILD_NETWORK_OVERLAP');
  expect(()=>assertNewNetwork(options(),[undefined])).toThrow();
 });
 it('creates only one named task tool with private namespaces, RO public mounts, fixed localhost ports',()=>{
  const args=toolHostArgs(options());expect(args[0]).toBe('--host=unix:///var/run/docker.sock');expect(args).toContain('--privileged');expect(args).toContain('--read-only');expect(args).toContain('--cgroupns=private');expect(args).toContain('--pull=never');expect(args).not.toContain('host');expect(args.join(' ')).not.toMatch(/src=\/var\/run\/docker.sock|src=\/opt\/kongos-console[,/]|deploy\/private|\.env/);
  expect(args.filter((v:string,i:number)=>args[i-1]==='--publish')).toEqual(['127.0.0.1:18443:28443/tcp','127.0.0.1:19443:29443/tcp','127.0.0.1:21443:31443/tcp','127.0.0.1:22443:32443/tcp']);
 });
 it('checks actual facts including no hidden volume/device/default-network or published wildcard bypass',()=>{
  expect(assertToolHostFacts(options(),facts())).toBe(true);
  const changes=[(f:any)=>f.image='foreign',(f:any)=>f.hostConfig.networkMode='host',(f:any)=>f.hostConfig.pidMode='host',(f:any)=>f.hostConfig.cgroupnsMode='host',(f:any)=>f.hostConfig.readOnlyRootfs=false,(f:any)=>f.hostConfig.devices=[{}],(f:any)=>f.hostConfig.memory=0,(f:any)=>f.networks.push({name:'admin'}),(f:any)=>f.mounts.push({type:'volume',destination:'/old'}),(f:any)=>f.mounts.push({type:'bind',source:'/var/run/docker.sock',destination:'/old'}),(f:any)=>f.mounts[0].readOnly=false,(f:any)=>f.published[0].hostIp='0.0.0.0',(f:any)=>delete f.hostConfig.tmpfs];
  for(const change of changes){const f=facts();change(f);expect(()=>assertToolHostFacts(options(),f)).toThrow();}
 });
 it('private daemon has independent RAM paths and no main containerd or TCP API listener',()=>{
  const args=privateDaemonArguments('overlay2');expect(args).toContain('/var/lib/kongos-docker');expect(args).toContain('--host=unix:///var/run/docker.sock');expect(args).toContain('--containerd-namespace=kongos-acceptance');expect(args).toContain('--init-path=/usr/local/bin/docker-init');expect(args.join(' ')).not.toMatch(/tcp:\/\/|\/run\/containerd\/containerd.sock/);expect(()=>privateDaemonArguments('unknown')).toThrow();expect(()=>overlayProbeCommands('/existing')).toThrow();
 });
 it('keeps runc safety sealing executable by using verified tools within a read-only parent directory',()=>{
  const p=runtimeToolDirectoryPlan();expect(p.readonly).toBe(true);expect(p.directory).toBe('/var/lib/kongos-docker/public-runtime-tools');expect(p.mountTarget).toBe('/usr/local/bin');expect(p.sources).toContainEqual(['runc','/usr/local/bin/runc']);expect(p.sources).toContainEqual(['node','/usr/local/bin/node']);expect(p.sources).toHaveLength(8);
  const args=toolHostArgs(options());expect(args).not.toContain('--pid=private');expect(args).toContain(`/var/lib/kongos-docker:rw,nosuid,nodev,exec,size=${RAM_LIMITS.data}`);expect(args).toContain('/tmp:rw,nosuid,nodev,exec,size=134217728');
 });
});

describe('whitelisted public files, no symlink/private traversal or overwrite',()=>{
 it('makes only the public context readable by nonroot consumers even under umask077',()=>{
  const root=temp(),out=join(root,'public/context');mkdirSync(join(root,'deploy/scripts'),{recursive:true});const file='deploy/scripts/kong-migrate.sh';writeFileSync(join(root,file),'PUBLIC',{mode:0o600});const old=process.umask(0o077);try{copyFrozenPublicContext(root,out,{[file]:sha('PUBLIC')});}finally{process.umask(old);}expect(statSync(out).mode&0o777).toBe(0o755);expect(statSync(join(out,'deploy/scripts')).mode&0o777).toBe(0o755);expect(statSync(join(out,file)).mode&0o777).toBe(0o444);expect(statSync(join(root,'public')).mode&0o777).toBe(0o700);
 });
 it('copies only regular frozen public files, leaving unknown secrets unread and absent',()=>{
  const root=temp(),out=join(root,'scratch/context'),value=Buffer.from('PUBLIC_PACKAGE');writeFileSync(join(root,'package.json'),value,{mode:0o600});
  const result=copyFrozenPublicContext(root,out,{'package.json':sha(value),'.env':digest,'deploy/private/token':digest,'artifacts/report':digest});expect(result).toMatchObject({files:1,privateFilesCopied:false});expect(readFileSync(join(out,'package.json')).equals(value)).toBe(true);expect(()=>readFileSync(join(out,'.env'))).toThrow();expect(()=>copyFrozenPublicContext(root,out,{'package.json':sha(value)})).toThrow();
 });
 it('rejects content tampering, group-writable file and source symlink',()=>{
  for(const mode of ['sha','writable','symlink']){const root=temp(),out=join(root,'scratch/context'),value='PUBLIC';writeFileSync(join(root,'package.json'),value,{mode:0o600});if(mode==='writable')chmodSync(join(root,'package.json'),0o620);if(mode==='symlink'){rmSync(join(root,'package.json'));symlinkSync('/nonexistent',join(root,'package.json'));}expect(()=>copyFrozenPublicContext(root,out,{'package.json':mode==='sha'?digest:sha(value)})).toThrow();}
 });
 it('rejects escape/private/build evidence paths while preserving legitimate source descriptors',()=>{
  for(const path of ['../package.json','apps/console-api/src/../private/key','.env.example','deploy/private/key','artifacts/report','apps/console-api/dist/main.js','apps/console-api/src/fixtures/secret','/etc/shadow'])expect(publicContextPath(path)).toBe(false);
  expect(publicContextPath('apps/console-api/src/infrastructure/secret.service.ts')).toBe(true);expect(publicContextPath('deploy/production.env.example')).toBe(true);
 });
 it('does not follow file symlinks or accept non-regular public descriptors',()=>{
  const root=temp();symlinkSync('/nonexistent',join(root,'public-link'));expect(()=>readRegularPublicFile(join(root,'public-link'))).toThrow();mkdirSync(join(root,'dir'));expect(()=>readRegularPublicFile(join(root,'dir'))).toThrow('RAM_PUBLIC_FILE_INVALID');
 });
});

function tar(entries:{name:string;body?:Buffer;kind?:string;link?:string}[]){const chunks:Buffer[]=[];for(const e of entries){const body=e.body??Buffer.alloc(0),header=Buffer.alloc(512);header.write(e.name);header.write('0000644\0',100);header.write('0000000\0',108);header.write('0000000\0',116);header.write(body.length.toString(8).padStart(11,'0')+'\0',124);header.write('00000000000\0',136);header.fill(32,148,156);header.write(e.kind??'0',156);if(e.link)header.write(e.link,157);header.write('ustar\0',257);header.write('00',263);const sum=header.reduce((s,n)=>s+n,0);header.write(sum.toString(8).padStart(6,'0')+'\0 ',148);chunks.push(header,body,Buffer.alloc((512-body.length%512)%512));}chunks.push(Buffer.alloc(1024));return Buffer.concat(chunks);}
function archive(){const layer=tar([{name:'usr/bin/public-control',body:Buffer.from('PUBLIC_LAYER')},{name:'usr/bin/hard-control',kind:'1',link:'usr/bin/public-control'}]),config=Buffer.from(JSON.stringify({rootfs:{type:'layers',diff_ids:['sha256:'+sha(layer)]}})),id='sha256:'+sha(config),bytes=tar([{name:sha(config)+'.json',body:config},{name:'layer.tar',body:layer},{name:'manifest.json',body:Buffer.from(JSON.stringify([{Config:sha(config)+'.json',Layers:['layer.tar']}]))}]);return{id,bytes};}
describe('public image archive allocation bound reads actual layer metadata, never extracts',()=>{
 it('verifies config identity/diffIDs and counts conservative filesystem blocks/hardlinks/metadata',()=>{
  const root=temp(),file=join(root,'public.tar'),a=archive();writeFileSync(file,a.bytes,{mode:0o600});const bound=estimateBaseArchiveAllocation(file,{expectedImageId:a.id});expect(bound).toMatchObject({layers:1,entries:2,hardLinks:1,regularAllocatedBytes:4096,hardLinkAllocatedBytes:4096,logicalImageSizeUsedAsBound:false,allLayerDiffIdsMatched:true});expect(bound.allocatedRootfsUpperBytes).toBeGreaterThan(a.bytes.length);expect(JSON.stringify(bound)).not.toContain('usr/bin');
 });
 it('rejects wrong image/config SHA, corrupted layers, permissions and archive links',()=>{
  for(const change of ['wrong-id','tamper','permissions','link']){const root=temp(),file=join(root,'public.tar'),a=archive();if(change==='tamper')a.bytes[1600]^=1;writeFileSync(file,a.bytes,{mode:0o600});if(change==='permissions')chmodSync(file,0o644);if(change==='link'){rmSync(file);symlinkSync('/nonexistent',file);}expect(()=>estimateBaseArchiveAllocation(file,{expectedImageId:change==='wrong-id'?'sha256:'+digest:a.id})).toThrow();}
 });
});

describe('fixed opaque TCP passthrough and owned cleanup',()=>{
 it('pipes original opaque bytes without HTTP/TLS interception and restricts every destination/port',async()=>{
  class Socket extends EventEmitter{destroyed=false;dest:any;timeout=0;setTimeout(n:number){this.timeout=n;}pipe(to:any){this.dest=to;return to;}destroy(){this.destroyed=true;}}
  const servers:any[]=[],connections:any[]=[];const netImplementation={createServer(cb:any){const s=new EventEmitter() as any;s.accept=cb;s.listen=(b:any,done:any)=>{s.binding=b;done();};s.close=()=>{};servers.push(s);return s;},createConnection(address:any){const s=new Socket();connections.push({address,s});return s;}};
  const relay=startFixedTlsPassthrough({netImplementation});await relay.ready;expect(servers.map(s=>s.binding.port)).toEqual(FIXED_TLS_PORTS.map((b:any)=>b.listen));
  const client=new Socket();servers[0].accept(client);connections[0].s.emit('connect');expect(connections[0].address).toEqual({host:'127.0.0.1',port:18443});expect(client.dest).toBe(connections[0].s);expect(connections[0].s.dest).toBe(client);expect(client.listenerCount('data')).toBe(0);relay.close();expect(client.destroyed).toBe(true);expect(()=>startFixedTlsPassthrough({maxConnections:129})).toThrow();
 });
 it('requires exact owned IDs, authenticated persistent backup and recoverable release images before removal',()=>{
  const o=options(),ownership={runId:o.runId,uid:process.getuid(),name:o.name,network:o.network,gateSha:digest},runtime={runId:o.runId,gateSha:digest,id:'b'.repeat(64),networkId:'c'.repeat(64)},evidence={runId:o.runId,gateSha:digest,allowDestroyOwnedToolHost:true,finalPublicEvidenceFrozen:true,projectsStopped:true,authenticatedBackupVerified:true,releaseImagesRecoverable:true,backupSha256:digest,backupPath:`/opt/kongpilot-private-backups/${o.runId}/bundle.enc`};
  expect(validateOwnedCleanup(o,ownership,runtime,evidence).containerId).toBe(runtime.id);
  for(const change of [(e:any)=>e.projectsStopped=false,(e:any)=>e.authenticatedBackupVerified=false,(e:any)=>e.releaseImagesRecoverable=false,(e:any)=>e.backupPath='/dev/shm/backup',(e:any)=>e.backupPath=`/opt/kongpilot-private-backups/${o.runId}/../old`,(e:any)=>e.runId='foreign']){const e={...evidence};change(e);expect(()=>validateOwnedCleanup(o,ownership,runtime,e)).toThrow();}
  expect(()=>validateOwnedCleanup(o,{...ownership,uid:-1},runtime,evidence)).toThrow();expect(()=>parseCleanupArgs(['--cleanup','--run-id',o.runId,'--evidence','/opt/kongpilot-console/artifacts/Production/root-private-ram-owned-cleanup-evidence.json','--evidence-sha',digest])).not.toThrow();expect(()=>parseCleanupArgs(['--cleanup','--all'])).toThrow();
 });
});
