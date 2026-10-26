import {posix} from 'node:path';

export const RAM_BASE_IMAGE='sha256:d0a16be756b6ec6658aecb8b7bcf87fa6c7d0d7fcc6ca53ad14bb49a4c90bdd7';
export const RAM_RESERVE=250*1024*1024;
export const RAM_LIMITS=Object.freeze({data:5*1024**3,archive:512*1024**2,backup:512*1024**2,context:32*1024**2,other:512*1024**2});
export const PUBLIC_TOOLS=Object.freeze({docker:'/usr/local/bin/docker',dockerd:'/usr/local/bin/dockerd',containerd:'/usr/local/bin/containerd',shim:'/usr/local/bin/containerd-shim-runc-v2',runc:'/usr/local/bin/runc',proxy:'/usr/local/bin/docker-proxy',init:'/usr/local/bin/docker-init',compose:'/usr/libexec/docker/cli-plugins/docker-compose'});
export const RAM_SOURCE_FILES=Object.freeze(['scripts/verification/production-ram-policy.mjs','scripts/verification/production-ram-bootstrap.mjs','scripts/verification/production-ram-daemon.mjs','scripts/verification/production-ram-image-bound.mjs','scripts/verification/production-ram-tls-passthrough.mjs']);
export const REQUIRED_CONTEXT=Object.freeze(['package.json','package-lock.json','.dockerignore','docker-compose.yml','apps/console-api/Dockerfile','apps/console-api/package.json','apps/console-api/tsconfig.json','apps/console-web/Dockerfile','apps/console-web/package.json','apps/console-web/index.html','apps/console-web/tsconfig.json','apps/console-web/vite.config.ts','apps/portal-web/Dockerfile','apps/portal-web/package.json','apps/portal-web/index.html','apps/portal-web/tsconfig.json','apps/portal-web/vite.config.ts','packages/contracts/package.json','deploy/compose/compose.production.yml','deploy/compose/compose.metrics.yml','deploy/compose/compose.production-metrics.yml','deploy/compose/compose.gitops.yml','deploy/compose/compose.production-gitops.yml','deploy/production.env.example','deploy/nginx/console-nginx.conf','deploy/nginx/default.conf','deploy/nginx/console-production.conf','deploy/nginx/portal-nginx.conf','deploy/nginx/portal.conf','deploy/nginx/portal-production.conf','deploy/loki/loki.yml','deploy/prometheus/prometheus.yml','deploy/scripts/kong-migrate.sh','deploy/scripts/kong-start.sh','deploy/scripts/kong-secure-start.sh','deploy/scripts/generate-env.mjs','deploy/scripts/enroll-metrics.mjs','deploy/scripts/prepare-metrics-storage.mjs','deploy/scripts/metrics-material.mjs','deploy/scripts/metrics-test-reference.mjs','deploy/scripts/metrics-operation-options.mjs','deploy/scripts/production-policy.mjs','deploy/metrics-collector/Dockerfile','deploy/deck-runner/Dockerfile','deploy/deck-runner/toolchain.json','deploy/deck-runner/runner.mjs','deploy/deck-runner/verify-toolchain.mjs',...RAM_SOURCE_FILES]);
const invalid=(code='RAM_PREPARATION_INPUT_INVALID')=>{throw new Error(code);};
export const isSha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
export function publicContextPath(path){
 if(typeof path!=='string'||path!==posix.normalize(path)||path.startsWith('/')||path.split('/').some(p=>!p||p==='..'||p.startsWith('.env')||['private','fixtures','artifacts','node_modules','dist','.git'].includes(p))||/[\x00-\x1f\\]/.test(path))return false;
 return REQUIRED_CONTEXT.includes(path)||/^(?:apps\/(?:console-api|console-web|portal-web)\/(?:src|public)\/|packages\/contracts\/src\/)/.test(path)||/^deploy\/metrics-collector\/[a-z][a-z0-9-]*\.mjs$/.test(path);
}
export function ramOptions(runId){
 if(typeof runId!=='string'||!/^[a-z0-9][a-z0-9-]{5,39}$/.test(runId))invalid();
 const root=`/dev/shm/kongos-production-ram-${runId}`;
 return Object.freeze({runId,root,context:`${root}/public/context`,run:`${root}/run`,private:`${root}/private`,output:`${root}/public/output`,name:`kongos-ram-tool-${runId}`,network:`kongos-ram-build-${runId}`,subnet:'172.29.250.0/24',toolIp:'172.29.250.10',project:`kongos-prod-${runId}`,restoreProject:`kongos-restore-${runId}`,socket:`unix://${root}/run/docker.sock`,repository:'/opt/kongpilot-console',ownershipLabel:'org.kongos.production-ram-run'});
}
export function validateRamGate(gate,runId){
 const options=ramOptions(runId);
 if(!gate||Object.getPrototypeOf(gate)!==Object.prototype||gate.scope!=='M0-M8-private-ram-production-acceptance'||gate.runtimeAuthorized!==true||gate.m8Closed!==true||gate.runId!==runId||gate.baseImageId!==RAM_BASE_IMAGE||!gate.sourceSha256||!gate.toolSha256||!['overlay2','vfs'].includes(gate.fallbackDriver))invalid('RAM_RELEASE_GATE_INVALID');
 for(const p of REQUIRED_CONTEXT)if(!isSha(gate.sourceSha256[p]))invalid('RAM_SOURCE_MANIFEST_INCOMPLETE');
 for(const name of Object.keys(PUBLIC_TOOLS))if(!isSha(gate.toolSha256[name]))invalid('RAM_TOOL_MANIFEST_INCOMPLETE');
 if(!isSha(gate.publicTrustSha256))invalid('RAM_TOOL_MANIFEST_INCOMPLETE');
 for(const [path,sha] of Object.entries(gate.sourceSha256)){if(!isSha(sha)||typeof path!=='string'||/[\x00-\x1f\\]/.test(path))invalid('RAM_SOURCE_MANIFEST_INVALID');}
 if(!Number.isSafeInteger(gate.evidenceAllowanceBytes)||gate.evidenceAllowanceBytes<1024*1024||gate.evidenceAllowanceBytes>32*1024**2)invalid('RAM_RELEASE_GATE_INVALID');
 return options;
}
const ip=value=>{if(typeof value!=='string'||!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value))invalid('RAM_NETWORK_FACTS_INVALID');const parts=value.split('.').map(Number);if(parts.some((n,i)=>n>255||String(n)!==value.split('.')[i]))invalid('RAM_NETWORK_FACTS_INVALID');return parts.reduce((s,n)=>s*256+n,0);};
const range=value=>{if(typeof value!=='string')invalid('RAM_NETWORK_FACTS_INVALID');const [host,prefix,...extra]=value.split('/');if(extra.length||!/^\d{1,2}$/.test(prefix)||Number(prefix)>32)invalid('RAM_NETWORK_FACTS_INVALID');const width=2**(32-Number(prefix)),low=Math.floor(ip(host)/width)*width;return[low,low+width-1];};
export function assertNewNetwork(options,subnets){
 if(!Array.isArray(subnets)||subnets.some(s=>typeof s!=='string'))invalid('RAM_NETWORK_FACTS_INVALID');
 const selected=range(options.subnet);for(const subnet of subnets){if(subnet.includes(':'))continue;const other=range(subnet);if(selected[0]<=other[1]&&other[0]<=selected[1])invalid('RAM_BUILD_NETWORK_OVERLAP');}
}
export function assertMainCapacity({availableBytes,allocatedRootfsUpperBytes,evidenceAllowanceBytes}){
 if(![availableBytes,allocatedRootfsUpperBytes,evidenceAllowanceBytes].every(n=>Number.isSafeInteger(n)&&n>=0)||allocatedRootfsUpperBytes===0)invalid('RAM_MAIN_CAPACITY_UNPROVEN');
 const required=allocatedRootfsUpperBytes+evidenceAllowanceBytes+RAM_RESERVE;if(!Number.isSafeInteger(required)||availableBytes<required)invalid('RAM_MAIN_CAPACITY_INSUFFICIENT');
 return {allocatedRootfsUpperBytes,reserveBytes:RAM_RESERVE,evidenceAllowanceBytes,requiredBytes:required};
}
export function assertRamHeadroom({tmpfsAvailableBytes,memAvailableBytes}){
 const storage=Object.values(RAM_LIMITS).reduce((a,b)=>a+b,0),memory=12*1024**3;
 if(![tmpfsAvailableBytes,memAvailableBytes].every(n=>Number.isSafeInteger(n)&&n>=0)||tmpfsAvailableBytes<storage||memAvailableBytes<memory)invalid('RAM_TMPFS_OR_MEMORY_HEADROOM_INSUFFICIENT');
 return{storagePoolLimitBytes:storage,toolHostMemoryLimitBytes:10*1024**3,protectedMemoryReserveBytes:2*1024**3};
}
export function expectedToolMounts(options){return [...Object.values(PUBLIC_TOOLS).map(source=>({source,destination:source,readOnly:true})),{source:options.context,destination:options.repository,readOnly:true},{source:options.run,destination:'/run',readOnly:false},{source:options.private,destination:'/run/kongos-private',readOnly:false},{source:options.output,destination:'/run/kongos-output',readOnly:false}];}
export function toolHostArgs(options){
 // Docker's empty PID mode is its own namespace; "private" is an invalid
 // Docker PID-mode token (unlike IPC/cgroup modes).
 // This is the isolated build daemon, not an application container: OCI
 // root filesystems and runc's private self-exec files must be executable.
 const args=['--host=unix:///var/run/docker.sock','run','-d','--pull=never','--name',options.name,'--label',`${options.ownershipLabel}=${options.runId}`,'--privileged','--network',options.network,'--ip',options.toolIp,'--ipc=private','--memory=10g','--cpus=4','--pids-limit=4096','--user','0:0','--workdir',options.repository,'--tmpfs',`/var/lib/kongos-docker:rw,nosuid,nodev,exec,size=${RAM_LIMITS.data}`,'--tmpfs','/tmp:rw,nosuid,nodev,exec,size=134217728','--tmpfs','/root/.docker:rw,nosuid,nodev,noexec,size=1048576'];
 for(const mount of expectedToolMounts(options))args.push('--mount',`type=bind,src=${mount.source},dst=${mount.destination}${mount.readOnly?',readonly':''}`);
 for(const [host,tool] of [[18443,28443],[19443,29443],[21443,31443],[22443,32443]])args.push('--publish',`127.0.0.1:${host}:${tool}/tcp`);
 args.push('--cgroupns=private','--read-only','--env',`KONGOS_RAM_RUN_ID=${options.runId}`,'--mount','type=bind,src=/etc/ssl/certs/ca-certificates.crt,dst=/etc/ssl/certs/ca-certificates.crt,readonly',RAM_BASE_IMAGE,'node','scripts/verification/production-ram-daemon.mjs');return args;
}
export function assertToolHostFacts(options,facts){
 const hc=facts?.hostConfig,nets=facts?.networks,mounts=facts?.mounts;
 if(!facts||facts.image!==RAM_BASE_IMAGE||facts.name!==options.name||facts.labels?.[options.ownershipLabel]!==options.runId||hc?.privileged!==true||hc.networkMode!==options.network||hc.pidMode!==''||hc.ipcMode!=='private'||!Array.isArray(nets)||nets.length!==1||nets[0].name!==options.network||nets[0].ip!==options.toolIp||!Array.isArray(mounts))invalid('RAM_TOOL_HOST_BOUNDARY_INVALID');
 if(hc.readOnlyRootfs!==true||hc.cgroupnsMode!=='private'||hc.memory!==10*1024**3||hc.pidsLimit!==4096||hc.nanoCpus!==4*1e9||hc.devices?.length||hc.deviceRequests?.length)invalid('RAM_TOOL_HOST_BOUNDARY_INVALID');
 const expected=[...expectedToolMounts(options),{source:'/etc/ssl/certs/ca-certificates.crt',destination:'/etc/ssl/certs/ca-certificates.crt',readOnly:true}],binds=mounts.filter(m=>m.type==='bind');if(binds.length!==expected.length||expected.some(e=>!binds.some(m=>m.source===e.source&&m.destination===e.destination&&m.readOnly===e.readOnly))||mounts.some(m=>m.type!=='bind'&&(m.type!=='tmpfs'||!['/root/.docker','/tmp','/var/lib/kongos-docker'].includes(m.destination))))invalid('RAM_TOOL_HOST_MOUNT_INVALID');
 const tmpfs=hc.tmpfs;if(!tmpfs||Object.keys(tmpfs).sort().join(',')!=='/root/.docker,/tmp,/var/lib/kongos-docker'||!tmpfs['/var/lib/kongos-docker'].includes(`size=${RAM_LIMITS.data}`))invalid('RAM_TOOL_HOST_TMPFS_INVALID');
 if(!Array.isArray(facts.published)||facts.published.length!==4||[[18443,28443],[19443,29443],[21443,31443],[22443,32443]].some(([host,tool])=>!facts.published.some(p=>p.hostIp==='127.0.0.1'&&p.hostPort===host&&p.containerPort===tool)))invalid('RAM_TOOL_HOST_PORT_INVALID');
 return true;
}
