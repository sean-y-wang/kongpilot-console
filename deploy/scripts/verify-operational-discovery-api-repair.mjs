import{createHash}from'node:crypto';
import{execFileSync}from'node:child_process';
import{constants,closeSync,existsSync,fstatSync,openSync,readFileSync,readdirSync,writeFileSync}from'node:fs';
import{resolve}from'node:path';
import{fileURLToPath}from'node:url';
import{portalTenantAssetManifest}from'./verify-portal-tenant-static-continuity.mjs';

const source='apps/console-api/src/modules/authorization/authorization.service.ts',compiled='apps/console-api/dist/modules/authorization/authorization.service.js';
const output='artifacts/M6/portal-operational-discovery-api-repair-continuity.json',label='portal-operational-discovery-api-repair';
const sha=value=>createHash('sha256').update(value).digest('hex'),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function materialSnapshot(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let bytes;
 try{const s=fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||s.nlink!==1||![0o400,0o600].includes(s.mode&0o777)||s.size<1||s.size>16*1024*1024)throw new Error('OPERATIONAL_REPAIR_MATERIAL_INVALID');
  bytes=readFileSync(fd);if(bytes.length!==s.size)throw new Error('OPERATIONAL_REPAIR_MATERIAL_CHANGED');return{inode:s.ino,mode:s.mode&0o777,mtimeMs:s.mtimeMs,size:s.size,sha256:sha(bytes)};
 }finally{bytes?.fill(0);closeSync(fd);}
}
export function operationalContainerProjection(row,allowApiRestart=false){
 return{name:row.Config.Labels['com.docker.compose.service'],id:row.Id,image:row.Image,status:row.State.Status,
  ...(allowApiRestart?{}:{startedAt:row.State.StartedAt,finishedAt:row.State.FinishedAt,exitCode:row.State.ExitCode}),
  envSHA256:sha(JSON.stringify([...(row.Config.Env??[])].sort())),configSHA256:sha(JSON.stringify({cmd:row.Config.Cmd,entrypoint:row.Config.Entrypoint,user:row.Config.User})),
  mounts:row.Mounts.map(r=>({type:r.Type,name:r.Name??null,source:r.Source,target:r.Destination,readOnly:!r.RW})).sort((a,b)=>a.target.localeCompare(b.target)),
  networks:Object.entries(row.NetworkSettings.Networks).map(([name,r])=>({name,id:r.NetworkID,ip:r.IPAddress})).sort((a,b)=>a.name.localeCompare(b.name))};
}
export function operationalDiscoveryChecks(before,after){
 return[
  {name:'same API container/image/environment/networks/mounts; only API process restart',passed:same(before.api,after.api)&&before.apiStartedAt!==after.apiStartedAt},
  {name:'every other running or exited service/bootstrap/migrator unchanged',passed:same(before.services,after.services)},
  {name:'all Console and Portal static paths and bytes unchanged',passed:same(before.statics,after.statics)},
  {name:'all current private environment/reference/metrics materials unchanged',passed:same(before.materials,after.materials)},
  {name:'source000–009 and complete applied migration rows unchanged',passed:same(before.migrations,after.migrations)&&same(before.sourceMigrations,after.sourceMigrations)&&same(after.sourceMigrations,after.migrations.map(({name,checksum})=>({name,checksum})))},
  {name:'frozen Authorization source retained and current compiled bytes match runtime mount',passed:before.sourceSHA256===after.sourceSHA256&&after.compiledSHA256===after.runtimeCompiledSHA256},
 ];
}
export function operationalDiscoveryPreflight(phase,expected,saved){
 if(!['--before','--after'].includes(phase)||typeof expected!=='string'||!/^[a-f0-9]{64}$/.test(expected))throw new Error('OPERATIONAL_REPAIR_ARGUMENTS_INVALID');
 if(sha(readFileSync(source))!==expected)throw new Error('OPERATIONAL_REPAIR_SOURCE_CHANGED');
 if(phase==='--before'&&existsSync(output))throw new Error('OPERATIONAL_REPAIR_BASELINE_EXISTS');
 if(phase==='--after'&&(saved?.label!==label||saved?.allPassed!==null||saved.sourceSHA256!==expected||!saved.before||Object.hasOwn(saved,'after')))throw new Error('OPERATIONAL_REPAIR_RECORD_SEALED');
}
function capture(expected){
 const env={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];
 const docker=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env,encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:4*1024*1024});
 const ids=docker(['ps','-a','-q','--filter','label=com.docker.compose.project=kongos-console']).trim().split(/\s+/).filter(Boolean);
 if(ids.length<15||ids.length>32)throw new Error('OPERATIONAL_REPAIR_SERVICE_SET_INVALID');
 const rows=JSON.parse(docker(['inspect',...ids])),api=rows.filter(r=>r.Config.Labels['com.docker.compose.service']==='console-api');
 if(api.length!==1||api[0].State.Status!=='running')throw new Error('OPERATIONAL_REPAIR_API_INVALID');
 const services=rows.filter(r=>r!==api[0]).map(r=>operationalContainerProjection(r)).sort((a,b)=>a.name.localeCompare(b.name));
 for(const required of ['kong-portal','kong-portal-db','kong-portal-migrations','console-migrations'])if(!services.some(r=>r.name===required))throw new Error('OPERATIONAL_REPAIR_SERVICE_SET_INVALID');
 const manifest=JSON.parse(readFileSync('deploy/private/metrics/manifest.json','utf8'));
 const paths=['.env','.env.multicluster','.env.portal-acceptance','/tmp/kongos-m6-runtime-secrets.json','deploy/private/metrics/manifest.json','deploy/private/metrics/collector/credentials.json','deploy/private/metrics/prometheus/prometheus.yml'];
 if(!Array.isArray(manifest.clusters)||manifest.clusters.length>8||manifest.clusters.some(row=>typeof row.clusterId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(row.clusterId)))throw new Error('OPERATIONAL_REPAIR_MATERIAL_INVALID');
 for(const row of manifest.clusters)for(const purpose of ['native_scrape','collector_scrape'])paths.push(`deploy/private/metrics/prometheus/${row.clusterId}-${purpose}.token`);
 const materials=Object.fromEntries(paths.sort().map(path=>[path,materialSnapshot(path)]));
 const program=String.raw`const{Pool}=require('pg'),{createHash}=require('node:crypto'),fs=require('node:fs');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});let d;try{d=await p.connect();await d.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await d.query("SET LOCAL statement_timeout='10s'");const migrations=(await d.query('SELECT name,checksum,applied_at FROM schema_migrations ORDER BY name LIMIT 11')).rows;if(migrations.length!==10)throw new Error();const runtimeCompiledSHA256=createHash('sha256').update(fs.readFileSync('/app/apps/console-api/dist/modules/authorization/authorization.service.js')).digest('hex');await d.query('COMMIT');process.stdout.write(JSON.stringify({migrations,runtimeCompiledSHA256}));}finally{if(d)d.release();await p.end();}})().catch(()=>process.exit(1));`;
 const database=JSON.parse(docker(['exec','-i',api[0].Id,'node','-e',program]));
 const dir='apps/console-api/src/infrastructure/migrations',sourceMigrations=readdirSync(dir).filter(name=>/^00[0-9]_.*\.sql$/.test(name)).sort().map(name=>({name,checksum:sha(readFileSync(`${dir}/${name}`))}));
 return{observedAt:new Date().toISOString(),api:operationalContainerProjection(api[0],true),apiStartedAt:api[0].State.StartedAt,services,materials,
  statics:{console:portalTenantAssetManifest('apps/console-web/dist'),portal:portalTenantAssetManifest('apps/portal-web/dist')},
  migrations:database.migrations,sourceMigrations,sourceSHA256:expected,compiledSHA256:sha(readFileSync(compiled)),runtimeCompiledSHA256:database.runtimeCompiledSHA256};
}
export function operationalDiscoveryMain(args){
 if(args.length!==2)throw new Error('OPERATIONAL_REPAIR_ARGUMENTS_INVALID');const[phase,expected]=args;
 const saved=phase==='--after'&&existsSync(output)?JSON.parse(readFileSync(output,'utf8')):null;
 operationalDiscoveryPreflight(phase,expected,saved);const current=capture(expected);
 if(phase==='--before'){writeFileSync(output,JSON.stringify({stage:'M6',label,sourceSHA256:expected,allPassed:null,before:current},null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({baseline:true,preservedOtherServices:current.services.length}));return;}
 const checks=operationalDiscoveryChecks(saved.before,current),allPassed=checks.every(r=>r.passed);writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed,epochsQueried:false,metricsSettingsQueried:false},null,2)+'\n');
 console.log(JSON.stringify({checks:checks.length,passed:checks.filter(r=>r.passed).length,allPassed,preservedOtherServices:current.services.length}));if(!allPassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try{operationalDiscoveryMain(process.argv.slice(2));}catch{console.error('OPERATIONAL_REPAIR_CONTINUITY_FAILED; raw errors withheld.');process.exitCode=1;}
