import{execFileSync}from'node:child_process';
import{createHash}from'node:crypto';
import{closeSync,constants,existsSync,fstatSync,lstatSync,mkdirSync,openSync,readFileSync,readdirSync,writeFileSync}from'node:fs';
import{resolve}from'node:path';
import{fileURLToPath}from'node:url';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const M7_METRICS_CONTINUITY_PROGRAM=String.raw`const{Pool}=require('pg');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL,statement_timeout:10000});const c=await p.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const migrations=(await c.query('SELECT name,checksum,applied_at FROM schema_migrations ORDER BY name')).rows;const generations=(await c.query('SELECT cluster_id,credential_generation FROM metrics_settings ORDER BY cluster_id')).rows;const credentials=(await c.query("SELECT count(*)::int AS count,encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(k) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex') AS sha256 FROM metrics_credentials k")).rows[0];const settings=(await c.query("SELECT count(*)::int AS count,encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(s)-'catalog_revision'-'revision'-'updated_at' ORDER BY cluster_id),'[]'::jsonb)::text,'UTF8')),'hex') AS sha256 FROM metrics_settings s")).rows[0];const progress=(await c.query('SELECT cluster_id,catalog_revision FROM metrics_settings ORDER BY cluster_id')).rows;const role=(await c.query("SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls,EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)) AS owns_public_relation FROM pg_roles WHERE rolname=current_user")).rows[0];await c.query('COMMIT');console.log(JSON.stringify({migrations,generations,credentials,settings,catalogProgress:progress,nonowner:role&&!Object.values(role).some(Boolean)}));}finally{c.release();await p.end();}})().catch(()=>process.exit(1));`;
export function m7ContinuityChecks(before,after){
 const checks=[],add=(name,value)=>checks.push({name,passed:!!value});
 for(const old of before.services){const next=after.services.find(row=>row.name===old.name);if(['console-api','console-web','portal-web'].includes(old.name)){
  add(old.name+' image and named volumes preserved',!!next&&old.image===next.image&&JSON.stringify(old.volumes)===JSON.stringify(next.volumes));
  if(old.name!=='console-api')add(old.name+' original container/environment/interfaces preserved',!!next&&old.id===next.id&&old.envSHA256===next.envSHA256&&JSON.stringify(old.networks)===JSON.stringify(next.networks));
  else add('API original interfaces preserved while delivery interface is added',!!next&&old.networks.every(network=>next.networks.some(row=>JSON.stringify(row)===JSON.stringify(network))));
 }else add(old.name+' exact container/process/environment/interfaces/storage preserved',!!next&&JSON.stringify(old)===JSON.stringify(next));}
 add('all previous migrations checksums and applied times unchanged',before.database.migrations.every(row=>after.database.migrations.some(next=>JSON.stringify(row)===JSON.stringify(next))));
 add('only append010 migration added',after.database.migrations.length===before.database.migrations.length+1&&after.database.migrations.some(row=>row.name==='010_m7_events.sql'));
 add('canonical private files exact metadata and bytes unchanged',JSON.stringify(before.materials)===JSON.stringify(after.materials));
 add('monitoring generations unchanged',JSON.stringify(before.database.generations)===JSON.stringify(after.database.generations));
 add('monitoring credential families and ciphertext unchanged',JSON.stringify(before.database.credentials)===JSON.stringify(after.database.credentials));
 add('monitoring settings configuration unchanged',JSON.stringify(before.database.settings)===JSON.stringify(after.database.settings));
 add('API runtime remains non-owner non-super non-bypass',before.database.nonowner===true&&after.database.nonowner===true);
 return checks;
}
function canonicalMaterials(){
 const paths=['.env','.env.multicluster','.env.portal-acceptance'];
 const walk=directory=>{for(const name of readdirSync(directory)){const path=resolve(directory,name),info=lstatSync(path);if(info.isSymbolicLink())throw new Error('M7_PRIVATE_LINK_REJECTED');if(info.isDirectory())walk(path);else if(info.isFile())paths.push(path);else throw new Error('M7_PRIVATE_FILE_REJECTED');}};
 if(existsSync('deploy/private/metrics'))walk('deploy/private/metrics');
 return paths.sort().map(path=>{let fd;try{fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const info=fstatSync(fd);if(!info.isFile()||info.nlink!==1||info.size>4*1024*1024)throw new Error('M7_PRIVATE_FILE_REJECTED');const bytes=readFileSync(fd);try{return{path,bytes:bytes.length,sha256:sha(bytes),inode:info.ino,mode:info.mode&0o777,uid:info.uid,gid:info.gid,mtime:info.mtimeMs};}finally{bytes.fill(0);}}finally{if(fd!==undefined)closeSync(fd);}});
}
function capture(){
 const run=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000});
 const ids=run(['ps','-aq','--filter','label=com.docker.compose.project=kongos-console']).trim().split(/\s+/).filter(Boolean);if(!ids.length)throw new Error('M7_PROJECT_UNAVAILABLE');
 const containers=JSON.parse(run(['inspect',...ids])),services=containers.filter(row=>!['event-receiver','event-mail'].includes(row.Config.Labels['com.docker.compose.service'])).map(row=>({name:row.Config.Labels['com.docker.compose.service'],id:row.Id,image:row.Image,startedAt:row.State.StartedAt,finishedAt:row.State.FinishedAt,status:row.State.Status,exitCode:row.State.ExitCode,envSHA256:sha(JSON.stringify(row.Config.Env)),volumes:row.Mounts.filter(m=>m.Type==='volume').map(m=>({name:m.Name,target:m.Destination})).sort((a,b)=>a.target.localeCompare(b.target)),networks:Object.entries(row.NetworkSettings.Networks).map(([name,n])=>({name,id:n.NetworkID,ip:n.IPAddress})).sort((a,b)=>a.name.localeCompare(b.name))})).sort((a,b)=>a.name.localeCompare(b.name));
 if(new Set(services.map(row=>row.name)).size!==services.length)throw new Error('M7_PROJECT_DUPLICATE');const api=services.find(row=>row.name==='console-api');if(!api)throw new Error('M7_API_UNAVAILABLE');
 const database=JSON.parse(run(['exec',api.id,'node','-e',M7_METRICS_CONTINUITY_PROGRAM]));
 return{observedAt:new Date().toISOString(),services,materials:canonicalMaterials(),database};
}
export function executeM7Continuity(mode){
 const directory=resolve('artifacts/M7'),baseline=resolve(directory,'runtime-before.json'),output=resolve(directory,'runtime-continuity.json');mkdirSync(directory,{recursive:true});
 if(!['before','after'].includes(mode)||existsSync(mode==='before'?baseline:output))throw new Error('M7_CONTINUITY_SEALED');
 if(mode==='after'&&!existsSync(baseline))throw new Error('M7_CONTINUITY_BASELINE_MISSING');
 const before=mode==='after'?JSON.parse(readFileSync(baseline,'utf8')):null,current=capture();
 if(mode==='before'){writeFileSync(baseline,JSON.stringify(current,null,2)+'\n',{flag:'wx'});return{allPassed:true,baselineCaptured:true};}
 const checks=m7ContinuityChecks(before,current),result={scope:'core process/storage/materials and stable monitoring configuration; catalog revisions may advance legitimately',observedAt:current.observedAt,allPassed:checks.every(row=>row.passed),checks,before,after:current};
 writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=executeM7Continuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');process.stdout.write(JSON.stringify({allPassed:result.allPassed,checks:result.checks?.length??0,baselineCaptured:result.baselineCaptured??false})+'\n');if(!result.allPassed)process.exitCode=1;}catch{process.stderr.write('M7_CONTINUITY_FAILED; no private data recorded.\n');process.exitCode=1;}
}
