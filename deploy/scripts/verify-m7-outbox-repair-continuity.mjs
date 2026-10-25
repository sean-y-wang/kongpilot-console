import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {closeSync,constants,existsSync,fstatSync,lstatSync,mkdirSync,openSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {M7_METRICS_CONTINUITY_PROGRAM} from './verify-m7-runtime-continuity.mjs';

const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const oldProjection="to_jsonb(s)-'catalog_revision'-'revision'-'updated_at'";
if(M7_METRICS_CONTINUITY_PROGRAM.split(oldProjection).length!==2)throw new Error('OUTBOX_REPAIR_PROGRAM_INVALID');
export const OUTBOX_REPAIR_READONLY_PROGRAM=M7_METRICS_CONTINUITY_PROGRAM.replace(oldProjection,"to_jsonb(s)-ARRAY['catalog_revision','catalog_status','last_verified_at','revision','updated_at']");
const output=resolve('artifacts/M7/outbox-worker-repair-continuity.json');
const run=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000});

export function outboxRepairChecks(before,after){
 const checks=[],check=(name,passed)=>checks.push({name,passed:!!passed});
 const stableAPI=row=>{const {pid,startedAt,finishedAt,...stable}=row;return stable;};
 check('same exact service set retained',JSON.stringify(before.services.map(s=>s.name))===JSON.stringify(after.services.map(s=>s.name)));
 for(const old of before.services){const next=after.services.find(s=>s.name===old.name);check(old.name+' container/environment/interfaces/storage and protected process preserved',!!next&&JSON.stringify(old.name==='console-api'?stableAPI(old):old)===JSON.stringify(old.name==='console-api'?stableAPI(next):next));}
 check('API process restarted after compiled code',after.services.find(s=>s.name==='console-api')?.startedAt!==before.services.find(s=>s.name==='console-api')?.startedAt);
 check('all source/applied 000-010 migrations and applied times unchanged',JSON.stringify(before.migrations)===JSON.stringify(after.migrations)&&JSON.stringify(before.database.migrations)===JSON.stringify(after.database.migrations));
 check('all private environments/certificates/metrics/receiver materials byte and metadata exact',JSON.stringify(before.materials)===JSON.stringify(after.materials));
 check('public deployment/ACL/portal/delivery configuration unchanged',before.configurationSHA256===after.configurationSHA256);
 for(const field of ['generations','credentials','settings'])check('stable monitoring '+field+' unchanged',JSON.stringify(before.database[field])===JSON.stringify(after.database[field]));
 check('runtime remains actual nonowner/non-super/non-bypass',before.database.nonowner===true&&after.database.nonowner===true);
 check('API and both local receivers healthy',after.services.filter(s=>['console-api','event-receiver','event-mail'].includes(s.name)).length===3&&after.services.filter(s=>['console-api','event-receiver','event-mail'].includes(s.name)).every(s=>s.health==='healthy'));
 return checks;
}

function materialSnapshot(){
 const paths=['.env','.env.multicluster','.env.portal-acceptance'];
 const walk=dir=>{for(const name of readdirSync(dir)){const path=resolve(dir,name),stat=lstatSync(path);if(stat.isSymbolicLink())throw new Error('OUTBOX_REPAIR_PRIVATE_INVALID');if(stat.isDirectory())walk(path);else if(stat.isFile())paths.push(path);else throw new Error('OUTBOX_REPAIR_PRIVATE_INVALID');}};
 for(const dir of ['deploy/private/metrics','deploy/private/event-delivery'])walk(dir);
 return paths.sort().map(path=>{const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let bytes;try{const s=fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size>4*1024*1024)throw new Error('OUTBOX_REPAIR_PRIVATE_INVALID');bytes=readFileSync(fd);return{path,inode:s.ino,mode:s.mode&0o777,uid:s.uid,gid:s.gid,mtimeMs:s.mtimeMs,size:s.size,sha256:digest(bytes)};}finally{bytes?.fill(0);closeSync(fd);}});
}

export function captureOutboxRepairSnapshot(){
 const ids=run(['ps','-aq','--filter','label=com.docker.compose.project=kongos-console']).trim().split(/\s+/).filter(Boolean);
 if(!ids.length)throw new Error('OUTBOX_REPAIR_PROJECT_UNAVAILABLE');
 const containers=JSON.parse(run(['inspect',...ids]));
 const services=containers.map(c=>({name:c.Config.Labels['com.docker.compose.service'],id:c.Id,image:c.Image,pid:c.State.Pid,startedAt:c.State.StartedAt,finishedAt:c.State.FinishedAt,status:c.State.Status,exitCode:c.State.ExitCode,health:c.State.Health?.Status??null,envSHA256:digest(JSON.stringify(c.Config.Env)),volumes:c.Mounts.filter(m=>m.Type==='volume').map(m=>({name:m.Name,target:m.Destination})).sort((a,b)=>a.target.localeCompare(b.target)),networks:Object.entries(c.NetworkSettings.Networks).map(([name,n])=>({name,id:n.NetworkID,ip:n.IPAddress})).sort((a,b)=>a.name.localeCompare(b.name))})).sort((a,b)=>a.name.localeCompare(b.name));
 if(new Set(services.map(s=>s.name)).size!==services.length)throw new Error('OUTBOX_REPAIR_DUPLICATE_SERVICE');
 const api=services.find(s=>s.name==='console-api');if(!api)throw new Error('OUTBOX_REPAIR_API_UNAVAILABLE');
 const database=JSON.parse(run(['exec',api.id,'node','-e',OUTBOX_REPAIR_READONLY_PROGRAM]));
 const directory='apps/console-api/src/infrastructure/migrations';
 const migrations=readdirSync(directory).filter(n=>n.endsWith('.sql')).sort().map(name=>({name,checksum:digest(readFileSync(join(directory,name)))}));
 const configurations=['docker-compose.yml','deploy/compose.development.yml','deploy/compose.multicluster-test.yml','deploy/compose.metrics.yml','deploy/compose.portal-acceptance.yml','deploy/compose.notifications-test.yml','deploy/nginx/default.conf','deploy/nginx/portal.conf','deploy/nginx/portal-nginx.conf','deploy/scripts/kong-secure-start.sh'];
 const configurationSHA256=digest(JSON.stringify(configurations.map(path=>({path,sha256:digest(readFileSync(path))}))));
 return{observedAt:new Date().toISOString(),services,migrations,materials:materialSnapshot(),configurationSHA256,database};
}

export function runOutboxRepairContinuity(mode){
 if(!['before','after'].includes(mode))throw new Error('OUTBOX_REPAIR_ARGUMENT_INVALID');
 mkdirSync(resolve('artifacts/M7'),{recursive:true});
 if(mode==='before'&&existsSync(output))throw new Error('OUTBOX_REPAIR_BASELINE_SEALED');
 const saved=mode==='after'?JSON.parse(readFileSync(output,'utf8')):null;
 if(saved&&(saved.label!=='outbox-worker-repair'||saved.allPassed!==null||saved.after))throw new Error('OUTBOX_REPAIR_RESULT_SEALED');
 const current=captureOutboxRepairSnapshot();
 if(mode==='before'){writeFileSync(output,JSON.stringify({label:'outbox-worker-repair',allPassed:null,before:current},null,2)+'\n',{flag:'wx'});return{baselineCaptured:true};}
 const checks=outboxRepairChecks(saved.before,current),result={...saved,after:current,checks,allPassed:checks.every(c=>c.passed),scope:'API process-only repair; stable configuration excludes observation-only catalog timestamps/status; all credentials/migrations/private materials/core processes remain exact'};
 writeFileSync(output,JSON.stringify(result,null,2)+'\n');return result;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=runOutboxRepairContinuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');console.log(JSON.stringify({baselineCaptured:result.baselineCaptured??false,allPassed:result.allPassed??null,checks:result.checks?.length??0}));if(result.allPassed===false)process.exitCode=1;}catch{process.stderr.write('OUTBOX_REPAIR_CONTINUITY_FAILED; no private values printed.\n');process.exitCode=1;}
}
