import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync,lstatSync,existsSync,writeFileSync,mkdirSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {m10DockerEnvironment} from './lib/m10-release-evidence.mjs';
import {validateM10TimerManifest,validateM10TimerCurrentBFF} from './lib/m10-native-timer-worker.mjs';

const repository=resolve(dirname(new URL(import.meta.url).pathname),'../..'),privateDirectory='/dev/shm/kongpilot-release-lab',reportPath=resolve(repository,'artifacts/M10/timer-verification.json');
const privateJSON=name=>{const path=`${privateDirectory}/${name}`,stat=lstatSync(path);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600&&stat.size<=32*1024*1024);return JSON.parse(readFileSync(path,'utf8'));};
const persist=report=>{mkdirSync(dirname(reportPath),{recursive:true});if(existsSync(reportPath)){let suffix=1;while(existsSync(reportPath.replace('.json',`.attempt-${suffix}.json`)))suffix++;writeFileSync(reportPath.replace('.json',`.attempt-${suffix}.json`),readFileSync(reportPath));}writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');};
try{
 assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_M10_DEPLOYED,'true');assert.equal(process.env.RELEASE_LAB_TIMER_READY,'true');
 const state=privateJSON('m10-harness.json'),fixtures=state.timerFixtures;assert(fixtures,'REAL_BFF_REGISTERED_TIMER_FIXTURES_REQUIRED');
 const session=state.sessions.admin;assert(session?.cookie&&session.user?.id);const base=new URL(process.env.RELEASE_LAB_API??'http://172.29.250.10:5445/api/v1');assert(base.protocol==='http:'&&base.hostname==='172.29.250.10'&&base.port==='5445'&&base.pathname==='/api/v1'&&!base.username&&!base.password&&!base.search&&!base.hash);
 const read=async path=>{assert(path.startsWith('/')&&!path.includes('://')&&!path.startsWith('//'));const response=await fetch(base.origin+base.pathname+path,{method:'GET',headers:{Cookie:session.cookie},redirect:'manual',signal:AbortSignal.timeout(20000)});assert.equal(response.status,200,'CURRENT_REAL_TIMER_READER_SESSION_REQUIRED');const payload=await response.json();assert(payload.data&&payload.meta?.requestId);return{data:payload.data,requestId:payload.meta.requestId};};
 const manifest=validateM10TimerManifest(fixtures.observationManifest);assert.equal(manifest.actorId,session.user.id,'REAL_TIMER_OBSERVER_OWNER_REQUIRED');
 for(const field of ['sourceClusterId','sourceWorkspaceId','targetClusterId','targetWorkspaceId'])assert.equal(manifest[field],fixtures[field],'REAL_TIMER_FIXTURE_SCOPE_REQUIRED');
 assert(manifest.schedules.find(s=>s.kind==='inspection').id===fixtures.inspectionScheduleId&&manifest.schedules.find(s=>s.kind==='drift').id===fixtures.driftScheduleId,'ORIGINAL_TIMER_IDS_REQUIRED');
 const schedules=manifest.schedules,manifestHash=createHash('sha256').update(JSON.stringify(manifest)).digest('hex'),journalPath=`${privateDirectory}/m10-timer-observation.json`;
 let journal=existsSync(journalPath)?privateJSON('m10-timer-observation.json'):null;
 if(journal&&(journal.version!==2||journal.manifestHash!==manifestHash)){let suffix=1;while(existsSync(journalPath.replace('.json',`.attempt-${suffix}.json`)))suffix++;writeFileSync(journalPath.replace('.json',`.attempt-${suffix}.json`),readFileSync(journalPath),{mode:0o600});journal=null;}
 journal??={version:2,manifestHash,manifest,startedAt:new Date().toISOString(),observations:[]};assert.equal(journal.version,2);assert.equal(journal.manifestHash,manifestHash);
 const save=()=>writeFileSync(journalPath,JSON.stringify(journal,null,2)+'\n',{mode:0o600});save();
 const latestDue=Math.max(...schedules.map(s=>Date.parse(s.nextRunAt))),deadline=latestDue+180000;assert(deadline>Date.now(),'ORIGINAL_TIMER_OBSERVATION_WINDOW_EXPIRED');assert(deadline-Date.now()<=600000,'TIMER_REAL_WAIT_BUDGET_EXCEEDED');
 // GET only: no automatic login refresh, forced due time or manual tick.
 const access=session.cookie.split('; ').find(p=>p.startsWith('kongos_access=')),claims=access?JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1],'base64url')):null;assert(claims?.sid===session.sid&&claims?.sub===session.user.id&&claims.exp*1000>deadline,'FRESH_ORIGINAL_TIMER_READER_SESSION_REQUIRED');
 let complete=false;
 while(Date.now()<deadline){
  const observation={at:new Date().toISOString(),schedules:[]};for(const s of schedules){const response=await read(`/clusters/${fixtures.sourceClusterId}/governance/schedules/${s.id}?workspaceId=${fixtures.sourceWorkspaceId}`),at=new Date().toISOString(),verified=validateM10TimerCurrentBFF(s,response,at);observation.schedules.push({id:s.id,kind:s.kind,requestId:response.requestId,observedAt:at,state:response.data.entity.state,currentVersion:response.data.entity.currentVersion,revision:response.data.entity.revision,nextRunAt:response.data.entity.nextRunAt,executionBlocked:response.data.entity.executionBlocked,blockingState:response.data.entity.blockingState,advanced:verified.advanced});}journal.observations.push(observation);save();
  if(Date.now()>=latestDue&&observation.schedules.every(s=>s.advanced&&!s.executionBlocked)){complete=true;break;}
  process.stdout.write(JSON.stringify({event:'m10.timer.await-natural-due',observedAt:observation.at,secondsUntilLatestDue:Math.max(0,Math.ceil((latestDue-Date.now())/1000))})+'\n');await new Promise(resolve=>setTimeout(resolve,10000));
 }
 assert(complete,'ORIGINAL_TIMER_OCCURRENCE_NOT_OBSERVED');
 const worker=readFileSync(resolve(repository,'tests/security/lib/m10-native-timer-worker.mjs'),'utf8'),input=worker+'\nawait observeM10Timers('+JSON.stringify(manifest)+');\n';
 const result=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2','-i','kongos-ram-tool-m08-20261012-a3','docker','--host=unix:///run/docker-production.sock','exec','-i','-e','RELEASE_LAB_READY=true','-e','RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1','kongpilot-release-lab-console-api-1','node','--input-type=module'],{env:m10DockerEnvironment(),input,encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
 if(result.error)throw Error('OWNED_M10_TIMER_WORKER_FAILED');let report;try{report=JSON.parse(result.stdout);}catch{throw Error('PUBLIC_M10_TIMER_REPORT_UNAVAILABLE');}assert.equal(report.milestone,'M10');report.observedOnlyGET=true;report.httpReadCount=journal.observations.reduce((sum,o)=>sum+o.schedules.length,0);persist(report);
 process.stdout.write(JSON.stringify({passed:report.passed,checks:report.checks.length,timers:report.observations.length,sqlMutationRequested:false,nativeKongWriteRequested:false,futureClockUsed:false,fakeSidUsed:false})+'\n');if(!report.passed||result.status!==0)process.exitCode=1;
}catch(error){const failure={code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:'M10_TIMER_OBSERVATION_FAILED'};persist({passed:false,milestone:'M10',productionDeployment:false,checks:[],failure,observedOnlyGET:true,sqlMutationRequested:false,nativeKongWriteRequested:false,futureClockUsed:false,fakeSidUsed:false,originalResponseRewritten:false});process.stderr.write(JSON.stringify({passed:false,...failure})+'\n');process.exitCode=1;}
