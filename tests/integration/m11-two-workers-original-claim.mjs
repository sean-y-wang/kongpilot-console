import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const keys=['version','milestone','capsule','clusterId','workspaceId','scheduleId','workflowId','notBefore'];
const fail=code=>{throw Error(code);};

/** Read-only fixture identity. This manifest contains no principal, SID,
 * delegation, approval, copied claim or substitute native permission. */
export function validateM11TwoWorkerManifest(input){
  if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).sort().join(',')!==[...keys].sort().join(','))fail('M11_TWO_WORKER_MANIFEST_INVALID');
  if(input.version!==1||input.milestone!=='M11'||!['a','b'].includes(input.capsule)
    ||['clusterId','workspaceId','scheduleId','workflowId'].some(key=>!uuid(input[key]))
    ||typeof input.notBefore!=='string'||!Number.isFinite(Date.parse(input.notBefore))||new Date(input.notBefore).toISOString()!==input.notBefore)fail('M11_TWO_WORKER_MANIFEST_INVALID');
  return Object.freeze({...input});
}
export function assertM11TwoWorkerDue(ids,scheduleId){
  if(!Array.isArray(ids)||ids.length>1||ids.some(id=>id!==scheduleId))fail('M11_TWO_WORKER_FOREIGN_DUE_ID');
}
export function validateM11TwoWorkerTick(result){
  if(!result||Object.keys(result).sort().join(',')!==['checked','claimed','completed','blocked','busy'].sort().join(',')
    ||['checked','claimed','completed','blocked'].some(key=>!Number.isSafeInteger(result[key])||result[key]<0||result[key]>1)
    ||result.busy!==false||result.claimed>result.checked||result.completed>result.claimed||result.blocked>result.checked)fail('M11_TWO_WORKER_TICK_RESULT_INVALID');
  return {...result};
}
const assertEnvironment=manifest=>{
  assert.equal(process.env.RELEASE_LAB_READY,'true');
  assert.equal(process.env.RELEASE_LAB_M11_TWO_WORKERS_READY,'true');
  assert.equal(process.env.RELEASE_LAB_CONTAINER,`kongpilot-release-lab-m11-scheduled-worker-${manifest.capsule}`);
  assert.equal(process.env.ENTITY_SCHEDULES_ENABLED,'false');
  assert.equal(process.env.SKIP_MIGRATIONS,'true');
  assert.equal(process.cwd(),'/app');
  const db=new URL(process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL);
  assert(['postgres:','postgresql:'].includes(db.protocol));assert.equal(db.hostname,'console-db');assert.equal(db.port,'5432');
  assert.equal(db.pathname,'/kongpilot');assert.equal(decodeURIComponent(db.username),'kongpilot_lab_app');
};
async function readManifest(){
  let raw='';for await(const chunk of process.stdin){raw+=chunk.toString('utf8');if(Buffer.byteLength(raw)>16384)fail('M11_TWO_WORKER_INPUT_BUDGET');}
  return validateM11TwoWorkerManifest(JSON.parse(raw));
}
/** Root alone runs two separate copies of this capsule after real approval,
 * logout and API timer shutdown. No repository method is overwritten and no
 * due ID is supplied to tick: original runtime policy creates every claim.
 * Output is orchestration evidence; Root independently verifies the actual
 * claim/source/native/outcome/audit rows and never infers success from counts. */
export async function runM11OriginalWorkerCapsule(manifest){
  const fixture=validateM11TwoWorkerManifest(manifest),report={version:1,milestone:'M11',capsule:fixture.capsule,
    scheduleId:fixture.scheduleId,passed:false,productionDeployment:false,overallM11Accepted:false,
    genuineOriginalWorker:false,tickInvocations:0,checks:[]};
  let app,stage='environment',originalPeek,context,repository,worker;
  const check=(name,facts={})=>report.checks.push({name,passed:true,...facts});
  try{
    assertEnvironment(fixture);check('fixed-isolated-console-capsule-and-disabled-timer');
    const require=createRequire('/app/apps/console-api/package.json');require('reflect-metadata');
    const{NestFactory}=require('@nestjs/core'),{AppModule}=require('/app/apps/console-api/dist/app.module.js');
    const{NativeKongPolicyService}=require('/app/apps/console-api/dist/modules/authorization/native-kong-policy.service.js');
    const{KongExecutionContextService}=require('/app/apps/console-api/dist/infrastructure/kong/execution-context.service.js');
    const{DbService}=require('/app/apps/console-api/dist/infrastructure/db.service.js');
    const{EntityChangeScheduleRepository}=require('/app/apps/console-api/dist/modules/workflows/entity-change-schedule.repository.js');
    const{EntityChangeScheduleWorker}=require('/app/apps/console-api/dist/modules/workflows/entity-change-schedule.worker.js');
    stage='bootstrap';app=await NestFactory.create(AppModule,{logger:false,abortOnError:false});
    app.get(NativeKongPolicyService).install();await app.init();
    context=app.get(KongExecutionContextService);repository=app.get(EntityChangeScheduleRepository);worker=app.get(EntityChangeScheduleWorker);
    report.genuineOriginalWorker=true;
    originalPeek=context.peek();assert.equal(originalPeek,null);report.contextBeforeNull=true;
    check('native-policy-installed-before-original-app-init-and-context-null');
    const db=app.get(DbService),current=()=>db.one(`SELECT s.id,s.cluster_id,s.workspace_id,s.not_before,p.state,p.claim_id,a.workflow_id,
      (s.not_before<=clock_timestamp()) AS due FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
      JOIN entity_change_schedule_activations a ON a.schedule_id=s.id WHERE s.id=$1`,[fixture.scheduleId]);
    stage='scope';const before=await current();
    if(!before||before.id!==fixture.scheduleId||before.cluster_id!==fixture.clusterId||before.workspace_id!==fixture.workspaceId
      ||before.workflow_id!==fixture.workflowId||new Date(before.not_before).toISOString()!==fixture.notBefore)fail('M11_TWO_WORKER_ACTUAL_SCOPE_MISMATCH');
    check('actual-persisted-schedule-scope-and-not-before',{scheduleId:before.id});
    stage='wait';const started=Date.now(),dueAt=Date.parse(fixture.notBefore);
    if(dueAt-started>60000)fail('M11_TWO_WORKER_WAIT_BUDGET');
    // Waiting only for an actual approved notBefore creates no claim and is
    // bounded; there is no worker retry, fake clock or looping tick.
    while(Date.now()<dueAt){if(Date.now()-started>=60000)fail('M11_TWO_WORKER_WAIT_BUDGET');await new Promise(done=>setTimeout(done,Math.min(1000,dueAt-Date.now())));}
    const now=await current();if(!now?.due)fail('M11_TWO_WORKER_NOT_YET_DUE');
    check('actual-database-not-before-reached',{waitedMs:Date.now()-started});
    assert.equal(context.peek(),null);
    stage='original-due';const due=await repository.listDue(25);assertM11TwoWorkerDue(due,fixture.scheduleId);
    if(!due.length){const claimed=await current();
      if(!claimed?.claim_id||!['claimed','running','succeeded','partial','failed','uncertain'].includes(claimed.state))fail('M11_TWO_WORKER_EMPTY_WITHOUT_ORIGINAL_CLAIM');}
    report.dueBefore=due.length;check('original-list-due-is-own-id-or-already-originally-claimed',{dueCount:due.length});
    assert.equal(context.peek(),null);assert.equal(process.env.ENTITY_SCHEDULES_ENABLED,'false');
    stage='single-original-tick';report.tickInvocations=1;
    report.result=validateM11TwoWorkerTick(await worker.tick());
    assert.equal(context.peek(),null);report.contextAfterNull=true;
    check('one-genuine-original-worker-tick-without-actor-or-session-substitution',report.result);
    report.passed=true;
  }catch(error){
    report.passed=false;report.failure={stage,code:/^M11_TWO_WORKER_[A-Z0-9_]+$/.test(error?.message??'')?error.message:'M11_TWO_WORKER_CAPSULE_FAILED'};
  }finally{
    if(app){try{await app.close();report.appClosed=true;}catch{report.passed=false;report.appClosed=false;report.failure={stage:'close',code:'M11_TWO_WORKER_APP_CLOSE_FAILED'};}}
  }
  return report;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  let report;try{report=await runM11OriginalWorkerCapsule(await readManifest());}
  catch{report={version:1,milestone:'M11',passed:false,tickInvocations:0,productionDeployment:false,overallM11Accepted:false,failure:{stage:'manifest',code:'M11_TWO_WORKER_MANIFEST_INVALID'}};}
  process.stdout.write(JSON.stringify(report)+'\n');if(!report.passed)process.exitCode=1;
}
