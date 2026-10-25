import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {capturePortalRepairSnapshot,nullableRepairContainerProjection,nullablePortalRepairContinuityChecks} from './verify-nullable-portal-repair-continuity.mjs';

export const FAILED_ISSUE_REPAIR_LABEL='portal-failed-issue-abandonment';
export const FAILED_ISSUE_MIGRATION='009_m6_failed_issue_abandonment.sql';
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);

export function failedIssueFixtureIds(firstProof,secondProof){
  const ids={firstWorkflowId:firstProof?.originalWorkflowId,firstExecutionId:firstProof?.originalExecutionId,failedWorkflowId:secondProof?.originalExecution?.workflowId,failedExecutionId:secondProof?.executions?.length===1?secondProof.executions[0].id:null};
  if(!Object.values(ids).every(uuid)||ids.firstWorkflowId===ids.failedWorkflowId||ids.firstExecutionId===ids.failedExecutionId)throw new Error('FAILED_ISSUE_FIXTURE_INVALID');
  return ids;
}

export function failedIssueMigrationExpectation(oldMigrations,newChecksum){
  if(!Array.isArray(oldMigrations)||oldMigrations.length!==9||!hash(newChecksum))throw new Error('FAILED_ISSUE_MIGRATIONS_INVALID');
  const old=oldMigrations.map(row=>({name:row.name,checksum:row.checksum})).sort((a,b)=>a.name.localeCompare(b.name));
  if(old.some((row,index)=>!row.name.startsWith(String(index).padStart(3,'0')+'_')||!/^\d{3}_[a-z0-9_]+\.sql$/.test(row.name)||!hash(row.checksum)))throw new Error('FAILED_ISSUE_MIGRATIONS_INVALID');
  return [...old,{name:FAILED_ISSUE_MIGRATION,checksum:newChecksum}];
}

export const FAILED_ISSUE_READONLY_PROGRAM=String.raw`
const{Pool}=require('pg'),fs=require('node:fs');
const bytes=fs.readFileSync(0);if(bytes.length>2048)process.exit(1);
const ids=JSON.parse(bytes);const names=['firstWorkflowId','firstExecutionId','failedWorkflowId','failedExecutionId'];
if(Object.keys(ids).sort().join(',')!==names.sort().join(',')||Object.values(ids).some(v=>typeof v!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v)))process.exit(1);
const digest=alias=>"encode(sha256(convert_to(to_jsonb("+alias+")::text,'UTF8')),'hex') AS \"rowSHA256\"";
(async()=>{const pool=new Pool({connectionString:process.env.DATABASE_URL});let db;try{
 db=await pool.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await db.query("SET LOCAL TIME ZONE 'UTC'");
 async function rows(sql,args){const result=await db.query(sql,args);if(result.rows.length>32)throw new Error('BOUNDED_FACTS_EXCEEDED');return result.rows;}
 async function facts(workflowId,executionId){
  const workflow=await rows('SELECT w.id,w.cluster_id,w.workspace_id,w.subject_id,w.state,w.plan_revision,w.plan_hash,'+digest('w')+' FROM workflows w WHERE w.id=$1',[workflowId]);
  if(workflow.length!==1)throw new Error('WORKFLOW_UNAVAILABLE');
  const grant=await rows('SELECT g.id,g.cluster_id,g.workspace_id,g.workflow_id,g.application_id,g.publication_id,g.consumer_id,g.acl_id,g.current_generation,g.current_credential_id,g.state,(g.reservation_released_at IS NOT NULL) AS released,'+digest('g')+' FROM portal_application_grants g WHERE g.workflow_id=$1',[workflowId]);
  if(grant.length!==1)throw new Error('GRANT_UNAVAILABLE');const g=grant[0];
  const credentials=await rows('SELECT c.id,c.grant_id,c.consumer_id,c.kong_id,c.generation,c.state,c.credential_ref_id,c.issue_operation_id,(c.last_revealed_at IS NOT NULL) AS revealed,encode(sha256(convert_to(c.key_secret,\'UTF8\')),\'hex\') AS "keyCipherSHA256",'+digest('c')+' FROM portal_credentials c WHERE c.grant_id=$1 ORDER BY c.generation,c.id',[g.id]);
  const versions=await rows('SELECT v.workflow_id,v.plan_revision,v.plan_hash,v.step_count,v.native_request_count,'+digest('v')+' FROM workflow_versions v WHERE v.workflow_id=$1 ORDER BY v.plan_revision',[workflowId]);
  const executions=await rows('SELECT e.id,e.workflow_id,e.state,e.snapshot_state,(e.completed_at IS NOT NULL) AS completed,'+digest('e')+' FROM workflow_executions e WHERE e.workflow_id=$1 ORDER BY e.id',[workflowId]);
  if(executions.length!==1||executions[0].id!==executionId)throw new Error('EXECUTION_UNAVAILABLE');
  const steps=await rows('SELECT s.id,s.step_order,s.kind,s.entity_type,s.state,s.operation_id,s.error_code,(s.receipt_secret IS NOT NULL) AS has_receipt,(s.after_fingerprint IS NOT NULL) AS has_after_fingerprint,(s.started_at IS NOT NULL) AS started,(s.completed_at IS NOT NULL) AS completed,'+digest('s')+' FROM workflow_steps s WHERE s.workflow_id=$1 ORDER BY s.step_order',[workflowId]);
  const operations=await rows('SELECT op.id,op.state,op.entity_type,op.action,op.error_code,op.remote_started,op.remote_completed,(op.result_secret IS NOT NULL) AS has_result,'+digest('op')+' FROM mutation_operations op WHERE op.workflow_id=$1 ORDER BY op.id',[workflowId]);
  const references=await rows('SELECT r.id,r.consumer_id,r.kong_id,r.credential_type,r.state,'+digest('r')+' FROM credential_refs r JOIN portal_application_grants g ON g.id=$1 WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id) AND (r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id OR r.kong_id IN(SELECT c.kong_id FROM portal_credentials c WHERE c.grant_id=g.id)) ORDER BY r.id',[g.id]);
  const approvals=await rows('SELECT a.id,'+digest('a')+' FROM workflow_approvals a WHERE a.workflow_id=$1 ORDER BY a.id',[workflowId]);
  const events=await rows('SELECT e.id,'+digest('e')+' FROM workflow_events e WHERE e.workflow_id=$1 ORDER BY e.id',[workflowId]);
  const audits=await rows('SELECT a.id,a.event_hash FROM audit_events a WHERE a.workflow_id=$1 OR a.entity_id=$2 ORDER BY a.id',[workflowId,g.id]);
  return{workflow,grant,credentials,versions,executions,steps,operations,references,approvals,events,audits};
 }
 const first=await facts(ids.firstWorkflowId,ids.firstExecutionId),failed=await facts(ids.failedWorkflowId,ids.failedExecutionId);
 const migrations=(await db.query('SELECT name,checksum,applied_at FROM schema_migrations ORDER BY name')).rows;
 const table=(await db.query("SELECT to_regclass('public.portal_failed_issue_abandonments') IS NOT NULL AS present")).rows[0].present;
 let certificateCount=null,privileges=null;if(table){certificateCount=Number((await db.query('SELECT count(*) AS count FROM portal_failed_issue_abandonments')).rows[0].count);privileges=(await db.query("SELECT has_table_privilege(current_user,'portal_failed_issue_abandonments','SELECT') AS read,has_table_privilege(current_user,'portal_failed_issue_abandonments','INSERT') AS append,has_table_privilege(current_user,'portal_failed_issue_abandonments','UPDATE') AS update,has_table_privilege(current_user,'portal_failed_issue_abandonments','DELETE') AS delete,has_table_privilege(current_user,'portal_failed_issue_abandonments','TRUNCATE') AS truncate,has_table_privilege(current_user,'portal_failed_issue_abandonments','REFERENCES') AS references,has_table_privilege(current_user,'portal_failed_issue_abandonments','TRIGGER') AS trigger")).rows[0];}
 await db.query('COMMIT');process.stdout.write(JSON.stringify({first,failed,migrations,abandonmentTable:{present:table,certificateCount,privileges}}));
 }finally{if(db){try{await db.query('ROLLBACK');}catch{}db.release();}await pool.end();}})().catch(()=>process.exit(1));
`;

export function firstIssueFactsIntact(facts){
  return facts?.grant?.length===1&&facts.grant[0].state==='active'&&facts.grant[0].current_generation===1&&facts.grant[0].released===false
    &&facts.credentials?.length===1&&facts.credentials[0].state==='active'&&facts.credentials[0].generation===1&&hash(facts.credentials[0].keyCipherSHA256)
    &&facts.executions?.length===1&&facts.executions[0].state==='succeeded'&&facts.executions[0].completed===true
    &&facts.steps?.length===4&&facts.steps.every(row=>row.state==='succeeded')&&facts.operations?.length===3&&facts.operations.every(row=>row.state==='succeeded'&&row.remote_started===true&&row.remote_completed===true)&&facts.references?.length===2;
}
export function failedIssueFactsIntact(facts){
  const first=facts?.steps?.[0];return facts?.grant?.length===1&&facts.grant[0].state==='pending'&&facts.grant[0].current_generation===0&&facts.grant[0].released===false
    &&facts.credentials?.length===1&&facts.credentials[0].state==='pending'&&facts.credentials[0].revealed===false&&facts.credentials[0].credential_ref_id===null&&facts.credentials[0].issue_operation_id===null&&hash(facts.credentials[0].keyCipherSHA256)
    &&facts.executions?.length===1&&facts.executions[0].state==='failed'&&facts.executions[0].snapshot_state==='ready'&&facts.executions[0].completed===true
    &&facts.steps?.length===4&&first?.step_order===1&&first.entity_type==='consumers'&&first.state==='failed'&&first.error_code==='KONG_VALIDATION_ERROR'
    &&facts.steps.slice(1).every(row=>row.state==='pending'&&row.operation_id===null&&row.started===false&&row.completed===false&&row.has_receipt===false&&row.has_after_fingerprint===false)
    &&facts.operations?.length===1&&facts.operations[0].entity_type==='consumers'&&facts.operations[0].action==='create'&&facts.operations[0].state==='failed'&&facts.operations[0].error_code==='KONG_VALIDATION_ERROR'&&facts.operations[0].remote_started===true&&facts.operations[0].remote_completed===false&&facts.operations[0].has_result===false&&facts.references?.length===0;
}

export function failedIssueRepairContinuityChecks(before,after,expected){
  const checks=nullablePortalRepairContinuityChecks(before.foundation,after.foundation),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const migrations=value=>value.business.migrations.map(row=>({name:row.name,checksum:row.checksum}));
  checks.push({name:'old000–008 source checksums and frozen009 source checksum retained',passed:same(before.sourceMigrations,expected)&&same(after.sourceMigrations,expected)});
  checks.push({name:'before database is exactly immutable000–008 without009',passed:same(migrations(before),expected.slice(0,9))&&before.business.abandonmentTable.present===false});
  checks.push({name:'after database adds only009 with frozen checksum; old migration rows unchanged',passed:same(migrations(after),expected)&&same(before.business.migrations,after.business.migrations.slice(0,9))});
  checks.push({name:'new abandoned-issue certificate table exists but no business abandonment executed',passed:after.business.abandonmentTable.present===true&&after.business.abandonmentTable.certificateCount===0});
  const p=after.business.abandonmentTable.privileges;checks.push({name:'runtime certificate grants allow only SELECT/INSERT and deny every mutation privilege',passed:!!p&&p.read===true&&p.append===true&&['update','delete','truncate','references','trigger'].every(key=>p[key]===false)});
  checks.push({name:'original exited migration service was not recreated or restarted by one-shot009 job',passed:same(before.migrationService,after.migrationService)&&before.migrationService.state==='exited'&&before.migrationService.exitCode===0});
  checks.push({name:'first granted credential remains active generation1 with original successful native3 and refs2',passed:firstIssueFactsIntact(before.business.first)&&firstIssueFactsIntact(after.business.first)});
  checks.push({name:'failed second issue retains one known-failed Consumer, three pristine pending steps and zero refs',passed:failedIssueFactsIntact(before.business.failed)&&failedIssueFactsIntact(after.business.failed)});
  checks.push({name:'all first-success business rows, ciphertext hash, immutable plan/audits remain exact',passed:same(before.business.first,after.business.first)});
  checks.push({name:'all second-failed business rows, ciphertext hash, failed execution/audits remain exact',passed:same(before.business.failed,after.business.failed)});
  return checks;
}

export function failedIssueSourceMigrations(expected,directory='apps/console-api/src/infrastructure/migrations'){
  return expected.map(row=>({name:row.name,checksum:createHash('sha256').update(readFileSync(resolve(directory,row.name))).digest('hex')}));
}

export function captureFailedIssueRepairSnapshot(sourceMigrations,readonlyProgram=FAILED_ISSUE_READONLY_PROGRAM){
  const foundation=capturePortalRepairSnapshot(),project=process.env.COMPOSE_PROJECT_NAME||'kongos-console';
  const ids=execFileSync('docker',['ps','-a','-q','--filter',`label=com.docker.compose.project=${project}`,'--filter','label=com.docker.compose.service=console-migrations'],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000}).trim().split(/\s+/).filter(Boolean);
  if(ids.length!==1)throw new Error('FAILED_ISSUE_MIGRATION_CONTAINER_INVALID');
  const migration=JSON.parse(execFileSync('docker',['inspect',ids[0]],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000}))[0];
  const fixture=failedIssueFixtureIds(JSON.parse(readFileSync('artifacts/M6/original-metadata-recovery-proof.json','utf8')),JSON.parse(readFileSync('artifacts/M6/second-credential-execution-failure-proof.json','utf8')));
  const business=JSON.parse(execFileSync('docker',['exec','-i',foundation.core.api.id,'node','-e',readonlyProgram],{input:JSON.stringify(fixture),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:256*1024}));
  return{foundation,migrationService:nullableRepairContainerProjection('console-migrations',migration),sourceMigrations,business};
}

export function failedIssueRepairMain(args=process.argv.slice(2)){
  if(args.length!==2||!['--before','--after'].includes(args[0])||!hash(args[1]))throw new Error('FAILED_ISSUE_REPAIR_ARGUMENTS_INVALID');
  const directory='artifacts/M6',output=resolve(directory,`${FAILED_ISSUE_REPAIR_LABEL}-repair-continuity.json`);
  const expected=failedIssueMigrationExpectation(JSON.parse(readFileSync(`${directory}/source-immutable-activation-repair-release-gate.json`,'utf8')).migrations,args[1]);
  const sourceMigrations=failedIssueSourceMigrations(expected);if(JSON.stringify(sourceMigrations)!==JSON.stringify(expected))throw new Error('FAILED_ISSUE_SOURCE_MIGRATION_CHANGED'); // No runtime calls for an unfrozen/mismatched source.
  let saved;if(args[0]==='--before'&&existsSync(output))throw new Error('FAILED_ISSUE_BASELINE_EXISTS');
  if(args[0]==='--after'){saved=JSON.parse(readFileSync(output,'utf8'));if(saved.stage!=='M6'||!saved.before||saved.label!==FAILED_ISSUE_REPAIR_LABEL||saved.allPassed!==null||Object.hasOwn(saved,'after')||Object.hasOwn(saved,'checks')||JSON.stringify(saved.expectedMigrations)!==JSON.stringify(expected))throw new Error('FAILED_ISSUE_BASELINE_INVALID');}
  const current=captureFailedIssueRepairSnapshot(sourceMigrations);mkdirSync(directory,{recursive:true});
  if(args[0]==='--before'){
    if(!firstIssueFactsIntact(current.business.first)||!failedIssueFactsIntact(current.business.failed)||JSON.stringify(current.sourceMigrations)!==JSON.stringify(expected)||JSON.stringify(current.business.migrations.map(row=>({name:row.name,checksum:row.checksum})))!==JSON.stringify(expected.slice(0,9))||current.business.abandonmentTable.present||current.migrationService.state!=='exited'||current.migrationService.exitCode!==0)throw new Error('FAILED_ISSUE_BEFORE_FACTS_INVALID');
    writeFileSync(output,JSON.stringify({stage:'M6',label:FAILED_ISSUE_REPAIR_LABEL,expectedMigrations:expected,allPassed:null,before:current},null,2)+'\n',{flag:'wx'});console.log('Failed-issue repair readonly baseline captured; no plaintext or raw errors printed.');
  }else{
    const checks=failedIssueRepairContinuityChecks(saved.before,current,expected),allPassed=checks.every(row=>row.passed);writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');console.log(JSON.stringify({checks:checks.length,passed:checks.filter(row=>row.passed).length,allPassed}));if(!allPassed)process.exitCode=1;
  }
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{failedIssueRepairMain();}catch{console.error('FAILED_ISSUE_REPAIR_CONTINUITY_FAILED; no plaintext or raw errors printed.');process.exitCode=1;}}
