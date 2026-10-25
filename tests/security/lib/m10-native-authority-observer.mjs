import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {optinDistFingerprint} from './m10-native-optin-observer.mjs';
import {m10DockerEnvironment} from './m10-release-evidence.mjs';

/** Root-only actual console DB observation. It runs inside the owned API as
 * the runtime role in READ ONLY and does not connect to a Kong database. */
export async function runAuthorityTimerObserver(input){
 let client;try{
  const {createRequire}=await import('node:module'),require=createRequire('/app/package.json');
  assert.equal(process.cwd(),'/app');assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-console-api-1');
  const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
  assert(['revoked','restored'].includes(input.mode));
  for(const key of ['actorId','sourceClusterId','sourceWorkspaceId','targetClusterId','targetWorkspaceId','sourceBindingId','targetBindingId','sourceRoleId','targetRoleId'])assert(uuid(input[key]));
  const f=input.timer,b=input.blockedTimer;assert(uuid(f?.id)&&uuid(b?.blockingOccurrenceId)&&f.ownerUserId===input.actorId&&f.currentVersion===b.blockingVersion&&f.currentVersion===b.currentVersion);
  assert.equal(f.policy.kind,'inspection');assert.equal(f.policy.intervalMinutes,5);assert.equal(f.policy.scope,'services');assert.equal(f.policy.paused,false);
  assert(/^[a-f\d]{64}$/.test(input.runtimeSourceSha256));assert.equal(optinDistFingerprint('/app/apps/console-api/dist'),input.runtimeDistSha256);
  const url=new URL(process.env.DATABASE_URL);assert.equal(url.hostname,'console-db');assert.equal(url.port,'5432');assert.equal(url.pathname,'/kongpilot');assert.equal(url.username,'kongpilot_lab_app');
  const {Client}=require('pg');client=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await client.connect();
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await client.query("SET LOCAL statement_timeout='5s'");
  const who=(await client.query('SELECT current_database() AS database,current_user AS role,now() AS actual_now')).rows[0];assert.equal(who.database,'kongpilot');assert.equal(who.role,'kongpilot_lab_app');
  assert(new Date(who.actual_now).getTime()>=Date.parse(f.nextRunAt),'ACTUAL_DATABASE_NATURAL_DUE_REQUIRED');
  for(const name of ['017_m10_governance.sql','018_m10_configuration_origins.sql']){
   const actual=createHash('sha256').update(readFileSync(`/app/apps/console-api/dist/infrastructure/migrations/${name}`)).digest('hex');assert.equal(actual,input.migrations[name]);
   assert.equal((await client.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name])).rows[0]?.checksum,actual);
  }
  const user=(await client.query("SELECT id,super_admin,status,force_password_change,deleted_at FROM users WHERE id=$1",[input.actorId])).rows[0];
  assert(user&&user.super_admin===false&&user.status==='active'&&!user.force_password_change&&user.deleted_at===null,'ACTUAL_NON_SUPER_TIMER_OWNER_REQUIRED');
  const bindings=(await client.query('SELECT id,user_id,role_id,cluster_id,workspace_id,status,revision FROM user_role_bindings WHERE user_id=$1 AND id=ANY($2::uuid[])',[input.actorId,[input.sourceBindingId,input.targetBindingId]])).rows;
  assert.equal(bindings.length,2);const source=bindings.find(row=>row.id===input.sourceBindingId),target=bindings.find(row=>row.id===input.targetBindingId);
  assert.equal(source.role_id,input.sourceRoleId);assert.equal(source.cluster_id,input.sourceClusterId);assert.equal(source.workspace_id,input.sourceWorkspaceId);assert.equal(source.status,input.mode==='revoked'?'revoked':'active');
  assert.equal(target.role_id,input.targetRoleId);assert.equal(target.cluster_id,input.targetClusterId);assert.equal(target.workspace_id,input.targetWorkspaceId);assert.equal(target.status,'active');
  const grants=(await client.query('SELECT module,action,scope_type,cluster_id,workspace_id,scope_values FROM iam_effective_grants WHERE user_id=$1',[input.actorId])).rows;
  assert(grants.every(g=>g.scope_type==='workspace'&&g.cluster_id!==null&&g.workspace_id!==null),'NO_GLOBAL_OR_SUPER_AUTHORITY_BORROWED');
  const sourceGrants=grants.filter(g=>g.cluster_id===input.sourceClusterId&&g.workspace_id===input.sourceWorkspaceId),targetGrants=grants.filter(g=>g.cluster_id===input.targetClusterId&&g.workspace_id===input.targetWorkspaceId);
  if(input.mode==='revoked')assert.equal(sourceGrants.length,0);else assert(sourceGrants.some(g=>g.module==='governance'&&g.action==='read'));
  for(const [module,action]of [['services','read'],['services','write'],['snapshots','read'],['snapshots','write'],['promote','read'],['promote','write']])assert(targetGrants.some(g=>g.module===module&&g.action===action));
  const root=(await client.query(`SELECT s.*,v.payload,v.policy_hmac FROM governance_schedules s JOIN governance_schedule_versions v
   ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=s.current_version
   WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3`,[f.id,input.sourceClusterId,input.sourceWorkspaceId])).rows[0];
  assert.equal(root?.owner_user_id,input.actorId);assert.equal(root.state,'active');assert.equal(root.current_version,f.currentVersion);assert.deepEqual(root.payload,f.policy);
  assert.equal(new Date(root.created_at).toISOString(),f.createdAt);assert.equal(root.revision,f.revision+1);assert(new Date(root.next_run_at).getTime()>Date.parse(f.nextRunAt));
  const occurrences=(await client.query('SELECT * FROM governance_schedule_runs WHERE schedule_id=$1 ORDER BY scheduled_at,id',[f.id])).rows;
  assert.equal(occurrences.length,1,'EXACT_SINGLE_NATURAL_AUTHORITY_OCCURRENCE_REQUIRED');const r=occurrences[0];
  assert.equal(r.id,b.blockingOccurrenceId);assert.equal(r.cluster_id,input.sourceClusterId);assert.equal(r.workspace_id,input.sourceWorkspaceId);assert.equal(r.creator_id,input.actorId);
  assert.equal(r.schedule_version,f.currentVersion);assert.equal(new Date(r.scheduled_at).toISOString(),f.nextRunAt);assert.equal(r.state,'paused_authority');assert.equal(r.error_code,'PERMISSION_DENIED');assert.equal(r.run_id,null);assert.equal(r.lease_generation,1);
  assert(new Date(r.created_at).getTime()>=Date.parse(f.nextRunAt)-1000);assert(new Date(r.completed_at).getTime()>=new Date(r.created_at).getTime());
  const blocked=(await client.query("SELECT EXISTS(SELECT 1 FROM governance_schedule_runs WHERE schedule_id=$1 AND state='paused_authority' AND schedule_version=$2) AS blocked",[f.id,f.currentVersion])).rows[0];assert.equal(blocked.blocked,true);
  const linked=(await client.query('SELECT count(*)::int AS count FROM governance_runs WHERE schedule_run_id=$1',[r.id])).rows[0];assert.equal(linked.count,0,'REVOKED_OWNER_STOPS_BEFORE_INVENTORY_RUN_REGISTRATION');
  const native=(await client.query(`SELECT count(*)::int AS count,count(*) FILTER(WHERE remote_started)::int AS started,count(*) FILTER(WHERE remote_completed)::int AS completed
   FROM mutation_operations WHERE actor_id=$1 AND cluster_id=ANY($2::uuid[])`,[input.actorId,[input.sourceClusterId,input.targetClusterId]])).rows[0];
  assert.equal(native.count,0);assert.equal(native.started,0);assert.equal(native.completed,0);
  const audit=(await client.query(`SELECT id,action,result,actor_id,cluster_id,workspace_id,entity_id,request_id FROM audit_events WHERE
   request_id=$1 AND actor_id=$2 AND cluster_id=$3 AND workspace_id=$4 AND entity_id=$5 ORDER BY occurred_at,id`,[`governance-schedule-${r.id}`,input.actorId,input.sourceClusterId,input.sourceWorkspaceId,r.id])).rows;
  assert(audit.some(a=>a.action==='governance.schedule.claim'&&a.result==='pending'));assert(audit.some(a=>a.action==='governance.schedule.failed'&&a.result==='failed'));
  await client.query('COMMIT');
  return{passed:true,mode:input.mode,consoleReadOnly:true,nonSuperOwner:true,ownerId:input.actorId,scheduleId:f.id,occurrenceId:r.id,scheduleVersion:r.schedule_version,
   scheduledAt:new Date(r.scheduled_at).toISOString(),completedAt:new Date(r.completed_at).toISOString(),occurrenceState:r.state,reasonCode:r.error_code,sourceBindingState:source.status,targetBindingState:target.status,
   sourceGrantCount:sourceGrants.length,targetGrantCount:targetGrants.length,currentVersionBlocked:true,linkedGovernanceRunCount:linked.count,mutationCount:native.count,nativeStartedCount:native.started,nativeCompletedCount:native.completed,
   auditIds:audit.map(a=>a.id),runtimeSourceSha256:input.runtimeSourceSha256,runtimeSourceAssociation:'Root deployment receipt',runtimeDistMatched:true,migrationChecksumsMatched:true,
   nativeKongWriteRequested:false,kongDatabaseAccess:false,independentWireLogClaim:false,sqlMutationRequested:false,futureClockUsed:false,fakeSidUsed:false};
 }finally{if(client){try{await client.query('ROLLBACK');}catch{}await client.end();}}
}
export function authorityTimerObserverProgram(input){
 return `import assert from 'node:assert/strict';\nimport {createHash} from 'node:crypto';\nimport {readFileSync,readdirSync} from 'node:fs';\nimport {join} from 'node:path';\n${optinDistFingerprint.toString()}\n${runAuthorityTimerObserver.toString()}\ntry {process.stdout.write(JSON.stringify(await runAuthorityTimerObserver(${JSON.stringify(input)}))+String.fromCharCode(10));} catch {process.stdout.write(JSON.stringify({passed:false,code:'M10_AUTHORITY_ACTUAL_CONSOLE_OBSERVATION_FAILED'})+String.fromCharCode(10));process.exitCode=1;}\n`;
}
export function observeAuthorityTimerConsole(input){
 const result=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2','-i','kongos-ram-tool-m08-20261012-a3',
  'docker','--host=unix:///run/docker-production.sock','exec','-i','-e','RELEASE_LAB_READY=true','-e','RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1','kongpilot-release-lab-console-api-1','node','--input-type=module'],
  {input:authorityTimerObserverProgram(input),encoding:'utf8',env:m10DockerEnvironment(),timeout:20000,maxBuffer:1024*1024});
 assert(!result.error&&result.status===0,'M10_AUTHORITY_ACTUAL_CONSOLE_OBSERVATION_FAILED');let proof;try{proof=JSON.parse(result.stdout);}catch{throw Error('M10_AUTHORITY_ACTUAL_CONSOLE_PROOF_INVALID');}
 assert.equal(proof.passed,true);return proof;
}
