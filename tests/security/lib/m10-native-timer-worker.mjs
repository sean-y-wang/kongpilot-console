import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire('/app/package.json');
const uuid=value=>typeof value==='string'&&/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value);
const timestamp=value=>{const at=value instanceof Date?value.getTime():typeof value==='string'?Date.parse(value):NaN;assert(Number.isFinite(at),'ACTUAL_TIMER_TIMESTAMP_REQUIRED');return at;};
const policyKeys=Object.freeze(['name','kind','scope','serviceIds','ruleCodes','target','intervalMinutes','timezone','threshold','includeEnvironmentFields','paused']);
const timerPolicy=value=>Object.fromEntries(policyKeys.filter(key=>Object.hasOwn(value,key)).map(key=>[key,structuredClone(value[key])]));

/** Public GET evidence only. No inferred version, reconstructed revision or
 * substitution of a registration response for the current observed policy. */
export function buildM10TimerScheduleFixture(receipt,{observedAt,actorId,id,kind}){
 const entity=receipt?.data?.entity;assert(entity&&typeof entity==='object','ACTUAL_BFF_TIMER_ENTITY_REQUIRED');assert(uuid(id)&&entity.id===id,'ACTUAL_BFF_TIMER_ID_REQUIRED');
 assert(entity.kind===kind&&['inspection','drift'].includes(kind),'ACTUAL_BFF_TIMER_KIND_REQUIRED');assert(entity.ownerUserId===actorId,'ACTUAL_BFF_TIMER_OWNER_REQUIRED');
 assert(typeof receipt.requestId==='string'&&receipt.requestId.length>0&&receipt.requestId.length<=128,'ACTUAL_BFF_TIMER_REQUEST_ID_REQUIRED');
 const fixture={id,kind,ownerUserId:entity.ownerUserId,currentVersion:entity.currentVersion,revision:entity.revision,createdAt:entity.createdAt,nextRunAt:entity.nextRunAt,
  observedAt,requestId:receipt.requestId,state:entity.state,enabled:entity.enabled,executionBlocked:entity.executionBlocked,policy:timerPolicy(entity)};
 if(entity.policyHash!==undefined)fixture.policyHash=entity.policyHash;
 validateM10TimerScheduleFixture(fixture,actorId);return fixture;
}
export function validateM10TimerScheduleFixture(fixture,actorId){
 assert(uuid(fixture?.id)&&['inspection','drift'].includes(fixture.kind),'ACTUAL_TIMER_FIXTURE_REQUIRED');assert(uuid(actorId)&&fixture.ownerUserId===actorId,'ACTUAL_TIMER_OWNER_REQUIRED');
 assert(Number.isSafeInteger(fixture.currentVersion)&&fixture.currentVersion>=1,'ACTUAL_TIMER_VERSION_REQUIRED');assert(Number.isSafeInteger(fixture.revision)&&fixture.revision>=fixture.currentVersion,'ACTUAL_TIMER_REVISION_REQUIRED');
 assert(fixture.state==='active'&&fixture.enabled===true&&fixture.executionBlocked===false,'ACTIVE_UNBLOCKED_TIMER_SEED_REQUIRED');
 assert(typeof fixture.requestId==='string'&&fixture.requestId.length>0&&fixture.requestId.length<=128,'ACTUAL_BFF_TIMER_REQUEST_ID_REQUIRED');
 const observed=timestamp(fixture.observedAt),due=timestamp(fixture.nextRunAt),created=timestamp(fixture.createdAt);
 assert(created<=observed&&due>observed&&due-created>=295000,'ACTUAL_FUTURE_TIMER_DUE_REQUIRED');
 assert(fixture.policy&&fixture.policy.kind===fixture.kind&&fixture.policy.intervalMinutes===5&&fixture.policy.paused===false,'IMMUTABLE_FIVE_MINUTE_TIMER_POLICY_REQUIRED');
 assert.deepEqual(fixture.policy,timerPolicy(fixture.policy),'ACTUAL_PUBLIC_TIMER_POLICY_REQUIRED');
 if(fixture.policyHash!==undefined)assert(typeof fixture.policyHash==='string'&&/^[a-f\d]{64}$/.test(fixture.policyHash),'ACTUAL_PUBLIC_TIMER_POLICY_HASH_REQUIRED');
}
export function validateM10TimerManifest(manifest){
 assert(manifest?.version===2&&manifest.milestone==='M10','CURRENT_TIMER_OBSERVATION_MANIFEST_REQUIRED');
 for(const value of [manifest.actorId,manifest.sourceClusterId,manifest.sourceWorkspaceId,manifest.targetClusterId,manifest.targetWorkspaceId])assert(uuid(value),'ACTUAL_TIMER_SCOPE_REQUIRED');
 assert(manifest.sourceClusterId!==manifest.targetClusterId,'DISTINCT_TIMER_ENVIRONMENTS_REQUIRED');
 assert(Array.isArray(manifest.schedules)&&manifest.schedules.length===2&&new Set(manifest.schedules.map(s=>s.id)).size===2&&new Set(manifest.schedules.map(s=>s.kind)).size===2,'EXACT_TIMER_PAIR_REQUIRED');
 for(const fixture of manifest.schedules){validateM10TimerScheduleFixture(fixture,manifest.actorId);if(fixture.kind==='drift')assert(fixture.policy.target?.clusterId===manifest.targetClusterId&&fixture.policy.target?.workspaceId===manifest.targetWorkspaceId,'ACTUAL_TIMER_TARGET_POLICY_REQUIRED');}
 return manifest;
}
export function validateM10TimerCurrentBFF(fixture,receipt,observedAt){
 const entity=receipt?.data?.entity;assert(entity?.id===fixture.id&&entity.ownerUserId===fixture.ownerUserId&&entity.kind===fixture.kind,'CURRENT_TIMER_IDENTITY_CHANGED');
 assert(entity.currentVersion===fixture.currentVersion,'CURRENT_TIMER_VERSION_CHANGED');assert(Number.isSafeInteger(entity.revision)&&entity.revision>=fixture.revision,'CURRENT_TIMER_REVISION_CHANGED');
 assert(entity.state==='active'&&entity.enabled===true&&timestamp(entity.createdAt)===timestamp(fixture.createdAt),'CURRENT_TIMER_POLICY_CLOSED');assert.deepEqual(timerPolicy(entity),fixture.policy,'CURRENT_TIMER_POLICY_CHANGED');
 if(fixture.policyHash!==undefined)assert(entity.policyHash===fixture.policyHash,'CURRENT_TIMER_POLICY_CHANGED');
 const due=timestamp(entity.nextRunAt);assert(due>=timestamp(fixture.nextRunAt),'CURRENT_TIMER_DUE_CHANGED');
 if(due>timestamp(fixture.nextRunAt))assert(timestamp(observedAt)>=timestamp(fixture.nextRunAt)-1000,'TIMER_ADVANCED_BEFORE_NATURAL_DUE');
 return{advanced:due>timestamp(fixture.nextRunAt),executionBlocked:entity.executionBlocked===true};
}
export function assertM10TimerRoot(fixture,root,manifest,newOccurrences,fingerprint){
 assert(root?.id===fixture.id&&root.cluster_id===manifest.sourceClusterId&&root.workspace_id===manifest.sourceWorkspaceId&&root.owner_user_id===fixture.ownerUserId,'TIMER_ROOT_IDENTITY_CHANGED');
 assert(root.state==='active'&&root.current_version===fixture.currentVersion&&root.policy_version===fixture.currentVersion,'TIMER_CURRENT_VERSION_CHANGED');
 assert(timestamp(root.created_at)===timestamp(fixture.createdAt)&&timestamp(root.policy_created_at)<=timestamp(fixture.observedAt),'TIMER_ROOT_CREATED_AT_CHANGED');
 assert.deepEqual(root.payload,fixture.policy,'TIMER_IMMUTABLE_POLICY_CHANGED');assert.equal(root.policy_hmac,fingerprint(root.payload),'TIMER_IMMUTABLE_POLICY_HASH_CHANGED');if(fixture.policyHash!==undefined)assert.equal(root.policy_hmac,fixture.policyHash,'TIMER_PUBLIC_POLICY_HASH_CHANGED');
 assert(Array.isArray(newOccurrences)&&newOccurrences.length>0&&newOccurrences.length<20,'EXACT_NEW_TIMER_CLAIMS_REQUIRED');
 for(const occurrence of newOccurrences){assert(occurrence.schedule_id===fixture.id&&occurrence.cluster_id===manifest.sourceClusterId&&occurrence.workspace_id===manifest.sourceWorkspaceId&&occurrence.creator_id===fixture.ownerUserId,'TIMER_NEW_CLAIM_SCOPE_CHANGED');
  assert(occurrence.schedule_version===fixture.currentVersion,'STALE_TIMER_VERSION_NEW_OCCURRENCE');assert(timestamp(occurrence.created_at)>=timestamp(fixture.observedAt)&&timestamp(occurrence.scheduled_at)>=timestamp(fixture.nextRunAt)&&timestamp(occurrence.created_at)>=timestamp(occurrence.scheduled_at)-1000,'TIMER_NEW_CLAIM_TIME_CHANGED');
  assert(['succeeded','incomplete'].includes(occurrence.state),'CURRENT_TIMER_CLAIM_UNRESOLVED');}
 assert(root.revision===fixture.revision+newOccurrences.length,'TIMER_REVISION_NOT_EXPLAINED_BY_NATURAL_CLAIMS');
 assert(timestamp(root.next_run_at)>timestamp(fixture.nextRunAt),'TIMER_NATURAL_CLAIM_NOT_ADVANCED');
}
export function decodeM10TimerInventory(kind,envelope,hmac,fingerprint){
 assert.equal(fingerprint(envelope),hmac,'TIMER_INVENTORY_HMAC_CHANGED');
 if(kind==='inspection'){assert(envelope?.version==='1.5.1','CURRENT_TIMER_INSPECTION_INVENTORY_REQUIRED');return{value:envelope,version:null};}
 assert(kind==='drift'&&envelope?.version===2,'CURRENT_TIMER_V2_COMPARISON_REQUIRED');
 assert.deepEqual(Object.keys(envelope).sort(),['inventory','nativeFingerprints','version'],'CURRENT_TIMER_V2_ENVELOPE_INVALID');const value=envelope.inventory,raw=envelope.nativeFingerprints;
 assert(value&&typeof value==='object'&&Array.isArray(value.objects)&&raw&&typeof raw==='object'&&!Array.isArray(raw),'CURRENT_TIMER_V2_ENVELOPE_INVALID');
 const keys=value.objects.map(o=>{assert(uuid(o.nativeId)&&[...['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','targets']].includes(o.entityType),'CURRENT_TIMER_V2_OBJECT_INVALID');return`${o.entityType}:${o.nativeId}`;});
 assert(new Set(keys).size===keys.length,'CURRENT_TIMER_V2_DUPLICATE_OBJECT');assert.deepEqual(Object.keys(raw).sort(),keys.sort(),'CURRENT_TIMER_V2_RAW_MAP_INCOMPLETE');for(const fp of Object.values(raw))assert(typeof fp==='string'&&/^[a-f\d]{64}$/.test(fp),'CURRENT_TIMER_V2_RAW_MAP_INVALID');
 return{value,version:2};
}

/** Own runtime SQL observation only. No INSERT/UPDATE/DELETE, source mutation,
 * future clock, force-claim, login impersonation or inferred native success. */
export async function observeM10Timers(manifest){
 const checks=[];let client,passed=false,failure;const observations=[];
 const check=async(name,fn)=>{try{const facts=await fn();checks.push({name,passed:true,...(facts??{})});}catch(error){checks.push({name,passed:false,code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:'ASSERTION_FAILED'});throw error;}};
 try{
  await check('fixed own console runtime and exact real schedule fixtures',async()=>{
   assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-console-api-1');validateM10TimerManifest(manifest);
   const url=new URL(process.env.DATABASE_URL);assert.equal(url.hostname,'console-db');assert.equal(url.port,'5432');assert.equal(url.pathname,'/kongpilot');assert.equal(url.username,'kongpilot_lab_app');
   client=new(require('pg').Client)({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await client.connect();await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await client.query("SET LOCAL statement_timeout='10s'");
  });
  require('reflect-metadata');const {SecretService}=require('/app/apps/console-api/dist/infrastructure/secret.service.js'),secrets=new SecretService();
  for(const fixture of manifest.schedules){
   const rows=(await client.query(`SELECT s.id,s.cluster_id,s.workspace_id,s.owner_user_id,s.state,s.current_version,s.revision,s.created_at,s.next_run_at,v.version AS policy_version,v.created_at AS policy_created_at,v.payload,v.policy_hmac
    FROM governance_schedules s JOIN governance_schedule_versions v ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=$4
    WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3 AND s.current_version=$4`,[fixture.id,manifest.sourceClusterId,manifest.sourceWorkspaceId,fixture.currentVersion])).rows;assert.equal(rows.length,1,'EXACT_CURRENT_TIMER_VERSION_REQUIRED');const root=rows[0];
   const newOccurrences=(await client.query('SELECT id,schedule_id,cluster_id,workspace_id,schedule_version,creator_id,state,scheduled_at,created_at FROM governance_schedule_runs WHERE schedule_id=$1 AND created_at>=$2 ORDER BY created_at,id LIMIT 20',[fixture.id,fixture.observedAt])).rows;
   await check(`${fixture.kind} schedule retains actual source owner and immutable 5 minute policy`,async()=>{
    assertM10TimerRoot(fixture,root,manifest,newOccurrences,value=>secrets.fingerprint(value));
    if(fixture.kind==='drift'){assert.equal(root.payload.target.clusterId,manifest.targetClusterId);assert.equal(root.payload.target.workspaceId,manifest.targetWorkspaceId);}return{scheduleId:fixture.id,version:root.current_version};
   });
   const occurrences=(await client.query(`SELECT o.*,r.actor_id,r.origin_type,r.origin_session_id,r.kind AS analysis_kind,r.state AS analysis_state,r.idempotency_key AS analysis_key
    FROM governance_schedule_runs o LEFT JOIN governance_runs r ON r.id=o.run_id AND r.cluster_id=o.cluster_id AND r.workspace_id=o.workspace_id
    WHERE o.schedule_id=$1 AND o.scheduled_at=$2 ORDER BY o.created_at,o.id LIMIT 3`,[fixture.id,fixture.nextRunAt])).rows;
   await check(`${fixture.kind} natural due occurrence has one real owner run without a browser SID`,async()=>{
    assert.equal(occurrences.length,1,'EXACT_ORIGINAL_TIMER_OCCURRENCE_REQUIRED');const occurrence=occurrences[0];assert(['succeeded','incomplete'].includes(occurrence.state),'TIMER_ORIGINAL_NOT_TERMINAL');assert.equal(occurrence.creator_id,manifest.actorId);assert.equal(occurrence.actor_id,manifest.actorId);assert.equal(occurrence.origin_type,'schedule');assert.equal(occurrence.origin_session_id,null);assert.equal(occurrence.lease_generation,1);assert.equal(occurrence.schedule_version,root.current_version);assert.equal(occurrence.analysis_key,`governance-schedule-${occurrence.id}`);
    assert.equal(occurrence.analysis_kind,fixture.kind==='drift'?'comparison':'inspection');assert.equal(occurrence.analysis_state,occurrence.state);assert(new Date(occurrence.created_at).getTime()>=Date.parse(fixture.nextRunAt)-1000);assert(new Date(occurrence.created_at).getTime()>=Date.parse(fixture.observedAt));assert(new Date(occurrence.completed_at).getTime()>=new Date(occurrence.created_at).getTime());
    return{occurrenceId:occurrence.id,runId:occurrence.run_id,state:occurrence.state,scheduledAt:new Date(occurrence.scheduled_at).toISOString(),createdAt:new Date(occurrence.created_at).toISOString(),completedAt:new Date(occurrence.completed_at).toISOString(),fakeSid:false};
   });
   const occurrence=occurrences[0],result=fixture.kind==='inspection'?(await client.query('SELECT * FROM governance_reports WHERE run_id=$1',[occurrence.run_id])).rows[0]:(await client.query('SELECT * FROM governance_comparisons WHERE run_id=$1',[occurrence.run_id])).rows[0];assert(result);
   await check(`${fixture.kind} sealed current inventory proves bounded readonly request accounting`,async()=>{
    const sealed=fixture.kind==='inspection'?[{value:secrets.decrypt(result.inventory_secret,`governance:inventory:${result.id}`),hmac:result.inventory_hmac}]
      :[{value:secrets.decrypt(result.source_inventory_secret,`governance:comparison-source:${result.id}`),hmac:result.source_inventory_hmac},{value:secrets.decrypt(result.target_inventory_secret,`governance:comparison-target:${result.id}`),hmac:result.target_inventory_hmac}];
    const material=sealed.map(({value:envelope,hmac})=>decodeM10TimerInventory(fixture.kind,envelope,hmac,value=>secrets.fingerprint(value)));
    for(const {value} of material){assert.equal(value.version,'1.5.1');for(const [key,max]of [['calls',500],['pages',100],['records',10000],['bytes',33554432]])assert(Number.isSafeInteger(value.usage[key])&&value.usage[key]>=0&&value.usage[key]<=max);assert(value.usage.calls>0);
     const from=timestamp(value.observedFrom),until=timestamp(value.observedUntil);assert(from>=timestamp(fixture.observedAt)&&from>=timestamp(occurrence.created_at)-1000&&until>=from&&until-from<=120000&&until<=timestamp(occurrence.completed_at)+1000);assert(value.objects.every(o=>!['credentials','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(o.entityType)));}
    assert.equal(material[0].value.scope.clusterId,manifest.sourceClusterId);assert.equal(material[0].value.scope.workspaceId,manifest.sourceWorkspaceId);
    if(fixture.kind==='drift'){assert.equal(material[1].value.scope.clusterId,manifest.targetClusterId);assert.equal(material[1].value.scope.workspaceId,manifest.targetWorkspaceId);assert.notEqual(material[0].value.scope.transportScope,material[1].value.scope.transportScope);}return{resultId:result.id,quality:result.quality,inventoryCount:material.length,inventoryEnvelopeVersions:material.map(m=>m.version),privateFingerprintSets:material.filter(m=>m.version===2).length,accountedCalls:material.reduce((sum,m)=>sum+m.value.usage.calls,0),observedWindowWithin120Seconds:true,secretsRecorded:false,wireLogClaim:false};
   });
   await check(`${fixture.kind} original occurrence claim analysis and finish all have exact owner scope audit`,async()=>{
    const rows=(await client.query('SELECT actor_id,cluster_id,workspace_id,entity_type,entity_id,action,result,request_id FROM audit_events WHERE request_id=$1 ORDER BY sequence',[`governance-schedule-${occurrence.id}`])).rows;
    for(const action of ['governance.schedule.claim','governance.schedule.run.requested','governance.schedule.run.complete','governance.schedule.finish'])assert(rows.some(r=>r.action===action),`TIMER_AUDIT_REQUIRED`);
    for(const r of rows){assert.equal(r.actor_id,manifest.actorId);assert.equal(r.cluster_id,manifest.sourceClusterId);assert.equal(r.workspace_id,manifest.sourceWorkspaceId);}return{auditRows:rows.length,originalRequestId:`governance-schedule-${occurrence.id}`};
   });
   observations.push({scheduleId:fixture.id,kind:fixture.kind,version:fixture.currentVersion,observedRevision:fixture.revision,currentRevision:root.revision,seedRequestId:fixture.requestId,observedAt:fixture.observedAt,occurrenceId:occurrence.id,runId:occurrence.run_id,resultId:result.id,state:occurrence.state,quality:result.quality,scheduledAt:new Date(occurrence.scheduled_at).toISOString()});
  }
  await check('timer request identifiers have no native mutation operation or configuration execution',async()=>{
   const requests=observations.map(o=>`governance-schedule-${o.occurrenceId}`),mutations=(await client.query('SELECT count(*)::int AS count FROM mutation_operations WHERE request_id=ANY($1::text[])',[requests])).rows[0].count;
   const jobs=(await client.query('SELECT count(*)::int AS count FROM configuration_jobs WHERE request_id=ANY($1::text[])',[requests])).rows[0].count;assert.equal(mutations,0);assert.equal(jobs,0);return{nativeMutationOperations:0,configurationJobs:0};
  });
  passed=true;
 }catch(error){failure={code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:'M10_TIMER_SQL_ASSERTION_FAILED'};}
 finally{if(client){await client.query('ROLLBACK').catch(()=>{});await client.end().catch(()=>{});}process.stdout.write(JSON.stringify({milestone:'M10',passed,source:'own-lab-readonly-sql-natural-timer',checks,observations,productionDeployment:false,nativeKongWriteRequested:false,sqlMutationRequested:false,futureClockUsed:false,fakeSidUsed:false,originalResponseRewritten:false,...(failure?{failure}:{})})+'\n');if(!passed)process.exitCode=1;}
}
