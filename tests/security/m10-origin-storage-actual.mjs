/** Root-only execution against the isolated console runtime after actual M10
 * BFF planning. Every SQL mutation rolls back. No gateway request or native
 * success is inferred from a foreign key, SQL fixture or historical row. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
const require=createRequire('/app/package.json'),checks=[],attempts=[];
let client,scope,passed=false,failure,rollbacks=0,initialDigest,finalDigest;
const uuid=value=>typeof value==='string'&&/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value);
const safeError=error=>({code:/^[A-Z0-9_]+$/.test(error?.code??'')?error.code:'ASSERTION_FAILED',...(typeof error?.constraint==='string'&&/^[a-z0-9_]+$/.test(error.constraint)?{constraint:error.constraint}:{})});
const check=async(name,fn)=>{try{const facts=await fn();checks.push({name,passed:true,...(facts??{})});}catch(e){checks.push({name,passed:false,...safeError(e)});throw e;}};
const transaction=async(fn)=>{await client.query('BEGIN');try{await client.query("SET LOCAL statement_timeout='5s'");await client.query("SET LOCAL lock_timeout='1s'");return await fn();}finally{await client.query('ROLLBACK');rollbacks++;}};
const reject=async(name,sql,values,code,constraint)=>{let observed;await transaction(async()=>{try{await client.query(sql,values);await client.query('SET CONSTRAINTS ALL IMMEDIATE');}catch(e){observed=safeError(e);}});
 attempts.push({name,rolledBack:true,...(observed??{code:'UNEXPECTED_SQL_SUCCESS'})});assert.equal(observed?.code,code);if(constraint)assert.equal(observed.constraint,constraint);};
const digest=async()=>{
 const result=await client.query(`SELECT jsonb_build_object(
  'promotion',(SELECT to_jsonb(p) FROM governance_promotions p WHERE p.id=$1),
  'comparison',(SELECT to_jsonb(c) FROM governance_comparisons c WHERE c.id=(SELECT comparison_id FROM governance_promotions WHERE id=$1)),
  'job',(SELECT to_jsonb(j) FROM configuration_jobs j WHERE j.id=$2),
  'job_binding',(SELECT to_jsonb(b) FROM configuration_job_origin_bindings b WHERE b.job_id=$2),
  'plan',(SELECT to_jsonb(p) FROM configuration_plans p WHERE p.id=$3),
  'plan_versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.plan_revision),'[]') FROM configuration_plan_versions v WHERE v.plan_id=$3),
  'plan_bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.plan_revision),'[]') FROM configuration_plan_origin_bindings b WHERE b.plan_id=$3),
  'intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.id),'[]') FROM governance_metadata_requests i WHERE i.workflow_id=ANY($4::uuid[])),
  'workflows',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY w.id),'[]') FROM workflows w WHERE w.id=ANY($4::uuid[])),
  'steps',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.workflow_id,s.step_order),'[]') FROM workflow_steps s WHERE s.workflow_id=ANY($4::uuid[])),
  'mutations',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]') FROM mutation_operations m WHERE m.configuration_job_id=$2 OR m.workflow_id=ANY($4::uuid[]))
 ) AS facts`,[scope.promotionId,scope.jobId,scope.planId,scope.metadataWorkflowIds]);
 return createHash('sha256').update(JSON.stringify(result.rows[0].facts)).digest('hex');
};
try{
 await check('explicit isolated runtime role and real M10 BFF receipt locators',async()=>{
  assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_M10_ORIGIN_STORAGE_READY,'true');assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-console-api-1');assert.equal(process.cwd(),'/app');
  const url=new URL(process.env.DATABASE_URL);assert.equal(url.hostname,'console-db');assert.equal(url.port,'5432');assert.equal(url.pathname,'/kongpilot');assert.equal(url.username,'kongpilot_lab_app');
  scope=JSON.parse(process.env.RELEASE_M10_ORIGIN_SCOPE??'null');assert(scope&&typeof scope==='object'&&!Array.isArray(scope));
  assert.equal(Object.keys(scope).sort().join(','),'jobId,metadataWorkflowIds,planId,promotionId,sourceClusterId,sourceWorkspaceId,targetClusterId,targetWorkspaceId');
  for(const key of ['jobId','planId','promotionId','sourceClusterId','sourceWorkspaceId','targetClusterId','targetWorkspaceId'])assert(uuid(scope[key]),`${key} locator must be a real UUID`);
  assert(Array.isArray(scope.metadataWorkflowIds)&&scope.metadataWorkflowIds.length>=1&&scope.metadataWorkflowIds.length<=8&&scope.metadataWorkflowIds.every(uuid)&&new Set(scope.metadataWorkflowIds).size===scope.metadataWorkflowIds.length);
  const {Client}=require('pg');client=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await client.connect();
  const row=(await client.query('SELECT current_database() AS database,current_user AS role')).rows[0];assert.equal(row.database,'kongpilot');assert.equal(row.role,'kongpilot_lab_app');
 });
 await check('SQL017 and SQL018 deployed checksums match immutable source bytes',async()=>{
  for(const name of ['017_m10_governance.sql','018_m10_configuration_origins.sql']){const expected=createHash('sha256').update(readFileSync(`/app/apps/console-api/dist/infrastructure/migrations/${name}`)).digest('hex');
   const row=(await client.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name])).rows[0];assert(row);assert.equal(row.checksum,expected);}
 });
 initialDigest=await digest();
 const parent=(await client.query('SELECT * FROM governance_promotions WHERE id=$1',[scope.promotionId])).rows[0];
 const job=(await client.query('SELECT * FROM configuration_jobs WHERE id=$1',[scope.jobId])).rows[0];
 const binding=(await client.query('SELECT * FROM configuration_job_origin_bindings WHERE job_id=$1',[scope.jobId])).rows[0];
 const version=(await client.query('SELECT * FROM configuration_plan_versions WHERE plan_id=$1 ORDER BY plan_revision DESC LIMIT 1',[scope.planId])).rows[0];
 const planBinding=version&&(await client.query('SELECT * FROM configuration_plan_origin_bindings WHERE plan_id=$1 AND plan_revision=$2 AND plan_hash=$3',[scope.planId,version.plan_revision,version.plan_hash])).rows[0];
 await check('actual Promote origin binds exact owner, source, target, material and sealed configuration plan',async()=>{
  assert(parent&&job&&binding&&version&&planBinding);assert.equal(parent.state,'ready');assert.equal(parent.cluster_id,scope.sourceClusterId);assert.equal(parent.workspace_id,scope.sourceWorkspaceId);
  assert.equal(parent.target_cluster_id,scope.targetClusterId);assert.equal(parent.target_workspace_id,scope.targetWorkspaceId);assert.equal(parent.configuration_job_id,job.id);assert.equal(parent.plan_id,scope.planId);assert.equal(parent.plan_revision,version.plan_revision);assert.equal(parent.plan_hash,version.plan_hash);
  assert.equal(job.cluster_id,scope.targetClusterId);assert.equal(job.workspace_id,scope.targetWorkspaceId);assert.equal(job.actor_id,parent.actor_id);assert.equal(job.kind,'import');assert.equal(job.required_origin_kind,'governance-promote');assert.equal(job.required_origin_id,parent.id);
  assert.equal(binding.cluster_id,job.cluster_id);assert.equal(binding.workspace_id,job.workspace_id);assert.equal(binding.job_id,job.id);assert.equal(binding.origin_kind,job.required_origin_kind);assert.equal(binding.origin_id,parent.id);assert.equal(binding.material_hmac,job.required_origin_hmac);
  assert.equal(binding.source_cluster_id,parent.cluster_id);assert.equal(binding.source_workspace_id,parent.workspace_id);assert.equal(binding.comparison_id,parent.comparison_id);assert.equal(version.source_job_id,job.id);
  assert.equal(planBinding.cluster_id,job.cluster_id);assert.equal(planBinding.workspace_id,job.workspace_id);assert.equal(planBinding.job_id,job.id);assert.equal(planBinding.origin_id,parent.id);assert.equal(planBinding.material_hmac,binding.material_hmac);
  return{sourceClusterId:parent.cluster_id,targetClusterId:parent.target_cluster_id,promotionId:parent.id,jobId:job.id,planId:version.plan_id,planRevision:version.plan_revision};
 });
 await check('real metadata workflows have exact encrypted intent and zero native mutation rows',async()=>{
  require('reflect-metadata');const {SecretService}=require('/app/apps/console-api/dist/infrastructure/secret.service.js'),secrets=new SecretService();
  for(const id of scope.metadataWorkflowIds){
   const w=(await client.query('SELECT * FROM workflows WHERE id=$1',[id])).rows[0];assert(w);assert.equal(w.kind,'governance-metadata');assert.equal(w.subject_type,'governance_metadata_requests');assert.equal(w.cluster_id,scope.targetClusterId);assert.equal(w.workspace_id,scope.targetWorkspaceId);assert.equal(w.execution_mode,'approval');assert.equal(w.approval_required,true);assert.equal(w.state,'succeeded');
   const i=(await client.query('SELECT * FROM governance_metadata_requests WHERE id=$1',[w.subject_id])).rows[0],v=(await client.query('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND plan_revision=$2',[id,w.plan_revision])).rows[0];assert(i&&v);assert.equal(i.actor_id,w.requester_user_id);assert.equal(i.workflow_id,w.id);assert.equal(i.idempotency_key,w.idempotency_key);
   const plan=secrets.decrypt(v.payload_secret,`workflow:${w.cluster_id}:${w.workspace_id}:${w.id}:${w.plan_revision}:plan`),payload=secrets.decrypt(i.payload_secret,`governance:metadata-payload:${i.id}`),before=i.before_secret?secrets.decrypt(i.before_secret,`governance:metadata-before:${i.id}`):null,storedScope=secrets.decrypt(i.scope_secret,`governance:metadata-scope:${i.id}`);
   assert.equal(secrets.fingerprint(plan),w.plan_hash);assert.equal(v.plan_hash,w.plan_hash);assert.equal(v.native_request_count,0);assert.equal(plan.steps.length,1);assert.equal(plan.prerequisites.length,0);
   assert.equal(secrets.fingerprint(payload),i.payload_hmac);assert.equal(secrets.fingerprint(before),i.before_hmac);assert.equal(secrets.fingerprint(storedScope.originalRequest),i.request_hmac);assert.equal(secrets.fingerprint({requester:plan.requester,clusterId:w.cluster_id,workspaceId:w.workspace_id,request:storedScope.originalRequest}),w.request_hash);
   const rows=(await client.query('SELECT * FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2',[id,w.plan_revision])).rows;assert.equal(rows.length,1);assert.equal(rows[0].kind,'metadata');assert.equal(rows[0].handler,'governance.metadata');assert.equal(rows[0].state,'succeeded');assert.equal(rows[0].operation_id,null);assert.deepEqual(rows[0].native_requests,[]);assert.equal(rows[0].entity_id,i.id);
   const mutations=(await client.query('SELECT count(*)::int AS count FROM mutation_operations WHERE workflow_id=$1',[id])).rows[0];assert.equal(mutations.count,0);
   const audits=(await client.query("SELECT count(*)::int AS count FROM audit_events WHERE workflow_id=$1 AND action=$2 AND entity_type=$3 AND entity_id=$4 AND actor_id=$5 AND result='success'",[id,`governance.metadata.${i.operation}`,i.resource_type,i.resource_id,i.actor_id])).rows[0];assert.equal(audits.count,1);
  }return{workflowCount:scope.metadataWorkflowIds.length,nativeMutationCount:0};
 });
 await check('actual SQL018 job marker is immutable and cannot be removed, altered or rebound',async()=>{
  for(const [name,patch]of [['remove',{required_origin_kind:null,required_origin_id:null,required_origin_hmac:null}],['other-source',{required_origin_id:randomUUID()}],['changed-material',{required_origin_hmac:'e'.repeat(64)}]])
   await reject(`marker-${name}`,'UPDATE configuration_jobs SET required_origin_kind=$2,required_origin_id=$3,required_origin_hmac=$4 WHERE id=$1',[job.id,patch.required_origin_kind===undefined?job.required_origin_kind:patch.required_origin_kind,patch.required_origin_id===undefined?job.required_origin_id:patch.required_origin_id,patch.required_origin_hmac===undefined?job.required_origin_hmac:patch.required_origin_hmac],'23514');
 });
 await check('actual origin job/plan binding rejects update and delete; runtime cannot truncate',async()=>{
  for(const table of ['configuration_job_origin_bindings','configuration_plan_origin_bindings']){
   await reject(`${table}-update`,`UPDATE ${table} SET material_hmac=$2 WHERE job_id=$1`,[job.id,'e'.repeat(64)],'42501');await reject(`${table}-delete`,`DELETE FROM ${table} WHERE job_id=$1`,[job.id],'42501');
   const row=(await client.query('SELECT has_table_privilege(current_user,$1,\'TRUNCATE\') AS allowed',[table])).rows[0];assert.equal(row.allowed,false);
  }
 });
 await check('real SQL018 rejects a forged job binding and malformed material without duplicate-key masking',async()=>{
  const constraint=(await client.query("SELECT conname FROM pg_constraint WHERE conrelid='configuration_job_origin_bindings'::regclass AND confrelid='configuration_jobs'::regclass AND contype='f'")).rows;assert.equal(constraint.length,1);
  const values=[binding.cluster_id,binding.workspace_id,randomUUID(),binding.origin_kind,binding.origin_id,binding.material_hmac,binding.source_cluster_id,binding.source_workspace_id,binding.comparison_id];
  const sql='INSERT INTO configuration_job_origin_bindings(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac,source_cluster_id,source_workspace_id,comparison_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)';
  await reject('missing-actual-job',sql,values,'23503',constraint[0].conname);values[5]='not-a-hmac';await reject('malformed-material',sql,values,'23514');
 });
 await check('existing sealed origin links satisfy deferred constraints with no writes',async()=>{await transaction(async()=>{await client.query('SET CONSTRAINTS ALL IMMEDIATE');});});
 finalDigest=await digest();assert.equal(finalDigest,initialDigest);passed=true;
}catch(e){failure=safeError(e);process.exitCode=1;}finally{if(client){await client.query('ROLLBACK').catch(()=>{});await client.end().catch(()=>{});}}
console.log(JSON.stringify({passed,source:'actual-isolated-console-postgresql',nativeRequests:0,nativeSuccessInferred:false,allMutationTrialsRolledBack:true,rollbackTrials:rollbacks,checks,attempts,
 ...(initialDigest?{beforeDigest:initialDigest}:{}),...(finalDigest?{afterDigest:finalDigest,sourceRowsUnchanged:initialDigest===finalDigest}:{}),...(failure?{failure}:{})},null,2));
