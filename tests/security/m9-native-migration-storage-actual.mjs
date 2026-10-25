/**
 * SQL016 diagnostics against original real migration approval rows only.
 * Run through the two fixed self-owned Docker hosts using node --input-type=module,
 * RELEASE_LAB_READY=true and RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1.
 * No successful source rows are fabricated. Every attempted write rolls back.
 * Terminal native/metadata success is deliberately not inferred from this report.
 */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';

const CID='e269f167-53e9-4895-af89-5b1b8835c6ec',WORKFLOW='c6331a67-c9ea-4ce4-bd15-f520fc44ef98';
const require=createRequire('/app/package.json'),checks=[],attempts=[];
let client,passed=false,failure,fixtureCounts,diagnostics,rollbackTrials=0;
const safeError=error=>({code:/^[A-Z0-9_]+$/.test(error?.code??'')?error.code:'ASSERTION_FAILED',
  ...(typeof error?.constraint==='string'&&/^[a-z0-9_]+$/.test(error.constraint)?{constraint:error.constraint}:{})});
const check=async(name,fn)=>{try{const facts=await fn();checks.push({name,passed:true,...(facts??{})});}catch(error){checks.push({name,passed:false,...safeError(error)});throw error;}};
const trial=async(name,queries,expectedCode,expectedConstraint)=>{
  await client.query('BEGIN');let observed;
  try{
    await client.query("SET LOCAL statement_timeout='5s'");await client.query("SET LOCAL lock_timeout='1s'");
    try{for(const [sql,values]of queries)await client.query(sql,values??[]);}catch(error){observed=safeError(error);}
  }finally{await client.query('ROLLBACK');rollbackTrials++;}
  attempts.push({name,rolledBack:true,...(observed??{code:'UNEXPECTED_SQL_SUCCESS'})});
  assert.equal(observed?.code,expectedCode);if(expectedConstraint)assert.equal(observed?.constraint,expectedConstraint);return observed;
};
const rollbackSuccess=async(name,fn)=>{
  await client.query('BEGIN');
  try{await client.query("SET LOCAL statement_timeout='5s'");await client.query("SET LOCAL lock_timeout='1s'");const result=await fn();
    attempts.push({name,rolledBack:true,code:'ROLLBACK_ONLY_SUCCESS'});return result;
  }finally{await client.query('ROLLBACK');rollbackTrials++;}
};
const insertBinding=`INSERT INTO workspace_migration_workflow_bindings
 (cluster_id,source_workspace_id,target_workspace_id,migration_plan_id,workflow_id,actor_id,migration_plan_hash,material_hmac,request_hash)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`;
const bindingValues=(row,patch={})=>{const merged={...row,...patch};return['cluster_id','source_workspace_id','target_workspace_id','migration_plan_id','workflow_id','actor_id','migration_plan_hash','material_hmac','request_hash'].map(name=>merged[name]);};
const digest=async()=>{
  const result=await client.query(`SELECT jsonb_build_object(
   'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.migration_plan_id),'[]') FROM workspace_migration_workflow_bindings b WHERE b.cluster_id=$1),
   'plans',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]') FROM workspace_migration_plans p WHERE p.cluster_id=$1),
   'migration_steps',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.plan_id,s.object_key),'[]') FROM workspace_migration_steps s WHERE s.cluster_id=$1),
   'workflows',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY w.id),'[]') FROM workflows w WHERE w.cluster_id=$1 AND w.kind='workspace-migration'),
   'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.workflow_id,v.plan_revision),'[]') FROM workflow_versions v WHERE v.cluster_id=$1 AND v.workflow_id IN(SELECT workflow_id FROM workspace_migration_workflow_bindings WHERE cluster_id=$1)),
   'workflow_steps',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.workflow_id,s.step_order),'[]') FROM workflow_steps s WHERE s.cluster_id=$1 AND s.workflow_id IN(SELECT workflow_id FROM workspace_migration_workflow_bindings WHERE cluster_id=$1)),
   'executions',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]') FROM workflow_executions e WHERE e.cluster_id=$1 AND e.workflow_id IN(SELECT workflow_id FROM workspace_migration_workflow_bindings WHERE cluster_id=$1)),
   'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]') FROM workflow_events e WHERE e.cluster_id=$1 AND e.workflow_id IN(SELECT workflow_id FROM workspace_migration_workflow_bindings WHERE cluster_id=$1)),
   'mutations',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]') FROM mutation_operations m WHERE m.cluster_id=$1 AND m.workflow_id IN(SELECT workflow_id FROM workspace_migration_workflow_bindings WHERE cluster_id=$1))
  ) AS facts`,[CID]);
  return createHash('sha256').update(JSON.stringify(result.rows[0].facts)).digest('hex');
};

try{
  await check('explicit self-owned console database runtime and fixed original workflow gate',async()=>{
    assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-console-api-1');
    assert.equal(process.cwd(),'/app');const url=new URL(process.env.DATABASE_URL);
    assert.equal(url.hostname,'console-db');assert.equal(url.port,'5432');assert.equal(url.pathname,'/kongpilot');assert.equal(url.username,'kongpilot_lab_app');
    const {Client}=require('pg');client=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await client.connect();
    const row=(await client.query('SELECT current_database() AS database,current_user AS role')).rows[0];assert.equal(row.database,'kongpilot');assert.equal(row.role,'kongpilot_lab_app');
  });
  const initial=await digest();
  const bindings=(await client.query('SELECT * FROM workspace_migration_workflow_bindings WHERE cluster_id=$1 ORDER BY created_at,migration_plan_id LIMIT 51',[CID])).rows;
  const known=bindings.find(row=>row.workflow_id===WORKFLOW);assert(known,'Original v2 approval binding required');
  await check('deployed SQL016 checksum matches its actual immutable migration source',async()=>{
    const name='016_m9_workspace_migration_workflow.sql';
    const checksum=createHash('sha256').update(readFileSync('/app/apps/console-api/dist/infrastructure/migrations/'+name)).digest('hex');
    const row=(await client.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name])).rows[0];assert(row);assert.equal(row.checksum,checksum);
  });
  require('reflect-metadata');const {SecretService}=require('/app/apps/console-api/dist/infrastructure/secret.service.js');const secrets=new SecretService();
  await check('actual immutable bindings preserve their original source, target, owner, subject and approval policy',async()=>{
    assert(bindings.length>0&&bindings.length<=50);let packetCount=0;
    for(const b of bindings){
      const p=(await client.query('SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2',[CID,b.migration_plan_id])).rows[0];
      const w=(await client.query('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[CID,b.source_workspace_id,b.workflow_id])).rows[0];
      assert(p&&w);assert.equal(p.actor_id,b.actor_id);assert.equal(p.source_workspace_id,b.source_workspace_id);assert.equal(p.target_workspace_id,b.target_workspace_id);
      assert.equal(p.plan_hash,b.migration_plan_hash);assert.notEqual(b.source_workspace_id,b.target_workspace_id);
      assert.equal(w.kind,'workspace-migration');assert.equal(w.subject_type,'workspace_migration_plans');assert.equal(w.subject_id,p.id);
      assert.equal(w.requester_type,'console');assert.equal(w.requester_user_id,b.actor_id);assert.equal(w.execution_mode,'approval');assert.equal(w.approval_required,true);
      const material=secrets.decrypt(p.payload_secret,`workspace-migration:${p.id}`);
      assert.equal(material.source.id,b.source_workspace_id);assert.equal(material.target.id,b.target_workspace_id);
      assert.equal(material.source.cluster_id,CID);assert.equal(material.target.cluster_id,CID);
      assert.equal(secrets.fingerprint({cid:CID,actor:b.actor_id,payload:material}),p.plan_hash);assert.equal(secrets.fingerprint(material),b.material_hmac);
      assert.equal(secrets.fingerprint({migrationId:p.id,input:{confirmed:true,confirm_name:material.target.name,plan_hash:p.plan_hash}}),b.request_hash);
      const v=(await client.query('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[CID,b.source_workspace_id,w.id,w.plan_revision])).rows[0];
      assert(v);const plan=secrets.decrypt(v.payload_secret,`workflow:${CID}:${b.source_workspace_id}:${w.id}:${w.plan_revision}:plan`);
      assert.equal(secrets.fingerprint(plan),w.plan_hash);assert.equal(v.plan_hash,w.plan_hash);assert.equal(secrets.fingerprint(plan.steps),v.steps_hash);
      assert.equal(plan.requester.id,b.actor_id);assert.equal(plan.subject.id,p.id);assert.equal(plan.migration.sourceWorkspaceId,b.source_workspace_id);
      assert.equal(plan.migration.targetWorkspaceId,b.target_workspace_id);assert.equal(plan.migration.materialHmac,b.material_hmac);
      const steps=(await client.query('SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order',[CID,b.source_workspace_id,w.id,w.plan_revision])).rows;
      assert.equal(steps.length,1);assert.equal(plan.steps.length,1);const s=steps[0],frozen=plan.steps[0];
      assert.equal(s.kind,'native');assert.equal(s.handler,null);assert.equal(s.step_key,'workspace-migration');assert.equal(s.entity_type,'workspace_migration');
      assert.equal(s.entity_id,p.id);assert.equal(s.mutation_action,'migrate');assert.equal(s.permission_action,'write');assert.equal(s.parent_id,null);assert.equal(s.credential_kind,null);assert.deepEqual(s.dependencies,[]);
      assert.equal(s.before_fingerprint,secrets.fingerprint(frozen.before));assert.equal(s.mutation_payload_hmac,secrets.fingerprint(frozen.mutationPayload));
      assert.equal(frozen.mutationPayload.plan_id,p.id);assert.equal(frozen.mutationPayload.plan_hash,p.plan_hash);assert.equal(frozen.mutationPayload.confirmed,true);assert.equal(frozen.mutationPayload.confirm_name,material.target.name);
      assert.equal(s.mutation_idempotency_key,frozen.mutationIdempotencyKey);
      const packets=frozen.nativeRequests;assert(packets.length>=1&&packets.length<=32);packetCount+=packets.length;
      assert.equal(packets.length,material.nodes.filter(node=>!node.inheritedOnly).length);
      for(const packet of packets){
        assert.equal(packet.method,'PATCH');assert.deepEqual(Object.keys(packet.body),['tags']);assert.equal(packet.bodyHmac,secrets.fingerprint(packet.body));
        const node=material.nodes.find(value=>value.path===packet.canonicalPath&&value.id===packet.nativeId);assert(node&&!node.inheritedOnly);
        assert.equal(packet.nativeType,node.type);assert.equal(packet.beforeHmac,node.beforeFingerprint);assert.equal(packet.beforeHmac,secrets.fingerprint(node.data));
        assert.deepEqual(packet.body.tags,node.afterTags);
      }
      assert.deepEqual(s.native_requests,packets.map(packet=>({method:packet.method,path_hash:secrets.fingerprint(packet.canonicalPath),native_type:packet.nativeType,native_id:packet.nativeId??null,parent_id:packet.parentId??null,credential_kind:packet.credentialKind??null,body_hmac:packet.bodyHmac,before_hmac:packet.beforeHmac??null})));
    }
    fixtureCounts={originalBindings:bindings.length,originalNativePackets:packetCount};return fixtureCounts;
  });
  const constraints=(await client.query("SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='workspace_migration_workflow_bindings'::regclass")).rows;
  const constraintFor=prefix=>{const row=constraints.find(value=>value.definition.startsWith(prefix));assert(row);assert(/^[a-z0-9_]+$/.test(row.conname));return row.conname;};
  const sourceFK=constraintFor('FOREIGN KEY (cluster_id, source_workspace_id) REFERENCES workspaces(cluster_id, id)');
  const targetFK=constraintFor('FOREIGN KEY (cluster_id, target_workspace_id) REFERENCES workspaces(cluster_id, id)');
  const planFK=constraintFor('FOREIGN KEY (cluster_id, migration_plan_id) REFERENCES workspace_migration_plans(cluster_id, id)');
  const actorFK=constraintFor('FOREIGN KEY (actor_id) REFERENCES users(id)');
  const workflowFK=constraintFor('FOREIGN KEY (cluster_id, source_workspace_id, workflow_id) REFERENCES workflows(cluster_id, workspace_id, id)');
  await check('deployed composite FKs bind actual plan, source, target, user and scoped workflow',async()=>{
    assert(constraints.find(row=>row.conname===workflowFK).definition.includes('DEFERRABLE INITIALLY DEFERRED'));
    return{foreignKeyCount:[sourceFK,targetFK,planFK,actorFK,workflowFK].length};
  });
  await check('deployed source validator and bound-plan guard enforce the original owner and material identity',async()=>{
    const validator=(await client.query("SELECT pg_get_functiondef('m9_validate_migration_wrapper()'::regprocedure) AS source")).rows[0].source.replace(/\s+/g,' ');
    for(const predicate of ["w.kind<>'workspace-migration'","w.subject_type<>'workspace_migration_plans'",'w.subject_id<>NEW.migration_plan_id','w.requester_user_id<>NEW.actor_id',
      'p.source_workspace_id=NEW.source_workspace_id','p.target_workspace_id=NEW.target_workspace_id','p.actor_id=NEW.actor_id','p.plan_hash=NEW.migration_plan_hash'])assert(validator.includes(predicate));
    const guard=(await client.query("SELECT pg_get_functiondef('m9_guard_bound_migration()'::regprocedure) AS source")).rows[0].source;
    for(const name of ['actor_id','source_workspace_id','target_workspace_id','plan_hash','payload_secret','expires_at'])assert(guard.includes(`NEW.${name} IS DISTINCT FROM OLD.${name}`));
  });
  await check('runtime cannot UPDATE, DELETE or TRUNCATE the immutable approval binding',async()=>{
    for(const [name,sql,params]of [
      ['binding.update','UPDATE workspace_migration_workflow_bindings SET actor_id=actor_id WHERE cluster_id=$1 AND migration_plan_id=$2',[CID,known.migration_plan_id]],
      ['binding.delete','DELETE FROM workspace_migration_workflow_bindings WHERE cluster_id=$1 AND migration_plan_id=$2',[CID,known.migration_plan_id]],
      ['binding.truncate','TRUNCATE workspace_migration_workflow_bindings',[]],
    ])await trial(name,[[sql,params]],'42501');
  });
  const foreignActor=(await client.query('SELECT id FROM users WHERE id<>$1 ORDER BY id LIMIT 1',[known.actor_id])).rows[0];assert(foreignActor);
  const otherWorkspace=(await client.query('SELECT id FROM workspaces WHERE cluster_id=$1 AND id<>ALL($2::uuid[]) ORDER BY id LIMIT 1',[CID,[known.source_workspace_id,known.target_workspace_id]])).rows[0];assert(otherWorkspace);
  for(const [column,replacement]of [['actor_id',foreignActor.id],['source_workspace_id',otherWorkspace.id],['target_workspace_id',otherWorkspace.id],['plan_hash','0'.repeat(64)]])
    await check(`bound original migration ${column} cannot be reassigned`,async()=>trial(`frozen.${column}`,
      [[`UPDATE workspace_migration_plans SET ${column}=$3 WHERE cluster_id=$1 AND id=$2`,[CID,known.migration_plan_id,replacement]]],'23514'));
  await check('bound original encrypted material and expiry cannot be replaced',async()=>{
    await trial('frozen.payload_secret',[["UPDATE workspace_migration_plans SET payload_secret=payload_secret||'A' WHERE cluster_id=$1 AND id=$2",[CID,known.migration_plan_id]]],'23514');
    await trial('frozen.expires_at',[["UPDATE workspace_migration_plans SET expires_at=expires_at+interval '1 minute' WHERE cluster_id=$1 AND id=$2",[CID,known.migration_plan_id]]],'23514');
    await trial('frozen.delete',[["DELETE FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2",[CID,known.migration_plan_id]]],'23514');
  });
  await check('existing source cannot gain a second approval binding under a different workflow or actor',async()=>{
    const primary=constraints.find(row=>row.definition.startsWith('PRIMARY KEY'));assert(primary);
    await trial('existing-binding-replay',[[insertBinding,bindingValues(known)]],'23505',primary.conname);
    await trial('existing-binding-other-workflow',[[insertBinding,bindingValues(known,{workflow_id:randomUUID()})]],'23505',primary.conname);
    await trial('existing-binding-other-actor',[[insertBinding,bindingValues(known,{actor_id:foreignActor.id})]],'23505',primary.conname);
  });
  // Use a REAL previously created unbound M3 plan, so unique constraints do not
  // mask source/target/actor FK trials. No fake successful source row is inserted.
  const candidate=(await client.query(`SELECT p.*,w.id AS candidate_workflow_id FROM workspace_migration_plans p
    JOIN workflows w ON w.cluster_id=p.cluster_id AND w.workspace_id=p.source_workspace_id AND w.requester_user_id=p.actor_id AND w.kind<>'workspace-migration'
    WHERE p.cluster_id=$1 AND NOT EXISTS(SELECT 1 FROM workspace_migration_workflow_bindings b WHERE b.cluster_id=p.cluster_id AND b.migration_plan_id=p.id)
    AND NOT EXISTS(SELECT 1 FROM workspace_migration_workflow_bindings b WHERE b.cluster_id=w.cluster_id AND b.workflow_id=w.id)
    ORDER BY p.created_at,w.created_at LIMIT 1`,[CID])).rows[0];assert(candidate,'A real unbound source and non-migration workflow are required');
  const base={...known,migration_plan_id:candidate.id,source_workspace_id:candidate.source_workspace_id,target_workspace_id:candidate.target_workspace_id,
    actor_id:candidate.actor_id,migration_plan_hash:candidate.plan_hash,workflow_id:candidate.candidate_workflow_id};
  const otherCandidateWorkspace=(await client.query('SELECT id FROM workspaces WHERE cluster_id=$1 AND id<>ALL($2::uuid[]) ORDER BY id LIMIT 1',
    [CID,[candidate.source_workspace_id,candidate.target_workspace_id]])).rows[0];assert(otherCandidateWorkspace);
  const immediate=name=>`SET CONSTRAINTS "${name}" IMMEDIATE`;
  for(const [name,patch,constraint]of [
    ['missing-source',{source_workspace_id:randomUUID()},sourceFK],['missing-target',{target_workspace_id:randomUUID()},targetFK],
    ['missing-plan',{migration_plan_id:randomUUID()},planFK],['missing-actor',{actor_id:randomUUID()},actorFK],
  ])await check(`real unbound source trial rejects ${name} at its actual foreign key`,async()=>
    trial(name,[[insertBinding,bindingValues(base,patch)]], '23503',constraint));
  await check('real unbound source cannot reference a missing workflow in its source scope',async()=>
    trial('missing-scoped-workflow',[[insertBinding,bindingValues(base,{workflow_id:randomUUID()})],[immediate(workflowFK)]],'23503',workflowFK));
  await check('real non-migration workflow cannot adopt a real unbound migration plan',async()=>
    trial('foreign-kind-workflow',[[insertBinding,bindingValues(base)],['SET CONSTRAINTS ALL IMMEDIATE']],'23503'));
  await check('a different existing source cannot bind the same real workflow scope',async()=>
    trial('wrong-existing-source-scope',[[insertBinding,bindingValues(base,{source_workspace_id:otherCandidateWorkspace.id})],[immediate(workflowFK)]],'23503',workflowFK));
  await check('original known 503 source retains its factual workflow, migration and operation status',async()=>{
    const rows=(await client.query(`SELECT w.state AS workflow_state,p.state AS migration_state,
      (SELECT count(*)::integer FROM workflow_executions e WHERE e.workflow_id=w.id) AS execution_count,
      (SELECT count(*)::integer FROM mutation_operations m WHERE m.workflow_id=w.id AND m.entity_type='workspace_migration') AS mutation_count,
      (SELECT count(*)::integer FROM mutation_operations m WHERE m.workflow_id=w.id AND m.entity_type='workspace_migration' AND m.remote_started) AS remote_started_count,
      (SELECT count(*)::integer FROM mutation_operations m WHERE m.workflow_id=w.id AND m.entity_type='workspace_migration' AND m.remote_completed) AS remote_completed_count
      FROM workflows w JOIN workspace_migration_workflow_bindings b ON b.workflow_id=w.id
      JOIN workspace_migration_plans p ON p.id=b.migration_plan_id WHERE w.id=$1 AND w.cluster_id=$2`,[WORKFLOW,CID])).rows;
    assert.equal(rows.length,1);diagnostics={workflowId:WORKFLOW,...rows[0],nativePacketTransmissionInferred:false};return diagnostics;
  });
  const originalWorkflow=(await client.query('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2',[WORKFLOW,CID])).rows[0];
  const originalExecution=(await client.query('SELECT * FROM workflow_executions WHERE workflow_id=$1 AND cluster_id=$2',[WORKFLOW,CID])).rows[0];
  const originalStep=(await client.query('SELECT * FROM workflow_steps WHERE workflow_id=$1 AND cluster_id=$2',[WORKFLOW,CID])).rows[0];
  assert(originalWorkflow&&originalExecution&&originalStep);
  await check('exact corrected terminal lookup resolves UUID step ID and TEXT mutation ID on the original completed native rows',async()=>
    rollbackSuccess('exact-corrected-terminal-select',async()=>{
      // Exact WorkflowService.execute source template, source-frozen after the
      // actual PostgreSQL UUID=TEXT failure. These are original v2 rows.
      const terminal=`SELECT s.state AS step_state,s.operation_id,m.actor_id,m.cluster_id,m.workspace_id,m.entity_type,m.entity_id,m.action,
              m.workflow_id,m.workflow_execution_id,m.workflow_step_id,m.workflow_plan_revision,m.workflow_plan_hash,m.state AS mutation_state,m.remote_started,m.remote_completed,
              m.before_secret,m.payload_secret,m.result_secret,p.state AS migration_state,p.plan_hash AS migration_plan_hash,p.operation_id AS migration_operation_id,
              p.actor_id AS migration_actor_id,p.source_workspace_id,p.target_workspace_id,p.payload_secret AS migration_material_secret
              FROM workflow_steps s JOIN mutation_operations m ON m.id=s.operation_id AND m.cluster_id=s.cluster_id AND m.workspace_id=s.workspace_id
              JOIN workspace_migration_plans p ON p.id=s.entity_id AND m.entity_id=p.id::text AND p.cluster_id=m.cluster_id
              WHERE s.id=$1 AND s.workflow_id=$2 AND s.plan_revision=$3 AND s.plan_hash=$4 FOR SHARE OF s,m,p`;
      const row=(await client.query(terminal,[originalStep.id,WORKFLOW,originalStep.plan_revision,originalStep.plan_hash])).rows[0];assert(row);
      assert.equal(row.step_state,'succeeded');assert.equal(row.mutation_state,'succeeded');assert.equal(row.migration_state,'succeeded');
      assert.equal(row.operation_id,row.migration_operation_id);assert.equal(row.workflow_execution_id,originalExecution.id);assert.equal(row.workflow_step_id,originalStep.id);
      assert.equal(row.actor_id,known.actor_id);assert.equal(row.migration_actor_id,known.actor_id);assert.equal(row.source_workspace_id,known.source_workspace_id);assert.equal(row.target_workspace_id,known.target_workspace_id);
      assert.equal(row.remote_started,true);assert.equal(row.remote_completed,true);assert.equal(row.entity_id,known.migration_plan_id);
      const types=(await client.query(`SELECT pg_typeof(s.entity_id)::text AS step_type,pg_typeof(m.entity_id)::text AS mutation_type,pg_typeof(p.id)::text AS migration_type
        FROM workflow_steps s JOIN mutation_operations m ON m.id=s.operation_id JOIN workspace_migration_plans p ON p.id=s.entity_id AND m.entity_id=p.id::text WHERE s.id=$1`,[originalStep.id])).rows[0];
      assert.deepEqual(types,{step_type:'uuid',mutation_type:'text',migration_type:'uuid'});
      return{originalRowsMatched:1,actualColumnTypes:types,sourceQuerySha256:createHash('sha256').update(terminal).digest('hex'),nativeWrites:0};
    }));
  await check('exact recovery facts SELECT shapes resolve original locks, component IDs, approver and frozen definition',async()=>
    rollbackSuccess('exact-recovery-facts-selects',async()=>{
      const cid=CID,wid=known.source_workspace_id,id=WORKFLOW,rev=originalWorkflow.plan_revision;
      const execution=(await client.query('SELECT * FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 FOR UPDATE',[cid,wid,id,rev])).rows;
      const steps=(await client.query('SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order FOR SHARE',[cid,wid,id,rev])).rows;
      const migration=(await client.query('SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2 FOR SHARE',[cid,known.migration_plan_id])).rows;
      const mutation=(await client.query('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND id=$2 FOR SHARE',[cid,originalStep.operation_id])).rows;
      const components=(await client.query('SELECT object_key,type,kong_id::text AS id,status,after_fingerprint,error_code FROM workspace_migration_steps WHERE cluster_id=$1 AND plan_id=$2 ORDER BY object_key',[cid,known.migration_plan_id])).rows;
      const approvals=(await client.query('SELECT * FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[cid,wid,id,rev])).rows;
      const stages=(await client.query('SELECT * FROM workflow_stages WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[cid,wid,id,rev])).rows;
      assert.equal(execution.length,1);assert.equal(steps.length,1);assert.equal(migration.length,1);assert.equal(mutation.length,1);assert(components.length>=1);
      assert.equal(approvals.length,1);assert.equal(stages.length,1);assert.equal(stages[0].required_approvals,1);assert.equal(stages[0].state,'approved');
      const definition=(await client.query('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',
        [cid,wid,originalWorkflow.definition_id,originalWorkflow.definition_version])).rows;
      assert.equal(definition.length,1);assert.equal(definition[0].mode,'single');assert.equal(definition[0].allow_self_approval,false);
      assert.equal(approvals[0].approver_id,execution[0].approved_by);assert.notEqual(execution[0].approved_by,known.actor_id);
      assert(components.every(component=>component.status==='succeeded'&&component.after_fingerprint&&component.error_code===null));
      return{selectShapesValidated:9,originalComponentCount:components.length,nativeWrites:0};
    }));
  const recoveryEventSQL=`INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_id,actor_type,action,result,execution_id,step_id,operation_id,request_id,safe_metadata) VALUES($1,$2,$3,$4,$5,$6,'user','execution.reconcile-migration-metadata','success',$7,$8,$9,$10,$11::jsonb)`;
  const eventParameters=(patch={})=>{const value={cid:CID,wid:known.source_workspace_id,id:WORKFLOW,revision:originalWorkflow.plan_revision,hash:originalWorkflow.plan_hash,
    actor:known.actor_id,execution:originalExecution.id,step:originalStep.id,operation:originalStep.operation_id,request:randomUUID(),...patch};
    return[value.cid,value.wid,value.id,value.revision,value.hash,value.actor,value.execution,value.step,value.operation,value.request,JSON.stringify({executionId:originalExecution.id,fromState:originalWorkflow.state,toState:'succeeded',requestHash:secrets.fingerprint({test:'rollback-only-shape-check'}),executionKeyFingerprint:secrets.fingerprint(originalExecution.idempotency_key),knownNativeComplete:true,nativeWrites:0,originalResponseResolved:false})];};
  await check('exact metadata recovery CAS and actor_type/result event INSERT validate deferred constraints and then roll back',async()=>
    rollbackSuccess('exact-recovery-cas-and-event',async()=>{
      assert(['uncertain','partial'].includes(originalWorkflow.state));assert(['uncertain','partial'].includes(originalExecution.state));
      const e=await client.query("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4 AND execution_actor_id=$5 AND state=$6 AND revision=$7",
        [originalExecution.id,WORKFLOW,originalWorkflow.plan_revision,originalWorkflow.plan_hash,known.actor_id,originalExecution.state,originalExecution.revision]);assert.equal(e.rowCount,1);
      const w=await client.query("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND revision=$6 AND state=$7",
        [WORKFLOW,CID,known.source_workspace_id,originalWorkflow.plan_revision,originalWorkflow.plan_hash,originalWorkflow.revision,originalWorkflow.state]);assert.equal(w.rowCount,1);
      const event=await client.query(recoveryEventSQL,eventParameters());assert.equal(event.rowCount,1);
      await client.query('SET CONSTRAINTS ALL IMMEDIATE');
      return{workflowCasRows:1,executionCasRows:1,rolledBackEventRows:1,deferredConstraintsValidated:true,nativeWrites:0};
    }));
  await check('exact recovery event INSERT rejects a missing original operation without a primary-key collision',async()=>
    trial('recovery-event-foreign-operation',[[recoveryEventSQL,eventParameters({operation:randomUUID()})],['SET CONSTRAINTS ALL IMMEDIATE']],'23503'));
  await check('all original plans, bindings, versions and steps remain unchanged after rollback trials',async()=>{
    assert.equal(await digest(),initial);return{originalFactsUnchanged:true,rollbackTrials};
  });
  passed=true;
}catch(error){failure=safeError(error);}
finally{
  if(client){await client.query('ROLLBACK').catch(()=>{});await client.end().catch(()=>{});}
  const report={passed,milestone:'M9',evidenceKind:'SQL016 actual-row diagnostics',productionAcceptance:false,nativeKongRequests:false,consoleDatabaseOnly:true,
    credentialsRecorded:false,persistedSourceRowsFabricated:false,fixtureCounts,diagnostics,checks,attempts,rollbackTrials,
    limitations:[
      'Existing approval binding replays hit their original primary key before deferred source validation; they prove no second binding, not an isolated FK predicate.',
      'Real unbound M3 plans and existing non-migration workflows are used only in rollback-only negative INSERT trials; no successful source facts are fabricated.',
      'These checks validate durable SQL identities and frozen approval material. The original native terminal bookkeeping failure and its later reconciliation require separate actual workflow acceptance evidence.',
    ],...(failure?{failure}:{})};
  process.stdout.write(JSON.stringify(report,null,2)+'\n');if(!passed)process.exitCode=1;
}
