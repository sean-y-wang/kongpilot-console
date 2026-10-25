import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const require=createRequire('/app/package.json');
const CID='e269f167-53e9-4895-af89-5b1b8835c6ec';
const errorCode=error=>/^[A-Z0-9_]+$/.test(error?.code??'')?error.code:'ASSERTION_FAILED';
const equalStoredJson=(left,right)=>assert.deepEqual(JSON.parse(JSON.stringify(left)),JSON.parse(JSON.stringify(right)));

/** Independently apply RFC 6902 operations to the stored redacted before value. */
export function applyAuditPatch(before,patch){
  let root=JSON.parse(JSON.stringify(before));
  const decode=segment=>{assert(!/~(?:[^01]|$)/.test(segment));return segment.replace(/~1/g,'/').replace(/~0/g,'~');};
  for(const operation of patch){
    assert(['add','remove','replace'].includes(operation.op));assert.equal(typeof operation.path,'string');
    if(operation.path===''){assert.notEqual(operation.op,'remove');root=JSON.parse(JSON.stringify(operation.value));continue;}
    assert(operation.path.startsWith('/'));
    const parts=operation.path.slice(1).split('/').map(decode),key=parts.pop();let parent=root;
    for(const part of parts){assert(parent!==null&&typeof parent==='object'&&Object.hasOwn(parent,part));parent=parent[part];}
    assert(parent!==null&&typeof parent==='object');
    if(Array.isArray(parent)){
      const index=key==='-'?parent.length:Number(key);assert(key==='-'||/^(?:0|[1-9]\d*)$/.test(key));
      assert(Number.isSafeInteger(index)&&index>=0&&index<=(operation.op==='add'?parent.length:parent.length-1));
      if(operation.op==='add')parent.splice(index,0,operation.value);else if(operation.op==='remove')parent.splice(index,1);else parent[index]=operation.value;
    }else{
      if(operation.op!=='add')assert(Object.hasOwn(parent,key));
      if(operation.op==='remove')delete parent[key];else Object.defineProperty(parent,key,{value:operation.value,enumerable:true,configurable:true,writable:true});
    }
  }
  return root;
}

/** Retain the failed original response while selecting its known native facts.
 * This is evidence validation only; no flag authorizes a native retry. */
export function knownCompletedOriginal(packet,proof,proofSha256){
  const resolution=packet.resolution;
  assert.equal(packet.state,'response_observed');assert.equal(packet.status,503);assert.equal(packet.errorCode,'WORKFLOW_EXECUTION_FAILED');
  assert.equal(resolution?.knownNativeComplete,true);assert.equal(resolution.metadataRecovered,true);assert.equal(resolution.receiptVerified,true);
  assert.equal(resolution.finalState,'succeeded');assert.equal(resolution.responseResolved,false);
  assert.match(proofSha256,/^[a-f0-9]{64}$/);assert.equal(resolution.factProofSha256,proofSha256);
  assert.equal(proof.source,'own-lab-readonly-sql');assert.equal(proof.nativeComplete,true);
  assert.equal(proof.execution.originalRequestId,packet.requestId);assert.equal(proof.execution.originalIdempotencyKey,packet.key);
  assert.equal(proof.workflow.state,'uncertain');assert.equal(proof.execution.state,'uncertain');
  assert.equal(proof.migration.state,'succeeded');assert.equal(proof.mutation.state,'succeeded');
  assert.equal(proof.mutation.remoteStarted,true);assert.equal(proof.mutation.remoteCompleted,true);assert.equal(proof.step.state,'succeeded');
  assert.equal(proof.step.operationId,proof.mutation.id);
  assert.equal(resolution.metadataRecovery?.workflowId,proof.workflow.id);assert.equal(resolution.metadataRecovery.executionId,proof.execution.id);
  assert.equal(resolution.metadataRecovery.clusterId,proof.scope.clusterId);assert.equal(resolution.metadataRecovery.workspaceId,proof.scope.sourceWorkspaceId);
  assert(Array.isArray(proof.components)&&proof.components.length>0&&proof.components.every(row=>row.state==='succeeded'));
  assert(proof.components.every(row=>typeof row.key==='string'&&typeof row.type==='string'&&typeof row.id==='string'));
  return {workflowId:proof.workflow.id,executionId:proof.execution.id,migrationPlanId:proof.migration.id,
    mutationId:proof.mutation.id,stepId:proof.step.id,sourceWorkspaceId:proof.scope.sourceWorkspaceId,targetWorkspaceId:proof.scope.targetWorkspaceId,
    components:proof.components.map(row=>({key:row.key,type:row.type,id:row.id})),
    proofSha256,originalStatus:503,originalResponseRewritten:false,responseResolved:false};
}

/** Bind every migrated component to its own audit and original native after HMAC. */
export function verifyMigrationComponentAudit(node,component,audit,sourceWorkspaceId,targetWorkspaceId,secrets){
  assert.equal(component.object_key,node.key);assert.equal(component.type,node.type);assert.equal(component.kong_id,node.id);
  assert.equal(component.status,'succeeded');assert.equal(component.error_code,null);assert.match(component.after_fingerprint,/^[a-f0-9]{64}$/);
  assert.equal(audit.entity_type,node.type);assert.equal(audit.entity_id,node.id);assert.equal(audit.result,'succeeded');
  if(node.inheritedOnly){
    assert.equal(audit.action,'workspace.inherit');
    assert.deepEqual(audit.before,{workspace_id:node.sourceWorkspaceId,target:node.data.target});
    assert.deepEqual(audit.after,{workspace_id:targetWorkspaceId,target:node.data.target});
    assert.equal(component.after_fingerprint,secrets.fingerprint(node.data));
  }else{
    assert.equal(audit.action,'workspace.migrate');assert.equal(audit.workspace_id,sourceWorkspaceId);
    equalStoredJson(audit.before,secrets.redact(node.data));
    const after=applyAuditPatch(node.data,audit.json_patch);
    equalStoredJson(audit.after,secrets.redact(after));assert.equal(secrets.fingerprint(after),component.after_fingerprint);
    assert(Array.isArray(after.tags));assert.deepEqual([...after.tags].sort(),[...node.afterTags].sort());
    const stable=value=>Object.fromEntries(Object.entries(value).filter(([name])=>!['tags','updated_at'].includes(name)));
    assert.deepEqual(stable(after),stable(node.data),'Migration audit cannot hide a non-tag configuration change');
  }
  assert.deepEqual(applyAuditPatch(audit.before,audit.json_patch),audit.after);
  return {entityType:node.type,entityId:node.id,auditId:audit.id,componentAfterHmacVerified:true,patchVerified:true};
}

/** Expected business actions keep their exact cluster. Global IAM envelopes
 * exist only for cluster management and cannot stand in for a business audit. */
export function verifyRequestAuditIdentities(request,facts,hits){
  assert(hits.length>0);let globalManagementEnvelopes=0;const historicalMissingSourceIP=[];
  for(const hit of hits){assert(facts.includes(hit));if(request.clusterId)assert.equal(hit.cluster_id,request.clusterId);}
  for(const fact of facts){
    assert.equal(fact.request_id,request.requestId);assert.equal(fact.actor_id,request.actorId);assert.equal(fact.actor_type,'user');
    if(request.clusterId&&fact.cluster_id!==request.clusterId){
      assert.equal(request.category,'cluster.metadata');assert.equal(fact.cluster_id,null);assert.equal(fact.entity_type,'clusters');
      assert.equal(fact.entity_id,request.clusterId);assert.equal(fact.workspace_id,null);
      assert(['iam.write.requested','iam.write'].includes(fact.action));globalManagementEnvelopes++;
    }
    if(!fact.source_ip){
      const approvedHistorical=request.source==='native'&&request.index===77&&request.method==='POST'
        &&request.requestId==='5d688f5d-b6b4-4559-90d9-356ba7efd96c'&&request.actorId==='f5738365-97c4-44af-abdb-0262c5104376'
        &&request.clusterId==='e269f167-53e9-4895-af89-5b1b8835c6ec'&&request.startedAt==='2026-10-12T18:39:16.184Z'
        &&request.routePath==='/clusters/e269f167-53e9-4895-af89-5b1b8835c6ec/workspace-migrations/6a2e803f-6f5e-436e-b896-6977e8a323db/apply'
        &&['migrate.requested','workspace.migrate','migrate'].includes(fact.action)
        &&new Date(fact.occurred_at).getTime()>=Date.parse(request.startedAt)
        &&new Date(fact.occurred_at).getTime()<Date.parse(request.startedAt)+30000;
      assert(approvedHistorical,'Current source IP audit metadata missing');
      historicalMissingSourceIP.push({auditId:fact.id,action:fact.action,entityType:fact.entity_type});
    }
    assert(Number.isFinite(new Date(fact.occurred_at).getTime()));assert(typeof fact.entity_type==='string'&&fact.entity_type.length>0);
  }
  if(historicalMissingSourceIP.length)assert.equal(historicalMissingSourceIP.length,4,'Only the four identified old audit rows are historical');
  return{globalManagementEnvelopes,historicalMissingSourceIP};
}

export async function runAudit(manifest){
  const checks=[],coverage=[],historicalShortfalls=[],attempts=[],knownNativeCompletionCoverage=[];
  let client,passed=false,failure,auditRowCount=0,rollbackTrials=0,evidenceContext;
  const check=async(name,fn)=>{try{const evidence=await fn();checks.push({name,passed:true,...(evidence??{})});}catch(error){checks.push({name,passed:false,code:errorCode(error)});throw error;}};
  const denied=async(name,sql,values)=>{
    await client.query('BEGIN');let code;
    try{await client.query("SET LOCAL statement_timeout='5s'");try{await client.query(sql,values);}catch(error){code=errorCode(error);}}
    finally{await client.query('ROLLBACK');rollbackTrials++;}
    attempts.push({name,code:code??'UNEXPECTED_SQL_SUCCESS',rolledBack:true});assert.equal(code,'42501');
  };
  try{
    await check('fixed self-owned lab container, console database and runtime role gate',async()=>{
      assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-console-api-1');
      assert.equal(manifest.clusterId,CID);assert.equal(manifest.milestone,'M9');
      assert.equal(typeof manifest.verifiedAfter,'string');assert(Number.isFinite(Date.parse(manifest.verifiedAfter)));
      assert(Array.isArray(manifest.requests)&&manifest.requests.length>0&&manifest.requests.length<=500);
      const url=new URL(process.env.DATABASE_URL);assert.equal(url.hostname,'console-db');assert.equal(url.port,'5432');
      assert.equal(url.pathname,'/kongpilot');assert.equal(url.username,'kongpilot_lab_app');
      const {Client}=require('pg');client=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await client.connect();
      const actual=(await client.query('SELECT current_database() AS database,current_user AS role')).rows[0];
      assert.equal(actual.database,'kongpilot');assert.equal(actual.role,'kongpilot_lab_app');
    });
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query("SET LOCAL statement_timeout='10s'");
    const requestIds=manifest.requests.map(request=>request.requestId).filter(Boolean);
    const rows=(await client.query('SELECT * FROM audit_events WHERE request_id=ANY($1::text[]) ORDER BY chain_scope,sequence LIMIT 2001',[requestIds])).rows;
    assert(rows.length<=2000,'Bounded audit request projection required');auditRowCount=rows.length;
    const byRequest=new Map();for(const row of rows)byRequest.set(row.request_id,[...(byRequest.get(row.request_id)??[]),row]);
    await check('successful business and original known-native-complete requests bind to original UUID, actor and cluster',async()=>{
      for(const request of manifest.requests){
        evidenceContext={stage:'request-identities',requestId:request.requestId,category:request.category};
        assert.equal(typeof request.requestId,'string');assert.equal(typeof request.actorId,'string');
        const facts=byRequest.get(request.requestId)??[];
        const expected=request.expectedActions;
        assert(Array.isArray(expected)&&expected.length>0);
        const hits=facts.filter(row=>expected.some(action=>action.endsWith('*')?row.action.startsWith(action.slice(0,-1)):row.action===action));
        if(!hits.length&&request.category==='route.simulation'&&Date.parse(request.startedAt)<Date.parse(manifest.verifiedAfter)){
          historicalShortfalls.push({source:request.source,index:request.index,requestId:request.requestId,category:request.category,reason:'PRE_FIX_ROUTE_SIMULATION_PERSISTED_WITHOUT_AUDIT',backfilled:false});
          coverage.push({source:request.source,index:request.index,requestId:request.requestId,category:request.category,covered:false,historical:true});continue;
        }
        assert(hits.length>0,'Required request audit missing');
        const identity=verifyRequestAuditIdentities(request,facts,hits);
        if(identity.historicalMissingSourceIP.length)historicalShortfalls.push({source:request.source,index:request.index,requestId:request.requestId,
          category:request.category,reason:'PRE_FIX_MIGRATION_AUDIT_MISSING_SOURCE_IP',affectedAuditRows:4,audits:identity.historicalMissingSourceIP,backfilled:false});
        if(request.category==='proxy.probe'){
          assert(hits.some(row=>row.action==='toolbox.proxy-probe.intent'&&row.result==='pending'));
          assert(hits.some(row=>row.action==='toolbox.proxy-probe.result'&&row.result==='success'));
        }
        coverage.push({source:request.source,index:request.index,requestId:request.requestId,category:request.category,covered:true,
          auditRows:facts.length,...identity,actions:[...new Set(facts.map(row=>row.action))].sort(),
          ...(request.knownNativeComplete?{originalStatus:503,knownNativeComplete:true,originalResponseRewritten:false}: {})});
      }
      return {businessRequests:manifest.requests.length,auditRows:rows.length,historicalMissingTransactions:historicalShortfalls.length};
    });
    await check('original 503 native completion covers every sealed component and retains its uncertain parent audit',async()=>{
      const originals=manifest.requests.filter(request=>request.knownNativeComplete);assert(originals.length>=1,'Original known-native-complete failure evidence required');
      require('reflect-metadata');const {SecretService}=require('/app/apps/console-api/dist/infrastructure/secret.service.js'),secrets=new SecretService();
      for(const request of originals){
        evidenceContext={stage:'known-original-identity',requestId:request.requestId};
        const reference=request.knownNativeComplete,originalAudit=byRequest.get(request.requestId)??[];
        const e=(await client.query('SELECT * FROM workflow_executions WHERE id=$1 AND workflow_id=$2 AND cluster_id=$3',[reference.executionId,reference.workflowId,CID])).rows[0];
        const w=(await client.query('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2',[reference.workflowId,CID])).rows[0];assert(e&&w);
        assert.equal(e.request_id,request.requestId);assert.equal(e.execution_actor_id,request.actorId);assert.equal(w.requester_user_id,request.actorId);
        assert.equal(e.workspace_id,reference.sourceWorkspaceId);assert.equal(w.workspace_id,reference.sourceWorkspaceId);
        const v=(await client.query('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND plan_revision=$2',[w.id,e.plan_revision])).rows[0];assert(v);
        const plan=secrets.decrypt(v.payload_secret,`workflow:${CID}:${e.workspace_id}:${w.id}:${e.plan_revision}:plan`);
        assert.equal(secrets.fingerprint(plan),e.plan_hash);assert.equal(secrets.fingerprint(plan),w.plan_hash);assert.equal(plan.requester.id,request.actorId);
        assert.equal(plan.kind,'workspace-migration');assert.equal(plan.subject.type,'workspace_migration_plans');assert.equal(plan.steps.length,1);
        const frozenStep=plan.steps[0];assert.equal(frozenStep.kind,'native');assert.equal(frozenStep.entityType,'workspace_migration');assert.equal(frozenStep.mutationAction,'migrate');
        assert.equal(frozenStep.entityId,plan.subject.id);assert.equal(plan.migration.targetWorkspaceId,reference.targetWorkspaceId);
        if(reference.migrationPlanId)assert.equal(plan.subject.id,reference.migrationPlanId);if(reference.stepId)assert.equal(frozenStep.id,reference.stepId);
        const p=(await client.query('SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2',[CID,plan.subject.id])).rows[0];assert(p);
        evidenceContext={stage:'known-original-material',requestId:request.requestId};
        const material=secrets.decrypt(p.payload_secret,`workspace-migration:${p.id}`);assert.equal(secrets.fingerprint(material),plan.migration.materialHmac);
        assert.equal(material.nodes.length,reference.components.length);
        for(const node of material.nodes)assert(reference.components.some(component=>component.key===node.key&&component.type===node.type&&component.id===node.id));
        assert.equal(p.actor_id,request.actorId);assert.equal(p.source_workspace_id,reference.sourceWorkspaceId);assert.equal(p.target_workspace_id,reference.targetWorkspaceId);assert.equal(p.state,'succeeded');
        const m=(await client.query('SELECT * FROM mutation_operations WHERE id=$1 AND cluster_id=$2',[reference.mutationId,CID])).rows[0];assert(m);
        assert.equal(m.workflow_id,w.id);assert.equal(m.workflow_execution_id,e.id);assert.equal(m.workflow_step_id,frozenStep.id);assert.equal(m.actor_id,request.actorId);
        assert.equal(m.request_id,request.requestId);assert.equal(m.entity_id,p.id);assert.equal(m.state,'succeeded');assert.equal(m.remote_started,true);assert.equal(m.remote_completed,true);assert.equal(p.operation_id,m.id);
        evidenceContext={stage:'known-original-native-receipt',requestId:request.requestId};
        const step=(await client.query('SELECT * FROM workflow_steps WHERE id=$1 AND workflow_id=$2',[frozenStep.id,w.id])).rows[0];assert(step);
        assert.equal(step.state,'succeeded');assert.equal(step.operation_id,m.id);assert.equal(step.plan_hash,e.plan_hash);assert.equal(step.before_fingerprint,frozenStep.beforeFingerprint);assert.equal(step.mutation_payload_hmac,frozenStep.mutationPayloadHmac);
        assert.equal(secrets.fingerprint(secrets.decrypt(m.before_secret,`mutation:${m.id}:before`)),frozenStep.beforeFingerprint);
        assert.equal(secrets.fingerprint(secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`)),frozenStep.mutationPayloadHmac);
        const result=secrets.decrypt(m.result_secret,`mutation:${m.id}:result`);assert.equal(result.id,p.id);assert.equal(result.state,'succeeded');assert.equal(result.affected.length,material.nodes.length);
        const receipt=secrets.decrypt(step.receipt_secret,`workflow:${e.id}:${step.id}:receipt`);
        assert.equal(receipt.receipt.operationId,m.id);assert.equal(receipt.receipt.state,'succeeded');assert.equal(receipt.receipt.remoteStarted,true);assert.equal(receipt.receipt.remoteCompleted,true);equalStoredJson(receipt.result,secrets.redact(result));
        evidenceContext={stage:'known-original-snapshot',requestId:request.requestId};
        assert.equal(e.snapshot_state,'ready');const snapshot=secrets.decrypt(e.snapshot_secret,`workflow:${CID}:${e.workspace_id}:${w.id}:${e.id}:snapshot`);
        assert.equal(secrets.fingerprint(snapshot),e.snapshot_hash);assert.equal(snapshot.planHash,e.plan_hash);assert.equal(snapshot.executionId,e.id);
        const expectedSnapshot=[...plan.prerequisites.map(item=>({path:item.path,type:item.type,id:item.id,fingerprint:item.fingerprint})),...frozenStep.nativeRequests.map(item=>({path:item.canonicalPath,type:item.nativeType,id:item.nativeId,fingerprint:item.beforeHmac}))];
        assert.equal(snapshot.objects.length,expectedSnapshot.length);
        for(const expected of expectedSnapshot){const object=snapshot.objects.find(item=>item.path===expected.path);assert(object&&!object.absent);
          assert.equal(object.type,expected.type);assert.equal(object.id,expected.id);assert.equal(object.fingerprint,expected.fingerprint);assert.equal(secrets.fingerprint(object.before),expected.fingerprint);}
        const components=(await client.query('SELECT * FROM workspace_migration_steps WHERE cluster_id=$1 AND plan_id=$2 ORDER BY object_key',[CID,p.id])).rows;
        assert.equal(components.length,material.nodes.length);const items=[];
        for(const node of material.nodes){const component=components.find(row=>row.object_key===node.key);assert(component);
          evidenceContext={stage:'known-original-component-audit',requestId:request.requestId,entityType:node.type,entityId:node.id};
          const candidates=originalAudit.filter(row=>row.entity_type===node.type&&row.entity_id===node.id&&row.action===(node.inheritedOnly?'workspace.inherit':'workspace.migrate'));
          assert.equal(candidates.length,1,'Every exact migrated component must have its own original request audit');const audit=candidates[0];
          assert.equal(audit.actor_id,request.actorId);assert.equal(audit.cluster_id,CID);assert.equal(audit.workflow_id,w.id);assert.equal(audit.request_id,request.requestId);
          items.push(verifyMigrationComponentAudit(node,component,audit,reference.sourceWorkspaceId,reference.targetWorkspaceId,secrets));
        }
        evidenceContext={stage:'known-original-parent-outcome',requestId:request.requestId};
        assert(originalAudit.some(row=>row.action==='workflow.execute.requested'&&row.result==='pending'));
        assert(originalAudit.some(row=>row.action==='workflow.execute'&&row.result==='uncertain'));
        assert(!originalAudit.some(row=>row.action==='workflow.execute'&&row.result==='success'),'Original failure must not be backfilled as success');
        evidenceContext={stage:'known-original-metadata-recovery',requestId:request.requestId};
        const recovery=manifest.requests.find(row=>row.category==='workflow.reconcile-migration-metadata'&&row.workflowId===w.id);assert(recovery);
        const audit=(byRequest.get(recovery.requestId)??[]).find(row=>row.action==='workflow.reconcile-migration-metadata');assert(audit);
        assert.equal(audit.actor_id,request.actorId);assert.equal(audit.workflow_id,w.id);assert.equal(audit.result,'success');
        assert.equal(audit.after.knownNativeComplete,true);assert.equal(audit.after.nativeWrites,0);assert.equal(audit.after.originalResponseResolved,false);
        const event=(await client.query("SELECT * FROM workflow_events WHERE workflow_id=$1 AND request_id=$2 AND action='execution.reconcile-migration-metadata'",[w.id,recovery.requestId])).rows;
        assert.equal(event.length,1);assert.equal(event[0].execution_id,e.id);assert.equal(event[0].step_id,frozenStep.id);assert.equal(event[0].operation_id,m.id);
        assert.equal(event[0].actor_id,request.actorId);assert.equal(event[0].result,'success');assert.equal(event[0].safe_metadata.nativeWrites,0);assert.equal(event[0].safe_metadata.originalResponseResolved,false);
        assert.equal(w.state,'succeeded');assert.equal(e.state,'succeeded');
        knownNativeCompletionCoverage.push({originalRequestId:request.requestId,originalStatus:503,originalWorkflowId:w.id,originalExecutionId:e.id,
          componentCount:items.length,components:items,originalParentAudit:'uncertain',metadataRecoveryRequestId:recovery.requestId,metadataRecoveryAudited:true,nativeWritesOnRecovery:0,originalResponseRewritten:false});
      }
      return {knownCompletedOriginals:originals.length,allComponentAuditsVerified:true};
    });
    await check('new direct controller migration audits every actual component with complete current IP metadata',async()=>{
      const direct=manifest.requests.filter(request=>/\/workspace-migrations\/[a-f0-9-]+\/apply$/.test(request.routePath??'')
        &&Date.parse(request.startedAt)>=Date.parse(manifest.verifiedAfter));assert(direct.length>=1,'Current direct migration acceptance required');
      require('reflect-metadata');const {SecretService}=require('/app/apps/console-api/dist/infrastructure/secret.service.js'),secrets=new SecretService();let componentCount=0;
      for(const request of direct){
        const planId=request.routePath.split('/').at(-2),p=(await client.query('SELECT * FROM workspace_migration_plans WHERE id=$1 AND cluster_id=$2',[planId,CID])).rows[0];
        assert(p);assert.equal(p.actor_id,request.actorId);assert.equal(p.state,'succeeded');
        const material=secrets.decrypt(p.payload_secret,`workspace-migration:${p.id}`);assert.equal(secrets.fingerprint({cid:CID,actor:request.actorId,payload:material}),p.plan_hash);
        const m=(await client.query('SELECT * FROM mutation_operations WHERE id=$1 AND cluster_id=$2',[p.operation_id,CID])).rows[0];assert(m);
        assert.equal(m.request_id,request.requestId);assert.equal(m.actor_id,request.actorId);assert.equal(m.state,'succeeded');assert.equal(m.remote_started,true);assert.equal(m.remote_completed,true);
        const components=(await client.query('SELECT * FROM workspace_migration_steps WHERE cluster_id=$1 AND plan_id=$2',[CID,p.id])).rows;assert.equal(components.length,material.nodes.length);
        const audits=byRequest.get(request.requestId)??[];
        for(const node of material.nodes){const component=components.find(row=>row.object_key===node.key);assert(component);
          const rows=audits.filter(row=>row.entity_type===node.type&&row.entity_id===node.id&&row.action===(node.inheritedOnly?'workspace.inherit':'workspace.migrate'));
          assert.equal(rows.length,1);const row=rows[0];assert(row.source_ip);assert.equal(row.actor_id,request.actorId);assert.equal(row.cluster_id,CID);assert.equal(row.request_id,request.requestId);
          verifyMigrationComponentAudit(node,component,row,p.source_workspace_id,p.target_workspace_id,secrets);componentCount++;
        }
        assert(audits.some(row=>row.action==='migrate'&&row.result==='success'&&row.source_ip));
      }
      return{freshDirectRequests:direct.length,componentAuditsWithIp:componentCount,historicalRowsBackfilled:false};
    });
    await check('new deployment route simulation has its own committed audit instead of rewriting historical rows',async()=>{
      const fresh=manifest.requests.filter(request=>request.category==='route.simulation'&&Date.parse(request.startedAt)>=Date.parse(manifest.verifiedAfter));
      assert(fresh.length>=1,'Fresh simulation acceptance request required');
      for(const request of fresh){const row=(byRequest.get(request.requestId)??[]).find(fact=>fact.action==='toolbox.route.simulated');
        assert(row&&row.result==='success');
        const material=(await client.query('SELECT actor_id,cluster_id,workspace_id FROM toolbox_debug_runs WHERE id=$1 AND kind=$2',[row.entity_id,'route-simulation'])).rows;
        assert.equal(material.length,1);assert.equal(material[0].actor_id,request.actorId);assert.equal(material[0].cluster_id,CID);assert.equal(material[0].workspace_id,row.workspace_id);
      }
      return {freshAuditedSimulations:fresh.length,historicalRowsBackfilled:false};
    });
    await check('actual write actions cover native CRUD, recovery, batch, cache, workflow and personal draft lifecycle',async()=>{
      const required=['create','update','delete','restore','toolbox.batch.plan','toolbox.cache.invalidate','workflow.approve','workflow.execute',
        'draft.create','draft.archive','draft.restore','toolbox.proxy-probe.intent','toolbox.proxy-probe.result','toolbox.route.simulated'];
      const actions=new Set(rows.map(row=>row.action));for(const action of required)assert(actions.has(action),action);
      return {requiredActions:required,actionCounts:Object.fromEntries(required.map(action=>[action,rows.filter(row=>row.action===action).length]))};
    });
    await check('JSON patch transforms every redacted before value into its exact redacted after value',async()=>{
      for(const row of rows){assert(Array.isArray(row.json_patch));assert.deepEqual(applyAuditPatch(row.before,row.json_patch),row.after);}
      return {validatedRows:rows.length};
    });
    await check('own cluster and global append-only chains and chain heads verify independently',async()=>{
      require('reflect-metadata');const {canonicalJson}=require('/app/apps/console-api/dist/infrastructure/secret.service.js');
      const scopes=[`cluster:${CID}`,'global'];
      const chain=(await client.query('SELECT * FROM audit_events WHERE chain_scope=ANY($1::text[]) ORDER BY chain_scope,sequence LIMIT 10001',[scopes])).rows;
      assert(chain.length<=10000,'Bounded complete audit chains required');
      const heads=(await client.query('SELECT chain_scope,last_sequence::text,last_hash FROM audit_chain_heads WHERE chain_scope=ANY($1::text[])',[scopes])).rows;
      for(const scope of scopes){
        const facts=chain.filter(row=>row.chain_scope===scope),head=heads.find(row=>row.chain_scope===scope);assert(facts.length>0&&head);
        let prior='GENESIS',sequence=0n;
        for(const row of facts){
          sequence++;assert.equal(row.sequence,String(sequence));assert.equal(row.prev_hash,prior);
          const record=Object.fromEntries(['id','chain_scope','sequence','actor_id','actor_type','source_ip','cluster_id','workspace_id',
            'entity_type','entity_id','action','before','after','json_patch','workflow_id','result','request_id','prev_hash'].map(key=>[key,row[key]]));
          record.occurred_at=new Date(row.occurred_at).toISOString();
          const hash=createHash('sha256').update(canonicalJson(record)).digest('hex');assert.equal(hash,row.event_hash);prior=hash;
        }
        assert.equal(head.last_sequence,String(sequence));assert.equal(head.last_hash,prior);
      }
      return {chainCount:scopes.length,chainRows:chain.length};
    });
    await client.query('ROLLBACK');rollbackTrials++;
    await check('runtime cannot UPDATE, DELETE or TRUNCATE original audit facts',async()=>{
      assert(rows.length>0);
      await denied('audit.update','UPDATE audit_events SET result=result WHERE id=$1',[rows[0].id]);
      await denied('audit.delete','DELETE FROM audit_events WHERE id=$1',[rows[0].id]);
      await denied('audit.truncate','TRUNCATE audit_events',[]);
    });
    await check('unknown original refresh response remains unresolved despite replacing its login session',async()=>{
      for(const unknown of manifest.unknownRequests??[]){assert.equal(unknown.responseResolved,false);assert.equal(unknown.originalKeyReplayed,false);}
      return {unknownOriginalCount:(manifest.unknownRequests??[]).length,originalResponseResolved:false};
    });
    passed=true;
  }catch(error){failure={code:errorCode(error),...(evidenceContext?{context:evidenceContext}:{})};}
  finally{
    if(client){await client.query('ROLLBACK').catch(()=>undefined);await client.end().catch(()=>undefined);}
    const report={passed,milestone:'M9',productionDeployment:false,credentialsRecorded:false,nativeKongRequests:false,consoleDatabaseOnly:true,
      verifiedAfter:manifest.verifiedAfter,auditRows:auditRowCount,rollbackTrials,checks,coverage,historicalShortfalls,
      failedOriginalRequests:manifest.failedRequests,unknownOriginalRequests:manifest.unknownRequests,excludedAuthenticationRequests:manifest.excludedAuthenticationRequests,
      attempts,knownNativeCompletionCoverage,backfilledAuditRows:false,originalResponseResolved:false,
      limits:['Coverage is for successful native and browser business request receipts retained in the own-lab journals. Validation/permission denials and authentication requests are reported separately.','Pre-fix route simulation missing audit transactions remain historical deficiencies; fresh post-deployment requests must independently prove the corrected transaction.'],
      ...(failure?{failure}:{})};
    process.stdout.write(JSON.stringify(report,null,2)+'\n');if(!passed)process.exitCode=1;
  }
}
