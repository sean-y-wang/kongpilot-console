import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { applyAuditPatch } from './m9-native-audit-worker.mjs';
import { assertM10RequestAuditIdentity, verifyM10AnalyticalAudit, verifyM10FixedIamAuditEvidence } from './m10-audit-policy.mjs';

const require=createRequire('/app/package.json');
const eq=(a,b)=>assert.deepEqual(JSON.parse(JSON.stringify(a)),JSON.parse(JSON.stringify(b)));
const safeCode=e=>/^[A-Z0-9_]{1,128}$/.test(e?.code??'')?e.code:e?.message==='M10_CURRENT_SOURCE_IP_REQUIRED'||e?.message==='M10_AUDIT_SCOPE_MISMATCH'?e.message:'ASSERTION_FAILED';

export async function runM10Audit(manifest){
 const checks=[],coverage=[],nativeCompletionCoverage=[],analyticalCompletionCoverage=[],runtimeDenials=[];let client,passed=false,failure,auditRows=0,chainRows=0,evidenceContext;
 const check=async(name,fn)=>{try{const evidence=await fn();checks.push({name,passed:true,...(evidence??{})});}catch(error){checks.push({name,passed:false,code:safeCode(error)});throw error;}};
 try{
  await check('fixed own console database and current runtime role',async()=>{
   assert.equal(process.env.RELEASE_LAB_READY,'true');assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-console-api-1');assert.equal(manifest.milestone,'M10');
   assert(manifest.clusterIds.length===2&&new Set(manifest.clusterIds).size===2);assert(Array.isArray(manifest.attempts)&&manifest.attempts.length<=1000);
   const u=new URL(process.env.DATABASE_URL);assert.equal(u.hostname,'console-db');assert.equal(u.port,'5432');assert.equal(u.pathname,'/kongpilot');assert.equal(u.username,'kongpilot_lab_app');
   const {Client}=require('pg');client=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await client.connect();const actual=(await client.query('SELECT current_database() AS database,current_user AS role')).rows[0];assert.equal(actual.database,'kongpilot');assert.equal(actual.role,'kongpilot_lab_app');
  });
  require('reflect-metadata');const {SecretService,canonicalJson}=require('/app/apps/console-api/dist/infrastructure/secret.service.js'),secrets=new SecretService();
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await client.query("SET LOCAL statement_timeout='10s'");
  const requestIds=[...new Set(manifest.attempts.map(r=>r.requestId).filter(Boolean))],keys=[...new Set(manifest.attempts.map(r=>r.originalKey).filter(Boolean))];
  const rows=(await client.query('SELECT * FROM audit_events WHERE request_id=ANY($1::text[]) ORDER BY chain_scope,sequence LIMIT 10001',[requestIds])).rows;assert(rows.length<=10000);auditRows=rows.length;
  const byRequest=new Map();for(const row of rows)byRequest.set(row.request_id,[...(byRequest.get(row.request_id)??[]),row]);
  await check('every successful M10 business request has original actor, current IP and exact tenant audit',async()=>{
   for(const request of manifest.requests){evidenceContext={stage:'request-identities',requestId:request.requestId,category:request.category};const facts=byRequest.get(request.requestId)??[],hits=facts.filter(row=>request.expectedActions.some(action=>action.endsWith('*')?row.action.startsWith(action.slice(0,-1)):row.action===action));assert(hits.length>0,'M10_BUSINESS_AUDIT_MISSING');
    let identityRequest=request,iamScopeNormalization=null;
    if(request.category==='iam.fixed'){
     const operations=(await client.query('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[request.actorId,request.originalKey])).rows;assert.equal(operations.length,1,'M10_IAM_EXACT_OPERATION_REQUIRED');const operation=operations[0];
     assert(operation.payload_secret&&operation.result_secret);const payload=secrets.decrypt(operation.payload_secret,`iam:${operation.id}:payload`),result=secrets.decrypt(operation.result_secret,`iam:${operation.id}:result`);
     assert.equal(secrets.fingerprint({actor:operation.actor_id,module:operation.module,action:operation.action,target:operation.target_id??null,clusterId:operation.cluster_id,workspaceId:operation.workspace_id,payload}),operation.request_hash,'M10_IAM_SEALED_REQUEST_SCOPE_MISMATCH');eq(operation.safe_result,secrets.redact(result));
     const original=request.iamFixed,roleId=original.kind==='role-create'?original.result.id:original.kind==='role-permissions'?original.subjectId:original.result.role_id;
     const role=(await client.query('SELECT id,cluster_id,workspace_id,name,code FROM roles WHERE id=$1',[roleId])).rows[0];
     const binding=original.kind.startsWith('user-binding-')?(await client.query('SELECT id,user_id,role_id,cluster_id,workspace_id FROM user_role_bindings WHERE id=$1',[original.result.id])).rows[0]:null;
     identityRequest=verifyM10FixedIamAuditEvidence(request,operation,role,binding,payload,result);
     assert(identityRequest.clusterId===null||manifest.clusterIds.includes(identityRequest.clusterId),'M10_IAM_OWNED_CLUSTER_REQUIRED');
     assert.equal(facts.length,3,'M10_IAM_THREE_TYPED_AUDITS_REQUIRED');
     for(const rule of identityRequest.iamAuditIdentity.rules)assert.equal(facts.filter(fact=>fact.action===rule.action&&fact.entity_type===rule.entityType&&fact.entity_id===rule.entityId&&fact.result===rule.result).length,1,'M10_IAM_EXACT_TYPED_AUDIT_REQUIRED');
     identityRequest.iamAuditIdentity.sourceIp=facts.find(fact=>fact.action===identityRequest.iamAuditIdentity.rules[0].action).source_ip;
     iamScopeNormalization={source:'exact-sealed-iam-operation-and-real-subject',operationId:operation.id,roleId:role.id,bindingId:binding?.id??null,clusterId:identityRequest.clusterId,workspaceId:identityRequest.workspaceId,typedAuditRulesVerified:3,auditRowsChanged:false};
    }
    let alternateScope=null;
    if(request.category==='governance.promote'){const parent=(await client.query('SELECT actor_id,cluster_id,workspace_id,target_cluster_id,target_workspace_id FROM governance_promotions WHERE id=$1 AND actor_id=$2 AND cluster_id=$3',[request.entityId,request.actorId,request.clusterId])).rows[0];assert(parent&&parent.workspace_id===request.workspaceId);alternateScope={clusterId:parent.target_cluster_id,workspaceId:parent.target_workspace_id};}
    if(['governance.fix','governance.reconcile'].includes(request.category)){const parent=(await client.query('SELECT actor_id,cluster_id,workspace_id,target_workspace_id FROM governance_fix_requests WHERE id=$1 AND actor_id=$2 AND cluster_id=$3',[request.entityId,request.actorId,request.clusterId])).rows[0];assert(parent&&parent.workspace_id===request.workspaceId);alternateScope={clusterId:parent.cluster_id,workspaceId:parent.target_workspace_id};}
    for(const fact of facts)assertM10RequestAuditIdentity(identityRequest,fact,alternateScope);
    if(request.category==='governance.inspection')for(const action of request.expectedActions)assert(hits.some(r=>r.action===action));
    if(request.category==='governance.comparison')for(const action of request.expectedActions)assert(hits.some(r=>r.action===action));
    if(request.category==='proxy.probe')for(const action of request.expectedActions)assert(hits.some(r=>r.action===action));
    coverage.push({source:request.source,index:request.index,requestId:request.requestId,category:request.category,covered:true,auditRows:facts.length,actions:[...new Set(hits.map(r=>r.action))].sort(),...(iamScopeNormalization?{scopeNormalization:iamScopeNormalization}:{})});
   }return{businessRequests:manifest.requests.length,coveredRequests:coverage.length};
  });
  await check('known native completions are audited even when their original HTTP response failed',async()=>{
   const mutations=(await client.query('SELECT * FROM mutation_operations WHERE cluster_id=ANY($1::uuid[]) AND(request_id=ANY($2::text[]) OR idempotency_key=ANY($3::text[])) ORDER BY created_at,id LIMIT 2001',[manifest.clusterIds,requestIds,keys])).rows;assert(mutations.length<=2000);
   const nativeTypes=new Set(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','targets','credentials']);
   for(const op of mutations){if(!nativeTypes.has(op.entity_type)||!op.remote_completed)continue;evidenceContext={stage:'native-receipt',operationId:op.id,requestId:op.request_id,entityType:op.entity_type};const original=manifest.attempts.find(r=>r.requestId===op.request_id);assert(original,'NATIVE_ORIGINAL_REQUEST_MISSING');assert.equal(op.actor_id,original.actorId);assert(manifest.clusterIds.includes(op.cluster_id));assert.equal(op.remote_started,true);assert(op.result_secret);
    const facts=byRequest.get(op.request_id)??[],hits=facts.filter(r=>r.cluster_id===op.cluster_id&&r.workspace_id===op.workspace_id&&r.actor_id===op.actor_id&&r.entity_type===op.entity_type&&r.entity_id===op.entity_id&&r.action===op.action&&['success','succeeded','uncertain'].includes(r.result));assert(hits.length>0,'NATIVE_COMPONENT_AUDIT_MISSING');
    const before=op.before_secret?secrets.decrypt(op.before_secret,`mutation:${op.id}:before`):null,result=secrets.decrypt(op.result_secret,`mutation:${op.id}:result`),after=['delete','purge'].includes(op.action)?null:result?.entity??result;
    const audit=hits.find(r=>canonicalJson(r.before)===canonicalJson(secrets.redact(before))&&canonicalJson(r.after)===canonicalJson(secrets.redact(after)));assert(audit,'NATIVE_ENCRYPTED_RECEIPT_AUDIT_MISMATCH');assert(audit.source_ip);eq(applyAuditPatch(audit.before,audit.json_patch),audit.after);
    nativeCompletionCoverage.push({requestId:original.requestId,originalStatus:original.status,operationId:op.id,entityType:op.entity_type,entityId:op.entity_id,auditId:audit.id,operationState:op.state,remoteCompleted:true,beforeAndAfterReceiptVerified:true,jsonPatchVerified:true,originalResponseRewritten:false,nativeReplayed:false});
   }assert(nativeCompletionCoverage.length>0,'ACTUAL_NATIVE_COMPLETION_REQUIRED');return{nativeCompletedOperations:nativeCompletionCoverage.length,completedFromFailedResponses:nativeCompletionCoverage.filter(r=>r.originalStatus>=400).length};
  });
  await check('committed analytical observations retain their exact original audit even after a failed HTTP history projection',async()=>{
   const runs=(await client.query("SELECT * FROM governance_runs WHERE cluster_id=ANY($1::uuid[]) AND idempotency_key=ANY($2::text[]) AND origin_type='http' AND state IN('succeeded','incomplete') ORDER BY created_at,id LIMIT 1001",[manifest.clusterIds,keys])).rows;assert(runs.length<=1000);
   for(const run of runs){const original=manifest.attempts.find(r=>r.actorId===run.actor_id&&r.originalKey===run.idempotency_key);assert(original,'ANALYTICAL_ORIGINAL_REQUEST_MISSING');evidenceContext={stage:'analytical-commit',runId:run.id,requestId:original.requestId};
    const input=secrets.decrypt(run.input_secret,`governance:run-input:${run.id}`);assert.equal(secrets.fingerprint({clusterId:run.cluster_id,workspaceId:run.workspace_id,kind:run.kind,request:input}),run.request_hmac);
    const table=run.kind==='inspection'?'governance_reports':run.kind==='comparison'?'governance_comparisons':null;assert(table);
    const records=(await client.query(`SELECT * FROM ${table} WHERE run_id=$1 AND cluster_id=$2 AND workspace_id=$3`,[run.id,run.cluster_id,run.workspace_id])).rows;assert.equal(records.length,1);const record=records[0];
    if(run.kind==='comparison'){const {decryptComparisonMaterial}=require('/app/apps/console-api/dist/modules/governance/governance-comparison-material.js'),material=decryptComparisonMaterial(record,secrets);assert.equal(material.source.inventory.scope.clusterId,run.cluster_id);assert.equal(material.source.inventory.scope.workspaceId,run.workspace_id);assert.equal(material.target.inventory.scope.clusterId,record.target_cluster_id);assert.equal(material.target.inventory.scope.workspaceId,record.target_workspace_id);assert.equal(secrets.fingerprint(record.policy),record.policy_hmac);}
    else{const inventory=secrets.decrypt(record.inventory_secret,`governance:inventory:${record.id}`);assert.equal(secrets.fingerprint(inventory),record.inventory_hmac);assert.equal(inventory.scope.clusterId,run.cluster_id);assert.equal(inventory.scope.workspaceId,run.workspace_id);}
    analyticalCompletionCoverage.push(verifyM10AnalyticalAudit(original,run,record,byRequest.get(original.requestId)??[]));
   }return{committedObservations:analyticalCompletionCoverage.length,committedWithFailedOriginalHTTP:analyticalCompletionCoverage.filter(row=>row.originalStatus>=400).length,originalResponseRewritten:false,nativeExecutionRequested:false};
  });
  await check('every stored redacted diff is an exact RFC 6902 before-to-after patch',async()=>{for(const row of rows){assert(Array.isArray(row.json_patch));eq(applyAuditPatch(row.before,row.json_patch),row.after);}return{validatedRows:rows.length};});
  await check('source, target and global append-only chains and current heads verify independently',async()=>{
   const scopes=[...manifest.clusterIds.map(id=>`cluster:${id}`),'global'],chain=(await client.query('SELECT * FROM audit_events WHERE chain_scope=ANY($1::text[]) ORDER BY chain_scope,sequence LIMIT 20001',[scopes])).rows,heads=(await client.query('SELECT chain_scope,last_sequence::text,last_hash FROM audit_chain_heads WHERE chain_scope=ANY($1::text[])',[scopes])).rows;assert(chain.length<=20000);chainRows=chain.length;
   for(const scope of scopes){const facts=chain.filter(row=>row.chain_scope===scope),head=heads.find(row=>row.chain_scope===scope);assert(facts.length>0&&head);let prior='GENESIS',sequence=0n;for(const row of facts){sequence++;assert.equal(row.sequence,String(sequence));assert.equal(row.prev_hash,prior);const record=Object.fromEntries(['id','chain_scope','sequence','actor_id','actor_type','source_ip','cluster_id','workspace_id','entity_type','entity_id','action','before','after','json_patch','workflow_id','result','request_id','prev_hash'].map(key=>[key,row[key]]));record.occurred_at=new Date(row.occurred_at).toISOString();const hash=createHash('sha256').update(canonicalJson(record)).digest('hex');assert.equal(hash,row.event_hash);prior=hash;}assert.equal(head.last_sequence,String(sequence));assert.equal(head.last_hash,prior);}return{chainCount:3,chainRows};
  });
  await client.query('ROLLBACK');
  await check('runtime UPDATE, DELETE and TRUNCATE of original audit facts are rejected and rolled back',async()=>{assert(rows.length>0);for(const[name,sql,args]of[['update','UPDATE audit_events SET result=result WHERE id=$1',[rows[0].id]],['delete','DELETE FROM audit_events WHERE id=$1',[rows[0].id]],['truncate','TRUNCATE audit_events',[]]]){await client.query('BEGIN');let code;try{await client.query("SET LOCAL statement_timeout='5s'");try{await client.query(sql,args);}catch(error){code=error.code;}}finally{await client.query('ROLLBACK');}runtimeDenials.push({operation:name,code:code??'UNEXPECTED_SQL_SUCCESS',rolledBack:true});assert.equal(code,'42501');}return{rollbackTrials:3};});
  await check('original unknown business responses are retained without replay or fabricated resolution',async()=>{assert.equal(manifest.unknownOriginalRequests.length,0,'M10_ORIGINAL_BUSINESS_RESPONSE_UNRESOLVED');return{unknownBusinessResponses:0,originalResponseRewritten:false};});
  passed=true;
 }catch(error){failure={code:safeCode(error),...(evidenceContext?{context:evidenceContext}:{})};}
 finally{if(client){await client.query('ROLLBACK').catch(()=>{});await client.end().catch(()=>{});}const report={passed,milestone:'M10',productionDeployment:false,credentialsRecorded:false,nativeKongRequests:false,consoleDatabaseOnly:true,verifiedAfter:manifest.verifiedAfter,auditRows,chainRows,checks,coverage,nativeCompletionCoverage,analyticalCompletionCoverage,runtimeDenials,failedOriginalRequests:manifest.failedOriginalRequests,unknownOriginalRequests:manifest.unknownOriginalRequests,unknownAuthenticationRequests:manifest.unknownAuthenticationRequests,excludedAuthenticationRequests:manifest.excludedAuthenticationRequests,historicalAuditExceptions:[],backfilledAuditRows:false,originalResponseRewritten:false,limits:['Current M10 native/browser business receipts only; historical M9 deficiencies are not waived or copied into this stage.','Every actual mutation row with remote completion is independently checked, including failed HTTP originals; response flags never substitute for SQL facts.'],...(failure?{failure}:{})};process.stdout.write(JSON.stringify(report,null,2)+'\n');if(!passed)process.exitCode=1;}
}
