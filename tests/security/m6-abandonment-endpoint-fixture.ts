import { expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { ConflictException, HttpException } from '@nestjs/common';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { publicationProofAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { activationRecoveryFixture } from './m6-activation-recovery-fixture';
import { actor, approverId, cid, eid, id, serviceId, wid, wf } from './m6-approved-fixture';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Real endpoint, immutable proof validator, certificate crypto/repository and
 * HTTP execution context. SQL policy/transactions, authz and native GET are
 * explicit offline substitutes; physical deferred SQL is independently tested
 * by Storage. This fixture never accesses a live DB, network or private file. */
export function abandonmentEndpointFixture() {
  const f = activationRecoveryFixture();
  Object.assign(f.workflow, { state:'failed', created_at:new Date(), revision:4 });
  Object.assign(f.execution, { state:'failed' });
  const operation = f.operations.get(f.rows[0].operation_id);
  Object.assign(operation, { state:'failed', entity_id:null, remote_started:true, remote_completed:false, result_secret:null, error_code:'KONG_VALIDATION_ERROR' });
  f.operations.clear(); f.operations.set(operation.id,operation); f.refs.splice(0);
  Object.assign(f.rows[0], { state:'failed', receipt_secret:null, after_fingerprint:null, recycle_entry_id:null, safe_result:{remoteStarted:true,remoteCompleted:false},error_code:'KONG_VALIDATION_ERROR' });
  for(const row of f.rows.slice(1)) Object.assign(row,{state:'pending',operation_id:null,safe_result:{},receipt_secret:null,after_fingerprint:null,recycle_entry_id:null,started_at:null,completed_at:null,error_code:null});
  f.nativeObjects.clear(); f.nativeObjects.set(`/services/${serviceId}`,f.serviceObject);
  f.publication.published_revision=1;
  const proof:any={ version:1,clusterId:cid,workspaceId:wid,publicationId:f.publication.id,publicationRevision:1,
    transportScope:f.plan.scope.transportScope,clusterRevision:1,workspaceRevision:1,executionMode:f.plan.executionMode,
    workflowId:id(701),executionId:id(702),planRevision:1,planHash:'b'.repeat(64),verifiedAt:new Date().toISOString(),
    serviceId,service:structuredClone(f.serviceObject),definitions:{'portal-credential-issue':f.plan.definition} };
  const proofRow:any={cluster_id:cid,workspace_id:wid,publication_id:f.publication.id,publication_revision:1,transport_scope:f.plan.scope.transportScope,
    workflow_id:proof.workflowId,workflow_execution_id:proof.executionId,workflow_plan_revision:1,workflow_plan_hash:proof.planHash,
    publication_proof_secret:f.secrets.encrypt(proof,publicationProofAad(cid,wid,f.publication.id,1)),publication_proof_hmac:f.secrets.fingerprint(proof)};
  const certificateRows:any[]=[],auditRows:any[]=[],events:string[]=[];
  const faults:any={candidate:null,certificateProof:null,cas:false,audit:false,insert:false,commitAck:false};
  let factsHash='c'.repeat(64);
  const clone=(value:any)=>value==null?null:structuredClone(value);
  const one=vi.fn(async(sql:string,p:any[]=[])=>{
    if(sql.includes('INSERT INTO portal_failed_issue_abandonments')) {
      events.push('certificate'); if(faults.insert) throw new Error('OFFLINE_CERTIFICATE_PERSIST_FAILED');
      const columns=['id','cluster_id','workspace_id','grant_id','workflow_id','execution_id','plan_revision','plan_hash','failed_step_id','failed_operation_id','credential_id','actor_id','session_id','original_execution_key','request_hash','transport_scope','original_grant_revision','facts_hash','reserved_impact','key_cipher_hmac','proof_secret','proof_hmac','absence_observed_at','audit_event_id','audit_event_hash'];
      const row:any={created_at:new Date()}; columns.forEach((key,i)=>{row[key]=p[i];}); certificateRows.push(row); return clone(row);
    }
    if(sql.includes('FROM portal_failed_issue_abandonments'))return clone(certificateRows.find(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.workflow_id===p[2]&&r.execution_id===p[3]&&r.actor_id===p[4]&&r.original_execution_key===p[5]));
    if(sql.includes('m6_rejected_issue_facts_hash'))return{hash:factsHash};
    if(sql.includes('FROM audit_events'))return clone(auditRows.find(r=>r.id===p[0]));
    if(sql.includes('FROM auth_sessions')) {
      const s=f.session;return s.id===p[0]&&s.user_id===p[1]&&!s.revoked_at&&s.expires_at.getTime()>Date.now()&&s.credential_epoch===s.session_credential_epoch&&s.status==='active'&&!s.force_password_change&&!s.deleted_at?{id:s.id}:null;
    }
    if(sql.includes('FROM iam_epoch'))return{version:1};
    if(sql.includes('FROM workflow_definitions'))return{id:f.plan.definition.id};
    if(sql.includes('FROM workflow_executions'))return p[0]===eid||p[0]===wf?clone(f.execution):null;
    if(sql==="SELECT workspace_id FROM workflows WHERE id=$1 AND cluster_id=$2 AND kind='control-metadata' AND state='succeeded' AND requester_user_id=$3"){
      expect(p).toEqual([wf,cid,actor.id]);expect(f.workflow.kind).toBe('portal-credential-issue');return null;
    }
    if(sql.includes('FROM workflows'))return clone(f.workflow);
    if(sql.includes('FROM workflow_versions'))return clone(f.version);
    if(sql.includes('FROM workflow_events'))return null;
    if(sql.includes('FROM workflow_approvals'))return sql.includes('idempotency_key')?null:f.approvals.some(r=>r.decision==='approve'&&r.approver_id===approverId&&r.plan_hash===f.execution.plan_hash)?{id:id(703)}:null;
    if(sql.includes('FROM clusters'))return clone(f.cluster);
    if(sql.includes('FROM workspaces'))return clone(f.workspace);
    if(sql.includes('FROM users'))return f.approvedBy.status==='active'&&!f.approvedBy.force_password_change?clone(f.approvedBy):null;
    if(sql.includes('FROM portal_application_grants'))return clone(f.grant);
    if(sql.includes('FROM portal_credentials'))return clone(f.credential);
    if(sql.includes('FROM portal_publication_proofs'))return clone(proofRow);
    if(sql.includes('FROM portal_publications')&&sql.includes('JOIN portal_publication_proofs'))return clone({...f.publication,publication_proof_hmac:proofRow.publication_proof_hmac});
    if(sql.includes('FROM portal_publications'))return clone(f.publication);
    if(sql.includes('FROM portal_applications'))return f.application.status==='active'?clone(f.application):null;
    if(sql.includes('FROM portal_developers'))return f.developer.status==='active'?clone(f.developer):null;
    if(sql.includes('FROM mutation_operations'))return clone(f.operations.get(p[0]));
    throw new Error(`UNHANDLED_OFFLINE_ENDPOINT_SQL:${sql}`);
  });
  const query=vi.fn(async(sql:string,p:any[]=[])=>{
    if(sql.replace(/\s+/g,' ').trim()===`SELECT DISTINCT w.* FROM workflows w LEFT JOIN workflow_executions e ON e.workflow_id=w.id LEFT JOIN workflow_approvals a ON a.workflow_id=w.id LEFT JOIN workflow_events v ON v.workflow_id=w.id AND v.action='decision.cancel' WHERE w.cluster_id=$1 AND w.kind='control-metadata' AND ((w.requester_user_id=$2 AND w.idempotency_key=$3) OR (e.execution_actor_id=$2 AND e.idempotency_key=$3) OR (a.approver_id=$2 AND a.idempotency_key=$3) OR (v.actor_id=$2 AND v.safe_metadata->>'key'=$3)) LIMIT 2`){
      expect(p).toEqual([cid,actor.id,f.originalKey]);expect(f.workflow.kind).toBe('portal-credential-issue');return [];
    }
    if(sql.includes('m6_assert_rejected_issue_candidate')) {
      if(faults.candidate)throw faults.candidate;
      if(operation.state!=='failed'||operation.error_code!=='KONG_VALIDATION_ERROR'||operation.remote_completed||operation.result_secret||operation.entity_id||f.rows.slice(1).some(r=>r.state!=='pending'||r.operation_id||r.receipt_secret||r.after_fingerprint)||f.refs.length)throw Object.assign(new Error('OFFLINE_SQL_CANDIDATE_REJECTED'),{code:'23514'});
      return[];
    }
    if(sql.includes('m6_assert_certified_failed_issue')){if(faults.certificateProof)throw faults.certificateProof;return[];}
    if(sql.includes('FROM workflow_steps'))return clone(f.rows);
    if(sql.includes('FROM workflow_approvals'))return clone(f.approvals);
    if(sql.includes('FROM iam_effective_grants'))return clone(f.grants);
    throw new Error(`UNHANDLED_OFFLINE_ENDPOINT_SQL_LIST:${sql}`);
  });
  const exec=vi.fn(async(sql:string,p:any[]=[])=>{
    if(!sql.startsWith('UPDATE portal_application_grants'))throw new Error('UNEXPECTED_HISTORY_OR_NATIVE_LEDGER_WRITE');
    events.push('grant-cas');if(faults.cas||p[0]!==f.grant.id||p[1]!==f.grant.revision||p[2]!==wf||f.grant.state!=='pending'||f.grant.reservation_released_at)return 0;
    Object.assign(f.grant,{state:'disabled',reservation_released_at:new Date(),revision:f.grant.revision+1});return 1;
  });
  const tx:any={one,query,exec};
  const transaction=vi.fn(async(fn:any)=>{
    const before=clone(f.grant),certs=clone(certificateRows),audits=clone(auditRows);
    try { await fn(tx); } catch(error) {Object.assign(f.grant,before);certificateRows.splice(0,certificateRows.length,...certs);auditRows.splice(0,auditRows.length,...audits);throw error;}
    events.push('commit');if(faults.commitAck)throw new Error('OFFLINE_COMMIT_ACK_LOST');
  });
  Object.assign(f.db,{one,query,exec,transaction});
  const audit:any={append:vi.fn(async(input:any,supplied:any)=>{
    if(supplied!==tx)throw new Error('AUDIT_MUST_SHARE_BUSINESS_TRANSACTION');events.push('audit');if(faults.audit)throw new Error('OFFLINE_AUDIT_FAILED');
    const row:any={id:id(710+auditRows.length),chain_scope:`cluster:${cid}`,sequence:String(auditRows.length+1),actor_id:input.actorId,actor_type:'user',source_ip:input.ip??null,
      cluster_id:input.clusterId,workspace_id:input.workspaceId,entity_type:input.entityType,entity_id:input.entityId,action:input.action,before:input.before,after:input.after,json_patch:[],workflow_id:input.workflowId,result:input.result,
      request_id:input.requestId??null,prev_hash:'0'.repeat(64),occurred_at:new Date().toISOString()};
    row.event_hash=createHash('sha256').update(canonicalJson(row)).digest('hex');auditRows.push(row);return{id:row.id,eventHash:row.event_hash,chainScope:row.chain_scope};
  })};
  const plans:any={load:vi.fn(async()=>({row:clone(f.workflow),plan:clone(f.plan),version:clone(f.version)})),definition:vi.fn(async()=>clone(f.plan.definition))};
  // This deliberately single-version offline repository exposes only the
  // originally captured definition row. The existing definition fault mock
  // substitutes that stored row; it does not simulate a latest-head update
  // while retaining a separate valid historical version. Exact lookup must
  // reject a substituted ID/version/hash instead of adopting a new policy.
  plans.exactDefinition=vi.fn(async(c:string,w:string,expected:WorkflowPlanV1['definition'],supplied:any=f.db):Promise<WorkflowPlanV1['definition']>=>{
    if(c!==cid||w!==wid||supplied!==f.db&&supplied!==tx)throw new ConflictException({code:'WORKFLOW_DEFINITION_UNAVAILABLE'});
    const captured=await plans.definition(c,w,f.plan.kind,supplied);
    if(!captured||captured.id!==expected.id||captured.version!==expected.version||captured.policyHash!==expected.policyHash)
      throw new ConflictException({code:'WORKFLOW_DEFINITION_UNAVAILABLE'});
    return clone(captured);
  });
  const handler={authorize:vi.fn(async()=>undefined)},registry:any={get:vi.fn(()=>handler)};
  const forbidden=new Proxy({},{get:()=>vi.fn(()=>{throw new Error('NATIVE_DISPATCH_OR_CAPABILITY_FORBIDDEN');})});
  const resolver:any={resolve:vi.fn(async(c:string,w:string)=>{if(c!==cid||w!==wid)throw new ConflictException({code:'WORKSPACE_SCOPE_MISMATCH'});return clone(f.workspace);})};
  const service=new WorkflowService(f.db,f.redis,f.secrets,f.kong,f.context,f.authz,audit,forbidden as any,forbidden as any,forbidden as any,resolver,plans,registry,forbidden as any,forbidden as any);
  const entityActor:any={user:actor,workspaceId:wid,idempotencyKey:f.originalKey,requestId:'offline-abandonment-request',ip:'127.0.0.1'};
  const body=()=>({revision:4,planHash:f.workflow.plan_hash,executionId:eid,confirmed:true,confirm_name:'portal-credential-issue'});
  const http=<T>(fn:()=>Promise<T>,who:any=entityActor,sid:string|null=f.sessionId,frameKey=who.idempotencyKey)=>f.context.runHttp({idempotencyKey:frameKey},async()=>{
    f.context.bindHttpActor(who.user,sid??undefined);const close=f.context.captureHttpCloser();try{return await fn();}finally{close();}
  });
  const invoke=(changes:any={},options:any={})=>{const who=options.actor??entityActor;return http(()=>service.abandonRejectedIssue(cid,wf,{...body(),...changes},who),who,options.noSID?null:options.sid??f.sessionId,options.frameKey??who.idempotencyKey);};
  const get=()=>http(()=>service.get(cid,wf,entityActor));
  const receipt=()=>http(()=>service.receiptByKey(cid,f.originalKey,entityActor));
  const absencePaths=[`/consumers/${f.grant.consumer_id}`,`/consumers/${f.grant.consumer_id}/acls/${f.grant.acl_id}`,`/consumers/${f.grant.consumer_id}/key-auth/${f.credential.kong_id}`];
  const unchanged=()=>{expectNeverNativeWrites(f.kong.request.mock.calls);if(f.grant.state!=='pending'||certificateRows.length||auditRows.length)throw new Error('OFFLINE_BUSINESS_NOT_ROLLED_BACK');};
  return{...f,operation,proofRow,certificateRows,auditRows,events,faults,service,entityActor,body,invoke,get,receipt,http,plans,registry,handler,audit,tx,absencePaths,unchanged,setFactsHash:(value:string)=>{factsHash=value;}};
}
export function expectNeverNativeWrites(calls:any[][]){if(calls.some(c=>c[1]!=='GET'))throw new Error('NATIVE_WRITE_IN_OFFLINE_ABANDONMENT');}
