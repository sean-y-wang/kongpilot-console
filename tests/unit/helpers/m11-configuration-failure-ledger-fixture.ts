import {expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {ConfigurationFailureLedgerService,CONFIGURATION_FAILURE_SCHEDULED_ORIGINS_QUERY as ORIGINS} from '../../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import {CONFIGURATION_FAILURE_ANCHOR_QUERY as ANCHOR,CONFIGURATION_FAILURE_STEPS_QUERY as STEPS,
 CONFIGURATION_FAILURE_JOB_CAS as JOB,CONFIGURATION_FAILURE_EXECUTION_CAS as EXECUTION,
 CONFIGURATION_FAILURE_STEP_CAS as STEP} from '../../../apps/console-api/src/modules/configuration/configuration-failure-queries';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {canonicalJson} from '../../../apps/console-api/src/infrastructure/secret.service';

/** Actual Context ancestry and the real failure ledger private WeakMap/CAS
 * behavior. SQL and fixed Access verifier are dependency doubles. These SOURCE
 * tests read no environment, sessions, sockets, production keys or database. */
const id=(n:number)=>`ab110000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const fp=(v:unknown)=>createHash('sha256').update(canonicalJson(v)).digest('hex');
export function configurationFailureLedgerFixture(shared?: any){
 const context=shared?.context??new KongExecutionContextService(),namespaceHandle=shared?.namespaceHandle??Object.freeze({}),jobHandle=Object.freeze({}),accessHandle=Object.freeze({});
 const actor=shared?.actor??{id:id(1),username:'synthetic-executor',superAdmin:false},authoringSid=id(2),cid=shared?.cid??id(3),wid=shared?.wid??id(4),jobId=shared?.plan.subject.id??id(5),executionId=id(6),planId=shared?.plan.steps[0].metadata.planId??id(7),workflowId=shared?.wf??id(8),wrapperE=shared?.stored.e.id??id(9);
 const anchor:any={job_id:jobId,cluster_id:cid,workspace_id:wid,actor_id:actor.id,origin_session_id:authoringSid,transport_scope:'e'.repeat(64),kind:'apply',
  job_state:'running',job_revision:3,plan_id:planId,plan_revision:2,plan_hash:'a'.repeat(64),workflow_id:workflowId,execution_mode:'approval',permission_version:'current-permissions',credential_epoch:4,
  lease_generation:2,lease_owner_hash:'b'.repeat(64),lease_until:new Date(Date.now()+30000).toISOString(),safe_progress:{preserved:true},job_request_id:'historical-author-http-request',
  execution_id:executionId,execution_state:'executing',execution_revision:2,claim_hash:'c'.repeat(64),execution_actor_id:actor.id,execution_workflow_id:workflowId,
  approved_version:3,workflow_plan_hash:'d'.repeat(64),execution_mode_actual:'approval',execution_permission_version:'current-permissions',execution_lease_generation:2,
  execution_plan_id:planId,execution_plan_revision:2,execution_plan_hash:'a'.repeat(64),step_count:2,version_plan_hash:'a'.repeat(64),current_revision:2,
  workflow_kind:'configuration_v2',workflow_state:'executing',subject_id:jobId,subject_type:'configuration_jobs',requester_user_id:actor.id,
  workflow_plan_revision:3,current_workflow_plan_hash:'d'.repeat(64),workflow_execution_id:wrapperE,workflow_execution_state:'executing',snapshot_state:'ready',
  workflow_execution_actor_id:actor.id,workflow_request_id:null,workflow_execution_plan_revision:3,workflow_execution_plan_hash:'d'.repeat(64)};
 if(shared){anchor.permission_version=anchor.execution_permission_version=shared.ns.permissionVersion;anchor.credential_epoch=Number(shared.ns.credentialEpoch);anchor.plan_revision=anchor.execution_plan_revision=anchor.current_revision=shared.plan.steps[0].metadata.planRevision;anchor.approved_version=anchor.workflow_plan_revision=anchor.workflow_execution_plan_revision=shared.plan.planRevision;anchor.workflow_plan_hash=anchor.current_workflow_plan_hash=anchor.workflow_execution_plan_hash=shared.ns.workflow.planHash;}
 const wrapper:any={id:id(10),claim_id:id(11),schedule_id:id(12),cluster_id:cid,workspace_id:wid,execution_id:wrapperE,executor_id:actor.id,
  workflow_id:workflowId,workflow_plan_revision:3,workflow_plan_hash:'d'.repeat(64),created_at:'2026-10-14T00:00:00Z'};
 if(shared){Object.assign(wrapper,{id:shared.stored.origin.id,claim_id:shared.ns.claim.id,schedule_id:shared.ns.claim.scheduleId,workflow_plan_revision:shared.plan.planRevision,workflow_plan_hash:shared.ns.workflow.planHash});}
 const nested:any={id:id(13),wrapper_origin_id:wrapper.id,claim_id:wrapper.claim_id,cluster_id:cid,workspace_id:wid,workflow_execution_id:wrapperE,
  workflow_id:workflowId,workflow_plan_revision:3,workflow_plan_hash:'d'.repeat(64),configuration_execution_id:executionId,configuration_job_id:jobId,
  configuration_plan_id:planId,configuration_plan_revision:2,configuration_plan_hash:'a'.repeat(64),workflow_step_id:id(14),created_at:'2026-10-14T00:00:01Z'};
 nested.workflow_plan_revision=anchor.workflow_plan_revision;nested.workflow_plan_hash=anchor.current_workflow_plan_hash;nested.configuration_plan_revision=anchor.plan_revision;
 const proof:any={origin:'workflow-scheduled-configuration',sessionId:null,jobHandle,namespaceHandle,claimId:wrapper.claim_id,wrapperOriginId:wrapper.id,wrapperExecutionId:wrapperE,
  configurationOriginId:nested.id,configurationExecutionId:executionId,configurationJobId:jobId,configurationPlanId:planId,configurationPlanRevision:2,configurationPlanHash:'a'.repeat(64),
  configurationClaimHash:'c'.repeat(64),workflowId,workflowPlanRevision:3,workflowPlanHash:'d'.repeat(64),actorId:actor.id,clusterId:cid,workspaceId:wid,
  permissionVersion:'current-permissions',credentialEpoch:4,leaseGeneration:2,expiresAt:Date.now()+60000};
 Object.assign(proof,{configurationPlanRevision:anchor.plan_revision,workflowPlanRevision:anchor.workflow_plan_revision,workflowPlanHash:anchor.current_workflow_plan_hash,permissionVersion:anchor.permission_version,credentialEpoch:anchor.credential_epoch});
 const scope={clusterId:cid,workspaceId:wid,transportScope:anchor.transport_scope},description:any={actor,sessionId:null,jobId,scope,permissionVersion:proof.permissionVersion,leaseGeneration:2};
 let live=true,ns=true;const capabilities=new WeakSet<object>();capabilities.add(accessHandle);
 const access:any={description:vi.fn(async(h:object)=>{if(!capabilities.has(h)||!live)throw Error('ORIGINAL_ACCESS_REQUIRED');return description;}),
  assertCurrent:vi.fn(async(h:object)=>{if(!capabilities.has(h)||!live)throw Error('CURRENT_AUTHORITY_CLOSED');}),
  verifyHandle:vi.fn(async(h:object)=>{if(!capabilities.has(h)||!live)throw Error('ORIGINAL_ACCESS_REQUIRED');return{origin:'workflow-scheduled-configuration',sessionId:null,readOnly:false,
   originalScheduledJobHandle:jobHandle,namespaceHandle,jobId};}),originalWorkflowScheduledConfigurationJobHandle:vi.fn((h:object)=>{if(!capabilities.has(h))throw Error('ORIGINAL_JOB_REQUIRED');return jobHandle;}),
  workflowScheduledConfigurationExecutionProof:vi.fn(async(h:object,e:string,_tx:any,checkpoint:string)=>{
   expect(checkpoint).toBe('ledger');if(!capabilities.has(h)||e!==executionId||!live)throw Error('ORIGINAL_NESTED_REQUIRED');return proof;})};
 const namespaceProof:any=Object.freeze({origin:'scheduled-workflow',sessionId:null,actor,clusterId:cid,workspaceId:wid,kind:'configuration_v2',expiresAt:new Date(Date.now()+60000).toISOString()});
 if(!shared)context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(h!==namespaceHandle||!ns)throw Error('NAMESPACE_CLOSED');},async verifyHandle(h){if(h!==namespaceHandle||!ns)throw Error('ORIGINAL_NAMESPACE_REQUIRED');return namespaceProof;}});
 const step=(n:number):any=>({id:id(20+n),state:n===1?'succeeded':'pending',revision:1,step_order:n,plan_step_id:id(30+n),object_workspace_id:wid,
  operation_id:n===1?id(40):null,receipt_operation_id:n===1?id(40):null,after_hmac:n===1?'f'.repeat(64):null,receipt_present:n===1,
  entity_type:'services',permission_action:'write',mutation_action:'create',parent_id:null,credential_kind:null,allocated_native_id:id(50+n),native_id:null,
  native_operation_id:n===1?id(40):null,native_entity_id:n===1?id(51):null,native_workflow_id:n===1?workflowId:null,native_result_present:n===1,
  native_state:n===1?'succeeded':null,remote_started:n===1?true:null,remote_completed:n===1?true:null,native_cluster_id:n===1?cid:null,
  native_workspace_id:n===1?wid:null,native_actor_id:n===1?actor.id:null,native_transport_scope:n===1?scope.transportScope:null,native_action:n===1?'create':null,
  native_entity_type:n===1?'services':null,native_parent_id:null,native_credential_kind:null,native_key:n===1?`configuration-${jobId}-${id(21)}`:null,
  configuration_job_id:n===1?jobId:null,configuration_execution_id:n===1?executionId:null,configuration_step_id:n===1?id(21):null,
  configuration_plan_revision:n===1?2:null,configuration_plan_hash:n===1?'a'.repeat(64):null,workflow_execution_id:null,workflow_step_id:null,workflow_plan_revision:null,workflow_plan_hash:null,fence_count:n===1?1:0});
 const state={anchor,wrapper,nested,steps:[step(1),step(2)],failCas:false};let db:any;
 db={transaction:vi.fn(async(fn:any)=>{const save=structuredClone(state);try{return await fn(db);}catch(e){Object.assign(state,save);throw e;}}),
  one:vi.fn(async(sql:string,p:any[])=>{if(sql===ANCHOR){expect(p).toEqual([cid,wid,jobId,executionId,wrapperE]);return structuredClone(state.anchor);}
   if(sql===ORIGINS){expect(p).toEqual([cid,wid,jobId,executionId,wrapperE]);return{wrapper_origin:structuredClone(state.wrapper),configuration_origin:structuredClone(state.nested)};}throw Error('UNEXPECTED_SQL');}),
  query:vi.fn(async(sql:string)=>{expect(sql).toBe(STEPS);return structuredClone(state.steps);}),
  exec:vi.fn(async(sql:string,p:any[])=>{if(state.failCas)return 0;
   if(sql===STEP){const s=state.steps.find(s=>s.id===p[7]);s.state=p[9];s.error_code=p[10];s.revision++;return 1;}
   if(sql===JOB){expect(p[9]).toBe(authoringSid);state.anchor.job_state=p[11];state.anchor.job_revision++;return 1;}
   if(sql===EXECUTION){expect(p[9]).toBe(authoringSid);state.anchor.execution_state=p[11];state.anchor.execution_revision++;return 1;}throw Error('UNEXPECTED_WRITE');})};
 const audit={append:vi.fn(async()=>({id:id(80)}))},secrets:any={fingerprint:fp,redact:(v:any)=>structuredClone(v)};
 const ledger=new ConfigurationFailureLedgerService(db,secrets,audit as any,access,context,{}as any);
 const run=<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(namespaceHandle,fn),arm=()=>ledger.arm(accessHandle as any,executionId,proof.configurationClaimHash,wrapperE);
 return{ledger,context,access,accessHandle,jobHandle,namespaceHandle,proof,state,audit,db,secrets,actor,scope,authoringSid,cid,wid,jobId,executionId,planId,workflowId,wrapperE,run,arm,
  closeAuthority(){live=false;ns=false;},revokeAccess(){live=false;}};
}
