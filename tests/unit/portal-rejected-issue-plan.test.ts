import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { beforeEach,afterEach,describe,it,expect,vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { normalizedNativeRequests } from '../../apps/console-api/src/modules/workflows/approved-execution.types';
import { planAad,snapshotAad,type WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { portalKeyAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { validateRejectedIssuePlan } from '../../apps/console-api/src/modules/portal/portal-rejected-issue-plan';

/** Real AEAD/plan/native-step builder, synthetic immutable SQL facts. This
 * proves the private plan verifier, not native absence or database constraints. */
function fixture(){
  const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),wf=randomUUID(),exec=randomUUID(),grantId=randomUUID(),developerId=randomUUID(),actorId=randomUUID(),consumerId=randomUUID(),aclId=randomUUID(),keyId=randomUUID(),credentialId=randomUUID();
  const key='Synthetic_Rejected_Issue_Key_Only',service={id:randomUUID(),name:'safe-service',tags:['kos-ws-test']};
  const g:any={id:grantId,cluster_id:cid,workspace_id:wid,transport_scope:'b'.repeat(64),developer_id:developerId,consumer_id:consumerId,acl_id:aclId,acl_group:'portal-test-group',workflow_id:wf,state:'pending',revision:1};
  const native=new PortalNativeService({}as any,secrets,{}as any,{}as any,{}as any,{}as any);
  const s0=native.nativeStep(1,'consumers','create',{id:consumerId,username:`kos-portal-${grantId}`,custom_id:randomUUID(),tags:['kos-ws-test']},null,{workflowId:wf});
  const s1=native.nativeStep(2,'credentials','create',{id:aclId,group:g.acl_group,tags:['kos-ws-test']},null,{workflowId:wf,parentId:consumerId,credentialKind:'acls',dependencies:[s0.id]});
  const s2=native.nativeStep(3,'credentials','create',{id:keyId,key,tags:['kos-ws-test']},null,{workflowId:wf,parentId:consumerId,credentialKind:'key-auth',dependencies:[s1.id]});
  const s3=native.metadataStep(4,'portal.credential.activate','portal_application_grants',grantId,structuredClone(g),{action:'issue',generation:1,credentialId,kongId:keyId,consumerId,aclId,keyFingerprint:secrets.fingerprint(key)},[s2.id]);
  const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,kind:'portal-credential-issue',executionMode:'direct',approvalRequired:true,subject:{type:'portal_application_grants',id:grantId},requester:{type:'developer',id:developerId},definition:{id:randomUUID(),version:1,policyHash:'c'.repeat(64)},issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:g.transport_scope,clusterRevision:1,workspaceRevision:1},prerequisites:[{type:'services',id:service.id,path:`/services/${service.id}`,before:service,fingerprint:secrets.fingerprint(service)}],steps:[s0,s1,s2,s3],generated:{consumerId,aclId,credentialId:keyId,key}};
  const hash=secrets.fingerprint(plan),w:any={id:wf,plan_revision:1,plan_hash:hash,requester_type:'developer',requester_developer_id:developerId,definition_id:plan.definition.id,definition_version:1,state:'failed',execution_mode:'direct',approval_required:true};
  const objects=[...plan.prerequisites.map(p=>({...p,absent:false})),...plan.steps.slice(0,3).map(s=>({type:s.nativeRequests[0].nativeType,id:s.nativeRequests[0].nativeId,path:`${s.nativeRequests[0].canonicalPath}/${s.nativeRequests[0].nativeId}`,before:null,absent:true,fingerprint:secrets.fingerprint(null)}))];
  const snapshot:any={version:1,workflowId:wf,executionId:exec,clusterId:cid,workspaceId:wid,planRevision:1,planHash:hash,capturedAt:new Date().toISOString(),objects};
  const e:any={id:exec,workflow_id:wf,plan_revision:1,plan_hash:hash,execution_actor_id:actorId,execution_mode:'direct',approval_required:true,state:'failed',snapshot_state:'ready',snapshot_secret:secrets.encrypt(snapshot,snapshotAad(cid,wid,wf,exec)),snapshot_hash:secrets.fingerprint(snapshot)};
  const v:any={plan_hash:hash,execution_mode:'direct',approval_required:true,payload_secret:secrets.encrypt(plan,planAad(cid,wid,wf,1)),steps_hash:secrets.fingerprint(plan.steps),step_count:4,native_request_count:3,policy_version:1};
  const rows=plan.steps.map(s=>({id:s.id,cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:hash,execution_mode:'direct',approval_required:true,step_order:s.order,step_key:s.key,kind:s.kind,entity_type:s.entityType,entity_id:s.entityId??null,parent_id:s.parentId??null,credential_kind:s.credentialKind??null,handler:s.handler??null,permission_action:s.permissionAction,mutation_action:s.mutationAction??null,mutation_payload_hmac:s.mutationPayloadHmac??null,mutation_idempotency_key:s.mutationIdempotencyKey??null,before_fingerprint:s.beforeFingerprint??null,metadata_before_hmac:s.metadataBeforeHmac??null,metadata_payload_hmac:s.metadataPayloadHmac??null,metadata_revision:s.metadataRevision??null,dependencies:s.dependencies,native_requests:normalizedNativeRequests(s.nativeRequests,secrets)}));
  const opId=randomUUID(),binding={workflowId:wf,executionId:exec,planRevision:1,planHash:hash,stepId:s0.id,beforeHmac:s0.beforeFingerprint},op:any={id:opId,state:'failed',error_code:'KONG_VALIDATION_ERROR',remote_started:true,remote_completed:false,entity_id:null,transport_scope:g.transport_scope,idempotency_key:s0.mutationIdempotencyKey,before_secret:secrets.encrypt(null,`mutation:${opId}:before`),payload_secret:secrets.encrypt(s0.mutationPayload,`mutation:${opId}:payload`),result_secret:null,request_hash:secrets.fingerprint({actor:actorId,clusterId:cid,workspaceId:wid,entityType:'consumers',entityId:null,action:'create',payload:s0.mutationPayload,parentId:null,credentialKind:null,approvedWorkflow:binding})};
  const c:any={id:credentialId,grant_id:grantId,consumer_id:consumerId,generation:1,kong_id:keyId,workflow_id:wf,key_secret:secrets.encrypt({key},portalKeyAad(cid,wid,credentialId,1)),key_fingerprint:secrets.fingerprint(key),state:'pending'};
  return{secrets,plan,snapshot,facts:{grant:g,workflow:w,execution:e,version:v,steps:rows,operation:op,credential:c}};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','dd'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('rejected-first-Consumer immutable plan proof',()=>{
  it('accepts the original sealed bugged custom_id without editing any historical ciphertext or row',()=>{const f=fixture(),before=structuredClone(f.facts);expect(validateRejectedIssuePlan(f.facts,f.secrets)).toEqual(f.plan);expect(f.facts).toEqual(before);});
  it.each(['plan-aead','key-aead','key-fingerprint','body-hmac','row-parent','row-type','row-manifest','create-logical-id','request-hash','scope','result','snapshot-aead','snapshot-hash','missing-absence','extra-absence','copied-native-before'])('denies %s substitution',kind=>{
    const f=fixture(),facts=f.facts;
    if(kind==='plan-aead')facts.version.payload_secret=facts.credential.key_secret;
    else if(kind==='key-aead')facts.credential.key_secret=facts.version.payload_secret;
    else if(kind==='key-fingerprint')facts.credential.key_fingerprint='0'.repeat(64);
    else if(kind==='body-hmac')facts.steps[0].mutation_payload_hmac='0'.repeat(64);
    else if(kind==='row-parent')facts.steps[1].parent_id=randomUUID();
    else if(kind==='row-type')facts.steps[1].credential_kind='key-auth';
    else if(kind==='row-manifest')facts.steps[1].native_requests[0].native_id=randomUUID();
    else if(kind==='create-logical-id')facts.steps[0].entity_id=facts.grant.consumer_id;
    else if(kind==='request-hash')facts.operation.request_hash='0'.repeat(64);
    else if(kind==='scope')facts.operation.transport_scope='a'.repeat(64);
    else if(kind==='result')facts.operation.result_secret=f.secrets.encrypt({},`mutation:${facts.operation.id}:result`);
    else if(kind==='snapshot-aead')facts.execution.snapshot_secret=facts.version.payload_secret;
    else if(kind==='snapshot-hash')facts.execution.snapshot_hash='0'.repeat(64);
    else if(kind==='copied-native-before')facts.operation.before_secret=f.secrets.encrypt({id:facts.grant.consumer_id},`mutation:${facts.operation.id}:before`);
    else{if(kind==='missing-absence')f.snapshot.objects.pop();else f.snapshot.objects.push(structuredClone(f.snapshot.objects[1]));facts.execution.snapshot_hash=f.secrets.fingerprint(f.snapshot);facts.execution.snapshot_secret=f.secrets.encrypt(f.snapshot,snapshotAad(f.plan.clusterId,f.plan.workspaceId,f.plan.workflowId,facts.execution.id));}
    expect(()=>validateRejectedIssuePlan(facts,f.secrets)).toThrowError(expect.objectContaining({response:expect.objectContaining({code:'PORTAL_REJECTED_ISSUE_PROOF_INVALID'})}));
  });
});
