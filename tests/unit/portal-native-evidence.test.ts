import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { PortalCredentialsService } from '../../apps/console-api/src/modules/portal/portal-credentials.service';
import { loadPortalGrantNativeEvidence, loadPortalIssueNativeEvidence } from '../../apps/console-api/src/modules/portal/portal-native-evidence';
import { portalKeyAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { normalizedNativeRequests } from '../../apps/console-api/src/modules/workflows/approved-execution.types';
import { planAad, type WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Real sealing, compiler manifests, evidence and activation handler. SQL and
 * native reads are explicit fixtures; actual constraints are tested in PG16. */
function fixture(parentState: 'executing'|'uncertain'|'succeeded' = 'succeeded') {
  const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),wf=randomUUID(),exec=randomUUID(),grantId=randomUUID(),credentialId=randomUUID(),actorId=randomUUID();
  const consumerId=randomUUID(),aclId=randomUUID(),keyId=randomUUID(),developerId=randomUUID(),key='SyntheticOnlyPortalKey_2026';
  const grant:any={id:grantId,cluster_id:cid,workspace_id:wid,transport_scope:'b'.repeat(64),application_id:randomUUID(),publication_id:randomUUID(),developer_id:developerId,consumer_id:consumerId,acl_id:aclId,acl_group:'kos-portal-test',workflow_id:wf,state:'pending',current_generation:0,current_credential_id:null,acl_credential_ref_id:null,reservation_released_at:null,revision:1};
  const credential:any={id:credentialId,cluster_id:cid,workspace_id:wid,grant_id:grantId,developer_id:developerId,consumer_id:consumerId,kong_id:keyId,generation:1,key_secret:secrets.encrypt({key},portalKeyAad(cid,wid,credentialId,1)),key_fingerprint:secrets.fingerprint(key),workflow_id:wf,state:'pending',revision:1};
  const native=new PortalNativeService({}as any,secrets,{}as any,{}as any,{}as any,{}as any);
  const p0={id:consumerId,username:'fixture-consumer',tags:['kos-ws-test']},p1={id:aclId,group:grant.acl_group,tags:['kos-ws-test']},p2={id:keyId,key,tags:['kos-ws-test']};
  const first=native.nativeStep(1,'consumers','create',p0,null,{workflowId:wf}),second=native.nativeStep(2,'credentials','create',p1,null,{workflowId:wf,parentId:consumerId,credentialKind:'acls',dependencies:[first.id]}),third=native.nativeStep(3,'credentials','create',p2,null,{workflowId:wf,parentId:consumerId,credentialKind:'key-auth',dependencies:[second.id]});
  const last=native.metadataStep(4,'portal.credential.activate','portal_application_grants',grantId,structuredClone(grant),{action:'issue',generation:1,credentialId,kongId:keyId,consumerId,aclId,keyFingerprint:credential.key_fingerprint},[third.id]);
  const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,kind:'portal-credential-issue',executionMode:'direct',approvalRequired:true,subject:{type:'portal_application_grants',id:grantId},requester:{type:'developer',id:developerId},definition:{id:randomUUID(),version:1,policyHash:'c'.repeat(64)},issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:grant.transport_scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[first,second,third,last],generated:{consumerId,aclId,credentialId:keyId,key}};
  const workflow:any={id:wf,cluster_id:cid,workspace_id:wid,plan_revision:1,plan_hash:secrets.fingerprint(plan),state:parentState,kind:plan.kind,subject_type:plan.subject.type,subject_id:grantId,requester_type:'developer',requester_developer_id:developerId,execution_mode:'direct',approval_required:true,approved_by:randomUUID()};
  const execution:any={id:exec,cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:workflow.plan_hash,state:parentState,execution_mode:'direct',approval_required:true,approved_by:workflow.approved_by,execution_actor_id:actorId};
  const version:any={plan_hash:workflow.plan_hash,steps_hash:secrets.fingerprint(plan.steps),payload_secret:secrets.encrypt(plan,planAad(cid,wid,wf,1)),execution_mode:'direct',approval_required:true,step_count:4,native_request_count:3};
  const raw=[{...p0,created_at:100},{...p1,consumer:{id:consumerId},created_at:100},{...p2,consumer:{id:consumerId},created_at:100}];
  const operations:any[]=[];
  const rows:any[]=plan.steps.map((step,index)=>{
    const row:any={id:step.id,cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:workflow.plan_hash,step_key:step.key,step_order:step.order,kind:step.kind,entity_type:step.entityType,entity_id:step.entityId??null,parent_id:step.parentId??null,credential_kind:step.credentialKind??null,permission_action:step.permissionAction,mutation_action:step.mutationAction??null,handler:step.handler??null,mutation_payload_hmac:step.mutationPayloadHmac??null,before_fingerprint:step.beforeFingerprint??null,mutation_idempotency_key:step.mutationIdempotencyKey??null,metadata_before_hmac:step.metadataBeforeHmac??null,metadata_payload_hmac:step.metadataPayloadHmac??null,metadata_revision:step.metadataRevision??null,dependencies:step.dependencies,native_requests:normalizedNativeRequests(step.nativeRequests,secrets),execution_mode:'direct',approval_required:true,state:index<3?'succeeded':parentState==='executing'?'running':parentState==='uncertain'?'uncertain':'succeeded',operation_id:null,revision:3};
    if(index<3){const id=randomUUID(),binding={workflowId:wf,executionId:exec,planRevision:1,planHash:workflow.plan_hash,stepId:step.id,beforeHmac:step.beforeFingerprint};
      row.operation_id=id;row.after_fingerprint=secrets.fingerprint(raw[index]);operations.push({id,cluster_id:cid,workspace_id:wid,transport_scope:grant.transport_scope,actor_id:actorId,action:'create',entity_type:step.entityType,entity_id:step.nativeRequests[0].nativeId,parent_id:step.parentId??null,credential_kind:step.credentialKind??null,workflow_id:wf,workflow_execution_id:exec,workflow_plan_revision:1,workflow_plan_hash:workflow.plan_hash,workflow_step_id:step.id,idempotency_key:step.mutationIdempotencyKey,state:'succeeded',remote_started:true,remote_completed:true,before_secret:secrets.encrypt(null,`mutation:${id}:before`),payload_secret:secrets.encrypt(step.mutationPayload,`mutation:${id}:payload`),result_secret:secrets.encrypt(raw[index],`mutation:${id}:result`),request_hash:secrets.fingerprint({actor:actorId,clusterId:cid,workspaceId:wid,entityType:step.entityType,entityId:null,action:'create',payload:step.mutationPayload,parentId:step.parentId??null,credentialKind:step.credentialKind??null,approvedWorkflow:binding})});}
    return row;
  });
  const refs=raw.slice(1).map((value,index)=>({id:randomUUID(),cluster_id:cid,consumer_id:consumerId,credential_type:index?'key-auth':'acls',kong_id:value.id,state:'active',payload_secret:secrets.encrypt({credential:value,rawInput:{}},`credential:${cid}:${consumerId}:${index?'key-auth':'acls'}:${value.id}`)}));
  const db:any={one:vi.fn(async(sql:string,p:any[])=>{
    if(sql.includes('FROM portal_application_grants'))return grant;
    if(sql.includes('FROM portal_credentials'))return credential;
    if(sql.includes('FROM workflow_executions'))return sql.startsWith('SELECT state')?{state:execution.state}:execution;
    if(sql.includes('FROM workflow_versions'))return version;if(sql.includes('FROM workflows'))return workflow;
    if(sql.includes('FROM mutation_operations'))return operations.find(op=>op.id===p[0]);
    if(sql.includes('FROM credential_refs'))return refs.find(ref=>ref.kong_id===p[2]);return null;
  }),query:vi.fn(async(sql:string)=>sql.includes('FROM workflow_steps')?sql.includes("kind='native'")?rows.slice(0,3):rows:sql.includes('FROM credential_refs')?refs:[]),exec:vi.fn(async(sql:string,p:any[])=>{
    if(sql.startsWith('UPDATE portal_credentials'))Object.assign(credential,{state:'active',credential_ref_id:p[1],issue_operation_id:p[2],revision:credential.revision+1});
    if(sql.startsWith('UPDATE portal_application_grants'))Object.assign(grant,{state:'active',current_generation:p[1],current_credential_id:p[2],acl_credential_ref_id:p[3],revision:grant.revision+1});return 1;
  })};
  const registry=new WorkflowRegistryService(),nativeReads=vi.fn(async(_cid:string,path:string)=>path===`/consumers/${consumerId}`?raw[0]:path.endsWith(`/acls/${aclId}`)?raw[1]:raw[2]);
  const service=new PortalCredentialsService(db,secrets,{}as any,{}as any,{}as any,{}as any,{assertSubject:vi.fn()}as any,{}as any,registry,{read:nativeReads}as any);service.onModuleInit();
  const input={plan,step:last,actor:{user:{id:actorId},workspaceId:wid}as any,executionId:exec};
  return{secrets,cid,wid,workflow,execution,version,plan,rows,operations,raw,refs,grant,credential,db,registry,input,nativeReads};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','dc'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('immutable Portal key and first-issuance evidence',()=>{
  it('reconstructs raw Consumer/ACL/key from exact successful encrypted receipts without any native call',async()=>{const f=fixture(),result=await loadPortalGrantNativeEvidence(f.db,f.secrets,{clusterId:f.cid,workspaceId:f.wid,grantId:f.grant.id});expect(result.consumer).toEqual(f.raw[0]);expect(result.acl).toEqual(f.raw[1]);expect(result.keyCredential).toEqual(f.raw[2]);expect(f.nativeReads).not.toHaveBeenCalled();});
  it('does not walk previous key generations and retains generation1 proof after its key is revoked',async()=>{const f=fixture();f.credential.state='revoked';f.grant.current_generation=9;f.grant.workflow_id=randomUUID();await expect(loadPortalGrantNativeEvidence(f.db,f.secrets,{clusterId:f.cid,workspaceId:f.wid,grantId:f.grant.id})).resolves.toMatchObject({consumer:f.raw[0]});expect(f.db.one.mock.calls.filter((call:any[])=>call[0].includes('FROM portal_credentials'))).toHaveLength(1);expect(f.db.one.mock.calls[1][0]).toContain('generation=1');});
  it.each(['uncertain','executing'])('refuses %s first-issue parent for later rotation compiler',async(state)=>{const f=fixture(state as any);await expect(loadPortalGrantNativeEvidence(f.db,f.secrets,{clusterId:f.cid,workspaceId:f.wid,grantId:f.grant.id})).rejects.toMatchObject({response:{code:'PORTAL_CREDENTIAL_PROOF_INVALID'}});});
  const failures:Array<[string,(f:ReturnType<typeof fixture>)=>void]>=[
    ['missing raw result',f=>f.operations[0].result_secret=null],['masked result',f=>{const op=f.operations[2];op.result_secret=f.secrets.encrypt({...f.raw[2],key:'[REDACTED]'},`mutation:${op.id}:result`);}],
    ['wrong after fingerprint',f=>f.rows[1].after_fingerprint='a'.repeat(64)],['unacknowledged operation',f=>f.operations[0].remote_completed=false],
    ['wrong physical scope',f=>f.operations[0].transport_scope='a'.repeat(64)],['foreign execution',f=>f.operations[1].workflow_execution_id=randomUUID()],
    ['wrong credential kind',f=>f.operations[1].credential_kind='key-auth'],['wrong parent',f=>f.operations[2].parent_id=randomUUID()],
    ['CREATE logical hash uses ACK UUID',f=>{const op=f.operations[0];op.request_hash=f.secrets.fingerprint({entityId:op.entity_id});}],
    ['wrong encrypted payload',f=>{const op=f.operations[2];op.payload_secret=f.secrets.encrypt({...f.plan.steps[2].mutationPayload as any,key:'changed'},`mutation:${op.id}:payload`);}],
    ['copied ciphertext context',f=>f.operations[1].result_secret=f.operations[0].result_secret],['extra normalized step',f=>f.rows.push({...f.rows[3],id:randomUUID()})],
    ['different key-only box',f=>f.credential.key_secret=f.secrets.encrypt({key:'changed'},portalKeyAad(f.cid,f.wid,f.credential.id,1))],
  ];
  it.each(failures)('rejects %s while retaining immutable history',async(_name,change)=>{const f=fixture();change(f);await expect(loadPortalGrantNativeEvidence(f.db,f.secrets,{clusterId:f.cid,workspaceId:f.wid,grantId:f.grant.id})).rejects.toMatchObject({response:{code:'PORTAL_CREDENTIAL_PROOF_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();expect(f.nativeReads).not.toHaveBeenCalled();});
  it.each(['executing','uncertain']as const)('actual activate handler preserves exact key ciphertext for %s parent',async(state)=>{const f=fixture(state),cipher=f.credential.key_secret,handler=f.registry.get('portal.credential.activate');await handler.prepare!(f.input);const inspection=await handler.inspect(f.input,f.db);expect(inspection.revision).toBe(1);await handler.apply({...f.input,transaction:f.db});expect(f.credential.key_secret).toBe(cipher);expect(f.secrets.decrypt(cipher,portalKeyAad(f.cid,f.wid,f.credential.id,1))).toEqual({key:f.raw[2].key});expect(f.credential.state).toBe('active');expect(f.grant.current_generation).toBe(1);expect(f.db.exec.mock.calls.find((call:any[])=>call[0].startsWith('UPDATE portal_credentials'))[0]).not.toContain('key_secret');});
  it('rejects current native drift before activation without any SQL write',async()=>{const f=fixture('uncertain');f.nativeReads.mockResolvedValueOnce({...f.raw[0],username:'changed'});await expect(f.registry.get('portal.credential.activate').prepare!(f.input)).rejects.toMatchObject({response:{code:'PORTAL_CREDENTIAL_PROOF_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();});
  it('rejects a terminal parent when trying to prepare a second activation',async()=>{const f=fixture();await expect(f.registry.get('portal.credential.activate').prepare!(f.input)).rejects.toMatchObject({response:{code:'PORTAL_CREDENTIAL_PROOF_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();});
});
