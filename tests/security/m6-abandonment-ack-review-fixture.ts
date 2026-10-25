import { vi } from 'vitest';
import { randomBytes,randomUUID } from 'node:crypto';
import { FAILED_ISSUE_DATABASE_SQL } from './lib/m6-failed-issue-continuation.mjs';
import { FAILED_ISSUE_TUPLE as T } from './lib/m6-failed-issue-key-capture.mjs';
import { PENDING_KEY_TUPLE as F } from './lib/m6-pending-key-capture.mjs';
import { M6_C1,M6_C2 } from './lib/m6-harness.mjs';
import { checkpointSha } from './lib/m6-isolated-transition.mjs';

/** Entirely invented reference and GET/SELECT responses. The real continuation
 * helper is exercised without importing its executable runner, a live harness,
 * any private checkpoint, Docker or a DB connection. */
export function acknowledgmentReviewFixture(){
 const fixtures=[T.clusterId,M6_C2,T.clusterId].map((clusterId,i)=>({cluster:{id:clusterId},workspace:{id:i?randomUUID():T.workspaceId,revision:1,status:'active'},settings:{id:randomUUID(),revision:1,published:true},services:[{id:randomUUID(),name:'synthetic-service',host:'offline.invalid'}],routes:[{id:randomUUID(),paths:['/synthetic']}],publications:Array.from({length:i?1:2},()=>({id:randomUUID(),revision:2,documentRevision:1,status:'published'}))}));
 const admin={user:{id:randomUUID()},cookie:'synthetic'},approver={user:{id:randomUUID()},cookie:'synthetic'},secondApprover={user:{id:randomUUID()},cookie:'synthetic'};
 const portalUsers=['developer-a','developer-b','developer-c2'].map((label,i)=>{const tenant={clusterId:fixtures[i===2?1:0].cluster.id,workspaceId:fixtures[i===2?1:0].workspace.id},id=randomUUID();return{label,id,tenant,session:{developer:{id,...tenant},cookie:'synthetic'}};});
 const tag='m6-isolated-independent-failed-issue',app={id:randomUUID(),name:`${tag} Application A`,revision:1,state:'active'},c2app={id:randomUUID(),name:`${tag} Application C2`,revision:1,state:'active'},planHash='a'.repeat(64);
 fixtures.forEach((row,i)=>Object.assign(row.workspace,{code:`${tag}-${i}`}));
 const pluginRows=['acl','key-auth'].map(name=>({id:randomUUID(),name,enabled:true,config:{}}));
 const first={workflowId:F.workflowId,app,grant:{id:F.grantId,state:'active',generation:1},credential:{id:F.credentialId,state:'active'},apiKey:randomBytes(32).toString('base64url'),managed:{consumer_id:F.consumerId,acl_id:F.aclId,kong_id:F.nativeId}};
 const prior={testTag:'m6-security-synthetic-prior-checkpoint',secrets:['old-synthetic-preserved-material'],writeAttempts:[{key:randomUUID(),state:'uncertain'}]};
 const request={key:randomUUID(),method:'POST',path:'/api/v1/portal/requests',state:'response_observed',httpStatus:201,actorId:portalUsers[0].id,body:{...portalUsers[0].tenant,applicationId:app.id,publicationId:fixtures[0].publications[1].id},responseData:{workflowId:T.workflowId,grant:{id:T.grantId}}};
 const execute={key:T.executionKey,method:'POST',path:`/api/v1/clusters/${T.clusterId}/workflows/${T.workflowId}/execute`,actorId:admin.user.id,state:'response_observed',httpStatus:409,errorCode:'KONG_VALIDATION_ERROR',body:{revision:3,planHash,confirmed:true,confirm_name:'portal-credential-issue'}};
 const reference:any={testTag:tag,phase:'portal-publications-published',fixtures,portalUsers,consoleAdministrator:admin,accounts:{'approver-only':{session:approver},'approver-c2':{session:secondApprover}},priorFixtureRuns:[{testTag:prior.testTag,checkpoint:prior,checkpointSha256:checkpointSha(prior)}],
 tokens:[M6_C1,M6_C2].flatMap(clusterId=>Object.entries({native_scrape:'bff',collector_scrape:'collector',collector_catalog:'bff',collector_ingest:'collector'}).map(([purpose,audience])=>({clusterId,generation:clusterId===M6_C1?2:1,purpose,audience,token:randomBytes(32).toString('base64url')}))),
 portalTestTargets:{primary:{adminUrl:'http://kong-portal-admin-endpoint:8001',proxyOrigin:'http://127.0.0.1:10000'},secondary:{proxyOrigin:'http://127.0.0.1:9000'}},
 metadataRecovery:{phase:'metadata-succeeded-original-execution',receiptState:'succeeded',workflowId:F.workflowId,executionId:F.executionId,grantId:F.grantId,credentialId:F.credentialId,after:{immutable_key_cipher_sha:'b'.repeat(64),key_fingerprint:'c'.repeat(64)}},
 grants:[first],failedIssueCredentialScanCaptures:[{credentialId:T.credentialId,executionId:T.executionId,scannerOnly:true}],secondCredentialExecutionFailure:{originalExecution:{key:T.executionKey},receipt:{state:'failed',executionId:T.executionId},native:[{id:T.consumerOperationId,state:'failed',remote_completed:false}],unresolved:0},
 writeAttempts:[request,execute,...[[app,portalUsers[0]],[c2app,portalUsers[2]]].map(([app,dev]:any)=>({path:'/api/v1/portal/applications',httpStatus:201,actorId:dev.id,body:{name:app.name},responseData:{entity:app}})),...pluginRows.map(p=>({path:`/api/v1/clusters/${T.clusterId}/entities/plugins`,query:`workspaceId=${T.workspaceId}`,httpStatus:201,responseData:{entity:p}}))]};
 const firstDB:any={id:F.credentialId,grant_id:F.grantId,execution_id:F.executionId,idempotency_key:F.executionKey,consumer_id:F.consumerId,kong_id:F.nativeId,credential_state:'active',grant_state:'active',generation:1,current_generation:1,current_credential_id:F.credentialId,credential_ref_id:F.keyReferenceId,acl_credential_ref_id:F.aclReferenceId,issue_operation_id:F.keyOperationId,workflow_state:'succeeded',execution_state:'succeeded',native_operation_count:3,native_unresolved:0,portal_unresolved:0,immutable_key_cipher_sha:'b'.repeat(64),key_fingerprint:'c'.repeat(64),execution_actor_id:admin.user.id};
 const failedDB:any={credential_state:'pending',generation:1,credential_ref_id:null,issue_operation_id:null,recycle_entry_id:null,revoked_at:null,last_revealed_at:null,cipher_sha:'d'.repeat(64),grant_state:'pending',current_generation:0,current_credential_id:null,acl_credential_ref_id:null,reservation_released_at:null,consumer_id:T.consumerId,acl_id:T.aclId,kong_id:T.nativeId,workflow_state:'failed',plan_hash:planHash,workflow_revision:4,execution_state:'failed',execution_actor_id:admin.user.id,native_operation_count:1,unexpected_native_results:0,credential_refs:0,certificates:0,native_unresolved:0,portal_unresolved:0,scope_grants:2,scope_credentials:2};
 const certificate={id:randomUUID(),failed_step_id:T.consumerStepId,failed_operation_id:T.consumerOperationId,actor_id:admin.user.id,original_execution_key:T.executionKey};let closed=false;
 const receipt=()=>({workflowId:T.workflowId,executionId:T.executionId,state:'failed',steps:[{id:T.consumerStepId,state:'failed',operationId:T.consumerOperationId,errorCode:'KONG_VALIDATION_ERROR',remoteStarted:true,remoteCompleted:false},...[T.aclStepId,T.keyStepId,T.metadataStepId].map(id=>({id,state:'pending',operationId:null,remoteStarted:false,remoteCompleted:false}))],issueAbandonment:{kind:'portal-credential-issue',executionId:T.executionId,grantId:T.grantId,originalExecutionKeyRequired:true,eligible:!closed,completed:closed,reservationReleased:closed,...(closed?{certificateId:certificate.id}:{})}});
 const h:any={referenceData:reference,requireLive:vi.fn(),check:(value:any,_id:any,message:string)=>{if(!value)throw new Error(message);},ok:(r:any)=>{if(r.status<200||r.status>=300)throw new Error('OFFLINE_REJECTED_HTTP');return r.payload.data;},saveReference:vi.fn((extra:any={})=>{h.referenceData={...h.referenceData,...extra};})};
 h.consoleRead=vi.fn((sql:string)=>{
  if(!sql.startsWith('SELECT'))throw new Error('UNEXPECTED_SQL_WRITE');
  if(sql.includes('immutable_key_cipher_sha'))return[structuredClone(firstDB)];
  if(sql===FAILED_ISSUE_DATABASE_SQL)return[{...structuredClone(failedDB),...(closed?{grant_state:'disabled',reservation_released_at:'2026-10-11T00:00:00.000Z',certificates:1}:{})}];
  if(sql.includes('SELECT id,failed_step_id'))return[structuredClone(certificate)];
  throw new Error('UNEXPECTED_SQL_READ');
 });
 h.request=vi.fn(async(session:any,path:string,method='GET',body?:any,options?:any)=>{
  const u=new URL(path,'http://offline.invalid');let data:any;
  if(method==='POST'){
   if(u.pathname!==`/clusters/${T.clusterId}/workflows/${T.workflowId}/abandon-rejected-issue`||options?.key!==T.executionKey||h.referenceData.failedIssueContinuation.phase!=='abandonment-request-started')throw new Error('UNJOURNALED_OR_UNEXPECTED_POST');
   closed=true;data=receipt();
  }else if(path==='/auth/me')data={id:session.user.id};
  else if(u.pathname.endsWith(`/receipts/by-key/${F.executionKey}`))data={state:'succeeded',executionId:F.executionId,steps:Array.from({length:4},()=>({state:'succeeded'}))};
  else if(u.pathname.endsWith(`/receipts/by-key/${T.executionKey}`))data=receipt();
  else if(u.pathname===`/clusters/${T.clusterId}/workflows/${T.workflowId}`)data={entity:{id:T.workflowId,kind:'portal-credential-issue',state:'failed',revision:4,planHash,capabilities:{abandonRejectedIssue:true}}};
  for(const f of fixtures){if(u.pathname===`/clusters/${f.cluster.id}/workspaces/${f.workspace.id}`)data=f.workspace;
   if(u.searchParams.get('workspaceId')===f.workspace.id){if(u.pathname.endsWith('/portal/settings'))data={settings:f.settings};for(const type of['services','routes','publications'])for(const row of f[type])if(u.pathname.endsWith(`/${type}/${row.id}`))data={entity:row};}}
  for(const row of pluginRows)if(u.pathname.endsWith(`/plugins/${row.id}`))data={entity:row};
  if([`/clusters/${T.clusterId}/entities/consumers/${T.consumerId}`,`/clusters/${T.clusterId}/consumers/${T.consumerId}/credentials/acls/${T.aclId}`,`/clusters/${T.clusterId}/consumers/${T.consumerId}/credentials/key-auth/${T.nativeId}`].includes(u.pathname))return{status:404,payload:{data:null}};
  if(!data)throw new Error('UNEXPECTED_BFF_READ');return{status:method==='POST'?201:200,payload:{data:structuredClone(data),meta:{requestId:'offline-request-id'}}};
 });
 h.portal=vi.fn(async(session:any,path:string,method='GET')=>{if(method!=='GET')throw new Error('OFFLINE_NEW_REQUEST_BLOCKED');let data:any;
  if(path.includes('/auth/me'))data=session.developer;else if(path.includes(`/applications/${app.id}/grants/${F.grantId}/credentials`))data={items:[{id:F.credentialId,state:'active',maskedKey:'••••••••'}]};else if(path.includes(`/applications/${app.id}/grants`))data={items:[first.grant]};else if(new URL(path,'http://offline.invalid').pathname.endsWith(`/applications/${app.id}`))data={entity:app};else if(new URL(path,'http://offline.invalid').pathname.endsWith(`/applications/${c2app.id}`))data={entity:c2app};if(!data)throw new Error('UNEXPECTED_PORTAL_READ');return{status:200,payload:{data:structuredClone(data)}};});
 return{h,reference,firstDB,failedDB,certificate,receipt,setClosed:(value:boolean)=>{closed=value;}};
}

