import {describe,expect,it,vi} from 'vitest';
import {randomBytes,randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {PENDING_KEY_TUPLE as T} from './lib/m6-pending-key-capture.mjs';
import {metadataRecoveryCheckpoint,guardMetadataRecovery,reconcileOriginalMetadata,assertRecoveryReceipt} from './lib/m6-metadata-recovery.mjs';
import {firstM6Grant,observeActivatedGrant} from './live-m6.mjs';
import {checkpointSha} from './lib/m6-isolated-transition.mjs';
import {M6_C1,M6_C2} from './lib/m6-harness.mjs';
import {RequestMethod} from '@nestjs/common';
import {EntitiesController} from '../../apps/console-api/src/modules/entities/entities.controller';
import {WorkflowController} from '../../apps/console-api/src/modules/workflows/workflow.controller';
import {WorkspacesController} from '../../apps/console-api/src/modules/workspaces/workspaces.controller';
import {PortalAdminController,PortalDeveloperController} from '../../apps/console-api/src/modules/portal/portal.controller';
import {AuthController} from '../../apps/console-api/src/modules/auth/auth.controller';
import {PortalAuthController} from '../../apps/console-api/src/modules/portal-auth/portal-auth.controller';

// Match the API workspace dependency even when npm nests Nest and the Vitest
// root alias resolves the public entry point rather than the constants subpath.
const apiRequire=createRequire(new URL('../../apps/console-api/package.json',import.meta.url));
const {PATH_METADATA,METHOD_METADATA}=apiRequire('@nestjs/common/constants');

function controllerRouteMatches(controllers:any[],path:string,method='GET'){
 const pathname=new URL(path,'http://unit.invalid').pathname;
 return controllers.some(controller=>Object.getOwnPropertyNames(controller.prototype).some(key=>{
  const endpoint=controller.prototype[key],route=Reflect.getMetadata(PATH_METADATA,endpoint),verb=Reflect.getMetadata(METHOD_METADATA,endpoint);
  if(typeof route!=='string'||RequestMethod[verb]!==method)return false;
  const full=`/${Reflect.getMetadata(PATH_METADATA,controller)}/${route}`.replace(/\/$/,'');
  const pattern=full.split('/').map(part=>part.startsWith(':')?'[^/]+':part.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('/');
  return new RegExp(`^${pattern}$`).test(pathname);
 }));
}

function fixture(){
 const tag='m6-isolated-synthetic',planHash=randomBytes(32).toString('hex'),app={id:randomUUID(),name:`${tag} Application A`,revision:1},c2App={id:randomUUID(),name:`${tag} Application C2`,revision:1};
 const fixtures=[T.clusterId,M6_C2,T.clusterId].map((id,index)=>({cluster:{id},workspace:{id:index?randomUUID():T.workspaceId,code:`${tag}-${index}`,revision:1,status:'active'},settings:{id:randomUUID(),revision:2,published:true},services:[{id:randomUUID(),host:'echo-upstream',port:8081}],routes:[{id:randomUUID(),paths:['/owned']}],publications:[{id:randomUUID(),serviceId:'',revision:5,documentRevision:2,status:'published'}]}));
 fixtures.forEach(f=>f.publications[0].serviceId=f.services[0].id);
 const consoleSession=()=>({user:{id:randomUUID()},cookie:`kongos_refresh=${randomUUID()}.synthetic; kongos_access=synthetic`});
 const admin=consoleSession(),approver=consoleSession(),c2Approver=consoleSession();
 const portalUsers=['developer-a','developer-b','developer-c2'].map((label,index)=>{const f=fixtures[index===2?1:0],id=randomUUID(),tenant={clusterId:f.cluster.id,workspaceId:f.workspace.id};return{id,label,tenant,session:{developer:{id,...tenant},cookie:`kongos_portal_refresh=${randomUUID()}.synthetic`}};});
 const newKey=randomUUID(),request={key:newKey,method:'POST',path:'/api/v1/portal/requests',actorId:portalUsers[0].id,httpStatus:201,state:'response_observed',body:{...portalUsers[0].tenant,applicationId:app.id,publicationId:fixtures[0].publications[0].id},responseData:{workflowId:T.workflowId,grant:{id:T.grantId}}};
 const exec={key:T.executionKey,method:'POST',path:`/api/v1/clusters/${T.clusterId}/workflows/${T.workflowId}/execute`,query:`?workspaceId=${T.workspaceId}`,actorId:admin.user.id,httpStatus:503,state:'response_observed',errorCode:'WORKFLOW_EXECUTION_FAILED',body:{confirmed:true,confirm_name:'portal-credential-issue',planHash,revision:3}};
 const native=[T.consumerOperationId,T.aclOperationId,T.keyOperationId].map((id,index)=>({id,entity_id:[T.consumerId,T.aclId,T.nativeId][index],state:'succeeded',remote_completed:true}));
 const diagnostic={originalExecution:{key:T.executionKey,workflowId:T.workflowId,clusterId:T.clusterId,workspaceId:T.workspaceId,status:503,errorCode:'WORKFLOW_EXECUTION_FAILED'},receipt:{state:'uncertain',executionId:T.executionId},native,grant:[{id:T.grantId,credential_id:T.credentialId,credential_state:'pending'}]};
 const plugins=['key-auth','acl'].map(name=>({id:randomUUID(),name,config:{},enabled:true})),old={testTag:'m6-security-prior',secrets:[randomUUID()]};
 const reference:any={testTag:tag,phase:'portal-publications-published',isolatedStart:{},priorFixtureRuns:[{testTag:old.testTag,checkpoint:old,checkpointSha256:checkpointSha(old)}],fixtures,portalUsers,consoleAdministrator:admin,accounts:{'approver-only':{session:approver},'approver-c2':{session:c2Approver}},portalTestTargets:{primary:{adminUrl:'http://kong-portal-admin-endpoint:8001',proxyOrigin:'http://127.0.0.1:10000'},secondary:{proxyOrigin:'http://127.0.0.1:9000'}},tokens:[M6_C1,M6_C2].flatMap(cid=>Object.entries({native_scrape:'bff',collector_scrape:'collector',collector_catalog:'bff',collector_ingest:'collector'}).map(([purpose,audience])=>({clusterId:cid,generation:cid===M6_C1?2:1,purpose,audience,token:randomBytes(32).toString('base64url')}))),pendingCredentialScanCaptures:[{credentialId:T.credentialId,executionId:T.executionId,scannerOnly:true}],credentialContinuation:{newKey,body:request.body},credentialExecutionFailure:diagnostic,writeAttempts:[...[[app,portalUsers[0]],[c2App,portalUsers[2]]].map(([value,user]:any)=>({path:'/api/v1/portal/applications',actorId:user.id,body:{name:value.name},httpStatus:201,responseData:{entity:value}})),...plugins.map(p=>({path:`/api/v1/clusters/${T.clusterId}/entities/plugins`,query:`?workspaceId=${T.workspaceId}`,httpStatus:201,responseData:{entity:p}})),request,exec]};
 return{reference,diagnostic,planHash,plugins,app,c2App};
}
function receipt(state='uncertain'){
 return{workflowId:T.workflowId,executionId:T.executionId,state,metadataRecovery:{eligible:true,executionId:T.executionId,originalExecutionKeyRequired:true},steps:[T.consumerOperationId,T.aclOperationId,T.keyOperationId].map((operationId,index)=>({id:randomUUID(),name:`native-${index}`,operationId,state:'succeeded',remoteCompleted:true})).concat([{id:T.metadataStepId,name:'portal.credential.activate',operationId:null,state,remoteCompleted:state==='succeeded'}]as any)};
}
function harness(){
 const f=fixture(),before:any={credential_state:'pending',grant_state:'pending',generation:1,current_generation:0,current_credential_id:null,credential_ref_id:null,issue_operation_id:null,workflow_state:'uncertain',execution_state:'uncertain',execution_actor_id:f.reference.consoleAdministrator.user.id,plan_hash:f.planHash,workflow_revision:4,native_operation_count:3,native_unresolved:0,portal_unresolved:0,immutable_key_cipher_sha:'a'.repeat(64),key_fingerprint:'b'.repeat(64)};
 const h:any={referenceData:f.reference,requireLive:vi.fn(),check(v:any,_id:any,message:any){if(!v)throw new Error(message);},ok(r:any){if(r.status<200||r.status>=300)throw new Error('synthetic rejected HTTP');return r.payload.data;},saveReference(extra:any={}){this.referenceData={...this.referenceData,...extra};},consoleRead:vi.fn(()=>[before])};
 h.request=vi.fn(async(session:any,path:string,method='GET')=>{if(method!=='GET')return{status:201,payload:{data:receipt('succeeded'),meta:{requestId:randomUUID()}}};let data:any;if(path==='/auth/me')data={id:session.user.id};if(path.includes('/workflows/receipts/'))data=receipt();else if(path.includes(`/workflows/${T.workflowId}`))data={entity:{id:T.workflowId,kind:'portal-credential-issue',state:'uncertain',revision:4,planHash:f.planHash}};for(const row of f.reference.fixtures){if(path.includes(`/workspaces/${row.workspace.id}`))data=row.workspace;else if(new URL(path,'http://unit.invalid').searchParams.get('workspaceId')===row.workspace.id){if(path.includes('/portal/settings'))data={settings:row.settings};for(const type of['services','routes','publications'])for(const value of row[type])if(path.includes(`/${type}/${value.id}`))data={entity:value};}}
 for(const p of f.plugins)if(path.includes(`/plugins/${p.id}`))data={entity:p};if(path.includes(`/consumers/${T.consumerId}`)){data={entity:{id:T.consumerId}};if(path.includes('/credentials/'))data={entity:{id:path.includes('key-auth')?T.nativeId:T.aclId,consumer:{id:T.consumerId},key:'[REDACTED:synthetic]'}};}
 if(!data)throw new Error('unplanned synthetic read');return{status:200,payload:{data}};});
 h.portal=vi.fn(async(session:any,path:string,method='GET')=>{if(method!=='GET'||!path.includes('/auth/me'))throw new Error('unplanned Portal packet');return{status:200,payload:{data:session.developer}};});
 return{...f,h,before};
}
describe('M6 exact original-execution metadata continuation (offline)',()=>{
 it('accepts the complete frozen uncertain checkpoint but rejects new key/executor/effect/material/history substitutions',()=>{
  const{reference,diagnostic}=fixture();expect(metadataRecoveryCheckpoint(reference,diagnostic).request.key).toBe(reference.credentialContinuation.newKey);
  const changes=[(r:any)=>r.metadataRecovery={phase:'reconcile-request-started'},(r:any)=>r.grants=[{id:randomUUID()}],(r:any)=>r.tokens[0].generation=9,(r:any)=>r.writeAttempts.at(-1).actorId=randomUUID(),(r:any)=>r.writeAttempts.at(-1).key=randomUUID(),(r:any)=>r.credentialExecutionFailure.native[0].state='uncertain',(r:any)=>r.priorFixtureRuns[0].checkpoint.secrets.push('tamper')];
  for(const change of changes){const r=structuredClone(reference);change(r);expect(()=>metadataRecoveryCheckpoint(r)).toThrow();}
 });
 it('validates original identities/native/configuration/receipts using GET+SELECT only before journaling the single original-key recovery',async()=>{
  const{h}=harness(),context=await guardMetadataRecovery(h);expect(h.request.mock.calls.every((c:any)=>!c[2]||c[2]==='GET')).toBe(true);expect(h.portal.mock.calls.every((c:any)=>!c[2]||c[2]==='GET')).toBe(true);expect(h.consoleRead.mock.calls[0][0]).toMatch(/^SELECT/);
  expect(context.recoveryBody).toMatchObject({revision:4,executionId:T.executionId,confirmed:true,confirm_name:'portal-credential-issue'});expect(h.referenceData.metadataRecovery.originalKey).toBe(T.executionKey);
  await expect(guardMetadataRecovery(h)).rejects.toThrow();
 });
 it('uses the actual Nest credential detail route for both existing children before admitting recovery',async()=>{
  const {h}=harness();
  const prefix=Reflect.getMetadata(PATH_METADATA,EntitiesController);
  const childRoute=Reflect.getMetadata(PATH_METADATA,EntitiesController.prototype.getCredential);
  const consumerRoute=Reflect.getMetadata(PATH_METADATA,EntitiesController.prototype.get);
  const expand=(route:string,params:Record<string,string>)=>`/${prefix}/${route}`.replace(/:([A-Za-z]+)/g,(_match,key)=>params[key]);
  const consumerPath=expand(consumerRoute,{clusterId:T.clusterId,entityType:'consumers',entityId:T.consumerId});
  const expectedChildren=['acls','key-auth'].map((kind,index)=>expand(childRoute,{clusterId:T.clusterId,consumerId:T.consumerId,kind,credentialId:[T.aclId,T.nativeId][index]}));
  const original=h.request.getMockImplementation();
  h.request.mockImplementation(async(...args:any[])=>{
   const pathname=new URL(args[1],'http://unit.invalid').pathname;
   if(pathname.includes('/credentials/')&&!expectedChildren.includes(pathname))return{status:404,payload:{data:null}};
   return original(...args);
  });
  await guardMetadataRecovery(h);
  const requested=h.request.mock.calls.map((call:any[])=>new URL(call[1],'http://unit.invalid').pathname);
  expect(requested).toContain(consumerPath);expect(requested.filter((path:string)=>path.includes('/credentials/'))).toEqual(expectedChildren);
  expect(h.referenceData.metadataRecovery.phase).toBe('before-single-reconcile');
  expect(h.request.mock.calls.every((call:any[])=>!call[2]||call[2]==='GET')).toBe(true);
 });
 it('matches every metadata continuation read, original recovery and normal reveal against actual Nest path and method metadata',async()=>{
  const f=harness(),{h,before}=f,base=h.request.getMockImplementation();let completed=false;
  const consoleControllers=[AuthController,WorkspacesController,EntitiesController,PortalAdminController,WorkflowController];
  h.request.mockImplementation(async(...args:any[])=>{
   const method=args[2]??'GET';expect(controllerRouteMatches(consoleControllers,args[1],method)).toBe(true);
   const response=await base(...args);
   if(method==='POST')completed=true;
   if(completed&&args[1].includes('/workflows/receipts/'))response.payload.data=receipt('succeeded');
   return response;
  });
  h.consoleRead.mockImplementation((sql:string)=>{
   if(sql.startsWith('SELECT g.consumer_id,g.acl_id,c.kong_id'))return[{consumer_id:T.consumerId,acl_id:T.aclId,kong_id:T.nativeId}];
   return[{...before,...(completed?{credential_state:'active',grant_state:'active',current_generation:1,current_credential_id:T.credentialId,credential_ref_id:T.keyReferenceId,acl_credential_ref_id:T.aclReferenceId,issue_operation_id:T.keyOperationId,workflow_state:'succeeded',execution_state:'succeeded'}:{})}];
  });
  const context=await guardMetadataRecovery(h);await reconcileOriginalMetadata(h,context);h.secrets=[];
  h.portal.mockImplementation(async(session:any,path:string,method='GET')=>{
   expect(controllerRouteMatches([PortalAuthController,PortalDeveloperController],`/portal${path}`,method)).toBe(true);
   let data:any;
   if(path.includes(`/applications/${context.app.id}/grants/${T.grantId}/credentials/${T.credentialId}/reveal`))data={key:'explicit-synthetic-placeholder-key-for-route-only-test'};
   else if(path.includes(`/applications/${context.app.id}/grants/${T.grantId}/credentials`))data={items:[{id:T.credentialId,state:'active',revision:2,maskedKey:'••••••••'}]};
   else if(path.includes(`/applications/${context.app.id}/grants`))data={items:[{id:T.grantId,state:'active',publicationId:context.primary.publications[0].id}]};
   else throw new Error('Unplanned route-contract packet');
   return{status:method==='POST'?201:200,payload:{data},response:{headers:new Headers({'cache-control':'no-store'})}};
  });
  const observed=await observeActivatedGrant(h,context.primary,context.developer,context.app,context.primary.publications[0],T.grantId,T.workflowId,T.credentialId);
  expect(observed.managed).toEqual({consumer_id:T.consumerId,acl_id:T.aclId,kong_id:T.nativeId});
  expect(h.request.mock.calls.filter((call:any[])=>call[2]==='POST')).toHaveLength(1);
  expect(h.portal.mock.calls.filter((call:any[])=>call[2]==='POST')).toHaveLength(1);
  expect(controllerRouteMatches(consoleControllers,`/clusters/${T.clusterId}/entities/consumers/${T.consumerId}/credentials/acls/${T.aclId}`)).toBe(false);
 });
 it('stops before any recovery write on revoked authorization, stale server eligibility or changed native completion count',async()=>{
  for(const failure of['revoked','ineligible','count']){const{h,before}=harness();if(failure==='revoked')h.request.mockResolvedValue({status:403});else if(failure==='count')before.native_operation_count=4;else{const base=h.request.getMockImplementation();h.request.mockImplementation(async(...args:any[])=>{const r=await base(...args);if(args[1].includes('/workflows/receipts/'))r.payload.data.metadataRecovery.eligible=false;return r;});}await expect(guardMetadataRecovery(h)).rejects.toThrow();expect(h.request.mock.calls.every((c:any)=>!c[2]||c[2]==='GET')).toBe(true);expect(h.referenceData.metadataRecovery).toBeUndefined();}
 });
 it('uses one formal POST with the original execution key, then receipt+DB reads prove activation and no extra native operation/cipher mutation',async()=>{
  const{h,before}=harness(),context=await guardMetadataRecovery(h);const actual=h.request.getMockImplementation();h.request.mockImplementation(async(...args:any[])=>{const r=await actual(...args);if(args[1].includes('/workflows/receipts/'))r.payload.data=receipt('succeeded');return r;});
  h.consoleRead.mockReturnValue([{...before,credential_state:'active',grant_state:'active',current_generation:1,current_credential_id:T.credentialId,credential_ref_id:T.keyReferenceId,acl_credential_ref_id:T.aclReferenceId,issue_operation_id:T.keyOperationId,workflow_state:'succeeded',execution_state:'succeeded'}]);
  await reconcileOriginalMetadata(h,context);const writes=h.request.mock.calls.filter((c:any)=>c[2]==='POST');expect(writes).toHaveLength(1);expect(writes[0][1]).toContain('/reconcile-metadata');expect(writes[0][4].key).toBe(T.executionKey);expect(h.referenceData.metadataRecovery.phase).toBe('metadata-succeeded-original-execution');
  await expect(reconcileOriginalMetadata(h,context)).rejects.toThrow();expect(h.request.mock.calls.filter((c:any)=>c[2]==='POST')).toHaveLength(1);
 });
 it('retains a started original-key recovery on transport loss and cannot resend or fall back to first request',async()=>{
  const{h}=harness(),context=await guardMetadataRecovery(h);h.request.mockRejectedValue(new TypeError('synthetic response unknown'));await expect(reconcileOriginalMetadata(h,context)).rejects.toThrow();expect(h.referenceData.metadataRecovery.phase).toBe('reconcile-request-started');
  await expect(reconcileOriginalMetadata(h,context)).rejects.toThrow();await expect(firstM6Grant(h,context)).rejects.toThrow();expect(h.request.mock.calls.filter((c:any)=>c[2]==='POST')).toHaveLength(1);expect(h.portal.mock.calls.every((c:any)=>c[2]!=='POST')).toBe(true);
 });
 it('continues from an observed completed first grant without a Portal request, approval or native execution replay',async()=>{
  const{h,app}=harness(),grant={id:T.grantId},credential={id:T.credentialId};h.referenceData.metadataRecovery={phase:'metadata-succeeded-original-execution',receiptState:'succeeded',workflowId:T.workflowId,grantId:T.grantId,credentialId:T.credentialId};
  const recovered={app,grant,credential,workflowId:T.workflowId},context={app,metadataRecoveryVerified:true,recoveredFirstGrant:recovered};expect(await firstM6Grant(h,context)).toBe(recovered);expect(h.request).not.toHaveBeenCalled();expect(h.portal).not.toHaveBeenCalled();
  await expect(firstM6Grant(h,{...context,metadataRecoveryVerified:false})).rejects.toThrow();
 });
 it('rejects stale original native operation IDs and wrong final metadata identity in otherwise successful receipts',()=>{
  const{h}=harness();const r=receipt('succeeded');r.steps[0].operationId=randomUUID();expect(()=>assertRecoveryReceipt(h,r,'succeeded')).toThrow();const q=receipt('succeeded');q.steps[3].id=randomUUID();expect(()=>assertRecoveryReceipt(h,q,'succeeded')).toThrow();
 });
});
