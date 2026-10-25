import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {ForbiddenException} from '@nestjs/common';
import {workflowScheduledFixture} from '../unit/helpers/workflow-scheduled-fixture';
import {WorkflowCandidatesService} from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import {WorkflowScheduledValidationReadService,WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL} from '../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.service';
import {WorkflowBusinessCurrentIdentityService,WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256} from '../../apps/console-api/src/modules/workflows/workflow-business-current-identity.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {workflowSchedulePlanSeal} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {grantMatchesEntity} from '../../apps/console-api/src/modules/authorization/grant-policy';

// Source-only controlled SQL with genuine Context private Namespace/read
// associations, real crypto, Candidate and Validation providers. No HTTP,
// PostgreSQL, runtime worker, session impersonation or Native permit is used.
function fixture(collection=false,kind:'configuration_v2'|'portal-credential-issue'='configuration_v2',selection:'user'|'team'|'role'='user',format:1|2=2){
 const f=workflowScheduledFixture(kind),nativeId=randomUUID(),h=(value:unknown)=>f.secrets.fingerprint(value);
 const selectors=f.approvalSet.reviewers.map((r:any)=>selection==='user'?r.userId:randomUUID());
 f.approvalSet.format=format;
 const policy:any={version:2,kind,allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:1,
  stages:f.approvalSet.reviewers.map((reviewer:any,i:number)=>({level:reviewer.level,name:`level-${reviewer.level}`,mode:'any',threshold:1,selector:selection==='user'?{users:[reviewer.userId]}:selection==='team'?{teams:[selectors[i]]}:{roles:[selectors[i]]}}))};
 f.plan.definition.policyHash=h(policy);f.draft.binding.policyHash=h(policy);f.draft.delegation.policyHash=h(policy);
 const reseal=()=>{const{scheduling,...base}=f.plan;f.draft.binding.basePlanHash=h(base);f.draft.delegation.basePlanHash=h(base);
  f.draft.delegationHmac=h(f.draft.delegation);f.plan.scheduling=workflowSchedulePlanSeal(f.draft);f.draft.binding.workflowPlanHash=h(f.plan);};reseal();
 const candidates=f.approvalSet.reviewers.map((r:any,i:number)=>({level:r.level,mode:'any',threshold:1,candidates:[{userId:r.userId,credentialEpoch:'1',provenance:[selection==='role'?{kind:'role',selectorId:selectors[i],bindingId:randomUUID(),bindingSource:'user'}:{kind:selection,selectorId:selectors[i]}]}]}));
 const manifest:any={version:1,clusterId:f.cid,workspaceId:f.wid,workflowId:f.plan.workflowId,planRevision:1,planHash:h(f.plan),definitionId:f.plan.definition.id,
  definitionVersion:1,policyHash:h(policy),candidateVersion:1,stages:candidates};
 const candidateHmac=h(manifest),approvalMaterial={version:1,clusterId:f.cid,workspaceId:f.wid,workflowId:f.plan.workflowId,planRevision:1,
  planHash:h(f.plan),policyHash:h(policy),candidateVersion:1,candidateManifestHmac:candidateHmac,reviewers:f.approvalSet.reviewers};
 f.approvalSet.policyHash=h(policy);f.approvalSet.setHmac=h(approvalMaterial);
 const now=Date.now(),claim:any={id:randomUUID(),scheduleId:f.scheduleId,scheduleVersion:1,occurrenceId:f.draft.occurrenceId,generation:1,workerOwnerHmac:h('actual-controlled-worker'),
  workflowId:f.plan.workflowId,workflowPlanRevision:1,workflowPlanHash:h(f.plan),issuedAt:new Date(now-100).toISOString(),authorityExpiresAt:f.plan.expiresAt,
  initialLeaseUntil:new Date(now+90000).toISOString()};
 f.state.stored.claim=claim;f.state.stored.latestLease={id:randomUUID(),claimId:claim.id,generation:1,workerOwnerHmac:claim.workerOwnerHmac,version:1,previousId:null,leaseUntil:claim.initialLeaseUntil};
 f.state.stored.progress={state:'claimed',revision:3,claimId:claim.id,reasonCode:null};f.state.stored.activation={workflowId:f.plan.workflowId,
  workflowPlanRevision:1,workflowPlanHash:h(f.plan),approvalFormat:2,approvalRequired:true,approvalSetId:f.approvalSet.setId,approvalSetHmac:f.approvalSet.setHmac};f.state.lease=true;
 const nsHandle=Object.freeze({}),ns:any=immutableJson({version:1,origin:'scheduled-workflow',actor:{id:f.owner,username:'actual-sql-principal',superAdmin:false,forcePasswordChange:false},
  sessionId:null,clusterId:f.cid,workspaceId:f.wid,kind,transportScope:f.draft.transportScope,clusterRevision:1,workspaceRevision:1,permissionVersion:`${f.owner}:1:1`,
  credentialEpoch:'1',expiresAt:claim.initialLeaseUntil,claim:{...claim,clusterId:f.cid,workspaceId:f.wid,ownerId:f.owner,executorId:f.owner,
   ownerCredentialEpoch:'1',executorCredentialEpoch:'1',delegationId:f.draft.delegation.id,delegationVersion:1,delegationHmac:f.draft.delegationHmac,
   specHmac:f.draft.specHmac,windowStart:f.draft.spec.windowStart,windowEnd:f.draft.spec.windowEnd,impactHmac:f.draft.impactHmac,subjectSealHmac:f.draft.delegation.subjectSealHmac},
  workflow:{id:f.plan.workflowId,planRevision:1,planHash:h(f.plan)},requester:f.draft.binding.requester,subjectSealHmac:f.draft.delegation.subjectSealHmac,approvalSet:f.approvalSet});
 const row:any={id:f.plan.workflowId,state:'approved',plan_revision:1,plan_hash:h(f.plan),definition_id:f.plan.definition.id,definition_version:1,
  approval_required:true,approval_format:2,candidate_version:1,candidate_manifest_hmac:candidateHmac,approval_set_id:f.approvalSet.setId,
  approval_set_hmac:f.approvalSet.setHmac,approved_by:f.approvalSet.reviewers[2].userId};
 const votes=f.approvalSet.reviewers.map((r:any)=>({id:r.approvalId,approver_id:r.userId,level:r.level,plan_hash:h(f.plan),decision:'approve',candidate_version:1,candidate_manifest_hmac:candidateHmac}));
 const stages=candidates.map((c:any)=>({level:c.level,plan_hash:h(f.plan),state:'approved',required_approvals:1,approval_format:2,candidate_version:1,candidate_manifest_hmac:candidateHmac,stage_mode:'any'}));
 const values:any={live:true,copy:false,read:true,secretGrant:true,secretResource:false,scopeChanged:false,invalidated:false,reviewerEpoch:'1',reviewerPermissions:'5',membership:true,votes,stages,row,
  registryRevision:1,last:null,resources:[{clusterId:f.cid,workspaceId:f.wid,path:collection?'/services':`/services/${nativeId}`,kind:collection?'collection':'point',
   entityType:'services',...(collection?{query:{size:2}}:{entityId:nativeId}),secrets:false}]};
 const principalGrants=(userId:string)=>[{user_id:userId,cluster_id:f.cid,workspace_id:f.wid,module:'services',action:'read',scope_type:'global',scope_values:[]},
    ...(values.secretGrant?[{user_id:userId,cluster_id:f.cid,workspace_id:f.wid,module:'secrets',action:'read',scope_type:'global',scope_values:[]}]:[])];
 const originalOne=f.db.one.getMockImplementation()!;
 f.db.one.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql===WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL){
   const grants=principalGrants(args[0]);
   const [user,epoch]=await Promise.all([originalOne(`SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
      FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`,args),originalOne('SELECT version FROM iam_epoch WHERE singleton=true',[])]);
   if(user&&args[0]!==f.owner){user.permissions_epoch=values.reviewerPermissions;user.credential_epoch=values.reviewerEpoch;}
   return user&&epoch?{...user,iam_version:epoch.version,grants}:null;
  }
  if(sql.includes('FROM team_members')||sql.includes('SELECT 1 FROM iam_effective_grants g'))return values.membership?{allowed:true}:null;
  if(sql.includes('FROM schema_migrations'))return f.state.migration?{checksum:WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256}:null;
  if(sql.includes('FROM workflow_definition_versions'))return{approval_format:2,policy,policy_hash:h(policy),allow_self_approval:false};
  if(sql.includes('FROM workflow_candidate_versions'))return{manifest,manifest_hmac:candidateHmac};
  if(sql.includes('FROM workflow_approval_sets'))return{id:f.approvalSet.setId,set_hmac:f.approvalSet.setHmac,manifest:approvalMaterial};
  if(sql.includes('FROM workflow_approval_invalidations'))return values.invalidated?{id:randomUUID()}:null;
  if(sql.includes('FROM workflow_versions'))return{...row};
  if(sql.includes('FROM workflows'))return values.row;
  if(sql.includes('SELECT status,deleted_at,force_password_change,credential_epoch FROM users'))return f.state.reviewerActive?{status:'active',deleted_at:null,force_password_change:false,credential_epoch:values.reviewerEpoch}:null;
  const result=await originalOne(sql,args);if(sql.includes('FROM clusters')&&result)result.revision=values.registryRevision;
  if(sql.includes('FROM users')&&result&&args[0]!==f.owner){result.permissions_epoch=values.reviewerPermissions;result.credential_epoch=values.reviewerEpoch;}return result;
 });
 f.db.query.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.includes('FROM iam_effective_grants'))return principalGrants(args[0]);
  if(sql.includes('FROM workflow_stages'))return values.stages;
  if(sql.includes('FROM workflow_approvals'))return values.votes;
  if(sql.includes('FROM workflow_candidates'))return candidates.flatMap((stage:any)=>stage.candidates.map((c:any)=>({level:stage.level,user_id:c.userId,
   credential_epoch:c.credentialEpoch,provenance:c.provenance,plan_hash:h(f.plan),manifest_hmac:candidateHmac})));
  if(sql.includes('FROM workflow_approval_set_members'))return f.approvalSet.reviewers.map((r:any)=>({cluster_id:f.cid,workspace_id:f.wid,workflow_id:f.plan.workflowId,
   plan_revision:1,plan_hash:h(f.plan),set_hmac:f.approvalSet.setHmac,approval_id:r.approvalId,user_id:r.userId,level:r.level,candidate_version:1,candidate_manifest_hmac:candidateHmac}));
  throw Error('Unexpected controlled validation query');
 });
 const context=new KongExecutionContextService();
 const service=new WorkflowScheduledValidationReadService(f.db,f.secrets,f.redis,f.plans,f.repository,new WorkflowCandidatesService(f.db));
 const business:any={resolveReadScope:vi.fn(async()=>({version:1,resources:values.resources,limits:{maxCalls:10,maxPages:5,maxRecords:10,maxBytes:8192}})),
  assertCurrent:vi.fn(async()=>{if(!values.read)throw new ForbiddenException({code:'ACTUAL_SUBJECT_READ_DENIED'});}),
  authorizeResponse:vi.fn(async(input:any)=>{if(values.scopeChanged)throw new ForbiddenException({code:'ACTUAL_OBJECT_SCOPE_CHANGED'});
   const items=input.resource.kind==='collection'?input.response.data:input.resource.kind==='schema'?[]:[input.response];
   for(const item of items){const target={clusterId:input.resource.clusterId,workspaceId:input.resource.workspaceId,entityType:'services',entity:item};
    if(!input.principal.grants.some((g:any)=>grantMatchesEntity(g,'services','read',target)))throw new ForbiddenException({code:'ACTUAL_OBJECT_READ_DENIED'});
    if(input.resource.secrets&&!input.principal.grants.some((g:any)=>grantMatchesEntity(g,'secrets','read',target)))throw new ForbiddenException({code:'ACTUAL_SECRET_READ_DENIED'});
   }} )};
 const fullVerify=vi.fn(async(handle:object)=>{if(handle!==nsHandle||!values.live||!f.state.lease)throw Error('ORIGINAL_SOURCE_NAMESPACE_REQUIRED');return ns;});
 const native=vi.fn(async()=>{throw Error('NO_NATIVE_CALL_PERMITTED');});
 context.installWorkflowScheduledNamespacePolicy({verifyHandle:fullVerify,assertLive(handle:object){if(handle!==nsHandle||!values.live||!f.state.lease)throw Error('ORIGINAL_SOURCE_NAMESPACE_CLOSED');}});
 context.installPolicy({authorizeRequest:native,authorizeResponse:native});
 const runner:any={originalNamespaceProof:(handle:object)=>context.requireWorkflowScheduledCurrentPrincipal(handle).namespace,
  // Root's real synchronous Namespace registry checks its original handle;
  // it never re-enters Context.chain() from the read capsule's own live hook.
  assertNamespaceLive:(handle:object)=>{if(handle!==nsHandle||!values.live||!f.state.lease)throw Error('ORIGINAL_SOURCE_NAMESPACE_CLOSED');},
  run:(handle:object,original:object,fn:any)=>context.runWorkflowScheduledValidationRead(handle,original,fn)};
 const install=()=>{service.installStorageContract(WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256);service.installBusinessPolicy(kind,business);service.installContextRunner(runner);
  context.installWorkflowScheduledValidationReadPolicy({verifyHandle:service.verifyHandle.bind(service),assertLive:service.assertLive.bind(service),
   authorizeRequest:service.authorizeRequest.bind(service),verifyRequest:service.verifyRequest.bind(service),authorizeResponse:service.authorizeResponse.bind(service)});};
 const identity=new WorkflowBusinessCurrentIdentityService(f.db,f.secrets,context,f.redis,f.repository,f.plans,new WorkflowCandidatesService(f.db),service);
 const namespace=<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(nsHandle,fn);
 const observe=(actor=f.owner,proof=ns,handle=nsHandle,tx=f.db)=>identity.currentPrincipal(handle,proof,actor,tx);
 const validation=<T>(fn:()=>Promise<T>,role:'executor'|'reviewer'='reviewer',actor=f.approvalSet.reviewers[0].userId)=>{
  values.resources=values.resources.map((r:any)=>({...r,required:false}));
  return service.runValidationRead(nsHandle,f.cid,values.resources.map((r:any)=>r.path),f.db,fn,{role,userId:role==='executor'?f.owner:actor});};
 const packet=(query:any=collection?{size:2}:{},overrides:any={})=>({clusterId:f.cid,workspaceId:f.wid,method:'GET',path:values.resources[0].path,query,...overrides});
 const run=(fn:any,options?:any)=>service.runValidationRead(nsHandle,f.cid,values.resources.map((r:any)=>r.path),f.db,fn,options);
 const read=async(handle:object,response:any={id:nativeId,host:'controlled-unit'},query:any=collection?{size:2}:{})=>{
  const token=await service.authorizeRequest(handle,packet(query));await service.verifyRequest(token);return service.authorizeResponse(token,response);};
 return{...f,service,values,business,runner,install,packet,run,read,ns,nsHandle,nativeId,reseal,context,fullVerify,native,identity,namespace,observe,validation};
}

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T08:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

describe('fixed business current identity bridge observes original Context and current SQL only',()=>{
 it('locks its storage contract to the unchanged real SQL026 file',()=>{
  expect(createHash('sha256').update(readFileSync('apps/console-api/src/infrastructure/migrations/026_m11_workflow_schedules.sql')).digest('hex')).toBe(WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256);
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('returns current %s executor identity without Native, SID or full Namespace re-entry',async kind=>{
  const f=fixture(false,kind);f.install();
  await f.namespace(async()=>{const value=await f.observe();expect(value).toEqual({actorId:f.owner,credentialEpoch:'1',permissionVersion:f.ns.permissionVersion,role:'executor',readOnly:false});expect(Object.isFrozen(value)).toBe(true);expect(f.context.current().sessionId).toBeUndefined();});
  expect(f.fullVerify).toHaveBeenCalledTimes(1);expect(f.native).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  expect(f.db.one.mock.calls.some(([sql]:any[])=>sql.includes('auth_sessions'))).toBe(false);
  expect(f.db.one.mock.calls.filter(([sql]:any[])=>sql.includes('SELECT status,deleted_at')).map(([,args]:any[])=>args[0])).toEqual(expect.arrayContaining(f.approvalSet.reviewers.map((r:any)=>r.userId)));
 });
 it('keeps missing legacy frozen candidate epochs closed without changing HTTP/V1 paths',async()=>{
  const f=fixture(false,'configuration_v2','user',1);f.install();await f.namespace(()=>expect(f.observe()).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_FROZEN_APPROVAL_REQUIRED'}}));expect(f.db.one).not.toHaveBeenCalled();
 });
 it.each(['team','role'] as const)('checks actual frozen %s selector membership after Namespace issuance',async selection=>{
  const f=fixture(false,'configuration_v2',selection);f.install();await f.namespace(async()=>{expect(await f.observe()).toMatchObject({actorId:f.owner,role:'executor'});f.values.membership=false;await expect(f.observe()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVER_SELECTOR_REVOKED'}});});expect(f.native).not.toHaveBeenCalled();
 });
 it('does not dispatch a generic business-origin loader from outer identity observation',async()=>{
  const f=fixture();f.install();f.plans.load.mockImplementation(async()=>{throw Error('BUSINESS_LOADER_MUST_NOT_REENTER');});await f.namespace(()=>f.observe());expect(f.plans.load).not.toHaveBeenCalled();
 });
 it('cannot observe a namespace outside the actual original frame',async()=>{const f=fixture();f.install();await expect(f.observe()).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();});
 it.each(['namespace-proof','namespace-handle','actor'] as const)('rejects copied or mismatched %s before SQL',async field=>{
  const f=fixture();f.install();await f.namespace(async()=>{await expect(f.observe(field==='actor'?randomUUID():f.owner,field==='namespace-proof'?{...f.ns}:f.ns,field==='namespace-handle'?{}:f.nsHandle)).rejects.toThrow();});expect(f.db.one).not.toHaveBeenCalled();
 });
 it('keeps a real reviewer readonly with its own frozen PV instead of borrowing executor identity',async()=>{
  const f=fixture();f.install();const actor=f.approvalSet.reviewers[0].userId;
  await f.namespace(()=>f.validation(async()=>{const current=f.context.requireWorkflowScheduledCurrentPrincipal(f.nsHandle);expect(current).toMatchObject({role:'reviewer',readOnly:true});
   const value=await f.observe(actor);expect(value).toEqual({actorId:actor,credentialEpoch:'1',permissionVersion:`${actor}:5:1`,role:'reviewer',readOnly:true});
   expect(value.permissionVersion).not.toBe(f.ns.permissionVersion);expect(Object.keys(value).sort()).toEqual(['actorId','credentialEpoch','permissionVersion','readOnly','role']);
   await expect(f.observe(f.owner)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_ORIGINAL_REQUIRED'}});
  }));expect(f.fullVerify).toHaveBeenCalledTimes(1);expect(f.native).not.toHaveBeenCalled();
 });
 it('does not turn an executor validation capsule into write identity',async()=>{
  const f=fixture();f.install();await f.namespace(()=>f.validation(async()=>{expect(await f.observe()).toMatchObject({actorId:f.owner,role:'executor',readOnly:true});},'executor'));
 });
 it('checks the reviewer frozen permission version after its private read frame starts',async()=>{
  const f=fixture();f.install();const actor=f.approvalSet.reviewers[0].userId;
  await expect(f.namespace(()=>f.validation(async()=>{f.values.reviewerPermissions='6';await f.observe(actor);}))).rejects.toThrow();expect(f.native).not.toHaveBeenCalled();
 });
 it('rejects a forged read handle through the genuine Context policy',async()=>{
  const f=fixture();f.install();await f.namespace(()=>expect(f.context.runWorkflowScheduledValidationRead({},f.nsHandle,async()=>f.observe())).rejects.toThrow());
 });
 it.each(['migration','credential','permission','force-password','reviewer','policy','portal-requester'] as const)('re-observes current %s changes even with an original live Namespace',async field=>{
  const f=fixture(false,field==='portal-requester'?'portal-credential-issue':'configuration_v2');f.install();
  await f.namespace(async()=>{if(field==='migration')f.state.migration=false;if(field==='credential')f.state.epoch='2';if(field==='permission')f.state.principalVersion='2';
   if(field==='force-password')f.state.forceChange=true;if(field==='reviewer')f.state.reviewerActive=false;if(field==='policy')f.state.policyChanged=true;if(field==='portal-requester')f.state.forceRequesterChange=true;
   await expect(f.observe()).rejects.toThrow();});expect(f.native).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['claimed-progress','generation','worker','lease','lease-version','activation','owner','scope'] as const)('rejects changed current %s facts before identity return',async field=>{
  const f=fixture();f.install();await f.namespace(async()=>{if(field==='claimed-progress')f.state.stored.progress.state='cancelled';if(field==='generation')f.state.stored.claim.generation=2;
   if(field==='worker')f.state.stored.latestLease.workerOwnerHmac='0'.repeat(64);if(field==='lease')f.state.stored.latestLease.leaseUntil=new Date(Date.now()-1).toISOString();
   if(field==='lease-version'){f.state.stored.latestLease.version=2;f.state.stored.latestLease.previousId=randomUUID();}
   if(field==='activation')f.state.stored.activation=null;if(field==='owner')f.state.stored.draft.delegation.ownerId=randomUUID();if(field==='scope')f.values.registryRevision=2;
   await expect(f.observe()).rejects.toThrow();});expect(f.native).not.toHaveBeenCalled();
 });
 it.each(['votes','invalidated','candidate-epoch'] as const)('requires the complete frozen approval and live %s facts',async field=>{
  const f=fixture();f.install();await f.namespace(async()=>{if(field==='votes')f.values.votes=f.values.votes.slice(1);if(field==='invalidated')f.values.invalidated=true;if(field==='candidate-epoch')f.values.reviewerEpoch='2';await expect(f.observe()).rejects.toThrow();});
 });
 it('fences lease loss across a SQL await without returning a stale identity',async()=>{
  const f=fixture();f.install();const original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,args:any[])=>{const value=await original(sql,args);if(sql.includes('FROM schema_migrations'))f.state.lease=false;return value;});
  await expect(f.namespace(()=>f.observe())).rejects.toThrow();expect(f.db.one).toHaveBeenCalledTimes(1);expect(f.native).not.toHaveBeenCalled();
 });
 it('denies a Namespace closed during a SQL await',async()=>{
  const f=fixture();f.install();const original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,args:any[])=>{const value=await original(sql,args);if(sql.includes('FROM schema_migrations'))f.values.live=false;return value;});
  await expect(f.namespace(()=>f.observe())).rejects.toThrow();expect(f.db.one).toHaveBeenCalledTimes(1);
 });
 it('rechecks stored claim cancellation after all initial facts were read',async()=>{
  const f=fixture();f.install();const original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,args:any[])=>{const value=await original(sql,args);if(sql.includes('FROM workspaces'))f.state.stored.progress.state='cancelled';return value;});
  await expect(f.namespace(()=>f.observe())).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_CLAIM_CHANGED'}});
 });
 it.each(['portal-requester','policy','registry'] as const)('re-observes %s after its first valid mid-phase observation',async field=>{
  const f=fixture(false,field==='portal-requester'?'portal-credential-issue':'configuration_v2');f.install();const original=f.db.one.getMockImplementation()!;
  let changed=false;f.db.one.mockImplementation(async(sql:string,args:any[])=>{const value=await original(sql,args);if(sql.includes('FROM workspaces')&&!changed){changed=true;
   if(field==='portal-requester')f.state.forceRequesterChange=true;if(field==='policy')f.state.policyChanged=true;if(field==='registry')f.values.registryRevision=2;}return value;});
  await expect(f.namespace(()=>f.observe())).rejects.toMatchObject({response:{code:field==='portal-requester'?'WORKFLOW_BUSINESS_IDENTITY_REQUESTER_REVOKED':field==='policy'?'WORKFLOW_BUSINESS_IDENTITY_POLICY_CHANGED':'WORKFLOW_BUSINESS_IDENTITY_SCOPE_CHANGED'}});
  expect(f.native).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['portal-requester','policy','registry'] as const)('checks readonly %s after the final original validator has returned',async field=>{
  const f=fixture(false,field==='portal-requester'?'portal-credential-issue':'configuration_v2');f.install();const actor=f.approvalSet.reviewers[0].userId;
  const verify=f.service.verifyHandle.bind(f.service);let inside=false,checks=0;
  vi.spyOn(f.service,'verifyHandle').mockImplementation(async(...args:Parameters<typeof verify>)=>{const value=await verify(...args);if(inside&&++checks===3){
   if(field==='portal-requester')f.state.forceRequesterChange=true;if(field==='policy')f.state.policyChanged=true;if(field==='registry')f.values.registryRevision=2;}return value;});
  await expect(f.namespace(()=>f.validation(async()=>{inside=true;await f.observe(actor);}))).rejects.toMatchObject({response:{code:field==='portal-requester'?'WORKFLOW_BUSINESS_IDENTITY_REQUESTER_REVOKED':field==='policy'?'WORKFLOW_BUSINESS_IDENTITY_POLICY_CHANGED':'WORKFLOW_BUSINESS_IDENTITY_SCOPE_CHANGED'}});
  expect(checks).toBe(3);expect(f.native).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('denies ordinary private planner callbacks attempting SQL writes',async()=>{
  const f=fixture();f.install();f.plans.definition.mockImplementation(async(_cid:any,_wid:any,_kind:any,tx:any)=>{await tx.exec('UPDATE users SET status=$1',['disabled']);return f.plan.definition;});
  await expect(f.namespace(()=>f.observe())).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_SQL_READ_ONLY'}});expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('fails closed on identity recursion rather than invoking the full Namespace verifier',async()=>{
  const f=fixture();f.install();const original=f.plans.definition.getMockImplementation()!;
  f.plans.definition.mockImplementation(async(...args:any[])=>{await f.observe();return original(...args);});
  await expect(f.namespace(()=>f.observe())).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_IDENTITY_REENTRANT'}});expect(f.fullVerify).toHaveBeenCalledTimes(1);expect(f.native).not.toHaveBeenCalled();
 });
 it('rejects an inherited detached frame after the original namespace callback closes',async()=>{
  const f=fixture();f.install();let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});let detached!:Promise<unknown>;
  await f.namespace(async()=>{detached=(async()=>{await gate;return f.observe();})();});release();await expect(detached).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();
 });
});
