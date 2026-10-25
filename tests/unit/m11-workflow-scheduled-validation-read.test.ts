import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {workflowScheduledFixture} from './helpers/workflow-scheduled-fixture';
import {WorkflowCandidatesService} from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import {WorkflowScheduledValidationReadService,WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL} from '../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.service';
import {workflowSchedulePlanSeal} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {grantMatchesEntity} from '../../apps/console-api/src/modules/authorization/grant-policy';

/** Real provider/crypto/current-grant predicates with controlled SQL and Root
 * identity. These tests send no HTTP/SQL, create no Native authority, and are
 * deliberately not evidence of an actual runtime SQL026 acceptance. */
function fixture(collection=false,kind:'configuration_v2'|'portal-credential-issue'='configuration_v2'){
 const f=workflowScheduledFixture(kind),nativeId=randomUUID(),h=(value:unknown)=>f.secrets.fingerprint(value);
 const policy:any={version:2,kind,allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:1,
  stages:f.approvalSet.reviewers.map((reviewer:any)=>({level:reviewer.level,name:`level-${reviewer.level}`,mode:'any',threshold:1,selector:{users:[reviewer.userId]}}))};
 f.plan.definition.policyHash=h(policy);f.draft.binding.policyHash=h(policy);f.draft.delegation.policyHash=h(policy);
 const reseal=()=>{const{scheduling,...base}=f.plan;f.draft.binding.basePlanHash=h(base);f.draft.delegation.basePlanHash=h(base);
  f.draft.delegationHmac=h(f.draft.delegation);f.plan.scheduling=workflowSchedulePlanSeal(f.draft);f.draft.binding.workflowPlanHash=h(f.plan);};reseal();
 const candidates=f.approvalSet.reviewers.map((r:any)=>({level:r.level,mode:'any',threshold:1,candidates:[{userId:r.userId,credentialEpoch:'1',provenance:[{kind:'user',selectorId:r.userId}]}]}));
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
 const values:any={live:true,copy:false,read:true,secretGrant:true,secretResource:false,scopeChanged:false,invalidated:false,reviewerEpoch:'1',votes,stages,row,
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
   return user&&epoch?{...user,iam_version:epoch.version,grants}:null;
  }
  if(sql.includes('FROM workflow_definition_versions'))return{approval_format:2,policy,policy_hash:h(policy),allow_self_approval:false};
  if(sql.includes('FROM workflow_candidate_versions'))return{manifest,manifest_hmac:candidateHmac};
  if(sql.includes('FROM workflow_approval_sets'))return{id:f.approvalSet.setId,set_hmac:f.approvalSet.setHmac,manifest:approvalMaterial};
  if(sql.includes('FROM workflow_approval_invalidations'))return values.invalidated?{id:randomUUID()}:null;
  if(sql.includes('FROM workflow_versions'))return{...row};
  if(sql.includes('FROM workflows'))return values.row;
  if(sql.includes('SELECT status,deleted_at,force_password_change,credential_epoch FROM users'))return f.state.reviewerActive?{status:'active',deleted_at:null,force_password_change:false,credential_epoch:values.reviewerEpoch}:null;
  const result=await originalOne(sql,args);if(sql.includes('FROM clusters')&&result)result.revision=values.registryRevision;return result;
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
 const service=new WorkflowScheduledValidationReadService(f.db,f.secrets,f.redis,f.plans,f.repository,new WorkflowCandidatesService(f.db));
 const business:any={resolveReadScope:vi.fn(async()=>({version:1,resources:values.resources,limits:{maxCalls:10,maxPages:5,maxRecords:10,maxBytes:8192}})),
  assertCurrent:vi.fn(async()=>{if(!values.read)throw new ForbiddenException({code:'ACTUAL_SUBJECT_READ_DENIED'});}),
  authorizeResponse:vi.fn(async(input:any)=>{if(values.scopeChanged)throw new ForbiddenException({code:'ACTUAL_OBJECT_SCOPE_CHANGED'});
   const items=input.resource.kind==='collection'?input.response.data:input.resource.kind==='schema'?[]:[input.response];
   for(const item of items){const target={clusterId:input.resource.clusterId,workspaceId:input.resource.workspaceId,entityType:'services',entity:item};
    if(!input.principal.grants.some((g:any)=>grantMatchesEntity(g,'services','read',target)))throw new ForbiddenException({code:'ACTUAL_OBJECT_READ_DENIED'});
    if(input.resource.secrets&&!input.principal.grants.some((g:any)=>grantMatchesEntity(g,'secrets','read',target)))throw new ForbiddenException({code:'ACTUAL_SECRET_READ_DENIED'});
   }} )};
 const runner:any={originalNamespaceProof:vi.fn((handle:object)=>{if(handle!==nsHandle||!values.live)throw new ForbiddenException({code:'ROOT_ORIGINAL_NS_REQUIRED'});return values.copy?{...ns}:ns;}),
  assertNamespaceLive:vi.fn((handle:object)=>{if(handle!==nsHandle||!values.live)throw new ForbiddenException({code:'ROOT_NS_NOT_LIVE'});}),
  run:vi.fn(async(handle:object,original:object,fn:any)=>{if(original!==nsHandle)throw Error('ROOT_ORIGINAL_NS_REQUIRED');values.last=handle;return fn();})};
 const install=()=>{service.installStorageContract('a'.repeat(64));service.installBusinessPolicy(kind,business);service.installContextRunner(runner);};
 const packet=(query:any=collection?{size:2}:{},overrides:any={})=>({clusterId:f.cid,workspaceId:f.wid,method:'GET',path:values.resources[0].path,query,...overrides});
 const run=(fn:any,options?:any)=>service.runValidationRead(nsHandle,f.cid,values.resources.map((r:any)=>r.path),f.db,fn,options);
 const read=async(handle:object,response:any={id:nativeId,host:'controlled-unit'},query:any=collection?{size:2}:{})=>{
  const token=await service.authorizeRequest(handle,packet(query));await service.verifyRequest(token);return service.authorizeResponse(token,response);};
 return{...f,service,values,business,runner,install,packet,run,read,ns,nsHandle,nativeId,reseal};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});
describe('M11 current SQL validation READ inside original business Namespace',()=>{
 it('defaults closed and installs all Root adapters once',async()=>{
  const f=fixture();await expect(f.run(async()=>true)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_CONTEXT_UNAVAILABLE'}});
  expect(()=>f.service.installContextRunner({run:f.runner.run} as any)).toThrow();f.install();expect(()=>f.install()).toThrow();
 });
 it('preserves original Namespace identity and current SQL actor/NULL SID while never calling full Authority',async()=>{
  const f=fixture();f.install();await f.run(async(handle:object)=>{const proof=await f.service.verifyHandle(handle,f.nsHandle,f.ns);
   expect(proof.namespace).toBe(f.ns);expect(proof.actor.id).toBe(f.owner);expect(proof.sessionId).toBeNull();expect(proof.readOnly).toBe(true);await f.read(handle);
  });expect(f.approvals.verifyApprovalSet).not.toHaveBeenCalled();expect(f.policy.assertReviewer).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  await expect(f.service.verifyHandle(f.values.last,f.nsHandle,f.ns)).rejects.toBeDefined();
 });
 it('requires genuine Namespace and handle/proof identities rather than matching copies',async()=>{
  const f=fixture();f.install();await expect(f.service.runValidationRead({...f.nsHandle},f.cid,[f.packet().path],f.db,async()=>true)).rejects.toBeDefined();
  await expect(f.run(async(handle:object)=>{await expect(f.service.verifyHandle({...handle},f.nsHandle,f.ns)).rejects.toBeDefined();
   await expect(f.service.verifyHandle(handle,f.nsHandle,{...f.ns})).rejects.toBeDefined();return true;})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_READ_FAILED'}});
 });
 it('uses the selected actual reviewer instead of lending the executor READ grant',async()=>{
  const f=fixture();f.install();const id=f.approvalSet.reviewers[0].userId;await f.run(async(handle:object)=>{
   expect((await f.service.verifyHandle(handle,f.nsHandle,f.ns)).actor.id).toBe(id);await f.read(handle);
  },{role:'reviewer',userId:id});expect(f.business.authorizeResponse.mock.calls[0][0].principal.user.id).toBe(id);
  await expect(f.run(async()=>true,{role:'reviewer',userId:randomUUID()})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_PRINCIPAL_REQUIRED'}});
 });
 it.each(['POST','PATCH','PUT','DELETE'])('rejects %s and poisons caught failures',async method=>{
  const f=fixture();f.install();await expect(f.run(async(handle:object)=>{await expect(f.service.authorizeRequest(handle,f.packet({}, {method,body:{approved:true}}))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_GET_ONLY'}});return true;})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_READ_FAILED'}});
 });
 it.each(['lease','owner-epoch','reviewer-epoch','password','requester','iam','registry','claim','progress','expiry','copy','read','votes','approval-set'])('rechecks %s before actual DNS/response',async reason=>{
  const f=fixture(false,reason==='requester'?'portal-credential-issue':'configuration_v2');f.install();await expect(f.run(async(handle:object)=>{
   const token=await f.service.authorizeRequest(handle,f.packet());
   if(reason==='lease')f.state.lease=false;else if(reason==='owner-epoch')f.state.epoch='2';else if(reason==='reviewer-epoch')f.values.reviewerEpoch='2';
   else if(reason==='password')f.state.forceChange=true;else if(reason==='requester')f.state.forceRequesterChange=true;else if(reason==='iam')f.state.principalVersion='2';
   else if(reason==='registry')f.values.registryRevision=2;else if(reason==='claim')f.state.stored.claim.workerOwnerHmac='0'.repeat(64);
   else if(reason==='progress')f.state.stored.progress.state='uncertain';else if(reason==='expiry'){
    const proof=await f.service.verifyHandle(handle,f.nsHandle,f.ns);vi.advanceTimersByTime(Date.parse(proof.expiresAt)-Date.now()+1);
   }else if(reason==='copy')f.values.copy=true;
   else if(reason==='read')f.values.read=false;else if(reason==='votes')f.values.votes.pop();else f.values.invalidated=true;
   await f.service.verifyRequest(token);return f.service.authorizeResponse(token,{id:f.nativeId});
  })).rejects.toBeDefined();expect(f.business.authorizeResponse).not.toHaveBeenCalled();
 });
 it('bounds server-selected paths to the fixed scope and rejects body/query/cursor substitution',async()=>{
  const f=fixture();f.install();await expect(f.service.runValidationRead(f.nsHandle,f.cid,['/services/'+randomUUID()],f.db,async()=>true)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN'}});
  for(const change of [{clusterId:randomUUID()},{workspaceId:randomUUID()},{path:'/consumers/'+randomUUID()},{query:{offset:'chosen'}},{body:{x:1}}])
   await expect(f.run(async(handle:object)=>{try{await f.service.authorizeRequest(handle,f.packet({},change));}catch{}return true;})).rejects.toBeDefined();
 });
 it('checks exact every-row scope and secret READ before releasing actual private material',async()=>{
  const f=fixture();f.values.resources[0].secrets=true;f.install();await expect(f.run(async(handle:object)=>{const token=await f.service.authorizeRequest(handle,f.packet());
   f.values.scopeChanged=true;return f.service.authorizeResponse(token,{id:f.nativeId,key:'synthetic-private'});})).rejects.toMatchObject({response:{code:'ACTUAL_OBJECT_SCOPE_CHANGED'}});
  const g=fixture();g.values.resources[0].secrets=true;g.values.secretGrant=false;g.install();await expect(g.run((handle:object)=>g.read(handle,{id:g.nativeId,key:'synthetic-private'}))).rejects.toMatchObject({response:{code:'ACTUAL_SECRET_READ_DENIED'}});
 });
 it('rejects credentials mislabeled as a non-secret resource',async()=>{
  const f=fixture();f.install();await expect(f.run((handle:object)=>f.read(handle,{id:f.nativeId,config:{password:'synthetic-only'}}))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_SECRET_SCOPE_REQUIRED'}});
 });
 it('requires genuine complete EOF and does not reallocate cursor during repeated DNS verification',async()=>{
  const f=fixture(true);f.install();await f.run(async(handle:object)=>{const token=await f.service.authorizeRequest(handle,f.packet());
   await f.service.verifyRequest(token);await f.service.verifyRequest(token);await f.service.authorizeResponse(token,{data:[{id:f.nativeId}],next:'/services?size=2&offset=next'});
   await f.read(handle,{data:[{id:randomUUID()}],next:null},{size:2,offset:'next'});
  });
 });
 it.each(['omitted','undefined','duplicate','foreign','loop','unfinished','no-read'])('rejects %s EOF without shrinking the declared collection',async reason=>{
  const f=fixture(true);f.install();await expect(f.run(async(handle:object)=>{
   if(reason==='no-read')return true;
   if(reason==='omitted')return f.read(handle,{data:[]});if(reason==='undefined')return f.read(handle,{data:[],next:undefined});
   if(reason==='duplicate')return f.read(handle,{data:[{id:f.nativeId},{id:f.nativeId}],next:null});
   if(reason==='foreign')return f.read(handle,{data:[],next:'http://foreign:8001/services?offset=evil'});
   await f.read(handle,{data:[{id:f.nativeId}],next:'/services?offset=second'});
   if(reason==='unfinished')return true;
   return f.read(handle,{data:[],next:'/services?offset=second'},{size:2,offset:'second'});
  })).rejects.toBeDefined();
 });
 it('poisons a denied final EOF even when business code catches and returns the first page',async()=>{
  const f=fixture(true);f.install();await expect(f.run(async(handle:object)=>{const first=await f.read(handle,{data:[{id:f.nativeId}],next:'/services?offset=last'});
   f.values.scopeChanged=true;try{await f.read(handle,{data:[],next:null},{size:2,offset:'last'});}catch{}f.values.scopeChanged=false;return first;
  })).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_READ_FAILED'}});
 });
 it('requires exact applied SQL026 and fences detached/original request reuse',async()=>{
  const f=fixture();f.install();f.state.migration=false;await expect(f.run(async()=>true)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_VALIDATION_STORAGE_UNAVAILABLE'}});
  const g=fixture();g.install();let token!:object;await g.run(async(handle:object)=>{token=await g.service.authorizeRequest(handle,g.packet());await g.service.authorizeResponse(token,{id:g.nativeId});});
  await expect(g.service.verifyRequest(token)).rejects.toBeDefined();await expect(g.service.authorizeResponse({...token},{id:g.nativeId})).rejects.toBeDefined();
 });
});
