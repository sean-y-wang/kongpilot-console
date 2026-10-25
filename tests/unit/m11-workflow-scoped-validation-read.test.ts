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
import {entityForPath} from '../../apps/console-api/src/infrastructure/kong/policy';

/** Actual Validation service, crypto, and private read/request maps. SQL,
 * Namespace identities, and the SDK observation bridge are controlled fixtures;
 * this suite does not send HTTP, change real SQL, or mint Native permission. */
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
  registryRevision:1,last:null,domain:'scoped-points-v1',secondWid:randomUUID(),readScope:undefined,resources:[{clusterId:f.cid,workspaceId:f.wid,path:collection?'/services':`/services/${nativeId}`,kind:collection?'collection':'point',
   entityType:'services',...(collection?{query:{size:2}}:{entityId:nativeId}),secrets:false,required:true}]};
 const principalGrants=(userId:string)=>[{user_id:userId,cluster_id:f.cid,workspace_id:null,module:'services',action:'read',scope_type:'global',scope_values:[]},
    ...(values.secretGrant?[{user_id:userId,cluster_id:f.cid,workspace_id:null,module:'secrets',action:'read',scope_type:'global',scope_values:[]}]:[])];
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
  if(sql.includes('FROM workspaces'))return{id:args[0],cluster_id:args[1],revision:1,status:'active'};
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
 const business:any={resolveReadScope:vi.fn(async()=>({version:1,domain:values.domain,resources:values.resources,limits:{maxCalls:10,maxPages:5,maxRecords:values.maxRecords??10,maxBytes:8192}})),
  assertCurrent:vi.fn(async()=>{if(!values.read)throw new ForbiddenException({code:'ACTUAL_SUBJECT_READ_DENIED'});}),
  authorizeResponse:vi.fn(async(input:any)=>{if(values.scopeChanged)throw new ForbiddenException({code:'ACTUAL_OBJECT_SCOPE_CHANGED'});
   const items=input.resource.kind==='collection'?input.response.data:input.resource.kind==='schema'||input.status===404?[]:[input.response];
   for(const item of items){const target={clusterId:input.resource.clusterId,workspaceId:input.resource.workspaceId,entityType:input.resource.entityType,entity:item};
    if(!input.principal.grants.some((g:any)=>grantMatchesEntity(g,'services','read',target)))throw new ForbiddenException({code:'ACTUAL_OBJECT_READ_DENIED'});
    if(input.resource.secrets&&!input.principal.grants.some((g:any)=>grantMatchesEntity(g,'secrets','read',target)))throw new ForbiddenException({code:'ACTUAL_SECRET_READ_DENIED'});
   }} )};
 const runner:any={originalNamespaceProof:vi.fn((handle:object)=>{if(handle!==nsHandle||!values.live)throw new ForbiddenException({code:'ROOT_ORIGINAL_NS_REQUIRED'});return values.copy?{...ns}:ns;}),
  assertNamespaceLive:vi.fn((handle:object)=>{if(handle!==nsHandle||!values.live)throw new ForbiddenException({code:'ROOT_NS_NOT_LIVE'});}),
  run:vi.fn(async(handle:object,original:object,fn:any)=>{if(original!==nsHandle)throw Error('ROOT_ORIGINAL_NS_REQUIRED');values.last=handle;return fn();})};
 const observations=new WeakMap<object,{token:object,response:unknown,status:number}>();
 const observer={verifyOriginalResponse:vi.fn((token:object,original:object)=>{const value=observations.get(original);if(!value||value.token!==token)throw new ForbiddenException({code:'ORIGINAL_SDK_404_REQUIRED'});return value;})};
 const original404=(token:object,response:unknown={message:'Not found'},status=404)=>{const original=Object.freeze({});observations.set(original,{token,response,status});return{original,response};};
 const install=()=>{service.installAbsentResponseVerifier(observer as any);service.installStorageContract('a'.repeat(64));service.installBusinessPolicy(kind,business);service.installContextRunner(runner);};
 const packet=(query:any=collection?{size:2}:{},overrides:any={})=>({clusterId:f.cid,workspaceId:f.wid,method:'GET',path:values.resources[0].path,query,...overrides});
 const run=(fn:any,options?:any)=>service.runValidationRead(nsHandle,f.cid,values.resources.map((r:any)=>r.path),f.db,fn,options);
 const read=async(handle:object,response:any={id:nativeId,host:'controlled-unit'},query:any=collection?{size:2}:{})=>{
  const token=await service.authorizeRequest(handle,packet(query));await service.verifyRequest(token);return service.authorizeResponse(token,response);};
 const selectedRun=(resources:any[],fn:any,options?:any)=>service.runValidationResources(nsHandle,f.cid,resources[0].workspaceId,resources,f.db,fn,options);
 const packetFor=(resource:any)=>({clusterId:resource.clusterId,workspaceId:resource.workspaceId,method:'GET',path:resource.path,query:resource.query??{}});
 const actualRead=async(handle:object,resource:any,response:any)=>{const token=await service.authorizeRequest(handle,packetFor(resource));await service.verifyRequest(token);return service.authorizeResponse(token,response);};
 const actualAbsent=async(handle:object,resource:any)=>{const token=await service.authorizeRequest(handle,packetFor(resource));await service.verifyRequest(token);const observed=original404(token);return service.authorizeResponse(token,observed.response,observed.original);};
 return{...f,service,values,business,runner,install,packet,run,read,ns,nsHandle,nativeId,reseal,selectedRun,packetFor,actualRead,actualAbsent,original404,observer};
}

function parentChild(f:ReturnType<typeof fixture>,kind='key-auth',workspaceId=f.wid){
 const parentType=kind==='targets'?'upstreams':'consumers',parentId=randomUUID(),childId=randomUUID();
 const parent:any={clusterId:f.cid,workspaceId,path:`/${parentType}/${parentId}`,kind:'point',entityType:parentType,
  entityId:parentId,secrets:false,allowAbsent:true,required:true};
 const path=`/${parentType}/${parentId}/${kind}/${childId}`;
 const child:any={clusterId:f.cid,workspaceId,path,kind:'point',entityType:entityForPath(path),entityId:childId,parentId,
  secrets:kind!=='targets'&&kind!=='acls',allowAbsent:true,required:true};
 f.values.resources=[parent,child];
 const policy={assertChild:vi.fn(async(input:any,actualChild:any,actualParent:any)=>{
  expect(input.transaction).toBe(f.db);expect(input.principal.user.superAdmin).toBe(false);
  expect(actualChild).toEqual(child);expect(actualParent).toEqual(parent);
  if(f.values.childGrant===false)throw new ForbiddenException({code:'ACTUAL_CHILD_READ_WRITE_SECRET_DENIED'});
 })};
 return{parent,child,policy};
}
const code=(value:string)=>({response:{code:value}});
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

describe('M11 fixed scoped Validation resource selection',()=>{
 it('selects identical schema paths in two real workspace registries by the complete descriptor',async()=>{
  const f=fixture(),first:any={clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false,required:true};
  const second={...first,workspaceId:f.values.secondWid};f.values.resources=[first,second];f.install();
  await expect(f.run(async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID'));
  for(const selected of [first,second])await f.selectedRun([selected],async(handle:object)=>{
   const proof=await f.service.verifyHandle(handle,f.nsHandle,f.ns);
   expect(proof.scope.resources).toEqual([selected]);expect(proof.registries.map(r=>r.workspaceId)).toEqual([selected.workspaceId]);
   expect(proof.scope.domain).toBe('scoped-points-v1');expect(proof.actor.id).toBe(f.owner);expect(proof.sessionId).toBeNull();
   await f.actualRead(handle,selected,{fields:[{name:{type:'string'}}]});
  });
  expect(f.db.exec).not.toHaveBeenCalled();expect(f.approvals.verifyApprovalSet).not.toHaveBeenCalled();
 });

 it('requires every selector in a capsule to belong to its selected CID and WID',async()=>{
  const f=fixture(),resource=f.values.resources[0];f.install();
  await expect(f.service.runValidationResources(f.nsHandle,f.cid,randomUUID(),[resource],f.db,async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID'));
  await expect(f.service.runValidationResources(f.nsHandle,randomUUID(),f.wid,[resource],f.db,async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID'));
  expect(f.runner.run).not.toHaveBeenCalled();
 });

 it.each(['workspaceId','entityId','secrets','required','allowAbsent','parentId','query','kind','domain'])('rejects selector %s substitution before creating an original capsule',async field=>{
  const f=fixture(),resource=f.values.resources[0];f.install();
  const changed:any={...resource,[field]:['workspaceId','entityId','parentId'].includes(field)?randomUUID():field==='query'?{size:1}:field==='kind'?'schema':field==='domain'?'scoped-points-v1':field==='required'?false:true};
  await expect(f.selectedRun([changed],async()=>true)).rejects.toBeDefined();expect(f.runner.run).not.toHaveBeenCalled();
 });

 it('compares collection query HMA rather than authorizing only its path',async()=>{
  const f=fixture(true);f.values.resources[0].query={size:2,tags:'owner-pay'};f.install();
  await expect(f.selectedRun([{...f.values.resources[0],query:{size:2,tags:'owner-other'}}],async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN'));
 });

 it('copies selectors without turning the caller object into authoritative mutable material',async()=>{
  const f=fixture(),resource=f.values.resources[0],selected={...resource};f.install();
  await f.selectedRun([selected],async(handle:object)=>{
   selected.secrets=true;selected.workspaceId=randomUUID();
   expect((await f.service.verifyHandle(handle,f.nsHandle,f.ns)).scope.resources).toEqual([resource]);
   await f.actualRead(handle,resource,{id:resource.entityId,host:'controlled-only'});
  });
 });

 it('rechecks the complete current fixed selector before DNS when server material changes',async()=>{
  const f=fixture(),resource=f.values.resources[0];f.install();
  await expect(f.selectedRun([resource],async(handle:object)=>{
   const token=await f.service.authorizeRequest(handle,f.packetFor(resource));f.values.resources=[{...resource,secrets:true}];
   return f.service.verifyRequest(token);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN'));
  expect(f.business.authorizeResponse).not.toHaveBeenCalled();
 });

 it.each(['caller-scoped','full','SCOPED-POINTS-V1',true,{}])('accepts only the fixed literal domain, rejecting %j',async domain=>{
  const f=fixture();f.values.domain=domain;f.install();
  await expect(f.selectedRun(f.values.resources,async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID'));
 });

 it('keeps the existing domainless scope bound to the sealed source/anchor workspace',async()=>{
  const f=fixture();f.values.domain=undefined;f.values.resources[0].workspaceId=f.values.secondWid;f.install();
  await expect(f.selectedRun(f.values.resources,async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID'));
 });

 it('requires all selected point reads and leaves a caught denial poisoned',async()=>{
  const f=fixture(),first=f.values.resources[0],second={...first,entityId:randomUUID()};second.path=`/services/${second.entityId}`;
  f.values.resources=[first,second];f.install();
  await expect(f.selectedRun(f.values.resources,async(handle:object)=>f.actualRead(handle,first,{id:first.entityId}))).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE'));
  await expect(f.selectedRun(f.values.resources,async(handle:object)=>{
   try{await f.service.authorizeRequest(handle,{...f.packetFor(first),workspaceId:randomUUID()});}catch{}
   return true;
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_FAILED'));
 });

 it.each(['root-id','root-parent','nested-parent-id','nested-parent-name','nested-child-id','trailing-slash','repeated-slash'])('rejects noncanonical %s in the fixed scoped resource itself',async reason=>{
  const f=fixture(),{parent,child}=parentChild(f);
  if(reason==='root-id')parent.path=`/consumers/${randomUUID()}`;
  if(reason==='root-parent')parent.parentId=randomUUID();
  if(reason==='nested-parent-id')child.parentId=randomUUID();
  if(reason==='nested-parent-name')child.path=`/consumers/display-name/key-auth/${child.entityId}`;
  if(reason==='nested-child-id')child.path=`/consumers/${parent.entityId}/key-auth/${randomUUID()}`;
  if(reason==='trailing-slash')child.path+='/';
  if(reason==='repeated-slash')parent.path=parent.path.replace('/consumers/','/consumers//');
  f.install();await expect(f.selectedRun(f.values.resources,async()=>true)).rejects.toMatchObject(code(reason==='repeated-slash'?'INVALID_KONG_PATH':'WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID'));
  expect(f.runner.run).not.toHaveBeenCalled();
 });
});

describe('M11 genuine private point absence and future FK children',()=>{
 it('returns an opaque witness only after the original accepted SDK404 observation',async()=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;resource.required=true;f.install();let saved!:object,handle!:object;
  await f.selectedRun([resource],async(original:object)=>{
   handle=original;await f.actualAbsent(handle,resource);saved=await f.service.requireObservedAbsentPoint(handle,resource);
   expect(Object.isFrozen(saved)).toBe(true);expect(Object.keys(saved)).toEqual([]);
   expect((await f.service.verifyHandle(handle,f.nsHandle,f.ns)).readOnly).toBe(true);
  });
  await expect(f.service.requireObservedAbsentPoint(handle,resource)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_HANDLE_REQUIRED'));
  expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();
 });

 it.each(['never-read','pending','present200'])('cannot derive an absent witness from %s',async reason=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.install();
  await expect(f.selectedRun([resource],async(handle:object)=>{
   if(reason==='present200')await f.actualRead(handle,resource,{id:resource.entityId});
   if(reason==='pending')await f.service.authorizeRequest(handle,f.packetFor(resource));
   return f.service.requireObservedAbsentPoint(handle,resource);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_ABSENCE_REQUIRED'));
 });

 it.each([404,401,500,{status:404,response:{message:'Not found'}},'404'])('rejects caller-shaped status/observation %j',async observation=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.install();
  await expect(f.selectedRun([resource],async(handle:object)=>{
   const token=await f.service.authorizeRequest(handle,f.packetFor(resource));
   return f.service.authorizeResponse(token,{message:'Not found'},observation as any);
  })).rejects.toBeDefined();
 });

 it.each([401,403,500,502])('rejects even an original observer fact whose status is %i',async status=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.install();
  await expect(f.selectedRun([resource],async(handle:object)=>{
   const token=await f.service.authorizeRequest(handle,f.packetFor(resource)),observed=f.original404(token,{message:'Not found'},status);
   return f.service.authorizeResponse(token,observed.response,observed.original);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_OBSERVATION_REQUIRED'));
 });

 it('does not clear an unobserved timed-out GET merely because the caller caught an error',async()=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.install();
  await expect(f.selectedRun([resource],async(handle:object)=>{
   await f.service.authorizeRequest(handle,f.packetFor(resource));
   try{throw new Error('controlled timeout');}catch{}
   return true;
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE'));
 });

 it.each(['copied-proof','copied-response','wrong-request','malformed-body'])('rejects %s as a private SDK404 association',async reason=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.install();
  await expect(f.selectedRun([resource],async(handle:object)=>{
   const token=await f.service.authorizeRequest(handle,f.packetFor(resource)),observed=f.original404(reason==='wrong-request'?{}:token,
    reason==='malformed-body'?{message:'Not found',id:resource.entityId}:{message:'Not found'});
   return f.service.authorizeResponse(token,reason==='copied-response'?{...observed.response as any}:observed.response,
    reason==='copied-proof'?{...observed.original}:observed.original);
  })).rejects.toBeDefined();
 });

 it('preserves the old domainless EOF absence requirement',async()=>{
  const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.values.domain=undefined;f.install();
  await expect(f.selectedRun([resource],(handle:object)=>f.actualAbsent(handle,resource))).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_WITNESS_REQUIRED'));
 });

 it('installs the fixed child material policy exactly once',()=>{
  const f=fixture(),{policy}=parentChild(f);f.install();
  expect(()=>f.service.installParentAbsencePolicy({} as any)).toThrow();
  expect(()=>f.service.installParentAbsencePolicy({...policy,authority:'caller'} as any)).toThrow();
  f.service.installParentAbsencePolicy(policy);expect(()=>f.service.installParentAbsencePolicy(policy)).toThrow();
 });

 it.each(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls','targets'])('derives %s child absence from a genuine parent404 without fabricating another SDK response',async kind=>{
  const f=fixture(),{parent,child,policy}=parentChild(f,kind);f.install();f.service.installParentAbsencePolicy(policy);
  await f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const parentWitness=await f.service.requireObservedAbsentPoint(handle,parent);
   const childWitness=await f.service.observeFutureChildAbsence(handle,child,parentWitness);
   expect(childWitness).toEqual({kind:'parent-FK-absence',nativeRequestsSent:0});expect(Object.isFrozen(childWitness)).toBe(true);
  });
  expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
  expect(f.policy.assertReviewer).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(policy.assertChild).toHaveBeenCalledTimes(1);
 });

 it('calls the fixed child material policy as the actual selected reviewer with NULL SID',async()=>{
  const f=fixture(),{parent,child,policy}=parentChild(f),userId=f.approvalSet.reviewers[0].userId;f.install();f.service.installParentAbsencePolicy(policy);
  await f.selectedRun([parent,child],async(handle:object)=>{
   expect((await f.service.verifyHandle(handle,f.nsHandle,f.ns)).sessionId).toBeNull();
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   await f.service.observeFutureChildAbsence(handle,child,witness);
  },{role:'reviewer',userId});
  expect(policy.assertChild.mock.calls[0][0].principal.user.id).toBe(userId);
  expect(policy.assertChild.mock.calls[0][0].role).toBe('reviewer');
 });

 it.each(['missing-policy','copy','foreign-capsule','parent-id','descriptor','pending-child','already-read','read-revoked','expiry','grant-revoked'])('rejects %s before allowing child absence and poisons caught failures',async reason=>{
  const f=fixture(),{parent,child,policy}=parentChild(f);f.install();
  if(reason!=='missing-policy')f.service.installParentAbsencePolicy(policy);
  let previous!:object;
  if(reason==='foreign-capsule')await f.selectedRun([parent],async(handle:object)=>{await f.actualAbsent(handle,parent);previous=await f.service.requireObservedAbsentPoint(handle,parent);});
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);let witness=await f.service.requireObservedAbsentPoint(handle,parent),selected={...child};
   if(reason==='copy')witness={...witness};if(reason==='foreign-capsule')witness=previous;
   if(reason==='parent-id')selected.parentId=randomUUID();if(reason==='descriptor')selected.secrets=!selected.secrets;
   if(reason==='pending-child')await f.service.authorizeRequest(handle,f.packetFor(child));
   if(reason==='already-read')await f.service.observeFutureChildAbsence(handle,child,witness);
   if(reason==='read-revoked')f.values.read=false;if(reason==='grant-revoked')f.values.childGrant=false;
   if(reason==='expiry'){const proof=await f.service.verifyHandle(handle,f.nsHandle,f.ns);vi.advanceTimersByTime(Date.parse(proof.expiresAt)-Date.now()+1);}
   try{await f.service.observeFutureChildAbsence(handle,selected,witness);}catch{}
   return true;
  })).rejects.toBeDefined();
 });

 it('cannot use a genuine parent witness from another workspace or parent',async()=>{
  const f=fixture(),a=parentChild(f),b=parentChild(f,'key-auth',f.values.secondWid);f.values.resources=[a.parent,a.child,b.parent,b.child];f.install();f.service.installParentAbsencePolicy(a.policy);
  let first!:object;
  await f.selectedRun([a.parent],async(handle:object)=>{await f.actualAbsent(handle,a.parent);first=await f.service.requireObservedAbsentPoint(handle,a.parent);});
  await expect(f.selectedRun([b.parent,b.child],async(handle:object)=>{
   await f.actualAbsent(handle,b.parent);return f.service.observeFutureChildAbsence(handle,b.child,first);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
  expect(a.policy.assertChild).not.toHaveBeenCalled();
 });

 it('requires current child READ/write/secret approval at the inference boundary',async()=>{
  const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);f.values.childGrant=false;
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   return f.service.observeFutureChildAbsence(handle,child,witness);
  })).rejects.toMatchObject(code('ACTUAL_CHILD_READ_WRITE_SECRET_DENIED'));
  expect(policy.assertChild).toHaveBeenCalledTimes(1);expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
 });

 it('requires the exact original parent even when two absent parents share one capsule',async()=>{
  const f=fixture(),a=parentChild(f),b=parentChild(f);f.values.resources=[a.parent,a.child,b.parent,b.child];f.install();f.service.installParentAbsencePolicy(a.policy);
  await expect(f.selectedRun(f.values.resources,async(handle:object)=>{
   await f.actualAbsent(handle,a.parent);await f.actualAbsent(handle,b.parent);
   const wrong=await f.service.requireObservedAbsentPoint(handle,b.parent);
   return f.service.observeFutureChildAbsence(handle,a.child,wrong);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
  expect(a.policy.assertChild).not.toHaveBeenCalled();
 });

 it('rejects a different-workspace parent within the same genuine original capsule',async()=>{
  const f=fixture(),a=parentChild(f),b=parentChild(f,'key-auth',f.values.secondWid);f.values.resources=[a.parent,a.child,b.parent,b.child];f.install();f.service.installParentAbsencePolicy(a.policy);
  await expect(f.run(async(handle:object)=>{
   await f.actualAbsent(handle,a.parent);await f.actualAbsent(handle,b.parent);
   const wrong=await f.service.requireObservedAbsentPoint(handle,b.parent);
   return f.service.observeFutureChildAbsence(handle,a.child,wrong);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
  expect(a.policy.assertChild).not.toHaveBeenCalled();
 });

 it('does not infer arbitrary relation absence from an absent parent',async()=>{
  const f=fixture(),parent=f.values.resources[0],routeId=randomUUID();parent.allowAbsent=true;parent.required=true;
  const child:any={clusterId:f.cid,workspaceId:f.wid,path:`/routes/${routeId}`,entityType:'routes',entityId:routeId,parentId:parent.entityId,
   kind:'point',secrets:false,allowAbsent:true,required:true};f.values.resources=[parent,child];f.install();const policy={assertChild:vi.fn(async()=>undefined)};f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   return f.service.observeFutureChildAbsence(handle,child,witness);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID'));
  expect(policy.assertChild).not.toHaveBeenCalled();
 });

 it.each(['iam','registry','lease','votes','reviewer-epoch','namespace'])('rechecks current %s before the child proof callback',async reason=>{
  const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   if(reason==='iam')f.state.principalVersion='2';if(reason==='registry')f.values.registryRevision=2;if(reason==='lease')f.state.lease=false;
   if(reason==='votes')f.values.votes.pop();if(reason==='reviewer-epoch')f.values.reviewerEpoch='2';if(reason==='namespace')f.values.live=false;
   return f.service.observeFutureChildAbsence(handle,child,witness);
  })).rejects.toBeDefined();
  expect(policy.assertChild).not.toHaveBeenCalled();
 });

 it('does not permit a copied original handle or changed descriptor after a real accepted404',async()=>{
  for(const reason of ['handle','descriptor']){
   const f=fixture(),resource=f.values.resources[0];resource.allowAbsent=true;f.install();
   await expect(f.selectedRun([resource],async(handle:object)=>{
    await f.actualAbsent(handle,resource);
    return f.service.requireObservedAbsentPoint(reason==='handle'?{...handle}:handle,reason==='descriptor'?{...resource,secrets:!resource.secrets}:resource);
   })).rejects.toBeDefined();
  }
 });

 it('charges semantically inferred children to the original shared record budget',async()=>{
  const f=fixture(),{parent,child}=parentChild(f),secondId=randomUUID(),second={...child,entityId:secondId,path:child.path.slice(0,child.path.lastIndexOf('/')+1)+secondId};
  f.values.resources=[parent,child,second];f.values.maxRecords=1;f.install();const policy={assertChild:vi.fn(async()=>undefined)};f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun(f.values.resources,async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   await f.service.observeFutureChildAbsence(handle,child,witness);
   return f.service.observeFutureChildAbsence(handle,second,witness);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_BUDGET'));
  expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
 });

 it('cannot reissue a parent-FK absence as an original SDK404 witness',async()=>{
  const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   const derived=await f.service.observeFutureChildAbsence(handle,child,witness);
   expect(derived).toEqual({kind:'parent-FK-absence',nativeRequestsSent:0});
   return f.service.requireObservedAbsentPoint(handle,child);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_ABSENCE_REQUIRED'));
  expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
 });

 it('rejects nested SDK404 under an absent parent and requires the separate logical FK proof',async()=>{
  const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);return f.actualAbsent(handle,child);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_WITNESS_REQUIRED'));
  expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(2);expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
  expect(policy.assertChild).not.toHaveBeenCalled();
 });

 it.each(['parent-false','parent-omitted','child-false','child-omitted'])('requires explicitly required:true for %s witnesses',async reason=>{
  const f=fixture(),{parent,child,policy}=parentChild(f),selected=reason.startsWith('parent')?parent:child;
  if(reason.endsWith('false'))selected.required=false;else delete selected.required;
  f.install();f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const original=await f.service.requireObservedAbsentPoint(handle,parent);
   return f.service.observeFutureChildAbsence(handle,child,original);
  })).rejects.toMatchObject(code(reason.startsWith('parent')?'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_ABSENCE_REQUIRED':'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
  expect(policy.assertChild).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });

 it('rechecks a genuine pending GET opened while the fixed child policy is awaiting',async()=>{
  const f=fixture(),{parent,child}=parentChild(f);f.install();
  let release!:()=>void,entered!:()=>void;
  const suspended=new Promise<void>(resolve=>{release=resolve;}),policyEntered=new Promise<void>(resolve=>{entered=resolve;});
  const policy={assertChild:vi.fn(async()=>{entered();await suspended;})};f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   const deriving=f.service.observeFutureChildAbsence(handle,child,witness);await policyEntered;
   try{await f.service.authorizeRequest(handle,f.packetFor(parent));}finally{release();}
   return deriving;
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
  expect(policy.assertChild).toHaveBeenCalledTimes(1);expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
  expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();
 });

 it('allows at most one concurrently awaited child inference and poisons the capsule on the duplicate',async()=>{
  const f=fixture(),{parent,child}=parentChild(f);f.install();
  let release!:()=>void,bothEntered!:()=>void,entered=0;
  const suspended=new Promise<void>(resolve=>{release=resolve;}),policiesEntered=new Promise<void>(resolve=>{bothEntered=resolve;});
  const policy={assertChild:vi.fn(async()=>{if(++entered===2)bothEntered();await suspended;})};f.service.installParentAbsencePolicy(policy);
  await expect(f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
   const first=f.service.observeFutureChildAbsence(handle,child,witness),second=f.service.observeFutureChildAbsence(handle,child,witness);
   const settled=Promise.allSettled([first,second]);await policiesEntered;release();
   const results=await settled,accepted=results.filter(result=>result.status==='fulfilled'),denied=results.filter(result=>result.status==='rejected');
   expect(accepted).toHaveLength(1);expect(denied).toHaveLength(1);
   expect((accepted[0] as PromiseFulfilledResult<object>).value).toEqual({kind:'parent-FK-absence',nativeRequestsSent:0});
   expect((denied[0] as PromiseRejectedResult).reason).toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
   return true;
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_FAILED'));
  expect(policy.assertChild).toHaveBeenCalledTimes(2);expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
  expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();
 });

 it('allows an actual existing parent200 followed by an original child404 without logical inference',async()=>{
  const f=fixture(),{parent,child}=parentChild(f);f.install();
  await f.selectedRun([parent,child],async(handle:object)=>{
   await f.actualRead(handle,parent,{id:parent.entityId,tags:['owner-pay']});await f.actualAbsent(handle,child);
   const witness=await f.service.requireObservedAbsentPoint(handle,child);
   expect(witness).toEqual({});expect(Object.isFrozen(witness)).toBe(true);expect(Object.hasOwn(witness,'kind')).toBe(false);
  });
  expect(f.business.authorizeResponse.mock.calls.map(([input])=>input.status)).toEqual([200,404]);expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
 });
});
