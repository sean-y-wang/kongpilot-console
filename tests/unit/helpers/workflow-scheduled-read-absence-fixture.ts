import {vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {workflowScheduledFixture} from './workflow-scheduled-fixture';
import {WorkflowCandidatesService} from '../../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import {WorkflowScheduleCandidateReadService} from '../../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import {WorkflowScheduledValidationReadService,WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.service';
import {workflowSchedulePlanSeal} from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import {immutableJson} from '../../../apps/console-api/src/infrastructure/kong/immutable-json';
import {grantMatchesEntity} from '../../../apps/console-api/src/modules/authorization/grant-policy';
/** Controlled SQL/crypto fixtures for Source-only GET404 observation tests.
 * No live PostgreSQL, actual approvals, Native authority or runtime proof. */
export function candidateAbsenceFixture(collection = false, kind: 'configuration_v2' | 'portal-credential-issue' = 'configuration_v2') {
  const f = workflowScheduledFixture(kind), nativeId = randomUUID(), reviewer = f.approvalSet.reviewers[0].userId;
  const policyBody: any = { version: 1, mode: 'single', allowSelfApproval: false, kind };
  f.plan.definition.policyHash = f.secrets.fingerprint(policyBody); f.draft.binding.policyHash = f.plan.definition.policyHash;
  f.draft.delegation.policyHash = f.plan.definition.policyHash;
  const reseal = () => { const { scheduling, ...base } = f.plan;
    f.draft.binding.basePlanHash = f.secrets.fingerprint(base); f.draft.delegation.basePlanHash = f.draft.binding.basePlanHash;
    f.draft.delegationHmac = f.secrets.fingerprint(f.draft.delegation); f.plan.scheduling = workflowSchedulePlanSeal(f.draft);
    f.draft.binding.workflowPlanHash = f.secrets.fingerprint(f.plan); };
  reseal(); f.state.workflowState = 'pending';
  const values: any = { read: true, secrets: true, secretResource: false, definition: policyBody, selectorVersion: 1, frozen: null, scopeChanged: false,
    badScope: false, last: null, counter: 0, resources: [{ clusterId: f.cid, workspaceId: f.wid, path: collection ? '/services' : `/services/${nativeId}`,
      kind: collection ? 'collection' : 'point', entityType: 'services', ...(collection ? { query: { size: 2 } } : { entityId: nativeId }), secrets: false }] };
  const baseOne = f.db.one.getMockImplementation()!, baseQuery = f.db.query.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, args: any[]) => {
    if (sql.includes('FROM workflow_definition_versions')) return { approval_format: values.selectorVersion, policy: values.definition, policy_hash: f.plan.definition.policyHash, mode: 'single', allow_self_approval: false };
    if (sql.includes('FROM workflow_candidate_versions')) return values.frozen;
    if (sql.includes('SELECT status,deleted_at,force_password_change,credential_epoch FROM users')) return f.state.ownerActive && !f.state.forceChange
      ? { status: 'active', deleted_at: null, force_password_change: false, credential_epoch: f.state.epoch } : null;
    return baseOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[]) => {
    if (sql.includes('iam_effective_grants')) return [{ user_id: args[0], cluster_id: f.cid, workspace_id: f.wid, module: 'services', action: 'read', scope_type: 'global', scope_values: [] },
      ...(values.secrets ? [{ user_id: args[0], cluster_id: f.cid, workspace_id: f.wid, module: 'secrets', action: 'read', scope_type: 'global', scope_values: [] }] : [])];
    return baseQuery(sql, args);
  });
  const policies: any = { resolveReadScope: vi.fn(async () => ({ version: 1, resources: values.resources,
    limits: { maxCalls: 10, maxPages: 5, maxRecords: 10, maxBytes: 8192 } })),
    assertCurrent: vi.fn(async () => { if (!values.read) throw new ForbiddenException({ code: 'ACTUAL_BUSINESS_READ_DENIED' }); }),
    authorizeResponse: vi.fn(async (input: any) => {
      if (values.scopeChanged) throw new ForbiddenException({ code: 'ACTUAL_OBJECT_SCOPE_CHANGED' });
      const items = input.resource.kind === 'collection' ? input.response.data : input.resource.kind === 'schema' || input.status === 404 ? [] : [input.response];
      for (const item of items) {
        const target = { clusterId: input.resource.clusterId, workspaceId: input.resource.workspaceId, entityType: 'services', entity: item };
        if (!input.principal.grants.some((g: any) => grantMatchesEntity(g, 'services', 'read', target))) throw new ForbiddenException({ code: 'ACTUAL_ENTITY_READ_DENIED' });
        if (input.resource.secrets && !input.principal.grants.some((g: any) => grantMatchesEntity(g, 'secrets', 'read', target))) throw new ForbiddenException({ code: 'ACTUAL_SECRET_READ_DENIED' });
      }
    }) };
  const service = new WorkflowScheduleCandidateReadService(f.db, f.secrets, f.context, f.plans, f.repository, new WorkflowCandidatesService(f.db));
  const runner: any = { assertNoFrame: vi.fn(() => { if (f.state.frame !== null) throw new ForbiddenException({ code: 'ACTUAL_EMPTY_CONTEXT_REQUIRED' }); }),
    run: vi.fn(async (handle: object, fn: any) => { runner.assertNoFrame(); values.last = handle; f.state.frame = { originalCandidateRead: handle };
      try { return await fn(); } finally { f.state.frame = null; } }) };
  const install = () => { service.installStorageContract('a'.repeat(64)); service.installBusinessPolicy(kind, policies); service.installContextRunner(runner); };
  const packet = (query: any = collection ? { size: 2 } : {}, overrides: any = {}) => ({ clusterId: f.cid, workspaceId: f.wid, method: 'GET', path: values.resources[0].path, query, ...overrides });
  const read = async (handle: object, raw: any = { id: nativeId, host: 'actual-controlled-read' }, query: any = collection ? { size: 2 } : {}, status = 200) => {
    const token = await service.authorizeRequest(handle, packet(query)); await service.verifyRequest(token); return service.authorizeResponse(token, raw, status);
  };
  return { ...f, service, values, policies, runner, install, nativeId, reviewer, reseal, packet, read };
}
export function validationAbsenceFixture(collection=false,kind:'configuration_v2'|'portal-credential-issue'='configuration_v2'){
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
