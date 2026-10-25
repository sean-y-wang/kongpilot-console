import {randomUUID} from 'node:crypto';
import {vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {workflowScheduledFixture} from './workflow-scheduled-fixture';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {immutableJson} from '../../../apps/console-api/src/infrastructure/kong/immutable-json';
import {WorkflowBusinessRuntimeService} from '../../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import {WorkflowBusinessCurrentIdentityService,WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256} from '../../../apps/console-api/src/modules/workflows/workflow-business-current-identity.service';
import {WorkflowCandidatesService} from '../../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import {workflowSchedulePlanSeal} from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

type Options={layout?:'single'|'multi'|'all'|'quorum';selection?:'user'|'team'|'role';frozenThreshold?:number;duplicateReviewer?:boolean};

/** Controlled SQL, actual Root/identity/candidate code, and the real Context's
 * private Namespace associations. No server, worker, HTTP or Native transport. */
export function m11LedgerIdentityFixture(options:Options={}){
 const f=workflowScheduledFixture('configuration_v2'),h=(value:unknown)=>f.secrets.fingerprint(value);
 const layout=options.layout??'multi',selection=options.selection??'user';
 const levels=layout==='multi'?3:1,mode=layout==='all'?'all':layout==='quorum'?'quorum':'any';
 const candidateCount=mode==='any'?1:3,threshold=options.frozenThreshold??(mode==='any'?1:mode==='all'?3:2);
 const groups=Array.from({length:levels},(_,i)=>({level:i+1,selectorId:randomUUID(),
  userIds:Array.from({length:candidateCount},()=>randomUUID()).sort()}));
 if(options.duplicateReviewer&&groups.length>1)groups[1].userIds[0]=groups[0].userIds[0];
 const policy:any={version:2,kind:'configuration_v2',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:1,
  stages:groups.map(g=>({level:g.level,name:`stage-${g.level}`,mode,threshold:mode==='all'?null:mode==='quorum'?2:1,
   selector:selection==='user'?{users:g.userIds}:selection==='team'?{teams:[g.selectorId]}:{roles:[g.selectorId]}}))};
 f.plan.definition.policyHash=h(policy);f.draft.binding.policyHash=h(policy);f.draft.delegation.policyHash=h(policy);
 const {scheduling:_old,...base}=f.plan;
 f.draft.binding.basePlanHash=h(base);f.draft.delegation.basePlanHash=h(base);f.draft.delegationHmac=h(f.draft.delegation);
 f.plan.scheduling=workflowSchedulePlanSeal(f.draft);f.draft.binding.workflowPlanHash=h(f.plan);
 const candidateStages=groups.map(g=>({level:g.level,mode,threshold,candidates:g.userIds.map(userId=>({userId,credentialEpoch:'1',
  provenance:[selection==='role'?{kind:'role',selectorId:g.selectorId,bindingId:randomUUID(),bindingSource:'user'}:
   {kind:selection,selectorId:selection==='user'?userId:g.selectorId}]}))}));
 f.approvalSet.reviewers=groups.flatMap(g=>g.userIds.slice(0,threshold).map(userId=>({approvalId:randomUUID(),userId,level:g.level,candidateVersion:1})));
 const manifest:any={version:1,clusterId:f.cid,workspaceId:f.wid,workflowId:f.plan.workflowId,planRevision:1,planHash:h(f.plan),
  definitionId:f.plan.definition.id,definitionVersion:1,policyHash:h(policy),candidateVersion:1,stages:candidateStages};
 const candidateHmac=h(manifest),approvalMaterial={version:1,clusterId:f.cid,workspaceId:f.wid,workflowId:f.plan.workflowId,planRevision:1,
  planHash:h(f.plan),policyHash:h(policy),candidateVersion:1,candidateManifestHmac:candidateHmac,reviewers:f.approvalSet.reviewers};
 f.approvalSet.policyHash=h(policy);f.approvalSet.setHmac=h(approvalMaterial);
 const claim:any={id:randomUUID(),scheduleId:f.scheduleId,scheduleVersion:1,occurrenceId:f.draft.occurrenceId,generation:1,
  workerOwnerHmac:h('controlled-ledger-worker'),workflowId:f.plan.workflowId,workflowPlanRevision:1,workflowPlanHash:h(f.plan),
  issuedAt:new Date(Date.now()-100).toISOString(),authorityExpiresAt:f.plan.expiresAt,initialLeaseUntil:new Date(Date.now()+90000).toISOString()};
 f.state.stored.claim=claim;f.state.stored.latestLease={id:randomUUID(),claimId:claim.id,generation:1,workerOwnerHmac:claim.workerOwnerHmac,
  version:1,previousId:null,leaseUntil:claim.initialLeaseUntil};
 f.state.stored.progress={state:'claimed',revision:3,claimId:claim.id,reasonCode:null};
 f.state.stored.activation={workflowId:f.plan.workflowId,workflowPlanRevision:1,workflowPlanHash:h(f.plan),approvalFormat:2,approvalRequired:true,
  approvalSetId:f.approvalSet.setId,approvalSetHmac:f.approvalSet.setHmac};f.state.lease=true;
 const nsHandle=Object.freeze({}),ns:any=immutableJson({version:1,origin:'scheduled-workflow',sessionId:null,kind:'configuration_v2',
  actor:{id:f.owner,username:'actual-sql-principal',superAdmin:false,forcePasswordChange:false},clusterId:f.cid,workspaceId:f.wid,
  transportScope:f.draft.transportScope,clusterRevision:1,workspaceRevision:1,permissionVersion:`${f.owner}:1:1`,credentialEpoch:'1',
  expiresAt:claim.initialLeaseUntil,claim:{...claim,clusterId:f.cid,workspaceId:f.wid,ownerId:f.owner,executorId:f.owner,
   ownerCredentialEpoch:'1',executorCredentialEpoch:'1',delegationId:f.draft.delegation.id,delegationVersion:1,delegationHmac:f.draft.delegationHmac,
   specHmac:f.draft.specHmac,windowStart:f.draft.spec.windowStart,windowEnd:f.draft.spec.windowEnd,impactHmac:f.draft.impactHmac,
   subjectSealHmac:f.draft.delegation.subjectSealHmac},workflow:{id:f.plan.workflowId,planRevision:1,planHash:h(f.plan)},
  requester:f.draft.binding.requester,subjectSealHmac:f.draft.delegation.subjectSealHmac,approvalSet:f.approvalSet});
 const row:any={id:f.plan.workflowId,state:'approved',plan_revision:1,plan_hash:h(f.plan),definition_id:f.plan.definition.id,definition_version:1,
  approval_required:true,approval_format:2,candidate_version:1,candidate_manifest_hmac:candidateHmac,approval_set_id:f.approvalSet.setId,
  approval_set_hmac:f.approvalSet.setHmac,approved_by:f.approvalSet.reviewers.at(-1).userId};
 const definitionRow={approval_format:2,policy,policy_hash:h(policy),allow_self_approval:false},versionRow={...row};
 const values:any={live:true,membership:true,invalidated:false,reviewerEpoch:'1',registryRevision:1,sqlFailure:false,onSql:null,
  definitionRow,versionRow,
  row,policy,manifest,approvalMaterial,candidateHmac,
  votes:f.approvalSet.reviewers.map((r:any)=>({id:r.approvalId,approver_id:r.userId,level:r.level,plan_hash:h(f.plan),decision:'approve',
   candidate_version:1,candidate_manifest_hmac:candidateHmac})),
  stages:candidateStages.map(s=>({level:s.level,plan_hash:h(f.plan),state:'approved',required_approvals:s.threshold,approval_format:2,
   candidate_version:1,candidate_manifest_hmac:candidateHmac,stage_mode:s.mode}))};
 const originalOne=f.db.one.getMockImplementation()!;
 const sqlFence=async(sql:string,args:any[])=>{if(values.sqlFailure)throw Error('CONTROLLED_SQL_UNAVAILABLE');await values.onSql?.(sql,args);};
 f.db.one.mockImplementation(async(sql:string,args:any[]=[])=>{
  await sqlFence(sql,args);
  if(sql.includes('FROM team_members')||sql.includes('SELECT 1 FROM iam_effective_grants g'))return values.membership?{allowed:true}:null;
  if(sql.includes('FROM schema_migrations'))return f.state.migration?{checksum:WORKFLOW_BUSINESS_CURRENT_IDENTITY_SQL026_SHA256}:null;
  if(sql.includes('FROM workflow_definition_versions'))return values.definitionRow;
  if(sql.includes('FROM workflow_candidate_versions'))return{manifest:values.manifest,manifest_hmac:candidateHmac};
  if(sql.includes('FROM workflow_approval_sets'))return{id:f.approvalSet.setId,set_hmac:f.approvalSet.setHmac,manifest:values.approvalMaterial};
  if(sql.includes('FROM workflow_approval_invalidations'))return values.invalidated?{id:randomUUID()}:null;
  if(sql.includes('FROM workflow_versions'))return values.versionRow;
  if(sql.includes('FROM workflows'))return values.row;
  if(sql.includes('SELECT status,deleted_at,force_password_change,credential_epoch FROM users'))return f.state.reviewerActive?
   {status:'active',deleted_at:null,force_password_change:false,credential_epoch:values.reviewerEpoch}:null;
  const result=await originalOne(sql,args);
  if(sql.includes('FROM clusters')&&result)result.revision=values.registryRevision;
  if(sql.includes('FROM users')&&result&&args[0]!==f.owner)result.credential_epoch=values.reviewerEpoch;
  return result;
 });
 f.db.query.mockImplementation(async(sql:string,args:any[]=[])=>{
  await sqlFence(sql,args);
  if(sql.includes('FROM workflow_stages'))return values.stages;
  if(sql.includes('FROM workflow_approvals'))return values.votes;
  if(sql.includes('FROM workflow_candidates'))return candidateStages.flatMap(s=>s.candidates.map(c=>({level:s.level,user_id:c.userId,
   credential_epoch:c.credentialEpoch,provenance:c.provenance,plan_hash:h(f.plan),manifest_hmac:candidateHmac})));
  if(sql.includes('FROM workflow_approval_set_members'))return f.approvalSet.reviewers.map((r:any)=>({cluster_id:f.cid,workspace_id:f.wid,
   workflow_id:f.plan.workflowId,plan_revision:1,plan_hash:h(f.plan),set_hmac:f.approvalSet.setHmac,approval_id:r.approvalId,user_id:r.userId,
   level:r.level,candidate_version:1,candidate_manifest_hmac:candidateHmac}));
  throw Error('UNEXPECTED_LEDGER_IDENTITY_QUERY');
 });
 const context=new KongExecutionContextService();
 const assertLive=vi.fn((handle:object)=>{if(handle!==nsHandle||!values.live)throw Error('ORIGINAL_LEDGER_NAMESPACE_CLOSED');});
 const fullVerify=vi.fn(async(handle:object)=>{assertLive(handle);return ns;});
 context.installWorkflowScheduledNamespacePolicy({verifyHandle:fullVerify,assertLive});
 const native=vi.fn(async()=>{throw Error('LEDGER_MUST_NOT_CALL_NATIVE');});
 const kong:any={request:native};context.installPolicy({authorizeRequest:native,authorizeResponse:native});
 const readRegistry=new WeakMap<object,any>();
 const validation:any={verifyHandle:vi.fn(async(handle:object,namespace:object,proof:object)=>{
  const read=readRegistry.get(handle);if(!read||namespace!==nsHandle||proof!==ns)throw Error('ORIGINAL_LEDGER_READ_REQUIRED');return read;
 }),assertLive(handle:object){if(!readRegistry.has(handle))throw Error('ORIGINAL_LEDGER_READ_REQUIRED');},
 authorizeRequest:native,verifyRequest:native,authorizeResponse:native};
 context.installWorkflowScheduledValidationReadPolicy(validation);
 const identity=new WorkflowBusinessCurrentIdentityService(f.db,f.secrets,context,f.redis,f.repository,f.plans,new WorkflowCandidatesService(f.db),validation);
 const identitySpy=vi.spyOn(identity,'currentPrincipal');
 const namespaces:any={assertLive};
 const runtime=new WorkflowBusinessRuntimeService(f.db,f.redis,f.secrets,context,kong,{} as any,f.plans,{} as any,{} as any,
  f.repository,{} as any,namespaces,{} as any,validation,{} as any,{} as any,identity,{} as any,{} as any,{} as any,{} as any);
 const namespace=<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(nsHandle,fn);
 const guard=(handle:object=nsHandle,proof:object=ns,tx:any=f.db):Promise<void>=>(runtime as any).assertLedgerCurrent(handle,proof,tx);
 const validationRead=<T>(role:'executor'|'reviewer',fn:()=>Promise<T>)=>{
  const actor=role==='executor'?ns.actor:{...ns.actor,id:f.approvalSet.reviewers[0].userId};
  const handle=Object.freeze({}),proof=immutableJson({version:1,origin:'workflow-scheduled-validation-read',readOnly:true,actor,sessionId:null,role,
   namespace:ns,expiresAt:new Date(Date.now()+5000).toISOString(),scope:{version:1,resources:[{clusterId:f.cid,workspaceId:f.wid,
    path:'/schemas/services',kind:'schema',entityType:'services',secrets:false}],limits:{maxCalls:1,maxPages:1,maxRecords:1,maxBytes:1024}},
   registries:[{clusterId:f.cid,workspaceId:f.wid,transportScope:ns.transportScope,clusterRevision:1,workspaceRevision:1}]});
  // Keep the original Namespace object, matching the provider/Context contract.
  const original=Object.freeze({...proof,namespace:ns});readRegistry.set(handle,original);
  return context.runWorkflowScheduledValidationRead(handle,nsHandle,fn).finally(()=>readRegistry.delete(handle));
 };
 return{...f,stored:f.state.stored,workflowRow:row,definitionRow,versionRow,approvalRows:values.votes,stageRows:values.stages,
  values,policy,manifest,candidateStages,ns,nsHandle,context,
  identity,identitySpy,runtime,namespaces,fullVerify,native,kong,namespace,guard,readonly:validationRead};
}
