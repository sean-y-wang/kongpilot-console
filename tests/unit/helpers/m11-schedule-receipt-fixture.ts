import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {workflowScheduledFixture} from './workflow-scheduled-fixture';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {AuthorizationService} from '../../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkflowBusinessSchedulesService} from '../../../apps/console-api/src/modules/workflows/workflow-business-schedules.service';
import {WorkflowBusinessRuntimeService} from '../../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import {WorkflowScheduledAuthorityService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import {assertWorkflowScheduledPlan,workflowSchedulePlanSeal} from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import {immutableJson} from '../../../apps/console-api/src/infrastructure/kong/immutable-json';

type Kind='configuration_v2'|'portal-credential-issue';
type Terminal='succeeded'|'partial'|'failed'|'uncertain'|'blocked'|'cancelled'|'expired';
const checksum=(name:string)=>createHash('sha256').update(readFileSync(`apps/console-api/src/infrastructure/migrations/${name}`)).digest('hex');

/** Actual Service, Authority, Root assembly, Context and SQL grant matcher.
 * The repository adapter models already-authenticated stored material; its
 * getters still enter the actual Authority delegate. No worker/Native runs. */
export function m11ScheduleReceiptFixture(kind:Kind='configuration_v2',promote=false){
 const base=workflowScheduledFixture(kind),context=new KongExecutionContextService(),secrets=base.secrets;
 const cid=base.cid,wid=base.wid,owner=base.owner,sid=randomUUID();
 const user:any=Object.freeze({id:owner,username:'receipt-reader',superAdmin:false,forcePasswordChange:false});
 const actor:any={user,workspaceId:wid,requestId:randomUUID()};
 const state:any={sessionLive:true,userActive:true,forcePasswordChange:false,credentialEpoch:'2',permissionsEpoch:'7',iamEpoch:'3',
  onSql:null,onGet:null,entries:[],grants:[],lastOperation:null};
 const grant=(module:string,action='read',workspaceId=wid)=>({user_id:owner,module,action,scope_type:'workspace',cluster_id:cid,
  workspace_id:workspaceId,scope_values:[workspaceId]});
 state.grants=[grant('workflows'),grant('snapshots'),grant('portal')];
 const versionFor=(plan:any)=>({cluster_id:cid,workspace_id:wid,workflow_id:plan.workflowId,plan_revision:plan.planRevision,
  plan_hash:secrets.fingerprint(plan),policy_version:plan.definition.version,execution_mode:plan.executionMode,approval_required:true,
  step_count:plan.steps.length,native_request_count:plan.steps.reduce((n:number,s:any)=>n+s.nativeRequests.length,0),
  steps_hash:secrets.fingerprint(plan.steps),created_by:owner,created_by_developer_id:null});
 const add=(terminal:Terminal='failed',copy?:any)=>{
  const plan:any=structuredClone(copy?.plan??base.plan),draft:any=structuredClone(copy?.draft??base.draft);
  if(copy){plan.workflowId=randomUUID();plan.subject.id=randomUUID();draft.scheduleId=randomUUID();draft.occurrenceId=randomUUID();
   draft.binding.workflowId=plan.workflowId;draft.binding.subjectId=plan.subject.id;draft.delegation.id=randomUUID();draft.delegation.workflowId=plan.workflowId;
   draft.delegation.subjectId=plan.subject.id;draft.binding.subjectSeal.subjectId=plan.subject.id;
   if(kind==='configuration_v2'){plan.steps[0].entityId=plan.subject.id;plan.steps[0].metadata.jobId=plan.subject.id;}}
  let portal:any;
  if(kind==='portal-credential-issue'){
   const consumer=plan.steps[0].nativeRequests[0].nativeId,acl=plan.steps[1].nativeRequests[0].nativeId,key=plan.steps[2].nativeRequests[0].nativeId;
   const serviceId=randomUUID(),raw={id:serviceId};
   plan.generated={consumerId:consumer,aclId:acl,credentialId:key,key:'controlled-receipt-key'};
   plan.prerequisites=[{type:'services',id:serviceId,path:`/services/${serviceId}`,before:raw,fingerprint:secrets.fingerprint(raw)}];
   const scope={cluster_id:cid,workspace_id:wid},appId=randomUUID(),publicationId=randomUUID(),credentialId=randomUUID(),aclGroup='receipt-group';
   portal={grant:{...scope,id:plan.subject.id,application_id:appId,publication_id:publicationId,developer_id:plan.requester.id,consumer_id:consumer,
    acl_id:acl,acl_group:aclGroup,workflow_id:plan.workflowId,transport_scope:plan.scope.transportScope,state:'failed'},
    application:{...scope,id:appId,developer_id:plan.requester.id,status:'disabled'},developer:{...scope,id:plan.requester.id,status:'disabled',credential_epoch:'99'},
    publication:{...scope,id:publicationId,service_id:serviceId,acl_group:aclGroup,transport_scope:plan.scope.transportScope,state:'retired'},
    credential:{...scope,id:credentialId,grant_id:plan.subject.id,developer_id:plan.requester.id,consumer_id:consumer,kong_id:key,credential_kind:'key-auth',
     generation:1,previous_credential_id:null,workflow_id:plan.workflowId,key_fingerprint:secrets.fingerprint(plan.generated.key),state:'failed'}};
  }
  if(kind==='configuration_v2')plan.steps[0].metadataPayloadHmac=secrets.fingerprint(plan.steps[0].metadata);
  if(promote){draft.binding.subjectSeal.driver='governance-promote';draft.binding.subjectSeal.sourceScopes=[{clusterId:randomUUID(),workspaceId:randomUUID(),materialHmac:secrets.fingerprint('old-promote-source')}];}
  draft.delegation.subjectSealHmac=secrets.fingerprint(draft.binding.subjectSeal);
  const {scheduling:_old,...unsealed}=plan;
  draft.binding.basePlanHash=secrets.fingerprint(unsealed);draft.delegation.basePlanHash=draft.binding.basePlanHash;
  draft.delegationHmac=secrets.fingerprint(draft.delegation);plan.scheduling=workflowSchedulePlanSeal(draft);
  draft.binding.workflowPlanHash=secrets.fingerprint(plan);
  const claimId=['blocked','cancelled','expired'].includes(terminal)?null:randomUUID();
  const stored:any={draft,plan,progress:{state:terminal,revision:5,claimId,reasonCode:'CONTROLLED_TERMINAL_REASON'},activation:null,claim:null,latestLease:null};
  const workflow:any={id:plan.workflowId,cluster_id:cid,workspace_id:wid,kind,subject_type:plan.subject.type,subject_id:plan.subject.id,
   requester_type:plan.requester.type,requester_user_id:plan.requester.type==='console'?plan.requester.id:null,
   requester_developer_id:plan.requester.type==='developer'?plan.requester.id:null,definition_id:plan.definition.id,definition_version:plan.definition.version,
   plan_revision:plan.planRevision,plan_hash:secrets.fingerprint(plan),execution_mode:plan.executionMode,approval_required:true};
  const payload=kind==='configuration_v2'?plan.steps[0].metadata:null;
  const job=payload?{id:payload.jobId,cluster_id:cid,workspace_id:wid,actor_id:owner,kind:'apply',plan_id:payload.planId,plan_revision:payload.planRevision,
   plan_hash:payload.planHash,workflow_id:plan.workflowId,transport_scope:plan.scope.transportScope,execution_mode:plan.executionMode,approval_required:true,
   cluster_revision:plan.scope.clusterRevision,workspace_revision:plan.scope.workspaceRevision}:null;
  const configuration=payload?{cluster_id:cid,workspace_id:wid,plan_id:payload.planId,plan_revision:payload.planRevision,plan_hash:payload.planHash,
   cluster_revision:plan.scope.clusterRevision,workspace_revision:plan.scope.workspaceRevision}:null;
  const entry:any={stored,workflow,version:versionFor(plan),job,configuration,portal,createdAt:new Date(Date.now()-1000).toISOString(),key:randomUUID()};
  // Real SELECT projections omit these columns; keeping their independent
  // source state lets tests prove history does not require executable state.
  entry.jobState=terminal;entry.originalDelegationEpoch=draft.delegation.ownerCredentialEpoch;
  state.entries.push(entry);return entry;
 };
 const entry=add();
 const fromParams=(params:any[],get:(e:any)=>any)=>state.entries.find((e:any)=>params.includes(get(e)));
 const scopeMatches=(params:any[])=>params.includes(cid)&&params.includes(wid);
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  await state.onSql?.(sql,p);
  if(sql.includes('FROM schema_migrations'))return{checksum:checksum(p[0]??'026_m11_workflow_schedules.sql')};
  if(sql.includes('FROM auth_sessions'))return state.sessionLive&&state.userActive&&!state.forcePasswordChange&&p[0]===sid&&p[1]===owner?
   {id:sid,credential_epoch:state.credentialEpoch,permissions_epoch:state.permissionsEpoch,iam_version:state.iamEpoch}:null;
  if(sql.includes('FROM users'))return state.userActive&&p[0]===owner?{id:owner,username:user.username,super_admin:false,status:'active',deleted_at:null,
   credential_epoch:state.credentialEpoch,permissions_epoch:state.permissionsEpoch,force_password_change:state.forcePasswordChange}:null;
  if(sql.includes('FROM iam_epoch'))return{version:state.iamEpoch};
  if(sql.includes('FROM clusters'))return p[0]===cid?{id:cid}:null;
  if(sql.includes('FROM workflow_schedules s')){const e=fromParams(p,(x:any)=>x.stored.draft.scheduleId);return e&&scopeMatches(p)?
   {id:e.stored.draft.scheduleId,owner_id:owner,workflow_id:e.stored.plan.workflowId,transport_scope:e.stored.plan.scope.transportScope,
    revision:e.stored.progress.revision,state:e.stored.progress.state,claim_id:e.stored.progress.claimId}:null;}
  if(sql.includes('FROM workflow_versions')){const e=fromParams(p,(x:any)=>x.version.workflow_id);return e&&scopeMatches(p)?structuredClone(e.version):null;}
  if(sql.includes('FROM workflows')){const e=fromParams(p,(x:any)=>x.workflow.id);return e&&scopeMatches(p)?structuredClone(e.workflow):null;}
  if(sql.includes('FROM configuration_plan_versions')){const e=fromParams(p,(x:any)=>x.configuration?.plan_id);return e&&scopeMatches(p)?structuredClone(e.configuration):null;}
  if(sql.includes('FROM configuration_jobs')){const e=fromParams(p,(x:any)=>x.job?.id);return e&&scopeMatches(p)?structuredClone(e.job):null;}
  for(const [table,key]of [['portal_application_grants','grant'],['portal_applications','application'],['portal_developers','developer'],
   ['portal_publications','publication'],['portal_credentials','credential']])if(sql.includes(`FROM ${table}`)){
    const e=fromParams(p,(x:any)=>table==='portal_credentials'?x.portal?.credential.grant_id:x.portal?.[key].id);
    return e&&scopeMatches(p)?structuredClone(e.portal[key]):null;
   }
  if(sql.includes('FROM audit_events')){const e=state.entries.find((x:any)=>secrets.fingerprint({domain:'workflow-business-schedule-command',cid,wid,actor:owner,key:x.key})===p[3]);
   return e?{after:{scheduleId:e.stored.draft.scheduleId,receipt:{entity:{state:'stale-audit-state'},arbitraryPrivatePayload:'must-never-project'}}}:null;}
  throw Error(`UNEXPECTED_RECEIPT_SQL:${sql.slice(0,90)}`);
 }),query:vi.fn(async(sql:string,p:any[]=[])=>{
  await state.onSql?.(sql,p);
  if(sql.includes('FROM iam_effective_grants'))return p[0]===owner?structuredClone(state.grants):[];
  if(sql.includes('SELECT id,created_at FROM workflow_schedules'))return p[0]===cid&&p[1]===wid?
   state.entries.map((e:any)=>({id:e.stored.draft.scheduleId,created_at:e.createdAt})):[];
  throw Error('UNEXPECTED_RECEIPT_QUERY');
 }),exec:vi.fn(async()=>{throw Error('RECEIPT_MUST_NOT_WRITE_SQL');}),transaction:vi.fn(async(fn:any)=>fn(db))};
 const native=vi.fn(async()=>{throw Error('RECEIPT_MUST_NOT_USE_NATIVE');}),kong:any={request:native,verifyScheduledReadAbsentTransport:native};
 const workspaces:any={get:vi.fn(async(c:string,w:string)=>{if(c!==cid||w!==wid)throw new ForbiddenException();return{id:wid,status:'active'};})};
 const authz=new AuthorizationService(db,workspaces,kong,context);
 let repositoryPolicy:any;
 const receipt=(s:any)=>({id:s.draft.scheduleId,revision:s.progress.revision,state:s.progress.state,kind:s.plan.kind,workflowId:s.plan.workflowId,
  workflowPlanRevision:s.plan.planRevision,workflowPlanHash:s.draft.binding.workflowPlanHash,requesterType:s.plan.requester.type,requesterId:s.plan.requester.id,
  executorId:s.draft.delegation.executorId,notBefore:s.draft.spec.notBefore,windowStart:s.draft.spec.windowStart,windowEnd:s.draft.spec.windowEnd,
  claimId:s.progress.claimId,reasonCode:s.progress.reasonCode,nativeAuthority:false});
 const repository:any={installFixedDelegate:vi.fn((policy:any)=>{repositoryPolicy=policy;}),
  inspectStored:vi.fn(async(id:string)=>{const e=state.entries.find((x:any)=>x.stored.draft.scheduleId===id);if(!e)throw Error('SOURCE_SCHEDULE_NOT_FOUND');
   assertWorkflowScheduledPlan(e.stored.plan,e.stored.draft,secrets);return immutableJson(e.stored);}),
  get:vi.fn(async(id:string,a:any,tx:any=db)=>{const e=state.entries.find((x:any)=>x.stored.draft.scheduleId===id);if(!e)throw Error('SOURCE_SCHEDULE_NOT_FOUND');
   await state.onGet?.(e,a,tx);await repositoryPolicy.assertRead(id,a,tx);return receipt(e.stored);})};
 const plans:any={load:vi.fn(async()=>{throw Error('OLD_PROMOTE_ORIGIN_LOAD_FORBIDDEN');}),installScheduledRevisionDelegate:vi.fn()};
 const redis:any={withLock:vi.fn(async(_key:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>{throw Error('RECEIPT_MUST_NOT_ACQUIRE_EXECUTION_LEASE');}),assertLeaseActive:vi.fn(()=>{throw Error('NO_EXECUTION_LEASE');})};
 const audit:any={append:vi.fn(async()=>{throw Error('RECEIPT_MUST_NOT_APPEND_AUDIT');})};
 const approvalFacts=vi.fn(async()=>{throw Error('RECEIPT_MUST_NOT_VERIFY_EXECUTION_APPROVAL');});
 // Receipt admission may install the execution reader at bootstrap, but must
 // never use it. Keep this Source adapter explicitly closed, not auto-approved.
 const approvals:any={installScheduledEligibilityFactsReader:vi.fn(()=>approvalFacts),installScheduledConfigurationEligibilityFactsReader:vi.fn(()=>approvalFacts),
  installScheduledConfigurationOriginSqlReader:vi.fn(()=>approvalFacts)};
 const authority=new WorkflowScheduledAuthorityService(db,secrets,redis,context,plans,approvals,repository);
 const schedules=new WorkflowBusinessSchedulesService(db,secrets,redis,context,authz,audit,plans,repository,authority);
 const provider=()=>({installStorageContract:vi.fn(),installContextRunner:vi.fn(),installBusinessPolicy:vi.fn(),installAbsentResponseVerifier:vi.fn(),
  installParentAbsencePolicy:vi.fn(),installFixedReader:vi.fn(()=>native),verifyHandle:native,assertLive:native,authorizeRequest:native,verifyRequest:native,authorizeResponse:native});
 const candidates:any={...provider(),assertOriginalHttpAcceptance:native},validation:any=provider();
 const approved:any={installWorkflowScheduledReviewerReadPolicy:vi.fn(),installWorkflowScheduledDelegate:vi.fn(),assertSubject:vi.fn(async()=>{throw new ForbiddenException({code:'CONFIGURATION_APPROVED_WRAPPER_INVALID'});})};
 const namespaces:any={installContextRunner:vi.fn(),verifyHandle:native,assertLive:native};
 const material:any={installScopedReadBridge:vi.fn(),businessReadPolicy:vi.fn(()=>({})),materialForPlan:native,currentReadInput:native};
 const workflows:any={installBusinessScheduledDelegate:vi.fn()},configuration:any={installRootVerifier:vi.fn()},worker:any={installFixedDelegate:vi.fn()};
 const core:any={installWorkflowScheduledConfigurationOrigin:vi.fn()},origins:any={installWorkflowScheduledOrigin:vi.fn()};
 const runtime=new WorkflowBusinessRuntimeService(db,redis,secrets,context,kong,authz,plans,workflows,approved,repository,authority,namespaces,candidates,
  validation,configuration,material,{} as any,schedules,worker,{get:(type:any)=>type.name==='ConfigurationService'?core:origins} as any,{} as any);
 runtime.onModuleInit();context.installPolicy({authorizeRequest:native,authorizeResponse:native});
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({},()=>{context.bindHttpActor(user,sid);return fn();});
 const scope=()=>schedules.assertReceiptReadScope(entry.stored,actor,db);
 return{base,state,cid,wid,owner,sid,user,actor,entry,add,db,context,secrets,authz,grant,native,kong,redis,audit,repository,plans,approved,authority,approvalFacts,
  schedules,runtime,run,scope,receipt,repositoryPolicy:()=>repositoryPolicy};
}
