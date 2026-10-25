import { isPortalCredentialScheduleKind } from '../portal/portal-credential-lifecycle-contract';
import {ConflictException,Injectable,NotFoundException,ServiceUnavailableException} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {AuditService} from '../audit/audit.service';
import {validImpact} from '../mutations/mutation-impact';
import type {EntityActor} from '../entities/entities.types';
import {planAad,type WorkflowPlanV1} from './workflow.types';
import {validateWorkflowPlan} from './workflow-validation';
import type {WorkflowScheduleSpecV1,WorkflowScheduleDraft,WorkflowScheduledPlanV1,WorkflowSchedulePlanSealV1,WorkflowScheduleStored,
  WorkflowScheduleActivation,WorkflowScheduleClaim,WorkflowScheduleRepositoryDelegate,WorkflowScheduleReceipt,WorkflowScheduleTerminalOutcome} from './workflow-schedule.contract';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i,hex=/^[a-f\d]{64}$/;
const invalid=(code='WORKFLOW_SCHEDULE_FACT_INVALID')=>new ConflictException({code});
const iso=(value:any)=>{const d=new Date(value);if(!Number.isFinite(d.getTime()))throw invalid();return d.toISOString();};
const epoch=(value:unknown)=>typeof value==='string'&&/^[1-9]\d{0,18}$/.test(value)&&BigInt(value)<=9223372036854775807n;
const keys=(value:any,names:string[])=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...names].sort().join(',');
const same=(secrets:SecretService,a:unknown,b:unknown)=>{if(secrets.fingerprint(a)!==secrets.fingerprint(b))throw invalid('WORKFLOW_SCHEDULE_MATERIAL_CHANGED');};
export const workflowDelegationAad=(cid:string,wid:string,id:string)=>`workflow-executor-delegation:${cid}:${wid}:${id}:material`;
export const workflowScheduleDraftAad=(cid:string,wid:string,id:string)=>`workflow-business-schedule:${cid}:${wid}:${id}:draft`;
export function normalizeWorkflowScheduleSpec(value:unknown,executorId:string):Readonly<WorkflowScheduleSpecV1>{
  const s=value as any;if(!keys(s,['version','notBefore','windowStart','windowEnd','executorId'])||s.version!==1||!uuid.test(executorId)||s.executorId!==executorId
    ||['notBefore','windowStart','windowEnd'].some(k=>typeof s[k]!=='string'||iso(s[k])!==s[k])
    ||Date.parse(s.windowStart)>Date.parse(s.notBefore)||Date.parse(s.notBefore)>=Date.parse(s.windowEnd))throw invalid('WORKFLOW_SCHEDULE_SPEC_INVALID');
  return immutableJson(s);
}
export function normalizeWorkflowScheduleDraft(value:Readonly<WorkflowScheduleDraft>,secrets:SecretService):Readonly<WorkflowScheduleDraft>{
  if(!keys(value,['binding','scheduleId','scheduleVersion','occurrenceId','spec','specHmac','delegation','delegationHmac','transportScope','impact','impactHmac'])
    ||!uuid.test(value.scheduleId)||value.scheduleVersion!==1||!uuid.test(value.occurrenceId))throw invalid();
  const b=value.binding,d=value.delegation;
  if(!keys(b,['clusterId','workspaceId','workflowId','workflowPlanRevision','workflowPlanHash','basePlanHash','kind','subjectType','subjectId','requester','definitionId','definitionVersion','policyHash','subjectSeal'])
    ||[b.clusterId,b.workspaceId,b.workflowId,b.subjectId,b.definitionId].some(id=>!uuid.test(id))||!Number.isSafeInteger(b.workflowPlanRevision)||b.workflowPlanRevision<1
    ||!Number.isSafeInteger(b.definitionVersion)||b.definitionVersion<1||[b.workflowPlanHash,b.basePlanHash,b.policyHash].some(h=>!hex.test(h))
    ||!keys(b.requester,['type','id','credentialEpoch'])||!uuid.test(b.requester.id)||!epoch(b.requester.credentialEpoch)
    ||!(b.kind==='configuration_v2'&&b.subjectType==='configuration_jobs'&&b.requester.type==='console'
      ||isPortalCredentialScheduleKind(b.kind)&&b.subjectType==='portal_application_grants'&&b.requester.type==='developer'))throw invalid();
  const subject=b.subjectSeal;
  if(!keys(subject,['version','driver','subjectId','materialHmac','nativeManifestHmac','sourceScopes'])||subject.version!==1||subject.subjectId!==b.subjectId
    ||!hex.test(subject.materialHmac)||!hex.test(subject.nativeManifestHmac)||!Array.isArray(subject.sourceScopes)||subject.sourceScopes.length>8
    ||subject.sourceScopes.some(s=>!keys(s,['clusterId','workspaceId','materialHmac'])||!uuid.test(s.clusterId)||!uuid.test(s.workspaceId)||!hex.test(s.materialHmac))
    ||new Set(subject.sourceScopes.map(s=>`${s.clusterId}:${s.workspaceId}`)).size!==subject.sourceScopes.length
    ||(b.kind==='configuration_v2'?!['configuration-apply','configuration-rollback','governance-promote'].includes(subject.driver)
      :isPortalCredentialScheduleKind(b.kind)?subject.driver!==b.kind:subject.driver!==b.kind)
    ||(subject.driver==='governance-promote'?subject.sourceScopes.length<1:subject.sourceScopes.length!==0))throw invalid();
  if(!keys(d,['version','id','revision','clusterId','workspaceId','workflowId','workflowPlanRevision','basePlanHash','kind','subjectType','subjectId','subjectSealHmac','requester',
    'ownerId','executorId','ownerCredentialEpoch','executorCredentialEpoch','policyHash','specHmac','issuedAt','expiresAt','statement'])
    ||d.version!==1||d.revision!==1||!uuid.test(d.id)||!uuid.test(d.ownerId)||d.ownerId!==d.executorId||!epoch(d.ownerCredentialEpoch)||d.ownerCredentialEpoch!==d.executorCredentialEpoch
    ||d.clusterId!==b.clusterId||d.workspaceId!==b.workspaceId||d.workflowId!==b.workflowId||d.workflowPlanRevision!==b.workflowPlanRevision||d.basePlanHash!==b.basePlanHash
    ||d.kind!==b.kind||d.subjectType!==b.subjectType||d.subjectId!==b.subjectId||d.policyHash!==b.policyHash||d.subjectSealHmac!==secrets.fingerprint(subject)
    ||d.statement!=='execute-this-exact-approved-business-workflow-with-my-current-authority'||iso(d.issuedAt)!==d.issuedAt||iso(d.expiresAt)!==d.expiresAt
    ||Date.parse(d.expiresAt)<=Date.parse(d.issuedAt)||Date.parse(d.expiresAt)-Date.parse(d.issuedAt)>168*3600000)throw invalid();
  same(secrets,d.requester,b.requester);
  if(b.requester.type==='console'&&(b.requester.id!==d.ownerId||b.requester.credentialEpoch!==d.ownerCredentialEpoch))throw invalid();
  const spec=normalizeWorkflowScheduleSpec(value.spec,d.executorId);
  if(value.specHmac!==secrets.fingerprint(spec)||d.specHmac!==value.specHmac||value.delegationHmac!==secrets.fingerprint(d)
    ||Date.parse(spec.windowEnd)>Date.parse(d.expiresAt)||!hex.test(value.transportScope)||!validImpact(value.impact)
    ||!keys(value.impact,['version','keyId','keys','domains','wildcards',...(Object.hasOwn(value.impact,'conservative')?['conservative']:[])])
    ||Object.hasOwn(value.impact,'conservative')&&typeof value.impact.conservative!=='boolean'
    ||value.impact.keys.length+value.impact.domains.length+value.impact.wildcards.length>100000||value.impactHmac!==secrets.fingerprint(value.impact))throw invalid();
  return immutableJson(value);
}
export function workflowSchedulePlanSeal(draft:Readonly<WorkflowScheduleDraft>):WorkflowSchedulePlanSealV1{
  const d=draft.delegation;return immutableJson({version:1,scheduleId:draft.scheduleId,scheduleVersion:1,occurrenceId:draft.occurrenceId,basePlanHash:draft.binding.basePlanHash,
    spec:draft.spec,specHmac:draft.specHmac,delegationId:d.id,delegationVersion:1,delegationHmac:draft.delegationHmac,ownerId:d.ownerId,ownerCredentialEpoch:d.ownerCredentialEpoch,
    executorId:d.executorId,executorCredentialEpoch:d.executorCredentialEpoch,requester:draft.binding.requester,transportScope:draft.transportScope,impactHmac:draft.impactHmac,subjectSealHmac:d.subjectSealHmac});
}
export function assertWorkflowScheduledPlan(plan:WorkflowPlanV1,draft:Readonly<WorkflowScheduleDraft>,secrets:SecretService):asserts plan is WorkflowScheduledPlanV1{
  const value=normalizeWorkflowScheduleDraft(draft,secrets),b=value.binding;validateWorkflowPlan(plan);
  const{scheduling,...base}=plan as WorkflowScheduledPlanV1;
  if(plan.clusterId!==b.clusterId||plan.workspaceId!==b.workspaceId||plan.workflowId!==b.workflowId||plan.planRevision!==b.workflowPlanRevision||plan.kind!==b.kind
    ||plan.subject.type!==b.subjectType||plan.subject.id!==b.subjectId||plan.requester.type!==b.requester.type||plan.requester.id!==b.requester.id
    ||plan.definition.id!==b.definitionId||plan.definition.version!==b.definitionVersion||plan.definition.policyHash!==b.policyHash||!plan.approvalRequired
    ||plan.scope.transportScope!==draft.transportScope||plan.expiresAt!==draft.delegation.expiresAt
    ||secrets.fingerprint(base)!==b.basePlanHash||secrets.fingerprint(plan)!==b.workflowPlanHash)throw invalid('WORKFLOW_SCHEDULE_PLAN_BINDING_INVALID');
  same(secrets,scheduling,workflowSchedulePlanSeal(value));
}
const required=['verifyDraft','verifyApproved','verifyClaim','verifyLease','verifyCancellation','verifyPhysicalReservation','verifyOutcome','verifyBlocked','assertRead'] as const;
function activationFact(value:WorkflowScheduleActivation):Readonly<WorkflowScheduleActivation>{
  if(!keys(value,['workflowId','workflowPlanRevision','workflowPlanHash','approvalFormat','approvalRequired','approvalSetId','approvalSetHmac'])
    ||!uuid.test(value.workflowId)||!Number.isSafeInteger(value.workflowPlanRevision)||value.workflowPlanRevision<1||!hex.test(value.workflowPlanHash)||value.approvalRequired!==true
    ||!(value.approvalFormat===1&&value.approvalSetId===null&&value.approvalSetHmac===null||value.approvalFormat===2&&uuid.test(value.approvalSetId??'')&&hex.test(value.approvalSetHmac??'')))throw invalid();
  return immutableJson(value);
}
function claimFact(value:WorkflowScheduleClaim):Readonly<WorkflowScheduleClaim>{
  if(!keys(value,['id','scheduleId','scheduleVersion','occurrenceId','generation','workerOwnerHmac','workflowId','workflowPlanRevision','workflowPlanHash','issuedAt','authorityExpiresAt','initialLeaseUntil'])
    ||[value.id,value.scheduleId,value.occurrenceId,value.workflowId].some(id=>!uuid.test(id))||value.scheduleVersion!==1||value.generation!==1||!hex.test(value.workerOwnerHmac)
    ||!Number.isSafeInteger(value.workflowPlanRevision)||value.workflowPlanRevision<1||!hex.test(value.workflowPlanHash)
    ||[value.issuedAt,value.authorityExpiresAt,value.initialLeaseUntil].some(t=>typeof t!=='string'||iso(t)!==t)||Date.parse(value.authorityExpiresAt)<=Date.parse(value.issuedAt)
    ||Date.parse(value.authorityExpiresAt)-Date.parse(value.issuedAt)>300000||Date.parse(value.initialLeaseUntil)<=Date.parse(value.issuedAt)||Date.parse(value.initialLeaseUntil)>Date.parse(value.authorityExpiresAt))throw invalid();
  return immutableJson(value);
}
/** Separate immutable facts only. No HTTP, Kong call, Source mutation, actor
 * reconstruction, runtime timer or native ticket is provided here. */
@Injectable()
export class WorkflowScheduleRepository{
  private delegate?:Readonly<WorkflowScheduleRepositoryDelegate>;
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly audit:AuditService){}
  installFixedDelegate(value:WorkflowScheduleRepositoryDelegate):void{
    if(this.delegate||!value||required.some(k=>typeof value[k]!=='function'))throw invalid('WORKFLOW_SCHEDULE_POLICY_ALREADY_INSTALLED');
    this.delegate=Object.freeze(Object.fromEntries(required.map(k=>[k,value[k].bind(value)]))) as unknown as Readonly<WorkflowScheduleRepositoryDelegate>;
  }
  private policy(){if(!this.delegate)throw new ServiceUnavailableException({code:'WORKFLOW_SCHEDULE_POLICY_UNAVAILABLE'});return this.delegate;}
  private proof(value:object){if(!value||typeof value!=='object'||Array.isArray(value))throw invalid('WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED');}
  private transaction<T>(tx:DbService|undefined,fn:(db:DbService)=>Promise<T>){return tx?fn(tx):this.db.transaction(fn);}
  private async iam(tx:DbService){await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');}
  private async row(id:string,tx:DbService){if(!uuid.test(id))throw invalid();const row=await tx.one<any>(`SELECT s.*,p.state,p.revision,p.claim_id,p.reason_code,v.payload_secret
    FROM workflow_schedules s JOIN workflow_schedule_progress p ON p.schedule_id=s.id
    JOIN workflow_versions v ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.workflow_id=s.workflow_id
      AND v.plan_revision=s.workflow_plan_revision AND v.plan_hash=s.workflow_plan_hash WHERE s.id=$1`,[id]);
    if(!row)throw new NotFoundException({code:'WORKFLOW_SCHEDULE_NOT_FOUND'});return row;}
  async inspectStored(id:string,tx=this.db):Promise<Readonly<WorkflowScheduleStored>>{
    this.policy();const row=await this.row(id,tx),draft=normalizeWorkflowScheduleDraft(this.secrets.decrypt<WorkflowScheduleDraft>(row.draft_ciphertext,workflowScheduleDraftAad(row.cluster_id,row.workspace_id,id)),this.secrets);
    if(this.secrets.fingerprint(draft)!==row.draft_hmac||draft.scheduleId!==row.id||draft.occurrenceId!==row.occurrence_id||draft.binding.clusterId!==row.cluster_id||draft.binding.workspaceId!==row.workspace_id
      ||draft.binding.workflowId!==row.workflow_id||draft.binding.workflowPlanRevision!==row.workflow_plan_revision||draft.binding.workflowPlanHash!==row.workflow_plan_hash
      ||draft.binding.basePlanHash!==row.base_plan_hash||draft.binding.kind!==row.kind||draft.delegation.id!==row.delegation_id||draft.delegationHmac!==row.delegation_hmac
      ||row.version!==1||draft.delegation.ownerId!==row.owner_id||draft.delegation.executorId!==row.executor_id||draft.delegation.ownerCredentialEpoch!==String(row.owner_credential_epoch)
      ||draft.delegation.executorCredentialEpoch!==String(row.executor_credential_epoch)||draft.binding.requester.type!==row.requester_type||draft.binding.requester.id!==row.requester_id
      ||draft.binding.requester.credentialEpoch!==String(row.requester_credential_epoch)||draft.binding.definitionId!==row.definition_id||draft.binding.definitionVersion!==row.definition_version
      ||draft.binding.policyHash!==row.policy_hash||draft.delegation.subjectSealHmac!==row.subject_seal_hmac
      ||draft.specHmac!==row.spec_hmac||draft.transportScope!==row.transport_scope||draft.impactHmac!==row.impact_hmac||draft.spec.notBefore!==iso(row.not_before)
      ||draft.spec.windowStart!==iso(row.window_start)||draft.spec.windowEnd!==iso(row.window_end)||draft.delegation.expiresAt!==iso(row.expires_at))throw invalid('WORKFLOW_SCHEDULE_STORED_MATERIAL_INVALID');
    same(this.secrets,row.spec,draft.spec);same(this.secrets,row.impact,draft.impact);
    const delegation=await tx.one<any>('SELECT * FROM workflow_executor_delegations WHERE id=$1',[row.delegation_id]);
    const d=draft.delegation,b=draft.binding;
    if(!delegation||delegation.version!==1||delegation.id!==d.id||delegation.cluster_id!==b.clusterId||delegation.workspace_id!==b.workspaceId||delegation.delegation_hmac!==draft.delegationHmac
      ||delegation.workflow_id!==b.workflowId||delegation.workflow_plan_revision!==b.workflowPlanRevision||delegation.base_plan_hash!==b.basePlanHash||delegation.kind!==b.kind
      ||delegation.subject_type!==b.subjectType||delegation.subject_id!==b.subjectId||delegation.requester_type!==b.requester.type||delegation.requester_id!==b.requester.id
      ||String(delegation.requester_credential_epoch)!==b.requester.credentialEpoch||delegation.owner_id!==d.ownerId||delegation.executor_id!==d.executorId
      ||String(delegation.owner_credential_epoch)!==d.ownerCredentialEpoch||String(delegation.executor_credential_epoch)!==d.executorCredentialEpoch
      ||delegation.spec_hmac!==draft.specHmac||delegation.policy_hash!==b.policyHash||delegation.subject_seal_hmac!==d.subjectSealHmac||iso(delegation.issued_at)!==d.issuedAt||iso(delegation.expires_at)!==d.expiresAt)throw invalid();
    same(this.secrets,this.secrets.decrypt(delegation.delegation_ciphertext,workflowDelegationAad(row.cluster_id,row.workspace_id,delegation.id)),draft.delegation);
    const plan=this.secrets.decrypt<WorkflowScheduledPlanV1>(row.payload_secret,planAad(row.cluster_id,row.workspace_id,row.workflow_id,row.workflow_plan_revision));assertWorkflowScheduledPlan(plan,draft,this.secrets);
    const activation=await tx.one<any>('SELECT * FROM workflow_schedule_activations WHERE schedule_id=$1',[id]);
    if(activation){activationFact(activation.activation);same(this.secrets,activation.activation,{workflowId:b.workflowId,workflowPlanRevision:b.workflowPlanRevision,workflowPlanHash:b.workflowPlanHash,
      approvalFormat:activation.approval_format,approvalRequired:activation.approval_required,approvalSetId:activation.approval_set_id,approvalSetHmac:activation.approval_set_hmac});
      if(activation.cluster_id!==b.clusterId||activation.workspace_id!==b.workspaceId||activation.schedule_id!==id||activation.workflow_id!==b.workflowId
        ||activation.workflow_plan_revision!==b.workflowPlanRevision||activation.workflow_plan_hash!==b.workflowPlanHash)throw invalid();}
    const claim=row.claim_id?await tx.one<any>('SELECT * FROM workflow_schedule_claims WHERE id=$1 AND schedule_id=$2',[row.claim_id,id]):null;
    if(row.claim_id&&!claim)throw invalid();
    if(claim){claimFact(claim.claim);same(this.secrets,claim.claim,{id:claim.id,scheduleId:id,scheduleVersion:claim.schedule_version,occurrenceId:draft.occurrenceId,generation:claim.generation,workerOwnerHmac:claim.worker_owner_hmac,
      workflowId:b.workflowId,workflowPlanRevision:b.workflowPlanRevision,workflowPlanHash:b.workflowPlanHash,issuedAt:iso(claim.issued_at),authorityExpiresAt:iso(claim.authority_expires_at),initialLeaseUntil:iso(claim.initial_lease_until)});
      if(claim.id!==row.claim_id||claim.cluster_id!==b.clusterId||claim.workspace_id!==b.workspaceId||claim.schedule_id!==id||claim.occurrence_id!==draft.occurrenceId||claim.workflow_id!==b.workflowId
        ||claim.workflow_plan_revision!==b.workflowPlanRevision||claim.workflow_plan_hash!==b.workflowPlanHash)throw invalid();}
    const lease=row.claim_id?await tx.one<any>('SELECT * FROM workflow_schedule_leases WHERE claim_id=$1 ORDER BY lease_version DESC LIMIT 1',[row.claim_id]):null;
    if(row.claim_id&&(!lease||!activation)||lease&&(lease.cluster_id!==b.clusterId||lease.workspace_id!==b.workspaceId||lease.claim_id!==row.claim_id||lease.generation!==1||lease.worker_owner_hmac!==claim.worker_owner_hmac
      ||!uuid.test(lease.id)||!Number.isSafeInteger(lease.lease_version)||lease.lease_version<1||lease.lease_version===1&&lease.previous_id!==null||lease.lease_version>1&&!uuid.test(lease.previous_id)
      ||Date.parse(iso(lease.lease_until))>Date.parse(iso(claim.authority_expires_at))))throw invalid();
    if(!['pending-approval','active','claimed','running','succeeded','partial','failed','uncertain','blocked','cancelled','expired'].includes(row.state)||!Number.isSafeInteger(row.revision)||row.revision<1
      ||(['claimed','running','succeeded','partial','failed','uncertain'].includes(row.state)!==!!row.claim_id)||row.state==='active'&&!activation||row.state==='pending-approval'&&activation)throw invalid();
    return immutableJson({draft,plan,progress:{state:row.state,revision:row.revision,claimId:row.claim_id??null,reasonCode:row.reason_code??null},activation:activation?.activation??null,claim:claim?.claim??null,
      latestLease:lease?{id:lease.id,claimId:lease.claim_id,generation:lease.generation,workerOwnerHmac:lease.worker_owner_hmac,version:lease.lease_version,previousId:lease.previous_id,leaseUntil:iso(lease.lease_until)}:null});
  }
  private receipt(stored:Readonly<WorkflowScheduleStored>):WorkflowScheduleReceipt{const{draft:d,progress:p}=stored,b=d.binding;return immutableJson({id:d.scheduleId,revision:p.revision,state:p.state,kind:b.kind,
    workflowId:b.workflowId,workflowPlanRevision:b.workflowPlanRevision,workflowPlanHash:b.workflowPlanHash,requesterType:b.requester.type,requesterId:b.requester.id,executorId:d.delegation.executorId,
    notBefore:d.spec.notBefore,windowStart:d.spec.windowStart,windowEnd:d.spec.windowEnd,claimId:p.claimId,reasonCode:p.reasonCode,nativeAuthority:false});}
  private async lock(id:string,tx:DbService){const before=await this.inspectStored(id,tx);await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))",[before.draft.transportScope]);
    await tx.one('SELECT schedule_id FROM workflow_schedule_progress WHERE schedule_id=$1 FOR UPDATE',[id]);return this.inspectStored(id,tx);}
  private async event(stored:Readonly<WorkflowScheduleStored>,kind:string,tx:DbService,actor?:EntityActor){const d=stored.draft,b=d.binding,p=stored.progress;
    await tx.exec('INSERT INTO workflow_schedule_events(id,cluster_id,workspace_id,schedule_id,event_kind,actor_id,claim_id,reason_code) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[randomUUID(),b.clusterId,b.workspaceId,d.scheduleId,kind,actor?.user.id??d.delegation.executorId,p.claimId,p.reasonCode]);
    await this.audit.append({actorId:actor?.user.id??d.delegation.executorId,clusterId:b.clusterId,workspaceId:b.workspaceId,workflowId:b.workflowId,entityType:'workflows',entityId:b.workflowId,
      action:`workflow.business-schedule.${kind}`,result:['blocked','failed','partial'].includes(kind)?'failed':kind==='uncertain'?'uncertain':'success',requestId:actor?.requestId,ip:actor?.ip,
      after:{scheduleId:d.scheduleId,state:p.state,claimId:p.claimId,requesterType:b.requester.type,requesterId:b.requester.id,executorId:d.delegation.executorId,reasonCode:p.reasonCode},
      scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id:b.workflowId},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:b.workspaceId,afterWorkspaceId:b.workspaceId}},tx);}
  async persistDraft(draft:Readonly<WorkflowScheduleDraft>,actor:EntityActor,rootProof:object,tx?:DbService):Promise<WorkflowScheduleReceipt>{
    this.proof(rootProof);const policy=this.policy(),hash=this.secrets.fingerprint(draft),value=normalizeWorkflowScheduleDraft(draft,this.secrets),b=value.binding,d=value.delegation;
    return this.transaction(tx,async db=>{await this.iam(db);await policy.verifyDraft(draft,actor,rootProof,db);same(this.secrets,draft,value);
      if(actor.user.id!==d.ownerId||actor.workspaceId!==b.workspaceId)throw invalid('WORKFLOW_SCHEDULE_CONSOLE_OWNER_REQUIRED');
      const prior=await db.one<any>('SELECT id FROM workflow_schedules WHERE workflow_id=$1 AND workflow_plan_revision=$2',[b.workflowId,b.workflowPlanRevision]);
      if(prior){const stored=await this.inspectStored(prior.id,db);if(prior.id!==value.scheduleId)throw invalid();same(this.secrets,stored.draft,value);return this.receipt(stored);}
      await db.exec(`INSERT INTO workflow_executor_delegations(id,cluster_id,workspace_id,workflow_id,workflow_plan_revision,base_plan_hash,kind,subject_type,subject_id,requester_type,requester_id,requester_credential_epoch,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,spec_hmac,delegation_hmac,delegation_ciphertext,issued_at,expires_at,policy_hash,subject_seal_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,[d.id,b.clusterId,b.workspaceId,b.workflowId,b.workflowPlanRevision,b.basePlanHash,b.kind,b.subjectType,b.subjectId,b.requester.type,b.requester.id,b.requester.credentialEpoch,d.ownerId,d.executorId,d.ownerCredentialEpoch,d.executorCredentialEpoch,value.specHmac,value.delegationHmac,this.secrets.encrypt(d,workflowDelegationAad(b.clusterId,b.workspaceId,d.id)),d.issuedAt,d.expiresAt,d.policyHash,d.subjectSealHmac]);
      await db.exec(`INSERT INTO workflow_schedules(id,cluster_id,workspace_id,workflow_id,workflow_plan_revision,workflow_plan_hash,base_plan_hash,kind,delegation_id,delegation_hmac,spec_hmac,spec,not_before,window_start,window_end,expires_at,occurrence_id,transport_scope,impact_hmac,impact,draft_hmac,draft_ciphertext,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,requester_type,requester_id,requester_credential_epoch,subject_seal_hmac,definition_id,definition_version,policy_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)`,[value.scheduleId,b.clusterId,b.workspaceId,b.workflowId,b.workflowPlanRevision,b.workflowPlanHash,b.basePlanHash,b.kind,d.id,value.delegationHmac,value.specHmac,JSON.stringify(value.spec),value.spec.notBefore,value.spec.windowStart,value.spec.windowEnd,d.expiresAt,value.occurrenceId,value.transportScope,value.impactHmac,JSON.stringify(value.impact),hash,this.secrets.encrypt(value,workflowScheduleDraftAad(b.clusterId,b.workspaceId,value.scheduleId)),d.ownerId,d.executorId,d.ownerCredentialEpoch,d.executorCredentialEpoch,b.requester.type,b.requester.id,b.requester.credentialEpoch,d.subjectSealHmac,b.definitionId,b.definitionVersion,b.policyHash]);
      await db.exec('INSERT INTO workflow_schedule_progress(schedule_id,cluster_id,workspace_id) VALUES($1,$2,$3)',[value.scheduleId,b.clusterId,b.workspaceId]);
      const stored=await this.inspectStored(value.scheduleId,db);await this.event(stored,'draft',db,actor);await policy.verifyDraft(draft,actor,rootProof,db);same(this.secrets,draft,value);return this.receipt(stored);});
  }
  async activate(id:string,activation:Readonly<WorkflowScheduleActivation>,rootProof:object,tx?:DbService,actualActor?:EntityActor):Promise<WorkflowScheduleReceipt>{
    this.proof(rootProof);const policy=this.policy(),value=activationFact(activation);
    if(!actualActor||!uuid.test(actualActor.user?.id??''))throw invalid('WORKFLOW_SCHEDULE_ACTUAL_ACTIVATION_ACTOR_REQUIRED');
    return this.transaction(tx,async db=>{await this.iam(db);const stored=await this.lock(id,db),b=stored.draft.binding;await policy.verifyApproved(id,activation,rootProof,db,actualActor);
      if(actualActor.workspaceId!==b.workspaceId)throw invalid('WORKFLOW_SCHEDULE_ACTUAL_ACTIVATION_ACTOR_REQUIRED');
      if(stored.progress.state!=='pending-approval'||value.workflowId!==b.workflowId||value.workflowPlanRevision!==b.workflowPlanRevision||value.workflowPlanHash!==b.workflowPlanHash)throw invalid();
      await policy.verifyPhysicalReservation(id,rootProof,db);await db.exec(`INSERT INTO workflow_schedule_activations(schedule_id,cluster_id,workspace_id,workflow_id,workflow_plan_revision,workflow_plan_hash,approval_format,approval_set_id,approval_set_hmac,activation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,[id,b.clusterId,b.workspaceId,b.workflowId,b.workflowPlanRevision,b.workflowPlanHash,value.approvalFormat,value.approvalSetId,value.approvalSetHmac,JSON.stringify(value)]);
      await this.cas(id,stored.progress.revision,'active',db);const current=await this.inspectStored(id,db);await this.event(current,'activated',db,actualActor);
      await policy.verifyApproved(id,activation,rootProof,db,actualActor);same(this.secrets,activation,value);return this.receipt(current);});
  }
  private async cas(id:string,revision:number,state:string,db:DbService,claimId?:string,reason?:string){if(await db.exec('UPDATE workflow_schedule_progress SET state=$3,claim_id=COALESCE($4::uuid,claim_id),reason_code=$5,revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id=$1 AND revision=$2',[id,revision,state,claimId??null,reason??null])!==1)throw invalid('WORKFLOW_SCHEDULE_STATE_CHANGED');}
  async appendDueClaim(id:string,claim:Readonly<WorkflowScheduleClaim>,rootProof:object,tx?:DbService):Promise<WorkflowScheduleClaim>{
    this.proof(rootProof);const policy=this.policy(),value=claimFact(claim);if(value.scheduleId!==id)throw invalid();
    return this.transaction(tx,async db=>{await this.iam(db);const stored=await this.lock(id,db),b=stored.draft.binding;await policy.verifyClaim(id,claim,rootProof,db);
      if(stored.progress.state!=='active'||stored.progress.claimId||stored.draft.occurrenceId!==value.occurrenceId||value.workflowId!==b.workflowId||value.workflowPlanRevision!==b.workflowPlanRevision||value.workflowPlanHash!==b.workflowPlanHash)throw invalid('WORKFLOW_SCHEDULE_OCCURRENCE_ALREADY_CLAIMED');
      await policy.verifyPhysicalReservation(id,rootProof,db);await db.exec('INSERT INTO workflow_schedule_claims(id,cluster_id,workspace_id,schedule_id,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,issued_at,authority_expires_at,initial_lease_until,claim) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)',[value.id,b.clusterId,b.workspaceId,id,value.occurrenceId,value.workerOwnerHmac,b.workflowId,b.workflowPlanRevision,b.workflowPlanHash,value.issuedAt,value.authorityExpiresAt,value.initialLeaseUntil,JSON.stringify(value)]);
      await db.exec('INSERT INTO workflow_schedule_leases(id,cluster_id,workspace_id,claim_id,generation,worker_owner_hmac,lease_version,previous_id,lease_until) VALUES($1,$2,$3,$4,1,$5,1,NULL,$6)',[randomUUID(),b.clusterId,b.workspaceId,value.id,value.workerOwnerHmac,value.initialLeaseUntil]);
      await this.cas(id,stored.progress.revision,'claimed',db,value.id);await this.event(await this.inspectStored(id,db),'claimed',db);same(this.secrets,claim,value);return value;});
  }
  async extendLease(claimId:string,ownerHmac:string,generation:number,until:string,rootProof:object,tx?:DbService):Promise<{leaseId:string;leaseVersion:number;leaseUntil:string}>{
    this.proof(rootProof);const policy=this.policy();if(!uuid.test(claimId)||!hex.test(ownerHmac)||generation!==1||iso(until)!==until)throw invalid();
    return this.transaction(tx,async db=>{await this.iam(db);await db.exec("SELECT pg_advisory_xact_lock(hashtextextended('workflow-schedule-claim:'||$1,0))",[claimId]);
      const claim=await db.one<any>('SELECT * FROM workflow_schedule_claims WHERE id=$1',[claimId]);if(!claim||claim.worker_owner_hmac!==ownerHmac||claim.generation!==1)throw invalid();
      const stored=await this.inspectStored(claim.schedule_id,db),prior=stored.latestLease;if(!prior||stored.progress.claimId!==claimId||!['claimed','running'].includes(stored.progress.state)
        ||Date.parse(prior.leaseUntil)<=Date.now()||Date.parse(until)<=Date.parse(prior.leaseUntil)||Date.parse(until)>Date.parse(iso(claim.authority_expires_at)))throw invalid('WORKFLOW_SCHEDULE_LEASE_CANNOT_RECLAIM');
      await policy.verifyLease(claimId,ownerHmac,generation,until,rootProof,db);const id=randomUUID(),version=prior.version+1,b=stored.draft.binding;
      await db.exec('INSERT INTO workflow_schedule_leases(id,cluster_id,workspace_id,claim_id,generation,worker_owner_hmac,lease_version,previous_id,lease_until) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8)',[id,b.clusterId,b.workspaceId,claimId,ownerHmac,version,prior.id,until]);
      await this.event(stored,'lease-extended',db);return{leaseId:id,leaseVersion:version,leaseUntil:until};});
  }
  async finishClaim(claimId:string,outcome:WorkflowScheduleTerminalOutcome,rootProof:object,tx?:DbService):Promise<WorkflowScheduleReceipt>{
    this.proof(rootProof);const policy=this.policy();if(!uuid.test(claimId)||!['succeeded','partial','failed','uncertain'].includes(outcome))throw invalid();
    return this.transaction(tx,async db=>{const claim=await db.one<any>('SELECT schedule_id FROM workflow_schedule_claims WHERE id=$1',[claimId]);if(!claim)throw invalid();
      const stored=await this.lock(claim.schedule_id,db),evidence=immutableJson(await policy.verifyOutcome(claimId,outcome,rootProof,db));
      if(!keys(evidence,['version','provenance','evidenceHmac'])||evidence.version!==1||!hex.test(evidence.evidenceHmac)||!['original-execution','callback-not-entered'].includes(evidence.provenance)
        ||evidence.provenance==='callback-not-entered'&&outcome!=='failed')throw invalid('WORKFLOW_SCHEDULE_ORIGINAL_OUTCOME_REQUIRED');
      if(!['claimed','running'].includes(stored.progress.state)||stored.progress.claimId!==claimId)throw invalid('WORKFLOW_SCHEDULE_OUTCOME_ALREADY_CLOSED');
      const b=stored.draft.binding;await db.exec('INSERT INTO workflow_schedule_outcomes(id,cluster_id,workspace_id,schedule_id,claim_id,outcome,provenance,evidence_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[randomUUID(),b.clusterId,b.workspaceId,stored.draft.scheduleId,claimId,outcome,evidence.provenance,evidence.evidenceHmac]);
      await this.cas(stored.draft.scheduleId,stored.progress.revision,outcome,db);const current=await this.inspectStored(stored.draft.scheduleId,db);await this.event(current,outcome,db);
      same(this.secrets,evidence,await policy.verifyOutcome(claimId,outcome,rootProof,db));return this.receipt(current);});
  }
  async cancel(id:string,actor:EntityActor,tx?:DbService):Promise<WorkflowScheduleReceipt>{const policy=this.policy();return this.transaction(tx,async db=>{await this.iam(db);const stored=await this.lock(id,db);
    await policy.verifyCancellation(id,actor,db);if(actor.workspaceId!==stored.draft.binding.workspaceId||actor.user.id!==stored.draft.delegation.ownerId||stored.progress.claimId||!['pending-approval','active'].includes(stored.progress.state))throw invalid('WORKFLOW_SCHEDULE_CANCEL_NOT_AVAILABLE');
    await this.cas(id,stored.progress.revision,'cancelled',db);const current=await this.inspectStored(id,db);await this.event(current,'cancelled',db,actor);return this.receipt(current);});}
  async appendBlocked(id:string,reason:string,rootProof:object,tx?:DbService):Promise<WorkflowScheduleReceipt>{this.proof(rootProof);const policy=this.policy();if(!/^[A-Z0-9_]{1,128}$/.test(reason))throw invalid();
    return this.transaction(tx,async db=>{await this.iam(db);const stored=await this.lock(id,db);await policy.verifyBlocked(id,reason,rootProof,db);if(stored.progress.claimId||!['pending-approval','active'].includes(stored.progress.state))throw invalid();
      const state=reason==='WORKFLOW_SCHEDULE_WINDOW_EXPIRED'?'expired':'blocked';await this.cas(id,stored.progress.revision,state,db,undefined,reason);const current=await this.inspectStored(id,db);await this.event(current,state,db);return this.receipt(current);});}
  async get(id:string,actor:EntityActor,tx=this.db):Promise<WorkflowScheduleReceipt>{await this.policy().assertRead(id,actor,tx);const stored=await this.inspectStored(id,tx);if(actor.workspaceId!==stored.draft.binding.workspaceId)throw invalid();return this.receipt(stored);}
  async listDue(limit=25):Promise<string[]>{this.policy();if(!Number.isInteger(limit)||limit<1||limit>25)throw invalid();return(await this.db.query<{id:string}>(`SELECT s.id FROM workflow_schedules s JOIN workflow_schedule_progress p ON p.schedule_id=s.id WHERE p.state='active' AND p.claim_id IS NULL AND s.not_before<=clock_timestamp() ORDER BY s.not_before,s.id LIMIT $1`,[limit])).map(r=>r.id);}
}
