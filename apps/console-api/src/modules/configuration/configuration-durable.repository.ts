import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { planAad, type WorkflowPlanV1 } from '../workflows/workflow.types';
import { assertConfigurationWorkflowPlan } from '../workflows/configuration-workflow';
import { ConfigurationDurableCodec, durableConfigurationLocator } from './configuration-durable.codec';
import { CONFIGURATION_DURABLE_DOMAIN, type DurableConfigurationEnvelope } from './configuration-durable.types';
import type { ConfigPlan } from './configuration.types';

const fail = (code='CONFIGURATION_DURABLE_BINDING_INVALID') => new ForbiddenException({code});
const iso = (value:any) => new Date(value).toISOString();
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/;
export const DURABLE_CONFIGURATION_PRESENCE_QUERY = `SELECT j.authority_domain,j.durable_issue_id,
 EXISTS(SELECT 1 FROM configuration_durable_issues i WHERE i.cluster_id=j.cluster_id AND i.workspace_id=j.workspace_id AND i.job_id=j.id) AS has_durable_issue,
 EXISTS(SELECT 1 FROM configuration_durable_bindings b WHERE b.cluster_id=j.cluster_id AND b.workspace_id=j.workspace_id AND b.job_id=j.id) AS has_durable_binding
 FROM configuration_jobs j WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3`;
export function isProvenLegacyConfigurationRow(row:any):boolean{return !!row&&row.authority_domain===null&&row.durable_issue_id===null
 &&row.has_durable_issue===false&&row.has_durable_binding===false;}
export const DURABLE_ISSUE_QUERY = 'SELECT * FROM configuration_durable_issues WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND job_id=$4';
export const DURABLE_BINDING_QUERY = 'SELECT * FROM configuration_durable_bindings WHERE issue_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND job_id=$4';
/** Unknown and partial markers always fail closed. A JSON descriptor is never authority. */
export function configurationDurableMarker(job:any): string|null {
  if(job.authority_domain==null && job.durable_issue_id==null)return null;
  if(job.authority_domain!==CONFIGURATION_DURABLE_DOMAIN||!uuid.test(job.durable_issue_id??'')
    ||!['apply','rollback'].includes(job.kind)||job.origin_type!=='http'||job.execution_mode!=='approval'||job.approval_required!==true
    ||job.required_origin_kind!=null||job.required_origin_id!=null||job.required_origin_hmac!=null)throw fail();
  return job.durable_issue_id;
}
/** SQL/AEAD-only verifier reused by HTTP access, stored workflow delegates,
 * repository reads and the real scheduled material compiler. It grants no SID,
 * claim, Native capability or permission and never calls Kong. */
@Injectable()
export class ConfigurationDurableRepository {
  private readonly codec:ConfigurationDurableCodec;
  constructor(private readonly secrets:SecretService){this.codec=new ConfigurationDurableCodec(secrets);}
  private same(a:unknown,b:unknown):void{if(this.secrets.fingerprint(a??null)!==this.secrets.fingerprint(b??null))throw fail();}
  async issue(job:any,tx:DbService):Promise<any>{
    const id=configurationDurableMarker(job);if(!id)return null;
    const i=await tx.one<any>(DURABLE_ISSUE_QUERY,[id,job.cluster_id,job.workspace_id,job.id]);
    if(!i||i.id!==id||i.job_id!==job.id||i.owner_id!==job.actor_id||i.authoring_session_id!==job.origin_session_id
      ||Number(i.credential_epoch)!==job.credential_epoch||i.permission_version!==job.permission_version
      ||iso(i.expires_at)!==iso(job.authority_expires_at)||iso(i.expires_at)!==iso(job.expires_at))throw fail();
    return i;
  }
  async verify(job:any,tx:DbService,current:boolean,providedPlan?:ConfigPlan):Promise<DurableConfigurationEnvelope|null>{
    const id=configurationDurableMarker(job);
    if(!id){if(providedPlan?.durableRef!==undefined)throw fail();return null;}
    const i=await this.issue(job,tx),b=await tx.one<any>(DURABLE_BINDING_QUERY,[id,job.cluster_id,job.workspace_id,job.id]);
    if(!b||b.issue_id!==id||b.job_id!==job.id||b.plan_id!==job.plan_id||b.plan_revision!==job.plan_revision||b.plan_hash!==job.plan_hash
      ||b.workflow_id!==job.workflow_id)throw fail();
    let e:DurableConfigurationEnvelope;try{e=this.codec.open({ciphertext:b.envelope_ciphertext,materialHmac:b.material_hmac},
      {domain:CONFIGURATION_DURABLE_DOMAIN,envelopeVersion:1,issueId:id,clusterId:job.cluster_id,workspaceId:job.workspace_id,
        jobId:job.id,planId:b.plan_id,planRevision:b.plan_revision,planHash:b.plan_hash},current?Date.now():Date.parse(iso(i.issued_at)));}catch{throw fail();}
    this.same(e.policy,{definitionId:i.definition_id,version:i.definition_version,hash:i.policy_hash,intentTtlHours:i.intent_ttl_hours});
    this.same(e.provenance,{jobId:i.source_job_id,planId:i.source_plan_id,planRevision:i.source_plan_revision,planHash:i.source_plan_hash,kind:i.source_kind});
    if(e.ownerId!==job.actor_id||e.authoringSessionId!==job.origin_session_id||e.credentialEpoch!==job.credential_epoch||e.permissionVersion!==job.permission_version
      ||e.issuedAt!==iso(i.issued_at)||e.admissionExpiresAt!==iso(i.admission_expires_at)||e.expiresAt!==iso(i.expires_at)||e.baseline.snapshotId!==b.baseline_snapshot_id
      ||e.baseline.version!==b.baseline_version||e.baseline.manifestHmac!==b.baseline_manifest_hmac)throw fail();
    const policy=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',
      [e.clusterId,e.workspaceId,e.policy.definitionId,e.policy.version]);
    if(!policy||policy.approval_format!==2||policy.policy_hash!==e.policy.hash||this.secrets.fingerprint(policy.policy)!==e.policy.hash
      ||policy.policy?.kind!=='configuration_v2'||policy.policy.version!==2||policy.policy.intentTtlHours!==e.policy.intentTtlHours)throw fail();
    const v=await tx.one<any>('SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4',
      [e.clusterId,e.workspaceId,e.plan.planId,e.plan.planRevision]);
    if(!v||v.source_job_id!==job.id||v.plan_hash!==e.plan.planHash||v.steps_hmac!==e.plan.stepsHmac||v.schema_hmac!==e.schemaHmac
      ||v.source_manifest_hmac!==e.plan.sourceManifestHmac||v.baseline_manifest_hmac!==e.plan.baselineManifestHmac||iso(v.expires_at)!==e.expiresAt)throw fail();
    const s=await tx.one<any>('SELECT v.manifest_hmac,v.consistency,v.completeness,s.state AS snapshot_state,m.state AS material_state FROM config_snapshot_versions v JOIN config_snapshots s ON s.id=v.snapshot_id AND s.cluster_id=v.cluster_id AND s.workspace_id=v.workspace_id JOIN configuration_materials m ON m.id=v.material_id AND m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4',
      [e.clusterId,e.workspaceId,e.baseline.snapshotId,e.baseline.version]);
    if(!s||s.manifest_hmac!==e.baseline.manifestHmac||s.consistency!=='console_fenced_best_effort'||s.completeness!=='complete'||current&&(s.snapshot_state!=='ready'||s.material_state!=='available'))throw fail();
    if(providedPlan){this.same(providedPlan.durableRef,{version:1,domain:CONFIGURATION_DURABLE_DOMAIN,issueId:id});
      if(this.secrets.fingerprint(providedPlan)!==e.plan.planHash||this.secrets.fingerprint(providedPlan.steps)!==e.plan.stepsHmac
        ||this.secrets.fingerprint(providedPlan.scope)!==e.scopeHmac||providedPlan.expiresAt!==e.expiresAt||providedPlan.originRef!==undefined)throw fail();}
    return e;
  }
  async verifyWorkflow(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    const step=assertConfigurationWorkflowPlan(plan),j=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',
      [plan.subject.id,plan.clusterId,plan.workspaceId]);
    if(!j)throw fail();const e=await this.verify(j,tx,false);if(!e)return;
    const m=step.metadata as any;
    if(j.workflow_id!==plan.workflowId||m.jobId!==j.id||m.planId!==e.plan.planId||m.planRevision!==e.plan.planRevision||m.planHash!==e.plan.planHash
      ||plan.expiresAt!==e.expiresAt||plan.requester.id!==e.ownerId||plan.definition.id!==e.policy.definitionId
      ||plan.definition.version!==e.policy.version||plan.definition.policyHash!==e.policy.hash)throw fail();
    const w=await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.workflowId,plan.clusterId,plan.workspaceId]);
    const v=await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4',
      [plan.workflowId,plan.clusterId,plan.workspaceId,plan.planRevision]);
    const b=await tx.one<any>(DURABLE_BINDING_QUERY,[e.issueId,e.clusterId,e.workspaceId,e.jobId]);
    if(!w||!v||!b||w.plan_revision!==plan.planRevision||w.plan_hash!==this.secrets.fingerprint(plan)||v.plan_hash!==w.plan_hash
      ||plan.planRevision<b.workflow_plan_revision||plan.planRevision===b.workflow_plan_revision&&w.plan_hash!==b.workflow_plan_hash)throw fail();
    let decoded:unknown;try{decoded=this.secrets.decrypt(v.payload_secret,planAad(plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision));}catch{throw fail();}
    this.same(decoded,plan);
    const initial=await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4',
      [plan.workflowId,plan.clusterId,plan.workspaceId,b.workflow_plan_revision]);
    if(!initial||initial.plan_hash!==b.workflow_plan_hash)throw fail();
    try{if(this.secrets.fingerprint(this.secrets.decrypt(initial.payload_secret,planAad(plan.clusterId,plan.workspaceId,plan.workflowId,b.workflow_plan_revision)))!==b.workflow_plan_hash)throw fail();}catch{throw fail();}
  }
  /** Invoked only by WorkflowPlans' separate bootstrap callback after its
   * original SQL029 proposal verifier. This is source validation, never a
   * claim or an assertion that the proposed version has been persisted. */
  async verifyScheduledProposal(plan:WorkflowPlanV1,base:WorkflowPlanV1,tx:DbService):Promise<void>{
    await this.verifyWorkflow(base,tx);
    const row=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[base.subject.id,base.clusterId,base.workspaceId]);
    if(!row||!configurationDurableMarker(row))return;
    if(!(plan as any).scheduling||plan.planRevision!==base.planRevision+1||!plan.steps[0]||plan.issuedAt<=base.issuedAt
      ||Date.parse(plan.issuedAt)>Date.now())throw fail();
    const expected={...base,planRevision:plan.planRevision,issuedAt:plan.issuedAt,steps:[{...base.steps[0],id:plan.steps[0].id}],scheduling:(plan as any).scheduling};
    this.same(expected,plan);
  }
  async bind(tx:DbService,e:DurableConfigurationEnvelope,workflow:WorkflowPlanV1):Promise<void>{
    const seal=this.codec.seal(e,durableConfigurationLocator(e),Date.now());
    await tx.exec(`INSERT INTO configuration_durable_bindings(issue_id,cluster_id,workspace_id,job_id,plan_id,plan_revision,plan_hash,
      workflow_id,workflow_plan_revision,workflow_plan_hash,baseline_snapshot_id,baseline_version,baseline_manifest_hmac,material_hmac,envelope_ciphertext)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[e.issueId,e.clusterId,e.workspaceId,e.jobId,e.plan.planId,e.plan.planRevision,e.plan.planHash,
      workflow.workflowId,workflow.planRevision,this.secrets.fingerprint(workflow),e.baseline.snapshotId,e.baseline.version,e.baseline.manifestHmac,seal.materialHmac,seal.ciphertext]);
  }
}
