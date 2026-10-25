import { expect, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { DbService } from '../../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../../apps/console-api/src/infrastructure/secret.service';
import { normalizeWorkflowApprovalPolicy } from '../../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import { planAad, type WorkflowPlanV1 } from '../../../apps/console-api/src/modules/workflows/workflow.types';
import type { ConfigPlan, ConfigurationPlanStep } from '../../../apps/console-api/src/modules/configuration/configuration.types';
import { ConfigurationDurableCodec, durableConfigurationLocator } from '../../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import { ConfigurationDurableRepository, configurationDurableMarker, DURABLE_BINDING_QUERY, DURABLE_ISSUE_QUERY } from '../../../apps/console-api/src/modules/configuration/configuration-durable.repository';
import type { DurableConfigurationEnvelope } from '../../../apps/console-api/src/modules/configuration/configuration-durable.types';

export const NOW=Date.parse('2026-10-15T20:00:00.000Z');
const POLICY_QUERY='SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4';
const PLAN_QUERY='SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4';
const SNAPSHOT_QUERY='SELECT v.manifest_hmac,v.consistency,v.completeness,s.state AS snapshot_state,m.state AS material_state FROM config_snapshot_versions v JOIN config_snapshots s ON s.id=v.snapshot_id AND s.cluster_id=v.cluster_id AND s.workspace_id=v.workspace_id JOIN configuration_materials m ON m.id=v.material_id AND m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4';
const JOB_QUERY='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3';
const WORKFLOW_QUERY='SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3';
const WORKFLOW_VERSION_QUERY='SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4';
const INSERT_BINDING=`INSERT INTO configuration_durable_bindings(issue_id,cluster_id,workspace_id,job_id,plan_id,plan_revision,plan_hash,
      workflow_id,workflow_plan_revision,workflow_plan_hash,baseline_snapshot_id,baseline_version,baseline_manifest_hmac,material_hmac,envelope_ciphertext)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`;

export function createDurableRepositoryFixture(){
  const secrets=new SecretService(),repository=new ConfigurationDurableRepository(secrets),codec=new ConfigurationDurableCodec(secrets);
  const ids={issue:randomUUID(),cluster:randomUUID(),workspace:randomUUID(),job:randomUUID(),owner:randomUUID(),sid:randomUUID(),
    definition:randomUUID(),sourceJob:randomUUID(),sourcePlan:randomUUID(),snapshot:randomUUID(),plan:randomUUID(),workflow:randomUUID(),service:randomUUID(),reviewer:randomUUID()};
  const issuedAt=new Date(NOW).toISOString(),expiresAt=new Date(NOW+24*3_600_000).toISOString();
  const policy=normalizeWorkflowApprovalPolicy({version:2,kind:'configuration_v2',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,
    stages:[{level:1,name:'Configuration approval',mode:'any',threshold:1,selector:{users:[ids.reviewer]}}]},'configuration_v2');
  const before={id:ids.service,name:'before',host:'upstream.internal',tags:['workspace:test']};
  const body={name:'after'},scope={clusterId:ids.cluster,workspaceId:ids.workspace,transportScope:secrets.fingerprint('fixture-transport'),kind:'services' as const,rootIds:[ids.service]};
  const packet={method:'PATCH' as const,canonicalPath:`/services/${ids.service}`,body,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before)};
  const step:ConfigurationPlanStep={stepId:randomUUID(),stepOrder:1,objectKey:`services:${ids.service}`,entityType:'services',objectWorkspaceId:ids.workspace,
    clearMap:[],nativeId:ids.service,permissionAction:'write',mutationAction:'update',dependencies:[],body,before,
    bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac,nativeRequests:[packet],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
  const baselineHmac=secrets.fingerprint({fixture:'complete-fresh-baseline'});
  const plan:ConfigPlan={durableRef:{version:1,domain:'durable-configuration-v1',issueId:ids.issue},scope,mode:'merge',steps:[step],
    sourceManifestHmac:secrets.fingerprint({fixture:'new-source-manifest'}),baselineManifestHmac:baselineHmac,schemaHmac:secrets.fingerprint({fixture:'schemas'}),
    permissionVersion:`${ids.owner}:1:1`,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt};
  const e:DurableConfigurationEnvelope={domain:'durable-configuration-v1',envelopeVersion:1,issueId:ids.issue,clusterId:ids.cluster,workspaceId:ids.workspace,
    jobId:ids.job,ownerId:ids.owner,authoringSessionId:ids.sid,credentialEpoch:1,permissionVersion:plan.permissionVersion,issuedAt,admissionExpiresAt:new Date(NOW+90_000).toISOString(),expiresAt,
    policy:{definitionId:ids.definition,version:1,hash:secrets.fingerprint(policy),intentTtlHours:24},
    provenance:{jobId:ids.sourceJob,planId:ids.sourcePlan,planRevision:1,planHash:secrets.fingerprint({fixture:'historical-provenance-plan'}),kind:'import'},
    baseline:{snapshotId:ids.snapshot,version:1,manifestHmac:baselineHmac},recipeHmac:secrets.fingerprint({fixture:'recipe'}),schemaHmac:plan.schemaHmac,
    scopeHmac:secrets.fingerprint(plan.scope),plan:{planId:ids.plan,planRevision:1,planHash:secrets.fingerprint(plan),stepsHmac:secrets.fingerprint(plan.steps),
      sourceManifestHmac:plan.sourceManifestHmac,baselineManifestHmac:baselineHmac}};
  const workflow:WorkflowPlanV1={version:1,clusterId:ids.cluster,workspaceId:ids.workspace,workflowId:ids.workflow,planRevision:1,kind:'configuration_v2',
    executionMode:'approval',approvalRequired:true,subject:{type:'configuration_jobs',id:ids.job},requester:{type:'console',id:ids.owner},
    definition:{id:ids.definition,version:1,policyHash:e.policy.hash},issuedAt,expiresAt,scope:{transportScope:scope.transportScope,clusterRevision:1,workspaceRevision:1},
    prerequisites:[],steps:[{id:randomUUID(),key:'configuration',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:ids.job,
      permissionAction:'write',dependencies:[],nativeRequests:[],metadata:{jobId:ids.job,planId:ids.plan,planRevision:1,planHash:e.plan.planHash}}]};
  const seal=codec.seal(e,durableConfigurationLocator(e),NOW);
  const job:any={id:ids.job,cluster_id:ids.cluster,workspace_id:ids.workspace,actor_id:ids.owner,origin_session_id:ids.sid,credential_epoch:1,
    permission_version:e.permissionVersion,authority_expires_at:expiresAt,expires_at:expiresAt,authority_domain:e.domain,durable_issue_id:ids.issue,
    kind:'apply',origin_type:'http',execution_mode:'approval',approval_required:true,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,
    plan_id:ids.plan,plan_revision:1,plan_hash:e.plan.planHash,workflow_id:ids.workflow};
  const rows:any={job,
    issue:{id:ids.issue,cluster_id:ids.cluster,workspace_id:ids.workspace,job_id:ids.job,owner_id:ids.owner,authoring_session_id:ids.sid,credential_epoch:1,
      permission_version:e.permissionVersion,issued_at:issuedAt,admission_expires_at:e.admissionExpiresAt,expires_at:expiresAt,definition_id:ids.definition,definition_version:1,policy_hash:e.policy.hash,intent_ttl_hours:24,
      source_job_id:ids.sourceJob,source_plan_id:ids.sourcePlan,source_plan_revision:1,source_plan_hash:e.provenance.planHash,source_kind:'import'},
    binding:{issue_id:ids.issue,cluster_id:ids.cluster,workspace_id:ids.workspace,job_id:ids.job,plan_id:ids.plan,plan_revision:1,plan_hash:e.plan.planHash,
      workflow_id:ids.workflow,workflow_plan_revision:1,workflow_plan_hash:secrets.fingerprint(workflow),baseline_snapshot_id:ids.snapshot,baseline_version:1,
      baseline_manifest_hmac:baselineHmac,envelope_ciphertext:seal.ciphertext,material_hmac:seal.materialHmac},
    policy:{cluster_id:ids.cluster,workspace_id:ids.workspace,definition_id:ids.definition,version:1,approval_format:2,policy_hash:e.policy.hash,policy:structuredClone(policy)},
    plan:{cluster_id:ids.cluster,workspace_id:ids.workspace,plan_id:ids.plan,plan_revision:1,source_job_id:ids.job,plan_hash:e.plan.planHash,
      steps_hmac:e.plan.stepsHmac,schema_hmac:e.schemaHmac,source_manifest_hmac:e.plan.sourceManifestHmac,baseline_manifest_hmac:baselineHmac,expires_at:expiresAt},
    snapshot:{manifest_hmac:baselineHmac,consistency:'console_fenced_best_effort',completeness:'complete',snapshot_state:'ready',material_state:'available'},
    workflow:{id:ids.workflow,cluster_id:ids.cluster,workspace_id:ids.workspace,plan_revision:workflow.planRevision,plan_hash:secrets.fingerprint(workflow)},
    workflowVersions:{'1':{workflow_id:ids.workflow,cluster_id:ids.cluster,workspace_id:ids.workspace,plan_revision:1,plan_hash:secrets.fingerprint(workflow),
      payload_secret:secrets.encrypt(workflow,planAad(ids.cluster,ids.workspace,ids.workflow,1))}}};
  const queries=new Map<string,{args:unknown[];key:string}>([
    [DURABLE_ISSUE_QUERY,{args:[ids.issue,ids.cluster,ids.workspace,ids.job],key:'issue'}],
    [DURABLE_BINDING_QUERY,{args:[ids.issue,ids.cluster,ids.workspace,ids.job],key:'binding'}],
    [POLICY_QUERY,{args:[ids.cluster,ids.workspace,ids.definition,1],key:'policy'}],
    [PLAN_QUERY,{args:[ids.cluster,ids.workspace,ids.plan,1],key:'plan'}],
    [SNAPSHOT_QUERY,{args:[ids.cluster,ids.workspace,ids.snapshot,1],key:'snapshot'}],
    [JOB_QUERY,{args:[ids.job,ids.cluster,ids.workspace],key:'job'}],
    [WORKFLOW_QUERY,{args:[ids.workflow,ids.cluster,ids.workspace],key:'workflow'}],
  ]);
  const one=vi.fn(async(sql:string,args:unknown[])=>{
    if(sql===WORKFLOW_VERSION_QUERY){
      expect(args.slice(0,3)).toEqual([ids.workflow,ids.cluster,ids.workspace]);expect(args).toHaveLength(4);
      if(args[3]!==1&&args[3]!==2)throw new Error('UNEXPECTED_EXACT_SQL_ARGUMENTS');
      return structuredClone(rows.workflowVersions[String(args[3])]??null);
    }
    const q=queries.get(sql);if(!q)throw new Error('UNEXPECTED_EXACT_SQL_QUERY');
    expect(args).toEqual(q.args);return structuredClone(rows[q.key]);
  });
  const exec=vi.fn(async()=>{throw new Error('UNEXPECTED_EXACT_SQL_EXEC');});
  const query=vi.fn(async()=>{throw new Error('UNEXPECTED_EXACT_SQL_QUERY');});
  const tx={one,exec,query} as unknown as DbService;
  return {secrets,repository,codec,e,plan,workflow,job,rows,ids,tx,one,exec,query,queries};
}
