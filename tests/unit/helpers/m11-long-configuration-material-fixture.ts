import { randomUUID } from 'node:crypto';
import { expect, vi } from 'vitest';
import { SecretService } from '../../../apps/console-api/src/infrastructure/secret.service';
import { SnapshotCryptoService } from '../../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import { ConfigurationDurableCodec, durableConfigurationLocator } from '../../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import { CONFIGURATION_DURABLE_DOMAIN, type DurableConfigurationEnvelope } from '../../../apps/console-api/src/modules/configuration/configuration-durable.types';
import { normalizeWorkflowApprovalPolicy } from '../../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import { WorkflowBusinessMaterialService } from '../../../apps/console-api/src/modules/workflows/workflow-business-material.service';
import { WorkflowScheduledConfigurationOriginService } from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';

/** Original production Snapshot AES-GCM, durable codec/SQL verifier and both
 * material readers. SQL rows are controlled immutable fixtures; no Native,
 * current authorization, actual PG or real >15m runtime claim is asserted. */
export async function longConfigurationMaterialFixture(durable=true,options:{omitPlanRef?:boolean;legacyPlanRef?:boolean}={}){
 const secrets=new SecretService(),crypto=new SnapshotCryptoService(secrets),hash=(value:unknown)=>secrets.fingerprint(value),now=Date.now();
 const ids=Object.fromEntries(['cluster','workspace','job','plan','material','artifact','actor','sid','workflow','issue','definition','reviewer','sourceJob','sourcePlan','baseline','service','step'].map(key=>[key,randomUUID()]));
 const authored=now-(durable?20*60_000:60_000),issuedAt=new Date(authored).toISOString(),expiresAt=new Date(authored+(durable?24*3_600_000:14*60_000)).toISOString();
 const policy=normalizeWorkflowApprovalPolicy({version:2,kind:'configuration_v2',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,
  stages:[{level:1,name:'Approval',mode:'any',threshold:1,selector:{users:[ids.reviewer]}}]},'configuration_v2');
 const before={id:ids.service,name:'before',host:'192.0.2.40',tags:['workspace:one']},body={name:'after'},scope={clusterId:ids.cluster,workspaceId:ids.workspace,transportScope:hash('fixture-transport'),kind:'workspace',rootIds:[]};
 const packet={method:'PATCH',canonicalPath:`/services/${ids.service}`,body,bodyHmac:hash(body),beforeHmac:hash(before)};
 const step:any={stepId:ids.step,stepOrder:1,objectKey:`services:${ids.service}`,entityType:'services',objectWorkspaceId:ids.workspace,nativeId:ids.service,allocatedNativeId:null,parentId:null,credentialKind:null,
  clearMap:[],permissionAction:'write',mutationAction:'update',dependencies:[],body,before,bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac,nativeRequests:[packet],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
 const plan:any={scope,mode:'merge',steps:[step],sourceManifestHmac:hash('source'),baselineManifestHmac:hash('baseline'),schemaHmac:hash('schema'),permissionVersion:`${ids.actor}:1:1`,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt,
  ...((durable&&!options.omitPlanRef)||options.legacyPlanRef?{durableRef:{version:1,domain:CONFIGURATION_DURABLE_DOMAIN,issueId:ids.issue}}:{})};
 const job:any={id:ids.job,cluster_id:ids.cluster,workspace_id:ids.workspace,actor_id:ids.actor,origin_session_id:ids.sid,origin_type:'http',authority_expires_at:expiresAt,expires_at:expiresAt,
  kind:'apply',idempotency_key:'fixture-original-job',request_hmac:hash('request'),input_secret:null,scope_kind:scope.kind,root_ids:[],transport_scope:scope.transportScope,
  permission_version:plan.permissionVersion,credential_epoch:1,cluster_revision:1,workspace_revision:1,capture_epoch:hash('capture'),execution_mode:'approval',approval_required:true,
  plan_id:ids.plan,plan_revision:1,plan_hash:hash(plan),workflow_id:ids.workflow,authority_domain:durable?CONFIGURATION_DURABLE_DOMAIN:null,durable_issue_id:durable?ids.issue:null,
  required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,created_at:issuedAt};
 const identity={clusterId:ids.cluster,workspaceId:ids.workspace,jobId:ids.job,materialId:ids.material,artifactId:ids.artifact,artifactKind:'plan' as const};
 const wrapped=crypto.createWrappedKey(identity),cipher=await crypto.withKey(identity,wrapped,async key=>({manifest:crypto.encrypt(key,identity,{section:'manifest',key:'plan'},plan),
  step:crypto.encrypt(key,identity,{section:'plan-step',key:ids.step,entityType:'services',nativeId:ids.service,parentId:null,credentialKind:null},step)}));
 const version:any={cluster_id:ids.cluster,workspace_id:ids.workspace,plan_id:ids.plan,plan_revision:1,plan_hash:job.plan_hash,input_hmac:job.plan_hash,source_job_id:ids.job,material_id:ids.material,artifact_id:ids.artifact,
  steps_hmac:hash(plan.steps),schema_hmac:plan.schemaHmac,source_manifest_hmac:plan.sourceManifestHmac,baseline_manifest_hmac:plan.baselineManifestHmac,step_count:1,native_packet_count:1,manifest_ciphertext:cipher.manifest,created_at:issuedAt,expires_at:expiresAt};
 const objects=[{cluster_id:ids.cluster,workspace_id:ids.workspace,plan_id:ids.plan,plan_revision:1,step_id:ids.step,step_order:1,object_workspace_id:ids.workspace,entity_type:'services',mutation_action:'update',
  body_hmac:step.bodyHmac,before_hmac:step.beforeHmac,reference_only:false,blocker_codes:[],dependencies:[],native_id:ids.service,allocated_native_id:null,parent_id:null,credential_kind:null,payload_ciphertext:cipher.step,
  native_requests:[{method:'PATCH',path_hmac:hash(packet.canonicalPath),body_hmac:packet.bodyHmac,before_hmac:packet.beforeHmac}]}];
 const envelope:DurableConfigurationEnvelope={domain:CONFIGURATION_DURABLE_DOMAIN,envelopeVersion:1,issueId:ids.issue,clusterId:ids.cluster,workspaceId:ids.workspace,jobId:ids.job,ownerId:ids.actor,authoringSessionId:ids.sid,
  credentialEpoch:1,permissionVersion:plan.permissionVersion,issuedAt,admissionExpiresAt:new Date(authored+90_000).toISOString(),expiresAt,policy:{definitionId:ids.definition,version:1,hash:hash(policy),intentTtlHours:24},
  provenance:{jobId:ids.sourceJob,planId:ids.sourcePlan,planRevision:1,planHash:hash('source-plan'),kind:'import'},baseline:{snapshotId:ids.baseline,version:1,manifestHmac:plan.baselineManifestHmac},recipeHmac:hash('recipe'),schemaHmac:plan.schemaHmac,scopeHmac:hash(scope),
  plan:{planId:ids.plan,planRevision:1,planHash:job.plan_hash,stepsHmac:version.steps_hmac,sourceManifestHmac:plan.sourceManifestHmac,baselineManifestHmac:plan.baselineManifestHmac}};
 // A legacy fake durableRef test never needs a valid durable envelope. Its
 // own fourteen-minute source material remains ordinary legacy material.
 const durableSeal=durable?new ConfigurationDurableCodec(secrets).seal(envelope,durableConfigurationLocator(envelope),authored):null;
 const rows:any={job,plan:{id:ids.plan,current_revision:1,transport_scope:scope.transportScope},version,
  material:{id:ids.material,job_id:ids.job,artifact_id:ids.artifact,artifact_kind:'plan',wrapped_key_secret:wrapped,state:'available'},
  issue:durable?{id:ids.issue,cluster_id:ids.cluster,workspace_id:ids.workspace,job_id:ids.job,owner_id:ids.actor,authoring_session_id:ids.sid,credential_epoch:1,permission_version:plan.permissionVersion,
   issued_at:issuedAt,admission_expires_at:envelope.admissionExpiresAt,expires_at:expiresAt,definition_id:ids.definition,definition_version:1,policy_hash:hash(policy),intent_ttl_hours:24,
   source_job_id:ids.sourceJob,source_plan_id:ids.sourcePlan,source_plan_revision:1,source_plan_hash:envelope.provenance.planHash,source_kind:'import'}:null,
  binding:durable?{issue_id:ids.issue,cluster_id:ids.cluster,workspace_id:ids.workspace,job_id:ids.job,plan_id:ids.plan,plan_revision:1,plan_hash:job.plan_hash,workflow_id:ids.workflow,
   workflow_plan_revision:1,workflow_plan_hash:hash('wrapper'),baseline_snapshot_id:ids.baseline,baseline_version:1,baseline_manifest_hmac:plan.baselineManifestHmac,envelope_ciphertext:durableSeal!.ciphertext,material_hmac:durableSeal!.materialHmac}:null,
  policy:{approval_format:2,policy_hash:hash(policy),policy},baseline:{manifest_hmac:plan.baselineManifestHmac,consistency:'console_fenced_best_effort',completeness:'complete',snapshot_state:'ready',material_state:'available'}};
 const db:any={one:vi.fn(async(sql:string,args:any[]=[])=>{
  if(sql==='SELECT * FROM configuration_jobs WHERE id=$1'){expect(args).toEqual([ids.job]);return structuredClone(rows.job);}
  if(sql.includes('FROM configuration_plans WHERE'))return structuredClone(rows.plan);
  if(sql.includes('FROM configuration_plan_versions WHERE'))return structuredClone(rows.version);
  if(sql.includes('FROM configuration_materials WHERE'))return structuredClone(rows.material);
  if(sql.includes('FROM configuration_durable_issues WHERE')){expect(args).toEqual([ids.issue,ids.cluster,ids.workspace,ids.job]);return structuredClone(rows.issue);}
  if(sql.includes('FROM configuration_durable_bindings WHERE')){expect(args).toEqual([ids.issue,ids.cluster,ids.workspace,ids.job]);return structuredClone(rows.binding);}
  if(sql.includes('FROM workflow_definition_versions WHERE'))return structuredClone(rows.policy);
  if(sql.includes('FROM config_snapshot_versions v JOIN config_snapshots'))return structuredClone(rows.baseline);
  if(sql.includes('FROM configuration_job_origin_bindings')||sql.includes('FROM configuration_plan_origin_bindings'))return null;
  throw Error(`UNEXPECTED_READONLY_SOURCE_QUERY:${sql}`);
 }),query:vi.fn(async(sql:string)=>{if(sql.includes('FROM configuration_plan_objects'))return structuredClone(objects);throw Error(`UNEXPECTED_READONLY_SOURCE_ROWS:${sql}`);}),exec:vi.fn(async()=>{throw Error('READ_ONLY_MATERIAL_FIXTURE');})};
 const business=new WorkflowBusinessMaterialService(db,secrets),origin=new WorkflowScheduledConfigurationOriginService(db,secrets,{} as any,{} as any,{} as any);
 return{secrets,crypto,codec:new ConfigurationDurableCodec(secrets),ids,plan,job,version,envelope,rows,objects,db,business,origin,
  readBusiness:()=>business.configurationMaterial(ids.job,db),readOrigin:()=>((origin as any).material(ids.job,db) as ReturnType<WorkflowBusinessMaterialService['configurationMaterial']>)};
}
