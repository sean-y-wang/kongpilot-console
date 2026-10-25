import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {WorkflowBusinessMaterialService} from '../../../apps/console-api/src/modules/workflows/workflow-business-material.service';
import {WorkflowScheduledConfigurationOriginService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import {SecretService} from '../../../apps/console-api/src/infrastructure/secret.service';
import {SnapshotCryptoService} from '../../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {transportScopeFor} from '../../../apps/console-api/src/infrastructure/kong/transport-scope';
import {planAad} from '../../../apps/console-api/src/modules/workflows/workflow.types';
import {portalKeyAad,publicationProofAad} from '../../../apps/console-api/src/modules/portal/portal-proof';
import {normalizedNativeRequests} from '../../../apps/console-api/src/modules/workflows/approved-execution.types';
import {ConfigurationOriginService} from '../../../apps/console-api/src/modules/configuration/configuration-origin.service';
import {governanceComparisonEnvelope} from '../../../apps/console-api/src/modules/governance/governance-comparison-material';
import {grantMatchesEntity} from '../../../apps/console-api/src/modules/authorization/grant-policy';
const id=(n:number)=>`9b000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const future=(ms=120000)=>new Date(Date.now()+ms).toISOString();
const created=()=>new Date(Date.now()-60000).toISOString();
/** Explicit SQL doubles and fixture native responses. These tests verify the
 * actual private codec/policy, not PostgreSQL, a Namespace or a Kong send. */
export async function businessAbsenceFixture(kind:'configuration_v2'|'portal-credential-issue'='configuration_v2') {
 const secrets=new SecretService(),cid=id(1),wid=id(2),actor=id(3),wf=id(4),serviceId=id(5),adminUrl='http://kong:8001';
 const transport=transportScopeFor(adminUrl,null),user:any={id:actor,username:'fixture',status:'active',deleted_at:null,force_password_change:false,
  credential_epoch:'1',permissions_epoch:'1',super_admin:false};
 const workspace:any={id:wid,cluster_id:cid,code:'default',status:'active',is_default:true,revision:1,deleted_at:null};
 const cluster:any={id:cid,admin_url:adminUrl,transport_scope:null,status:'online',version:'1.5.1',revision:1,execution_mode:'approval'};
 const tables:Record<string,any[]>={users:[user],iam_epoch:[{version:'1'}],workspaces:[workspace],clusters:[cluster],iam_effective_grants:[],
  workflow_steps:[],workflow_versions:[],workflows:[],configuration_jobs:[],configuration_plans:[],configuration_plan_versions:[],configuration_plan_objects:[],configuration_materials:[],
  portal_application_grants:[],portal_credentials:[],portal_applications:[],portal_developers:[],portal_publications:[],portal_publication_proofs:[],configuration_job_origin_bindings:[],configuration_plan_origin_bindings:[]};
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
   const table=sql.match(/FROM\s+(\w+)/i)?.[1];const rows=tables[table??''];if(!rows)throw Error(`Unexpected SQL table ${table}`);
   if(table==='iam_epoch')return rows[0]??null;
   if(table==='workspaces'&&sql.includes('code=$2'))return rows.find(r=>r.cluster_id===p[0]&&r.code===p[1])??null;
   if(table==='workspaces')return rows.find(r=>r.cluster_id===p[0]&&r.id===p[1])??null;
   if(table==='portal_credentials')return rows.find(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.grant_id===p[2]&&r.generation===1)??null;
   if(table==='portal_publication_proofs')return rows.find(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.publication_id===p[2]&&r.publication_revision===p[3])??null;
   if(['configuration_plan_versions','workflow_versions'].includes(table!))return rows.find(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&(r.plan_id??r.workflow_id)===p[2]&&r.plan_revision===p[3])??null;
   if(sql.includes('cluster_id=$1'))return rows.find(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.id===p[2])??null;
   return rows.find(r=>r.id===p[0])??null;
  }),query:vi.fn(async(sql:string,p:any[]=[])=>{
   const table=sql.match(/FROM\s+(\w+)/i)?.[1];const rows=tables[table??''];if(!rows)throw Error(`Unexpected SQL table ${table}`);
   if(table==='iam_effective_grants')return rows.filter(r=>r.user_id===p[0]);
   return rows.filter(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&(r.workflow_id??r.plan_id)===p[2]&&r.plan_revision===p[3]);
  }),exec:vi.fn(async()=>{throw Error('Material compiler must never write SQL');})};
 const compiler=new WorkflowBusinessMaterialService(db,secrets),definition={id:id(8),version:1,policyHash:secrets.fingerprint({fixture:true})};
 let nested:any,job:any;
 const plan:any={version:1,clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,kind,executionMode:'approval',approvalRequired:true,
  subject:{type:kind==='configuration_v2'?'configuration_jobs':'portal_application_grants',id:id(10)},requester:{type:kind==='configuration_v2'?'console':'developer',id:kind==='configuration_v2'?actor:id(11)},
  definition,issuedAt:created(),expiresAt:future(),scope:{transportScope:transport,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[]};
 const service={id:serviceId,name:'fixture-service',host:'echo',tags:['kos-ws-default']};
 if(kind==='configuration_v2') {
  const body={id:serviceId,name:'fixture-service',host:'echo',tags:['kos-ws-default']},before=null,step:any={stepId:id(12),stepOrder:1,objectKey:`services:${serviceId}`,
   entityType:'services',objectWorkspaceId:wid,clearMap:[],nativeId:null,allocatedNativeId:serviceId,parentId:null,credentialKind:null,
   permissionAction:'write',mutationAction:'create',dependencies:[],body,before,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before),
   nativeRequests:[{method:'POST',canonicalPath:'/services',body,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before)}],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
  nested={scope:{clusterId:cid,workspaceId:wid,transportScope:transport,kind:'workspace',rootIds:[]},mode:'merge',steps:[step],sourceManifestHmac:'a'.repeat(64),
   baselineManifestHmac:'b'.repeat(64),schemaHmac:'c'.repeat(64),permissionVersion:`${actor}:1:1`,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt:plan.expiresAt};
  const hash=secrets.fingerprint(nested),identity={clusterId:cid,workspaceId:wid,jobId:id(20),materialId:id(21),artifactId:id(22),artifactKind:'plan' as const},crypto=new SnapshotCryptoService(secrets);
  const wrapped=crypto.createWrappedKey(identity),encrypted=await crypto.withKey(identity,wrapped,async key=>({manifest:crypto.encrypt(key,identity,{section:'manifest',key:'plan'},nested),
   object:crypto.encrypt(key,identity,{section:'plan-step',key:step.stepId,entityType:'services',nativeId:serviceId,parentId:null,credentialKind:null},step)}));
  job={id:plan.subject.id,cluster_id:cid,workspace_id:wid,actor_id:actor,origin_type:'http',origin_session_id:id(23),authority_expires_at:plan.expiresAt,
   expires_at:plan.expiresAt,kind:'apply',idempotency_key:'fixture-source-key',request_hmac:'d'.repeat(64),input_secret:null,scope_kind:'workspace',root_ids:[],transport_scope:transport,
   permission_version:`${actor}:1:1`,credential_epoch:1,cluster_revision:1,workspace_revision:1,capture_epoch:'fixture',execution_mode:'approval',approval_required:true,
   plan_id:id(24),plan_revision:1,plan_hash:hash,workflow_id:wf,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,created_at:created()};
  tables.configuration_jobs.push(job);tables.configuration_plans.push({id:job.plan_id,cluster_id:cid,workspace_id:wid,current_revision:1,transport_scope:transport});
  tables.configuration_materials.push({id:identity.materialId,cluster_id:cid,workspace_id:wid,job_id:identity.jobId,artifact_id:identity.artifactId,artifact_kind:'plan',wrapped_key_secret:wrapped,state:'available'});
  tables.configuration_plan_versions.push({cluster_id:cid,workspace_id:wid,plan_id:job.plan_id,plan_revision:1,plan_hash:hash,input_hmac:hash,source_job_id:identity.jobId,
   material_id:identity.materialId,artifact_id:identity.artifactId,steps_hmac:secrets.fingerprint(nested.steps),schema_hmac:nested.schemaHmac,
   source_manifest_hmac:nested.sourceManifestHmac,baseline_manifest_hmac:nested.baselineManifestHmac,step_count:1,native_packet_count:1,
   manifest_ciphertext:encrypted.manifest,created_at:created(),expires_at:plan.expiresAt});
  tables.configuration_plan_objects.push({cluster_id:cid,workspace_id:wid,plan_id:job.plan_id,plan_revision:1,step_id:step.stepId,step_order:1,
   object_workspace_id:wid,entity_type:'services',mutation_action:'create',body_hmac:step.bodyHmac,before_hmac:step.beforeHmac,reference_only:false,blocker_codes:[],
   dependencies:[],native_id:null,allocated_native_id:serviceId,parent_id:null,credential_kind:null,payload_ciphertext:encrypted.object,
   native_requests:step.nativeRequests.map((r:any)=>({method:r.method,path_hmac:secrets.fingerprint(r.canonicalPath),body_hmac:r.bodyHmac,before_hmac:r.beforeHmac}))});
  const metadata={jobId:job.id,planId:job.plan_id,planRevision:1,planHash:hash};plan.steps.push({id:id(25),key:'apply',order:1,kind:'metadata',handler:'configuration_v2',
   entityType:'configuration_jobs',entityId:job.id,permissionAction:'write',dependencies:[],nativeRequests:[],metadata,metadataRevision:1,
   metadataBeforeHmac:secrets.fingerprint({revision:1}),metadataPayloadHmac:secrets.fingerprint(metadata)});
 } else {
  const grant={id:plan.subject.id,cluster_id:cid,workspace_id:wid,transport_scope:transport,application_id:id(30),publication_id:id(31),developer_id:plan.requester.id,
   consumer_id:id(32),acl_group:'fixture-acl',acl_id:id(33),workflow_id:wf,revision:1,state:'pending',current_generation:0,current_credential_id:null,acl_credential_ref_id:null,
   reservation_released_at:null,created_at:created()};tables.portal_application_grants.push(grant);
  const key='fixture-only-api-key-not-live',credential={id:id(34),cluster_id:cid,workspace_id:wid,grant_id:grant.id,developer_id:grant.developer_id,consumer_id:grant.consumer_id,
   credential_kind:'key-auth',kong_id:id(35),generation:1,previous_credential_id:null,key_secret:secrets.encrypt({key},portalKeyAad(cid,wid,id(34),1)),
   key_fingerprint:secrets.fingerprint(key),workflow_id:wf,state:'pending',created_at:created()};tables.portal_credentials.push(credential);
  tables.portal_applications.push({id:grant.application_id,cluster_id:cid,workspace_id:wid,developer_id:grant.developer_id,status:'active',deleted_at:null,created_at:created()});
  tables.portal_developers.push({id:grant.developer_id,cluster_id:cid,workspace_id:wid,status:'active',deleted_at:null,must_change_password:false,credential_epoch:'1'});
  const pub={id:grant.publication_id,cluster_id:cid,workspace_id:wid,state:'published',published_revision:1,transport_scope:transport,service_id:serviceId,
   acl_group:grant.acl_group,acl_plugin_id:id(36),key_auth_plugin_id:id(37)};tables.portal_publications.push(pub);
  const aclPlugin={id:pub.acl_plugin_id,name:'acl',enabled:true,service:{id:serviceId},route:null,consumer:null,tags:['kos-ws-default'],config:{whitelist:[grant.acl_group]}},
   keyPlugin={id:pub.key_auth_plugin_id,name:'key-auth',enabled:true,service:{id:serviceId},route:null,consumer:null,tags:['kos-ws-default'],config:{key_names:['apikey']}};
  const proof={version:1,clusterId:cid,workspaceId:wid,publicationId:pub.id,publicationRevision:1,transportScope:transport,clusterRevision:1,workspaceRevision:1,
   executionMode:'approval',workflowId:id(38),executionId:id(39),planRevision:1,planHash:'e'.repeat(64),verifiedAt:created(),serviceId,aclGroup:grant.acl_group,
   aclPluginId:pub.acl_plugin_id,keyAuthPluginId:pub.key_auth_plugin_id,service,aclPlugin,keyAuthPlugin:keyPlugin,schemas:{consumers:{fields:[]},acls:{fields:[]},keyAuth:{fields:[]}},definitions:{[kind]:definition}};
  tables.portal_publication_proofs.push({cluster_id:cid,workspace_id:wid,publication_id:pub.id,publication_revision:1,transport_scope:transport,
   publication_proof_secret:secrets.encrypt(proof,publicationProofAad(cid,wid,pub.id,1)),publication_proof_hmac:secrets.fingerprint(proof),workflow_id:proof.workflowId,
   workflow_execution_id:proof.executionId,workflow_plan_revision:1,workflow_plan_hash:proof.planHash});
  plan.prerequisites.push({type:'services',id:serviceId,path:`/services/${serviceId}`,before:service,fingerprint:secrets.fingerprint(service)});
  const bodies=[{id:grant.consumer_id,username:`fixture-${grant.id}`,custom_id:grant.id,tags:['kos-ws-default']},
   {id:grant.acl_id,group:grant.acl_group,consumer:{id:grant.consumer_id},tags:['kos-ws-default']},
   {id:credential.kong_id,key,consumer:{id:grant.consumer_id},tags:['kos-ws-default']}];
  for(const [i,body]of bodies.entries()){const credentialKind=i===1?'acls':i===2?'key-auth':undefined;plan.steps.push({id:id(40+i),key:`native-${i}`,order:i+1,kind:'native',
   entityType:i?'credentials':'consumers',permissionAction:'write',dependencies:i?[id(39+i)]:[],mutationAction:'create',mutationPayload:body,mutationPayloadHmac:secrets.fingerprint(body),
   mutationIdempotencyKey:`fixture-portal-native-${i}`,before:null,beforeFingerprint:secrets.fingerprint(null),...(i?{parentId:grant.consumer_id,credentialKind}:{}),
   nativeRequests:[{method:'POST',canonicalPath:i?`/consumers/${grant.consumer_id}/${credentialKind}`:'/consumers',nativeType:credentialKind??'consumers',nativeId:body.id,
    ...(i?{parentId:grant.consumer_id,credentialKind}:{}),body,bodyHmac:secrets.fingerprint(body)}]});}
  const metadata={retireConsumer:false,credentialId:credential.id,kongId:credential.kong_id,generation:1,oldCredentialId:null,consumerId:grant.consumer_id,
   aclId:grant.acl_id,keyFingerprint:credential.key_fingerprint,action:'issue'};
  plan.steps.push({id:id(43),key:'activate',order:4,kind:'metadata',handler:'portal.credential.activate',entityType:'portal_application_grants',entityId:grant.id,
   permissionAction:'write',dependencies:[id(42)],nativeRequests:[],before:structuredClone(grant),metadata,metadataRevision:1,
   metadataBeforeHmac:secrets.fingerprint(grant),metadataPayloadHmac:secrets.fingerprint(metadata)});
  plan.generated={consumerId:grant.consumer_id,aclId:grant.acl_id,credentialId:credential.kong_id,key};
 }
 const grants=['workflows','snapshots','portal','services','consumers','plugins','secrets'].flatMap(module=>['read','write','approve'].map(action=>({user_id:actor,
  module,action,cluster_id:null,workspace_id:null,scope_type:'global',scope_values:[]})));tables.iam_effective_grants.push(...grants);
 const persist=()=>{const hash=secrets.fingerprint(plan);tables.workflows=[{id:wf,cluster_id:cid,workspace_id:wid,state:'pending',kind,subject_type:plan.subject.type,subject_id:plan.subject.id,
  plan_revision:1,plan_hash:hash,requester_type:plan.requester.type,requester_user_id:kind==='configuration_v2'?actor:null,requester_developer_id:kind==='configuration_v2'?null:plan.requester.id,
  definition_id:definition.id,definition_version:1,approval_required:true,execution_mode:'approval'}];
  tables.workflow_versions=[{cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:hash,payload_secret:secrets.encrypt(plan,planAad(cid,wid,wf,1)),
   steps_hash:secrets.fingerprint(plan.steps),step_count:plan.steps.length,native_request_count:plan.steps.reduce((n:number,s:any)=>n+s.nativeRequests.length,0),policy_version:1,approval_required:true,execution_mode:'approval'}];
  tables.workflow_steps=plan.steps.map((s:any)=>({id:s.id,cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:hash,step_order:s.order,step_key:s.key,kind:s.kind,
   entity_type:s.entityType,entity_id:s.entityId??null,parent_id:s.parentId??null,credential_kind:s.credentialKind??null,permission_action:s.permissionAction,mutation_action:s.mutationAction??null,
   handler:s.handler??null,mutation_payload_hmac:s.mutationPayloadHmac??null,mutation_idempotency_key:s.mutationIdempotencyKey??null,before_fingerprint:s.beforeFingerprint??null,
   metadata_before_hmac:s.metadataBeforeHmac??null,metadata_revision:s.metadataRevision??null,metadata_payload_hmac:s.metadataPayloadHmac??null,dependencies:s.dependencies,
   native_requests:normalizedNativeRequests(s.nativeRequests,secrets),execution_mode:'approval',approval_required:true}));};persist();
 const seal=await compiler.subjectSealForPlan(plan,db);plan.scheduling={version:1,scheduleId:id(50)};persist();
 const input:any={plan,draft:{binding:{clusterId:cid,workspaceId:wid,workflowId:wf,workflowPlanRevision:1,workflowPlanHash:secrets.fingerprint(plan),kind,
   subjectType:plan.subject.type,subjectId:plan.subject.id,requester:{...plan.requester,credentialEpoch:'1'},subjectSeal:seal},spec:{windowEnd:future(60000)},
   delegation:{ownerId:actor,executorId:actor,executorCredentialEpoch:'1'}},role:'executor',principal:{user:{id:actor,username:'fixture',superAdmin:false},
   credentialEpoch:'1',permissionVersion:`${actor}:1:1`,grants},transaction:db};
 return{compiler,secrets,db,tables,input,plan,nested,job,user,workspace,cluster,service,actor,cid,wid,seal,persist};
}
export async function observe(f:Awaited<ReturnType<typeof businessAbsenceFixture>>,r:any,response:any):Promise<void>{await f.compiler.authorizeResponse({...f.input,resource:r,response,status:200});}
export async function completeEmptyService(f:Awaited<ReturnType<typeof businessAbsenceFixture>>):Promise<void>{
 const scope=await f.compiler.resolveReadScope(f.input);
 for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:r.kind==='collection'?{data:[],next:null}:f.service);
 await f.compiler.assertReadComplete(f.input);
}
