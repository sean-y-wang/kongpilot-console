import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {WorkflowBusinessMaterialService} from '../../apps/console-api/src/modules/workflows/workflow-business-material.service';
import {WorkflowScheduledConfigurationOriginService} from '../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {planAad} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {portalKeyAad,publicationProofAad} from '../../apps/console-api/src/modules/portal/portal-proof';
import {normalizedNativeRequests} from '../../apps/console-api/src/modules/workflows/approved-execution.types';
import {ConfigurationOriginService} from '../../apps/console-api/src/modules/configuration/configuration-origin.service';
import {governanceComparisonEnvelope} from '../../apps/console-api/src/modules/governance/governance-comparison-material';
import {grantMatchesEntity} from '../../apps/console-api/src/modules/authorization/grant-policy';
import {promotionForkFixture} from './helpers/m11-promotion-fork-fixture';
const id=(n:number)=>`9b000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
const future=(ms=120000)=>new Date(Date.now()+ms).toISOString();
const created=()=>new Date(Date.now()-60000).toISOString();
/** Explicit SQL doubles and fixture native responses. These tests verify the
 * actual private codec/policy, not PostgreSQL, a Namespace or a Kong send. */
async function fixture(kind:'configuration_v2'|'portal-credential-issue'='configuration_v2',portalSchemas?:any) {
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
   aclPluginId:pub.acl_plugin_id,keyAuthPluginId:pub.key_auth_plugin_id,service,aclPlugin,keyAuthPlugin:keyPlugin,schemas:portalSchemas??{consumers:{fields:[]},acls:{fields:[]},keyAuth:{fields:[]}},definitions:{[kind]:definition}};
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
async function observe(f:Awaited<ReturnType<typeof fixture>>,r:any,response:any):Promise<void>{await f.compiler.authorizeResponse({...f.input,resource:r,response,status:200});}
async function completeEmptyService(f:Awaited<ReturnType<typeof fixture>>):Promise<void>{
 const scope=await f.compiler.resolveReadScope(f.input);
 for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:r.kind==='collection'?{data:[],next:null}:f.service);
 await f.compiler.assertReadComplete(f.input);
}
describe('real private scheduled business material decoding',()=>{
 it('keeps exact original configuration Origin immutable-job/full-plan seal while using real AES-GCM fixture material',async()=>{
  const f=await fixture(),origin=new WorkflowScheduledConfigurationOriginService(f.db,f.secrets,{}as any,{}as any,{}as any);
  const original=await(origin as any).material(f.job.id,f.db),actual=await f.compiler.configurationMaterial(f.job.id,f.db);
  expect(actual).toEqual(original);expect(actual.subjectSeal).toEqual(f.seal);expect(actual.plan).toEqual(f.nested);expect(Object.isFrozen(actual.plan)).toBe(true);
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['ciphertext','material-key','steps-hash','native-row','source-job','missing-object','row-before-hmac']as const)('rejects corrupted original configuration %s',async mode=>{
  const f=await fixture(),v=f.tables.configuration_plan_versions[0],o=f.tables.configuration_plan_objects[0],m=f.tables.configuration_materials[0];
  if(mode==='ciphertext')v.manifest_ciphertext=v.manifest_ciphertext.slice(0,-2)+'xx';if(mode==='material-key')m.wrapped_key_secret=f.secrets.encrypt({dek:'A'.repeat(43)},'foreign-material');
  if(mode==='steps-hash')v.steps_hmac='0'.repeat(64);if(mode==='native-row')o.native_requests[0].path_hmac='0'.repeat(64);if(mode==='source-job')v.source_job_id=id(999);
  if(mode==='missing-object')f.tables.configuration_plan_objects=[];if(mode==='row-before-hmac')o.before_hmac='0'.repeat(64);
  await expect(f.compiler.configurationMaterial(f.job.id,f.db)).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('seals Portal actual Consumer → ACL → Key → activation and preserves stable native commitment when scheduling is added',async()=>{
  const f=await fixture('portal-credential-issue'),m=await f.compiler.portalMaterial(f.plan,f.db);
  expect(m.subjectSeal).toEqual(f.seal);expect(m.plan.steps.map(s=>s.handler??s.credentialKind??s.entityType)).toEqual(['consumers','acls','key-auth','portal.credential.activate']);
  expect(m.plan.requester.id).not.toBe(f.actor);expect(m.plan.generated?.key).toBe('fixture-only-api-key-not-live');expect(f.db.exec).not.toHaveBeenCalled();
  expect(JSON.stringify(m.subjectSeal)).not.toContain('fixture-only-api-key-not-live');expect(Object.isFrozen(m.publicationProof)).toBe(true);
 });
 it.each(['key-ciphertext','key-fingerprint','grant-consumer','publication-proof','developer-disabled','developer-force-password','application-disabled','missing-native-step','extra-packet','activation-key-fingerprint']as const)('rejects Portal %s',async mode=>{
  const f=await fixture('portal-credential-issue');
  if(mode==='key-ciphertext')f.tables.portal_credentials[0].key_secret=f.secrets.encrypt({key:'foreign'},'foreign-aad');if(mode==='key-fingerprint')f.tables.portal_credentials[0].key_fingerprint='0'.repeat(64);
  if(mode==='grant-consumer')f.tables.portal_application_grants[0].consumer_id=id(999);if(mode==='publication-proof')f.tables.portal_publication_proofs[0].publication_proof_hmac='0'.repeat(64);
  if(mode==='developer-disabled')f.tables.portal_developers[0].status='disabled';if(mode==='developer-force-password')f.tables.portal_developers[0].must_change_password=true;
  if(mode==='application-disabled')f.tables.portal_applications[0].status='disabled';if(mode==='missing-native-step')f.plan.steps.splice(1,1);if(mode==='extra-packet')f.plan.steps[0].nativeRequests.push(structuredClone(f.plan.steps[0].nativeRequests[0]));
  if(mode==='activation-key-fingerprint')f.plan.steps[3].metadata.keyFingerprint='0'.repeat(64);
  await expect(f.compiler.portalMaterial(f.plan,f.db)).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
});
describe('fixed business SQL-only current and path compiler',()=>{
 it.each(['configuration_v2','portal-credential-issue']as const)('resolves %s without Kong calls, fake SID or SQL writes',async kind=>{
  const f=await fixture(kind);await f.compiler.assertCurrent(f.input);const scope=await f.compiler.resolveReadScope(f.input);
  expect(scope.limits).toEqual({maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432});expect(scope.resources.every(r=>!r.allowAbsent)).toBe(true);
  expect(scope.resources.some(r=>r.path===(kind==='configuration_v2'?'/services':'/consumers')&&r.kind==='collection')).toBe(true);
  if(kind==='portal-credential-issue')expect(scope.resources.some(r=>r.path.startsWith(`/consumers/${f.plan.generated.consumerId}/`))).toBe(false);
  expect(scope.resources.every(r=>!r.path.startsWith('/schemas/plugins/'))).toBe(true);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['role-revoked','password-reset','forced-password','epoch-changed','scope-changed','window-extended','subject-seal-changed','binding-owner-changed']as const)('rejects current %s without any Native read',async mode=>{
  const f=await fixture();
  if(mode==='role-revoked')f.tables.iam_effective_grants=[];if(mode==='password-reset')f.user.credential_epoch='2';if(mode==='forced-password')f.user.force_password_change=true;
  if(mode==='epoch-changed')f.tables.iam_epoch[0].version='2';if(mode==='scope-changed')f.cluster.revision=2;if(mode==='window-extended')f.input.draft.spec.windowEnd=future(240000);
  if(mode==='subject-seal-changed')f.input.draft.binding.subjectSeal={...f.seal,nativeManifestHmac:'0'.repeat(64)};if(mode==='binding-owner-changed')f.input.draft.delegation.executorId=id(999);
  await expect(f.compiler.assertCurrent(f.input)).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not renew an expired original job deadline even with an otherwise current wrapper window',async()=>{
  const f=await fixture();f.job.authority_expires_at=created();await expect(f.compiler.assertCurrent(f.input)).rejects.toThrow();
  expect(f.job.authority_expires_at).toBeDefined();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('refuses using a different business callback or unknown kind',async()=>{
  const f=await fixture();await expect(f.compiler.businessReadPolicy('portal-credential-issue').resolveReadScope(f.input)).rejects.toThrow();
  expect(()=>f.compiler.businessReadPolicy('native-change'as any)).toThrow();
 });
});
describe('current raw EOF and per-row permission fences',()=>{
 it('proves allocated service absence by true EOF and checks only proposed subject WRITE while unrelated rows require READ',async()=>{
  const f=await fixture(),unrelated={id:id(80),name:'unrelated',host:'echo',tags:['kos-ws-default']};
  f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter(g=>g.module!=='services'||g.action==='read');
  const special:any={user_id:f.actor,module:'services',action:'write',cluster_id:f.cid,workspace_id:f.wid,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:f.service.id}]};
  f.tables.iam_effective_grants.push(special);f.input.principal.grants=f.tables.iam_effective_grants;
  await f.compiler.runResponseScope(async()=>{const scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:{data:[unrelated],next:null});
   await f.compiler.assertReadComplete(f.input);
  });
  expect(grantMatchesEntity(special,'services','write',{clusterId:f.cid,workspaceId:f.wid,entityType:'services',entity:unrelated})).toBe(false);
 });
 it('requires Root private read witness scope and closes it after callback completion',async()=>{
  const f=await fixture(),r=(await f.compiler.resolveReadScope(f.input)).resources.find(r=>r.kind==='collection')!;
  await expect(observe(f,r,{data:[],next:null})).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_READ_SCOPE_REQUIRED'}});
  await f.compiler.runResponseScope(()=>completeEmptyService(f));
  await expect(f.compiler.assertReadComplete(f.input)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_READ_SCOPE_REQUIRED'}});
 });
 it.each(['next-undefined','no-next','missing-page','wrong-path','foreign-actor','extra-workspace-tag','foreign-ID','read-denied']as const)('rejects %s and poisons a caught-error scope',async mode=>{
  const f=await fixture(),scope=await f.compiler.resolveReadScope(f.input),r=scope.resources.find(r=>r.kind==='collection')!;
  await expect(f.compiler.runResponseScope(async()=>{
   const row:any={id:id(80),host:'echo',tags:['kos-ws-default']};let descriptor:any=r,response:any={data:[row],next:null};
   if(mode==='next-undefined')response.next=undefined;if(mode==='no-next')delete response.next;if(mode==='missing-page')response.next='/services?offset=next';
   if(mode==='wrong-path')descriptor={...r,path:'/routes'};if(mode==='foreign-actor')f.input.principal.user={...f.input.principal.user,id:id(999)};
   if(mode==='extra-workspace-tag')row.tags.push('kos-ws-other');if(mode==='foreign-ID')row.id='not-a-uuid';
   if(mode==='read-denied'){f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter(g=>g.module!=='services'||g.action!=='read');f.input.principal.grants=f.tables.iam_effective_grants;}
   try{await observe(f,descriptor,response);await f.compiler.assertReadComplete(f.input);}catch{/* Consumer catching an error cannot accept the scope. */}
  })).rejects.toThrow();
 });
 it('refuses an existing allocated UUID after a complete current collection',async()=>{
  const f=await fixture();await expect(f.compiler.runResponseScope(async()=>{const scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:{data:[f.service],next:null});await f.compiler.assertReadComplete(f.input);
  })).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_CREATE_ID_ALREADY_EXISTS'}});
 });
 it('rejects an unrelated secret-bearing raw response without a current secret grant',async()=>{
  const f=await fixture('portal-credential-issue');f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter(g=>g.module!=='secrets');f.input.principal.grants=f.tables.iam_effective_grants;
  await expect(f.compiler.runResponseScope(async()=>{const scope=await f.compiler.resolveReadScope(f.input);
   await observe(f,scope.resources.find(r=>r.entityType==='services')!,f.service);
   const r=scope.resources.find(r=>r.entityType==='plugins')!,pub=f.tables.portal_publications[0];
   await observe(f,r,{id:r.entityId,name:r.entityId===pub.acl_plugin_id?'acl':'key-auth',service:{id:f.service.id},route:null,consumer:null,
    tags:['kos-ws-default'],config:{client_secret:'fixture-only-not-live'}});
  })).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_RESPONSE_SECRET_DENIED'}});
 });
 it('completes a genuine Portal future-parent absence scope without issuing nested reads or caching planned parents as native objects',async()=>{
  const f=await fixture('portal-credential-issue');await f.compiler.runResponseScope(async()=>{
   const m=await f.compiler.portalMaterial(f.plan,f.db),scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:r.kind==='collection'?{data:[],next:null}
    :r.entityType==='services'?f.service:r.entityId===m.publicationProof.aclPluginId?m.publicationProof.aclPlugin:m.publicationProof.keyAuthPlugin);
   await f.compiler.assertReadComplete(f.input);await f.compiler.assertReadComplete(f.input);
  });expect(f.db.exec).not.toHaveBeenCalled();
 });
});
describe('three-attempt GET and two-source-fence budget reserve',()=>{
 it('accepts a bounded one-packet measured graph and refuses a larger batch without raising hard limits',async()=>{
  const f=await fixture();expect(()=>f.compiler.assertExecutionReadBudget(1,{calls:50,pages:10,records:1000,bytes:2000})).not.toThrow();
  expect(()=>f.compiler.assertExecutionReadBudget(2,{calls:50,pages:10,records:1000,bytes:2000})).toThrow(expect.objectContaining({response:{code:'WORKFLOW_BUSINESS_EXECUTION_BUDGET_EXCEEDED'}}));
 });
 it.each(['calls','pages','records','bytes']as const)('includes private credential %s usage in each future fence',async key=>{
  const f=await fixture(),base={calls:1,pages:1,records:1,bytes:1},extra={calls:1,pages:1,records:1,bytes:1};
  extra[key]=key==='bytes'?16777216:key==='records'?5000:key==='pages'?50:250;
  expect(()=>f.compiler.assertExecutionReadBudget(1,base,extra)).toThrow();
 });
 it.each([-1,501,NaN,1.5])('refuses invalid %s packet count',async n=>{const f=await fixture();expect(()=>f.compiler.assertExecutionReadBudget(n,{calls:1,pages:1,records:1,bytes:1})).toThrow();});
});

describe('live READ grants preserve native outcome independence',()=>{
 it('can verify actual current created-ID grants without claiming prefix success or changing SQL',async()=>{
  const f=await fixture();await f.compiler.runResponseScope(async()=>{const scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:{data:[f.service],next:null});
   await f.compiler.assertCurrentReadGrants(f.input);await f.compiler.assertCurrentReadGrants(f.input);
  });expect(f.db.exec).not.toHaveBeenCalled();expect(f.db.one.mock.calls.some(([sql]:any)=>/mutation_operations|workflow_executions/.test(sql))).toBe(false);
 });
 it('requires current object WRITE in addition to proposed tags, preventing a tag swap to steal an object',async()=>{
  const f=await fixture(),pay='team-pay',finance='team-finance';f.service.tags.push(finance);
  f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter(g=>g.module!=='services'||g.action==='read');
  f.tables.iam_effective_grants.push({user_id:f.actor,module:'services',action:'write',cluster_id:f.cid,workspace_id:f.wid,scope_type:'tag_group',scope_values:[pay]});
  f.input.principal.grants=f.tables.iam_effective_grants;
  await expect(f.compiler.runResponseScope(async()=>{const scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:{data:[f.service],next:null});
   await f.compiler.assertCurrentReadGrants(f.input);
  })).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_CURRENT_SUBJECT_ACTION_DENIED'}});
 });
 it('rejects changed Portal developer credential epoch despite unchanged console executor',async()=>{
  const f=await fixture('portal-credential-issue');f.tables.portal_developers[0].credential_epoch='2';
  await expect(f.compiler.assertCurrent(f.input)).rejects.toThrow();expect(f.user.credential_epoch).toBe('1');
 });
 it('rejects a secret entity whitelist with the wrong object type even when its UUID matches',async()=>{
  const f=await fixture('portal-credential-issue');f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter(g=>g.module!=='secrets');
  f.tables.iam_effective_grants.push({user_id:f.actor,module:'secrets',action:'read',cluster_id:f.cid,workspace_id:f.wid,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:f.plan.generated.credentialId}]});
  f.input.principal.grants=f.tables.iam_effective_grants;
  await expect(f.compiler.runResponseScope(async()=>{const m=await f.compiler.portalMaterial(f.plan,f.db),scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources)await observe(f,r,r.kind==='schema'?{fields:[]}:r.kind==='collection'?{data:[],next:null}:r.entityType==='services'?f.service
    :r.entityId===m.publicationProof.aclPluginId?m.publicationProof.aclPlugin:m.publicationProof.keyAuthPlugin);await f.compiler.assertCurrentReadGrants(f.input);
  })).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SUBJECT_SECRET_DENIED'}});
 });
 it('refuses altered actual Portal publication schema rather than returning a plausible form',async()=>{
  const f=await fixture('portal-credential-issue');await expect(f.compiler.runResponseScope(async()=>{
   const r=(await f.compiler.resolveReadScope(f.input)).resources.find(r=>r.path==='/schemas/consumers')!;
   await observe(f,r,{fields:[{forged_required_field:{type:'string'}}]});
  })).rejects.toThrow();
 });
 it.each([['consumers','consumers'],['acls','acls'],['keyAuth','keyauth_credentials']])('accepts only equivalent lazy string validation in actual %s response policy',async(name,path)=>{
  const schema={fields:[{id:{type:'string',uuid:true}},{tags:{type:'set',elements:{type:'string'}}}]};
  const schemas={consumers:schema,acls:schema,keyAuth:schema},f=await fixture('portal-credential-issue',schemas);
  const before=JSON.stringify(f.tables),response=structuredClone(schema);
  Object.assign(response.fields[0].id!,{len_min:1});Object.assign(response.fields[1].tags!.elements,{len_min:1});
  await f.compiler.runResponseScope(async()=>{const r=(await f.compiler.resolveReadScope(f.input)).resources.find(r=>r.path===`/schemas/${path}`)!;
   await observe(f,r,response);});
  expect(JSON.stringify(f.tables)).toBe(before);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each([0,2,null,false,'1'])('rejects explicit changed Portal string minimum %j',async minimum=>{
  const schema={fields:[{id:{type:'string',uuid:true}}]},f=await fixture('portal-credential-issue',{consumers:schema,acls:schema,keyAuth:schema});
  await expect(f.compiler.runResponseScope(async()=>{const r=(await f.compiler.resolveReadScope(f.input)).resources.find(r=>r.path==='/schemas/consumers')!;
   await observe(f,r,{fields:[{id:{type:'string',uuid:true,len_min:minimum}}]});})).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SCHEMA_RESPONSE_INVALID'}});
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each([{required:true},{default:'different'},{one_of:['b','a']},{len_max:4},{type:'integer'}])('rejects changed Portal schema constraint %j',async change=>{
  const schema={fields:[{id:{type:'string',uuid:true}}]},f=await fixture('portal-credential-issue',{consumers:schema,acls:schema,keyAuth:schema});
  await expect(f.compiler.runResponseScope(async()=>{const r=(await f.compiler.resolveReadScope(f.input)).resources.find(r=>r.path==='/schemas/consumers')!;
   await observe(f,r,{fields:[{id:{type:'string',uuid:true,...change}}]});})).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SCHEMA_RESPONSE_INVALID'}});
 });
});

describe('Portal current metadata and actual publication proof',()=>{
 it('rejects changed activation metadata revision without native or SQL writes',async()=>{
  const f=await fixture('portal-credential-issue');f.tables.portal_application_grants[0].revision++;
  await expect(f.compiler.assertCurrent(f.input)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_PORTAL_ACTIVATION_BEFORE_CHANGED'}});expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['service','acl','key-auth']as const)('rejects actual %s publication drift even with current READ/write grants',async mode=>{
  const f=await fixture('portal-credential-issue');await expect(f.compiler.runResponseScope(async()=>{
   const m=await f.compiler.portalMaterial(f.plan,f.db),scope=await f.compiler.resolveReadScope(f.input);
   for(const r of scope.resources){let response:any=r.kind==='schema'?{fields:[]}:r.kind==='collection'?{data:[],next:null}:r.entityType==='services'?structuredClone(f.service)
    :r.entityId===m.publicationProof.aclPluginId?structuredClone(m.publicationProof.aclPlugin):structuredClone(m.publicationProof.keyAuthPlugin);
    if(mode==='service'&&r.entityType==='services')response.host='other';if(mode==='acl'&&r.entityId===m.publicationProof.aclPluginId)response.config.whitelist=[];
    if(mode==='key-auth'&&r.entityId===m.publicationProof.keyAuthPluginId)response.enabled=false;await observe(f,r,response);
   }await f.compiler.assertCurrentReadGrants(f.input);
  })).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_PORTAL_NATIVE_PUBLICATION_CHANGED'}});
 });
});

async function promotionFixture(){return promotionForkFixture(await fixture());}
describe('real Promote comparison AEAD and exact old Source marker',()=>{
 it('authenticates the original 018 marker with the same actual ConfigurationOrigin manifest algorithm',async()=>{
  const f=await promotionFixture(),m=await f.compiler.promotionMaterial(f.m,f.db);
  expect(m?.source).toEqual(f.source);expect(m?.target).toEqual(f.target);expect(m?.sourceNativeFingerprints).toEqual(f.loaded.sourceNativeFingerprints);
  expect(m?.recovery).toBeNull();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['source-ciphertext','source-raw-hash-map','origin-hmac','import-source-job','quality','selection-hmac','source-registry','sensitive-without-recovery']as const)('refuses Promote %s without source/target Native permission',async mode=>{
  const f=await promotionFixture();if(mode==='source-ciphertext')f.comparison.source_inventory_secret=f.secrets.encrypt({arbitrary:true},'foreign-aad');
  if(mode==='source-raw-hash-map'){const env=f.secrets.decrypt<any>(f.comparison.source_inventory_secret,`governance:comparison-source:${f.comparison.id}`);env.nativeFingerprints={};
   f.comparison.source_inventory_secret=f.secrets.encrypt(env,`governance:comparison-source:${f.comparison.id}`);f.comparison.source_inventory_hmac=f.secrets.fingerprint(env);f.row.source_inventory_hmac=f.comparison.source_inventory_hmac;}
  if(mode==='origin-hmac')f.m.sourceOrigin.marker.hmac='0'.repeat(64);if(mode==='import-source-job')f.row.configuration_job_id=id(999);if(mode==='quality')f.comparison.quality='incomplete';
  if(mode==='selection-hmac')f.row.selection_hmac='0'.repeat(64);if(mode==='source-registry')f.m.sourceOrigin.jobOrigin.source_cluster_id=id(999);
  if(mode==='sensitive-without-recovery'){const s=f.secrets.decrypt<any>(f.row.selection_secret,`governance:promotion-selection:${f.row.id}`);s.includeCredentials=true;
   f.row.selection_secret=f.secrets.encrypt(s,`governance:promotion-selection:${f.row.id}`);f.row.selection_hmac=f.secrets.fingerprint(s);}
  await expect(f.compiler.promotionMaterial(f.m,f.db)).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
});

describe('Root reconstructs metadata without importing caller identity authority',()=>{
 it('returns current SQL-derived principal/grants as a readonly input, while keeping the actual transaction outside JSON cloning',async()=>{
  const f=await fixture(),input=await f.compiler.currentReadInput(f.input.plan,f.input.draft,f.actor,'executor',f.db);
  expect(input.principal.user.id).toBe(f.actor);expect(input.principal.user.forcePasswordChange).toBe(false);expect(input.principal.grants).toHaveLength(f.tables.iam_effective_grants.length);
  expect(input.transaction).toBe(f.db);expect(Object.isFrozen(input.principal)).toBe(true);expect(Object.isFrozen(input)).toBe(true);expect(f.db.exec).not.toHaveBeenCalled();
  await expect(f.compiler.assertCurrentReadGrants(input)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_READ_SCOPE_REQUIRED'}});
 });
 it('never derives grants from a supplied plan requester or a nonexistent console actor',async()=>{
  const f=await fixture();await expect(f.compiler.currentReadInput(f.input.plan,f.input.draft,id(999),'executor',f.db)).rejects.toThrow();
  expect(f.db.exec).not.toHaveBeenCalled();
 });
});

describe('sealed configuration no-op stays demonstrable and readonly',()=>{
 it('uses a real fixed schema GET, preserves zero actual native packets, and creates no write authority',async()=>{
  const f=await fixture(),v=f.tables.configuration_plan_versions[0],m=f.tables.configuration_materials[0],crypto=new SnapshotCryptoService(f.secrets),
   identity={clusterId:f.cid,workspaceId:f.wid,jobId:v.source_job_id,materialId:m.id,artifactId:v.artifact_id,artifactKind:'plan' as const};
  f.nested.steps=[];f.job.plan_hash=f.secrets.fingerprint(f.nested);v.plan_hash=f.job.plan_hash;v.input_hmac=f.job.plan_hash;
  v.steps_hmac=f.secrets.fingerprint([]);v.step_count=0;v.native_packet_count=0;f.tables.configuration_plan_objects=[];
  v.manifest_ciphertext=await crypto.withKey(identity,m.wrapped_key_secret,async key=>crypto.encrypt(key,identity,{section:'manifest',key:'plan'},f.nested));
  f.plan.steps[0].metadata.planHash=f.job.plan_hash;f.plan.steps[0].metadataPayloadHmac=f.secrets.fingerprint(f.plan.steps[0].metadata);f.persist();
  f.input.draft.binding.workflowPlanHash=f.secrets.fingerprint(f.plan);f.input.draft.binding.subjectSeal=await f.compiler.subjectSealForPlan(f.plan,f.db);
  const scope=await f.compiler.resolveReadScope(f.input);expect(scope.resources.map(r=>r.path)).toEqual(['/schemas/services']);
  await f.compiler.runResponseScope(async()=>{await observe(f,scope.resources[0],{fields:[]});await f.compiler.assertReadComplete(f.input);});
  expect((await f.compiler.configurationMaterial(f.job.id,f.db)).plan.steps).toEqual([]);expect(f.db.exec).not.toHaveBeenCalled();
 });
});
