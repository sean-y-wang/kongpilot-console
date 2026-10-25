import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {businessAbsenceFixture as fixture,observe} from './helpers/workflow-business-absence-fixture';
import {WorkflowBusinessScopedReadService} from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';

const id=(n:number)=>`9b000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
type Fixture=Awaited<ReturnType<typeof fixture>>;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
function install(f:Fixture){f.compiler.installScopedReadBridge(new WorkflowBusinessScopedReadService());}
function grants(f:Fixture,kind:'global'|'workspace'|'tag_group'|'entity',values:any[],wid:string|null=f.wid){
 const rows=f.input.principal.grants.map((g:any)=>({...g,cluster_id:f.cid,workspace_id:wid,scope_type:kind,scope_values:values}));
 f.input.principal.grants=rows;f.tables.iam_effective_grants=rows;return rows;
}
/** Re-seals the actual fixture SQL/AES rows. Tests exercise the real Material
 * compiler, rather than replacing its authenticated plan with a DTO. */
async function reseal(f:Fixture){
 const {nested,job,secrets,tables}=f,version=tables.configuration_plan_versions[0],material=tables.configuration_materials[0];
 const identity={clusterId:f.cid,workspaceId:f.wid,jobId:version.source_job_id,materialId:material.id,artifactId:version.artifact_id,artifactKind:'plan' as const};
 const crypto=new SnapshotCryptoService(secrets);
 await crypto.withKey(identity,material.wrapped_key_secret,async key=>{
  nested.steps.forEach((s:any)=>{s.bodyHmac=secrets.fingerprint(s.body);s.beforeHmac=secrets.fingerprint(s.before??null);
   s.nativeRequests.forEach((r:any)=>{r.bodyHmac=secrets.fingerprint(r.body);r.beforeHmac=s.beforeHmac;});});
  const hash=secrets.fingerprint(nested);job.plan_hash=hash;version.plan_hash=hash;version.input_hmac=hash;
  version.steps_hmac=secrets.fingerprint(nested.steps);version.step_count=nested.steps.length;
  version.native_packet_count=nested.steps.reduce((n:number,s:any)=>n+s.nativeRequests.length,0);
  version.manifest_ciphertext=crypto.encrypt(key,identity,{section:'manifest',key:'plan'},nested);
  tables.configuration_plan_objects=nested.steps.map((s:any)=>({cluster_id:f.cid,workspace_id:f.wid,plan_id:job.plan_id,plan_revision:1,step_id:s.stepId,step_order:s.stepOrder,
   object_workspace_id:s.objectWorkspaceId,entity_type:s.entityType,mutation_action:s.mutationAction,body_hmac:s.bodyHmac,before_hmac:s.beforeHmac,reference_only:false,
   blocker_codes:[],dependencies:s.dependencies,native_id:s.nativeId??null,allocated_native_id:s.allocatedNativeId??null,parent_id:s.parentId??null,credential_kind:s.credentialKind??null,
   payload_ciphertext:crypto.encrypt(key,identity,{section:'plan-step',key:s.stepId,entityType:s.entityType,nativeId:s.nativeId??s.allocatedNativeId??null,
    parentId:s.parentId??null,credentialKind:s.credentialKind??null},s),native_requests:s.nativeRequests.map((r:any)=>({method:r.method,path_hmac:secrets.fingerprint(r.canonicalPath),body_hmac:r.bodyHmac,before_hmac:r.beforeHmac}))}));
  f.plan.steps[0].metadata.planHash=hash;f.plan.steps[0].metadataPayloadHmac=secrets.fingerprint(f.plan.steps[0].metadata);
 });
 f.persist();f.input.draft.binding.workflowPlanHash=secrets.fingerprint(f.plan);
 f.input.draft.binding.subjectSeal=await f.compiler.subjectSealForPlan(f.plan,f.db);
}
async function completeCreates(f:Fixture){
 const scope=await f.compiler.resolveReadScope(f.input);
 for(const resource of scope.resources)if(resource.kind==='schema')await observe(f,resource,{fields:[]});
 else if(resource.allowAbsent)await f.compiler.authorizeResponse({...f.input,resource,status:404,response:{message:'Not found'}});
 else throw Error(`Unexpected existing subject ${resource.path}`);
 await f.compiler.assertReadComplete(f.input);return scope;
}

/** Source domain checks do not authenticate HTTP404 themselves. The real
 * Validation/SDK tests separately require original transport witnesses. Here
 * SQL/AES, current feature/native scopes and private response ALS are real. */
describe('fixed scoped business material dispatch',()=>{
 it('retains old full-EOF admission without an installed bridge',async()=>{
  const f=await fixture(),full=await f.compiler.resolveReadScope(f.input);expect(full.domain).toBeUndefined();expect(full.resources.some(r=>r.kind==='collection')).toBe(true);
  grants(f,'entity',[{entity_type:'services',entity_id:f.service.id}]);await expect(f.compiler.assertCurrent(f.input)).rejects.toThrow();
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('installs once and compiles SQL super-admin ordinary manifests into exact required points',async()=>{
  const f=await fixture();install(f);expect(()=>install(f)).toThrow();f.user.super_admin=true;f.input.principal.user.superAdmin=true;
  await f.compiler.assertCurrent(f.input);const scope=await f.compiler.resolveReadScope(f.input);expect(scope.domain).toBe('scoped-points-v1');
  expect(scope.resources.some(r=>r.kind==='collection')).toBe(false);expect(scope.resources.find(r=>r.entityId===f.service.id)).toMatchObject({required:true,allowAbsent:true});
 });
 it.each(['workspace','entity','tag_group']as const)('admits exact allocated Service points with current %s feature and native grants',async kind=>{
  const f=await fixture();f.nested.steps[0].body.tags.push('team-pay');await reseal(f);install(f);
  grants(f,kind,kind==='workspace'?[f.wid]:kind==='tag_group'?['team-pay']:[{entity_type:'services',entity_id:f.service.id}]);
  await f.compiler.assertCurrent(f.input);const scope=await f.compiler.runResponseScope(()=>completeCreates(f));
  expect(scope.domain).toBe('scoped-points-v1');expect(scope.resources.some(r=>r.kind==='collection')).toBe(false);
  expect(scope.resources.find(r=>r.allowAbsent)).toMatchObject({path:`/services/${f.service.id}`,workspaceId:f.wid,required:true});
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('supports two sealed object workspaces and keeps duplicate schema paths precisely separated',async()=>{
  const f=await fixture(),other=id(80);f.tables.workspaces.push({...f.workspace,id:other,code:'payments',is_default:false});
  const second=structuredClone(f.nested.steps[0]);second.stepId=id(81);second.stepOrder=2;second.objectWorkspaceId=other;second.allocatedNativeId=id(82);
  second.objectKey=`services:${id(82)}`;second.body={...second.body,id:id(82),name:'payment-service',tags:['kos-ws-payments']};second.nativeRequests[0].body=second.body;
  f.nested.steps.push(second);await reseal(f);install(f);
  const own=grants(f,'workspace',[f.wid]);const additional=own.map((g:any)=>({...g,workspace_id:other,scope_values:[other]}));
  f.input.principal.grants=[...own,...additional];f.tables.iam_effective_grants=f.input.principal.grants;
  const scope=await f.compiler.runResponseScope(()=>completeCreates(f));expect(scope.resources.filter(r=>r.path==='/schemas/services').map(r=>r.workspaceId).sort()).toEqual([f.wid,other].sort());
  expect(scope.resources.filter(r=>r.allowAbsent).map(r=>r.entityId)).toEqual([f.service.id,id(82)]);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects a real200 point in a different current workspace and poisons the capsule',async()=>{
  const f=await fixture();install(f);grants(f,'workspace',[f.wid]);const other=id(80);f.tables.workspaces.push({...f.workspace,id:other,code:'payments'});
  const scope=await f.compiler.resolveReadScope(f.input),resource=scope.resources.find(r=>r.allowAbsent)!;
  await expect(f.compiler.runResponseScope(async()=>{await expect(observe(f,resource,{...f.service,tags:['kos-ws-payments']})).rejects.toThrow();await expect(f.compiler.assertReadComplete(f.input)).rejects.toThrow();})).rejects.toThrow();
 });
 it.each(['native-read','native-write','feature-write','feature-tags','stale-principal']as const)('rejects %s after fixed SQL and actual proposed-object checks',async reason=>{
  const f=await fixture();f.nested.steps[0].body.tags.push('team-pay');await reseal(f);install(f);grants(f,'tag_group',['team-pay']);
  if(reason==='native-read'||reason==='native-write'){const action=reason==='native-read'?'read':'write';f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='services'||g.action!==action);f.tables.iam_effective_grants=f.input.principal.grants;}
  if(reason==='feature-write'){f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='snapshots'||g.action!=='write');f.tables.iam_effective_grants=f.input.principal.grants;}
  if(reason==='feature-tags'){f.input.principal.grants=f.input.principal.grants.map((g:any)=>g.module==='snapshots'?{...g,scope_values:['team-other']}:g);f.tables.iam_effective_grants=f.input.principal.grants;}
  if(reason==='stale-principal')f.tables.iam_effective_grants=[];
  await expect(f.compiler.runResponseScope(()=>completeCreates(f))).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each([false,true])('requires authentic Consumer absence before Portal child FK absence with current super-admin=%s',async superAdmin=>{
  const f=await fixture('portal-credential-issue');f.user.super_admin=superAdmin;f.input.principal.user.superAdmin=superAdmin;install(f);grants(f,'workspace',[f.wid]);const material=await f.compiler.portalMaterial(f.plan,f.db),scope=await f.compiler.resolveReadScope(f.input);
  expect(scope.resources.some(r=>r.kind==='collection')).toBe(false);
  await f.compiler.runResponseScope(async()=>{
   const parent=scope.resources.find(r=>r.entityType==='consumers'&&r.allowAbsent)!,children=scope.resources.filter(r=>r.parentId===parent.entityId);
   await f.compiler.authorizeResponse({...f.input,resource:parent,status:404,response:{message:'Not found'}});
   for(const child of children)await f.compiler.authorizeScopedParentAbsence(f.input,child,parent);
   for(const r of scope.resources.filter(r=>!r.allowAbsent))await observe(f,r,r.kind==='schema'?r.path==='/schemas/consumers'?material.publicationProof.schemas.consumers:r.path==='/schemas/acls'?material.publicationProof.schemas.acls:material.publicationProof.schemas.keyAuth
    :r.entityType==='services'?material.publicationProof.service:r.entityId===material.publicationProof.aclPluginId?material.publicationProof.aclPlugin:material.publicationProof.keyAuthPlugin);
   await f.compiler.assertReadComplete(f.input);
  });expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['no-parent','present-parent','wrong-parent','wrong-child','secret-revoked']as const)('rejects %s for prospective credential FK proof',async reason=>{
  const f=await fixture('portal-credential-issue');install(f);grants(f,'workspace',[f.wid]);let scope=await f.compiler.resolveReadScope(f.input);
  const parent=scope.resources.find(r=>r.entityType==='consumers'&&r.allowAbsent)!,original=scope.resources.find(r=>r.path.includes('/key-auth/'))!;
  await expect(f.compiler.runResponseScope(async()=>{
   if(reason==='present-parent')await observe(f,parent,f.plan.steps[0].mutationPayload);
   else if(reason!=='no-parent')await f.compiler.authorizeResponse({...f.input,resource:parent,status:404,response:{message:'Not found'}});
   if(reason==='secret-revoked'){f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='secrets');f.tables.iam_effective_grants=f.input.principal.grants;}
   await f.compiler.authorizeScopedParentAbsence(f.input,reason==='wrong-child'?{...original,entityId:id(90),path:original.path.replace(original.entityId!,id(90))}:original,
    reason==='wrong-parent'?{...parent,entityId:id(91),path:`/consumers/${id(91)}`}:parent);
  })).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('inherits only real observed Consumer tags for credential authorization while keeping raw bytes and sealed Native body untouched',async()=>{
  const f=await fixture('portal-credential-issue');install(f);const scope=await f.compiler.resolveReadScope(f.input),parent=scope.resources.find(r=>r.entityType==='consumers'&&r.allowAbsent)!,child=scope.resources.find(r=>r.path.includes('/key-auth/'))!;
  const raw={...f.plan.steps[2].mutationPayload};delete raw.tags;const rawHash=f.secrets.fingerprint(raw),sealedHash=f.secrets.fingerprint(f.plan.steps[2].mutationPayload);
  const own=f.input.principal.grants.map((g:any)=>['consumers','secrets'].includes(g.module)?{...g,cluster_id:f.cid,workspace_id:f.wid,scope_type:'tag_group',scope_values:['team-pay']}:g);
  f.input.principal.grants=own;f.tables.iam_effective_grants=own;
  await f.compiler.runResponseScope(async()=>{await observe(f,parent,{...f.plan.steps[0].mutationPayload,tags:['kos-ws-default','team-pay']});await observe(f,child,raw);});
  expect(f.secrets.fingerprint(raw)).toBe(rawHash);expect(raw.tags).toBeUndefined();expect(f.secrets.fingerprint(f.plan.steps[2].mutationPayload)).toBe(sealedHash);
 });
 it('keeps Route observations before inherited Service reads in the fixed scope',async()=>{
  const service=new WorkflowBusinessScopedReadService(),input:any={principal:{user:{superAdmin:false}},plan:{clusterId:id(1)}},material:any={kind:'configuration_v2'};
  const original:any={version:1,limits:{maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432},resources:[
   {clusterId:id(1),workspaceId:id(2),path:`/services/${id(3)}`,kind:'point',entityType:'services',entityId:id(3),secrets:false,required:true},
   {clusterId:id(1),workspaceId:id(2),path:`/routes/${id(4)}`,kind:'point',entityType:'routes',entityId:id(4),secrets:false,required:true}]};
  expect((await service.resolveReadScope(input,material,[],original)).resources.map(r=>r.entityType)).toEqual(['routes','services']);
 });
 it.each([{collision:false,superAdmin:false},{collision:true,superAdmin:false},{collision:false,superAdmin:true},{collision:true,superAdmin:true}])('checks exact old/new Target authority for %j',async({collision,superAdmin})=>{
  const f=await fixture(),upstream=id(90),allocated=id(91),step=f.nested.steps[0];f.user.super_admin=superAdmin;f.input.principal.user.superAdmin=superAdmin;
  Object.assign(step,{entityType:'targets',mutationAction:'update',nativeId:f.service.id,allocatedNativeId:allocated,parentId:upstream,
   objectKey:`targets:${f.service.id}`,before:{id:f.service.id,target:'echo:80',weight:50,upstream:{id:upstream}},
   body:{id:allocated,target:'echo:80',weight:100,upstream:{id:upstream}}});
  step.nativeRequests=[{method:'POST',canonicalPath:`/upstreams/${upstream}/targets`,body:step.body}];await reseal(f);install(f);
  f.input.principal.grants=[...f.input.principal.grants,...['read','write'].map(action=>({user_id:f.actor,module:'upstreams',action,cluster_id:null,workspace_id:null,scope_type:'global',scope_values:[]}))];
  f.tables.iam_effective_grants=f.input.principal.grants;const scope=await f.compiler.resolveReadScope(f.input);
  expect(scope.resources.filter(r=>r.kind==='point'&&r.entityType==='targets').map(r=>({id:r.entityId,absent:r.allowAbsent}))).toEqual([{id:f.service.id,absent:undefined},{id:allocated,absent:true}]);
  const run=f.compiler.runResponseScope(async()=>{
   for(const resource of scope.resources)if(resource.kind==='schema')await observe(f,resource,{fields:[]});
   else if(resource.entityType==='upstreams')await observe(f,resource,{id:upstream,name:'echo',tags:['kos-ws-default']});
   else if(resource.entityId===f.service.id)await observe(f,resource,step.before);
   else if(collision)await observe(f,resource,step.body);else await f.compiler.authorizeResponse({...f.input,resource,response:{message:'Not found'},status:404});
   await f.compiler.assertReadComplete(f.input);
  });if(collision)await expect(run).rejects.toThrow();else await run;expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['workspace','tag_group']as const)('does not convert a %s coarse grant into authority for a sealed empty plan',async kind=>{
  const f=await fixture();f.nested.steps=[];await reseal(f);install(f);grants(f,kind,kind==='workspace'?[f.wid]:['team-pay']);
  const operation=f.compiler.runResponseScope(()=>completeCreates(f));if(kind==='workspace')await operation;else await expect(operation).rejects.toThrow();
  expect(f.db.exec).not.toHaveBeenCalled();
 });
});
