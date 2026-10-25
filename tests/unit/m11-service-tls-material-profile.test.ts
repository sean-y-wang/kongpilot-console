import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {businessAbsenceFixture as fixture,observe} from './helpers/workflow-business-absence-fixture';
import {WorkflowBusinessScopedReadService} from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {isServiceHostReferencePoint,isServiceHostTargetCollection,validServiceHostReference} from '../../apps/console-api/src/modules/workflows/workflow-service-host-reference';
import {WorkflowScheduleCandidateReadService} from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
const id=(n:number)=>`9b000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
type Fixture=Awaited<ReturnType<typeof fixture>>;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
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


async function setup(host='echo',client=true,cas=true){
 const f=await fixture();f.compiler.installScopedReadBridge(new WorkflowBusinessScopedReadService());const step=f.nested.steps[0];
 step.nativeId=f.service.id;step.allocatedNativeId=null;step.mutationAction='update';step.before={...f.service,host,retries:5,...(client?{client_certificate:{id:id(90)}}:{}),...(cas?{ca_certificates:[id(91),id(92)]}:{})};
 step.body={retries:4};step.nativeRequests=[{method:'PATCH',canonicalPath:`/services/${f.service.id}`,body:step.body}];await reseal(f);
 const grant=['certificates','ca_certificates'].map(module=>({user_id:f.actor,module,action:'read',cluster_id:f.cid,workspace_id:f.wid,scope_type:'workspace',scope_values:[f.wid]}));
 f.input.principal.grants=[...f.input.principal.grants,...grant];f.tables.iam_effective_grants=f.input.principal.grants;
 const scope=await f.compiler.resolveAbsenceReadScope(f.input),rows:any[]=[...(client?[{id:id(90),cert:'fixture-only-public-certificate',key:'fixture-only-private-key',tags:['kos-ws-default']}]:[]),...(cas?[{id:id(91),cert:'fixture-only-ca-one',tags:['kos-ws-default']},{id:id(92),cert:'fixture-only-ca-two',tags:['kos-ws-default']}]:[])];
 const references=rows.map(entity=>({resource:scope.resources.find(r=>r.entityId===entity.id)!,entity}));
 return{...f,step,rows,references,observation:{serviceId:f.service.id,before:step.before,references}};
}
/** Domain-only tests: SQL/AES/current grants are real fixture components;
 * original SDK provenance and Native authority remain the fixed Core gates. */
describe('fixed Service TLS relation participant',()=>{
 it.each(['echo','127.0.0.1','::1'])('checks every sealed certificate and CA for host %s without requiring a named Upstream',async host=>{
  const f=await setup(host);await f.compiler.assertServiceTlsParticipant(f.input,f.observation);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('requires no phantom certificate READ when the sealed effective TLS set is empty',async()=>{
  const f=await setup('127.0.0.1',false,false);f.input.principal.grants=f.input.principal.grants.filter((g:any)=>!['certificates','ca_certificates','secrets'].includes(g.module));f.tables.iam_effective_grants=f.input.principal.grants;
  await f.compiler.assertServiceTlsParticipant(f.input,f.observation);
 });
 it('recompiles the effective fields and accepts explicit client and CA clears with an exact empty set',async()=>{
  const f=await setup();f.step.body={retries:4,client_certificate:null,ca_certificates:[]};f.step.nativeRequests[0].body=f.step.body;await reseal(f);
  await f.compiler.assertServiceTlsParticipant(f.input,{...f.observation,references:[]});
  await expect(f.compiler.assertServiceTlsParticipant(f.input,f.observation)).rejects.toThrow();
 });
 it('requires new effective CA IDs instead of accepting historical refs from the before object',async()=>{
  const f=await setup();f.step.body={retries:4,ca_certificates:[id(93)]};f.step.nativeRequests[0].body=f.step.body;await reseal(f);
  await expect(f.compiler.assertServiceTlsParticipant(f.input,f.observation)).rejects.toThrow();
 });
 it.each(['missing','extra','duplicate','wrong-path','wrong-workspace','wrong-type','wrong-id','wrong-parent','missing-secret-read','missing-cert-read','missing-ca-read','revoked-user','before-hma','wrong-service-id','missing-service-read','missing-service-write','feature-revoked']as const)('rejects %s in the current fixed TLS observation set',async reason=>{
  const f=await setup();let observation:any=structuredClone(f.observation);
  if(reason==='missing')observation.references.pop();
  if(reason==='extra')observation.references.push({...observation.references[0],entity:{...observation.references[0].entity,id:id(99)}});
  if(reason==='duplicate')observation.references[1]=observation.references[0];
  if(reason==='wrong-path')observation.references[0].resource.path='/certificates/other';
  if(reason==='wrong-workspace')observation.references[0].resource.workspaceId=id(99);
  if(reason==='wrong-type')observation.references[0].resource.entityType='ca_certificates';
  if(reason==='wrong-id')observation.references[0].entity.id=id(99);
  if(reason==='wrong-parent'){f.tables.workspaces.push({...f.workspace,id:id(80),code:'other',is_default:false});observation.references[0].entity.tags=['kos-ws-other'];}
  if(reason==='before-hma')observation.before.retries=3;
  if(reason==='wrong-service-id')observation.serviceId=id(99);
  if(['missing-secret-read','missing-cert-read','missing-ca-read','missing-service-read','missing-service-write','feature-revoked'].includes(reason)){
   const module=reason==='missing-secret-read'?'secrets':reason==='missing-cert-read'?'certificates':reason==='missing-ca-read'?'ca_certificates':reason==='feature-revoked'?'snapshots':'services',action=reason==='missing-service-write'?'write':'read';
   f.input.principal.grants=f.input.principal.grants.filter((g:any)=>!(g.module===module&&(module!=='services'||g.action===action)));f.tables.iam_effective_grants=f.input.principal.grants;
  }
  if(reason==='revoked-user')f.user.status='disabled';
  await expect(f.compiler.assertServiceTlsParticipant(f.input,observation)).rejects.toThrow();
 });
 it('rejects a create profile rather than claiming a prospective body is a current existing Service',async()=>{
  const f=await setup();f.step.mutationAction='create';f.step.nativeId=null;f.step.allocatedNativeId=f.service.id;f.step.before=null;f.step.body={...f.service};f.step.nativeRequests=[{method:'POST',canonicalPath:'/services',body:f.step.body}];await reseal(f);
  await expect(f.compiler.assertServiceTlsParticipant(f.input,{serviceId:f.service.id,before:null,references:[]})).rejects.toThrow();
 });
 it('checks reviewer permissions in a separate current-principal scope and restores the executor state',async()=>{
  const f=await setup(),reviewer=id(88),input:any={...f.input,role:'reviewer',principal:{...f.input.principal,user:{...f.input.principal.user,id:reviewer},permissionVersion:`${reviewer}:1:1`,grants:f.input.principal.grants.map((g:any)=>({...g,user_id:reviewer}))}};
  f.tables.users.push({...f.user,id:reviewer});f.tables.iam_effective_grants=[...f.tables.iam_effective_grants,...input.principal.grants];
  await f.compiler.runResponseScope(async()=>{await f.compiler.assertServiceTlsParticipant(input,f.observation);});
  input.principal.grants=input.principal.grants.filter((g:any)=>g.module!=='certificates');f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter((g:any)=>g.user_id!==reviewer||g.module!=='certificates');
  await expect(f.compiler.assertServiceTlsParticipant(input,f.observation)).rejects.toThrow();
 });
 it('rejects a late TLS participant inherited from a closed outer scope',async()=>{
  const f=await setup();let release!:()=>void,late!:Promise<void>;const barrier=new Promise<void>(resolve=>{release=resolve;});
  await f.compiler.runResponseScope(async()=>{late=(async()=>{await barrier;await f.compiler.assertServiceTlsParticipant(f.input,f.observation);})();});release();await expect(late).rejects.toThrow();
 });
 it('checks expiry after the awaited inner scope returns, before exposing success',async()=>{
  const f=await setup(),als=(f.compiler as any).responses,original=als.run.bind(als);
  vi.spyOn(als,'run').mockImplementation((state:any,fn:any)=>original(state,async()=>{const result=await fn();queueMicrotask(()=>{state.expiresAt=Date.now()-1;});return result;}));
  await expect(f.compiler.assertServiceTlsParticipant(f.input,f.observation)).rejects.toThrow();
 });
});
