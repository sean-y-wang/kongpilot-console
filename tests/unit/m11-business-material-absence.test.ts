import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {businessAbsenceFixture as fixture,completeEmptyService,observe} from './helpers/workflow-business-absence-fixture';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
async function completePortal(f:Awaited<ReturnType<typeof fixture>>){
 const m=await f.compiler.portalMaterial(f.plan,f.db),scope=await f.compiler.resolveReadScope(f.input);
 for(const r of scope.resources){const body=r.kind==='collection'?{data:[],next:null}:r.kind==='schema'
  ?r.path==='/schemas/consumers'?m.publicationProof.schemas.consumers:r.path==='/schemas/acls'?m.publicationProof.schemas.acls:m.publicationProof.schemas.keyAuth
  :r.entityType==='services'?m.publicationProof.service:r.entityId===m.publicationProof.aclPluginId?m.publicationProof.aclPlugin:m.publicationProof.keyAuthPlugin;
  await observe(f,r,body);}
 await f.compiler.assertReadComplete(f.input);
}
/** Actual sealed material, AES/DAO decoding and current grant predicates.
 * HTTP404 authenticity is separately checked by the SDK/Context tests. These
 * domain tests alone mint no transport observation, approval or permission. */
describe('fixed sealed-business scope supplements real EOF with optional allocated-ID points',()=>{
 it.each(['configuration_v2','portal-credential-issue']as const)('preserves default %s scope and requires explicit fixed policy opt-in',async kind=>{
  const f=await fixture(kind),base=await f.compiler.resolveReadScope(f.input),extended=await f.compiler.resolveAbsenceReadScope(f.input);
  expect(base.resources.every(r=>!r.allowAbsent)).toBe(true);expect(extended.resources.slice(0,base.resources.length)).toEqual(base.resources);
  const optional=extended.resources.slice(base.resources.length);expect(optional).toHaveLength(kind==='configuration_v2'?2:3);
  expect(optional.filter(r=>!r.serviceHostReference)).toHaveLength(kind==='configuration_v2'?1:3);
  expect(optional.filter(r=>r.serviceHostReference).map(r=>r.path)).toEqual(kind==='configuration_v2'?['/upstreams/echo']:[]);
  expect(optional.every(r=>r.allowAbsent===true&&r.required===false&&r.kind==='point'&&r.clusterId===f.cid&&r.workspaceId===f.wid)).toBe(true);
  expect(await f.compiler.businessReadPolicy(kind).resolveReadScope(f.input)).toEqual(base);
  expect(await f.compiler.businessReadPolicy(kind,true).resolveReadScope(f.input)).toEqual(extended);
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('accepts an allocated Service point absence only after complete original read/grant witnesses',async()=>{
  const f=await fixture(),scope=await f.compiler.resolveAbsenceReadScope(f.input),resource=scope.resources.find(r=>r.allowAbsent)!;
  await f.compiler.runResponseScope(async()=>{await completeEmptyService(f);await f.compiler.authorizeResponse({...f.input,resource,response:{message:'Not found'},status:404});});
  expect(resource.entityId).toBe(f.nested.steps[0].allocatedNativeId);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('checks nested Portal future-parent READ/WRITE/secrets inside the actual complete sealed domain witnesses',async()=>{
  const f=await fixture('portal-credential-issue'),scope=await f.compiler.resolveAbsenceReadScope(f.input);
  await f.compiler.runResponseScope(async()=>{await completePortal(f);
   for(const resource of scope.resources.filter(r=>r.allowAbsent))await f.compiler.authorizeResponse({...f.input,resource,response:{message:'Not found'},status:404});});
  expect(scope.resources.filter(r=>r.allowAbsent).map(r=>r.entityId)).toEqual([f.plan.generated.consumerId,f.plan.generated.aclId,f.plan.generated.credentialId]);
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['missing-eof','missing-read','missing-write','foreign-id','not-create','scope-changed'])('rejects %s without turning a 404 error body into an entity or permit',async reason=>{
  const f=await fixture(),scope=await f.compiler.resolveAbsenceReadScope(f.input);let resource:any=scope.resources.find(r=>r.allowAbsent)!;
  if(reason==='missing-read'||reason==='missing-write'){
   const action=reason==='missing-read'?'read':'write';f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter((g:any)=>g.module!=='services'||g.action!==action);
   f.input.principal.grants=f.input.principal.grants.filter((g:any)=>g.module!=='services'||g.action!==action);
  }
  if(reason==='foreign-id')resource={...resource,entityId:'9b000000-0000-4000-8000-000000000999',path:'/services/9b000000-0000-4000-8000-000000000999'};
  if(reason==='not-create')resource={...resource,allowAbsent:false};if(reason==='scope-changed')f.cluster.revision=99;
  await expect(f.compiler.runResponseScope(async()=>{
   if(reason!=='missing-eof')await completeEmptyService(f);
   await f.compiler.authorizeResponse({...f.input,resource,response:{message:'Not found'},status:404});
  })).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
});
