import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {businessAbsenceFixture} from './helpers/workflow-business-absence-fixture';
import {WorkflowBusinessScopedReadService} from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ca'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
const id=(n:number)=>`9b000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
async function fixture(superAdmin:boolean,kind:'configuration_v2'|'portal-credential-issue'='configuration_v2'){
 const f=await businessAbsenceFixture(kind);f.user.super_admin=superAdmin;f.input.principal.user.superAdmin=superAdmin;
 f.compiler.installScopedReadBridge(new WorkflowBusinessScopedReadService());return f;
}
/** SQL/AES/current domain compiler tests. A status404 in this component does
 * not issue an SDK witness. Actual Candidate/Validation provider tests retain
 * their genuine original request/parsed404/parent-FK capability requirements. */
describe('all-role exact-point scope compilation keeps authorization independent',()=>{
 it.each(['configuration_v2','portal-credential-issue']as const)('selects the same exact UUID resources for every current role in %s',async kind=>{
  const f=await fixture(false,kind);const expected=await f.compiler.resolveAbsenceReadScope(f.input);
  expect(expected.domain).toBe('scoped-points-v1');expect(expected.resources.filter(r=>r.kind==='collection')).toHaveLength(0);
  for(const role of ['global','workspace','tag_group','entity','super-admin']){
   f.user.super_admin=role==='super-admin';f.input.principal.user.superAdmin=f.user.super_admin;
   const original=f.input.principal.grants,scope_values=role==='workspace'?[f.wid]:role==='tag_group'?['kos-ws-default']:
    role==='entity'?[{entity_type:'services',entity_id:f.service.id}]:[];
   f.input.principal.grants=role==='super-admin'?[]:original.map((g:any)=>({...g,cluster_id:f.cid,workspace_id:f.wid,scope_type:role,scope_values}));
   f.tables.iam_effective_grants=f.input.principal.grants;
   const actual=await f.compiler.resolveAbsenceReadScope(f.input);expect(actual).toEqual(expected);
   f.input.principal.grants=original;f.tables.iam_effective_grants=original;
  }
 });
 it.each([false,true])('requires allocated Service observation and rejects collisions for super-admin=%s',async superAdmin=>{
  const f=await fixture(superAdmin),scope=await f.compiler.resolveReadScope(f.input),point=scope.resources.find(r=>r.entityId===f.service.id)!;
  expect(point).toMatchObject({required:true,allowAbsent:true,path:`/services/${f.service.id}`});
  await expect(f.compiler.runResponseScope(async()=>{for(const r of scope.resources){
   await f.compiler.authorizeResponse({...f.input,resource:r,status:200,response:r.kind==='schema'?{fields:[]}:f.service});}
   await f.compiler.assertReadComplete(f.input);
  })).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_CREATE_ID_ALREADY_EXISTS'}});
 });
 it('retains super-admin current SQL identity, workspace, exact WID and scope closure',async()=>{
  for(const failure of ['status','deleted','force-password','superflag','workspace','wrong-wid','tampered-resource']as const){
   const f=await fixture(true),scope=await f.compiler.resolveReadScope(f.input),point=scope.resources.find(r=>r.entityId===f.service.id)!;
   if(failure==='status')f.user.status='disabled';if(failure==='deleted')f.user.deleted_at=new Date().toISOString();if(failure==='force-password')f.user.force_password_change=true;
   if(failure==='superflag')f.user.super_admin=false;if(failure==='workspace')f.workspace.status='disabled';
   if(failure==='wrong-wid')f.tables.workspaces.push({...f.workspace,id:id(99),code:'other'});
   await expect(f.compiler.runResponseScope(()=>f.compiler.authorizeResponse({...f.input,
    resource:failure==='tampered-resource'?{...point,required:false}:point,status:200,
    response:failure==='wrong-wid'?{...f.service,tags:['kos-ws-other']}:f.service}))).rejects.toThrow();
   expect(f.db.exec).not.toHaveBeenCalled();
  }
 });
 it.each([false,true])('does not invent a parent absence or accept a different child with super-admin=%s',async superAdmin=>{
  const f=await fixture(superAdmin,'portal-credential-issue'),scope=await f.compiler.resolveReadScope(f.input),parent=scope.resources.find(r=>r.entityType==='consumers'&&r.allowAbsent)!,child=scope.resources.find(r=>r.parentId===parent.entityId)!;
  expect(parent.required).toBe(true);expect(child.required).toBe(true);
  await expect(f.compiler.runResponseScope(()=>f.compiler.authorizeScopedParentAbsence(f.input,child,parent))).rejects.toThrow();
 });
 it('keeps compiler-only super-admin support separate from non-super feature authorizer',async()=>{
  const f=await fixture(true),service=new WorkflowBusinessScopedReadService(),material=await f.compiler.materialForPlan(f.plan,f.db);
  await expect(service.assertSubject(f.input,material,[])).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SCOPED_PRINCIPAL_REQUIRED'}});
 });
 it.each([false,true])('retains true Promote coverage collections in the compiler for super-admin=%s',async superAdmin=>{
  const compiler=new WorkflowBusinessScopedReadService(),original:any={version:1,limits:{maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432},resources:[
   {clusterId:id(1),workspaceId:id(2),path:'/services',kind:'collection',entityType:'services',secrets:false,required:true,query:{size:100}}]};
  const actual=await compiler.resolveReadScope({principal:{user:{superAdmin}},plan:{clusterId:id(1)}}as any,{kind:'configuration_v2',promotion:{}}as any,[],original);
  expect(actual.resources).toEqual(original.resources);expect(actual.resources[0].query).toEqual({size:100});expect(actual.domain).toBe('scoped-points-v1');
 });
});
