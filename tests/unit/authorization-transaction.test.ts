import 'reflect-metadata';
import {describe,it,expect,vi} from 'vitest';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const id=(n:number)=>`61000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
/** Synthetic query responses deliberately fail if a transaction-bound check
 * borrows the global pool. Real PostgreSQL contention has separate evidence. */
function fixture(){
 const actor={id:id(1),username:'transaction-fixture',superAdmin:false},sid=id(2),cid=id(3),wid=id(4);
 const state={active:true,session:true,epoch:1,grants:[{module:'snapshots',action:'read',scope_type:'workspace',cluster_id:cid,workspace_id:wid,scope_values:[wid]}] as any[],workspace:'active',cluster:true};
 const global:any={one:vi.fn(async()=>{throw Error('GLOBAL_POOL_BORROW_FORBIDDEN');}),query:vi.fn(async()=>{throw Error('GLOBAL_POOL_BORROW_FORBIDDEN');})};
 const tx:any={one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM users'))return state.active?{id:actor.id,username:actor.username,super_admin:false,credential_epoch:1,permissions_epoch:1}:null;
  if(sql.includes('FROM auth_sessions'))return state.session&&p[0]===sid?{id:sid}:null;
  if(sql.includes('FROM iam_epoch'))return{version:state.epoch};
  if(sql.includes('FROM clusters'))return state.cluster&&p[0]===cid?{id:cid}:null;
  if(sql.includes('FROM workspaces'))return p[0]===cid&&p[1]===wid?{id:wid,cluster_id:cid,status:state.workspace}:null;
  throw Error('UNEXPECTED_SYNTHETIC_QUERY');
 }),query:vi.fn(async(sql:string)=>{if(sql.includes('iam_effective_grants'))return structuredClone(state.grants);throw Error('UNEXPECTED_SYNTHETIC_QUERY');})};
 const execution=new KongExecutionContextService(),workspaces=new WorkspaceResolverService(global);
 const authz=new AuthorizationService(global,workspaces,{} as any,execution);
 const run=<T>(fn:()=>Promise<T>)=>execution.runHttp({},async()=>{execution.bindHttpActor(actor,sid);return fn();});
 return{actor,sid,cid,wid,state,global,tx,authz,run};
}

describe('transaction-bound current authorization',()=>{
 it('reads identity, active SID and IAM epoch on the provided connection',async()=>{const f=fixture();await f.run(async()=>{
  expect(await f.authz.permissionVersion(f.actor,f.tx)).toBe(`${f.actor.id}:1:1`);
  expect(f.tx.query).not.toHaveBeenCalled();expect(f.global.one).not.toHaveBeenCalled();
 });});
 it.each(['cluster','workspace','services'])('keeps all nested %s scope queries on that connection',async(scope)=>{const f=fixture();
  if(scope==='cluster')f.state.grants=[{module:'snapshots',action:'read',scope_type:'global',cluster_id:f.cid,workspace_id:null,scope_values:[]}];
  await f.run(async()=>{
   if(scope==='cluster')await f.authz.assertWholeCluster(f.actor,f.cid,'snapshots','read',f.tx);
   else if(scope==='workspace')await f.authz.assertWholeWorkspace(f.actor,f.cid,f.wid,'snapshots','read',f.tx);
   else await f.authz.assertCluster(f.actor,f.cid,'snapshots','read',f.wid,f.tx);
   expect(f.global.one).not.toHaveBeenCalled();expect(f.global.query).not.toHaveBeenCalled();
   expect(f.tx.query).toHaveBeenCalled();
  });
 });
 it.each(['inactive','revoked','wrong-actor','missing-grant','wrong-workspace','wrong-cluster','wrong-module','disabled-write'])('still denies %s instead of trusting a transaction or stale actor',async(reason)=>{const f=fixture();
  if(reason==='inactive')f.state.active=false;if(reason==='revoked')f.state.session=false;if(reason==='missing-grant')f.state.grants=[];
  if(reason==='disabled-write'){f.state.workspace='disabled';f.state.grants[0].action='write';}
  await f.run(async()=>{await expect(f.authz.assertWholeWorkspace(reason==='wrong-actor'?{...f.actor,id:id(9),superAdmin:true}:f.actor,
   reason==='wrong-cluster'?id(9):f.cid,reason==='wrong-workspace'?id(9):f.wid,reason==='wrong-module'?'gitops':'snapshots',reason==='disabled-write'?'write':'read',f.tx)).rejects.toThrow();
   expect(f.global.one).not.toHaveBeenCalled();expect(f.global.query).not.toHaveBeenCalled();
  });
 });
 it('rechecks the IAM epoch after materializing grants in the transaction',async()=>{const f=fixture();const read=f.tx.query.getMockImplementation()!;
  f.tx.query.mockImplementation(async(...args:any[])=>{const result=await read(...args);f.state.epoch++;return result;});
  await f.run(async()=>{await expect(f.authz.assertWholeWorkspace(f.actor,f.cid,f.wid,'snapshots','read',f.tx)).rejects.toMatchObject({status:403});});
 });
});
