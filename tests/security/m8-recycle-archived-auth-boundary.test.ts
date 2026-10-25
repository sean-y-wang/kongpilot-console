// Source-only real RecycleService call boundaries with a synthetic sealed graph.
import {describe,it,expect,vi} from 'vitest';
import {ForbiddenException,NotFoundException} from '@nestjs/common';
import {RecycleService} from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import type {RecycleGraph} from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`,cid=id(1),wid=id(2),actor={id:id(3),username:'synthetic',superAdmin:false},consumer=id(4),entryId=id(5);
function fixture(){
 const root={key:`consumers:${consumer}`,type:'consumers',id:consumer,path:`/consumers/${consumer}`,data:{id:consumer,username:'ordinary',tags:['workspace:synthetic']},affected:true,dependencies:[],restorable:true};
 const child={key:`key-auth:${id(6)}`,type:'key-auth',id:id(6),path:`/consumers/${consumer}/key-auth/${id(6)}`,data:{id:id(6),consumer:{id:consumer},key:'SyntheticOnlyCredential'},affected:true,dependencies:[root.key],restorable:true};
 const graph:RecycleGraph={complete:true,rootKey:root.key,nodes:[root,child],capturedAt:new Date().toISOString()};
 const entry={id:entryId,cluster_id:cid,workspace_id:wid,root_type:'consumers',original_id:consumer,root_name:'ordinary',payload_secret:'synthetic-encrypted-only',state:'deleted',actor_id:actor.id};
 const db:any={one:vi.fn(async(sql:string)=>sql.includes('FROM configuration_recycle_components')?null:entry),query:vi.fn(async()=>[]),exec:vi.fn(async()=>1),transaction:vi.fn(async(fn:any)=>fn(db))};
 const authz:any={assertCluster:vi.fn(async()=>undefined),assertEntity:vi.fn(async()=>undefined),assertArchivedEntity:vi.fn(async()=>undefined),isPlatformAdmin:vi.fn(async()=>false)};
 const secrets:any={decrypt:vi.fn(()=>graph),redact:vi.fn((v:any)=>v),fingerprint:vi.fn((v:any)=>JSON.stringify(v))};
 const kong:any={request:vi.fn()},mutations:any={execute:vi.fn()},workspaces:any={listScope:vi.fn(async()=>({workspaceId:wid})),resolve:vi.fn(async()=>({status:'active'})),assertMembership:vi.fn()};
 const service=new RecycleService(db,secrets,kong,mutations,{}as any,authz,{append:vi.fn()}as any,{}as any,{}as any,workspaces,{}as any);
 return{service,db,authz,secrets,kong,mutations,graph,root,child,entry,scope:{workspaceId:wid}};
}
describe('M8 sealed archive authorization stays outside live mutation authorization',()=>{
 it('live deletion preflight retains real current assertEntity without archived fallback',async()=>{
  const f=fixture();await(f.service as any).authorizeGraph(cid,actor,f.graph,'delete',f.scope);
  expect(f.authz.assertEntity).toHaveBeenCalledTimes(2);expect(f.authz.assertArchivedEntity).not.toHaveBeenCalled();
 });
 it('archive preflight receives exact server-decrypted graph and each original node identity',async()=>{
  const f=fixture();await(f.service as any).authorizeGraph(cid,actor,f.graph,'write',f.scope,true);
  expect(f.authz.assertEntity).not.toHaveBeenCalled();expect(f.authz.assertArchivedEntity.mock.calls).toEqual(f.graph.nodes.map(n=>[actor,cid,n.type,'write',n.data,wid,f.graph.nodes]));
 });
 it('shared dependencies require read while affected child requires current write',async()=>{
  const f=fixture();f.root.affected=false;await(f.service as any).authorizeGraph(cid,actor,f.graph,'write',f.scope,true);
  expect(f.authz.assertArchivedEntity.mock.calls.map((v:any[])=>[v[2],v[3]])).toEqual([['consumers','read'],['key-auth','write']]);
 });
 it('preview uses authenticated decrypted archive, including missing-parent child, without a metadata/native write',async()=>{
  const f=fixture();const result=await f.service.preview(cid,entryId,actor,wid);
  expect(f.secrets.decrypt).toHaveBeenCalledWith(f.entry.payload_secret,`recycle:${entryId}`);
  expect(f.authz.assertArchivedEntity).toHaveBeenCalledTimes(4);expect(f.authz.assertEntity).not.toHaveBeenCalled();expect(result.entry).not.toHaveProperty('payload_secret');
  expect(f.db.exec).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('current archived-grant rejection occurs before restoring transition, Mutation or Native',async()=>{
  const f=fixture();f.authz.assertArchivedEntity.mockRejectedValue(new ForbiddenException({code:'CURRENT_GRANT_REVOKED'}));
  await expect(f.service.restore(cid,entryId,actor,{confirmed:true,confirm_name:'ordinary'},{workspaceId:wid})).rejects.toMatchObject({response:{code:'CURRENT_GRANT_REVOKED'}});
  expect(f.db.exec).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('historical Portal ownership still denies before archived permission/dependency/metadata evaluation',async()=>{
  const f=fixture();f.db.query.mockResolvedValue([{id:id(9)}]);
  await expect(f.service.restore(cid,entryId,actor,{confirmed:true,confirm_name:'ordinary'},{workspaceId:wid})).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
  expect(f.authz.assertArchivedEntity).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('archive purge checks current archived delete authority and remains only a console metadata action',async()=>{
  const f=fixture();await f.service.purge(cid,entryId,actor,{confirmed:true,confirm_name:'ordinary'},{workspaceId:wid});
  expect(f.authz.assertArchivedEntity.mock.calls.filter((v:any[])=>v[3]==='delete')).toHaveLength(3);
  expect(f.authz.assertEntity).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.mutations.execute).toHaveBeenCalledTimes(1);
 });
 it('every post-write restored object is checked by real assertEntity, not archived authority',async()=>{
  const f=fixture();f.graph.nodes=[f.root];let actual:any;f.db.one.mockImplementation(async(sql:string)=>sql.includes('FROM configuration_recycle_components')?null:sql.includes('restore_state')?{restore_state:'pending',delete_state:'deleted'}:f.entry);
  f.mutations.execute.mockImplementation(async(_context:any,apply:any)=>apply());
  f.kong.request.mockImplementation(async(_cid:string,method:string,_path:string,body:any)=>{if(method==='POST'){actual={...body};return actual;}if(!actual)throw new NotFoundException();return actual;});
  (f.service as any).execution={runInternalRead:async(_cid:string,_purpose:string,fn:any)=>fn()};
  (f.service as any).index={upsert:vi.fn(async()=>undefined)};
  const result=await f.service.restore(cid,entryId,actor,{confirmed:true,confirm_name:'ordinary'},{workspaceId:wid});
  expect(result.state).toBe('restored');expect(f.authz.assertEntity).toHaveBeenCalledExactlyOnceWith(actor,cid,'consumers','write',actual,wid);
 });
});
