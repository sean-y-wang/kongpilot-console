import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { WorkspaceService } from '../../apps/console-api/src/modules/workspaces/workspace.service';
import { WorkspaceResolverService, WorkspaceRow } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { executionFixture } from './execution-test-fixture';

const cid='b681f77a-4d64-4eb7-995c-c00f7deff09b',wid='ebf6267d-3b88-4b58-8e8e-92449c7c2807',defaultId='ebf6267d-3b88-4b58-8e8e-92449c7c2808';
const actor={user:{id:'a9b0ef37-c073-457e-8e54-a56e1bf9fa85',username:'admin',superAdmin:true},idempotencyKey:'workspace-business'};
function harness(){
 const defaults={id:defaultId,cluster_id:cid,code:'default',name:'默认工作区',is_default:true,status:'active',revision:1,description:'',owner_user_id:null,deleted_at:null,retention_until:null,created_at:'2026-10-10T10:00:00Z',updated_at:'2026-10-10T10:00:00Z'} as WorkspaceRow;
 const row={...defaults,id:wid,code:'pay',name:'支付团队',is_default:false,description:'kept-description',created_at:'2026-10-10T11:00:00Z'} as WorkspaceRow;
 const rows=[defaults,row];
 const db:any={exec:vi.fn().mockResolvedValue(1),query:vi.fn().mockResolvedValue(rows),transaction:vi.fn(),one:vi.fn(async(sql:string,params:any[])=>{
  if(sql.includes('FROM users'))return params[0]===actor.user.id?{id:actor.user.id}:null;
  if(sql.startsWith('SELECT'))return rows.find(r=>r.cluster_id===params[0]&&(sql.includes("code='default'")?r.is_default:sql.includes('code=$2')?r.code===params[1]:r.id===params[1]))??null;
  if(sql.startsWith('INSERT INTO workspaces')){if(rows.some(r=>r.code===params[1]))return null;const created={...defaults,id:'ebf6267d-3b88-4b58-8e8e-92449c7c2809',code:params[1],name:params[2],is_default:false,owner_user_id:params[3],description:params[4]};rows.push(created);return created;}
  if(sql.startsWith('UPDATE workspaces')){
   const current=rows.find(r=>r.cluster_id===params[0]&&r.id===params[1]);if(!current)return null;
   const revision=sql.includes('SET name=')?params[6]:params[2];if(current.revision!==revision)return null;
   if(sql.includes("SET status='deleted'")){current.status='deleted';current.deleted_at='2026-10-10T12:00:00Z';current.retention_until='2026-11-09T12:00:00Z';}
   else if(sql.includes("SET status='active'")){current.status='active';current.deleted_at=null;current.retention_until=null;}
   else Object.assign(current,{name:params[2],owner_user_id:params[3],description:params[4],status:params[5]});
   current.revision++;return {...current};
  }
  throw new Error('Unexpected SQL');
 })};db.transaction.mockImplementation(async(fn:any)=>fn(db));
 const authz={assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined),filterEntities:vi.fn(async(_a:any,_c:any,_m:any,items:any[])=>items),permissionVersion:vi.fn().mockResolvedValue('permission-1')};
 const mutations={execute:vi.fn(async(_context:any,fn:any)=>fn())},audit={append:vi.fn().mockResolvedValue(undefined)},kong={list:vi.fn().mockResolvedValue({items:[],nextCursor:null,size:1})};
 const resolver=new WorkspaceResolverService(db);
 const execution=executionFixture();execution.runActor=vi.fn(execution.runActor);execution.runInternalRead=vi.fn(execution.runInternalRead);
 const service=new WorkspaceService(db,resolver,authz as any,mutations as any,audit as any,kong as any,execution);
 return {service,rows,row,defaults,db,authz,mutations,audit,kong,execution};
}
function withRealMutations(f:ReturnType<typeof harness>,mode='direct'){
 Object.assign(f.kong,{transportScope:vi.fn().mockResolvedValue('a'.repeat(64))});
 Object.assign(f.authz,{isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true)});
 const oldQuery=f.db.query.getMockImplementation();f.db.query.mockImplementation((sql:string,...args:any[])=>sql.includes('mutation_operations')?Promise.resolve([]):oldQuery(sql,...args));
 const normal=f.db.one.getMockImplementation()!;
 f.db.one.mockImplementation(async(sql:string,params:any[])=>sql.includes('FROM clusters')?{id:cid,version:'1.5.1',execution_mode:mode}
  :sql.includes('FROM mutation_operations')?null:normal(sql,params));
 const redis={withLock:vi.fn(async(_key:string,fn:any)=>fn())};
 const resolver=new WorkspaceResolverService(f.db),secrets=new SecretService();
 const mutation=new MutationService(f.db,redis as any,secrets,f.audit as any,f.kong as any,f.authz as any,resolver,executionFixture());
 return new WorkspaceService(f.db,resolver,f.authz as any,mutation,f.audit as any,f.kong as any,f.execution);
}

describe('M3 workspace metadata business integrity',()=>{
 beforeEach(()=>{vi.stubEnv('APP_SECRET','workspace-business-signing-key-more-than-32-bytes');vi.stubEnv('CONSOLE_ENCRYPTION_KEY','5b'.repeat(32));});afterEach(()=>vi.unstubAllEnvs());
 it('creates console metadata inside MutationService and audits the row atomically without any gateway write',async()=>{
  const {service,mutations,audit,kong,db}=harness();const row=await service.create(cid,{code:'ops',name:'运维',owner_user_id:actor.user.id},actor);
  expect(row.code).toBe('ops');expect(mutations.execute).toHaveBeenCalledWith(expect.objectContaining({entityType:'workspaces',workspaceId:defaultId}),expect.any(Function));
  expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'workspace.metadata.created',workspaceId:row.id}),db);expect(kong.list).not.toHaveBeenCalled();
 });
 it('refuses reuse of a soft-deleted code and refuses an unavailable owner',async()=>{
  const {service,row,db}=harness();row.status='deleted';
  await expect(service.create(cid,{code:'pay',name:'reuse'},actor)).rejects.toMatchObject({response:{code:'WORKSPACE_CODE_RESERVED'}});
  await expect(service.create(cid,{code:'ops',name:'ops',owner_user_id:'a9b0ef37-c073-457e-8e54-a56e1bf9fa86'},actor)).rejects.toMatchObject({response:{code:'WORKSPACE_OWNER_UNAVAILABLE'}});
  expect(db.one.mock.calls.filter(([sql]:any[])=>sql.startsWith('INSERT INTO workspaces'))).toHaveLength(1);
 });
 it('rejects stale metadata after the outer lock is acquired before any SQL update',async()=>{
  const {service,row,mutations,db}=harness();mutations.execute.mockImplementation(async(_ctx:any,fn:any)=>{row.revision=2;return fn();});
  await expect(service.update(cid,wid,{revision:1,description:'stale-edit'},actor)).rejects.toMatchObject({response:{code:'WORKSPACE_REVISION_CONFLICT'}});
  expect(db.one.mock.calls.some(([sql]:any[])=>sql.startsWith('UPDATE workspaces'))).toBe(false);
 });
 it('protects default workspace from deletion or disablement',async()=>{
  const {service,defaults,mutations}=harness();
  await expect(service.remove(cid,defaultId,{revision:1,confirmed:true,confirm_name:defaults.name},actor)).rejects.toMatchObject({response:{code:'DEFAULT_WORKSPACE_PROTECTED'}});
  await expect(service.update(cid,defaultId,{revision:1,status:'disabled'},actor)).rejects.toMatchObject({response:{code:'DEFAULT_WORKSPACE_PROTECTED'}});expect(mutations.execute).not.toHaveBeenCalled();
 });
 it('counts a malformed multi-workspace entity as nonempty and never deletes metadata around it',async()=>{
  const {service,row,kong,db}=harness();kong.list.mockResolvedValue({items:[{id:'quarantined',tags:['kos-ws-pay','kos-ws-ops']}],nextCursor:null,size:1} as any);
  await expect(service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:row.name},actor)).rejects.toMatchObject({response:{code:'WORKSPACE_NOT_EMPTY'}});
  expect(row.status).toBe('active');expect(kong.list).toHaveBeenCalledTimes(1);expect(db.one.mock.calls.some(([sql]:any[])=>sql.startsWith('UPDATE workspaces'))).toBe(false);
 });
 it('checks all eight native collections with size1 and soft-deletes then restores the original ID and description',async()=>{
  const {service,row,kong,db,audit}=harness();const name=row.name;
  const removed=await service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:name},actor);
  expect(removed).toMatchObject({state:'deleted',workspace:{id:wid,description:'kept-description',revision:2}});expect(kong.list).toHaveBeenCalledTimes(8);
  expect(kong.list.mock.calls.every((args:any[])=>args[2].size===1&&args[2].tags==='kos-ws-pay')).toBe(true);
  expect(db.one.mock.calls.some(([sql]:any[])=>sql.startsWith('DELETE'))).toBe(false);
  const restored=await service.restore(cid,wid,{revision:2,confirmed:true,confirm_name:name},actor);expect(restored).toMatchObject({id:wid,status:'active',revision:3,description:'kept-description',deleted_at:null});
  expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'workspace.metadata.restored',workspaceId:wid}),db);
 });
 it('requires the exact confirmation and keeps callback-time renames from bypassing it',async()=>{
  const {service,row,mutations}=harness();
  await expect(service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:'wrong'},actor)).rejects.toMatchObject({status:400});expect(mutations.execute).not.toHaveBeenCalled();
  const original=row.name;mutations.execute.mockImplementation(async(_ctx:any,fn:any)=>{row.name='new-name';return fn();});
  await expect(service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:original},actor)).rejects.toMatchObject({response:{code:'CONFIRMATION_REQUIRED'}});
 });
 it('binds metadata keyset pagination to actor, filters, page size and current permission version',async()=>{
  const {service,db,authz}=harness();const first=await service.list(cid,{size:1},actor);expect(first.nextCursor).toBeTruthy();
  for(const options of [{size:2},{search:'payment'},{status:'deleted' as const}])await expect(service.list(cid,{size:1,cursor:first.nextCursor!,...options},actor)).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
  await expect(service.list(cid,{size:1,cursor:first.nextCursor!},{user:{...actor.user,id:'other-user'}})).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
  authz.permissionVersion.mockResolvedValue('permission-2');await expect(service.list(cid,{size:1,cursor:first.nextCursor!},actor)).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
  expect(db.query.mock.calls[0][1].at(-1)).toBe(2);
 });

 it('uses the real approval gate for create, update, soft-delete and recovery without entering metadata transactions',async()=>{
  const f=harness(),service=withRealMutations(f,'approval');
  await expect(service.create(cid,{code:'ops',name:'operations'},actor)).rejects.toMatchObject({status:409,response:{code:'APPROVAL_REQUIRED'}});
  await expect(service.update(cid,wid,{revision:1,description:'blocked'},actor)).rejects.toMatchObject({response:{code:'APPROVAL_REQUIRED'}});
  await expect(service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:f.row.name},actor)).rejects.toMatchObject({response:{code:'APPROVAL_REQUIRED'}});
  f.row.status='deleted';f.row.deleted_at='2026-10-10T12:00:00Z';f.row.retention_until='2026-11-09T12:00:00Z';
  await expect(service.restore(cid,wid,{revision:1,confirmed:true,confirm_name:f.row.name},actor)).rejects.toMatchObject({response:{code:'APPROVAL_REQUIRED'}});
  expect(f.db.transaction).not.toHaveBeenCalled();expect(f.kong.list).not.toHaveBeenCalled();
  expect(f.audit.append.mock.calls).toHaveLength(4);expect(f.audit.append.mock.calls.every(([event]:any[])=>event.result==='blocked_approval_required')).toBe(true);
 });

 it('allows a platform administrator to soft-delete and restore an empty disabled workspace through real durable mutations',async()=>{
  const f=harness(),service=withRealMutations(f);f.row.status='disabled';
  const removed=await service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:f.row.name},{...actor,idempotencyKey:'real-delete'});
  expect(removed.state).toBe('deleted');expect(f.kong.list).toHaveBeenCalledTimes(8);
  const restored=await service.restore(cid,wid,{revision:2,confirmed:true,confirm_name:f.row.name},{...actor,idempotencyKey:'real-restore'});
  expect(restored).toMatchObject({id:wid,status:'active',revision:3,description:'kept-description'});
  expect(f.db.exec.mock.calls.filter(([sql]:any[])=>sql.includes('INSERT INTO mutation_operations'))).toHaveLength(2);
  expect(f.audit.append.mock.calls.filter(([event]:any[])=>event.result==='success')).toHaveLength(2);
 });

 it('requires current workspace metadata permission for inactive recovery and permits an explicit enable operation',async()=>{
  const f=harness(),service=withRealMutations(f);f.row.status='disabled';
  const nonPlatform={...actor,user:{...actor.user,superAdmin:false}};
  f.authz.assertCluster.mockImplementation(async(user:any)=>{if(!user.superAdmin)throw new ForbiddenException({code:'IAM_SCOPE_DENIED'});});
  await expect(service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:f.row.name},nonPlatform)).rejects.toMatchObject({status:403,response:{code:'IAM_SCOPE_DENIED'}});
  expect(f.kong.list).not.toHaveBeenCalled();expect(f.db.transaction).not.toHaveBeenCalled();
  expect(await service.update(cid,wid,{revision:1,status:'active'},{...actor,idempotencyKey:'real-enable'})).toMatchObject({status:'active',revision:2});
 });

 it('uses a private bounded raw emptiness proof instead of a permission-filtered caller page',async()=>{
  const f=harness();let purpose:string|undefined;
  f.execution.runInternalRead.mockImplementation(async(_cid:string,next:string,fn:any)=>{const prior=purpose;purpose=next;try{return await fn();}finally{purpose=prior;}});
  f.kong.list.mockImplementation(async()=>({items:purpose==='workspace-empty'?[{id:'hidden-from-tag-group',tags:['kos-ws-pay','team:foreign']}]:[],nextCursor:null,size:1}));
  await expect(f.service.remove(cid,wid,{revision:1,confirmed:true,confirm_name:f.row.name},actor)).rejects.toMatchObject({response:{code:'WORKSPACE_NOT_EMPTY'}});
  expect(f.execution.runActor).toHaveBeenCalledWith(expect.objectContaining({clusterId:cid,workspaceId:wid,module:'workspaces',action:'delete'}),expect.any(Function));
  expect(f.execution.runInternalRead).toHaveBeenCalledWith(cid,'workspace-empty',expect.any(Function),expect.objectContaining({workspaceId:wid,maxCalls:8,maxPages:8,maxRecords:8,paths:expect.arrayContaining(['/services','/snis'])}));
  expect(f.db.one.mock.calls.some(([sql]:any[])=>sql.startsWith('UPDATE workspaces'))).toBe(false);expect(f.audit.append).not.toHaveBeenCalled();
 });
});
