import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { executionFixture } from './execution-test-fixture';
import { EntityIndexService } from '../../apps/console-api/src/modules/entities/entity-index.service';
const cid='7476b4b8-e8ae-4b29-89be-fd1eeb3f388c',actor={id:'actor',username:'test',superAdmin:false};
describe('scoped search over the background index',()=>{
 let db:any,kong:any,authz:any,workspaces:any,index:EntityIndexService;
 beforeEach(()=>{vi.stubEnv('APP_SECRET','test-index-signature-key-at-least-32-characters');
  db={query:vi.fn().mockResolvedValue([{kong_id:'a',name:'alpha'},{kong_id:'b',name:'beta'}]),one:vi.fn().mockResolvedValue({completed_at:'2026-01-01'}),exec:vi.fn().mockResolvedValue(1)};
  kong={request:vi.fn().mockImplementation(async(_c,_m,path)=>({id:path.split('/').pop(),name:'name',tags:[]}))};
  authz={isPlatformAdmin:vi.fn().mockImplementation(async(user:any)=>user.superAdmin),assertCluster:vi.fn(),scopeTags:vi.fn(),permissionVersion:vi.fn().mockResolvedValue('role-version-1'),filterEntities:vi.fn().mockImplementation(async(_a,_c,_t,rows)=>rows)};
  workspaces={resolve:vi.fn().mockImplementation(async(_cid,wid)=>({id:wid??'default-wid',revision:1})),
   listScope:vi.fn().mockImplementation(async(_cid,wid,tags)=>({workspaceId:wid,workspaceRevision:1,mode:wid==='default-wid'?'default':'tag',workspaceTag:wid==='default-wid'?'kos-ws-default':'kos-ws-pay',requestedTags:tags?tags.split(tags.includes('/')?'/':','):[],tagOperator:tags?.includes('/')?'or':'and',binding:`${wid}:1:${tags??''}`})),
   matches:vi.fn().mockImplementation((scope,entity)=>{const reserved=(entity.tags??[]).filter((tag:string)=>tag.startsWith('kos-ws-'));const membership=scope.mode==='default'?reserved.length===0||reserved.length===1&&reserved[0]==='kos-ws-default':reserved.length===1&&reserved[0]===scope.workspaceTag;return membership&&(!scope.requestedTags.length||(scope.tagOperator==='or'?scope.requestedTags.some((tag:string)=>entity.tags?.includes(tag)):scope.requestedTags.every((tag:string)=>entity.tags?.includes(tag))));})};
  index=new EntityIndexService(db,{withLock:vi.fn()} as any,{redact:(v:any)=>v} as any,kong,authz,workspaces,executionFixture());
 });
 afterEach(()=>vi.unstubAllEnvs());
 it('does not expose cached objects without a live read and authorization',async()=>{authz.filterEntities.mockResolvedValue([]);const page=await index.search(cid,'services',{size:1},actor);expect(page.items).toEqual([]);expect(kong.request).toHaveBeenCalledTimes(2);expect(authz.filterEntities).toHaveBeenCalledTimes(2);});
 it('drops deleted and forbidden cached rows instead of returning stale data',async()=>{kong.request.mockRejectedValueOnce(new NotFoundException()).mockRejectedValueOnce(new ForbiddenException());const page=await index.search(cid,'services',{size:1},actor);expect(page.items).toEqual([]);expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('DELETE FROM entity_index'),[cid,'services','a']);});
 it('binds cursor to caller, scope and current permission version',async()=>{const page=await index.search(cid,'services',{size:1},actor);expect(page.nextCursor).toBeTruthy();await expect(index.search(cid,'services',{size:1,cursor:page.nextCursor!},{...actor,id:'other'})).rejects.toMatchObject({status:400});authz.permissionVersion.mockResolvedValue('role-version-2');await expect(index.search(cid,'services',{size:1,cursor:page.nextCursor!},actor)).rejects.toMatchObject({status:400});expect(db.query).toHaveBeenCalledTimes(1);});
 it('rejects forged cursors, unsupported sort and out of range page sizes before SQL',async()=>{for(const options of [{sort:'name;drop table users'},{size:101},{size:0},{size:NaN},{cursor:'a.b'}])await expect(index.search(cid,'services',options,actor)).rejects.toMatchObject({status:400});expect(db.query).not.toHaveBeenCalled();});
 it('keeps search values parameterized and verifies actual tags after indexing',async()=>{authz.scopeTags.mockResolvedValue('team-a/team-b');kong.request.mockResolvedValue({id:'a',tags:['team-c']});const page=await index.search(cid,'services',{search:"';drop table users;--",size:1},actor);expect(page.items).toEqual([]);expect(db.query.mock.calls[0][0]).not.toContain('drop table');expect(db.query.mock.calls[0][1]).toContain("';drop table users;--");});
 it('omits renamed objects which no longer match a cached search',async()=>{kong.request.mockResolvedValue({id:'a',name:'changed'});const page=await index.search(cid,'services',{search:'alpha',size:1},actor);expect(page.items).toEqual([]);expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO entity_index'),expect.any(Array));});
 it('only sweeps stale inventory after a complete successful traversal',async()=>{
  db.one.mockResolvedValue({cursor:null});kong.list=vi.fn().mockResolvedValue({items:[],nextCursor:'next-page'});
  const worker=new EntityIndexService(db,{withLock:async(_key:string,fn:any)=>fn()} as any,{redact:(v:any)=>v} as any,kong,authz,workspaces,executionFixture());
  await worker.refreshCluster(cid);expect(db.exec.mock.calls.some((call:any[])=>call[0].startsWith('DELETE FROM entity_index'))).toBe(false);
  kong.list.mockResolvedValue({items:[],nextCursor:null});await worker.refreshCluster(cid);
  const sweeps=db.exec.mock.calls.filter((call:any[])=>call[0].startsWith('DELETE FROM entity_index'));expect(sweeps).toHaveLength(8);expect(sweeps[0][0]).toContain('observed_at <');expect(sweeps[0][0]).toContain('sync_cycle IS DISTINCT FROM');expect(kong.list).toHaveBeenCalledTimes(16);
 });
 it('pushes default negative membership into SQL and rechecks live migrated objects',async()=>{
  kong.request.mockResolvedValue({id:'a',name:'alpha',tags:['kos-ws-pay']});
  const page=await index.search(cid,'services',{size:1},actor);
  expect(page.items).toEqual([]);expect(db.query.mock.calls[0][0]).toContain("workspace_tag<>'kos-ws-default'");expect(workspaces.matches).toHaveBeenCalledTimes(2);expect(authz.filterEntities).not.toHaveBeenCalled();
 });
 it('uses workspace AND business OR SQL without exposing other workspace rows',async()=>{
  authz.scopeTags.mockResolvedValue('team-a/team-b');kong.request.mockResolvedValue({id:'a',name:'alpha',tags:['kos-ws-pay','team-b']});
  const page=await index.search(cid,'services',{workspaceId:'pay-wid',size:1},actor);
  expect(page.items).toHaveLength(1);const [sql,values]=db.query.mock.calls[0];expect(sql).toContain('tags @>');expect(sql).toContain('tags &&');expect(sql).toContain('workspace_tag LIKE');expect(values).toContainEqual(['kos-ws-pay']);expect(values).toContainEqual(['team-a','team-b']);expect(authz.filterEntities).toHaveBeenCalledWith(actor,cid,'services',expect.any(Array),'pay-wid');
 });
 it('rejects same-ID cursor reuse in a different workspace and after scope revision change',async()=>{
  const page=await index.search(cid,'services',{size:1},actor);expect(page.nextCursor).toBeTruthy();
  await expect(index.search(cid,'services',{size:1,workspaceId:'pay-wid',cursor:page.nextCursor!},actor)).rejects.toMatchObject({status:400});
  workspaces.listScope.mockResolvedValue({workspaceId:'default-wid',workspaceRevision:2,mode:'default',workspaceTag:'kos-ws-default',requestedTags:[],tagOperator:'and',binding:'default-wid:2:'});
  await expect(index.search(cid,'services',{size:1,cursor:page.nextCursor!},actor)).rejects.toMatchObject({status:400});expect(db.query).toHaveBeenCalledTimes(1);
 });
 it('does not let duplicated or unknown reserved tags fall into the default view',async()=>{
  kong.request.mockResolvedValueOnce({id:'a',tags:['kos-ws-default','kos-ws-pay']}).mockResolvedValueOnce({id:'b',tags:['kos-ws-unknown']});
  const page=await index.search(cid,'services',{size:1},actor);expect(page.items).toEqual([]);expect(authz.filterEntities).not.toHaveBeenCalled();
 });
 it('reports explicit zero counts for all eight kinds in an empty or partial workspace',async()=>{
  db.query.mockResolvedValue([{entity_type:'services',count:2,observed_at:'2026-01-01'}]);db.one.mockResolvedValue({count:1});
  const summary=await index.summary(cid,{...actor,superAdmin:true},'pay-wid');
  expect(summary.counts).toEqual({services:2,routes:0,consumers:0,plugins:0,upstreams:0,certificates:0,ca_certificates:0,snis:0});expect(summary.quarantined_count).toBe(1);expect(summary.workspace_id).toBe('pay-wid');
 });
 it('rejects a foreign refresh scope before any inventory synchronization',async()=>{
  workspaces.resolve.mockRejectedValue(new ForbiddenException());const sync=vi.spyOn(index,'refreshCluster');
  await expect(index.refreshForActor(cid,actor,'foreign-wid')).rejects.toMatchObject({status:403});expect(sync).not.toHaveBeenCalled();
 });
 it('keeps actor initiated index refresh scoped while its trusted inventory job stays cluster-wide',async()=>{
  const sync=vi.spyOn(index,'refreshCluster').mockResolvedValue({results:[]});
  await expect(index.refreshForActor(cid,actor,'pay-wid')).resolves.toEqual({workspace_id:'pay-wid',results:[]});
  expect(authz.assertCluster).toHaveBeenLastCalledWith(actor,cid,'overview','write','pay-wid');expect(sync).toHaveBeenCalledWith(cid);
 });
});
