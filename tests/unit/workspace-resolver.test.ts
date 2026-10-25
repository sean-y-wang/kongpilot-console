import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { WorkspaceResolverService, WorkspaceRow } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';

const cid='c18a536e-25d2-40d0-a0eb-45b0b1c6b646',otherCid='c18a536e-25d2-40d0-a0eb-45b0b1c6b647';
const defaultId='d054387d-47aa-4f3d-bf53-a774e93a87d1',payId='d054387d-47aa-4f3d-bf53-a774e93a87d2',opsId='d054387d-47aa-4f3d-bf53-a774e93a87d3';
function harness(){
 const rows:WorkspaceRow[]=['default','pay','ops','gone'].map((code,index)=>({id:[defaultId,payId,opsId,'d054387d-47aa-4f3d-bf53-a774e93a87d4'][index],
  cluster_id:cid,code,name:code,owner_user_id:null,description:'',status:code==='gone'?'deleted':'active',is_default:code==='default',revision:1,
  deleted_at:code==='gone'?'2026-10-10':null,retention_until:null,created_at:'2026-10-10',updated_at:'2026-10-10'}));
 const db={exec:vi.fn().mockResolvedValue(1),one:vi.fn(async(sql:string,params:any[])=>rows.find(row=>row.cluster_id===params[0]&&
  (sql.includes("code='default'")?row.code==='default':sql.includes('code=$2')?row.code===params[1]:row.id===params[1]))??null)};
 return {resolver:new WorkspaceResolverService(db as any),rows,db};
}

describe('M3 authoritative native workspace membership',()=>{
 it('puts untagged history and only the explicit default marker in the default workspace',async()=>{
  const {resolver}=harness(),scope=await resolver.listScope(cid);
  expect(scope.workspaceId).toBe(defaultId);expect(scope.mode).toBe('default');
  expect(resolver.matches(scope,{tags:null})).toBe(true);expect(resolver.matches(scope,{tags:[encodeTag('team:pay')]})).toBe(true);
  expect(resolver.matches(scope,{tags:['kos-ws-default',encodeTag('team:pay')]})).toBe(true);
  expect(resolver.matches(scope,{tags:['kos-ws-pay']})).toBe(false);
 });

 it('quarantines multi/unknown/deleted reserved markers and never exposes a multi-tag object to either workspace',async()=>{
  const {resolver}=harness(),pay=await resolver.listScope(cid,payId),ops=await resolver.listScope(cid,opsId),defaults=await resolver.listScope(cid);
  for(const value of [['kos-ws-pay','kos-ws-ops'],['kos-ws-pay','kos-ws-pay'],['kos-ws-unknown'],['kos-ws-gone'],['kos-ws-']]){
   const result=await resolver.classify(cid,value);expect(result.state).toBe('invalid');expect(result.workspace).toBeNull();
   expect(resolver.matches(defaults,{tags:value})).toBe(false);
  }
  const ambiguous={tags:['kos-ws-pay','kos-ws-ops']};expect(resolver.matches(pay,ambiguous)).toBe(false);expect(resolver.matches(ops,ambiguous)).toBe(false);
  expect(()=>resolver.assertMembership(pay,ambiguous)).toThrow();
 });

 it('never resolves the same workspace ID from another cluster or aliases a deleted workspace to default',async()=>{
  const {resolver}=harness();await expect(resolver.get(otherCid,payId)).rejects.toMatchObject({status:404});
  await expect(resolver.resolve(otherCid,payId)).rejects.toMatchObject({status:403,response:{code:'WORKSPACE_ACCESS_DENIED'}});
  await expect(resolver.resolve(cid,'d054387d-47aa-4f3d-bf53-a774e93a87d4')).rejects.toMatchObject({status:403,response:{code:'WORKSPACE_ACCESS_DENIED'}});
  await expect(resolver.resolve(cid,'d054387d-47aa-4f3d-bf53-a774e93a87d5')).rejects.toMatchObject({status:403,response:{code:'WORKSPACE_ACCESS_DENIED'}});
  await expect(resolver.resolve(otherCid)).rejects.toMatchObject({status:404,response:{code:'CLUSTER_NOT_FOUND'}});
  expect((await resolver.get(cid,'d054387d-47aa-4f3d-bf53-a774e93a87d4',true)).status).toBe('deleted');
 });

 it('pushes workspace AND business-AND to Kong but evaluates workspace AND business-OR in BFF',async()=>{
  const {resolver}=harness(),pay=encodeTag('team:pay'),shared=encodeTag('team:shared');
  const and=await resolver.listScope(cid,payId,`${pay},${shared}`);expect(and.nativeTags?.split(',').sort()).toEqual(['kos-ws-pay',pay,shared].sort());
  const or=await resolver.listScope(cid,payId,`${pay}/${shared}`);expect(or.nativeTags).toBe('kos-ws-pay');expect(or.requiresPostFilter).toBe(true);
  expect(resolver.matches(or,{tags:['kos-ws-pay',shared]})).toBe(true);expect(resolver.matches(or,{tags:['kos-ws-ops',shared]})).toBe(false);
  expect(resolver.matches(or,{tags:['kos-ws-pay']})).toBe(false);
  await expect(resolver.listScope(cid,payId,`${pay},${shared}/other`)).rejects.toMatchObject({status:400});
 });

 it('binds a normalized filter to cluster, workspace revision and full requested boolean expression',async()=>{
  const {resolver,rows}=harness();const original=await resolver.listScope(cid,payId,'a,b');
  expect((await resolver.listScope(cid,payId,'b,a')).binding).toBe(original.binding);
  expect((await resolver.listScope(cid,payId,'a/b')).binding).not.toBe(original.binding);
  expect((await resolver.listScope(cid,opsId,'a,b')).binding).not.toBe(original.binding);
  rows[1].revision++;expect((await resolver.listScope(cid,payId,'a,b')).binding).not.toBe(original.binding);
 });

 it('injects workspace tags on creation, preserves business tags and refuses ordinary cross-workspace mutation',async()=>{
  const {resolver}=harness(),body={name:'test',tags:[encodeTag('team:pay')]};
  expect((await resolver.prepareCreate(cid,'services',body,payId)).tags).toEqual([...body.tags,'kos-ws-pay']);expect(body.tags).toHaveLength(1);
  await expect(resolver.prepareCreate(cid,'services',{tags:['kos-ws-ops']},payId)).rejects.toMatchObject({response:{code:'WORKSPACE_TAG_IMMUTABLE'}});
  const before={id:'entity',tags:['kos-ws-pay','business']};
  expect((await resolver.prepareUpdate(cid,'services',before,{tags:['replacement']},payId)).tags).toEqual(['replacement','kos-ws-pay']);
  expect((await resolver.prepareUpdate(cid,'services',{tags:['business']},{tags:['replacement']})).tags).toEqual(['replacement']);
  await expect(resolver.prepareUpdate(cid,'services',before,{tags:['kos-ws-ops']},payId)).rejects.toMatchObject({response:{code:'WORKSPACE_TAG_IMMUTABLE'}});
 });

 it('derives child workspace from its parent and repairs lagged child mirrors without changing secrets or business tags',async()=>{
  const {resolver}=harness(),parent={id:'consumer',tags:['kos-ws-pay']},child={id:'credential',tags:['kos-ws-ops','business'],password:'current-hash'};
  const patch=await resolver.prepareInheritedUpdate(cid,'basic-auth',parent,child,{tags:child.tags},payId);
  expect(patch).toEqual({tags:['business','kos-ws-pay']});expect(patch).not.toHaveProperty('password');expect(child.tags).toContain('kos-ws-ops');
  expect((await resolver.prepareInheritedCreate(cid,'key-auth',parent,{key:'synthetic-secret'},payId)).tags).toEqual(['kos-ws-pay']);
  await expect(resolver.prepareInheritedUpdate(cid,'targets',parent,child,{tags:['kos-ws-unrelated']},payId)).rejects.toMatchObject({status:400});
 });

 it('keeps disabled workspaces readable while rejecting configuration writes',async()=>{
  const {resolver,rows}=harness();rows[1].status='disabled';
  expect((await resolver.classify(cid,['kos-ws-pay'])).state).toBe('resolved');expect(resolver.matches(await resolver.listScope(cid,payId),{tags:['kos-ws-pay']})).toBe(true);
  await expect(resolver.prepareCreate(cid,'plugins',{},payId)).rejects.toMatchObject({response:{code:'WORKSPACE_DISABLED'}});
 });
});
