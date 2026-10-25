import 'reflect-metadata';
import { describe,expect,it,vi } from 'vitest';
import { CREDENTIAL_KINDS } from '../../apps/console-api/src/modules/entities/entities.types';
import { assertMigrationConsumerCredentialClosure as validate, type CredentialClosureNode } from '../../apps/console-api/src/modules/workspaces/workspace-credential-closure';

const cid='764178a5-96b2-4d40-971b-f1610cfe60ef';
const id=(n:number)=>`beab2ee1-045b-4c76-8d3b-${n.toString().padStart(12,'0')}`;
const consumer=id(1),otherConsumer=id(2);
const node=(type:string,n:number,parent=consumer):CredentialClosureNode=>({type,id:id(n),data:{id:id(n),...(type==='consumers'?{}:{consumer:{id:parent}})}});
function fixture(nodes:CredentialClosureNode[]=[node('consumers',1)]){
 const pages=new Map<string,any[]>();
 for(const kind of CREDENTIAL_KINDS)pages.set(`/consumers/${consumer}/${kind}`,[{items:nodes.filter(item=>item.type===kind&&item.data.consumer.id===consumer).map(item=>item.data),nextCursor:null}]);
 const kong={list:vi.fn(async(_cid:string,path:string,_query:any,cursor?:string)=>{
  const collection=pages.get(path)??[{items:[],nextCursor:null}];return collection[cursor?Number(cursor):0]??{items:[],nextCursor:null};
 })};
 return {nodes,pages,kong,budget:{pages:0,records:0,bytes:777}};
}

describe('M3 migration Consumer credential closure before remote writes',()=>{
 it('checks all six complete collections including cursor pages and every moved Consumer using the shared aggregate budget',async()=>{
  const nodes=[node('consumers',1),node('consumers',2),...CREDENTIAL_KINDS.map((kind,index)=>node(kind,10+index)),node('key-auth',20)];
  const f=fixture(nodes);f.budget.pages=3;f.budget.records=8;
  f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[nodes[2].data],nextCursor:'1'},{items:[nodes.at(-1)!.data],nextCursor:null}]);
  expect(await validate(f.kong as any,cid,nodes,f.budget)).toEqual({consumers:2,credentials:7,pages:13,records:7});
  expect(f.budget).toEqual({pages:16,records:15,bytes:777});
  expect(f.kong.list.mock.calls.every(([cluster,path,query])=>cluster===cid&&path.startsWith('/consumers/')&&query.size<=100&&!Object.hasOwn(query,'tags'))).toBe(true);
  expect(f.kong.list.mock.calls[1]).toEqual([cid,`/consumers/${consumer}/key-auth`,{size:100},'1','workspace-migration-credential-closure']);
 });

 it.each(['added','deleted','reparented','moved-type'])('refuses a %s credential closure before the caller can issue any PATCH',async(change)=>{
  const f=fixture([node('consumers',1),node('key-auth',10)]),patch=vi.fn();
  if(change==='added')f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[f.nodes[1].data],nextCursor:'1'},{items:[node('key-auth',11).data],nextCursor:null}]);
  if(change==='deleted')f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[],nextCursor:null}]);
  if(change==='reparented')f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[node('key-auth',10,otherConsumer).data],nextCursor:null}]);
  if(change==='moved-type'){
   f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[],nextCursor:null}]);
   f.pages.set(`/consumers/${consumer}/jwt`,[{items:[node('jwt',10).data],nextCursor:null}]);
  }
  const execute=async()=>{await validate(f.kong as any,cid,f.nodes,f.budget);patch();};
  await expect(execute()).rejects.toMatchObject({status:409,response:{code:'MIGRATION_CHILDREN_CHANGED'}});expect(patch).not.toHaveBeenCalled();
 });

 it('does not read or output credential material and ignores secret rotation when the identity/parent closure stays unchanged',async()=>{
  const f=fixture([node('consumers',1),node('basic-auth',10)]);
  Object.defineProperty(f.nodes[1].data,'password',{get:()=>{throw new Error('Secret lookup is forbidden');},enumerable:true});
  const live={id:id(10),consumer:consumer};
  Object.defineProperty(live,'password',{get:()=>{throw new Error('Secret lookup is forbidden');},enumerable:true});
  f.pages.set(`/consumers/${consumer}/basic-auth`,[{items:[live],nextCursor:null}]);
  expect(await validate(f.kong as any,cid,f.nodes,f.budget)).toEqual({consumers:1,credentials:1,pages:6,records:1});
 });

 it('checks only Consumers actually being moved, leaving an independently moved credential parent to caller reference checks',async()=>{
  const f=fixture([node('key-auth',10,otherConsumer)]);
  expect(await validate(f.kong as any,cid,f.nodes,f.budget)).toEqual({consumers:0,credentials:0,pages:0,records:0});
  expect(f.kong.list).not.toHaveBeenCalled();
 });

 it('refuses duplicate identities even when a later page repeats an expected object',async()=>{
  const f=fixture([node('consumers',1),node('key-auth',10)]);
  f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[f.nodes[1].data],nextCursor:'1'},{items:[f.nodes[1].data],nextCursor:null}]);
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toMatchObject({response:{code:'MIGRATION_CHILDREN_CHANGED'}});
 });

 it('refuses cyclic pagination without following an unbounded cursor chain',async()=>{
  const f=fixture();f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[],nextCursor:'1'},{items:[],nextCursor:'1'}]);
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toMatchObject({status:409,response:{code:'WORKSPACE_MIGRATION_PAGINATION_LOOP'}});
  expect(f.kong.list).toHaveBeenCalledTimes(2);
 });

 it('honors an already consumed aggregate page budget before transport and refuses partial collection proof',async()=>{
  const f=fixture();f.budget.pages=100;
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toMatchObject({response:{code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT'}});expect(f.kong.list).not.toHaveBeenCalled();
  f.budget.pages=0;
  await expect(validate(f.kong as any,cid,f.nodes,f.budget,{maxPages:5,maxRecords:10000})).rejects.toMatchObject({response:{code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT'}});
  expect(f.kong.list).toHaveBeenCalledTimes(5);
 });

 it('shrinks the requested page to the remaining record budget and stops before another transport can exceed it',async()=>{
  const f=fixture([node('consumers',1),node('key-auth',10),node('basic-auth',11)]);f.budget.records=9999;
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toMatchObject({response:{code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT'}});
  expect(f.kong.list.mock.calls[0][2]).toEqual({size:1});expect(f.budget.records).toBe(10000);expect(f.kong.list).toHaveBeenCalledTimes(1);
 });

 it('preserves the query bound to a signed cursor and reports aggregate exhaustion before changing its size',async()=>{
  const f=fixture([node('consumers',1),node('key-auth',10),node('key-auth',11)]);f.budget.records=9997;
  f.pages.set(`/consumers/${consumer}/key-auth`,[{items:[f.nodes[1].data],nextCursor:'1'},{items:[f.nodes[2].data],nextCursor:null}]);
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toMatchObject({status:409,response:{code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT'}});
  expect(f.kong.list).toHaveBeenCalledTimes(1);expect(f.kong.list.mock.calls[0][2]).toEqual({size:3});expect(f.budget.records).toBe(9998);
 });

 it.each([
  {items:null,nextCursor:null},
  {items:Array.from({length:101},()=>({id:id(10),consumer})),nextCursor:null},
  {items:[{id:'invalid',consumer}],nextCursor:null},
  {items:[],nextCursor:42},
 ])('rejects malformed native list proof without leaking response content',async(response)=>{
  const f=fixture();f.pages.set(`/consumers/${consumer}/key-auth`,[response]);
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toMatchObject({status:502,response:{code:'KONG_INVALID_MIGRATION_CHILDREN'}});
 });

 it('charges failed transport attempts and propagates their safe failure without fetching another page',async()=>{
  const f=fixture(),error=new Error('Controlled transport failure');f.kong.list.mockRejectedValueOnce(error);
  await expect(validate(f.kong as any,cid,f.nodes,f.budget)).rejects.toBe(error);expect(f.budget.pages).toBe(1);expect(f.kong.list).toHaveBeenCalledTimes(1);
 });
});
