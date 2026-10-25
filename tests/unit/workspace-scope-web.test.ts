import { describe,expect,it } from 'vitest';
import { canonicalId,receiptProvesCompletion,safeRecoveryReferences,scopeQuery,workspacePath } from '../../apps/console-web/src/api/workspace-scope';

const cid='5b316db5-b0b7-4b91-8197-f893ecb76540';
const wid='ac18ace3-6ecd-473e-a09b-46be792203d7';
const otherWid='46f5bc97-cfe3-4e2a-a4e0-c8c9988e604a';
const actorId='b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40';
const otherActor='8d0fcfe8-f993-4d97-829f-e3e9b4cfb113';
const key='fc843d08-7627-46f5-8cd0-93fc49f1af22';
const operationId='bc7bd065-9372-405d-9782-015d31a30aa1';
const now=Date.parse('2026-10-10T12:00:00Z');
const validReference={actor_id:actorId,cid,wid,idempotencyKey:key,operationId,created_at:new Date(now-1000).toISOString(),state:'uncertain'};

describe('M3 frontend captured workspace scope',()=>{
 it('keeps the original workspace when checking a durable receipt or opening an archived entry',()=>{
  const receipt=scopeQuery(`/clusters/${cid}/mutations/${operationId}`,cid,wid);
  const archived=scopeQuery(`/clusters/${cid}/recycle-bin/${operationId}?reveal=false`,cid,wid);
  expect(new URL(receipt,'https://console.example').searchParams.get('workspaceId')).toBe(wid);
  expect(new URL(archived,'https://console.example').searchParams.get('workspaceId')).toBe(wid);
  expect(new URL(archived,'https://console.example').searchParams.get('reveal')).toBe('false');
 });
 it('rejects cross-workspace paths rather than silently retargeting a captured request',()=>{
  expect(()=>scopeQuery(`/clusters/${cid}/entities/services?workspaceId=${otherWid}`,cid,wid)).toThrow('操作范围不一致');
  expect(()=>scopeQuery(`/clusters/${otherWid}/entities/services`,cid,wid)).toThrow('尚未就绪');
 });
 it('requires both canonical registry identifiers and a scoped resource path',()=>{
  for(const value of [undefined,'default','workspace:pay','../../other','',`${wid}/`])expect(()=>scopeQuery(`/clusters/${cid}/entities/services`,cid,value)).toThrow();
  expect(()=>scopeQuery(`/clusters/${cid}`,cid,wid)).toThrow();
  expect(()=>scopeQuery(`https://kong:8001/clusters/${cid}/services`,cid,wid)).toThrow();
 });
 it('replaces duplicate workspace query parameters with a single captured canonical value',()=>{
  const scoped=scopeQuery(`/clusters/${cid}/entities/routes?size=20&workspaceId=${wid.toUpperCase()}&workspaceId=${otherWid}&tags=team%3Apay`,cid,wid);
  const params=new URL(scoped,'https://console.example').searchParams;
  expect(params.getAll('workspaceId')).toEqual([wid]);expect(params.get('size')).toBe('20');expect(params.get('tags')).toBe('team:pay');
 });
 it('constructs entity queries without reading a mutable global selector',()=>{
  const query=new URLSearchParams({size:'20',cursor:'signed+/cursor',tags:'team:pay'});
  const original=workspacePath(cid,wid,'/entities/plugins',query);
  const later=workspacePath(cid,otherWid,'/entities/plugins',query);
  expect(new URL(original,'https://console.example').searchParams.get('workspaceId')).toBe(wid);
  expect(new URL(later,'https://console.example').searchParams.get('workspaceId')).toBe(otherWid);
  expect(query.has('workspaceId')).toBe(false);
 });
});

describe('M3 frontend durable recovery reference hygiene',()=>{
 it('persists only account, scope and operation identifiers while excluding credentials and payloads',()=>{
  const reference={...validReference,password:'private',config:{key:'private'},before:{secret:'private'},after:{token:'private'},body:'private',requestId:'untrusted'};
  expect(safeRecoveryReferences([reference],actorId,now)).toEqual([validReference]);
 });
 it('drops another account references and malformed scope/key identifiers',()=>{
  const values=[{...validReference,actor_id:otherActor},{...validReference,cid:'kong:8001'},{...validReference,wid:'default'},{...validReference,idempotencyKey:'../mutations'},{...validReference,actor_id:'admin'},null,[],false];
  expect(safeRecoveryReferences(values,actorId,now)).toEqual([]);expect(safeRecoveryReferences({},actorId,now)).toEqual([]);
 });
 it('drops expired, invalid and excessive future timestamps',()=>{
  const values=['invalid',new Date(now-86_400_001).toISOString(),new Date(now+60_001).toISOString()].map(created_at=>({...validReference,created_at}));
  expect(safeRecoveryReferences(values,actorId,now)).toEqual([]);
  expect(safeRecoveryReferences([{...validReference,created_at:new Date(now-86_400_000).toISOString()}],actorId,now)).toHaveLength(1);
 });
 it('canonicalizes persisted ids, ignores invalid optional operation ids and never trusts unknown states',()=>{
  const reference={...validReference,cid:cid.toUpperCase(),wid:wid.toUpperCase(),idempotencyKey:key.toUpperCase(),operationId:'../../other',state:'succeeded'};
  const [safe]=safeRecoveryReferences([reference],actorId,now);
  expect(safe).toEqual({...validReference,operationId:undefined,state:'uncertain'});
  expect(Object.hasOwn(safe,'operationId')).toBe(false);
  expect(canonicalId(cid.toUpperCase())).toBe(cid);expect(canonicalId(` ${cid}`)).toBeUndefined();
 });
 it('bounds browser retained references after validating every entry',()=>{
  const values=Array.from({length:35},(_,index)=>({...validReference,created_at:new Date(now-index*1000).toISOString()}));
  expect(safeRecoveryReferences(values,actorId,now)).toEqual(values.slice(-30));
 });
});

describe('M3 conservative receipt completion proof',()=>{
 it('requires a terminal state and an actual boolean remote_completed proof',()=>{
  for(const state of ['succeeded','failed'])expect(receiptProvesCompletion({state,remote_completed:true})).toBe(true);
  for(const state of ['running','uncertain','pending','partial','deleted','restored',''])expect(receiptProvesCompletion({state,remote_completed:true})).toBe(false);
  for(const remote_completed of [false,undefined,null,0,1,'true','false'])expect(receiptProvesCompletion({state:'succeeded',remote_completed})).toBe(false);
 });
 it('does not infer completion from a missing receipt, optimistic safe_result or an error code',()=>{
  for(const receipt of [null,undefined,{}, {state:'succeeded',safe_result:{state:'succeeded'}}, {state:'failed',error_code:'ENTITY_CHANGED',remote_started:false}])expect(receiptProvesCompletion(receipt)).toBe(false);
 });
});
