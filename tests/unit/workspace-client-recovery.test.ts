import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';

const cid='5b316db5-b0b7-4b91-8197-f893ecb76540',wid='ac18ace3-6ecd-473e-a09b-46be792203d7';
const actorA='b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40',actorB='8d0fcfe8-f993-4d97-829f-e3e9b4cfb113';
const operationId='bc7bd065-9372-405d-9782-015d31a30aa1',key='fc843d08-7627-46f5-8cd0-93fc49f1af22';
const entityPath=`/clusters/${cid}/entities/services?workspaceId=${wid}`;
const options={method:'POST',body:JSON.stringify({name:'service'})};
let client:typeof import('../../apps/console-web/src/api/client');
let events:ReturnType<typeof vi.fn>;
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});

beforeEach(async()=>{
 vi.resetModules();events=vi.fn();vi.stubGlobal('window',{dispatchEvent:events});
 vi.stubGlobal('crypto',{randomUUID:()=>key});
 vi.stubGlobal('CustomEvent',class extends Event{detail:unknown;constructor(type:string,options?:{detail?:unknown}){super(type);this.detail=options?.detail;}});
 client=await import('../../apps/console-web/src/api/client');client.setApiActorId(actorA);client.setCsrfToken('test-csrf');
});
afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});

describe('M3 HTTP recovery stays bound to the initiating account and scope',()=>{
 it('attributes a delayed unknown write to its initiating actor even after another account signs in',async()=>{
  let fail!:(error:Error)=>void;vi.stubGlobal('fetch',vi.fn(()=>new Promise((_resolve,reject)=>{fail=reject;})));
  const pending=client.api(entityPath,options).catch(error=>error);
  client.setApiActorId(actorB);fail(new Error('connection closed'));
  const error=await pending;
  expect(error).toMatchObject({code:'WRITE_RESULT_UNKNOWN',recovery:{clusterId:cid,workspaceId:wid,idempotencyKey:key,state:'uncertain'}});
  expect(events).toHaveBeenCalledTimes(1);expect(events.mock.calls[0][0].detail).toMatchObject({actorId:actorA,error});
 });
 it('classifies only plan/reconcile POST calls as interrupted read-only review operations',async()=>{
  const fetch=vi.fn().mockRejectedValue(new Error('connection closed'));vi.stubGlobal('fetch',fetch);
  for(const path of [`/clusters/${cid}/workspace-migrations/plan?workspaceId=${wid}`,`/clusters/${cid}/workspace-migrations/${operationId}/reconcile?workspaceId=${wid}`,`/clusters/${cid}/inventory/refresh?workspaceId=${wid}`]){
   const error=await client.api(path,options).catch(error=>error);expect(error).toMatchObject({code:'NETWORK_REVIEW_INTERRUPTED'});expect(error.recovery).toBeUndefined();
  }
  expect(events).not.toHaveBeenCalled();
  const error=await client.api(`/clusters/${cid}/workspace-migrations/${operationId}/apply?workspaceId=${wid}`,options).catch(error=>error);
  expect(error.code).toBe('WRITE_RESULT_UNKNOWN');expect(error.recovery.workspaceId).toBe(wid);expect(events).toHaveBeenCalledTimes(1);
  const patch=await client.api(`/clusters/${cid}/inventory/refresh?workspaceId=${wid}`,{...options,method:'PATCH'}).catch(error=>error);expect(patch.code).toBe('WRITE_RESULT_UNKNOWN');expect(events).toHaveBeenCalledTimes(2);
 });
 it('retains unknown status for proxy errors and unreadable successful write responses',async()=>{
  for(const response of [json({},502),json({},504),new Response('upstream closed',{status:200}),new Response('null',{status:200})]){
   vi.stubGlobal('fetch',vi.fn().mockResolvedValue(response));const error=await client.api(entityPath,options).catch(error=>error);
   expect(error).toMatchObject({code:'WRITE_RESULT_UNKNOWN',recovery:{idempotencyKey:key,clusterId:cid,workspaceId:wid,state:'uncertain'}});
  }
  expect(events).toHaveBeenCalledTimes(4);
 });
 it('refreshes the same account without changing the original write idempotency key or workspace',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(json({error:{code:'SESSION_EXPIRED'}},401)).mockResolvedValueOnce(json({data:{refreshed:true}})).mockResolvedValueOnce(json({data:{id:'service'}}));vi.stubGlobal('fetch',fetch);
  await expect(client.api(entityPath,options)).resolves.toEqual({id:'service'});
  expect(fetch.mock.calls.map(call=>call[0])).toEqual([`/api/v1${entityPath}`,'/api/v1/auth/refresh',`/api/v1${entityPath}`]);
  expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);expect(new Headers(fetch.mock.calls[2][1].headers).get('X-Idempotency-Key')).toBe(key);expect(events).not.toHaveBeenCalled();
 });
 it('does not refresh or replay an old account write after the initial 401 arrives under a different account',async()=>{
  const fetch=vi.fn().mockImplementationOnce(async()=>{client.setApiActorId(actorB);return json({error:{code:'SESSION_EXPIRED'}},401);}).mockResolvedValue(json({data:{id:'unexpected'}}));vi.stubGlobal('fetch',fetch);
  const error=await client.api(entityPath,options).catch(error=>error);
  expect(error).toMatchObject({code:'SESSION_CHANGED'});expect(fetch).toHaveBeenCalledTimes(1);expect(events).not.toHaveBeenCalled();
 });
 it('does not replay an old account write if the account changes while refresh is in flight',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(json({error:{code:'SESSION_EXPIRED'}},401)).mockImplementationOnce(async()=>{client.setApiActorId(actorB);return json({data:{refreshed:true}});}).mockResolvedValue(json({data:{id:'unexpected'}}));vi.stubGlobal('fetch',fetch);
  const error=await client.api(entityPath,options).catch(error=>error);
  expect(error).toMatchObject({code:'SESSION_CHANGED'});expect(fetch).toHaveBeenCalledTimes(2);expect(events).not.toHaveBeenCalled();
 });
 it('does not expire the new account when the old account refresh fails after an account switch',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(json({error:{code:'SESSION_EXPIRED'}},401)).mockImplementationOnce(async()=>{client.setApiActorId(actorB);return json({error:{code:'SESSION_EXPIRED'}},401);});vi.stubGlobal('fetch',fetch);
  const error=await client.api(entityPath,options).catch(error=>error);
  expect(error).toMatchObject({code:'SESSION_CHANGED'});expect(fetch).toHaveBeenCalledTimes(2);expect(events).not.toHaveBeenCalled();
 });
 it('does not expire the new account when a delayed retried request returns the old account 401',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(json({error:{code:'SESSION_EXPIRED'}},401)).mockResolvedValueOnce(json({data:{refreshed:true}})).mockImplementationOnce(async()=>{client.setApiActorId(actorB);return json({error:{code:'SESSION_EXPIRED'}},401);});vi.stubGlobal('fetch',fetch);
  const error=await client.api(entityPath,options).catch(error=>error);
  expect(error).toMatchObject({code:'SESSION_CHANGED'});expect(fetch).toHaveBeenCalledTimes(3);expect(events).not.toHaveBeenCalled();
 });
});
