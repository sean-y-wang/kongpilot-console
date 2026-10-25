import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';

const cid='5b316db5-b0b7-4b91-8197-f893ecb76540',wid='ac18ace3-6ecd-473e-a09b-46be792203d7';
const actor='b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40',intent='bc7bd065-9372-405d-9782-015d31a30aa1',key='fc843d08-7627-46f5-8cd0-93fc49f1af22';
let client:typeof import('../../apps/console-web/src/api/client'),events:ReturnType<typeof vi.fn>;
beforeEach(async()=>{
 vi.resetModules();events=vi.fn();vi.stubGlobal('window',{dispatchEvent:events});
 vi.stubGlobal('crypto',{randomUUID:()=>key});
 vi.stubGlobal('CustomEvent',class extends Event{detail:unknown;constructor(type:string,options?:{detail?:unknown}){super(type);this.detail=options?.detail;}});
 client=await import('../../apps/console-web/src/api/client');client.setApiActorId(actor);client.setCsrfToken('source-only-test-csrf');
});
afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});
describe('M11 annotation preparation owns its original-key recovery',()=>{
 it.each([undefined,'fresh-verified-session-csrf',''])('preserves a caller-verified CSRF header %j instead of substituting cached credentials',async explicit=>{
  const fetch=vi.fn().mockResolvedValue(new Response(JSON.stringify({data:{prepared:true}}),{headers:{'Content-Type':'application/json'}}));vi.stubGlobal('fetch',fetch);
  await client.api(`/clusters/${cid}/annotation-changes/prepare?workspaceId=${wid}`,{method:'POST',body:'{}',headers:explicit===undefined?{}:{'X-CSRF-Token':explicit}},true);
  expect(new Headers(fetch.mock.calls[0][1].headers).get('X-CSRF-Token')).toBe(explicit===undefined?'source-only-test-csrf':explicit);
  expect(fetch).toHaveBeenCalledTimes(1);
 });
 it.each(['prepare',`${intent}/submit`])('keeps interrupted %s out of the generic native mutation journal',async suffix=>{
  const fetch=vi.fn().mockRejectedValue(new Error('transport closed'));vi.stubGlobal('fetch',fetch);
  const error=await client.api(`/clusters/${cid}/annotation-changes/${suffix}?workspaceId=${wid}`,{method:'POST',body:'{}',headers:{'X-Idempotency-Key':key}},true).catch(e=>e);
  expect(error.recovery).toBeUndefined();expect(events).not.toHaveBeenCalled();expect(fetch).toHaveBeenCalledTimes(1);
  expect(new Headers(fetch.mock.calls[0][1].headers).get('X-Idempotency-Key')).toBe(key);
 });
 it.each(['prepare',`${intent}/submit`])('does not refresh or replay an annotation %s POST after 401',async suffix=>{
  const fetch=vi.fn().mockResolvedValue(new Response(JSON.stringify({error:{code:'SESSION_EXPIRED'}}),{status:401,headers:{'Content-Type':'application/json'}}));vi.stubGlobal('fetch',fetch);
  await expect(client.api(`/clusters/${cid}/annotation-changes/${suffix}?workspaceId=${wid}`,{method:'POST',body:'{}'},true)).rejects.toMatchObject({status:401});
  expect(fetch).toHaveBeenCalledTimes(1);
 });
 it.each([['POST','prepare-extra'],['POST',`${intent}/execute`],['PATCH','prepare']])('keeps unrelated %s %s failures in the normal write recovery domain',async(method,suffix)=>{
  vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new Error('transport closed')));
  const error=await client.api(`/clusters/${cid}/annotation-changes/${suffix}?workspaceId=${wid}`,{method,body:'{}'},true).catch(e=>e);
  expect(error).toMatchObject({code:'WRITE_RESULT_UNKNOWN',recovery:{clusterId:cid,workspaceId:wid,idempotencyKey:key,state:'uncertain'}});
  expect(events).toHaveBeenCalledTimes(1);
 });
});
