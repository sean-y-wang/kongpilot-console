import {describe,it,expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
// @ts-expect-error executable Node helper
import {journalBrowserTailMutation,proveTailApplicationReceipt,markTailInterrupted} from './lib/m6-browser-tail.mjs';
const fixture=()=>{
  const f={clusterId:randomUUID(),workspaceId:randomUUID(),publicationId:randomUUID()},ownerId=randomUUID(),applicationId=randomUUID();
  const c={fixture:f,ownerId,applicationId,accessExpired:false};
  const r:any={writeAttempts:[],browserTail:{phase:'tail-actions-started',originalApplicationReceiptVerified:true},consoleAdministrator:{user:{id:randomUUID()}},browserWorkflowId:randomUUID(),browserUnknown:{operationId:randomUUID()}};
  return{r,c,body:{clusterId:f.clusterId,workspaceId:f.workspaceId,applicationId,publicationId:f.publicationId}};
};
function request(path:string,body:any,origin='http://127.0.0.1:8082',key=randomUUID()){
  return{url:()=>origin+path,method:()=> 'POST',headers:()=>({'x-idempotency-key':key}),postDataJSON:()=>body};
}
describe('independent unfinished-browser packet tests',()=>{
  it('durably exposes the exact original body, actor and scope before permission to transmit',()=>{
    const f=fixture(),body={...f.body,reason:'原始申请正文'},req=request('/api/v1/portal/requests',body),sent=new Map();
    const persist=vi.fn(()=>{const a=f.r.writeAttempts.at(-1);expect(a.body).toEqual(body);expect(a.actorId).toBe(f.c.ownerId);expect(a.key).toBe(req.headers()['x-idempotency-key']);expect(a.source).toBe('browser-remaining');expect(a.continuation).toBe('tail-only');expect(sent.size).toBe(0);});
    journalBrowserTailMutation(f.r,req,f.c,sent,persist);expect(persist).toHaveBeenCalledOnce();expect(sent.size).toBe(1);
  });
  it.each(['/api/v1/portal/auth/login','/api/v1/portal/applications','/api/v1/portal/applications/old/grants/old/credentials/old/reveal'])('cannot replay prior successful endpoint %s',path=>{
    const f=fixture(),persist=vi.fn();expect(()=>journalBrowserTailMutation(f.r,request(path,f.body),f.c,new Map(),persist)).toThrow();expect(persist).not.toHaveBeenCalled();expect(f.r.writeAttempts).toEqual([]);
  });
  it('rejects cross-origin, cross-tenant and previously used original keys before persistence',()=>{
    const f=fixture(),oldKey=randomUUID();f.r.writeAttempts.push({key:oldKey,state:'response_observed'});
    const variants=[request('/api/v1/portal/requests',f.body,'http://foreign.invalid'),request('/api/v1/portal/requests',{...f.body,workspaceId:randomUUID()}),request('/api/v1/portal/requests',f.body,'http://127.0.0.1:8082',oldKey)];
    for(const req of variants){const persist=vi.fn();expect(()=>journalBrowserTailMutation(f.r,req,f.c,new Map(),persist)).toThrow();expect(persist).not.toHaveBeenCalled();}
    expect(f.r.writeAttempts).toHaveLength(1);
  });
  it('cannot refresh an unexpired original session or send a second request with a different key',()=>{
    const f=fixture(),sent=new Map(),persist=vi.fn();expect(()=>journalBrowserTailMutation(f.r,request('/api/v1/portal/auth/refresh',f.body),f.c,sent,persist)).toThrow();
    journalBrowserTailMutation(f.r,request('/api/v1/portal/requests',f.body),f.c,sent,persist);
    expect(()=>journalBrowserTailMutation(f.r,request('/api/v1/portal/requests',f.body),f.c,sent,persist)).toThrow();expect(persist).toHaveBeenCalledOnce();
  });
  it('a stopped continuation blocks even a new endpoint and key',()=>{
    const f=fixture();f.r.browserTail.phase='stopped-without-replay';const persist=vi.fn();
    expect(()=>journalBrowserTailMutation(f.r,request('/api/v1/auth/login',{username:'admin'},'http://127.0.0.1:8080'),f.c,new Map(),persist)).toThrow();expect(persist).not.toHaveBeenCalled();
  });
  it('retains an interrupted original body and key, then blocks a different future write',()=>{
    const f=fixture(),req=request('/api/v1/portal/requests',f.body),sent=new Map(),persist=vi.fn();
    const original=journalBrowserTailMutation(f.r,req,f.c,sent,persist);
    markTailInterrupted(f.r,req,()=>{expect(original.state).toBe('response-uncertain');expect(original.key).toBe(req.headers()['x-idempotency-key']);expect(original.body).toEqual(f.body);expect(f.r.browserTail.phase).toBe('stopped-without-replay');});
    expect(original.transportInterrupted).toBe(true);
    expect(()=>journalBrowserTailMutation(f.r,request('/api/v1/auth/login',{username:'admin'},'http://127.0.0.1:8080'),f.c,sent,persist)).toThrow();
    expect(f.r.writeAttempts).toHaveLength(1);
  });
  it('does not accept a successful receipt for a different app or operation',()=>{
    const f=fixture(),receipt={id:f.r.browserUnknown.operationId,state:'succeeded',remoteCompleted:true,module:'applications',action:'create',clusterId:f.c.fixture.clusterId,workspaceId:f.c.fixture.workspaceId,safeResult:{entity:{id:f.c.applicationId}}};
    expect(proveTailApplicationReceipt(f.r,receipt,f.c)).toMatchObject({originalKeyVerified:true});
    for(const patch of [{id:randomUUID()},{remoteCompleted:false},{workspaceId:randomUUID()},{safeResult:{entity:{id:randomUUID()}}}])expect(()=>proveTailApplicationReceipt(f.r,{...receipt,...patch},f.c)).toThrow();
  });
});
