import { beforeEach,afterEach,describe,it,expect,vi } from 'vitest';

const actorA='b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40',actorB='8d0fcfe8-f993-4d97-829f-e3e9b4cfb113';
let client:typeof import('../../apps/console-web/src/api/client');
let login:typeof import('../../apps/console-web/src/api/login-session');
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
function deferred<T>(){let resolve!:(value:T)=>void;const promise=new Promise<T>(done=>{resolve=done;});return {promise,resolve};}
beforeEach(async()=>{
 vi.resetModules();vi.stubGlobal('window',{dispatchEvent:vi.fn()});
 vi.stubGlobal('CustomEvent',class extends Event{detail:unknown;constructor(type:string,options?:{detail?:unknown}){super(type);this.detail=options?.detail;}});
 client=await import('../../apps/console-web/src/api/client');login=await import('../../apps/console-web/src/api/login-session');
 client.setApiActorId(actorA);client.setCsrfToken('old-test-csrf');
});
afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});

describe('M4 login verifies cookies after draining an existing refresh',()=>{
 it.each(['/auth/login','/auth/ldap/corporate/login'])('waits for the old refresh before posting %s and verifies the resulting account',async(path)=>{
  const refresh=deferred<Response>();let reads=0,refreshCompleted=false;const observed:string[]=[];
  const fetch=vi.fn(async(url:string)=>{
   observed.push(url);
   if(url==='/api/v1/private-read')return ++reads===1?json({error:{code:'SESSION_EXPIRED'}},401):json({data:{visible:true}});
   if(url==='/api/v1/auth/refresh'){const response=await refresh.promise;refreshCompleted=true;return response;}
   if(url===`/api/v1${path}`){expect(refreshCompleted).toBe(true);return json({data:{user:{id:actorB,username:'next-user'},csrfToken:'next-csrf'}});}
   if(url==='/api/v1/auth/me')return json({data:{user:{id:actorB,username:'next-user'},csrfToken:'next-csrf'}});
   throw new Error('Unexpected test URL');
  });vi.stubGlobal('fetch',fetch);
  const oldRead=client.api('/private-read');
  await vi.waitFor(()=>expect(observed).toContain('/api/v1/auth/refresh'));
  const pendingLogin=login.loadLoginSession(path,{username:'next-user',password:'test-input-only'});
  await Promise.resolve();await Promise.resolve();
  expect(observed).not.toContain(`/api/v1${path}`);
  refresh.resolve(json({data:{user:{id:actorA},refreshed:true}}));
  const result=await pendingLogin;await oldRead;
  expect(result.user.id).toBe(actorB);expect(client.getApiActorId()).toBe(actorB);
  expect(observed.filter(url=>url===`/api/v1${path}`)).toHaveLength(1);
  expect(observed.indexOf('/api/v1/auth/me')).toBeGreaterThan(observed.indexOf(`/api/v1${path}`));
 });
 it('rejects a login response whose subsequently authenticated cookie belongs to another account',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(json({data:{user:{id:actorB,username:'next-user'},csrfToken:'next-csrf'}}))
   .mockResolvedValueOnce(json({data:{user:{id:actorA,username:'old-user'},csrfToken:'old-csrf'}}));vi.stubGlobal('fetch',fetch);
  await expect(login.loadLoginSession('/auth/login',{username:'next-user',password:'test-input-only'})).rejects.toMatchObject({code:'SESSION_CHANGED'});
  expect(fetch.mock.calls.map(call=>call[0])).toEqual(['/api/v1/auth/login','/api/v1/auth/me']);
  expect(client.getApiActorId()).toBe(actorA);
 });
 it('does not start a new old-account refresh when its delayed 401 arrives after a new login POST began',async()=>{
  const oldResponse=deferred<Response>(),loginResponse=deferred<Response>();const observed:string[]=[];
  vi.stubGlobal('fetch',vi.fn(async(url:string)=>{
   observed.push(url);
   if(url==='/api/v1/private-read')return oldResponse.promise;
   if(url==='/api/v1/auth/login')return loginResponse.promise;
   if(url==='/api/v1/auth/me')return json({data:{user:{id:actorB},csrfToken:'next-csrf'}});
   if(url==='/api/v1/auth/refresh')return json({data:{user:{id:actorA},refreshed:true}});
   throw new Error('Unexpected test URL');
  }));
  const oldRead=client.api('/private-read').catch(error=>error);
  const pendingLogin=login.loadLoginSession('/auth/login',{username:'next-user',password:'test-input-only'});
  await vi.waitFor(()=>expect(observed).toContain('/api/v1/auth/login'));
  oldResponse.resolve(json({error:{code:'SESSION_EXPIRED'}},401));
  const oldError=await oldRead;
  expect(oldError).toMatchObject({code:'SESSION_CHANGED'});expect(observed).not.toContain('/api/v1/auth/refresh');
  loginResponse.resolve(json({data:{user:{id:actorB},csrfToken:'next-csrf'}}));
  await expect(pendingLogin).resolves.toMatchObject({user:{id:actorB}});
 });

 it('rejects concurrent local or LDAP logins without posting a second credential request',async()=>{
  const response=deferred<Response>();const observed:string[]=[];
  vi.stubGlobal('fetch',vi.fn(async(url:string)=>{
   observed.push(url);if(url==='/api/v1/auth/login')return response.promise;
   if(url==='/api/v1/auth/me')return json({data:{user:{id:actorB},csrfToken:'next-csrf'}});throw new Error('Unexpected test URL');
  }));
  const pending=login.loadLoginSession('/auth/login',{username:'next-user',password:'test-input-only'});
  await vi.waitFor(()=>expect(observed).toContain('/api/v1/auth/login'));
  await expect(login.loadLoginSession('/auth/ldap/corporate/login',{username:'other',password:'other-input'})).rejects.toMatchObject({code:'LOGIN_IN_PROGRESS'});
  expect(observed).not.toContain('/api/v1/auth/ldap/corporate/login');
  response.resolve(json({data:{user:{id:actorB},csrfToken:'next-csrf'}}));await pending;
 });
 it('cleans up the login transition after a known login rejection so a deliberate later login can proceed',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(json({error:{code:'INVALID_CREDENTIALS'}},401))
   .mockResolvedValueOnce(json({data:{user:{id:actorB},csrfToken:'next-csrf'}}))
   .mockResolvedValueOnce(json({data:{user:{id:actorB},csrfToken:'next-csrf'}}));vi.stubGlobal('fetch',fetch);
  await expect(login.loadLoginSession('/auth/login',{username:'next-user',password:'wrong-input'})).rejects.toMatchObject({code:'INVALID_CREDENTIALS'});
  await expect(login.loadLoginSession('/auth/login',{username:'next-user',password:'correct-input'})).resolves.toMatchObject({user:{id:actorB}});
  expect(fetch.mock.calls.map(call=>call[0])).toEqual(['/api/v1/auth/login','/api/v1/auth/login','/api/v1/auth/me']);
 });

 it('publishes the verified actor before releasing the gate, so a late old 401 cannot refresh during React applySession scheduling',async()=>{
  const oldResponse=deferred<Response>(),observed:string[]=[];
  vi.stubGlobal('fetch',vi.fn(async(url:string)=>{
   observed.push(url);if(url==='/api/v1/private-read')return oldResponse.promise;
   if(['/api/v1/auth/login','/api/v1/auth/me'].includes(url))return json({data:{user:{id:actorB},csrfToken:'next-csrf'}});
   if(url==='/api/v1/auth/refresh')return json({data:{refreshed:true}});throw new Error('Unexpected test URL');
  }));
  const oldRead=client.api('/private-read').catch(error=>error);
  await login.loadLoginSession('/auth/login',{username:'next-user',password:'test-input-only'});
  expect(client.getApiActorId()).toBe(actorB);
  oldResponse.resolve(json({error:{code:'SESSION_EXPIRED'}},401));
  await expect(oldRead).resolves.toMatchObject({code:'SESSION_CHANGED'});expect(observed).not.toContain('/api/v1/auth/refresh');
 });

});
