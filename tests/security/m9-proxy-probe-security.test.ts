import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';

const network=vi.hoisted(()=>({lookup:vi.fn(),http:vi.fn(),https:vi.fn()}));
vi.mock('node:dns/promises',()=>({lookup:network.lookup}));
vi.mock('node:http',()=>({request:network.http}));
vi.mock('node:https',()=>({request:network.https}));
import { assertRegisteredProxyOrigin, proxyProbe } from '../../apps/console-api/src/modules/toolbox/proxy-probe';
import { routeDebugInput } from '../../apps/console-api/src/modules/toolbox/toolbox-input';

const debug=(fields:Record<string,unknown>={})=>routeDebugInput({method:'GET',url:'http://routing.example/v1/resource',headers:{},...fields});
const response=(fields:Record<string,unknown>={})=>Object.assign(new EventEmitter(),{statusCode:200,headers:{},destroy:vi.fn(),...fields});
function installResponse(res:any,chunks:Buffer[]=[]){
  const request=Object.assign(new EventEmitter(),{end:vi.fn(()=>queueMicrotask(()=>{for(const chunk of chunks)res.emit('data',chunk);res.emit('end');})),destroy:vi.fn(),write:vi.fn()});
  network.http.mockImplementation((_url:any,_options:any,receive:any)=>{receive(res);return request;});
  network.https.mockImplementation((_url:any,_options:any,receive:any)=>{receive(res);return request;});return request;
}
beforeEach(()=>{vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','gateway.example,kong,[2001:db8::1],2001:db8::1');for(const key of ['PUBLIC_ORIGINS','PORTAL_PUBLIC_ORIGINS','DATABASE_URL','REDIS_URL'])vi.stubEnv(key,'');network.lookup.mockReset();network.http.mockReset();network.https.mockReset();network.lookup.mockResolvedValue([{address:'192.0.2.1',family:4}]);});
afterEach(()=>{vi.unstubAllEnvs();vi.useRealTimers();});

describe('M9 proxy diagnostics preserve the registered network boundary',()=>{
  it('connects only to the registered origin and pins the DNS result once instead of routing to the submitted URL',async()=>{
    const res=response();installResponse(res);const fence=vi.fn(async()=>undefined);
    const result=await proxyProbe('http://gateway.example:8000',debug(),fence);
    expect(network.lookup).toHaveBeenCalledExactlyOnceWith('gateway.example',{all:true});expect(fence).toHaveBeenCalledTimes(1);
    const [url,options]=network.http.mock.calls[0];expect(url.origin).toBe('http://gateway.example:8000');expect(url.pathname).toBe('/v1/resource');expect(options.headers.host).toBe('routing.example');
    const resolver=vi.fn();options.lookup('gateway.example',{},resolver);expect(resolver).toHaveBeenCalledWith(null,'192.0.2.1',4);expect(network.lookup).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({status:200,bodyReturned:false});
  });
  it.each(['127.0.0.1','169.254.169.254','0.0.0.0','::1','::','::ffff:7f00:1','0:0:0:0:0:0:0:1','0:0:0:0:0:ffff:7f00:1','fe80::1%eth0','fe80::1','fe90::1','fea0::1','febf::1','ff02::1','224.0.0.1','239.255.255.255'])('blocks a protected DNS address before authorization or connection: %s',async address=>{
    network.lookup.mockResolvedValue([{address,family:address.includes(':')?6:4}]);const fence=vi.fn();
    await expect(proxyProbe('http://gateway.example:8000',debug(),fence)).rejects.toMatchObject({response:{code:'PROBE_ADDRESS_FORBIDDEN'}});
    expect(fence).not.toHaveBeenCalled();expect(network.http).not.toHaveBeenCalled();expect(network.https).not.toHaveBeenCalled();
  });
  it('rejects a mixed public/link-local answer instead of trusting the first safe address',async()=>{
    network.lookup.mockResolvedValue([{address:'192.0.2.1',family:4},{address:'169.254.169.254',family:4}]);await expect(proxyProbe('http://gateway.example:8000',debug(),async()=>undefined)).rejects.toMatchObject({response:{code:'PROBE_ADDRESS_FORBIDDEN'}});expect(network.http).not.toHaveBeenCalled();
  });
  it('rechecks permission immediately before connection and sends nothing if that fence rejects',async()=>{
    await expect(proxyProbe('http://gateway.example:8000',debug(),async()=>{throw new Error('synthetic grant revoked');})).rejects.toThrow('synthetic grant revoked');expect(network.http).not.toHaveBeenCalled();
  });
  it('does not follow redirects, return response cookies or echo the submitted authentication header',async()=>{
    const res=response({statusCode:302,headers:{location:'http://169.254.169.254/latest','set-cookie':'synthetic-session=private','authorization':'synthetic-response-token','content-type':'application/json'}});const req=installResponse(res,[Buffer.from('synthetic-private-response')]);
    const result=await proxyProbe('http://gateway.example:8000',debug({headers:{Authorization:'Bearer synthetic-api-key',Host:'169.254.169.254',Connection:'keep-alive','Proxy-Authorization':'synthetic-proxy-key'}}),async()=>undefined);
    expect(network.http).toHaveBeenCalledTimes(1);expect(result.headers).toEqual({'content-type':'application/json'});expect(JSON.stringify(result)).not.toMatch(/synthetic|169\.254|location|cookie|Bearer/);
    expect(network.http.mock.calls[0][1].headers).toEqual({authorization:'Bearer synthetic-api-key',host:'routing.example',connection:'close'});expect(req.write).not.toHaveBeenCalled();
  });
  it('stops response consumption at 64 KiB without returning response bodies',async()=>{
    const res=response();const req=installResponse(res,[Buffer.alloc(65537,120)]);const result=await proxyProbe('http://gateway.example:8000',debug(),async()=>undefined);
    expect(result).toMatchObject({bodyReturned:false,truncated:true,observedBytes:65536});expect(res.destroy).toHaveBeenCalledTimes(1);expect(req.destroy).toHaveBeenCalledTimes(1);
  });
  it('keeps TLS certificate validation enabled and uses the routing SNI explicitly',async()=>{
    installResponse(response());await proxyProbe('https://gateway.example:8000',debug({url:'https://routing.example/v1/resource',sni:'tls.routing.example'}),async()=>undefined);
    expect(network.http).not.toHaveBeenCalled();const options=network.https.mock.calls[0][1];expect(options.servername).toBe('tls.routing.example');expect(options).not.toHaveProperty('rejectUnauthorized',false);
  });
  it.each(['POST','PATCH','DELETE','OPTIONS'])('permits no mutating or unexpected diagnostic method: %s',async method=>{
    await expect(proxyProbe('http://gateway.example:8000',debug({method}),async()=>undefined)).rejects.toMatchObject({response:{code:'PROBE_METHOD_NOT_ALLOWED'}});expect(network.lookup).not.toHaveBeenCalled();expect(network.http).not.toHaveBeenCalled();
  });
  it('protects the registered Admin API even when it uses a custom TCP port',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'http://gateway.example:8002'}])};await expect(assertRegisteredProxyOrigin(db,'http://gateway.example:8002')).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});expect(network.http).not.toHaveBeenCalled();
  });
  it('compares host and TCP port across schemes instead of treating one TLS endpoint as a different destination',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'https://gateway.example:8002'}])};await expect(assertRegisteredProxyOrigin(db,'http://gateway.example:8002')).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});
  });
  it.each([['DATABASE_URL','postgresql://synthetic:synthetic@gateway.example:55432/db','http://gateway.example:55432'],['REDIS_URL','rediss://:synthetic@gateway.example:56379/0','http://gateway.example:56379'],['PORTAL_PUBLIC_ORIGINS','http://gateway.example:5456','http://gateway.example:5456']])('protects custom service endpoints configured through %s',async(environment,registered,origin)=>{
    vi.stubEnv(environment,registered);const db:any={query:vi.fn(async()=>[])};await expect(assertRegisteredProxyOrigin(db,origin)).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});expect(network.lookup).not.toHaveBeenCalled();
  });
  it('rejects a DNS alias of the protected Admin endpoint using the server-pinned addresses and matching TCP port',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'http://admin-alias.example:8002'}])};
    await expect(proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination))).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});
    expect(network.lookup.mock.calls.map(row=>row[0])).toEqual(['gateway.example','admin-alias.example']);expect(network.http).not.toHaveBeenCalled();
  });
  it('does not block the legitimate Kong proxy just because Admin resolves to the same host on a different port',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'http://kong:8001'}])};installResponse(response());
    await proxyProbe('http://kong:8000',debug(),destination=>assertRegisteredProxyOrigin(db,'http://kong:8000',destination));
    expect(network.http).toHaveBeenCalledTimes(1);expect(network.lookup).toHaveBeenCalledExactlyOnceWith('kong',{all:true});
  });
  it('rejects a protected alias appearing anywhere in a multi-address DNS answer',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'http://admin-alias.example:8002'}])};network.lookup.mockImplementation(async(host:string)=>host==='gateway.example'?[{address:'192.0.2.1',family:4}]:[{address:'192.0.2.2',family:4},{address:'192.0.2.1',family:4}]);
    await expect(proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination))).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});expect(network.http).not.toHaveBeenCalled();
  });
  it('normalizes equivalent IPv6 and mapped-IPv4 protected DNS addresses before comparison',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'http://admin-alias.example:8002'}])};network.lookup.mockImplementation(async(host:string)=>host==='gateway.example'?[{address:'2001:db8::1',family:6}]:[{address:'2001:0db8:0:0:0:0:0:1',family:6}]);
    await expect(proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination))).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});
    network.lookup.mockImplementation(async(host:string)=>host==='gateway.example'?[{address:'192.0.2.1',family:4}]:[{address:'::ffff:c000:201',family:6}]);
    await expect(proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination))).rejects.toMatchObject({response:{code:'PROTECTED_PROXY_DESTINATION'}});expect(network.http).not.toHaveBeenCalled();
  });
  it('refuses a copied proof and freezes all of the server proof address material',async()=>{
    const db:any={query:vi.fn(async()=>[])};
    await expect(proxyProbe('http://gateway.example:8002',debug(),async destination=>{expect(Object.isFrozen(destination)).toBe(true);expect(Object.isFrozen(destination.addresses)).toBe(true);await assertRegisteredProxyOrigin(db,'http://gateway.example:8002',{...destination});})).rejects.toMatchObject({response:{code:'PROXY_DESTINATION_PROOF_REQUIRED'}});expect(network.http).not.toHaveBeenCalled();
  });
  it('fails closed if protected endpoint DNS lookup fails',async()=>{
    const db:any={query:vi.fn(async()=>[{url:'http://admin-alias.example:8002'}])};network.lookup.mockImplementation(async(host:string)=>{if(host!=='gateway.example')throw Object.assign(new Error('synthetic failed resolver'),{code:'ENOTFOUND'});return[{address:'192.0.2.1',family:4}];});
    await expect(proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination))).rejects.toMatchObject({response:{code:'PROXY_PROTECTED_DNS_FAILED'}});expect(network.http).not.toHaveBeenCalled();
  });
  it('caps protected same-port DNS candidates at 32 before issuing any of their lookups',async()=>{
    const db:any={query:vi.fn(async()=>Array.from({length:33},(_,index)=>({url:`http://protected-${index}.example:8002`})))};
    await expect(proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination))).rejects.toMatchObject({response:{code:'PROXY_PROTECTED_DNS_BUDGET'}});expect(network.lookup).toHaveBeenCalledTimes(1);expect(network.http).not.toHaveBeenCalled();
  });
  it('caps the combined target and protected DNS stage at 1500 ms and emits no request after timeout',async()=>{
    vi.useFakeTimers();const db:any={query:vi.fn(async()=>[{url:'http://admin-alias.example:8002'}])};network.lookup.mockImplementation(async(host:string)=>host==='gateway.example'?[{address:'192.0.2.1',family:4}]:new Promise(()=>{}));
    const probe=proxyProbe('http://gateway.example:8002',debug(),destination=>assertRegisteredProxyOrigin(db,'http://gateway.example:8002',destination));
    const assertion=expect(probe).rejects.toMatchObject({response:{code:'PROXY_PROTECTED_DNS_TIMEOUT'}});await vi.advanceTimersByTimeAsync(1501);await assertion;expect(network.http).not.toHaveBeenCalled();
  });
});
