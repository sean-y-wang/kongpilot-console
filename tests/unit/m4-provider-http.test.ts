import { EventEmitter } from 'node:events';
import { beforeEach,afterEach,describe,expect,it,vi } from 'vitest';
const mocks=vi.hoisted(()=>({lookup:vi.fn(),request:vi.fn(),status:200,body:'{"keys":[]}'}));
vi.mock('node:dns/promises',()=>({lookup:mocks.lookup}));
vi.mock('node:https',()=>({request:mocks.request}));
import { providerJson,providerUrl } from '../../apps/console-api/src/modules/auth/providers/provider-http';
beforeEach(()=>{
 vi.stubEnv('AUTH_PROVIDER_ALLOWED_HOSTS','idp.example');mocks.status=200;mocks.body='{"keys":[]}';mocks.lookup.mockReset().mockResolvedValue([{address:'10.0.0.50',family:4}]);mocks.request.mockReset();
 mocks.request.mockImplementation((_url:any,_options:any,cb:any)=>{
  const request:any=new EventEmitter();request.write=vi.fn();request.destroy=(error:any)=>{request.emit('error',error);request.emit('close');};request.end=()=>queueMicrotask(()=>{const response:any=new EventEmitter();response.statusCode=mocks.status;cb(response);response.emit('data',Buffer.from(mocks.body));response.emit('end');request.emit('close');});return request;
 });
});
afterEach(()=>vi.unstubAllEnvs());
describe('M4 authentication provider transport boundaries',()=>{
 it.each(['169.254.169.254','127.0.0.1','::1','::ffff:169.254.169.254','fe80::1','fe90::1','febf::1','0:0:0:0:0:0:0:1','::ffff:7f00:1','224.0.0.1'])('refuses prohibited resolved address %s before sending provider credentials',async(address)=>{
  mocks.lookup.mockResolvedValue([{address,family:address.includes(':')?6:4}]);await expect(providerJson('https://idp.example/token','POST',new URLSearchParams({secret:'private'}))).rejects.toMatchObject({status:403});expect(mocks.request).not.toHaveBeenCalled();
 });
 it('pins the configured DNS address and keeps credentials in a TLS request body/header rather than URL',async()=>{
  await providerJson('https://idp.example/token','POST',new URLSearchParams({grant_type:'authorization_code',code:'private-code'}),'Basic private-auth');
  const [url,options]=mocks.request.mock.calls[0];expect(url.toString()).toBe('https://idp.example/token');expect(options).not.toHaveProperty('rejectUnauthorized',false);
  const callback=vi.fn();options.lookup('idp.example',{},callback);expect(callback).toHaveBeenCalledWith(null,'10.0.0.50',4);expect(options.headers.Authorization).toBe('Basic private-auth');
 });
 it('rejects redirects without following a new URL and bounds the response',async()=>{
  mocks.status=302;await expect(providerJson('https://idp.example/jwks')).rejects.toMatchObject({status:503});expect(mocks.request).toHaveBeenCalledTimes(1);
  mocks.status=200;mocks.body='x'.repeat(1024*1024+1);await expect(providerJson('https://idp.example/jwks')).rejects.toMatchObject({status:503});
 });
 it('accepts only JSON object responses and configured fixed HTTPS endpoints',async()=>{
  mocks.body='["not-a-jwks-object"]';await expect(providerJson('https://idp.example/jwks')).rejects.toMatchObject({status:503});
  expect(()=>providerUrl('https://unregistered.example/jwks')).toThrow();expect(()=>providerUrl('http://idp.example/jwks')).toThrow();
 });
});
