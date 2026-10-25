import 'reflect-metadata';
import { beforeEach,afterEach,describe,expect,it,vi } from 'vitest';
import { generateKeyPairSync,createHash } from 'node:crypto';
import jwt from 'jsonwebtoken';
const mocks=vi.hoisted(()=>({json:vi.fn(),bind:vi.fn(),search:vi.fn(),unbind:vi.fn(),client:vi.fn()}));
vi.mock('../../apps/console-api/src/modules/auth/providers/provider-http',async(importOriginal)=>({...(await importOriginal<any>()),providerJson:mocks.json,providerAddress:vi.fn(async()=>({address:'10.0.0.50',family:4}))}));
vi.mock('ldapts',()=>({Client:class {constructor(options:any){mocks.client(options);}bind=mocks.bind;search=mocks.search;unbind=mocks.unbind;}}));
import { IdentityProviders,configuredProviders,escapeLdapFilter } from '../../apps/console-api/src/modules/auth/providers/identity-providers';
const role='f021291a-c12e-4ce7-99e1-ab1990c8c6b4';
const oidc:any={id:'corp',name:'Corporate SSO',type:'oidc',issuer:'https://idp.example',authorization_url:'https://idp.example/authorize',token_url:'https://idp.example/token',jwks_url:'https://idp.example/jwks',client_id:'console',client_secret:'provider-secret-never-public',callback_uri:'https://console.example/api/v1/auth/oidc/corp/callback',groups_claim:'groups',group_roles:{operators:[role]}};
const ldap:any={id:'directory',name:'Directory',type:'ldap',url:'ldaps://ldap.example:636',bind_dn:'cn=reader,dc=example',bind_password:'bind-secret-never-public',base_dn:'ou=users,dc=example',username_attribute:'uid',subject_attribute:'entryUUID',groups_attribute:'memberOf',group_roles:{operators:[role]}};
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
let redis:any,states:Map<string,string>,providers:IdentityProviders;
function environment(config:any[]=[oidc,ldap]){vi.stubEnv('AUTH_PROVIDERS_JSON',JSON.stringify(config));}
beforeEach(()=>{
 vi.stubEnv('AUTH_PROVIDER_ALLOWED_HOSTS','idp.example,ldap.example');vi.stubEnv('PUBLIC_ORIGINS','https://console.example');vi.stubEnv('NODE_ENV','production');environment();
 states=new Map();redis={client:{set:vi.fn(async(key:string,value:string)=>{states.set(key,value);return 'OK';}),getdel:vi.fn(async(key:string)=>{const value=states.get(key);states.delete(key);return value;})}};
 providers=new IdentityProviders(redis);mocks.json.mockReset();mocks.bind.mockReset().mockResolvedValue(undefined);mocks.search.mockReset();mocks.unbind.mockReset().mockResolvedValue(undefined);mocks.client.mockReset();
});
afterEach(()=>vi.unstubAllEnvs());
async function flow(overrides:any={}){
 const begin=await providers.start('corp','/profile'),url=new URL(begin.authorizationUrl),state=url.searchParams.get('state')!,stored=JSON.parse([...states.values()][0]);
 const {iss,aud,...rest}=overrides;const token=jwt.sign({nonce:stored.nonce,groups:['operators'],email:'admin@example',email_verified:true,...rest},privateKey,{algorithm:'RS256',keyid:'key-1',issuer:overrides.iss??oidc.issuer,audience:overrides.aud??oidc.client_id,subject:'verified-subject',expiresIn:300});
 const jwk={...publicKey.export({format:'jwk'}),kid:'key-1',alg:'RS256',use:'sig'};
 mocks.json.mockImplementation(async(path:string)=>path===oidc.token_url?{id_token:token}:{keys:[jwk]});return {begin,url,state,stored,token,jwk};
}
describe('M4 bounded optional authentication providers',()=>{
 it('publishes only id/name/type and never provider secrets or endpoint configuration',()=>{
  expect(providers.catalog()).toEqual([{id:'corp',name:'Corporate SSO',type:'oidc'},{id:'directory',name:'Directory',type:'ldap'}]);expect(JSON.stringify(providers.catalog())).not.toContain('secret');
 });
 it('has no fallback login for unconfigured LDAP/OIDC providers',async()=>{
  environment([]);expect(providers.catalog()).toEqual([]);await expect(providers.ldap('missing','user','pw')).rejects.toMatchObject({status:503});await expect(providers.start('missing')).rejects.toMatchObject({status:503});expect(mocks.json).not.toHaveBeenCalled();expect(mocks.bind).not.toHaveBeenCalled();
 });
 it.each(['http://idp.example/jwks','https://rogue.example/jwks','https://user:pw@idp.example/jwks','https://idp.example/jwks?url=rogue'])('rejects unsafe configured JWKS URL %s',url=>{environment([{...oidc,jwks_url:url}]);expect(()=>configuredProviders()).toThrow();});
 it('rejects callback origins and paths outside the registered console',()=>{
  environment([{...oidc,callback_uri:'https://rogue.example/api/v1/auth/oidc/corp/callback'}]);expect(()=>configuredProviders()).toThrow();
  environment([{...oidc,callback_uri:'https://console.example/redirect'}]);expect(()=>configuredProviders()).toThrow();
 });
 it('escapes all RFC4515 filter metacharacters and verifies one directory subject with TLS pinned DNS',async()=>{
  mocks.search.mockResolvedValue({searchEntries:[{dn:'uid=alice,ou=users,dc=example',entryUUID:'stable-directory-id',memberOf:['operators']}],searchReferences:[]});
  const username='alice*)(uid=*)';const result=await providers.ldap('directory',username,'ephemeral-password');
  expect(escapeLdapFilter('\0()*\\')).toBe('\\00\\28\\29\\2a\\5c');
  expect(mocks.search.mock.calls[0][1]).toMatchObject({filter:'(uid=alice\\2a\\29\\28uid=\\2a\\29)',sizeLimit:2,timeLimit:5});
  expect(mocks.client.mock.calls[0][0]).toMatchObject({url:'ldaps://10.0.0.50:636',tlsOptions:{servername:'ldap.example',rejectUnauthorized:true}});
  expect(mocks.bind.mock.calls).toEqual([[ldap.bind_dn,ldap.bind_password],['uid=alice,ou=users,dc=example','ephemeral-password']]);expect(result).toMatchObject({subject:'stable-directory-id',roleIds:[role]});expect(result).not.toHaveProperty('password');expect(mocks.unbind).toHaveBeenCalledOnce();
 });
 it('rejects ambiguous directory identities and never binds the supplied password',async()=>{
  mocks.search.mockResolvedValue({searchEntries:[{dn:'a'},{dn:'b'}]});await expect(providers.ldap('directory','alice','password')).rejects.toMatchObject({status:401});expect(mocks.bind).toHaveBeenCalledTimes(1);
 });
 it('generates PKCE S256 and consumes server-side state once, with fixed callback and bounded relative redirect',async()=>{
  const f=await flow();expect(f.url.searchParams.get('code_challenge_method')).toBe('S256');expect(f.url.searchParams.get('code_challenge')).toBe(createHash('sha256').update(f.stored.verifier).digest('base64url'));
  expect(redis.client.set.mock.calls[0].slice(2)).toEqual(['EX',300,'NX']);expect(f.url.searchParams.get('redirect_uri')).toBe(oidc.callback_uri);
  const result=await providers.callback('corp','authorization-code',f.state,f.begin.correlation);expect(result).toMatchObject({identity:{subject:'verified-subject',roleIds:[role]},redirect:'/profile'});expect(result.identity).not.toHaveProperty('email');
  expect(mocks.json.mock.calls[0][2].get('code_verifier')).toBe(f.stored.verifier);expect(mocks.json.mock.calls[0][3]).toMatch(/^Basic /);
  await expect(providers.callback('corp','authorization-code',f.state,f.begin.correlation)).rejects.toMatchObject({status:401});expect(mocks.json).toHaveBeenCalledTimes(2);
 });
 it.each([{nonce:'wrong-nonce'},{iss:'https://rogue.example'},{aud:'another-client'},{azp:'another-client'}])('rejects signed token binding errors %j',async(overrides)=>{
  const f=await flow(overrides);await expect(providers.callback('corp','code',f.state,f.begin.correlation)).rejects.toMatchObject({status:401});
 });
 it('rejects correlation-cookie mismatch without exchanging a code or minting a session',async()=>{
  const f=await flow();await expect(providers.callback('corp','code',f.state,'A'.repeat(43))).rejects.toMatchObject({status:401});expect(mocks.json).not.toHaveBeenCalled();
 });
 it('rejects expired states, user-controlled redirects and unsigned/non-asymmetric identity tokens',async()=>{
  await expect(providers.start('corp','https://rogue.example')).rejects.toMatchObject({status:400});const f=await flow();
  const [key,value]=[...states.entries()][0];states.set(key,JSON.stringify({...JSON.parse(value),createdAt:Date.now()-301000}));await expect(providers.callback('corp','code',f.state,f.begin.correlation)).rejects.toMatchObject({status:401});expect(mocks.json).not.toHaveBeenCalled();
  const next=await flow();mocks.json.mockResolvedValue({id_token:jwt.sign({nonce:next.stored.nonce},'attacker-secret',{algorithm:'HS256'})});await expect(providers.callback('corp','code',next.state,next.begin.correlation)).rejects.toMatchObject({status:401});
 });
});
