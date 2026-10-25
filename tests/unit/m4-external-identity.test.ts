import 'reflect-metadata';
import { describe,it,expect,beforeEach,afterEach,vi } from 'vitest';
import { AuthService } from '../../apps/console-api/src/modules/auth/auth.service';
import { executionFixture } from './execution-test-fixture';
const adminId='466cf398-ed18-44a9-986d-a67c2d49ed78',externalId='466cf398-ed18-44a9-986d-a67c2d49ed79',identityId='a9285662-956a-488c-8092-dd6b4ca351af';
const roleId='f021291a-c12e-4ce7-99e1-ab1990c8c6b4',bindingId='6ad14ae4-f0bc-477c-bd99-40b97de49e09',manualRole='c04d097a-c2be-4a8e-b82b-ea7e5c0bec1f';
let state:any,db:any,auth:AuthService,audit:any;
const identity:any={provider:{id:'corporate',name:'Company SSO',type:'oidc'},providerKey:'corporate:verified-issuer-hash',subject:'verified-stable-subject',groups:[],roleIds:[]};
function database(read:()=>any){return {
 one:vi.fn(async(sql:string,p:any[]=[])=>{
  const s=read();if(sql.includes('FROM iam_epoch'))return {version:'1'};
  if(sql.includes('FROM auth_identities'))return s.identity;
  if(sql.startsWith('SELECT * FROM users'))return s.users[p[0]]??null;
  if(sql.startsWith('SELECT id FROM users WHERE username='))return Object.values(s.users).find((u:any)=>u.username===p[0])??null;
  if(sql.startsWith('INSERT INTO users')){const row={id:p[0],username:p[1],password_hash:p[2],super_admin:false,status:'active',auth_source:p[3],display_name:p[4],credential_epoch:'1',revision:1};s.users[row.id]=row;return row;}
  if(sql.startsWith('INSERT INTO auth_identities')){s.identity={id:identityId,user_id:p[0],provider_type:p[1],provider_key:p[2],subject:p[3],status:'active'};return s.identity;}
  if(sql.startsWith('INSERT INTO auth_sessions')){s.sessions.push({id:p[0],user_id:p[1],credential_epoch:p[6],revoked:false});return {id:p[0]};}
  if(sql.includes('FROM user_role_bindings'))return s.bindings.find((b:any)=>b.user_id===p[0]&&b.role_id===p[1]&&b.status==='active')??null;
  if(sql.startsWith('INSERT INTO user_role_bindings')){const b={id:bindingId,user_id:p[0],role_id:p[1],cluster_id:p[2],workspace_id:p[3],status:'active'};s.bindings.push(b);return b;}
  return null;
 }),
 query:vi.fn(async(sql:string,p:any[]=[])=>sql.includes('FROM roles')?read().roles.filter((r:any)=>p[0].includes(r.id)):read().bindings.filter((b:any)=>b.providerOwned&&b.status==='active')),
 exec:vi.fn(async(sql:string,p:any[]=[])=>{
  const s=read();if(sql.startsWith('UPDATE user_role_bindings'))s.bindings.find((b:any)=>b.id===p[0]).status='revoked';
  if(sql.startsWith('INSERT INTO auth_identity_bindings'))s.bindings.find((b:any)=>b.id===p[1]).providerOwned=true;
  if(sql.startsWith('UPDATE auth_sessions SET revoked_at=COALESCE'))s.sessions.filter((se:any)=>se.user_id===p[0]).forEach((se:any)=>se.revoked=true);
  return 1;
 })
};}
beforeEach(()=>{
 vi.stubEnv('APP_SECRET','identity-test-private-key-at-least-32-bytes');vi.stubEnv('PASSWORD_BCRYPT_ROUNDS','10');
 state={users:{[adminId]:{id:adminId,username:'admin',email:'admin@example',super_admin:true,status:'active',auth_source:'local',password_hash:'protected-existing-hash',credential_epoch:'1',revision:1}},identity:null,roles:[],bindings:[],sessions:[]};
 db=database(()=>state);db.transaction=vi.fn(async(fn:any)=>{const next=structuredClone(state);const result=await fn(database(()=>next));state=next;return result;});audit={append:vi.fn(async()=>{})};
 const authz:any={snapshot:vi.fn(async(user:any)=>({user:{...user,forcePasswordChange:false},version:'current'})),capabilities:vi.fn(async()=>({modules:{},grants:[],clusters:[],platformAdmin:false}))};
 auth=new AuthService(db,{rateLimit:vi.fn(async()=>({allowed:true})),client:{}} as any,audit,authz,executionFixture(),{} as any);
});
afterEach(()=>vi.unstubAllEnvs());
describe('M4 verified external subject and role ownership',()=>{
 it('creates a separate non-platform account even if an asserted email matches an existing admin',async()=>{
  const original=structuredClone(state.users[adminId]);const result=await (auth as any).externalSession({...identity,email:'admin@example',username:'admin'},'10.0.0.2','Browser');
  expect(result.user.id).not.toBe(adminId);expect(result.user.superAdmin).toBe(false);expect(result.user.username).toMatch(/^ext-[a-f0-9]{48}$/);expect(state.users[adminId]).toEqual(original);expect(state.identity.subject).toBe('verified-stable-subject');
  const calls=JSON.stringify([result,audit.append.mock.calls]);expect(calls).not.toContain('protected-existing-hash');expect(calls).not.toContain('verified-stable-subject');
 });
 it('does not reactivate revoked links or disabled externally managed accounts',async()=>{
  state.identity={id:identityId,user_id:externalId,status:'revoked'};await expect((auth as any).externalSession(identity,'','')).rejects.toMatchObject({status:401});expect(Object.keys(state.users)).toHaveLength(1);
  state.identity.status='active';state.users[externalId]={id:externalId,status:'disabled',auth_source:'oidc'};await expect((auth as any).externalSession(identity,'','')).rejects.toMatchObject({status:401});expect(state.sessions).toEqual([]);
 });
 it('locks the IAM epoch before users/bindings and syncs only provider-owned grants, preserving manual assignments',async()=>{
  state.identity={id:identityId,user_id:externalId,status:'active'};state.users[externalId]={id:externalId,username:'external',status:'active',auth_source:'oidc',credential_epoch:'1'};
  state.bindings=[{id:bindingId,user_id:externalId,role_id:roleId,status:'active',providerOwned:true},{id:'manual',user_id:externalId,role_id:manualRole,status:'active',providerOwned:false}];state.sessions=[{id:'old',user_id:externalId,revoked:false}];
  await (auth as any).externalSession(identity,'','');expect(state.bindings[0].status).toBe('revoked');expect(state.bindings[1].status).toBe('active');expect(state.sessions[0].revoked).toBe(true);expect(state.sessions[1].revoked).toBe(false);
  expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'sessions.revoke_all'}),expect.anything());
 });
 it('assigns mapped roles using their exact configured cluster/workspace and never promotes super-admin',async()=>{
  const cluster='efc85a7f-d60d-45b9-8685-1efc6d4e776c',workspace='12335662-956a-488c-8092-dd6b4ca351af';state.roles=[{id:roleId,builtin_kind:'workspace-read-only',cluster_id:cluster,workspace_id:workspace}];
  await (auth as any).externalSession({...identity,groups:['operators'],roleIds:[roleId]},'','');expect(state.bindings[0]).toMatchObject({cluster_id:cluster,workspace_id:workspace,providerOwned:true});
  const previous=structuredClone(state);state.roles[0].builtin_kind='super-admin';const blocked=structuredClone(state);
  await expect((auth as any).externalSession({...identity,roleIds:[roleId]},'','')).rejects.toMatchObject({status:403});expect(state).toEqual(blocked);expect(previous.users[adminId].super_admin).toBe(true);
 });
 it('rolls back external-account registration and role/session changes if audit persistence fails',async()=>{
  audit.append.mockRejectedValue(new Error('audit unavailable'));const original=structuredClone(state);
  await expect((auth as any).externalSession(identity,'','')).rejects.toThrow('audit unavailable');expect(state).toEqual(original);
 });
});
