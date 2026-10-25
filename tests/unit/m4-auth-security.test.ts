import 'reflect-metadata';
import { executionFixture } from './execution-test-fixture';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { ForbiddenException } from '@nestjs/common';
import { AuthService } from '../../apps/console-api/src/modules/auth/auth.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { validatePassword } from '../../apps/console-api/src/common/password-policy';

const uid='466cf398-ed18-44a9-986d-a67c2d49ed78',other='466cf398-ed18-44a9-986d-a67c2d49ed79',sid='a9285662-956a-488c-8092-dd6b4ca351af';
const secret='M4-test-only-signing-key-with-at-least-32-bytes';
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const password='Existing-Password-123!',nextPassword='Different-Password-456!';
let state:any,db:any,audit:any,authz:any,auth:AuthService,redis:any;
let permitted:boolean,failAudit:boolean,dropCommitAck:boolean,resetKey:string|undefined,context:any;
function database(read:()=>any){
 return {
  one:vi.fn(async(sql:string,p:any[]=[])=>{
   const s=read();
   if(sql.includes('FROM iam_operations'))return s.operations.find((o:any)=>o.actor_id===p[0]&&o.idempotency_key===p[1])??null;
   if(sql.includes('auth_refresh_history'))return s.history.find((r:any)=>r.session_id===p[0]&&r.token_hash===p[1])??null;
   if(sql.includes('FROM auth_sessions')){
    const se=s.sessions.find((r:any)=>r.id===p[0]);const u=se&&s.users[se.user_id];
    if(!u||se.revoked_at||u.status!=='active'||u.deleted_at||se.credential_epoch!==u.credential_epoch)return null;
    return {...u,session_id:se.id,session_credential_epoch:se.credential_epoch,csrf_token_hash:se.csrf_token_hash,refresh_token_hash:se.refresh_token_hash,family_id:se.family_id,refresh_generation:se.refresh_generation,session_expires_at:se.expires_at};
   }
   if(sql.startsWith('SELECT * FROM users'))return s.users[p[0]]??Object.values(s.users).find((u:any)=>u.username===p[0])??null;
   if(sql.startsWith('UPDATE users SET display_name')){const u=s.users[p[0]];if(u.revision!==p[4])return null;Object.assign(u,{display_name:p[1],locale:p[2],timezone:p[3],revision:u.revision+1});return {...u};}
   return null;
  }),
  exec:vi.fn(async(sql:string,p:any[]=[])=>{
   const s=read();
   if(sql.startsWith('INSERT INTO iam_operations')){s.operations.push({id:p[0],actor_id:p[1],idempotency_key:p[2],request_hash:p[3],module:'users',action:'write',target_id:p[4],payload_secret:p[5],state:'running',remote_completed:false});return 1;}
   if(sql.startsWith('UPDATE iam_operations')){const op=s.operations.find((o:any)=>o.id===p[0]);Object.assign(op,{state:'succeeded',remote_completed:true,result_secret:p[1],safe_result:JSON.parse(p[2])});return 1;}
   if(sql.startsWith('UPDATE users SET password_hash')){const u=s.users[p[0]];if(u.revision!==p[2])return 0;u.password_hash=p[1];u.credential_epoch=String(Number(u.credential_epoch)+1);u.revision++;u.force_password_change=sql.includes('force_password_change=true');return 1;}
   if(sql.startsWith('UPDATE auth_sessions SET revoked_at')){for(const se of s.sessions)if(se.user_id===p[0]&&(!sql.includes('family_id=$2')||se.family_id===p[1]))se.revoked_at='now';return 1;}
   if(sql.startsWith('INSERT INTO auth_refresh_history')){s.history.push({session_id:p[0],token_hash:p[1],generation:p[2],expires_at:p[3]});return 1;}
   if(sql.startsWith('UPDATE auth_sessions SET refresh_token_hash')){const se=s.sessions.find((r:any)=>r.id===p[0]);se.refresh_token_hash=p[1];se.refresh_generation++;return 1;}
   return 1;
  }),
 };
}
beforeEach(async()=>{
 vi.stubEnv('APP_SECRET',secret);vi.stubEnv('CONSOLE_ENCRYPTION_KEY','bc'.repeat(32));vi.stubEnv('PASSWORD_BCRYPT_ROUNDS','10');
 permitted=true;failAudit=false;dropCommitAck=false;resetKey='reset-test-key-1';
 const user={id:uid,username:'regular',password_hash:await bcrypt.hash(password,4),super_admin:false,status:'active',auth_source:'local',credential_epoch:'1',revision:1,display_name:'Regular',locale:'zh-CN',timezone:'UTC',force_password_change:false,deleted_at:null};
 state={users:{[uid]:user,[other]:{...user,id:other,username:'other'}},sessions:[{id:sid,user_id:uid,credential_epoch:'1',family_id:sid,refresh_generation:0,refresh_token_hash:hash('old-secret'),csrf_token_hash:hash('csrf'),expires_at:new Date(Date.now()+86400000),revoked_at:null}],history:[],operations:[]};
 db=database(()=>state);
 db.transaction=vi.fn(async(fn:any)=>{const working=structuredClone(state),tx=database(()=>working);const result=await fn(tx);state=working;if(dropCommitAck){dropCommitAck=false;throw new Error('COMMIT acknowledgment lost');}return result;});
 audit={append:vi.fn(async()=>{if(failAudit)throw new Error('audit storage unavailable');})};
 redis={withLock:vi.fn(async(_key:any,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>{}),rateLimit:vi.fn(async()=>({allowed:true})),client:{set:vi.fn(async()=> 'OK'),del:vi.fn(async()=>1)}};
 db.query=vi.fn(async()=>[]);authz={permissionVersion:vi.fn(async()=> 'epoch-current'),snapshot:vi.fn(async(user:any)=>({user:{id:user.id,username:state.users[user.id].username,superAdmin:state.users[user.id].super_admin,forcePasswordChange:state.users[user.id].force_password_change},version:'epoch-current'})),capabilities:vi.fn(async()=>({modules:{},grants:[],clusters:[],platformAdmin:false})),assertConsole:vi.fn(async()=>{if(!permitted)throw new ForbiddenException({code:'PERMISSION_DENIED'});}),isPlatformAdmin:vi.fn(async()=>false)};
 context={...executionFixture(),peek:()=>({actor:actor(),idempotencyKey:resetKey,requestId:'trusted-request-id',ip:'10.1.2.3'})};
 auth=new AuthService(db,redis,audit,authz,context,new SecretService());
});
afterEach(()=>vi.unstubAllEnvs());
const actor=()=>({id:uid,username:'regular',superAdmin:false});
function access(extra:any={}){return jwt.sign({sid,...extra},secret,{algorithm:'HS256',issuer:'kongos-console',audience:'kongos-api',subject:uid,expiresIn:900});}

describe('M4 password and session authority',()=>{
 it.each(['lowercase-only-password123!','UPPERCASE-ONLY-PASSWORD123!','No-Digits-Password!','NoSymbolsPassword123','Short-1!','Aa1!'+ '中'.repeat(23)])('rejects a policy violation before bcrypt (%s)',value=>{expect(()=>validatePassword(value)).toThrow();});
 it('rejects stale credential epochs even with an otherwise valid signed JWT',async()=>{
  state.users[uid].credential_epoch='2';await expect(auth.authenticate(access({superAdmin:true}))).rejects.toMatchObject({status:401});expect(authz.snapshot).not.toHaveBeenCalled();
 });
 it.each([{sid:'not-uuid'},{sid},{sid,sub:'not-uuid'}])('requires valid session/subject and expiration claims',async(payload)=>{
  const token=jwt.sign(payload,secret,{algorithm:'HS256',issuer:'kongos-console',audience:'kongos-api',...(payload.sub?{}:{subject:uid})});
  await expect(auth.authenticate(token)).rejects.toMatchObject({status:401});expect(db.one).not.toHaveBeenCalled();
 });
 it('ignores forged privilege claims and publishes only current authorization capabilities',async()=>{
  const result=await auth.authenticate(access({superAdmin:true,roles:['super-admin'],capabilities:{platformAdmin:true}}));
  expect(result.user.superAdmin).toBe(false);expect(result.user.capabilities?.platformAdmin).toBe(false);expect(result.user.permissionsVersion).toBe('epoch-current');
 });
 it.each(['admin','super_admin','superAdmin','roles','permissions','password_hash','id','status','auth_source','credential_epoch','constructor','__proto__'])('rejects profile mass assignment of %s without touching account',async(field)=>{
  const body=JSON.parse(JSON.stringify({revision:1}) .replace('}',`,"${field}":true}`));
  await expect(auth.updateProfile(actor(),body)).rejects.toMatchObject({status:400});expect(db.transaction).not.toHaveBeenCalled();expect(state.users[uid].super_admin).toBe(false);
 });
 it('updates only the authenticated profile and records a safe atomic diff',async()=>{
  const result=await auth.updateProfile(actor(),{revision:1,display_name:'New Name',locale:'en-US',timezone:'Asia/Shanghai'});
  expect(state.users[uid]).toMatchObject({display_name:'New Name',revision:2,super_admin:false});expect(state.users[other].revision).toBe(1);expect(result).not.toHaveProperty('password_hash');
  expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'profile.update',entityId:uid}),expect.anything());
 });
 it('denies cross-user reset before hashing or database writes despite a forged superAdmin flag',async()=>{
  permitted=false;await expect(auth.resetPassword({...actor(),superAdmin:true},other,nextPassword,1,true)).rejects.toMatchObject({status:403});expect(db.transaction).not.toHaveBeenCalled();expect(state.users[other].password_hash).toBe(state.users[uid].password_hash);
 });
 it('protects platform accounts from ordinary IAM user-write grants',async()=>{
  state.users[other].super_admin=true;await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:403});expect(state.users[other].revision).toBe(1);
 });
 it('revision conflicts have no password, epoch, session or success-audit side effects',async()=>{
  const original=structuredClone(state);await expect(auth.resetPassword(actor(),uid,nextPassword,9,true)).rejects.toMatchObject({status:409});expect(state).toEqual(original);expect(audit.append).not.toHaveBeenCalled();
 });
 it('rolls back password and session revocation if the append-only audit fails',async()=>{
  const original=structuredClone(state);failAudit=true;await expect(auth.resetPassword(actor(),uid,nextPassword,1,true)).rejects.toMatchObject({status:503,response:{code:'IAM_RESULT_UNCERTAIN'}});expect(state).toEqual(original);
 });
 it('resets password and revokes both access and refresh atomically, without plaintext in receipts or audits',async()=>{
  const token=access();const result=await auth.resetPassword(actor(),uid,nextPassword,1,true);
  expect(result).toEqual({id:uid,revision:2,sessionsRevoked:true,forcePasswordChange:true});expect(await bcrypt.compare(nextPassword,state.users[uid].password_hash)).toBe(true);expect(state.sessions[0].revoked_at).toBe('now');expect(state.users[uid].credential_epoch).toBe('2');
  await expect(auth.authenticate(token)).rejects.toMatchObject({status:401});await expect(auth.refresh(`${sid}.old-secret`,'csrf')).rejects.toMatchObject({status:401});
  const publicEvidence=JSON.stringify([result,audit.append.mock.calls]);expect(publicEvidence).not.toContain(nextPassword);expect(publicEvidence).not.toContain(state.users[uid].password_hash);
 });
 it('self password changes require the current password and cannot target another account',async()=>{
  await expect(auth.changePassword(actor(),{revision:1,current_password:password,new_password:nextPassword,confirmed:true,id:other})).rejects.toMatchObject({status:400});
  await expect(auth.changePassword(actor(),{revision:1,current_password:'wrong-password',new_password:nextPassword,confirmed:true})).rejects.toMatchObject({status:401});expect(state.users[uid].revision).toBe(1);
  const result=await auth.changePassword(actor(),{revision:1,current_password:password,new_password:nextPassword,confirmed:true});expect(result.forcePasswordChange).toBe(false);expect(state.users[other].revision).toBe(1);
 });
 it('commits recognized refresh replay revocation before returning rejection',async()=>{
  const first=await auth.refresh(`${sid}.old-secret`,'csrf');expect(first.refreshToken).not.toBe(`${sid}.old-secret`);
  await expect(auth.refresh(`${sid}.old-secret`,'csrf')).rejects.toMatchObject({status:401});expect(state.sessions[0].revoked_at).toBe('now');
  await expect(auth.refresh(first.refreshToken!,'csrf')).rejects.toMatchObject({status:401});expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'refresh.replay_detected'}),expect.anything());
 });
 it('arbitrary incorrect refresh material cannot revoke a victim session by guessing its UUID',async()=>{
  await expect(auth.refresh(`${sid}.random-incorrect-secret`,'csrf')).rejects.toMatchObject({status:401});expect(state.sessions[0].revoked_at).toBeNull();expect(state.history).toEqual([]);expect(audit.append).not.toHaveBeenCalled();
 });
 it('does not expose session token hashes, binds cursors to actor/target, and marks only the trusted current session',async()=>{
  db.query.mockResolvedValue([{id:sid,ip:'10.1.2.3',user_agent:'Browser',created_at:new Date(),expires_at:new Date(Date.now()+100000)},{id:'a9285662-956a-488c-8092-dd6b4ca351ae',ip:'10.1.2.4',created_at:new Date(Date.now()-1000),expires_at:new Date(Date.now()+100000)}]);
  const result=await auth.listSessions(actor(),uid,{size:1});expect(result.nextCursor).toBeTypeOf('string');expect(result.items).toHaveLength(1);
  expect(db.query.mock.calls[0][0]).not.toContain('refresh_token_hash');expect(db.query.mock.calls[0][0]).not.toContain('csrf_token_hash');
  await expect(auth.listSessions(actor(),other,{size:1,cursor:result.nextCursor!})).rejects.toMatchObject({status:400});
  await expect(auth.listSessions(actor(),uid,{size:2,cursor:result.nextCursor!})).rejects.toMatchObject({status:400});
 });
 it('blocks ordinary cross-user session revocation and protects the target session',async()=>{
  permitted=false;const original=structuredClone(state);
  await expect(auth.revokeSessions(actor(),other,{confirmed:true,confirm_name:'regular'})).rejects.toMatchObject({status:403});expect(state).toEqual(original);
 });
 it('requires exact confirmation for session revoke-all and invalidates all old access tokens',async()=>{
  await expect(auth.revokeSessions(actor(),uid,{confirmed:true,confirm_name:'wrong'})).rejects.toMatchObject({status:400});
  await expect(auth.revokeSessions(actor(),uid,{confirmed:true,confirm_name:'regular',admin:true})).rejects.toMatchObject({status:400});
  const token=access();await auth.revokeSessions(actor(),uid,{confirmed:true,confirm_name:'regular'});expect(state.sessions[0].revoked_at).toBe('now');await expect(auth.authenticate(token)).rejects.toMatchObject({status:401});
 });

 it('requires a trusted original request key and actor for administrative resets',async()=>{
  resetKey=undefined;await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:400,response:{code:'RESET_IDEMPOTENCY_REQUIRED'}});
  resetKey='valid-original-key';context.peek=()=>({actor:{...actor(),id:other},idempotencyKey:resetKey});
  await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:400});expect(db.transaction).not.toHaveBeenCalled();
 });
 it('replays a terminal reset key without hashing, updating the password epoch or revoking another session',async()=>{
  const first=await auth.resetPassword(actor(),other,nextPassword,1,true),transactions=db.transaction.mock.calls.length;
  const next=await auth.resetPassword(actor(),other,nextPassword,1,true);
  expect(next).toEqual(first);expect(state.users[other].revision).toBe(2);expect(state.users[other].credential_epoch).toBe('2');expect(db.transaction).toHaveBeenCalledTimes(transactions);
  expect(state.operations).toHaveLength(1);expect(state.operations[0]).toMatchObject({state:'succeeded',remote_completed:true,target_id:other});
  const evidence=JSON.stringify([state.operations,audit.append.mock.calls]);expect(evidence).not.toContain(nextPassword);expect(evidence).not.toContain(state.users[other].password_hash);
  expect(state.operations[0].request_hash).toMatch(/^[a-f0-9]{64}$/);
 });
 it('binds reset replay to the exact actor, target, revision and password fingerprint',async()=>{
  await auth.resetPassword(actor(),other,nextPassword,1,true);
  for(const [target,pwd,rev]of [[uid,nextPassword,1],[other,'Different-Third-Password-789!',1],[other,nextPassword,2]] as const){
   await expect(auth.resetPassword(actor(),target,pwd,rev,true)).rejects.toMatchObject({status:409,response:{code:'IDEMPOTENCY_CONFLICT'}});
  }
  expect(state.users[other].credential_epoch).toBe('2');expect(state.operations).toHaveLength(1);
 });
 it('preserves a successful ledger when COMMIT applied but its acknowledgment was lost, then proves the original key',async()=>{
  dropCommitAck=true;await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:503,response:{code:'IAM_RESULT_UNCERTAIN',state:'uncertain'}});
  expect(state.users[other].revision).toBe(2);expect(state.operations[0]).toMatchObject({state:'succeeded',remote_completed:true});
  await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).resolves.toMatchObject({id:other,revision:2});
  expect(state.users[other].credential_epoch).toBe('2');expect(state.operations).toHaveLength(1);
  resetKey='new-key-after-response-loss';await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:409,response:{code:'REVISION_CONFLICT'}});
 });
 it('cannot replay a reset after the submitting actor loses its current user-write grant',async()=>{
  await auth.resetPassword(actor(),other,nextPassword,1,true);permitted=false;
  await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:403});expect(state.users[other].revision).toBe(2);
 });
 it('keeps password, epoch, sessions and the result ledger atomic when audit persistence fails',async()=>{
  const original=structuredClone(state);failAudit=true;await expect(auth.resetPassword(actor(),other,nextPassword,1,true)).rejects.toMatchObject({status:503});
  expect(state).toEqual(original);expect(state.operations).toEqual([]);
 });
 it('links refresh and logout audits to trusted request metadata without recording refresh material',async()=>{
  await auth.refresh(`${sid}.old-secret`,'csrf');await auth.revoke(sid,uid);
  expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'refresh',requestId:'trusted-request-id',ip:'10.1.2.3'}),expect.anything());
  expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'logout',requestId:'trusted-request-id',ip:'10.1.2.3'}),expect.anything());
  expect(JSON.stringify(audit.append.mock.calls)).not.toContain('old-secret');
 });

});
