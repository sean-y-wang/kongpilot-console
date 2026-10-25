import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync,writeFileSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { AuditService } from '../../apps/console-api/src/modules/audit/audit.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { PortalAuthService } from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';

/** Disposable PostgreSQL only; never uses the application's DATABASE_URL or running Kong. */
async function main():Promise<void>{
 const container=`kongos-m6-auth-${randomUUID().slice(0,8)}`,checks:any[]=[];let db:DbService|undefined;
 const assert=(value:any)=>{if(!value)throw new Error('PortalAuth isolated assertion failed');};
 const rejected=async(fn:()=>Promise<any>,status:number)=>{try{await fn();throw new Error('Expected rejection');}catch(error:any){if(error.getStatus?.()!==status)throw error;}};
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error){process.stderr.write(`Failed safe check: ${name}\n`);throw error;}};
 try{
  execFileSync('docker',['run','-d','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine'],{stdio:'ignore'});
  const port=execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;process.env.CONSOLE_ENCRYPTION_KEY='ba'.repeat(32);
  process.env.BOOTSTRAP_ADMIN_USERNAME='portal-isolated';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!BootstrapPortal2026';
  process.env.APP_SECRET='Console!DifferentSigningKeyIsolated2026';process.env.PORTAL_SECRET='Portal!IndependentSigningKeyIsolated2026';process.env.PORTAL_PUBLIC_ORIGINS='http://localhost:8082';process.env.PASSWORD_BCRYPT_ROUNDS='10';
  db=new DbService();for(let n=0;n<60;n++){try{await db.one('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,100));if(n===59)throw new Error('Isolated PostgreSQL unavailable');}}
  await db.migrateAndSeed();const cid=randomUUID(),otherCid=randomUUID();
  await db.exec("INSERT INTO clusters(id,name,admin_url) VALUES($1,'portal-isolated','http://isolated-kong:8001'),($2,'portal-other','http://other-isolated-kong:8001')",[cid,otherCid]);
  const workspaces=new WorkspaceResolverService(db),w=await workspaces.ensureDefault(cid),otherW=await workspaces.ensureDefault(otherCid),scope={clusterId:cid,workspaceId:w.id},otherScope={clusterId:otherCid,workspaceId:otherW.id};
  await db.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name,published,registration_enabled) VALUES($1,$2,'portal-isolated','Portal',true,true),($3,$4,'portal-other','Other',true,true)",[cid,w.id,otherCid,otherW.id]);
  const secrets=new SecretService(),audit=new AuditService(db,secrets,new AuditOutboxWriter(db,secrets)),redis:any={rateLimit:async()=>({allowed:true}),withLock:async(_key:string,fn:any)=>fn(),assertLeaseOwnership:async()=>undefined};
  const authz:any={assertWholeWorkspace:async()=>undefined},metadata:any={assertStep:async()=>{throw new Error('Approved capability required');}};
  const service=new PortalAuthService(db,redis,secrets,audit,authz,metadata),password='Synthetic!PortalDeveloper2026',nextPassword='Synthetic!RotatedDeveloper2026';service.onModuleInit();
  const registration={username:'developer',email:'developer@example.test',displayName:'开发者',password};let developer:any;
  await check('scoped registration creates pending account and refuses login before review',async()=>{
   assert((await service.register(scope,registration,{requestId:'portal-register-isolated'})).status==='pending');developer=await db!.one<any>('SELECT * FROM portal_developers WHERE cluster_id=$1 AND workspace_id=$2',[cid,w.id]);
   assert(developer.status==='pending');await rejected(()=>service.login(scope,{username:'developer',password},{}),401);assert(!(await db!.one('SELECT id FROM portal_sessions')));
  });
  await check('same identity in another tenant remains an independent pending developer',async()=>{
   await service.register(otherScope,registration,{});const other=await db!.one<any>('SELECT id FROM portal_developers WHERE cluster_id=$1',[otherCid]);assert(other.id!==developer.id);
  });
  const actor=await db.one<any>('SELECT id,username,super_admin FROM users WHERE super_admin');
  await check('current console review advances epoch and applies active CAS under SQL constraints',async()=>{
   developer=await service.reviewDeveloper({user:{id:actor.id,username:actor.username,superAdmin:true}},developer.id,scope,{revision:1,status:'active'},{});
   assert(developer.status==='active');assert(Number((await db!.one<any>('SELECT credential_epoch FROM portal_developers WHERE id=$1',[developer.id])).credential_epoch)===2);
  });
  const login=await service.login(scope,{username:'developer',password},{}),principal=await service.authenticate(login.accessToken);
  await check('login/session and reload CSRF use actual current DB epoch and original token',async()=>{
   const proof=service.verifyOrigin({method:'GET',origin:'http://localhost:8082'}),value=await service.csrf(scope,{accessToken:login.accessToken,csrfCookie:login.csrfToken},proof);
   assert(value.csrfToken===login.csrfToken&&!value.cookieToken);await rejected(()=>service.csrf(otherScope,{accessToken:login.accessToken,csrfCookie:login.csrfToken},proof),403);
  });
  await check('profile SQL ledger persists encrypted result; identical replay does not repeat revision',async()=>{
   const request={revision:developer.revision,displayName:'新资料'},context={idempotencyKey:'portal-isolated-profile-key'};
   const result=await service.updateProfile(principal,request,context),replay=await service.updateProfile(principal,request,context);assert(result.revision===replay.revision);
   const receipt=await service.operation(principal,context.idempotencyKey,true);assert(receipt.state==='succeeded'&&receipt.remoteCompleted);
   assert((await db!.one<any>('SELECT revision FROM portal_developers WHERE id=$1',[developer.id])).revision===result.revision);developer=result;
  });
  await check('unknown refresh cannot revoke family; valid rotation marks exact old hash as used',async()=>{
   await rejected(()=>service.refresh(scope,`${principal.sessionId}.${'x'.repeat(64)}`,login.csrfToken,{}),401);
   assert(!(await db!.one<any>('SELECT revoked_at FROM portal_sessions WHERE id=$1',[principal.sessionId])).revoked_at);
   const refreshed=await service.refresh(scope,login.refreshToken,login.csrfToken,{});assert(refreshed.refreshToken!==login.refreshToken);
   assert((await db!.query('SELECT * FROM portal_refresh_history')).length===1);
   await rejected(()=>service.refresh(scope,login.refreshToken,refreshed.csrfToken,{}),401);await rejected(()=>service.assertCurrent(principal),401);
  });
  const again=await service.login(scope,{username:'developer',password},{}),current=await service.authenticate(again.accessToken);
  await check('password epoch/session/receipt/audit commits atomically with no plaintext retention',async()=>{
   const result=await service.changePassword(current,{revision:developer.revision,currentPassword:password,newPassword:nextPassword,confirmed:true},{idempotencyKey:'portal-isolated-password-key'});assert(result.changed);
   await rejected(()=>service.assertCurrent(current),401);const operation=await db!.one<any>('SELECT * FROM portal_operations WHERE id=$1',[result.operationId]);
   assert(operation.payload_secret===null&&operation.result_secret===null);assert(!JSON.stringify(operation.safe_result).includes(password)&&!JSON.stringify(operation.safe_result).includes(nextPassword));assert(operation.state==='succeeded');
   await rejected(()=>service.login(scope,{username:'developer',password},{}),401);await service.login(scope,{username:'developer',password:nextPassword},{});
   const audits=await db!.query<any>("SELECT actor_id,actor_type,before,after,json_patch FROM audit_events WHERE entity_type LIKE 'portal%' OR entity_type='password'");
   assert(audits.length>0&&audits.every(row=>row.actor_type!=='developer'||row.actor_id===null));assert(!JSON.stringify(audits).includes(password)&&!JSON.stringify(audits).includes(nextPassword));
  });
  await check('five failed attempts lock actual account and valid password remains rejected during lock',async()=>{
   for(let n=0;n<5;n++)await rejected(()=>service.login(scope,{username:'developer',password:'wrong'},{}),401);
   assert(new Date((await db!.one<any>('SELECT locked_until FROM portal_developers WHERE id=$1',[developer.id])).locked_until).getTime()>Date.now());await rejected(()=>service.login(scope,{username:'developer',password:nextPassword},{}),401);
  });
  mkdirSync('artifacts/M6',{recursive:true});writeFileSync('artifacts/M6/portal-auth-storage.json',JSON.stringify({milestone:'M6',scope:'Disposable PostgreSQL; actual PortalAuth service, no application runtime or Kong writes',checks,passed:checks.length,failed:0},null,2));
  process.stdout.write(`M6 isolated PortalAuth: ${checks.length} checks passed\n`);
 }finally{if(db)await db.onModuleDestroy();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}
}
main().catch(error=>{process.stderr.write(`M6 isolated PortalAuth failed: ${error?.code??error?.getResponse?.()?.code??'UNKNOWN'}\n`);process.exitCode=1;});
