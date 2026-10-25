import { Injectable, UnauthorizedException, ForbiddenException, HttpException, BadRequestException, ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { randomBytes, randomUUID, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { AuditService } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import type { AuthUser } from '../../common/auth';
import { hashPolicyPassword,validatePassword } from '../../common/password-policy';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { IdentityProviders,VerifiedExternalIdentity } from './providers/identity-providers';

const hash=(v:string)=>createHash('sha256').update(v).digest('hex');
const equal=(a:unknown,b:unknown)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const denied=()=>new UnauthorizedException({code:'INVALID_CREDENTIALS',message:'账号或密码错误'});
const expired=()=>new UnauthorizedException({code:'SESSION_EXPIRED',message:'会话已失效，请重新登录'});
// This valid constant hash is timing work for unknown users, never a credential.
const DUMMY_HASH='$2b$12$Ts1VlcRpyMlZuRRRo42IAedGCppnCLpFkVIbBpo91SQDsrfbLTtsa';
export interface PasswordChangeReceipt {id:string;revision:number;sessionsRevoked:true;forcePasswordChange:boolean;}

@Injectable()
export class AuthService {
 private readonly providers:IdentityProviders;
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly audit:AuditService,
  private readonly authz:AuthorizationService,private readonly execution:KongExecutionContextService,private readonly secrets:SecretService) {this.providers=new IdentityProviders(redis);}
 onModuleInit(){this.providers.catalog();}
 private metadata(){const frame=this.execution.peek();return {requestId:frame?.requestId,ip:frame?.ip};}
 private signingKey(){const key=process.env.APP_SECRET;if(!key||key.length<32)throw new Error('APP_SECRET must contain at least 32 characters');return key;}
 private actor(row:any):AuthUser{return {id:row.id,username:row.username,superAdmin:row.super_admin===true};}
 async publicUser(row:any):Promise<AuthUser>{
  const snapshot=await this.authz.snapshot(this.actor(row)),current=snapshot.user;
  return {...current,displayName:row.display_name??null,locale:row.locale??'zh-CN',timezone:row.timezone??'UTC',revision:row.revision,
   forcePasswordChange:current.forcePasswordChange===true,permissionsVersion:snapshot.version,capabilities:await this.authz.capabilities(current)};
 }
 async currentUser(user:AuthUser):Promise<AuthUser>{
  const row=await this.db.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL",[user.id]);
  if(!row)throw expired();return this.publicUser(row);
 }
 private access(row:any,sid:string){return jwt.sign({sid},this.signingKey(),{algorithm:'HS256',issuer:'kongos-console',audience:'kongos-api',subject:row.id,expiresIn:'15m'});}
 hashPassword(password:string,options:{username?:string;previousHash?:string}={}):Promise<string>{return hashPolicyPassword(password,options);}
 private exact(value:unknown,keys:string[]):asserts value is Record<string,any>{
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!keys.includes(key)))throw new BadRequestException({code:'INVALID_AUTH_PAYLOAD',message:'请求包含不允许的字段'});
 }
 private revision(value:unknown):asserts value is number {if(!Number.isInteger(value)||Number(value)<1||Number(value)>2147483647)throw new BadRequestException({code:'INVALID_REVISION',message:'必须提供有效的数据修订号'});}
 private async loginLimits(username:string,ip:string){
  for(const [key,limit] of [[`auth:login:ip:${hash(ip)}`,30],[`auth:login:account:${hash(username.toLowerCase())}`,10]] as const){
   if(!(await this.redis.rateLimit(key,limit,60_000)).allowed)throw new HttpException({code:'LOGIN_RATE_LIMIT',message:'登录尝试过多，请稍后重试'},429);
  }
 }
 private async passwordLimit(actor:AuthUser){if(!(await this.redis.rateLimit(`auth:password:${actor.id}`,10,60000)).allowed)throw new HttpException({code:'PASSWORD_RATE_LIMIT',message:'密码变更过于频繁，请稍后重试'},429);}
 private async session(tx:DbService,row:any,ip:string,userAgent:string){
  await tx.exec("UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL AND id NOT IN (SELECT id FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC,id DESC LIMIT 9)",[row.id]);
  const sid=randomUUID(),refresh=randomBytes(48).toString('base64url'),csrf=randomBytes(32).toString('base64url');
  await tx.one<any>("INSERT INTO auth_sessions(id,user_id,refresh_token_hash,csrf_token_hash,expires_at,ip,user_agent,credential_epoch,family_id) VALUES($1,$2,$3,$4,now()+interval '7 days',$5,$6,$7,$1) RETURNING id",
   [sid,row.id,hash(refresh),hash(csrf),ip,userAgent.slice(0,512),row.credential_epoch]);
  return {sid,csrfToken:csrf,accessToken:this.access(row,sid),refreshToken:`${sid}.${refresh}`};
 }
 async login(username:string,password:string,ip:string,userAgent:string){
  if(typeof username!=='string'||typeof password!=='string'||!username.length||username.length>128||/[\x00-\x1f\x7f]/.test(username)||!password.length||Buffer.byteLength(password,'utf8')>72||password.includes('\0'))throw denied();
  await this.loginLimits(username,ip);
  const outcome=await this.db.transaction(async tx=>{
   const row=await tx.one<any>('SELECT * FROM users WHERE username=$1 FOR UPDATE',[username]);
   const ok=await bcrypt.compare(password,row?.password_hash??DUMMY_HASH);
   const locked=row?.locked_until&&new Date(row.locked_until).getTime()>Date.now();
   if(locked){await this.audit.append({actorId:row.id,actorType:'anonymous',entityType:'authentication',action:'login',result:'locked',...this.metadata(),ip},tx);return {locked:true};}
   if(!ok||!row||row.status!=='active'||row.deleted_at||row.auth_source!=='local'){
    if(row?.status==='active'&&!row.deleted_at&&row.auth_source==='local')await tx.exec("UPDATE users SET failed_attempts=CASE WHEN locked_until<=now() THEN 1 ELSE failed_attempts+1 END, locked_until=CASE WHEN (CASE WHEN locked_until<=now() THEN 1 ELSE failed_attempts+1 END)>=5 THEN now()+interval '15 minutes' ELSE NULL END WHERE id=$1",[row.id]);
    await this.audit.append({actorId:row?.id,actorType:'anonymous',entityType:'authentication',action:'login',result:'denied',...this.metadata(),ip},tx);return {denied:true};
   }
   const result=await this.session(tx,row,ip,userAgent);
   await tx.exec('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=$1',[row.id]);
   await this.audit.append({actorId:row.id,entityType:'authentication',action:'login',result:'success',...this.metadata(),ip},tx);
   return {row,result};
  });
  if(outcome.locked)throw new ForbiddenException({code:'ACCOUNT_LOCKED',message:'账号暂时锁定'});
  if(outcome.denied||!outcome.result||!outcome.row)throw denied();
  await this.redis.client.set(`auth:session:${outcome.result.sid}`,outcome.row.id,'EX',604800).catch(()=>undefined);
  return {...outcome.result,user:await this.publicUser(outcome.row)};
 }
 async authenticate(token:string){
  let payload:jwt.JwtPayload;
  try {const verified=jwt.verify(token,this.signingKey(),{algorithms:['HS256'],issuer:'kongos-console',audience:'kongos-api'});
   if(typeof verified==='string'||typeof verified.sub!=='string'||!UUID.test(verified.sub)||typeof verified.sid!=='string'||!UUID.test(verified.sid)||typeof verified.exp!=='number')throw new Error();payload=verified;
  }catch{throw expired();}
  const row=await this.db.one<any>("SELECT u.*,s.id AS session_id,s.csrf_token_hash,s.credential_epoch AS session_credential_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND u.id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' AND u.deleted_at IS NULL AND s.credential_epoch=u.credential_epoch",[payload.sid,payload.sub]);
  if(!row||!Number.isSafeInteger(Number(row.credential_epoch))||Number(row.credential_epoch)<1||row.session_credential_epoch!==row.credential_epoch)throw expired();
  return {user:await this.publicUser(row),sessionId:row.session_id,csrfHash:row.csrf_token_hash};
 }
 checkCsrf(token:string|undefined,expected:string){if(!token||typeof token!=='string'||token.length>128||!equal(hash(token),expected))throw new ForbiddenException({code:'CSRF_INVALID',message:'请求校验失败，请刷新页面'});}
 private refreshHandle(value:unknown):{sid:string;secret:string}{
  if(typeof value!=='string'||value.length>256)throw expired();const parts=value.split('.');
  if(parts.length!==2||!UUID.test(parts[0])||!/^[A-Za-z0-9_-]{8,128}$/.test(parts[1]))throw expired();return {sid:parts[0],secret:parts[1]};
 }
 async csrfForRefresh(value:string,csrf:string|undefined){
  const {sid,secret}=this.refreshHandle(value);
  const row=await this.db.one<any>("SELECT s.csrf_token_hash,s.refresh_token_hash FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' AND u.deleted_at IS NULL AND s.credential_epoch=u.credential_epoch",[sid]);
  if(!row||!equal(hash(secret),row.refresh_token_hash))throw expired();this.checkCsrf(csrf,row.csrf_token_hash);return csrf!;
 }
 async refresh(value:string,csrf:string|undefined){
  const {sid,secret}=this.refreshHandle(value);
  if(!(await this.redis.rateLimit(`auth:refresh:${sid}`,30,60_000)).allowed)throw new HttpException({code:'REFRESH_RATE_LIMIT',message:'会话刷新过于频繁'},429);
  const outcome=await this.db.transaction(async tx=>{
   // Consistent user-before-session lock order matches password reset/revoke transactions.
   await tx.one('SELECT id FROM users WHERE id=(SELECT user_id FROM auth_sessions WHERE id=$1) FOR UPDATE',[sid]);
   const row=await tx.one<any>("SELECT u.*,s.id AS session_id,s.csrf_token_hash,s.refresh_token_hash,s.family_id,s.refresh_generation,s.expires_at AS session_expires_at,s.credential_epoch AS session_credential_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' AND u.deleted_at IS NULL AND s.credential_epoch=u.credential_epoch FOR UPDATE OF s",[sid]);
   if(!row||!Number.isSafeInteger(Number(row.credential_epoch))||Number(row.credential_epoch)<1||row.session_credential_epoch!==row.credential_epoch)throw expired();
   this.checkCsrf(csrf,row.csrf_token_hash);
   if(!equal(hash(secret),row.refresh_token_hash)){
    const used=await tx.one<any>('SELECT token_hash FROM auth_refresh_history WHERE session_id=$1 AND token_hash=$2 AND expires_at>now()',[sid,hash(secret)]);
    if(!used)return {invalid:true};
    await tx.exec('UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1 AND family_id=$2',[row.id,row.family_id]);
    await this.audit.append({actorId:row.id,entityType:'auth_sessions',entityId:sid,action:'refresh.replay_detected',after:{family_revoked:true},result:'denied',...this.metadata()},tx);
    return {replayed:true};
   }
   const next=randomBytes(48).toString('base64url');
   await tx.exec('INSERT INTO auth_refresh_history(session_id,token_hash,generation,expires_at) VALUES($1,$2,$3,$4)',[sid,row.refresh_token_hash,row.refresh_generation,row.session_expires_at]);
   await tx.exec('UPDATE auth_sessions SET refresh_token_hash=$2,refresh_generation=refresh_generation+1 WHERE id=$1',[sid,hash(next)]);
   await this.audit.append({actorId:row.id,entityType:'auth_sessions',entityId:sid,action:'refresh',after:{rotated:true},result:'success',...this.metadata()},tx);
   return {row,refreshToken:`${sid}.${next}`};
  });
  if(outcome.invalid||outcome.replayed||!outcome.row)throw expired();
  return {accessToken:this.access(outcome.row,sid),refreshToken:outcome.refreshToken,user:await this.publicUser(outcome.row)};
 }
 async revokeAllSessions(userId:string,tx:DbService,context:{actorId:string;reason:string;requestId?:string;ip?:string}):Promise<void>{
  if(!UUID.test(userId)||!UUID.test(context.actorId))throw new BadRequestException('账号 ID 无效');
  await tx.exec('UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1',[userId]);
  await this.audit.append({actorId:context.actorId,entityType:'users',entityId:userId,action:'sessions.revoke_all',after:{revoked:true,reason:context.reason},requestId:context.requestId,ip:context.ip,result:'success'},tx);
 }
 async resetPassword(actor:AuthUser,targetId:string,newPassword:string,revision:number,confirmed:boolean):Promise<PasswordChangeReceipt>{
  if(!UUID.test(targetId))throw new BadRequestException('账号 ID 无效');this.revision(revision);
  if(confirmed!==true)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'必须确认重置密码'});
  await this.authz.assertConsole(actor,'users','write',targetId);
  const frame=this.execution.peek(),key=frame?.idempotencyKey;
  if(frame?.actor?.id!==actor.id||typeof key!=='string'||!/^[A-Za-z0-9._:-]{8,128}$/.test(key))
   throw new BadRequestException({code:'RESET_IDEMPOTENCY_REQUIRED',message:'密码重置必须携带有效的原始幂等键'});
  validatePassword(newPassword);
  const payload={operation:'password_reset',revision,confirmed:true};
  // A keyed fingerprint binds the password without retaining it in ledger/audit.
  const requestHash=this.secrets.fingerprint({actor:actor.id,module:'users',action:'write',target:targetId,
   clusterId:null,workspaceId:null,payload:{...payload,new_password:newPassword}});
  let operationId:string|undefined;
  try{return await this.redis.withLock(`iam-operation:${actor.id}:${key}`,async()=>{
   await this.authz.assertConsole(actor,'users','write',targetId);
   const old=await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.id,key]);
   if(old){
    if(old.request_hash!==requestHash||old.module!=='users'||old.action!=='write'||old.target_id!==targetId||old.cluster_id||old.workspace_id)
     throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键已用于不同身份变更'});
    const target=await this.db.one<any>('SELECT * FROM users WHERE id=$1',[targetId]);
    if(!target||target.status!=='active'||target.deleted_at)throw new NotFoundException('账号不存在或已停用');
    if(target.super_admin&&!await this.authz.isPlatformAdmin(actor))throw new ForbiddenException({code:'PROTECTED_ACCOUNT',message:'仅平台管理员可重置平台管理员密码'});
    if(old.state!=='succeeded'||old.remote_completed!==true||!old.result_secret)
     throw new ServiceUnavailableException({code:'IAM_RESULT_UNCERTAIN',message:'原密码重置结果需要核验，请勿重新提交',operationId:old.id,state:old.state});
    const receipt=this.secrets.decrypt<PasswordChangeReceipt>(old.result_secret,`iam:${old.id}:result`);
    if(receipt.id!==targetId||receipt.revision!==revision+1||receipt.sessionsRevoked!==true||receipt.forcePasswordChange!==true)
     throw new ServiceUnavailableException({code:'IAM_RESULT_UNCERTAIN',message:'原密码重置回执无法核验',operationId:old.id,state:old.state});
    return receipt;
   }
   await this.passwordLimit(actor);
   const passwordHash=await this.hashPassword(newPassword);
   operationId=randomUUID();
   return this.db.transaction(async tx=>{
    // Serialize permission changes before user rows, matching the IAM lock order.
    await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR UPDATE NOWAIT');
    await this.authz.assertConsole(actor,'users','write',targetId);await this.redis.assertLeaseOwnership();
    const target=await tx.one<any>('SELECT * FROM users WHERE id=$1 FOR UPDATE',[targetId]);
    if(!target||target.deleted_at||target.status!=='active')throw new NotFoundException('账号不存在或已停用');
    if(target.auth_source!=='local')throw new ConflictException({code:'EXTERNAL_ACCOUNT_PASSWORD',message:'外部认证账号的密码由身份提供方管理'});
    if(target.super_admin&&!await this.authz.isPlatformAdmin(actor))throw new ForbiddenException({code:'PROTECTED_ACCOUNT',message:'仅平台管理员可重置平台管理员密码'});
    if(target.revision!==revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'账号已变化，请刷新后重试'});
    if(await bcrypt.compare(newPassword,target.password_hash))throw new BadRequestException({code:'PASSWORD_UNCHANGED',message:'新密码不能与当前密码相同'});
    await tx.exec(`INSERT INTO iam_operations(id,actor_id,idempotency_key,request_hash,module,action,target_id,cluster_id,workspace_id,payload_secret)
     VALUES($1,$2,$3,$4,'users','write',$5,NULL,NULL,$6)`,[operationId,actor.id,key,requestHash,targetId,this.secrets.encrypt(payload,`iam:${operationId}:payload`)]);
    await this.audit.append({actorId:actor.id,entityType:'users',entityId:targetId,action:'password.reset.requested',after:payload,result:'pending',...this.metadata()},tx);
    const changed=await tx.exec('UPDATE users SET password_hash=$2,credential_epoch=credential_epoch+1,revision=revision+1,force_password_change=true,updated_at=now() WHERE id=$1 AND revision=$3',[targetId,passwordHash,revision]);
    if(changed!==1)throw new ConflictException({code:'REVISION_CONFLICT',message:'账号已变化，请刷新后重试'});
    await this.revokeAllSessions(targetId,tx,{actorId:actor.id,reason:'password_reset',...this.metadata()});
    await this.audit.append({actorId:actor.id,entityType:'users',entityId:targetId,action:'password.reset',before:{revision},after:{revision:revision+1,credential_epoch_changed:true,force_password_change:true},result:'success',...this.metadata()},tx);
    const receipt:PasswordChangeReceipt={id:targetId,revision:revision+1,sessionsRevoked:true,forcePasswordChange:true};
    const recorded=await tx.exec("UPDATE iam_operations SET state='succeeded',remote_completed=true,result_secret=$2,safe_result=$3::jsonb,updated_at=now() WHERE id=$1 AND actor_id=$4 AND state='running'",
     [operationId,this.secrets.encrypt(receipt,`iam:${operationId}:result`),JSON.stringify(receipt),actor.id]);
    if(recorded!==1)throw new ServiceUnavailableException({code:'IAM_LEDGER_UNAVAILABLE',message:'密码重置回执无法持久化'});
    await this.redis.assertLeaseOwnership();return receipt;
   });
  });}catch(error:any){
   if(error?.code==='55P03')throw new ConflictException({code:'IAM_WRITE_BUSY',message:'另一个授权变更正在提交，请刷新后重试'});
   if(error instanceof HttpException&&error.getStatus()<500)throw error;
   // A rejected COMMIT acknowledgment may follow a successful commit. Never
   // overwrite its success or send another password update to resolve it.
   throw new ServiceUnavailableException({code:'IAM_RESULT_UNCERTAIN',message:'密码重置结果需要核验，请使用原幂等键查询回执，不要重新提交',...(operationId?{operationId}:{}),state:'uncertain'});
  }
 }
 async updateProfile(actor:AuthUser,body:unknown):Promise<AuthUser>{
  this.exact(body,['display_name','locale','timezone','revision']);this.revision(body.revision);
  if(body.display_name!==undefined&&(typeof body.display_name!=='string'||body.display_name.trim().length>128||/[\x00-\x1f]/.test(body.display_name)))throw new BadRequestException('显示名称无效');
  if(body.locale!==undefined&&!['zh-CN','en-US'].includes(body.locale))throw new BadRequestException('语言标识无效');
  if(body.timezone!==undefined){try{if(typeof body.timezone!=='string'||body.timezone.length>64)throw new Error();new Intl.DateTimeFormat('en-US',{timeZone:body.timezone});}catch{throw new BadRequestException('时区无效');}}
  const updated=await this.db.transaction(async tx=>{
   if((await this.authz.snapshot(actor)).user.forcePasswordChange)throw new ForbiddenException({code:'PASSWORD_CHANGE_REQUIRED',message:'请先修改初始密码'});
   const row=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE",[actor.id]);
   if(!row)throw expired();if(row.revision!==body.revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'个人资料已变化，请刷新后重试'});
   const next=await tx.one<any>('UPDATE users SET display_name=$2,locale=$3,timezone=$4,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$5 RETURNING *',[actor.id,body.display_name?.trim()??row.display_name,body.locale??row.locale,body.timezone??row.timezone,body.revision]);
   if(!next)throw new ConflictException({code:'REVISION_CONFLICT',message:'个人资料已变化，请刷新后重试'});
   await this.audit.append({actorId:actor.id,entityType:'users',entityId:actor.id,action:'profile.update',before:{display_name:row.display_name,locale:row.locale,timezone:row.timezone,revision:row.revision},after:{display_name:next.display_name,locale:next.locale,timezone:next.timezone,revision:next.revision},result:'success',...this.metadata()},tx);return next;
  });return this.publicUser(updated);
 }
 async changePassword(actor:AuthUser,body:unknown):Promise<PasswordChangeReceipt>{
  this.exact(body,['current_password','new_password','revision','confirmed']);this.revision(body.revision);
  if(body.confirmed!==true)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'必须确认修改密码'});
  if(typeof body.current_password!=='string'||!body.current_password||Buffer.byteLength(body.current_password)>72)throw denied();
  await this.passwordLimit(actor);
  const passwordHash=await this.hashPassword(body.new_password);
  return this.db.transaction(async tx=>{
   await this.authz.snapshot(actor);
   const row=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE",[actor.id]);
   if(!row)throw expired();if(row.auth_source!=='local')throw new ConflictException({code:'EXTERNAL_ACCOUNT_PASSWORD',message:'外部认证账号的密码由身份提供方管理'});
   if(row.revision!==body.revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'账号已变化，请刷新后重试'});
   if(!await bcrypt.compare(body.current_password,row.password_hash))throw denied();
   if(await bcrypt.compare(body.new_password,row.password_hash))throw new BadRequestException({code:'PASSWORD_UNCHANGED',message:'新密码不能与当前密码相同'});
   const count=await tx.exec('UPDATE users SET password_hash=$2,credential_epoch=credential_epoch+1,revision=revision+1,force_password_change=false,updated_at=now() WHERE id=$1 AND revision=$3',[actor.id,passwordHash,body.revision]);
   if(count!==1)throw new ConflictException({code:'REVISION_CONFLICT',message:'账号已变化，请刷新后重试'});
   await this.revokeAllSessions(actor.id,tx,{actorId:actor.id,reason:'password_changed',...this.metadata()});
   await this.audit.append({actorId:actor.id,entityType:'users',entityId:actor.id,action:'password.change',after:{revision:body.revision+1,credential_epoch_changed:true,force_password_change:false},result:'success',...this.metadata()},tx);
   return {id:actor.id,revision:body.revision+1,sessionsRevoked:true,forcePasswordChange:false};
  });
 }
 providerCatalog(){return {items:this.providers.catalog()};}
 async ldapLogin(providerId:string,body:unknown,ip:string,userAgent:string){
  this.exact(body,['username','password']);if(typeof body.username!=='string'||typeof body.password!=='string')throw denied();
  await this.loginLimits(`${providerId}:${body.username}`,ip);
  const identity=await this.providers.ldap(providerId,body.username,body.password);
  return this.externalSession(identity,ip,userAgent);
 }
 async oidcStart(providerId:string,redirect:string,ip:string){
  if(!(await this.redis.rateLimit(`auth:oidc:start:${hash(ip)}`,20,60_000)).allowed)throw new HttpException({code:'LOGIN_RATE_LIMIT',message:'登录尝试过多'},429);
  return this.providers.start(providerId,redirect);
 }
 async oidcCallback(providerId:string,code:string,state:string,correlation:string,ip:string,userAgent:string){
  if(!(await this.redis.rateLimit(`auth:oidc:callback:${hash(ip)}`,30,60_000)).allowed)throw new HttpException({code:'LOGIN_RATE_LIMIT',message:'登录尝试过多'},429);
  const result=await this.providers.callback(providerId,code,state,correlation);
  return {...await this.externalSession(result.identity,ip,userAgent),redirect:result.redirect};
 }
 private async externalSession(identity:VerifiedExternalIdentity,ip:string,userAgent:string){
  const externalHash=await this.hashPassword(`${randomBytes(32).toString('base64url')}-aA1!`);
  const outcome=await this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR UPDATE');
   await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`${identity.provider.type}:${identity.providerKey}:${identity.subject}`]);
   let link=await tx.one<any>('SELECT * FROM auth_identities WHERE provider_type=$1 AND provider_key=$2 AND subject=$3 FOR UPDATE',[identity.provider.type,identity.providerKey,identity.subject]);
   if(link&&link.status!=='active')throw denied();
   let row=link?await tx.one<any>('SELECT * FROM users WHERE id=$1 FOR UPDATE',[link.user_id]):null;
   if(link&&(!row||row.status!=='active'||row.deleted_at||row.auth_source!==identity.provider.type))throw denied();
   if(!link){
    const id=randomUUID(),username=`ext-${hash(`${identity.provider.type}:${identity.providerKey}:${identity.subject}`).slice(0,48)}`;
    if(await tx.one('SELECT id FROM users WHERE username=$1',[username]))throw new ConflictException({code:'EXTERNAL_IDENTITY_CONFLICT',message:'外部身份标识冲突，需管理员处理'});
    row=await tx.one<any>("INSERT INTO users(id,username,password_hash,super_admin,status,auth_source,display_name) VALUES($1,$2,$3,false,'active',$4,$5) RETURNING *",[id,username,externalHash,identity.provider.type,identity.provider.name]);
    link=await tx.one<any>('INSERT INTO auth_identities(user_id,provider_type,provider_key,subject) VALUES($1,$2,$3,$4) RETURNING *',[id,identity.provider.type,identity.providerKey,identity.subject]);
    if(!row||!link)throw new ServiceUnavailableException({code:'EXTERNAL_IDENTITY_FAILED',message:'无法登记外部身份'});
   }
   // Linking by email or supplied username is deliberately absent. Only a verified stable subject identifies this user.
   const roles=identity.roleIds.length?await tx.query<any>("SELECT * FROM roles WHERE id=ANY($1::uuid[]) AND status='active' AND deleted_at IS NULL",[identity.roleIds]):[];
   if(roles.length!==identity.roleIds.length||roles.some(role=>role.builtin_kind==='super-admin'))throw new ForbiddenException({code:'PROVIDER_ROLE_MAPPING_INVALID',message:'认证提供方角色映射失效或包含受保护平台角色'});
   const owned=await tx.query<any>("SELECT b.* FROM auth_identity_bindings p JOIN user_role_bindings b ON b.id=p.binding_id WHERE p.identity_id=$1 AND b.status='active' FOR UPDATE OF b",[link.id]);
   let changed=false;
   for(const binding of owned)if(!identity.roleIds.includes(binding.role_id)){
    await tx.exec("UPDATE user_role_bindings SET status='revoked',revoked_at=now(),retention_until=now()+interval '30 days',revision=revision+1,updated_at=now() WHERE id=$1 AND status='active'",[binding.id]);changed=true;
   }
   for(const role of roles){
    const existing=await tx.one<any>("SELECT id FROM user_role_bindings WHERE user_id=$1 AND role_id=$2 AND cluster_id IS NOT DISTINCT FROM $3::uuid AND workspace_id IS NOT DISTINCT FROM $4::uuid AND status='active'",[row.id,role.id,role.cluster_id,role.workspace_id]);
    if(existing)continue;
    const binding=await tx.one<any>('INSERT INTO user_role_bindings(user_id,role_id,cluster_id,workspace_id) VALUES($1,$2,$3,$4) RETURNING id',[row.id,role.id,role.cluster_id,role.workspace_id]);
    if(!binding)throw new ServiceUnavailableException('无法同步身份角色');
    await tx.exec('INSERT INTO auth_identity_bindings(identity_id,binding_id) VALUES($1,$2)',[link.id,binding.id]);changed=true;
   }
   if(changed){await this.revokeAllSessions(row.id,tx,{actorId:row.id,reason:'provider_groups_changed',...this.metadata(),ip});await tx.exec('UPDATE users SET permissions_epoch=permissions_epoch+1 WHERE id=$1',[row.id]);}
   const result=await this.session(tx,row,ip,userAgent);
   await this.audit.append({actorId:row.id,actorType:'external',entityType:'authentication',action:'external.login',after:{provider:identity.provider.id,type:identity.provider.type,group_count:identity.groups.length,mapped_role_count:identity.roleIds.length},result:'success',...this.metadata(),ip},tx);
   return {row,result};
  });
  return {...outcome.result,user:await this.publicUser(outcome.row)};
 }
 async listSessions(actor:AuthUser,targetId:string=actor.id,options:{size?:number;cursor?:string}={}){
  if(!UUID.test(targetId))throw new BadRequestException('账号 ID 无效');
  if(targetId!==actor.id)await this.authz.assertConsole(actor,'users','read',targetId);else await this.authz.snapshot(actor);
  const size=Number(options.size??20);if(!Number.isInteger(size)||size<1||size>100)throw new BadRequestException('分页大小须在 1–100 之间');
  const binding={actorId:actor.id,targetId,size,version:await this.authz.permissionVersion(actor)};let position:any=null;
  const sign=(value:string)=>createHmac('sha256',this.signingKey()).update(`auth:sessions:${value}`).digest('base64url');
  if(options.cursor){try{
   const [value,signature,...extra]=options.cursor.split('.');if(extra.length||!equal(signature,sign(value)))throw new Error();const parsed=JSON.parse(Buffer.from(value,'base64url').toString('utf8'));
   if(JSON.stringify(parsed.binding)!==JSON.stringify(binding)||parsed.expiresAt<Date.now()||!UUID.test(parsed.position?.id)||!Number.isFinite(Date.parse(parsed.position?.createdAt)))throw new Error();position=parsed.position;
  }catch{throw new BadRequestException({code:'INVALID_CURSOR',message:'会话分页游标无效或已过期'});}}
  const rows=await this.db.query<any>(`SELECT id,ip,user_agent,created_at,expires_at FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()
   AND ($2::timestamptz IS NULL OR (created_at,id)<($2::timestamptz,$3::uuid)) ORDER BY created_at DESC,id DESC LIMIT $4`,[targetId,position?.createdAt??null,position?.id??null,size+1]);
  const page=rows.slice(0,size),sessionId=this.execution.peek()?.sessionId;let nextCursor:string|null=null;
  if(rows.length>size){const last=page[page.length-1],value=Buffer.from(JSON.stringify({binding,position:{id:last.id,createdAt:new Date(last.created_at).toISOString()},expiresAt:Date.now()+3600000})).toString('base64url');nextCursor=`${value}.${sign(value)}`;}
  return {items:page.map(row=>({...row,current:row.id===sessionId})),nextCursor,size,total:null};
 }
 async revokeSessions(actor:AuthUser,targetId:string,body:unknown,sessionId?:string){
  this.exact(body,['confirmed','confirm_name']);if(!UUID.test(targetId)||sessionId!==undefined&&!UUID.test(sessionId))throw new BadRequestException('账号或会话 ID 无效');
  if(body.confirmed!==true||body.confirm_name!==actor.username)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'请确认并输入当前账号名称'});
  if(targetId!==actor.id)await this.authz.assertConsole(actor,'users','write',targetId);
  else await this.authz.snapshot(actor);
  return this.db.transaction(async tx=>{
   if(targetId!==actor.id)await this.authz.assertConsole(actor,'users','write',targetId);else await this.authz.snapshot(actor);
   const row=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE",[targetId]);if(!row)throw new NotFoundException('账号不存在');
   if(targetId!==actor.id&&row.super_admin&&!await this.authz.isPlatformAdmin(actor))throw new ForbiddenException({code:'PROTECTED_ACCOUNT',message:'仅平台管理员可撤销平台管理员会话'});
   if(sessionId){
    const session=await tx.one<any>('SELECT id FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL FOR UPDATE',[sessionId,targetId]);if(!session)throw new NotFoundException('会话不存在或已撤销');
    await tx.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2',[sessionId,targetId]);
    await this.audit.append({actorId:actor.id,entityType:'auth_sessions',entityId:sessionId,action:'session.revoke',after:{revoked:true},result:'success',...this.metadata()},tx);
   }else await this.revokeAllSessions(targetId,tx,{actorId:actor.id,reason:'explicit_revoke',...this.metadata()});
   return {id:targetId,sessionId:sessionId??null,revoked:true,loggedOut:targetId===actor.id&&(!sessionId||sessionId===this.execution.peek()?.sessionId)};
  });
 }
 async revoke(sid:string,userId:string){await this.db.transaction(async tx=>{await tx.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2',[sid,userId]);await this.audit.append({actorId:userId,entityType:'auth_sessions',entityId:sid,action:'logout',after:{revoked:true},result:'success',...this.metadata()},tx);});await this.redis.client.del(`auth:session:${sid}`).catch(()=>undefined);}
}
