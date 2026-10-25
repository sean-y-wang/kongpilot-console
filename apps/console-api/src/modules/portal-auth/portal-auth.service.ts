import { BadRequestException, ConflictException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService } from '../audit/audit.service';
import { metadataAuditScope } from '../event-producers/native-audit-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { hashPolicyPassword } from '../../common/password-policy';
import type { EntityActor } from '../entities/entities.types';
import { APPROVED_WORKFLOW_METADATA_POLICY, type ApprovedMetadataStepPolicy } from '../workflows/approved-execution.types';
import { releaseUnusedPortalReservations } from '../portal/portal-grant-lifecycle';
import { PORTAL_UUID, portalExact, portalRevision, portalScope, type PortalAuthResult, type PortalDeveloperView, type PortalMetadataMutation, type PortalOperationView, type PortalOriginProof, type PortalPrincipal, type PortalRequestContext, type PortalScope } from './portal-auth.types';

const hash=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
const equal=(a:unknown,b:unknown)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const expired=()=>new UnauthorizedException({code:'PORTAL_SESSION_EXPIRED',message:'门户会话已失效，请重新登录'});
const denied=()=>new UnauthorizedException({code:'PORTAL_INVALID_CREDENTIALS',message:'门户账号或密码错误'});
const csrfInvalid=()=>new ForbiddenException({code:'PORTAL_CSRF_INVALID',message:'门户请求校验失败，请重新登录'});
const DUMMY_HASH='$2b$12$Ts1VlcRpyMlZuRRRo42IAedGCppnCLpFkVIbBpo91SQDsrfbLTtsa';
const safeDate=(value:any)=>new Date(value).toISOString();

@Injectable()
export class PortalAuthService implements OnModuleInit {
  private readonly principals=new WeakSet<object>();
  private readonly origins=new WeakSet<object>();
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly audit:AuditService,private readonly authz:AuthorizationService,
    @Inject(APPROVED_WORKFLOW_METADATA_POLICY) private readonly metadataPolicy:ApprovedMetadataStepPolicy){}
  onModuleInit():void {this.signingKey();this.allowedOrigins();}
  private signingKey():string {
    const key=process.env.PORTAL_SECRET;
    if(!key||Buffer.byteLength(key)<32||key.length>1024||key===process.env.APP_SECRET||/^(change[-_ ]?me|test|development|default)/i.test(key))throw new Error('PORTAL_SECRET must be an independent high entropy signing key');
    return key;
  }
  private allowedOrigins():string[] {
    const origins=(process.env.PORTAL_PUBLIC_ORIGINS??'').split(',').map(value=>value.trim()).filter(Boolean);
    if(!origins.length||origins.length>8)throw new Error('PORTAL_PUBLIC_ORIGINS is required');
    for(const origin of origins){let url:URL;try{url=new URL(origin);}catch{throw new Error('PORTAL_PUBLIC_ORIGINS contains an invalid origin');}
      if(url.origin!==origin||!['http:','https:'].includes(url.protocol)||url.username||url.password||(process.env.NODE_ENV==='production'&&url.protocol!=='https:'&&!['127.0.0.1','localhost','[::1]'].includes(url.hostname)))throw new Error('PORTAL_PUBLIC_ORIGINS must contain explicit portal origins');}
    return origins;
  }
  /** Only configured portal origins, never forwarded headers, can mint a CSRF origin proof. */
  verifyOrigin(input:{origin?:string;secFetchSite?:string;host?:string;method:string}):PortalOriginProof {
    const allowed=this.allowedOrigins();let origin=input.origin;
    if(input.secFetchSite&&input.secFetchSite!=='same-origin')throw new ForbiddenException({code:'PORTAL_ORIGIN_DENIED',message:'不允许的门户来源'});
    if(!origin){
      if(input.method!=='GET'||input.secFetchSite!=='same-origin'||!input.host)throw new ForbiddenException({code:'PORTAL_ORIGIN_DENIED',message:'门户请求必须来自已登记来源'});
      origin=allowed.find(value=>new URL(value).host===input.host);
    }
    if(!origin||!allowed.includes(origin))throw new ForbiddenException({code:'PORTAL_ORIGIN_DENIED',message:'不允许的门户来源'});
    const proof=Object.freeze({origin});this.origins.add(proof);return proof;
  }
  private assertOrigin(proof:PortalOriginProof):void {if(!proof||!this.origins.has(proof))throw new ForbiddenException({code:'PORTAL_ORIGIN_DENIED',message:'门户来源尚未验证'});}
  private view(row:any):PortalDeveloperView {return {id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,username:row.username,email:row.email,
    displayName:row.display_name,status:row.status,revision:Number(row.revision),mustChangePassword:row.must_change_password===true,createdAt:safeDate(row.created_at)};}
  private event(scope:PortalScope,developerId:string|null,context:PortalRequestContext){return {actorType:developerId?'developer':'anonymous',actorId:null,
    clusterId:scope.clusterId,workspaceId:scope.workspaceId,entityType:'portal_developers',entityId:developerId,requestId:context.requestId,ip:context.ip};}
  private async tenant(scope:PortalScope,tx=this.db,write=false):Promise<any> {
    portalScope(scope);
    const row=await tx.one<any>(`SELECT p.id,p.revision,w.status AS workspace_status,c.execution_mode,c.revision AS cluster_revision
      FROM portal_settings p JOIN workspaces w ON w.cluster_id=p.cluster_id AND w.id=p.workspace_id JOIN clusters c ON c.id=p.cluster_id
      WHERE p.cluster_id=$1 AND p.workspace_id=$2 AND p.status='active' AND p.published=true
        AND p.deleted_at IS NULL AND w.deleted_at IS NULL AND c.deleted_at IS NULL AND c.status<>'disabled' FOR SHARE OF p,w,c`,[scope.clusterId,scope.workspaceId]);
    if(!row)throw new ForbiddenException({code:'PORTAL_NOT_AVAILABLE',message:'此门户租户当前不可用'});
    if(write&&row.workspace_status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED',message:'此工作区当前仅可读取'});
    return row;
  }
  private principal(row:any):PortalPrincipal {
    const value=Object.freeze({kind:'portal_developer' as const,developerId:row.id,sessionId:row.session_id,
      clusterId:row.cluster_id,workspaceId:row.workspace_id,credentialEpoch:Number(row.credential_epoch)});
    this.principals.add(value);return value;
  }
  private async sessionRow(sid:string,developerId?:string,tx=this.db,lock=false):Promise<any> {
    const row=await tx.one<any>(`SELECT d.*,s.id AS session_id,s.csrf_token_hash,s.refresh_token_hash,s.family_id,s.refresh_generation,s.expires_at,
      s.credential_epoch AS session_epoch FROM portal_sessions s JOIN portal_developers d ON d.cluster_id=s.cluster_id AND d.workspace_id=s.workspace_id AND d.id=s.developer_id
      WHERE s.id=$1 AND ($2::uuid IS NULL OR d.id=$2) AND s.revoked_at IS NULL AND s.expires_at>now()
        AND d.status='active' AND d.deleted_at IS NULL AND d.credential_epoch=s.credential_epoch${lock?' FOR UPDATE OF s,d':''}`,[sid,developerId??null]);
    if(!row||!Number.isSafeInteger(Number(row.credential_epoch))||Number(row.credential_epoch)<1)throw expired();
    await this.tenant({clusterId:row.cluster_id,workspaceId:row.workspace_id},tx);return row;
  }
  private access(row:any,sid:string):string {return jwt.sign({kind:'portal_developer',sid,cid:row.cluster_id,wid:row.workspace_id,credential_epoch:Number(row.credential_epoch)},
    this.signingKey(),{algorithm:'HS256',issuer:'kongos-portal',audience:'kongos-portal',subject:row.id,expiresIn:'15m'});}
  async authenticate(token:string):Promise<PortalPrincipal> {
    let payload:jwt.JwtPayload;
    try {const value=jwt.verify(token,this.signingKey(),{algorithms:['HS256'],issuer:'kongos-portal',audience:'kongos-portal'});
      if(typeof value==='string'||value.kind!=='portal_developer'||!PORTAL_UUID.test(value.sub??'')||!PORTAL_UUID.test(value.sid??'')||!PORTAL_UUID.test(value.cid??'')||!PORTAL_UUID.test(value.wid??'')||!Number.isSafeInteger(value.credential_epoch))throw new Error();payload=value;
    }catch{throw expired();}
    const row=await this.sessionRow(payload.sid,payload.sub);
    if(row.cluster_id!==payload.cid||row.workspace_id!==payload.wid||Number(row.credential_epoch)!==payload.credential_epoch)throw expired();
    return this.principal(row);
  }
  async assertCurrent(principal:PortalPrincipal,tx=this.db,write=false):Promise<PortalDeveloperView> {
    if(!principal||!this.principals.has(principal))throw expired();
    const row=await this.sessionRow(principal.sessionId,principal.developerId,tx);
    if(row.cluster_id!==principal.clusterId||row.workspace_id!==principal.workspaceId||Number(row.credential_epoch)!==principal.credentialEpoch)throw expired();
    if(write)await this.tenant(principal,tx,true);return this.view(row);
  }
  assertScope(principal:PortalPrincipal,scope:PortalScope):void {
    portalScope(scope);if(principal.clusterId!==scope.clusterId||principal.workspaceId!==scope.workspaceId)throw new ForbiddenException({code:'PORTAL_SCOPE_DENIED',message:'门户会话不属于所选租户'});
  }
  async checkCsrf(principal:PortalPrincipal,token:unknown):Promise<void> {
    await this.assertCurrent(principal);const row=await this.sessionRow(principal.sessionId,principal.developerId);
    if(typeof token!=='string'||token.length>128||!equal(hash(token),row.csrf_token_hash))throw csrfInvalid();
  }
  private refreshHandle(value:unknown):{sid:string;secret:string} {
    if(typeof value!=='string'||value.length>256)throw expired();const parts=value.split('.');
    if(parts.length!==2||!PORTAL_UUID.test(parts[0])||!/^[A-Za-z0-9_-]{43,128}$/.test(parts[1]))throw expired();return {sid:parts[0],secret:parts[1]};
  }
  private anonymous(scope:PortalScope,proof:PortalOriginProof):string {
    return jwt.sign({kind:'portal_csrf',cid:scope.clusterId,wid:scope.workspaceId,origin:proof.origin,nonce:randomBytes(32).toString('base64url')},
      this.signingKey(),{algorithm:'HS256',issuer:'kongos-portal',audience:'kongos-portal-csrf',expiresIn:'10m'});
  }
  verifyAnonymousCsrf(scope:PortalScope,cookie:unknown,header:unknown,proof:PortalOriginProof):void {
    this.assertOrigin(proof);portalScope(scope);
    try {if(typeof cookie!=='string'||cookie.length>2048||!equal(cookie,header))throw new Error();
      const payload=jwt.verify(cookie,this.signingKey(),{algorithms:['HS256'],issuer:'kongos-portal',audience:'kongos-portal-csrf'});
      if(typeof payload==='string'||payload.kind!=='portal_csrf'||payload.cid!==scope.clusterId||payload.wid!==scope.workspaceId||payload.origin!==proof.origin)throw new Error();
    }catch{throw csrfInvalid();}
  }
  async csrf(scope:PortalScope,cookies:{accessToken?:string;refreshToken?:string;csrfCookie?:string},proof:PortalOriginProof):Promise<{csrfToken:string;cookieToken?:string;expiresAt:string;authenticated:boolean}> {
    this.assertOrigin(proof);await this.tenant(scope);let row:any;
    if(cookies.accessToken){try{const principal=await this.authenticate(cookies.accessToken);this.assertScope(principal,scope);row=await this.sessionRow(principal.sessionId,principal.developerId);}
      catch(error){if(error instanceof ForbiddenException)throw error;if(!(error instanceof UnauthorizedException))throw error;}}
    if(!row&&cookies.refreshToken){try{const handle=this.refreshHandle(cookies.refreshToken),candidate=await this.sessionRow(handle.sid);
        if(candidate.cluster_id!==scope.clusterId||candidate.workspace_id!==scope.workspaceId)throw new ForbiddenException({code:'PORTAL_SCOPE_DENIED',message:'门户会话不属于所选租户'});
        if(equal(hash(handle.secret),candidate.refresh_token_hash))row=candidate;
      }catch(error){if(error instanceof ForbiddenException)throw error;if(!(error instanceof UnauthorizedException))throw error;}}
    if(row){if(typeof cookies.csrfCookie!=='string'||cookies.csrfCookie.length>128||!equal(hash(cookies.csrfCookie),row.csrf_token_hash))throw csrfInvalid();
      return {csrfToken:cookies.csrfCookie,expiresAt:safeDate(row.expires_at),authenticated:true};}
    const token=this.anonymous(scope,proof);return {csrfToken:token,cookieToken:token,expiresAt:new Date(Date.now()+600000).toISOString(),authenticated:false};
  }
  private async limits(key:string,limit:number,window=60000):Promise<void> {
    if(!(await this.redis.rateLimit(`portal:${key}`,limit,window)).allowed)throw new HttpException({code:'PORTAL_RATE_LIMIT',message:'门户请求过于频繁，请稍后重试'},429);
  }
  async register(scope:PortalScope,body:unknown,context:PortalRequestContext):Promise<{status:'pending'}> {
    const value=portalExact(body,['username','email','displayName','password']);await this.tenant(scope,this.db,true);
    if(typeof value.username!=='string'||!/^[a-z0-9._-]{3,64}$/.test(value.username.toLowerCase())||typeof value.email!=='string'||value.email.length>254||!/^\S+@\S+\.\S+$/.test(value.email)||typeof value.displayName!=='string'||value.displayName.trim().length<1||value.displayName.length>128)throw new BadRequestException({code:'INVALID_PORTAL_REGISTRATION',message:'门户注册字段无效'});
    await this.limits(`register:ip:${hash(context.ip??'')}`,10,3600000);
    const passwordHash=await hashPolicyPassword(value.password,{username:value.username});
    const settings=await this.db.one<any>('SELECT registration_enabled FROM portal_settings WHERE cluster_id=$1 AND workspace_id=$2',[scope.clusterId,scope.workspaceId]);
    if(!settings?.registration_enabled)throw new ForbiddenException({code:'PORTAL_REGISTRATION_DISABLED',message:'此门户未开放注册'});
    try {await this.db.transaction(async tx=>{await this.tenant(scope,tx,true);
      const current=await tx.one<any>('SELECT registration_enabled FROM portal_settings WHERE cluster_id=$1 AND workspace_id=$2 FOR SHARE',[scope.clusterId,scope.workspaceId]);
      if(!current?.registration_enabled)throw new ForbiddenException({code:'PORTAL_REGISTRATION_DISABLED',message:'此门户未开放注册'});
      const id=randomUUID();await tx.exec(`INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7)`,[id,scope.clusterId,scope.workspaceId,value.username.toLowerCase(),value.email.toLowerCase(),value.displayName.trim(),passwordHash]);
      await this.audit.append({...this.event(scope,id,context),action:'portal.register',after:{developerId:id,status:'pending'}},tx);
    });}catch(error:any){if(error?.code!=='23505')throw error;/* Same acknowledgement avoids account enumeration. */}
    return {status:'pending'};
  }
  private async createSession(tx:DbService,row:any,context:PortalRequestContext):Promise<PortalAuthResult> {
    const sid=randomUUID(),refresh=randomBytes(48).toString('base64url'),csrf=randomBytes(32).toString('base64url');
    await tx.exec(`UPDATE portal_sessions SET revoked_at=now() WHERE developer_id=$1 AND revoked_at IS NULL AND id NOT IN
      (SELECT id FROM portal_sessions WHERE developer_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC,id DESC LIMIT 9)`,[row.id]);
    await tx.exec(`INSERT INTO portal_sessions(id,cluster_id,workspace_id,developer_id,family_id,credential_epoch,refresh_token_hash,csrf_token_hash,expires_at,ip,user_agent)
      VALUES($1,$2,$3,$4,$1,$5,$6,$7,now()+interval '7 days',$8,$9)`,[sid,row.cluster_id,row.workspace_id,row.id,row.credential_epoch,hash(refresh),hash(csrf),context.ip??null,(context.userAgent??'').slice(0,1024)]);
    return {developer:this.view(row),accessToken:this.access(row,sid),refreshToken:`${sid}.${refresh}`,csrfToken:csrf,expiresAt:new Date(Date.now()+604800000).toISOString()};
  }
  async login(scope:PortalScope,body:unknown,context:PortalRequestContext):Promise<PortalAuthResult> {
    const value=portalExact(body,['username','password']);await this.tenant(scope,this.db,true);
    if(typeof value.username!=='string'||!/^[a-z0-9._-]{3,64}$/.test(value.username.toLowerCase())||typeof value.password!=='string'||Buffer.byteLength(value.password)>72||!value.password||value.password.includes('\0'))throw denied();
    const username=value.username.toLowerCase();await this.limits(`login:ip:${hash(context.ip??'')}`,30);await this.limits(`login:account:${hash(`${scope.clusterId}:${scope.workspaceId}:${username}`)}`,10);
    const outcome=await this.db.transaction(async tx=>{await this.tenant(scope,tx,true);
      const row=await tx.one<any>('SELECT * FROM portal_developers WHERE cluster_id=$1 AND workspace_id=$2 AND username=$3 FOR UPDATE',[scope.clusterId,scope.workspaceId,username]);
      const ok=await bcrypt.compare(value.password,row?.password_hash??DUMMY_HASH);
      const locked=row?.locked_until&&new Date(row.locked_until).getTime()>Date.now();
      if(!ok||!row||locked||row.status!=='active'||row.deleted_at){
        if(row?.status==='active'&&!locked)await tx.exec(`UPDATE portal_developers SET failed_attempts=CASE WHEN locked_until<=now() THEN 1 ELSE failed_attempts+1 END,
          locked_until=CASE WHEN (CASE WHEN locked_until<=now() THEN 1 ELSE failed_attempts+1 END)>=5 THEN now()+interval '15 minutes' ELSE NULL END WHERE id=$1`,[row.id]);
        await this.audit.append({...this.event(scope,row?.id??null,context),action:'portal.login',result:'denied'},tx);return null;
      }
      await tx.exec('UPDATE portal_developers SET failed_attempts=0,locked_until=NULL WHERE id=$1',[row.id]);
      const result=await this.createSession(tx,row,context);await this.audit.append({...this.event(scope,row.id,context),action:'portal.login'},tx);return result;
    });if(!outcome)throw denied();return outcome;
  }
  async refresh(scope:PortalScope,refreshToken:unknown,csrfToken:unknown,context:PortalRequestContext):Promise<PortalAuthResult> {
    portalScope(scope);const handle=this.refreshHandle(refreshToken);await this.limits(`refresh:${handle.sid}`,20);
    const outcome=await this.db.transaction(async tx=>{
      const row=await this.sessionRow(handle.sid,undefined,tx,true);
      if(row.cluster_id!==scope.clusterId||row.workspace_id!==scope.workspaceId)throw new ForbiddenException({code:'PORTAL_SCOPE_DENIED',message:'门户会话不属于所选租户'});
      if(typeof csrfToken!=='string'||csrfToken.length>128||!equal(hash(csrfToken),row.csrf_token_hash))throw csrfInvalid();
      const digest=hash(handle.secret);
      if(!equal(digest,row.refresh_token_hash)){
        const used=await tx.one('SELECT token_hash FROM portal_refresh_history WHERE session_id=$1 AND token_hash=$2 AND expires_at>now()',[handle.sid,digest]);
        if(used){await tx.exec('UPDATE portal_sessions SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL',[row.family_id]);
          await this.audit.append({...this.event(scope,row.id,context),action:'portal.refresh',result:'replay'},tx);}
        return null;
      }
      const secret=randomBytes(48).toString('base64url'),csrf=randomBytes(32).toString('base64url');
      await tx.exec(`INSERT INTO portal_refresh_history(cluster_id,workspace_id,session_id,token_hash,generation,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
        [scope.clusterId,scope.workspaceId,handle.sid,digest,row.refresh_generation,row.expires_at]);
      await tx.exec('UPDATE portal_sessions SET refresh_token_hash=$2,csrf_token_hash=$3,refresh_generation=refresh_generation+1,updated_at=now() WHERE id=$1',[handle.sid,hash(secret),hash(csrf)]);
      await this.audit.append({...this.event(scope,row.id,context),action:'portal.refresh'},tx);
      return {developer:this.view(row),accessToken:this.access(row,handle.sid),refreshToken:`${handle.sid}.${secret}`,csrfToken:csrf,expiresAt:safeDate(row.expires_at)};
    });if(!outcome)throw expired();return outcome;
  }
  async logout(principal:PortalPrincipal,context:PortalRequestContext):Promise<void> {
    await this.assertCurrent(principal);await this.db.transaction(async tx=>{const row=await this.sessionRow(principal.sessionId,principal.developerId,tx,true);
      await tx.exec('UPDATE portal_sessions SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL',[row.family_id]);
      await this.audit.append({...this.event(principal,principal.developerId,context),action:'portal.logout'},tx);});
  }
  me(principal:PortalPrincipal):Promise<PortalDeveloperView> {return this.assertCurrent(principal);}
  async updateProfile(principal:PortalPrincipal,body:unknown,context:PortalRequestContext):Promise<PortalDeveloperView> {
    const value=portalExact(body,['revision','displayName']);portalRevision(value.revision);
    if(typeof value.displayName!=='string'||!value.displayName.trim()||value.displayName.length>128)throw new BadRequestException({code:'INVALID_PORTAL_PROFILE',message:'开发者显示名无效'});
    return this.executeMetadata(principal,{module:'profile',action:'update',targetId:principal.developerId,payload:value,context},async tx=>{
      const before=await this.assertCurrent(principal,tx,true),row=await tx.one<any>(`UPDATE portal_developers SET display_name=$4,revision=revision+1,updated_at=now()
        WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revision=$5 AND status='active' RETURNING *`,[principal.developerId,principal.clusterId,principal.workspaceId,value.displayName.trim(),value.revision]);
      if(!row)throw new ConflictException({code:'REVISION_CONFLICT',message:'开发者资料已变化，请重新加载'});
      await this.audit.append({...this.event(principal,principal.developerId,context),action:'portal.profile',before,after:this.view(row)},tx);return this.view(row);
    });
  }
  async changePassword(principal:PortalPrincipal,body:unknown,context:PortalRequestContext):Promise<any> {
    const value=portalExact(body,['revision','currentPassword','newPassword','confirmed']);portalRevision(value.revision);
    if(value.confirmed!==true||typeof value.currentPassword!=='string'||Buffer.byteLength(value.currentPassword)>72)throw new BadRequestException({code:'PASSWORD_CONFIRMATION_REQUIRED',message:'需要当前密码和确认'});
    await this.limits(`password:${principal.developerId}`,10);
    const retained={operation:'password_change',revision:value.revision,confirmed:true};
    return this.executeMetadata(principal,{module:'password',action:'update',targetId:principal.developerId,payload:value,context},async(tx,operationId)=>{
      const row=await this.sessionRow(principal.sessionId,principal.developerId,tx,true);
      if(!await bcrypt.compare(value.currentPassword,row.password_hash))throw denied();
      const passwordHash=await hashPolicyPassword(value.newPassword,{username:row.username,previousHash:row.password_hash});await this.assertCurrent(principal,tx,true);
      const updated=await tx.one<any>(`UPDATE portal_developers SET password_hash=$2,credential_epoch=credential_epoch+1,must_change_password=false,
        revision=revision+1,failed_attempts=0,locked_until=NULL,updated_at=now() WHERE id=$1 AND revision=$3 RETURNING id`,[row.id,passwordHash,value.revision]);
      if(!updated)throw new ConflictException({code:'REVISION_CONFLICT',message:'开发者资料已变化，请重新加载'});
      await this.revokeSessions(row.id,principal,tx,context);
      await this.audit.append({...this.event(principal,row.id,context),action:'portal.password',after:{developerId:row.id,changed:true}},tx);
      return {changed:true,reauthenticate:true,operationId};
    },retained,true);
  }
  async revokeSessions(developerId:string,scope:PortalScope,tx:DbService,context:PortalRequestContext):Promise<void> {
    if(!PORTAL_UUID.test(developerId))throw new BadRequestException('开发者 ID 无效');
    await tx.exec('UPDATE portal_sessions SET revoked_at=now(),updated_at=now() WHERE developer_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revoked_at IS NULL',[developerId,scope.clusterId,scope.workspaceId]);
    await this.audit.append({...this.event(scope,developerId,context),action:'portal.sessions.revoke'},tx);
  }
  /** SQL-only developer mutations. The private principal and fresh DB session remain authoritative. */
  async executeMetadata<T>(principal:PortalPrincipal,mutation:PortalMetadataMutation,fn:(tx:DbService,operationId:string)=>Promise<T>,retainedPayload:unknown=mutation.payload,revokesOwnSession=false):Promise<T> {
    await this.assertCurrent(principal,undefined,true);const key=mutation.context.idempotencyKey;
    if(typeof key!=='string'||!/^[A-Za-z\d_.:-]{8,128}$/.test(key))throw new BadRequestException({code:'IDEMPOTENCY_KEY_REQUIRED',message:'门户写操作必须提供有效幂等键'});
    const requestHash=this.secrets.fingerprint({developerId:principal.developerId,clusterId:principal.clusterId,workspaceId:principal.workspaceId,module:mutation.module,action:mutation.action,targetId:mutation.targetId??null,payload:mutation.payload});
    return this.redis.withLock(`portal-operation:${principal.developerId}:${key}`,async()=>{
      await this.assertCurrent(principal,undefined,true);
      const old=await this.db.one<any>('SELECT * FROM portal_operations WHERE developer_id=$1 AND idempotency_key=$2',[principal.developerId,key]);
      if(old){if(old.request_hash!==requestHash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键已用于不同门户变更'});
        if(old.state==='succeeded'&&old.remote_completed)return old.module==='password'?this.secrets.redact(old.safe_result) as T:this.secrets.decrypt<T>(old.result_secret,`portal-operation:${old.id}:result`);
        throw new ConflictException({code:'PORTAL_RESULT_UNCERTAIN',message:'此操作已经尝试执行，请核验原回执',operationId:old.id,state:old.state});}
      const id=randomUUID();await this.db.transaction(async tx=>{await this.assertCurrent(principal,tx,true);
        await tx.exec(`INSERT INTO portal_operations(id,cluster_id,workspace_id,developer_id,idempotency_key,request_hash,module,action,target_id,payload_secret)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[id,principal.clusterId,principal.workspaceId,principal.developerId,key,requestHash,mutation.module,mutation.action,mutation.targetId??null,mutation.module==='password'?null:this.secrets.encrypt(retainedPayload,`portal-operation:${id}:payload`)]);
        await this.audit.append({...this.event(principal,principal.developerId,mutation.context),entityType:mutation.module,entityId:mutation.targetId,action:`portal.${mutation.action}.requested`,after:this.secrets.redact(retainedPayload),result:'pending'},tx);
      });
      try {return await this.db.transaction(async tx=>{await this.sessionRow(principal.sessionId,principal.developerId,tx,true);await this.assertCurrent(principal,tx,true);
        await this.redis.assertLeaseOwnership();await tx.exec("UPDATE portal_operations SET remote_started=true WHERE id=$1 AND state='running'",[id]);
        const result=await fn(tx,id);await this.redis.assertLeaseOwnership();
        if(!revokesOwnSession)await this.assertCurrent(principal,tx,true);
        await tx.exec("UPDATE portal_operations SET state='succeeded',remote_completed=true,result_secret=$2,safe_result=$3::jsonb,updated_at=now() WHERE id=$1 AND state='running'",
          [id,mutation.module==='password'?null:this.secrets.encrypt(result,`portal-operation:${id}:result`),JSON.stringify(this.secrets.redact(result))]);return result;
      });}catch(error:any){
        // Lost COMMIT acknowledgement can hide success. Never overwrite committed success.
        const committed=await this.db.one<any>('SELECT state,remote_completed,result_secret,module,safe_result FROM portal_operations WHERE id=$1',[id]).catch(()=>null);
        if(committed?.state==='succeeded'&&committed.remote_completed)return committed.module==='password'?this.secrets.redact(committed.safe_result) as T:this.secrets.decrypt<T>(committed.result_secret,`portal-operation:${id}:result`);
        if(error?.code==='23505')error=new ConflictException({code:'PORTAL_DUPLICATE_RESOURCE',message:'门户对象已存在'});
        if(['23503','23514','22P02'].includes(error?.code))error=new BadRequestException({code:'INVALID_PORTAL_RELATION',message:'门户对象范围或关联无效'});
        const response=error instanceof HttpException?error.getResponse():null,code=response&&typeof response==='object'&&'code'in response?String(response.code):'PORTAL_OPERATION_FAILED';
        const uncertain=!(error instanceof HttpException)||error.getStatus()>=500;
        await this.db.transaction(async tx=>{await tx.exec("UPDATE portal_operations SET state=$2,remote_started=true,remote_completed=$3,error_code=$4,updated_at=now() WHERE id=$1 AND state='running'",[id,uncertain?'uncertain':'failed',!uncertain,code]);
          await this.audit.append({...this.event(principal,principal.developerId,mutation.context),entityType:mutation.module,entityId:mutation.targetId,action:`portal.${mutation.action}`,result:uncertain?'uncertain':'failed'},tx);
        }).catch(()=>undefined);
        if(uncertain)throw new HttpException({code:'PORTAL_RESULT_UNCERTAIN',message:'门户变更结果需要核验，请勿使用新幂等键重试',operationId:id,state:'uncertain'},503);
        throw error;
      }
    });
  }
  async operation(principal:PortalPrincipal,keyOrId:string,byKey=false):Promise<PortalOperationView> {
    await this.assertCurrent(principal);
    if(byKey?!/^[A-Za-z\d_.:-]{8,128}$/.test(keyOrId):!PORTAL_UUID.test(keyOrId))throw new BadRequestException({code:'INVALID_PORTAL_RECEIPT',message:'回执标识无效'});
    const row=await this.db.one<any>(`SELECT * FROM portal_operations WHERE developer_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND ${byKey?'idempotency_key':'id'}=$4`,[principal.developerId,principal.clusterId,principal.workspaceId,keyOrId]);
    if(!row)throw new NotFoundException({code:'PORTAL_OPERATION_NOT_FOUND',message:'门户操作回执不存在'});await this.assertCurrent(principal);
    return {id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,state:row.state,module:row.module,action:row.action,targetId:row.target_id,
      remoteStarted:row.remote_started,remoteCompleted:row.remote_completed,errorCode:row.error_code,safeResult:this.secrets.redact(row.safe_result),createdAt:safeDate(row.created_at),updatedAt:safeDate(row.updated_at)};
  }
  async reviewDeveloper(actor:EntityActor,developerId:string,scope:PortalScope,body:unknown,context:PortalRequestContext,transaction?:DbService):Promise<PortalDeveloperView> {
    const value=portalExact(body,['revision','status','reason']);portalRevision(value.revision);portalScope(scope);
    if(!PORTAL_UUID.test(developerId)||!['active','rejected','disabled','deleted'].includes(value.status)||value.reason!==undefined&&(typeof value.reason!=='string'||value.reason.length>2048))throw new BadRequestException({code:'INVALID_DEVELOPER_REVIEW',message:'开发者审核参数无效'});
    await this.authz.assertWholeWorkspace(actor.user,scope.clusterId,scope.workspaceId,'developers',value.status==='deleted'?'delete':'write');
    if(value.status==='active'||value.status==='rejected')await this.authz.assertWholeWorkspace(actor.user,scope.clusterId,scope.workspaceId,'workflows','approve');
    return (transaction??this.db).transaction(async tx=>{
      // Configuration authorization and the write share one stable IAM epoch.
      await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR SHARE');
      const before=await tx.one<any>('SELECT * FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE',[developerId,scope.clusterId,scope.workspaceId]);
      if(!before)throw new NotFoundException({code:'PORTAL_DEVELOPER_NOT_FOUND',message:'开发者不存在'});
      if(before.revision!==value.revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'开发者资料已变化'});
      const cluster=await tx.one<any>('SELECT execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[scope.clusterId]);
      if(!cluster)throw new ForbiddenException({code:'PORTAL_NOT_AVAILABLE',message:'集群不可用'});
      // Private plan/inspection seals the exact DB row, including hashed credentials.
      // Audit and public views still receive only the safe projection.
      if(cluster.execution_mode==='approval')await this.metadataPolicy.assertStep({handler:'portal.developer.review',actor:actor.user,clusterId:scope.clusterId,workspaceId:scope.workspaceId,entityType:'portal_developers',entityId:developerId,before,revision:value.revision,payload:value},tx);
      await this.authz.assertWholeWorkspace(actor.user,scope.clusterId,scope.workspaceId,'developers',value.status==='deleted'?'delete':'write');
      const allowed:Record<string,string[]>={pending:['active','rejected','deleted'],active:['disabled','deleted'],disabled:['active','deleted'],rejected:['active','deleted'],deleted:['disabled']};
      if(!allowed[before.status]?.includes(value.status))throw new ConflictException({code:'INVALID_DEVELOPER_TRANSITION',message:'开发者状态不能执行此变更'});
      let releasedReservations=0;
      if(['disabled','deleted','rejected'].includes(value.status)){
        releasedReservations=await releaseUnusedPortalReservations(tx,{clusterId:scope.clusterId,workspaceId:scope.workspaceId,developerId});
        const inUse=await tx.one('SELECT id FROM portal_application_grants WHERE cluster_id=$1 AND workspace_id=$2 AND developer_id=$3 AND state<>\'revoked\' AND reservation_released_at IS NULL LIMIT 1 FOR UPDATE',[scope.clusterId,scope.workspaceId,developerId]);
        if(inUse)throw new ConflictException({code:'PORTAL_CREDENTIALS_ACTIVE',message:'开发者仍有有效或未决凭证授权，必须先撤销或处理申请'});
      }
      const row=await tx.one<any>(`UPDATE portal_developers SET status=$4,credential_epoch=credential_epoch+1,revision=revision+1,reviewed_by=$5,reviewed_at=now(),review_reason=$6,
        deleted_at=CASE WHEN $4='deleted' THEN now() ELSE NULL END,retention_until=CASE WHEN $4='deleted' THEN now()+interval '30 days' ELSE NULL END,updated_at=now()
        WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revision=$7 RETURNING *`,[developerId,scope.clusterId,scope.workspaceId,value.status,actor.user.id,value.reason??'',value.revision]);
      if(!row)throw new ConflictException({code:'REVISION_CONFLICT',message:'开发者资料已变化'});
      await tx.exec('UPDATE portal_sessions SET revoked_at=now() WHERE developer_id=$1 AND revoked_at IS NULL',[developerId]);
      await this.audit.append({actorId:actor.user.id,clusterId:scope.clusterId,workspaceId:scope.workspaceId,entityType:'portal_developers',entityId:developerId,action:'portal.developer.review',before:this.view(before),after:{...this.view(row),releasedReservations},requestId:context.requestId,ip:context.ip,scopeHints:metadataAuditScope('developers','portal_developers',developerId,scope.workspaceId)},tx);
      return this.view(row);
    });
  }
}
