import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {AuthService} from '../../apps/console-api/src/modules/auth/auth.service';
import {PortalAuthService} from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';

/** A new independent, synthetic runtime-role proof of the actual exported RAM
 * pair reader. No original reference, current application DB, HTTP or browser. */
async function main():Promise<void>{
 const runId=new Date().toISOString().replace(/[:.]/g,'-'),container=`kongos-m6-manualsessions-${randomUUID().slice(0,8)}`;
 const checks:Array<{name:string;passed:boolean;errorCode?:string}>=[],hash=(v:string|Buffer)=>createHash('sha256').update(v).digest('hex');
 const sourcePath='tests/security/lib/m6-manual-session-recovery.mjs',sourceHash=hash(readFileSync(sourcePath));
 const errorCode=(e:any)=>String(e?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,64);
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(e){checks.push({name,passed:false,errorCode:errorCode(e)});throw e;}};
 const dockerEnv={...process.env};for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnv[k];
 const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 let owner:DbService|undefined,runtime:DbService|undefined,failureCode:string|undefined;
 let roleEvidence:unknown,migrations:Array<{name:string;checksum:string}>=[],programHash:string|undefined,queryHash:string|undefined;
 let actualPortalLogins=0,actualConsoleLogins=0,readerRuns=0,readerDenials=0,queryOnlyRuns=0;
 const portalKey='Synthetic!PortalManualSessionReaderSigning2026Key',consoleKey='Synthetic!ConsoleManualSessionReaderSigning2026Key';
 try{
  docker(['run','-d','--pull=never','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',container,'5432']).trim().split(':').pop();process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='be'.repeat(32);process.env.APP_SECRET=consoleKey;process.env.PORTAL_SECRET=portalKey;
  process.env.PORTAL_PUBLIC_ORIGINS='http://127.0.0.1:18082';process.env.BOOTSTRAP_ADMIN_USERNAME='manual-reader-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!ManualReaderBootstrap2026Password';
  owner=new DbService();for(let n=0;n<80;n++){try{await owner.one('SELECT 1');break;}catch{if(n===79)throw Error('DISPOSABLE_DATABASE_UNAVAILABLE');await new Promise(r=>setTimeout(r,100));}}
  await owner.migrateAndSeed();process.env.CONSOLE_DB_RUNTIME_USER='m6_manual_reader_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!ManualReaderRuntime2026Password';await provisionRuntimeRole(owner);
  const runtimeUrl=`postgres://m6_manual_reader_runtime@127.0.0.1:${port}/postgres`;process.env.DATABASE_URL=runtimeUrl;runtime=new DbService();const db=runtime;
  await check('actual PG16 unchanged000-009; every login and exported reader uses nonowner nonsuper runtime credentials',async()=>{
   assert.match((await db.one<any>('SHOW server_version')).server_version,/^16\./);migrations=await db.query('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,10);
   for(const row of migrations)assert.equal(row.checksum,hash(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)));
   const role=await db.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user');assert(Object.values(role).every(v=>v===false));
   const owns=(await db.one<any>("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname IN('audit_events','auth_sessions','portal_sessions') AND r.rolname=current_user) AS owns")).owns;assert.equal(owns,false);
   const privileges:any={};for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE']){const allowed=(await db.one<any>("SELECT has_table_privilege(current_user,'audit_events',$1) AS allowed",[privilege])).allowed;privileges[privilege]=allowed;assert.equal(allowed,['SELECT','INSERT'].includes(privilege));}
   roleEvidence={...role,ownsFixtureTables:owns,auditPrivileges:privileges};
  });
  // Execute the actual ESM export to avoid reimplementing its SQL or generated
  // program. This subprocess returns only static public source, never secrets.
  const exported=JSON.parse(execFileSync(process.execPath,['--input-type=module','-e',`import * as h from './${sourcePath}';process.stdout.write(JSON.stringify({query:h.MANUAL_PAIR_SESSION_SQL,program:h.MANUAL_SESSION_READER_PROGRAM}));`],{encoding:'utf8',stdio:['ignore','pipe','pipe']}));
  const {query,program}=exported;programHash=hash(program);queryHash=hash(query);assert(program.includes(JSON.stringify(query)));assert.deepEqual([...new Set(query.match(/\$\d+/g))].sort((a:any,b:any)=>Number(a.slice(1))-Number(b.slice(1))),Array.from({length:10},(_,n)=>`$${n+1}`));
  const secrets=new SecretService(),audit=new AuditService(db,secrets,new AuditOutboxWriter(db,secrets)),context=new KongExecutionContextService();
  const redis:any={client:{set:async()=> 'OK'},rateLimit:async()=>({allowed:true})};
  const kong:any={request:()=>{throw Error('NATIVE_REQUEST_FORBIDDEN');}};
  const authz=new AuthorizationService(db,new WorkspaceResolverService(db),kong,context),consoleAuth=new AuthService(db,redis,audit,authz,context,secrets);
  const portalAuth=new PortalAuthService(db,redis,secrets,audit,authz,{assertStep:async()=>{throw Error('WORKFLOW_METADATA_FORBIDDEN');}});
  const password='Synthetic!ManualSessionReader2026Password',passwordHash=await bcrypt.hash(password,12);
  const fixture=async()=>{
   const cid=randomUUID(),wid=randomUUID(),developerId=randomUUID(),userId=randomUUID(),portalRequest=randomUUID(),consoleRequest=randomUUID();
   const portalUsername=`portal-${developerId}`,consoleUsername=`console-${userId}`;
   await db.transaction(async tx=>{
    await tx.exec("INSERT INTO clusters(id,name,admin_url,version,status) VALUES($1,$2,$3,'1.5.1','healthy')",[cid,`Synthetic manual ${cid}`,`http://synthetic-${cid}.invalid:8001`]);
    await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'manual','Synthetic manual reader workspace')",[wid,cid]);
    await tx.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name,status,published) VALUES($1,$2,$3,'Synthetic manual reader portal','active',true)",[cid,wid,`manual-${cid}`]);
    await tx.exec("INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,'Synthetic manual reader developer',$6,'active')",[developerId,cid,wid,portalUsername,`${developerId}@example.test`,passwordHash]);
    await tx.exec('INSERT INTO users(id,username,password_hash) VALUES($1,$2,$3)',[userId,consoleUsername,passwordHash]);
   });
   const pStart=new Date().toISOString(),portal=await portalAuth.login({clusterId:cid,workspaceId:wid},{username:portalUsername,password},{requestId:portalRequest,ip:'127.0.0.1',userAgent:'synthetic-manual-reader'}),pEnd=new Date().toISOString();actualPortalLogins++;
   const cStart=new Date().toISOString(),console=await context.runHttp({requestId:consoleRequest},()=>consoleAuth.login(consoleUsername,password,'127.0.0.1','synthetic-manual-reader')),cEnd=new Date().toISOString();actualConsoleLogins++;
   const portalClaims=jwt.decode(portal.accessToken) as jwt.JwtPayload,consoleClaims=jwt.decode(console.accessToken) as jwt.JwtPayload;
   assert.equal((await portalAuth.authenticate(portal.accessToken)).developerId,developerId);assert.equal((await consoleAuth.authenticate(console.accessToken)).user.id,userId);
   const expected={owner:{actorId:developerId,clusterId:cid,workspaceId:wid,loginRequestId:portalRequest,startedAt:pStart,responseObservedAt:pEnd},administrator:{actorId:userId,loginRequestId:consoleRequest,startedAt:cStart,responseObservedAt:cEnd}};
   const candidates=['unrelated-synthetic-candidate',portal.accessToken,portal.refreshToken,portal.csrfToken,console.accessToken,console.refreshToken,console.csrfToken];
   const params=[developerId,cid,wid,portalRequest,pStart,pEnd,userId,consoleRequest,cStart,cEnd];
   return{cid,wid,developerId,userId,portal,console,portalClaims,consoleClaims,input:{expected,candidates},params};
  };
  type Fixture=Awaited<ReturnType<typeof fixture>>;
  const readonlyDigest=async()=> (await db.one<any>(`SELECT encode(sha256(convert_to(jsonb_build_object('console',(SELECT jsonb_agg(s ORDER BY s.id) FROM auth_sessions s),'portal',(SELECT jsonb_agg(s ORDER BY s.id) FROM portal_sessions s),'audit',(SELECT jsonb_agg(a ORDER BY a.id) FROM audit_events a))::text,'UTF8')),'hex') AS hash`)).hash as string;
  const run=async(input:Fixture['input'],clock?:number)=>{
   readerRuns++;const before=await readonlyDigest();let result:{exit:number;stdout:string;stderr:string};
   const actualProgram=(clock===undefined?'':`Date.now=()=>${clock};`)+program;
   try{const stdout=execFileSync(process.execPath,['-e',actualProgram],{cwd:resolve('apps/console-api'),env:{PATH:process.env.PATH,DATABASE_URL:runtimeUrl,PORTAL_SECRET:portalKey,APP_SECRET:consoleKey},input:JSON.stringify(input),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:16384});result={exit:0,stdout,stderr:''};}
   catch(e:any){result={exit:Number(e.status),stdout:String(e.stdout??''),stderr:String(e.stderr??'')};}
   assert.equal(await readonlyDigest(),before,'READONLY_READER_CHANGED_SESSION_OR_AUDIT');return result;
  };
  const denied=async(input:Fixture['input'])=>{const r=await run(input);assert.equal(r.exit,2);assert.equal(r.stdout,'');assert.equal(r.stderr,'');readerDenials++;};
  const accepted=async(f:Fixture,clock?:number)=>{const r=await run(f.input,clock);assert.equal(r.exit,0);assert.equal(r.stderr,'');const p=JSON.parse(r.stdout);
   for(const [role,claims,start]of [['owner',f.portalClaims,1],['administrator',f.consoleClaims,4]] as const){assert.deepEqual(Object.keys(p[role]).sort(),['accessIndex','refreshIndex','csrfIndex','sessionId','issuedAt','accessExpired','originalLoginAudited','currentSessionVerified','refreshVerified','csrfVerified'].sort());assert.equal(p[role].sessionId,claims.sid);assert.equal(p[role].issuedAt,claims.iat);assert.equal(p[role].accessIndex,start);assert.equal(p[role].refreshIndex,start+1);assert.equal(p[role].csrfIndex,start+2);assert.equal(p[role].accessExpired,clock===undefined?false:true);for(const k of ['originalLoginAudited','currentSessionVerified','refreshVerified','csrfVerified'])assert.equal(p[role][k],true);}
   for(const v of f.input.candidates)assert(!r.stdout.includes(v));return p;};
  const f=await fixture();
  await check('actual exported combined SQL binds original audit request, actor, tenant, session creation and current epoch for both real logins',async()=>{
   const rows=await db.query<any>(query,f.params);queryOnlyRuns++;assert.equal(rows.length,2);for(const row of rows){assert.equal(row.session.login_count,1);assert.equal(Number(row.session.credential_epoch),1);}
   assert.equal(rows.find(r=>r.role==='owner').session.id,f.portalClaims.sid);assert.equal(rows.find(r=>r.role==='administrator').session.id,f.consoleClaims.sid);
  });
  await check('actual exported program validates independent HS256 namespaces and both sameSID refresh/CSRF hashes with no secret output',async()=>{await accepted(f);});
  await check('expired access classification retains actual original iat and current sessions; controlled classifier clock only',async()=>{await accepted(f,(Math.max(f.portalClaims.iat!,f.consoleClaims.iat!)+901)*1000);});
  await check('missing original login audit fails the entire pair with no partial output',async()=>{await denied({...f.input,expected:{...f.input.expected,owner:{...f.input.expected.owner,loginRequestId:randomUUID()}}});});
  await check('foreign tenant cannot reuse an original portal JWT or database session',async()=>{await denied({...f.input,expected:{...f.input.expected,owner:{...f.input.expected.owner,workspaceId:randomUUID()}}});});
  await check('original login window mismatch fails even when signed actor and refresh values are genuine',async()=>{await denied({...f.input,expected:{...f.input.expected,administrator:{...f.input.expected.administrator,startedAt:new Date(Date.parse(f.input.expected.administrator.startedAt)+6000).toISOString(),responseObservedAt:new Date(Date.parse(f.input.expected.administrator.responseObservedAt)+6000).toISOString()}}});});
  await check('another same-window current console SID makes original identity ambiguous instead of choosing a first row',async()=>{
   const second=randomUUID();await db.exec("INSERT INTO auth_sessions(id,user_id,refresh_token_hash,csrf_token_hash,expires_at,credential_epoch,created_at) SELECT $1,user_id,refresh_token_hash,csrf_token_hash,expires_at,credential_epoch,created_at FROM auth_sessions WHERE id=$2",[second,f.consoleClaims.sid]);await denied(f.input);await db.exec('DELETE FROM auth_sessions WHERE id=$1',[second]);await accepted(f);
  });
  await check('revoked console original session invalidates both recovered jars atomically',async()=>{const x=await fixture();await db.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[x.consoleClaims.sid]);await denied(x.input);});
  await check('advanced current console credential epoch invalidates otherwise exact original material',async()=>{const x=await fixture();await db.exec('UPDATE users SET credential_epoch=credential_epoch+1 WHERE id=$1',[x.userId]);await denied(x.input);});
  await check('unpublished original portal tenant refuses recovery despite active console session',async()=>{const x=await fixture();await db.exec('UPDATE portal_settings SET published=false,revision=revision+1 WHERE cluster_id=$1 AND workspace_id=$2',[x.cid,x.wid]);await denied(x.input);});
  await check('rotated current refresh hash rejects stale original material without any refresh packet',async()=>{const x=await fixture();await db.exec('UPDATE auth_sessions SET refresh_token_hash=$2 WHERE id=$1',[x.consoleClaims.sid,hash('SyntheticRotatedRefreshValue')]);await denied(x.input);});
  await check('repeated exact successful console login audit is ambiguous rather than reused as original evidence',async()=>{
   const x=await fixture();await audit.append({actorId:x.userId,entityType:'authentication',action:'login',result:'success',requestId:x.input.expected.administrator.loginRequestId});await denied(x.input);
  });
  await check('reader has no DML and retains frozen helper/schema checksums after successful and denied actual runtime reads',async()=>{
   assert.equal(hash(readFileSync(sourcePath)),sourceHash);for(const row of migrations)assert.equal(row.checksum,hash(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)));await accepted(f);
   const mutable=(await db.one<any>("SELECT has_table_privilege(current_user,'audit_events','UPDATE') AS allowed")).allowed;assert.equal(mutable,false);
  });
 }catch(e){failureCode=errorCode(e);throw e;}finally{
  const artifact=`artifacts/M6/manual-session-recovery-postgres-${runId}.json`;mkdirSync('artifacts/M6',{recursive:true});
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,sourcePath,sourceHash,queryHash,programHash,fixtureSourceHash:hash(readFileSync('tests/integration/manual-session-recovery.ts')),database:'disposable PostgreSQL16; unchanged000-009; genuine runtime nonowner/nonsuper',migrations,roleEvidence,actualPortalLogins,actualConsoleLogins,readerRuns,readerDenials,queryOnlyRuns,nativePackets:0,httpPackets:0,currentRuntimeReads:0,privateReferenceReads:0,browserActions:0,fixtureLimitations:['all users/tenants/cookies/passwords/material synthetic; no actual manual material accessed','actual production PortalAuthService and AuthService login/Audit/Authorization services run under runtime role; Redis allowed-only login fixture','expired classification uses only controlled Date.now in the actual reader subprocess; original signed iat, DB timestamps, current session and audit remain unchanged','no actual recovery, refresh, metadata action, deployment, build or current DB request'],checks,passed:checks.filter(v=>v.passed).length,total:checks.length},null,2));
  await runtime?.onModuleDestroy();await owner?.onModuleDestroy();try{docker(['rm','-f',container]);}catch{}process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(v=>v.passed).length,total:checks.length})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated manual session reader verification failed; see safe artifact\n');process.exitCode=1;});
