import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {compileFunction} from 'node:vm';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {PortalAuthService} from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';

/** Actual exported browser reader, disposable PostgreSQL and synthetic cookies.
 * No browser, HTTP request, Kong, existing application environment or private
 * reference is used. Redis throttling is the only login dependency fixture. */
async function main():Promise<void>{
 const runId=new Date().toISOString().replace(/[:.]/g,'-'),container=`kongos-m6-reader-${randomUUID().slice(0,8)}`;
 const checks:Array<{name:string;passed:boolean;errorCode?:string}>=[];
 let owner:DbService|undefined,runtime:DbService|undefined,failureCode:string|undefined;
 let serverVersion:string|undefined,sourceHash:string|undefined,queryHash:string|undefined,programHash:string|undefined;
 let migrations:Array<{name:string;checksum:string}>=[],roleEvidence:Record<string,unknown>|undefined;
 let readerRuns=0,readerRejections=0,runtimeLogins=0,fixtureRedisCalls=0;
 const sourcePath='tests/security/lib/m6-browser-remaining.mjs',portalSecret='SyntheticPortalBrowserReaderSigningKey2026!Independent';
 const safeCode=(error:any)=>String(error?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128);
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error){checks.push({name,passed:false,errorCode:safeCode(error)});throw error;}};
 const deniedSql=async(fn:()=>Promise<unknown>,code:string)=>{try{await fn();}catch(error){assert.equal(safeCode(error),code);return;}throw new Error('EXPECTED_SQL_REJECTION');};
 const hash=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
 const dockerEnv={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnv[key];
 const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 try{
  docker(['run','-d','--pull=never','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',container,'5432']).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='ab'.repeat(32);process.env.APP_SECRET='SyntheticConsoleBrowserReaderSigningKey2026!';
  process.env.PORTAL_SECRET=portalSecret;process.env.PORTAL_PUBLIC_ORIGINS='http://127.0.0.1:18082';
  process.env.BOOTSTRAP_ADMIN_USERNAME='reader-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!ReaderBootstrap2026Password';
  owner=new DbService();for(let n=0;n<80;n++){try{await owner.one('SELECT 1');break;}catch{if(n===79)throw new Error('DISPOSABLE_DATABASE_UNAVAILABLE');await new Promise(done=>setTimeout(done,100));}}
  await owner.migrateAndSeed();
  const sql=owner;
  await check('actual PostgreSQL16 applies unchanged migrations000-009 without extensions or schema patches',async()=>{
   serverVersion=(await sql.one<any>('SHOW server_version')).server_version;assert.match(serverVersion!,/^16\./);
   migrations=await sql.query<{name:string;checksum:string}>('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,10);
   for(const row of migrations)assert.equal(row.checksum,createHash('sha256').update(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)).digest('hex'));
   assert.equal((await sql.one<any>("SELECT count(*)::int AS n FROM pg_extension WHERE extname='pgcrypto'")).n,0);
  });
  process.env.CONSOLE_DB_RUNTIME_USER='m6_reader_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!ReaderRuntime2026Password';
  await provisionRuntimeRole(sql);
  const runtimeUrl=`postgres://m6_reader_runtime@127.0.0.1:${port}/postgres`;process.env.DATABASE_URL=runtimeUrl;runtime=new DbService();
  await check('reader and login use a genuine non-superuser non-owner runtime role with append-only audit privileges',async()=>{
   const role=await runtime!.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user');
   assert.equal(role.rolsuper,false);assert.equal(role.rolcreatedb,false);assert.equal(role.rolcreaterole,false);
   const owned=(await runtime!.one<any>("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname IN('audit_events','portal_sessions','portal_developers','portal_settings') AND r.rolname=current_user) AS owned")).owned;assert.equal(owned,false);
   for(const privilege of ['SELECT','INSERT'])assert.equal((await runtime!.one<any>("SELECT has_table_privilege(current_user,'audit_events',$1) AS allowed",[privilege])).allowed,true);
   for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await runtime!.one<any>("SELECT has_table_privilege(current_user,'audit_events',$1) AS allowed",[privilege])).allowed,false);
   roleEvidence={...role,ownsFixtureTables:owned,auditPrivileges:'SELECT INSERT only'};
  });
  const source=readFileSync(sourcePath,'utf8');sourceHash=hash(source);
  assert.equal(sourceHash,'e3b09ac5276a74082b54670f3c73f4e501fbc86f3d9c92416923899ae9230ae0','OWNER_FIXED_SOURCE_CHANGED');
  const queryInitializer=/export const BROWSER_COOKIE_SESSION_SQL=(`[^`]*`);/.exec(source)?.[1];assert(queryInitializer,'ACTUAL_SQL_EXPORT_REQUIRED');
  const query=compileFunction(`return ${queryInitializer};`)() as string;
  const programInitializer=/export const BROWSER_COOKIE_READER_PROGRAM=(`[^`]*`);/.exec(source)?.[1];assert(programInitializer,'ACTUAL_PROGRAM_EXPORT_REQUIRED');
  const program=compileFunction(`return ${programInitializer};`,['BROWSER_COOKIE_SESSION_SQL'])(query) as string;
  queryHash=hash(query);programHash=hash(program);assert(program.includes(JSON.stringify(query)));
  assert.deepEqual([...new Set(query.match(/\$\d+/g))].sort(),['$1','$2','$3','$4','$5']);
  const secrets=new SecretService(),audit=new AuditService(runtime,secrets,new AuditOutboxWriter(runtime,secrets));
  const auth=new PortalAuthService(runtime,{rateLimit:async()=>{fixtureRedisCalls++;return{allowed:true};}} as any,secrets,audit,{} as any,{assertStep:async()=>{throw new Error('NO_APPROVED_WORKFLOW_IN_READER_FIXTURE');}});
  const password='Synthetic!ReaderDeveloper2026Password',passwordHash=await bcrypt.hash(password,12);
  const fixture=async()=>{
   const cid=randomUUID(),wid=randomUUID(),developerId=randomUUID(),username=`dev-${developerId}`,loginRequestId=randomUUID();
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO clusters(id,name,admin_url,version,status) VALUES($1,$2,$3,'1.5.1','healthy')",[cid,`reader-${cid}`,`http://synthetic-${cid}.invalid:8001`]);
    await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'reader','Synthetic reader tenant')",[wid,cid]);
    await tx.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name,status,published) VALUES($1,$2,$3,'Synthetic reader portal','active',true)",[cid,wid,`reader-${cid}`]);
    await tx.exec("INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,'Synthetic reader developer',$6,'active')",[developerId,cid,wid,username,`${developerId}@example.test`,passwordHash]);
   });
   const login=await auth.login({clusterId:cid,workspaceId:wid},{username,password},{requestId:loginRequestId,ip:'127.0.0.1',userAgent:'synthetic-pg-reader'});runtimeLogins++;
   const claims=jwt.decode(login.accessToken) as jwt.JwtPayload;assert.equal(claims.sub,developerId);assert.equal(claims.exp! - claims.iat!,900);
   const expected={ownerId:developerId,clusterId:cid,workspaceId:wid,loginRequestId,issuedAt:claims.iat!};
   const candidates=['unrelated-synthetic-candidate',login.accessToken,login.refreshToken,login.csrfToken];
   const params=[claims.sid,developerId,cid,wid,loginRequestId];
   return{cid,wid,developerId,login,claims,expected,candidates,params};
  };
  type Fixture=Awaited<ReturnType<typeof fixture>>;
  const runReader=(input:{expected:Record<string,unknown>;candidates:string[]})=>{
   readerRuns++;
   try{
    const stdout=execFileSync(process.execPath,['-e',program],{cwd:resolve('apps/console-api'),env:{PATH:process.env.PATH,DATABASE_URL:runtimeUrl,PORTAL_SECRET:portalSecret},input:JSON.stringify(input),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:16384});
    return{exitCode:0,stdout,stderr:''};
   }catch(error:any){return{exitCode:Number(error.status),stdout:String(error.stdout??''),stderr:String(error.stderr??'')};}
  };
  const rejectedReader=(input:{expected:Record<string,unknown>;candidates:string[]})=>{
   const result=runReader(input);assert.equal(result.exitCode,2);assert.equal(result.stdout,'');assert.equal(result.stderr,'');readerRejections++;
  };
  const currentInput=(f:Fixture,patch?:{expected?:Record<string,unknown>;candidates?:string[]})=>({expected:patch?.expected??f.expected,candidates:patch?.candidates??f.candidates});
  const verifyReader=(f:Fixture,input=currentInput(f),expired=false)=>{
   const result=runReader(input);assert.equal(result.exitCode,0);assert.equal(result.stderr,'');
   const proof=JSON.parse(result.stdout);assert.deepEqual(Object.keys(proof).sort(),['accessExpired','accessIndex','credentialEpoch','csrfIndex','currentSessionVerified','expiresAt','originalLoginAudited','refreshIndex','sessionId'].sort());
   assert.equal(proof.sessionId,f.claims.sid);assert.equal(proof.accessIndex,1);assert.equal(proof.refreshIndex,2);assert.equal(proof.csrfIndex,3);assert.equal(proof.credentialEpoch,1);
   assert.equal(proof.originalLoginAudited,true);assert.equal(proof.currentSessionVerified,true);assert.equal(proof.accessExpired,expired);assert(Date.parse(proof.expiresAt)>Date.now());
   for(const value of input.candidates)if(value.length>32)assert(!result.stdout.includes(value));
  };
  const f=await fixture();
  await check('legacy exact developer UUID equality raises42883 under the real runtime role',async()=>{
   assert(query.includes('a.entity_id=d.id::text'));
   await deniedSql(()=>runtime!.query(query.replace('a.entity_id=d.id::text','a.entity_id=d.id'),f.params),'42883');
  });
  await check('legacy audit created_at column raises42703 independently after the type cast is correct',async()=>{
   assert(query.includes('a.occurred_at'));
   await deniedSql(()=>runtime!.query(query.replace('a.occurred_at','a.created_at'),f.params),'42703');
  });
  await check('actual exported five-bind SQL returns the original audited login and current session epoch',async()=>{
   const rows=await runtime!.query<any>(query,f.params);assert.equal(rows.length,1);assert.equal(rows[0].id,f.claims.sid);assert.equal(rows[0].original_login_audited,true);assert.equal(Number(rows[0].credential_epoch),1);
   assert.equal(rows[0].refresh_token_hash,hash(f.login.refreshToken.split('.')[1]));assert.equal(rows[0].csrf_token_hash,hash(f.login.csrfToken));
   assert.equal((await runtime!.one<any>('SELECT count(*)::int AS n FROM audit_events WHERE request_id=$1 AND actor_id IS NULL AND actor_type=\'developer\' AND action=\'portal.login\' AND result=\'success\'',[f.expected.loginRequestId])).n,1);
  });
  await check('actual exported reader program verifies signed JWT sameSID refresh CSRF and original login on runtime SQL',async()=>{verifyReader(f);});
  await check('expired original access JWT is accepted only with a still-current exact session and original hashes',async()=>{
   const issuedAt=Math.floor(Date.now()/1000)-901,access=jwt.sign({...f.claims,iat:issuedAt,exp:issuedAt+900},portalSecret,{algorithm:'HS256'});
   verifyReader(f,currentInput(f,{expected:{...f.expected,issuedAt},candidates:[f.candidates[0],access,f.login.refreshToken,f.login.csrfToken]}),true);
  });
  const inputs:Array<{name:string;input:()=>ReturnType<typeof currentInput>}>= [
   {name:'missing access candidate',input:()=>currentInput(f,{candidates:[f.candidates[0],f.login.refreshToken,f.login.csrfToken]})},
   {name:'ambiguous duplicated signed access candidate',input:()=>currentInput(f,{candidates:[...f.candidates,f.login.accessToken]})},
   {name:'signed access for another session SID',input:()=>currentInput(f,{candidates:[f.candidates[0],jwt.sign({...f.claims,sid:randomUUID()},portalSecret,{algorithm:'HS256'}),f.login.refreshToken,f.login.csrfToken]})},
   {name:'JWT signed by a different independent key',input:()=>currentInput(f,{candidates:[f.candidates[0],jwt.sign({...f.claims},portalSecret+'-different',{algorithm:'HS256'}),f.login.refreshToken,f.login.csrfToken]})},
   {name:'JWT audience mismatch',input:()=>currentInput(f,{candidates:[f.candidates[0],jwt.sign({...f.claims,aud:'different-audience'},portalSecret,{algorithm:'HS256'}),f.login.refreshToken,f.login.csrfToken]})},
   {name:'trusted original issued-at mismatch',input:()=>currentInput(f,{expected:{...f.expected,issuedAt:f.expected.issuedAt+1}})},
   {name:'JWT credential epoch differs from actual current database epoch',input:()=>currentInput(f,{candidates:[f.candidates[0],jwt.sign({...f.claims,credential_epoch:2},portalSecret,{algorithm:'HS256'}),f.login.refreshToken,f.login.csrfToken]})},
   {name:'missing original login audit request identity',input:()=>currentInput(f,{expected:{...f.expected,loginRequestId:randomUUID()}})},
   {name:'missing refresh candidate',input:()=>currentInput(f,{candidates:[f.candidates[0],f.login.accessToken,f.login.csrfToken]})},
   {name:'refresh secret with a foreign SID prefix',input:()=>currentInput(f,{candidates:[f.candidates[0],f.login.accessToken,`${randomUUID()}.${f.login.refreshToken.split('.')[1]}`,f.login.csrfToken]})},
   {name:'refresh secret hash mismatch',input:()=>currentInput(f,{candidates:[f.candidates[0],f.login.accessToken,`${f.claims.sid}.${'z'.repeat(64)}`,f.login.csrfToken]})},
   {name:'ambiguous duplicated refresh candidate',input:()=>currentInput(f,{candidates:[...f.candidates,f.login.refreshToken]})},
   {name:'missing CSRF candidate',input:()=>currentInput(f,{candidates:[f.candidates[0],f.login.accessToken,f.login.refreshToken]})},
   {name:'CSRF hash mismatch',input:()=>currentInput(f,{candidates:[f.candidates[0],f.login.accessToken,f.login.refreshToken,'y'.repeat(43)]})},
   {name:'ambiguous duplicated CSRF candidate',input:()=>currentInput(f,{candidates:[...f.candidates,f.login.csrfToken]})},
   {name:'selected tenant differs from the signed original JWT',input:()=>currentInput(f,{expected:{...f.expected,workspaceId:randomUUID()}})}
  ];
  for(const item of inputs)await check(`${item.name}: actual reader fails closed without secret output`,async()=>{rejectedReader(item.input());});
  await check('revoked original database session is denied by the actual reader',async()=>{
   const revoked=await fixture();await runtime!.exec('UPDATE portal_sessions SET revoked_at=now(),updated_at=now() WHERE id=$1',[revoked.claims.sid]);rejectedReader(currentInput(revoked));
  });
  await check('expired database session is denied even when all signed cookie candidates remain exact',async()=>{
   const expired=await fixture();await runtime!.exec("UPDATE portal_sessions SET expires_at=created_at+interval '1 millisecond',updated_at=now() WHERE id=$1",[expired.claims.sid]);rejectedReader(currentInput(expired));
  });
  await check('unpublished tenant is denied rather than recovering a session for private portal metadata',async()=>{
   const unpublished=await fixture();await runtime!.exec('UPDATE portal_settings SET published=false,revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND workspace_id=$2',[unpublished.cid,unpublished.wid]);rejectedReader(currentInput(unpublished));
  });
  await check('disabled workspace is denied by the actual exported current-session query',async()=>{
   const disabled=await fixture();await runtime!.exec("UPDATE workspaces SET status='disabled',revision=revision+1,updated_at=now() WHERE id=$1",[disabled.wid]);rejectedReader(currentInput(disabled));
  });
  await check('developer epoch advancement and session revocation commit atomically and old browser material fails closed',async()=>{
   const advanced=await fixture();await runtime!.transaction(async tx=>{await tx.exec('UPDATE portal_sessions SET revoked_at=now(),updated_at=now() WHERE developer_id=$1',[advanced.developerId]);await tx.exec('UPDATE portal_developers SET credential_epoch=credential_epoch+1,revision=revision+1,updated_at=now() WHERE id=$1',[advanced.developerId]);});rejectedReader(currentInput(advanced));
  });
  await check('readonly query and reader executions leave original valid login/session hashes and migration history unchanged',async()=>{
   const rows=await runtime!.query<any>(query,f.params);assert.equal(rows.length,1);assert.equal(rows[0].original_login_audited,true);assert.equal(rows[0].refresh_token_hash,hash(f.login.refreshToken.split('.')[1]));assert.equal(rows[0].csrf_token_hash,hash(f.login.csrfToken));
   assert.equal((await runtime!.one<any>('SELECT count(*)::int AS n FROM schema_migrations')).n,10);assert.equal(hash(readFileSync(sourcePath,'utf8')),sourceHash);
   assert.equal((await runtime!.one<any>("SELECT has_table_privilege(current_user,'audit_events','UPDATE') AS allowed")).allowed,false);
  });
 }catch(error){failureCode=safeCode(error);throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/portal-browser-session-reader-postgres-${runId}.json`;
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,database:'disposable PostgreSQL16; unchanged migrations000-009; actual non-owner runtime role',serverVersion,migrations,sourcePath,sourceHash,queryExport:'BROWSER_COOKIE_SESSION_SQL',queryHash,programExport:'BROWSER_COOKIE_READER_PROGRAM',programHash,roleEvidence,readerRuns,readerRejections,runtimeLogins,fixtureRedisCalls,nativeRequests:0,businessHttpRequests:0,browserActions:0,privateReferenceReads:0,coverage:['actual exported SQL and expanded actual exported program; no reimplemented reader','actual PortalAuthService.login/AuditService under same runtime role produce synthetic current sessions and cookies','signed synthetic HS256 JWT/current SID/current credential epoch/original audit/refresh and CSRF hash validation','legacy exact expressions reproduce42883 and42703 without schema changes','successful and fail-closed subprocess output checked in memory; artifacts never serialize tokens or query rows'],fixtures:['owner migration and synthetic tenant/developer seeding only; runtime role performs actual login and all query/program checks','Redis rate limiter for login is an explicit allowed-only fixture','expired synthetic JWT uses an earlier signed iat against the current valid fixture session; no clock or session history is rewritten','no browser, HTTP, application deployment, current environment or Kong endpoint is used'],checks,passed:checks.filter(c=>c.passed).length,total:checks.length},null,2));
  await runtime?.onModuleDestroy();await owner?.onModuleDestroy();try{docker(['rm','-f',container]);}catch{}
  process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(c=>c.passed).length,total:checks.length,nativeRequests:0,businessHttpRequests:0})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated browser session reader proof failed; safe artifact retained.\n');process.exitCode=1;});
