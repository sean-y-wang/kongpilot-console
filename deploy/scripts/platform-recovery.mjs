#!/usr/bin/env node
/** Platform-only recovery. No Kong transport, Kong storage, tar extraction, or shell interpolation. */
import { spawnSync } from 'node:child_process';
import { createHash, createHmac, randomBytes, randomUUID, createCipheriv, createDecipheriv } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';

const FORMAT='kongpilot-platform-backup-v1', MAGIC=Buffer.from('KPBK0001'), MAX=256*1024*1024;
const SHA=/^[a-f0-9]{64}$/, ID=/^[a-f0-9]{64}$/, NAME=/^[a-z][a-z0-9_-]{2,47}$/, UUID=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const fail=code=>{throw new Error(code);};
const hash=b=>createHash('sha256').update(b).digest('hex');
export const canonical=value=>value===null||typeof value!=='object'?JSON.stringify(value):Array.isArray(value)?`[${value.map(canonical).join(',')}]`:`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
const equal=(a,b)=>canonical(a)===canonical(b);
function exact(v,keys,code){if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||Object.keys(v).some(k=>!keys.includes(k)))fail(code);}
function safeName(v){if(typeof v!=='string'||!NAME.test(v))fail('RECOVERY_NAME_INVALID');return v;}
/** Every existing path component is checked; never follow a user-selected symlink. */
export function securePath(raw,{mustExist=true,directory=false,privateFile=false}={}){
 if(typeof raw!=='string'||!isAbsolute(raw)||raw.includes('\0')||raw.includes('\\')||raw.split('/').some(p=>p==='.'||p==='..'))fail('RECOVERY_PATH_INVALID');
 const path=resolve(raw),root=parse(path).root;let current=root;
 for(const part of path.slice(root.length).split(sep).filter(Boolean)){current=join(current,part);let found;try{found=lstatSync(current);}catch(error){if(error.code!=='ENOENT')throw error;}if(!found){if(current!==path||mustExist)fail('RECOVERY_PATH_MISSING');break;}const s=found;if(s.isSymbolicLink())fail('RECOVERY_SYMLINK_FORBIDDEN');if(current!==path&&!s.isDirectory())fail('RECOVERY_PATH_COMPONENT_INVALID');}
 if(existsSync(path)){const s=lstatSync(path);if(directory?!s.isDirectory():!s.isFile())fail('RECOVERY_PATH_TYPE_INVALID');if(privateFile&&((s.mode&0o777)!==0o600||s.uid!==process.getuid()))fail('RECOVERY_PRIVATE_FILE_0600_REQUIRED');}
 return path;
}
function privateJson(path){const p=securePath(path,{privateFile:true}),s=lstatSync(p);if(s.size>65536)fail('RECOVERY_CONFIG_SIZE');try{return JSON.parse(readFileSync(p,'utf8'));}catch{fail('RECOVERY_CONFIG_INVALID');}}
function privateDirectory(path){const p=securePath(path,{mustExist:false,directory:true});if(existsSync(p))fail('RECOVERY_NEW_DIRECTORY_REQUIRED');const parent=lstatSync(dirname(p));if(parent.uid!==process.getuid()||(parent.mode&0o022))fail('RECOVERY_PRIVATE_PARENT_REQUIRED');mkdirSync(p,{mode:0o700});return p;}
function writePrivate(path,bytes){const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}const parent=openSync(dirname(path),'r');try{fsyncSync(parent);}finally{closeSync(parent);}}
const json=(path,value)=>writePrivate(path,JSON.stringify(value,null,2)+'\n');
function keyBytes(v){if(typeof v!=='string'||!SHA.test(v))fail('RECOVERY_KEY_HEX_32_REQUIRED');return Buffer.from(v,'hex');}
export function validateSecrets(v){exact(v,['CONSOLE_ENCRYPTION_KEY','APP_SECRET','PORTAL_SECRET','BACKUP_ENCRYPTION_KEY'],'RECOVERY_SECRETS_FIELDS');keyBytes(v.CONSOLE_ENCRYPTION_KEY);keyBytes(v.BACKUP_ENCRYPTION_KEY);if([v.APP_SECRET,v.PORTAL_SECRET].some(x=>typeof x!=='string'||x.length<32||x.length>1024||/[\x00-\x1f\x7f]/.test(x))||new Set(Object.values(v)).size!==4)fail('RECOVERY_INDEPENDENT_KEYS_REQUIRED');return v;}
function keyRefs(v){exact(v,['encryption','app','portal','backup'],'RECOVERY_KEY_REFERENCES_REQUIRED');for(const x of Object.values(v))if(typeof x!=='string'||!/^(?:vault|kms|secret-manager|file):[A-Za-z0-9/_:.@-]{3,220}$/.test(x)||x.includes('://'))fail('RECOVERY_KEY_REFERENCE_INVALID');return v;}
export function validateSource(v){exact(v,['format','siteId','project','database','keyReferences'],'RECOVERY_SOURCE_FIELDS');if(v.format!=='kongpilot-platform-site-v1'||!UUID.test(v.siteId))fail('RECOVERY_SOURCE_IDENTITY_REQUIRED');safeName(v.project);exact(v.database,['user','name'],'RECOVERY_DATABASE_FIELDS');safeName(v.database.user);safeName(v.database.name);keyRefs(v.keyReferences);return v;}
export function validateTarget(v,source){exact(v,['format','siteId','project'],'RECOVERY_TARGET_FIELDS');if(v.format!=='kongpilot-platform-restore-v1'||!UUID.test(v.siteId)||v.siteId===source.siteId)fail('RESTORE_NEW_SITE_REQUIRED');safeName(v.project);if(v.project===source.project)fail('RESTORE_SOURCE_PROJECT_FORBIDDEN');return v;}
function signatures(secrets){return Object.fromEntries(['CONSOLE_ENCRYPTION_KEY','APP_SECRET','PORTAL_SECRET'].map(k=>[k,createHmac('sha256',keyBytes(secrets.BACKUP_ENCRYPTION_KEY)).update(`kongpilot-platform-key-reference:v1:${k}:`).update(secrets[k]).digest('hex')]));}
export function encryptDump(dump,identity,key){if(!Buffer.isBuffer(dump)||dump.length>MAX||dump.subarray(0,5).toString()!=='PGDMP')fail('BACKUP_POSTGRES_CUSTOM_DUMP_REQUIRED');const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',keyBytes(key),iv);cipher.setAAD(Buffer.from(canonical(identity)));return Buffer.concat([MAGIC,iv,cipher.update(dump),cipher.final(),cipher.getAuthTag()]);}
export function decryptDump(archive,identity,key){if(archive.length>MAX+64||archive.length<41||!archive.subarray(0,8).equals(MAGIC))fail('RESTORE_ARCHIVE_INVALID');try{const decipher=createDecipheriv('aes-256-gcm',keyBytes(key),archive.subarray(8,20));decipher.setAAD(Buffer.from(canonical(identity)));decipher.setAuthTag(archive.subarray(-16));const dump=Buffer.concat([decipher.update(archive.subarray(20,-16)),decipher.final()]);if(dump.length>MAX||dump.subarray(0,5).toString()!=='PGDMP')fail('RESTORE_DUMP_INVALID');return dump;}catch{fail('RESTORE_AUTHENTICATION_FAILED');}}

export function dockerExecutor(args,{input,maxBuffer=MAX+64,timeout=180000}={}){
 // Never inherit DOCKER_HOST/CONTEXT/TLS variables. The current local daemon is explicit.
 const env={PATH:process.env.PATH,HOME:process.env.HOME,LANG:'C.UTF-8'};
 const result=spawnSync('docker',['--host=unix:///var/run/docker.sock',...args],{env,input,encoding:null,maxBuffer,timeout,stdio:['pipe','pipe','pipe']});
 if(result.error||result.status!==0)fail('RECOVERY_PRIVATE_DOCKER_COMMAND_FAILED');return result.stdout;
}
function readJsonCommand(exec,args){try{return JSON.parse(exec(args,{maxBuffer:8*1024*1024}).toString());}catch{fail('RECOVERY_DOCKER_FACTS_INVALID');}}
function selector(project,service,running=false){return ['ps',...(running?[]:['-a']),'-q','--no-trunc','--filter',`label=com.docker.compose.project=${project}`,...(service?['--filter',`label=com.docker.compose.service=${service}`]:[])];}
function ids(exec,args){const raw=exec(args,{maxBuffer:65536}).toString().trim();if(!raw)return[];const values=raw.split(/\r?\n/);if(values.some(x=>!ID.test(x))||new Set(values).size!==values.length)fail('RECOVERY_CONTAINER_IDS_INVALID');return values;}
function inspect(exec,id,project,service,{running=true}={}){const list=readJsonCommand(exec,['inspect',id]);if(!Array.isArray(list)||list.length!==1)fail('RECOVERY_CONTAINER_FACTS_INVALID');const c=list[0];if(c.Id!==id||c.Config?.Labels?.['com.docker.compose.project']!==project||c.Config?.Labels?.['com.docker.compose.service']!==service||(running&&c.State?.Status!=='running')||!SHA.test(c.Image?.replace(/^sha256:/,'')))fail('RECOVERY_EXACT_PLATFORM_CONTAINER_REQUIRED');return c;}
function one(exec,project,service){const list=ids(exec,selector(project,service));if(list.length!==1)fail('RECOVERY_SINGLE_PLATFORM_STORAGE_REQUIRED');return inspect(exec,list[0],project,service);}
const sql=(exec,db,source,text,timeout)=>{try{return JSON.parse(exec(['exec','-i',db,'psql','--no-psqlrc','--quiet','--set=ON_ERROR_STOP=1','-U',source.database.user,'-d',source.database.name,'-At'],{input:Buffer.from(text),maxBuffer:32*1024*1024,...(timeout===undefined?{}:{timeout})}).toString());}catch{fail('RECOVERY_PRIVATE_SQL_CHECK_FAILED');}};
export const CHECKPOINT_SQL=`BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT json_build_object('migrations',(SELECT coalesce(json_agg(m ORDER BY name),'[]') FROM (SELECT name,checksum FROM schema_migrations) m),
'auditCount',(SELECT count(*)::text FROM audit_events),'auditHeads',(SELECT coalesce(json_agg(h ORDER BY chain_scope),'[]') FROM (SELECT chain_scope,last_sequence::text,last_hash FROM audit_chain_heads) h),
'credentialReferenceCount',(SELECT count(*)::text FROM credential_refs),'otherClients',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'));
COMMIT;`;
/** Bounded read-only observation, never a client filter or backend terminator.
 * The accepted checkpoint is exactly the original query with every other
 * database client absent; persistent clients still stop the backup. */
export async function waitForStoppedDatabaseClients(exec,db,source){
 const deadline=performance.now()+5000;
 for(let attempt=0;attempt<20;attempt++){
  const remaining=deadline-performance.now();if(remaining<=0)fail('BACKUP_OTHER_DATABASE_CLIENTS_PRESENT');
  const checkpoint=sql(exec,db,source,CHECKPOINT_SQL,Math.max(1,Math.ceil(remaining)));
  if(!Number.isSafeInteger(checkpoint.otherClients)||checkpoint.otherClients<0)fail('RECOVERY_PRIVATE_SQL_CHECK_FAILED');
  if(performance.now()>=deadline)fail('BACKUP_OTHER_DATABASE_CLIENTS_PRESENT');
  if(checkpoint.otherClients===0)return checkpoint;
  const delayMs=Math.min(250,deadline-performance.now());if(attempt===19||delayMs<=0)fail('BACKUP_OTHER_DATABASE_CLIENTS_PRESENT');
  await delay(delayMs);
 }
 fail('BACKUP_OTHER_DATABASE_CLIENTS_PRESENT');
}
function sourceTree(root){const entries=[];let bytes=0;const visit=(path,relative)=>{const s=lstatSync(path);if(s.isSymbolicLink())fail('RECOVERY_SOURCE_SYMLINK_FORBIDDEN');if(s.isDirectory()){for(const name of readdirSync(path).sort())visit(join(path,name),`${relative}/${name}`);}else if(s.isFile()){if(entries.length>=20000||(bytes+=s.size)>256*1024*1024)fail('RECOVERY_SOURCE_INVENTORY_BUDGET');entries.push({path:relative,bytes:s.size,sha256:hash(readFileSync(path))});}else fail('RECOVERY_SOURCE_FILE_TYPE_INVALID');};for(const family of ['apps','packages']){const dir=join(root,family);if(!existsSync(dir))continue;for(const name of readdirSync(dir).sort()){const project=join(dir,name);if(!lstatSync(project).isDirectory()||lstatSync(project).isSymbolicLink())fail('RECOVERY_SOURCE_PROJECT_INVALID');for(const path of ['src','public','package.json','Dockerfile'])if(existsSync(join(project,path)))visit(join(project,path),`${family}/${name}/${path}`);}}return {sourceInputCount:entries.length,sourceTreeSha256:hash(canonical(entries))};}
function repositoryFacts(repository){const root=securePath(repository,{directory:true}),pkg=JSON.parse(readFileSync(securePath(join(root,'package.json')),'utf8')),lock=securePath(join(root,'package-lock.json')),directory=securePath(join(root,'apps/console-api/src/infrastructure/migrations'),{directory:true});const files=readdirSync(directory).filter(x=>/^\d{3}_[a-z0-9_]+\.sql$/.test(x)).sort();if(!files.length)fail('BACKUP_MIGRATIONS_REQUIRED');return {packageName:pkg.name,packageVersion:pkg.version,packageLockSha256:hash(readFileSync(lock)),...sourceTree(root),migrations:files.map(name=>({name,checksum:hash(readFileSync(securePath(join(directory,name))))}))};}
function canary(secrets,backupId){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',keyBytes(secrets.CONSOLE_ENCRYPTION_KEY),iv);cipher.setAAD(Buffer.from(`kongpilot-platform-canary:v1:${backupId}`));return Buffer.concat([iv,cipher.update(Buffer.from(backupId)),cipher.final(),cipher.getAuthTag()]).toString('base64');}
function checkCanary(secrets,identity){try{const b=Buffer.from(identity.consoleEncryptionCanary,'base64'),d=createDecipheriv('aes-256-gcm',keyBytes(secrets.CONSOLE_ENCRYPTION_KEY),b.subarray(0,12));d.setAAD(Buffer.from(`kongpilot-platform-canary:v1:${identity.backupId}`));d.setAuthTag(b.subarray(-16));if(Buffer.concat([d.update(b.subarray(12,-16)),d.final()]).toString()!==identity.backupId)fail('X');}catch{fail('RESTORE_CONSOLE_ENCRYPTION_KEY_MISMATCH');}}
export async function backupPlatform({config,secretsFile,output,repository,exec=dockerExecutor,now=()=>new Date().toISOString()}){
 const source=validateSource(privateJson(config)),secrets=validateSecrets(privateJson(secretsFile)),release=repositoryFacts(repository),dir=privateDirectory(output),startedAt=now();let writers=[],stopAttempted=false;
 try{
  const db=one(exec,source.project,'console-db'),redis=one(exec,source.project,'redis');
  if(ids(exec,selector(source.project,'console-migrations',true)).length)fail('BACKUP_RUNNING_MIGRATOR_FORBIDDEN');
  writers=ids(exec,selector(source.project,'console-api',true));if(!writers.length)fail('BACKUP_RUNNING_API_REQUIRED');for(const id of writers)inspect(exec,id,source.project,'console-api');
  stopAttempted=true;exec(['stop','--time=60',...writers]);
  for(const id of writers){const c=inspect(exec,id,source.project,'console-api',{running:false});if(c.State.Status!=='exited')fail('BACKUP_API_NOT_QUIESCED');}
  const before=await waitForStoppedDatabaseClients(exec,db.Id,source);
  if(!equal(before.migrations,release.migrations))fail('BACKUP_RELEASE_MIGRATIONS_MISMATCH');
  const dump=exec(['exec',db.Id,'pg_dump','-U',source.database.user,'-d',source.database.name,'--format=custom','--no-owner','--no-acl'],{maxBuffer:MAX,timeout:600000});
  const after=sql(exec,db.Id,source,CHECKPOINT_SQL);if(!equal(release,repositoryFacts(repository)))fail('BACKUP_RELEASE_CHANGED_WHILE_QUIESCED');if(!equal(before,after))fail('BACKUP_DATABASE_CHANGED_WHILE_QUIESCED');
  const backupId=randomUUID(),identity={format:FORMAT,backupId,startedAt,completedAt:now(),source,release,checkpoint:before,images:{postgres:db.Image,redis:redis.Image},apiImageIds:[...new Set(writers.map(id=>inspect(exec,id,source.project,'console-api',{running:false}).Image))].sort(),sourceStorageContainerIds:[db.Id,redis.Id],redisPolicy:'fresh-empty-do-not-replay-leases-or-oidc-state',keySignatures:signatures(secrets),consoleEncryptionCanary:canary(secrets,backupId),maxCustomDumpBytes:MAX,dumpSha256:hash(dump),dumpBytes:dump.length};
  const archive=encryptDump(dump,identity,secrets.BACKUP_ENCRYPTION_KEY);dump.fill(0);writePrivate(join(dir,'console-postgres.kpgcm'),archive);
  const manifest={identity,archive:{file:'console-postgres.kpgcm',bytes:archive.length,sha256:hash(archive),algorithm:'AES-256-GCM'}};json(join(dir,'manifest.json'),manifest);
  return {completed:true,backupId,platformOnly:true,kongContacted:false,kongContactScope:'tool-direct-actions-only',writerCount:writers.length,archiveBytes:archive.length,redisRestored:false,productionRecoveryVerified:false};
 }finally{if(stopAttempted&&writers.length)exec(['start',...writers]);for(const k of Object.keys(secrets))secrets[k]='';}
}

/** Audit verifier copies the exact nineteen-field canonical hash contract. It does not rewrite history. */
export function verifyAudit(rows,heads){const current=new Map();for(const row of rows){if(!row||typeof row.chain_scope!=='string'||!/^\d+$/.test(String(row.sequence)))fail('RESTORE_AUDIT_ROW_INVALID');const prior=current.get(row.chain_scope)??{sequence:0n,hash:'GENESIS'};if(BigInt(row.sequence)!==prior.sequence+1n||row.prev_hash!==prior.hash)fail('RESTORE_AUDIT_CHAIN_INVALID');const {event_hash,...record}=row;if(hash(canonical(record))!==event_hash)fail('RESTORE_AUDIT_HASH_INVALID');current.set(row.chain_scope,{sequence:BigInt(row.sequence),hash:event_hash});}if(current.size!==heads.filter(h=>BigInt(h.last_sequence)>0n).length)fail('RESTORE_AUDIT_HEAD_COUNT_INVALID');for(const h of heads){const last=current.get(h.chain_scope)??{sequence:0n,hash:'GENESIS'};if(last.sequence!==BigInt(h.last_sequence)||last.hash!==h.last_hash)fail('RESTORE_AUDIT_HEAD_INVALID');}return{rows:rows.length,chains:heads.length};}
const AUDIT_SQL=`BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT json_build_object('rows',(SELECT coalesce(json_agg(r ORDER BY chain_scope,sequence::bigint),'[]') FROM (SELECT id,chain_scope,sequence::text,actor_id,actor_type,source_ip,cluster_id,workspace_id,entity_type,entity_id,action,before,after,json_patch,workflow_id,result,request_id,prev_hash,to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at,event_hash FROM audit_events) r),'heads',(SELECT coalesce(json_agg(h ORDER BY chain_scope),'[]') FROM (SELECT chain_scope,last_sequence::text,last_hash FROM audit_chain_heads) h)); COMMIT;`;
export function verifyCiphertextSamples(rows,key){if(!Array.isArray(rows)||rows.length>300)fail('RESTORE_CIPHERTEXT_SAMPLE_BUDGET');for(const row of rows){try{if(typeof row.context!=='string'||row.context.length>256||typeof row.ciphertext!=='string')fail('X');const parts=row.ciphertext.split('.');if(parts.length!==4||parts[0]!=='v1'||parts.slice(1).some(x=>!/^[A-Za-z0-9_-]+$/.test(x)))fail('X');const iv=Buffer.from(parts[1],'base64url'),tag=Buffer.from(parts[2],'base64url');if(iv.length!==12||tag.length!==16)fail('X');const d=createDecipheriv('aes-256-gcm',keyBytes(key),iv);d.setAAD(Buffer.from(`kongos-secret:v1:${row.context}`));d.setAuthTag(tag);JSON.parse(Buffer.concat([d.update(Buffer.from(parts[3],'base64url')),d.final()]).toString('utf8'));}catch{fail('RESTORE_APPLICATION_CIPHERTEXT_INVALID');}}return {checked:rows.length,passed:true,fullCoverage:false};}
const CIPHERTEXT_SQL=`BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT json_build_object('ciphertextSamples',(SELECT coalesce(json_agg(v),'[]') FROM (SELECT 'cluster:'||id AS context,connection_secret AS ciphertext FROM clusters WHERE connection_secret IS NOT NULL ORDER BY id LIMIT 100) v),'mutationSamples',(SELECT coalesce(json_agg(v),'[]') FROM (SELECT 'mutation:'||id||':before' AS context,before_secret AS ciphertext FROM mutation_operations WHERE before_secret IS NOT NULL ORDER BY id LIMIT 100) v),'recycleSamples',(SELECT coalesce(json_agg(v),'[]') FROM (SELECT 'recycle:'||id AS context,payload_secret AS ciphertext FROM recycle_entries WHERE payload_secret IS NOT NULL ORDER BY id LIMIT 100) v)); COMMIT;`;
const SESSION_SQL=`BEGIN; UPDATE auth_sessions SET revoked_at=greatest(now(),created_at) WHERE revoked_at IS NULL; UPDATE portal_sessions SET revoked_at=greatest(now(),created_at) WHERE revoked_at IS NULL; SELECT json_build_object('consoleActive',(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL),'portalActive',(SELECT count(*) FROM portal_sessions WHERE revoked_at IS NULL)); COMMIT;`;
function absentResource(exec,kind,name){const list=exec([kind,'ls',...(kind==='volume'?['-q']:['--format={{.Name}}'])],{maxBuffer:1024*1024}).toString().trim().split(/\r?\n/);if(list.includes(name))fail('RESTORE_EXISTING_RESOURCE_FORBIDDEN');}
function create(exec,kind,name,args,labels){return exec([kind,'create',...labels,...args,name]).toString().trim();}
function ownedResource(exec,kind,name,target,attemptId,networkId,allowedContainers=[]){const rows=readJsonCommand(exec,[kind,'inspect',name]);if(!Array.isArray(rows)||rows.length!==1)fail('RESTORE_OWNED_RESOURCE_REQUIRED');const r=rows[0],labels=r.Labels??{};if(r.Name!==name||labels['com.docker.compose.project']!==target.project||labels['com.kongpilot.restore.site']!==target.siteId||labels['com.kongpilot.restore.attempt']!==attemptId||r.Options&&Object.keys(r.Options).length)fail('RESTORE_OWNED_RESOURCE_REQUIRED');if(kind==='volume'){if(r.Driver!=='local'||r.Scope!=='local')fail('RESTORE_PLAIN_LOCAL_VOLUME_REQUIRED');}else if(r.Id!==networkId||r.Driver!=='bridge'||r.Internal!==true||Object.keys(r.Containers??{}).some(id=>!allowedContainers.includes(id)))fail('RESTORE_ISOLATED_NETWORK_REQUIRED');}
function ownedResources(exec,network,volumes,target,attemptId,networkId,allowedContainers=[]){ownedResource(exec,'network',network,target,attemptId,networkId,allowedContainers);for(const name of volumes)ownedResource(exec,'volume',name,target,attemptId,networkId);}

export const RESTORE_POSTGRES_IDENTITY_SQL="BEGIN READ ONLY; SELECT json_build_object('database',current_database(),'user',current_user,'ready',true); COMMIT;";
/** The official entrypoint's temporary initialization postmaster listens only
 * on its Unix socket. TCP must be ready before the real target database is
 * opened. The SQL identity probe remains socket-local so no password enters
 * argv or logs. Both probes share one original monotonic deadline. */
export async function waitPostgres(exec,id,source){
 const deadline=performance.now()+15000;
 for(let n=0;n<60;n++){
  const remaining=deadline-performance.now();if(remaining<=0)fail('RESTORE_DATABASE_NOT_READY');
  try{
   exec(['exec',id,'pg_isready','--host=127.0.0.1','--timeout=1','-U',source.database.user,'-d',source.database.name],{timeout:Math.max(1,Math.min(1000,Math.ceil(remaining)))});
   const sqlRemaining=deadline-performance.now();if(sqlRemaining<=0)fail('RESTORE_DATABASE_NOT_READY');
   const identity=sql(exec,id,source,RESTORE_POSTGRES_IDENTITY_SQL,Math.max(1,Math.min(1000,Math.ceil(sqlRemaining))));
   if(performance.now()>=deadline)fail('RESTORE_DATABASE_NOT_READY');
   if(identity?.database!==source.database.name||identity?.user!==source.database.user||identity?.ready!==true)fail('RESTORE_DATABASE_IDENTITY_MISMATCH');
   return;
  }catch(error){
   if(error?.message==='RESTORE_DATABASE_IDENTITY_MISMATCH')throw error;
   const wait=Math.min(250,deadline-performance.now());if(n===59||wait<=0)fail('RESTORE_DATABASE_NOT_READY');
   await delay(wait);
  }
 }
 fail('RESTORE_DATABASE_NOT_READY');
}
export async function restorePlatform({backup,secretsFile,targetConfig,output,repository,exec=dockerExecutor,now=()=>new Date().toISOString()}){
 const dir=securePath(backup,{directory:true}),manifest=privateJson(join(dir,'manifest.json')),secrets=validateSecrets(privateJson(secretsFile));exact(manifest,['identity','archive'],'RESTORE_MANIFEST_FIELDS');const identity=manifest.identity;
 if(identity?.format!==FORMAT||!UUID.test(identity.backupId))fail('RESTORE_MANIFEST_FORMAT');validateSource(identity.source);const target=validateTarget(privateJson(targetConfig),identity.source);
 if(!equal(identity.release,repositoryFacts(repository)))fail('RESTORE_FROZEN_RELEASE_REQUIRED');if(!equal(identity.keySignatures,signatures(secrets)))fail('RESTORE_KEY_REFERENCES_MISMATCH');checkCanary(secrets,identity);
 exact(manifest.archive,['file','bytes','sha256','algorithm'],'RESTORE_ARCHIVE_FIELDS');if(manifest.archive.file!=='console-postgres.kpgcm'||manifest.archive.algorithm!=='AES-256-GCM'||!SHA.test(manifest.archive.sha256)||manifest.archive.bytes>MAX+64)fail('RESTORE_ARCHIVE_DESCRIPTOR_INVALID');
 const archivePath=securePath(join(dir,manifest.archive.file),{privateFile:true});if(lstatSync(archivePath).size!==manifest.archive.bytes)fail('RESTORE_ARCHIVE_SIZE_MISMATCH');const archive=readFileSync(archivePath);if(hash(archive)!==manifest.archive.sha256)fail('RESTORE_ARCHIVE_DIGEST_MISMATCH');
 const dump=decryptDump(archive,identity,secrets.BACKUP_ENCRYPTION_KEY);if(dump.length!==identity.dumpBytes||hash(dump)!==identity.dumpSha256)fail('RESTORE_DUMP_DIGEST_MISMATCH');
 for(const image of Object.values(identity.images??{}))if(typeof image!=='string'||!/^sha256:[a-f0-9]{64}$/.test(image))fail('RESTORE_PINNED_PLATFORM_IMAGES_REQUIRED');if(Object.keys(identity.images??{}).sort().join(',')!=='postgres,redis')fail('RESTORE_PLATFORM_IMAGE_SET_REQUIRED');
 for(const image of new Set(Object.values(identity.images))){const found=readJsonCommand(exec,['image','inspect',image]);if(!Array.isArray(found)||found.length!==1||found[0].Id!==image)fail('RESTORE_LOCAL_IMAGE_ID_REQUIRED');}
 const out=privateDirectory(output),network=`${target.project}_restore_storage`,pgVolume=`${target.project}_console_db_data`,redisVolume=`${target.project}_redis_data`,dbName=`${target.project}-console-db-1`,redisName=`${target.project}-redis-1`,startedAt=now();
 // Never delete, reuse, connect to, stop or overwrite an existing resource, even after a failed attempt.
 if(ids(exec,selector(target.project)).length)fail('RESTORE_EXISTING_PROJECT_FORBIDDEN');
 for(const kind of ['network','volume'])if(exec([kind,'ls','--filter',`label=com.docker.compose.project=${target.project}`,...(kind==='volume'?['-q']:['--format={{.Name}}'])],{maxBuffer:1024*1024}).toString().trim())fail('RESTORE_EXISTING_PROJECT_RESOURCES_FORBIDDEN');
 for(const [kind,name] of [['network',network],['volume',pgVolume],['volume',redisVolume]])absentResource(exec,kind,name);
 const attemptId=randomUUID(),labels=['--label',`com.kongpilot.restore.attempt=${attemptId}`,'--label',`com.kongpilot.restore.site=${target.siteId}`,'--label',`com.docker.compose.project=${target.project}`],password=randomBytes(32).toString('hex'),redisPassword=randomBytes(32).toString('hex');
 writePrivate(join(out,'postgres.env'),`POSTGRES_USER=${identity.source.database.user}\nPOSTGRES_DB=${identity.source.database.name}\nPOSTGRES_PASSWORD=${password}\n`);
 writePrivate(join(out,'redis.env'),`REDIS_PASSWORD=${redisPassword}\n`);
 // The original signing/encryption material stays in its existing external keystore; only references are recorded.
 json(join(out,'recovery-fence.json'),{format:'kongpilot-platform-recovery-fence-v1',attemptId,target,sourceSiteId:identity.source.siteId,backupId:identity.backupId,state:'isolated-storage-only',apiStarted:false,writesEnabled:false,workersEnabled:false,deliveryEnabled:false,originalSiteMayStillBeActive:true,keyReferences:identity.source.keyReferences});
 let dbId,redisId;
 try{
  const networkId=create(exec,'network',network,['--internal'],labels);if(!ID.test(networkId))fail('RESTORE_NEW_NETWORK_ID_REQUIRED');ownedResource(exec,'network',network,target,attemptId,networkId);create(exec,'volume',pgVolume,[],labels);ownedResource(exec,'volume',pgVolume,target,attemptId,networkId);create(exec,'volume',redisVolume,[],labels);ownedResources(exec,network,[pgVolume,redisVolume],target,attemptId,networkId);
  dbId=exec(['run','--pull=never','-d','--name',dbName,...labels,'--label','com.docker.compose.service=console-db','--network',network,'--network-alias','console-db','--mount',`type=volume,source=${pgVolume},target=/var/lib/postgresql/data`,'--env-file',join(out,'postgres.env'),identity.images.postgres],{maxBuffer:65536}).toString().trim();if(!ID.test(dbId)||identity.sourceStorageContainerIds.includes(dbId))fail('RESTORE_NEW_DATABASE_CONTAINER_REQUIRED');
  await waitPostgres(exec,dbId,identity.source);
  const empty=sql(exec,dbId,identity.source,"SELECT json_build_object('tables',(SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'));" );if(empty.tables!==0)fail('RESTORE_EMPTY_DATABASE_REQUIRED');
  exec(['exec','-i',dbId,'pg_restore','--exit-on-error','--single-transaction','--no-owner','--no-acl','-U',identity.source.database.user,'-d',identity.source.database.name],{input:dump,timeout:600000,maxBuffer:16*1024*1024});dump.fill(0);
  const checkpoint=sql(exec,dbId,identity.source,CHECKPOINT_SQL);if(!equal(checkpoint,identity.checkpoint))fail('RESTORE_CHECKPOINT_MISMATCH');
  const auditData=sql(exec,dbId,identity.source,AUDIT_SQL),audit=verifyAudit(auditData.rows,auditData.heads);
  const encrypted=sql(exec,dbId,identity.source,CIPHERTEXT_SQL),ciphertextSampleVerification=verifyCiphertextSamples([...encrypted.ciphertextSamples,...encrypted.mutationSamples,...encrypted.recycleSamples],secrets.CONSOLE_ENCRYPTION_KEY);
  const sessions=sql(exec,dbId,identity.source,SESSION_SQL);if(sessions.consoleActive!==0||sessions.portalActive!==0)fail('RESTORE_SESSIONS_NOT_REVOKED');
  ownedResources(exec,network,[pgVolume,redisVolume],target,attemptId,networkId,[dbId]);
  redisId=exec(['run','--pull=never','-d','--name',redisName,...labels,'--label','com.docker.compose.service=redis','--network',network,'--network-alias','redis','--mount',`type=volume,source=${redisVolume},target=/data`,'--env-file',join(out,'redis.env'),identity.images.redis,'/bin/sh','-ec','exec redis-server --appendonly yes --requirepass "$REDIS_PASSWORD"'],{maxBuffer:65536}).toString().trim();if(!ID.test(redisId)||identity.sourceStorageContainerIds.includes(redisId))fail('RESTORE_NEW_REDIS_CONTAINER_REQUIRED');
  let redisEmpty=false;for(let n=0;n<30;n++){try{const size=exec(['exec',redisId,'/bin/sh','-ec','REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli --raw DBSIZE'],{timeout:5000,maxBuffer:1024}).toString().trim();if(size!=='0')fail('RESTORE_REDIS_NOT_EMPTY');redisEmpty=true;break;}catch{await delay(250);}}
  if(!redisEmpty)fail('RESTORE_REDIS_EMPTY_CHECK_FAILED');
  // No API container is created: all HTTP mutations, schedules, observer timers and deliveries are physically absent.
  const result={completed:true,platformOnly:true,kongContacted:false,kongContactScope:'tool-direct-actions-only',backupId:identity.backupId,sourceSiteId:identity.source.siteId,targetSiteId:target.siteId,startedAt,completedAt:now(),audit,ciphertextSampleVerification,checkpointMatched:true,keyCanaryDecrypted:true,sessionActiveCounts:sessions,redisFreshAndEmpty:true,apiStarted:false,writesEnabled:false,workersEnabled:false,deliveryEnabled:false,runtimeRoleProvisioningPending:true,applicationCiphertextValidationPending:true,credentialProxyValidationPending:true,productionReady:false,resourceIds:{database:dbId,redis:redisId}};
  json(join(out,'restore-verification.json'),result);return result;
 }catch(error){json(join(out,'restore-failed.json'),{completed:false,code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:'RESTORE_PRIVATE_COMMAND_FAILED',startedAt,failedAt:now(),apiStarted:false,writesEnabled:false,workersEnabled:false,deliveryEnabled:false,resourcesRetainedForInspection:true});throw error;}finally{dump.fill(0);for(const k of Object.keys(secrets))secrets[k]='';}
}
export async function cli(argv){const command=argv[0],allowed=command==='backup'?['config','secrets-file','output','repository']:command==='restore'?['backup','secrets-file','target-config','output','repository']:[];if(!allowed.length)fail('RECOVERY_COMMAND_REQUIRED');const values={};for(const arg of argv.slice(1)){const m=/^--([a-z-]+)=(.+)$/.exec(arg);if(!m||!allowed.includes(m[1])||Object.hasOwn(values,m[1]))fail('RECOVERY_ARGUMENTS_INVALID');values[m[1]]=m[2];}if(Object.keys(values).length!==allowed.length)fail('RECOVERY_ARGUMENTS_REQUIRED');const common={secretsFile:values['secrets-file'],output:values.output,repository:values.repository};return command==='backup'?backupPlatform({...common,config:values.config}):restorePlatform({...common,backup:values.backup,targetConfig:values['target-config']});}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))cli(process.argv.slice(2)).then(result=>process.stdout.write(JSON.stringify(result)+'\n')).catch(error=>{process.stderr.write(JSON.stringify({completed:false,code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:'RECOVERY_PRIVATE_FAILURE'})+'\n');process.exitCode=1;});
