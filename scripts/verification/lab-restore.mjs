import{execFileSync}from'node:child_process';import{readFileSync,lstatSync,existsSync,writeFileSync}from'node:fs';
import{createDecipheriv,createHash}from'node:crypto';
const v=Object.fromEntries(process.argv.slice(2).map(a=>{const i=a.indexOf('=');if(i<0||!a.startsWith('--'))throw Error('RESTORE_ARGUMENTS');return[a.slice(2,i),a.slice(i+1)];}));
const{socket,tool,backup,project}=v;
if(process.env.KONGOS_RESTORE_EXCLUSIVE_READY!=='true'||!/^kongos-restore-[a-z\d-]+$/.test(project??'')||!/^kongos-ram-tool-[a-z\d-]+$/.test(tool??'')||!socket?.startsWith('unix:///dev/shm/kongos-production-ram-')||!backup?.startsWith('/opt/kongpilot-release/'))throw Error('RESTORE_EXPLICIT_THIRD_PROJECT_REQUIRED');
const report='artifacts/Production/root-production-third-project-restore-actual.json';if(existsSync(report))throw Error('RESTORE_REPORT_EXISTS');
const manifest=JSON.parse(readFileSync(backup+'/manifest.json')),archive=readFileSync(backup+'/recovery-point.kosgcm'),keyPath=backup+'/recovery-key.bin',ks=lstatSync(keyPath);
if(ks.isSymbolicLink()||!ks.isFile()||(ks.mode&511)!==384||ks.uid!==process.getuid()||createHash('sha256').update(archive).digest('hex')!==manifest.encryptedArchive.sha256||archive.subarray(0,8).toString()!=='KOSBAK01')throw Error('RESTORE_AUTHENTICATED_ORIGINAL_ARCHIVE_REQUIRED');
const key=readFileSync(keyPath),d=createDecipheriv('aes-256-gcm',key,archive.subarray(8,20));d.setAAD(Buffer.from('KOSBAK01'));d.setAuthTag(archive.subarray(-16));
let clear;try{clear=Buffer.concat([d.update(archive.subarray(20,-16)),d.final()]);}catch{throw Error('RESTORE_ARCHIVE_AUTHENTICATION_FAILED');}
if(clear.length>64*1024**2)throw Error('RESTORE_ARCHIVE_SIZE_LIMIT');
const execute=(args,extra={})=>{try{return execFileSync('docker',args,{stdio:['pipe','pipe','pipe'],timeout:180000,maxBuffer:32*1024**2,...extra});}catch{throw Error('RESTORE_PRIVATE_COMMAND_FAILED');}};
const docker=(args,extra={})=>execute([`--host=${socket}`,...args],extra);
const main=(args,extra={})=>execute(['--host=unix:///var/run/docker.sock','exec','-i','--workdir','/opt/kongpilot-console',tool,...args],extra);
const databaseResume=process.env.KONGOS_RESTORE_DATABASE_CONTINUATION==='true';
if(docker(['ps','-a','--filter',`label=com.docker.compose.project=${project}`,'-q']).toString().trim()&&!databaseResume)throw Error('RESTORE_NEW_PROJECT_REQUIRED');
const root=`/run/kongos-private/restore/${project}`,env=root+'/materials/.env',startedAt=new Date().toISOString();
if(databaseResume){
 const proof=JSON.parse(readFileSync('artifacts/Production/root-production-restore-known-empty-database-continuation.json'));
 if(!proof.allPassed||proof.project!==project||proof.backupSha256!==manifest.encryptedArchive.sha256||proof.onlyOwnedThreeStorageContainers!==true||!proof.emptyConsoleDatabase||!proof.emptyKongDatabase)throw Error('RESTORE_KNOWN_EMPTY_DATABASE_REQUIRED');
 const containers=JSON.parse(docker(['inspect',...['console-db','kong-db','redis'].map(s=>project+'-'+s+'-1')]));
 if(containers.some(c=>!proof.containerIds.includes(c.Id)||c.Config.Labels['com.docker.compose.project']!==project)||docker(['ps','-a','--filter','label=com.docker.compose.project='+project,'-q']).toString().trim().split('\n').length!==3)throw Error('RESTORE_EXACT_STORAGE_CONTAINERS_CHANGED');
 const hash=JSON.parse(main(['node','-e',"const fs=require('fs'),c=require('crypto');process.stdout.write(JSON.stringify({sha256:c.createHash('sha256').update(fs.readFileSync(process.argv[1])).digest('hex')}));",env]));
 if(hash.sha256!==proof.configuredEnvironmentSha256)throw Error('RESTORE_CONFIGURED_ENV_CHANGED');clear.fill(0);
}else if(process.env.KONGOS_RESTORE_PREPARED_CONTINUATION==='true'){
 const proof=JSON.parse(readFileSync('artifacts/Production/root-production-restore-original-materials-preparation-proof.json'));
 if(!proof.allPassed||proof.project!==project||proof.backupSha256!==manifest.encryptedArchive.sha256||proof.databaseContainersCreated!==0)throw Error('RESTORE_EXACT_PRE_DATABASE_CONTINUATION_REQUIRED');
 const check=JSON.parse(main(['node','-e',"const fs=require('fs'),c=require('crypto'),p=process.argv[1];const hash=n=>c.createHash('sha256').update(fs.readFileSync(p+'/'+n)).digest('hex');process.stdout.write(JSON.stringify({environment:hash('materials/.env'),console:hash('console.dump'),kong:hash('kong-primary.dump')}));",root]));
 if(check.environment!==proof.environmentSha256||check.console!==manifest.files.find(f=>f.file==='console.dump').sha256||check.kong!==manifest.files.find(f=>f.file==='kong-primary.dump').sha256)throw Error('RESTORE_PREPARED_ORIGINAL_BYTES_CHANGED');
 clear.fill(0);
}else{
 main(['node','-e',"const fs=require('fs');const p=process.argv[1];if(fs.existsSync(p))throw Error('RESTORE_PATH_EXISTS');fs.mkdirSync(p,{recursive:true,mode:448});",root]);
main(['tar','-xz','-C',root],{input:clear});clear.fill(0);
}
const configure=`const fs=require('fs');const root=process.argv[1],project=process.argv[2],p=root+'/materials/.env';let s=fs.readFileSync(p,'utf8');const replacements={COMPOSE_PROJECT_NAME:project,CONSOLE_HTTPS_PORT:'21443',PORTAL_HTTPS_PORT:'22443',KONG_PROXY_PORT:'28000',PUBLIC_ORIGINS:'https://localhost:21443,https://console.kongos.test:21443',PORTAL_PUBLIC_ORIGINS:'https://127.0.0.1:22443',KONGOS_CONSOLE_TLS_DIRECTORY:root+'/materials/tls/console',KONGOS_PORTAL_TLS_DIRECTORY:root+'/materials/tls/portal',KONGOS_METRICS_DIRECTORY:root+'/materials/metrics',KONGOS_DECK_CA_DIRECTORY:root+'/materials/trust'};s=s.split('\\n').map(l=>{const i=l.indexOf('=');if(i<0)return l;const k=l.slice(0,i);if(k in replacements)return k+'='+replacements[k];if(/SUBNET$|_IP$/.test(k))return k+'='+l.slice(i+1).replace(/172\\.30\\./g,'172.31.');return l;}).join('\\n');for(const[k,val]of Object.entries(replacements))if(!s.includes(k+'='))s+='\\n'+k+'='+val;fs.writeFileSync(p,s,{mode:384});fs.chmodSync(p,384);fs.chownSync(p,1000,1000);for(const name of ['console','portal']){const dir=root+'/materials/tls/'+name;fs.chownSync(dir,101,101);fs.chmodSync(dir,488);for(const entry of fs.readdirSync(dir)){const file=dir+'/'+entry;if(!fs.lstatSync(file).isFile())throw Error('RESTORE_TLS_FILE_REQUIRED');fs.chownSync(file,101,101);fs.chmodSync(file,entry.endsWith('.key')?288:292);}}for(const name of ['prometheus','collector']){const dir=root+'/materials/metrics/'+name;if(fs.existsSync(dir)){fs.chownSync(dir,1000,1000);fs.chmodSync(dir,448);for(const entry of fs.readdirSync(dir)){const file=dir+'/'+entry;if(!fs.lstatSync(file).isFile())throw Error('RESTORE_METRICS_FILE_REQUIRED');fs.chownSync(file,1000,1000);fs.chmodSync(file,256);}}}`;
if(!databaseResume)main(['node','-e',configure,root,project]);
const dc=['docker','--host=unix:///var/run/docker.sock','compose','--project-name',project,'--env-file',env,...['docker-compose.yml','deploy/compose/compose.production.yml','deploy/compose/compose.metrics.yml','deploy/compose/compose.production-metrics.yml'].flatMap(p=>['-f',p])];
const compose=args=>main([...dc,...args],{cwd:'/opt/kongpilot-console'});
// Only empty databases and Redis start first; no API or gateway writer.
compose(['up','-d','--no-build','--wait','--wait-timeout','120','console-db','kong-db','redis']);
if(!databaseResume)docker(['exec',`${project}-console-db-1`,'psql','-U','kongos','-d','kongos','-v','ON_ERROR_STOP=1','-c','CREATE ROLE kongos_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS']);
const restores=[];
for(const[service,user,db,file]of[['console-db','kongos','kongos','console.dump'],['kong-db','kong','kong','kong-primary.dump']]){
 const source=main(['node','-e',"process.stdout.write(require('fs').readFileSync(process.argv[1]));",`${root}/${file}`]);
 const expected=manifest.files.find(f=>f.file===file);if(createHash('sha256').update(source).digest('hex')!==expected.sha256)throw Error('RESTORE_ORIGINAL_DUMP_HASH_CHANGED');
 // Preserve every archived row and constraint. Resolve application functions
 // during COPY just as in normal runtime sessions; pg_restore's empty search
 // path otherwise makes unqualified PL/pgSQL helper calls fail their CHECKs.
 const sql=docker(['exec','-i',`${project}-${service}-1`,'pg_restore','--no-owner','--file=-'],{input:source});
 const prologue=Buffer.from("SELECT pg_catalog.set_config('search_path', '', false);"),pos=sql.indexOf(prologue);
 if(pos<0||pos>4096||sql.indexOf(prologue,pos+prologue.length)!==-1)throw Error('RESTORE_EXACT_POSTGRES_PROLOGUE_REQUIRED');
 const configured=Buffer.concat([sql.subarray(0,pos),Buffer.from("SELECT pg_catalog.set_config('search_path', 'pg_catalog,public', false);"),sql.subarray(pos+prologue.length)]);
 docker(['exec','-i',`${project}-${service}-1`,'psql','-U',user,'-d',db,'--single-transaction','--set','ON_ERROR_STOP=on'],{input:configured});
 restores.push({file,originalSha256:expected.sha256,exitCode:0,allConstraintsPreserved:true,singleTransaction:true,onlySearchPathPrologueChanged:true});source.fill(0);sql.fill(0);configured.fill(0);
}
const checkpointSql="SELECT json_build_object('auditCount',(SELECT count(*) FROM audit_events),'auditHeads',(SELECT json_agg(h ORDER BY chain_scope) FROM audit_chain_heads h),'snapshotCount',(SELECT count(*) FROM config_snapshots),'credentialReferenceCount',(SELECT count(*) FROM credential_refs),'migrations',(SELECT json_agg(m ORDER BY name) FROM schema_migrations m),'externalActiveChannels',(SELECT count(*) FROM notification_channels WHERE status='active'),'activeSnapshotSchedules',(SELECT count(*) FROM config_snapshot_schedules WHERE state='active'))";
const query=sql=>JSON.parse(docker(['exec',`${project}-console-db-1`,'psql','-U','kongos','-d','kongos','-At','-v','ON_ERROR_STOP=1','-c',sql]).toString());
const checkpoint=query(checkpointSql);if(JSON.stringify(checkpoint)!==JSON.stringify(manifest.checkpoint))throw Error('RESTORE_DATABASE_AUDIT_CHECKPOINT_MISMATCH');
if(checkpoint.externalActiveChannels!==0||checkpoint.activeSnapshotSchedules!==0)throw Error('RESTORE_EXTERNAL_PROVIDER_OR_TIMER_FENCE_REQUIRED');
// Preserve rows and all FK references. Only sessions are revoked; no audit or
// historical job is rewritten. Empty Redis contains no copied old locks/tokens.
docker(['exec',`${project}-console-db-1`,'psql','-U','kongos','-d','kongos','-v','ON_ERROR_STOP=1','-c','BEGIN; UPDATE auth_sessions SET revoked_at=now() WHERE revoked_at IS NULL; UPDATE portal_sessions SET revoked_at=now() WHERE revoked_at IS NULL; COMMIT;']);
const sessionFence=query("SELECT json_build_object('activeConsoleSessions',(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL),'activePortalSessions',(SELECT count(*) FROM portal_sessions WHERE revoked_at IS NULL))");
if(sessionFence.activeConsoleSessions||sessionFence.activePortalSessions)throw Error('RESTORE_SESSION_FENCE_FAILED');
compose(['up','-d','--no-build','--wait','--wait-timeout','150']);
const facts=JSON.parse(docker(['inspect',...['console-api','console-web','portal-web','kong','console-db','kong-db','redis'].map(s=>`${project}-${s}-1`)]));
if(facts.some(c=>c.Config.Labels['com.docker.compose.project']!==project||c.State.Health?.Status!=='healthy'))throw Error('RESTORE_ALL_HEALTHCHECKS_REQUIRED');
const end=new Date().toISOString(),result={version:1,allPassed:true,project,startedAt,completedAt:end,restoreElapsedSeconds:(Date.parse(end)-Date.parse(startedAt))/1000,sourceBackupSha256:manifest.encryptedArchive.sha256,authenticatedArchiveVerified:true,restores,originalDatabaseCheckpointMatched:true,originalAuditRowsChanged:false,checkpoint,oldSessionsFencedBeforeApiOpen:true,sessionFence,tlsAndMetricsRuntimeOwnershipAppliedBeforeStartup:true,redisPolicy:'fresh cache; backed-up Redis data preserved privately, old locks and tokens not activated',externalProviderCount:0,activeSnapshotSchedules:0,containers:facts.map(c=>({service:c.Config.Labels['com.docker.compose.service'],id:c.Id,imageId:c.Image,health:c.State.Health.Status})),credentialProxyVerificationPending:true,configurationDecryptionVerificationPending:true,productionReady:false};
writeFileSync(report,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o644});console.log(JSON.stringify({allPassed:true,restoreElapsedSeconds:result.restoreElapsedSeconds,auditCheckpointMatched:true,credentialProxyVerificationPending:true}));
