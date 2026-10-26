import { execFileSync, spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, openSync, closeSync, fsyncSync, lstatSync } from 'node:fs';
import { createHash, randomBytes, createCipheriv } from 'node:crypto';
import { resolve } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { createWriteStream } from 'node:fs';

// Explicit, coordinated recovery point. Refuses the development daemon and
// writes only an authenticated encrypted archive outside the ephemeral lab.
const values=Object.fromEntries(process.argv.slice(2).map(v=>{const i=v.indexOf('=');if(!v.startsWith('--')||i<0)throw Error('BACKUP_ARGUMENTS');return[v.slice(2,i),v.slice(i+1)];}));
const {socket,project,tool,environment,output}=values;
if(process.env.KONGOS_BACKUP_WRITERS_QUIESCED!=='true'||!/^kongos-prod-[a-z\d-]+$/.test(project??'')||!/^kongos-ram-tool-[a-z\d-]+$/.test(tool??'')||!socket?.startsWith('unix:///dev/shm/kongos-production-ram-')||!environment?.startsWith('/run/kongos-private/production/')||!output?.startsWith('/opt/kongpilot-release/'))throw Error('BACKUP_EXPLICIT_ISOLATED_TARGET_REQUIRED');
const dir=resolve(output);if(existsSync(dir))throw Error('BACKUP_NEW_OUTPUT_REQUIRED');mkdirSync(dir,{recursive:true,mode:0o700});
const execute=(args,options={})=>{try{return execFileSync('docker',args,{stdio:['pipe','pipe','pipe'],maxBuffer:64*1024**2,timeout:60000,...options});}catch{throw Error('BACKUP_PRIVATE_COMMAND_FAILED');}};
const docker=(args,options={})=>execute([`--host=${socket}`,...args],options);
const main=(args,options={})=>execute(['--host=unix:///var/run/docker.sock','exec','-i',tool,...args],options);
const required=['console-api','console-web','portal-web','kong','kong-db','console-db','redis'];
const ids=required.map(s=>`${project}-${s}-1`),facts=JSON.parse(docker(['inspect',...ids]));
if(facts.some(c=>c.Config.Labels['com.docker.compose.project']!==project||c.State.Status!=='running'))throw Error('BACKUP_RUNNING_EXACT_PROJECT_REQUIRED');
const start=new Date().toISOString(),writers=facts.filter(c=>['console-api','kong'].includes(c.Config.Labels['com.docker.compose.service'])).map(c=>c.Id);
const collectorIds=docker(['ps','--filter',`label=com.docker.compose.project=${project}`,'--filter','label=com.docker.compose.service=telemetry-collector','-q']).toString().trim();
if(collectorIds)writers.push(collectorIds);
const backupRuntime=`/run/kongos-private/backups/${project}`;
const sql="SELECT json_build_object('auditCount',(SELECT count(*) FROM audit_events),'auditHeads',(SELECT json_agg(h ORDER BY chain_scope) FROM audit_chain_heads h),'snapshotCount',(SELECT count(*) FROM config_snapshots),'credentialReferenceCount',(SELECT count(*) FROM credential_refs),'migrations',(SELECT json_agg(m ORDER BY name) FROM schema_migrations m),'externalActiveChannels',(SELECT count(*) FROM notification_channels WHERE status='active'),'activeSnapshotSchedules',(SELECT count(*) FROM config_snapshot_schedules WHERE state='active'))";
const query=()=>JSON.parse(docker(['exec',`${project}-console-db-1`,'psql','-U','kongos','-d','kongos','-At','-c',sql]).toString());
let stopped=false;
try{
 docker(['stop','--time','30',...writers]);stopped=true;
 const checkpoint=query();
 main(['node','--input-type=module','-e',"import fs from'node:fs';const p=process.argv[1];if(fs.existsSync(p))throw Error('BACKUP_RUNTIME_EXISTS');fs.mkdirSync(p,{recursive:true,mode:448});fs.cpSync('/run/kongos-private/production',p+'/materials',{recursive:true,preserveTimestamps:true});",backupRuntime]);
 const files=[];
 for(const [service,user,db,file]of[['console-db','kongos','kongos','console.dump'],['kong-db','kong','kong','kong-primary.dump']]){
  const dump=docker(['exec',`${project}-${service}-1`,'pg_dump','-U',user,'-d',db,'-Fc','--no-owner']);
  main(['node','-e',"const fs=require('fs');const b=fs.readFileSync(0);fs.writeFileSync(process.argv[1],b,{flag:'wx',mode:384});",`${backupRuntime}/${file}`],{input:dump});
  files.push({file,bytes:dump.length,sha256:createHash('sha256').update(dump).digest('hex'),exitCode:0});
 }
 const redisSave=docker(['exec',`${project}-redis-1`,'/bin/sh','-ec','REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli SAVE']).toString().trim();
 if(redisSave!=='OK')throw Error('BACKUP_REDIS_SAVE_FAILED');
 // Copy the volume only after writers stop and Redis confirms SAVE.
 main(['docker',`--host=unix:///var/run/docker.sock`,'cp',`${project}-redis-1:/data`,`${backupRuntime}/redis`]);
 const stable=query();if(JSON.stringify(checkpoint)!==JSON.stringify(stable))throw Error('BACKUP_CHECKPOINT_CHANGED_DURING_QUIESCE');
 const key=randomBytes(32),iv=randomBytes(12),keyPath=resolve(dir,'recovery-key.bin'),archivePath=resolve(dir,'recovery-point.kosgcm');
 writeFileSync(keyPath,key,{flag:'wx',mode:0o600});
 const fd=openSync(archivePath,'wx',0o600);writeFileSync(fd,Buffer.concat([Buffer.from('KOSBAK01'),iv]));closeSync(fd);
 const tar=spawn('docker',['--host=unix:///var/run/docker.sock','exec',tool,'tar','-cz','-C',backupRuntime,'.'],{stdio:['ignore','pipe','pipe']});let stderrBytes=0;tar.stderr.on('data',b=>{stderrBytes+=b.length;});
 const exit=new Promise((accept,reject)=>{tar.once('error',reject);tar.once('exit',code=>code===0?accept():reject(Error('BACKUP_PRIVATE_ARCHIVE_FAILED')));});
 const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from('KOSBAK01'));
 await pipeline(tar.stdout,cipher,createWriteStream(archivePath,{flags:'a',mode:0o600}));await exit;
 const endFd=openSync(archivePath,'a');writeFileSync(endFd,cipher.getAuthTag());fsyncSync(endFd);closeSync(endFd);
 const bytes=readFileSync(archivePath),evidence={version:1,allPassed:true,project,startedAt:start,completedAt:new Date().toISOString(),writerContainerIds:writers,coordinatedWriterStop:true,checkpoint,files,redisSaveConfirmed:true,encryptedArchive:{bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),algorithm:'AES-256-GCM',authenticated:true,persistentWorkspaceCopy:true,offHostStorageTested:false,keyPublished:false},sourceImages:facts.map(c=>({service:c.Config.Labels['com.docker.compose.service'],imageId:c.Image})),privateArchiveStderrByteCount:stderrBytes};
 writeFileSync(resolve(dir,'manifest.json'),JSON.stringify(evidence,null,2)+'\n',{flag:'wx',mode:0o600});
 const report='artifacts/Production/root-production-coordinated-encrypted-backup-actual.json';if(existsSync(report))throw Error('BACKUP_PUBLIC_REPORT_EXISTS');writeFileSync(report,JSON.stringify(evidence,null,2)+'\n',{flag:'wx',mode:0o644});
 console.log(JSON.stringify({allPassed:true,coordinatedBackup:true,encryptedBytes:bytes.length,auditCount:checkpoint.auditCount,offHostStorageTested:false}));
}finally{
 if(stopped)docker(['start',...writers]);
}
