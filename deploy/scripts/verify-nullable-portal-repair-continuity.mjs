import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureApiRepairSnapshot, repairContainerProjection, apiRepairContinuityChecks } from './verify-api-repair-continuity.mjs';

export const NULLABLE_REPAIR_C3_SERVICES = ['kong-portal','kong-portal-db','kong-portal-migrations'];

export function nullableRepairContainerProjection(name, container) {
  return {...repairContainerProjection(name, container), state:container.State.Status, health:container.State.Health?.Status??null, finishedAt:container.State.FinishedAt, exitCode:container.State.ExitCode};
}

export function nullableRepairPrivateFileSnapshot(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid?.() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 || stat.size < 1 || stat.size > 4*1024*1024) throw new Error('NULLABLE_REPAIR_PRIVATE_FILE_INVALID');
    bytes=readFileSync(fd);
    if(bytes.length!==stat.size)throw new Error('NULLABLE_REPAIR_PRIVATE_FILE_CHANGED');
    return {inode:stat.ino,mode:stat.mode&0o777,mtimeMs:stat.mtimeMs,size:stat.size,sha256:createHash('sha256').update(bytes).digest('hex')};
  } finally {bytes?.fill(0);closeSync(fd);}
}

export function nullablePortalRepairContinuityChecks(before, after) {
  const checks=apiRepairContinuityChecks(before.core,after.core);
  const exactNames=value=>Array.isArray(value.c3)&&value.c3.map(row=>row.name).sort().join(',')===[...NULLABLE_REPAIR_C3_SERVICES].sort().join(',');
  checks.push({name:'C3 Kong/PG/bootstrap exact three-container baseline retained',passed:exactNames(before)&&exactNames(after)});
  const ready=value=>value.c3.every(row=>row.name==='kong-portal-migrations'?row.state==='exited'&&row.exitCode===0:row.state==='running'&&row.health==='healthy');
  checks.push({name:'C3 Kong/PG healthy and original bootstrap remains successfully exited',passed:ready(before)&&ready(after)});
  for(const name of NULLABLE_REPAIR_C3_SERVICES)checks.push({name:`${name} container/process/image/environment/state/networks/volumes unchanged`,passed:JSON.stringify(before.c3.find(row=>row.name===name))===JSON.stringify(after.c3.find(row=>row.name===name))});
  for(const key of ['environment','runtimeReference'])checks.push({name:`C3 private ${key} inode/mode/mtime/size/bytes unchanged`,passed:JSON.stringify(before.privateFiles[key])===JSON.stringify(after.privateFiles[key])});
  return checks;
}

export function capturePortalRepairSnapshot(){
  const project=process.env.COMPOSE_PROJECT_NAME||'kongos-console',core=captureApiRepairSnapshot();
  const c3=NULLABLE_REPAIR_C3_SERVICES.map(name=>{
    // Bootstrap has exited successfully; ps -a is required to prove it was not replaced.
    const ids=execFileSync('docker',['ps','-a','-q','--filter',`label=com.docker.compose.project=${project}`,'--filter',`label=com.docker.compose.service=${name}`],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000}).trim().split(/\s+/).filter(Boolean);
    if(ids.length!==1)throw new Error('NULLABLE_REPAIR_C3_CONTAINER_INVALID');
    const container=JSON.parse(execFileSync('docker',['inspect',ids[0]],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000}))[0];
    return nullableRepairContainerProjection(name,container);
  });
  return {core,c3,privateFiles:{environment:nullableRepairPrivateFileSnapshot('.env.portal-acceptance'),runtimeReference:nullableRepairPrivateFileSnapshot('/tmp/kongos-m6-runtime-secrets.json')}};
}

export function portalRepairRunOptions(args){
  const phase=args[0],label=args[1]??'nullable-portal';
  if(args.length<1||args.length>2||!['--before','--after'].includes(phase)||!/^[a-z][a-z0-9-]{0,63}$/.test(label))throw new Error('NULLABLE_REPAIR_ARGUMENTS_INVALID');
  return {phase,label,filename:`${label}-repair-continuity.json`};
}

function validateRecord(output,options){
  const saved=JSON.parse(readFileSync(output,'utf8'));
  if(saved.stage!=='M6'||!saved.before||(saved.label??'nullable-portal')!==options.label)throw new Error('NULLABLE_REPAIR_BASELINE_INVALID');
  // A completed run is immutable. A necessary further repair needs a new label.
  if(saved.allPassed!==null||Object.hasOwn(saved,'after')||Object.hasOwn(saved,'checks'))throw new Error('NULLABLE_REPAIR_RESULT_EXISTS');
  return saved;
}

export function writePortalRepairContinuityRecord(directory,options,current){
  const validated=portalRepairRunOptions([options.phase,options.label]);
  if(validated.filename!==options.filename)throw new Error('NULLABLE_REPAIR_ARGUMENTS_INVALID');
  const output=resolve(directory,validated.filename);mkdirSync(directory,{recursive:true});
  if(options.phase==='--before'){
    writeFileSync(output,JSON.stringify({stage:'M6',label:options.label,scope:'API process-only repair preserves canonical12 plus C3 Kong/PG/bootstrap and all private references; optional mounted static assets do not restart other processes',allPassed:null,before:current},null,2)+'\n',{flag:'wx'});
    return {output,allPassed:null};
  }
  const saved=validateRecord(output,options),checks=nullablePortalRepairContinuityChecks(saved.before,current),allPassed=checks.every(row=>row.passed);
  writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');
  return {output,checks,allPassed};
}

export function nullablePortalRepairContinuityMain(args=process.argv.slice(2)){
  const options=portalRepairRunOptions(args),directory='artifacts/M6',output=resolve(directory,options.filename);
  if(options.phase==='--before'&&existsSync(output))throw new Error('NULLABLE_REPAIR_BASELINE_EXISTS');
  if(options.phase==='--after')validateRecord(output,options); // Refuse sealed history before any runtime query.
  const result=writePortalRepairContinuityRecord(directory,options,capturePortalRepairSnapshot());
  if(options.phase==='--before')console.log('M6 labelled repair read-only baseline captured; no secret values recorded.');
  else{
    console.log(`${result.checks.filter(row=>row.passed).length}/${result.checks.length} M6 labelled process-only repair continuity checks passed; no private values recorded.`);
    if(!result.allPassed)process.exitCode=1;
  }
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{nullablePortalRepairContinuityMain();}
  catch{console.error('NULLABLE_PORTAL_REPAIR_CONTINUITY_FAILED; no raw errors or private values printed.');process.exitCode=1;}
}
