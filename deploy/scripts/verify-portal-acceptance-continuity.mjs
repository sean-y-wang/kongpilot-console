import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { captureApiRepairSnapshot, apiRepairContinuityChecks } from './verify-api-repair-continuity.mjs';

export function portalAcceptanceContinuityChecks(before, after) {
  const added = after.core.api.networks.filter(row => !before.core.api.networks.some(old => old.name === row.name));
  const normalized = {...after.core, api: {...after.core.api, envSHA256: before.core.api.envSHA256, networks: after.core.api.networks.filter(row => before.core.api.networks.some(old => old.name === row.name))}};
  const checks = apiRepairContinuityChecks(before.core, normalized).map(row => row.name.startsWith('API container') ? {...row, name:'API original image/environment/network/volume preserved; only required API container recreate allowed', passed: JSON.stringify({...before.core.api,id:null}) === JSON.stringify({...normalized.api,id:null})} : row);
  checks.push({name:'API has exactly one new fixed C3 Admin interface', passed:added.length===1&&added[0].name.endsWith('_kong-portal-admin')&&added[0].ip==='172.28.13.10'});
  checks.push({name:'all original API credentials and non-allowlist environment byte-identical',passed:before.policy.stableEnvSHA256===after.policy.stableEnvSHA256});
  checks.push({name:'outbound permits only exact new Admin alias host:port',passed:before.policy.allowRules.every(row=>after.policy.allowRules.includes(row))&&after.policy.allowRules.filter(row=>!before.policy.allowRules.includes(row)).join(',')==='kong-portal-admin-endpoint:8001'});
  checks.push({name:'all old destination protections preserved with exact new C3 host/IP extensions',passed:before.policy.protectedHosts.every(row=>after.policy.protectedHosts.includes(row))&&['kong-portal-db','172.28.23.20','kong-portal-admin-endpoint','172.28.13.20','172.28.13.10'].every(row=>after.policy.protectedHosts.includes(row))&&after.policy.protectedHosts.filter(row=>!before.policy.protectedHosts.includes(row)).every(row=>['kong-portal-db','172.28.23.20','kong-portal-admin-endpoint','172.28.13.20','172.28.13.10'].includes(row))});
  checks.push({name:'existing private runtime reference inode/mode/mtime/bytes preserved',passed:JSON.stringify(before.reference)===JSON.stringify(after.reference)});
  return checks;
}
function snapshot(){
  const core=captureApiRepairSnapshot();
  const value=JSON.parse(execFileSync('docker',['inspect',core.api.id],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000}))[0];
  const env=value.Config.Env||[], parsed=Object.fromEntries(env.map(row=>{const index=row.indexOf('=');return[row.slice(0,index),row.slice(index+1)];}));
  const stable=env.filter(row=>!row.startsWith('OUTBOUND_ALLOWED_HOSTS=')&&!row.startsWith('PROTECTED_DESTINATION_HOSTS=')).sort();
  const path='/tmp/kongos-m6-runtime-secrets.json',stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==process.getuid?.()||(stat.mode&0o777)!==0o600)throw new Error('PRIVATE_REFERENCE_INVALID');
  return {core,policy:{stableEnvSHA256:createHash('sha256').update(JSON.stringify(stable)).digest('hex'),allowRules:parsed.OUTBOUND_ALLOWED_HOSTS.split(',').filter(Boolean),protectedHosts:parsed.PROTECTED_DESTINATION_HOSTS.split(',').filter(Boolean)},reference:{inode:stat.ino,mode:stat.mode&0o777,mtimeMs:stat.mtimeMs,size:stat.size,sha256:createHash('sha256').update(readFileSync(path)).digest('hex')}};
}
if(process.argv[1]?.endsWith('/verify-portal-acceptance-continuity.mjs')){
  try{
    if(process.argv.length!==3||!['--before','--after'].includes(process.argv[2]))throw new Error('ARGUMENTS_INVALID');
    const output='artifacts/M6/portal-acceptance-runtime-continuity.json';
    if(process.argv[2]==='--before'&&existsSync(output))throw new Error('BASELINE_EXISTS');
    const current=snapshot();
    if(process.argv[2]==='--before'){
      writeFileSync(output,JSON.stringify({stage:'M6',scope:'C3 bootstrap and one necessary BFF env/network recreate preserve all canonical native/data/metrics/Portal services',allPassed:null,before:current},null,2)+'\n',{flag:'wx'});
      console.log('C3 read-only continuity baseline captured; no secret values recorded.');
    }else{
      const saved=JSON.parse(readFileSync(output,'utf8')),checks=portalAcceptanceContinuityChecks(saved.before,current),allPassed=checks.every(row=>row.passed);
      writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');
      console.log(`${checks.filter(row=>row.passed).length}/${checks.length} C3 activation continuity checks passed; no secret values recorded.`);
      if(!allPassed)process.exitCode=1;
    }
  }catch{console.error('PORTAL_ACCEPTANCE_CONTINUITY_FAILED; no raw tool errors or private values printed.');process.exitCode=1;}
}
