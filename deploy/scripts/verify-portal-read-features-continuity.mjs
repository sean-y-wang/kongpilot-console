import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureFailedIssueRepairSnapshot,failedIssueSourceMigrations} from './verify-failed-issue-repair-continuity.mjs';
import {nullablePortalRepairContinuityChecks} from './verify-nullable-portal-repair-continuity.mjs';
import {portalProofMigrationExpectation} from './verify-portal-proof-read-lock-continuity.mjs';
import {PORTAL_TENANT_READONLY_PROGRAM,portalTenantAssetManifest,portalTenantPublicSourceInventory} from './verify-portal-tenant-static-continuity.mjs';
const LABEL='portal-catalog-admin-details',directory='artifacts/M6',gatePath=`${directory}/source-portal-read-features-release-gate.json`;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),sha=b=>createHash('sha256').update(b).digest('hex');

/** Reads the same tested historical-subject program, never native credentials. */
export function portalReadFeaturesChecks(before,after,expected){
  const checks=nullablePortalRepairContinuityChecks(before.foundation,after.foundation);
  checks.push({name:'all original Portal grants/credentials/refs/proofs/failed certificate and immutable execution rows unchanged',passed:same(before.business,after.business)});
  checks.push({name:'000–009 source and database checksums/applied-at unchanged; no migration',passed:same(before.sourceMigrations,expected)&&same(after.sourceMigrations,expected)&&same(before.business.migrations,after.business.migrations)&&same(after.business.migrations?.map(r=>({name:r.name,checksum:r.checksum})),expected)});
  checks.push({name:'original exited Console migration service unchanged',passed:same(before.migrationService,after.migrationService)&&after.migrationService.state==='exited'&&after.migrationService.exitCode===0});
  checks.push({name:'public build/product/deployment source files stay frozen throughout the three builds',passed:same(before.publicSources,after.publicSources)});
  return checks;
}
export function assertUnsealedPortalReadFeaturesRecord(value){
  if(value?.stage!=='M6'||value.label!==LABEL||value.allPassed!==null||!value.before||Object.hasOwn(value,'after')||Object.hasOwn(value,'checks'))throw new Error('PORTAL_READ_FEATURES_RECORD_SEALED');
}
function snapshot(expected){
  return {...captureFailedIssueRepairSnapshot(expected,PORTAL_TENANT_READONLY_PROGRAM),publicSources:portalTenantPublicSourceInventory(),assets:{api:portalTenantAssetManifest('apps/console-api/dist'),console:portalTenantAssetManifest('apps/console-web/dist'),portal:portalTenantAssetManifest('apps/portal-web/dist',{publicReadable:true})}};
}
export function portalReadFeaturesMain(args=process.argv.slice(2)){
  if(args.length!==1||!['--before','--after'].includes(args[0]))throw new Error('PORTAL_READ_FEATURES_ARGUMENTS_INVALID');
  const phase=args[0],output=`${directory}/${LABEL}-repair-continuity.json`,gate=JSON.parse(readFileSync(gatePath,'utf8'));
  if(gate.allPassed!==true||gate.label!==LABEL||!gate.sourceSha256||!Array.isArray(gate.migrations)||gate.migrations.length!==10)throw new Error('PORTAL_READ_FEATURES_GATE_INVALID');
  if(!Object.entries(gate.sourceSha256).every(([path,digest])=>sha(readFileSync(path))===digest))throw new Error('PORTAL_READ_FEATURES_SOURCE_CHANGED');
  const expected=portalProofMigrationExpectation(gate.migrations);
  if(!same(failedIssueSourceMigrations(expected),expected))throw new Error('PORTAL_READ_FEATURES_MIGRATIONS_CHANGED');
  if(phase==='--before'&&existsSync(output))throw new Error('PORTAL_READ_FEATURES_BASELINE_EXISTS');
  const saved=phase==='--after'?JSON.parse(readFileSync(output,'utf8')):null;
  if(saved)assertUnsealedPortalReadFeaturesRecord(saved); // Sealed history rejected before Docker/private/DB access.
  if(saved&&saved.sourceReleaseSHA256!==sha(readFileSync(gatePath)))throw new Error('PORTAL_READ_FEATURES_GATE_CHANGED');
  const current=snapshot(expected);mkdirSync(directory,{recursive:true});
  if(phase==='--before'){
    writeFileSync(output,JSON.stringify({stage:'M6',label:LABEL,sourceReleaseSHA256:sha(readFileSync(gatePath)),allPassed:null,before:current},null,2)+'\n',{flag:'wx'});
    console.log('M6 read-feature repair baseline captured; private values withheld.');return;
  }
  const checks=portalReadFeaturesChecks(saved.before,current,expected),allPassed=checks.every(c=>c.passed);
  writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');
  console.log(JSON.stringify({checks:checks.length,passed:checks.filter(c=>c.passed).length,allPassed}));if(!allPassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{portalReadFeaturesMain();}catch{console.error('PORTAL_READ_FEATURES_CONTINUITY_FAILED; raw errors withheld.');process.exitCode=1;}
}
