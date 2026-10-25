import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureFailedIssueRepairSnapshot,failedIssueSourceMigrations} from './verify-failed-issue-repair-continuity.mjs';
import {portalReadFeaturesChecks} from './verify-portal-read-features-continuity.mjs';
import {portalProofMigrationExpectation} from './verify-portal-proof-read-lock-continuity.mjs';
import {PORTAL_TENANT_READONLY_PROGRAM,portalTenantAssetManifest,portalTenantPublicSourceInventory} from './verify-portal-tenant-static-continuity.mjs';

export const PORTAL_METADATA_RESTORE_LABEL='portal-metadata-restore';
const directory='artifacts/M6',gatePath=`${directory}/source-portal-metadata-restore-release-gate.json`;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),sha=value=>createHash('sha256').update(value).digest('hex'),digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const manifest=value=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length>0&&Object.entries(value).every(([path,hash])=>typeof path==='string'&&/^[a-zA-Z0-9_./-]+$/.test(path)&&!path.startsWith('/')&&!path.split('/').includes('..')&&!/(?:^|\/)(?:private|node_modules|dist)(?:\/|$)/.test(path)&&(!path.split('/').some(part=>part.startsWith('.env'))||path==='.env.example')&&digest(hash));

export function portalMetadataRestoreOptions(args){
  if(args.length!==1||!['--before','--after'].includes(args[0]))throw new Error('PORTAL_METADATA_RESTORE_ARGUMENTS_INVALID');
  return{phase:args[0],label:PORTAL_METADATA_RESTORE_LABEL,filename:`${PORTAL_METADATA_RESTORE_LABEL}-repair-continuity.json`};
}

export function portalMetadataRestoreGateExpectation(gate){
  if(gate?.allPassed!==true||gate.label!==PORTAL_METADATA_RESTORE_LABEL||!manifest(gate.sourceSha256))throw new Error('PORTAL_METADATA_RESTORE_GATE_INVALID');
  return portalProofMigrationExpectation(gate.migrations);
}

export function portalMetadataRestorePreflight({phase,gate,gateSHA256,sources,migrations,outputExists,saved}){
  portalMetadataRestoreOptions([phase]);const expected=portalMetadataRestoreGateExpectation(gate);
  if(!digest(gateSHA256)||!same(sources,gate.sourceSha256)||!same(migrations,expected))throw new Error('PORTAL_METADATA_RESTORE_FROZEN_SOURCE_CHANGED');
  if(phase==='--before'&&outputExists)throw new Error('PORTAL_METADATA_RESTORE_BASELINE_EXISTS');
  if(phase==='--after'){
    if(saved?.stage!=='M6'||saved.label!==PORTAL_METADATA_RESTORE_LABEL||saved.allPassed!==null||!saved.before||Object.hasOwn(saved,'after')||Object.hasOwn(saved,'checks')||!same(saved.expectedMigrations,expected))throw new Error('PORTAL_METADATA_RESTORE_RECORD_SEALED');
    if(saved.sourceReleaseSHA256!==gateSHA256)throw new Error('PORTAL_METADATA_RESTORE_GATE_CHANGED');
  }
  return expected;
}

export function portalMetadataRestoreChecks(before,after,expected){
  const checks=portalReadFeaturesChecks(before,after,expected);
  for(const kind of ['console','portal'])checks.push({name:`all ${kind} static asset paths and bytes unchanged; no static build`,passed:!!before.assets?.[kind]&&Object.keys(before.assets[kind]).length>0&&same(before.assets[kind],after.assets?.[kind])});
  return checks;
}

function snapshot(expected){
  return{...captureFailedIssueRepairSnapshot(expected,PORTAL_TENANT_READONLY_PROGRAM),publicSources:portalTenantPublicSourceInventory(),assets:{api:portalTenantAssetManifest('apps/console-api/dist'),console:portalTenantAssetManifest('apps/console-web/dist'),portal:portalTenantAssetManifest('apps/portal-web/dist',{publicReadable:true})}};
}

export function portalMetadataRestoreMain(args=process.argv.slice(2)){
  const options=portalMetadataRestoreOptions(args),output=`${directory}/${options.filename}`,gateBytes=readFileSync(gatePath),gate=JSON.parse(gateBytes.toString('utf8')),gateSHA256=sha(gateBytes);
  const expected=portalMetadataRestoreGateExpectation(gate),sources=Object.fromEntries(Object.keys(gate.sourceSha256).map(path=>[path,sha(readFileSync(path))])),migrations=failedIssueSourceMigrations(expected),outputExists=existsSync(output),saved=options.phase==='--after'?JSON.parse(readFileSync(output,'utf8')):null;
  // Reject changed gates/checksums and any existing/sealed history before private,
  // Docker or DB access. Historical helpers and their sealed records stay untouched.
  portalMetadataRestorePreflight({phase:options.phase,gate,gateSHA256,sources,migrations,outputExists,saved});
  const current=snapshot(expected);mkdirSync(directory,{recursive:true});
  if(options.phase==='--before'){
    if(!portalMetadataRestoreChecks(current,current,expected).every(row=>row.passed))throw new Error('PORTAL_METADATA_RESTORE_BASELINE_INVALID');
    writeFileSync(output,JSON.stringify({stage:'M6',label:options.label,sourceReleaseSHA256:gateSHA256,expectedMigrations:expected,scope:'API workspace build and same-container API process restart only; all static assets and prior runtime/material/business facts retained',allPassed:null,before:current},null,2)+'\n',{flag:'wx'});
    console.log('M6 metadata-restore repair baseline captured; private values withheld.');return;
  }
  const checks=portalMetadataRestoreChecks(saved.before,current,expected),allPassed=checks.every(row=>row.passed);
  writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');
  console.log(JSON.stringify({checks:checks.length,passed:checks.filter(row=>row.passed).length,allPassed}));if(!allPassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{portalMetadataRestoreMain();}catch{console.error('PORTAL_METADATA_RESTORE_CONTINUITY_FAILED; raw errors withheld.');process.exitCode=1;}
}
