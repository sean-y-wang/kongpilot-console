import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {FAILED_ISSUE_MIGRATION,FAILED_ISSUE_READONLY_PROGRAM,captureFailedIssueRepairSnapshot,failedIssueSourceMigrations,firstIssueFactsIntact,failedIssueFactsIntact} from './verify-failed-issue-repair-continuity.mjs';
import {nullablePortalRepairContinuityChecks} from './verify-nullable-portal-repair-continuity.mjs';

export const PORTAL_PROOF_REPAIR_LABEL='portal-proof-read-lock';
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sourceGate='artifacts/M6/source-failed-issue-repair-release-gate.json';
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const ending="await db.query('COMMIT');process.stdout.write(JSON.stringify({first,failed,migrations,abandonmentTable:{present:table,certificateCount,privileges}}));";
if(FAILED_ISSUE_READONLY_PROGRAM.split(ending).length!==2)throw new Error('PORTAL_PROOF_READONLY_SOURCE_INVALID');
// The same fixed SQL-side hashing and readonly transaction now also attest the
// publication proof table privileges. No proof body or SQL error is serialized.
export const PORTAL_PROOF_READONLY_PROGRAM=FAILED_ISSUE_READONLY_PROGRAM.replace(ending,String.raw`
 const publicationProofPrivileges=(await db.query("SELECT has_table_privilege(current_user,'portal_publication_proofs','SELECT') AS read,has_table_privilege(current_user,'portal_publication_proofs','INSERT') AS append,has_table_privilege(current_user,'portal_publication_proofs','UPDATE') AS update,has_table_privilege(current_user,'portal_publication_proofs','DELETE') AS delete,has_table_privilege(current_user,'portal_publication_proofs','TRUNCATE') AS truncate,has_table_privilege(current_user,'portal_publication_proofs','REFERENCES') AS references,has_table_privilege(current_user,'portal_publication_proofs','TRIGGER') AS trigger")).rows[0];
 await db.query('COMMIT');process.stdout.write(JSON.stringify({first,failed,migrations,abandonmentTable:{present:table,certificateCount,privileges},publicationProofPrivileges}));`);

export function portalProofMigrationExpectation(value){
  if(!Array.isArray(value)||value.length!==10)throw new Error('PORTAL_PROOF_MIGRATIONS_INVALID');
  const rows=value.map(row=>({name:row?.name,checksum:row?.checksum}));
  if(rows.some((row,index)=>typeof row.name!=='string'||!row.name.startsWith(String(index).padStart(3,'0')+'_')||!/^\d{3}_[a-z0-9_]+\.sql$/.test(row.name)||!digest(row.checksum))||rows[9].name!==FAILED_ISSUE_MIGRATION)throw new Error('PORTAL_PROOF_MIGRATIONS_INVALID');
  return rows;
}

export function portalProofAppendOnlyPrivileges(value){
  return !!value&&Object.keys(value).sort().join(',')==='append,delete,read,references,trigger,truncate,update'&&value.read===true&&value.append===true&&['update','delete','truncate','references','trigger'].every(key=>value[key]===false);
}

export function portalProofSnapshotReady(value,expected){
  const business=value?.business;
  return !!business&&same(value.sourceMigrations,expected)&&same(business.migrations?.map(row=>({name:row.name,checksum:row.checksum})),expected)
    &&business.migrations.every(row=>typeof row.applied_at==='string'&&row.applied_at.length>0)
    &&business.abandonmentTable?.present===true&&business.abandonmentTable.certificateCount===0
    &&portalProofAppendOnlyPrivileges(business.abandonmentTable.privileges)&&portalProofAppendOnlyPrivileges(business.publicationProofPrivileges)
    &&firstIssueFactsIntact(business.first)&&failedIssueFactsIntact(business.failed)
    &&value.migrationService?.state==='exited'&&value.migrationService.exitCode===0;
}

export function portalProofReadLockContinuityChecks(before,after,expected){
  const checks=nullablePortalRepairContinuityChecks(before.foundation,after.foundation),b=before.business,a=after.business;
  checks.push({name:'immutable000–009 source checksums remain exactly pinned',passed:same(before.sourceMigrations,expected)&&same(after.sourceMigrations,expected)});
  checks.push({name:'both databases retain exactly000–009 and all applied_at rows without a migration',passed:same(b.migrations?.map(row=>({name:row.name,checksum:row.checksum})),expected)&&same(a.migrations?.map(row=>({name:row.name,checksum:row.checksum})),expected)&&same(b.migrations,a.migrations)});
  checks.push({name:'existing failed-issue certificate table remains present and empty before and after',passed:b.abandonmentTable?.present===true&&a.abandonmentTable?.present===true&&b.abandonmentTable.certificateCount===0&&a.abandonmentTable.certificateCount===0});
  checks.push({name:'certificate table SELECT/INSERT-only runtime privileges unchanged',passed:portalProofAppendOnlyPrivileges(b.abandonmentTable?.privileges)&&portalProofAppendOnlyPrivileges(a.abandonmentTable?.privileges)&&same(b.abandonmentTable?.privileges,a.abandonmentTable?.privileges)});
  checks.push({name:'publication proofs retain SELECT/INSERT-only runtime privileges unchanged',passed:portalProofAppendOnlyPrivileges(b.publicationProofPrivileges)&&portalProofAppendOnlyPrivileges(a.publicationProofPrivileges)&&same(b.publicationProofPrivileges,a.publicationProofPrivileges)});
  checks.push({name:'original exited migration service container/process/state retained without any job',passed:same(before.migrationService,after.migrationService)&&before.migrationService.state==='exited'&&before.migrationService.exitCode===0});
  checks.push({name:'first active generation1 grant and original succeeded native3/refs2 retained',passed:firstIssueFactsIntact(b.first)&&firstIssueFactsIntact(a.first)});
  checks.push({name:'second pending grant keeps its known-failed Consumer and three untouched pending steps',passed:failedIssueFactsIntact(b.failed)&&failedIssueFactsIntact(a.failed)});
  checks.push({name:'all first-active SQL-side whole-row/cipher/plan/ledger/audit hashes retained',passed:same(b.first,a.first)});
  checks.push({name:'all second-failed SQL-side whole-row/cipher/plan/ledger/audit hashes retained',passed:same(b.failed,a.failed)});
  return checks;
}

export function portalProofRepairOptions(args){
  if(args.length!==1||!['--before','--after'].includes(args[0]))throw new Error('PORTAL_PROOF_REPAIR_ARGUMENTS_INVALID');
  return{phase:args[0],label:PORTAL_PROOF_REPAIR_LABEL,filename:`${PORTAL_PROOF_REPAIR_LABEL}-repair-continuity.json`};
}

export function portalProofValidateBaseline(saved,expected){
  if(saved?.stage!=='M6'||saved.label!==PORTAL_PROOF_REPAIR_LABEL||saved.allPassed!==null||!saved.before||Object.hasOwn(saved,'after')||Object.hasOwn(saved,'checks')||!same(saved.expectedMigrations,expected)||!portalProofSnapshotReady(saved.before,expected))throw new Error('PORTAL_PROOF_BASELINE_INVALID');
  return saved;
}

export function writePortalProofRepairRecord(directory,options,current,expected){
  const validated=portalProofRepairOptions([options.phase]);
  if(!same(validated,options)||!same(portalProofMigrationExpectation(expected),expected))throw new Error('PORTAL_PROOF_REPAIR_ARGUMENTS_INVALID');
  const output=resolve(directory,validated.filename);mkdirSync(directory,{recursive:true});
  if(options.phase==='--before'){
    if(!portalProofSnapshotReady(current,expected))throw new Error('PORTAL_PROOF_BEFORE_FACTS_INVALID');
    writeFileSync(output,JSON.stringify({stage:'M6',label:PORTAL_PROOF_REPAIR_LABEL,scope:'API workspace build and same-container process restart only; no migration, static build, other restart, native or business write',expectedMigrations:expected,allPassed:null,before:current},null,2)+'\n',{flag:'wx'});
    return{output,allPassed:null};
  }
  const saved=portalProofValidateBaseline(JSON.parse(readFileSync(output,'utf8')),expected);
  const checks=portalProofReadLockContinuityChecks(saved.before,current,expected),allPassed=checks.every(row=>row.passed);
  writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');
  return{output,checks,allPassed};
}

export function portalProofRepairMain(args=process.argv.slice(2)){
  const options=portalProofRepairOptions(args),directory='artifacts/M6',output=resolve(directory,options.filename);
  const gate=JSON.parse(readFileSync(sourceGate,'utf8'));if(gate.allPassed!==true)throw new Error('PORTAL_PROOF_SOURCE_GATE_INVALID');
  const expected=portalProofMigrationExpectation(gate.migrations),sourceMigrations=failedIssueSourceMigrations(expected);
  if(!same(sourceMigrations,expected))throw new Error('PORTAL_PROOF_SOURCE_MIGRATION_CHANGED');
  // Reject conflicting/sealed history before Docker, databases or private files.
  if(options.phase==='--before'&&existsSync(output))throw new Error('PORTAL_PROOF_BASELINE_EXISTS');
  if(options.phase==='--after')portalProofValidateBaseline(JSON.parse(readFileSync(output,'utf8')),expected);
  const result=writePortalProofRepairRecord(directory,options,captureFailedIssueRepairSnapshot(sourceMigrations,PORTAL_PROOF_READONLY_PROGRAM),expected);
  if(options.phase==='--before')console.log('Portal proof read-lock readonly baseline captured; no private values recorded.');
  else{console.log(JSON.stringify({checks:result.checks.length,passed:result.checks.filter(row=>row.passed).length,allPassed:result.allPassed}));if(!result.allPassed)process.exitCode=1;}
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{portalProofRepairMain();}catch{console.error('PORTAL_PROOF_READ_LOCK_CONTINUITY_FAILED; no plaintext or raw errors printed.');process.exitCode=1;}}
