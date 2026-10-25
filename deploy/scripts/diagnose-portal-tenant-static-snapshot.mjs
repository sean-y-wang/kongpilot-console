import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureFailedIssueRepairSnapshot,failedIssueSourceMigrations} from './verify-failed-issue-repair-continuity.mjs';
import {nullableRepairContainerProjection} from './verify-nullable-portal-repair-continuity.mjs';
import {portalProofMigrationExpectation} from './verify-portal-proof-read-lock-continuity.mjs';
import {PORTAL_TENANT_READONLY_PROGRAM,portalTenantAssetManifest,portalTenantPublicSourceInventory,portalTenantSnapshotReady} from './verify-portal-tenant-static-continuity.mjs';

const conditions=['BOUNDED_FACTS_EXCEEDED','WORKFLOW_UNAVAILABLE','GRANT_UNAVAILABLE','EXECUTION_UNAVAILABLE','MANAGED_TOTALS_INVALID','API_REPAIR_CONTAINER_INVALID','NULLABLE_REPAIR_C3_CONTAINER_INVALID','NULLABLE_REPAIR_PRIVATE_FILE_INVALID','NULLABLE_REPAIR_PRIVATE_FILE_CHANGED','FAILED_ISSUE_MIGRATION_CONTAINER_INVALID','FAILED_ISSUE_FIXTURE_INVALID','PORTAL_TENANT_ASSET_PERMISSIONS_INVALID','PORTAL_TENANT_ASSET_SYMLINK','PORTAL_TENANT_ASSET_EMPTY','PORTAL_TENANT_ASSET_TYPE_INVALID','PORTAL_TENANT_PUBLIC_SOURCE_SYMLINK'];
const phases=['capture-foundation-migration-business','business-readonly-start','business-first','business-failed','business-migrations','business-privileges','business-managed-totals','business-total-grants','business-total-credentials','business-total-references','business-total-certificates','business-total-publicationProofs','api-inspect','assets-api','assets-console','assets-portal','public-source','snapshot-ready'];
const marker='.catch(()=>process.exit(1));';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

export function portalTenantDiagnosticProgram(){
  if(PORTAL_TENANT_READONLY_PROGRAM.split(marker).length!==2)throw new Error('DIAGNOSTIC_MARKER_INVALID');
  return "let diagnosticPhase='business-readonly-start';\n"+PORTAL_TENANT_READONLY_PROGRAM
    .replace('const first=await facts(ids.firstWorkflowId,ids.firstExecutionId),failed=await facts(ids.failedWorkflowId,ids.failedExecutionId);',"diagnosticPhase='business-first';const first=await facts(ids.firstWorkflowId,ids.firstExecutionId);diagnosticPhase='business-failed';const failed=await facts(ids.failedWorkflowId,ids.failedExecutionId);")
    .replace('const migrations=(await db.query',"diagnosticPhase='business-migrations';const migrations=(await db.query")
    .replace('const table=(await db.query',"diagnosticPhase='business-privileges';const table=(await db.query")
    .replace('const managedTotals={};',"diagnosticPhase='business-managed-totals';const managedTotals={};")
    .replace('const row=(await db.query(sql)).rows[0];',"diagnosticPhase='business-total-'+name;const row=(await db.query(sql)).rows[0];")
    .replace(marker,`.catch(error=>{const allowed=${JSON.stringify(conditions)},phaseSet=${JSON.stringify(phases)};process.stdout.write(JSON.stringify({diagnosticFailure:true,phase:phaseSet.includes(diagnosticPhase)?diagnosticPhase:'business-readonly-start',sqlState:typeof error.code==='string'&&/^[0-9A-Z]{5}$/.test(error.code)?error.code:null,safeCondition:allowed.includes(error.message)?error.message:null,errorClass:typeof error.name==='string'&&/^[A-Za-z]{1,40}$/.test(error.name)?error.name:'Error'}));process.exit(1);});`);
}

function safeFailure(error,phase){
  const buffers=[error?.stdout,error?.stderr];
  for(const bytes of buffers){if(!bytes||bytes.length>4096)continue;try{const row=JSON.parse(bytes.toString());if(row.diagnosticFailure!==true||!phases.includes(row.phase))continue;return{phase:row.phase,sqlState:typeof row.sqlState==='string'&&/^[0-9A-Z]{5}$/.test(row.sqlState)?row.sqlState:null,safeCondition:conditions.includes(row.safeCondition)?row.safeCondition:null,errorClass:typeof row.errorClass==='string'&&/^[A-Za-z]{1,40}$/.test(row.errorClass)?row.errorClass:'Error'};}catch{}}
  return{phase,sqlState:typeof error?.code==='string'&&/^[0-9A-Z]{5}$/.test(error.code)?error.code:null,safeCondition:conditions.includes(error?.message)?error.message:null,errorClass:typeof error?.name==='string'&&/^[A-Za-z]{1,40}$/.test(error.name)?error.name:'Error'};
}

export function portalTenantSnapshotDiagnosticMain(args=process.argv.slice(2)){
  if(args.length!==0)throw new Error('DIAGNOSTIC_ARGUMENTS_INVALID');
  const directory='artifacts/M6',output=resolve(directory,'portal-tenant-deep-link-snapshot-diagnostic.json');
  // Reserve the record before any actual snapshot: this executable is single-use.
  const record={stage:'M6',label:'portal-tenant-deep-link',kind:'single authorized readonly snapshot diagnostic',startedAt:new Date().toISOString(),diagnosticCompleted:false,snapshotReady:false,phases:[],buildPerformed:false,otherProcessChange:false,businessOrNativeWrites:0,sourceSha256:{diagnostic:sha(readFileSync(fileURLToPath(import.meta.url))),frozenHelper:sha(readFileSync('deploy/scripts/verify-portal-tenant-static-continuity.mjs')),readonlyProgram:sha(PORTAL_TENANT_READONLY_PROGRAM)}};
  writeFileSync(output,JSON.stringify(record,null,2)+'\n',{flag:'wx'});
  let phase='capture-foundation-migration-business';
  try{
    const gate=JSON.parse(readFileSync(`${directory}/source-portal-tenant-deep-link-release-gate.json`,'utf8')),expected=portalProofMigrationExpectation(gate.migrations),sources=Object.fromEntries(Object.keys(gate.sourceSha256).map(path=>[path,sha(readFileSync(path))])),sourceMigrations=failedIssueSourceMigrations(expected);
    const value=captureFailedIssueRepairSnapshot(sourceMigrations,portalTenantDiagnosticProgram());
    record.phases.push({phase:'capture-foundation-migration-business',passed:true},{phase:'capture-foundation',passed:!!value.foundation},{phase:'migration-container',passed:!!value.migrationService},{phase:'business-readonly',passed:!!value.business});
    phase='api-inspect';const api=JSON.parse(execFileSync('docker',['inspect',value.foundation.core.api.id],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000,maxBuffer:256*1024}))[0];value.apiProcess=nullableRepairContainerProjection('console-api',api);record.phases.push({phase,passed:true});
    value.assets={};for(const [name,root]of [['api','apps/console-api/dist'],['console','apps/console-web/dist'],['portal','apps/portal-web/dist']]){phase=`assets-${name}`;value.assets[name]=portalTenantAssetManifest(root,{publicReadable:name==='portal'});record.phases.push({phase,passed:true});}
    phase='public-source';value.frozenSources=sources;value.publicSources=portalTenantPublicSourceInventory();record.phases.push({phase,passed:true});
    phase='snapshot-ready';record.snapshotReady=portalTenantSnapshotReady(value,expected);record.phases.push({phase,passed:record.snapshotReady});record.failure=record.snapshotReady?null:{phase,sqlState:null,safeCondition:null,errorClass:'SnapshotGuardRejected'};
  }catch(error){record.failure=safeFailure(error,phase);record.phases.push({phase:record.failure.phase,passed:false});}
  record.diagnosticCompleted=true;record.completedAt=new Date().toISOString();writeFileSync(output,JSON.stringify(record,null,2)+'\n');
  console.log(JSON.stringify({diagnosticCompleted:true,snapshotReady:record.snapshotReady,failure:record.failure??null,buildPerformed:false,businessOrNativeWrites:0}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{portalTenantSnapshotDiagnosticMain();}catch{console.error('PORTAL_TENANT_DIAGNOSTIC_FAILED; no raw message, SQL, rows or credentials printed.');process.exitCode=1;}}
