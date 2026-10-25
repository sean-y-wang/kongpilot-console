import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {constants,copyFileSync,existsSync,lstatSync,mkdirSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureFailedIssueRepairSnapshot,failedIssueSourceMigrations} from './verify-failed-issue-repair-continuity.mjs';
import {nullablePortalRepairContinuityChecks,nullableRepairContainerProjection} from './verify-nullable-portal-repair-continuity.mjs';
import {PORTAL_PROOF_READONLY_PROGRAM,portalProofAppendOnlyPrivileges,portalProofMigrationExpectation} from './verify-portal-proof-read-lock-continuity.mjs';

export const PORTAL_TENANT_REPAIR_LABEL='portal-tenant-deep-link';
export const PORTAL_TENANT_DELTA_PATHS=['apps/portal-web/src/main.tsx','apps/portal-web/src/app/tenant-selection.ts','tests/unit/m6-portal-tenant-selection.test.ts'];
export const PORTAL_TENANT_PREVIOUS_GATES=['startup-verification','startup-final-verification','deployment-boundary-final','admin-network-final-verification','metrics-deployment-verification','portal-deployment-verification'];
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),sha=b=>createHash('sha256').update(b).digest('hex'),hash=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const ending="await db.query('COMMIT');process.stdout.write(JSON.stringify({first,failed,migrations,abandonmentTable:{present:table,certificateCount,privileges},publicationProofPrivileges}));";
if(PORTAL_PROOF_READONLY_PROGRAM.split(ending).length!==2)throw new Error('PORTAL_TENANT_READONLY_SOURCE_INVALID');
const grantLookup='FROM portal_application_grants g WHERE g.workflow_id=$1';
export const PORTAL_TENANT_GRANT_LOOKUP_SQL="FROM portal_application_grants g JOIN workflows origin ON origin.id=$1 AND origin.kind='portal-credential-issue' AND origin.subject_type='portal_application_grants' AND origin.subject_id=g.id AND origin.cluster_id=g.cluster_id AND origin.workspace_id=g.workspace_id";
if(PORTAL_PROOF_READONLY_PROGRAM.split(grantLookup).length!==2)throw new Error('PORTAL_TENANT_GRANT_SOURCE_INVALID');
// No state constants: earlier business recovery is already complete. Attest its
// fresh state and all managed grant/ref rows entirely inside Console PostgreSQL.
export const PORTAL_TENANT_READONLY_PROGRAM=PORTAL_PROOF_READONLY_PROGRAM
  .replace(grantLookup,PORTAL_TENANT_GRANT_LOOKUP_SQL.replaceAll("'","\\'"))
  .replace("await db.query(\"SET LOCAL TIME ZONE 'UTC'\");","await db.query(\"SET LOCAL TIME ZONE 'UTC'\");await db.query(\"SET LOCAL statement_timeout='10000ms'\");")
  .replace(ending,String.raw`
 const managedTotals={};
 const queries={
  grants:"SELECT count(*)::integer AS count,encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(g)::text,chr(10) ORDER BY g.id),''),'UTF8')),'hex') AS sha256 FROM portal_application_grants g",
  credentials:"SELECT count(*)::integer AS count,encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(c)::text,chr(10) ORDER BY c.id),''),'UTF8')),'hex') AS sha256 FROM portal_credentials c",
  references:"SELECT count(*)::integer AS count,encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(r)::text,chr(10) ORDER BY r.id),''),'UTF8')),'hex') AS sha256 FROM credential_refs r WHERE EXISTS(SELECT 1 FROM portal_application_grants g WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id) AND(r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id OR r.kong_id IN(SELECT c.kong_id FROM portal_credentials c WHERE c.grant_id=g.id)))",
  certificates:"SELECT count(*)::integer AS count,encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(cert)::text,chr(10) ORDER BY cert.id),''),'UTF8')),'hex') AS sha256 FROM portal_failed_issue_abandonments cert",
  publicationProofs:"SELECT count(*)::integer AS count,encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(proof)::text,chr(10) ORDER BY proof.cluster_id,proof.workspace_id,proof.publication_id,proof.publication_revision),''),'UTF8')),'hex') AS sha256 FROM portal_publication_proofs proof"
 };for(const [name,sql]of Object.entries(queries)){const row=(await db.query(sql)).rows[0];if(!Number.isInteger(row.count)||row.count<0||row.count>512||typeof row.sha256!=='string'||!/^[a-f0-9]{64}$/.test(row.sha256))throw new Error('MANAGED_TOTALS_INVALID');managedTotals[name]=row;}
 await db.query('COMMIT');process.stdout.write(JSON.stringify({first,failed,migrations,abandonmentTable:{present:table,certificateCount,privileges},publicationProofPrivileges,managedTotals}));`);

export function portalTenantStaticCommands(){return[
 {command:'node',args:['deploy/scripts/verify-portal-tenant-static-continuity.mjs','--before']},
 {command:'npm',args:['run','build','-w','@kongpilot/portal-web']},
 {command:'node',args:['deploy/scripts/stage-deploy.mjs','M6','--multicluster','--observability','--portal','--verify-only']},
 {command:'node',args:['deploy/scripts/verify-portal-tenant-static-continuity.mjs','--after']}
];}

export function portalTenantRepairOptions(args){if(args.length!==1||!['--before','--after'].includes(args[0]))throw new Error('PORTAL_TENANT_ARGUMENTS_INVALID');return{phase:args[0],label:PORTAL_TENANT_REPAIR_LABEL,filename:`${PORTAL_TENANT_REPAIR_LABEL}-repair-continuity.json`};}
function manifestValid(value){return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length>0&&Object.entries(value).every(([path,digest])=>/^[a-zA-Z0-9_./-]+$/.test(path)&&!path.startsWith('/')&&!path.split('/').includes('..')&&hash(digest));}
function runtimeSource(path){return /^(?:apps\/|packages\/|docker-compose\.yml$|package(?:-lock)?\.json$|deploy\/(?:compose[./-]|nginx\/|metrics-collector\/|prometheus\/))/.test(path)&&!/(?:^|\/)(?:dist|node_modules|private)(?:\/|$)/.test(path);}
export function portalTenantRuntimeSourceDeltaChecks(previous,current){
  if(!manifestValid(previous)||!manifestValid(current))throw new Error('PORTAL_TENANT_SOURCE_MANIFEST_INVALID');
  const changed=[...new Set([...Object.keys(previous),...Object.keys(current)])].filter(runtimeSource).filter(path=>previous[path]!==current[path]);
  return[{name:'previously frozen product/build/network sources change only in explicit tenant runtime files',passed:changed.every(path=>PORTAL_TENANT_DELTA_PATHS.includes(path)),changedPaths:changed.sort()}];
}

export function portalTenantAssetManifest(directory,{publicReadable=false}={}){
  const result={};
  function visit(path){const stat=lstatSync(path);if(stat.isSymbolicLink())throw new Error('PORTAL_TENANT_ASSET_SYMLINK');if(publicReadable&&(stat.mode&0o777)!==(stat.isDirectory()?0o755:0o644))throw new Error('PORTAL_TENANT_ASSET_PERMISSIONS_INVALID');if(stat.isDirectory()){for(const name of readdirSync(path).sort())visit(join(path,name));}else if(stat.isFile())result[path]=sha(readFileSync(path));else throw new Error('PORTAL_TENANT_ASSET_TYPE_INVALID');}
  visit(directory);if(!Object.keys(result).length)throw new Error('PORTAL_TENANT_ASSET_EMPTY');return result;
}

export function portalTenantPublicSourceInventory(){
  const result={};function visit(path){const stat=lstatSync(path);if(stat.isSymbolicLink())throw new Error('PORTAL_TENANT_PUBLIC_SOURCE_SYMLINK');if(stat.isDirectory()){for(const name of readdirSync(path).sort()){if(['dist','node_modules','private','.git'].includes(name))continue;visit(join(path,name));}}else if(stat.isFile())result[path]=sha(readFileSync(path));}
  for(const root of ['apps','packages','deploy'])visit(root);for(const path of ['package.json','package-lock.json','docker-compose.yml'])result[path]=sha(readFileSync(path));return result;
}

export function portalTenantSnapshotReady(value,expected){
  const b=value?.business,totals=b?.managedTotals;
  return !!b&&same(value.sourceMigrations,expected)&&same(b.migrations?.map(row=>({name:row.name,checksum:row.checksum})),expected)
    &&b.migrations.every(row=>typeof row.applied_at==='string'&&row.applied_at.length>0)
    &&b.abandonmentTable?.present===true&&Number.isInteger(b.abandonmentTable.certificateCount)&&b.abandonmentTable.certificateCount>=0
    &&portalProofAppendOnlyPrivileges(b.abandonmentTable.privileges)&&portalProofAppendOnlyPrivileges(b.publicationProofPrivileges)
    &&!!totals&&Object.keys(totals).sort().join(',')==='certificates,credentials,grants,publicationProofs,references'
    &&Object.values(totals).every(row=>!!row&&Object.keys(row).sort().join(',')==='count,sha256'&&Number.isInteger(row.count)&&row.count>=0&&row.count<=512&&hash(row.sha256))
    &&totals.certificates.count===b.abandonmentTable.certificateCount
    &&!!b.first&&!!b.failed&&value.apiProcess?.state==='running'&&value.apiProcess.health==='healthy'
    &&value.migrationService?.state==='exited'&&value.migrationService.exitCode===0
    &&manifestValid(value.frozenSources)&&manifestValid(value.publicSources)&&manifestValid(value.assets?.api)&&manifestValid(value.assets?.console)&&manifestValid(value.assets?.portal);
}

export function portalTenantStaticContinuityChecks(before,after,expected){
  const checks=nullablePortalRepairContinuityChecks(before.foundation,after.foundation),b=before.business,a=after.business;
  checks.push({name:'API process StartedAt/id/image/state/health/environment/networks/volumes unchanged',passed:same(before.apiProcess,after.apiProcess)&&before.apiProcess.state==='running'&&after.apiProcess.state==='running'&&before.apiProcess.health==='healthy'&&after.apiProcess.health==='healthy'});
  checks.push({name:'all frozen release sources unchanged during the static-only build',passed:same(before.frozenSources,after.frozenSources)});
  checks.push({name:'all public product/build/deployment sources unchanged during the static-only build',passed:same(before.publicSources,after.publicSources)});
  checks.push({name:'compiled API asset paths and all bytes unchanged',passed:same(before.assets.api,after.assets.api)});
  checks.push({name:'Console static asset paths and all bytes unchanged',passed:same(before.assets.console,after.assets.console)});
  checks.push({name:'immutable000–009 source checksums and all database applied_at rows retained without migration',passed:same(before.sourceMigrations,expected)&&same(after.sourceMigrations,expected)&&same(b.migrations,a.migrations)&&same(a.migrations?.map(row=>({name:row.name,checksum:row.checksum})),expected)});
  checks.push({name:'existing abandonment certificate count/facts and SELECT/INSERT-only runtime privileges unchanged',passed:b.abandonmentTable?.present===true&&a.abandonmentTable?.present===true&&same(b.abandonmentTable,a.abandonmentTable)&&portalProofAppendOnlyPrivileges(b.abandonmentTable.privileges)&&portalProofAppendOnlyPrivileges(a.abandonmentTable.privileges)});
  checks.push({name:'publication proof SELECT/INSERT-only runtime privileges unchanged',passed:same(b.publicationProofPrivileges,a.publicationProofPrivileges)&&portalProofAppendOnlyPrivileges(b.publicationProofPrivileges)&&portalProofAppendOnlyPrivileges(a.publicationProofPrivileges)});
  checks.push({name:'original exited migration service container/process/environment/state retained without job',passed:same(before.migrationService,after.migrationService)&&before.migrationService.state==='exited'&&before.migrationService.exitCode===0});
  checks.push({name:'fresh first-success/now-revoked whole-row/cipher/plan/audit facts unchanged without obsolete status constants',passed:same(b.first,a.first)});
  checks.push({name:'fresh old-failed/now-disabled whole-row/cipher/plan/audit facts unchanged without obsolete status constants',passed:same(b.failed,a.failed)});
  checks.push({name:'every current managed grant/credential/ref/certificate/publication-proof total and SQL-side hash unchanged',passed:same(b.managedTotals,a.managedTotals)});
  checks.push({name:'both fresh dynamic snapshots retain bounded facts, valid assets and safe metadata',passed:portalTenantSnapshotReady(before,expected)&&portalTenantSnapshotReady(after,expected)});
  return checks;
}

export function archivePortalTenantPreviousGates(directory){
  return PORTAL_TENANT_PREVIOUS_GATES.map(name=>{const from=resolve(directory,`${name}.json`),to=resolve(directory,`${PORTAL_TENANT_REPAIR_LABEL}-previous-${name}.json`);copyFileSync(from,to,constants.COPYFILE_EXCL);const digest=sha(readFileSync(from));if(sha(readFileSync(to))!==digest)throw new Error('PORTAL_TENANT_ARCHIVE_MISMATCH');return{artifact:to,sha256:digest};});
}

function exactKeys(value,keys){return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype&&same(Object.keys(value).sort(),[...keys].sort());}
function publicResumeBytes(path,digest){const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>1024*1024)throw new Error('PORTAL_TENANT_RESUME_FILE_INVALID');const bytes=readFileSync(path);if(sha(bytes)!==digest)throw new Error('PORTAL_TENANT_RESUME_BYTES_CHANGED');return bytes;}
export function portalTenantResumePreviousGates(directory,metadata){
  if(existsSync(resolve(directory,`${PORTAL_TENANT_REPAIR_LABEL}-repair-continuity.json`)))throw new Error('PORTAL_TENANT_BASELINE_EXISTS');
  if(!exactKeys(metadata,['label','archives','failure','diagnostic'])||metadata.label!==PORTAL_TENANT_REPAIR_LABEL||!Array.isArray(metadata.archives)||metadata.archives.length!==6)throw new Error('PORTAL_TENANT_RESUME_METADATA_INVALID');
  const paths=PORTAL_TENANT_PREVIOUS_GATES.map(name=>({artifact:join(directory,`${PORTAL_TENANT_REPAIR_LABEL}-previous-${name}.json`),currentArtifact:join(directory,`${name}.json`)}));
  if(!metadata.archives.every((row,index)=>exactKeys(row,['artifact','sha256','currentArtifact','currentSHA256'])&&row.artifact===paths[index].artifact&&row.currentArtifact===paths[index].currentArtifact&&hash(row.sha256)&&row.sha256===row.currentSHA256))throw new Error('PORTAL_TENANT_RESUME_ARCHIVES_INVALID');
  const expectedFailure=join(directory,`${PORTAL_TENANT_REPAIR_LABEL}-coverage-corrected-deployment.json`),expectedDiagnostic=join(directory,`${PORTAL_TENANT_REPAIR_LABEL}-snapshot-diagnostic.json`);
  if(!exactKeys(metadata.failure,['artifact','sha256'])||metadata.failure.artifact!==expectedFailure||!hash(metadata.failure.sha256)||!exactKeys(metadata.diagnostic,['artifact','sha256'])||metadata.diagnostic.artifact!==expectedDiagnostic||!hash(metadata.diagnostic.sha256))throw new Error('PORTAL_TENANT_RESUME_REPORTS_INVALID');
  const failure=JSON.parse(publicResumeBytes(expectedFailure,metadata.failure.sha256).toString('utf8')),diagnostic=JSON.parse(publicResumeBytes(expectedDiagnostic,metadata.diagnostic.sha256).toString('utf8'));
  const boundaryKeys=['otherBuild','restart','recreate','migration','envOrNetworkChange','privateMaterialChange','nativeOrBusinessWrite','enrollRotateOrCapture'];
  if(failure.stage!=='M6'||failure.label!==PORTAL_TENANT_REPAIR_LABEL||failure.attempt!==`${PORTAL_TENANT_REPAIR_LABEL}-coverage-corrected`||failure.allPassed!==false||failure.inProgress!==false||failure.failedStep!=='fresh-readonly-before-snapshot'||failure.failureCode!=='PORTAL_TENANT_STATIC_CONTINUITY_FAILED'||!Array.isArray(failure.steps)||failure.steps.length!==1||failure.steps[0].step!=='fresh-readonly-before-and-six-wx-history-archives'||failure.steps[0].exitCode!==1||!exactKeys(failure.boundaries,boundaryKeys)||!boundaryKeys.every(key=>failure.boundaries[key]===false))throw new Error('PORTAL_TENANT_RESUME_FAILURE_INVALID');
  if(diagnostic.stage!=='M6'||diagnostic.label!==PORTAL_TENANT_REPAIR_LABEL||diagnostic.diagnosticCompleted!==true||diagnostic.snapshotReady!==false||diagnostic.buildPerformed!==false||diagnostic.otherProcessChange!==false||diagnostic.businessOrNativeWrites!==0||diagnostic.failure?.phase!=='business-first'||diagnostic.failure?.safeCondition!=='GRANT_UNAVAILABLE'||!same(diagnostic.phases,[{phase:'business-first',passed:false}]))throw new Error('PORTAL_TENANT_RESUME_DIAGNOSTIC_INVALID');
  return metadata.archives.map(row=>{publicResumeBytes(row.artifact,row.sha256);publicResumeBytes(row.currentArtifact,row.currentSHA256);return{artifact:resolve(row.artifact),sha256:row.sha256};});
}

function archiveEntriesValid(directory,items){return Array.isArray(items)&&items.length===PORTAL_TENANT_PREVIOUS_GATES.length&&items.every((row,index)=>row.artifact===resolve(directory,`${PORTAL_TENANT_REPAIR_LABEL}-previous-${PORTAL_TENANT_PREVIOUS_GATES[index]}.json`)&&hash(row.sha256));}
function baselineValid(saved,expected,expectedSources,directory){if(saved?.stage!=='M6'||saved.label!==PORTAL_TENANT_REPAIR_LABEL||saved.allPassed!==null||Object.hasOwn(saved,'after')||Object.hasOwn(saved,'checks')||!same(saved.expectedMigrations,expected)||!same(saved.expectedSources,expectedSources)||!portalTenantSnapshotReady(saved.before,expected)||!archiveEntriesValid(directory,saved.preservedPreviousGates))throw new Error('PORTAL_TENANT_BASELINE_INVALID');return saved;}
export function writePortalTenantRepairRecord(directory,options,current,expected,expectedSources,archives=[]){
  const validated=portalTenantRepairOptions([options.phase]);if(!same(options,validated)||!manifestValid(expectedSources))throw new Error('PORTAL_TENANT_ARGUMENTS_INVALID');
  const output=resolve(directory,options.filename);mkdirSync(directory,{recursive:true});
  if(options.phase==='--before'){
    if(!portalTenantSnapshotReady(current,expected)||!same(current.frozenSources,expectedSources)||!archiveEntriesValid(directory,archives))throw new Error('PORTAL_TENANT_BEFORE_FACTS_INVALID');
    writeFileSync(output,JSON.stringify({stage:'M6',label:PORTAL_TENANT_REPAIR_LABEL,scope:'Portal mounted static workspace build only; no process restart, migration, environment change or business/native write',expectedMigrations:expected,expectedSources,preservedPreviousGates:archives,allPassed:null,before:current},null,2)+'\n',{flag:'wx'});return{output,allPassed:null};
  }
  const saved=baselineValid(JSON.parse(readFileSync(output,'utf8')),expected,expectedSources,directory),checks=portalTenantStaticContinuityChecks(saved.before,current,expected);
  checks.push({name:'all six prior readiness report archives retain exact bytes',passed:saved.preservedPreviousGates.every(row=>existsSync(row.artifact)&&sha(readFileSync(row.artifact))===row.sha256)});
  const allPassed=checks.every(row=>row.passed)&&same(current.frozenSources,expectedSources);
  writeFileSync(output,JSON.stringify({...saved,after:current,checks,allPassed},null,2)+'\n');return{output,checks,allPassed};
}

function snapshot(expectedSources,sourceMigrations){
  const facts=captureFailedIssueRepairSnapshot(sourceMigrations,PORTAL_TENANT_READONLY_PROGRAM);
  const api=JSON.parse(execFileSync('docker',['inspect',facts.foundation.core.api.id],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:5000,maxBuffer:256*1024}))[0];
  return{...facts,apiProcess:nullableRepairContainerProjection('console-api',api),frozenSources:Object.fromEntries(Object.keys(expectedSources).map(path=>[path,sha(readFileSync(path))])),publicSources:portalTenantPublicSourceInventory(),assets:{api:portalTenantAssetManifest('apps/console-api/dist'),console:portalTenantAssetManifest('apps/console-web/dist'),portal:portalTenantAssetManifest('apps/portal-web/dist',{publicReadable:true})}};
}

export function portalTenantRepairMain(args=process.argv.slice(2)){
  const options=portalTenantRepairOptions(args),directory='artifacts/M6',output=resolve(directory,options.filename);
  const gate=JSON.parse(readFileSync(`${directory}/source-portal-tenant-deep-link-release-gate.json`,'utf8')),previous=JSON.parse(readFileSync(`${directory}/source-proof-read-lock-repair-release-gate.json`,'utf8'));
  if(gate.allPassed!==true||previous.allPassed!==true||!manifestValid(gate.sourceSha256)||!portalTenantRuntimeSourceDeltaChecks(previous.sourceSha256,gate.sourceSha256).every(row=>row.passed))throw new Error('PORTAL_TENANT_SOURCE_GATE_INVALID');
  const expected=portalProofMigrationExpectation(gate.migrations),sourceMigrations=failedIssueSourceMigrations(expected),sources=Object.fromEntries(Object.keys(gate.sourceSha256).map(path=>[path,sha(readFileSync(path))]));
  if(!same(sources,gate.sourceSha256)||!same(sourceMigrations,expected))throw new Error('PORTAL_TENANT_FROZEN_SOURCE_CHANGED');
  // Sealed/history/source checks precede all private-file, Docker and DB access.
  if(options.phase==='--before'&&existsSync(output))throw new Error('PORTAL_TENANT_BASELINE_EXISTS');
  if(options.phase==='--after')baselineValid(JSON.parse(readFileSync(output,'utf8')),expected,sources,directory);
  const archives=options.phase==='--before'?(Object.hasOwn(gate,'archivedBeforeResume')?portalTenantResumePreviousGates(directory,gate.archivedBeforeResume):archivePortalTenantPreviousGates(directory)):[];
  const result=writePortalTenantRepairRecord(directory,options,snapshot(sources,sourceMigrations),expected,sources,archives);
  if(options.phase==='--before')console.log('Portal static-only readonly baseline captured; no private values recorded.');else{console.log(JSON.stringify({checks:result.checks.length,passed:result.checks.filter(row=>row.passed).length,allPassed:result.allPassed}));if(!result.allPassed)process.exitCode=1;}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{portalTenantRepairMain();}catch{console.error('PORTAL_TENANT_STATIC_CONTINUITY_FAILED; no plaintext or raw errors printed.');process.exitCode=1;}}
