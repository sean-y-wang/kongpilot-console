import {describe,it,expect} from 'vitest';
// @ts-expect-error deployment source module is JavaScript.
import {assessProductionBuildStep,assessOwnedBuildCache,productionPreparationPlan,PRODUCTION_BUILD_ORDER} from '../../deploy/scripts/production-preparation.mjs';

const digest='a'.repeat(64);
const budget=()=>({service:'console-api',driver:'vfs',availableBytes:944197632,peakBound:{bytes:500000000,pendingBaseDownloadBytes:100000000,driver:'vfs',kind:'conservative-component-bound',sourceFreezeSha256:digest,lockSha256:digest,evidencePath:'public/run-component-bound.json'},writeReserve:{bytes:100000000,evidencePath:'public/protected-write-reserve.json'}});
const cache=()=>({id:'123456789abcdefghijklmno',sizeBytes:1000,createdAt:'2026-10-11T00:00:00Z',shared:false,reclaimable:true,containerReferenceCount:0,releaseOrRollbackReferenced:false,retiredBuild:true});
const inventory=()=>({ownedIds:[cache().id],protectedIds:[],inventoryComplete:true,allContainerReferencesIncluded:true,releaseAndRollbackInventoryIncluded:true});
const options=()=>({project:'kongos-production-smoke',restoreProject:'kongos-production-restore',envFile:'/synthetic/production/production.env',restoreEnvFile:'/synthetic/restore/production.env',metricsDirectory:'/synthetic/production/metrics',restoreMetricsDirectory:'/synthetic/restore/metrics',backupDirectory:'/synthetic/private-backups/run',artifactDirectory:'/synthetic/public-reports/run',publicCaFile:'/synthetic/public-ca/ca.crt',consoleOrigin:'https://console.example.test:18443',portalOrigin:'https://portal.example.test:19443',includeRunner:true});

describe('production build evidence and precise cache proposals without runtime',()=>{
 it('does not infer a peak from runtime image/dist sizes or a 30GiB threshold',()=>{
  expect(assessProductionBuildStep({service:'console-api',driver:'vfs',availableBytes:944197632,imageSizeBytes:227000000,distSizeBytes:3100000})).toMatchObject({decision:'unproven',buildExecuted:false});
  expect(assessProductionBuildStep(budget())).toMatchObject({decision:'fits-bound',requiredBytes:700000000,runtimeVerified:false});
 });
 it('includes downloaded base layers and protected writes and rejects invalid/overflow evidence',()=>{
  const b=budget();b.peakBound.pendingBaseDownloadBytes=400000000;expect(assessProductionBuildStep(b).decision).toBe('insufficient');
  for(const change of [(v:any)=>v.peakBound.driver='overlay2',(v:any)=>v.peakBound.kind='image-size-only',(v:any)=>v.peakBound.bytes=-1,(v:any)=>v.peakBound.sourceFreezeSha256='invalid',(v:any)=>v.peakBound.bytes=Number.MAX_SAFE_INTEGER]){const v=budget();change(v);expect(()=>assessProductionBuildStep(v)).toThrow('PRODUCTION_PREPARATION_INPUT_INVALID');}
 });
 it('returns only safe metadata and a potential byte count with no automatic delete authorization',()=>{
  const row={...cache(),rawDescription:'SYNTHETIC_SECRET_CANARY'},result=assessOwnedBuildCache([row],inventory());expect(result).toMatchObject({potentialReclaimableBytes:1000,actualReclaimedBytes:null,deletionAuthorized:false,deletionExecuted:false});expect(JSON.stringify(result)).not.toContain('SYNTHETIC_SECRET_CANARY');
 });
 it('rejects owned but shared/protected/current/unknown references; inventories include stopped containers',()=>{
  const changes=[(v:any)=>v.shared=true,(v:any)=>delete v.shared,(v:any)=>v.reclaimable=false,(v:any)=>v.containerReferenceCount=1,(v:any)=>delete v.containerReferenceCount,(v:any)=>v.releaseOrRollbackReferenced=true,(v:any)=>v.retiredBuild=false];
  for(const change of changes){const v=cache();change(v);expect(assessOwnedBuildCache([v],inventory()).rows[0].eligibleForExactIdReview).toBe(false);}
  for(const changed of [{...inventory(),ownedIds:[]},{...inventory(),protectedIds:[cache().id]},{...inventory(),allContainerReferencesIncluded:false},{...inventory(),releaseAndRollbackInventoryIncluded:false}])expect(assessOwnedBuildCache([cache()],changed).potentialReclaimableBytes).toBe(0);
  expect(()=>assessOwnedBuildCache([cache(),cache()],inventory())).toThrow();
 });
});

describe('source-only independent production and third restore command templates',()=>{
 it('builds one API image for migrator and serial app services with no development/global/pull/cleanup command',()=>{
  const plan=productionPreparationPlan(options()),builds=plan.commands.filter((row:any)=>row.phase==='serial-bounded-image-build');
  expect(builds.map((row:any)=>row.service)).toEqual(PRODUCTION_BUILD_ORDER);expect(builds[0].migratorSharesApiImage).toBe(true);
  expect(builds.every((row:any)=>row.argv.includes('--pull=false'))).toBe(true);expect(plan).toMatchObject({sourceOnly:true,runtimeExecuted:false,automaticCleanup:false});
  expect(JSON.stringify(plan)).not.toMatch(/compose\.development|multicluster-test|portal-acceptance|system prune|volume prune|--insecure|--tls-skip|down.*--volumes/);
 });
 it('starts only base services before explicit initial enrollment, storage prep and observability',()=>{
  const p=productionPreparationPlan(options()),base=p.commands.find((row:any)=>row.phase==='base-cold-start');expect(base.argv.slice(base.argv.indexOf('--no-build')+1)).not.toContain('prometheus');expect(base.argv).not.toContain('console-deck-runner');
  const enrollment=p.commands.filter((row:any)=>row.phase==='initial-new-project-metrics');expect(enrollment).toHaveLength(1);expect(enrollment[0].argv).toContain('--production');expect(enrollment[0].argv).not.toContain('--rotate-confirmed');expect(enrollment[0].argv).not.toContain('--test-private-reference');
  expect(p.commands.findIndex((row:any)=>row.phase==='new-project-prometheus-volume-permissions')).toBeLessThan(p.commands.findIndex((row:any)=>row.phase==='start-prepared-observability'));
 });
 it('requires independent HTTPS cookie hosts/project/private env/material paths',()=>{
  const changes=[(o:any)=>o.project='kongos-console',(o:any)=>o.restoreProject=o.project,(o:any)=>o.restoreEnvFile=o.envFile,(o:any)=>o.restoreMetricsDirectory=o.metricsDirectory,(o:any)=>o.portalOrigin='http://portal.example.test',(o:any)=>o.portalOrigin='https://console.example.test:19443',(o:any)=>o.consoleOrigin='https://user:secret@console.example.test',(o:any)=>o.artifactDirectory=o.metricsDirectory+'/reports',(o:any)=>o.backupDirectory=o.artifactDirectory+'/dump'];
  for(const change of changes){const o=options();change(o);expect(()=>productionPreparationPlan(o)).toThrow('PRODUCTION_PREPARATION_INPUT_INVALID');}
 });
 it('uses explicit local socket and exact four production files; runner adds only its TLS overlay',()=>{
  const plan=productionPreparationPlan(options());for(const row of plan.commands.filter((r:any)=>r.command==='docker')){expect(row.argv.slice(0,4)).toEqual(['--host=unix:///var/run/docker.sock','compose','--project-name',row.phase.startsWith('third-project')?'kongos-production-restore':'kongos-production-smoke']);}
  const collector=plan.commands.find((r:any)=>r.service==='telemetry-collector');expect(collector.argv.filter((_:string,i:number)=>collector.argv[i-1]==='-f')).toEqual(['docker-compose.yml','deploy/compose/compose.production.yml','deploy/compose/compose.metrics.yml','deploy/compose/compose.production-metrics.yml']);
 });
 it('verifies actual CA and hostname, never adds an insecure mode',()=>{
  const p=productionPreparationPlan(options()),tls=p.commands.filter((r:any)=>r.phase==='real-tls-hostname-verification');expect(tls).toHaveLength(2);expect(tls.every((r:any)=>r.argv.includes('-verify_return_error')&&r.argv.includes('-verify_hostname')&&r.argv.includes('-CAfile'))).toBe(true);
 });
 it('dumps matching PG containers only to private files and restores into third project before migrator',()=>{
  const plan=productionPreparationPlan(options()),dumps=plan.commands.filter((r:any)=>r.phase==='coordinated-postgres-dump'),restores=plan.commands.filter((r:any)=>r.phase==='third-project-postgres-restore');expect(dumps).toHaveLength(2);expect(restores).toHaveLength(2);
  for(const row of dumps){expect(row.privateStdoutFile.startsWith('/synthetic/private-backups/run/')).toBe(true);expect(row.stdoutMode).toBe('0600_WX_PRIVATE_NEVER_PUBLIC');expect(row.argv).toContain('--no-owner');expect(row.argv).toContain('--no-acl');}
  for(const row of restores){expect(row.argv).toContain('--exit-on-error');expect(row.argv[3]).toBe('kongos-production-restore');expect(row.privateStdinFile.startsWith('/synthetic/private-backups/run/')).toBe(true);}
  expect(plan.commands.at(-1).phase).toBe('third-project-migration-check-and-runtime-role');expect(plan.commands.at(-1).argv.slice(-4)).toEqual(['run','--rm','--no-deps','console-migrations']);
 });
 it('does not start restored API or re-enroll/rotate restored metrics before egress/session/unknown-delivery control',()=>{
  const p=productionPreparationPlan(options());expect(p.restoredApiAutomaticallyStarted).toBe(false);expect(p.remainingProofs).toContain('BEFORE_OPENING_RESTORE_API_ENFORCE_PROVIDER_EGRESS_AND_OLD_SESSION_FENCE');
  const restored=p.commands.filter((r:any)=>r.phase.startsWith('third-project'));expect(restored.some((r:any)=>r.argv.includes('console-api'))).toBe(false);expect(restored.some((r:any)=>r.argv.includes('enroll-metrics.mjs'))).toBe(false);
 });
});
