import {resolve,sep} from 'node:path';

// Pure preparation only: importing/calling this file does not read files,
// inspect Docker, generate credentials, issue requests, build or delete anything.
const fail=()=>{throw new Error('PRODUCTION_PREPARATION_INPUT_INVALID');};
const bytes=value=>Number.isSafeInteger(value)&&value>=0;
const sha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const text=value=>typeof value==='string'&&value.length>0&&value.length<=4096&&!/[\r\n\0]/.test(value);
const path=value=>{if(!text(value)||value.startsWith('-'))fail();return resolve(value);};
const project=value=>{if(typeof value!=='string'||!/^[a-z][a-z0-9_-]{1,62}$/.test(value)||['kongos-console','kongpilot-console'].includes(value))fail();return value;};
const publicOrigin=value=>{let url;try{url=new URL(value);}catch{fail();}if(url.protocol!=='https:'||url.origin!==value||url.username||url.password||!url.hostname)fail();return url;};

export const PRODUCTION_BASE_FILES=Object.freeze(['docker-compose.yml','deploy/compose.production.yml']);
export const PRODUCTION_METRICS_FILES=Object.freeze([...PRODUCTION_BASE_FILES,'deploy/compose.metrics.yml','deploy/compose.production-metrics.yml']);
export const PRODUCTION_GITOPS_FILES=Object.freeze([...PRODUCTION_METRICS_FILES,'deploy/compose.gitops.yml','deploy/compose.production-gitops.yml']);
export const PRODUCTION_BUILD_ORDER=Object.freeze(['console-api','console-web','portal-web','telemetry-collector','console-deck-runner']);

/** A runtime image size is not an upper bound on a VFS build peak. A positive
 * decision requires a run-specific upper bound and a protected-write reserve.
 * The evidence paths are public receipt selectors, never read by this helper. */
export function assessProductionBuildStep(facts){
 if(!facts||!bytes(facts.availableBytes)||!PRODUCTION_BUILD_ORDER.includes(facts.service)||facts.driver!=='vfs')fail();
 const common={service:facts.service,availableBytes:facts.availableBytes,driver:facts.driver,runtimeVerified:false,buildExecuted:false};
 const bound=facts.peakBound,reserve=facts.writeReserve;
 if(!bound||!reserve)return {...common,decision:'unproven',reason:'RUN_SPECIFIC_PEAK_AND_RESERVE_EVIDENCE_REQUIRED'};
 if(!bytes(bound.bytes)||!bytes(reserve.bytes)||!bytes(bound.pendingBaseDownloadBytes)||!sha(bound.sourceFreezeSha256)||!sha(bound.lockSha256)||bound.driver!==facts.driver||!['measured-matching-build','conservative-component-bound'].includes(bound.kind)||!text(bound.evidencePath)||!text(reserve.evidencePath))fail();
 const required=bound.bytes+bound.pendingBaseDownloadBytes+reserve.bytes;if(!Number.isSafeInteger(required))fail();
 return {...common,decision:facts.availableBytes>=required?'fits-bound':'insufficient',reason:facts.availableBytes>=required?'BOUND_PLUS_PROTECTED_WRITE_RESERVE_FITS':'BOUND_PLUS_PROTECTED_WRITE_RESERVE_EXCEEDS_FREE',requiredBytes:required,remainingAfterBoundBytes:facts.availableBytes-required,sourceFreezeSha256:bound.sourceFreezeSha256,lockSha256:bound.lockSha256,peakEvidencePath:bound.evidencePath,reserveEvidencePath:reserve.evidencePath};
}

/** Screen fresh safe metadata; this creates a review proposal, not deletion
 * permission. Reclaimable bytes are potential, never actual recovered bytes. */
export function assessOwnedBuildCache(candidates,{ownedIds,protectedIds=[],inventoryComplete=false,allContainerReferencesIncluded=false,releaseAndRollbackInventoryIncluded=false}={}){
 if(!Array.isArray(candidates)||!Array.isArray(ownedIds)||!Array.isArray(protectedIds)||candidates.length>1000||new Set(candidates.map(row=>row?.id)).size!==candidates.length)fail();
 const owned=new Set(ownedIds),protectedSet=new Set(protectedIds),complete=inventoryComplete===true&&allContainerReferencesIncluded===true&&releaseAndRollbackInventoryIncluded===true;
 const rows=candidates.map(row=>{
  if(!row||typeof row.id!=='string'||!/^[a-z0-9]{12,64}$/.test(row.id)||!bytes(row.sizeBytes)||typeof row.createdAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(row.createdAt)||!Number.isFinite(Date.parse(row.createdAt)))fail();
  const reasons=[];if(!complete)reasons.push('INVENTORY_INCOMPLETE');if(!owned.has(row.id))reasons.push('NOT_EXPLICITLY_OWNED');if(protectedSet.has(row.id)||row.releaseOrRollbackReferenced!==false)reasons.push('PROTECTED_OR_RELEASE_REFERENCE_UNPROVEN');if(row.shared!==false)reasons.push('SHARED_OR_UNKNOWN');if(row.reclaimable!==true)reasons.push('NOT_RECLAIMABLE_OR_UNKNOWN');if(row.containerReferenceCount!==0)reasons.push('CONTAINER_REFERENCE_OR_UNKNOWN');if(row.retiredBuild!==true)reasons.push('BUILD_NOT_RETIRED');
  return {id:row.id,sizeBytes:row.sizeBytes,createdAt:row.createdAt,eligibleForExactIdReview:reasons.length===0,reasons};
 });
 const total=rows.filter(row=>row.eligibleForExactIdReview).reduce((sum,row)=>sum+row.sizeBytes,0);if(!Number.isSafeInteger(total))fail();
 return {rows,potentialReclaimableBytes:total,actualReclaimedBytes:null,deletionAuthorized:false,deletionExecuted:false};
}

/** Return argv arrays and explicit private stdin/stdout selectors. No shell
 * interpolation, secret values, runtime env lookup or command execution. */
export function productionPreparationPlan(input){
 if(!input||typeof input!=='object'||Array.isArray(input))fail();
 const name=project(input.project),restoreName=project(input.restoreProject);if(name===restoreName)fail();
 const env=path(input.envFile),restoreEnv=path(input.restoreEnvFile),metrics=path(input.metricsDirectory),restoreMetrics=path(input.restoreMetricsDirectory),backup=path(input.backupDirectory),reports=path(input.artifactDirectory),ca=path(input.publicCaFile);
 const origin=publicOrigin(input.consoleOrigin),portal=publicOrigin(input.portalOrigin);
 if(origin.hostname===portal.hostname||env===restoreEnv||metrics===restoreMetrics||[env,restoreEnv].some(p=>p===reports||p.startsWith(reports+sep))||[metrics,restoreMetrics].some(dir=>[env,restoreEnv,reports,backup].some(p=>p===dir||p.startsWith(dir+sep)))||backup===reports||backup.startsWith(reports+sep)||reports.startsWith(backup+sep))fail();
 const includeRunner=input.includeRunner===true;
 const compose=(restored=false,layer='base')=>['--host=unix:///var/run/docker.sock','compose','--project-name',restored?restoreName:name,'--env-file',restored?restoreEnv:env,...(layer==='base'?PRODUCTION_BASE_FILES:layer==='metrics'?PRODUCTION_METRICS_FILES:PRODUCTION_GITOPS_FILES).flatMap(file=>['-f',file]),...(layer!=='base'?['--profile','observability']:[]),...(layer==='gitops'?['--profile','gitops-runner']:[])];
 const command=(phase,argv,extra={})=>({phase,command:'docker',argv,...extra});
 const completeLayer=includeRunner?'gitops':'metrics';
 const starts=['kong-db','kong-migrations','kong','console-db','redis','console-migrations','console-api','console-web','portal-web'];
 const commands=[
  {phase:'new-private-environment',command:'node',argv:['deploy/scripts/generate-env.mjs',env,'--production','--portal-origin',portal.origin],preconditions:['NEW_0700_PARENT','TARGET_DOES_NOT_EXIST','REVIEW_PRODUCTION_TEMPLATE_NONSECRET_PARAMETERS']},
  command('effective-config-policy-before-build',[...compose(false,completeLayer),'config','--format','json'],{stdout:'RAM_ONLY_ASSERT_PRODUCTION_COMPOSITION_NEVER_PUBLISH_ENV'}),
  ...PRODUCTION_BUILD_ORDER.filter(service=>includeRunner||service!=='console-deck-runner').map(service=>command('serial-bounded-image-build',[...compose(false,service==='console-deck-runner'?'gitops':service==='telemetry-collector'?'metrics':'base'),'build','--pull=false',service],{service,preconditions:['EXACT_SOURCE_AND_LOCK_FREEZE','RUN_SPECIFIC_PEAK_AND_RESERVE_EVIDENCE','BUILD_ONLY_PROXY_CA_SECRET_WHEN_REQUIRED'],migratorSharesApiImage:service==='console-api'})),
  command('base-cold-start',[...compose(false,completeLayer),'up','-d','--no-build',...starts],{preconditions:['NEW_PROJECT_VOLUMES_NETWORKS_AND_SECRETS','REAL_SAN_MATCHED_TLS_KEYS_UID101_READABLE','PUBLIC_CONFIGS_0644','FINAL_IMAGE_IDS_MATCH','API_AND_MIGRATOR_SAME_IMAGE']}),
  {phase:'initial-new-project-metrics',command:'node',argv:['deploy/scripts/enroll-metrics.mjs','--production','--project',name,'--env-file',env,'--metrics-directory',metrics,'--output',resolve(reports,'metrics-enrollment.json'),'--discover'],preconditions:['BASE_API_READY','REAL_REGISTERED_HEALTHY_NODE_WITH_PROMETHEUS_PLUGIN']},
  {phase:'new-project-prometheus-volume-permissions',command:'node',argv:['deploy/scripts/prepare-metrics-storage.mjs','--production','--project',name,'--env-file',env,'--metrics-directory',metrics,'--output',resolve(reports,'metrics-storage.json')]},
  command('start-prepared-observability',[...compose(false,'metrics'),'up','-d','--no-build','prometheus','loki','telemetry-collector']),
  ...[origin,portal].map(url=>({phase:'real-tls-hostname-verification',command:'openssl',argv:['s_client','-connect',`${url.hostname}:${url.port||443}`,'-servername',url.hostname,'-CAfile',ca,'-verify_hostname',url.hostname,'-verify_return_error','-brief'],stdin:'EOF',preconditions:['DNS_OR_LOCAL_MAPPING_POINTS_ONLY_TO_NEW_PROJECT'],rawOutput:'PRIVATE_OR_DISCARD'})),
  command('coordinated-backup-writer-stop',[...compose(false,'metrics'),'stop','console-api','kong','telemetry-collector'],{preconditions:['ONLY_NEW_ACCEPTANCE_PROJECT','INGRESS_MAINTENANCE_AND_PROXY_OAUTH_TRAFFIC_STOPPED','UTC_BACKUP_WINDOW_STARTED']}),
  ...[['console-db','kongos','kongos','console.dump'],['kong-db','kong','kong','kong-primary.dump']].map(([service,user,db,file])=>command('coordinated-postgres-dump',[...compose(),'exec','-T',service,'pg_dump','-U',user,'-d',db,'-Fc','--no-owner','--no-acl'],{privateStdoutFile:resolve(backup,file),stdoutMode:'0600_WX_PRIVATE_NEVER_PUBLIC',postgresToolSource:'MATCHING_DATABASE_CONTAINER'})),
  command('coordinated-redis-save',[...compose(),'exec','-T','redis','/bin/sh','-ec','REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli SAVE >/dev/null']),
  command('coordinated-redis-stop',[...compose(),'stop','redis']),
  command('coordinated-redis-copy',[...compose(),'cp','--archive','redis:/data',resolve(backup,'redis')],{preconditions:['NEW_0700_BACKUP_PARENT','ENCRYPT_OFFHOST_WITH_ROOT_KEYS_AND_PRIVATE_METRICS_MATERIAL','RECORD_ALL_DUMP_EXITS_AND_HASHES']}),
  command('third-project-database-start',[...compose(true),'up','-d','--no-build','console-db','kong-db'],{preconditions:['THIRD_PROJECT_FRESH_VOLUMES_DISTINCT_IPAM_PORTS','FROZEN_SAME_DB_MAJOR_AND_IMAGE_DIGESTS','RESTORE_ROOT_KEYS_AND_METRICS_MATERIAL_SECURELY_NO_ENROLLMENT']}),
  ...[['console-db','kongos','kongos','console.dump'],['kong-db','kong','kong','kong-primary.dump']].map(([service,user,db,file])=>command('third-project-postgres-restore',[...compose(true),'exec','-T',service,'pg_restore','-U',user,'-d',db,'--no-owner','--no-acl','--exit-on-error'],{privateStdinFile:resolve(backup,file),postgresToolSource:'MATCHING_DATABASE_CONTAINER'})),
  command('third-project-redis-create',[...compose(true),'create','redis']),
  command('third-project-redis-restore',[...compose(true),'cp','--archive',resolve(backup,'redis')+'/.','redis:/data/']),
  command('third-project-redis-start',[...compose(true),'up','-d','--no-build','redis']),
  command('third-project-migration-check-and-runtime-role',[...compose(true),'run','--rm','--no-deps','console-migrations'],{preconditions:['ORIGINAL_SQL_CHECKSUMS_000_THROUGH_011_EXACT','ROOT_KEYS_AND_PRIVATE_MATERIAL_RESTORED','RESTORE_NOT_A_NEW_ENROLLMENT']}),
 ];
 return {sourceOnly:true,runtimeExecuted:false,project:name,restoreProject:restoreName,commands,automaticCleanup:false,restoredApiAutomaticallyStarted:false,remainingProofs:['REAL_DOCKER_UID_RO_CAPS_NETWORK_AND_RUNTIME_ROLE','TLS_HEALTH_HEADERS_PORTAL_BOUNDARIES','FINAL_IMAGE_SBOM_AND_FRESH_DB_CVE_SCAN','M0_M8_TARGETED_SMOKE_AND_REQUEST_AUDIT_MATCH','BEFORE_OPENING_RESTORE_API_ENFORCE_PROVIDER_EGRESS_AND_OLD_SESSION_FENCE','ACTUAL_RESTORED_AES_PROXY_CREDENTIALS_AUDIT_CHECKPOINT_AND_RPO_RTO'],restoreMetricsDirectory:restoreMetrics};
}
