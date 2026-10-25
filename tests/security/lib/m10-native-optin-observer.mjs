import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { m10DockerEnvironment } from './m10-release-evidence.mjs';

export function optinDistFingerprint(root) {
  const files = [];
  const walk = (path, prefix = '') => { for (const row of readdirSync(path, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${row.name}` : row.name;
    // The API owns a second source-SQL bind mount at this exact path. Host
    // compiled dist has an empty directory; SQL017/018 are independently
    // checked below against actual mounted bytes and the immutable ledger.
    // No other path, source map or compiled file is excluded from this digest.
    if (relative === 'infrastructure/migrations') { assert(row.isDirectory(), 'ACTUAL_MIGRATION_MOUNT_DIRECTORY_REQUIRED'); continue; }
    if (row.isDirectory()) walk(join(path, row.name), relative);
    else { assert(row.isFile(), 'DEPLOYED_API_DIST_REGULAR_FILES_REQUIRED'); files.push(relative); }
  } };
  walk(root); assert(files.length > 20, 'ACTUAL_DEPLOYED_API_DIST_REQUIRED');
  const digest = createHash('sha256');
  for (const name of files.sort()) digest.update(name).update('\0').update(readFileSync(join(root, name))).update('\0');
  return digest.digest('hex');
}

/** Runs only inside the owned API container against the console runtime DB.
 * All statements are SELECT or transaction controls under READ ONLY. No Kong
 * DB is contacted. Compiled dist (excluding only the separate SQL bind mount)
 * and immutable migration checks are actual observations,
 * while the source SHA association is supplied by Root's deployment receipt. */
export async function runOptinObserver(input) {
  let client;
  try {
    const { createRequire } = await import('node:module');
    const require = createRequire('/app/package.json');
    assert.equal(process.env.RELEASE_LAB_READY, 'true'); assert.equal(process.cwd(), '/app');
    assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-console-api-1');
    assert(['origin', 'no-native', 'failed-no-native'].includes(input.mode));
    const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
    for (const field of ['actorId', 'clusterId', 'workspaceId', 'key']) assert(uuid(input[field]));
    assert(typeof input.requestId === 'string' && input.requestId.length > 0 && input.requestId.length <= 128);
    assert(/^[a-f\d]{64}$/.test(input.runtimeSourceSha256));
    const url = new URL(process.env.DATABASE_URL);
    assert.equal(url.hostname, 'console-db'); assert.equal(url.port, '5432'); assert.equal(url.pathname, '/kongpilot'); assert.equal(url.username, 'kongpilot_lab_app');
    assert.equal(optinDistFingerprint('/app/apps/console-api/dist'), input.runtimeDistSha256);
    const { Client } = require('pg'); client = new Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000 }); await client.connect();
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); await client.query("SET LOCAL statement_timeout='5s'");
    const who = (await client.query('SELECT current_database() AS database,current_user AS role')).rows[0];
    assert.equal(who.database, 'kongpilot'); assert.equal(who.role, 'kongpilot_lab_app');
    for (const name of ['017_m10_governance.sql', '018_m10_configuration_origins.sql']) {
      const actual = createHash('sha256').update(readFileSync(`/app/apps/console-api/dist/infrastructure/migrations/${name}`)).digest('hex');
      assert.equal(input.migrations[name], actual);
      const row = (await client.query('SELECT checksum FROM schema_migrations WHERE name=$1', [name])).rows[0]; assert.equal(row?.checksum, actual);
    }
    const jobs = (await client.query('SELECT id,state,kind,request_id,plan_id,plan_revision,plan_hash,safe_progress,remote_started,remote_completed,error_code FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4', [input.clusterId, input.workspaceId, input.actorId, input.key])).rows;
    let facts;
    if (input.mode === 'no-native') {
      const mutations = (await client.query(`SELECT count(*)::int AS count,count(*) FILTER(WHERE remote_started)::int AS started,count(*) FILTER(WHERE remote_completed)::int AS completed
        FROM mutation_operations WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND
        (request_id=$4 OR configuration_job_id=ANY($5::uuid[]) OR idempotency_key=$6)`, [input.actorId, input.clusterId, input.workspaceId, input.requestId, jobs.map(row => row.id), input.key])).rows[0];
      assert.equal(jobs.length, 0); assert.equal(mutations.count, 0); assert.equal(mutations.started, 0); assert.equal(mutations.completed, 0);
      facts = { configurationJobCount: jobs.length, mutationCount: mutations.count, nativeStartedCount: mutations.started, nativeCompletedCount: mutations.completed };
    } else if (input.mode === 'failed-no-native') {
      for (const name of ['sourceClusterId','sourceWorkspaceId','inputPlanId','copiedPlanId','jobId','executionId']) assert(uuid(input[name]));
      assert.equal(jobs.length,1); const job=jobs[0];assert.equal(job.id,input.jobId);assert.equal(job.request_id,input.requestId);assert.equal(job.kind,'apply');
      assert.equal(job.state,'failed');assert.equal(job.error_code,'KONG_EXECUTION_CONTEXT_REQUIRED');assert.equal(job.remote_started,false);assert.equal(job.remote_completed,false);assert.equal(job.plan_id,input.copiedPlanId);
      const marker=(await client.query('SELECT required_origin_kind,required_origin_id,required_origin_hmac FROM configuration_jobs WHERE id=$1 AND actor_id=$2 AND cluster_id=$3 AND workspace_id=$4',[input.jobId,input.actorId,input.clusterId,input.workspaceId])).rows[0];
      assert.equal(marker?.required_origin_kind,'governance-promote');assert(uuid(marker.required_origin_id));assert(/^[a-f\d]{64}$/.test(marker.required_origin_hmac));
      const parent=(await client.query('SELECT * FROM governance_promotions WHERE id=$1',[marker.required_origin_id])).rows[0];
      assert.equal(parent?.actor_id,input.actorId);assert.equal(parent.cluster_id,input.sourceClusterId);assert.equal(parent.workspace_id,input.sourceWorkspaceId);assert.equal(parent.target_cluster_id,input.clusterId);assert.equal(parent.target_workspace_id,input.workspaceId);assert.equal(parent.plan_id,input.inputPlanId);assert.equal(parent.state,'ready');
      const binding=(await client.query('SELECT * FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3',[input.clusterId,input.workspaceId,input.jobId])).rows[0];
      assert.equal(binding?.origin_id,parent.id);assert.equal(binding.origin_kind,marker.required_origin_kind);assert.equal(binding.material_hmac,marker.required_origin_hmac);assert.equal(binding.source_cluster_id,parent.cluster_id);assert.equal(binding.source_workspace_id,parent.workspace_id);assert.equal(binding.comparison_id,parent.comparison_id);
      const bindings=(await client.query('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=ANY($3::uuid[])',[input.clusterId,input.workspaceId,[input.inputPlanId,input.copiedPlanId]])).rows;
      const originalBinding=bindings.find(row=>row.plan_id===input.inputPlanId&&row.plan_revision===parent.plan_revision&&row.plan_hash===parent.plan_hash&&row.job_id===parent.configuration_job_id);
      const copiedBinding=bindings.find(row=>row.plan_id===input.copiedPlanId&&row.plan_revision===job.plan_revision&&row.plan_hash===job.plan_hash&&row.job_id===job.id);
      assert(originalBinding&&copiedBinding);for(const row of [originalBinding,copiedBinding]){assert.equal(row.origin_id,parent.id);assert.equal(row.origin_kind,marker.required_origin_kind);assert.equal(row.material_hmac,marker.required_origin_hmac);}
      const executions=(await client.query('SELECT id,state,before_snapshot_id,before_snapshot_version,job_id,plan_id,plan_revision,plan_hash FROM configuration_executions WHERE job_id=$1 AND actor_id=$2 AND cluster_id=$3 AND workspace_id=$4',[input.jobId,input.actorId,input.clusterId,input.workspaceId])).rows;
      assert.equal(executions.length,1);const x=executions[0];assert.equal(x.id,input.executionId);assert.equal(x.job_id,job.id);assert.equal(x.plan_id,job.plan_id);assert.equal(x.plan_revision,job.plan_revision);assert.equal(x.plan_hash,job.plan_hash);
      assert.equal(x.before_snapshot_id,job.safe_progress.baselineSnapshotId);assert.equal(x.before_snapshot_version,job.safe_progress.baselineVersion);
      const inputVersion=(await client.query('SELECT expires_at,expires_at<=now() AS expired FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',[input.clusterId,input.workspaceId,input.inputPlanId,parent.plan_revision,parent.plan_hash])).rows[0];assert.equal(inputVersion?.expired,true);
      const mutations=(await client.query(`SELECT count(*)::int AS count,count(*) FILTER(WHERE remote_started)::int AS started,count(*) FILTER(WHERE remote_completed)::int AS completed
        FROM mutation_operations WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND(request_id=$4 OR configuration_job_id=$5 OR idempotency_key=$6)`,[input.actorId,input.clusterId,input.workspaceId,input.requestId,input.jobId,input.key])).rows[0];
      assert.equal(mutations.count,0);assert.equal(mutations.started,0);assert.equal(mutations.completed,0);
      const digest=async()=>{const row=(await client.query(`SELECT jsonb_build_object(
        'job',(SELECT to_jsonb(j) FROM configuration_jobs j WHERE j.id=$1),
        'execution',(SELECT to_jsonb(e) FROM configuration_executions e WHERE e.id=$2),
        'parent',(SELECT to_jsonb(p) FROM governance_promotions p WHERE p.id=$3),
        'job_binding',(SELECT to_jsonb(b) FROM configuration_job_origin_bindings b WHERE b.job_id=$1),
        'plans',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM configuration_plans p WHERE p.id=ANY($4::uuid[])),
        'plan_versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY v.plan_id,v.plan_revision) FROM configuration_plan_versions v WHERE v.plan_id=ANY($4::uuid[])),
        'plan_bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.plan_id,b.plan_revision) FROM configuration_plan_origin_bindings b WHERE b.plan_id=ANY($4::uuid[]))
        ) AS facts`,[input.jobId,input.executionId,parent.id,[input.inputPlanId,input.copiedPlanId]])).rows[0];return createHash('sha256').update(JSON.stringify(row.facts)).digest('hex');};
      const initialDigest=await digest(),finalDigest=await digest();assert.equal(finalDigest,initialDigest);
      facts={sourceClusterId:input.sourceClusterId,sourceWorkspaceId:input.sourceWorkspaceId,failedJobId:job.id,inputPlanId:input.inputPlanId,copiedPlanId:job.plan_id,executionId:x.id,
        configurationJobCount:1,jobState:job.state,jobErrorCode:job.error_code,jobRemoteStarted:job.remote_started,jobRemoteCompleted:job.remote_completed,
        mutationCount:mutations.count,nativeStartedCount:mutations.started,nativeCompletedCount:mutations.completed,immutableOriginMatched:true,
        inputPlanExpired:true,inputPlanExpiresAt:new Date(inputVersion.expires_at).toISOString(),initialDigest,finalDigest,transactionSnapshotDigestMatched:true};
    } else {
      for (const field of ['promotionId', 'jobId', 'planId', 'baselineSnapshotId', 'executionId']) assert(uuid(input[field]));
      assert(Number.isSafeInteger(input.baselineVersion) && input.baselineVersion > 0);
      assert.equal(jobs.length, 1); const job = jobs[0]; assert.equal(job.id, input.jobId); assert.equal(job.state, 'succeeded');
      assert.equal(job.safe_progress.baselineSnapshotId, input.baselineSnapshotId); assert.equal(job.safe_progress.baselineVersion, input.baselineVersion);
      const executions = (await client.query('SELECT id,state,before_snapshot_id,before_snapshot_version,job_id,plan_id,plan_revision,plan_hash FROM configuration_executions WHERE job_id=$1 AND actor_id=$2 AND cluster_id=$3 AND workspace_id=$4', [input.jobId, input.actorId, input.clusterId, input.workspaceId])).rows;
      assert.equal(executions.length, 1); const x = executions[0];
      assert.equal(x.id, input.executionId); assert.equal(job.safe_progress.executionId, x.id); assert.equal(x.state, 'succeeded');
      assert.equal(x.job_id, input.jobId); assert.equal(x.plan_id, job.plan_id); assert.equal(x.plan_revision, job.plan_revision); assert.equal(x.plan_hash, job.plan_hash);
      assert.equal(x.before_snapshot_id, input.baselineSnapshotId); assert.equal(x.before_snapshot_version, input.baselineVersion);
      const snapshot = (await client.query('SELECT snapshot_id,version FROM config_snapshot_versions WHERE cluster_id=$1 AND workspace_id=$2 AND snapshot_id=$3 AND version=$4', [input.clusterId, input.workspaceId, input.baselineSnapshotId, input.baselineVersion])).rows[0]; assert(snapshot);
      const binding = (await client.query('SELECT origin_id FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3', [input.clusterId, input.workspaceId, input.jobId])).rows[0]; assert.equal(binding?.origin_id, input.promotionId);
      const planBinding = (await client.query('SELECT origin_id FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 AND plan_id=$4 AND plan_revision=$5 AND plan_hash=$6', [input.clusterId, input.workspaceId, input.jobId, job.plan_id, job.plan_revision, job.plan_hash])).rows[0]; assert.equal(planBinding?.origin_id, input.promotionId);
      const original = (await client.query('SELECT actor_id,target_cluster_id,target_workspace_id,plan_id,plan_revision,plan_hash,configuration_job_id,state FROM governance_promotions WHERE id=$1', [input.promotionId])).rows[0];
      assert.equal(original?.actor_id, input.actorId); assert.equal(original.target_cluster_id, input.clusterId); assert.equal(original.target_workspace_id, input.workspaceId);
      assert.equal(original.plan_id, input.planId); assert.equal(original.state, 'ready');
      const initialPlan = (await client.query('SELECT origin_id FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 AND plan_id=$4 AND plan_revision=$5 AND plan_hash=$6', [input.clusterId, input.workspaceId, original.configuration_job_id, original.plan_id, original.plan_revision, original.plan_hash])).rows[0]; assert.equal(initialPlan?.origin_id, input.promotionId);
      facts = { actualBaselineSnapshotId: x.before_snapshot_id, actualBaselineVersion: x.before_snapshot_version, sourcePlanId: input.planId, actualExecutionId: x.id, immutableOriginMatched: true };
    }
    await client.query('COMMIT');
    return { passed: true, mode: input.mode, consoleReadOnly: true, requestId: input.requestId, actorId: input.actorId, clusterId: input.clusterId, workspaceId: input.workspaceId,
      runtimeSourceSha256: input.runtimeSourceSha256, runtimeSourceAssociation: 'Root deployment receipt', runtimeDistMatched: true, migrationChecksumsMatched: true,
      kongDatabaseAccess: false, independentWireLogClaim: false, ...facts };
  } finally { if (client) { try { await client.query('ROLLBACK'); } catch {} await client.end(); } }
}

export function optinObserverProgram(input) {
  return `${readFileSync(new URL(import.meta.url), 'utf8').split('export function optinObserverProgram')[0]
    .replace("import { m10DockerEnvironment } from './m10-release-evidence.mjs';", '')
    .replace("import { spawnSync } from 'node:child_process';", '')}
try { process.stdout.write(JSON.stringify(await runOptinObserver(${JSON.stringify(input)}))+String.fromCharCode(10)); }
catch { process.stdout.write(JSON.stringify({passed:false,code:'M10_OPTIN_ACTUAL_CONSOLE_OBSERVATION_FAILED'})+String.fromCharCode(10)); process.exitCode=1; }
`;
}

export function observeOptinConsole(input) {
  const source = optinObserverProgram(input);
  const result = spawnSync('docker', ['--host=unix:///var/run/docker.sock', 'exec', '--env', 'GOMAXPROCS=2', '-i', 'kongos-ram-tool-m08-20261012-a3',
    'docker', '--host=unix:///run/docker-production.sock', 'exec', '-i', '-e', 'RELEASE_LAB_READY=true', '-e', 'RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1',
    'kongpilot-release-lab-console-api-1', 'node', '--input-type=module'], { input: source, encoding: 'utf8', env: m10DockerEnvironment(), timeout: 20000, maxBuffer: 1024 * 1024 });
  assert(!result.error && result.status === 0, 'M10_OPTIN_ACTUAL_CONSOLE_OBSERVATION_FAILED');
  let proof; try { proof = JSON.parse(result.stdout); } catch { throw Error('M10_OPTIN_ACTUAL_CONSOLE_PROOF_INVALID'); }
  assert.equal(proof.passed, true); return proof;
}
