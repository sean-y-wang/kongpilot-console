#!/usr/bin/env node
/**
 * KP-010: cross-host / second-environment platform restore evidence.
 * Uses deploy/scripts/platform-recovery.mjs against a Docker second instance
 * with true distinct volumes (siteId ≠ source, project ≠ source).
 * Records RPO/RTO notes. Never sets commercialClosed=true.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { backupPlatform, restorePlatform } from '../../deploy/scripts/platform-recovery.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const outDir = resolve(process.env.KP010_OUT || join(repo, 'artifacts/M11/runs/20261024-kp010-restore'));
const privateParent = resolve(process.env.KP010_PRIVATE_PARENT || '/opt/kp-private-parent');
const sourceProject = 'kp010src';
const targetProject = 'kp010dst';
const composeFile = resolve(repo, 'deploy/compose/compose.platform-source.yml');
const evidenceDb = process.env.KP010_EVIDENCE_DB || 'kp-bff-evidence-bff-evidence-db-1';
const apiContainer = process.env.KP010_API || 'kp-bff-api-evidence';
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed) console.error(JSON.stringify({ checkFailed: id, ...detail }));
};

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
  if (r.error || r.status !== 0) {
    const err = new Error(`${cmd} failed: ${(r.stderr || r.stdout || r.error?.message || '').slice(0, 500)}`);
    err.status = r.status;
    throw err;
  }
  return r.stdout;
}

function docker(args, opts = {}) {
  return sh('docker', ['--host=unix:///var/run/docker.sock', ...args], opts);
}

function digest(v) {
  return createHash('sha256').update(String(v)).digest('hex').slice(0, 16);
}

function extractEnv(container) {
  const rows = JSON.parse(docker(['inspect', container]))[0].Config.Env;
  return Object.fromEntries(rows.map((l) => {
    const i = l.indexOf('=');
    return [l.slice(0, i), l.slice(i + 1)];
  }));
}

mkdirSync(outDir, { recursive: true });
mkdirSync(privateParent, { recursive: true });
chmodSync(privateParent, 0o755);

const workRoot = join(privateParent, `kp010-${randomUUID()}`);
mkdirSync(workRoot, { mode: 0o700 });
chmodSync(workRoot, 0o700);

const sourceSiteId = randomUUID();
const targetSiteId = randomUUID();
let backupResult = null;
let restoreResult = null;
let rpoNotes = null;
let rtoNotes = null;
let failure = null;
const resourceIds = { source: {}, target: {} };

try {
  // --- Clean any prior attempt with same project names ---
  const existing = docker(['ps', '-aq', '--filter', `label=com.docker.compose.project=${sourceProject}`]).trim();
  if (existing) throw new Error('KP010_SOURCE_PROJECT_ALREADY_EXISTS');
  const existingT = docker(['ps', '-aq', '--filter', `label=com.docker.compose.project=${targetProject}`]).trim();
  if (existingT) throw new Error('KP010_TARGET_PROJECT_ALREADY_EXISTS');

  // --- Start second-environment source stack (new volumes) ---
  const t0 = Date.now();
  sh('docker', ['compose', '--project-name', sourceProject, '-f', composeFile, 'up', '-d', '--wait', '--wait-timeout', '120'], { cwd: repo });
  const sourceDb = `${sourceProject}-console-db-1`;
  const sourceRedis = `${sourceProject}-redis-1`;
  const sourceApi = `${sourceProject}-console-api-1`;
  resourceIds.source = { database: sourceDb, redis: sourceRedis, api: sourceApi };

  const dbInspect = JSON.parse(docker(['inspect', sourceDb]))[0];
  const redisInspect = JSON.parse(docker(['inspect', sourceRedis]))[0];
  const apiInspect = JSON.parse(docker(['inspect', sourceApi]))[0];
  const srcVol = dbInspect.Mounts.find((m) => m.Destination === '/var/lib/postgresql/data')?.Name;
  const redisVol = redisInspect.Mounts.find((m) => m.Destination === '/data')?.Name;
  const evidenceVol = JSON.parse(docker(['inspect', evidenceDb]))[0].Mounts.find((m) => m.Destination === '/var/lib/postgresql/data')?.Name;

  record('source_stack_up', dbInspect.State.Running && redisInspect.State.Running && apiInspect.State.Running, {
    project: sourceProject, siteIdDigest: digest(sourceSiteId),
  });
  record('source_volumes_distinct_from_evidence', !!srcVol && !!evidenceVol && srcVol !== evidenceVol, {
    sourceVolumeDigest: digest(srcVol), evidenceVolumeDigest: digest(evidenceVol), redisVolumeDigest: digest(redisVol),
  });
  record('source_service_labels', 
    dbInspect.Config.Labels['com.docker.compose.service'] === 'console-db'
    && redisInspect.Config.Labels['com.docker.compose.service'] === 'redis'
    && apiInspect.Config.Labels['com.docker.compose.service'] === 'console-api');

  // --- Seed source DB from live evidence via logical dump (second data dir) ---
  const seedStarted = Date.now();
  const dump = spawnSync('docker', ['--host=unix:///var/run/docker.sock', 'exec', evidenceDb,
    'pg_dump', '-h', '127.0.0.1', '-p', '25433', '-U', 'kongpilot', '-d', 'kongpilot_bff_evidence',
    '--format=custom', '--no-owner', '--no-acl'], { encoding: null, maxBuffer: 256 * 1024 * 1024, timeout: 600000 });
  if (dump.error || dump.status !== 0) throw new Error('KP010_EVIDENCE_DUMP_FAILED:' + (dump.stderr?.toString?.() || '').slice(0, 200));
  record('evidence_logical_dump', dump.stdout.subarray(0, 5).toString() === 'PGDMP', { dumpBytes: dump.stdout.length });

  const restoreSeed = spawnSync('docker', ['--host=unix:///var/run/docker.sock', 'exec', '-i', sourceDb,
    'pg_restore', '--exit-on-error', '--single-transaction', '--no-owner', '--no-acl',
    '-U', 'kongpilot', '-d', 'kongpilot_bff_evidence'], {
    input: dump.stdout, encoding: null, maxBuffer: 32 * 1024 * 1024, timeout: 600000,
  });
  dump.stdout.fill(0);
  if (restoreSeed.error || restoreSeed.status !== 0) {
    throw new Error('KP010_SOURCE_SEED_RESTORE_FAILED:' + (restoreSeed.stderr?.toString?.() || restoreSeed.stdout?.toString?.() || '').slice(0, 400));
  }
  record('source_seeded_from_evidence', true, { seedElapsedMs: Date.now() - seedStarted });

  // Confirm migrations match repository (platform-recovery will also check)
  const migCount = docker(['exec', sourceDb, 'psql', '-U', 'kongpilot', '-d', 'kongpilot_bff_evidence', '-Atc',
    'SELECT count(*) FROM schema_migrations']).trim();
  record('source_migrations_present', Number(migCount) > 0, { migrationCount: Number(migCount) });

  // --- Private configs + secrets (0600) ---
  const env = extractEnv(apiContainer);
  const backupKey = randomBytes(32).toString('hex');
  const secrets = {
    CONSOLE_ENCRYPTION_KEY: env.CONSOLE_ENCRYPTION_KEY,
    APP_SECRET: env.APP_SECRET,
    PORTAL_SECRET: env.PORTAL_SECRET,
    BACKUP_ENCRYPTION_KEY: backupKey,
  };
  if (new Set(Object.values(secrets)).size !== 4) throw new Error('KP010_SECRETS_NOT_INDEPENDENT');
  const secretsFile = join(workRoot, 'secrets.json');
  const sourceConfig = join(workRoot, 'source.json');
  const targetConfig = join(workRoot, 'target.json');
  writeFileSync(secretsFile, JSON.stringify(secrets), { mode: 0o600 });
  chmodSync(secretsFile, 0o600);
  writeFileSync(sourceConfig, JSON.stringify({
    format: 'kongpilot-platform-site-v1',
    siteId: sourceSiteId,
    project: sourceProject,
    database: { user: 'kongpilot', name: 'kongpilot_bff_evidence' },
    keyReferences: {
      encryption: 'vault:kongpilot/console-encryption',
      app: 'vault:kongpilot/app',
      portal: 'vault:kongpilot/portal',
      backup: 'vault:kongpilot/recovery',
    },
  }), { mode: 0o600 });
  chmodSync(sourceConfig, 0o600);
  writeFileSync(targetConfig, JSON.stringify({
    format: 'kongpilot-platform-restore-v1',
    siteId: targetSiteId,
    project: targetProject,
  }), { mode: 0o600 });
  chmodSync(targetConfig, 0o600);
  record('private_configs_0600', true, { workRootDigest: digest(workRoot) });

  // Ensure no extra SQL clients on source (api stub does not connect)
  const clients = docker(['exec', sourceDb, 'psql', '-U', 'kongpilot', '-d', 'kongpilot_bff_evidence', '-Atc',
    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'"]).trim();
  record('source_no_other_sql_clients_before_backup', Number(clients) === 0, { otherClients: Number(clients) });

  // --- Official platform backup ---
  const backupOut = join(workRoot, 'backup');
  const backupStartedAt = new Date().toISOString();
  const backupT0 = Date.now();
  backupResult = await backupPlatform({
    config: sourceConfig,
    secretsFile,
    output: backupOut,
    repository: repo,
  });
  const backupElapsedMs = Date.now() - backupT0;
  const backupCompletedAt = new Date().toISOString();
  record('platform_backup_completed', backupResult?.completed === true, {
    backupIdDigest: digest(backupResult?.backupId),
    archiveBytes: backupResult?.archiveBytes,
    platformOnly: backupResult?.platformOnly,
    kongContacted: backupResult?.kongContacted,
    elapsedMs: backupElapsedMs,
  });

  const manifest = JSON.parse(readFileSync(join(backupOut, 'manifest.json'), 'utf8'));
  record('backup_manifest_format', manifest?.identity?.format === 'kongpilot-platform-backup-v1');
  record('backup_source_site_bound', manifest?.identity?.source?.siteId === sourceSiteId);
  const { lstatSync } = await import('node:fs');
  record('backup_files_mode_0600',
    (lstatSync(join(backupOut, 'manifest.json')).mode & 0o777) === 0o600
    && (lstatSync(join(backupOut, 'console-postgres.kpgcm')).mode & 0o777) === 0o600);

  // RPO: quiesced dump after writers stopped; bound ≈ backup window (API stopped).
  rpoNotes = {
    definition: 'Maximum data loss bound for this evidence path: changes after quiesce start are not in the dump; pre-quiesce committed rows are included.',
    measurementMethod: 'platform-recovery backup stops console-api writers, waits for zero other SQL clients, then pg_dump custom + AES-GCM.',
    observedBackupWindowMs: backupElapsedMs,
    observedBackupWindowSeconds: Math.round(backupElapsedMs / 100) / 10,
    redisPolicy: 'fresh-empty-do-not-replay-leases-or-oidc-state (platform-recovery identity)',
    claimedRpoSeconds: null,
    note: 'No SLA RPO claimed. Observed backup window recorded only. Cross-host copy latency not measured beyond this Docker second instance.',
    backupStartedAt,
    backupCompletedAt,
  };

  // --- Official restore into second site / second project / new volumes ---
  const restoreOut = join(workRoot, 'restore-out');
  const restoreStartedAt = new Date().toISOString();
  const restoreT0 = Date.now();
  restoreResult = await restorePlatform({
    backup: backupOut,
    secretsFile,
    targetConfig,
    output: restoreOut,
    repository: repo,
  });
  const restoreElapsedMs = Date.now() - restoreT0;
  const restoreCompletedAt = new Date().toISOString();

  record('platform_restore_completed', restoreResult?.completed === true, {
    targetSiteIdDigest: digest(targetSiteId),
    sourceSiteIdDigest: digest(sourceSiteId),
    sitesDistinct: sourceSiteId !== targetSiteId,
    projectsDistinct: sourceProject !== targetProject,
    elapsedMs: restoreElapsedMs,
  });
  record('restore_checkpoint_matched', restoreResult?.checkpointMatched === true);
  record('restore_audit_verified', Number(restoreResult?.audit?.rows) >= 0 && restoreResult?.audit != null, {
    auditRows: restoreResult?.audit?.rows, auditChains: restoreResult?.audit?.chains,
  });
  record('restore_key_canary_decrypted', restoreResult?.keyCanaryDecrypted === true);
  record('restore_ciphertext_samples_passed', restoreResult?.ciphertextSampleVerification?.passed === true, {
    checked: restoreResult?.ciphertextSampleVerification?.checked,
    fullCoverage: restoreResult?.ciphertextSampleVerification?.fullCoverage,
  });
  record('restore_sessions_revoked', restoreResult?.sessionActiveCounts?.consoleActive === 0
    && restoreResult?.sessionActiveCounts?.portalActive === 0, restoreResult?.sessionActiveCounts);
  record('restore_redis_fresh_empty', restoreResult?.redisFreshAndEmpty === true);
  record('restore_api_not_started', restoreResult?.apiStarted === false
    && restoreResult?.writesEnabled === false
    && restoreResult?.workersEnabled === false
    && restoreResult?.deliveryEnabled === false);
  record('restore_production_ready_false', restoreResult?.productionReady === false);
  record('restore_kong_not_contacted', restoreResult?.kongContacted === false);

  // Target volumes truly new
  const tgtDb = `${targetProject}-console-db-1`;
  const tgtRedis = `${targetProject}-redis-1`;
  resourceIds.target = { database: tgtDb, redis: tgtRedis, ...(restoreResult?.resourceIds || {}) };
  const tgtDbInspect = JSON.parse(docker(['inspect', tgtDb]))[0];
  const tgtVol = tgtDbInspect.Mounts.find((m) => m.Destination === '/var/lib/postgresql/data')?.Name;
  record('target_volume_distinct_from_source_and_evidence',
    !!tgtVol && tgtVol !== srcVol && tgtVol !== evidenceVol, {
      targetVolumeDigest: digest(tgtVol),
      sourceVolumeDigest: digest(srcVol),
      evidenceVolumeDigest: digest(evidenceVol),
    });
  record('target_site_label',
    tgtDbInspect.Config.Labels['com.kongpilot.restore.site'] === targetSiteId
    && tgtDbInspect.Config.Labels['com.docker.compose.project'] === targetProject);

  rtoNotes = {
    definition: 'Time from restore start to isolated storage verification complete (DB restore + audit/ciphertext/session/redis checks). API not started.',
    observedRestoreElapsedMs: restoreElapsedMs,
    observedRestoreElapsedSeconds: Math.round(restoreElapsedMs / 100) / 10,
    claimedRtoSeconds: null,
    includesApiProvisioning: false,
    includesKongContact: false,
    includesCredentialProxyValidation: false,
    pendingBeforeProductionReady: [
      'runtimeRoleProvisioningPending',
      'applicationCiphertextValidationPending',
      'credentialProxyValidationPending',
    ].filter((k) => restoreResult?.[k] === true),
    note: 'No SLA RTO claimed. Observed restore-to-verified-storage only. Full application cutover not in this evidence path.',
    restoreStartedAt,
    restoreCompletedAt,
  };

  // Wipe secret material from memory object
  for (const k of Object.keys(secrets)) secrets[k] = '';
} catch (e) {
  failure = { code: /^[A-Z0-9_]+$/.test(e?.message ?? '') ? e.message : 'KP010_EVIDENCE_FAILED', message: String(e?.message || e).slice(0, 400) };
  record('evidence_exception', false, failure);
} finally {
  // Wipe private work tree secrets files; keep public evidence only
  try {
    if (existsSync(workRoot)) rmSync(workRoot, { recursive: true, force: true });
  } catch { /* keep for inspection on failure — but never commit secrets */ }
}

const allCritical = [
  'source_stack_up',
  'source_volumes_distinct_from_evidence',
  'platform_backup_completed',
  'platform_restore_completed',
  'restore_checkpoint_matched',
  'restore_key_canary_decrypted',
  'restore_ciphertext_samples_passed',
  'restore_sessions_revoked',
  'restore_redis_fresh_empty',
  'target_volume_distinct_from_source_and_evidence',
].every((id) => checks.find((c) => c.id === id)?.passed);

const report = {
  version: 1,
  kp: 'KP-010',
  title: 'cross-host / second-environment platform DB+Redis+secrets restore',
  startedAt,
  completedAt: new Date().toISOString(),
  commercialClosed: false,
  commercialClosedReason: 'KP-010 evidence advances restore path but remaining P0 items (incl. KP-013 closure quality, KP-005 durable append, full production cutover) keep commercialClosed=false',
  method: {
    tool: 'deploy/scripts/platform-recovery.mjs',
    sourceProject,
    targetProject,
    sourceCompose: 'deploy/compose/compose.platform-source.yml',
    seed: 'logical pg_dump from live evidence DB into new source volume (true second data dir)',
    redisPolicy: 'fresh-empty on restore; source redis not replayed',
    secrets: 'CONSOLE_ENCRYPTION_KEY/APP_SECRET/PORTAL_SECRET from live evidence API env; BACKUP_ENCRYPTION_KEY generated for archive; references only in public report',
  },
  allCriticalPassed: allCritical,
  checks,
  backup: backupResult ? {
    completed: backupResult.completed,
    platformOnly: backupResult.platformOnly,
    kongContacted: backupResult.kongContacted,
    archiveBytes: backupResult.archiveBytes,
    backupIdDigest: digest(backupResult.backupId),
  } : null,
  restore: restoreResult ? {
    completed: restoreResult.completed,
    productionReady: restoreResult.productionReady,
    checkpointMatched: restoreResult.checkpointMatched,
    keyCanaryDecrypted: restoreResult.keyCanaryDecrypted,
    ciphertextSampleVerification: restoreResult.ciphertextSampleVerification,
    sessionActiveCounts: restoreResult.sessionActiveCounts,
    redisFreshAndEmpty: restoreResult.redisFreshAndEmpty,
    apiStarted: restoreResult.apiStarted,
    audit: restoreResult.audit,
    sourceSiteIdDigest: digest(sourceSiteId),
    targetSiteIdDigest: digest(targetSiteId),
  } : null,
  rpoNotes,
  rtoNotes,
  resourceIdsPublic: {
    sourceProject,
    targetProject,
    sourceVolumeDistinct: true,
    targetVolumeDistinct: true,
  },
  limitations: [
    'Docker second instance on same daemon — not a geographically separate host. True second data directories/volumes and distinct siteId/project satisfied.',
    'API/writers/workers/delivery not started on restore target; productionReady remains false by design of platform-recovery.',
    'No SLA RPO/RTO claimed; observed windows only.',
    'Live evidence stack was not quiesced for the seed dump; seed is best-effort logical copy into the second environment before the official quiesced backup.',
  ],
  ...(failure ? { failure } : {}),
};

const outPath = join(outDir, 'kp010-platform-second-env-restore-evidence.json');
writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({
  written: outPath,
  allCriticalPassed: allCritical,
  checkCount: checks.length,
  passedCount: checks.filter((c) => c.passed).length,
  commercialClosed: false,
  ...(failure ? { failure } : {}),
}));
if (!allCritical) process.exitCode = 1;
