import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// Root invokes this only in the own-console migration namespace. No HTTP,
// business facts, schema ledger writes or Kong database access are performed.
const require = createRequire('/app/package.json');
const { Client } = require('pg');
const expectedSha256 = 'a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb';
let client, stage = 'environment', report;
try {
  const url = new URL(process.env.DATABASE_URL);
  if (process.env.RELEASE_LAB_READY !== 'true' || url.hostname !== 'console-db' || url.port !== '5432'
    || url.pathname !== '/kongpilot' || process.env.CONSOLE_DB_RUNTIME_USER !== 'kongpilot_lab_app'
    || url.username === process.env.CONSOLE_DB_RUNTIME_USER) throw Error('OWN_CONSOLE_MIGRATION_ROLE_REQUIRED');
  const bytes = readFileSync('/app/apps/console-api/dist/infrastructure/migrations/019_m11_approval_policy.sql');
  if (createHash('sha256').update(bytes).digest('hex') !== expectedSha256) throw Error('FROZEN_SQL019_REQUIRED');
  client = new Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000 });
  stage = 'console-connection'; await client.connect();
  await client.query('BEGIN READ ONLY');
  const ledger = (await client.query('SELECT name,checksum FROM schema_migrations ORDER BY name DESC LIMIT 2')).rows;
  await client.query('ROLLBACK');
  if (ledger.length !== 2 || ledger[0].name !== '018_m10_configuration_origins.sql') throw Error('EXACT_PRE_M11_LEDGER_REQUIRED');
  stage = 'rolled-back-ddl'; await client.query('BEGIN');
  await client.query("SET LOCAL statement_timeout='15s'");
  await client.query(bytes.toString('utf8'));
  await client.query('SET CONSTRAINTS ALL IMMEDIATE');
  report = { passed: true, trialRolledBack: true, ledger019Absent: true, priorMigrations: ledger, sql019Sha256: expectedSha256 };
} catch (error) {
  report = { passed: false, stage, failure: { code: error.code ?? (/^[A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'M11_MIGRATION_TRIAL_FAILED'), position: error.position ?? null } };
} finally {
  if (client) { await client.query('ROLLBACK').catch(() => {}); await client.end().catch(() => {}); }
  process.stdout.write(JSON.stringify({ ...report, milestone: 'M11', productionDeployment: false, nativeKongRequests: 0, originalFailureRewritten: false }) + '\n');
  if (!report?.passed) process.exitCode = 1;
}
