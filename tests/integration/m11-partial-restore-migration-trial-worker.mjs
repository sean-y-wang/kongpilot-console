import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

// Root runs this only in the isolated migration-owner container. No SQL fact,
// approval, source, native receipt or executable occurrence is manufactured.
assert.equal(process.env.RELEASE_LAB_READY, 'true');
assert.equal(process.env.RELEASE_LAB_M11_PARTIAL_DDL_TRIAL_READY, 'true');
assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-m11-partial-ddl-trial');
const checksum = process.env.M11_PARTIAL_DDL_CHECKSUM;
assert(/^[a-f0-9]{64}$/.test(checksum ?? ''));
const bytes = readFileSync('/tmp/025_m11_partial_recycle_restore.sql');
const digest = value => createHash('sha256').update(value).digest('hex');
assert.equal(digest(bytes), checksum);
const require = createRequire('/app/apps/console-api/package.json'), { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? process.env.CONSOLE_DATABASE_URL });
const table = 'entity_change_recycle_restore_present_facts';
const report = { passed: false, sourceOnly: false, productionDeployment: false, overallM11Accepted: false,
  candidate: '025_m11_partial_recycle_restore.sql', candidateSha256: checksum, nativeRequestsSent: 0,
  trialRolledBack: false, factsInserted: 0, checks: [] };
let client, baseline, stage = 'connect';
const check = (name, facts = {}) => report.checks.push({ name, passed: true, ...facts });
const catalogSql = `SELECT jsonb_build_object(
 'relations',(SELECT jsonb_agg(jsonb_build_array(oid,relname,relkind,relowner,relacl) ORDER BY oid) FROM pg_class WHERE relnamespace='public'::regnamespace),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(oid,conrelid,conname,condeferrable,condeferred,convalidated,pg_get_constraintdef(oid,true)) ORDER BY oid) FROM pg_constraint WHERE connamespace='public'::regnamespace),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace),
 'functions',(SELECT jsonb_agg(jsonb_build_array(oid,proname,proowner,proacl,pg_get_functiondef(oid)) ORDER BY oid) FROM pg_proc WHERE pronamespace='public'::regnamespace AND prokind IN('f','p')),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid)) ORDER BY i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace)) AS value`;
const snapshot = async () => {
  const ledger = (await client.query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;
  const catalog = (await client.query(catalogSql)).rows[0].value;
  const facts = (await client.query(`SELECT jsonb_build_object(
    'events',(SELECT jsonb_agg(jsonb_build_array(id,fact_hmac) ORDER BY id) FROM entity_change_packet_events),
    'receipts',(SELECT jsonb_agg(jsonb_build_array(attempt_id,result_hmac,verification_hmac) ORDER BY attempt_id) FROM entity_change_recycle_receipts),
    'archives',(SELECT jsonb_agg(jsonb_build_array(entry_id,graph_hmac,node_manifest_hmac) ORDER BY entry_id) FROM entity_change_recycle_archives)) AS value`)).rows[0].value;
  return { ledger, catalogSha256: digest(JSON.stringify(catalog)), factsSha256: digest(JSON.stringify(facts)) };
};
try {
  client = await pool.connect();
  await client.query("SET statement_timeout='15s'");
  stage = 'historical-schema-and-owner';
  const current = (await client.query('SELECT current_user AS role')).rows[0].role;
  assert.notEqual(current, process.env.M11_RUNTIME_ROLE);
  const before = baseline = await snapshot();
  assert.equal(before.ledger.length, 25);
  assert.equal(before.ledger.at(-1).name, '024_m11_entity_schedules.sql');
  assert.equal((await client.query('SELECT to_regclass($1) IS NULL AS absent', ['public.' + table])).rows[0].absent, true);
  check(stage, { historicalMigrations: 25 });
  await client.query('BEGIN');
  await client.query('SELECT pg_advisory_xact_lock($1)', [1545015001]);
  stage = 'complete-candidate-ddl';
  await client.query(bytes.toString('utf8'));
  const constraints = (await client.query(`SELECT contype,convalidated,confdeltype FROM pg_constraint WHERE conrelid=$1::regclass`, ['public.' + table])).rows;
  assert(constraints.filter(c => c.contype === 'f').length >= 7);
  assert(constraints.every(c => c.convalidated && (c.contype !== 'f' || c.confdeltype === 'r')));
  const triggers = (await client.query(`SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid=$1::regclass AND NOT tgisinternal`, ['public.' + table])).rows;
  assert(triggers.length >= 3 && triggers.every(t => t.tgenabled === 'O'));
  check(stage, { validatedRestrictForeignKeys: constraints.filter(c => c.contype === 'f').length, enabledTriggers: triggers.length });
  stage = 'actual-immutable-truncate-rejection';
  await client.query('SAVEPOINT invalid_truncate');
  let rejected;
  try { await client.query('TRUNCATE ' + table + ' CASCADE'); }
  catch (error) { rejected = error.code; }
  await client.query('ROLLBACK TO SAVEPOINT invalid_truncate');
  assert.equal(rejected, '23514');
  check(stage, { sqlState: rejected });
  stage = 'deferred-guards-and-rollback';
  await client.query('SET CONSTRAINTS ALL IMMEDIATE');
  await client.query('ROLLBACK'); report.trialRolledBack = true;
  const after = await snapshot();
  assert.deepEqual(after, before);
  assert.equal((await client.query('SELECT to_regclass($1) IS NULL AS absent', ['public.' + table])).rows[0].absent, true);
  check(stage, { originalCatalogUnchanged: true, originalLedgerUnchanged: true, originalNativeEvidenceUnchanged: true });
  report.passed = true;
} catch (error) {
  report.failure = { stage, kind: error.name === 'AssertionError' ? 'assertion' : 'database',
    ...(/^[A-Z0-9]{5}$/.test(error.code ?? '') ? { sqlState: error.code } : {}),
    ...(/^\d+$/.test(error.position ?? '') ? { sourcePosition: Number(error.position) } : {}),
    ...(/^\d+$/.test(error.internalPosition ?? '') ? { internalPosition: Number(error.internalPosition) } : {}),
    ...(typeof error.message === 'string' && /syntax error at or near "([a-z_][a-z0-9_]*)"/i.test(error.message)
      ? { syntaxToken: error.message.match(/syntax error at or near "([a-z_][a-z0-9_]*)"/i)[1] } : {}) };
} finally {
  if (client) {
    try {
      await client.query('ROLLBACK');
      if (baseline) { assert.deepEqual(await snapshot(), baseline); report.trialRolledBack = true; }
    } catch { report.rollbackVerificationFailed = true; report.passed = false; }
    client.release();
  }
  await pool.end(); console.log(JSON.stringify(report)); if (!report.passed) process.exitCode = 1;
}
