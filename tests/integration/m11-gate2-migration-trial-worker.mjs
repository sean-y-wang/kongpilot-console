import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// Root alone invokes this in an own-console owner-role oneshot container.
// The complete candidate DDL is rolled back. There are no business inserts,
// schema-ledger writes, runtime grants, HTTP requests or native/Kong calls.
const candidateName = '020_m11_durable_entity_intents.sql';
const candidateSha256 = 'd220ee5401d5b704f0dd189ef6d9763d3591fbede52f5cf5a236deddd04cccce';
const migrationDirectory = '/app/apps/console-api/dist/infrastructure/migrations';
const candidatePath = '/tmp/020_m11_durable_entity_intents.sql';
const legacy = [
  ['000_m0.sql', '02f171ea1ff6dd64d12840e36681b315cec9665552aa3b8acdf72319a1c2fd96'],
  ['001_m1.sql', 'ef2e738577ae5321ddfdbd69c315a820e7dfa2bfcbef59176a2a8b9491b3fee6'],
  ['002_m1_index.sql', 'bd67be44dd80554872943d8ef3bac85757f2790f965e31a9ff996e380b1f7663'],
  ['003_m1_index_cycles.sql', 'dc695f4006e0839104df4b4108fc4426ca0670d6c7fa4083b1f29032ad751bf6'],
  ['004_m3_workspaces.sql', '263301537a1bbbdce62fafe44bc9a40589f6b450c9f4f0c787879a252752d501'],
  ['005_m4_iam.sql', '1ab35fdca5b4724af18f1287936c6eced21061ae5605f19b455acabc69f06d22'],
  ['006_m4_child_navigation.sql', 'd5e89915b7192efcdb32e3a9b729543d44c8691d3cc957fc457b9bc1a42e6c01'],
  ['007_m5_metrics.sql', 'e301a76f25c74a72e6599e1c735b152b981bd4df20bfc6f57b3b18c2f59887bf'],
  ['008_m6_portal.sql', '241444c9f85ea30bc09f6a4a93ded051acc5692317068a1e68814c92d9f520bc'],
  ['009_m6_failed_issue_abandonment.sql', '39b2eaf3f0554407114add04aa90a2f197f8cb23b2991077cdc7e018f9dba7fd'],
  ['010_m7_events.sql', '32e46c977d121449795cb7af82ce028d6a121e859f452df7fd3534adc06a8a53'],
  ['011_m8_configuration.sql', '99131280ca62d17e22093ac31449a5f07c98f76321ea54aef93d028de7ba1b1a'],
  ['012_m9_toolbox.sql', 'bbd6c5ca35d6e98545ccd61594969e0ccc78acb5e871276499a4418928737631'],
  ['013_m9_cache_key_constraint.sql', '65dd6e62f80c3677dd2b357ed584fa79427fb180e5939f60eb236cbf1a365cc5'],
  ['014_m9_configuration_recycle_graphs.sql', 'f6a0fd59d1311471f9dc9439303a881e59d80d3032be37eef63337c77d8f47c2'],
  ['015_m9_configuration_recycle_workspaces.sql', '679d3d498c3c467735221980537d8e163d19385a6034a56ef87f9d44a7a00349'],
  ['016_m9_workspace_migration_workflow.sql', 'e98a1afa0c42f182ae8b4ad7d2f2f06c0531a5cf07bd7d8c52cf55c4cc1dac38'],
  ['017_m10_governance.sql', '677510dd14357029d4e69933c295472c1600e0c31ff7e75a869a52ca82846ec8'],
  ['018_m10_configuration_origins.sql', '41c60fea0f26f9e2758acdae2c39a71e7945a27c53ed6159e26bff2574ad92d7'],
  ['019_m11_approval_policy.sql', 'a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb']
];
const tables = ['entity_change_intents', 'entity_change_intent_versions', 'entity_change_intent_packets', 'entity_change_submissions', 'entity_change_execution_sources'];
const functions = ['m11_validate_intent_graph()', 'm11_validate_entity_change_subject()', 'm11_validate_execution_source()'];
const checks = [];
let client, stage = 'environment', passed = false, failure, trialRolledBack = false;
let beforeLedgerDigest, afterLedgerDigest, beforeSchemaDigest, afterSchemaDigest;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const query = async (sql, values = []) => client.query(sql, values);
const row = async (sql, values = []) => (await query(sql, values)).rows[0];
const check = async (name, action) => { stage = name; const details = await action(); checks.push({name, passed: true, ...(details ?? {})}); };
const ledger = async () => (await query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;
const ledgerDigest = async () => sha256(JSON.stringify(await ledger()));
const subjectSource = async () => row(String.raw`SELECT
  encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') AS original,
  encode(sha256(convert_to(regexp_replace(p.prosrc,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''native-change'' THEN RETURN NULL;END IF;'),'UTF8')),'hex') AS expected
  FROM pg_proc p WHERE p.oid='public.m6_validate_workflow_subject()'::regprocedure`);
// Only a digest leaves PostgreSQL: no row payloads, ciphertexts, credentials or
// stored function text enter the report. Catalog facts prove DDL rollback.
const schemaDigest = async () => (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
  'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.relname,c.relkind) ORDER BY c.oid),'[]') FROM pg_class c WHERE c.relnamespace='public'::regnamespace),
  'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.attnotnull,a.attisdropped) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::regnamespace AND a.attnum>0),
  'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.conrelid,c.conname,pg_get_constraintdef(c.oid,true)) ORDER BY c.oid),'[]') FROM pg_constraint c WHERE c.connamespace='public'::regnamespace),
  'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled) ORDER BY t.oid),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace),
  'functions',(SELECT coalesce(jsonb_agg(jsonb_build_array(p.oid,p.proname,pg_get_functiondef(p.oid)) ORDER BY p.oid),'[]') FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.prokind IN('f','p'))
 )::text,'UTF8')),'hex') AS digest`)).digest;
const candidateAbsent = async () => {
  for (const table of tables) assert.equal((await row('SELECT to_regclass($1) IS NULL AS absent', [`public.${table}`])).absent, true);
  for (const fn of functions) assert.equal((await row('SELECT to_regprocedure($1) IS NULL AS absent', [`public.${fn}`])).absent, true);
};

try {
  assert.equal(process.env.RELEASE_LAB_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_M11_GATE2_MIGRATION_TRIAL_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-m11-gate2-migration-trial');
  assert.equal(process.cwd(), '/app');
  const url = new URL(process.env.DATABASE_URL), runtimeRole = process.env.CONSOLE_DB_RUNTIME_USER;
  const ownerRole = decodeURIComponent(url.username);
  assert(url.hostname === 'console-db' && url.port === '5432' && url.pathname === '/kongpilot');
  assert(/^[a-z][a-z0-9_]{0,62}$/.test(ownerRole) && runtimeRole === 'kongpilot_lab_app' && ownerRole !== runtimeRole);
  const bytes = readFileSync(candidatePath); assert.equal(sha256(bytes), candidateSha256, 'FROZEN_SQL020_REQUIRED');
  for (const [name, checksum] of legacy) assert.equal(sha256(readFileSync(`${migrationDirectory}/${name}`)), checksum, 'FROZEN_LEGACY_SQL_REQUIRED');
  checks.push({name: 'candidate_and_all_legacy_migration_bytes_frozen', passed: true, legacyCount: legacy.length});
  const require = createRequire('/app/package.json'), {Client} = require('pg');
  client = new Client({connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000});
  stage = 'console_connection'; await client.connect(); await query('BEGIN');
  await query("SET LOCAL statement_timeout='20s'"); await query("SET LOCAL lock_timeout='2s'");
  await query("SET LOCAL idle_in_transaction_session_timeout='45s'");
  // DDL must create public objects; keep catalog rendering identical after
  // ROLLBACK when the transaction-local settings disappear.
  await query('SET search_path=public,pg_catalog');
  await check('actual_own_console_and_exact_pre020_ledger', async () => {
    const current = await row("SELECT current_database() AS database,current_user AS role,has_schema_privilege(current_user,'public','CREATE') AS ddl");
    assert(current.database === 'kongpilot' && current.role === ownerRole && current.ddl);
    assert.deepEqual(await ledger(), legacy.map(([name, checksum]) => ({name, checksum})));
    await candidateAbsent(); beforeLedgerDigest = await ledgerDigest(); beforeSchemaDigest = await schemaDigest();
    return {ledgerCount: legacy.length, ledgerMax: legacy.at(-1)[0], candidateAbsent: true};
  });
  const subjectBefore = await subjectSource(); assert(subjectBefore && subjectBefore.original !== subjectBefore.expected);
  await check('complete_candidate_ddl_and_deferred_constraints', async () => {
    await query(bytes.toString('utf8')); await query('SET CONSTRAINTS ALL IMMEDIATE');
    return {completeDdlExecuted: true, deferredConstraintsForced: true, businessRowsInserted: 0};
  });
  await check('new_append_only_scope_graph_and_latest_subject_guard', async () => {
    for (const table of tables) {
      const value = await row(`SELECT c.relkind,
        (SELECT count(*)::int FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal AND t.tgfoid='public.m8_immutable()'::regprocedure AND
          (t.tgname=$2 AND t.tgtype=27 OR t.tgname=$3 AND t.tgtype=34)) AS immutable_triggers
        FROM pg_class c WHERE c.oid=to_regclass($1)`, [`public.${table}`, `${table}_immutable`, `${table}_no_truncate`]);
      assert(value?.relkind === 'r' && value.immutable_triggers === 2);
    }
    for (const fn of functions) assert.equal((await row('SELECT to_regprocedure($1) IS NOT NULL AS exists', [`public.${fn}`])).exists, true);
    for (const [from, to, columns] of [['entity_change_submissions', 'workflow_versions', 5], ['entity_change_execution_sources', 'entity_change_submissions', 10], ['entity_change_execution_sources', 'workflow_executions', 6]]) {
      const fk = await row(`SELECT count(*)::int AS count FROM pg_constraint WHERE contype='f' AND conrelid=to_regclass($1) AND confrelid=to_regclass($2) AND cardinality(conkey)=$3 AND cardinality(confkey)=$3`, [`public.${from}`, `public.${to}`, columns]);
      assert.equal(fk.count, 1);
    }
    assert.equal((await subjectSource()).original, subjectBefore.expected);
    return {tableCount: tables.length, immutableTriggerCount: tables.length * 2, compositeBindingCount: 3, latestLegacySubjectBodyPreserved: true};
  });
  await check('schema_ledger_untouched_inside_trial', async () => { assert.equal(await ledgerDigest(), beforeLedgerDigest); return {ledger020Absent: true}; });
  stage = 'outer_rollback'; await query('ROLLBACK'); trialRolledBack = true;
  await check('rollback_removes_candidate_and_restores_exact_legacy_catalog', async () => {
    await candidateAbsent(); afterLedgerDigest = await ledgerDigest(); afterSchemaDigest = await schemaDigest();
    assert.equal(afterLedgerDigest, beforeLedgerDigest); assert.equal(afterSchemaDigest, beforeSchemaDigest);
    assert.equal((await subjectSource()).original, subjectBefore.original);
    return {candidateAbsent: true, completeLegacyCatalogRestored: true, schemaLedgerUnchanged: true};
  });
  passed = true;
} catch (error) {
  const code = /^[A-Z0-9]{5}$/.test(error?.code ?? '') ? error.code : 'M11_GATE2_MIGRATION_TRIAL_FAILED';
  failure = {stage, code, position: /^\d+$/.test(error?.position ?? '') ? Number(error.position) : null};
} finally {
  if (client) {
    if (!trialRolledBack) { try {await query('ROLLBACK'); trialRolledBack = true;} catch {} }
    await client.end().catch(() => {});
  }
  process.stdout.write(JSON.stringify({passed, milestone: 'M11', gate: 2, checks, sql020Sha256: candidateSha256, trialRolledBack,
    businessCommitted: false, schemaLedgerWritten: false, businessRowsInserted: 0, nativeKongRequests: 0, runtimeGrantsProvisioned: false,
    productionDeployment: false, originalFailureRewritten: false,
    schemaLedgerUnchanged: typeof afterLedgerDigest === 'string' && afterLedgerDigest === beforeLedgerDigest,
    legacyCatalogUnchanged: typeof afterSchemaDigest === 'string' && afterSchemaDigest === beforeSchemaDigest,
    ...(failure ? {failure} : {})}) + '\n');
  if (!passed) process.exitCode = 1;
}
