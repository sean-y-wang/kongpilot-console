import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// Root alone invokes this in the separate own-console owner-role container.
// This is a complete, rolled-back DDL trial, not an execution proof. It never
// manufactures current sources, packets, approvals, claims or native receipts.
const candidateName = '021_m11_entity_execution_facts.sql';
const candidateSha256 = '133756b722dae11085d20e1a419378e821fcae0c66e7a721350344e63b4a2956';
const ledger000Through020Sha256 = '11379b6863b9ca71c5f4da22aea921be80943570bf78f4c64979c8bb383485fe';
const sql020Sha256 = 'd220ee5401d5b704f0dd189ef6d9763d3591fbede52f5cf5a236deddd04cccce';
const migrationDirectory = '/app/apps/console-api/dist/infrastructure/migrations';
const candidatePath = '/tmp/021_m11_entity_execution_facts.sql';
const tables = ['entity_change_baselines', 'entity_change_baseline_objects', 'entity_change_baseline_pins',
  'entity_change_packet_attempts', 'entity_change_packet_events', 'entity_change_recovery_links'];
const functions = ['m11_validate_baseline_graph()', 'm11_validate_baseline_pin()', 'm11_validate_packet_attempt()',
  'm11_validate_entity_mutation_binding()', 'm11_validate_packet_event()', 'm11_entity_baseline_pin_active(uuid)', 'm11_validate_entity_recovery_link()'];
const mutationColumns = ['entity_change_source_id', 'entity_change_baseline_id', 'entity_change_attempt_id', 'entity_change_packet_key'];
const mutationConstraints = ['mutation_entity_change_binding_complete', 'mutation_entity_change_attempt_unique', 'mutation_entity_change_attempt_fk'];
const checks = [];
let client, stage = 'environment', substep = null, diagnostic = null, passed = false, failure, trialRolledBack = false, rollbackFailure;
let beforeLedgerDigest, afterLedgerDigest, beforeSchemaDigest, afterSchemaDigest, oldCatalog;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const query = async (sql, values = []) => client.query(sql, values);
const row = async (sql, values = []) => (await query(sql, values)).rows[0];
const check = async (name, action) => { stage = name; substep = null; diagnostic = null; const details = await action(); checks.push({name, passed: true, ...(details ?? {})}); };
const ledger = async () => (await query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows.map(({name, checksum}) => ({name, checksum}));
const ledgerDigest = async () => sha256(JSON.stringify(await ledger()));

// PostgreSQL returns only digests of definitions. No SQL source, business row,
// ciphertext, connection string or credential is written to the report.
const schemaDigest = async () => (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
  'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.relname,c.relkind,c.relowner,c.relacl) ORDER BY c.oid),'[]') FROM pg_class c WHERE c.relnamespace='public'::regnamespace),
  'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attisdropped,a.attidentity,a.attgenerated) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::regnamespace AND a.attnum>0),
  'defaults',(SELECT coalesce(jsonb_agg(jsonb_build_array(d.oid,d.adrelid,d.adnum,pg_get_expr(d.adbin,d.adrelid)) ORDER BY d.oid),'[]') FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid WHERE c.relnamespace='public'::regnamespace),
  'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.conrelid,c.conname,c.condeferrable,c.condeferred,c.convalidated,pg_get_constraintdef(c.oid,true)) ORDER BY c.oid),'[]') FROM pg_constraint c WHERE c.connamespace='public'::regnamespace),
  'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY t.oid),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace),
  'functions',(SELECT coalesce(jsonb_agg(jsonb_build_array(p.oid,p.proname,p.proowner,p.proacl,pg_get_functiondef(p.oid)) ORDER BY p.oid),'[]') FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.prokind IN('f','p')),
  'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid)) ORDER BY i.indexrelid),'[]') FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace)
 )::text,'UTF8')),'hex') AS digest`)).digest;

const originalCatalogIds = async () => row(`SELECT
  ARRAY(SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace ORDER BY oid)::oid[] AS relations,
  ARRAY(SELECT oid FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY oid)::oid[] AS constraints,
  ARRAY(SELECT p.oid FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.prokind IN('f','p') ORDER BY p.oid)::oid[] AS functions,
  ARRAY(SELECT t.oid FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace ORDER BY t.oid)::oid[] AS triggers,
  (SELECT max(attnum)::int FROM pg_attribute WHERE attrelid='public.mutation_operations'::regclass) AS mutation_last_column`);

const originalGuardDigest = async () => (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
  'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.conrelid,c.conname,c.condeferrable,c.condeferred,c.convalidated,pg_get_constraintdef(c.oid,true)) ORDER BY c.oid),'[]') FROM pg_constraint c WHERE c.oid=ANY($1::oid[])),
  'functions',(SELECT coalesce(jsonb_agg(jsonb_build_array(p.oid,p.proname,p.proowner,p.proacl,pg_get_functiondef(p.oid)) ORDER BY p.oid),'[]') FROM pg_proc p WHERE p.oid=ANY($2::oid[])),
  'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY t.oid),'[]') FROM pg_trigger t WHERE t.oid=ANY($3::oid[])),
  'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attisdropped,a.attidentity,a.attgenerated) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a WHERE a.attrelid=ANY($4::oid[]) AND a.attnum>0 AND (a.attrelid<>'public.mutation_operations'::regclass OR a.attnum<=$5))
 )::text,'UTF8')),'hex') AS digest`, [oldCatalog.constraints, oldCatalog.functions, oldCatalog.triggers, oldCatalog.relations, oldCatalog.mutation_last_column])).digest;

const candidateAbsent = async () => {
  for (const table of tables) assert.equal((await row('SELECT to_regclass($1) IS NULL AS absent', [`public.${table}`])).absent, true);
  for (const fn of functions) assert.equal((await row('SELECT to_regprocedure($1) IS NULL AS absent', [`public.${fn}`])).absent, true);
  assert.equal((await row(`SELECT count(*)::int AS count FROM pg_attribute WHERE attrelid='public.mutation_operations'::regclass AND NOT attisdropped AND attname=ANY($1::text[])`, [mutationColumns])).count, 0);
  assert.equal((await row(`SELECT count(*)::int AS count FROM pg_constraint WHERE conrelid='public.mutation_operations'::regclass AND conname=ANY($1::text[])`, [mutationConstraints])).count, 0);
};

try {
  assert.equal(process.env.RELEASE_LAB_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_M11_GATE3_MIGRATION_TRIAL_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-m11-gate3-migration-trial');
  assert.equal(process.cwd(), '/app');
  const url = new URL(process.env.DATABASE_URL), runtimeRole = process.env.CONSOLE_DB_RUNTIME_USER;
  const ownerRole = decodeURIComponent(url.username);
  assert(url.hostname === 'console-db' && url.port === '5432' && url.pathname === '/kongpilot');
  assert(/^[a-z][a-z0-9_]{0,62}$/.test(ownerRole) && runtimeRole === 'kongpilot_lab_app' && ownerRole !== runtimeRole);
  const bytes = readFileSync(candidatePath); assert.equal(sha256(bytes), candidateSha256, 'FROZEN_SQL021_REQUIRED');
  assert.equal(sha256(readFileSync(`${migrationDirectory}/020_m11_durable_entity_intents.sql`)), sql020Sha256, 'FROZEN_SQL020_REQUIRED');
  checks.push({name: 'candidate_and_latest_applied_migration_bytes_frozen', passed: true, candidateName});
  const require = createRequire('/app/package.json'), {Client} = require('pg');
  client = new Client({connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000});
  stage = 'console_connection'; await client.connect(); await query('SET search_path=public,pg_catalog'); await query('BEGIN');
  await query("SET LOCAL statement_timeout='20s'"); await query("SET LOCAL lock_timeout='2s'");
  await query("SET LOCAL idle_in_transaction_session_timeout='45s'");
  await check('actual_own_console_exact_000_through_020_ledger_and_bytes', async () => {
    const current = await row("SELECT current_database() AS database,current_user AS role,has_schema_privilege(current_user,'public','CREATE') AS ddl");
    assert(current.database === 'kongpilot' && current.role === ownerRole && current.ddl);
    const entries = await ledger(); assert.equal(entries.length, 21); assert.equal(sha256(JSON.stringify(entries)), ledger000Through020Sha256);
    assert.equal(entries.at(-1).name, '020_m11_durable_entity_intents.sql');
    for (const entry of entries) {
      assert(/^\d{3}_[a-z0-9_]+\.sql$/.test(entry.name));
      assert.equal(sha256(readFileSync(`${migrationDirectory}/${entry.name}`)), entry.checksum, 'FROZEN_LEGACY_SQL_REQUIRED');
    }
    await candidateAbsent(); beforeLedgerDigest = await ledgerDigest(); beforeSchemaDigest = await schemaDigest(); oldCatalog = await originalCatalogIds();
    return {ledgerCount: entries.length, ledgerMax: entries.at(-1).name, allLegacyBytesMatch: true, candidateAbsent: true};
  });
  const originalGuards = await originalGuardDigest();
  await check('complete_candidate_ddl_and_deferred_constraints', async () => {
    await query(bytes.toString('utf8')); await query('SET CONSTRAINTS ALL IMMEDIATE');
    return {completeDdlExecuted: true, deferredConstraintsForced: true, businessRowsInserted: 0};
  });
  await check('six_append_only_facts_and_separate_complete_v3_binding', async () => {
    for (const table of tables) {
      substep = 'append_only_table'; diagnostic = {table};
      const value = await row(`SELECT c.relkind,
        (SELECT count(*)::int FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal AND t.tgfoid='public.m8_immutable()'::regprocedure AND
          (t.tgname=$2 AND t.tgtype=27 OR t.tgname=$3 AND t.tgtype=34)) AS immutable_triggers
        FROM pg_class c WHERE c.oid=to_regclass($1)`, [`public.${table}`, `${table}_immutable`, `${table}_no_truncate`]);
      diagnostic = {table, ordinaryTable: value?.relkind === 'r', immutableTriggerCount: value?.immutable_triggers ?? null};
      assert(value?.relkind === 'r' && value.immutable_triggers === 2);
    }
    for (const fn of functions) {
      substep = 'candidate_function'; const exists = (await row('SELECT to_regprocedure($1) IS NOT NULL AS exists', [`public.${fn}`])).exists;
      diagnostic = {function: fn, exists}; assert.equal(exists, true);
    }
    substep = 'v3_column_types'; diagnostic = null;
    const columns = (await query(`SELECT attname,atttypid='uuid'::regtype AS uuid,atttypid='text'::regtype AS text,attnotnull FROM pg_attribute
      WHERE attrelid='public.mutation_operations'::regclass AND NOT attisdropped AND attname=ANY($1::text[]) ORDER BY attname`, [mutationColumns])).rows;
    diagnostic = {columnCount: columns.length}; assert.equal(columns.length, 4);
    for (const column of columns) {
      diagnostic = {column: column.attname, nullable: !column.attnotnull, correctType: column.attname==='entity_change_packet_key' ? column.text : column.uuid};
      assert(diagnostic.nullable && diagnostic.correctType);
    }
    substep = 'v3_complete_check'; diagnostic = null;
    const complete = await row(`SELECT contype,convalidated,pg_get_constraintdef(oid,true) AS definition FROM pg_constraint
      WHERE conrelid='public.mutation_operations'::regclass AND conname='mutation_entity_change_binding_complete'`);
    diagnostic = {checkConstraint: complete?.contype === 'c', validated: complete?.convalidated === true};
    assert(diagnostic.checkConstraint && diagnostic.validated);
    const compact = complete.definition.replace(/\s+/g, '');
    const v3 = `num_nonnulls(${mutationColumns.join(',')})`;
    for (const [name, fragment] of [['v3_absence', `${v3}=0`], ['v3_complete', `${v3}=4`], ['workspace_required', 'workspace_idISNOTNULL'], ['workflow_required', 'workflow_idISNOTNULL'],
      ['portal_tuple_null', 'num_nonnulls(workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)=0'],
      ['configuration_tuple_null', 'num_nonnulls(configuration_job_id,configuration_execution_id,configuration_step_id,configuration_plan_revision,configuration_plan_hash)=0']]) {
      diagnostic = {fragment: name, present: compact.includes(fragment)}; assert(diagnostic.present);
    }
    substep = 'v3_attempt_composite_fk'; diagnostic = null;
    const fk = await row(`SELECT c.contype,c.convalidated,c.confdeltype,
      ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num ORDER BY k.ord) AS local_columns,
      ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.num ORDER BY k.ord) AS foreign_columns
      FROM pg_constraint c WHERE c.conrelid='public.mutation_operations'::regclass AND c.conname='mutation_entity_change_attempt_fk' AND c.confrelid='public.entity_change_packet_attempts'::regclass`);
    diagnostic = {foreignKey: fk?.contype === 'f', validated: fk?.convalidated === true, deleteRestrict: fk?.confdeltype === 'r',
      localColumnArray: Array.isArray(fk?.local_columns), foreignColumnArray: Array.isArray(fk?.foreign_columns),
      localColumnsMatch: JSON.stringify(fk?.local_columns) === JSON.stringify(['cluster_id', 'workspace_id', 'entity_change_attempt_id', 'entity_change_source_id', 'entity_change_baseline_id', 'entity_change_packet_key']),
      foreignColumnsMatch: JSON.stringify(fk?.foreign_columns) === JSON.stringify(['cluster_id', 'workspace_id', 'id', 'source_id', 'baseline_id', 'packet_key'])};
    assert(diagnostic.foreignKey && diagnostic.validated && diagnostic.deleteRestrict && diagnostic.localColumnArray && diagnostic.foreignColumnArray);
    assert.deepEqual(fk.local_columns, ['cluster_id', 'workspace_id', 'entity_change_attempt_id', 'entity_change_source_id', 'entity_change_baseline_id', 'entity_change_packet_key']);
    assert.deepEqual(fk.foreign_columns, ['cluster_id', 'workspace_id', 'id', 'source_id', 'baseline_id', 'packet_key']);
    substep = 'v3_single_attempt'; diagnostic = null;
    const unique = await row(`SELECT count(*)::int AS count FROM pg_constraint c WHERE c.conrelid='public.mutation_operations'::regclass AND c.conname='mutation_entity_change_attempt_unique' AND c.contype='u'
      AND cardinality(c.conkey)=1 AND c.conkey[1]=(SELECT attnum FROM pg_attribute WHERE attrelid=c.conrelid AND attname='entity_change_attempt_id')`);
    diagnostic = {uniqueCount: unique.count}; assert.equal(unique.count, 1);
    substep = 'v3_insert_update_delete_guard'; diagnostic = null;
    const trigger = await row(`SELECT (tgtype::int & 1)=1 AS "row",(tgtype::int & 2)=2 AS "before",(tgtype::int & 4)=4 AS "insert",
      (tgtype::int & 8)=8 AS "delete",(tgtype::int & 16)=16 AS "update",tgenabled='O' AS enabled,
      tgfoid='public.m11_validate_entity_mutation_binding()'::regprocedure AS exact_function
      FROM pg_trigger WHERE tgrelid='public.mutation_operations'::regclass AND tgname='mutation_operations_entity_change_binding'`);
    diagnostic = trigger ?? {exists: false}; assert(trigger && Object.values(trigger).every(value => value === true));
    substep = 'all_original_guard_catalog'; diagnostic = {unchanged: await originalGuardDigest() === originalGuards}; assert(diagnostic.unchanged);
    return {tableCount: 6, immutableTriggerCount: 12, functionCount: 7, v3ColumnCount: 4, compositeBindingColumns: 6,
      completeBindingConstraintInspected: true, existingV1V2ConstraintsFunctionsTriggersAndColumnsPreserved: true, nativeAuthorityProven: false};
  });
  await check('schema_ledger_untouched_inside_trial', async () => { assert.equal(await ledgerDigest(), beforeLedgerDigest); return {ledger021Absent: true}; });
  stage = 'outer_rollback'; await query('ROLLBACK'); trialRolledBack = true;
  await check('rollback_removes_candidate_and_restores_exact_legacy_catalog', async () => {
    await candidateAbsent(); afterLedgerDigest = await ledgerDigest(); afterSchemaDigest = await schemaDigest();
    assert.equal(afterLedgerDigest, beforeLedgerDigest); assert.equal(afterSchemaDigest, beforeSchemaDigest); assert.equal(await originalGuardDigest(), originalGuards);
    return {candidateAbsent: true, completeLegacyCatalogRestored: true, all21SchemaLedgerEntriesUnchanged: true};
  });
  passed = true;
} catch (error) {
  const code = /^[A-Z0-9]{5}$/.test(error?.code ?? '') ? error.code : 'M11_GATE3_MIGRATION_TRIAL_FAILED';
  failure = {stage, substep, code, position: /^\d+$/.test(error?.position ?? '') ? Number(error.position) : null, ...(diagnostic ? {diagnostic} : {})};
} finally {
  if (client) {
    if (!trialRolledBack) { try {await query('ROLLBACK'); trialRolledBack = true;} catch {} }
    if (trialRolledBack && beforeLedgerDigest && beforeSchemaDigest && (!afterLedgerDigest || !afterSchemaDigest)) {
      try {
        await candidateAbsent(); afterLedgerDigest = await ledgerDigest(); afterSchemaDigest = await schemaDigest();
        assert.equal(afterLedgerDigest, beforeLedgerDigest); assert.equal(afterSchemaDigest, beforeSchemaDigest);
        checks.push({name: 'failed_trial_rollback_restores_exact_catalog_and_ledger', passed: true,
          candidateAbsent: true, completeLegacyCatalogRestored: true, all21SchemaLedgerEntriesUnchanged: true});
      } catch (error) {
        rollbackFailure = {code: /^[A-Z0-9]{5}$/.test(error?.code ?? '') ? error.code : 'M11_GATE3_ROLLBACK_VERIFICATION_FAILED'};
      }
    }
    await client.end().catch(() => {});
  }
  process.stdout.write(JSON.stringify({passed, milestone: 'M11', gate: 3, checks, sql021Sha256: candidateSha256, trialRolledBack,
    businessCommitted: false, schemaLedgerWritten: false, businessRowsInserted: 0, nativeKongRequests: 0, runtimeGrantsProvisioned: false,
    currentSourcesManufactured: false, approvalsManufactured: false, executionClaimsManufactured: false, nativeAuthorityProven: false,
    productionDeployment: false, originalFailureRewritten: false,
    schemaLedgerUnchanged: typeof afterLedgerDigest === 'string' && afterLedgerDigest === beforeLedgerDigest,
    legacyCatalogUnchanged: typeof afterSchemaDigest === 'string' && afterSchemaDigest === beforeSchemaDigest,
    ...(failure ? {failure} : {}), ...(rollbackFailure ? {rollbackFailure} : {})}) + '\n');
  if (!passed) process.exitCode = 1;
}
