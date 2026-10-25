import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

// SQL structural controls only: copied ciphertexts/HMACs are not reissued or
// decrypted and cannot be interpreted as HTTP, approval or native authority.
// Root invokes this only in its separate own-console owner-role container.
const sql020Sha256 = 'd220ee5401d5b704f0dd189ef6d9763d3591fbede52f5cf5a236deddd04cccce';
const ledger000Through020Sha256 = '11379b6863b9ca71c5f4da22aea921be80943570bf78f4c64979c8bb383485fe';
const tables = ['entity_change_intents', 'entity_change_intent_versions', 'entity_change_intent_packets', 'entity_change_submissions', 'entity_change_execution_sources'];
const cloneTables = [...tables.slice(0, 4), 'workflows', 'workflow_versions', 'workflow_steps'];
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const checks = [], trials = [];
let client, scope, fixture, stage = 'environment', activeNegativeTrial = null, passed = false, outerRolledBack = false, failure;
let initialFacts, finalFacts, initialLedger, finalLedger, initialCatalog, finalCatalog;
const query = async (sql, values = []) => client.query(sql, values);
const row = async (sql, values = []) => (await query(sql, values)).rows[0];
const check = async (name, action) => { stage = name; const details = await action(); checks.push({name, passed: true, ...(details ?? {})}); };
const ledger = async () => (await query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows.map(({name, checksum}) => ({name, checksum}));
const ledgerDigest = async () => sha256(JSON.stringify(await ledger()));
const factDigest = async () => (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
  'intents',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM entity_change_intents r WHERE cluster_id=$1 AND workspace_id=$2),
  'versions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY intent_id,intent_revision),'[]') FROM entity_change_intent_versions r WHERE cluster_id=$1 AND workspace_id=$2),
  'packets',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY intent_id,intent_revision,packet_order),'[]') FROM entity_change_intent_packets r WHERE cluster_id=$1 AND workspace_id=$2),
  'submissions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM entity_change_submissions r WHERE cluster_id=$1 AND workspace_id=$2),
  'sources',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM entity_change_execution_sources r),
  'workflow',(SELECT to_jsonb(r) FROM workflows r WHERE id=$3),
  'workflow_versions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY plan_revision),'[]') FROM workflow_versions r WHERE workflow_id=$3),
  'workflow_steps',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY step_order),'[]') FROM workflow_steps r WHERE workflow_id=$3),
  'executions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM workflow_executions r WHERE workflow_id=$3),
  'mutations',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM mutation_operations r WHERE workflow_id=$3)
 )::text,'UTF8')),'hex') AS digest`, [scope.clusterId, scope.workspaceId, scope.workflowId])).digest;
const catalogDigest = async () => (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
  'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.relname,c.relkind) ORDER BY c.oid),'[]') FROM pg_class c WHERE c.relnamespace='public'::regnamespace),
  'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.attnotnull,a.attisdropped) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::regnamespace AND a.attnum>0),
  'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,c.conrelid,c.conname,pg_get_constraintdef(c.oid,true)) ORDER BY c.oid),'[]') FROM pg_constraint c WHERE c.connamespace='public'::regnamespace),
  'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled) ORDER BY t.oid),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace),
  'functions',(SELECT coalesce(jsonb_agg(jsonb_build_array(p.oid,p.proname,pg_get_functiondef(p.oid)) ORDER BY p.oid),'[]') FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.prokind IN('f','p'))
 )::text,'UTF8')),'hex') AS digest`)).digest;
const clone = async (table, predicate, values, patch) => {
  assert(cloneTables.includes(table));
  const result = await query(`INSERT INTO ${table} SELECT (jsonb_populate_record(NULL::${table},to_jsonb(source)||$${values.length + 1}::jsonb)).* FROM ${table} source WHERE ${predicate}`, [...values, JSON.stringify(patch)]);
  assert.equal(result.rowCount, 1, 'EXACT_ONE_SHADOW_ROW_REQUIRED');
};
const savepoint = async (name, action) => {
  assert(/^[a-z][a-z0-9_]+$/.test(name)); await query(`SAVEPOINT ${name}`);
  try { await query('SET CONSTRAINTS ALL DEFERRED'); return await action(); }
  finally { await query(`ROLLBACK TO SAVEPOINT ${name}`); await query(`RELEASE SAVEPOINT ${name}`); }
};
const reject = async (name, state, action, expectedConstraint) => {
  stage = 'negative_trials'; activeNegativeTrial = name; let observed;
  await savepoint(name, async () => { try { await action(); await query('SET CONSTRAINTS ALL IMMEDIATE'); }
    catch (error) { observed = {state: error.code, constraint: error.constraint}; } });
  const constraintMatches = expectedConstraint === undefined || observed?.constraint === expectedConstraint;
  trials.push({name, passed: observed?.state === state && constraintMatches, sqlState: observed?.state ?? null, expectedSqlState: state,
    constraintVerified: expectedConstraint === undefined ? null : constraintMatches, rolledBack: true});
  assert(observed?.state === state && constraintMatches, 'EXPECTED_CONSTRAINT_REJECTION_REQUIRED'); activeNegativeTrial = null;
};

async function cloneBundle(mode = 'complete') {
  assert(['complete', 'missing_packet', 'self_dependency', 'null_wrapper_entity_id'].includes(mode));
  const intentId = randomUUID(), workflowId = randomUUID(), submitKey = `m11-g2-shadow-${randomUUID()}`;
  await clone('entity_change_intents', 'source.id=$1', [scope.intentId], {id: intentId, prepare_key: `m11-g2-prepare-${randomUUID()}`});
  if (mode === 'self_dependency') {
    const result = await query(`INSERT INTO entity_change_intent_versions SELECT (jsonb_populate_record(NULL::entity_change_intent_versions,
      to_jsonb(source)||jsonb_build_object('intent_id',$3::uuid,'packet_manifest',jsonb_set(source.packet_manifest,'{0,dependencies}',jsonb_build_array($4::text),false)))).*
      FROM entity_change_intent_versions source WHERE source.intent_id=$1 AND source.intent_revision=$2`, [scope.intentId, scope.intentRevision, intentId, fixture.packetKey]);
    assert.equal(result.rowCount, 1);
  } else await clone('entity_change_intent_versions', 'source.intent_id=$1 AND source.intent_revision=$2', [scope.intentId, scope.intentRevision], {intent_id: intentId});
  if (mode !== 'missing_packet') await clone('entity_change_intent_packets', 'source.intent_id=$1 AND source.intent_revision=$2 AND source.packet_order=1', [scope.intentId, scope.intentRevision],
    {intent_id: intentId, ...(mode === 'self_dependency' ? {dependencies: [fixture.packetKey]} : {})});
  await clone('workflows', 'source.id=$1', [scope.workflowId], {id: workflowId, subject_id: intentId, idempotency_key: submitKey, state: 'pending', revision: 1,
    approved_by: null, approved_at: null, cancelled_at: null, not_before: null, window_start: null, window_end: null});
  await clone('workflow_versions', 'source.workflow_id=$1 AND source.plan_revision=$2', [scope.workflowId, fixture.planRevision], {workflow_id: workflowId});
  await clone('workflow_steps', 'source.workflow_id=$1 AND source.plan_revision=$2 AND source.step_order=1', [scope.workflowId, fixture.planRevision],
    {id: randomUUID(), workflow_id: workflowId, entity_id: mode === 'null_wrapper_entity_id' ? null : intentId, state: 'pending'});
  await clone('entity_change_submissions', 'source.intent_id=$1 AND source.intent_revision=$2', [scope.intentId, scope.intentRevision],
    {id: randomUUID(), intent_id: intentId, workflow_id: workflowId, submit_key: submitKey});
}

try {
  assert.equal(process.env.RELEASE_LAB_READY, 'true'); assert.equal(process.env.RELEASE_LAB_M11_GATE2_SQL_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-m11-gate2-integrity'); assert.equal(process.cwd(), '/app');
  const url = new URL(process.env.DATABASE_URL), ownerRole = decodeURIComponent(url.username), runtimeRole = process.env.M11_RUNTIME_ROLE ?? process.env.CONSOLE_DB_RUNTIME_USER;
  assert(url.hostname === 'console-db' && url.port === '5432' && url.pathname === '/kongpilot');
  assert(/^[a-z][a-z0-9_]{0,62}$/.test(ownerRole) && runtimeRole === 'kongpilot_lab_app' && ownerRole !== runtimeRole);
  scope = {clusterId: process.env.M11_CLUSTER_ID, workspaceId: process.env.M11_WORKSPACE_ID, intentId: process.env.M11_INTENT_ID,
    intentRevision: Number(process.env.M11_INTENT_REVISION), workflowId: process.env.M11_WORKFLOW_ID};
  assert([scope.clusterId, scope.workspaceId, scope.intentId, scope.workflowId].every(uuid)); assert.equal(scope.intentRevision, 1);
  assert.equal(sha256(readFileSync('/app/apps/console-api/dist/infrastructure/migrations/020_m11_durable_entity_intents.sql')), sql020Sha256);
  const require = createRequire('/app/package.json'), {Client} = require('pg');
  client = new Client({connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000}); stage = 'console_connection'; await client.connect();
  await query('SET search_path=public,pg_catalog'); await query('BEGIN'); await query("SET LOCAL statement_timeout='10s'");
  await query("SET LOCAL lock_timeout='2s'"); await query("SET LOCAL idle_in_transaction_session_timeout='45s'"); await query('SET CONSTRAINTS ALL DEFERRED');
  await check('actual_own_console_and_frozen_000_through_020_ledger', async () => {
    const current = await row("SELECT current_database() AS database,current_user AS role,has_table_privilege(current_user,'workflows','INSERT') AND has_table_privilege(current_user,'workflow_steps','INSERT') AS writer");
    assert(current.database === 'kongpilot' && current.role === ownerRole && current.writer);
    const entries = await ledger(); assert.equal(entries.length, 21); assert.equal(sha256(JSON.stringify(entries)), ledger000Through020Sha256);
    for (const entry of entries) assert.equal(sha256(readFileSync(`/app/apps/console-api/dist/infrastructure/migrations/${entry.name}`)), entry.checksum);
    assert.equal(entries.at(-1).name, '020_m11_durable_entity_intents.sql'); initialLedger = await ledgerDigest();
    initialCatalog = await catalogDigest(); return {ledgerCount: entries.length, sql020Matches: true};
  });
  await check('runtime_five_facts_are_select_insert_only', async () => {
    const role = await row('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=$1', [runtimeRole]); assert(role && !role.rolsuper && !role.rolbypassrls);
    for (const table of tables) { const privileges = await row(`SELECT has_table_privilege($1,$2,'SELECT') AS read,has_table_privilege($1,$2,'INSERT') AS append,
      has_table_privilege($1,$2,'UPDATE') AS update,has_table_privilege($1,$2,'DELETE') AS delete,has_table_privilege($1,$2,'TRUNCATE') AS truncate`, [runtimeRole, `public.${table}`]);
      assert(privileges.read && privileges.append && !privileges.update && !privileges.delete && !privileges.truncate); }
    return {tableCount: tables.length};
  });
  await check('actual_immutable_http_intent_and_complete_zero_native_wrapper', async () => {
    fixture = await row(`SELECT i.id,i.requester_id,v.packet_count,v.execution_mode,b.workflow_id,b.workflow_plan_revision AS plan_revision,w.state,w.kind,w.approval_required,w.approval_format,
      (SELECT packet_key FROM entity_change_intent_packets p WHERE p.intent_id=i.id AND p.intent_revision=v.intent_revision AND p.packet_order=1) AS packet_key,
      (SELECT count(*)::int FROM workflow_executions x WHERE x.workflow_id=w.id) AS executions,
      (SELECT count(*)::int FROM mutation_operations m WHERE m.workflow_id=w.id) AS native_mutations,
      (SELECT count(*)::int FROM entity_change_execution_sources) AS short_sources,
      (SELECT count(*)::int FROM workflow_steps s WHERE s.workflow_id=w.id AND s.plan_revision=w.plan_revision AND s.kind='metadata' AND s.handler='entity.change' AND s.entity_id=i.id AND s.native_requests='[]'::jsonb AND s.operation_id IS NULL) AS wrappers
      FROM entity_change_intents i JOIN entity_change_intent_versions v ON v.cluster_id=i.cluster_id AND v.workspace_id=i.workspace_id AND v.intent_id=i.id AND v.intent_revision=$4
      JOIN entity_change_submissions b ON b.cluster_id=v.cluster_id AND b.workspace_id=v.workspace_id AND b.intent_id=v.intent_id AND b.intent_revision=v.intent_revision AND b.material_hmac=v.material_hmac AND b.change_digest=v.change_digest AND b.packet_manifest_hmac=v.packet_manifest_hmac
      JOIN workflows w ON w.cluster_id=b.cluster_id AND w.workspace_id=b.workspace_id AND w.id=b.workflow_id AND w.plan_revision=b.workflow_plan_revision AND w.plan_hash=b.workflow_plan_hash
      WHERE i.id=$1 AND i.cluster_id=$2 AND i.workspace_id=$3 AND w.id=$5`, [scope.intentId, scope.clusterId, scope.workspaceId, scope.intentRevision, scope.workflowId]);
    assert(fixture && fixture.packet_count === 1 && fixture.execution_mode === 'direct' && fixture.kind === 'native-change' && !fixture.approval_required && fixture.approval_format === 1);
    assert(['pending', 'cancelled'].includes(fixture.state) && fixture.wrappers === 1 && fixture.executions === 0 && fixture.native_mutations === 0 && fixture.short_sources === 0);
    fixture.planRevision = fixture.plan_revision; fixture.packetKey = fixture.packet_key; initialFacts = await factDigest();
    return {intentId: scope.intentId, workflowId: scope.workflowId, intentRevision: scope.intentRevision, nativePacketCount: 1, nativeMutationCount: 0, shortExecutionSourceCount: 0};
  });
  await check('otherwise_complete_sql_shadow_validated_then_rolled_back', async () => { await savepoint('complete_shadow_control', async () => { await cloneBundle(); await query('SET CONSTRAINTS ALL IMMEDIATE'); }); return {structuralControlOnly: true}; });
  await reject('missing_packet', '23514', () => cloneBundle('missing_packet'));
  await reject('manifest_and_row_self_dependency', '23514', () => cloneBundle('self_dependency'));
  const versionFk = await row("SELECT conname FROM pg_constraint WHERE contype='f' AND conrelid='public.entity_change_intent_versions'::regclass AND confrelid='public.entity_change_intents'::regclass"); assert(versionFk);
  await reject('foreign_workspace_exact_version_binding', '23503', () => clone('entity_change_intent_versions', 'source.intent_id=$1 AND source.intent_revision=$2', [scope.intentId, scope.intentRevision], {workspace_id: randomUUID()}), versionFk.conname);
  await reject('inserted_wrapper_null_entity_id', '23514', () => cloneBundle('null_wrapper_entity_id'));
  await check('original_private_facts_catalog_and_ledger_unchanged', async () => {
    finalFacts = await factDigest(); finalLedger = await ledgerDigest(); finalCatalog = await catalogDigest();
    assert.equal(finalFacts, initialFacts); assert.equal(finalLedger, initialLedger); assert.equal(finalCatalog, initialCatalog);
    assert.equal((await row('SELECT count(*)::int AS count FROM entity_change_execution_sources')).count, 0);
    return {actualShortExecutionSources: 0};
  });
  stage = 'outer_rollback'; await query('ROLLBACK'); outerRolledBack = true;
  await check('outer_rollback_and_originals_rechecked', async () => { assert.equal(await factDigest(), initialFacts); assert.equal(await ledgerDigest(), initialLedger); assert.equal(await catalogDigest(), initialCatalog); });
  assert.equal(trials.length, 4); passed = true;
} catch (error) {
  failure = {stage, ...(activeNegativeTrial ? {negativeTrialName: activeNegativeTrial} : {}), code: /^[A-Z0-9]{5}$/.test(error?.code ?? '') ? error.code : 'M11_GATE2_INTEGRITY_CHECK_FAILED'};
} finally {
  if (client) { if (!outerRolledBack) {try {await query('ROLLBACK'); outerRolledBack = true;} catch {}} await client.end().catch(() => {}); }
  process.stdout.write(JSON.stringify({passed, milestone: 'M11', gate: 2, checks, trials, outerRolledBack,
    originalFactsUnchanged: typeof finalFacts === 'string' && finalFacts === initialFacts,
    schemaLedgerUnchanged: typeof finalLedger === 'string' && finalLedger === initialLedger,
    originalCatalogUnchanged: typeof finalCatalog === 'string' && finalCatalog === initialCatalog,
    shortExecutionSourcesFabricated: 0, nativeKongRequests: 0, businessCommitted: false, schemaLedgerWritten: false,
    shadowControlsAreSqlStructuralOnly: true, productionDeployment: false, originalHttpResponsesRewritten: false,
    ...(failure ? {failure} : {})}) + '\n'); if (!passed) process.exitCode = 1;
}
