import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

// Root alone invokes this in the isolated console owner-role container after
// Source23 acceptance. Complete SQL024 DDL and all deliberate invalid INSERTs
// are rolled back. Pure CHECK-expression probes do not create source facts.
// This script does not issue grants, fabricate successful approvals, create
// an executable occurrence, manufacture native receipts or contact Kong.
const candidate = '024_m11_entity_schedules.sql';
const checksum = '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f';
const sql023Checksum = '9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb';
const migrationDirectory = '/app/apps/console-api/dist/infrastructure/migrations';
const appendOnly = ['entity_change_owner_delegations', 'entity_change_schedules', 'entity_change_schedule_activations',
  'entity_change_schedule_claims', 'entity_change_schedule_leases', 'entity_change_schedule_events'];
const progress = 'entity_change_schedule_progress', tables = [...appendOnly, progress];
const functions = ['m11_validate_schedule_storage()', 'm11_guard_schedule_progress()', 'm11_validate_schedule_draft()',
  'm11_fence_scheduled_submission()', 'm11_validate_schedule_activation()', 'm11_validate_schedule_claim()', 'm11_validate_schedule_lease()',
  'm11_validate_scheduled_execution_source(entity_change_execution_sources)', 'm11_validate_source_schedule_origin()'];
const sourceColumns = ['origin_type', 'schedule_id', 'schedule_version', 'spec_hmac', 'delegation_id', 'delegation_version', 'delegation_hmac',
  'occurrence_id', 'claim_id', 'claim_generation', 'worker_owner_hmac', 'window_start', 'window_end'];
const sourceConstraints = ['entity_sources_origin_check', 'entity_sources_schedule_claim_fk'];
const hash = value => createHash('sha256').update(value).digest('hex');
const checks = [], negativeCasesObserved = [], staticConstraintNames = new Set();
let client, stage = 'environment', substep, diagnostic, failure, rollbackFailure, passed = false, rolledBack = false, before, after, oldHttpBody;
const q = (sql, values = []) => {
  // All statements in this worker have controlled placeholders. Catch tool
  // array-shape errors before PostgreSQL receives a malformed Bind packet.
  const needed = Math.max(0, ...[...sql.matchAll(/\$(\d+)\b/g)].map(match => Number(match[1])));
  assert.equal(values.length, needed, 'SAFE_SQL_PARAMETER_ARITY');
  return client.query(sql, values);
};
const row = async (sql, values) => (await q(sql, values)).rows[0];
const ledger = async () => (await q('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;
const check = async (name, fn) => { stage = name; substep = undefined; diagnostic = undefined; const result = await fn(); checks.push({ name, passed: true, ...result }); };
const safeFailure = error => ({ name: ['AssertionError', 'Error'].includes(error?.name) ? error.name : 'DatabaseError',
  code: /^[A-Z\d]{5}$/.test(error?.code ?? '') ? error.code : undefined,
  position: /^\d+$/.test(error?.position ?? '') ? Number(error.position) : undefined,
  internalPosition: /^\d+$/.test(error?.internalPosition ?? '') ? Number(error.internalPosition) : undefined });
const catalog = async () => (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
 'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,relname,relkind,relowner,relacl) ORDER BY oid),'[]') FROM pg_class WHERE relnamespace='public'::regnamespace),
 'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attisdropped,a.attidentity,a.attgenerated) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::regnamespace AND a.attnum>0),
 'defaults',(SELECT coalesce(jsonb_agg(jsonb_build_array(d.oid,d.adrelid,d.adnum,pg_get_expr(d.adbin,d.adrelid)) ORDER BY d.oid),'[]') FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid WHERE c.relnamespace='public'::regnamespace),
 'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,conrelid,conname,condeferrable,condeferred,convalidated,pg_get_constraintdef(oid,true)) ORDER BY oid),'[]') FROM pg_constraint WHERE connamespace='public'::regnamespace),
 'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY t.oid),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace),
 'functions',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,proname,proowner,proacl,pg_get_functiondef(oid)) ORDER BY oid),'[]') FROM pg_proc WHERE pronamespace='public'::regnamespace AND prokind IN('f','p')),
 'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid)) ORDER BY i.indexrelid),'[]') FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace)
)::text,'UTF8')),'hex') AS digest`)).digest;
const absent = async () => {
  for (const table of tables) assert.equal((await row('SELECT to_regclass($1) IS NULL AS absent', ['public.' + table])).absent, true);
  for (const fn of functions) assert.equal((await row('SELECT to_regprocedure($1) IS NULL AS absent', ['public.' + fn])).absent, true);
  assert.equal((await row(`SELECT count(*)::int AS n FROM pg_attribute WHERE attrelid='public.entity_change_execution_sources'::regclass AND NOT attisdropped AND attname=ANY($1::text[])`, [sourceColumns])).n, 0);
  assert.equal((await row(`SELECT count(*)::int AS n FROM pg_constraint WHERE conrelid='public.entity_change_execution_sources'::regclass AND conname=ANY($1::text[])`, [sourceConstraints])).n, 0);
};
async function blocked(name, sql, values, expectedCode, expectedConstraint) {
  substep = 'negative:' + name;
  await q('SAVEPOINT invalid_scheduled_fact'); let actualCode, actualConstraint, actualKind;
  try { await q(sql, values); await q('SET CONSTRAINTS ALL IMMEDIATE'); } catch (error) {
    actualCode = error?.code; actualConstraint = error?.constraint; actualKind = error?.name === 'AssertionError' ? 'assertion' : 'database';
  }
  await q('ROLLBACK TO SAVEPOINT invalid_scheduled_fact'); await q('RELEASE SAVEPOINT invalid_scheduled_fact');
  const constraint = value => value == null ? null : staticConstraintNames.has(value) ? value : 'unlisted_static_constraint';
  diagnostic = { negativeCase: name, actualKind: actualKind ?? null, actualCode: /^[A-Z\d]{5}$/.test(actualCode ?? '') ? actualCode : null,
    expectedCode, actualConstraint: constraint(actualConstraint), expectedConstraint: constraint(expectedConstraint) };
  negativeCasesObserved.push({ ...diagnostic, passed: actualCode === expectedCode && (!expectedConstraint || actualConstraint === expectedConstraint) });
  assert.equal(actualCode, expectedCode, name);
  if (expectedConstraint) assert.equal(actualConstraint, expectedConstraint, name);
  return { name, code: actualCode, targetedConstraintVerified: Boolean(expectedConstraint) };
}
async function exactFk(name, table, target, local, foreign) {
  const value = await row(`SELECT c.contype,c.convalidated,c.confdeltype,
    ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num ORDER BY k.ord) AS local_columns,
    ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.num ORDER BY k.ord) AS foreign_columns
    FROM pg_constraint c WHERE c.conrelid=to_regclass($1) AND c.conname=$2 AND c.confrelid=to_regclass($3)`, ['public.' + table, name, 'public.' + target]);
  assert(value?.contype === 'f' && value.convalidated && value.confdeltype === 'r');
  assert.deepEqual(value.local_columns, local); assert.deepEqual(value.foreign_columns, foreign);
}
async function targetedCheck(table, fragment) {
  substep = 'targeted_check_lookup';
  const result = (await q(`SELECT conname,pg_get_constraintdef(oid,true) AS definition FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype='c'`, ['public.' + table])).rows;
  for (const value of result) staticConstraintNames.add(value.conname);
  const matches = result.filter(value => value.definition.replace(/\s+/g, '').includes(fragment));
  diagnostic = { checkTable: table, availableCheckCount: result.length, matchingCheckCount: matches.length };
  assert.equal(matches.length, 1); return matches[0].conname;
}
try {
  assert.equal(process.env.RELEASE_LAB_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_M11_SCHEDULE_DDL_TRIAL_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-m11-schedule-ddl-trial');
  assert.equal(process.cwd(), '/app');
  const url = new URL(process.env.DATABASE_URL), owner = decodeURIComponent(url.username);
  assert.equal(url.hostname, 'console-db'); assert.equal(url.port, '5432'); assert.equal(url.pathname, '/kongpilot');
  assert(/^[a-z][a-z0-9_]{0,62}$/.test(owner)); assert.equal(process.env.CONSOLE_DB_RUNTIME_USER, 'kongpilot_lab_app'); assert.notEqual(owner, 'kongpilot_lab_app');
  const sql = readFileSync('/tmp/' + candidate); assert.equal(hash(sql), checksum);
  assert.equal(hash(readFileSync(migrationDirectory + '/023_m11_entity_recycle_facts.sql')), sql023Checksum);
  const { Client } = createRequire('/app/package.json')('pg');
  client = new Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000 });
  await client.connect(); await q('SET search_path=public,pg_catalog'); await q('BEGIN');
  await q("SET LOCAL statement_timeout='20s'"); await q("SET LOCAL lock_timeout='2s'"); await q("SET LOCAL idle_in_transaction_session_timeout='45s'");
  await check('exact_owner_console_000_through_023_bytes_and_absent_candidate', async () => {
    const current = await row("SELECT current_database() AS db,current_user AS role,has_schema_privilege(current_user,'public','CREATE') AS ddl");
    assert(current.db === 'kongpilot' && current.role === owner && current.ddl);
    const entries = await ledger(); assert.equal(entries.length, 24); assert.equal(entries.at(-1).name, '023_m11_entity_recycle_facts.sql'); assert.equal(entries.at(-1).checksum, sql023Checksum);
    for (const [index, entry] of entries.entries()) {
      assert(new RegExp('^' + String(index).padStart(3, '0') + '_[a-z0-9_]+\\.sql$').test(entry.name));
      assert.equal(hash(readFileSync(migrationDirectory + '/' + entry.name)), entry.checksum);
    }
    await absent(); oldHttpBody = (await row("SELECT prosrc FROM pg_proc WHERE oid='m11_validate_execution_source()'::regprocedure")).prosrc;
    assert(!oldHttpBody.includes('m11_validate_scheduled_execution_source'));
    before = { ledgerSha256: hash(JSON.stringify(entries)), schemaSha256: await catalog(), httpGuardSha256: hash(oldHttpBody) };
    return { ledgerCount: 24, allAppliedBytesMatch: true, candidateAbsent: true };
  });
  await check('complete_sql024_ddl_and_all_deferred_constraints', async () => { await q(sql.toString('utf8')); await q('SET CONSTRAINTS ALL IMMEDIATE'); return { fullDdl: true, deferredConstraintsForced: true }; });
  await check('six_append_only_tables_progress_fence_exact_claim_fk_and_live_guards', async () => {
    substep = 'append_only_triggers';
    for (const table of appendOnly) {
      const value = await row(`SELECT count(*)::int AS n FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgfoid='m8_immutable()'::regprocedure AND tgenabled='O'
        AND (tgname=$2 AND tgtype=27 OR tgname=$3 AND tgtype=34)`, ['public.' + table, table + '_immutable', table + '_no_truncate']); assert.equal(value.n, 2);
    }
    substep = 'guard_functions';
    for (const fn of functions) assert.equal((await row('SELECT to_regprocedure($1) IS NOT NULL AS present', ['public.' + fn])).present, true);
    substep = 'progress_triggers';
    const progressGuards = await row(`SELECT count(*)::int AS n FROM pg_trigger WHERE tgrelid='entity_change_schedule_progress'::regclass AND tgenabled='O' AND
      (tgname='entity_schedule_progress_identity' AND tgtype=27 AND tgfoid='m11_guard_schedule_progress()'::regprocedure
      OR tgname='entity_schedule_progress_no_truncate' AND tgtype=34 AND tgfoid='m8_immutable()'::regprocedure)`); assert.equal(progressGuards.n, 2);
    substep = 'complete_graph_triggers';
    const complete = await row(`SELECT count(*)::int AS n,bool_and(tgdeferrable AND tginitdeferred AND tgenabled='O' AND (tgtype::int & 4)=4) AS bounded
      FROM pg_trigger WHERE tgrelid=ANY($1::regclass[]) AND tgfoid='m11_validate_schedule_storage()'::regprocedure`, [['entity_change_schedules', 'entity_change_schedule_activations', 'entity_change_schedule_claims', progress, 'entity_change_schedule_leases']]); assert(complete.n === 5 && complete.bounded);
    substep = 'validated_restrict_foreign_keys';
    const fks = await row(`SELECT count(*)::int AS n,bool_and(convalidated AND confdeltype='r') AS guarded FROM pg_constraint WHERE conrelid=ANY($1::regclass[]) AND contype='f'`, [tables.map(table => 'public.' + table)]); assert(fks.n >= 16 && fks.guarded);
    substep = 'exact_source_claim_foreign_key';
    await exactFk('entity_sources_schedule_claim_fk', 'entity_change_execution_sources', 'entity_change_schedule_claims',
      ['cluster_id', 'workspace_id', 'claim_id', 'schedule_id', 'schedule_version', 'occurrence_id', 'claim_generation', 'worker_owner_hmac', 'workflow_id', 'workflow_plan_revision', 'workflow_plan_hash', 'execution_actor_id', 'credential_epoch', 'delegation_id', 'delegation_version', 'delegation_hmac', 'spec_hmac', 'window_start', 'window_end'],
      ['cluster_id', 'workspace_id', 'id', 'schedule_id', 'schedule_version', 'occurrence_id', 'generation', 'worker_owner_hmac', 'workflow_id', 'workflow_plan_revision', 'workflow_plan_hash', 'owner_id', 'owner_credential_epoch', 'delegation_id', 'delegation_version', 'delegation_hmac', 'spec_hmac', 'window_start', 'window_end']);
    substep = 'eight_before_insert_guards';
    const currentGuards = (await q(`SELECT tgname,tgtype,tgenabled FROM pg_trigger WHERE tgname=ANY($1::text[])`, [[
      'entity_schedule_draft_unsubmitted', 'entity_submissions_schedule_fence', 'entity_schedule_activation_current', 'entity_schedule_claim_current', 'entity_schedule_lease_current', 'entity_sources_scheduled_intent_origin', 'entity_change_execution_sources_current', 'mutation_operations_entity_change_binding']])).rows;
    assert.equal(currentGuards.length, 8); for (const guard of currentGuards) assert(guard.tgenabled === 'O' && (guard.tgtype & 7) === 7);
    return { appendOnlyTables: 6, immutableTriggers: 12, completeGraphTriggers: 5, progressIdentityFenced: true, validatedRestrictForeignKeys: fks.n, sourceClaimTupleColumns: 19, actualBeforeInsertGuards: 8 };
  });
  await check('old_http_guard_verbatim_and_mutually_exclusive_origin_check', async () => {
    const body = (await row("SELECT prosrc FROM pg_proc WHERE oid='m11_validate_execution_source()'::regprocedure")).prosrc;
    const branch = "\n IF NEW.origin_type='scheduled-entity' THEN RETURN m11_validate_scheduled_execution_source(NEW);END IF;";
    assert.equal(body.split(branch).length, 2); assert.equal(body.replace(branch, ''), oldHttpBody);
    const origin = await row(`SELECT convalidated,pg_get_expr(conbin,conrelid) AS expression FROM pg_constraint WHERE conrelid='entity_change_execution_sources'::regclass AND conname='entity_sources_origin_check'`); assert(origin.convalidated);
    // Probe the actual stored CHECK against row-typed values without inserting
    // sources or asserting that a matching shape has execution authority.
    const id = randomUUID(), h = 'a'.repeat(64), now = new Date(), start = new Date(now.getTime() - 1000).toISOString(), end = new Date(now.getTime() + 60000).toISOString();
    const http = { origin_type: 'http', session_id: id }, scheduled = { origin_type: 'scheduled-entity', session_id: null, schedule_id: id, schedule_version: 1, spec_hmac: h,
      delegation_id: id, delegation_version: 1, delegation_hmac: h, occurrence_id: id, claim_id: id, claim_generation: 1, worker_owner_hmac: h, window_start: start, window_end: end, issued_at: now.toISOString(), expires_at: end };
    const shapes = [['http_exact_shape', http, true], ['scheduled_exact_shape', scheduled, true], ['http_missing_sid', { ...http, session_id: null }, false],
      ['http_with_scheduled_tuple', { ...scheduled, origin_type: 'http', session_id: id }, false], ['scheduled_borrows_sid', { ...scheduled, session_id: id }, false],
      ['scheduled_partial_null_tuple', { ...scheduled, delegation_hmac: null }, false], ['scheduled_wrong_generation', { ...scheduled, claim_generation: 2 }, false]];
    for (const [name, value, expected] of shapes) { const result = await row(`SELECT (${origin.expression}) AS result FROM jsonb_populate_record(NULL::entity_change_execution_sources,$1::jsonb) AS source_shape`, [JSON.stringify(value)]); assert.equal(result.result, expected, name); }
    assert.equal((await row(`SELECT attnotnull FROM pg_attribute WHERE attrelid='entity_change_execution_sources'::regclass AND attname='origin_type'`)).attnotnull, true);
    assert.equal(await hash(JSON.stringify(await ledger())), before.ledgerSha256);
    return { oldHttpFunctionBodyUnchanged: true, originShapeOnlyCases: shapes.length, realSourceRowsInserted: 0, legacyLedgerUnchangedInsideTrial: true };
  });
  await check('actual_rejected_delegation_schedule_claim_lease_native_binding_and_truncate', async () => {
    substep = 'static_constraint_catalog';
    for (const value of (await q('SELECT conname FROM pg_constraint WHERE conrelid=ANY($1::regclass[])',
      [[...tables.map(table => 'public.' + table), 'public.entity_change_execution_sources', 'public.mutation_operations']])).rows)
      if (/^[a-z_][a-z\d_]{0,62}$/.test(value.conname)) staticConstraintNames.add(value.conname);
    const id = randomUUID(), other = randomUUID(), h = 'a'.repeat(64), cipher = 'v1.' + 'A'.repeat(16) + '.' + 'B'.repeat(22) + '.C';
    const negatives = [], ownerCheck = await targetedCheck('entity_change_owner_delegations', 'owner_id=executor_id'), specCheck = await targetedCheck('entity_change_schedules', "spec->>'version'");
    negatives.push(await blocked('delegation_cannot_change_executor', `INSERT INTO entity_change_owner_delegations(id,version,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,policy_hash,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,spec_hmac,delegation_hmac,delegation_ciphertext,issued_at,expires_at)
      VALUES($1,1,$1,$1,$1,1,$3,$3,$3,$3,$1,$2,1,1,$3,$3,$4,clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour')`, [id, other, h, cipher], '23514', ownerCheck));
    negatives.push(await blocked('schedule_rejects_missing_required_spec', `INSERT INTO entity_change_schedules(id,version,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,spec,not_before,window_start,window_end,expires_at,occurrence_id,transport_scope,impact_hmac,impact)
      VALUES($1,1,$1,$1,$1,1,$2,$2,$2,$1,1,$1,1,$2,$2,'{}',clock_timestamp(),clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour',$1,$2,$2,$3::jsonb)`, [id, h, JSON.stringify({ version: 1, keyId: h, keys: [], domains: [], wildcards: [] })], '23514', specCheck));
    negatives.push(await blocked('claim_requires_real_owner_approved_occurrence', `INSERT INTO entity_change_schedule_claims(id,cluster_id,workspace_id,schedule_id,schedule_version,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end,issued_at,authority_expires_at,initial_lease_until)
      VALUES($1,$1,$1,$1,1,$1,1,$2,$1,1,$2,$1,1,$1,1,$2,$2,clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 minute',clock_timestamp(),clock_timestamp()+interval '30 seconds',clock_timestamp()+interval '30 seconds')`, [id, h], '23514'));
    negatives.push(await blocked('lease_cannot_steal_nonexistent_generation', `INSERT INTO entity_change_schedule_leases(id,cluster_id,workspace_id,claim_id,generation,worker_owner_hmac,lease_version,previous_id,lease_until)
      VALUES($1,$1,$1,$1,1,$2,1,NULL,clock_timestamp()+interval '1 minute')`, [id, h], '23514'));
    negatives.push(await blocked('scheduled_source_requires_real_claim_without_sid', `INSERT INTO entity_change_execution_sources(id,cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch,session_id,permission_version_hmac,issued_at,expires_at,origin_type,schedule_id,schedule_version,spec_hmac,delegation_id,delegation_version,delegation_hmac,occurrence_id,claim_id,claim_generation,worker_owner_hmac,window_start,window_end)
      VALUES($1,$1,$1,$1,1,$2,$2,$2,$1,1,$2,$1,$1,1,NULL,$2,clock_timestamp(),clock_timestamp()+interval '30 seconds','scheduled-entity',$1,1,$2,$1,1,$2,$1,$1,1,$2,clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 minute')`, [id, h], '23514'));
    negatives.push(await blocked('native_binding_without_actual_source_packet_rejected', `INSERT INTO mutation_operations(id,cluster_id,actor_id,action,idempotency_key,request_hash,state,workflow_id,workspace_id,entity_type,entity_id,entity_change_source_id,entity_change_baseline_id,entity_change_attempt_id,entity_change_packet_key)
      VALUES($1::uuid,$1::uuid,$1::uuid,'update','scheduled-invalid-binding',$2::text,'pending',$1::uuid,$1::uuid,'services',$1::uuid::text,$1::uuid,$1::uuid,$1::uuid,'invalid-packet')`, [id, h], '23514'));
    // Probe leaf tables so PostgreSQL's unrelated TRUNCATE/FK prerequisite
    // check cannot hide the immutable BEFORE TRUNCATE trigger being tested.
    negatives.push(await blocked('append_only_schedule_events_no_truncate', 'TRUNCATE entity_change_schedule_events', [], '23514'));
    negatives.push(await blocked('mutable_schedule_progress_no_truncate', 'TRUNCATE entity_change_schedule_progress', [], '23514'));
    return { negativeCases: negatives, deliberatelyInvalidOnly: true, successfulDelegationsClaimsSourcesOrNativeBindingsCreated: false };
  });
  await q('ROLLBACK'); rolledBack = true;
  await check('outer_rollback_restores_exact_000_through_023_schema_http_guard_and_ledger', async () => {
    await absent(); after = { ledgerSha256: hash(JSON.stringify(await ledger())), schemaSha256: await catalog(), httpGuardSha256: hash((await row("SELECT prosrc FROM pg_proc WHERE oid='m11_validate_execution_source()'::regprocedure")).prosrc) };
    assert.deepEqual(after, before); return { exactCatalogRestored: true, exactHttpGuardRestored: true, exactLedgerRestored: true, candidateAbsent: true };
  }); passed = true;
} catch (error) { failure = { stage, substep, ...(diagnostic ? { diagnostic } : {}), ...safeFailure(error) }; }
finally {
  if (client) {
    if (!rolledBack) try { await q('ROLLBACK'); rolledBack = true; } catch (error) { rollbackFailure = safeFailure(error); }
    if (rolledBack && before && !after) try {
      await absent(); after = { ledgerSha256: hash(JSON.stringify(await ledger())), schemaSha256: await catalog(), httpGuardSha256: hash((await row("SELECT prosrc FROM pg_proc WHERE oid='m11_validate_execution_source()'::regprocedure")).prosrc) };
      assert.deepEqual(after, before); checks.push({ name: 'failed_trial_rollback_restores_exact_schema_http_guard_and_ledger', passed: true });
    } catch (error) { rollbackFailure = safeFailure(error); }
    await client.end().catch(() => {});
  }
  process.stdout.write(JSON.stringify({ milestone: 'M11', gate: 4, phase: 'scheduled-sql024-ddl-trial', passed, candidate, candidateSha256: checksum,
    checks, negativeCasesObserved, before, after, trialRolledBack: rolledBack, businessRowsCommitted: 0, schemaLedgerWritten: false, runtimeGrantsProvisioned: false,
    realSuccessfulSourcesManufactured: false, approvalSetsManufactured: false, successfulClaimsManufactured: false, nativeRequestsSent: 0,
    executionAuthorityCreated: false, productionDeployment: false, ...(failure ? { failure } : {}), ...(rollbackFailure ? { rollbackFailure } : {}) }) + '\n');
  if (!passed) process.exitCode = 1;
}
