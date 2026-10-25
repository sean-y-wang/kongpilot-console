import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

// Root runs this against the own console database after real BFF fixtures.
// SQL-only shadow records exist inside SAVEPOINTs and the outer ROLLBACK.
// Ciphertexts are copied only by INSERT SELECT inside PostgreSQL; neither
// plaintext nor ciphertext is returned, decrypted, rewritten or logged.
const sql019Sha256 = 'a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb';
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const identifier = value => typeof value === 'string' && /^[a-z][a-z0-9_]{0,62}$/.test(value);
const sqlState = error => /^[A-Z0-9]{5}$/.test(error?.code ?? '') ? error.code : null;
const fixedFailure = error => ({ code: sqlState(error) ?? 'M11_GATE1_INTEGRITY_CHECK_FAILED' });
const tables = ['workflow_candidate_versions', 'workflow_candidates', 'workflow_approval_sets', 'workflow_approval_set_members', 'workflow_approval_invalidations', 'workflow_policy_requests'];
const checks = [], trials = [];
let client, scope, pending, approved, sibling, passed = false, failure, stage = 'environment', rolledBack = false;
let initialDigest, finalDigest, ledgerDigest, finalLedgerDigest;
let activeNegativeTrial = null;

const check = async (name, action) => { const result = await action(); checks.push({ name, passed: true, ...(result ?? {}) }); };
const query = async (sql, values = []) => client.query(sql, values);
const row = async (sql, values = []) => (await query(sql, values)).rows[0];
const clone = async (table, predicate, values, patch) => {
  assert(['workflow_definitions', 'workflow_definition_versions', 'workflow_definition_stages', 'workflows', 'workflow_versions', 'workflow_steps', 'workflow_candidate_versions', 'workflow_stages', 'workflow_candidates', 'governance_metadata_requests', 'workflow_policy_requests', 'workflow_approval_sets'].includes(table));
  const patchIndex = values.length + 1;
  const result = await query(`INSERT INTO ${table} SELECT (jsonb_populate_record(NULL::${table},to_jsonb(source)||$${patchIndex}::jsonb)).* FROM ${table} source WHERE ${predicate}`, [...values, JSON.stringify(patch)]);
  assert.equal(result.rowCount, 1, 'EXACT_ONE_SHADOW_ROW_REQUIRED');
};
const savepoint = async (name, action) => {
  assert(/^[a-z][a-z0-9_]+$/.test(name)); await query(`SAVEPOINT ${name}`);
  try { await query('SET CONSTRAINTS ALL DEFERRED'); return await action(); }
  finally { await query(`ROLLBACK TO SAVEPOINT ${name}`); await query(`RELEASE SAVEPOINT ${name}`); }
};
const reject = async (name, expectedState, action, expectedConstraint) => {
  activeNegativeTrial = name;
  let observed = null;
  await savepoint(name, async () => {
    try { await action(); await query('SET CONSTRAINTS ALL IMMEDIATE'); }
    catch (error) { observed = { state: sqlState(error), constraint: error.constraint }; }
  });
  const stateMatches = observed?.state === expectedState;
  const constraintMatches = expectedConstraint === undefined || observed?.constraint === expectedConstraint;
  trials.push({ name, passed: stateMatches && constraintMatches, sqlState: observed?.state ?? null, expectedSqlState: expectedState, constraintVerified: expectedConstraint === undefined ? null : constraintMatches, rolledBack: true });
  assert(stateMatches && constraintMatches, 'EXPECTED_CONSTRAINT_REJECTION_REQUIRED');
  activeNegativeTrial = null;
};

async function fixture(id) {
  const value = await row(`SELECT id,cluster_id,workspace_id,kind,subject_type,subject_id,requester_type,requester_user_id,
    definition_id,definition_version,plan_revision,plan_hash,execution_mode,approval_required,approval_format,state,
    candidate_version,candidate_manifest_hmac,approval_set_id,approval_set_hmac,approved_by,expires_at
    FROM workflows WHERE id=$1 FOR SHARE`, [id]);
  assert(value && value.cluster_id === scope.clusterId && value.workspace_id === scope.workspaceId);
  assert(['governance-metadata', 'workflow-policy-metadata'].includes(value.kind) && value.requester_type === 'console');
  assert.equal(value.subject_type, value.kind === 'governance-metadata' ? 'governance_metadata_requests' : 'workflow_policy_requests');
  assert(value.approval_format === 2 && value.approval_required && value.execution_mode === 'approval');
  const version = await row('SELECT step_count,native_request_count,approval_format,plan_hash FROM workflow_versions WHERE workflow_id=$1 AND plan_revision=$2', [id, value.plan_revision]);
  assert(version?.step_count === 1 && version.native_request_count === 0 && version.approval_format === 2 && version.plan_hash === value.plan_hash);
  const counts = await row(`SELECT
    (SELECT count(*)::int FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2) AS stages,
    (SELECT count(*)::int FROM workflow_approvals WHERE workflow_id=$1 AND plan_revision=$2) AS votes,
    (SELECT count(*)::int FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2) AS executions,
    (SELECT count(*)::int FROM workflow_approval_sets WHERE workflow_id=$1 AND plan_revision=$2) AS sets,
    (SELECT count(*)::int FROM mutation_operations WHERE workflow_id=$1) AS native_mutations,
    (SELECT count(*)::int FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2 AND(kind<>'metadata' OR native_requests<>'[]'::jsonb OR operation_id IS NOT NULL)) AS unsafe_steps`, [id, value.plan_revision]);
  assert(counts.stages >= 2 && counts.stages <= 8 && counts.native_mutations === 0 && counts.unsafe_steps === 0);
  return { ...value, counts };
}
async function sourceDigest() {
  return (await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
    'definitions',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id),'[]') FROM workflow_definitions d WHERE d.cluster_id=$1 AND d.workspace_id=$2),
    'definition_versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.definition_id,v.version),'[]') FROM workflow_definition_versions v WHERE v.cluster_id=$1 AND v.workspace_id=$2),
    'definition_stages',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.definition_id,s.definition_version,s.level),'[]') FROM workflow_definition_stages s WHERE s.cluster_id=$1 AND s.workspace_id=$2),
    'workflows',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY w.id),'[]') FROM workflows w WHERE w.id=ANY($3::uuid[])),
    'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.workflow_id,v.plan_revision),'[]') FROM workflow_versions v WHERE v.workflow_id=ANY($3::uuid[])),
    'steps',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.workflow_id,s.step_order),'[]') FROM workflow_steps s WHERE s.workflow_id=ANY($3::uuid[])),
    'stages',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.workflow_id,s.plan_revision,s.level),'[]') FROM workflow_stages s WHERE s.workflow_id=ANY($3::uuid[])),
    'candidate_versions',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.workflow_id,c.plan_revision,c.candidate_version),'[]') FROM workflow_candidate_versions c WHERE c.workflow_id=ANY($3::uuid[])),
    'candidates',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.workflow_id,c.plan_revision,c.level,c.user_id),'[]') FROM workflow_candidates c WHERE c.workflow_id=ANY($3::uuid[])),
    'votes',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]') FROM workflow_approvals a WHERE a.workflow_id=ANY($3::uuid[])),
    'sets',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]') FROM workflow_approval_sets a WHERE a.workflow_id=ANY($3::uuid[])),
    'members',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.set_id,m.approval_id),'[]') FROM workflow_approval_set_members m WHERE m.workflow_id=ANY($3::uuid[])),
    'executions',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]') FROM workflow_executions e WHERE e.workflow_id=ANY($3::uuid[])),
    'governance_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]') FROM governance_metadata_requests r WHERE r.workflow_id=ANY($3::uuid[])),
    'policy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]') FROM workflow_policy_requests r WHERE r.workflow_id=ANY($3::uuid[]))
  )::text,'UTF8')),'hex') AS digest`, [scope.clusterId, scope.workspaceId, scope.workflowIds])).digest;
}
async function schemaLedgerDigest() {
  return (await row("SELECT encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(m) ORDER BY name),'[]')::text,'UTF8')),'hex') AS digest FROM schema_migrations m")).digest;
}
async function clonePending(duplicate = false) {
  const id = randomUUID(), intentId = randomUUID(), stepId = randomUUID(), key = `m11-sql-shadow-${randomUUID()}`;
  await clone('workflows', 'source.id=$1', [pending.id], { id, subject_id: intentId, idempotency_key: key });
  await clone(pending.subject_type, 'source.id=$1', [pending.subject_id], { id: intentId, workflow_id: id, idempotency_key: key });
  await clone('workflow_versions', 'source.workflow_id=$1 AND source.plan_revision=$2', [pending.id, pending.plan_revision], { workflow_id: id });
  await clone('workflow_steps', 'source.workflow_id=$1 AND source.plan_revision=$2', [pending.id, pending.plan_revision], { id: stepId, workflow_id: id, entity_id: intentId });
  const candidateSource = await row(`SELECT manifest FROM workflow_candidate_versions WHERE workflow_id=$1 AND plan_revision=$2 AND candidate_version=$3`, [pending.id, pending.plan_revision, pending.candidate_version]);
  // This manifest contains only IAM IDs, epochs and selectors. No encrypted
  // payload is fetched. Keep cardinality constant to isolate duplicate IDs.
  const manifest = structuredClone(candidateSource.manifest); manifest.workflowId = id;
  if (duplicate) { const target = manifest.stages.find(item => item.candidates.length >= 2); assert(target, 'MULTI_CANDIDATE_REAL_STAGE_REQUIRED'); target.candidates[1] = structuredClone(target.candidates[0]); }
  await clone('workflow_candidate_versions', 'source.workflow_id=$1 AND source.plan_revision=$2 AND source.candidate_version=$3', [pending.id, pending.plan_revision, pending.candidate_version], { workflow_id: id, manifest });
  const stages = (await query('SELECT level FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY level', [pending.id, pending.plan_revision])).rows;
  for (const item of stages) await clone('workflow_stages', 'source.workflow_id=$1 AND source.plan_revision=$2 AND source.level=$3', [pending.id, pending.plan_revision, item.level], { workflow_id: id });
  const candidates = (await query('SELECT level,user_id FROM workflow_candidates WHERE workflow_id=$1 AND plan_revision=$2 AND candidate_version=$3 ORDER BY level,user_id', [pending.id, pending.plan_revision, pending.candidate_version])).rows;
  for (const item of candidates) await clone('workflow_candidates', 'source.workflow_id=$1 AND source.plan_revision=$2 AND source.candidate_version=$3 AND source.level=$4 AND source.user_id=$5', [pending.id, pending.plan_revision, pending.candidate_version, item.level, item.user_id], { workflow_id: id });
  return id;
}

try {
  assert.equal(process.env.RELEASE_LAB_READY, 'true'); assert.equal(process.env.RELEASE_LAB_M11_GATE1_SQL_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_CONTAINER, 'kongpilot-release-lab-m11-gate1-integrity'); assert.equal(process.cwd(), '/app');
  const url = new URL(process.env.DATABASE_URL); assert(url.hostname === 'console-db' && url.port === '5432' && url.pathname === '/kongpilot');
  const connectionRole = decodeURIComponent(url.username), runtimeRole = process.env.M11_RUNTIME_ROLE ?? process.env.CONSOLE_DB_RUNTIME_USER;
  assert(identifier(connectionRole) && runtimeRole === 'kongpilot_lab_app' && connectionRole !== runtimeRole, 'OWN_CONSOLE_OWNER_ROLE_REQUIRED');
  scope = { clusterId: process.env.M11_CLUSTER_ID, workspaceId: process.env.M11_WORKSPACE_ID,
    pendingId: process.env.M11_PENDING_WORKFLOW_ID, approvedId: process.env.M11_APPROVED_WORKFLOW_ID, siblingId: process.env.M11_SECOND_APPROVED_WORKFLOW_ID };
  assert([scope.clusterId, scope.workspaceId, scope.pendingId, scope.approvedId].every(uuid));
  if (scope.siblingId !== undefined) assert(uuid(scope.siblingId));
  scope.workflowIds = [...new Set([scope.pendingId, scope.approvedId, scope.siblingId].filter(Boolean))]; assert.equal(scope.workflowIds.length, scope.siblingId ? 3 : 2);
  const bytes = readFileSync('/app/apps/console-api/dist/infrastructure/migrations/019_m11_approval_policy.sql');
  assert.equal(createHash('sha256').update(bytes).digest('hex'), sql019Sha256, 'FROZEN_SQL019_REQUIRED');
  const require = createRequire('/app/package.json'), { Client } = require('pg');
  client = new Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000 });
  stage = 'connection'; await client.connect(); await query('BEGIN');
  await query("SET LOCAL statement_timeout='8s'"); await query("SET LOCAL lock_timeout='2s'"); await query("SET LOCAL idle_in_transaction_session_timeout='45s'");
  await query('SET LOCAL search_path=pg_catalog,public'); await query('SET CONSTRAINTS ALL DEFERRED');
  await check('actual_own_console_and_frozen_ledger', async () => {
    const current = await row('SELECT current_database() AS database,current_user AS role'); assert(current.database === 'kongpilot' && current.role === connectionRole);
    const ledger = await row('SELECT checksum FROM schema_migrations WHERE name=$1', ['019_m11_approval_policy.sql']); assert.equal(ledger?.checksum, sql019Sha256);
    const owner = await row("SELECT has_table_privilege(current_user,'workflows','INSERT') AND has_table_privilege(current_user,'workflows','UPDATE') AND has_table_privilege(current_user,'workflow_stages','UPDATE') AS allowed"); assert.equal(owner.allowed, true);
    ledgerDigest = await schemaLedgerDigest(); return { sql019Matches: true };
  });
  await check('runtime_facts_are_select_insert_only', async () => {
    const runtime = await row('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=$1', [runtimeRole]); assert(runtime && !runtime.rolsuper && !runtime.rolbypassrls);
    for (const table of tables) {
      const privilege = await row(`SELECT has_table_privilege($1,$2,'SELECT') AS read,has_table_privilege($1,$2,'INSERT') AS append,
        has_table_privilege($1,$2,'UPDATE') AS update,has_table_privilege($1,$2,'DELETE') AS delete,has_table_privilege($1,$2,'TRUNCATE') AS truncate`, [runtimeRole, table]);
      assert(privilege.read && privilege.append && !privilege.update && !privilege.delete && !privilege.truncate);
    } return { tableCount: tables.length };
  });
  stage = 'fixtures'; pending = await fixture(scope.pendingId); approved = await fixture(scope.approvedId); if (scope.siblingId) sibling = await fixture(scope.siblingId);
  await check('actual_pending_and_complete_approval_sets', async () => {
    assert(pending.state === 'pending' && pending.counts.votes === 0 && pending.counts.executions === 0 && pending.counts.sets === 0 && pending.approval_set_id === null && pending.approved_by === null && Date.parse(pending.expires_at) > Date.now());
    assert.equal((await row("SELECT count(*)::int AS count FROM workflow_stages WHERE workflow_id=$1 AND state='active'", [pending.id])).count, 1);
    for (const value of [approved, sibling].filter(Boolean)) {
      assert(['approved', 'executing', 'succeeded', 'cancelled', 'partial', 'failed', 'uncertain'].includes(value.state));
      assert(uuid(value.approval_set_id) && value.approval_set_hmac && value.approved_by && value.counts.votes >= 2);
      await query('SELECT m11_assert_approval_facts($1,$2,$3)', [value.id, value.plan_revision, value.plan_hash]);
      const set = await row('SELECT id,set_hmac,policy_hash,candidate_version,candidate_manifest_hmac FROM workflow_approval_sets WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6', [value.approval_set_id, scope.clusterId, scope.workspaceId, value.id, value.plan_revision, value.plan_hash]);
      assert(set && set.set_hmac === value.approval_set_hmac && set.candidate_version === value.candidate_version && set.candidate_manifest_hmac === value.candidate_manifest_hmac);
      const counts = await row(`SELECT count(*)::int AS members,count(*) FILTER(WHERE a.id IS NULL OR a.decision<>'approve')::int AS invalid
        FROM workflow_approval_set_members m LEFT JOIN workflow_approvals a ON a.id=m.approval_id AND a.cluster_id=m.cluster_id AND a.workspace_id=m.workspace_id AND a.workflow_id=m.workflow_id AND a.plan_revision=m.plan_revision AND a.plan_hash=m.plan_hash AND a.level=m.level AND a.approver_id=m.user_id AND a.candidate_version=m.candidate_version AND a.candidate_manifest_hmac=m.candidate_manifest_hmac
        WHERE m.set_id=$1`, [set.id]); assert(counts.members === value.counts.votes && counts.invalid === 0);
      assert.equal((await row("SELECT count(*)::int AS count FROM workflow_stages WHERE workflow_id=$1 AND state<>'approved'", [value.id])).count, 0);
    } return { pendingWorkflowId: pending.id, approvedWorkflowId: approved.id, ...(sibling ? { secondApprovedWorkflowId: sibling.id } : {}), pendingStageCount: pending.counts.stages, approvedVoteCount: approved.counts.votes, nativeMutationCount: 0 };
  });
  initialDigest = await sourceDigest();
  stage = 'shadow_control'; await savepoint('valid_shadow_control', async () => { await clonePending(false); await query('SET CONSTRAINTS ALL IMMEDIATE'); });
  checks.push({ name: 'otherwise_complete_pending_shadow_validated_then_rolled_back', passed: true });
  stage = 'negative_trials';
  await reject('missing_policy_scalar', '23514', async () => {
    const id = randomUUID(); await clone('workflow_definitions', 'source.id=$1', [pending.definition_id], { id, code: `m11-sql-${id}`, current_version: 1 });
    await query(`INSERT INTO workflow_definition_versions SELECT (jsonb_populate_record(NULL::workflow_definition_versions,to_jsonb(v)||jsonb_build_object('definition_id',$3::uuid,'version',1,'policy',v.policy-'allowSelfApproval'))).* FROM workflow_definition_versions v WHERE v.definition_id=$1 AND v.version=$2`, [pending.definition_id, pending.definition_version, id]);
    const sourceStages = (await query('SELECT level FROM workflow_definition_stages WHERE definition_id=$1 AND definition_version=$2 ORDER BY level', [pending.definition_id, pending.definition_version])).rows;
    for (const item of sourceStages) await clone('workflow_definition_stages', 'source.definition_id=$1 AND source.definition_version=$2 AND source.level=$3', [pending.definition_id, pending.definition_version, item.level], { definition_id: id, definition_version: 1 });
  });
  await reject('v1_null_threshold', '23514', async () => {
    const v1 = await row('SELECT definition_id,version FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND approval_format=1 ORDER BY definition_id,version LIMIT 1', [scope.clusterId, scope.workspaceId]); assert(v1, 'REAL_V1_DEFINITION_REQUIRED');
    const id = randomUUID(); await clone('workflow_definitions', 'source.id=$1', [v1.definition_id], { id, code: `m11-sql-${id}`, current_version: 1 });
    await clone('workflow_definition_versions', 'source.definition_id=$1 AND source.version=$2', [v1.definition_id, v1.version], { definition_id: id, version: 1 });
    await clone('workflow_definition_stages', 'source.definition_id=$1 AND source.definition_version=$2 AND source.level=1', [v1.definition_id, v1.version], { definition_id: id, definition_version: 1, required_approvals: null });
  });
  await reject('duplicate_candidate_manifest', '23514', () => clonePending(true));
  await reject('stage_advance_without_votes', '23514', async () => {
    await query("UPDATE workflow_stages SET state=CASE WHEN level=1 THEN 'approved' WHEN level=2 THEN 'active' ELSE state END,revision=revision+1,updated_at=now() WHERE workflow_id=$1 AND plan_revision=$2 AND level IN(1,2)", [pending.id, pending.plan_revision]);
  });
  const setFk = await row("SELECT conname FROM pg_constraint WHERE conrelid='workflow_approval_sets'::regclass AND confrelid='workflow_candidate_versions'::regclass AND contype='f'"); assert(setFk);
  await reject('cross_scope_set_binding', '23503', async () => {
    await clone('workflow_approval_sets', 'source.id=$1', [approved.approval_set_id], { id: randomUUID(), workspace_id: randomUUID(), workflow_id: pending.id, plan_revision: pending.plan_revision, plan_hash: pending.plan_hash });
  }, setFk.conname);
  await reject('execution_uses_other_workflow_set', '23503', async () => {
    await query(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,claim_token_hash,idempotency_key,expires_at,approval_format,approval_set_id,approval_set_hmac)
      VALUES($1,$2,$3,$4,$5,$6,'approval',true,$7,$8,$9,$10,$11,2,$12,$13)`, [randomUUID(), scope.clusterId, scope.workspaceId, pending.id, pending.plan_revision, pending.plan_hash, approved.approved_by, pending.requester_user_id, 'e'.repeat(64), `m11-sql-${randomUUID()}`, pending.expires_at, approved.approval_set_id, approved.approval_set_hmac]);
  }, 'workflow_executions_approval_set_fk');
  finalDigest = await sourceDigest(); finalLedgerDigest = await schemaLedgerDigest();
  assert(initialDigest === finalDigest && ledgerDigest === finalLedgerDigest, 'ORIGINAL_FIXTURE_OR_LEDGER_CHANGED');
  checks.push({ name: 'original_facts_and_schema_ledger_unchanged', passed: true });
  await query('ROLLBACK'); rolledBack = true;
  assert.equal(await sourceDigest(), initialDigest); assert.equal(await schemaLedgerDigest(), ledgerDigest);
  checks.push({ name: 'outer_transaction_rolled_back_and_originals_rechecked', passed: true });
  assert.equal(trials.length, 6); passed = true;
} catch (error) { failure = { stage, ...(activeNegativeTrial ? {negativeTrialName: activeNegativeTrial} : {}), ...fixedFailure(error) }; }
finally {
  if (client) { if (!rolledBack) { try { await query('ROLLBACK'); rolledBack = true; } catch {} } await client.end().catch(() => {}); }
  process.stdout.write(JSON.stringify({ passed, milestone: 'M11', gate: 1, checks, trials, outerRolledBack: rolledBack,
    originalFactsUnchanged: typeof initialDigest === 'string' && initialDigest === finalDigest,
    schemaLedgerUnchanged: typeof ledgerDigest === 'string' && ledgerDigest === finalLedgerDigest,
    productionDeployment: false, nativeKongRequests: 0, businessCommitted: false, shadowControlsAreSqlStructuralOnly: true, originalHttpResponsesRewritten: false,
    ...(failure ? { failure } : {}) }) + '\n');
  if (!passed) process.exitCode = 1;
}
