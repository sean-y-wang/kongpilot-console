/**
 * Real M9 storage evidence, run only in the self-owned release API container.
 * DATABASE_URL and the encryption key come from that container's environment.
 * Every SQL trial rolls back; this script creates no successful source facts,
 * sends no Kong request, and prints neither row content nor credentials.
 *
 * Host invocation (the two fixed Docker hosts are intentional):
 *   cat tests/security/m9-native-recycle-storage-actual.mjs | GOMAXPROCS=2 \
 *     docker --host=unix:///var/run/docker.sock exec --env GOMAXPROCS=2 -i \
 *     kongos-ram-tool-m08-20261012-a3 docker \
 *     --host=unix:///run/docker-production.sock exec -i \
 *     -e RELEASE_LAB_READY=true -e RELEASE_LAB_CONTAINER=kongpilot-release-lab-console-api-1 \
 *     kongpilot-release-lab-console-api-1 node --input-type=module
 * Save the single public JSON line to artifacts/M9/recycle-storage-verification.json.
 */
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

const CID = 'e269f167-53e9-4895-af89-5b1b8835c6ec';
const CONTAINER = 'kongpilot-release-lab-console-api-1';
const require = createRequire('/app/package.json');
const checks = [];
const attempts = [];
let client;
let transactionsRolledBack = 0;
let passed = false;
let failure;
let fixtureCounts;

const safeError = error => ({
  code: /^[A-Z0-9_]+$/.test(error?.code ?? '') ? error.code : 'ASSERTION_FAILED',
  ...(typeof error?.constraint === 'string' && /^[a-z0-9_]+$/.test(error.constraint)
    ? { constraint: error.constraint } : {}),
});
const check = async (name, fn) => {
  try {
    const evidence = await fn();
    checks.push({ name, passed: true, ...(evidence ?? {}) });
  } catch (error) {
    checks.push({ name, passed: false, ...safeError(error) });
    throw error;
  }
};

// Keep a single connection so no failed trial can leave an open transaction.
const rollbackTrial = async (name, sql, values, expectedCode, expectedConstraint) => {
  await client.query('BEGIN');
  let observed;
  try {
    await client.query("SET LOCAL lock_timeout='1s'");
    await client.query("SET LOCAL statement_timeout='5s'");
    try { await client.query(sql, values); } catch (error) { observed = safeError(error); }
  } finally {
    await client.query('ROLLBACK');
    transactionsRolledBack++;
  }
  attempts.push({ name, rolledBack: true, ...(observed ?? { code: 'UNEXPECTED_SQL_SUCCESS' }) });
  assert.equal(observed?.code, expectedCode);
  if (expectedConstraint) assert.equal(observed?.constraint, expectedConstraint);
  return observed;
};

const componentInsert = `INSERT INTO configuration_recycle_components
 (cluster_id,workspace_id,graph_id,step_id,recycle_entry_id,operation_id)
 VALUES($1,$2,$3,$4,$5,$6)`;
const componentValues = (row, patch = {}) => {
  const value = { ...row, ...patch };
  return ['cluster_id', 'workspace_id', 'graph_id', 'step_id', 'recycle_entry_id', 'operation_id'].map(key => value[key]);
};
const graphInsert = `INSERT INTO configuration_recycle_graphs
 (id,cluster_id,workspace_id,job_id,execution_id,plan_id,plan_revision,plan_hash,
 actor_id,recycle_entry_id,graph_hmac,delete_count,object_workspace_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`;
const graphValues = (row, patch = {}) => {
  const value = { ...row, id: randomUUID(), ...patch };
  return ['id', 'cluster_id', 'workspace_id', 'job_id', 'execution_id', 'plan_id',
    'plan_revision', 'plan_hash', 'actor_id', 'recycle_entry_id', 'graph_hmac',
    'delete_count', 'object_workspace_id'].map(key => value[key]);
};

// Hash only protected, already existing source rows, never decrypted content.
const sourceDigest = async () => {
  const result = await client.query(`SELECT jsonb_build_object(
    'graphs',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.id),'[]') FROM configuration_recycle_graphs g WHERE g.cluster_id=$1),
    'components',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.step_id),'[]') FROM configuration_recycle_components c WHERE c.cluster_id=$1),
    'entries',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]') FROM recycle_entries r WHERE r.cluster_id=$1 AND r.id IN(
      SELECT recycle_entry_id FROM configuration_recycle_graphs WHERE cluster_id=$1 UNION SELECT recycle_entry_id FROM configuration_recycle_components WHERE cluster_id=$1)),
    'nodes',(SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY n.entry_id,n.node_key),'[]') FROM recycle_nodes n WHERE n.entry_id IN(
      SELECT recycle_entry_id FROM configuration_recycle_graphs WHERE cluster_id=$1 UNION SELECT recycle_entry_id FROM configuration_recycle_components WHERE cluster_id=$1)),
    'executions',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]') FROM configuration_executions e WHERE e.cluster_id=$1 AND e.id IN(
      SELECT execution_id FROM configuration_recycle_graphs WHERE cluster_id=$1)),
    'steps',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM configuration_job_steps s WHERE s.cluster_id=$1 AND s.execution_id IN(
      SELECT execution_id FROM configuration_recycle_graphs WHERE cluster_id=$1)),
    'mutations',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]') FROM mutation_operations m WHERE m.cluster_id=$1 AND m.id IN(
      SELECT operation_id FROM configuration_recycle_components WHERE cluster_id=$1))
    ) AS source`, [CID]);
  return createHash('sha256').update(JSON.stringify(result.rows[0].source)).digest('hex');
};

try {
  await check('explicit self-owned container, console database and non-owner runtime gate', async () => {
    assert.equal(process.env.RELEASE_LAB_READY, 'true');
    assert.equal(process.env.RELEASE_LAB_CONTAINER, CONTAINER);
    assert.equal(process.cwd(), '/app');
    const url = new URL(process.env.DATABASE_URL ?? 'invalid:');
    assert(['postgres:', 'postgresql:'].includes(url.protocol));
    assert.equal(url.hostname, 'console-db');
    assert.equal(url.port, '5432');
    assert.equal(url.pathname, '/kongpilot');
    assert.equal(url.username, 'kongpilot_lab_app');
    require('reflect-metadata');
    const { Client } = require('pg');
    client = new Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000 });
    await client.connect();
    const { rows } = await client.query(`SELECT current_database() AS database,current_user AS role,
      rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls
      FROM pg_roles WHERE rolname=current_user`);
    assert.equal(rows[0].database, 'kongpilot');
    assert.equal(rows[0].role, 'kongpilot_lab_app');
    for (const flag of ['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls']) assert.equal(rows[0][flag], false);
    const cluster = await client.query('SELECT id FROM clusters WHERE id=$1', [CID]);
    assert.equal(cluster.rowCount, 1);
  });

  const initialDigest = await sourceDigest();
  const graphs = (await client.query('SELECT * FROM configuration_recycle_graphs WHERE cluster_id=$1 ORDER BY created_at,id LIMIT 51', [CID])).rows;
  const components = (await client.query(`SELECT c.*,g.execution_id,g.object_workspace_id
    FROM configuration_recycle_components c JOIN configuration_recycle_graphs g ON g.id=c.graph_id
    WHERE c.cluster_id=$1 ORDER BY g.created_at,c.step_id LIMIT 501`, [CID])).rows;
  const { SecretService } = require('/app/apps/console-api/dist/infrastructure/secret.service.js');
  const secrets = new SecretService();

  await check('real completed native executions supply multiple sealed workspace graphs', async () => {
    assert(graphs.length >= 3 && graphs.length <= 50);
    assert(components.length >= 6 && components.length <= 500);
    const executions = new Set(graphs.map(row => row.execution_id));
    const workspaces = new Set(graphs.map(row => row.object_workspace_id));
    assert(executions.size >= 2);
    assert(workspaces.size >= 3);
    const grouped = new Map();
    for (const row of graphs) grouped.set(row.execution_id, [...(grouped.get(row.execution_id) ?? []), row]);
    const crossWorkspace = [...grouped.values()].find(rows => new Set(rows.map(row => row.object_workspace_id)).size >= 2);
    assert(crossWorkspace);
    assert.equal(new Set(crossWorkspace.map(row => row.workspace_id)).size, 1, 'Execution anchor must remain fixed');
    assert(crossWorkspace.some(row => row.object_workspace_id !== row.workspace_id));
    fixtureCounts = { sealedGraphs: graphs.length, components: components.length, sourceExecutions: executions.size, objectWorkspaces: workspaces.size };
    return fixtureCounts;
  });

  await check('every whole archive decrypts with its original AAD and matches the sealed graph HMAC', async () => {
    for (const g of graphs) {
      const { rows } = await client.query(`SELECT r.*,e.actor_id AS execution_actor,e.cluster_id AS execution_cluster,
        e.workspace_id AS execution_workspace,e.job_id AS execution_job,e.plan_id AS execution_plan,
        e.plan_revision AS execution_revision,e.plan_hash AS execution_hash,e.state AS execution_state,
        v.plan_hash AS version_hash,v.source_job_id AS version_job
        FROM recycle_entries r JOIN configuration_executions e ON e.id=$1
        JOIN configuration_plan_versions v ON v.cluster_id=e.cluster_id AND v.workspace_id=e.workspace_id
        AND v.plan_id=e.plan_id AND v.plan_revision=e.plan_revision WHERE r.id=$2`, [g.execution_id,g.recycle_entry_id]);
      assert.equal(rows.length, 1);
      const r = rows[0];
      assert.equal(r.cluster_id, CID);
      assert.equal(r.workspace_id, g.object_workspace_id);
      assert.equal(r.actor_id, g.actor_id);
      assert.equal(r.execution_actor, g.actor_id);
      assert.equal(r.execution_cluster, g.cluster_id);
      assert.equal(r.execution_workspace, g.workspace_id);
      assert.equal(r.execution_job, g.job_id);
      assert.equal(r.execution_plan, g.plan_id);
      assert.equal(r.execution_revision, g.plan_revision);
      assert.equal(r.execution_hash, g.plan_hash);
      assert.equal(r.version_hash, g.plan_hash);
      assert.equal(r.version_job, g.job_id);
      assert.equal(r.execution_state, 'succeeded');
      const graph = secrets.decrypt(r.payload_secret, `recycle:${r.id}`);
      assert.equal(secrets.fingerprint(graph), g.graph_hmac);
      assert.equal(graph.complete, true);
      assert.equal(graph.purpose, 'recycle');
      assert.equal(graph.nodes.length, r.node_count);
      assert.equal(graph.nodes.filter(node => node.affected).length, g.delete_count);
      const nodes = (await client.query('SELECT * FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key', [r.id])).rows;
      assert.equal(nodes.length, graph.nodes.length);
      for (const node of graph.nodes) {
        const stored = nodes.find(row => row.node_key === node.key);
        assert(stored);
        assert.equal(stored.entity_type, node.type);
        assert.equal(stored.original_id, node.id);
        assert.equal(stored.affected, node.affected);
        assert.deepEqual([...stored.dependencies].sort(), [...node.dependencies].sort());
        if (node.affected) {
          assert.equal(node.restorable, true);
          assert(node.restoreData);
          assert.equal(stored.delete_state, 'deleted');
        }
      }
    }
    return { credentialMaterialPrinted: false };
  });

  await check('each component has its exact delete step, actor, entity workspace and acknowledged native receipt', async () => {
    for (const c of components) {
      const { rows } = await client.query(`SELECT s.*,p.entity_type AS plan_type,p.mutation_action AS plan_action,
        p.object_workspace_id AS plan_workspace,p.before_hmac AS plan_before,
        r.workspace_id AS archive_workspace,r.actor_id AS archive_actor,r.mutation_id AS archive_mutation,
        r.root_type,r.credential_kind,r.original_id,r.parent_id,
        m.workspace_id AS mutation_workspace,m.actor_id AS mutation_actor,m.action AS mutation_action,
        m.state AS mutation_state,m.remote_started,m.remote_completed,m.before_secret,
        g.actor_id AS graph_actor,g.job_id AS graph_job,g.execution_id AS graph_execution,g.workspace_id AS graph_anchor,
        g.object_workspace_id AS graph_workspace,g.recycle_entry_id AS full_entry
        FROM configuration_job_steps s
        JOIN configuration_plan_objects p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id
        AND p.plan_id=s.plan_id AND p.plan_revision=s.plan_revision AND p.step_id=s.plan_step_id
        JOIN recycle_entries r ON r.id=$2 JOIN mutation_operations m ON m.id=$3
        JOIN configuration_recycle_graphs g ON g.id=$4 WHERE s.id=$1`,
      [c.step_id,c.recycle_entry_id,c.operation_id,c.graph_id]);
      assert.equal(rows.length, 1);
      const s = rows[0];
      assert.equal(s.cluster_id, c.cluster_id);
      assert.equal(s.workspace_id, c.workspace_id);
      assert.equal(s.workspace_id, s.graph_anchor);
      assert.equal(s.job_id, s.graph_job);
      assert.equal(s.execution_id, s.graph_execution);
      assert.equal(s.object_workspace_id, s.graph_workspace);
      assert.equal(s.object_workspace_id, s.plan_workspace);
      assert.equal(s.object_workspace_id, s.archive_workspace);
      assert.equal(s.object_workspace_id, s.mutation_workspace);
      assert.equal(s.graph_actor, s.archive_actor);
      assert.equal(s.graph_actor, s.mutation_actor);
      assert.equal(s.state, 'succeeded');
      assert.equal(s.receipt_operation_id, c.operation_id);
      assert.equal(s.archive_mutation, c.operation_id);
      assert.equal(s.recycle_entry_id, c.recycle_entry_id);
      assert.equal(s.plan_action, 'delete');
      assert.equal(s.mutation_action, 'delete');
      assert.equal(s.mutation_state, 'succeeded');
      assert.equal(s.remote_started, true);
      assert.equal(s.remote_completed, true);
      assert.equal(s.before_hmac, s.plan_before);
      assert.equal(secrets.fingerprint(secrets.decrypt(s.before_secret, `mutation:${c.operation_id}:before`)), s.before_hmac);
      const nodeKey = `${s.credential_kind ?? s.root_type}:${s.parent_id ? `${s.parent_id}:` : ''}${s.original_id}`;
      const node = (await client.query('SELECT node_key FROM recycle_nodes WHERE entry_id=$1 AND node_key=$2 AND affected', [s.full_entry,nodeKey])).rows;
      assert.equal(node.length, 1);
    }
  });

  await check('deployed origin trigger binds live execution, original actor, entity workspace and real native acknowledgment', async () => {
    const { rows } = await client.query("SELECT pg_get_functiondef('m9_validate_configuration_recycle()'::regprocedure) AS source");
    const source = rows[0].source.replace(/\s+/g, ' ');
    for (const predicate of ['e.actor_id=NEW.actor_id',"e.state='executing'","r.state='archived'",
      'r.workspace_id=NEW.object_workspace_id','r.actor_id=e.actor_id','s.job_id=g.job_id',
      's.execution_id=g.execution_id','s.object_workspace_id=g.object_workspace_id',
      'r.workspace_id=g.object_workspace_id','m.workspace_id=g.object_workspace_id',
      "s.state='succeeded'",'s.receipt_operation_id=NEW.operation_id','r.mutation_id=m.id',
      'm.actor_id=g.actor_id',"m.state='succeeded'",'m.remote_completed']) assert(source.includes(predicate), predicate);
  });

  await check('composite FK definitions preserve the job anchor and independently bind the entity workspace', async () => {
    const constraints = (await client.query(`SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conrelid IN ('configuration_recycle_graphs'::regclass,'configuration_recycle_components'::regclass)`)).rows;
    const definitions = constraints.map(row => row.definition);
    for (const expected of [
      'FOREIGN KEY (cluster_id, object_workspace_id) REFERENCES workspaces(cluster_id, id)',
      'FOREIGN KEY (cluster_id, workspace_id, execution_id, job_id, plan_revision, plan_hash) REFERENCES configuration_executions(cluster_id, workspace_id, id, job_id, plan_revision, plan_hash)',
      'FOREIGN KEY (cluster_id, workspace_id, graph_id) REFERENCES configuration_recycle_graphs(cluster_id, workspace_id, id)',
      'FOREIGN KEY (cluster_id, workspace_id, step_id) REFERENCES configuration_job_steps(cluster_id, workspace_id, id)',
      'FOREIGN KEY (cluster_id, operation_id) REFERENCES mutation_operations(cluster_id, id)',
    ]) assert(definitions.some(value => value.startsWith(expected)), expected);
  });

  for (const table of ['configuration_recycle_graphs','configuration_recycle_components']) {
    await check(`runtime UPDATE, DELETE and TRUNCATE on ${table} are denied and rolled back`, async () => {
      const select = table.endsWith('graphs') ? { field:'id',id:graphs[0].id } : { field:'step_id',id:components[0].step_id };
      for (const [action, sql, values] of [
        ['update',`UPDATE ${table} SET cluster_id=cluster_id WHERE ${select.field}=$1`,[select.id]],
        ['delete',`DELETE FROM ${table} WHERE ${select.field}=$1`,[select.id]],
        ['truncate',`TRUNCATE ${table}`,[]],
      ]) await rollbackTrial(`${table}.${action}`,sql,values,'42501');
    });
  }

  const current = components[0];
  const foreignWorkspace = components.find(row => row.object_workspace_id !== current.object_workspace_id);
  const foreignExecution = components.find(row => row.execution_id !== current.execution_id);
  const sibling = components.find(row => row.graph_id === current.graph_id && row.step_id !== current.step_id);
  assert(foreignWorkspace && foreignExecution && sibling);
  await check('exact real component reaches duplicate constraint after its origin predicate succeeds', async () =>
    rollbackTrial('valid-real-component-duplicate',componentInsert,componentValues(current),'23505','configuration_recycle_components_pkey'));
  await check('cross-workspace graph cannot adopt another workspace\'s real acknowledged deletion', async () =>
    rollbackTrial('cross-workspace-graph',componentInsert,componentValues(current,{graph_id:foreignWorkspace.graph_id}),'23503'));
  await check('a different real execution step cannot replace the original step', async () =>
    rollbackTrial('cross-execution-step',componentInsert,componentValues(current,{step_id:foreignExecution.step_id}),'23503'));
  await check('another real acknowledged sibling receipt cannot authorize the current step', async () =>
    rollbackTrial('wrong-real-native-receipt',componentInsert,componentValues(current,{operation_id:sibling.operation_id}),'23503'));
  await check('another real recycle component cannot replace the original step archive', async () =>
    rollbackTrial('wrong-real-step-archive',componentInsert,componentValues(current,{recycle_entry_id:sibling.recycle_entry_id}),'23503'));
  await check('a missing native receipt cannot create composite membership', async () =>
    rollbackTrial('missing-native-receipt',componentInsert,componentValues(current,{operation_id:randomUUID()}),'23503'));
  await check('a real deletion step cannot gain a second membership in another cluster', async () =>
    rollbackTrial('cross-cluster-component',componentInsert,componentValues(current,{cluster_id:randomUUID()}),'23505','configuration_recycle_components_step_id_key'));
  await check('a forged cluster and workspace cannot bind a real acknowledged component', async () =>
    rollbackTrial('cross-cluster-and-workspace-component',componentInsert,
      componentValues(current,{cluster_id:randomUUID(),workspace_id:foreignWorkspace.object_workspace_id}),'23505','configuration_recycle_components_step_id_key'));

  await check('a completed source execution cannot be reused to create a new whole archive', async () =>
    rollbackTrial('terminal-source-graph-reuse',graphInsert,graphValues(graphs[0]),'23503'));
  await check('whole-graph insert with another existing actor is refused by the frozen source predicate', async () => {
    const actor = (await client.query('SELECT id FROM users WHERE id<>$1 ORDER BY id LIMIT 1', [graphs[0].actor_id])).rows[0];
    assert(actor);
    return rollbackTrial('forged-whole-graph-actor',graphInsert,graphValues(graphs[0],{actor_id:actor.id}),'23503');
  });
  await check('whole-graph insert with another real execution is refused', async () =>
    rollbackTrial('forged-whole-graph-execution',graphInsert,graphValues(graphs[0],{execution_id:foreignExecution.execution_id}),'23503'));
  await check('whole-graph insert with another real entity workspace is refused', async () =>
    rollbackTrial('forged-whole-graph-workspace',graphInsert,
      graphValues(graphs[0],{object_workspace_id:foreignWorkspace.object_workspace_id}),'23503'));

  await check('all existing graph, component, archive, execution, step and native mutation facts remain unchanged', async () => {
    assert.equal(await sourceDigest(), initialDigest);
    return { originalFactsUnchanged:true, rollbackTrials:transactionsRolledBack };
  });
  passed = true;
} catch (error) {
  failure = safeError(error);
} finally {
  if (client) { await client.query('ROLLBACK').catch(() => undefined); await client.end().catch(() => undefined); }
  const report = {
    passed, milestone:'M9', evidence:'actual composite-recycle rows created by real Kong 1.5.1 executions',
    environment:{container:CONTAINER,database:'kongpilot',runtimeRole:'kongpilot_lab_app',clusterId:CID},
    nativeKongRequests:false, consoleDatabaseOnly:true, credentialsRecorded:false,
    noPersistentWrites:true, rollbackTrials:transactionsRolledBack,
    fixtureCounts, checks, attempts,
    limits:[
      'Whole-graph source executions are already terminal. Their actor, execution and workspace insert denials share the live-execution/archive predicate; they do not isolate each predicate independently.',
      'The exact real component replay passes the origin predicate and fails only at the existing primary key. Other component forgeries use already acknowledged facts to isolate graph, step, archive and receipt binding.',
      'Cross-cluster replay of an existing acknowledged step reaches UNIQUE(step_id) before the composite foreign keys. The SQL trial proves no second membership; the foreign-key structure is verified separately from deployed catalog definitions.',
      'This verifies the deployed PostgreSQL runtime role and storage bindings; HTTP authorization and credential usability are covered by separate native acceptance evidence.',
    ],
    ...(failure ? { failure } : {}),
  };
  process.stdout.write(JSON.stringify(report,null,2)+'\n');
  if (!passed) process.exitCode=1;
}
