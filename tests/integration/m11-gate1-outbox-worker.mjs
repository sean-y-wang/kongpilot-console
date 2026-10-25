import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require = createRequire('/app/package.json');
const {Client} = require('pg');
let client, passed = false, checks = [], failure;
try {
  assert.equal(process.env.RELEASE_LAB_READY, 'true');
  assert.equal(process.env.RELEASE_LAB_M11_GATE1_OUTBOX_READY, 'true');
  assert.equal(process.cwd(), '/app');
  const url = new URL(process.env.DATABASE_URL);
  assert.equal(url.hostname, 'console-db'); assert.equal(url.pathname, '/kongpilot');
  assert.equal(decodeURIComponent(url.username), 'kongpilot_lab_app');
  client = new Client({connectionString: process.env.DATABASE_URL}); await client.connect();
  await client.query('BEGIN READ ONLY'); await client.query("SET LOCAL statement_timeout='5s'");
  const cid = '095b11dd-a414-4f76-b591-9fdfa4a29d83', wid = '22002fd0-8f1f-4213-a2b6-c539e9b8c136';
  const ids = ['4f3ee988-cdb4-4f3f-947f-63ee59f85302', '79daeacf-2556-4ef0-baa8-d67dd4c55c7e'];
  for (const id of ids) {
    const audit = (await client.query(`SELECT a.action,count(*)::int AS count,
      count(*) FILTER(WHERE e.id IS NOT NULL AND o.state='dispatched')::int AS dispatched,
      count(*) FILTER(WHERE e.event_type=CASE WHEN a.action='workflow.approval.progress' THEN 'workflow.approval.progress' ELSE 'workflow.approved' END
        AND e.phase=CASE WHEN a.action='workflow.approval.progress' THEN 'aggregate' ELSE 'terminal' END)::int AS correctly_mapped
      FROM audit_events a LEFT JOIN event_records e ON e.audit_event_id=a.id LEFT JOIN event_outbox o ON o.event_id=e.id
      WHERE a.cluster_id=$1 AND a.workspace_id=$2 AND a.workflow_id=$3 AND a.result='success'
        AND a.action IN('workflow.approval.progress','workflow.approve') GROUP BY a.action ORDER BY a.action`, [cid, wid, id])).rows;
    const progress = audit.find(r => r.action === 'workflow.approval.progress'), terminal = audit.find(r => r.action === 'workflow.approve');
    assert.equal(progress?.count, 4); assert.equal(terminal?.count, 1);
    for (const r of audit) {assert.equal(r.dispatched, r.count); assert.equal(r.correctly_mapped, r.count);}
    checks.push({name: 'actual_partial_votes_are_progress_events_and_only_final_vote_is_approved', passed: true, workflowId: id, progressEvents: 4, approvedEvents: 1, dispatchedEvents: 5});
  }
  const blocked = (await client.query('SELECT count(*)::int AS count FROM workflow_executions WHERE workflow_id=$1', [ids[1]])).rows[0];
  assert.equal(blocked.count, 0); checks.push({name: 'revoked_reviewer_rejection_created_no_execution_claim', passed: true});
  const native = (await client.query('SELECT count(*)::int AS count FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2', [cid, wid])).rows[0];
  assert.equal(native.count, 0); checks.push({name: 'entire_own_M11_workspace_has_zero_native_mutations', passed: true});
  const policy = (await client.query('SELECT id,payload_secret,material_hmac FROM workflow_policy_requests WHERE cluster_id=$1 AND workspace_id=$2', [cid, wid])).rows;
  assert.equal(policy.length, 1);
  const {SecretService} = require('/app/apps/console-api/dist/infrastructure/secret.service.js');
  const secrets = new SecretService(), intent = secrets.decrypt(policy[0].payload_secret, `workflow-policy:${policy[0].id}`);
  assert.equal(secrets.fingerprint(intent), policy[0].material_hmac);
  assert.equal(intent.before.current_version, 1); assert.equal(intent.payload.policy.version, 2);
  checks.push({name: 'actual_frozen_policy_intent_records_original_version_before_execution', passed: true, originalDefinitionVersion: 1, requestedPolicyFormat: 2});
  await client.query('ROLLBACK'); passed = true;
} catch (error) {failure = /^[A-Z0-9]{5}$/.test(error?.code ?? '') ? error.code : 'M11_GATE1_OUTBOX_ASSERTION_FAILED';}
finally {
  if (client) {await client.query('ROLLBACK').catch(() => {}); await client.end();}
  console.log(JSON.stringify({passed, checks, productionDeployment: false, nativeKongRequests: 0, transactionReadOnly: true,
    externalDeliveryVerified: false, notificationDeliveryVerified: false, ...(failure ? {failure} : {})}));
  if (!passed) process.exitCode = 1;
}
