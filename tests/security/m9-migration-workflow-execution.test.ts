import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { NotFoundException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { MutationService, type MutationContext } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { WorkspaceMigrationWorkflowRecoveryService } from '../../apps/console-api/src/modules/workflows/workspace-migration-workflow-recovery.service';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { normalizedNativeRequests } from '../../apps/console-api/src/modules/workflows/approved-execution.types';
import { migrationNativeRequests } from '../../apps/console-api/src/modules/workflows/workspace-migration-workflow';
import { planAad, type WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import { workspaceTestResolver, PAY_WORKSPACE_ID, OPS_WORKSPACE_ID } from '../unit/workspace-test-helper';
import { assertWorkflowEvidenceSqlTypes } from './lib/m9-workflow-sql-contract';

/** Actual workflow engine, authorization, native policy, mutation ledger and
 * private approved verifier. SQL transactions, locks, audit persistence and
 * gateway transport are explicit in-memory boundaries. A limited migration
 * delegate drives the already sealed packets through those real policies;
 * this is not evidence for live M3 graph capture or a deployed gateway. */
function fixture() {
  const hooks: { beforeSend?: () => void; afterReviewerGrantLoad?: () => void; beforeTerminalFact?: () => void } = {};
  const cid = randomUUID(), workflowId = randomUUID(), migrationId = randomUUID(), stepId = randomUUID();
  const secrets = new SecretService(), context = new KongExecutionContextService(), workspaceFixture = workspaceTestResolver(cid);
  const source = structuredClone(workspaceFixture.rows.find(row => row.id === PAY_WORKSPACE_ID)!);
  const target = structuredClone(workspaceFixture.rows.find(row => row.id === OPS_WORKSPACE_ID)!);
  const executorId = randomUUID(), reviewerId = randomUUID(), sessionId = randomUUID();
  const user = { id: executorId, username: 'migration-executor', superAdmin: false };
  const actor = { user, workspaceId: source.id, requestId: randomUUID(), ip: '192.0.2.42', idempotencyKey: 'original-migration-execution' };
  const cluster = { id: cid, admin_url: 'http://kong:8001', transport_scope: 'b'.repeat(64), version: '1.5.1', execution_mode: 'approval', revision: 1, status: 'active' };
  const users = new Map([executorId, reviewerId].map(id => [id, { id, username: id === executorId ? user.username : 'independent-reviewer',
    super_admin: false, status: 'active', deleted_at: null, force_password_change: false, permissions_epoch: 1, credential_epoch: 1, revision: 1 }]));
  const grant = (wid: string, module: string, action: string) => ({ cluster_id: cid, workspace_id: wid, module, action, scope_type: 'workspace', scope_values: [wid] });
  const grants = new Map<string, any[]>([
    [executorId, [source.id, target.id].flatMap(wid => ['workflows', 'workspaces', 'services', 'consumers'].flatMap(module => ['read', 'write'].map(action => grant(wid, module, action))))],
    [reviewerId, [source.id, target.id].flatMap(wid => [grant(wid, 'workflows', 'approve'), ...['workflows', 'workspaces', 'services', 'consumers'].map(module => grant(wid, module, 'read'))])],
  ]);
  const serviceId = randomUUID(), consumerId = randomUUID(), credentialId = randomUUID();
  const native = new Map<string, any>([
    [`/services/${serviceId}`, { id: serviceId, name: 'pay-service', host: 'backend.test', tags: ['team-pay', 'kos-ws-pay'] }],
    [`/consumers/${consumerId}`, { id: consumerId, username: 'pay-consumer', tags: ['team-pay', 'kos-ws-pay'] }],
    [`/consumers/${consumerId}/key-auth/${credentialId}`, { id: credentialId, key: 'synthetic-original-key', consumer: { id: consumerId }, tags: ['team-pay', 'kos-ws-pay'] }],
  ]);
  const nodes = [...native].map(([path, data]) => {
    const nested = path.startsWith('/consumers/') && path.includes('/key-auth/'), type = nested ? 'key-auth' : path.split('/')[1];
    const { tags: _tags, updated_at: _updated, ...configuration } = data;
    return { key: nested ? `${type}:${consumerId}:${data.id}` : `${type}:${data.id}`, type, id: data.id, path,
      data: structuredClone(data), affected: true, restorable: true, dependencies: nested ? [`consumers:${consumerId}`] : [],
      sourceWorkspaceId: source.id, beforeFingerprint: secrets.fingerprint(data), configFingerprint: secrets.fingerprint(configuration),
      afterTags: ['team-pay', 'kos-ws-ops'], inheritedOnly: false };
  });
  const material: any = { source, target, nodes, referenceNodes: [], edges: [[nodes[2].key, nodes[1].key]], conflicts: [],
    budget: { pages: 4, records: 3, nodes: 3, bytes: 1800 }, permissions: `${executorId}:1:1` };
  const migrationHash = secrets.fingerprint({ cid, actor: executorId, payload: material }), payload = { plan_id: migrationId, plan_hash: migrationHash, confirmed: true, confirm_name: target.name };
  const before = { id: migrationId, workspace_id: source.id }, expiry = new Date(Date.now() + 600_000).toISOString();
  const plan: WorkflowPlanV1 = { version: 1, clusterId: cid, workspaceId: source.id, workflowId, planRevision: 1, kind: 'workspace-migration',
    executionMode: 'approval', approvalRequired: true, subject: { type: 'workspace_migration_plans', id: migrationId }, requester: { type: 'console', id: executorId },
    definition: { id: randomUUID(), version: 1, policyHash: secrets.fingerprint({ mode: 'single', allow_self_approval: false }) },
    issuedAt: new Date().toISOString(), expiresAt: expiry, scope: { transportScope: cluster.transport_scope, clusterRevision: 1, workspaceRevision: 1 },
    migration: { sourceWorkspaceId: source.id, targetWorkspaceId: target.id, targetWorkspaceRevision: 1, materialHmac: secrets.fingerprint(material) }, prerequisites: [],
    steps: [{ id: stepId, key: 'workspace-migration', order: 1, kind: 'native', entityType: 'workspace_migration', entityId: migrationId,
      permissionAction: 'write', dependencies: [], mutationAction: 'migrate', mutationPayload: payload, mutationPayloadHmac: secrets.fingerprint(payload),
      mutationIdempotencyKey: `migration-${workflowId}`, before, beforeFingerprint: secrets.fingerprint(before), nativeRequests: migrationNativeRequests(material, secrets) }] };
  validateWorkflowPlan(plan); const planHash = secrets.fingerprint(plan), step = plan.steps[0];
  const version: any = { cluster_id: cid, workspace_id: source.id, workflow_id: workflowId, plan_revision: 1, plan_hash: planHash,
    execution_mode: 'approval', approval_required: true, expires_at: expiry, policy_version: 1, step_count: 1, native_request_count: 3,
    steps_hash: secrets.fingerprint(plan.steps), payload_secret: secrets.encrypt(plan, planAad(cid, source.id, workflowId, 1)) };
  const state: any = { epoch: 1, workflow: { id: workflowId, cluster_id: cid, workspace_id: source.id, kind: plan.kind, subject_type: plan.subject.type,
    subject_id: migrationId, requester_type: 'console', requester_user_id: executorId, definition_id: plan.definition.id, definition_version: 1,
    plan_revision: 1, plan_hash: planHash, execution_mode: 'approval', approval_required: true, state: 'approved', approved_by: reviewerId,
    revision: 1, created_at: new Date().toISOString(), expires_at: expiry, idempotency_key: 'original-migration-submission' },
    executions: new Map<string, any>(), operations: new Map<string, any>(), audits: [], parents: [], events: [],
    rows: [{ id: step.id, cluster_id: cid, workspace_id: source.id, workflow_id: workflowId, plan_revision: 1, plan_hash: planHash,
      execution_mode: 'approval', approval_required: true, step_key: step.key, step_order: 1, kind: step.kind, handler: null,
      entity_type: step.entityType, entity_id: migrationId, parent_id: null, credential_kind: null, permission_action: 'write',
      mutation_action: 'migrate', mutation_payload_hmac: step.mutationPayloadHmac, mutation_idempotency_key: step.mutationIdempotencyKey,
      before_fingerprint: step.beforeFingerprint, native_requests: normalizedNativeRequests(step.nativeRequests, secrets),
      dependencies: [], metadata_before_hmac: null, metadata_revision: null, metadata_payload_hmac: null, operation_id: null, revision: 1, state: 'pending' }],
    migration: { id: migrationId, cluster_id: cid, actor_id: executorId, source_workspace_id: source.id, target_workspace_id: target.id,
      state: 'planned', plan_hash: migrationHash, payload_secret: secrets.encrypt(material, `workspace-migration:${migrationId}`),
      expires_at: new Date(Date.now() + 900_000).toISOString(), operation_id: null },
    migrationSteps:nodes.map(node=>({cluster_id:cid,plan_id:migrationId,object_key:node.key,type:node.type,kong_id:node.id,status:'pending',after_fingerprint:null,error_code:null})),
    failTerminalCas: null, failTerminalAudit: false, failRecoveryAudit:false, partialDelegate: false };
  const binding = { cluster_id: cid, source_workspace_id: source.id, target_workspace_id: target.id, migration_plan_id: migrationId,
    workflow_id: workflowId, actor_id: executorId, migration_plan_hash: migrationHash, material_hmac: plan.migration!.materialHmac };
  const approvals = [{ workflow_id: workflowId, decision: 'approve', approver_id: reviewerId, plan_hash: planHash, level: 1 }];
  const stages = [{ workflow_id: workflowId, state: 'approved', required_approvals: 1, level: 1, plan_hash: planHash }];
  const copy = (value: any) => value == null ? null : structuredClone(value);
  const db: any = { one: vi.fn(async (sql: string, p: any[] = []) => {
    if (sql.includes('FROM iam_epoch')) return { version: state.epoch };
    if (sql.includes('FROM auth_sessions')) return p[0] === sessionId && p[1] === executorId && p[2] === 1 ? { id: sessionId } : null;
    if (sql.includes('FROM users')) { const row = users.get(p[0]); return row?.status === 'active' && !row.deleted_at && (!sql.includes('force_password_change=false') || !row.force_password_change) ? copy(row) : null; }
    if (sql.includes('FROM workspace_migration_workflow_bindings')) return p[0] === cid && p[1] === migrationId && p[2] === workflowId ? copy(binding) : null;
    if (sql.includes('FROM workspace_migration_plans')) {
      const hit = sql.includes('WHERE id=$1') ? p[0] === migrationId && p[1] === cid && p[2] === source.id : p[0] === cid && p[1] === migrationId;
      return hit ? copy(state.migration) : null;
    }
    if (sql.includes('FROM workflow_definition_versions')) return { mode: 'single', allow_self_approval: false, policy_hash: plan.definition.policyHash };
    if (sql.includes('FROM workflow_versions')) return p[0] === cid && p[1] === source.id && p[2] === workflowId && p[3] === 1 ? copy(version) : null;
    if (sql.includes('FROM workflow_executions')) return copy(sql.includes('WHERE workflow_id=$1') ? [...state.executions.values()].find(e => e.workflow_id === p[0] && e.plan_revision === p[1])
      :sql.includes('WHERE cluster_id=$1')?[...state.executions.values()].find(e=>e.cluster_id===p[0]&&e.workspace_id===p[1]&&e.workflow_id===p[2]&&e.plan_revision===p[3]):state.executions.get(p[0]));
    if (sql.includes('FROM workflow_steps') && sql.includes('JOIN mutation_operations m')) {
      assertWorkflowEvidenceSqlTypes(sql);
      hooks.beforeTerminalFact?.();
      const row = state.rows.find(row => row.id === p[0] && row.workflow_id === p[1] && row.plan_revision === p[2] && row.plan_hash === p[3]);
      const operation = row && state.operations.get(row.operation_id), migration = state.migration;
      if(!row || !operation || operation.cluster_id!==row.cluster_id || operation.workspace_id!==row.workspace_id
        || migration.id!==operation.entity_id || migration.cluster_id!==operation.cluster_id) return null;
      return copy({...operation,step_state:row.state,operation_id:row.operation_id,mutation_state:operation.state,
        migration_state:migration.state,migration_plan_hash:migration.plan_hash,migration_operation_id:migration.operation_id,
        migration_actor_id:migration.actor_id,source_workspace_id:migration.source_workspace_id,target_workspace_id:migration.target_workspace_id,
        migration_material_secret:migration.payload_secret});
    }
    if (sql.includes('FROM workflow_steps')) return copy(state.rows.find(row => row.workflow_id === p[0] && row.state === 'running' || row.id === p[0]));
    if (sql.includes('FROM workflows')) return p[0] === workflowId || p[0] === cid && p[1] === source.id && p[2] === workflowId ? copy(state.workflow) : null;
    if (sql.includes('FROM mutation_operations')) return copy(sql.includes('WHERE cluster_id=$1 AND idempotency_key=$2')
      ? [...state.operations.values()].find(row => row.cluster_id === p[0] && row.idempotency_key === p[1])
      :sql.includes('WHERE cluster_id=$1 AND id=$2')?[...state.operations.values()].find(row=>row.cluster_id===p[0]&&row.id===p[1]):state.operations.get(p[0]));
    if(sql.includes('FROM workflow_events'))return copy(state.events.find(event=>event.cluster_id===p[0]&&event.workspace_id===p[1]&&event.workflow_id===p[2]&&event.actor_id===p[3]&&event.safe_metadata.executionId===p[4]));
    if (sql.includes('FROM clusters')) return p[0] === cid ? copy(cluster) : null;
    if (sql.includes('FROM workspaces')) return workspaceFixture.db.one(sql, p);
    throw new Error(`Unhandled test SQL read: ${sql}`);
  }), query: vi.fn(async (sql: string, p: any[] = []) => {
    if (sql.includes('FROM iam_effective_grants')) { const result=copy(grants.get(p[0]) ?? []);
      if(p[0]===reviewerId)hooks.afterReviewerGrantLoad?.();return result; }
    if (sql.includes('FROM workflow_approvals')) return copy(approvals);
    if (sql.includes('FROM workflow_stages')) return copy(stages);
    if (sql.includes('FROM workflow_steps')) return copy(state.rows);
    if (sql.includes('FROM workspace_migration_steps')) return copy(state.migrationSteps.map(row=>({...row,key:row.object_key,id:row.kong_id})));
    if (sql.includes('FROM mutation_operations')) return [...state.operations.values()].filter(row => ['running', 'uncertain'].includes(row.state) && row.id !== p[1]).map(copy);
    throw new Error(`Unhandled test SQL list: ${sql}`);
  }), exec: vi.fn(async (sql: string, p: any[] = []) => {
    if (sql.startsWith('INSERT INTO workspaces')) return 0;
    if (sql.startsWith('INSERT INTO entity_parent_index')) {
      if(p[0]!==cid)throw new Error('Foreign parent-index scope');
      for(const row of JSON.parse(p[3]))state.parents.push({cluster_id:p[0],child_type:p[1],parent_type:p[2],...row});return 1;
    }
    if(sql.startsWith('INSERT INTO workflow_events')){state.events.push({cluster_id:p[0],workspace_id:p[1],workflow_id:p[2],plan_revision:p[3],plan_hash:p[4],actor_id:p[5],actor_type:'user',action:'execution.reconcile-migration-metadata',result:'success',execution_id:p[6],step_id:p[7],operation_id:p[8],request_id:p[9],safe_metadata:JSON.parse(p[10])});return 1;}
    if (sql.startsWith('INSERT INTO workflow_executions')) { const [id, cluster_id, workspace_id, workflow_id, plan_revision, plan_hash, execution_mode, approval_required, approved_by, execution_actor_id, claim_token_hash, request_id, idempotency_key, expires_at] = p;
      state.executions.set(id, { id, cluster_id, workspace_id, workflow_id, plan_revision, plan_hash, execution_mode, approval_required, approved_by, execution_actor_id,
        claim_token_hash, request_id, idempotency_key, expires_at, state: 'executing', snapshot_state: 'pending', revision: 1 }); return 1; }
    if (sql.startsWith('INSERT INTO mutation_operations')) { const [id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret, workspace_id, transport_scope, impact, parent_id, credential_kind, workflow_execution_id, workflow_plan_revision, workflow_plan_hash, workflow_step_id] = p;
      state.operations.set(id, { id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id,
        before_secret, payload_secret, workspace_id, transport_scope, impact: JSON.parse(impact), parent_id, credential_kind, workflow_execution_id,
        workflow_plan_revision, workflow_plan_hash, workflow_step_id, state: 'running' }); return 1; }
    if (sql.startsWith('UPDATE workflow_steps SET operation_id')) { const row = state.rows.find(row => row.id === p[0]);
      if (!row || row.operation_id || row.state !== 'running' || row.revision !== p[2]) return 0; row.operation_id = p[1]; row.revision++; return 1; }
    if (sql.startsWith('UPDATE workflow_steps')) { const row = state.rows.find(row => row.id === p[0]); if (!row) return 0;
      if (sql.includes("SET state='running'")) { if (row.state !== 'pending') return 0; row.state = 'running'; }
      else if (sql.includes("SET state='succeeded'")) { if (state.failTerminalCas === 'workflow_steps' || row.state !== 'running'
        ||row.workflow_id!==p[5]||row.plan_revision!==p[6]||row.plan_hash!==p[7]) return 0;
        Object.assign(row, { state: 'succeeded', safe_result: JSON.parse(p[1]), receipt_secret: p[2], recycle_entry_id: p[3], after_fingerprint: p[4] }); }
      else if (sql.includes('SET state=$2')) { if (row.state !== 'running') return 0; Object.assign(row, { state: p[1], error_code: p[2], safe_result: JSON.parse(p[3]) }); }
      else throw new Error(`Unhandled step update: ${sql}`); row.revision++; return 1; }
    if (sql.startsWith('UPDATE workflow_executions')) { const row = state.executions.get(p[0]); if (!row) return 0;
      if (sql.includes("SET snapshot_state='ready'")) {if(row.snapshot_state!=='pending'||row.state!=='executing'||row.workflow_id!==p[4]||row.plan_hash!==p[5])return 0;
        Object.assign(row, { snapshot_state: 'ready', snapshot_secret: p[1], snapshot_hash: p[2], snapshot_id: p[3] });}
      else if (sql.includes("SET state='succeeded'")) { if (state.failTerminalCas === 'workflow_executions'
        ||row.state!==(sql.includes('AND state=$6')?p[5]:'executing')||sql.includes('AND revision=$7')&&row.revision!==p[6]
        ||row.workflow_id!==p[1]||row.plan_revision!==p[2]||row.plan_hash!==p[3]||row.execution_actor_id!==p[4]) return 0; row.state = 'succeeded'; }
      else if (sql.includes('SET state=$2')) { if (row.state !== 'executing') return 0; row.state = p[1]; }
      else throw new Error(`Unhandled execution update: ${sql}`); row.revision++; return 1; }
    if (sql.startsWith('UPDATE workflows')) { const row = state.workflow; if (row.id !== p[0]) return 0;
      if (sql.includes("SET state='executing'")) { if (row.revision !== p[1] || row.state !== p[2]) return 0; row.state = 'executing'; }
      else if (sql.includes("SET state='succeeded'")) {const recovery=sql.includes('AND cluster_id=$2');
        if(state.failTerminalCas==='workflows')return 0;
        if(recovery){if(row.cluster_id!==p[1]||row.workspace_id!==p[2]||row.plan_revision!==p[3]||row.plan_hash!==p[4]||row.revision!==p[5]||row.state!==p[6])return 0;}
        else if(row.state!=='executing'||row.plan_revision!==p[1]||row.plan_hash!==p[2]||row.revision!==p[3])return 0;
        row.state='succeeded'; }
      else if (sql.includes('SET state=$2')) { if (row.state !== 'executing') return 0; row.state = p[1]; }
      else throw new Error(`Unhandled workflow update: ${sql}`); row.revision++; return 1; }
    if (sql.startsWith('UPDATE mutation_operations')) { const row = state.operations.get(p[0]); if (!row) return 0;
      if (sql.includes('remote_started=true')) row.remote_started = true;
      else if (sql.includes('remote_completed=true')) Object.assign(row, { remote_completed: true, entity_id: p[1], result_secret: p[2] });
      else if (sql.includes("state='succeeded'")) Object.assign(row, { state: 'succeeded', safe_result: JSON.parse(p[1]) });
      else if (sql.includes('SET state=$2')) Object.assign(row, { state: p[1], error_code: p[2], safe_result: JSON.parse(p[3]) });
      else throw new Error(`Unhandled mutation update: ${sql}`); return 1; }
    throw new Error(`Unhandled test SQL mutation: ${sql}`);
  }), transaction: vi.fn(async (fn: any) => { const snapshot = structuredClone(state);
    try { return await fn(db); } catch (error) { Object.assign(state, snapshot); throw error; } }) };
  const resolver: any = workspaceFixture.resolver;
  // Resolver's transaction-aware lookups are allowed against the shared SQL
  // fixture; ordinary resolver calls keep its independent native-tag policy.
  const writes: any[] = [], reads: any[] = [];
  const kong: any = { transportScope: vi.fn(async (scope: string) => { if (scope !== cid) throw new Error('Foreign cluster'); return cluster.transport_scope; }),
    request: vi.fn(async (scope: string, method: string, path: string, body?: any, query: any = {}) => {
      if (scope !== cid) throw new Error('Foreign cluster');
      const ticket = await context.authorizeRequest(cluster, method, path, body, query);
      if (method === 'GET') { reads.push(path); const value = native.get(path) ?? (path === '/routes' ? { data: [], next: null } : null);
        if (!value) throw new NotFoundException(); return context.authorizeResponse(ticket, structuredClone(value)); }
      await context.assertApprovedNativeRequest(ticket, 'prepare'); hooks.beforeSend?.(); await context.beforeNativeSend(ticket);
      if (method !== 'PATCH' || !native.has(path)) throw new Error('Unexpected synthetic gateway packet');
      writes.push({ method, path, body: structuredClone(body), actorId: context.current().actor!.id, sessionId: context.current().sessionId });
      const after = { ...native.get(path), ...structuredClone(body), updated_at: 2 }; native.set(path, after);
      return context.authorizeResponse(ticket, structuredClone(after));
    }) };
  const authz = new AuthorizationService(db, resolver, kong, context);
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn(async () => undefined) };
  const audit: any = { append: vi.fn(async (event: any, tx?: any) => {
    if (state.failTerminalAudit && event.action === 'workflow.execute' && event.result === 'success') throw new Error('Synthetic terminal audit storage failure');
    if(state.failRecoveryAudit&&event.action==='workflow.reconcile-migration-metadata')throw new Error('Synthetic recovery audit storage failure');
    state.audits.push({ event: secrets.redact(event), transaction: tx === db }); return { id: randomUUID() };
  }) };
  const approved = new ApprovedWorkflowExecutionService(db, secrets, authz, resolver, kong, redis, context); approved.onModuleInit();
  const policy = new NativeKongPolicyService(db, secrets, kong, context, authz, resolver); policy.install();
  const mutations = new MutationService(db, redis, secrets, audit, kong, authz, resolver, context);
  const plans: any = { load: vi.fn(async (scope: string, wid: string, id: string) => {
    if (scope !== cid || wid !== source.id || id !== workflowId) throw new NotFoundException();
    const frozen = secrets.decrypt<WorkflowPlanV1>(version.payload_secret, planAad(cid, source.id, workflowId, 1)); validateWorkflowPlan(frozen);
    if (secrets.fingerprint(frozen) !== state.workflow.plan_hash || version.steps_hash !== secrets.fingerprint(frozen.steps)) throw new Error('Frozen plan mismatch');
    return { row: copy(state.workflow), plan: frozen, version: copy(version) };
  }) };
  const migrations: any = { apply: vi.fn(async (scope: string, id: string, input: any, child: any) => {
    if (scope !== cid || id !== migrationId || input.plan_hash !== migrationHash || child.user.id !== executorId) throw new Error('Unexpected migration dispatch');
    const mutation: MutationContext = { clusterId: cid, workspaceId: source.id, actor: child.user, entityType: 'workspace_migration', entityId: migrationId,
      action: 'migrate', before, payload, idempotencyKey: child.idempotencyKey, requestId: child.requestId, ip: child.ip, impactNodes: nodes };
    return mutations.execute(mutation, async () => {
      state.migration.state = 'running'; state.migration.operation_id = mutation.operationId;
      const affected = [];
      for (const request of step.nativeRequests) {
        const after=await kong.request(cid, request.method, request.canonicalPath, request.body);
        const ack=state.migrationSteps.find(row=>row.kong_id===request.nativeId&&row.type===request.nativeType);
        Object.assign(ack,{status:'succeeded',after_fingerprint:secrets.fingerprint(after)});
        affected.push({ key: nodes.find(node => node.path === request.canonicalPath)!.key, id: request.nativeId, type: request.nativeType, status: 'succeeded' });
        if (state.partialDelegate) { state.migration.state = 'partial'; return { id: migrationId, state: 'partial', affected }; }
      }
      state.migration.state = 'succeeded'; return { id: migrationId, state: 'succeeded', affected };
    });
  }) };
  const workflow = new WorkflowService(db, redis, secrets, kong, context, authz, audit, {} as any, mutations, {} as any, resolver,
    plans, new WorkflowRegistryService(), approved, {} as any, migrations);
  const recovery=new WorkspaceMigrationWorkflowRecoveryService(db,redis,secrets,kong,context,authz,audit,plans,approved);
  const executeBody = { revision: 1, planHash, confirmed: true, confirm_name: 'workspace-migration' };
  const http = <T>(fn: () => Promise<T>) => context.runHttp({ requestId: actor.requestId }, async () => {
    context.bindHttpActor(user, sessionId); const close = context.captureHttpCloser();
    try { return await fn(); } finally { close(); }
  });
  const execute = () => http(() => workflow.execute(cid, workflowId, executeBody, actor));
  const revokeReviewer = (wid: string, module: string, action: string) => grants.set(reviewerId, grants.get(reviewerId)!.filter(grant => !(grant.workspace_id === wid && grant.module === module && grant.action === action)));
  return { state, plan, version, db, context, authz, approved, workflow, mutations, migrations, execute, writes, reads, native, grants, users,
    actor, reviewerId, sessionId, source, target, serviceId, consumerId, credentialId, revokeReviewer, secrets, audit, hooks,
    http,cid,workflowId,migrationId,material,kong,redis,resolver,recovery };
}

beforeEach(() => { vi.stubEnv('APP_SECRET', 'm9-migration-harness-independent-hmac-secret-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cc'.repeat(32));
  vi.stubEnv('PORTAL_ENABLED', 'false'); vi.stubEnv('METRICS_BRIDGE_ENABLED', 'false'); });
afterEach(() => {vi.unstubAllEnvs();vi.useRealTimers();});

describe('M9 actual workflow execution with independent live reviewer eligibility', () => {
  it('executes the sealed three-packet migration under the requester SID and commits terminal workflow audit', async () => {
    const f = fixture(), receipt = await f.execute();
    expect(receipt.state).toBe('succeeded'); expect(f.state.workflow.state).toBe('succeeded');
    expect([...f.state.executions.values()][0].state).toBe('succeeded'); expect(f.state.rows[0].state).toBe('succeeded');
    expect(f.writes).toHaveLength(3); expect(f.writes.every(packet => packet.actorId === f.actor.user.id && packet.sessionId === f.sessionId)).toBe(true);
    expect(f.native.get(`/consumers/${f.consumerId}/key-auth/${f.credentialId}`).key).toBe('synthetic-original-key');
    expect(f.state.audits.filter(row => row.event.action === 'workflow.execute' && row.event.result === 'success'))
      .toMatchObject([{ transaction: true, event: { actorId: f.actor.user.id, requestId: f.actor.requestId, ip: f.actor.ip } }]);
    const readSessions = f.db.one.mock.calls.filter(call => call[0].includes('FROM auth_sessions'));
    expect(readSessions.length).toBeGreaterThan(0); expect(readSessions.every(call => call[1][1] === f.actor.user.id)).toBe(true);
    const count = f.writes.length; await expect(f.execute()).resolves.toMatchObject({ state: 'succeeded' }); expect(f.writes).toHaveLength(count);
  });

  it.each(['workflow_steps', 'workflow_executions', 'workflows'])('does not replay packets after the terminal %s CAS rejects', async table => {
    const f = fixture(); f.state.failTerminalCas = table;
    await expect(f.execute()).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    expect(f.writes).toHaveLength(3); expect(f.state.workflow.state).not.toBe('succeeded');
    expect(f.state.audits.some(row => row.event.action === 'workflow.execute' && row.event.result === 'success')).toBe(false);
    const before = f.writes.length; await f.execute(); expect(f.writes).toHaveLength(before); expect(f.migrations.apply).toHaveBeenCalledOnce();
  });

  it('rolls terminal success back on mandatory audit failure while keeping known native completion and original-key recovery', async () => {
    const f = fixture(); f.state.failTerminalAudit = true;
    await expect(f.execute()).rejects.toMatchObject({ response: { code: 'WORKFLOW_EXECUTION_FAILED' } });
    expect(f.writes).toHaveLength(3); expect(f.state.workflow.state).not.toBe('succeeded');
    expect([...f.state.operations.values()][0]).toMatchObject({ state: 'succeeded', remote_completed: true });
    expect(f.state.audits.some(row => row.event.action === 'workflow.execute' && row.event.result === 'success')).toBe(false);
    const before = f.writes.length; await f.execute(); expect(f.writes).toHaveLength(before); expect(f.migrations.apply).toHaveBeenCalledOnce();
  });

  it.each([['workflows', 'approve'], ['services', 'read'], ['consumers', 'read']])('sends zero native packets after target reviewer %s/%s revocation', async (module, action) => {
    const f = fixture(); f.revokeReviewer(f.target.id, module, action);
    await expect(f.execute()).rejects.toMatchObject({ status: 403, response: { code: 'PERMISSION_DENIED' } });
    expect(f.writes).toHaveLength(0); expect(f.migrations.apply).not.toHaveBeenCalled(); expect(f.state.workflow.state).not.toBe('succeeded');
  });

  it('rejects disabled reviewers without replacing the executor identity or sending a packet', async () => {
    const f = fixture(); f.users.get(f.reviewerId)!.status = 'disabled';
    await expect(f.execute()).rejects.toMatchObject({ status: 403, response: { code: 'APPROVED_APPROVER_REVOKED' } });
    expect(f.writes).toHaveLength(0); expect(f.migrations.apply).not.toHaveBeenCalled();
  });

  it('rechecks target reviewer approval after authorization and prepare, before the first packet is sent', async () => {
    const f = fixture(); f.hooks.beforeSend = () => f.revokeReviewer(f.target.id, 'workflows', 'approve');
    await expect(f.execute()).rejects.toMatchObject({ status: 403, response: { code: 'PERMISSION_DENIED' } });
    expect(f.writes).toHaveLength(0); expect(f.migrations.apply).toHaveBeenCalledOnce();
    expect([...f.state.operations.values()][0]).toMatchObject({state:'failed',remote_started:true});
  });

  it('fences reviewer or executor epoch changes introduced while reading reviewer grants', async () => {
    const f = fixture(); f.hooks.afterReviewerGrantLoad = () => { f.state.epoch++; };
    await expect(f.execute()).rejects.toMatchObject({ status: 403, response: { code: 'PERMISSION_DENIED' } });
    expect(f.writes).toHaveLength(0); expect(f.migrations.apply).not.toHaveBeenCalled();
  });

  it.each(['missing native acknowledgement','altered before HMAC','partial stored result','missing joined mutation'])('rejects terminal %s without treating first-packet GET as proof',async reason=>{
    const f=fixture();f.hooks.beforeTerminalFact=()=>{
      const operation=[...f.state.operations.values()][0];
      if(reason==='missing native acknowledgement')operation.remote_completed=false;
      if(reason==='altered before HMAC')operation.before_secret=f.secrets.encrypt({id:randomUUID()},`mutation:${operation.id}:before`);
      if(reason==='partial stored result')operation.result_secret=f.secrets.encrypt({id:f.plan.subject.id,state:'partial',affected:[]},`mutation:${operation.id}:result`);
      if(reason==='missing joined mutation')f.state.operations.delete(operation.id);
    };
    await expect(f.execute()).rejects.toMatchObject({response:{code:'MIGRATION_WORKFLOW_ACK_MISSING',state:'uncertain'}});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).not.toBe('succeeded');
    expect(f.state.audits.some(row=>row.event.action==='workflow.execute'&&row.event.result==='success')).toBe(false);
    const before=f.writes.length;await f.execute();expect(f.writes).toHaveLength(before);expect(f.migrations.apply).toHaveBeenCalledOnce();
  });

  it.each(['empty','missing','duplicate','foreign'])('rejects %s acknowledged object graphs rather than inferring completion from every([])',async reason=>{
    const f=fixture();f.hooks.beforeTerminalFact=()=>{
      const operation=[...f.state.operations.values()][0];
      const result=f.secrets.decrypt<any>(operation.result_secret,`mutation:${operation.id}:result`);
      if(reason==='empty')result.affected=[];
      if(reason==='missing')result.affected.pop();
      if(reason==='duplicate')result.affected[result.affected.length-1]=structuredClone(result.affected[0]);
      if(reason==='foreign')result.affected[result.affected.length-1]={key:`consumers:${randomUUID()}`,type:'consumers',id:randomUUID(),status:'succeeded'};
      operation.result_secret=f.secrets.encrypt(result,`mutation:${operation.id}:result`);
    };
    await expect(f.execute()).rejects.toMatchObject({response:{code:'MIGRATION_WORKFLOW_ACK_MISSING',state:'uncertain'}});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).not.toBe('succeeded');
    expect(f.state.audits.some(row=>row.event.action==='workflow.execute'&&row.event.result==='success')).toBe(false);
    const before=f.writes.length;await f.execute();expect(f.writes).toHaveLength(before);expect(f.migrations.apply).toHaveBeenCalledOnce();
  });

  it('does not mistake a deterministically partial migration for a successful workflow', async () => {
    const f = fixture(); f.state.partialDelegate = true;
    await expect(f.execute()).rejects.toMatchObject({ response: { code: 'MIGRATION_WORKFLOW_PARTIAL', state: 'partial' } });
    expect(f.writes).toHaveLength(1); expect(f.state.workflow.state).toBe('partial');
    const before = f.writes.length; await f.execute(); expect(f.writes).toHaveLength(before); expect(f.migrations.apply).toHaveBeenCalledOnce();
  });
});

describe('M9 known-complete migration metadata recovery without native authority',()=>{
  async function ready(){
    const f=fixture();f.state.failTerminalAudit=true;
    await expect(f.execute()).rejects.toMatchObject({response:{code:'WORKFLOW_EXECUTION_FAILED',state:'uncertain'}});
    f.state.failTerminalAudit=false;
    const execution=[...f.state.executions.values()][0];
    const body={revision:f.state.workflow.revision,planHash:f.state.workflow.plan_hash,executionId:execution.id,confirmed:true,confirm_name:'workspace-migration'};
    const scope=<T>(fn:()=>Promise<T>)=>f.http(()=>f.context.runActor({actor:f.actor.user,clusterId:f.cid,workspaceId:f.source.id,module:'workflows',action:'write'},fn));
    const recover=(value:any=body,actor:any=f.actor)=>scope(()=>f.recovery.reconcile(f.cid,f.workflowId,value,actor));
    const projection=()=>f.http(()=>f.recovery.projection(f.cid,f.source.id,f.workflowId,f.actor));
    expect(f.writes).toHaveLength(3);expect(f.state.rows[0].state).toBe('succeeded');
    return{...f,execution,body,recover,projection};
  }

  it('closes only parent metadata, audits the original execution and replays without minting another native claim',async()=>{
    const f=await ready(),nativeCount=f.writes.length;
    const approvedCalls=vi.spyOn(f.approved,'runApprovedExecution');
    await expect(f.projection()).resolves.toMatchObject({eligible:true,knownNativeComplete:true,originalExecutionKeyRequired:true,executionId:f.execution.id});
    await f.recover();
    expect(f.state.workflow.state).toBe('succeeded');expect([...f.state.executions.values()][0].state).toBe('succeeded');
    expect(f.writes).toHaveLength(nativeCount);expect(approvedCalls).not.toHaveBeenCalled();expect(f.migrations.apply).toHaveBeenCalledOnce();
    expect(f.state.events).toHaveLength(1);expect(f.state.events[0].safe_metadata).toMatchObject({executionId:f.execution.id,knownNativeComplete:true,nativeWrites:0,originalResponseResolved:false});
    expect(f.state.audits.filter(row=>row.event.action==='workflow.reconcile-migration-metadata'))
      .toMatchObject([{transaction:true,event:{actorId:f.actor.user.id,requestId:f.actor.requestId,ip:f.actor.ip,result:'success',after:{nativeWrites:0,originalResponseResolved:false}}}]);
    await expect(f.projection()).resolves.toMatchObject({eligible:false,completed:true,knownNativeComplete:true});
    const metadataCount=f.state.events.length;await f.recover();expect(f.state.events).toHaveLength(metadataCount);expect(f.writes).toHaveLength(nativeCount);
    await expect(f.execute()).resolves.toMatchObject({state:'succeeded'});expect(f.writes).toHaveLength(nativeCount);
  });

  it('permits historical metadata closure after the sealed native plan expires, with zero new writes or approved handles',async()=>{
    const f=await ready();vi.useFakeTimers();vi.setSystemTime(Date.now()+700_000);
    const approvedCalls=vi.spyOn(f.approved,'runApprovedExecution');
    await expect(f.projection()).resolves.toMatchObject({eligible:true});await f.recover();
    expect(f.writes).toHaveLength(3);expect(approvedCalls).not.toHaveBeenCalled();expect(f.state.workflow.state).toBe('succeeded');
  });

  it.each(['wrong key','wrong execution','wrong hash','foreign actor'])('rejects %s recovery requests without sending a packet',async reason=>{
    const f=await ready(),body={...f.body},actor={...f.actor};
    if(reason==='wrong key')actor.idempotencyKey='different-original-execution-key';
    if(reason==='wrong execution')body.executionId=randomUUID();
    if(reason==='wrong hash')body.planHash='e'.repeat(64);
    if(reason==='foreign actor')actor.user={...actor.user,id:randomUUID()};
    await expect(f.recover(body,actor)).rejects.toMatchObject({status:403});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).toBe('uncertain');expect(f.state.events).toHaveLength(0);
  });

  it.each(['unknown mutation','missing acknowledged component','uncertain component','missing receipt','foreign snapshot','incomplete stored graph'])('refuses metadata closure with %s',async reason=>{
    const f=await ready(),mutation=[...f.state.operations.values()][0];
    if(reason==='unknown mutation')mutation.state='uncertain';
    if(reason==='missing acknowledged component')f.state.migrationSteps.pop();
    if(reason==='uncertain component')f.state.migrationSteps[0].status='uncertain';
    if(reason==='missing receipt')f.state.rows[0].receipt_secret=null;
    if(reason==='foreign snapshot'){
      const aad=`workflow:${f.cid}:${f.source.id}:${f.workflowId}:${f.execution.id}:snapshot`;
      const snapshot=f.secrets.decrypt<any>(f.execution.snapshot_secret,aad);snapshot.executionId=randomUUID();
      f.execution.snapshot_secret=f.secrets.encrypt(snapshot,aad);f.execution.snapshot_hash=f.secrets.fingerprint(snapshot);
    }
    if(reason==='incomplete stored graph'){
      const result=f.secrets.decrypt<any>(mutation.result_secret,`mutation:${mutation.id}:result`);result.affected=[];
      mutation.result_secret=f.secrets.encrypt(result,`mutation:${mutation.id}:result`);
    }
    await expect(f.projection()).resolves.toBeUndefined();await expect(f.recover()).rejects.toMatchObject({response:{code:'MIGRATION_METADATA_RECOVERY_NOT_ELIGIBLE'}});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).toBe('uncertain');expect(f.state.events).toHaveLength(0);
  });

  it.each([['workflows','approve'],['services','read'],['consumers','read']])('rechecks current target reviewer %s/%s on recovery',async(module,action)=>{
    const f=await ready();f.revokeReviewer(f.target.id,module,action);
    await expect(f.projection()).resolves.toBeUndefined();await expect(f.recover()).rejects.toMatchObject({status:403,response:{code:'PERMISSION_DENIED'}});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).toBe('uncertain');expect(f.state.events).toHaveLength(0);
  });

  it.each(['workflows','consumers'])('requires the original owner current target %s write grant for metadata closure',async module=>{
    const f=await ready();f.grants.set(f.actor.user.id,f.grants.get(f.actor.user.id)!.filter(grant=>!(grant.workspace_id===f.target.id&&grant.module===module&&grant.action==='write')));
    await expect(f.projection()).resolves.toBeUndefined();await expect(f.recover()).rejects.toMatchObject({status:403,response:{code:'PERMISSION_DENIED'}});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).toBe('uncertain');expect(f.state.events).toHaveLength(0);
  });

  it.each(['workflows','workflow_executions'])('rolls the recovery transaction back if its %s CAS rejects',async table=>{
    const f=await ready();f.state.failTerminalCas=table;
    await expect(f.recover()).rejects.toMatchObject({response:{code:'REVISION_CONFLICT'}});
    expect(f.state.workflow.state).toBe('uncertain');expect([...f.state.executions.values()][0].state).toBe('uncertain');
    expect(f.state.events).toHaveLength(0);expect(f.writes).toHaveLength(3);
    f.state.failTerminalCas=null;await f.recover();expect(f.state.workflow.state).toBe('succeeded');expect(f.state.events).toHaveLength(1);expect(f.writes).toHaveLength(3);
  });

  it('rejects changed current credential configuration rather than issuing another write to restore the expected graph',async()=>{
    const f=await ready();f.native.get(`/consumers/${f.consumerId}/key-auth/${f.credentialId}`).key='externally-rotated-synthetic-key';
    await expect(f.recover()).rejects.toMatchObject({status:409,response:{code:'MIGRATION_RECOVERY_CURRENT_OBJECT_CHANGED'}});
    expect(f.writes).toHaveLength(3);expect(f.state.workflow.state).toBe('uncertain');expect(f.state.events).toHaveLength(0);
  });

  it('rolls parent states, closure event and audit back together if recovery audit storage fails, then safely retries the same key',async()=>{
    const f=await ready();f.state.failRecoveryAudit=true;
    await expect(f.recover()).rejects.toThrow('Synthetic recovery audit storage failure');
    expect(f.state.workflow.state).toBe('uncertain');expect([...f.state.executions.values()][0].state).toBe('uncertain');
    expect(f.state.events).toHaveLength(0);expect(f.writes).toHaveLength(3);
    f.state.failRecoveryAudit=false;await f.recover();expect(f.state.workflow.state).toBe('succeeded');expect(f.state.events).toHaveLength(1);expect(f.writes).toHaveLength(3);
  });
});
