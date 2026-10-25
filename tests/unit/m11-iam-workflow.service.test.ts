import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { IamWorkflowService } from '../../apps/console-api/src/modules/iam/iam-workflow.service';
import { IamService } from '../../apps/console-api/src/modules/iam/iam.service';
import { IamMutationsService } from '../../apps/console-api/src/modules/iam/iam-mutations.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';

/** Real compiler, IAM services, private execution WeakMap and Context ALS.
 * SQL/Redis/current-grants and the Root persist/Approved provider are
 * fixture transports. These tests do not certify live SQL or native Kong. */
function fixture(twoClusters = false) {
  const cid = '40000000-0000-4000-8000-000000000001', wid = randomUUID(), cid2 = '40000000-0000-4000-8000-000000000002', wid2 = randomUUID(), rid = randomUUID();
  const userId = randomUUID(), reviewerId = randomUUID(), sid = randomUUID(), otherSid = randomUUID(), reviewerSid = randomUUID();
  const secrets = new SecretService(), context = new KongExecutionContextService();
  const author: any = { user: { id: userId, username: 'iam-owner', superAdmin: false }, workspaceId: wid, idempotencyKey: 'iam-workflow-original-key', requestId: randomUUID(), ip: '192.0.2.81' };
  const reviewer: any = { user: { id: reviewerId, username: 'iam-reviewer', superAdmin: false }, workspaceId: wid, idempotencyKey: 'iam-reviewer-key', requestId: randomUUID(), ip: '192.0.2.82' };
  const globalGrant = (module: string, action: string) => ({ module, action, scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
  const workspaceGrant = (module: string, action: string, clusterId: string, workspaceId: string) => ({ module, action, scope_type: 'workspace', scope_values: [workspaceId], cluster_id: clusterId, workspace_id: workspaceId });
  const scopes = [[cid, wid], ...(twoClusters ? [[cid2, wid2]] : [])];
  let state: any = {
    epoch: 10,
    users: new Map([userId, reviewerId].map(id => [id, { id, username: id === userId ? 'iam-owner' : 'iam-reviewer', status: 'active', super_admin: false, force_password_change: false, deleted_at: null, credential_epoch: 3, permissions_epoch: 7 }])),
    grants: new Map([userId, reviewerId].map(id => [id, [globalGrant('roles', 'read'), globalGrant('roles', 'write'), globalGrant('roles', 'delete'), globalGrant('permissions', 'read'), globalGrant('permissions', 'write'),
      ...scopes.flatMap(([clusterId, workspaceId]) => ['read', 'write', 'approve'].map(action => workspaceGrant('workflows', action, clusterId, workspaceId)))]])),
    sessions: new Map([[sid, { id: sid, user_id: userId, credential_epoch: 3, expires_at: new Date(Date.now() + 1800000).toISOString(), revoked_at: null }],
      [otherSid, { id: otherSid, user_id: userId, credential_epoch: 3, expires_at: new Date(Date.now() + 1800000).toISOString(), revoked_at: null }],
      [reviewerSid, { id: reviewerSid, user_id: reviewerId, credential_epoch: 3, expires_at: new Date(Date.now() + 1800000).toISOString(), revoked_at: null }]]),
    clusters: new Map(scopes.map(([id]) => [id, { id, admin_url: id === cid ? 'http://kong:8001' : 'http://kong-two:8001', transport_scope: null, revision: 2, execution_mode: 'approval', version: '1.5.1', status: 'healthy', deleted_at: null }])),
    workspaces: new Map(scopes.map(([cluster_id, id]) => [id, { id, cluster_id, revision: 3, is_default: true, status: 'active', deleted_at: null }])),
    roles: new Map([[rid, { id: rid, code: 'payment_ops', name: 'Payments Operators', description: 'Original role', revision: 4, status: 'active', protected: false, builtin_kind: null,
      cluster_id: twoClusters ? null : cid, workspace_id: twoClusters ? null : wid }]]),
    permissions: twoClusters ? scopes.map(([cluster_id, workspace_id]) => ({ id: randomUUID(), role_id: rid, module: 'services', action: 'read', scope_type: 'workspace', scope_values: [workspace_id], cluster_id, workspace_id, status: 'active', revision: 1 })) : [],
    teams: new Map(), bindings: [], intents: new Map(), metadata: new Map(), workflows: new Map(), plans: new Map(), operations: new Map(), facts: [], audit: [], revokeOwnPermissions: false,
    definition: { id: randomUUID(), version: 1 }, policy: { version: 2, kind: 'iam-metadata', allowSelfApproval: false, distinctAcrossStages: true, intentTtlHours: 24,
      stages: [{ level: 1, name: 'IAM reviewer', mode: 'any', threshold: 1, selector: { users: [reviewerId] } }] }, policyFormat: 2, running: null,
  };
  const writes: string[] = [], metadataChecks: any[] = [];
  const one = (sql: string, p: any[] = []): any => {
    if (sql.includes('FROM iam_epoch')) return { version: state.epoch };
    if (sql.includes('FROM auth_sessions')) { const row = state.sessions.get(p[0]), user = row && state.users.get(row.user_id);
      return row && (!p[1] || row.user_id === p[1]) && !row.revoked_at && Date.parse(row.expires_at) > Date.now() && (p[2] == null || String(row.credential_epoch) === String(p[2]))
        && (!sql.includes('JOIN users') || user?.status === 'active' && !user.deleted_at && !user.force_password_change && row.credential_epoch === user.credential_epoch) ? structuredClone(row) : null; }
    if (sql.includes('FROM users WHERE id=')) { const row = state.users.get(p[0]); return row && (!sql.includes("status='active'") || row.status === 'active' && !row.deleted_at && !row.force_password_change) ? structuredClone(row) : null; }
    if (sql.includes("FROM clusters WHERE execution_mode='approval'")) return [...state.clusters.values()].find((row: any) => row.execution_mode === 'approval' && row.deleted_at == null && (p[0] === true || p[1].includes(row.id))) ?? null;
    if (sql.includes('FROM clusters WHERE id=')) { const row = state.clusters.get(p[0]); return row?.deleted_at == null ? structuredClone(row ?? null) : null; }
    if (sql.includes('FROM workspaces')) { const row = p[1] ? state.workspaces.get(p[1]) : [...state.workspaces.values()].find((row: any) => row.cluster_id === p[0] && row.is_default); return row && row.cluster_id === p[0] && (!sql.includes("status='active'") || row.status === 'active' && row.deleted_at == null) ? structuredClone(row) : null; }
    if (sql.includes('FROM roles WHERE id=')) return structuredClone(state.roles.get(p[0]) ?? null);
    if (sql.includes('FROM teams WHERE id=')) return structuredClone(state.teams.get(p[0]) ?? null);
    if (sql.startsWith('SELECT id FROM roles WHERE code=')) return [...state.roles.values()].find((row: any) => row.code === p[0]) ?? null;
    if (sql.includes('FROM iam_change_intents')) return structuredClone(sql.includes('actor_id=$1') ? [...state.intents.values()].find((row: any) => row.actor_id === p[0] && row.idempotency_key === p[1]) ?? null : state.intents.get(p[0]) ?? null);
    if (sql.includes('FROM iam_metadata_requests')) { const row = state.metadata.get(p[0]); return row && (!p[1] || row.workflow_id === p[1]) && (!p[2] || row.cluster_id === p[2]) && (!p[3] || row.workspace_id === p[3]) ? structuredClone(row) : null; }
    if (sql.includes('FROM workflow_definition_versions')) return { approval_format: state.policyFormat, policy: structuredClone(state.policy) };
    if (sql.includes('FROM workflow_executions e JOIN workflows')) {
      const row = state.running;
      return row && row.executionId === p[0] && row.workflowId === p[1] && row.clusterId === p[2] && row.workspaceId === p[3] && row.actorId === p[4] && row.stepId === p[5] && row.planHash === p[6] && row.planRevision === p[7]
        && row.executionState === 'executing' && row.workflowState === 'executing' && row.stepState === 'running' && row.handler === 'iam.metadata' && row.kind === 'metadata' && row.nativeCount === 0 && row.approvalFormat === 2 ? { id: row.executionId } : null;
    }
    if (sql.includes('FROM workflows WHERE id=')) return structuredClone(state.workflows.get(p[0]) ?? null);
    if (sql.includes('FROM iam_workflow_mutation_facts f')) {
      if (sql.startsWith('SELECT f.*,o.idempotency_key')) {
        const fact = state.facts.find((f: any[]) => f[1] === p[0] && f[2] === p[1] && f[3] === p[2] && f[4] === p[3] && f[7] === p[4] && f[8] === p[5] && f[10] === p[6] && f[9] === p[7]), operation = fact && state.operations.get(fact[0]);
        return operation && { operation_id: fact[0], intent_id: fact[1], workflow_id: fact[2], execution_id: fact[3], step_id: fact[4], cluster_id: fact[5], workspace_id: fact[6], actor_id: fact[7], session_id: fact[8],
          plan_revision: fact[9], plan_hash: fact[10], before_permission_version: fact[11], after_permission_version: fact[12], before_iam_epoch: fact[13], after_iam_epoch: fact[14], result_hmac: fact[15], workflow_cluster_id: fact[16], workflow_workspace_id: fact[17],
          operation_key: operation.idempotency_key, operation_actor: operation.actor_id, operation_cluster_id: operation.cluster_id, operation_workspace_id: operation.workspace_id, operation_state: operation.state, remote_completed: operation.remote_completed, result_secret: operation.result_secret };
      }
      if (sql.startsWith('SELECT e.id AS execution_id')) {
        const fact = state.facts.find((f: any[]) => f[1] === p[0] && f[2] === p[1] && f[7] === p[2] && f[8] === p[3] && f[10] === p[4] && f[9] === p[5]), operation = fact && state.operations.get(fact[0]), workflow = state.workflows.get(p[1]), running = state.running;
        return fact && operation && workflow && running && workflow.cluster_id === p[6] && workflow.workspace_id === p[7] && workflow.state === 'succeeded' && running.executionState === 'succeeded' && running.stepState === 'succeeded'
          && operation.state === 'succeeded' && operation.remote_completed === true && fact[3] === running.executionId && fact[4] === running.stepId && fact[2] === running.workflowId
          && running.planHash === workflow.plan_hash && running.planRevision === workflow.plan_revision && fact[7] === running.actorId && running.handler === 'iam.metadata' && running.kind === 'metadata' && running.nativeCount === 0
          ? { execution_id: running.executionId, execution_key: running.executionKey, revision: workflow.revision, step_id: running.stepId } : null;
      }
      const fact = state.facts.find((f: any[]) => f[1] === p[0] && f[2] === p[1] && f[7] === p[2] && f[8] === p[3] && f[10] === p[4]), running = state.running;
      return fact && running && fact[3] === running.executionId && fact[4] === running.stepId && fact[2] === running.workflowId && fact[10] === running.planHash && fact[7] === running.actorId
        && running.executionState === 'succeeded' && running.stepState === 'succeeded' && running.handler === 'iam.metadata' ? { operation_id: fact[0] } : null;
    }
    if (sql.includes('FROM iam_operations')) return [...state.operations.values()].find((row: any) => row.actor_id === p[0] && row.idempotency_key === p[1]) ?? null;
    if (sql.startsWith('INSERT INTO roles')) { writes.push(sql); const row = { id: p[0], code: p[1], name: p[2], description: p[3], cluster_id: p[4], workspace_id: p[5], revision: 1, status: 'active', protected: false, builtin_kind: null }; state.roles.set(row.id, row); state.epoch++; return structuredClone(row); }
    if (sql.startsWith('UPDATE roles SET')) {
      writes.push(sql); const row = state.roles.get(p[p.length - 2]); if (!row || row.revision !== p[p.length - 1]) return null;
      for (const field of sql.matchAll(/(name|description)=\$(\d+)/g)) row[field[1]] = p[Number(field[2]) - 1];
      row.revision++; state.epoch++; return structuredClone(row);
    }
    throw new Error(`Unimplemented IAM fixture query: ${sql}`);
  };
  const query = (sql: string, p: any[] = []): any[] => {
    if (sql.includes('FROM iam_effective_grants')) return structuredClone(state.grants.get(p[0]) ?? []);
    if (sql.includes('SELECT id,execution_mode FROM clusters')) return [...state.clusters.values()].filter((row: any) => row.deleted_at == null && (p[0] === true || p[1].includes(row.id))).map((row: any) => ({ id: row.id, execution_mode: row.execution_mode }));
    if (sql.includes('SELECT id FROM clusters')) return [...state.clusters.values()].filter((row: any) => row.deleted_at == null).map((row: any) => ({ id: row.id }));
    if (sql.includes('FROM role_permissions')) return structuredClone(state.permissions.filter((row: any) => row.role_id === p[0] && row.status === 'active'));
    if (sql.includes('FROM user_role_bindings')) return structuredClone(state.bindings.filter((row: any) => sql.includes('role_id=$1') ? row.role_id === p[0] : row.user_id === p[0]));
    if (sql.includes('FROM team_role_bindings') || sql.includes('FROM team_members')) return [];
    throw new Error(`Unimplemented IAM fixture list: ${sql}`);
  };
  const exec = (sql: string, p: any[] = []): number => {
    writes.push(sql);
    if (sql.startsWith('INSERT INTO iam_change_intents')) state.intents.set(p[0], { id: p[0], cluster_id: p[1], workspace_id: p[2], actor_id: p[3], authoring_session_id: p[4], workflow_id: p[5], idempotency_key: p[6], request_hmac: p[7], material_hmac: p[8], material_secret: p[9], credential_epoch: p[10], permission_version: p[11], issued_at: p[12], expires_at: p[13] });
    else if (sql.startsWith('INSERT INTO iam_metadata_requests')) state.metadata.set(p[0], { id: p[0], cluster_id: p[1], workspace_id: p[2], actor_id: p[3], workflow_id: p[4], idempotency_key: p[5], request_hmac: p[6], material_hmac: p[7] });
    else if (sql.startsWith('INSERT INTO iam_operations')) state.operations.set(p[0], { id: p[0], actor_id: p[1], idempotency_key: p[2], request_hash: p[3], module: p[4], action: p[5], target_id: p[6], cluster_id: p[7], workspace_id: p[8], payload_secret: p[9], state: 'running', remote_completed: false });
    else if (sql.startsWith('UPDATE iam_operations')) { const row = state.operations.get(p[0]); if (!row || row.state !== 'running') return 0;
      if (sql.includes('state=$2')) Object.assign(row, { state: p[1], remote_completed: p[2], error_code: p[3], safe_result: JSON.parse(p[4]) });
      else Object.assign(row, { state: 'succeeded', remote_completed: true, result_secret: p[1], safe_result: JSON.parse(p[2]) }); }
    else if (sql.startsWith('INSERT INTO iam_workflow_mutation_facts')) state.facts.push([...p]);
    else if (sql.startsWith('UPDATE role_permissions')) { for (const row of state.permissions) if (row.role_id === p[0] && row.status === 'active') row.status = 'revoked'; state.epoch++;
      if (state.revokeOwnPermissions) { state.grants.set(userId, []); state.users.get(userId).permissions_epoch++; } }
    else if (sql.startsWith('INSERT INTO role_permissions')) { state.permissions.push({ id: p[0], role_id: p[1], module: p[2], action: p[3], scope_type: p[4], cluster_id: p[5], workspace_id: p[6],
      scope_values: p[4] === 'workspace' ? [p[6]] : [], status: 'active', revision: 1 }); state.epoch++; }
    else if (sql.startsWith('INSERT INTO role_permission_tags')) state.permissions.find((row: any) => row.id === p[0]).scope_values.push(p[2]);
    else if (sql.startsWith('INSERT INTO role_permission_entities')) state.permissions.find((row: any) => row.id === p[0]).scope_values.push({ entity_type: p[1], entity_id: p[2] });
    else throw new Error(`Unexpected IAM fixture write: ${sql}`);
    return 1;
  };
  const tx: any = { one: vi.fn(async (sql: string, p?: any[]) => one(sql, p)), query: vi.fn(async (sql: string, p?: any[]) => query(sql, p)), exec: vi.fn(async (sql: string, p?: any[]) => exec(sql, p)) };
  const db: any = { one: vi.fn(async (sql: string, p?: any[]) => one(sql, p)), query: vi.fn(async (sql: string, p?: any[]) => query(sql, p)), exec: vi.fn(async (sql: string, p?: any[]) => exec(sql, p)),
    transaction: vi.fn(async (fn: any) => { const before = structuredClone(state); try { return await fn(tx); } catch (error) { state = before; throw error; } }) };
  const authz: any = { snapshot: vi.fn(async (user: any, transaction: any = db) => { const row = await transaction.one("SELECT * FROM users WHERE id=$1 AND status='active'", [user.id]); if (!row) throw new ForbiddenException(); return { user: { ...user, superAdmin: row.super_admin === true }, grants: await transaction.query('SELECT * FROM iam_effective_grants WHERE user_id=$1', [user.id]) }; }), assertDelegatable: vi.fn(), assertConsole: vi.fn(), assertCluster: vi.fn(), isPlatformAdmin: vi.fn(async (user: any) => state.users.get(user.id)?.super_admin === true) };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn() }, audit: any = { append: vi.fn(async (event: any) => state.audit.push(secrets.redact(event))) };
  const mutations = new IamMutationsService(db, redis, secrets, audit, authz), iam = new IamService(db, secrets, audit, authz, {} as any, mutations);
  const registry = new WorkflowRegistryService();
  const plans: any = { definitions: vi.fn(), definition: vi.fn(async () => ({ ...state.definition, policyHash: secrets.fingerprint(state.policy) })),
    persist: vi.fn(async (plan: any, key: string, request: any, transaction: any, metadata: any) => { expect(transaction).toBe(tx); validateWorkflowPlan(plan); state.plans.set(plan.workflowId, immutableJson(plan)); state.workflows.set(plan.workflowId, { id: plan.workflowId, cluster_id: plan.clusterId, workspace_id: plan.workspaceId, state: 'pending', revision: 1, plan_revision: plan.planRevision, plan_hash: secrets.fingerprint(plan), idempotency_key: key, request_hmac: secrets.fingerprint(request), request: structuredClone(metadata) }); }) };
  const workflow = new IamWorkflowService(db, redis, secrets, audit, authz, context, iam, mutations, plans, registry); workflow.onModuleInit();
  const originalExecutions = new WeakMap<object, any>(), originalSteps = new WeakMap<object, any>();
  const approved: any = {
    verifyExecution: vi.fn(async (handle: object) => { const proof = originalExecutions.get(handle); if (!proof) throw new Error('Fixture original Approved handle required'); return proof; }),
    verifyStep: vi.fn(async (proof: any, id: string) => { const current = state.running; if (!current || id !== current.stepId || proof.executionId !== current.executionId) throw new Error('Fixture original Approved step required'); const step = Object.freeze({ execution: proof, stepId: id, kind: 'metadata' }); originalSteps.set(step, proof); return step; }),
    assertMetadata: vi.fn(async (step: any, input: any, transaction: any) => { const plan: any = state.plans.get(step.execution.workflowId), sealed = plan.steps[0];
      if (originalSteps.get(step) !== step.execution || transaction !== tx || input.handler !== 'iam.metadata' || input.actor.id !== userId || input.clusterId !== plan.clusterId || input.workspaceId !== plan.workspaceId || input.entityType !== plan.subject.type || input.entityId !== plan.subject.id || input.revision !== sealed.metadataRevision || secrets.fingerprint(input.before) !== sealed.metadataBeforeHmac || secrets.fingerprint(input.payload) !== sealed.metadataPayloadHmac) throw new Error('Fixture exact original metadata step required');
      metadataChecks.push({ step, input, transaction }); }),
    mutationBinding: vi.fn(() => { throw new Error('IAM metadata cannot mint Native binding'); }), bindOperation: vi.fn(), assertNative: vi.fn(() => { throw new Error('IAM metadata cannot send Native'); }),
  };
  context.installApprovedPolicy(approved);
  const http = <T>(fn: () => Promise<T>, actor: any = author, sessionId: string | undefined = actor.user.id === userId ? sid : reviewerSid) => context.runHttp({ requestId: actor.requestId, ip: actor.ip }, async () => {
    context.bindHttpActor(actor.user, sessionId); const close = context.captureHttpCloser(); try { return await fn(); } finally { close(); }
  });
  const request = () => ({ resource: 'roles', operation: 'update', resourceId: rid, input: { revision: 4, name: 'Approved IAM role' } });
  const prepare = () => http(() => workflow.prepare(request(), author));
  const submit = (receipt: any) => http(() => workflow.submit(receipt.intentId, { confirmed: true, materialHmac: receipt.materialHmac }, author));
  const intent = (id?: string): any => { const row: any = id ? state.intents.get(id) : [...state.intents.values()][0]; return secrets.decrypt(row.material_secret, `iam-workflow:${row.id}:intent`); };
  const execute = (plan: any, mutateRunning?: (fact: any) => void, insideCallback?: (input: any, originalResult: Record<string, unknown>, beforePermissionVersion: string) => Promise<void>) => http(() => db.transaction(async (transaction: any) => {
    const beforePermissionVersion = `${userId}:${state.users.get(userId).permissions_epoch}:${state.epoch}`;
    const sealed = state.plans.get(plan.workflowId), executionId = randomUUID(), handle = Object.freeze({}), proof = Object.freeze({ executionId, workflowId: sealed.workflowId, actorId: userId, sessionId: sid, clusterId: sealed.clusterId, workspaceId: sealed.workspaceId,
      permissionVersion: `${userId}:7:${state.epoch}`, expiresAt: Date.now() + 60000 }); originalExecutions.set(handle, proof);
    state.running = { executionId, executionKey: `workflow-${executionId}`, workflowId: sealed.workflowId, clusterId: sealed.clusterId, workspaceId: sealed.workspaceId, actorId: userId, stepId: sealed.steps[0].id, planHash: secrets.fingerprint(sealed), planRevision: sealed.planRevision,
      executionState: 'executing', workflowState: 'executing', stepState: 'running', handler: 'iam.metadata', kind: 'metadata', nativeCount: 0, approvalFormat: 2 }; if (mutateRunning) mutateRunning(state.running);
    return context.runApprovedWorkflow(handle as any, () => context.runApprovedStep(plan.steps[0].id, async () => {
      const input = { plan, step: plan.steps[0], actor: author, executionId, transaction }, result = await registry.get('iam.metadata').apply(input);
      if (insideCallback) await insideCallback(input, result, beforePermissionVersion);
      return result;
    }));
  }));
  return { cid, wid, cid2, wid2, rid, userId, reviewerId, sid, otherSid, author, reviewer, context, db, tx, secrets, iam, mutations, workflow, plans, registry, approved, audit, authz, writes, metadataChecks,
    state: () => state, request, http, prepare, submit, intent, execute };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '6b'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M11 actual IAM workflow prepare/submit/current authority', () => {
  it('prepares an encrypted immutable intention with the actual HTTP SID, current SQL grant facts and no business mutation', async () => {
    const f = fixture(), before = structuredClone(f.state().roles), receipt = await f.prepare(), intent = f.intent();
    expect(receipt).toMatchObject({ state: 'prepared', nativeRequestsSent: 0, workflowId: null, clusterId: f.cid, workspaceId: f.wid });
    expect(intent).toMatchObject({ actorId: f.userId, authoringSessionId: f.sid, credentialEpoch: '3', permissionVersion: `${f.userId}:7:10` });
    expect(intent.capture.before.resource).toEqual(before.get(f.rid));
    expect(f.state().roles).toEqual(before); expect(f.state().operations.size).toBe(0);
    expect(f.writes).toHaveLength(1); expect(f.writes[0]).toContain('INSERT INTO iam_change_intents');
    expect(JSON.stringify([...f.state().intents.values()])).not.toContain('Approved IAM role');
    expect(receipt).not.toHaveProperty('capture'); expect(receipt).not.toHaveProperty('material_secret');
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'iam.change.prepare', after: expect.objectContaining({ nativeRequestsSent: 0 }) }), f.tx);
    expect(f.approved.assertNative).not.toHaveBeenCalled();
  });

  it('does not adopt a SID supplied in an actor DTO', async () => {
    const f = fixture(); await f.http(() => f.workflow.prepare(f.request(), { ...f.author, sessionId: randomUUID() } as any));
    expect(f.intent().authoringSessionId).toBe(f.sid);
  });

  it.each(['no-context', 'no-sid', 'wrong-actor', 'fake-sid', 'revoked-sid'])('refuses %s authoring context before persisting an intention', async variant => {
    const f = fixture(); let operation: Promise<any>;
    if (variant === 'revoked-sid') f.state().sessions.get(f.sid).revoked_at = new Date().toISOString();
    if (variant === 'no-context') operation = f.workflow.prepare(f.request(), f.author);
    else if (variant === 'no-sid') operation = f.context.runHttp({}, async () => { f.context.bindHttpActor(f.author.user); return f.workflow.prepare(f.request(), f.author); });
    else if (variant === 'wrong-actor') operation = f.http(() => f.workflow.prepare(f.request(), f.author), f.reviewer);
    else operation = f.http(() => f.workflow.prepare(f.request(), f.author), f.author, variant === 'fake-sid' ? randomUUID() : f.sid);
    await expect(operation).rejects.toThrow(); expect(f.state().intents.size).toBe(0); expect(f.state().operations.size).toBe(0);
  });

  it('ignores caller super-admin claims when actual SQL grants no IAM/workflow write', async () => {
    const f = fixture(); f.state().grants.set(f.userId, []); f.author.user.superAdmin = true;
    await expect(f.prepare()).rejects.toBeInstanceOf(ForbiddenException); expect(f.state().intents.size).toBe(0);
  });

  it.each(['tag_group', 'entity'])('does not treat a coarse %s workflow grant as authority for the whole IAM scope', async scopeType => {
    const f = fixture();
    f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'workflows' && g.action === 'write')));
    f.state().grants.get(f.userId).push({ module: 'workflows', action: 'write', scope_type: scopeType, cluster_id: f.cid, workspace_id: f.wid,
      scope_values: scopeType === 'tag_group' ? ['team-payments'] : [{ entity_type: 'services', entity_id: randomUUID() }] });
    await expect(f.prepare()).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_SCOPE_DENIED' } }); expect(f.state().intents.size).toBe(0);
  });

  it('checks actual SQL grant containment before preparing a permission the author cannot delegate', async () => {
    const f = fixture(), permissions = [{ module: 'services', action: 'write', scope_type: 'workspace', scope_values: [f.wid], cluster_id: f.cid, workspace_id: f.wid }];
    await expect(f.http(() => f.workflow.prepare({ resource: 'roles', operation: 'permissions', resourceId: f.rid, input: { revision: 4, permissions } }, f.author))).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_DELEGATION_DENIED' } });
    expect(f.state().intents.size).toBe(0); expect(f.state().operations.size).toBe(0); expect(f.writes).toEqual([]);
  });

  it('returns the same actor-private prepared receipt for the same key/body and rejects a changed body', async () => {
    const f = fixture(), one = await f.prepare(), two = await f.prepare(); expect(two).toEqual(one); expect(f.state().intents.size).toBe(1);
    await expect(f.http(() => f.workflow.prepare({ ...f.request(), input: { revision: 4, name: 'Different request' } }, f.author))).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    expect(f.state().intents.size).toBe(1); expect(f.state().operations.size).toBe(0);
  });

  it('rejects another owner and another authoring session when submitting the same encrypted intent', async () => {
    const f = fixture(), receipt = await f.prepare(), body = { confirmed: true, materialHmac: receipt.materialHmac };
    await expect(f.http(() => f.workflow.submit(receipt.intentId as string, body, f.reviewer), f.reviewer)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_AUTHOR_MISMATCH' } });
    await expect(f.http(() => f.workflow.submit(receipt.intentId as string, body, f.author), f.author, f.otherSid)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_AUTHOR_MISMATCH' } });
    expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.state().metadata.size).toBe(0);
  });

  it('rejects an authoring session revoked after prepare before submitting any metadata request', async () => {
    const f = fixture(), receipt = await f.prepare(); f.state().sessions.get(f.sid).revoked_at = new Date().toISOString();
    await expect(f.submit(receipt)).rejects.toThrow(); expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.state().metadata.size).toBe(0);
  });

  it('keeps intent receipts actor-private while allowing the owner to use another valid live session', async () => {
    const f = fixture(), receipt = await f.prepare();
    await expect(f.http(() => f.workflow.receipt(receipt.intentId as string, f.reviewer), f.reviewer)).rejects.toMatchObject({ response: { code: 'IAM_CHANGE_INTENT_OWNER_REQUIRED' } });
    await expect(f.http(() => f.workflow.receipt(receipt.intentId as string, f.author), f.author, f.otherSid)).resolves.toMatchObject({ intentId: receipt.intentId });
  });

  it.each(['role-grant', 'workflow-grant', 'credential-epoch', 'disabled-user', 'before-row'])('fences a prepared intent when current %s changes', async variant => {
    const f = fixture(), receipt = await f.prepare();
    if (variant === 'role-grant') f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'roles' && g.action === 'write')));
    if (variant === 'workflow-grant') f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'workflows' && g.action === 'write')));
    if (variant === 'credential-epoch') f.state().users.get(f.userId).credential_epoch++;
    if (variant === 'disabled-user') f.state().users.get(f.userId).status = 'disabled';
    if (variant === 'before-row') f.state().roles.get(f.rid).description = 'Changed outside the workflow';
    await expect(f.submit(receipt)).rejects.toThrow(); expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.state().metadata.size).toBe(0);
  });

  it('captures and checks both actual clusters affected by a platform-owned role', async () => {
    const f = fixture(true), receipt = await f.prepare(), intent = f.intent();
    expect(intent.scope.clusterScopes.map((s: any) => s.clusterId)).toEqual([f.cid, f.cid2]);
    f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'workflows' && g.action === 'write' && g.cluster_id === f.cid2)));
    await expect(f.submit(receipt)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_SCOPE_DENIED' } }); expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it('includes every registered cluster when an existing platform-owned role has a wildcard permission', async () => {
    const f = fixture(true);
    f.state().grants.get(f.userId).push({ module: 'workflows', action: 'write', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    f.state().permissions = [{ id: randomUUID(), role_id: f.rid, module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null, status: 'active' }];
    f.state().bindings = [{ id: randomUUID(), role_id: f.rid, user_id: f.userId, cluster_id: f.cid, workspace_id: f.wid, status: 'active' }];
    await f.prepare();
    expect([...new Set(f.intent().scope.clusterScopes.map((scope: any) => scope.clusterId))]).toEqual([f.cid, f.cid2]);
  });

  it('does not let a global owner conceal an approval cluster behind role bindings on the direct path', async () => {
    const f = fixture(true); f.state().permissions = [];
    f.state().bindings = [{ id: randomUUID(), role_id: f.rid, user_id: f.userId, cluster_id: f.cid2, workspace_id: f.wid2, status: 'active' }];
    await expect(f.http(() => f.iam.update('roles', f.rid, { revision: 4, name: 'Direct hidden-scope change' }, f.author))).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.state().operations.size).toBe(0); expect(f.writes).toEqual([]); expect(f.state().roles.get(f.rid).revision).toBe(4);
  });

  it('the direct path treats an existing wildcard role permission as affecting every approval cluster', async () => {
    const f = fixture(true);
    f.state().permissions = [{ id: randomUUID(), role_id: f.rid, module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null, status: 'active' }];
    await expect(f.http(() => f.iam.update('roles', f.rid, { revision: 4, name: 'Direct wildcard change' }, f.author))).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.state().operations.size).toBe(0); expect(f.writes).toEqual([]);
  });

  it('keeps global user directory changes on their console path without inventing a Kong cluster authority', async () => {
    const f = fixture();
    await expect(f.http(() => f.workflow.prepare({ resource: 'users', operation: 'create', input: { username: 'operator', password: 'Synthetic-password' } }, f.author))).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_GLOBAL_DIRECTORY_DIRECT' } });
    expect(f.state().intents.size).toBe(0); expect(f.state().operations.size).toBe(0); expect(f.writes).toEqual([]);
  });

  it.each(['registry-url', 'cluster-revision', 'workspace-revision', 'execution-mode', 'kong-version'])('refuses %s drift in the second affected cluster', async variant => {
    const f = fixture(true), receipt = await f.prepare();
    if (variant === 'registry-url') f.state().clusters.get(f.cid2).admin_url = 'http://other-kong:8001';
    if (variant === 'cluster-revision') f.state().clusters.get(f.cid2).revision++;
    if (variant === 'workspace-revision') f.state().workspaces.get(f.wid2).revision++;
    if (variant === 'execution-mode') f.state().clusters.get(f.cid2).execution_mode = 'direct';
    if (variant === 'kong-version') f.state().clusters.get(f.cid2).version = '2.8.0';
    await expect(f.submit(receipt)).rejects.toThrow(); expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it.each(['actor_id', 'authoring_session_id', 'credential_epoch', 'permission_version', 'material_hmac', 'material_secret', 'issued_at', 'expires_at'])('refuses tampered SQL intent %s facts instead of trusting its shape', async field => {
    const f = fixture(), receipt = await f.prepare(), row = f.state().intents.get(receipt.intentId);
    row[field] = field === 'credential_epoch' ? 999 : field === 'material_hmac' ? 'f'.repeat(64) : field === 'material_secret' ? `${row.material_secret}corrupt` : randomUUID();
    await expect(f.submit(receipt)).rejects.toThrow(); expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it('submits exactly one V2-policy metadata plan and returns its durable receipt on retry', async () => {
    const f = fixture(), prepared = await f.prepare(), receipt = await f.submit(prepared), plan = [...f.state().plans.values()][0], retry = await f.submit(prepared);
    expect(receipt).toMatchObject({ state: 'pending', workflowId: plan.workflowId, nativeRequestsSent: 0 }); expect(retry).toEqual(receipt);
    expect(f.plans.persist).toHaveBeenCalledOnce(); expect(f.state().metadata.size).toBe(1); expect(f.state().operations.size).toBe(0);
    expect(plan).toMatchObject({ kind: 'iam-metadata', executionMode: 'approval', approvalRequired: true, prerequisites: [] });
    expect(plan.steps).toHaveLength(1); expect(plan.steps[0]).toMatchObject({ kind: 'metadata', handler: 'iam.metadata', nativeRequests: [] });
    expect(plan.steps[0].metadata.materialHmac).toBe(prepared.materialHmac); expect(plan.requester.id).toBe(f.userId);
    expect(f.plans.persist.mock.calls[0][4]).toEqual({ requestId: f.author.requestId, ip: f.author.ip });
  });

  it('keeps the encrypted intention and persisted scope independent of later caller mutations', async () => {
    const f = fixture(), request = f.request();
    const prepared = await f.http(() => f.workflow.prepare(request, f.author)); request.input.name = 'Caller replacement';
    await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    expect(f.intent().capture.request.input.name).toBe('Approved IAM role');
    expect(Object.isFrozen(plan)).toBe(true); expect(Object.isFrozen(plan.scope)).toBe(true); expect(Object.isFrozen(plan.steps[0].metadata)).toBe(true);
    try { plan.scope.clusterRevision = 999; } catch { /* fixed immutable plan */ }
    expect(plan.scope.clusterRevision).toBe(2);
    expect(prepared).not.toHaveProperty('scope'); expect(prepared).not.toHaveProperty('capture');
  });

  it('the actual shared workflow validator rejects IAM handler and subject smuggled into another workflow kind', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared);
    const plan = structuredClone([...f.state().plans.values()][0]); plan.kind = 'portal-metadata'; plan.subject.type = 'portal_content';
    expect(() => validateWorkflowPlan(plan)).toThrow();
    expect(() => f.registry.register('iam.metadata', f.registry.get('iam.metadata'))).toThrow();
    expect(() => f.registry.register('iam.injected', f.registry.get('iam.metadata'))).toThrow();
  });

  it.each(['legacy-policy', 'wrong-kind', 'self-approval', 'shorter-ttl'])('rejects %s approval policy before persistence', async variant => {
    const f = fixture(); if (variant === 'shorter-ttl') f.state().sessions.get(f.sid).expires_at = new Date(Date.now() + 10800000).toISOString();
    const prepared = await f.prepare();
    if (variant === 'legacy-policy') f.state().policyFormat = 1;
    if (variant === 'wrong-kind') f.state().policy.kind = 'event-metadata';
    if (variant === 'self-approval') f.state().policy.allowSelfApproval = true;
    if (variant === 'shorter-ttl') f.state().policy.intentTtlHours = 1;
    await expect(f.submit(prepared)).rejects.toThrow(); expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.state().metadata.size).toBe(0);
  });
});

describe('M11 actual IAM workflow original-handle metadata execution', () => {
  it('inspects the actual SQL before graph without executing a mutation', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], before = structuredClone(f.state().roles), writeCount = f.writes.length;
    const result = await f.http(() => f.registry.get('iam.metadata').inspect({ plan, step: plan.steps[0], actor: f.author, executionId: randomUUID() }, f.tx));
    expect(result).toEqual({ before: f.intent().capture.before, revision: 4 }); expect(f.state().roles).toEqual(before); expect(f.writes).toHaveLength(writeCount);
  });

  it('runs the original IAM SQL callback under genuine Context proof and verifies actual SQL readback before acknowledging the result', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    const result = await f.execute(plan);
    expect(result).toMatchObject({ entity: { id: f.rid, name: 'Approved IAM role', revision: 5 }, resource: 'roles', operation: 'update', nativeRequestsSent: 0 });
    expect(f.state().roles.get(f.rid).name).toBe('Approved IAM role'); expect(f.state().operations.size).toBe(1); expect(f.state().facts).toHaveLength(1);
    expect(f.metadataChecks).toHaveLength(2); expect(f.metadataChecks.every(check => check.transaction === f.tx)).toBe(true);
    const ledger: any = [...f.state().operations.values()][0]; expect(ledger).toMatchObject({ state: 'succeeded', remote_completed: true });
    expect(f.state().facts[0]).toEqual(expect.arrayContaining([f.sid, f.cid, f.wid, f.userId]));
    expect(f.tx.one).toHaveBeenCalledWith(expect.stringContaining('FROM roles WHERE id=$1'), [f.rid]);
    expect(f.approved.assertNative).not.toHaveBeenCalled(); expect(f.approved.mutationBinding).not.toHaveBeenCalled();
  });

  it.each(['execution-state', 'workflow-state', 'step-state', 'wrong-handler', 'native-packet', 'legacy-approval'])('rejects current %s facts before business SQL', async variant => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], before = structuredClone(f.state().roles);
    await expect(f.execute(plan, running => {
      if (variant === 'execution-state') running.executionState = 'succeeded'; if (variant === 'workflow-state') running.workflowState = 'pending'; if (variant === 'step-state') running.stepState = 'pending';
      if (variant === 'wrong-handler') running.handler = 'entity.change'; if (variant === 'native-packet') running.nativeCount = 1; if (variant === 'legacy-approval') running.approvalFormat = 1;
    })).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_APPROVED_EXECUTION_REQUIRED' } });
    expect(f.state().roles).toEqual(before); expect(f.state().operations.size).toBe(0);
  });

  it('refuses ordinary HTTP calling the registered apply handler without its original Approved step', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    await expect(f.http(() => f.registry.get('iam.metadata').apply({ plan, step: plan.steps[0], actor: f.author, executionId: randomUUID(), transaction: f.tx }))).rejects.toThrow();
    expect(f.state().operations.size).toBe(0);
  });

  it('keeps the genuine IAM execution handle private and refuses a copied handle even inside the correct original Approved callback', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], apply = f.iam.applyApprovedChange.bind(f.iam);
    vi.spyOn(f.iam, 'applyApprovedChange').mockImplementation(async (handle, capture, actor, tx) => {
      await expect(apply(structuredClone(handle), capture, actor, tx)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ORIGINAL_EXECUTION_REQUIRED' } });
      return apply(handle, capture, actor, tx);
    });
    await expect(f.execute(plan)).resolves.toHaveProperty('entity.name', 'Approved IAM role');
  });

  it('expires the actual original IAM execution handle when the registered apply callback closes', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], apply = f.iam.applyApprovedChange.bind(f.iam); let original!: object, capture!: any;
    vi.spyOn(f.iam, 'applyApprovedChange').mockImplementation(async (handle, value, actor, tx) => { original = handle; capture = value; return apply(handle, value, actor, tx); });
    await f.execute(plan); const writeCount = f.writes.length;
    await expect(f.http(() => apply(original, capture, f.author, f.tx))).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ORIGINAL_EXECUTION_REQUIRED' } });
    expect(f.writes).toHaveLength(writeCount);
  });

  it('rolls back actual SQL effects if the final SQL row differs from the callback result', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], before = structuredClone(f.state().roles);
    f.audit.append.mockImplementation(async (event: any) => { if (event.action === 'iam.update') f.state().roles.get(f.rid).description = 'Unexpected committed row difference'; });
    await expect(f.execute(plan)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_RESULT_READBACK_MISMATCH' } });
    expect(f.state().roles).toEqual(before); expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });

  it.each(['definition', 'issuedAt', 'planRevision', 'before', 'metadata'])('refuses a substituted %s plan under the genuine original execution SQL facts', async field => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = structuredClone([...f.state().plans.values()][0]), before = structuredClone(f.state().roles);
    if (field === 'definition') plan.definition.id = randomUUID();
    if (field === 'issuedAt') plan.issuedAt = new Date(Date.now() - 60000).toISOString();
    if (field === 'planRevision') plan.planRevision++;
    if (field === 'before') { plan.steps[0].before.resource.name = 'Injected old name'; plan.steps[0].metadataBeforeHmac = f.secrets.fingerprint(plan.steps[0].before); }
    if (field === 'metadata') { plan.steps[0].metadata.operation = 'archive'; plan.steps[0].metadataPayloadHmac = f.secrets.fingerprint(plan.steps[0].metadata); }
    await expect(f.execute(plan)).rejects.toThrow(); expect(f.state().roles).toEqual(before); expect(f.state().operations.size).toBe(0);
  });

  it.each(['write-grant', 'session'])('rechecks current %s after the initial genuine metadata assertion before business SQL', async variant => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], before = structuredClone(f.state().roles), assertion = f.approved.assertMetadata.getMockImplementation()!;
    f.approved.assertMetadata.mockImplementationOnce(async (...args: any[]) => { await assertion(...args);
      if (variant === 'write-grant') f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'roles' && g.action === 'write')));
      else f.state().sessions.get(f.sid).revoked_at = new Date().toISOString();
    });
    await expect(f.execute(plan)).rejects.toThrow(); expect(f.state().roles).toEqual(before); expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });

  it('checks reviewer access across both captured cluster scopes rather than using the author permissions', async () => {
    const f = fixture(true), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], delegate = f.workflow.approvedDelegate();
    await expect(delegate.verifyReviewer(f.reviewerId, plan, f.tx)).resolves.toBeUndefined();
    f.state().grants.set(f.reviewerId, f.state().grants.get(f.reviewerId).filter((g: any) => !(g.module === 'workflows' && g.action === 'approve' && g.cluster_id === f.cid2)));
    await expect(delegate.verifyReviewer(f.reviewerId, plan, f.tx)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_SCOPE_DENIED' } });
    expect(f.state().operations.size).toBe(0);
  });

  it('requires the reviewer to contain every actual delegated permission independently of the author', async () => {
    const f = fixture(), permission = { module: 'services', action: 'read', scope_type: 'workspace', scope_values: [f.wid], cluster_id: f.cid, workspace_id: f.wid };
    f.state().grants.get(f.userId).push(permission);
    const prepared = await f.http(() => f.workflow.prepare({ resource: 'roles', operation: 'permissions', resourceId: f.rid, input: { revision: 4, permissions: [permission] } }, f.author));
    await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    await expect(f.workflow.approvedDelegate().verifyReviewer(f.reviewerId, plan, f.tx)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_DELEGATION_DENIED' } });
    expect(f.state().operations.size).toBe(0);
  });

  it('requires actual reviewer super-admin authority for a super-admin role binding even when delegatedGrants is empty', async () => {
    const f = fixture(true), normalRoleId = randomUUID();
    f.state().users.get(f.userId).super_admin = true;
    Object.assign(f.state().roles.get(f.rid), { cluster_id: null, workspace_id: null, builtin_kind: 'super-admin', protected: true });
    f.state().roles.set(normalRoleId, { id: normalRoleId, name: 'Scoped Reader', status: 'active', cluster_id: f.cid2, workspace_id: f.wid2, revision: 1 });
    f.state().permissions = [];
    f.state().bindings = [{ id: randomUUID(), role_id: normalRoleId, user_id: f.userId, cluster_id: f.cid2, workspace_id: f.wid2, status: 'active', revision: 1 }];
    f.state().grants.get(f.reviewerId).push({ module: 'users', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null },
      { module: 'workflows', action: 'approve', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    f.author.workspaceId = f.wid2;
    const prepared = await f.http(() => f.workflow.prepare({ resource: 'users', operation: 'binding.grant', resourceId: f.userId, input: { role_id: f.rid } }, f.author));
    expect(f.intent().capture.delegatedGrants).toEqual([]);
    expect(new Set(f.intent().scope.clusterScopes.map((scope: any) => scope.clusterId))).toEqual(new Set([f.cid, f.cid2]));
    await f.submit(prepared); const plan = [...f.state().plans.values()][0], delegate = f.workflow.approvedDelegate();
    await expect(delegate.verifyReviewer(f.reviewerId, plan, f.tx)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_SUPER_ADMIN_REQUIRED' } });
    f.state().users.get(f.reviewerId).super_admin = true;
    await expect(delegate.verifyReviewer(f.reviewerId, plan, f.tx)).resolves.toBeUndefined();
    expect(f.state().operations.size).toBe(0);
  });
});

describe('M11 IAM final UI receipt, restricted preview and lifetime API', () => {
  it('looks up only the original prepare key for its current owner and never adopts the internal workflow key', async () => {
    const f = fixture(), prepared = await f.prepare();
    await expect(f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.author))).resolves.toEqual(prepared);
    await expect(f.http(() => f.workflow.receiptByKey(f.intent().workflowKey, f.author))).rejects.toMatchObject({ response: { code: 'IAM_CHANGE_INTENT_NOT_FOUND' } });
    await expect(f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.reviewer), f.reviewer)).rejects.toMatchObject({ response: { code: 'IAM_CHANGE_INTENT_NOT_FOUND' } });
  });

  it('isolates two actors using the same original prepare key', async () => {
    const f = fixture(), one = await f.prepare(); f.reviewer.idempotencyKey = f.author.idempotencyKey;
    const two = await f.http(() => f.workflow.prepare(f.request(), f.reviewer), f.reviewer);
    expect(two.intentId).not.toBe(one.intentId);
    await expect(f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.author))).resolves.toHaveProperty('intentId', one.intentId);
    await expect(f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.reviewer), f.reviewer)).resolves.toHaveProperty('intentId', two.intentId);
  });

  it.each(['missing', 'malformed', 'fake-sid', 'revoked-sid'])('rejects %s by-key lookup without exposing another intent', async variant => {
    const f = fixture(); await f.prepare(); const writes = f.writes.length;
    if (variant === 'revoked-sid') f.state().sessions.get(f.sid).revoked_at = new Date().toISOString();
    await expect(f.http(() => f.workflow.receiptByKey(variant === 'missing' ? 'unknown-original-key' : variant === 'malformed' ? '../injected-key' : f.author.idempotencyKey, f.author), f.author, variant === 'fake-sid' ? randomUUID() : f.sid)).rejects.toThrow();
    expect(f.writes).toHaveLength(writes);
  });

  it('returns the fixed preview schema with current-readable metadata and its confirmation name', async () => {
    const f = fixture(), prepared: any = await f.prepare(), preview = prepared.preview;
    expect(Object.keys(preview).sort()).toEqual(['request', 'before', 'after', 'affectedScopes', 'confirmationName'].sort());
    expect(preview).toMatchObject({ request: f.request(), before: f.intent().capture.before, confirmationName: 'Payments Operators',
      after: { resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved IAM role' } } });
    expect(preview.affectedScopes).toEqual(f.intent().scope.clusterScopes);
    for (const value of [f.sid, f.state().intents.get(prepared.intentId).material_secret, f.intent().permissionVersion, f.intent().requestHmac]) expect(JSON.stringify(preview)).not.toContain(value);
    expect(preview).not.toHaveProperty('sessionId'); expect(preview).not.toHaveProperty('authoringSessionId'); expect(preview).not.toHaveProperty('materialHmac');
  });

  it('masks old permission rows and related role details using current permission READ while leaving the encrypted before graph intact', async () => {
    const f = fixture(); f.state().permissions = [{ id: randomUUID(), role_id: f.rid, module: 'services', action: 'read', scope_type: 'workspace', scope_values: [f.wid], cluster_id: f.cid, workspace_id: f.wid, status: 'active' }];
    f.state().bindings = [{ id: randomUUID(), role_id: f.rid, user_id: f.userId, cluster_id: f.cid, workspace_id: f.wid, status: 'active' }];
    f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'permissions' && g.action === 'read')));
    const prepared: any = await f.prepare(), preview = prepared.preview;
    expect(preview.before.permissions).toEqual({ count: 1, restricted: true });
    expect(preview.before.related).toEqual([{ type: 'roles', row: f.intent().capture.before.related[0].row, permissions: { count: 1, restricted: true } }]);
    expect(f.intent().capture.before.permissions).toHaveLength(1);
    f.state().grants.get(f.userId).push({ module: 'permissions', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    const allowed: any = await f.http(() => f.workflow.receipt(prepared.intentId, f.author));
    expect(allowed.preview.before.permissions).toHaveLength(1); expect(allowed.preview.before.related[0].row.name).toBe('Payments Operators');
    f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'roles' && g.action === 'read')));
    const roleRestricted: any = await f.http(() => f.workflow.receipt(prepared.intentId, f.author));
    expect(roleRestricted.preview.before.related[0].row).toEqual({ id: f.rid }); expect(roleRestricted.preview.before.related[0].permissions).toHaveLength(1);
  });

  it('reduces a binding owner to its ID when the current actor has no global users READ', async () => {
    const f = fixture(); f.state().users.get(f.reviewerId).email = 'private-owner@example.test';
    const prepared: any = await f.http(() => f.workflow.prepare({ resource: 'users', operation: 'binding.grant', resourceId: f.reviewerId, input: { role_id: f.rid, cluster_id: f.cid, workspace_id: f.wid } }, f.author));
    expect(prepared.preview.before.resource).toEqual({ id: f.reviewerId }); expect(JSON.stringify(prepared.preview)).not.toContain('private-owner@example.test');
    f.state().grants.get(f.userId).push({ module: 'users', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    const allowed: any = await f.http(() => f.workflow.receipt(prepared.intentId, f.author));
    expect(allowed.preview.before.resource).toHaveProperty('email', 'private-owner@example.test');
  });

  it('reduces a related team member to its ID without borrowing workspace directory access as global users READ', async () => {
    const f = fixture(), teamId = randomUUID(); f.state().teams.set(teamId, { id: teamId, name: 'Payments Team', code: 'payments_team', revision: 1, status: 'active', cluster_id: f.cid, workspace_id: f.wid });
    f.state().grants.get(f.userId).push({ module: 'teams', action: 'write', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null },
      { module: 'teams', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null },
      { module: 'users', action: 'read', scope_type: 'workspace', scope_values: [f.wid], cluster_id: f.cid, workspace_id: f.wid });
    f.state().users.get(f.reviewerId).email = 'private-member@example.test';
    const prepared: any = await f.http(() => f.workflow.prepare({ resource: 'teams', operation: 'member.add', resourceId: teamId, input: { user_id: f.reviewerId } }, f.author));
    expect(prepared.preview.before.related).toEqual([{ type: 'users', row: { id: f.reviewerId } }]);
    expect(prepared.preview.confirmationName).toBe('Payments Team'); expect(JSON.stringify(prepared.preview)).not.toContain('private-member@example.test');
  });

  it('reads the actual one-hour V2 policy while preparing and clamps a longer live session to that TTL', async () => {
    const f = fixture(); f.state().policy.intentTtlHours = 1; f.state().sessions.get(f.sid).expires_at = new Date(Date.now() + 43200000).toISOString();
    const prepared = await f.prepare(), intent = f.intent(), duration = Date.parse(intent.expiresAt) - Date.parse(intent.issuedAt);
    expect(duration).toBe(3600000); expect(prepared.expiresAt).toBe(intent.expiresAt);
    await expect(f.submit(prepared)).resolves.toHaveProperty('state', 'pending');
    expect(f.plans.definition).toHaveBeenCalledWith(f.cid, f.wid, 'iam-metadata', f.tx);
  });

  it.each(['legacy', 'self-approval', 'invalid-ttl'])('rejects %s policy during prepare before saving any intention', async variant => {
    const f = fixture(); if (variant === 'legacy') f.state().policyFormat = 1; if (variant === 'self-approval') f.state().policy.allowSelfApproval = true; if (variant === 'invalid-ttl') f.state().policy.intentTtlHours = 0;
    await expect(f.prepare()).rejects.toThrow(); expect(f.state().intents.size).toBe(0); expect(f.writes).toEqual([]);
  });

  it('fences the original IAM handle at intent expiry after business SQL and rolls the whole transaction back', async () => {
    const f = fixture(); f.state().sessions.get(f.sid).expires_at = new Date(Date.now() + 10000).toISOString();
    const prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], before = structuredClone(f.state().roles), expires = Date.parse(f.intent().expiresAt);
    let clock: ReturnType<typeof vi.spyOn> | undefined;
    f.audit.append.mockImplementation(async (event: any) => { if (event.action === 'iam.update') clock = vi.spyOn(Date, 'now').mockReturnValue(expires + 1); });
    try { await expect(f.execute(plan)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ORIGINAL_EXECUTION_REQUIRED' } }); } finally { clock?.mockRestore(); }
    expect(f.state().roles).toEqual(before); expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });

  it('locks all affected direct clusters twice, including inside the actual IAM business transaction', async () => {
    const f = fixture(true); for (const cluster of f.state().clusters.values()) cluster.execution_mode = 'direct';
    await f.http(() => f.iam.update('roles', f.rid, { revision: 4, name: 'Authorized direct change' }, f.author));
    const outer = f.db.query.mock.calls.filter((call: any[]) => call[0].includes('SELECT id,execution_mode FROM clusters')), inner = f.tx.query.mock.calls.filter((call: any[]) => call[0].includes('SELECT id,execution_mode FROM clusters'));
    expect(outer).toHaveLength(1); expect(inner).toHaveLength(1);
    for (const call of [...outer, ...inner]) { expect(call[0]).toContain('FOR SHARE'); expect(new Set(call[1][1])).toEqual(new Set([f.cid, f.cid2])); }
    expect(f.state().roles.get(f.rid).name).toBe('Authorized direct change');
  });

  it('rechecks the second affected cluster inside the direct IAM transaction and never executes business SQL after a mode race', async () => {
    const f = fixture(true); for (const cluster of f.state().clusters.values()) cluster.execution_mode = 'direct';
    const query = f.tx.query.getMockImplementation()!;
    f.tx.query.mockImplementation(async (sql: string, p: any[]) => { if (sql.includes('SELECT id,execution_mode FROM clusters')) f.state().clusters.get(f.cid2).execution_mode = 'approval'; return query(sql, p); });
    await expect(f.http(() => f.iam.update('roles', f.rid, { revision: 4, name: 'Direct raced change' }, f.author))).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.state().roles.get(f.rid).revision).toBe(4); expect(f.writes.some(sql => sql.startsWith('UPDATE roles'))).toBe(false);
  });

  it('returns only the owned terminal receipt after the exact approved permission operation revokes its own IAM grants', async () => {
    const f = fixture(); Object.assign(f.state().roles.get(f.rid), { cluster_id: null, workspace_id: null });
    const grants = ['roles', 'permissions', 'workflows'].flatMap(module => ['read', 'write'].map(action => ({ module, action, scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null })));
    f.state().grants.set(f.userId, grants); f.state().permissions = grants.map(grant => ({ ...grant, id: randomUUID(), role_id: f.rid, status: 'active' }));
    f.state().bindings = [{ id: randomUUID(), role_id: f.rid, user_id: f.userId, cluster_id: null, workspace_id: null, status: 'active' }];
    const prepared = await f.http(() => f.workflow.prepare({ resource: 'roles', operation: 'permissions', resourceId: f.rid, input: { revision: 4, permissions: [] } }, f.author)); await f.submit(prepared);
    const plan = [...f.state().plans.values()][0]; f.state().revokeOwnPermissions = true;
    await f.execute(plan); expect(f.state().grants.get(f.userId)).toEqual([]); expect(f.state().facts).toHaveLength(1);
    f.state().workflows.get(plan.workflowId).state = 'succeeded'; Object.assign(f.state().running, { executionState: 'succeeded', workflowState: 'succeeded', stepState: 'succeeded' });
    const terminal: any = await f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.author));
    expect(terminal).toMatchObject({ state: 'succeeded', workflowId: plan.workflowId, preview: null, nativeRequestsSent: 0 }); expect(terminal).not.toHaveProperty('capabilities'); expect(terminal).not.toHaveProperty('entity');
    const operationCount = f.state().operations.size;
    await expect(f.submit(prepared)).rejects.toBeInstanceOf(ForbiddenException); expect(f.state().operations.size).toBe(operationCount);
    f.state().facts = [];
    await expect(f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.author))).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('does not accept a succeeded-looking workflow without the original owned terminal mutation fact', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    f.state().workflows.get(plan.workflowId).state = 'succeeded'; f.state().grants.set(f.userId, []);
    await expect(f.http(() => f.workflow.receipt(prepared.intentId as string, f.author))).rejects.toBeInstanceOf(ForbiddenException);
    expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });

  it.each(['actor', 'session', 'plan-hash'])('does not borrow a terminal mutation fact with a different %s tuple', async variant => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0]; await f.execute(plan);
    f.state().workflows.get(plan.workflowId).state = 'succeeded'; Object.assign(f.state().running, { executionState: 'succeeded', workflowState: 'succeeded', stepState: 'succeeded' });
    f.state().grants.set(f.userId, []);
    f.state().facts[0][variant === 'actor' ? 7 : variant === 'session' ? 8 : 10] = variant === 'plan-hash' ? 'f'.repeat(64) : randomUUID();
    await expect(f.http(() => f.workflow.receiptByKey(f.author.idempotencyKey, f.author))).rejects.toBeInstanceOf(ForbiddenException);
    expect(f.state().operations.size).toBe(1);
  });
});

describe('M11 actual IAM permission readback normalization', () => {
  it.each([['clone', 'tag_group'], ['clone', 'entity'], ['permissions', 'tag_group'], ['permissions', 'entity']])('acknowledges the original %s / %s grant using real SQL readback and canonical fixed IDs', async (operation, scopeType) => {
    const f = fixture(), values = scopeType === 'tag_group' ? ['team:payments'] : [{ entity_type: 'services', entity_id: randomUUID() }],
      permission = { module: 'services', action: 'read', scope_type: scopeType, scope_values: values, cluster_id: f.cid, workspace_id: f.wid };
    f.state().grants.get(f.userId).push({ module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    if (operation === 'clone') f.state().permissions = [{ ...permission, id: randomUUID(), role_id: f.rid, status: 'active', revision: 1, scope_values: scopeType === 'tag_group' ? [encodeTag('team:payments')] : values }];
    const prepared = await f.http(() => f.workflow.prepare({ resource: 'roles', operation, resourceId: f.rid,
      input: operation === 'clone' ? { code: 'copied_role', name: 'Copied Role', cluster_id: f.cid, workspace_id: f.wid } : { revision: 4, permissions: [permission] } }, f.author));
    await f.submit(prepared); const plan = [...f.state().plans.values()][0], capture = f.intent().capture;
    const result: any = await f.execute(plan), appliedId = operation === 'clone' ? capture.allocatedIds[0] : f.rid;
    const actual: any = await f.iam.readAppliedChange(capture, f.tx);
    expect(result.entity).toEqual(actual);
    const rows = f.state().permissions.filter((row: any) => row.role_id === appliedId && row.status === 'active');
    expect(rows.map((row: any) => row.id)).toEqual(capture.allocatedIds.slice(operation === 'clone' ? 1 : 0));
    expect(rows[0].scope_values).toEqual(scopeType === 'tag_group' ? [encodeTag('team:payments')] : values);
    if (operation === 'permissions' && scopeType === 'tag_group') expect(actual.items[0].scope_values).toEqual(['team:payments']);
    expect(f.state().facts).toHaveLength(1); expect(f.approved.assertNative).not.toHaveBeenCalled();
  });

  it.each([['clone', 'id'], ['clone', 'tuple'], ['permissions', 'id'], ['permissions', 'tuple']])('rolls back actual %s SQL when the readback grant %s differs from the sealed allocation', async (operation, variant) => {
    const f = fixture(), permission = { module: 'services', action: 'read', scope_type: 'tag_group', scope_values: ['team:payments'], cluster_id: f.cid, workspace_id: f.wid };
    f.state().grants.get(f.userId).push({ module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    if (operation === 'clone') f.state().permissions = [{ ...permission, id: randomUUID(), role_id: f.rid, status: 'active', scope_values: [encodeTag('team:payments')] }];
    const prepared = await f.http(() => f.workflow.prepare({ resource: 'roles', operation, resourceId: f.rid,
      input: operation === 'clone' ? { code: 'copied_role', name: 'Copied Role', cluster_id: f.cid, workspace_id: f.wid } : { revision: 4, permissions: [permission] } }, f.author));
    await f.submit(prepared); const plan = [...f.state().plans.values()][0], beforeRoles = structuredClone(f.state().roles), beforePermissions = structuredClone(f.state().permissions), capture = f.intent().capture,
      appliedId = operation === 'clone' ? capture.allocatedIds[0] : f.rid;
    f.audit.append.mockImplementation(async (event: any) => { if (event.action === `iam.${operation}`) { const row = f.state().permissions.find((row: any) => row.role_id === appliedId && row.status === 'active'); if (variant === 'id') row.id = randomUUID(); else row.action = 'write'; } });
    await expect(f.execute(plan)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_PERMISSION_READBACK_MISMATCH' } });
    expect(f.state().roles).toEqual(beforeRoles); expect(f.state().permissions).toEqual(beforePermissions); expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });
});

describe('M11 original IAM metadata completion and safe terminal receipt', () => {
  it('hides unrelated foreign bindings and roles from both scoped author preview and real reviewer diff while preserving the complete encrypted graph', async () => {
    const f = fixture(true), foreignRoleId = randomUUID(), foreignBindingId = randomUUID(), foreignGrantorId = randomUUID();
    f.state().roles.set(foreignRoleId, { id: foreignRoleId, name: 'Private Foreign Role', status: 'active', cluster_id: f.cid2, workspace_id: f.wid2, revision: 1 });
    f.state().bindings = [{ id: foreignBindingId, role_id: foreignRoleId, user_id: f.reviewerId, granted_by: foreignGrantorId, cluster_id: f.cid2, workspace_id: f.wid2, status: 'active' }];
    for (const id of [f.userId, f.reviewerId]) {
      f.state().grants.set(id, f.state().grants.get(id).filter((g: any) => !(['roles', 'permissions'].includes(g.module) && g.action === 'read')));
      for (const module of ['roles', 'permissions']) f.state().grants.get(id).push({ module, action: 'read', scope_type: 'workspace', scope_values: [f.wid], cluster_id: f.cid, workspace_id: f.wid });
    }
    f.state().grants.get(f.userId).push({ module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    const prepared: any = await f.http(() => f.workflow.prepare({ resource: 'users', operation: 'binding.grant', resourceId: f.reviewerId, input: { role_id: f.rid, cluster_id: f.cid, workspace_id: f.wid } }, f.author));
    expect(prepared.preview.before.bindings).toEqual([]); expect(prepared.preview.before.restrictedBindings).toEqual({ count: 1, restricted: true });
    expect(prepared.preview.before.restrictedRelated).toEqual({ count: 1, restricted: true });
    await f.submit(prepared); const plan = [...f.state().plans.values()][0], review: any = await f.http(() => f.workflow.completionDelegate().reviewPreview(plan, f.reviewer), f.reviewer);
    expect(review.diff[0].before.bindings).toEqual([]); expect(review.diff[0].before.restrictedBindings).toEqual({ count: 1, restricted: true });
    for (const value of [f.cid2, f.wid2, foreignRoleId, foreignBindingId, foreignGrantorId, 'Private Foreign Role']) {
      expect(JSON.stringify(prepared.preview)).not.toContain(value); expect(JSON.stringify(review)).not.toContain(value);
    }
    expect(f.intent().capture.before.bindings[0]).toMatchObject({ id: foreignBindingId, role_id: foreignRoleId, granted_by: foreignGrantorId, cluster_id: f.cid2 });
    expect(f.intent().capture.before.related.some((row: any) => row.row.id === foreignRoleId)).toBe(true);
    expect(f.intent().scope.clusterScopes.map((scope: any) => scope.clusterId)).toEqual([f.cid]);
  });

  it('masks clone source dependencies when the reviewer can read only the target workspace', async () => {
    const f = fixture(true), foreignBindingId = randomUUID(), foreignUserId = randomUUID(); Object.assign(f.state().roles.get(f.rid), { cluster_id: null, workspace_id: null });
    f.state().permissions = [{ id: randomUUID(), role_id: f.rid, module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null, status: 'active' }];
    f.state().bindings = [{ id: foreignBindingId, role_id: f.rid, user_id: foreignUserId, cluster_id: f.cid2, workspace_id: f.wid2, status: 'active' }];
    f.state().grants.get(f.userId).push({ module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    f.state().grants.set(f.reviewerId, f.state().grants.get(f.reviewerId).filter((g: any) => !(['roles', 'permissions'].includes(g.module) && g.action === 'read')));
    for (const module of ['roles', 'permissions']) f.state().grants.get(f.reviewerId).push({ module, action: 'read', scope_type: 'workspace', scope_values: [f.wid], cluster_id: f.cid, workspace_id: f.wid });
    const prepared: any = await f.http(() => f.workflow.prepare({ resource: 'roles', operation: 'clone', resourceId: f.rid, input: { code: 'private_scoped_copy', name: 'Scoped Copy', cluster_id: f.cid, workspace_id: f.wid } }, f.author));
    await f.submit(prepared); const plan = [...f.state().plans.values()][0], review: any = await f.http(() => f.workflow.completionDelegate().reviewPreview(plan, f.reviewer), f.reviewer), graph = review.diff[0].before;
    expect(graph.resource).toEqual({ id: f.rid }); expect(graph.permissions).toEqual({ count: 1, restricted: true }); expect(graph.bindings).toEqual([]);
    expect(graph.restrictedBindings).toEqual({ count: 1, restricted: true }); expect(graph.related[0].row).toEqual({ id: f.rid });
    for (const value of [f.cid2, f.wid2, foreignBindingId, foreignUserId, 'Payments Operators']) expect(JSON.stringify(review)).not.toContain(value);
    expect(f.intent().capture.before.bindings[0].user_id).toBe(foreignUserId); expect(f.intent().capture.before.permissions[0].cluster_id).toBeNull();
  });

  it('keeps a scoped user binding impact narrow while preserving the full unrelated before bindings', async () => {
    const f = fixture(true), unrelatedRoleId = randomUUID();
    f.state().roles.set(unrelatedRoleId, { id: unrelatedRoleId, name: 'Other Cluster Role', status: 'active', cluster_id: f.cid2, workspace_id: f.wid2, revision: 1 });
    f.state().bindings = [{ id: randomUUID(), role_id: unrelatedRoleId, user_id: f.reviewerId, cluster_id: f.cid2, workspace_id: f.wid2, status: 'active', revision: 1 }];
    f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'workflows' && g.action === 'write' && g.cluster_id === f.cid2)));
    f.state().grants.get(f.userId).push({ module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    await f.http(() => f.workflow.prepare({ resource: 'users', operation: 'binding.grant', resourceId: f.reviewerId, input: { role_id: f.rid, cluster_id: f.cid, workspace_id: f.wid } }, f.author));
    expect(f.intent().capture.before.bindings).toHaveLength(1); expect(f.intent().capture.before.bindings[0].cluster_id).toBe(f.cid2);
    expect(f.intent().scope.clusterScopes.map((scope: any) => scope.clusterId)).toEqual([f.cid]);
    expect(f.intent().capture.delegatedGrants.every((grant: any) => grant.cluster_id === f.cid)).toBe(true);
  });

  it('treats a global role clone source as read-only and derives impact only from the resolved target grants', async () => {
    const f = fixture(true); Object.assign(f.state().roles.get(f.rid), { cluster_id: null, workspace_id: null });
    f.state().permissions = [{ id: randomUUID(), role_id: f.rid, module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null, status: 'active' }];
    f.state().grants.set(f.userId, f.state().grants.get(f.userId).filter((g: any) => !(g.module === 'workflows' && g.action === 'write' && g.cluster_id === f.cid2)));
    f.state().grants.get(f.userId).push({ module: 'services', action: 'read', scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null });
    await f.http(() => f.workflow.prepare({ resource: 'roles', operation: 'clone', resourceId: f.rid, input: { code: 'scoped_copy', name: 'Scoped Copy', cluster_id: f.cid, workspace_id: f.wid } }, f.author));
    expect(f.intent().capture.before.permissions[0].cluster_id).toBeNull(); expect(f.intent().scope.clusterScopes.map((scope: any) => scope.clusterId)).toEqual([f.cid]);
    expect(f.intent().capture.delegatedGrants[0]).toMatchObject({ cluster_id: f.cid, workspace_id: f.wid, scope_type: 'workspace', scope_values: [f.wid] });
  });

  it('returns the real reviewer diff and safe affected scopes without authoring SID or transport/material HMAC data', async () => {
    const f = fixture(true), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    const preview: any = await f.http(() => f.workflow.completionDelegate().reviewPreview(plan, f.reviewer), f.reviewer);
    expect(Object.keys(preview).sort()).toEqual(['affectedScopes', 'diff']);
    expect(preview.diff).toHaveLength(1); expect(preview.diff[0]).toMatchObject({ id: plan.steps[0].id, kind: 'metadata', operation: 'update', entityType: 'roles', entityId: f.rid,
      before: { resource: { id: f.rid, name: 'Payments Operators' } }, after: { input: { name: 'Approved IAM role' } } });
    expect(preview.affectedScopes.map((scope: any) => scope.clusterId)).toEqual([f.cid, f.cid2]);
    expect(preview.affectedScopes.every((scope: any) => !Object.hasOwn(scope, 'transportScope'))).toBe(true);
    for (const value of [f.sid, f.intent().scope.transportScope, f.secrets.fingerprint(f.intent()), f.intent().requestHmac]) expect(JSON.stringify(preview)).not.toContain(value);
  });

  it('refuses the entire reviewer diff when any required current READ scope is absent', async () => {
    const f = fixture(true), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    f.state().grants.set(f.reviewerId, f.state().grants.get(f.reviewerId).filter((g: any) => !(g.module === 'workflows' && g.action === 'read' && g.cluster_id === f.cid2)));
    await expect(f.http(() => f.workflow.completionDelegate().reviewPreview(plan, f.reviewer), f.reviewer)).rejects.toMatchObject({ status: 403, response: { code: 'IAM_WORKFLOW_SCOPE_DENIED' } });
    f.state().grants.get(f.reviewerId).push({ module: 'workflows', action: 'read', scope_type: 'workspace', scope_values: [f.wid2], cluster_id: f.cid2, workspace_id: f.wid2 });
    f.state().grants.set(f.reviewerId, f.state().grants.get(f.reviewerId).filter((g: any) => !(g.module === 'roles' && g.action === 'read')));
    await expect(f.http(() => f.workflow.completionDelegate().reviewPreview(plan, f.reviewer), f.reviewer)).rejects.toMatchObject({ status: 403, response: { code: 'IAM_WORKFLOW_SUBJECT_DENIED' } });
  });

  it('independently masks permission rows in the current reviewer diff without hiding current-readable role metadata', async () => {
    const f = fixture(true), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0];
    f.state().grants.set(f.reviewerId, f.state().grants.get(f.reviewerId).filter((g: any) => !(g.module === 'permissions' && g.action === 'read')));
    const preview: any = await f.http(() => f.workflow.completionDelegate().reviewPreview(plan, f.reviewer), f.reviewer);
    expect(preview.diff[0].before.resource.name).toBe('Payments Operators'); expect(preview.diff[0].before.permissions).toEqual({ count: 2, restricted: true });
    expect(f.intent().capture.before.permissions).toHaveLength(2);
  });

  it('consumes only the original result with the same original input, transaction and active Context step', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], completion = f.workflow.completionDelegate();
    await f.execute(plan, undefined, async (input, result, before) => {
      expect(f.context.currentApprovedStep().stepId).toBe(input.step.id); expect(input.transaction).toBe(f.tx);
      await expect(completion.verifyMetadataCompletion(input, result, before)).resolves.toBeUndefined();
      await expect(completion.verifyMetadataCompletion(input, result, before)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ORIGINAL_COMPLETION_REQUIRED' } });
    });
    expect(f.state().facts).toHaveLength(1); expect([...f.state().operations.values()][0].state).toBe('succeeded');
  });

  it.each(['copied-result', 'copied-input', 'wrong-before-version', 'result-body', 'changed-transaction'])('rolls back the original IAM transaction for %s completion substitution', async variant => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], beforeRoles = structuredClone(f.state().roles), completion = f.workflow.completionDelegate();
    await expect(f.execute(plan, undefined, async (input, result, before) => {
      let proposed = result;
      if (variant === 'result-body') { expect(Object.isFrozen(result.entity)).toBe(true); proposed = structuredClone(result); (proposed.entity as any).name = 'Forged completion entity'; }
      if (variant === 'changed-transaction') input.transaction = { ...f.tx };
      await completion.verifyMetadataCompletion(variant === 'copied-input' ? { ...input } : input, variant === 'copied-result' ? structuredClone(result) : proposed, variant === 'wrong-before-version' ? 'wrong-permission-version' : before);
    })).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ORIGINAL_COMPLETION_REQUIRED' } });
    expect(f.state().roles).toEqual(beforeRoles); expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });

  it.each(['epoch', 'fact-before', 'fact-after', 'fact-result', 'operation-complete', 'encrypted-result', 'raw-readback', 'lease'])('rolls back actual IAM SQL if completion %s proof changes', async variant => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], beforeRoles = structuredClone(f.state().roles), completion = f.workflow.completionDelegate();
    await expect(f.execute(plan, undefined, async (input, result, before) => {
      const fact = f.state().facts[0], operation = f.state().operations.get(fact[0]);
      if (variant === 'epoch') f.state().epoch++;
      if (variant === 'fact-before') fact[11] = 'different-original-permission-version';
      if (variant === 'fact-after') fact[12] = 'different-current-permission-version';
      if (variant === 'fact-result') fact[15] = 'f'.repeat(64);
      if (variant === 'operation-complete') operation.remote_completed = false;
      if (variant === 'encrypted-result') operation.result_secret = f.secrets.encrypt({ id: f.rid, name: 'Different actual SQL result' }, `iam:${fact[0]}:result`);
      if (variant === 'raw-readback') f.state().roles.get(f.rid).description = 'Changed actual readback';
      if (variant === 'lease') f.redis.assertLeaseOwnership.mockRejectedValueOnce(new Error('Original workflow lease lost'));
      await completion.verifyMetadataCompletion(input, result, before);
    })).rejects.toThrow();
    expect(f.state().roles).toEqual(beforeRoles); expect(f.state().operations.size).toBe(0); expect(f.state().facts).toHaveLength(0);
  });

  it('rejects the original result after its actual Context step has closed and consumes that escaped completion', async () => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0], completion = f.workflow.completionDelegate(); let input: any, result!: Record<string, unknown>, before!: string;
    await f.execute(plan, undefined, async (originalInput, originalResult, beforeVersion) => { input = originalInput; result = originalResult; before = beforeVersion; });
    await expect(f.http(() => completion.verifyMetadataCompletion(input, result, before))).rejects.toThrow();
    await expect(f.http(() => completion.verifyMetadataCompletion(input, result, before))).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ORIGINAL_COMPLETION_REQUIRED' } });
    expect(f.state().operations.size).toBe(1);
  });

  it('verifies safe completion after the exact permission replacement removes the actor grants and advances actual IAM version facts', async () => {
    const f = fixture(); Object.assign(f.state().roles.get(f.rid), { cluster_id: null, workspace_id: null });
    const grants = ['roles', 'permissions', 'workflows'].flatMap(module => ['read', 'write'].map(action => ({ module, action, scope_type: 'global', scope_values: [], cluster_id: null, workspace_id: null })));
    f.state().grants.set(f.userId, grants); f.state().permissions = grants.map(grant => ({ ...grant, id: randomUUID(), role_id: f.rid, status: 'active' }));
    f.state().bindings = [{ id: randomUUID(), role_id: f.rid, user_id: f.userId, cluster_id: null, workspace_id: null, status: 'active' }];
    const prepared = await f.http(() => f.workflow.prepare({ resource: 'roles', operation: 'permissions', resourceId: f.rid, input: { revision: 4, permissions: [] } }, f.author)); await f.submit(prepared);
    const plan = [...f.state().plans.values()][0]; f.state().revokeOwnPermissions = true;
    await f.execute(plan, undefined, async (input, result, before) => { expect(f.state().grants.get(f.userId)).toEqual([]); await f.workflow.completionDelegate().verifyMetadataCompletion(input, result, before); });
    expect(f.state().facts[0][11]).not.toBe(f.state().facts[0][12]); expect(f.state().facts[0][13]).not.toBe(f.state().facts[0][14]);
    f.state().workflows.get(plan.workflowId).state = 'succeeded'; Object.assign(f.state().running, { executionState: 'succeeded', stepState: 'succeeded' });
    const receipt = await f.http(() => f.workflow.completionDelegate().terminalReceipt(plan, f.author));
    expect(receipt).toMatchObject({ state: 'succeeded', executionId: f.state().running.executionId, idempotencyKey: f.state().running.executionKey,
      steps: [{ name: 'iam.metadata', state: 'succeeded', operationId: null, remoteStarted: false, remoteCompleted: true }], propagation: 'acknowledged' });
    expect(receipt).not.toHaveProperty('entity'); expect(receipt).not.toHaveProperty('preview'); expect(receipt).not.toHaveProperty('capabilities');
  });

  it.each(['other-owner', 'fake-sid', 'workflow-pending', 'execution-pending', 'step-pending', 'operation-incomplete', 'native-packet', 'fact-sid', 'plan-hash'])('keeps terminal receipt closed for %s', async variant => {
    const f = fixture(), prepared = await f.prepare(); await f.submit(prepared); const plan = [...f.state().plans.values()][0]; await f.execute(plan, undefined, (input, result, before) => f.workflow.completionDelegate().verifyMetadataCompletion(input, result, before));
    f.state().workflows.get(plan.workflowId).state = 'succeeded'; Object.assign(f.state().running, { executionState: 'succeeded', stepState: 'succeeded' });
    if (variant === 'workflow-pending') f.state().workflows.get(plan.workflowId).state = 'pending';
    if (variant === 'execution-pending') f.state().running.executionState = 'executing';
    if (variant === 'step-pending') f.state().running.stepState = 'running';
    if (variant === 'operation-incomplete') [...f.state().operations.values()][0].remote_completed = false;
    if (variant === 'native-packet') f.state().running.nativeCount = 1;
    if (variant === 'fact-sid') f.state().facts[0][8] = randomUUID();
    if (variant === 'plan-hash') f.state().workflows.get(plan.workflowId).plan_hash = 'f'.repeat(64);
    await expect(f.http(() => f.workflow.completionDelegate().terminalReceipt(plan, variant === 'other-owner' ? f.reviewer : f.author), variant === 'other-owner' ? f.reviewer : f.author, variant === 'fake-sid' ? randomUUID() : undefined)).rejects.toThrow();
    expect(f.state().operations.size).toBe(1);
  });
});
