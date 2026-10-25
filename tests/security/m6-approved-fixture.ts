import { vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { normalizedNativeRequests } from '../../apps/console-api/src/modules/workflows/approved-execution.types';
import { planAad, snapshotAad, type WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';
import type { MutationContext } from '../../apps/console-api/src/modules/mutations/mutation.service';

export const id = (n: number) => `10000000-0000-4000-8000-${n.toString().padStart(12, '0')}`;
export const cid = id(1), wid = id(2), wf = id(3), eid = id(4), sid = id(5), nativeId = id(6), serviceId = id(7), subjectId = id(8);
export const actor = { id: id(9), username: 'executor', superAdmin: false };
export const approverId = id(10), physical = 'a'.repeat(64);
export function approvedFixture() {
  const secrets = new SecretService(), context = new KongExecutionContextService();
  const serviceObject: any = { id: serviceId, name: 'published-api', host: 'business.test', tags: ['kos-ws-pay', 'team-pay'] };
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', transport_scope: physical, version: '1.5.1', execution_mode: 'approval', revision: 1, status: 'active' };
  const workspace: any = { id: wid, cluster_id: cid, status: 'active', revision: 1 };
  let permissionVersion = 'epoch-1', executorEnabled = true;
  const body = { id: nativeId, username: 'portal-application', tags: ['kos-ws-pay'] };
  const plan: WorkflowPlanV1 = {
    version: 1, clusterId: cid, workspaceId: wid, workflowId: wf, planRevision: 1,
    kind: 'portal-credential-issue', executionMode: 'approval', approvalRequired: true,
    subject: { type: 'portal_application_grants', id: subjectId }, requester: { type: 'developer', id: id(11) },
    definition: { id: id(12), version: 1, policyHash: secrets.fingerprint({ single: true }) },
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300_000).toISOString(),
    scope: { transportScope: physical, clusterRevision: 1, workspaceRevision: 1 },
    prerequisites: [{ type: 'services', id: serviceId, path: `/services/${serviceId}`, fingerprint: secrets.fingerprint(serviceObject), before: structuredClone(serviceObject) }],
    steps: [{ id: sid, key: 'consumer', order: 1, kind: 'native', entityType: 'consumers', permissionAction: 'write', dependencies: [],
      mutationAction: 'create', mutationPayload: body, mutationPayloadHmac: secrets.fingerprint(body), mutationIdempotencyKey: 'sealed-consumer-step',
      beforeFingerprint: secrets.fingerprint(null), nativeRequests: [{ method: 'POST', canonicalPath: '/consumers', nativeType: 'consumers', nativeId, body, bodyHmac: secrets.fingerprint(body) }] }],
  };
  const execution: any = { id: eid, cluster_id: cid, workspace_id: wid, workflow_id: wf, plan_revision: 1, state: 'executing', snapshot_state: 'ready', approval_required: true,
    execution_mode: 'approval', approved_by: approverId, execution_actor_id: actor.id, expires_at: plan.expiresAt };
  const workflow: any = { id: wf, cluster_id: cid, workspace_id: wid, plan_revision: 1, state: 'executing', approval_required: true, execution_mode: 'approval', approved_by: approverId,
    subject_type: plan.subject.type, subject_id: subjectId, kind: plan.kind, requester_type: 'developer', requester_developer_id: id(11), definition_id: plan.definition.id, definition_version: 1, expires_at: plan.expiresAt };
  const version: any = { plan_revision: 1, policy_version: 1, approval_required: true, execution_mode: 'approval', expires_at: plan.expiresAt };
  const rows: any[] = [], operations = new Map<string, any>();
  const approvals: any[] = [], stages: any[] = [];
  const approvedBy: any = { id: approverId, super_admin: false, status: 'active' };
  const grants: any[] = [{ module: 'workflows', action: 'approve', scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: serviceId }], cluster_id: cid, workspace_id: wid }];
  const publication: any = { id: id(13), cluster_id: cid, workspace_id: wid, state: 'published', transport_scope: physical, service_id: serviceId };
  const grant: any = { id: subjectId, cluster_id: cid, workspace_id: wid, state: 'pending', transport_scope: physical, publication_id: publication.id, application_id: id(14), developer_id: id(11) };
  const developer: any = { id: id(11), cluster_id: cid, workspace_id: wid, status: 'active' };
  const application: any = { id: id(14), cluster_id: cid, workspace_id: wid, status: 'active', developer_id: developer.id };
  const definition: any = { mode: 'single', allow_self_approval: false, policy_hash: plan.definition.policyHash };
  let snapshot: any;
  function seal() {
    workflow.kind = plan.kind; workflow.subject_type = plan.subject.type; workflow.subject_id = plan.subject.id;
    for (const row of [execution, workflow, version]) Object.assign(row, { execution_mode: plan.executionMode, approval_required: plan.approvalRequired, plan_hash: secrets.fingerprint(plan) });
    Object.assign(version, { payload_secret: secrets.encrypt(plan, planAad(cid, wid, wf, 1)), steps_hash: secrets.fingerprint(plan.steps), step_count: plan.steps.length, native_request_count: plan.steps.reduce((n, s) => n + s.nativeRequests.length, 0) });
    rows.splice(0, rows.length, ...plan.steps.map(step => ({ id: step.id, cluster_id: cid, workspace_id: wid, workflow_id: wf, plan_revision: 1, plan_hash: execution.plan_hash,
      execution_mode: plan.executionMode, approval_required: plan.approvalRequired, step_key: step.key, step_order: step.order, kind: step.kind, handler: step.handler ?? null,
      entity_type: step.entityType, entity_id: step.entityId ?? null, parent_id: step.parentId ?? null, credential_kind: step.credentialKind ?? null, permission_action: step.permissionAction,
      mutation_action: step.mutationAction ?? null, mutation_payload_hmac: step.mutationPayloadHmac ?? null, mutation_idempotency_key: step.mutationIdempotencyKey ?? null,
      before_fingerprint: step.beforeFingerprint ?? null, native_requests: normalizedNativeRequests(step.nativeRequests, secrets), dependencies: step.dependencies,
      metadata_before_hmac: step.metadataBeforeHmac ?? null, metadata_revision: step.metadataRevision ?? null, metadata_payload_hmac: step.metadataPayloadHmac ?? null,
      state: 'running', operation_id: null, revision: 1 })));
    snapshot = { version: 1, workflowId: wf, executionId: eid, clusterId: cid, workspaceId: wid, planRevision: 1, planHash: execution.plan_hash, capturedAt: new Date().toISOString(),
      objects: [...plan.prerequisites.map(item => ({ ...item, absent: false })), ...plan.steps.flatMap(step => step.nativeRequests.map(request => ({ type: request.nativeType, id: request.nativeId,
        path: request.method === 'POST' ? `${request.canonicalPath}/${request.nativeId}` : request.canonicalPath, before: request.method === 'POST' ? null : step.before,
        absent: request.method === 'POST', fingerprint: request.method === 'POST' ? secrets.fingerprint(null) : (request.beforeHmac ?? step.beforeFingerprint) })))] };
    sealSnapshot();
    approvals.splice(0, approvals.length, { decision: 'approve', approver_id: approverId, plan_hash: execution.plan_hash, level: 1 });
    stages.splice(0, stages.length, { state: 'approved', required_approvals: 1, level: 1, plan_hash: execution.plan_hash });
  }
  function sealSnapshot() { execution.snapshot_secret = secrets.encrypt(snapshot, snapshotAad(cid, wid, wf, eid)); execution.snapshot_hash = secrets.fingerprint(snapshot); }
  seal();
  const db: any = {
    one: vi.fn(async (sql: string, p: any[] = []) => {
      if (sql.includes('FROM iam_epoch')) return { version: 1 };
      if (sql.includes('FROM workflow_executions')) return p[0] === eid ? execution : null;
      if (sql.includes('FROM workflows')) return workflow;
      if (sql.includes('FROM workflow_versions')) return version;
      if (sql.includes('FROM workflow_definition_versions')) return definition;
      if (sql.includes('FROM clusters')) return cluster;
      if (sql.includes('FROM users')) return approvedBy.status === 'active' ? approvedBy : null;
      if (sql.includes('FROM portal_application_grants')) return grant;
      if (sql.includes('FROM portal_publications')) return publication;
      if (sql.includes('FROM portal_applications')) return application;
      if (sql.includes('FROM portal_developers')) return developer;
      if (sql.includes('FROM mutation_operations')) return operations.get(p[0]) ?? [...operations.values()].find(row => row.cluster_id === p[0] && row.idempotency_key === p[1]) ?? null;
      throw new Error(`Unhandled private DB read: ${sql}`);
    }),
    query: vi.fn(async (sql: string) => {
      if (sql.includes('FROM workflow_steps')) return rows;
      if (sql.includes('FROM workflow_approvals')) return approvals;
      if (sql.includes('FROM workflow_stages')) return stages;
      if (sql.includes('FROM iam_effective_grants')) return grants;
      if (sql.includes('FROM mutation_operations')) return [];
      throw new Error(`Unhandled private DB list: ${sql}`);
    }),
    exec: vi.fn(async (sql: string, p: any[]) => {
      if (sql.startsWith('INSERT INTO mutation_operations')) {
        const [id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret, workspace_id, transport_scope, impact, parent_id, credential_kind, workflow_execution_id, workflow_plan_revision, workflow_plan_hash, workflow_step_id] = p;
        operations.set(id, { id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret, workspace_id, transport_scope, impact: JSON.parse(impact), parent_id, credential_kind, workflow_execution_id, workflow_plan_revision, workflow_plan_hash, workflow_step_id, state: 'running' }); return 1;
      }
      if (sql.startsWith('UPDATE workflow_steps SET operation_id')) {
        const row = rows.find(item => item.id === p[0]); if (!row || row.operation_id || row.state !== 'running' || row.revision !== p[2]) return 0;
        row.operation_id = p[1]; row.revision++; return 1;
      }
      const op = operations.get(p[0]); if (!op) return 0;
      if (sql.includes('remote_started=true')) op.remote_started = true;
      else if (sql.includes('remote_completed=true')) Object.assign(op, { remote_completed: true, entity_id: p[1], result_secret: p[2] });
      else if (sql.includes("state='succeeded'")) Object.assign(op, { state: 'succeeded', safe_result: JSON.parse(p[1]) });
      else if (sql.includes('SET state=$2')) Object.assign(op, { state: p[1], error_code: p[2] });
      return 1;
    }),
    transaction: vi.fn(async (fn: any) => {
      const oldOps = structuredClone([...operations.entries()]), oldRows = structuredClone(rows);
      try { return await fn(db); } catch (error) { operations.clear(); for (const [k, v] of oldOps) operations.set(k, v); rows.splice(0, rows.length, ...oldRows); throw error; }
    }),
  };
  const authz: any = {
    snapshot: vi.fn(async (user: any) => { if (!executorEnabled) throw new ForbiddenException({ code: 'SESSION_REVOKED' }); return { user, version: permissionVersion, grants: [] }; }),
    permissionVersion: vi.fn(async () => permissionVersion),
    assertScopedResource: vi.fn(async () => undefined), assertWholeWorkspace: vi.fn(async () => undefined), assertCluster: vi.fn(async () => undefined), assertEntity: vi.fn(async () => undefined), isPlatformAdmin: vi.fn(async () => false),
  };
  const workspaceResolver: any = { resolve: vi.fn(async () => workspace), listScope: vi.fn(async () => ({ workspaceId: wid, mode: 'tag', workspaceTag: 'kos-ws-pay' })),
    matches: (_scope: any, value: any) => value.tags?.includes('kos-ws-pay'), assertMembership: vi.fn(() => undefined) };
  const nativeObjects = new Map<string, any>([[`/services/${serviceId}`, serviceObject]]);
  const kong: any = { transportScope: vi.fn(async () => physical), request: vi.fn(async (_cid: string, method: string, path: string) => {
    if (method !== 'GET') throw new Error('Fixture transport must never send native writes');
    const value = nativeObjects.get(path); if (value == null) throw new NotFoundException(); return value;
  }) };
  const redis: any = { assertLeaseOwnership: vi.fn(async () => undefined), withLock: vi.fn(async (_key: string, fn: any) => fn()) };
  const verifier = new ApprovedWorkflowExecutionService(db, secrets, authz, workspaceResolver, kong, redis, context); verifier.onModuleInit();
  const hooks: any = { authorizeRequest: vi.fn(async () => ({ before: null })), authorizeResponse: vi.fn(async (_ticket: any, result: any) => result) };
  context.installPolicy(hooks);
  const mutationContext = (): MutationContext => ({ clusterId: cid, workspaceId: wid, actor, entityType: plan.steps[0].entityType, entityId: plan.steps[0].entityId,
    parentId: plan.steps[0].parentId, credentialKind: plan.steps[0].credentialKind, action: plan.steps[0].mutationAction!, before: plan.steps[0].before,
    payload: plan.steps[0].mutationPayload, idempotencyKey: plan.steps[0].mutationIdempotencyKey });
  const http = <T>(fn: () => Promise<T>, user = actor, session = 'verified-session') => context.runHttp({}, async () => {
    context.bindHttpActor(user, session); const close = context.captureHttpCloser();
    try { return await context.runActor({ actor: user, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write' }, fn); } finally { close(); }
  });
  const run = <T>(fn: () => Promise<T>) => http(() => verifier.runApprovedExecution(eid, () => context.runApprovedStep(sid, fn)));
  const allocate = async () => {
    const ctx = mutationContext(), binding = (await context.approvedMutationBinding(ctx))!, opId = id(99);
    operations.set(opId, { id: opId, state: 'running', actor_id: actor.id, cluster_id: cid, workspace_id: wid, workflow_id: wf, workflow_execution_id: eid,
      workflow_plan_revision: 1, workflow_plan_hash: execution.plan_hash, workflow_step_id: sid, remote_started: true,
      before_secret: secrets.encrypt(ctx.before ?? null, `mutation:${opId}:before`), payload_secret: secrets.encrypt(ctx.payload ?? null, `mutation:${opId}:payload`) });
    await context.bindApprovedOperation(ctx, binding, opId, db); return { ctx, binding, opId };
  };
  const withPacket = async <T>(fn: (ticket: any, opId: string) => Promise<T>) => {
    const { ctx, opId } = await allocate();
    return context.runOperation({ ...ctx, workspaceId: wid, operationId: opId }, async () => {
      const request = plan.steps[0].nativeRequests[0], ticket = await context.authorizeRequest(cluster, request.method, request.canonicalPath, request.body, {});
      return fn(ticket, opId);
    });
  };
  return { verifier, context, db, secrets, cluster, workspace, plan, execution, workflow, version, rows, approvals, stages, approvedBy, grants, grant, application, developer, publication,
    snapshot: () => snapshot, sealSnapshot, seal, authz, redis, kong, nativeObjects, serviceObject, hooks, mutationContext, http, run, allocate, withPacket,
    setVersion: (value: string) => { permissionVersion = value; }, revokeExecutor: () => { executorEnabled = false; }, operations };
}
