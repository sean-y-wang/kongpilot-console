import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { assertKongPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { PortalAdminService } from '../../apps/console-api/src/modules/portal/portal-admin.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { WorkflowPlansService } from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'd8'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

// Actual retry policy, sealed repository load, AES-GCM and request HMACs.
// SQL rows and Kong GET responses are fixtures; no gateway mutation, PostgreSQL
// constraint or browser-recovery behavior is claimed by this suite.
function fixture(approved = false) {
  const cid = randomUUID(), wid = randomUUID(), uid = randomUUID(), serviceId = randomUUID(), workflowId = randomUUID();
  const physical = 'b'.repeat(64), secrets = new SecretService();
  const publication: any = { id: randomUUID(), cluster_id: cid, workspace_id: wid, service_id: serviceId, transport_scope: physical,
    name: 'Reviewed API', slug: 'reviewed-api', acl_group: 'reviewed-portal-group', revision: 4, current_revision: 1, state: 'pending', workflow_id: workflowId };
  const actor: any = { user: { id: uid, superAdmin: false }, workspaceId: wid, idempotencyKey: 'explicit-new-publication-key', requestId: randomUUID(), ip: '192.0.2.17' };
  const scope = { transportScope: physical, clusterRevision: 1, workspaceRevision: 1, executionMode: 'approval' as const };
  const context: any = { runActor: vi.fn(async (_scope: any, fn: any) => fn()), runPortalMetadataRead: vi.fn(async (_cid: any, _path: any, fn: any) => fn()), runInternalRead: vi.fn(async (_cid: any, _purpose: any, fn: any) => fn()) };
  const authz: any = { assertCluster: vi.fn(), assertScopedResource: vi.fn(), assertEntity: vi.fn() };
  const workspaces: any = { resolve: vi.fn(async () => ({ id: wid, status: 'active', revision: 1 })),
    prepareCreate: vi.fn(async (_cid: any, _type: any, payload: any) => payload), prepareUpdate: vi.fn(async (_cid: any, _type: any, _before: any, patch: any) => patch) };
  const kong: any = { transportScope: vi.fn(async () => physical), request: vi.fn(async (_cid: string, method: string, path: string) => {
    assertKongPath(method as any, path); expect(method).toBe('GET');
    if (path === `/services/${serviceId}`) return { id: serviceId, name: 'visible-service', tags: ['kos-ws-pay'] };
    if (path === '/plugins') return { data: [], next: null };
    if (path.startsWith('/schemas/')) return { fields: [] };
    throw new Error('Unexpected read fixture path');
  }) };
  let data: any;
  const db: any = { one: vi.fn(async (sql: string, p: any[]) => {
    if (sql.includes('FROM portal_publications')) return structuredClone(publication);
    if (sql.includes('FROM clusters')) return { revision: 1, execution_mode: 'approval', version: '1.5.1', status: 'healthy' };
    if (sql.includes('FROM workflow_versions')) return data.version;
    if (sql.includes('FROM workflows')) {
      if (sql.includes('idempotency_key')) return actor.idempotencyKey === data.row.idempotency_key ? { id: workflowId } : null;
      return p[0] === workflowId ? data.row : null;
    }
    if (sql.includes('FROM workflow_definitions')) return { id: randomUUID(), current_version: 1, policy_hash: 'c'.repeat(64) };
    return null;
  }), query: vi.fn(async (sql: string) => {
    if (sql.includes('FROM workflow_executions')) return data.executions;
    if (sql.includes('FROM workflow_steps')) return data.steps;
    if (sql.includes('FROM mutation_operations')) return data.operations;
    if (sql.includes('FROM iam_operations')) return data.iamOperations;
    throw new Error('Unexpected SQL fixture query');
  }), exec: vi.fn(async (sql: string, p: any[]) => {
    if (sql.startsWith('UPDATE portal_publications')) {
      if (publication.revision !== p[4] || publication.workflow_id !== p[5]) return 0;
      publication.state = p[1]; publication.workflow_id = p[2]; publication.revision++;
    }
    return 1;
  }), transaction: vi.fn(async (fn: any) => {
    const saved = structuredClone(publication);
    try { return await fn(db); } catch (error) { Object.assign(publication, saved); throw error; }
  }) };
  const native = new PortalNativeService(db, secrets, kong, context, authz, workspaces);
  const aclPayload = { id: randomUUID(), name: 'acl', service: { id: serviceId }, config: { whitelist: [publication.acl_group] } };
  const first = native.nativeStep(1, 'plugins', 'create', aclPayload, null, { workflowId });
  const second = native.nativeStep(2, 'plugins', 'create', { id: randomUUID(), name: 'key-auth', service: { id: serviceId }, config: { key_names: ['apikey'] } },
    null, { workflowId, dependencies: [first.id] });
  const terminal = native.metadataStep(3, 'portal.publication.publish', 'portal_publications', publication.id, structuredClone(publication), { publicationRevision: 1 }, [second.id]);
  const plan: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId, planRevision: 1, kind: 'portal-publication',
    executionMode: approved ? 'approval' : 'direct', approvalRequired: approved, subject: { type: 'portal_publications', id: publication.id },
    requester: { type: 'console', id: uid }, definition: { id: randomUUID(), version: 1, policyHash: 'c'.repeat(64) },
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString(), scope: { transportScope: physical, clusterRevision: 1, workspaceRevision: 1 }, prerequisites: [], steps: [first, second, terminal] };
  validateWorkflowPlan(plan);
  const row: any = { id: workflowId, cluster_id: cid, workspace_id: wid, plan_revision: 1, plan_hash: secrets.fingerprint(plan), state: 'failed',
    execution_mode: plan.executionMode, approval_required: approved,
    idempotency_key: 'original-failed-publication-key', request_hash: secrets.fingerprint({ requester: plan.requester, clusterId: cid, workspaceId: wid, request: { publicationId: publication.id, revision: 3, publish: true } }) };
  const execution: any = { id: randomUUID(), cluster_id: cid, workspace_id: wid, workflow_id: workflowId, plan_revision: 1, plan_hash: row.plan_hash,
    execution_actor_id: uid, idempotency_key: 'original-execution-key', execution_mode: plan.executionMode, approval_required: approved, approved_by: approved ? randomUUID() : null, state: 'failed' };
  const operation: any = { id: randomUUID(), actor_id: uid, cluster_id: cid, workspace_id: wid, transport_scope: physical,
    state: 'failed', remote_started: true, remote_completed: false, action: 'create', entity_type: 'plugins', entity_id: null,
    idempotency_key: first.mutationIdempotencyKey, workflow_id: approved ? workflowId : null, workflow_execution_id: approved ? execution.id : null,
    workflow_plan_revision: approved ? 1 : null, workflow_plan_hash: approved ? row.plan_hash : null, workflow_step_id: approved ? first.id : null };
  operation.payload_secret = secrets.encrypt(aclPayload, `mutation:${operation.id}:payload`);
  operation.before_secret = secrets.encrypt(null, `mutation:${operation.id}:before`);
  operation.request_hash = secrets.fingerprint({ actor: uid, clusterId: cid, workspaceId: wid, entityType: 'plugins', entityId: null, action: 'create',
    payload: aclPayload, parentId: null, credentialKind: null, ...(approved ? { approvedWorkflow: { workflowId, executionId: execution.id, planRevision: 1, planHash: row.plan_hash, stepId: first.id, beforeHmac: first.beforeFingerprint } } : {}) });
  const steps = plan.steps.map((step: any, index: number) => ({ id: step.id, cluster_id: cid, workspace_id: wid, workflow_id: workflowId, plan_revision: 1, plan_hash: row.plan_hash,
    kind: step.kind, entity_type: step.entityType, entity_id: step.entityId ?? null, parent_id: step.parentId ?? null, credential_kind: step.credentialKind ?? null,
    mutation_action: step.mutationAction ?? null, mutation_idempotency_key: step.mutationIdempotencyKey ?? null, state: index === 0 ? 'failed' : 'pending',
    completed_at: index === 0 ? new Date().toISOString() : null, operation_id: index === 0 && approved ? operation.id : null,
    safe_result: index === 0 ? { nativeOperationId: operation.id, remoteStarted: true, remoteCompleted: false } : {}, after_fingerprint: null, recycle_entry_id: null }));
  data = { row, version: { plan_hash: row.plan_hash, steps_hash: secrets.fingerprint(plan.steps), payload_secret: secrets.encrypt(plan, planAad(cid, wid, workflowId, 1)) },
    steps, executions: [execution], operations: [operation], iamOperations: [] };
  const plans = new WorkflowPlansService(db, secrets, { append: vi.fn() } as any);
  let submitted: any;
  vi.spyOn(plans, 'persist').mockImplementation(async (newPlan: any) => {
    validateWorkflowPlan(newPlan); submitted = newPlan;
    return { id: newPlan.workflowId, kind: newPlan.kind, state: 'pending', revision: 1, plan_revision: 1, plan_hash: secrets.fingerprint(newPlan),
      approval_required: true, execution_mode: 'approval', created_at: new Date().toISOString(), expires_at: newPlan.expiresAt };
  });
  const workflows: any = { execute: vi.fn(), receiptByKey: vi.fn(async () => ({ workflowId, state: row.state })) };
  const admin = new PortalAdminService(db, secrets, authz, { append: vi.fn() } as any, {} as any, {} as any, workspaces, {} as any,
    plans, new WorkflowRegistryService(), workflows, native, {} as any);
  const body = { revision: publication.revision, confirmed: true, confirm_name: publication.name };
  return { admin, cid, wid, actor, publication, body, row, execution, operation, first, steps, plan, data, db, plans, native, kong, authz, workflows, secrets,
    submitted: () => submitted, reseal: () => { row.plan_hash = secrets.fingerprint(plan); data.version = { plan_hash: row.plan_hash, steps_hash: secrets.fingerprint(plan.steps), payload_secret: secrets.encrypt(plan, planAad(cid, wid, workflowId, 1)) }; },
    publish: () => admin.publish(cid, publication.id, body, actor) };
}

describe('M6 independent explicit new-key known-failed publication recovery', () => {
  it.each([false, true])('permits one explicit fresh plan after a sealed known failure (approved=%s), without dispatching any native packet', async approved => {
    const f = fixture(approved), originalWorkflow = f.publication.workflow_id;
    const result = await f.publish(); expect(result.state).toBe('pending'); expect(result.workflowId).not.toBe(originalWorkflow);
    expect(f.submitted().subject.id).toBe(f.publication.id); expect(f.submitted().approvalRequired).toBe(true);
    expect(f.workflows.execute).not.toHaveBeenCalled(); expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
    expect(f.db.query.mock.calls.filter((call: any[]) => call[0].includes('FROM mutation_operations'))).toHaveLength(2);
    expect(f.db.one.mock.calls.some((call: any[]) => call[0].includes('FOR UPDATE'))).toBe(true);
  });

  it('original failed submission key returns the original receipt with no scan, replan or execution', async () => {
    const f = fixture(); f.actor.idempotencyKey = f.row.idempotency_key; f.body.revision = 3;
    expect(await f.publish()).toEqual({ workflowId: f.row.id, state: 'failed' });
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.plans.persist).not.toHaveBeenCalled();
    expect(f.workflows.execute).not.toHaveBeenCalled();
  });

  it.each(['snapshot denied before any step', 'first Entity preflight denied before mutation allocation'])('permits explicit recovery after a durable known 403: %s, with zero mutation facts', async phase => {
    const f = fixture(); f.data.operations = []; f.steps[0].safe_result = {}; f.steps[0].operation_id = null;
    if (phase === 'snapshot denied before any step') { f.steps[0].state = 'pending'; f.steps[0].completed_at = null; }
    else f.steps[0].error_code = 'ENTITY_PERMISSION_DENIED';
    const result = await f.publish(); expect(result.state).toBe('pending'); expect(f.plans.persist).toHaveBeenCalledOnce();
    expect(f.workflows.execute).not.toHaveBeenCalled();
  });

  it.each(['pending', 'approved', 'executing', 'partial', 'uncertain', 'succeeded'])('refuses current prior workflow state %s after exact current Service authorization and before plugin scanning', async state => {
    const f = fixture(); f.row.state = state;
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.kong.request).toHaveBeenCalledOnce(); expect(f.kong.request.mock.calls[0][2]).toBe(`/services/${f.publication.service_id}`);
    expect(f.authz.assertScopedResource).toHaveBeenCalledOnce(); expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it.each([
    ['missing execution', (f: any) => { f.data.executions = []; }],
    ['second execution', (f: any) => { f.data.executions.push({ ...f.execution, id: randomUUID() }); }],
    ['missing normalized child', (f: any) => { f.data.steps.pop(); }],
    ['missing referenced native receipt', (f: any) => { f.data.operations = []; }],
    ['completed native packet', (f: any) => { f.operation.remote_completed = true; }],
    ['uncertain native receipt', (f: any) => { f.operation.state = 'uncertain'; }],
    ['running native receipt', (f: any) => { f.operation.state = 'running'; }],
    ['succeeded child', (f: any) => { f.steps[0].state = 'succeeded'; }],
    ['pending child with started fact', (f: any) => { f.steps[1].started_at = new Date().toISOString(); }],
    ['child after fingerprint', (f: any) => { f.steps[0].after_fingerprint = 'a'.repeat(64); }],
    ['child archive', (f: any) => { f.steps[0].recycle_entry_id = randomUUID(); }],
    ['metadata failure', (f: any) => { f.steps[2].state = 'failed'; f.steps[2].completed_at = new Date().toISOString(); }],
    ['metadata IAM ledger fact', (f: any) => { f.data.iamOperations = [{ id: randomUUID() }]; }],
    ['foreign physical scope', (f: any) => { f.operation.transport_scope = 'f'.repeat(64); }],
    ['foreign workspace', (f: any) => { f.operation.workspace_id = randomUUID(); }],
    ['foreign execution actor', (f: any) => { f.operation.actor_id = randomUUID(); }],
    ['substituted operation UUID', (f: any) => { f.steps[0].safe_result.nativeOperationId = randomUUID(); }],
    ['duplicate native ledger facts', (f: any) => { f.data.operations.push({ ...f.operation, id: randomUUID() }); }],
    ['foreign execution version', (f: any) => { f.execution.plan_hash = 'f'.repeat(64); }],
    ['foreign normalized child tuple', (f: any) => { f.steps[0].entity_type = 'services'; }],
    ['encrypted payload substitution', (f: any) => { f.operation.payload_secret = f.secrets.encrypt({ id: randomUUID() }, `mutation:${f.operation.id}:payload`); }],
    ['encrypted before substitution', (f: any) => { f.operation.before_secret = f.secrets.encrypt({ id: randomUUID() }, `mutation:${f.operation.id}:before`); }],
    ['logical CREATE incorrectly hashed with native UUID', (f: any) => { f.operation.request_hash = f.secrets.fingerprint({ ...f.operation, entityId: f.first.mutationPayload.id }); }],
    ['foreign preallocated CREATE acknowledgment ID', (f: any) => { f.operation.entity_id = randomUUID(); }],
  ] as const)('refuses %s and preserves the original publication pointer', async (_name, change) => {
    const f = fixture(), originalWorkflow = f.publication.workflow_id; change(f);
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.publication.workflow_id).toBe(originalWorkflow); expect(f.plans.persist).not.toHaveBeenCalled();
    expect(f.kong.request).toHaveBeenCalledOnce(); expect(f.kong.request.mock.calls[0][2]).toBe(`/services/${f.publication.service_id}`);
  });

  it.each(['executionId', 'stepId', 'planHash'])('refuses an approved Native receipt linked to the wrong %s', async field => {
    const f = fixture(true);
    if (field === 'executionId') f.operation.workflow_execution_id = randomUUID();
    if (field === 'stepId') f.operation.workflow_step_id = randomUUID();
    if (field === 'planHash') f.operation.workflow_plan_hash = 'e'.repeat(64);
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it.each(['subject', 'physical scope'])('refuses a sealed prior plan belonging to another %s', async field => {
    const f = fixture();
    if (field === 'subject') f.plan.subject.id = randomUUID(); else f.plan.scope.transportScope = 'e'.repeat(64);
    f.reseal();
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it('does not accept an unresolvable current publication workflow pointer as the old failed workflow', async () => {
    const f = fixture(); f.publication.workflow_id = randomUUID();
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it('rejects a corrupted sealed plan instead of accepting client or normalized-row assurances', async () => {
    const f = fixture(); f.data.version.steps_hash = 'f'.repeat(64);
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.plans.persist).not.toHaveBeenCalled();
  });

  it('revalidates current Service portal-write authority before creating a replacement plan', async () => {
    const f = fixture(); f.authz.assertScopedResource.mockRejectedValue(new ForbiddenException({ code: 'RESOURCE_PERMISSION_DENIED' }));
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'RESOURCE_PERMISSION_DENIED' } });
    expect(f.kong.request).toHaveBeenCalledOnce(); expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
  });

  it('stops when a receipt becomes unknown between the initial proof and transaction revalidation', async () => {
    const f = fixture(), request = f.kong.request.getMockImplementation()!;
    f.kong.request.mockImplementation(async (...args: any[]) => { if (args[2] === '/plugins') f.operation.state = 'uncertain'; return request(...args); });
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_RECOVERY_REQUIRED' } });
    expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['revision', 'workflow_id'])('publication %s CAS loss does not persist or execute a replacement plan', async field => {
    const f = fixture(), request = f.kong.request.getMockImplementation()!;
    f.kong.request.mockImplementation(async (...args: any[]) => { if (args[2] === '/plugins') field === 'revision' ? f.publication.revision++ : f.publication.workflow_id = randomUUID(); return request(...args); });
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.workflows.execute).not.toHaveBeenCalled();
  });
});

describe('§49 republishing an already-proven publication revision is refused at prepare with a clean 409', () => {
  const proven = (f: any) => { f.publication.state = 'published'; const provenRev = f.publication.current_revision; const one = f.db.one.getMockImplementation();
    f.db.one.mockImplementation(async (sql: string, p: any[]) => sql.includes('FROM portal_publication_proofs') ? (p[2] === f.publication.id && p[3] === provenRev ? { proven: 1 } : null) : one(sql, p)); };
  it('refuses with PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED before plugin scan, CAS, plan persist or execution', async () => {
    const f = fixture(true); proven(f); const before = structuredClone(f.publication);
    await expect(f.publish()).rejects.toMatchObject({ status: 409, response: { code: 'PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED', publicationRevision: 1 } });
    expect(f.kong.request.mock.calls.some((c: any[]) => c[2] === '/plugins')).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
    expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.workflows.execute).not.toHaveBeenCalled(); expect(f.publication).toEqual(before);
  });
  it('allows publishing once a new draft revision exists (proof only for the old revision)', async () => {
    const f = fixture(true); proven(f); f.publication.current_revision = 2; f.body.revision = f.publication.revision;
    const result = await f.publish(); expect(result.state).toBe('pending'); expect(f.plans.persist).toHaveBeenCalledOnce();
    expect(f.submitted().steps.at(-1).metadata.publicationRevision).toBe(2);
  });
  it('rechecks inside the transaction (proof landing between scan and CAS) and persists nothing', async () => {
    const f = fixture(true); f.publication.state = 'published'; const one = f.db.one.getMockImplementation(); let landed = false;
    f.db.one.mockImplementation(async (sql: string, p: any[]) => sql.includes('FROM portal_publication_proofs') ? (landed ? { proven: 1 } : null) : one(sql, p));
    const request = f.kong.request.getMockImplementation()!; f.kong.request.mockImplementation(async (...a: any[]) => { if (a[2] === '/plugins') landed = true; return request(...a); });
    await expect(f.publish()).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED' } });
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.plans.persist).not.toHaveBeenCalled();
  });
  it('unpublish is not affected by an existing proof', async () => {
    const f = fixture(true); proven(f);
    await f.admin.publish(f.cid, f.publication.id, f.body, f.actor, false).catch((e: any) => { expect(e?.response?.code).not.toBe('PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED'); });
  });
});
