import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { migrationNativeRequests } from '../../apps/console-api/src/modules/workflows/workspace-migration-workflow';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';
import type { WorkspaceMigrationMaterial } from '../../apps/console-api/src/modules/workspaces/workspace-migration.service';

/** Real encrypted-material comparison and subject authorization. Database and
 * grant functions are explicit synthetic fixtures; no capability, execution
 * handle, approval receipt or native authorization proof is fabricated. */
function fixture() {
  const secrets = new SecretService(), cid = randomUUID(), sourceId = randomUUID(), targetId = randomUUID();
  const actor = { id: randomUUID(), username: 'migration-requester', superAdmin: false };
  const approver = { id: randomUUID(), username: 'migration-approver', superAdmin: false };
  const migrationId = randomUUID(), workflowId = randomUUID(), serviceId = randomUUID(), consumerId = randomUUID();
  const credentialId = randomUUID(), upstreamId = randomUUID(), targetEntityId = randomUUID(), certificateId = randomUUID();
  const source = { id: sourceId, cluster_id: cid, code: 'source', name: '源工作区', status: 'active', revision: 1 };
  const target = { id: targetId, cluster_id: cid, code: 'target', name: '目标工作区', status: 'active', revision: 1 };
  const node = (type: string, id: string, data: any, parent?: string, inheritedOnly = false): any => {
    const path = parent ? type === 'targets' ? `/upstreams/${parent}/targets/${id}` : `/consumers/${parent}/${type}/${id}` : `/${type}/${id}`;
    const key = parent ? `${type}:${parent}:${id}` : `${type}:${id}`;
    const before = { id, tags: ['team-pay', 'kos-ws-source'], ...data };
    const { tags: _tags, updated_at: _updated, ...configuration } = before;
    return { key, type, id, path, data: before, affected: true, restorable: true,
      dependencies: parent ? [`${type === 'targets' ? 'upstreams' : 'consumers'}:${parent}`] : [],
      sourceWorkspaceId: sourceId, beforeFingerprint: secrets.fingerprint(before), configFingerprint: secrets.fingerprint(configuration),
      afterTags: inheritedOnly ? before.tags : ['team-pay', 'kos-ws-target'], inheritedOnly };
  };
  const reference = node('certificates', certificateId, { cert: 'captured-public-certificate', key: 'captured-private-key' });
  reference.affected = false; reference.workspaceId = sourceId;
  const material = { source, target,
    nodes: [node('services', serviceId, { name: 'source-service', host: 'backend.test', client_certificate: { id: certificateId } }),
      node('consumers', consumerId, { username: 'source-client' }),
      node('key-auth', credentialId, { consumer: { id: consumerId }, key: 'captured-api-key' }, consumerId),
      node('upstreams', upstreamId, { name: 'source-upstream' }),
      node('targets', targetEntityId, { upstream: { id: upstreamId }, target: 'backend.test:8080', weight: 100 }, upstreamId, true)],
    referenceNodes: [reference], edges: [[`services:${serviceId}`, `certificates:${certificateId}`]],
    conflicts: [], budget: { pages: 10, records: 6, nodes: 6, bytes: 2000 }, permissions: 'epoch-1',
  } as unknown as WorkspaceMigrationMaterial;
  const planHash = secrets.fingerprint({ cid, actor: actor.id, payload: material }), materialHash = secrets.fingerprint(material);
  const payload = { plan_id: migrationId, plan_hash: planHash, confirmed: true, confirm_name: target.name };
  const before = { id: migrationId, workspace_id: sourceId };
  const plan: WorkflowPlanV1 = { version: 1, clusterId: cid, workspaceId: sourceId, workflowId, planRevision: 1,
    kind: 'workspace-migration', executionMode: 'approval', approvalRequired: true,
    subject: { type: 'workspace_migration_plans', id: migrationId }, requester: { type: 'console', id: actor.id },
    definition: { id: randomUUID(), version: 1, policyHash: 'b'.repeat(64) },
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(),
    scope: { transportScope: 'c'.repeat(64), clusterRevision: 1, workspaceRevision: 1 },
    migration: { sourceWorkspaceId: sourceId, targetWorkspaceId: targetId, targetWorkspaceRevision: 1, materialHmac: materialHash },
    prerequisites: [...material.referenceNodes, ...material.nodes.filter(node => node.inheritedOnly)]
      .map(node => ({ type: node.type, id: node.id, path: node.path, before: node.data, fingerprint: secrets.fingerprint(node.data) })),
    steps: [{ id: randomUUID(), key: 'workspace-migration', order: 1, kind: 'native', entityType: 'workspace_migration',
      entityId: migrationId, permissionAction: 'write', dependencies: [], mutationAction: 'migrate',
      mutationPayload: payload, mutationPayloadHmac: secrets.fingerprint(payload), mutationIdempotencyKey: `migration-${workflowId}`,
      nativeRequests: migrationNativeRequests(material, secrets), before, beforeFingerprint: secrets.fingerprint(before) }],
  };
  const row: any = { id: migrationId, cluster_id: cid, actor_id: actor.id, source_workspace_id: sourceId, target_workspace_id: targetId,
    state: 'planned', plan_hash: planHash, payload_secret: secrets.encrypt(material, `workspace-migration:${migrationId}`),
    operation_id: null, expires_at: new Date(Date.now() + 900_000).toISOString(), workflow_id: workflowId };
  const binding: any = { cluster_id: cid, source_workspace_id: sourceId, target_workspace_id: targetId,
    migration_plan_id: migrationId, workflow_id: workflowId, actor_id: actor.id,
    migration_plan_hash: planHash, material_hmac: materialHash, request_hash: 'd'.repeat(64) };
  const state: { row: any; binding: any; epoch: string } = { row, binding, epoch: 'epoch-1' };
  const db: any = { one: vi.fn(async (sql: string, parameters: any[]) => {
    if (sql.includes('FROM workspace_migration_workflow_bindings')) return state.binding
      && state.binding.cluster_id === parameters[0] && state.binding.migration_plan_id === parameters[1] && state.binding.workflow_id === parameters[2]
      ? structuredClone(state.binding) : null;
    if (sql.includes('FROM workspace_migration_plans')) return state.row
      && state.row.id === parameters[0] && state.row.cluster_id === parameters[1] && state.row.source_workspace_id === parameters[2]
      ? structuredClone(state.row) : null;
    throw new Error('Unexpected subject query');
  }) };
  const authz: any = { permissionVersion: vi.fn(async () => state.epoch), assertWholeWorkspace: vi.fn(),
    assertCluster: vi.fn(), assertMigrationEntity: vi.fn(), assertEntity: vi.fn() };
  const currentSource = structuredClone(source), currentTarget = structuredClone(target);
  const workspaces: any = { get: vi.fn(async (_clusterId: string, id: string) => structuredClone(id === sourceId ? currentSource : currentTarget)) };
  const kong: any = { request: vi.fn(), transportScope: vi.fn() };
  const verifier = new ApprovedWorkflowExecutionService(db, secrets, authz, workspaces, kong, {} as any, {} as any);
  const encryptMaterial = () => { state.row.payload_secret = secrets.encrypt(material, `workspace-migration:${migrationId}`); };
  return { verifier, secrets, plan, material, state, row, binding, db, authz, workspaces, kong,
    actor, approver, cid, sourceId, targetId, currentSource, currentTarget, encryptMaterial };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cd'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

const rejectWith = (promise: Promise<unknown>, status: number, code: string) => expect(promise).rejects.toMatchObject({ status, response: { code } });

describe('M9 original encrypted workspace migration authority', () => {
  it('authorizes the requester on both actual workspace graphs without any gateway call or native proof', async () => {
    const f = fixture(); await f.verifier.assertSubject(f.plan, f.actor, 'write');
    expect(f.authz.assertWholeWorkspace.mock.calls.map(call => call.slice(1)))
      .toEqual([[f.cid, f.sourceId, 'workflows', 'write'], [f.cid, f.targetId, 'workflows', 'write']]);
    expect(f.authz.assertMigrationEntity).toHaveBeenCalledTimes(f.material.nodes.length * 2);
    for (let i = 0; i < f.material.nodes.length; i++) {
      const source = f.authz.assertMigrationEntity.mock.calls[i * 2], target = f.authz.assertMigrationEntity.mock.calls[i * 2 + 1];
      expect(source[4]).toEqual(f.material.nodes[i].data); expect(source[5]).toBe(f.sourceId);
      expect(target[5]).toBe(f.targetId); expect(target[6].find(node => node.type === 'consumers').data.tags).toContain('kos-ws-target');
      expect(target[6].find(node => node.type === 'upstreams').data.tags).toContain('kos-ws-target');
    }
    expect(f.authz.assertEntity).toHaveBeenCalledWith(f.actor, f.cid, 'certificates', 'read', f.material.referenceNodes[0].data, f.sourceId);
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('requires both workspace approval grants and object reads, without granting approvers object write', async () => {
    const f = fixture(); await f.verifier.assertSubject(f.plan, f.approver, 'approve');
    expect(f.authz.assertWholeWorkspace.mock.calls.map(call => call.slice(1)))
      .toEqual([[f.cid, f.sourceId, 'workflows', 'approve'], [f.cid, f.targetId, 'workflows', 'approve']]);
    expect(f.authz.assertMigrationEntity.mock.calls.every(call => call[3] === 'read')).toBe(true);
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each([
    ['missing material row', (f: ReturnType<typeof fixture>) => { f.state.row = null; }],
    ['missing fixed binding', (f: ReturnType<typeof fixture>) => { f.state.binding = null; }],
    ['foreign cluster binding', (f: ReturnType<typeof fixture>) => { f.binding.cluster_id = randomUUID(); }],
    ['foreign workflow binding', (f: ReturnType<typeof fixture>) => { f.binding.workflow_id = randomUUID(); }],
    ['foreign migration binding', (f: ReturnType<typeof fixture>) => { f.binding.migration_plan_id = randomUUID(); }],
    ['foreign row actor', (f: ReturnType<typeof fixture>) => { f.row.actor_id = randomUUID(); }],
    ['foreign binding actor', (f: ReturnType<typeof fixture>) => { f.binding.actor_id = randomUUID(); }],
    ['foreign source binding', (f: ReturnType<typeof fixture>) => { f.binding.source_workspace_id = randomUUID(); }],
    ['foreign target binding', (f: ReturnType<typeof fixture>) => { f.binding.target_workspace_id = randomUUID(); }],
    ['foreign row target', (f: ReturnType<typeof fixture>) => { f.row.target_workspace_id = randomUUID(); }],
    ['changed original migration hash', (f: ReturnType<typeof fixture>) => { f.row.plan_hash = 'e'.repeat(64); }],
    ['changed binding migration hash', (f: ReturnType<typeof fixture>) => { f.binding.migration_plan_hash = 'e'.repeat(64); }],
    ['changed payload migration hash', (f: ReturnType<typeof fixture>) => { (f.plan.steps[0].mutationPayload as any).plan_hash = 'e'.repeat(64); }],
    ['changed binding material HMAC', (f: ReturnType<typeof fixture>) => { f.binding.material_hmac = 'e'.repeat(64); }],
    ['changed plan material HMAC', (f: ReturnType<typeof fixture>) => { f.plan.migration!.materialHmac = 'e'.repeat(64); }],
    ['shortened native material expiry', (f: ReturnType<typeof fixture>) => { f.row.expires_at = new Date(Date.now() - 1).toISOString(); }],
  ])('rejects %s before object disclosure or native work', async (_name, change) => {
    const f = fixture(); change(f);
    await rejectWith(f.verifier.assertSubject(f.plan, f.actor, 'write'), 403, 'MIGRATION_WORKFLOW_BINDING_INVALID');
    expect(f.authz.assertMigrationEntity).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each([
    ['changed material source', (f: ReturnType<typeof fixture>) => { f.material.source.id = randomUUID(); f.encryptMaterial(); }],
    ['changed material target', (f: ReturnType<typeof fixture>) => { f.material.target.id = randomUUID(); f.encryptMaterial(); }],
    ['changed material cluster', (f: ReturnType<typeof fixture>) => { f.material.target.cluster_id = randomUUID(); f.encryptMaterial(); }],
    ['changed captured secret', (f: ReturnType<typeof fixture>) => { f.material.nodes.find(node => node.type === 'key-auth')!.data.key = 'altered-key'; f.encryptMaterial(); }],
    ['changed confirmation name', (f: ReturnType<typeof fixture>) => { (f.plan.steps[0].mutationPayload as any).confirm_name = 'other-target'; }],
    ['changed target revision in wrapper', (f: ReturnType<typeof fixture>) => { f.plan.migration!.targetWorkspaceRevision = 2; }],
    ['different exact tags', (f: ReturnType<typeof fixture>) => { const r = f.plan.steps[0].nativeRequests[0]; r.body = { tags: ['other-team', 'kos-ws-target'] }; r.bodyHmac = f.secrets.fingerprint(r.body); }],
    ['different native before HMAC', (f: ReturnType<typeof fixture>) => { f.plan.steps[0].nativeRequests[0].beforeHmac = 'e'.repeat(64); }],
    ['removed native packet', (f: ReturnType<typeof fixture>) => { f.plan.steps[0].nativeRequests.pop(); }],
    ['reordered native packets', (f: ReturnType<typeof fixture>) => { f.plan.steps[0].nativeRequests.reverse(); }],
    ['removed shared reference', (f: ReturnType<typeof fixture>) => { f.plan.prerequisites.shift(); }],
    ['removed inherited Target proof', (f: ReturnType<typeof fixture>) => { f.plan.prerequisites.pop(); }],
    ['changed prerequisite before', (f: ReturnType<typeof fixture>) => { f.plan.prerequisites[0].before.key = 'altered-private-key'; f.plan.prerequisites[0].fingerprint = f.secrets.fingerprint(f.plan.prerequisites[0].before); }],
    ['material re-HMAC without original plan', (f: ReturnType<typeof fixture>) => {
      f.material.nodes[0].afterTags = ['other-team', 'kos-ws-target']; f.encryptMaterial();
      f.plan.migration!.materialHmac = f.binding.material_hmac = f.secrets.fingerprint(f.material);
      f.plan.steps[0].nativeRequests = migrationNativeRequests(f.material, f.secrets);
    }],
  ])('rejects %s independently of the fixed plan shape', async (_name, change) => {
    const f = fixture(); change(f);
    await rejectWith(f.verifier.assertSubject(f.plan, f.actor, 'write'), 403, 'MIGRATION_WORKFLOW_MATERIAL_INVALID');
    expect(f.authz.assertMigrationEntity).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('rejects a non-requester writer even with all synthetic workspace and entity grants', async () => {
    const f = fixture(); await rejectWith(f.verifier.assertSubject(f.plan, f.approver, 'write'), 403, 'MIGRATION_EXECUTOR_MISMATCH');
    expect(f.authz.assertWholeWorkspace).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['source', 'target'])('rejects an approver missing the %s workspace grant', async scope => {
    const f = fixture(), deniedWorkspace = scope === 'source' ? f.sourceId : f.targetId;
    f.authz.assertWholeWorkspace.mockImplementation(async (_actor: any, _cid: string, wid: string, module: string, action: string) => {
      if (wid === deniedWorkspace && module === 'workflows' && action === 'approve') throw new ForbiddenException({ code: 'ENTITY_SCOPE_DENIED' });
    });
    await rejectWith(f.verifier.assertSubject(f.plan, f.approver, 'approve'), 403, 'ENTITY_SCOPE_DENIED');
    expect(f.authz.assertMigrationEntity).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['source revision', 'target revision', 'source code', 'target code', 'source disabled', 'target disabled'])('rejects %s after approval', async reason => {
    const f = fixture(), current = reason.startsWith('source') ? f.currentSource : f.currentTarget;
    if (reason.endsWith('revision')) current.revision++;
    if (reason.endsWith('code')) current.code = 'renamed';
    if (reason.endsWith('disabled')) current.status = 'disabled';
    await rejectWith(f.verifier.assertSubject(f.plan, f.actor, 'write'), 409, 'MIGRATION_WORKSPACE_CHANGED');
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('allows authorized history reads after metadata revisions change, while retaining both object read checks', async () => {
    const f = fixture(); f.currentSource.revision++; f.currentTarget.revision++;
    await f.verifier.assertSubject(f.plan, f.actor, 'read');
    expect(f.authz.assertMigrationEntity).toHaveBeenCalledTimes(f.material.nodes.length * 2);
    expect(f.authz.assertMigrationEntity.mock.calls.every(call => call[3] === 'read')).toBe(true);
  });

  it.each(['source', 'target'])('rejects a writer missing exact %s entity scope despite coarse workspace grants', async scope => {
    const f = fixture(), deniedWorkspace = scope === 'source' ? f.sourceId : f.targetId;
    f.authz.assertMigrationEntity.mockImplementation(async (_actor: any, _cid: string, _type: string, action: string, _entity: any, wid: string) => {
      if (action === 'write' && wid === deniedWorkspace) throw new ForbiddenException({ code: 'ENTITY_SCOPE_DENIED' });
    });
    await rejectWith(f.verifier.assertSubject(f.plan, f.actor, 'write'), 403, 'ENTITY_SCOPE_DENIED');
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('rejects an approver missing shared dependency read authority', async () => {
    const f = fixture(); f.authz.assertEntity.mockRejectedValue(new ForbiddenException({ code: 'DEPENDENCY_READ_DENIED' }));
    await rejectWith(f.verifier.assertSubject(f.plan, f.approver, 'approve'), 403, 'DEPENDENCY_READ_DENIED');
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('rejects permission changes while awaiting graph authorization', async () => {
    const f = fixture(); f.authz.assertMigrationEntity.mockImplementation(async () => { f.state.epoch = 'epoch-2'; });
    await rejectWith(f.verifier.assertSubject(f.plan, f.actor, 'write'), 403, 'PERMISSIONS_CHANGED');
    expect(f.authz.permissionVersion).toHaveBeenCalledTimes(2); expect(f.kong.request).not.toHaveBeenCalled();
  });
});
