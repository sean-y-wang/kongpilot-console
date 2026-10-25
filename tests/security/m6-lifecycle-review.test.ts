import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalAuthBoundaryService } from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';
import { PortalAdminService } from '../../apps/console-api/src/modules/portal/portal-admin.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'bc'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

// SQL rows and transport are fixtures. The actual final-send service decides
// ownership/risk; this suite does not claim PostgreSQL release-proof validation.
function historyFixture(released = true) {
  const cid = randomUUID(), wid = randomUUID(), alias = randomUUID(), consumer = randomUUID(), acl = randomUUID(), key = randomUUID(), other = randomUUID();
  const physical = 'a'.repeat(64), grant = { id: randomUUID(), cluster_id: cid, workspace_id: wid, consumer_id: consumer, acl_id: acl,
    state: 'disabled', reservation_released_at: released ? new Date().toISOString() : null };
  const db: any = { query: vi.fn(async (sql: string, params: unknown[]) => {
    expect(params).toEqual([physical]);
    if (sql.includes('FROM portal_publications')) return [];
    if (sql.includes('FROM portal_credentials')) return [{ kong_id: key, state: 'pending', grant_id: grant.id }];
    return [grant];
  }) };
  const kong: any = { list: vi.fn(), request: vi.fn() }, context: any = { runPortalBoundaryRead: vi.fn(async () => { throw new ForbiddenException({ code: 'PRIVATE_CAPTURE_REQUIRED' }); }) };
  const approved: any = { assertNativeWrite: vi.fn(async () => { throw new ForbiddenException({ code: 'APPROVED_STEP_REQUIRED' }); }) };
  const service = new PortalAuthBoundaryService(db, new SecretService(), kong, context, {} as any, approved);
  const packet = (method: string, path: string, body?: any, extra: any = {}) => ({ clusterId: alias, workspaceId: wid, transportScope: physical,
    operationId: randomUUID(), method, canonicalPath: path, mutationAction: method === 'DELETE' ? 'delete' : 'restore', body, ...extra });
  return { service, packet, consumer, acl, key, other, grant, db, kong, context, approved };
}

describe('M6 independent released-reservation history boundary', () => {
  it('removes only released authentication risk while retaining physical alias ownership', async () => {
    const f = historyFixture();
    await f.service.assertBeforeNativeSend(f.packet('PATCH', `/services/${randomUUID()}`, { name: 'unrelated-change' }), {} as any);
    expect(f.context.runPortalBoundaryRead).not.toHaveBeenCalled();
    await expect(f.service.assertBeforeNativeSend(f.packet('POST', '/consumers', { id: f.consumer }), {} as any))
      .rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    expect(f.approved.assertNativeWrite).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'])('still denies new %s children under a released historical Consumer', async kind => {
    const f = historyFixture();
    await expect(f.service.assertBeforeNativeSend(f.packet('POST', `/consumers/${f.consumer}/${kind}`, { id: randomUUID() }, { parentId: f.consumer }), {} as any))
      .rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    expect(f.context.runPortalBoundaryRead).not.toHaveBeenCalled();
  });
  it.each(['key-auth', 'acls'])('denies reuse of a released historical %s UUID under an unrelated Consumer', async kind => {
    const f = historyFixture(), id = kind === 'acls' ? f.acl : f.key;
    await expect(f.service.assertBeforeNativeSend(f.packet('POST', `/consumers/${f.other}/${kind}`, { id }, { parentId: f.other }), {} as any))
      .rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('does not mistake a merely disabled grant for safe release', async () => {
    const f = historyFixture(false);
    await expect(f.service.assertBeforeNativeSend(f.packet('PATCH', `/services/${randomUUID()}`, { name: 'unrelated-change' }), {} as any))
      .rejects.toMatchObject({ response: { code: 'PRIVATE_CAPTURE_REQUIRED' } });
    expect(f.context.runPortalBoundaryRead).toHaveBeenCalledOnce();
  });
});

// Actual PortalAdmin and canonical plan validator, explicit metadata SQL and
// gateway fixtures. No native mutation, HTTP, or SQL constraint proof is mocked
// as success: the plan is kept pending in approval mode.
function withdrawalFixture() {
  const cid = randomUUID(), wid = randomUUID(), serviceId = randomUUID(), id = randomUUID(), userId = randomUUID(), secrets = new SecretService();
  const publication: any = { id, cluster_id: cid, workspace_id: wid, name: 'published API', service_id: serviceId, transport_scope: 'a'.repeat(64), revision: 4,
    current_revision: 1, published_revision: 1, state: 'published', acl_group: `kos-portal-api-${id}`, acl_plugin_id: randomUUID(), key_auth_plugin_id: randomUUID() };
  const grant: any = { id: randomUUID(), state: 'disabled', reservation_released_at: new Date().toISOString() };
  const actor: any = { user: { id: userId, superAdmin: false }, workspaceId: wid, idempotencyKey: 'withdrawal-original-key' };
  const scope = { transportScope: publication.transport_scope, clusterRevision: 1, workspaceRevision: 1, executionMode: 'approval' };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM workflows')) return null;
    if (sql.includes('FROM portal_application_grants')) return grant.state === 'revoked' || sql.includes('reservation_released_at IS NULL') && grant.reservation_released_at !== null ? null : grant;
    if (sql.includes('FROM portal_publications')) return structuredClone(publication);
    return null;
  }), exec: vi.fn(async (sql: string, params: any[]) => {
    if (sql.startsWith('UPDATE portal_publications')) { publication.state = params[1]; publication.workflow_id = params[2]; publication.revision++; }
    return 1;
  }), transaction: vi.fn(async (fn: any) => fn(db)) };
  const authz: any = { assertCluster: vi.fn(), assertWholeWorkspace: vi.fn() }, workspaces: any = { resolve: vi.fn(async () => ({ id: wid, revision: 1 })) };
  const nativeFactory = new PortalNativeService(db, secrets, {} as any, {} as any, authz, workspaces);
  const native: any = { actor: vi.fn(async (_cid: string, _actor: any, _module: string, _action: string, fn: any) => fn()), scope: vi.fn(async () => scope),
    service: vi.fn(async () => ({ id: serviceId, tags: ['kos-ws-pay'] })), collection: vi.fn(), nativeStep: vi.fn(), metadataStep: nativeFactory.metadataStep.bind(nativeFactory) };
  let plan: any;
  const plans: any = { definition: vi.fn(async () => ({ id: randomUUID(), version: 1, policyHash: 'b'.repeat(64) })), persist: vi.fn(async (value: any) => {
    validateWorkflowPlan(value); plan = value; return { id: value.workflowId, kind: value.kind, state: 'pending', plan_revision: 1, plan_hash: secrets.fingerprint(value),
      revision: 1, execution_mode: 'approval', approval_required: true, created_at: new Date().toISOString(), expires_at: value.expiresAt };
  }) };
  const workflows: any = { execute: vi.fn() }, approved: any = { assertSubject: vi.fn() }, iam: any = { execute: vi.fn() };
  const admin = new PortalAdminService(db, secrets, authz, { append: vi.fn() } as any, iam, {} as any, workspaces, approved, plans,
    new WorkflowRegistryService(), workflows, native, {} as any);
  return { admin, cid, id, actor, publication, grant, db, plans, native, workflows, getPlan: () => plan,
    body: { revision: publication.revision, confirmed: true, confirm_name: publication.name } };
}

describe('M6 independent publication withdrawal lifecycle', () => {
  it('can review withdrawal with an already SQL-released cancelled reservation without native packets', async () => {
    const f = withdrawalFixture();
    const result = await f.admin.publish(f.cid, f.id, f.body, f.actor, false);
    expect(result.entity.approvalRequired).toBe(true); expect(f.getPlan().steps).toHaveLength(1);
    expect(f.getPlan().steps[0]).toMatchObject({ kind: 'metadata', handler: 'portal.publication.unpublish', nativeRequests: [] });
    expect(f.native.collection).not.toHaveBeenCalled(); expect(f.native.nativeStep).not.toHaveBeenCalled(); expect(f.workflows.execute).not.toHaveBeenCalled();
  });
  it.each(['active', 'partial', 'uncertain', 'disabled'])('never treats unreleased %s history as safe withdrawal', async state => {
    const f = withdrawalFixture(); f.grant.state = state; f.grant.reservation_released_at = null;
    await expect(f.admin.publish(f.cid, f.id, f.body, f.actor, false)).rejects.toMatchObject({ response: { code: 'PORTAL_ACTIVE_GRANTS_REQUIRE_REVOCATION' } });
    expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.workflows.execute).not.toHaveBeenCalled();
  });
});
