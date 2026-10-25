import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';
import { opsWorkspaceId, payWorkspaceId, workspaceFixture } from '../unit/workspace-test-fixture';

const cid = 'a0c05a03-0e83-4e6f-9a5f-c4136287c4b4';
const otherCid = '556996a5-2027-4e40-a415-dcb4de5171fd';
const uid = '023bf70d-0d08-49c4-96bc-57a8e232e353';
const bobId = '21a2d3c3-7f3b-453e-8b51-eab4524f8f7c';
const sid = '24115d53-b412-44a9-8404-06bb1f6c4a48';
const serviceId = 'bb0cde73-87d5-47ef-8a58-b4bbf843af94';
const anotherId = '341401f9-bd2f-4364-8434-f94e65e0c2e9';
const pay = encodeTag('team:pay'), ops = encodeTag('team:ops');
const actor = { id: uid, username: 'monitoring-only', superAdmin: false };
const resource = (extra: Record<string, unknown> = {}) => ({ id: serviceId, name: 'resource', tags: ['kos-ws-pay', pay], ...extra });
const grant = (scope: EffectiveGrant['scope_type'] = 'workspace', values: EffectiveGrant['scope_values'] = [payWorkspaceId],
  wid: string | null = payWorkspaceId, extra: Partial<EffectiveGrant> = {}): EffectiveGrant =>
  ({ module: 'monitoring', action: 'read', scope_type: scope, scope_values: values, cluster_id: cid, workspace_id: wid, ...extra });

// Actual authorization/grant policy, workspace resolver and private context.
// Current IAM rows and raw Kong objects alone are deterministic fixtures;
// no AuthorizationService policy method is stubbed in this suite.
function fixture(initial: EffectiveGrant[] = [grant()]) {
  let epoch = 1, sessionActive = true;
  const user = { id: uid, username: actor.username, status: 'active', deleted_at: null,
    super_admin: false, permissions_epoch: 1, credential_epoch: 1 };
  const bob = { ...user, id: bobId, username: 'second-monitor' };
  const currentGrants = new Map<string, EffectiveGrant[]>([[uid, initial]]);
  const workspace = workspaceFixture(cid), execution = new KongExecutionContextService();
  const remote = new Map<string, unknown>();
  const db: any = {
    one: vi.fn(async (sql: string, params: any[] = []) => {
      if (sql.includes('FROM users')) { const row = params[0] === uid ? user : params[0] === bobId ? bob : null; return row?.status === 'active' ? row : null; }
      if (sql.includes('FROM auth_sessions')) return sessionActive ? { id: sid } : null;
      if (sql.includes('FROM iam_epoch')) return { version: epoch };
      if (sql.includes('FROM clusters')) return [cid, otherCid].includes(params[0]) ? { id: params[0] } : null;
      throw new Error('unexpected authorization fixture SQL');
    }),
    query: vi.fn(async (sql: string, params: any[] = []) => {
      if (sql.includes('iam_effective_grants')) return structuredClone(currentGrants.get(params[0]) ?? []);
      throw new Error('unexpected authorization fixture query');
    }),
  };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => {
    expect(method).toBe('GET'); const value = remote.get(path); if (!value) throw new NotFoundException(); return structuredClone(value);
  }) };
  const authz = new AuthorizationService(db, workspace.resolver, kong, execution);
  const run = <T>(fn: () => Promise<T>, acting = actor, wid = payWorkspaceId): Promise<T> => execution.runHttp({}, async () => {
    execution.bindHttpActor(acting, sid); const close = execution.captureHttpCloser();
    try { return await execution.runActor({ actor: acting, clusterId: cid, workspaceId: wid, module: 'monitoring', action: 'read' }, fn); }
    finally { close(); }
  });
  return { authz, execution, workspace, user, bob, db, kong, run,
    replaceGrants: (rows: EffectiveGrant[], id = uid) => { currentGrants.set(id, rows); epoch++; },
    revokeSession: () => { sessionActive = false; } };
}

describe('M5 independent resource-scoped monitoring authorization', () => {
  it.each(['services', 'routes', 'consumers'])('allows monitoring-only %s scope without granting native or data-source configuration read', async type => {
    const f = fixture(), actual = resource();
    await f.run(async () => {
      await f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', type, actual, payWorkspaceId);
      await expect(f.authz.assertEntity(actor, cid, type, 'read', actual, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertCluster(actor, cid, 'data-sources', 'read')).rejects.toMatchObject({ status: 403 });
    });
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('cannot assemble a monitoring read from another module or action row', async () => {
    const f = fixture([
      grant('entity', [{ entity_type: 'services', entity_id: anotherId }]),
      grant('global', [], null, { action: 'write' }),
      grant('tag_group', [pay], payWorkspaceId, { module: 'services' }),
    ]);
    await expect(f.run(() => f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId)))
      .rejects.toMatchObject({ status: 403 });
  });

  it('keeps tag-group OR inside the workspace AND ceiling', async () => {
    const f = fixture([grant('tag_group', [pay, ops])]);
    await f.run(async () => {
      for (const tag of [pay, ops]) await f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource({ tags: ['kos-ws-pay', tag] }), payWorkspaceId);
      await expect(f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource({ tags: ['kos-ws-pay', encodeTag('team:other')] }), payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource({ tags: ['kos-ws-ops', pay] }), opsWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });

  it('retains cluster and workspace ceilings even for a scoped global grant', async () => {
    const f = fixture([grant('global', [])]);
    await f.run(async () => {
      await f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId);
      await expect(f.authz.assertScopedResource(actor, otherCid, 'monitoring', 'read', 'services', resource(), payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource({ tags: ['kos-ws-ops', pay] }), opsWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });

  it('requires the exact native type as well as the whitelisted UUID', async () => {
    const f = fixture([grant('entity', [{ entity_type: 'services', entity_id: serviceId }])]);
    await f.run(async () => {
      await f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId);
      await expect(f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'routes', resource(), payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource({ id: anotherId }), payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });

  it('does not reuse native Service-write inheritance or monitoring Service IDs for another resource type', async () => {
    const f = fixture([grant('entity', [{ entity_type: 'services', entity_id: serviceId }], payWorkspaceId, { module: 'services', action: 'write' })]);
    await expect(f.run(() => f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId))).rejects.toMatchObject({ status: 403 });
    f.replaceGrants([grant('entity', [{ entity_type: 'services', entity_id: serviceId }])]);
    await expect(f.run(() => f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'routes', resource({ service: { id: serviceId } }), payWorkspaceId))).rejects.toMatchObject({ status: 403 });
  });

  it('keeps disabled workspaces readable under the existing resolver contract', async () => {
    const f = fixture(); f.workspace.rows[1].status = 'disabled';
    await f.run(() => f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId));
  });

  it.each([['invalid-id', resource({ id: 'not-a-uuid' })], ['multiple-workspaces', resource({ tags: ['kos-ws-pay', 'kos-ws-ops'] })],
    ['unknown-workspace', resource({ tags: ['kos-ws-unknown'] })]])
    ('rejects %s even when the current DB user is platform admin', async (_name, actual) => {
      const f = fixture([]); f.user.super_admin = true;
      await expect(f.run(() => f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', actual, payWorkspaceId))).rejects.toMatchObject({ status: 403 });
    });

  it('filters each actual object using its own tags and typed identity', async () => {
    const f = fixture([grant('tag_group', [pay]), grant('entity', [{ entity_type: 'services', entity_id: anotherId }])]);
    const first = resource(), whitelisted = resource({ id: anotherId, tags: ['kos-ws-pay', ops] }), denied = resource({ id: '7f2b03e2-f2b1-4416-b26b-1c2ff8e55a2a', tags: ['kos-ws-pay', ops] });
    const result = await f.run(() => f.authz.filterScopedResources(actor, cid, 'monitoring', 'read', 'services', [first, whitelisted, denied], payWorkspaceId));
    expect(result.map(item => item.id)).toEqual([serviceId, anotherId]);
  });

  it('rechecks grants, DB platform status and sessions rather than caller flags', async () => {
    const f = fixture();
    await f.run(async () => {
      await f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId);
      f.replaceGrants([]);
      await expect(f.authz.assertScopedResource({ ...actor, superAdmin: true }, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      f.replaceGrants([grant()]); f.revokeSession();
      await expect(f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId)).rejects.toMatchObject({ status: 401 });
    });
  });

  it('does not expose cluster-wide node gauges through workspace/tag/entity grants', async () => {
    const f = fixture();
    await f.run(async () => {
      for (const row of [grant(), grant('tag_group', [pay]), grant('entity', [{ entity_type: 'services', entity_id: serviceId }]), grant('global', []),
        grant('global', [], null, { module: 'services' })]) {
        f.replaceGrants([row]); expect(await f.authz.hasWholeCluster(actor, cid, 'monitoring', 'read')).toBe(false);
      }
      f.replaceGrants([grant('global', [], null)]);
      expect(await f.authz.hasWholeCluster(actor, cid, 'monitoring', 'read')).toBe(true);
      await f.authz.assertWholeCluster(actor, cid, 'monitoring', 'read');
      expect(await f.authz.hasWholeCluster(actor, otherCid, 'monitoring', 'read')).toBe(false);
    });
  });

  it('isolates two current actors and workspace scopes across concurrent awaits', async () => {
    const f = fixture(); const bob = { id: bobId, username: 'second-monitor', superAdmin: false };
    f.replaceGrants([grant('workspace', [opsWorkspaceId], opsWorkspaceId)], bobId);
    const first = f.run(async () => { await Promise.resolve(); await f.authz.assertScopedResource(actor, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId); return f.execution.current().actor?.id; });
    const second = f.run(async () => {
      await Promise.resolve();
      await f.authz.assertScopedResource(bob, cid, 'monitoring', 'read', 'services', resource({ tags: ['kos-ws-ops', ops] }), opsWorkspaceId);
      await expect(f.authz.assertScopedResource(bob, cid, 'monitoring', 'read', 'services', resource(), payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      return f.execution.current().actor?.id;
    }, bob, opsWorkspaceId);
    expect(await Promise.all([first, second])).toEqual([uid, bobId]); expect(f.execution.peek()).toBeNull();
  });
});
