import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { DataSourcesService } from '../../apps/console-api/src/modules/data-sources/data-sources.service';

const clusterA = '39fd1f43-81e5-4ee9-915f-0e91c7c25f37';
const clusterB = '50cae558-3d9a-4f5b-92d1-e0b6d367d54d';
const sourceId = '76c3f54a-0c6b-46de-a317-b10513b0063e';
const source = { id: sourceId, cluster_id: clusterA, name: 'source-a', enabled: true, revision: 1 };
const actor = { user: { id: 'fresh-registry-user', username: 'unit', superAdmin: true }, requestId: 'registry-test' };

function fixture() {
  const db = {
    one: vi.fn(async (_sql: string, params: string[]) => params[0] === clusterA && params[1] === sourceId ? source : null),
    query: vi.fn().mockResolvedValue([]),
    exec: vi.fn(),
    transaction: vi.fn(),
  };
  const clusters = { get: vi.fn().mockResolvedValue({ id: clusterB }), validateId: vi.fn() };
  const secrets = { decrypt: vi.fn(), encrypt: vi.fn() };
  // Replace only the current DB authorization/metadata ledger dependencies.
  // The actual service must scope its own object lookup by cluster and ID.
  const authz = { assertCluster: vi.fn().mockResolvedValue(undefined), snapshot: vi.fn().mockResolvedValue({ user: actor.user, grants: [] }), isPlatformAdmin: vi.fn().mockResolvedValue(true), permissionVersion: vi.fn().mockResolvedValue('current-fixture-version') };
  const operations = { completed: vi.fn().mockResolvedValue(null), execute: vi.fn() };
  const service = new DataSourcesService(db as any, secrets as any, clusters as any, { append: vi.fn() } as any, authz as any, operations as any);
  return { db, clusters, secrets, authz, operations, service };
}

describe('M0 data source cross-cluster IDOR regression', () => {
  it('uses both the registered cluster and object ID for reads', async () => {
    const { service, db, authz } = fixture();
    expect(await service.get(clusterA, sourceId, actor)).toEqual(source);
    expect(authz.assertCluster).toHaveBeenCalledWith(actor.user, clusterA, 'data-sources', 'read');
    expect(db.one).toHaveBeenCalledWith(expect.stringContaining('WHERE cluster_id=$1 AND id=$2'), [clusterA, sourceId]);
  });

  it('does not expose a data source under a different registered cluster', async () => {
    const { service, db } = fixture();
    await expect(service.get(clusterB, sourceId, actor)).rejects.toMatchObject({ status: 404 });
    expect(db.one).toHaveBeenCalledWith(expect.stringContaining('WHERE cluster_id=$1 AND id=$2'), [clusterB, sourceId]);
  });

  it('rejects a foreign object update before persistence', async () => {
    const { service, db } = fixture();
    await expect(service.update(clusterB, sourceId, { revision: 1, name: 'stolen' }, actor)).rejects.toMatchObject({ status: 404 });
    expect(db.exec).not.toHaveBeenCalled();
    expect(db.transaction).not.toHaveBeenCalled();
  });

  it('rejects a foreign object connection test before loading its secrets', async () => {
    const { service, db, secrets } = fixture();
    await expect(service.probe(clusterB, sourceId, actor)).rejects.toMatchObject({ status: 404 });
    expect(secrets.decrypt).not.toHaveBeenCalled();
    expect(db.one).toHaveBeenCalledTimes(1);
    expect(db.exec).not.toHaveBeenCalled();
  });

  it('rejects a foreign object deactivation even with a valid-looking confirmation', async () => {
    const { service, db } = fixture();
    await expect(service.deactivate(clusterB, sourceId, { revision: 1, confirm: true, confirm_name: source.name }, actor)).rejects.toMatchObject({ status: 404 });
    expect(db.transaction).not.toHaveBeenCalled();
  });

  it('filters data source lists at the backend by cluster', async () => {
    const { service, db, authz } = fixture();
    await service.list(clusterB, actor);
    expect(authz.assertCluster).toHaveBeenCalledWith(actor.user, clusterB, 'data-sources', 'read');
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('WHERE cluster_id=$1'), [clusterB]);
  });

  it('does not query source objects for a missing or disabled cluster', async () => {
    const { service, db, authz } = fixture();
    authz.assertCluster.mockRejectedValue({ status: 403 });
    await expect(service.get(clusterB, sourceId, actor)).rejects.toMatchObject({ status: 403 });
    expect(db.one).not.toHaveBeenCalled();
  });

  it('requires current authorization before querying a known foreign data-source ID', async () => {
    const { service, db, authz, operations } = fixture();
    authz.assertCluster.mockRejectedValue({ status: 403 });
    await expect(service.update(clusterB, sourceId, { revision: 1, name: 'stolen' }, actor)).rejects.toMatchObject({ status: 403 });
    expect(db.one).not.toHaveBeenCalled();
    expect(operations.execute).not.toHaveBeenCalled();
  });

  it('does not permit workspace-limited grants to modify shared cluster data sources', async () => {
    const { service, db, authz } = fixture();
    authz.snapshot.mockResolvedValue({ user: { ...actor.user, superAdmin: false }, grants: [{ module: 'data-sources', action: 'write', scope_type: 'global', cluster_id: clusterA, workspace_id: 'pay' }] });
    await expect(service.update(clusterA, sourceId, { revision: 1, name: 'stolen' }, actor)).rejects.toMatchObject({ status: 403 });
    expect(db.one).not.toHaveBeenCalled();
  });

  it('removes connection metadata from an ordinary cluster-wide authorized response', async () => {
    const { service, db, authz } = fixture();
    authz.snapshot.mockResolvedValue({ user: { ...actor.user, superAdmin: false }, grants: [{ module: 'data-sources', action: 'read', scope_type: 'global', cluster_id: clusterA, workspace_id: null }] });
    authz.isPlatformAdmin.mockResolvedValue(false);
    db.one.mockResolvedValue({ ...source, base_url: 'http://private-provider:9090', auth_configured: true });
    expect(await service.get(clusterA, sourceId, actor)).toEqual(source);
  });

  it('blocks a completed SQL read when current permission revision changes during the await', async () => {
    const { service, authz } = fixture();
    authz.permissionVersion.mockResolvedValueOnce('old-version').mockResolvedValueOnce('revoked-version');
    await expect(service.get(clusterA, sourceId, actor)).rejects.toMatchObject({ status: 403, response: { code: 'PERMISSIONS_CHANGED' } });
  });
});
