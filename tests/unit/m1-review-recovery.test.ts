import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { NotFoundException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RecycleService, graphOrder } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import type { GraphNode, RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { defaultWorkspaceId,workspaceFixture } from './workspace-test-fixture';

const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const entryId = '4b25f0dd-f78e-4f54-b58c-9fdd0687a5c4';
const actor = { id: 'a35313a2-9968-4818-9f31-7b3066ce1728', username: 'admin', superAdmin: true };

function node(type: string, id: string, data: any, dependencies: string[] = [], affected = true): GraphNode {
  return { key: `${type}:${id}`, type, id, path: `/${type}/${id}`, data, restoreData: structuredClone(data), dependencies, affected, restorable: true };
}

function harness(graph: RecycleGraph, objects: Record<string, any>) {
  const secrets = new SecretService();
  const root = graph.nodes.find(item => item.key === graph.rootKey)!;
  const entry = { id: entryId, cluster_id: cid,workspace_id:defaultWorkspaceId, root_type: root.type, original_id: root.id, root_name: root.data.name ?? root.id,
    state: 'partially_restored', payload_secret: secrets.encrypt(graph, `recycle:${entryId}`), parent_id: null, credential_kind: null };
  const db = { one: vi.fn(async (sql: string) => sql.includes('FROM configuration_recycle_components') ? null : sql.includes('FROM recycle_entries') ? entry : { restore_state: 'restored', delete_state: 'deleted', restored_id: root.id }),
    exec: vi.fn().mockResolvedValue(1), query: vi.fn().mockResolvedValue([]), transaction: vi.fn() };
  db.transaction.mockImplementation(async fn => fn(db));
  const kong = { request: vi.fn(async (_cid: string, method: string, path: string, body: any) => {
    if (method === 'GET') { if (!(path in objects)) throw new NotFoundException(); return structuredClone(objects[path]); }
    if (method === 'POST') { objects[`${path}/${body.id}`] = structuredClone(body); return structuredClone(body); }
    throw new Error('Unexpected destructive operation during restore');
  }), list: vi.fn() };
  const mutations = { claimGraphImpact:vi.fn(),execute: vi.fn(async (_context, fn) => fn()) };
  const authz = { isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true),assertCluster: vi.fn().mockResolvedValue(undefined), assertEntity: vi.fn().mockResolvedValue(undefined) };
  (authz as any).assertArchivedEntity=authz.assertEntity;
  const audit = { append: vi.fn().mockResolvedValue(undefined) };
  const credentials = { save: vi.fn().mockResolvedValue(undefined) };
  const index = { upsert: vi.fn().mockResolvedValue(undefined), remove: vi.fn().mockResolvedValue(undefined) };
  const service = new RecycleService(db as any, secrets, kong as any, mutations as any, {} as any, authz as any, audit as any, credentials as any, index as any,workspaceFixture(cid).resolver,executionFixture());
  return { service, db, kong, audit, index };
}

describe('Independent M1 recovery review regressions', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ac'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());

  it('continues a certificate restore after a previous SNI step was interrupted', async () => {
    const cert = node('certificates', 'cert', { id: 'cert', cert: 'public-pem', key: 'private-pem', snis: ['one.example', 'two.example'] });
    delete cert.restoreData.snis;
    const sni1 = node('snis', 'sni1', { id: 'sni1', name: 'one.example', certificate: { id: 'cert' } }, [cert.key]);
    const sni2 = node('snis', 'sni2', { id: 'sni2', name: 'two.example', certificate: { id: 'cert' } }, [cert.key]);
    const graph: RecycleGraph = { rootKey: cert.key, nodes: [cert, sni1, sni2], complete: true, capturedAt: new Date().toISOString() };
    const { service, kong } = harness(graph, {
      '/certificates/cert': { id: 'cert', cert: 'public-pem', key: 'private-pem', snis: ['one.example'] },
      '/snis/sni1': sni1.data,
    });
    const result = await service.restore(cid, entryId, actor, { confirmed: true, confirm_name: 'cert' });
    expect(result.state).toBe('restored');
    expect(kong.request).toHaveBeenCalledWith(cid, 'POST', '/snis', sni2.restoreData);
    expect(kong.request.mock.calls.filter(call => call[1] === 'POST').map(call => call[2])).toEqual(['/snis']);
  });

  it('detects a conflicting user config.ttl instead of dropping it as entity metadata', async () => {
    const plugin = node('plugins', 'plugin', { id: 'plugin', name: 'custom-installed-plugin', config: { nested: { ttl: 'original', updated_at: 'original' } } });
    const graph: RecycleGraph = { rootKey: plugin.key, nodes: [plugin], complete: true, capturedAt: new Date().toISOString() };
    const { service, kong } = harness(graph, {
      '/plugins/plugin': { ...plugin.data, config: { nested: { ttl: 'changed', updated_at: 'changed' } } },
    });
    await expect(service.restore(cid, entryId, actor, { confirmed: true, confirm_name: plugin.data.name })).rejects.toMatchObject({
      response: { code: 'RECYCLE_RESTORE_INCOMPLETE', cause: 'RESTORE_ID_CONFLICT' },
    });
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it('orders Consumer before its bound Plugin even when archive iteration order puts the Plugin first', () => {
    const consumer = node('consumers', 'consumer', { id: 'consumer', username: 'alice' });
    const plugin = node('plugins', 'plugin', { id: 'plugin', name: 'acl', consumer: { id: 'consumer' } }, [consumer.key]);
    const credential = node('key-auth', 'credential', { id: 'credential', consumer: { id: 'consumer' }, key: 'test-key' }, [consumer.key]);
    const graph: RecycleGraph = { rootKey: consumer.key, nodes: [plugin, credential, consumer], complete: true, capturedAt: new Date().toISOString() };
    const order = graphOrder(graph).map(item => item.key);
    expect(order.indexOf(consumer.key)).toBeLessThan(order.indexOf(plugin.key));
    expect(order.indexOf(consumer.key)).toBeLessThan(order.indexOf(credential.key));
  });

  it('never writes a shared parent during a child restore and rechecks current parent read permissions', async () => {
    const service = node('services', 'service', { id: 'service', name: 'parent', host: 'old.example' }, [], false);
    const route = node('routes', 'route', { id: 'route', name: 'child', paths: ['/child'], service: { id: 'service' } }, [service.key]);
    const graph: RecycleGraph = { rootKey: route.key, nodes: [route, service], complete: true, capturedAt: new Date().toISOString() };
    const { service: recycler, kong } = harness(graph, { '/services/service': { ...service.data, host: 'new.example' } });
    await expect(recycler.restore(cid, entryId, actor, { confirmed: true, confirm_name: 'child' })).resolves.toMatchObject({ state: 'restored' });
    expect(kong.request.mock.calls.filter(call => call[1] === 'POST').map(call => call[2])).toEqual(['/routes']);
  });
});
