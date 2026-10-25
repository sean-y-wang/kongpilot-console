import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { GraphCapturerService, RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';

const clusterId = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const kinds = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];

function harness(objects: Record<string, any>, collections: Record<string, any[]> = {}) {
  const kong = {
    request: vi.fn(async (cluster: string, method: string, path: string) => {
      expect(cluster).toBe(clusterId);
      expect(method).toBe('GET');
      if (!(path in objects)) {
        if (path.startsWith('/upstreams/')) throw new NotFoundException();
        throw new Error(`Unexpected read: ${path}`);
      }
      return structuredClone(objects[path]);
    }),
    list: vi.fn(async (cluster: string, path: string, query: any, cursor?: string) => {
      expect(cluster).toBe(clusterId);
      expect(query).toEqual({ size: 100 });
      if (!(path in collections)) {
        if(path==='/services')return{items:[],size:100,nextCursor:null};
        throw new Error(`Unexpected collection: ${path}`);
      }
      const start = cursor ? Number(cursor) : 0;
      const items = collections[path].slice(start, start + 100);
      return { items: structuredClone(items), size: 100, nextCursor: start + 100 < collections[path].length ? String(start + 100) : null };
    }),
  };
  const credentials = {
    getRestorePayload: vi.fn(async (_cluster: string, _consumer: string, kind: string, _id: string, remote: any) => {
      if (kind === 'basic-auth') return { ...remote, password: 'encrypted-store-original-password' };
      return remote;
    }),
  };
  return { kong, credentials, capturer: new GraphCapturerService(kong as any, credentials as any,executionFixture()) };
}

function find(graph: RecycleGraph, type: string, id: string) {
  const node = graph.nodes.find(item => item.type === type && item.id === id);
  expect(node, `${type}/${id} was captured`).toBeDefined();
  return node!;
}

describe('Recycle graph: native cascades and shared references', () => {
  it('captures a service, routes and both plugin scopes once; shared consumers and certificates remain references', async () => {
    const service = { id: 'svc', name: 'checkout', host: 'upstream', client_certificate: { id: 'cert' }, created_at: 10, updated_at: 20 };
    const route = { id: 'route', name: 'checkout-route', service: { id: 'svc' }, created_at: 11 };
    const otherRoute = { id: 'other-route', service: { id: 'other-service' } };
    const servicePlugin = { id: 'plugin-service', name: 'cors', service: { id: 'svc' }, route: null, consumer: null, config: { created_at: 'user-config-field' }, created_at: 12 };
    const routePlugin = { id: 'plugin-route', name: 'key-auth', service: null, route: { id: 'route' }, consumer: { id: 'consumer' }, config: {} };
    const unrelated = { id: 'plugin-other', name: 'cors', service: null, route: { id: 'other-route' }, consumer: null };
    const { kong, capturer } = harness({
      '/services/checkout': service,
      '/certificates/cert': { id: 'cert', cert: 'PUBLIC-CERT', key: 'PRIVATE-KEY' },
      '/consumers/consumer': { id: 'consumer', username: 'shared-user' },
      '/routes/other-route': otherRoute,
    }, { '/services/svc/routes': [route], '/plugins': [servicePlugin, routePlugin, unrelated] });
    const graph = await capturer.capture(clusterId, 'services', 'checkout');

    expect(graph).toMatchObject({ rootKey: 'services:svc', complete: true });
    expect(graph.nodes).toHaveLength(6);
    expect(graph.nodes.filter(node => node.affected).map(node => node.id).sort()).toEqual(['plugin-route', 'plugin-service', 'route', 'svc']);
    expect(find(graph, 'services', 'svc')).toMatchObject({ path: '/services/svc', dependencies: ['certificates:cert'], restoreData: { id: 'svc', name: 'checkout', host: 'upstream' } });
    expect(find(graph, 'services', 'svc').restoreData).not.toHaveProperty('created_at');
    expect(find(graph, 'services', 'svc').restoreData).not.toHaveProperty('updated_at');
    expect(find(graph, 'plugins', 'plugin-service').restoreData.config.created_at).toBe('user-config-field');
    expect(find(graph, 'routes', 'route').dependencies).toEqual(['services:svc']);
    expect(find(graph, 'plugins', 'plugin-route').dependencies).toEqual(['routes:route', 'consumers:consumer']);
    expect(find(graph, 'certificates', 'cert')).toMatchObject({ affected: false, restorable: true });
    expect(find(graph, 'certificates', 'cert').restoreData).toBeUndefined();
    expect(find(graph, 'consumers', 'consumer').affected).toBe(false);
    expect(kong.list.mock.calls.map(call => call[1])).toEqual(['/services/svc/routes', '/plugins']);
    expect(kong.request.mock.calls.map(call => call[2])).not.toContain('/routes/other-route');
  });

  it('captures only a route cascade, while fetching its service and certificate ancestors without their children', async () => {
    const { kong, capturer } = harness({
      '/routes/route': { id: 'route', service: { id: 'service' } },
      '/services/service': { id: 'service', client_certificate: { id: 'certificate' } },
      '/certificates/certificate': { id: 'certificate', cert: 'cert', key: 'key' },
    }, { '/plugins': [{ id: 'plugin', name: 'cors', route: { id: 'route' }, service: null, consumer: null }] });
    const graph = await capturer.capture(clusterId, 'routes', 'route');
    expect(graph.nodes.filter(node => node.affected).map(node => node.id)).toEqual(['route', 'plugin']);
    expect(find(graph, 'services', 'service').dependencies).toEqual(['certificates:certificate']);
    expect(kong.list).toHaveBeenCalledTimes(1);
  });

  it('captures certificate SNIs and records certificate-before-SNI dependencies', async () => {
    const { capturer, kong } = harness({ '/certificates/cert': { id: 'cert', cert: 'pem', key: 'secret', snis: ['one.example.com', 'two.example.com'] } }, {
      '/certificates/cert/snis': [
        { id: 'sni1', name: 'one.example.com', certificate: { id: 'cert' }, created_at: 10 },
        { id: 'sni2', name: 'two.example.com', certificate: { id: 'cert' } },
      ],
    });
    const graph = await capturer.capture(clusterId, 'certificates', 'cert');
    expect(graph.nodes).toHaveLength(3);
    expect(graph.nodes.every(node => node.affected)).toBe(true);
    expect(find(graph, 'snis', 'sni1').dependencies).toEqual(['certificates:cert']);
    expect(find(graph, 'snis', 'sni1').restoreData).not.toHaveProperty('created_at');
    expect(find(graph, 'certificates', 'cert').data.snis).toEqual(['one.example.com', 'two.example.com']);
    expect(find(graph, 'certificates', 'cert').restoreData).not.toHaveProperty('snis');
    expect(kong.request).toHaveBeenCalledTimes(1);
  });

  it('refuses in-use client certificates before touching any SNI mutation',async()=>{
    const {capturer,kong}=harness({'/certificates/cert':{id:'cert',cert:'public',key:'private'}},{
      '/services':[{id:'service',client_certificate:{id:'cert'}}],'/certificates/cert/snis':[{id:'sni',name:'live.example',certificate:{id:'cert'}}],
    });
    await expect(capturer.capture(clusterId,'certificates','cert')).rejects.toMatchObject({status:409,response:{code:'CERTIFICATE_IN_USE'}});
    expect(kong.list.mock.calls.map(call=>call[1])).toEqual(['/services']);
    expect(kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);
  });

  it('captures a real host-to-Upstream shared reference while allowing ordinary DNS names',async()=>{
    const {capturer}=harness({'/services/service':{id:'service',host:'gateway-pool'},'/upstreams/gateway-pool':{id:'upstream',name:'gateway-pool'}},
      {'/services/service/routes':[],'/plugins':[]});
    const graph=await capturer.capture(clusterId,'services','service');
    expect(find(graph,'services','service').dependencies).toEqual(['upstreams:upstream']);
    expect(find(graph,'upstreams','upstream').affected).toBe(false);
    const dns=harness({'/services/service':{id:'service',host:'api.internal'}},{'/services/service/routes':[],'/plugins':[]});
    expect((await dns.capturer.capture(clusterId,'services','service')).nodes).toHaveLength(1);
  });

  it.each(['plugins', 'ca_certificates', 'snis'])('captures a %s root without invoking unrelated cascades', async type => {
    const data: any = { id: 'root' };
    if (type === 'snis') data.certificate = { id: 'certificate' };
    const { capturer, kong } = harness({ [`/${type}/root`]: data, '/certificates/certificate': { id: 'certificate', cert: 'pem' } });
    const graph = await capturer.capture(clusterId, type, 'root');
    expect(find(graph, type, 'root').affected).toBe(true);
    expect(kong.list).not.toHaveBeenCalled();
  });

  it('refuses a partially captured shared dependency and never issues a mutation', async () => {
    const { capturer, kong } = harness({ '/routes/route': { id: 'route', service: { id: 'missing' } } }, { '/plugins': [] });
    await expect(capturer.capture(clusterId, 'routes', 'route')).rejects.toThrow('Unexpected read: /services/missing');
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it('refuses a nested child that points to a different parent', async () => {
    const { capturer } = harness({ '/services/service': { id: 'service' }, '/services/other': { id: 'other' } }, {
      '/services/service/routes': [{ id: 'route', service: { id: 'other' } }], '/plugins': [],
    });
    await expect(capturer.capture(clusterId, 'services', 'service')).rejects.toMatchObject({ response: { code: 'KONG_INVALID_ENTITY_GRAPH' } });
  });
});

describe('Recycle graph: credential recovery', () => {
  it('captures all six credential kinds and consumer plugins with recoverable Basic-auth plaintext only in the restore payload', async () => {
    const collections: Record<string, any[]> = { '/plugins': [{ id: 'plugin', name: 'acl', consumer: { id: 'consumer' }, service: null, route: null }] };
    for (const kind of kinds) collections[`/consumers/consumer/${kind}`] = [{ id: `${kind}-id`, consumer: { id: 'consumer' }, password: 'REMOTE-HASH', created_at: 10 }];
    const { capturer, credentials, kong } = harness({ '/consumers/consumer': { id: 'consumer', username: 'alice' } }, collections);
    const graph = await capturer.capture(clusterId, 'consumers', 'consumer');
    expect(graph.nodes).toHaveLength(8);
    for (const kind of kinds) {
      const node = find(graph, kind, `${kind}-id`);
      expect(node.dependencies).toEqual(['consumers:consumer']);
      expect(node.path).toBe(`/consumers/consumer/${kind}/${kind}-id`);
      expect(node.restoreData.id).toBe(`${kind}-id`);
      expect(node.restoreData).not.toHaveProperty('created_at');
    }
    expect(find(graph, 'basic-auth', 'basic-auth-id').data.password).toBe('REMOTE-HASH');
    expect(find(graph, 'basic-auth', 'basic-auth-id').restoreData.password).toBe('encrypted-store-original-password');
    expect(find(graph, 'plugins', 'plugin').dependencies).toEqual(['consumers:consumer']);
    expect(credentials.getRestorePayload).toHaveBeenCalledTimes(6);
    expect(kong.request).toHaveBeenCalledTimes(1);
  });

  it('fails closed before any delete when a historical Basic-auth raw password is absent', async () => {
    const { capturer, credentials, kong } = harness({
      '/consumers/consumer/basic-auth/credential': { id: 'credential', consumer: { id: 'consumer' }, password: 'REMOTE-HASH' },
      '/consumers/consumer': { id: 'consumer', username: 'alice' },
    });
    credentials.getRestorePayload.mockRejectedValue(new ConflictException({ code: 'BASIC_AUTH_NOT_RECOVERABLE', message: '原始密码缺失' }));
    await expect(capturer.capture(clusterId, 'credentials', 'credential', { parentId: 'consumer', credentialKind: 'basic-auth' })).rejects.toMatchObject({ status: 409, response: { code: 'BASIC_AUTH_NOT_RECOVERABLE' } });
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
    expect(kong.list).not.toHaveBeenCalled();
  });

  it('captures a single credential with its consumer as a shared reference', async () => {
    const { capturer, credentials } = harness({
      '/consumers/consumer/key-auth/key': { id: 'key', consumer: { id: 'consumer' }, key: 'secret' },
      '/consumers/consumer': { id: 'consumer', username: 'alice' },
    });
    const graph = await capturer.capture(clusterId, 'key-auth', 'key', { parentId: 'consumer' });
    expect(graph.rootKey).toBe('key-auth:consumer:key');
    expect(find(graph, 'consumers', 'consumer').affected).toBe(false);
    expect(credentials.getRestorePayload).toHaveBeenCalledWith(clusterId, 'consumer', 'key-auth', 'key', expect.objectContaining({ key: 'secret' }));
  });

  it('rejects a credential belonging to another consumer', async () => {
    const { capturer } = harness({ '/consumers/consumer/key-auth/key': { id: 'key', consumer: { id: 'other' }, key: 'secret' } });
    await expect(capturer.capture(clusterId, 'key-auth', 'key', { parentId: 'consumer' })).rejects.toMatchObject({ response: { code: 'KONG_INVALID_ENTITY_GRAPH' } });
  });
});

describe('Recycle graph: immutable Target history', () => {
  it('archives all history but restores only effective positive-weight targets, deduplicating repeated IDs', async () => {
    const old = { id: 'old', target: 'backend:80', weight: 10, upstream: { id: 'upstream' }, created_at: 1 };
    const current = { id: 'current', target: 'backend:80', weight: 50, upstream: { id: 'upstream' }, created_at: 2 };
    const removed = { id: 'removed', target: 'gone:80', weight: 0, upstream: { id: 'upstream' }, created_at: 3 };
    const { capturer } = harness({ '/upstreams/upstream': { id: 'upstream', name: 'backends' } }, {
      '/upstreams/upstream/targets/all': [removed, current, old],
      '/upstreams/upstream/targets': [current, current, removed],
    });
    const graph = await capturer.capture(clusterId, 'upstreams', 'upstream');
    expect(graph.targetHistory).toEqual([{ upstreamId: 'upstream', items: [removed, current, old] }]);
    expect(graph.nodes.map(node => node.id)).toEqual(['upstream', 'current']);
    expect(find(graph, 'targets', 'current')).toMatchObject({ key: 'targets:upstream:current', path: '/upstreams/upstream/targets/current', dependencies: ['upstreams:upstream'] });
    expect(find(graph, 'targets', 'current').restoreData).not.toHaveProperty('created_at');
  });

  it('rejects history/effective divergence rather than archiving a partial snapshot', async () => {
    const { capturer } = harness({ '/upstreams/upstream': { id: 'upstream' } }, {
      '/upstreams/upstream/targets/all': [],
      '/upstreams/upstream/targets': [{ id: 'new', target: 'backend:80', weight: 100 }],
    });
    await expect(capturer.capture(clusterId, 'upstreams', 'upstream')).rejects.toMatchObject({ response: { code: 'KONG_INVALID_ENTITY_GRAPH' } });
  });

  it('captures a single Target with no cascade of other upstream targets', async () => {
    const { capturer, kong } = harness({
      '/upstreams/upstream/targets/target': { id: 'target', target: 'backend:80', weight: 100, upstream: { id: 'upstream' } },
      '/upstreams/upstream': { id: 'upstream' },
    },{'/upstreams/upstream/targets':[{ id: 'target', target: 'backend:80', weight: 100, upstream: { id: 'upstream' } }]});
    const graph = await capturer.capture(clusterId, 'targets', 'target', { parentId: 'upstream' });
    expect(graph.nodes).toHaveLength(2);
    expect(find(graph, 'upstreams', 'upstream').affected).toBe(false);
    expect(kong.request).not.toHaveBeenCalledWith(clusterId, 'GET', '/upstreams/upstream/targets/backend%3A80');
    expect(kong.list).toHaveBeenCalledWith(clusterId,'/upstreams/upstream/targets',{size:100},undefined,'current-effective-target:upstream');
  });

  it.each([
    { id: 'latest', weight: 100 },
    { id: 'target', weight: 0 },
  ])('rejects a historical or disabled single Target from the scoped effective collection %j', async effective => {
    const { capturer, kong } = harness({
      '/upstreams/upstream/targets/target': { id: 'target', target: 'backend:80', weight: 10, upstream: { id: 'upstream' } },
      '/upstreams/upstream': { id: 'upstream' },
    },{'/upstreams/upstream/targets':effective.weight>0?[{ ...effective, target: 'backend:80', upstream: { id: 'upstream' } }]:[]});
    await expect(capturer.capture(clusterId, 'targets', 'target', { parentId: 'upstream' })).rejects.toMatchObject({ status: 409, response: { code: 'TARGET_NOT_EFFECTIVE' } });
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it('normalizes an absent effective Target address to a conflict before any deletion', async () => {
    const { capturer, kong } = harness({
      '/upstreams/upstream/targets/target': { id: 'target', target: 'backend:80', weight: 10, upstream: { id: 'upstream' } },
      '/upstreams/upstream': { id: 'upstream' },
    },{'/upstreams/upstream/targets':[]});
    await expect(capturer.capture(clusterId, 'targets', 'target', { parentId: 'upstream' })).rejects.toMatchObject({ status: 409, response: { code: 'TARGET_NOT_EFFECTIVE' } });
  });

  it('refuses a current Target returned for another upstream', async () => {
    const { capturer } = harness({
      '/upstreams/upstream/targets/target': { id: 'target', target: 'backend:80', weight: 100, upstream: { id: 'upstream' } },
      '/upstreams/upstream': { id: 'upstream' },
    },{'/upstreams/upstream/targets':[{ id: 'target', target: 'backend:80', weight: 100, upstream: { id: 'other' } }]});
    await expect(capturer.capture(clusterId, 'targets', 'target', { parentId: 'upstream' })).rejects.toMatchObject({ response: { code: 'KONG_INVALID_TARGET_LIST' } });
  });
});

describe('Recycle graph: strict bounded cursor traversal', () => {
  it('uses size=100 cursors, captures later-page dependents and reads the root once', async () => {
    const routes = Array.from({ length: 101 }, (_, index) => ({ id: `route-${index}`, service: { id: 'service' } }));
    const { capturer, kong } = harness({ '/services/service': { id: 'service' } }, {
      '/services/service/routes': routes,
      '/plugins': [{ id: 'plugin-last', route: { id: 'route-100' }, service: null, consumer: null }],
    });
    const graph = await capturer.capture(clusterId, 'services', 'service');
    expect(graph.nodes.filter(node => node.affected)).toHaveLength(103);
    expect(kong.list.mock.calls.map(call => [call[1], call[3]])).toEqual([
      ['/services/service/routes', undefined], ['/services/service/routes', '100'], ['/plugins', undefined],
    ]);
    expect(kong.request).toHaveBeenCalledTimes(1);
  });

  it('refuses a collection requiring page 101 and never fetches that page', async () => {
    const { capturer, kong } = harness({ '/routes/route': { id: 'route', service: null } }, { '/plugins': [] });
    kong.list.mockImplementation(async () => ({ items: [], size: 100, nextCursor: String(kong.list.mock.calls.length) }));
    await expect(capturer.capture(clusterId, 'routes', 'route')).rejects.toMatchObject({ status: 409, response: { code: 'RECYCLE_CAPTURE_LIMIT' } });
    expect(kong.list).toHaveBeenCalledTimes(100);
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it('refuses repeated cursors rather than accepting an incomplete graph', async () => {
    const { capturer, kong } = harness({ '/routes/route': { id: 'route', service: null } }, { '/plugins': [] });
    kong.list.mockResolvedValue({ items: [], size: 100, nextCursor: 'same' });
    await expect(capturer.capture(clusterId, 'routes', 'route')).rejects.toMatchObject({ response: { code: 'RECYCLE_PAGINATION_LOOP' } });
    expect(kong.list).toHaveBeenCalledTimes(2);
  });

  it('refuses more than 10000 graph nodes including shared references', async () => {
    const { capturer } = harness({ '/services/service': { id: 'service' } }, {
      '/services/service/routes': Array.from({ length: 10_000 }, (_, index) => ({ id: `route-${index}`, service: { id: 'service' } })),
      '/plugins': [],
    });
    await expect(capturer.capture(clusterId, 'services', 'service')).rejects.toMatchObject({ response: { code: 'RECYCLE_CAPTURE_LIMIT' } });
  });

  it.each([
    ['vaults', 'id', {}], ['targets', 'id', {}], ['credentials', 'id', { parentId: 'consumer', credentialKind: 'unknown' }],
    ['services', '../keys', {}], ['services', 'a/b', {}],
  ])('rejects invalid input %s/%s before making any remote request', async (type, id, options) => {
    const { capturer, kong } = harness({});
    await expect(capturer.capture(clusterId, type as string, id as string, options)).rejects.toMatchObject({ status: 400 });
    expect(kong.request).not.toHaveBeenCalled();
  });

  it('isolates each capture budget and caches even an empty plugin collection only within that capture', async () => {
    const { capturer, kong } = harness({ '/routes/route': { id: 'route', service: null } }, { '/plugins': [] });
    await capturer.capture(clusterId, 'routes', 'route');
    await capturer.capture(clusterId, 'routes', 'route');
    expect(kong.list).toHaveBeenCalledTimes(2);
  });
});
