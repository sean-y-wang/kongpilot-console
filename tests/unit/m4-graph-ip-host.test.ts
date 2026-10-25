import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { BadRequestException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { GraphCapturerService } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const cid = '0756d13d-30ce-460f-b127-b7ed8f4efdc8';
const serviceId = '84bf2f60-ebc5-4bda-a4e3-5d69c7de3973';
const upstreamId = '7ce6ab62-1aa2-4c3b-aada-e0683e5a55eb';
const actor = { id: '11336e1d-52b1-48e1-87c9-d2cf8b2f18da', username: 'capture-fixture', superAdmin: true };

// The actual CaptureSession and execution scope run on raw recorded-response
// fixtures. No Kong write or live network call is made by these regressions.
function fixture(host: string, lookup: 'found' | 'missing' | 'bad-request' | 'unavailable' = 'bad-request') {
  const execution = new KongExecutionContextService();
  const service = { id: serviceId, name: 'literal-or-dns-host', host, port: 8080, tags: [] };
  const kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => {
      expect(_cid).toBe(cid); expect(method).toBe('GET');
      expect(execution.current()).toMatchObject({ kind: 'internal-read', purpose: 'capture' });
      if (path === `/services/${serviceId}`) return structuredClone(service);
      if (path.startsWith('/upstreams/')) {
        if (lookup === 'found') return { id: upstreamId, name: host, tags: [] };
        if (lookup === 'missing') throw new NotFoundException({ code: 'KONG_VALIDATION_ERROR' });
        if (lookup === 'unavailable') throw new ServiceUnavailableException({ code: 'KONG_UPSTREAM_ERROR' });
        // Kong 1.5's native unique-name lookup rejects a literal IPv4 host.
        throw new BadRequestException({ code: 'KONG_VALIDATION_ERROR', fields: { name: 'invalid unique name' } });
      }
      throw new Error('unexpected fixture path');
    }),
    list: vi.fn(async (_cid: string, path: string) => {
      expect([`/services/${serviceId}/routes`, '/plugins']).toContain(path);
      return { items: [], size: 100, nextCursor: null };
    }),
  };
  const capture = new GraphCapturerService(kong, {} as any, execution);
  const run = () => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor); const close = execution.captureHttpCloser();
    try { return await execution.runActor({ actor, clusterId: cid, module: 'services', action: 'delete' },
      () => capture.capture(cid, 'services', serviceId)); }
    finally { close(); }
  });
  return { kong, run, service };
}

describe('Kong 1.5 capture distinguishes Service IP literals from implicit Upstreams', () => {
  it.each(['127.0.0.1', '203.0.113.42', '::1', '2001:db8::1', '[2001:db8::1]', '::ffff:127.0.0.1'])
    ('captures %s without invoking the invalid Upstream name endpoint', async host => {
      const f = fixture(host); const graph = await f.run();
      expect(graph).toMatchObject({ complete: true, budget: { pages: 2, nodes: 1 } });
      expect(graph.nodes[0]).toMatchObject({ type: 'services', affected: true, dependencies: [], data: f.service, restoreData: f.service });
      expect(f.kong.request.mock.calls.map(call => call[2])).toEqual([`/services/${serviceId}`]);
    });

  it('still captures a DNS host matching a real Upstream as a shared dependency', async () => {
    const f = fixture('api-pool.internal', 'found'), graph = await f.run();
    expect(graph.nodes[0].dependencies).toEqual([`upstreams:${upstreamId}`]);
    expect(graph.nodes[1]).toMatchObject({ type: 'upstreams', id: upstreamId, affected: false });
    expect(f.kong.request).toHaveBeenCalledWith(cid, 'GET', '/upstreams/api-pool.internal');
  });

  it('still accepts a DNS host whose Upstream lookup returns only 404', async () => {
    const f = fixture('api.internal', 'missing');
    expect((await f.run()).nodes).toHaveLength(1);
    expect(f.kong.request).toHaveBeenCalledWith(cid, 'GET', '/upstreams/api.internal');
  });

  it.each([['bad-request', 400], ['unavailable', 503]] as const)
    ('propagates a DNS lookup %s before scanning the deletion graph', async (lookup, status) => {
      const f = fixture('api.internal', lookup);
      await expect(f.run()).rejects.toMatchObject({ status });
      expect(f.kong.list).not.toHaveBeenCalled();
      expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
    });
});
