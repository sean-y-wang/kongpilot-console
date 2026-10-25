import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';
import { GraphCapturerService } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';

const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';

describe('Independent M1 schema and graph safety review', () => {
  it.each(['constructor', 'toString', '__proto__'])('rejects inherited JavaScript key %s as an unknown Kong field', name => {
    const payload = JSON.parse(`{"${name}":{"unsafe":true}}`);
    expect(() => validateKnownFields(payload, { fields: [{ name: { type: 'string' } }] })).toThrow(expect.objectContaining({ status: 400 }));
    expect(() => validateKnownFields({ config: payload }, { fields: [{ config: { type: 'record', fields: [{ allowed: { type: 'string' } }] } }] })).toThrow(expect.objectContaining({ status: 400 }));
  });

  it('checks all Service pages for a restrictive client_certificate reference before reading/deleting any SNI', async () => {
    const kong = {
      request: vi.fn().mockResolvedValue({ id: 'cert', cert: 'public-pem', key: 'private-pem' }),
      list: vi.fn(async (_cid: string, path: string, query: any, cursor?: string) => {
        expect(path).toBe('/services');
        expect(query).toEqual({ size: 100 });
        return cursor ? { items: [{ id: 'later-page-service', client_certificate: { id: 'cert' } }], nextCursor: null, size: 100 }
          : { items: [{ id: 'unrelated', client_certificate: null }], nextCursor: 'next', size: 100 };
      }),
    };
    const capturer = new GraphCapturerService(kong as any, {} as any,executionFixture());
    await expect(capturer.capture(cid, 'certificates', 'cert')).rejects.toMatchObject({ response: { code: 'CERTIFICATE_IN_USE' } });
    expect(kong.list).toHaveBeenCalledTimes(2);
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
    expect(kong.list.mock.calls.every(call => call[1] === '/services')).toBe(true);
  });

  it.each([true, false])('records an existing host-matched Upstream as shared dependency while allowing ordinary DNS (exists=%s)', async exists => {
    const kong = {
      request: vi.fn(async (_cid: string, method: string, path: string) => {
        expect(method).toBe('GET');
        if (path === '/services/service') return { id: 'service', host: 'backend.internal' };
        expect(path).toBe('/upstreams/backend.internal');
        if (!exists) throw new NotFoundException();
        return { id: 'upstream', name: 'backend.internal' };
      }),
      list: vi.fn(async (_cid: string, path: string) => {
        expect(['/services/service/routes', '/plugins']).toContain(path);
        return { items: [], size: 100, nextCursor: null };
      }),
    };
    const capturer = new GraphCapturerService(kong as any, {} as any,executionFixture());
    const graph = await capturer.capture(cid, 'services', 'service');
    expect(graph.nodes.filter(node => node.affected).map(node => node.id)).toEqual(['service']);
    const service = graph.nodes.find(node => node.type === 'services')!;
    expect(service.dependencies).toEqual(exists ? ['upstreams:upstream'] : []);
    expect(graph.nodes.find(node => node.type === 'upstreams')?.affected).toBe(exists ? false : undefined);
    expect(kong.list.mock.calls.some(call => call[1].includes('targets'))).toBe(false);
  });
});
