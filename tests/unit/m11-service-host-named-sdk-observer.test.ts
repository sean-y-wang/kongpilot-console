import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { NotFoundException } from '@nestjs/common';
import { fixedValidationFixture } from './helpers/m11-fixed-validation-reader-fixture';

/** Independent Source components: genuine KongService.perform -> Context
 * opaque ticket/transport observation -> scheduled Validation provider. Only
 * SQL/Namespace fixtures and outbound transport are controlled adapters.
 * No product-private Map is seeded, no real HTTP/SQL/Native is performed. */
function fixture(host = 'orders.internal') {
  const f = fixedValidationFixture(false), upstreamId = randomUUID(), serviceId = randomUUID();
  const resource = { clusterId: f.cid, workspaceId: f.wid, path: `/upstreams/${encodeURIComponent(host)}`,
    kind: 'point' as const, entityType: 'upstreams', serviceHostReference: { host, serviceIds: [serviceId] },
    secrets: false, required: false, allowAbsent: true };
  f.values.resources = [resource]; f.outbound.mockClear();
  const raw = { id: upstreamId, name: host, tags: ['workspace:default'] };
  let transport: { ticket: any; proof: object } | undefined;
  const original = f.kong.verifyScheduledReadAbsentTransport.bind(f.kong);
  const transportVerifier = vi.spyOn(f.kong, 'verifyScheduledReadAbsentTransport').mockImplementation((ticket, proof) => {
    transport = { ticket, proof }; return original(ticket, proof);
  });
  f.outbound.mockImplementation(async (_base, _path, method, _body, _query, _auth, _timeout, beforeSend, prepareSend) => {
    if (method !== 'GET') throw Error('SOURCE_COMPONENT_GET_ONLY');
    await prepareSend?.(); beforeSend?.(); return { status: 200, body: raw, bytes: 100, jsonParsed: true };
  });
  const reply = (status: number, body: any, ...parsing: [] | [boolean | undefined]) => {
    const jsonParsed = parsing.length ? parsing[0] : true;
    f.outbound.mockImplementation(async (_base, _path, method, _body, _query, _auth, _timeout, beforeSend, prepareSend) => {
      if (method !== 'GET') throw Error('SOURCE_COMPONENT_GET_ONLY');
      await prepareSend?.(); beforeSend?.(); return { status, body, bytes: 100,
        ...(jsonParsed === undefined ? {} : { jsonParsed }) } as any;
    });
  };
  const point = () => f.kong.request(f.cid, 'GET', resource.path);
  return { ...f, resource, raw, upstreamId, serviceId, reply, point, transportVerifier, transport: () => transport };
}

beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z'));
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('fixed Service.host named point through genuine SDK observer', () => {
  it('accepts the exact optional marker and real UUID/name response without an upstream collection scan', async () => {
    const f = fixture(); let observed: unknown;
    await f.run(async () => { observed = await f.point(); });
    expect(observed).toEqual(f.raw); expect(f.outbound).toHaveBeenCalledTimes(1);
    expect(f.acceptedRequests.map(r => ({ method: r.method, path: r.path, query: r.query })))
      .toEqual([{ method: 'GET', path: f.resource.path, query: {} }]);
    expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
    expect(f.business.authorizeResponse.mock.calls[0][0]).toMatchObject({ resource: f.resource, response: f.raw, status: 200 });
    expect(f.transportVerifier).not.toHaveBeenCalled(); expect(f.generic).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('returns only the actual parsed SDK404 body and its original opaque association while the same read is live', async () => {
    const f = fixture(), raw = { message: 'Not found' }; f.reply(404, raw);
    let handle: object | undefined, originalWitness: object | undefined;
    await f.run(async (h: object) => {
      handle = h;
      await expect(f.point()).rejects.toMatchObject({ status: 404, response: { code: 'KONG_VALIDATION_ERROR', upstreamStatus: 404 } });
      const observed = await f.service.observedServiceHostAbsence(h, f.resource);
      expect(observed.response).toEqual(raw); expect(Object.isFrozen(observed)).toBe(true);
      expect(Object.isFrozen(observed.originalWitness)).toBe(true); expect(Object.keys(observed.originalWitness)).toEqual([]);
      originalWitness = observed.originalWitness;
    });
    expect(originalWitness).toBeDefined(); expect(f.transportVerifier).toHaveBeenCalledTimes(1);
    expect(f.business.authorizeResponse.mock.calls.map((c: any) => c[0].status)).toEqual([404]);
    await expect(f.service.observedServiceHostAbsence(handle!, f.resource)).rejects.toBeDefined();
    const original = f.transport()!;
    expect(() => f.kong.verifyScheduledReadAbsentTransport(original.ticket, original.proof)).toThrow();
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.generic).not.toHaveBeenCalled();
  });

  it('does not mint an absence from a caller-thrown NotFoundException without the SDK original transport proof', async () => {
    const f = fixture();
    f.outbound.mockRejectedValue(new NotFoundException({ message: 'Not found' }));
    await expect(f.run(async (handle: object) => {
      await expect(f.point()).rejects.toMatchObject({ status: 404 });
      await expect(f.service.observedServiceHostAbsence(handle, f.resource)).rejects.toBeDefined();
    })).rejects.toBeDefined();
    expect(f.transportVerifier).not.toHaveBeenCalled(); expect(f.business.authorizeResponse).not.toHaveBeenCalled();
  });

  it.each([
    ['wrong exact name', { id: randomUUID(), name: 'different.internal' }],
    ['invalid response UUID', { id: 'not-a-native-uuid', name: 'orders.internal' }],
  ])('rejects %s at the actual response boundary', async (_name, response) => {
    const f = fixture(); f.reply(200, response);
    await expect(f.run(async () => { await f.point(); })).rejects.toBeDefined();
    expect(f.outbound).toHaveBeenCalledTimes(1); expect(f.business.authorizeResponse).not.toHaveBeenCalled();
  });

  it.each(['health', 'enabled'])('accepts legitimate host name %s as a fixed upstream-name marker with HTTP200', async host => {
    const f = fixture(host); let raw: unknown;
    await f.run(async () => { raw = await f.point(); });
    expect(raw).toEqual(f.raw); expect(f.acceptedRequests).toHaveLength(1);
    expect(f.acceptedRequests[0].path).toBe(`/upstreams/${host}`); expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
  });

  it.each(['health', 'enabled'])('accepts legitimate host name %s only from the parsed SDK404 proof when absent', async host => {
    const f = fixture(host); f.reply(404, { message: 'Not found' });
    await f.run(async (handle: object) => {
      await expect(f.point()).rejects.toMatchObject({ status: 404 });
      const result = await f.service.observedServiceHostAbsence(handle, f.resource);
      expect(result.response).toEqual({ message: 'Not found' });
    });
    expect(f.transportVerifier).toHaveBeenCalledTimes(1); expect(f.outbound).toHaveBeenCalledTimes(1);
  });

  it('rejects a copied opaque SDK proof even while the genuine transport observation is live', async () => {
    const f = fixture(); f.reply(404, { message: 'Not found' });
    const original = Object.getPrototypeOf(f.kong).verifyScheduledReadAbsentTransport.bind(f.kong);
    // Restore the fixture spy first; this wrapper only inspects an actual SDK
    // invocation and cannot mint or insert any private observer association.
    f.transportVerifier.mockRestore();
    const verify = vi.spyOn(f.kong, 'verifyScheduledReadAbsentTransport').mockImplementation((ticket, proof) => {
      expect(() => original(ticket, { ...proof })).toThrow(); return original(ticket, proof);
    });
    await f.run(async (handle: object) => {
      await expect(f.point()).rejects.toMatchObject({ status: 404 });
      expect((await f.service.observedServiceHostAbsence(handle, f.resource)).response).toEqual({ message: 'Not found' });
    });
    expect(verify).toHaveBeenCalledTimes(1);
  });

  it('rejects a copied read handle while the genuine SDK404 association remains usable', async () => {
    const f = fixture(); f.reply(404, { message: 'Not found' });
    await f.run(async (handle: object) => {
      await expect(f.point()).rejects.toMatchObject({ status: 404 });
      await expect(f.service.observedServiceHostAbsence({ ...handle }, f.resource)).rejects.toBeDefined();
      expect((await f.service.observedServiceHostAbsence(handle, f.resource)).response).toEqual({ message: 'Not found' });
    });
  });

  it('rejects using the observed named absence for another resource and poisons the original group', async () => {
    const f = fixture(); f.reply(404, { message: 'Not found' });
    const foreign = { ...f.resource, path: '/upstreams/foreign.internal',
      serviceHostReference: { ...f.resource.serviceHostReference, host: 'foreign.internal' } };
    await expect(f.run(async (handle: object) => {
      await expect(f.point()).rejects.toMatchObject({ status: 404 });
      await expect(f.service.observedServiceHostAbsence(handle, foreign)).rejects.toBeDefined();
    })).rejects.toBeDefined();
  });

  it.each([false, undefined])('does not accept a named 404 with jsonParsed=%s', async jsonParsed => {
    const f = fixture(); f.reply(404, { message: 'Not found' }, jsonParsed);
    await expect(f.run(async (handle: object) => {
      await expect(f.point()).rejects.toMatchObject({ status: 404 });
      await expect(f.service.observedServiceHostAbsence(handle, f.resource)).rejects.toBeDefined();
    })).rejects.toBeDefined();
    expect(f.transportVerifier).not.toHaveBeenCalled(); expect(f.business.authorizeResponse).not.toHaveBeenCalled();
  });
});
