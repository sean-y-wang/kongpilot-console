import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException, ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { businessStepVerificationFixture } from './helpers/m11-business-step-verification-fixture';
import { PortalAuthBoundaryService } from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ed'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const codes = ['KONG_EXECUTION_CALL_LIMIT', 'KONG_EXECUTION_RESPONSE_LIMIT', 'KONG_EXECUTION_CONTEXT_EXPIRED'] as const;

/** Real Boundary, Approved public execution/step/binding registries, Context
 * Namespace ancestry and AEAD plans. SQL/identity/lease/Kong are controlled
 * Source adapters. No private maps are seeded and no actual Native is sent. */
function fixture() {
  const f = businessStepVerificationFixture(); f.rows[0].state = 'running';
  const ownership = { publications: [], grants: [{ consumer_id: f.plan.steps[0].entityId,
    state: 'revoked', reservation_released_at: new Date().toISOString() }], credentials: [] };
  const boundaryDb: any = { query: vi.fn(async (sql: string) => {
    if (sql.includes('FROM portal_publications')) return structuredClone(ownership.publications);
    if (sql.includes('FROM portal_application_grants')) return structuredClone(ownership.grants);
    if (sql.includes('FROM portal_credentials')) return structuredClone(ownership.credentials);
    throw Error('UNEXPECTED_SOURCE_BOUNDARY_QUERY');
  }) };
  Object.assign(f.kong, { list: vi.fn(async () => { throw Error('CAPTURE_MUST_NOT_START_AFTER_APPROVED_DENIAL'); }),
    schema: vi.fn(), pluginSchema: vi.fn() });
  const boundary = new PortalAuthBoundaryService(boundaryDb, f.secrets, f.kong, f.context, {} as any, f.verifier);
  const actualApproved = vi.spyOn(f.verifier, 'assertNativeWrite');
  const native = vi.fn(), metrics = vi.fn();
  const run = (fn: (input: any) => Promise<any>) => f.run(() => f.context.runApprovedStep(f.plan.steps[0].id, async () => {
    const context = f.nativeContext(), binding = await f.context.approvedMutationBinding(context), operation = f.operation();
    await f.context.bindApprovedOperation(context, binding!, operation.id, f.db); operation.remote_started = true;
    const request = f.plan.steps[0].nativeRequests[0], input = {
      clusterId: f.cid, workspaceId: f.wid, transportScope: f.plan.scope.transportScope, operationId: operation.id,
      method: request.method, canonicalPath: request.canonicalPath, body: request.body, before: null,
      mutationAction: 'create', parentId: undefined, credentialKind: undefined,
    };
    return fn(input);
  }));
  const noContinuation = () => {
    expect(f.kong.list).not.toHaveBeenCalled(); expect(f.kong.schema).not.toHaveBeenCalled();
    expect(native).not.toHaveBeenCalled(); expect(metrics).not.toHaveBeenCalled();
    expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  };
  const invoke = async (input: any) => { await boundary.assertBeforeNativeSend(input, {} as any); native(); metrics(); };
  return { ...f, boundary, boundaryDb, ownership, actualApproved, native, metrics, run, noContinuation, invoke };
}

describe('M11 Portal managed boundary preserves only fixed public infrastructure diagnostics', () => {
  it.each(codes)('preserves %s with a rebuilt safe response and the original error status', async code => {
    const f = fixture(); let caught: any;
    await f.run(async input => {
      const original = new HttpException({ code, message: 'PRIVATE_SOURCE_SENTINEL', stack: 'PRIVATE_SOURCE_SENTINEL',
        secret: 'PRIVATE_SOURCE_SENTINEL', fields: { key: 'PRIVATE_SOURCE_SENTINEL' } }, 429);
      f.redis.assertLeaseOwnership.mockRejectedValueOnce(original);
      const writes = f.db.exec.mock.calls.length;
      try { await f.invoke(input); } catch (error) { caught = error; }
      expect(caught).toBeInstanceOf(HttpException); expect(caught).not.toBe(original); expect(caught.getStatus()).toBe(429);
      expect(caught.getResponse()).toEqual({ code, message: expect.any(String) });
      expect(JSON.stringify(caught.getResponse())).not.toContain('PRIVATE_SOURCE_SENTINEL');
      expect(f.db.exec.mock.calls.length).toBe(writes);
    });
    expect(f.actualApproved).toHaveBeenCalledTimes(1); f.noContinuation();
  });

  it.each(['calls', 'response'] as const)('keeps the actual Context %s limit raised inside the real Approved chain', async kind => {
    const f = fixture(); let caught: any;
    await f.run(async input => {
      f.redis.assertLeaseOwnership.mockImplementationOnce(async () => f.context.runInternalRead(f.cid, 'authorization', async () => {
        await f.kong.request(f.cid, 'GET', `/services/${f.service.id}`);
        if (kind === 'calls') await f.kong.request(f.cid, 'GET', `/services/${f.service.id}`);
      }, { paths: [`/services/${f.service.id}`], maxCalls: 1, maxBytes: kind === 'response' ? 1 : 32768 }));
      const writes = f.db.exec.mock.calls.length;
      try { await f.invoke(input); } catch (error) { caught = error; }
      expect(caught).toBeInstanceOf(HttpException); expect(caught.getStatus()).toBe(403);
      expect(caught.getResponse()).toEqual({ code: kind === 'calls' ? codes[0] : codes[1], message: expect.any(String) });
      expect(f.db.exec.mock.calls.length).toBe(writes);
    });
    f.noContinuation();
  });

  const disguised: Array<[string, () => unknown]> = [
    ['ordinary exception', () => new Error('PRIVATE_SOURCE_SENTINEL')],
    ['unknown HttpException', () => new ForbiddenException({ code: 'APPROVED_NATIVE_REQUEST_MISMATCH', message: 'PRIVATE_SOURCE_SENTINEL' })],
    ['duck typed error', () => ({ getStatus: () => 403, getResponse: () => ({ code: codes[0], secret: 'PRIVATE_SOURCE_SENTINEL' }) })],
    ['non-error HTTP status', () => new HttpException({ code: codes[0], secret: 'PRIVATE_SOURCE_SENTINEL' }, 200)],
    ['string response', () => new HttpException(codes[0], 403)],
    ['inherited code', () => new HttpException(Object.create({ code: codes[0] }), 403)],
    ['nested code', () => new HttpException({ error: { code: codes[0] }, secret: 'PRIVATE_SOURCE_SENTINEL' }, 403)],
    ['nonstring code', () => new HttpException({ code: { value: codes[0] } }, 403)],
    ['prototype property name', () => new HttpException({ code: 'constructor' }, 403)],
    ['unreadable exception response', () => new class extends HttpException { getResponse(): never { throw Error('PRIVATE_SOURCE_SENTINEL'); } }({}, 403)],
  ];
  it.each(disguised)('keeps generic denial for %s without capture, Native or metric continuation', async (_label, makeError) => {
    const f = fixture();
    await f.run(async input => {
      f.redis.assertLeaseOwnership.mockRejectedValueOnce(makeError());
      const writes = f.db.exec.mock.calls.length;
      await expect(f.invoke(input)).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
      expect(f.db.exec.mock.calls.length).toBe(writes);
    }); f.noContinuation();
  });

  it('does not invoke a response code getter while classifying a denied packet', async () => {
    const f = fixture(), getter = vi.fn(() => codes[0]), response = {};
    Object.defineProperty(response, 'code', { get: getter, enumerable: true });
    await f.run(async input => {
      f.redis.assertLeaseOwnership.mockRejectedValueOnce(new HttpException(response, 403));
      await expect(f.invoke(input)).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    }); expect(getter).not.toHaveBeenCalled(); f.noContinuation();
  });

  it.each(['operationId', 'body', 'transportScope', 'workspaceId', 'before'] as const)('keeps actual original packet %s mismatch generic', async field => {
    const f = fixture();
    await f.run(async input => {
      const modified = { ...input, [field]: field === 'body' ? { ...input.body, username: 'forged' }
        : field === 'before' ? { id: randomUUID() } : field === 'transportScope' ? 'f'.repeat(64) : randomUUID() };
      await expect(f.invoke(modified)).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    }); f.noContinuation();
  });

  it('rejects a caller without an original execution/step instead of lending approved identity', async () => {
    const f = fixture(), step = f.plan.steps[0];
    await expect(f.invoke({ clusterId: f.cid, workspaceId: f.wid, transportScope: f.plan.scope.transportScope,
      operationId: randomUUID(), method: 'POST', canonicalPath: '/consumers', body: step.nativeRequests[0].body,
      before: null, mutationAction: 'create' })).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    expect(f.db.exec).not.toHaveBeenCalled(); f.noContinuation();
  });

  it('keeps a copied step proof generic without creating an Approved private registry entry', async () => {
    const f = fixture();
    await f.run(async input => {
      const original = f.context.currentApprovedStep();
      // Deliberately substitute a copied public projection, not a private map.
      vi.spyOn(f.context, 'currentApprovedStep').mockReturnValue({ ...original });
      await expect(f.invoke(input)).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    }); f.noContinuation();
  });

  it('retains the unchanged successful original Approved boundary path', async () => {
    const f = fixture();
    await f.run(async input => {
      await expect(f.boundary.assertBeforeNativeSend(input, {} as any)).resolves.toBeUndefined();
    }); expect(f.actualApproved).toHaveBeenCalledTimes(1); f.noContinuation();
  });
});
