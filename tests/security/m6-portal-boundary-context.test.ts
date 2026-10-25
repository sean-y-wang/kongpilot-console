import { describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { actor, cid, id, serviceId, wid } from './m6-approved-fixture';

const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
const path = `/services/${serviceId}`;
const denied = (fn: () => unknown, code: string) => expect(Promise.resolve().then(fn)).rejects.toMatchObject({ response: { code } });
function fixture(hook: (...args: any[]) => Promise<void>) {
  const context = new KongExecutionContextService();
  context.installPolicy({ authorizeRequest: async () => ({ before: { id: serviceId } }), authorizeResponse: async (_ticket, result) => result, beforeNativeSend: hook });
  const http = <T>(fn: () => Promise<T>) => context.runHttp({}, async () => {
    context.bindHttpActor(actor, 'verified-session'); const close = context.captureHttpCloser();
    try { return await context.runActor({ actor, clusterId: cid, workspaceId: wid, module: 'services', action: 'write' }, fn); } finally { close(); }
  });
  const write = <T>(fn: (ticket: any) => Promise<T>, operationId = id(90)) => context.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId, entityType: 'services', entityId: serviceId, action: 'update' }, async () => {
    const ticket = await context.authorizeRequest(cluster, 'PATCH', path, { tags: ['kos-ws-pay'] }, {}); return fn(ticket);
  });
  return { context, http, write };
}

describe('M6 private final-write Portal boundary read permits', () => {
  it('issues a live packet-bound permit to the 8th hook argument and keeps decision as the 7th', async () => {
    let f!: ReturnType<typeof fixture>; const observations: any[] = [];
    f = fixture(async (frame, actualCluster, method, actualPath, body, query, decision, permit) => {
      expect(decision).toEqual({ before: { id: serviceId } }); expect(permit).toEqual({});
      expect([actualCluster.id, method, actualPath]).toEqual([cid, 'PATCH', path]);
      await f.context.runPortalBoundaryRead(permit, ['/services', `/consumers/${id(6)}/acls`, `/consumers/${id(6)}/key-auth/${id(7)}`], async () => {
        const read = f.context.current(); f.context.assertPortalBoundaryRead(read);
        observations.push([read.actor?.id, read.sessionId, read.workspaceId, read.operation?.operationId, frame.operation.operationId]);
        const ticket = await f.context.authorizeRequest(cluster, 'GET', '/services', undefined, { size: 100, offset: 'native-cursor' });
        await f.context.authorizeResponse(ticket, { data: [{ id: serviceId }], next: null });
      }, { maxCalls: 1, maxPages: 1, maxRecords: 100, maxBytes: 1024 });
      expect(body).toEqual({ tags: ['kos-ws-pay'] }); expect(query).toEqual({});
    });
    await f.http(() => f.write(ticket => f.context.beforeNativeSend(ticket)));
    expect(observations).toEqual([[actor.id, 'verified-session', wid, id(90), id(90)]]);
  });

  it('rejects serialized/copied permits and a general compiler/internal-read Portal purpose', async () => {
    const f = fixture(async () => undefined);
    await f.http(async () => {
      await denied(() => f.context.runPortalBoundaryRead({} as any, ['/services'], async () => undefined), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
      await denied(() => f.context.runInternalRead(cid, 'portal-boundary', async () => undefined, { paths: ['/services'] }), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    });
    let g!: ReturnType<typeof fixture>;
    g = fixture(async (...args) => denied(() => g.context.runPortalBoundaryRead({ ...args[7] }, ['/services'], async () => undefined), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED'));
    await g.http(() => g.write(ticket => g.context.beforeNativeSend(ticket)));
  });

  it('releases the permit after hook success and failure, including inside the still-alive operation', async () => {
    let permit: any; const f = fixture(async (...args) => { permit = args[7]; });
    await f.http(() => f.write(async ticket => {
      await f.context.beforeNativeSend(ticket);
      await denied(() => f.context.runPortalBoundaryRead(permit, ['/services'], async () => undefined), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    }));
    const g = fixture(async (...args) => { permit = args[7]; throw new Error('known boundary rejection'); });
    await g.http(() => g.write(async ticket => {
      await expect(g.context.beforeNativeSend(ticket)).rejects.toThrow('known boundary rejection');
      await denied(() => g.context.runPortalBoundaryRead(permit, ['/services'], async () => undefined), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    }));
  });

  it('forbids copied read frames and additional nested operations from changing the original packet scope', async () => {
    let f!: ReturnType<typeof fixture>;
    f = fixture(async (...args) => {
      await f.context.runPortalBoundaryRead(args[7], ['/services'], async () => {
        await denied(() => f.context.assertPortalBoundaryRead({ ...f.context.current() }), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
        await f.context.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId: id(91), entityType: 'services', entityId: serviceId, action: 'update' }, async () => {
          // Creating a new ordinary operation frame is not a graph-read permit.
          await denied(() => f.context.assertPortalBoundaryRead(f.context.current()), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
        });
      });
    });
    await f.http(() => f.write(ticket => f.context.beforeNativeSend(ticket)));
  });

  it.each(['/consumers', `/consumers/${id(6)}/key-auth`, '/certificates', '/cache', '/schemas/services', '/plugins/schema/key-auth', `/services/${serviceId}/routes`])('does not grant unrelated or full credential lists: %s', async forbiddenPath => {
    let f!: ReturnType<typeof fixture>;
    f = fixture(async (...args) => denied(() => f.context.runPortalBoundaryRead(args[7], [forbiddenPath], async () => undefined), 'PORTAL_BOUNDARY_READ_PATH_INVALID'));
    await f.http(() => f.write(ticket => f.context.beforeNativeSend(ticket)));
  });

  it('rejects tag filters, unbounded pages, another identity path and writes even with a valid permit', async () => {
    let f!: ReturnType<typeof fixture>;
    f = fixture(async (...args) => f.context.runPortalBoundaryRead(args[7], ['/services'], async () => {
      for (const query of [{ size: 101 }, { size: 100, tags: 'team-pay' }, { size: 'NaN' }]) {
        await denied(() => f.context.authorizeRequest(cluster, 'GET', '/services', undefined, query), 'PORTAL_BOUNDARY_READ_QUERY_INVALID');
      }
      await denied(() => f.context.authorizeRequest(cluster, 'GET', path, undefined, {}), 'KONG_INTERNAL_PATH_FORBIDDEN');
      await denied(() => f.context.authorizeRequest(cluster, 'PATCH', '/services', {}, {}), 'KONG_READ_CAPABILITY_WRITE_FORBIDDEN');
    }));
    await f.http(() => f.write(ticket => f.context.beforeNativeSend(ticket)));
  });

  it('cannot continue graph reads after the response closes its HTTP ancestor during the hook', async () => {
    let close!: () => void, f!: ReturnType<typeof fixture>; const transport = vi.fn();
    f = fixture(async (...args) => { close(); await denied(() => f.context.runPortalBoundaryRead(args[7], ['/services'], transport), 'KONG_EXECUTION_CONTEXT_EXPIRED'); });
    await expect(f.http(() => { close = f.context.captureHttpCloser(); return f.write(ticket => f.context.beforeNativeSend(ticket)); })).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(transport).not.toHaveBeenCalled();
  });
});
