import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import { validationMeterFixture } from './helpers/m11-validation-meter-fixture';
import { fixedValidationFixture, fixedParentChild } from './helpers/m11-fixed-validation-reader-fixture';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T17:00:00Z'));
  vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {}); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });
const limited = { response: { code: 'KONG_EXECUTION_CALL_LIMIT' } };

describe('original validation support and single planned read meters (Source only)', () => {
  it.each(['operation-check', 'authorization', 'entity-preflight'] as const)
  ('preserves one planned %s GET alongside genuine Namespace support', async purpose => {
    const f = validationMeterFixture(); let local: unknown, total: unknown;
    await f.run(async () => {
      await f.context.runInternalRead(f.cluster.id, purpose, async () => {
        f.state.armed = true; await f.readPoint(); local = f.context.currentUsage();
        await expect(f.requestPoint()).rejects.toMatchObject(limited);
      }, { paths: [f.point], maxCalls: 1 });
      total = f.context.currentUsage();
    });
    expect(local).toMatchObject({ calls: 1, pages: 0, records: 0 });
    expect(total).toMatchObject({ calls: 2, pages: 1, records: 1 });
    expect(f.state.supportReads).toBe(1); expect(f.genericRequest).toHaveBeenCalledTimes(2);
  });

  it('uses the genuine fixed provider, Context and Root readResources under a single-point parent', async () => {
    const f = fixedValidationFixture(); f.outbound.mockClear();
    f.values.present = new Set(f.values.resources.map((r: any) => r.path));
    const original = (f.context as any).workflowScheduledPolicy.verifyHandle;
    let armed = false, local: unknown;
    (f.context as any).workflowScheduledPolicy.verifyHandle = async (handle: object, checkpoint: string) => {
      const proof = await original(handle, checkpoint);
      if (armed && checkpoint === 'capture') {
        armed = false; await f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db, async () => undefined);
      }
      return proof;
    };
    f.generic.mockImplementation(async (_: unknown, result: unknown) => result);
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, () => f.context.runInternalRead(f.cid, 'operation-check', async () => {
      armed = true; await f.kong.request(f.cid, 'GET', f.values.resources[0].path); local = f.context.currentUsage();
    }, { paths: [f.values.resources[0].path], maxCalls: 1 }));
    expect(local).toMatchObject({ calls: 1 }); expect(f.business.authorizeResponse).toHaveBeenCalledTimes(1);
    expect(f.outbound).toHaveBeenCalledTimes(2); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('charges support retries and response capacity only to their real support and aggregate domains', async () => {
    const f = validationMeterFixture(); let outer: unknown, child: unknown, total: unknown;
    await f.run(async () => {
      await f.context.runInternalRead(f.cluster.id, 'operation-check', async () => {
        await f.support(async () => { await f.readSupport({ data: [{ id: 'a' }, { id: 'b' }], next: null }, true); child = f.context.currentUsage(); });
        await f.readPoint(); outer = f.context.currentUsage();
      }, { paths: [f.point], maxCalls: 1, maxPages: 1, maxRecords: 1, maxBytes: 64 });
      total = f.context.currentUsage();
    });
    expect(child).toMatchObject({ calls: 2, pages: 1, records: 2 });
    expect(outer).toMatchObject({ calls: 1, pages: 0, records: 0 });
    expect(total).toMatchObject({ calls: 3, pages: 1, records: 2 });
  });

  it('retains the Namespace aggregate 1000-call scheduled configuration ceiling (user-approved 2026-10-24) across independent support groups', async () => {
    const f = validationMeterFixture(); vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    await f.run(async () => {
      for (let index = 0; index < 50; index++) await f.support(async () => {
        for (let packet = 0; packet < 20; packet++) await f.readSupport({ id: 'support' });
      }, { maxCalls: 20, maxPages: 100 });
      expect(f.context.currentUsage()).toMatchObject({ calls: 1000, pages: 0 });
      await expect(f.support(() => f.readSupport())).rejects.toMatchObject(limited);
    });
    expect(f.state.supportReads).toBe(1000); expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it('keeps a newly created descendant local meter bounded inside an authentic validation group', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.support(() => f.context.runInternalRead(f.cluster.id, 'capture', async () => {
      await f.readSupport(); await expect(f.readSupport()).rejects.toMatchObject(limited);
    }, { paths: ['/services'], maxCalls: 1 })));
    expect(f.state.supportReads).toBe(1);
  });

  it.each(['multiple-paths', 'no-paths'] as const)('retains an aggregate %s internal ancestor meter', async reason => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'capture', async () => {
      await f.support(() => f.readSupport()); await f.readPoint();
    }, { ...(reason === 'multiple-paths' ? { paths: [f.point, '/services'] } : {}), maxCalls: 1 }))).rejects.toMatchObject(limited);
    expect(f.genericRequest).not.toHaveBeenCalled(); expect(f.state.supportReads).toBe(1);
  });

  it('keeps a multi-call single-path ancestor on its original aggregate meter', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'capture', async () => {
      await f.support(async () => { await f.readSupport(); await f.readSupport(); }); await f.readPoint();
    }, { paths: [f.point], maxCalls: 2 }))).rejects.toMatchObject(limited);
    expect(f.genericRequest).not.toHaveBeenCalled(); expect(f.state.supportReads).toBe(2);
  });

  it('preserves the real operation meter while separating its inherited local authorization observer', async () => {
    const f = validationMeterFixture(); let local: unknown, operation: unknown, total: unknown;
    await f.run(async () => {
      await f.context.runOperation({ actor: f.namespace.actor, clusterId: f.cluster.id, workspaceId: f.namespace.workspaceId,
        operationId: 'source-controlled-operation', entityType: 'services' }, async () => {
        await f.context.runInternalRead(f.cluster.id, 'authorization', async () => {
          expect(f.context.current().operation?.operationId).toBe('source-controlled-operation');
          await f.support(() => f.readSupport()); await f.readPoint(); local = f.context.currentUsage();
        }, { paths: [f.point], maxCalls: 1 });
        operation = f.context.currentUsage();
      });
      total = f.context.currentUsage();
    });
    expect(local).toMatchObject({ calls: 1, pages: 0 });
    expect(operation).toMatchObject({ calls: 2, pages: 1 }); expect(total).toMatchObject({ calls: 2, pages: 1 });
  });

  it('keeps the original planned GET retry bounded by its one-call local meter', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', async () => {
      await f.support(() => f.readSupport()); const ticket = await f.requestPoint();
      expect(() => f.context.chargeRetry(ticket)).toThrow();
    }, { paths: [f.point], maxCalls: 1 }));
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({ frame: { kind: 'internal-read', purpose: 'operation-check' }, budgetKind: 'calls', limit: 1, current: 2 }));
  });

  it('retains the actual validation call ceiling for its retry', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', () =>
      f.support(() => f.readSupport(undefined, true), { maxCalls: 1 }), { paths: [f.point], maxCalls: 1 }))).rejects.toMatchObject(limited);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({ frame: { kind: 'workflow-validation-read', purpose: 'configuration' }, budgetKind: 'calls', limit: 1, current: 2 }));
  });

  it.each(['bytes', 'records', 'pages'] as const)('retains the validation %s ceiling independently of a point observer', async kind => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', () => f.support(async () => {
      const result = kind === 'bytes' ? { data: [{ value: 's'.repeat(64) }], next: null }
        : kind === 'records' ? { data: [{ id: 'a' }, { id: 'b' }], next: null } : { data: [], next: null };
      await f.readSupport(result); if (kind === 'pages') await f.readSupport(result);
    }, { [kind === 'bytes' ? 'maxBytes' : kind === 'records' ? 'maxRecords' : 'maxPages']: 1 }),
    { paths: [f.point], maxCalls: 1 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_RESPONSE_LIMIT' } });
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({ frame: { kind: 'workflow-validation-read', purpose: 'configuration' }, budgetKind: kind, limit: 1 }));
  });

  it('keeps support pages inside the Namespace aggregate response limit', async () => {
    const f = validationMeterFixture();
    await f.run(async () => {
      for (let index = 0; index < 10; index++) await f.support(async () => {
        for (let page = 0; page < 10; page++) await f.readSupport({ data: [], next: null });
      });
      await expect(f.support(() => f.readSupport({ data: [], next: null }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_RESPONSE_LIMIT' } });
    });
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({ frame: { kind: 'scheduled-workflow', purpose: 'configuration' }, budgetKind: 'pages', limit: 100, current: 101 }));
  });

  it('uses the same local meter rule for genuine SDK404 observations and FK absence', async () => {
    const f = fixedValidationFixture(); f.outbound.mockClear(); const { parent, child } = fixedParentChild(f);
    const point = '/services/11111111-1111-4111-8111-111111111111'; let local: unknown, total: unknown;
    f.generic.mockImplementation(async (_: unknown, result: unknown) => result);
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => {
      await f.context.runInternalRead(f.cid, 'operation-check', async () => {
        await f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db, async (_: unknown, observations: Map<string, any>) => {
          expect([...observations.values()].map(o => o.absence)).toEqual(['sdk404', 'parent-FK-absence']);
        });
        const ticket = await f.context.authorizeRequest({ id: f.cid, admin_url: 'http://kong:8001' } as any, 'GET', point, undefined, {});
        await f.context.authorizeResponse(ticket, { id: point.split('/').at(-1) }); local = f.context.currentUsage();
      }, { paths: [point], maxCalls: 1 });
      total = f.context.currentUsage();
    });
    expect(parent.entityId).toBe(child.parentId); expect(local).toMatchObject({ calls: 1 }); expect(total).toMatchObject({ calls: 2 });
    expect(f.outbound).toHaveBeenCalledTimes(1); expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('does not ignore an original local frame closed during a detached support wait', async () => {
    const f = validationMeterFixture(); let resume!: () => void, started!: () => void, detached!: Promise<unknown>;
    const wait = new Promise<void>(resolve => { resume = resolve; }), entered = new Promise<void>(resolve => { started = resolve; });
    await f.run(async () => {
      await f.context.runInternalRead(f.cluster.id, 'operation-check', async () => {
        detached = f.support(async () => { started(); await wait; await f.readSupport(); });
        await entered;
      }, { paths: [f.point], maxCalls: 1 });
      resume(); await expect(detached).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    });
    expect(f.allocate).not.toHaveBeenCalled();
  });

  it('does not ignore original lease loss while a support response waits', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', () => f.support(async () => {
      const ticket = await f.context.authorizeRequest(f.cluster, 'GET', '/services', undefined, {});
      f.state.live = false; await f.context.authorizeResponse(ticket, { data: [], next: null });
    }), { paths: [f.point], maxCalls: 1 }))).rejects.toThrow('ORIGINAL_CURRENT_VALIDATION_REQUIRED');
    expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it('keeps ordinary nested reads charged to their original parent', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'capture', async () => {
      await f.context.runInternalRead(f.cluster.id, 'entity-preflight', f.readPoint);
      await expect(f.context.runInternalRead(f.cluster.id, 'entity-preflight', f.readPoint)).rejects.toMatchObject(limited);
    }, { paths: [f.point], maxCalls: 1 }));
    expect(f.genericRequest).toHaveBeenCalledTimes(2);
  });

  it('preserves every original ancestor deadline during support response waits', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', () => f.support(async () => {
      vi.advanceTimersByTime(5001); await f.readSupport();
    }), { paths: [f.point], maxCalls: 1, timeoutMs: 5000 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(f.allocate).not.toHaveBeenCalled();
  });

  it('logs only bounded structural budget facts and keeps the original public denial', async () => {
    const f = validationMeterFixture(), warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', async () => {
      await f.readPoint(); await expect(f.requestPoint()).rejects.toMatchObject(limited);
    }, { paths: [f.point], maxCalls: 1 }));
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toEqual({ event: 'kong_execution_budget_exceeded', frame: { kind: 'internal-read', purpose: 'operation-check' }, budgetKind: 'calls', limit: 1, current: 2 });
  });

  it('keeps the original public limit denial when the synchronous diagnostic sink fails', async () => {
    const f = validationMeterFixture(); vi.mocked(Logger.prototype.warn).mockImplementation(() => { throw Error('SOURCE_LOG_SINK_UNAVAILABLE'); });
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', async () => {
      await f.readPoint(); await expect(f.requestPoint()).rejects.toMatchObject(limited);
    }, { paths: [f.point], maxCalls: 1 }));
  });

  it('identifies the expired authorization scope without exposing request or principal data', async () => {
    const f = validationMeterFixture(), warn = vi.mocked(Logger.prototype.warn);
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'authorization', async () => {
      vi.advanceTimersByTime(10_001);
      f.context.current();
    }, { paths: [f.point], maxCalls: 1 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toEqual({ event: 'kong_execution_context_expired',
      frame: { kind: 'internal-read', purpose: 'authorization' }, reason: 'deadline', timeoutMs: 10_000, usage:{calls:0,pages:0,records:0,bytes:0}, overdueMs: 1 });
    const logged = JSON.stringify(warn.mock.calls);
    for (const privateValue of [f.cluster.id, f.namespace.actor.id, f.namespace.workspaceId, f.point]) expect(logged).not.toContain(privateValue);
    expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it('reports a closed callback distinctly and emits its structural diagnostic only once', async () => {
    const f = validationMeterFixture(), warn = vi.mocked(Logger.prototype.warn); let late!: () => Promise<void>;
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'authorization', async () => {
      const { AsyncResource } = await import('node:async_hooks');
      const resource = new AsyncResource('source-expired-context-diagnostic');
      late = () => resource.runInAsyncScope(async () => { f.context.current(); });
    }, { paths: [f.point], maxCalls: 1 }));
    await expect(late()).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    await expect(late()).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toMatchObject({ event: 'kong_execution_context_expired', reason: 'closed', overdueMs: null });
    expect(f.allocate).not.toHaveBeenCalled();
  });

  it('preserves context expiration when the structural diagnostic sink throws', async () => {
    const f = validationMeterFixture(); vi.mocked(Logger.prototype.warn).mockImplementation(() => { throw Error('SOURCE_LOG_SINK_UNAVAILABLE'); });
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'authorization', async () => {
      vi.advanceTimersByTime(10_001); f.context.current();
    }, { paths: [f.point], maxCalls: 1 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
  });

  it('rejects copied original tickets instead of granting their validation meter domain', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'operation-check', () => f.support(async () => {
      const ticket = await f.context.authorizeRequest(f.cluster, 'GET', '/services', undefined, {}), copy = { ...ticket };
      expect(() => f.context.chargeRetry(copy as any)).toThrow();
      await expect(f.context.authorizeResponse(copy as any, { data: [], next: null })).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_TICKET_INVALID' } });
      await f.context.authorizeResponse(ticket, { data: [], next: null });
    }), { paths: [f.point], maxCalls: 1 }));
    expect(f.allocate).toHaveBeenCalledTimes(1);
  });
});
