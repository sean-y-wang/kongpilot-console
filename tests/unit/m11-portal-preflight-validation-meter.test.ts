import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { validationMeterFixture } from './helpers/m11-validation-meter-fixture';
import { fixedValidationFixture, fixedParentChild } from './helpers/m11-fixed-validation-reader-fixture';

/** Source-only accounting regressions. The fixed fixture owns original
 * validation handles and runs the real provider, Root reader, SDK and Context.
 * SQL/current eligibility and transport responses are controlled; no Native
 * write, live database, HTTP request or production authority is exercised. */
beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T17:00:00Z'));
  vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });
const limited = { response: { code: 'KONG_EXECUTION_CALL_LIMIT' } };
const responseLimited = { response: { code: 'KONG_EXECUTION_RESPONSE_LIMIT' } };

describe('genuine scheduled support inside the SDK four-call entity preflight (Source only)', () => {
  it.each(['schema', 'point'] as const)
  ('retains actual SDK %s preflight after five fixed-provider support GETs', async kind => {
    const f = fixedValidationFixture(); f.outbound.mockClear();
    const resource = f.values.resources[0];
    f.values.resources = Array.from({ length: 5 }, () => {
      const entityId = randomUUID(); return { ...resource, entityId, path: `/services/${entityId}` };
    });
    f.values.present = new Set(f.values.resources.map((r: any) => r.path));
    const point = `/consumers/${randomUUID()}`, businessPath = kind === 'schema' ? '/schemas/consumers' : point;
    const outbound = f.outbound.getMockImplementation()!;
    const businessPackets: string[] = [], supportUsage: unknown[] = [];
    f.outbound.mockImplementation(async (...args: any[]) => {
      if (args[1] !== businessPath) return (outbound as any)(...args);
      if (args[2] !== 'GET') throw Error('SOURCE_FIXTURE_MUST_NOT_SEND_NATIVE');
      await args[8]?.(); args[7]?.(); businessPackets.push(args[1]);
      return { status: 200, body: kind === 'schema' ? { fields: [] } : { id: point.split('/').at(-1) }, bytes: 20, jsonParsed: true };
    });
    f.generic.mockImplementation(async (_: unknown, result: unknown) => result);
    const policy = (f.context as any).workflowScheduledPolicy, verify = policy.verifyHandle;
    let armed = false, local: unknown, total: unknown;
    policy.verifyHandle = async (handle: object, checkpoint: string) => {
      const proof = await verify(handle, checkpoint);
      if (armed && checkpoint === 'capture') {
        armed = false;
        await f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db,
          async (_: unknown, observations: Map<string, unknown>, usage: unknown) => {
            expect(observations.size).toBe(5); supportUsage.push(usage);
          });
      }
      return proof;
    };
    // These are the SDK's actual fixed maxCalls:4 wrappers. The probe records
    // their real local meter without replacing the Context implementation.
    const originalRun = f.context.runInternalRead.bind(f.context);
    vi.spyOn(f.context, 'runInternalRead').mockImplementation(((cid: string, purpose: any, fn: () => Promise<unknown>, limits: any) =>
      originalRun(cid, purpose, async () => { const result = await fn(); local = f.context.currentUsage(); return result; }, limits)) as any);
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => {
      armed = true;
      try {
        if (kind === 'schema') await (f.kong as any).validateBody(f.cid, '/consumers', 'consumers', {});
        else await (f.kong as any).protectedRead(f.cid, point);
      } catch (error) {
        // Preserve a precise, bounded counterexample when this same test runs
        // against original Source through the isolated Context-only alias.
        expect(error).toMatchObject(limited);
        const diagnostic = vi.mocked(Logger.prototype.warn).mock.calls.at(-1)?.[0];
        expect(diagnostic).toEqual({ event: 'kong_execution_budget_exceeded', frame: { kind: 'internal-read', purpose: 'entity-preflight' },
          budgetKind: 'calls', limit: 4, current: 5 });
        expect(businessPackets).toEqual([]); expect(f.db.exec).not.toHaveBeenCalled();
        expect(f.outbound.mock.calls.every(call => call[2] === 'GET')).toBe(true);
        console.info({ sourceCounterexample: kind, diagnostic, supportPacketsSent: f.outbound.mock.calls.length, businessPacketsSent: businessPackets.length, nativeWritesSent: 0 });
        throw error;
      }
      total = f.context.currentUsage();
    });
    expect(local).toMatchObject({ calls: 1, pages: 0, records: 0 });
    expect(total).toMatchObject({ calls: 6, pages: 0, records: 0 });
    expect(supportUsage).toEqual([expect.objectContaining({ calls: 5 })]);
    expect(f.business.authorizeResponse).toHaveBeenCalledTimes(5);
    expect(f.outbound).toHaveBeenCalledTimes(6); expect(businessPackets).toEqual([businessPath]);
    expect(f.outbound.mock.calls.every(call => call[2] === 'GET')).toBe(true);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('keeps the fifth business GET bounded by the original four-call preflight', async () => {
    const f = validationMeterFixture(); let local: unknown;
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      await f.support(async () => { for (let index = 0; index < 5; index++) await f.readSupport(); });
      for (let index = 0; index < 4; index++) await f.readPoint();
      local = f.context.currentUsage(); await expect(f.requestPoint()).rejects.toMatchObject(limited);
    }, { paths: [f.point], maxCalls: 4 }));
    expect(local).toMatchObject({ calls: 4 }); expect(f.state.supportReads).toBe(5);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'internal-read', purpose: 'entity-preflight' }, budgetKind: 'calls', limit: 4, current: 5 }));
  });

  it('keeps the fifth business attempt bounded when the GET retries', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      await f.support(() => f.readSupport()); const ticket = await f.requestPoint();
      for (let retry = 0; retry < 3; retry++) f.context.chargeRetry(ticket);
      expect(f.context.currentUsage()).toMatchObject({ calls: 4 });
      expect(() => f.context.chargeRetry(ticket)).toThrow();
    }, { paths: [f.point], maxCalls: 4 }));
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'internal-read', purpose: 'entity-preflight' }, budgetKind: 'calls', limit: 4, current: 5 }));
  });

  it('retains the fifth support-call denial on its own four-call meter', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', () => f.support(async () => {
      for (let index = 0; index < 5; index++) await f.readSupport();
    }, { maxCalls: 4 }), { paths: [f.point], maxCalls: 4 }))).rejects.toMatchObject(limited);
    expect(f.state.supportReads).toBe(4); expect(f.genericRequest).not.toHaveBeenCalled();
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'workflow-validation-read', purpose: 'configuration' }, budgetKind: 'calls', limit: 4, current: 5 }));
  });

  it('charges support retries and response bytes/pages/records to validation and Namespace only', async () => {
    const f = validationMeterFixture(); let local: unknown, support: unknown, total: unknown;
    await f.run(async () => {
      await f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
        await f.support(async () => {
          for (let page = 0; page < 2; page++) await f.readSupport({ data: [{ id: 'a' }, { id: 'b' }], next: null }, page === 0);
          support = f.context.currentUsage();
        });
        await f.readPoint(); local = f.context.currentUsage();
      }, { paths: [f.point], maxCalls: 4, maxPages: 1, maxRecords: 1, maxBytes: 64 });
      total = f.context.currentUsage();
    });
    const pointBytes = Buffer.byteLength(JSON.stringify({ id: f.point.split('/').at(-1) }));
    expect(local).toEqual({ calls: 1, pages: 0, records: 0, bytes: pointBytes });
    expect(support).toMatchObject({ calls: 3, pages: 2, records: 4 });
    expect(total).toMatchObject({ calls: 4, pages: 2, records: 4 });
    expect((total as any).bytes).toBe((support as any).bytes + pointBytes);
  });

  it('retains the support retry ceiling even under the four-call business preflight', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', () =>
      f.support(() => f.readSupport(undefined, true), { maxCalls: 1 }), { paths: [f.point], maxCalls: 4 }))).rejects.toMatchObject(limited);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'workflow-validation-read', purpose: 'configuration' }, budgetKind: 'calls', limit: 1, current: 2 }));
  });

  it.each(['bytes', 'records', 'pages'] as const)('retains the support %s ceiling under the four-call business preflight', async kind => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', () => f.support(async () => {
      const result = kind === 'bytes' ? { data: [{ value: 's'.repeat(64) }], next: null }
        : kind === 'records' ? { data: [{ id: 'a' }, { id: 'b' }], next: null } : { data: [], next: null };
      await f.readSupport(result); if (kind === 'pages') await f.readSupport(result);
    }, { [kind === 'bytes' ? 'maxBytes' : kind === 'records' ? 'maxRecords' : 'maxPages']: 1 }),
    { paths: [f.point], maxCalls: 4 }))).rejects.toMatchObject(responseLimited);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'workflow-validation-read', purpose: 'configuration' }, budgetKind: kind, limit: 1 }));
  });

  it.each(['bytes', 'records', 'pages'] as const)('retains the business %s ceiling after independent support', async kind => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      await f.support(() => f.readSupport({ data: [{ value: 'support'.repeat(32) }, { id: 'b' }], next: null }));
      const result = kind === 'bytes' ? { value: 'business' }
        : kind === 'records' ? { data: [{ id: 'a' }, { id: 'b' }], next: null } : { data: [], next: null };
      await f.context.authorizeResponse(await f.requestPoint(), result);
      if (kind === 'pages') await f.context.authorizeResponse(await f.requestPoint(), result);
    }, { paths: [f.point], maxCalls: 4,
      [kind === 'bytes' ? 'maxBytes' : kind === 'records' ? 'maxRecords' : 'maxPages']: 1 }))).rejects.toMatchObject(responseLimited);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'internal-read', purpose: 'entity-preflight' }, budgetKind: kind, limit: 1 }));
  });

  it('retains the Namespace 1000-call scheduled configuration aggregate (user-approved 2026-10-24) across fixed support groups', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      for (let group = 0; group < 50; group++) await f.support(async () => {
        for (let packet = 0; packet < 20; packet++) await f.readSupport({ id: 'support' });
      }, { maxCalls: 20 });
      expect(f.context.currentUsage()).toMatchObject({ calls: 0 });
      await expect(f.support(() => f.readSupport({ id: 'support' }))).rejects.toMatchObject(limited);
    }, { paths: [f.point], maxCalls: 4 }));
    expect(f.state.supportReads).toBe(1000);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'scheduled-workflow', purpose: 'configuration' }, budgetKind: 'calls', limit: 1000, current: 1001 }));
  });

  it.each([2, 3, 5])('keeps a single-path entity preflight with maxCalls:%s on its original aggregate meter', async maxCalls => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      await f.support(async () => { for (let index = 0; index < maxCalls; index++) await f.readSupport({ id: 'support' }); });
      await f.readPoint();
    }, { paths: [f.point], maxCalls }))).rejects.toMatchObject(limited);
    expect(f.state.supportReads).toBe(maxCalls); expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it.each(['capture', 'authorization', 'operation-check'] as const)
  ('keeps a non-entity %s four-call observer on its original aggregate meter', async purpose => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, purpose, async () => {
      await f.support(async () => { for (let index = 0; index < 4; index++) await f.readSupport({ id: 'support' }); });
      await f.readPoint();
    }, { paths: [f.point], maxCalls: 4 }))).rejects.toMatchObject(limited);
    expect(f.state.supportReads).toBe(4); expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it.each(['multiple-paths', 'no-paths'] as const)
  ('keeps a %s four-call entity preflight on its original aggregate meter', async reason => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      await f.support(async () => { for (let index = 0; index < 4; index++) await f.readSupport({ id: 'support' }); });
      await f.readPoint();
    }, { ...(reason === 'multiple-paths' ? { paths: [f.point, '/services'] } : {}), maxCalls: 4 }))).rejects.toMatchObject(limited);
    expect(f.state.supportReads).toBe(4); expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it('keeps a four-call descendant created inside validation on its own meter', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.support(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      for (let index = 0; index < 4; index++) await f.readSupport({ id: 'support' });
      await expect(f.readSupport()).rejects.toMatchObject(limited);
    }, { paths: ['/services'], maxCalls: 4 })));
    expect(f.state.supportReads).toBe(4);
    expect(Logger.prototype.warn).toHaveBeenCalledWith(expect.objectContaining({
      frame: { kind: 'internal-read', purpose: 'entity-preflight' }, budgetKind: 'calls', limit: 4, current: 5 }));
  });

  it('does not separate ordinary nested reads from their original four-call parent', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      for (let index = 0; index < 4; index++) await f.context.runInternalRead(f.cluster.id, 'capture', f.readPoint);
      await expect(f.context.runInternalRead(f.cluster.id, 'capture', f.readPoint)).rejects.toMatchObject(limited);
    }, { paths: [f.point], maxCalls: 4 }));
    expect(f.genericRequest).toHaveBeenCalledTimes(8);
  });

  it('retains the real operation aggregate while separating its inherited preflight', async () => {
    const f = validationMeterFixture(); let local: unknown, operation: unknown;
    await f.run(() => f.context.runOperation({ actor: f.namespace.actor, clusterId: f.cluster.id, workspaceId: f.namespace.workspaceId,
      operationId: 'source-controlled-operation', entityType: 'services' }, async () => {
      await f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
        await f.support(async () => { for (let index = 0; index < 5; index++) await f.readSupport(); });
        await f.readPoint(); local = f.context.currentUsage();
      }, { paths: [f.point], maxCalls: 4 });
      operation = f.context.currentUsage();
    }));
    expect(local).toMatchObject({ calls: 1, pages: 0 }); expect(operation).toMatchObject({ calls: 6, pages: 5 });
  });

  it('uses the same original four-call local rule for genuine SDK404 and inferred child absence', async () => {
    const f = fixedValidationFixture(); f.outbound.mockClear(); fixedParentChild(f);
    const point = `/services/${randomUUID()}`; let local: unknown, total: unknown;
    f.generic.mockImplementation(async (_: unknown, result: unknown) => result);
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => {
      await f.context.runInternalRead(f.cid, 'entity-preflight', async () => {
        await f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db,
          async (_: unknown, observations: Map<string, any>) => {
            expect([...observations.values()].map(o => o.absence)).toEqual(['sdk404', 'parent-FK-absence']);
          });
        for (let index = 0; index < 4; index++) {
          const ticket = await f.context.authorizeRequest({ id: f.cid, admin_url: 'http://kong:8001' } as any, 'GET', point, undefined, {});
          await f.context.authorizeResponse(ticket, { id: point.split('/').at(-1) });
        }
        local = f.context.currentUsage();
      }, { paths: [point], maxCalls: 4 });
      total = f.context.currentUsage();
    });
    expect(local).toMatchObject({ calls: 4 }); expect(total).toMatchObject({ calls: 5 });
    expect(f.outbound).toHaveBeenCalledTimes(1); expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('retains the original preflight deadline during a support wait', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', () => f.support(async () => {
      vi.advanceTimersByTime(5001); await f.readSupport();
    }), { paths: [f.point], maxCalls: 4, timeoutMs: 5000 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(f.allocate).not.toHaveBeenCalled();
  });

  it('retains closure of the exact original preflight during a detached support wait', async () => {
    const f = validationMeterFixture(); let resume!: () => void, started!: () => void, detached!: Promise<unknown>;
    const wait = new Promise<void>(resolve => { resume = resolve; }), entered = new Promise<void>(resolve => { started = resolve; });
    await f.run(async () => {
      await f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
        detached = f.support(async () => { started(); await wait; await f.readSupport(); }); await entered;
      }, { paths: [f.point], maxCalls: 4 });
      resume(); await expect(detached).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    });
    expect(f.allocate).not.toHaveBeenCalled();
  });

  it('revalidates current support authority while the response waits', async () => {
    const f = validationMeterFixture();
    await expect(f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', () => f.support(async () => {
      const ticket = await f.context.authorizeRequest(f.cluster, 'GET', '/services', undefined, {});
      f.state.live = false; await f.context.authorizeResponse(ticket, { data: [], next: null });
    }), { paths: [f.point], maxCalls: 4 }))).rejects.toThrow('ORIGINAL_CURRENT_VALIDATION_REQUIRED');
    expect(f.genericRequest).not.toHaveBeenCalled();
  });

  it('retains real provider current-grant revalidation after a support transport await', async () => {
    const f = fixedValidationFixture(); f.outbound.mockClear();
    f.values.present = new Set(f.values.resources.map((resource: any) => resource.path));
    const outbound = f.outbound.getMockImplementation()!;
    f.outbound.mockImplementation(async (...args: any[]) => {
      const result = await (outbound as any)(...args); f.values.read = false; return result;
    });
    await expect(f.context.runWorkflowScheduledNamespace(f.nsHandle, () => f.context.runInternalRead(f.cid, 'entity-preflight', () =>
      f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db, async () => undefined),
    { paths: [`/consumers/${randomUUID()}`], maxCalls: 4 }))).rejects.toThrow();
    expect(f.outbound).toHaveBeenCalledTimes(1); expect(f.generic).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects a copied provider handle after its legitimate group has closed', async () => {
    const f = fixedValidationFixture(); f.outbound.mockClear();
    f.values.present = new Set(f.values.resources.map((resource: any) => resource.path));
    const authorize = vi.spyOn(f.service, 'authorizeRequest');
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, () => f.context.runInternalRead(f.cid, 'entity-preflight', async () => {
      await f.runtime.withLiveReads(f.nsHandle, f.plan.workflowId, f.owner, 'executor', f.db, async () => undefined);
      const original = authorize.mock.calls[0][0];
      expect(original).toBeTruthy(); expect(f.context.current().kind).toBe('internal-read');
      await expect(f.context.runWorkflowScheduledValidationRead({ ...original }, f.nsHandle, async () => undefined))
        .rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_HANDLE_REQUIRED' } });
    }, { paths: [`/consumers/${randomUUID()}`], maxCalls: 4 }));
    expect(f.outbound).toHaveBeenCalledTimes(1); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects copied tickets and plain frame lookalikes', async () => {
    const f = validationMeterFixture();
    await f.run(() => f.context.runInternalRead(f.cluster.id, 'entity-preflight', async () => {
      const originalFrame = f.context.current();
      await f.support(async () => {
        const ticket = await f.context.authorizeRequest(f.cluster, 'GET', '/services', undefined, {}), copy = { ...ticket };
        expect(() => f.context.chargeRetry(copy as any)).toThrow();
        await expect(f.context.authorizeResponse(copy as any, { data: [], next: null })).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_TICKET_INVALID' } });
        await f.context.authorizeResponse(ticket, { data: [], next: null });
      });
      await expect((f.context as any).storage.run({ ...originalFrame }, () => f.support(() => f.readSupport())))
        .rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
      await f.readPoint(); expect(f.context.currentUsage()).toMatchObject({ calls: 1 });
    }, { paths: [f.point], maxCalls: 4 }));
    expect(f.allocate).toHaveBeenCalledTimes(1);
  });
});
