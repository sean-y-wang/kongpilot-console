import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { workflowScheduledValidationBudgetMs } from '../../apps/console-api/src/infrastructure/kong/workflow-scheduled-validation-budget';
import { validationAbsenceFixture } from './helpers/workflow-scheduled-read-absence-fixture';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const outbound = vi.mocked(outboundJson);

/** Real Validation private handles and SQL current checks -> Context -> SDK;
 * current SQL rows, original namespace issuance and transport are controlled
 * Source adapters. Counts/modelled SQL delay are not production timings. */
function fixture(kind: 'configuration_v2' | 'portal-credential-issue' = 'configuration_v2') {
  const f = validationAbsenceFixture(false, kind), context = new KongExecutionContextService();
  f.redis.rateLimit = vi.fn(async () => ({ allowed: true }));
  const kong = new KongService(f.db, f.redis, f.secrets, {} as any, context);
  const ordinary = vi.fn(async () => { throw new Error('ORDINARY_HTTP_OR_NATIVE_AUTHORITY_MUST_NOT_RUN'); });
  context.installPolicy({ authorizeRequest: ordinary, authorizeResponse: ordinary });
  const live = (handle: object) => {
    if (handle !== f.nsHandle || !f.values.live || !f.state.lease) throw new ForbiddenException({ code: 'SOURCE_CURRENT_NAMESPACE_LEASE_REQUIRED' });
  };
  context.installWorkflowScheduledNamespacePolicy({ verifyHandle: async handle => { live(handle); return f.ns; }, assertLive: live });
  f.runner.originalNamespaceProof.mockImplementation((handle: object) => context.requireWorkflowScheduledCurrentPrincipal(handle).namespace);
  f.runner.assertNamespaceLive.mockImplementation(live);
  f.runner.run.mockImplementation((handle: object, namespace: object, fn: () => Promise<unknown>) => context.runWorkflowScheduledValidationRead(handle, namespace, fn));
  const current = vi.spyOn(f.service as any, 'current'), verify = vi.spyOn(f.service, 'verifyHandle');
  const request = vi.fn(f.service.verifyRequest.bind(f.service));
  const provider = { verifyHandle: f.service.verifyHandle.bind(f.service), assertLive: f.service.assertLive.bind(f.service),
    authorizeRequest: f.service.authorizeRequest.bind(f.service), verifyRequest: request, authorizeResponse: f.service.authorizeResponse.bind(f.service) };
  context.installWorkflowScheduledValidationReadPolicy(provider); f.install();
  outbound.mockImplementation(async (_url, _path, method, _body, _query, _auth, _timeout, beforeSend, prepareSend) => {
    if (method !== 'GET') throw new Error('SOURCE_READ_ONLY'); await prepareSend?.(); beforeSend?.();
    return { status: 200, body: { id: f.nativeId, host: 'controlled-checkpoint-service' }, bytes: 100, jsonParsed: true };
  });
  const cluster: any = { id: f.cid, admin_url: 'http://kong:8001', version: '1.5.1', revision: 1, execution_mode: 'approval' };
  const run = (fn: (handle: object) => Promise<unknown>, role: 'executor' | 'reviewer' = 'executor') => context.runWorkflowScheduledNamespace(f.nsHandle,
    () => f.service.runValidationResources(f.nsHandle, f.cid, f.wid, f.values.resources, f.db, fn, { role, userId: role === 'executor' ? f.owner : f.approvalSet.reviewers[0].userId }));
  const stage = (name: 'refresh' | 'send' | 'response', ticket: any) => name === 'refresh' ? context.refreshAuthorization(ticket)
    : name === 'send' ? context.beforeNativeSend(ticket) : context.authorizeResponse(ticket, { id: f.nativeId, host: 'controlled-checkpoint-service' });
  const ticket = () => context.authorizeRequest(cluster, 'GET', f.values.resources[0].path, undefined, {});
  return { ...f, context, kong, current, verify, request, provider, ordinary, cluster, run, stage, ticket };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T16:00:00Z')); outbound.mockReset(); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('Validation original request checkpoints avoid same-stage repeated full SQL', () => {
  it.each(['refresh', 'send'] as const)('performs exactly one fresh current() for %s, retaining all current tables', async name => {
    const f = fixture(); await f.run(async () => {
      const ticket = await f.ticket(); f.current.mockClear(); f.request.mockClear(); f.db.one.mockClear(); f.db.query.mockClear();
      await f.stage(name, ticket);
      expect(f.request).toHaveBeenCalledOnce(); expect(f.current).toHaveBeenCalledOnce();
      const sql = [...f.db.one.mock.calls, ...f.db.query.mock.calls].map(call => call[0]).join('\n');
      for (const table of ['users', 'iam_epoch', 'iam_effective_grants', 'workflow_candidate_versions', 'workflow_approval_sets', 'workflow_approval_set_members', 'clusters', 'workspaces']) expect(sql).toContain(table);
      await f.stage('response', ticket);
    });
    expect(f.ordinary).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('keeps fresh request, actual response and post-response current checks at the response stage', async () => {
    const f = fixture(); await f.run(async () => {
      const ticket = await f.ticket(); f.current.mockClear(); f.request.mockClear();
      await f.stage('response', ticket);
      expect(f.request).toHaveBeenCalledOnce(); expect(f.current).toHaveBeenCalledTimes(3);
      expect(f.business.authorizeResponse).toHaveBeenCalledOnce();
    });
  });
  it('quantifies the same-checkpoint SQL reduction without claiming production timings', async () => {
    const count = async (emulatePriorDoubleCheck: boolean) => {
      const f = fixture(); let result!: { current: number; one: number; query: number };
      await f.run(async () => {
        const ticket = await f.ticket(); f.current.mockClear(); f.db.one.mockClear(); f.db.query.mockClear();
        // This is an explicit Source-only reconstruction of the former
        // consecutive checks, not an execution of a historical deployment.
        if (emulatePriorDoubleCheck) await (f.context as any).verifyWorkflowValidationRead(f.context.current(), f.cluster, 'GET', undefined);
        await f.stage('refresh', ticket);
        result = { current: f.current.mock.calls.length, one: f.db.one.mock.calls.length, query: f.db.query.mock.calls.length };
        await f.stage('response', ticket);
      });
      return result;
    };
    const current = await count(false), previousCheckReconstruction = await count(true);
    expect(current.current).toBe(1); expect(previousCheckReconstruction.current).toBe(2);
    expect(previousCheckReconstruction.one).toBe(current.one * 2);
    expect(previousCheckReconstruction.query).toBe(current.query * 2);
    console.info('SOURCE_ONLY_VALIDATION_CURRENT_SQL_COST', { current, previousCheckReconstruction, productionTimingClaimed: false });
  });
  it('runs the actual SDK GET pipeline and measures its actual response token checkpoint', async () => {
    const f = fixture(); await f.run(async () => {
      f.current.mockClear(); f.request.mockClear();
      await expect(f.kong.request(f.cid, 'GET', f.values.resources[0].path)).resolves.toMatchObject({ id: f.nativeId });
      // KongService GET uses its governance/synchronous transport fence. It
      // does not call the native-write refresh/beforeSend methods. Never
      // confuse explicit Context stage tests with actual SDK GET behavior.
      expect(f.request).toHaveBeenCalledTimes(1);
      expect(f.current).toHaveBeenCalledTimes(5);
    });
    expect(outbound).toHaveBeenCalledOnce(); expect(f.ordinary).not.toHaveBeenCalled();
  });
  it.each(['refresh', 'send', 'response'] as const)('detects live grant revocation before %s even after prior ticket acceptance', async name => {
    const f = fixture(); await expect(f.run(async () => {
      const ticket = await f.ticket(); f.values.read = false;
      await f.stage(name, ticket);
    })).rejects.toThrow(); expect(f.context.peek()).toBeNull(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['refresh', 'send', 'response'] as const)('requires the original proof object for %s, not a copied projection', async name => {
    const f = fixture(); await expect(f.run(async () => {
      const ticket = await f.ticket(), original = f.request.getMockImplementation()!;
      f.request.mockImplementationOnce(async token => ({ ...await original(token) }));
      await f.stage(name, ticket);
    })).rejects.toThrow(); expect(f.context.peek()).toBeNull();
  });
  it.each(['refresh', 'send', 'response'] as const)('rechecks synchronous original namespace lease after %s SQL await', async name => {
    const f = fixture(); await expect(f.run(async () => {
      const ticket = await f.ticket(), original = f.request.getMockImplementation()!;
      f.request.mockImplementationOnce(async token => { const proof = await original(token); f.state.lease = false; return proof; });
      await f.stage(name, ticket);
    })).rejects.toThrow(); expect(f.context.peek()).toBeNull();
  });
  it.each(['refresh', 'send', 'response'] as const)('rechecks current cluster transport and revision after %s SQL await', async name => {
    const f = fixture(); await expect(f.run(async () => {
      const ticket = await f.ticket(), original = f.request.getMockImplementation()!;
      f.request.mockImplementationOnce(async token => { const proof = await original(token); f.cluster.admin_url = 'http://different-kong:8001'; f.cluster.revision++; return proof; });
      await f.stage(name, ticket);
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED' } });
  });
  it.each(['refresh', 'send', 'response'] as const)('rechecks capsule expiry after %s SQL await', async name => {
    const f = fixture(); await expect(f.run(async () => {
      const ticket = await f.ticket(), original = f.request.getMockImplementation()!;
      f.request.mockImplementationOnce(async token => { const proof = await original(token);
        vi.advanceTimersByTime(workflowScheduledValidationBudgetMs(proof.namespace.kind, proof.scope) + 1); return proof; });
      await f.stage(name, ticket);
    })).rejects.toThrow(); expect(f.context.peek()).toBeNull();
  });
  it('cannot authorize a new write or use an already consumed token', async () => {
    const f = fixture(); await f.run(async () => {
      await expect(f.context.authorizeRequest(f.cluster, 'POST', '/services', { host: 'forbidden' }, {})).rejects.toThrow();
      const ticket = await f.ticket(); await f.stage('response', ticket);
      await expect(f.stage('send', ticket)).rejects.toThrow();
    }); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.ordinary).not.toHaveBeenCalled();
  });
  it('does not keep a proof cache across requests or let an earlier reviewer grant authorize the executor', async () => {
    const f = fixture(); await f.run(async () => {
      const ticket = await f.ticket(); await f.stage('response', ticket);
    }, 'reviewer');
    f.values.read = false;
    await expect(f.run(async () => { await f.kong.request(f.cid, 'GET', f.values.resources[0].path); })).rejects.toThrow();
    expect(outbound).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('completes a configuration GET after 30 seconds within its fixed real-resource budget', async () => {
    const f = fixture(); await f.run(async () => {
      expect(f.context.current().purpose).toBe('configuration'); expect(f.context.current().limits.timeoutMs).toBe(35000);
      vi.advanceTimersByTime(30001);
      await expect(f.kong.request(f.cid, 'GET', f.values.resources[0].path)).resolves.toMatchObject({ id: f.nativeId });
    });
    expect(f.context.peek()).toBeNull(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('keeps a Portal GET expired after the original 30 seconds', async () => {
    const f = fixture('portal-credential-issue');
    await expect(f.run(async () => {
      expect(f.context.current().purpose).toBeUndefined(); expect(f.context.current().limits.timeoutMs).toBe(30000);
      vi.advanceTimersByTime(30001); await f.kong.request(f.cid, 'GET', f.values.resources[0].path);
    })).rejects.toThrow(); expect(outbound).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('clamps a configuration capsule to the original namespace/claim lease instead of extending it', async () => {
    const f = fixture();
    await expect(f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => {
      vi.advanceTimersByTime(75000);
      await f.service.runValidationResources(f.nsHandle, f.cid, f.wid, f.values.resources, f.db, async () => {
        expect(f.context.current().limits.timeoutMs).toBe(15000);
        vi.advanceTimersByTime(15000);
        await expect(f.kong.request(f.cid, 'GET', f.values.resources[0].path)).rejects.toThrow();
      });
    })).rejects.toThrow();
    expect(outbound).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('cannot buy a larger budget by supplying DTO ttl or unknown validation options', async () => {
    const f = fixture(); await f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => {
      await expect(f.service.runValidationResources(f.nsHandle, f.cid, f.wid, f.values.resources, f.db, async () => {
        expect(f.context.current().limits.timeoutMs).toBe(35000);
        const ticket = await f.ticket(); await f.stage('response', ticket);
      }, { role: 'executor', userId: f.owner, ttlMs: 300000, timeoutMs: 300000 } as any)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_INPUT_INVALID' } });
    });
  });
});

describe('fixed shared resource budget does not multiply collection page limits', () => {
  it('charges only mandatory point/schema reads and one shared maxPages across all collections', () => {
    const scope: any = { version: 1, resources: [{ kind: 'point', required: true }, { kind: 'schema' }, { kind: 'point', required: false },
      { kind: 'collection', required: true }, { kind: 'collection', required: true }], limits: { maxPages: 8 } };
    expect(workflowScheduledValidationBudgetMs('configuration_v2', scope)).toBe(80000);
    expect(workflowScheduledValidationBudgetMs('portal-credential-issue', scope)).toBe(30000);
  });
  it('retains the established configuration ceiling for large server-selected workloads', () => {
    const scope: any = { version: 1, resources: Array.from({ length: 500 }, () => ({ kind: 'point', required: true })), limits: { maxPages: 100 } };
    expect(workflowScheduledValidationBudgetMs('configuration_v2', scope)).toBe(300000);
  });
});
