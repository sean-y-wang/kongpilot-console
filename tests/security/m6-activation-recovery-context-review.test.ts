import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { actor, cid, eid, id, physical, serviceId, wid, wf } from './m6-approved-fixture';

afterEach(() => vi.useRealTimers());
const reject = (fn: () => unknown, code: string) => expect(Promise.resolve().then(fn)).rejects.toMatchObject({ response: { code } });
function recoveryContextFixture(mode: 'direct' | 'approval' = 'direct') {
  const context = new KongExecutionContextService(), handle = Object.freeze({});
  let active = true;
  const proof = { executionId: eid, workflowId: wf, clusterId: cid, workspaceId: wid, transportScope: physical,
    actorId: actor.id, sessionId: id(601), permissionVersion: 'epoch-1', stepId: id(602), expiresAt: Date.now() + 120_000 };
  // Explicit server verifier fixture; context is production code. Actual SQL
  // verifier is exercised independently in activation-recovery-review.test.ts.
  const forbidden = async () => { throw new ForbiddenException({ code: 'APPROVED_EXECUTION_INVALID' }); };
  const verifier: any = { verifyExecution: forbidden, verifyStep: forbidden, mutationBinding: forbidden, bindOperation: forbidden,
    assertNative: forbidden, assertMetadata: forbidden, verifyIssueActivationRecovery: vi.fn(async (value: unknown) => {
      if (value !== handle || !active) throw new ForbiddenException({ code: 'PORTAL_RECOVERY_INVALID' }); return { ...proof };
    }) };
  context.installApprovedPolicy(verifier);
  const hooks = { authorizeRequest: vi.fn(async () => ({ platformAdmin: true })), authorizeResponse: vi.fn(async (_ticket, result) => result),
    beforeNativeSend: vi.fn(async () => undefined) };
  context.installPolicy(hooks);
  const cluster = { id: cid, admin_url: 'http://kong:8001', transport_scope: physical, version: '1.5.1', execution_mode: mode };
  const http = <T>(fn: () => Promise<T>, user: any = actor, sessionId: string | undefined = proof.sessionId, clusterId = cid, workspaceId = wid) => context.runHttp({}, async () => {
    context.bindHttpActor(user, sessionId); const close = context.captureHttpCloser();
    try { return await context.runActor({ actor: user, clusterId, workspaceId, module: 'workflows', action: 'write' }, fn); } finally { close(); }
  });
  const recover = <T>(fn: () => Promise<T>) => http(() => context.runIssueActivationRecovery(handle as any, fn));
  const operation: any = { actor, clusterId: cid, workspaceId: wid, operationId: id(620), entityType: 'services', entityId: serviceId, action: 'update' };
  return { context, cluster, hooks, proof, handle, http, recover, operation, verifier, revoke: () => { active = false; } };
}

describe('M6 independent metadata-only recovery context', () => {
  it('rejects caller IDs and copied opaque handles before executing recovery', async () => {
    const f = recoveryContextFixture(), callback = vi.fn();
    await f.http(async () => {
      await reject(() => f.context.runIssueActivationRecovery({ executionId: eid, workflowId: wf } as any, callback), 'PORTAL_RECOVERY_INVALID');
      await reject(() => f.context.runIssueActivationRecovery({ ...f.handle } as any, callback), 'PORTAL_RECOVERY_INVALID');
      await reject(() => f.context.currentIssueActivationRecovery(), 'PORTAL_RECOVERY_REQUIRED');
      await reject(() => f.context.runInternalRead(cid, 'portal-recovery-boundary', callback, { paths: ['/services'] }), 'PORTAL_BOUNDARY_READ_PERMIT_REQUIRED');
    });
    expect(callback).not.toHaveBeenCalled(); expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });

  it.each([
    ['no session', actor, undefined, cid, wid, 'PORTAL_RECOVERY_CONTEXT_INVALID'],
    ['another actor', { ...actor, id: id(777) }, id(601), cid, wid, 'PORTAL_RECOVERY_SCOPE_MISMATCH'],
    ['another session', actor, id(777), cid, wid, 'PORTAL_RECOVERY_SCOPE_MISMATCH'],
    ['another cluster', actor, id(601), id(777), wid, 'PORTAL_RECOVERY_SCOPE_MISMATCH'],
    ['another workspace', actor, id(601), cid, id(777), 'PORTAL_RECOVERY_SCOPE_MISMATCH'],
  ])('refuses %s without running the metadata callback', async (_label, user, session, clusterId, workspaceId, code) => {
    const f = recoveryContextFixture(), callback = vi.fn();
    // Pass an explicitly absent session without activating the wrapper default.
    const actualSession = session === undefined ? '' : session as string;
    await reject(() => f.http(() => f.context.runIssueActivationRecovery(f.handle as any, callback), user, actualSession, clusterId as string, workspaceId as string), code as string);
    expect(callback).not.toHaveBeenCalled();
  });

  it.each(['direct', 'approval'] as const)('blocks every native entry under %s while keeping the metadata proof live', async mode => {
    const f = recoveryContextFixture(mode), callbacks = vi.fn();
    await f.recover(async () => {
      expect(await f.context.currentIssueActivationRecovery()).toMatchObject({ executionId: eid, stepId: f.proof.stepId });
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        await reject(() => f.context.authorizeRequest(f.cluster, method, `/services/${serviceId}`, { id: serviceId }, {}), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      }
      await reject(() => f.context.runOperation(f.operation, callbacks), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.runArchiveDelete({ entryId: id(621), operationId: id(620), clusterId: cid, workspaceId: wid, nodes: [] }, callbacks), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.approvedMutationBinding({ ...f.operation, payload: {} }), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.bindApprovedOperation({ ...f.operation, payload: {} }, {} as any, id(622), {} as any), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.runManagedMetricsProvision(cid, callbacks), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.runApprovedWorkflow({} as any, callbacks), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.runApprovedStep(id(622), callbacks), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await reject(() => f.context.assertApprovedMetadataStep({} as any, {} as any), 'APPROVED_STEP_REQUIRED');
      await reject(() => f.context.runIssueActivationRecovery(f.handle as any, callbacks), 'PORTAL_RECOVERY_CONTEXT_INVALID');
    });
    expect(callbacks).not.toHaveBeenCalled(); expect(f.hooks.authorizeRequest).not.toHaveBeenCalled(); expect(f.hooks.beforeNativeSend).not.toHaveBeenCalled();
  });

  it('observes the full authentication graph only with a live recovery ancestor and strict paginated GETs', async () => {
    const f = recoveryContextFixture();
    await f.recover(() => f.context.runPortalRecoveryBoundaryRead(['/services', '/routes', '/plugins', `/consumers/${id(6)}/acls`, `/consumers/${id(6)}/key-auth/${id(603)}`], async () => {
      const frame = f.context.current(); await f.context.assertPortalRecoveryBoundaryRead(frame);
      expect(frame.operation).toBeUndefined(); expect(frame.archive).toBeUndefined(); expect(frame.sessionId).toBe(f.proof.sessionId);
      expect(frame.limits).toMatchObject({ maxCalls: 250, maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024, timeoutMs: 120000 });
      const ticket = await f.context.authorizeRequest(f.cluster, 'GET', '/plugins', undefined, { size: 100, offset: 'native-cursor' });
      await f.context.authorizeResponse(ticket, { data: [{ id: id(700) }], next: null });
      await reject(() => f.context.assertPortalRecoveryBoundaryRead({ ...frame }), 'KONG_EXECUTION_CONTEXT_EXPIRED');
      await reject(() => f.context.authorizeRequest(f.cluster, 'GET', '/certificates', undefined, {}), 'KONG_INTERNAL_PATH_FORBIDDEN');
      await reject(() => f.context.authorizeRequest(f.cluster, 'GET', '/plugins', undefined, { size: 101 }), 'PORTAL_BOUNDARY_READ_QUERY_INVALID');
      await reject(() => f.context.authorizeRequest(f.cluster, 'GET', '/plugins', undefined, { size: 100, tags: 'other-workspace' }), 'PORTAL_BOUNDARY_READ_QUERY_INVALID');
      await reject(() => f.context.authorizeRequest(f.cluster, 'PATCH', '/plugins', {}, {}), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
    }));
    expect(f.hooks.authorizeRequest).toHaveBeenCalledTimes(1);
  });

  it.each(['/consumers', `/consumers/${id(6)}/key-auth`, '/cache', '/clustering', '/schemas/services', '/plugins/schema/key-auth'])('does not expose unrelated raw or secret collections: %s', async path => {
    const f = recoveryContextFixture(), callback = vi.fn();
    await f.recover(() => reject(() => f.context.runPortalRecoveryBoundaryRead([path], callback), 'PORTAL_RECOVERY_PATH_INVALID'));
    expect(callback).not.toHaveBeenCalled();
  });

  it('refuses to accept graph responses beyond complete page and byte budgets', async () => {
    const f = recoveryContextFixture();
    await f.recover(() => f.context.runPortalRecoveryBoundaryRead(['/plugins'], async () => {
      const first = await f.context.authorizeRequest(f.cluster, 'GET', '/plugins', undefined, { size: 100 });
      await f.context.authorizeResponse(first, { data: [{ id: id(700) }], next: 'next' });
      const second = await f.context.authorizeRequest(f.cluster, 'GET', '/plugins', undefined, { size: 100, offset: 'next' });
      await reject(() => f.context.authorizeResponse(second, { data: [] }), 'KONG_EXECUTION_RESPONSE_LIMIT');
    }, { maxPages: 1 }));
    const g = recoveryContextFixture();
    await g.recover(() => g.context.runPortalRecoveryBoundaryRead(['/services'], async () => {
      const ticket = await g.context.authorizeRequest(g.cluster, 'GET', '/services', undefined, { size: 100 });
      await reject(() => g.context.authorizeResponse(ticket, { data: [{ name: 'x'.repeat(1024) }] }), 'KONG_EXECUTION_RESPONSE_LIMIT');
    }, { maxBytes: 64 }));
  });

  it('rechecks exact proof identity after awaits, including permission version and revoked claim', async () => {
    const f = recoveryContextFixture();
    await f.recover(async () => {
      f.proof.permissionVersion = 'epoch-2';
      await reject(() => f.context.currentIssueActivationRecovery(), 'PORTAL_RECOVERY_SCOPE_MISMATCH');
      f.proof.permissionVersion = 'epoch-1'; f.revoke();
      await reject(() => f.context.runPortalRecoveryBoundaryRead(['/services'], async () => undefined), 'PORTAL_RECOVERY_INVALID');
    });
  });

  it('rejects expiry and async continuations after callback or HTTP response closure', async () => {
    const f = recoveryContextFixture(); let resume!: () => void, late!: Promise<unknown>;
    const gate = new Promise<void>(resolve => { resume = resolve; });
    await f.recover(async () => { late = gate.then(() => f.context.currentIssueActivationRecovery()).catch(error => error); });
    resume(); expect(await late).toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    const g = recoveryContextFixture();
    await g.recover(async () => { const close = g.context.captureHttpCloser(); close();
      await reject(() => g.context.authorizeRequest(g.cluster, 'POST', '/consumers', {}, {}), 'KONG_EXECUTION_CONTEXT_EXPIRED');
    });
    const h = recoveryContextFixture(); h.proof.expiresAt = Date.now() - 1;
    await reject(() => h.recover(async () => undefined), 'PORTAL_RECOVERY_SCOPE_MISMATCH');
  });
});
