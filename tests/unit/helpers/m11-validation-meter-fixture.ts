import { vi } from 'vitest';
import { KongExecutionContextService } from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Source-only Context accounting fixture. Namespace/SQL eligibility and raw
 * transport observations are controlled, while frames, original handles,
 * private tickets, readonly rules and all counters are the actual Context.
 * It issues no HTTP, SQL, Native writes or production approval evidence. */
export function validationMeterFixture(options: { supportCalls?: number; supportLimits?: Record<string, number> } = {}) {
  const context = new KongExecutionContextService(), namespaceHandle = Object.freeze({});
  const cluster: any = { id: 'meter-cluster', admin_url: 'http://meter-kong:8001', revision: 1 };
  const point = '/services/11111111-1111-4111-8111-111111111111';
  const namespace: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', sessionId: null,
    actor: Object.freeze({ id: 'meter-executor', username: 'meter-executor', superAdmin: false }),
    clusterId: cluster.id, workspaceId: 'meter-workspace', kind: 'configuration_v2',
    expiresAt: new Date(Date.now() + 90000).toISOString() });
  const state = { armed: false, live: true, checkpointSupport: false, supportReads: 0, plannedReads: 0, latestHandle: null as object | null };
  const tokens = new Map<object, { proof: any; handle: object }>(), proofs = new Map<object, any>();
  const genericRequest = vi.fn(async () => { state.plannedReads++; return Object.freeze({ allowed: true }); });
  const genericResponse = vi.fn(async (_: unknown, result: unknown) => result);
  context.installPolicy({ authorizeRequest: genericRequest, authorizeResponse: genericResponse });
  const live = (handle: object) => { if (handle !== namespaceHandle || !state.live) throw Error('ORIGINAL_LIVE_NAMESPACE_REQUIRED'); };
  const allocate = vi.fn(async (handle: object) => {
    const proof = proofs.get(handle); if (!proof || !state.live) throw Error('ORIGINAL_CURRENT_VALIDATION_REQUIRED');
    const token = Object.freeze({}); tokens.set(token, { proof, handle }); return token;
  });
  context.installWorkflowScheduledValidationReadPolicy({
    async verifyHandle(handle: object, original: object, proof: object) {
      live(original); if (proof !== namespace || !proofs.has(handle)) throw Error('ORIGINAL_CURRENT_VALIDATION_REQUIRED'); return proofs.get(handle);
    },
    assertLive(handle: object) { if (!proofs.has(handle) || !state.live) throw Error('ORIGINAL_CURRENT_VALIDATION_REQUIRED'); },
    authorizeRequest: allocate,
    async verifyRequest(token: object) { const item = tokens.get(token); if (!item || !state.live) throw Error('ORIGINAL_CURRENT_TOKEN_REQUIRED'); return item.proof; },
    async authorizeResponse(token: object, response: unknown) {
      if (!tokens.has(token) || !state.live) throw Error('ORIGINAL_CURRENT_TOKEN_REQUIRED'); tokens.delete(token); return response;
    },
  });
  const support = async <T>(fn: () => Promise<T>, limits: Record<string, number> = {}) => {
    const handle = Object.freeze({});
    const proof: any = Object.freeze({ version: 1, origin: 'workflow-scheduled-validation-read', readOnly: true, sessionId: null,
      role: 'executor', actor: namespace.actor, namespace, expiresAt: new Date(Date.now() + 29000).toISOString(),
      scope: { version: 1, resources: [{ clusterId: cluster.id, workspaceId: namespace.workspaceId, path: '/services', kind: 'collection' }],
        limits: { maxCalls: 20, maxPages: 10, maxRecords: 100, maxBytes: 8192, ...options.supportLimits, ...limits } },
      registries: [{ clusterId: cluster.id, workspaceId: namespace.workspaceId, transportScope: transportScopeFor(cluster.admin_url), clusterRevision: 1, workspaceRevision: 1 }] });
    proofs.set(handle, proof); state.latestHandle = handle;
    try { return await context.runWorkflowScheduledValidationRead(handle, namespaceHandle, fn); }
    finally { proofs.delete(handle); }
  };
  const readSupport = async (response: unknown = { data: [{ id: 'support' }], next: null }, retry = false) => {
    const ticket = await context.authorizeRequest(cluster, 'GET', '/services', undefined, { size: 20 });
    await context.refreshAuthorization(ticket); if (retry) context.chargeRetry(ticket); await context.beforeNativeSend(ticket);
    state.supportReads++; return context.authorizeResponse(ticket, response);
  };
  const verifyNamespace = vi.fn(async (handle: object, checkpoint: string) => {
    live(handle);
    if (state.armed && !state.checkpointSupport && checkpoint !== 'claim') {
      state.armed = false; state.checkpointSupport = true;
      try { await support(async () => { for (let index = 0; index < (options.supportCalls ?? 1); index++) await readSupport(); }); }
      finally { state.checkpointSupport = false; }
    }
    return namespace;
  });
  context.installWorkflowScheduledNamespacePolicy({ verifyHandle: verifyNamespace, assertLive: live });
  const requestPoint = () => context.authorizeRequest(cluster, 'GET', point, undefined, {});
  const readPoint = async () => {
    const ticket = await requestPoint(); await context.refreshAuthorization(ticket); await context.beforeNativeSend(ticket);
    return context.authorizeResponse(ticket, { id: point.split('/').at(-1) });
  };
  return { context, cluster, namespaceHandle, namespace, state, point, tokens, proofs, support, readSupport, requestPoint, readPoint,
    verifyNamespace, allocate, genericRequest, genericResponse,
    run: <T>(fn: () => Promise<T>) => context.runWorkflowScheduledNamespace(namespaceHandle, fn) };
}
