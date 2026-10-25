import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../apps/console-api/src/common/auth';
import { KongExecutionContextService, type KongPolicyHooks, type KongPolicyTicket } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

// These tests exercise the actual ALS/capability implementation. The policy
// callback is an explicit in-memory authorization fixture, not a live RBAC DB.
const alice: AuthUser = { id: 'alice', username: 'alice', superAdmin: false };
const bob: AuthUser = { id: 'bob', username: 'bob', superAdmin: false };
const c1 = { id: 'cluster-1', admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
const c2 = { ...c1, id: 'cluster-2', admin_url: 'http://kong-secondary:8001' };
const path = '/services/4f969920-4715-43a1-8cac-49ba8e86b232';
function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function fixture(hooks?: Partial<KongPolicyHooks>) {
  const contexts = new KongExecutionContextService();
  const policy: KongPolicyHooks = {
    authorizeRequest: vi.fn(async frame => ({ actorId: frame.actor?.id, platformAdmin: false })),
    authorizeResponse: vi.fn(async (_decision, result) => result), ...hooks,
  };
  contexts.installPolicy(policy);
  return { contexts, policy };
}
async function actor<T>(contexts: KongExecutionContextService, fn: () => Promise<T>, user = alice, cluster = c1, workspaceId = 'pay') {
  return contexts.runHttp({ requestId: `${user.id}-request` }, async () => {
    contexts.bindHttpActor(user, `${user.id}-session`);
    const close = contexts.captureHttpCloser();
    try { return await contexts.runActor({ actor: user, clusterId: cluster.id, workspaceId, module: 'services', action: 'read' }, fn); }
    finally { close(); }
  });
}
const denied = (promise: Promise<unknown>, code: string) => expect(promise).rejects.toMatchObject({ response: { code } });

describe('M4 independent native execution context security', () => {
  it('fails closed when the policy provider is missing or replacement is attempted', async () => {
    const contexts = new KongExecutionContextService();
    await denied(actor(contexts, () => contexts.authorizeRequest(c1, 'GET', path, undefined, {})), 'KONG_POLICY_UNAVAILABLE');
    const policy = { authorizeRequest: async () => ({}), authorizeResponse: async (_: unknown, value: unknown) => value };
    contexts.installPolicy(policy);
    contexts.installPolicy(policy);
    expect(() => contexts.installPolicy({ ...policy })).toThrowError();
  });

  it('cannot create an actor scope from an anonymous HTTP frame or serialized client frame', async () => {
    const { contexts, policy } = fixture();
    await denied(contexts.runHttp({}, async () => contexts.runActor({ actor: alice, clusterId: c1.id }, async () => undefined)), 'KONG_ACTOR_SCOPE_MISMATCH');
    await denied(contexts.runHttp({}, () => contexts.authorizeRequest(c1, 'GET', path, { actor: alice, kind: 'operation', operationId: 'forged' }, {})), 'KONG_CLUSTER_SCOPE_MISMATCH');
    expect(policy.authorizeRequest).not.toHaveBeenCalled();
  });

  it('binds identity after an awaited guard without losing the caller HTTP context', async () => {
    const { contexts } = fixture();
    await contexts.runHttp({ requestId: 'guard-await' }, async () => {
      const beforeAwait = contexts.current();
      expect(beforeAwait.actor).toBeUndefined();
      await Promise.resolve();
      contexts.bindHttpActor(alice, 'validated-session');
      expect(contexts.current()).toBe(beforeAwait);
      expect(beforeAwait.actor?.id).toBe(alice.id);
      expect(beforeAwait.sessionId).toBe('validated-session');
      expect(() => contexts.bindHttpActor(bob)).toThrowError();
      contexts.captureHttpCloser()();
    });
  });

  it('isolates concurrent actors, workspaces, sessions and policy tickets across awaits', async () => {
    const ready = deferred(), release = deferred();
    let arrivals = 0;
    const observed: string[] = [];
    const { contexts } = fixture({ authorizeRequest: async frame => {
      if (++arrivals === 2) ready.resolve();
      await release.promise;
      observed.push(`${frame.actor?.id}/${frame.workspaceId}/${frame.sessionId}`);
      return { actorId: frame.actor?.id };
    }, authorizeResponse: async (decision: any, result) => ({ ...result, authorizedActor: decision.actorId }) });
    const request = (user: AuthUser, cluster: typeof c1, workspace: string) => actor(contexts, async () => {
      const ticket = await contexts.authorizeRequest(cluster, 'GET', path, undefined, {});
      return contexts.authorizeResponse(ticket, { id: 'safe-public-object' });
    }, user, cluster, workspace);
    const first = request(alice, c1, 'pay'), second = request(bob, c2, 'ops');
    await ready.promise; release.resolve();
    const results = await Promise.all([first, second]);
    expect(observed.sort()).toEqual(['alice/pay/alice-session', 'bob/ops/bob-session']);
    expect(results.map(value => value.authorizedActor)).toEqual(['alice', 'bob']);
    expect(contexts.peek()).toBeNull();
  });

  it('does not upgrade the bound actor from a supplied superAdmin flag', async () => {
    const { contexts } = fixture();
    await actor(contexts, () => contexts.runActor({ actor: { ...alice, superAdmin: true }, clusterId: c1.id, workspaceId: 'pay' }, async () => {
      expect(contexts.current().actor?.superAdmin).toBe(false);
      const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
      expect(contexts.verifiedPlatformAdmin(ticket)).toBe(false);
    }));
  });

  it('uses only the verified policy decision for platform-only Lua privilege', async () => {
    const { contexts } = fixture({ authorizeRequest: async () => ({ platformAdmin: true }) });
    await actor(contexts, async () => {
      expect(contexts.current().actor?.superAdmin).toBe(false);
      const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
      expect(contexts.verifiedPlatformAdmin(ticket)).toBe(true);
    });
  });

  it('rejects a different actor or cluster before entering a nested scope', async () => {
    const { contexts, policy } = fixture();
    await actor(contexts, async () => {
      expect(() => contexts.runActor({ actor: bob, clusterId: c1.id }, async () => undefined)).toThrowError();
      expect(() => contexts.runActor({ actor: alice, clusterId: c2.id }, async () => undefined)).toThrowError();
    });
    await denied(actor(contexts, () => contexts.authorizeRequest(c2, 'GET', path, undefined, {})), 'KONG_CLUSTER_SCOPE_MISMATCH');
    expect(policy.authorizeRequest).not.toHaveBeenCalled();
  });

  it('rejects forged/copied/deserialized tickets and prevents reuse after response authorization', async () => {
    const { contexts } = fixture();
    await actor(contexts, async () => {
      const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
      for (const forged of [{}, { ...ticket }, JSON.parse(JSON.stringify(ticket)), { kind: 'operation', actor: alice }]) {
        expect(() => contexts.assertTicketActive(forged as KongPolicyTicket)).toThrowError();
      }
      expect(await contexts.authorizeResponse(ticket, { id: 'public' })).toEqual({ id: 'public' });
      expect(() => contexts.assertTicketActive(ticket)).toThrowError();
    });
  });

  it('rejects a genuine ticket in a concurrent unrelated request', async () => {
    const { contexts } = fixture();
    const ready = deferred<KongPolicyTicket>(), release = deferred();
    const first = actor(contexts, async () => {
      ready.resolve(await contexts.authorizeRequest(c1, 'GET', path, undefined, {}));
      await release.promise;
    });
    const ticket = await ready.promise;
    await actor(contexts, async () => { expect(() => contexts.assertTicketActive(ticket)).toThrowError(); }, bob);
    release.resolve(); await first;
  });

  it('closes inherited callbacks after their authorized operation returns', async () => {
    const { contexts } = fixture();
    const release = deferred();
    let late!: Promise<unknown>;
    await actor(contexts, async () => {
      const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
      late = release.promise.then(() => contexts.assertTicketActive(ticket));
    });
    const rejected = denied(late, 'KONG_EXECUTION_CONTEXT_EXPIRED');
    release.resolve(); await rejected;
  });

  it('fences a request if the HTTP lifetime closes while policy authorization is awaiting', async () => {
    const entered = deferred(), release = deferred();
    const { contexts } = fixture({ authorizeRequest: async () => { entered.resolve(); await release.promise; return {}; } });
    let close!: () => void;
    const request = contexts.runHttp({}, async () => {
      contexts.bindHttpActor(alice); close = contexts.captureHttpCloser();
      return contexts.runActor({ actor: alice, clusterId: c1.id }, () => contexts.authorizeRequest(c1, 'GET', path, undefined, {}));
    });
    await entered.promise; const rejected = denied(request, 'KONG_EXECUTION_CONTEXT_EXPIRED'); close(); release.resolve(); await rejected;
  });

  it('fences a response if the request closes while fresh response policy is awaiting', async () => {
    const entered = deferred(), release = deferred();
    const { contexts } = fixture({ authorizeResponse: async (_, result) => { entered.resolve(); await release.promise; return result; } });
    let close!: () => void;
    const request = contexts.runHttp({}, async () => {
      contexts.bindHttpActor(alice); close = contexts.captureHttpCloser();
      return contexts.runActor({ actor: alice, clusterId: c1.id }, async () => {
        const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
        return contexts.authorizeResponse(ticket, { id: 'private-after-revoke' });
      });
    });
    await entered.promise; const rejected = denied(request, 'KONG_EXECUTION_CONTEXT_EXPIRED'); close(); release.resolve(); await rejected;
  });

  it('requires a durable-operation scope for every native write and separate archive capability for DELETE', async () => {
    const { contexts, policy } = fixture();
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) await denied(actor(contexts, () => contexts.authorizeRequest(c1, method, path, {}, {})), 'KONG_NATIVE_OPERATION_REQUIRED');
    await denied(actor(contexts, () => contexts.runOperation({ actor: alice, clusterId: c1.id, workspaceId: 'pay', operationId: 'durable-op', entityType: 'services' }, () => contexts.authorizeRequest(c1, 'DELETE', path, undefined, {}))), 'KONG_RECYCLE_CAPABILITY_REQUIRED');
    expect(policy.authorizeRequest).not.toHaveBeenCalled();
  });

  it('keeps archive deletion limited to the exact recorded operation, workspace and node paths', async () => {
    const { contexts, policy } = fixture();
    await actor(contexts, () => contexts.runOperation({ actor: alice, clusterId: c1.id, workspaceId: 'pay', operationId: 'durable-op', entityType: 'services' }, async () => {
      const archive = { entryId: 'encrypted-archive', operationId: 'durable-op', clusterId: c1.id, workspaceId: 'pay', nodes: [{ path, type: 'services', id: path.split('/').at(-1)! }] };
      expect(() => contexts.runArchiveDelete({ ...archive, operationId: 'forged-op' }, async () => undefined)).toThrowError();
      expect(() => contexts.runArchiveDelete({ ...archive, workspaceId: 'ops' }, async () => undefined)).toThrowError();
      await contexts.runArchiveDelete(archive, async () => {
        await contexts.authorizeRequest(c1, 'DELETE', path, undefined, {});
        await denied(contexts.authorizeRequest(c1, 'DELETE', '/services/another-id', undefined, {}), 'KONG_RECYCLE_CAPABILITY_REQUIRED');
      });
    }));
    expect(policy.authorizeRequest).toHaveBeenCalledTimes(1);
  });

  it('still consults the durable policy hook instead of treating a factory operation ID as a DB proof', async () => {
    const { contexts } = fixture({ authorizeRequest: async frame => {
      if (frame.operation?.operationId !== 'actually-stored-operation') throw new ForbiddenException({ code: 'FIXTURE_OPERATION_NOT_DURABLE' });
      return {};
    } });
    await denied(actor(contexts, () => contexts.runOperation({ actor: alice, clusterId: c1.id, operationId: 'made-up-id', entityType: 'services' }, () => contexts.authorizeRequest(c1, 'PATCH', path, { retries: 1 }, {}))), 'FIXTURE_OPERATION_NOT_DURABLE');
  });

  it('cannot invoke actorless system scopes from a user request and bounds system probe paths', async () => {
    const { contexts } = fixture();
    await actor(contexts, async () => { expect(() => contexts.runSystemRead(c1.id, 'probe', async () => undefined)).toThrowError(); });
    await contexts.runSystemRead(c1.id, 'probe', async () => {
      await contexts.authorizeRequest(c1, 'GET', '/status', undefined, {});
      await denied(contexts.authorizeRequest(c1, 'GET', '/services', undefined, {}), 'KONG_PROBE_PATH_FORBIDDEN');
      await denied(contexts.authorizeRequest(c1, 'POST', '/services', {}, {}), 'KONG_READ_CAPABILITY_WRITE_FORBIDDEN');
      await denied(contexts.authorizeRequest(c2, 'GET', '/status', undefined, {}), 'KONG_CLUSTER_SCOPE_MISMATCH');
    });
  });

  it('bounds actorless inventory to core entity pages of at most 100 records', async () => {
    const { contexts } = fixture();
    await contexts.runSystemRead(c1.id, 'indexer', async () => {
      await contexts.authorizeRequest(c1, 'GET', '/services', undefined, { size: 100 });
      await denied(contexts.authorizeRequest(c1, 'GET', '/services', undefined, { size: 101 }), 'KONG_INDEXER_PATH_FORBIDDEN');
      await denied(contexts.authorizeRequest(c1, 'GET', path, undefined, {}), 'KONG_INDEXER_PATH_FORBIDDEN');
      await denied(contexts.authorizeRequest(c1, 'GET', '/cache', undefined, {}), 'KONG_INDEXER_PATH_FORBIDDEN');
    });
  });

  it('requires explicit authorization-read paths and refuses budget/path/nesting escalation', async () => {
    const { contexts, policy } = fixture();
    await actor(contexts, async () => {
      expect(() => contexts.runInternalRead(c1.id, 'authorization', async () => undefined)).toThrowError();
      expect(() => contexts.runInternalRead(c1.id, 'authorization', async () => undefined, { paths: [path], maxCalls: 33 })).toThrowError();
      await contexts.runInternalRead(c1.id, 'authorization', async () => {
        await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
        await denied(contexts.authorizeRequest(c1, 'GET', '/services/unapproved-id', undefined, {}), 'KONG_INTERNAL_PATH_FORBIDDEN');
        expect(() => contexts.runInternalRead(c1.id, 'capture', async () => undefined, { maxCalls: 500 })).toThrowError();
      }, { paths: [path], maxCalls: 1 });
    });
    expect(policy.authorizeRequest).toHaveBeenCalledTimes(1);
  });

  it('charges nested read calls against the parent budget instead of resetting it', async () => {
    const { contexts, policy } = fixture();
    await actor(contexts, () => contexts.runInternalRead(c1.id, 'capture', async () => {
      await contexts.runInternalRead(c1.id, 'entity-preflight', () => contexts.authorizeRequest(c1, 'GET', path, undefined, {}));
      await denied(contexts.runInternalRead(c1.id, 'entity-preflight', () => contexts.authorizeRequest(c1, 'GET', path, undefined, {})), 'KONG_EXECUTION_CALL_LIMIT');
    }, { maxCalls: 1 }));
    expect(policy.authorizeRequest).toHaveBeenCalledTimes(1);
  });

  it('never converts an internal read into a write even inside a durable operation', async () => {
    const { contexts, policy } = fixture();
    await denied(actor(contexts, () => contexts.runOperation({ actor: alice, clusterId: c1.id, operationId: 'durable-op', entityType: 'services' }, () => contexts.runInternalRead(c1.id, 'capture', () => contexts.authorizeRequest(c1, 'PATCH', path, {}, {})))), 'KONG_READ_CAPABILITY_WRITE_FORBIDDEN');
    expect(policy.authorizeRequest).not.toHaveBeenCalled();
  });

  it('charges transport retries against the same bounded private read capability', async () => {
    const { contexts } = fixture();
    await actor(contexts, () => contexts.runInternalRead(c1.id, 'authorization', async () => {
      const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
      expect(() => contexts.chargeRetry(ticket)).toThrowError();
    }, { paths: [path], maxCalls: 1 }));
  });

  it.each([
    [{ maxRecords: 1 }, { data: [{ id: 'a' }, { id: 'b' }] }],
    [{ maxBytes: 32 }, { id: 'x'.repeat(64) }],
  ])('bounds actual response consumption before returning policy-filtered data', async (limits, result) => {
    const { contexts, policy } = fixture();
    await denied(actor(contexts, () => contexts.runInternalRead(c1.id, 'capture', async () => {
      const ticket = await contexts.authorizeRequest(c1, 'GET', path, undefined, {});
      return contexts.authorizeResponse(ticket, result);
    }, limits)), 'KONG_EXECUTION_RESPONSE_LIMIT');
    expect(policy.authorizeResponse).not.toHaveBeenCalled();
  });
});
