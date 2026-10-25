import { describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

function fixture(maxCalls = 8) {
  const context = new KongExecutionContextService(), namespaceHandle = Object.freeze({}), readHandle = Object.freeze({});
  const source: any = { id: 'source', admin_url: 'http://source:8001', revision: 1 }, target: any = { id: 'target', admin_url: 'http://target:8001', revision: 2 };
  const namespace: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', sessionId: null, actor: { id: 'executor' },
    clusterId: 'target', workspaceId: 'target-w', kind: 'configuration_v2', expiresAt: new Date(Date.now() + 60000).toISOString() });
  let leaseLive = true, current = true, namespaceCopy = false;
  const fullVerify = vi.fn(async (handle: object) => { if (handle !== namespaceHandle) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); return namespace; });
  context.installWorkflowScheduledNamespacePolicy({ verifyHandle: fullVerify, assertLive(handle) { if (handle !== namespaceHandle || !leaseLive) throw Error('ACTUAL_LEASE_REVOKED'); } });
  const proof: any = Object.freeze({ version: 1, origin: 'workflow-scheduled-validation-read', readOnly: true, sessionId: null, role: 'reviewer',
    actor: { id: 'real-reviewer' }, namespace, expiresAt: new Date(Date.now() + 29000).toISOString(), scope: { version: 1,
      limits: { maxCalls, maxPages: 2, maxRecords: 10, maxBytes: 1048576 }, resources: [
        { clusterId: 'source', workspaceId: 'source-w', path: '/services', kind: 'collection' },
        { clusterId: 'target', workspaceId: 'target-w', path: '/routes', kind: 'collection' }] }, registries: [
        { clusterId: 'source', workspaceId: 'source-w', transportScope: transportScopeFor(source.admin_url), clusterRevision: 1, workspaceRevision: 1 },
        { clusterId: 'target', workspaceId: 'target-w', transportScope: transportScopeFor(target.admin_url), clusterRevision: 2, workspaceRevision: 1 }] });
  const tokens = new WeakSet<object>();
  const verify = vi.fn(async (handle: object, originalNamespace: object, originalProof: object) => {
    if (handle !== readHandle || originalNamespace !== namespaceHandle || originalProof !== namespace || !current) throw Error('CURRENT_SQL_PRINCIPAL_CLAIM_GRANTS_DENIED');
    return namespaceCopy ? Object.freeze({ ...proof, namespace: { ...namespace } }) : proof;
  });
  const genericRequest = vi.fn(async () => { throw Error('ORDINARY_SID_POLICY_MUST_NOT_RUN'); });
  const genericResponse = vi.fn(async () => { throw Error('ORDINARY_SID_RESPONSE_MUST_NOT_RUN'); });
  context.installPolicy({ authorizeRequest: genericRequest, authorizeResponse: genericResponse });
  const allocate = vi.fn(async (handle: object, request: any) => {
    if (handle !== readHandle || !current) throw Error('CURRENT_SQL_PRINCIPAL_CLAIM_GRANTS_DENIED');
    if (request.query.offset === 'forged-offset') throw Error('CURSOR_CONTINUITY_DENIED');
    const token = Object.freeze({}); tokens.add(token); return token;
  });
  const verifyRequest = vi.fn(async (token: object) => { if (!tokens.has(token) || !current) throw Error('CURRENT_TOKEN_GRANTS_DENIED'); return proof; });
  const policy: any = { verifyHandle: verify, authorizeRequest: allocate, verifyRequest,
    assertLive(handle: object) { if (handle !== readHandle || !leaseLive) throw Error('READ_CAPSULE_CLOSED'); },
    async authorizeResponse(token: object, response: any) {
      if (!tokens.has(token) || !current || response.data.some((row: any) => row.tags.includes('team:foreign'))) throw Error('ACTUAL_ROW_GRANTS_DENIED');
      tokens.delete(token); return response;
    } };
  return { context, namespaceHandle, readHandle, namespace, proof, source, target, policy, verify, verifyRequest, allocate, fullVerify, genericRequest, genericResponse,
    revoke() { current = false; }, loseLease() { leaseLive = false; }, copyNamespace() { namespaceCopy = true; } };
}

describe('business scheduled validation reads preserve the original namespace ancestor', () => {
  it('requires the fixed provider and matching original namespace handle', async () => {
    const f = fixture();
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {})).rejects.toMatchObject({ response: { code: 'KONG_POLICY_UNAVAILABLE' } });
      f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
      await expect(f.context.runWorkflowScheduledValidationRead(f.readHandle, {}, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED' } });
      await expect(f.context.runWorkflowScheduledValidationRead({}, f.namespaceHandle, async () => {})).rejects.toThrow('CURRENT_SQL_PRINCIPAL_CLAIM_GRANTS_DENIED');
    });
    expect(f.allocate).not.toHaveBeenCalled();
  });
  it('reads exact source and target GETs without recursively entering the full business verifier', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
        expect(f.context.current().sessionId).toBeUndefined(); expect(f.context.current().actor?.id).toBe('real-reviewer');
        expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.namespaceHandle);
        for (const [cluster, path] of [[f.source, '/services'], [f.target, '/routes']] as const) {
          const ticket = await f.context.authorizeRequest(cluster, 'GET', path, undefined, { size: 20 });
          await f.context.refreshAuthorization(ticket); await f.context.beforeNativeSend(ticket);
          await expect(f.context.authorizeResponse(ticket, { data: [{ id: 'current', tags: ['team:allowed'] }], next: null })).resolves.toMatchObject({ next: null });
        }
      });
      expect(f.context.current().actor?.id).toBe('executor');
      expect(f.context.currentUsage()).toMatchObject({ calls: 2, pages: 2, records: 2 });
    });
    expect(f.fullVerify).toHaveBeenCalledTimes(1); expect(f.verifyRequest).toHaveBeenCalledTimes(6);
    expect(f.allocate).toHaveBeenCalledTimes(2); expect(f.genericRequest).not.toHaveBeenCalled(); expect(f.genericResponse).not.toHaveBeenCalled();
  });
  it('retains internal read path limits and authentic offset validation', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
      await f.context.runInternalRead('source', 'authorization', async () => {
        await expect(f.context.authorizeRequest(f.source, 'GET', '/routes', undefined, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN' } });
        await expect(f.context.authorizeRequest(f.source, 'GET', '/services', undefined, { offset: 'forged-offset' })).rejects.toThrow('CURSOR_CONTINUITY_DENIED');
      }, { paths: ['/services'] });
    }));
  });
  it.each(['POST', 'PATCH', 'DELETE'])('cannot turn the real reviewer into %s authority', async method => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
      await expect(f.context.authorizeRequest(f.target, method, '/routes', undefined, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY' } });
    })); expect(f.allocate).not.toHaveBeenCalled();
  });
  it('rejects foreign registries, revision drift, changed endpoint, bodies and undeclared paths', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
      for (const cluster of [{ ...f.source, id: 'foreign' }, { ...f.source, revision: 2 }, { ...f.source, admin_url: 'http://different:8001' }])
        await expect(f.context.authorizeRequest(cluster, 'GET', '/services', undefined, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_SCOPE_CHANGED' } });
      await expect(f.context.authorizeRequest(f.source, 'GET', '/services', {}, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY' } });
      await expect(f.context.authorizeRequest(f.source, 'GET', '/plugins', undefined, {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_PATH_FORBIDDEN' } });
    })); expect(f.allocate).not.toHaveBeenCalled();
  });
  it('requires the exact namespace proof reference from the private provider', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy); f.copyNamespace();
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED' } });
    });
  });
  it.each(['refresh', 'before-wire', 'response'])('fences current SQL revocation at %s without allocating another token', async stage => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
        const ticket = await f.context.authorizeRequest(f.source, 'GET', '/services', undefined, {}); f.revoke();
        const operation = stage === 'refresh' ? f.context.refreshAuthorization(ticket) : stage === 'before-wire' ? f.context.beforeNativeSend(ticket) : f.context.authorizeResponse(ticket, { data: [], next: null });
        await expect(operation).rejects.toThrow('CURRENT_TOKEN_GRANTS_DENIED');
      })).rejects.toThrow('CURRENT_SQL_PRINCIPAL_CLAIM_GRANTS_DENIED');
    }); expect(f.allocate).toHaveBeenCalledTimes(1);
  });
  it('checks every actual response row instead of filtering forbidden objects to EOF', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
      const ticket = await f.context.authorizeRequest(f.source, 'GET', '/services', undefined, {});
      await expect(f.context.authorizeResponse(ticket, { data: [{ id: 'foreign', tags: ['team:foreign'] }], next: null })).rejects.toThrow('ACTUAL_ROW_GRANTS_DENIED');
    }));
  });
  it('charges source and target against the same validation and root namespace budget', async () => {
    const f = fixture(1); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
      const ticket = await f.context.authorizeRequest(f.source, 'GET', '/services', undefined, {}); await f.context.authorizeResponse(ticket, { data: [], next: null });
      await expect(f.context.authorizeRequest(f.target, 'GET', '/routes', undefined, {})).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CALL_LIMIT' } });
    })); expect(f.allocate).toHaveBeenCalledTimes(1);
  });
  it('cannot get a full execution proof, detach to a config job, or adopt another validation handle', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    const config = vi.fn(async () => { throw Error('BORROWED_JOB'); }); f.context.installConfigurationJobPolicy({ verifyHandle: config });
    const approved = vi.fn(async () => { throw Error('BORROWED_EXECUTION'); });
    f.context.installApprovedPolicy({ verifyExecution: approved, async verifyStep() {}, async mutationBinding() {}, async bindOperation() {}, async assertNative() {}, async assertMetadata() {} } as any);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
      await expect(f.context.verifyWorkflowScheduledNamespace('step')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY' } });
      await expect(f.context.runConfigurationJob({}, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_JOB_ADOPTION_FORBIDDEN' } });
      await expect(f.context.runApprovedWorkflow({} as any, async () => {})).rejects.toMatchObject({ response: { code: 'APPROVED_EXECUTION_CONTEXT_INVALID' } });
      await expect(f.context.runWorkflowScheduledValidationRead({}, f.namespaceHandle, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED' } });
      await expect(f.context.runGovernanceRead({}, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY' } });
      await expect(f.context.runPromotionPlanning({}, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_READ_ONLY' } });
      expect(()=>f.context.runHttp({},()=>{})).toThrow();
    })); expect(config).not.toHaveBeenCalled(); expect(approved).not.toHaveBeenCalled();
  });
  it('losing the original lease or closing the ancestor stops existing tickets', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await expect(f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
        const ticket = await f.context.authorizeRequest(f.source, 'GET', '/services', undefined, {}); f.loseLease();
        await expect(f.context.beforeNativeSend(ticket)).rejects.toThrow('READ_CAPSULE_CLOSED');
      })).rejects.toThrow('READ_CAPSULE_CLOSED');
    });
  });
  it('cannot reuse an original handle or send through a detached continuation', async () => {
    const f = fixture(); f.context.installWorkflowScheduledValidationReadPolicy(f.policy);
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }); let detached!: Promise<unknown>;
    await f.context.runWorkflowScheduledNamespace(f.namespaceHandle, async () => {
      await f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {
        detached = (async () => { await gate; return f.context.authorizeRequest(f.source, 'GET', '/services', undefined, {}); })();
      });
      await expect(f.context.runWorkflowScheduledValidationRead(f.readHandle, f.namespaceHandle, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_REQUIRED' } });
    }); release(); await expect(detached).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
  });
});
