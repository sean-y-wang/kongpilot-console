import { describe, expect, it, vi } from 'vitest';
import { METADATA_RECOVERY_DATABASE_SQL, metadataRecoveryCheckpoint, guardMetadataRecovery, reconcileOriginalMetadata } from './lib/m6-metadata-recovery.mjs';
import { M6_C1, M6_C2 } from './lib/m6-harness.mjs';
import { PENDING_KEY_TUPLE as T } from './lib/m6-pending-key-capture.mjs';
import { checkpointSha } from './lib/m6-isolated-transition.mjs';

const id = (n: number) => `50000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const operationIds = [T.consumerOperationId, T.aclOperationId, T.keyOperationId];
const nativeIds = [T.consumerId, T.aclId, T.nativeId];

function fixture() {
  const tag = 'm6-isolated-metadata-review';
  const fixtures = [T.clusterId, M6_C2, T.clusterId].map((clusterId, index) => ({
    cluster: { id: clusterId }, workspace: { id: index === 0 ? T.workspaceId : id(10 + index), code: `${tag}-${index}`, revision: 1, status: 'active' },
    settings: { id: id(20 + index), revision: 2, published: true },
    services: [{ id: id(30 + index), name: `service-${index}`, host: 'echo-upstream', protocol: 'http', port: 8081, tags: [`owner:review-${index}`] }],
    routes: [{ id: id(40 + index), name: `route-${index}`, paths: [`/owned-${index}`], protocols: ['http'], service: { id: id(30 + index) } }],
    publications: [{ id: id(50 + index), serviceId: id(30 + index), revision: 5, documentRevision: 2, status: 'published' }],
  }));
  const consoleSession = (n: number) => ({ user: { id: id(n) }, csrf: 'synthetic-console-csrf-at-least16', cookie: `kongos_refresh=${id(n + 200)}.opaque; kongos_access=synthetic-original-access` });
  const admin = consoleSession(100);
  const portalUsers = ['developer-a', 'developer-b', 'developer-c2'].map((label, index) => {
    const f = fixtures[index === 2 ? 1 : 0], tenant = { clusterId: f.cluster.id, workspaceId: f.workspace.id }, developerId = id(60 + index);
    return { id: developerId, label, tenant, session: { developer: { id: developerId, ...tenant }, csrf: 'synthetic-portal-csrf-at-least16', cookie: `kongos_portal_refresh=${id(400 + index)}.opaque; kongos_portal_access=synthetic-original-access` } };
  });
  const app = { id: id(70), name: `${tag} Application A` }, c2App = { id: id(71), name: `${tag} Application C2` };
  const plugins = ['key-auth', 'acl'].map((name, index) => ({ id: id(90 + index), name, enabled: true, service: { id: fixtures[0].services[0].id }, config: { publicFlag: true } }));
  const execute = { method: 'POST', path: `/api/v1/clusters/${T.clusterId}/workflows/${T.workflowId}/execute`, query: `?workspaceId=${T.workspaceId}`, key: T.executionKey, actorId: admin.user.id, state: 'response_observed', httpStatus: 503, errorCode: 'WORKFLOW_EXECUTION_FAILED', body: { revision: 3, planHash: 'a'.repeat(64), confirmed: true, confirm_name: 'portal-credential-issue' } };
  const request = { method: 'POST', path: '/api/v1/portal/requests', key: id(80), actorId: portalUsers[0].id, httpStatus: 201,
    body: { clusterId: T.clusterId, workspaceId: T.workspaceId, applicationId: app.id, publicationId: fixtures[0].publications[0].id }, responseData: { workflowId: T.workflowId, grant: { id: T.grantId } } };
  const purposes = [['native_scrape', 'bff'], ['collector_scrape', 'collector'], ['collector_catalog', 'bff'], ['collector_ingest', 'collector']];
  const historical = { testTag: 'm6-security-independent-prior', secrets: ['SyntheticPriorCheckpointCanary'] };
  const reference: any = { testTag: tag, phase: 'portal-publications-published', isolatedStart: {},
    priorFixtureRuns: [{ testTag: historical.testTag, checkpoint: historical, checkpointSha256: checkpointSha(historical) }], fixtures, grants: [], consoleAdministrator: admin,
    portalTestTargets: { primary: { adminUrl: 'http://kong-portal-admin-endpoint:8001', proxyOrigin: 'http://127.0.0.1:10000' }, secondary: { proxyOrigin: 'http://127.0.0.1:9000' } },
    accounts: { 'approver-only': { session: consoleSession(101) }, 'approver-c2': { session: consoleSession(102) } }, portalUsers,
    writeAttempts: [
      { path: '/api/v1/portal/applications', actorId: portalUsers[0].id, body: { name: app.name }, httpStatus: 201, responseData: { entity: app } },
      { path: '/api/v1/portal/applications', actorId: portalUsers[2].id, body: { name: c2App.name }, httpStatus: 201, responseData: { entity: c2App } },
      ...plugins.map(value => ({ path: `/api/v1/clusters/${T.clusterId}/entities/plugins`, query: `?workspaceId=${T.workspaceId}`, httpStatus: 201, responseData: { entity: value } })), request, execute,
    ], credentialContinuation: { newKey: request.key, body: request.body },
    pendingCredentialScanCaptures: [{ credentialId: T.credentialId, executionId: T.executionId, scannerOnly: true }],
    tokens: [M6_C1, M6_C2].flatMap((clusterId, family) => purposes.map(([purpose, audience], index) => ({ clusterId, generation: family ? 1 : 2, purpose, audience, token: String.fromCharCode(65 + family * 4 + index).repeat(43) }))),
  };
  const diagnostic: any = { originalExecution: { key: T.executionKey, workflowId: T.workflowId, clusterId: T.clusterId, workspaceId: T.workspaceId, status: 503, errorCode: 'WORKFLOW_EXECUTION_FAILED' },
    receipt: { state: 'uncertain', executionId: T.executionId }, native: operationIds.map((opId, index) => ({ id: opId, entity_id: nativeIds[index], state: 'succeeded', remote_completed: true, remote_started: true })),
    grant: [{ id: T.grantId, credential_id: T.credentialId, credential_state: 'pending' }] };
  return { reference, diagnostic, app, c2App, plugins, execute };
}

function receipt(state: 'uncertain' | 'succeeded') {
  return { id: T.executionId, executionId: T.executionId, workflowId: T.workflowId, clusterId: T.clusterId, workspaceId: T.workspaceId, idempotencyKey: T.executionKey, action: 'execute', state,
    revision: 4, planHash: 'a'.repeat(64), metadataRecovery: { eligible: state === 'uncertain', kind: 'portal-credential-issue', executionId: T.executionId, originalExecutionKeyRequired: true },
    steps: [ ...operationIds.map((opId, index) => ({ id: id(500 + index), name: ['consumers.create.1', 'credentials.create.2', 'credentials.create.3'][index], state: 'succeeded', operationId: opId, remoteStarted: true, remoteCompleted: true })),
      { id: T.metadataStepId, name: 'portal.credential.activate', state, operationId: null, remoteStarted: true, remoteCompleted: state === 'succeeded' } ],
  };
}

function harness() {
  const f = fixture();
  let completed = false;
  const pending: any = { credential_state: 'pending', grant_state: 'pending', generation: 1, current_generation: 0, current_credential_id: null, credential_ref_id: null, issue_operation_id: null,
    workflow_state: 'uncertain', execution_state: 'uncertain', execution_actor_id: f.reference.consoleAdministrator.user.id, plan_hash: 'a'.repeat(64), workflow_revision: 4,
    immutable_key_cipher_sha: 'b'.repeat(64), key_fingerprint: 'c'.repeat(64), native_operation_count: 3, native_unresolved: 0, portal_unresolved: 0 };
  const active = () => ({ ...pending, credential_state: 'active', grant_state: 'active', current_generation: 1, current_credential_id: T.credentialId, credential_ref_id: T.keyReferenceId,
    acl_credential_ref_id: T.aclReferenceId, issue_operation_id: T.keyOperationId, workflow_state: 'succeeded', execution_state: 'succeeded' });
  const view: any = { id: T.workflowId, kind: 'portal-credential-issue', name: 'portal-credential-issue', state: 'uncertain', planHash: 'a'.repeat(64), revision: 4, capabilities: { reconcileMetadata: true } };
  const h: any = { referenceData: f.reference, secrets: [], requireLive: vi.fn(), rememberCookies: vi.fn(),
    check: (passed: boolean) => { if (!passed) throw new Error('Synthetic original checkpoint proof failed'); },
    ok: (result: any) => { if (result?.status < 200 || result?.status >= 300 || !result) throw new Error('Synthetic response failed'); return result.value; },
    saveReference: vi.fn((extra: any) => Object.assign(f.reference, structuredClone(extra))),
  };
  h.portal = vi.fn(async (session: any, path: string, method = 'GET') => {
    if (method !== 'GET' || !path.includes('/auth/me')) throw new Error('Guard cannot submit Portal requests or authenticate new actors');
    return { status: 200, value: { ...session.developer } };
  });
  h.request = vi.fn(async (session: any, path: string, method = 'GET', body?: unknown, options?: any) => {
    if (method === 'POST') {
      if (!path.includes(`/workflows/${T.workflowId}/reconcile-metadata?`) || options?.key !== T.executionKey) throw new Error('Forbidden replay');
      expect(f.reference.metadataRecovery.phase).toBe('reconcile-request-started');
      completed = true; return { status: 201, value: receipt('succeeded'), payload: { meta: { requestId: id(800) } } };
    }
    if (method !== 'GET') throw new Error('Forbidden fixture write');
    if (path === '/auth/me') return { status: 200, value: { id: session.user.id } };
    if (path.includes('/workflows/receipts/by-key/')) return { status: 200, value: receipt(completed ? 'succeeded' : 'uncertain') };
    if (path.includes(`/workflows/${T.workflowId}?`)) return { status: 200, value: { entity: view } };
    if (path === `/clusters/${T.clusterId}/consumers/${T.consumerId}/credentials/acls/${T.aclId}?workspaceId=${T.workspaceId}`) return { status: 200, value: { entity: { id: T.aclId, consumer: { id: T.consumerId } } } };
    if (path === `/clusters/${T.clusterId}/consumers/${T.consumerId}/credentials/key-auth/${T.nativeId}?workspaceId=${T.workspaceId}`) return { status: 200, value: { entity: { id: T.nativeId, consumer: { id: T.consumerId }, key: '[REDACTED]' } } };
    if (path.includes(`/entities/consumers/${T.consumerId}?`)) return { status: 200, value: { entity: { id: T.consumerId } } };
    for (const row of f.reference.fixtures) {
      if (path.endsWith(`/workspaces/${row.workspace.id}`)) return { status: 200, value: { ...row.workspace } };
      if (new URL(path, 'http://synthetic.invalid').searchParams.get('workspaceId') !== row.workspace.id) continue;
      if (path.includes('/portal/settings?')) return { status: 200, value: { settings: { ...row.settings } } };
      for (const type of ['services', 'routes', 'publications']) for (const value of row[type]) if (path.includes(`/${value.id}?`)) return { status: 200, value: { entity: structuredClone(value) } };
      for (const value of f.plugins) if (path.includes(`/plugins/${value.id}?`)) return { status: 200, value: { entity: structuredClone(value) } };
    }
    throw new Error('Unexpected original-scope read');
  });
  h.consoleRead = vi.fn((sql: string, args: unknown[]) => { expect(sql.startsWith('SELECT')).toBe(true); expect(args).toContain(T.executionKey); return [completed ? active() : { ...pending }]; });
  return { h, ...f, pending, view };
}

describe('M6 independent original-key metadata-only continuation', () => {
  it('guards existing actor/SID, fixture configuration, server eligibility and read-only ledgers before saving one original-key request', async () => {
    const f = harness(), before = structuredClone(f.reference);
    const context = await guardMetadataRecovery(f.h, f.diagnostic);
    expect(context.recoveryBody).toEqual({ revision: 4, planHash: 'a'.repeat(64), executionId: T.executionId, confirmed: true, confirm_name: 'portal-credential-issue' });
    expect(f.reference.metadataRecovery).toMatchObject({ phase: 'before-single-reconcile', originalKey: T.executionKey, body: context.recoveryBody });
    expect(f.reference.writeAttempts).toEqual(before.writeAttempts); expect(f.reference.tokens).toEqual(before.tokens);
    expect(f.h.request.mock.calls.every((call: any[]) => call[2] === undefined || call[2] === 'GET')).toBe(true);
    expect(f.h.portal.mock.calls.every((call: any[]) => call[2] === undefined || call[2] === 'GET')).toBe(true);
    expect(f.h.request.mock.calls.filter((call: any[]) => call[1].includes('/credentials/')).map((call: any[]) => call[1])).toEqual([
      `/clusters/${T.clusterId}/consumers/${T.consumerId}/credentials/acls/${T.aclId}?workspaceId=${T.workspaceId}`,
      `/clusters/${T.clusterId}/consumers/${T.consumerId}/credentials/key-auth/${T.nativeId}?workspaceId=${T.workspaceId}`,
    ]);
    expect(f.h.request.mock.calls.some((call: any[]) => call[1] === `/clusters/${T.clusterId}/entities/consumers/${T.consumerId}?workspaceId=${T.workspaceId}`)).toBe(true);
    expect(f.h.consoleRead).toHaveBeenCalledWith(METADATA_RECOVERY_DATABASE_SQL, [T.credentialId, T.grantId, T.clusterId, T.workspaceId,
      [M6_C1, M6_C2, T.clusterId], f.reference.fixtures.map((row: any) => row.workspace.id), T.executionId, T.executionKey]);
    expect(f.h.saveReference).toHaveBeenCalledTimes(1);
    await expect(guardMetadataRecovery(f.h, f.diagnostic)).rejects.toThrow();
    expect(f.h.saveReference).toHaveBeenCalledTimes(1);
  });

  it('database proof failure stops before recovery journaling or any formal metadata POST', async () => {
    const f = harness(), attempts = structuredClone(f.reference.writeAttempts), originalTokens = structuredClone(f.reference.tokens);
    f.h.consoleRead.mockImplementation(() => { throw new Error('Read-only database evidence unavailable'); });
    await expect(guardMetadataRecovery(f.h, f.diagnostic)).rejects.toThrow('Read-only database evidence unavailable');
    expect(f.h.consoleRead).toHaveBeenCalledTimes(1); expect(f.h.consoleRead.mock.calls[0][0]).toBe(METADATA_RECOVERY_DATABASE_SQL);
    expect(f.reference.metadataRecovery).toBeUndefined(); expect(f.h.saveReference).not.toHaveBeenCalled();
    expect(f.h.request.mock.calls.every((call: any[]) => call[2] === undefined || call[2] === 'GET')).toBe(true);
    expect(f.h.portal.mock.calls.every((call: any[]) => call[2] === undefined || call[2] === 'GET')).toBe(true);
    expect(f.reference.writeAttempts).toEqual(attempts); expect(f.reference.tokens).toEqual(originalTokens);
  });

  it('a failed child-credential GET never weakens native proof, persists a recovery request or advances to its POST', async () => {
    const f = harness(), read = f.h.request.getMockImplementation();
    f.h.request.mockImplementation(async (...args: any[]) => args[1].includes(`/credentials/acls/${T.aclId}?`)
      ? { status: 404, value: { code: 'NOT_FOUND' } } : read(...args));
    await expect(guardMetadataRecovery(f.h, f.diagnostic)).rejects.toThrow('Synthetic response failed');
    expect(f.reference.metadataRecovery).toBeUndefined(); expect(f.h.saveReference).not.toHaveBeenCalled();
    expect(f.h.request.mock.calls.every((call: any[]) => call[2] === undefined || call[2] === 'GET')).toBe(true);
    expect(f.h.request.mock.calls.some((call: any[]) => call[1].includes('/credentials/key-auth/'))).toBe(false);
  });

  it.each(['native-unresolved', 'portal-unresolved', 'extra-native-op', 'already-activated', 'credential-pointer', 'changed-workspace', 'changed-native', 'changed-publication', 'server-ineligible', 'foreign-execution', 'unknown-native-ACK'])('stops on %s before journaling or sending any recovery packet', async variant => {
    const f = harness();
    if (variant === 'native-unresolved') f.pending.native_unresolved = 1;
    if (variant === 'portal-unresolved') f.pending.portal_unresolved = 1;
    if (variant === 'extra-native-op') f.pending.native_operation_count = 4;
    if (variant === 'already-activated') f.pending.grant_state = 'active';
    if (variant === 'credential-pointer') f.pending.credential_ref_id = T.keyReferenceId;
    const read = f.h.request.getMockImplementation();
    f.h.request.mockImplementation(async (...args: any[]) => {
      const result = await read(...args), path = args[1];
      if (variant === 'changed-workspace' && path.includes('/workspaces/')) result.value.revision++;
      if (variant === 'changed-native' && path.includes('/entities/services/')) result.value.entity.host = 'foreign-host';
      if (variant === 'changed-publication' && path.includes('/portal/publications/')) result.value.entity.documentRevision++;
      if (path.includes('/workflows/receipts/by-key/')) {
        if (variant === 'server-ineligible') result.value.metadataRecovery.eligible = false;
        if (variant === 'foreign-execution') result.value.executionId = id(999);
        if (variant === 'unknown-native-ACK') result.value.steps[2].remoteCompleted = false;
      }
      return result;
    });
    await expect(guardMetadataRecovery(f.h, f.diagnostic)).rejects.toThrow();
    expect(f.h.saveReference).not.toHaveBeenCalled();
    expect(f.h.request.mock.calls.every((call: any[]) => call[2] === undefined || call[2] === 'GET')).toBe(true);
  });

  it('sends exactly one formal metadata POST with the original key, then proves the original receipt and immutable ciphertext without Native replay', async () => {
    const f = harness(), context = await guardMetadataRecovery(f.h, f.diagnostic);
    const result = await reconcileOriginalMetadata(f.h, context);
    const writes = f.h.request.mock.calls.filter((call: any[]) => call[2] === 'POST');
    expect(writes).toHaveLength(1); expect(writes[0][1]).toContain(`/workflows/${T.workflowId}/reconcile-metadata?workspaceId=${T.workspaceId}`);
    expect(writes[0][3]).toEqual(context.recoveryBody); expect(writes[0][4]).toEqual({ key: T.executionKey });
    expect(result.state).toBe('succeeded'); expect(result.steps.slice(0, 3).map((step: any) => step.operationId)).toEqual(operationIds);
    expect(f.reference.metadataRecovery).toMatchObject({ phase: 'metadata-succeeded-original-execution', after: { native_operation_count: 3, immutable_key_cipher_sha: context.before.immutable_key_cipher_sha, key_fingerprint: context.before.key_fingerprint } });
    await expect(reconcileOriginalMetadata(f.h, context)).rejects.toThrow();
    expect(f.h.request.mock.calls.filter((call: any[]) => call[2] === 'POST')).toHaveLength(1);
  });

  it('an unknown recovery acknowledgement leaves the prejournaled started state and makes zero further reads or writes', async () => {
    const f = harness(), context = await guardMetadataRecovery(f.h, f.diagnostic), read = f.h.request.getMockImplementation();
    f.h.request.mockClear(); f.h.request.mockImplementation(async (...args: any[]) => { if (args[2] === 'POST') throw new Error('Recovery response lost'); return read(...args); });
    await expect(reconcileOriginalMetadata(f.h, context)).rejects.toThrow('Recovery response lost');
    expect(f.reference.metadataRecovery.phase).toBe('reconcile-request-started'); expect(f.h.request).toHaveBeenCalledTimes(1);
    await expect(reconcileOriginalMetadata(f.h, context)).rejects.toThrow(); expect(f.h.request).toHaveBeenCalledTimes(1);
  });

  it.each(['ciphertext', 'fingerprint', 'native-count', 'partial-receipt'])('does not accept apparent success with changed %s proof', async variant => {
    const f = harness(), context = await guardMetadataRecovery(f.h, f.diagnostic), dbRead = f.h.consoleRead.getMockImplementation(), read = f.h.request.getMockImplementation();
    f.h.consoleRead.mockImplementation((...args: any[]) => { const rows = dbRead(...args); if (variant === 'ciphertext') rows[0].immutable_key_cipher_sha = 'd'.repeat(64); if (variant === 'fingerprint') rows[0].key_fingerprint = 'd'.repeat(64); if (variant === 'native-count') rows[0].native_operation_count = 4; return rows; });
    f.h.request.mockImplementation(async (...args: any[]) => { const result = await read(...args); if (variant === 'partial-receipt' && args[2] === 'POST') result.value.steps[2].state = 'uncertain'; return result; });
    await expect(reconcileOriginalMetadata(f.h, context)).rejects.toThrow();
    expect(f.reference.metadataRecovery.phase).toBe('reconcile-request-started'); expect(f.h.request.mock.calls.filter((call: any[]) => call[2] === 'POST')).toHaveLength(1);
  });

  it('refuses swapped original execution, missing scanner material and a new monitoring family from the initial checkpoint', () => {
    for (const variant of ['key', 'execution', 'capture', 'monitoring-family', 'native-history']) {
      const f = fixture();
      if (variant === 'key') f.diagnostic.originalExecution.key = id(900);
      if (variant === 'execution') f.diagnostic.receipt.executionId = id(901);
      if (variant === 'capture') f.reference.pendingCredentialScanCaptures = [];
      if (variant === 'monitoring-family') f.reference.tokens[0].generation++;
      if (variant === 'native-history') f.diagnostic.native[0].id = T.keyOperationId;
      expect(() => metadataRecoveryCheckpoint(f.reference, f.diagnostic)).toThrow();
    }
  });
});
