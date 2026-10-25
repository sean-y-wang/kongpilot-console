import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { WorkflowPlansService } from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import { planAad, type WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Actual immutable plan repository and secret handling. The SQL transaction
 * and Audit dependency are explicit doubles; no live database or HTTP calls. */
function fixture(requesterType: 'console' | 'developer' = 'console') {
  const secrets = new SecretService(), cid = randomUUID(), wid = randomUUID(), workflowId = randomUUID(), uid = randomUUID();
  const plan: WorkflowPlanV1 = { version: 1, kind: 'portal-metadata', clusterId: cid, workspaceId: wid, workflowId, planRevision: 1,
    executionMode: 'approval', approvalRequired: true, subject: { type: 'portal_content', id: randomUUID() }, requester: { type: requesterType, id: uid },
    definition: { id: randomUUID(), version: 1, policyHash: 'a'.repeat(64) }, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(),
    scope: { transportScope: 'b'.repeat(64), clusterRevision: 1, workspaceRevision: 1 }, prerequisites: [],
    steps: [{ id: randomUUID(), key: 'portal.page.draft', order: 1, kind: 'metadata', handler: 'portal.page.draft', entityType: 'portal_content', permissionAction: 'write',
      nativeRequests: [], dependencies: [], before: { title: 'old' }, metadata: { title: 'new' }, metadataRevision: 1, metadataBeforeHmac: 'c'.repeat(64), metadataPayloadHmac: 'd'.repeat(64) }] };
  const state: any = { row: null, version: null, audits: [] }, audit = { append: vi.fn(async (event: any, tx: any) => { expect(tx).toBe(db); state.audits.push(structuredClone(event)); }) };
  const db: any = { one: vi.fn(async () => state.row), exec: vi.fn(async (sql: string, p: any[]) => {
    if (sql.startsWith('INSERT INTO workflows(')) state.row = { id: p[0], cluster_id: p[1], workspace_id: p[2], requester_user_id: p[7], requester_developer_id: p[8], plan_hash: p[12], request_hash: p[15], idempotency_key: p[16] };
    if (sql.startsWith('INSERT INTO workflow_versions')) state.version = { payload_secret: p[7], safe_diff: JSON.parse(p[12]) }; return 1;
  }), transaction: async (fn: any) => { const old = structuredClone(state); try { return await fn(db); } catch (error) { Object.assign(state, old); throw error; } } };
  const service = new WorkflowPlansService(db, secrets, audit as any), context = { requestId: randomUUID(), ip: '192.0.2.17' };
  const persist = (metadata: any = context, request: unknown = { title: 'new' }) => db.transaction((tx: any) => service.persist(plan, 'original-submit-key', request, tx, metadata));
  return { service, secrets, plan, context, db, audit, state, persist };
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '7a'.repeat(32))); afterEach(() => vi.unstubAllEnvs());
describe('M7 workflow submission terminal audit correlation', () => {
  it.each(['console', 'developer'] as const)('persists the %s submission and its actual HTTP metadata in the same transaction without changing plan/request hashes', async type => {
    const f = fixture(type), original = structuredClone(f.plan), request = { title: 'new', requestId: randomUUID(), ip: '198.51.100.99' };
    const row = await f.persist(f.context, request);
    expect(row.plan_hash).toBe(f.secrets.fingerprint(original));
    expect(row.request_hash).toBe(f.secrets.fingerprint({ requester: original.requester, clusterId: original.clusterId, workspaceId: original.workspaceId, request }));
    expect(f.secrets.decrypt(f.state.version.payload_secret, planAad(original.clusterId, original.workspaceId, original.workflowId, 1))).toEqual(original);
    expect(f.audit.append).toHaveBeenCalledOnce();
    expect(f.state.audits[0]).toMatchObject({ action: 'workflow.submit', requestId: f.context.requestId, ip: f.context.ip, clusterId: original.clusterId, workspaceId: original.workspaceId,
      actorType: type === 'console' ? 'user' : 'developer', entityType: 'workflows', entityId: original.workflowId, workflowId: original.workflowId, result: 'success',
      after: { planHash: row.plan_hash, approvalRequired: true }, scopeHints: { quality: 'verified', beforeExists: false, afterExists: true, afterWorkspaceId: original.workspaceId } });
    expect(f.plan).toEqual(original);
  });
  it('same original key/hash returns the original workflow without repeating writes or submission audit even with a new HTTP request ID', async () => {
    const f = fixture(), first = await f.persist(); const writes = f.db.exec.mock.calls.length;
    expect(await f.persist({ requestId: randomUUID(), ip: '::ffff:192.0.2.18' })).toEqual(first);
    expect(f.db.exec).toHaveBeenCalledTimes(writes); expect(f.audit.append).toHaveBeenCalledOnce(); expect(f.state.audits[0].requestId).toBe(f.context.requestId);
  });
  it('original key with a changed body does not write or audit a new submission', async () => {
    const f = fixture(); await f.persist(); const writes = f.db.exec.mock.calls.length;
    await expect(f.persist({ requestId: randomUUID(), ip: '::1' }, { title: 'other' })).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    expect(f.db.exec).toHaveBeenCalledTimes(writes); expect(f.audit.append).toHaveBeenCalledOnce();
  });
  it.each([null, undefined, {}, { requestId: 'client-chosen-id', ip: '192.0.2.1' }, { requestId: randomUUID() }, { requestId: randomUUID(), ip: 'not-an-ip' },
    { requestId: randomUUID(), ip: '192.0.2.1\nspoof' }, { requestId: randomUUID(), ip: '192.0.2.1', actorId: randomUUID() }, [{ requestId: randomUUID(), ip: '192.0.2.1' }]])('rejects missing or malformed trusted metadata before any SQL: %j', async metadata => {
    const f = fixture(); await expect(f.db.transaction((tx: any) => f.service.persist(f.plan, 'original-submit-key', {}, tx, metadata as any))).rejects.toMatchObject({ response: { code: 'WORKFLOW_SUBMISSION_AUDIT_METADATA_REQUIRED' } });
    expect(f.db.one).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('an audit failure rolls back the original immutable plan rather than returning a successful uncorrelated submission', async () => {
    const f = fixture(); f.audit.append.mockRejectedValueOnce(new Error('AUDIT_WRITE_FAILED'));
    await expect(f.persist()).rejects.toThrow('AUDIT_WRITE_FAILED'); expect(f.state).toEqual({ row: null, version: null, audits: [] });
  });
});
