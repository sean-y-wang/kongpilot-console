import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { approvedFixture, actor, cid, wid, sid, subjectId, id } from './m6-approved-fixture';

/** Real ApprovedService, encryption and execution context. SQL/native transport
 * and grants are explicit fakes; the separate PG gate verifies runtime SQL. */
function restoreFixture(type: 'portal_content' | 'portal_publications' = 'portal_content') {
  const f = approvedFixture(), handler = type === 'portal_content' ? 'portal.page.draft' : 'portal.publication.draft';
  const row: any = type === 'portal_publications' ? f.publication : {
    id: subjectId, cluster_id: cid, workspace_id: wid, state: 'deleted', title: 'Archived page',
    revision: 5, published_revision: null, deleted_at: new Date('2026-01-01T00:00:00Z'), retention_until: null,
  };
  if (type === 'portal_publications') Object.assign(row, { state: 'deleted', revision: 5, published_revision: null });
  Object.assign(f.plan, { kind: 'portal-metadata', subject: { type, id: row.id }, requester: { type: 'console', id: id(51) }, prerequisites: [] });
  f.plan.steps = [{ id: sid, key: handler, order: 1, kind: 'metadata', handler, entityType: type, entityId: row.id,
    permissionAction: 'write', dependencies: [], nativeRequests: [], before: structuredClone(row), metadata: { archive: false },
    metadataRevision: row.revision, metadataBeforeHmac: f.secrets.fingerprint(row), metadataPayloadHmac: f.secrets.fingerprint({ archive: false }) }];
  f.workflow.requester_type = 'console'; f.workflow.requester_user_id = f.plan.requester.id;
  f.grants[0] = { module: 'workflows', action: 'approve', scope_type: 'workspace', scope_values: [wid], cluster_id: cid, workspace_id: wid };
  const originalOne = f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, values: unknown[] = []) => sql.includes('FROM portal_content') ? row : originalOne(sql, values));
  f.seal();
  const input = () => ({ handler, actor, clusterId: cid, workspaceId: wid, entityType: type, entityId: row.id,
    before: f.plan.steps[0].before, revision: 5, payload: { archive: false } });
  return { ...f, row, handler, input };
}
const unavailable = { response: { code: 'APPROVED_SUBJECT_UNAVAILABLE' } };
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'aa'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M6 sealed archived metadata restore authorization', () => {
  it.each(['portal_content', 'portal_publications'] as const)('permits exact %s restore review/approval/write with current action grants', async type => {
    const f = restoreFixture(type);
    for (const action of ['read', 'approve', 'write'] as const) await f.http(() => f.verifier.assertSubject(f.plan, actor, action));
    const checks = (type === 'portal_content' ? f.authz.assertWholeWorkspace : f.authz.assertScopedResource).mock.calls;
    expect(checks.map((call: unknown[]) => type === 'portal_content' ? call.slice(3, 5) : call.slice(2, 4))).toEqual([
      ['workflows', 'read'], ['portal', 'read'], ['workflows', 'approve'], ['workflows', 'write'], ['portal', 'write'],
    ].filter(tuple => type === 'portal_content' || tuple[0] !== 'portal' || tuple[1] !== 'read'));
    expect(f.kong.request.mock.calls.every((call: unknown[]) => call[1] === 'GET')).toBe(true);
  });

  it.each(['portal_content', 'portal_publications'] as const)('allows private %s metadata execution while denying native mutation authority', async type => {
    const f = restoreFixture(type);
    await f.run(async () => {
      await f.verifier.assertStep(f.input(), f.db);
      await expect(f.verifier.assertStep({ ...f.input(), payload: { archive: false, published: true } }, f.db))
        .rejects.toMatchObject({ response: { code: 'APPROVED_METADATA_REQUEST_MISMATCH' } });
      await expect(f.context.approvedMutationBinding(f.mutationContext())).rejects.toMatchObject({ response: { code: 'APPROVED_NATIVE_STEP_REQUIRED' } });
      await expect(f.verifier.assertNativeWrite({ clusterId: cid, workspaceId: wid, transportScope: f.plan.scope.transportScope,
        operationId: id(99), method: 'POST', canonicalPath: '/consumers', body: {}, before: null, mutationAction: 'create' }))
        .rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    });
    expect(f.operations.size).toBe(0);
    expect(f.kong.request.mock.calls.every((call: unknown[]) => call[1] === 'GET')).toBe(true);
  });

  it('continues ordinary authorization after the restored row becomes draft', async () => {
    const f = restoreFixture(); await f.run(() => f.verifier.assertStep(f.input(), f.db));
    Object.assign(f.row, { state: 'draft', revision: 6, deleted_at: null });
    await f.http(() => f.verifier.assertSubject(f.plan, actor, 'read'));
    expect(f.authz.assertWholeWorkspace.mock.calls.at(-1)?.slice(3, 5)).toEqual(['portal', 'read']);
  });

  it.each([
    ['unsealed caller plan', (f: ReturnType<typeof restoreFixture>) => { f.version.payload_secret = f.secrets.encrypt({ ...f.plan, issuedAt: 'different' }, `workflow:${cid}:${wid}:${f.plan.workflowId}:1:plan`); }],
    ['missing immutable version', (f: ReturnType<typeof restoreFixture>) => { const one = f.db.one.getMockImplementation()!; f.db.one.mockImplementation((sql: string, p: unknown[]) => sql.includes('FROM workflow_versions') ? null : one(sql, p)); }],
    ['wrong workflow hash', (f: ReturnType<typeof restoreFixture>) => { f.workflow.plan_hash = 'b'.repeat(64); }],
    ['changed current revision', (f: ReturnType<typeof restoreFixture>) => { f.row.revision++; }],
    ['same revision changed content', (f: ReturnType<typeof restoreFixture>) => { f.row.title = 'externally changed'; }],
    ['missing normalized step', (f: ReturnType<typeof restoreFixture>) => { f.rows.length = 0; }],
    ['normalized native operation link', (f: ReturnType<typeof restoreFixture>) => { f.rows[0].operation_id = id(99); }],
    ['normalized payload mismatch', (f: ReturnType<typeof restoreFixture>) => { f.rows[0].metadata_payload_hmac = 'b'.repeat(64); }],
    ['normalized handler substitution', (f: ReturnType<typeof restoreFixture>) => { f.rows[0].handler = 'portal.page.publish'; }],
    ['foreign actual workspace', (f: ReturnType<typeof restoreFixture>) => { f.row.workspace_id = id(90); }],
  ] as const)('rejects %s without granting subject access', async (_name, change) => {
    const f = restoreFixture(); change(f);
    await expect(f.http(() => f.verifier.assertSubject(f.plan, actor, 'read'))).rejects.toMatchObject(unavailable);
    expect(f.authz.assertWholeWorkspace).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each([
    ['generic deleted subject read', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps[0].metadata = { title: 'Edit archive' }; }],
    ['extra restore metadata', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps[0].metadata = { archive: false, published: true }; }],
    ['archive instead of restore', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps[0].metadata = { archive: true }; }],
    ['different workflow kind', (f: ReturnType<typeof restoreFixture>) => { f.plan.kind = 'portal-publication'; }],
    ['direct plan cannot mint exception', (f: ReturnType<typeof restoreFixture>) => { f.plan.executionMode = 'direct'; f.plan.approvalRequired = false; }],
    ['native packet on metadata', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps[0].nativeRequests = [{ method: 'DELETE', canonicalPath: `/consumers/${id(90)}`, nativeType: 'consumers', nativeId: id(90), bodyHmac: f.secrets.fingerprint(null) }]; }],
    ['second logical step', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps.push({ ...f.plan.steps[0], id: id(91), order: 2 }); }],
    ['different handler', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps[0].handler = 'portal.page.publish'; }],
    ['credential parent binding', (f: ReturnType<typeof restoreFixture>) => { f.plan.steps[0].parentId = id(90); }],
    ['generated credentials', (f: ReturnType<typeof restoreFixture>) => { f.plan.generated = { consumerId: id(90), aclId: id(91), credentialId: id(92), key: 'unused-test-key' }; }],
  ] as const)('rejects freshly sealed %s', async (_name, change) => {
    const f = restoreFixture(); change(f); f.plan.steps[0].metadataPayloadHmac = f.secrets.fingerprint(f.plan.steps[0].metadata); f.seal();
    await expect(f.http(() => f.verifier.assertSubject(f.plan, actor, 'write'))).rejects.toMatchObject(unavailable);
    expect(f.operations.size).toBe(0); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('keeps rejected developer review and deleted credential subjects rejected', async () => {
    const f = restoreFixture(); f.plan.subject = { type: 'portal_developers', id: f.developer.id }; f.developer.status = 'rejected';
    await expect(f.http(() => f.verifier.assertSubject(f.plan, actor, 'approve'))).rejects.toMatchObject(unavailable);
    f.plan.subject = { type: 'portal_application_grants', id: f.grant.id }; f.grant.state = 'deleted';
    await expect(f.http(() => f.verifier.assertSubject(f.plan, actor, 'read'))).rejects.toMatchObject(unavailable);
  });

  it('preserves current executor and approver revocation fences', async () => {
    const f = restoreFixture(); f.authz.assertWholeWorkspace.mockRejectedValue(new ForbiddenException({ code: 'GRANT_REVOKED' }));
    await expect(f.run(() => f.verifier.assertStep(f.input(), f.db))).rejects.toMatchObject({ response: { code: 'GRANT_REVOKED' } });
    f.authz.assertWholeWorkspace.mockResolvedValue(undefined); f.approvedBy.status = 'disabled';
    await expect(f.run(() => f.verifier.assertStep(f.input(), f.db))).rejects.toMatchObject({ response: { code: 'APPROVED_APPROVER_REVOKED' } });
    expect(f.operations.size).toBe(0);
  });
});
