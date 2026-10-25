import { vi } from 'vitest';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { fixture, receipt } from './m6-failed-issue-continuation-fixture';
import { checkpointSha } from './lib/m6-isolated-transition.mjs';
import { PENDING_KEY_TUPLE as F } from './lib/m6-pending-key-capture.mjs';
import { FAILED_ISSUE_TUPLE as T } from './lib/m6-failed-issue-key-capture.mjs';
import { RETIRED_KEY_ARCHIVE, RETIRED_RESTORE_DATABASE_SQL } from './lib/m6-retired-lifecycle-continuation.mjs';

export const sha = (v: any) => createHash('sha256').update(JSON.stringify(v)).digest('hex');

/** Invented facts only. No executable runner, private reference, database or
 * network is loaded; every available outbound primitive is explicitly mocked. */
export function retiredLifecycleReviewFixture() {
  const base = fixture(), r: any = base.reference, a: any = base.first;
  const primary = r.fixtures[0], secondary = r.fixtures[1];
  const rotated = { id: randomUUID(), generation: 2 }, nativeId = randomUUID();
  const newKey = randomBytes(32).toString('base64url'), opId = randomUUID();
  primary.routes.push({ id: randomUUID(), paths: ['/synthetic-second'] });
  a.grant.publicationId = primary.publications[0].id;
  const independentGrant = (app: any, publication: any) => ({
    app, grant: { id: randomUUID(), publicationId: publication.id, state: 'active', generation: 1 },
    credential: { id: randomUUID() }, apiKey: randomBytes(32).toString('base64url'), workflowId: randomUUID(),
    managed: { consumer_id: randomUUID(), acl_id: randomUUID(), kong_id: randomUUID() },
  });
  const b = independentGrant(base.app, primary.publications[1]);
  const c = independentGrant(base.c2App, secondary.publications[0]);
  const originalJournal = { phase: 'abandonment-request-started', originalExecutionKey: T.executionKey };
  const originalAttempt = { key: T.executionKey, path: '/synthetic/original-abandonment', state: 'response_observed' };
  const certificateId = randomUUID();
  Object.assign(r, {
    phase: 'dual-cluster-approved-credentials', grants: [a, b, c], secrets: [a.apiKey, b.apiKey, c.apiKey, newKey],
    abandonmentAcknowledgment: {
      phase: 'certificate-verified', totalFormalPosts: 2, additionalFormalPosts: 1, certificateId,
      originalJournal, originalJournalSha256: checkpointSha(originalJournal),
      originalAttempt, originalAttemptSha256: checkpointSha(originalAttempt),
    },
    failedIssueContinuation: {
      phase: 'new-second-issue-complete', newGrantId: b.grant.id, newCredentialId: b.credential.id,
      certificateId, before: { cipher_sha: 'c'.repeat(64) },
    },
  });
  const attempt: any = {
    path: `/api/v1/clusters/${T.clusterId}/recycle-bin/${RETIRED_KEY_ARCHIVE}/restore`, method: 'POST',
    key: randomUUID(), actorId: r.consoleAdministrator.user.id, state: 'response_observed', httpStatus: 404,
    errorCode: 'KONG_VALIDATION_ERROR', requestId: randomUUID(), query: `?workspaceId=${T.workspaceId}`,
    body: { confirmed: true, confirm_name: nativeId },
  };
  r.writeAttempts.push(
    { path: `/api/v1/portal/applications/${a.app.id}/grants/${a.grant.id}/credentials/${F.credentialId}/rotate`, httpStatus: 201 },
    { path: `/api/v1/portal/applications/${a.app.id}/grants/${a.grant.id}/credentials/${rotated.id}/revoke`, httpStatus: 201, body: { retireConsumer: true } },
    { path: `/api/v1/portal/applications/${a.app.id}/grants/${a.grant.id}/credentials/${rotated.id}/reveal`, httpStatus: 201, actorId: r.portalUsers[0].id, responseData: { key: newKey } }, attempt,
  );
  const database: any = {
    credential_id: rotated.id, grant_id: F.grantId, consumer_id: F.consumerId, kong_id: nativeId,
    credential_state: 'revoked', generation: 2, grant_state: 'revoked', current_generation: 2,
    current_credential_id: rotated.id, archive_state: 'deleted', root_type: 'credentials', original_id: nativeId,
    parent_id: F.consumerId, credential_kind: 'key-auth', affected_nodes: 1, shared_consumer_nodes: 1,
    attempted_restored_nodes: 0, active_credential_refs: 0, same_request_operations: 1,
    same_request_completed_results: 0, native_unresolved: 0, portal_unresolved: 0,
  };
  const proof: any = {
    allPassed: true, readOnly: true, noPostReplay: true, originalStatus: 404, originalErrorCode: 'KONG_VALIDATION_ERROR',
    entryId: RETIRED_KEY_ARCHIVE, originalAttemptSha256: sha(attempt), originalRequestId: attempt.requestId,
    receipt: { status: 200 }, operation: { id: opId, state: 'failed', error_code: 'KONG_VALIDATION_ERROR', remote_started: true, remote_completed: false, has_result: false },
    database, currentArchiveStatus: 200, currentParentStatus: 404,
    proxyStatuses: { originalFirstKey: 401, retiredRotatedKey: 401, activeSecondPublication: 200, activeOtherCluster: 200 },
  };
  const report = {
    testTag: r.testTag, passed: 750, failed: 1, lastHttpRequest: { method: 'POST', path: attempt.path.replace('/api/v1', ''), status: 404 },
    failedIssueAbandonment: { formalAbandonmentPosts: 2 },
  };
  const row: any = {
    ...database, operation_id: opId, operation_state: 'failed', error_code: 'KONG_VALIDATION_ERROR',
    remote_started: true, remote_completed: false, has_result: false, changed_archive_nodes: 0,
    original_credential_state: 'revoked', original_key_cipher_sha: r.metadataRecovery.after.immutable_key_cipher_sha,
  };
  const closed: any = {
    grant_state: 'disabled', current_generation: 0, reservation_released_at: '2026-10-11T00:00:00Z', certificates: 1,
    credential_state: 'pending', generation: 1, last_revealed_at: null, credential_ref_id: null, credential_refs: 0,
    native_operation_count: 1, unexpected_native_results: 0, native_unresolved: 0, portal_unresolved: 0, cipher_sha: 'c'.repeat(64),
  };
  const bin: any = {
    entry: { id: RETIRED_KEY_ARCHIVE, state: 'deleted', original_id: nativeId, parent_id: F.consumerId },
    nodes: [{ affected: true, delete_state: 'deleted', restore_state: 'pending', restored_id: null }],
  };
  const identity: any = { state: 'failed', action: 'create', entity_type: 'consumers', error_code: 'PORTAL_MANAGED_OBJECT', remote_completed: false, has_result: false };
  const h: any = {
    tag: r.testTag, referenceData: r, secrets: [...r.secrets], public: {}, requireLive: vi.fn(),
    check(value: any, _id: string, message: string) { if (!value) throw Error(message); },
    ok(res: any) { if (res.status < 200 || res.status >= 300) throw Error('SYNTHETIC_HTTP_REJECTION'); return res.payload.data; },
    saveReference(extra: any = {}) { this.referenceData = { ...this.referenceData, ...extra }; },
    checkpoint: vi.fn(), verifyAuditCoverage: vi.fn(), verifyAppendOnlyStorage: vi.fn(),
  };
  h.consoleRead = vi.fn((sql: string) => {
    if (!sql.startsWith('SELECT')) throw Error('SQL_WRITE_FORBIDDEN');
    if (sql === RETIRED_RESTORE_DATABASE_SQL) return [structuredClone(row)];
    if (sql.startsWith('SELECT state,action,entity_type')) return [structuredClone(identity)];
    return [structuredClone(closed)];
  });
  h.request = vi.fn(async (session: any, path: string, method = 'GET') => {
    if (method !== 'GET') throw Error('BUSINESS_PACKET_NOT_STUBBED');
    const u = new URL(path, 'http://synthetic.invalid'); let data: any;
    if (path === '/auth/me') data = { id: session.user.id };
    else if (u.pathname === `/clusters/${T.clusterId}/mutations/by-key/${attempt.key}`) data = { id: opId, state: 'failed', remote_completed: false, error_code: 'KONG_VALIDATION_ERROR' };
    else if (path.includes(`/workflows/receipts/by-key/${T.executionKey}`)) data = receipt(true, certificateId);
    else if (u.pathname === `/clusters/${T.clusterId}/recycle-bin/${RETIRED_KEY_ARCHIVE}`) data = bin;
    else if (u.pathname === `/clusters/${T.clusterId}/recycle-bin`) data = { items: [{ id: randomUUID(), root_type: 'consumers', original_id: F.consumerId }] };
    else if (u.pathname === `/clusters/${T.clusterId}/entities/consumers/${F.consumerId}`) return { status: 404, payload: { error: { code: 'KONG_VALIDATION_ERROR' } } };
    for (const f of r.fixtures) {
      if (u.pathname === `/clusters/${f.cluster.id}/workspaces/${f.workspace.id}`) data = f.workspace;
      else if (u.searchParams.get('workspaceId') === f.workspace.id) {
        if (u.pathname === `/clusters/${f.cluster.id}/portal/settings`) data = { settings: f.settings };
        for (const type of ['services', 'routes', 'publications']) for (const value of f[type])
          if (u.pathname.endsWith(`/${type}/${value.id}`)) data = { entity: value };
      }
    }
    for (const plugin of base.plugins) if (u.pathname === `/clusters/${T.clusterId}/entities/plugins/${plugin.id}`) data = { entity: plugin };
    if (!data) throw Error(`UNEXPECTED_READ:${u.pathname}`);
    return { status: 200, payload: { data: structuredClone(data) } };
  });
  h.portal = vi.fn(async (session: any, path: string, method = 'GET') => {
    if (method !== 'GET') throw Error('PORTAL_PACKET_NOT_STUBBED');
    const u = new URL(path, 'http://synthetic.invalid'); let data: any;
    if (u.pathname === '/auth/me') data = session.developer;
    for (const g of [a, b, c]) {
      if (u.pathname === `/applications/${g.app.id}/grants/${g.grant.id}/credentials`) data = { items: g === a
        ? [F.credentialId, rotated.id].map(id => ({ id, state: 'revoked', maskedKey: '••••••••', capabilities: { reveal: false } }))
        : [{ id: g.credential.id, state: 'active', maskedKey: '••••••••' }] };
      else if (u.pathname === `/applications/${g.app.id}/grants`) data = { items: g === c ? [c.grant] : [{ ...a.grant, state: 'revoked', generation: 2 }, b.grant] };
      else if (u.pathname === `/applications/${g.app.id}`) data = { entity: g.app };
    }
    if (!data) throw Error('UNEXPECTED_PORTAL_READ'); return { status: 200, payload: { data: structuredClone(data) } };
  });
  h.proxy = vi.fn(async (_cluster: any, _path: string, _method: string, _body: any, headers: any) => [a.apiKey, newKey].includes(headers.apikey) ? 401 : 200);
  h.waitProxy = vi.fn(async (_cluster: any, _path: string, expected: number) => expected);
  return { h, r, a, b, c, rotated, newKey, opId, proof, report, row, closed, bin, identity, attempt, plugins: base.plugins, evidence: { proof, report } };
}
