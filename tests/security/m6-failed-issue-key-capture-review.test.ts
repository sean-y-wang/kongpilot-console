import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { portalKeyAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { FAILED_ISSUE_TUPLE as T, FAILED_ISSUE_CAPTURE_PROGRAM, decryptFailedIssueTransfer, failedIssueCaptureAad, mergeFailedIssueCapture } from './lib/m6-failed-issue-key-capture.mjs';
import { PENDING_KEY_TUPLE as FIRST } from './lib/m6-pending-key-capture.mjs';
import { checkpointSha } from './lib/m6-isolated-transition.mjs';

beforeEach(() => { vi.stubEnv('APP_SECRET', 'offline-failed-key-signing-secret-at-least32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cf'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

async function executeCapture(change: (row: any, steps: any[], plan: any, seal: () => void) => void = () => undefined) {
  const secrets = new SecretService(), key = 'SyntheticUnissuedKeyOnlyForOfflineScanReview2026', transferKey = crypto.randomBytes(32);
  const ids = [T.consumerStepId, T.aclStepId, T.keyStepId, T.metadataStepId];
  const plan: any = { version: 1, clusterId: T.clusterId, workspaceId: T.workspaceId, workflowId: T.workflowId, planRevision: 1,
    kind: 'portal-credential-issue', subject: { type: 'portal_application_grants', id: T.grantId },
    generated: { consumerId: T.consumerId, aclId: T.aclId, credentialId: T.nativeId, key }, steps: [
      { id: ids[0], mutationPayload: { id: T.consumerId } },
      { id: ids[1], parentId: T.consumerId, mutationPayload: { id: T.aclId } },
      { id: ids[2], parentId: T.consumerId, mutationPayload: { id: T.nativeId, key } },
      { id: ids[3], entityId: T.grantId, metadata: { credentialId: T.credentialId } },
    ] };
  const row: any = { key_secret: secrets.encrypt({ key }, portalKeyAad(T.clusterId, T.workspaceId, T.credentialId, 1)), key_fingerprint: secrets.fingerprint(key),
    credential_state: 'pending', grant_state: 'pending', current_generation: 0, current_credential_id: null, acl_credential_ref_id: null, reservation_released_at: null,
    credential_ref_id: null, issue_operation_id: null, recycle_entry_id: null, revoked_at: null, deleted_at: null, last_revealed_at: null,
    workflow_state: 'failed', execution_state: 'failed', kind: 'portal-credential-issue', plan_revision: 1,
    operation_state: 'failed', entity_id: null, remote_completed: false, error_code: 'KONG_VALIDATION_ERROR', result_secret: null, native_operation_count: 1, reference_count: 0 };
  const seal = () => Object.assign(row, { payload_secret: secrets.encrypt(plan, planAad(T.clusterId, T.workspaceId, T.workflowId, 1)), plan_hash: secrets.fingerprint(plan), steps_hash: secrets.fingerprint(plan.steps) });
  seal();
  const steps: any[] = ids.map((stepId, index) => ({ id: stepId, step_order: index + 1, kind: index === 3 ? 'metadata' : 'native',
    handler: index === 3 ? 'portal.credential.activate' : null, state: index === 0 ? 'failed' : 'pending', entity_type: index === 0 ? 'consumers' : index === 3 ? 'portal_application_grants' : 'credentials',
    parent_id: index === 1 || index === 2 ? T.consumerId : null, credential_kind: index === 1 ? 'acls' : index === 2 ? 'key-auth' : null,
    operation_id: index === 0 ? T.consumerOperationId : null, native_operation_id: index === 0 ? T.consumerOperationId : null,
    native_state: index === 0 ? 'failed' : null, remote_completed: index === 0 ? false : null,
    receipt_secret: null, safe_result: {}, after_fingerprint: null, recycle_entry_id: null, started_at: null, completed_at: null }));
  change(row, steps, plan, seal);
  const queries: string[] = [], stdout: string[] = [], stderr: string[] = [];
  const client = { query: async (sql: string) => { queries.push(sql); if (sql.startsWith('BEGIN') || sql === 'ROLLBACK') return { rows: [] };
    if (sql.includes('FROM portal_credentials')) return { rows: [row] }; if (sql.includes('FROM workflow_steps')) return { rows: steps };
    throw new Error('Unexpected offline scanner SQL'); }, release: vi.fn() };
  const fakeProcess: any = { env: {}, stdout: { write: (value: string) => stdout.push(value) }, stderr: { write: (value: string) => stderr.push(value) } };
  await runInNewContext(FAILED_ISSUE_CAPTURE_PROGRAM, { Buffer, process: fakeProcess, require: (name: string) => {
    if (name === 'node:fs') return { readFileSync: () => Buffer.from(JSON.stringify({ key: transferKey.toString('hex'), tuple: T })) };
    if (name === 'node:crypto') return crypto; if (name === 'pg') return { Pool: class { async connect() { return client; } async end() {} } };
    if (name.endsWith('secret.service.js')) return { SecretService }; if (name.endsWith('portal-proof.js')) return { portalKeyAad };
    if (name.endsWith('workflow.types.js')) return { planAad }; throw new Error('Unexpected scanner module');
  } }, { timeout: 1000 });
  return { queries, stdout, stderr, fakeProcess, transferKey, key };
}

describe('M6 independent failed-first-Consumer scanner, actual isolated program', () => {
  it('executes only fixed repeatable-read SELECTs and authenticates ciphertext without printing a key or transfer secret', async () => {
    const f = await executeCapture(); expect(f.fakeProcess.exitCode).toBeUndefined(); expect(f.stderr).toEqual([]); expect(f.stdout).toHaveLength(1);
    expect(f.queries.every(sql => /^(?:SELECT|BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY|ROLLBACK)/.test(sql))).toBe(true);
    expect(f.queries.at(-1)).toBe('ROLLBACK'); expect(f.stdout[0]).not.toContain(f.key); expect(f.stdout[0]).not.toContain(f.transferKey.toString('hex'));
    expect(decryptFailedIssueTransfer(JSON.parse(f.stdout[0]), f.transferKey)).toEqual({ tuple: T, validated: true, key: f.key });
  });
  it.each([
    ['unknown first operation', (row: any) => { row.operation_state = 'uncertain'; }],
    ['completed first operation', (row: any) => { row.remote_completed = true; }],
    ['unexpected created ID', (row: any) => { row.entity_id = T.consumerId; }],
    ['timeout instead of known validation rejection', (row: any) => { row.error_code = 'KONG_TIMEOUT'; }],
    ['native result present', (row: any) => { row.result_secret = 'unexpected-result'; }],
    ['more native operations', (row: any) => { row.native_operation_count = 2; }],
    ['credential reference exists', (row: any) => { row.reference_count = 1; }],
    ['already released grant', (row: any) => { row.reservation_released_at = new Date().toISOString(); }],
    ['already revealed pending Key', (row: any) => { row.last_revealed_at = new Date().toISOString(); }],
    ['later ACL has started', (_row: any, steps: any[]) => { steps[1].started_at = new Date().toISOString(); }],
    ['later Key receipt exists', (_row: any, steps: any[]) => { steps[2].receipt_secret = 'unexpected-receipt'; }],
    ['wrong final metadata handler', (_row: any, steps: any[]) => { steps[3].handler = 'portal.credential.rotate'; }],
    ['wrong parent in pending ACL row', (_row: any, steps: any[]) => { steps[1].parent_id = T.nativeId; }],
    ['sealed plan hash mismatch', (row: any) => { row.plan_hash = '0'.repeat(64); }],
    ['substituted sealed Key', (_row: any, _steps: any[], plan: any, seal: () => void) => { plan.steps[2].mutationPayload.key = 'SyntheticOtherKey'; seal(); }],
  ])('emits no secret or ciphertext on %s', async (_label, change) => {
    const f = await executeCapture(change); expect(f.fakeProcess.exitCode).toBe(2); expect(f.stdout).toEqual([]);
    expect(f.stderr).toEqual(['FAILED_ISSUE_CAPTURE_FAILED\n']); expect(f.stderr.join('')).not.toContain(f.key); expect(f.queries.at(-1)).toBe('ROLLBACK');
  });
  it('rejects tuple/purpose/tag tampering rather than reusing the failed Key transfer as Portal reveal', async () => {
    const f = await executeCapture(), encrypted = JSON.parse(f.stdout[0]);
    expect(() => failedIssueCaptureAad({ ...T, executionId: FIRST.executionId })).toThrow();
    expect(() => decryptFailedIssueTransfer({ ...encrypted, tag: '0'.repeat(32) }, f.transferKey)).toThrow();
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', f.transferKey, iv); cipher.setAAD(Buffer.from('portal-reveal'));
    const bytes = Buffer.concat([cipher.update(JSON.stringify({ tuple: T, key: f.key, validated: true })), cipher.final()]);
    expect(() => decryptFailedIssueTransfer({ version: 1, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: bytes.toString('base64') }, f.transferKey)).toThrow();
  });
  it('adds only private scanner material and leaves both failed history and previously active original grant unchanged', async () => {
    const f = await executeCapture(), prior = { testTag: 'm6-security-prior-offline', secrets: ['SyntheticPriorPrivateCanary'] }, actorId = '50000000-0000-4000-8000-000000000900';
    const reference: any = { testTag: 'm6-isolated-failed-review', fixtures: [{ cluster: { id: T.clusterId }, workspace: { id: T.workspaceId, code: 'm6-isolated-failed-review-portal' } }],
      consoleAdministrator: { user: { id: actorId } }, metadataRecovery: { phase: 'metadata-succeeded-original-execution', receiptState: 'succeeded', workflowId: FIRST.workflowId, executionId: FIRST.executionId, grantId: FIRST.grantId, credentialId: FIRST.credentialId },
      grants: [{ workflowId: FIRST.workflowId, grant: { id: FIRST.grantId }, credential: { id: FIRST.credentialId } }],
      writeAttempts: [{ key: T.executionKey, method: 'POST', state: 'response_observed', path: `/api/v1/clusters/${T.clusterId}/workflows/${T.workflowId}/execute`, query: `?workspaceId=${T.workspaceId}`, actorId, httpStatus: 409, errorCode: 'KONG_VALIDATION_ERROR' }],
      priorFixtureRuns: [{ checkpoint: prior, checkpointSha256: checkpointSha(prior) }], tokens: [{ token: 'SyntheticRetainedTelemetryToken' }], secrets: [] };
    const before = structuredClone(reference), bundle = decryptFailedIssueTransfer(JSON.parse(f.stdout[0]), f.transferKey), next = mergeFailedIssueCapture(reference, bundle);
    expect(reference).toEqual(before); for (const name of ['metadataRecovery', 'grants', 'writeAttempts', 'priorFixtureRuns', 'tokens']) expect(next[name]).toEqual(before[name]);
    expect(next.secrets).toContain(f.key); expect(next.failedIssueCredentialScanCaptures[0]).toMatchObject({ scannerOnly: true, businessWrites: 0, nativeWrites: 0 });
    expect(JSON.stringify(next.failedIssueCredentialScanCaptures)).not.toContain(f.key); expect(() => mergeFailedIssueCapture(next, bundle)).toThrow();
  });
});
