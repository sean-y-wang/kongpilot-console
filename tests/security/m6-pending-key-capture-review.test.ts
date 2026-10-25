import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createCipheriv, randomBytes } from 'node:crypto';
import * as crypto from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { portalKeyAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { PENDING_KEY_TUPLE as tuple, PENDING_CAPTURE_PROGRAM, pendingCaptureAad, decryptPendingTransfer, mergePendingCapture } from './lib/m6-pending-key-capture.mjs';
import { checkpointSha } from './lib/m6-isolated-transition.mjs';

beforeEach(() => { vi.stubEnv('APP_SECRET', 'offline-pending-scan-signing-key-at-least32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'bc'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

async function captureProgram(change: (row: any, native: any[]) => void = () => undefined) {
  const secrets = new SecretService(), transferKey = randomBytes(32), key = 'SyntheticOfflinePendingKeyCanary2026';
  const entity = { id: tuple.nativeId, consumer: { id: tuple.consumerId }, key };
  const row: any = { key_secret: secrets.encrypt({ key }, portalKeyAad(tuple.clusterId, tuple.workspaceId, tuple.credentialId, 1)),
    key_fingerprint: secrets.fingerprint(key), credential_state: 'pending', grant_state: 'pending', current_generation: 0,
    current_credential_id: null, credential_ref_id: null, issue_operation_id: null, workflow_state: 'uncertain', kind: 'portal-credential-issue',
    execution_state: 'uncertain', operation_state: 'succeeded', remote_completed: true, reference_state: 'active',
    payload_secret: secrets.encrypt({ credential: entity }, `credential:${tuple.clusterId}:${tuple.consumerId}:key-auth:${tuple.nativeId}`),
    result_secret: secrets.encrypt({ entity }, `mutation:${tuple.keyOperationId}:result`) };
  const opIds = [tuple.consumerOperationId, tuple.aclOperationId, tuple.keyOperationId];
  const entityIds = [tuple.consumerId, tuple.aclId, tuple.nativeId];
  const native: any[] = opIds.map((operationId: string, index: number) => ({ id: `synthetic-step-${index}`, kind: 'native', handler: null,
    state: 'succeeded', operation_id: operationId, native_operation_id: operationId, operation_state: 'succeeded', remote_completed: true,
    entity_id: entityIds[index], entity_type: index ? 'credentials' : 'consumers', parent_id: index ? tuple.consumerId : null,
    credential_kind: index === 1 ? 'acls' : index === 2 ? 'key-auth' : null }));
  native.push({ id: tuple.metadataStepId, kind: 'metadata', handler: 'portal.credential.activate', state: 'uncertain', operation_id: null });
  change(row, native);
  const queries: string[] = [], stdout: string[] = [], stderr: string[] = [];
  const client = { query: async (sql: string) => {
    queries.push(sql);
    if (sql.startsWith('BEGIN') || sql === 'ROLLBACK') return { rows: [] };
    if (sql.includes('FROM portal_credentials')) return { rows: [row] };
    if (sql.includes('FROM workflow_steps')) return { rows: native };
    if (sql.includes('FROM credential_refs')) return { rows: [{ id: tuple.aclReferenceId }] };
    throw new Error('UNEXPECTED_OFFLINE_SQL');
  }, release: vi.fn() };
  const fakeProcess: any = { env: {}, stdout: { write: (value: string) => stdout.push(value) }, stderr: { write: (value: string) => stderr.push(value) } };
  const sandbox = { Buffer, process: fakeProcess, require: (name: string) => {
    if (name === 'node:fs') return { readFileSync: () => Buffer.from(JSON.stringify({ key: transferKey.toString('hex'), tuple })) };
    if (name === 'node:crypto') return crypto;
    if (name === 'pg') return { Pool: class { async connect() { return client; } async end() {} } };
    if (name.endsWith('secret.service.js')) return { SecretService };
    if (name.endsWith('portal-proof.js')) return { portalKeyAad };
    throw new Error('UNEXPECTED_OFFLINE_REQUIRE');
  } };
  await runInNewContext(PENDING_CAPTURE_PROGRAM, sandbox, { timeout: 1000 });
  return { key, transferKey, stdout, stderr, queries, fakeProcess };
}

describe('M6 independent pending scanner transfer, offline trusted program', () => {
  it('runs the actual capture program with only SELECT/READONLY and transfers authenticated ciphertext', async () => {
    const f = await captureProgram();
    expect(f.fakeProcess.exitCode).toBeUndefined(); expect(f.stderr).toEqual([]); expect(f.stdout).toHaveLength(1);
    expect(f.stdout[0]).not.toContain(f.key); expect(f.stdout[0]).not.toContain(f.transferKey.toString('hex'));
    expect(f.queries[0]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'); expect(f.queries.at(-1)).toBe('ROLLBACK');
    expect(f.queries.every(sql => /^(?:SELECT|BEGIN|ROLLBACK)/.test(sql))).toBe(true);
    expect(decryptPendingTransfer(JSON.parse(f.stdout[0]), f.transferKey)).toEqual({ key: f.key, tuple, validated: true });
  });

  it.each([
    ['wrong metadata step', (_r: any, steps: any[]) => { steps[3].id = tuple.keyOperationId; }],
    ['other metadata handler', (_r: any, steps: any[]) => { steps[3].handler = 'portal.credential.rotate'; }],
    ['another Consumer', (_r: any, steps: any[]) => { steps[0].entity_id = tuple.aclId; }],
    ['wrong credential table', (_r: any, steps: any[]) => { steps[1].entity_type = 'plugins'; }],
    ['foreign ACL parent', (_r: any, steps: any[]) => { steps[1].parent_id = tuple.nativeId; }],
    ['credential kind confusion', (_r: any, steps: any[]) => { steps[1].credential_kind = 'key-auth'; }],
    ['substituted successful operation', (_r: any, steps: any[]) => { steps[0].operation_id = steps[0].native_operation_id = tuple.keyOperationId; }],
    ['unknown native step', (_r: any, steps: any[]) => { steps[2].remote_completed = false; }],
    ['already activated credential', (r: any) => { r.credential_state = 'active'; }],
    ['mismatched remembered key', (r: any) => { r.key_fingerprint = '0'.repeat(64); }],
  ])('emits zero ciphertext/plaintext for %s', async (_label, change) => {
    const f = await captureProgram(change); expect(f.fakeProcess.exitCode).toBe(2); expect(f.stdout).toEqual([]);
    expect(f.stderr).toEqual(['PENDING_KEY_CAPTURE_FAILED\n']); expect(f.stderr.join('')).not.toContain(f.key);
    expect(f.queries.at(-1)).toBe('ROLLBACK');
  });

  it('rejects purpose/tuple/tag/ciphertext tampering and preserves all original journals when merging', async () => {
    const f = await captureProgram(), encrypted = JSON.parse(f.stdout[0]);
    expect(() => decryptPendingTransfer({ ...encrypted, ciphertext: encrypted.ciphertext.slice(4) }, f.transferKey)).toThrow();
    expect(() => decryptPendingTransfer({ ...encrypted, tag: '0'.repeat(32) }, f.transferKey)).toThrow();
    const wrongPurposeIv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', f.transferKey, wrongPurposeIv); cipher.setAAD(Buffer.from('portal-reveal'));
    const wrongPurposeBody = Buffer.concat([cipher.update(JSON.stringify({ key: f.key, tuple, validated: true })), cipher.final()]);
    expect(() => decryptPendingTransfer({ version: 1, iv: wrongPurposeIv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: wrongPurposeBody.toString('base64') }, f.transferKey)).toThrow();
    const checkpoint = { testTag: 'prior-offline', writeAttempts: [{ key: 'immutable-old-key', body: { name: 'kept' } }], secrets: ['SyntheticPriorCanary'] };
    const reference: any = { testTag: 'current-offline', fixtures: [{ cluster: { id: tuple.clusterId }, workspace: { id: tuple.workspaceId, code: 'current-offline-pay' } }],
      writeAttempts: [{ key: tuple.executionKey, path: `/api/v1/clusters/${tuple.clusterId}/workflows/${tuple.workflowId}/execute`, query: `?workspaceId=${tuple.workspaceId}`, httpStatus: 503, errorCode: 'WORKFLOW_EXECUTION_FAILED' }],
      tokens: [{ purpose: 'native_scrape', token: 'SyntheticMetricsTokenPreserved' }], secrets: [],
      priorFixtureRuns: [{ checkpoint, checkpointSha256: checkpointSha(checkpoint) }], credentialContinuation: { completed: true } };
    const before = structuredClone(reference), bundle = decryptPendingTransfer(encrypted, f.transferKey), next = mergePendingCapture(reference, bundle);
    expect(reference).toEqual(before); expect(next.writeAttempts).toEqual(before.writeAttempts); expect(next.tokens).toEqual(before.tokens);
    expect(next.priorFixtureRuns).toEqual(before.priorFixtureRuns); expect(next.credentialContinuation).toEqual(before.credentialContinuation);
    expect(next.pendingCredentialScanCaptures[0]).toMatchObject({ scannerOnly: true, businessActivationPerformed: false, nativeWritesPerformed: 0 });
    expect(JSON.stringify(next.pendingCredentialScanCaptures)).not.toContain(f.key);
    expect(() => pendingCaptureAad({ ...tuple, workflowId: tuple.grantId })).toThrow();
  });
});
