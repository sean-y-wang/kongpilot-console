import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ReleaseHarness, releaseScope } from '../security/lib/release-harness.mjs';

/** Isolated in-memory journal policy only. Never construct the real harness,
 * read private RAM, replace an actual receipt, or send a network request. */
function fixture() {
  const actorId = randomUUID(), clusterId = randomUUID(), workspaceId = randomUUID(), workflowId = randomUUID(),
    executionId = randomUUID(), requestId = randomUUID(), key = randomUUID(), planHash = 'c'.repeat(64);
  const original: any = { actorId, key, requestId, method: 'POST', status: 503, state: 'response_observed',
    path: releaseScope(clusterId, workspaceId, `workflows/${workflowId}/execute`),
    resolution: { factProofSha256: 'a'.repeat(64), metadataRecovery: { kind: 'entity-change-no-send',
      clusterId, workspaceId, workflowId, executionId, planHash, revision: 8 } } };
  const harness: any = Object.create(ReleaseHarness.prototype);
  harness.state = { requests: [original] };
  const operation: any = { session: { user: { id: actorId } }, method: 'POST', key,
    path: releaseScope(clusterId, workspaceId, `workflows/${workflowId}/reconcile-no-send`), metadataOnlyFor: requestId,
    body: { executionId, planHash, revision: 8, confirmed: true, confirm_name: 'native-change' } };
  return { harness, original, operation };
}

describe('M11 release journal permits only the proven original no-send metadata closure', () => {
  it('allows the one exact metadata request while preserving the original 503 and blocking normal writes', () => {
    const f = fixture(), before = JSON.stringify(f.original);
    expect(() => f.harness.assertWritable(f.operation)).not.toThrow();
    expect(JSON.stringify(f.original)).toBe(before);
    expect(() => f.harness.assertWritable()).toThrow('NO_REPLAY');
    expect(() => f.harness.assertWritable({ ...f.operation, path: f.original.path })).toThrow('NO_REPLAY');
    expect(() => f.harness.assertWritable({ ...f.operation, path: '/auth/refresh', body: undefined })).toThrow('NO_REPLAY');
  });

  it.each(['key', 'actor', 'cluster', 'workspace', 'workflow', 'execution', 'hash', 'revision', 'confirmation',
    'confirmation-name', 'extra-body', 'method', 'native-path', 'original-request', 'missing-link', 'bad-digest',
    'unknown-response', 'prepared-original', 'different-status', 'different-kind', 'second-unresolved-write'])
  ('rejects altered %s without rewriting or clearing the original failure', variant => {
    const f = fixture(), proof = f.original.resolution.metadataRecovery;
    if (variant === 'key') f.operation.key = randomUUID();
    if (variant === 'actor') f.operation.session.user.id = randomUUID();
    if (variant === 'cluster') f.operation.path = f.operation.path.replace(proof.clusterId, randomUUID());
    if (variant === 'workspace') f.operation.path = f.operation.path.replace(proof.workspaceId, randomUUID());
    if (variant === 'workflow') f.operation.path = f.operation.path.replace(proof.workflowId, randomUUID());
    if (variant === 'execution') f.operation.body.executionId = randomUUID();
    if (variant === 'hash') f.operation.body.planHash = 'd'.repeat(64);
    if (variant === 'revision') f.operation.body.revision++;
    if (variant === 'confirmation') f.operation.body.confirmed = false;
    if (variant === 'confirmation-name') f.operation.body.confirm_name = 'workspace-migration';
    if (variant === 'extra-body') f.operation.body.approved = true;
    if (variant === 'method') f.operation.method = 'PATCH';
    if (variant === 'native-path') f.operation.path = f.original.path;
    if (variant === 'original-request') f.operation.metadataOnlyFor = randomUUID();
    if (variant === 'missing-link') delete f.operation.metadataOnlyFor;
    if (variant === 'bad-digest') f.original.resolution.factProofSha256 = 'operator-guess-not-real-proof';
    if (variant === 'unknown-response') f.original.state = 'response_unknown';
    if (variant === 'prepared-original') f.original.state = 'prepared';
    if (variant === 'different-status') f.original.status = 500;
    if (variant === 'different-kind') proof.kind = 'native-retry';
    if (variant === 'second-unresolved-write') f.harness.state.requests.push({ state: 'prepared' });
    const before = JSON.stringify(f.harness.state);
    expect(() => f.harness.assertWritable(f.operation)).toThrow('NO_REPLAY');
    expect(JSON.stringify(f.harness.state)).toBe(before);
  });
});
