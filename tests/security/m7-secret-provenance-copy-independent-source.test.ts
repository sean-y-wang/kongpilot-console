// @ts-nocheck -- real collector; synthetic RAM references only, no constructor.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { m7CapturedSecrets } from './lib/m7-secret-scan-policy.mjs';
import { sha256 } from './lib/m7-harness.mjs';

function fixture() {
  const key = randomUUID(), clusterId = randomUUID(), workspaceId = randomUUID();
  const body = { name: 'synthetic-channel', auth: { token: 'SyntheticCapturedBearer!47' } };
  const packet = { index: 0, key, method: 'POST', path: `/api/v1/clusters/${clusterId}/events/channels`, query: `?workspaceId=${workspaceId}`,
    body, bodySha256: sha256(JSON.stringify(body)), actorId: randomUUID(), sessionId: randomUUID(), clusterId, workspaceId,
    headers: { Cookie: 'kongos_access=SyntheticCapturedAccess!47', 'X-CSRF-Token': 'SyntheticCapturedCsrf!47', 'X-Idempotency-Key': key, 'Content-Type': 'application/json' },
    state: 'response_observed', status: 201, requestId: randomUUID(), responseData: { entity: { id: randomUUID(), key: '[REDACTED:0123456789abcdef]' } },
  };
  const reference = { version: 1, milestone: 'M7', testTag: 'synthetic-copy-provenance', requests: [packet],
    secrets: ['SyntheticCapturedBearer!47', 'SyntheticCapturedAccess!47', 'SyntheticCapturedCsrf!47'] };
  const copy = structuredClone(packet), history = { version: 1, milestone: 'M7', testTag: reference.testTag, secrets: [...reference.secrets],
    manualUiFiveRowActiveHistory: { originalHttpRequests: [copy] } };
  return { reference, packet, copy, history };
}
function secondPacket(f, overrides = {}) {
  const packet = structuredClone(f.packet); packet.index = 1; packet.key = randomUUID(); packet.requestId = randomUUID();
  packet.headers['X-Idempotency-Key'] = packet.key; packet.body = { name: 'synthetic-second' }; packet.responseData = { entity: { id: randomUUID() } };
  Object.assign(packet, overrides); packet.bodySha256 = sha256(JSON.stringify(packet.body)); f.reference.requests.push(packet); return packet;
}

describe('independent full originalHttpRequests copy provenance', () => {
  it('accepts a byte-equivalent full checkpoint packet without classifying its public operation key as a credential', () => {
    const f = fixture(), before = JSON.stringify({ reference: f.reference, history: f.history });
    expect(m7CapturedSecrets(f.reference, [f.history])).toEqual(f.reference.secrets);
    expect(m7CapturedSecrets(f.reference, [f.history])).not.toContain(f.packet.key);
    expect(JSON.stringify({ reference: f.reference, history: f.history })).toBe(before);
  });
  it('binds a same-key retry copy to its own index and complete original packet', () => {
    const f = fixture(), retry = structuredClone(f.packet); retry.index = 1; retry.status = 200; retry.requestId = randomUUID();
    f.reference.requests.push(retry); f.history.manualUiFiveRowActiveHistory.originalHttpRequests = [structuredClone(retry)];
    expect(m7CapturedSecrets(f.reference, [f.history])).toEqual(f.reference.secrets);
  });
  it.each(['sessionId', 'actorId', 'clusterId', 'workspaceId', 'body', 'headers'])('rejects a retained copy with changed or missing %s', field => {
    const f = fixture();
    if (field === 'body') f.copy.body.name = 'changed-copy-only';
    else if (field === 'headers') delete f.copy.headers;
    else f.copy[field] = randomUUID();
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it.each(['payload', 'response'])('the same public UUID remains protected as a %s key', location => {
    const f = fixture();
    if (location === 'payload') {
      f.packet.body.key = f.packet.key; f.packet.bodySha256 = sha256(JSON.stringify(f.packet.body));
    } else f.packet.responseData.key = f.packet.key;
    f.history.manualUiFiveRowActiveHistory.originalHttpRequests = [structuredClone(f.packet)];
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('a complete matching copy inside body.inner.originalHttpRequests never escapes the body secret context', () => {
    const f = fixture(); secondPacket(f, { body: { inner: { originalHttpRequests: [structuredClone(f.packet)] } } });
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('a complete matching copy inside an actual successful response never gains checkpoint metadata provenance', () => {
    const f = fixture(); secondPacket(f, { responseData: { originalHttpRequests: [structuredClone(f.packet)] } });
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('shared object identity between a checkpoint and payload retains separate effective provenance', () => {
    const f = fixture(); secondPacket(f, { body: { inner: { originalHttpRequests: [f.copy] } } });
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('arbitrary originalPacket copies remain outside the single retained-field exception', () => {
    const f = fixture(); f.history = { version: 1, milestone: 'M7', testTag: f.reference.testTag, secrets: [...f.reference.secrets], originalPacket: structuredClone(f.packet) };
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
});

function budgetFixture() {
  return { version: 1, milestone: 'M7', testTag: 'synthetic-structural-budget', requests: [], secrets: ['SyntheticBudgetCredential!47'] };
}
function chain(length, tail = { terminal: true }) {
  let value = tail;
  for (let index = 0; index < length; index++) value = { next: value };
  return value;
}

describe('independent structural hash and effective context bounds', () => {
  it('does not merge a differently ordered full packet into an accepted exact copy', () => {
    const f = fixture(), reordered = Object.fromEntries(Object.entries(f.packet).reverse());
    expect(JSON.stringify(reordered)).not.toBe(JSON.stringify(f.packet));
    // LIFO visits the valid copy first. A hash which sorted property names
    // would incorrectly skip the invalid copy in the same semantic context.
    f.history.manualUiFiveRowActiveHistory.originalHttpRequests = [reordered, structuredClone(f.packet)];
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('does not merge arrays whose order changes retained packet provenance', () => {
    const f = fixture(); f.packet.body.values = ['first', 'second']; f.packet.bodySha256 = sha256(JSON.stringify(f.packet.body));
    const reordered = structuredClone(f.packet); reordered.body.values.reverse();
    f.history.manualUiFiveRowActiveHistory.originalHttpRequests = [reordered, structuredClone(f.packet)];
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('classifies equal cloned subtrees separately when one is a successful response and another is a body', () => {
    const f = fixture(), redacted = { token: '[REDACTED:0123456789abcdef]' };
    // responseData is inserted later and is visited first. Its trusted marker
    // must not cause the structurally equal body subtree to be skipped.
    secondPacket(f, { body: structuredClone(redacted), responseData: structuredClone(redacted) });
    expect(() => m7CapturedSecrets(f.reference, [f.history])).toThrow('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
  });
  it('accepts more than 200000 physical cloned leaves when their structural and semantic values remain bounded', () => {
    const reference = budgetFixture(); reference.neutralNodes = Array.from({ length: 12500 }, (_, ordinal) => ({ ordinal }));
    const histories = Array.from({ length: 16 }, () => structuredClone(reference));
    expect(17 * reference.neutralNodes.length).toBeGreaterThan(200000);
    expect(m7CapturedSecrets(reference, histories)).toEqual(reference.secrets);
  }, 20000);
  it('rejects 200001 genuinely distinct structural leaves without increasing the unique-object limit', () => {
    const reference = budgetFixture(); reference.neutralNodes = Array.from({ length: 200001 }, (_, ordinal) => ({ ordinal }));
    expect(() => m7CapturedSecrets(reference)).toThrow('M7_SECRET_HISTORY_BUDGET');
  }, 20000);
  it('rejects cyclic neutral input before semantic deduplication', () => {
    const reference = budgetFixture(); reference.neutral = {}; reference.neutral.self = reference.neutral;
    expect(() => m7CapturedSecrets(reference)).toThrow('M7_SECRET_HISTORY_CYCLE');
  });
  it('rejects an ordinary neutral path deeper than 64 object edges', () => {
    const reference = budgetFixture(); reference.neutral = chain(65);
    expect(() => m7CapturedSecrets(reference)).toThrow('M7_SECRET_HISTORY_BUDGET');
  });
  it('rejects a deep path even when the identical physical subtree was previously hashed and visited at a shallow path', () => {
    const reference = budgetFixture(), shared = chain(30); reference.neutral = shared;
    const history = { version: 1, milestone: 'M7', testTag: reference.testTag,
      deep: chain(40, shared), shallow: shared };
    // Current input hashes shared first; the history's later shallow field is
    // semantically visited first. Neither cache may hide its 71-deep path.
    expect(() => m7CapturedSecrets(reference, [history])).toThrow('M7_SECRET_HISTORY_BUDGET');
  });
});
