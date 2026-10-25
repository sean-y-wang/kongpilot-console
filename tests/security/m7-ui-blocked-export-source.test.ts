// @ts-nocheck -- exact synthetic journal objects; no environment or runtime.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { isDeepStrictEqual } from 'node:util';
import { M7_BLOCKED_UI_EXPORT as f, isKnownM7BlockedUiExport as actualPredicate } from './lib/m7-ui-blocked-export.mjs';
import { sha256 } from './lib/m7-harness.mjs';
import { m7KnownWritePacket } from './lib/m7-secret-scan-policy.mjs';
function fixture() {
  const requests = Array.from({ length: 295 }, (_, index) => ({ index, key: randomUUID(), state: 'response_observed' }));
  const attempts = Array.from({ length: 12 }, (_, i) => ({ index: i, key: randomUUID(), state: 'succeeded', requestId: randomUUID(), receiptRequestId: randomUUID(), rawBody: '{}', bodySha256: 'synthetic' }));
  for (let i = 0; i < 8; i++) requests[283 + i] = { ...attempts[i], source: 'manual-ui', index: 283 + i, manualIndex: i };
  const packet = { source: 'manual-ui', state: 'blocked-before-packet', index: f.index, manualIndex: f.manualIndex, action: 'audit-export', role: 'admin', method: 'POST', key: f.key,
    actorId: f.actorId, originalExpectedActorId: f.actorId, sessionId: f.sessionId, clusterId: f.clusterId, workspaceId: f.workspaceId, headers: { 'x-idempotency-key': f.key },
    rawBody: JSON.stringify({ format: 'csv', confirmed: true, workspaceId: f.workspaceId }), url: `http://127.0.0.1:8080/api/v1/clusters/${f.clusterId}/audit/exports?workspaceId=${f.workspaceId}`, expected: [200, 201] };
  requests[f.index] = packet;
  const reference = { version: 1, milestone: 'M7', testTag: 'm7-security-b81047b2', requests, manualUiJournal: { priorKeys: [f.key], attempts },
    manualUiEightWriteContinuationHistory: { version: 1, externalReference: { sha256: 'a'.repeat(64) } },
    manualUiEightWriteContinuation: { version: 1, phase: 'active', failureSha256: f.failureSha256, archivePath: f.failurePath, blockedOriginalKey: f.key, originalHttpRequests: structuredClone(requests) } };
  return { reference, packet };
}
// Substitute only the private packet-byte trust anchor in RAM. The product
// retains its exact real captured SHA and rejects these synthetic packets.
const ram = runInNewContext(readFileSync(new URL('./lib/m7-ui-blocked-export.mjs', import.meta.url), 'utf8')
  .replace(/^import .*;\n/gm, '').replaceAll(f.packetSha256, sha256(JSON.stringify(fixture().packet))).replaceAll('export ', '')
  + ';({isKnownM7BlockedUiExport,readM7BlockedUiExportEvidence});', { sha256, isDeepStrictEqual: (a, b) => isDeepStrictEqual(structuredClone(a), structuredClone(b)), readFileSync: () => { throw Error('UNEXPECTED_RUNTIME_READ'); } });
const { isKnownM7BlockedUiExport, readM7BlockedUiExportEvidence } = ram;
describe('one exact retained M7 route-aborted export packet', () => {
  it('recognizes the precise before-transport record without deleting it or changing confirmed writes', () => {
    const { reference, packet } = fixture(), snapshot = JSON.stringify(reference);
    expect(isKnownM7BlockedUiExport(reference, packet)).toBe(true); expect(actualPredicate(reference, packet)).toBe(false); expect(JSON.stringify(reference)).toBe(snapshot);
  });
  it('the full private original header bytes cannot change even with a self-consistent altered prefix', () => {
    const { reference, packet } = fixture(); packet.headers.Cookie = 'SyntheticChangedOpaqueCookie'; reference.manualUiEightWriteContinuation.originalHttpRequests[f.index] = structuredClone(packet);
    expect(isKnownM7BlockedUiExport(reference, packet)).toBe(false);
  });
  for (const [field, value] of [['index', 293], ['key', randomUUID()], ['actorId', randomUUID()], ['sessionId', randomUUID()], ['clusterId', randomUUID()], ['workspaceId', randomUUID()], ['method', 'PATCH'], ['state', 'response_unknown'], ['status', 201], ['requestId', randomUUID()], ['receiptData', {}], ['rawBody', '{}']]) {
    it(`refuses changed ${field}, including any HTTP or receipt evidence`, () => {
      const { reference, packet } = fixture(); packet[field] = value; reference.manualUiEightWriteContinuation.originalHttpRequests[f.index] = structuredClone(packet);
      expect(isKnownM7BlockedUiExport(reference, packet)).toBe(false); expect(m7KnownWritePacket(reference, packet)).toBe(false);
    });
  }
  it('refuses missing sealed failure, replayed key, or changed original eight-success prefix', () => {
    for (const mutate of [r => { r.manualUiEightWriteContinuation.failureSha256 = '0'.repeat(64); }, r => { r.manualUiJournal.attempts[8].key = f.key; }, r => { r.requests[283].requestId = randomUUID(); }, r => { delete r.manualUiEightWriteContinuationHistory; }]) {
      const { reference, packet } = fixture(); mutate(reference); expect(isKnownM7BlockedUiExport(reference, packet)).toBe(false);
    }
  });
  it('missing response alone cannot exempt an arbitrary blocked request', () => {
    const { reference, packet } = fixture(); const arbitrary = { ...packet, index: 7, key: randomUUID() }; expect(m7KnownWritePacket(reference, arbitrary)).toBe(false);
  });
  it('requires byte-identical fixed public failed attempt evidence', () => {
    const { reference } = fixture(); expect(() => readM7BlockedUiExportEvidence(reference, () => Buffer.from('{}'))).toThrow('FAILURE_CHANGED');
  });
});
