import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { sha256 } from './m7-harness.mjs';

export const M7_BLOCKED_UI_EXPORT = Object.freeze({
  index: 294, manualIndex: 8, key: '508ce003-e8e0-4e2f-9189-636f6fafb973',
  rawBodySha256: '6ba7679174733fce34db92f45dd96873ebdb5152bedf2e22c95229108e507239',
  packetSha256: 'faa5aa57a1aaedf4dba0d48e7d48bacb79df524aeb4592b20e6e736e5dfa56be',
  actorId: '721af4e8-548e-4020-aa12-89127abe1e28', sessionId: '34c05d84-e69f-42a7-8060-4a48c17c785a',
  clusterId: 'dff45535-ed8d-4851-b7a6-6376feac7f59', workspaceId: '4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5',
  failurePath: 'artifacts/M7/manual-ui-eight-write-unsent-export-failure.json',
  failureSha256: '2041f2ccd9b48206f833d712f5ababc7633810f303367b2768406d2ccccf13c0'
});

/** One exact route-aborted browser packet, retained alongside twelve actual
 * confirmed writes. Missing status alone never establishes an unsent packet. */
export function isKnownM7BlockedUiExport(reference, packet) {
  const f = M7_BLOCKED_UI_EXPORT, marker = reference?.manualUiEightWriteContinuation, journal = reference?.manualUiJournal;
  if (reference?.version !== 1 || reference.milestone !== 'M7' || reference.testTag !== 'm7-security-b81047b2' || marker?.version !== 1 || marker.phase !== 'active' ||
    marker.failureSha256 !== f.failureSha256 || marker.archivePath !== f.failurePath || marker.blockedOriginalKey !== f.key ||
    reference.manualUiEightWriteContinuationHistory?.version !== 1 || !reference.manualUiEightWriteContinuationHistory.externalReference ||
    !Array.isArray(marker.originalHttpRequests) || marker.originalHttpRequests.length !== f.index + 1 ||
    !isDeepStrictEqual(marker.originalHttpRequests, reference.requests?.slice(0, f.index + 1)) || !isDeepStrictEqual(marker.originalHttpRequests[f.index], packet) ||
    !Array.isArray(journal?.priorKeys) || !journal.priorKeys.includes(f.key) || journal.attempts?.some(a => a.key === f.key) || reference.requests?.filter(p => p.key === f.key).length !== 1) return false;
  if (packet?.source !== 'manual-ui' || packet.state !== 'blocked-before-packet' || packet.index !== f.index || packet.manualIndex !== f.manualIndex ||
    sha256(JSON.stringify(packet)) !== f.packetSha256 ||
    packet.action !== 'audit-export' || packet.role !== 'admin' || packet.method !== 'POST' || packet.key !== f.key || packet.actorId !== f.actorId ||
    packet.originalExpectedActorId !== f.actorId || packet.sessionId !== f.sessionId || packet.clusterId !== f.clusterId || packet.workspaceId !== f.workspaceId ||
    packet.status != null || packet.requestId != null || packet.responseData != null || packet.responseSha256 != null || packet.receiptRequestId != null || packet.receiptData != null ||
    packet.path != null || packet.query != null || packet.body != null || packet.bodySha256 != null || packet.headers?.['x-idempotency-key'] !== f.key ||
    typeof packet.rawBody !== 'string' || sha256(packet.rawBody) !== f.rawBodySha256 || packet.url !== `http://127.0.0.1:8080/api/v1/clusters/${f.clusterId}/audit/exports?workspaceId=${f.workspaceId}` ||
    !isDeepStrictEqual(JSON.parse(packet.rawBody), { format: 'csv', confirmed: true, workspaceId: f.workspaceId }) || !isDeepStrictEqual(packet.expected, [200, 201])) return false;
  const firstEight = marker.originalHttpRequests.filter(p => p.source === 'manual-ui' && p.state === 'succeeded');
  return firstEight.length === 8 && firstEight.every((p, i) => p.manualIndex === i && p.key === journal.attempts?.[i]?.key && p.requestId === journal.attempts[i].requestId &&
    p.rawBody === journal.attempts[i].rawBody && p.receiptRequestId === journal.attempts[i].receiptRequestId && p.bodySha256 === journal.attempts[i].bodySha256 && p.state === journal.attempts[i].state);
}

export function readM7BlockedUiExportEvidence(reference, reader = readFileSync) {
  const f = M7_BLOCKED_UI_EXPORT, packet = reference?.requests?.[f.index];
  if (!isKnownM7BlockedUiExport(reference, packet)) throw new Error('M7_BLOCKED_UI_EXPORT_NOT_EXACT');
  const bytes = reader(f.failurePath), report = JSON.parse(bytes);
  if (sha256(bytes) !== f.failureSha256 || report.testTag !== reference.testTag || report.allPassed !== false || report.failed !== 1 || report.passed !== 8 ||
    report.successfulUiWrites !== 8 || report.unknownUiWrites !== 0 || report.unresolvedUiWrites !== 0 || report.blockedBeforePacketAttempts !== 1 || report.screenshots?.length !== 4 ||
    report.checks?.length !== 9 || report.checks.slice(0, 8).some(v => v.passed !== true)) throw new Error('M7_BLOCKED_UI_EXPORT_FAILURE_CHANGED');
  return { beforeTransportAttempts: 1, originalFailurePath: f.failurePath, originalFailureSha256: f.failureSha256, originalRecordIndex: f.index, originalKey: f.key,
    originalRawBodySha256: f.rawBodySha256, originalPacketSha256: f.packetSha256, originalEightSuccessfulWritesRetained: true, transportAttempted: false, requestIdExpected: false, auditObligation: false };
}
