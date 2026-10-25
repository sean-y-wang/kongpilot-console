import { cookieMerge } from './m7-harness.mjs';
import { createHash } from 'node:crypto';
import { isKnownM7StoppedSamplingIntent } from './m7-blocked-observation.mjs';
import { isKnownM7BlockedUiExport, M7_BLOCKED_UI_EXPORT } from './m7-ui-blocked-export.mjs';

export const M7_LOG_SERVICES = Object.freeze(['kong', 'kong-secondary', 'kong-portal', 'console-api', 'console-web', 'portal-web', 'telemetry-collector', 'event-receiver', 'event-mail']);
export function m7KnownWritePacket(reference, value) {
  if (value.state === 'response_observed') return true;
  if (isKnownM7BlockedUiExport(reference, value)) return true;
  if (value.source !== 'manual-ui' || value.state !== 'succeeded' || reference.manualUiJournal?.phase !== 'complete' || reference.manualUiJournal.inFlight !== null) return false;
  const attempt = reference.manualUiJournal.attempts.find(a => a.index === value.manualIndex);
  return !!attempt && attempt.key === value.key && attempt.requestId === value.requestId && attempt.bodySha256 === value.bodySha256 && attempt.actorId === value.actorId && attempt.sessionId === value.sessionId && attempt.path === value.path && attempt.query === value.query && attempt.method === value.method && attempt.clusterId === value.clusterId && attempt.workspaceId === value.workspaceId && attempt.state === 'succeeded' && typeof attempt.receiptRequestId === 'string' && attempt.receiptData != null;
}
export function m7SecretForms(values) {
  return [...new Set(values.filter(value => typeof value === 'string' && value.length > 0).flatMap(value => [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString('base64')]))];
}
function cookieSecrets(value) {
  return value.split(';').flatMap(pair => {
    const at = pair.indexOf('=');
    return at > 0 && /^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(pair.slice(0, at).trim()) ? [pair.slice(at + 1).trim()] : [];
  });
}
/** Every packet is captured before transport; all cookie header generations
 * precede body parsing. Historical secret registries must remain a subset of
 * the current cumulative registry. Public idempotency UUIDs are never secrets. */
export function m7CapturedSecrets(reference, histories = [], diagnose) {
  if (reference?.version !== 1 || reference.milestone !== 'M7' || !Array.isArray(reference.secrets) || reference.secrets.some(value => typeof value !== 'string' || !value)) throw new Error('M7_SECRET_REGISTRY_INVALID');
  if (!Array.isArray(histories) || histories.length > 32 || histories.some(value => value?.version !== 1 || value.milestone !== 'M7' || value.testTag !== reference.testTag)) throw new Error('M7_SECRET_HISTORY_INVALID');
  // Byte-exact JSON histories contain independent copies. Hash each physical
  // object once, then classify each structural value in each effective context.
  // Input bytes retain the existing current32MiB + history128MiB bounds;
  // distinct structural objects and semantic visits still stop at 200000.
  const digests = new WeakMap(), heights = new WeakMap(), hashing = new WeakSet(), structures = new Set(); let hashedBytes = 0;
  const digest = (value, depth = 0) => {
    if (!value || typeof value !== 'object') {
      const token = String(JSON.stringify(value)); hashedBytes += Buffer.byteLength(token, 'utf8');
      if (hashedBytes > 160 * 1024 * 1024) throw new Error('M7_SECRET_HISTORY_BYTE_BUDGET');
      return createHash('sha256').update(typeof value).update(':').update(token).digest('hex');
    }
    if (depth > 64) throw new Error('M7_SECRET_HISTORY_BUDGET');
    if (hashing.has(value)) throw new Error('M7_SECRET_HISTORY_CYCLE');
    if (digests.has(value)) {
      if (depth + heights.get(value) > 64) throw new Error('M7_SECRET_HISTORY_BUDGET');
      return digests.get(value);
    }
    hashing.add(value); const hash = createHash('sha256').update(Array.isArray(value) ? 'array:' : 'object:');
    hashedBytes += 2; let height = 0;
    // Preserve key order: retained-packet provenance requires full JSON equality.
    const entries = Array.isArray(value) ? value.map((child, index) => [String(index), child]) : Object.entries(value);
    for (const [name, child] of entries) {
      const key = JSON.stringify(name); hashedBytes += Buffer.byteLength(key, 'utf8') + 2;
      if (hashedBytes > 160 * 1024 * 1024) throw new Error('M7_SECRET_HISTORY_BYTE_BUDGET');
      hash.update(key).update(':').update(digest(child, depth + 1)).update(';');
      if (child && typeof child === 'object') height = Math.max(height, 1 + heights.get(child));
    }
    const result = hash.digest('hex'); hashing.delete(value); digests.set(value, result); heights.set(value, height); structures.add(result);
    if (structures.size > 200000) throw new Error('M7_SECRET_HISTORY_BUDGET');
    return result;
  };
  [reference, ...histories].forEach(value => digest(value));
  const captured = new Set(reference.secrets), visited = new Set(), pending = [reference, ...histories].map(value => [value, 0, null, false, false]); let count = 0;
  const requireCaptured = (value, fromResponse = false, kind = 'history-registry') => {
    if (typeof value === 'string' && value && !(fromResponse && /^\[REDACTED:[a-f\d]{16}\]$/.test(value)) && !captured.has(value)) {
      // This optional private diagnostic cannot authorize omission or replace
      // the strict registry check. The error and fail-closed outcome are fixed.
      if (typeof diagnose === 'function') diagnose({ kind, trustedResponse: fromResponse,
        originalPacketKey: reference.requests.some(packet => packet.key === value), cookieValue: /^eyJ/.test(value) });
      throw new Error('M7_CAPTURED_SECRET_REGISTRY_INCOMPLETE');
    }
  };
  while (pending.length) {
    const [node, depth, owner, fromResponse, fromBody] = pending.pop();
    if (!node || typeof node !== 'object') continue;
    if (depth > 64) throw new Error('M7_SECRET_HISTORY_BUDGET');
    const context = `${fromResponse}:${fromBody}:${['requests', 'originalHttpRequests', 'attempts', 'eventOperations'].includes(owner) ? owner : 'other'}`, identity = `${digests.get(node)}:${context}`;
    if (visited.has(identity)) continue;
    if (++count > 200000) throw new Error('M7_SECRET_HISTORY_BUDGET');
    visited.add(identity);
    if (Array.isArray(node)) { for (const child of node) if (child && typeof child === 'object') pending.push([child, depth + 1, owner, fromResponse, fromBody]); continue; }
    for (const [name, value] of Object.entries(node)) {
      if (name === 'secrets' && Array.isArray(value)) value.forEach(v => requireCaptured(v));
      if (/^(password|current_password|new_password|secret|token|csrfToken|client_secret|accessToken|refreshToken)$/i.test(name)) requireCaptured(value, fromResponse && !fromBody, 'credential-field');
      if (['cookie', 'Cookie', 'csrf'].includes(name) && typeof value === 'string') {
        if (name === 'csrf') requireCaptured(value); else cookieSecrets(value).forEach(v => requireCaptured(v));
      }
      if (name === 'responseCookies' && Array.isArray(value)) {
        if (value.every(v => typeof v === 'string')) cookieSecrets(cookieMerge('', value)).forEach(v => requireCaptured(v));
        else if (value.every(v => v && typeof v === 'object' && typeof v.name === 'string' && typeof v.value === 'string')) {
          for (const cookie of value) if (/^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(cookie.name)) requireCaptured(cookie.value);
        } else throw new Error('M7_CAPTURED_COOKIE_HEADER_INVALID');
      }
      if (name === 'key' && typeof value === 'string') {
        const candidates = reference.requests.filter(packet => packet.key === value && ['POST', 'PATCH', 'PUT', 'DELETE'].includes(packet.method) && typeof packet.path === 'string' && packet.path.startsWith('/api/v1/'));
        // A proven rolled-back SQL request may deliberately retain its key on
        // one subsequent attempt. The original attempt index remains distinct.
        const original = ['requests', 'originalHttpRequests'].includes(owner) ? candidates.find(packet => packet.index === node.index) : candidates[0];
        const packetMetadata = !fromBody && owner === 'requests' && original && ['index', 'method', 'path', 'query', 'bodySha256', 'actorId', 'sessionId', 'clusterId', 'workspaceId'].every(field => node[field] === original[field]);
        // The UI's immutable checkpoint retains complete original HTTP packets.
        // A public operation key in that exact copy has the same provenance as
        // the current packet. Body/response data cannot claim this provenance,
        // and changed headers, body or authority invalidate the full copy.
        const retainedPacketMetadata = !fromBody && !fromResponse && owner === 'originalHttpRequests' && original
          && ['index', 'method', 'path', 'query', 'bodySha256', 'actorId', 'sessionId', 'clusterId', 'workspaceId'].every(field => node[field] === original[field])
          && JSON.stringify(node) === JSON.stringify(original);
        const operationMetadata = !fromBody && owner === 'eventOperations' && original && node.cid === original.clusterId && node.wid === original.workspaceId && node.handler === original.responseData?.handler;
        const manualMetadata = !fromBody && owner === 'attempts' && original?.source === 'manual-ui' && node.path === original.path && node.bodySha256 === original.bodySha256 && node.actorId === original.actorId && node.sessionId === original.sessionId && node.requestId === original.requestId;
        // The sole route-aborted attempt has no parsed path/status. Rebuild only
        // the browser runner's exact global-packet projection, then require the
        // existing literal original-body/header/hash/authority proof unchanged.
        const retainedBlockedManualMetadata = !fromBody && !fromResponse && owner === 'attempts' && value === M7_BLOCKED_UI_EXPORT.key
          && isKnownM7BlockedUiExport(reference, { ...node, source: 'manual-ui', index: M7_BLOCKED_UI_EXPORT.index, manualIndex: node.index, expected: [200, 201] });
        const retainedBlockedPacketMetadata = !fromBody && !fromResponse && ['requests', 'originalHttpRequests'].includes(owner) && value === M7_BLOCKED_UI_EXPORT.key
          && isKnownM7BlockedUiExport(reference, node);
        if (!packetMetadata && !retainedPacketMetadata && !operationMetadata && !manualMetadata && !retainedBlockedManualMetadata && !retainedBlockedPacketMetadata) requireCaptured(value, fromResponse && !fromBody, fromBody ? 'body-key' : 'non-packet-key');
      }
      if (value && typeof value === 'object') {
        const nextBody = fromBody || name === 'body' && ['requests', 'originalHttpRequests', 'attempts'].includes(owner);
        const packetResponse = !nextBody && ['requests', 'originalHttpRequests', 'attempts'].includes(owner) && ['responseData', 'receiptData'].includes(name) && ['response_observed', 'succeeded'].includes(node.state) && node.status >= 200 && node.status < 300;
        const storedResponse = !nextBody && node.version === 1 && node.milestone === 'M7' && node.testTag === reference.testTag && ['producerAcceptance', 'auditAcceptance'].includes(name);
        pending.push([value, depth + 1, name, !nextBody && (fromResponse || packetResponse || storedResponse), nextBody]);
      }
    }
  }
  if (!captured.size) throw new Error('M7_SECRET_REGISTRY_EMPTY');
  return [...captured];
}
export function assertFinalM7Evidence(reference, evidence) {
  if (reference?.phase !== 'cleanup-complete' || reference.inFlight != null || reference.requests.some(value => !m7KnownWritePacket(reference, value)) || reference.providerControls.some(value => value.state !== 'observed') || reference.samplingIntents.some(value => value.state !== 'completed' && !isKnownM7StoppedSamplingIntent(reference, value))) throw new Error('M7_FINAL_UNKNOWN_OR_INCOMPLETE');
  if (reference.requests.some(value => isKnownM7BlockedUiExport(reference, value)) && (reference.manualUiBlockedExportProof?.state !== 'completed' || reference.manualUiBlockedExportProof.transportAttempted !== false || !/^[a-f\d-]{36}$/.test(reference.manualUiBlockedExportProof.receiptAbsenceReadRequestId ?? ''))) throw new Error('M7_FINAL_BLOCKED_EXPORT_PROOF_INCOMPLETE');
  const { http, producers, manual, cleanup } = evidence;
  if (![http, producers, manual, cleanup].every(value => value?.allPassed === true && value.failed === 0 && value.testTag === reference.testTag)
    || cleanup.auditWriteCoverage?.allCovered !== true || cleanup.auditWriteCoverage.coveredWrites !== cleanup.auditWriteCoverage.successfulWrites
    || !reference.cleanup?.businessCompleted || !reference.producersComplete || reference.c2ModeChanged && reference.c2ModeRestored !== true) throw new Error('M7_FINAL_EVIDENCE_INCOMPLETE');
  return true;
}
