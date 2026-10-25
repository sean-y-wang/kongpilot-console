import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
// Native Node executes this passive harness; it cannot import the product's
// TypeScript. Read the one frozen literal registry rather than invent a second
// handler vocabulary. No request body or runtime/environment file is read.
const registrySource = readFileSync(new URL('../../../apps/console-api/src/modules/workflows/event-workflow.ts', import.meta.url), 'utf8');
const registryLiteral = /export const EVENT_WORKFLOW_HANDLERS = \{([\s\S]*?)\} as const;/.exec(registrySource)?.[1];
const registryKeys = [...(registryLiteral ?? '').matchAll(/^\s*'(event\.[a-z.]+)':\s*\{\s*subject:/gm)].map(match => match[1]);
if (registryKeys.length !== 9 || new Set(registryKeys).size !== 9) throw Error('M7_FIXED_WORKFLOW_HANDLER_SOURCE_INVALID');
const handlers = new Set(registryKeys);

// These are immutable provenance for the observed M7 correlation defect, not
// a general compatibility policy. A later/fresh request can never enter this
// list, even if it has the same handler, actor, workflow or missing metadata.
export const M7_LEGACY_WORKFLOW_SUBMISSION_CHECKPOINT = Object.freeze({
  version: 1, packetCount: 258,
  packetSha256: '51f81f3ec02fd640e528b996ca80888706d80613acd410e481baf96b9d037eb9',
  failedArtifactSha256: '22638c9d5e3bf267232b4c582690bda3ed4316abae52ed735cc98cc0b4d7531e',
  legacyReadonlyProofSha256: '6ac9fa7203ccd429c4e92fa05a844d44c65ba06ffef762a27f6520c25bd0253e'
});

const pendingSubmission = packet => packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300
  && !['GET', 'HEAD'].includes(packet.method) && packet.responseData?.domain === 'workflow' && packet.responseData.configurationCommitted === false;
const basePath = packet => `/clusters/${packet.clusterId}`;
const scoped = (packet, suffix, query = {}) => `${basePath(packet)}/${suffix}?${new URLSearchParams({ workspaceId: packet.workspaceId, ...query })}`;

function exactCheckpoint(h, checkpoint) {
  h.check(isDeepStrictEqual(checkpoint, M7_LEGACY_WORKFLOW_SUBMISSION_CHECKPOINT)
    && h.state.requests.length >= checkpoint.packetCount && digest(h.state.requests.slice(0, checkpoint.packetCount)) === checkpoint.packetSha256,
  'legacy submission proof is restricted to the exact archived 258-packet failure and readonly provenance');
  const packets = h.state.requests.slice(0, checkpoint.packetCount).filter(pendingSubmission);
  h.check(packets.length === 12 && new Set(packets.map(packet => packet.responseData.handler)).size === 9,
    'legacy submission exception contains exactly the original twelve packets and nine fixed handlers');
  for (const packet of packets) {
    const receipt = packet.responseData, uri = new URL('https://synthetic.invalid' + packet.path + (packet.query ?? ''));
    h.check(packet.index >= 0 && packet.index < checkpoint.packetCount && h.state.requests[packet.index] === packet
      && uuid.test(packet.key) && uuid.test(packet.requestId) && uuid.test(packet.actorId) && uuid.test(packet.sessionId) && uuid.test(packet.clusterId) && uuid.test(packet.workspaceId)
      && packet.bodySha256 === digest(packet.body ?? null) && uri.pathname.startsWith(`/api/v1/clusters/${packet.clusterId}/events/`)
      && uri.searchParams.get('workspaceId') === packet.workspaceId && receipt.clusterId === packet.clusterId && receipt.workspaceId === packet.workspaceId
      && receipt.idempotencyKey === packet.key && uuid.test(receipt.id) && receipt.workflowId === receipt.id && receipt.entity?.id === receipt.id
      && receipt.entity?.clusterId === packet.clusterId && receipt.entity?.workspaceId === packet.workspaceId && receipt.entity?.kind === 'event-metadata'
      && receipt.entity?.planHash === receipt.planHash && /^[a-f\d]{64}$/.test(receipt.planHash ?? '') && handlers.has(receipt.handler)
      && receipt.submissionCompleted === true && receipt.executionCompleted === false,
    'legacy submission packet preserves its original key body actor SID CID WID fixed namespace and sealed workflow identity');
  }
  h.check(new Set(packets.map(packet => packet.key)).size === 12 && new Set(packets.map(packet => packet.requestId)).size === 12
    && new Set(packets.map(packet => packet.responseData.workflowId)).size === 12,
  'legacy submission packets cannot duplicate original keys requests or workflows');
  return packets;
}

function assertTerminal(h, packet, view, publicView) {
  publicView(h, view);
  h.check(view.action === 'workflow.submit' && view.result === 'success' && view.actorType === 'user' && view.actorId === packet.actorId
    && view.clusterId === packet.clusterId && view.workspaceId === packet.workspaceId && view.entityType === 'workflows'
    && view.entityId === packet.responseData.workflowId && view.workflowId === packet.responseData.workflowId && view.scopeQuality === 'verified'
    && view.requestId === null && view.sourceIp === null && view.before === null
    && isDeepStrictEqual(view.after, { kind: 'event-metadata', planHash: packet.responseData.planHash, approvalRequired: true }),
  'legacy audit is the real immutable exact workflow submission with explicitly missing request ID and source IP', { auditId: view.id, workflowId: view.workflowId });
}

async function originalTerminal(h, actors, packet, publicView) {
  const views = [], reads = []; let cursor;
  for (let pageIndex = 0; pageIndex < 12; pageIndex++) {
    const read = await h.request(actors.admin, scoped(packet, 'audit', { workflowId: packet.responseData.workflowId, entityType: 'workflows', entityId: packet.responseData.workflowId, action: 'workflow.submit', result: 'success', size: '100', ...(cursor ? { cursor } : {}) }));
    const page = h.data(read);
    h.check(read.status === 200 && uuid.test(read.requestId) && Array.isArray(page?.items) && page.total === null && page.items.length <= 100,
      'legacy proof uses actual bounded workflow audit reads with server request IDs');
    reads.push(read.requestId);
    for (const view of page.items) { assertTerminal(h, packet, view, publicView); views.push(view); }
    if (!page.nextCursor) break;
    h.check(pageIndex < 11, 'legacy workflow audit reaches real EOF within the bounded page budget'); cursor = page.nextCursor;
  }
  h.check(views.length === 1, 'legacy workflow has exactly one actual successful immutable submission terminal');
  const view = views[0], read = await h.request(actors.admin, scoped(packet, `audit/${view.id}`)), detail = h.data(read);
  h.check(read.status === 200 && uuid.test(read.requestId), 'legacy submission detail is an actual authenticated BFF read');
  assertTerminal(h, packet, detail, publicView);
  h.check(isDeepStrictEqual(view, detail), 'legacy immutable submission detail exactly matches the independent workflow audit page');
  return { view: detail, auditReadRequestIds: [...reads, read.requestId] };
}

/** Sole Security caller supplies the sealed checkpoint once while original
 * actors are active. Later bootstrap closures reuse the prior actual by-key
 * evidence and re-read immutable audit views; disabled actors are not revived. */
export async function prepareLegacySubmissionAuditProof(h, actors, checkpoint, publicView) {
  const old = h.state.legacyWorkflowSubmissionAuditProof;
  if (checkpoint === undefined && old === undefined) return new Map();
  const fixed = checkpoint ?? old.checkpoint, packets = exactCheckpoint(h, fixed), records = new Map();
  if (old !== undefined) {
    h.check(old.version === 1 && old.state === 'complete' && old.testTag === h.state.testTag && isDeepStrictEqual(old.checkpoint, fixed) && old.records?.length === 12,
      'legacy closure requires complete earlier actual protected receipts before actor cleanup');
    for (const packet of packets) {
      const matching = old.records.filter(record => record.index === packet.index), record = matching[0], read = record?.receiptRead;
      h.check(matching.length === 1 && record.packetSha256 === digest(packet) && read?.method === 'GET'
        && read.path === scoped(packet, `events/operations/by-key/${packet.key}`) && read.actorId === packet.actorId && read.sessionId === packet.sessionId
        && read.status === 200 && uuid.test(read.requestId) && read.workflowId === packet.responseData.workflowId && read.planHash === packet.responseData.planHash
        && /^[a-f\d]{64}$/.test(read.contentSha256 ?? '') && uuid.test(record.auditId) && /^[a-f\d]{64}$/.test(record.auditContentSha256 ?? '')
        && record.auditReadRequestIds?.length >= 2 && record.auditReadRequestIds.every(value => uuid.test(value)),
      'legacy closure refuses missing or foreign original protected receipt and immutable terminal proof');
      records.set(packet, record);
    }
    h.check(new Set([...records.values()].map(record => record.auditId)).size === 12, 'legacy closure keeps twelve distinct immutable submission audit identities');
    return records;
  }
  h.check(!h.state.cleanupStarted, 'legacy original protected receipt proof must precede account cleanup');
  const proof = { version: 1, state: 'building', testTag: h.state.testTag, checkpoint: { ...fixed }, records: [] };
  h.state.legacyWorkflowSubmissionAuditProof = proof; h.save();
  for (const packet of packets) {
    const actor = [...Object.values(h.state.sessions ?? {}), ...Object.values(actors)].find(value => value?.user?.id === packet.actorId && value?.sid === packet.sessionId);
    h.check(actor && !actor.revoked, 'legacy protected receipt read uses the original active named actor and SID');
    const path = scoped(packet, `events/operations/by-key/${packet.key}`), read = await h.request(actor, path), receipt = h.data(read), original = packet.responseData;
    h.check(read.status === 200 && uuid.test(read.requestId) && receipt.domain === 'workflow' && receipt.id === original.id && receipt.workflowId === original.workflowId
      && receipt.clusterId === packet.clusterId && receipt.workspaceId === packet.workspaceId && receipt.idempotencyKey === packet.key && receipt.handler === original.handler
      && receipt.planHash === original.planHash && receipt.entity?.id === original.id && receipt.entity?.planHash === original.planHash
      && receipt.submissionCompleted === true && receipt.state === 'succeeded' && receipt.configurationCommitted === true && receipt.executionCompleted === true,
    'legacy actual original-key receipt proves the exact existing terminal workflow without replaying its submission');
    const terminal = await originalTerminal(h, actors, packet, publicView);
    const record = { index: packet.index, packetSha256: digest(packet), receiptRead: { method: 'GET', path, status: read.status, requestId: read.requestId,
      actorId: actor.user.id, sessionId: actor.sid, workflowId: receipt.workflowId, planHash: receipt.planHash, contentSha256: digest(receipt) },
    auditId: terminal.view.id, auditContentSha256: digest(terminal.view), auditReadRequestIds: terminal.auditReadRequestIds };
    proof.records.push(record); records.set(packet, record); h.save();
  }
  h.check(new Set(proof.records.map(record => record.auditId)).size === 12, 'legacy proof records twelve distinct actual submission terminals');
  proof.state = 'complete'; h.save(); return records;
}

export async function readLegacySubmissionAuditTerminal(h, actors, packet, record, publicView) {
  const read = await h.request(actors.admin, scoped(packet, `audit/${record.auditId}`)), view = h.data(read);
  h.check(read.status === 200 && uuid.test(read.requestId), 'legacy final coverage re-reads the same immutable submission using current bootstrap authority');
  assertTerminal(h, packet, view, publicView);
  h.check(digest(view) === record.auditContentSha256 && record.packetSha256 === digest(packet),
    'legacy final coverage preserves the full immutable original submission and sealed packet content');
  return view;
}
