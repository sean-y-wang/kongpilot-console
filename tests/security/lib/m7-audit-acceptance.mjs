import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import jsonPatch from 'fast-json-patch';
import { entity, scope, sha256 } from './m7-harness.mjs';
import { prepareLegacySubmissionAuditProof, readLegacySubmissionAuditTerminal } from './m7-legacy-submission-audit.mjs';
import { isKnownM7BlockedUiExport } from './m7-ui-blocked-export.mjs';
import { account, nativeCreate, role, wsGrant } from './m7-fixtures.mjs';
import { M7_UI_ACTIONS, confirmM7UiReceipt, m7UiReceiptPath, uiSha } from './m7-manual-journal.mjs';

// Passive source helper: only the sole M7 runner supplies an already-created
// harness and named sessions. There is no constructor, fetch, SQL or process
// execution here. Every write retains the harness's original durable packet.
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const csvHeader = ['id', 'occurredAt', 'actorId', 'actorType', 'sourceIp', 'clusterId', 'workspaceId', 'entityType', 'entityId', 'action', 'result', 'requestId', 'workflowId', 'before', 'after', 'jsonPatch'];
const chainFields = ['sequence', 'event_hash', 'eventHash', 'prev_hash', 'prevHash', 'chain_scope', 'chainScope', 'history_scope', 'sourceScope', 'sourceScopeHmac', 'history_scope_hmac'];
const dangerousCell = value => /^[\s\u0000-\u001f]*[=+@-]/.test(value) || /^[\t\r\n]/.test(value);
const terminalStates = new Set(['succeeded', 'incomplete', 'failed', 'cancelled', 'expired']);

/** Independent RFC 4180 reader, including escaped quotes and embedded CRLF. */
export function parseAuditCsv(bytes) {
  const text = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes);
  if (Buffer.byteLength(text) > 32 * 1024 * 1024) throw new Error('M7_CSV_READ_BUDGET');
  const result = []; let row = [], value = '', quoted = false, closed = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { value += '"'; i++; }
      else if (char === '"') { quoted = false; closed = true; }
      else value += char;
      continue;
    }
    if (closed && char !== ',' && char !== '\r' && char !== '\n') throw new Error('M7_CSV_TRAILING_QUOTE_CONTENT');
    if (char === '"') { if (value || closed) throw new Error('M7_CSV_QUOTE_POSITION'); quoted = true; }
    else if (char === ',') { row.push(value); value = ''; closed = false; }
    else if (char === '\r' || char === '\n') {
      if (char === '\r') { if (text[i + 1] !== '\n') throw new Error('M7_CSV_BARE_CR'); i++; }
      row.push(value); result.push(row); row = []; value = ''; closed = false;
    } else value += char;
  }
  if (quoted) throw new Error('M7_CSV_UNTERMINATED_QUOTE');
  if (row.length || value || closed) { row.push(value); result.push(row); }
  return result;
}

export function auditPatchMatches(view) {
  if (!view || !Array.isArray(view.jsonPatch)) return false;
  try {
    // Use the independent RFC 6902 library, never the product's diff routine.
    const patched = jsonPatch.applyPatch(structuredClone(view.before), structuredClone(view.jsonPatch), true, false, true).newDocument;
    return isDeepStrictEqual(patched, view.after);
  } catch { return false; }
}

function publicView(h, view) {
  h.check(view && uuid.test(view.id) && chainFields.every(key => !Object.hasOwn(view, key)), 'audit DTO exposes identity without chain fields or scope HMAC');
  h.check(auditPatchMatches(view), 'independent RFC6902 application exactly reproduces actual audited after state', { auditId: view.id });
  h.check(!h.state.secrets.filter(value => value.length >= 8).some(value => JSON.stringify(view).includes(value)), 'audit DTO contains no captured credential');
}

function logicalService(value) {
  const copy = structuredClone(value);
  if (Array.isArray(copy?.tags)) copy.tags = copy.tags.map(tag => {
    if (tag.startsWith('kos-ws-')) return `workspace:${tag.slice(7)}`;
    if (!tag.startsWith('kos-tag-')) return tag;
    const logical = Buffer.from(tag.slice(8), 'base64url').toString('utf8');
    return Buffer.from(logical).toString('base64url') === tag.slice(8) ? logical : tag;
  });
  return copy;
}

async function auditPage(h, actor, area, filters = {}, cursor) {
  const page = h.data(await h.request(actor, scope(area.cid, area.wid, 'audit', { ...filters, size: 100, cursor })));
  h.check(Array.isArray(page?.items) && page.total === null && page.size === 100 && (page.nextCursor === null || typeof page.nextCursor === 'string'), 'audit listing uses bounded opaque cursor without total or hidden chain bounds');
  for (const view of page.items) publicView(h, view);
  return page;
}

async function terminalAudit(h, actor, area, filters) {
  // Fresh precise filters should fit one page; explicitly consume the opaque
  // continuation instead of assuming an empty first page proves absence.
  const seen = []; let cursor;
  for (let pageIndex = 0; pageIndex < 12; pageIndex++) {
    const page = await auditPage(h, actor, area, filters, cursor); seen.push(...page.items);
    if (!page.nextCursor) return seen;
    cursor = page.nextCursor;
  }
  h.check(false, 'precise fresh audit query completes within bounded page budget');
  return seen;
}

async function nativeTerminal(h, actors, area, { requestId, id, action, before, after }) {
  h.check(uuid.test(requestId), 'native request retains actual server request ID');
  const candidates = await terminalAudit(h, actors.admin, area, { requestId, entityType: 'services', entityId: id, action, result: 'success' });
  h.check(candidates.length === 1, 'one original native request has exactly one successful business terminal audit', { entityId: id, count: candidates.length });
  const view = candidates[0];
  h.check(view.actorId === actors.admin.user.id && view.actorType === 'user' && view.clusterId === area.cid && view.workspaceId === area.wid && view.requestId === requestId && view.workflowId === null && view.scopeQuality === 'verified' && Boolean(view.sourceIp), 'native terminal preserves real actor source IP request and exact cluster workspace identity', { auditId: view.id });
  h.check(isDeepStrictEqual(logicalService(view.before), before) && isDeepStrictEqual(logicalService(view.after), after), 'native terminal contains full actual before and after readbacks including default Kong fields', { auditId: view.id });
  const detail = h.data(await h.request(actors.admin, scope(area.cid, area.wid, `audit/${view.id}`)));
  h.check(isDeepStrictEqual(detail, view), 'audit detail and filtered list return the same safe terminal');
  return view;
}

async function exportDownload(h, actor, area, format, filters) {
  const key = randomUUID();
  const receipt = h.data(await h.request(actor, scope(area.cid, area.wid, 'audit/exports'), 'POST', { workspaceId: area.wid, format, confirmed: true, ...filters }, { key }));
  h.check(receipt?.domain === 'audit-export' && receipt.durable === true && uuid.test(receipt.jobId), 'audit export create exposes only its own durable export receipt', { jobId: receipt.jobId, format });
  h.state.fixtures.push({ type: 'audit_export_jobs', id: receipt.jobId, actorLabel: actor.label, ...area }); h.save();
  return readExportDownload(h, actor, area, format, receipt.jobId, key);
}

async function readExportDownload(h, actor, area, format, jobId, key) {
  const byKey = h.data(await h.request(actor, scope(area.cid, area.wid, `audit/exports/by-key/${key}`)));
  h.check(byKey.domain === 'audit-export' && byKey.durable === true && byKey.jobId === jobId, 'audit export original key resolves the exact owner job without repeating POST');
  const job = await h.poll(async () => h.data(await h.request(actor, scope(area.cid, area.wid, `audit/exports/${jobId}`))), value => terminalStates.has(value.state), 'bounded fresh audit export reaches a durable terminal state', 45000);
  h.check(job.id === jobId && job.state === 'succeeded' && job.complete === true && job.format === format && job.rowCount > 0 && job.capabilities.download === true, 'small audit export is complete and currently authorized', { jobId: job.id, rowCount: job.rowCount });
  const download = await h.request(actor, scope(area.cid, area.wid, `audit/exports/${job.id}/download`), 'GET', undefined, { raw: true });
  const headers = download.response.headers;
  h.check(download.bytes.length === job.bytesCount && Number(headers.get('content-length')) === job.bytesCount && job.bytesCount <= 32 * 1024 * 1024 && headers.get('cache-control')?.includes('no-store') && headers.get('x-content-type-options') === 'nosniff' && headers.get('content-disposition')?.includes(`audit-${job.id}.${format}`), 'actual audit download has exact bounded bytes safe attachment and no-store headers', { jobId: job.id, bytes: job.bytesCount });
  h.check(!h.state.secrets.filter(value => value.length >= 8).some(value => download.bytes.includes(Buffer.from(value))), 'actual exported bytes contain no captured credential');
  return { job, key, bytes: download.bytes };
}

/** Actual full-chain verification, or caller-supplied trusted bounded interval. */
export async function auditIntegrityAcceptance(h, actor, cid, interval) {
  if (interval) h.check(/^[1-9]\d*$/.test(interval.fromSequence) && /^[1-9]\d*$/.test(interval.toSequence) && BigInt(interval.fromSequence) <= BigInt(interval.toSequence), 'trusted actual audit interval uses ordered positive decimal bounds');
  let cursor, checkedRows = 0, result;
  for (let page = 0; page < 12; page++) {
    const query = new URLSearchParams({ ...(interval ?? {}), ...(cursor ? { cursor } : {}) });
    result = h.data(await h.request(actor, `/clusters/${cid}/audit/integrity${query.size ? `?${query}` : ''}`));
    h.check(['verified', 'partial'].includes(result.status) && Number.isSafeInteger(result.checkedRows) && result.checkedRows >= 0 && result.checkedRows <= 1000 && result.scope === 'cluster', 'real integrity page validates canonical chain content and remains bounded', { checkedRows: result.checkedRows });
    checkedRows += result.checkedRows;
    if (!result.nextCursor) break;
    h.check(result.status === 'partial' && result.complete === false && result.intervalComplete === false && result.reasonCodes.length === 1 && result.reasonCodes[0] === 'AUDIT_BUDGET_REACHED', 'integrity continuation is explicitly partial instead of claiming complete verification');
    cursor = result.nextCursor;
  }
  h.check(result?.status === 'verified' && result.nextCursor === null && result.intervalComplete === true && result.reasonCodes.length === 0 && checkedRows > 0 && (interval || result.complete === true), 'actual chain verification reaches real interval EOF within12 bounded pages', { checkedRows, complete: result?.complete === true, intervalComplete: result?.intervalComplete === true });
  if (interval) h.check(isDeepStrictEqual(result.verifiedInterval, interval), 'verified interval exactly matches caller supplied actual bounds');
  return { checkedRows, complete: result.complete, intervalComplete: result.intervalComplete };
}

/** Call after the real C2 nine-handler approval flow has completed. */
export async function auditWorkflowAcceptance(h, actors) {
  const operations = (h.state.eventOperations ?? []).filter(value => value.approval && value.workflowId);
  h.check(operations.length > 0, 'workflow audit acceptance has actual completed original event workflow receipts');
  const ids = [];
  for (const operation of operations) {
    const area = { cid: operation.cid, wid: operation.wid };
    const packet = h.state.requests.find(value => value.method === 'POST' && value.path.endsWith(`/workflows/${operation.workflowId}/execute`) && value.clusterId === area.cid && value.workspaceId === area.wid && value.status >= 200 && value.status < 300);
    h.check(packet && uuid.test(packet.requestId), 'approved workflow terminal maps back to its original observed execute packet', { workflowId: operation.workflowId });
    const views = await terminalAudit(h, actors.admin, area, { workflowId: operation.workflowId, result: 'success' });
    const business = views.filter(view => view.action === operation.handler && view.requestId === packet.requestId);
    const completion = views.filter(view => view.action === 'workflow.execute' && view.entityId === operation.workflowId && view.requestId === packet.requestId);
    h.check(business.length === 1 && completion.length === 1 && business[0].actorId === packet.actorId && business[0].clusterId === area.cid && business[0].workspaceId === area.wid && business[0].scopeQuality === 'verified', 'approved workflow has one successful exact handler terminal and one correlated completion audit', { workflowId: operation.workflowId, count: business.length + completion.length });
    ids.push(business[0].id, completion[0].id);
  }
  h.public ??= {}; h.public.auditWorkflows = { workflows: operations.length, terminalAudits: ids.length, auditEventIds: ids };
  return ids;
}

// Sort object keys for a public-view content digest. This is not an internal
// audit event hash/sequence: those nineteen-field chain values stay private.
function safeContentHash(value) {
  const normalize = item => Array.isArray(item) ? item.map(normalize) : item && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, normalize(item[key])])) : item;
  return sha256(JSON.stringify(normalize(value)));
}
const manualTuple = value => ({ manualIndex: value.manualIndex ?? value.index, idempotencyKey: value.key, requestId: value.requestId, bodySha256: value.bodySha256,
  actorId: value.actorId, sessionId: value.sessionId, clusterId: value.clusterId, workspaceId: value.workspaceId, method: value.method, path: value.path,
  query: value.query, action: value.action, role: value.role, namespace: value.namespace, handler: value.handler ?? null, status: value.status, receiptRequestId: value.receiptRequestId });

function strictManualPackets(h) {
  const allPackets = h.state.requests.filter(value => value.source === 'manual-ui'), blocked = allPackets.filter(value => isKnownM7BlockedUiExport(h.state, value));
  h.check(blocked.length <= 1, 'manual UI coverage permits only the one exact retained before-transport blocked export');
  const packets = allPackets.filter(value => !blocked.includes(value)), journal = h.state.manualUiJournal;
  if (!packets.length && !journal) return [];
  h.check(journal?.version === 1 && journal.milestone === 'M7' && journal.source === 'manual-ui' && journal.testTag === h.state.testTag && journal.phase === 'complete' && journal.inFlight === null && journal.nextIndex === M7_UI_ACTIONS.length && journal.attempts?.length === M7_UI_ACTIONS.length && packets.length === M7_UI_ACTIONS.length, 'manual UI coverage requires the complete original confirmed journal');
  const seenKeys = new Set(), seenRequestIds = new Set(), result = [];
  for (let index = 0; index < M7_UI_ACTIONS.length; index++) {
    const attempt = journal.attempts[index], matching = packets.filter(value => value.manualIndex === index), packet = matching[0];
    h.check(matching.length === 1 && attempt.index === index && attempt.action === M7_UI_ACTIONS[index] && attempt.state === 'succeeded' && packet.state === 'succeeded', 'manual UI coverage refuses missing duplicate or unresolved original attempts');
    const copied = structuredClone(packet); delete copied.source; delete copied.manualIndex; delete copied.expected; copied.index = index;
    h.check(packet.index === h.state.requests.indexOf(packet) && isDeepStrictEqual(packet.expected, [200, 201]) && isDeepStrictEqual(copied, attempt), 'manual UI write packet matches its exact original journal including acknowledgement and receipt');
    const session = journal.sessions?.[attempt.role], authenticated = journal.authenticated?.[attempt.role], original = h.state.sessions?.[attempt.role];
    h.check(['admin', 'owner'].includes(attempt.role) && uuid.test(attempt.actorId) && uuid.test(attempt.sessionId) && attempt.actorId === attempt.originalExpectedActorId && attempt.actorId === session?.user?.id && attempt.sessionId === session?.sid && authenticated?.id === attempt.actorId && authenticated?.sid === attempt.sessionId && original?.user?.id === attempt.actorId && original?.sid === attempt.sessionId, 'manual UI coverage binds original named actor and SID without restoring disabled users');
    let url, body; try { url = new URL(attempt.url); body = JSON.parse(attempt.rawBody); } catch { h.check(false, 'manual UI original URL and serialized body are valid'); }
    const cid = journal.scope?.cid, wid = journal.scope?.wid;
    h.check(uuid.test(cid) && uuid.test(wid) && attempt.clusterId === cid && attempt.workspaceId === wid && url.origin === 'http://127.0.0.1:8080' && !url.username && !url.password && !url.hash && url.pathname === attempt.path && url.search === attempt.query && url.searchParams.getAll('workspaceId').length === 1 && url.searchParams.get('workspaceId') === wid && (url.pathname.startsWith(`/api/v1/clusters/${cid}/`) ? url.searchParams.size === 1 : url.pathname.startsWith('/api/v1/notifications/') && url.searchParams.size === 2 && url.searchParams.get('clusterId') === cid), 'manual UI coverage has the exact original packet CID WID path and query');
    h.check(['POST', 'PATCH', 'DELETE'].includes(attempt.method) && uuid.test(attempt.key) && uuid.test(attempt.requestId) && uuid.test(attempt.receiptRequestId) && Number.isInteger(attempt.status) && attempt.status >= 200 && attempt.status < 300 && typeof attempt.rawBody === 'string' && uiSha(attempt.rawBody) === attempt.bodySha256 && isDeepStrictEqual(body, attempt.body) && attempt.headers?.['x-idempotency-key'] === attempt.key && !attempt.headers?.authorization && isDeepStrictEqual(attempt.responseData, packet.responseData) && attempt.receiptData != null && !seenKeys.has(attempt.key) && !seenRequestIds.has(attempt.requestId) && !journal.priorKeys.includes(attempt.key) && h.state.requests.filter(value => value.key === attempt.key).length === 1 && h.state.requests.filter(value => value.requestId === attempt.requestId).length === 1, 'manual UI coverage requires original unique key body hash successful ACK and confirmed receipt');
    seenKeys.add(attempt.key); seenRequestIds.add(attempt.requestId); result.push({ packet, attempt });
  }
  return result;
}

function manualReceiptReplay(journal) {
  const copy = structuredClone(journal);
  copy.phase = 'ready'; copy.nextIndex = 0; copy.inFlight = null;
  copy.bindings = { delivery: copy.bindings.delivery, notifications: copy.bindings.notifications };
  copy.attempts.forEach(attempt => { attempt.state = 'response-observed'; });
  return copy;
}
function validateManualReceipt(h, replay, attempt, data, requestId) {
  replay.inFlight = attempt.index;
  try { confirmM7UiReceipt(replay, attempt.role, { method: 'GET', url: 'http://127.0.0.1:8080' + m7UiReceiptPath(replay, attempt) }, data, requestId, () => {}); }
  catch { h.check(false, 'manual UI original protected receipt validates exact namespace handler subject completion and sealed result'); }
}

/** Before any fixture/account cleanup, corroborate the browser journal through
 * original actors' real protected by-key BFF reads and immutable audit rows.
 * No actor is reactivated or invented. Later cleanup closure uses bootstrap
 * reads of those same immutable audit views, not disabled owner sessions. */
export async function auditManualUiReceiptsAcceptance(h, actors) {
  h.check(h.state.inFlight == null && !h.state.requests.some(value => ['prepared', 'response_unknown'].includes(value.state)), 'manual UI proof refuses unresolved original request packets');
  const packets = strictManualPackets(h);
  if (!packets.length) return { confirmedWrites: 0, auditEventIds: [] };
  h.check(!h.state.cleanupStarted && !h.state.manualUiAuditProof, 'manual UI actual protected receipt proof is established once before cleanup');
  const journal = h.state.manualUiJournal, retained = manualReceiptReplay(journal), current = manualReceiptReplay(journal);
  // Validate all retained confirmations before scheduling any read. The
  // independently served current receipts below are the actual corroboration.
  for (const { attempt } of packets) validateManualReceipt(h, retained, attempt, attempt.receiptData, attempt.receiptRequestId);
  const proof = { version: 1, state: 'building', testTag: h.state.testTag, journalSha256: safeContentHash(journal), records: [] };
  h.state.manualUiAuditProof = proof; h.save();
  for (const { packet, attempt } of packets) {
    const actor = actors[attempt.role] ?? h.state.sessions[attempt.role];
    h.check(actor?.user?.id === attempt.actorId && actor?.sid === attempt.sessionId, 'manual UI protected receipt read uses the original active named actor SID');
    const path = m7UiReceiptPath(journal, attempt).replace(/^\/api\/v1/, ''), read = await h.request(actor, path);
    h.check(read.status >= 200 && read.status < 300 && uuid.test(read.requestId), 'manual UI by-key proof is an actual successful BFF read with server request ID');
    const data = h.data(read); validateManualReceipt(h, current, attempt, data, read.requestId);
    h.check(attempt.namespace === 'audit-export' ? data.jobId === attempt.receiptData.jobId && data.job.id === attempt.receiptData.job.id && data.job.format === attempt.receiptData.job.format : data.id === attempt.receiptData.id && isDeepStrictEqual(data.result, attempt.receiptData.result), 'manual UI current receipt preserves original durable ledger identity and immutable sealed result');
    const query = { requestId: packet.requestId, result: 'success', size: 100 }, views = [], readRequestIds = []; let cursor;
    for (let pageIndex = 0; pageIndex < 12; pageIndex++) {
      const auditRead = await h.request(actors.admin, scope(packet.clusterId, packet.workspaceId, 'audit', { ...query, cursor })), page = h.data(auditRead);
      h.check(uuid.test(auditRead.requestId) && Array.isArray(page?.items) && page.total === null && page.items.length <= 100, 'manual UI proof reads bounded actual immutable exact request audit rows');
      readRequestIds.push(auditRead.requestId);
      for (const view of page.items) {
        publicView(h, view);
        h.check(view.requestId === packet.requestId && view.actorId === packet.actorId && view.clusterId === packet.clusterId && view.workspaceId === packet.workspaceId && ['success', 'succeeded'].includes(view.result), 'manual UI receipt corroboration uses actual terminal actor CID WID and request ID');
        views.push({ auditId: view.id, contentSha256: safeContentHash(view), action: view.action, entityType: view.entityType, entityId: view.entityId });
      }
      if (!page.nextCursor) break;
      h.check(pageIndex < 11, 'manual UI immutable terminal proof reaches actual bounded EOF'); cursor = page.nextCursor;
    }
    h.check(views.length > 0 && new Set(views.map(view => view.auditId)).size === views.length, 'manual UI independently protected receipt has nonduplicate actual terminal audit evidence');
    proof.records.push({ ...manualTuple(packet), confirmed: true, receiptRead: { method: 'GET', path, status: read.status, requestId: read.requestId, actorId: actor.user.id, sessionId: actor.sid,
      ledgerId: data.id ?? data.jobId, contentSha256: safeContentHash(data) }, auditReadRequestIds: readRequestIds, views });
    h.save();
  }
  proof.state = 'complete'; h.save();
  const result = { confirmedWrites: proof.records.length, auditEventIds: [...new Set(proof.records.flatMap(record => record.views.map(view => view.auditId)))] };
  h.public ??= {}; h.public.manualUiAuditProof = result;
  return result;
}

/** Read-only closure after cleanup/UI: validate every original observed write.
 * Scope candidates come only from this runner's durable journal. IAM uses
 * snake-case body scopes and permission routes inherit a role's stored scope,
 * so packet.clusterId alone does not describe all real audit chain scopes. */
export async function auditAllWritesCoverage(h, actors, legacyWorkflowSubmissions) {
  h.check(h.state.inFlight == null && !h.state.requests.some(value => ['prepared', 'response_unknown'].includes(value.state)), 'audit write coverage refuses unresolved original request packets');
  const manualPackets = strictManualPackets(h), manualProofs = new Map();
  if (manualPackets.length) {
    const proof = h.state.manualUiAuditProof;
    h.check(proof?.version === 1 && proof.state === 'complete' && proof.testTag === h.state.testTag && proof.journalSha256 === safeContentHash(h.state.manualUiJournal) && proof.records?.length === manualPackets.length, 'manual UI coverage requires earlier actual protected receipt and immutable audit proof before cleanup');
    for (const { packet } of manualPackets) {
      const records = proof.records.filter(record => record.manualIndex === packet.manualIndex), record = records[0], read = record?.receiptRead;
      h.check(records.length === 1 && record.confirmed === true && isDeepStrictEqual(Object.fromEntries(Object.keys(manualTuple(packet)).map(key => [key, record[key]])), manualTuple(packet)) && read?.method === 'GET' && read.path === m7UiReceiptPath(h.state.manualUiJournal, packet).replace(/^\/api\/v1/, '') && read.actorId === packet.actorId && read.sessionId === packet.sessionId && uuid.test(read.requestId) && uuid.test(read.ledgerId) && read.status >= 200 && read.status < 300 && /^[a-f\d]{64}$/.test(read.contentSha256 ?? '') && record.auditReadRequestIds?.length > 0 && record.auditReadRequestIds.every(value => uuid.test(value)) && record.views?.length > 0 && record.views.every(view => uuid.test(view.auditId) && /^[a-f\d]{64}$/.test(view.contentSha256 ?? '')), 'manual UI coverage refuses incomplete foreign or unconfirmed prior actual receipt proof');
      manualProofs.set(packet, record);
    }
  }
  const blockedBeforeTransport = new Set(h.state.requests.filter(packet => isKnownM7BlockedUiExport(h.state, packet)));
  h.check(blockedBeforeTransport.size <= 1, 'audit closure permits only the exact retained unsent export history');
  h.check(h.state.requests.every(packet => ['GET', 'HEAD'].includes(packet.method) || blockedBeforeTransport.has(packet)
    || packet.state === 'response_observed' && Number.isInteger(packet.status) && packet.status >= 100 && packet.status <= 599 || manualProofs.has(packet)), 'audit coverage refuses arbitrary succeeded states without strict manual UI proof');
  const knownClusters = [...new Set([actors.direct?.cid, actors.approval?.cid, actors.foreign?.cid, ...Object.values(h.state.scopes ?? {}).map(value => value.cid)].filter(value => uuid.test(value)))];
  const legacyProofs = await prepareLegacySubmissionAuditProof(h, actors, legacyWorkflowSubmissions, publicView);
  const auditIds = new Set(), legacyAuditIds = new Set(); let submissionOnly = 0, successfulWrites = 0, legacyMissingRequestMetadata = 0;
  // Reads may perform the normal same-SID refresh through h.request. Include
  // those newly journalled successful writes rather than freezing a stale
  // denominator and incorrectly reporting100% of an earlier snapshot.
  for (let index = 0; index < h.state.requests.length; index++) {
    h.check(index < 10000, 'successful-write audit closure remains bounded');
    const packet = h.state.requests[index];
    if (blockedBeforeTransport.has(packet)) continue;
    if (['GET', 'HEAD'].includes(packet.method) || packet.state !== 'response_observed' && !manualProofs.has(packet) || packet.status < 200 || packet.status >= 300) continue;
    successfulWrites++;
    h.check(uuid.test(packet.requestId), 'every observed successful write has its actual server request ID');
    const namedFixture = h.state.fixtures.find(value => ['roles', 'teams', 'preferences'].includes(value.type) && packet.path.includes(`/${value.id}`));
    const clusterCandidates = [...new Set([packet.clusterId, packet.body?.clusterId, packet.body?.cluster_id, namedFixture?.cid, ...knownClusters].filter(value => uuid.test(value)))];
    const candidates = packet.clusterId || packet.body?.clusterId || packet.body?.cluster_id || namedFixture?.cid ? [...clusterCandidates, null] : [null, ...clusterCandidates];
    const terminals = [], pendingSubmission = packet.responseData?.domain === 'workflow' && packet.responseData?.configurationCommitted === false;
    for (const clusterId of candidates) {
      let cursor;
      for (let pageIndex = 0; pageIndex < 12; pageIndex++) {
        const query = new URLSearchParams({...(clusterId ? {scope: 'cluster'} : {}), requestId: packet.requestId, size: '100', ...(cursor ? {cursor} : {})});
        const page = h.data(await h.request(actors.admin, `${clusterId ? `/clusters/${clusterId}/audit` : '/audit/global'}?${query}`));
        h.check(Array.isArray(page?.items) && page.total === null && page.items.length <= 100, 'successful-write coverage uses bounded exact request audit pages');
        for (const view of page.items) {
          publicView(h, view);
          h.check(view.requestId === packet.requestId && view.clusterId === clusterId, 'write coverage row belongs to the exact original request and actual chain scope', { auditId: view.id });
          if (['success', 'succeeded'].includes(view.result)) terminals.push(view);
        }
        if (!page.nextCursor) break;
        h.check(pageIndex < 11, 'successful-write coverage reaches exact request EOF within bounded pages'); cursor = page.nextCursor;
      }
      if (terminals.some(view => (packet.actorId == null || view.actorId === packet.actorId) && (!pendingSubmission || view.action === 'workflow.submit' && view.workflowId === packet.responseData.workflowId))) break;
    }
    const legacyProof = legacyProofs.get(packet);
    if (legacyProof) {
      h.check(pendingSubmission && terminals.length === 0, 'archived legacy submission remains explicitly uncorrelated by original request ID');
      const view = await readLegacySubmissionAuditTerminal(h, actors, packet, legacyProof, publicView);
      terminals.push(view); legacyAuditIds.add(view.id); legacyMissingRequestMetadata++;
    }
    // Anonymous login packets legitimately have no preexisting console actor.
    // All other successful writes must correlate to the original named actor.
    h.check(terminals.length > 0 && (packet.actorId === null || packet.actorId === undefined || terminals.some(view => view.actorId === packet.actorId)), 'every original successful write has at least one actual successful terminal audit', { requestId: packet.requestId, terminalCount: terminals.length });
    const manualProof = manualProofs.get(packet);
    if (manualProof) h.check(terminals.length === manualProof.views.length && manualProof.views.every(expected => terminals.some(view => view.id === expected.auditId && view.actorId === packet.actorId && view.clusterId === packet.clusterId && view.workspaceId === packet.workspaceId && view.action === expected.action && view.entityType === expected.entityType && view.entityId === expected.entityId && safeContentHash(view) === expected.contentSha256)), 'manual UI final bootstrap read verifies every same immutable terminal identity full transition patch and content digest');
    if (pendingSubmission) {
      const workflowId = packet.responseData.workflowId;
      h.check(terminals.some(view => view.action === 'workflow.submit' && view.workflowId === workflowId), 'workflow submission coverage proves persisted submission without claiming configuration execution', { workflowId });
      submissionOnly++;
    }
    terminals.forEach(view => auditIds.add(view.id));
  }
  const result = {successfulWrites, coveredWrites: successfulWrites, submissionOnlyWrites: submissionOnly, auditedWriteRequests: successfulWrites - submissionOnly, terminalAuditRows: auditIds.size, auditEventIds: [...auditIds],
    blockedBeforeTransportAttempts: blockedBeforeTransport.size, legacyMissingRequestMetadata, ledgerMatchedLegacyWrites: legacyMissingRequestMetadata, requestMatchedWrites: successfulWrites - legacyMissingRequestMetadata, legacyAuditEventIds: [...legacyAuditIds], allRequestIdsMatched: legacyMissingRequestMetadata === 0, allCovered: true};
  h.public ??= {}; h.public.auditWriteCoverage = result;
  return result;
}

/** Resume only the unused tail after an observed download representation
 * failure. The Security entry separately verifies/preserves the exact failed
 * artifact and packet prefix before supplying this harness. This helper never
 * recreates a Service, account, role, annotation or the first NDJSON export. */
export async function auditDownloadTailAcceptance(h, actors) {
  h.check(h.state.inFlight == null && !h.state.requests.some(packet => ['prepared', 'response_unknown'].includes(packet.state)) && !h.state.auditAcceptance && !h.state.auditDownloadTail,
    'audit download tail requires the original known checkpoint with no unresolved write or repeated tail');
  const area = actors.direct, { admin } = actors;
  const accounts = {}, sessions = {}, roles = {};
  for (const label of ['tag-union', 'tag-complete', 'entity-allowed', 'entity-wrong-type']) {
    const entries = h.state.accounts.filter(account => account.label === `audit-${label}` && account.cid === area.cid && account.wid === area.wid);
    h.check(entries.length === 1 && uuid.test(entries[0].userId) && uuid.test(entries[0].role?.id), 'download tail uses only each original disposable named audit account');
    const account = entries[0], session = h.state.sessions?.[account.label] ?? account.session;
    h.check(session?.user?.id === account.userId && session.label === account.label, 'download tail preserves the original captured audit actor without login or replacement');
    accounts[label] = account; sessions[label] = session; roles[label] = account.role;
  }
  const jobs = h.state.fixtures.filter(fixture => fixture.type === 'audit_export_jobs' && fixture.actorLabel === sessions['tag-complete'].label && fixture.cid === area.cid && fixture.wid === area.wid);
  h.check(jobs.length === 1, 'download checkpoint contains exactly the original owner NDJSON export fixture');
  const originalCreates = h.state.requests.filter(packet => packet.method === 'POST' && packet.path === `/api/v1/clusters/${area.cid}/audit/exports` && packet.responseData?.jobId === jobs[0].id);
  h.check(originalCreates.length === 1, 'original export identity resolves one original durable create packet');
  const original = originalCreates[0], filter = original.body;
  h.check(original.state === 'response_observed' && original.status >= 200 && original.status < 300 && original.actorId === sessions['tag-complete'].user.id && uuid.test(original.sessionId) && original.sessionId === sessions['tag-complete'].sid && original.clusterId === area.cid && original.workspaceId === area.wid && uuid.test(original.key) && uuid.test(original.requestId) && sha256(JSON.stringify(filter)) === original.bodySha256 && original.responseData.domain === 'audit-export' && original.responseData.durable === true && filter?.format === 'ndjson' && filter.confirmed === true && filter.workspaceId === area.wid && uuid.test(filter.requestId) && uuid.test(filter.entityId) && filter.entityType === 'services' && filter.action === 'update' && filter.result === 'success',
    'download tail binds original NDJSON key body hash actor SID CID WID and precise native audit filter');
  const serviceFixtures = h.state.fixtures.filter(fixture => fixture.type === 'services' && fixture.id === filter.entityId && fixture.cid === area.cid && fixture.wid === area.wid);
  h.check(serviceFixtures.length === 1, 'download tail Service belongs to this runner original scope and journal');
  const originalService = h.state.requests.filter(packet => packet.method === 'POST' && packet.path === `/api/v1/clusters/${area.cid}/entities/services` && entity(packet.responseData)?.id === filter.entityId && packet.actorId === admin.user.id && packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300);
  const originalUpdate = h.state.requests.filter(packet => packet.method === 'PATCH' && packet.path === `/api/v1/clusters/${area.cid}/entities/services/${filter.entityId}` && packet.requestId === filter.requestId && packet.actorId === admin.user.id && packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300);
  h.check(originalService.length === 1 && originalUpdate.length === 1, 'download tail retains one successful original native create and update without replay');
  const annotationWrites = h.state.requests.filter(packet => packet.method === 'PUT' && packet.path === `/api/v1/clusters/${area.cid}/entity-annotations/services/${filter.entityId}` && packet.actorId === admin.user.id && packet.workspaceId === area.wid && packet.state === 'response_observed' && packet.status >= 200 && packet.status < 300);
  h.check(annotationWrites.length === 1 && annotationWrites[0].body.description === '=SUM(1,2)\r\n"M7 nested CSV safety"' && annotationWrites[0].body.metadata?.acceptance === h.state.testTag,
    'download tail uses the already persisted original multiline CSV annotation');
  h.check(!h.state.requests.some(packet => packet.method === 'POST' && packet.path === `/api/v1/clusters/${area.cid}/audit/exports` && packet.body?.format === 'csv' && packet.body?.requestId === annotationWrites[0].requestId) && !h.state.requests.some(packet => packet.method === 'PUT' && packet.path === `/api/v1/iam/roles/${roles['tag-complete'].id}/permissions` && packet.body?.permissions?.length === 0),
    'download tail refuses previously issued CSV or revocation writes instead of silently replaying them');
  h.state.auditDownloadTail = { state: 'started', originalNdjsonJobId: jobs[0].id, originalCreateRequestId: original.requestId }; h.save();

  // First re-read this exact original protected ledger and strict download.
  // A representation/permission/expiry failure cannot schedule a new export.
  const ndjson = await readExportDownload(h, sessions['tag-complete'], area, 'ndjson', jobs[0].id, original.key);
  const service = entity(h.data(await h.request(admin, scope(area.cid, area.wid, `entities/services/${filter.entityId}`))));
  h.check(isDeepStrictEqual(service, entity(originalUpdate[0].responseData)), 'original native update still agrees with current Service readback');
  const updatedAudit = await nativeTerminal(h, actors, area, { requestId: filter.requestId, id: service.id, action: 'update', before: entity(originalService[0].responseData), after: service });
  const createdAudit = await terminalAudit(h, admin, area, { requestId: originalService[0].requestId, entityType: 'services', entityId: service.id, action: 'create', result: 'success' });
  h.check(createdAudit.length === 1 && createdAudit[0].actorId === admin.user.id, 'original native create terminal remains readable without executing another create');
  const annotation = h.data(await h.request(admin, scope(area.cid, area.wid, `entity-annotations/services/${service.id}`)));
  h.check(annotation.description === annotationWrites[0].body.description && annotation.revision === annotationWrites[0].responseData.revision, 'original annotation is unchanged before its first CSV export');
  const exported = ndjson.bytes.toString('utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
  h.check(exported.length === ndjson.job.rowCount && exported.length === 1 && isDeepStrictEqual(exported[0], updatedAudit), 'original NDJSON export bytes exactly match the actual immutable terminal after download checkpoint');
  await h.request(sessions['entity-allowed'], scope(area.cid, area.wid, `audit/exports/${ndjson.job.id}`), 'GET', undefined, { expected: [404] });
  await h.request(admin, scope(area.cid, area.wid, `audit/exports/${ndjson.job.id}/download`), 'GET', undefined, { expected: [404] });
  const csv = await exportDownload(h, admin, area, 'csv', { requestId: annotationWrites[0].requestId, entityType: 'services', entityId: service.id, result: 'success' });
  const parsed = parseAuditCsv(csv.bytes);
  h.check(isDeepStrictEqual(parsed[0], csvHeader) && parsed.length - 1 === csv.job.rowCount && parsed.slice(1).every(row => row.length === csvHeader.length && row.every(value => !dangerousCell(value))), 'checkpoint tail first RFC4180 CSV has complete rows and no executable formula cell prefix', { rows: csv.job.rowCount });
  h.check(parsed.slice(1).some(row => JSON.parse(row[csvHeader.indexOf('after')]).description === annotationWrites[0].body.description), 'checkpoint tail CSV preserves the original nested newline quote and formula fixture');
  const currentRole = h.data(await h.request(admin, `/iam/roles/${roles['tag-complete'].id}/permissions`));
  await h.request(admin, `/iam/roles/${roles['tag-complete'].id}/permissions`, 'PUT', { revision: currentRole.revision, permissions: [] });
  for (const suffix of [`audit/${updatedAudit.id}`, `audit/exports/${ndjson.job.id}`, `audit/exports/by-key/${ndjson.key}`, `audit/exports/${ndjson.job.id}/download`]) await h.request(sessions['tag-complete'], scope(area.cid, area.wid, suffix), 'GET', undefined, { expected: [403] });
  const integrity = await auditIntegrityAcceptance(h, admin, area.cid);
  const workflowAuditIds = (h.state.eventOperations ?? []).some(value => value.approval && value.workflowId) ? await auditWorkflowAcceptance(h, actors) : [];
  const auditEventIds = [createdAudit[0].id, updatedAudit.id, ...workflowAuditIds], exportJobIds = [ndjson.job.id, csv.job.id];
  h.public ??= {}; h.public.audit = { terminalAudits: auditEventIds.length, auditEventIds, exportJobIds, ndjsonRows: ndjson.job.rowCount, csvRows: csv.job.rowCount, directScalarFormulaFixture: false, csvNestedFormulaFixture: true, sameGrantRequired: true, typedEntityScope: true, currentRevocation: true, integrity, originalNdjsonExportRecreated: false, originalNativeWritesReplayed: false, originalAccountsRecreated: false };
  h.state.auditDownloadTail.state = 'completed'; h.save();
  return { service, auditEventIds, exportJobIds, actors: { tagUnion: sessions['tag-union'], tagComplete: sessions['tag-complete'], entityAllowed: sessions['entity-allowed'], entityWrongType: sessions['entity-wrong-type'] }, roleIds: Object.values(roles).map(role => role.id), annotationId: service.id };
}

export async function auditAcceptance(h, actors, serviceFixture) {
  const area = actors.direct, { admin } = actors;
  const beforeTag = `${h.state.testTag}-audit-before`, afterTag = `${h.state.testTag}-audit-after`;
  let service = serviceFixture?.service ?? (serviceFixture?.id ? serviceFixture : null), createdAudit;
  if (!service) {
    service = await nativeCreate(h, admin, area, 'services', { name: `${h.state.testTag}-audit`, protocol: 'http', host: 'echo-upstream', port: 8081, tags: [beforeTag] });
    const packet = h.state.requests.findLast(value => value.method === 'POST' && value.path.endsWith('/entities/services') && entity(value.responseData)?.id === service.id);
    const readback = entity(h.data(await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`))));
    createdAudit = await nativeTerminal(h, actors, area, { requestId: packet?.requestId, id: service.id, action: 'create', before: null, after: readback });
  } else {
    // Reusing a caller-owned fresh fixture is explicit and remains in the
    // same durable journal. Do not mutate another scope or an arbitrary ID.
    h.check(h.state.fixtures.some(value => value.type === 'services' && value.id === service.id && value.cid === area.cid && value.wid === area.wid), 'caller supplied native audit fixture belongs to this runner exact direct scope');
    await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`), 'PATCH', { tags: [beforeTag] });
  }
  const before = entity(h.data(await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`))));
  h.check(before.tags.includes(beforeTag) && !before.tags.includes(afterTag), 'real native preimage has only the before business tag');
  const changed = await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`), 'PATCH', { tags: [afterTag], retries: before.retries === 3 ? 4 : 3 });
  service = entity(h.data(changed));
  const after = entity(h.data(await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`))));
  h.check(isDeepStrictEqual(after, service) && after.tags.includes(afterTag) && !after.tags.includes(beforeTag), 'real native postimage is freshly read and has only the after business tag');
  const updatedAudit = await nativeTerminal(h, actors, area, { requestId: changed.requestId, id: service.id, action: 'update', before, after });

  // No broad audit/workspace read grant is mixed into these test principals.
  const specs = [
    ['tag-union', [wsGrant(area.cid, area.wid, 'audit', 'read', 'tag_group', [beforeTag]), wsGrant(area.cid, area.wid, 'audit', 'read', 'tag_group', [afterTag])]],
    ['tag-complete', [wsGrant(area.cid, area.wid, 'audit', 'read', 'tag_group', [beforeTag, afterTag])]],
    ['entity-allowed', [wsGrant(area.cid, area.wid, 'audit', 'read', 'entity', [{ entity_type: 'services', entity_id: service.id }])]],
    ['entity-wrong-type', [wsGrant(area.cid, area.wid, 'audit', 'read', 'entity', [{ entity_type: 'routes', entity_id: service.id }])]],
  ];
  const roles = {}, sessions = {};
  for (const [label, grants] of specs) { roles[label] = await role(h, admin, `audit-${label}`, grants, area.cid, area.wid); sessions[label] = await account(h, admin, `audit-${label}`, roles[label], area.cid, area.wid); }
  for (const label of ['tag-union', 'entity-wrong-type']) {
    await h.request(sessions[label], scope(area.cid, area.wid, `audit/${updatedAudit.id}`), 'GET', undefined, { expected: [403] });
    const list = await terminalAudit(h, sessions[label], area, { requestId: changed.requestId, entityType: 'services', entityId: service.id, action: 'update', result: 'success' });
    h.check(list.length === 0, 'server-side audit list denies cross-grant union and wrong typed identity', { actor: label });
  }
  for (const label of ['tag-complete', 'entity-allowed']) {
    const detail = h.data(await h.request(sessions[label], scope(area.cid, area.wid, `audit/${updatedAudit.id}`)));
    h.check(isDeepStrictEqual(detail, updatedAudit), 'one complete current historical grant authorizes both exact immutable sides', { actor: label, auditId: detail.id });
    // Entity/tag audit grants discover scope, without granting native reads.
    const workspaces = h.data(await h.request(sessions[label], `/clusters/${area.cid}/workspaces`));
    h.check((Array.isArray(workspaces) ? workspaces : workspaces.items ?? []).some(value => value.id === area.wid), 'restricted historical module grants discover the real workspace');
    await h.request(sessions[label], scope(area.cid, area.wid, `entities/services/${service.id}`), 'GET', undefined, { expected: [403] });
  }
  await h.request(actors.readonly, scope(area.cid, area.wid, `audit/${updatedAudit.id}`));
  await h.request(admin, scope(actors.foreign.cid, actors.foreign.wid, `audit/${updatedAudit.id}`), 'GET', undefined, { expected: [404] });
  await h.request(sessions['tag-complete'], `/clusters/${area.cid}/audit/integrity`, 'GET', undefined, { expected: [403] });
  for (const method of ['PATCH', 'DELETE']) await h.request(admin, scope(area.cid, area.wid, `audit/${updatedAudit.id}`), method, { confirmed: true }, { expected: [404] });

  const annotationPath = scope(area.cid, area.wid, `entity-annotations/services/${service.id}`);
  const annotationBefore = h.data(await h.request(admin, annotationPath));
  const marker = '=SUM(1,2)\r\n"M7 nested CSV safety"';
  const annotationWrite = await h.request(admin, annotationPath, 'PUT', { revision: annotationBefore.revision, description: marker, metadata: { acceptance: h.state.testTag } });
  const annotation = h.data(annotationWrite);
  h.state.fixtures.push({ type: 'entity_annotations', entityType: 'services', id: service.id, name: service.name, revision: annotation.revision, ...area }); h.save();
  h.check(annotation.description === marker, 'real console annotation retains nested CSV formula marker and escaped newline quote');

  const filter = { requestId: changed.requestId, entityType: 'services', entityId: service.id, action: 'update', result: 'success' };
  const ndjson = await exportDownload(h, sessions['tag-complete'], area, 'ndjson', filter);
  const exported = ndjson.bytes.toString('utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
  h.check(exported.length === ndjson.job.rowCount && exported.length === 1 && isDeepStrictEqual(exported[0], updatedAudit), 'NDJSON real export exactly matches the currently authorized complete terminal audit');
  await h.request(sessions['entity-allowed'], scope(area.cid, area.wid, `audit/exports/${ndjson.job.id}`), 'GET', undefined, { expected: [404] });
  await h.request(admin, scope(area.cid, area.wid, `audit/exports/${ndjson.job.id}/download`), 'GET', undefined, { expected: [404] });
  const csv = await exportDownload(h, admin, area, 'csv', { requestId: annotationWrite.requestId, entityType: 'services', entityId: service.id, result: 'success' });
  const parsed = parseAuditCsv(csv.bytes);
  h.check(isDeepStrictEqual(parsed[0], csvHeader) && parsed.length - 1 === csv.job.rowCount && parsed.slice(1).every(row => row.length === csvHeader.length && row.every(value => !dangerousCell(value))), 'actual RFC4180 CSV has exact complete rows and no executable formula cell prefix', { rows: csv.job.rowCount });
  h.check(parsed.slice(1).some(row => JSON.parse(row[csvHeader.indexOf('after')]).description === marker), 'actual CSV JSON cell preserves harmless nested formula fixture without truncating multiline content');

  // Independent disposable role only: no shared runner authority is revoked.
  const currentRole = h.data(await h.request(admin, `/iam/roles/${roles['tag-complete'].id}/permissions`));
  await h.request(admin, `/iam/roles/${roles['tag-complete'].id}/permissions`, 'PUT', { revision: currentRole.revision, permissions: [] });
  for (const suffix of [`audit/${updatedAudit.id}`, `audit/exports/${ndjson.job.id}`, `audit/exports/by-key/${ndjson.key}`, `audit/exports/${ndjson.job.id}/download`]) await h.request(sessions['tag-complete'], scope(area.cid, area.wid, suffix), 'GET', undefined, { expected: [403] });
  h.check(true, 'current audit grant revocation immediately denies history receipts and previously completed export download', { jobId: ndjson.job.id });
  const integrity = await auditIntegrityAcceptance(h, admin, area.cid, serviceFixture?.integrityInterval);
  const workflowAuditIds = (h.state.eventOperations ?? []).some(value => value.approval && value.workflowId) ? await auditWorkflowAcceptance(h, actors) : [];
  const auditEventIds = [createdAudit?.id, updatedAudit.id, ...workflowAuditIds].filter(Boolean), exportJobIds = [ndjson.job.id, csv.job.id];
  h.public ??= {}; h.public.audit = { terminalAudits: auditEventIds.length, auditEventIds, exportJobIds, ndjsonRows: ndjson.job.rowCount, csvRows: csv.job.rowCount, directScalarFormulaFixture: false, csvNestedFormulaFixture: true, sameGrantRequired: true, typedEntityScope: true, currentRevocation: true, integrity };
  h.save();
  return { service, auditEventIds, exportJobIds, actors: { tagUnion: sessions['tag-union'], tagComplete: sessions['tag-complete'], entityAllowed: sessions['entity-allowed'], entityWrongType: sessions['entity-wrong-type'] }, roleIds: Object.values(roles).map(value => value.id), annotationId: service.id };
}
