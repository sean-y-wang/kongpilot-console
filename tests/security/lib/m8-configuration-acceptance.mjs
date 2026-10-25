import { randomUUID } from 'node:crypto';
import { entity, scope, sha256 } from './m8-harness.mjs';
import { m8WorkflowStructuralProof } from './m8-workflow-structural-proof.mjs';

const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const hex = value => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
export const configurationPath = (area, path, query) => scope(area.cid, area.wid, path, query);
export async function configurationRead(h, actor, area, path, query) {
  return h.data(await h.request(actor, configurationPath(area, path, query)), 'configuration protected current read');
}
export function assertConfigurationReceipt(h, receipt, { actor, area, key, jobId, kind }) {
  h.check(receipt?.domain === 'configuration' && receipt.durable === true && receipt.idempotencyKey === key
    && uuid(receipt.jobId) && receipt.id === receipt.jobId && (!jobId || receipt.jobId === jobId)
    && receipt.actorId === actor.user.id && receipt.originalScope?.clusterId === area.cid
    && receipt.originalScope?.workspaceId === area.wid && receipt.clusterId === area.cid && receipt.workspaceId === area.wid
    && (!kind || receipt.kind === kind), 'configuration receipt is bound to original actor, key, job and exact scope');
  return receipt;
}
/** Every initial write is sent once. Polling uses only its protected by-key GET. */
export async function configurationWrite(h, actor, area, path, body, { kind, method = 'POST', allowApproval = false, key = randomUUID() } = {}) {
  if (!uuid(key)) throw Error('M8_CONFIGURATION_KEY_UUID_REQUIRED');
  const operation = { key, area: { ...area }, path, method, bodySha256: sha256(JSON.stringify(body)), actorId: actor.user.id, sessionId: actor.sid, state: 'prepared' };
  h.state.configurationOperations.push(operation); h.save();
  const initial = h.data(await h.request(actor, configurationPath(area, path), method, body, { key, expected: [200, 201, 202] }));
  assertConfigurationReceipt(h, initial, { actor, area, key, kind });
  Object.assign(operation, { jobId: initial.jobId, workflowId: initial.workflowId, state: 'submitted' }); h.save();
  const terminal = await h.poll(async () => {
    const receipt = await configurationRead(h, actor, area, `configuration/jobs/by-key/${key}`);
    return assertConfigurationReceipt(h, receipt, { actor, area, key, jobId: initial.jobId, kind });
  }, value => ['succeeded', 'failed', 'uncertain', 'partial', 'cancelled'].includes(value.state) || allowApproval && value.state === 'waiting_approval', 'original configuration job reaches a known durable state', 60000);
  h.check(terminal.state === 'succeeded' || allowApproval && terminal.state === 'waiting_approval', 'configuration job succeeds or waits for its genuine approval', { jobId: terminal.jobId, state: terminal.state });
  if (terminal.state === 'waiting_approval') h.check(uuid(terminal.workflowId) && terminal.approvalRequired === true && terminal.executionCompleted === false, 'pending configuration result is submission only');
  Object.assign(operation, { state: terminal.state, receipt: terminal }); h.save(); return terminal;
}
export async function completeConfigurationWorkflow(h, actors, area, receipt, expectedKind, expectedHandler) {
  const { admin, approver } = actors, workflowId = receipt.workflowId;
  h.check(uuid(workflowId) && receipt.state === 'waiting_approval', 'only a genuine pending configuration workflow may execute');
  let detail = await configurationRead(h, admin, area, `workflows/${workflowId}`), summary = entity(detail);
  h.check(summary.id === workflowId && summary.clusterId === area.cid && summary.workspaceId === area.wid && summary.kind === expectedKind
    && detail.steps?.length === 1 && detail.steps[0].kind === 'metadata' && hex(summary.planHash), 'configuration public wrapper has its exact scope, sealed version and one metadata step');
  if(detail.steps[0].handler===undefined&&detail.steps[0].nativeRequests===undefined)
    await m8WorkflowStructuralProof(h,admin,area,summary,detail.steps[0],expectedHandler);
  else h.check(detail.steps[0].handler===expectedHandler&&Array.isArray(detail.steps[0].nativeRequests)&&detail.steps[0].nativeRequests.length===0,
    'an explicitly exposed workflow packet cannot contradict the fixed handler or zero V1 Native budget');
  const approveKey = randomUUID(), approved = entity(h.data(await h.request(approver, configurationPath(area, `workflows/${workflowId}/approve`), 'POST',
    { revision: summary.revision, planHash: summary.planHash, confirmed: true, confirm_name: expectedKind }, { key: approveKey })));
  h.check(approved.id === workflowId && approved.state === 'approved', 'a different current approver approves the original immutable wrapper');
  const decision = await configurationRead(h, approver, area, `workflows/receipts/by-key/${approveKey}`);
  h.check(decision.workflowId === workflowId && decision.clusterId === area.cid && decision.workspaceId === area.wid
    && decision.idempotencyKey === approveKey && decision.action === 'approve' && decision.decisionCompleted === true, 'original approval key has an exact current decision receipt');
  detail = await configurationRead(h, admin, area, `workflows/${workflowId}`); summary = entity(detail);
  const executionKey = randomUUID(), executed = h.data(await h.request(admin, configurationPath(area, `workflows/${workflowId}/execute`), 'POST',
    { revision: summary.revision, planHash: summary.planHash, confirmed: true, confirm_name: expectedKind }, { key: executionKey, expected: [200, 201, 202] }));
  h.check(executed.workflowId === workflowId && executed.clusterId === area.cid && executed.workspaceId === area.wid
    && executed.state === 'succeeded' && executed.steps?.length === 1 && executed.steps[0].remoteCompleted === true, 'original configuration workflow actually executes to successful terminal receipt');
  const execution = await configurationRead(h, admin, area, `workflows/receipts/by-key/${executionKey}`);
  h.check(execution.action === 'execute' && execution.idempotencyKey === executionKey && execution.workflowId === workflowId
    && execution.clusterId === area.cid && execution.workspaceId === area.wid && execution.state === 'succeeded', 'original execution key proves the exact successful workflow');
  const original = await configurationRead(h, admin, area, `configuration/jobs/by-key/${receipt.idempotencyKey}`);
  assertConfigurationReceipt(h, original, { actor: admin, area, key: receipt.idempotencyKey, jobId: receipt.jobId, kind: receipt.kind });
  h.check(original.workflowId === workflowId && original.state === 'succeeded' && original.executionCompleted === true, 'configuration native result is proved by original submitted job after workflow completion');
  h.state.workflowOperations ??= []; h.state.workflowOperations.push({ area, workflowId, approveKey, executionKey, jobId: receipt.jobId, kind: expectedKind, handler: expectedHandler, state: 'succeeded' }); h.save(); return original;
}
export async function boundedSnapshotObjects(h, actor, area, snapshotId, size = 2) {
  let cursor, pages = 0; const seenCursors = new Set(), seenKeys = new Set(), objects = []; let summary;
  do {
    h.check(pages++ < 100, 'snapshot display pagination stays within its explicit page budget');
    const page = await configurationRead(h, actor, area, `snapshots/${snapshotId}`, { size, ...(cursor ? { cursor } : {}) }); summary = entity(page);
    h.check(summary.id === snapshotId && summary.clusterId === area.cid && summary.workspaceId === area.wid && Array.isArray(page.items) && page.items.length <= size, 'snapshot page is current, exact scope and server bounded');
    for (const object of page.items) { h.check(typeof object.objectKey === 'string' && !seenKeys.has(object.objectKey), 'snapshot cursor yields each typed object once'); seenKeys.add(object.objectKey); objects.push(object); }
    cursor = page.nextCursor;
    h.check(cursor === null || typeof cursor === 'string' && cursor.length > 0 && !seenCursors.has(cursor), 'snapshot cursor chain terminates or advances without replay');
    if (cursor) seenCursors.add(cursor);
  } while (cursor);
  h.check(pages > 1 && objects.length > size, 'actual snapshot display observes multiple pages and terminal EOF'); return { summary, objects, pages, terminalObserved: true };
}
export async function downloadConfiguration(h, actor, area, receipt, confirmationName) {
  h.check(receipt.state === 'succeeded' && receipt.capabilities?.download === true && uuid(receipt.exportId) && Number.isInteger(receipt.exportRevision), 'download uses current exact export revision and unused permit');
  const body = { revision: receipt.exportRevision, ...(receipt.mode === 'deployment' ? { confirmed: true, confirm_name: confirmationName } : {}) }, key = randomUUID();
  const result = await h.request(actor, configurationPath(area, `configuration/exports/${receipt.exportId}/download`), 'POST', body, { key, expected: [200,201], raw: true });
  const headers = result.response.headers;
  h.check(headers.get('cache-control') === 'no-store' && headers.get('x-content-type-options') === 'nosniff'
    && /^application\/yaml\b/.test(headers.get('content-type') ?? '') && /^attachment; filename="configuration-[a-f\d-]{36}\.yaml"$/.test(headers.get('content-disposition') ?? ''), 'actual YAML stream has one nosniff, no-store and fixed attachment identity');
  h.check(result.bytes.length > 0 && result.bytes.length <= 8 * 1024 * 1024 && /_format_version:\s*["']?1\.1["']?/.test(result.bytes.toString('utf8')), 'actual YAML is bounded decK1.1 content');
  const download = await configurationRead(h, actor, area, `configuration/jobs/by-key/${key}`);
  assertConfigurationReceipt(h, download, { actor, area, key, kind: 'export' });
  h.check(download.state === 'succeeded' && download.exportId === receipt.exportId && download.downloadPermitConsumed === true && download.byteCount === result.bytes.length, 'actual bytes match the durably consumed one-time download permit');
  h.state.downloads ??= []; h.state.downloads.push({ key, jobId: download.jobId, exportId: receipt.exportId, mode: receipt.mode, bytes: result.bytes.length, sha256: sha256(result.bytes) }); h.save();
  return result.bytes.toString('utf8'); // caller retains raw material privately; never report it
}
