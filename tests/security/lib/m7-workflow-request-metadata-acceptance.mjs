import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { entity, rows, scope, sha256 } from './m7-harness.mjs';
import { eventWrite } from './m7-event-acceptance.mjs';
import { auditPatchMatches } from './m7-audit-acceptance.mjs';

export function freshSubmissionAuditMatches(view, packet, workflow, area) {
  return Boolean(view && packet?.state === 'response_observed' && packet.status === 201 &&
    packet.responseData?.domain === 'workflow' && packet.responseData.submissionCompleted === true &&
    packet.responseData.configurationCommitted === false && packet.responseData.workflowId === workflow?.id &&
    packet.clusterId === area.cid && packet.workspaceId === area.wid &&
    view.action === 'workflow.submit' && view.result === 'success' && view.scopeQuality === 'verified' &&
    view.actorId === packet.actorId && view.actorType === 'user' && view.clusterId === area.cid &&
    view.workspaceId === area.wid && view.entityType === 'workflows' && view.entityId === workflow.id &&
    view.workflowId === workflow.id && view.requestId === packet.requestId &&
    typeof view.sourceIp === 'string' && view.sourceIp.length > 0 && view.before === null &&
    isDeepStrictEqual(view.after, { kind: 'event-metadata', planHash: workflow.planHash, approvalRequired: true }) && auditPatchMatches(view));
}

// Only one new metadata workflow demonstrates the repaired production entry.
// Every previous submission and immutable audit record remains unchanged.
export async function freshWorkflowRequestMetadataAcceptance(h, actors) {
  const area = actors.approval;
  h.check(!h.state.workflowRequestMetadataProof && h.state.c2ModeRestored === true,
    'fresh request metadata proof begins once after the original C2 mode restoration');
  const current = rows(h.data(await h.request(actors.admin, '/clusters'))).find(row => row.id === area.cid);
  const originalMode = h.state.originalClusterModes[area.cid]?.mode;
  h.check(current?.execution_mode === originalMode && originalMode === 'direct',
    'fresh approval proof preserves the canonical original direct mode and current revision');
  const proof = { version: 1, state: 'prepared', cid: area.cid, wid: area.wid, originalMode,
    startedAt: new Date().toISOString(), name: `${h.state.testTag}-request-audit-${randomUUID().slice(0, 8)}` };
  h.state.workflowRequestMetadataProof = proof; h.save();
  const changed = h.data(await h.request(actors.admin, `/clusters/${area.cid}`, 'PATCH',
    { revision: current.revision, execution_mode: 'approval' }));
  h.check(changed.execution_mode === 'approval', 'fresh proof changes only exact canonical C2 execution mode through BFF');
  h.state.c2ModeRestored = false; proof.modeChanged = true; h.save();
  const result = await eventWrite(h, actors.admin, actors.approver, area, 'channels', 'POST',
    { name: proof.name, type: 'email', endpoint: { recipients: ['acceptance@example.test'] }, auth: { type: 'none' } },
    'event.channel.save', true);
  const operation = h.state.eventOperations.at(-1), packet = h.state.requests.find(row => row.key === operation?.key);
  h.check(operation?.approval === true && operation.handler === 'event.channel.save' &&
    operation.cid === area.cid && operation.wid === area.wid && packet?.body?.name === proof.name &&
    sha256(JSON.stringify(packet.body)) === packet.bodySha256 && result.entity?.name === proof.name,
    'new nonce channel has one exact original approval packet and no test-delivery request');
  const detail = h.data(await h.request(actors.admin, scope(area.cid, area.wid, `workflows/${operation.workflowId}`)));
  const workflow = entity(detail);
  h.check(workflow.id === operation.workflowId && workflow.kind === 'event-metadata' && workflow.state === 'succeeded' &&
    workflow.clusterId === area.cid && workflow.workspaceId === area.wid &&
    detail.steps.length === 1 && detail.steps[0].kind === 'metadata',
    'new proof workflow completes its single fixed metadata step without native execution');
  const page = h.data(await h.request(actors.admin, scope(area.cid, area.wid, 'audit',
    { requestId: packet.requestId, workflowId: workflow.id, action: 'workflow.submit', result: 'success', size: 100 })));
  h.check(Array.isArray(page.items) && page.items.length === 1 && page.nextCursor === null &&
    freshSubmissionAuditMatches(page.items[0], packet, workflow, area),
    'repaired fresh submission preserves exact actual request ID source IP actor scope and full patch');
  const audit = h.data(await h.request(actors.admin, scope(area.cid, area.wid, `audit/${page.items[0].id}`)));
  h.check(isDeepStrictEqual(audit, page.items[0]), 'fresh submit immutable detail agrees with its exact request-filtered terminal');
  const now = rows(h.data(await h.request(actors.admin, '/clusters'))).find(row => row.id === area.cid);
  h.check(now?.execution_mode === 'approval', 'fresh proof restore uses actual current canonical C2 revision');
  const restored = h.data(await h.request(actors.admin, `/clusters/${area.cid}`, 'PATCH',
    { revision: now.revision, execution_mode: originalMode }));
  h.check(restored.execution_mode === originalMode, 'fresh proof restores original canonical execution mode through BFF');
  h.state.c2ModeRestored = true;
  Object.assign(proof, { state: 'completed', completedAt: new Date().toISOString(), channelId: result.entity.id,
    workflowId: workflow.id, requestId: packet.requestId, auditId: audit.id,
    auditViewSha256: sha256(JSON.stringify(audit)), requestIdPresent: true, sourceIpPresent: true,
    terminalFullPatchVerified: true, modeRestored: true, nativeTransportWrites: 0, providerTestRequests: 0 });
  h.save();
  const safe = { channelId: proof.channelId, workflowId: proof.workflowId, requestId: proof.requestId,
    auditId: proof.auditId, requestIdPresent: true, sourceIpPresent: true, terminalFullPatchVerified: true,
    originalModeRestored: true, nativeTransportWrites: 0, providerTestRequests: 0 };
  h.public ??= {}; h.public.freshWorkflowRequestMetadata = safe;
  return safe;
}
