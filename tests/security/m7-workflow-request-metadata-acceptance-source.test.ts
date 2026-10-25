// @ts-nocheck -- pure original-packet versus immutable safe-audit validation.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { freshSubmissionAuditMatches } from './lib/m7-workflow-request-metadata-acceptance.mjs';

function fixture() {
  const area = { cid: randomUUID(), wid: randomUUID() }, workflow = { id: randomUUID(), planHash: 'actual-sealed-plan-hash' };
  const packet = { state: 'response_observed', status: 201, actorId: randomUUID(), requestId: randomUUID(), clusterId: area.cid, workspaceId: area.wid,
    responseData: { domain: 'workflow', submissionCompleted: true, configurationCommitted: false, workflowId: workflow.id } };
  const after = { kind: 'event-metadata', planHash: workflow.planHash, approvalRequired: true };
  const view = { action: 'workflow.submit', result: 'success', scopeQuality: 'verified', actorId: packet.actorId, actorType: 'user', clusterId: area.cid, workspaceId: area.wid,
    entityType: 'workflows', entityId: workflow.id, workflowId: workflow.id, requestId: packet.requestId, sourceIp: '127.0.0.1', before: null, after,
    jsonPatch: [{ op: 'replace', path: '', value: after }] };
  return { area, workflow, packet, view };
}
describe('fresh workflow submission actual request metadata proof', () => {
  it('accepts exact original pending submission with actual source IP and full immutable patch', () => {
    const f = fixture(); expect(freshSubmissionAuditMatches(f.view, f.packet, f.workflow, f.area)).toBe(true);
  });
  it.each(['requestId', 'sourceIp'])('rejects old NULL %s instead of claiming a repaired historical record', field => {
    const f = fixture(); f.view[field] = null; expect(freshSubmissionAuditMatches(f.view, f.packet, f.workflow, f.area)).toBe(false);
  });
  it('rejects foreign actor, scope, workflow and immutable sealed-plan association', () => {
    for (const field of ['actorId', 'clusterId', 'workspaceId', 'entityId', 'workflowId', 'requestId']) {
      const f = fixture(); f.view[field] = randomUUID(); expect(freshSubmissionAuditMatches(f.view, f.packet, f.workflow, f.area)).toBe(false);
    }
    const f = fixture(); f.view.after.planHash = 'another-plan'; expect(freshSubmissionAuditMatches(f.view, f.packet, f.workflow, f.area)).toBe(false);
  });
  it('rejects sparse patch and terminal receipt used to substitute the original submission packet', () => {
    const f = fixture(); f.view.jsonPatch = []; expect(freshSubmissionAuditMatches(f.view, f.packet, f.workflow, f.area)).toBe(false);
    const g = fixture(); g.packet.responseData.configurationCommitted = true; expect(freshSubmissionAuditMatches(g.view, g.packet, g.workflow, g.area)).toBe(false);
    const sparse = fixture(); delete sparse.view.after.approvalRequired; expect(freshSubmissionAuditMatches(sparse.view, sparse.packet, sparse.workflow, sparse.area)).toBe(false);
  });
});
