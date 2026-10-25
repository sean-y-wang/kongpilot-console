// @ts-nocheck -- actual acceptance/eventWrite helpers, synthetic RAM only.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { freshWorkflowRequestMetadataAcceptance } from './lib/m7-workflow-request-metadata-acceptance.mjs';
import { sha256 } from './lib/m7-harness.mjs';

function fixture(options = {}) {
  const area = { cid: randomUUID(), wid: randomUUID() }, calls = [], receipts = new Map(), decisions = new Map();
  const actors = { approval: area, admin: { user: { id: randomUUID() }, sid: randomUUID() }, approver: { user: { id: randomUUID() }, sid: randomUUID() } };
  const cluster = { id: area.cid, execution_mode: 'direct', revision: 10 };
  let workflow, channel, audit, submitKey, originalSubmission, executionId, writeCount = 0;
  const prefix = [{ index: 0, key: randomUUID(), method: 'POST', path: '/api/v1/synthetic-original', state: 'response_observed', status: 201, body: { original: true } }];
  const h = { state: { testTag: 'synthetic-m7-metadata', requests: structuredClone(prefix), fixtures: [], eventOperations: [], originalClusterModes: { [area.cid]: { mode: 'direct' } }, c2ModeRestored: true },
    check(value, name) { if (!value) throw Error(name); },
    data(result) { if (result.status >= 300) throw Error('SYNTHETIC_HTTP_FAILURE'); return result.payload.data; },
    save(extra = {}) { Object.assign(h.state, extra); },
  };
  h.request = async (actor, path, method = 'GET', body, config = {}) => {
    const uri = new URL(path, 'https://synthetic.invalid'), requestId = randomUUID(), key = config.key ?? randomUUID();
    const call = { actorId: actor.user.id, sessionId: actor.sid, path: uri.pathname, method, body: structuredClone(body), key };
    calls.push(call);
    let packet;
    if (method !== 'GET') {
      writeCount++; packet = { index: h.state.requests.length, ...call, path: '/api/v1' + uri.pathname, query: uri.search,
        clusterId: area.cid, workspaceId: uri.searchParams.get('workspaceId'), bodySha256: sha256(JSON.stringify(body)), state: 'prepared' };
      h.state.requests.push(packet);
      if (options.unknownAtWrite === writeCount) {
        packet.state = 'response_unknown'; h.state.phase = 'stopped-unknown';
        throw Error('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED');
      }
    }
    let data, status = method === 'GET' || method === 'PATCH' ? 200 : 201;
    if (uri.pathname === '/clusters') data = [structuredClone(cluster)];
    else if (uri.pathname === `/clusters/${area.cid}` && method === 'PATCH') {
      expect(body.revision).toBe(cluster.revision); cluster.execution_mode = body.execution_mode; cluster.revision++;
      data = structuredClone(cluster);
    } else if (uri.pathname.endsWith('/events/channels') && method === 'POST') {
      expect(cluster.execution_mode).toBe('approval'); submitKey = key;
      workflow = { id: randomUUID(), kind: 'event-metadata', clusterId: area.cid, workspaceId: area.wid, revision: 1, state: 'pending', planHash: 'a'.repeat(64) };
      originalSubmission = { id: workflow.id, workflowId: workflow.id, domain: 'workflow', handler: 'event.channel.save',
        clusterId: area.cid, workspaceId: area.wid, idempotencyKey: key, state: 'pending', configurationCommitted: false,
        submissionCompleted: true, executionCompleted: false, entity: structuredClone(workflow) };
      receipts.set(key, structuredClone(originalSubmission)); data = structuredClone(originalSubmission);
      const after = { kind: 'event-metadata', planHash: workflow.planHash, approvalRequired: true };
      audit = { id: randomUUID(), action: 'workflow.submit', result: 'success', scopeQuality: 'verified', actorId: actor.user.id, actorType: 'user',
        clusterId: area.cid, workspaceId: area.wid, entityType: options.singularEntity ? 'workflow' : 'workflows', entityId: workflow.id,
        workflowId: workflow.id, requestId, sourceIp: '127.0.0.1', before: null, after, jsonPatch: [{ op: 'replace', path: '', value: after }] };
    } else if (uri.pathname.endsWith(`/workflows/${workflow?.id}/approve`)) {
      expect(actor).toBe(actors.approver); expect(body.planHash).toBe(workflow.planHash);
      workflow.state = 'approved'; workflow.revision++; data = { entity: structuredClone(workflow) };
      decisions.set(key, { action: 'approve', idempotencyKey: key, decisionCompleted: true, workflowId: workflow.id, clusterId: area.cid, workspaceId: area.wid });
    } else if (uri.pathname.endsWith(`/workflows/${workflow?.id}/execute`)) {
      expect(actor).toBe(actors.admin); expect(workflow.state).toBe('approved'); workflow.state = 'succeeded'; workflow.revision++;
      executionId = randomUUID(); channel = { id: randomUUID(), name: calls.find(value => value.method === 'POST' && value.path.endsWith('/events/channels')).body.name,
        type: 'email', configured: true, status: 'active' };
      Object.assign(receipts.get(submitKey), { state: 'succeeded', configurationCommitted: true, executionCompleted: true, result: { entity: channel } });
      data = { workflowId: workflow.id, executionId, clusterId: area.cid, workspaceId: area.wid, state: 'succeeded', steps: [{ state: 'succeeded' }] };
      decisions.set(key, { ...structuredClone(data), action: 'execute', idempotencyKey: key });
    } else if (uri.pathname.includes('/workflows/receipts/by-key/')) data = structuredClone(decisions.get(uri.pathname.split('/').at(-1)));
    else if (uri.pathname.includes('/events/operations/by-key/')) data = structuredClone(receipts.get(uri.pathname.split('/').at(-1)));
    else if (uri.pathname.endsWith(`/workflows/${workflow?.id}`)) {
      data = { entity: structuredClone(workflow), steps: [{ kind: 'metadata', handler: 'event.channel.save', nativeRequests: [] }] };
      if (options.finalWorkflowState && workflow.state === 'succeeded') data.entity.state = options.finalWorkflowState;
    } else if (uri.pathname.endsWith('/audit')) {
      expect(uri.searchParams.get('workflowId')).toBe(workflow.id); expect(uri.searchParams.get('requestId')).toBe(audit.requestId);
      data = { items: [structuredClone(audit)], nextCursor: null };
    } else if (uri.pathname.endsWith(`/audit/${audit?.id}`)) data = structuredClone(audit);
    else throw Error('SYNTHETIC_UNEXPECTED_PATH');
    if (packet) Object.assign(packet, { state: 'response_observed', status, requestId, responseData: structuredClone(data) });
    return { status, requestId, payload: { data: structuredClone(data) } };
  };
  return { h, area, actors, calls, prefix, cluster };
}

describe('independent actual fresh workflow request-metadata helper', () => {
  it('creates one metadata approval with five original business writes, exact CAS restore and immutable original prefix', async () => {
    const f = fixture(), before = sha256(JSON.stringify(f.h.state.requests));
    const result = await freshWorkflowRequestMetadataAcceptance(f.h, f.actors);
    expect(f.calls.filter(call => call.method !== 'GET').map(call => call.method)).toEqual(['PATCH', 'POST', 'POST', 'POST', 'PATCH']);
    expect(f.calls.filter(call => call.method === 'PATCH').map(call => call.body)).toEqual([{ revision: 10, execution_mode: 'approval' }, { revision: 11, execution_mode: 'direct' }]);
    expect(f.calls.some(call => /entities|\/test$|deliveries|targets/.test(call.path))).toBe(false);
    expect(f.h.state.workflowRequestMetadataProof).toMatchObject({ state: 'completed', modeRestored: true, nativeTransportWrites: 0, providerTestRequests: 0 });
    expect(result).toMatchObject({ requestIdPresent: true, sourceIpPresent: true, originalModeRestored: true });
    expect(f.cluster.execution_mode).toBe('direct'); expect(f.h.state.c2ModeRestored).toBe(true);
    expect(sha256(JSON.stringify(f.h.state.requests.slice(0, f.prefix.length)))).toBe(before);
    const submitted = f.h.state.requests.find(packet => packet.path.endsWith('/events/channels'));
    expect(submitted.responseData.state).toBe('pending'); expect(submitted.responseData.configurationCommitted).toBe(false);
    expect(f.h.state.eventOperations).toHaveLength(1); expect(f.h.state.eventOperations[0].approval).toBe(true);
  });
  it('unknown execution stops before restore and cannot allocate another nonce or replay the original intent', async () => {
    const f = fixture({ unknownAtWrite: 4 });
    await expect(freshWorkflowRequestMetadataAcceptance(f.h, f.actors)).rejects.toThrow('M7_RESPONSE_UNKNOWN');
    expect(f.calls.filter(call => call.method !== 'GET')).toHaveLength(4); expect(f.cluster.execution_mode).toBe('approval');
    const before = structuredClone(f.h.state.requests), count = f.calls.length, name = f.h.state.workflowRequestMetadataProof.name;
    await expect(freshWorkflowRequestMetadataAcceptance(f.h, f.actors)).rejects.toThrow('begins once');
    expect(f.calls).toHaveLength(count); expect(f.h.state.requests).toEqual(before); expect(f.h.state.workflowRequestMetadataProof.name).toBe(name);
    expect(f.h.state.workflowRequestMetadataProof.state).toBe('prepared'); expect(f.h.state.c2ModeRestored).toBe(false);
  });
  it('a singular workflow audit entity fails before the mode restore or a green proof', async () => {
    const f = fixture({ singularEntity: true });
    await expect(freshWorkflowRequestMetadataAcceptance(f.h, f.actors)).rejects.toThrow('repaired fresh submission');
    expect(f.calls.filter(call => call.method !== 'GET')).toHaveLength(4); expect(f.h.state.workflowRequestMetadataProof.state).toBe('prepared');
    expect(f.h.public?.freshWorkflowRequestMetadata).toBeUndefined();
  });
  it('a final partial workflow cannot substitute for the required succeeded immutable terminal', async () => {
    const f = fixture({ finalWorkflowState: 'partial' });
    await expect(freshWorkflowRequestMetadataAcceptance(f.h, f.actors)).rejects.toThrow('completes its single');
    expect(f.calls.some(call => call.path.endsWith('/audit'))).toBe(false); expect(f.h.state.workflowRequestMetadataProof.state).toBe('prepared');
    expect(f.calls.filter(call => call.method !== 'GET')).toHaveLength(4);
  });
});
