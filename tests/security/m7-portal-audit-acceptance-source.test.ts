// @ts-nocheck -- passive BFF helper with supplied synthetic transport only.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID, createHash } from 'node:crypto';
import { portalTerminalAuditAcceptance } from './lib/m7-portal-audit-acceptance.mjs';

function fixture(fault = '') {
  const cid = randomUUID(), wid = randomUUID(), pageId = randomUUID(), workflowId = randomUUID();
  const admin = { user: { id: randomUUID() }, sid: randomUUID() }, calls = [], audits = [], checks = [];
  const actors = { admin, direct: { cid, wid } };
  let page, markdown;
  const pageView = row => ({ id: row.id, slug: row.slug, title: row.title, revision: row.revision, documentRevision: row.published_revision, state: row.state });
  const h = { state: { testTag: 'm7-security-abcdef01', fixtures: [], requests: [], secrets: ['SyntheticPrivateCredential'] }, save: vi.fn(),
    check(ok, name, facts = {}) { if (!ok) throw Error(name); checks.push({ name, ...facts }); },
    data(result) { return result.payload.data; },
  };
  h.request = vi.fn(async (actor, path, method = 'GET', body) => {
    const url = new URL('https://synthetic.invalid' + path), route = url.pathname, requestId = randomUUID();
    const packet = { method, path: route, body: structuredClone(body), key: randomUUID(), requestId, actorId: actor.user.id, sessionId: actor.sid,
      clusterId: cid, workspaceId: wid, bodySha256: createHash('sha256').update(JSON.stringify(body ?? null)).digest('hex'), state: 'prepared' };
    calls.push(packet);
    if (method !== 'GET') {
      h.state.requests.push(packet);
      if (fault === `unknown-${method}`) { packet.state = 'response_unknown'; h.state.inFlight = h.state.requests.length - 1; throw Error('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED'); }
    }
    let data;
    if (route === `/clusters/${cid}/portal/pages` && method === 'POST') {
      page = { id: pageId, cluster_id: cid, workspace_id: wid, slug: body.slug, title: body.title, current_revision: 2, published_revision: null,
        workflow_id: workflowId, state: 'draft', revision: 2, created_by: admin.user.id, updated_by: admin.user.id,
        created_at: '2026-10-01T00:00:00.000Z', updated_at: '2026-10-01T00:01:00.000Z', deleted_at: null, retention_until: null };
      markdown = body.markdown; data = { entity: pageView(page), workflowId, receipt: { state: 'succeeded' } };
    } else if (route === `/clusters/${cid}/workflows/${workflowId}`) {
      data = { entity: { id: workflowId, kind: 'portal-metadata', executionMode: 'direct', approvalRequired: false, state: 'succeeded' }, steps: [{ kind: fault === 'native-step' ? 'native' : 'metadata', state: 'succeeded', operationId: null, recycleEntryId: null }] };
    } else if (route === `/clusters/${cid}/portal/pages/${pageId}`) {
      if (method === 'PATCH') {
        expect(body).toEqual({ revision: page.revision, slug: page.slug, title: 'm7-security-abcdef01 Portal audit after', markdown: '# M7 portal audit after\n\nUpdated unpublished acceptance content.\n' });
        const before = structuredClone(page);
        page = { ...page, title: body.title, revision: page.revision + 1, current_revision: page.current_revision + 1, updated_at: '2026-10-01T00:02:00.000Z' }; markdown = body.markdown;
        const patch = [{ op: 'replace', path: '/title', value: page.title }, { op: 'replace', path: '/revision', value: page.revision }, { op: 'replace', path: '/current_revision', value: page.current_revision }, { op: 'replace', path: '/updated_at', value: page.updated_at }];
        for (const action of ['portal.page.draft', 'iam.write']) audits.push({ id: randomUUID(), actorId: admin.user.id, actorType: 'user', sourceIp: '127.0.0.1', clusterId: cid, workspaceId: wid,
          entityType: 'portal_content', entityId: pageId, action, before: structuredClone(before), after: structuredClone(page), jsonPatch: structuredClone(patch), workflowId: null,
          result: 'success', requestId, occurredAt: '2026-10-01T00:02:00.001Z', scopeQuality: 'verified' });
        if (fault === 'null-before') audits[0].before = null;
        if (fault === 'sparse-before') delete audits[0].before.created_at;
        if (fault === 'old-wrapper-after') audits[1].after = { entity: pageView(page) };
        if (fault === 'wrong-patch') audits[0].jsonPatch = [];
        if (fault === 'wrong-request') audits[0].requestId = randomUUID();
        if (fault === 'wrong-scope') audits[0].workspaceId = randomUUID();
        if (fault === 'wrong-actor') audits[0].actorId = randomUUID();
        if (fault === 'missing-terminal') audits.pop();
        if (fault === 'extra-terminal') audits.push({ ...structuredClone(audits[0]), id: randomUUID() });
        if (fault === 'secret-audit') audits[0].after.title = h.state.secrets[0];
        data = { entity: pageView(page) };
      } else if (method === 'DELETE') {
        expect(body).toEqual({ revision: page.revision, confirmed: true, confirm_name: page.title });
        page = { ...page, revision: page.revision + 1, state: 'deleted', deleted_at: '2026-10-01T00:03:00.000Z', retention_until: '2026-11-01T00:03:00.000Z' };
        data = { entity: pageView(page) };
      } else data = { entity: pageView(page), markdown };
    } else if (route === `/clusters/${cid}/audit`) {
      expect(Object.fromEntries(url.searchParams)).toMatchObject({ workspaceId: wid, entityType: 'portal_content', entityId: pageId, result: 'success', size: '100' });
      data = { items: structuredClone(audits), total: null, size: 100, nextCursor: null };
    } else if (route.startsWith(`/clusters/${cid}/audit/`)) data = structuredClone(audits.find(row => row.id === route.split('/').at(-1)));
    else throw Error('UNAUTHORIZED_SYNTHETIC_ENDPOINT');
    packet.state = 'response_observed'; packet.status = method === 'POST' ? 201 : 200;
    return { status: packet.status, requestId, payload: { success: true, data } };
  });
  return { h, actors, calls, audits, checks, cid, wid, pageId };
}

describe('Portal terminal actual-BFF helper, source only', () => {
  it('reads full business and IAM transition and archives a fresh draft without native or publication requests', async () => {
    const f = fixture(), result = await portalTerminalAuditAcceptance(f.h, f.actors);
    expect(result).toMatchObject({ pageId: f.pageId, terminalAudits: 2, archived: true, published: false, nativeSteps: 0, fullBeforeAfterVerified: true, independentPatchVerified: true });
    expect(result.auditEventIds).toEqual(f.audits.map(row => row.id));
    expect(f.h.public.portalTerminalAudit).toEqual(result);
    expect(f.h.state.fixtures).toEqual([expect.objectContaining({ type: 'portal_pages', id: f.pageId, revision: 4, archived: true, cid: f.cid, wid: f.wid })]);
    expect(f.calls.filter(row => row.method !== 'GET').map(row => row.method)).toEqual(['POST', 'PATCH', 'DELETE']);
    expect(f.calls.every(row => row.actorId === f.actors.admin.user.id && row.clusterId === f.cid && row.workspaceId === f.wid)).toBe(true);
    expect(f.calls.every(row => /^\/clusters\/[^/]+\/(portal\/pages(?:\/[^/]+)?|workflows\/[^/]+|audit(?:\/[^/]+)?)$/.test(row.path))).toBe(true);
    expect(JSON.stringify(result)).not.toMatch(/markdown|Portal audit after|SyntheticPrivateCredential/);
  });
  it.each(['native-step', 'null-before', 'sparse-before', 'old-wrapper-after', 'wrong-patch', 'wrong-request', 'wrong-scope', 'wrong-actor', 'missing-terminal', 'extra-terminal', 'secret-audit'])('rejects %s before archiving or reporting closure', async fault => {
    const f = fixture(fault); await expect(portalTerminalAuditAcceptance(f.h, f.actors)).rejects.toThrow();
    expect(f.calls.some(row => row.method === 'DELETE')).toBe(false); expect(f.h.public).toBeUndefined();
    expect(f.h.state.fixtures).toHaveLength(1);
  });
  it.each(['POST', 'PATCH', 'DELETE'])('an unknown original %s response propagates without retries, replacement keys or cleanup packets', async method => {
    const f = fixture(`unknown-${method}`);
    await expect(portalTerminalAuditAcceptance(f.h, f.actors)).rejects.toThrow('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED');
    const unknown = f.h.state.requests.at(-1);
    expect(unknown.state).toBe('response_unknown'); expect(unknown.method).toBe(method);
    expect(f.calls.at(-1)).toBe(unknown); expect(f.h.public).toBeUndefined();
    expect(f.calls.filter(row => row.method === method)).toHaveLength(1);
    expect(new Set(f.h.state.requests.map(row => row.key)).size).toBe(f.h.state.requests.length);
    expect(f.h.state.fixtures).toHaveLength(method === 'POST' ? 0 : 1);
  });
});
