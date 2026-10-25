import { describe, expect, it, vi } from 'vitest';
import { guardIsolatedTransition, registerIsolatedCluster } from './lib/m6-isolated-transition.mjs';
import { M6_C1, M6_C2 } from './lib/m6-harness.mjs';

const id = (n: number) => `20000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function setup(options: { unknown?: 'registration' | 'probe'; persistFailure?: 'registration' | 'probe'; observedVersion?: string } = {}) {
  const fixtures = [[M6_C1, id(1)], [M6_C2, id(2)], [M6_C1, id(3)]].map(([clusterId, workspaceId]) => ({ cluster: { id: clusterId }, workspace: { id: workspaceId, code: `m6-security-old-${workspaceId}` }, publications: [] }));
  const purposes = [['native_scrape', 'bff'], ['collector_catalog', 'bff'], ['collector_scrape', 'collector'], ['collector_ingest', 'collector']];
  const reference: any = { phase: 'bootstrap', testTag: 'm6-security-old', liveStartedAt: '2026-10-10T20:00:00.000Z', fixtures, grants: [], portalUsers: [],
    consoleAdministrator: { user: { id: id(10) } }, boundaryRefusalProof: { workflowId: id(11), originalKey: id(12) },
    writeAttempts: [{ key: id(13), requestId: id(14), method: 'POST', path: `/api/v1/clusters/${M6_C1}/entities/plugins`, state: 'response_observed', httpStatus: 403, errorCode: 'PORTAL_UNMANAGED_AUTH_BOUNDARY' }],
    tokens: [M6_C1, M6_C2].flatMap((clusterId, family) => purposes.map(([purpose, audience], i) => ({ clusterId, generation: family === 0 ? 2 : 1, purpose, audience, token: String.fromCharCode(65 + family * 4 + i).repeat(43) }))) };
  const facts = { grants: 0, issuedCredentials: 0, credentialRefs: 0, completedNative: 0, unresolvedNative: 0, metadataApplied: 0 };
  const evidence: any = { ownedScopes: fixtures.map(row => ({ clusterId: row.cluster.id, workspaceId: row.workspace.id })), publicationKey: id(12), publicationReceipt: { workflowId: id(11), state: 'failed', steps: [{ state: 'failed', remoteCompleted: false }, { state: 'pending', remoteCompleted: false }, { state: 'pending', remoteCompleted: false }] }, aclKey: id(13), aclReceipt: { state: 'failed', remoteCompleted: false, entityId: null }, oldFacts: facts };
  const targets: any = { primary: { id: id(20), adminUrl: 'http://kong-portal-admin-endpoint:8001', proxyOrigin: 'http://127.0.0.1:10000' }, secondary: { id: M6_C2, adminUrl: 'http://kong-secondary:8001', proxyOrigin: 'http://127.0.0.1:9000' } };
  const trace: { kind: 'persist' | 'request'; path?: string; method?: string; registration?: any }[] = [];
  let probed = false;
  const h: any = { referenceData: reference, requireLive: vi.fn(),
    saveReference: vi.fn((extra: any) => {
      trace.push({ kind: 'persist', registration: structuredClone(extra.isolatedRegistration) });
      if (options.persistFailure === 'registration' && extra.isolatedRegistration?.state === 'before-single-registration') throw new Error('Registration journal unavailable');
      if (options.persistFailure === 'probe' && extra.isolatedRegistration?.probe?.state === 'before-single-probe') throw new Error('Probe journal unavailable');
      Object.assign(reference, extra);
    }),
    request: vi.fn(async (_actor: any, path: string, method = 'GET', _body?: any, requestOptions?: any) => {
      trace.push({ kind: 'request', path, method });
      if (path === '/clusters' && method === 'POST') {
        expect(reference.isolatedRegistration.state).toBe('before-single-registration'); expect(requestOptions.key).toBe(reference.isolatedRegistration.key);
        if (options.unknown === 'registration') throw new Error('Registration acknowledgement lost');
        return { status: 201, value: { id: id(20), admin_url: targets.primary.adminUrl, version: null } };
      }
      if (path === `/clusters/${id(20)}/probe` && method === 'POST') {
        expect(reference.isolatedRegistration.clusterId).toBe(id(20)); expect(reference.isolatedRegistration.probe.state).toBe('before-single-probe');
        expect(requestOptions.key).toBe(reference.isolatedRegistration.probe.key); expect(requestOptions.key).not.toBe(reference.isolatedRegistration.key);
        if (options.unknown === 'probe') throw new Error('Probe acknowledgement lost');
        probed = true; return { status: 201, value: { version: '1.5.1' } };
      }
      if (method !== 'GET') throw new Error('Unexpected write during registration review');
      if (path === '/auth/me') return { status: 200, value: { user: reference.consoleAdministrator.user } };
      if (path.includes('/workflows/receipts/by-key/')) return { status: 200, value: evidence.publicationReceipt };
      if (path.includes('/mutations/by-key/')) return { status: 200, value: { state: 'failed', remoteCompleted: false } };
      const workspace = fixtures.find(row => path.includes(`/workspaces/${row.workspace.id}`));
      if (workspace) return { status: 200, value: workspace.workspace };
      const target = [targets.primary, targets.secondary].find(row => path === `/clusters/${row.id}`);
      if (target) return { status: 200, value: { id: target.id, admin_url: target.adminUrl, version: target.id === id(20) ? (probed ? options.observedVersion ?? '1.5.1' : null) : '1.5.1' } };
      throw new Error('Unexpected independent review read');
    }),
    ok: (result: any) => { if (result.status < 200 || result.status >= 300) throw new Error('Response not successful'); return result.value; },
    check: (passed: boolean) => { if (!passed) throw new Error('Current fact not proved'); },
    consoleRead: vi.fn((sql: string) => sql.startsWith('SELECT state,') ? [{ state: 'failed', remote_started: true, remote_completed: false, entity_id: null }] : [facts]) };
  return { h, reference, evidence, targets, trace };
}

describe('M6 independent isolated registration/probe sequencing delta', () => {
  it('accepts a null registration version, journals two distinct original keys before their packets, then verifies the current GET version', async () => {
    const f = setup(), cluster = await registerIsolatedCluster(f.h, 'm6-isolated-sequencing-review');
    expect(cluster.version).toBeNull(); await guardIsolatedTransition(f.h, f.evidence, f.targets);
    const writes = f.h.request.mock.calls.filter((row: any[]) => row[2] === 'POST');
    expect(writes.map((row: any[]) => row[1])).toEqual(['/clusters', `/clusters/${id(20)}/probe`]);
    const requests = f.trace.filter(row => row.kind === 'request');
    expect(requests.findIndex(row => row.path === `/clusters/${id(20)}`)).toBeGreaterThan(requests.findIndex(row => row.path === `/clusters/${id(20)}/probe`));
    for (const packet of f.trace.filter(row => row.method === 'POST')) {
      const index = f.trace.indexOf(packet), prior = f.trace.slice(0, index).filter(row => row.kind === 'persist').at(-1)?.registration;
      expect(packet.path?.endsWith('/probe') ? prior?.probe?.key : prior?.key).toMatch(/^[\da-f-]{36}$/);
    }
    expect(f.reference.phase).toBe('bootstrap'); expect(f.reference.writeAttempts[0].key).toBe(id(13));
  });
  it.each(['registration', 'probe'] as const)('stops after unknown %s with zero subsequent requests and refuses a second registration attempt', async unknown => {
    const f = setup({ unknown }); await expect(registerIsolatedCluster(f.h, 'm6-isolated-sequencing-review')).rejects.toThrow('acknowledgement lost');
    const checkpoint = structuredClone(f.reference.isolatedRegistration), count = f.h.request.mock.calls.length;
    expect(count).toBe(unknown === 'registration' ? 1 : 2);
    expect(f.h.request.mock.calls.every((row: any[]) => row[2] === 'POST')).toBe(true);
    await expect(registerIsolatedCluster(f.h, 'm6-isolated-another-tag')).rejects.toThrow('already attempted');
    expect(f.h.request).toHaveBeenCalledTimes(count); expect(f.reference.isolatedRegistration).toEqual(checkpoint);
    if (unknown === 'registration') expect(checkpoint.probe).toBeUndefined();
    else { expect(checkpoint.clusterId).toBe(id(20)); expect(checkpoint.probe.state).toBe('before-single-probe'); }
  });
  it.each(['registration', 'probe'] as const)('does not issue the %s packet when its durable original-key journal cannot be saved', async persistFailure => {
    const f = setup({ persistFailure }); await expect(registerIsolatedCluster(f.h, 'm6-isolated-sequencing-review')).rejects.toThrow('journal unavailable');
    expect(f.h.request).toHaveBeenCalledTimes(persistFailure === 'registration' ? 0 : 1);
    expect(f.h.request.mock.calls.some((row: any[]) => row[1].endsWith('/probe'))).toBe(false);
  });
  it('does not trust a successful probe response instead of the current registry version; wrong current version preserves the original checkpoint', async () => {
    const f = setup({ observedVersion: '2.8.0' }); await registerIsolatedCluster(f.h, 'm6-isolated-sequencing-review');
    await expect(guardIsolatedTransition(f.h, f.evidence, f.targets)).rejects.toThrow('not proved');
    expect(f.reference.phase).toBe('bootstrap'); expect(f.reference.isolatedStart).toBeUndefined();
    expect(f.h.request.mock.calls.filter((row: any[]) => row[2] === 'POST')).toHaveLength(2);
    expect(f.h.request.mock.calls.filter((row: any[]) => row[1] === `/clusters/${id(20)}`)).toHaveLength(1);
  });
});
