import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ObservationAuthorityService } from '../../apps/console-api/src/modules/event-observers/observation-authority.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { nativeAuditScope, nativeHistoricalScope } from '../../apps/console-api/src/modules/event-producers/native-audit-scope';

const cid = 'dff45535-ed8d-4851-b7a6-6376feac7f59', wid = '28329ea2-83a4-4b2c-b030-a209567d3276';
const id = '12491546-24cc-4f35-be68-bbe6f25da3b1', child = '32dfc101-e68d-480e-a30e-6b0ce16c0ba2';
describe('M7 real-source observation capabilities', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
  afterEach(() => { vi.unstubAllEnvs(); vi.useRealTimers(); });
  function fixture() {
    const state = { fenceCount: '0', unsettled: '0', revision: 1, workspaceRevision: 1, workspaceStatus: 'active', node: 'node-one', health: 'healthy', targetsChanged: false, pending: '0', baselineRevision: null as number | null };
    const upstream = { id, name: 'fixture', tags: ['team-pay'], healthchecks: { active: { healthy: { interval: 0 } } } };
    const target = { id: child, target: 'example.test:80', upstream: { id }, weight: 100, created_at: 1 };
    let targetRead = 0, rootRead = 0;
    const tx: any = { exec: vi.fn().mockResolvedValue(1), query: vi.fn().mockResolvedValue([{ id: cid, admin_url: 'http://kong:8001' }]), one: vi.fn(async (sql: string) => {
      if (sql.includes('FROM clusters')) return { id: cid, revision: state.revision, admin_url: 'http://kong:8001', version: '1.5.1', status: 'healthy' };
      if (sql.includes('FROM metrics_write_fences')) return { count: state.fenceCount, latest: null, unsettled: state.unsettled };
      if (sql.includes('FROM mutation_operations')) return { count: state.pending };
      if (sql.includes('FROM workspaces')) return { revision: state.workspaceRevision, status: state.workspaceStatus };
      if (sql.includes('FROM event_detection_state')) return state.baselineRevision === null ? null : { revision: state.baselineRevision };
      throw new Error('unexpected query');
    }) };
    const kong: any = { request: vi.fn(async (_cid: string, _method: string, path: string) => path === '/' ? { version: '1.5.1', node_id: ++rootRead === 1 ? 'node-one' : state.node } : structuredClone(upstream)),
      list: vi.fn(async (_cid: string, path: string) => ({ items: path.endsWith('/health') ? [{ ...target, health: state.health }] : [{ ...target, weight: state.targetsChanged && ++targetRead > 1 ? 200 : 100 }], nextCursor: null })) };
    const execution: any = { runEventObservationRead: vi.fn(async (_cid: string, _paths: string[], fn: () => Promise<unknown>) => fn()) };
    const workspaces: any = { classify: vi.fn().mockResolvedValue({ state: 'resolved', workspace: { id: wid, revision: 1, status: 'active' } }) };
    const authority = new ObservationAuthorityService(tx, new SecretService(), kong, execution, workspaces);
    return { state, tx, kong, execution, authority };
  }
  it('uses fixed bounded real read paths and seals only safe observed state', async () => {
    const f = fixture(), capture = await f.authority.observe(cid, 'upstreams', id);
    expect(f.execution.runEventObservationRead.mock.calls[0][1]).toEqual(['/', `/upstreams/${id}`, `/upstreams/${id}/targets/all`, `/upstreams/${id}/health`]);
    expect(capture.input.observationSafe).toEqual({ kind: 'upstream_health', health: 'healthy' });
    expect(JSON.stringify(capture.input)).not.toContain('example.test:80');
    expect(JSON.stringify(capture.input)).not.toContain(child);
    await expect(f.authority.assertCurrent(capture.input, f.tx)).resolves.toBeUndefined();
    expect(f.tx.exec).toHaveBeenCalledWith('SELECT pg_advisory_xact_lock(hashtext($1))', [expect.stringContaining('kongos:metrics-transport:')]);
    capture.release(); await expect(f.authority.assertCurrent(capture.input, f.tx)).rejects.toMatchObject({ status: 403 });
  });
  it('rejects copied/serialized proof and changed subject, config or observation', async () => {
    const f = fixture(), capture = await f.authority.observe(cid, 'upstreams', id);
    await expect(f.authority.assertCurrent({ ...capture.input, sourceProof: { ...capture.input.sourceProof } } as any, f.tx)).rejects.toMatchObject({ status: 403 });
    await expect(f.authority.assertCurrent(JSON.parse(JSON.stringify(capture.input)), f.tx)).rejects.toMatchObject({ status: 403 });
    for (const delta of [{ subjectId: child }, { workspaceId: cid }, { configFingerprint: '0'.repeat(64) }, { quality: 'partial' }, { observationSafe: { kind: 'upstream_health', health: 'unhealthy' } }]) {
      await expect(f.authority.assertCurrent({ ...capture.input, ...delta } as any, f.tx)).rejects.toMatchObject({ status: 403 });
    }
  });
  it.each(['fenceCount', 'unsettled', 'revision', 'workspaceRevision', 'workspaceStatus', 'pending'] as const)('rechecks current %s at both transaction fences', async field => {
    const f = fixture(), capture = await f.authority.observe(cid, 'upstreams', id);
    await f.authority.assertCurrent(capture.input, f.tx);
    (f.state as any)[field] = field === 'workspaceStatus' ? 'disabled' : typeof f.state[field] === 'number' ? 2 : '1';
    await expect(f.authority.assertCurrent(capture.input, f.tx)).rejects.toBeDefined();
  });
  it('accepts historical fences with terminal parents without forgetting the native continuity stamp', async () => {
    const f = fixture(); f.state.fenceCount = '89';
    const capture = await f.authority.observe(cid, 'upstreams', id);
    await expect(f.authority.assertCurrent(capture.input, f.tx)).resolves.toBeUndefined();
    f.state.fenceCount = '90';
    await expect(f.authority.assertCurrent(capture.input, f.tx)).rejects.toBeDefined();
  });
  it('rejects unresolved parents before any Kong read and resolves physical aliases for NULL-scope legacy operations', async () => {
    const f = fixture(); f.state.unsettled = '1';
    await expect(f.authority.observe(cid, 'upstreams', id)).rejects.toMatchObject({ status: 409 });
    expect(f.kong.request).not.toHaveBeenCalled();
    f.state.unsettled = '0'; f.state.pending = '1';
    f.tx.query.mockResolvedValue([{ id: cid, admin_url: 'http://kong:8001' }, { id: child, admin_url: 'http://kong:8001' }]);
    await expect(f.authority.observe(cid, 'upstreams', id)).rejects.toMatchObject({ status: 409 });
    expect(f.tx.one.mock.calls.findLast(([sql]: [string]) => sql.includes('FROM mutation_operations'))?.[1]?.[1]).toEqual([cid, child]);
    expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects oversized or vanished physical aliases before any Kong read', async () => {
    const f = fixture(); f.tx.query.mockResolvedValue(Array.from({ length: 10001 }, () => ({ id: cid, admin_url: 'http://kong:8001' })));
    await expect(f.authority.observe(cid, 'upstreams', id)).rejects.toMatchObject({ status: 409 });
    f.tx.query.mockResolvedValue([]);
    await expect(f.authority.observe(cid, 'upstreams', id)).rejects.toMatchObject({ status: 403 });
    expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('does not refresh stale proof by updating observed timestamp', async () => {
    vi.useFakeTimers(); const f = fixture(), capture = await f.authority.observe(cid, 'upstreams', id);
    vi.advanceTimersByTime(15_001);
    await expect(f.authority.assertCurrent(capture.input, f.tx)).rejects.toMatchObject({ status: 403 });
    await expect(f.authority.assertCurrent({ ...capture.input, observedAt: new Date().toISOString() }, f.tx)).rejects.toMatchObject({ status: 403 });
  });
  it.each(['node', 'health', 'targetsChanged'] as const)('never publishes incomplete or changed %s readings', async field => {
    const f = fixture(); (f.state as any)[field] = field === 'targetsChanged' ? true : 'unknown';
    await expect(f.authority.observe(cid, 'upstreams', id)).rejects.toBeDefined();
  });
  it('clears an unavailable interval through a real quality record before confirming later samples', async () => {
    const f = fixture(); f.authority.noteGap(cid, 'upstreams', id);
    const recovered = await f.authority.observe(cid, 'upstreams', id);
    expect(recovered.input).toMatchObject({ quality: 'partial', observationSafe: null });
    await f.authority.assertCurrent(recovered.input, f.tx); recovered.release(true);
    const next = await f.authority.observe(cid, 'upstreams', id);
    expect(next.input).toMatchObject({ quality: 'verified', observationSafe: { kind: 'upstream_health', health: 'healthy' } });
  });
  it('does not reuse old baseline continuity after restart or an uncommitted quality record', async () => {
    const f = fixture(); f.state.baselineRevision = 3;
    const restart = await f.authority.observe(cid, 'upstreams', id);
    expect(restart.input).toMatchObject({ quality: 'partial', observationSafe: null, beforeBaselineRevision: 3 });
    restart.release(false);
    const retry = await f.authority.observe(cid, 'upstreams', id);
    expect(retry.input).toMatchObject({ quality: 'partial', observationSafe: null });
    retry.release(true);
    const fresh = await f.authority.observe(cid, 'upstreams', id);
    expect(fresh.input.quality).toBe('verified');
  });
});

describe('M7 producer historical scope', () => {
  it('keeps before and after tags/workspaces separate for migration', () => {
    const scope = nativeAuditScope({ type: 'services', id, before: { id, tags: ['team-pay'] }, after: { id, tags: ['team-sales'] }, beforeWorkspaceId: wid, afterWorkspaceId: cid });
    expect(scope).toMatchObject({ quality: 'verified', beforeTags: ['team-pay'], afterTags: ['team-sales'], beforeWorkspaceId: wid, afterWorkspaceId: cid });
    expect(scope.beforeTags).not.toContain('team-sales');
  });
  it('binds typed credential and parent without parent tag union', () => {
    const scope = nativeAuditScope({ type: 'credentials', credentialKind: 'jwt', parentId: child, id, before: null, after: { id, tags: ['own-child'] }, beforeWorkspaceId: null, afterWorkspaceId: wid });
    expect(scope).toMatchObject({ nativeType: 'jwt', parentContext: { nativeType: 'consumers', nativeId: child, credentialKind: 'jwt' }, beforeExists: false, afterExists: true, afterTags: ['own-child'] });
  });
  it('never declares a planned object or a changed native id as verified', () => {
    expect(nativeHistoricalScope({ type: 'services', id, before: null, after: { name: 'planned', tags: ['team-pay'] }, beforeWorkspaceId: null, afterWorkspaceId: wid }).quality).toBe('legacy_unknown');
    expect(nativeHistoricalScope({ type: 'targets', id: child, parentId: cid, before: { id }, after: { id: child }, beforeWorkspaceId: wid, afterWorkspaceId: wid }).quality).toBe('legacy_unknown');
  });
});
