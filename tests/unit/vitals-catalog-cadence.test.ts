import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MetricsCatalogService } from '../../apps/console-api/src/modules/vitals/bridges/metrics-catalog.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
const cid = '9a15a2e4-bada-44f3-bc3d-0f164072901b', sid = '5147b0fc-9790-47fe-9522-4355d6a49830', rid = '9a017b15-16c9-4c72-b7cb-3af2c48d0351', node = 'c1e09535-62f2-41f2-a0d7-3cb3a07d1c2e';
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M5 continuous catalog proof with Prometheus-only fifteen-second scrapes', () => {
  it('refreshes before proof expires and keeps one sixty-second counter baseline', async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-10T12:00:00Z')); vi.stubEnv('METRICS_BRIDGE_ENABLED', 'true');
    const state = { verified: 0, openedAt: 0, opened: 0, revision: 1 }, execution = new KongExecutionContextService();
    const settings: any = { get: vi.fn(async () => ({ state: state.verified ? 'ready' : 'uninitialized', catalogRevision: state.revision, maxAgeMs: 15000, lastVerifiedAt: state.verified ? new Date(state.verified).toISOString() : null })) };
    const repository: any = { publishVerifiedCatalog: vi.fn(async input => {
      const observed = Date.parse(input.observedAt);
      // Explicit repository interval model: gaps open a new baseline; fresh
      // proof extends verification without changing immutable openedAt.
      if (!state.verified || observed > state.verified + 15000) { state.opened++; state.openedAt = observed; }
      state.verified = observed; return { catalogRevision: state.revision };
    }) };
    const kong: any = { transportScope: vi.fn(async () => 'a'.repeat(64)), request: vi.fn(async () => ({ version: '1.5.1', node_id: node })), list: vi.fn(async (_cid, path) => ({ items: path === '/services' ? [{ id: sid, name: 's', host: 'business.example', tags: [] }] : path === '/routes' ? [{ id: rid, name: 'r', service: { id: sid }, tags: [] }] : [], nextCursor: null })) };
    const service = new MetricsCatalogService(kong, execution, repository, settings, { query: async () => [{ cluster_id: cid }] } as any);
    await service.scan(cid); const start = state.openedAt; service.onModuleInit();
    try {
      for (let scrape = 0; scrape < 4; scrape++) { await vi.advanceTimersByTimeAsync(15010); await service.ensureFresh(cid); expect(Date.now() - state.verified).toBeLessThan(15000); }
      expect(state.opened).toBe(1); expect(state.openedAt).toBe(start); expect(Date.now() - state.openedAt).toBeGreaterThanOrEqual(60000);
      expect(repository.publishVerifiedCatalog.mock.calls.length).toBeGreaterThanOrEqual(12);
    } finally { service.onModuleDestroy(); }
    const scans = repository.publishVerifiedCatalog.mock.calls.length; await vi.advanceTimersByTimeAsync(20000); expect(repository.publishVerifiedCatalog).toHaveBeenCalledTimes(scans);
  });
});
