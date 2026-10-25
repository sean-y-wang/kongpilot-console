import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { GovernanceInventoryService } from '../../apps/console-api/src/modules/governance/governance-inventory.service';
import { GovernanceService } from '../../apps/console-api/src/modules/governance/governance.service';
import { GovernancePromotionSourceService } from '../../apps/console-api/src/modules/governance/governance-promotion-source.service';
import { GOVERNANCE_ENTITY_TYPES } from '../../apps/console-api/src/modules/governance/governance-inventory.types';
import { id, schemas } from './m8-config-transfer.fixture';

/** Actual orchestration, inventory, private receipt WeakMap and logical engine.
 * Authority/SQL/wire are explicitly synthetic bounded seams; this is source
 * regression evidence, not a real Kong capture or a timer acceptance result. */
function fixture() {
  const secret = new SecretService(), sourceCid = id(101), targetCid = id(201), sourceWid = id(100), targetWid = id(200), uid = id(300), sid = id(301);
  const actor = { user: { id: uid, username: 'schema-union-owner', superAdmin: false }, workspaceId: sourceWid, idempotencyKey: randomUUID(), requestId: randomUUID(), ip: '192.0.2.10' };
  const pluginNames = ['correlation-id', 'cors'], enabled = [...pluginNames, 'unused-enabled-plugin'];
  const raw = new Map<string, Map<string, any>>(), wire: Array<{ cid: string; method: string; path: string; handle: object }> = [];
  for (const [cid, wid, name, nativeId] of [[sourceCid, sourceWid, pluginNames[0], id(1)], [targetCid, targetWid, pluginNames[1], id(2)]]) {
    const records = new Map<string, any>([['/', { version: '1.5.1' }], ['/plugins/enabled', { enabled_plugins: enabled }]]);
    for (const type of GOVERNANCE_ENTITY_TYPES) {
      records.set(`/schemas/${type}`, schemas().entities[type]); records.set(`/${type}`, { data: [], next: null });
    }
    records.set('/plugins', { data: [{ id: nativeId, name, enabled: true, config: name === 'cors' ? { origins: ['*'] } : { header_name: 'X-Trace', generator: 'uuid', echo_downstream: false }, tags: [] }], next: null });
    for (const plugin of pluginNames) records.set(`/plugins/schema/${plugin}`, JSON.parse(readFileSync(`tests/fixtures/kong-1.5.1/plugin-schema-${plugin}.json`, 'utf8')));
    raw.set(cid, records);
  }
  type State = { cid: string; wid: string; usage: { calls: number; pages: number; records: number; bytes: number }; fingerprints: Record<string, string>; valid: boolean; token?: object };
  const states = new WeakMap<object, State>(); let active: object | undefined;
  const get = (handle: object): State => { const value = states.get(handle); if (!value || !value.valid) throw new ForbiddenException({ code: 'GOVERNANCE_AUTHORITY_REQUIRED' }); return value; };
  const mint = (cid: string, wid: string) => { const handle = Object.freeze({}); states.set(handle, { cid, wid, usage: { calls: 0, pages: 0, records: 0, bytes: 0 }, fingerprints: {}, valid: true }); return handle; };
  const authority: any = {
    acquireActor: vi.fn(async (cid: string, input: any) => mint(cid, input.workspaceId)),
    acquireDueSchedule: vi.fn(async (locator: any) => mint(locator.side === 'target' ? targetCid : sourceCid, locator.side === 'target' ? targetWid : sourceWid)),
    description: async (handle: object) => { const state = get(handle); return { scope: { clusterId: state.cid, workspaceId: state.wid, kind: 'workspace', rootIds: [], transportScope: state.cid === sourceCid ? 'a'.repeat(64) : 'b'.repeat(64) }, version: '1.5.1', actor: { ...actor, workspaceId: state.wid }, projection: false, permittedTypes: GOVERNANCE_ENTITY_TYPES }; },
    assertCurrent: vi.fn(async (handle: object) => { get(handle); }),
    runRead: vi.fn(async (handle: object, fn: any) => { get(handle); const previous = active; active = handle; try { return await fn(); } finally { active = previous; } }),
    usage: (handle: object) => ({ ...get(handle).usage }), managedBoundary: async () => 'none',
    beginInventoryFingerprints: async (handle: object) => { const state = get(handle), token = Object.freeze({}); if (state.token) throw new Error('overlapping capture'); state.fingerprints = {}; state.token = token; return token; },
    sealInventoryFingerprints: async (handle: object, token: object) => { const state = get(handle); if (state.token !== token) throw new Error('capture token required'); return { ...state.fingerprints }; },
    discardInventoryFingerprints: (handle: object, token: object) => { const state = get(handle); if (state.token === token) delete state.token; },
  };
  const kong: any = { request: vi.fn(async (cid: string, method: string, path: string) => {
    if (!active || get(active).cid !== cid || method !== 'GET') throw new Error('same read-only scoped handle required');
    const state = get(active); if (state.usage.calls >= 500) throw new ConflictException({ code: 'GOVERNANCE_BUDGET_EXHAUSTED' });
    state.usage.calls++; wire.push({ cid, method, path, handle: active });
    if (!raw.get(cid)!.has(path)) throw new NotFoundException({ code: 'NOT_FOUND' });
    return structuredClone(raw.get(cid)!.get(path));
  }), list: vi.fn(async (cid: string, path: string) => {
    const page = await kong.request(cid, 'GET', path), state = get(active!); state.usage.pages++; state.usage.records += page.data.length;
    for (const object of page.data) state.fingerprints[`${path.slice(1)}:${object.id}`] = secret.fingerprint(object);
    return { items: page.data, nextCursor: null };
  }) };
  const workspaces: any = { resolve: async (cid: string) => ({ id: cid === sourceCid ? sourceWid : targetWid }), classify: async (cid: string) => ({ state: 'resolved', workspace: { id: cid === sourceCid ? sourceWid : targetWid } }) };
  const context: any = { current: () => ({ actor: actor.user, sessionId: sid, limits: { maxCalls: 500 } }), currentUsage: () => active ? { ...get(active).usage } : { pages: 0 } };
  const inventory = new GovernanceInventoryService(authority, kong, {} as any, secret, workspaces, { getMany: async () => ({}) } as any, context);
  const capture = vi.spyOn(inventory, 'capture'), enrich = vi.spyOn(inventory, 'enrichPluginSchemas');
  const run: any = { id: randomUUID(), cluster_id: sourceCid, workspace_id: sourceWid, actor_id: uid, idempotency_key: actor.idempotencyKey, kind: 'comparison', state: 'running' };
  let sealed: any;
  const repo: any = { beginRun: async () => ({ row: run, existing: false }), saveComparison: vi.fn(async (input: any) => { sealed = input; }), finishRun: async (_id: string, state: string) => { run.state = state; }, run: async () => run,
    comparison: async () => ({ id: sealed.id, cluster_id: sourceCid, workspace_id: sourceWid, target_cluster_id: targetCid, target_workspace_id: targetWid, quality: sealed.result.completeness, counts: sealed.result.counts, created_at: new Date() }), comparisonInventories: () => ({ source: sealed.source, target: sealed.target }) };
  const db: any = { query: async () => [], transaction: async (fn: any) => fn(db), one: async (sql: string) => sql.includes('governance_comparisons') ? { id: sealed.id } : null, exec: vi.fn(async () => 1) };
  const authz: any = { assertCluster: async () => undefined, permissionVersion: async () => 'epoch', assertScopedResource: async () => undefined, assertEntity: async () => undefined, hasWholeWorkspace: async () => false };
  const service = new GovernanceService(db, { withLock: async (_lock: string, fn: any) => fn() } as any, secret, context, authz, workspaces, authority, inventory, repo, {} as any, {} as any, { append: vi.fn(async () => undefined) } as any);
  const compare = () => service.compare(sourceCid, { target: { clusterId: targetCid, workspaceId: targetWid } }, actor);
  const scheduled = () => service.runScheduled({ scheduleId: id(401), clusterId: sourceCid, workspaceId: sourceWid, ownerUserId: uid, version: 1, revision: 1, scheduledAt: '2026-10-13T01:00:00Z', runId: id(402), leaseGeneration: 1 }, { kind: 'drift', threshold: 0 });
  return { secret, sourceCid, targetCid, sourceWid, targetWid, actor, raw, wire, authority, inventory, capture, enrich, context, db, repo, service, compare, scheduled, sealed: () => sealed, get };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ca'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M10 configured plugin schema union in actual orchestration', () => {
  it.each(['http', 'schedule'] as const)('fills both actual gateway schemas for a disjoint configured union (%s)', async mode => {
    const f = fixture(); await (mode === 'http' ? f.compare() : f.scheduled()); const sealed = f.sealed();
    expect(sealed.result.completeness).toBe('complete');
    for (const [cid, inv] of [[f.sourceCid, sealed.source], [f.targetCid, sealed.target]]) {
      expect(Object.keys(inv.pluginSchemas).sort()).toEqual(['correlation-id', 'cors']);
      expect(f.wire.filter(packet => packet.cid === cid && packet.path.startsWith('/plugins/schema/')).map(packet => packet.path).sort()).toEqual(['/plugins/schema/correlation-id', '/plugins/schema/cors']);
      for (const type of GOVERNANCE_ENTITY_TYPES) expect(f.wire.filter(packet => packet.cid === cid && packet.path === `/${type}`)).toHaveLength(1);
      const scopedWire = f.wire.filter(packet => packet.cid === cid); expect(new Set(scopedWire.map(packet => packet.handle)).size).toBe(1);
      expect(inv.usage.calls).toBe(scopedWire.length);
    }
    expect(f.enrich).toHaveBeenCalledTimes(2); expect(f.wire.every(packet => packet.method === 'GET')).toBe(true);
    expect(Object.keys(sealed.sourceNativeFingerprints)).toEqual([`plugins:${id(1)}`]); expect(Object.keys(sealed.targetNativeFingerprints)).toEqual([`plugins:${id(2)}`]);
    expect(mode === 'schedule' ? f.authority.acquireActor : f.authority.acquireDueSchedule).not.toHaveBeenCalled();
  });
  it('keeps a missing target schema incomplete rather than copying the available source schema', async () => {
    const f = fixture(); f.raw.get(f.targetCid)!.delete('/plugins/schema/correlation-id');
    await expect(f.compare()).resolves.toMatchObject({ state: 'incomplete', entity: { quality: 'incomplete' } });
    expect(f.sealed().source.pluginSchemas['correlation-id']).toBeDefined(); expect(f.sealed().target.pluginSchemas['correlation-id']).toBeUndefined();
    expect(f.sealed().target.reasonCodes).toContain('PLUGIN_SCHEMA_NOT_CAPTURED'); expect(f.sealed().result.threshold.evaluated).toBe(false);
    expect(f.wire).toContainEqual(expect.objectContaining({ cid: f.targetCid, path: '/plugins/schema/correlation-id' }));
  });
  it('rejects revoked authority during enrichment before storing a comparison or laundering a raw receipt', async () => {
    const f = fixture(), actual = f.inventory.enrichPluginSchemas.bind(f.inventory);
    f.enrich.mockImplementation(async (handle, inventory, names) => { f.get(handle).valid = false; return actual(handle, inventory, names); });
    await expect(f.compare()).rejects.toMatchObject({ status: 403 }); expect(f.repo.saveComparison).not.toHaveBeenCalled();
  });
});

describe('M10 immutable schema requirements in Promote source policy', () => {
  async function prepared() {
    const f = fixture(); await f.compare(); const sealed = f.sealed(), promotionId = id(403);
    const material = { row: { actor_id: f.actor.user.id }, source: sealed.source, target: sealed.target, options: { targetWorkspaceCode: 'target' } };
    const provider = new GovernancePromotionSourceService(f.db, f.secret, f.context, f.repo, f.authority, f.inventory, {} as any);
    vi.spyOn(provider as any, 'material').mockResolvedValue(material); vi.spyOn(provider, 'assertGrants').mockResolvedValue(undefined);
    f.capture.mockClear(); const claim = await provider.acquire(promotionId, f.actor); return { ...f, provider, promotionId, claim, material };
  }
  it('uses each target gateway and its own schema for a source-only plugin, then retains the exact sealed union for every refresh', async () => {
    const f = await prepared(), initial = f.capture.mock.calls.slice();
    expect(initial).toHaveLength(2); expect(initial[0][1]).toEqual({ requiredPluginSchemas: ['correlation-id', 'cors'] }); expect(initial[1][1]).toEqual(initial[0][1]);
    const sourceUsage = f.get(f.claim.handle).usage.calls, targetHandle = initial[1][0];
    const fresh = await f.provider.refresh(f.promotionId, f.claim.handle, f.actor);
    expect(f.capture.mock.calls[2][0]).toBe(f.claim.handle); expect(f.capture.mock.calls[2][1]).toEqual(initial[0][1]);
    expect(Object.isFrozen(f.capture.mock.calls[2][1]!.requiredPluginSchemas)).toBe(true); expect(f.get(f.claim.handle).usage.calls).toBeGreaterThan(sourceUsage);
    expect(f.get(targetHandle).usage.calls).toBe(f.claim.target.usage!.calls);
    const fingerprints = await f.provider.fingerprints(f.promotionId, f.claim.handle, fresh); expect(fingerprints).toHaveProperty(`plugins:${id(1)}`);
    await expect(f.provider.fingerprints(f.promotionId, f.claim.handle, structuredClone(fresh))).rejects.toMatchObject({ status: 403 });
  });
  it('cannot renew the source shared 500-call budget by refreshing its actual handle', async () => {
    const f = await prepared(); f.get(f.claim.handle).usage.calls = 500;
    await expect(f.provider.refresh(f.promotionId, f.claim.handle, f.actor)).rejects.toMatchObject({ response: { code: 'GOVERNANCE_BUDGET_EXHAUSTED' } });
    expect(f.capture.mock.calls.at(-1)![0]).toBe(f.claim.handle); expect(f.get(f.claim.handle).usage.calls).toBe(500);
    await expect(f.provider.refresh(f.promotionId, { ...f.claim.handle }, f.actor)).rejects.toMatchObject({ status: 403 });
    expect(f.capture).toHaveBeenCalledTimes(3);
  });
  it('detects an actual new plugin rather than shrinking fresh schema requests to the old configured set', async () => {
    const f = await prepared(); f.raw.get(f.sourceCid)!.get('/plugins').data.push({ id: id(3), name: 'cors', enabled: true, config: { origins: ['new-fixture.invalid'] }, tags: [] });
    const fresh = await f.provider.refresh(f.promotionId, f.claim.handle, f.actor), fingerprints = await f.provider.fingerprints(f.promotionId, f.claim.handle, fresh);
    expect(fresh.objects).toHaveLength(f.claim.source.objects.length + 1); expect(fingerprints).toHaveProperty(`plugins:${id(3)}`);
    expect(Object.keys(fresh.pluginSchemas).sort()).toEqual(['correlation-id', 'cors']);
  });
});
