import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { MutationReconciliationService } from '../../apps/console-api/src/modules/mutations/mutation-reconciliation.service';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import type { GraphNode, RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { opsWorkspaceId, payWorkspaceId, workspaceFixture } from '../unit/workspace-test-fixture';

const cid = '7530297b-364c-41d9-aeb5-9e2d119843b4';
const uid = '75ea1b46-eb04-4b56-8d1d-87b020bdb68a';
const opId = 'a4c2a47b-16c7-4b80-b945-5c008d431892';
const entryId = '28b631a4-0219-44e9-9d86-e49492d0bf89';
const sid = '9d0043e1-576e-4ad2-a397-2b9da0e6ce11';
const rid = 'b4293a82-13d2-4c4c-9184-5a207095045b';
const pid = '42ad2f93-0c30-4d6e-b7bc-9829a4579aa4';
const certId = '88079266-a478-4e6b-bf12-b58d4814daf2';
const consumerId = '8a3e4fd9-6f69-4d81-a907-c6be669021ad';
const targetId = '853f9064-e784-41af-a996-d03ce6dd6cdd';
const newTargetId = '9d96bb20-e45a-4d54-9d7f-4f2be240ebc3';
const now = Date.parse('2026-10-10T12:00:00Z');
const exactRevision = '2026-10-10 11:59:00.123456+00';
const user = { id: uid, username: 'recovery-admin', superAdmin: true };
const actor = { user, requestId: 'reconciliation-independent-request', ip: '192.0.2.10' };
const tags = ['kos-ws-pay'];
const syntheticSecret = 'SYNTHETIC-ARCHIVE-SECRET-NEVER-IN-RECEIPT';

function node(type: string, id: string, data: any, dependencies: string[] = [], affected = true, path = `/${type}/${id}`): GraphNode {
  return { key: `${type}:${id}`, type, id, path, data: { id, ...data }, dependencies, affected,
    restorable: true, restoreData: { id, ...data } };
}

function serviceGraph(): RecycleGraph {
  const certificate = node('certificates', certId, { cert: 'public-certificate', key: syntheticSecret, tags }, [], false);
  const consumer = node('consumers', consumerId, { username: 'shared-customer', tags }, [], false);
  const service = node('services', sid, { name: 'orders', host: '127.0.0.1', client_certificate: { id: certId }, tags }, [certificate.key]);
  const route = node('routes', rid, { name: 'orders-route', paths: ['/orders'], service: { id: sid }, tags }, [service.key]);
  const plugin = node('plugins', pid, { name: 'key-auth', config: { key_names: ['apikey'] }, service: { id: sid },
    route: { id: rid }, consumer: { id: consumerId }, tags }, [service.key, route.key, consumer.key]);
  return { rootKey: service.key, nodes: [plugin, route, service, consumer, certificate], complete: true,
    capturedAt: new Date(now - 120000).toISOString(), purpose: 'recycle' };
}

function targetGraph(): RecycleGraph {
  const upstream = node('upstreams', sid, { name: 'orders-pool', tags }, [], false);
  const target = node('targets', targetId, { target: '127.0.0.1:9000', weight: 100, upstream: { id: sid }, tags },
    [upstream.key], true, `/upstreams/${sid}/targets/${targetId}`);
  return { rootKey: target.key, nodes: [target, upstream], complete: true, capturedAt: new Date(now - 120000).toISOString() };
}

beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ae'.repeat(32));
  vi.spyOn(Date, 'now').mockReturnValue(now);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** The production reconciliation, authorization, native read policy, private
 * execution context, archive preview and workspace resolver run unchanged.
 * Only durable SQL storage, the physical lease and native GET responses are
 * deterministic fixtures; transactions restore their contents on failure. */
function fixture(action: 'delete' | 'restore' = 'delete', graph = serviceGraph()) {
  const secrets = new SecretService(), execution = new KongExecutionContextService(), workspaces = workspaceFixture(cid);
  const root = graph.nodes.find(item => item.key === graph.rootKey)!;
  const state = { platform: true, enabled: true, session: true, epoch: 1, missingEntry: false, ambiguousLegacy: false,
    legacy: false, casFailure: false, auditFailure: false, leaseLost: false, lockActive: false, clusterRevision: 1,
    approval: false, afterRead: undefined as undefined | ((path: string) => void), transactionHook: undefined as undefined | (() => void) };
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct', revision: 1 };
  const operation: any = { id: opId, actor_id: uid, cluster_id: cid, workspace_id: payWorkspaceId, entity_type: root.type,
    entity_id: root.id, action, state: 'uncertain', remote_completed: false, updated_at: new Date(now - 60000),
    recovery_revision: exactRevision, payload_secret: secrets.encrypt(action === 'restore' ? { entryId } : {}, `mutation:${opId}:payload`) };
  const entry: any = { id: entryId, cluster_id: cid, workspace_id: payWorkspaceId, root_type: root.type, original_id: root.id,
    root_name: root.data.name ?? root.data.username ?? root.data.target ?? root.id, mutation_id: opId, state: 'partially_deleted',
    node_count: graph.nodes.length, payload_secret: secrets.encrypt(graph, `recycle:${entryId}`), parent_id: null, credential_kind: null };
  const remote = new Map(graph.nodes.map(item => [item.path, structuredClone(item.data)]));
  const readErrors = new Map<string, Error>(), events: any[] = [], committedAudits: any[] = [], nodeStates = new Map<string, any>();
  const durableNodes = new Map(graph.nodes.map(item => [item.key, { node_key: item.key, entity_type: item.type,
    original_id: item.id, affected: item.affected, dependencies: item.dependencies,
    delete_state: action === 'delete' ? 'deleted' : 'pending', restore_state: action === 'restore' ? 'restored' : 'pending',
    restored_id: action === 'restore' ? item.id : null }]));
  const copy = <T>(value: T): T => structuredClone(value);
  const db: any = {
    one: vi.fn(async (sql: string, params: any[] = []) => {
      // These legacy fixtures model one original archive, not a composite
      // configuration batch. The new complete-graph lookup must explicitly
      // return no component instead of fabricating an unknown parent record.
      if (sql.includes('FROM configuration_recycle_components')) {
        expect(params).toEqual([cid,entryId,payWorkspaceId]);return null;
      }
      if (sql.includes('FROM users')) return state.enabled ? { id: uid, username: user.username, super_admin: state.platform,
        status: 'active', deleted_at: null, permissions_epoch: state.epoch, credential_epoch: 1 } : null;
      if (sql.includes('FROM auth_sessions')) return state.session ? { id: 'verified-session' } : null;
      if (sql.includes('FROM iam_epoch')) return { version: state.epoch };
      if (sql.includes('FROM clusters')) return params[0] === cid ? { ...cluster, revision: state.clusterRevision, execution_mode: state.approval ? 'approval' : 'direct' } : null;
      if (sql.includes('FROM mutation_operations')) return params[0] === cid && params[1] === opId ? copy(operation) : null;
      if (sql.includes('FROM recycle_entries')) {
        if (state.missingEntry || params[0] !== cid) return null;
        if (sql.includes('mutation_id=$2')) return !state.legacy && params[1] === opId ? copy(entry) : null;
        return params[1] === entry.id ? copy(entry) : null;
      }
      throw new Error('unexpected reconciliation fixture SQL read');
    }),
    query: vi.fn(async (sql: string) => {
      if (sql.includes('iam_effective_grants')) return [];
      if (sql.includes('FROM recycle_nodes')) return copy([...durableNodes.values()]);
      if (sql.includes('FROM recycle_entries') && sql.includes('mutation_id IS NULL')) {
        if (!state.legacy || state.missingEntry) return [];
        const candidate = { ...entry, mutation_id: null };
        return state.ambiguousLegacy ? [copy(candidate), { ...copy(candidate), id: certId }] : [copy(candidate)];
      }
      throw new Error('unexpected reconciliation fixture SQL query');
    }),
    exec: vi.fn(async (sql: string, p: any[]) => {
      events.push({ kind: 'db-write', sql });
      if (sql.startsWith('UPDATE mutation_operations')) {
        expect(sql).toContain("state='uncertain'");
        expect(sql).toContain('updated_at=$8::timestamptz');
        expect(p[7]).toBe(exactRevision); // Preserve PostgreSQL microseconds, not a JS Date truncation.
        if (state.casFailure) return 0;
        Object.assign(operation, { state: p[2], remote_completed: true, error_code: p[3], workspace_id: p[4],
          result_secret: p[5], safe_result: JSON.parse(p[6]) });
        return 1;
      }
      if (sql.startsWith('UPDATE recycle_entries SET workspace_id')) { entry.workspace_id = p[1]; return 1; }
      if (sql.startsWith('UPDATE recycle_entries SET state=')) { entry.state = p[1]; return 1; }
      if (sql.startsWith('UPDATE recycle_nodes')) {
        nodeStates.set(p[1], { state: p[2], restoredId: p[3] ?? null }); return 1;
      }
      throw new Error('unexpected reconciliation fixture SQL mutation');
    }),
  };
  db.transaction = vi.fn(async (fn: any) => {
    const beforeOperation = copy(operation), beforeEntry = copy(entry), beforeNodes = copy([...nodeStates]), beforeAudits = committedAudits.length;
    state.transactionHook?.();
    try { return await fn(db); }
    catch (error) {
      for (const key of Object.keys(operation)) delete operation[key]; Object.assign(operation, beforeOperation);
      for (const key of Object.keys(entry)) delete entry[key]; Object.assign(entry, beforeEntry);
      nodeStates.clear(); for (const [key, value] of beforeNodes) nodeStates.set(key, value);
      committedAudits.splice(beforeAudits); throw error;
    }
  });
  const redis: any = { withLock: vi.fn(async (key: string, fn: () => Promise<any>) => {
    events.push({ kind: 'lock', key }); state.lockActive = true;
    try { return await fn(); } finally { state.lockActive = false; }
  }), assertLeaseOwnership: vi.fn(async () => {
    if (!state.lockActive || state.leaseLost) throw new ServiceUnavailableException({ code: 'LOCK_LOST' });
  }) };
  const kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => {
      expect(method).toBe('GET'); // Any retry/recovery native write is a test failure.
      expect(state.lockActive).toBe(true);
      const ticket = await execution.authorizeRequest(cluster, method, path, undefined, {});
      events.push({ kind: 'native', method, path, purpose: execution.peek()?.purpose });
      if (readErrors.has(path)) throw readErrors.get(path);
      if (!remote.has(path)) throw new NotFoundException({ code: 'NOT_FOUND' });
      const result = await execution.authorizeResponse(ticket, copy(remote.get(path)));
      state.afterRead?.(path); return result;
    }),
    list: vi.fn(async (_cid: string, path: string, query: any, cursor?: string) => {
      expect(cursor).toBeUndefined(); expect(state.lockActive).toBe(true);
      const ticket = await execution.authorizeRequest(cluster, 'GET', path, undefined, query);
      const items = [...remote.entries()].filter(([key, value]) => key.startsWith(`${path}/`) && value?.weight > 0).map(([, value]) => copy(value));
      events.push({ kind: 'native', method: 'GET', path });
      await execution.authorizeResponse(ticket, { data: items, next: null });
      state.afterRead?.(path); return { items, nextCursor: null, size: query.size };
    }),
  };
  const authz = new AuthorizationService(db, workspaces.resolver, kong, execution);
  new NativeKongPolicyService(db, secrets, kong, execution, authz, workspaces.resolver).install();
  const audit: any = { append: vi.fn(async (event: any, tx: any) => {
    expect(tx).toBe(db);
    if (state.auditFailure) throw new Error('controlled audit persistence failure');
    committedAudits.push(copy(event));
  }) };
  const recycle = new RecycleService(db, secrets, kong, {} as any, {} as any, authz, audit, {} as any, {} as any, workspaces.resolver, execution);
  const service = new MutationReconciliationService(db, redis, secrets, kong, execution, authz, recycle, workspaces.resolver, audit);
  const setGraph = (value: RecycleGraph) => { entry.payload_secret = secrets.encrypt(value, `recycle:${entryId}`); entry.node_count = value.nodes.length; };
  const run = (body: any = { confirmed: true, confirm_name: entry.root_name }, wid = payWorkspaceId) => execution.runHttp({}, async () => {
    execution.bindHttpActor(user, 'verified-session'); const close = execution.captureHttpCloser();
    try { return await service.reconcile(cid, opId, { workspaceId: wid }, body, actor); }
    finally { close(); }
  });
  const absent = () => { for (const item of graph.nodes.filter(row => row.affected)) remote.delete(item.path); };
  const unchanged = () => {
    expect(operation.state).toBe('uncertain'); expect(operation.remote_completed).toBe(false);
    expect(committedAudits.filter(event => event.action === 'mutation.reconciled')).toEqual([]);
    expect(nodeStates.size).toBe(0); expect(events.filter(event => event.kind === 'native').every(event => event.method === 'GET')).toBe(true);
  };
  const authorityReadsOnly=()=>{
    // Current archive permission checks reread shared references. These two
    // bounded reads do not inspect any affected node or settle old evidence.
    expect(kong.request.mock.calls.map((call:any[])=>[call[0],call[1],call[2]])).toEqual([
      [cid,'GET',`/consumers/${consumerId}`],[cid,'GET',`/certificates/${certId}`],
    ]);
    expect(events.filter(event=>event.kind==='native').slice(-2).map(event=>event.purpose)).toEqual(['authorization','authorization']);
    expect(kong.list).not.toHaveBeenCalled();
  };
  return { service, run, state, operation, entry, graph, setGraph, absent, unchanged, remote, readErrors,
    events, committedAudits, nodeStates, durableNodes, db, redis, kong, authz, secrets, workspaces,authorityReadsOnly };
}

describe('M5 independent explicit graph mutation reconciliation', () => {
  it('proves complete DELETE absence with GET only, atomically settles archive/receipt and appends a safe scoped audit', async () => {
    const f = fixture(); f.absent();
    const result = await f.run();
    expect(result).toMatchObject({ operationId: opId, entryId, state: 'succeeded', observedOutcome: 'completely_applied', verifiedObjects: 3, appliedObjects: 3 });
    expect(f.operation).toMatchObject({ state: 'succeeded', remote_completed: true, error_code: 'RECONCILED_APPLIED' });
    expect(f.entry.state).toBe('deleted'); expect([...f.nodeStates.values()].map(value => value.state)).toEqual(['deleted', 'deleted', 'deleted']);
    expect(f.redis.withLock).toHaveBeenCalledWith(`mutation:${transportScopeFor('http://kong:8001')}`, expect.any(Function));
    expect(f.committedAudits).toEqual([expect.objectContaining({ actorId: uid, clusterId: cid, workspaceId: payWorkspaceId,
      entityType: 'mutation_operations', entityId: opId, action: 'mutation.reconciled', requestId: actor.requestId, ip: actor.ip, result: 'success' })]);
    expect(JSON.stringify(result)).not.toContain(syntheticSecret); expect(JSON.stringify(f.committedAudits)).not.toContain(syntheticSecret);
    expect(f.secrets.decrypt(f.operation.result_secret, `mutation:${opId}:result`)).toEqual(result);
    expect(f.events.filter(value => value.kind === 'native').every(value => value.method === 'GET')).toBe(true);
  });

  it('proves all restored configurations including shared parent references without resending a POST', async () => {
    const f = fixture('restore'), result = await f.run();
    expect(result).toMatchObject({ state: 'succeeded', observedOutcome: 'completely_applied', appliedObjects: 3 });
    expect(result.restored.map((value: any) => [value.originalId, value.restoredId])).toEqual([[sid, sid], [rid, rid], [pid, pid]]);
    expect(f.entry.state).toBe('restored'); expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
    expect(f.events.some(value => value.kind === 'native' && value.path === `/certificates/${certId}`)).toBe(true);
    expect(f.events.some(value => value.kind === 'native' && value.path === `/consumers/${consumerId}`)).toBe(true);
  });

  it.each(['delete', 'restore'] as const)('classifies fully not-applied %s as failed instead of claiming success or retrying', async action => {
    const f = fixture(action); if (action === 'restore') f.absent();
    const result = await f.run();
    expect(result).toMatchObject({ state: 'failed', observedOutcome: 'not_applied', appliedObjects: 0 });
    expect(f.operation.error_code).toBe('RECONCILED_NOT_APPLIED'); expect(result.deleted).toBeUndefined(); expect(result.restored).toBeUndefined();
    expect(f.committedAudits).toHaveLength(1);
  });

  it.each(['delete', 'restore'] as const)('settles only fully evidenced partial %s as failed and retains a recoverable partial archive', async action => {
    const f = fixture(action); f.remote.delete(`/plugins/${pid}`);
    const result = await f.run();
    expect(result).toMatchObject({ state: 'failed', observedOutcome: 'partially_applied', appliedObjects: action === 'delete' ? 1 : 2 });
    expect(f.operation.error_code).toBe('RECONCILED_PARTIAL'); expect(f.operation.remote_completed).toBe(true);
    expect(f.entry.state).toBe(action === 'delete' ? 'partially_deleted' : 'partially_restored');
    expect(f.entry.payload_secret).toBeTruthy(); expect(result.deleted).toBeUndefined(); expect(result.restored).toBeUndefined();
  });

  it('supports a restored effective Target with a new immutable UUID, using the correct Upstream collection', async () => {
    const f = fixture('restore', targetGraph()), original = f.remote.get(`/upstreams/${sid}/targets/${targetId}`);
    f.remote.delete(`/upstreams/${sid}/targets/${targetId}`); f.remote.set(`/upstreams/${sid}/targets/${newTargetId}`, { ...original, id: newTargetId });
    const result = await f.run(); expect(result.restored).toEqual([{ type: 'targets', id: targetId, originalId: targetId, restoredId: newTargetId }]);
    expect(f.kong.list).toHaveBeenCalledWith(cid, `/upstreams/${sid}/targets`, { size: 100 }, undefined, expect.any(String));
    expect(f.kong.request.mock.calls.some(call => call[2].endsWith('127.0.0.1%3A9000'))).toBe(false);
  });

  it.each(['changed-config', 'foreign-workspace', 'unexpected-503', 'unreadable-403', 'changed-reference'] as const)
    ('keeps unknown state for %s and performs no native writes or reconciliation audit', async fault => {
      const f = fixture('restore');
      if (fault === 'changed-config') f.remote.set(`/plugins/${pid}`, { ...f.remote.get(`/plugins/${pid}`), config: { key_names: ['other'] } });
      if (fault === 'foreign-workspace') f.remote.set(`/routes/${rid}`, { ...f.remote.get(`/routes/${rid}`), tags: ['kos-ws-ops'] });
      if (fault === 'unexpected-503') f.readErrors.set(`/plugins/${pid}`, new ServiceUnavailableException({ code: 'KONG_UNAVAILABLE' }));
      if (fault === 'unreadable-403') f.readErrors.set(`/plugins/${pid}`, new HttpException({ code: 'PERMISSION_DENIED' }, 403));
      if (fault === 'changed-reference') f.remote.set(`/certificates/${certId}`, { ...f.remote.get(`/certificates/${certId}`), cert: 'external-replaced-certificate' });
      await expect(f.run()).rejects.toBeDefined(); f.unchanged();
    });

  it.each(['missing-archive', 'purged-archive', 'incomplete-graph', 'migration-graph', 'missing-dependency', 'wrong-root'] as const)
    ('rejects %s before attempting proof or altering the old durable operation', async fault => {
      const f = fixture();
      if (fault === 'missing-archive') f.state.missingEntry = true;
      if (fault === 'purged-archive') f.entry.state = 'purged';
      if (fault === 'incomplete-graph') f.setGraph({ ...f.graph, complete: false } as any);
      if (fault === 'migration-graph') f.setGraph({ ...f.graph, purpose: 'migration' });
      if (fault === 'missing-dependency') f.setGraph({ ...f.graph, nodes: f.graph.nodes.filter(value => value.type !== 'certificates') });
      if (fault === 'wrong-root') f.entry.original_id = rid;
      await expect(f.run()).rejects.toBeDefined(); f.unchanged(); expect(f.kong.request).not.toHaveBeenCalled();
    });

  it.each(['non-platform', 'approval', 'running', 'too-recent', 'foreign-workspace', 'wrong-confirmation', 'forged-outcome'] as const)
    ('rejects %s at the authoritative boundary before native proof', async fault => {
      const f = fixture(); let body: any = { confirmed: true, confirm_name: f.entry.root_name }, wid = payWorkspaceId;
      if (fault === 'non-platform') f.state.platform = false; // Caller still supplies the old superAdmin=true.
      if (fault === 'approval') f.state.approval = true;
      if (fault === 'running') f.operation.state = 'running';
      if (fault === 'too-recent') f.operation.updated_at = new Date(now - 14000);
      if (fault === 'foreign-workspace') wid = opsWorkspaceId;
      if (fault === 'wrong-confirmation') body.confirm_name = 'another-name';
      if (fault === 'forged-outcome') body.state = 'succeeded';
      await expect(f.run(body, wid)).rejects.toMatchObject({ status: fault === 'non-platform' || fault === 'foreign-workspace' ? 403 : fault === 'wrong-confirmation' || fault === 'forged-outcome' ? 400 : 409 });
      expect(f.operation.remote_completed).toBe(false); expect(f.committedAudits).toEqual([]);
      if(fault==='running'||fault==='too-recent')f.authorityReadsOnly();else expect(f.kong.request).not.toHaveBeenCalled();
    });

  it.each(['permission-version', 'platform-revoked', 'session-revoked', 'account-disabled'] as const)
    ('discards complete proof if current %s changes during the final read', async changed => {
      const f = fixture('restore'); let fired = false;
      f.state.afterRead = () => { if (fired) return; fired = true; if (changed === 'permission-version') f.state.epoch++;
        if (changed === 'platform-revoked') f.state.platform = false; if (changed === 'session-revoked') f.state.session = false;
        if (changed === 'account-disabled') f.state.enabled = false; };
      await expect(f.run()).rejects.toMatchObject({ status: changed === 'session-revoked' || changed === 'account-disabled' ? 401 : 403 }); f.unchanged();
    });

  it.each(['lock-lost', 'cas-failed', 'audit-failed', 'cluster-changed', 'archive-changed'] as const)
    ('leaves receipt/archive unchanged when %s interrupts the final commit', async fault => {
      const f = fixture(); f.absent(); const originalPayload = f.entry.payload_secret;
      if (fault === 'lock-lost') f.state.leaseLost = true;
      if (fault === 'cas-failed') f.state.casFailure = true;
      if (fault === 'audit-failed') f.state.auditFailure = true;
      if (fault === 'cluster-changed') f.state.transactionHook = () => { f.state.clusterRevision++; };
      if (fault === 'archive-changed') f.state.transactionHook = () => { f.entry.payload_secret = f.secrets.encrypt({ ...f.graph, capturedAt: new Date(now).toISOString() }, `recycle:${entryId}`); };
      await expect(f.run()).rejects.toBeDefined(); f.unchanged(); expect(f.entry.state).toBe('partially_deleted');
      if (fault !== 'archive-changed') expect(f.entry.payload_secret).toBe(originalPayload);
    });

  it('uses a unique legacy NULL-mutation archive and refuses to guess between two candidates', async () => {
    const unique = fixture(); unique.state.legacy = true; unique.absent();
    expect((await unique.run()).state).toBe('succeeded');
    const ambiguous = fixture(); ambiguous.state.legacy = true; ambiguous.state.ambiguousLegacy = true; ambiguous.absent();
    await expect(ambiguous.run()).rejects.toMatchObject({ status: 409 }); ambiguous.unchanged(); expect(ambiguous.kong.request).not.toHaveBeenCalled();
  });

  it.each(['unknown-last-packet', 'all-pending', 'missing-child-state'] as const)
    ('never treats15 seconds and complete current absence as proof that %s has stopped at Kong', async fault => {
      const f = fixture(); f.absent();
      if (fault === 'unknown-last-packet') f.durableNodes.get(`services:${sid}`)!.delete_state = 'uncertain';
      if (fault === 'all-pending') for (const row of f.durableNodes.values()) row.delete_state = 'pending';
      if (fault === 'missing-child-state') f.durableNodes.delete(`plugins:${pid}`);
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'RECONCILIATION_PROOF_INCOMPLETE' } });
      f.unchanged(); f.authorityReadsOnly();
    });

  it('permits untouched pending nodes only after a durable known failure proves the executor stopped before sending them', async () => {
    const f = fixture();
    f.durableNodes.get(`plugins:${pid}`)!.delete_state = 'deleted'; f.remote.delete(`/plugins/${pid}`);
    f.durableNodes.get(`routes:${rid}`)!.delete_state = 'failed';
    f.durableNodes.get(`services:${sid}`)!.delete_state = 'pending';
    const result = await f.run(); expect(result).toMatchObject({ state: 'failed', observedOutcome: 'partially_applied', appliedObjects: 1 });
    expect(f.operation.error_code).toBe('RECONCILED_PARTIAL');
  });

  it.each(['duplicate-node-key', 'over200-nodes', 'forged-root-node-id'] as const)
    ('refuses %s before exceeding the bounded complete-graph proof', async fault => {
      const f = fixture();
      if (fault === 'duplicate-node-key') f.setGraph({ ...f.graph, nodes: [...f.graph.nodes, f.graph.nodes[0]] });
      if (fault === 'over200-nodes') f.setGraph({ ...f.graph, nodes: [...f.graph.nodes,
        ...Array.from({ length: 196 }, (_, index) => ({ ...f.graph.nodes[0], key: `plugins:bounded-${index}` }))] });
      if (fault === 'forged-root-node-id') f.setGraph({ ...f.graph, nodes: f.graph.nodes.map(row => row.key === f.graph.rootKey ? { ...row, id: rid } : row) });
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'RECONCILIATION_PROOF_INCOMPLETE' } });
      f.unchanged(); expect(f.kong.request).not.toHaveBeenCalled();
    });

  it('rechecks current archive authority for an already reconciled safe status without repeating affected-node evidence or appending another audit', async () => {
    const f = fixture(); f.absent(); await f.run(); f.kong.request.mockClear();
    expect(await f.run()).toEqual({ operationId: opId, entryId, state: 'succeeded', alreadyReconciled: true });
    f.authorityReadsOnly(); expect(f.committedAudits).toHaveLength(1);
  });
});
