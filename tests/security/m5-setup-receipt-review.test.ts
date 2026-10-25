import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { IamMutationsService } from '../../apps/console-api/src/modules/iam/iam-mutations.service';
import { MetricsScopeService } from '../../apps/console-api/src/modules/vitals/metrics-scope.service';
import { VitalsService } from '../../apps/console-api/src/modules/vitals/vitals.service';
import { defaultWorkspaceId, opsWorkspaceId, payWorkspaceId, workspaceFixture } from '../unit/workspace-test-fixture';

const cid = 'bfe12ed3-32bd-4b36-a783-81b31f4c4b1e', uid = '4b665405-644d-47af-8a63-9a1a2f0c3068';
const otherUid = 'e589c5e7-813d-42f9-bd7a-755a27631618', sourceId = '42bdc30e-9a6d-43d6-8478-d4721898d92a';
const key = '9792b39b-2be8-4d59-8d89-6ef66c0137ac', token = 't'.repeat(43);
const user = { id: uid, username: 'setup-platform', superAdmin: true }, otherUser = { id: otherUid, username: 'other-platform', superAdmin: true };
const actor = { user, idempotencyKey: key, requestId: 'setup-independent-request' };
const input = { sourceId, mode: 'collector', confirmed: true, confirm_name: 'test-cluster' };
const stepKey = (name: string) => `metrics:${createHash('sha256').update(`${key}:${name}`).digest('hex')}`;
const ledgerKey = (id: string, idempotency: string) => `${id}:${idempotency}`;
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'bc'.repeat(32))); afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** Real Vitals, IAM idempotency/encryption, current authorization, native read
 * policy, workspace and request-context services. Entity writes, metadata SQL
 * and settings are deterministic domain fixtures, not real fault injection. */
function fixture() {
  const secrets = new SecretService(), execution = new KongExecutionContextService(), ws = workspaceFixture(cid);
  const state = { generation: 1, sourceRevision: 1, permissionEpoch: 1, platform: true, settingsRevision: 1,
    lossAfterParentCommit: false, lossAfterSettingsCommit: false, unknownChild: undefined as string | undefined,
    afterCompletedLookup: undefined as (() => void) | undefined,
    lostAckLookupKey: undefined as string | undefined,
    lostAckLookupFault: undefined as 'unavailable'|'wrong-hash'|'wrong-row-id'|'nonterminal'|'remote-incomplete'|'missing-result'|undefined,
    afterLostAckLookup: undefined as (() => void) | undefined };
  const operations = new Map<string, any>(), native = new Map<string, any>(), plugins = new Map<string, any>(), audits: any[] = [], effects: any[] = [];
  const cluster = { id: cid, name: input.confirm_name, version: '1.5.1', enabled_plugins: ['prometheus'], execution_mode: 'direct', status: 'connected', revision: 1 };
  const copy = <T>(value: T): T => structuredClone(value);
  const db: any = {
    one: vi.fn(async (sql: string, p: any[] = []) => {
      if (sql.includes('FROM users')) {
        effects.push({ kind: 'current-authorization-read', actorId: p[0], platform: state.platform });
        return [uid, otherUid].includes(p[0]) ? { id: p[0], username: p[0] === uid ? user.username : otherUser.username,
          status: 'active', super_admin: state.platform, permissions_epoch: state.permissionEpoch, credential_epoch: 1 } : null;
      }
      if (sql.includes('FROM auth_sessions')) return { id: 'verified-session' };
      if (sql.includes('FROM iam_epoch')) return { version: state.permissionEpoch };
      if (sql.includes('FROM clusters')) return p[0] === cid ? copy(cluster) : null;
      if (sql.includes('FROM mutation_operations')) return p[1] === cid ? copy(native.get(ledgerKey(p[0], p[2])) ?? null) : null;
      if (sql.includes('FROM iam_operations')) {
        const value = p.length === 3 ? p[1] === cid ? operations.get(ledgerKey(p[0], p[2])) : null : operations.get(ledgerKey(p[0], p[1]));
        if (sql === 'SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2' && p[1] === state.lostAckLookupKey) {
          state.lostAckLookupKey = undefined;
          const observed = copy(value ?? null);
          effects.push({ kind: 'lost-ack-original-read', sql, parameters: copy(p), key: p[1],
            rowId: observed?.id, requestHash: observed?.request_hash, state: observed?.state,
            remoteCompleted: observed?.remote_completed, hasSealedResult: Boolean(observed?.result_secret) });
          state.afterLostAckLookup?.();
          if (state.lostAckLookupFault === 'unavailable') throw new Error('controlled original terminal read unavailable');
          if (state.lostAckLookupFault === 'wrong-hash') observed.request_hash = '0'.repeat(64);
          if (state.lostAckLookupFault === 'wrong-row-id') observed.id = randomUUID();
          if (state.lostAckLookupFault === 'nonterminal') observed.state = 'running';
          if (state.lostAckLookupFault === 'remote-incomplete') observed.remote_completed = false;
          if (state.lostAckLookupFault === 'missing-result') delete observed.result_secret;
          return observed;
        }
        if (sql.startsWith('SELECT *') && value?.idempotency_key === stepKey('settings')) state.afterCompletedLookup?.();
        return copy(value ?? null);
      }
      throw new Error('unexpected setup fixture SQL read');
    }), query: vi.fn(async (sql: string) => {
      if (sql.includes('iam_effective_grants')) return []; throw new Error('unexpected setup fixture SQL query');
    }), exec: vi.fn(async (sql: string, p: any[]) => {
      if (sql.startsWith('INSERT INTO iam_operations')) {
        operations.set(ledgerKey(p[1], p[2]), { id: p[0], actor_id: p[1], idempotency_key: p[2], request_hash: p[3], module: p[4], action: p[5],
          target_id: p[6], cluster_id: p[7], workspace_id: p[8], payload_secret: p[9], state: 'running', remote_completed: false });
        effects.push({ kind: 'iam-insert', key: p[2] }); return 1;
      }
      if (sql.startsWith('UPDATE iam_operations')) {
        const row = [...operations.values()].find(value => value.id === p[0]); if (!row) return 0;
        if (sql.includes("state='running'") && row.state !== 'running') return 0;
        if (sql.includes("state='succeeded'")) { Object.assign(row, { state: 'succeeded', remote_completed: true, result_secret: p[1], safe_result: JSON.parse(p[2]) }); effects.push({ kind: 'iam-success', key: row.idempotency_key }); }
        else Object.assign(row, { state: p[1], remote_completed: p[2], error_code: p[3], safe_result: JSON.parse(p[4]) });
        return 1;
      }
      throw new Error('unexpected setup fixture SQL write');
    }),
  };
  db.transaction = vi.fn(async (fn: any) => {
    const before = copy([...operations]), beforeAudits = audits.length;
    let value: any;
    try { value = await fn(db); } catch (error) { operations.clear(); for (const [id, row] of before) operations.set(id, row); audits.splice(beforeAudits); throw error; }
    // A transaction has committed; losing its acknowledgement must not erase
    // the succeeded row or reclassify the completed write as running.
    const parent = operations.get(ledgerKey(uid, stepKey('parent'))), settings = operations.get(ledgerKey(uid, stepKey('settings')));
    if (state.lossAfterParentCommit && parent?.state === 'succeeded') {
      state.lossAfterParentCommit = false; state.lostAckLookupKey = stepKey('parent');
      effects.push({ kind: 'commit-ack-lost', key: stepKey('parent'), rowId: parent.id });
      throw new Error('controlled parent commit acknowledgement loss');
    }
    if (state.lossAfterSettingsCommit && settings?.state === 'succeeded') {
      state.lossAfterSettingsCommit = false; state.lostAckLookupKey = stepKey('settings');
      effects.push({ kind: 'commit-ack-lost', key: stepKey('settings'), rowId: settings.id });
      throw new Error('controlled settings commit acknowledgement loss');
    }
    return value;
  });
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn(async () => undefined) };
  const audit: any = { append: vi.fn(async (event: any, tx: any) => { expect(tx).toBe(db); audits.push(copy(event)); }) };
  const kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => {
      expect(method).toBe('GET'); const ticket = await execution.authorizeRequest(cluster, method, path, undefined, {});
      const plugin = plugins.get(path.split('/').at(-1)!); if (!plugin) throw new NotFoundException(); return execution.authorizeResponse(ticket, copy(plugin));
    }), list: vi.fn(async (_cid: string, path: string, query: any) => {
      expect(path).toBe('/plugins'); const ticket = await execution.authorizeRequest(cluster, 'GET', path, undefined, query);
      const items = [...plugins.values()].map(copy); await execution.authorizeResponse(ticket, { data: items, next: null }); return { items, nextCursor: null, size: query.size };
    }),
  };
  const authz = new AuthorizationService(db, ws.resolver, kong, execution);
  new NativeKongPolicyService(db, secrets, kong, execution, authz, ws.resolver).install();
  const metadata = new IamMutationsService(db, redis, secrets, audit, authz);
  const executeMetadata = metadata.execute.bind(metadata);
  vi.spyOn(metadata, 'execute').mockImplementation((context: any, callback: any) => executeMetadata(context, async (...args: any[]) => {
    effects.push({ kind: 'metadata-callback', key: context.actor.idempotencyKey, rowId: args[1] });
    return callback(...args);
  }));
  const sources: any = { read: vi.fn(async () => ({ id: sourceId, type: 'prometheus', revision: state.sourceRevision })),
    assertCurrent: vi.fn(async (_cid: string, source: any) => { if (source.revision !== state.sourceRevision) throw new ConflictException({ code: 'METRICS_SOURCE_CHANGED' }); }) };
  const settings: any = { get: vi.fn(async () => ({ revision: state.settingsRevision, credentialGeneration: state.generation, collectorEnabled: false })),
    configure: vi.fn(async () => { state.settingsRevision++; effects.push({ kind: 'settings-configured' }); return { revision: state.settingsRevision }; }) };
  const credentials: any = { getActiveIngestCredential: vi.fn(async () => ({ token, generation: state.generation })) };
  const entities: any = { create: vi.fn(async (_cid: string, _type: string, payload: any, query: any, stepActor: any) => {
    const plugin = { ...copy(payload), id: randomUUID(), tags: ['kos-ws-default'] };
    expect(query.workspaceId).toBe(defaultWorkspaceId); plugins.set(plugin.id, plugin);
    const row = { id: randomUUID(), actor_id: stepActor.user.id, cluster_id: cid, workspace_id: query.workspaceId, entity_type: 'plugins',
      entity_id: plugin.id, action: 'create', state: state.unknownChild === payload.name ? 'uncertain' : 'succeeded', remote_completed: state.unknownChild !== payload.name };
    native.set(ledgerKey(stepActor.user.id, stepActor.idempotencyKey), row); effects.push({ kind: 'native-domain-create', name: payload.name });
    if (state.unknownChild === payload.name) throw new ServiceUnavailableException({ code: 'KONG_WRITE_RESULT_UNKNOWN', operationId: row.id, state: 'uncertain' });
    return { entity: plugin };
  }), update: vi.fn() };
  const scope = new MetricsScopeService(authz, ws.resolver, kong, execution, {} as any);
  const service = new VitalsService(scope, sources, settings, authz, db, {} as any, kong, execution, entities, ws.resolver, credentials, metadata, secrets);
  const http = <T>(acting: any, fn: () => Promise<T>) => execution.runHttp({}, async () => {
    execution.bindHttpActor(acting.user, 'verified-session'); const close = execution.captureHttpCloser(); try { return await fn(); } finally { close(); }
  });
  const run = () => http(actor, () => service.setup(cid, { workspaceId: payWorkspaceId }, input, actor));
  const receipt = (wid = payWorkspaceId, acting = actor) => http(acting, () => service.setupReceipt(cid, key, { workspaceId: wid }, acting));
  return { service, run, receipt, state, operations, native, plugins, effects, settings, entities, kong, credentials, secrets, metadata, audits };
}

describe('M5 independent real composite setup ledger and recovery', () => {
  it('persists the scoped parent marker before the first entity write and replays complete setup with no native/token/configuration writes', async () => {
    const f = fixture(), result = await f.run();
    const parentDone = f.effects.findIndex(row => row.kind === 'iam-success' && row.key === stepKey('parent'));
    expect(parentDone).toBeGreaterThanOrEqual(0); expect(parentDone).toBeLessThan(f.effects.findIndex(row => row.kind === 'native-domain-create'));
    const writes = f.entities.create.mock.calls.length, configured = f.settings.configure.mock.calls.length, tokens = f.credentials.getActiveIngestCredential.mock.calls.length;
    expect(await f.run()).toEqual(result); expect(f.entities.create).toHaveBeenCalledTimes(writes); expect(f.settings.configure).toHaveBeenCalledTimes(configured); expect(f.credentials.getActiveIngestCredential).toHaveBeenCalledTimes(tokens);
    const receipt = await f.receipt(); expect(receipt).toMatchObject({ clusterId: cid, workspaceId: payWorkspaceId, idempotencyKey: key, parentState: 'succeeded' });
    expect(receipt.steps).toHaveLength(3); expect(receipt.steps.every((row: any) => row.state === 'succeeded' && row.remoteCompleted)).toBe(true);
    expect(JSON.stringify(receipt)).not.toContain(token); expect(JSON.stringify(receipt)).not.toContain('http_endpoint');
  });
  it.each(['generation', 'source-revision'] as const)('refuses old completed setup replay after current %s changed without invoking another native step', async changed => {
    const f = fixture(); await f.run(); const writes = f.entities.create.mock.calls.length;
    if (changed === 'generation') f.state.generation++; else f.state.sourceRevision++;
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    expect(f.entities.create).toHaveBeenCalledTimes(writes); expect(f.settings.configure).toHaveBeenCalledOnce();
  });
  it.each(['generation', 'permissions', 'platform'] as const)('rejects completed lookup await-gap %s change before returning the old result', async changed => {
    const f = fixture(); await f.run(); const writes = f.entities.create.mock.calls.length, tokenCalls = f.credentials.getActiveIngestCredential.mock.calls.length;
    f.state.afterCompletedLookup = () => { if (changed === 'generation') f.state.generation++; if (changed === 'permissions') f.state.permissionEpoch++; if (changed === 'platform') f.state.platform = false; };
    await expect(f.run()).rejects.toMatchObject({ status: changed === 'generation' ? 409 : 403 });
    expect(f.entities.create).toHaveBeenCalledTimes(writes); expect(f.credentials.getActiveIngestCredential).toHaveBeenCalledTimes(tokenCalls);
  });
  it('does not disclose another actor setup or accept a foreign workspace anchor', async () => {
    const f = fixture(); await f.run();
    await expect(f.receipt(opsWorkspaceId)).rejects.toMatchObject({ response: { code: 'METRICS_SETUP_RECEIPT_SCOPE_MISMATCH' } });
    const otherActor = { ...actor, user: otherUser }, receipt = await f.receipt(payWorkspaceId, otherActor);
    expect(receipt).toMatchObject({ parentState: 'not_sent', steps: [] }); expect(receipt.result).toBeUndefined();
  });
  it('retains an unknown child and never resends it even when the parent marker succeeded and the original key is reused', async () => {
    const f = fixture(); f.state.unknownChild = 'http-log';
    await expect(f.run()).rejects.toMatchObject({ response: { setupReceipt: true, state: 'uncertain' } });
    expect((await f.receipt()).parentState).toBe('uncertain');
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'METRICS_SETUP_STEP_NOT_TERMINAL', state: 'uncertain' } });
    expect(f.entities.create).toHaveBeenCalledTimes(2); expect(f.entities.update).not.toHaveBeenCalled(); expect(f.settings.configure).not.toHaveBeenCalled();
  });
  it('reconciles a lost parent COMMIT acknowledgement by exact original terminal read and fresh authorization before the first native callback', async () => {
    const f = fixture(); f.state.lossAfterParentCommit = true;
    const result = await f.run(), parent = f.operations.get(ledgerKey(uid, stepKey('parent')));
    const acknowledgementLoss = f.effects.findIndex(row => row.kind === 'commit-ack-lost'), originalRead = f.effects.findIndex(row => row.kind === 'lost-ack-original-read');
    const authorization = f.effects.findIndex((row, index) => index > originalRead && row.kind === 'current-authorization-read'), firstNative = f.effects.findIndex(row => row.kind === 'native-domain-create');
    expect(parent).toMatchObject({ state: 'succeeded', remote_completed: true });
    expect(f.effects[originalRead]).toMatchObject({ sql: 'SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2', parameters: [uid, stepKey('parent')], rowId: parent.id, requestHash: parent.request_hash, state: 'succeeded', remoteCompleted: true, hasSealedResult: true });
    expect(originalRead).toBeGreaterThan(acknowledgementLoss); expect(authorization).toBeGreaterThan(originalRead); expect(firstNative).toBeGreaterThan(authorization);
    expect(f.effects.filter(row => row.kind === 'metadata-callback' && row.key === stepKey('parent'))).toEqual([{ kind: 'metadata-callback', key: stepKey('parent'), rowId: parent.id }]);
    expect(f.effects.filter(row => row.kind === 'iam-insert' && row.key === stepKey('parent'))).toHaveLength(1);
    expect(f.entities.create).toHaveBeenCalledTimes(2); expect(f.settings.configure).toHaveBeenCalledOnce(); expect(f.credentials.getActiveIngestCredential).toHaveBeenCalledOnce();
    expect((await f.receipt()).parentState).toBe('succeeded');
    expect(await f.run()).toEqual(result);
    expect(f.entities.create).toHaveBeenCalledTimes(2); expect(f.settings.configure).toHaveBeenCalledOnce(); expect(f.credentials.getActiveIngestCredential).toHaveBeenCalledOnce();
    expect(f.audits.some(event => ['failed', 'uncertain'].includes(event.result))).toBe(false);
  });
  it('returns the exact committed settings result after lost COMMIT acknowledgement without rerunning callback or native writes', async () => {
    const f = fixture(); f.state.lossAfterSettingsCommit = true;
    const result = await f.run(), settings = f.operations.get(ledgerKey(uid, stepKey('settings')));
    const acknowledgementLoss = f.effects.findIndex(row => row.kind === 'commit-ack-lost'), originalRead = f.effects.findIndex(row => row.kind === 'lost-ack-original-read');
    expect(originalRead).toBeGreaterThan(acknowledgementLoss);
    expect(f.effects[originalRead]).toMatchObject({ parameters: [uid, stepKey('settings')], rowId: settings.id, requestHash: settings.request_hash, state: 'succeeded', remoteCompleted: true, hasSealedResult: true });
    expect(f.effects.slice(originalRead + 1).some(row => row.kind === 'current-authorization-read')).toBe(true);
    expect(f.effects.slice(originalRead + 1).some(row => ['metadata-callback', 'settings-configured', 'native-domain-create', 'iam-insert', 'iam-success'].includes(row.kind))).toBe(false);
    expect(settings).toMatchObject({ state: 'succeeded', remote_completed: true });
    expect(result).toEqual(f.secrets.decrypt(settings.result_secret, `iam:${settings.id}:result`));
    expect(f.effects.filter(row => row.kind === 'metadata-callback' && row.key === stepKey('settings'))).toEqual([{ kind: 'metadata-callback', key: stepKey('settings'), rowId: settings.id }]);
    expect((await f.receipt()).parentState).toBe('succeeded');
    expect(await f.run()).toEqual(result); expect(result.settingsRevision).toBe(2);
    expect(f.entities.create).toHaveBeenCalledTimes(2); expect(f.settings.configure).toHaveBeenCalledOnce(); expect(f.credentials.getActiveIngestCredential).toHaveBeenCalledOnce();
    expect(f.effects.filter(row => row.kind === 'metadata-callback' && row.key === stepKey('settings'))).toHaveLength(1);
    expect(f.audits.some(event => ['failed', 'uncertain'].includes(event.result))).toBe(false);
  });
  it.each((['parent', 'settings'] as const).flatMap(stage => (['unavailable', 'wrong-hash', 'wrong-row-id', 'nonterminal', 'remote-incomplete', 'missing-result'] as const).map(fault => ({ stage, fault }))))('does not recover $stage success from $fault lost-ACK evidence or repeat its callback/native sends', async ({ stage, fault }) => {
    const f = fixture(); f.state.lostAckLookupFault = fault;
    if (stage === 'parent') f.state.lossAfterParentCommit = true; else f.state.lossAfterSettingsCommit = true;
    await expect(f.run()).rejects.toMatchObject({ status: 503, response: { code: 'IAM_RESULT_UNCERTAIN', state: 'uncertain' } });
    const committed = f.operations.get(ledgerKey(uid, stepKey(stage))), read = f.effects.findIndex(row => row.kind === 'lost-ack-original-read');
    expect(committed).toMatchObject({ state: 'succeeded', remote_completed: true });
    expect(f.effects.filter(row => row.kind === 'lost-ack-original-read')).toHaveLength(1);
    expect(f.effects.filter(row => row.kind === 'metadata-callback' && row.key === stepKey(stage))).toEqual([{ kind: 'metadata-callback', key: stepKey(stage), rowId: committed.id }]);
    expect(f.effects.filter(row => row.kind === 'iam-insert' && row.key === stepKey(stage))).toHaveLength(1);
    expect(f.effects.slice(read + 1).some(row => ['metadata-callback', 'settings-configured', 'native-domain-create', 'iam-insert', 'iam-success'].includes(row.kind))).toBe(false);
    expect(f.entities.create).toHaveBeenCalledTimes(stage === 'parent' ? 0 : 2); expect(f.entities.update).not.toHaveBeenCalled();
    expect(f.settings.configure).toHaveBeenCalledTimes(stage === 'parent' ? 0 : 1); expect(f.credentials.getActiveIngestCredential).toHaveBeenCalledTimes(stage === 'parent' ? 0 : 1);
    expect(f.audits.at(-1)).toMatchObject({ result: 'uncertain' });
  });
  it.each(['parent', 'settings'] as const)('requires fresh current authorization after exact $stage lost-ACK terminal proof', async stage => {
    const f = fixture(); f.state.afterLostAckLookup = () => { f.state.platform = false; };
    if (stage === 'parent') f.state.lossAfterParentCommit = true; else f.state.lossAfterSettingsCommit = true;
    await expect(f.run()).rejects.toMatchObject({ status: 403 });
    const committed = f.operations.get(ledgerKey(uid, stepKey(stage))), read = f.effects.findIndex(row => row.kind === 'lost-ack-original-read');
    expect(committed).toMatchObject({ state: 'succeeded', remote_completed: true });
    expect(f.effects.slice(read + 1)).toContainEqual({ kind: 'current-authorization-read', actorId: uid, platform: false });
    expect(f.effects.slice(read + 1).some(row => ['metadata-callback', 'settings-configured', 'native-domain-create', 'iam-insert', 'iam-success'].includes(row.kind))).toBe(false);
    expect(f.effects.filter(row => row.kind === 'metadata-callback' && row.key === stepKey(stage))).toHaveLength(1);
    expect(f.entities.create).toHaveBeenCalledTimes(stage === 'parent' ? 0 : 2); expect(f.settings.configure).toHaveBeenCalledTimes(stage === 'parent' ? 0 : 1);
  });
});
