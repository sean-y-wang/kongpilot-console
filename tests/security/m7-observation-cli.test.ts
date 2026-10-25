import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initializeObservationPolicy, parseSamplingKeys, safeObservationFailure, sampleObservationOnce, sampleObservationSequence } from '../../apps/console-api/src/infrastructure/event-observe-test';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';

const cid = 'e37a22ba-fc78-48e3-9ea5-3cfc6a2a1553', wid = '30e705c5-b4a0-40bc-b10c-a49a5f34ef1e';
const id = '4bfa1196-c881-4c0b-9b44-68c12e1b4cba', oid = '30b4fbf0-800a-4886-9d73-478b729c39c4';
const key = '713909c0-ce7f-4979-9762-e8fc4f5ef1a5';
describe('M7 test-only actual-source sampling receipts', () => {
  let directory: string;
  beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ad'.repeat(32)); directory = mkdtempSync(join(tmpdir(), 'kongos-m7-cli-unit-')); });
  afterEach(() => { vi.unstubAllEnvs(); rmSync(directory, { recursive: true, force: true }); });
  function fixture() {
    const input: any = { observationId: oid, actorType: 'system', actorId: null, clusterId: cid, workspaceId: wid,
      subjectType: 'certificates', subjectId: id, detectorKey: 'certificate.expiry.v1', transportScope: 'test-transport',
      observedNodeId: null, clusterRevision: 1, workspaceRevision: 1, configFingerprint: 'a'.repeat(64), scopeEpoch: 'b'.repeat(64),
      observedAt: new Date().toISOString(), quality: 'verified', beforeBaselineRevision: null, sourceProof: {},
      observationSafe: { kind: 'certificate_expiry', expiresAt: new Date(Date.now() + 120_000).toISOString() },
      sourceScope: { version: 1, quality: 'verified', module: 'events', nativeType: 'certificates', nativeId: id, before: null,
        after: { workspaceId: wid, physicalTags: [] } } };
    const authority: any = { observe: vi.fn().mockResolvedValue({ input, release: vi.fn() }) };
    const events: any = { enqueueObservation: vi.fn().mockResolvedValue({ observationId: oid, eventId: null, disposition: 'baseline_created' }) };
    const db: any = { one: vi.fn().mockResolvedValue(null), transaction: vi.fn(async (fn: any) => fn(db)) };
    const params = { clusterId: cid, subjectType: 'certificates' as const, subjectId: id, samplingKey: key, receiptDirectory: directory };
    return { deps: { db, authority, events, secrets: new SecretService() }, params };
  }
  it('persists the private exact original before SQL and only returns safe fields', async () => {
    const f = fixture();
    f.deps.events.enqueueObservation.mockImplementationOnce(async () => {
      const receipt = JSON.parse(readFileSync(join(directory, `${key}.json`), 'utf8'));
      expect(receipt).toMatchObject({ state: 'ready', observationId: oid, clusterId: cid });
      expect(receipt.observationHmac).toMatch(/^[a-f\d]{64}$/);
      expect(receipt).not.toHaveProperty('sourceProof');
      return { observationId: oid, eventId: null, disposition: 'baseline_created' };
    });
    const result = await sampleObservationOnce(f.deps, f.params);
    expect(result).toMatchObject({ status: 'confirmed', observationId: oid, quality: 'verified' });
    expect(result).not.toHaveProperty('observationHmac');
    expect(f.deps.authority.observe.mock.results[0].value).toBeDefined();
    expect((await f.deps.authority.observe.mock.results[0].value).release).toHaveBeenCalledWith(true);
  });
  it('never reenqueues or recaptures after an ambiguous commit, including absent and mismatched original proofs', async () => {
    const f = fixture();
    f.deps.db.transaction.mockImplementationOnce(async (fn: any) => { await fn(f.deps.db); throw Object.assign(new Error('COMMIT unknown'), { code: '08006' }); });
    expect((await sampleObservationOnce(f.deps, f.params)).status).toBe('uncertain');
    expect((await sampleObservationOnce(f.deps, f.params)).status).toBe('uncertain');
    f.deps.db.one.mockResolvedValueOnce({ cluster_id: cid, observation_hmac: '0'.repeat(64) });
    expect((await sampleObservationOnce(f.deps, f.params)).status).toBe('uncertain');
    expect(f.deps.authority.observe).toHaveBeenCalledTimes(1);
    expect(f.deps.events.enqueueObservation).toHaveBeenCalledTimes(1);
    const old = JSON.parse(readFileSync(join(directory, `${key}.json`), 'utf8'));
    f.deps.db.one.mockResolvedValueOnce({ cluster_id: cid, workspace_id: wid, observation_hmac: old.observationHmac, quality: 'verified', observed_at: new Date() });
    expect(await sampleObservationOnce(f.deps, f.params)).toMatchObject({ status: 'confirmed', reconciled: true, observationId: oid });
    expect(f.deps.authority.observe).toHaveBeenCalledTimes(1);
  });
  it('does not mint a new sample when the private receipt belongs to a different subject', async () => {
    const f = fixture(); await sampleObservationOnce(f.deps, f.params);
    await expect(sampleObservationOnce(f.deps, { ...f.params, subjectId: wid })).rejects.toThrow('OBSERVATION_TEST_RECEIPT_SCOPE_CHANGED');
    expect(f.deps.authority.observe).toHaveBeenCalledTimes(1);
  });
  it('rejects unsafe directory permissions or a linked receipt before contacting the actual source', async () => {
    const f = fixture(); chmodSync(directory, 0o755);
    await expect(sampleObservationOnce(f.deps, f.params)).rejects.toThrow('OBSERVATION_TEST_DIRECTORY_UNSAFE');
    chmodSync(directory, 0o700); symlinkSync('/dev/null', join(directory, `${key}.json`));
    await expect(sampleObservationOnce(f.deps, f.params)).rejects.toBeDefined();
    expect(f.deps.authority.observe).not.toHaveBeenCalled();
    expect(f.deps.db.transaction).not.toHaveBeenCalled();
  });
  it('keeps one live authority for distinct bounded samples and waits 30 seconds between real observations', async () => {
    const f = fixture(), wait = vi.fn().mockResolvedValue(undefined), emitted: any[] = [];
    const next = '235c726c-1885-4ba0-b698-ea439f959cc5';
    await sampleObservationSequence(f.deps, f.params, [key, next], result => emitted.push(result), wait);
    expect(f.deps.authority.observe).toHaveBeenCalledTimes(2);
    expect(wait).toHaveBeenCalledExactlyOnceWith(30_000);
    expect(emitted.map(result => result.samplingKey)).toEqual([key, next]);
    expect(emitted.every(result => result.status === 'confirmed')).toBe(true);
  });
  it('stops the entire sequence on the first unknown result, retaining each original key', async () => {
    const f = fixture(), wait = vi.fn(), emit = vi.fn();
    f.deps.db.transaction.mockImplementationOnce(async (fn: any) => { await fn(f.deps.db); throw new Error('COMMIT unknown'); });
    await sampleObservationSequence(f.deps, f.params, [key, wid], emit, wait);
    expect(wait).not.toHaveBeenCalled();
    expect(f.deps.authority.observe).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ status: 'uncertain', samplingKey: key }));
  });
  it('rejects duplicate, invalid and excessive sequence keys before starting', () => {
    for (const keys of ['', 'invalid', `${key},${key}`, [key, wid, id, oid, cid, '235c726c-1885-4ba0-b698-ea439f959cc5'].join(',')]) {
      expect(() => parseSamplingKeys(keys)).toThrow('OBSERVATION_TEST_KEYS_INVALID');
    }
  });
  it('installs the actual native policy in a CLI application context before bounded reads, with no default allow fallback', async () => {
    const execution = new KongExecutionContextService();
    const policy = new NativeKongPolicyService({} as any, new SecretService(), {} as any, execution, {} as any, {} as any);
    const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', status: 'healthy', execution_mode: 'direct' };
    await expect(execution.runEventObservationRead(cid, ['/'], () => execution.authorizeRequest(cluster, 'GET', '/', undefined, {})))
      .rejects.toMatchObject({ response: { code: 'KONG_POLICY_UNAVAILABLE' } });
    initializeObservationPolicy({ get: type => { expect(type).toBe(NativeKongPolicyService); return policy; } });
    const raw = { id, cert: 'Synthetic certificate response not a real secret' };
    await execution.runEventObservationRead(cid, ['/', `/certificates/${id}`], async () => {
      const ticket = await execution.authorizeRequest(cluster, 'GET', `/certificates/${id}`, undefined, {});
      expect(await execution.authorizeResponse(ticket, raw)).toEqual(raw);
      await expect(execution.authorizeRequest(cluster, 'DELETE', `/certificates/${id}`, undefined, {})).rejects.toMatchObject({ status: 403 });
      await expect(execution.authorizeRequest(cluster, 'GET', `/certificates/${id}`, undefined, { tags: 'owner' })).rejects.toMatchObject({ status: 403 });
    });
    await expect(execution.authorizeRequest(cluster, 'GET', '/', undefined, {})).rejects.toMatchObject({ status: 403 });
  });
  it('reports only fixed safe failure metadata while retaining an uncertain original result', async () => {
    const f = fixture();
    f.deps.authority.observe.mockRejectedValue(Object.assign(new Error('Synthetic secret and raw source must stay private'), { code: 'KONG_POLICY_UNAVAILABLE' }));
    expect(await sampleObservationOnce(f.deps, f.params)).toMatchObject({ status: 'uncertain', observationId: null,
      failureStage: 'source', failureCode: 'KONG_POLICY_UNAVAILABLE', failureKind: 'Error' });
    expect(f.deps.events.enqueueObservation).not.toHaveBeenCalled();
    expect(safeObservationFailure({ code: 'private-source-value', name: 'PrivateSecret', message: 'Synthetic secret' })).toEqual({ failureCode: null, failureKind: null });
    expect(safeObservationFailure({ getResponse() { throw Error('Synthetic secret'); } })).toEqual({ failureCode: null, failureKind: null });
    expect(safeObservationFailure(Object.assign(new Error('Never exported'), { code: '42703' }))).toEqual({ failureCode: '42703', failureKind: 'Error' });
  });
});
