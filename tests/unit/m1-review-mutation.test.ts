import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { BadRequestException, ForbiddenException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MutationService, type MutationContext } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { workspaceFixture } from './workspace-test-fixture';

const clusterId = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const actor = { id: 'a35313a2-9968-4818-9f31-7b3066ce1728', username: 'admin', superAdmin: true };
function context(extra: Partial<MutationContext> = {}): MutationContext {
  return { clusterId, actor, entityType: 'services', action: 'create', payload: { host: 'example.test' }, idempotencyKey: 'independent-review', ...extra };
}

function harness() {
  const records = new Map<string, any>();
  const cluster = { id: clusterId, version: '1.5.1', execution_mode: 'direct' };
  const db = { one: vi.fn(async (sql: string, params: any[]) => {
    if (sql.includes('FROM clusters')) return cluster;
    if (sql.includes('FROM mutation_operations')) return records.get(params[1]) ?? null;
    throw new Error('Unexpected SQL read');
  }), exec: vi.fn(async (sql: string, params: any[]) => {
    if (sql.includes('INSERT INTO mutation_operations')) {
      const [id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret,workspace_id,transport_scope,impact] = params;
      records.set(idempotency_key, { id, cluster_id, actor_id, action, idempotency_key, request_hash, workflow_id, request_id, entity_type, entity_id, before_secret, payload_secret,workspace_id,transport_scope,impact:JSON.parse(impact), state: 'running' });
      return 1;
    }
    const record = [...records.values()].find(item => item.id === params[0]);
    if (!record) throw new Error('Unexpected SQL mutation');
    if (sql.includes('remote_started=true')) record.remote_started = true;
    else if (sql.includes('remote_completed=true')) Object.assign(record, { remote_completed: true, entity_id: params[1], result_secret: params[2] });
    else if (sql.includes("state='succeeded'")) Object.assign(record, { state: 'succeeded', safe_result: JSON.parse(params[1]) });
    else if (sql.includes("state='uncertain'")) Object.assign(record, { state: 'uncertain', error_code: 'LOCK_LOST' });
    else if (sql.includes('SET state=$2')) Object.assign(record, { state: params[1], error_code: params[2], safe_result: JSON.parse(params[3]) });
    else throw new Error('Unexpected SQL update');
    return 1;
  }), query:vi.fn(async()=>[...records.values()].filter(row=>['running','uncertain'].includes(row.state))),transaction: vi.fn() };
  db.transaction.mockImplementation(async fn => fn(db));
  const redis = { withLock: vi.fn(async (_key, fn) => fn()) };
  const secrets = new SecretService();
  const audit = { append: vi.fn().mockResolvedValue(undefined) };
  const kong = { transportScope:vi.fn(async()=>clusterId),request: vi.fn().mockResolvedValue({ id: 'remote', name: 'readback', host: 'example.test' }) };
  const authz = { isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true),assertCluster: vi.fn().mockResolvedValue(undefined), assertEntity: vi.fn().mockResolvedValue(undefined) };
  const service = new MutationService(db as any, redis as any, secrets, audit as any, kong as any, authz as any,workspaceFixture(clusterId).resolver,executionFixture());
  return { service, records, cluster, db, redis, secrets, audit, kong, authz };
}

describe('Independent M1 mutation integrity review', () => {
  beforeEach(() => {vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'be'.repeat(32));vi.stubEnv('APP_SECRET','independent-mutation-test-key-32-characters');});
  afterEach(() => vi.unstubAllEnvs());

  it('durably records requested state before the callback and replays success without another remote write', async () => {
    const { service, records, audit, kong } = harness();
    const fn = vi.fn(async () => {
      expect(records.get('independent-review').state).toBe('running');
      expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'create.requested', result: 'pending' }), expect.any(Object));
      return { id: 'remote', host: 'example.test' };
    });
    expect(await service.execute(context(), fn)).toEqual({ id: 'remote', host: 'example.test' });
    expect(await service.execute(context(), fn)).toEqual({ id: 'remote', host: 'example.test' });
    expect(fn).toHaveBeenCalledTimes(1);
    expect(kong.request).toHaveBeenCalledTimes(2); // Readback plus current-scope recheck on cached replay.
    expect(kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'create', after: { id: 'remote', name: 'readback', host: 'example.test' }, result: 'success' }), expect.any(Object));
  });

  it('encrypts raw result and payload, exposes only a redacted durable summary', async () => {
    const { service, records, secrets } = harness();
    const raw = 'private-test-secret-never-log';
    await service.execute(context({ entityType: 'credentials', parentId: 'consumer', credentialKind: 'key-auth', payload: { key: raw } }), async () => ({ id: 'credential', key: raw }));
    const operation = records.get('independent-review');
    expect(JSON.stringify(operation)).not.toContain(raw);
    expect(secrets.decrypt(operation.result_secret, `mutation:${operation.id}:result`)).toEqual({ id: 'credential', key: raw });
    expect(operation.safe_result.key).toMatch(/^\[REDACTED:/);
  });

  it('rejects key reuse for a different payload or actor without executing either callback again', async () => {
    const { service } = harness();
    const fn = vi.fn().mockResolvedValue({ id: 'remote' });
    await service.execute(context(), fn);
    await expect(service.execute(context({ payload: { host: 'changed.test' } }), fn)).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    await expect(service.execute(context({ actor: { ...actor, id: 'ccba7e66-e5be-4d91-a0a4-9b761acdaffc' } }), fn)).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('marks a network failure uncertain and refuses retry under the same key', async () => {
    const { service, records, audit } = harness();
    const fn = vi.fn().mockRejectedValue(new ServiceUnavailableException({ code: 'KONG_WRITE_RESULT_UNKNOWN', message: 'response lost' }));
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ status: 503 });
    expect(records.get('independent-review').state).toBe('uncertain');
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ response: { code: 'MUTATION_RESULT_UNCERTAIN' } });
    expect(fn).toHaveBeenCalledTimes(1);
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'create', result: 'uncertain' }), expect.any(Object));
  });

  it('keeps a rejected remote validation attempt failed and never automatically retries it', async () => {
    const { service, records } = harness();
    const fn = vi.fn().mockRejectedValue(new BadRequestException({ code: 'KONG_VALIDATION_ERROR', message: 'invalid' }));
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ status: 400 });
    expect(records.get('independent-review').state).toBe('failed');
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ response: { code: 'MUTATION_ALREADY_ATTEMPTED' } });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('detects a stale object after acquiring the cluster lock and before any durable mutation/write', async () => {
    const { service, kong, redis, records } = harness();
    const before = { id: 'remote', host: 'old.test' };
    kong.request.mockImplementation(async () => {
      expect(redis.withLock).toHaveBeenCalledTimes(1);
      return { ...before, host: 'changed-by-other-client.test' };
    });
    const fn = vi.fn();
    await expect(service.execute(context({ action: 'update', entityId: 'remote', before, payload: { host: 'ours.test' } }), fn)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGED' } });
    expect(fn).not.toHaveBeenCalled();
    expect(records.size).toBe(0);
  });

  it('fails closed on missing entity authorization before locking or reading Kong', async () => {
    const { service, authz, redis, kong } = harness();
    authz.assertEntity.mockRejectedValue(new ForbiddenException());
    const fn = vi.fn();
    await expect(service.execute(context({ before: { id: 'remote' } }), fn)).rejects.toMatchObject({ status: 403 });
    expect(redis.withLock).not.toHaveBeenCalled();
    expect(kong.request).not.toHaveBeenCalled();
    expect(fn).not.toHaveBeenCalled();
  });

  it('does not write remotely when recording the initial operation/audit fails', async () => {
    const { service, audit } = harness();
    audit.append.mockRejectedValue(new Error('console store unavailable'));
    const fn = vi.fn();
    await expect(service.execute(context(), fn)).rejects.toThrow('console store unavailable');
    expect(fn).not.toHaveBeenCalled();
  });

  it('marks a completed remote callback uncertain when readback fails, even with a 404 readback', async () => {
    const { service, kong, records } = harness();
    kong.request.mockRejectedValue(new NotFoundException());
    const fn = vi.fn().mockResolvedValue({ id: 'remote' });
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ status: 503, response:{code:'MUTATION_RESULT_UNCERTAIN'} });
    expect(records.get('independent-review')).toMatchObject({ state: 'uncertain', remote_completed: true });
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ response: { code: 'MUTATION_RESULT_UNCERTAIN' } });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('changes a completed operation to uncertain if the distributed lease is lost after callback completion', async () => {
    const { service, redis, records, audit } = harness();
    redis.withLock.mockImplementation(async (_key, fn) => { await fn(); throw new ServiceUnavailableException({ code: 'LOCK_LOST', message: 'lease lost' }); });
    const fn = vi.fn().mockResolvedValue({ id: 'remote' });
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    expect(records.get('independent-review')).toMatchObject({ state: 'uncertain', error_code: 'LOCK_LOST' });
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ result: 'uncertain_lock_lost' }));
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('blocks approval mode before either a remote request or callback', async () => {
    const { service, cluster, kong, audit } = harness();
    cluster.execution_mode = 'approval';
    const fn = vi.fn();
    await expect(service.execute(context(), fn)).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(kong.request).not.toHaveBeenCalled();
    expect(fn).not.toHaveBeenCalled();
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ result: 'blocked_approval_required' }));
  });

  it('replays a deleted object only with matching actor, object alias, hash and historical entity authorization', async () => {
    const { service, authz, kong } = harness();
    const before = { id: 'remote', name: 'original', host: 'example.test' };
    kong.request.mockResolvedValue(before);
    const deletion = context({ action: 'delete', entityId: 'remote', before, payload: { confirmed: true, confirm_name: 'original' } });
    await service.execute(deletion, async () => ({ entryId: 'archive', state: 'deleted' }));
    expect(await service.completed({ ...deletion, before: undefined, entityId: 'original' })).toEqual({ entryId: 'archive', state: 'deleted' });
    await expect(service.completed({ ...deletion, before: undefined, entityId: 'other' })).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
    authz.assertEntity.mockRejectedValue(new ForbiddenException());
    await expect(service.completed({ ...deletion, before: undefined })).rejects.toMatchObject({ status: 403 });
  });
});
