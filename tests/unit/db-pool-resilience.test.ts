import 'reflect-metadata';
import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';

const mocks = vi.hoisted(() => ({ query: vi.fn(), connect: vi.fn(), end: vi.fn() }));
vi.mock('pg', async () => {
  const { EventEmitter } = await import('node:events');
  return { Pool: class extends EventEmitter {
    query = mocks.query;
    connect = mocks.connect;
    end = mocks.end;
  } };
});

import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { HealthController } from '../../apps/console-api/src/modules/health/health.controller';
import { resetScheduleWorkerProbeForTests } from '../../apps/console-api/src/infrastructure/schedule-worker-probe';

describe('database background connection resilience', () => {
  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://fixture:fixture-password@fixture.invalid/fixture');
    vi.clearAllMocks();
    mocks.query.mockResolvedValue({ rows: [{ healthy: true }], rowCount: 1 });
  });
  afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

  it('consumes repeated idle pool errors using only a fixed safe structured log', async () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const db = new DbService();
    const pool = (db as unknown as { pool: EventEmitter }).pool;
    const error = Object.assign(new Error('fixture-password fixture.invalid SELECT sensitive'), {
      host: 'fixture.invalid', password: 'fixture-password', code: 'secret-in-code',
      detail: 'credential detail', stack: 'private connection stack',
    });
    expect(pool.listenerCount('error')).toBe(1);
    expect(() => pool.emit('error', error, { password: 'client-secret' })).not.toThrow();
    expect(() => pool.emit('error', error)).not.toThrow();
    expect(warn.mock.calls).toEqual([
      [{ component: 'postgres-pool', code: 'DB_POOL_IDLE_CONNECTION_ERROR' }],
      [{ component: 'postgres-pool', code: 'DB_POOL_IDLE_CONNECTION_ERROR' }],
    ]);
    expect(mocks.query).not.toHaveBeenCalled();
    expect(mocks.end).not.toHaveBeenCalled();
    await expect(db.one('SELECT 1')).resolves.toEqual({ healthy: true });
  });

  it.each(['query', 'one', 'exec'] as const)('preserves the original %s request rejection', async method => {
    const db = new DbService(), failure = new Error('request connection unavailable');
    mocks.query.mockRejectedValueOnce(failure);
    await expect(db[method]('SELECT $1', ['fixture'])).rejects.toBe(failure);
    expect(mocks.query).toHaveBeenCalledWith('SELECT $1', ['fixture']);
  });

  it('preserves connection acquisition failures without starting transaction work', async () => {
    const db = new DbService(), failure = new Error('connection acquisition unavailable');
    const work = vi.fn();
    mocks.connect.mockRejectedValueOnce(failure);
    await expect(db.transaction(work)).rejects.toBe(failure);
    expect(work).not.toHaveBeenCalled();
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it('reports unavailable readiness while DB queries fail and recovers on a later successful query', async () => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const db = new DbService(), pool = (db as unknown as { pool: EventEmitter }).pool;
    const redis = { client: { ping: vi.fn().mockResolvedValue('PONG') } };
    const health = new HealthController(db, redis as any);
    pool.emit('error', new Error('idle connection terminated'));
    mocks.query.mockRejectedValueOnce(new Error('database unavailable'));
    await expect(health.ready()).rejects.toMatchObject({
      status: 503, response: { code: 'NOT_READY', message: '控制台存储暂不可用' },
    });
    expect(redis.client.ping).not.toHaveBeenCalled();
    await expect(health.ready()).resolves.toMatchObject({ status: 'ready', schedules: { business: { enabled: false, timerRunning: false }, entity: { enabled: false, timerRunning: false } } });
    expect(mocks.query.mock.calls).toEqual([['SELECT 1', []], ['SELECT 1', []]]);
    expect(redis.client.ping).toHaveBeenCalledOnce();
  });
});
