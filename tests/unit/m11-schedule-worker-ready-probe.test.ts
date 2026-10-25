import { describe, it, expect, beforeEach } from 'vitest';
import {
  assertScheduleWorkersReadyForProbe,
  publishBusinessScheduleWorkerProbe,
  readScheduleWorkerProbe,
  resetScheduleWorkerProbeForTests,
} from '../../apps/console-api/src/infrastructure/schedule-worker-probe';
import { HealthController } from '../../apps/console-api/src/modules/health/health.controller';

describe('schedule worker ready probe', () => {
  beforeEach(() => resetScheduleWorkerProbeForTests());

  it('default (schedules off) is ready with timers stopped', () => {
    const probe = readScheduleWorkerProbe();
    expect(probe.business).toEqual({ enabled: false, timerRunning: false });
    expect(() => assertScheduleWorkersReadyForProbe(probe)).not.toThrow();
  });

  it('fail-closed when business schedules enabled but timer not running', () => {
    publishBusinessScheduleWorkerProbe({ enabled: true, timerRunning: false });
    expect(() => assertScheduleWorkersReadyForProbe()).toThrow(/BUSINESS_SCHEDULE_WORKER_NOT_READY/);
  });

  it('ready when business schedules enabled and timer running', () => {
    publishBusinessScheduleWorkerProbe({ enabled: true, timerRunning: true });
    expect(() => assertScheduleWorkersReadyForProbe()).not.toThrow();
  });

  it('health/ready returns 503 BUSINESS_SCHEDULE_WORKER_NOT_READY when opted-in without timer', async () => {
    publishBusinessScheduleWorkerProbe({ enabled: true, timerRunning: false });
    const db = { one: async () => ({}) } as any;
    const redis = { client: { ping: async () => 'PONG' } } as any;
    const health = new HealthController(db, redis);
    await expect(health.ready()).rejects.toMatchObject({
      status: 503,
      response: { code: 'BUSINESS_SCHEDULE_WORKER_NOT_READY' },
    });
  });

  it('health/ready includes schedules when storage ok and schedules off', async () => {
    const db = { one: async () => ({}) } as any;
    const redis = { client: { ping: async () => 'PONG' } } as any;
    const health = new HealthController(db, redis);
    await expect(health.ready()).resolves.toMatchObject({
      status: 'ready',
      schedules: { business: { enabled: false, timerRunning: false } },
    });
  });
});
