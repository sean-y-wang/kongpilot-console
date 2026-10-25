import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { assertScheduleWorkersReadyForProbe, publishEntityScheduleWorkerProbe, readScheduleWorkerProbe, resetScheduleWorkerProbeForTests } from '../../apps/console-api/src/infrastructure/schedule-worker-probe';
import { EntityChangeScheduleBootstrapService } from '../../apps/console-api/src/modules/workflows/entity-change-schedule-bootstrap.service';

// Browser E2E (M11 matrix) found /health/ready reporting entity:{enabled:false}
// while ENTITY_SCHEDULES_ENABLED=true and the timer was naturally executing schedules.
function bootstrap() {
  const svc = new EntityChangeScheduleBootstrapService({} as any, { installRepositoryPolicies() {}, intentSchedulingDelegate: () => ({}), acquireDueClaim: async () => null, executeClaim: async () => null } as any,
    { installSchedulingDelegate() {} } as any, { installFixedDelegate() {}, tick: async () => undefined } as any);
  svc.onModuleInit(); return svc;
}
describe('entity schedule worker readiness probe', () => {
  const prev = process.env.ENTITY_SCHEDULES_ENABLED;
  beforeEach(() => resetScheduleWorkerProbeForTests());
  afterEach(() => { if (prev === undefined) delete process.env.ENTITY_SCHEDULES_ENABLED; else process.env.ENTITY_SCHEDULES_ENABLED = prev; });

  it('publishes enabled+timerRunning when opted in, and stopped on destroy', () => {
    process.env.ENTITY_SCHEDULES_ENABLED = 'true'; const svc = bootstrap(); svc.onApplicationBootstrap();
    expect(readScheduleWorkerProbe().entity).toEqual({ enabled: true, timerRunning: true });
    expect(() => assertScheduleWorkersReadyForProbe()).not.toThrow();
    svc.onModuleDestroy(); expect(readScheduleWorkerProbe().entity).toEqual({ enabled: true, timerRunning: false });
    expect(() => assertScheduleWorkersReadyForProbe()).toThrow(/ENTITY_SCHEDULE_WORKER_NOT_READY/);
  });
  it('publishes disabled when the flag is off', () => {
    process.env.ENTITY_SCHEDULES_ENABLED = 'false'; const svc = bootstrap(); svc.onApplicationBootstrap();
    expect(readScheduleWorkerProbe().entity).toEqual({ enabled: false, timerRunning: false }); svc.onModuleDestroy();
    expect(() => assertScheduleWorkersReadyForProbe()).not.toThrow();
  });
  it('fails closed when opted in but the timer is not running', () => {
    publishEntityScheduleWorkerProbe({ enabled: true, timerRunning: false });
    expect(() => assertScheduleWorkersReadyForProbe()).toThrow(/ENTITY_SCHEDULE_WORKER_NOT_READY/);
  });
});
