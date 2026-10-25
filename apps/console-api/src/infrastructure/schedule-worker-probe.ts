/** Process-local readiness facts for schedule workers. Workers publish; /health/ready reads.
 * No secrets. Fail-closed: enabled===true requires timerRunning===true. */
export type ScheduleWorkerProbeState = { enabled: boolean; timerRunning: boolean };

const state: {
  business: ScheduleWorkerProbeState;
  entity: ScheduleWorkerProbeState;
} = {
  business: { enabled: false, timerRunning: false },
  entity: { enabled: false, timerRunning: false },
};

export function publishBusinessScheduleWorkerProbe(next: ScheduleWorkerProbeState): void {
  state.business = { enabled: !!next.enabled, timerRunning: !!next.timerRunning };
}

export function publishEntityScheduleWorkerProbe(next: ScheduleWorkerProbeState): void {
  state.entity = { enabled: !!next.enabled, timerRunning: !!next.timerRunning };
}

export function readScheduleWorkerProbe(): { business: ScheduleWorkerProbeState; entity: ScheduleWorkerProbeState } {
  return {
    business: { ...state.business },
    entity: { ...state.entity },
  };
}

export function assertScheduleWorkersReadyForProbe(probe = readScheduleWorkerProbe()): void {
  // Both workers install an interval timer when opted in; each must prove it.
  if (probe.business.enabled && !probe.business.timerRunning) {
    const err = new Error('BUSINESS_SCHEDULE_WORKER_NOT_READY');
    (err as Error & { code?: string }).code = 'BUSINESS_SCHEDULE_WORKER_NOT_READY';
    throw err;
  }
  if (probe.entity.enabled && !probe.entity.timerRunning) {
    const err = new Error('ENTITY_SCHEDULE_WORKER_NOT_READY');
    (err as Error & { code?: string }).code = 'ENTITY_SCHEDULE_WORKER_NOT_READY';
    throw err;
  }
}

/** Test-only reset; production code must not call this. */
export function resetScheduleWorkerProbeForTests(): void {
  state.business = { enabled: false, timerRunning: false };
  state.entity = { enabled: false, timerRunning: false };
}
