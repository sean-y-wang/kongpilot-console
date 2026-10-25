import { ForbiddenException } from '@nestjs/common';

/**
 * KP-007 fail-closed contract (checkpoint P0): IDOR / cross-tenant access
 * matrix by actor · cluster · workspace · entity · original executor; single
 * worker claim; fault injection outcomes that never auto-replay or invent
 * success. Pure guards — no Kong / Redis / SQL side effects.
 */

export const KP007_ACCESS_DIMENSIONS = Object.freeze([
  'actor',
  'cluster',
  'workspace',
  'entity',
  'originalExecutor',
] as const);
export type Kp007AccessDimension = (typeof KP007_ACCESS_DIMENSIONS)[number];

/** Business schedule kinds covered by the KP-007 matrix (no live Kong). */
export const KP007_SCHEDULE_KINDS = Object.freeze([
  'configuration_v2',
  'portal-credential-issue',
  'portal-credential-rotate',
  'portal-credential-revoke',
] as const);
export type Kp007ScheduleKind = (typeof KP007_SCHEDULE_KINDS)[number];

export const isKp007ScheduleKind = (kind: string): kind is Kp007ScheduleKind =>
  (KP007_SCHEDULE_KINDS as readonly string[]).includes(kind);

/** Progress states that may remain after lease loss / restart without Root
 * completion. `claimed` means the original claim is held; never re-acquire. */
export const KP007_FAULT_HELD_STATES = Object.freeze(['failed', 'uncertain', 'claimed'] as const);
export type Kp007FaultHeldState = (typeof KP007_FAULT_HELD_STATES)[number];

/** Terminal outcomes forbidden after lease loss / mid-execution restart unless
 * a genuine Root completion proof exists. */
export const KP007_FAULT_FORBIDDEN_WITHOUT_COMPLETION = Object.freeze(['succeeded', 'partial'] as const);

export type Kp007AccessTuple = Readonly<{
  actorId: string;
  clusterId: string;
  workspaceId: string;
  entityId: string;
  originalExecutorId: string;
}>;

const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const hex64 = /^[a-f0-9]{64}$/;

const deny = (code: string) =>
  new ForbiddenException({ code, message: `${code}: KP-007 越权/故障合同拒绝：跨租户维度不一致或故障后未 fail-closed` });

function requireUuid(value: unknown, code: string): string {
  if (typeof value !== 'string' || !uuid.test(value)) throw deny(code);
  return value;
}

/** Five-dimension equality for claim/execute and cross-tenant denial. */
export function assertKp007AccessIdentity(
  sealed: Kp007AccessTuple,
  observed: Kp007AccessTuple,
): void {
  const dims: ReadonlyArray<{ key: keyof Kp007AccessTuple; dim: Kp007AccessDimension; code: string }> = [
    { key: 'actorId', dim: 'actor', code: 'KP007_ACCESS_ACTOR_MISMATCH' },
    { key: 'clusterId', dim: 'cluster', code: 'KP007_ACCESS_CLUSTER_MISMATCH' },
    { key: 'workspaceId', dim: 'workspace', code: 'KP007_ACCESS_WORKSPACE_MISMATCH' },
    { key: 'entityId', dim: 'entity', code: 'KP007_ACCESS_ENTITY_MISMATCH' },
    { key: 'originalExecutorId', dim: 'originalExecutor', code: 'KP007_ACCESS_EXECUTOR_MISMATCH' },
  ];
  for (const { key, code } of dims) {
    const left = requireUuid(sealed[key], code);
    const right = requireUuid(observed[key], code);
    if (left !== right) throw deny(code);
  }
  if (sealed.originalExecutorId !== sealed.actorId) throw deny('KP007_ACCESS_EXECUTOR_NOT_ACTOR');
  if (observed.originalExecutorId !== observed.actorId) throw deny('KP007_ACCESS_EXECUTOR_NOT_ACTOR');
}

/**
 * At most one winning claim for a schedule occurrence. Distinct
 * workerOwnerHmac values must not both be recorded as active claims.
 */
export function assertKp007SingleWorkerClaim(
  claims: ReadonlyArray<Readonly<{ workerOwnerHmac: string; scheduleId: string; generation?: number }>>,
): void {
  if (!Array.isArray(claims)) throw deny('KP007_SINGLE_CLAIM_INVALID');
  const bySchedule = new Map<string, string>();
  for (const claim of claims) {
    if (!claim || typeof claim.scheduleId !== 'string' || !uuid.test(claim.scheduleId)) {
      throw deny('KP007_SINGLE_CLAIM_INVALID');
    }
    if (typeof claim.workerOwnerHmac !== 'string' || !hex64.test(claim.workerOwnerHmac)) {
      throw deny('KP007_SINGLE_CLAIM_OWNER_INVALID');
    }
    if (claim.generation !== undefined && claim.generation !== 1) {
      throw deny('KP007_SINGLE_CLAIM_GENERATION');
    }
    const prior = bySchedule.get(claim.scheduleId);
    if (prior && prior !== claim.workerOwnerHmac) throw deny('KP007_SINGLE_CLAIM_MULTI_WORKER');
    bySchedule.set(claim.scheduleId, claim.workerOwnerHmac);
  }
}

export type Kp007FaultObservation = Readonly<{
  /** Progress after the fault. */
  progressState: string;
  /** Native / Root executor entered before the fault. */
  executorEntered: boolean;
  /** Genuine Root completion proof was verified. */
  completionVerified: boolean;
  /** A later acquireDueClaim returned a new handle (must stay false). */
  reacquired: boolean;
  /** finishClaim wrote succeeded/partial without completion. */
  finishedAsSuccess: boolean;
}>;

/** Lease loss / worker restart / unknown mid-flight must stay fail-closed. */
export function assertKp007FaultFailClosed(obs: Kp007FaultObservation): void {
  if (!obs || typeof obs !== 'object') throw deny('KP007_FAULT_OBSERVATION_INVALID');
  if (obs.reacquired === true) throw deny('KP007_FAULT_REACQUIRED');
  if (obs.finishedAsSuccess === true && obs.completionVerified !== true) {
    throw deny('KP007_FAULT_FABRICATED_SUCCESS');
  }
  if (
    (KP007_FAULT_FORBIDDEN_WITHOUT_COMPLETION as readonly string[]).includes(obs.progressState)
    && obs.completionVerified !== true
  ) {
    throw deny('KP007_FAULT_FORBIDDEN_TERMINAL');
  }
  if (obs.executorEntered === true && obs.completionVerified !== true) {
    // Mid-callback fault: claim must remain held (claimed/uncertain), not
    // silently cleared back to active for another worker.
    if (!['claimed', 'uncertain', 'failed'].includes(obs.progressState)) {
      throw deny('KP007_FAULT_CLAIM_NOT_HELD');
    }
  } else if (obs.executorEntered !== true) {
    if (!(KP007_FAULT_HELD_STATES as readonly string[]).includes(obs.progressState)
      && obs.progressState !== 'blocked' && obs.progressState !== 'expired') {
      throw deny('KP007_FAULT_PRECALLBACK_STATE');
    }
  }
}

export type Kp007WorkerTick = Readonly<{
  checked: number;
  claimed: number;
  completed: number;
  blocked: number;
  busy: boolean;
}>;

/** Worker counters stay non-negative and cannot invent completions. */
export function assertKp007WorkerTickBounds(tick: Kp007WorkerTick): void {
  if (!tick || typeof tick !== 'object') throw deny('KP007_TICK_INVALID');
  const { checked, claimed, completed, blocked, busy } = tick;
  for (const n of [checked, claimed, completed, blocked]) {
    if (!Number.isSafeInteger(n) || n < 0) throw deny('KP007_TICK_COUNTER');
  }
  if (typeof busy !== 'boolean') throw deny('KP007_TICK_BUSY');
  if (busy === true) {
    if (checked !== 0 || claimed !== 0 || completed !== 0 || blocked !== 0) {
      throw deny('KP007_TICK_BUSY_NONZERO');
    }
    return;
  }
  if (claimed > checked) throw deny('KP007_TICK_CLAIMED_OVERFLOW');
  if (completed > claimed) throw deny('KP007_TICK_COMPLETED_OVERFLOW');
  if (blocked > checked) throw deny('KP007_TICK_BLOCKED_OVERFLOW');
  // Every due id is either claimed or blocked (including execution failures).
  if (checked > 0 && claimed + blocked < checked) throw deny('KP007_TICK_UNACCOUNTED');
}
