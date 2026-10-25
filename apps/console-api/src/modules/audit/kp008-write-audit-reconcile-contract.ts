import { ForbiddenException } from '@nestjs/common';

/**
 * KP-008 fail-closed contract (checkpoint P0): each success / reject / fail
 * business request reconciles 1:1 with audit, diff, ticket (workflow), and
 * delivery (outbox) records. Historical omissions stay retained only with an
 * explicit explanation event — never silently dropped. Pure guards; no SQL /
 * Kong / Redis side effects.
 */

export const KP008_BUSINESS_OUTCOMES = Object.freeze([
  'success',
  'rejected',
  'failed',
] as const);
export type Kp008BusinessOutcome = (typeof KP008_BUSINESS_OUTCOMES)[number];

/** Critical business-schedule writes that must carry ticket + delivery on success. */
export const KP008_BUSINESS_SCHEDULE_ACTIONS = Object.freeze([
  'workflow.business-schedule.author.command',
  'workflow.business-schedule.activate.command',
  'workflow.business-schedule.cancel.command',
] as const);
export type Kp008BusinessScheduleAction =
  (typeof KP008_BUSINESS_SCHEDULE_ACTIONS)[number];

export const isKp008BusinessScheduleAction = (
  action: string,
): action is Kp008BusinessScheduleAction =>
  (KP008_BUSINESS_SCHEDULE_ACTIONS as readonly string[]).includes(action);

/** Audit / diff / ticket / delivery dimensions of the 1:1 tuple. */
export const KP008_RECONCILE_DIMENSIONS = Object.freeze([
  'audit',
  'diff',
  'ticket',
  'delivery',
] as const);
export type Kp008ReconcileDimension =
  (typeof KP008_RECONCILE_DIMENSIONS)[number];

export type Kp008BusinessRequest = Readonly<{
  requestId: string;
  outcome: Kp008BusinessOutcome;
  actorId: string | null;
  clusterId: string | null;
  workspaceId: string | null;
  workflowId: string | null;
  action: string;
  /** Success business-schedule (and similar) writes require a workflow ticket. */
  requiresWorkflow: boolean;
  /** Success writes that mapAuditEvent fans out require an outbox delivery link. */
  requiresDelivery: boolean;
  /** Success writes with a durable after-state require a json_patch diff. */
  requiresDiff: boolean;
}>;

export type Kp008AuditRecord = Readonly<{
  id: string;
  requestId: string;
  result: string;
  action: string;
  actorId: string | null;
  clusterId: string | null;
  workspaceId: string | null;
  workflowId: string | null;
  before: unknown;
  after: unknown;
  jsonPatch: unknown;
  eventHash?: string | null;
  sequence?: string | null;
}>;

export type Kp008DeliveryLink = Readonly<{
  eventId: string;
  auditEventId: string;
  outboxPresent: boolean;
}>;

export type Kp008HistoricalGap = Readonly<{
  requestId: string;
  missing: ReadonlyArray<Kp008ReconcileDimension>;
  retainedExplanationEventId: string;
  explanationKind: 'historical_omission_retained';
}>;

export type Kp008ReconcileGap = Readonly<{
  requestId: string;
  missing: ReadonlyArray<Kp008ReconcileDimension>;
  detail?: string;
}>;

export type Kp008ReconcileResult = Readonly<{
  matched: ReadonlyArray<{
    requestId: string;
    auditId: string;
    workflowId: string | null;
    deliveryEventId: string | null;
  }>;
  gaps: ReadonlyArray<Kp008ReconcileGap>;
}>;

const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const hex64 = /^[a-f0-9]{64}$/;

const deny = (code: string) =>
  new ForbiddenException({
    code,
    message: `${code}: KP-008 审计对账合同拒绝：业务请求与审计/diff/工单/投递未 1:1 闭合`,
  });

function requireUuid(value: unknown, code: string): string {
  if (typeof value !== 'string' || !uuid.test(value)) throw deny(code);
  return value;
}

/** Expected outbox mapping for KP-008 business-schedule success (kept in sync
 * with mapAuditEvent via unit tests). */
export function kp008MapBusinessScheduleAudit(
  action: string,
  result: string,
): { eventType: string; phase: 'terminal'; title: string } | null {
  if (!isKp008BusinessScheduleAction(action)) return null;
  if (result !== 'success') return null;
  if (action === 'workflow.business-schedule.cancel.command') {
    return {
      eventType: 'workflow.cancelled',
      phase: 'terminal',
      title: '业务定时工单已取消',
    };
  }
  return {
    eventType: 'workflow.executed',
    phase: 'terminal',
    title: '业务定时工单已落账',
  };
}

/** Build the expected request tuple for a sealed business-schedule success. */
export function kp008BusinessScheduleSuccessRequest(input: {
  requestId: string;
  actorId: string;
  clusterId: string;
  workspaceId: string;
  workflowId: string;
  action: string;
}): Kp008BusinessRequest {
  if (!isKp008BusinessScheduleAction(input.action)) {
    throw deny('KP008_ACTION_NOT_CRITICAL');
  }
  return Object.freeze({
    requestId: requireUuid(input.requestId, 'KP008_REQUEST_ID_INVALID'),
    outcome: 'success' as const,
    actorId: requireUuid(input.actorId, 'KP008_ACTOR_INVALID'),
    clusterId: requireUuid(input.clusterId, 'KP008_CLUSTER_INVALID'),
    workspaceId: requireUuid(input.workspaceId, 'KP008_WORKSPACE_INVALID'),
    workflowId: requireUuid(input.workflowId, 'KP008_TICKET_INVALID'),
    action: input.action,
    requiresWorkflow: true,
    requiresDelivery: true,
    requiresDiff: true,
  });
}

/** Reject / fail HTTP-boundary facts: audit required; no ticket / delivery fanout. */
export function kp008RejectOrFailRequest(input: {
  requestId: string;
  outcome: 'rejected' | 'failed';
  actorId: string | null;
  action: string;
  result: string;
}): Kp008BusinessRequest {
  if (!['rejected', 'failed'].includes(input.outcome)) {
    throw deny('KP008_OUTCOME_INVALID');
  }
  if (!/^http\.request\.(POST|PUT|PATCH|DELETE)\.failed$/.test(input.action)) {
    throw deny('KP008_REJECT_ACTION_INVALID');
  }
  if (!/^http_([45]\d\d|disconnected)$/.test(input.result)) {
    throw deny('KP008_REJECT_RESULT_INVALID');
  }
  return Object.freeze({
    requestId: requireUuid(input.requestId, 'KP008_REQUEST_ID_INVALID'),
    outcome: input.outcome,
    actorId:
      input.actorId == null
        ? null
        : requireUuid(input.actorId, 'KP008_ACTOR_INVALID'),
    clusterId: null,
    workspaceId: null,
    workflowId: null,
    action: input.action,
    requiresWorkflow: false,
    requiresDelivery: false,
    requiresDiff: false,
  });
}

function outcomeMatchesResult(
  outcome: Kp008BusinessOutcome,
  result: string,
): boolean {
  if (outcome === 'success') return result === 'success' || result === 'succeeded';
  if (outcome === 'rejected') {
    return (
      result === 'http_400' ||
      result === 'http_403' ||
      result === 'http_409' ||
      result === 'rejected'
    );
  }
  return (
    result === 'failed' ||
    result === 'http_500' ||
    result === 'http_503' ||
    result === 'http_disconnected' ||
    result === 'uncertain'
  );
}

/** 1:1 request ↔ audit identity (requestId, action, outcome↔result, actor/scope). */
export function assertKp008AuditMatchesRequest(
  request: Kp008BusinessRequest,
  audit: Kp008AuditRecord,
): void {
  requireUuid(request.requestId, 'KP008_REQUEST_ID_INVALID');
  requireUuid(audit.id, 'KP008_AUDIT_ID_INVALID');
  if (audit.requestId !== request.requestId) throw deny('KP008_AUDIT_REQUEST_MISMATCH');
  if (audit.action !== request.action) throw deny('KP008_AUDIT_ACTION_MISMATCH');
  if (!outcomeMatchesResult(request.outcome, audit.result)) {
    throw deny('KP008_AUDIT_RESULT_MISMATCH');
  }
  if (request.actorId != null && audit.actorId !== request.actorId) {
    throw deny('KP008_AUDIT_ACTOR_MISMATCH');
  }
  if (request.clusterId != null && audit.clusterId !== request.clusterId) {
    throw deny('KP008_AUDIT_CLUSTER_MISMATCH');
  }
  if (request.workspaceId != null && audit.workspaceId !== request.workspaceId) {
    throw deny('KP008_AUDIT_WORKSPACE_MISMATCH');
  }
}

/** Diff present for success writes; reject/fail must not invent a success after. */
export function assertKp008DiffConsistent(
  request: Kp008BusinessRequest,
  audit: Kp008AuditRecord,
): void {
  if (request.requiresDiff) {
    if (!Array.isArray(audit.jsonPatch)) throw deny('KP008_DIFF_MISSING');
    if (audit.after == null) throw deny('KP008_DIFF_AFTER_MISSING');
  }
  if (request.outcome !== 'success' && audit.result === 'success') {
    throw deny('KP008_DIFF_SUCCESS_ON_REJECT');
  }
}

/** Ticket (workflowId) bound when the write requires one. */
export function assertKp008TicketBound(
  request: Kp008BusinessRequest,
  audit: Kp008AuditRecord,
): void {
  if (!request.requiresWorkflow) {
    if (request.workflowId != null) throw deny('KP008_TICKET_UNEXPECTED');
    return;
  }
  const ticket = requireUuid(request.workflowId, 'KP008_TICKET_MISSING');
  if (audit.workflowId !== ticket) throw deny('KP008_TICKET_MISMATCH');
}

/** Delivery / outbox link when mapAuditEvent fans out the success write. */
export function assertKp008DeliveryBound(
  request: Kp008BusinessRequest,
  audit: Kp008AuditRecord,
  delivery: Kp008DeliveryLink | null,
): void {
  if (!request.requiresDelivery) {
    if (delivery != null && delivery.outboxPresent) {
      throw deny('KP008_DELIVERY_UNEXPECTED');
    }
    return;
  }
  if (!delivery) throw deny('KP008_DELIVERY_MISSING');
  requireUuid(delivery.eventId, 'KP008_DELIVERY_EVENT_INVALID');
  if (delivery.auditEventId !== audit.id) throw deny('KP008_DELIVERY_AUDIT_MISMATCH');
  if (!delivery.outboxPresent) throw deny('KP008_DELIVERY_OUTBOX_MISSING');
}

/**
 * Reconcile a closed set of critical business requests against audits and
 * delivery links. Every request must match exactly one audit; gaps are listed
 * (never silently ignored). Extra audits for the same requestId are gaps.
 */
export function reconcileKp008(
  requests: ReadonlyArray<Kp008BusinessRequest>,
  audits: ReadonlyArray<Kp008AuditRecord>,
  deliveries: ReadonlyArray<Kp008DeliveryLink>,
): Kp008ReconcileResult {
  const byRequest = new Map<string, Kp008AuditRecord[]>();
  for (const audit of audits) {
    const list = byRequest.get(audit.requestId) ?? [];
    list.push(audit);
    byRequest.set(audit.requestId, list);
  }
  const deliveryByAudit = new Map<string, Kp008DeliveryLink>();
  for (const d of deliveries) {
    if (deliveryByAudit.has(d.auditEventId)) {
      // Ambiguous delivery fanout is itself a gap surface for the caller.
      deliveryByAudit.set(d.auditEventId, {
        ...d,
        outboxPresent: false,
      });
    } else {
      deliveryByAudit.set(d.auditEventId, d);
    }
  }

  const matched: Array<{
    requestId: string;
    auditId: string;
    workflowId: string | null;
    deliveryEventId: string | null;
  }> = [];
  const gaps: Kp008ReconcileGap[] = [];
  const seen = new Set<string>();

  for (const request of requests) {
    if (seen.has(request.requestId)) {
      gaps.push({
        requestId: request.requestId,
        missing: ['audit'],
        detail: 'KP008_DUPLICATE_REQUEST',
      });
      continue;
    }
    seen.add(request.requestId);
    const candidates = byRequest.get(request.requestId) ?? [];
    if (candidates.length === 0) {
      const missing: Kp008ReconcileDimension[] = ['audit'];
      if (request.requiresDiff) missing.push('diff');
      if (request.requiresWorkflow) missing.push('ticket');
      if (request.requiresDelivery) missing.push('delivery');
      gaps.push({ requestId: request.requestId, missing });
      continue;
    }
    if (candidates.length !== 1) {
      gaps.push({
        requestId: request.requestId,
        missing: ['audit'],
        detail: 'KP008_AUDIT_NOT_ONE_TO_ONE',
      });
      continue;
    }
    const audit = candidates[0]!;
    const missing: Kp008ReconcileDimension[] = [];
    try {
      assertKp008AuditMatchesRequest(request, audit);
    } catch {
      missing.push('audit');
    }
    try {
      assertKp008DiffConsistent(request, audit);
    } catch {
      missing.push('diff');
    }
    try {
      assertKp008TicketBound(request, audit);
    } catch {
      missing.push('ticket');
    }
    const delivery = deliveryByAudit.get(audit.id) ?? null;
    try {
      assertKp008DeliveryBound(request, audit, delivery);
    } catch {
      missing.push('delivery');
    }
    if (missing.length) {
      gaps.push({ requestId: request.requestId, missing });
      continue;
    }
    matched.push({
      requestId: request.requestId,
      auditId: audit.id,
      workflowId: audit.workflowId,
      deliveryEventId: delivery?.eventId ?? null,
    });
  }

  return Object.freeze({
    matched: Object.freeze(matched),
    gaps: Object.freeze(gaps),
  });
}

/** Fail-closed: any unreconciled gap aborts (unless covered by retained history). */
export function assertKp008FailClosed(
  result: Kp008ReconcileResult,
  retained: ReadonlyArray<Kp008HistoricalGap> = [],
): void {
  if (!result.gaps.length) return;
  const retainedIds = new Set(retained.map((g) => g.requestId));
  for (const gap of retained) assertKp008HistoricalGapRetained(gap);
  for (const gap of result.gaps) {
    if (!retainedIds.has(gap.requestId)) {
      throw deny('KP008_RECONCILE_GAP');
    }
    const retainedGap = retained.find((g) => g.requestId === gap.requestId)!;
    for (const dim of gap.missing) {
      if (!retainedGap.missing.includes(dim)) throw deny('KP008_RECONCILE_GAP');
    }
  }
}

/** Historical omissions must stay retained with an explicit explanation event. */
export function assertKp008HistoricalGapRetained(gap: Kp008HistoricalGap): void {
  requireUuid(gap.requestId, 'KP008_HISTORICAL_REQUEST_INVALID');
  requireUuid(
    gap.retainedExplanationEventId,
    'KP008_HISTORICAL_EXPLANATION_INVALID',
  );
  if (gap.explanationKind !== 'historical_omission_retained') {
    throw deny('KP008_HISTORICAL_KIND_INVALID');
  }
  if (!gap.missing.length) throw deny('KP008_HISTORICAL_GAP_EMPTY');
  for (const dim of gap.missing) {
    if (!(KP008_RECONCILE_DIMENSIONS as readonly string[]).includes(dim)) {
      throw deny('KP008_HISTORICAL_DIMENSION_INVALID');
    }
  }
}

/**
 * Post-append seal for business-schedule success writes: requestId, ticket,
 * immutable audit receipt identity, and expected delivery mapping must all be
 * present before the command returns.
 */
export function assertKp008BusinessWriteSealed(input: {
  requestId: string;
  actorId: string;
  clusterId: string;
  workspaceId: string;
  workflowId: string;
  action: string;
  auditReceiptId: string;
  auditEventHash: string;
  auditSequence: string;
  after: unknown;
}): void {
  const request = kp008BusinessScheduleSuccessRequest(input);
  requireUuid(input.auditReceiptId, 'KP008_AUDIT_RECEIPT_INVALID');
  if (typeof input.auditEventHash !== 'string' || !hex64.test(input.auditEventHash)) {
    throw deny('KP008_AUDIT_HASH_INVALID');
  }
  if (typeof input.auditSequence !== 'string' || !/^\d+$/.test(input.auditSequence)) {
    throw deny('KP008_AUDIT_SEQUENCE_INVALID');
  }
  if (input.after == null) throw deny('KP008_DIFF_AFTER_MISSING');
  if (kp008MapBusinessScheduleAudit(request.action, 'success') == null) {
    throw deny('KP008_DELIVERY_MAPPING_MISSING');
  }
  // Seal the 1:1 identity tuple the reconciler will later prove against reads.
  assertKp008AuditMatchesRequest(request, {
    id: input.auditReceiptId,
    requestId: input.requestId,
    result: 'success',
    action: input.action,
    actorId: input.actorId,
    clusterId: input.clusterId,
    workspaceId: input.workspaceId,
    workflowId: input.workflowId,
    before: null,
    after: input.after,
    jsonPatch: [{ op: 'add', path: '', value: input.after }],
    eventHash: input.auditEventHash,
    sequence: input.auditSequence,
  });
  assertKp008TicketBound(request, {
    id: input.auditReceiptId,
    requestId: input.requestId,
    result: 'success',
    action: input.action,
    actorId: input.actorId,
    clusterId: input.clusterId,
    workspaceId: input.workspaceId,
    workflowId: input.workflowId,
    before: null,
    after: input.after,
    jsonPatch: [],
  });
}
