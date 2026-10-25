import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import {
  KP008_BUSINESS_SCHEDULE_ACTIONS,
  KP008_RECONCILE_DIMENSIONS,
  assertKp008AuditMatchesRequest,
  assertKp008BusinessWriteSealed,
  assertKp008DeliveryBound,
  assertKp008DiffConsistent,
  assertKp008FailClosed,
  assertKp008HistoricalGapRetained,
  assertKp008TicketBound,
  isKp008BusinessScheduleAction,
  kp008BusinessScheduleSuccessRequest,
  kp008MapBusinessScheduleAudit,
  kp008RejectOrFailRequest,
  reconcileKp008,
  type Kp008AuditRecord,
  type Kp008BusinessRequest,
  type Kp008DeliveryLink,
} from '../../apps/console-api/src/modules/audit/kp008-write-audit-reconcile-contract';
import { mapAuditEvent } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';

const uuid = () => randomUUID();
const hash = () => 'a'.repeat(64);

function codeOf(err: unknown): string {
  if (err instanceof ForbiddenException) {
    const body = err.getResponse() as { code?: string };
    return body?.code ?? 'NO_CODE';
  }
  return String(err);
}

function expectDeny(fn: () => unknown, code: string) {
  try {
    fn();
    throw new Error(`expected ${code}`);
  } catch (e) {
    expect(codeOf(e)).toBe(code);
  }
}

function successAudit(
  request: Kp008BusinessRequest,
  overrides: Partial<Kp008AuditRecord> = {},
): Kp008AuditRecord {
  const after = { scheduleId: uuid(), sealed: true };
  return {
    id: uuid(),
    requestId: request.requestId,
    result: 'success',
    action: request.action,
    actorId: request.actorId,
    clusterId: request.clusterId,
    workspaceId: request.workspaceId,
    workflowId: request.workflowId,
    before: null,
    after,
    jsonPatch: [{ op: 'add', path: '', value: after }],
    eventHash: hash(),
    sequence: '1',
    ...overrides,
  };
}

function deliveryFor(audit: Kp008AuditRecord): Kp008DeliveryLink {
  return {
    eventId: uuid(),
    auditEventId: audit.id,
    outboxPresent: true,
  };
}

describe('KP-008 business-schedule action catalog and outbox mapping sync', () => {
  it('covers author / activate / cancel only', () => {
    expect([...KP008_BUSINESS_SCHEDULE_ACTIONS]).toEqual([
      'workflow.business-schedule.author.command',
      'workflow.business-schedule.activate.command',
      'workflow.business-schedule.cancel.command',
    ]);
    expect(isKp008BusinessScheduleAction('workflow.submit')).toBe(false);
  });

  it.each([...KP008_BUSINESS_SCHEDULE_ACTIONS])(
    'mapAuditEvent and kp008Map stay in sync for %s success',
    (action) => {
      const expected = kp008MapBusinessScheduleAudit(action, 'success');
      expect(expected).not.toBeNull();
      expect(mapAuditEvent(action, 'success')).toEqual(expected);
    },
  );

  it.each([...KP008_BUSINESS_SCHEDULE_ACTIONS])(
    'does not fan out delivery for non-success %s',
    (action) => {
      for (const result of ['failed', 'rejected', 'http_403', 'uncertain']) {
        expect(kp008MapBusinessScheduleAudit(action, result)).toBeNull();
        expect(mapAuditEvent(action, result)).toBeNull();
      }
    },
  );

  it('cancel maps to workflow.cancelled; author/activate to workflow.executed', () => {
    expect(kp008MapBusinessScheduleAudit(
      'workflow.business-schedule.cancel.command',
      'success',
    )?.eventType).toBe('workflow.cancelled');
    expect(kp008MapBusinessScheduleAudit(
      'workflow.business-schedule.author.command',
      'success',
    )?.eventType).toBe('workflow.executed');
  });
});

describe('KP-008 success request ↔ audit ↔ diff ↔ ticket ↔ delivery 1:1', () => {
  it.each([...KP008_BUSINESS_SCHEDULE_ACTIONS])(
    'reconciles a complete %s success tuple with no gaps',
    (action) => {
      const request = kp008BusinessScheduleSuccessRequest({
        requestId: uuid(),
        actorId: uuid(),
        clusterId: uuid(),
        workspaceId: uuid(),
        workflowId: uuid(),
        action,
      });
      const audit = successAudit(request);
      const delivery = deliveryFor(audit);
      assertKp008AuditMatchesRequest(request, audit);
      assertKp008DiffConsistent(request, audit);
      assertKp008TicketBound(request, audit);
      assertKp008DeliveryBound(request, audit, delivery);
      const result = reconcileKp008([request], [audit], [delivery]);
      expect(result.gaps).toEqual([]);
      expect(result.matched).toHaveLength(1);
      expect(result.matched[0]).toMatchObject({
        requestId: request.requestId,
        auditId: audit.id,
        workflowId: request.workflowId,
        deliveryEventId: delivery.eventId,
      });
      assertKp008FailClosed(result);
    },
  );

  it('fail-closes when audit is missing', () => {
    const request = kp008BusinessScheduleSuccessRequest({
      requestId: uuid(),
      actorId: uuid(),
      clusterId: uuid(),
      workspaceId: uuid(),
      workflowId: uuid(),
      action: 'workflow.business-schedule.author.command',
    });
    const result = reconcileKp008([request], [], []);
    expect(result.gaps[0]?.missing).toEqual(
      expect.arrayContaining(['audit', 'diff', 'ticket', 'delivery']),
    );
    expectDeny(() => assertKp008FailClosed(result), 'KP008_RECONCILE_GAP');
  });

  it('fail-closes when ticket / diff / delivery dimensions drift', () => {
    const request = kp008BusinessScheduleSuccessRequest({
      requestId: uuid(),
      actorId: uuid(),
      clusterId: uuid(),
      workspaceId: uuid(),
      workflowId: uuid(),
      action: 'workflow.business-schedule.activate.command',
    });
    const wrongTicket = successAudit(request, { workflowId: uuid() });
    expectDeny(
      () => assertKp008TicketBound(request, wrongTicket),
      'KP008_TICKET_MISMATCH',
    );
    const noDiff = successAudit(request, { jsonPatch: null, after: null });
    expectDeny(
      () => assertKp008DiffConsistent(request, noDiff),
      'KP008_DIFF_MISSING',
    );
    const audit = successAudit(request);
    expectDeny(
      () => assertKp008DeliveryBound(request, audit, null),
      'KP008_DELIVERY_MISSING',
    );
    expectDeny(
      () =>
        assertKp008DeliveryBound(request, audit, {
          eventId: uuid(),
          auditEventId: audit.id,
          outboxPresent: false,
        }),
      'KP008_DELIVERY_OUTBOX_MISSING',
    );
  });

  it('fail-closes duplicate audits for one requestId (not 1:1)', () => {
    const request = kp008BusinessScheduleSuccessRequest({
      requestId: uuid(),
      actorId: uuid(),
      clusterId: uuid(),
      workspaceId: uuid(),
      workflowId: uuid(),
      action: 'workflow.business-schedule.cancel.command',
    });
    const a1 = successAudit(request);
    const a2 = successAudit(request);
    const result = reconcileKp008(
      [request],
      [a1, a2],
      [deliveryFor(a1), deliveryFor(a2)],
    );
    expect(result.gaps[0]?.detail).toBe('KP008_AUDIT_NOT_ONE_TO_ONE');
    expectDeny(() => assertKp008FailClosed(result), 'KP008_RECONCILE_GAP');
  });

  it('seals post-append business write identity', () => {
    const after = { scheduleId: uuid(), commandCompleted: true };
    assertKp008BusinessWriteSealed({
      requestId: uuid(),
      actorId: uuid(),
      clusterId: uuid(),
      workspaceId: uuid(),
      workflowId: uuid(),
      action: 'workflow.business-schedule.author.command',
      auditReceiptId: uuid(),
      auditEventHash: hash(),
      auditSequence: '42',
      after,
    });
    expectDeny(
      () =>
        assertKp008BusinessWriteSealed({
          requestId: uuid(),
          actorId: uuid(),
          clusterId: uuid(),
          workspaceId: uuid(),
          workflowId: uuid(),
          action: 'workflow.business-schedule.author.command',
          auditReceiptId: uuid(),
          auditEventHash: 'not-a-hash',
          auditSequence: '1',
          after,
        }),
      'KP008_AUDIT_HASH_INVALID',
    );
    expectDeny(
      () =>
        assertKp008BusinessWriteSealed({
          requestId: uuid(),
          actorId: uuid(),
          clusterId: uuid(),
          workspaceId: uuid(),
          workflowId: uuid(),
          action: 'workflow.submit',
          auditReceiptId: uuid(),
          auditEventHash: hash(),
          auditSequence: '1',
          after,
        }),
      'KP008_ACTION_NOT_CRITICAL',
    );
  });
});

describe('KP-008 reject / fail business requests 1:1 with audit (no ticket/delivery)', () => {
  it.each([
    ['rejected', 'http_403', 'http.request.POST.failed'],
    ['rejected', 'http_400', 'http.request.PUT.failed'],
    ['rejected', 'http_409', 'http.request.PATCH.failed'],
    ['failed', 'http_500', 'http.request.DELETE.failed'],
    ['failed', 'http_503', 'http.request.POST.failed'],
    ['failed', 'http_disconnected', 'http.request.POST.failed'],
  ] as const)(
    'reconciles %s / %s without inventing delivery',
    (outcome, result, action) => {
      const request = kp008RejectOrFailRequest({
        requestId: uuid(),
        outcome,
        actorId: uuid(),
        action,
        result,
      });
      expect(request.requiresWorkflow).toBe(false);
      expect(request.requiresDelivery).toBe(false);
      expect(request.requiresDiff).toBe(false);
      expect(mapAuditEvent(action, result)).toBeNull();
      const audit: Kp008AuditRecord = {
        id: uuid(),
        requestId: request.requestId,
        result,
        action,
        actorId: request.actorId,
        clusterId: null,
        workspaceId: null,
        workflowId: null,
        before: null,
        after: null,
        jsonPatch: [],
      };
      assertKp008AuditMatchesRequest(request, audit);
      assertKp008DiffConsistent(request, audit);
      assertKp008TicketBound(request, audit);
      assertKp008DeliveryBound(request, audit, null);
      const reconciled = reconcileKp008([request], [audit], []);
      expect(reconciled.gaps).toEqual([]);
      assertKp008FailClosed(reconciled);
    },
  );

  it('rejects inventing a success delivery on a failed HTTP fact', () => {
    const request = kp008RejectOrFailRequest({
      requestId: uuid(),
      outcome: 'failed',
      actorId: uuid(),
      action: 'http.request.POST.failed',
      result: 'http_500',
    });
    const audit: Kp008AuditRecord = {
      id: uuid(),
      requestId: request.requestId,
      result: 'http_500',
      action: request.action,
      actorId: request.actorId,
      clusterId: null,
      workspaceId: null,
      workflowId: null,
      before: null,
      after: null,
      jsonPatch: [],
    };
    expectDeny(
      () =>
        assertKp008DeliveryBound(request, audit, {
          eventId: uuid(),
          auditEventId: audit.id,
          outboxPresent: true,
        }),
      'KP008_DELIVERY_UNEXPECTED',
    );
  });

  it('fail-closes when reject has no audit row', () => {
    const request = kp008RejectOrFailRequest({
      requestId: uuid(),
      outcome: 'rejected',
      actorId: null,
      action: 'http.request.POST.failed',
      result: 'http_403',
    });
    const result = reconcileKp008([request], [], []);
    expect(result.gaps[0]?.missing).toEqual(['audit']);
    expectDeny(() => assertKp008FailClosed(result), 'KP008_RECONCILE_GAP');
  });
});

describe('KP-008 mixed success+reject+fail set and historical gaps', () => {
  it('reconciles a mixed critical set 1:1', () => {
    const success = kp008BusinessScheduleSuccessRequest({
      requestId: uuid(),
      actorId: uuid(),
      clusterId: uuid(),
      workspaceId: uuid(),
      workflowId: uuid(),
      action: 'workflow.business-schedule.author.command',
    });
    const rejected = kp008RejectOrFailRequest({
      requestId: uuid(),
      outcome: 'rejected',
      actorId: uuid(),
      action: 'http.request.POST.failed',
      result: 'http_403',
    });
    const failed = kp008RejectOrFailRequest({
      requestId: uuid(),
      outcome: 'failed',
      actorId: uuid(),
      action: 'http.request.POST.failed',
      result: 'http_500',
    });
    const successAuditRow = successAudit(success);
    const rejectedAudit: Kp008AuditRecord = {
      id: uuid(),
      requestId: rejected.requestId,
      result: 'http_403',
      action: rejected.action,
      actorId: rejected.actorId,
      clusterId: null,
      workspaceId: null,
      workflowId: null,
      before: null,
      after: null,
      jsonPatch: [],
    };
    const failedAudit: Kp008AuditRecord = {
      id: uuid(),
      requestId: failed.requestId,
      result: 'http_500',
      action: failed.action,
      actorId: failed.actorId,
      clusterId: null,
      workspaceId: null,
      workflowId: null,
      before: null,
      after: null,
      jsonPatch: [],
    };
    const result = reconcileKp008(
      [success, rejected, failed],
      [successAuditRow, rejectedAudit, failedAudit],
      [deliveryFor(successAuditRow)],
    );
    expect(result.gaps).toEqual([]);
    expect(result.matched).toHaveLength(3);
    assertKp008FailClosed(result);
  });

  it('retains historical omissions only with an explanation event', () => {
    const requestId = uuid();
    const gap = {
      requestId,
      missing: ['delivery'] as const,
      retainedExplanationEventId: uuid(),
      explanationKind: 'historical_omission_retained' as const,
    };
    assertKp008HistoricalGapRetained(gap);
    expect([...KP008_RECONCILE_DIMENSIONS]).toEqual([
      'audit',
      'diff',
      'ticket',
      'delivery',
    ]);
    expectDeny(
      () =>
        assertKp008HistoricalGapRetained({
          ...gap,
          missing: [],
        }),
      'KP008_HISTORICAL_GAP_EMPTY',
    );
    const request = kp008BusinessScheduleSuccessRequest({
      requestId,
      actorId: uuid(),
      clusterId: uuid(),
      workspaceId: uuid(),
      workflowId: uuid(),
      action: 'workflow.business-schedule.author.command',
    });
    const audit = successAudit(request);
    // Delivery intentionally missing — covered only via retained history.
    const result = reconcileKp008([request], [audit], []);
    expect(result.gaps[0]?.missing).toContain('delivery');
    expectDeny(() => assertKp008FailClosed(result), 'KP008_RECONCILE_GAP');
    assertKp008FailClosed(result, [gap]);
    // Retained explanation that does not cover the actual missing dim still fails.
    expectDeny(
      () =>
        assertKp008FailClosed(result, [
          {
            requestId,
            missing: ['ticket'],
            retainedExplanationEventId: uuid(),
            explanationKind: 'historical_omission_retained',
          },
        ]),
      'KP008_RECONCILE_GAP',
    );
  });
});
