import type { DbService } from '../../infrastructure/db.service';
import type { AuthUser } from '../../common/auth';
import type { WorkflowPlanV1 } from './workflow.types';
import type { WorkflowApprovalSet } from './workflow-approval.types';
import type { EntityScheduledDraft, EntityScheduledIntentEnvelopeV2, EntityScheduleClaim, EntityScheduleTerminalOutcome } from './entity-change-schedule.contract';

/** A read-only metadata view supplied only for an original opaque handle.
 * Neither this shape nor its copied principal is an HTTP identity, SID, native
 * context or permit. Root must install and verify its own scheduled namespace. */
export interface EntityScheduledAuthorityInspection {
  readonly version: 1;
  readonly claim: EntityScheduleClaim;
  readonly draft: EntityScheduledDraft;
  readonly envelope: EntityScheduledIntentEnvelopeV2;
  readonly plan: WorkflowPlanV1;
  readonly approvalSet: WorkflowApprovalSet;
  readonly principal: Readonly<AuthUser>;
  readonly permissionVersion: string;
  readonly leaseUntil: string;
  readonly authorityExpiresAt: string;
}
export type EntityScheduledAuthorityCheckpoint = 'inspect' | 'claim' | 'capture' | 'packet' | 'before-send';
/** Root returns an original private completion object and authenticates it
 * independently. A raw outcome string, SQL receipt or copied object cannot
 * become a native observation via this interface. No delegate is installed by
 * default and this module has no timer, source creator or native writer. */
export interface EntityScheduledExecutorDelegate {
  executeClaim(originalHandle: object): Promise<object>;
  verifyCompletion(originalHandle: object, originalCompletion: object, tx: DbService): Promise<EntityScheduleTerminalOutcome>;
}
