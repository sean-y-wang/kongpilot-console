import type { AuthUser } from '../../common/auth';
import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { WorkflowPlanV1 } from './workflow.types';
import type { WorkflowApprovalSet } from './workflow-approval.types';
import type { WorkflowScheduleDraft as WorkflowScheduledDraft, WorkflowScheduledPlanV1, WorkflowScheduleClaim, WorkflowScheduleTerminalOutcome, WorkflowScheduleStored } from './workflow-schedule.contract';

export type WorkflowScheduledBusinessKind = 'configuration_v2' | 'portal-credential-issue' | 'portal-credential-rotate' | 'portal-credential-revoke' | 'entity-annotation' | 'control-metadata' | 'configuration-metadata' | 'governance-metadata' | 'workflow-policy-metadata' | 'iam-metadata' | 'portal-metadata' | 'portal-developer-review' | 'event-metadata';
export type WorkflowScheduledAuthorityCheckpoint = 'inspect' | 'claim' | 'capture' | 'step' | 'packet' | 'before-send';
export type WorkflowScheduledNamespaceCheckpoint = Exclude<WorkflowScheduledAuthorityCheckpoint, 'inspect'>;

/** Root installs exactly one fixed policy for each supported business kind.
 * These callbacks validate genuine server plans and current SQL permissions;
 * they never supply an Actor, SID, Context, native permit or approval result.
 * Portal requester and the accepted console executor are separate identities.
 * Configuration/Promote must retain their complete source/target origin checks.
 */
export interface WorkflowScheduledBusinessPolicy {
  assertDraft(plan: WorkflowPlanV1, draft: Readonly<WorkflowScheduledDraft>, actualActor: EntityActor, tx: DbService): Promise<void>;
  assertRequester(plan: WorkflowPlanV1, draft: Readonly<WorkflowScheduledDraft>, tx: DbService): Promise<void>;
  assertSubject(plan: WorkflowPlanV1, executorUserId: string, action: 'read' | 'write' | 'approve', checkpoint: WorkflowScheduledAuthorityCheckpoint, tx: DbService): Promise<void>;
  assertReviewer(plan: WorkflowPlanV1, reviewerUserId: string, checkpoint: WorkflowScheduledAuthorityCheckpoint, tx: DbService): Promise<void>;
  /** The fixed Root predicate observes the Service's private GET scope. No
   * request field, receipt DTO or command replay can establish that scope. */
  isReceiptRead(): boolean;
  /** Safe historical metadata only. Must verify that same private scope and
   * current HTTP identity before and after current SQL subject/read checks.
   * It never authenticates an executable subject or issues a native permit. */
  assertReceiptRead(stored: Readonly<WorkflowScheduleStored>, actualActor: EntityActor, tx: DbService): Promise<void>;
}

/** Inspection is read-only current metadata. Neither a copied principal nor
 * this shape becomes a background identity, session or native capability. */
export interface WorkflowScheduledAuthorityInspection {
  readonly version: 1;
  readonly claim: Readonly<WorkflowScheduleClaim>;
  readonly draft: Readonly<WorkflowScheduledDraft>;
  readonly plan: Readonly<WorkflowScheduledPlanV1>;
  readonly approvalSet: Readonly<WorkflowApprovalSet>;
  readonly principal: Readonly<AuthUser>;
  readonly permissionVersion: string;
  readonly leaseUntil: string;
  readonly authorityExpiresAt: string;
}

/** Only Root's genuine original completion object can certify an outcome.
 * Raw strings, receipts and copied DTOs are deliberately not accepted. The
 * completion verifier may preserve an actual acknowledgement after expiry;
 * it must never grant the next write or retry an unknown native request. */
export interface WorkflowScheduledExecutorDelegate {
  /** Authority creates this one-shot closure for the original handle. Root
   * calls it synchronously inside the genuine namespace immediately before
   * entering business execution; it is never a request DTO or native permit. */
  executeClaim(originalAuthorityHandle: object, beginBusinessCallback:(originalNamespaceHandle:object)=>void): Promise<object>;
  verifyCompletion(originalAuthorityHandle: object, originalCompletion: object, tx: DbService): Promise<WorkflowScheduleTerminalOutcome>;
}

/** Copied facts contain no authority handle or private plan/credential data. */
export interface WorkflowScheduledNamespaceClaim extends WorkflowScheduleClaim {
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly ownerId: string;
  readonly executorId: string;
  readonly ownerCredentialEpoch: string;
  readonly executorCredentialEpoch: string;
  readonly delegationId: string;
  readonly delegationVersion: 1;
  readonly delegationHmac: string;
  readonly specHmac: string;
  readonly windowStart: string;
  readonly windowEnd: string;
  readonly impactHmac: string;
  readonly subjectSealHmac: string;
}
export interface WorkflowScheduledNamespaceProof {
  readonly version: 1;
  readonly origin: 'scheduled-workflow';
  readonly actor: Readonly<AuthUser>;
  readonly sessionId: null;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly kind: WorkflowScheduledBusinessKind;
  readonly transportScope: string;
  readonly clusterRevision: number;
  readonly workspaceRevision: number;
  readonly permissionVersion: string;
  readonly credentialEpoch: string;
  readonly expiresAt: string;
  readonly claim: Readonly<WorkflowScheduledNamespaceClaim>;
  readonly workflow: Readonly<{ id: string; planRevision: number; planHash: string }>;
  readonly requester: Readonly<{ type: 'console' | 'developer'; id: string; credentialEpoch: string }>;
  readonly subjectSealHmac: string;
  readonly approvalSet: Readonly<WorkflowApprovalSet>;
}

/** The Root runner checks real Context.peek() and installs its own private
 * frame-to-original-namespace association. It must not clear inherited ALS. */
export interface WorkflowScheduledContextRunner {
  assertNoFrame(): void;
  run<T>(originalNamespaceHandle: object, fn: () => Promise<T>): Promise<T>;
}
