import type {DbService} from '../../infrastructure/db.service';
import type {EntityActor} from '../entities/entities.types';
import type {MutationImpact} from '../mutations/mutation-impact';
import type {WorkflowPlanV1} from './workflow.types';

/** Independent business schedule namespace. Importing this contract installs
 * no runtime worker, context, approval, executor or native permission. */
/** SQL041: metadata schedule kinds are typed here. Runtime allow-lists open as Root policies install. */
export type WorkflowScheduledKind='configuration_v2'|'portal-credential-issue'|'portal-credential-rotate'|'portal-credential-revoke'|'entity-annotation'|'control-metadata'|'configuration-metadata'|'governance-metadata'|'workflow-policy-metadata'|'iam-metadata'|'portal-metadata'|'portal-developer-review'|'event-metadata';
export interface WorkflowScheduleSpecV1{
  readonly version:1;readonly notBefore:string;readonly windowStart:string;readonly windowEnd:string;
  readonly executorId:string;
}
export interface WorkflowScheduleRequester{
  readonly type:'console'|'developer';readonly id:string;readonly credentialEpoch:string;
}
export interface WorkflowBusinessSubjectSealV1{
  readonly version:1;readonly driver:'configuration-apply'|'configuration-rollback'|'governance-promote'|'portal-credential-issue'|'portal-credential-rotate'|'portal-credential-revoke'|'entity-annotation'|'control-metadata'|'configuration-metadata'|'governance-metadata'|'workflow-policy-metadata'|'iam-metadata'|'portal-metadata'|'portal-developer-review'|'event-metadata';
  readonly subjectId:string;readonly materialHmac:string;readonly nativeManifestHmac:string;
  /** Read-source commitments for Promote, never a target write grant. */
  readonly sourceScopes:readonly Readonly<{clusterId:string;workspaceId:string;materialHmac:string}>[];
}
export interface WorkflowScheduleBinding{
  readonly clusterId:string;readonly workspaceId:string;readonly workflowId:string;readonly workflowPlanRevision:number;
  readonly workflowPlanHash:string;readonly basePlanHash:string;readonly kind:WorkflowScheduledKind;
  readonly subjectType:'configuration_jobs'|'portal_application_grants'|'entity_annotation_requests'|'control_metadata_requests'|'config_snapshots'|'config_snapshot_schedules'|'configuration_gitops_runs'|'governance_metadata_requests'|'workflow_policy_requests'|'iam_metadata_requests'|'portal_settings'|'portal_developers'|'portal_applications'|'portal_publications'|'portal_content'|'notification_channels'|'event_subscriptions'|'event_deliveries';readonly subjectId:string;
  readonly requester:WorkflowScheduleRequester;readonly definitionId:string;readonly definitionVersion:number;readonly policyHash:string;
  readonly subjectSeal:WorkflowBusinessSubjectSealV1;
}
export interface WorkflowExecutorDelegationV1{
  readonly version:1;readonly id:string;readonly revision:1;
  readonly clusterId:string;readonly workspaceId:string;readonly workflowId:string;readonly workflowPlanRevision:number;
  /** The pre-scheduling plan hash avoids a circular delegation/plan hash. The
   * final signed plan includes the spec and delegation HMAC commitment. */
  readonly basePlanHash:string;readonly kind:WorkflowScheduledKind;readonly subjectType:WorkflowScheduleBinding['subjectType'];readonly subjectId:string;
  readonly subjectSealHmac:string;
  readonly requester:WorkflowScheduleRequester;
  /** Console owner/executor never substitutes for the Portal developer. */
  readonly ownerId:string;readonly executorId:string;readonly ownerCredentialEpoch:string;readonly executorCredentialEpoch:string;
  readonly policyHash:string;readonly specHmac:string;readonly issuedAt:string;readonly expiresAt:string;
  readonly statement:'execute-this-exact-approved-business-workflow-with-my-current-authority';
}
/** This block is part of the immutable plan BEFORE its first approval. A
 * changed executor/window/delegation/impact requires a newly sealed plan and
 * fresh approval. It creates no scheduled execution handle. */
export interface WorkflowSchedulePlanSealV1{
  readonly version:1;readonly scheduleId:string;readonly scheduleVersion:1;readonly occurrenceId:string;
  readonly basePlanHash:string;readonly spec:WorkflowScheduleSpecV1;readonly specHmac:string;
  readonly delegationId:string;readonly delegationVersion:1;readonly delegationHmac:string;
  readonly ownerId:string;readonly ownerCredentialEpoch:string;readonly executorId:string;readonly executorCredentialEpoch:string;
  readonly requester:WorkflowScheduleRequester;readonly transportScope:string;readonly impactHmac:string;
  readonly subjectSealHmac:string;
}
export interface WorkflowScheduledPlanV1 extends WorkflowPlanV1{
  kind:WorkflowScheduledKind;subject:{type:WorkflowScheduleBinding['subjectType'];id:string};
  scheduling:WorkflowSchedulePlanSealV1;
}
export interface WorkflowScheduleDraft{
  readonly binding:WorkflowScheduleBinding;readonly scheduleId:string;readonly scheduleVersion:1;readonly occurrenceId:string;
  readonly spec:WorkflowScheduleSpecV1;readonly specHmac:string;
  readonly delegation:WorkflowExecutorDelegationV1;readonly delegationHmac:string;
  readonly transportScope:string;readonly impact:MutationImpact;readonly impactHmac:string;
}
export type WorkflowScheduleState='pending-approval'|'active'|'claimed'|'running'|'succeeded'|'partial'|'failed'|'uncertain'|'blocked'|'cancelled'|'expired';
export type WorkflowScheduleTerminalOutcome='succeeded'|'partial'|'failed'|'uncertain';
/** Returned only by the once-installed Root verifier after authenticating its
 * private completion/no-callback proof. Public outcome DTOs carry neither. */
export interface WorkflowScheduleOutcomeEvidence{
  readonly version:1;readonly provenance:'original-execution'|'callback-not-entered';readonly evidenceHmac:string;
}
export interface WorkflowScheduleActivation{
  readonly workflowId:string;readonly workflowPlanRevision:number;readonly workflowPlanHash:string;
  readonly approvalFormat:1|2;readonly approvalRequired:true;readonly approvalSetId:string|null;readonly approvalSetHmac:string|null;
}
export interface WorkflowScheduleClaim{
  readonly id:string;readonly scheduleId:string;readonly scheduleVersion:1;readonly occurrenceId:string;readonly generation:1;
  readonly workerOwnerHmac:string;readonly workflowId:string;readonly workflowPlanRevision:number;readonly workflowPlanHash:string;
  readonly issuedAt:string;readonly authorityExpiresAt:string;readonly initialLeaseUntil:string;
}
export interface WorkflowScheduleLease{
  readonly id:string;readonly claimId:string;readonly generation:1;readonly workerOwnerHmac:string;
  readonly version:number;readonly previousId:string|null;readonly leaseUntil:string;
}
export interface WorkflowScheduleReceipt{
  readonly id:string;readonly revision:number;readonly state:WorkflowScheduleState;readonly kind:WorkflowScheduledKind;
  readonly workflowId:string;readonly workflowPlanRevision:number;readonly workflowPlanHash:string;
  readonly requesterType:'console'|'developer';readonly requesterId:string;readonly executorId:string;
  readonly notBefore:string;readonly windowStart:string;readonly windowEnd:string;readonly claimId:string|null;readonly reasonCode:string|null;
  readonly nativeAuthority:false;
}
/** Server-only authenticated stored facts. It grants no delegation or native
 * execution. Public routes must authorize and project the safe receipt. */
export interface WorkflowScheduleStored{
  readonly draft:WorkflowScheduleDraft;readonly plan:WorkflowScheduledPlanV1;
  readonly progress:Readonly<{state:WorkflowScheduleState;revision:number;claimId:string|null;reasonCode:string|null}>;
  readonly activation:WorkflowScheduleActivation|null;readonly claim:WorkflowScheduleClaim|null;readonly latestLease:WorkflowScheduleLease|null;
}
/** Fixed Root callbacks authenticate genuine proofs against private registries
 * and current SQL. Repository copies/HMACs/approved-shaped DTOs never serve as
 * proof; no installed delegate means every operation remains closed. */
export interface WorkflowScheduleRepositoryDelegate{
  verifyDraft(draft:Readonly<WorkflowScheduleDraft>,actor:EntityActor,rootProof:object,tx:DbService):Promise<void>;
  verifyApproved(scheduleId:string,activation:Readonly<WorkflowScheduleActivation>,rootProof:object,tx:DbService,actualActor:EntityActor):Promise<void>;
  verifyClaim(scheduleId:string,claim:Readonly<WorkflowScheduleClaim>,rootProof:object,tx:DbService):Promise<void>;
  verifyLease(claimId:string,workerOwnerHmac:string,generation:number,leaseUntil:string,rootProof:object,tx:DbService):Promise<void>;
  verifyCancellation(scheduleId:string,actor:EntityActor,tx:DbService):Promise<void>;
  verifyPhysicalReservation(scheduleId:string,rootProof:object,tx:DbService):Promise<void>;
  verifyOutcome(claimId:string,outcome:WorkflowScheduleTerminalOutcome,rootProof:object,tx:DbService):Promise<Readonly<WorkflowScheduleOutcomeEvidence>>;
  verifyBlocked(scheduleId:string,reasonCode:string,rootProof:object,tx:DbService):Promise<void>;
  assertRead(scheduleId:string,actor:EntityActor,tx:DbService):Promise<void>;
}
export interface WorkflowScheduleWorkerDelegate{
  acquireDueClaim(scheduleId:string):Promise<object|null>;
  executeClaim(originalClaim:object):Promise<void>;
}
