import type { DbService } from '../../infrastructure/db.service';
import type { WorkflowKind, WorkflowPlanV1 } from './workflow.types';

export type WorkflowApprovalCheckpoint = 'vote' | 'seal' | 'claim' | 'snapshot' | 'step' | 'packet';
export interface WorkflowApprovalSelector {
  readonly users?: readonly string[];
  readonly teams?: readonly string[];
  readonly roles?: readonly string[];
}
export interface WorkflowApprovalStagePolicy {
  readonly level: number;
  readonly name: string;
  readonly mode: 'any' | 'quorum' | 'all';
  /** all uses the actual frozen candidate count, never a mutable selector count. */
  readonly threshold: number | null;
  readonly selector: WorkflowApprovalSelector;
}
export interface WorkflowApprovalPolicyV2 {
  readonly version: 2;
  readonly kind: WorkflowKind;
  readonly allowSelfApproval: false;
  readonly distinctAcrossStages: boolean;
  readonly intentTtlHours: number;
  readonly stages: readonly WorkflowApprovalStagePolicy[];
}
export interface WorkflowReviewerPolicy {
  /** Validation only. This callback cannot supply an actor, session or native permit. */
  verifyCurrent(reviewerId: string, plan: WorkflowPlanV1, tx: DbService, checkpoint: WorkflowApprovalCheckpoint): Promise<void>;
}
/** A once-installed internal reader, never an HTTP option or Native permit.
 * Only the real scheduled Authority's private eligibility invocation can
 * supply a live one-shot token. The caller must still fully authorize every
 * returned reviewer before publishing an Authority inspection. */
export interface WorkflowScheduledApprovalFactsVerifier {
  enter(original: object, plan: WorkflowPlanV1, checkpoint: WorkflowApprovalCheckpoint, tx: DbService): Promise<void>;
  leave(original: object, plan: WorkflowPlanV1, checkpoint: WorkflowApprovalCheckpoint, tx: DbService): Promise<void>;
}
export type WorkflowScheduledApprovalFactsReader = (original: object, plan: WorkflowPlanV1,
  input: Readonly<{ checkpoint: WorkflowApprovalCheckpoint }>, tx: DbService) => Promise<WorkflowApprovalSet>;
/** Bootstrap-only canonical SQL policy for the separate genuine configuration
 * Namespace reader. It is not subject/Native eligibility or a public mode. */
export interface WorkflowScheduledConfigurationCanonicalSqlPolicy {
  verifyCurrent(reviewerId: string, plan: WorkflowPlanV1, tx: DbService): Promise<void>;
}
export interface WorkflowApprovalSet {
  readonly format: 1 | 2;
  readonly policyHash: string;
  readonly setId: string | null;
  readonly setHmac: string | null;
  readonly reviewers: readonly Readonly<{ approvalId: string; userId: string; level: number; candidateVersion: number | null }>[];
}
export interface WorkflowCandidateProvenance {
  readonly kind: 'user' | 'team' | 'role';
  readonly selectorId: string;
  readonly bindingId?: string;
  readonly bindingSource?: 'user' | 'team';
  readonly teamId?: string;
}
export interface WorkflowFrozenCandidate {
  readonly userId: string;
  readonly credentialEpoch: string;
  readonly provenance: readonly WorkflowCandidateProvenance[];
}
export interface WorkflowCandidateManifest {
  readonly version: 1;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly workflowId: string;
  readonly planRevision: number;
  readonly planHash: string;
  readonly definitionId: string;
  readonly definitionVersion: number;
  readonly policyHash: string;
  readonly candidateVersion: number;
  readonly stages: readonly Readonly<{ level: number; mode: 'any' | 'quorum' | 'all'; threshold: number; candidates: readonly WorkflowFrozenCandidate[] }>[];
}
