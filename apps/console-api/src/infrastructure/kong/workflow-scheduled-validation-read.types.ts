import type { AuthUser } from '../../common/auth';
import type { WorkflowScheduledNamespaceProof } from '../../modules/workflows/workflow-scheduled-authority.types';
import type { WorkflowScheduleCandidateReadResource, WorkflowScheduleCandidateReadScope, WorkflowScheduleCandidateRequest } from '../../modules/workflows/workflow-schedule-candidate-read.types';

/** A projection returned only by the fixed private provider. It is neither a
 * claim handle, an HTTP identity nor native mutation authority. Namespace
 * identity is the original proof reference, never a copied SQL projection. */
export interface WorkflowScheduledValidationReadProof {
  readonly version: 1;
  readonly origin: 'workflow-scheduled-validation-read';
  readonly readOnly: true;
  readonly actor: Readonly<AuthUser>;
  readonly sessionId: null;
  readonly role: 'executor' | 'reviewer';
  readonly namespace: Readonly<WorkflowScheduledNamespaceProof>;
  readonly expiresAt: string;
  readonly scope: Readonly<WorkflowScheduleCandidateReadScope>;
  readonly registries: readonly Readonly<{ clusterId: string; workspaceId: string; transportScope: string; clusterRevision: number; workspaceRevision: number; endpointHmac: string }>[];
}

/** Installed once by Root. All methods validate original WeakMap identities
 * and current SQL principal/claim/window/lease/grants. They must not recurse
 * through the full business Namespace verifier or an ordinary SID policy.
 * The provider owns cursor continuity, mandatory EOF and every-row READ and
 * secret authorization. A failed request/response poisons its whole capsule. */
export interface WorkflowScheduledValidationReadPolicy {
  verifyHandle(originalReadHandle: object, originalNamespaceHandle: object, originalNamespaceProof: Readonly<WorkflowScheduledNamespaceProof>): Promise<Readonly<WorkflowScheduledValidationReadProof>>;
  assertLive(originalReadHandle: object): void;
  authorizeRequest(originalReadHandle: object, request: WorkflowScheduleCandidateRequest): Promise<object>;
  verifyRequest(originalRequestToken: object): Promise<Readonly<WorkflowScheduledValidationReadProof>>;
  authorizeResponse(originalRequestToken: object, response: unknown, originalAbsenceObservation?: 200 | object): Promise<unknown>;
}

/** The exact resource is fixed by the private provider, not by caller paths. */
export type WorkflowScheduledValidationReadResource = WorkflowScheduleCandidateReadResource;
