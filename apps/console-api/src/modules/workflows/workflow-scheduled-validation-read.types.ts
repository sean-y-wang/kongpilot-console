import type { DbService } from '../../infrastructure/db.service';
import type { WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { WorkflowScheduleCandidateReadInput, WorkflowScheduleCandidateBusinessPolicy } from './workflow-schedule-candidate-read.types';
import type { WorkflowScheduleCandidateReadResource } from './workflow-schedule-candidate-read.types';
import type { WorkflowScheduledValidationReadProof } from '../../infrastructure/kong/workflow-scheduled-validation-read.types';
export type { WorkflowScheduledParentAbsencePolicy } from './workflow-schedule-candidate-read.types';

/** Root-only bridge to the genuine live Context/Namespace association. The
 * getter returns its original proof reference, without invoking the full
 * business Authority verifier. Nothing here accepts an HTTP identity. */
export interface WorkflowScheduledValidationReadRunner {
  originalNamespaceProof(originalNamespaceHandle: object): Readonly<WorkflowScheduledNamespaceProof>;
  assertNamespaceLive(originalNamespaceHandle: object): void;
  run<T>(originalReadHandle: object, originalNamespaceHandle: object, fn: () => Promise<T>): Promise<T>;
}

export interface WorkflowScheduledValidationReadOptions {
  readonly role: 'executor' | 'reviewer';
  readonly userId: string;
}

/** Installed once by Root. The provider invokes this fixed GET implementation;
 * callers of the returned closure cannot supply executable callbacks. */
export interface WorkflowScheduledValidationFixedReader {
  frame(namespaceHandle: object, namespace: Readonly<WorkflowScheduledNamespaceProof>,
    read?: Readonly<{ handle: object; proof: Readonly<WorkflowScheduledValidationReadProof> }>): object;
  read(handle: object, proof: Readonly<WorkflowScheduledValidationReadProof>): Promise<WorkflowScheduledValidationFixedResult>;
}
export interface WorkflowScheduledValidationFixedResult {
  readonly observations: readonly Readonly<{ resource: Readonly<WorkflowScheduleCandidateReadResource>; value: unknown; absence?: 'sdk404' | 'parent-FK-absence' }>[];
  readonly usage: Readonly<{ calls: number; pages: number; records: number; bytes: number }>;
  readonly inferredRecords: number;
}
export type WorkflowScheduledValidationFixedGroup = (namespaceHandle: object, clusterId: string, workspaceId: string,
  resources: readonly Readonly<WorkflowScheduleCandidateReadResource>[], tx: DbService,
  options: WorkflowScheduledValidationReadOptions) => Promise<Readonly<WorkflowScheduledValidationFixedResult>>;

/** Root installs fixed compilers for actual business kinds. Scope/current
 * callbacks must use only SQL: a Kong read from either would recurse through
 * Namespace validation. The response callback sees every actual raw object
 * and must resolve workspace/parents plus the principal's current READ,
 * secret and subject-action grants; filtering rows is prohibited. */
export interface WorkflowScheduledValidationReadBusinessPolicy extends WorkflowScheduleCandidateBusinessPolicy {}


export type WorkflowScheduledValidationReadInput = WorkflowScheduleCandidateReadInput;
export type WorkflowScheduledValidationReadTransaction = DbService;
