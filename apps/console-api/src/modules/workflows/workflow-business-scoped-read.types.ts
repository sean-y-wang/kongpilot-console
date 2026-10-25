import type { WorkflowBusinessMaterial } from './workflow-business-material.types';
import type { WorkflowScheduleCandidateReadInput, WorkflowScheduleCandidateReadScope } from './workflow-schedule-candidate-read.types';
import type { PermissionAction } from '../../common/authorization.types';

/** Compiled exclusively from authenticated material, not caller proposals. */
export interface WorkflowBusinessScopedDescriptor {
  readonly type: string; readonly id: string; readonly parentId?: string; readonly credentialKind?: string;
  readonly workspaceId: string; readonly body: any; readonly before: any; readonly action: PermissionAction; readonly create: boolean;
  /** Kong1.5 target weight updates append a distinct stored target UUID. */
  readonly appendAllocatedId?: string;
}
export interface WorkflowBusinessScopedSubject {
  readonly entityType: string; readonly entity: any; readonly clusterId: string; readonly workspaceId: string;
}
/** Once-installed SQL/material policy. Scope locators or an HTTP marker never
 * confer READ, secret access, a write Namespace or Native permission. */
export interface WorkflowBusinessScopedReadBridge {
  assertSubject(input: WorkflowScheduleCandidateReadInput, material: Readonly<WorkflowBusinessMaterial>,
    descriptors: readonly Readonly<WorkflowBusinessScopedDescriptor>[], observed?: readonly Readonly<WorkflowBusinessScopedSubject>[]): Promise<void>;
  resolveReadScope(input: WorkflowScheduleCandidateReadInput, material: Readonly<WorkflowBusinessMaterial>,
    descriptors: readonly Readonly<WorkflowBusinessScopedDescriptor>[], originalScope: Readonly<WorkflowScheduleCandidateReadScope>): Promise<Readonly<WorkflowScheduleCandidateReadScope>>;
}
