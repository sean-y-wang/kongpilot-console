import { BadRequestException } from '@nestjs/common';
import type { WorkflowPlanV1, WorkflowStep } from './workflow.types';

export interface WorkflowPolicyMetadataPayload {
  intentId: string; definitionId: string; operation: 'version' | 'archive' | 'restore'; payloadHmac: string;
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i, digest = /^[a-f0-9]{64}$/;
/** Definition administration is one fixed zero-native metadata operation. */
export function assertWorkflowPolicyMetadataPlan(plan: WorkflowPlanV1): WorkflowStep {
  const invalid = (): never => { throw new BadRequestException({ code: 'WORKFLOW_POLICY_METADATA_PLAN_INVALID' }); };
  if (!plan || (plan.kind as string) !== 'workflow-policy-metadata' || (plan.subject.type as string) !== 'workflow_policy_requests' || plan.requester.type !== 'console'
    || plan.executionMode !== 'approval' || !plan.approvalRequired || plan.steps.length !== 1 || plan.prerequisites.length || plan.generated !== undefined || plan.migration !== undefined) invalid();
  const step = plan.steps[0], metadata = step.metadata as WorkflowPolicyMetadataPayload;
  if (step.kind !== 'metadata' || step.handler !== 'workflow.policy' || step.entityType !== 'workflow_policy_requests' || step.entityId !== plan.subject.id || step.parentId != null || step.credentialKind != null
    || step.nativeRequests.length || step.dependencies.length || step.mutationAction !== undefined || step.mutationPayload !== undefined || step.mutationIdempotencyKey !== undefined || step.beforeFingerprint !== undefined
    || !metadata || typeof metadata !== 'object' || Array.isArray(metadata) || Object.keys(metadata).length !== 4 || !['intentId', 'definitionId', 'operation', 'payloadHmac'].every(key => Object.hasOwn(metadata, key))
    || metadata.intentId !== plan.subject.id || !uuid.test(metadata.intentId) || !uuid.test(metadata.definitionId) || !['version', 'archive', 'restore'].includes(metadata.operation) || !digest.test(metadata.payloadHmac)
    || !digest.test(step.metadataPayloadHmac ?? '') || !digest.test(step.metadataBeforeHmac ?? '') || !Number.isSafeInteger(step.metadataRevision) || Number(step.metadataRevision) < 1
    || step.permissionAction !== (metadata.operation === 'archive' ? 'delete' : 'write')) invalid();
  return step;
}
export function workflowPolicyMetadataProjection(input: unknown): Record<string, unknown> | null {
  if (input == null) return null; if (typeof input !== 'object' || Array.isArray(input)) return {};
  const value = input as Record<string, unknown>;
  return Object.fromEntries(['id', 'code', 'name', 'kind', 'revision', 'current_version', 'status', 'operation', 'definitionId', 'policy', 'policyHash', 'policy_hash', 'approval_format'].filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]]));
}
