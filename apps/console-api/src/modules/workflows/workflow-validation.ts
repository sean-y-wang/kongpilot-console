import { BadRequestException } from '@nestjs/common';
import { assertKongPath } from '../../infrastructure/kong/policy';
import { WORKFLOW_HANDLERS } from './workflow-registry.service';
import { WORKFLOW_KINDS, type WorkflowPlanV1 } from './workflow.types';
import { assertEventWorkflowPlan, EVENT_WORKFLOW_HANDLERS } from './event-workflow';
import { assertConfigurationWorkflowPlan } from './configuration-workflow';
import { assertConfigurationMetadataWorkflowPlan, CONFIGURATION_METADATA_RESOURCES } from './configuration-metadata-workflow';
import { assertToolboxWorkflowPlan } from './toolbox-workflow';
import { assertWorkspaceMigrationWorkflowPlan } from './workspace-migration-workflow';
import { assertGovernanceMetadataPlan } from '../governance/governance-workflow';
import { assertWorkflowPolicyMetadataPlan } from './workflow-policy-metadata';
import { assertEntityChangeWorkflowPlan } from './entity-change-workflow';
import { assertIamMetadataPlan } from '../iam/iam-workflow-plan';
import { assertControlMetadataPlan } from '../control-plane/control-metadata-plan';
import { assertMetricsSetupPlan } from '../vitals/vitals-setup-plan';
import { assertEntityAnnotationPlan } from '../annotations/entity-annotation-workflow-plan';
export const workflowId = (value: unknown): string => {
  if (typeof value !== 'string' || !/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value)) throw new BadRequestException({ code: 'INVALID_WORKFLOW_ID' });
  return value.toLowerCase();
};
export function workflowKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z\d_.:-]{8,128}$/.test(value)) throw new BadRequestException({ code: 'INVALID_IDEMPOTENCY_KEY' }); return value;
}
export function validateWorkflowPlan(plan: WorkflowPlanV1): void {
  const fail = (): never => { throw new BadRequestException({ code: 'INVALID_WORKFLOW_PLAN', message: '工作流计划不满足受限版本和步骤约束' }); };
  if (!plan || plan.version !== 1 || !(WORKFLOW_KINDS as readonly string[]).includes(plan.kind) || !['direct', 'approval'].includes(plan.executionMode) || typeof plan.approvalRequired !== 'boolean' || plan.executionMode === 'approval' && !plan.approvalRequired) fail();
  for (const id of [plan.clusterId, plan.workspaceId, plan.workflowId, plan.subject.id, plan.requester.id, plan.definition.id]) workflowId(id);
  if (!Number.isInteger(plan.planRevision) || plan.planRevision < 1 || !Number.isInteger(plan.scope.clusterRevision) || !Number.isInteger(plan.scope.workspaceRevision) || !/^[a-f0-9]{64}$/.test(plan.scope.transportScope) || !Number.isFinite(Date.parse(plan.expiresAt)) || !Array.isArray(plan.steps) || !plan.steps.length || plan.steps.length > 16 || !Array.isArray(plan.prerequisites) || plan.prerequisites.length > 64 || Buffer.byteLength(JSON.stringify(plan)) > 2 * 1024 * 1024) fail();
  if (plan.kind.startsWith('portal-credential-') && !plan.approvalRequired) fail();
  if (plan.kind==='configuration_v2') {try{assertConfigurationWorkflowPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='configuration_jobs'||plan.steps.some(step=>step.handler==='configuration_v2'))fail();
  if(plan.kind==='configuration-metadata'){try{assertConfigurationMetadataWorkflowPlan(plan);}catch{fail();}}
  else if((CONFIGURATION_METADATA_RESOURCES as readonly string[]).includes(plan.subject.type)||plan.steps.some(step=>step.handler==='configuration.metadata'))fail();
  if (plan.kind === 'event-metadata') { try { assertEventWorkflowPlan(plan); } catch { fail(); } }
  else if (plan.steps.some(step => Object.hasOwn(EVENT_WORKFLOW_HANDLERS, step.handler ?? ''))) fail();
  if(plan.kind==='toolbox-operation'){try{assertToolboxWorkflowPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='toolbox_operations'||plan.steps.some(step=>step.handler==='toolbox.execute'))fail();
  if(plan.kind==='workspace-migration'){try{assertWorkspaceMigrationWorkflowPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='workspace_migration_plans'||plan.migration!==undefined||plan.steps.some(step=>step.mutationAction==='migrate'||step.entityType==='workspace_migration'))fail();
  if(plan.kind==='governance-metadata'){try{assertGovernanceMetadataPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='governance_metadata_requests'||plan.steps.some(step=>step.handler==='governance.metadata'||step.entityType==='governance_metadata_requests'))fail();
  if(plan.kind==='workflow-policy-metadata'){try{assertWorkflowPolicyMetadataPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='workflow_policy_requests'||plan.steps.some(step=>step.handler==='workflow.policy'||step.entityType==='workflow_policy_requests'))fail();
  if(plan.kind==='native-change'){try{assertEntityChangeWorkflowPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='entity_change_intents'||plan.steps.some(step=>step.handler==='entity.change'||step.entityType==='entity_change_intents'))fail();
  if(plan.kind==='iam-metadata'){try{assertIamMetadataPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='iam_metadata_requests'||plan.steps.some(step=>step.handler==='iam.metadata'||step.entityType==='iam_metadata_requests'))fail();
  if(plan.kind==='metrics-setup'){try{assertMetricsSetupPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='metrics_setup_requests'||plan.steps.some(step=>step.handler==='metrics.setup.settings'||step.entityType==='metrics_setup_requests'))fail();
  if(plan.kind==='control-metadata'){try{assertControlMetadataPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='control_metadata_requests'||plan.steps.some(step=>step.handler==='control.metadata'||step.entityType==='control_metadata_requests'))fail();
  if(plan.kind==='entity-annotation'){try{assertEntityAnnotationPlan(plan);}catch{fail();}}
  else if(plan.subject.type==='entity_annotation_requests'||plan.steps.some(step=>step.handler==='entity.annotation'||step.entityType==='entity_annotation_requests'))fail();
  const seen = new Set<string>(); let requests = 0;
  for (const [index, step] of plan.steps.entries()) {
    workflowId(step.id);
    if (seen.has(step.id) || step.order !== index + 1 || !Array.isArray(step.dependencies) || step.dependencies.some(id => !seen.has(id)) || !['write', 'delete'].includes(step.permissionAction) || !Array.isArray(step.nativeRequests)) fail();
    seen.add(step.id);
    if (step.kind === 'metadata') {
      if (!(WORKFLOW_HANDLERS as readonly string[]).includes(step.handler || '') || step.nativeRequests.length || step.mutationAction || !step.metadataPayloadHmac || !step.metadataBeforeHmac || !Number.isInteger(step.metadataRevision)) fail();
    } else if (step.kind === 'native') {
      // M6 dispatch maps each logical step to one EntityService operation.
      // Cascades must be separate sealed steps; an unimplemented second packet
      // must never be reported as an executed part of the plan.
      if (plan.kind!=='workspace-migration'&&(!['create', 'update', 'delete', 'restore'].includes(step.mutationAction || '') || step.nativeRequests.length !== 1) || !step.mutationPayloadHmac || !step.beforeFingerprint || !step.mutationIdempotencyKey) fail();
      workflowKey(step.mutationIdempotencyKey);
      for (const request of step.nativeRequests) { assertKongPath(request.method, request.canonicalPath); if (!/^[a-f0-9]{64}$/.test(request.bodyHmac)) fail(); requests++; }
    } else fail();
  }
  if (requests > 32) fail();
}
