import { BadRequestException } from '@nestjs/common';
import type { WorkflowPlanV1, WorkflowStep } from './workflow.types';

export const CONFIGURATION_METADATA_RESOURCES = ['config_snapshots', 'config_snapshot_schedules', 'configuration_gitops_runs'] as const;
export type ConfigurationMetadataResource = typeof CONFIGURATION_METADATA_RESOURCES[number];
export type ConfigurationMetadataOperation = 'create' | 'update' | 'archive' | 'restore' | 'purge';
export interface ConfigurationMetadataPayload {
  jobId: string; resourceType: ConfigurationMetadataResource; resourceId: string;
  operation: ConfigurationMetadataOperation; payload: Record<string, unknown>;
}
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const operations: Record<ConfigurationMetadataResource, readonly ConfigurationMetadataOperation[]> = {
  config_snapshots: ['archive', 'restore', 'purge'],
  config_snapshot_schedules: ['create', 'update', 'archive', 'restore', 'purge'],
  configuration_gitops_runs: ['create'],
};
const fail = (): never => { throw new BadRequestException({ code: 'CONFIGURATION_METADATA_WORKFLOW_INVALID' }); };
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![null, Object.prototype].includes(Object.getPrototypeOf(value))) fail();
  const target=value as object,descriptors = Object.getOwnPropertyDescriptors(target);
  if (Reflect.ownKeys(target).some(key => typeof key !== 'string' || ['__proto__', 'prototype', 'constructor'].includes(key)
    || !Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable)) fail();
  return value as Record<string, unknown>;
}
function fields(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  const data = object(value);
  if (required.some(key => !Object.hasOwn(data, key)) || Object.keys(data).some(key => !required.includes(key) && !optional.includes(key))) fail();
  return data;
}
function text(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}
/** Fixed DB metadata only. It cannot represent a native plan, callback, secret
 * import, pipeline command or another workflow subject. */
export function assertConfigurationMetadataWorkflowPlan(plan: WorkflowPlanV1): WorkflowStep {
  if (!plan || plan.kind !== 'configuration-metadata' || plan.requester?.type !== 'console'
    || !CONFIGURATION_METADATA_RESOURCES.includes(plan.subject?.type as ConfigurationMetadataResource)
    || !Array.isArray(plan.steps) || plan.steps.length !== 1 || !Array.isArray(plan.prerequisites) || plan.prerequisites.length
    || plan.generated !== undefined) fail();
  const step = plan.steps[0], metadata = fields(step?.metadata, ['jobId', 'resourceType', 'resourceId', 'operation', 'payload']) as unknown as ConfigurationMetadataPayload;
  if (!step || step.kind !== 'metadata' || step.handler !== 'configuration.metadata' || step.order !== 1
    || step.entityType !== plan.subject.type || step.entityId !== plan.subject.id
    || !Array.isArray(step.dependencies) || step.dependencies.length || !Array.isArray(step.nativeRequests) || step.nativeRequests.length
    || step.parentId !== undefined || step.credentialKind !== undefined || step.mutationAction !== undefined || step.mutationPayload !== undefined
    || step.mutationPayloadHmac !== undefined || step.mutationIdempotencyKey !== undefined || step.beforeFingerprint !== undefined
    || !uuid.test(metadata.jobId ?? '') || !uuid.test(metadata.resourceId ?? '') || metadata.resourceId !== plan.subject.id
    || metadata.resourceType !== plan.subject.type || !Object.hasOwn(operations, metadata.resourceType)
    || !operations[metadata.resourceType].includes(metadata.operation) || step.permissionAction !== configurationMetadataAction(metadata)
    || !Number.isSafeInteger(step.metadataRevision) || (step.metadataRevision ?? -1) < 0
    || !/^[a-f\d]{64}$/.test(step.metadataBeforeHmac ?? '') || !/^[a-f\d]{64}$/.test(step.metadataPayloadHmac ?? '')) fail();
  let payload: Record<string, unknown>;
  if (metadata.operation === 'archive' || metadata.operation === 'purge') {
    payload = fields(metadata.payload, ['revision', 'confirmed', 'confirm_name']);
    if (payload.confirmed !== true || !text(payload.confirm_name, 256)) fail();
  } else if (metadata.operation === 'restore') payload = fields(metadata.payload, ['revision']);
  else if (metadata.resourceType === 'config_snapshot_schedules') {
    payload = fields(metadata.payload, metadata.operation === 'create' ? ['name', 'intervalMinutes', 'timezone', 'retentionDays'] : ['revision', 'name', 'intervalMinutes', 'timezone', 'retentionDays'], metadata.operation === 'update' ? ['paused'] : []);
    if (!text(payload.name, 128) || !Number.isSafeInteger(payload.intervalMinutes) || Number(payload.intervalMinutes) < 5 || Number(payload.intervalMinutes) > 10080
      || !Number.isSafeInteger(payload.retentionDays) || Number(payload.retentionDays) < 1 || Number(payload.retentionDays) > 3650
      || !text(payload.timezone, 100) || Object.hasOwn(payload, 'paused') && typeof payload.paused !== 'boolean') fail();
    try { new Intl.DateTimeFormat('en', { timeZone: payload.timezone as string }).format(new Date()); } catch { fail(); }
  } else {
    payload = fields(metadata.payload, ['sourceJobId', 'repositoryLabel', 'commitSha', 'pipelineReference']);
    if (!uuid.test(String(payload.sourceJobId ?? '')) || !text(payload.repositoryLabel, 128) || !/^[A-Za-z0-9_. /-]+$/.test(payload.repositoryLabel)
      || typeof payload.commitSha !== 'string' || !/^([a-f0-9]{40}|[a-f0-9]{64})$/.test(payload.commitSha)
      || !text(payload.pipelineReference, 256) || !/^[A-Za-z0-9_. /:#-]+$/.test(payload.pipelineReference)
      || /(?:[a-z][a-z0-9+.-]*:\/\/|https?:|@|[?&=]|(?:token|password|secret|authorization|api[_-]?key)[:=])/i.test(payload.pipelineReference)) fail();
  }
  if (metadata.operation === 'create') {
    if (step.metadataRevision !== 0 || step.before !== null) fail();
  } else if (!Number.isSafeInteger(payload.revision) || Number(payload.revision) < 1 || payload.revision !== step.metadataRevision) fail();
  return step;
}
export function configurationMetadataAction(metadata: Pick<ConfigurationMetadataPayload, 'operation'>): 'write' | 'delete' {
  return ['archive', 'purge'].includes(metadata.operation) ? 'delete' : 'write';
}
/** Mirrors the independently sealed, original console metadata job input. */
export function configurationMetadataLedgerInput(metadata:ConfigurationMetadataPayload):Record<string,unknown>{
  return{action:'metadata',resourceType:metadata.resourceType,resourceId:metadata.resourceId,operation:metadata.operation,payload:metadata.payload};
}
