import { ForbiddenException } from '@nestjs/common';
import type { WorkflowPlanV1, WorkflowStep } from './workflow.types';

/** The workflow engine can depend on this fixed registry without importing the
 * Events management module or accepting a client-selected callback. */
export const EVENT_WORKFLOW_HANDLERS = {
  'event.channel.save': { subject: 'notification_channels', action: 'write' },
  'event.channel.status': { subject: 'notification_channels', action: 'write' },
  'event.channel.delete': { subject: 'notification_channels', action: 'delete' },
  'event.channel.restore': { subject: 'notification_channels', action: 'write' },
  'event.channel.test': { subject: 'notification_channels', action: 'write' },
  'event.subscription.save': { subject: 'event_subscriptions', action: 'write' },
  'event.subscription.delete': { subject: 'event_subscriptions', action: 'delete' },
  'event.subscription.restore': { subject: 'event_subscriptions', action: 'write' },
  'event.delivery.replay': { subject: 'event_deliveries', action: 'write' },
} as const;
export type EventWorkflowHandlerName = keyof typeof EVENT_WORKFLOW_HANDLERS;
export function eventWorkflowHandler(name: unknown) {
  if (typeof name !== 'string' || !Object.hasOwn(EVENT_WORKFLOW_HANDLERS, name))
    throw new ForbiddenException({ code: 'EVENT_WORKFLOW_HANDLER_INVALID' });
  return EVENT_WORKFLOW_HANDLERS[name as EventWorkflowHandlerName];
}
export function assertEventWorkflowPlan(plan: WorkflowPlanV1): WorkflowStep {
  const reject = (): never => { throw new ForbiddenException({ code: 'EVENT_WORKFLOW_PLAN_INVALID' }); };
  if (plan.kind !== 'event-metadata' || plan.executionMode !== 'approval' || plan.approvalRequired !== true
    || plan.requester?.type !== 'console' || plan.generated !== undefined || !Array.isArray(plan.prerequisites)
    || plan.prerequisites.length || !Array.isArray(plan.steps) || plan.steps.length !== 1) reject();
  const step = plan.steps[0], mapping = eventWorkflowHandler(step.handler);
  if (mapping.subject !== plan.subject.type || step.kind !== 'metadata' || step.entityType !== plan.subject.type
    || step.entityId !== plan.subject.id || step.permissionAction !== mapping.action || step.order !== 1
    || !Array.isArray(step.dependencies) || step.dependencies.length || !Array.isArray(step.nativeRequests)
    || step.nativeRequests.length || step.parentId !== undefined || step.credentialKind !== undefined
    || step.mutationAction !== undefined || step.mutationPayload !== undefined || step.mutationPayloadHmac !== undefined
    || step.mutationIdempotencyKey !== undefined || step.beforeFingerprint !== undefined) reject();
  return step;
}

export interface EventExecutionAuditProof {
  version: 1; handler: string; requestHmac: string; beforeHmac: string; payloadHmac: string;
  workflow: {id: string; executionId: string; planRevision: number; planHash: string; stepId: string};
}
export function eventExecutionAuditProof(plan: WorkflowPlanV1, step: WorkflowStep, executionId: string, planHash: string): EventExecutionAuditProof {
  assertEventWorkflowPlan(plan);
  return { version: 1, handler:step.handler!, requestHmac:step.metadataPayloadHmac!, beforeHmac:step.metadataBeforeHmac!,payloadHmac:step.metadataPayloadHmac!,
    workflow:{id: plan.workflowId, executionId, planRevision: plan.planRevision, planHash, stepId:step.id} };
}

/** Separate event diff projection: raw target paths, recipients, auth and
 * ciphertext never become review fields merely because they have a safe name. */
export function eventMetadataProjection(value: unknown): Record<string, unknown> | null {
  if (value == null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) return {};
  const source = value as Record<string, unknown>, out: Record<string, unknown> = {};
  for (const key of ['id', 'name', 'type', 'status', 'revision', 'credentialGeneration', 'credential_generation',
    'channelId', 'channel_id', 'configured', 'authConfigured', 'destinationHost', 'maskedDestination',
    'createOrUpdate', 'deliveryId', 'eventId', 'replayGeneration']) {
    const entry = source[key];
    if (entry === null || ['string', 'number', 'boolean'].includes(typeof entry)) out[key] = entry;
  }
  for (const key of ['eventTypes', 'event_types', 'nativeIds', 'native_ids']) {
    const entry = source[key];
    if (Array.isArray(entry) && entry.length <= 256 && entry.every(v => typeof v === 'string')) out[key] = [...entry];
  }
  for(const [raw,safe] of Object.entries({credential_generation:'credentialGeneration',channel_id:'channelId',event_types:'eventTypes',native_ids:'nativeIds',native_type:'nativeType',desiredStatus:'status'})){
    if(Object.hasOwn(out,raw)){out[safe]=out[raw];delete out[raw];}
    else if((raw==='native_type'||raw==='desiredStatus')&&(source[raw]===null||typeof source[raw]==='string'))out[safe]=source[raw];
  }
  if(source.nativeType===null||typeof source.nativeType==='string')out.nativeType=source.nativeType;
  if(Object.hasOwn(source,'endpoint_secret'))out.configured=!!source.endpoint_secret;
  const physicalTags=source.physicalTags??source.physical_tags;if(Array.isArray(physicalTags))out.tagCount=physicalTags.length;
  // A server-validated sealed material can contribute only its bounded safe
  // summary. Endpoint/auth/recipient material itself is never copied to diff.
  const desired=source.desiredConfigSecret;
  if(desired&&typeof desired==='object'&&!Array.isArray(desired)){
    const summary=(desired as Record<string,unknown>).safeSummary;
    if(summary&&typeof summary==='object'&&!Array.isArray(summary))for(const key of ['destinationHost','maskedDestination','authConfigured','recipientCount']){
      const entry=(summary as Record<string,unknown>)[key];if(entry===null||['string','number','boolean'].includes(typeof entry))out[key]=entry;
    }
    out.configured=true;
  }
  return out;
}
