import type { ConfigurationPlanStep } from './configuration.types';

/** Kong 1.5 Target weight change seals as POST + new allocatedNativeId.
 * Shared fail-closed shape check for durable admission and business-schedule
 * author/revision/activate/preclaim. Well-formed packets pass; incomplete
 * seals stay closed at the caller-chosen code. */
export function configurationTargetAppendPacketIncomplete(step: Readonly<ConfigurationPlanStep>): boolean {
  if (step.entityType !== 'targets' || step.mutationAction !== 'update') return false;
  if (step.allocatedNativeId == null || step.allocatedNativeId === step.nativeId) return false;
  const packet = step.nativeRequests?.[0];
  return !packet || step.nativeRequests.length !== 1 || packet.method !== 'POST'
    || packet.canonicalPath !== `/upstreams/${step.parentId}/targets`
    || step.parentId == null || step.before == null || typeof step.before !== 'object'
    || (step.before as { id?: unknown }).id !== step.nativeId || step.body?.id !== step.allocatedNativeId
    || step.body?.target == null || !Number.isInteger(step.body?.weight)
    || packet.bodyHmac !== step.bodyHmac || packet.beforeHmac !== step.beforeHmac;
}
