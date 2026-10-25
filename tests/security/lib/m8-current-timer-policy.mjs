/** A real timer may legally finish another interval before the operator
 * pauses it. Use its actual current CAS without inventing a fixed revision. */
export function assertM8CurrentTimerPolicy(policy, { id, area, actorId, name, version = 1 }) {
  if (!policy || policy.id !== id || policy.clusterId !== area.cid || policy.workspaceId !== area.wid
    || policy.ownerUserId !== actorId || policy.name !== name || policy.state !== 'active'
    || !Number.isSafeInteger(policy.revision) || policy.revision < 2 || policy.currentVersion !== version
    || policy.intervalMinutes !== 5 || !Number.isFinite(Date.parse(policy.nextRunAt))
    || policy.capabilities?.write !== true) throw Error('M8_CURRENT_ORIGINAL_TIMER_POLICY_REQUIRED');
  return policy;
}
