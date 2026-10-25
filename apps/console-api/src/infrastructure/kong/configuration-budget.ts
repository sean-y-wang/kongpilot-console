/** Fixed server-side M8 budgets. These values are never accepted from a DTO.
 * Native call/page/record/byte limits and every current-authority check remain
 * unchanged. Ordinary workflows and Portal retain their 120 second limit. */
export const CONFIGURATION_TIMEOUT_MS = 300_000;
export const CONFIGURATION_LEASE_MS = CONFIGURATION_TIMEOUT_MS + 5_000;

const uuidSegment = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const configurationPost = new RegExp(`^/api/v1/clusters/${uuidSegment}/(?:snapshots(?:/${uuidSegment}/(?:export|rollback-plan))?|configuration/(?:imports|exports|exports/${uuidSegment}/download|plans/${uuidSegment}/(?:apply|reconcile|durable-submissions))|workflows/${uuidSegment}/execute)$`, 'i');
const configurationCompare = new RegExp(`^/api/v1/clusters/${uuidSegment}/snapshots/${uuidSegment}/compare/${uuidSegment}$`, 'i');

/** Extends only the HTTP wait envelope. It supplies no actor, grant, approved
 * proof or native capability. The actual durable plan decides the actor budget. */
export function configurationHttpWait(method: string, path: string): boolean {
  return method === 'POST' && configurationPost.test(path)
    || method === 'GET' && configurationCompare.test(path);
}
