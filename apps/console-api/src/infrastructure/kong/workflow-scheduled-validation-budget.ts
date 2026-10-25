import { CONFIGURATION_TIMEOUT_MS } from './configuration-budget';
import type { WorkflowScheduleCandidateReadScope } from '../../modules/workflows/workflow-schedule-candidate-read.types';

const ordinaryValidationMs = 30_000;
const perReadWorkUnitMs = 5_000;

/** Only the original private provider's current SQL scope may select this
 * fixed budget. It grants no authority and never extends any original
 * namespace, claim, lease or window expiry. Portal retains its 30s limit. */
export function workflowScheduledValidationBudgetMs(kind: string, scope: Readonly<WorkflowScheduleCandidateReadScope>): number {
  if (kind !== 'configuration_v2') return ordinaryValidationMs;
  const required = scope.resources.filter(resource => resource.required !== false);
  const fixedReads = required.filter(resource => resource.kind === 'point' || resource.kind === 'schema').length;
  // maxPages belongs to the complete scope. Charging it once avoids silently
  // multiplying the shared pagination budget by each collection's count.
  const pages = required.some(resource => resource.kind === 'collection') ? scope.limits.maxPages : 0;
  return Math.min(CONFIGURATION_TIMEOUT_MS, ordinaryValidationMs + perReadWorkUnitMs * (fixedReads + pages));
}
