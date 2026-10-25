import { api } from './client';
import { governancePath, type GovernanceIdentity } from '../features/governance.model';

/** Only the fixed Governance BFF family; no Admin API, transport or arbitrary native path. */
export function governanceRead<T>(identity: GovernanceIdentity, resource: string, filters: Record<string, string> = {}, signal?: AbortSignal) { return api<T>(governancePath(identity, resource, filters), { signal }); }
export function governanceWrite<T>(identity: GovernanceIdentity, resource: string, method: 'POST' | 'PATCH' | 'DELETE', body: unknown, originalKey: string, signal?: AbortSignal) {
  return api<T>(governancePath(identity, resource), { method, body: JSON.stringify(body), headers: { 'X-Idempotency-Key': originalKey }, signal });
}
