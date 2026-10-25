import type { HistoricalEventScope, TrustedAuditScopeHints } from '../event-core/event.types';

const nativeTypes = new Set(['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'targets', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']);
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;

/** Only successful producers call this with locked before and verified readback.
 * Planned payloads and HTTP fields are never accepted as historical evidence. */
export function nativeHistoricalScope(input: {
  type: string; id: string; before: unknown; after: unknown;
  beforeWorkspaceId: string | null; afterWorkspaceId: string | null;
  parentId?: string; credentialKind?: string; module?: string;
}): HistoricalEventScope {
  const type = input.type === 'credentials' ? input.credentialKind : input.type;
  const unknown: HistoricalEventScope = { version: 1, quality: 'legacy_unknown', module: input.module ?? type ?? input.type, before: null, after: null };
  if (!type || !nativeTypes.has(type) || !uuid.test(input.id)) return unknown;
  const side = (entity: unknown, workspaceId: string | null) => {
    if (entity === null || entity === undefined) return null;
    if (typeof entity !== 'object' || Array.isArray(entity) || !workspaceId || !uuid.test(workspaceId)) throw new Error('UNVERIFIED_AUDIT_SCOPE');
    const actual = entity as Record<string, unknown>;
    if (actual.id !== input.id) throw new Error('UNVERIFIED_AUDIT_ID');
    const tags = actual.tags ?? [];
    if (!Array.isArray(tags) || tags.length > 1000 || tags.some(tag => typeof tag !== 'string' || !tag || tag.length > 128)) throw new Error('UNVERIFIED_AUDIT_TAGS');
    return { workspaceId, physicalTags: [...new Set(tags as string[])].sort() };
  };
  try {
    if ((type === 'targets' || ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'].includes(type)) && (!input.parentId || !uuid.test(input.parentId))) return unknown;
    const before = side(input.before, input.beforeWorkspaceId), after = side(input.after, input.afterWorkspaceId);
    if (!before && !after) return unknown;
    return { version: 1, quality: 'verified', module: input.module ?? type, nativeType: type, nativeId: input.id,
      ...(input.parentId ? { parentId: input.parentId } : {}),
      ...(input.credentialKind ? { credentialKind: input.credentialKind } : {}), before, after };
  } catch { return unknown; }
}

/** Console metadata has explicit whole-workspace historical scope. */
export function metadataAuditScope(module: string, type: string, id: string, workspaceId: string): TrustedAuditScopeHints {
  if (!uuid.test(id) || !uuid.test(workspaceId)) throw new Error('INVALID_METADATA_AUDIT_SCOPE');
  return { quality: 'verified', module, subject: { type, id }, beforeExists: true, afterExists: true,
    beforeWorkspaceId: workspaceId, afterWorkspaceId: workspaceId, beforeTags: [], afterTags: [] };
}

export function auditScopeHints(scope: HistoricalEventScope): TrustedAuditScopeHints {
  return { quality: scope.quality, module: scope.module,
    ...(scope.nativeType ? { nativeType: scope.nativeType, nativeId: scope.nativeId } : {}),
    ...(scope.parentId ? { parentContext: { nativeType: scope.nativeType === 'targets' ? 'upstreams' : 'consumers', nativeId: scope.parentId,
      ...(scope.credentialKind ? { credentialKind: scope.credentialKind } : {}) } } : {}),
    ...(scope.subject ? { subject: { ...scope.subject } } : {}), beforeExists: scope.before !== null, afterExists: scope.after !== null,
    beforeWorkspaceId: scope.before?.workspaceId ?? null, afterWorkspaceId: scope.after?.workspaceId ?? null,
    beforeTags: [...(scope.before?.physicalTags ?? [])], afterTags: [...(scope.after?.physicalTags ?? [])] };
}

export function nativeAuditScope(input: Parameters<typeof nativeHistoricalScope>[0]): TrustedAuditScopeHints {
  return auditScopeHints(nativeHistoricalScope(input));
}
