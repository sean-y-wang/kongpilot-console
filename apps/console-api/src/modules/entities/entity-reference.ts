/** Kong foreign fields support a UUID string or an { id } reference. */
export function entityReferenceId(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && !Array.isArray(value) && typeof (value as { id?: unknown }).id === 'string') return (value as { id: string }).id;
  return undefined;
}

/** Authorization evaluates one canonical foreign-reference view. The exact
 * native wire body, saved graph and their HMACs remain unchanged. */
export function normalizeEntityAuthorizationView(type: string, entity: any): any {
  if (!entity || typeof entity !== 'object' || Array.isArray(entity)) return entity;
  const fields = type === 'plugins' ? ['service', 'route', 'consumer'] : type === 'routes' ? ['service']
    : type === 'snis' ? ['certificate'] : type === 'services' ? ['client_certificate'] : type === 'targets' ? ['upstream']
    : ['credentials', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls', 'keyauth_credentials', 'basicauth_credentials', 'jwt_secrets', 'oauth2_credentials', 'hmacauth_credentials'].includes(type) ? ['consumer'] : [];
  const result = { ...entity };
  for (const field of fields) if (typeof result[field] === 'string') result[field] = { id: result[field] };
  return result;
}
