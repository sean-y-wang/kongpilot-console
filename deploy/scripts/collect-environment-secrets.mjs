/** Collect actual deployment secrets privately; callers must never log values. */
export function collectEnvironmentSecrets(environment) {
  const values = Object.entries(environment)
    .filter(([name, value]) => /PASSWORD|APP_SECRET|PORTAL_SECRET|ENCRYPTION_KEY/.test(name) && typeof value === 'string' && value)
    .map(([, value]) => value);
  if (environment.AUTH_PROVIDERS_JSON) {
    let providers;
    try { providers = JSON.parse(environment.AUTH_PROVIDERS_JSON); }
    catch { throw new Error('INVALID_PROVIDER_CONFIGURATION_FOR_SECRET_SCAN'); }
    if (!Array.isArray(providers)) throw new Error('INVALID_PROVIDER_CONFIGURATION_FOR_SECRET_SCAN');
    for (const provider of providers) {
      if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new Error('INVALID_PROVIDER_CONFIGURATION_FOR_SECRET_SCAN');
      for (const key of ['bind_password', 'client_secret']) {
        if (typeof provider[key] === 'string' && provider[key]) values.push(provider[key]);
      }
      // OIDC exchange encodes both fields before HTTP Basic base64 conversion.
      if (typeof provider.client_id === 'string' && typeof provider.client_secret === 'string' && provider.client_secret) {
        values.push(Buffer.from(`${encodeURIComponent(provider.client_id)}:${encodeURIComponent(provider.client_secret)}`).toString('base64'));
      }
    }
  }
  return [...new Set(values)];
}
