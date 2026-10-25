import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Use the same compiled implementation as the BFF. A missing/stale API build
// must be resolved before recording; do not fall back to another secret regex.
export function createFixtureSanitizer() {
  require('reflect-metadata');
  const { SecretService } = require('../../apps/console-api/dist/infrastructure/secret.service.js');
  const { stripSensitiveSchemaDefaults } = require('../../apps/console-api/dist/infrastructure/kong/schema-secrets.js');
  const secrets = new SecretService();
  return {
    sanitizeBody: value => secrets.redact(value),
    sanitizeSchema: value => stripSensitiveSchemaDefaults(value, secrets),
  };
}
