import { isSensitiveSchemaName } from '../components/kong-schema-rules';

/** Display defense; the BFF must also redact before a response reaches the browser. */
export function redactForDisplay(value: unknown, fieldName = ''): unknown {
  if (isSensitiveSchemaName(fieldName, typeof value)) return '[REDACTED]';
  if (Array.isArray(value)) return value.map(item => redactForDisplay(item));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactForDisplay(item, name)]));
  if (typeof value === 'string' && (/-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(value) || /^(?:Bearer|Basic)\s+\S/i.test(value) || /^(?:(?:proxy-)?authorization|(?:set-)?cookie|x-api-key)\s*:/i.test(value))) return '[REDACTED]';
  return value;
}
