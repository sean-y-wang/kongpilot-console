import type { SecretService } from '../secret.service';

/** Preserve the full form schema while withholding actual credential defaults. */
export function stripSensitiveSchemaDefaults(schema: any, secrets: Pick<SecretService, 'redact'>): any {
  const clone = structuredClone(schema);
  const removed = Symbol('secret-default');
  const scrub = (raw: any, safe: any): any => {
    if (typeof safe === 'string' && safe.startsWith('[REDACTED')) return removed;
    if (Array.isArray(raw)) {
      const entries = raw.map((entry, index) => scrub(entry, safe?.[index]));
      // Dropping entries could alter positions in a record array, so omit that whole default.
      return entries.includes(removed) ? removed : entries;
    }
    if (raw && typeof raw === 'object') {
      const result = Object.create(null);
      for (const [key, value] of Object.entries(raw)) {
        const cleaned = scrub(value, safe?.[key]);
        if (cleaned !== removed) result[key] = cleaned;
      }
      return result;
    }
    return raw;
  };
  const field = (definition: any, name?: string): void => {
    if (!definition || typeof definition !== 'object') return;
    if (Object.hasOwn(definition, 'default')) {
      // CORS credentials is a public boolean flag. Classify it using its actual
      // value type so a credential object/string stays sensitive without hiding
      // this plugin's false default or forcing a bogus credential form value.
      const probe = definition.type === 'boolean' ? false : 'kongos-schema-default-classification';
      const sensitive = name !== undefined && secrets.redact({ [name]: probe })[name] !== probe;
      if (sensitive) { delete definition.default; definition.default_redacted = true; }
      else {
        const original = definition.default;
        const cleaned = scrub(original, secrets.redact(original));
        if (cleaned === removed) { delete definition.default; definition.default_redacted = true; }
        else if (JSON.stringify(cleaned) !== JSON.stringify(original)) { definition.default = cleaned; definition.default_redacted = true; }
      }
    }
    if (Array.isArray(definition.fields)) {
      for (const entry of definition.fields) for (const [key, value] of Object.entries(entry)) field(value, key);
    } else if (definition.fields && typeof definition.fields === 'object') {
      for (const [key, value] of Object.entries(definition.fields)) field(value, key);
    }
    field(definition.elements);
    field(definition.values);
    field(definition.keys);
  };
  field(clone);
  return clone;
}
