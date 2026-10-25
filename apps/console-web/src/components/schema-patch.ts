import { redactForDisplay } from '../api/redaction';
import { formPayload, prepareFormValues, redactedValue, schemaFields, type KongSchema } from './KongSchemaForm';

export function hasHiddenValue(value: unknown): boolean {
  if (redactedValue(value)) return true;
  if (Array.isArray(value)) return value.some(hasHiddenValue);
  return !!value && typeof value === 'object' && Object.values(value).some(hasHiddenValue);
}
function canonical(value: any): string {
  const normalize = (input: any): any => Array.isArray(input) ? input.map(normalize) : input && typeof input === 'object' ? Object.fromEntries(Object.keys(input).sort().filter(key => input[key] !== undefined).map(key => [key, normalize(input[key])])) : input;
  return JSON.stringify(normalize(value));
}

/** Preserve hidden maps and unset optional collections when editing another field. */
export function omitUnchangedHiddenMaps(schema: KongSchema, payload: Record<string, any>, original: Record<string, any>): Record<string, any> {
  const safeOriginal = redactForDisplay(original) as Record<string, any>;
  const baseline = formPayload(schema, prepareFormValues(schema, safeOriginal, true), true);
  const result = structuredClone(payload);
  function visit(definition: KongSchema, current: any, previous: any, initial: any) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return;
    for (const [name, field] of schemaFields(definition)) {
      if (!Object.hasOwn(current, name)) continue;
      if (['array', 'set'].includes(field.type ?? '') && previous?.[name] == null && Array.isArray(current[name]) && current[name].length === 0) delete current[name];
      else if (field.type === 'map' && hasHiddenValue(previous?.[name]) && canonical(current[name]) === canonical(initial?.[name])) delete current[name];
      else if (field.type === 'record') visit(field, current[name], previous?.[name], initial?.[name]);
    }
  }
  visit(schema, result, safeOriginal, baseline);
  return result;
}
