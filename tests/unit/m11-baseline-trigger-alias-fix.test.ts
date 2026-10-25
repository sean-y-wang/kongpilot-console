import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationDirectory = resolve('apps/console-api/src/infrastructure/migrations');
const original = readFileSync(resolve(migrationDirectory, '021_m11_entity_execution_facts.sql'), 'utf8');
const repair = readFileSync(resolve(migrationDirectory, '022_m11_baseline_trigger_alias_fix.sql'), 'utf8');
const functionPattern = /CREATE(?: OR REPLACE)? FUNCTION m11_validate_baseline_graph\(\)[\s\S]*?\$\$;/;
const stripComments = (value: string) => value.replace(/^\s*--[^\n]*$/gm, '').trim();

/** Security equivalence of an append-only migration. These checks do not
 * execute PostgreSQL, create approval facts or imply a successful rollout. */
describe('M11 baseline trigger alias repair preserves every integrity check', () => {
  it('leaves the formally applied SQL021 migration byte-for-byte immutable', () => {
    expect(createHash('sha256').update(original).digest('hex')).toBe('133756b722dae11085d20e1a419378e821fcae0c66e7a721350344e63b4a2956');
  });

  it('changes only the ambiguous SQL aliases, retaining the complete original function body', () => {
    const originalFunction = original.match(functionPattern)?.[0];
    const repairedFunction = repair.match(functionPattern)?.[0];
    expect(originalFunction).toBeDefined();
    expect(repairedFunction).toBeDefined();
    const inverseRenamed = repairedFunction!
      .replace('CREATE OR REPLACE FUNCTION', 'CREATE FUNCTION')
      .replace(/\bcandidate_object\b/g, 'o')
      .replace(/\bprevious_object\b/g, 'old');
    expect(inverseRenamed).toBe(originalFunction);
    expect(repairedFunction).not.toMatch(/FROM entity_change_baseline_objects o\s+WHERE/);
    // The PL/pgSQL row variable remains intact; only SQL relation aliases move.
    expect(repairedFunction).toContain('FOR o IN SELECT * FROM entity_change_baseline_objects');
    expect(repairedFunction).toContain('FROM entity_change_baseline_objects candidate_object WHERE candidate_object.baseline_id=b.id');
  });

  it('contains only one function replacement and adds no weaker schema, trigger or authorization settings', () => {
    const repairedFunction = repair.match(functionPattern)?.[0];
    expect(stripComments(repair)).toBe(repairedFunction);
    expect(repair).not.toMatch(/\b(?:DROP|DISABLE|GRANT|REVOKE|ALTER|TRUNCATE)\b|SECURITY\s+DEFINER|variable_conflict/i);
  });
});
