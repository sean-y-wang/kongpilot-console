import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const directory = resolve(process.cwd(), 'apps/console-api/src/infrastructure/migrations');
// Source capture for this independent review, not evidence of an applied DB
// ledger. Do not regenerate these expected digests from the files under test.
const frozenMigrations: ReadonlyArray<readonly [string, string]> = [
  ['000_m0.sql', '02f171ea1ff6dd64d12840e36681b315cec9665552aa3b8acdf72319a1c2fd96'],
  ['001_m1.sql', 'ef2e738577ae5321ddfdbd69c315a820e7dfa2bfcbef59176a2a8b9491b3fee6'],
  ['002_m1_index.sql', 'bd67be44dd80554872943d8ef3bac85757f2790f965e31a9ff996e380b1f7663'],
  ['003_m1_index_cycles.sql', 'dc695f4006e0839104df4b4108fc4426ca0670d6c7fa4083b1f29032ad751bf6'],
  ['004_m3_workspaces.sql', '263301537a1bbbdce62fafe44bc9a40589f6b450c9f4f0c787879a252752d501'],
  ['005_m4_iam.sql', '1ab35fdca5b4724af18f1287936c6eced21061ae5605f19b455acabc69f06d22'],
  ['006_m4_child_navigation.sql', 'd5e89915b7192efcdb32e3a9b729543d44c8691d3cc957fc457b9bc1a42e6c01'],
  ['007_m5_metrics.sql', 'e301a76f25c74a72e6599e1c735b152b981bd4df20bfc6f57b3b18c2f59887bf'],
  ['008_m6_portal.sql', '241444c9f85ea30bc09f6a4a93ded051acc5692317068a1e68814c92d9f520bc'],
  ['009_m6_failed_issue_abandonment.sql', '39b2eaf3f0554407114add04aa90a2f197f8cb23b2991077cdc7e018f9dba7fd'],
  ['010_m7_events.sql', '32e46c977d121449795cb7af82ce028d6a121e859f452df7fd3534adc06a8a53'],
  ['011_m8_configuration.sql', '99131280ca62d17e22093ac31449a5f07c98f76321ea54aef93d028de7ba1b1a'],
  ['012_m9_toolbox.sql', 'bbd6c5ca35d6e98545ccd61594969e0ccc78acb5e871276499a4418928737631'],
  ['013_m9_cache_key_constraint.sql', '65dd6e62f80c3677dd2b357ed584fa79427fb180e5939f60eb236cbf1a365cc5'],
  ['014_m9_configuration_recycle_graphs.sql', 'f6a0fd59d1311471f9dc9439303a881e59d80d3032be37eef63337c77d8f47c2'],
  ['015_m9_configuration_recycle_workspaces.sql', '679d3d498c3c467735221980537d8e163d19385a6034a56ef87f9d44a7a00349'],
  ['016_m9_workspace_migration_workflow.sql', 'e98a1afa0c42f182ae8b4ad7d2f2f06c0531a5cf07bd7d8c52cf55c4cc1dac38'],
  ['017_m10_governance.sql', '677510dd14357029d4e69933c295472c1600e0c31ff7e75a869a52ca82846ec8'],
  ['018_m10_configuration_origins.sql', '41c60fea0f26f9e2758acdae2c39a71e7945a27c53ed6159e26bff2574ad92d7'],
  ['019_m11_approval_policy.sql', 'a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb'],
  ['020_m11_durable_entity_intents.sql', 'd220ee5401d5b704f0dd189ef6d9763d3591fbede52f5cf5a236deddd04cccce'],
  ['021_m11_entity_execution_facts.sql', '133756b722dae11085d20e1a419378e821fcae0c66e7a721350344e63b4a2956'],
  ['022_m11_baseline_trigger_alias_fix.sql', '8abdc8219e82f3932f0d0bdd7a6c2eddd389e1d29d9fcd6d5e306b50f4f7d5f4'],
  ['023_m11_entity_recycle_facts.sql', '9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb'],
  ['024_m11_entity_schedules.sql', '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f'],
  ['025_m11_partial_recycle_restore.sql', '72b19980dfd3d5cda3370d89a05994f35d557cecf7e8ceb8218315864c419534'],
];

type Column = { type: string; notNull: boolean };
type ForeignKey = { local: string[]; table: string; remote: string[]; onDeleteRestrict: boolean };
type Table = { columns: Map<string, Column>; unique: string[][]; foreignKeys: ForeignKey[] };
type Schema = Map<string, Table>;

/** Small fail-closed source parser, not a PostgreSQL parser or DDL trial. Its
 * supported grammar is exercised below; unsupported FK forms fail the tests. */
function withoutComments(source: string): string {
  let output = '', quoted = false, identifier = false, block = 0;
  for (let index = 0; index < source.length; index++) {
    const current = source[index], next = source[index + 1];
    if (block) {
      if (current === '/' && next === '*') { block++; output += '  '; index++; }
      else if (current === '*' && next === '/') { block--; output += '  '; index++; }
      else output += current === '\n' ? '\n' : ' ';
      continue;
    }
    if (!quoted && !identifier && current === '-' && next === '-') {
      while (index < source.length && source[index] !== '\n') { output += ' '; index++; }
      if (index < source.length) output += '\n';
      continue;
    }
    if (!quoted && !identifier && current === '/' && next === '*') { block = 1; output += '  '; index++; continue; }
    output += current;
    if (!identifier && current === "'") {
      if (quoted && next === "'") { output += next; index++; }
      else quoted = !quoted;
    } else if (!quoted && current === '"') {
      if (identifier && next === '"') { output += next; index++; }
      else identifier = !identifier;
    }
  }
  if (quoted || identifier || block) throw new Error('Unclosed SQL quote/comment');
  return output;
}
function parenthesized(source: string, opening: number): { body: string; end: number } {
  if (source[opening] !== '(') throw new Error('Expected SQL opening parenthesis');
  let depth = 0, quote = false;
  for (let index = opening; index < source.length; index++) {
    if (source[index] === "'") {
      if (quote && source[index + 1] === "'") { index++; continue; }
      quote = !quote;
    }
    if (quote) continue;
    if (source[index] === '(') depth++;
    if (source[index] === ')' && --depth === 0) return { body: source.slice(opening + 1, index), end: index + 1 };
  }
  throw new Error('Unclosed SQL parenthesis');
}
function pieces(source: string): string[] {
  const result: string[] = [];
  let start = 0;
  for (let index = 0; index < source.length; index++) {
    if (source[index] === "'") {
      for (index++; index < source.length; index++) {
        if (source[index] === "'" && source[index + 1] === "'") index++;
        else if (source[index] === "'") break;
      }
      if (index >= source.length) throw new Error('Unclosed SQL string');
    } else if (source[index] === '(') index = parenthesized(source, index).end - 1;
    else if (source[index] === ',') { result.push(source.slice(start, index).trim()); start = index + 1; }
  }
  result.push(source.slice(start).trim());
  return result;
}
function columns(source: string): string[] {
  const values = pieces(source).map(value => value.toLowerCase());
  if (!values.length || values.some(value => !/^[a-z_][a-z0-9_]*$/.test(value))) throw new Error('Unsupported SQL key column');
  return values;
}
function addPart(table: Table, part: string): void {
  const column = /^([a-z_][a-z0-9_]*)\s+(uuid|text|integer|bigint|bigserial|serial|smallint|boolean|jsonb|timestamptz|timestamp|real|double\s+precision|numeric|bytea)(\[\])?(?![a-z_])/i.exec(part);
  if (column) {
    const name = column[1].toLowerCase();
    if (table.columns.has(name)) throw new Error(`Duplicate SQL column ${name}`);
    const type = column[2].toLowerCase().replace(/^bigserial$/, 'bigint').replace(/^serial$/, 'integer');
    const constraints = part.slice(column[0].length).replace(/'(?:''|[^'])*'/g, "''");
    table.columns.set(name, { type: (type + (column[3] ?? '')).replace(/\s+/g, ' '), notNull: /\bNOT NULL\b|\bPRIMARY KEY\b/i.test(constraints) });
    if (/\bPRIMARY KEY\b|\bUNIQUE\b/i.test(constraints)) table.unique.push([name]);
    const reference = /\bREFERENCES\s+([a-z_][a-z0-9_]*)\s*\(/i.exec(part);
    if (reference) table.foreignKeys.push({ local: [name], table: reference[1].toLowerCase(), remote: columns(parenthesized(part, reference.index + reference[0].length - 1).body), onDeleteRestrict: /\bON DELETE RESTRICT\b/i.test(part) });
    return;
  }
  const key = /^(?:CONSTRAINT\s+\w+\s+)?(?:PRIMARY KEY|UNIQUE)\s*\(/i.exec(part);
  if (key) { table.unique.push(columns(parenthesized(part, key.index + key[0].length - 1).body)); return; }
  const fk = /^(?:CONSTRAINT\s+\w+\s+)?FOREIGN KEY\s*\(/i.exec(part);
  if (fk) {
    const local = parenthesized(part, fk.index + fk[0].length - 1);
    const reference = /\bREFERENCES\s+([a-z_][a-z0-9_]*)\s*\(/i.exec(part.slice(local.end));
    if (!reference) throw new Error('Foreign key without explicit referenced columns');
    const remoteOpening = local.end + reference.index + reference[0].length - 1;
    table.foreignKeys.push({ local: columns(local.body), table: reference[1].toLowerCase(), remote: columns(parenthesized(part, remoteOpening).body), onDeleteRestrict: /\bON DELETE RESTRICT\b/i.test(part) });
  } else if (!/^(?:CONSTRAINT\s+\w+\s+)?CHECK\s*\(/i.test(part)) throw new Error(`Unsupported SQL table element: ${part.slice(0, 60)}`);
}
function schemaOf(sources: readonly string[]): Schema {
  const schema: Schema = new Map();
  for (const source of sources) {
    // SQL function/DO text cannot masquerade as actual CREATE/ALTER DDL.
    const code = withoutComments(source).replace(/(\$(?:[a-z_][a-z0-9_]*)?\$)[\s\S]*?\1/gi, value => ' '.repeat(value.length));
    for (const match of code.matchAll(/\bCREATE TABLE\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(/gi)) {
      const name = match[1].toLowerCase();
      if (schema.has(name)) throw new Error(`Duplicate SQL table ${name}`);
      const table: Table = { columns: new Map(), unique: [], foreignKeys: [] };
      pieces(parenthesized(code, match.index! + match[0].length - 1).body).forEach(part => addPart(table, part));
      schema.set(name, table);
    }
    for (const match of code.matchAll(/\bALTER TABLE\s+([a-z_][a-z0-9_]*)\s+ADD\s+(COLUMN\s+)?/gi)) {
      const table = schema.get(match[1].toLowerCase());
      if (!table) throw new Error(`Unknown ALTER TABLE ${match[1]}`);
      const start = match.index! + match[0].length, end = code.indexOf(';', start);
      if (end < 0) throw new Error('Unclosed ALTER TABLE');
      const part = code.slice(start, end).trim();
      if (/^(?:CONSTRAINT\s+\w+\s+)?(?:CHECK|UNIQUE|PRIMARY KEY|FOREIGN KEY)\b/i.test(part) || match[2]) addPart(table, part);
      else throw new Error(`Unsupported SQL ADD form: ${part.slice(0, 50)}`);
    }
    for (const match of code.matchAll(/\bCREATE UNIQUE INDEX\s+(?:IF NOT EXISTS\s+)?\w+\s+ON\s+(\w+)\s*\(/gi)) {
      const tuple = parenthesized(code, match.index! + match[0].length - 1), tail = code.slice(tuple.end, code.indexOf(';', tuple.end));
      if (!/\bWHERE\b/i.test(tail) && /^[a-z_\d\s,]+$/i.test(tuple.body)) schema.get(match[1].toLowerCase())?.unique.push(columns(tuple.body));
    }
  }
  return schema;
}
function assertForeignKeys(candidate: Schema, historical: Schema): void {
  for (const [name, table] of candidate) for (const fk of table.foreignKeys) {
    const target = historical.get(fk.table) ?? candidate.get(fk.table);
    if (!target || fk.local.length !== fk.remote.length || new Set(fk.local).size !== fk.local.length || new Set(fk.remote).size !== fk.remote.length) throw new Error(`Invalid FK bijection ${name} -> ${fk.table}`);
    fk.local.forEach((column, index) => {
      const local = table.columns.get(column), remote = target.columns.get(fk.remote[index]);
      if (!local || !remote || local.type !== remote.type) throw new Error(`FK type/column mismatch ${name}.${column} -> ${fk.table}.${fk.remote[index]}`);
      if (['cluster_id', 'workspace_id'].includes(fk.remote[index]) && column !== fk.remote[index]) throw new Error(`FK scope mismatch ${name}.${column} -> ${fk.table}.${fk.remote[index]}`);
    });
    const sorted = [...fk.remote].sort().join(',');
    if (!target.unique.some(tuple => [...tuple].sort().join(',') === sorted)) throw new Error(`FK lacks an existing complete unique tuple ${fk.table}(${fk.remote})`);
    if (!fk.onDeleteRestrict) throw new Error(`FK must preserve historical facts ${name} -> ${fk.table}`);
  }
}
function sqlFunction(source: string, name: string): string {
  const code = withoutComments(source), signature = new RegExp(`\\bCREATE FUNCTION ${name}\\s*\\(`, 'i').exec(code);
  if (!signature) throw new Error(`Missing SQL function ${name}`);
  const opening = code.indexOf('AS $$', signature.index), closing = code.indexOf('$$;', opening + 5);
  if (opening < 0 || closing < 0) throw new Error(`Unclosed SQL function ${name}`);
  return code.slice(opening + 5, closing);
}
function rowComparisons(body: string): Array<{ left: string[]; right: string[] }> {
  const result: Array<{ left: string[]; right: string[] }> = [];
  for (const match of body.matchAll(/\bROW\s*\(/gi)) {
    const left = parenthesized(body, match.index! + match[0].length - 1), comparison = /^\s*IS DISTINCT FROM\s+ROW\s*\(/i.exec(body.slice(left.end));
    if (!comparison) continue;
    const right = parenthesized(body, left.end + comparison[0].length - 1);
    result.push({ left: pieces(left.body), right: pieces(right.body) });
  }
  return result;
}
function assertTypedRowReferences(body: string, schema: Schema, observation: string): void {
  const variables = new Map<string, string>([['p_observation', observation]]);
  for (const match of body.matchAll(/\b(v_[a-z_]+)\s+([a-z_]+)%ROWTYPE\b/gi)) {
    if (!schema.has(match[2])) throw new Error(`Unknown row type ${match[2]}`);
    variables.set(match[1], match[2]);
  }
  const referenceType = (expression: string): string => {
    const reference = /^((?:v_[a-z_]+|p_observation))\.([a-z_]+)(?:::(\w+))?$/i.exec(expression.trim());
    if (reference) {
      const table = variables.get(reference[1]), column = table && schema.get(table)?.columns.get(reference[2]);
      if (!column) throw new Error(`Unknown row-type field ${reference[1]}.${reference[2]}`);
      return reference[3]?.toLowerCase() ?? column.type;
    }
    if (/^NULL::\w+$/i.test(expression.trim())) return expression.trim().split('::')[1].toLowerCase();
    if (/^'(?:''|[^'])*'::\w+$/.test(expression.trim())) return expression.trim().split('::').at(-1)!;
    if (/^\d+$/.test(expression.trim())) return 'integer';
    throw new Error(`Unsupported typed ROW expression ${expression}`);
  };
  const code = body.replace(/'(?:''|[^'])*'/g, "''");
  for (const match of code.matchAll(/\b(v_[a-z_]+|p_observation)\.([a-z_]+)\b/gi)) referenceType(match[0]);
  for (const pair of rowComparisons(body)) {
    if (pair.left.length !== pair.right.length) throw new Error('Typed ROW comparison is not a bijection');
    pair.left.forEach((field, index) => { if (referenceType(field) !== referenceType(pair.right[index])) throw new Error(`Typed ROW comparison mismatch ${field} / ${pair.right[index]}`); });
  }
  for (const match of body.matchAll(/\b((?:v_[a-z_]+|p_observation)\.[a-z_]+(?:::\w+)?)\s*(?:IS (?:NOT )?DISTINCT FROM|<>|=|<=|>=|<|>)\s*((?:v_[a-z_]+|p_observation)\.[a-z_]+(?:::\w+)?)/gi)) {
    if (referenceType(match[1]) !== referenceType(match[2])) throw new Error(`Scalar row-type comparison mismatch ${match[1]} / ${match[2]}`);
  }
}
function assertObservationOnlyWrites(source: string, observation: string): void {
  const code = withoutComments(source).replace(/'(?:''|[^'])*'/g, "''");
  if (/\bDROP\b|\bCREATE\s+OR\s+REPLACE\b|\bALTER\s+TABLE\b|\bEXECUTE\b(?!\s+(?:FUNCTION|PROCEDURE)\b)|\bSECURITY\s+DEFINER\b/i.test(code)) throw new Error('Candidate cannot replace old definitions or introduce dynamic/privileged SQL');
  for (const match of code.matchAll(/\b(?:INSERT\s+INTO|DELETE\s+FROM|TRUNCATE\s+(?!ON\b)(?:TABLE\s+)?|UPDATE\s+(?!OR\b|ON\b|OF\b))\s*([a-z_][a-z0-9_]*)\b/gi)) {
    if (match[1].toLowerCase() !== observation) throw new Error(`Candidate writes old facts or a native/source ledger: ${match[1]}`);
  }
}
const compact = (source: string): string => source.replace(/\s+/g, ' ').trim();
function raisedGuard(body: string, message: string): string {
  const marker = `THEN RAISE EXCEPTION '${message}'`, end = body.indexOf(marker), start = body.lastIndexOf(' IF ', end);
  if (end < 0 || start < 0) throw new Error(`Missing failing guard ${message}`);
  return compact(body.slice(start + 4, end));
}
function requirePredicates(guard: string, predicates: readonly string[]): void {
  for (const predicate of predicates) if (!guard.includes(predicate)) throw new Error(`Missing necessary rejection: ${predicate}`);
}
function requireRowPairs(guard: string, expected: ReadonlyArray<readonly [string, string]>): void {
  const pairs = rowComparisons(guard).flatMap(row => row.left.map((left, index) => [compact(left), compact(row.right[index])]));
  for (const [left, right] of expected) if (!pairs.some(pair => pair[0] === left && pair[1] === right)) throw new Error(`Missing exact tuple comparison ${left} / ${right}`);
}
type Trigger = { constraint: boolean; timing: string; events: string; table: string; deferred: boolean; row: boolean; function: string };
function triggersOf(source: string): Trigger[] {
  const code = withoutComments(source).replace(/(\$(?:[a-z_][a-z0-9_]*)?\$)[\s\S]*?\1/gi, value => ' '.repeat(value.length));
  return [...code.matchAll(/\bCREATE\s+(CONSTRAINT\s+)?TRIGGER\s+\w+\s+(BEFORE|AFTER)\s+([\s\S]*?)\s+ON\s+(\w+)\s+([\s\S]*?)EXECUTE FUNCTION\s+(\w+)\(\)\s*;/gi)].map(match => ({
    constraint: !!match[1], timing: match[2], events: compact(match[3]), table: match[4], deferred: /DEFERRABLE INITIALLY DEFERRED/i.test(match[5]), row: /FOR EACH ROW/i.test(match[5]), function: match[6],
  }));
}
function assertLifecycleTriggers(source: string): void {
  const triggers = triggersOf(source), mutable = ['mutation_operations', 'workflow_executions', 'workflow_steps', 'workflows'];
  const exactlyOne = (predicate: (trigger: Trigger) => boolean) => { if (triggers.filter(predicate).length !== 1) throw new Error('Missing or duplicated lifecycle trigger'); };
  exactlyOne(trigger => trigger.table === observation && trigger.timing === 'BEFORE' && trigger.events === 'INSERT' && trigger.row && trigger.function === 'm11_target_result_observation_insert');
  exactlyOne(trigger => trigger.table === observation && trigger.timing === 'AFTER' && trigger.events === 'INSERT' && trigger.constraint && trigger.deferred && trigger.row && trigger.function === 'm11_target_result_observation_complete');
  for (const table of mutable) {
    exactlyOne(trigger => trigger.table === table && trigger.timing === 'BEFORE' && trigger.events === 'UPDATE' && trigger.row && trigger.function === 'm11_target_result_state_guard');
    exactlyOne(trigger => trigger.table === table && trigger.timing === 'AFTER' && trigger.events === 'UPDATE' && trigger.constraint && trigger.deferred && trigger.row && trigger.function === 'm11_target_result_observation_complete');
  }
  exactlyOne(trigger => trigger.table === observation && trigger.timing === 'BEFORE' && trigger.events === 'UPDATE OR DELETE' && trigger.row && trigger.function === 'm8_immutable');
  exactlyOne(trigger => trigger.table === observation && trigger.timing === 'BEFORE' && trigger.events === 'TRUNCATE' && !trigger.row && trigger.function === 'm8_immutable');
}
const historicalSources = frozenMigrations.map(([name]) => readFileSync(resolve(directory, name), 'utf8'));
const observation = 'entity_change_target_result_observations';
function candidateSource(): string { return readFileSync(resolve(directory, '027_m11_target_result_observations.sql'), 'utf8'); }

/** Source-only tests. No SQL driver, child process, HTTP client, runtime state
 * or private proof files are imported. Passing cannot prove DB admission. */
describe('SQL027 observation source schema verifier', () => {
  it('freezes all 0–25 migration bytes independently of the database ledger', () => {
    expect(frozenMigrations).toHaveLength(26);
    for (const [name, digest] of frozenMigrations) expect(createHash('sha256').update(readFileSync(resolve(directory, name))).digest('hex'), name).toBe(digest);
  });
  it('models the real legacy UUID/TEXT identities, revisions and complete unique tuples', () => {
    const schema = schemaOf(historicalSources);
    for (const table of ['workflows', 'workflow_executions', 'workflow_steps']) {
      expect(schema.get(table)?.columns.get('id')?.type).toBe('uuid');
      expect(schema.get(table)?.columns.get('revision')?.type).toBe('integer');
    }
    expect(schema.get('mutation_operations')?.columns.get('entity_id')?.type).toBe('text');
    expect(schema.get('mutation_operations')?.columns.get('parent_id')?.type).toBe('text');
    expect(schema.get('entity_change_packet_attempts')?.columns.get('native_id')?.type).toBe('uuid');
    expect(schema.get('entity_change_packet_events')?.unique).toContainEqual(['attempt_id', 'event_kind']);
    expect(schema.get('mutation_operations')?.unique).toContainEqual(['entity_change_attempt_id']);
  });
  it('accepts only real typed composite FK bijections backed by a complete unique key', () => {
    const old = schemaOf(['CREATE TABLE original(cluster_id uuid NOT NULL,id uuid NOT NULL,revision integer NOT NULL,UNIQUE(cluster_id,id,revision));']);
    const newTable = (localType: string, remote: string) => schemaOf([`CREATE TABLE observation(cluster_id uuid NOT NULL,id ${localType} NOT NULL,revision integer NOT NULL,FOREIGN KEY(cluster_id,id,revision) REFERENCES original(${remote}) ON DELETE RESTRICT);`]);
    expect(() => assertForeignKeys(newTable('uuid', 'cluster_id,id,revision'), old)).not.toThrow();
    expect(() => assertForeignKeys(newTable('text', 'cluster_id,id,revision'), old)).toThrow(/type\/column/);
    expect(() => assertForeignKeys(newTable('uuid', 'cluster_id,missing,revision'), old)).toThrow(/type\/column/);
    expect(() => assertForeignKeys(newTable('uuid', 'cluster_id,id,id'), old)).toThrow(/bijection/);
    const partial = schemaOf(['CREATE TABLE observation(cluster_id uuid NOT NULL,id uuid NOT NULL,FOREIGN KEY(cluster_id,id) REFERENCES original(cluster_id,id) ON DELETE RESTRICT);']);
    expect(() => assertForeignKeys(partial, old)).toThrow(/complete unique tuple/);
  });
  it('does not treat comments, function strings or partial indexes as DDL guarantees', () => {
    const schema = schemaOf(["-- CREATE TABLE fake(id uuid PRIMARY KEY);\nCREATE TABLE original(id uuid NOT NULL,state text NOT NULL); CREATE UNIQUE INDEX partial_key ON original(id) WHERE state='succeeded'; DO $$ BEGIN EXECUTE 'CREATE TABLE fake(id uuid PRIMARY KEY)'; END; $$;"]);
    expect(schema.has('fake')).toBe(false);
    const candidate = schemaOf(['CREATE TABLE observation(id uuid NOT NULL REFERENCES original(id) ON DELETE RESTRICT);']);
    expect(() => assertForeignKeys(candidate, schema)).toThrow(/complete unique tuple/);
    const literal = schemaOf(["CREATE TABLE original(id uuid NOT NULL CHECK('UNIQUE' <> ''),CHECK('PRIMARY KEY(id)' <> '')); "]);
    expect(literal.get('original')?.unique).toEqual([]);
    expect(() => schemaOf(['CREATE TABLE observation(id uuid,FOREIGN KEY(id) REFERENCES original ON DELETE RESTRICT);'])).toThrow(/explicit referenced columns/);
  });
  it('detects old-fact and fake-receipt writes even inside a new trigger function', () => {
    const body = (statement: string) => `CREATE FUNCTION guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${statement} RETURN NEW; END; $$;`;
    expect(() => assertObservationOnlyWrites(body('SELECT state FROM mutation_operations FOR UPDATE;'), 'observation')).not.toThrow();
    expect(() => assertObservationOnlyWrites('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON observation FOR EACH ROW EXECUTE FUNCTION m8_immutable(); CREATE TRIGGER no_truncate BEFORE TRUNCATE ON observation FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();', 'observation')).not.toThrow();
    expect(() => assertObservationOnlyWrites(body("RAISE EXCEPTION 'UPDATE mutation_operations is prohibited';"), 'observation')).not.toThrow();
    for (const statement of [
      "UPDATE mutation_operations SET state='succeeded';", "UPDATE workflows SET state='succeeded';", "DELETE FROM entity_change_packet_events;",
      'INSERT INTO entity_change_execution_sources(id) VALUES(NEW.id);', 'INSERT INTO entity_change_packet_events(id) VALUES(NEW.id);',
      'INSERT INTO entity_change_packet_attempts(id) VALUES(NEW.id);', 'TRUNCATE TABLE workflow_executions;',
    ]) expect(() => assertObservationOnlyWrites(body(statement), 'observation')).toThrow(/writes old facts/);
    for (const statement of ['DROP TRIGGER old_guard ON mutation_operations;', 'ALTER TABLE workflows DROP CONSTRAINT frozen;', "EXECUTE 'SELECT 1';", 'CREATE OR REPLACE FUNCTION old_guard() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql;']) {
      expect(() => assertObservationOnlyWrites(statement, 'observation')).toThrow(/replace old definitions/);
    }
  });
  it('requires exactly one separately named 027 candidate instead of modifying an earlier migration', () => {
    const candidates = readdirSync(directory).filter(name => /^027_.*\.sql$/.test(name));
    expect(candidates).toHaveLength(1);
  });
  it('anchors every candidate FK to a real 0–25 typed column and existing complete unique tuple', () => {
    const candidate = schemaOf([candidateSource()]), historical = schemaOf(historicalSources);
    expect([...candidate.keys()]).toEqual([observation]);
    const table = candidate.get(observation)!;
    expect(table.foreignKeys).toHaveLength(14);
    expect(table.foreignKeys.every(fk => historical.has(fk.table))).toBe(true);
    expect(table.foreignKeys.every(fk => fk.local.every(column => table.columns.get(column)?.notNull))).toBe(true);
    expect(() => assertForeignKeys(candidate, historical)).not.toThrow();
    const anchored: Record<string, string[]> = {
      entity_change_execution_sources: ['cluster_id', 'workspace_id', 'id', 'intent_id', 'intent_revision', 'material_hmac', 'change_digest', 'packet_manifest_hmac', 'workflow_id', 'workflow_plan_revision', 'workflow_plan_hash', 'workflow_execution_id', 'execution_actor_id', 'credential_epoch'],
      entity_change_baselines: ['cluster_id', 'workspace_id', 'id', 'source_id', 'workflow_execution_id', 'baseline_hmac', 'object_manifest_hmac'],
      entity_change_baseline_pins: ['cluster_id', 'workspace_id', 'id', 'baseline_id', 'source_id', 'workflow_execution_id'],
      entity_change_packet_attempts: ['cluster_id', 'workspace_id', 'id', 'source_id', 'baseline_id', 'pin_id', 'workflow_execution_id'],
      entity_change_intent_packets: ['cluster_id', 'workspace_id', 'intent_id', 'intent_revision', 'packet_key', 'packet_order', 'material_hmac', 'change_digest', 'packet_manifest_hmac', 'method', 'path_hmac', 'native_type', 'native_id', 'permission_action', 'mutation_action', 'body_hmac', 'before_hmac'],
      mutation_operations: ['cluster_id', 'workspace_id', 'id'], workflow_executions: ['cluster_id', 'workspace_id', 'id', 'workflow_id', 'plan_revision', 'plan_hash'],
      workflow_steps: ['cluster_id', 'workspace_id', 'id', 'workflow_id', 'plan_revision', 'plan_hash'], workflow_approval_sets: ['cluster_id', 'workspace_id', 'id', 'set_hmac', 'workflow_id', 'plan_revision', 'plan_hash'],
      audit_events: ['id', 'event_hash'],
    };
    for (const [target, tuple] of Object.entries(anchored)) expect(table.foreignKeys.filter(fk => fk.table === target).map(fk => fk.remote)).toEqual([tuple]);
    for (const name of ['cluster_id', 'workspace_id', 'parent_id', 'original_native_id', 'native_id', 'operation_id', 'workflow_execution_id', 'workflow_step_id']) {
      expect(table.columns.get(name)).toEqual({ type: 'uuid', notNull: true });
    }
    for (const name of ['workflow_revision_before', 'execution_revision_before', 'step_revision_before']) expect(table.columns.get(name)).toEqual({ type: 'integer', notNull: true });
    const swapped = schemaOf([candidateSource().replace('FOREIGN KEY(cluster_id,workspace_id,source_id', 'FOREIGN KEY(workspace_id,cluster_id,source_id')]);
    expect(() => assertForeignKeys(swapped, historical)).toThrow(/scope mismatch/);
  });
  it('validates every declared row-type field and comparison, including the required UUID to TEXT casts', () => {
    const source = candidateSource(), schema = schemaOf([...historicalSources, source]), body = sqlFunction(source, 'm11_validate_target_result_observation');
    const names = [...source.matchAll(/\bCREATE FUNCTION\s+(\w+)\(/g)].map(match => match[1]);
    expect(names).toHaveLength(4);
    for (const name of names) expect(() => assertTypedRowReferences(sqlFunction(source, name), schema, observation), name).not.toThrow();
    expect(() => assertTypedRowReferences(body.replace('v_mutation.state', 'v_mutation.revision'), schema, observation)).toThrow(/Unknown row-type field/);
    expect(() => assertTypedRowReferences(body.replace('p_observation.native_id::text', 'p_observation.native_id'), schema, observation)).toThrow(/comparison mismatch/);
    expect(() => assertTypedRowReferences(body.replace('p_observation.workflow_id::text', 'p_observation.workflow_id'), schema, observation)).toThrow(/comparison mismatch/);
    expect(() => assertTypedRowReferences(body.replace('v_step.entity_id', 'v_step.missing_id'), schema, observation)).toThrow(/Unknown row-type field/);
  });
  it('adds only observation DDL and read-only guards without replacing old SQL or manufacturing native/source facts', () => {
    expect(() => assertObservationOnlyWrites(candidateSource(), observation)).not.toThrow();
  });
  it('confines the new encrypted observation to version one HTTP single-packet Target weight zero', () => {
    const source = candidateSource(), code = compact(withoutComments(source)), table = schemaOf([source]).get(observation)!;
    for (const predicate of ["CHECK(version=1)", "CHECK(proof_kind='target-weight-zero-original-response-v1')", "CHECK(method='POST')", "CHECK(native_type='targets')", "CHECK(permission_action='write')", "CHECK(mutation_action='update')", 'CHECK(weight=0)', 'CHECK(packet_order=1)', 'CHECK(certified_native_status=201)', 'CHECK(m6_encrypted(observation_ciphertext,12582912))', 'CHECK(original_native_id<>native_id AND send_event_id<>outcome_event_id)']) expect(code).toContain(predicate);
    for (const field of ['source_id', 'workflow_id', 'workflow_execution_id', 'workflow_step_id', 'attempt_id', 'operation_id', 'send_event_id', 'outcome_event_id', 'audit_id']) expect(table.unique).toContainEqual([field]);
    for (const field of ['result_hmac', 'producer_attestation_hmac', 'history_proof_hmac', 'current_observation_hmac', 'observation_hmac', 'send_fact_hmac', 'outcome_fact_hmac']) expect(table.columns.get(field)).toEqual({ type: 'text', notNull: true });
    for (const field of ['native_response', 'body', 'payload_secret', 'result_secret', 'credential_key']) expect(table.columns.has(field)).toBe(false);
    const body = sqlFunction(source, 'm11_validate_target_result_observation'), guard = raisedGuard(body, 'Observation requires one original HTTP Target attempt and complete frozen before facts');
    const necessary = ["v_source.origin_type<>'http'", 'v_source.session_id IS NULL', 'v_source.expires_at>clock_timestamp()', 'v_version.packet_count<>1', "v_version.execution_mode<>'approval'", "v_baseline.readiness<>'ready'", 'v_baseline.object_count<>3', 'v_baseline.graph_count<>1', 'v_pin.pin_version<>1', 'v_pin.previous_pin_id IS NOT NULL', '(SELECT count(*) FROM entity_change_packet_attempts WHERE source_id=v_source.id)<>1', '(SELECT count(*) FROM mutation_operations WHERE entity_change_source_id=v_source.id)<>1', '(SELECT count(*) FROM entity_change_packet_events WHERE source_id=v_source.id)<>2'];
    expect(() => requirePredicates(guard, necessary)).not.toThrow();
    expect(() => requirePredicates(guard.replace('v_version.packet_count<>1', 'v_version.packet_count<1'), necessary)).toThrow(/necessary rejection/);
  });
  it('requires original-present, allocated-absent and real-parent baseline identities rather than object existence alone', () => {
    const body = sqlFunction(candidateSource(), 'm11_validate_target_result_observation');
    const guard = raisedGuard(body, 'Observation is confined to the exact allocated Target append and its original parent/before/absence');
    const necessary = [
      "v_packet.dependencies<>'{}'::text[]", 'old_target.baseline_id=v_baseline.id', "old_target.native_type='targets'", 'old_target.native_id=p_observation.original_native_id', 'old_target.parent_id=p_observation.parent_id', 'old_target.credential_kind IS NULL', "old_target.affected AND old_target.present AND old_target.recovery='complete'", 'old_target.before_hmac=p_observation.before_hmac',
      'allocated_target.baseline_id=v_baseline.id', 'allocated_target.native_id=p_observation.native_id', 'allocated_target.parent_id=p_observation.parent_id', "allocated_target.affected AND NOT allocated_target.present AND allocated_target.recovery='absent'",
      'parent_object.baseline_id=v_baseline.id', "parent_object.native_type='upstreams'", 'parent_object.native_id=p_observation.parent_id', 'parent_object.parent_id IS NULL', "NOT parent_object.affected AND parent_object.present AND parent_object.recovery='reference'",
    ];
    expect(() => requirePredicates(guard, necessary)).not.toThrow();
    expect(() => requirePredicates(guard.replace('old_target.native_id=p_observation.original_native_id', 'true'), necessary)).toThrow(/necessary rejection/);
    requireRowPairs(guard, [['v_attempt.parent_id', 'p_observation.parent_id'], ['v_attempt.original_native_id', 'p_observation.original_native_id'], ['v_packet.original_native_id', 'p_observation.original_native_id'], ['v_attempt.method', "'POST'::text"], ['v_attempt.native_type', "'targets'::text"], ['v_attempt.mutation_action', "'update'::text"]]);
  });
  it('ties saved mutation facts to the exact scoped V3 tuple and retains the actual original error and response', () => {
    const guard = raisedGuard(sqlFunction(candidateSource(), 'm11_validate_target_result_observation'), 'Observation cannot change the original V3 ledger identity, saved response or namespace');
    const exact = ['cluster_id', 'workspace_id', 'workflow_id', 'actor_id', 'entity_change_source_id', 'entity_change_baseline_id', 'entity_change_attempt_id', 'entity_change_packet_key'];
    const counterparts = ['cluster_id', 'workspace_id', 'workflow_id', 'execution_actor_id', 'source_id', 'baseline_id', 'attempt_id', 'packet_key'];
    const pairs = exact.map((field, index) => [`v_mutation.${field}`, `p_observation.${counterparts[index]}`] as const);
    expect(() => requireRowPairs(guard, pairs)).not.toThrow();
    expect(() => requireRowPairs(guard.replace('p_observation.workspace_id', 'p_observation.cluster_id'), pairs)).toThrow(/exact tuple/);
    requirePredicates(guard, ["v_mutation.entity_type<>'targets'", "v_mutation.action<>'update'", 'v_mutation.parent_id IS DISTINCT FROM p_observation.parent_id::text', 'v_mutation.entity_id IS DISTINCT FROM p_observation.native_id::text', 'v_mutation.credential_kind IS NOT NULL', 'v_mutation.transport_scope IS DISTINCT FROM p_observation.transport_scope', 'v_mutation.idempotency_key IS DISTINCT FROM p_observation.operation_key', 'NOT v_mutation.remote_started', 'NOT v_mutation.remote_completed', 'v_mutation.result_secret IS NULL', 'v_mutation.before_secret IS NULL', 'v_mutation.payload_secret IS NULL', "v_mutation.error_code IS DISTINCT FROM 'KONG_VALIDATION_ERROR'", 'num_nonnulls(v_mutation.workflow_execution_id,v_mutation.workflow_plan_revision,v_mutation.workflow_plan_hash,v_mutation.workflow_step_id, v_mutation.configuration_job_id,v_mutation.configuration_execution_id,v_mutation.configuration_step_id,v_mutation.configuration_plan_revision,v_mutation.configuration_plan_hash)<>0']);
  });
  it('uses insert/complete phases to require all four original states and exact CAS revisions atomically', () => {
    const source = candidateSource(), body = sqlFunction(source, 'm11_validate_target_result_observation');
    requirePredicates(compact(body), ["p_phase NOT IN('insert','complete')", "v_expected_state=CASE WHEN p_phase='insert' THEN 'uncertain' ELSE 'succeeded' END", "v_increment=CASE WHEN p_phase='insert' THEN 0 ELSE 1 END"]);
    requirePredicates(compact(sqlFunction(source, 'm11_target_result_observation_insert')), ["m11_validate_target_result_observation(NEW,'insert')", "'entity-schedule-impact:'||NEW.transport_scope", "'entity-change-attempt:'||NEW.attempt_id::text"]);
    requirePredicates(compact(sqlFunction(source, 'm11_target_result_observation_complete')), ["m11_validate_target_result_observation(v_observation,'complete')"]);
    requirePredicates(raisedGuard(body, 'Observation cannot change the original V3 ledger identity, saved response or namespace'), ['v_mutation.state IS DISTINCT FROM v_expected_state']);
    const guard = raisedGuard(body, 'All original metadata states and CAS revisions must describe the same approved execution');
    const necessary = ['v_workflow.state IS DISTINCT FROM v_expected_state', 'v_execution.state IS DISTINCT FROM v_expected_state', 'v_step.state IS DISTINCT FROM v_expected_state', 'v_workflow.revision<>p_observation.workflow_revision_before+v_increment', 'v_execution.revision<>p_observation.execution_revision_before+v_increment', 'v_step.revision<>p_observation.step_revision_before+v_increment', 'v_execution.idempotency_key IS DISTINCT FROM p_observation.original_execution_key', 'v_execution.snapshot_id IS DISTINCT FROM p_observation.baseline_id', "v_execution.snapshot_state<>'ready'", 'v_execution.completed_at IS NULL', 'v_step.completed_at IS NULL', 'v_step.operation_id IS NOT NULL', 'v_step.receipt_secret IS NOT NULL'];
    expect(() => requirePredicates(guard, necessary)).not.toThrow();
    expect(() => requirePredicates(guard.replace('v_step.state IS DISTINCT FROM v_expected_state', 'false'), necessary)).toThrow(/necessary rejection/);
    expect(() => assertLifecycleTriggers(source)).not.toThrow();
    expect(() => assertLifecycleTriggers(source.replace(/CREATE CONSTRAINT TRIGGER step_target_result_observation_complete[^;]+;/, ''))).toThrow(/lifecycle trigger/);
  });
  it('preserves both original event identities, sent-unknown and NULL status without manufacturing a replacement outcome', () => {
    const guard = raisedGuard(sqlFunction(candidateSource(), 'm11_validate_target_result_observation'), 'Original sent-unknown events and NULL native status must remain untouched');
    const shared = ['cluster_id', 'workspace_id', 'attempt_id', 'source_id', 'baseline_id', 'pin_id', 'workflow_execution_id'];
    for (const alias of ['v_send', 'v_outcome']) requireRowPairs(guard, shared.map(field => [`${alias}.${field}`, `p_observation.${field}`] as const));
    requireRowPairs(guard, [['v_send.event_kind', "'send-intent'::text"], ['v_send.fact_hmac', 'p_observation.send_fact_hmac'], ['v_outcome.event_kind', "'outcome'::text"], ['v_outcome.fact_hmac', 'p_observation.outcome_fact_hmac']]);
    const necessary = ['v_send.outcome IS NOT NULL', 'v_send.native_status IS NOT NULL', 'v_send.error_code IS NOT NULL', "v_outcome.outcome IS DISTINCT FROM 'sent-unknown'", 'v_outcome.native_status IS NOT NULL', "v_outcome.error_code IS DISTINCT FROM 'MUTATION_RESULT_UNCERTAIN'", 'v_send.observed_at>v_outcome.observed_at', 'v_outcome.observed_at>p_observation.current_observed_at'];
    expect(() => requirePredicates(guard, necessary)).not.toThrow();
    expect(() => requirePredicates(guard.replace('v_outcome.native_status IS NOT NULL', 'v_outcome.native_status<>201'), necessary)).toThrow(/necessary rejection/);
  });
  it('requires the live current actor/session and unchanged epoch, permissions and cluster/workspace scope', () => {
    const body = sqlFunction(candidateSource(), 'm11_validate_target_result_observation'), guard = raisedGuard(body, 'Metadata observation requires the real current original actor and unchanged scope');
    const necessary = ["v_user.status<>'active'", 'v_user.deleted_at IS NOT NULL', 'v_user.force_password_change', 'v_user.credential_epoch IS DISTINCT FROM p_observation.credential_epoch', 'v_session.user_id IS DISTINCT FROM p_observation.execution_actor_id', 'v_session.credential_epoch IS DISTINCT FROM p_observation.credential_epoch', 'v_session.revoked_at IS NOT NULL', 'v_session.expires_at<=clock_timestamp()', 'v_cluster.revision<>p_observation.cluster_revision', 'v_cluster.transport_scope IS NOT NULL AND v_cluster.transport_scope IS DISTINCT FROM p_observation.transport_scope', "v_cluster.execution_mode<>'approval'", "v_workspace.status<>'active'", 'v_workspace.revision<>p_observation.workspace_revision'];
    expect(() => requirePredicates(guard, necessary)).not.toThrow();
    expect(() => requirePredicates(guard.replace('v_session.expires_at<=clock_timestamp()', 'false'), necessary)).toThrow(/necessary rejection/);
    expect(body).toContain('FROM auth_sessions WHERE id=p_observation.metadata_session_id FOR SHARE');
    expect(body).toContain('v_source.permission_version_hmac IS DISTINCT FROM p_observation.permission_version_hmac');
    expect(guard).not.toMatch(/v_session\.id\s*(?:=|<>|IS (?:NOT )?DISTINCT FROM)\s*v_source\.session_id/);
  });
  it('requires scoped typed audit evidence for metadata-only reconciliation and preserves original NULL status', () => {
    const guard = raisedGuard(sqlFunction(candidateSource(), 'm11_validate_target_result_observation'), 'A unique scoped audit and authenticated observation must commit with the original states');
    requireRowPairs(guard, [['v_audit.cluster_id', 'p_observation.cluster_id'], ['v_audit.workspace_id', 'p_observation.workspace_id'], ['v_audit.workflow_id', 'p_observation.workflow_id'], ['v_audit.actor_id', 'p_observation.execution_actor_id'], ['v_audit.entity_id', 'p_observation.workflow_id::text'], ['v_audit.action', "'workflow.execute.target-result-reconciled'::text"], ['v_audit.result', "'success'::text"]]);
    const necessary = ['v_audit_scope.cluster_id IS DISTINCT FROM p_observation.cluster_id', 'v_audit_scope.workspace_id IS DISTINCT FROM p_observation.workspace_id', 'v_audit_scope.audit_event_hash IS DISTINCT FROM p_observation.audit_event_hash', "v_audit_scope.scope->>'quality' IS DISTINCT FROM 'verified'", "v_audit.after->>'observationId' IS DISTINCT FROM p_observation.id::text", "v_audit.after->>'observationHmac' IS DISTINCT FROM p_observation.observation_hmac", "v_audit.after->>'originalOutcome' IS DISTINCT FROM 'sent-unknown'", "v_audit.after->'nativeStatusRecorded' IS DISTINCT FROM 'null'::jsonb", "v_audit.after->'certifiedNativeStatus' IS DISTINCT FROM '201'::jsonb", "v_audit.after->'nativeRequestsSent' IS DISTINCT FROM '0'::jsonb", "v_audit.after->'metadataReconciled' IS DISTINCT FROM 'true'::jsonb"];
    expect(() => requirePredicates(guard, necessary)).not.toThrow();
    expect(() => requirePredicates(guard.replace('v_audit_scope.workspace_id IS DISTINCT FROM p_observation.workspace_id', 'false'), necessary)).toThrow(/necessary rejection/);
  });
  it('requires an observation for V3 closure and limits CAS changes to state, revision and safe projection', () => {
    const body = compact(sqlFunction(candidateSource(), 'm11_target_result_state_guard'));
    const necessary = ["IF OLD.state<>'uncertain' OR NEW.state<>'succeeded' THEN RETURN NEW", 'WHERE operation_id=OLD.id AND attempt_id=OLD.entity_change_attempt_id', 'v_observation.id IS NULL OR v_observation.source_id IS DISTINCT FROM OLD.entity_change_source_id', 'v_observation.baseline_id IS DISTINCT FROM OLD.entity_change_baseline_id', 'v_observation.packet_key IS DISTINCT FROM OLD.entity_change_packet_key', 'v_observation.cluster_id IS DISTINCT FROM OLD.cluster_id', 'v_observation.workspace_id IS DISTINCT FROM OLD.workspace_id', 'OLD.revision IS DISTINCT FROM v_revision', 'NEW.revision<>OLD.revision+1'];
    expect(() => requirePredicates(body, necessary)).not.toThrow();
    expect(() => requirePredicates(body.replace('v_observation.workspace_id IS DISTINCT FROM OLD.workspace_id', 'false'), necessary)).toThrow(/necessary rejection/);
    expect(() => requirePredicates(body.replace('v_observation.id IS NULL OR v_observation.source_id IS DISTINCT FROM OLD.entity_change_source_id', 'v_observation.id IS NULL'), necessary)).toThrow(/necessary rejection/);
    const exclusions = [...body.matchAll(/to_jsonb\((NEW|OLD)\)-ARRAY\[([^\]]+)\]/g)].map(match => ({ record: match[1], allowed: pieces(match[2]).map(value => value.replace(/^'|'$/g, '')) }));
    expect(exclusions).toEqual([
      { record: 'NEW', allowed: ['state', 'updated_at', 'safe_result'] }, { record: 'OLD', allowed: ['state', 'updated_at', 'safe_result'] },
      { record: 'NEW', allowed: ['state', 'revision', 'updated_at', 'safe_result'] }, { record: 'OLD', allowed: ['state', 'revision', 'updated_at', 'safe_result'] },
    ]);
    expect(body).not.toMatch(/IF v_observation\.id IS NULL THEN RETURN NEW/);
  });
  it('makes observations immutable while treating PUBLIC revocation as separate from actual runtime-role grants', () => {
    const source = candidateSource(), code = compact(withoutComments(source));
    expect(() => assertLifecycleTriggers(source)).not.toThrow();
    expect(code).toContain(`REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON ${observation} FROM PUBLIC`);
    expect(code).not.toMatch(/\bGRANT\b/);
    expect(source).toContain('this PUBLIC revoke does not replace that step');
    expect(code).not.toMatch(/FUNCTION\s+m11_(?:validate_entity_recovery_link|entity_baseline_pin_active|validate_packet_event)\s*\(/);
  });
});
