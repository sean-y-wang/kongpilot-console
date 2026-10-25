import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const transport = vi.hoisted(() => ({ query: vi.fn(), connect: vi.fn(), release: vi.fn(), on: vi.fn(), end: vi.fn() }));
vi.mock('pg', () => ({ Pool: class {
  query = transport.query; connect = transport.connect; on = transport.on; end = transport.end;
} }));
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';

/** Source contracts and actual DbService orchestration over an explicit fake
 * PostgreSQL transport only. No SQL is executed; Root owns real empty-path
 * vectors, catalog/OID comparisons and unmodified custom-dump restoration. */
const directory = fileURLToPath(new URL('../../apps/console-api/src/infrastructure/migrations/', import.meta.url));
const prefix = 'apps/console-api/src/infrastructure/migrations/';
const migrationName = '037_m11_restore_check_function_search_path.sql';
const sql = readFileSync(join(directory, migrationName), 'utf8');
const currentFiles = readdirSync(directory).filter(name => /^\d+_[\w-]+\.sql$/.test(name)).sort();
const currentMigrations = currentFiles.map(name => ({ name, source: readFileSync(join(directory, name), 'utf8') }));
const historicalFiles = readdirSync(directory).filter(name => /^\d+_[\w-]+\.sql$/.test(name) && parseInt(name, 10) <= 36).sort();
const historical = historicalFiles.map(name => ({ name, source: readFileSync(join(directory, name), 'utf8') }));
const sha = (value: string) => createHash('sha256').update(value).digest('hex');
const oldLedger = () => historical.map(({ name, source }) => ({ name, checksum: sha(source) }));
const code = sql.replace(/--[^\n]*/g, '').trim();
const expected = [
  ['m7_historical_scope', 'jsonb'],
  ['m7_filter', 'text[], text, uuid[], text[]'],
  ['m7_observation_value', 'text, text, jsonb'],
  ['m7_event_payload', 'jsonb'],
] as const;

interface Definition { name: string; arguments: string; body: string; file: string }
const declarations: Definition[] = [];
for (const { name: file, source } of historical) {
  const pattern = /CREATE(?:\s+OR\s+REPLACE)?\s+FUNCTION\s+(?:public\.)?([a-z][\w]*)\s*\(([\s\S]*?)\)\s+RETURNS\b[\s\S]*?\bAS\s+\$([\w]*)\$([\s\S]*?)\$\3\$\s*;/gi;
  for (const match of source.matchAll(pattern)) declarations.push({ name: match[1], arguments: match[2], body: match[4], file });
}
const functions = new Map(declarations.map(value => [value.name, value]));
const applicationNames = [...functions.keys()];
const calls = (source: string) => applicationNames.filter(name => new RegExp(`(?<![\\w.])${name}\\s*\\(`, 'i').test(source));

// Balanced CHECK extraction respects quoted SQL text; a CHECK's surrounding
// table declaration is not mistaken for a dependency of the function body.
function closingParen(source: string, start: number): number {
  let depth = 0, quote = '';
  for (let index = start; index < source.length; index++) {
    const ch = source[index];
    if (quote) {
      if (ch === quote) { if (source[index + 1] === quote) index++; else quote = ''; }
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === '(') depth++;
    if (ch === ')' && --depth === 0) return index;
  }
  throw new Error('Unbalanced historical CHECK expression');
}
const checks: { file: string; expression: string; functions: string[] }[] = [];
for (const { name: file, source } of historical) {
  for (const match of source.matchAll(/\bCHECK\s*\(/gi)) {
    const open = match.index! + match[0].lastIndexOf('('), close = closingParen(source, open);
    const expression = source.slice(open + 1, close), dependencies = calls(expression);
    if (dependencies.length) checks.push({ file, expression, functions: dependencies });
  }
}
const roots = new Set(checks.flatMap(check => check.functions));
const closure = new Set(roots);
for (const name of closure) for (const dependency of calls(functions.get(name)!.body)) closure.add(dependency);
const wrappers = [...closure].filter(name => calls(functions.get(name)!.body).length > 0).sort();

function databaseFixture(options: { failAlter?: boolean; currentLedger?: boolean; omitMigration?: string; tamperChecksum?: string } = {}) {
  const ledger = (options.currentLedger ? currentMigrations.map(({name,source})=>({name,checksum:sha(source)})) : oldLedger())
    .filter(row=>row.name!==options.omitMigration).map(row=>row.name===options.tamperChecksum?{...row,checksum:'0'.repeat(64)}:row);
  let applying: {name:string;source:string}|undefined;
  const queries: { sql: string; params: unknown[] }[] = [];
  transport.query.mockImplementation(async (statement: string, params: unknown[] = []) => {
    queries.push({ sql: statement, params });
    if (statement === 'SELECT name, checksum FROM schema_migrations ORDER BY name') return { rows: ledger, rowCount: ledger.length };
    if (statement === "SELECT id FROM users WHERE super_admin = true AND status = 'active' LIMIT 1") return { rows: [{ id: 'source-only-existing-admin' }], rowCount: 1 };
    const migration = currentMigrations.find(value=>value.source===statement);
    if (migration) {
      applying=migration;
      if (migration.name===migrationName && options.failAlter) throw Object.assign(new Error('synthetic missing exact function signature'), { code: '42883' });
      return { rows: [], rowCount: 0 };
    }
    if (statement === 'INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)') {
      expect(applying).toBeDefined(); expect(params).toEqual([applying!.name, sha(applying!.source)]); return { rows: [], rowCount: 1 };
    }
    if (['SELECT pg_advisory_lock($1)', 'SELECT pg_advisory_unlock($1)'].includes(statement)) {
      expect(params).toEqual([1545015001]); return { rows: [], rowCount: 1 };
    }
    if (statement === 'CREATE TABLE IF NOT EXISTS schema_migrations (\n        name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())'
      || ['BEGIN', 'COMMIT', 'ROLLBACK'].includes(statement)) return { rows: [], rowCount: 0 };
    throw new Error('UNEXPECTED_SOURCE_FIXTURE_SQL');
  });
  transport.connect.mockResolvedValue({ query: transport.query, release: transport.release });
  return { db: new DbService(), queries };
}

beforeEach(() => { vi.clearAllMocks(); vi.stubEnv('DATABASE_URL', 'postgres://source-only:synthetic@db.invalid/kongpilot'); });
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

describe('SQL037 fixes only CHECK-wrapper lookup without rewriting history', () => {
  it('preserves all original 000–036 migration bytes, including function bodies, CHECKs and SQL026 pins', () => {
    expect(historicalFiles).toHaveLength(37);
    const manifest = historical.map(({ name, source }) => `${prefix}${name}\0${sha(source)}\n`).join('');
    expect(sha(manifest)).toBe('f5de558e6b12c24c888f080c0bee13bcc447c9b23e19414051e0f216df06198d');
  });

  it('contains exactly the four schema-qualified ALTER signatures and the catalog/public/temp-last path', () => {
    const statements = code.split(';').map(value => value.trim().replace(/\s+/g, ' ')).filter(Boolean);
    expect(statements).toEqual(expected.map(([name, args]) => `ALTER FUNCTION public.${name}(${args}) SET search_path = pg_catalog, public, pg_temp`));
    expect(code).not.toMatch(/\bCREATE\b|\bDROP\b|\bGRANT\b|\bREVOKE\b|\bSECURITY\b|\bOWNER\b|\bUPDATE\b|\bDELETE\b|\bINSERT\b|\bTRUNCATE\b|\bALTER\s+TABLE\b|session_replication_role|SET\s+CONSTRAINTS|DISABLE\s+TRIGGER|\bDO\b|\$\$/i);
  });

  it('derives the exact minimal repair from every historical CHECK root and its application dependencies', () => {
    expect(declarations).toHaveLength(165); expect(functions.size).toBe(152);
    expect([...roots].sort()).toEqual(['m6_encrypted', 'm6_native_request_manifest', 'm6_portal_branding', 'm7_event_payload', 'm7_filter', 'm7_hex64', 'm7_historical_scope', 'm7_native_type', 'm7_object', 'm7_observation_value', 'm8_cipher', 'm8_hex64']);
    expect([...closure].sort()).toEqual([...roots].sort());
    expect(wrappers).toEqual(expected.map(([name]) => name).sort());
    expect(checks.filter(check => check.functions.some(name => wrappers.includes(name)))).toHaveLength(10);
  });

  it.each(expected)('uses the genuine original %s signature without recreating or replacing its body', (name, signature) => {
    const versions = declarations.filter(definition => definition.name === name);
    expect(versions).toHaveLength(1); expect(versions[0].file).toBe('010_m7_events.sql');
    expect(versions[0].arguments.split(',').map(argument => argument.trim().replace(/^\w+\s+/, '')).join(', ')).toBe(signature);
    expect(versions[0].body).toContain(name === 'm7_filter' ? 'm7_native_type(' : 'm7_object(');
  });

  it('leaves the catalog-only leaves and every M6/M8/M11 authority function outside the ALTER scope', () => {
    for (const name of [...closure].filter(name => !wrappers.includes(name))) expect(calls(functions.get(name)!.body)).toEqual([]);
    expect(code).not.toMatch(/public\.(?:m6_|m8_|m11_|m7_object\b|m7_native_type\b|m7_hex64\b)/);
  });

  it('discovers037 and all later current release migrations through the real migrator, committing each exact SQL plus checksum atomically', async () => {
    const f = databaseFixture(); await f.db.migrate();
    expect(f.queries.map(query => query.sql)).toEqual([
      'SELECT pg_advisory_lock($1)',
      'CREATE TABLE IF NOT EXISTS schema_migrations (\n        name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())',
      'SELECT name, checksum FROM schema_migrations ORDER BY name',
      ...currentMigrations.filter(value=>parseInt(value.name,10)>=37).flatMap(value=>['BEGIN',value.source,
        'INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)','COMMIT']), 'SELECT pg_advisory_unlock($1)',
    ]);
    expect(transport.release).toHaveBeenCalledOnce();
  });

  it('rolls back a failed exact-signature ALTER without a ledger insert or commit, then releases its lock', async () => {
    const f = databaseFixture({ failAlter: true }); await expect(f.db.migrate()).rejects.toMatchObject({ code: '42883' });
    expect(f.queries.map(query => query.sql).slice(-3)).toEqual([sql, 'ROLLBACK', 'SELECT pg_advisory_unlock($1)']);
    expect(f.queries.some(query => query.sql.startsWith('INSERT INTO') || query.sql === 'COMMIT')).toBe(false);
    expect(transport.release).toHaveBeenCalledOnce();
  });

  it('refuses an older runtime ledger missing037 before administrator validation or any owner migration', async () => {
    vi.stubEnv('SKIP_MIGRATIONS', 'true'); const f = databaseFixture();
    await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_MISSING:${migrationName}`);
    expect(f.queries.map(query => query.sql)).toEqual(['SELECT name, checksum FROM schema_migrations ORDER BY name']);
    expect(transport.connect).not.toHaveBeenCalled();
  });

  it.each(currentFiles.filter(name=>parseInt(name,10)>37))('refuses the current runtime ledger missing %s before administrator validation or owner writes',async name=>{
    vi.stubEnv('SKIP_MIGRATIONS','true');const f=databaseFixture({currentLedger:true,omitMigration:name});
    await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_MISSING:${name}`);
    expect(f.queries.map(query=>query.sql)).toEqual(['SELECT name, checksum FROM schema_migrations ORDER BY name']);
    expect(transport.connect).not.toHaveBeenCalled();
  });

  it.each(currentFiles.filter(name=>parseInt(name,10)>37))('refuses the current runtime ledger checksum mismatch for %s before administrator validation or owner writes',async name=>{
    vi.stubEnv('SKIP_MIGRATIONS','true');const f=databaseFixture({currentLedger:true,tamperChecksum:name});
    await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_CHECKSUM_MISMATCH:${name}`);
    expect(f.queries.map(query=>query.sql)).toEqual(['SELECT name, checksum FROM schema_migrations ORDER BY name']);
    expect(transport.connect).not.toHaveBeenCalled();
  });

  it('accepts the complete current release ledger without running ALTER or any other owner writes', async () => {
    expect(currentFiles).toEqual(expect.arrayContaining(['038_m11_durable_configuration_materials.sql','039_m11_durable_configuration_rejections.sql']));
    vi.stubEnv('SKIP_MIGRATIONS', 'true'); const f = databaseFixture({ currentLedger: true }); await f.db.onModuleInit();
    expect(f.queries.map(query => query.sql)).toEqual(['SELECT name, checksum FROM schema_migrations ORDER BY name', "SELECT id FROM users WHERE super_admin = true AND status = 'active' LIMIT 1"]);
    expect(transport.connect).not.toHaveBeenCalled();
  });
});
