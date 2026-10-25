import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Pool, PoolClient, QueryResult } from 'pg';
import { createHash, randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { readdir, readFile, access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { hashPolicyPassword } from '../common/password-policy';

/** One verification read may repeat the identical SELECT on its own open
 * transaction connection many times (layered re-verification). Inside an
 * explicit withReadMemo scope those identical, non-locking, non-volatile
 * SELECTs are answered from the first result of THIS scope only. Epoch probes
 * (`SELECT ... FROM iam_epoch`), locking reads, volatile functions and every
 * statement inside freshRead always reach PostgreSQL, so before/after change
 * detection is unchanged. Any non-SELECT on the connection clears the memo. */
interface ReadMemoScope { readonly client: PoolClient; readonly rows: Map<string, unknown[]>; readonly values: Map<string, unknown>; generation: number; hits: number; misses: number }
const readMemoStorage = new AsyncLocalStorage<ReadMemoScope | null>();
const freshReadStorage = new AsyncLocalStorage<true>();
const LOCKING_READ = /\bFOR\s+(?:NO\s+KEY\s+)?(?:UPDATE|SHARE|KEY\s+SHARE)\b/i;
const VOLATILE_READ = /\b(?:now|clock_timestamp|statement_timestamp|transaction_timestamp|timeofday|random)\s*\(|\b(?:current_timestamp|localtimestamp|current_time|localtime)\b/i;
const EPOCH_PROBE = /^\s*SELECT\b(?:(?!\bFROM\b)[\s\S])*\bFROM\s+iam_epoch\b/i;
// Side-effect-free builtins/keywords that may precede "(" in a memoizable read.
const PURE_CALLS = new Set(['select', 'from', 'where', 'and', 'or', 'not', 'in', 'exists', 'any', 'all', 'as', 'on', 'join', 'values', 'over', 'filter', 'using',
  'coalesce', 'nullif', 'greatest', 'least', 'count', 'max', 'min', 'sum', 'avg', 'bool_and', 'bool_or', 'array_agg', 'jsonb_agg', 'json_agg', 'to_jsonb', 'to_json',
  'jsonb_build_object', 'json_build_object', 'jsonb_build_array', 'jsonb_array_length', 'jsonb_typeof', 'jsonb_object_keys', 'jsonb_array_elements', 'jsonb_array_elements_text',
  'array_length', 'cardinality', 'unnest', 'lower', 'upper', 'length', 'octet_length', 'substring', 'left', 'right', 'concat', 'encode', 'decode', 'row_number', 'cast',
  'extract', 'date_trunc', 'abs', 'floor', 'ceil', 'round', 'string_agg', 'distinct', 'lateral', 'case', 'when', 'then', 'else', 'is', 'null', 'limit', 'offset', 'order', 'by', 'group',
  'having', 'union', 'with', 'array', 'row', 'interval', 'text', 'numeric', 'bigint', 'integer', 'int', 'uuid', 'jsonb', 'boolean', 'timestamptz', 'now', 'clock_timestamp',
  'statement_timestamp', 'transaction_timestamp', 'timeofday', 'random']);
function unknownCall(sql: string): boolean {
  for (const match of sql.matchAll(/([A-Za-z_][\w$]*)\s*\(/g)) if (!PURE_CALLS.has(match[1].toLowerCase())) return true;
  return false;
}
/** Does this statement possibly change state (so the memo must be dropped)? */
export function readMemoInvalidates(sql: string): boolean {
  return !/^\s*SELECT\b/i.test(sql) || /;\s*\S/.test(sql) || /\b(?:INSERT|UPDATE|DELETE|MERGE|TRUNCATE)\b/i.test(sql.replace(LOCKING_READ, '')) || unknownCall(sql);
}
export function readMemoCacheable(sql: string): boolean {
  return !readMemoInvalidates(sql) && !LOCKING_READ.test(sql) && !VOLATILE_READ.test(sql) && !EPOCH_PROBE.test(sql);
}

@Injectable()
export class DbService implements OnModuleInit, OnModuleDestroy {
  private readonly pool: Pool;
  private readonly logger = new Logger(DbService.name);
  private connection?: PoolClient;
  private ownsPool = true;
  private savepointSequence = 0;

  constructor() {
    const connectionString = process.env.DATABASE_URL ?? process.env.CONSOLE_DATABASE_URL;
    if (!connectionString) throw new Error('DATABASE_URL is required for the console database');
    this.pool = new Pool({ connectionString, max: 10, connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000, statement_timeout: 15000, application_name: 'kongpilot-console' });
    // pg removes failed idle clients. Consume only this background event; real
    // query/connect failures still reject and readiness probes use a fresh query.
    // Never serialize the pg error/client: either can contain connection secrets.
    this.pool.on('error', () => this.logger.warn({
      component: 'postgres-pool', code: 'DB_POOL_IDLE_CONNECTION_ERROR',
    }));
  }

  async onModuleInit(): Promise<void> {
    if (process.env.SKIP_MIGRATIONS === 'true') {
      await this.assertRuntimeSchema();
      const admin = await this.one("SELECT id FROM users WHERE super_admin = true AND status = 'active' LIMIT 1");
      if (!admin) throw new Error('Console bootstrap administrator is missing; run the migration job');
      return;
    }
    await this.migrateAndSeed();
  }

  async migrateAndSeed(): Promise<void> {
    await this.migrate();
    await this.seedBootstrapAdmin();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.ownsPool) await this.pool.end();
  }

  private async result(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const memo = this.connection ? readMemoStorage.getStore() : undefined;
    if (memo && memo.client === this.connection && readMemoInvalidates(sql)) { memo.rows.clear(); memo.values.clear(); memo.generation++; }
    return (this.connection ?? this.pool).query(sql, params);
  }

  async query<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
    const memo = this.connection ? readMemoStorage.getStore() : undefined;
    if (memo && memo.client === this.connection && !freshReadStorage.getStore() && readMemoCacheable(sql)) {
      let key: string | undefined;
      try { key = `${sql}\u0000${JSON.stringify(params, (_k, v) => typeof v === 'bigint' ? `${v}n` : v)}`; } catch { key = undefined; }
      if (key !== undefined) {
        const prior = memo.rows.get(key);
        if (prior) { memo.hits++; return structuredClone(prior) as T[]; }
        const generation = memo.generation, result = await (this.connection as PoolClient).query(sql, params);
        memo.misses++;
        if (memo.generation === generation && readMemoStorage.getStore() === memo) memo.rows.set(key, structuredClone(result.rows));
        return result.rows as T[];
      }
    }
    const result = await this.result(sql, params);
    return result.rows as T[];
  }

  /** Run one verification read with a memo bound to this open transaction
   * connection. Nested scopes reuse the outer scope only when it belongs to
   * the same connection; outside a transaction this is a plain call. */
  async withReadMemo<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.connection) return fn();
    const outer = readMemoStorage.getStore();
    if (outer && outer.client === this.connection) return fn();
    return readMemoStorage.run({ client: this.connection, rows: new Map(), values: new Map(), generation: 0, hits: 0, misses: 0 }, fn);
  }

  /** Derived deep-frozen value computed only from SQL reads of this same open
   * scope (e.g. a decrypted, HMAC-verified plan material). Shared only within
   * the current withReadMemo scope and dropped by any write on the
   * connection; outside a scope, or inside freshRead, it always recomputes. */
  async memoizedRead<T>(key: string, compute: () => Promise<T>): Promise<T> {
    const memo = this.connection ? readMemoStorage.getStore() : undefined;
    if (!memo || memo.client !== this.connection || freshReadStorage.getStore()) return compute();
    if (memo.values.has(key)) { memo.hits++; return memo.values.get(key) as T; }
    const generation = memo.generation, value = await compute();
    if (memo.generation === generation && readMemoStorage.getStore() === memo && value !== null && typeof value === 'object' && Object.isFrozen(value)) memo.values.set(key, value);
    return value;
  }

  /** Statements inside always reach PostgreSQL (after-checks/re-reads). */
  async freshRead<T>(fn: () => Promise<T>): Promise<T> { return freshReadStorage.run(true, fn); }

  async one<T = any>(sql: string, params: unknown[] = []): Promise<T | null> {
    const rows = await this.query<T>(sql, params);
    return rows[0] ?? null;
  }

  async exec(sql: string, params: unknown[] = []): Promise<number> {
    return (await this.result(sql, params)).rowCount ?? 0;
  }

  async transaction<T>(fn: (tx: DbService) => Promise<T>): Promise<T> {
    if (this.connection) {
      const name = `kongos_savepoint_${++this.savepointSequence}`;
      await this.exec(`SAVEPOINT ${name}`);
      try {
        const result = await fn(this);
        await this.exec(`RELEASE SAVEPOINT ${name}`);
        return result;
      } catch (error) {
        await this.exec(`ROLLBACK TO SAVEPOINT ${name}`);
        await this.exec(`RELEASE SAVEPOINT ${name}`);
        throw error;
      }
    }
    const client = await this.pool.connect();
    const tx = Object.create(DbService.prototype) as DbService;
    Object.assign(tx, { pool: this.pool, connection: client, ownsPool: false, savepointSequence: 0 });
    try {
      await client.query('BEGIN');
      const value = await fn(tx);
      await client.query('COMMIT');
      return value;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  private async migrationDirectory(): Promise<string> {
    const candidates = [join(__dirname, 'migrations'),
      resolve(process.cwd(), 'apps/console-api/src/infrastructure/migrations'),
      resolve(process.cwd(), 'src/infrastructure/migrations')];
    for (const directory of candidates) {
      try { await access(directory); return directory; } catch { /* Try the next known build/source location. */ }
    }
    throw new Error('Console SQL migrations are missing from this build');
  }

  /** Runtime credentials can read the ledger, never initialize or repair it.
   * Refuse an older restore, a changed migration, or an incompatible newer
   * database before Nest starts accepting traffic. Errors contain no SQL,
   * checksums, filesystem paths or database connection details. */
  private async assertRuntimeSchema(): Promise<void> {
    let directory:string,files:string[];
    try {
      directory=await this.migrationDirectory();
      files=(await readdir(directory)).filter(file=>/^\d+_[\w-]+\.sql$/.test(file))
        .sort((left,right)=>parseInt(left,10)-parseInt(right,10)||left.localeCompare(right));
    } catch { throw new Error('CONSOLE_SCHEMA_BUILD_UNAVAILABLE'); }
    if(!files.length)throw new Error('CONSOLE_SCHEMA_BUILD_EMPTY');
    const expected=new Map<string,string>();
    for(const file of files){
      try { expected.set(file,createHash('sha256').update(await readFile(join(directory,file),'utf8')).digest('hex')); }
      catch { throw new Error(`CONSOLE_SCHEMA_BUILD_UNREADABLE:${file}`); }
    }
    let rows:Array<{name:string;checksum:string}>;
    try { rows=await this.query('SELECT name, checksum FROM schema_migrations ORDER BY name'); }
    catch { throw new Error('CONSOLE_SCHEMA_LEDGER_UNAVAILABLE'); }
    if(!Array.isArray(rows))throw new Error('CONSOLE_SCHEMA_LEDGER_INVALID');
    const applied=new Map<string,string>();
    for(const row of rows){
      if(!row||typeof row.name!=='string'||!/^\d+_[\w-]+\.sql$/.test(row.name)
        ||typeof row.checksum!=='string'||!/^[a-f\d]{64}$/.test(row.checksum)||applied.has(row.name))throw new Error('CONSOLE_SCHEMA_LEDGER_INVALID');
      if(!expected.has(row.name))throw new Error(`CONSOLE_SCHEMA_UNEXPECTED:${row.name}`);
      applied.set(row.name,row.checksum);
    }
    for(const [file,checksum]of expected){
      if(!applied.has(file))throw new Error(`CONSOLE_SCHEMA_MISSING:${file}`);
      if(applied.get(file)!==checksum)throw new Error(`CONSOLE_SCHEMA_CHECKSUM_MISMATCH:${file}`);
    }
  }

  /** One connection holds the advisory lock throughout discovery and all migrations. */
  async migrate(): Promise<void> {
    const directory = await this.migrationDirectory();
    const files = (await readdir(directory)).filter(file => /^\d+_[\w-]+\.sql$/.test(file))
      .sort((left, right) => parseInt(left, 10) - parseInt(right, 10) || left.localeCompare(right));
    if (!files.length) throw new Error('Console SQL migrations directory is empty');
    const client = await this.pool.connect();
    let locked = false;
    try {
      await client.query('SELECT pg_advisory_lock($1)', [1545015001]);
      locked = true;
      await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
        name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
      const applied = await client.query<{name: string; checksum: string}>('SELECT name, checksum FROM schema_migrations ORDER BY name');
      const checksums = new Map(applied.rows.map(row => [row.name, row.checksum]));
      for (const name of checksums.keys()) if (!files.includes(name)) throw new Error(`Applied migration is missing from this build: ${name}`);
      const latestApplied = Math.max(-1, ...applied.rows.map(row => parseInt(row.name, 10)));
      for (const file of files) {
        const sql = await readFile(join(directory, file), 'utf8');
        const checksum = createHash('sha256').update(sql).digest('hex');
        const existing = checksums.get(file);
        if (existing && existing !== checksum) throw new Error(`Applied migration checksum mismatch: ${file}`);
        if (existing) continue;
        if (parseInt(file, 10) < latestApplied) throw new Error(`New migration must follow previously applied migrations: ${file}`);
        await client.query('BEGIN');
        try {
          // SQL comes exclusively from version-controlled migration files, never from a request.
          await client.query(sql);
          await client.query('INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)', [file, checksum]);
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw error;
        }
      }
    } finally {
      try { if (locked) await client.query('SELECT pg_advisory_unlock($1)', [1545015001]); }
      finally { client.release(); }
    }
  }

  private async seedBootstrapAdmin(): Promise<void> {
    await this.transaction(async tx => {
      await tx.exec('SELECT pg_advisory_xact_lock($1)', [1545015002]);
      const existing = await tx.one<{count: string}>('SELECT count(*)::text AS count FROM users');
      if (existing && Number(existing.count) > 0) return;
      const username = process.env.BOOTSTRAP_ADMIN_USERNAME;
      const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
      if (!username || !password) throw new Error('First startup requires BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD');
      if (!/^[a-zA-Z\d_.@-]{3,64}$/.test(username)) throw new Error('Bootstrap username must be 3–64 letters, digits or _.@-');
      if (password.length < 12 || password.length > 72 || Buffer.byteLength(password, 'utf8') > 72) {
        throw new Error('Bootstrap password must be 12–72 characters and at most 72 UTF-8 bytes');
      }
      const passwordHash = await hashPolicyPassword(password, { username });
      await tx.exec(`INSERT INTO users(id, username, password_hash, super_admin, status)
        VALUES ($1, $2, $3, true, 'active')`, [randomUUID(), username, passwordHash]);
    });
  }
}

/** Helpers tolerate test doubles that only implement query/one/exec. */
export function withVerificationReadMemo<T>(tx: unknown, fn: () => Promise<T>): Promise<T> {
  return tx instanceof DbService ? tx.withReadMemo(fn) : fn();
}
export function freshVerificationRead<T>(tx: unknown, fn: () => Promise<T>): Promise<T> {
  return tx instanceof DbService ? tx.freshRead(fn) : fn();
}
