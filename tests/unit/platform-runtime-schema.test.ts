import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { basename, join } from 'node:path';

const mocks=vi.hoisted(()=>({query:vi.fn(),connect:vi.fn(),on:vi.fn(),end:vi.fn(),access:vi.fn(),readdir:vi.fn(),readFile:vi.fn()}));
vi.mock('pg',()=>({Pool:class{query=mocks.query;connect=mocks.connect;on=mocks.on;end=mocks.end;}}));
vi.mock('node:fs/promises',()=>({access:mocks.access,readdir:mocks.readdir,readFile:mocks.readFile}));
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';

const first='000_platform.sql',second='001_platform.sql',sqls:Record<string,string>={[first]:'CREATE TABLE ordinary(id uuid PRIMARY KEY);\n',[second]:'ALTER TABLE ordinary ADD COLUMN enabled boolean;\n'};
const ledger=()=>Object.entries(sqls).map(([name,sql])=>({name,checksum:createHash('sha256').update(sql).digest('hex')}));
function fixture(){
  const rows=ledger();mocks.query.mockImplementation(async(sql:string)=>({rows:sql.includes('schema_migrations')?rows:[{id:'synthetic-admin'}],rowCount:1}));
  return{rows,db:new DbService()};
}
beforeEach(()=>{
  vi.stubEnv('DATABASE_URL','postgres://synthetic:synthetic@db.invalid/platform');vi.stubEnv('SKIP_MIGRATIONS','true');vi.clearAllMocks();
  mocks.access.mockResolvedValue(undefined);mocks.readdir.mockResolvedValue([second,'README.md',first]);mocks.readFile.mockImplementation(async(path:string)=>sqls[basename(path)]);
});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});

describe('Platform runtime boot requires the exact shipped schema without owner writes',()=>{
  it('accepts the complete matching ledger and issues SELECTs only before administrator validation',async()=>{
    const f=fixture();f.rows.reverse();await f.db.onModuleInit();
    expect(mocks.query.mock.calls.map(call=>call[0])).toEqual(['SELECT name, checksum FROM schema_migrations ORDER BY name',"SELECT id FROM users WHERE super_admin = true AND status = 'active' LIMIT 1"]);
    expect(mocks.connect).not.toHaveBeenCalled();expect(mocks.query.mock.calls.every(call=>String(call[0]).startsWith('SELECT '))).toBe(true);
  });
  it('rejects an empty restored ledger even when a bootstrap administrator exists',async()=>{
    const f=fixture();f.rows.length=0;await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_MISSING:${first}`);expect(mocks.query).toHaveBeenCalledTimes(1);expect(mocks.connect).not.toHaveBeenCalled();
  });
  it('rejects a partial older restore missing the latest migration instead of reporting ready',async()=>{
    const f=fixture();f.rows.pop();await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_MISSING:${second}`);expect(mocks.query).toHaveBeenCalledTimes(1);
  });
  it('rejects the same migration names with changed SQL bytes or a mismatched restore checksum',async()=>{
    const f=fixture();mocks.readFile.mockImplementation(async(path:string)=>sqls[basename(path)]+(basename(path)===second?'-- changed release bytes\n':''));
    await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_CHECKSUM_MISMATCH:${second}`);expect(mocks.connect).not.toHaveBeenCalled();
  });
  it('rejects a newer database not represented in the application image',async()=>{
    const f=fixture();f.rows.push({name:'099_future.sql',checksum:'a'.repeat(64)});await expect(f.db.onModuleInit()).rejects.toThrow('CONSOLE_SCHEMA_UNEXPECTED:099_future.sql');expect(mocks.query).toHaveBeenCalledTimes(1);
  });
  it.each([{name:'../synthetic-secret.sql',checksum:'a'.repeat(64)},{name:first,checksum:'synthetic-secret'},{name:first,checksum:null},null])('rejects malformed ledger data without echoing SQL, secrets or unsafe paths: %j',async row=>{
    const f=fixture();(f.rows as any[]).push(row);await expect(f.db.onModuleInit()).rejects.toThrow(/^CONSOLE_SCHEMA_LEDGER_INVALID$/);expect(mocks.query).toHaveBeenCalledTimes(1);
  });
  it('rejects duplicate ledger rows rather than accepting the last checksum',async()=>{
    const f=fixture();f.rows.push({...f.rows[0]});await expect(f.db.onModuleInit()).rejects.toThrow('CONSOLE_SCHEMA_LEDGER_INVALID');
  });
  it('normalizes missing-ledger or denied-read database errors without exposing connection material',async()=>{
    const f=fixture();mocks.query.mockRejectedValue(Object.assign(new Error('synthetic private postgres connection material'),{code:'42P01'}));
    await expect(f.db.onModuleInit()).rejects.toThrow(/^CONSOLE_SCHEMA_LEDGER_UNAVAILABLE$/);expect(mocks.connect).not.toHaveBeenCalled();
  });
  it('rejects an empty shipped migration directory without any database request',async()=>{
    const f=fixture();mocks.readdir.mockResolvedValue(['README.md']);await expect(f.db.onModuleInit()).rejects.toThrow('CONSOLE_SCHEMA_BUILD_EMPTY');expect(mocks.query).not.toHaveBeenCalled();
  });
  it('normalizes an unreadable migration file to its safe basename without SQL or full paths',async()=>{
    const f=fixture();mocks.readFile.mockRejectedValue(new Error('/private/synthetic-secret-file'));await expect(f.db.onModuleInit()).rejects.toThrow(`CONSOLE_SCHEMA_BUILD_UNREADABLE:${first}`);expect(mocks.query).not.toHaveBeenCalled();
  });
  it('rejects absent compiled and source migration locations without any database request',async()=>{
    const f=fixture();mocks.access.mockRejectedValue(new Error('/private/synthetic-source-location'));await expect(f.db.onModuleInit()).rejects.toThrow(/^CONSOLE_SCHEMA_BUILD_UNAVAILABLE$/);expect(mocks.query).not.toHaveBeenCalled();expect(mocks.access).toHaveBeenCalledTimes(3);
  });
  it.each(['repository-root','api-workspace'])('supports the declared %s source fallback when the compiled directory is missing',async location=>{
    const f=fixture();vi.spyOn(process,'cwd').mockReturnValue('/synthetic-runtime');
    const target=location==='repository-root'?'/synthetic-runtime/apps/console-api/src/infrastructure/migrations':'/synthetic-runtime/src/infrastructure/migrations';
    mocks.access.mockImplementation(async(path:string)=>{if(path!==target)throw new Error('synthetic missing compiled directory');});
    await f.db.onModuleInit();expect(mocks.readFile).toHaveBeenCalledWith(join(target,first),'utf8');expect(mocks.readFile).toHaveBeenCalledWith(join(target,second),'utf8');expect(mocks.connect).not.toHaveBeenCalled();
  });
  it('preserves the dedicated migration-owner path when runtime skip is disabled',async()=>{
    const f=fixture();vi.stubEnv('SKIP_MIGRATIONS','false');const owner=vi.spyOn(f.db,'migrateAndSeed').mockResolvedValue(undefined);await f.db.onModuleInit();expect(owner).toHaveBeenCalledTimes(1);expect(mocks.query).not.toHaveBeenCalled();
  });
});
