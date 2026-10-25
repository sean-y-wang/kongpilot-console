import { describe, expect, it } from 'vitest';
import { DbService, readMemoCacheable, readMemoInvalidates, withVerificationReadMemo, freshVerificationRead } from '../../apps/console-api/src/infrastructure/db.service';

function fakeDb(rowsFor: (sql: string, params: unknown[]) => unknown[]) {
  const calls: string[] = [];
  const client = { query: async (sql: string, params: unknown[] = []) => { calls.push(sql); return { rows: rowsFor(sql, params) }; }, release: () => undefined };
  const db = Object.create(DbService.prototype) as DbService;
  Object.assign(db, { pool: { connect: async () => client, query: client.query }, connection: undefined, ownsPool: false, savepointSequence: 0 });
  return { db, calls: () => calls.filter(s => !/^(BEGIN|COMMIT|ROLLBACK)$/.test(s)) };
}

describe('verification read memo', () => {
  it('classifies epoch probes, locking and volatile reads as uncacheable and writes as invalidating', () => {
    expect(readMemoCacheable('SELECT version FROM iam_epoch WHERE id=1')).toBe(false);
    expect(readMemoCacheable('SELECT * FROM users WHERE id=$1 FOR UPDATE')).toBe(false);
    expect(readMemoCacheable('SELECT now()')).toBe(false);
    expect(readMemoCacheable('SELECT * FROM users WHERE id=$1')).toBe(true);
    expect(readMemoInvalidates("UPDATE users SET status='disabled' WHERE id=$1")).toBe(true);
  });

  it('shares identical reads inside one scope but never epoch probes or freshRead', async () => {
    let grants = 1;
    const { db, calls } = fakeDb(sql => sql.includes('iam_epoch') ? [{ version: 1 }] : [{ grants }]);
    await db.transaction(tx => withVerificationReadMemo(tx, async () => {
      await tx.query('SELECT version FROM iam_epoch WHERE id=1');
      expect(await tx.query('SELECT grants FROM p WHERE id=$1', [1])).toEqual([{ grants: 1 }]);
      grants = 2;
      expect(await tx.query('SELECT grants FROM p WHERE id=$1', [1])).toEqual([{ grants: 1 }]);
      expect(await freshVerificationRead(tx, () => tx.query('SELECT grants FROM p WHERE id=$1', [1]))).toEqual([{ grants: 2 }]);
      await tx.query('SELECT version FROM iam_epoch WHERE id=1');
    }));
    expect(calls().filter(s => s.includes('iam_epoch'))).toHaveLength(2);
    expect(calls().filter(s => s.includes('FROM p'))).toHaveLength(2);
  });

  it('drops the memo on a write and does not leak across verifications', async () => {
    let grants = 1;
    const { db, calls } = fakeDb(() => [{ grants }]);
    const read = (tx: DbService) => tx.query<{ grants: number }>('SELECT grants FROM p WHERE id=$1', [1]);
    await db.transaction(tx => withVerificationReadMemo(tx, async () => {
      await read(tx); await tx.query("UPDATE p SET grants=0 WHERE id=$1", [1]); grants = 0;
      expect(await read(tx)).toEqual([{ grants: 0 }]);
    }));
    grants = 5; // permission change between two verifications is observed
    await db.transaction(tx => withVerificationReadMemo(tx, async () => { expect(await read(tx)).toEqual([{ grants: 5 }]); }));
    expect(calls().filter(s => s.startsWith('SELECT'))).toHaveLength(3);
  });

  it('returns copies so callers cannot mutate cached rows, and is a no-op outside a transaction', async () => {
    const { db, calls } = fakeDb(() => [{ v: { n: 1 } }]);
    await db.transaction(tx => withVerificationReadMemo(tx, async () => {
      const a = await tx.query<any>('SELECT v FROM t'); a[0].v.n = 9;
      expect(await tx.query('SELECT v FROM t')).toEqual([{ v: { n: 1 } }]);
    }));
    await withVerificationReadMemo(db, async () => { await db.query('SELECT v FROM t'); await db.query('SELECT v FROM t'); });
    expect(calls()).toHaveLength(3);
  });
});
