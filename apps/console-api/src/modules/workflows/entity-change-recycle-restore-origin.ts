import { ConflictException } from '@nestjs/common';

/** Read-only guard run before an entity-change intent is sealed.
 * Entity-change execution restores only entries archived by the entity-change
 * writer (recycle_entries.mutation_id IS NULL with an entity_change_recycle_archives
 * row). A legacy mutation-origin entry would otherwise be sealed, approved by a
 * second person, and then deterministically fail at execute with
 * ENTITY_RECYCLE_FACT_INVALID (zero native writes, but a wasted approval and an
 * "unverified result" banner). Refuse it up front with a stable code. */
export async function assertEntityChangeRecycleRestoreOrigin(
  db: { one<T = any>(sql: string, params?: unknown[]): Promise<T | undefined | null> },
  clusterId: string,
  change: unknown,
): Promise<void> {
  const value = change as { kind?: unknown; action?: unknown; entryId?: unknown } | null;
  if (!value || value.kind !== 'recycle' || value.action !== 'restore' || typeof value.entryId !== 'string') return;
  const row = await db.one<{ mutation_id: string | null }>('SELECT mutation_id FROM recycle_entries WHERE cluster_id=$1 AND id=$2', [clusterId, value.entryId]);
  if (row && row.mutation_id !== null && row.mutation_id !== undefined)
    throw new ConflictException({ code: 'ENTITY_RECYCLE_LEGACY_ORIGIN_RESTORE_UNSUPPORTED', message: '该归档由旧版删除流程产生，不能通过变更工单恢复；未生成工单，请联系平台管理员处理' });
}
