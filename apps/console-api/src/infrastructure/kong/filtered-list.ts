import type { KongService } from './kong.service';

/** Each response consumes at most five native pages. Empty filtered pages still
 * return their next cursor, so continuing never requires a full gateway scan. */
export async function filteredList(
  kong: Pick<KongService, 'list'>,
  clusterId: string,
  path: string,
  params: Record<string, string | number>,
  cursor: string | undefined,
  subject: string,
  filter: (items: any[]) => Promise<any[]>,
  budget = 5,
): Promise<{ items: any[]; nextCursor: string | null; size: number; total: null; scan_budget_exhausted: boolean }> {
  for (let page = 0; page < budget; page++) {
    const result = await kong.list(clusterId, path, params, cursor, subject);
    const items = await filter(result.items);
    if (items.length || !result.nextCursor || page === budget - 1) {
      return { ...result, items, total: null, scan_budget_exhausted: !items.length && !!result.nextCursor && page === budget - 1 };
    }
    cursor = result.nextCursor || undefined;
  }
  throw new Error('Filtered page budget must be positive');
}
