import { BadGatewayException, BadRequestException, ConflictException } from '@nestjs/common';
import type { KongService } from './kong.service';

export interface TargetLookupBudget { pages: number; records: number; bytes: number; }
export interface TargetLookupPage { items: any[]; nextCursor: string | null; size: number; }
export interface TargetLookupOptions {
  maxPages?: number;
  maxRecords?: number;
  maxBytes?: number;
  pageSize?: number;
  /** Aggregate graph callers charge each fetched page to their own budget. */
  onPage?: (page: TargetLookupPage, charge: TargetLookupBudget) => void | Promise<void>;
}
const ceilings = { maxPages: 100, maxRecords: 10_000, maxBytes: 32 * 1024 * 1024, pageSize: 100 };
const exhausted = () => new ConflictException({ code: 'TARGET_LOOKUP_LIMIT', message: '当前有效 Target 核验超过分页或数据预算，未执行变更' });
const invalid = () => new BadGatewayException({ code: 'KONG_INVALID_TARGET_LIST', message: '网关返回了无效或冲突的有效 Target 集合，未执行变更' });
function segment(value: string): string {
  if (typeof value !== 'string' || !value || value.length > 1024 || value === '.' || value === '..' || /[\\/\u0000?#]/.test(value)) {
    throw new BadRequestException({ code: 'INVALID_TARGET_PARENT', message: 'Target 所属 Upstream 标识无效' });
  }
  return encodeURIComponent(value);
}

/** Kong 1.5's generic nested GET by target address uses global endpoint_key
 * selection; it does not guarantee this Upstream's latest effective record.
 * Stream the parent-scoped effective collection instead. Never reconstruct
 * current state from a historical UUID or a target-address GET response. */
export async function currentEffectiveTarget(kong: Pick<KongService, 'list'>, clusterId: string, upstreamId: string, address: string, options: TargetLookupOptions = {}): Promise<{ target: any | null; budget: TargetLookupBudget }> {
  const path = `/upstreams/${segment(upstreamId)}/targets`;
  if (typeof address !== 'string' || !address || address.length > 1024) throw new BadRequestException({ code: 'INVALID_TARGET_ADDRESS', message: '待核验的 Target 地址无效' });
  const limits = { ...ceilings };
  for (const key of Object.keys(ceilings) as Array<keyof typeof ceilings>) {
    const value = options[key] ?? ceilings[key];
    if (!Number.isInteger(value) || value < 0 || value > ceilings[key] || key === 'pageSize' && value === 0) {
      throw new BadRequestException({ code: 'INVALID_TARGET_LOOKUP_BUDGET', message: 'Target 核验预算无效或超过安全上限' });
    }
    limits[key] = value;
  }
  if (!limits.maxPages || !limits.maxRecords || !limits.maxBytes) throw exhausted();
  // Kong signed cursors bind size. Keep one size for the entire traversal,
  // reserving a full page before every request rather than shrinking later.
  const size = Math.min(limits.pageSize, limits.maxRecords);
  const budget: TargetLookupBudget = { pages: 0, records: 0, bytes: 0 };
  const seenCursors = new Set<string>(), seenIds = new Set<string>(), seenAddresses = new Set<string>();
  let cursor: string | undefined, target: any | null = null;
  do {
    if (budget.pages >= limits.maxPages || budget.records + size > limits.maxRecords) throw exhausted();
    const page = await kong.list(clusterId, path, { size }, cursor, `current-effective-target:${upstreamId}`);
    if (!Array.isArray(page?.items) || page.items.length > size || page.nextCursor !== null && (typeof page.nextCursor !== 'string' || !page.nextCursor)) throw invalid();
    const charge = { pages: 1, records: page.items.length, bytes: Buffer.byteLength(JSON.stringify(page.items), 'utf8') };
    budget.pages += charge.pages; budget.records += charge.records; budget.bytes += charge.bytes;
    if (budget.bytes > limits.maxBytes) throw exhausted();
    await options.onPage?.(page, charge);
    for (const item of page.items) {
      if (typeof item?.id !== 'string' || !item.id || typeof item.target !== 'string' || !item.target || item.upstream?.id !== upstreamId || !Number.isInteger(item.weight) || item.weight <= 0 || item.weight > 1000 || seenIds.has(item.id) || seenAddresses.has(item.target)) throw invalid();
      seenIds.add(item.id); seenAddresses.add(item.target);
      if (item.target === address) target = item;
    }
    if (page.nextCursor) {
      if (seenCursors.has(page.nextCursor)) throw new ConflictException({ code: 'TARGET_PAGINATION_LOOP', message: 'Target 有效集合分页重复，未执行变更' });
      seenCursors.add(page.nextCursor);
    }
    cursor = page.nextCursor ?? undefined;
  } while (cursor);
  return { target, budget };
}
