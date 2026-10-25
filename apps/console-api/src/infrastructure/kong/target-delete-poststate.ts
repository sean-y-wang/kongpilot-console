import { BadGatewayException, BadRequestException, ConflictException } from '@nestjs/common';
import type { KongService } from './kong.service';
import type { SecretService } from '../secret.service';
import { immutableJson } from './immutable-json';
import type { TargetLookupBudget } from './effective-target';

/**
 * KP-005 Target DELETE poststate (Kong 1.5.x). Native DELETE does not remove
 * the address: it appends a weight=0 history overlay (or clean_history may
 * prune every row for that address). Archive-before-delete must already be
 * sealed. Bare GET404 / HTTP status alone never certifies delete completion.
 */

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex64 = /^[a-f\d]{64}$/;
const record = (v: any): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
const invalid = () => new BadGatewayException({
  code: 'TARGET_DELETE_POSTSTATE_INVALID',
  message: 'Target 删除后历史或有效集合与原归档不一致，请核验原操作，勿重复提交',
});
const changed = () => new ConflictException({
  code: 'TARGET_DELETE_POSTSTATE_CHANGED',
  message: 'Target 删除回读期间历史或有效集合发生变化，请核验原操作，勿重复提交',
});
const exhausted = () => new ConflictException({
  code: 'TARGET_DELETE_POSTSTATE_LIMIT',
  message: 'Target 删除核验超过有界分页或数据预算，请核验原操作，勿重复提交',
});
const archiveRequired = () => new ConflictException({
  code: 'TARGET_DELETE_ARCHIVE_REQUIRED',
  message: 'Target 删除须先完成回收站归档密封，禁止仅凭 HTTP 状态宣称完成',
});

const ceilings = { maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024, pageSize: 100 };

export interface TargetDeletePoststateOptions {
  maxPages?: number; maxRecords?: number; maxBytes?: number; pageSize?: number;
}

export interface TargetDeleteArchiveSeal {
  entryId: string;
  graphHmac: string;
  nodeCount: number;
}

export interface TargetDeletePoststateInput {
  clusterId: string;
  upstreamId: string;
  originalNativeId: string;
  address: string;
  weightBefore: number;
  archive: TargetDeleteArchiveSeal;
  /** Kong Admin DELETE returns raw null (204). Any body is unknown. */
  nativeDeleteResult: null;
  approvedBefore: unknown;
}

export interface TargetDeletePoststateObservation {
  archiveEntryId: string;
  originalNativeId: string;
  address: string;
  historyRetention: 'weight-zero-overlay' | 'native-pruned';
  currentEffectiveAbsent: true;
  restoreRequiresSealedReplacement: true;
  observedOverlayHmac: string | null;
  historySnapshotHmac: string;
  effectiveSnapshotHmac: string;
  archiveGraphHmac: string;
  budget: TargetLookupBudget;
}

const tags = (v: unknown): string[] | null =>
  v == null ? [] : Array.isArray(v) && v.every(t => typeof t === 'string' && !!t) && new Set(v).size === v.length
    ? [...v].sort() : null;

/** Fail-closed seal check used before any native DELETE may be considered
 * complete. Does not grant delete authority. */
export function assertTargetDeleteArchiveSeal(
  archive: TargetDeleteArchiveSeal,
  before: Readonly<{ id: string; target: string; weight: number }>,
): void {
  if (!archive || !uuid.test(archive.entryId) || !hex64.test(archive.graphHmac)
    || !Number.isInteger(archive.nodeCount) || archive.nodeCount < 1) throw archiveRequired();
  if (!uuid.test(before.id) || typeof before.target !== 'string' || !before.target || before.target.length > 1024
    || !Number.isInteger(before.weight) || before.weight < 1 || before.weight > 1000) throw invalid();
}

export async function observeTargetDeletePoststate(
  kong: Pick<KongService, 'list'>,
  secrets: Pick<SecretService, 'fingerprint'>,
  input: Readonly<TargetDeletePoststateInput>,
  options: TargetDeletePoststateOptions = {},
): Promise<TargetDeletePoststateObservation> {
  const frozen = immutableJson(input);
  if (frozen.nativeDeleteResult !== null) throw invalid();
  if (!uuid.test(frozen.clusterId ?? '') || !uuid.test(frozen.upstreamId ?? '')
    || !uuid.test(frozen.originalNativeId ?? '') || typeof frozen.address !== 'string' || !frozen.address
    || frozen.address.length > 1024 || !Number.isInteger(frozen.weightBefore) || frozen.weightBefore < 1
    || frozen.weightBefore > 1000 || !record(frozen.approvedBefore)) throw invalid();
  const before = frozen.approvedBefore;
  if (before.id !== frozen.originalNativeId || before.target !== frozen.address
    || before.weight !== frozen.weightBefore || before.upstream?.id !== undefined
    && before.upstream.id !== frozen.upstreamId) throw invalid();
  if (tags(before.tags) === null) throw invalid();
  assertTargetDeleteArchiveSeal(frozen.archive, {
    id: frozen.originalNativeId, target: frozen.address, weight: frozen.weightBefore,
  });

  const limits = { ...ceilings };
  for (const key of Object.keys(ceilings) as Array<keyof typeof ceilings>) {
    const value = options[key] ?? ceilings[key];
    if (!Number.isInteger(value) || value < 0 || value > ceilings[key] || key === 'pageSize' && value === 0) {
      throw new BadRequestException({ code: 'TARGET_DELETE_POSTSTATE_BUDGET_INVALID' });
    }
    limits[key] = value;
  }
  if (!limits.maxPages || !limits.maxRecords || !limits.maxBytes) throw exhausted();

  const size = Math.min(limits.pageSize, limits.maxRecords);
  const budget: TargetLookupBudget = { pages: 0, records: 0, bytes: 0 };
  const base = `/upstreams/${frozen.upstreamId}/targets`;

  const collection = async (history: boolean, phase: number): Promise<any[]> => {
    const rows: any[] = [], seenIds = new Set<string>(), seenAddresses = new Set<string>();
    const seenTimes = new Set<string>(), seenCursors = new Set<string>();
    let cursor: string | undefined;
    do {
      if (budget.pages >= limits.maxPages || budget.records + size > limits.maxRecords) throw exhausted();
      const page = await kong.list(
        frozen.clusterId,
        history ? `${base}/all` : base,
        { size },
        cursor,
        `target-delete-poststate:${frozen.upstreamId}:${frozen.originalNativeId}:${phase}`,
      );
      if (!Array.isArray(page?.items) || page.items.length > size || page.size !== size
        || page.console_permission_projection
        || page.nextCursor !== null && (typeof page.nextCursor !== 'string' || !page.nextCursor)) throw invalid();
      budget.pages++; budget.records += page.items.length;
      budget.bytes += Buffer.byteLength(JSON.stringify(page.items));
      if (budget.bytes > limits.maxBytes) throw exhausted();
      for (const row of page.items) {
        if (!record(row) || !uuid.test(row.id ?? '') || seenIds.has(row.id.toLowerCase())
          || typeof row.target !== 'string' || !row.target || row.target.length > 1024
          || row.upstream?.id !== frozen.upstreamId || !Number.isInteger(row.weight)
          || row.weight < (history ? 0 : 1) || row.weight > 1000
          || !Number.isFinite(row.created_at) || row.created_at <= 0 || tags(row.tags) === null
          || !history && seenAddresses.has(row.target)) throw invalid();
        const time = JSON.stringify([row.target, row.created_at]);
        if (history && seenTimes.has(time)) throw changed();
        seenIds.add(row.id.toLowerCase()); seenAddresses.add(row.target); seenTimes.add(time); rows.push(row);
      }
      if (page.nextCursor) {
        if (seenCursors.has(page.nextCursor)) throw invalid();
        seenCursors.add(page.nextCursor);
      }
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    return rows;
  };

  const verifyHistory = (rows: any[]): 'weight-zero-overlay' | 'native-pruned' => {
    const sameAddress = rows.filter(row => row.target === frozen.address);
    if (!sameAddress.length) {
      // Original UUID must not resurface under a foreign address.
      if (rows.some(row => row.id.toLowerCase() === frozen.originalNativeId.toLowerCase())) throw invalid();
      return 'native-pruned';
    }
    const latest = Math.max(...sameAddress.map(row => row.created_at));
    const latestRows = sameAddress.filter(row => row.created_at === latest);
    if (latestRows.length !== 1 || latestRows[0].weight !== 0) throw changed();
    return 'weight-zero-overlay';
  };

  const verifyEffective = (rows: any[]) => {
    if (rows.some(row => row.target === frozen.address
      || row.id.toLowerCase() === frozen.originalNativeId.toLowerCase())) throw changed();
  };

  const history1 = await collection(true, 1), retention1 = verifyHistory(history1);
  const effective1 = await collection(false, 2); verifyEffective(effective1);
  const history2 = await collection(true, 3), retention2 = verifyHistory(history2);
  const effective2 = await collection(false, 4); verifyEffective(effective2);

  const fingerprint = (rows: any[]) => secrets.fingerprint([...rows].sort((a, b) => a.id.localeCompare(b.id)));
  if (retention1 !== retention2 || fingerprint(history1) !== fingerprint(history2)
    || fingerprint(effective1) !== fingerprint(effective2)) throw changed();

  const overlay = retention2 === 'weight-zero-overlay'
    ? history2.filter(row => row.target === frozen.address)
      .sort((a, b) => b.created_at - a.created_at)[0]
    : null;

  return immutableJson({
    archiveEntryId: frozen.archive.entryId,
    originalNativeId: frozen.originalNativeId,
    address: frozen.address,
    historyRetention: retention2,
    currentEffectiveAbsent: true,
    restoreRequiresSealedReplacement: true,
    observedOverlayHmac: overlay ? secrets.fingerprint(overlay) : null,
    historySnapshotHmac: fingerprint(history2),
    effectiveSnapshotHmac: fingerprint(effective2),
    archiveGraphHmac: frozen.archive.graphHmac,
    budget,
  });
}
