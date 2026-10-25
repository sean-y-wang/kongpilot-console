import { apiBlob } from '../api/client';
import { canonicalId } from '../api/workspace-scope';
import { sameM7Identity, type M7Identity } from './m7.cursor';
export function auditDownloadFilename(header: string | null, format: 'csv' | 'ndjson'): string {
  const raw = header?.match(/filename="?([^";]+)"?/i)?.[1] ?? '';
  return /^audit-[a-f\d-]{36}\.(csv|ndjson)$/i.test(raw) && raw.endsWith(`.${format}`) ? raw : `audit-export.${format}`;
}
export async function downloadAuditExport(path: string, format: 'csv' | 'ndjson', identity: M7Identity, current: () => M7Identity, signal?: AbortSignal) {
  const file = await apiBlob(path, signal);
  if (!sameM7Identity(identity, current()) || signal?.aborted) throw new Error('账号、权限或范围已变化，请重新下载。');
  const filename = auditDownloadFilename(file.contentDisposition, format), url = URL.createObjectURL(file.blob);
  try { const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.style.display = 'none'; document.body.appendChild(anchor); anchor.click(); anchor.remove(); } finally { URL.revokeObjectURL(url); }
}
export function notificationNavigation(link: { kind: string; id: string } | null, scope: { cid?: string; wid?: string }, targetScope: { clusterId: string | null; workspaceId: string | null }): string | undefined {
  if (!link || !canonicalId(link.id) || scope.cid !== targetScope.clusterId || scope.wid !== targetScope.workspaceId) return undefined;
  if (link.kind === 'workflow') return `/workflows/${link.id}`;
  if (link.kind === 'audit') return `/audit?eventId=${link.id}`;
  if (link.kind === 'event') return `/events?eventId=${link.id}`;
  return undefined;
}
