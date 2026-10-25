import { apiConfigurationBlob } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canonicalId } from '../api/workspace-scope';
import { configurationPath, sameConfigurationIdentity } from './m8.model';
import type { ConfigurationIdentity } from './m8.types';
export function configurationDownloadFilename(header: string | null, format: 'deck-1.1' | 'review-json'): string { const suffix = format === 'deck-1.1' ? 'yaml' : 'json', name = header?.match(/filename="?([^";]+)"?/i)?.[1] ?? ''; return new RegExp(`^(?:configuration|kongos)-[a-f\\d-]{36}\\.${suffix}$`, 'i').test(name) ? name : `configuration-export.${suffix}`; }
export async function downloadConfigurationExport(input: { id: string; revision: number; name: string; format: 'deck-1.1' | 'review-json'; identity: ConfigurationIdentity; current: () => ConfigurationIdentity; signal?: AbortSignal }) {
  if (!canonicalId(input.id) || !sameConfigurationIdentity(input.identity, input.current())) throw new Error('原导出账号或范围已变化。');
  const file = await apiConfigurationBlob(configurationPath(input.identity, `configuration/exports/${input.id}/download`), { revision: input.revision, confirmed: true, confirm_name: input.name }, newIdempotencyKey(), input.signal);
  if (input.signal?.aborted || !sameConfigurationIdentity(input.identity, input.current())) throw new Error('范围或权限已变化，已忽略旧下载。');
  const expected = input.format === 'review-json' ? /application\/json/i : /(?:yaml|octet-stream)/i;
  if (!expected.test(file.contentType ?? '')) throw new Error('下载格式与原导出任务不符。');
  const url = URL.createObjectURL(file.blob), anchor = document.createElement('a');
  try { anchor.href = url; anchor.download = configurationDownloadFilename(file.contentDisposition, input.format); anchor.style.display = 'none'; document.body.appendChild(anchor); anchor.click(); } finally { anchor.remove(); URL.revokeObjectURL(url); }
}
