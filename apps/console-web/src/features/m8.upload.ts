import { MAX_CONFIGURATION_UPLOAD_BYTES, configurationSelection } from './m8.model';
import type { ConfigurationSelection } from './m8.types';
/** Plaintext is limited to this call and its File/Form input; never returned as a query/receipt. */
export async function uploadConfiguration<T>(input: {
  selection: ConfigurationSelection; mode: 'merge' | 'sync'; confirmDeletes?: boolean; basicPasswordIntents?: Record<string, 'keep' | 'replace'>; file?: Pick<File, 'size' | 'text'>; content?: string;
  assertCurrent: () => void; clearMaterial: () => void;
  upload: (body: ConfigurationSelection & { mode: 'merge' | 'sync'; yaml: string; confirm_deletes?: true; basicPasswordIntents?: Record<string, 'keep' | 'replace'> }) => Promise<T>;
}): Promise<T> {
  let content = '';
  try {
    input.assertCurrent(); const selection = configurationSelection(input.selection);
    if (!['merge', 'sync'].includes(input.mode) || input.file && input.file.size > MAX_CONFIGURATION_UPLOAD_BYTES) throw new Error('文件或导入模式无效。');
    if (input.mode === 'sync' && input.confirmDeletes !== true) throw new Error('同步预检须明确确认包含范围内的拟删除影响；执行前仍会再次确认实际数量。');
    content = input.file ? await input.file.text() : input.content ?? '';
    if (!content.trim() || new TextEncoder().encode(content).byteLength > MAX_CONFIGURATION_UPLOAD_BYTES) throw new Error('配置必须非空且不超过 8 MiB。');
    input.assertCurrent(); input.clearMaterial();
    return await input.upload({ ...selection, mode: input.mode, yaml: content, ...(input.mode === 'sync' ? { confirm_deletes: true as const } : {}), ...(input.basicPasswordIntents && Object.keys(input.basicPasswordIntents).length ? { basicPasswordIntents: input.basicPasswordIntents } : {}) });
  } finally { content = ''; input.clearMaterial(); }
}
