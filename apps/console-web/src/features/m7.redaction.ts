import { redactForDisplay } from '../api/redaction';
import { isSensitiveSchemaName } from '../components/kong-schema-rules';
export function jsonPointerParts(pointer: string): string[] { if (!pointer.startsWith('/') && pointer !== '') throw new Error('JSON pointer 无效'); return pointer.split('/').slice(1).map(part => { if (/~(?![01])/u.test(part)) throw new Error('JSON pointer 转义无效'); return part.replace(/~1/g, '/').replace(/~0/g, '~'); }); }
export function redactAuditPatch(value: unknown): unknown {
  if (!Array.isArray(value)) return '[INVALID PATCH]';
  return value.slice(0, 500).map(item => {
    if (!item || typeof item !== 'object' || !['add', 'remove', 'replace', 'move', 'copy', 'test'].includes(item.op) || typeof item.path !== 'string') return '[INVALID PATCH]';
    try { const names = [...jsonPointerParts(item.path), ...(typeof item.from === 'string' ? jsonPointerParts(item.from) : [])]; return { op: item.op, path: item.path, ...(typeof item.from === 'string' ? { from: item.from } : {}), ...(Object.hasOwn(item, 'value') ? { value: names.some(name => isSensitiveSchemaName(name, typeof item.value)) ? '[REDACTED]' : redactForDisplay(item.value) } : {}) }; } catch { return '[INVALID PATCH]'; }
  });
}
export function safeJsonPreview(value: unknown): string { const text = JSON.stringify(redactForDisplay(value), null, 2) ?? 'null'; return text.length > 65536 ? text.slice(0, 65536) + '\n…（显示上限 64KiB）' : text; }
