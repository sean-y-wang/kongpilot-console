import { canonicalId } from '../api/workspace-scope';
import { nativeEventTypes, type EventChannel, type NotificationView } from './m7.types';
export function lines(value: unknown, max = 256): string[] { const items = typeof value === 'string' ? value.split(/\r?\n/).map(v => v.trim()).filter(Boolean) : []; if (items.length > max) throw new Error(`最多 ${max} 项`); return [...new Set(items)]; }
export function logicalTags(value: unknown): string[] { const tags = lines(value); if (tags.some(tag => tag.startsWith('workspace:') || tag.startsWith('kos-ws-'))) throw new Error('保留工作区标签不能作为业务标签提交'); return tags; }
export function channelPayload(values: Record<string, any>, row?: EventChannel): Record<string, unknown> {
  const changing = !!values.replaceTarget || !row, body: Record<string, unknown> = row ? { revision: row.revision } : { name: values.name, type: values.type, options: {}, status: values.status ?? 'active' };
  if (changing) {
    if (values.type === 'email') { const recipients = lines(values.recipients, 50); if (!recipients.length) throw new Error('请输入收件人'); body.endpoint = { recipients }; }
    else { if (typeof values.endpoint !== 'string' || !values.endpoint.trim() || /\*{2}|••/.test(values.endpoint)) throw new Error('请输入完整的新目标地址，不能提交掩码'); body.endpoint = values.endpoint.trim(); }
    if (!['none', 'bearer', 'basic', 'feishu-signature'].includes(values.authType)) throw new Error('请选择新的目标认证方式');
    body.auth = values.authType === 'none' ? { type: 'none' } : values.authType === 'bearer' ? { type: 'bearer', token: values.token } : values.authType === 'basic' ? { type: 'basic', username: values.username, password: values.password } : { type: 'feishu-signature', secret: values.secret };
    if (Object.entries(body.auth as Record<string, unknown>).some(([key, value]) => key !== 'type' && (typeof value !== 'string' || !value))) throw new Error('新目标认证内容不完整');
  }
  return body;
}
export function notificationBatch(rows: NotificationView[], action: 'read' | 'dismiss'): Record<string, unknown> {
  if (!rows.length || rows.length > 100 || !canonicalId(rows[0].clusterId) || !canonicalId(rows[0].workspaceId)) throw new Error('请选择同一集群、工作区的 1–100 条通知');
  const { clusterId, workspaceId } = rows[0], seen = new Set<string>();
  if (rows.some(row => row.clusterId !== clusterId || row.workspaceId !== workspaceId || !canonicalId(row.id) || !Number.isInteger(row.revision) || row.revision < 1 || !row.capabilities.write || seen.has(row.id) || !seen.add(row.id))) throw new Error('通知范围、权限或版本不一致');
  return { clusterId, workspaceId, items: rows.map(({ id, revision }) => ({ id, revision })), confirmed: true };
}
export function eventFilters(values: Record<string, any>): { eventTypes: string[]; nativeType: string | null; nativeIds: string[]; tags: string[] } {
  if (!Array.isArray(values.eventTypes) || !values.eventTypes.length || values.eventTypes.length > 32 || values.eventTypes.some((value: unknown) => typeof value !== 'string' || value.length > 128)) throw new Error('请选择 1–32 个事件类型');
  const nativeIds = lines(values.nativeIdsText), nativeType = values.nativeType ?? null;
  if (nativeIds.some(id => !canonicalId(id)) || nativeType !== null && !nativeEventTypes.includes(nativeType) || nativeIds.length && !nativeType) throw new Error('对象 ID 必须为有效 UUID，且选择其对象类型');
  return { eventTypes: [...new Set(values.eventTypes)], nativeType, nativeIds, tags: logicalTags(values.tagsText) };
}
export function personalPreferencePayload(values: Record<string, any>, scope: { cid?: string; wid?: string }, revision?: number): Record<string, unknown> {
  const { nativeType, ...filters } = eventFilters(values);
  return { clusterId: scope.cid, workspaceId: scope.wid, name: values.name, ...filters, ...(nativeType === null ? {} : { nativeType }), inAppEnabled: values.inAppEnabled, ...(revision === undefined ? {} : { revision }) };
}
