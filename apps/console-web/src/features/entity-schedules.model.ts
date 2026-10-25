import { canonicalId } from '../api/workspace-scope';
import { isEntityType } from './entities';

export interface ScheduledIntentSpec { id: string; version: 1; executorId: string; notBefore: string; windowStart: string; windowEnd: string; }
export interface EntitySchedule {
  id: string; revision: number; state: string; intentId: string; notBefore: string; windowStart: string; windowEnd: string;
  workflowId: string | null; claimId: string | null; reasonCode: string | null; nativeAuthority: false;
  capabilities: { activate: boolean; cancel: boolean };
}
export interface ScheduleLocalInput { notBefore: string; windowStart: string; windowEnd: string; }
export const entityScheduleStateLabels: Record<string, string> = { 'pending-approval': '待审批', active: '已激活待执行', claimed: '已领取', running: '执行中', succeeded: '已完成', partial: '部分完成', failed: '失败', uncertain: '结果待核验', blocked: '已阻止', cancelled: '已撤销', expired: '已过期' };
const object = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
export function canonicalScheduleInstant(value: unknown): value is string { return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value; }
export function validateScheduleWindow(value: Pick<ScheduledIntentSpec, 'notBefore' | 'windowStart' | 'windowEnd'>) {
  if (![value.notBefore, value.windowStart, value.windowEnd].every(canonicalScheduleInstant) || Date.parse(value.windowStart) > Date.parse(value.notBefore) || Date.parse(value.notBefore) >= Date.parse(value.windowEnd)) throw new Error('执行时间必须位于变更窗口内：开始时间 ≤ 执行时间 < 结束时间。');
}
export function shanghaiLocalToUtc(value: string) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value);
  if (!match) throw new Error('请输入上海时区的完整日期与时间。');
  const [, y, m, d, h, min, seconds] = match, parts = [y, m, d, h, min, seconds ?? '0'].map(Number), [year, month, day, hour, minute, second] = parts;
  const local = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (year < 2000 || local.getUTCFullYear() !== year || local.getUTCMonth() !== month - 1 || local.getUTCDate() !== day || local.getUTCHours() !== hour || local.getUTCMinutes() !== minute || local.getUTCSeconds() !== second) throw new Error('日期或时间无效。');
  return new Date(local.getTime() - 8 * 3600000).toISOString();
}
export function formatScheduleTime(value: string) {
  if (!canonicalScheduleInstant(value)) return '—';
  return new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date(value));
}
export function defaultScheduleLocal(now = Date.now()): ScheduleLocalInput {
  const local = (offset: number) => new Date(Math.ceil((now + offset) / 60000) * 60000 + 8 * 3600000).toISOString().slice(0, 16);
  return { notBefore: local(15 * 60000), windowStart: local(10 * 60000), windowEnd: local(60 * 60000) };
}
export function scheduledTargetChangeValid(change: Record<string, any>) {
  if (change.kind !== 'target' || !['create', 'weight'].includes(change.action) || canonicalId(change.upstreamId) !== change.upstreamId || !canonicalId(change.upstreamId) || !object(change.body)) return false;
  const creating = change.action === 'create';
  if (Object.keys(change).some(key => !['kind', 'action', 'upstreamId', 'body', ...(creating ? [] : ['targetId'])].includes(key))
    || !creating && (canonicalId(change.targetId) !== change.targetId || !canonicalId(change.targetId))) return false;
  if (Object.keys(change.body).some(key => !(creating ? ['target', 'weight', 'tags'] : ['weight']).includes(key))) return false;
  if (creating && (typeof change.body.target !== 'string' || !change.body.target.trim())) return false;
  if ((!creating || change.body.weight !== undefined) && (!Number.isInteger(change.body.weight) || change.body.weight < 0 || change.body.weight > 1000)) return false;
  return change.body.tags === undefined || Array.isArray(change.body.tags) && change.body.tags.every((tag: unknown) => typeof tag === 'string' && !/^workspace:|^kos-ws-/i.test(tag));
}
/** A returned append has a new ID; the selected old ID remains its before identity. */
export function scheduledTargetReviewMatchesRequest(changes: Array<{ entityType: string; nativeId: string; originalNativeId?: string; action: string; before: unknown; after: unknown }>, request: Record<string, any>) {
  if (!scheduledTargetChangeValid(request) || changes.length !== 1) return false;
  const row = changes[0], creating = request.action === 'create';
  if (row.entityType !== 'targets' || row.action !== (creating ? 'create' : 'update') || !object(row.after) || row.after.id !== row.nativeId
    || request.body.weight !== undefined && row.after.weight !== request.body.weight) return false;
  if (creating) return row.originalNativeId === undefined && row.before === null && row.after.target === request.body.target;
  return row.originalNativeId === request.targetId && row.nativeId !== request.targetId && object(row.before) && row.before.id === request.targetId
    && row.before.upstream?.id === request.upstreamId && typeof row.before.target === 'string' && row.after.target === row.before.target;
}
export function scheduledPreparationPayload(change: Record<string, any>, input: ScheduleLocalInput, executorId: string | undefined, ttlHours: number, now = Date.now()) {
  const target = change.kind === 'target', valid = target ? scheduledTargetChangeValid(change) : change.kind === 'entity' && isEntityType(change.entityType) || change.kind === 'credential' && ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'].includes(change.credentialKind) && !!canonicalId(change.consumerId);
  if (!valid || !target && (!['create', 'update'].includes(change.action) || !object(change.body) || change.action === 'update' && !canonicalId(change.kind === 'entity' ? change.entityId : change.credentialId))) throw new Error('请选择受支持的定时创建、编辑或 Target 权重变更。');
  if (!canonicalId(executorId) || !Number.isInteger(ttlHours) || ttlHours < 1 || ttlHours > 168) throw new Error('执行账号或工单有效期无效。');
  const schedule = { version: 1 as const, executorId: executorId!, notBefore: shanghaiLocalToUtc(input.notBefore), windowStart: shanghaiLocalToUtc(input.windowStart), windowEnd: shanghaiLocalToUtc(input.windowEnd) };
  validateScheduleWindow(schedule);
  if (Date.parse(schedule.notBefore) <= now || Date.parse(schedule.windowEnd) > now + ttlHours * 3600000) throw new Error('执行时间必须在未来，且窗口结束不得超过工单有效期。');
  return { change: structuredClone(change), ttlHours, confirmed: true as const, confirm_name: 'scheduled-change' as const, schedule };
}
export function normalizeScheduledIntentSpec(raw: unknown): ScheduledIntentSpec {
  if (!object(raw) || !canonicalId(raw.id) || raw.version !== 1 || !canonicalId(raw.executorId)) throw new Error('定时变更预览格式无效。');
  validateScheduleWindow(raw as ScheduledIntentSpec);
  return { id: raw.id, version: 1, executorId: raw.executorId, notBefore: raw.notBefore, windowStart: raw.windowStart, windowEnd: raw.windowEnd };
}
export function scheduledIntentMatchesRequest(actual: ScheduledIntentSpec | undefined, requested: Omit<ScheduledIntentSpec, 'id'>) {
  return !!actual && ['version', 'executorId', 'notBefore', 'windowStart', 'windowEnd'].every(field => actual[field as keyof ScheduledIntentSpec] === requested[field as keyof typeof requested]);
}
export function normalizeEntitySchedule(raw: unknown): EntitySchedule {
  if (!object(raw) || !canonicalId(raw.id) || !Number.isSafeInteger(raw.revision) || raw.revision < 1 || !Object.hasOwn(entityScheduleStateLabels, raw.state) || !canonicalId(raw.intentId) || raw.nativeAuthority !== false
    || raw.workflowId !== null && !canonicalId(raw.workflowId) || raw.claimId !== null && !canonicalId(raw.claimId) || raw.reasonCode !== null && (typeof raw.reasonCode !== 'string' || !/^[A-Z0-9_]{1,128}$/.test(raw.reasonCode))) throw new Error('定时变更响应格式无效。');
  validateScheduleWindow(raw as EntitySchedule);
  return { id: raw.id, revision: raw.revision, state: raw.state, intentId: raw.intentId, notBefore: raw.notBefore, windowStart: raw.windowStart, windowEnd: raw.windowEnd, workflowId: raw.workflowId, claimId: raw.claimId, reasonCode: raw.reasonCode, nativeAuthority: false, capabilities: { activate: raw.capabilities?.activate === true, cancel: raw.capabilities?.cancel === true } };
}
export function entityScheduleCommandBody(row: EntitySchedule, action: 'activate' | 'cancel') {
  if (row.capabilities[action] !== true) throw new Error('服务端当前未授予此定时变更操作。');
  return { revision: row.revision, confirmed: true as const, confirm_name: `${action}-schedule` };
}
export function normalizeEntityScheduleCommand(raw: unknown, expectedId: string): EntitySchedule {
  if (!object(raw) || raw.commandCompleted !== true) throw new Error('定时操作回执不完整，请核验原请求。');
  const entity = normalizeEntitySchedule(raw.entity); if (entity.id !== expectedId) throw new Error('定时操作记录不匹配。'); return entity;
}
