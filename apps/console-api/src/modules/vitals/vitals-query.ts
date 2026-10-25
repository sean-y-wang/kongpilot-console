import { BadRequestException } from '@nestjs/common';
import type { VitalsQuery, VitalsTimeWindow } from './vitals.types';
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
export function metricsId(value: unknown, optional = false): string | undefined {
  if (optional && value === undefined) return undefined;
  if (typeof value !== 'string' || !uuid.test(value)) throw new BadRequestException({ code: 'INVALID_METRICS_ID', message: '监控标识必须是 UUID' });
  return value.toLowerCase();
}
export function exactKeys(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) throw new BadRequestException({ code: 'INVALID_VITALS_QUERY', message: '监控请求含不支持的字段' });
}
export function parseVitalsQuery(query: VitalsQuery, now = Date.now()): VitalsTimeWindow {
  exactKeys(query, ['workspaceId', 'scope', 'sourceId', 'serviceId', 'routeId', 'start', 'end', 'step']);
  if (query.scope !== undefined && (typeof query.scope !== 'string' || !['workspace', 'cluster'].includes(query.scope))) throw new BadRequestException({ code: 'INVALID_METRICS_SCOPE', message: '监控范围须为 workspace 或 cluster' });
  for (const field of ['workspaceId', 'sourceId', 'serviceId', 'routeId'] as const) metricsId(query[field], true);
  const parse = (value: unknown): number => {
    if (typeof value !== 'string' || !iso.test(value)) throw new BadRequestException({ code: 'INVALID_METRICS_TIME', message: '时间必须使用 ISO UTC Z 格式' });
    const result = Date.parse(value);
    if (!Number.isFinite(result) || new Date(result).toISOString() !== (value.includes('.') ? value : value.replace('Z', '.000Z'))) throw new BadRequestException({ code: 'INVALID_METRICS_TIME', message: '时间无效' });
    return result;
  };
  const start = parse(query.start), end = parse(query.end), duration = end - start;
  if (duration < 300_000 || duration > 7 * 86400_000 || end > now + 5000) throw new BadRequestException({ code: 'INVALID_METRICS_WINDOW', message: '时间范围须为 5 分钟至 7 天，结束时间不得超出当前时间' });
  if (query.step !== undefined && (typeof query.step !== 'string' && typeof query.step !== 'number' || typeof query.step === 'string' && !/^\d+$/.test(query.step))) throw new BadRequestException({ code: 'INVALID_METRICS_STEP', message: '采样间隔必须为整数' });
  const step = query.step === undefined ? Math.max(15, Math.ceil(duration / 1000 / 799)) : Number(query.step);
  if (!Number.isInteger(step) || step < 15 || step > 86400 || Math.floor(duration / (step * 1000)) + 1 > 800) throw new BadRequestException({ code: 'INVALID_METRICS_STEP', message: '采样间隔须不少于 15 秒，每条曲线最多 800 个点' });
  return { start: new Date(start).toISOString(), end: new Date(end).toISOString(), step, rateWindowSeconds: Math.max(60, 2 * step) };
}
