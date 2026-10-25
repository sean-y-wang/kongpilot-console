import { BadRequestException } from '@nestjs/common';
import type { VitalsTimeWindow } from '../vitals.types';

/** Loki evaluates metric ranges on Unix step boundaries, rather than start + n*step. */
export function lokiEvaluationWindow(requested: VitalsTimeWindow): VitalsTimeWindow {
  const stepMs = requested.step * 1000;
  const start = Math.ceil(Date.parse(requested.start) / stepMs) * stepMs;
  const end = Math.floor(Date.parse(requested.end) / stepMs) * stepMs;
  if (!Number.isFinite(start) || !Number.isFinite(end) || start > end) {
    throw new BadRequestException({ code: 'LOKI_EVALUATION_WINDOW_EMPTY', message: '请求范围内没有 Loki 时间步长采样点，请缩小步长或扩大时间范围' });
  }
  return { ...requested, start: new Date(start).toISOString(), end: new Date(end).toISOString() };
}
