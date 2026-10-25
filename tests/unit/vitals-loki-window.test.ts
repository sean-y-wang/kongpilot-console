import { describe, expect, it } from 'vitest';
import { lokiEvaluationWindow } from '../../apps/console-api/src/modules/vitals/providers/loki-window';
import { parseVitalsQuery } from '../../apps/console-api/src/modules/vitals/vitals-query';

describe('Loki actual Unix-step evaluation windows', () => {
  const window = { start: '2026-10-10T20:12:01.000Z', end: '2026-10-10T20:17:01.000Z', step: 15, rateWindowSeconds: 60 };
  it('keeps all evaluation points inside the original request without inventing a final sample', () => {
    expect(lokiEvaluationWindow(window)).toEqual({ ...window, start: '2026-10-10T20:12:15.000Z', end: '2026-10-10T20:17:00.000Z' });
    expect(window.start).toBe('2026-10-10T20:12:01.000Z');
  });
  it('retains an already aligned request and rounds subsecond bounds inward', () => {
    const aligned = { ...window, start: '2026-10-10T20:12:15.000Z', end: '2026-10-10T20:17:00.000Z' };
    expect(lokiEvaluationWindow(aligned)).toEqual(aligned);
    expect(lokiEvaluationWindow({ ...window, start: '2026-10-10T20:12:15.001Z', end: '2026-10-10T20:17:00.999Z' })).toEqual({ ...window, start: '2026-10-10T20:12:30.000Z', end: '2026-10-10T20:17:00.000Z' });
  });
  it('rejects a valid requested range whose large step has no evaluation point', () => {
    const parsed = parseVitalsQuery({ start: window.start, end: window.end, step: 86400 }, Date.parse(window.end));
    expect(() => lokiEvaluationWindow(parsed)).toThrow(expect.objectContaining({ status: 400, response: expect.objectContaining({ code: 'LOKI_EVALUATION_WINDOW_EMPTY' }) }));
  });
  it('checks the minimum requested duration before shortening the evaluation span', () => {
    const parsed = parseVitalsQuery({ start: window.start, end: window.end, step: 15 }, Date.parse(window.end));
    const evaluated = lokiEvaluationWindow(parsed);
    expect(Date.parse(evaluated.end) - Date.parse(evaluated.start)).toBe(285000);
    expect(() => parseVitalsQuery({ start: evaluated.start, end: evaluated.end, step: 15 }, Date.parse(window.end))).toThrow();
  });
});
