import { describe, expect, it } from 'vitest';
import { exactKeys, metricsId, parseVitalsQuery } from '../../apps/console-api/src/modules/vitals/vitals-query';
import { MetricsQueryBudget } from '../../apps/console-api/src/modules/vitals/providers/query-budget';

const now = Date.parse('2026-10-10T20:00:00.000Z');
const query = { start: '2026-10-10T19:55:00Z', end: '2026-10-10T20:00:00Z' };
const mib = 1024 * 1024;

describe('M5 independent bounded UTC query parsing', () => {
  it('normalizes the five-minute UTC window and reserves the rate window on the server', () => {
    expect(parseVitalsQuery(query, now)).toEqual({ start: '2026-10-10T19:55:00.000Z', end: '2026-10-10T20:00:00.000Z', step: 15, rateWindowSeconds: 60 });
    expect(parseVitalsQuery({ ...query, step: 60 }, now).rateWindowSeconds).toBe(120);
  });
  it('keeps seven days within 800 inclusive timestamps rather than truncating a curve', () => {
    const parsed = parseVitalsQuery({ start: new Date(now - 7 * 86400_000).toISOString(), end: query.end }, now);
    expect(Math.floor(7 * 86400 / parsed.step) + 1).toBeLessThanOrEqual(800);
    expect(() => parseVitalsQuery({ start: new Date(now - 7 * 86400_000 - 1).toISOString(), end: query.end }, now)).toThrow();
  });
  it('accepts exactly 800 samples and rejects 801 before executing a provider', () => {
    expect(parseVitalsQuery({ start: new Date(now - 799 * 15_000).toISOString(), end: query.end, step: '15' }, now).step).toBe(15);
    expect(() => parseVitalsQuery({ start: new Date(now - 800 * 15_000).toISOString(), end: query.end, step: '15' }, now)).toThrow();
  });
  it.each(['2026-02-30T19:55:00Z', '2026-10-10T19:55:00+00:00', '2026-10-10T19:55:00', '2026-13-10T19:55:00Z', 'not-a-date'])
    ('rejects the malformed or noncanonical timestamp %s', start => {
      expect(() => parseVitalsQuery({ ...query, start }, now)).toThrow();
    });
  it('enforces the exact five-second future allowance without hiding a wrong clock', () => {
    const window = (extra: number) => ({ start: query.start, end: new Date(now + extra).toISOString() });
    expect(() => parseVitalsQuery(window(5000), now)).not.toThrow();
    expect(() => parseVitalsQuery(window(5001), now)).toThrow();
    expect(() => parseVitalsQuery({ start: query.end, end: query.start }, now)).toThrow();
    expect(() => parseVitalsQuery({ start: new Date(now - 299_999).toISOString(), end: query.end }, now)).toThrow();
  });
  it.each(['promql', 'query', 'consumerId', 'url', 'path', 'template', 'rateWindow'])
    ('rejects caller-controlled %s instead of accepting a generic metrics proxy', field => {
      expect(() => parseVitalsQuery({ ...query, [field]: 'untrusted-input' } as any, now)).toThrow();
    });
  it.each([14, 15.5, Number.NaN, Infinity, 86401, ['15'], ['15', '15'], { value: '15' }].map(step => ({ step })))
    ('rejects invalid or structured step $step', ({ step }) => {
      expect(() => parseVitalsQuery({ ...query, step } as any, now)).toThrow();
    });
  it('requires UUID IDs and exact top-level objects for caps/entity query callers', () => {
    expect(metricsId('A0C05A03-0E83-4E6F-9A5F-C4136287C4B4')).toBe('a0c05a03-0e83-4e6f-9a5f-c4136287c4b4');
    expect(() => metricsId(['a0c05a03-0e83-4e6f-9a5f-c4136287c4b4'])).toThrow();
    expect(() => metricsId('service-name')).toThrow();
    expect(() => exactKeys([], ['workspaceId', 'sourceId'])).toThrow();
    expect(() => exactKeys({ sourceId: 'id', endpoint: 'http://untrusted' }, ['workspaceId', 'sourceId'])).toThrow();
  });
  it('accepts only explicit scalar workspace/cluster aggregation, never invented or structured scopes', () => {
    expect(() => parseVitalsQuery({ ...query, scope: 'workspace' }, now)).not.toThrow();
    expect(() => parseVitalsQuery({ ...query, scope: 'cluster' }, now)).not.toThrow();
    for (const scope of ['global', 'platform_all_epochs', ['cluster'], { value: 'workspace' }, null, false]) expect(() => parseVitalsQuery({ ...query, scope } as any, now)).toThrow();
  });
});

describe('M5 independent whole-overview metrics resource budgets', () => {
  it('shares the byte and call budget across latency, status, bandwidth and TopN calls', () => {
    const budget = new MetricsQueryBudget();
    expect(budget.beginCall()).toBe(8 * mib); budget.chargeResponse(3 * mib);
    expect(budget.beginCall()).toBe(5 * mib); budget.chargeResponse(5 * mib);
    expect(() => budget.beginCall()).toThrow();
    expect(budget.snapshot().bytes).toBe(8 * mib);
    const calls = new MetricsQueryBudget();
    for (let index = 0; index < 18; index++) calls.beginCall();
    expect(() => calls.beginCall()).toThrow();
  });
  it('refuses aggregate overflow even if every individual provider response was within its own bound', () => {
    const budget = new MetricsQueryBudget();
    for (let index = 0; index < 8; index++) { budget.beginCall(); budget.chargeResponse(mib); }
    expect(() => budget.chargeResponse(1)).toThrow();
  });
  it('counts all public series and samples, and does not silently clip a large curve', () => {
    const budget = new MetricsQueryBudget();
    for (let index = 0; index < 64; index++) budget.chargeSeries(800);
    expect(budget.snapshot()).toMatchObject({ series: 64, points: 51200 });
    expect(() => budget.chargeSeries(0)).toThrow();
    expect(() => new MetricsQueryBudget().chargeSeries(801)).toThrow();
    const sharedPoints = new MetricsQueryBudget({ calls: 18, bytes: 8 * mib, series: 64, points: 1000 });
    sharedPoints.chargeSeries(700); expect(() => sharedPoints.chargeSeries(301)).toThrow();
  });
  it('bounds UTF-8 public bytes rather than only string length', () => {
    const budget = new MetricsQueryBudget();
    expect(() => budget.publicResponse({ names: '汉'.repeat(700_000) })).toThrow();
    expect(() => budget.publicResponse({ series: [{ value: null }, { value: 0 }] })).not.toThrow();
  });
  it('does not let malformed accounting values create a negative or infinite budget', () => {
    for (const value of [-1, 0.5, Number.NaN, Infinity]) {
      expect(() => new MetricsQueryBudget().chargeResponse(value)).toThrow();
      expect(() => new MetricsQueryBudget().chargeSeries(value)).toThrow();
    }
  });
});
