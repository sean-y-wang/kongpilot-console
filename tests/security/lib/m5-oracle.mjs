/** Independent conversion of a real Prometheus reply; absence remains null. */
export function finitePrometheusValue(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

export function oracleMatrixPoints(matrix, scale = 1) {
  if (!Array.isArray(matrix)) throw new Error('Prometheus matrix must be an array');
  const values = new Map();
  for (const series of matrix) {
    for (const [seconds, raw] of series.values ?? []) {
      const timestamp = Math.round(Number(seconds) * 1000);
      const number = finitePrometheusValue(raw);
      const prior = values.get(timestamp);
      // Each oracle template must have the same intended aggregation as the
      // public series. Sum only real values; never coerce NaN/missing to zero.
      values.set(timestamp, number === null ? prior ?? null : (prior ?? 0) + number * scale);
    }
  }
  return [...values].sort(([a], [b]) => a - b);
}

export function compareMonitoringPoints(actual, oracle, { absolute = 1e-8, relative = 1e-6 } = {}) {
  const expected = new Map(oracle);
  const actualTimes = new Set();
  let compared = 0, nullCompared = 0;
  for (const [timestamp, raw] of actual) {
    if (actualTimes.has(timestamp)) throw new Error('public series has duplicate timestamps');
    actualTimes.add(timestamp);
    const value = finitePrometheusValue(raw);
    const reference = expected.has(timestamp) ? expected.get(timestamp) : null;
    if (reference === null) {
      if (value !== null) throw new Error('missing oracle sample was presented as a value');
      nullCompared++;
      continue;
    }
    if (value === null || Math.abs(value - reference) > absolute + relative * Math.abs(reference)) throw new Error('public sample differs from real Prometheus oracle');
    compared++;
  }
  if ([...expected].some(([timestamp, value]) => value !== null && !actualTimes.has(timestamp))) throw new Error('public series omitted a real oracle timestamp');
  return { compared, nullCompared, points: actual.length };
}

/** Prometheus classic histogram linear interpolation, independently computed. */
export function classicHistogramQuantile(quantile, buckets) {
  if (!Number.isFinite(quantile) || quantile < 0 || quantile > 1) throw new Error('quantile must be within0..1');
  const ordered = buckets.map(([bound, count]) => [bound === '+Inf' || bound === Infinity ? Infinity : Number(bound), finitePrometheusValue(count)]).sort(([a], [b]) => a - b);
  if (ordered.length < 2 || ordered.at(-1)[0] !== Infinity || ordered.some(([bound, count], index) => Number.isNaN(bound) || count === null || count < 0 || index > 0 && count < ordered[index - 1][1])) return null;
  const total = ordered.at(-1)[1];
  if (total === 0) return null;
  const rank = quantile * total;
  const index = ordered.findIndex(([, count]) => count >= rank);
  if (index === ordered.length - 1) return ordered[index - 1][0];
  const [upper, count] = ordered[index];
  const lower = index === 0 ? Math.min(0, upper) : ordered[index - 1][0];
  const previous = index === 0 ? 0 : ordered[index - 1][1];
  if (count === previous) return upper;
  return lower + (upper - lower) * (rank - previous) / (count - previous);
}
