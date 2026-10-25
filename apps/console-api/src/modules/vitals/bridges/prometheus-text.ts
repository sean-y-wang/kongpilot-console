import { BadGatewayException } from '@nestjs/common';
export interface PrometheusSample { name: string; labels: Record<string, string>; value: number; }
const definitions: Record<string, { type: string; labels: string[] }> = {
  kong_http_status: { type: 'counter', labels: ['code', 'service', 'route'] },
  kong_latency_bucket: { type: 'histogram', labels: ['type', 'service', 'route', 'le'] },
  kong_latency_count: { type: 'histogram', labels: ['type', 'service', 'route'] },
  kong_latency_sum: { type: 'histogram', labels: ['type', 'service', 'route'] },
  kong_bandwidth: { type: 'counter', labels: ['type', 'service', 'route'] },
  kong_datastore_reachable: { type: 'gauge', labels: [] },
  kong_nginx_http_current_connections: { type: 'gauge', labels: ['state'] },
  kong_memory_lua_shared_dict_bytes: { type: 'gauge', labels: ['shared_dict'] },
  kong_memory_lua_shared_dict_total_bytes: { type: 'gauge', labels: ['shared_dict'] },
  kong_memory_workers_lua_vms_bytes: { type: 'gauge', labels: ['pid'] },
  kong_nginx_metric_errors_total: { type: 'counter', labels: [] },
};
const invalid = () => new BadGatewayException({ code: 'INVALID_NATIVE_METRICS', message: 'Kong 指标文本格式无效或超过预算' });
function labels(text: string): Record<string, string> {
  const result: Record<string, string> = Object.create(null);
  let position = 0;
  const pattern = /\s*([a-zA-Z_][a-zA-Z\d_]*)="((?:[^"\\]|\\[\\"n])*)"\s*(?:,|$)/gy;
  while (position < text.length) {
    pattern.lastIndex = position; const match = pattern.exec(text);
    if (!match || Object.hasOwn(result, match[1])) throw invalid();
    const decoded = match[2].replace(/\\([\\"n])/g, (_whole, char) => char === 'n' ? '\n' : char);
    if (decoded.length > 1024 || Object.keys(result).length >= 16) throw invalid();
    result[match[1]] = decoded; position = pattern.lastIndex;
  }
  return result;
}
export function parsePrometheusText(text: string): PrometheusSample[] {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 2 * 1024 * 1024) throw invalid();
  const result: PrometheusSample[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (line.length > 8192 || result.length >= 32000) throw invalid();
    const match = /^([a-zA-Z_:][a-zA-Z\d_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+[+-]?\d+)?\s*$/.exec(line);
    if (!match) throw invalid();
    if (!Object.hasOwn(definitions, match[1])) continue;
    const values = labels(match[2] || ''), definition = definitions[match[1]];
    if (Object.keys(values).some(key => !definition.labels.includes(key)) || definition.labels.some(key => !Object.hasOwn(values, key))) throw invalid();
    if (!/^(?:[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|NaN|[+-]?Inf)$/.test(match[3])) throw invalid();
    const value = Number(match[3]);
    // Native NaN is missing information, never a synthetic zero.
    if (!Number.isFinite(value)) continue;
    if (value < 0 || match[1] === 'kong_http_status' && !/^[1-5]\d\d$/.test(values.code)
      || match[1].startsWith('kong_latency_') && !['request', 'upstream', 'kong'].includes(values.type)
      || match[1] === 'kong_bandwidth' && !['ingress', 'egress'].includes(values.type)) throw invalid();
    if (match[1] === 'kong_latency_bucket' && values.le !== '+Inf' && !(Number.isFinite(Number(values.le)) && Number(values.le) > 0)) throw invalid();
    result.push({ name: match[1], labels: values, value });
  }
  return result;
}
export function escapePrometheusLabel(value: string): string { return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"'); }
export function encodePrometheusText(samples: PrometheusSample[]): string {
  const emitted = new Set<string>(), lines: string[] = [];
  for (const sample of samples) {
    const family = sample.name.startsWith('kong_latency_') ? 'kong_latency' : sample.name;
    if (!emitted.has(family)) { lines.push(`# TYPE ${family} ${definitions[sample.name].type}`); emitted.add(family); }
    const labelText = Object.entries(sample.labels).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}="${escapePrometheusLabel(value)}"`).join(',');
    lines.push(`${sample.name}${labelText ? `{${labelText}}` : ''} ${sample.value}`);
  }
  const result = `${lines.join('\n')}\n`;
  if (Buffer.byteLength(result) > 2 * 1024 * 1024) throw invalid();
  return result;
}
