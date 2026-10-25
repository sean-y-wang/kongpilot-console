import { describe, expect, it } from 'vitest';
import { encodePrometheusText, parsePrometheusText } from '../../apps/console-api/src/modules/vitals/bridges/prometheus-text';
describe('Kong 1.5 native text sanitization', () => {
  it('retains exact 0.6 counter/histogram families and drops custom families', () => {
    const samples = parsePrometheusText('kong_http_status{code="200",service="svc",route="r"} 12\nkong_latency_bucket{type="request",service="svc",route="r",le="+Inf"} 10\ncustom_token_metric{token="secret"} 1\n');
    expect(samples).toHaveLength(2); expect(encodePrometheusText(samples)).not.toContain('custom_token_metric');
  });
  it.each(['0x10', '0b10', '--1', '1_000', '-1'])('rejects invalid or negative sample %s', value => expect(() => parsePrometheusText(`kong_datastore_reachable ${value}\n`)).toThrow());
  it('omits NaN and infinities without inventing zero samples', () => expect(parsePrometheusText('kong_datastore_reachable NaN\nkong_datastore_reachable +Inf\n')).toEqual([]));
  it.each(['token="secret"', 'service="s",route="r",code="200",code="401"'])('rejects unauthorized or duplicate label set', labels => expect(() => parsePrometheusText(`kong_http_status{${labels}} 1\n`)).toThrow());
  it('escapes labels as data without adding a new sample or raw comment', () => {
    const text = encodePrometheusText([{ name: 'kong_http_status', labels: { code: '200', cluster_id: 'c', route_id: 'r"\nsecret' }, value: 1 }]);
    expect(text.split('\n')).toHaveLength(3); expect(text).toContain('r\\"\\nsecret');
  });
});
