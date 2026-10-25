import { randomBytes, createHash } from 'node:crypto';
import { isUuid } from '../metrics-collector/sanitize.mjs';

export const purposes = ['native_scrape', 'collector_scrape', 'collector_catalog', 'collector_ingest'];
export const digest = token => createHash('sha256').update(token, 'utf8').digest('hex');
export function createMetricsMaterial(clusterId, generation, random = () => randomBytes(32).toString('base64url')) {
  if (!isUuid(clusterId) || !Number.isSafeInteger(generation) || generation < 1) throw new Error('METRICS_ENROLLMENT_INPUT_INVALID');
  const credentials = purposes.map(purpose => ({ purpose, audience: ['native_scrape', 'collector_catalog'].includes(purpose) ? 'bff' : 'collector', token: random() }));
  if (credentials.some(row => !/^[A-Za-z0-9_-]{43}$/.test(row.token)) || new Set(credentials.map(row => row.token)).size !== 4) throw new Error('METRICS_ENROLLMENT_RANDOM_INVALID');
  const find = purpose => credentials.find(row => row.purpose === purpose).token;
  return {
    enrollment: { clusterId, generation, credentials },
    collector: { clusterId, generation, catalogToken: find('collector_catalog'), ingestFingerprint: digest(find('collector_ingest')), scrapeFingerprint: digest(find('collector_scrape')) },
    prometheus: { native: find('native_scrape'), collector: find('collector_scrape') },
    fingerprints: Object.fromEntries(credentials.map(row => [row.purpose, digest(row.token)])),
  };
}
export function prometheusConfiguration(clusters) {
  if (!Array.isArray(clusters) || !clusters.length || clusters.length > 32 || clusters.some(row => !isUuid(row.clusterId) || !/^[a-f0-9]{64}$/.test(row.nodeId || ''))) throw new Error('METRICS_ENROLLMENT_INPUT_INVALID');
  const jobs = clusters.flatMap(({ clusterId, nodeId }) => [
    `  - job_name: 'kong-native-${clusterId}'\n    metrics_path: '/scrape/${clusterId}'\n    bearer_token_file: '/etc/prometheus/${clusterId}-native_scrape.token'\n    static_configs:\n      - targets: ['metrics-bff:9092']\n        labels:\n          cluster_id: '${clusterId}'\n          node_id: '${nodeId}'\n          job_kind: 'kongos-native'\n          source: 'native'`,
    `  - job_name: 'kong-collector-${clusterId}'\n    metrics_path: '/metrics/${clusterId}'\n    bearer_token_file: '/etc/prometheus/${clusterId}-collector_scrape.token'\n    static_configs:\n      - targets: ['telemetry-collector:9093']\n        labels:\n          cluster_id: '${clusterId}'\n          node_id: '${nodeId}'\n          job_kind: 'kongos-collector'\n          source: 'http_log_approximate'`,
  ]);
  return `global:\n  scrape_interval: 15s\n  scrape_timeout: 12s\n  evaluation_interval: 15s\nscrape_configs:\n${jobs.join('\n')}\n`;
}
export function materialFromEnrollment(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['clusterId', 'generation', 'credentials'].includes(key)) || !Array.isArray(input.credentials) || input.credentials.length !== 4) throw new Error('METRICS_ENROLLMENT_INPUT_INVALID');
  const tokens = purposes.map(purpose => {
    const rows = input.credentials.filter(row => row?.purpose === purpose);
    const audience = ['native_scrape', 'collector_catalog'].includes(purpose) ? 'bff' : 'collector';
    if (rows.length !== 1 || rows[0].audience !== audience || Object.keys(rows[0]).some(key => !['purpose', 'audience', 'token'].includes(key))) throw new Error('METRICS_ENROLLMENT_INPUT_INVALID');
    return rows[0].token;
  });
  return createMetricsMaterial(input.clusterId, input.generation, () => tokens.shift());
}
