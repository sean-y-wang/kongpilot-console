import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

// Run only after an approved Nginx reload, while other live writers are paused.
// Synthetic sentinels and Docker log bodies remain exclusively in memory.
const checks = [];
const check = (name, condition) => checks.push({ name, passed: Boolean(condition) });
let failure;
try {
  const source = readFileSync('deploy/nginx/default.conf', 'utf8');
  const active = execFileSync('docker', ['compose', 'exec', '-T', 'console-web', 'nginx', '-T'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const format = source.match(/log_format\s+kongos_safe\s+'([^']+)';/)?.[1] ?? '';
  check('source access format includes only approved metadata variables', format === '$remote_addr $request_method $uri $status $body_bytes_sent $request_time');
  check('source format excludes query, complete request, headers, and body', format && !/\$(?:request\b|request_uri|args|query_string|http_|request_body)/.test(format));
  check('active server uses safe access format', active.includes('access_log /dev/stdout kongos_safe;'));
  check('active server discards native request-context errors', active.includes('error_log /dev/null;'));
  check('health access logging remains disabled', /location = \/healthz\s*\{\s*access_log off;/.test(active));
  const startedAt = new Date(Date.now() - 1000).toISOString();
  const code = randomBytes(32).toString('hex'), state = randomBytes(32).toString('hex');
  const referer = randomBytes(32).toString('hex'), userAgent = randomBytes(32).toString('hex');
  const path = '/api/v1/auth/oidc/kongos-log-check/callback';
  const statuses = await Promise.all(Array.from({ length: 65 }, async () => {
    const response = await fetch(`http://127.0.0.1:8080${path}?code=${code}&state=${state}`, {
      redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { Referer: `https://example.invalid/?code=${referer}`, 'User-Agent': userAgent },
    });
    await response.arrayBuffer();
    return response.status;
  }));
  // Access records are flushed at request completion; this wait is bounded.
  await new Promise(resolve => setTimeout(resolve, 150));
  const capture = spawnSync('docker', ['logs', '--since', startedAt, 'kongos-console-console-web-1'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 2e6,
  });
  if (capture.status !== 0) throw new Error('LOG_CAPTURE_FAILED');
  const logs = String(capture.stdout || '') + String(capture.stderr || '');
  check('actual callback request reached the safe access log', logs.includes(` GET ${path} `));
  // This deployment has no OIDC provider: its documented unconfigured state
  // is HTTP503 AUTH_PROVIDER_UNAVAILABLE, distinct from an internal error.
  check('callback rejection is handled without credential authentication', statuses.every(status => [400, 401, 403, 404, 429, 503].includes(status)));
  check('rate-limit error path was actually exercised', statuses.includes(429));
  check('synthetic OIDC code and state never entered Docker access logs', !logs.includes(code) && !logs.includes(state));
  check('synthetic Referer and User-Agent never entered Docker access logs', !logs.includes(referer) && !logs.includes(userAgent));
} catch {
  failure = 'NGINX_SAFE_LOG_VERIFICATION_EXCEPTION';
  check('Nginx safe-log verification completed', false);
}
const result = { checkedAt: new Date().toISOString(), validation: 'active-nginx-synthetic-callback-and-rate-limit',
  sentinelValuesRecorded: false, rawLogsRecorded: false, applicationRebuilt: false, nativeGatewayWritesPerformed: false,
  nativeErrorLogTradeoff: 'Request-context proxy error details are discarded; safe method/path/status/timing access records and redacted BFF diagnostics remain.',
  allPassed: checks.every(item => item.passed), checks, ...(failure ? { failure } : {}) };
mkdirSync('artifacts/M4', { recursive: true });
writeFileSync('artifacts/M4/nginx-safe-log-verification.json', JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ allPassed: result.allPassed, passed: checks.filter(item => item.passed).length, total: checks.length, failure }));
if (!result.allPassed) process.exitCode = 1;
