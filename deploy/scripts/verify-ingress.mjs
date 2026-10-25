import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Bounded public-health reads verify nginx's ingress limit without touching
// Kong entities, sessions, credentials, or downstream monitoring providers.
const stage = process.argv[2];
if (!/^M(?:[0-9]|1[01])$/.test(stage || '')) {
  console.error('Usage: node deploy/scripts/verify-ingress.mjs M0..M11');
  process.exit(2);
}
const base = (process.env.CONSOLE_BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
const target = new URL('/api/v1/health/live', base);
if (!['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname)) {
  throw new Error('Ingress probe is restricted to the local validation console');
}
const checks = [], traces = [];
function check(name, passed) { checks.push({ name, passed: Boolean(passed) }); }
async function request() {
  const response = await fetch(target, { signal: AbortSignal.timeout(5000) });
  const safeHeaders = ['x-content-type-options', 'x-frame-options', 'content-security-policy']
    .every(name => Boolean(response.headers.get(name)));
  const trace = { method: 'GET', path: target.pathname, status: response.status, securityHeadersPresent: safeHeaders };
  // Never store the response body, even on an unexpected status.
  await response.arrayBuffer();
  traces.push(trace);
  return trace;
}
const startedAt = new Date().toISOString();
let counts = {}, result;
try {
  await new Promise(resolve => setTimeout(resolve, 2500));
  const baseline = await request();
  check('public health baseline responds', baseline.status === 200);
  const responses = await Promise.all(Array.from({ length: 100 }, request));
  counts = responses.reduce((sum, response) => ({ ...sum, [response.status]: (sum[response.status] || 0) + 1 }), {});
  check('bounded burst produces nginx 429', (counts[429] || 0) > 0);
  check('burst only receives successful or limited responses', responses.every(r => [200, 429].includes(r.status)));
  check('security headers also present on 429', responses.filter(r => r.status === 429).every(r => r.securityHeadersPresent));
  await new Promise(resolve => setTimeout(resolve, 2500));
  const recovered = await request();
  check('ingress limit recovers without restart', recovered.status === 200);
  result = { stage, kind: 'bounded-read-only-ingress-verification', startedAt, completedAt: new Date().toISOString(), requestCount: traces.length, ratePerSecond: 20, burst: 40, counts, allPassed: checks.every(c => c.passed), checks, traces, credentialsUsed: false, kongEntityReadsOrWrites: false };
} catch {
  result = { stage, kind: 'bounded-read-only-ingress-verification', startedAt, completedAt: new Date().toISOString(), allPassed: false, checks, traces, credentialsUsed: false, kongEntityReadsOrWrites: false, failureDetailsSuppressed: true };
}
const directory = resolve('artifacts', stage);
mkdirSync(directory, { recursive: true });
writeFileSync(resolve(directory, 'ingress-verification.json'), JSON.stringify(result, null, 2) + '\n');
if (!result.allPassed) process.exitCode = 1;
console.log(`${stage} nginx ingress verification ${result.allPassed ? 'passed' : 'failed'}; ${counts[429] || 0} bounded health reads limited, no credentials used.`);
