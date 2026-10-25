import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { FRESH_BROWSER_PREFIX, m10BrowserHandoffSha256, validateFreshBrowserIntent, retainedBrowserResponseCookies } from './lib/m10-fresh-browser-intent.mjs';

const id = (n: number) => `${n.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`, sha = (value: any) => createHash('sha256').update(value).digest('hex');
function fixture() {
  const actorId = id(1), username = 'synthetic-browser-user', body = { username, password: 'synthetic-private-password' }, csrfToken = 'synthetic-issued-csrf-value';
  const handoff = { nativeVerified: true, verifiedAt: '2026-10-13T07:52:00.000Z', clusterId: id(2), workspaceId: id(3), reportId: id(4), comparisonId: id(5), ruleName: 'synthetic rule', scheduleName: 'synthetic schedule', sourceConsumerName: 'synthetic consumer' };
  const original: any = { version: 1, milestone: 'M10', source: 'actual-browser', actorId, passed: false, failure: { errorType: 'TimeoutError', code: 'M10_BROWSER_VERIFICATION_FAILED' }, privateFailure: { errorType: 'TimeoutError', message: 'locator.click 发布对象范围 ant-select-selection-item intercepts pointer events' }, requests: [{ method: 'POST', path: '/api/v1/auth/login', actorId, state: 'response_observed', status: 201, startedAt: '2026-10-13T07:53:00.000Z', body, bodyHash: sha(JSON.stringify(body)), responseHash: sha('actual synthetic response'), responseData: { user: { id: actorId }, csrfToken }, responseHeaders: ['kongos_access=synthetic-issued-access; Path=/api', 'kongos_refresh=synthetic-issued-refresh; Path=/api', `kongos_csrf=${csrfToken}; Path=/api`].map(value => ({ name: 'set-cookie', value })) }] };
  const report: any = { passed: false, actualBackend: true, mocksUsed: false, credentialsRecorded: false, nativeWritesPerformed: false, traceRecorded: false, observedWrites: 1, unknownWrites: 0, failure: { errorType: 'TimeoutError', code: 'M10_BROWSER_VERIFICATION_FAILED', failedRequests: [] }, checks: Array.from({ length: 4 }, (_, i) => ({ name: `synthetic-check-${i}`, passed: true })), screenshots: ['inspection-report', 'lint-rule-version', 'schedule', 'environment-drift'].map(name => `artifacts/M10/browser/${name}.png`) };
  const originalJournalBytes = Buffer.from(JSON.stringify(original)), originalReportBytes = Buffer.from(JSON.stringify(report));
  const intent: any = { version: 1, prefix: FRESH_BROWSER_PREFIX, cause: 'visible-ant-select-click-timeout', actorId, ...Object.fromEntries(['clusterId', 'workspaceId', 'reportId', 'comparisonId'].map(field => [field, (handoff as any)[field]])), handoffSha256: m10BrowserHandoffSha256(handoff), originalJournalSha256: sha(originalJournalBytes), originalReportSha256: sha(originalReportBytes), originalMaterialPresent: false, originalMaterialSha256: null, originalResponseRewritten: false, originalRequestsReplayed: false, freshAuthenticationOnly: true };
  return { intent, actorId, username, handoff, original, report, originalJournalBytes, originalReportBytes, originalMaterialBytes: null };
}
const reseal = (f: any) => { f.originalJournalBytes = Buffer.from(JSON.stringify(f.original)); f.originalReportBytes = Buffer.from(JSON.stringify(f.report)); f.intent.originalJournalSha256 = sha(f.originalJournalBytes); f.intent.originalReportSha256 = sha(f.originalReportBytes); };

describe('explicit fixed fresh browser cycle after observed auth-only selector timeout', () => {
  it('retains exact original packets without mutating the failure and never fabricates an absent material file', () => {
    const f = fixture(), before = JSON.stringify(f), result = validateFreshBrowserIntent(f);
    expect(result.journalName).toBe('m10-browser-after-visible-select-fix-journal.json'); expect(result.retainedOriginalEvidence.originalMaterialPresent).toBe(false);
    expect(result.retainedOriginalEvidence.materialName).toBeNull(); expect(result.originalMaterial).toBeNull(); expect(JSON.stringify(f)).toBe(before);
    const { sourceCycle, ...packet } = result.retainedRequests[0]; expect(sourceCycle).toBe('m10-browser-original'); expect(packet).toEqual(f.original.requests[0]);
    expect(retainedBrowserResponseCookies(result.retainedRequests)).toHaveLength(3);
  });
  it.each(['prefix', 'journal-bytes', 'report-bytes', 'actor', 'scope', 'handoff', 'unknown-write', 'non-auth-write', 'non-201', 'wrong-login-actor', 'wrong-username', 'not-select-timeout', 'missing-issued-cookie', 'missing-issued-csrf', 'invented-material', 'native-report', 'replay-flag'])('rejects before any new browser/login: %s', reason => {
    const f: any = fixture();
    if (reason === 'prefix') f.intent.prefix += '-retry';
    if (reason === 'journal-bytes') f.originalJournalBytes = Buffer.concat([f.originalJournalBytes, Buffer.from(' ')]);
    if (reason === 'report-bytes') f.originalReportBytes = Buffer.concat([f.originalReportBytes, Buffer.from(' ')]);
    if (reason === 'actor') f.intent.actorId = id(99);
    if (reason === 'scope') f.intent.workspaceId = id(99);
    if (reason === 'handoff') f.handoff.comparisonId = id(99);
    if (reason === 'unknown-write') f.original.requests[0].state = 'response_unknown';
    if (reason === 'non-auth-write') f.original.requests[0].path = `/api/v1/clusters/${id(2)}/configuration/plans/${id(6)}/apply`;
    if (reason === 'non-201') f.original.requests[0].status = 500;
    if (reason === 'wrong-login-actor') f.original.requests[0].responseData.user.id = id(99);
    if (reason === 'wrong-username') { f.original.requests[0].body.username = 'another-user'; f.original.requests[0].bodyHash = sha(JSON.stringify(f.original.requests[0].body)); }
    if (reason === 'not-select-timeout') f.original.privateFailure.message = 'unrelated network timeout';
    if (reason === 'missing-issued-cookie') f.original.requests[0].responseHeaders = [];
    if (reason === 'missing-issued-csrf') delete f.original.requests[0].responseData.csrfToken;
    if (reason === 'invented-material') f.intent.originalMaterialPresent = true;
    if (reason === 'native-report') f.report.nativeWritesPerformed = true;
    if (reason === 'replay-flag') f.intent.originalRequestsReplayed = true;
    if (!['journal-bytes', 'report-bytes'].includes(reason)) reseal(f);
    expect(() => validateFreshBrowserIntent(f)).toThrow();
  });
  it('retains a genuinely present original material under its exact byte digest', () => {
    const f: any = fixture(); f.originalMaterialBytes = Buffer.from(JSON.stringify({ version: 1, milestone: 'M10', cookies: [{ name: 'kongos_csrf', value: 'synthetic-original-csrf' }] })); f.intent.originalMaterialPresent = true; f.intent.originalMaterialSha256 = sha(f.originalMaterialBytes);
    const result = validateFreshBrowserIntent(f); expect(result.retainedOriginalEvidence.materialName).toBe('m10-browser-secret-material.json'); expect(result.originalMaterial.cookies).toHaveLength(1);
    f.originalMaterialBytes = Buffer.concat([f.originalMaterialBytes, Buffer.from(' ')]); expect(() => validateFreshBrowserIntent(f)).toThrow();
  });
  it('browser runner clicks the visible Ant selector and waits for actual data before evidence capture without forced clicks', () => {
    const source = readFileSync('tests/e2e/m10-native-browser.mjs', 'utf8');
    expect(source).toContain('ant-select-selector'); expect(source).toContain('await selector.click()'); expect(source).not.toContain('force: true');
    expect(source).toContain('ACTUAL_HISTORICAL_COMPARISON_TWO_CHANGES_REQUIRED'); expect(source).toContain("await responseData(findingsResponse)"); expect(source).toContain('await settle();');
    expect(source).toContain("--fresh-visible-select-cycle"); expect(source).toContain('ORIGINAL_BROWSER_ARTIFACTS_PRESENT_NO_OVERWRITE'); expect(source).toContain("packet.state = 'blocked_before_send'");
  });
});
