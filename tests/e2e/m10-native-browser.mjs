import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { chromium, expect } from '@playwright/test';
import { M10_ORIGINAL_BROWSER, M10_FRESH_BROWSER, M10_READONLY_BROWSER, validateFreshBrowserIntent, validateReadOnlyBrowserRecheckIntent, retainedBrowserResponseCookies } from '../security/lib/m10-fresh-browser-intent.mjs';

// Root supplies the reviewed actual native handoff. This runner reads existing
// reports/configuration and exercises forms; it never applies gateway changes.
if (process.env.RELEASE_LAB_READY !== 'true') throw Error('EXPLICIT_RELEASE_LAB_REQUIRED');
const privateDirectory = '/dev/shm/kongpilot-release-lab', privatePath = `${privateDirectory}/m10-harness.json`, stat = lstatSync(privatePath);
assert(stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600, 'PRIVATE_NATIVE_HANDOFF_REQUIRED');
const state = JSON.parse(readFileSync(privatePath, 'utf8')), handoff = state.browserHandoff, uuid = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i;
assert(state.milestone === 'M10' && handoff?.nativeVerified === true && Number.isFinite(Date.parse(handoff.verifiedAt)), 'VERIFIED_M10_NATIVE_HANDOFF_REQUIRED');
for (const name of ['clusterId', 'workspaceId', 'reportId', 'comparisonId']) assert(uuid.test(handoff[name] ?? ''), 'EXACT_M10_SCOPE_HANDOFF_REQUIRED');
assert(typeof handoff.ruleName === 'string' && typeof handoff.scheduleName === 'string', 'REAL_METADATA_FIXTURES_REQUIRED');
const admin = state.sessions.admin; assert(uuid.test(admin?.user?.id ?? '') && admin.username && admin.password, 'ORIGINAL_M10_ACTOR_REQUIRED');
const hash = value => createHash('sha256').update(value).digest('hex');
const readPrivate = path => { const s = lstatSync(path); assert(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o777) === 0o600 && s.size <= 32 * 1024 * 1024, 'PRIVATE_BROWSER_PROOF_REQUIRED'); return readFileSync(path); };
const freshRequested = process.argv.includes('--fresh-visible-select-cycle');
const readonlyRequested = process.argv.includes('--readonly-recheck');
const readonlyAttempt2 = process.argv.includes('--attempt=2');
assert(!freshRequested || !readonlyRequested, 'ONE_EXPLICIT_BROWSER_CYCLE_REQUIRED');
assert(!readonlyAttempt2 || readonlyRequested, 'READONLY_ATTEMPT2_ONLY');
assert(process.argv.slice(2).every(argument => ['--fresh-visible-select-cycle', '--readonly-recheck', '--attempt=2'].includes(argument)), 'FIXED_BROWSER_CYCLE_ARGUMENT_REQUIRED');
let cycle = { ...M10_ORIGINAL_BROWSER, prefix: 'm10-browser-original', retainedRequests: [] }, originalGuard;
if (freshRequested || readonlyRequested) {
  assert.equal(process.env[readonlyRequested ? 'RELEASE_LAB_M10_BROWSER_READONLY_READY' : 'RELEASE_LAB_M10_BROWSER_FRESH_READY'], 'true', 'EXPLICIT_ROOT_FRESH_BROWSER_HANDOFF_REQUIRED');
  const intentPath = `${privateDirectory}/m10-browser-fresh-intent.json`, intentBytes = readPrivate(intentPath), intent = JSON.parse(intentBytes);
  const oldJournalPath = `${privateDirectory}/${M10_ORIGINAL_BROWSER.journalName}`, oldMaterialPath = `${privateDirectory}/${M10_ORIGINAL_BROWSER.materialName}`;
  const originalJournalBytes = readPrivate(oldJournalPath), originalReportBytes = readFileSync(M10_ORIGINAL_BROWSER.reportPath), originalMaterialBytes = existsSync(oldMaterialPath) ? readPrivate(oldMaterialPath) : null;
  cycle = validateFreshBrowserIntent({ intent, originalJournalBytes, originalReportBytes, originalMaterialBytes, actorId: admin.user.id, username: admin.username, handoff });
  originalGuard = () => {
    assert.equal(hash(readPrivate(intentPath)), hash(intentBytes), 'ROOT_BROWSER_INTENT_BYTES_CHANGED');
    assert.equal(hash(readPrivate(oldJournalPath)), intent.originalJournalSha256, 'ORIGINAL_BROWSER_JOURNAL_BYTES_CHANGED');
    assert.equal(hash(readFileSync(M10_ORIGINAL_BROWSER.reportPath)), intent.originalReportSha256, 'ORIGINAL_BROWSER_REPORT_BYTES_CHANGED');
    assert.equal(existsSync(oldMaterialPath), intent.originalMaterialPresent, 'ORIGINAL_BROWSER_MATERIAL_PRESENCE_CHANGED');
    if (intent.originalMaterialPresent) assert.equal(hash(readPrivate(oldMaterialPath)), intent.originalMaterialSha256, 'ORIGINAL_BROWSER_MATERIAL_BYTES_CHANGED');
  };
  originalGuard();
  if (readonlyRequested) {
    const readonlyIntentPath = `${privateDirectory}/m10-browser-readonly-recheck-intent.json`, readonlyIntentBytes = readPrivate(readonlyIntentPath), readonlyIntent = JSON.parse(readonlyIntentBytes);
    const previousJournalPath = `${privateDirectory}/${M10_FRESH_BROWSER.journalName}`, previousMaterialPath = `${privateDirectory}/${M10_FRESH_BROWSER.materialName}`;
    const previousJournalBytes = readPrivate(previousJournalPath), previousMaterialBytes = readPrivate(previousMaterialPath), previousReportBytes = readFileSync(M10_FRESH_BROWSER.reportPath);
    let continuationRefreshBytes = null, rawContinuationRefreshBytes = null, rootRefreshPacket = null, continuationMetadata;
    if (readonlyAttempt2) {
      continuationMetadata = state.browserContinuationRefresh; assert.equal(continuationMetadata?.sameActualSid, true); assert.equal(continuationMetadata.browserEvidenceName, 'm10-browser-continuation-refresh-browser.json');
      continuationRefreshBytes = readPrivate(`${privateDirectory}/m10-browser-continuation-refresh-browser.json`); rawContinuationRefreshBytes = readPrivate(`${privateDirectory}/m10-browser-continuation-refresh.json`);
      assert.equal(hash(continuationRefreshBytes), continuationMetadata.browserEvidenceSha256); assert.equal(hash(rawContinuationRefreshBytes), continuationMetadata.evidenceSha256);
      const receipts = state.requests.filter(packet => packet.key === continuationMetadata.key && packet.requestId === continuationMetadata.requestId); assert.equal(receipts.length, 1); rootRefreshPacket = receipts[0];
    }
    cycle = validateReadOnlyBrowserRecheckIntent({ intent: readonlyIntent, previousJournalBytes, previousMaterialBytes, previousReportBytes, freshIntentBytes: intentBytes, originalJournalBytes, originalReportBytes, originalMaterialBytes, actorId: admin.user.id, username: admin.username, handoff, continuationRefreshBytes, rawContinuationRefreshBytes, rootRefreshPacket });
    const oldGuard = originalGuard;
    originalGuard = () => { oldGuard(); assert.equal(hash(readPrivate(readonlyIntentPath)), hash(readonlyIntentBytes), 'ROOT_READONLY_INTENT_BYTES_CHANGED'); assert.equal(hash(readPrivate(previousJournalPath)), readonlyIntent.previousJournalSha256); assert.equal(hash(readPrivate(previousMaterialPath)), readonlyIntent.previousMaterialSha256); assert.equal(hash(readFileSync(M10_FRESH_BROWSER.reportPath)), readonlyIntent.previousReportSha256); };
    originalGuard();
    if (continuationRefreshBytes) {
      const priorGuard = originalGuard; originalGuard = () => { priorGuard(); assert.equal(hash(readPrivate(`${privateDirectory}/m10-browser-continuation-refresh-browser.json`)), continuationMetadata.browserEvidenceSha256); assert.equal(hash(readPrivate(`${privateDirectory}/m10-browser-continuation-refresh.json`)), continuationMetadata.evidenceSha256); const nowState = JSON.parse(readPrivate(privatePath)), matching = nowState.requests.filter(packet => packet.key === continuationMetadata.key && packet.requestId === continuationMetadata.requestId); assert.equal(matching.length, 1); assert.deepEqual(matching[0], rootRefreshPacket); }; originalGuard();
    }
    if (readonlyAttempt2) {
      const paths = { journalName: M10_READONLY_BROWSER.journalName, materialName: M10_READONLY_BROWSER.materialName, reportPath: M10_READONLY_BROWSER.reportPath };
      const bytes = { journal: readPrivate(`${privateDirectory}/${paths.journalName}`), material: readPrivate(`${privateDirectory}/${paths.materialName}`), report: readFileSync(paths.reportPath) };
      const previousReadonly = JSON.parse(bytes.journal), previousReadonlyMaterial = JSON.parse(bytes.material), previousReadonlyReport = JSON.parse(bytes.report);
      assert.equal(previousReadonly.passed, false); assert.equal(previousReadonly.actorId, admin.user.id); assert.equal(previousReadonly.sourceCycle, cycle.prefix); assert.equal(previousReadonly.failure?.errorType, 'TimeoutError');
      assert(previousReadonly.privateFailure?.message?.includes('切换深色模式') && previousReadonly.privateFailure.message.includes('intercepts pointer events'), 'EXACT_THEME_BUTTON_DRAWER_INTERCEPTION_REQUIRED');
      assert.deepEqual(previousReadonly.requests, cycle.retainedRequests); assert.deepEqual(previousReadonlyMaterial.issuedPackets, cycle.retainedRequests); assert.deepEqual(previousReadonlyMaterial.readOnlyRecheckEvidence, cycle.readOnlyRecheckEvidence);
      assert.equal(previousReadonlyReport.passed, false); assert.equal(previousReadonlyReport.observedWrites, 2); assert.equal(previousReadonlyReport.currentCycleObservedWrites, 0); assert.equal(previousReadonlyReport.unknownWrites, 0); assert.equal(previousReadonlyReport.checks?.length, 8); assert.equal(previousReadonlyReport.screenshots?.length, 5); assert.equal(previousReadonlyReport.nativeWritesPerformed, false); assert.deepEqual(previousReadonlyReport.failure?.failedRequests, []);
      const evidence = { ...paths, journalSha256: hash(bytes.journal), materialSha256: hash(bytes.material), reportSha256: hash(bytes.report), verificationAttempt: 1, originalPassed: false, observedWrites: 2, currentCycleObservedWrites: 0, unknownWrites: 0, originalFailurePreserved: true, originalResponseRewritten: false, originalRequestsReplayed: false };
      Object.assign(cycle, { journalName: 'm10-browser-readonly-recheck-attempt2-journal.json', materialName: 'm10-browser-readonly-recheck-attempt2-secret-material.json', directory: 'artifacts/M10/browser-readonly-recheck-attempt2', readOnlyPreviousAttemptEvidence: evidence, previousReadonly, previousReadonlyMaterial });
      const previousGuard = originalGuard; originalGuard = () => { previousGuard(); assert.equal(hash(readPrivate(`${privateDirectory}/${paths.journalName}`)), evidence.journalSha256); assert.equal(hash(readPrivate(`${privateDirectory}/${paths.materialName}`)), evidence.materialSha256); assert.equal(hash(readFileSync(paths.reportPath)), evidence.reportSha256); }; originalGuard();
    }
  }
}
const journalPath = `${privateDirectory}/${cycle.journalName}`, materialPath = `${privateDirectory}/${cycle.materialName}`;
assert(!existsSync(journalPath) && !existsSync(materialPath), 'ORIGINAL_BROWSER_LEDGER_PRESENT_NO_REPLAY');
const directory = cycle.directory; assert(!existsSync(directory), 'ORIGINAL_BROWSER_ARTIFACTS_PRESENT_NO_OVERWRITE'); mkdirSync(directory, { recursive: true });
const journal = { version: 1, milestone: 'M10', actorId: admin.user.id, source: 'actual-browser', sourceCycle: cycle.prefix, startedAt: new Date().toISOString(),
  ...(readonlyRequested ? { verificationAttempt: readonlyAttempt2 ? 2 : 1 } : {}), ...(cycle.retainedOriginalEvidence ? { retainedOriginalEvidence: cycle.retainedOriginalEvidence } : {}), ...(cycle.readOnlyRecheckEvidence ? { readOnlyRecheckEvidence: cycle.readOnlyRecheckEvidence } : {}), ...(cycle.readOnlyPreviousAttemptEvidence ? { readOnlyPreviousAttemptEvidence: cycle.readOnlyPreviousAttemptEvidence } : {}), ...(cycle.freshCookieEvidence ? { freshCookieEvidence: cycle.freshCookieEvidence } : {}), requests: cycle.retainedRequests }, checks = [], screenshots = [], errors = [], failedRequests = [], requests = [], tasks = [], packets = new WeakMap();
let currentCookies = cycle.seedCookies ?? [], readonlyWriteDenied = false;
const save = initial => {
  originalGuard?.();
  const options = { mode: 0o600, ...(initial ? { flag: 'wx' } : {}) };
  writeFileSync(journalPath, JSON.stringify(journal, null, 2) + '\n', options); chmodSync(journalPath, 0o600);
  writeFileSync(materialPath, JSON.stringify({ version: 1, milestone: 'M10', sourceCycle: cycle.prefix, cookies: currentCookies, responseCookies: retainedBrowserResponseCookies(journal.requests), issuedPackets: journal.requests,
    ...(cycle.retainedOriginalEvidence ? { retainedOriginalEvidence: cycle.retainedOriginalEvidence, retainedOriginalJournal: cycle.original, retainedOriginalMaterial: cycle.originalMaterial } : {}),
    ...(cycle.readOnlyRecheckEvidence ? { readOnlyRecheckEvidence: cycle.readOnlyRecheckEvidence, retainedPreviousJournal: cycle.previous, retainedPreviousMaterial: cycle.previousMaterial } : {}), ...(cycle.readOnlyPreviousAttemptEvidence ? { readOnlyPreviousAttemptEvidence: cycle.readOnlyPreviousAttemptEvidence, retainedPreviousReadOnlyJournal: cycle.previousReadonly, retainedPreviousReadOnlyMaterial: cycle.previousReadonlyMaterial } : {}), ...(cycle.freshCookieEvidence ? { freshCookieEvidence: cycle.freshCookieEvidence, continuationRefreshEvidence: cycle.continuationRefreshEvidence, rawContinuationRefreshEvidence: cycle.rawContinuationRefreshEvidence } : {}) }, null, 2) + '\n', options); chmodSync(materialPath, 0o600);
};
save(true);
const browser = await chromium.launch({ headless: true, ...(existsSync('/usr/bin/chromium') ? { executablePath: '/usr/bin/chromium' } : {}) });
let page, context, passed = false, failure;
try {
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, baseURL: 'http://127.0.0.1:5455' });
  if (readonlyRequested) {
    await context.addCookies(cycle.seedCookies);
    const response = await context.request.get('/api/v1/auth/me'), bytes = await response.body(); assert.equal(response.status(), 200, 'EXISTING_BROWSER_SESSION_MUST_BE_VERIFIED_NO_LOGIN');
    const actual = JSON.parse(bytes); assert.equal(actual.data?.user?.id, admin.user.id); assert.equal(actual.data?.csrfToken, cycle.seedCookies.find(cookie => cookie.name === 'kongos_csrf').value); assert(actual.meta?.requestId);
    journal.readOnlySessionVerification = { method: 'GET', path: '/api/v1/auth/me', status: response.status(), actorId: actual.data.user.id, sessionId: cycle.seedSessionId, requestId: actual.meta.requestId, responseHash: hash(bytes), verifiedAt: new Date().toISOString() }; save();
  } else {
  const body = { username: admin.username, password: admin.password }, loginPacket = { method: 'POST', path: '/api/v1/auth/login', body, bodyHash: hash(JSON.stringify(body)), actorId: admin.user.id, sourceCycle: cycle.prefix, state: 'prepared', startedAt: new Date().toISOString() };
  journal.requests.push(loginPacket); save();
  const login = await context.request.post('/api/v1/auth/login', { data: body }), loginBytes = await login.body(), loginData = JSON.parse(loginBytes);
  Object.assign(loginPacket, { state: 'response_observed', status: login.status(), responseHash: hash(loginBytes), responseData: loginData.data, responseHeaders: await login.headersArray() }); save();
  assert.equal(login.status(), 201, 'Real authenticated browser session required'); assert.equal(loginData.data.user.id, admin.user.id);
  }
  await context.addInitScript(({ cid, wid }) => { sessionStorage.setItem('kongos.clusterId', cid); sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid); }, { cid: handoff.clusterId, wid: handoff.workspaceId });
  await context.route('**/api/v1/**', async (route, request) => {
    if (!['GET', 'HEAD'].includes(request.method())) {
      if (readonlyRequested) { readonlyWriteDenied = true; journal.rejectedRequests ??= []; journal.rejectedRequests.push({ method: request.method(), path: new URL(request.url()).pathname, blockedBeforeSend: true }); save(); await route.abort('blockedbyclient'); return; }
      const url = new URL(request.url()), wireBody = request.postData() ?? '', headers = await request.allHeaders(), packet = { method: request.method(), path: url.pathname, query: url.search, headers, body: wireBody ? JSON.parse(wireBody) : null, bodyHash: hash(wireBody || 'null'), key: headers['x-idempotency-key'] ?? null, actorId: admin.user.id, sourceCycle: cycle.prefix, state: 'prepared', startedAt: new Date().toISOString() };
      journal.requests.push(packet); save();
      if (request.method() !== 'POST' || !['/api/v1/auth/login', '/api/v1/auth/refresh'].includes(url.pathname)) { packet.state = 'blocked_before_send'; save(); await route.abort('blockedbyclient'); return; }
      packets.set(request, packet);
    }
    await route.continue();
  });
  context.on('response', response => { const packet = packets.get(response.request()); if (!packet) return; tasks.push((async () => { try { const bytes = await response.body(), data = JSON.parse(bytes); Object.assign(packet, { state: 'response_observed', status: response.status(), responseHash: hash(bytes), responseData: data.data ?? null, responseHeaders: await response.headersArray(), requestId: data.meta?.requestId ?? null, errorCode: data.error?.code ?? null }); } catch { packet.state = 'response_unknown'; } finally { save(); } })()); });
  page = await context.newPage(); page.on('pageerror', error => errors.push(error.name)); page.on('request', request => requests.push(request.url())); page.on('response', response => { if (response.status() >= 400) failedRequests.push({ path: new URL(response.url()).pathname, status: response.status() }); });
  const check = (name, condition = true) => { assert(condition, name); checks.push({ name, passed: true }); };
  const scopedResponse = suffix => page.waitForResponse(response => { const url = new URL(response.url()); return response.request().method() === 'GET' && url.pathname === `/api/v1/clusters/${handoff.clusterId}/governance/${suffix}` && url.searchParams.get('workspaceId') === handoff.workspaceId; });
  async function responseData(promise) { const response = await promise; assert.equal(response.status(), 200, 'ACTUAL_SCOPED_BROWSER_READ_REQUIRED'); const value = await response.json(); assert(value.data && value.meta?.requestId); return value.data; }
  async function settle() {
    const drawer = page.locator('.ant-drawer-body:visible').last(), region = await drawer.count() ? drawer : page.locator('.ant-tabs-tabpane-active').last();
    await expect(region.locator('.ant-spin-spinning:visible')).toHaveCount(0, { timeout: 30000 });
    await page.evaluate(async () => { await Promise.all(document.getAnimations().filter(animation => animation.playState === 'running' && Number.isFinite(animation.effect?.getComputedTiming().endTime)).map(animation => animation.finished.catch(() => {}))); await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
  }
  async function selectVisible(label, option) {
    const selector = page.getByRole('combobox', { name: label, exact: true }).locator('xpath=ancestor::*[contains(concat(" ", normalize-space(@class), " "), " ant-select-selector ")][1]');
    await expect(selector).toBeVisible(); await selector.click();
    const dropdown = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)').last(); await expect(dropdown).toBeVisible(); await dropdown.getByText(option, { exact: true }).last().click();
  }
  async function screenshot(name) {
    await settle();
    const layout = await page.evaluate(() => ({ viewport: innerWidth, width: document.querySelector('.console-sidebar')?.getBoundingClientRect().width })); if (layout.viewport >= 992) assert(layout.width >= 240, 'Desktop sidebar must remain available after drawers close');
    const values = [admin.password, ...(await context.cookies()).map(cookie => cookie.value), ...(handoff.secretValues ?? [])].filter(value => typeof value === 'string' && value.length >= 8), visible = await page.evaluate(() => [document.body.innerText, ...Array.from(document.querySelectorAll('input,textarea')).map(input => input.value)].join('\n'));
    assert(values.every(value => !visible.includes(value)), 'Browser DOM must not contain actual credentials'); const path = `${directory}/${name}.png`; await page.screenshot({ path, fullPage: true, animations: 'disabled' }); chmodSync(path, 0o644); screenshots.push(path);
  }
  const reportResponse = scopedResponse(`reports/${handoff.reportId}`), findingsResponse = scopedResponse(`reports/${handoff.reportId}/findings`);
  await page.goto(`/governance?tab=reports&reportId=${handoff.reportId}`); await page.getByRole('heading', { name: '配置治理', exact: true }).waitFor(); await page.getByText('巡检报告', { exact: true }).last().waitFor(); await page.getByText('发现问题', { exact: true }).waitFor();
  const reportData = await responseData(reportResponse), findingData = await responseData(findingsResponse);
  assert.equal(reportData.entity?.id, handoff.reportId); assert.equal(reportData.entity?.clusterId, handoff.clusterId); assert.equal(reportData.entity?.workspaceId, handoff.workspaceId); assert.equal(reportData.entity?.quality, 'complete'); assert(Array.isArray(findingData.items) && findingData.items.length > 0);
  await expect(page.locator('.ant-drawer-body:visible .ant-table-tbody > tr.ant-table-row')).toHaveCount(findingData.items.length, { timeout: 30000 }); await settle();
  check('actual report and findings render in the exact source workspace'); await screenshot('inspection-report');
  await page.keyboard.press('Escape'); await page.getByRole('tab', { name: 'Lint 规则', exact: true }).click(); await page.getByRole('button', { name: handoff.ruleName, exact: true }).click(); await page.getByText(/当前版本 v\d+ · 修订 \d+/).waitFor(); check('actual immutable rule version and DSL are visible'); await screenshot('lint-rule-version');
  await page.keyboard.press('Escape'); await page.getByRole('tab', { name: '调度', exact: true }).click(); await page.getByRole('button', { name: handoff.scheduleName, exact: true }).click(); await page.getByText('调度只执行检查，不自动修复或发布配置。', { exact: true }).waitFor(); check('actual schedule configuration remains readonly toward the gateway'); await screenshot('schedule');
  await page.keyboard.press('Escape'); const driftResponse = scopedResponse(`comparisons/${handoff.comparisonId}`);
  await page.goto(`/governance?tab=drift&comparisonId=${handoff.comparisonId}`); await page.getByText('环境配置差异', { exact: true }).waitFor();
  const driftData = await responseData(driftResponse); assert.equal(driftData.entity?.id, handoff.comparisonId); assert.equal(driftData.entity?.clusterId, handoff.clusterId); assert.equal(driftData.entity?.workspaceId, handoff.workspaceId); assert.equal(driftData.entity?.quality, 'complete');
  assert.equal(driftData.entity.counts.modified, 2, 'ACTUAL_HISTORICAL_COMPARISON_TWO_CHANGES_REQUIRED'); assert.equal(driftData.items.filter(item => item.action === 'changed').length, 2);
  await expect(page.locator('.ant-drawer-body:visible .ant-table-tbody > tr.ant-table-row')).toHaveCount(driftData.items.length, { timeout: 30000 }); await expect(page.getByRole('cell', { name: '已变更', exact: true })).toHaveCount(2, { timeout: 30000 }); await settle();
  check('actual dual-environment logical diff is shown with both loaded changed rows'); await screenshot('environment-drift');
  await page.keyboard.press('Escape'); await page.goto(`/governance?tab=promote&comparisonId=${handoff.comparisonId}`); await page.getByText('环境发布预览', { exact: true }).waitFor();
  await selectVisible('发布对象范围', '全部源资源'); await selectVisible('发布资源类型', 'consumers');
  const sourceConsumerName = handoff.sourceConsumerName ?? state.fixtures?.source?.consumer?.username; assert(typeof sourceConsumerName === 'string', 'ACTUAL_UNCHANGED_CONSUMER_HANDOFF_REQUIRED');
  await page.getByRole('cell', { name: sourceConsumerName, exact: true }).waitFor(); check('unchanged Consumer is available from the actual authorized source-object cursor page');
  const consumerRow = page.getByRole('row').filter({ has: page.getByRole('cell', { name: sourceConsumerName, exact: true }) }); await consumerRow.locator('input[type=checkbox]').check(); await page.getByRole('button', { name: /^生成目标发布 Diff（1）$/ }).click();
  for (const label of ['显式发布环境字段', '显式发布凭证', '显式发布秘密配置']) assert.equal(await page.getByRole('checkbox', { name: label, exact: true }).isChecked(), false, `${label} must default off`);
  check('Promote defaults credentials, secrets and environment fields to excluded');
  await page.getByRole('checkbox', { name: '显式发布凭证', exact: true }).check(); await selectVisible('发布凭证类型', 'key-auth'); await expect(page.locator('.ant-drawer-body:visible .ant-select-selection-item').filter({ hasText: /^key-auth$/ })).toHaveCount(1); await page.keyboard.press('Escape'); check('credential opt-in exposes the fixed Kong 1.5 credential-type selector'); await page.getByRole('checkbox', { name: '显式发布凭证', exact: true }).uncheck();
  assert(await page.getByRole('button', { name: '生成目标 Diff', exact: true }).isVisible()); check('publishing still requires the exact typed confirmation'); await screenshot('promote-defaults');
  await page.goto('/governance?tab=promote'); await page.getByRole('heading', { name: '配置治理', exact: true }).waitFor(); await expect(page.locator('.ant-drawer-content-wrapper:visible')).toHaveCount(0, { timeout: 30000 });
  await page.getByRole('button', { name: '切换深色模式', exact: true }).click(); await page.waitForFunction(() => document.documentElement.dataset.appearance === 'dark'); await screenshot('governance-dark'); check('governance preserves the platform dark theme');
  await page.getByRole('button', { name: '切换浅色模式', exact: true }).click(); await page.setViewportSize({ width: 390, height: 844 }); await page.goto('/governance?tab=reports'); await page.getByRole('heading', { name: '配置治理', exact: true }).waitFor(); await screenshot('governance-mobile'); check('mobile governance avoids horizontal page overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  check('browser never connects directly to Kong Admin API', requests.every(value => !['8001', '8444'].includes(new URL(value).port))); check('actual browser pages produce no script errors', errors.length === 0);
  await Promise.all(tasks); check('all browser write responses remain observed under their original keys', journal.requests.every(packet => packet.state === 'response_observed' && packet.status < 500));
  check('browser performs no gateway apply or mutation writes', journal.requests.every(packet => packet.path === '/api/v1/auth/login' || packet.path === '/api/v1/auth/refresh'));
  if (readonlyRequested) { assert.equal(readonlyWriteDenied, false, 'READONLY_BROWSER_SESSION_EXPIRED_OR_WRITE_REQUESTED'); assert.deepEqual(journal.requests, cycle.previous.requests); check('readonly recheck verifies the same real session without issuing or replaying any authentication write'); }
  currentCookies = await context.cookies(); save(); passed = true;
} catch (error) { journal.privateFailure = { errorType: error.name, message: String(error.message), stack: String(error.stack ?? '') }; failure = { errorType: error.name, code: 'M10_BROWSER_VERIFICATION_FAILED', failedRequests }; process.exitCode = 1; }
finally { await Promise.allSettled(tasks); if (context) currentCookies = await context.cookies().catch(() => currentCookies); Object.assign(journal, { completedAt: new Date().toISOString(), passed, ...(failure ? { failure } : {}) }); save(); await browser.close(); writeFileSync(`${directory}/verification.json`, JSON.stringify({ passed, actualBackend: true, mocksUsed: false, credentialsRecorded: false, nativeWritesPerformed: false, traceRecorded: false, sourceCycle: cycle.prefix, ...(readonlyRequested ? { verificationAttempt: readonlyAttempt2 ? 2 : 1 } : {}), ...(cycle.retainedOriginalEvidence ? { retainedOriginalEvidence: cycle.retainedOriginalEvidence } : {}), ...(cycle.readOnlyRecheckEvidence ? { readOnlyRecheckEvidence: cycle.readOnlyRecheckEvidence } : {}), ...(cycle.readOnlyPreviousAttemptEvidence ? { readOnlyPreviousAttemptEvidence: cycle.readOnlyPreviousAttemptEvidence } : {}), ...(cycle.freshCookieEvidence ? { freshCookieEvidence: cycle.freshCookieEvidence } : {}), checks, screenshots, observedWrites: journal.requests.filter(packet => packet.state === 'response_observed').length, currentCycleObservedWrites: journal.requests.filter(packet => packet.sourceCycle === cycle.prefix && packet.state === 'response_observed').length, unknownWrites: journal.requests.filter(packet => packet.state !== 'response_observed').length, ...(failure ? { failure } : {}) }, null, 2) + '\n', { flag: 'wx' }); process.stdout.write(JSON.stringify({ passed, checks: checks.length, screenshots: screenshots.length, sourceCycle: cycle.prefix }) + '\n'); }
