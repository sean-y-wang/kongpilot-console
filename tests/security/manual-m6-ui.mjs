import { chromium, expect } from '@playwright/test';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { privateReference, M6_REFERENCE } from './lib/m6-reference.mjs';
import { authorizeFreshBootstrap, authorizeRestoredManualSession, beforeManualMutation, collectManualUuidValues, completeManualMutation, createManualJournal, interruptManualMutation, manualAttemptForPacket, manualJournalSummary, stopManualJournal, writeManualReferenceAtomic } from './lib/m6-manual-journal.mjs';
import { manualReadPacketMatches, mergeManualWriteEvidence, validateManualReadEvidence } from './lib/m6-manual-read-evidence.mjs';
import { manualChromiumLaunchOptions, prepareManualCatalogFilterContinuation, prepareManualZeroPacketContinuation, preserveManualCatalogFilterContinuation, preserveManualZeroPacketContinuation } from './lib/m6-manual-zero-packet.mjs';
import { prepareManualDetailRemaining, preserveManualDetailRemaining } from './lib/m6-manual-detail-remaining.mjs';
import { manualSessionRecoveryContext, originalManualCookieJar, readOriginalManualSessionCookies } from './lib/m6-manual-session-recovery.mjs';

// Source-only preparation until Security returns the exclusive manual window.
if (process.env.M6_MANUAL_READY !== 'true') throw new Error('explicit M6 manual write-window handoff required');
if (existsSync('.env')) process.loadEnvFile('.env');
const http = JSON.parse(readFileSync('artifacts/M6/security-live.json', 'utf8'));
const browserEvidence = JSON.parse(readFileSync('artifacts/M6/browser-verification.json', 'utf8'));
if (http.failed !== 0 || browserEvidence.failed !== 0 || http.passed < 1 || browserEvidence.passed < 1) throw new Error('clean actual HTTP and browser evidence required');
const reference = privateReference(M6_REFERENCE, true), fixture = reference.fixtures?.[0], published = http.fixturesForBrowser;
if (!fixture || !published || fixture.cluster.id !== published.clusterId || fixture.workspace.id !== published.workspaceId || fixture.slug !== published.tenantSlug || reference.testTag !== http.testTag) throw new Error('current dynamic fixture identity mismatch');
const zeroPacketContinuationRequested = process.env.M6_MANUAL_ZERO_PACKET_CONTINUATION_READY === 'true';
const catalogFilterContinuationRequested = process.env.M6_MANUAL_CATALOG_FILTER_CONTINUATION_READY === 'true';
const detailRemainingRequested = process.env.M6_MANUAL_DETAIL_REMAINING_READY === 'true';
if ([zeroPacketContinuationRequested, catalogFilterContinuationRequested, detailRemainingRequested].filter(Boolean).length > 1) throw new Error('only one explicit manual continuation entry is allowed');
if (!catalogFilterContinuationRequested && !detailRemainingRequested) {
  if (!zeroPacketContinuationRequested && (reference.manualJournal || reference.manualMetadata?.length || reference.manualWriteAttempts?.length || reference.manualWriteEvidence?.length || Object.hasOwn(reference, 'manualZeroPacketContinuation') || Object.hasOwn(reference, 'manualZeroPacketHistory') || Object.hasOwn(reference, 'manualCatalogFilterContinuation') || Object.hasOwn(reference, 'manualCatalogFilterHistory') || Object.hasOwn(reference, 'manualDetailRemainingContinuation') || Object.hasOwn(reference, 'manualDetailRemainingHistory'))) throw new Error('prior manual attempts exist; inspect original receipts instead of replaying this script');
}
const owner = reference.portalUsers?.find(row => row.label === 'developer-a' && row.tenant?.clusterId === fixture.cluster.id && row.tenant?.workspaceId === fixture.workspace.id);
const approver = reference.accounts?.['approver-only'];
const administrator = reference.consoleAdministrator?.user;
if (!owner?.password || !approver?.password || administrator?.username !== (process.env.BOOTSTRAP_ADMIN_USERNAME ?? 'admin') || !process.env.BOOTSTRAP_ADMIN_PASSWORD || approver.role?.cluster_id !== fixture.cluster.id || approver.role?.workspace_id !== fixture.workspace.id || approver.binding?.cluster_id !== fixture.cluster.id || approver.binding?.workspace_id !== fixture.workspace.id) throw new Error('current tenant account references required');
const portalOrigin = 'http://127.0.0.1:8082', consoleOrigin = 'http://127.0.0.1:8080';
const title = `${http.testTag} Manual UI Page`, slug = `${http.testTag}-manual-ui-page`;
const originalMarkdown = '# 手工验收页面\n\n这里只包含公开测试文字。\n\n<script>window.m6RawHtmlExecuted=true</script>\n\n**审核通过后才可领取凭证。**';
const safeMarkdown = '# 手工验收页面\n\n这里只包含公开测试文字。\n\n比较示例：`x < 2`。\n\n**审核通过后才可领取凭证。**';
const retainedIds = collectManualUuidValues(reference);
let journal = createManualJournal({ clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id,
  actors: { owner: { id: owner.id, username: owner.username, password: owner.password }, administrator: { id: administrator.id, username: administrator.username, password: process.env.BOOTSTRAP_ADMIN_PASSWORD }, approver: { id: approver.user.id, username: approver.user.username, password: approver.password } },
  content: { title, slug, markdown: safeMarkdown }, priorKeys: retainedIds, forbiddenEntityIds: retainedIds });
if (zeroPacketContinuationRequested) journal.zeroPacketContinuation = prepareManualZeroPacketContinuation(reference, readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json'), { testTag: http.testTag, clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, actors: journal.actors, content: journal.content }, true);
if (catalogFilterContinuationRequested) journal.catalogFilterContinuation = prepareManualCatalogFilterContinuation(reference, readFileSync('artifacts/M6/UI-review-pre-catalog-filter-attempt.json'), readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json'), { testTag: http.testTag, clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, publicationId: published.publicationId, actors: journal.actors, originalContent: { ...journal.content, markdown: originalMarkdown }, plannedContent: journal.content }, true);
if (detailRemainingRequested) {
  const prepared = prepareManualDetailRemaining(reference, readFileSync('artifacts/M6/UI-review-third-attempt.json'), readFileSync('artifacts/M6/UI-review-pre-catalog-filter-attempt.json'), readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json'), { testTag: http.testTag, clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, publicationId: published.publicationId, actors: journal.actors, content: journal.content }, true);
  journal = structuredClone(reference.manualJournal); journal.phase = 'ready'; delete journal.stopReason; delete journal.stoppedAt; journal.detailRemainingContinuation = prepared;
}
const priorReport = journal.detailRemainingContinuation?.originalFailure;
const checks = priorReport ? structuredClone(priorReport.checks.filter(row => row.passed)) : [], screenshots = priorReport ? [...priorReport.screenshots] : [], writes = detailRemainingRequested ? structuredClone(reference.manualWriteEvidence) : [], responseTasks = [], contexts = [];
const pageErrors = [], adminRequests = [], missingScope = [], portalConsoleRequests = [];
const manualMetadata = [], manualAttempts = journal.attempts, newSecrets = new Set(Object.values(journal.actors).map(actor => actor.password));
const report = { stage: 'actual-manual', testTag: http.testTag, fixtureJournal: [], workspaces: [], checks, screenshots, readEvidence: priorReport ? structuredClone(priorReport.readEvidence) : [], ...(journal.zeroPacketContinuation ? { zeroPacketContinuation: { sourceFailureSha256: journal.zeroPacketContinuation.failureReportSha256, originalPrivateHistoryRetained: true, originalZeroPacketAttemptExcludedFromSuccess: true } } : {}), ...(journal.catalogFilterContinuation ? { catalogFilterContinuation: { sourceFailureSha256: journal.catalogFilterContinuation.failureReportSha256, originalPrivateHistoryRetained: true, previousKnownAnonymousRejectionExcludedFromSuccess: true } } : {}), ...(priorReport ? { detailRemainingContinuation: { sourceFailureSha256: journal.detailRemainingContinuation.failureReportSha256, originalPrivateHistoryRetained: true, originalFailedCheckRetainedInArchive: true, inheritedPassedChecks: priorReport.passed, inheritedScreenshots: priorReport.screenshots.length, inheritedReadEvidence: priorReport.readEvidence.length, inheritedSuccessfulLogins: 2, unusedPlannedIntents: 5 }, sessionReadEvidence: [] } : {}), allPassed: false };
let browser, currentCheck = 'preflight';
function check(name, condition) { currentCheck = name; checks.push({ name, passed: Boolean(condition) }); if (!condition) throw new Error('manual assertion failed'); }
function phase(name) { currentCheck = name; }
function retain() {
  const latest = privateReference(M6_REFERENCE, true);
  const preserved = journal.detailRemainingContinuation ? preserveManualDetailRemaining(latest, journal.detailRemainingContinuation, journal) : journal.catalogFilterContinuation ? preserveManualCatalogFilterContinuation(latest, journal.catalogFilterContinuation, journal) : journal.zeroPacketContinuation ? preserveManualZeroPacketContinuation(latest, journal.zeroPacketContinuation, journal) : latest;
  writeManualReferenceAtomic(M6_REFERENCE, { ...preserved, secrets: [...new Set([...(latest.secrets ?? []), ...newSecrets])], writeEvidence: mergeManualWriteEvidence(latest.writeEvidence, writes), manualJournal: journal, manualMetadata, manualWriteAttempts: manualAttempts, manualWriteEvidence: writes });
}
function persist() {
  report.performedAt = new Date().toISOString(); report.passed = checks.filter(row => row.passed).length; report.failed = checks.filter(row => !row.passed).length;
  writeFileSync('artifacts/M6/UI-review.json', JSON.stringify(report, null, 2) + '\n');
}
async function boundary(context, role, restored = false) {
  if (!restored) authorizeFreshBootstrap(journal, role, await context.cookies(), retain);
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.port === '8001') { try { stopManualJournal(journal, 'browser-admin-api-blocked', retain); } catch {} await route.abort('blockedbyclient'); return; }
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) { await route.continue(); return; }
    let attempt;
    try {
      const cookies = await context.cookies();
      for (const cookie of cookies) if (/^kongos_(portal_)?(access|refresh|csrf)$/.test(cookie.name) && cookie.value) newSecrets.add(cookie.value);
      attempt = beforeManualMutation(journal, role, { url: request.url(), method: request.method(), headers: await request.allHeaders(), rawBody: request.postData() }, cookies, retain);
      await route.continue();
    } catch {
      try { if (attempt) interruptManualMutation(journal, attempt, retain); else stopManualJournal(journal, 'blocked-before-packet', retain); } catch {}
      await route.abort('blockedbyclient').catch(() => undefined);
    }
  });
}
function observe(page, role) {
  const portal = role === 'owner';
  page.on('pageerror', error => pageErrors.push(error.name));
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.port === '8001') adminRequests.push(url.pathname);
    if (!url.pathname.startsWith('/api/v1/')) return;
    if (portal && !url.pathname.startsWith('/api/v1/portal/')) portalConsoleRequests.push(url.pathname);
    if ((portal && /^\/api\/v1\/portal\/(applications|requests|auth\/me|operations)(\/|$)/.test(url.pathname) && (!url.searchParams.get('clusterId') || !url.searchParams.get('workspaceId')))
      || (!portal && /^\/api\/v1\/clusters\/[^/]+\/(portal|workflows)(\/|$)/.test(url.pathname) && !url.searchParams.get('workspaceId'))) missingScope.push(url.pathname);
  });
  page.on('requestfailed', request => {
    const url = new URL(request.url());
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method()) || !url.pathname.startsWith('/api/v1/')) return;
    const attempt = manualAttemptForPacket(journal, role, { url: request.url(), method: request.method(), headers: request.headers(), rawBody: request.postData() });
    if (attempt) try { interruptManualMutation(journal, attempt, retain); } catch {}
  });
  page.on('response', response => {
    if (!new URL(response.url()).pathname.startsWith('/api/v1/')) return;
    responseTasks.push((async () => {
      for (const value of await response.headerValues('set-cookie')) {
        const pair = value.split(';')[0], at = pair.indexOf('=');
        if (/^kongos_(portal_)?(access|refresh|csrf)=/.test(pair) && pair.slice(at + 1)) newSecrets.add(pair.slice(at + 1));
      }
      const request = response.request(), url = new URL(response.url());
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
        const attempt = manualAttemptForPacket(journal, role, { url: request.url(), method: request.method(), headers: request.headers(), rawBody: request.postData() });
        if (!attempt) throw new Error('M6_MANUAL_UNJOURNALED_RESPONSE');
        let payload; try { payload = await response.json(); } catch {}
        if (response.ok()) {
          if (payload?.data?.csrfToken) newSecrets.add(payload.data.csrfToken);
          writes.push({ method: request.method(), path: url.pathname, requestId: payload?.meta?.requestId, status: response.status() });
        }
        completeManualMutation(journal, attempt, response.status(), payload, retain, await page.context().cookies());
      }
      retain();
    })().catch(() => { try { stopManualJournal(journal, 'response-observation-failed', retain); } catch {} }));
  });
}
async function ready() { await Promise.all(responseTasks); if (journal.phase === 'stopped-without-replay') throw new Error('M6_MANUAL_WINDOW_STOPPED'); }
async function password(page, value) {
  await page.getByLabel('密码', { exact: true }).evaluate((input, secret) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, secret);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }, value);
}
async function screenshot(page, name) {
  if (detailRemainingRequested) name = name.replace(/^manual-/, 'manual-remaining-');
  check(`${name}: secret panel closed`, await page.getByRole('dialog', { name: '临时查看 API Key' }).count() === 0);
  await page.evaluate(() => window.scrollTo(0, 0)); await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  await page.mouse.move(290, 100); await page.waitForTimeout(300);
  await page.screenshot({ path: `artifacts/M6/${name}.png`, fullPage: true, animations: 'disabled' }); screenshots.push(`${name}.png`); persist();
}
async function choose(page, label, text) {
  await page.getByLabel(label, { exact: true }).and(page.locator('input[role="combobox"]')).locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-select ")][1]').locator('.ant-select-selector').click();
  await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ hasText: text }).first().click();
}
async function consoleLogin(page, username, secret) {
  phase('console account login');
  await page.goto('/portal'); await page.getByLabel('账号', { exact: true }).fill(username); await password(page, secret);
  const loggedIn = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/login' && response.request().method() === 'POST');
  await ready();
  await page.getByRole('button', { name: '登录控制台', exact: true }).click();
  const response = await loggedIn; check('console login actual success', response.ok());
  const session = (await response.json()).data;
  await ready();
  check('console login current requested identity', session?.user?.username === username);
  await expect(page.locator('.user-button')).toContainText(session.user.displayName || username);
}
async function confirm(page, expected) {
  await ready();
  await page.getByLabel('确认名称', { exact: true }).fill(expected);
  const modal = page.locator('.ant-modal:visible'); await expect(modal.getByRole('button', { name: '确认执行', exact: true })).toBeEnabled();
  await modal.getByRole('button', { name: '确认执行', exact: true }).click();
}
function mutation(page, suffix, method) {
  return page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/clusters/${fixture.cluster.id}/portal/${suffix}` && response.request().method() === method);
}
async function result(response, name) {
  check(`${name}: actual 2xx`, response.ok()); const payload = await response.json();
  await ready();
  check(`${name}: requestId`, typeof payload.meta?.requestId === 'string'); return payload.data;
}
function manualRead(page, expected) {
  return page.waitForResponse(response => manualReadPacketMatches({ url: response.url(), method: response.request().method() }, expected));
}
async function readResult(response, expected, name) {
  const validated = validateManualReadEvidence({ url: response.url(), method: response.request().method() }, response.status(), await response.json(), expected);
  await ready(); report.readEvidence.push(validated.evidence); check(`${name}: actual safe DTO and original CID/WID`, true); return validated;
}
async function descriptionValue(drawer, label, value) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const cell = drawer.locator('th.ant-descriptions-item-label').filter({ hasText: new RegExp(`^${escaped}$`) });
  await expect(cell).toHaveCount(1);
  const content = cell.locator('xpath=..').locator('td.ant-descriptions-item-content');
  await expect(content).toHaveCount(1); await expect(content).toHaveText(String(value));
}
async function restoredSessionRead(response, role) {
  const url = new URL(response.url()), payload = await response.json(), portal = role === 'owner';
  const identity = portal ? payload?.data : payload?.data?.user, actor = journal.actors[role];
  check(`${role}: original session GET verifies current actor`, response.ok() && identity?.id === actor.id && identity.username === actor.username && typeof payload.meta?.requestId === 'string'
    && url.origin === (portal ? portalOrigin : consoleOrigin) && url.pathname === (portal ? '/api/v1/portal/auth/me' : '/api/v1/auth/me') && response.request().method() === 'GET'
    && (!portal || url.searchParams.get('clusterId') === fixture.cluster.id && url.searchParams.get('workspaceId') === fixture.workspace.id && identity.clusterId === fixture.cluster.id && identity.workspaceId === fixture.workspace.id && identity.status === 'active'));
  await ready(); report.sessionReadEvidence.push({ role, method: 'GET', path: url.pathname, requestId: payload.meta.requestId, actorVerified: true, clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id });
}

mkdirSync('artifacts/M6', { recursive: true }); persist();
try {
  retain();
  let recoveredCookies, sessionProof;
  if (detailRemainingRequested) {
    const expected = Object.fromEntries(['owner', 'administrator'].map(role => { const login = journal.attempts.find(attempt => attempt.category === 'planned' && attempt.role === role); return [role, { actorId: journal.actors[role].id, ...(role === 'owner' ? { clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id } : {}), loginRequestId: login.requestId, startedAt: login.startedAt, responseObservedAt: login.responseObservedAt }]; }));
    const recovery = manualSessionRecoveryContext({ candidates: [...new Set(reference.secrets)], expected });
    sessionProof = readOriginalManualSessionCookies(recovery);
    recoveredCookies = Object.fromEntries(['owner', 'administrator'].map(role => [role, originalManualCookieJar(recovery, sessionProof, role)]));
  }
  browser = await chromium.launch(manualChromiumLaunchOptions(process.env, existsSync));
  const portal = await browser.newContext({ baseURL: portalOrigin, viewport: { width: 1440, height: 960 } }); contexts.push(portal);
  if (detailRemainingRequested) { await portal.addCookies(recoveredCookies.owner); authorizeRestoredManualSession(journal, 'owner', sessionProof.owner, await portal.cookies(), retain); }
  await boundary(portal, 'owner', detailRemainingRequested);
  const page = await portal.newPage(); observe(page, 'owner'); page.setDefaultTimeout(15_000);
  const activePublication = fixture.publications.find(row => row.id === published.activePublicationId);
  const activeGrant = reference.grants?.find(row => row.grant?.id === published.activeGrantId && row.app?.id === published.applicationId);
  if (detailRemainingRequested) {
    phase('restored owner original session read');
    const currentOwner = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/portal/auth/me' && response.request().method() === 'GET' && response.ok());
    await page.goto(`/apis?tenant=${published.tenantSlug}`); await restoredSessionRead(await currentOwner, 'owner');
    check('remaining references preserve exact current active grant and publication', Boolean(activePublication && activeGrant?.workflowId));
  } else {
  phase('catalog published-category or all-category search');
  const catalogExpected = { kind: 'catalog', clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, publicationId: published.publicationId };
  const catalogLoading = manualRead(page, catalogExpected);
  await page.goto(`/apis?tenant=${published.tenantSlug}`); await expect(page.getByTestId('portal-catalog')).toBeVisible(); check('public catalog current tenant', true);
  const catalog = await readResult(await catalogLoading, catalogExpected, 'initial public catalog'), currentPublication = catalog.target;
  const categoryInput = page.getByLabel('筛选 API 分类', { exact: true });
  await expect(categoryInput).toHaveValue('');
  const category = currentPublication.category, filterExpected = { ...catalogExpected, ...(category ? { category } : { search: currentPublication.name }) };
  const filteredLoading = manualRead(page, filterExpected);
  if (category) { await categoryInput.fill(category); await categoryInput.press('Enter'); }
  else { const searchInput = page.getByLabel('搜索 API', { exact: true }); await searchInput.fill(currentPublication.name); await searchInput.press('Enter'); }
  await readResult(await filteredLoading, filterExpected, category ? 'actual published category filter' : 'unclassified fixture searches real API across all categories');
  const filteredPublication = page.locator(`.portal-api-grid h3 a[href="/apis/${published.publicationId}"]`);
  await expect(filteredPublication).toHaveText(currentPublication.name); await expect(categoryInput).toHaveValue(category || '');
  check('catalog filter renders current published API from actual bounded GET', true); await screenshot(page, 'manual-portal-catalog-filter');
  await page.locator(`.portal-api-grid h3 a[href="/apis/${published.publicationId}"]`).click(); await expect(page.getByTestId('portal-document')).toBeVisible(); check('real published OpenAPI document', true); await screenshot(page, 'manual-portal-document');
  await page.getByRole('button', { name: '开发者登录', exact: true }).click(); await page.getByRole('link', { name: '申请开发者账号', exact: true }).click();
  await expect(page.getByText('提交注册申请', { exact: true })).toBeVisible(); check('registration pending-review flow available', true);
  phase('portal active developer login');
  await page.getByRole('link', { name: '已有账号，返回登录', exact: true }).click(); await page.getByLabel('开发者账号', { exact: true }).fill(owner.username); await password(page, owner.password); await ready(); await page.getByRole('button', { name: '登录开发者门户', exact: true }).click();
  await expect(page.getByTestId('portal-create-application')).toBeVisible();
  await ready();
  await page.goto(`/applications/${published.applicationId}`); await expect(page.getByTestId('portal-credential-masked').first()).toBeVisible(); check('owned application credentials remain masked', true);
  await expect(page.getByText('停用 / 吊销后恢复访问需要重新申请', { exact: true })).toBeVisible(); check('revocation never promises old-key restore', true);
  check('active publication belongs to current fixture', Boolean(activePublication));
  phase('credential typed confirmation without submission');
  const credentialRow = page.locator(`tr.ant-table-row[data-row-key="${published.activeCredentialId}"]`);
  await expect(credentialRow).toHaveCount(1);
  const card = credentialRow.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-card ")][1]');
  await expect(card).toHaveCount(1); await expect(card.getByText(activePublication.name, { exact: true })).toBeVisible();
  await credentialRow.getByRole('button', { name: '停用 / 吊销', exact: true }).click();
  const revoke = page.getByRole('dialog', { name: '确认申请停用 / 吊销凭证' }); await revoke.getByLabel('确认名称', { exact: true }).fill('wrong-name'); await expect(revoke.getByRole('button', { name: '确认执行', exact: true })).toBeDisabled();
  await revoke.getByLabel('确认名称', { exact: true }).fill(`吊销 ${published.activeCredentialId}`); await expect(revoke.getByRole('button', { name: '确认执行', exact: true })).toBeEnabled(); check('typed credential revoke disabled on mismatch; no write sent', true);
  await revoke.getByRole('button', { name: /取\s*消/ }).click(); await page.reload(); await expect(page.getByTestId('portal-credential-masked').first()).toBeVisible(); check('authenticated portal reload unchanged actor', true); await screenshot(page, 'manual-portal-owned-application');
  phase('owned request list and completed detail');
  await page.goto('/requests'); await expect(page.getByRole('heading', { name: '我的申请', exact: true })).toBeVisible();
  check('request list uses cursor controls', await page.getByRole('button', { name: '下一页', exact: true }).count() === 1);
  check('completed request belongs to current active grant', Boolean(activeGrant?.workflowId));
  await page.goto(`/requests/${activeGrant.workflowId}`); await expect(page.getByTestId('portal-request-state')).toHaveText('已完成'); check('owned completed request real state', true);
  await page.goto('/profile'); await expect(page.getByRole('button', { name: '保存个人资料', exact: true })).toBeVisible();
  await expect(page.getByLabel('当前密码', { exact: true })).toHaveValue(''); await expect(page.getByLabel('新密码', { exact: true })).toHaveValue('');
  check('profile current actor fields available with empty password fields', true);
  await page.setViewportSize({ width: 390, height: 844 }); await page.goto(`/applications/${published.applicationId}`); await screenshot(page, 'manual-portal-mobile'); await page.setViewportSize({ width: 1440, height: 960 });
  }

  const admin = await browser.newContext({ baseURL: consoleOrigin, viewport: { width: 1440, height: 960 } }); contexts.push(admin);
  if (detailRemainingRequested) { await admin.addCookies(recoveredCookies.administrator); authorizeRestoredManualSession(journal, 'administrator', sessionProof.administrator, await admin.cookies(), retain); }
  await boundary(admin, 'administrator', detailRemainingRequested);
  await admin.addInitScript(({ cid, wid }) => { sessionStorage.setItem('kongos.clusterId', cid); sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid); }, { cid: fixture.cluster.id, wid: fixture.workspace.id });
  const consolePage = await admin.newPage(); observe(consolePage, 'administrator'); consolePage.setDefaultTimeout(15_000);
  if (detailRemainingRequested) {
    phase('restored administrator original session read');
    const currentAdministrator = consolePage.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/me' && response.request().method() === 'GET' && response.ok());
    await consolePage.goto('/portal'); await restoredSessionRead(await currentAdministrator, 'administrator');
  } else { await consoleLogin(consolePage, process.env.BOOTSTRAP_ADMIN_USERNAME ?? 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD); await consolePage.goto('/portal'); }
  if (!detailRemainingRequested) {
  await expect(consolePage.getByRole('tab', { name: 'API 发布', exact: true })).toBeVisible(); check('console current dynamic portal workspace', true); await screenshot(consolePage, 'manual-console-portal');
  phase('API configuration and document read only');
  const publicationRow = consolePage.locator(`.ant-table-row[data-row-key="${published.publicationId}"]`);
  await expect(publicationRow).toBeVisible(); await publicationRow.getByRole('button', { name: '配置 / 文档', exact: true }).click();
  const apiEditor = consolePage.locator('.ant-drawer:visible');
  await expect(apiEditor.getByLabel('API 编码（创建后不可更改）', { exact: true })).toBeDisabled();
  await expect(apiEditor.getByLabel('发布 Service', { exact: true }).and(apiEditor.locator('input[role="combobox"]'))).toBeDisabled();
  await expect.poll(() => apiEditor.getByLabel('文档 JSON / YAML', { exact: true }).inputValue()).not.toBe('');
  check('API edit preserves immutable slug and Service with real document', true); await apiEditor.locator('.ant-drawer-close').click();
  }
  phase('console current developer Configuration detail');
  await consolePage.getByRole('tab', { name: '开发者审核', exact: true }).click(); await choose(consolePage, '开发者状态', '启用');
  const developerRow = consolePage.locator(`tr.ant-table-row[data-row-key="${owner.id}"]`); await expect(developerRow).toHaveCount(1); await expect(developerRow).toContainText(owner.username);
  const developerExpected = { kind: 'developer', clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, id: owner.id, username: owner.username };
  const developerLoading = manualRead(consolePage, developerExpected); await developerRow.getByRole('button', { name: /^详\s*情$/ }).click();
  const developerData = (await readResult(await developerLoading, developerExpected, 'console developer Configuration')).data.entity;
  const developerDetail = consolePage.getByTestId('portal-admin-developer-detail'); await expect(developerDetail).toBeVisible(); await expect(developerDetail.getByRole('tab', { name: 'Configuration / 配置', exact: true })).toHaveAttribute('aria-selected', 'true');
  await descriptionValue(developerDetail, '开发者账号', developerData.username); await descriptionValue(developerDetail, '显示名称', developerData.displayName); await descriptionValue(developerDetail, '邮箱', developerData.email);
  await descriptionValue(developerDetail, '状态', '启用'); await descriptionValue(developerDetail, '下次登录修改密码', developerData.mustChangePassword ? '需要' : '无需'); await descriptionValue(developerDetail, '资料版本', developerData.revision); await descriptionValue(developerDetail, '开发者 ID', owner.id);
  check('developer Configuration renders current safe response fields', true); await screenshot(consolePage, 'manual-console-developer-configuration'); await developerDetail.locator('.ant-drawer-close').click();
  phase('console current application Configuration and relations');
  await consolePage.getByRole('tab', { name: '应用管理', exact: true }).click();
  const applicationRow = consolePage.locator(`tr.ant-table-row[data-row-key="${published.applicationId}"]`); await expect(applicationRow).toHaveCount(1);
  const applicationExpected = { kind: 'application', clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, id: published.applicationId, developerId: owner.id };
  const applicationLoading = manualRead(consolePage, applicationExpected); await applicationRow.getByRole('button', { name: /^详\s*情$/ }).click();
  const applicationData = (await readResult(await applicationLoading, applicationExpected, 'console application Configuration')).data.entity;
  const applicationDetail = consolePage.getByTestId('portal-admin-application-detail'); await expect(applicationDetail).toBeVisible(); await expect(applicationDetail.getByRole('tab', { name: 'Configuration / 配置', exact: true })).toHaveAttribute('aria-selected', 'true');
  await descriptionValue(applicationDetail, '应用名称', applicationData.name); await descriptionValue(applicationDetail, '说明', applicationData.description || '—'); await descriptionValue(applicationDetail, '状态', '启用'); await descriptionValue(applicationDetail, '资料版本', applicationData.revision); await descriptionValue(applicationDetail, '所属开发者 ID', owner.id); await descriptionValue(applicationDetail, '应用 ID', published.applicationId);
  await expect(applicationDetail.getByText('这里只显示应用与授权元数据', { exact: true })).toBeVisible(); check('application Configuration renders owned safe metadata and capabilities', true); await screenshot(consolePage, 'manual-console-application-configuration');
  const relationExpected = { clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, id: published.applicationId, publicationId: published.activePublicationId, grantId: published.activeGrantId, workflowId: activeGrant.workflowId };
  const grantsExpected = { ...relationExpected, kind: 'grants' }, grantsLoading = manualRead(consolePage, grantsExpected);
  await applicationDetail.getByRole('tab', { name: '授权记录', exact: true }).click(); const grantsData = await readResult(await grantsLoading, grantsExpected, 'console application grants');
  for (const grant of grantsData.data.items) { const grantRow = applicationDetail.locator(`tr.ant-table-row[data-row-key="${grant.id}"]`); await expect(grantRow).toHaveCount(1); await expect(grantRow).toContainText(grant.publicationName); }
  const activeGrantRow = applicationDetail.locator(`tr.ant-table-row[data-row-key="${published.activeGrantId}"]`); await expect(activeGrantRow).toContainText(activePublication.name); await expect(activeGrantRow.getByText('启用', { exact: true })).toBeVisible(); await expect(activeGrantRow.getByText(published.activeGrantId, { exact: true })).toBeVisible();
  await expect(applicationDetail.getByText('保留历史授权状态，不显示凭证', { exact: true })).toBeVisible(); check('grants DOM matches exact current active grant and preserves historical rows', true); await screenshot(consolePage, 'manual-console-application-grants');
  const requestsExpected = { ...relationExpected, kind: 'requests' }, requestsLoading = manualRead(consolePage, requestsExpected);
  await applicationDetail.getByRole('tab', { name: '申请 / 工作流', exact: true }).click(); const requestsData = await readResult(await requestsLoading, requestsExpected, 'console application request relationships');
  for (const request of requestsData.data.items) { const requestRow = applicationDetail.locator(`tr.ant-table-row[data-row-key="${request.id}"]`); await expect(requestRow).toHaveCount(1); await expect(requestRow).toContainText(request.kind); await expect(requestRow.getByRole('link', { name: '查看申请链', exact: true })).toHaveAttribute('href', `/workflows/${request.id}`); }
  const completedRequestRow = applicationDetail.locator(`tr.ant-table-row[data-row-key="${activeGrant.workflowId}"]`); await expect(completedRequestRow.getByText('已完成', { exact: true })).toBeVisible(); await expect(completedRequestRow.getByText(requestsData.target.approvalRequired ? '需审批' : '直接执行', { exact: true })).toBeVisible();
  check('application request DOM links the completed actual workflow to its current grant and publication', true); await screenshot(consolePage, 'manual-console-application-requests'); await applicationDetail.locator('.ant-drawer-close').click();
  await consolePage.getByRole('tab', { name: '门户设置', exact: true }).click();
  await expect(consolePage.getByLabel('公开门户编码', { exact: true })).toHaveValue(published.tenantSlug); check('settings use current tenant slug', true);
  phase('Markdown create staged confirmation');
  await consolePage.getByRole('tab', { name: 'Markdown 页面 / 回收站', exact: true }).click(); await consolePage.getByRole('button', { name: '新增 Markdown 页面', exact: true }).click();
  await consolePage.getByLabel('页面编码', { exact: true }).fill(slug); await consolePage.getByLabel('标题', { exact: true }).fill(title); await consolePage.getByLabel('Markdown 内容', { exact: true }).fill(safeMarkdown);
  const attemptedPagesBeforeCancel = manualAttempts.filter(value => /\/portal\/pages/.test(value.path)).length;
  await consolePage.getByRole('button', { name: '保存页面', exact: true }).click(); await consolePage.getByLabel('确认名称', { exact: true }).fill('wrong-name'); await expect(consolePage.locator('.ant-modal:visible').getByRole('button', { name: '确认执行', exact: true })).toBeDisabled(); check('Markdown typed mismatch blocks actual create', true); await screenshot(consolePage, 'manual-console-page-confirmation');
  await consolePage.locator('.ant-modal:visible').getByRole('button', { name: /取\s*消/ }).click();
  check('cancelled staged create sends no metadata request', manualAttempts.filter(value => /\/portal\/pages/.test(value.path)).length === attemptedPagesBeforeCancel);
  await consolePage.getByRole('button', { name: '保存页面', exact: true }).click();
  const creating = mutation(consolePage, 'pages', 'POST'); await confirm(consolePage, title); const created = await result(await creating, 'Markdown create');
  const content = created.entity; check('direct actual entity differs from parent workflow', typeof content?.id === 'string' && content.id !== created.workflowId && created.receipt?.state === 'succeeded');
  manualMetadata.push({ type: 'portal-page', id: content.id, clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id, title, slug, createdThrough: 'UI' }); report.fixtureJournal.push(...manualMetadata); retain(); persist();
  await expect(consolePage.getByText('变更执行完成，配置生效中', { exact: true })).toBeVisible(); await expect(consolePage.getByRole('link', { name: '查看计划与每步执行回执', exact: true })).toHaveAttribute('href', `/workflows/${created.workflowId}`); check('notice uses safe parent receipt and current read navigation', true); await screenshot(consolePage, 'manual-console-parent-workflow-notice');
  const row = consolePage.locator('.ant-table-row').filter({ has: consolePage.getByText(title, { exact: true }) }); await expect(row).toHaveCount(1);
  const publishing = mutation(consolePage, `pages/${content.id}/publish`, 'POST'); await row.getByRole('button', { name: /^发\s*布$/ }).click(); await confirm(consolePage, title); await result(await publishing, 'Markdown publish');
  await page.goto(`/pages/${slug}`); const renderedMarkdown = page.getByTestId('portal-markdown'); await expect(renderedMarkdown.locator('h1')).toHaveText('手工验收页面'); await expect(renderedMarkdown.locator('code')).toHaveText('x < 2'); await expect(renderedMarkdown.locator('strong')).toHaveText('审核通过后才可领取凭证。'); await expect(renderedMarkdown.locator('script')).toHaveCount(0); check('published safe Markdown renders heading, inline code and emphasis without script DOM', true); await screenshot(page, 'manual-portal-published-markdown');
  const deleting = mutation(consolePage, `pages/${content.id}`, 'DELETE'); await row.getByRole('button', { name: '移入回收站', exact: true }).click(); await confirm(consolePage, title); await result(await deleting, 'Markdown soft archive');
  await page.reload(); await expect(page.getByTestId('portal-markdown')).toHaveCount(0); check('archived page is no longer publicly available', true);
  await choose(consolePage, '门户页面状态', '页面回收站'); await expect(row).toHaveCount(1); check('deleted content visible in metadata recycle page', true);
  const restoring = mutation(consolePage, `pages/${content.id}/restore`, 'POST'); await row.getByRole('button', { name: /^恢\s*复$/ }).click(); await confirm(consolePage, title); await result(await restoring, 'Markdown restore');
  await choose(consolePage, '门户页面状态', '当前页面'); await expect(row).toContainText('草稿'); check('restore does not automatically republish', true);
  await consolePage.goto(`/workflows/${created.workflowId}`); await expect(consolePage.getByTestId('workflow-state')).toHaveText('已完成'); check('actual direct workflow safe detail', true);
  await consolePage.setViewportSize({ width: 390, height: 844 }); await screenshot(consolePage, 'manual-console-mobile');

  const reader = await browser.newContext({ baseURL: consoleOrigin, viewport: { width: 1440, height: 960 } }); contexts.push(reader);
  await boundary(reader, 'approver');
  await reader.addInitScript(({ cid, wid }) => { sessionStorage.setItem('kongos.clusterId', cid); sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid); }, { cid: fixture.cluster.id, wid: fixture.workspace.id });
  const readerPage = await reader.newPage(); observe(readerPage, 'approver'); readerPage.setDefaultTimeout(15_000); await consoleLogin(readerPage, approver.user.username, approver.password); await readerPage.goto(`/workflows/${created.workflowId}`); await expect(readerPage.getByTestId('workflow-state')).toBeVisible(); check('ordinary approval-only account has no execution control', await readerPage.getByRole('button', { name: '执行已确认计划', exact: true }).count() === 0);
  await Promise.all(responseTasks); check('no browser AdminAPI requests', adminRequests.length === 0); check('Portal uses independent BFF namespace', portalConsoleRequests.length === 0); check('all private requests carry original scope', missingScope.length === 0); check('no page errors', pageErrors.length === 0);
  check('all successful writes have audit requestId', writes.every(row => typeof row.requestId === 'string'));
  const ids = [...new Set(writes.map(row => row.requestId))];
  const code = "import pg from 'pg';let s='';for await(const c of process.stdin)s+=c;const p=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});try{const r=await p.query('SELECT request_id FROM audit_events WHERE request_id=ANY($1::text[])',[JSON.parse(s)]);process.stdout.write(JSON.stringify(r.rows.map(v=>v.request_id)));}finally{await p.end();}";
  const audited = new Set(JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify(ids), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })));
  check('all successful write requests are audited', ids.every(id => audited.has(id)));
  report.auditCoverage = { successfulProductWrites: writes.length, distinctRequestIds: ids.length, auditedRequestIds: audited.size, allPassed: true };
  report.productMetadataWrites = writes.filter(row => /\/portal\/pages/.test(row.path)).length; check('only four planned Markdown metadata writes', report.productMetadataWrites === 4);
  report.writeBoundary = manualJournalSummary(journal); check('all seven planned packets complete with only bounded known-denied anonymous bootstrap extras', report.writeBoundary.complete);
  report.pageErrors = pageErrors.length; report.browserAdminRequests = adminRequests.length; report.portalRequestsToConsole = portalConsoleRequests.length; report.missingTenantQueries = missingScope.length; report.allPassed = true;
  report.notPerformed = [{ name: 'repeat lost-response application write', reason: 'Security already verified the original parent key; manual review reads the completed browser evidence and never creates another uncertain application write.' }, { name: 'Portal-only workflow navigation runtime', reason: 'No new IAM grants are created during manual review; safe no-link behavior is covered by source-backed focused unit tests.' }];
} catch (error) {
  try { stopManualJournal(journal, 'manual-harness-stopped', retain); } catch {}
  checks.push({ name: `harness stopped after ${currentCheck}`, passed: false, errorName: error.name }); report.allPassed = false; process.exitCode = 1;
} finally {
  await Promise.allSettled(responseTasks);
  for (const context of contexts) { for (const cookie of await context.cookies()) if (/^kongos_(portal_)?(access|refresh|csrf)$/.test(cookie.name) && cookie.value) newSecrets.add(cookie.value); await context.close(); }
  if (browser) await browser.close(); report.writeBoundary = manualJournalSummary(journal);
  if (!report.writeBoundary.complete) { report.allPassed = false; if (checks.every(row => row.passed)) checks.push({ name: 'durable manual write boundary did not complete', passed: false }); }
  retain(); persist();
  console.log(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, screenshots: screenshots.length, successfulWrites: writes.length, runtimeSecretValuesPublished: false }));
}
