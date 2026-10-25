import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { M6_REFERENCE, privateReference } from '../security/lib/m6-reference.mjs';

if (existsSync('.env')) process.loadEnvFile('.env');
// A failure while the explicit reveal lease is open must never create an
// automatic screenshot or trace containing the key. Screenshots below are
// taken only after closing and clearing the lease.
test.use({ trace: 'off', screenshot: 'off', video: 'off' });

test('M6 real separate portal session, masked credentials, UI issue/approval and lost-response receipt recovery', async ({ browser }) => {
  if (process.env.M6_DEPLOYMENT_READY !== 'true') throw new Error('explicit M6 deployed exclusive window is required');
  test.setTimeout(240_000);
  const live = JSON.parse(readFileSync('artifacts/M6/security-live.json', 'utf8'));
  expect(live.failed).toBe(0);
  const reference = privateReference(M6_REFERENCE, true), fixture = live.fixturesForBrowser;
  const owner = reference.portalUsers.find((row: any) => row.label === 'developer-a');
  if (!owner?.password || !fixture?.applicationId) throw new Error('actual HTTP portal fixtures required');
  const portalOrigin = process.env.PORTAL_PLAYWRIGHT_BASE_URL ?? 'http://127.0.0.1:8082';
  const consoleOrigin = process.env.PLAYWRIGHT_BASE_URL ?? 'http://127.0.0.1:8080';
  const contexts: BrowserContext[] = [], screenshots: string[] = [], evidence: Promise<void>[] = [];
  const errors: string[] = [], adminRequests: string[] = [], portalConsoleRequests: string[] = [], missingScope: string[] = [];
  const writes: { method: string; path: string; requestId?: string }[] = [];
  let portalRefreshes = 0;
  mkdirSync('artifacts/M6', { recursive: true });
  function retain() {
    const latest = privateReference(M6_REFERENCE, true);
    writeFileSync(M6_REFERENCE, JSON.stringify({ ...latest, ...reference, secrets: [...new Set([...(latest.secrets ?? []), ...(reference.secrets ?? [])])], browserWriteEvidence: writes }), { mode: 0o600 });
  }
  async function password(page: Page, label: string, value: string) {
    await page.getByLabel(label, { exact: true }).evaluate((input, secret) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, secret);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
  }
  function observe(page: Page, portal: boolean) {
    page.on('pageerror', error => errors.push(error.name));
    page.on('request', request => {
      const url = new URL(request.url()); if (url.port === '8001') adminRequests.push(url.pathname);
      if (portal && url.pathname.startsWith('/api/v1/') && (url.origin !== portalOrigin || !url.pathname.startsWith('/api/v1/portal/'))) portalConsoleRequests.push(url.pathname);
      if (portal && request.method() === 'GET' && /^\/api\/v1\/portal\/(applications|requests|auth\/me|operations)(\/|$)/.test(url.pathname) && (!url.searchParams.get('clusterId') || !url.searchParams.get('workspaceId'))) missingScope.push(url.pathname);
    });
    page.on('response', response => {
      const request = response.request(), url = new URL(response.url());
      if (!url.pathname.startsWith('/api/v1/')) return;
      evidence.push((async () => {
        for (const header of await response.headerValues('set-cookie')) {
          const pair = header.split(';')[0], at = pair.indexOf('=');
          if (/^kongos_(portal_)?(access|refresh|csrf)=/.test(pair)) reference.secrets.push(pair.slice(at + 1));
        }
        retain();
        if (['GET', 'HEAD'].includes(request.method()) || response.status() < 200 || response.status() >= 300) return;
        const json = await response.json();
        if (url.pathname === '/api/v1/portal/auth/refresh') portalRefreshes++;
        if (url.pathname.endsWith('/reveal') && typeof json.data?.key === 'string') { reference.secrets.push(json.data.key); retain(); }
        writes.push({ method: request.method(), path: url.pathname, requestId: json.meta?.requestId });
      })());
    });
  }
  async function screenshot(page: Page, name: string) {
    expect(await page.getByRole('dialog', { name: '临时查看 API Key' }).count()).toBe(0);
    await page.mouse.move(275, 105); await page.waitForTimeout(400);
    await page.screenshot({ path: `artifacts/M6/${name}.png`, fullPage: true, animations: 'disabled' }); screenshots.push(`${name}.png`);
  }
  async function choose(page: Page, label: string, name: string) {
    const combo = page.getByRole('combobox', { name: label, exact: true });
    await combo.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-select ")][1]').locator('.ant-select-selector').click();
    await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ hasText: name }).first().click();
  }
  const portal = await browser.newContext({ baseURL: portalOrigin, viewport: { width: 1440, height: 960 } }); contexts.push(portal);
  const page = await portal.newPage(); observe(page, true); page.setDefaultTimeout(15_000);
  try {
    await page.goto(`/apis?tenant=${fixture.tenantSlug}`);
    await expect(page.getByTestId('portal-catalog')).toBeVisible();
    await screenshot(page, 'portal-public-api-catalog');
    await page.goto(`/login?tenant=${fixture.tenantSlug}`);
    await page.getByLabel('开发者账号', { exact: true }).fill(owner.username); await password(page, '密码', owner.password);
    await page.getByRole('button', { name: '登录开发者门户', exact: true }).click();
    await expect(page.getByTestId('portal-create-application')).toBeVisible();
    await page.goto(`/applications/${fixture.applicationId}`);
    await expect(page.getByTestId('portal-credential-masked').first()).toBeVisible();
    // Simulate an absent access cookie while retaining the valid independent
    // refresh/session cookie. This verifies the real reload CSRF+refresh path.
    const refreshesBeforeReload = portalRefreshes;
    reference.secrets.push(...(await portal.cookies()).filter(cookie => /^kongos_portal_(access|refresh|csrf)$/.test(cookie.name)).map(cookie => cookie.value)); retain();
    await portal.clearCookies({ name: 'kongos_portal_access' });
    await page.reload();
    await expect(page.getByRole('heading', { name: reference.grants[0].app.name, exact: true })).toBeVisible();
    await expect.poll(() => portalRefreshes).toBeGreaterThan(refreshesBeforeReload);
    const cookieNames = (await portal.cookies()).map(cookie => cookie.name);
    expect(cookieNames.includes('kongos_portal_access')).toBe(true); expect(cookieNames.includes('kongos_access')).toBe(false);
    await screenshot(page, 'portal-owned-application-masked-key');
    const activeGrantCard = page.locator('.ant-card').filter({ has: page.getByText(reference.fixtures[0].publications[1].name, { exact: true }) });
    await expect(activeGrantCard).toHaveCount(1);
    await activeGrantCard.getByRole('button', { name: '查看 API Key', exact: true }).click();
    const lease = page.getByRole('dialog', { name: '临时查看 API Key' }); await expect(lease).toBeVisible();
    // Only assert a boolean, never publish the temporary value in an assertion.
    expect(await lease.locator('input').evaluate((input, expected) => (input as HTMLInputElement).value === expected, reference.grants[1].apiKey)).toBe(true);
    await lease.getByRole('button', { name: '关闭并清除', exact: true }).click();
    await expect(lease).toHaveCount(0);
    expect((await page.locator('body').innerText()).includes(reference.grants[1].apiKey)).toBe(false);
    await screenshot(page, 'portal-reveal-lease-cleared');

    // Discard one successful application-create response after the server has
    // committed it. The original key is retained before route.fetch; recovery
    // is GET-only and must not create a second application.
    await page.goto('/applications'); await page.getByTestId('portal-create-application').click();
    const appName = `${live.testTag} Browser Application`;
    await page.getByLabel('应用名称', { exact: true }).fill(appName);
    let writesSent = 0, originalKey = '', appId = '';
    const routePattern = '**/api/v1/portal/applications?*';
    await page.route(routePattern, async route => {
      if (route.request().method() !== 'POST') { await route.continue(); return; }
      writesSent++; originalKey = route.request().headers()['x-idempotency-key'];
      reference.browserUnknown = { key: originalKey, clusterId: fixture.clusterId, workspaceId: fixture.workspaceId, actorId: owner.id, method: 'POST', path: '/api/v1/portal/applications', startedAt: new Date().toISOString() }; retain();
      const result = await route.fetch(); const payload = await result.json();
      expect(result.status()).toBe(201); appId = payload.data?.entity?.id ?? payload.data?.id;
      writes.push({ method: 'POST', path: '/api/v1/portal/applications', requestId: payload.meta?.requestId });
      reference.browserApplication = { id: appId, name: appName, tenant: owner.tenant, ownerId: owner.id }; retain();
      await route.abort('failed');
    });
    await page.getByRole('button', { name: '保存应用', exact: true }).click();
    await expect(page.getByRole('button', { name: '核验操作', exact: true })).toBeVisible();
    expect(writesSent).toBe(1); expect(!!originalKey && !!appId).toBe(true);
    // Close the editor only; never resend the interrupted application POST.
    const close = page.locator('.ant-drawer-close'); if (await close.count()) await close.click();
    await page.reload(); await expect(page.getByRole('button', { name: '核验操作', exact: true })).toBeVisible();
    await page.getByRole('button', { name: '核验操作', exact: true }).click();
    await expect(page.getByRole('dialog', { name: '门户操作核验结果' })).toBeVisible();
    await screenshot(page, 'portal-original-key-receipt-recovery');
    await page.getByRole('dialog', { name: '门户操作核验结果' }).getByRole('button', { name: /确\s*定|OK/ }).click();
    await page.unroute(routePattern); expect(writesSent).toBe(1);
    await page.goto(`/apis/${fixture.publicationId}`);
    await page.getByRole('button', { name: '申请 API Key', exact: true }).click();
    await choose(page, '申请应用', appName);
    const requested = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/portal/requests' && response.request().method() === 'POST');
    await page.getByRole('button', { name: '提交凭证申请', exact: true }).click();
    const requestedResponse = await requested; expect(requestedResponse.status()).toBe(201);
    const requestedData = (await requestedResponse.json()).data, workflowId = requestedData.workflowId ?? requestedData.id;
    reference.browserWorkflowId = workflowId; retain();
    await expect(page.getByText('待审核', { exact: true }).first()).toBeVisible(); await screenshot(page, 'portal-credential-request-awaiting-approval');

    const console = await browser.newContext({ baseURL: consoleOrigin, viewport: { width: 1440, height: 960 } }); contexts.push(console);
    await console.addInitScript(({ cid, wid }) => { sessionStorage.setItem('kongos.clusterId', cid); sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid); }, { cid: fixture.clusterId, wid: fixture.workspaceId });
    const consolePage = await console.newPage(); observe(consolePage, false); consolePage.setDefaultTimeout(15_000);
    await consolePage.goto(`/workflows/${workflowId}`);
    await consolePage.getByLabel('账号', { exact: true }).fill(process.env.BOOTSTRAP_ADMIN_USERNAME ?? 'admin'); await password(consolePage, '密码', process.env.BOOTSTRAP_ADMIN_PASSWORD!);
    await consolePage.getByRole('button', { name: '登录控制台', exact: true }).click();
    await consolePage.goto(`/workflows/${workflowId}`);
    await consolePage.getByRole('button', { name: '批准变更', exact: true }).click();
    await consolePage.getByLabel('确认名称', { exact: true }).fill('portal-credential-issue');
    await consolePage.getByRole('button', { name: '确认执行', exact: true }).click();
    await expect(consolePage.getByRole('button', { name: '执行已确认计划', exact: true })).toBeVisible();
    await consolePage.getByRole('button', { name: '执行已确认计划', exact: true }).click();
    await consolePage.getByLabel('确认名称', { exact: true }).fill('portal-credential-issue');
    await consolePage.getByRole('button', { name: '确认执行', exact: true }).click();
    await expect(consolePage.getByText('已完成', { exact: true }).first()).toBeVisible(); await screenshot(consolePage, 'console-current-actor-approved-workflow-complete');
    await page.goto(`/applications/${appId}`); await expect(page.getByTestId('portal-credential-masked')).toBeVisible();
    await screenshot(page, 'portal-approved-browser-application');
    await page.setViewportSize({ width: 390, height: 844 }); await screenshot(page, 'portal-mobile-owned-application');
    await Promise.all(evidence);
    expect(errors).toEqual([]); expect(adminRequests).toEqual([]); expect(portalConsoleRequests).toEqual([]); expect(missingScope).toEqual([]);
    expect(writes.every(row => !!row.requestId)).toBe(true);
    const ids = [...new Set(writes.map(row => row.requestId))];
    const code = `import pg from 'pg';let s='';for await(const c of process.stdin)s+=c;const p=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});try{const r=await p.query('SELECT request_id FROM audit_events WHERE request_id=ANY($1::text[])',[JSON.parse(s)]);process.stdout.write(JSON.stringify(r.rows.map(v=>v.request_id)));}finally{await p.end();}`;
    const audited = new Set(JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify(ids), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })));
    expect(ids.every(id => audited.has(id))).toBe(true);
    writeFileSync('artifacts/M6/browser-verification.json', JSON.stringify({ performedAt: new Date().toISOString(), passed: 1, failed: 0, mechanisms: { separatePortalOriginAndIdentity: true, authenticatedReload: true, actualRefreshAfterMissingAccessCookie: true, maskedCredentialAndClearedRevealLease: true, actualUiCredentialRequestApprovalExecution: true, lostApplicationResponseOriginalKeyRecoveryWithoutReplay: true, mobile: true }, lostResponseNativePostCount: writesSent, pageErrors: errors.length, browserAdminRequests: adminRequests.length, portalRequestsToConsole: portalConsoleRequests.length, missingTenantQueries: missingScope.length, screenshots, auditCoverage: { successfulProductWrites: writes.length, distinctRequestIds: ids.length, auditedRequestIds: audited.size, allPassed: true } }, null, 2) + '\n');
  } finally {
    for (const context of contexts) { reference.secrets.push(...(await context.cookies()).filter(cookie => /^kongos_(portal_)?(access|refresh|csrf)$/.test(cookie.name)).map(cookie => cookie.value)); await context.close(); }
    retain();
  }
});
