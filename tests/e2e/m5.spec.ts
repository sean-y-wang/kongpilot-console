import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';

if (existsSync('.env')) process.loadEnvFile('.env');
test.use({ trace: 'off', viewport: { width: 1440, height: 960 } });

test('M5 actual Prometheus/Loki charts, minimal monitoring-only selectors and immediate role revocation', async ({ browser }) => {
  test.setTimeout(210_000);
  const live = JSON.parse(readFileSync('artifacts/M5/security-live.json', 'utf8'));
  expect(live.failed).toBe(0);
  const referencePath = '/tmp/kongos-m5-runtime-secrets.json';
  if (!existsSync(referencePath) || (statSync(referencePath).mode & 0o777) !== 0o600) throw new Error('private M5 runtime reference is required');
  const reference = JSON.parse(readFileSync(referencePath, 'utf8'));
  let stopTraffic = false, trafficRequests = 0;
  const traffic = (async () => {
    if (!Array.isArray(reference.traffic) || reference.traffic.length !== 6) throw new Error('bounded owned dual-cluster proxy traffic references required');
    const deadline = Date.now() + 205_000;
    while (!stopTraffic && Date.now() < deadline) {
      for (const row of reference.traffic) {
        if (!['http://127.0.0.1:8000', 'http://127.0.0.1:9000'].includes(row.origin) || !row.path.startsWith(`/m5/${live.testTag}/`) || ![200, 404, 500].includes(row.status)) throw new Error('browser traffic reference escaped owned fixture');
        const response = await fetch(row.origin + row.path, { headers: { apikey: row.apiKey }, redirect: 'manual', signal: AbortSignal.timeout(5000) });
        await response.arrayBuffer();
        if (response.status !== row.status) throw new Error('actual browser-phase proxy traffic lost its expected status');
        trafficRequests++;
      }
      await new Promise(resolve => setTimeout(resolve, 750));
    }
  })();
  // Attach a handler immediately so asynchronous traffic failure cannot leak a
  // raw unhandled-rejection diagnostic while the UI test is still running.
  let trafficFailure: Error | undefined;
  const trafficDone = traffic.catch(error => { trafficFailure = error; });
  const contexts: BrowserContext[] = [];
  const errors: string[] = [], directAdmin: string[] = [], nativeConfigurationReads: string[] = [], missingScope: string[] = [], screenshots: string[] = [];
  const successfulWrites: { method: string; path: string; requestId?: string }[] = [];
  const evidence: Promise<void>[] = [];
  mkdirSync('artifacts/M5', { recursive: true });
  async function open(label: string) {
    const account = label === 'bootstrap' ? { username: process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password: process.env.BOOTSTRAP_ADMIN_PASSWORD } : reference.users.find((row: any) => row.id === live.accounts[label]?.id && row.label === label);
    if (!account?.password) throw new Error('monitoring fixture account is missing');
    const context = await browser.newContext({ baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080', viewport: { width: 1440, height: 960 } });
    contexts.push(context);
    await context.addInitScript(({ cid, wid }) => { sessionStorage.setItem('kongos.clusterId', cid); sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid); }, { cid: live.clusterId, wid: live.payWorkspace.id });
    const page = await context.newPage(); page.setDefaultTimeout(15_000);
    page.on('pageerror', error => errors.push(error.name));
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.port === '8001') directAdmin.push(url.pathname);
      if (label !== 'bootstrap' && request.method() === 'GET' && /\/api\/v1\/clusters\/[^/]+\/(?:entities|consumers|upstreams)(?:\/|$)/.test(url.pathname)) nativeConfigurationReads.push(url.pathname);
      if (/\/api\/v1\/clusters\/[^/]+\/vitals\//.test(url.pathname) && !url.searchParams.has('workspaceId')) missingScope.push(url.pathname);
    });
    page.on('response', response => {
      const request = response.request(), path = new URL(response.url()).pathname;
      if (!path.startsWith('/api/v1/') || ['GET', 'HEAD'].includes(request.method()) || response.status() < 200 || response.status() >= 300 || path.endsWith('/authorization/entity-capabilities')) return;
      evidence.push((async () => { const payload = await response.json(); successfulWrites.push({ method: request.method(), path, requestId: payload?.meta?.requestId }); })());
    });
    await page.goto('/vitals');
    await page.getByLabel('账号', { exact: true }).fill(account.username);
    // Never put a generated password in Playwright's .fill() diagnostic text.
    await page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, value);
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, account.password);
    await page.getByRole('button', { name: '登录控制台', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Vitals 监控', exact: true })).toBeVisible();
    const cookies = await context.cookies();
    reference.secrets.push(...cookies.filter(cookie => /^kongos_(access|refresh|csrf)$/.test(cookie.name)).map(cookie => cookie.value));
    const csrf = cookies.find(cookie => cookie.name === 'kongos_csrf')?.value;
    if (!csrf) throw new Error('validated CSRF cookie required');
    return { context, page, csrf };
  }
  async function choose(page: Page, label: string, text: string) {
    const combo = page.getByRole('combobox', { name: label, exact: true });
    await combo.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-select ")][1]').locator('.ant-select-selector').click();
    // Native identities use bounded server-side cursor pages. Search for the
    // exact owned fixture instead of assuming it is on the first page.
    if (['监控服务', '监控路由'].includes(label)) await combo.fill(text);
    const dropdown = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)');
    await dropdown.locator('.ant-select-item-option').filter({ hasText: text }).first().click();
  }
  async function screenshot(page: Page, name: string) {
    await page.mouse.move(280, 100); await page.waitForTimeout(450);
    await page.screenshot({ path: `artifacts/M5/${name}.png`, fullPage: true, animations: 'disabled' });
    screenshots.push(`${name}.png`);
  }
  async function latestOverview(page: Page, action: () => Promise<void>, matches: (url: URL) => boolean) {
    const waited = page.waitForResponse(response => { const url = new URL(response.url()); return response.request().method() === 'GET' && url.pathname.endsWith('/vitals/overview') && matches(url); });
    await action(); const response = await waited; expect(response.status()).toBe(200);
    return (await response.json()).data;
  }
  try {
    const workspace = await open('monitor-workspace');
    await expect(workspace.page.getByTestId('vitals-chart-qps')).toHaveAttribute('data-available', 'true');
    await expect(workspace.page.getByTestId('vitals-card-qps')).toHaveAttribute('data-availability', 'available');
    await expect(workspace.page.getByRole('button', { name: '配置监控通道', exact: true })).toHaveCount(0);
    await expect(workspace.page.getByLabel('自动刷新监控', { exact: true })).toHaveAttribute('aria-checked', 'false');
    await screenshot(workspace.page, 'vitals-prometheus-workspace');
    const primary = live.fixtures.find((row: any) => row.type === 'services' && row.clusterId === live.clusterId && row.id === live.fixtureIds.service);
    if (!primary) throw new Error('real primary monitoring Service fixture required');
    const selected = await latestOverview(workspace.page, () => choose(workspace.page, '监控服务', primary.name), url => url.searchParams.get('serviceId') === primary.id);
    expect(selected.topN.services.every((row: any) => row.id === primary.id)).toBe(true);
    await screenshot(workspace.page, 'vitals-service-drilldown');
    const lokiScope = await latestOverview(workspace.page, () => choose(workspace.page, '监控数据源', live.sources[live.clusterId].loki.name), url => url.searchParams.get('sourceId') === live.sources[live.clusterId].loki.id && !url.searchParams.has('serviceId'));
    expect(lokiScope.source.type).toBe('loki');
    const loki = await latestOverview(workspace.page, () => choose(workspace.page, '监控服务', primary.name), url => url.searchParams.get('sourceId') === live.sources[live.clusterId].loki.id && url.searchParams.get('serviceId') === primary.id);
    expect(loki.cards.qps.value).not.toBeNull();
    await screenshot(workspace.page, 'vitals-real-loki-channel');

    const serviceOnly = await open('monitor-tuple-mix');
    const identity = await serviceOnly.context.request.get(`/api/v1/clusters/${live.clusterId}/vitals/entities?workspaceId=${live.payWorkspace.id}&type=services&size=20`);
    expect(identity.status()).toBe(200);
    const identities = (await identity.json()).data.items;
    expect(identities.every((row: any) => row.id === primary.id && Object.keys(row).every(key => ['id', 'name', 'parentName'].includes(key)))).toBe(true);
    expect((await serviceOnly.context.request.get(`/api/v1/clusters/${live.clusterId}/entities/services/${primary.id}?workspaceId=${live.payWorkspace.id}`)).status()).toBe(403);
    await screenshot(serviceOnly.page, 'vitals-typed-service-without-native-config');
    const routeOnly = await open('monitor-route');
    const route = live.fixtures.find((row: any) => row.type === 'routes' && row.clusterId === live.clusterId && row.id === live.fixtureIds.route);
    if (!route) throw new Error('real Route fixture required');
    const routeResult = await latestOverview(routeOnly.page, () => choose(routeOnly.page, '监控路由', route.name), url => url.searchParams.get('routeId') === route.id);
    expect(routeResult.cards.qps.value).not.toBeNull();
    await screenshot(routeOnly.page, 'vitals-exact-route-drilldown');
    const consumerOnly = await open('monitor-consumer');
    const consumer = live.fixtures.find((row: any) => row.type === 'consumers' && row.id === live.fixtureIds.primaryConsumer);
    if (!consumer) throw new Error('real Consumer fixture required');
    await expect(consumerOnly.page.getByText(consumer.name, { exact: true })).toBeVisible();
    await expect(consumerOnly.page.getByTestId('vitals-chart-qps')).toHaveAttribute('data-available', 'false');
    await screenshot(consumerOnly.page, 'vitals-consumer-collector-only');

    const longWindow = await latestOverview(workspace.page, () => choose(workspace.page, '监控时间范围', '最近 7 天'), url => Date.parse(url.searchParams.get('end') || '') - Date.parse(url.searchParams.get('start') || '') === 7 * 86400_000);
    expect(Object.values(longWindow.series).every((points: any) => points.length <= 800)).toBe(true);
    expect(longWindow.quality.historicalScope).toBe('current_epoch');
    await expect(workspace.page.getByTestId('vitals-quality')).toBeVisible();
    await screenshot(workspace.page, 'vitals-seven-day-current-epoch-gaps');
    await workspace.page.setViewportSize({ width: 390, height: 844 });
    await screenshot(workspace.page, 'vitals-mobile');

    const revocable = await open('browser-revoke'), administrator = await open('bootstrap');
    const account = live.accounts['browser-revoke'];
    const result = await administrator.context.request.delete(`/api/v1/iam/users/${account.id}/role-bindings/${account.binding.id}`, { headers: { 'X-CSRF-Token': administrator.csrf, 'X-Idempotency-Key': randomUUID() }, data: { revision: account.binding.revision, confirmed: true, confirm_name: account.role.name } });
    expect(result.status()).toBe(200);
    successfulWrites.push({ method: 'DELETE', path: `/api/v1/iam/users/${account.id}/role-bindings/${account.binding.id}`, requestId: (await result.json()).meta?.requestId });
    const forbidden = await revocable.context.request.get(`/api/v1/clusters/${live.clusterId}/vitals/overview?workspaceId=${live.payWorkspace.id}&start=${encodeURIComponent(live.savedEvaluationWindow.start)}&end=${encodeURIComponent(live.savedEvaluationWindow.end)}&step=15`);
    expect(forbidden.status()).toBe(403);
    await revocable.page.reload();
    await expect(revocable.page.getByTestId('vitals-chart-qps')).toHaveCount(0);
    await screenshot(revocable.page, 'vitals-role-revoked-current-session');
    expect(errors).toEqual([]); expect(directAdmin).toEqual([]); expect(nativeConfigurationReads).toEqual([]); expect(missingScope).toEqual([]);
    stopTraffic = true;
    await trafficDone;
    if (trafficFailure) throw trafficFailure;
    await Promise.all(evidence);
    expect(successfulWrites.every(value => !!value.requestId)).toBe(true);
    const ids = [...new Set(successfulWrites.map(value => value.requestId))];
    const code = `import pg from 'pg';let input='';for await(const c of process.stdin)input+=c;const pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});try{const r=await pool.query('SELECT request_id FROM audit_events WHERE request_id=ANY($1::text[])',[JSON.parse(input)]);console.log(JSON.stringify(r.rows.map(v=>v.request_id)));}finally{await pool.end();}`;
    const audited = new Set(JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify(ids), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })));
    expect(ids.every(id => audited.has(id))).toBe(true);
    writeFileSync('artifacts/M5/browser-verification.json', JSON.stringify({ performedAt: new Date().toISOString(), passed: 1, failed: 0, mechanisms: { actualPrometheusAndLoki: true, serviceAndRouteIndependentSelectors: true, consumerCollectorOnly: true, monitoringOnlyNoNativeConfigurationReads: true, sevenDayCurrentEpochGaps: true, existingCookieImmediateRoleRevocation: true, mobile: true }, boundedOwnedProxyRequests: trafficRequests, pageErrors: errors.length, browserAdminRequests: directAdmin.length, unexpectedNativeConfigurationReads: nativeConfigurationReads.length, missingWorkspaceQueries: missingScope.length, screenshots, auditCoverage: { successfulProductWrites: successfulWrites.length, distinctRequestIds: ids.length, auditedRequestIds: audited.size, allPassed: true } }, null, 2) + '\n');
  } finally {
    stopTraffic = true;
    await trafficDone;
    for (const context of contexts) {
      reference.secrets.push(...(await context.cookies()).filter(cookie => /^kongos_(access|refresh|csrf)$/.test(cookie.name)).map(cookie => cookie.value));
      await context.close();
    }
    writeFileSync(referencePath, JSON.stringify(reference), { mode: 0o600 });
  }
});
