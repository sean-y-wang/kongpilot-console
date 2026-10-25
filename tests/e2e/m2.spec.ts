import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

if (existsSync('.env')) process.loadEnvFile('.env');
test.use({ trace: 'off', viewport: { width: 1440, height: 960 } });

test('M2 market, nested conditional records, priority diagram and uncertain-write receipt', async ({ page, context }) => {
  test.setTimeout(120_000);
  page.setDefaultTimeout(15_000);
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required');
  const live = JSON.parse(readFileSync('artifacts/M2/security-live.json', 'utf8'));
  if (live.failed || live.verifiedPlugins.length !== 34) throw new Error('successful real M2 plugin sweep is required first');
  const pageErrors: string[] = [], browserAdminRequests: string[] = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).port === '8001') browserAdminRequests.push(request.url()); });
  mkdirSync('artifacts/M2', { recursive: true });

  async function capture(name: string, preserveDrawerScroll = false) {
    await expect(page.locator('.ant-message-notice')).toHaveCount(0);
    await page.mouse.move(280, 120);
    await page.evaluate(preserveDrawer => {
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
      window.scrollTo(0, 0);
      for (const element of document.querySelectorAll('.console-sidebar, .ant-table-content, .ant-table-body, .ant-drawer-body')) { element.scrollLeft = 0; if (!preserveDrawer || !element.classList.contains('ant-drawer-body')) element.scrollTop = 0; }
    }, preserveDrawerScroll);
    await page.screenshot({ path: `artifacts/M2/${name}.png`, fullPage: !preserveDrawerScroll, animations: 'disabled' });
  }
  async function choose(label: string, value: string, scope: Page | Locator = page) {
    await scope.getByRole('combobox', { name: label, exact: true }).click();
    // AntD's virtual accessibility list exposes only adjacent options; the
    // visible menu contains the complete rendered choices.
    const exactText = new RegExp(`^${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
    await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ hasText: exactText }).click();
  }
  async function bindService(serviceName: string) {
    const selector = page.getByRole('combobox', { name: 'service', exact: true });
    await selector.click(); await selector.fill(serviceName);
    await page.locator('.ant-select-item-option').filter({ hasText: serviceName }).click();
  }
  async function disableEditorPlugin() {
    const toggle = page.getByRole('switch', { name: 'enabled', exact: true });
    if (await toggle.getAttribute('aria-checked') === 'true') await toggle.click();
    await expect(toggle).toHaveAttribute('aria-checked', 'false');
  }

  await page.goto('/');
  await page.getByLabel('账号', { exact: true }).fill(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin');
  await page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, password);
  await page.getByRole('button', { name: '登录控制台', exact: true }).click();
  await expect(page.getByRole('heading', { name: '网关总览', exact: true })).toBeVisible();
  const csrf = (await context.cookies()).find(cookie => cookie.name === 'kongos_csrf')?.value;
  if (!csrf) throw new Error('authenticated CSRF cookie is required');
  const serviceName = `m2-browser-${Date.now()}-service`;
  const setup = await context.request.post(`/api/v1/clusters/${live.clusterId}/entities/services`, { headers: { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }, data: { name: serviceName, host: 'echo-upstream', port: 8081, tags: ['m2-browser'] } });
  expect(setup.ok()).toBe(true);
  const serviceId = (await setup.json()).data.entity.id;

  // A masked Authorization match must survive an unrelated edit through the
  // actual schema drawer. Assertions compare booleans, never secret values.
  const headerValue = `Bearer m2-header-${randomUUID()}`;
  // The invoking harness can scan the finished compressed HTML report for this
  // temporary synthetic value, then remove the private file outside the repo.
  if (process.env.M2_SECRET_SCAN_FILE) {
    const prior = existsSync(process.env.M2_SECRET_SCAN_FILE) ? JSON.parse(readFileSync(process.env.M2_SECRET_SCAN_FILE, 'utf8')) : [];
    writeFileSync(process.env.M2_SECRET_SCAN_FILE, JSON.stringify([...prior, headerValue]), { mode: 0o600 });
  }
  const routeName = `m2-browser-${Date.now()}-protected-header`;
  const routeSetup = await context.request.post(`/api/v1/clusters/${live.clusterId}/entities/routes`, { headers: { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }, data: { name: routeName, service: { id: serviceId }, paths: [`/m2/browser/${randomUUID()}`], protocols: ['http'], headers: { authorization: [headerValue] }, tags: ['m2-browser'] } });
  expect(routeSetup.ok()).toBe(true);
  const routeId = (await routeSetup.json()).data.entity.id;
  const maskedRoute = await context.request.get(`/api/v1/clusters/${live.clusterId}/entities/routes/${routeId}`);
  expect(maskedRoute.ok()).toBe(true);
  const maskedRouteBody = await maskedRoute.json();
  expect(JSON.stringify(maskedRouteBody).includes(headerValue)).toBe(false);
  expect(JSON.stringify(maskedRouteBody.data.entity.headers).includes('[REDACTED')).toBe(true);
  await page.goto(`/entities/routes/${routeId}`);
  await expect(page.getByRole('tab', { name: 'Configuration', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /编辑$/ }).last().click();
  await page.getByLabel('name', { exact: true }).fill(`${routeName}-renamed`);
  const renamedResponse = page.waitForResponse(response => response.request().method() === 'PATCH' && response.url().endsWith(`/entities/routes/${routeId}`));
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  expect((await renamedResponse).ok()).toBe(true);
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toHaveCount(0);
  const revealedRoute = await context.request.get(`/api/v1/clusters/${live.clusterId}/entities/routes/${routeId}?reveal=true`);
  expect(revealedRoute.ok()).toBe(true);
  const retainedRoute = (await revealedRoute.json()).data.entity;
  expect(retainedRoute.name === `${routeName}-renamed`).toBe(true);
  expect(retainedRoute.headers.authorization?.[0] === headerValue).toBe(true);

  // Optional protocol-specific arrays must also stay unset on UI creation.
  const uiRouteName = `m2-browser-${Date.now()}-ui-created-route`;
  await page.goto('/entities/routes');
  await page.getByRole('button', { name: /创建 Routes$/ }).click();
  await page.getByLabel('name', { exact: true }).fill(uiRouteName);
  await bindService(serviceName);
  const pathRows = page.getByTestId('schema-field-paths');
  await pathRows.getByRole('button', { name: /添加一项$/ }).click();
  await pathRows.getByRole('textbox', { name: 'item', exact: true }).fill(`/m2/browser-created/${randomUUID()}`);
  const uiCreatedResponse = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith('/entities/routes'));
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  const uiCreated = await uiCreatedResponse;
  expect(uiCreated.ok()).toBe(true);
  const uiRoute = (await uiCreated.json()).data.entity;
  expect(uiRoute.name === uiRouteName && uiRoute.sources === null && uiRoute.destinations === null).toBe(true);
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toHaveCount(0);

  await page.goto('/plugin-center');
  await expect(page.getByRole('heading', { name: '插件中心', exact: true })).toBeVisible();
  await expect(page.locator('.plugin-market-card')).toHaveCount(34);
  await capture('plugin-market');
  await page.getByRole('button', { name: '配置 statsd', exact: true }).click();
  await bindService(serviceName); await disableEditorPlugin();
  await page.getByLabel('host', { exact: true }).fill('127.0.0.1');
  await page.getByLabel('port', { exact: true }).fill('9');
  const metrics = page.getByTestId('schema-field-config-metrics');
  await expect(metrics).toBeVisible();
  while (await metrics.locator('.schema-array-row').count()) await metrics.getByRole('button', { name: /移除$/ }).first().click();
  await metrics.getByRole('button', { name: /添加一项$/ }).click();
  const first = metrics.locator('.schema-array-row').nth(0);
  await choose('name', 'unique_users', first);
  await choose('stat_type', 'set', first);
  await choose('consumer_identifier', 'custom_id', first);
  await metrics.getByRole('button', { name: /添加一项$/ }).click();
  const second = metrics.locator('.schema-array-row').nth(1);
  await choose('name', 'request_count', second);
  await choose('stat_type', 'counter', second);
  // counter makes sample_rate mandatory inside this second record.
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toBeVisible();
  await expect(second.locator('.ant-form-item-explain-error')).not.toHaveCount(0);
  await second.getByLabel('sample_rate', { exact: true }).fill('1');
  await metrics.scrollIntoViewIfNeeded();
  await capture('nested-plugin-form', true);
  const savedResponse = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith('/entities/plugins'));
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  const saved = await savedResponse;
  expect(saved.ok()).toBe(true);
  const statsd = (await saved.json()).data.entity;
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toHaveCount(0);
  const state = await context.request.get(`/api/v1/clusters/${live.clusterId}/entities/plugins/${statsd.id}`);
  expect(state.ok()).toBe(true);
  const actual = (await state.json()).data.entity;
  expect(actual.enabled).toBe(false);
  expect(actual.service.id).toBe(serviceId);
  expect(actual.config.metrics).toHaveLength(2);
  expect(actual.config.metrics).toMatchObject([{ name: 'unique_users', stat_type: 'set', consumer_identifier: 'custom_id' }, { name: 'request_count', stat_type: 'counter', sample_rate: 1 }]);

  await page.getByRole('tab', { name: '优先级与冲突', exact: true }).click();
  await expect(page.getByTestId('plugin-precedence-flow').locator('.plugin-precedence-step')).toHaveCount(8);
  await expect(page.getByTestId('plugin-precedence-flow')).toContainText('Consumer + Route + Service');
  await expect(page.getByTestId('plugin-precedence-flow')).toContainText('全局');
  await page.getByTestId('resolve-plugin-context').click();
  await expect(page.getByTestId('plugin-execution-chain')).toBeVisible();
  await capture('plugin-precedence');

  await page.getByRole('tab', { name: '插件市场', exact: true }).click();
  await page.getByRole('button', { name: '配置 cors', exact: true }).click();
  await bindService(serviceName); await disableEditorPlugin();
  let hiddenWriteCount = 0, hiddenPluginId: string | undefined, originalKey: string | undefined;
  await page.route('**/entities/plugins', async route => {
    if (route.request().method() !== 'POST') { await route.continue(); return; }
    hiddenWriteCount++;
    originalKey = route.request().headers()['x-idempotency-key'];
    const backend = await route.fetch();
    if (!backend.ok()) throw new Error('fault fixture did not complete at backend');
    hiddenPluginId = (await backend.json()).data.entity.id;
    // Real write succeeded; hide its response to simulate a lost client result.
    await route.abort('failed');
  });
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.getByRole('button', { name: '核验操作', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toBeDisabled();
  expect(hiddenWriteCount).toBe(1);
  expect(hiddenPluginId).toBeTruthy(); expect(originalKey).toBeTruthy();
  const receiptResponse = page.waitForResponse(response => response.url().includes(`/clusters/${live.clusterId}/mutations/by-key/${originalKey}`));
  await page.getByRole('button', { name: '核验操作', exact: true }).click();
  expect((await receiptResponse).ok()).toBe(true);
  await expect(page.locator('.ant-modal-confirm-title').filter({ hasText: '操作核验结果' })).toBeVisible();
  await expect(page.locator('.ant-modal .json-preview')).toContainText('succeeded');
  expect(hiddenWriteCount).toBe(1);
  expect(pageErrors).toEqual([]); expect(browserAdminRequests).toEqual([]);
  writeFileSync('artifacts/M2/browser-verification.json', `${JSON.stringify({ performedAt: new Date().toISOString(), passed: 1, failed: 0, browser: 'Chromium', statsdId: statsd.id, hiddenPluginId, protectedRouteId: routeId, uiCreatedRouteId: uiRoute.id, routeCreatedViaUi: true, protectedRouteHeaderPreserved: true, defaultHeaderResponseMasked: true, uncertainWriteRequests: hiddenWriteCount, receiptState: 'succeeded', nestedRecords: actual.config.metrics.length, conditionalRequiredValidated: true, pageErrors: 0, browserAdminRequests: 0, screenshots: ['plugin-market.png', 'nested-plugin-form.png', 'plugin-precedence.png'] }, null, 2)}\n`);
});
