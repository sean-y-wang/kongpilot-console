import { existsSync, mkdirSync } from 'node:fs';
import { expect, test } from '@playwright/test';

if (existsSync('.env')) process.loadEnvFile('.env');

// Playwright traces record action arguments and authentication bodies.
test.use({ trace: 'off', viewport: { width: 1440, height: 960 } });

test('M0 login, cluster registration and data source configuration', async ({ page, context }) => {
  const username = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required for the live browser test');
  const consoleErrors: string[] = [];
  const browserKongRequests: string[] = [];
  page.on('pageerror', error => consoleErrors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).port === '8001') browserKongRequests.push(request.url()); });

  async function capture(name: string) {
    await expect(page.locator('.ant-message-notice')).toHaveCount(0);
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      for (const element of document.querySelectorAll('.console-sidebar, .ant-table-content, .ant-table-body')) {
        element.scrollTop = 0;
        element.scrollLeft = 0;
      }
    });
    await page.screenshot({ path: `artifacts/M0/${name}.png`, fullPage: true, animations: 'disabled' });
  }

  await page.goto('/');
  await page.getByLabel('账号', { exact: true }).fill(username);
  // fill(password) exposes its value in HTML reporter step titles, even without trace.
  await page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    setter.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, password);
  await page.getByRole('button', { name: '登录控制台' }).click();
  await expect(page.getByRole('heading', { name: '网关总览' })).toBeVisible();

  // Preserve refresh+CSRF cookies while simulating expired/removed access after reload.
  await context.clearCookies({ name: 'kongos_access' });
  await page.reload();
  await expect(page.getByRole('heading', { name: '网关总览' })).toBeVisible();
  expect((await context.cookies()).some(cookie => cookie.name === 'kongos_access')).toBe(true);
  mkdirSync('artifacts/M0', { recursive: true });
  await capture('overview');

  await page.getByRole('menuitem', { name: /集群管理$/ }).click();
  await expect(page.getByRole('heading', { name: '集群管理', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '默认集群', exact: true })).toBeVisible();
  const name = `浏览器验收-${Date.now()}`;
  await page.getByRole('button', { name: /登记集群$/ }).click();
  await page.getByLabel('集群名称', { exact: true }).fill(name);
  await page.getByLabel('环境', { exact: true }).fill('e2e');
  await page.getByRole('button', { name: '保存集群', exact: true }).click();
  await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
  const row = page.getByRole('row').filter({ has: page.getByRole('button', { name, exact: true }) });
  await row.getByRole('button', { name: /探测$/ }).click();
  await expect(row.getByText('Kong 1.5.1', { exact: true })).toBeVisible({ timeout: 20_000 });
  await capture('clusters');
  await page.getByRole('button', { name, exact: true }).click();
  await page.getByRole('button', { name: '切换至此集群', exact: true }).click();

  await page.getByRole('menuitem', { name: /数据源管理$/ }).click();
  await expect(page.getByRole('heading', { name: '数据源管理', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /添加数据源$/ }).click();
  await page.getByLabel('数据源名称', { exact: true }).fill('浏览器验收 Prometheus');
  await page.getByLabel('服务地址', { exact: true }).fill('http://prometheus:9090');
  await page.getByRole('button', { name: '保存数据源', exact: true }).click();
  await expect(page.getByText('浏览器验收 Prometheus', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /测试$/ }).click();
  await expect(page.getByText('连通性测试已完成，请查看数据源状态', { exact: true })).toBeVisible({ timeout: 15_000 });
  const sourceRow = page.getByRole('row').filter({ has: page.getByText('浏览器验收 Prometheus', { exact: true }) });
  await expect(sourceRow.getByText('连接正常', { exact: true })).toBeVisible();
  await capture('data-sources');
  expect(browserKongRequests).toEqual([]);
  expect(consoleErrors).toEqual([]);
});
