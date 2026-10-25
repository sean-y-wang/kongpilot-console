import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

if (existsSync('.env')) process.loadEnvFile('.env');

// Authentication secrets must never enter trace or reporter step titles.
test.use({ trace: 'off', viewport: { width: 1440, height: 960 } });

test('M1 Service UI create, edit, detail tabs, confirmed deletion and recovery', async ({ page }) => {
  test.setTimeout(90_000);
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required');
  const consoleErrors: string[] = [], browserAdminRequests: string[] = [];
  page.on('pageerror', error => consoleErrors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).port === '8001') browserAdminRequests.push(request.url()); });
  const name = `m1-browser-${Date.now()}`, updatedName = `${name}-updated`;
  mkdirSync('artifacts/M1', { recursive: true });

  async function capture(file: string) {
    await expect(page.locator('.ant-message-notice')).toHaveCount(0);
    await page.mouse.move(280, 120);
    await page.evaluate(() => {
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
      window.scrollTo(0, 0);
      for (const element of document.querySelectorAll('.console-sidebar, .ant-table-content, .ant-table-body')) { element.scrollTop = 0; element.scrollLeft = 0; }
    });
    await page.screenshot({ path: `artifacts/M1/${file}.png`, fullPage: true, animations: 'disabled' });
  }
  async function search(value: string) { await page.getByLabel('搜索实体', { exact: true }).fill(value); await page.getByLabel('搜索实体', { exact: true }).press('Enter'); }

  await page.goto('/');
  await page.getByLabel('账号', { exact: true }).fill(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin');
  await page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, password);
  await page.getByRole('button', { name: '登录控制台', exact: true }).click();
  await expect(page.getByRole('heading', { name: '网关总览', exact: true })).toBeVisible();
  await page.getByRole('menuitem', { name: /Services$/ }).click();
  await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /创建 Services$/ }).click();
  await page.getByLabel('name', { exact: true }).fill(name);
  await page.getByLabel('host', { exact: true }).fill('echo-upstream');
  await page.getByLabel('port', { exact: true }).fill('8081');
  // The live schema must omit fields unavailable on Kong 1.5.
  await expect(page.getByLabel('tls_verify', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toHaveCount(0);
  await search(name);
  const originalRow = page.getByRole('row').filter({ has: page.getByRole('button', { name, exact: true }) });
  await expect(originalRow).toBeVisible({ timeout: 20_000 });
  await originalRow.getByRole('button', { name: /编辑$/ }).click();
  await page.getByLabel('name', { exact: true }).fill(updatedName);
  await page.getByLabel('retries', { exact: true }).fill('2');
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toHaveCount(0);
  await search(updatedName);
  const row = page.getByRole('row').filter({ has: page.getByRole('button', { name: updatedName, exact: true }) });
  await expect(row).toBeVisible();
  await capture('services');
  await row.getByRole('button', { name: updatedName, exact: true }).click();
  await expect(page.getByRole('tab', { name: 'Configuration', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Routes', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Plugins', exact: true })).toBeVisible();
  await capture('service-details');
  await page.getByRole('tab', { name: 'Routes', exact: true }).click();
  await page.getByRole('tab', { name: 'Plugins', exact: true }).click();
  await page.getByRole('tab', { name: 'Configuration', exact: true }).click();
  await page.getByRole('button', { name: /删除$/ }).last().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: '确认执行', exact: true })).toBeDisabled();
  await dialog.getByLabel('确认名称', { exact: true }).fill('wrong-name');
  await expect(dialog.getByRole('button', { name: '确认执行', exact: true })).toBeDisabled();
  await dialog.getByLabel('确认名称', { exact: true }).fill(updatedName);
  await dialog.getByRole('button', { name: '确认执行', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'Configuration', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: updatedName, exact: true })).toHaveCount(0);

  await page.getByRole('menuitem', { name: /回收站$/ }).click();
  const archivedRow = page.getByRole('row').filter({ has: page.getByRole('button', { name: updatedName, exact: true }) });
  await expect(archivedRow).toBeVisible();
  await capture('recycle-bin');
  await archivedRow.getByRole('button', { name: /恢复$/ }).click();
  await page.getByRole('dialog').getByLabel('确认名称', { exact: true }).fill(updatedName);
  await page.getByRole('dialog').getByRole('button', { name: '确认恢复', exact: true }).click();
  await expect(page.getByText('恢复 / 清理执行结果', { exact: true })).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: '关闭', exact: true }).click();
  await expect(archivedRow.getByRole('button', { name: /恢复$/ })).toBeDisabled();
  await page.getByRole('menuitem', { name: /Services$/ }).click();
  await search(updatedName);
  await expect(page.getByRole('button', { name: updatedName, exact: true })).toBeVisible();
  expect(browserAdminRequests).toEqual([]);
  expect(consoleErrors).toEqual([]);
  writeFileSync('artifacts/M1/browser-verification.json', `${JSON.stringify({ performedAt: new Date().toISOString(), passed: 1, failed: 0, browser: 'Chromium', tested: ['Service create/edit/detail tabs', 'typed confirmed deletion', 'recycle restoration', 'unsupported field omitted'], pageErrors: consoleErrors.length, browserAdminRequests: browserAdminRequests.length, screenshots: ['services.png', 'service-details.png', 'recycle-bin.png'] }, null, 2)}\n`);
});
