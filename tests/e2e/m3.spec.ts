import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

if (existsSync('.env')) process.loadEnvFile('.env');
test.use({ trace: 'off', viewport: { width: 1440, height: 960 } });

test('M3 workspace switch, reviewed migration and recovery using original source scope', async ({ page, context }) => {
  test.setTimeout(120_000);
  page.setDefaultTimeout(15_000);
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('BOOTSTRAP_ADMIN_PASSWORD is required');
  const live = JSON.parse(readFileSync('artifacts/M3/security-live.json', 'utf8'));
  if (live.failed || !live.workspaceA?.id || !live.workspaceB?.id) throw new Error('successful real M3 HTTP gate required');
  mkdirSync('artifacts/M3', { recursive: true });
  const pageErrors: string[] = [], directAdminRequests: string[] = [], scopedEntityRequests: string[] = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.port === '8001') directAdminRequests.push(url.pathname);
    if (/\/api\/v1\/clusters\/[^/]+\/(entities|entity-annotations|upstreams|consumers|recycle-bin|plugin-center|plugin-schemas|schemas|inventory|mutations|workspace-migrations)(\/|$)/.test(url.pathname) && !url.searchParams.has('workspaceId')) scopedEntityRequests.push(`${request.method()} ${url.pathname}`);
  });
  async function select(label: string, value: string, scope: Page | Locator = page) {
    const picker = scope.getByRole('combobox', { name: label, exact: true });
    // rc-select's readonly search input is covered by its selected-value span;
    // users open the visible selector wrapper, rather than that hidden input.
    await picker.locator('xpath=ancestor::*[contains(@class,"ant-select-selector")][1]').click();
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ hasText: new RegExp(`^${escaped}$`) }).click();
  }
  async function switchWorkspace(name: string) { await select('选择工作区', name); }
  async function capture(name: string) {
    await expect(page.locator('.ant-message-notice')).toHaveCount(0);
    await page.mouse.move(280, 120);
    await page.evaluate(() => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); window.scrollTo(0, 0); });
    await page.screenshot({ path: `artifacts/M3/${name}.png`, fullPage: true, animations: 'disabled' });
  }
  await page.goto('/');
  await page.getByLabel('账号', { exact: true }).fill(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin');
  await page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, password);
  await page.getByRole('button', { name: '登录控制台', exact: true }).click();
  await expect(page.getByRole('heading', { name: '网关总览', exact: true })).toBeVisible();
  const csrf = (await context.cookies()).find(item => item.name === 'kongos_csrf')?.value;
  if (!csrf) throw new Error('CSRF cookie required');
  const sourceId = live.workspaceA.id, targetId = live.workspaceB.id;
  const fixtureName = `m3-browser-${Date.now()}-service`;
  const created = await context.request.post(`/api/v1/clusters/${live.clusterId}/entities/services?workspaceId=${sourceId}`, { headers: { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }, data: { name: fixtureName, host: 'echo-upstream', port: 8081, tags: ['m3-browser'] } });
  expect(created.ok()).toBe(true);
  const serviceId = (await created.json()).data.entity.id;
  await switchWorkspace(live.workspaceA.name);
  await page.goto('/entities/services');
  // Named search is server-paged, avoiding a full Kong object fetch in the UI.
  await page.getByLabel('搜索实体', { exact: true }).fill(fixtureName);
  await page.getByLabel('搜索实体', { exact: true }).press('Enter');
  await expect(page.getByRole('button', { name: fixtureName, exact: true })).toBeVisible();
  const targetListResponse = page.waitForResponse(response => {
    const url = new URL(response.url());
    return response.request().method() === 'GET' && url.pathname.endsWith('/entities/services') && url.searchParams.get('workspaceId') === targetId && url.searchParams.get('search') === fixtureName;
  });
  await switchWorkspace(live.workspaceB.name);
  await page.getByLabel('搜索实体', { exact: true }).fill(fixtureName);
  await page.getByLabel('搜索实体', { exact: true }).press('Enter');
  const targetList = await targetListResponse;
  expect(targetList.ok()).toBe(true);
  expect((await targetList.json()).data.items.some((item: { id: string }) => item.id === serviceId)).toBe(false);
  await expect(page.getByRole('button', { name: fixtureName, exact: true })).toHaveCount(0);
  await switchWorkspace(live.workspaceA.name);
  await page.getByLabel('搜索实体', { exact: true }).fill(fixtureName);
  await page.getByLabel('搜索实体', { exact: true }).press('Enter');
  await expect(page.getByRole('button', { name: fixtureName, exact: true })).toBeVisible();
  await page.goto('/workspaces');
  await expect(page.getByText(/软隔离/).first()).toBeVisible();
  await capture('workspace-isolation');

  await page.goto('/workspace-migrations');
  await select('target_workspace_id', live.workspaceB.name);
  const root = page.getByTestId('migration-root-0');
  await select('type', 'Services', root);
  const lookup = root.getByRole('combobox', { name: 'id', exact: true });
  await lookup.click(); await lookup.fill(fixtureName);
  await page.locator('.ant-select-item-option').filter({ hasText: fixtureName }).click();
  const planResponse = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/workspace-migrations/plan'));
  await page.getByRole('button', { name: '预览迁移差异', exact: true }).click();
  const planned = await planResponse; expect(planned.ok()).toBe(true);
  const plan = (await planned.json()).data;
  expect(plan.conflicts.length).toBe(0);
  expect(plan.affected.some((item: { id: string }) => item.id === serviceId)).toBe(true);
  await capture('workspace-migration-preview');

  let writeCount = 0, originalKey = '', originalWorkspaceId = '', applyState = '';
  await page.route('**/workspace-migrations/*/apply*', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    writeCount++;
    originalKey = route.request().headers()['x-idempotency-key'] || '';
    originalWorkspaceId = new URL(route.request().url()).searchParams.get('workspaceId') || '';
    const nativeCompleted = await route.fetch();
    const payload = await nativeCompleted.json();
    applyState = payload.data?.state || '';
    expect(nativeCompleted.ok()).toBe(true);
    // Actual backend apply finishes; browser never receives its successful body.
    await route.abort('failed');
  });
  await page.getByRole('button', { name: '执行迁移', exact: true }).click();
  await page.getByLabel('确认名称', { exact: true }).fill(live.workspaceB.name);
  await page.getByRole('button', { name: '确认执行', exact: true }).click();
  await expect(page.getByRole('button', { name: '核验操作', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '执行迁移', exact: true })).toBeDisabled();
  expect(writeCount).toBe(1); expect(originalWorkspaceId).toBe(sourceId); expect(originalKey.length).toBeGreaterThan(0);
  expect(['succeeded', 'completed'].includes(applyState)).toBe(true);
  await page.unroute('**/workspace-migrations/*/apply*');
  // The confirmation remains open after an unknown result and asks users to
  // close it before inspecting the saved receipt. Cancel only closes this UI.
  await page.getByRole('dialog').getByRole('button', { name: /^取\s*消$/ }).click();
  // The recovery reference must survive both scope change and reload, retaining
  // source scope even though every actual entity now belongs to B.
  await switchWorkspace(live.workspaceB.name);
  await page.reload();
  await expect(page.getByRole('button', { name: '核验操作', exact: true })).toBeVisible();
  const receiptResponse = page.waitForResponse(response => response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith(`/mutations/by-key/${originalKey}`));
  await page.getByRole('button', { name: '核验操作', exact: true }).click();
  const receipt = await receiptResponse; expect(receipt.ok()).toBe(true);
  expect(new URL(receipt.url()).searchParams.get('workspaceId')).toBe(sourceId);
  expect((await receipt.json()).data.state).toBe('succeeded');
  await capture('workspace-migration-recovery');
  const moved = await context.request.get(`/api/v1/clusters/${live.clusterId}/entities/services/${serviceId}?workspaceId=${targetId}`);
  const former = await context.request.get(`/api/v1/clusters/${live.clusterId}/entities/services/${serviceId}?workspaceId=${sourceId}`);
  expect(moved.ok()).toBe(true); expect(former.status()).toBe(403);
  const movedEntity = (await moved.json()).data.entity;
  expect(movedEntity.tags.includes(`workspace:${live.workspaceB.code}`)).toBe(true);
  expect(movedEntity.tags.includes(`workspace:${live.workspaceA.code}`)).toBe(false);
  const cleanBrowser = !pageErrors.length && !directAdminRequests.length && !scopedEntityRequests.length;
  writeFileSync('artifacts/M3/browser-verification.json', `${JSON.stringify({ performedAt: new Date().toISOString(), passed: cleanBrowser ? 1 : 0, failed: cleanBrowser ? 0 : 1, clusterId: live.clusterId, sourceWorkspaceId: sourceId, targetWorkspaceId: targetId, serviceId, planId: plan.id, migrationRequests: writeCount, originalSourceReceipt: true, recoverySurvivesSwitchAndReload: true, formerScopeDenied: true, movedScopeVisible: true, pageErrors: pageErrors.length, browserAdminRequests: directAdminRequests.length, missingWorkspaceQueries: scopedEntityRequests.length, screenshots: ['workspace-isolation.png', 'workspace-migration-preview.png', 'workspace-migration-recovery.png'] }, null, 2)}\n`);
  expect(pageErrors).toEqual([]); expect(directAdminRequests).toEqual([]); expect(scopedEntityRequests).toEqual([]);
});
